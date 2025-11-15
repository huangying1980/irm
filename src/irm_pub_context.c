/* huangying */
#include "irm_pub_context.h"

#include <unistd.h>
#include <pthread.h>

#include <sys/mman.h>
#include <sys/syscall.h>

#ifdef IRM_ENABLE_EFVI
#include "irm_efvi_netio.h"
#endif
#include "irm_native_netio.h"
#include "irm_storage.h"
#include "irm_time_clock.h"
#include "irm_mbuf.h"
#include "irm_msg.h"
#include "irm_buffer.h"
#include "irm_config.h"
#include "irm_error.h"
#include "irm_log.h"
#include "irm_memory_pool.h"

IRM_C_BEGIN

#ifndef IRM_PUB_CTX_EVENT_LOOP_NAME
#define IRM_PUB_CTX_EVENT_LOOP_NAME "irmpub"
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
#define IRM_PUB_MAGIC 0x49505542 //RPUB
#else
#define IRM_PUB_MAGIC 0x42555049 //BUPR
#endif

#ifndef IRM_PUB_MAJOR
#define IRM_PUB_MAJOR (1)
#endif
#ifndef IRM_PUB_MINOR
#define IRM_PUB_MINOR (0)
#endif

#ifndef IRM_PUB_SMALL
#define IRM_PUB_SMALL (0)
#endif

#define IRM_PUB_VERSION \
    (((IRM_PUB_MAJOR) << 16) | ((IRM_PUB_MINOR) << 8) | (IRM_PUB_SMALL))

#define IRM_PUB_SOBJ2MBUF(_s, _m, _o) \
do {\
    irm_memcpy(IRM_MBUF_M2D(_m) + (_o), (_s)->data, (_s)->data_size);\
    IRM_MBUF_DATA_SIZE(_m) = (_s)->data_size;\
} while (0)

static struct irm_netio_ops* pub_netops[] = {
    &native_netops,
#ifdef IRM_ENABLE_EFVI
    &efvi_netops,
#endif
    NULL
};

static uint32_t pub_tx_valve[2] = {IRM_BUFFER_VALVE_OFF, IRM_BUFFER_VALVE_ON};

static void* irm_pub_context_event_loop(void* arg);
    
static struct irm_sub_info* irm_pub_context_sub_info_create(
    void* mpool, struct irm_config* cfg);
static struct irm_sub_info* irm_pub_context_sub_info_create_temp(
    void* mpool, struct irm_config* cfg);
static struct irm_sub_info* irm_pub_context_sub_info_create_keep(
    struct irm_config* cfg);
static void irm_pub_context_sub_info_release(struct irm_sub_info* subs);

static void irm_pub_context_ask_init(struct irm_pub_context* ctx);
IRM_HOT_CALL static void irm_pub_context_ask_handle(
    struct irm_pub_context* ctx, struct irm_mbuf* mbuf);

IRM_HOT_CALL static IRM_ALWAYS_INLINE void irm_pub_context_nack_handle(
    struct irm_pub_context* ctx, struct irm_mbuf* mbuf);
IRM_HOT_CALL static void irm_pub_context_lost_from_buffer(
    struct irm_pub_context* ctx, const uint8_t sender_id,
    const uint32_t nack_seq, const uint32_t start, const uint32_t end);

static void irm_pub_context_resend_init(struct irm_pub_context* ctx);

IRM_HOT_CALL static int irm_pub_context_resend_from_storage(
    struct irm_pub_context* ctx, uint32_t seq, uint8_t target_id);
IRM_HOT_CALL static void irm_pub_context_resend_from_buffer(
    struct irm_pub_context* ctx, struct irm_mbuf* mbuf,
    const uint8_t sender_id);

static void irm_pub_context_invitation_init(struct irm_pub_context* ctx);
static int irm_pub_context_invitation(struct irm_pub_context* ctx);
IRM_HOT_CALL static void irm_pub_context_invitation_handle(
    struct irm_pub_context* ctx, struct irm_mbuf* mbuf);

static void irm_pub_context_close_init(struct irm_pub_context* ctx);

IRM_HOT_CALL static void irm_pub_context_close_handle(
    struct irm_pub_context* ctx, struct irm_mbuf* mbuf);

IRM_HOT_CALL static IRM_ALWAYS_INLINE void irm_pub_context_heartbeat_handle(
    struct irm_pub_context* ctx, struct irm_mbuf* mbuf);

static void irm_pub_context_lost_data_init(struct irm_pub_context* ctx);
static void irm_pub_context_data_init(struct irm_pub_context* ctx);

static void irm_pub_context_breakpoint_init(struct irm_pub_context* ctx);
IRM_HOT_CALL static IRM_ALWAYS_INLINE void irm_pub_context_breakpoint_check(
    struct irm_pub_context* ctx, const uint64_t curr_ts,
    uint64_t* const breakpoint_ts, const uint64_t heartbeat_timeout);

IRM_HOT_CALL static IRM_ALWAYS_INLINE int irm_pub_context_msg_handle(
    void* ctx, struct irm_mbuf* mbuf);

IRM_HOT_CALL static IRM_ALWAYS_INLINE void irm_pub_context_update_desc(
    struct irm_pub_context* ctx, struct irm_msg_header* header);

IRM_HOT_CALL static void irm_pub_context_check_alive(
    struct irm_pub_context* ctx);

IRM_HOT_CALL static void IRM_ALWAYS_INLINE irm_pub_context_fifo(
    struct irm_pub_context* ctx);

static int irm_pub_config_check(const struct irm_config* cfg);

static int irm_pub_config_check(const struct irm_config* cfg)
{

    if (!cfg->addr.mcgroup_port) {
        IRM_ERR("multicast group port config error");
        return -IRM_ERR_CONFIG;
    }
    if (!cfg->addr.mcgroup_ip[0]) {
        IRM_ERR("multicast group ip config error");
        return -IRM_ERR_CONFIG;
    }

    if (!cfg->addr.local_port) {
        IRM_ERR("local port config error");
        return -IRM_ERR_CONFIG;
    }

    if (!cfg->addr.local_ip[0]) {
        IRM_ERR("local ip config error");
        return -IRM_ERR_CONFIG;
    }

    if (cfg->io_mode < IRM_SOCKET_TYPE_NATIVE
        || cfg->io_mode >= IRM_SOCKET_TYPE_MAX) {
        IRM_ERR("io mode config error");
        return -IRM_ERR_CONFIG;
    }

    switch (cfg->io_mode) {
        case IRM_SOCKET_TYPE_NATIVE:
            if (cfg->tx.mbuf_count < IRM_CONFIG_PUB_TX_MBUF_COUNT_MIN) {
                IRM_ERR("tx mbuf count config error, must more than %u",
                    IRM_CONFIG_PUB_TX_MBUF_COUNT_MIN);
                return -IRM_ERR_CONFIG;
            }
            break;
#ifdef IRM_ENABLE_EFVI
        case IRM_SOCKET_TYPE_EFVI:
            if (cfg->tx.mbuf_count <  IRM_CONFIG_PUB_TX_MBUF_COUNT_MIN ||
                cfg->tx.mbuf_count > IRM_CONFIG_PUB_TX_MBUF_COUNT_DEFAULT) {
                IRM_ERR("tx mbuf count config error, must in [%u, %u]",
                    IRM_CONFIG_PUB_TX_MBUF_COUNT_MIN,
                    IRM_CONFIG_PUB_TX_MBUF_COUNT_DEFAULT);
                return -IRM_ERR_CONFIG;
            }
            break;
#endif
    }
    if (cfg->rx.mbuf_count <  IRM_CONFIG_PUB_RX_MBUF_COUNT_DEFAULT) {
        IRM_ERR("rx mbuf count config error");
        return -IRM_ERR_CONFIG;
    }
    return IRM_OK;
}

struct irm_pub_context* irm_pub_context_create(void)
{
    struct irm_pub_context* ctx;

    ctx = IRM_PUB_CTX(calloc(1, sizeof(struct irm_pub_context)));
    if (!ctx) {
        IRM_ERR("pub context calloc failed");
        irm_errno = -IRM_ERR_PUB_CONTEXT_CALLOC;
        return NULL;
    }
    return ctx; 
}

int irm_pub_context_init(struct irm_pub_context* ctx)
{
    struct irm_config*      cfg = &ctx->cfg;
    struct irm_netio*       netio = NULL;
    struct irm_netio_ops*   netops = pub_netops[cfg->io_mode];
    struct irm_sub_info*    subs = NULL;
    struct irm_buffer*      tx_buffer = NULL;
    void*                   mpool = NULL;
    uint32_t                flags;
    int                     ret;

    ret = irm_pub_config_check(cfg);
    if (ret != IRM_OK) {
        IRM_ERR("create pub context failed, config error %d", ret);
        irm_errno = ret;
        goto IRM_ERR_OUT;
    }
    mpool = irm_memory_pool_create(cfg->memory.pool_size);
    if (!mpool) {
        IRM_ERR("create pub context failed, memory pool create error %d",
            irm_errno);
        goto IRM_ERR_OUT;
    }

    tx_buffer = irm_buffer_create(mpool, cfg->tx.mbuf_count);
    if (!tx_buffer) {
        IRM_ERR("create pub context error, tx_buffer create failed, err %d",
            irm_errno);
    }
    subs = irm_pub_context_sub_info_create(mpool, cfg);
    if (!subs) {
        IRM_ERR("create pub context error, sub info create failed, err %d",
            irm_errno);
        goto IRM_ERR_OUT;
    }

    netops = pub_netops[cfg->io_mode];
    netio = netops->create(mpool, cfg);
    if (!netio) {
        IRM_ERR("create pub context error, netio create failed, err %d",
            irm_errno);
        goto IRM_ERR_OUT;
    }
    cfg->rv.mbuf_count = IRM_PUB_RESERVE_MBUF_MAX;
    if (cfg->storage.enable) {
        cfg->rv.mbuf_count += IRM_PUB_RESEND_MBUF_N;
    }
    ret = netops->init(mpool, netio);
    if (ret != IRM_OK) {
        irm_errno = ret;
        IRM_ERR("create pub context error, netio init failed, err %d", ret);
        goto IRM_ERR_OUT;
    }
    flags = IRM_POOL_MGR_SINGLE_CONS | IRM_POOL_MGR_SINGLE_PROD; 
    irm_netio_set_option(netio, IRM_NETIO_OPTION_MBUF_RV_POOL, &flags, sizeof(flags));
    irm_netio_set_option(netio, IRM_NETIO_OPTION_MBUF_RX_POOL, &flags, sizeof(flags));

    netio->process_msg_rx_handle = irm_pub_context_msg_handle;
    netio->process_msg_tx_handle = NULL;
    netio->tx_buffer = tx_buffer;
    netio->rx_buffer = NULL;
    netio->ctx = ctx;

    ctx->mpool = mpool;
    ctx->token = irm_get_token();
    ctx->self_id = ((uint8_t *)&netio->local_ip_be32)[3];
    ctx->subs = subs;
    ctx->tx_buffer = tx_buffer;
    IRM_BUFFER_VALVE(tx_buffer, IRM_BUFFER_VALVE_OFF);

    ctx->netio = netio;
    ctx->netops = *netops;

    if (cfg->storage.enable) {
        irm_pub_context_resend_init(ctx);
        
        ret = irm_storage_init(mpool, &ctx->storage, netio,
            netops->payload_offset, cfg);
        if (ret != IRM_OK) {
            IRM_ERR("pub context storage init failed error %d", ret);
            irm_storage_deinit(&ctx->storage);
        }
        
    }

    irm_pub_context_invitation_init(ctx);
    irm_pub_context_ask_init(ctx);
    irm_pub_context_close_init(ctx);
    irm_pub_context_lost_data_init(ctx);
    irm_pub_context_breakpoint_init(ctx);
    irm_pub_context_data_init(ctx);

    ret = pthread_create(&ctx->event_loop_thread_id, NULL,
        irm_pub_context_event_loop, ctx);
    if (ret) {
        IRM_ERR("pub context event loop start failed, error %s", strerror(ret));    
        irm_errno = -IRM_ERR_PUB_CONTEXT_EVENT_LOOP;
    }

IRM_ERR_OUT:
    if (irm_errno != IRM_OK) {
        if (subs) {
            irm_pub_context_sub_info_release(subs);
        }
        if (netio) {
            netops->deinit(netio);
        }
        irm_storage_deinit(&ctx->storage);
        irm_memory_pool_release(mpool);
    }
    return irm_errno; 
}

void irm_pub_context_release(struct irm_pub_context* ctx)
{
    if (!ctx) {
        return;
    }

    IRM_RMB();

    irm_storage_deinit(&ctx->storage);

    ctx->quit = IRM_TRUE;

    if (ctx->event_loop_thread_id) {
        pthread_join(ctx->event_loop_thread_id, NULL);
    }
    irm_pub_context_sub_info_release(ctx->subs);
    if (ctx->netio) {
        ctx->netops.deinit(ctx->netio);
    }
    irm_memory_pool_release(ctx->mpool);
    free(ctx);
}

static struct irm_sub_info* 
irm_pub_context_sub_info_create_keep(struct irm_config* cfg)
{
    struct irm_sub_info* subs;
    size_t               size;

    size = IRM_SIZE_ALIGN(sizeof(struct irm_sub_info), cfg->hugepage_size);
    subs = (struct irm_sub_info *)irm_load_state(cfg->path, cfg->path_len, size,
        IRM_PUB_MAGIC, IRM_PUB_VERSION);
    if (!subs)  {
        return NULL;
    }
    subs->size = size;
    IRM_MEM_LOCK(subs, size);
    irm_errno = IRM_OK;
    
    return subs;
}

static struct irm_sub_info* 
irm_pub_context_sub_info_create_temp(void* mpool,
    struct irm_config* cfg)
{
    struct irm_sub_info* subs;
    size_t               size;

    size = sizeof(struct irm_sub_info);
    subs = (struct irm_sub_info *)irm_memory_calloc_align(mpool, size,
        IRM_CACHELINE);
    if (!subs) {
        IRM_ERR("sub temp info create, alloc error %d", irm_errno);
        return NULL;
    }

    irm_errno = IRM_OK;
    subs->size = 0;

    return subs; 
}

static struct irm_sub_info*
irm_pub_context_sub_info_create(void* mpool,
    struct irm_config* cfg)
{
    struct irm_sub_info* subs;
    struct irm_sub_desc* desc;
    int                  i;

    if (!cfg->path_len) {
        subs = irm_pub_context_sub_info_create_temp(mpool, cfg);
    } else {
        subs = irm_pub_context_sub_info_create_keep(cfg);
    }

    desc = subs->desc;
    for (i = 0; i < IRM_SUB_MAX; ++i) {
        desc[i].slot = -1;    
        desc[i].ip_be32 = 0;
        desc[i].alive = IRM_FALSE;
        desc[i].online = IRM_FALSE;
        desc[i].idle_times = 0;
    }
    subs->alive_count = 0;    
    return subs;
}

static void irm_pub_context_sub_info_release(struct irm_sub_info* subs)
{
    uint32_t size;
    if (!subs || !subs->size) {
        return;
    }
    size = subs->size;
    IRM_MEM_UNLOCK(subs, size);
    munmap(subs, size);
}

static void irm_pub_context_invitation_init(struct irm_pub_context* ctx)
{
    struct irm_mbuf*                mbuf;
    struct irm_msg_invitation*      msg;

    mbuf = irm_mbuf_get(&ctx->netio->rv_pool);
    msg = IRM_MBUF_MSG(irm_msg_invitation, mbuf, ctx->netops.payload_offset);
    msg->header.msg_type = IRM_MSG_TYPE_INVITATION;
    msg->header.role = IRM_ROLE_TYPE_PUB;
    msg->header.sender_id = ctx->self_id;
    msg->header.source_id = ctx->self_id;
    msg->header.target_id = 0;
    msg->header.seq = 0;
    msg->header.size = sizeof(struct irm_msg_invitation_body);
    msg->header.token = ctx->token;
    msg->header.ip_be32 = ctx->netio->local_ip_be32;
    mbuf->size = sizeof(struct irm_msg_invitation);
    mbuf->reserved = IRM_TRUE;
    ctx->reserved_mbufs[IRM_PUB_INVITATION_MBUF_ID] = mbuf;

    IRM_DBG("mbuf %p, header %p, id %u, msg type %u, prev %p, next %p",
        mbuf, msg, mbuf->id, msg->header.msg_type,
        mbuf->cache_ln.prev, mbuf->cache_ln.next);
}

static int irm_pub_context_invitation(struct irm_pub_context* ctx)
{
    struct irm_config*          cfg = &ctx->cfg;
    struct irm_mbuf*            invitation_mbuf;
    struct irm_msg_header*      header;
    uint32_t                    i;
    int                         ret = IRM_OK;
    int                         retry; 
    int                         abort = IRM_FALSE;
    const uint32_t              offset = ctx->netops.payload_offset;

    invitation_mbuf = ctx->reserved_mbufs[IRM_PUB_INVITATION_MBUF_ID];
    header = IRM_MBUF_MSG(irm_msg_header, invitation_mbuf, offset);

    for (i = 0; i < cfg->invitation.times; ++i) {
        IRM_DBG("pub send invitation times %u invitation_mbuf %p, id %u",
            i + 1, invitation_mbuf, invitation_mbuf->id);
        retry = cfg->invitation.retry;
        while (retry--) {
            header->seq = ctx->invitation_seq;
            ret = ctx->netops.send(ctx->netio, invitation_mbuf);
            if (ret == IRM_OK) {
                ++ctx->invitation_seq;
                break;
            }
            if (ret != IRM_OK && ret != -IRM_ERR_SEND_AGAIN) {
                abort = IRM_TRUE;
                break;
            }    
            usleep(100 * 1000);
            IRM_DBG("pub send invitation again");
        }
        if (abort || !retry) {
            IRM_ERR("pub send invitation aborted ret %d, err %d, retry %d",
                ret, irm_errno, retry);
            ctx->quit = IRM_TRUE;
            return -IRM_ERR_PUB_INVITATION;
        }
        usleep(300 * 1000);
    }
    return ret;
}

IRM_HOT_CALL static void
irm_pub_context_invitation_handle(struct irm_pub_context* ctx,
    struct irm_mbuf* mbuf)
{
    struct irm_config*          cfg = &ctx->cfg;
    struct irm_msg_invitation*  msg;
    struct irm_mbuf*            ask_mbuf;
    struct irm_msg_ask*         ask_msg;
    uint8_t                     sender_id;
    int                         ret;
    int                         retry;
    int                         abort = IRM_FALSE;
    const uint32_t              offset = ctx->netops.payload_offset;

    msg = IRM_MBUF_MSG(irm_msg_invitation, mbuf, offset);

    IRM_DBG("receive invitation sender_id %u, seq %u",
        msg->header.sender_id, msg->header.seq);

    ask_mbuf = ctx->reserved_mbufs[IRM_PUB_ASK_MBUF_ID];
    ask_msg = IRM_MBUF_MSG(irm_msg_ask, ask_mbuf, offset);
    ask_msg->header.seq = msg->header.seq;
    ask_msg->body.last_seq = 0;
    sender_id = msg->header.sender_id;

    irm_mbuf_put(&ctx->netio->rx_pool, mbuf);
    if (ask_mbuf->status != IRM_MBUF_STATUS_IDLE) {
        IRM_DBG("ask mbuf is sending, id %u", ask_mbuf->id);
        return;
    }

    retry = cfg->retry;
    while (retry--) {
        ask_msg->header.target_id = sender_id;
        ret = ctx->netops.send(ctx->netio, ask_mbuf);
        if (ret == IRM_OK) {
            break;
        }
        ask_mbuf->status = IRM_MBUF_STATUS_IDLE;
        if (ret != IRM_OK && ret != -IRM_ERR_SEND_AGAIN) {
            abort = IRM_TRUE;
            break;
        }    
        usleep(100 * 1000);
        IRM_DBG("pub send ask again");
    }
    if (abort || !retry) {
        IRM_ERR("pub ask failed");
        ctx->quit = IRM_TRUE;
    }
}

static void irm_pub_context_ask_init(struct irm_pub_context* ctx)
{
    struct irm_mbuf*    mbuf;
    struct irm_msg_ask* msg;
    
    mbuf = irm_mbuf_get(&ctx->netio->rv_pool);
    IRM_DBG("mbuf %p, id %u, prev %p, next %p", mbuf, mbuf->id,
        mbuf->cache_ln.prev, mbuf->cache_ln.next);
    msg = IRM_MBUF_MSG(irm_msg_ask, mbuf, ctx->netops.payload_offset);
    msg->header.msg_type = IRM_MSG_TYPE_ASK;
    msg->header.role = IRM_ROLE_TYPE_PUB;
    msg->header.sender_id = ctx->self_id;
    msg->header.target_id = 0;
    msg->header.source_id = ctx->self_id;
    msg->header.seq = 0;
    msg->header.token = ctx->token;
    msg->header.ip_be32 = ctx->netio->local_ip_be32;
    msg->body.last_seq = 0;
    msg->header.size = sizeof(struct irm_msg_ask_body);
    mbuf->size = sizeof(struct irm_msg_ask);
    mbuf->reserved = IRM_TRUE;
    ctx->reserved_mbufs[IRM_PUB_ASK_MBUF_ID] = mbuf;
}

IRM_HOT_CALL static void
irm_pub_context_ask_handle(struct irm_pub_context* ctx,
    struct irm_mbuf* mbuf)
{
#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
    struct irm_msg_header* header;
    header = IRM_MBUF_MSG(irm_msg_header, mbuf, ctx->netops.payload_offset);
    IRM_DBG("receive ask sender_id %u, seq %u", header->sender_id,
        header->seq);
#endif
    irm_mbuf_put(&ctx->netio->rx_pool, mbuf);
}

static void irm_pub_context_close_init(struct irm_pub_context* ctx)
{
    struct irm_mbuf*        mbuf;
    struct irm_msg_close*   msg;

    mbuf = irm_mbuf_get(&ctx->netio->rv_pool);
    msg = IRM_MBUF_MSG(irm_msg_close, mbuf, ctx->netops.payload_offset);
    msg->header.msg_type = IRM_MSG_TYPE_CLOSE;
    msg->header.role = IRM_ROLE_TYPE_PUB;
    msg->header.sender_id = ctx->self_id;
    msg->header.source_id = ctx->self_id;
    msg->header.target_id = 0;
    msg->header.seq = 0;
    msg->header.size = sizeof(struct irm_msg_close_body);
    msg->header.token = ctx->token;
    msg->header.ip_be32 = ctx->netio->local_ip_be32;
    mbuf->size = sizeof(struct irm_msg_close);
    mbuf->reserved = IRM_TRUE;
    ctx->reserved_mbufs[IRM_PUB_CLOSE_MBUF_ID] = mbuf;

    IRM_DBG("mbuf %p, header %p, id %u, msg type %u, prev %p, next %p",
        mbuf, msg, mbuf->id, msg->header.msg_type,
        mbuf->cache_ln.prev, mbuf->cache_ln.next);
}

void irm_pub_context_close(struct irm_pub_context* ctx)
{
    struct irm_config*      cfg = &ctx->cfg;
    struct irm_mbuf*        mbuf;
    uint32_t                i;
    int                     retry; 
    int                     ret;

     if (!ctx || !ctx->netio) {
        return;
    }
    mbuf = ctx->reserved_mbufs[IRM_PUB_CLOSE_MBUF_ID];

    for (i = 0; i < cfg->invitation.times; ++i) {
        IRM_DBG("pub send close times %u mbuf %p, id %u", i + 1, mbuf, mbuf->id);
        retry = cfg->invitation.retry;
        while (retry--) {
            ret = ctx->netops.send(ctx->netio, mbuf);
            if (ret == IRM_OK) {
                break;
            }
            mbuf->status = IRM_MBUF_STATUS_IDLE;
            usleep(100);
            IRM_DBG("pub send close again");
        }
        usleep(100);
    }
}

IRM_HOT_CALL static void
irm_pub_context_close_handle(struct irm_pub_context* ctx,
    struct irm_mbuf* mbuf)
{
    struct irm_msg_header*  header;
    struct irm_sub_desc*    desc;
    const uint32_t          offset = ctx->netops.payload_offset;
    uint8_t*                alives = ctx->subs->alives;
    uint8_t                 alive_count = ctx->subs->alive_count;
    

    header = IRM_MBUF_MSG(irm_msg_header, mbuf, offset);
    IRM_DBG("receive close sender_id %u, seq %u, token %u",
        header->sender_id, header->seq, header->token);

    desc = &ctx->subs->desc[header->sender_id];
    irm_mbuf_put(&ctx->netio->rx_pool, mbuf);

    alives[desc->slot] = alives[alive_count - 1];
    alives[alive_count - 1] = 0;
    --ctx->subs->alive_count;

    desc->online = IRM_FALSE;
    desc->slot = -1;
    desc->idle_times = 0;
    desc->ip_be32 = 0;
    desc->alive = IRM_FALSE;
}

static void irm_pub_context_breakpoint_init(struct irm_pub_context* ctx)
{
    struct irm_mbuf*            mbuf;
    struct irm_msg_breakpoint*  msg;
    
    mbuf = irm_mbuf_get(&ctx->netio->rv_pool);
    IRM_DBG("mbuf %p", mbuf);
    IRM_DBG("mbuf %p, id %u, prev %p, next %p", mbuf, mbuf->id,
        mbuf->cache_ln.prev, mbuf->cache_ln.next);
    msg = IRM_MBUF_MSG(irm_msg_breakpoint, mbuf, ctx->netops.payload_offset);
    msg->header.msg_type = IRM_MSG_TYPE_BREAKPOINT;
    msg->header.role = IRM_ROLE_TYPE_PUB;
    msg->header.sender_id = ctx->self_id;
    msg->header.target_id = 0;
    msg->header.token = ctx->token;
    msg->header.ip_be32 = ctx->netio->local_ip_be32;
    msg->header.source_id = ctx->self_id;
    msg->header.seq = 0;
    msg->body.last_send_seq = 0;
    msg->body.heartbeat = IRM_FALSE;
    msg->header.size = sizeof(struct irm_msg_breakpoint_body);
    mbuf->size = sizeof(struct irm_msg_breakpoint);
    mbuf->reserved = IRM_TRUE;
    ctx->reserved_mbufs[IRM_PUB_BREAKPOINT_MBUF_ID] = mbuf;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE void
irm_pub_context_breakpoint_check(struct irm_pub_context* ctx,
    const uint64_t curr_ts, uint64_t* const breakpoint_ts,
    const uint64_t heartbeat_timeout)
{
    struct irm_mbuf*            mbuf;
    struct irm_msg_breakpoint*  msg; 
    int64_t                     last_send_seq = ctx->netio->last_send_seq;
    uint8_t                     heartbeat = IRM_FALSE;
  
    mbuf = ctx->reserved_mbufs[IRM_PUB_BREAKPOINT_MBUF_ID];
    if (mbuf->status != IRM_MBUF_STATUS_IDLE) {
        return;
    }

    if (last_send_seq < 0) {
        heartbeat = IRM_TRUE;
        last_send_seq = 0;
    }

    if (irm_txbuffer_available(ctx->netio->tx_buffer)) {
        heartbeat = IRM_TRUE;
        last_send_seq = 0;
    }
    if (heartbeat && curr_ts - *breakpoint_ts < heartbeat_timeout) {
        IRM_DBG("do not send breakpoing, heartbeat %u, curr_ts %lu, "
            "breakpoint_ts %lu, heartbeat_timeout %lu",
            heartbeat, curr_ts, *breakpoint_ts, heartbeat_timeout);
        return;
    }
    msg = IRM_MBUF_MSG(irm_msg_breakpoint, mbuf, ctx->netops.payload_offset);
    msg->header.seq = ctx->breakpoint_seq;
    msg->body.last_send_seq = (uint32_t)last_send_seq;
    msg->body.heartbeat = heartbeat;
    if (ctx->netops.send(ctx->netio, mbuf) != IRM_OK) {
        IRM_DBG("breakpoint msg send failed, heartbeat %u", heartbeat);
        mbuf->status = IRM_MBUF_STATUS_IDLE; 
        return;
    }

    IRM_DBG("last_send_seq %ld, breakpoint_seq %u, heartbeat %u",
        last_send_seq, ctx->breakpoint_seq, heartbeat); 
    ++ctx->breakpoint_seq;
    *breakpoint_ts = curr_ts;
}

static void irm_pub_context_data_init(struct irm_pub_context* ctx)
{
    struct irm_mbuf_pool_mgr* tx_pool = &ctx->netio->tx_pool;
    struct irm_msg_header*    header;
    uint32_t                  i;

    for (i = 0; i < tx_pool->count; ++i) {
        header = IRM_MBUF_MSG(irm_msg_header, tx_pool->ring[i],
            ctx->netops.payload_offset);    
        header->msg_type = IRM_MSG_TYPE_DATA;
        header->role = IRM_ROLE_TYPE_PUB; 
        header->sender_id = ctx->self_id;
        header->target_id = 0;
        header->token = ctx->token;
        header->ip_be32 = ctx->netio->local_ip_be32;
        header->token = ctx->token;
        header->source_id = ctx->self_id;
        header->seq = 0;
        header->size = 0;
    }
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE void
irm_pub_context_heartbeat_handle(struct irm_pub_context* ctx,
    struct irm_mbuf* mbuf)
{
#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
    struct irm_msg_header* header;
    header = IRM_MBUF_MSG(irm_msg_header, mbuf, ctx->netops.payload_offset);
    IRM_DBG("receive heartbeat sender_id %u, seq %u", header->sender_id,
        header->seq);
#endif
    irm_mbuf_put(&ctx->netio->rx_pool, mbuf);
}

static void irm_pub_context_lost_data_init(struct irm_pub_context* ctx)
{
    struct irm_mbuf*            mbuf;
    struct irm_msg_lost_data*   msg;

    mbuf = irm_mbuf_get(&ctx->netio->rv_pool);
    IRM_DBG("mbuf %p, id %u, prev %p, next %p", mbuf, mbuf->id,
        mbuf->cache_ln.prev, mbuf->cache_ln.next);
    msg = IRM_MBUF_MSG(irm_msg_lost_data, mbuf, ctx->netops.payload_offset);
    msg->header.msg_type = IRM_MSG_TYPE_LOST_DATA;
    msg->header.role = IRM_ROLE_TYPE_PUB;
    msg->header.sender_id = ctx->self_id;
    msg->header.target_id = 0;
    msg->header.source_id = ctx->self_id;
    msg->header.seq = 0;
    msg->header.token = ctx->token;
    msg->header.ip_be32 = ctx->netio->local_ip_be32;
    msg->header.size = sizeof(struct irm_msg_lost_data_body);
    msg->body.old_start = 0;
    msg->body.current_start = 0;
    msg->body.old_end = 0;
    msg->body.current_end = 0;
    msg->body.count = 0;
    mbuf->size = sizeof(struct irm_msg_lost_data);
    mbuf->reserved = IRM_TRUE;
    ctx->reserved_mbufs[IRM_PUB_LOST_DATA_MBUF_ID] = mbuf;
}

static void irm_pub_context_resend_init(struct irm_pub_context* ctx)
{
    uint32_t i;
    for (i = 0; i < IRM_PUB_RESEND_MBUF_N; ++i) {
        ctx->resend_mbufs[i] = irm_mbuf_get(&ctx->netio->rv_pool);
    }
}

IRM_HOT_CALL static int
irm_pub_context_resend_from_storage(struct irm_pub_context* ctx, uint32_t seq,
    uint8_t target_id)
{
    struct irm_msg_header* header;
    struct irm_sobj*       sobj;
    struct irm_mbuf*       mbuf = NULL;
    uint32_t               i;
    const uint32_t         offset = ctx->netops.payload_offset;

    sobj = irm_storage_get(&ctx->storage, seq);
    if (!sobj) {
        IRM_ERR("seq %u not found in storage, target_id %u", seq, target_id);
        return IRM_FALSE;
    }

    for (i = 0; i < IRM_PUB_RESEND_MBUF_N; ++i) {
        if (ctx->resend_mbufs[i]->status == IRM_MBUF_STATUS_IDLE) {
            mbuf = ctx->resend_mbufs[i];
            IRM_DBG("idle mbuf %p, id %u", mbuf, mbuf->id);
            break;
        }
        IRM_DBG("mbuf %p, id %u i %u not idle", ctx->resend_mbufs[i],
            ctx->resend_mbufs[i]->id, i);
    }

    if (!mbuf) {
        IRM_DBG("have no idle resend_mbuf, seq %u, target_id %u",
            seq, target_id);
        return IRM_TRUE;
    }

    IRM_PUB_SOBJ2MBUF(sobj, mbuf, offset);
    IRM_DBG("SOBJ2MBUF mbuf %p, sobj->data_size %u, sobj->size %u, mubf->size %u",
        mbuf, sobj->data_size, sobj->size, mbuf->size);
    irm_storage_put(&ctx->storage, sobj);

    header = IRM_MBUF_MSG(irm_msg_header, mbuf, offset);
    IRM_DBG("mbuf %p, header seq %u, msg type %u, msg size %u, target_id %u:%u",
        mbuf, header->seq, header->msg_type, header->size, header->target_id,
        target_id);
    header->target_id = target_id;

    if (ctx->netops.send(ctx->netio, mbuf) != IRM_OK) {
        mbuf->status = IRM_MBUF_STATUS_IDLE;
        IRM_DBG("resend msg from storage failed seq %u, target_id %u",
            header->seq, target_id);
    }

    return IRM_TRUE;
}

IRM_HOT_CALL static void
irm_pub_context_resend_from_buffer(struct irm_pub_context* ctx,
    struct irm_mbuf* mbuf, const uint8_t sender_id)
{

    struct irm_msg_header*    header;
    const uint32_t            offset = ctx->netops.payload_offset;

    if (mbuf->status != IRM_MBUF_STATUS_IDLE) {
        IRM_DBG("data mbuf is sending, id %u target_id %u",
            mbuf->id, sender_id);
        return;
    }
    header = IRM_MBUF_MSG(irm_msg_header, mbuf, offset);
    header->target_id = sender_id;
    if (ctx->netops.send(ctx->netio, mbuf) != IRM_OK) {
        IRM_DBG("resend msg send failed, seq %u, target_id %u",
            header->seq, sender_id);
#ifdef IRM_TRACE
        IRM_WARN("resend msg send failed, seq %u, target_id %u",
            header->seq, sender_id);
        IRM_WARN("after resend mbuf available count %u, buffer count %u",
            irm_mbuf_available(&ctx->netio->tx_pool),
            ctx->netio->tx_buffer->tail - ctx->netio->tx_buffer->head);
#endif
        mbuf->status = IRM_MBUF_STATUS_IDLE;
    }
}

IRM_HOT_CALL static void
irm_pub_context_lost_from_buffer(struct irm_pub_context* ctx,
    const uint8_t sender_id, const uint32_t nack_seq,
    const uint32_t start, const uint32_t end)
{
    struct irm_mbuf*          lost_mbuf;
    struct irm_mbuf*          resend_mbuf;
    struct irm_msg_header*    header;
    struct irm_msg_lost_data* lost;
    const uint32_t            offset = ctx->netops.payload_offset;
    uint32_t                  i = start;
    uint32_t                  lost_end = 0;
    uint32_t                  lost_start = 0;
    uint32_t                  current_start = 0;
    uint32_t                  current_end = 0;
    uint32_t                  count = 0;

IRM_REDO_LOST_FROM_BUFFER:
    for (; i <= end; ++i) {
        resend_mbuf = (struct irm_mbuf *)irm_buffer_pick(ctx->tx_buffer, i);
        header = IRM_MBUF_MSG(irm_msg_header, resend_mbuf, offset);
        if (header->seq == i) {
            break;
        }
        if (!lost_start) {
            lost_start = i;
            current_start = header->seq;
        }
        lost_end = i;
        current_end = header->seq;
        ++count;
    }

    if (!count) {
        goto IRM_BUFFER_RESEND;
    }

    lost_mbuf = ctx->reserved_mbufs[IRM_PUB_LOST_DATA_MBUF_ID];
    lost = IRM_MBUF_MSG(irm_msg_lost_data, lost_mbuf, offset);
    lost->header.target_id = sender_id;
    lost->header.seq = nack_seq;
    lost->body.old_start = lost_start;
    lost->body.current_start = current_start; 
    lost->body.old_end = lost_end;
    lost->body.current_end = current_end;
    lost->body.count = count;

    IRM_DBG("irreversible sender_id %u, start %u:%u:%u, end %u:%u:%u, "
        "count %u, nack_seq %u", sender_id, start, lost_start, current_start,
        end, lost_end, current_end, count, nack_seq);

    if (lost_mbuf->status != IRM_MBUF_STATUS_IDLE) {
        IRM_DBG("lost mbuf is sending, id %u", lost_mbuf->id);    
        goto IRM_BUFFER_RESEND;
    }
    if (ctx->netops.send(ctx->netio, lost_mbuf) != IRM_OK) {
        IRM_DBG("lost msg sending failed");
        lost_mbuf->status = IRM_MBUF_STATUS_IDLE;
    }

IRM_BUFFER_RESEND:
    for (; i <= end; ++i) {
        resend_mbuf = (struct irm_mbuf *)irm_buffer_pick(ctx->tx_buffer, i);
        header = IRM_MBUF_MSG(irm_msg_header, resend_mbuf, offset);
        if (header->seq != i) {
            IRM_DBG("lost msg old_seq %u, current seq %u, sender_id %u, "
                "start %u, end %u, nack_seq %u", i, header->seq,
                sender_id, start, end, nack_seq);
            break;
        }
        irm_pub_context_resend_from_buffer(ctx, resend_mbuf, sender_id);
    }
    
    if (i <= end) {
        IRM_DBG("REDO_LOST_FROM_BUFFER sender_id %u, i %u, start %u, end %u, "
            "nack_seq %u", sender_id, i, start, end, nack_seq);
        lost_start = 0;
        count = 0;
        goto IRM_REDO_LOST_FROM_BUFFER;
    }

}

IRM_HOT_CALL static void
irm_pub_context_lost_from_storage(struct irm_pub_context* ctx,
    const uint8_t sender_id, const uint32_t nack_seq,
    const uint32_t start, const uint32_t end)
{
    struct irm_mbuf*          lost_mbuf;
    struct irm_mbuf*          resend_mbuf;
    struct irm_msg_header*    header;
    struct irm_msg_lost_data* lost;
    const uint32_t            offset = ctx->netops.payload_offset;
    uint32_t                  i = start;
    uint32_t                  lost_end = 0;
    uint32_t                  lost_start = 0;
    uint32_t                  current_start = 0;
    uint32_t                  current_end = 0;
    uint32_t                  count = 0;

IRM_REDO_LOST_FROM_STORAGE:
    for (; i <= end; ++i) {
        resend_mbuf = (struct irm_mbuf *)irm_buffer_pick(ctx->tx_buffer, i);
        header = IRM_MBUF_MSG(irm_msg_header, resend_mbuf, offset);
        if (header->seq == i) {
            IRM_DBG("in buffer msg seq %u, sender_id %u, start %u, end %u, "
                "nack_seq %u", i, sender_id, start, end, nack_seq);
            break;
        }

        if (irm_storage_lookup(&ctx->storage, i)) {
            IRM_DBG("in storage msg seq %u, sender_id %u, start %u, end %u, "
                "nack_seq %u", i, sender_id, start, end, nack_seq);
            break;
        }

        if (!lost_start) {
            lost_start = i;
            current_start = header->seq;
        }
        lost_end = i;
        current_end = header->seq;
        ++count;
    }

    if (!count) {
        goto IRM_STORAGE_RESEND;
    }

    lost_mbuf = ctx->reserved_mbufs[IRM_PUB_LOST_DATA_MBUF_ID];
    lost = IRM_MBUF_MSG(irm_msg_lost_data, lost_mbuf, offset);
    lost->header.target_id = sender_id;
    lost->header.seq = nack_seq;
    lost->body.old_start = lost_start;
    lost->body.current_start = current_start; 
    lost->body.old_end = lost_end;
    lost->body.current_end = current_end;
    lost->body.count = count;

    IRM_DBG("irreversible sender_id %u, start %u:%u:%u, end %u:%u:%u, "
        "count %u, nack_seq %u", sender_id, start, lost_start, current_start,
        end, lost_end, current_end, count, nack_seq);

    if (lost_mbuf->status != IRM_MBUF_STATUS_IDLE) {
        IRM_DBG("lost mbuf is sending, id %u", lost_mbuf->id);    
        goto IRM_STORAGE_RESEND;
    }
    if (ctx->netops.send(ctx->netio, lost_mbuf) != IRM_OK) {
        IRM_DBG("lost msg sending failed");
        lost_mbuf->status = IRM_MBUF_STATUS_IDLE;
    }

IRM_STORAGE_RESEND:
    for (; i <= end; ++i) {
        resend_mbuf = (struct irm_mbuf *)irm_buffer_pick(ctx->tx_buffer, i);
        header = IRM_MBUF_MSG(irm_msg_header, resend_mbuf, offset);
        if (header->seq == i) {
            irm_pub_context_resend_from_buffer(ctx, resend_mbuf, sender_id);
            continue;
        }

        if (!irm_pub_context_resend_from_storage(ctx, i, sender_id)) {
            break;
        }
    }
    
    if (i <= end) {
        IRM_DBG("REDO_LOST_FROM_STORAGE sender_id %u, i %u, start %u, end %u, "
            "nack_seq %u", sender_id, i, start, end, nack_seq);
        lost_start = 0;
        count = 0;
        goto IRM_REDO_LOST_FROM_STORAGE;
    }

}

IRM_HOT_CALL static IRM_ALWAYS_INLINE void
irm_pub_context_nack_handle(struct irm_pub_context* ctx,
    struct irm_mbuf* mbuf)
{
    struct irm_msg_header*    header;
    struct irm_msg_nack*      nack;
    struct irm_mbuf*          resend_mbuf;
    uint32_t                  i;
    uint32_t                  start;
    uint32_t                  end;
    uint32_t                  nack_seq;
    uint8_t                   sender_id;
    const uint32_t            offset = ctx->netops.payload_offset;

    nack = IRM_MBUF_MSG(irm_msg_nack, mbuf, offset);
    IRM_DBG("self_id %u, source_id %u, nack_seq %u", ctx->self_id,
        nack->header.source_id, nack->header.seq);
    if (nack->header.source_id != ctx->self_id
        || nack->header.token != ctx->token) {
        irm_mbuf_put(&ctx->netio->rx_pool, mbuf);
        return;
    }

    sender_id = nack->header.sender_id;
    nack_seq = nack->header.seq;
    start = nack->body.start;
    end = nack->body.end;
    irm_mbuf_put(&ctx->netio->rx_pool, mbuf);

    IRM_DBG("sender_id %u, nack start %u, end %u, nack_seq %u",
        sender_id, start, end, nack_seq);

    if (!ctx->storage.inited) {
        IRM_WARN("enter nack start %u, end %u", start, end);
#ifdef IRM_TRACE
        IRM_TRC("enter nack start %u, end %u, "
            "tx_pool (tail %u, head %u, available %u), "
            "tx_buffer (tail %u, head %u, free %u)",
            start, end, ctx->netio->tx_pool.tail, ctx->netio->tx_pool.head,
            ctx->netio->tx_pool.tail - ctx->netio->tx_pool.head,
            ctx->tx_buffer->tail, ctx->tx_buffer->head,
            ctx->tx_buffer->count - (ctx->tx_buffer->tail - ctx->tx_buffer->head));
#endif
        for (i = start; i <= end; ++i) {
            resend_mbuf = (struct irm_mbuf *)irm_buffer_pick(ctx->tx_buffer, i);
            header = IRM_MBUF_MSG(irm_msg_header, resend_mbuf, offset);
            if (header->seq != i) {
                IRM_DBG("from buffer sender_id %u, nack start %u, end %u, "
                    "nack_seq %u, old seq %u, current seq %u", sender_id,
                    start, end, nack_seq, i, header->seq);
                break;
            }
            irm_pub_context_resend_from_buffer(ctx, resend_mbuf, sender_id);
        }
        if (i <= end) {
            irm_pub_context_lost_from_buffer(ctx, sender_id, nack_seq, i, end);
        }
        IRM_WARN("exit nack i %u, start %u, end %u", i, start, end);
#ifdef IRM_TRACE
        IRM_TRC("exit i %u nack start %u, end %u, "
            "tx_pool (tail %u, head %u, available %u), "
            "tx_buffer (tail %u, head %u, free %u)", i, start, end,
            ctx->netio->tx_pool.tail, ctx->netio->tx_pool.head,
            ctx->netio->tx_pool.tail - ctx->netio->tx_pool.head,
            ctx->tx_buffer->tail, ctx->tx_buffer->head,
            ctx->tx_buffer->count - (ctx->tx_buffer->tail - ctx->tx_buffer->head));
#endif
        return;
    }

    for (i = start; i <= end; ++i) {
        resend_mbuf = (struct irm_mbuf *)irm_buffer_pick(ctx->tx_buffer, i);
        header = IRM_MBUF_MSG(irm_msg_header, resend_mbuf, offset);
        if (header->seq != i) {
            if (!irm_pub_context_resend_from_storage(ctx, i, sender_id)) {
                IRM_DBG("not in storage sender_id %u, nack start %u, end %u, "
                    "nack_seq %u, old seq %u, current seq %u", sender_id,
                    start, end, nack_seq, i, header->seq);
                break;
            }
            IRM_DBG("from storage sender_id %u, nack start %u, end %u, "
                "nack_seq %u, old seq %u, current seq %u", sender_id,
                 start, end, nack_seq, i, header->seq);
            continue;
        }
        irm_pub_context_resend_from_buffer(ctx, resend_mbuf, sender_id);
    }
    if (i <= end) {
        irm_pub_context_lost_from_storage(ctx, sender_id, nack_seq, i, end);
    }
   
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE void
irm_pub_context_update_desc(struct irm_pub_context* ctx,
    struct irm_msg_header* header)
{
    struct irm_sub_info*    subs = ctx->subs;
    struct irm_sub_desc*    desc;
    uint8_t                 sender_id = header->sender_id;

    desc = &subs->desc[sender_id];
    if (IRM_UNLIKELY(desc->slot < 0)) {
        desc->slot = subs->alive_count;
        desc->online = IRM_TRUE;
        desc->ip_be32 = header->ip_be32;
        subs->alives[subs->alive_count++] = sender_id;
    }
    desc->alive = IRM_TRUE;
    desc->idle_times = 0;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_pub_context_msg_handle(void* ctx, struct irm_mbuf* mbuf)
{
    struct irm_pub_context* pub_ctx = IRM_PUB_CTX(ctx);
    struct irm_msg_header*  header;

    header = IRM_MBUF_MSG(irm_msg_header, mbuf, pub_ctx->netops.payload_offset);

    IRM_DBG("receive mbuf size %u, msg type %u, role %u, sender_id %u, "
        "target_id %u, seq %u, size %u", mbuf->size, header->msg_type,
        header->role, header->sender_id, header->target_id, header->seq,
        header->size);

    if (IRM_UNLIKELY(header->role == IRM_ROLE_TYPE_PUB)) {
        pub_ctx->netops.blacklist_set(pub_ctx->netio, header->ip_be32);
        irm_mbuf_put(&pub_ctx->netio->rx_pool, mbuf);
        return IRM_OK;
    }

    switch (header->msg_type) {
        case IRM_MSG_TYPE_INVITATION:
            irm_pub_context_update_desc(pub_ctx, header);
            irm_pub_context_invitation_handle(pub_ctx, mbuf);
            break;
        case IRM_MSG_TYPE_ASK:
            irm_pub_context_update_desc(pub_ctx, header);
            irm_pub_context_ask_handle(pub_ctx, mbuf);
            break;
        case IRM_MSG_TYPE_NACK:
            irm_pub_context_update_desc(pub_ctx, header);
            irm_pub_context_nack_handle(pub_ctx, mbuf);
            break;
        case IRM_MSG_TYPE_HEARTBEAT:
            irm_pub_context_update_desc(pub_ctx, header);
            irm_pub_context_heartbeat_handle(pub_ctx, mbuf);
            break;
        case IRM_MSG_TYPE_CLOSE:
            irm_pub_context_close_handle(pub_ctx, mbuf);
            break;
        default:
            IRM_WARN("don't supported msg_type");
            pub_ctx->netops.blacklist_set(pub_ctx->netio, header->ip_be32);
            irm_mbuf_put(&pub_ctx->netio->rx_pool, mbuf);
            return -IRM_ERR_MSG;
    }

    return IRM_OK; 
}

IRM_HOT_CALL static void
irm_pub_context_check_alive(struct irm_pub_context* ctx)
{
    struct irm_config*      cfg = &ctx->cfg;
    struct irm_sub_desc*    desc;
    uint8_t*                alives;
    uint8_t                 alive_count = 0;
    uint8_t                 i;
    const uint8_t           times = cfg->timeout.times;
    

    alives = ctx->subs->alives;
    alive_count = ctx->subs->alive_count;
    IRM_DBG("alive_count %u", alive_count);
    for (i = 0; i < alive_count; ++i) {
        desc = &ctx->subs->desc[alives[i]];
        IRM_DBG("id %u, alive %d", alives[i], desc->alive);
        if (desc->alive) {
            desc->alive = IRM_FALSE;
            continue;
        }
        if (++desc->idle_times >= times) {
            IRM_INFO("offline id %u, idle_times %u, times %u",
                alives[i], desc->idle_times, times);
            
            desc->online = IRM_FALSE;
            desc->slot = -1;
            alives[i] = alives[alive_count - 1];
            alives[alive_count - 1] = 0;
            --ctx->subs->alive_count;
        }
    }
}

IRM_HOT_CALL static void IRM_ALWAYS_INLINE
irm_pub_context_fifo(struct irm_pub_context* ctx)
{
    uint32_t            count;
    struct irm_mbuf*    mbufs[8]; 
    struct irm_storage* storage = &ctx->storage;
    struct irm_config*  cfg = &ctx->cfg;

    if (irm_buffer_free(ctx->netio->tx_buffer) > cfg->tx.fifo_threshold) {
#ifdef IRM_TRACE
        IRM_TRC("buffer not full, buffer tail %u, buffer head %u buffer count %u "
            "tx pool tail %u, tx pool head %u, tx pool availabel count %u",
            ctx->netio->tx_buffer->tail, ctx->netio->tx_buffer->head,
            ctx->netio->tx_buffer->tail - ctx->netio->tx_buffer->head,
            ctx->netio->tx_pool.tail, ctx->netio->tx_pool.head,
            ctx->netio->tx_pool.tail - ctx->netio->tx_pool.head);
#endif
        return;
    }
    count = ctx->netops.fifo(ctx->netio, mbufs, 8);
    if (!count) {
        IRM_TRC("irm_buffer_fifo count %u", count);
        return;
    }
    IRM_TRC("fifo count %u", count);

#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
    {
        struct irm_msg_header* header;
        uint32_t i;
        for (i = 0; i < count; ++i) {
            header = IRM_MBUF_MSG(irm_msg_header, mbufs[i],
                ctx->netops.payload_offset);
            IRM_DBG("fifo msg seq %u, mbuf %p status %u",
                header->seq, mbufs[i], mbufs[i]->status);
        }
    }
#endif
    if (!storage->inited) {
        while (count != irm_mbuf_put_batch(&ctx->netio->tx_pool, mbufs, count));
        return;
    }
   
    irm_storage_commit(storage, mbufs, count);
}

IRM_HOT_CALL static void* irm_pub_context_event_loop(void* arg)
{
    struct irm_pub_context* ctx = IRM_PUB_CTX(arg);
    struct irm_config*      cfg = &ctx->cfg;
    struct irm_time_clock   tc;

    uint64_t                idle_timeout;
    uint64_t                heartbeat_timeout;
    uint64_t                breakpoint_timeout;
    uint64_t                alive_timeout;

    uint64_t                delta_ts = 0;
    uint64_t                breakpoint_ts = 0;
    uint64_t                curr_ts = 0;
    uint64_t                idle_ts = 0;

    uint8_t                 alives = 0;;
    
    const uint8_t           wait_n = cfg->invitation.wait_sub_count;

    pid_t                   tid = -1;

    tid = syscall(SYS_gettid);
    if (cfg->cpu.cpu_id > 0) {
        irm_set_core(tid, cfg->cpu.cpu_id);
    }
    if (cfg->cpu.rt && cfg->cpu.priority >= 0) {
        irm_set_fifo(tid, cfg->cpu.priority);    
    }
    irm_set_thread_name(tid, IRM_PUB_CTX_EVENT_LOOP_NAME, cfg->name.pub);

    irm_time_clock_init(&tc, 0.0); 
    idle_timeout = irm_time_clock_us2cycle(&tc, cfg->timeout.span_us);    
    heartbeat_timeout = irm_time_clock_us2cycle(&tc, cfg->heartbeat.send_timeout);    
    alive_timeout = irm_time_clock_us2cycle(&tc, cfg->heartbeat.alive_timeout);    
    breakpoint_timeout = irm_time_clock_us2cycle(&tc,
        cfg->timeout.breakpoint_timeout);

    IRM_DBG("idle_timeout %lu, heartbeat_timeout %lu, alive_timeout %lu, "
        "breakpoint_timeout %lu", idle_timeout, heartbeat_timeout,
        alive_timeout, breakpoint_timeout);

    irm_pub_context_invitation(ctx);

    while (!ctx->quit) {
        ctx->netops.egress_process(ctx->netio);
        idle_ts = IRM_NETIO_GET_IDLE(ctx->netio);
        alives = IRM_PUB_ALIVE_SUB_COUNT(ctx);
        IRM_BUFFER_VALVE(ctx->tx_buffer, pub_tx_valve[wait_n <= alives]);
        irm_pub_context_fifo(ctx);
        if (IRM_LIKELY(!idle_ts)) {
            continue;
        }

        curr_ts = irm_get_cycle();

        if (curr_ts - idle_ts <= idle_timeout) {
            continue;
        }

        if (!IRM_PUB_ALIVE_SUB_COUNT(ctx)) {
            IRM_DBG("curr_ts %lu, idle_ts %lu, idle_timeout %lu, "
                "send invitation", curr_ts, idle_ts, idle_timeout);
            irm_pub_context_invitation(ctx);
            IRM_NETIO_UPDATE_IDLE(ctx->netio, curr_ts);
            continue; 
        }

        if (curr_ts - breakpoint_ts >= breakpoint_timeout) {
            irm_pub_context_breakpoint_check(ctx, curr_ts, &breakpoint_ts,
                heartbeat_timeout);
        }
        
        delta_ts = curr_ts - idle_ts;
        if (delta_ts >= alive_timeout) {
            IRM_DBG("curr_ts %lu, idle_ts %lu, alive_timeout %lu, "
                "check alive", curr_ts, idle_ts, alive_timeout);
            irm_pub_context_check_alive(ctx);
            IRM_NETIO_UPDATE_IDLE(ctx->netio, curr_ts);
        }
    }
    irm_pub_context_close(ctx);
    IRM_INFO("pub context event loop quit");
    return NULL;
}

IRM_C_END

