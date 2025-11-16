/* huangying */
#include "irm_sub_context.h"

#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#ifdef IRM_ENABLE_EFVI
#include "irm_efvi_netio.h"
#endif

#include "irm_memory_pool.h"
#include "irm_config.h"
#include "irm_error.h"
#include "irm_log.h"
#include "irm_native_netio.h"
#include "irm_time_clock.h"
#include "irm_buffer.h"
#include "irm_prefetch.h"

IRM_C_BEGIN

#ifndef IRM_SUB_CHECK_CACHE_N
#define IRM_SUB_CHECK_CACHE_N (8U)
#endif

#ifndef IRM_SUB_CTX_EVENT_LOOP_NAME
#define IRM_SUB_CTX_EVENT_LOOP_NAME "irmsub"
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
#define IRM_SUB_MAGIC 0x49535542 //ISUB
#else
#define IRM_SUB_MAGIC 0x42555349 //BUSI
#endif

#ifndef IRM_SUB_MAJOR
#define IRM_SUB_MAJOR (1)
#endif
#ifndef IRM_SUB_MINOR
#define IRM_SUB_MINOR (0)
#endif

#ifndef IRM_SUB_SMALL
#define IRM_SUB_SMALL (0)
#endif

#ifndef IRM_SUB_RECYCLE_COUNT
#define IRM_SUB_RECYCLE_COUNT   (16u)
#endif

#ifndef IRM_SUB_RECYCLE_THRESHOLD
#define IRM_SUB_RECYCLE_THRESHOLD (8u)
#endif

#define IRM_SUB_RECYCLE_RETRY (256u)

#define IRM_SUB_DEL_CACHE(_ctx, _desc, _cln, _dln)\
do {\
    IRM_QUEUE_REMOVE(_dln);\
    --(_desc)->cache.count;\
    IRM_DBG("remove sender_ln self %p, prev %p, next %p, desc count %u",\
        (_dln), (_dln)->prev, (_dln)->next, (_desc)->cache.count);\
    IRM_QUEUE_REMOVE(_cln);\
    --(_ctx)->cache_count;\
    IRM_DBG("remove iter cache_ln self %p, prev %p, next %p, cache count %u",\
        (_cln), (_cln)->prev, (_cln)->next, (_ctx)->cache_count);\
} while (0)

#define IRM_SUB_DESC_CACHE_INSERT_HEAD(_desc, _dln)\
do {\
    IRM_QUEUE_INSERT_HEAD(&(_desc)->cache.cache_list, _dln);\
    ++(_desc)->cache.count;\
    IRM_DBG("inserted head sender_ln self %p, prev %p, next %p, desc count %u",\
        (_dln), (_dln)->prev, (_dln)->next, (_desc)->cache.count);\
} while (0)

#define IRM_SUB_DESC_CACHE_INSERT_BEFORE(_desc, _elm, _dln)\
do {\
    IRM_QUEUE_INSERT_BEFORE(_elm, _dln);\
    ++(_desc)->cache.count;\
    IRM_DBG("inserted before %p, sender_ln self %p, prev %p, next %p, desc count %u",\
        (_elm), (_dln), (_dln)->prev, (_dln)->next, (_desc)->cache.count);\
} while (0)

#define IRM_SUB_DESC_CACHE_INSERT_TAIL(_desc, _dln)\
do {\
    IRM_QUEUE_INSERT_TAIL(&(_desc)->cache.cache_list, _dln);\
    ++(_desc)->cache.count;\
    IRM_DBG("inserted tail sender_ln self %p, prev %p, next %p, desc count %u",\
        (_dln), (_dln)->prev, (_dln)->next, (_desc)->cache.count);\
} while (0)

#define IRM_SUB_CTX_CACHE_INSERT_TAIL(_ctx, _cln)\
do {\
    IRM_QUEUE_INSERT_TAIL(&(_ctx)->cache_list, _cln);\
    ++(_ctx)->cache_count;\
    IRM_DBG("inserted tail cache_ln self %p, prev %p, next %p, cache count %u",\
        (_cln), (_cln)->prev, (_cln)->next, (_ctx)->cache_count);\
} while (0)

#define IRM_SUB_VERSION \
    (((IRM_SUB_MAJOR) << 16) | ((IRM_SUB_MINOR) << 8) | (IRM_SUB_SMALL))


#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)

//only for native
#define IRM_SUB_CONTEXT_COMMIT(_mbuf) \
do {\
    struct irm_msg_header* header = IRM_MBUF_MSG(irm_msg_header, _mbuf, 0);\
    if (!irm_buffer_put(ctx->rx_buffer, (_mbuf))) {\
        IRM_DBG("SUB_COMMIT COUNT sender_id %u, seq %u, tail %u, head %u",\
            header->sender_id, header->seq, ctx->rx_buffer->tail, ctx->rx_buffer->head);\
        break;\
    }\
    IRM_DBG("rx buffer is full");\
} while (1)
#else // IRM_DEBUG || IRM_DEBUG_VERBOSE

#ifdef IRM_TRACE
//only for native
#define IRM_SUB_CONTEXT_COMMIT(_mbuf) \
do {\
    struct irm_msg_header* header = IRM_MBUF_MSG(irm_msg_header, _mbuf, 0);\
    if (!irm_buffer_put(ctx->rx_buffer, (_mbuf))) {\
        IRM_ERR("SUB_COMMIT COUNT rx buffer sender_id %u, seq %u, tail %u, head %u, mbuf %p",\
            header->sender_id, header->seq, ctx->rx_buffer->tail, ctx->rx_buffer->head, _mbuf);\
        break;\
    }\
    IRM_ERR("SUB_COMMIT COUNT rx buffer is full, sender_id %u, seq %u, tail %u, head %u",\
        header->sender_id, header->seq, ctx->rx_buffer->tail, ctx->rx_buffer->head);\
} while (1)

#else //IRM_TRACE
#define IRM_SUB_CONTEXT_COMMIT(_mbuf) \
    while(IRM_UNLIKELY(irm_buffer_put(ctx->rx_buffer, (_mbuf))))
#endif //IRM_TRACE

#endif //IRM_DEBUG || IRM_DEBUG_VERBOSE

static struct irm_netio_ops* sub_netops[] = {
    &native_netops,
#ifdef IRM_ENABLE_EFVI
    &efvi_netops,   
#endif
    NULL
};

static inline void irm_sub_context_pub_cache_init(
    struct irm_pub_cache* cache);
static struct irm_pub_info* irm_sub_context_pub_info_create(
    void* mpool, struct irm_config* cfg);
static struct irm_pub_info* irm_sub_context_pub_info_create_temp(
    void* mpool, struct irm_config* cfg);
static struct irm_pub_info* irm_sub_context_pub_info_create_keep(
    struct irm_config* cfg);
static void irm_sub_context_pub_info_release(struct irm_pub_info* pubs);

static int irm_sub_context_invitation(struct irm_sub_context* ctx);
static void irm_sub_context_invitation_init(struct irm_sub_context* ctx);
IRM_HOT_CALL static void irm_sub_context_invitation_handle(
    struct irm_sub_context* ctx, struct irm_mbuf* mbuf);

static void irm_sub_context_close_init(struct irm_sub_context* ctx);
IRM_HOT_CALL static void irm_sub_context_close_handle(
    struct irm_sub_context* ctx,struct irm_mbuf* mbuf);

static void irm_sub_context_ask_init(struct irm_sub_context* ctx);
IRM_HOT_CALL static void irm_sub_context_ask_handle(
    struct irm_sub_context* ctx, struct irm_mbuf* mbuf);

static void irm_sub_context_heartbeat_init(struct irm_sub_context* ctx);
IRM_HOT_CALL static void irm_sub_context_heartbeat(struct irm_sub_context* ctx);

IRM_HOT_CALL static IRM_ALWAYS_INLINE void irm_sub_context_breakpoint_handle(
    struct irm_sub_context* ctx, struct irm_mbuf* mbuf);

static void irm_sub_context_nack_init(struct irm_sub_context* ctx);
IRM_HOT_CALL static IRM_ALWAYS_INLINE void irm_sub_context_nack(
    struct irm_sub_context* ctx, uint8_t source_id, uint64_t curr_ts);
IRM_HOT_CALL static IRM_ALWAYS_INLINE void irm_sub_context_nack_update(
    struct irm_pub_desc* desc, struct irm_msg_header* header);

IRM_HOT_CALL static IRM_ALWAYS_INLINE void irm_sub_context_update_desc(
    struct irm_sub_context* ctx, struct irm_msg_header* header);

IRM_HOT_CALL static void irm_sub_context_reset_desc(
    struct irm_sub_context* ctx, uint8_t sender_id);

IRM_HOT_CALL static IRM_ALWAYS_INLINE void irm_sub_context_recycle(
    struct irm_sub_context* ctx);

IRM_HOT_CALL static void irm_sub_context_check_alive(
    struct irm_sub_context* ctx);

IRM_HOT_CALL static void* irm_sub_context_event_loop(void* arg);

IRM_HOT_CALL static IRM_ALWAYS_INLINE void irm_sub_context_data_handle(
    struct irm_sub_context* ctx, struct irm_mbuf* mbuf);

IRM_HOT_CALL static IRM_ALWAYS_INLINE void irm_sub_context_lost_data_handle(
    struct irm_sub_context* ctx, struct irm_mbuf* mbuf);

IRM_HOT_CALL static IRM_ALWAYS_INLINE int irm_sub_context_msg_handle(
    void* ctx, struct irm_mbuf* mbuf);

IRM_HOT_CALL static IRM_ALWAYS_INLINE void irm_sub_context_get_cache(
    struct irm_sub_context* ctx);
IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t irm_sub_context_update_cache(
    struct irm_sub_context* ctx);
IRM_HOT_CALL static IRM_ALWAYS_INLINE int irm_sub_context_check_cache_min(
    struct irm_sub_context* ctx, const uint32_t sender_id);

IRM_HOT_CALL static IRM_ALWAYS_INLINE void irm_sub_context_desc_cache_discard(
    struct irm_sub_context* ctx, uint32_t sender_id);

static int irm_sub_config_check(const struct irm_config* cfg)
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
        && cfg->io_mode >= IRM_SOCKET_TYPE_MAX) {
        IRM_ERR("io mode config error");
        return -IRM_ERR_CONFIG;
    }
    if (cfg->tx.mbuf_count < IRM_CONFIG_SUB_TX_MBUF_COUNT_DEFAULT) {
        IRM_ERR("tx mbuf count config error");
        return -IRM_ERR_CONFIG;
    }

    switch (cfg->io_mode) {
        case IRM_SOCKET_TYPE_NATIVE:
            if (cfg->rx.mbuf_count < IRM_CONFIG_SUB_RX_MBUF_COUNT_MIN) {
                IRM_ERR("rx mbuf count config error, must more than %u",
                    IRM_CONFIG_SUB_RX_MBUF_COUNT_MIN);
                return -IRM_ERR_CONFIG;
            }
            break;
#ifdef IRM_ENABLE_EFVI
        case IRM_SOCKET_TYPE_EFVI:
            if (cfg->rx.mbuf_count < IRM_CONFIG_SUB_RX_MBUF_COUNT_MIN || 
                cfg->rx.mbuf_count > IRM_CONFIG_SUB_RX_MBUF_COUNT_DEFAULT) {
                IRM_ERR("rx mbuf count config error, must in [%u, %u]",
                    IRM_CONFIG_SUB_RX_MBUF_COUNT_MIN,
                    IRM_CONFIG_SUB_RX_MBUF_COUNT_DEFAULT);
                return -IRM_ERR_CONFIG;
            }
            break;
#endif
    }
    return IRM_OK;
}

struct irm_sub_context* irm_sub_context_create(void)
{
    struct irm_sub_context* ctx;

    ctx = IRM_SUB_CTX(calloc(1, sizeof(struct irm_sub_context)));
    if (!ctx) {
        IRM_ERR("sub context calloc failed");        
        irm_errno = -IRM_ERR_SUB_CONTEXT_CALLOC;
    }
    return ctx;
}

int irm_sub_context_init(struct irm_sub_context* ctx)
{
    struct irm_config*      cfg = &ctx->cfg;
    struct irm_netio*       netio = NULL;
    struct irm_netio_ops*   netops = sub_netops[cfg->io_mode];
    struct irm_pub_info*    pubs = NULL;
    struct irm_buffer*      rx_buffer = NULL;
    void*                   mpool = NULL;
    uint32_t                flags;
    int                     ret;

    ret = irm_sub_config_check(cfg);
    if (ret != IRM_OK) {
        IRM_ERR("sub context create failed, config error %d", ret);        
        irm_errno = ret;
        goto IRM_ERR_OUT;
    }

    mpool = irm_memory_pool_create(cfg->memory.pool_size);
    if (!mpool) {
        IRM_ERR("create sub context failed, memory pool create error %d",
            irm_errno);
        goto IRM_ERR_OUT;
    }

    pubs = irm_sub_context_pub_info_create(mpool, cfg);
    if (!pubs) {
        IRM_ERR("sub context create error,  pub info create failed, err %d",
            irm_errno);
        goto IRM_ERR_OUT;
    }

    rx_buffer = irm_buffer_create(mpool, cfg->rx.mbuf_count);
    if (!rx_buffer) {
        IRM_ERR("create sub context error, rx_buffer create failed, err %d",
            irm_errno);
        goto IRM_ERR_OUT;
    }

    netio = netops->create(mpool, cfg);
    if (!netio) {
        IRM_ERR("create sub context error, netio create failed, err %d",
            irm_errno);
        goto IRM_ERR_OUT;
    }

    cfg->rv.mbuf_count = IRM_SUB_RESERVE_MBUF_MAX;
    ret = netops->init(mpool, netio);
    if (ret != IRM_OK) {
        irm_errno = ret;
        IRM_ERR("create sub_ctx error, netio init failed, err %d", ret);
        goto IRM_ERR_OUT;
    }

    flags = IRM_POOL_MGR_SINGLE_CONS | IRM_POOL_MGR_SINGLE_PROD;
    irm_netio_set_option(netio, IRM_NETIO_OPTION_MBUF_RV_POOL, &flags, sizeof(flags));
    flags = IRM_POOL_MGR_SINGLE_CONS;
    irm_netio_set_option(netio, IRM_NETIO_OPTION_MBUF_RX_POOL, &flags, sizeof(flags));

    netio->process_msg_rx_handle = irm_sub_context_msg_handle;
    netio->process_msg_tx_handle = NULL;
    netio->tx_buffer = NULL;
    netio->rx_buffer = rx_buffer;
    netio->ctx = ctx;

    ctx->mpool = mpool;
    ctx->self_id = ((uint8_t *)&netio->local_ip_be32)[3];
    ctx->pubs = pubs;
    ctx->rx_buffer = rx_buffer;
    IRM_BUFFER_VALVE(rx_buffer, IRM_BUFFER_VALVE_ON);

    ctx->netio = netio;
    ctx->netops = *netops;

    irm_sub_context_invitation_init(ctx);
    irm_sub_context_close_init(ctx);
    irm_sub_context_ask_init(ctx);
    irm_sub_context_heartbeat_init(ctx);
    irm_sub_context_nack_init(ctx);
    
    IRM_QUEUE_INIT(&ctx->cache_list);
    IRM_DBG("ctx->cache_list self %p, prev %p, next %p", &ctx->cache_list,
        ctx->cache_list.prev, ctx->cache_list.next);
    ret = pthread_create(&ctx->event_loop_thread_id, NULL,
        irm_sub_context_event_loop, ctx);
    if (ret) {
        IRM_ERR("sub context event loop create failed, error %s",
            strerror(errno));
        irm_errno = -IRM_ERR_SUB_CONTEXT_EVENT_LOOP;
    }

IRM_ERR_OUT:
    if (irm_errno != IRM_OK) {
        if (pubs) {
            irm_sub_context_pub_info_release(pubs);
            ctx->pubs = NULL;
        }
        ctx->rx_buffer = NULL;
        if (netio) {
            netops->deinit(netio);
            ctx->netio = NULL;
        }
    }
    return irm_errno;
}

void irm_sub_context_release(struct irm_sub_context* ctx)
{
    if (!ctx) {
        return;
    }

    ctx->quit = IRM_TRUE;
    IRM_RMB();
    if (ctx->event_loop_thread_id) {
        pthread_join(ctx->event_loop_thread_id, NULL);
    }

    if (ctx->pubs) {
        irm_sub_context_pub_info_release(ctx->pubs);
    }
    if (ctx->netio) {
        ctx->netops.deinit(ctx->netio);
    }
    irm_memory_pool_release(ctx->mpool);
    free(ctx); 
}

static void irm_sub_context_nack_init(struct irm_sub_context* ctx)
{
    struct irm_mbuf*     mbuf;
    struct irm_msg_nack* msg;

    mbuf = irm_mbuf_get(&ctx->netio->rv_pool);
    msg = IRM_MBUF_MSG(irm_msg_nack, mbuf, ctx->netops.payload_offset); 
    msg->header.msg_type = IRM_MSG_TYPE_NACK;
    msg->header.role = IRM_ROLE_TYPE_SUB;
    msg->header.sender_id = ctx->self_id;
    msg->header.target_id = 0;
    msg->header.source_id = 0;
    msg->header.ip_be32 = ctx->netio->local_ip_be32;
    msg->header.size = sizeof(struct irm_msg_nack_body);
    msg->body.start = 0;
    msg->body.end = 0;
    mbuf->size = sizeof(struct irm_msg_nack);
    mbuf->reserved = IRM_TRUE;
    ctx->reserved_mbufs[IRM_SUB_NACK_MBUF_ID] = mbuf;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE void
irm_sub_context_nack(struct irm_sub_context* ctx, uint8_t source_id,
    uint64_t curr_ts)
{
    struct irm_mbuf*     nack_mbuf;
    struct irm_msg_nack* nack_msg;
    struct irm_pub_desc* desc;

    nack_mbuf = ctx->reserved_mbufs[IRM_SUB_NACK_MBUF_ID];
    if (nack_mbuf->status != IRM_MBUF_STATUS_IDLE) {
        IRM_DBG("nack mbuf is sending, id %u", nack_mbuf->id);
        return;
    }
    desc = &ctx->pubs->desc[source_id];
    IRM_WARN("nack start %u, end %u, source id %u", desc->nack.start,
        desc->nack.end, source_id);
    nack_msg = IRM_MBUF_MSG(irm_msg_nack, nack_mbuf, ctx->netops.payload_offset);
    nack_msg->header.seq = ctx->nack_seq;
    nack_msg->header.source_id = source_id;
    nack_msg->header.token = desc->token;
    nack_msg->body.start = desc->nack.start;
    nack_msg->body.end = desc->nack.end;
    if (ctx->netops.send(ctx->netio, nack_mbuf) != IRM_OK) {
        IRM_ERR("nack msg send failed");
        nack_mbuf->status = IRM_MBUF_STATUS_IDLE;
        return;
    }
    desc->nack.ts = curr_ts;
    IRM_WARN("nack start %u, end %u, source id %u, nack.ts %lu, nack seq %u",
        desc->nack.start, desc->nack.end, source_id, desc->nack.ts, ctx->nack_seq);
    ++ctx->nack_seq;
}

static struct irm_pub_info*
irm_sub_context_pub_info_create_keep(struct irm_config* cfg)
{
    struct irm_pub_info* pubs;
    size_t               size;
    uint32_t             i;
    
    size = IRM_SIZE_ALIGN(sizeof(struct irm_pub_info), cfg->hugepage_size);
    pubs = (struct irm_pub_info *)irm_load_state(cfg->path, cfg->path_len, size,
        IRM_SUB_MAGIC, IRM_SUB_VERSION);
    if (!pubs) {
        return NULL;
    }
    pubs->size = size;
    irm_errno = IRM_OK;
    for (i = 0; i < IRM_PUB_MAX; ++i) {
        irm_sub_context_pub_cache_init(&pubs->desc[i].cache);
        IRM_DBG("sender_id %u, desc cache_list self %p, prev %p, next %p",
            i, &pubs->desc[i].cache.cache_list,
            pubs->desc[i].cache.cache_list.prev,
            pubs->desc[i].cache.cache_list.next);
    }
    IRM_MEM_LOCK(pubs, size);
    return pubs;
}

static struct irm_pub_info*
irm_sub_context_pub_info_create_temp(void* mpool, struct irm_config* cfg)
{
    uint32_t             i;
    size_t               size;
    struct irm_pub_info* pubs;

    size = sizeof(struct irm_pub_info);
    pubs = (struct irm_pub_info *)irm_memory_calloc_align(mpool, size,
        IRM_CACHELINE);
    if (!pubs) {
        IRM_ERR("pub temp info create, alloc error %d", irm_errno);
        return NULL;        
    }

    irm_errno = IRM_OK;
    pubs->size = 0;
    for (i = 0; i < IRM_PUB_MAX; ++i) {
        irm_sub_context_pub_cache_init(&pubs->desc[i].cache);
        IRM_DBG("sender_id %u, desc cache_list self %p, prev %p, next %p",
            i, &pubs->desc[i].cache.cache_list,
            pubs->desc[i].cache.cache_list.prev,
            pubs->desc[i].cache.cache_list.next);
    }

    return pubs; 
}

static struct irm_pub_info*
irm_sub_context_pub_info_create(void* mpool, struct irm_config* cfg)
{
    struct irm_pub_info* pubs;
    struct irm_pub_desc* desc;
    int                  i;

    if (!cfg->path_len) {
        pubs = irm_sub_context_pub_info_create_temp(mpool, cfg);
    } else {
        pubs = irm_sub_context_pub_info_create_keep(cfg);
    }

    desc = pubs->desc;
    for (i = 0; i < IRM_PUB_MAX; ++i) {
        desc[i].slot = -1;    
        desc[i].ip_be32 = 0;
        desc[i].alive = IRM_FALSE;
        desc[i].online = IRM_FALSE;
        desc[i].token = 0;
        desc[i].idle_times = 0;
    }
    pubs->alive_count = 0;    
    return pubs;
}

static void irm_sub_context_pub_info_release(struct irm_pub_info* pubs)
{
    uint32_t size;
    if (!pubs || !pubs->size) {
        return;
    }
    size = pubs->size;
    IRM_MEM_UNLOCK(pubs, size);
    munmap(pubs, size);
}


static void irm_sub_context_invitation_init(struct irm_sub_context* ctx)
{
    struct irm_mbuf*           mbuf;
    struct irm_msg_invitation* msg;
    
    mbuf = irm_mbuf_get(&ctx->netio->rv_pool);
    msg = IRM_MBUF_MSG(irm_msg_invitation, mbuf, ctx->netops.payload_offset);
    msg->header.msg_type = IRM_MSG_TYPE_INVITATION;
    msg->header.role = IRM_ROLE_TYPE_SUB;
    msg->header.sender_id = ctx->self_id;
    msg->header.target_id = 0;
    msg->header.source_id = 0;
    msg->header.seq = 0;
    msg->header.size = sizeof(struct irm_msg_invitation_body);
    msg->header.ip_be32 = ctx->netio->local_ip_be32;
    mbuf->size = sizeof(struct irm_msg_invitation);
    mbuf->reserved = IRM_TRUE;
    ctx->reserved_mbufs[IRM_SUB_INVITATION_MBUF_ID] = mbuf;
}

static int irm_sub_context_invitation(struct irm_sub_context* ctx)
{
    struct irm_config*        cfg = &ctx->cfg;
    struct irm_mbuf*          invitation_mbuf;
    struct irm_msg_header*    header;
    uint32_t                  i;
    int                       ret = IRM_OK;
    int                       retry; 
    int                       abort = IRM_FALSE;
    const uint32_t            offset = ctx->netops.payload_offset;

    invitation_mbuf = ctx->reserved_mbufs[IRM_SUB_INVITATION_MBUF_ID];
    header = IRM_MBUF_MSG(irm_msg_header, invitation_mbuf, offset);
    for (i = 0; i < cfg->invitation.times; ++i) {
        IRM_DBG("sub send invitation times %u", i + 1);
        retry = cfg->invitation.retry;
        while (retry--) {
            header->seq = ctx->invitation_seq;
            ret = ctx->netops.send(ctx->netio, invitation_mbuf);
            if (ret == IRM_OK) {
                ++ctx->invitation_seq;
                break;
            }
            invitation_mbuf->status = IRM_MBUF_STATUS_IDLE;
            if (ret != IRM_OK && ret != -IRM_ERR_SEND_AGAIN) {
                abort = IRM_TRUE;
                break;
            }    
            usleep(100 * 1000);
            IRM_DBG("sub send invitation again");
        }
        if (abort || !retry) {
            IRM_ERR("sub send invitation aborted ret %d, err %d, retry %d",
                ret, irm_errno, retry);
            ctx->quit = IRM_TRUE;
            return ret;
        }
        usleep(300 * 1000);
    }
    return ret;
}

IRM_HOT_CALL static void
irm_sub_context_invitation_handle(struct irm_sub_context* ctx,
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

    msg = IRM_MBUF_MSG(irm_msg_invitation, mbuf, ctx->netops.payload_offset);

    IRM_DBG("receive invitation sender_id %u, seq %u",
        msg->header.sender_id, msg->header.seq);

    ask_mbuf = ctx->reserved_mbufs[IRM_SUB_ASK_MBUF_ID];
    ask_msg = IRM_MBUF_MSG(irm_msg_ask, ask_mbuf, ctx->netops.payload_offset);
    IRM_DBG("send ask ask_mbuf %p, ask_msg %p", ask_mbuf, ask_msg);
    ask_msg->header.seq = msg->header.seq;
    ask_msg->body.last_seq = ctx->pubs->desc[msg->header.sender_id].last_seq;
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
        IRM_DBG("sub send ask again");
    }
    if (abort || !retry) {
        IRM_ERR("sub ask failed");
        ctx->quit = IRM_TRUE;
    }
}

static void irm_sub_context_close_init(struct irm_sub_context* ctx)
{
    struct irm_mbuf*      mbuf;
    struct irm_msg_close* msg;
    
    mbuf = irm_mbuf_get(&ctx->netio->rv_pool);
    msg = IRM_MBUF_MSG(irm_msg_close, mbuf, ctx->netops.payload_offset);
    msg->header.msg_type = IRM_MSG_TYPE_CLOSE;
    msg->header.role = IRM_ROLE_TYPE_SUB;
    msg->header.sender_id = ctx->self_id;
    msg->header.target_id = 0;
    msg->header.source_id = 0;
    msg->header.seq = 0;
    msg->header.size = sizeof(struct irm_msg_close_body);
    msg->header.ip_be32 = ctx->netio->local_ip_be32;
    mbuf->size = sizeof(struct irm_msg_close);
    mbuf->reserved = IRM_TRUE;
    ctx->reserved_mbufs[IRM_SUB_CLOSE_MBUF_ID] = mbuf;
}

void irm_sub_context_close(struct irm_sub_context* ctx)
{
    struct irm_config*        cfg = &ctx->cfg;
    struct irm_mbuf*          mbuf;
    uint32_t                  i;
    int                       ret = IRM_OK;
    int                       retry; 

    if (!ctx || !ctx->netio) {
        return;
    }
    mbuf = ctx->reserved_mbufs[IRM_SUB_CLOSE_MBUF_ID];
    for (i = 0; i < cfg->invitation.times; ++i) {
        IRM_DBG("sub send close times %u", i + 1);
        retry = cfg->invitation.retry;
        while (retry--) {
            ret = ctx->netops.send(ctx->netio, mbuf);
            if (ret == IRM_OK) {
                break;
            }
            mbuf->status = IRM_MBUF_STATUS_IDLE;
            usleep(100);
            IRM_DBG("sub send close again");
        }
        usleep(100);
    }
}

IRM_HOT_CALL static void
irm_sub_context_close_handle(struct irm_sub_context* ctx,
    struct irm_mbuf* mbuf)
{
    struct irm_pub_desc*       desc;
    struct irm_msg_header*     header;
    struct irm_mbuf*           cache_mbuf;
    struct irm_queue*          iter;
    uint8_t                    sender_id;
    const uint32_t             offset = ctx->netops.payload_offset;

    header = IRM_MBUF_MSG(irm_msg_header, mbuf, offset);
    IRM_INFO("receive close sender_id %u, seq %u, token %u",
        header->sender_id, header->seq, header->token);
    sender_id = header->sender_id;
    irm_mbuf_put(&ctx->netio->rx_pool, mbuf);
    if (!ctx->pubs->alive_count) {
        return;
    }

    irm_sub_context_desc_cache_discard(ctx, sender_id);
    irm_sub_context_reset_desc(ctx, sender_id);
    if (ctx->pubs->alive_count) {
        return;
    }

    IRM_QUEUE_FOREACH(iter, &ctx->cache_list) {
        cache_mbuf = IRM_QUEUE_DATA(iter, struct irm_mbuf, cache_ln);
        header = IRM_MBUF_MSG(irm_msg_header, cache_mbuf, offset);
        IRM_DBG("remove sender_id %u from cache, msg seq %u, token %u",
            header->sender_id, header->seq, header->token);
        
        desc = &ctx->pubs->desc[header->sender_id];
        IRM_SUB_DEL_CACHE(ctx, desc, iter, &cache_mbuf->sender_ln);
        irm_mbuf_put(&ctx->netio->rx_pool, cache_mbuf); 
    }
}

IRM_HOT_CALL static void
irm_sub_context_reset_desc(struct irm_sub_context* ctx, uint8_t sender_id)
{
    struct irm_pub_desc*       desc = &ctx->pubs->desc[sender_id];
    uint8_t*                   alives = ctx->pubs->alives; 
    uint8_t                    alive_count = ctx->pubs->alive_count;

    desc->last_seq = 0;
    desc->token = 0;
    desc->alive = IRM_FALSE;
    desc->online = IRM_FALSE;
    desc->idle_times = 0;
    desc->nack.ts = 0;
    desc->nack.start = 0;
    desc->nack.end = 0;
    desc->nack.count = 0;
    desc->nack.timeout = 0;
    desc->ip_be32 = 0;

    alives[desc->slot] = alives[alive_count - 1];
    alives[alive_count - 1] = 0;
    desc->slot = -1;
    --ctx->pubs->alive_count;
}

static void irm_sub_context_ask_init(struct irm_sub_context* ctx)
{
    struct irm_mbuf*           mbuf;
    struct irm_msg_ask*        msg;
    
    mbuf = irm_mbuf_get(&ctx->netio->rv_pool);
    msg = IRM_MBUF_MSG(irm_msg_ask, mbuf, ctx->netops.payload_offset);
    msg->header.msg_type = IRM_MSG_TYPE_ASK;
    msg->header.role = IRM_ROLE_TYPE_SUB;
    msg->header.sender_id = ctx->self_id;
    msg->header.target_id = 0;
    msg->header.source_id = 0;
    msg->header.seq = 0;
    msg->header.ip_be32 = ctx->netio->local_ip_be32;
    msg->body.last_seq = 0;
    msg->header.size = sizeof(struct irm_msg_ask_body);
    mbuf->size = sizeof(struct irm_msg_ask);
    mbuf->reserved = IRM_TRUE;
    ctx->reserved_mbufs[IRM_SUB_ASK_MBUF_ID] = mbuf;
    IRM_DBG("ask init mbuf %p, msg %p", mbuf, msg);
}

IRM_HOT_CALL static void
irm_sub_context_ask_handle(struct irm_sub_context* ctx, struct irm_mbuf* mbuf)
{
#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
    struct irm_msg_header* header;
    header = IRM_MBUF_MSG(irm_msg_header, mbuf, ctx->netops.payload_offset);
    IRM_DBG("receive ask sender_id %u, seq %u", header->sender_id,
        header->seq);
#endif
    irm_mbuf_put(&ctx->netio->rx_pool, mbuf);
}

static void irm_sub_context_heartbeat_init(struct irm_sub_context* ctx)
{
    struct irm_mbuf*          mbuf;
    struct irm_msg_heartbeat* msg;

    mbuf = irm_mbuf_get(&ctx->netio->rv_pool);
    msg = IRM_MBUF_MSG(irm_msg_heartbeat, mbuf, ctx->netops.payload_offset);
    msg->header.msg_type = IRM_MSG_TYPE_HEARTBEAT;
    msg->header.role = IRM_ROLE_TYPE_SUB;
    msg->header.sender_id = ctx->self_id;
    msg->header.target_id = 0;
    msg->header.source_id = 0;
    msg->header.ip_be32 = ctx->netio->local_ip_be32;
    msg->header.seq = 0;
    msg->header.size = sizeof(struct irm_msg_heartbeat_body);
    mbuf->size = sizeof(struct irm_msg_heartbeat);
    mbuf->reserved = IRM_TRUE;
    ctx->reserved_mbufs[IRM_SUB_HEARTBEAT_MBUF_ID] = mbuf;
}

static void irm_sub_context_heartbeat(struct irm_sub_context* ctx)
{
    struct irm_mbuf*          mbuf;
    struct irm_msg_heartbeat* msg;

    mbuf = ctx->reserved_mbufs[IRM_SUB_HEARTBEAT_MBUF_ID];
    if (mbuf->status != IRM_MBUF_STATUS_IDLE) {
        IRM_DBG("heartbeat mbuf is sending, id %u", mbuf->id);
        return;
    }
    msg = IRM_MBUF_MSG(irm_msg_heartbeat, mbuf, ctx->netops.payload_offset);
    msg->header.seq = ctx->heartbeat_seq;
    if (ctx->netops.send(ctx->netio, mbuf) != IRM_OK) {
        IRM_DBG("heartbeat msg send failed");
        mbuf->status = IRM_MBUF_STATUS_IDLE;
        return;
    }
    ++ctx->heartbeat_seq;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE void
irm_sub_context_breakpoint_handle(struct irm_sub_context* ctx,
    struct irm_mbuf* mbuf)
{
    struct irm_msg_breakpoint* msg;
    struct irm_pub_desc*       desc;
    uint64_t                   curr_ts;
    uint32_t                   last_send_seq;
    uint32_t                   token;
    uint8_t                    sender_id;
    uint8_t                    heartbeat;

    msg = IRM_MBUF_MSG(irm_msg_breakpoint, mbuf, ctx->netops.payload_offset);

    IRM_DBG("breakpoint sender_id %u, seq %u, last_send_seq %u",
        msg->header.sender_id, msg->header.seq, msg->body.last_send_seq);

    sender_id = msg->header.sender_id;
    token = msg->header.token;
    last_send_seq = msg->body.last_send_seq;
    heartbeat = msg->body.heartbeat;

    irm_mbuf_put(&ctx->netio->rx_pool, mbuf);

    desc = &ctx->pubs->desc[sender_id];
    if (desc->token != token) {
        IRM_DBG("sender_id %u, token %u != %u, invalid", sender_id,
            token, desc->token);
        return;
    }

    if (heartbeat) {
        IRM_DBG("breakpoint heartbeat sender_id %u", sender_id);
        return;
    }

    if (desc->last_seq > last_send_seq) {
        IRM_DBG("breakpoint repeated sender_id %u, desc->last_seq %u, "
            "last_send_seq %u, invalid", sender_id, desc->last_seq, last_send_seq);
        return;
    }

    if (!IRM_QUEUE_EMPTY(&desc->cache.cache_list)) {
        IRM_DBG("breakpoint cache not empty sender_id %u, desc->last_seq %u, "
            "last_send_seq %u, invalid", sender_id, desc->last_seq, last_send_seq);
        return;
    }
    
    curr_ts = irm_get_cycle();
    if (desc->nack.ts + desc->nack.timeout >= curr_ts) {
        IRM_DBG("breakpoint nack has not timeout, curr_ts %lu, nack.ts %lu, "
            "nack.timeout %lu", curr_ts, desc->nack.ts, desc->nack.timeout);
        return;
    }

    desc->nack.start = desc->last_seq;
    desc->nack.end = last_send_seq;
    desc->nack.count = last_send_seq - desc->last_seq + 1;
#ifdef IRM_NACK_TIMEOUT_STATIC
    desc->nack.timeout = ctx->renack_timeout;
#else
    desc->nack.timeout = desc->nack.count * ctx->renack_timeout
        + IRM_CONFIG_TIMEOUT_RENACK_BASE;
#endif

    IRM_DBG("breakpoint send nack msg, sender_id %u, start %u, end %u, "
        "count %u, curr_ts %lu, nack.ts %lu, renack_timeout %lu, nack,timeout %lu",
        sender_id, desc->nack.start, desc->nack.end, desc->nack.count,
        curr_ts, desc->nack.ts, ctx->renack_timeout, desc->nack.timeout);

    irm_sub_context_nack(ctx, sender_id, curr_ts);
}


IRM_HOT_CALL static IRM_ALWAYS_INLINE void
irm_sub_context_get_cache(struct irm_sub_context* ctx)
{
    struct irm_queue*      cache = &ctx->cache_list;
    struct irm_queue*      cache_iter;
    struct irm_mbuf*       cache_mbuf;
    struct irm_pub_desc*   cache_desc;
    struct irm_msg_header* cache_header;

    struct irm_queue*      min_iter;
    struct irm_mbuf*       min_mbuf;
    struct irm_msg_header* min_header;

    const uint32_t         offset = ctx->netops.payload_offset;

    if (IRM_QUEUE_EMPTY(cache)) {
        return;
    }

    cache_iter = IRM_QUEUE_HEAD(cache);
    cache_mbuf = IRM_CONTAINER_OF(cache_iter, struct irm_mbuf, cache_ln);    
    cache_header = IRM_MBUF_MSG(irm_msg_header, cache_mbuf, offset);

    IRM_DBG("cache_iter cache_ln self %p, prev %p, next %p seq %u", cache_iter,
        cache_iter->prev, cache_iter->next, cache_header->seq);

    cache_desc = &ctx->pubs->desc[cache_header->sender_id];
    if (cache_desc->last_seq != cache_header->seq) {
        return;
    }

    IRM_SUB_DEL_CACHE(ctx, cache_desc, cache_iter, &cache_mbuf->sender_ln);
    
    if (IRM_QUEUE_EMPTY(&cache_desc->cache.cache_list)) {

        IRM_DBG("cache msg sender_id %u, cache seq %u, last seq %u, "
            "reset sender cache, commit", cache_header->sender_id,
            cache_header->seq, cache_desc->last_seq);

        cache_desc->cache.min = 0;
        cache_desc->cache.max = 0;

    } else {

        min_iter = IRM_QUEUE_HEAD(&cache_desc->cache.cache_list);
        min_mbuf = IRM_CONTAINER_OF(min_iter, struct irm_mbuf, sender_ln);
        min_header = IRM_MBUF_MSG(irm_msg_header, min_mbuf, offset);

        IRM_DBG("min_iter sender_ln self %p, prev %p, next %p", min_iter,
            min_iter->prev, min_iter->next);

        IRM_DBG("cache msg sender_id %u, cache seq %u, last seq %u, "
            "update sender cache, new min seq %u, old min seq %u, "
            "cache.max %u, commit", cache_header->sender_id,
            cache_header->seq, cache_desc->last_seq, min_header->seq,
            cache_desc->cache.min, cache_desc->cache.max);

        cache_desc->cache.min = min_header->seq;
    }

    cache_desc->last_seq = cache_header->seq + 1;
    IRM_SUB_CONTEXT_COMMIT(cache_mbuf);
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE void
irm_sub_context_data_handle(struct irm_sub_context* ctx,
    struct irm_mbuf* mbuf)
{
    struct irm_queue*      iter;
    struct irm_msg_header* iter_header;
    struct irm_mbuf*       iter_mbuf;

    struct irm_msg_header* header;
    struct irm_pub_desc*   desc;
    uint64_t               curr_ts;
    const uint32_t         offset = ctx->netops.payload_offset;

    header = IRM_MBUF_MSG(irm_msg_header, mbuf, offset);
    desc = &ctx->pubs->desc[header->sender_id];

    if (IRM_UNLIKELY(desc->token != header->token)) {
        IRM_DBG("token dismatched desc->token %u, msg token %u, sender_id %u",
            desc->token, header->token, header->sender_id);
        irm_mbuf_put(&ctx->netio->rx_pool, mbuf);
        return;
    }

    //irm_sub_context_nack_update(desc, header);
    
    if (IRM_LIKELY(header->seq == desc->last_seq)) {
        IRM_DBG("sender_id %u, header seq %u == last seq %u, "
            "min %u, max %u cache_empty %d, sender_empty %d, commit",
            header->sender_id, header->seq, desc->last_seq, desc->cache.min,
            desc->cache.max, IRM_QUEUE_EMPTY(&desc->cache.cache_list),
            IRM_QUEUE_EMPTY(&ctx->cache_list));
        desc->last_seq = header->seq + 1;
        IRM_SUB_CONTEXT_COMMIT(mbuf);
        irm_sub_context_nack_update(desc, header);
        return;
    }

    irm_sub_context_get_cache(ctx);

    if (header->seq < desc->last_seq) {
        IRM_DBG("sender_id %u, header seq %u < last seq %u repeat drop",
            header->sender_id, header->seq, desc->last_seq);
        irm_mbuf_put(&ctx->netio->rx_pool, mbuf);
        return;
    }

    if (IRM_QUEUE_EMPTY(&desc->cache.cache_list)) {
        IRM_DBG("sender_id %u, header seq %u, desc->seq %u insert empty cache list",
            header->sender_id, header->seq, desc->last_seq);
        IRM_SUB_DESC_CACHE_INSERT_HEAD(desc, &mbuf->sender_ln);
        desc->cache.min = header->seq; 
        desc->cache.max = header->seq; 
        goto IRM_DO_CACHE;
    }

    if (header->seq == desc->cache.min || header->seq == desc->cache.max) {
        IRM_DBG("sender_id %u, header seq %u cache.min %u cache.max %u drop",
            header->sender_id, header->seq, desc->cache.min, desc->cache.max);
        irm_mbuf_put(&ctx->netio->rx_pool, mbuf);
        return;
    } 

    if (header->seq < desc->cache.min) {
        IRM_DBG("sender_id %u, header seq %u cache.min %u cache",
            header->sender_id, header->seq, desc->cache.min);
        IRM_SUB_DESC_CACHE_INSERT_HEAD(desc, &mbuf->sender_ln);
        desc->cache.min = header->seq;
        goto IRM_DO_CACHE;
    }

    if (header->seq > desc->cache.max) {
        IRM_DBG("sender_id %u, header seq %u cache.max %u desc->seq %u cache",
            header->sender_id, header->seq, desc->cache.max, desc->last_seq);
        IRM_SUB_DESC_CACHE_INSERT_TAIL(desc, &mbuf->sender_ln);
        desc->cache.max = header->seq;
        goto IRM_DO_CACHE;
    }

    IRM_QUEUE_FOREACH(iter, &desc->cache.cache_list) {
        IRM_PREFETCH_0(iter->next);
        iter_mbuf = IRM_CONTAINER_OF(iter, struct irm_mbuf, sender_ln);    
        iter_header = IRM_MBUF_MSG(irm_msg_header, iter_mbuf, offset);
        if (header->seq == iter_header->seq) {
            IRM_DBG("sender_id %u, header seq %u iter_header seq %u repeat drop, "
                "mbuf %p, mbuf id %u, mbuf self %p, mbuf->prev %p, mbuf->next %p, "
                "iter_mbuf %p, iter_mbuf id %u, iter self %p, iter->prev %p, iter->next %p",
                header->sender_id, header->seq, iter_header->seq, mbuf, mbuf->id,
                &mbuf->sender_ln, mbuf->sender_ln.prev, mbuf->sender_ln.next,
                iter_mbuf, iter_mbuf->id, &iter_mbuf->sender_ln, iter_mbuf->sender_ln.prev,
                iter_mbuf->sender_ln.next);
            irm_mbuf_put(&ctx->netio->rx_pool, mbuf);
            return;
        }
        if (header->seq < iter_header->seq) {
            IRM_DBG("sender_id %u, header seq %u iter_header seq %u cache",
                header->sender_id, header->seq, iter_header->seq);
            IRM_SUB_DESC_CACHE_INSERT_BEFORE(desc, iter, &mbuf->sender_ln);
            break;
        }
    }    

IRM_DO_CACHE:
    irm_sub_context_nack_update(desc, header);
    IRM_SUB_CTX_CACHE_INSERT_TAIL(ctx, &mbuf->cache_ln);
    while (irm_sub_context_check_cache_min(ctx, header->sender_id));

    curr_ts = irm_get_cycle();
    if (desc->nack.ts + desc->nack.timeout >= curr_ts) {
        return;
    }

    IRM_DBG("sender_id %u, curr_ts %lu, nack.ts %lu, nack.timeout %lu, "
        "last_seq %u, cache.min %u, cache.max %u", header->sender_id,
        curr_ts, desc->nack.ts, desc->nack.timeout, desc->last_seq,
        desc->cache.min, desc->cache.max);

    if (desc->last_seq >= desc->cache.min) {
        IRM_DBG("sender_id %u, desc->last_seq %u >= desc->cache.min %u, "
            "desc->cache.max %u", header->sender_id, desc->last_seq,
            desc->cache.min, desc->cache.max);
        return;
    }
    desc->nack.start = desc->last_seq;
    desc->nack.end = desc->cache.min - 1;
    desc->nack.count = desc->cache.min - desc->last_seq;
#ifdef IRM_NACK_TIMEOUT_STATIC
    desc->nack.timeout = ctx->renack_timeout;
#else
    desc->nack.timeout = desc->nack.count * ctx->renack_timeout
        + IRM_CONFIG_TIMEOUT_RENACK_BASE;
#endif

    IRM_DBG("send nack sender_id %u, start %u, end %u, count %u, timeout %lu",
        header->sender_id, desc->nack.start, desc->nack.end,
        desc->nack.count, desc->nack.timeout);

    irm_sub_context_nack(ctx, header->sender_id, curr_ts);
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE void
irm_sub_context_nack_update(struct irm_pub_desc* desc,
    struct irm_msg_header* header)
{
    uint32_t             start = desc->nack.start;
    uint32_t             end = desc->nack.end;

    if (!desc->nack.count) {
        IRM_DBG("have not sent nack, sender_id %u, "
            "start %u, end %u, msg seq %u",
            header->sender_id, start, end, header->seq);
        return;
    }

    if (header->seq < start || header->seq > end) {
        IRM_DBG("not in nack, sender_id %u, start %u, end %u, msg seq %u",
            header->sender_id, start, end, header->seq);
        return;
    }

    IRM_WARN("resent msg seq %u, sender_id %u, start %u, end %u, count %u",
        header->seq, header->sender_id, start, end, desc->nack.count);
    if (!--desc->nack.count) {
        desc->nack.ts = 0;
        desc->nack.timeout = 0;
    } else {
        desc->nack.ts = irm_get_cycle();
    }
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE void
irm_sub_context_lost_data_handle(struct irm_sub_context* ctx,
    struct irm_mbuf* mbuf)
{
    struct irm_msg_lost_data* msg;
    struct irm_pub_desc*      desc;

    msg = IRM_MBUF_MSG(irm_msg_lost_data, mbuf, ctx->netops.payload_offset);
    desc = &ctx->pubs->desc[msg->header.sender_id];
    if (msg->header.token != desc->token) {
        IRM_DBG("sender_id %u, token %u != %u, invalid", msg->header.sender_id,
            desc->token, msg->header.token);
        irm_mbuf_put(&ctx->netio->rx_pool, mbuf);
        return;
    }

    IRM_WARN("irreversible msg sender_id %u, target_id %u, nack_seq %u, "
        "old_start %u, current_start %u, old_end %u, current_end %u, count %u "
        "cache.min %u, cache.max %u, desc->last_seq %u",
        msg->header.sender_id, msg->header.target_id, msg->header.seq,
        msg->body.old_start, msg->body.current_start, msg->body.old_end,
        msg->body.current_end, msg->body.count,
        desc->cache.min, desc->cache.max, desc->last_seq);

    if (desc->last_seq != msg->body.old_start) {
        IRM_WARN("irreversible drop last_seq %u, old_start %u, current_start %u, "
            "nack seq %u", desc->last_seq, msg->body.old_start,
            msg->body.current_start, msg->header.seq);
        goto IRM_LOST_DATA_DROP;
    }
    desc->last_seq = msg->body.old_end + 1;
    if (desc->cache.min && desc->cache.min < desc->last_seq) {
        desc->last_seq = desc->cache.min;
    }
    desc->nack.count = desc->last_seq - msg->body.old_start;
    if (desc->nack.count) {
        desc->nack.ts = irm_get_cycle();
    } else {
        desc->nack.ts = 0;
        desc->nack.timeout = 0;
    }

    IRM_WARN("irreversible data loss, sender_id %u, last_seq %u, old_start %u, "
        "current start %u, old_end %u, current_end %u, count %u, nack start %u, "
        "nack end %u, nack count %u, nack timeout %lu, nack seq %u",
        msg->header.sender_id, desc->last_seq, msg->body.old_start,
        msg->body.current_start, msg->body.old_end, msg->body.current_end,
        msg->body.count, desc->nack.start, desc->nack.end, desc->nack.count,
        desc->nack.timeout, msg->header.seq);

IRM_LOST_DATA_DROP:
    irm_mbuf_put(&ctx->netio->rx_pool, mbuf);

}

IRM_HOT_CALL static IRM_ALWAYS_INLINE void
irm_sub_context_update_desc(struct irm_sub_context* ctx,
    struct irm_msg_header* header)
{
    struct irm_pub_info*    pubs = ctx->pubs;
    struct irm_pub_desc*    desc;
    uint8_t                 sender_id = header->sender_id;

    desc = &pubs->desc[sender_id];
    if (IRM_UNLIKELY(desc->slot < 0)) {
        desc->slot = pubs->alive_count;
        desc->online = IRM_TRUE;
        desc->token = header->token;
        desc->ip_be32 = header->ip_be32;
        pubs->alives[pubs->alive_count++] = sender_id;
        IRM_DBG("new pub online sender_id %u, slot %d, token %u",
            sender_id, desc->slot, desc->token);
        goto IRM_SUB_OUT;
    } 

    if (desc->token != header->token) {
        IRM_DBG("token changed, old %u, new %u", desc->token, header->token);
        desc->token = header->token;
        desc->last_seq = 0;
        desc->nack.ts = 0;
        desc->nack.start = 0;
        desc->nack.end = 0;
        desc->nack.count = 0;
        desc->nack.timeout = 0;
        irm_sub_context_desc_cache_discard(ctx, sender_id);
    }

IRM_SUB_OUT:
    desc->alive = IRM_TRUE;
    desc->idle_times = 0;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_sub_context_msg_handle(void* ctx, struct irm_mbuf* mbuf)
{
    struct irm_sub_context* sub_ctx = IRM_SUB_CTX(ctx);
    struct irm_msg_header*  header;
    
    header = IRM_MBUF_MSG(irm_msg_header, mbuf, sub_ctx->netops.payload_offset);
    
     IRM_DBG("receive mbuf size %u, mbuf payload %u, msg type %u, role %u, "
        "sender_id %u, target_id %u, seq %u, size %u, mbuf id %u", mbuf->size,
        mbuf->payload, header->msg_type, header->role, header->sender_id,
        header->target_id, header->seq, header->size, mbuf->id);
    
    if (IRM_UNLIKELY(header->role == IRM_ROLE_TYPE_SUB)) {
        sub_ctx->netops.blacklist_set(sub_ctx->netio, header->ip_be32);
        irm_mbuf_put(&sub_ctx->netio->rx_pool, mbuf);
        return IRM_OK;
    }
    
    switch (header->msg_type) {
        case IRM_MSG_TYPE_DATA:
            irm_sub_context_update_desc(sub_ctx, header);
            irm_sub_context_data_handle(sub_ctx, mbuf);
            break;
        case IRM_MSG_TYPE_INVITATION:
            irm_sub_context_update_desc(sub_ctx, header);
            irm_sub_context_invitation_handle(sub_ctx, mbuf);
            break;
        case IRM_MSG_TYPE_ASK:
            irm_sub_context_update_desc(sub_ctx, header);
            irm_sub_context_ask_handle(sub_ctx, mbuf);
            break;
        case IRM_MSG_TYPE_LOST_DATA:
            irm_sub_context_update_desc(sub_ctx, header);
            irm_sub_context_lost_data_handle(sub_ctx, mbuf);
            break;
        case IRM_MSG_TYPE_BREAKPOINT:
            irm_sub_context_update_desc(sub_ctx, header);
            irm_sub_context_breakpoint_handle(sub_ctx, mbuf);
            break;
        case IRM_MSG_TYPE_CLOSE:
            irm_sub_context_close_handle(sub_ctx, mbuf);
            break;
        default:
            IRM_WARN("don't supported msg_type");
            sub_ctx->netops.blacklist_set(sub_ctx->netio, header->ip_be32);
            irm_mbuf_put(&sub_ctx->netio->rx_pool, mbuf);
            return -IRM_ERR_MSG;
    }

    return IRM_OK; 
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_sub_context_check_cache_min(struct irm_sub_context* ctx,
    const uint32_t sender_id)
{
    struct irm_pub_desc*     desc = &ctx->pubs->desc[sender_id];
    struct irm_queue*        iter;
    struct irm_mbuf*         mbuf;
    struct irm_msg_header*   header;
    const uint32_t           offset = ctx->netops.payload_offset;

    if (IRM_QUEUE_EMPTY(&desc->cache.cache_list)) {
        return IRM_FALSE;
    }

    iter = IRM_QUEUE_HEAD(&desc->cache.cache_list); 
    mbuf = IRM_CONTAINER_OF(iter, struct irm_mbuf, sender_ln);    
    header = IRM_MBUF_MSG(irm_msg_header, mbuf, offset);
    IRM_DBG("iter sender_ln self %p, prev %p, next %p, "
        "header seq %u, desc->seq %u", iter, iter->prev, iter->next,
        header->seq, desc->last_seq);

    if (header->seq > desc->last_seq) {
        return IRM_FALSE;
    }

    IRM_SUB_DEL_CACHE(ctx, desc, &mbuf->cache_ln, iter);
    
    if (header->seq == desc->last_seq) {
        IRM_DBG("header->seq %u == desc->last_seq %u, commit",
            header->seq, desc->last_seq);
        IRM_SUB_CONTEXT_COMMIT(mbuf);
        desc->last_seq = header->seq + 1;
    } else {
        IRM_DBG("header->seq %u < desc->last_seq %u, drop",
            header->seq, desc->last_seq);
        irm_mbuf_put(&ctx->netio->rx_pool, mbuf);
    }
    
    if (IRM_QUEUE_EMPTY(&desc->cache.cache_list)) {
        IRM_DBG("cache min hit, sender %u, min seq %u, last seq %u reset",
            sender_id, header->seq, desc->last_seq);
        desc->cache.min = 0;
        desc->cache.max = 0;
    } else {
        IRM_DBG("cache min hit, sender %u, min seq %u, last seq %u",
            sender_id, header->seq, desc->last_seq);

        iter = IRM_QUEUE_HEAD(&desc->cache.cache_list);
        mbuf = IRM_CONTAINER_OF(iter, struct irm_mbuf, sender_ln);
        header = IRM_MBUF_MSG(irm_msg_header, mbuf, offset);
        IRM_DBG("cache min hit, sender %u, update cache.min seq %u "
            "to header seq %u, cache.max %u, last seq %u", sender_id,
            desc->cache.min, header->seq, desc->cache.max, desc->last_seq);
        desc->cache.min = header->seq;
    }

    return IRM_TRUE;
}
IRM_HOT_CALL static IRM_ALWAYS_INLINE void
irm_sub_context_desc_cache_discard(struct irm_sub_context* ctx,
    uint32_t sender_id)
{
    struct irm_queue*    iter;
    struct irm_mbuf*     mbuf;
    struct irm_pub_desc* desc = &ctx->pubs->desc[sender_id];

    IRM_QUEUE_FOREACH(iter, &desc->cache.cache_list) {
        mbuf = IRM_QUEUE_DATA(iter, struct irm_mbuf, sender_ln);
        IRM_SUB_DEL_CACHE(ctx, desc, &mbuf->cache_ln, iter);
        irm_mbuf_put(&ctx->netio->rx_pool, mbuf);
    }
    desc->cache.min = 0;
    desc->cache.max = 0;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE void
irm_sub_context_recycle(struct irm_sub_context* ctx)
{
    struct irm_config*      cfg = &ctx->cfg;
    struct irm_pub_desc*    desc;
    struct irm_msg_header*  header;
    struct irm_mbuf*        mbuf;
    struct irm_queue*       tail;
    struct irm_queue*       max_iter;
    struct irm_mbuf*        max_mbuf;
    const uint32_t          count = cfg->rx.recycle;
    const uint8_t           alive_count = ctx->pubs->alive_count;
    uint8_t*                alives = ctx->pubs->alives;
    uint32_t                retry = 0;
    uint32_t                n = 0;
    uint8_t                 i = 0;
    const uint32_t          offset = ctx->netops.payload_offset;
    
    if (IRM_LIKELY(ctx->cache_count < count)) {
        return;
    }

    IRM_INFO("recycle max count %u, cache count %u", count, ctx->cache_count);

    while (n < IRM_SUB_RECYCLE_COUNT && retry++ < IRM_SUB_RECYCLE_RETRY) {
        for (i = 0; i < alive_count; ++i) {
            desc = &ctx->pubs->desc[alives[i]];
            if (desc->cache.count > IRM_SUB_RECYCLE_THRESHOLD) {

                tail = IRM_QUEUE_TAIL(&desc->cache.cache_list);
                mbuf = IRM_QUEUE_DATA(tail, struct irm_mbuf, sender_ln);
#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
                {
                    header = IRM_MBUF_MSG(irm_msg_header, mbuf, offset);
                    IRM_DBG("sender_id %u, cache count %u, desc count %u, "
                        "last seq %u, token %u, min %u, max %u, msg seq %u",
                        alives[i], ctx->cache_count, desc->cache.count,
                        desc->last_seq, desc->token, desc->cache.min,
                        desc->cache.max, header->seq);
                }
#endif
                IRM_SUB_DEL_CACHE(ctx, desc, &mbuf->cache_ln, tail);
                irm_mbuf_put(&ctx->netio->rx_pool, mbuf);

                max_iter = IRM_QUEUE_TAIL(&desc->cache.cache_list);
                max_mbuf = IRM_QUEUE_DATA(max_iter, struct irm_mbuf, sender_ln);
                header = IRM_MBUF_MSG(irm_msg_header, max_mbuf, offset);
                IRM_INFO("recycle update cache max %u to %u, min %u",
                    desc->cache.max, header->seq, desc->cache.min);
                desc->cache.max = header->seq;
                ++n;
            }
        }
    }
    IRM_INFO("recycle max count %u, cache count %u, alive count %u, recycled %u",
        count, ctx->cache_count, alive_count, n);
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_sub_context_update_cache(struct irm_sub_context* ctx)
{
    struct irm_pub_desc*   desc = ctx->pubs->desc;
    struct irm_queue*      iter;
    struct irm_msg_header* msg_header;
    struct irm_msg_header* min_msg_header;
    struct irm_mbuf*       mbuf;
    struct irm_mbuf*       min_mbuf;
    struct irm_queue*      min_iter;
    uint32_t               i = 0;    
    uint32_t               n = 0;
    const uint32_t         offset = ctx->netops.payload_offset;
    uint8_t                sender_id = 0;
    uint64_t               curr_ts = 0;

    if (IRM_QUEUE_EMPTY(&ctx->cache_list)) {
        return 0;
    }
    
    IRM_QUEUE_FOREACH(iter, &ctx->cache_list) {
        if (i++ >= IRM_SUB_CHECK_CACHE_N) {
            break;
        }
        IRM_PREFETCH_0(iter->next);
        mbuf = IRM_QUEUE_DATA(iter, struct irm_mbuf, cache_ln); 
        msg_header = IRM_MBUF_MSG(irm_msg_header, mbuf, offset);

        if (!desc[msg_header->sender_id].online) {
            IRM_DBG("found offline sender_id %u, msg token %u, desc->token %u",
                msg_header->sender_id, msg_header->token,
                desc[msg_header->sender_id].token);
            sender_id = msg_header->sender_id;
            break;
        }

        if (desc[msg_header->sender_id].token != msg_header->token) {
            IRM_DBG("found dismatched token sender_id %u, msg token %u, "
                "desc->token %u", msg_header->sender_id, msg_header->token,
                desc[msg_header->sender_id].token);
            sender_id = msg_header->sender_id;
            break;
        }

        if (desc[msg_header->sender_id].last_seq != msg_header->seq) {
            IRM_DBG("found a lost msg sender_id %u, last_seq %u, in cache seq %u",
                msg_header->sender_id, desc[msg_header->sender_id].last_seq,
                msg_header->seq);
            if (irm_sub_context_check_cache_min(ctx, msg_header->sender_id)) {
                continue;
            }
            sender_id = msg_header->sender_id;
            break;
        }

        IRM_DBG("found a cache msg sender_id %u, last_seq %u, in cache seq %u",
            msg_header->sender_id, desc[msg_header->sender_id].last_seq,
            msg_header->seq);

        IRM_SUB_DEL_CACHE(ctx, &desc[msg_header->sender_id], iter, &mbuf->sender_ln);

        if (IRM_QUEUE_EMPTY(&desc[msg_header->sender_id].cache.cache_list)) {
            desc[msg_header->sender_id].cache.min = 0;
            desc[msg_header->sender_id].cache.max = 0;
        } else {
            min_iter = IRM_QUEUE_HEAD(&desc[msg_header->sender_id].cache.cache_list);
            IRM_DBG("min_iter sender_ln self %p, prev %p, next %p", min_iter,
                min_iter->prev, min_iter->next);
            min_mbuf = IRM_CONTAINER_OF(min_iter, struct irm_mbuf, sender_ln);
            min_msg_header = IRM_MBUF_MSG(irm_msg_header, min_mbuf, offset);
            desc[msg_header->sender_id].cache.min = min_msg_header->seq;
        }

        IRM_SUB_CONTEXT_COMMIT(mbuf);
        desc[msg_header->sender_id].last_seq = msg_header->seq + 1;
        ++n;
    }
    if (!sender_id) {
        IRM_DBG("found no lost msg, n %u", n);
        return n;
    }

    if (!desc[sender_id].online || desc[sender_id].token != msg_header->token) {
        IRM_DBG("found a discard sender_id %u, desc->token %u, header->token %u",
            sender_id, desc[sender_id].token, msg_header->token);
        irm_sub_context_desc_cache_discard(ctx, sender_id);    
        return n;
    }

    if (desc[sender_id].last_seq >= desc[sender_id].cache.min) {
        return n;
    }

    curr_ts = irm_get_cycle();
    if (desc[sender_id].nack.ts + desc[sender_id].nack.timeout >= curr_ts) {
        IRM_DBG("curr_ts %lu, nack.ts %lu, nack.timeout %lu, sender id %u",
            curr_ts, desc[sender_id].nack.ts, desc[sender_id].nack.timeout,
            sender_id);
        return n;
    }

    IRM_DBG("send nack sender_id %u, curr_ts %lu, nack.ts %lu, nack.timeout %lu, "
        "last_seq %u, cache.min %u, cache.max %u", sender_id, curr_ts,
        desc[sender_id].nack.ts, desc[sender_id].nack.timeout,
        desc[sender_id].last_seq, desc[sender_id].cache.min,
        desc[sender_id].cache.max);

    //maybe block other pubs
    desc[sender_id].nack.start = desc[sender_id].last_seq;
    desc[sender_id].nack.end = desc[sender_id].cache.min - 1; 
    desc[sender_id].nack.count = 
        desc[sender_id].cache.min - desc[sender_id].last_seq;
#ifdef IRM_NACK_TIMEOUT_STATIC    
    desc[sender_id].nack.timeout = ctx->renack_timeout;
#else
    desc[sender_id].nack.timeout =
        ctx->renack_timeout * desc[sender_id].nack.count
        + IRM_CONFIG_TIMEOUT_RENACK_BASE;
#endif

    IRM_DBG("send nack msg, sender_id %u, start %u, end %u, count %u, timeout %lu",
        sender_id, desc[sender_id].nack.start, desc[sender_id].nack.end,
        desc[sender_id].nack.count, desc[sender_id].nack.timeout);

    irm_sub_context_nack(ctx, sender_id, curr_ts);

    return n;
}

IRM_HOT_CALL static void
irm_sub_context_check_alive(struct irm_sub_context* ctx)
{
    struct irm_config*      cfg = &ctx->cfg;
    struct irm_pub_desc*    desc;
    const uint8_t           times = cfg->timeout.times;
    uint8_t*                alives;
    uint8_t                 alive_count = 0;
    uint8_t                 sender_id;
    uint8_t                 i;

    alives = ctx->pubs->alives;
    alive_count = ctx->pubs->alive_count;
    IRM_DBG("alive_count %u", alive_count);
    for (i = 0; i < alive_count; ++i) {
        desc = &ctx->pubs->desc[alives[i]];
        IRM_DBG("id %u, alive %d", alives[i], desc->alive);
        if (desc->alive) {
            desc->alive = IRM_FALSE;
            continue;
        }
        if (++desc->idle_times >= times) {
            IRM_DBG("offline id %u, idle_times %u, times %u", 
                alives[i], desc->idle_times, times);
            sender_id = alives[i]; 
            desc->online = IRM_FALSE;
            desc->slot = -1;
            alives[i] = alives[alive_count - 1]; 
            alives[alive_count - 1] = 0;
            --ctx->pubs->alive_count;
            desc->token = 0;
            desc->last_seq = 0;
            desc->nack.ts = 0;
            desc->nack.start = 0;
            desc->nack.end = 0;
            desc->nack.count = 0;
            desc->nack.timeout = 0;
            irm_sub_context_desc_cache_discard(ctx, sender_id);
        }

    }
}

static inline void
irm_sub_context_pub_cache_init(struct irm_pub_cache* cache)
{
    IRM_QUEUE_INIT(&cache->cache_list);
    cache->min = 0;
    cache->max = 0; 
}

IRM_HOT_CALL static void* irm_sub_context_event_loop(void* arg)
{
    struct irm_sub_context* ctx = IRM_SUB_CTX(arg);
    struct irm_config*      cfg = &ctx->cfg;
    struct irm_time_clock   tc;

    uint64_t                idle_timeout;
    uint64_t                curr_ts = 0;
    uint64_t                idle_ts = 0;
    uint64_t                heartbeat_timeout;
    uint64_t                alive_timeout;

    pid_t                   tid = -1;
    
    tid = syscall(SYS_gettid);
    if (cfg->cpu.cpu_id >= 0) {
        irm_set_core(tid, cfg->cpu.cpu_id);
    }

    if (cfg->cpu.rt && cfg->cpu.priority >= 0) {
        irm_set_fifo(tid, cfg->cpu.priority);    
    }
    irm_set_thread_name(tid, IRM_SUB_CTX_EVENT_LOOP_NAME, cfg->name.sub);

    irm_time_clock_init(&tc, 0);
    idle_timeout = irm_time_clock_us2cycle(&tc, cfg->timeout.span_us);
    heartbeat_timeout = irm_time_clock_us2cycle(&tc, cfg->heartbeat.send_timeout);
    alive_timeout = irm_time_clock_us2cycle(&tc, cfg->heartbeat.alive_timeout);

    ctx->renack_timeout = irm_time_clock_us2cycle(&tc,
        cfg->timeout.nack_timeout);

    IRM_DBG("idle_timeout %lu, heartbeat_timeout %lu, alive_timeout %lu",
        idle_timeout, heartbeat_timeout, alive_timeout);

    irm_sub_context_invitation(ctx);

    while (!ctx->quit) {
        ctx->netops.ingress_process(ctx->netio);
        irm_sub_context_recycle(ctx);
        irm_sub_context_update_cache(ctx);

        idle_ts = IRM_NETIO_GET_IDLE(ctx->netio);
        if (IRM_LIKELY(!idle_ts)) {
            continue;
        }

        curr_ts = irm_get_cycle();
        if (curr_ts - idle_ts < idle_timeout) {
            continue;
        }

        if (curr_ts - idle_ts >= alive_timeout) {
            IRM_DBG("curr_ts %lu, idle_ts %lu, alive_timeout %lu, "
                "check alive", curr_ts, idle_ts, alive_timeout);
            irm_sub_context_check_alive(ctx);
            IRM_NETIO_UPDATE_IDLE(ctx->netio, curr_ts);
        }
        if (curr_ts - idle_ts >= heartbeat_timeout) {
            IRM_DBG("curr_ts %lu, idle_ts %lu, heartbeat_timeout %lu, "
                "send heartbeat", curr_ts, idle_ts, heartbeat_timeout);
            irm_sub_context_heartbeat(ctx);
            IRM_NETIO_UPDATE_IDLE(ctx->netio, curr_ts);
        }     
    }

    irm_sub_context_close(ctx);
    IRM_INFO("sub event loop quit");
    return NULL;
}

IRM_C_END
