/* huangying */
#include "irm_native_netio.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>

#include "irm_config.h"
#include "irm_netio_ops.h"
#include "irm_buffer.h"
#include "irm_time_clock.h"
#include "irm_utils.h"
#include "irm_error.h"
#include "irm_log.h"
#include "irm_msg.h"
#include "irm_memory_pool.h"

IRM_C_BEGIN

static struct irm_netio* irm_native_netio_create(void* mpool,
    struct irm_config* cfg);
static int irm_native_netio_init(void* mpool, struct irm_netio* netio);
static int irm_native_netio_deinit(struct irm_netio* netio);
static int irm_native_netio_set_skbuf(struct irm_netio* netio);

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_native_netio_send(struct irm_netio* netio, struct irm_mbuf* mbuf);

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_native_netio_ingress_process(struct irm_netio* netio);
IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_native_netio_egress_process(struct irm_netio* netio);

static void irm_native_netio_blacklist_set(struct irm_netio* netio,
    uint32_t ip_be32);

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_native_netio_fifo(struct irm_netio* netio, struct irm_mbuf* mbufs[],
    uint32_t max);

struct irm_netio_ops native_netops = {
    .payload_offset = 0,
    .max_payload_size = 0,
    .create = irm_native_netio_create,
    .init = irm_native_netio_init,
    .deinit = irm_native_netio_deinit,
    .ingress_process = irm_native_netio_ingress_process,
    .egress_process = irm_native_netio_egress_process,
    .send = irm_native_netio_send,
    .fifo = irm_native_netio_fifo,
    .blacklist_set = irm_native_netio_blacklist_set,
};

static struct irm_netio* irm_native_netio_create(void* mpool,
    struct irm_config* cfg)
{
    struct irm_native_netio* nio;
    nio = (struct irm_native_netio *)irm_memory_calloc_align(mpool,
        sizeof(struct irm_native_netio), IRM_CACHELINE);
    if (!nio) {
        IRM_ERR("irm_native_netio_create failed, calloc error");
        irm_errno = -IRM_ERR_NATIVE_NETIO_CREATE_CALLOC;
        return NULL;
    }
    IRM_NETIO(nio)->cfg = cfg;
    return IRM_NETIO(nio); 
}

static int irm_native_netio_init(void* mpool, struct irm_netio* netio)
{
    struct irm_native_netio* nio = IRM_NATIVE_NETIO(netio);        
    struct irm_config*       cfg = netio->cfg;
    struct irm_mbuf_pool*    pool;

    int         ret = IRM_OK;
    uint32_t    rx_count;
    uint32_t    tx_count;
    uint32_t    rv_count;
    uint32_t    count;
    uint32_t    mbuf_size;

    rx_count = irm_power2_align32(cfg->rx.mbuf_count);
    tx_count = irm_power2_align32(cfg->tx.mbuf_count);
    rv_count = irm_power2_align32(cfg->rv.mbuf_count);
    count = rx_count + tx_count + rv_count;

    IRM_DBG("rx_count %u, tx_count %u, rv_count %u",
        rx_count, tx_count, rv_count);
#ifdef IRM_TRACE
    fprintf(stderr, "tx mbuf pool count %u\n", tx_count);
#endif
    mbuf_size = cfg->rx.mbuf_size > cfg->tx.mbuf_size ?
        cfg->rx.mbuf_size : cfg->tx.mbuf_size;
    pool = irm_mbuf_pool_create(mpool, count, mbuf_size, cfg->memory.rank,
        cfg->memory.channel);
    if (!pool) {
        IRM_ERR("mbuf pool create failed, err %d", irm_errno);
        goto IRM_ERR_OUT;
    }


    IRM_POOL_MGR_INIT(&netio->rx_pool, pool, rx_count);
    IRM_DBG("rx_pool->ring %p, last %u, count %u",
        netio->rx_pool.ring, pool->last, netio->rx_pool.count);

    IRM_POOL_MGR_INIT(&netio->tx_pool, pool, tx_count);
    IRM_DBG("tx_pool->ring %p, last %u, count %u",
        netio->tx_pool.ring, pool->last, netio->tx_pool.count);

    IRM_POOL_MGR_INIT(&netio->rv_pool, pool, rv_count);
    IRM_DBG("rv_pool->ring %p, last %u, count %u",
        netio->rv_pool.ring, pool->last, netio->rv_pool.count);

    native_netops.max_payload_size = pool->elt_size;
    IRM_DBG("max_payload_size %u", pool->elt_size);
    ret = irm_netio_init(netio);  
    if (ret < 0) {
        IRM_ERR("netio init error, err %d", ret);
        goto IRM_ERR_OUT;
    }

    irm_native_netio_set_skbuf(netio);

#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
    for (uint32_t i = 0; i < netio->rv_pool.count; ++i) {
        IRM_DBG("rv_pool i %u, mbuf %p, id %u", i, netio->rv_pool.ring[i], netio->rv_pool.ring[i]->id);
    }
#endif
    
    nio->remote.sin_family = AF_INET;
    nio->remote.sin_port = netio->mcgroup_port_be16;
    nio->remote.sin_addr.s_addr = netio->mcgroup_ip_be32;

    memset(nio->buf, 0, sizeof(nio->buf));
    nio->filter = (struct ip_msfilter *)nio->buf;

    nio->filter->imsf_multiaddr.s_addr = netio->mcgroup_ip_be32;
    nio->filter->imsf_interface.s_addr = netio->local_ip_be32;
    nio->filter->imsf_fmode = MCAST_EXCLUDE;
    nio->filter->imsf_numsrc = 0; 

    ret = IRM_OK;

#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
    for (uint32_t i = 0; i < netio->rv_pool.count; ++i) {
        IRM_DBG("rv_pool i %u, mbuf %p, id %u", i, netio->rv_pool.ring[i], netio->rv_pool.ring[i]->id);
    }
#endif

IRM_ERR_OUT:
    if (ret != IRM_OK) {
        irm_netio_deinit(netio);
        pool = NULL;
    }
    netio->mbuf_pool = pool;
    return ret;
}

static int irm_native_netio_deinit(struct irm_netio* netio)
{
    irm_netio_deinit(netio);
    return IRM_OK;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_native_netio_ingress_process(struct irm_netio* netio)
{
    struct irm_mbuf_pool_mgr* rx_pool = &netio->rx_pool;
    struct irm_mbuf*          mbuf;
    struct sockaddr_in        addr;
    socklen_t                 addr_len = sizeof(addr);
    ssize_t                   ret; 

    mbuf = (struct irm_mbuf *)irm_mbuf_get(rx_pool);
    if (IRM_UNLIKELY(!mbuf)) {
        IRM_ERR("get no mbuf");
        return -IRM_ERR_NATIVE_NETIO_INGRESS_RECV_MBUF;
    }
    ret = recvfrom(netio->gfd, IRM_MBUF_M2D(mbuf), IRM_MBUF_PAYLOAD(mbuf),
        0, (struct sockaddr *)&addr, &addr_len); 
    if (IRM_LIKELY(ret > 0)) {
#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
        IRM_DBG("received from addr %u.%u.%u.%u:%u, ret %ld, "
            "mbuf size %u, mbuf id %u, mbuf payload %u",
            IRM_IP_N2S(&addr.sin_addr.s_addr), irm_ntohs(addr.sin_port),
            ret, IRM_MBUF_DATA_SIZE(mbuf), mbuf->id, mbuf->payload);
#endif
        mbuf->size = (uint32_t)ret; 
        netio->process_msg_rx_handle(netio->ctx, mbuf);
        netio->idle_ts = 0;
        return IRM_OK;
    }

    if (!netio->idle_ts) {
        netio->idle_ts = irm_get_cycle();
    }
    irm_mbuf_put(rx_pool, mbuf);
    if (errno == EAGAIN) {
        //IRM_DBG("ingress recvfrom again");
        irm_errno = -IRM_ERR_NATIVE_NETIO_INGRESS_AGAIN;    
        return irm_errno;
    }
    IRM_ERR("ingress error, recvfrom failed, error %s", strerror(errno));
    irm_errno = -IRM_ERR_NATIVE_NETIO_INGRESS_RECVFROM;

    return irm_errno;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_native_netio_fifo(struct irm_netio* netio, struct irm_mbuf* mbufs[],
    uint32_t max)
{
    return irm_buffer_fifo(netio->tx_buffer, mbufs, max);        
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_native_netio_egress_process(struct irm_netio* netio)
{
    struct irm_msg_header*    header;
    struct irm_mbuf_pool_mgr* rx_pool = &netio->rx_pool;
    struct irm_mbuf*          rx_mbuf;
    struct irm_mbuf*          tx_mbuf;
    struct sockaddr_in        addr;
    socklen_t                 addr_len = sizeof(addr);
    int                       ret;

    tx_mbuf = (struct irm_mbuf *)irm_buffer_get(netio->tx_buffer);
    if (IRM_UNLIKELY(!tx_mbuf)) {
        IRM_DBG("no mbuf to send");
        if (!netio->idle_ts) {
            netio->idle_ts = irm_get_cycle();
        }
        goto IRM_RCVD;
    }

    tx_mbuf->status = IRM_MBUF_STATUS_SENDING;
    header = IRM_MBUF_MSG(irm_msg_header, tx_mbuf, native_netops.payload_offset);
    netio->last_send_seq = (int64_t)header->seq;
    ret = irm_native_netio_send(netio, tx_mbuf);

    if (IRM_UNLIKELY(ret != IRM_OK)) {
        IRM_DBG("rollback mbuf %u, msg type %u, seq %u", tx_mbuf->id,
            header->msg_type, header->seq);
#ifdef IRM_TRACE
        IRM_WARN("rollback mbuf %u, msg type %u, seq %u", tx_mbuf->id,
            header->msg_type, header->seq);
#endif
        irm_buffer_rollback(netio->tx_buffer);
    } 
#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
    else {
        IRM_DBG("sent msg type %u, sender_id %u, seq %u",
            header->msg_type, header->sender_id, header->seq);

#ifdef IRM_RUNTIME_ENABLE
        IRM_SEND_ADD(netio->runtime, 1);
#endif
    }
#endif
    if (netio->tx_times++ < netio->cfg->weight.tx) {
        return IRM_OK;
    }

IRM_RCVD:
    netio->tx_times = 0;
    rx_mbuf = irm_mbuf_get(rx_pool);
    if (!rx_mbuf) {
        irm_errno = -IRM_ERR_NATIVE_NETIO_EGRESS_RECV_MBUF;
        IRM_DBG("irm_mbuf_get no mbuf");
        return irm_errno;  
    }
    ret = recvfrom(netio->gfd, IRM_MBUF_M2D(rx_mbuf), IRM_MBUF_PAYLOAD(rx_mbuf),
        0, (struct sockaddr *)&addr, &addr_len); 
    if (IRM_UNLIKELY(ret > 0)) {
#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
        IRM_DBG("received from addr %u.%u.%u.%u:%u",
            IRM_IP_N2S(&addr.sin_addr.s_addr),
            irm_ntohs(addr.sin_port));
#endif
        rx_mbuf->size = (uint32_t)ret; 
        netio->idle_ts = 0;
        netio->process_msg_rx_handle(netio->ctx, rx_mbuf);
        return IRM_OK;
    }
    irm_mbuf_put(rx_pool, rx_mbuf);
    if (errno == EAGAIN) {
        //IRM_DBG("egress recvfrom again");
        irm_errno = -IRM_ERR_NATIVE_NETIO_EGRESS_AGAIN;    
        return irm_errno;
    }
    IRM_ERR("egress error, recvfrom failed, error %s", strerror(errno));
    irm_errno = -IRM_ERR_NATIVE_NETIO_EGRESS_RECVFROM;
    return irm_errno;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_native_netio_send(struct irm_netio* netio, struct irm_mbuf* mbuf)
{
    struct irm_native_netio* nio = IRM_NATIVE_NETIO(netio);
    struct irm_msg_header*   header;
    size_t                   size = IRM_MBUF_DATA_SIZE(mbuf);
    ssize_t                  ret;

#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
    {
        struct irm_msg_header* header;
        header = IRM_MBUF_MSG(irm_msg_header, mbuf, native_netops.payload_offset);
        IRM_DBG("send msg type %u, sender_id %u, seq %u", header->msg_type,
            header->sender_id, header->seq);
    }
#endif
    mbuf->status = IRM_MBUF_STATUS_SENDING; 
    netio->idle_ts = 0;
    ret = sendto(netio->lfd, IRM_MBUF_M2D(mbuf), size, 0,
        (struct sockaddr *)&nio->remote, sizeof(nio->remote));
    header = IRM_MBUF_MSG(irm_msg_header, mbuf, native_netops.payload_offset);
    header->target_id = 0;
    IRM_DBG("sendto ret %ld, size %lu,  msg type %u, sender_id %u, seq %u, msg size %u",
        ret, size, header->msg_type, header->sender_id, header->seq, header->size);
    if (IRM_LIKELY(ret == (ssize_t)size)) {
        mbuf->status = IRM_MBUF_STATUS_IDLE;
        return IRM_OK;
    }
    irm_errno = -IRM_ERR_NATIVE_NETIO_SENDTO;
    IRM_ERR("irm_native_netio_send error, sendto failed, error %s",
        strerror(errno));
    return irm_errno;
}

static void
irm_native_netio_blacklist_set(struct irm_netio* netio, uint32_t ip_be32)
{
    struct irm_native_netio* nio = IRM_NATIVE_NETIO(netio);
    struct ip_msfilter*      filter;
    socklen_t                len;
    int                      n;
    int                      ret;
                
    filter = nio->filter;
    IRM_DBG("get imsf_numsrc %u", filter->imsf_numsrc);
    for (uint32_t i = 0; i < filter->imsf_numsrc; ++i) {
        IRM_DBG("list ip %u.%u.%u.%u", IRM_IP_N2S(&filter->imsf_slist[i].s_addr));    
        IRM_DBG("want add ip %u.%u.%u.%u", IRM_IP_N2S(&ip_be32));
        if (filter->imsf_slist[i].s_addr == ip_be32) {
            IRM_DBG("ip %u.%u.%u.%u already in black list", IRM_IP_N2S(&ip_be32));
            return;
        }
    }

    n = filter->imsf_numsrc;
    if (n >= IRM_NETIO_IP_FILTER_LEN) {
        IRM_WARN("ip list full");
        return;
    }
    filter->imsf_numsrc = n + 1;
    filter->imsf_slist[n].s_addr = ip_be32;
    len = IP_MSFILTER_SIZE(0) + sizeof(struct in_addr) * filter->imsf_numsrc;

#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
    IRM_DBG("set len %d imsf_numsrc %u", len, filter->imsf_numsrc);
    for (uint32_t i = 0; i < filter->imsf_numsrc; ++i) {
        IRM_DBG("set %u.%u.%u.%u", IRM_IP_N2S(&filter->imsf_slist[i].s_addr));    
    }
#endif
    ret = setsockopt(netio->gfd, SOL_IP, IP_MSFILTER, nio->buf, len);
    if (ret < 0) {
        IRM_WARN("set filer error, setsockopt %u.%u.%u.%u failed, "
            "error %s", IRM_IP_N2S(&ip_be32), strerror(errno));
    }
}

static int irm_native_netio_set_skbuf(struct irm_netio* netio)
{
    int ret;

    ret = irm_set_skbuf(netio->gfd, netio->cfg->skbuf.rd, 0); 
    if (ret != IRM_OK) {
        return ret;
    }   

    ret = irm_set_skbuf(netio->lfd, 0, netio->cfg->skbuf.wr);
    if (ret != IRM_OK) {
        return ret;
    }   

    return IRM_OK;
}

IRM_C_END
