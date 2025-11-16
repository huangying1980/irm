/* huangying */
#include "irm_efvi_netio.h"

#include <netinet/in.h>

#include "irm_msg.h"
#include "irm_time_clock.h"
#include "irm_buffer.h"
#include "irm_inet.h"
#include "irm_error.h"
#include "irm_log.h"
#include "irm_memory_pool.h"

#include "etherfabric/capabilities.h"
#include "etherfabric/checksum.h"

IRM_C_BEGIN

#ifndef IRM_EFVI_REFILL_BATCH_SIZE
#define IRM_EFVI_REFILL_BATCH_SIZE 8 
#endif

#ifndef IRM_EFVI_CTPIO_THREASH
#define IRM_EFVI_CTPIO_THREASH (40)
#endif

#ifndef IRM_EFVI_TX_RING
#define IRM_EFVI_TX_RING (2047)
#endif

#ifndef IRM_EFVI_RX_RING
#define IRM_EFVI_RX_RING (4095)
#endif

#ifndef IRM_EFVI_EGRESS_POLL_EVENT_N
#define IRM_EFVI_EGRESS_POLL_EVENT_N   (8)
#endif

#ifndef IRM_EFVI_INGRESS_POLL_EVENT_N
#define IRM_EFVI_INGRESS_POLL_EVENT_N   (16)
#endif

#define IRM_EFVI_NETIO_ID2M(_p, _id) \
    ((struct irm_mbuf *)((char *)(_p)->mbufs + ((_id) << 11)))

static struct irm_netio* irm_efvi_netio_create(void* mpool,
    struct irm_config* cfg);
static int irm_efvi_netio_init(void* mpool, struct irm_netio* netio);
static int irm_efvi_netio_deinit(struct irm_netio* netio);

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_efvi_netio_ingress_process(struct irm_netio* netio);
IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_efvi_netio_egress_process(struct irm_netio* netio);

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_efvi_netio_send(struct irm_netio* netio, struct irm_mbuf* mbuf);

IRM_HOT_CALL static IRM_ALWAYS_INLINE void
irm_efvi_netio_handle_rx(struct irm_netio* netio, uint32_t id, int len);
IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_efvi_netio_refill_rx(struct irm_efvi_netio* eio);

static int irm_efvi_netio_mbuf_pool_init(void* mpool,
    struct irm_efvi_netio* eio);
static void irm_efvi_netio_eth_init(struct irm_efvi_netio* eio,
    struct irm_eth_hdr* eth);
static void irm_efvi_netio_ip4_init(struct irm_efvi_netio* eio,
    struct irm_ip4_hdr* ip4);
static void irm_efvi_netio_udp_init(struct irm_efvi_netio* eio,
    struct irm_mbuf* mbuf);

IRM_HOT_CALL static IRM_ALWAYS_INLINE void
irm_efvi_netio_update_size(struct irm_mbuf* mbuf);

IRM_HOT_CALL static IRM_ALWAYS_INLINE void irm_efvi_netio_blacklist_set(
    struct irm_netio * IRM_UNUSED(netio), uint32_t IRM_UNUSED(ip_be32));

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_efvi_netio_fifo(struct irm_netio* netio, struct irm_mbuf* mbufs[],
    uint32_t max);

struct irm_netio_ops efvi_netops = {
    .payload_offset = IRM_INET_HEADER_SIZE,
    .max_payload_size = 0,
    .create = irm_efvi_netio_create,

    .init = irm_efvi_netio_init,
    .deinit = irm_efvi_netio_deinit,

    .ingress_process = irm_efvi_netio_ingress_process,
    .egress_process = irm_efvi_netio_egress_process,

    .send = irm_efvi_netio_send,
    
    .fifo = irm_efvi_netio_fifo,

    .blacklist_set = irm_efvi_netio_blacklist_set,
};

static struct irm_netio* irm_efvi_netio_create(void* mpool,
    struct irm_config* cfg)
{
    struct irm_efvi_netio* eio;    

    eio = (struct irm_efvi_netio *)irm_memory_calloc_align(mpool,
        sizeof(struct irm_efvi_netio), IRM_PAGE_SIZE);    
    if (!eio)  {
        IRM_ERR("irm_efvi_netio_create error, calloc failed");
        irm_errno = -IRM_ERR_EFVI_NETIO_CREATE_CALLOC;
        return NULL;
    }
    IRM_NETIO(eio)->cfg = cfg;
    return IRM_NETIO(eio);
}

static int irm_efvi_netio_init(void* mpool, struct irm_netio* netio)
{
    struct irm_efvi_netio* eio = IRM_EFVI_NETIO(netio);
    struct irm_config*     cfg = netio->cfg;
    struct irm_mbuf*       mbuf;
    unsigned long          capa_val = 0;
    int                    i;
    int                    vi_flags = EF_VI_FLAGS_DEFAULT;
    int                    ret;
     
    IRM_BUG_ON(IRM_EFVI_EGRESS_POLL_EVENT_N < EF_VI_EVENT_POLL_MIN_EVS);
    IRM_BUG_ON(IRM_EFVI_INGRESS_POLL_EVENT_N < EF_VI_EVENT_POLL_MIN_EVS);

    ret = ef_driver_open(&eio->dh); 
    if (ret < 0) {
        IRM_ERR("ef_driver_open failed, err %d", ret);
        irm_errno = -IRM_ERR_EFVI_DRIVER_OPEN;
    }

    eio->ifindex = irm_get_ifindex(cfg->addr.ifname);
    eio->pd_flags = EF_PD_DEFAULT;
    
    ret = ef_pd_alloc(&eio->pd, eio->dh, eio->ifindex, eio->pd_flags);
    if (ret < 0) {
        IRM_ERR("ef_pd_alloc failed, err %d", ret);                
        irm_errno = -IRM_ERR_EFVI_PD_ALLOC;
        goto DO_EXIT;
    }

    eio->ctpio = IRM_FALSE;
    if (cfg->tx.ctpio == IRM_TRUE) {
        ret = ef_vi_capabilities_get(eio->dh, eio->ifindex,
            EF_VI_CAP_CTPIO, &capa_val);
        if (!ret && capa_val) {
            vi_flags |= EF_VI_TX_CTPIO;
        }
        if (cfg->tx.ctpio_no_poison == IRM_TRUE) {
            vi_flags |= EF_VI_TX_CTPIO_NO_POISON;
            ret = ef_vi_alloc_from_pd(&eio->vi, eio->dh, &eio->pd, eio->dh,
                -1, IRM_EFVI_RX_RING, IRM_EFVI_TX_RING, NULL, -1,
                (enum ef_vi_flags)vi_flags);
            if (ret >= 0) {
                eio->ctpio = IRM_TRUE;
                goto DO_NETIO_INIT;
            }
        }
        IRM_INFO("alloc efvi with ctpio_no_poison failed, err %d", ret);

        vi_flags &= ~EF_VI_TX_CTPIO_NO_POISON;
        ret = ef_vi_alloc_from_pd(&eio->vi, eio->dh, &eio->pd, eio->dh,
            -1, IRM_EFVI_RX_RING, IRM_EFVI_TX_RING, NULL, -1,
            (enum ef_vi_flags)vi_flags);
        if (ret >= 0) {
            eio->ctpio = IRM_TRUE;
            goto DO_NETIO_INIT;
        }
        IRM_WARN("alloc efvi with ctpio failed, err %d", ret);    
    }
    vi_flags = EF_VI_FLAGS_DEFAULT;
     
    ret = ef_vi_alloc_from_pd(&eio->vi, eio->dh, &eio->pd, eio->dh,
        -1, IRM_EFVI_RX_RING, IRM_EFVI_TX_RING, NULL, -1,
        (enum ef_vi_flags)vi_flags);
    if (ret < 0) {
        IRM_ERR("alloc efvi with tx default failed, err %d", ret);    
        ret = -IRM_ERR_ALLOC_EFVI; 
        goto DO_EXIT;
    }
    
DO_NETIO_INIT:
    ef_vi_get_mac(&eio->vi, eio->dh, eio->local_mac);
    eio->rx_prefix_len = ef_vi_receive_prefix_len(&eio->vi);
    efvi_netops.payload_offset += eio->rx_prefix_len; 
    ret = irm_netio_init(netio);
    if (ret < 0) {
        IRM_ERR("netio init error, err %d", ret);
        goto DO_EXIT;
    }
    ret = irm_efvi_netio_mbuf_pool_init(mpool, eio);
    if (ret != IRM_OK) {
        IRM_ERR("efvi netio mbuf pool init failed, err %d", ret);
        goto DO_EXIT;
    }

    eio->max_fill = ef_vi_receive_capacity(&eio->vi) - 16;
    eio->refill_level = eio->max_fill - IRM_EFVI_REFILL_BATCH_SIZE;
    eio->refill_min = eio->max_fill >> 1;
    IRM_DBG("max_fill %d", eio->max_fill);
    for (i = 0; i < eio->max_fill; ++i) {
        mbuf = irm_mbuf_get(&netio->rx_pool);
        if (!mbuf) {
            IRM_WARN("fill %d mbufs in rx ring", i);
            break;
        }
        ret = ef_vi_receive_init(&eio->vi, mbuf->ef_addr, mbuf->id); 
        if (ret < 0) {
            IRM_ERR("ef_vi_receive_init failed, ret %d", ret);
        }
    } 
    ef_vi_receive_push(&eio->vi);
    
    ef_filter_spec_init(&eio->ef_filter, EF_FILTER_FLAG_NONE);
    ret = ef_filter_spec_set_ip4_local(&eio->ef_filter, IPPROTO_UDP,
        eio->netio.mcgroup_ip_be32, eio->netio.mcgroup_port_be16);
    if (ret < 0) {
        IRM_ERR("ef_filter_spec_set_ip4_local failed, err %d", ret);
        ret = irm_errno = -IRM_ERR_EFCTX_INIT_SET_IP4_LOCAL;
        goto DO_EXIT;
    }

    ret = ef_vi_filter_add(&eio->vi, eio->dh, &eio->ef_filter, NULL);
    if (ret < 0) {
        ret = irm_errno = -IRM_ERR_EFCTX_INIT_FILTER_ADD;
        IRM_ERR("ef_vi_filter_add failed, err %d", ret);
    }
    
DO_EXIT:
    if (ret != IRM_OK) {
        return ret;
    }

    return IRM_OK;
}

static int irm_efvi_netio_deinit(struct irm_netio* netio)
{
    struct irm_efvi_netio* eio = IRM_EFVI_NETIO(netio);
    if (eio->memreg_ok) {
        ef_memreg_free(&eio->memreg, eio->dh);    
    }
    ef_vi_free(&eio->vi, eio->dh);
    ef_pd_free(&eio->pd, eio->dh);
    ef_driver_close(eio->dh);
    irm_netio_deinit(netio);
    return IRM_OK;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_efvi_netio_ingress_process(struct irm_netio* netio)
{
    struct irm_efvi_netio* eio = IRM_EFVI_NETIO(netio);
    struct irm_mbuf*       sent_mbuf;
    ef_request_id          ids[EF_VI_TRANSMIT_BATCH];
    ef_event               evs[IRM_EFVI_INGRESS_POLL_EVENT_N];
    int                    events;
    int                    i;
    int                    sent_n;
    int                    j;

    irm_efvi_netio_refill_rx(IRM_EFVI_NETIO(netio));
    events = ef_eventq_poll(&eio->vi, evs, IRM_EFVI_INGRESS_POLL_EVENT_N);
    if (IRM_UNLIKELY(events <= 0)) {
        if (!netio->idle_ts)  {
            netio->idle_ts = irm_get_cycle();        
        }
        return IRM_OK;
    }
    for (i = 0; i < events; ++i) {
        switch (EF_EVENT_TYPE(evs[i])) {
            case EF_EVENT_TYPE_RX:
                IRM_DBG("EF_EVENT_TYPE_RX");
                irm_efvi_netio_handle_rx(netio, EF_EVENT_RX_RQ_ID(evs[i]),
                    EF_EVENT_RX_BYTES(evs[i]) - eio->rx_prefix_len);
                break;
            case EF_EVENT_TYPE_TX:
                IRM_DBG("EF_EVENT_TYPE_TX");
                sent_n = ef_vi_transmit_unbundle(&eio->vi, &evs[i], ids);
                IRM_DBG("sent_n %d", sent_n);
                for (j = 0; j < sent_n; ++j) {
                    sent_mbuf = IRM_EFVI_NETIO_ID2M(netio->mbuf_pool, ids[j]);
                    sent_mbuf->status = IRM_MBUF_STATUS_IDLE;
                    IRM_DBG("sent_mbuf %p, mbuf id %u, reserved %u", sent_mbuf,
                        ids[j], sent_mbuf->reserved);
                }
                break;
        }
    }
    netio->idle_ts = 0;
    return IRM_OK;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_efvi_netio_fifo(struct irm_netio*netio, struct irm_mbuf* mbufs[],
    uint32_t max)
{
    return irm_buffer_fifo_idle(netio->tx_buffer, mbufs, max);        
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_efvi_netio_egress_process(struct irm_netio* netio)
{
    struct irm_msg_header* header;
    struct irm_mbuf*       mbuf;
    struct irm_mbuf*       sent_mbuf;
    ef_event               evs[IRM_EFVI_EGRESS_POLL_EVENT_N];
    ef_request_id          ids[EF_VI_TRANSMIT_BATCH];
    int                    events;
    int                    i;
    int                    sent_n;
    int                    j;
    int                    ret;
    struct irm_efvi_netio* eio = IRM_EFVI_NETIO(netio);
    

    mbuf = (struct irm_mbuf *)irm_buffer_get(netio->tx_buffer); 
    if (IRM_UNLIKELY(!mbuf)) {
        if (!netio->idle_ts) {
            netio->idle_ts = irm_get_cycle();
        }
        goto IRM_EVENT_POLL;
    }
    header = IRM_MBUF_MSG(irm_msg_header, mbuf, efvi_netops.payload_offset);
    netio->last_send_seq = (int64_t)header->seq;
    ret = irm_efvi_netio_send(netio, mbuf);

    IRM_DBG("irm_efvi_netio_send ret %d", ret);

    if (IRM_UNLIKELY(ret < 0)) {
        IRM_ERR("efvi send failed, error %d", ret);
        mbuf->status = IRM_MBUF_STATUS_IDLE;
        IRM_DBG("rollback mbuf %u, msg type %u, seq %u", mbuf->id,
            header->msg_type, header->seq);
        irm_buffer_rollback(netio->tx_buffer);
    }

IRM_EVENT_POLL:
    irm_efvi_netio_refill_rx(IRM_EFVI_NETIO(netio));
    events = ef_eventq_poll(&eio->vi, evs, IRM_EFVI_EGRESS_POLL_EVENT_N);
    for (i = 0; i < events; ++i) {
        switch (EF_EVENT_TYPE(evs[i])) {
            case EF_EVENT_TYPE_TX:
                sent_n = ef_vi_transmit_unbundle(&eio->vi, &evs[i], ids);
                IRM_DBG("sent_n %d", sent_n);
                for (j = 0; j < sent_n; ++j) {
                    sent_mbuf = IRM_EFVI_NETIO_ID2M(netio->mbuf_pool, ids[j]);
                    sent_mbuf->status = IRM_MBUF_STATUS_IDLE;
                    IRM_DBG("sent_mbuf %p netio->mbuf_pool %p, mbuf id %u %u, reserved %u",
                        sent_mbuf, &netio->mbuf_pool->mbufs[ids[j]], ids[j],
                        sent_mbuf->id, sent_mbuf->reserved);

#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
                    {
                        uint8_t* dma_buf = IRM_MBUF_M2D(sent_mbuf);
                        struct irm_eth_hdr* eth_hdr = (struct irm_eth_hdr *)dma_buf;
                        struct irm_ip4_hdr* ip4_hdr = (struct irm_ip4_hdr *)(eth_hdr + 1);
                        struct irm_msg_header* header = IRM_MBUF_MSG(irm_msg_header,
                            sent_mbuf, efvi_netops.payload_offset);
                        IRM_DBG("sent mbuf, msg type %u, role %u, sender_id %u, "
                            "src ip %u.%u.%u.%u, dst ip %u.%u.%u.%u",
                            header->msg_type,
                            header->role, header->sender_id,
                            ((uint8_t*)&ip4_hdr->ip_saddr_be32)[0],
                            ((uint8_t*)&ip4_hdr->ip_saddr_be32)[1],
                            ((uint8_t*)&ip4_hdr->ip_saddr_be32)[2],
                            ((uint8_t*)&ip4_hdr->ip_saddr_be32)[3],
                            ((uint8_t*)&ip4_hdr->ip_daddr_be32)[0],
                            ((uint8_t*)&ip4_hdr->ip_daddr_be32)[1],
                            ((uint8_t*)&ip4_hdr->ip_daddr_be32)[2],
                            ((uint8_t*)&ip4_hdr->ip_daddr_be32)[3]);
                    }
#endif
                }
                break;
            case EF_EVENT_TYPE_RX:
                IRM_DBG("EF_EVENT_TYPE_RX");
                irm_efvi_netio_handle_rx(netio, EF_EVENT_RX_RQ_ID(evs[i]),
                    EF_EVENT_RX_BYTES(evs[i]) - eio->rx_prefix_len);
                break;
        }
    }
    return IRM_OK;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_efvi_netio_send(struct irm_netio* netio, struct irm_mbuf* mbuf)
{
    struct irm_efvi_netio* eio = IRM_EFVI_NETIO(netio);
    int                    ret = IRM_OK; 

    mbuf->status = IRM_MBUF_STATUS_SENDING;
    netio->idle_ts = 0;

    IRM_DBG("send mbuf %p %p, reserved %d, id %u",
        mbuf, &netio->mbuf_pool->mbufs[mbuf->id], mbuf->reserved, mbuf->id);

#if defined(IRM_DEBUG) || defined (IRM_DEBUG_VERBOSE)
    {
        struct irm_msg_header* header;
        header = IRM_MBUF_MSG(irm_msg_header, mbuf, efvi_netops.payload_offset);
        IRM_DBG("send msg type %u, sender_id %u, seq %u", header->msg_type,
            header->sender_id, header->seq);
    }
#endif

    irm_efvi_netio_update_size(mbuf);     
    if (eio->ctpio) {
        ef_vi_transmit_ctpio(&eio->vi, IRM_MBUF_M2D(mbuf),
            mbuf->payload, IRM_EFVI_CTPIO_THREASH);
        ret = ef_vi_transmit_ctpio_fallback(&eio->vi, IRM_MBUF_DMA(mbuf),
            mbuf->payload, IRM_MBUF_ID(mbuf));
#if defined(IRM_DEBUG) || defined (IRM_DEBUG_VERBOSE)
        if (ret < 0) {
            IRM_ERR("ctpio send failed %d", ret);
        }
#endif
        return ret;
    }
    ret = ef_vi_transmit(&eio->vi, IRM_MBUF_DMA(mbuf), mbuf->payload,
        IRM_MBUF_ID(mbuf));
#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
    if (ret < 0) {
        IRM_ERR("transmit failed %d", ret);
    }
#endif

    return ret;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE void
irm_efvi_netio_handle_rx(struct irm_netio* netio, uint32_t id, int len)
{
    struct irm_mbuf* mbuf = IRM_EFVI_NETIO_ID2M(netio->mbuf_pool, id);

#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
    uint8_t* dma_buf = IRM_MBUF_M2D(mbuf);
    struct irm_eth_hdr* eth_hdr = (struct irm_eth_hdr *)dma_buf;
    struct irm_ip4_hdr* ip4_hdr = (struct irm_ip4_hdr *)(eth_hdr + 1);
    struct irm_msg_header* header = IRM_MBUF_MSG(irm_msg_header, mbuf,
        efvi_netops.payload_offset);
    IRM_DBG("received mbuf id %u, len %u, msg type %u, role %u, sender_id %u, "
        "msg size %u, src ip %u.%u.%u.%u, dst ip %u.%u.%u.%u", id, (uint32_t)len,
        header->msg_type, header->role, header->sender_id, header->size,
        ((uint8_t*)&ip4_hdr->ip_saddr_be32)[0], ((uint8_t*)&ip4_hdr->ip_saddr_be32)[1],
        ((uint8_t*)&ip4_hdr->ip_saddr_be32)[2], ((uint8_t*)&ip4_hdr->ip_saddr_be32)[3],
        ((uint8_t*)&ip4_hdr->ip_daddr_be32)[0], ((uint8_t*)&ip4_hdr->ip_daddr_be32)[1],
        ((uint8_t*)&ip4_hdr->ip_daddr_be32)[2], ((uint8_t*)&ip4_hdr->ip_daddr_be32)[3]);
#endif

    mbuf->size = (uint32_t)len;
    netio->idle_ts = 0;
    netio->process_msg_rx_handle(netio->ctx, mbuf);
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_efvi_netio_refill_rx(struct irm_efvi_netio* eio)
{
    struct irm_netio*         netio = IRM_NETIO(eio);
    struct irm_mbuf_pool_mgr* rx_pool = &netio->rx_pool;
    struct irm_mbuf*          mbufs[IRM_EFVI_REFILL_BATCH_SIZE];
    uint32_t                  i;
    uint32_t                  n;
    
    if (ef_vi_receive_fill_level(&eio->vi) > eio->refill_level
        || irm_mbuf_available(rx_pool) < IRM_EFVI_REFILL_BATCH_SIZE) {
#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
        IRM_DBG("don't need refill level %d, fill level %d, available %u",
            eio->refill_level, ef_vi_receive_fill_level(&eio->vi),
            irm_mbuf_available(rx_pool));
#endif
        return IRM_FALSE;
    }

    do {
        n = irm_mbuf_get_batch(rx_pool, mbufs, IRM_EFVI_REFILL_BATCH_SIZE); 
        for (i = 0; i < n; ++i) {
            ef_vi_receive_init(&eio->vi, mbufs[i]->ef_addr, mbufs[i]->id); 
        } 
        IRM_DBG("refill mubf %u", n);
    } while (ef_vi_receive_fill_level(&eio->vi) < eio->refill_min
        && irm_mbuf_available(rx_pool) >= IRM_EFVI_REFILL_BATCH_SIZE);

    ef_vi_receive_push(&eio->vi);

    return IRM_TRUE;
}

static int irm_efvi_netio_mbuf_pool_init(void* mpool,
    struct irm_efvi_netio* eio)
{
    struct irm_netio*            netio = IRM_NETIO(eio);
    struct irm_config*           cfg = netio->cfg;
    struct irm_mbuf_pool*        pool; 
    struct irm_mbuf*             mbuf;
    uint32_t                     i;
    uint32_t                     rx_count;
    uint32_t                     tx_count;
    uint32_t                     rv_count;
    uint32_t                     count;
    int                          ret;

    rx_count = irm_power2_align32(cfg->rx.mbuf_count);
    tx_count = irm_power2_align32(cfg->tx.mbuf_count);
    rv_count = irm_power2_align32(cfg->rv.mbuf_count);
    count = rx_count + tx_count + rv_count;
    pool = irm_mbuf_pool_create(mpool, count, 0, 0, 0);
    if (!pool) {
        return irm_errno;
    }

    IRM_DBG("PKT ADDR %p, PKT_SIZE %u", IRM_MBUF_PKT(pool),
        IRM_MBUF_PKT_SIZE(pool));
    ret = ef_memreg_alloc(&eio->memreg, eio->dh, &eio->pd, eio->dh,
        IRM_MBUF_PKT(pool), IRM_MBUF_PKT_SIZE(pool));
    if (ret) {
        IRM_DBG("ef_memreg_alloc failed, ret %d", ret);
        eio->memreg_ok = IRM_FALSE;
        return -IRM_ERR_EFVI_MEMREG_ALLOC;
    }
    eio->memreg_ok = IRM_TRUE;
    efvi_netops.max_payload_size = pool->elt_size - efvi_netops.payload_offset;

    for (i = 0; i < count; ++i) {
        mbuf = pool->ring[i];
        mbuf->reserved = IRM_FALSE;
        mbuf->ef_addr = ef_memreg_dma_addr(&eio->memreg,
            i * IRM_MBUF_ELT_SIZE) + sizeof(struct irm_mbuf);
        irm_efvi_netio_udp_init(eio, pool->ring[i]);
    } 
    netio->mbuf_pool = pool;
    IRM_POOL_MGR_INIT(&netio->rx_pool, pool, rx_count);
    IRM_POOL_MGR_INIT(&netio->tx_pool, pool, tx_count);
    IRM_POOL_MGR_INIT(&netio->rv_pool, pool, rv_count);

    return IRM_OK;
}

static void irm_efvi_netio_eth_init(struct irm_efvi_netio* eio,
    struct irm_eth_hdr* eth)
{
    struct irm_netio* netio = IRM_NETIO(eio);
    eth->dst_host[0] = 0x1;
    eth->dst_host[1] = 0;
    eth->dst_host[2] = 0x5e;
    eth->dst_host[3] = 0x7f & (netio->mcgroup_ip_be32 >> 8);
    eth->dst_host[4] = 0xff & (netio->mcgroup_ip_be32 >> 16);
    eth->dst_host[5] = 0xff & (netio->mcgroup_ip_be32 >> 24);
    irm_memcpy(eth->src_host, eio->local_mac, IRM_ETH_ALEN);
    eth->eth_type = irm_htons(IRM_ETH_TYPE_IP);
}

static void irm_efvi_netio_ip4_init(struct irm_efvi_netio* eio,
    struct irm_ip4_hdr* ip4)
{
    struct irm_netio*   netio = IRM_NETIO(eio);
    static uint16_t     id = 0;

    ip4->ip_ihl_version = 0x40 | sizeof(struct irm_ip4_hdr) >> 2;
    ip4->ip_tos = 0x10;
    ip4->ip_tot_len_be16 = 0;
    ip4->ip_id_be16 = irm_htons(id);
    id++;
    ip4->ip_frag_off_be16 = 0;
    ip4->ip_ttl = 64;
    ip4->ip_protocol = IPPROTO_UDP;
    ip4->ip_saddr_be32 = netio->local_ip_be32;
    ip4->ip_daddr_be32 = netio->mcgroup_ip_be32;
    ip4->ip_check_be16 = 0;
}

static void irm_efvi_netio_udp_init(struct irm_efvi_netio* eio,
    struct irm_mbuf* mbuf)
{
    struct irm_netio*   netio = IRM_NETIO(eio);
    uint8_t*            dma_buf = IRM_MBUF_M2D(mbuf);
    struct irm_eth_hdr* eth_hdr = (struct irm_eth_hdr *)dma_buf;
    struct irm_ip4_hdr* ip4_hdr = (struct irm_ip4_hdr *)(eth_hdr + 1);
    struct irm_udp_hdr* udp_hdr = (struct irm_udp_hdr *)(ip4_hdr + 1);

    irm_efvi_netio_eth_init(eio, eth_hdr);
    irm_efvi_netio_ip4_init(eio, ip4_hdr);

    udp_hdr->udp_source_be16 = netio->local_port_be16;
    udp_hdr->udp_dest_be16 = netio->mcgroup_port_be16;
    udp_hdr->udp_len_be16 = 0;
    udp_hdr->udp_check_be16 = 0;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE void
irm_efvi_netio_update_size(struct irm_mbuf* mbuf)
{
    struct irm_eth_hdr* eth_hdr = (struct irm_eth_hdr *)IRM_MBUF_M2D(mbuf);
    struct irm_ip4_hdr* ip4_hdr = (struct irm_ip4_hdr *)(eth_hdr + 1);
    struct irm_udp_hdr* udp_hdr = (struct irm_udp_hdr *)(ip4_hdr + 1);
    uint16_t            udp_paylen = sizeof(struct irm_udp_hdr) + mbuf->size;
    uint16_t            ip_paylen = sizeof(struct irm_ip4_hdr) + udp_paylen;

#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
    {
        struct irm_msg_header* header;
        header = IRM_MBUF_MSG(irm_msg_header, mbuf, efvi_netops.payload_offset);
        IRM_DBG("mbuf %p, mbuf size %u, dma addr %lu, msg type %u, sender_id %u, seq %u, size %u, role %u",
            mbuf, mbuf->size, mbuf->ef_addr, header->msg_type, header->sender_id, header->seq,
            header->size, header->role);
    }    
#endif
    ip4_hdr->ip_tot_len_be16 = irm_htons(ip_paylen);
    udp_hdr->udp_len_be16 = irm_htons(udp_paylen);
    mbuf->payload = ip_paylen + sizeof(struct irm_eth_hdr);

    IRM_DBG("payload %u, udp header %lu, udp_paylen %u", mbuf->payload,
        sizeof(struct irm_udp_hdr), udp_paylen);
    IRM_DBG("eth hdr %lu, ip header %lu, ip_paylen %u", sizeof(struct irm_eth_hdr),
        sizeof(struct irm_ip4_hdr), ip_paylen);
    ip4_hdr->ip_check_be16 = irm_ip_checksum(ip4_hdr);

#ifdef IRM_EFVI_NETIO_CHECKSUM
    {
        struct iovec iov;

        iov.iov_base = udp_hdr + 1;
        iov.iov_len = paylen;
        udp_hdr->udp_check_be16 = ef_udp_checksum((const struct iphdr*)ip4_hdr,
            (const struct udphdr*)udp_hdr, &iov, 1);
    }
#endif
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE void
irm_efvi_netio_blacklist_set(struct irm_netio* IRM_UNUSED(netio),
    uint32_t IRM_UNUSED(ip_be32))
{
    return;
}

IRM_C_END
