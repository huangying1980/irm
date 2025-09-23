/* huangying */
#ifndef IRM_NET_IO_H
#define IRM_NET_IO_H

#include <stdint.h>
#include <netinet/in.h>

#include "irm_decls.h"
#include "irm_config.h"
#include "irm_mbuf_pool.h"
#include "irm_common.h"
#include "irm_time_clock.h"

IRM_C_BEGIN

#ifndef IRM_NETIO_IP_FILTER_LEN
#define IRM_NETIO_IP_FILTER_LEN 256
#endif

struct irm_netio {
    
    int64_t                     last_send_seq;
    uint32_t                    local_ip_be32;
    uint32_t                    mcgroup_ip_be32;
    uint16_t                    mcgroup_port_be16;
    uint16_t                    local_port_be16;
    uint32_t                    tx_times;
    int                         gfd;  
    int                         lfd;
    struct irm_buffer*          tx_buffer;
    struct irm_buffer*          rx_buffer;
    struct irm_mbuf_pool*       mbuf_pool;
    struct irm_mbuf_pool_mgr    rx_pool;
    struct irm_mbuf_pool_mgr    tx_pool;
    struct irm_mbuf_pool_mgr    rv_pool;
    struct irm_config*          cfg;
    void*                       ctx;
    uint64_t                    idle_ts;
    int (*process_msg_rx_handle) (void* ctx, struct irm_mbuf* mbuf);
    int (*process_msg_tx_handle) (void* ctx, struct irm_mbuf* mbuf);

} IRM_ATTR_CACHELINE_ALIGN;

enum {
    IRM_NETIO_OPTION_MBUF_RX_POOL,
    IRM_NETIO_OPTION_MBUF_TX_POOL,
    IRM_NETIO_OPTION_MBUF_RV_POOL,
    IRM_NETIO_OPTION_MAX
};

#define IRM_NETIO(_netio) ((struct irm_netio *)(_netio))
#define IRM_NETIO_GET_IDLE(_netio) ((_netio)->idle_ts)
#define IRM_NETIO_UPDATE_IDLE(_netio, _ts) ((_netio)->idle_ts = (_ts))

int irm_netio_init(struct irm_netio* netio);
void irm_netio_deinit(struct irm_netio* netio);
int irm_netio_set_option(struct irm_netio* netio, uint32_t type,
    void* val, size_t val_len);

IRM_C_END
#endif
