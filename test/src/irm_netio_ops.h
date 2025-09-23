/* huangying */
#ifndef IRM_NETIO_OPS_H
#define IRM_NETIO_OPS_H

#include <stdint.h>

#include "irm_config.h"
#include "irm_netio.h"

IRM_C_BEGIN
struct irm_netio_ops {
    uint32_t    payload_offset;
    uint32_t    max_payload_size;
    struct irm_netio* (*create) (void* mpool, struct irm_config* cfg);
    int (*init) (void* mpool, struct irm_netio* netio);
    int (*deinit) (struct irm_netio* netio);

    int (*ingress_process) (struct irm_netio* netio);
    int (*egress_process) (struct irm_netio* netio);

    int (*send) (struct irm_netio* netio, struct irm_mbuf* mbuf);
    
    uint32_t (*fifo) (struct irm_netio* netio, struct irm_mbuf* mbufs[], uint32_t max);

    void (*blacklist_set) (struct irm_netio* netio, uint32_t ip_be32);
};

IRM_C_END
#endif
