/* huangying */
#ifndef IRM_ETHTOOL_H
#define IRM_ETHTOOL_H

#include <stdint.h>
#include <net/if.h>

#include "irm_decls.h"

IRM_C_BEGIN
struct irm_ethtool_ringparam {
    uint32_t   cmd;  
    uint32_t   rx_max_pending;
    uint32_t   rx_mini_max_pending;
    uint32_t   rx_jumbo_max_pending;
    uint32_t   tx_max_pending;
    uint32_t   rx_pending;
    uint32_t   rx_mini_pending;
    uint32_t   rx_jumbo_pending;
    uint32_t   tx_pending;
};
int irm_ethtool_ring_set_max(const char* ifname, int rx, int tx);
IRM_C_END
#endif
