/* huangying */
#ifndef IRM_EFVI_NETIO_H
#define IRM_EFVI_NETIO_H

#include <netinet/in.h>

#include "irm_netio.h"
#include "irm_netio_ops.h"
#include "irm_mbuf_pool.h"

#include "etherfabric/pio.h"
#include "etherfabric/vi.h"
#include "etherfabric/pd.h"
#include "etherfabric/memreg.h"
#include "etherfabric/ef_vi.h"

#ifndef IRM_MAC_LEN
#define IRM_MAC_LEN 6
#endif

#ifndef IRM_EFVI_IP_FILTER_LEN
#define IRM_EFVI_IP_FILTER_LEN  256
#endif

IRM_C_BEGIN
extern struct irm_netio_ops efvi_netops;

struct irm_efvi_netio {
    struct irm_netio            netio;
    int                         ifindex;
    int                         rx_prefix_len;
    int                         ctpio;
    int                         refill_level;
    int                         refill_min;
    int                         max_fill;
    struct irm_mbuf_pool*       mbuf_pool;
    ef_driver_handle            dh;
    ef_filter_spec              ef_filter; 
    ef_pd                       pd;
    ef_vi                       vi;
    ef_memreg                   memreg;
    enum ef_pd_flags            pd_flags;
    ef_pio                      pio;
    enum ef_vi_flags            vi_flags;
    int                         memreg_ok;
    uint8_t                     mcgroup_mac[IRM_MAC_LEN];
    uint8_t                     local_mac[IRM_MAC_LEN];
    struct ip_msfilter*         filter;
    char                        buf[IP_MSFILTER_SIZE(IRM_EFVI_IP_FILTER_LEN)];
} IRM_ATTR_CACHELINE_ALIGN;

#define IRM_EFVI_NETIO(_netio) ((struct irm_efvi_netio *)_netio)

IRM_C_END
#endif
