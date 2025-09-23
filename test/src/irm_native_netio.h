/* huangying */
#ifndef IRM_NATIVE_NETIO_H
#define IRM_NATIVE_NETIO_H

#include <netinet/in.h>

#include "irm_netio.h"
#include "irm_netio_ops.h"

IRM_C_BEGIN


extern struct irm_netio_ops native_netops;
struct irm_native_netio {
    struct irm_netio      netio;
    struct sockaddr_in    remote;
    struct ip_msfilter*   filter;
    char                  buf[IP_MSFILTER_SIZE(IRM_NETIO_IP_FILTER_LEN)];
} IRM_ATTR_CACHELINE_ALIGN;

#define IRM_NATIVE_NETIO(_netio) ((struct irm_native_netio *)(_netio))

IRM_C_END
#endif
