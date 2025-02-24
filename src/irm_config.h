/* huangying */
#ifndef IRM_CONFIG_H
#define IRM_CONFIG_H

#include <stdint.h>

#include "irm_decls.h"
#include "irm_socket.h"
#include "irm_sockopt.h"

IRM_C_BEGIN

#ifndef IRM_CONFIG_RETRY_DEFAULT
#define IRM_CONFIG_RETRY_DEFAULT                5
#endif

#ifndef IRM_CONFIG_MCGROUP_IP_DEFAULT
#define IRM_CONFIG_MCGROUP_IP_DEFAULT           "239.1.1.1"
#endif

#ifndef IRM_CONFIG_MCGROUP_PORT_DEFAULT
#define IRM_CONFIG_MCGROUP_PORT_DEFAULT         5555
#endif

#ifndef IRM_CONFIG_LOCAL_PORT_DEFAULT
#define IRM_CONFIG_LOCAL_PORT_DEFAULT           6666 
#endif

#ifndef IRM_CONFIG_TIMEOUT_SPAN_DEFAULT
#define IRM_CONFIG_TIMEOUT_SPAN_DEFAULT         (10 * 1000)
#endif

#ifndef IRM_CONFIG_TIMEOUT_TIMES_DEFAULT
#define IRM_CONFIG_TIMEOUT_TIMES_DEFAULT        3  
#endif

#ifndef IRM_CONFIG_TIMEOUT_RENACK
#define IRM_CONFIG_TIMEOUT_RENACK               (10)
#endif

#ifndef IRM_CONFIG_TIMEOUT_RENACK_BASE          
#define IRM_CONFIG_TIMEOUT_RENACK_BASE          (50 * 1000)
#endif

#ifndef IRM_CONFIG_TIMEOUT_BREAKPOINT
#define IRM_CONFIG_TIMEOUT_BREAKPOINT           (50 * 1000)
#endif

#ifndef IRM_CONFIG_PUB_TX_MBUF_COUNT_DEFAULT
#define IRM_CONFIG_PUB_TX_MBUF_COUNT_DEFAULT    (1U << 16)
#endif

#ifndef IRM_CONFIG_PUB_TX_MBUF_COUNT_NATIVE_DEFAULT
#define IRM_CONFIG_PUB_TX_MBUF_COUNT_NATIVE_DEFAULT (1U << 18)
#endif

#ifndef IRM_CONFIG_PUB_TX_MBUF_COUNT_MIN
#define IRM_CONFIG_PUB_TX_MBUF_COUNT_MIN        (1U << 14)
#endif

#ifndef IRM_CONFIG_PUB_FIFO_THRESHOLD
#define IRM_CONFIG_PUB_FIFO_THRESHOLD           (512U)
#endif

#ifndef IRM_CONFIG_PUB_FIFO_TIMEOUT
#define IRM_CONFIG_PUB_FIFO_TIMEOUT             (500 * 1000)
#endif

#ifndef IRM_CONFIG_PUB_RX_MBUF_COUNT_DEFAULT
#define IRM_CONFIG_PUB_RX_MBUF_COUNT_DEFAULT    (32U)
#endif

#ifndef IRM_CONFIG_SUB_TX_MBUF_COUNT_DEFAULT
#define IRM_CONFIG_SUB_TX_MBUF_COUNT_DEFAULT    (32U)
#endif

#ifndef IRM_CONFIG_SUB_RX_MBUF_COUNT_DEFAULT
#define IRM_CONFIG_SUB_RX_MBUF_COUNT_DEFAULT    (1U << 16)
#endif

#ifndef IRM_CONFIG_SUB_RX_MBUF_COUNT_NATIVE_DEFAULT
#define IRM_CONFIG_SUB_RX_MBUF_COUNT_NATIVE_DEFAULT    (1U << 18)
#endif

#ifndef IRM_CONFIG_SUB_RX_MBUF_COUNT_MIN
#define IRM_CONFIG_SUB_RX_MBUF_COUNT_MIN        (1U << 14)
#endif

#ifndef IRM_CONFIG_MBUF_SIZE_DEFAULT
#define IRM_CONFIG_MBUF_SIZE_DEFAULT            (1U << 11)
#endif

#ifndef IRM_CONFIG_MBUF_SIZE_NATIVE_DEFAULT
#define IRM_CONFIG_MBUF_SIZE_NATIVE_DEFAULT     (1U << 10)
#endif

#ifndef IRM_CONFIG_INVITATION_TIMES             
#define IRM_CONFIG_INVITATION_TIMES             3
#endif

#ifndef IRM_CONFIG_INVITATION_RETRY
#define IRM_CONFIG_INVITATION_RETRY             5
#endif

#ifndef IRM_CONFIG_INVITATION_WAIT_SUB_COUNT
#define IRM_CONFIG_INVITATION_WAIT_SUB_COUNT    1
#endif

#ifndef IRM_CONFIG_CPU_PRIORITY_DEFAULT
#define IRM_CONFIG_CPU_PRIORITY_DEFAULT         1
#endif

#ifndef IRM_CONFIG_HEARTBEAT_SEND_TIMEOUT
#define IRM_CONFIG_HEARTBEAT_SEND_TIMEOUT       (5000 * 1000)
#endif

#ifndef IRM_CONFIG_HEARTBEAT_ALIVE_TIMEOUT
#define IRM_CONFIG_HEARTBEAT_ALIVE_TIMEOUT      (5000 * 1000)
#endif

#ifndef IRM_CONFIG_PATH_MAX
#define IRM_CONFIG_PATH_MAX                     4096
#endif

#ifndef IRM_CONFIG_TX_WEIGHT
#define IRM_CONFIG_TX_WEIGHT                    100
#endif

#ifndef IRM_CONFIG_SKBUF_RD                     
#define IRM_CONFIG_SKBUF_RD                     0
#endif

#ifndef IRM_CONFIG_SKBUF_WR
#define IRM_CONFIG_SKBUF_WR                     0
#endif

#ifndef IRM_CONFIG_MEMORY_POOL_SIZE            
#define IRM_CONFIG_MEMORY_POOL_SIZE            (1UL << 29)
#endif

struct irm_config_reserved {
    uint32_t    mbuf_count;
};

struct irm_config_weight {
    uint32_t    tx;
    uint32_t    rx;
};

struct irm_config {
    int                          io_mode;
    int                          retry;
    char                         path[IRM_CONFIG_PATH_MAX];
    size_t                       path_len;
    uint32_t                     hugepage_size;
    struct irm_config_addr       addr;
    struct irm_config_cpu        cpu;
    struct irm_config_timeout    timeout;
    struct irm_config_tx         tx;
    struct irm_config_rx         rx;
    struct irm_config_memory     memory;
    struct irm_config_invitation invitation;
    struct irm_config_heartbeat  heartbeat;
    struct irm_config_storage    storage;
    struct irm_config_reserved   rv;
    struct irm_config_weight     weight;
    struct irm_config_name       name;
    struct irm_config_skbuf      skbuf;
};

IRM_C_END

#endif
