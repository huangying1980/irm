/* huangying */
#ifndef IRM_SOCKOPT_H
#define IRM_SOCKOPT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    IRM_CONFIG_TYPE_RETRY = 0,
    IRM_CONFIG_TYPE_ADDR,
    IRM_CONFIG_TYPE_IO_MODE,
    IRM_CONFIG_TYPE_CPU,
    IRM_CONFIG_TYPE_TIMEOUT,
    IRM_CONFIG_TYPE_TX,
    IRM_CONFIG_TYPE_RX,
    IRM_CONFIG_TYPE_MEMORY,
    IRM_CONFIG_TYPE_HUGEPAGE,
    IRM_CONFIG_TYPE_INVITATION,
    IRM_CONFIG_TYPE_HEARTBEAT,
    IRM_CONFIG_TYPE_STORAGE,
    IRM_CONFIG_TYPE_NAME,
    IRM_CONFIG_TYPE_SKBUF,
    IRM_CONFIG_TYPE_MAX
};

struct irm_config_addr {
    char        ifname[IRM_IFNAME_MAX_LEN];
    char        mcgroup_ip[IRM_IP_MAX_LEN];
    uint16_t    mcgroup_port;
    char        local_ip[IRM_IP_MAX_LEN];
    uint16_t    local_port; 
};

struct irm_config_cpu {
    int         cpu_id;
    int         rt;
    int         priority;
};
struct irm_config_timeout {
    uint64_t    span_us;
    uint8_t     times;    
    uint64_t    nack_timeout;
    uint64_t    breakpoint_timeout;
};
struct irm_config_tx {
    uint32_t    mbuf_count;
    uint32_t    mbuf_size;
    uint32_t    fifo_threshold;
    uint64_t    fifo_timeout;
    int         ctpio;
    int         ctpio_no_poison;
};

struct irm_config_rx {
    uint32_t    mbuf_count;
    uint32_t    mbuf_size;
    uint32_t    recycle;
};

struct irm_config_memory {
    uint32_t    channel;
    uint32_t    rank;
    uint64_t    pool_size;
};

struct irm_config_invitation {
    uint32_t    times;
    int         retry; 
    uint8_t     wait_sub_count;
};

struct irm_config_heartbeat {
    uint64_t    send_timeout;
    uint64_t    alive_timeout; 
};

struct irm_config_storage {
    int         enable;
    int         cpu_id;
    int         rt;
    int         priority;
    uint32_t    sobj_count;
    uint32_t    sobj_size;
    uint32_t    task_count;
};

struct irm_config_skbuf {
    uint32_t    rd;
    uint32_t    wr;
};

struct irm_config_name {
    char        pub[IRM_NAME_MAX_LEN + 1];
    char        sub[IRM_NAME_MAX_LEN + 1];
};

int irm_pub_setsockopt(IRM_PUBHANDLE handle, int type, void* val, size_t val_len);
int irm_pub_getsockopt(IRM_PUBHANDLE handle, int type, void* val, size_t val_len);

int irm_sub_setsockopt(IRM_SUBHANDLE handle, int type, void* val, size_t val_len);
int irm_sub_getsockopt(IRM_SUBHANDLE handle, int type, void* val, size_t val_len);

#ifdef __cplusplus
}
#endif

#endif
