/* huangying */
#ifndef IRM_SUB_CONTEXT_H
#define IRM_SUB_CONTEXT_H

#include <pthread.h>

#include "irm_mbuf_pool.h"
#include "irm_queue.h"
#include "irm_msg.h"
#include "irm_netio_ops.h"

IRM_C_BEGIN

#ifndef IRM_PUB_MAX
#define IRM_PUB_MAX 256
#endif

enum {
    IRM_SUB_INVITATION_MBUF_ID = 0,
    IRM_SUB_ASK_MBUF_ID,
    IRM_SUB_HEARTBEAT_MBUF_ID,
    IRM_SUB_NACK_MBUF_ID,
    IRM_SUB_CLOSE_MBUF_ID,
    IRM_SUB_RESERVE_MBUF_MAX
};

struct irm_pub_cache {
    struct irm_queue cache_list;
    uint32_t         min;
    uint32_t         max;
    uint32_t         count;
};

struct irm_sub_nack {
    uint64_t        ts;
    uint64_t        timeout;
    uint32_t        start;
    uint32_t        end;
    uint32_t        count;
};
struct irm_pub_desc {
    uint32_t                last_seq;
    uint32_t                token;
    int                     alive;
    int                     slot;
    uint8_t                 online;
    uint8_t                 idle_times;
    struct irm_sub_nack     nack;
    struct irm_pub_cache    cache;
    uint32_t                ip_be32;
} IRM_ATTR_CACHELINE_ALIGN;

struct irm_pub_info {
    uint32_t            size;
    uint8_t             alive_count;
    uint8_t             alives[IRM_PUB_MAX];
    struct irm_pub_desc desc[IRM_PUB_MAX];
};

struct irm_sub_context {
    uint32_t                  invitation_seq;
    uint32_t                  heartbeat_seq;
    uint32_t                  nack_seq;
    uint32_t                  cache_count;
    uint8_t                   self_id;
    struct irm_pub_info*      pubs;
    volatile int              quit;
    struct irm_netio*         netio;
    struct irm_buffer*        rx_buffer;
    struct irm_queue          cache_list;
    struct irm_netio_ops      netops;
    struct irm_mbuf*          reserved_mbufs[IRM_SUB_RESERVE_MBUF_MAX];
    uint64_t                  renack_timeout;
    uint64_t                  nack_all_timeout;
    uint64_t                  renack_timeout_base;
#ifdef IRM_RUNTIME_ENABLE
    struct irm_runtime        runtime;
#endif
    pthread_t                 event_loop_thread_id;
    struct irm_config         cfg;
    void*                     mpool;
};

#define IRM_SUB_CTX(_c) ((struct irm_sub_context *)(_c))
#define IRM_SUB_ALIVE_PUB_COUNT(_c) ((_c)->pubs->alive_count)
struct irm_sub_context* irm_sub_context_create(void);
int irm_sub_context_init(struct irm_sub_context* ctx);
void irm_sub_context_release(struct irm_sub_context* ctx);
void irm_sub_context_close(struct irm_sub_context* ctx);

IRM_C_END
#endif
