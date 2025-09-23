/* huangying */
#ifndef IRM_PUB_CONTEXT_H
#define IRM_PUB_CONTEXT_H

#include "irm_decls.h"
#include "irm_netio.h"
#include "irm_netio_ops.h"
#include "irm_storage.h"

IRM_C_BEGIN

#ifndef IRM_SUB_MAX
#define IRM_SUB_MAX 256
#endif

#ifndef IRM_PUB_RESEND_MBUF_N
#define IRM_PUB_RESEND_MBUF_N (16)
#endif

enum {
    IRM_PUB_INVITATION_MBUF_ID = 0,
    IRM_PUB_ASK_MBUF_ID,
    IRM_PUB_LOST_DATA_MBUF_ID,
    IRM_PUB_BREAKPOINT_MBUF_ID,
    IRM_PUB_CLOSE_MBUF_ID,
    IRM_PUB_RESERVE_MBUF_MAX
};

struct irm_sub_desc {
    uint32_t            ip_be32;
    uint32_t            online;
    int                 alive;
    int                 slot;
    uint8_t             idle_times;
};

struct irm_sub_info {
    uint32_t            size;
    uint8_t             alive_count;
    uint8_t             alives[IRM_SUB_MAX];
    struct irm_sub_desc desc[IRM_SUB_MAX];
};

struct irm_pub_context {
    uint32_t                  token;
    uint32_t                  invitation_seq;
    uint32_t                  heartbeat_seq;
    uint32_t                  breakpoint_seq;
    uint8_t                   self_id;
    volatile int              quit;
    struct irm_buffer*        tx_buffer;
    struct irm_netio*         netio;
    struct irm_netio_ops      netops;
    struct irm_sub_info*      subs;
    struct irm_mbuf*          reserved_mbufs[IRM_PUB_RESERVE_MBUF_MAX];
    struct irm_mbuf*          resend_mbufs[IRM_PUB_RESEND_MBUF_N];
    struct irm_storage        storage;
    pthread_t                 event_loop_thread_id; 
    struct irm_config         cfg;
    void*                     mpool;
};

#define  IRM_PUB_CTX(_c) ((struct irm_pub_context *)(_c))
#define IRM_PUB_ALIVE_SUB_COUNT(_c) ((_c)->subs->alive_count)

struct irm_pub_context* irm_pub_context_create(void);
int irm_pub_context_init(struct irm_pub_context* ctx);
void irm_pub_context_release(struct irm_pub_context* ctx);
void irm_pub_context_close(struct irm_pub_context* ctx);
IRM_C_END
#endif
