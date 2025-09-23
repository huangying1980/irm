/* huangying */
#ifndef IRM_MBUF_POOL_H
#define IRM_MBUF_POOL_H

#include <stddef.h>

#include "irm_decls.h"
#include "irm_common.h"
#include "irm_mbuf.h"
#include "irm_ring.h"
#include "irm_utils.h"
#include "irm_log.h"

IRM_C_BEGIN

#define IRM_POOL_MGR_SINGLE_CONS IRM_RING_SC_DEQ
#define IRM_POOL_MGR_SINGLE_PROD IRM_RING_SP_ENQ
#define IRM_MBUF_POOL_COUNT(_p) ((_p)->count)
#define IRM_MBUF_PKT(_pool) (((struct irm_mbuf_pool *)(_pool))->mbufs)
#define IRM_MBUF_PKT_SIZE(_pool) (((struct irm_mbuf_pool *)_pool)->mbufs_size)

struct irm_mbuf_pool {
    uint32_t           size;
    uint32_t           elt_size;
    uint32_t           mask;
    uint32_t           count;
    uint32_t           ring_size;
    uint32_t           last;
    struct irm_mbuf**  ring;
    struct irm_mbuf*   mbufs;
    uint32_t           mbufs_size; 
} IRM_ATTR_CACHELINE_ALIGN;

#define IRM_POOL_MGR_INIT(_pm, _pool, _c)\
do {\
    struct irm_mbuf_pool* p = (struct irm_mbuf_pool *)(_pool);\
    (_pm)->ring = &p->ring[p->last];\
    (_pm)->count = (_c);\
    irm_pool_mgr_init((_pm), p);\
} while(0)

#define IRM_POOL_MGR_SET_FLAGS(_pm, _flags) \
    IRM_RING_SET_FLAGS(&(_pm)->ring_mgr, _flags)

struct irm_mbuf_pool_mgr {
    struct irm_ring           ring_mgr;
    struct irm_mbuf**         ring;
    struct irm_mbuf_pool*     pool;
    uint32_t                  count;
};

int irm_pool_mgr_init(struct irm_mbuf_pool_mgr* pm,
    struct irm_mbuf_pool* pool);


IRM_HOT_CALL static IRM_ALWAYS_INLINE struct irm_mbuf*
irm_mbuf_get(struct irm_mbuf_pool_mgr* mgr)
{
    void*            mbuf = NULL;
    int              ret ;

    ret = irm_ring_dequeue(&mgr->ring_mgr, &mbuf);
    if (ret != IRM_OK) {
        return NULL;    
    }

    return (struct irm_mbuf *)mbuf;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_mbuf_put(struct irm_mbuf_pool_mgr* mgr, struct irm_mbuf* mbuf)
{
    return irm_ring_enqueue(&mgr->ring_mgr, mbuf);
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_mbuf_get_batch(struct irm_mbuf_pool_mgr* mgr, struct irm_mbuf* mbufs[],
    const uint32_t count)
{
    return irm_ring_dequeue_bulk(&mgr->ring_mgr, (void **)mbufs, count, NULL);
}


IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_mbuf_put_batch(struct irm_mbuf_pool_mgr* mgr, struct irm_mbuf* mbufs[],
    const uint32_t count)
{
    return irm_ring_enqueue_bulk(&mgr->ring_mgr, (void **)mbufs, count, NULL);
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_mbuf_available(struct irm_mbuf_pool_mgr* mgr)
{
    return irm_ring_count(&mgr->ring_mgr);
}

struct irm_mbuf_pool* irm_mbuf_pool_create(void* mpool,
    uint32_t count, uint32_t elt_size, uint32_t nrank,
    uint32_t nchannel);

IRM_C_END

#endif
