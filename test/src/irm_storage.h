/* huangying */
#ifndef IRM_STORAGE_H
#define IRM_STORAGE_H

#include "irm_hashtable.h"
#include "irm_sobj_pool.h"
#include "irm_taskqueue.h"
#include "irm_config.h"
#include "irm_netio.h"
#include "irm_mbuf.h"

IRM_C_BEGIN

#define IRM_STORAGE_LOCK_ON (1u)
#define IRM_STORAGE_LOCK_OFF (0)

struct irm_storage {
    struct irm_hashtable*            ht;    
    struct irm_sobj_pool*            pool;
    struct irm_queue                 lru;
    struct irm_taskqueue*            taskqueue;
    struct irm_config*               cfg;
    struct irm_netio*                netio;
    uint32_t                         payload_offset;
    pthread_t                        tid;
    volatile int                     quit;
    int                              inited;
    volatile uint32_t                lock IRM_ATTR_CACHELINE_ALIGN;
};

#define IRM_STORAGE_LOCK(_l) \
    while (!IRM_CAS32(&(_l), IRM_STORAGE_LOCK_OFF, IRM_STORAGE_LOCK_ON))

#define IRM_STORAGE_UNLOCK(_l) ((_l) = IRM_STORAGE_LOCK_OFF)

static IRM_ALWAYS_INLINE int
irm_storage_commit(struct irm_storage* st, struct irm_mbuf* mbufs[], uint32_t n)
{
    while (irm_taskqueue_push_batch(st->taskqueue, mbufs, n) != n);   
    return n;
}

int irm_storage_init(void* mpool, struct irm_storage* storage,
    struct irm_netio* netio, uint32_t payload_offset,
    struct irm_config* cfg);
void irm_storage_deinit(struct irm_storage* storage);

static IRM_ALWAYS_INLINE struct irm_sobj*
irm_storage_get(struct irm_storage* storage, uint32_t key)
{
    struct irm_hashtable_ln* ln;
    struct irm_sobj*         sobj = NULL;

    IRM_STORAGE_LOCK(storage->lock);
    ln = irm_hashtable_del(storage->ht, key);
    if (!ln) {
        IRM_DBG("key %u not found in storage", key);
        goto IRM_STORAGE_GET_OUT;
    }
    sobj = IRM_CONTAINER_OF(ln, struct irm_sobj, ln);
    IRM_QUEUE_REMOVE(&sobj->lru);

IRM_STORAGE_GET_OUT:
    IRM_STORAGE_UNLOCK(storage->lock);
    return sobj;
}

static IRM_ALWAYS_INLINE int
irm_storage_lookup(struct irm_storage* storage, uint32_t key)
{
    struct irm_hashtable_ln* ln = NULL;

    IRM_STORAGE_LOCK(storage->lock);
    ln = irm_hashtable_lookup(storage->ht, key);
#if defined(IRM_DEBUG) || defined(IRM_DEBUG_VERBOSE)
    if (!ln) {
        IRM_DBG("lookup key %u not found in storage", key);
    }
#endif
    IRM_STORAGE_UNLOCK(storage->lock);
    return !!ln;
}

static IRM_ALWAYS_INLINE void 
irm_storage_put(struct irm_storage* storage, struct irm_sobj* sobj)
{
    IRM_STORAGE_LOCK(storage->lock);
    irm_hashtable_insert(storage->ht, &sobj->ln);
    IRM_QUEUE_INSERT_TAIL(&storage->lru, &sobj->lru);
    IRM_STORAGE_UNLOCK(storage->lock);
}

IRM_C_END
#endif
