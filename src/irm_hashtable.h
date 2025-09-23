/* huangying */

#ifndef IRM_HASHTABLE_H
#define IRM_HASHTABLE_H

#include <stdint.h>

#include "irm_common.h"
#include "irm_queue.h"
#include "irm_error.h"

IRM_C_BEGIN

#define IRM_HASHTABLE_LN_INIT(_ln) \
do {  \
    (_ln)->key = 0; \
    (_ln)->q.prev = NULL;  \
    (_ln)->q.next = NULL;  \
} while (0)

#define IRM_HASHTABLE_LN(_i) ((struct irm_hashtable_ln *)(_i))

struct irm_hashtable_ln;
struct irm_hashtable_ln {
  struct irm_queue     q;
  uint32_t             key;
};

struct irm_hashtable {
  uint32_t                    size;
  uint32_t                    count;
  uint32_t                    mask;
  size_t		              total_size;
  struct irm_queue*           buckets;    
} IRM_ATTR_CACHELINE_ALIGN;

struct irm_hashtable* irm_hashtable_create(void* mpool,
    uint32_t size);

static IRM_ALWAYS_INLINE void
irm_hashtable_insert(struct irm_hashtable* ht, struct irm_hashtable_ln* ln)
{   
    uint32_t  slot;

    slot = ln->key & ht->mask;
    IRM_QUEUE_INSERT_HEAD(&ht->buckets[slot], &ln->q);
}

static IRM_ALWAYS_INLINE struct irm_hashtable_ln*
irm_hashtable_lookup(struct irm_hashtable* ht, uint32_t key)
{
    struct irm_queue*        iter;
    uint32_t                 slot;

    slot = key & ht->mask;
    IRM_QUEUE_FOREACH(iter, &ht->buckets[slot]) {
        if (key == IRM_HASHTABLE_LN(iter)->key) {
            return IRM_HASHTABLE_LN(iter);
        }
    }
    return NULL;
}

static IRM_ALWAYS_INLINE int
irm_hashtable_remove(struct irm_hashtable* ht, struct irm_hashtable_ln* ln)
{ 
    uint32_t             slot;
    struct irm_queue*    iter;
  
    slot = ln->key & ht->mask;

    IRM_QUEUE_FOREACH(iter, &ht->buckets[slot]) {
        if (ln->key == IRM_HASHTABLE_LN(iter)->key) {
            IRM_QUEUE_REMOVE(iter);
            return IRM_OK;
        }
    }

    return -IRM_HASHTABLE_REMOVE_ERROR;
}

static IRM_ALWAYS_INLINE struct irm_hashtable_ln* 
irm_hashtable_del(struct irm_hashtable* ht, uint32_t key)
{
    uint32_t            slot;
    struct irm_queue*   iter;

    slot = key & ht->mask;

    IRM_QUEUE_FOREACH(iter, &ht->buckets[slot]) {
        if (key == IRM_HASHTABLE_LN(iter)->key) {
            IRM_QUEUE_REMOVE(iter);
            return IRM_HASHTABLE_LN(iter);
        }
    }
    return NULL;
}

IRM_C_END


#endif
