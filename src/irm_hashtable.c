/* huangying */
#include "irm_hashtable.h"

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

#include "irm_memory_pool.h"
#include "irm_utils.h"
#include "irm_log.h"

#define IRM_HASHTABLE_TOTAL_SIZE(_n) \
    ({sizeof(struct irm_hashtable) + (_n) * sizeof(struct irm_queue);})

#define IRM_HASHTABLE_INIT(_ht, _bz, _tz) \
do {\
    (_ht)->size = (_bz);\
    (_ht)->count = 0;\
    (_ht)->mask = (_bz) - 1;\
    (_ht)->total_size = (_tz);\
    (_ht)->buckets = (struct irm_queue *)&(_ht)[1];\
} while (0)

struct irm_hashtable* irm_hashtable_create(void* mpool, uint32_t size)
{
    struct irm_hashtable*   ht = NULL;
    size_t                  total_size;
    uint32_t                bucket_size;
    uint32_t                count;
    uint32_t                i;

    bucket_size = irm_power2_align32(size);
    total_size = IRM_HASHTABLE_TOTAL_SIZE(bucket_size);
  
    IRM_DBG("total_size %lu, bucket_size %u", total_size, bucket_size); 

    ht = (struct irm_hashtable *)irm_memory_alloc_align(mpool, total_size,
        IRM_CACHELINE);
    if (!ht) {
        IRM_ERR("hashtable create failed, alloc error %d", irm_errno);
        return NULL;
    }

    count = (total_size - sizeof(struct irm_hashtable))
        / sizeof(struct irm_queue);
    bucket_size = irm_prevpow2_align32(count);

    IRM_DBG("bucket_size %u, count %u", bucket_size, count);

    IRM_HASHTABLE_INIT(ht, bucket_size, total_size);
    for (i = 0; i < bucket_size; ++i) {
        IRM_QUEUE_INIT(&ht->buckets[i]);
    }
    irm_errno = 0;

    return ht;
}
