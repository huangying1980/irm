/* huangying */

#ifndef IRM_SOBJ_POOL_H
#define IRM_SOBJ_POOL_H
#include <stdint.h>

#include "irm_common.h"
#include "irm_sobj.h"

IRM_C_BEGIN

struct irm_sobj_pool {
    uint32_t         total_size;
    uint32_t         count;
    uint32_t         sobj_size;
    struct irm_sobj* last;
} IRM_ATTR_CACHELINE_ALIGN;

struct irm_sobj_pool* irm_sobj_pool_create(void* mpool,
    uint32_t elt_size, uint32_t count, uint32_t rank, uint32_t channel);

static IRM_ALWAYS_INLINE struct irm_sobj*
irm_sobj_get(struct irm_sobj_pool* pool)
{
    struct irm_sobj* obj;
    
    if (IRM_UNLIKELY(!pool->count)) {
        return NULL;
    }
    obj = pool->last;
    pool->last = (struct irm_sobj *)((uint8_t *)pool->last + pool->sobj_size);
    --pool->count;
    return obj;
}

IRM_C_END

#endif

