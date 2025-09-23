/* huangying */
#include "irm_sobj_pool.h"

#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#include "irm_memory_pool.h"
#include "irm_utils.h"
#include "irm_error.h"
#include "irm_log.h"

#define IRM_SOBJ_POOL_ALIGN      IRM_CACHELINE
#define IRM_SOBJ_POOL_ALIGN_MASK (IRM_SOBJ_POOL_ALIGN - 1)

#ifndef IRM_SOBJ_POOL_SIZE_MAX
#define IRM_SOBJ_POOL_SIZE_MAX  (1UL << 31)
#endif

#define IRM_SOBJ_POOL(_ptr) ((struct irm_sobj_pool *)(_ptr))

#define IRM_SOBJ_POOL_INIT(_pool, _tz, _sz, _n) \
do {\
    _pool->total_size = (_tz);\
    _pool->count = (_n);\
    _pool->sobj_size = (_sz);\
    _pool->last = (struct irm_sobj *)&_pool[1];\
} while (0)

IRM_C_BEGIN
static uint32_t irm_sobj_gcd(uint32_t a, uint32_t b);
static uint32_t irm_sobj_size_align(uint32_t size, uint32_t rank,
    uint32_t channel);
IRM_C_END

struct irm_sobj_pool* irm_sobj_pool_create(void* mpool,
    const uint32_t elt_size, uint32_t count, uint32_t rank, uint32_t channel)
{
    struct irm_sobj_pool* pool = NULL;
    struct irm_sobj*      obj;
    size_t                total_size;
    uint32_t              sobj_size;
    uint32_t              i;

    sobj_size = sizeof(struct irm_sobj) + elt_size;
    sobj_size = irm_sobj_size_align(sobj_size, rank, channel);
    total_size = sizeof(struct irm_sobj_pool) + count * sobj_size;
    if (total_size > IRM_SOBJ_POOL_SIZE_MAX) {
        total_size = IRM_SOBJ_POOL_SIZE_MAX;
    }
    total_size = IRM_PAGE_ALIGN(total_size);

    IRM_DBG("total_size %lu, count %u, sobj_size %u", total_size,
        count, sobj_size);
    pool = (struct irm_sobj_pool *)irm_memory_alloc_align(mpool, total_size,
        IRM_CACHELINE);
    if (!pool) {
        IRM_ERR("sobj pool create failed, alloc error %d", irm_errno);
        return NULL;
    }

    count = (total_size - sizeof(struct irm_sobj_pool)) / sobj_size;

    IRM_DBG("total_size %lu, count %u, sobj_size %u", total_size,
        count, sobj_size);

    IRM_SOBJ_POOL_INIT(pool, total_size, sobj_size, count);
    for (i = 0; i < count; ++i) {
        obj = (struct irm_sobj *)((uint8_t *)pool->last + i * sobj_size);     
        obj->size = elt_size;
        obj->data_size = 0;
        IRM_HASHTABLE_LN_INIT(&obj->ln);
        IRM_QUEUE_INIT(&obj->lru);
    }

    irm_errno = 0;

    return pool;
}

#ifdef IRM_ARCH_NONE_X86
static uint32_t irm_sobj_size_align(uint32_t size, uint32_t IRM_UNUSED(rank),
    uint32_t IRM_UNUSED(channel))
{
    return IRM_CACHELINE_ALIGN(size);
}
#else
static uint32_t irm_sobj_gcd(uint32_t a, uint32_t b)
{
    uint32_t c;

    if (0 == a) {
        return b;
    }
    if (0 == b) {
        return a;
    }

    if (a < b) {
        c = a;
        a = b;
        b = c;
    }

    while (b != 0) {
        c = a % b;
        a = b;
        b = c;
    }

    return a;
}

static uint32_t irm_sobj_size_align(uint32_t size, uint32_t rank,
    uint32_t channel)
{
    uint32_t new_size;
    if (!rank || !channel) {
        return IRM_CACHELINE_ALIGN(size);
    }
    new_size = (size + IRM_SOBJ_POOL_ALIGN_MASK) / IRM_SOBJ_POOL_ALIGN;
    while (irm_sobj_gcd(new_size, rank * channel) != 1) {
        new_size++;
    }
    return new_size * IRM_SOBJ_POOL_ALIGN;
}
#endif
