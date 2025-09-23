/* huangying */
#include "irm_mbuf_pool.h"

#include <sys/statfs.h>
#include <sys/mman.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "irm_memory_pool.h"
#include "irm_mbuf.h"
#include "irm_common.h"
#include "irm_utils.h"
#include "irm_error.h"
#include "irm_log.h"

#include "irm_ring.h"

IRM_C_BEGIN

#define IRM_MBUF_POOL_ALIGN IRM_CACHELINE
#define IRM_MBUF_POOL_ALIGN_MASK (IRM_MBUF_POOL_ALIGN - 1)

#define IRM_MBUF_POOL(_ptr) ((struct irm_mbuf_pool* )(_ptr))

#define IRM_MBUF_POOL_INIT(_ptr, _tz, _rz, _pz, _ez) \
do {\
    struct irm_mbuf_pool* _pool = IRM_MBUF_POOL(_ptr);\
    _pool->last = 0; \
    _pool->size = (_tz); \
    _pool->elt_size = (_ez); \
    _pool->ring_size = (_rz); \
    _pool->mbufs_size = (_pz);\
    _pool->ring = (struct irm_mbuf** )&_pool[1];\
    _pool->mbufs = (struct irm_mbuf* )((char *)_pool + (_rz));\
} while (0)

static uint32_t irm_gcd(uint32_t a, uint32_t b);
static uint32_t irm_mbuf_size_align(uint32_t size, uint32_t rank,
    uint32_t channel);
static void irm_mbuf_pool_list_init(struct irm_mbuf_pool* pool, uint32_t count,
    uint32_t mbuf_size);

struct irm_mbuf_pool* irm_mbuf_pool_create(void* mpool, uint32_t total_count,
    uint32_t elt_size, uint32_t rank, uint32_t channel)
{
    void*                    addr = NULL;
    size_t                   total_size;
    uint32_t                 mbuf_size;
    uint32_t                 ring_size;
    uint32_t                 pkts_size;

    if (!elt_size) {
        mbuf_size = IRM_MBUF_ELT_SIZE;
    } else {
        mbuf_size = sizeof(struct irm_mbuf) + elt_size;
        mbuf_size = irm_mbuf_size_align(mbuf_size, rank, channel);
    }
    elt_size = mbuf_size - sizeof(struct irm_mbuf);

    ring_size = IRM_CACHELINE_ALIGN(total_count * sizeof(struct irm_mbuf *));
    ring_size = IRM_PAGE_ALIGN(ring_size + sizeof(struct irm_mbuf_pool));
    pkts_size =  IRM_PAGE_ALIGN(total_count * mbuf_size);
    total_size = ring_size + pkts_size;

    IRM_DBG("total_size %lu, total_count %u, pkts_size %u, ring_size %u, "
        "mbuf_size %u, elt_size %u, sizeof(struct irm_buf) %lu", total_size,
        total_count, pkts_size, ring_size, mbuf_size, elt_size,
        sizeof(struct irm_mbuf));

    addr = irm_memory_alloc_align(mpool, total_size, IRM_PAGE_SIZE);
    if (!addr) {
        IRM_ERR("irm_mbuf_pool_create failed, alloc error %d", irm_errno);
        return NULL;
    }

    IRM_DBG("total_count %u", total_count);
    IRM_MBUF_POOL_INIT(addr, total_size, ring_size, pkts_size, elt_size);
    irm_mbuf_pool_list_init(IRM_MBUF_POOL(addr), total_count, mbuf_size);
    irm_errno = 0;

    return IRM_MBUF_POOL(addr);
}

static void irm_mbuf_pool_list_init(struct irm_mbuf_pool* pool, uint32_t count,
    uint32_t mbuf_size)
{
    uint32_t          i;
    struct irm_mbuf*  mbuf;
    for (i = 0; i < count; ++i) {
        mbuf = IRM_MBUF((char *)pool->mbufs + mbuf_size * i);
        pool->ring[i] = mbuf;
        mbuf->id = i;
        mbuf->status = IRM_MBUF_STATUS_IDLE;
        mbuf->size = pool->elt_size;
        mbuf->payload = pool->elt_size;
#ifdef IRM_ENABLE_EFVI
        mbuf->ef_addr = 0;
#endif
        IRM_LN_INIT(&mbuf->cache_ln);
        IRM_LN_INIT(&mbuf->sender_ln);
        IRM_DBG("mbufs %p, mbuf[%u] %p, id %u", pool->mbufs, i, mbuf, mbuf->id);
    }
}

#ifdef IRM_ARCH_NONE_X86
static uint32_t irm_mbuf_size_align(uint32_t size, uint32_t IRM_UNUSED(rank),
    uint32_t IRM_UNUSED(channel))
{
    return IRM_CACHELINE_ALIGN(size);
}
#else
static uint32_t irm_gcd(uint32_t a, uint32_t b)
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

static uint32_t irm_mbuf_size_align(uint32_t size, uint32_t rank,
    uint32_t channel)
{
    uint32_t new_size;
    if (!rank || !channel) {
        return size;
    }
    new_size = (size + IRM_MBUF_POOL_ALIGN_MASK) / IRM_MBUF_POOL_ALIGN;
    while (irm_gcd(new_size, rank * channel) != 1) {
        new_size++;
    }
    return new_size * IRM_MBUF_POOL_ALIGN;
}
#endif

int irm_pool_mgr_init(struct irm_mbuf_pool_mgr* pm,
    struct irm_mbuf_pool* pool)
{
    int ret;
    ret = irm_ring_init(&pm->ring_mgr, pm->count, 0);
    if (ret != IRM_OK) {
        return ret;
    }
    
    irm_ring_set_start(&pm->ring_mgr, (void **)pm->ring);
    irm_ring_set_prod(&pm->ring_mgr, pm->count);

    return IRM_OK;
}

IRM_C_END

