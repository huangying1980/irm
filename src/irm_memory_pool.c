/* huangying */
#include "irm_memory_pool.h"

#include "mpool.h"

IRM_C_BEGIN

void* irm_memory_pool_create(size_t size)
{
    return mpool_create(size);
}

void irm_memory_pool_release(void* mpool)
{
    mpool_release(mpool);
}

void* irm_memory_alloc(void* mpool, size_t size)
{
    return mpool_alloc(mpool, size);
}

void* irm_memory_calloc(void* mpool, size_t size)
{
    return mpool_calloc(mpool, size);
}

void* irm_memory_alloc_align(void* mpool, size_t size, size_t align)
{
    return mpool_alloc_align(mpool, size, align);
}

void* irm_memory_calloc_align(void* mpool, size_t size,
    size_t align)
{
    return mpool_calloc_align(mpool, size, align);
}

void irm_memory_free(void* mpool, void* ptr)
{
    return mpool_free(mpool, ptr);
}

IRM_C_END

