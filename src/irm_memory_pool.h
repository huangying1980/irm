/* huangying */
#ifndef IRM_MEMORY_POOL_H
#define IRM_MEMORY_POOL_H

#include <stdint.h>
#include <stddef.h>

#include "irm_decls.h"

IRM_C_BEGIN


void* irm_memory_pool_create(size_t size);
void  irm_memory_pool_release(void* mpool);
void* irm_memory_alloc(void* mpool, size_t size);
void* irm_memory_calloc(void* mpool, size_t size);
void* irm_memory_alloc_align(void* mpool, size_t size,
    size_t align);
void* irm_memory_calloc_align(void* mpool, size_t size,
    size_t align);

IRM_C_END

#endif
