/* huangying */
#include "irm_memory_pool.h"

#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "irm_common.h"
#include "irm_queue.h"
#include "irm_utils.h"
#include "irm_error.h"
#include "irm_log.h"

IRM_C_BEGIN

#ifndef IRM_MEMORY_SLICE_SIZE_MIN
#define IRM_MEMORY_SLICE_SIZE_MIN   (1UL << 29)
#endif

#define IRM_MEMORY_SLICE_INIT(_sl, _sz) \
do {\
    (_sl)->free_size = (_sz) - sizeof(struct irm_memory_slice);\
    (_sl)->total_size = (_sz);\
    (_sl)->pos = (uint8_t *)&_sl[1];\
    IRM_QUEUE_INIT(&(_sl)->ln);\
} while (0)

#define IRM_MEMORY_SLICE_UPDATE(_sl, _sz)\
do {\
    (_sl)->free_size -= (_sz); \
    (_sl)->pos += (_sz);\
} while (0)

struct irm_memory_pool {
    struct irm_queue free_list;
    struct irm_queue full_list;    
};

struct irm_memory_slice {
    struct irm_queue        ln;
    size_t                  free_size;
    size_t                  total_size;
    uint8_t*                pos;
} IRM_ATTR__CACHELINE_ALIGN;

static struct irm_memory_slice* irm_memory_slice_create(size_t size);
static void irm_memory_slice_release(struct irm_memory_slice* slice);

void* irm_memory_pool_create(size_t size)
{
    struct irm_memory_pool      *mpool;
    struct irm_memory_slice     *slice;

    if (size < IRM_MEMORY_SLICE_SIZE_MIN) {
        size = IRM_MEMORY_SLICE_SIZE_MIN;
    }

    slice = irm_memory_slice_create(size);
    if (!slice) {
        IRM_ERR("%s failed, irm_memory_slice_create error", __func__);
        return NULL;
    }

    mpool = malloc(sizeof(struct irm_memory_pool));
    if (!mpool) {
        IRM_ERR("%s failed, malloc error", __func__);
        irm_memory_slice_release(slice);
        return NULL;
    }
    IRM_QUEUE_INIT(&mpool->free_list);
    IRM_QUEUE_INIT(&mpool->full_list);
    IRM_QUEUE_INSERT_HEAD(&mpool->free_list, &slice->ln);

    return mpool;
}

void irm_memory_pool_release(void* mpool)
{
    struct irm_memory_slice* slice;
    struct irm_memory_pool*  pool = (struct irm_memory_pool *)mpool;
    struct irm_queue*        iter;
    struct irm_queue*        next;

    if (!mpool) {
        return;
    }

    IRM_QUEUE_FOREACH_SAFE(iter, &pool->full_list, next) {
        slice = IRM_QUEUE_DATA(iter, struct irm_memory_slice, ln);    
        IRM_QUEUE_REMOVE(&slice->ln);
        irm_memory_slice_release(slice);
    }

    IRM_QUEUE_FOREACH_SAFE(iter, &pool->free_list, next) {
        slice = IRM_QUEUE_DATA(iter, struct irm_memory_slice, ln);    
        IRM_QUEUE_REMOVE(&slice->ln);
        irm_memory_slice_release(slice);
    }

    free(pool);
}

static struct irm_memory_slice* irm_memory_slice_create(size_t size)
{
    struct irm_memory_slice* slice;
    size_t                   total_size;
    size_t                   tmp_size;
    int                      fd = -1;
    int                      flags = MAP_PRIVATE | MAP_POPULATE;

    if (size < IRM_MEMORY_SLICE_SIZE_MIN) {
        size = IRM_MEMORY_SLICE_SIZE_MIN;
    }

    total_size = IRM_PAGE_ALIGN(size);
    tmp_size = total_size;
    fd = irm_prepare_hugepage(&total_size); 
    if (fd < 0) {
        goto IRM_MEMORY_SLICE_DO_NORMAL_MMAP;
    }
    slice = (struct irm_memory_slice *)mmap(NULL, total_size,
        PROT_READ | PROT_WRITE, flags, fd, 0); 
    if (slice != (struct irm_memory_slice *)MAP_FAILED) {
        goto IRM_MEMORY_SLICE_OUT;
    }

IRM_MEMORY_SLICE_DO_NORMAL_MMAP:
    IRM_WARN("mmap for hugepage failed, error %s", strerror(errno));
    IRM_WARN("mmap 4KB page");
    total_size = tmp_size;
    flags |= MAP_ANONYMOUS;
    slice = mmap(NULL, total_size, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (slice == (struct irm_memory_slice *)MAP_FAILED) {
        IRM_ERR("memory slice create failed, mmap error %s, total_size %lu",
            strerror(errno), total_size);    
        irm_errno = -IRM_MEMORY_SLICE_CREATE_MMAP;
        slice = NULL;
        goto IRM_MEMORY_SLICE_ERR;
    }

IRM_MEMORY_SLICE_OUT:
    IRM_MEMORY_SLICE_INIT(slice, total_size);
    IRM_MEM_LOCK(slice, total_size);
    
IRM_MEMORY_SLICE_ERR:
    if (fd > 0) {
        close(fd);
    }

    return slice;
}

static void irm_memory_slice_release(struct irm_memory_slice* slice)
{
    size_t size;

    if (!slice) {
        return;
    }

    size = slice->total_size;
    IRM_MEM_UNLOCK(slice, size);
    munmap(slice, size);
}

void* irm_memory_alloc(void* mpool, size_t size)
{
    struct irm_memory_slice* slice;
    struct irm_memory_pool*  pool = (struct irm_memory_pool *)mpool;
    struct irm_queue*        iter;
    void*                    addr = NULL;                  

    IRM_QUEUE_FOREACH(iter, &pool->free_list) {
        slice = IRM_QUEUE_DATA(iter, struct irm_memory_slice, ln);
        if (slice->free_size >= size) {
            addr = slice->pos;
            IRM_MEMORY_SLICE_UPDATE(slice, size);
            if (!slice->free_size) {
                IRM_QUEUE_REMOVE(&slice->ln);
                IRM_QUEUE_INSERT_HEAD(&pool->full_list, &slice->ln);
            }
            return addr;
        }
    }

    IRM_WARN("alloc memory in slow path");
    slice = irm_memory_slice_create(size);
    if (!slice) {
        IRM_ERR("%s failed, irm_memory_slice_create error", __func__);
        return NULL;
    }
    addr = slice->pos;
    IRM_MEMORY_SLICE_UPDATE(slice, size);
    if (!slice->free_size) {
        IRM_QUEUE_INSERT_HEAD(&pool->full_list, &slice->ln);
    } else {
        IRM_QUEUE_INSERT_HEAD(&pool->free_list, &slice->ln);
    }

    return addr;
}

void* irm_memory_calloc(void* mpool, size_t size)
{
    void* addr = irm_memory_alloc(mpool, size);
    if (!addr) {
        return NULL;
    }
    memset(addr, 0, size);
    return addr;
}

void* irm_memory_alloc_align(void* mpool, size_t size, size_t align)
{
    struct irm_memory_slice*     slice;
    struct irm_memory_pool*      pool = (struct irm_memory_pool *)mpool;
    struct irm_queue*            iter;
    size_t                       aligned_size;
    void*                        addr;

    IRM_QUEUE_FOREACH(iter, &pool->free_list) {
        slice = IRM_QUEUE_DATA(iter, struct irm_memory_slice, ln);
        addr = (void *)IRM_SIZE_ALIGN(IRM_OFFSET(slice->pos), align);
        aligned_size = (uint8_t *)addr - slice->pos + size;
        if (slice->free_size >= aligned_size) {
            IRM_MEMORY_SLICE_UPDATE(slice, aligned_size);
            if (!slice->free_size) {
                IRM_QUEUE_REMOVE(&slice->ln);
                IRM_QUEUE_INSERT_HEAD(&pool->full_list, &slice->ln);
            }
            return addr;
        }
    }

    IRM_WARN("aligned alloc memory in slow path");
    aligned_size = IRM_SIZE_ALIGN(sizeof(struct irm_memory_slice), align) + size;
    slice = irm_memory_slice_create(aligned_size);
    if (!slice) {
        IRM_ERR("%s failed, hugepage_slice_create error, required size %lu, "
            "act size %lu", __func__, size, aligned_size);
        return NULL;
    }

    addr = (void *)IRM_SIZE_ALIGN(IRM_OFFSET(slice->pos), align);
    IRM_MEMORY_SLICE_UPDATE(slice, aligned_size);
    if (!slice->free_size) {
        IRM_QUEUE_INSERT_HEAD(&pool->full_list, &slice->ln);
    } else {
        IRM_QUEUE_INSERT_HEAD(&pool->free_list, &slice->ln);
    }

    return addr;
    
}

void* irm_memory_calloc_align(void* mpool, size_t size,
    size_t align)
{
    void* addr = irm_memory_alloc_align(mpool, size, align);
    if (!addr) {
        return 0;
    }
    memset(addr, 0, size);
    return addr;
}

IRM_C_END

