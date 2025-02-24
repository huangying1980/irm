/* huangying */
#include "irm_memory_pool.h"

#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "irm_common.h"
#include "irm_utils.h"
#include "irm_error.h"
#include "irm_log.h"

IRM_C_BEGIN

#ifndef IRM_MEMORY_SLICE_SIZE_MIN
#define IRM_MEMORY_SLICE_SIZE_MIN   (1UL << 29)
#endif

#define IRM_MEMORY_POOL(_mp) ((struct irm_memory_pool *)(_mp))
#define IRM_MEMORY_SLICE(_ms) ((struct irm_memory_slice *)(_ms))
#define IRM_MEMORY_POOL_SLICE(_mp) IRM_MEMORY_SLICE(&IRM_MEMORY_POOL(_mp)[1])
#define IRM_MEMORY_SLICE_RESET(_sl)\
do {\
    struct irm_memory_slice *_slice = IRM_MEMORY_SLICE(_sl);\
    _slice->start = NULL;\
    _slice->end = NULL;\
    _slice->last = NULL;\
    _slice->next = NULL;\
    _slice->external = IRM_FALSE;\
    _slice->size = 0;\
} while (0)

#define IRM_MEMORY_POOL_INIT(_mp, _sz, _n)  \
do {\
    struct irm_memory_pool *_pool = IRM_MEMORY_POOL(_mp);\
    _pool->size = (_sz);\
    _pool->count = (_n);\
    _pool->curr = IRM_MEMORY_POOL_SLICE(_mp);\
    _pool->tail = &_pool->curr[(_n) - 1];\
} while (0)

#define IRM_MEMORY_POOL_CURRENT_SLICE(_mp) \
    IRM_MEMORY_SLICE(IRM_MEMORY_POOL(_mp)->curr)

#define IRM_MEMORY_SLICE_INIT(_sc, _start, _sz, _ext) \
do {\
    struct irm_memory_slice *_slice = IRM_MEMORY_SLICE(_sc);\
    _slice->start = (_start);\
    _slice->end = (uint8_t *)_slice->start + (_sz);\
    _slice->last = _slice->start;\
    _slice->size = (size_t)(_sz);\
    _slice->external = (size_t)(_ext);\
} while (0)

#define IRM_MEMORY_POOL_SLICE_FOREACH(_mp, _iter)\
    for ((_iter) = IRM_MEMORY_POOL_SLICE(_mp); (_iter); (_iter) = (_iter)->next)

#define IRM_MEMORY_POOL_SLICE_FOREACH_FROM(_iter)\
    for (; (_iter); (_iter) = (_iter)->next)

#define IRM_MEMORY_SLICE_END(_sl) (IRM_MEMORY_SLICE(_sl)->end)
#define IRM_MEMORY_SLICE_LAST(_sl) (IRM_MEMORY_SLICE(_sl)->last)
#define IRM_MEMORY_SLICE_LAST_UPDATE(_sl, _sz) \
do {\
    uint8_t *p = (uint8_t *)IRM_MEMORY_SLICE_LAST(_sl);\
    p += (_sz);\
    IRM_MEMORY_SLICE_LAST(_sl) = p;\
} while (0)

#define IRM_MEMORY_SLICE_FREE_SIZE(_sl) \
    (IRM_OFFSET(IRM_MEMORY_SLICE_END(_sl)) - IRM_OFFSET(IRM_MEMORY_SLICE_LAST(_sl)))

#define IRM_MEMORY_SLICE_LAST(_sl) (IRM_MEMORY_SLICE(_sl)->last)

#define IRM_MEMORY_SLICE_EMPTY(_sl) (!IRM_MEMORY_SLICE(_sl)->size)

#define IRM_MEMORY_SLICE_EXTERNAL(_sl) ((_sl)->external)
#define IRM_MEMORY_SLICE_APPEND(_mp, _sl) \
do {\
    IRM_MEMORY_POOL(_mp)->tail->next = (_sl);\
    IRM_MEMORY_POOL(_mp)->tail = (_sl);\
} while (0)

struct irm_memory_slice {
    void                    *start;
    void                    *end;
    void                    *last;
    size_t                   external;
    size_t                   size;
    struct irm_memory_slice *next;
} IRM_ATTR_PTR_ALIGN;

void *irm_memory_pool_create(size_t size)
{
    struct irm_memory_pool      *mpool;
    struct irm_memory_slice     *slice;
    size_t                       total_size; 
    size_t                       tmp_size;
    size_t                       count;
    size_t                       i;
    int                          fd = -1;
    int                          flags = MAP_PRIVATE | MAP_POPULATE;

    if (size < IRM_MEMORY_SLICE_SIZE_MIN) {
        size = IRM_MEMORY_SLICE_SIZE_MIN;
    }
    total_size = IRM_PAGE_ALIGN(sizeof(struct irm_memory_pool))
        + IRM_PAGE_ALIGN(size);
    tmp_size = total_size;
    fd = irm_prepare_hugepage(&total_size); 
    if (fd < 0) {
        goto IRM_MEMORY_POOL_DO_NORMAL_MMAP;
    }
    mpool = (struct irm_memory_pool *)mmap(NULL, total_size,
        PROT_READ | PROT_WRITE, flags, fd, 0); 
    if (mpool != (struct irm_memory_pool *)MAP_FAILED) {
        goto IRM_MEMORY_POOL_OUT;
    }

IRM_MEMORY_POOL_DO_NORMAL_MMAP:
    IRM_WARN("mmap for hugepage failed, error %s", strerror(errno));
    IRM_WARN("mmap 4KB page");
    total_size = IRM_PAGE_ALIGN(tmp_size);
    flags |= MAP_ANONYMOUS;
    mpool = (struct irm_memory_pool *)mmap(NULL, total_size,
        PROT_READ | PROT_WRITE, flags, -1, 0);
    if (mpool == (struct irm_memory_pool *)MAP_FAILED) {
        IRM_ERR("memory pool create failed, mmap error %s, total_size %lu",
        strerror(errno), total_size);    
        irm_errno = -IRM_MEMORY_POOL_CREATE_MMAP;
        mpool = NULL;
        goto IRM_MEMORY_POOL_ERR;
    }

IRM_MEMORY_POOL_OUT:
    memset(mpool, 0, total_size);
    IRM_MEM_LOCK(mpool, total_size);
    count = (IRM_PAGE_SIZE - sizeof(struct irm_memory_pool))
        / sizeof(struct irm_memory_slice);
    IRM_MEMORY_POOL_INIT(mpool, total_size, count);
    slice = IRM_MEMORY_POOL_SLICE(mpool);
    for (i = 0; i < count - 1; ++i) {
        IRM_MEMORY_SLICE_RESET(&slice[i]);
        slice[i].next = &slice[i + 1];
    }
    IRM_MEMORY_SLICE_RESET(&slice[i]);
  
    slice = IRM_MEMORY_POOL_CURRENT_SLICE(mpool);
    IRM_MEMORY_SLICE_INIT(slice, (uint8_t *)mpool + IRM_PAGE_SIZE,
        total_size - IRM_PAGE_SIZE, IRM_TRUE);

IRM_MEMORY_POOL_ERR:
    if (fd > 0) {
        close(fd);
    }

    return mpool;
}

void irm_memory_pool_release(void *mpool)
{
    struct irm_memory_slice *slice;
    void                    *addr;
    uint64_t                 size;

    if (!mpool) {
        return;
    }

    IRM_MEMORY_POOL_SLICE_FOREACH(mpool, slice) {
        if (!slice->size) {
            continue;
        }
        addr = slice->external ? (void *)slice->start : (void *)slice;
        size = (!slice->external) * IRM_PAGE_SIZE + slice->size;
        IRM_MEM_UNLOCK(addr, size);
        munmap(addr, size);
    }
    IRM_MEM_UNLOCK(mpool, mpool->size);
    munmap(mpool, IRM_MEMORY_POOL(mpool)->size);
}

static struct irm_memory_slice *irm_memory_slice_create(
    struct irm_memory_slice *slice, size_t size)
{
    size_t       total_size;
    size_t       tmp_size;
    void        *addr = NULL;
    int          fd = -1;
    int          flags = MAP_PRIVATE | MAP_POPULATE;

    if (size < IRM_MEMORY_SLICE_SIZE_MIN) {
        size = IRM_MEMORY_SLICE_SIZE_MIN;
    }

    total_size = (!slice) * IRM_PAGE_SIZE + IRM_PAGE_ALIGN(size);
    tmp_size = total_size;
    fd = irm_prepare_hugepage(&total_size); 
    if (fd < 0) {
        goto IRM_MEMORY_SLICE_DO_NORMAL_MMAP;
    }
    addr = mmap(NULL, total_size, PROT_READ | PROT_WRITE, flags, fd, 0); 
    if (addr != MAP_FAILED) {
        goto IRM_MEMORY_SLICE_OUT;
    }

IRM_MEMORY_SLICE_DO_NORMAL_MMAP:
    IRM_WARN("mmap for hugepage failed, error %s", strerror(errno));
    IRM_WARN("mmap 4KB page");
    total_size = IRM_PAGE_ALIGN(tmp_size);
    flags |= MAP_ANONYMOUS;
    addr = mmap(NULL, total_size, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (addr == MAP_FAILED) {
        IRM_ERR("memory slice create failed, mmap error %s, total_size %lu",
        strerror(errno), total_size);    
        irm_errno = -IRM_MEMORY_SLICE_CREATE_MMAP;
        slice = NULL;
        goto IRM_MEMORY_SLICE_ERR;
    }

IRM_MEMORY_SLICE_OUT:
    if (!slice) {
        slice = (struct irm_memory_slice *)addr;
        IRM_MEMORY_SLICE_INIT(slice, (uint8_t *)slice + IRM_PAGE_SIZE,
            total_size - IRM_PAGE_SIZE, IRM_FALSE);
    } else {
        IRM_MEMORY_SLICE_INIT(slice, addr, total_size - IRM_PAGE_SIZE, IRM_TRUE);
    }
    
IRM_MEMORY_SLICE_ERR:
    if (fd > 0) {
        close(fd);
    }

    return slice;
}

void *irm_memory_alloc(void *mpool, size_t size)
{
    struct irm_memory_slice *slice;
    void                    *addr = NULL;
    size_t                   free_size = 0;

    slice = IRM_MEMORY_POOL_CURRENT_SLICE(mpool);
    IRM_MEMORY_POOL_SLICE_FOREACH_FROM(slice) {
        if (IRM_MEMORY_SLICE_EMPTY(slice)) {
            break;
        }
        free_size = IRM_MEMORY_SLICE_FREE_SIZE(slice);
        if (free_size >= size) {
            addr = IRM_MEMORY_SLICE_LAST(slice);           
            IRM_MEMORY_SLICE_LAST_UPDATE(slice, size);
            return addr;
        }
    }
   
    slice = irm_memory_slice_create(slice, size);
    if (!slice) {
        return NULL;
    }
    if (!IRM_MEMORY_SLICE_EXTERNAL(slice)) {
        IRM_MEMORY_SLICE_APPEND(mpool, slice); 
    }
    addr = IRM_MEMORY_SLICE_LAST(slice);
    IRM_MEMORY_SLICE_LAST_UPDATE(slice, size);

    return addr;
}

void *irm_memory_calloc(void *mpool, size_t size)
{
    void *addr = irm_memory_alloc(mpool, size);
    if (!addr) {
        return NULL;
    }
    memset(addr, 0, size);
    return addr;
}

void *irm_memory_alloc_align(void *mpool, size_t size,
    size_t align)
{
    struct irm_memory_slice     *slice;
    size_t                       offset;
    size_t                       aligned_size;
    size_t                       free_size = 0;

    slice = IRM_MEMORY_POOL_CURRENT_SLICE(mpool);
    IRM_MEMORY_POOL_SLICE_FOREACH_FROM(slice) {
        if (IRM_MEMORY_SLICE_EMPTY(slice)) {
            break;
        }
        free_size = IRM_MEMORY_SLICE_FREE_SIZE(slice);
        offset = IRM_SIZE_ALIGN(IRM_OFFSET(IRM_MEMORY_SLICE_LAST(slice)), align);
        aligned_size = offset - IRM_OFFSET(IRM_MEMORY_SLICE_LAST(slice)) + size;
        if (free_size >=  aligned_size) {
            IRM_MEMORY_SLICE_LAST_UPDATE(slice, aligned_size);
            return (void *)offset;
        }
    }

    aligned_size = IRM_SIZE_ALIGN(size, align) + align;
    slice = irm_memory_slice_create(slice, aligned_size);
    if (!slice) {
        return NULL;
    }
    if (!IRM_MEMORY_SLICE_EXTERNAL(slice)) {
        IRM_MEMORY_SLICE_APPEND(mpool, slice); 
    }
    offset = IRM_SIZE_ALIGN(IRM_OFFSET(IRM_MEMORY_SLICE_LAST(slice)), align);
    aligned_size = offset - IRM_OFFSET(IRM_MEMORY_SLICE_LAST(slice)) + size;
    IRM_MEMORY_SLICE_LAST_UPDATE(slice, aligned_size);

    return (void *)offset;
}

void *irm_memory_calloc_align(void *mpool, size_t size,
    size_t align)
{
    void *addr = irm_memory_alloc_align(mpool, size, align);
    if (!addr) {
        return 0;
    }
    memset(addr, 0, size);
    return addr;
}

IRM_C_END

