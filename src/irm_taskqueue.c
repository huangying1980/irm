/* huangying */
#include "irm_taskqueue.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>

#include <sys/mman.h>

#include "irm_memory_pool.h"
#include "irm_utils.h"
#include "irm_error.h"
#include "irm_log.h"

struct irm_taskqueue* irm_taskqueue_create(void* mpool, uint32_t count)
{
    struct irm_taskqueue* taskqueue = NULL;
    size_t                size;
    uint32_t              total_count;
    
    total_count = irm_power2_align32(count);
    size = sizeof(struct irm_taskqueue) + (sizeof(irm_ptr_t) * total_count);
    size = IRM_PAGE_ALIGN(size);
    taskqueue = (struct irm_taskqueue *)irm_memory_alloc_align(mpool, size,
        IRM_CACHELINE);
    if (!taskqueue) {
        IRM_ERR("taskqueue create failed alloc error %d", irm_errno);
        return NULL;
    }  

    taskqueue->size = size; 
    taskqueue->count = total_count;
    taskqueue->mask = total_count - 1;
    taskqueue->head = 0;
    taskqueue->tail = 0;

    return taskqueue;
}
