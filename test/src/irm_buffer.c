/* huangying */
#include "irm_buffer.h"

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

struct irm_buffer* irm_buffer_create(void* mpool, uint32_t count)
{
    struct irm_buffer* buffer = NULL;
    size_t             size;
    uint32_t           total_count;
    
    total_count = irm_power2_align32(count);
    size = sizeof(struct irm_buffer) + (sizeof(struct irm_mbuf *) * total_count);
    size = IRM_PAGE_ALIGN(size);
    buffer = (struct irm_buffer *)irm_memory_alloc_align(mpool, size,
        IRM_CACHELINE);

    if (buffer) {
        buffer->size = size; 
        buffer->count = total_count;
        buffer->mask = total_count - 1;
        buffer->head = 0;
        buffer->tail = 0;
        buffer->curr = 0;
        buffer->tlock = IRM_BUFFER_LOCK_OFF;
    }

    return buffer;
}
