/* huangying */
#ifndef IRM_TASKQUEUE_H
#define IRM_TASKQUEUE_H

#include "irm_decls.h"
#include "irm_common.h"
#include "irm_utils.h"
#include "irm_error.h"
#include "irm_sobj.h"
#include "irm_mbuf.h"
#include "irm_log.h"

IRM_C_BEGIN

typedef void* irm_ptr_t;

struct irm_taskqueue {
    size_t            size;
    uint32_t          count; 
    uint32_t          mask;
    volatile uint32_t head IRM_ATTR_CACHELINE_ALIGN;
    volatile uint32_t tail IRM_ATTR_CACHELINE_ALIGN;
} IRM_ATTR_CACHELINE_ALIGN;

struct irm_taskqueue* irm_taskqueue_create(void* mpool,
     uint32_t count);

IRM_HOT_CALL static IRM_ALWAYS_INLINE irm_ptr_t  
irm_taskqueue_pop(struct irm_taskqueue* taskqueue)
{
    uint32_t          head;
    uint32_t          tail;
    uint32_t          available;
    irm_ptr_t*        addr = (irm_ptr_t *)&taskqueue[1];
    irm_ptr_t         obj;

    IRM_RMB();
    head = taskqueue->head;
    tail = taskqueue->tail;

    available = tail - head;
    if (IRM_UNLIKELY(!available)) {
        irm_errno = -IRM_ERR_GET_AGAIN;
        return NULL;
    }
    do {
        head = taskqueue->head;
        obj = addr[head & taskqueue->mask];
    } while (!IRM_CAS32(&taskqueue->head, head, head + 1));

    return obj;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_taskqueue_push(struct irm_taskqueue* taskqueue, irm_ptr_t obj)
{
    irm_ptr_t*        addr = (irm_ptr_t *)&taskqueue[1];
    uint32_t          head;
    uint32_t          tail;
    uint32_t          count;
    uint32_t          available;


    IRM_RMB();
    head = taskqueue->head;
    tail = taskqueue->tail;
    count = taskqueue->count;

    available = tail - head;
  
    if (IRM_UNLIKELY(available >= count)) {
        irm_errno = -IRM_ERR_PUSH_AGAIN;
        return irm_errno;
    }

    do {
        tail = taskqueue->tail;
        addr[taskqueue->mask & tail] = obj;
    } while (!IRM_CAS32(&taskqueue->tail, tail, tail + 1));

    return IRM_OK;
}

static IRM_ALWAYS_INLINE uint32_t
irm_taskqueue_push_batch(struct irm_taskqueue* taskqueue,
    struct irm_mbuf* mbufs[], const uint32_t count)
{
    irm_ptr_t*  addr = (irm_ptr_t *)&taskqueue[1];
    uint32_t    tail;
    uint32_t    available;
    uint32_t    free;
    uint32_t    n;
    uint32_t    i = 0;
    uint32_t    j = 0;
    const uint32_t mask = taskqueue->mask;

    IRM_WMB();
    tail = taskqueue->tail;    
    available = tail - taskqueue->head;
    free = taskqueue->count - available;
    if (IRM_UNLIKELY(free < count)) {
        return 0;
    }
    n = (count + 7) >> 3;
    do {
        j = tail = taskqueue->tail;    
        switch (count & 7) {
            case 0: do { addr[j++ & mask] = mbufs[i++];
            case 7: addr[j++ & mask] = mbufs[i++];
            case 6: addr[j++ & mask] = mbufs[i++];
            case 5: addr[j++ & mask] = mbufs[i++];
            case 4: addr[j++ & mask] = mbufs[i++];
            case 3: addr[j++ & mask] = mbufs[i++];
            case 2: addr[j++ & mask] = mbufs[i++];
            case 1: addr[j++ & mask] = mbufs[i++];
                    } while (--n > 0);
        }
    } while (!IRM_CAS32(&taskqueue->tail, tail, tail + count));

    return count;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_taskqueue_available(struct irm_taskqueue* taskqueue)
{
    IRM_RMB();
    return taskqueue->tail - taskqueue->head;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_taskqueue_full(struct irm_taskqueue* taskqueue)
{
    IRM_RMB();
    return taskqueue->tail - taskqueue->head >= taskqueue->count;
}

IRM_C_END

#endif
