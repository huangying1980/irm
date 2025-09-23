/* huangying */
#ifndef IRM_BUFFER_H
#define IRM_BUFFER_H

#include "irm_decls.h"
#include "irm_common.h"
#include "irm_utils.h"
#include "irm_error.h"
#include "irm_mbuf.h"
#include "irm_log.h"
#include "irm_prefetch.h"

#ifdef IRM_BUFFER_V2
#include "irm_ring.h"
#endif

IRM_C_BEGIN

#define IRM_BUFFER_VALVE_ON (0xFFFFFFFFU)
#define IRM_BUFFER_VALVE_OFF (0U)

struct irm_buffer {
    size_t            size;
    uint32_t          count; 
    uint32_t          mask;
    char              pad IRM_ATTR_CACHELINE_ALIGN;
    volatile uint32_t valve IRM_ATTR_CACHELINE_ALIGN;
    volatile uint32_t head IRM_ATTR_CACHELINE_ALIGN;
    volatile uint32_t tlock IRM_ATTR_CACHELINE_ALIGN;
    volatile uint32_t tail IRM_ATTR_CACHELINE_ALIGN;
    volatile uint32_t curr IRM_ATTR_CACHELINE_ALIGN;
} IRM_ATTR_CACHELINE_ALIGN;

#define IRM_BUFFER_LOCK_ON  (1U)
#define IRM_BUFFER_LOCK_OFF (0U) 

#define IRM_BUFFER_PUT_LOCK(_b) \
    do {} while (!IRM_CAS32(&(_b)->tlock, \
        IRM_BUFFER_LOCK_OFF, \
        IRM_BUFFER_LOCK_ON))

#define IRM_BUFFER_PUT_UNLOCK(_b) \
    do {} while (!IRM_CAS32(&(_b)->tlock, \
        IRM_BUFFER_LOCK_ON, \
        IRM_BUFFER_LOCK_OFF))

struct irm_buffer* irm_buffer_create(void* mpool, uint32_t count);

IRM_HOT_CALL static IRM_ALWAYS_INLINE struct irm_mbuf* const
irm_buffer_pop(struct irm_buffer* buffer)
{
    uint32_t          available;
    uint32_t          tail;
    uint32_t          head;
    struct irm_mbuf** addr = (struct irm_mbuf **)&buffer[1];
    struct irm_mbuf*  obj;
    const uint32_t    mask = buffer->mask;


    do {
        head = buffer->head;
        tail = buffer->tail;
        IRM_RMB();
        available = tail - head;
        if (IRM_UNLIKELY(!available)) {
            irm_errno = -IRM_ERR_GET_AGAIN;
            return NULL;
        }
        obj = addr[head & mask];
    } while (!IRM_CAS32(&buffer->head, head, head + 1));
    
    IRM_DBG("pop obj %p, tail %u, curr %u, head %u, mask %u", obj,
        buffer->tail, buffer->curr, buffer->head, buffer->mask);

    return obj;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE struct irm_mbuf* const
irm_buffer_get(struct irm_buffer* buffer)
{
    uint32_t          available;
    uint32_t          tail;
    struct irm_mbuf** addr = (struct irm_mbuf **)&buffer[1];
    struct irm_mbuf*  obj;
    const uint32_t    mask = buffer->mask;

    tail = buffer->tail;
    IRM_RMB();
    available = tail - buffer->curr;
    if (IRM_UNLIKELY(!available)) {
        irm_errno = -IRM_ERR_GET_AGAIN;
        IRM_DBG("no available mbuf tail %u, head %u, curr %u",
            tail, buffer->head, buffer->curr);
        return NULL;
    }
    obj = addr[buffer->curr++ & mask];
    IRM_DBG("get obj tail %u, curr %u, head %u, count %u",
        buffer->tail, buffer->curr, buffer->head, buffer->count);
    return obj;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_buffer_fifo(struct irm_buffer* buffer, struct irm_mbuf* objs[],
    const uint32_t count) 
{
    uint32_t            available;
    uint32_t            cnt;
    uint32_t            i = 0;
    uint32_t            head = 0;
    uint32_t            n;
    struct irm_mbuf**   addr = (struct irm_mbuf **)&buffer[1];
    const uint32_t      mask = buffer->mask;

    head = buffer->head;
    IRM_RMB();
    available = buffer->curr - head;
    if (IRM_UNLIKELY(!available)) {
        return 0;
    }
    cnt = available ^ ((count ^ available) & -(count < available));
    n = (cnt + 7) >> 3;
    IRM_DBG("to fifo count %u", cnt); 

    switch (cnt & 7) {
        case 0: do {objs[i++] = addr[head++ & mask];
        case 7: objs[i++] = addr[head++ & mask];
        case 6: objs[i++] = addr[head++ & mask];
        case 5: objs[i++] = addr[head++ & mask];
        case 4: objs[i++] = addr[head++ & mask];
        case 3: objs[i++] = addr[head++ & mask];
        case 2: objs[i++] = addr[head++ & mask];
        case 1: objs[i++] = addr[head++ & mask];
                } while (--n > 0);
    }

    buffer->head = head;

    return cnt;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_buffer_fifo_idle(struct irm_buffer* buffer, struct irm_mbuf* objs[],
    const uint32_t count) 
{
    uint32_t            available;
    uint32_t            cnt;
    uint32_t            i;
    uint32_t            slot;
    uint32_t            head;
    const uint32_t      mask = buffer->mask;
    struct irm_mbuf**   addr = (struct irm_mbuf **)&buffer[1];

    head = buffer->head;
    IRM_RMB();
    available = buffer->curr - head;
    cnt = available ^ ((count ^ available) & -(count < available));

    for (i = 0; i < cnt; ++i) {
        slot = head & mask;
        if (addr[slot]->status == IRM_MBUF_STATUS_SENDING) {
            break;
        }
        objs[i] = addr[slot];
        ++head;
    }

    buffer->head = head;
    return cnt;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_buffer_put(struct irm_buffer* buffer, struct irm_mbuf* obj)
{
    struct irm_mbuf** addr = (struct irm_mbuf **)&buffer[1];
    uint32_t          available;
    uint32_t          tail;
    uint32_t          count;
    const uint32_t    mask = buffer->mask;

    tail = buffer->tail;
    IRM_RMB();
    count = buffer->count & buffer->valve;
    available = tail - buffer->head;

    if (IRM_UNLIKELY(available >= count)) {
        irm_errno = -IRM_ERR_PUT_AGAIN;
        IRM_DBG("tail %u, head %u, available %u, count %u, put error %d",
            buffer->tail, buffer->head, available, count, irm_errno);
        return irm_errno;
    }

    addr[mask & tail++] = obj;
    buffer->tail = tail;
    IRM_DBG("put obj tail %u, head %u, curr %u",
        buffer->tail, buffer->head, buffer->curr);

    return IRM_OK;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_buffer_put_sequence(struct irm_buffer* buffer, struct irm_mbuf* obj,
    uint32_t* seq)
{
    struct irm_mbuf** addr = (struct irm_mbuf **)&buffer[1];
    uint32_t          count;
    uint32_t          tail;
    uint32_t          head;
    uint32_t          available;
    const uint32_t    mask = buffer->mask;

    IRM_BUFFER_PUT_LOCK(buffer);
    tail = buffer->tail;
    head = buffer->head;
    count = buffer->count & buffer->valve;
    available = tail - head;
    if (IRM_UNLIKELY(available >= count)) {
        IRM_BUFFER_PUT_UNLOCK(buffer);
        IRM_DBG("buffer full tail %u, head %u, curr %u, count %u, valve %u",
            tail, head, buffer->curr, count, buffer->valve);
        irm_errno = -IRM_ERR_PUT_AGAIN;
        return irm_errno;
    }


    *seq = tail;
    addr[mask & tail++] = obj;
    buffer->tail = tail;
    IRM_BUFFER_PUT_UNLOCK(buffer);
    IRM_DBG("irm_buffer_put_sequence tail %u, head %u, curr %u, count %u\n",
        buffer->tail, buffer->head, buffer->curr, buffer->count);

    return IRM_OK;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE void
irm_buffer_rollback(struct irm_buffer* buffer)
{
    --buffer->curr;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE struct irm_mbuf* const
irm_buffer_pick(struct irm_buffer* buffer, uint32_t index)
{
    const uint32_t      mask = buffer->mask;
    struct irm_mbuf**   addr = (struct irm_mbuf **)&buffer[1];

    return addr[index & mask];    
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_rxbuffer_available(struct irm_buffer* buffer)
{
    uint32_t available;

    available = buffer->tail - buffer->head;
    IRM_RMB();
    return available;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_txbuffer_available(struct irm_buffer* buffer)
{
    uint32_t available;

    available = buffer->tail - buffer->curr;
    IRM_RMB();
    return available;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_buffer_full(struct irm_buffer* buffer)
{
    uint32_t available;

    available = buffer->tail - buffer->head;
    IRM_RMB();
    return available >= buffer->count;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_buffer_free(struct irm_buffer* buffer)
{
    uint32_t available;

    available = buffer->tail - buffer->head;
    IRM_RMB();

    return buffer->count - available; 
}

#define IRM_BUFFER_VALVE(_b, _v) ((_b)->valve = (_v))

IRM_C_END

#endif
