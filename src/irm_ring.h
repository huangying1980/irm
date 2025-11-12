/* huangying */
#ifndef IRM_RING_H
#define IRM_RING_H

#include "irm_error.h"
#include "irm_common.h"
#include "irm_utils.h"

IRM_C_BEGIN

#define IRM_RING_SP_ENQ 0x0001
#define IRM_RING_SC_DEQ 0x0002

#define IRM_RING_SP (1)
#define IRM_RING_MP (0)
#define IRM_RING_SC (1)
#define IRM_RING_MC (0)


#define IRM_RING_SET_FLAGS(_ring, _flags)\
do {\
    (_ring)->prod.single = ((_flags) & IRM_RING_SP_ENQ) ? IRM_RING_SP : IRM_RING_MP;\
    (_ring)->cons.single = ((_flags) & IRM_RING_SC_DEQ) ? IRM_RING_SC : IRM_RING_MC;\
} while (0)

#define IRM_ENQUEUE_PTRS(r, start, prod_head, obj_table, n, obj_type) do { \
    uint32_t i; \
    const uint32_t size = (r)->size; \
    uint32_t idx = prod_head & (r)->mask; \
    obj_type* ring = (obj_type *)start; \
    if (IRM_LIKELY(idx + n < size)) { \
        for (i = 0; i < (n & ((~(unsigned)0x3))); i+=4, idx+=4) { \
            ring[idx] = obj_table[i]; \
            ring[idx+1] = obj_table[i+1]; \
            ring[idx+2] = obj_table[i+2]; \
            ring[idx+3] = obj_table[i+3]; \
        } \
        switch (n & 0x3) { \
            case 3: \
                ring[idx++] = obj_table[i++]; \
            case 2: \
                ring[idx++] = obj_table[i++]; \
            case 1: \
                ring[idx++] = obj_table[i++]; \
        } \
    } else { \
        for (i = 0; idx < size; i++, idx++) {\
            ring[idx] = obj_table[i]; \
        } \
        for (idx = 0; i < n; i++, idx++) {\
            ring[idx] = obj_table[i]; \
        } \
    } \
} while (0)

#define IRM_DEQUEUE_PTRS(r, start, cons_head, obj_table, n, obj_type) do { \
    uint32_t i; \
    uint32_t idx = cons_head & (r)->mask; \
    const uint32_t size = (r)->size; \
    obj_type* ring = (obj_type *)start; \
    if (IRM_LIKELY(idx + n < size)) { \
        for (i = 0; i < (n & (~(uint32_t)0x3)); i+=4, idx+=4) {\
            obj_table[i] = ring[idx]; \
            obj_table[i+1] = ring[idx+1]; \
            obj_table[i+2] = ring[idx+2]; \
            obj_table[i+3] = ring[idx+3]; \
        } \
        switch (n & 0x3) { \
            case 3: \
                obj_table[i++] = ring[idx++]; \
            case 2: \
                obj_table[i++] = ring[idx++]; \
            case 1: \
                obj_table[i++] = ring[idx++]; \
        } \
    } else { \
        for (i = 0; idx < size; i++, idx++) { \
            obj_table[i] = ring[idx]; \
        } \
        for (idx = 0; i < n; i++, idx++) {\
            obj_table[i] = ring[idx]; \
        } \
    } \
} while (0)

enum irm_ring_queue_behavior {
    IRM_RING_QUEUE_FIXED = 0, 
    IRM_RING_QUEUE_VARIABLE 
};

struct irm_ring_headtail {
    volatile uint32_t       head;
    volatile uint32_t       tail;
    uint32_t                single;
};

struct irm_ring {
    uint32_t                    size;
    uint32_t                    mask;
    uint32_t                    capacity;
    uint32_t                    flags;
    void**                      start;
    char                        pad0 IRM_ATTR_CACHELINE_ALIGN;

    struct irm_ring_headtail    prod IRM_ATTR_CACHELINE_ALIGN;
    char                        pad1 IRM_ATTR_CACHELINE_ALIGN;

    struct irm_ring_headtail    cons IRM_ATTR_CACHELINE_ALIGN;
    char                        pad2 IRM_ATTR_CACHELINE_ALIGN;

};

IRM_HOT_CALL static IRM_ALWAYS_INLINE void 
irm_update_tail(struct irm_ring_headtail* ht, uint32_t old_val,
    uint32_t new_val, uint32_t single, uint32_t enqueue)
{
    if (enqueue) {
        IRM_SMP_WMB();
    } else {
        IRM_SMP_RMB();
    }
    if (!single) {
        while (IRM_UNLIKELY(ht->tail != old_val)) {
            IRM_PAUSE();
        }
    }

    ht->tail = new_val;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_move_prod_head(struct irm_ring* r, uint32_t is_sp,
    uint32_t n, enum irm_ring_queue_behavior behavior,
    uint32_t* old_head, uint32_t* new_head, uint32_t* free_entries)
{
    const uint32_t capacity = r->capacity;
    uint32_t       max = n;
    int            success;

    do {
        n = max;
        *old_head = r->prod.head;
        IRM_SMP_RMB();

        *free_entries = (capacity + r->cons.tail - *old_head);
        if (IRM_UNLIKELY(n > *free_entries)) {
            n = (behavior == IRM_RING_QUEUE_FIXED) ? 0 : *free_entries;
        }

        if (n == 0) {
            return 0;
        }

        *new_head = *old_head + n;
        if (is_sp) {
            r->prod.head = *new_head;
            success = IRM_TRUE;
        } else {
            success = IRM_CAS32(&r->prod.head, *old_head, *new_head);
        }
    } while (IRM_UNLIKELY(success == IRM_FALSE));

    return n;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_move_cons_head(struct irm_ring* r, uint32_t is_sc,
    uint32_t n, enum irm_ring_queue_behavior behavior,
    uint32_t* old_head, uint32_t* new_head, uint32_t* entries)
{
    uint32_t     max = n;
    int          success;

    do {
        n = max;

        *old_head = r->cons.head;

        IRM_SMP_RMB();

        *entries = (r->prod.tail - *old_head);

        if (n > *entries) {
            n = (behavior == IRM_RING_QUEUE_FIXED) ? 0 : *entries;
        }

        if (IRM_UNLIKELY(n == 0)) {
            return 0;
        }

        *new_head = *old_head + n;
        if (is_sc) {
            r->cons.head = *new_head;
            IRM_SMP_RMB();
            success = IRM_TRUE;
        } else {
            success = IRM_CAS32(&r->cons.head, *old_head, *new_head);
        }
    } while (IRM_UNLIKELY(success == IRM_FALSE));

    return n;
}


IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_do_enqueue(struct irm_ring* r, void* const* obj_table,
    uint32_t n, enum irm_ring_queue_behavior behavior,
    uint32_t is_sp, uint32_t* free_space)
{
    uint32_t prod_head;
    uint32_t prod_next;
    uint32_t free_entries;

    n = irm_ring_move_prod_head(r, is_sp, n, behavior,
            &prod_head, &prod_next, &free_entries);
    if (n == 0) {
        goto IRM_RING_DO_ENQUEUE_END;
    }
    IRM_ENQUEUE_PTRS(r, r->start, prod_head, obj_table, n, void *);
    irm_update_tail(&r->prod, prod_head, prod_next, is_sp, 1);

IRM_RING_DO_ENQUEUE_END:
    if (free_space != NULL) {
        *free_space = free_entries - n;
    }

    return n;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_do_dequeue(struct irm_ring* r, void** obj_table,
    uint32_t n, enum irm_ring_queue_behavior behavior,
    uint32_t is_sc, uint32_t* available)
{
    uint32_t cons_head;
    uint32_t cons_next;
    uint32_t entries;

    n = irm_ring_move_cons_head(r, is_sc, n, behavior,
        &cons_head, &cons_next, &entries);
    if (n == 0) {
        goto IRM_RING_DO_DEQUEUE_END;
    }

    IRM_DEQUEUE_PTRS(r, r->start, cons_head, obj_table, n, void *);

    irm_update_tail(&r->cons, cons_head, cons_next, is_sc, 0);

IRM_RING_DO_DEQUEUE_END:
    if (available != NULL) {
        *available = entries - n;
    }
    return n;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_mp_enqueue_bulk(struct irm_ring* r, void* const* obj_table,
    uint32_t n, uint32_t* free_space)
{
    return irm_ring_do_enqueue(r, obj_table, n, IRM_RING_QUEUE_FIXED,
        IRM_RING_MP, free_space);
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_sp_enqueue_bulk(struct irm_ring* r, void* const* obj_table,
    uint32_t n, uint32_t* free_space)
{
    return irm_ring_do_enqueue(r, obj_table, n, IRM_RING_QUEUE_FIXED,
        IRM_RING_SP, free_space);
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_enqueue_bulk(struct irm_ring* r, void* const* obj_table,
    uint32_t n, uint32_t* free_space)
{
    return irm_ring_do_enqueue(r, obj_table, n, IRM_RING_QUEUE_FIXED,
        r->prod.single, free_space);
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_ring_mp_enqueue(struct irm_ring* r, void* obj)
{
    if (irm_ring_mp_enqueue_bulk(r, &obj, 1, NULL)) {
        return IRM_OK;
    }
    return -IRM_ERR_RING_ENQUEUE_NOBUFS;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_ring_sp_enqueue(struct irm_ring* r, void* obj)
{
    if (irm_ring_sp_enqueue_bulk(r, &obj, 1, NULL)) {
        return IRM_OK;
    }
    return -IRM_ERR_RING_ENQUEUE_NOBUFS;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_ring_enqueue(struct irm_ring* r, void* obj)
{
    if (irm_ring_enqueue_bulk(r, &obj, 1, NULL)) {
        return IRM_OK;
    }
    return -IRM_ERR_RING_ENQUEUE_NOBUFS;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_mc_dequeue_bulk(struct irm_ring* r, void** obj_table,
    uint32_t n, uint32_t* available)
{
    return irm_ring_do_dequeue(r, obj_table, n, IRM_RING_QUEUE_FIXED,
        IRM_RING_MC, available);
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_sc_dequeue_bulk(struct irm_ring* r, void** obj_table,
    uint32_t n, uint32_t* available)
{
    return irm_ring_do_dequeue(r, obj_table, n, IRM_RING_QUEUE_FIXED,
        IRM_RING_SC, available);
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_dequeue_bulk(struct irm_ring* r, void** obj_table, uint32_t n,
    uint32_t* available)
{
    return irm_ring_do_dequeue(r, obj_table, n, IRM_RING_QUEUE_FIXED,
        r->cons.single, available);
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_ring_mc_dequeue(struct irm_ring* r, void** obj_p)
{
    if (irm_ring_mc_dequeue_bulk(r, obj_p, 1, NULL)) {
        return IRM_OK;
    }
    return -IRM_ERR_RING_DEQUEUE_NOENTRY;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_ring_sc_dequeue(struct irm_ring* r, void** obj_p)
{
    if (irm_ring_sc_dequeue_bulk(r, obj_p, 1, NULL)) {
        return IRM_OK;
    }
    return -IRM_ERR_RING_DEQUEUE_NOENTRY;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_ring_dequeue(struct irm_ring* r, void** obj_p)
{
    if (irm_ring_dequeue_bulk(r, obj_p, 1, NULL)) {
        return IRM_OK;
    }
    return -IRM_ERR_RING_DEQUEUE_NOENTRY;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_count(const struct irm_ring* r)
{
    uint32_t prod_tail = r->prod.tail;
    uint32_t cons_tail = r->cons.tail;
    uint32_t count = (prod_tail - cons_tail) & r->mask;
    return (count > r->capacity) ? r->capacity : count;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_free_count(const struct irm_ring* r)
{
    return r->capacity - irm_ring_count(r);
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_ring_full(const struct irm_ring* r)
{
    return irm_ring_free_count(r) == 0;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE int
irm_ring_empty(const struct irm_ring* r)
{
        return irm_ring_count(r) == 0;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_get_size(const struct irm_ring* r)
{
    return r->size;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_get_capacity(const struct irm_ring* r)
{
    return r->capacity;
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_mp_enqueue_burst(struct irm_ring* r, void* const* obj_table,
    uint32_t n, uint32_t* free_space)
{
    return irm_ring_do_enqueue(r, obj_table, n,
        IRM_RING_QUEUE_VARIABLE, IRM_RING_MP, free_space);
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_sp_enqueue_burst(struct irm_ring* r, void* const* obj_table,
    uint32_t n, uint32_t* free_space)
{
    return irm_ring_do_enqueue(r, obj_table, n,
        IRM_RING_QUEUE_VARIABLE, IRM_RING_SP, free_space);
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_enqueue_burst(struct irm_ring* r, void* const* obj_table,
    uint32_t n, uint32_t* free_space)
{
    return irm_ring_do_enqueue(r, obj_table, n, IRM_RING_QUEUE_VARIABLE,
        r->prod.single, free_space);
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_mc_dequeue_burst(struct irm_ring* r, void** obj_table,
    uint32_t n, uint32_t* available)
{
    return irm_ring_do_dequeue(r, obj_table, n,
        IRM_RING_QUEUE_VARIABLE, IRM_RING_MC, available);
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_sc_dequeue_burst(struct irm_ring* r, void** obj_table,
    uint32_t n, uint32_t* available)
{
    return irm_ring_do_dequeue(r, obj_table, n,
        IRM_RING_QUEUE_VARIABLE, IRM_RING_SC, available);
}

IRM_HOT_CALL static IRM_ALWAYS_INLINE uint32_t
irm_ring_dequeue_burst(struct irm_ring* r, void** obj_table,
    uint32_t n, uint32_t* available)
{
    return irm_ring_do_dequeue(r, obj_table, n, IRM_RING_QUEUE_VARIABLE,
        r->cons.single, available);
}

int irm_ring_init(struct irm_ring* ring, uint32_t count, uint32_t flags);
void irm_ring_set_start(struct irm_ring* r, void** ring_start);
void irm_ring_set_prod(struct irm_ring* r, uint32_t pos);

IRM_C_END

#endif
