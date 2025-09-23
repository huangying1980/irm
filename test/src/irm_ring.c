/* huangying */
#include "irm_ring.h"
#include "irm_log.h"

#define IRM_RING_ISPOWER2(_x) ((((_x) - 1) & (_x)) == 0)


#define IRM_RING_SZ_MASK  (0x7fffffffU)

int irm_ring_init(struct irm_ring* ring, uint32_t count, uint32_t flags)
{
    if (!IRM_RING_ISPOWER2(count) || count > IRM_RING_SZ_MASK) {
        IRM_ERR("count %u is not power2", count);
        return -IRM_ERR_RING_INIT;
    }

    memset(ring, 0, sizeof(struct irm_ring));
    ring->start = NULL;
    ring->size = count;
    ring->mask = count - 1;
    ring->capacity = ring->mask;
    ring->prod.head = ring->cons.head;
    ring->prod.tail = ring->cons.tail;
    ring->prod.single = (flags & IRM_RING_SP_ENQ) ? IRM_RING_SP : IRM_RING_MP;
    ring->cons.single = (flags & IRM_RING_SC_DEQ) ? IRM_RING_SC : IRM_RING_MC;
    ring->flags = flags;

    return IRM_OK;
}

void irm_ring_set_start(struct irm_ring* r, void** ring_start)
{
    r->start = ring_start;
}

void irm_ring_set_prod(struct irm_ring* r, uint32_t pos)
{
    r->prod.head = r->prod.tail = pos;
}
