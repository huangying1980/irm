/* huangying */
#ifndef IRM_MBUF_H
#define IRM_MBUF_H

#include <stdint.h>

#include "irm_decls.h"
#include "irm_queue.h"

#ifdef IRM_ENABLE_EFVI
#include "etherfabric/ef_vi.h"
#endif

IRM_C_BEGIN

#define IRM_MBUF_DMA(_mbuf) (((struct irm_mbuf *)(_mbuf))->ef_addr)
#define IRM_MBUF(_ptr) ((struct irm_mbuf *)(_ptr))
#define IRM_MBUF_NEXT(_mbuf) IRM_MBUF(_mbuf)->ln.next
#define IRM_MBUF_M2D(_mbuf) ((uint8_t *)(&IRM_MBUF(_mbuf)[1]))
#define IRM_MBUF_D2M(_data) &IRM_MBUF(_data)[-1]
#define IRM_MBUF_ELT_SIZE (2048U)
#define IRM_MBUF_DATA_SIZE(_ptr) IRM_MBUF(_ptr)->size
#define IRM_MBUF_ID(_ptr) IRM_MBUF(_ptr)->id
#define IRM_MBUF_LN(_ptr) &IRM_MBUF(_ptr)->ln
#define IRM_MBUF_MSG(_type, _mbuf, _o) (struct _type *)(IRM_MBUF_M2D(_mbuf) + (_o))
#define IRM_MBUF_PAYLOAD(_ptr) IRM_MBUF(_ptr)->payload

enum {
    IRM_MBUF_STATUS_SENDING = 0,
    IRM_MBUF_STATUS_IDLE = 1
};

struct irm_mbuf {
    struct irm_queue        cache_ln;
    struct irm_queue        sender_ln; 
    uint32_t                id;
    uint32_t                size;
    uint32_t                payload;
    uint8_t                 reserved:1;
    uint8_t                 status:7;
#ifdef IRM_ENABLE_EFVI
    ef_addr                 ef_addr;
#endif
} IRM_ATTR_CACHELINE_ALIGN;

IRM_C_END

#endif
