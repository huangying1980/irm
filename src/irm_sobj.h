/* huangying */
#ifndef IRM_SOBJ_H
#define IRM_SOBJ_H

#include <stdint.h>

#include "irm_decls.h"
#include "irm_hashtable.h"

IRM_C_BEGIN

struct irm_sobj {
    struct irm_hashtable_ln ln;
    struct irm_queue        lru;
    uint32_t                size;
    uint32_t                key;
    uint32_t                data_size;
    unsigned char           data[0];
};

IRM_C_END

#endif
