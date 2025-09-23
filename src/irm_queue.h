/* huangying */
#ifndef IRM_QUEUE_H
#define IRM_QUEUE_H

#include <stddef.h>

#include "irm_decls.h"
#include "irm_common.h"

IRM_C_BEGIN

struct irm_queue;
struct irm_queue {
  struct irm_queue* prev;
  struct irm_queue* next;
};

#define IRM_LN_INIT(_ln) ((_ln)->prev = (_ln)->next = NULL)

#define IRM_QUEUE_INIT(_q) \
  (_q)->prev = (_q); \
  (_q)->next = (_q)

#define IRM_QUEUE_EMPTY(_h) \
  (_h == (_h)->prev)

#define IRM_QUEUE_SENTINEL(_h) \
  (_h)

#define IRM_QUEUE_LAST(_h, _x)\
    ((_x)->next == (_h))

#define IRM_QUEUE_HEAD(_h) \
  (_h)->next

#define IRM_QUEUE_TAIL(_h) \
  (_h)->prev

#define IRM_QUEUE_NEXT(_q) \
  (_q)->next

#define IRM_QUEUE_PREV(_q) \
  (_q)->prev

#define IRM_QUEUE_DATA(_q, _type, _link) \
  ((_type *) ((unsigned char *) (_q) - IRM_OFFSETOF(_type, _link)))

#define IRM_QUEUE_INSERT_HEAD(_h, _x) \
  (_x)->next = (_h)->next; \
  (_x)->next->prev = (_x); \
  (_x)->prev = (_h); \
  (_h)->next = (_x)

#define IRM_QUEUE_INSERT_TAIL(_h, _x) \
  (_x)->prev = (_h)->prev; \
  (_x)->prev->next = (_x); \
  (_x)->next = (_h); \
  (_h)->prev = (_x)

#define IRM_QUEUE_INSERT_BEFORE(listelm, elm) \
do {  \
    (elm)->prev = (listelm)->prev;              \
    (elm)->next = (listelm);                    \
    (listelm)->prev->next = (elm);              \
    (listelm)->prev = (elm);                    \
} while (0)

#define IRM_QUEUE_INSERT_AFTER(_listelm, _elm) \
do {  \
  (_elm)->next = (_listelm)->next;                      \
  (_elm)->prev = (_listelm);                            \
  (_listelm)->next->prev = (_elm);                      \
  (_listelm)->next = (_elm);                            \
} while (0)

#define IRM_QUEUE_REMOVE(_x) \
  (_x)->next->prev = (_x)->prev; \
  (_x)->prev->next = (_x)->next; \

#define IRM_QUEUE_FOREACH(_i, _queue) \
  for ((_i) = (_queue)->next; (_i) != (_queue); (_i) = (_i)->next)

#define IRM_QUEUE_FOREACH_SAFE(_i, _queue, _next) \
  for ((_i) = (_queue)->next, (_next) = (_i)->next; \
    (_i) != (_queue); (_i) = (_next))

#define IRM_QUEUE_FOREACH_FROM(_i, _queue) \
  for (; (_i) != (_queue); (_i) = (_i)->next)

IRM_C_END

#endif
