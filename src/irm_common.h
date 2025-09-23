/* huangying */
#ifndef IRM_COMMON_H
#define IRM_COMMON_H
#include <stdint.h>
#include <emmintrin.h>
#include <linux/limits.h>

#include "irm_decls.h"

IRM_C_BEGIN

#define IRM_TRUE 1
#define IRM_FALSE 0

#define IRM_PAGE_1GB  (1UL << 30)
#define IRM_PAGE_2MB  (1UL << 21)
#define IRM_PAGE_SIZE (4096)
#define IRM_CACHELINE (64)
#define IRM_PATH_MAX   PATH_MAX

#ifndef IRM_WAIT_US
#define IRM_WAIT_US     (5 * 1000)
#endif

#ifndef IRM_WAIT_RETRY
#define IRM_WAIT_RETRY  (5)
#endif

#define IRM_INVALID_FD (-1)

#ifndef typeof
#define typeof __typeof__
#endif

#define IRM_OFFSET(_o) ((uintptr_t)(_o))
#define IRM_OFFSETOF(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define IRM_CONTAINER_OF(ptr, type, member) ({			\
	(type *)( (char *)ptr - IRM_OFFSETOF(type, member) );})

#define IRM_SIZE_ALIGN(_s, _m) (((_s) + (_m) - 1) & ~((_m) - 1))
#define IRM_CACHELINE_ALIGN(_s) IRM_SIZE_ALIGN(_s, IRM_CACHELINE)
#define IRM_PAGE_ALIGN(_s) IRM_SIZE_ALIGN(_s, IRM_PAGE_SIZE)

#define IRM_ATTR_ALIGN(_s) __attribute__((aligned(_s)))
#define IRM_ATTR_CACHELINE_ALIGN IRM_ATTR_ALIGN(IRM_CACHELINE)
#define IRM_ATTR_PTR_ALIGN IRM_ATTR_ALIGN(sizeof(void *))
#define IRM_ATTR_PAGE_ALIGN IRM_ATTR_ALIGN(IRM_PAGE_SIZE)
#define IRM_ATTR_PACKED __attribute__((packed))

#ifdef IRM_FENCE
#define IRM_RMB()   _mm_lfence()
#define IRM_WMB()   _mm_sfence()
#define IRM_MB()    _mm_mfence()
#define IRM_PAUSE() _mm_pause()
#else
#define IRM_RMB() 
#define IRM_WMB()
#define IRM_MB()
#define IRM_PAUSE()
#endif

#define IRM_LIKELY(x) __builtin_expect(!!(x), 1)
#define IRM_UNLIKELY(x)  __builtin_expect(!!(x), 0)

#ifdef IRM_DISABLE_HOT_CALL
#define IRM_HOT_CALL
#else
#define IRM_HOT_CALL __attribute__((hot))
#endif

#ifdef IRM_DISABLE_ALWAYS_INLINE
#define IRM_ALWAYS_INLINE inline
#else
#define IRM_ALWAYS_INLINE inline __attribute__((always_inline))
#endif

#define IRM_UNUSED(_sym) _sym __attribute__((unused))

#ifndef IRM_HUGEPAGE_ENV
#define IRM_HUGEPAGE_ENV "IRM_HUGEPAGE_HOME"
#endif

#ifndef IRM_HUGEPAGE_FILE
#define IRM_HUGEPAGE_FILE "irm_hugepage"
#endif

#define IRM_BUG_ON(_c) ((void)sizeof(char[1 - 2*!!(_c)]))


IRM_C_END

#endif
