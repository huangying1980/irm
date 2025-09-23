/* huangying */
#ifndef IRM_PREFETCH_X86_64_H_
#define IRM_PREFETCH_X86_64_H_
#include <xmmintrin.h>

#include "irm_decls.h"
#include "irm_common.h"

IRM_C_BEGIN

#ifdef IRM_PREFETCH_DEFAULT_NUM
#define IRM_PREFETCH_DEFAULT_NUM 3
#endif

#ifdef IRM_DISABLE_PREFETCH 
#define IRM_PREFETCH_0(_p)
#define IRM_PREFETCH_1(_p)
#define IRM_PREFETCH_2(_p)
#define IRM_PREFETCH_NTA(_p)
#else
#define IRM_PREFETCH_0(_p) irm_prefetch0(_p)
#define IRM_PREFETCH_1(_p) irm_prefetch1(_p)
#define IRM_PREFETCH_2(_p) irm_prefetch2(_p)
#define IRM_PREFETCH_NTA(_p) irm_prefetch_nta(_p)
#endif

#ifdef _mm_prefetch
IRM_HOT_CALL
static IRM_ALWAYS_INLINE void irm_prefetch0(const void* p)
{
    _mm_prefetch(p, _MM_HINT_T0);
}

IRM_HOT_CALL
static IRM_ALWAYS_INLINE void irm_prefetch1(const void* p)
{
    _mm_prefetch(p, _MM_HINT_T1);
}

IRM_HOT_CALL
static IRM_ALWAYS_INLINE void irm_prefetch2(const void* p)
{
    _mm_prefetch(p, _MM_HINT_T2);
}

IRM_HOT_CALL
static IRM_ALWAYS_INLINE void irm_prefetch_nta(const void* p)
{
    _mm_prefetch(p, _MM_HINT_NTA);
}
#else

IRM_HOT_CALL
static IRM_ALWAYS_INLINE void irm_prefetch0(const void* p)
{
	asm volatile ("prefetcht0 %[p]" : : [p] "m" (*(const volatile char *)p));
}

IRM_HOT_CALL
static IRM_ALWAYS_INLINE void irm_prefetch1(const void* p)
{
	asm volatile ("prefetcht1 %[p]" : : [p] "m" (*(const volatile char *)p));
}

IRM_HOT_CALL
static IRM_ALWAYS_INLINE void irm_prefetch2(const void* p)
{
	asm volatile ("prefetcht2 %[p]" : : [p] "m" (*(const volatile char *)p));
}

IRM_HOT_CALL
static IRM_ALWAYS_INLINE void irm_prefetch_nta(const void* p)
{
	asm volatile ("prefetchnta %[p]" : : [p] "m" (*(const volatile char *)p));
}
#endif

IRM_C_END
#endif 
