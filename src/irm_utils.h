/* huangying */
#ifndef IRM_UTILS_H
#define IRM_UTILS_H

#include <string.h>
#include <time.h>
#include <sys/time.h>

#include <linux/stddef.h>
#include <linux/swab.h>
#include <net/if.h>

#include "irm_decls.h"
#include "irm_common.h"

IRM_C_BEGIN

#ifndef IRM_NO_MULTITHREAD
#if (__GNUC__ > 4 || (__GNUC__ >= 4 && __GNUC_MINOR__ >= 2))
#define IRM_CAS32(val, old, set) __sync_bool_compare_and_swap((val), (old), (set))
#else
#define IRM_CAS32(val, old, set) irm_cas32((val), (old), (set))
static IRM_ALWAYS_INLINE unsigned char
irm_cas32(volatile uint32_t* dst, uint32_t exp, uint32_t src)
{
    unsigned char res;
    asm volatile(
        "lock;"
        "cmpxchgl %[src], %[dst];"
        "sete %[res];"
        : [res] "=a" (res),
        [dst] "=m" (*dst)
        : [src] "r" (src),
        "a" (exp),
        "m" (*dst)
        : "memory");
    return res;
}
#endif
#else
#define IRM_CAS32(val, old, set) ({*(val) = (set); IRM_TRUE;})
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define __irm_ntohs(x)			__builtin_bswap16(x)
# define __irm_htons(x)			__builtin_bswap16(x)
# define __irm_constant_ntohs(x)	___constant_swab16(x)
# define __irm_constant_htons(x)	___constant_swab16(x)
# define __irm_ntohl(x)			__builtin_bswap32(x)
# define __irm_htonl(x)			__builtin_bswap32(x)
# define __irm_constant_ntohl(x)	___constant_swab32(x)
# define __irm_constant_htonl(x)	___constant_swab32(x)
# define __irm_be64_to_cpu(x)		__builtin_bswap64(x)
# define __irm_cpu_to_be64(x)		__builtin_bswap64(x)
# define __irm_constant_be64_to_cpu(x)	___constant_swab64(x)
# define __irm_constant_cpu_to_be64(x)	___constant_swab64(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define __irm_ntohs(x)			(x)
# define __irm_htons(x)			(x)
# define __irm_constant_ntohs(x)	(x)
# define __irm_constant_htons(x)	(x)
# define __irm_ntohl(x)			(x)
# define __irm_htonl(x)			(x)
# define __irm_constant_ntohl(x)	(x)
# define __irm_constant_htonl(x)	(x)
# define __irm_be64_to_cpu(x)		(x)
# define __irm_cpu_to_be64(x)		(x)
# define __irm_constant_be64_to_cpu(x)  (x)
# define __irm_constant_cpu_to_be64(x)  (x)
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif

#define irm_htons(x)				\
	(__builtin_constant_p(x) ?		\
	 __irm_constant_htons(x) : __irm_htons(x))
#define irm_ntohs(x)				\
	(__builtin_constant_p(x) ?		\
	 __irm_constant_ntohs(x) : __irm_ntohs(x))
#define irm_htonl(x)				\
	(__builtin_constant_p(x) ?		\
	 __irm_constant_htonl(x) : __irm_htonl(x))
#define irm_ntohl(x)				\
	(__builtin_constant_p(x) ?		\
	 __irm_constant_ntohl(x) : __irm_ntohl(x))
#define irm_cpu_to_be64(x)			\
	(__builtin_constant_p(x) ?		\
	 __irm_constant_cpu_to_be64(x) : __irm_cpu_to_be64(x))
#define irm_be64_to_cpu(x)			\
	(__builtin_constant_p(x) ?		\
	 __irm_constant_be64_to_cpu(x) : __irm_be64_to_cpu(x))

#define IRM_IS_POWER2(n) ((n) && !(((n) - 1) & (n)))
#ifdef IRM_ENABLE_MLOCK
#define IRM_MEM_LOCK(_addr, _sz) mlock((_addr), (_sz))    
#define IRM_MEM_UNLOCK(_addr, _sz) munlock((_addr), (_sz))    
#else
#define IRM_MEM_LOCK(_addr, _sz) do{}while(0)
#define IRM_MEM_UNLOCK(_addr, _sz) do{}while(0)
#endif

#ifdef IRM_FAST_MEMCPY
#define irm_memcpy irm_fast_memcpy
#else
#define irm_memcpy memcpy
#endif

#define IRM_IP_N2S(_ip) \
((uint8_t *)_ip)[0], ((uint8_t *)_ip)[1], ((uint8_t *)_ip)[2], ((uint8_t *)_ip)[3]

int irm_set_skbuf(int fd, uint32_t rd, uint32_t wr);
int irm_get_ifname_ip(uint32_t ip_be32, char * const ifname);
int irm_prepare_hugepage(size_t* size);
int irm_set_core(pid_t tid, int core_id);
int irm_set_fifo(pid_t tid, int priority);
int irm_set_thread_name(pid_t tid, const char* name, const char* suffix);
void* irm_load_state(const char* path, size_t path_len, size_t size,
    uint32_t magic, uint32_t version);

static inline unsigned int irm_get_ifindex(const char* ifname)
{
  return if_nametoindex(ifname);
}

static inline uint64_t irm_combine64(uint64_t v)
{
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;

    return v;
}

static inline uint64_t irm_power2_align64(uint64_t v)
{
    v--;
    v = irm_combine64(v);
    return v + 1;
}

static inline uint32_t irm_combine32(uint32_t x)
{
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;

    return x;
}

static inline uint32_t irm_power2_align32(uint32_t x)
{
    x--;
    x = irm_combine32(x);
    return x + 1;
}

static inline uint32_t irm_prevpow2_align32(uint32_t x)
{
  x = irm_combine32(x);
  return x - (x >> 1);
}

static inline uint32_t irm_get_token(void)
{
    struct timeval   tv = {0, 0};
    struct tm        tm = {0, 0};
    uint32_t         token;

    gettimeofday(&tv, NULL); 
    localtime_r(&tv.tv_sec, &tm);
    token = (tm.tm_mday % 4) * 1000000000 + tm.tm_hour * 10000000
        + tm.tm_min * 100000 + tm.tm_sec * 1000 + tv.tv_usec / 1000;
    return token;
}

IRM_C_END

#endif 
