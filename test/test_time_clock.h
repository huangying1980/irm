/* huangying */
#ifndef TEST_TIME_CLOCK_H
#define TEST_TIME_CLOCK_H

#include <time.h>
#include <stdint.h>

#define TEST_ATTR_CACHELINE_ALIGN __attribute__((aligned(64)))
#define TEST_TIME_CLOCK_SECOND(n) (n * 1000000000)
#define TEST_TIME_CLOCK_MILLISECOND(n) (n * 1000000)

#define TEST_HOT_CALL __attribute__((hot))
#define TEST_ALWAYS_INLINE inline __attribute__((always_inline))

#define TEST_TIME_CLOCK_MIN_WAIT_NS 10000000

#if !(__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9))
TEST_HOT_CALL static TEST_ALWAYS_INLINE uint64_t
test_get_cycle(void)
{
    return __builtin_ia32_rdtsc();
}
#else
TEST_HOT_CALL static TEST_ALWAYS_INLINE uint64_t
test_get_cycle(void)
{
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)lo) | (((uint64_t)hi) << 32);
}
#endif

struct test_time_clock {
    double   tsc_ghz_inv TEST_ATTR_CACHELINE_ALIGN;
    uint64_t tsc_per_ns;
    uint64_t tsc_per_us;
    uint64_t tsc_per_ms;
    uint64_t tsc_per_s;   
    uint64_t ns_offset;
    uint64_t base_tsc;
    uint64_t base_ns;
};

double test_time_clock_init(struct test_time_clock* tc, double tsc_ghz);

TEST_HOT_CALL static TEST_ALWAYS_INLINE uint64_t
test_time_clock_cycle2ns(struct test_time_clock* tc, uint64_t tsc)
{
    return tc->ns_offset + (uint64_t)(tsc * tc->tsc_ghz_inv);
}

TEST_HOT_CALL static TEST_ALWAYS_INLINE uint64_t
test_time_clock_us2cycle(struct test_time_clock* tc, uint64_t us)
{
    return tc->tsc_per_us * us;
}

TEST_HOT_CALL static TEST_ALWAYS_INLINE uint64_t
test_time_clock_ms2cycle(struct test_time_clock* tc, uint64_t ms)
{
    return tc->tsc_per_ms * ms;
}

static inline uint64_t test_tc_rdsysns(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

#endif
