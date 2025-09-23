/* huangying */
#include "irm_time_clock.h"

static double irm_time_clock_calibrate(struct irm_time_clock* tc,
    uint64_t min_wait_ns);
static void irm_time_clock_sync_time(uint64_t* tsc, uint64_t* ns);
static void irm_time_clock_adjust_offset(struct irm_time_clock* tc);
static inline uint64_t irm_time_clock_rdsysns(void);

double irm_time_clock_init(struct irm_time_clock* tc, double tsc_ghz)
{
    tc->tsc_ghz_inv = 1.0;
    tc->ns_offset = 0;
    tc->base_tsc = 0;
    tc->base_ns = 0;
    double ghz;
    irm_time_clock_sync_time(&tc->base_tsc, &tc->base_ns);
    if (tsc_ghz > 0) {
        tc->tsc_ghz_inv = 1.0 / tsc_ghz;
        irm_time_clock_adjust_offset(tc);
        ghz = tsc_ghz;
    } else {
        ghz = irm_time_clock_calibrate(tc, 10000000);
    }
    tc->tsc_per_ns = ghz;
    tc->tsc_per_us = ghz * 1000;
    tc->tsc_per_ms = ghz * 1000000;
    tc->tsc_per_s = ghz * 1000000000;
    return ghz;
}

static double irm_time_clock_calibrate(struct irm_time_clock* tc,
    uint64_t min_wait_ns)
{
    uint64_t delayed_tsc = 0;
    uint64_t delayed_ns = 0;

    do {
        irm_time_clock_sync_time(&delayed_tsc, &delayed_ns);
    } while ((delayed_ns - tc->base_ns) < min_wait_ns);

    tc->tsc_ghz_inv = (double)(delayed_ns - tc->base_ns) /
        (delayed_tsc - tc->base_tsc);
    irm_time_clock_adjust_offset(tc);

    return 1.0 / tc->tsc_ghz_inv;
}

static void irm_time_clock_sync_time(uint64_t* tsc, uint64_t* ns)
{
    int N = 10;
    uint64_t tscs[N + 1];
    uint64_t nses[N + 1];

    tscs[0] = irm_get_cycle();
    for (int i = 1; i <= N; i++) {
        nses[i] = irm_time_clock_rdsysns();
        tscs[i] = irm_get_cycle();
    }

    int best = 1;
    for (int i = 2; i <= N; i++) {
        if (tscs[i] - tscs[i - 1] < tscs[best] - tscs[best - 1]) best = i;
    }

    *tsc = (tscs[best] + tscs[best - 1]) >> 1;
    *ns = nses[best];
}


static void irm_time_clock_adjust_offset(struct irm_time_clock* tc)
{ 
  tc->ns_offset = tc->base_ns - (uint64_t)(tc->base_tsc * tc->tsc_ghz_inv);
}

static inline uint64_t irm_time_clock_rdsysns(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

