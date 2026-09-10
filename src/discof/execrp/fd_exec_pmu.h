#ifndef HEADER_fd_src_discof_execrp_fd_exec_pmu_h
#define HEADER_fd_src_discof_execrp_fd_exec_pmu_h

/* API for fast hardware performance counter sampling on AMD Zen 3+.

   This allows threads to cheaply track CPU ILP and cache misses with
   fine granularity (e.g. every Solana transaction). */

#include "../../flamenco/runtime/fd_runtime.h"

#if FD_HAS_X86
#if defined(__has_include)
#if __has_include(<linux/perf_event.h>)
#define FD_EXEC_PMU_HAS_PERF 1
#include <linux/perf_event.h>
#endif
#endif
#endif

#ifndef FD_EXEC_PMU_HAS_PERF
#define FD_EXEC_PMU_HAS_PERF 0
struct perf_event_mmap_page;
#endif

#define FD_EXEC_PMU_MAGIC     (0xf17eda2ce9c2b417UL)
#define FD_EXEC_PMU_EVENT_CNT (3UL)

#define FD_EXEC_PMU_EVENT_CYCLES       (0UL) /* cycles */
#define FD_EXEC_PMU_EVENT_INSTRUCTIONS (1UL) /* instructions retired */
#define FD_EXEC_PMU_EVENT_LLC_MISS     (2UL) /* demand data LLC misses */

struct fd_exec_pmu {
  ulong                         magic;
  int                           enabled;
  int                           txn_valid;
  int                           fd  [ FD_EXEC_PMU_EVENT_CNT ];
  struct perf_event_mmap_page * page[ FD_EXEC_PMU_EVENT_CNT ];
  ulong                         prev[ FD_EXEC_PMU_EVENT_CNT ];
};

typedef struct fd_exec_pmu fd_exec_pmu_t;

FD_PROTOTYPES_BEGIN

uint
fd_exec_pmu_amd_llc_miss_umask( uint family,
                                uint model );

void
fd_exec_pmu_reset( fd_exec_pmu_t * pmu );

/* Returns 1 when enabled, 0 when intentionally disabled, and -1 when
   supported setup failed with errno preserved. */
int
fd_exec_pmu_init( fd_exec_pmu_t * pmu,
                  int             is_pinned );

FD_PROTOTYPES_END

static inline int
fd_exec_pmu_read_one( struct perf_event_mmap_page const * page,
                      ulong *                             value ) {
#if FD_EXEC_PMU_HAS_PERF
  for( int retry=0; retry<16; retry++ ) {
    uint seq = FD_VOLATILE_CONST( page->lock );
    FD_COMPILER_MFENCE();
    if( FD_UNLIKELY( seq&1U ) ) continue;

    uint   cap_user_rdpmc = ((struct perf_event_mmap_page const volatile *)page)->cap_user_rdpmc;
    uint   idx       =       FD_VOLATILE_CONST( page->index          );
    long   offset    = (long)FD_VOLATILE_CONST( page->offset         );
    ushort pmc_width =       FD_VOLATILE_CONST( page->pmc_width      );
    if( FD_UNLIKELY( (!cap_user_rdpmc) | (!idx) | (!pmc_width) | (pmc_width>64U) ) ) return 0;

    uint lo, hi;
    __asm__ __volatile__( "rdpmc" : "=a"(lo), "=d"(hi) : "c"(idx-1U) );
    ulong pmc = ((ulong)hi<<32) | (ulong)lo;
    if( pmc_width<64U ) pmc = (ulong)(((long)(pmc<<(64U-pmc_width)))>>(64U-pmc_width));

    FD_COMPILER_MFENCE();
    if( FD_LIKELY( FD_VOLATILE_CONST( page->lock )==seq ) ) {
      *value = (ulong)(offset+(long)pmc);
      return 1;
    }
  }
#else
  (void)page;
  (void)value;
#endif
  return 0;
}

static inline int
fd_exec_pmu_snapshot( fd_exec_pmu_t * pmu,
                      ulong           value[ static FD_EXEC_PMU_EVENT_CNT ] ) {
  if( FD_UNLIKELY( !pmu->enabled ) ) return 0;
  for( ulong i=0UL; i<FD_EXEC_PMU_EVENT_CNT; i++ ) {
    if( FD_UNLIKELY( !fd_exec_pmu_read_one( pmu->page[ i ], &value[ i ] ) ) ) return 0;
  }
  return 1;
}

static inline void
fd_exec_pmu_record( fd_exec_pmu_t * pmu,
                    fd_txn_out_t *  txn_out ) {
  ulong now[ FD_EXEC_PMU_EVENT_CNT ];
  if( FD_UNLIKELY( !pmu->txn_valid || !fd_exec_pmu_snapshot( pmu, now ) ) ) {
    pmu->txn_valid = 0;
    fd_memset( &txn_out->details.pmc, 0, sizeof(txn_out->details.pmc) );
    return;
  }

  txn_out->details.pmc.cpu_cycles      = now[ FD_EXEC_PMU_EVENT_CYCLES       ] - pmu->prev[ FD_EXEC_PMU_EVENT_CYCLES       ];
  txn_out->details.pmc.instructions    = now[ FD_EXEC_PMU_EVENT_INSTRUCTIONS ] - pmu->prev[ FD_EXEC_PMU_EVENT_INSTRUCTIONS ];
  txn_out->details.pmc.demand_llc_miss = now[ FD_EXEC_PMU_EVENT_LLC_MISS     ] - pmu->prev[ FD_EXEC_PMU_EVENT_LLC_MISS     ];
  pmu->txn_valid = 0;
}

#endif /* HEADER_fd_src_discof_execrp_fd_exec_pmu_h */
