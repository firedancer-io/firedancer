#ifndef HEADER_fd_src_disco_wksp_fd_wksp_mon_h
#define HEADER_fd_src_disco_wksp_fd_wksp_mon_h

/* fd_wksp_mon incrementally scans fd_wksp partitions lockfree to
   track space utilization. */

#include "../../util/wksp/fd_wksp.h"

#define FD_WKSP_MON_BURST_MAX    (4096UL)
#define FD_WKSP_MON_DEFAULT_RATE (10UL<<20) /* 10 MB/s */

struct fd_wksp_mon {
  fd_wksp_t * wksp;
  ulong       part_max;
  ulong       ticks_per_part;

  ulong       scan_idx;
  long        last_tick;
  long        tick_rem;

  ulong       acc_free_cnt;
  ulong       acc_free_sz;
  ulong       acc_free_max_sz;
  ulong       acc_used_cnt;
  ulong       acc_used_sz;
  ulong       acc_used_hist[64]; /* log2-bucketed used partition sizes */

  ulong       free_cnt;
  ulong       free_sz;
  ulong       free_max_sz;
  ulong       part_median_sz;
  ulong       part_mean_sz;
  ulong       sweep_cnt;
};

typedef struct fd_wksp_mon fd_wksp_mon_t;

FD_PROTOTYPES_BEGIN

/* fd_wksp_mon_init starts monitoring wksp.  bytes_per_sec controls the
   pinfo scan rate (use FD_WKSP_MON_DEFAULT_RATE for 10 MB/s).
   Internally converts to ticks_per_part via fd_tempo_tick_per_ns.
   now is fd_tickcount(). */

fd_wksp_mon_t *
fd_wksp_mon_init( fd_wksp_mon_t * mon,
                  fd_wksp_t *     wksp,
                  ulong           bytes_per_sec,
                  long            now );

void *
fd_wksp_mon_fini( fd_wksp_mon_t * mon );

/* fd_wksp_mon_tick does incremental scanning.  Call with now from
   fd_tickcount().  Scans a rate-limited burst of partitions per call.
   Publishes metrics when a full sweep completes. */

fd_wksp_mon_t *
fd_wksp_mon_tick( fd_wksp_mon_t * mon,
                  long            now );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_wksp_fd_wksp_mon_h */
