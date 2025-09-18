#ifndef HEADER_fd_src_flamenco_repair_fd_catchup_h
#define HEADER_fd_src_flamenco_repair_fd_catchup_h

/* fd_catchup tracks metadata on the N most recent slots, in particular
   the time it took to complete the slot.  As this purpose of this
   module currently is exclusively to print a waterfall diagram of the
   catchup progress, this is a circular buffer of the last N slots,
   where N=256 and is non-configurable. */


#include "../../util/fd_util_base.h"
struct fd_catchup_metrics {
  ulong slot;
  long  first_ts;
  long  slot_complete_ts;

  uint repair_cnt;
  uint turbine_cnt;
};
typedef struct fd_catchup_metrics fd_catchup_metrics_t;

#define FD_CATCHUP_METRICS_MAX 256

struct fd_catchup_t {
  fd_catchup_metrics_t metrics[ FD_CATCHUP_METRICS_MAX ];
  uint                 st;
  uint                 en;
  ulong                turbine_slot0;
};
typedef struct fd_catchup_t fd_catchup_t;


FD_FN_CONST static inline ulong
fd_catchup_align( void ) {
  return alignof( fd_catchup_metrics_t );
}

FD_FN_CONST static inline ulong
fd_catchup_footprint( void ) {
  return sizeof( fd_catchup_t );
}

void *
fd_catchup_new( void * mem );

fd_catchup_t *
fd_catchup_join( void * catchup );

void
fd_catchup_set_turbine_slot0( fd_catchup_t * catchup, ulong turbine_slot0 );

void
fd_catchup_print( fd_catchup_t * catchup );

void
fd_catchup_add_slot( fd_catchup_t * catchup, ulong slot, long first_ts, long slot_complete_ts, uint repair_cnt, uint turbine_cnt );



#endif /* HEADER_fd_src_flamenco_repair_fd_catchup_h */
