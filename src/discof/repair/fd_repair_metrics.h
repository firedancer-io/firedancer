#ifndef HEADER_fd_src_discof_repair_fd_repair_metrics_h
#define HEADER_fd_src_discof_repair_fd_repair_metrics_h

/* fd_repair_metrics tracks metadata on the N most recent slots, in particular
   the time it took to complete the slot.  As this purpose of this
   module currently is exclusively to print a waterfall diagram of the
   repair_metrics progress, this is a circular buffer of the last N slots,
   where N=256 and is non-configurable. */

#include "../../util/fd_util_base.h"

struct fd_slot_metrics {
  ulong slot;

  long  first_shred_ts;
  long  slot_complete_ts; /* tick */

  uint repair_cnt;
  uint turbine_cnt;
};
typedef struct fd_slot_metrics fd_slot_metrics_t;

struct fd_shred_metrics {
  ulong slot;
  uint  shred_idx;
  ulong req_cnt;
  ulong res_cnt;
};
typedef struct fd_shred_metrics fd_shred_metrics_t;

#define FD_CATCHUP_METRICS_MAX 16384

struct fd_repair_metrics_t {
  fd_slot_metrics_t  slots[FD_CATCHUP_METRICS_MAX];
  fd_shred_metrics_t shreds[FD_CATCHUP_METRICS_MAX];
  uint               st;
  uint               en;
  ulong              turbine_slot0;
};
typedef struct fd_repair_metrics_t fd_repair_metrics_t;


FD_FN_CONST static inline ulong
fd_repair_metrics_align( void ) {
  return alignof( fd_slot_metrics_t );
}

FD_FN_CONST static inline ulong
fd_repair_metrics_footprint( void ) {
  return sizeof( fd_repair_metrics_t );
}

void *
fd_repair_metrics_new( void * mem );

fd_repair_metrics_t *
fd_repair_metrics_join( void * repair_metrics );

void
fd_repair_metrics_set_turbine_slot0( fd_repair_metrics_t * repair_metrics, ulong turbine_slot0 );

void
fd_repair_metrics_print( fd_repair_metrics_t * repair_metrics, int verbose );

void
fd_repair_metrics_print_sorted( fd_repair_metrics_t * repair_metrics, int verbose, fd_slot_metrics_t * temp_slots );

void
fd_repair_metrics_add_slot( fd_repair_metrics_t * repair_metrics, ulong slot, long first_ts, long slot_complete_ts, uint repair_cnt, uint turbine_cnt );



#endif /* HEADER_fd_src_discof_repair_fd_repair_metrics_h */
