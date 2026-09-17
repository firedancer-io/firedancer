#ifndef HEADER_fd_src_discof_rotor_fd_repair_stats_h
#define HEADER_fd_src_discof_rotor_fd_repair_stats_h

/* fd_repair_stats is a sidecar to the chainer that tracks the per-slot
   statistics the legacy repair forest kept: when a slot's first shred
   arrived, when the block became whole, and how many of its shreds
   came from turbine, from repair, or were recovered from coding shreds.

   The chainer knows nothing about this module and this module knows
   nothing about the chainer: the tile, which sees every shred arrive
   and reads the chainer after every call, starts a slot's clock when
   it first sees the slot and stops it when it finds a version whole.
   Shred sources come from the tile as well, which is the only
   component that sees where a shred arrived from.

   Records live in one table indexed by slot modulo its size and stay
   there after completion, so the recent history is queryable, until a
   newer slot lands on the same position and overwrites them.  Nothing
   is ever freed and nothing can leak.  Versions of one slot share its
   record: the first version to appear starts the clock and the first
   to complete stops it, which is what the forest measured. */

#include "../../disco/shred/fd_shred_tile.h"

struct fd_repair_stats_slot {
  ulong slot;             /* ULONG_MAX when the record is empty */
  long  first_shred_ts;   /* first shred seen or first version created */

  uint  repair_cnt;       /* data shreds that arrived as repair responses */
  uint  turbine_cnt;      /* data shreds that arrived over turbine */
  uint  recovered_cnt;    /* data shreds reconstructed from coding shreds; set on completion */

  uint  code_cnt;         /* number of coding shreds received */
};
typedef struct fd_repair_stats_slot fd_repair_stats_slot_t;

typedef struct fd_repair_stats fd_repair_stats_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_repair_stats_align( void );

/* fd_repair_stats_footprint returns the footprint for a table of
   slot_max records.  Returns 0 if slot_max is 0. */

FD_FN_CONST ulong
fd_repair_stats_footprint( ulong slot_max );

void *
fd_repair_stats_new( void * mem,
                     ulong  slot_max );

fd_repair_stats_t *
fd_repair_stats_join( void * mem );

void *
fd_repair_stats_leave( fd_repair_stats_t const * stats );

void *
fd_repair_stats_delete( void * mem );

/* fd_repair_stats_slot_start starts slot's clock at now if it has not
   started (a version was created before any of its shreds arrived,
   e.g. from a votor block id). */

void
fd_repair_stats_slot_start( fd_repair_stats_t * self,
                            ulong               slot,
                            long                now );

/* fd_repair_stats_shred_received counts one accepted data shred for
   slot, from repair if from_repair is set and from turbine otherwise,
   starting the slot's clock at now if it has not started.  Called by
   the tile, which is the only party that knows the source. */

void
fd_repair_stats_shred_received( fd_repair_stats_t * self,
                                ulong               slot,
                                int                 is_data,
                                uint                shred_src,
                                long                now );

/* fd_repair_stats_print_slot logs slot's record as one NOTICE line: the
   time from its first shred to complete_ts, and its data shreds by
   source.  complete_ts is the chainer block's completion stamp
   (fd_log_wallclock), which the stats do not track themselves.  Silent
   if the slot has no record (never seen, or displaced by a newer slot
   on the same table position). */

void
fd_repair_stats_print_slot( fd_repair_stats_t const * self,
                            ulong                     slot,
                            long                      complete_ts );

/* fd_repair_stats_query copies slot's record to *out and returns 1, or
   returns 0 if the slot has no record (never seen, or overwritten by a
   newer slot on the same table position).  Completion time lives on the
   chainer block (complete_ts), not here. */

int
fd_repair_stats_query( fd_repair_stats_t const * self,
                       ulong                     slot,
                       fd_repair_stats_slot_t *  out );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_rotor_fd_repair_stats_h */
