#ifndef HEADER_fd_src_discof_poh_fd_poh_h
#define HEADER_fd_src_discof_poh_fd_poh_h

#include "../../disco/pack/fd_pack.h"

/* The maximum number of microblocks pack may put in a slot: one per
   non-tick hash position (one per tick in low power mode), less the
   phantom microblock PoH reserves for the done_packing message.  This
   is not consensus critical; PoH reserves this many hashes so it never
   runs out of positions to mixin microblocks still coming from pack.
   Pack shrinks its live bound with the time left in the slot (see
   compute_dynamic_max_microblocks in fd_pack_tile.c), so the reserve
   is gone by the end of the slot rather than hashed through. */

/* Alpenglow has one tick per block, so the hash budget does not bound
   microblocks; pack is given this fixed budget instead. */
#define FD_POH_ALPENGLOW_MAX_MICROBLOCKS_PER_SLOT (131072UL)

FD_FN_CONST static inline ulong
fd_poh_max_microblocks_per_slot( ulong ticks_per_slot,
                                 ulong hashcnt_per_tick ) {
  return ticks_per_slot*(fd_ulong_max( hashcnt_per_tick, 2UL )-1UL)-1UL; /* low power genesis encodes hashes_per_tick as 0 or 1 */
}

/* When we are hashing in the background in case a prior leader skips
   their slot, we need to store the result of each tick hash so we can
   publish them when we become leader.  The network requires at least
   one leader slot to publish in each epoch for the leader schedule to
   generate, so in the worst case we might need two full epochs of slots
   to store the hashes.  (Eg, if epoch T only had a published slot in
   position 0 and epoch T+1 only had a published slot right at the end).

   There is a tighter bound: the block data limit at the 200ms slot
   params is FD_PACK_MAX_DATA_PER_BLOCK, or 7,810,880 bytes per slot.
   At 48 bytes per tick, it is not possible to publish a slot that skips
   162,727 or more prior slots. */
#define MAX_SKIPPED_TICKS (1UL+(FD_PACK_MAX_DATA_PER_BLOCK/48UL))

/* Per-transaction lifecycle timing for a leader block, captured by poh
   in mix order for telemetry purposes.  The records are stored in a
   shared txn_timing[] array. */

struct fd_leader_txn_timing_rec {
  long received_ns;
  long dispatched_ticks;
  long replayed_ticks;
  long poh_mixed_ticks;
};

typedef struct fd_leader_txn_timing_rec fd_leader_txn_timing_rec_t;

FD_STATIC_ASSERT( sizeof(fd_leader_txn_timing_rec_t)==32UL, leader_txn_timing_rec );

/* The ldr_tt object holds FD_LEADER_TXN_TIMING_TABLE_CNT tables back to
   back, each with room for config->limits.max_txn_per_slot records, so
   the table stride is a runtime value: index them with
   fd_leader_txn_timing_table(). */

struct fd_leader_txn_timing_table {
  ulong slot;
  ulong cnt;
  fd_leader_txn_timing_rec_t rec[]; /* max_txn_per_slot */
};

typedef struct fd_leader_txn_timing_table fd_leader_txn_timing_table_t;

#define FD_LEADER_TXN_TIMING_TABLE_CNT (2UL)

FD_FN_CONST static inline ulong
fd_leader_txn_timing_table_footprint( ulong max_txn_per_slot ) {
  return sizeof(fd_leader_txn_timing_table_t)+max_txn_per_slot*sizeof(fd_leader_txn_timing_rec_t);
}

FD_FN_CONST static inline fd_leader_txn_timing_table_t const *
fd_leader_txn_timing_table_const( fd_leader_txn_timing_table_t const * tables,
                                  ulong                                idx,
                                  ulong                                max_txn_per_slot ) {
  return (fd_leader_txn_timing_table_t const *)( (uchar const *)tables + idx*fd_leader_txn_timing_table_footprint( max_txn_per_slot ) );
}

FD_FN_CONST static inline fd_leader_txn_timing_table_t *
fd_leader_txn_timing_table( fd_leader_txn_timing_table_t * tables,
                            ulong                          idx,
                            ulong                          max_txn_per_slot ) {
  return (fd_leader_txn_timing_table_t *)fd_leader_txn_timing_table_const( tables, idx, max_txn_per_slot );
}

struct fd_poh_leader_slot_ended {
  int   completed;
  ulong slot;
  uchar blockhash[ 32UL ];

  ulong timing_table_idx;

  ulong microblock_count;
  ulong pack_block_cost;
  ulong pack_data_bytes;
  ulong bundle_txn_count;
  int   pack_end_reason;
  long  pack_start_ns;
  long  pack_end_ns;
};

typedef struct fd_poh_leader_slot_ended fd_poh_leader_slot_ended_t;

struct fd_poh_out_private {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
};

typedef struct fd_poh_out_private fd_poh_out_t;

#endif /* HEADER_fd_src_discof_poh_fd_poh_h */
