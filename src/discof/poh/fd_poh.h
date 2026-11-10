#ifndef HEADER_fd_src_discof_poh_fd_poh_h
#define HEADER_fd_src_discof_poh_fd_poh_h

#include "../../disco/pack/fd_pack.h"

/* The maximum number of microblocks pack may put in a slot.  This is
   not consensus critical; Alpenglow has one tick per block, so there
   is no hash budget bounding microblocks and pack is given this fixed
   budget instead. */
#define FD_POH_ALPENGLOW_MAX_MICROBLOCKS_PER_SLOT (131072UL)

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
