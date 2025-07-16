#ifndef HEADER_fd_src_discof_replay_fd_exec_h
#define HEADER_fd_src_discof_replay_fd_exec_h

#include "../../flamenco/fd_flamenco_base.h"
#include "../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../flamenco/runtime/fd_runtime_public.h"
#include "../../flamenco/stakes/fd_stakes.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"

/* Replay tile msg link formatting. The following take a pointer into
   a dcache region and formats it as a specific message type. */

static inline ulong
generate_stake_weight_msg( fd_exec_slot_ctx_t * slot_ctx,
                           fd_spad_t          * runtime_spad,
                           ulong                epoch,
                           ulong              * stake_weight_msg_out ) {

  fd_stake_weight_msg_t *           stake_weight_msg = (fd_stake_weight_msg_t *)fd_type_pun( stake_weight_msg_out );
  fd_stake_weight_t     *           stake_weights    = (fd_stake_weight_t *)&stake_weight_msg_out[5];
  fd_vote_accounts_global_t const * vote_accounts    = fd_bank_epoch_stakes_locking_query( slot_ctx->bank );
  ulong                             stake_weight_idx = fd_stake_weights_by_node( vote_accounts,
                                                                           stake_weights,
                                                                           runtime_spad );
  fd_bank_epoch_stakes_end_locking_query( slot_ctx->bank );

  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( slot_ctx->bank );

  stake_weight_msg->epoch          = epoch;
  stake_weight_msg->staked_cnt     = stake_weight_idx;                           /* staked_cnt */
  stake_weight_msg->start_slot     = fd_epoch_slot0( epoch_schedule, stake_weight_msg_out[0] ); /* start_slot */
  stake_weight_msg->slot_cnt       = epoch_schedule->slots_per_epoch; /* slot_cnt */
  stake_weight_msg->excluded_stake = 0UL;                                        /* excluded stake */

  return 5*sizeof(ulong) + (stake_weight_idx * sizeof(fd_stake_weight_t));
}

static inline void
generate_hash_bank_msg( ulong                               task_infos_gaddr,
                        ulong                               lt_hash_gaddr,
                        ulong                               start_idx,
                        ulong                               end_idx,
                        ulong                               curr_slot,
                        fd_runtime_public_hash_bank_msg_t * hash_msg_out ) {
  hash_msg_out->task_infos_gaddr = task_infos_gaddr;
  hash_msg_out->lthash_gaddr     = lt_hash_gaddr;
  hash_msg_out->start_idx        = start_idx;
  hash_msg_out->end_idx          = end_idx;
  hash_msg_out->slot             = curr_slot;
}

/* Execution tracking helpers */

struct fd_slice_exec {
  uchar * buf;       /* Pointer to the memory region sized for max sz of a block. */
  ulong   wmark;     /* Offset into slice where previous bytes have been executed, and following bytes have not. Will be on a transaction or microblock boundary. */
  ulong   sz;        /* Total bytes this slice occupies in mbatch memory. New slices are placed at this offset */
  ulong   mblks_rem; /* Number of microblocks remaining in the current batch iteration. */
  ulong   txns_rem;  /* Number of txns remaining in current microblock iteration. */

  ulong   last_mblk_off; /* Stored offset to the last microblock header seen. Updated during block execution. */
  int     last_batch;    /* Signifies last batch execution. */
};
typedef struct fd_slice_exec fd_slice_exec_t;

/* Note the current usage of slice_exec is that it is embedded directly
   in replay_tile_ctx_t, so there's no need for (_new) currently. */

fd_slice_exec_t *
fd_slice_exec_join( void * slmem );

void
fd_slice_exec_txn_parse( fd_slice_exec_t * slice_exec_ctx,
                         fd_txn_p_t      * txn_p_out );

void
fd_slice_exec_microblock_parse( fd_slice_exec_t * slice_exec_ctx );

void
fd_slice_exec_reset( fd_slice_exec_t * slice_exec_ctx );

void
fd_slice_exec_begin( fd_slice_exec_t * slice_exec_ctx,
                     ulong             slice_sz,
                     int               last_batch );

static inline int
fd_slice_exec_txn_ready( fd_slice_exec_t * slice_exec_ctx ) {
  return slice_exec_ctx->txns_rem > 0UL;
}

static inline int
fd_slice_exec_microblock_ready( fd_slice_exec_t * slice_exec_ctx ) {
  return slice_exec_ctx->txns_rem == 0 && slice_exec_ctx->mblks_rem > 0UL;
}

static inline int
fd_slice_exec_slice_ready( fd_slice_exec_t * slice_exec_ctx ) {
  return slice_exec_ctx->txns_rem == 0 && slice_exec_ctx->mblks_rem == 0UL;
}

static inline int
fd_slice_exec_slot_complete( fd_slice_exec_t * slice_exec_ctx ) {
  return slice_exec_ctx->last_batch && slice_exec_ctx->mblks_rem == 0 && slice_exec_ctx->txns_rem == 0;
}

#endif /* HEADER_fd_src_discof_replay_fd_exec_h */
