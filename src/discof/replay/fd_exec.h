#ifndef HEADER_fd_src_discof_replay_fd_exec_h
#define HEADER_fd_src_discof_replay_fd_exec_h

#include "../../flamenco/fd_flamenco_base.h"
#include "../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/stakes/fd_stakes.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../discof/restore/utils/fd_ssmsg.h"

/* FIXME: SIMD-0180 - set the correct epochs */
#define FD_SIMD0180_ACTIVE_EPOCH_TESTNET (5000)
#define FD_SIMD0180_ACTIVE_EPOCH_MAINNET (5000)

/* Replay tile msg link formatting. The following take a pointer into
   a dcache region and formats it as a specific message type. */

static inline ulong
generate_stake_weight_msg( fd_exec_slot_ctx_t *              slot_ctx,
                           ulong                             epoch,
                           fd_vote_states_t const *          vote_states,
                           ulong *                           stake_weight_msg_out ) {
  fd_stake_weight_msg_t *     stake_weight_msg = (fd_stake_weight_msg_t *)fd_type_pun( stake_weight_msg_out );
  fd_vote_stake_weight_t *    stake_weights    = stake_weight_msg->weights;
  ulong                       staked_cnt       = fd_stake_weights_by_node( vote_states, stake_weights );
  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( slot_ctx->bank );

  stake_weight_msg->epoch          = epoch;
  stake_weight_msg->staked_cnt     = staked_cnt;
  stake_weight_msg->start_slot     = fd_epoch_slot0( epoch_schedule, stake_weight_msg_out[0] );
  stake_weight_msg->slot_cnt       = epoch_schedule->slots_per_epoch;
  stake_weight_msg->excluded_stake = 0UL;
  stake_weight_msg->vote_keyed_lsched = (ulong)fd_runtime_should_use_vote_keyed_leader_schedule( slot_ctx->bank );

  return fd_stake_weight_msg_sz( staked_cnt );
}

static inline ulong
generate_stake_weight_msg_manifest( ulong                                       epoch,
                                    fd_epoch_schedule_t const *                 epoch_schedule,
                                    fd_snapshot_manifest_epoch_stakes_t const * epoch_stakes,
                                    ulong *                                     stake_weight_msg_out ) {
  fd_stake_weight_msg_t *  stake_weight_msg = (fd_stake_weight_msg_t *)fd_type_pun( stake_weight_msg_out );
  fd_vote_stake_weight_t * stake_weights    = stake_weight_msg->weights;

  stake_weight_msg->epoch             = epoch;
  stake_weight_msg->staked_cnt        = epoch_stakes->vote_stakes_len;
  stake_weight_msg->start_slot        = fd_epoch_slot0( epoch_schedule, epoch );
  stake_weight_msg->slot_cnt          = epoch_schedule->slots_per_epoch;
  stake_weight_msg->excluded_stake    = 0UL;
  stake_weight_msg->vote_keyed_lsched = 1UL;

  /* FIXME: SIMD-0180 - hack to (de)activate in testnet vs mainnet.
     This code can be removed once the feature is active. */
  {
    if(    ( 1==epoch_schedule->warmup && epoch<FD_SIMD0180_ACTIVE_EPOCH_TESTNET )
        || ( 0==epoch_schedule->warmup && epoch<FD_SIMD0180_ACTIVE_EPOCH_MAINNET ) ) {
      stake_weight_msg->vote_keyed_lsched = 0UL;
    }
  }

  /* epoch_stakes from manifest are already filtered (stake>0), but not sorted */
  for( ulong i=0UL; i<epoch_stakes->vote_stakes_len; i++ ) {
    stake_weights[ i ].stake = epoch_stakes->vote_stakes[ i ].stake;
    memcpy( stake_weights[ i ].id_key.uc, epoch_stakes->vote_stakes[ i ].identity, sizeof(fd_pubkey_t) );
    memcpy( stake_weights[ i ].vote_key.uc, epoch_stakes->vote_stakes[ i ].vote, sizeof(fd_pubkey_t) );
  }
  sort_vote_weights_by_stake_vote_inplace( stake_weights, epoch_stakes->vote_stakes_len);

  return fd_stake_weight_msg_sz( epoch_stakes->vote_stakes_len );
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
