#ifndef HEADER_fd_src_discof_replay_fd_exec_h
#define HEADER_fd_src_discof_replay_fd_exec_h

#include "../../flamenco/fd_flamenco_base.h"
#include "../../flamenco/stakes/fd_stakes.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../discof/restore/utils/fd_ssmsg.h"

/* FIXME: SIMD-0180 - set the correct epochs */
#define FD_SIMD0180_ACTIVE_EPOCH_TESTNET (829)
#define FD_SIMD0180_ACTIVE_EPOCH_MAINNET (841)

/* Replay tile msg link formatting. The following take a pointer into
   a dcache region and formats it as a specific message type. */

static inline ulong
generate_stake_weight_msg( ulong                       epoch,
                           fd_epoch_schedule_t const * epoch_schedule,
                           fd_vote_states_t const *    epoch_stakes,
                           ulong *                     stake_weight_msg_out ) {
  fd_stake_weight_msg_t *  stake_weight_msg = (fd_stake_weight_msg_t *)fd_type_pun( stake_weight_msg_out );
  fd_vote_stake_weight_t * stake_weights    = stake_weight_msg->weights;

  stake_weight_msg->epoch             = epoch;
  stake_weight_msg->start_slot        = fd_epoch_slot0( epoch_schedule, epoch );
  stake_weight_msg->slot_cnt          = epoch_schedule->slots_per_epoch;
  stake_weight_msg->excluded_stake    = 0UL;
  stake_weight_msg->vote_keyed_lsched = 1UL;

  /* FIXME: SIMD-0180 - hack to (de)activate in testnet vs mainnet.
     This code can be removed once the feature is active. */
  if( (1==epoch_schedule->warmup && epoch<FD_SIMD0180_ACTIVE_EPOCH_TESTNET) ||
      (0==epoch_schedule->warmup && epoch<FD_SIMD0180_ACTIVE_EPOCH_MAINNET) ) {
    stake_weight_msg->vote_keyed_lsched = 0UL;
  }

  /* epoch_stakes from manifest are already filtered (stake>0), but not sorted */
  fd_vote_states_iter_t iter_[1];
  ulong idx = 0UL;
  for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( iter_, epoch_stakes ); !fd_vote_states_iter_done( iter ); fd_vote_states_iter_next( iter ) ) {
    fd_vote_state_ele_t * vote_state = fd_vote_states_iter_ele( iter );
    if( FD_UNLIKELY( !vote_state->stake ) ) continue;

    stake_weights[ idx ].stake = vote_state->stake;
    memcpy( stake_weights[ idx ].id_key.uc, &vote_state->node_account, sizeof(fd_pubkey_t) );
    memcpy( stake_weights[ idx ].vote_key.uc, &vote_state->vote_account, sizeof(fd_pubkey_t) );
    idx++;
  }
  stake_weight_msg->staked_cnt = idx;
  sort_vote_weights_by_stake_vote_inplace( stake_weights, idx );

  return fd_stake_weight_msg_sz( idx );
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

static inline void
fd_slice_exec_skip_slice( fd_slice_exec_t * slice_exec_ctx ) {
  slice_exec_ctx->mblks_rem = 0UL;
  slice_exec_ctx->txns_rem  = 0UL;
}

static inline int
fd_slice_exec_txn_ready( fd_slice_exec_t const * slice_exec_ctx ) {
  return slice_exec_ctx->txns_rem > 0UL;
}

static inline int
fd_slice_exec_microblock_ready( fd_slice_exec_t const * slice_exec_ctx ) {
  return slice_exec_ctx->txns_rem == 0 && slice_exec_ctx->mblks_rem > 0UL;
}

static inline int
fd_slice_exec_slice_ready( fd_slice_exec_t const * slice_exec_ctx ) {
  return slice_exec_ctx->txns_rem == 0 && slice_exec_ctx->mblks_rem == 0UL;
}

static inline int
fd_slice_exec_slot_complete( fd_slice_exec_t const * slice_exec_ctx ) {
  return slice_exec_ctx->last_batch && slice_exec_ctx->mblks_rem == 0 && slice_exec_ctx->txns_rem == 0;
}

/* Exec tile msg link formatting. The following take a pointer into
   a dcache region and formats it as a specific message type. */

/* definition of the public/readable workspace */
#define EXEC_NEW_TXN_SIG         (0x777777UL)

#define FD_WRITER_BOOT_SIG       (0xAABB0011UL)
#define FD_WRITER_SLOT_SIG       (0xBBBB1122UL)
#define FD_WRITER_TXN_SIG        (0xBBCC2233UL)

#define FD_EXEC_STATE_NOT_BOOTED (0xFFFFFFFFUL)
#define FD_EXEC_STATE_BOOTED     (1<<1UL      )

#define FD_EXEC_ID_SENTINEL      (UINT_MAX    )

/**********************************************************************/

/* fd_exec_txn_msg_t is the message that is sent from the replay tile to
   the exec tile.  This represents all of the information that is needed
   to identify and execute a transaction against a bank.  An idx to the
   bank in the bank pool must be sent over because the key of the bank
   will change as FEC sets are processed. */

struct fd_exec_txn_msg {
  ulong      bank_idx;
  fd_txn_p_t txn;
};
typedef struct fd_exec_txn_msg fd_exec_txn_msg_t;

/* fd_exec_writer_boot_msg_t is the message sent from the exec tile to
   the writer tile on boot.  This message contains the offset of the
   txn_ctx in the tile's exec spad. */

struct fd_exec_writer_boot_msg {
  uint txn_ctx_offset;
};
typedef struct fd_exec_writer_boot_msg fd_exec_writer_boot_msg_t;
FD_STATIC_ASSERT( sizeof(fd_exec_writer_boot_msg_t)<=FD_EXEC_WRITER_MTU, exec_writer_msg_mtu );

/* fd_exec_writer_txn_msg is the message sent from the exec tile to the
   writer tile after a transaction has been executed.  This message
   contains the id of the exec tile that executed the transaction. */

struct fd_exec_writer_txn_msg {
  uchar exec_tile_id;
};
typedef struct fd_exec_writer_txn_msg fd_exec_writer_txn_msg_t;
FD_STATIC_ASSERT( sizeof(fd_exec_writer_txn_msg_t)<=FD_EXEC_WRITER_MTU, exec_writer_msg_mtu );

/* Writer->Replay message APIs ****************************************/

/* fd_writer_replay_txn_finalized_msg_t is the message sent from
   writer tile to replay tile, notifying the replay tile that a txn has
   been finalized. */

struct __attribute__((packed)) fd_writer_replay_txn_finalized_msg {
  int exec_tile_id;
};
typedef struct fd_writer_replay_txn_finalized_msg fd_writer_replay_txn_finalized_msg_t;

#endif /* HEADER_fd_src_discof_replay_fd_exec_h */
