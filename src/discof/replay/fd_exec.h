#ifndef HEADER_fd_src_discof_replay_fd_exec_h
#define HEADER_fd_src_discof_replay_fd_exec_h

#include "../../flamenco/fd_flamenco_base.h"
#include "../../flamenco/leaders/fd_leaders_base.h"
#include "../../flamenco/runtime/context/fd_exec_epoch_ctx.h"
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
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );

  fd_stake_weight_msg_t * stake_weight_msg = fd_type_pun( stake_weight_msg_out );
  ulong                   stake_weight_idx = fd_stake_weights_by_node( &slot_ctx->slot_bank.epoch_stakes,
                                                                       stake_weight_msg->weights,
                                                                       runtime_spad );

  stake_weight_msg->epoch          = epoch;
  stake_weight_msg->staked_cnt     = stake_weight_idx;                           /* staked_cnt */
  stake_weight_msg->start_slot     = fd_epoch_slot0( &epoch_bank->epoch_schedule, stake_weight_msg_out[0] ); /* start_slot */
  stake_weight_msg->slot_cnt       = epoch_bank->epoch_schedule.slots_per_epoch; /* slot_cnt */
  stake_weight_msg->excluded_stake = 0UL;                                        /* excluded stake */

  return 5*sizeof(ulong) + (stake_weight_idx * sizeof(fd_stake_weight_t));
}

/* generate_replay_exec_epoch_msg formats memory at epoch_msg_out to be
   a fd_runtime_public_epoch_msg_t. On return, epoch_msg_out is well-
   formatted. */
static inline void
generate_replay_exec_epoch_msg( fd_exec_slot_ctx_t * slot_ctx,
                                fd_spad_t          * runtime_spad,
                                fd_wksp_t          * runtime_public_wksp,
                                fd_bank_hash_cmp_t * bank_hash_cmp,
                                fd_runtime_public_epoch_msg_t * epoch_msg_out ) {

  epoch_msg_out->features            = slot_ctx->epoch_ctx->features;
  epoch_msg_out->total_epoch_stake   = slot_ctx->epoch_ctx->total_epoch_stake;
  epoch_msg_out->epoch_schedule      = slot_ctx->epoch_ctx->epoch_bank.epoch_schedule;
  epoch_msg_out->rent                = slot_ctx->epoch_ctx->epoch_bank.rent;
  epoch_msg_out->slots_per_year      = slot_ctx->epoch_ctx->epoch_bank.slots_per_year;
  epoch_msg_out->bank_hash_cmp_gaddr = fd_wksp_gaddr_fast( runtime_public_wksp, fd_bank_hash_cmp_leave( bank_hash_cmp ) );

  if( FD_UNLIKELY( !epoch_msg_out->bank_hash_cmp_gaddr ) ) {
    FD_LOG_ERR(( "Failed to get gaddr for bank hash cmp" ));
  }

  ulong   stakes_encode_sz  = fd_stakes_delegation_size( &slot_ctx->epoch_ctx->epoch_bank.stakes ) + 128UL;
  uchar * stakes_encode_mem = fd_spad_alloc( runtime_spad,
                                             fd_stakes_delegation_align(),
                                             stakes_encode_sz );

  fd_bincode_encode_ctx_t encode = {
    .data    = stakes_encode_mem,
    .dataend = stakes_encode_mem + stakes_encode_sz
  };
  int err = fd_stakes_delegation_encode( &slot_ctx->epoch_ctx->epoch_bank.stakes, &encode );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Failed to encode stakes" ));
  }

  epoch_msg_out->stakes_encoded_gaddr = fd_wksp_gaddr_fast( runtime_public_wksp, stakes_encode_mem );;
  epoch_msg_out->stakes_encoded_sz    = stakes_encode_sz;
}

/* generate_replay_exec_slot_msg formats memory at slot_msg_out to be
   a fd_runtime_public_slot_msg_t. On return, slot_msg_out is well-
   formatted. */
static inline void
generate_replay_exec_slot_msg( fd_exec_slot_ctx_t * slot_ctx,
                               fd_spad_t          * runtime_spad,
                               fd_wksp_t          * runtime_public_wksp,
                               fd_runtime_public_slot_msg_t * slot_msg_out ) {

  slot_msg_out->slot                        = slot_ctx->slot_bank.slot;
  slot_msg_out->prev_lamports_per_signature = slot_ctx->prev_lamports_per_signature;
  slot_msg_out->fee_rate_governor           = slot_ctx->slot_bank.fee_rate_governor;
  slot_msg_out->enable_exec_recording       = slot_ctx->enable_exec_recording;

  /* Now encode the bhq */
  ulong   bhq_encode_sz  = fd_block_hash_queue_size( &slot_ctx->slot_bank.block_hash_queue ) + 128UL;
  uchar * bhq_encode_mem = fd_spad_alloc( runtime_spad,
                                          fd_block_hash_queue_align(),
                                          bhq_encode_sz );
  fd_bincode_encode_ctx_t encode = {
    .data    = bhq_encode_mem,
    .dataend = bhq_encode_mem + bhq_encode_sz
  };
  int err = fd_block_hash_queue_encode( &slot_ctx->slot_bank.block_hash_queue, &encode );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Failed to encode block hash queue" ));
  }
  slot_msg_out->block_hash_queue_encoded_gaddr = fd_wksp_gaddr_fast( runtime_public_wksp, bhq_encode_mem );
  slot_msg_out->block_hash_queue_encoded_sz    = bhq_encode_sz;

}

static inline void
generate_hash_bank_msg( ulong task_infos_gaddr,
                        ulong lt_hash_gaddr,
                        ulong start_idx,
                        ulong end_idx,
                        fd_runtime_public_hash_bank_msg_t * hash_msg_out ) {
  hash_msg_out->task_infos_gaddr = task_infos_gaddr;
  hash_msg_out->lthash_gaddr     = lt_hash_gaddr;
  hash_msg_out->start_idx        = start_idx;
  hash_msg_out->end_idx          = end_idx;
}

static inline void
generate_bpf_scan_msg( ulong start_idx,
                       ulong end_idx,
                       ulong recs_gaddr,
                       ulong is_bpf_gaddr,
                       fd_runtime_public_bpf_scan_msg_t * scan_msg_out ) {
  scan_msg_out->start_idx       = start_idx;
  scan_msg_out->end_idx         = end_idx;
  scan_msg_out->recs_gaddr      = recs_gaddr;
  scan_msg_out->is_bpf_gaddr    = is_bpf_gaddr;
}

/* Execution tracking helpers */

struct fd_slice_exec {
  uchar * buf;    /* Pointer to the memory region sized for max sz of a block. */
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
                     ulong slice_sz,
                     int   last_batch );

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
