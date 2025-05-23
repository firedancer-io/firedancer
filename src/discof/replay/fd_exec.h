#ifndef HEADER_fd_src_discof_replay_fd_exec_h
#define HEADER_fd_src_discof_replay_fd_exec_h

#include "../../flamenco/fd_flamenco_base.h"
#include "../../flamenco/runtime/context/fd_exec_epoch_ctx.h"
#include "../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../flamenco/runtime/fd_runtime_public.h"
// TODO: move to exec.h
struct fd_replay_txn_ctx {
  fd_wksp_t         * spad_wksp;
  ulong               spad_laddr;
  fd_exec_txn_ctx_t * txn_ctx;
};
typedef struct fd_replay_txn_ctx fd_replay_txn_ctx_t;


/* generate_replay_exec_epoch_msg formats memory at epoch_msg_out to be
   a fd_runtime_public_epoch_msg_t. On return, epoch_msg_out is
   guaranteed to be ... */
void
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

  ulong   stakes_encode_sz  = fd_stakes_size( &slot_ctx->epoch_ctx->epoch_bank.stakes ) + 128UL;
  uchar * stakes_encode_mem = fd_spad_alloc( runtime_spad,
                                             fd_stakes_align(),
                                             stakes_encode_sz );

  fd_bincode_encode_ctx_t encode = {
    .data    = stakes_encode_mem,
    .dataend = stakes_encode_mem + stakes_encode_sz
  };
  int err = fd_stakes_encode( &slot_ctx->epoch_ctx->epoch_bank.stakes, &encode );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Failed to encode stakes" ));
  }

  epoch_msg_out->stakes_encoded_gaddr = fd_wksp_gaddr_fast( runtime_public_wksp, stakes_encode_mem );;
  epoch_msg_out->stakes_encoded_sz    = stakes_encode_sz;
}

/* generate_replay_exec_slot_msg formats memory at slot_msg_out to be
   a fd_runtime_public_slot_msg_t. On return, slot_msg_out is
   guaranteed to be ... */
void
generate_replay_exec_slot_msg( fd_exec_slot_ctx_t * slot_ctx,
                               fd_spad_t          * runtime_spad,
                               fd_wksp_t          * runtime_public_wksp,
                               fd_runtime_public_slot_msg_t * slot_msg_out ) {

  slot_msg_out->slot                        = slot_ctx->slot_bank.slot;
  slot_msg_out->prev_lamports_per_signature = slot_ctx->prev_lamports_per_signature;
  slot_msg_out->fee_rate_governor           = slot_ctx->slot_bank.fee_rate_governor;
  slot_msg_out->enable_exec_recording       = slot_ctx->enable_exec_recording;

  /* Save the gaddr of the sysvar cache */
  slot_msg_out->sysvar_cache_gaddr = fd_wksp_gaddr_fast( runtime_public_wksp, slot_ctx->sysvar_cache );

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



#endif /* HEADER_fd_src_discof_replay_fd_exec_h */