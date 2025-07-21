#include "fd_sysvar_recent_hashes.h"
#include "../fd_acc_mgr.h"
#include "fd_sysvar.h"
#include "../fd_runtime.h"
#include "../fd_system_ids.h"

/* Skips fd_types encoding preflight checks and directly serializes the
   blockhash queue into a buffer representing account data for the
   recent blockhashes sysvar. */

static void
encode_rbh_from_blockhash_queue( fd_exec_slot_ctx_t * slot_ctx,
                                 uchar                out_mem[ FD_SYSVAR_RECENT_HASHES_BINCODE_SZ ] ) {
  fd_blockhashes_t const * bhq = fd_bank_block_hash_queue_query( slot_ctx->bank );

  ulong queue_sz = fd_blockhash_deq_cnt( bhq->d.deque );
  ulong out_max  = fd_ulong_min( queue_sz, FD_SYSVAR_RECENT_HASHES_CAP );

  uchar * enc = out_mem;
  fd_memcpy( enc, &out_max, sizeof(ulong) );

  enc += sizeof(ulong);

  /* Iterate over blockhash queue and encode the recent blockhashes.
     We can do direct memcpying and avoid redundant checks from fd_types
     encoders since the enc buffer is already sized out to the
     worst-case bound. */
  ulong out_idx = 0UL;
  for( fd_blockhash_deq_iter_t iter = fd_blockhash_deq_iter_init_rev( bhq->d.deque );
       out_idx<FD_SYSVAR_RECENT_HASHES_CAP &&
          !fd_blockhash_deq_iter_done_rev( bhq->d.deque, iter );
       out_idx++,   iter = fd_blockhash_deq_iter_prev( bhq->d.deque, iter ) ) {
    fd_blockhash_info_t const * n = fd_blockhash_deq_iter_ele_const( bhq->d.deque, iter );
    fd_memcpy( enc, n->hash.uc, 32 );
    FD_STORE( ulong, enc+32, n->fee_calculator.lamports_per_signature );
    enc += 40;
  }
}

void
fd_sysvar_recent_hashes_init( fd_exec_slot_ctx_t * slot_ctx,
                              fd_spad_t *          runtime_spad ) {

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  if( fd_bank_slot_get( slot_ctx->bank ) != 0 ) {
    return;
  }

  ulong   sz  = FD_SYSVAR_RECENT_HASHES_BINCODE_SZ;
  uchar * enc = fd_spad_alloc( runtime_spad, FD_SPAD_ALIGN, sz );
  fd_memset( enc, 0, sz );
  encode_rbh_from_blockhash_queue( slot_ctx, enc );
  fd_sysvar_set( slot_ctx->bank, slot_ctx->funk, slot_ctx->funk_txn, &fd_sysvar_owner_id, &fd_sysvar_recent_block_hashes_id, enc, sz, fd_bank_slot_get( slot_ctx->bank ) );

  } FD_SPAD_FRAME_END;
}

// https://github.com/anza-xyz/agave/blob/e8750ba574d9ac7b72e944bc1227dc7372e3a490/accounts-db/src/blockhash_queue.rs#L113
static void
register_blockhash( fd_exec_slot_ctx_t * slot_ctx,
                    fd_hash_t const *    hash ) {
  fd_blockhashes_t * bhq = fd_bank_block_hash_queue_modify( slot_ctx->bank );
  fd_blockhash_info_t * bh = fd_blockhashes_push_new( bhq, hash );
  bh->fee_calculator = (fd_fee_calculator_t){
    .lamports_per_signature = fd_bank_lamports_per_signature_get( slot_ctx->bank )
  };
}

/* This implementation is more consistent with Agave's bank implementation for updating the block hashes sysvar:
   1. Update the block hash queue with the latest poh
   2. Take the first 150 blockhashes from the queue (or fewer if there are)
   3. Manually serialize the recent blockhashes
   4. Set the sysvar account with the new data */
void
fd_sysvar_recent_hashes_update( fd_exec_slot_ctx_t * slot_ctx, fd_spad_t * runtime_spad ) {
  FD_SPAD_FRAME_BEGIN( runtime_spad ) {
  /* Update the blockhash queue */

  register_blockhash( slot_ctx, fd_bank_poh_query( slot_ctx->bank ) );

  /* Derive the new sysvar recent blockhashes from the blockhash queue */
  ulong   sz        = FD_SYSVAR_RECENT_HASHES_BINCODE_SZ;
  uchar * enc       = fd_spad_alloc( runtime_spad, FD_SPAD_ALIGN, sz );
  uchar * enc_start = enc;
  fd_memset( enc, 0, sz );

  /* Encode the recent blockhashes */
  encode_rbh_from_blockhash_queue( slot_ctx, enc );

  /* Set the sysvar from the encoded data */
  fd_sysvar_set( slot_ctx->bank,
                 slot_ctx->funk,
                 slot_ctx->funk_txn,
                 &fd_sysvar_owner_id,
                 &fd_sysvar_recent_block_hashes_id,
                 enc_start,
                 sz,
                 fd_bank_slot_get( slot_ctx->bank ) );
  } FD_SPAD_FRAME_END;
}

fd_recent_block_hashes_t *
fd_sysvar_recent_hashes_read( fd_funk_t * funk, fd_funk_txn_t * funk_txn, fd_spad_t * spad ) {
  FD_TXN_ACCOUNT_DECL( acc );
  int err = fd_txn_account_init_from_funk_readonly( acc, &fd_sysvar_recent_block_hashes_id, funk, funk_txn );
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) )
    return NULL;

  fd_bincode_decode_ctx_t ctx = {
    .data    = acc->vt->get_data( acc ),
    .dataend = acc->vt->get_data( acc ) + acc->vt->get_data_len( acc ),
  };

  /* This check is needed as a quirk of the fuzzer. If a sysvar account
     exists in the accounts database, but doesn't have any lamports,
     this means that the account does not exist. This wouldn't happen
     in a real execution environment. */
  if( FD_UNLIKELY( acc->vt->get_lamports( acc ) == 0UL ) ) {
    return NULL;
  }

  ulong total_sz = 0;
  err = fd_recent_block_hashes_decode_footprint( &ctx, &total_sz );
  if( FD_UNLIKELY( err ) ) {
    return NULL;
  }

  uchar * mem = fd_spad_alloc( spad, fd_recent_block_hashes_align(), total_sz );
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_CRIT(( "fd_spad_alloc failed" ));
  }

  /* This would never happen in a real cluster, this is a workaround
     for fuzz-generated cases where sysvar accounts are not funded. */
  if( FD_UNLIKELY( acc->vt->get_lamports( acc ) == 0 ) ) {
    return NULL;
  }

  return fd_recent_block_hashes_decode( mem, &ctx );
}
