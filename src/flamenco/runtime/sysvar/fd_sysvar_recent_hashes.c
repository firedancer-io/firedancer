#include "fd_sysvar_recent_hashes.h"
#include "../fd_runtime_account.h"
#include "fd_sysvar.h"
#include "../context/fd_exec_slot_ctx.h"
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
fd_sysvar_recent_hashes_init( fd_exec_slot_ctx_t * slot_ctx ) {
  uchar enc[ FD_SYSVAR_RECENT_HASHES_BINCODE_SZ ] = {0};
  encode_rbh_from_blockhash_queue( slot_ctx, enc );
  fd_sysvar_account_update( slot_ctx, &fd_sysvar_recent_block_hashes_id, enc, FD_SYSVAR_RECENT_HASHES_BINCODE_SZ );
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
fd_sysvar_recent_hashes_update( fd_exec_slot_ctx_t * slot_ctx ) {
  register_blockhash( slot_ctx, fd_bank_poh_query( slot_ctx->bank ) );

  uchar enc[ FD_SYSVAR_RECENT_HASHES_BINCODE_SZ ] = {0};
  encode_rbh_from_blockhash_queue( slot_ctx, enc );
  fd_sysvar_account_update( slot_ctx, &fd_sysvar_recent_block_hashes_id, enc, sizeof(enc) );
}

fd_recent_block_hashes_t *
fd_sysvar_recent_hashes_read( fd_accdb_client_t * accdb,
                              fd_spad_t *         spad ) {
  int db_err = FD_ACCDB_READ_BEGIN( accdb, &fd_sysvar_recent_block_hashes_id, rec ) {
    return fd_bincode_decode_spad(
        recent_block_hashes,
        spad,
        fd_accdb_ref_data_const( rec ),
        fd_accdb_ref_data_sz   ( rec ),
        NULL );
  }
  FD_ACCDB_READ_END;
  if( FD_UNLIKELY( db_err!=FD_ACCDB_ERR_KEY ) ) FD_LOG_ERR(( "Failed to read sysvar recent block hashes: database error (%i-%s)", db_err, fd_accdb_strerror( db_err ) ));
  return NULL;
}
