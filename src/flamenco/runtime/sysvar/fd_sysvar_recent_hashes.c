#include "fd_sysvar_recent_hashes.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../fd_system_ids.h"
#include "fd_sysvar_cache.h"

/* Skips fd_types encoding preflight checks and directly serializes the
   blockhash queue into a buffer representing account data for the
   recent blockhashes sysvar. */

void
fd_sysvar_recent_hashes_encode( fd_blockhashes_t const * bhq,
                                uchar                    out_mem[ FD_SYSVAR_RECENT_HASHES_BINCODE_SZ ] ) {
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

  ulong sz_max = 0UL;
  uchar * data = fd_sysvar_cache_data_modify_prepare( slot_ctx, &fd_sysvar_recent_block_hashes_id, NULL, &sz_max );
  if( FD_UNLIKELY( !data ) ) FD_LOG_ERR(( "fd_sysvar_cache_data_modify_prepare(recent_block_hashes) failed" ));
  FD_TEST( sz_max>=FD_SYSVAR_RECENT_HASHES_BINCODE_SZ );
  fd_memset( data, 0, FD_SYSVAR_RECENT_HASHES_BINCODE_SZ );
  fd_sysvar_cache_data_modify_commit( slot_ctx, &fd_sysvar_recent_block_hashes_id, FD_SYSVAR_RECENT_HASHES_BINCODE_SZ );

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

void
fd_sysvar_recent_hashes_update( fd_exec_slot_ctx_t * slot_ctx ) {

  /* Add PoH hash to bank blockhash queue */
  register_blockhash( slot_ctx, fd_bank_poh_query( slot_ctx->bank ) );

  /* Update sysvar account with latest 150 hashes */
  fd_sysvar_cache_t * sysvar_cache = fd_bank_sysvar_cache_modify( slot_ctx->bank );
  if( FD_UNLIKELY( !fd_sysvar_recent_hashes_is_valid( sysvar_cache ) ) ) {
    fd_sysvar_recent_hashes_init( slot_ctx );
  }
  ulong sz_max = 0UL;
  uchar * data = fd_sysvar_cache_data_modify_prepare( slot_ctx, &fd_sysvar_recent_block_hashes_id, NULL, &sz_max );
  if( FD_UNLIKELY( !data ) ) FD_LOG_ERR(( "fd_sysvar_cache_data_modify_prepare(recent_block_hashes) failed" ));
  FD_TEST( sz_max>=FD_SYSVAR_RECENT_HASHES_BINCODE_SZ );
  fd_sysvar_recent_hashes_encode( fd_bank_block_hash_queue_query( slot_ctx->bank ), data );
  fd_sysvar_cache_data_modify_commit( slot_ctx, &fd_sysvar_recent_block_hashes_id, FD_SYSVAR_RECENT_HASHES_BINCODE_SZ );
}
