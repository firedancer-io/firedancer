#include "fd_sysvar_slot_hashes.h"
#include "fd_sysvar_cache.h"
#include "../fd_system_ids.h"
#include "../context/fd_exec_slot_ctx.h"

void
fd_sysvar_slot_hashes_init( fd_exec_slot_ctx_t * slot_ctx ) {
  ulong sz_max;
  uchar * data = fd_sysvar_cache_data_modify_prepare( slot_ctx, &fd_sysvar_slot_hashes_id, NULL, &sz_max );
  FD_TEST( sz_max>=FD_SYSVAR_SLOT_HASHES_BINCODE_SZ );
  fd_memset( data, 0, FD_SYSVAR_SLOT_HASHES_BINCODE_SZ );
  fd_sysvar_cache_data_modify_commit( slot_ctx, &fd_sysvar_slot_hashes_id, FD_SYSVAR_SLOT_HASHES_BINCODE_SZ );
}

/* https://github.com/anza-xyz/agave/blob/v2.3.2/runtime/src/bank.rs#L2290 */

void
fd_sysvar_slot_hashes_update( fd_exec_slot_ctx_t * slot_ctx ) {

  /* Create an empty sysvar account if it doesn't exist
     https://github.com/anza-xyz/agave/blob/v2.3.2/runtime/src/bank.rs#L2295 */

  fd_sysvar_cache_t * sysvar_cache = fd_bank_sysvar_cache_modify( slot_ctx->bank );
  if( FD_UNLIKELY( !fd_sysvar_slot_hashes_is_valid( sysvar_cache ) ) ) {
    fd_sysvar_slot_hashes_init( slot_ctx );
  }

  /* Update an existing sysvar account, but abort if deserialization of
     that existing account failed.
     https://github.com/anza-xyz/agave/blob/v2.3.2/runtime/src/bank.rs#L2294 */

  fd_slot_hash_t * hashes = fd_sysvar_slot_hashes_join( slot_ctx );
  if( FD_UNLIKELY( !hashes ) ) FD_LOG_ERR(( "Slot hashes sysvar is invalid, cannot update" ));

  uchar found = 0;
  for( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( hashes );
       !deq_fd_slot_hash_t_iter_done( hashes, iter );
       iter = deq_fd_slot_hash_t_iter_next( hashes, iter ) ) {
    fd_slot_hash_t * ele = deq_fd_slot_hash_t_iter_ele( hashes, iter );
    if( ele->slot == fd_bank_slot_get( slot_ctx->bank ) ) {
      fd_hash_t const * bank_hash = fd_bank_bank_hash_query( slot_ctx->bank );
      memcpy( &ele->hash, bank_hash, sizeof(fd_hash_t) );
      found = 1;
    }
  }

  if( !found ) {
    // https://github.com/firedancer-io/solana/blob/08a1ef5d785fe58af442b791df6c4e83fe2e7c74/runtime/src/bank.rs#L2371
    fd_slot_hash_t slot_hash = {
      .hash = fd_bank_bank_hash_get( slot_ctx->bank ), // parent hash?
      .slot = fd_bank_parent_slot_get( slot_ctx->bank ),   // parent_slot
    };
    FD_LOG_DEBUG(( "fd_sysvar_slot_hash_update:  slot %lu,  hash %s", slot_hash.slot, FD_BASE58_ENC_32_ALLOCA( slot_hash.hash.key ) ));

    if( deq_fd_slot_hash_t_full( hashes ) ) {
      memset( deq_fd_slot_hash_t_pop_tail_nocopy( hashes ), 0, sizeof(fd_slot_hash_t) );
    }

    deq_fd_slot_hash_t_push_head( hashes, slot_hash );
  }

  fd_sysvar_slot_hashes_leave( slot_ctx, hashes );
}
