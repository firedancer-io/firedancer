#include "fd_hashes.h"
#include "fd_bank.h"
#include "../capture/fd_capture_ctx.h"

void
fd_hashes_account_lthash_simple( uchar const         pubkey[ static FD_HASH_FOOTPRINT ],
                                 uchar const         owner[ static FD_HASH_FOOTPRINT ],
                                 ulong               lamports,
                                 int                 executable,
                                 uchar const *       data,
                                 ulong               data_len,
                                 fd_lthash_value_t * lthash_out ) {
  fd_lthash_zero( lthash_out );
  if( FD_UNLIKELY( !lamports ) ) return;

  uchar executable_flag = !!executable;

  fd_blake3_t b3[1];
  fd_blake3_init( b3 );
  fd_blake3_append( b3, &lamports, sizeof( ulong ) );
  fd_blake3_append( b3, data, data_len );
  fd_blake3_append( b3, &executable_flag, sizeof( uchar ) );
  fd_blake3_append( b3, owner, FD_HASH_FOOTPRINT );
  fd_blake3_append( b3, pubkey, FD_HASH_FOOTPRINT );
  fd_blake3_fini_2048( b3, lthash_out->bytes );
}

void
fd_hashes_hash_bank( fd_lthash_value_t const * lthash,
                     fd_hash_t const *         prev_bank_hash,
                     fd_hash_t const *         last_blockhash,
                     ulong                     signature_count,
                     fd_hash_t *               hash_out ) {

  /* The bank hash for a slot is a sha256 of two sub-hashes:
     sha256(
        sha256( previous bank hash, signature count, last PoH blockhash ),
        lthash of the accounts modified in this slot
     )
  */
  fd_sha256_t sha;
  fd_sha256_init( &sha );
  fd_sha256_append( &sha, prev_bank_hash, sizeof( fd_hash_t ) );
  fd_sha256_append( &sha, (uchar const *) &signature_count, sizeof( ulong ) );
  fd_sha256_append( &sha, (uchar const *) last_blockhash, sizeof( fd_hash_t ) );
  fd_sha256_fini( &sha, hash_out->hash );

  fd_sha256_init( &sha );
  fd_sha256_append( &sha, (uchar const *) hash_out->hash, sizeof(fd_hash_t) );
  fd_sha256_append( &sha, (uchar const *) lthash->bytes,  sizeof(fd_lthash_value_t) );
  fd_sha256_fini( &sha, hash_out->hash );
}

void
fd_hashes_update_simple( fd_lthash_value_t *       lthash_post, /* out */
                         fd_lthash_value_t const * lthash_prev, /* in */
                         uchar const               pubkey[ static FD_HASH_FOOTPRINT ],
                         uchar const               owner[ static FD_HASH_FOOTPRINT ],
                         ulong                     lamports,
                         int                       executable,
                         uchar const *             data,
                         ulong                     data_len,
                         fd_bank_t               * bank,
                         fd_capture_ctx_t        * capture_ctx ) {
  /* Compute the new hash of the account */
  fd_hashes_account_lthash_simple( pubkey, owner, lamports, executable, data, data_len, lthash_post );

  /* Subtract the old hash of the account from the bank lthash */
  fd_lthash_value_t * bank_lthash = fd_bank_lthash_locking_modify( bank );
  fd_lthash_sub( bank_lthash, lthash_prev );

  /* Add the new hash of the account to the bank lthash */
  fd_lthash_add( bank_lthash, lthash_post );

  fd_bank_lthash_end_locking_modify( bank );

  if( FD_UNLIKELY( capture_ctx &&
                   capture_ctx->capture_solcap &&
                   bank->f.slot>=capture_ctx->solcap_start_slot ) ) {
    fd_solana_account_meta_t solana_meta[1];
    fd_solana_account_meta_init( solana_meta, lamports, owner, executable );
    fd_capture_link_write_account_update(
      capture_ctx,
      capture_ctx->current_txn_idx,
      (fd_pubkey_t*)pubkey,
      solana_meta,
      bank->f.slot,
      data,
      data_len );
  }
}

void
fd_hashes_apply_hard_forks( fd_hash_t *   hash,
                            ulong         slot,
                            ulong         parent_slot,
                            ulong const * hard_forks,
                            ulong const * hard_forks_cnts,
                            ulong         hard_forks_cnt ) {
  ulong sum = 0UL;
  for( ulong i=0UL; i<hard_forks_cnt; i++ ) {
    if( FD_UNLIKELY( parent_slot<hard_forks[ i ] && hard_forks[ i ]<=slot ) ) sum += hard_forks_cnts[ i ];
  }

  if( FD_UNLIKELY( !sum ) ) return;

  ulong sum_le[ 1 ];
  FD_STORE( ulong, sum_le, sum );

  fd_sha256_t sha;
  fd_sha256_init( &sha );
  fd_sha256_append( &sha, hash->hash, sizeof(fd_hash_t) );
  fd_sha256_append( &sha, sum_le,     sizeof(ulong)     );
  fd_sha256_fini( &sha, hash->hash );
}
