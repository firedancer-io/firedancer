#include "fd_hashes.h"
#include "fd_bank.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../capture/fd_capture_ctx.h"

static fd_blake3_t *
account_lthash_init( fd_blake3_t * b3,
                     uchar const   pubkey[ static FD_HASH_FOOTPRINT ],
                     uchar const   owner[ static FD_HASH_FOOTPRINT ],
                     ulong         lamports,
                     int           executable,
                     uchar const * data,
                     ulong         data_len ) {
  uchar executable_flag = !!executable;

  fd_blake3_init( b3 );
  fd_blake3_append( b3, &lamports, sizeof( ulong ) );
  fd_blake3_append( b3, data, data_len );
  fd_blake3_append( b3, &executable_flag, sizeof( uchar ) );
  fd_blake3_append( b3, owner, FD_HASH_FOOTPRINT );
  fd_blake3_append( b3, pubkey, FD_HASH_FOOTPRINT );
  return b3;
}

void
fd_hashes_account_lthash_simple( uchar const         pubkey[ static FD_HASH_FOOTPRINT ],
                                 uchar const         owner[ static FD_HASH_FOOTPRINT ],
                                 ulong               lamports,
                                 int                 executable,
                                 uchar const *       data,
                                 ulong               data_len,
                                 fd_lthash_value_t * lthash_out ) {
  if( FD_UNLIKELY( !lamports ) ) {
    fd_lthash_zero( lthash_out );
    return;
  }

  fd_blake3_t b3[1];
  fd_blake3_fini_2048( account_lthash_init( b3, pubkey, owner, lamports, executable, data, data_len ), lthash_out->bytes );
}

void
fd_hashes_account_lthash_xn( ulong                 n,
                             uchar const * const * pubkey,
                             uchar const * const * owner,
                             ulong const *         lamports,
                             int const *           executable,
                             uchar const * const * data,
                             ulong const *         data_len,
                             fd_lthash_value_t **  lthash_out ) {
  fd_blake3_t   b3  [ FD_BLAKE3_XN_MAX ];
  fd_blake3_t * sha [ FD_BLAKE3_XN_MAX ];
  void *        hash[ FD_BLAKE3_XN_MAX ];
  ulong         m = 0UL;

  for( ulong i=0UL; i<n; i++ ) {
    if( FD_UNLIKELY( !lamports[ i ] ) ) {
      fd_lthash_zero( lthash_out[ i ] );
      continue;
    }

    sha [ m ] = account_lthash_init( b3+m, pubkey[ i ], owner[ i ], lamports[ i ], executable[ i ], data[ i ], data_len[ i ] );
    hash[ m ] = lthash_out[ i ]->bytes;
    m++;
  }

  if( FD_LIKELY( m ) ) fd_blake3_fini_2048_xn( m, sha, hash );
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

static void
update_bank_lthash( fd_bank_t *               bank,
                    fd_lthash_value_t const * lthash_prev,
                    fd_lthash_value_t const * lthash_post ) {
  fd_lthash_value_t delta[1];
  fd_memcpy( delta, lthash_post, sizeof(fd_lthash_value_t) );
  fd_lthash_sub( delta, lthash_prev );

  fd_lthash_value_t * bank_lthash = fd_bank_lthash_locking_modify( bank );
  fd_lthash_add( bank_lthash, delta );
  fd_bank_lthash_end_locking_modify( bank );
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
  if( bank->lthash_mode==FD_BANK_LTHASH_MODE_INBAND ) {
    /* Compute the new hash of the account. */
    fd_hashes_account_lthash_simple( pubkey, owner, lamports, executable, data, data_len, lthash_post );
    update_bank_lthash( bank, lthash_prev, lthash_post );
  } else if( bank->lthash_mode==FD_BANK_LTHASH_MODE_OOB_RECORD ) {
    fd_bank_lthash_record( bank, pubkey );
  }

  fd_hashes_capture_account( pubkey, owner, lamports, executable, data, data_len, bank, capture_ctx );
}

void
fd_hashes_update_pair( uchar const        pubkey[ static FD_HASH_FOOTPRINT ],
                       uchar const        prev_owner[ static FD_HASH_FOOTPRINT ],
                       ulong              prev_lamports,
                       int                prev_executable,
                       uchar const *      prev_data,
                       ulong              prev_data_len,
                       uchar const        owner[ static FD_HASH_FOOTPRINT ],
                       ulong              lamports,
                       int                executable,
                       uchar const *      data,
                       ulong              data_len,
                       fd_bank_t *        bank,
                       fd_capture_ctx_t * capture_ctx ) {
  if( bank->lthash_mode==FD_BANK_LTHASH_MODE_INBAND ) {
    /* Hash the account before and after the write in one batch. */
    fd_lthash_value_t   lthash_prev[1];
    fd_lthash_value_t   lthash_post[1];
    uchar const *       pk [2] = { pubkey,          pubkey     };
    uchar const *       ow [2] = { prev_owner,      owner      };
    ulong               la [2] = { prev_lamports,   lamports   };
    int                 ex [2] = { prev_executable, executable };
    uchar const *       da [2] = { prev_data,       data       };
    ulong               dl [2] = { prev_data_len,   data_len   };
    fd_lthash_value_t * out[2] = { lthash_prev,     lthash_post };
    fd_hashes_account_lthash_xn( 2UL, pk, ow, la, ex, da, dl, out );
    update_bank_lthash( bank, lthash_prev, lthash_post );
  } else if( bank->lthash_mode==FD_BANK_LTHASH_MODE_OOB_RECORD ) {
    fd_bank_lthash_record( bank, pubkey );
  }

  fd_hashes_capture_account( pubkey, owner, lamports, executable, data, data_len, bank, capture_ctx );
}

void
fd_hashes_capture_account( uchar const        pubkey[ static FD_HASH_FOOTPRINT ],
                           uchar const        owner[ static FD_HASH_FOOTPRINT ],
                           ulong              lamports,
                           int                executable,
                           uchar const *      data,
                           ulong              data_len,
                           fd_bank_t *        bank,
                           fd_capture_ctx_t * capture_ctx ) {
  if( FD_LIKELY( !capture_ctx ||
                 !capture_ctx->capture_solcap ||
                 bank->f.slot<capture_ctx->solcap_start_slot ) ) return;

  fd_solana_account_meta_t solana_meta[1];
  fd_solana_account_meta_init( solana_meta, lamports, owner, executable );
  fd_capture_link_write_account_update(
    capture_ctx,
    capture_ctx->current_txn_idx,
    (fd_pubkey_t const *)pubkey,
    solana_meta,
    bank->f.slot,
    data,
    data_len );
}

void
fd_hashes_apply_hard_forks( fd_hash_t *            hash,
                            ulong                  slot,
                            ulong                  parent_slot,
                            fd_hard_fork_t const * hard_forks,
                            ulong                  hard_fork_cnt ) {
  ulong sum = 0UL;
  for( ulong i=0UL; i<hard_fork_cnt; i++ ) {
    if( FD_UNLIKELY( parent_slot<hard_forks[ i ].slot && hard_forks[ i ].slot<=slot ) ) sum += hard_forks[ i ].cnt;
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
