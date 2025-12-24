#include "fd_hashes.h"
#include "fd_bank.h"
#include "../capture/fd_capture_ctx.h"
#include "../../ballet/blake3/fd_blake3.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../solcap/fd_solcap_writer.h"

void
fd_hashes_account_lthash( fd_pubkey_t const       * pubkey,
                          fd_account_meta_t const * account,
                          uchar const             * data,
                          fd_lthash_value_t       * lthash_out ) {
  fd_hashes_account_lthash_simple( pubkey->uc,
                                   account->owner,
                                   account->lamports,
                                   account->executable,
                                   data,
                                   account->dlen,
                                   lthash_out );
}

void
fd_hashes_account_lthash_simple( uchar const         pubkey[ static FD_HASH_FOOTPRINT ],
                                 uchar const         owner[ static FD_HASH_FOOTPRINT ],
                                 ulong               lamports,
                                 uchar               executable,
                                 uchar const *       data,
                                 ulong               data_len,
                                 fd_lthash_value_t * lthash_out ) {
  fd_lthash_zero( lthash_out );

  /* Accounts with zero lamports are not included in the hash, so they should always be treated as zero */
  if( FD_UNLIKELY( lamports == 0 ) ) {
    return;
  }

  uchar executable_flag = executable & 0x1;

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
fd_hashes_update_lthash( fd_pubkey_t const *       pubkey,
                         fd_account_meta_t const * meta,
                         fd_lthash_value_t const * prev_account_hash,
                         fd_bank_t               * bank,
                         fd_capture_ctx_t        * capture_ctx ) {
  fd_pkt_writer_t * solcap = capture_ctx->solcap;

  /* Hash the new version of the account */
  fd_lthash_value_t new_hash[1];
  fd_hashes_account_lthash( pubkey, meta, fd_account_data( meta ), new_hash );

  /* Subtract the old hash of the account from the bank lthash */
  fd_lthash_value_t * bank_lthash = fd_type_pun( fd_bank_lthash_locking_modify( bank ) );
  fd_lthash_sub( bank_lthash, prev_account_hash );
  fd_solcap_lthash_sub( solcap, bank->bank_seq, prev_account_hash->bytes, pubkey->uc );

  /* Add the new hash of the account to the bank lthash */
  fd_lthash_add( bank_lthash, new_hash );
  fd_solcap_lthash_add( solcap, bank->bank_seq, new_hash->bytes, pubkey->uc );

  fd_bank_lthash_end_locking_modify( bank );
}
