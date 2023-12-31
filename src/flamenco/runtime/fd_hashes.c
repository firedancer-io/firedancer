#include "fd_hashes.h"
#include "fd_acc_mgr.h"
#include "fd_bank.h"
#include "context/fd_capture_ctx.h"
#include "../capture/fd_solcap_writer.h"
#include "../../ballet/blake3/fd_blake3.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../ballet/sha256/fd_sha256.h"

void
fd_hashes_account_lthash( fd_pubkey_t const       * pubkey,
                          fd_account_meta_t const * account,
                          uchar const             * data,
                          fd_lthash_value_t       * lthash_out ) {
  fd_lthash_zero( lthash_out );

  /* Accounts with zero lamports are not included in the hash, so they should always be treated as zero */
  if( FD_UNLIKELY( account->info.lamports == 0 ) ) {
    return;
  }

  uchar executable = account->info.executable & 0x1;

  fd_blake3_t b3[1];
  fd_blake3_init( b3 );
  fd_blake3_append( b3, &account->info.lamports, sizeof( ulong ) );
  fd_blake3_append( b3, data, account->dlen );
  fd_blake3_append( b3, &executable, sizeof( uchar ) );
  fd_blake3_append( b3, account->info.owner, FD_PUBKEY_FOOTPRINT );
  fd_blake3_append( b3, pubkey, FD_PUBKEY_FOOTPRINT );
  fd_blake3_fini_2048( b3, lthash_out->bytes );
}

void
fd_hashes_hash_bank( fd_slot_lthash_t const * lthash,
                     fd_hash_t const *        prev_bank_hash,
                     fd_hash_t const *        last_blockhash,
                     ulong                    signature_count,
                     fd_hash_t *              hash_out ) {

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
  fd_sha256_append( &sha, (uchar const *) hash_out->hash, sizeof( fd_hash_t ) );
  fd_sha256_append( &sha, (uchar const *) lthash->lthash, sizeof( lthash->lthash ) );
  fd_sha256_fini( &sha, hash_out->hash );
}

void
fd_hashes_update_lthash( fd_txn_account_t const  * account,
                         fd_lthash_value_t const * prev_account_hash,
                         fd_bank_t               * bank,
                         fd_capture_ctx_t        * capture_ctx ) {

  /* Subtract the old hash of the account from the bank lthash */
  fd_lthash_value_t * bank_lthash = fd_type_pun( fd_bank_lthash_locking_modify( bank ) );
  fd_lthash_sub( bank_lthash, prev_account_hash );

  /* Hash the new version of the account */
  fd_lthash_value_t new_hash[1];
  fd_account_meta_t const * meta = fd_txn_account_get_meta( account );
  fd_hashes_account_lthash( account->pubkey, meta, fd_txn_account_get_data( account ), new_hash );

  /* Add the new hash of the account to the bank lthash */
  fd_lthash_add( bank_lthash, new_hash );

  fd_bank_lthash_end_locking_modify( bank );

  /* Write the new account state to the capture file */
  if( capture_ctx && capture_ctx->capture && fd_bank_slot_get( bank )>=capture_ctx->solcap_start_slot ) {
    uchar new_hash_checksum[FD_HASH_FOOTPRINT];
    fd_lthash_hash( new_hash, new_hash_checksum );
    int err = fd_solcap_write_account(
      capture_ctx->capture,
      account->pubkey,
      &meta->info,
      fd_txn_account_get_data( account ),
      fd_txn_account_get_data_len( account ),
      new_hash_checksum );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "Failed to write account to capture file" ));
    }
  }
}
