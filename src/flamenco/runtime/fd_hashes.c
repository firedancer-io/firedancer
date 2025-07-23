#include "fd_hashes.h"
#include "fd_acc_mgr.h"
#include "fd_bank.h"
#include "fd_blockstore.h"
#include "fd_runtime.h"
#include "fd_borrowed_account.h"
#include "context/fd_capture_ctx.h"
#include "fd_runtime_public.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "../capture/fd_solcap_writer.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/blake3/fd_blake3.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../disco/capture/fd_capture.h"
#include "../../disco/stem/fd_stem.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

void
fd_hash_account_lthash_value( fd_pubkey_t const       * pubkey,
                              fd_account_meta_t const * account,
                              uchar const             * data,
                              fd_lthash_value_t *       lthash_out ) {
  fd_lthash_zero( lthash_out );

  /* Accounts with zero lamports are not included in the hash */
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
  fd_blake3_fini_varlen( b3, lthash_out->bytes, FD_LTHASH_LEN_BYTES );

  FD_LOG_WARNING(( "lthash of %s: %s (lamports=%lu, data_len=%lu, executable=%u, owner=%s)",
    FD_BASE58_ENC_32_ALLOCA( pubkey ),
    FD_LTHASH_ENC_32_ALLOCA( lthash_out ),
    account->info.lamports,
    account->dlen,
    executable,
    FD_BASE58_ENC_32_ALLOCA( &account->info.owner ) ));
}

// slot_ctx should be const.
static void
fd_hash_bank( fd_exec_slot_ctx_t *    slot_ctx,
              fd_capture_ctx_t *      capture_ctx,
              fd_hash_t *             hash,
              fd_stem_context_t *     stem,
              fd_replay_out_link_t *  capture_out ) {

  fd_hash_t const * bank_hash = fd_bank_bank_hash_query( slot_ctx->bank );

  fd_bank_prev_bank_hash_set( slot_ctx->bank, *bank_hash );

  fd_bank_parent_signature_cnt_set( slot_ctx->bank, fd_bank_signature_count_get( slot_ctx->bank ) );

  fd_bank_lamports_per_signature_set( slot_ctx->bank, fd_bank_lamports_per_signature_get( slot_ctx->bank ) );

  fd_slot_lthash_t const * lthash = fd_bank_lthash_locking_query( slot_ctx->bank );

  fd_sha256_t sha;
  fd_sha256_init( &sha );
  fd_sha256_append( &sha, (uchar const *)bank_hash, sizeof( fd_hash_t ) );
  fd_sha256_append( &sha, (uchar const *) fd_bank_signature_count_query( slot_ctx->bank ), sizeof( ulong ) );
  fd_sha256_append( &sha, (uchar const *) fd_bank_poh_query( slot_ctx->bank )->hash, sizeof( fd_hash_t ) );
  fd_sha256_fini( &sha, hash->hash );

  fd_sha256_init( &sha );
  fd_sha256_append( &sha, (uchar const *) &hash->hash, sizeof( fd_hash_t ) );
  fd_sha256_append( &sha, (uchar const *) lthash->lthash, sizeof( lthash->lthash ) );
  fd_sha256_fini( &sha, hash->hash );

  if( capture_ctx != NULL && capture_ctx->capture != NULL && fd_bank_slot_get( slot_ctx->bank )>=capture_ctx->solcap_start_slot ) {
    if( stem && capture_out && capture_out->idx != ULONG_MAX ) {
      uchar * lthash_checksum = (uchar *)fd_alloca_check( 1UL, 32UL );
      fd_lthash_hash((fd_lthash_value_t *) lthash->lthash, lthash_checksum);

      /* Send message to capture tile */
      void * msg = fd_chunk_to_laddr( capture_out->mem, capture_out->chunk );
      fd_capture_msg_write_bank_preimage_t * preimage_msg = fd_capture_msg_write_bank_preimage(
          msg,
          hash->hash,
          fd_bank_prev_bank_hash_query( slot_ctx->bank ),
          NULL, /* account_delta_hash */
          lthash_checksum,
          fd_bank_poh_query( slot_ctx->bank )->hash,
          fd_bank_signature_count_get( slot_ctx->bank ) );
      
      if( FD_LIKELY( preimage_msg ) ) {
        ulong sig  = FD_CAPTURE_MSG_TYPE_WRITE_BANK_PREIMAGE;
        ulong sz   = sizeof(fd_capture_msg_write_bank_preimage_t);
        ulong ctl  = 0UL;
        ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
        
        fd_stem_publish( stem, capture_out->idx, sig, capture_out->chunk, sz, ctl, 0UL, tspub );
        
        capture_out->chunk = fd_dcache_compact_next( capture_out->chunk, sz,
                                                      capture_out->chunk0, capture_out->wmark );
      }
    }
  }

  FD_LOG_NOTICE(( "\n\n[Replay]\n"
                  "slot:             %lu\n"
                  "bank hash:        %s\n"
                  "parent bank hash: %s\n"
                  "lthash:           %s\n"
                  "signature_count:  %lu\n"
                  "last_blockhash:   %s\n",
                  fd_bank_slot_get( slot_ctx->bank ),
                  FD_BASE58_ENC_32_ALLOCA( hash->hash ),
                  FD_BASE58_ENC_32_ALLOCA( fd_bank_prev_bank_hash_query( slot_ctx->bank ) ),
                  FD_LTHASH_ENC_32_ALLOCA( (fd_lthash_value_t *) lthash->lthash ),
                  fd_bank_signature_count_get( slot_ctx->bank ),
                  FD_BASE58_ENC_32_ALLOCA( fd_bank_poh_query( slot_ctx->bank )->hash ) ));
  fd_bank_lthash_end_locking_query( slot_ctx->bank );
}

int
fd_update_hash_bank_exec_hash( fd_exec_slot_ctx_t *           slot_ctx,
                               fd_hash_t *                    hash,
                               fd_capture_ctx_t *             capture_ctx,
                               ulong                          signature_cnt,
                               fd_stem_context_t *            stem,
                               fd_replay_out_link_t *         capture_out ) {
  fd_bank_signature_count_set( slot_ctx->bank, signature_cnt );
  fd_hash_bank( slot_ctx, capture_ctx, hash, stem, capture_out );

  return FD_EXECUTOR_INSTR_SUCCESS;

}
