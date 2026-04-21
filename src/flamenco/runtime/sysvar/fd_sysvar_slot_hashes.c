#include "fd_sysvar_slot_hashes.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"

/* FD_SYSVAR_SLOT_HASHES_CAP is the max number of entries that the
   "slot hashes" sysvar will include.

   https://github.com/anza-xyz/agave/blob/6398ddf6ab8a8f81017bf675ab315a70067f0bf0/sdk/program/src/slot_hashes.rs#L19 */

#define FD_SYSVAR_SLOT_HASHES_CAP (512UL)

static void
fd_sysvar_slot_hashes_write( fd_bank_t *               bank,
                             fd_accdb_t *              accdb,
                             fd_capture_ctx_t *        capture_ctx,
                             fd_slot_hashes_global_t * slot_hashes_global ) {
  uchar __attribute__((aligned(FD_SYSVAR_SLOT_HASHES_ALIGN))) enc[ FD_SYSVAR_SLOT_HASHES_BINCODE_SZ ] = {0};
  fd_bincode_encode_ctx_t ctx = {
    .data    = enc,
    .dataend = enc+FD_SYSVAR_SLOT_HASHES_BINCODE_SZ,
  };
  FD_TEST( !fd_slot_hashes_encode_global( slot_hashes_global, &ctx ) );
  fd_sysvar_account_update( bank, accdb, capture_ctx, &fd_sysvar_slot_hashes_id, enc, FD_SYSVAR_SLOT_HASHES_BINCODE_SZ );
}

fd_slot_hashes_global_t *
fd_sysvar_slot_hashes_read( fd_accdb_t *       accdb,
                            fd_accdb_fork_id_t fork_id,
                            uchar *            slot_hashes_mem ) {
  fd_accdb_entry_t entry = fd_accdb_read_one( accdb, fork_id, fd_sysvar_slot_hashes_id.uc );
  if( FD_UNLIKELY( !entry.lamports ) ) return NULL;

  fd_bincode_decode_ctx_t decode = {
    .data    = entry.data,
    .dataend = entry.data+entry.data_len,
  };

  fd_slot_hashes_global_t * rc = fd_slot_hashes_decode_global( slot_hashes_mem, &decode );
  fd_accdb_unread_one( accdb, &entry );
  return rc;
}


/* https://github.com/anza-xyz/agave/blob/b11ca828cfc658b93cb86a6c5c70561875abe237/runtime/src/bank.rs#L2283-L2294 */
void
fd_sysvar_slot_hashes_update( fd_bank_t *        bank,
                              fd_accdb_t *       accdb,
                              fd_capture_ctx_t * capture_ctx ) {
  uchar __attribute__((aligned(FD_SYSVAR_SLOT_HASHES_ALIGN))) slot_hashes_mem[FD_SYSVAR_SLOT_HASHES_FOOTPRINT];
  fd_slot_hashes_global_t * slot_hashes_global = fd_sysvar_slot_hashes_read( accdb, bank->accdb_fork_id, slot_hashes_mem );
  if( FD_UNLIKELY( !slot_hashes_global ) ) {
    /* Note: Agave's implementation initializes a new slot_hashes if it
       doesn't already exist (refer to above URL). */
    uchar * slot_hash_mem = (uchar*)fd_ulong_align_up( (ulong)((uchar *)slot_hashes_mem + sizeof(fd_slot_hashes_global_t)), deq_fd_slot_hash_t_align() );
    deq_fd_slot_hash_t_new( (void*)slot_hash_mem, FD_SYSVAR_SLOT_HASHES_CAP );
    slot_hashes_global->hashes_offset = (ulong)slot_hash_mem - (ulong)slot_hashes_global;
  }

  fd_slot_hash_t * hashes = deq_fd_slot_hash_t_join( (uchar*)slot_hashes_global + slot_hashes_global->hashes_offset );

  int found = 0;
  for( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( hashes );
        !deq_fd_slot_hash_t_iter_done( hashes, iter );
        iter = deq_fd_slot_hash_t_iter_next( hashes, iter ) ) {
    fd_slot_hash_t * ele = deq_fd_slot_hash_t_iter_ele( hashes, iter );
    if( ele->slot == bank->f.parent_slot ) {
      fd_hash_t const * bank_hash = &bank->f.bank_hash;
      fd_memcpy( &ele->hash, bank_hash, sizeof(fd_hash_t) );
      found = 1;
    }
  }

  if( !found ) {
    // https://github.com/firedancer-io/solana/blob/08a1ef5d785fe58af442b791df6c4e83fe2e7c74/runtime/src/bank.rs#L2371
    fd_slot_hash_t slot_hash = {
      .hash = bank->f.bank_hash, // parent hash?
      .slot = bank->f.parent_slot,   // parent_slot
    };

    if( deq_fd_slot_hash_t_full( hashes ) ) {
      fd_memset( deq_fd_slot_hash_t_pop_tail_nocopy( hashes ), 0, sizeof(fd_slot_hash_t) );
    }

    deq_fd_slot_hash_t_push_head( hashes, slot_hash );
  }

  fd_sysvar_slot_hashes_write( bank, accdb, capture_ctx, slot_hashes_global );
}
