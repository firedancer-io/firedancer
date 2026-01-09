#include "fd_sysvar_slot_hashes.h"
#include "fd_sysvar.h"
#include "../fd_acc_mgr.h"
#include "../fd_system_ids.h"
#include "../../accdb/fd_accdb_impl_v1.h"

/* FIXME These constants should be header defines */

void
fd_sysvar_slot_hashes_write( fd_bank_t *               bank,
                             fd_accdb_user_t *         accdb,
                             fd_funk_txn_xid_t const * xid,
                             fd_capture_ctx_t *        capture_ctx,
                             fd_slot_hashes_global_t * slot_hashes_global ) {
  uchar __attribute__((aligned(FD_SYSVAR_SLOT_HASHES_ALIGN))) enc[ FD_SYSVAR_SLOT_HASHES_BINCODE_SZ ] = {0};
  fd_bincode_encode_ctx_t ctx = {
    .data    = enc,
    .dataend = enc + FD_SYSVAR_SLOT_HASHES_BINCODE_SZ,
  };
  if( fd_slot_hashes_encode_global( slot_hashes_global, &ctx ) ) {
    FD_LOG_ERR(("fd_slot_hashes_encode failed"));
  }
  fd_sysvar_account_update( bank, accdb, xid, capture_ctx, &fd_sysvar_slot_hashes_id, enc, FD_SYSVAR_SLOT_HASHES_BINCODE_SZ );
}

ulong
fd_sysvar_slot_hashes_footprint( ulong slot_hashes_cap ) {
  return sizeof(fd_slot_hashes_global_t) +
         deq_fd_slot_hash_t_footprint( slot_hashes_cap ) + deq_fd_slot_hash_t_align();
}

void *
fd_sysvar_slot_hashes_new( void * mem,
                           ulong  slot_hashes_cap ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_ERR(( "Unable to allocate memory for slot hashes" ));
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_SYSVAR_SLOT_HASHES_ALIGN ) ) ) {
    FD_LOG_ERR(( "Memory for slot hashes is not aligned" ));
  }

  fd_slot_hashes_global_t * slot_hashes_global = (fd_slot_hashes_global_t *)mem;

  uchar * slot_hash_mem = (uchar*)fd_ulong_align_up( (ulong)((uchar *)mem + sizeof(fd_slot_hashes_global_t)), deq_fd_slot_hash_t_align() );
  deq_fd_slot_hash_t_new( (void*)slot_hash_mem, slot_hashes_cap );
  slot_hashes_global->hashes_offset = (ulong)slot_hash_mem - (ulong)slot_hashes_global;

  return slot_hashes_global;
}

fd_slot_hashes_global_t *
fd_sysvar_slot_hashes_join( void *            shmem,
                            fd_slot_hash_t ** slot_hash ) {
  fd_slot_hashes_global_t * slot_hashes_global = (fd_slot_hashes_global_t *)shmem;
  *slot_hash                                   = deq_fd_slot_hash_t_join( (uchar*)shmem + slot_hashes_global->hashes_offset );

  return slot_hashes_global;
}

void *
fd_sysvar_slot_hashes_leave( fd_slot_hashes_global_t * slot_hashes_global,
                             fd_slot_hash_t *          slot_hash ) {
  deq_fd_slot_hash_t_leave( slot_hash );

  return slot_hashes_global;
}

void *
fd_sysvar_slot_hashes_delete( void * mem ) {
  void * slot_hash_mem = (void *)fd_ulong_align_up( (ulong)((uchar *)mem + sizeof(fd_slot_hashes_global_t)), deq_fd_slot_hash_t_align() );
  deq_fd_slot_hash_t_delete( slot_hash_mem );

  return mem;
}

/* https://github.com/anza-xyz/agave/blob/b11ca828cfc658b93cb86a6c5c70561875abe237/runtime/src/bank.rs#L2283-L2294 */
void
fd_sysvar_slot_hashes_update( fd_bank_t *               bank,
                              fd_accdb_user_t *         accdb,
                              fd_funk_txn_xid_t const * xid,
                              fd_capture_ctx_t *        capture_ctx ) {
  uchar __attribute__((aligned(FD_SYSVAR_SLOT_HASHES_ALIGN))) slot_hashes_mem[FD_SYSVAR_SLOT_HASHES_FOOTPRINT];
  fd_slot_hashes_global_t * slot_hashes_global = fd_sysvar_slot_hashes_read( accdb, xid, slot_hashes_mem );
  fd_slot_hash_t *          hashes             = NULL;
  if( FD_UNLIKELY( !slot_hashes_global ) ) {
    /* Note: Agave's implementation initializes a new slot_hashes if it doesn't already exist (refer to above URL). */
    slot_hashes_global = fd_sysvar_slot_hashes_new( slot_hashes_mem, FD_SYSVAR_SLOT_HASHES_CAP );
  }
  slot_hashes_global = fd_sysvar_slot_hashes_join( slot_hashes_global, &hashes );

  uchar found = 0;
  for( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( hashes );
        !deq_fd_slot_hash_t_iter_done( hashes, iter );
        iter = deq_fd_slot_hash_t_iter_next( hashes, iter ) ) {
    fd_slot_hash_t * ele = deq_fd_slot_hash_t_iter_ele( hashes, iter );
    if( ele->slot == fd_bank_parent_slot_get( bank ) ) {
      fd_hash_t const * bank_hash = fd_bank_bank_hash_query( bank );
      memcpy( &ele->hash, bank_hash, sizeof(fd_hash_t) );
      found = 1;
    }
  }

  if( !found ) {
    // https://github.com/firedancer-io/solana/blob/08a1ef5d785fe58af442b791df6c4e83fe2e7c74/runtime/src/bank.rs#L2371
    fd_slot_hash_t slot_hash = {
      .hash = fd_bank_bank_hash_get( bank ), // parent hash?
      .slot = fd_bank_parent_slot_get( bank ),   // parent_slot
    };

    if( deq_fd_slot_hash_t_full( hashes ) )
      memset( deq_fd_slot_hash_t_pop_tail_nocopy( hashes ), 0, sizeof(fd_slot_hash_t) );

    deq_fd_slot_hash_t_push_head( hashes, slot_hash );
  }

  fd_sysvar_slot_hashes_write( bank, accdb, xid, capture_ctx, slot_hashes_global );
  fd_sysvar_slot_hashes_leave( slot_hashes_global, hashes );
}

fd_slot_hashes_global_t *
fd_sysvar_slot_hashes_read( fd_accdb_user_t *         accdb,
                            fd_funk_txn_xid_t const * xid,
                            uchar *                   slot_hashes_mem ) {
  fd_accdb_ro_t ro[1];
  if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, ro, xid, &fd_sysvar_slot_hashes_id ) ) ) {
    return NULL;
  }

  /* This check is needed as a quirk of the fuzzer. If a sysvar account
     exists in the accounts database, but doesn't have any lamports,
     this means that the account does not exist. This wouldn't happen
     in a real execution environment. */
  if( FD_UNLIKELY( fd_accdb_ref_lamports( ro )==0UL ) ) {
    fd_accdb_close_ro( accdb, ro );
    return NULL;
  }

  fd_bincode_decode_ctx_t decode = {
    .data    = fd_accdb_ref_data_const( ro ),
    .dataend = (uchar *)fd_accdb_ref_data_const( ro ) + fd_accdb_ref_data_sz( ro )
  };

  fd_slot_hashes_global_t * rc = fd_slot_hashes_decode_global( slot_hashes_mem, &decode );
  fd_accdb_close_ro( accdb, ro );
  return rc;
}
