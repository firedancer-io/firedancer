#include "fd_sysvar_slot_hashes.h"
#include "fd_sysvar.h"
#include "../fd_acc_mgr.h"
#include "../fd_borrowed_account.h"
#include "../fd_system_ids.h"
#include "../context/fd_exec_slot_ctx.h"
/* FIXME These constants should be header defines */

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_hashes.rs#L11 */
FD_FN_UNUSED static const ulong slot_hashes_max_entries = 512;

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/sysvar/slot_hashes.rs#L12 */
static const ulong slot_hashes_account_size = 20488;

void
fd_sysvar_slot_hashes_write( fd_exec_slot_ctx_t *      slot_ctx,
                             fd_slot_hashes_global_t * slot_hashes_global ) {
  uchar enc[slot_hashes_account_size];
  fd_memset( enc, 0, slot_hashes_account_size );
  fd_bincode_encode_ctx_t ctx = {
    .data    = enc,
    .dataend = enc + slot_hashes_account_size,
  };
  if( fd_slot_hashes_encode_global( slot_hashes_global, &ctx ) ) {
    FD_LOG_ERR(("fd_slot_hashes_encode failed"));
  }
  fd_sysvar_set( slot_ctx->bank, slot_ctx->funk, slot_ctx->funk_txn, &fd_sysvar_owner_id, &fd_sysvar_slot_hashes_id, enc, slot_hashes_account_size, slot_ctx->slot );
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

void
fd_sysvar_slot_hashes_init( fd_exec_slot_ctx_t * slot_ctx,
                            fd_spad_t *          runtime_spad ) {
  FD_SPAD_FRAME_BEGIN( runtime_spad ) {
    void * mem                                    = fd_spad_alloc( runtime_spad, FD_SYSVAR_SLOT_HASHES_ALIGN, fd_sysvar_slot_hashes_footprint( FD_SYSVAR_SLOT_HASHES_CAP ) );
    fd_slot_hash_t * shnull                       = NULL;
    fd_slot_hashes_global_t * slot_hashes_global  = fd_sysvar_slot_hashes_join( fd_sysvar_slot_hashes_new( mem, FD_SYSVAR_SLOT_HASHES_CAP ), &shnull );

    fd_sysvar_slot_hashes_write( slot_ctx, slot_hashes_global);
    fd_sysvar_slot_hashes_delete( fd_sysvar_slot_hashes_leave( slot_hashes_global, shnull ) );
  } FD_SPAD_FRAME_END;
}

/* https://github.com/anza-xyz/agave/blob/b11ca828cfc658b93cb86a6c5c70561875abe237/runtime/src/bank.rs#L2283-L2294 */
void
fd_sysvar_slot_hashes_update( fd_exec_slot_ctx_t * slot_ctx, fd_spad_t * runtime_spad ) {
FD_SPAD_FRAME_BEGIN( runtime_spad ) {
  fd_slot_hashes_global_t * slot_hashes_global = fd_sysvar_slot_hashes_read( slot_ctx->funk, slot_ctx->funk_txn, runtime_spad );
  fd_slot_hash_t *          hashes             = NULL;
  if( FD_UNLIKELY( !slot_hashes_global ) ) {
    /* Note: Agave's implementation initializes a new slot_hashes if it doesn't already exist (refer to above URL). */
    void * mem = fd_spad_alloc( runtime_spad, FD_SYSVAR_SLOT_HASHES_ALIGN, fd_sysvar_slot_hashes_footprint( FD_SYSVAR_SLOT_HASHES_CAP ) );
    slot_hashes_global = fd_sysvar_slot_hashes_new( mem, FD_SYSVAR_SLOT_HASHES_CAP );
  }
  slot_hashes_global = fd_sysvar_slot_hashes_join( slot_hashes_global, &hashes );

  uchar found = 0;
  for( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( hashes );
       !deq_fd_slot_hash_t_iter_done( hashes, iter );
       iter = deq_fd_slot_hash_t_iter_next( hashes, iter ) ) {
    fd_slot_hash_t * ele = deq_fd_slot_hash_t_iter_ele( hashes, iter );
    if( ele->slot == slot_ctx->slot ) {
      fd_hash_t const * bank_hash = fd_bank_bank_hash_query( slot_ctx->bank );
      memcpy( &ele->hash, bank_hash, sizeof(fd_hash_t) );
      found = 1;
    }
  }

  if( !found ) {
    // https://github.com/firedancer-io/solana/blob/08a1ef5d785fe58af442b791df6c4e83fe2e7c74/runtime/src/bank.rs#L2371
    fd_slot_hash_t slot_hash = {
      .hash = fd_bank_bank_hash_get( slot_ctx->bank ), // parent hash?
      .slot = fd_bank_prev_slot_get( slot_ctx->bank ),   // parent_slot
    };
    FD_LOG_DEBUG(( "fd_sysvar_slot_hash_update:  slot %lu,  hash %s", slot_hash.slot, FD_BASE58_ENC_32_ALLOCA( slot_hash.hash.key ) ));

    if( deq_fd_slot_hash_t_full( hashes ) )
      memset( deq_fd_slot_hash_t_pop_tail_nocopy( hashes ), 0, sizeof(fd_slot_hash_t) );

    deq_fd_slot_hash_t_push_head( hashes, slot_hash );
  }

  fd_sysvar_slot_hashes_write( slot_ctx, slot_hashes_global );
  fd_sysvar_slot_hashes_leave( slot_hashes_global, hashes );
} FD_SPAD_FRAME_END;
}

fd_slot_hashes_global_t *
fd_sysvar_slot_hashes_read( fd_funk_t *     funk,
                            fd_funk_txn_t * funk_txn,
                            fd_spad_t *     spad ) {
  FD_TXN_ACCOUNT_DECL( rec );
  int err = fd_txn_account_init_from_funk_readonly( rec, (fd_pubkey_t const *)&fd_sysvar_slot_hashes_id, funk, funk_txn );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    return NULL;
  }

  /* This check is needed as a quirk of the fuzzer. If a sysvar account
     exists in the accounts database, but doesn't have any lamports,
     this means that the account does not exist. This wouldn't happen
     in a real execution environment. */
  if( FD_UNLIKELY( rec->vt->get_lamports( rec )==0 ) ) {
    return NULL;
  }

  fd_bincode_decode_ctx_t decode = {
    .data    = rec->vt->get_data( rec ),
    .dataend = rec->vt->get_data( rec ) + rec->vt->get_data_len( rec )
  };

  ulong total_sz = 0UL;
  err = fd_slot_hashes_decode_footprint( &decode, &total_sz );
  if( FD_UNLIKELY( err ) ) {
    return NULL;
  }

  uchar * mem = fd_spad_alloc( spad, fd_slot_hashes_align(), total_sz );

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_ERR(( "Unable to allocate memory for slot hashes" ));
  }

  return fd_slot_hashes_decode_global( mem, &decode );
}
