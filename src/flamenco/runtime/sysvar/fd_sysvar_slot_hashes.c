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

static void
write_slot_hashes( fd_exec_slot_ctx_t *      slot_ctx,
                   fd_slot_hashes_global_t * slot_hashes_global ) {
  uchar enc[slot_hashes_account_size];
  fd_memset( enc, 0, slot_hashes_account_size );
  fd_bincode_encode_ctx_t ctx = {
    .data    = enc,
    .dataend = enc + slot_hashes_account_size,
    .wksp    = slot_ctx->runtime_wksp
  };
  if( fd_slot_hashes_encode_global( slot_hashes_global, &ctx ) ) {
    FD_LOG_ERR(("fd_slot_hashes_encode failed"));
  }
  fd_sysvar_set( slot_ctx, &fd_sysvar_owner_id, &fd_sysvar_slot_hashes_id, enc, slot_hashes_account_size, slot_ctx->slot_bank.slot );
}

void
fd_sysvar_slot_hashes_init( fd_exec_slot_ctx_t *      slot_ctx,
                            fd_slot_hashes_global_t * slot_hashes_global ) {
  write_slot_hashes( slot_ctx, slot_hashes_global );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_hashes.rs#L34 */
void
fd_sysvar_slot_hashes_update( fd_exec_slot_ctx_t * slot_ctx, fd_spad_t * runtime_spad ) {
  fd_slot_hashes_global_t * slot_hashes_global = fd_sysvar_slot_hashes_read( slot_ctx, runtime_spad );
  fd_slot_hash_t *          hashes             = NULL;
  if( !slot_hashes_global ) {
    uchar * deque_mem = fd_spad_alloc( runtime_spad,
                                       deq_fd_slot_hash_t_align(),
                                       deq_fd_slot_hash_t_footprint( FD_SYSVAR_SLOT_HASHES_CAP ) );
    hashes = deq_fd_slot_hash_t_join( deq_fd_slot_hash_t_new( deque_mem, FD_SYSVAR_SLOT_HASHES_CAP ) );
    if( FD_UNLIKELY( !hashes ) ) {
      FD_LOG_ERR(( "Unable to allocate memory for slot hashes" ));
    }
  } else {
    hashes = deq_fd_slot_hash_t_join( (uchar*)slot_hashes_global + slot_hashes_global->hashes_offset );
  }

  uchar found = 0;
  for( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( hashes );
       !deq_fd_slot_hash_t_iter_done( hashes, iter );
       iter = deq_fd_slot_hash_t_iter_next( hashes, iter ) ) {
    fd_slot_hash_t * ele = deq_fd_slot_hash_t_iter_ele( hashes, iter );
    if( ele->slot == slot_ctx->slot_bank.slot ) {
      memcpy( &ele->hash, &slot_ctx->slot_bank.banks_hash, sizeof(fd_hash_t) );
      found = 1;
    }
  }

  if( !found ) {
    // https://github.com/firedancer-io/solana/blob/08a1ef5d785fe58af442b791df6c4e83fe2e7c74/runtime/src/bank.rs#L2371
    fd_slot_hash_t slot_hash = {
      .hash = slot_ctx->slot_bank.banks_hash, // parent hash?
      .slot = slot_ctx->slot_bank.prev_slot,   // parent_slot
    };
    FD_LOG_DEBUG(( "fd_sysvar_slot_hash_update:  slot %lu,  hash %s", slot_hash.slot, FD_BASE58_ENC_32_ALLOCA( slot_hash.hash.key ) ));

    if (deq_fd_slot_hash_t_full( hashes ) )
      fd_slot_hash_destroy( deq_fd_slot_hash_t_pop_tail_nocopy( hashes ) );

    deq_fd_slot_hash_t_push_head( hashes, slot_hash );
  }

  write_slot_hashes( slot_ctx, slot_hashes_global );
}

fd_slot_hashes_global_t *
fd_sysvar_slot_hashes_read( fd_exec_slot_ctx_t *  slot_ctx,
                            fd_spad_t *           runtime_spad ) {
  FD_TXN_ACCOUNT_DECL( rec );
  int err = fd_txn_account_init_from_funk_readonly( rec, (fd_pubkey_t const *)&fd_sysvar_slot_hashes_id, slot_ctx->funk, slot_ctx->funk_txn );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) )
    return NULL;

  fd_bincode_decode_ctx_t decode = {
    .data    = rec->vt->get_data( rec ),
    .dataend = rec->vt->get_data( rec ) + rec->vt->get_data_len( rec ),
    .wksp    = slot_ctx->runtime_wksp
  };

  ulong total_sz = 0UL;
  err = fd_slot_hashes_decode_footprint( &decode, &total_sz );
  if( FD_UNLIKELY( err ) ) {
    return NULL;
  }

  uchar * mem = fd_spad_alloc( runtime_spad, fd_slot_hashes_align(), total_sz );

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_ERR(( "Unable to allocate memory for slot hashes" ));
  }

  return fd_slot_hashes_decode_global( mem, &decode );
}
