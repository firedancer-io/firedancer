#include "fd_sysvar_slot_hashes.h"
#include "../../../flamenco/types/fd_types.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_hashes.rs#L11 */
const ulong slot_hashes_max_entries = 512;

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/sysvar/slot_hashes.rs#L12 */
const ulong slot_hashes_min_account_size = 20488;

void write_slot_hashes( fd_exec_slot_ctx_t * slot_ctx, fd_slot_hashes_t* slot_hashes ) {
  ulong sz = fd_slot_hashes_size( slot_hashes );
  if (sz < slot_hashes_min_account_size)
    sz = slot_hashes_min_account_size;
  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  if ( fd_slot_hashes_encode( slot_hashes, &ctx ) )
    FD_LOG_ERR(("fd_slot_hashes_encode failed"));

  fd_sysvar_set( slot_ctx, fd_sysvar_owner_id.key, &fd_sysvar_slot_hashes_id, enc, sz, slot_ctx->slot_bank.slot, NULL );
}

//void fd_sysvar_slot_hashes_init( fd_slot_ctx_ctx_t* slot_ctx ) {
//  fd_slot_hashes_t slot_hashes;
//  memset( &slot_hashes, 0, sizeof(fd_slot_hashes_t) );
//  write_slot_hashes( slot_ctx, &slot_hashes );
//}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_hashes.rs#L34 */
void fd_sysvar_slot_hashes_update( fd_exec_slot_ctx_t * slot_ctx ) {
  FD_SCRATCH_SCOPED_FRAME;

  fd_slot_hashes_t slot_hashes;
  int err = fd_sysvar_slot_hashes_read( slot_ctx, &slot_hashes );
  switch( err ) {
  case 0: break;
  case FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT:
    slot_hashes.hashes = deq_fd_slot_hash_t_alloc( slot_ctx->valloc );
    FD_TEST( slot_hashes.hashes );
    break;
  default:
    FD_LOG_ERR(( "fd_sysvar_slot_hashes_read failed (%d)", err ));
  }

  fd_slot_hash_t * hashes = slot_hashes.hashes;

  uchar found = 0;
  for ( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( hashes );
        !deq_fd_slot_hash_t_iter_done( hashes, iter );
        iter = deq_fd_slot_hash_t_iter_next( hashes, iter ) ) {
    fd_slot_hash_t * ele = deq_fd_slot_hash_t_iter_ele( hashes, iter );
    if ( ele->slot == slot_ctx->slot_bank.slot ) {
      memcpy( &ele->hash, &slot_ctx->slot_bank.banks_hash, sizeof(fd_hash_t) );
      found = 1;
    }
  }

  if ( !found ) {
  // https://github.com/firedancer-io/solana/blob/08a1ef5d785fe58af442b791df6c4e83fe2e7c74/runtime/src/bank.rs#L2371
    fd_slot_hash_t slot_hash = {
      .hash = slot_ctx->slot_bank.banks_hash, // parent hash?
      .slot = slot_ctx->slot_bank.prev_slot,   // parent_slot
    };
    FD_LOG_DEBUG(( "fd_sysvar_slot_hash_update:  slot %ld,  hash %32J", slot_hash.slot, slot_hash.hash.key ));
    fd_bincode_destroy_ctx_t ctx2 = { .valloc = slot_ctx->valloc };

    if (deq_fd_slot_hash_t_full( hashes ) )
      fd_slot_hash_destroy( deq_fd_slot_hash_t_pop_tail_nocopy( hashes ), &ctx2 );

    deq_fd_slot_hash_t_push_head( hashes, slot_hash );
  }

  write_slot_hashes( slot_ctx, &slot_hashes );
  fd_bincode_destroy_ctx_t ctx = { .valloc = slot_ctx->valloc };
  fd_slot_hashes_destroy( &slot_hashes, &ctx );
}

int
fd_sysvar_slot_hashes_read( fd_exec_slot_ctx_t *  slot_ctx,
                            fd_slot_hashes_t *    result ) {

//  FD_LOG_INFO(( "SysvarS1otHashes111111111111111111111111111 at slot %lu: " FD_LOG_HEX16_FMT, slot_ctx->slot_bank.slot, FD_LOG_HEX16_FMT_ARGS(     metadata.hash    ) ));

  FD_BORROWED_ACCOUNT_DECL(rec);
  int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, (fd_pubkey_t const *)&fd_sysvar_slot_hashes_id, rec );
  if (FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS))
    return err;

  fd_bincode_decode_ctx_t decode = {
    .data    = rec->const_data,
    .dataend = rec->const_data + rec->const_meta->dlen,
    .valloc  = slot_ctx->valloc /* !!! There is no reason to place this on the slot_ctx heap.  Use scratch instead. */
  };

  err = fd_slot_hashes_decode( result, &decode );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) )
    return err;

  return 0;
}
