#include "fd_sysvar_slot_hashes.h"
#include "../../../flamenco/types/fd_types.h"
#include "fd_sysvar.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_hashes.rs#L11 */
const ulong slot_hashes_max_entries = 512;

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/sysvar/slot_hashes.rs#L12 */
const ulong slot_hashes_min_account_size = 20488;

void write_slot_hashes( fd_global_ctx_t* global, fd_slot_hashes_t* slot_hashes ) {
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

  fd_sysvar_set( global, global->sysvar_owner, global->sysvar_slot_hashes, enc, sz, global->bank.slot );
}

//void fd_sysvar_slot_hashes_init( fd_global_ctx_t* global ) {
//  fd_slot_hashes_t slot_hashes;
//  memset( &slot_hashes, 0, sizeof(fd_slot_hashes_t) );  
//  write_slot_hashes( global, &slot_hashes );
//} 

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_hashes.rs#L34 */
void fd_sysvar_slot_hashes_update( fd_global_ctx_t* global ) {
  fd_slot_hashes_t slot_hashes;
  fd_sysvar_slot_hashes_read( global, &slot_hashes );
  fd_slot_hash_t * hashes = slot_hashes.hashes;

  uchar found = 0;
  for ( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( hashes );
        !deq_fd_slot_hash_t_iter_done( hashes, iter );
        iter = deq_fd_slot_hash_t_iter_next( hashes, iter ) ) {
    fd_slot_hash_t * ele = deq_fd_slot_hash_t_iter_ele( hashes, iter );
    if ( ele->slot == global->bank.slot ) {
      memcpy( &ele->hash, &global->banks_hash, sizeof(fd_hash_t) );
      found = 1; 
    }
  }

  if ( !found ) {
    /* TODO: handle case where current_slot > slot_hashes_max_entries */
  // https://github.com/firedancer-io/solana/blob/08a1ef5d785fe58af442b791df6c4e83fe2e7c74/runtime/src/bank.rs#L2371
    fd_slot_hash_t slot_hash = {
      .hash = global->banks_hash, // parent hash?
      .slot = global->bank.slot - 1,  // parent_slot
    };

    if (FD_UNLIKELY(global->log_level > 2))  {
      char buf[50];
      fd_base58_encode_32((uchar *) slot_hash.hash.key, NULL, buf);

      FD_LOG_WARNING(( "fd_sysvar_slot_hash_update:  slot %ld,  hash %s", slot_hash.slot, buf)); 
    }

    FD_TEST( !deq_fd_slot_hash_t_full( hashes ) );
    deq_fd_slot_hash_t_push_head( hashes, slot_hash );
  }

  write_slot_hashes( global, &slot_hashes );
  fd_bincode_destroy_ctx_t ctx;
  ctx.freef = global->freef;
  ctx.freef_arg = global->allocf_arg;
  fd_slot_hashes_destroy( &slot_hashes, &ctx );
}

void fd_sysvar_slot_hashes_read( fd_global_ctx_t* global, fd_slot_hashes_t* result ) {
  /* Read the slot hashes sysvar from the account */
  fd_account_meta_t metadata;
  int               read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_slot_hashes, &metadata );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    // Initialize the database... 
    memset(result, 0, sizeof(*result));
    result->hashes = deq_fd_slot_hash_t_alloc( global->allocf, global->allocf_arg );
    return;
  }

//  FD_LOG_INFO(( "SysvarS1otHashes111111111111111111111111111 at slot %lu: " FD_LOG_HEX16_FMT, global->bank.slot, FD_LOG_HEX16_FMT_ARGS(     metadata.hash    ) ));

  unsigned char *raw_acc_data = fd_alloca( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_slot_hashes, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_ERR(( "failed to read account data: %d", read_result ));
  }

  fd_bincode_decode_ctx_t ctx;
  ctx.data = raw_acc_data;
  ctx.dataend = raw_acc_data + metadata.dlen;
  ctx.allocf = global->allocf;
  ctx.allocf_arg = global->allocf_arg;
  if ( fd_slot_hashes_decode( result, &ctx ) )
    FD_LOG_ERR(("fd_slot_hashes_decode failed"));
}
