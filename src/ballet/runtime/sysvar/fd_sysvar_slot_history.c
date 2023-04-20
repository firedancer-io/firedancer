#include "fd_sysvar_slot_history.h"
#include "../fd_types.h"
#include "fd_sysvar.h"

const ulong slot_history_min_account_size = 131097;

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L37 */
const ulong slot_history_max_entries = 1024 * 1024;

/* TODO: move into seperate bitvec library */
const ulong bits_per_block = 8 * sizeof(ulong);
void set( fd_slot_history_t* history, ulong i ) {
  ulong block_idx = i / bits_per_block;
  history->bits.bits->blocks[ block_idx ] |= ( 1UL << ( i % bits_per_block ) );
}

const ulong blocks_len = slot_history_max_entries / bits_per_block;

void write_history( fd_global_ctx_t* global, fd_slot_history_t* history ) {
  ulong          sz = fd_slot_history_size( history );
  if (sz < slot_history_min_account_size)
    sz = slot_history_min_account_size;
  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  void const *ptr = (void const *) enc;
  fd_slot_history_encode( history, &ptr );

  fd_sysvar_set( global, global->sysvar_owner, global->sysvar_slot_history, enc, sz, global->bank.solana_bank.slot );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L16 */
void fd_sysvar_slot_history_init( fd_global_ctx_t* global ) {
  /* Create a new slot history instance */
  fd_slot_history_t history;
  fd_slot_history_inner_t *inner = (fd_slot_history_inner_t *)(global->allocf)( global->allocf_arg, 8UL, sizeof(fd_slot_history_inner_t) );
  inner->blocks = (ulong*)(global->allocf)( global->allocf_arg, 8UL, sizeof(ulong) * blocks_len );
  memset( inner->blocks, 0, sizeof(ulong) * blocks_len );
  inner->blocks_len = blocks_len;
  history.bits.bits = inner;
  history.bits.len = slot_history_max_entries;

  /* TODO: handle slot != 0 init case */
  set( &history, 0 );
  history.next_slot = 1;

  write_history( global, &history );
  fd_slot_history_destroy( &history, global->freef, global->allocf_arg );
} 

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/bank.rs#L2345 */
void fd_sysvar_slot_history_update( fd_global_ctx_t* global ) {
  /* Set current_slot, and update next_slot */
  fd_slot_history_t history;
  fd_sysvar_slot_history_read( global, &history );

  /* TODO: handle case where current_slot > max_entries */

  /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L48 */
  set( &history, global->bank.solana_bank.slot );
  history.next_slot = global->bank.solana_bank.slot + 1;

  write_history( global, &history );
  fd_slot_history_destroy( &history, global->freef, global->allocf_arg );
}

void fd_sysvar_slot_history_read( fd_global_ctx_t* global, fd_slot_history_t* result ) {
  /* Read the slot history sysvar from the account */
  fd_account_meta_t metadata;
  int               read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_slot_history, &metadata );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account metadata: %d", read_result ));
    return;
  }

  char encoded_hash[50];
  fd_base58_encode_32((uchar *) metadata.hash, 0, encoded_hash);
  FD_LOG_INFO(( "slot history sysvar hash at slot %lu: %48s", global->bank.solana_bank.slot, encoded_hash ));

  unsigned char *raw_acc_data = fd_alloca( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_slot_history, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account data: %d", read_result ));
    return;
  }

  void* input = (void *)raw_acc_data;
  fd_slot_history_decode( result, (const void **)&input, raw_acc_data + metadata.dlen, global->allocf, global->allocf_arg );
}
