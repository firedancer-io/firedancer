#include "fd_sysvar_slot_history.h"
#include "../../../flamenco/types/fd_types.h"
#include "fd_sysvar.h"

const ulong slot_history_min_account_size = 131097;

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L37 */
const ulong slot_history_max_entries = 1024 * 1024;

/* TODO: move into seperate bitvec library */
const ulong bits_per_block = 8 * sizeof(ulong);
void fd_sysvar_slot_history_set( fd_slot_history_t* history, ulong i ) {
  ulong block_idx = (i / bits_per_block) % (history->bits.bits->blocks_len);
  history->bits.bits->blocks[ block_idx ] |= ( 1UL << ( i % bits_per_block ) );
}

const ulong blocks_len = slot_history_max_entries / bits_per_block;

int fd_sysvar_slot_history_write_history( fd_global_ctx_t* global, fd_slot_history_t* history ) {
  ulong          sz = fd_slot_history_size( history );
  if (sz < slot_history_min_account_size)
    sz = slot_history_min_account_size;
  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  int err = fd_slot_history_encode( history, &ctx );
  if (0 != err)
    return err;
  return fd_sysvar_set( global, global->sysvar_owner, (fd_pubkey_t *) global->sysvar_slot_history, enc, sz, global->bank.slot );
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
  fd_sysvar_slot_history_set( &history, global->bank.slot );
  history.next_slot = global->bank.slot + 1;

  fd_sysvar_slot_history_write_history( global, &history );
  fd_bincode_destroy_ctx_t ctx;
  ctx.freef = global->freef;
  ctx.freef_arg = global->allocf_arg;
  fd_slot_history_destroy( &history, &ctx );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/bank.rs#L2345 */
int fd_sysvar_slot_history_update( fd_global_ctx_t* global ) {
  /* Set current_slot, and update next_slot */
  fd_slot_history_t history;
  fd_slot_history_new(&history);

  int err = 0;
  fd_funk_rec_t const *con_rec = NULL;
  char * raw_acc_data = (char*) fd_acc_mgr_view_data(global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_slot_history , &con_rec, &err);
  if (NULL == raw_acc_data)
    return err;
  fd_account_meta_t *m = (fd_account_meta_t *) raw_acc_data;

  fd_bincode_decode_ctx_t ctx;
  ctx.data = raw_acc_data + m->hlen;
  ctx.dataend = (uchar *) ctx.data + m->dlen;
  ctx.allocf = global->allocf;
  ctx.allocf_arg = global->allocf_arg;
  err = fd_slot_history_decode( &history, &ctx );
  if (0 != err)
    return err;

  /* TODO: handle case where current_slot > max_entries */

  /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L48 */
  fd_sysvar_slot_history_set( &history, global->bank.slot );
  history.next_slot = global->bank.slot + 1;

  ulong          sz = fd_slot_history_size( &history );
  if (sz < slot_history_min_account_size)
    sz = slot_history_min_account_size;

  fd_funk_rec_t * acc_data_rec = NULL;

  ulong acc_sz = sizeof(fd_account_meta_t) + sz;

  raw_acc_data = fd_acc_mgr_modify_data(global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_slot_history, 1, &acc_sz, con_rec, &acc_data_rec, &err);
  if ( FD_UNLIKELY (NULL == raw_acc_data) )
    return FD_ACC_MGR_ERR_READ_FAILED;

  m = (fd_account_meta_t *)raw_acc_data;

  fd_bincode_encode_ctx_t e_ctx;
  e_ctx.data = raw_acc_data + m->hlen;
  e_ctx.dataend = (char*)e_ctx.data + sz;
  err = fd_slot_history_encode( &history, &e_ctx );
  if (0 != err)
    return err;

  m->info.lamports = (sz + 128) * ((ulong) ((double)global->bank.rent.lamports_per_uint8_year * global->bank.rent.exemption_threshold));

  m->dlen = sz;
  fd_memcpy(m->info.owner, global->sysvar_owner, 32);

  err = fd_acc_mgr_commit_data(global->acc_mgr, acc_data_rec, (fd_pubkey_t *) global->sysvar_slot_history, raw_acc_data, global->bank.slot, 0);

  fd_bincode_destroy_ctx_t ctx_d;
  ctx_d.freef = global->freef;
  ctx_d.freef_arg = global->allocf_arg;
  fd_slot_history_destroy( &history, &ctx_d );

  return err;
}
