#include "fd_sysvar_epoch_schedule.h"
#include "../fd_types.h"
#include "fd_sysvar.h"

void write_epoch_schedule( fd_global_ctx_t* global, fd_epoch_schedule_t* epoch_schedule ) {
  ulong          sz = fd_epoch_schedule_size( epoch_schedule );
  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  void const *ptr = (void const *) enc;
  fd_epoch_schedule_encode( epoch_schedule, &ptr );

  fd_sysvar_set( global, global->sysvar_owner, global->sysvar_epoch_schedule, enc, sz, global->current_slot );
}

void fd_sysvar_epoch_schedule_read( fd_global_ctx_t* global, fd_epoch_schedule_t* result ) {
  fd_account_meta_t metadata;
  int               read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_epoch_schedule, &metadata );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account metadata: %d", read_result ));
    return;
  }

  unsigned char *raw_acc_data = fd_alloca( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_epoch_schedule, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account data: %d", read_result ));
    return;
  }

  void* input = (void *)raw_acc_data;
  fd_epoch_schedule_decode( result, (const void **)&input, raw_acc_data + metadata.dlen, global->allocf, global->allocf_arg );
}

void fd_sysvar_epoch_schedule_init( fd_global_ctx_t* global ) {
  /* Defaults taken from https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/epoch_schedule.rs#L45 */
  /* TODO: handle non-default case */
  fd_epoch_schedule_t epoch_schedule = {
    .slots_per_epoch = 432000,
    .leader_schedule_slot_offset = 432000
//    .first_normal_epoch = 14,
//    .first_normal_slot = 524256,
//    .warmup = 1
  };
  write_epoch_schedule( global, &epoch_schedule );
}
