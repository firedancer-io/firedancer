#include "fd_sysvar_last_restart_slot.h"
#include "../../../flamenco/types/fd_types.h"
#include "fd_sysvar.h"

void
fd_sysvar_last_restart_slot_init( fd_global_ctx_t * global ) {

  if( !FD_FEATURE_ACTIVE( global, last_restart_slot_sysvar ) ) {
    FD_LOG_INFO(( "sysvar LastRestartSlot not supported by this ledger version!" ));
    return;
  }

  fd_sol_sysvar_last_restart_slot_t const * sysvar = &global->bank.last_restart_slot;

  ulong sz = fd_sol_sysvar_last_restart_slot_size( sysvar );
  uchar enc[ sz ];
  fd_memset( enc, 0, sz );

  fd_bincode_encode_ctx_t encode = {
    .data    = enc,
    .dataend = enc + sz,
  };
  int err = fd_sol_sysvar_last_restart_slot_encode( sysvar, &encode );
  FD_TEST( err==FD_BINCODE_SUCCESS );

  fd_sysvar_set( global,
                 global->sysvar_owner,
                 (fd_pubkey_t const *)global->sysvar_last_restart_slot,
                 enc, sz,
                 global->bank.slot,
                 NULL );
}

int
fd_sysvar_last_restart_slot_read( fd_global_ctx_t const *             global,
                                  fd_sol_sysvar_last_restart_slot_t * result ) {

  FD_BORROWED_ACCOUNT_DECL(rec);
  int err = fd_acc_mgr_view(global->acc_mgr, global->funk_txn, (fd_pubkey_t const *)global->sysvar_last_restart_slot, rec);

  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) )
    return err;

  fd_bincode_decode_ctx_t decode = {
    .data    = rec->const_data,
    .dataend = rec->const_data + rec->const_meta->dlen
    /* deliberately not setting valloc here, as the data structure
       does not need dynamic allocations */
  };

  err = fd_sol_sysvar_last_restart_slot_decode( result, &decode );
  FD_TEST( err==FD_BINCODE_SUCCESS );

  return FD_ACC_MGR_SUCCESS;
}

void
fd_sysvar_last_restart_slot_update( fd_global_ctx_t * global ) {
  if( !FD_FEATURE_ACTIVE( global, last_restart_slot_sysvar ) ) return;

  /* Set this every slot? */
  uchar data[ 8 ];
  memcpy( data, &global->bank.last_restart_slot, 8 );
  fd_sysvar_set( global, global->sysvar_owner,
                 (fd_pubkey_t const *)global->sysvar_last_restart_slot,
                 data, /* sz */ 8UL,
                 global->bank.slot,
                 NULL );
}
