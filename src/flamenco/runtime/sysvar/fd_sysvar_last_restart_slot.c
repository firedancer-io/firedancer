#include "fd_sysvar_last_restart_slot.h"
#include "../../../flamenco/types/fd_types.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"

void
fd_sysvar_last_restart_slot_init( fd_exec_slot_ctx_t * slot_ctx ) {

  if( !FD_FEATURE_ACTIVE( slot_ctx, last_restart_slot_sysvar ) ) {
    FD_LOG_INFO(( "sysvar LastRestartSlot not supported by this ledger version!" ));
    return;
  }

  fd_sol_sysvar_last_restart_slot_t const * sysvar = &slot_ctx->slot_bank.last_restart_slot;

  ulong sz = fd_sol_sysvar_last_restart_slot_size( sysvar );
  uchar enc[ sz ];
  fd_memset( enc, 0, sz );

  fd_bincode_encode_ctx_t encode = {
    .data    = enc,
    .dataend = enc + sz,
  };
  int err = fd_sol_sysvar_last_restart_slot_encode( sysvar, &encode );
  FD_TEST( err==FD_BINCODE_SUCCESS );

  fd_sysvar_set( slot_ctx,
                 fd_sysvar_owner_id.key,
                 &fd_sysvar_last_restart_slot_id,
                 enc, sz,
                 slot_ctx->slot_bank.slot,
                 0UL );
}

fd_sol_sysvar_last_restart_slot_t *
fd_sysvar_last_restart_slot_read( fd_sol_sysvar_last_restart_slot_t * result,
                                  fd_exec_slot_ctx_t const *          slot_ctx ) {

  FD_BORROWED_ACCOUNT_DECL(acc);
  int err = fd_acc_mgr_view(slot_ctx->acc_mgr, slot_ctx->funk_txn, &fd_sysvar_last_restart_slot_id, acc);
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) )
    return NULL;

  fd_bincode_decode_ctx_t decode =
    { .data    = acc->const_data,
      .dataend = acc->const_data + acc->const_meta->dlen,
      .valloc  = {0}  /* valloc not required */ };

  if( FD_UNLIKELY( fd_sol_sysvar_last_restart_slot_decode( result, &decode )!=FD_BINCODE_SUCCESS ) )
    return NULL;
  return FD_ACC_MGR_SUCCESS;
}

void
fd_sysvar_last_restart_slot_update( fd_exec_slot_ctx_t * slot_ctx ) {
  if( !FD_FEATURE_ACTIVE( slot_ctx, last_restart_slot_sysvar ) ) return;
  fd_sol_sysvar_last_restart_slot_t result;
  fd_sysvar_last_restart_slot_read( &result, slot_ctx );
  if ( result.slot == slot_ctx->slot_bank.last_restart_slot.slot ) return;

  /* Set this every slot? */
  uchar data[ 8 ];
  memcpy( data, &slot_ctx->slot_bank.last_restart_slot, 8 );
  fd_sysvar_set( slot_ctx, fd_sysvar_owner_id.key,
                 &fd_sysvar_last_restart_slot_id,
                 data, /* sz */ 8UL,
                 slot_ctx->slot_bank.slot,
                 0UL );
}
