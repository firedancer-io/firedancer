#include "fd_sysvar_rent.h"
#include "fd_sysvar.h"
#include "../fd_acc_mgr.h"
#include "../fd_system_ids.h"
#include "../context/fd_exec_slot_ctx.h"

#include <assert.h>

void
fd_sysvar_rent_write( fd_exec_slot_ctx_t * slot_ctx,
                      fd_rent_t const *    rent ) {

  uchar enc[ 32 ];

  ulong sz = fd_rent_size( rent );
  FD_TEST( sz<=sizeof(enc) );
  memset( enc, 0, sz );

  fd_bincode_encode_ctx_t ctx;
  ctx.data    = enc;
  ctx.dataend = enc + sz;
  if( fd_rent_encode( rent, &ctx ) )
    FD_LOG_ERR(("fd_rent_encode failed"));

  fd_sysvar_account_update( slot_ctx, &fd_sysvar_rent_id, enc, sz );
}

void
fd_sysvar_rent_init( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_rent_t const * rent = fd_bank_rent_query( slot_ctx->bank );
  fd_sysvar_rent_write( slot_ctx, rent );
}

fd_rent_t const *
fd_sysvar_rent_read( fd_funk_t *     funk,
                     fd_funk_txn_t * funk_txn,
                     fd_spad_t *     spad ) {
  FD_TXN_ACCOUNT_DECL( acc );
  int rc = fd_txn_account_init_from_funk_readonly( acc, &fd_sysvar_rent_id, funk, funk_txn );
  if( FD_UNLIKELY( rc!=FD_ACC_MGR_SUCCESS ) ) {
    return NULL;
  }

  /* This check is needed as a quirk of the fuzzer. If a sysvar account
     exists in the accounts database, but doesn't have any lamports,
     this means that the account does not exist. This wouldn't happen
     in a real execution environment. */
  if( FD_UNLIKELY( acc->vt->get_lamports( acc )==0 ) ) {
    return NULL;
  }

  int err;
  return fd_bincode_decode_spad(
      rent, spad,
      acc->vt->get_data( acc ),
      acc->vt->get_data_len( acc ),
      &err );
}
