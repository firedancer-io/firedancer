#include "fd_sysvar_fees.h"
#include "../../../flamenco/types/fd_types.h"
#include "fd_sysvar.h"

static void
write_fees( fd_global_ctx_t* global, fd_sysvar_fees_t* fees ) {
  ulong          sz = fd_sysvar_fees_size( fees );
  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  if ( fd_sysvar_fees_encode( fees, &ctx ) )
    FD_LOG_ERR(("fd_sysvar_fees_encode failed"));

  fd_sysvar_set( global, global->sysvar_owner, (fd_pubkey_t *) global->sysvar_fees, enc, sz, global->bank.slot, NULL );
}

void
fd_sysvar_fees_read( fd_global_ctx_t  * global,
                     fd_sysvar_fees_t * result ) {

  int err = 0;
  uchar const * record = fd_acc_mgr_view_raw( global->acc_mgr, global->funk_txn, (fd_pubkey_t const *)global->sysvar_fees, NULL, &err );
  if( FD_UNLIKELY( !record ) ) {
    FD_LOG_ERR(( "failed to read fees sysvar: %d", err ));
    return;
  }

  fd_account_meta_t const * metadata     = (fd_account_meta_t const *)record;
  uchar const *             raw_acc_data = record + metadata->hlen;

  fd_bincode_decode_ctx_t decode = {
    .data    = raw_acc_data,
    .dataend = raw_acc_data + metadata->dlen,
    .valloc  = global->valloc
  };

  if( FD_UNLIKELY( fd_sysvar_fees_decode( result, &decode ) ) )
    FD_LOG_ERR(("fd_sysvar_fees_decode failed"));
}

void fd_sysvar_fees_init( fd_global_ctx_t* global ) {
  /* Default taken from https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/fee_calculator.rs#L110 */
  /* TODO: handle non-default case */
  fd_sysvar_fees_t fees = {
    {
      .lamports_per_signature = 0,
    }
  };
  write_fees( global, &fees );
}
