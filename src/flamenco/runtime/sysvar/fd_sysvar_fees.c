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

  FD_BORROWED_ACCOUNT_DECL(fees_rec);

  int err = fd_acc_mgr_view( global->acc_mgr, global->funk_txn, (fd_pubkey_t const *)global->sysvar_fees, fees_rec );
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_ERR(( "failed to read fees sysvar: %d", err ));
    return;
  }

  fd_bincode_decode_ctx_t decode = {
    .data    = fees_rec->const_data,
    .dataend = fees_rec->const_data + fees_rec->const_meta->dlen,
    .valloc  = global->valloc
  };

  if( FD_UNLIKELY( fd_sysvar_fees_decode( result, &decode ) ) )
    FD_LOG_ERR(("fd_sysvar_fees_decode failed"));
}

/*
https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/sdk/program/src/fee_calculator.rs#L105-L165
*/
void
fd_sysvar_fees_new_derived(
  fd_global_ctx_t * global,
  fd_fee_rate_governor_t base_fee_rate_governor,
  ulong latest_singatures_per_slot
) {
  fd_fee_rate_governor_t me = {
    .target_signatures_per_slot = base_fee_rate_governor.target_signatures_per_slot,
    .target_lamports_per_signature = base_fee_rate_governor.target_lamports_per_signature,
    .max_lamports_per_signature = base_fee_rate_governor.max_lamports_per_signature,
    .min_lamports_per_signature = base_fee_rate_governor.min_lamports_per_signature,
    .burn_percent = base_fee_rate_governor.burn_percent
  };
  ulong lamports_per_signature = 0;
  if ( me.target_signatures_per_slot > 0 ) {
    me.min_lamports_per_signature = fd_ulong_max( 1UL, (ulong)(me.target_lamports_per_signature / 2) );
    me.max_lamports_per_signature = me.target_lamports_per_signature * 10;
    ulong desired_lamports_per_signature = fd_ulong_min(
      me.max_lamports_per_signature,
      fd_ulong_max(
        me.min_lamports_per_signature,
        me.target_lamports_per_signature
        * fd_ulong_min(latest_singatures_per_slot, (ulong)UINT_MAX)
        / me.target_signatures_per_slot
      )
    );
    long gap = (long)desired_lamports_per_signature - (long)global->bank.lamports_per_signature;
    if ( gap == 0 ) {
      lamports_per_signature = desired_lamports_per_signature;
    } else {
      long gap_adjust = (long)(fd_ulong_max( 1UL, (ulong)(me.target_lamports_per_signature / 20) ))
        * (gap != 0)
        * (gap > 0 ? 1 : -1);
      lamports_per_signature = fd_ulong_min(
        me.min_lamports_per_signature,
        fd_ulong_max(
          me.min_lamports_per_signature,
          (ulong)((long) global->bank.lamports_per_signature + gap_adjust)
        )
      );
    }
  } else {
    lamports_per_signature = base_fee_rate_governor.target_lamports_per_signature;
    me.min_lamports_per_signature = me.target_lamports_per_signature;
    me.max_lamports_per_signature = me.target_lamports_per_signature;
  }

  global->bank.lamports_per_signature = lamports_per_signature;
  fd_memcpy(&global->bank.fee_rate_governor, &me, sizeof(fd_fee_rate_governor_t));

}

void
fd_sysvar_fees_update( fd_global_ctx_t * global ) {
  if ( FD_FEATURE_ACTIVE( global, disable_fees_sysvar ))
    return;
  fd_sysvar_fees_t fees;
  fd_sysvar_fees_read( global, &fees );
  /* todo: I need to the lamports_per_signature field */
  fees.fee_calculator.lamports_per_signature = global->bank.lamports_per_signature;
  write_fees( global, &fees );
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
