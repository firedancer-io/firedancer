#include "fd_sysvar_fees.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"
#include "../fd_runtime.h"
#include "../fd_bank_mgr.h"
#include "../context/fd_exec_epoch_ctx.h"

static void
write_fees( fd_exec_slot_ctx_t* slot_ctx, fd_sysvar_fees_t* fees ) {
  ulong sz = fd_sysvar_fees_size( fees );
  uchar enc[sz];
  fd_memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx = {
    .data    = enc,
    .dataend = enc + sz
  };
  if( fd_sysvar_fees_encode( fees, &ctx ) ) {
    FD_LOG_ERR(( "fd_sysvar_fees_encode failed" ));
  }

  fd_sysvar_set( slot_ctx, &fd_sysvar_owner_id, &fd_sysvar_fees_id, enc, sz, slot_ctx->slot );
}

fd_sysvar_fees_t *
fd_sysvar_fees_read( fd_funk_t *     funk,
                     fd_funk_txn_t * funk_txn,
                     fd_spad_t *     spad ) {

  FD_TXN_ACCOUNT_DECL( acc );
  int err = fd_txn_account_init_from_funk_readonly( acc, &fd_sysvar_fees_id, funk, funk_txn );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) )
    return NULL;

  return fd_bincode_decode_spad(
      sysvar_fees, spad,
      acc->vt->get_data( acc ),
      acc->vt->get_data_len( acc ),
      &err );
}

/*
https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/sdk/program/src/fee_calculator.rs#L105-L165
*/
void
fd_sysvar_fees_new_derived( fd_exec_slot_ctx_t *   slot_ctx,
                            ulong                  latest_singatures_per_slot ) {
  fd_bank_mgr_t            bank_mgr_obj;
  fd_bank_mgr_t *          bank_mgr               = fd_bank_mgr_join( &bank_mgr_obj, slot_ctx->funk, slot_ctx->funk_txn );
  fd_fee_rate_governor_t * base_fee_rate_governor = fd_bank_mgr_fee_rate_governor_query( bank_mgr );
  ulong *                  lamports_per_signature = fd_bank_mgr_lamports_per_signature_query( bank_mgr );

  fd_fee_rate_governor_t me = {
    .target_signatures_per_slot    = base_fee_rate_governor->target_signatures_per_slot,
    .target_lamports_per_signature = base_fee_rate_governor->target_lamports_per_signature,
    .max_lamports_per_signature    = base_fee_rate_governor->max_lamports_per_signature,
    .min_lamports_per_signature    = base_fee_rate_governor->min_lamports_per_signature,
    .burn_percent                  = base_fee_rate_governor->burn_percent
  };

  ulong new_lamports_per_signature = 0;
  if( me.target_signatures_per_slot > 0 ) {
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
    long gap = (long)desired_lamports_per_signature - (long)*lamports_per_signature;
    if ( gap == 0 ) {
      new_lamports_per_signature = desired_lamports_per_signature;
    } else {
      long gap_adjust = (long)(fd_ulong_max( 1UL, (ulong)(me.target_lamports_per_signature / 20) ))
        * (gap != 0)
        * (gap > 0 ? 1 : -1);
      new_lamports_per_signature = fd_ulong_min(
        me.max_lamports_per_signature,
        fd_ulong_max(
          me.min_lamports_per_signature,
          (ulong)((long)*lamports_per_signature + gap_adjust)
        )
      );
    }
  } else {
    new_lamports_per_signature = base_fee_rate_governor->target_lamports_per_signature;
    me.min_lamports_per_signature = me.target_lamports_per_signature;
    me.max_lamports_per_signature = me.target_lamports_per_signature;
  }

  ulong * prev_lamports_per_signature = fd_bank_mgr_prev_lamports_per_signature_modify( bank_mgr );
  if( FD_UNLIKELY( *lamports_per_signature==0UL ) ) {
    *prev_lamports_per_signature = new_lamports_per_signature;
  } else {
    *prev_lamports_per_signature = *lamports_per_signature;
  }
  fd_bank_mgr_prev_lamports_per_signature_save( bank_mgr );

  base_fee_rate_governor = fd_bank_mgr_fee_rate_governor_modify( bank_mgr );
  *base_fee_rate_governor = me;
  fd_bank_mgr_fee_rate_governor_save( bank_mgr );

  lamports_per_signature = fd_bank_mgr_lamports_per_signature_modify( bank_mgr );
  *lamports_per_signature = new_lamports_per_signature;
  fd_bank_mgr_lamports_per_signature_save( bank_mgr );
}

void
fd_sysvar_fees_update( fd_exec_slot_ctx_t * slot_ctx, fd_spad_t * runtime_spad ) {
  if( FD_FEATURE_ACTIVE( slot_ctx->slot, slot_ctx->epoch_ctx->features, disable_fees_sysvar ))
    return;

  fd_sysvar_fees_t * fees = fd_sysvar_fees_read( slot_ctx->funk,
                                                 slot_ctx->funk_txn,
                                                 runtime_spad );
  if( FD_UNLIKELY( fees == NULL ) ) {
    FD_LOG_ERR(( "failed to read sysvar fees" ));
  }

  fd_bank_mgr_t bank_mgr_obj;
  fd_bank_mgr_t * bank_mgr = fd_bank_mgr_join( &bank_mgr_obj, slot_ctx->funk, slot_ctx->funk_txn );
  ulong * lamports_per_signature = fd_bank_mgr_lamports_per_signature_query( bank_mgr );
  fees->fee_calculator.lamports_per_signature = *lamports_per_signature;
  write_fees( slot_ctx, fees );
}

void fd_sysvar_fees_init( fd_exec_slot_ctx_t * slot_ctx ) {
  /* Default taken from https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/fee_calculator.rs#L110 */
  /* TODO: handle non-default case */
  fd_sysvar_fees_t fees = {
    {
      .lamports_per_signature = 0,
    }
  };
  write_fees( slot_ctx, &fees );
}
