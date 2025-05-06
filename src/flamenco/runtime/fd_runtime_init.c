#include "fd_runtime_init.h"
#include "fd_runtime_err.h"
#include <stdio.h>
#include "../types/fd_types.h"
#include "context/fd_exec_epoch_ctx.h"
#include "context/fd_exec_slot_ctx.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "fd_bank_mgr.h"
#include "fd_system_ids.h"

/* This file must not depend on fd_executor.h */

int
fd_runtime_save_epoch_bank( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  ulong sz = sizeof(uint) + fd_epoch_bank_size(epoch_bank);
  fd_funk_rec_key_t id = fd_runtime_epoch_bank_key();
  int opt_err = 0;
  fd_funk_rec_prepare_t prepare[1];
  fd_funk_t * funk   = slot_ctx->funk;
  fd_funk_rec_t *rec = fd_funk_rec_prepare(funk, slot_ctx->funk_txn, &id, prepare, &opt_err);
  if (NULL == rec)
  {
    FD_LOG_WARNING(("fd_runtime_save_banks failed: %s", fd_funk_strerror(opt_err)));
    return opt_err;
  }

  uchar *buf = fd_funk_val_truncate(rec, sz, fd_funk_alloc( funk ), fd_funk_wksp(funk), NULL);
  *(uint*)buf = FD_RUNTIME_ENC_BINCODE;
  fd_bincode_encode_ctx_t ctx = {
      .data = buf + sizeof(uint),
      .dataend = buf + sz,
  };

  if (FD_UNLIKELY(fd_epoch_bank_encode(epoch_bank, &ctx) != FD_BINCODE_SUCCESS))
  {
    FD_LOG_WARNING(("fd_runtime_save_banks: fd_firedancer_banks_encode failed"));
    fd_funk_rec_cancel( funk, prepare );
    return -1;
  }
  FD_TEST(ctx.data == ctx.dataend);

  fd_funk_rec_publish( funk, prepare );

  FD_LOG_DEBUG(( "epoch frozen, slot=%lu bank_hash=%s poh_hash=%s", slot_ctx->slot, FD_BASE58_ENC_32_ALLOCA( slot_ctx->slot_bank.banks_hash.hash ), FD_BASE58_ENC_32_ALLOCA( slot_ctx->slot_bank.poh.hash ) ));

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int fd_runtime_save_slot_bank( fd_exec_slot_ctx_t * slot_ctx ) {
  ulong sz = sizeof(uint) + fd_slot_bank_size( &slot_ctx->slot_bank );

  fd_funk_rec_key_t id      = fd_runtime_slot_bank_key();
  int               opt_err = 0;

  fd_funk_t * funk = slot_ctx->funk;

  fd_funk_rec_hard_remove( funk, slot_ctx->funk_txn, &id );

  fd_funk_rec_prepare_t prepare[1];
  fd_funk_rec_t * rec = fd_funk_rec_prepare(funk, slot_ctx->funk_txn, &id, prepare, &opt_err);
  if( !rec ) {
    FD_LOG_WARNING(( "fd_runtime_save_banks failed: %s", fd_funk_strerror( opt_err ) ));
    return opt_err;
  }

  uchar * buf = fd_funk_val_truncate(rec, sz, fd_funk_alloc( funk ), fd_funk_wksp( funk ), NULL);
  *(uint*)buf = FD_RUNTIME_ENC_BINCODE;
  fd_bincode_encode_ctx_t ctx = {
      .data    = buf + sizeof(uint),
      .dataend = buf + sz,
  };

  if( FD_UNLIKELY( fd_slot_bank_encode( &slot_ctx->slot_bank, &ctx ) != FD_BINCODE_SUCCESS ) ) {
    FD_LOG_WARNING(( "fd_runtime_save_banks: fd_firedancer_banks_encode failed" ));
    fd_funk_rec_cancel( funk, prepare );
    return -1;
  }

  if( FD_UNLIKELY( ctx.data!=ctx.dataend ) ) {
    FD_LOG_ERR(( "Data does not equal to end of buffer" ));
  }

  fd_funk_rec_publish( funk, prepare );

  FD_LOG_DEBUG(( "slot frozen, slot=%lu bank_hash=%s poh_hash=%s",
                 slot_ctx->slot,
                 FD_BASE58_ENC_32_ALLOCA( slot_ctx->slot_bank.banks_hash.hash ),
                 FD_BASE58_ENC_32_ALLOCA( slot_ctx->slot_bank.poh.hash ) ));

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

void
fd_runtime_recover_banks( fd_exec_slot_ctx_t * slot_ctx,
                          int                  delete_first,
                          int                  clear_first,
                          fd_spad_t *          runtime_spad ) {

  fd_funk_t *           funk         = slot_ctx->funk;
  fd_funk_txn_t *       txn          = slot_ctx->funk_txn;
  fd_exec_epoch_ctx_t * epoch_ctx    = slot_ctx->epoch_ctx;
  for(;;) {
    fd_funk_rec_key_t id = fd_runtime_epoch_bank_key();
    fd_funk_rec_query_t query[1];
    fd_funk_rec_t const *rec = fd_funk_rec_query_try_global(funk, txn, &id, NULL, query);
    if (rec == NULL)
      FD_LOG_ERR(("failed to read banks record: missing record"));
    void * val = fd_funk_val( rec, fd_funk_wksp(funk) );

    if( fd_funk_val_sz( rec ) < sizeof(uint) ) {
      FD_LOG_ERR(("failed to read banks record: empty record"));
    }
    uint magic = *(uint*)val;
    if( FD_UNLIKELY( magic!=FD_RUNTIME_ENC_BINCODE ) ) {
      FD_LOG_ERR(( "failed to read banks record: invalid magic number" ));
    }

    if( clear_first ) {
      fd_exec_epoch_ctx_bank_mem_clear( epoch_ctx );
    }

    int err;
    fd_epoch_bank_t * epoch_bank = fd_bincode_decode_spad(
        epoch_bank, runtime_spad,
        (uchar*)val           + sizeof(uint),
        fd_funk_val_sz( rec ) - sizeof(uint),
        &err );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "failed to read banks record: invalid decode" ));
      return;
    }

    epoch_ctx->epoch_bank = *epoch_bank;

    FD_LOG_NOTICE(( "recovered epoch_bank" ));

    if( !fd_funk_rec_query_test( query ) ) break;
  }

  for(;;) {
    if( delete_first ) {
      memset( &slot_ctx->slot_bank, 0, sizeof(fd_slot_bank_t) );
    }
    fd_funk_rec_key_t     id  = fd_runtime_slot_bank_key();
    fd_funk_rec_query_t   query[1];
    fd_funk_rec_t const * rec = fd_funk_rec_query_try_global( funk, txn, &id, NULL, query );
    if( FD_UNLIKELY( !rec ) ) {
      FD_LOG_ERR(( "failed to read banks record: missing record" ));
    }
    void * val = fd_funk_val( rec, fd_funk_wksp( funk ) );

    if( fd_funk_val_sz( rec ) < sizeof(uint) ) {
      FD_LOG_ERR(( "failed to read banks record: empty record" ));
    }
    uint magic = *(uint*)val;
    if( FD_UNLIKELY( magic != FD_RUNTIME_ENC_BINCODE ) ) {
      FD_LOG_ERR(("failed to read banks record: invalid magic number"));
    }

    int err;
    fd_slot_bank_t * slot_bank = fd_bincode_decode_spad(
        slot_bank, runtime_spad,
        (uchar*)val           + sizeof(uint),
        fd_funk_val_sz( rec ) - sizeof(uint),
        &err );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "failed to read banks record: invalid decode" ));
    }

    /* FIXME: This memcpy is not good. The slot ctx should just have a pointer
        to a slot_bank that can be assigned at this point. */
    slot_ctx->slot_bank = *slot_bank;

    if( fd_funk_rec_query_test( query ) ) {
      delete_first = 1;
      continue;
    }

    FD_LOG_NOTICE(( "recovered slot_bank for slot=%ld banks_hash=%s poh_hash %s lthash %s",
                    (long)slot_ctx->slot,
                    FD_BASE58_ENC_32_ALLOCA( slot_ctx->slot_bank.banks_hash.hash ),
                    FD_BASE58_ENC_32_ALLOCA( slot_ctx->slot_bank.poh.hash ),
                    FD_LTHASH_ENC_32_ALLOCA( (fd_lthash_value_t *) slot_ctx->slot_bank.lthash.lthash ) ));

    fd_bank_mgr_t bank_mgr_obj = {0};
    fd_bank_mgr_t * bank_mgr = fd_bank_mgr_join( &bank_mgr_obj, slot_ctx->funk, slot_ctx->funk_txn );
    ulong * execution_fees = fd_bank_mgr_execution_fees_modify( bank_mgr );
    *execution_fees = 0;
    fd_bank_mgr_execution_fees_save( bank_mgr );

    slot_ctx->slot_bank.collected_priority_fees = 0;
    slot_ctx->txn_count = 0;
    slot_ctx->nonvote_txn_count = 0;
    slot_ctx->failed_txn_count = 0;
    slot_ctx->nonvote_failed_txn_count = 0;
    slot_ctx->total_compute_units_used = 0;

    break;
  }

}

void
fd_runtime_delete_banks( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_exec_epoch_ctx_epoch_bank_delete( slot_ctx->epoch_ctx );
  memset( &slot_ctx->slot_bank, 0, sizeof(fd_slot_bank_t) );
}


/* fd_feature_restore loads a feature from the accounts database and
   updates the bank's feature activation state, given a feature account
   address. */

static void
fd_feature_restore( fd_exec_slot_ctx_t *    slot_ctx,
                    fd_feature_id_t const * id,
                    uchar const             acct[ static 32 ],
                    fd_spad_t *             runtime_spad ) {

  FD_TXN_ACCOUNT_DECL( acct_rec );
  int err = fd_txn_account_init_from_funk_readonly( acct_rec,
                                                    (fd_pubkey_t *)acct,
                                                    slot_ctx->funk,
                                                    slot_ctx->funk_txn );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    return;
  }

  /* Skip accounts that are not owned by the feature program */
  if( FD_UNLIKELY( memcmp( acct_rec->vt->get_owner( acct_rec ), fd_solana_feature_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    return;
  }

  /* Skip reverted features */
  if( FD_UNLIKELY( id->reverted ) ) {
    return;
  }

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {
    int decode_err;
    fd_feature_t * feature = fd_bincode_decode_spad(
        feature, runtime_spad,
        acct_rec->vt->get_data( acct_rec ),
        acct_rec->vt->get_data_len( acct_rec ),
        &decode_err );
    if( FD_UNLIKELY( decode_err ) ) {
      FD_LOG_ERR(( "Failed to decode feature account %s (%d)", FD_BASE58_ENC_32_ALLOCA( acct ), decode_err ));
    }

    if( feature->has_activated_at ) {
      FD_LOG_INFO(( "Feature %s activated at %lu", FD_BASE58_ENC_32_ALLOCA( acct ), feature->activated_at ));
      fd_features_set( &slot_ctx->epoch_ctx->features, id, feature->activated_at );
    } else {
      FD_LOG_DEBUG(( "Feature %s not activated at %lu", FD_BASE58_ENC_32_ALLOCA( acct ), feature->activated_at ));
    }
    /* No need to call destroy, since we are using fd_spad allocator. */
  } FD_SPAD_FRAME_END;
}

void
fd_features_restore( fd_exec_slot_ctx_t * slot_ctx, fd_spad_t * runtime_spad ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init();
                                   !fd_feature_iter_done( id );
                               id = fd_feature_iter_next( id ) ) {
    fd_feature_restore( slot_ctx, id, id->id.key, runtime_spad );
  }
}
