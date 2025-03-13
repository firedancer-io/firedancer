#include "fd_runtime_init.h"
#include "fd_runtime_err.h"
#include <stdio.h>
#include "../types/fd_types.h"
#include "context/fd_exec_epoch_ctx.h"
#include "context/fd_exec_slot_ctx.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "fd_system_ids.h"

/* This file must not depend on fd_executor.h */

fd_funk_rec_key_t
fd_runtime_epoch_bank_key( void ) {
  fd_funk_rec_key_t id;
  fd_memset(&id, 1, sizeof(id));
  id.c[FD_FUNK_REC_KEY_FOOTPRINT - 1] = FD_BLOCK_EPOCH_BANK_TYPE;

  return id;
}

fd_funk_rec_key_t
fd_runtime_slot_bank_key( void ) {
  fd_funk_rec_key_t id;
  fd_memset(&id, 1, sizeof(id));
  id.c[FD_FUNK_REC_KEY_FOOTPRINT - 1] = FD_BLOCK_SLOT_BANK_TYPE;

  return id;
}

int
fd_runtime_save_epoch_bank( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  ulong sz = sizeof(uint) + fd_epoch_bank_size(epoch_bank);
  fd_funk_rec_key_t id = fd_runtime_epoch_bank_key();
  int opt_err = 0;
  fd_funk_rec_t * rec = fd_funk_rec_write_prepare( slot_ctx->acc_mgr->funk, slot_ctx->funk_txn, &id, sz, 1, NULL, &opt_err );
  if (NULL == rec)
  {
    FD_LOG_WARNING(("fd_runtime_save_banks failed: %s", fd_funk_strerror(opt_err)));
    return opt_err;
  }

  uchar *buf = fd_funk_val(rec, fd_funk_wksp(slot_ctx->acc_mgr->funk));
  *(uint*)buf = FD_RUNTIME_ENC_BINCODE;
  fd_bincode_encode_ctx_t ctx = {
      .data = buf + sizeof(uint),
      .dataend = buf + sz,
  };

  if (FD_UNLIKELY(fd_epoch_bank_encode(epoch_bank, &ctx) != FD_BINCODE_SUCCESS))
  {
    FD_LOG_WARNING(("fd_runtime_save_banks: fd_firedancer_banks_encode failed"));
    return -1;
  }
  FD_TEST(ctx.data == ctx.dataend);

  FD_LOG_DEBUG(( "epoch frozen, slot=%lu bank_hash=%s poh_hash=%s", slot_ctx->slot_bank.slot, FD_BASE58_ENC_32_ALLOCA( slot_ctx->slot_bank.banks_hash.hash ), FD_BASE58_ENC_32_ALLOCA( slot_ctx->slot_bank.poh.hash ) ));

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int fd_runtime_save_slot_bank( fd_exec_slot_ctx_t * slot_ctx ) {
  ulong sz = sizeof(uint) + fd_slot_bank_size( &slot_ctx->slot_bank );

  fd_funk_rec_key_t id      = fd_runtime_slot_bank_key();
  int               opt_err = 0;
  fd_funk_rec_t *   rec     = fd_funk_rec_write_prepare( slot_ctx->acc_mgr->funk,
                                                         slot_ctx->funk_txn,
                                                         &id,
                                                         sz,
                                                         1,
                                                         NULL,
                                                         &opt_err );
  if( !rec ) {
    FD_LOG_WARNING(( "fd_runtime_save_banks failed: %s", fd_funk_strerror( opt_err ) ));
    return opt_err;
  }

  uchar * buf = fd_funk_val( rec, fd_funk_wksp( slot_ctx->acc_mgr->funk ) );
  *(uint*)buf = FD_RUNTIME_ENC_BINCODE;
  fd_bincode_encode_ctx_t ctx = {
      .data    = buf + sizeof(uint),
      .dataend = buf + sz,
  };

  if( FD_UNLIKELY( fd_slot_bank_encode( &slot_ctx->slot_bank, &ctx ) != FD_BINCODE_SUCCESS ) ) {
    FD_LOG_WARNING(( "fd_runtime_save_banks: fd_firedancer_banks_encode failed" ));
    return -1;
  }

  if( FD_UNLIKELY( ctx.data!=ctx.dataend ) ) {
    FD_LOG_ERR(( "Data does not equal to end of buffer" ));
  }

  FD_LOG_DEBUG(( "slot frozen, slot=%lu bank_hash=%s poh_hash=%s",
                 slot_ctx->slot_bank.slot,
                 FD_BASE58_ENC_32_ALLOCA( slot_ctx->slot_bank.banks_hash.hash ),
                 FD_BASE58_ENC_32_ALLOCA( slot_ctx->slot_bank.poh.hash ) ));

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

void
fd_runtime_recover_banks( fd_exec_slot_ctx_t * slot_ctx,
                          int                  delete_first,
                          int                  clear_first,
                          fd_spad_t *          runtime_spad ) {

  fd_funk_t *           funk         = slot_ctx->acc_mgr->funk;
  fd_funk_txn_t *       txn          = slot_ctx->funk_txn;
  fd_exec_epoch_ctx_t * epoch_ctx    = slot_ctx->epoch_ctx;
  {
    fd_funk_rec_key_t id = fd_runtime_epoch_bank_key();
    fd_funk_rec_t const * rec = fd_funk_rec_query_global(funk, txn, &id, NULL);
    if ( rec == NULL )
      FD_LOG_ERR(("failed to read banks record: missing record"));
    void * val = fd_funk_val( rec, fd_funk_wksp(funk) );

    if( fd_funk_val_sz( rec ) < sizeof(uint) ) {
      FD_LOG_ERR(("failed to read banks record: empty record"));
    }
    uint magic = *(uint*)val;

    if( clear_first ) {
      fd_exec_epoch_ctx_bank_mem_clear( epoch_ctx );
    }

    fd_bincode_decode_ctx_t ctx = {
      .data    = (uchar*)val + sizeof(uint),
      .dataend = (uchar*)val + fd_funk_val_sz( rec )
    };
    if( magic==FD_RUNTIME_ENC_BINCODE ) {

      ulong total_sz = 0UL;
      int   err      = fd_epoch_bank_decode_footprint( &ctx, &total_sz );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "failed to read banks record: invalid decode" ));
        return;
      }

      uchar * mem = fd_spad_alloc( runtime_spad, fd_epoch_bank_align(), total_sz );
      if( FD_UNLIKELY( !mem ) ) {
        FD_LOG_ERR(( "failed to read banks record: unable to allocate memory" ));
      }

      fd_epoch_bank_decode( mem, &ctx );

      epoch_ctx->epoch_bank = *(fd_epoch_bank_t *)mem;
    } else {
      FD_LOG_ERR(( "failed to read banks record: invalid magic number" ));
    }

    FD_LOG_NOTICE(( "recovered epoch_bank" ));
  }

  {
    if( delete_first ) {
      fd_slot_bank_destroy( &slot_ctx->slot_bank );
    }
    fd_funk_rec_key_t     id  = fd_runtime_slot_bank_key();
    fd_funk_rec_t const * rec = fd_funk_rec_query_global( funk, txn, &id, NULL );
    if( FD_UNLIKELY( !rec ) ) {
      FD_LOG_ERR(( "failed to read banks record: missing record" ));
    }
    void * val = fd_funk_val( rec, fd_funk_wksp( funk ) );

    if( fd_funk_val_sz( rec ) < sizeof(uint) ) {
      FD_LOG_ERR(( "failed to read banks record: empty record" ));
    }
    uint magic = *(uint*)val;

    fd_bincode_decode_ctx_t ctx = {
      .data    = (uchar*)val + sizeof(uint),
      .dataend = (uchar*)val + fd_funk_val_sz( rec ),
    };
    if( magic == FD_RUNTIME_ENC_BINCODE ) {

      ulong total_sz = 0UL;
      int   err      = fd_slot_bank_decode_footprint( &ctx, &total_sz );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_ERR(( "failed to read banks record: invalid decode" ));
      }

      uchar * mem = fd_spad_alloc( runtime_spad, fd_slot_bank_align(), total_sz );
      if( FD_UNLIKELY( !mem ) ) {
        FD_LOG_ERR(( "failed to read banks record: unable to allocate memory" ));
      }

      fd_slot_bank_decode( mem, &ctx );

      /* FIXME: This memcpy is not good. The slot ctx should just have a pointer
         to a slot_bank that can be assigned at this point. */
      memcpy( &slot_ctx->slot_bank, mem, sizeof(fd_slot_bank_t) );

    } else {
      FD_LOG_ERR(("failed to read banks record: invalid magic number"));
    }

    FD_LOG_NOTICE(( "recovered slot_bank for slot=%ld banks_hash=%s poh_hash %s lthash %s",
                    (long)slot_ctx->slot_bank.slot,
                    FD_BASE58_ENC_32_ALLOCA( slot_ctx->slot_bank.banks_hash.hash ),
                    FD_BASE58_ENC_32_ALLOCA( slot_ctx->slot_bank.poh.hash ),
                    FD_LTHASH_ENC_32_ALLOCA( (fd_lthash_value_t *) slot_ctx->slot_bank.lthash.lthash ) ));

    slot_ctx->slot_bank.collected_execution_fees = 0;
    slot_ctx->slot_bank.collected_priority_fees = 0;
    slot_ctx->slot_bank.collected_rent = 0;
    slot_ctx->txn_count = 0;
    slot_ctx->nonvote_txn_count = 0;
    slot_ctx->failed_txn_count = 0;
    slot_ctx->nonvote_failed_txn_count = 0;
    slot_ctx->total_compute_units_used = 0;
  }

}

void
fd_runtime_delete_banks( fd_exec_slot_ctx_t * slot_ctx ) {

  /* As the collection pointers are not owned by fd_alloc, zero them
     out to prevent invalid frees by the destroy function.

     TODO: This free actually doesn't do anything because of spad. */

  fd_exec_epoch_ctx_epoch_bank_delete( slot_ctx->epoch_ctx );
  fd_slot_bank_destroy( &slot_ctx->slot_bank );
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
  int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, (fd_pubkey_t *)acct, acct_rec );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    return;
  }

  /* Skip accounts that are not owned by the feature program */
  if( FD_UNLIKELY( memcmp( acct_rec->const_meta->info.owner, fd_solana_feature_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    return;
  }

  /* Skip reverted features */
  if( FD_UNLIKELY( id->reverted ) ) {
    return;
  }

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

    fd_bincode_decode_ctx_t ctx = {
      .data    = acct_rec->const_data,
      .dataend = acct_rec->const_data + acct_rec->const_meta->dlen,
    };

    ulong total_sz   = 0UL;
    int   decode_err = fd_feature_decode_footprint( &ctx, &total_sz );
    if( FD_UNLIKELY( decode_err!=FD_BINCODE_SUCCESS ) ) {
      FD_LOG_ERR(( "Failed to decode feature account %s (%d)", FD_BASE58_ENC_32_ALLOCA( acct ), decode_err ));
    }

    uchar * mem = fd_spad_alloc( runtime_spad, fd_feature_align(), total_sz );
    if( FD_UNLIKELY( !mem ) ) {
      FD_LOG_ERR(( "Failed to allocate memory for feature account %s", FD_BASE58_ENC_32_ALLOCA( acct ) ));
    }

    fd_feature_t * feature = fd_feature_decode( mem, &ctx );

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
