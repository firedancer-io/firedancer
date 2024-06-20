#include "fd_runtime_init.h"
#include "fd_runtime_err.h"
#include "../types/fd_types.h"
#include "context/fd_exec_epoch_ctx.h"
#include "context/fd_exec_slot_ctx.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

/* This file must not depend on fd_executor.h */

fd_funk_rec_key_t
fd_runtime_firedancer_bank_key( void ) {
  fd_funk_rec_key_t id;
  fd_memset(&id, 1, sizeof(id));
  id.c[FD_FUNK_REC_KEY_FOOTPRINT - 1] = FD_BLOCK_BANKS_TYPE;

  return id;
}

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
  ulong sz = fd_epoch_bank_size(epoch_bank);
  fd_funk_rec_key_t id = fd_runtime_epoch_bank_key();
  int opt_err = 0;
  fd_funk_rec_t *rec = fd_funk_rec_write_prepare(slot_ctx->acc_mgr->funk, slot_ctx->funk_txn, &id, sz, 1, NULL, &opt_err);
  if (NULL == rec)
  {
    FD_LOG_WARNING(("fd_runtime_save_banks failed: %s", fd_funk_strerror(opt_err)));
    return opt_err;
  }

  uchar *buf = fd_funk_val(rec, fd_funk_wksp(slot_ctx->acc_mgr->funk));
  fd_bincode_encode_ctx_t ctx = {
      .data = buf,
      .dataend = buf + sz,
  };

  if (FD_UNLIKELY(fd_epoch_bank_encode(epoch_bank, &ctx) != FD_BINCODE_SUCCESS))
  {
    FD_LOG_WARNING(("fd_runtime_save_banks: fd_firedancer_banks_encode failed"));
    return -1;
  }

  FD_LOG_DEBUG(("epoch frozen, slot=%d bank_hash=%32J poh_hash=%32J", slot_ctx->slot_bank.slot, slot_ctx->slot_bank.banks_hash.hash, slot_ctx->slot_bank.poh.hash));

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int fd_runtime_save_slot_bank(fd_exec_slot_ctx_t *slot_ctx)
{
  ulong sz = fd_slot_bank_size(&slot_ctx->slot_bank);

  fd_funk_rec_key_t id = fd_runtime_slot_bank_key();
  int opt_err = 0;
  fd_funk_rec_t *rec = fd_funk_rec_write_prepare(slot_ctx->acc_mgr->funk, slot_ctx->funk_txn, &id, sz, 1, NULL, &opt_err);
  if (NULL == rec)
  {
    FD_LOG_WARNING(("fd_runtime_save_banks failed: %s", fd_funk_strerror(opt_err)));
    return opt_err;
  }

  uchar *buf = fd_funk_val(rec, fd_funk_wksp(slot_ctx->acc_mgr->funk));
  fd_bincode_encode_ctx_t ctx = {
      .data = buf,
      .dataend = buf + sz,
  };
  if (FD_UNLIKELY(fd_slot_bank_encode(&slot_ctx->slot_bank, &ctx) != FD_BINCODE_SUCCESS))
  {
    FD_LOG_WARNING(("fd_runtime_save_banks: fd_firedancer_banks_encode failed"));
    return -1;
  }

  // FD_LOG_DEBUG(("slot frozen, slot=%d bank_hash=%32J poh_hash=%32J", slot_ctx->slot_bank.slot, slot_ctx->slot_bank.banks_hash.hash, slot_ctx->slot_bank.poh.hash));
  slot_ctx->slot_bank.block_height += 1UL;

  // Update blockstore
  if ( slot_ctx->blockstore != NULL ) {
    fd_blockstore_block_height_set(
        slot_ctx->blockstore, slot_ctx->slot_bank.slot, slot_ctx->slot_bank.block_height );
  } else {
    FD_LOG_WARNING(( "NULL blockstore in slot_ctx" ));
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

void
fd_runtime_recover_banks( fd_exec_slot_ctx_t * slot_ctx, int delete_first ) {
  fd_funk_t *           funk        = slot_ctx->acc_mgr->funk;
  fd_funk_txn_t *       txn         = slot_ctx->funk_txn;
  fd_exec_epoch_ctx_t * epoch_ctx   = slot_ctx->epoch_ctx;
  fd_epoch_bank_t *     epoch_bank  = fd_exec_epoch_ctx_epoch_bank( epoch_ctx );
  fd_valloc_t           epoch_valloc = fd_scratch_virtual();
  {
    fd_funk_rec_key_t id = fd_runtime_epoch_bank_key();
    fd_funk_rec_t const * rec = fd_funk_rec_query_global(funk, txn, &id);
    if ( rec == NULL )
      FD_LOG_ERR(("failed to read banks record"));
    void * val = fd_funk_val( rec, fd_funk_wksp(funk) );

    fd_exec_epoch_ctx_bank_mem_clear( epoch_ctx );
    fd_bincode_decode_ctx_t ctx;
    ctx.data = val;
    ctx.dataend = (uchar*)val + fd_funk_val_sz( rec );
    ctx.valloc  = epoch_valloc;
    FD_TEST( fd_epoch_bank_decode_no_malloc( epoch_bank, &ctx, epoch_ctx )==FD_BINCODE_SUCCESS );

    FD_LOG_NOTICE(( "recovered epoch_bank" ));
  }

  {
    if ( delete_first ) {
      fd_bincode_destroy_ctx_t ctx;
      ctx.valloc  = slot_ctx->valloc;
      fd_slot_bank_destroy(&slot_ctx->slot_bank, &ctx);
    }
    fd_funk_rec_key_t id = fd_runtime_slot_bank_key();
    fd_funk_rec_t const * rec = fd_funk_rec_query_global(funk, txn, &id);
    if ( rec == NULL )
      FD_LOG_ERR(("failed to read banks record"));
    void * val = fd_funk_val( rec, fd_funk_wksp(funk) );
    fd_bincode_decode_ctx_t ctx;
    ctx.data = val;
    ctx.dataend = (uchar*)val + fd_funk_val_sz( rec );
    ctx.valloc  = slot_ctx->valloc;
    FD_TEST( fd_slot_bank_decode(&slot_ctx->slot_bank, &ctx )==FD_BINCODE_SUCCESS );

    FD_LOG_NOTICE(( "recovered slot_bank for slot=%ld banks_hash=%32J poh_hash %32J lthash %32J",
                    (long)slot_ctx->slot_bank.slot,
                    slot_ctx->slot_bank.banks_hash.hash,
                    slot_ctx->slot_bank.poh.hash,
                    slot_ctx->slot_bank.lthash ));

    slot_ctx->slot_bank.collected_fees = 0;
    slot_ctx->slot_bank.collected_rent = 0;
  }

}

void
fd_runtime_delete_banks( fd_exec_slot_ctx_t * slot_ctx ) {

  /* As the collection pointers are not owned by fd_alloc, zero them
     out to prevent invalid frees by the destroy function. */

  fd_bincode_destroy_ctx_t ctx = { .valloc = slot_ctx->valloc };
  fd_exec_epoch_ctx_epoch_bank_delete( slot_ctx->epoch_ctx );
  fd_slot_bank_destroy( &slot_ctx->slot_bank, &ctx );
}


/* fd_feature_restore loads a feature from the accounts database and
   updates the bank's feature activation state, given a feature account
   address. */

static void
fd_feature_restore( fd_exec_slot_ctx_t * slot_ctx,
                    fd_feature_id_t const * id,
                    uchar const       acct[ static 32 ] ) {

  FD_BORROWED_ACCOUNT_DECL(acct_rec);
  int err = fd_acc_mgr_view(slot_ctx->acc_mgr, slot_ctx->funk_txn, (fd_pubkey_t *)acct, acct_rec);
  if (FD_UNLIKELY(err != FD_ACC_MGR_SUCCESS))
    return;

  fd_feature_t feature[1];

  FD_SCRATCH_SCOPE_BEGIN
  {

    fd_bincode_decode_ctx_t ctx = {
        .data = acct_rec->const_data,
        .dataend = acct_rec->const_data + acct_rec->const_meta->dlen,
        .valloc = fd_scratch_virtual(),
    };
    int decode_err = fd_feature_decode(feature, &ctx);
    if (FD_UNLIKELY(decode_err != FD_BINCODE_SUCCESS))
    {
      FD_LOG_ERR(("Failed to decode feature account %32J (%d)", acct, decode_err));
      return;
    }

    if( feature->has_activated_at ) {
      FD_LOG_INFO(( "Feature %32J activated at %lu", acct, feature->activated_at ));
      fd_features_set(&slot_ctx->epoch_ctx->features, id, feature->activated_at);
    } else {
      FD_LOG_DEBUG(( "Feature %32J not activated at %lu", acct, feature->activated_at ));
    }
    /* No need to call destroy, since we are using fd_scratch allocator. */
  } FD_SCRATCH_SCOPE_END;
}

void
fd_features_restore( fd_exec_slot_ctx_t * slot_ctx ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init();
                                   !fd_feature_iter_done( id );
                               id = fd_feature_iter_next( id ) ) {
    fd_feature_restore( slot_ctx, id, id->id.key );
  }
}
