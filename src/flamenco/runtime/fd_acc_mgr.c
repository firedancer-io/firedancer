#include "fd_acc_mgr.h"
#include "../../ballet/base58/fd_base58.h"
#include "context/fd_exec_epoch_ctx.h"
#include "context/fd_exec_slot_ctx.h"
#include "fd_rent_lists.h"
#include "sysvar/fd_sysvar_rent.h"
#include <assert.h>

fd_acc_mgr_t *
fd_acc_mgr_new( void *      mem,
                fd_funk_t * funk ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_ACC_MGR_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_memset( mem, 0, FD_ACC_MGR_FOOTPRINT );

  fd_acc_mgr_t * acc_mgr = fd_type_pun( mem );
  acc_mgr->funk = funk;
  return acc_mgr;

}

void *
fd_acc_mgr_delete( fd_acc_mgr_t * acc_mgr ) {

  if( FD_UNLIKELY( !acc_mgr ) ) return NULL;

  memset( acc_mgr, 0, FD_ACC_MGR_FOOTPRINT );
  return acc_mgr;
}

static ulong
fd_rent_lists_key_to_bucket( fd_acc_mgr_t * acc_mgr,
                             fd_funk_rec_t const * rec ) {
  fd_pubkey_t const * key = fd_type_pun_const( &rec->pair.key[0].uc );
  ulong prefixX_be = key->ul[0];
  ulong prefixX    = fd_ulong_bswap( prefixX_be );
  return fd_rent_key_to_partition( prefixX, acc_mgr->part_width, acc_mgr->slots_per_epoch );
}

static uint
fd_rent_lists_cb( fd_funk_rec_t * rec,
                  uint            part_cnt,
                  void *          cb_arg ) {
  (void)part_cnt;

  fd_exec_slot_ctx_t * slot_ctx = (fd_exec_slot_ctx_t *)cb_arg;
  fd_acc_mgr_t *       acc_mgr  = slot_ctx->acc_mgr;

  if( fd_funk_key_is_acc( rec->pair.key ) ) {
    if( acc_mgr->skip_rent_rewrites ) {
      void const * data = fd_funk_val( rec, fd_funk_wksp(acc_mgr->funk) );
      fd_account_meta_t const * metadata = fd_type_pun_const( data );

      ulong required_balance = fd_rent_exempt_minimum_balance2( &slot_ctx->epoch_ctx->epoch_bank.rent, metadata->dlen );
      if( required_balance <= metadata->info.lamports )
        return FD_FUNK_PART_NULL;
    }

    return (uint)fd_rent_lists_key_to_bucket( acc_mgr, rec );
  }

  return FD_FUNK_PART_NULL;
}

void
fd_acc_mgr_set_slots_per_epoch( fd_exec_slot_ctx_t * slot_ctx,
                                ulong                slots_per_epoch ) {

  fd_acc_mgr_t * acc_mgr = slot_ctx->acc_mgr;

  /* Handle feature activation of 'skip_rent_rewrites' or change of
     slots_per_epoch. */

  int skip_rent_rewrites = FD_FEATURE_ACTIVE( slot_ctx, skip_rent_rewrites );

  if( ( slots_per_epoch    == acc_mgr->slots_per_epoch    ) &
      ( skip_rent_rewrites == acc_mgr->skip_rent_rewrites ) )
    return;

  acc_mgr->slots_per_epoch = slots_per_epoch;
  acc_mgr->part_width      = fd_rent_partition_width( slots_per_epoch );

  fd_funk_repartition( acc_mgr->funk, (uint)slots_per_epoch, fd_rent_lists_cb, slot_ctx );
}

fd_account_meta_t const *
fd_acc_mgr_view_raw( fd_acc_mgr_t *         acc_mgr,
                     fd_funk_txn_t const *  txn,
                     fd_pubkey_t const *    pubkey,
                     fd_funk_rec_t const ** orec,
                     int *                  opt_err ) {

  fd_funk_rec_key_t id   = fd_acc_funk_key( pubkey );
  fd_funk_t *       funk = acc_mgr->funk;

  fd_funk_rec_t const * rec = fd_funk_rec_query_global( funk, txn, &id );

  if( FD_UNLIKELY( !rec || !!( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) )  {
    fd_int_store_if( !!opt_err, opt_err, FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT );
    return NULL;
  }
  if (NULL != orec)
    *orec = rec;

  void const * raw = fd_funk_val( rec, fd_funk_wksp(funk) );
  // TODO/FIXME: this check causes issues with some metadata writes

  fd_account_meta_t const * metadata = fd_type_pun_const( raw );
  if( metadata->magic != FD_ACCOUNT_META_MAGIC )
    return NULL;

  return metadata;
}

int
fd_acc_mgr_view( fd_acc_mgr_t *          acc_mgr,
                 fd_funk_txn_t const *   txn,
                 fd_pubkey_t const *     pubkey,
                 fd_borrowed_account_t * account) {

  int err = FD_ACC_MGR_SUCCESS;
  fd_account_meta_t const * meta = fd_acc_mgr_view_raw( acc_mgr, txn, pubkey, &account->const_rec, &err );
  if (FD_UNLIKELY( !fd_acc_exists( meta ) ) ) {
    if (err != FD_ACC_MGR_SUCCESS)
      return err;
    return FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT;
  }

  FD_TEST(FD_BORROWED_ACCOUNT_MAGIC == account->magic);

  fd_memcpy(account->pubkey, pubkey, sizeof(fd_pubkey_t));

  if( FD_UNLIKELY( meta->magic != FD_ACCOUNT_META_MAGIC ) )
    return FD_ACC_MGR_ERR_WRONG_MAGIC;

  account->orig_rec = account->const_rec;
  account->orig_meta = account->const_meta = meta;
  account->orig_data = account->const_data = (uchar const *)meta + meta->hlen;

  if (ULONG_MAX == account->starting_dlen)
    account->starting_dlen = meta->dlen;

  if (ULONG_MAX == account->starting_lamports)
    account->starting_lamports = meta->info.lamports;

  return FD_ACC_MGR_SUCCESS;
}

int
fd_acc_mgr_modify( fd_acc_mgr_t *          acc_mgr,
                   fd_funk_txn_t *         txn,
                   fd_pubkey_t const *     pubkey,
                   int                     do_create,
                   ulong                   min_data_sz,
                   fd_borrowed_account_t * account ) {
  int err = FD_ACC_MGR_SUCCESS;

  fd_account_meta_t * meta = fd_acc_mgr_modify_raw( acc_mgr, txn, pubkey, do_create, min_data_sz, account->const_rec, &account->rec, &err );
  if( FD_UNLIKELY( !meta ) ) return err;

  assert( account->magic == FD_BORROWED_ACCOUNT_MAGIC );

  fd_memcpy(account->pubkey, pubkey, sizeof(fd_pubkey_t));

  if( FD_UNLIKELY( meta->magic != FD_ACCOUNT_META_MAGIC ) )
    return FD_ACC_MGR_ERR_WRONG_MAGIC;

  account->orig_rec  = account->const_rec  = account->rec;
  account->orig_meta = account->const_meta = account->meta = meta;
  account->orig_data = account->const_data = account->data = (uchar *)meta + meta->hlen;

  if( ULONG_MAX == account->starting_dlen )
    account->starting_dlen = meta->dlen;

  if( ULONG_MAX == account->starting_lamports )
    account->starting_lamports = meta->info.lamports;

  return FD_ACC_MGR_SUCCESS;
}

fd_account_meta_t *
fd_acc_mgr_modify_raw( fd_acc_mgr_t *        acc_mgr,
                       fd_funk_txn_t *       txn,
                       fd_pubkey_t const *   pubkey,
                       int                   do_create,
                       ulong                 min_data_sz,
                       fd_funk_rec_t const * opt_con_rec,
                       fd_funk_rec_t **      opt_out_rec,
                       int *                 opt_err ) {

  fd_funk_t *       funk = acc_mgr->funk;
  fd_funk_rec_key_t id   = fd_acc_funk_key( pubkey );

  int funk_err = FD_FUNK_SUCCESS;
  fd_funk_rec_t * rec = fd_funk_rec_write_prepare( funk, txn, &id, sizeof(fd_account_meta_t)+min_data_sz, do_create, opt_con_rec, &funk_err );

  if( FD_UNLIKELY( !rec ) )  {
    if( FD_LIKELY( funk_err==FD_FUNK_ERR_KEY ) ) {
      fd_int_store_if( !!opt_err, opt_err, FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT );
      return NULL;
    }
    /* Irrecoverable funky internal error [[noreturn]] */
    FD_LOG_ERR(( "fd_funk_rec_write_prepare failed (%i-%s)", funk_err, fd_funk_strerror( funk_err ) ));
  }

  if (NULL != opt_out_rec)
    *opt_out_rec = rec;

  // At this point, we don't know if the record WILL be rent exempt so
  // it is safer to just stick it into the partition and look at it later.
  if ( acc_mgr->slots_per_epoch != 0 )
    fd_funk_part_set(funk, rec, (uint)fd_rent_lists_key_to_bucket( acc_mgr, rec ));

  fd_account_meta_t * ret = fd_funk_val( rec, fd_funk_wksp(funk) );

  if( do_create && ret->magic == 0 )
    fd_account_meta_init(ret);

  if( ret->magic != FD_ACCOUNT_META_MAGIC )
    FD_LOG_ERR(( "bad magic" ));

  return ret;
}

int
fd_acc_mgr_commit_raw( fd_acc_mgr_t *       acc_mgr,
                       fd_funk_rec_t *      rec,
                       fd_pubkey_t const *  pubkey,
                       void *               raw_acc,
                       fd_exec_slot_ctx_t * slot_ctx ) {

  (void)acc_mgr;
  (void)rec;
  (void)pubkey;

  fd_account_meta_t * m = (fd_account_meta_t *)raw_acc;
  m->slot = slot_ctx->slot_bank.slot;

  /* TODO do hashing work here? */

  return FD_ACC_MGR_SUCCESS;
}

FD_FN_CONST char const *
fd_acc_mgr_strerror( int err ) {
  switch( err ) {
  case FD_ACC_MGR_SUCCESS:
    return "success";
  case FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT:
    return "unknown account";
  case FD_ACC_MGR_ERR_WRITE_FAILED:
    return "write failed";
  case FD_ACC_MGR_ERR_READ_FAILED:
    return "read failed";
  case FD_ACC_MGR_ERR_WRONG_MAGIC:
    return "wrong magic";
  default:
    return "unknown";
  }
}
