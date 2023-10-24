#include "fd_acc_mgr.h"
#include "../../ballet/base58/fd_base58.h"
#include "fd_hashes.h"
#include "fd_runtime.h"
#include "fd_rent_lists.h"
#include <stdio.h>

fd_acc_mgr_t *
fd_acc_mgr_new( void *      mem,
                fd_funk_t * funk ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  fd_memset( mem, 0, FD_ACC_MGR_FOOTPRINT );

  fd_acc_mgr_t * acc_mgr = (fd_acc_mgr_t*)mem;
  acc_mgr->funk = funk;
  return (fd_acc_mgr_t *)mem;
}


fd_funk_rec_key_t
fd_acc_mgr_key( fd_pubkey_t const * pubkey ) {
  fd_funk_rec_key_t id;
  fd_memset( &id, 0, sizeof(id) );
  fd_memcpy( id.c, pubkey, sizeof(fd_pubkey_t) );
  id.c[ FD_FUNK_REC_KEY_FOOTPRINT - 1 ] = FD_ACC_MGR_KEY_TYPE;

  return id;
}

inline int
fd_acc_mgr_is_key( fd_funk_rec_key_t const* id ) {
  return id->c[ FD_FUNK_REC_KEY_FOOTPRINT - 1 ] == FD_ACC_MGR_KEY_TYPE;
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
fd_rent_lists_cb(fd_funk_rec_t * rec, uint num_part, void * cb_arg) {
  (void)num_part;
  fd_exec_slot_ctx_t * slot_ctx = (fd_exec_slot_ctx_t *) cb_arg;
  fd_acc_mgr_t * acc_mgr = slot_ctx->acc_mgr;
  if ( fd_acc_mgr_is_key( rec->pair.key ) ) {
    if ( acc_mgr->skip_rent_rewrites ) {
      void const * data = fd_funk_val( rec, fd_funk_wksp(acc_mgr->funk) );
      fd_account_meta_t const * metadata = (fd_account_meta_t const *)fd_type_pun_const( data );

      if (fd_rent_exempt_minimum_balance2( &slot_ctx->bank.rent, metadata->dlen) <= metadata->info.lamports)
        return FD_FUNK_PART_NULL;
    }

    return (uint)fd_rent_lists_key_to_bucket( acc_mgr, rec );
  }
  return FD_FUNK_PART_NULL;
}

void
fd_acc_mgr_set_slots_per_epoch( fd_exec_slot_ctx_t * slot_ctx,
                                ulong slots_per_epoch ) {
  fd_acc_mgr_t * acc_mgr = slot_ctx->acc_mgr;

  uchar skip_rent_rewrites = FD_FEATURE_ACTIVE( slot_ctx, skip_rent_rewrites );

  if ((slots_per_epoch == acc_mgr->slots_per_epoch ) && (skip_rent_rewrites == acc_mgr->skip_rent_rewrites))
    return;

  acc_mgr->slots_per_epoch    = slots_per_epoch;
  acc_mgr->skip_rent_rewrites = skip_rent_rewrites;
  acc_mgr->part_width         = fd_rent_partition_width( slots_per_epoch );

  fd_funk_repartition(acc_mgr->funk, (uint)slots_per_epoch, fd_rent_lists_cb, slot_ctx);
}

void const *
fd_acc_mgr_view_raw( fd_acc_mgr_t *         acc_mgr,
                     fd_funk_txn_t const *  txn,
                     fd_pubkey_t const *    pubkey,
                     fd_funk_rec_t const ** orec,
                     int *                  opt_err ) {

  fd_funk_rec_key_t     id = fd_acc_mgr_key(pubkey);
  fd_funk_t *           funk = acc_mgr->funk;

  fd_funk_rec_t const * rec = fd_funk_rec_query_global(funk, txn, &id);

  if( FD_UNLIKELY( !rec || !!( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) )  {
    fd_int_store_if( !!opt_err, opt_err, FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT );
    return NULL;
  }
  if (NULL != orec)
    *orec = rec;
  void const * data = fd_funk_val( rec, fd_funk_wksp(funk) );
  // TODO/FIXME: this check causes issues with some metadata writes
  fd_account_meta_t const * metadata = (fd_account_meta_t const *)fd_type_pun_const( data );
  if ( metadata->magic != FD_ACCOUNT_META_MAGIC ) {
    FD_LOG_NOTICE(("metadata->magic %32J %d %d", pubkey->uc, metadata->magic, metadata->magic == FD_ACCOUNT_META_MAGIC));
    return NULL;
  }
  FD_TEST( metadata->magic == FD_ACCOUNT_META_MAGIC );

  return data;
}

void *
fd_acc_mgr_modify_raw( fd_acc_mgr_t *        acc_mgr,
                       fd_funk_txn_t *       txn,
                       fd_pubkey_t const *   pubkey,
                       int                   do_create,
                       ulong                 min_data_sz,
                       fd_funk_rec_t const * opt_con_rec,
                       fd_funk_rec_t **      opt_out_rec,
                       int *                 opt_err ) {

  fd_funk_t *       funk = acc_mgr->funk;
  fd_funk_rec_key_t id   = fd_acc_mgr_key( pubkey );

  int funk_err = FD_FUNK_SUCCESS;
  fd_funk_rec_t * rec = fd_funk_rec_write_prepare( funk, txn, &id, sizeof(fd_account_meta_t)+min_data_sz, do_create, opt_con_rec, &funk_err );

  if( FD_UNLIKELY( !rec ) )  {
    if( FD_LIKELY( funk_err==FD_FUNK_ERR_KEY ) ) {
      fd_int_store_if( !!opt_err, opt_err, FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT );
      return NULL;
    }
    /* Irrecoverable funky internal error [[noreturn]] */
    FD_LOG_ERR(( "fd_funk_rec_write_prepare(%32J) failed (%i-%s)", pubkey->key, funk_err, fd_funk_strerror( funk_err ) ));
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
  FD_TEST( ret->magic == FD_ACCOUNT_META_MAGIC );

  return ret;
}

int
fd_acc_mgr_commit_raw( fd_acc_mgr_t *      acc_mgr FD_PARAM_UNUSED,
                       fd_funk_rec_t *     rec,
                       fd_pubkey_t const * pubkey,
                       void *              raw_acc,
                       fd_exec_slot_ctx_t * slot_ctx ) {
  fd_account_meta_t *     m      = (fd_account_meta_t *)raw_acc;
  void const *            data   = (void const *)( (ulong)raw_acc + m->hlen );

  m->slot = slot_ctx->slot_bank.slot;

  fd_hash_t hash[1];
  fd_hash_account_current( hash->hash, m, pubkey->key, data, slot_ctx );

  if( 0!=memcmp( &hash, m->hash, sizeof(hash) ) ) {
    FD_LOG_DEBUG(( "fd_acc_mgr_commit_raw: %32J slot: %ld lamports: %ld  owner: %32J  executable: %s,  rent_epoch: %ld, data_len: %ld, data: %s = %32J",
                    pubkey->uc, slot_ctx->slot_bank.slot, m->info.lamports, m->info.owner, m->info.executable ? "true" : "false", m->info.rent_epoch, m->dlen, "xx", hash->uc ));

    FD_TEST( rec );
  }

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
