#include "fd_acc_mgr.h"
#include "../../ballet/base58/fd_base58.h"
#include "fd_hashes.h"
#include "fd_runtime.h"
#include <stdio.h>

fd_acc_mgr_t *
fd_acc_mgr_new( void *            mem,
                fd_global_ctx_t * global ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  fd_memset( mem, 0, FD_ACC_MGR_FOOTPRINT );

  fd_acc_mgr_t * acc_mgr = (fd_acc_mgr_t*)mem;
  acc_mgr->global        = global;
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

void const *
fd_acc_mgr_view_raw( fd_acc_mgr_t *         acc_mgr,
                      fd_funk_txn_t const *  txn,
                      fd_pubkey_t const *    pubkey,
                      fd_funk_rec_t const ** orec,
                      int *                  opt_err ) {

  fd_funk_rec_key_t     id = fd_acc_mgr_key(pubkey);
  fd_funk_t *           funk = acc_mgr->global->funk;

  fd_funk_rec_t const * rec = fd_funk_rec_query_global(funk, txn, &id);

  if ( FD_UNLIKELY( NULL == rec ) )  {
    fd_int_store_if( !!opt_err, opt_err, FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT );
    return NULL;
  }
  if (NULL != orec)
    *orec = rec;
  void const * data = fd_funk_val_cache( funk, rec, opt_err );
  if( FD_UNLIKELY( !data ) ) FD_LOG_CRIT(( "fd_funk_val_cache failed (%d-%s)", *opt_err, fd_funk_strerror( *opt_err ) ));
  fd_account_meta_t const *metadata = (fd_account_meta_t const *) data;
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

  fd_funk_t            *funk     = acc_mgr->global->funk;
  fd_funk_rec_key_t     id       = fd_acc_mgr_key( pubkey );

  fd_funk_rec_t * rec = fd_funk_rec_write_prepare(funk, txn, &id, sizeof(fd_account_meta_t)+min_data_sz, do_create, opt_con_rec, opt_err);

  if ( FD_UNLIKELY( NULL == rec ) )  {
    fd_int_store_if( !!opt_err, opt_err, FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT );
    return NULL;
  }

  if (NULL != opt_out_rec)
    *opt_out_rec = rec;

  fd_account_meta_t * ret = fd_funk_val_cache( funk, rec, opt_err );
  if( FD_UNLIKELY( !ret ) )
    FD_LOG_CRIT(( "Internal funky error: fd_funk_val_cache failed (%d-%s)", *opt_err, fd_funk_strerror( *opt_err ) ));

  if( do_create && ret->magic == 0 )
    fd_account_meta_init(ret);
  else {
    FD_TEST( ret->magic == FD_ACCOUNT_META_MAGIC );
  }

  return ret;
}

int
fd_acc_mgr_commit_raw( fd_acc_mgr_t *      acc_mgr,
                       fd_funk_rec_t *     rec,
                       fd_pubkey_t const * pubkey,
                       void *              raw_acc,
                       ulong               slot,
                       int                 uncache ) {

  fd_global_ctx_t const * global = acc_mgr->global;
  fd_funk_t *             funk   = global->funk;
  fd_account_meta_t *     m      = (fd_account_meta_t *)raw_acc;
  void const *            data   = (void const *)( (ulong)raw_acc + m->hlen );

  m->slot = slot;

  fd_hash_t hash[1];
  fd_hash_account_current( hash->hash, m, pubkey->key, data, global );

  if( 0!=memcmp( &hash, m->hash, sizeof(hash) ) ) {
    if( FD_UNLIKELY( acc_mgr->global->log_level > 2 ) ) {
      FD_LOG_DEBUG(( "fd_acc_mgr_commit_raw: %32J slot: %ld lamports: %ld  owner: %32J  executable: %s,  rent_epoch: %ld, data_len: %ld, data: %s = %32J",
                     pubkey->uc, slot, m->info.lamports, m->info.owner, m->info.executable ? "true" : "false", m->info.rent_epoch, m->dlen, "xx", hash->uc ));
    }

    FD_TEST( rec );
    int err = fd_funk_rec_persist(funk, rec);
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "fd_funk_rec_persist failed (%d-%s)", err, fd_funk_strerror( err ) ));
      return FD_ACC_MGR_ERR_WRITE_FAILED;
    }

    if( uncache ) {
      err = fd_funk_val_uncache(funk, rec);
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "fd_funk_val_uncache failed (%d-%s)", err, fd_funk_strerror( err ) ));
        return FD_ACC_MGR_ERR_WRITE_FAILED;
      }
    }
  }

  return FD_ACC_MGR_SUCCESS;
}
