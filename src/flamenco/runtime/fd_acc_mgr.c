#include "fd_acc_mgr.h"
#include "../../ballet/base58/fd_base58.h"
#include "fd_hashes.h"
#include "fd_runtime.h"
#include "fd_rent_lists.h"
#include <stdio.h>

fd_acc_mgr_t *
fd_acc_mgr_new( void *            mem,
                fd_funk_t *       funk,
                fd_blockstore_t * blockstore ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  fd_memset( mem, 0, FD_ACC_MGR_FOOTPRINT );

  fd_acc_mgr_t * acc_mgr = (fd_acc_mgr_t*)mem;
  acc_mgr->funk = funk;
  acc_mgr->blockstore = blockstore;
  return (fd_acc_mgr_t *)mem;
}

inline fd_funk_rec_key_t
fd_acc_mgr_key( fd_pubkey_t const * pubkey ) {
  fd_funk_rec_key_t id;
  memcpy( id.uc, pubkey, sizeof(fd_pubkey_t) );
  memset( id.uc + sizeof(fd_pubkey_t), 0, sizeof(fd_funk_rec_key_t) - sizeof(fd_pubkey_t) );

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

      if (fd_rent_exempt_minimum_balance2( &slot_ctx->epoch_ctx->epoch_bank.rent, metadata->dlen) <= metadata->info.lamports)
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

  fd_funk_rec_t const * rec = fd_funk_rec_query_global_const(funk, txn, &id);

  if( FD_UNLIKELY( !rec || !!( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) )  {
    fd_int_store_if( !!opt_err, opt_err, FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT );
    return NULL;
  }
  if (NULL != orec)
    *orec = rec;
  void const * data = fd_funk_val_const( rec, fd_funk_wksp(funk) );
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

  if( ret->magic != FD_ACCOUNT_META_MAGIC ) {
    FD_LOG_ERR(( "bad magic" ));
  }

  return ret;
}

void *
fd_acc_mgr_modify_raw_prealloc( fd_acc_mgr_t *        acc_mgr,
                                fd_funk_txn_t *       txn,
                                fd_pubkey_t const *   pubkey,
                                int                   do_create,
                                ulong                 min_data_sz,
                                fd_funk_rec_t *       prealloc_rec,
                                fd_funk_rec_t const * opt_con_rec,
                                fd_funk_rec_t **      opt_out_rec,
                                int *                 opt_err ) {

  fd_funk_t *       funk = acc_mgr->funk;
  fd_funk_rec_key_t id   = fd_acc_mgr_key( pubkey );

  int funk_err = FD_FUNK_SUCCESS;
  fd_funk_rec_t * rec = fd_funk_rec_write_prepare_prealloc( funk, txn, &id, sizeof(fd_account_meta_t)+min_data_sz, do_create, prealloc_rec, opt_con_rec, &funk_err );

  if( FD_UNLIKELY( !rec ) )  {
    if( FD_LIKELY( funk_err==FD_FUNK_ERR_KEY ) ) {
      fd_int_store_if( !!opt_err, opt_err, FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT );
      return NULL;
    }
    /* Irrecoverable funky internal error [[noreturn]] */
    FD_LOG_ERR(( "fd_funk_rec_write_prepare_prealloc(%32J) failed (%i-%s)", pubkey->key, funk_err, fd_funk_strerror( funk_err ) ));
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

  if( ret->magic != FD_ACCOUNT_META_MAGIC ) {
    FD_LOG_ERR(( "bad magic" ));
  }

  return ret;
}

int
fd_acc_mgr_commit_raw( fd_acc_mgr_t *      acc_mgr FD_PARAM_UNUSED,
                       fd_funk_rec_t *     rec,
                       fd_pubkey_t const * pubkey,
                       void *              raw_acc,
                       fd_exec_slot_ctx_t * slot_ctx ) {
  fd_account_meta_t *     m      = (fd_account_meta_t *)raw_acc;
  m->slot = slot_ctx->slot_bank.slot;

#if 0
  void const * data   = (void const *)( (ulong)raw_acc + m->hlen );

  fd_hash_t hash[1];
  fd_hash_account_current( hash->hash, NULL, m, pubkey->key, data, slot_ctx );

  if( 0!=memcmp( &hash, m->hash, sizeof(hash) ) ) {
    FD_LOG_DEBUG(( "fd_acc_mgr_commit_raw: %32J slot: %ld lamports: %ld  owner: %32J  executable: %s,  rent_epoch: %ld, data_len: %ld, data: %s = %32J",
                    pubkey->uc, slot_ctx->slot_bank.slot, m->info.lamports, m->info.owner, m->info.executable ? "true" : "false", m->info.rent_epoch, m->dlen, "xx", hash->uc ));

    FD_TEST( rec );
  }
#else
  (void) rec;
  (void) pubkey;
#endif

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

static inline int
fd_acc_mgr_save_prealloc( fd_acc_mgr_t *          acc_mgr,
                          fd_funk_txn_t *         txn,
                          fd_funk_rec_t *         prealloc_rec,
                          fd_valloc_t             valloc,
                          fd_borrowed_account_t * account ) {
  int err = FD_ACC_MGR_SUCCESS;

  if( account->meta == NULL ) {
    // The meta is NULL so the account is not writable.
    FD_LOG_DEBUG(( "fd_acc_mgr_save: account is not writable: %32J", account->pubkey ));
    return FD_ACC_MGR_SUCCESS;
  }

  if( account->orig_data == account->data ) {
    // We never had to realloc/resize the account, so we have nothing to do.
    return FD_ACC_MGR_SUCCESS;
  }

  uchar * raw = fd_acc_mgr_modify_raw_prealloc( acc_mgr, txn, account->pubkey, 1, account->meta->dlen, prealloc_rec, account->const_rec, &account->rec, &err );
  if( FD_UNLIKELY( !raw ) ) {
    return err;
  }

  FD_TEST(FD_BORROWED_ACCOUNT_MAGIC == account->magic);

  fd_account_meta_t * meta = (fd_account_meta_t *)raw;

  if( FD_UNLIKELY( meta->magic != FD_ACCOUNT_META_MAGIC ) ) {
    return FD_ACC_MGR_ERR_WRONG_MAGIC;
  }

  fd_memcpy( raw, account->meta, sizeof(fd_account_meta_t)+account->const_meta->dlen );
  fd_valloc_free( valloc, account->meta );

  account->orig_rec = account->const_rec = account->rec;
  account->orig_meta = account->const_meta = account->meta = meta;
  account->orig_data = account->const_data = account->data = raw + meta->hlen;

  return FD_ACC_MGR_SUCCESS;
}

void
fd_acc_mgr_lock( fd_acc_mgr_t * acc_mgr ) {
  FD_TEST( !acc_mgr->is_locked );
  acc_mgr->is_locked = 1;
}

void
fd_acc_mgr_unlock( fd_acc_mgr_t * acc_mgr ) {
  FD_TEST( acc_mgr->is_locked );
  acc_mgr->is_locked = 0;
}

struct fd_acc_mgr_save_task_args {
  fd_acc_mgr_t * acc_mgr;
  fd_funk_txn_t * txn;
  fd_valloc_t valloc;
};
typedef struct fd_acc_mgr_save_task_args fd_acc_mgr_save_task_args_t;

struct fd_acc_mgr_save_task_info {
  fd_borrowed_account_t * * accounts;
  fd_funk_rec_t * * prealloc_recs;
  ulong accounts_cnt;
  int result;
};
typedef struct fd_acc_mgr_save_task_info fd_acc_mgr_save_task_info_t;

static void
fd_acc_mgr_save_task( void *tpool,
                      ulong t0 FD_PARAM_UNUSED, ulong t1 FD_PARAM_UNUSED,
                      void *args FD_PARAM_UNUSED,
                      void *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                      ulong l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
                      ulong m0, ulong m1 FD_PARAM_UNUSED,
                      ulong n0 FD_PARAM_UNUSED, ulong n1 FD_PARAM_UNUSED ) {
  fd_acc_mgr_save_task_args_t * task_args = (fd_acc_mgr_save_task_args_t *)args;
  fd_acc_mgr_save_task_info_t * task_info = (fd_acc_mgr_save_task_info_t *)tpool + m0;

  for( ulong i = 0; i < task_info->accounts_cnt; i++ ) {
    int err = fd_acc_mgr_save_prealloc(task_args->acc_mgr, task_args->txn, task_info->prealloc_recs[i], task_args->valloc, task_info->accounts[i] );
    if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
      task_info->result = err;
      return;
    }
  }
}

int
fd_acc_mgr_save_many_tpool( fd_acc_mgr_t *          acc_mgr,
                            fd_funk_txn_t *         txn,
                            fd_valloc_t             valloc,
                            fd_borrowed_account_t * * accounts,
                            ulong accounts_cnt,
                            fd_tpool_t * tpool,
                            ulong max_workers ) {
  FD_SCRATCH_SCOPE_BEGIN {
    fd_funk_t *        funk = acc_mgr->funk;
    fd_wksp_t * wksp = fd_funk_wksp( funk );
    fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, wksp );

    ulong pre_key_cnt = fd_funk_rec_map_key_cnt( rec_map );

    ulong batch_cnt = fd_ulong_min(
      fd_funk_rec_map_private_list_cnt( fd_funk_rec_map_key_max( rec_map ) ),
      fd_ulong_pow2_up( max_workers )
    );
    ulong batch_mask = (batch_cnt - 1UL);

    ulong * batch_szs = fd_scratch_alloc( 8UL, batch_cnt * sizeof(ulong) );
    fd_memset( batch_szs, 0, batch_cnt * sizeof(ulong) );

    ulong * account_batch_idxs = fd_scratch_alloc( 8UL, accounts_cnt * sizeof(ulong) );
    fd_funk_rec_t * * task_prealloc_recs = fd_scratch_alloc( 8UL, accounts_cnt * sizeof(fd_funk_rec_t *) );

    /* Compute the batch sizes */
    for( ulong i = 0; i < accounts_cnt; i++ ) {
      fd_borrowed_account_t * borrowed_account = accounts[i];

      fd_funk_rec_key_t rec_key = fd_acc_mgr_key( borrowed_account->pubkey );
      fd_funk_xid_key_pair_t xid_key_pair[1];

      fd_funk_xid_key_pair_init( xid_key_pair, fd_funk_txn_xid( txn ), &rec_key );

      ulong rec_map_list_idx = fd_funk_rec_map_list_idx( rec_map, xid_key_pair );

      task_prealloc_recs[i] = fd_funk_rec_map_pop_free_ele( rec_map );

      ulong batch_idx = rec_map_list_idx & batch_mask;
      batch_szs[batch_idx]++;
      account_batch_idxs[i] = batch_idx;
    }

    fd_borrowed_account_t * * task_accounts = fd_scratch_alloc( 8UL, accounts_cnt * sizeof(fd_borrowed_account_t *) );
    fd_acc_mgr_save_task_info_t * task_infos = fd_scratch_alloc( 8UL, batch_cnt * sizeof(fd_acc_mgr_save_task_info_t) );
    fd_borrowed_account_t * * task_accounts_cursor = task_accounts;
    fd_funk_rec_t * * task_prealloc_recs_cursor = task_prealloc_recs;

    /* Construct the batches */
    for( ulong i = 0; i < batch_cnt; i++ ) {
      ulong batch_sz = batch_szs[i];
      fd_acc_mgr_save_task_info_t * task_info = &task_infos[i];

      task_info->accounts_cnt = 0;
      task_info->accounts = task_accounts_cursor;
      task_info->prealloc_recs = task_prealloc_recs_cursor;

      task_info->result = 0;

      task_accounts_cursor += batch_sz;
      task_prealloc_recs_cursor += batch_sz;
    }

    for( ulong i = 0; i < accounts_cnt; i++ ) {
      fd_borrowed_account_t * borrowed_account = accounts[i];
      ulong batch_idx = account_batch_idxs[i];

      fd_acc_mgr_save_task_info_t * task_info = &task_infos[batch_idx];
      task_info->accounts[task_info->accounts_cnt++] = borrowed_account;
    }

    fd_acc_mgr_save_task_args_t task_args = {
      .acc_mgr = acc_mgr,
      .txn = txn,
      .valloc = valloc,
    };

    /* Save accounts in a thread pool */
    fd_tpool_exec_all_rrobin( tpool, 0, max_workers, fd_acc_mgr_save_task, task_infos, &task_args, NULL, 1, 0, batch_cnt );

    /* Check results */
    for( ulong i = 0; i < batch_cnt; i++ ) {
      fd_acc_mgr_save_task_info_t * task_info = &task_infos[i];
      if( task_info->result != FD_ACC_MGR_SUCCESS ) {
        return task_info->result;
      }
    }

    /* Fix up and clean up */
    ulong added_rec_cnt = 0;
    for( ulong i = 0; i < accounts_cnt; i++ ) {
      fd_borrowed_account_t * borrowed_account = task_accounts[i];
      fd_funk_rec_t * prealloc_rec = task_prealloc_recs[i];

      if( prealloc_rec != borrowed_account->rec ) {
        fd_funk_rec_map_push_free_ele( rec_map, prealloc_rec );
      } else {
        if( fd_funk_rec_fixup_links( funk, txn, borrowed_account->rec, NULL ) == NULL ) {
          FD_LOG_ERR(( "error while fixing links" ));
        }
        added_rec_cnt++;
      }
    }

    /* Fix the key_cnt */
    fd_funk_rec_map_set_key_cnt( rec_map, pre_key_cnt + added_rec_cnt );

    return FD_ACC_MGR_SUCCESS;
  } FD_SCRATCH_SCOPE_END;
}
