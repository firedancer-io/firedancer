#include "fd_hashes.h"
#include "fd_acc_mgr.h"
#include "fd_bank.h"
#include "fd_blockstore.h"
#include "fd_runtime.h"
#include "fd_borrowed_account.h"
#include "context/fd_capture_ctx.h"
#include "fd_runtime_public.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "../capture/fd_solcap_writer.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/blake3/fd_blake3.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../ballet/sha256/fd_sha256.h"

#include <assert.h>
#include <stdio.h>

#define SORT_NAME sort_pubkey_hash_pair
#define SORT_KEY_T fd_pubkey_hash_pair_t
static int
fd_pubkey_hash_pair_compare(fd_pubkey_hash_pair_t const * a, fd_pubkey_hash_pair_t const * b) {
  for (uint i = 0; i < sizeof(fd_pubkey_t)/sizeof(ulong); ++i) {
    /* First byte is least significant when seen as a long. Make it most significant. */
    ulong al = __builtin_bswap64(a->rec->pair.key->ul[i]);
    ulong bl = __builtin_bswap64(b->rec->pair.key->ul[i]);
    if (al != bl) return (al < bl);
  }
  return 0;
}
#define SORT_BEFORE(a,b) fd_pubkey_hash_pair_compare(&a, &b)
#include "../../util/tmpl/fd_sort.c"

#define FD_ACCOUNT_DELTAS_MERKLE_FANOUT (16UL)
#define FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT (16UL)

static void
fd_hash_account_deltas( fd_pubkey_hash_pair_list_t * lists, ulong lists_len, fd_hash_t * hash ) {
  fd_sha256_t shas[FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT];
  uchar       num_hashes[FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT+1];

  // Init the number of hashes
  fd_memset( num_hashes, 0, sizeof(num_hashes) );

  for( ulong j = 0; j < FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT; ++j ) {
    fd_sha256_init( &shas[j] );
}

  if( lists_len == 0 ) {
    fd_sha256_fini( &shas[0], hash->hash );
    return;
  }

  fd_pubkey_hash_pair_t * prev_pair = NULL;
  for( ulong k = 0; k < lists_len; ++k ) {
    fd_pubkey_hash_pair_t * pairs     = lists[k].pairs;
    ulong                   pairs_len = lists[k].pairs_len;
    for( ulong i = 0; i < pairs_len; ++i ) {
      if( prev_pair ) FD_TEST(fd_pubkey_hash_pair_compare(prev_pair, &pairs[i]) > 0);
      prev_pair = &pairs[i];
      fd_sha256_append( &shas[0], pairs[i].hash->hash, sizeof( fd_hash_t ) );
      num_hashes[0]++;

      for( ulong j = 0; j < FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT; ++j ) {
        if (num_hashes[j] == FD_ACCOUNT_DELTAS_MERKLE_FANOUT) {
          num_hashes[j] = 0;
          num_hashes[j+1]++;
          fd_sha256_fini( &shas[j], hash->hash );
          fd_sha256_init( &shas[j] );
          fd_sha256_append( &shas[j+1], (uchar const *) hash->hash, sizeof( fd_hash_t ) );
        } else {
          break;
        }
      }
    }
  }

  ulong tot_num_hashes = 0;
  for( ulong k = 0; k < FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT; ++k ) {
    tot_num_hashes += num_hashes[k];
  }

  if( tot_num_hashes == 1 ) {
    return;
  }

  // TODO: use CZT on pairs_len
  ulong height = 0;
  for( long i = FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT-1; i >= 0; --i ) {
    if( num_hashes[i] != 0 ) {
      height = (ulong) i + 1;
      break;
    }
  }


  for( ulong i = 0; i < height; ++i ) {
    if( num_hashes[i]==0 ) {
      continue;
    }
    // At level i, finalize and append to i + 1
    //fd_hash_t sub_hash;
    fd_sha256_fini( &shas[i], hash );
    num_hashes[i] = 0;
    num_hashes[i+1]++;

    ulong tot_num_hashes = 0;
    for (ulong k = 0; k < FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT; ++k ) {
      tot_num_hashes += num_hashes[k];
    }
    if (i == (height-1)) {
      assert(tot_num_hashes == 1);
      return;
    }
    fd_sha256_append( &shas[i+1], (uchar const *) hash->hash, sizeof( fd_hash_t ) );

    // There is now one more hash at level i+1

    // check, have we filled this level and ones above it.
    for( ulong j = i+1; j < height; ++j ) {
      // if the level is full, finalize and push into next level.
      if (num_hashes[j] == FD_ACCOUNT_DELTAS_MERKLE_FANOUT) {
        num_hashes[j] = 0;
        num_hashes[j+1]++;
        fd_hash_t sub_hash;
        fd_sha256_fini( &shas[j], &sub_hash );
        if (j != height - 1) {
          fd_sha256_append( &shas[j+1], (uchar const *) sub_hash.hash, sizeof( fd_hash_t ) );
        } else {
          memcpy(hash->hash, sub_hash.hash, sizeof(fd_hash_t));
          return;
        }
      }
    }
  }

  // If the level at the `height' was rolled into, do something about it
}


void
fd_calculate_epoch_accounts_hash_values( fd_exec_slot_ctx_t * slot_ctx ) {
  ulong slot_idx = 0;
  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( slot_ctx->bank );
  ulong epoch = fd_slot_to_epoch( epoch_schedule, slot_ctx->bank->slot, &slot_idx );

  if( FD_FEATURE_ACTIVE_BANK( slot_ctx->bank, accounts_lt_hash) ) {
    fd_bank_eah_start_slot_set( slot_ctx->bank, ULONG_MAX );
    fd_bank_eah_stop_slot_set( slot_ctx->bank, ULONG_MAX );
    fd_bank_eah_interval_set( slot_ctx->bank, ULONG_MAX );
    return;
  }

  ulong slots_per_epoch = fd_epoch_slot_cnt( epoch_schedule, epoch );
  ulong first_slot_in_epoch           = fd_epoch_slot0   ( epoch_schedule, epoch );

  ulong calculation_offset_start = slots_per_epoch / 4;
  ulong calculation_offset_stop = slots_per_epoch / 4 * 3;
  ulong calculation_interval = fd_ulong_sat_sub(calculation_offset_stop, calculation_offset_start);

  // This came from the vote program.. maybe we need to put it into a header?
  const ulong MAX_LOCKOUT_HISTORY = 31UL;
  const ulong CALCULATION_INTERVAL_BUFFER = 150UL;
  const ulong MINIMUM_CALCULATION_INTERVAL = MAX_LOCKOUT_HISTORY + CALCULATION_INTERVAL_BUFFER;

  if( calculation_interval < MINIMUM_CALCULATION_INTERVAL ) {
    fd_bank_eah_start_slot_set( slot_ctx->bank, ULONG_MAX );
    fd_bank_eah_stop_slot_set( slot_ctx->bank, ULONG_MAX );
    fd_bank_eah_interval_set( slot_ctx->bank, ULONG_MAX );
    return;
  }

  fd_bank_eah_start_slot_set( slot_ctx->bank, first_slot_in_epoch + calculation_offset_start );
  if( slot_ctx->bank->slot > fd_bank_eah_start_slot_get( slot_ctx->bank ) ) {
    fd_bank_eah_start_slot_set( slot_ctx->bank, ULONG_MAX );
  }

  fd_bank_eah_stop_slot_set( slot_ctx->bank, first_slot_in_epoch + calculation_offset_stop );
  if( slot_ctx->bank->slot > fd_bank_eah_stop_slot_get( slot_ctx->bank ) ) {
    fd_bank_eah_stop_slot_set( slot_ctx->bank, ULONG_MAX );
  }

  fd_bank_eah_interval_set( slot_ctx->bank, calculation_interval );

}

// https://github.com/solana-labs/solana/blob/b0dcaf29e358c37a0fcb8f1285ce5fff43c8ec55/runtime/src/bank/epoch_accounts_hash_utils.rs#L13
static int
fd_should_include_epoch_accounts_hash( fd_exec_slot_ctx_t * slot_ctx ) {
  if( FD_FEATURE_ACTIVE_BANK( slot_ctx->bank, accounts_lt_hash) ) {
    return 0;
  }

  ulong calculation_stop = fd_bank_eah_stop_slot_get( slot_ctx->bank );
  ulong prev_slot = fd_bank_prev_slot_get( slot_ctx->bank );
  return prev_slot < calculation_stop && (slot_ctx->bank->slot >= calculation_stop);
}

// slot_ctx should be const.
static void
fd_hash_bank( fd_exec_slot_ctx_t *    slot_ctx,
              fd_capture_ctx_t *      capture_ctx,
              fd_hash_t *             hash,
              fd_pubkey_hash_pair_t * dirty_keys,
              ulong                   dirty_key_cnt ) {

  fd_hash_t const * bank_hash = fd_bank_bank_hash_query( slot_ctx->bank );

  fd_bank_prev_bank_hash_set( slot_ctx->bank, *bank_hash );

  fd_bank_parent_signature_cnt_set( slot_ctx->bank, fd_bank_signature_count_get( slot_ctx->bank ) );

  fd_bank_lamports_per_signature_set( slot_ctx->bank, fd_bank_lamports_per_signature_get( slot_ctx->bank ) );

  fd_hash_t account_delta_hash;

  if( !FD_FEATURE_ACTIVE_BANK( slot_ctx->bank, remove_accounts_delta_hash) ) {
    sort_pubkey_hash_pair_inplace( dirty_keys, dirty_key_cnt );
    fd_pubkey_hash_pair_list_t list1 = { .pairs = dirty_keys, .pairs_len = dirty_key_cnt };
    fd_hash_account_deltas(&list1, 1, &account_delta_hash );
  }

  fd_sha256_t sha;
  fd_sha256_init( &sha );
  fd_sha256_append( &sha, (uchar const *)bank_hash, sizeof( fd_hash_t ) );
  if( !FD_FEATURE_ACTIVE_BANK( slot_ctx->bank, remove_accounts_delta_hash) )
    fd_sha256_append( &sha, (uchar const *) &account_delta_hash, sizeof( fd_hash_t  ) );
  fd_sha256_append( &sha, (uchar const *) fd_bank_signature_count_query( slot_ctx->bank ), sizeof( ulong ) );

  fd_sha256_append( &sha, (uchar const *) fd_bank_poh_query( slot_ctx->bank )->hash, sizeof( fd_hash_t ) );

  fd_sha256_fini( &sha, hash->hash );

  // https://github.com/anza-xyz/agave/blob/766cd682423b8049ddeac3c0ec6cebe0a1356e9e/runtime/src/bank.rs#L5250
  if( FD_FEATURE_ACTIVE_BANK( slot_ctx->bank, accounts_lt_hash ) ) {
    fd_sha256_init( &sha );
    fd_sha256_append( &sha, (uchar const *) &hash->hash, sizeof( fd_hash_t ) );
    fd_slot_lthash_t const * lthash = fd_bank_lthash_query( slot_ctx->bank );
    fd_sha256_append( &sha, (uchar const *) lthash->lthash, sizeof( lthash->lthash ) );
    fd_sha256_fini( &sha, hash->hash );
  } else {
    if (fd_should_include_epoch_accounts_hash(slot_ctx)) {
      fd_sha256_init( &sha );
      fd_sha256_append( &sha, (uchar const *) &hash->hash, sizeof( fd_hash_t ) );
      fd_sha256_append( &sha, (uchar const *) fd_bank_epoch_account_hash_query( slot_ctx->bank ), sizeof( fd_hash_t ) );
      fd_sha256_fini( &sha, hash->hash );
    }
  }

  if( capture_ctx != NULL && capture_ctx->capture != NULL && slot_ctx->bank->slot>=capture_ctx->solcap_start_slot ) {
    uchar *lthash = NULL;

    if( FD_FEATURE_ACTIVE_BANK( slot_ctx->bank, accounts_lt_hash ) ) {
      lthash = (uchar *)fd_alloca_check( 1UL, 32UL );
      fd_slot_lthash_t const * lthash_val = fd_bank_lthash_query( slot_ctx->bank );
      fd_lthash_hash((fd_lthash_value_t *) lthash_val->lthash, lthash);
    }

    fd_solcap_write_bank_preimage(
        capture_ctx->capture,
        hash->hash,
        fd_bank_prev_bank_hash_query( slot_ctx->bank ),
        FD_FEATURE_ACTIVE_BANK( slot_ctx->bank, remove_accounts_delta_hash) ? NULL : account_delta_hash.hash,
        lthash,
        fd_bank_poh_query( slot_ctx->bank )->hash,
        fd_bank_signature_count_get( slot_ctx->bank ) );
  }

  if( FD_FEATURE_ACTIVE_BANK( slot_ctx->bank, remove_accounts_delta_hash) ) {
    FD_LOG_NOTICE(( "\n\n[Replay]\n"
                    "slot:             %lu\n"
                    "bank hash:        %s\n"
                    "parent bank hash: %s\n"
                    "lthash:           %s\n"
                    "signature_count:  %lu\n"
                    "last_blockhash:   %s\n",
                    slot_ctx->bank->slot,
                    FD_BASE58_ENC_32_ALLOCA( hash->hash ),
                    FD_BASE58_ENC_32_ALLOCA( fd_bank_prev_bank_hash_query( slot_ctx->bank ) ),
                    FD_LTHASH_ENC_32_ALLOCA( (fd_lthash_value_t *) fd_bank_lthash_query( slot_ctx->bank )->lthash ),
                    fd_bank_signature_count_get( slot_ctx->bank ),
                    FD_BASE58_ENC_32_ALLOCA( fd_bank_poh_query( slot_ctx->bank )->hash ) ));
  } else {
    FD_LOG_NOTICE(( "\n\n[Replay]\n"
                    "slot:             %lu\n"
                    "bank hash:        %s\n"
                    "parent bank hash: %s\n"
                    "accounts_delta:   %s\n"
                    "lthash:           %s\n"
                    "signature_count:  %lu\n"
                    "last_blockhash:   %s\n",
                    slot_ctx->bank->slot,
                    FD_BASE58_ENC_32_ALLOCA( hash->hash ),
                    FD_BASE58_ENC_32_ALLOCA( fd_bank_prev_bank_hash_query( slot_ctx->bank ) ),
                    FD_BASE58_ENC_32_ALLOCA( account_delta_hash.hash ),
                    FD_LTHASH_ENC_32_ALLOCA( (fd_lthash_value_t *) fd_bank_lthash_query( slot_ctx->bank )->lthash ),
                    fd_bank_signature_count_get( slot_ctx->bank ),
                    FD_BASE58_ENC_32_ALLOCA( fd_bank_poh_query( slot_ctx->bank )->hash ) ));
  }
}

void
fd_account_hash( fd_funk_t *                    funk,
                 fd_funk_txn_t *                funk_txn,
                 fd_accounts_hash_task_info_t * task_info,
                 fd_lthash_value_t *            lt_hash,
                 ulong                          slot,
                 fd_features_t const *          features ) {
  int err = 0;
  fd_funk_txn_t const *     txn_out  = NULL;
  fd_account_meta_t const * acc_meta = fd_funk_get_acc_meta_readonly( funk,
                                                                      funk_txn,
                                                                      task_info->acc_pubkey,
                                                                      NULL,
                                                                      &err,
                                                                      &txn_out );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS || !acc_meta ) ) {
    FD_LOG_WARNING(( "failed to view account during bank hash" ));
    return;
  }

  fd_account_meta_t const * acc_meta_parent = NULL;
  if( txn_out ) {
    fd_funk_txn_pool_t * txn_pool = fd_funk_txn_pool( funk );
    txn_out = fd_funk_txn_parent( txn_out, txn_pool );
    acc_meta_parent = fd_funk_get_acc_meta_readonly( funk, txn_out, task_info->acc_pubkey, NULL, &err, NULL );
  }

  if( FD_UNLIKELY( !acc_meta->info.lamports ) ) {
    fd_memset( task_info->acc_hash->hash, 0, FD_HASH_FOOTPRINT );

    /* If we erase records instantly, this causes problems with the
        iterator.  Instead, we will store away the record and erase
        it later where appropriate.  */
    task_info->should_erase = 1;
    if( FD_UNLIKELY( NULL != acc_meta_parent) ){
      if( FD_UNLIKELY( acc_meta->info.lamports != acc_meta_parent->info.lamports ) )
        task_info->hash_changed = 1;
    }
  } else {
    uchar *             acc_data = fd_account_meta_get_data((fd_account_meta_t *) acc_meta);
    fd_lthash_value_t new_lthash_value;
    fd_lthash_zero( &new_lthash_value );
    fd_hash_account_current( task_info->acc_hash->hash,
                             &new_lthash_value,
                             acc_meta,
                             task_info->acc_pubkey,
                             acc_data,
                             FD_HASH_BOTH_HASHES,
                             features );

    if( memcmp( task_info->acc_hash->hash, acc_meta->hash, sizeof(fd_hash_t) ) != 0 ) {
      task_info->hash_changed = 1;
      // char *prev_lthash = FD_LTHASH_ENC_32_ALLOCA( lt_hash );
      fd_lthash_add( lt_hash, &new_lthash_value);
      // FD_LOG_NOTICE(( "lthash %s + %s = %s (%s)", prev_lthash, FD_LTHASH_ENC_32_ALLOCA( &new_lthash_value ), FD_LTHASH_ENC_32_ALLOCA( lt_hash ),
      //    FD_BASE58_ENC_32_ALLOCA( task_info->acc_pubkey )));
    }
  }
  if( FD_LIKELY(task_info->hash_changed && ((NULL != acc_meta_parent) && (acc_meta_parent->info.lamports != 0) ) ) ) {
    uchar const * acc_data = fd_account_meta_get_data_const( acc_meta_parent );
    fd_lthash_value_t old_lthash_value;
    fd_lthash_zero(&old_lthash_value);
    fd_hash_t old_hash;

    fd_hash_account_current( old_hash.hash,
                             &old_lthash_value,
                             acc_meta_parent,
                             task_info->acc_pubkey,
                             acc_data,
                             FD_HASH_JUST_LTHASH,
                             features );

    // char *prev_lthash = FD_LTHASH_ENC_32_ALLOCA( lt_hash );
    fd_lthash_sub( lt_hash, &old_lthash_value );
    // FD_LOG_NOTICE(( "lthash %s - %s = %s (%s)", prev_lthash, FD_LTHASH_ENC_32_ALLOCA( &old_lthash_value ), FD_LTHASH_ENC_32_ALLOCA( lt_hash ),
    //    FD_BASE58_ENC_32_ALLOCA( task_info->acc_pubkey )));
  }

  if( acc_meta->slot == slot ) {
    task_info->hash_changed = 1;
  }
}

void
fd_account_hash_task( void * tpool,
                      ulong t0, ulong t1,
                      void *args,
                      void *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                      ulong l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
                      ulong m0 FD_PARAM_UNUSED, ulong m1 FD_PARAM_UNUSED,
                      ulong n0 FD_PARAM_UNUSED, ulong n1 FD_PARAM_UNUSED ) {

  fd_accounts_hash_task_data_t * task_data  = (fd_accounts_hash_task_data_t *)tpool;
  ulong                          start_idx  = t0;
  ulong                          stop_idx   = t1;

  fd_lthash_value_t * lthash = (fd_lthash_value_t*)args;

  for( ulong i=start_idx; i<=stop_idx; i++ ) {
    fd_accounts_hash_task_info_t * task_info = &task_data->info[i];
    fd_exec_slot_ctx_t *           slot_ctx  = task_info->slot_ctx;
    fd_account_hash( slot_ctx->funk,
                     slot_ctx->funk_txn,
                     task_info,
                     lthash,
                     slot_ctx->bank->slot,
                     fd_bank_features_query( slot_ctx->bank )
      );
  }
}

void
fd_collect_modified_accounts( fd_exec_slot_ctx_t *           slot_ctx,
                              fd_accounts_hash_task_data_t * task_data,
                              fd_spad_t *                    runtime_spad ) {
  fd_funk_t *     funk = slot_ctx->funk;
  fd_funk_txn_t * txn  = slot_ctx->funk_txn;

  ulong rec_cnt = 0;
  for( fd_funk_rec_t const * rec = fd_funk_txn_first_rec( funk, txn );
       NULL != rec;
       rec = fd_funk_txn_next_rec( funk, rec ) ) {

    if( !fd_funk_key_is_acc( rec->pair.key  ) ) {
      continue;
    }

    fd_funk_rec_key_t const * pubkey = rec->pair.key;

    if (((pubkey->ul[0] == 0) & (pubkey->ul[1] == 0) & (pubkey->ul[2] == 0) & (pubkey->ul[3] == 0)))
      FD_LOG_WARNING(( "null pubkey (system program?) showed up as modified" ));

    rec_cnt++;
  }

  task_data->info    = fd_spad_alloc( runtime_spad, alignof(fd_accounts_hash_task_info_t), rec_cnt * sizeof(fd_accounts_hash_task_info_t) );
  task_data->info_sz = rec_cnt;

  /* Iterate over accounts that have been changed in the current
     database transaction. */
  ulong recs_iterated = 0;
  for( fd_funk_rec_t const * rec = fd_funk_txn_first_rec( funk, txn );
       NULL != rec;
       rec = fd_funk_txn_next_rec( funk, rec ) ) {

    if( !fd_funk_key_is_acc( rec->pair.key ) ) continue;

    fd_accounts_hash_task_info_t * task_info = &task_data->info[recs_iterated++];

    memcpy( task_info->acc_pubkey, rec->pair.key->uc, sizeof(fd_pubkey_t) );
    task_info->slot_ctx     = slot_ctx;
    task_info->hash_changed = 0;
    task_info->should_erase = 0;
  }

  if( FD_UNLIKELY( recs_iterated!=task_data->info_sz ) ) {
    FD_LOG_ERR(( "recs_iterated: %lu, task_data->info_sz: %lu", recs_iterated, task_data->info_sz ));
  }
}

int
fd_update_hash_bank_exec_hash( fd_exec_slot_ctx_t *           slot_ctx,
                               fd_hash_t *                    hash,
                               fd_capture_ctx_t *             capture_ctx,
                               fd_accounts_hash_task_data_t * task_datas,
                               ulong                          task_datas_cnt,
                               fd_lthash_value_t *            lt_hashes,
                               ulong                          lt_hashes_cnt,
                               ulong                          signature_cnt,
                               fd_spad_t *                    runtime_spad ) {
  ulong dirty_key_cnt = 0;

  fd_funk_t *     funk = slot_ctx->funk;
  fd_funk_txn_t * txn  = slot_ctx->funk_txn;

  // Apply the lthash changes to the bank lthash
  fd_slot_lthash_t * lthash_val = fd_bank_lthash_modify( slot_ctx->bank );
  for( ulong i = 0; i < lt_hashes_cnt; i++ ) {
    fd_lthash_add( (fd_lthash_value_t *)lthash_val->lthash, &lt_hashes[i] );
  }

  for( ulong j=0UL; j<task_datas_cnt; j++ ) {

    fd_accounts_hash_task_data_t * task_data = &task_datas[j];

    fd_pubkey_hash_pair_t * dirty_keys = fd_spad_alloc( runtime_spad,
                                                        FD_PUBKEY_HASH_PAIR_ALIGN,
                                                        task_data->info_sz * FD_PUBKEY_HASH_PAIR_FOOTPRINT );

    for( ulong i = 0; i < task_data->info_sz; i++ ) {
      fd_accounts_hash_task_info_t * task_info = &task_data->info[i];
      /* Upgrade to writable record */
      if( !task_info->hash_changed ) {
        continue;
      }

      FD_TXN_ACCOUNT_DECL( acc_rec );

      fd_pubkey_t const * acc_key = task_info->acc_pubkey;
      int err = fd_txn_account_init_from_funk_mutable( acc_rec, acc_key, funk, txn, 0, 0UL);
      if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_ERR(( "failed to modify account during bank hash" ));
      }

      /* Update hash */
      acc_rec->vt->set_hash( acc_rec, task_info->acc_hash );
      acc_rec->vt->set_slot( acc_rec, slot_ctx->bank->slot );

      fd_txn_account_mutable_fini( acc_rec, funk, txn );

      /* Add account to "dirty keys" list, which will be added to the
        bank hash. */

      fd_pubkey_hash_pair_t * dirty_entry = &dirty_keys[dirty_key_cnt++];
      dirty_entry->rec = acc_rec->vt->get_rec( acc_rec );
      dirty_entry->hash = acc_rec->vt->get_hash( acc_rec );

      char acc_key_string[ FD_BASE58_ENCODED_32_SZ ];
      fd_acct_addr_cstr( acc_key_string, (uchar const*)acc_key );
      char owner_string[ FD_BASE58_ENCODED_32_SZ ];
      fd_acct_addr_cstr( owner_string, acc_rec->vt->get_owner( acc_rec )->uc );

      FD_LOG_DEBUG(( "fd_acc_mgr_update_hash: %s "
                    "slot: %lu "
                    "lamports: %lu  "
                    "owner: %s "
                    "executable: %s,  "
                    "rent_epoch: %lu, "
                    "data_len: %lu",
                    acc_key_string,
                    slot_ctx->bank->slot,
                    acc_rec->vt->get_lamports( acc_rec ),
                    owner_string,
                    acc_rec->vt->is_executable( acc_rec ) ? "true" : "false",
                    acc_rec->vt->get_rent_epoch( acc_rec ),
                    acc_rec->vt->get_data_len( acc_rec ) ));

      if( capture_ctx != NULL && capture_ctx->capture != NULL && slot_ctx->bank->slot>=capture_ctx->solcap_start_slot ) {
        fd_account_meta_t const * acc_meta = fd_funk_get_acc_meta_readonly( slot_ctx->funk,
                                                                            slot_ctx->funk_txn,
                                                                            task_info->acc_pubkey,
                                                                            NULL,
                                                                            &err,
                                                                            NULL);
        if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
          FD_LOG_WARNING(( "failed to view account during capture" ));
          continue;
        }

        uchar const * acc_data = (uchar *)acc_meta + acc_meta->hlen;

        err = fd_solcap_write_account( capture_ctx->capture,
                                      acc_key->uc,
                                      acc_rec->vt->get_info( acc_rec ),
                                      acc_data,
                                      acc_rec->vt->get_data_len( acc_rec ),
                                      task_info->acc_hash->hash );

        if( FD_UNLIKELY( err ) ) {
          FD_LOG_ERR(( "Unable to write out solcap file" ));
        }
      }
    }

    /* Sort and hash "dirty keys" to the accounts delta hash. */

    fd_bank_signature_count_set( slot_ctx->bank, signature_cnt );

    fd_hash_bank( slot_ctx, capture_ctx, hash, dirty_keys, dirty_key_cnt);

    for( ulong i = 0; i < task_data->info_sz; i++ ) {
      fd_accounts_hash_task_info_t * task_info = &task_data->info[i];
      /* Upgrade to writable record */
      if( FD_LIKELY( !task_info->should_erase ) ) {
        continue;
      }

      /* All removed recs should be stored with the slot from the funk txn. */
      int err = FD_ACC_MGR_SUCCESS;
      fd_funk_rec_t const * rec = NULL;
      fd_funk_get_acc_meta_readonly( slot_ctx->funk,
        slot_ctx->funk_txn,
        task_info->acc_pubkey,
        &rec,
        &err,
        NULL);
      if( err != FD_ACC_MGR_SUCCESS ) {
        FD_LOG_ERR(( "failed to view account" ));
      }
      fd_funk_rec_remove( funk, txn, rec->pair.key, NULL, rec->pair.xid->ul[0] );
    }
  }

  return FD_EXECUTOR_INSTR_SUCCESS;

}

int
fd_update_hash_bank_tpool( fd_exec_slot_ctx_t * slot_ctx,
                           fd_capture_ctx_t *   capture_ctx,
                           fd_hash_t *          hash,
                           ulong                signature_cnt,
                           fd_tpool_t *         tpool,
                           fd_spad_t *          runtime_spad ) {

  /* Collect list of changed accounts to be added to bank hash */
  fd_accounts_hash_task_data_t * task_data = fd_spad_alloc( runtime_spad,
                                                            alignof(fd_accounts_hash_task_data_t),
                                                            sizeof(fd_accounts_hash_task_data_t) );

  fd_collect_modified_accounts( slot_ctx, task_data, runtime_spad );

  ulong wcnt = 0UL;

  /* Handle non-tpool case in a single-threaded manner */
  if( FD_LIKELY( tpool ) ){
    wcnt = fd_tpool_worker_cnt( tpool );
  } else {
    wcnt = 1UL;
  }


  fd_lthash_value_t * lt_hashes = fd_spad_alloc( runtime_spad,
                                                 FD_LTHASH_VALUE_ALIGN,
                                                 wcnt * FD_LTHASH_VALUE_FOOTPRINT );
  for( ulong i=0UL; i<wcnt; i++ ) {
    fd_lthash_zero( &lt_hashes[i] );
  }

  if( FD_LIKELY( tpool ) ) {
    ulong cnt_per_worker = (wcnt>1) ? (task_data->info_sz / (wcnt-1UL)) + 1UL : task_data->info_sz;
    for( ulong worker_idx=1UL; worker_idx<wcnt; worker_idx++ ) {
      ulong start_idx = (worker_idx-1UL) * cnt_per_worker;
      if( start_idx >= task_data->info_sz ) {
        wcnt = worker_idx;
        break;
      }
      ulong end_idx = fd_ulong_sat_sub((worker_idx) * cnt_per_worker, 1UL);
      if( end_idx >= task_data->info_sz )
        end_idx = fd_ulong_sat_sub( task_data->info_sz, 1UL );;
      fd_tpool_exec( tpool, worker_idx, fd_account_hash_task,
        task_data, start_idx, end_idx,
        &lt_hashes[worker_idx], slot_ctx, 0UL,
        0UL, 0UL, worker_idx, 0UL, 0UL, 0UL );
    }

    for( ulong worker_idx=1UL; worker_idx<wcnt; worker_idx++ ) {
      fd_tpool_wait( tpool, worker_idx );
    }
  } else {
    for( ulong i=0UL; i<task_data->info_sz; i++ ) {
      fd_accounts_hash_task_info_t * task_info = &task_data->info[i];
      fd_account_hash( slot_ctx->funk,
                       slot_ctx->funk_txn,
                       task_info,
                       &lt_hashes[ 0 ],
                       slot_ctx->bank->slot,
                       fd_bank_features_query( slot_ctx->bank ) );
    }
  }

  return fd_update_hash_bank_exec_hash( slot_ctx,
                                        hash,
                                        capture_ctx,
                                        task_data,
                                        1UL,
                                        lt_hashes,
                                        wcnt,
                                        signature_cnt,
                                        runtime_spad );
}

void const *
fd_hash_account( uchar                     hash[ static 32 ],
                 fd_lthash_value_t *       lthash,
                 fd_account_meta_t const * m,
                 fd_pubkey_t const *       pubkey,
                 uchar const *             data,
                 int                       hash_needed,
                 fd_features_t const *     features FD_PARAM_UNUSED ) {
  ulong         lamports   = m->info.lamports;  /* >0UL */
  ulong         rent_epoch = m->info.rent_epoch;
  uchar         executable = m->info.executable & 0x1;
  uchar const * owner      = (uchar const *)m->info.owner;

  if( (hash_needed & FD_HASH_JUST_ACCOUNT_HASH) ) {
    fd_blake3_t b3[1];
    fd_blake3_init  ( b3 );
    fd_blake3_append( b3, &lamports,   sizeof( ulong ) );
    fd_blake3_append( b3, &rent_epoch, sizeof( ulong ) );
    fd_blake3_append( b3, data,        m->dlen         );
    fd_blake3_append( b3, &executable, sizeof( uchar ) );
    fd_blake3_append( b3, owner,       32UL            );
    fd_blake3_append( b3, pubkey,      32UL            );
    fd_blake3_fini  ( b3, hash );
  }

  if( (hash_needed & FD_HASH_JUST_LTHASH) ) {
    fd_blake3_t b3[1];
    fd_blake3_init  ( b3 );
    fd_blake3_append( b3, &lamports,   sizeof( ulong ) );
    fd_blake3_append( b3, data,        m->dlen         );
    fd_blake3_append( b3, &executable, sizeof( uchar ) );
    fd_blake3_append( b3, owner,       32UL            );
    fd_blake3_append( b3, pubkey,      32UL            );
    fd_blake3_fini_varlen( b3, lthash->bytes, FD_LTHASH_LEN_BYTES );
  }

  return hash;
}

void const *
fd_hash_account_current( uchar                     hash[ static 32 ],
                         fd_lthash_value_t *       lthash,
                         fd_account_meta_t const * account,
                         fd_pubkey_t const       * pubkey,
                         uchar const *             data,
                         int                       hash_needed,
                         fd_features_t const *     features ) {
  return fd_hash_account( hash, lthash, account, pubkey, data, hash_needed, features );
}

struct accounts_hash {
  fd_funk_rec_t * key;
  ulong  hash;
};
typedef struct accounts_hash accounts_hash_t;

#define MAP_NAME accounts_hash
#define MAP_KEY_T fd_funk_rec_t *
#define MAP_HASH_T ulong
#define MAP_KEY_EQUAL(k0,k1) ((NULL != k0) && (NULL != k1) && fd_funk_rec_key_eq( k0->pair.key, k1->pair.key ))
#define MAP_KEY_HASH(p) fd_funk_rec_key_hash( p->pair.key, 2887034UL )
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_NULL 0UL
#define MAP_KEY_INVAL(k) (NULL == k)

// #define MAP_KEY_COPY(kd,ks)   fd_funk_xid_key_pair_copy((kd),(ks))

#define MAP_T    accounts_hash_t
#include "../../util/tmpl/fd_map_dynamic.c"

/* fd_accounts_sorted_subrange_count will determine the number of accounts that
   should be in the accounts slice for a given range_idx. This is split out to
   from fd_accounts_sorted_subrange_gather to avoid dynamic resizing of the pair.

   TODO: The common code in these functions could be factored out. */

ulong
fd_accounts_sorted_subrange_count( fd_funk_t * funk,
                                   uint        range_idx,
                                   uint        range_cnt ) {

  fd_wksp_t *           wksp      = fd_funk_wksp( funk );
  ulong                 num_pairs = 0UL;
  ulong                 range_len = ULONG_MAX/range_cnt;
  ulong                 range_min = range_len*range_idx;
  ulong                 range_max = (range_idx+1U<range_cnt) ? (range_min+range_len-1U) : ULONG_MAX;

  fd_funk_all_iter_t iter[1];
  for( fd_funk_all_iter_new( funk, iter );
       !fd_funk_all_iter_done( iter );
       fd_funk_all_iter_next( iter ) ) {
    fd_funk_rec_t const * rec = fd_funk_all_iter_ele_const( iter );

    if ( !fd_funk_key_is_acc( rec->pair.key ) ||         /* not a solana record */
        (rec->flags & FD_FUNK_REC_FLAG_ERASE) ||        /* this is a tombstone */
        (rec->pair.xid->ul[0] | rec->pair.xid->ul[1]) != 0 /* not root xid */ ) {
      continue;
    }

    ulong n = __builtin_bswap64( rec->pair.key->ul[0] );
    if( n<range_min || n>range_max ) {
      continue;
    }

    fd_account_meta_t * metadata = (fd_account_meta_t *)fd_funk_val_const( rec, wksp );
    int is_empty = (metadata->info.lamports == 0);
    if( is_empty ) {
      continue;
    }

    if( (metadata->info.executable & ~1) != 0 ) {
      continue;
    }

    num_pairs++;
  }

  return num_pairs;
}

void
fd_accounts_sorted_subrange_gather( fd_funk_t *             funk,
                                    uint                    range_idx,
                                    uint                    range_cnt,
                                    ulong *                 num_pairs_out,
                                    fd_lthash_value_t *     lthash_value_out,
                                    fd_pubkey_hash_pair_t * pairs,
                                    fd_features_t const *   features ) {

  fd_wksp_t *     wksp              = fd_funk_wksp( funk );
  ulong           num_pairs         = 0UL;
  ulong           range_len         = ULONG_MAX/range_cnt;
  ulong           range_min         = range_len*range_idx;
  ulong           range_max         = (range_idx+1U<range_cnt) ? (range_min+range_len-1U) : ULONG_MAX;

  fd_lthash_value_t accum = {0};

  fd_funk_all_iter_t iter[1];
  for( fd_funk_all_iter_new( funk, iter );
       !fd_funk_all_iter_done( iter );
       fd_funk_all_iter_next( iter ) ) {
    fd_funk_rec_t const * rec = fd_funk_all_iter_ele_const( iter );
    if ( !fd_funk_key_is_acc( rec->pair.key ) ||         /* not a solana record */
        (rec->flags & FD_FUNK_REC_FLAG_ERASE) ||        /* this is a tombstone */
        (rec->pair.xid->ul[0] | rec->pair.xid->ul[1]) != 0 /* not root xid */ ) {
      continue;
    }

    ulong n = __builtin_bswap64( rec->pair.key->ul[0] );
    if( n<range_min || n>range_max ) {
      continue;
    }
    fd_account_meta_t * metadata = (fd_account_meta_t *)fd_funk_val_const( rec, wksp );
    int is_empty = (metadata->info.lamports == 0);
    if( is_empty ) {
      continue;
    }

    /* FIXME: remove magic number */
    uchar hash[32];
    fd_lthash_value_t new_lthash_value = {0};

    fd_hash_account_current( (uchar *)hash, &new_lthash_value, metadata, fd_type_pun_const(rec->pair.key->uc), fd_account_meta_get_data( metadata ), FD_HASH_BOTH_HASHES, features  );
    fd_lthash_add( &accum, &new_lthash_value );

    fd_hash_t * h = (fd_hash_t *)metadata->hash;
    if( FD_LIKELY( (h->ul[0] | h->ul[1] | h->ul[2] | h->ul[3]) != 0 ) ) {
      if( FD_UNLIKELY( fd_account_meta_exists( metadata ) && memcmp( metadata->hash, &hash, 32 ) != 0 ) ) {
        FD_LOG_WARNING(( "snapshot hash (%s) doesn't match calculated hash (%s)", FD_BASE58_ENC_32_ALLOCA( metadata->hash ), FD_BASE58_ENC_32_ALLOCA( &hash ) ));
      }
    } else {
      fd_memcpy( metadata->hash, &hash, sizeof(fd_hash_t) );
    }

    if( (metadata->info.executable & ~1) != 0 ) {
      continue;
    }

    fd_pubkey_hash_pair_t * pair = &pairs[num_pairs++];
    pair->rec                    = rec;
    pair->hash                   = (const fd_hash_t *)metadata->hash;
  }

  sort_pubkey_hash_pair_inplace( pairs, num_pairs );

  *num_pairs_out = num_pairs;

  if (lthash_value_out) {
    fd_lthash_add( lthash_value_out, &accum  );
  }
}

static void
fd_accounts_sorted_subrange_count_task( void *tpool,
                                        ulong t0 FD_PARAM_UNUSED, ulong t1 FD_PARAM_UNUSED,
                                        void *args FD_PARAM_UNUSED,
                                        void *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                                        ulong l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
                                        ulong m0, ulong m1 FD_PARAM_UNUSED,
                                        ulong n0 FD_PARAM_UNUSED, ulong n1 FD_PARAM_UNUSED ) {
  fd_subrange_task_info_t * task_info = (fd_subrange_task_info_t *)tpool;
  task_info->lists[m0].pairs_len = fd_accounts_sorted_subrange_count( task_info->funk,
                                                                      (uint)m0,
                                                                      (uint)task_info->num_lists );
}

static void
fd_accounts_sorted_subrange_gather_task( void *tpool,
                                         ulong t0 FD_PARAM_UNUSED, ulong t1 FD_PARAM_UNUSED,
                                         void *args FD_PARAM_UNUSED,
                                         void *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                                         ulong l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
                                         ulong m0, ulong m1 FD_PARAM_UNUSED,
                                         ulong n0 FD_PARAM_UNUSED, ulong n1 FD_PARAM_UNUSED ) {
  fd_subrange_task_info_t * task_info = (fd_subrange_task_info_t *)tpool;
  fd_accounts_sorted_subrange_gather( task_info->funk, (uint)m0, (uint)task_info->num_lists,
                                      &task_info->lists[m0].pairs_len, &task_info->lthash_values[m0],
                                      task_info->lists[m0].pairs, task_info->features );
}

void
fd_accounts_hash_counter_and_gather_tpool_cb( void * para_arg_1,
                                              void * para_arg_2 FD_PARAM_UNUSED,
                                              void * fn_arg_1,
                                              void * fn_arg_2,
                                              void * fn_arg_3 FD_PARAM_UNUSED,
                                              void * fn_arg_4 FD_PARAM_UNUSED ) {
  fd_tpool_t *              tpool        = (fd_tpool_t *)para_arg_1;
  fd_subrange_task_info_t * task_info    = (fd_subrange_task_info_t *)fn_arg_1;
  fd_spad_t *               runtime_spad = (fd_spad_t *)fn_arg_2;

  ulong num_lists = fd_tpool_worker_cnt( tpool ) - 1UL;

  fd_pubkey_hash_pair_list_t * lists         = fd_spad_alloc( runtime_spad, alignof(fd_pubkey_hash_pair_list_t), num_lists * sizeof(fd_pubkey_hash_pair_list_t) );
  fd_lthash_value_t *          lthash_values = fd_spad_alloc( runtime_spad, FD_LTHASH_VALUE_ALIGN, num_lists * FD_LTHASH_VALUE_FOOTPRINT );
  for( ulong i = 0; i < num_lists; i++ ) {
    fd_lthash_zero(&lthash_values[i] );
  }

  task_info->num_lists     = num_lists;
  task_info->lists         = lists;
  task_info->lthash_values = lthash_values;

  /* Exec and wait counting the number of records to hash and exec */
  ulong worker_cnt = fd_tpool_worker_cnt( tpool );
  for( ulong worker_idx=1UL; worker_idx<worker_cnt; worker_idx++ ) {
    fd_tpool_exec( tpool, worker_idx, fd_accounts_sorted_subrange_count_task, task_info, 0UL,
                   0UL, NULL, NULL, 0UL, 0UL, 0UL, worker_idx-1UL, 0UL, 0UL, 0UL );
  }

  for( ulong worker_idx=1UL; worker_idx<worker_cnt; worker_idx++ ) {
    fd_tpool_wait( tpool, worker_idx );
  }

  /* Allocate out the number of pairs calculated. */
  for( ulong i=0UL; i<task_info->num_lists; i++ ) {
    task_info->lists[i].pairs     = fd_spad_alloc( runtime_spad,
                                                   FD_PUBKEY_HASH_PAIR_ALIGN,
                                                   task_info->lists[i].pairs_len * sizeof(fd_pubkey_hash_pair_t) );
    task_info->lists[i].pairs_len = 0UL;
  }

  /* Exec and wait gathering the accounts to hash. */
  for( ulong worker_idx=1UL; worker_idx<worker_cnt; worker_idx++ ) {
    fd_tpool_exec( tpool, worker_idx, fd_accounts_sorted_subrange_gather_task, task_info, 0UL,
                    0UL, NULL, NULL, 0UL, 0UL, 0UL, worker_idx-1UL, 0UL, 0UL, 0UL );
  }

  for( ulong worker_idx=1UL; worker_idx<worker_cnt; worker_idx++ ) {
    fd_tpool_wait( tpool, worker_idx );
  }

}

int
fd_accounts_hash( fd_funk_t *             funk,
                  ulong                   slot,
                  fd_hash_t *             accounts_hash,
                  fd_spad_t *             runtime_spad,
                  fd_features_t const *   features,
                  fd_exec_para_cb_ctx_t * exec_para_ctx,
                  fd_lthash_value_t *     lt_hash ) {

  int lthash_enabled = (NULL != lt_hash) && (FD_FEATURE_ACTIVE( slot, features, snapshots_lt_hash ) || FD_FEATURE_ACTIVE( slot, features, accounts_lt_hash ) );

  FD_LOG_NOTICE(("accounts_hash start"));

  /* FIXME: this is not the correct lock to use, although in reality this is fine as we never modify
     accounts at the same time as hashing them. Once the hashing has been moved into tiles, we need to
     change it so that we partition by hash chains, and acquire the lock on the individual hash chains. */
  fd_funk_rec_pool_t * rec_pool = fd_funk_rec_pool( funk );
  fd_funk_rec_pool_lock( rec_pool, 1 );
  fd_funk_txn_start_read( funk );

  if( fd_exec_para_cb_is_single_threaded( exec_para_ctx ) ) {
    ulong               num_pairs     = 0UL;
    fd_lthash_value_t * lthash_values = ( NULL != lt_hash ) ? fd_spad_alloc( runtime_spad, FD_LTHASH_VALUE_ALIGN, FD_LTHASH_VALUE_FOOTPRINT ) : NULL;

    if ( NULL != lt_hash )
      fd_lthash_zero( &lthash_values[0] );

    fd_pubkey_hash_pair_t * pairs =
        fd_spad_alloc( runtime_spad, FD_PUBKEY_HASH_PAIR_ALIGN, fd_funk_rec_max( funk ) * sizeof(fd_pubkey_hash_pair_t) );

    fd_accounts_sorted_subrange_gather( funk, 0, 1, &num_pairs, lthash_values, pairs, features );
    if( FD_UNLIKELY( !pairs ) ) {
      FD_LOG_ERR(( "failed to allocate memory for account hash" ));
    }
    fd_pubkey_hash_pair_list_t list1 = { .pairs = pairs, .pairs_len = num_pairs };
    fd_hash_account_deltas( &list1, 1, accounts_hash );

    if ( NULL != lt_hash )
      fd_lthash_add( lt_hash, &lthash_values[0] );

  } else {
    /* First calculate how big the list needs to be sized out to be, bump
       allocate the size of the array then caclulate the hash. */

    fd_subrange_task_info_t task_info = {
      .features      = features,
      .funk          = funk,
    };

    exec_para_ctx->fn_arg_1 = &task_info;
    exec_para_ctx->fn_arg_2 = runtime_spad;
    fd_exec_para_call_func( exec_para_ctx );

    fd_hash_account_deltas( task_info.lists, task_info.num_lists, accounts_hash );

    if ( NULL!= lt_hash ) {
      for( ulong i = 0UL; i < task_info.num_lists; i++ ) {
        fd_lthash_add( lt_hash, &task_info.lthash_values[i] );
      }
    }
  }

  if( lthash_enabled ) {
    FD_LOG_NOTICE(( "accounts_lthash %s", FD_LTHASH_ENC_32_ALLOCA( lt_hash ) ));
  } else {
    FD_LOG_NOTICE(( "accounts_hash %s", FD_BASE58_ENC_32_ALLOCA( accounts_hash->hash ) ));
  }

  fd_funk_rec_pool_unlock( rec_pool );
  fd_funk_txn_end_read( funk );

  return 0;
}

int
fd_accounts_hash_inc_only( fd_exec_slot_ctx_t * slot_ctx,
                           fd_hash_t *          accounts_hash,
                           fd_funk_txn_t *      child_txn,
                           ulong                do_hash_verify,
                           fd_spad_t *          spad ) {
  FD_LOG_NOTICE(( "accounts_hash_inc_only start for txn %p, do_hash_verify=%s", (void *)child_txn, do_hash_verify ? "true" : "false" ));

  FD_SPAD_FRAME_BEGIN( spad ) {

  fd_funk_t * funk = slot_ctx->funk;
  fd_wksp_t * wksp = fd_funk_wksp( funk );

  // How many total records are we dealing with?
  ulong                   num_pairs         = 0UL;
  ulong                   num_iter_accounts = 0UL;
  for (fd_funk_rec_t const *rec = fd_funk_txn_first_rec( funk, child_txn ); NULL != rec; rec = fd_funk_txn_next_rec(funk, rec)) {
    if ( !fd_funk_key_is_acc( rec->pair.key ) || ( rec->flags & FD_FUNK_REC_FLAG_ERASE ) )
      continue;
    ++num_iter_accounts;
  }

  fd_pubkey_hash_pair_t * pairs             = fd_spad_alloc( spad, FD_PUBKEY_HASH_PAIR_ALIGN, num_iter_accounts * sizeof(fd_pubkey_hash_pair_t) );
  if( FD_UNLIKELY( !pairs ) ) {
    FD_LOG_ERR(( "failed to allocate memory for pairs" ));
  }

  fd_blake3_t * b3 = NULL;

  for (fd_funk_rec_t const *rec = fd_funk_txn_first_rec( funk, child_txn ); NULL != rec; rec = fd_funk_txn_next_rec(funk, rec)) {
    if ( !fd_funk_key_is_acc( rec->pair.key ) || ( rec->flags & FD_FUNK_REC_FLAG_ERASE ) )
      continue;

    fd_account_meta_t * metadata = (fd_account_meta_t *) fd_funk_val_const( rec, wksp );
    int is_empty = (metadata->info.lamports == 0);

    if (is_empty) {
      pairs[num_pairs].rec = rec;

      fd_hash_t * hash = fd_spad_alloc( spad, alignof(fd_hash_t), sizeof(fd_hash_t) );
      if( NULL == b3 ) {
        b3 = fd_spad_alloc( spad, alignof(fd_blake3_t), sizeof(fd_blake3_t) );
      }
      fd_blake3_init( b3 );
      fd_blake3_append( b3, rec->pair.key->uc, sizeof( fd_pubkey_t ) );
      fd_blake3_fini( b3, hash );

      pairs[num_pairs].hash = hash;
      num_pairs++;
      continue;
    } else {
      fd_hash_t *h = (fd_hash_t *) metadata->hash;
      if ((h->ul[0] | h->ul[1] | h->ul[2] | h->ul[3]) == 0) {
        // By the time we fall into this case, we can assume the ignore_slot feature is enabled...
        fd_hash_account_current( (uchar *) metadata->hash, NULL, metadata, fd_type_pun_const(rec->pair.key->uc), fd_account_meta_get_data(metadata), FD_HASH_JUST_ACCOUNT_HASH, fd_bank_features_query( slot_ctx->bank ) );
      } else if( do_hash_verify ) {
        uchar hash[32];
        // ulong old_slot = slot_ctx->bank->slot;
        // slot_ctx->bank->slot = metadata->slot;
        fd_hash_account_current( (uchar *) &hash, NULL, metadata, fd_type_pun_const(rec->pair.key->uc), fd_account_meta_get_data(metadata), FD_HASH_JUST_ACCOUNT_HASH, fd_bank_features_query( slot_ctx->bank ) );
        // slot_ctx->bank->slot = old_slot;
        if ( fd_account_meta_exists( metadata ) && memcmp( metadata->hash, &hash, 32 ) != 0 ) {
          FD_LOG_WARNING(( "snapshot hash (%s) doesn't match calculated hash (%s)", FD_BASE58_ENC_32_ALLOCA( metadata->hash ), FD_BASE58_ENC_32_ALLOCA( &hash ) ));
        }
      }
    }

    if ((metadata->info.executable & ~1) != 0)
      continue;

    pairs[num_pairs].rec = rec;
    pairs[num_pairs].hash = (const fd_hash_t *)metadata->hash;
    num_pairs++;
  }

  sort_pubkey_hash_pair_inplace( pairs, num_pairs );
  fd_pubkey_hash_pair_list_t list1 = { .pairs = pairs, .pairs_len = num_pairs };
  fd_hash_account_deltas( &list1, 1, accounts_hash );

  FD_LOG_INFO(( "accounts_hash %s", FD_BASE58_ENC_32_ALLOCA( accounts_hash->hash) ));

  } FD_SPAD_FRAME_END;

  return 0;
}

/* Same as fd_accounts_hash_inc_only but takes a list of pubkeys to hash.
   Query the accounts from the root of funk. This is done as a read-only
   way to generate an accounts hash from a subset of accounts from funk. */
static int
fd_accounts_hash_inc_no_txn( fd_funk_t *                 funk,
                             fd_hash_t *                 accounts_hash,
                             fd_funk_rec_key_t const * * pubkeys,
                             ulong                       pubkeys_len,
                             ulong                       do_hash_verify,
                             fd_spad_t *                 spad,
                             fd_features_t *             features ) {
  FD_LOG_NOTICE(( "accounts_hash_inc_no_txn" ));

  fd_wksp_t *     wksp    = fd_funk_wksp( funk );

  /* Pre-allocate the number of pubkey pairs that we are iterating over. */

  FD_SPAD_FRAME_BEGIN( spad ) {

  ulong                   num_pairs         = 0UL;
  fd_pubkey_hash_pair_t * pairs             = fd_spad_alloc( spad,
                                                             FD_PUBKEY_HASH_PAIR_ALIGN,
                                                             pubkeys_len * sizeof(fd_pubkey_hash_pair_t) );

  if( FD_UNLIKELY( !pairs ) ) {
    FD_LOG_ERR(( "failed to allocate memory for pairs" ));
  }

  fd_blake3_t * b3 = NULL;


  for( ulong i=0UL; i<pubkeys_len; i++ ) {
    fd_funk_rec_query_t query[1];
    fd_funk_rec_t const * rec = fd_funk_rec_query_try( funk, NULL, pubkeys[i], query );

    fd_account_meta_t * metadata = (fd_account_meta_t *) fd_funk_val_const( rec, wksp );
    int is_empty = (!metadata || metadata->info.lamports == 0);

    if( is_empty ) {
      pairs[num_pairs].rec = rec;

      fd_hash_t * hash = fd_spad_alloc( spad, alignof(fd_hash_t), sizeof(fd_hash_t) );
      if( !b3 ) {
        b3 = fd_spad_alloc( spad, alignof(fd_blake3_t), sizeof(fd_blake3_t) );
      }
      fd_blake3_init( b3 );
      fd_blake3_append( b3, rec->pair.key->uc, sizeof(fd_pubkey_t) );
      fd_blake3_fini( b3, hash );

      pairs[ num_pairs ].hash = hash;
      num_pairs++;
      continue;
    } else {
      fd_hash_t *h = (fd_hash_t*)metadata->hash;
      if( !(h->ul[ 0 ] | h->ul[ 1 ] | h->ul[ 2 ] | h->ul[ 3 ]) ) {
        // By the time we fall into this case, we can assume the ignore_slot feature is enabled...
        fd_hash_account_current( (uchar*)metadata->hash, NULL, metadata, fd_type_pun_const(rec->pair.key->uc), fd_account_meta_get_data( metadata ), FD_HASH_JUST_ACCOUNT_HASH, features );
      } else if( do_hash_verify ) {
        uchar hash[ FD_HASH_FOOTPRINT ];
        fd_hash_account_current( (uchar*)&hash, NULL, metadata, fd_type_pun_const(rec->pair.key->uc), fd_account_meta_get_data( metadata ), FD_HASH_JUST_ACCOUNT_HASH, features );
        if( fd_account_meta_exists( metadata ) && memcmp( metadata->hash, &hash, FD_HASH_FOOTPRINT ) ) {
          FD_LOG_WARNING(( "snapshot hash (%s) doesn't match calculated hash (%s)", FD_BASE58_ENC_32_ALLOCA(metadata->hash), FD_BASE58_ENC_32_ALLOCA(&hash) ));
        }
      }
    }

    if( (metadata->info.executable & ~1) ) {
      continue;
    }

    pairs[ num_pairs ].rec = rec;
    pairs[ num_pairs ].hash = (fd_hash_t const *)metadata->hash;
    num_pairs++;

    FD_TEST( !fd_funk_rec_query_test( query ) );
  }

  sort_pubkey_hash_pair_inplace( pairs, num_pairs );
  fd_pubkey_hash_pair_list_t list1 = { .pairs = pairs, .pairs_len = num_pairs };
  fd_hash_account_deltas( &list1, 1, accounts_hash );

  } FD_SPAD_FRAME_END;

  FD_LOG_INFO(( "accounts_hash %s", FD_BASE58_ENC_32_ALLOCA( accounts_hash->hash ) ));

  return 0;
}


/* TODO: Combine with the above to get correct snapshot hash verification. */

int
fd_snapshot_service_hash( fd_hash_t *       accounts_hash,
                          fd_hash_t *       snapshot_hash,
                          fd_funk_t *       funk,
                          fd_tpool_t *      tpool,
                          fd_spad_t *       runtime_spad,
                          fd_features_t *   features ) {

  fd_sha256_t h;

  fd_exec_para_cb_ctx_t exec_para_ctx = {
    .func       = fd_accounts_hash_counter_and_gather_tpool_cb,
    .para_arg_1 = tpool
  };

  /* FIXME: this has an invalid slot number. */
  fd_accounts_hash( funk, 0UL, accounts_hash, runtime_spad, features, &exec_para_ctx, NULL );


  // int should_include_eah = eah_stop_slot != ULONG_MAX && eah_start_slot == ULONG_MAX;
  int should_include_eah = 0;

  if( should_include_eah ) {
    fd_sha256_init( &h );
    fd_sha256_append( &h, (uchar const *) accounts_hash, sizeof( fd_hash_t ) );
    // fd_sha256_append( &h, (uchar const *) slot_bank->epoch_account_hash.hash, sizeof( fd_hash_t ) );
    fd_sha256_fini( &h, snapshot_hash );
  } else {
    *snapshot_hash = *accounts_hash;
  }

  return 0;
}

int
fd_snapshot_service_inc_hash( fd_hash_t *                 accounts_hash,
                              fd_hash_t *                 snapshot_hash,
                              fd_funk_t *                 funk,
                              fd_funk_rec_key_t const * * pubkeys,
                              ulong                       pubkeys_len,
                              fd_spad_t *                 spad,
                              fd_features_t              *features ) {
  fd_sha256_t h;
  fd_accounts_hash_inc_no_txn( funk, accounts_hash, pubkeys, pubkeys_len, 0UL, spad, features );

  int should_include_eah = 0;

  if( should_include_eah ) {
    fd_sha256_init( &h );
    fd_sha256_append( &h, (uchar const *) accounts_hash, sizeof( fd_hash_t ) );
    // fd_sha256_append( &h, (uchar const *) slot_bank->epoch_account_hash.hash, sizeof( fd_hash_t ) );
    fd_sha256_fini( &h, snapshot_hash );
  } else {
    *snapshot_hash = *accounts_hash;
  }

  return 0;
}

/* Re-computes the lthash from the current slot */
void
fd_accounts_check_lthash( fd_funk_t *      funk,
                          fd_funk_txn_t *  funk_txn,
                          fd_spad_t *      runtime_spad,
                          fd_features_t *  features ) {

  fd_wksp_t *          wksp     = fd_funk_wksp( funk );
  fd_funk_txn_pool_t * txn_pool = fd_funk_txn_pool( funk );

  // How many txns are we dealing with?
  fd_funk_txn_start_read( funk );
  ulong txn_cnt = 1;
  fd_funk_txn_t * txn = funk_txn;
  while (NULL != txn) {
    txn_cnt++;
    txn = fd_funk_txn_parent( txn, txn_pool );
  }

  fd_funk_txn_t ** txns = fd_alloca_check(sizeof(fd_funk_txn_t *), sizeof(fd_funk_txn_t *) * txn_cnt);
  if ( FD_UNLIKELY(NULL == txns))
    FD_LOG_ERR(( "Unable to allocate txn pointers" ));

  // Lay it flat to make it easier to walk backwards up the chain from
  // the root
  txn = funk_txn;
  ulong txn_idx = txn_cnt;
  while (1) {
    txns[--txn_idx] = txn;
    if (NULL == txn)
      break;
    txn = fd_funk_txn_parent( txn, txn_pool );
  }

  // How many total records are we dealing with?
  ulong num_iter_accounts = fd_funk_rec_max( funk );

  int accounts_hash_slots = fd_ulong_find_msb(num_iter_accounts  ) + 1;

  FD_LOG_WARNING(("allocating memory for hash.  num_iter_accounts: %lu   slots: %d", num_iter_accounts, accounts_hash_slots));
  void * hashmem = fd_spad_alloc( runtime_spad, accounts_hash_align(), accounts_hash_footprint(accounts_hash_slots));
  FD_LOG_WARNING(("initializing memory for hash"));
  accounts_hash_t * hash_map = accounts_hash_join(accounts_hash_new(hashmem, accounts_hash_slots));

  FD_LOG_WARNING(("copying in accounts"));

  // walk up the transactions...
  for (ulong idx = 0; idx < txn_cnt; idx++) {
    for (fd_funk_rec_t const *rec = fd_funk_txn_first_rec( funk, txns[idx]);
         NULL != rec;
         rec = fd_funk_txn_next_rec(funk, rec)) {
      if ( fd_funk_key_is_acc( rec->pair.key ) && !( rec->flags & FD_FUNK_REC_FLAG_ERASE ) ) {
        accounts_hash_t * q = accounts_hash_query(hash_map, (fd_funk_rec_t *) rec, NULL);
        if (NULL != q)
          accounts_hash_remove(hash_map, q);
        if (!(rec->flags & FD_FUNK_REC_FLAG_ERASE))
          accounts_hash_insert(hash_map, (fd_funk_rec_t *) rec);
      }
    }
  }

  FD_LOG_WARNING(("assumulating a new lthash"));

  // Initialize the accumulator to zero
  fd_lthash_value_t acc_lthash;
  fd_lthash_zero( &acc_lthash );

  ulong slot_cnt = accounts_hash_slot_cnt(hash_map);;
  for( ulong slot_idx=0UL; slot_idx<slot_cnt; slot_idx++ ) {
    accounts_hash_t *slot = &hash_map[slot_idx];
    if (FD_UNLIKELY (NULL != slot->key)) {
      void const * data = fd_funk_val_const( slot->key, wksp );
      fd_account_meta_t * metadata = (fd_account_meta_t *)fd_type_pun_const( data );
      if( FD_UNLIKELY(metadata->info.lamports != 0) ) {
        uchar * acc_data = fd_account_meta_get_data(metadata);
        uchar hash  [ 32 ];
        fd_lthash_value_t new_lthash_value;
        fd_lthash_zero(&new_lthash_value);
        fd_hash_account_current( hash, &new_lthash_value, metadata, fd_type_pun_const(slot->key->pair.key[0].uc), acc_data, FD_HASH_BOTH_HASHES, features );
        fd_lthash_add( &acc_lthash, &new_lthash_value );

        if (fd_account_meta_exists( metadata ) && memcmp( metadata->hash, &hash, 32 ) != 0 ) {
          FD_LOG_WARNING(( "snapshot hash (%s) doesn't match calculated hash (%s)", FD_BASE58_ENC_32_ALLOCA( metadata->hash ), FD_BASE58_ENC_32_ALLOCA( &hash ) ));
        }
      }
    }
  }

  // Compare the accumulator to the slot
  fd_lthash_value_t * acc = (fd_lthash_value_t *)fd_type_pun_const( NULL );
  if ( memcmp( acc, &acc_lthash, sizeof( fd_lthash_value_t ) ) == 0 ) {
    FD_LOG_NOTICE(("accounts_lthash %s == %s", FD_LTHASH_ENC_32_ALLOCA (acc), FD_LTHASH_ENC_32_ALLOCA (&acc_lthash)));
  } else {
    FD_LOG_ERR(("accounts_lthash %s != %s", FD_LTHASH_ENC_32_ALLOCA (acc), FD_LTHASH_ENC_32_ALLOCA (&acc_lthash)));
  }

  fd_funk_txn_end_read( funk );
}
