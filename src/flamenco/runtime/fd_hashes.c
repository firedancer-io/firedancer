#include "fd_hashes.h"
#include "fd_acc_mgr.h"
#include "fd_runtime.h"
#include "fd_account.h"
#include "context/fd_capture_ctx.h"
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

struct fd_pubkey_hash_pair_list {
  fd_pubkey_hash_pair_t * pairs;
  ulong pairs_len;
};
typedef struct fd_pubkey_hash_pair_list fd_pubkey_hash_pair_list_t;

static void
fd_hash_account_deltas( fd_pubkey_hash_pair_list_t * lists, ulong lists_len, fd_hash_t * hash, fd_exec_slot_ctx_t * slot_ctx FD_PARAM_UNUSED ) {
  fd_sha256_t shas[FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT];
  uchar       num_hashes[FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT+1];

  // Init the number of hashes
  fd_memset( num_hashes, 0, sizeof(num_hashes) );

  // FD_LOG_DEBUG(("sorting %d", pairs_len));
  // long timer_sort = -fd_log_wallclock();
  // sort_pubkey_hash_pair_inplace( pairs, pairs_len );
  // timer_sort += fd_log_wallclock();
  // FD_LOG_DEBUG(("sorting done %6.3f ms", (double)timer_sort*(1e-6)));

  // FD_LOG_DEBUG(("fancy bmtree started"));
  for( ulong j = 0; j < FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT; ++j ) {
    fd_sha256_init( &shas[j] );
}

  if( lists_len == 0 ) {
    fd_sha256_fini( &shas[0], hash->hash );
    return;
  }

  fd_pubkey_hash_pair_t * prev_pair = NULL;
  for( ulong k = 0; k < lists_len; ++k ) {
    fd_pubkey_hash_pair_t * pairs = lists[k].pairs;
    ulong pairs_len               = lists[k].pairs_len;
    for( ulong i = 0; i < pairs_len; ++i ) {
#ifdef VLOG
      FD_LOG_NOTICE(( "account delta hash X { \"key\":%ld, \"pubkey\":\"%s\", \"hash\":\"%s\" },",
                      i,
                      FD_BASE58_ENC_32_ALLOCA( pairs[i].pubkey->key ),
                      FD_BASE58_ENC_32_ALLOCA( pairs[i].hash->hash ) ));
#endif

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
  for (ulong k = 0; k < FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT; ++k ) {
    tot_num_hashes += num_hashes[k];
  }

  if (tot_num_hashes == 1) {
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
fd_calculate_epoch_accounts_hash_values(fd_exec_slot_ctx_t * slot_ctx) {
  if( !FD_FEATURE_ACTIVE( slot_ctx, epoch_accounts_hash ) )
    return;

  ulong slot_idx = 0;
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  ulong epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, slot_ctx->slot_bank.slot, &slot_idx );

  ulong slots_per_epoch = fd_epoch_slot_cnt( &epoch_bank->epoch_schedule, epoch );
  ulong first_slot_in_epoch           = fd_epoch_slot0   ( &epoch_bank->epoch_schedule, epoch );

  ulong calculation_offset_start = slots_per_epoch / 4;
  ulong calculation_offset_stop = slots_per_epoch / 4 * 3;
  ulong calculation_interval = fd_ulong_sat_sub(calculation_offset_stop, calculation_offset_start);

  // This came from the vote program.. maybe we need to put it into a header?
  const ulong MAX_LOCKOUT_HISTORY = 31UL;
  const ulong CALCULATION_INTERVAL_BUFFER = 150UL;
  const ulong MINIMUM_CALCULATION_INTERVAL = MAX_LOCKOUT_HISTORY + CALCULATION_INTERVAL_BUFFER;

  if (calculation_interval < MINIMUM_CALCULATION_INTERVAL) {
    epoch_bank->eah_start_slot = ULONG_MAX;
    epoch_bank->eah_stop_slot = ULONG_MAX;
    epoch_bank->eah_interval = ULONG_MAX;
    return;
  }

  epoch_bank->eah_start_slot = first_slot_in_epoch + calculation_offset_start;
  if (slot_ctx->slot_bank.slot > epoch_bank->eah_start_slot)
    epoch_bank->eah_start_slot = ULONG_MAX;
  epoch_bank->eah_stop_slot = first_slot_in_epoch + calculation_offset_stop;
  if (slot_ctx->slot_bank.slot > epoch_bank->eah_stop_slot)
    epoch_bank->eah_stop_slot = ULONG_MAX;
  epoch_bank->eah_interval = calculation_interval;
}

// https://github.com/solana-labs/solana/blob/b0dcaf29e358c37a0fcb8f1285ce5fff43c8ec55/runtime/src/bank/epoch_accounts_hash_utils.rs#L13
static int
fd_should_include_epoch_accounts_hash(fd_exec_slot_ctx_t * slot_ctx) {
  if( FD_LIKELY (!FD_FEATURE_ACTIVE( slot_ctx, epoch_accounts_hash ) ) )
    return 0;

  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  ulong calculation_stop = epoch_bank->eah_stop_slot;
  return slot_ctx->slot_bank.prev_slot < calculation_stop && (slot_ctx->slot_bank.slot >= calculation_stop);
}

static int
fd_should_snapshot_include_epoch_accounts_hash(fd_exec_slot_ctx_t * slot_ctx) {
  if( FD_LIKELY (!FD_FEATURE_ACTIVE( slot_ctx, epoch_accounts_hash ) ) )
    return 0;

  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );

  // We need to find the correct logic
  if (epoch_bank->eah_start_slot != ULONG_MAX)
    return 0;
  if (epoch_bank->eah_stop_slot == ULONG_MAX)
    return 0;
  return 1;
}

// slot_ctx should be const.
static void
fd_hash_bank( fd_exec_slot_ctx_t * slot_ctx,
              fd_capture_ctx_t * capture_ctx,
              fd_hash_t * hash,
              fd_pubkey_hash_pair_t * dirty_keys,
              ulong dirty_key_cnt ) {
  slot_ctx->prev_banks_hash = slot_ctx->slot_bank.banks_hash;
  slot_ctx->parent_signature_cnt = slot_ctx->signature_cnt;
  slot_ctx->prev_lamports_per_signature = slot_ctx->slot_bank.lamports_per_signature;
  slot_ctx->parent_transaction_count = slot_ctx->slot_bank.transaction_count;

  sort_pubkey_hash_pair_inplace( dirty_keys, dirty_key_cnt );
  fd_pubkey_hash_pair_list_t list1 = { .pairs = dirty_keys, .pairs_len = dirty_key_cnt };
  fd_hash_account_deltas(&list1, 1, &slot_ctx->account_delta_hash, slot_ctx );

  fd_sha256_t sha;
  fd_sha256_init( &sha );
  fd_sha256_append( &sha, (uchar const *) &slot_ctx->slot_bank.banks_hash, sizeof( fd_hash_t ) );
  fd_sha256_append( &sha, (uchar const *) &slot_ctx->account_delta_hash, sizeof( fd_hash_t  ) );
  fd_sha256_append( &sha, (uchar const *) &slot_ctx->signature_cnt, sizeof( ulong ) );
  fd_sha256_append( &sha, (uchar const *) &slot_ctx->slot_bank.poh, sizeof( fd_hash_t ) );

  fd_sha256_fini( &sha, hash->hash );

  if (fd_should_include_epoch_accounts_hash(slot_ctx)) {
    fd_sha256_init( &sha );
    fd_sha256_append( &sha, (uchar const *) &hash->hash, sizeof( fd_hash_t ) );

    fd_sha256_append( &sha, (uchar const *) &slot_ctx->slot_bank.epoch_account_hash.hash, sizeof( fd_hash_t ) );

    fd_sha256_fini( &sha, hash->hash );
  }

  if( capture_ctx != NULL && capture_ctx->capture != NULL ) {
    fd_solcap_write_bank_preimage(
        capture_ctx->capture,
        hash->hash,
        slot_ctx->prev_banks_hash.hash,
        slot_ctx->account_delta_hash.hash,
        &slot_ctx->slot_bank.poh.hash,
        slot_ctx->signature_cnt );
  }

  FD_LOG_NOTICE(( "\n\n[Replay]\n"
                  "slot:             %lu\n"
                  "bank hash:        %s\n"
                  "parent bank hash: %s\n"
                  "accounts_delta:   %s\n"
                  "lthash:           %s\n"
                  "signature_count:  %ld\n"
                  "last_blockhash:   %s\n",
                  slot_ctx->slot_bank.slot,
                  FD_BASE58_ENC_32_ALLOCA( hash->hash ),
                  FD_BASE58_ENC_32_ALLOCA( slot_ctx->prev_banks_hash.hash ),
                  FD_BASE58_ENC_32_ALLOCA( slot_ctx->account_delta_hash.hash ),
                  FD_LTHASH_ENC_32_ALLOCA( (fd_lthash_value_t *) slot_ctx->slot_bank.lthash.lthash ),
                  slot_ctx->signature_cnt,
                  FD_BASE58_ENC_32_ALLOCA( slot_ctx->slot_bank.poh.hash ) ));
}

struct fd_accounts_hash_task_info {
  fd_exec_slot_ctx_t * slot_ctx;
  fd_pubkey_t acc_pubkey[1];
  fd_hash_t acc_hash[1];
  fd_funk_rec_t const * rec;
  uint should_erase;
  uint hash_changed;
};
typedef struct fd_accounts_hash_task_info fd_accounts_hash_task_info_t;

struct fd_accounts_hash_task_data {
  struct fd_accounts_hash_task_info *info;
  ulong                              info_sz;
  fd_lthash_value_t                 *lthash_values;
};
typedef struct fd_accounts_hash_task_data fd_accounts_hash_task_data_t;

static void
fd_account_hash_task( void *tpool,
                      ulong t0 FD_PARAM_UNUSED, ulong t1 FD_PARAM_UNUSED,
                      void *args FD_PARAM_UNUSED,
                      void *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                      ulong l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
                      ulong m0, ulong m1 FD_PARAM_UNUSED,
                      ulong n0 FD_PARAM_UNUSED, ulong n1 FD_PARAM_UNUSED) {
  fd_accounts_hash_task_info_t * task_info = ((fd_accounts_hash_task_data_t *)tpool)->info + m0;
  fd_exec_slot_ctx_t * slot_ctx = task_info->slot_ctx;
  int err = 0;
  fd_funk_txn_t const * txn_out = NULL;
  fd_account_meta_t const * acc_meta = fd_acc_mgr_view_raw( slot_ctx->acc_mgr, slot_ctx->funk_txn, task_info->acc_pubkey, &task_info->rec, &err, &txn_out );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "failed to view account during bank hash" ));
    return;
  }

  fd_account_meta_t * acc_meta_parent = NULL;
  if( NULL != txn_out ) {
    fd_funk_t *     funk = slot_ctx->acc_mgr->funk;
    fd_wksp_t *     wksp = fd_funk_wksp( funk );
    fd_funk_txn_t * txn_map  = fd_funk_txn_map( funk, wksp );
    txn_out = fd_funk_txn_parent( (fd_funk_txn_t *) txn_out, txn_map );
    acc_meta_parent = (fd_account_meta_t *)fd_acc_mgr_view_raw( slot_ctx->acc_mgr, txn_out, task_info->acc_pubkey, NULL, &err, NULL);
  }

  fd_lthash_value_t * acc = &(((fd_accounts_hash_task_data_t *)tpool)->lthash_values[n0]);

  if( FD_UNLIKELY(acc_meta->info.lamports == 0) ) {
    fd_memset( task_info->acc_hash->hash, 0, FD_HASH_FOOTPRINT );

    /* If we erase records instantly, this causes problems with the
        iterator.  Instead, we will store away the record and erase
        it later where appropriate.  */
    task_info->should_erase = 1;
    if( memcmp( task_info->acc_hash->hash, acc_meta->hash, sizeof(fd_hash_t) ) != 0 ) {
      task_info->hash_changed = 1;
    }
  } else {
    uchar *             acc_data = fd_account_get_data((fd_account_meta_t *) acc_meta);
    fd_pubkey_t const * acc_key  = fd_type_pun_const( task_info->rec->pair.key[0].uc );
    fd_lthash_value_t new_lthash_value;
    fd_lthash_zero(&new_lthash_value);
    fd_hash_account_current( task_info->acc_hash->hash, &new_lthash_value, acc_meta, acc_key->key, acc_data, slot_ctx );

    if( memcmp( task_info->acc_hash->hash, acc_meta->hash, sizeof(fd_hash_t) ) != 0 ) {
      task_info->hash_changed = 1;
      fd_lthash_add( acc, &new_lthash_value);
    }
  }

  if( FD_LIKELY(task_info->hash_changed && ((NULL != acc_meta_parent) && (acc_meta_parent->info.lamports != 0) ) ) ) {
    uchar *             acc_data = fd_account_get_data(acc_meta_parent);
    fd_pubkey_t const * acc_key  = fd_type_pun_const( task_info->rec->pair.key[0].uc );
    fd_lthash_value_t old_lthash_value;
    fd_lthash_zero(&old_lthash_value);
    fd_hash_t old_hash;

    fd_hash_account_current( old_hash.hash, &old_lthash_value, acc_meta_parent, acc_key->key, acc_data, slot_ctx );
    fd_lthash_sub( acc, &old_lthash_value );
  }

  if( FD_FEATURE_ACTIVE( slot_ctx, account_hash_ignore_slot ) && acc_meta->slot == slot_ctx->slot_bank.slot ) {
      task_info->hash_changed = 1;
  }
}

void
fd_collect_modified_accounts( fd_exec_slot_ctx_t * slot_ctx,
                              fd_accounts_hash_task_data_t *task_data ) {
  fd_acc_mgr_t *  acc_mgr = slot_ctx->acc_mgr;
  fd_funk_t *     funk    = acc_mgr->funk;
  fd_funk_txn_t * txn     = slot_ctx->funk_txn;

  ulong rec_cnt = 0;
  for( fd_funk_rec_t const * rec = fd_funk_txn_first_rec( funk, txn );
       NULL != rec;
       rec = fd_funk_txn_next_rec( funk, rec ) ) {

    if( !fd_funk_key_is_acc( rec->pair.key  ) )
      continue;

    fd_pubkey_t const * pubkey  = fd_type_pun_const( rec->pair.key[0].uc );

    if (((pubkey->ul[0] == 0) & (pubkey->ul[1] == 0) & (pubkey->ul[2] == 0) & (pubkey->ul[3] == 0)))
      FD_LOG_WARNING(( "null pubkey (system program?) showed up as modified" ));

    rec_cnt++;
  }

  task_data->info = fd_valloc_malloc( slot_ctx->valloc, 8UL, rec_cnt * sizeof(fd_accounts_hash_task_info_t) );

  /* Iterate over accounts that have been changed in the current
     database transaction. */
  ulong task_info_idx = 0;
  for( fd_funk_rec_t const * rec = fd_funk_txn_first_rec( funk, txn );
       NULL != rec;
       rec = fd_funk_txn_next_rec( funk, rec ) ) {

    fd_pubkey_t const * acc_key  = fd_type_pun_const( rec->pair.key[0].uc );

    if( !fd_funk_key_is_acc( rec->pair.key  ) )
      continue;

    fd_accounts_hash_task_info_t * task_info = &task_data->info[task_info_idx++];

    *task_info->acc_pubkey = *acc_key;
    task_info->slot_ctx = slot_ctx;
    task_info->hash_changed = 0;
    task_info->should_erase = 0;
  }

  task_data->info_sz = task_info_idx;
}

int
fd_update_hash_bank_tpool( fd_exec_slot_ctx_t * slot_ctx,
                           fd_capture_ctx_t *   capture_ctx,
                           fd_hash_t *          hash,
                           ulong                signature_cnt,
                           fd_tpool_t *         tpool ) {
  fd_acc_mgr_t *  acc_mgr = slot_ctx->acc_mgr;
  fd_funk_t *     funk    = acc_mgr->funk;
  fd_funk_txn_t * txn     = slot_ctx->funk_txn;

  /* Collect list of changed accounts to be added to bank hash */
  fd_accounts_hash_task_data_t task_data;

  ulong wcnt = fd_tpool_worker_cnt( tpool );
  task_data.lthash_values = fd_valloc_malloc( slot_ctx->valloc, FD_LTHASH_VALUE_ALIGN, wcnt * FD_LTHASH_VALUE_FOOTPRINT );
  for( ulong i = 0; i < wcnt; i++ ) {
    fd_lthash_zero(&task_data.lthash_values[i]);
  }

  /* Find accounts which might have changed */
  fd_collect_modified_accounts( slot_ctx, &task_data);

  fd_pubkey_hash_pair_t * dirty_keys = fd_valloc_malloc( slot_ctx->valloc, FD_PUBKEY_HASH_PAIR_ALIGN, task_data.info_sz * FD_PUBKEY_HASH_PAIR_FOOTPRINT );
  ulong dirty_key_cnt = 0;

  /* Find accounts which have changed */
  fd_tpool_exec_all_rrobin( tpool, 0, wcnt, fd_account_hash_task, &task_data, NULL, NULL, 1, 0, task_data.info_sz );

  // Apply the lthash changes to the bank lthash
  fd_lthash_value_t * acc = (fd_lthash_value_t *)fd_type_pun(slot_ctx->slot_bank.lthash.lthash);
  for( ulong i = 0; i < wcnt; i++ ) {
    fd_lthash_add( acc, &task_data.lthash_values[i] );
  }

  for( ulong i = 0; i < task_data.info_sz; i++ ) {
    fd_accounts_hash_task_info_t * task_info = &task_data.info[i];
    /* Upgrade to writable record */
    if( !task_info->hash_changed ) {
      continue;
    }

    FD_BORROWED_ACCOUNT_DECL(acc_rec);
    acc_rec->const_rec = task_info->rec;

    fd_pubkey_t const * acc_key = fd_type_pun_const( task_info->rec->pair.key[0].uc );
    int err = fd_acc_mgr_modify( acc_mgr, txn, acc_key, 0, 0UL, acc_rec);
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_ERR(( "failed to modify account during bank hash" ));
    }

    /* Update hash */

    memcpy( acc_rec->meta->hash, task_info->acc_hash->hash, sizeof(fd_hash_t) );
    acc_rec->meta->slot = slot_ctx->slot_bank.slot;

    /* Add account to "dirty keys" list, which will be added to the
       bank hash. */

    fd_pubkey_hash_pair_t * dirty_entry = &dirty_keys[dirty_key_cnt++];
    dirty_entry->rec = task_info->rec;
    dirty_entry->hash = (fd_hash_t const *)acc_rec->meta->hash;

    char acc_key_string[ FD_BASE58_ENCODED_32_SZ ];
    fd_acct_addr_cstr( acc_key_string, (uchar const*)acc_key );
    char owner_string[ FD_BASE58_ENCODED_32_SZ ];
    fd_acct_addr_cstr( owner_string, acc_rec->meta->info.owner );

    FD_LOG_DEBUG(( "fd_acc_mgr_update_hash: %s "
        "slot: %ld "
        "lamports: %ld  "
        "owner: %s "
        "executable: %s,  "
        "rent_epoch: %ld, "
        "data_len: %ld",
        acc_key_string,
        slot_ctx->slot_bank.slot,
        acc_rec->meta->info.lamports,
        owner_string,
        acc_rec->meta->info.executable ? "true" : "false",
        acc_rec->meta->info.rent_epoch,
        acc_rec->meta->dlen ));

    if( capture_ctx != NULL && capture_ctx->capture != NULL ) {
      fd_account_meta_t const * acc_meta = fd_acc_mgr_view_raw( slot_ctx->acc_mgr, slot_ctx->funk_txn, task_info->acc_pubkey, &task_info->rec, &err, NULL);
      if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "failed to view account during capture" ));
        continue;
      }

      uchar const *       acc_data = (uchar *)acc_meta + acc_meta->hlen;

      err = fd_solcap_write_account(
        capture_ctx->capture,
        acc_key->uc,
        &acc_rec->meta->info,
        acc_data,
        acc_rec->meta->dlen,
        task_info->acc_hash->hash );
      FD_TEST( err==0 );
    }
  }

  /* Sort and hash "dirty keys" to the accounts delta hash. */

  // FD_LOG_DEBUG(("slot %ld, dirty %ld", slot_ctx->slot_bank.slot, dirty_key_cnt));

  slot_ctx->signature_cnt = signature_cnt;
  fd_hash_bank( slot_ctx, capture_ctx, hash, dirty_keys, dirty_key_cnt);

  for( ulong i = 0; i < task_data.info_sz; i++ ) {
    fd_accounts_hash_task_info_t * task_info = &task_data.info[i];
    /* Upgrade to writable record */
    if( FD_LIKELY( !task_info->should_erase ) ) {
      continue;
    }

    fd_funk_rec_remove(funk, fd_funk_rec_modify(funk, task_info->rec), 1);
  }

  // Sanity-check LT Hash
  //    fd_accounts_check_lthash( slot_ctx );

  fd_valloc_free( slot_ctx->valloc, task_data.info );
  fd_valloc_free( slot_ctx->valloc, task_data.lthash_values );
  fd_valloc_free( slot_ctx->valloc, dirty_keys );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_print_account_hashes( fd_exec_slot_ctx_t * slot_ctx,
                         fd_tpool_t *         tpool ) {

  // fd_acc_mgr_t *  acc_mgr = slot_ctx->acc_mgr;
  // fd_funk_txn_t * txn     = slot_ctx->funk_txn;

  /* Collect list of changed accounts to be added to bank hash */
  fd_accounts_hash_task_data_t task_data;

  fd_collect_modified_accounts( slot_ctx, &task_data );

  fd_pubkey_hash_pair_t * dirty_keys = fd_valloc_malloc( slot_ctx->valloc, FD_PUBKEY_HASH_PAIR_ALIGN, task_data.info_sz * FD_PUBKEY_HASH_PAIR_FOOTPRINT );
  ulong dirty_key_cnt = 0;

  ulong wcnt = fd_tpool_worker_cnt( tpool );
  task_data.lthash_values = fd_valloc_malloc( slot_ctx->valloc, FD_LTHASH_VALUE_ALIGN, wcnt * FD_LTHASH_VALUE_FOOTPRINT );
  for( ulong i = 0; i < wcnt; i++ ) {
    fd_lthash_zero(&task_data.lthash_values[i]);
  }

  /* Find accounts which have changed */
  fd_tpool_exec_all_rrobin( tpool, 0, fd_tpool_worker_cnt( tpool ), fd_account_hash_task, task_data.info, NULL, NULL, 1, 0, task_data.info_sz );

  for( ulong i = 0; i < task_data.info_sz; i++ ) {
    fd_accounts_hash_task_info_t * task_info = &task_data.info[i];
    /* Upgrade to writable record */
    if( !task_info->hash_changed ) {
      continue;
    }

    FD_BORROWED_ACCOUNT_DECL(acc_rec);
    acc_rec->const_rec = task_info->rec;

    // int err = fd_acc_mgr_modify( acc_mgr, txn, acc_key, 0, 0UL, acc_rec);
    // if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    //   FD_LOG_ERR(( "failed to modify account during bank hash" ));
    // }

    /* Update hash */

    // memcpy( acc_rec->meta->hash, task_info->acc_hash->hash, sizeof(fd_hash_t) );
    // acc_rec->meta->slot = slot_ctx->slot_bank.slot;

    /* Add account to "dirty keys" list, which will be added to the
       bank hash. */

    fd_pubkey_hash_pair_t * dirty_entry = &dirty_keys[dirty_key_cnt++];
    dirty_entry->rec = task_info->rec;
    dirty_entry->hash = (fd_hash_t const *)task_info->acc_hash->hash;

    // FD_TEST( err==0 );
  }

  /* Sort and hash "dirty keys" to the accounts delta hash. */

#ifdef VLOG
  for( ulong i = 0; i < dirty_key_cnt; ++i ) {
    FD_LOG_NOTICE(( "account delta hash X { \"key\":%ld, \"pubkey\":\"%s\", \"hash\":\"%s\" },",
                    i,
                    FD_BASE58_ENC_32_ALLOCA( dirty_keys[i].pubkey->key ),
                    FD_BASE58_ENC_32_ALLOCA( dirty_keys[i].hash->hash) ));

    /*
      pubkey
      slot
      lamports
      owner
      executable
      rent_epoch
      data_len
      data
      hash
    */
    // fd_pubkey_t current_owner;
    // fd_acc_mgr_get_owner( global->acc_mgr, global->funk_txn, &pairs[i].pubkey, &current_owner );
    // char encoded_owner[50];
    // fd_base58_encode_32((uchar *) &current_owner, 0, encoded_owner);
    int err = FD_ACC_MGR_SUCCESS;
    uchar * raw_acc_data = (uchar*) fd_acc_mgr_view_raw(slot_ctx->acc_mgr, slot_ctx->funk_txn, dirty_keys[i].pubkey, NULL, &err, NULL);
    if (NULL != raw_acc_data) {

      fd_account_meta_t * metadata = (fd_account_meta_t *)raw_acc_data;
      uchar *             acc_data = fd_account_get_data(metadata);
      char *              acc_data_str = fd_valloc_malloc(slot_ctx->valloc, 8, 5*metadata->dlen + 1);

      char * acc_data_str_cursor = acc_data_str;
      if (metadata->dlen > 0) {
        for( ulong j = 0; j < (metadata->dlen - 1); j++ ) {
          int x = sprintf(acc_data_str_cursor, "%u, ", acc_data[j]);
          acc_data_str_cursor += x;
        }
        sprintf(acc_data_str_cursor, "%u", acc_data[metadata->dlen - 1]);
      } else {
        *acc_data_str_cursor = 0;
      }

      FD_LOG_NOTICE(( "account_delta_hash_compare pubkey: (%s) slot: (%lu) lamports: (%lu), owner: (%s), executable: (%d), rent_epoch: (%lu), data_len: (%ld), hash: (%s) ",
                      FD_BASE58_ENC_32_ALLOCA( dirty_keys[i].pubkey->uc ),
                      slot_ctx->slot_bank.slot,
                      metadata->info.lamports,
                      FD_BASE58_ENC_32_ALLOCA( metadata->info.owner ),
                      metadata->info.executable,
                      metadata->info.rent_epoch,
                      metadata->dlen,
                      FD_BASE58_ENC_32_ALLOCA( dirty_keys[i].hash->hash ) ));

      fd_valloc_free(slot_ctx->valloc, acc_data_str);
    }
  }
#endif

  fd_valloc_free( slot_ctx->valloc, task_data.info );
  fd_valloc_free( slot_ctx->valloc, task_data.lthash_values );
  fd_valloc_free( slot_ctx->valloc, dirty_keys );

  return 0;
}

int
fd_update_hash_bank( fd_exec_slot_ctx_t * slot_ctx,
                     fd_capture_ctx_t *   capture_ctx,
                     fd_hash_t *          hash,
                     ulong                signature_cnt ) {

  fd_acc_mgr_t *       acc_mgr  = slot_ctx->acc_mgr;
  fd_funk_t *          funk     = acc_mgr->funk;
  fd_funk_txn_t *      txn      = slot_ctx->funk_txn;

  /* Collect list of changed accounts to be added to bank hash */


  ulong rec_cnt = 0;
  for( fd_funk_rec_t const * rec = fd_funk_txn_first_rec( funk, txn );
       NULL != rec;
       rec = fd_funk_txn_next_rec( funk, rec ) ) {

    if( !fd_funk_key_is_acc( rec->pair.key  ) ) continue;
    if( !fd_funk_rec_is_modified( funk, rec ) ) continue;

    rec_cnt++;
  }
  /* Iterate over accounts that have been changed in the current
     database transaction. */
  fd_pubkey_hash_pair_t * dirty_keys = fd_valloc_malloc( slot_ctx->valloc, FD_PUBKEY_HASH_PAIR_ALIGN, rec_cnt * FD_PUBKEY_HASH_PAIR_FOOTPRINT );
  fd_funk_rec_t const * * erase_recs = fd_valloc_malloc( slot_ctx->valloc, 8UL, rec_cnt * sizeof(fd_funk_rec_t *) );

  ulong dirty_key_cnt = 0;
  ulong erase_rec_cnt = 0;

  for( fd_funk_rec_t const * rec = fd_funk_txn_first_rec( funk, txn );
       NULL != rec;
       rec = fd_funk_txn_next_rec( funk, rec ) ) {

    fd_pubkey_t const *       acc_key  = fd_type_pun_const( rec->pair.key[0].uc );

    if( !fd_funk_key_is_acc( rec->pair.key  ) ) continue;
    if( !fd_funk_rec_is_modified( funk, rec ) ) continue;

    /* Get dirty account */

    fd_funk_rec_t const *     rec      = NULL;

    int           err = 0;
    fd_account_meta_t const * acc_meta = fd_acc_mgr_view_raw( acc_mgr, txn, acc_key, &rec, &err, NULL);
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_ERR(( "failed to view account during bank hash" ));
    }
    uchar const *             acc_data = (uchar *)acc_meta + acc_meta->hlen;

    /* Hash account */

    fd_hash_t acc_hash[1];
    // TODO: talk to jsiegel about this
    if (FD_UNLIKELY(acc_meta->info.lamports == 0)) { //!fd_acc_exists(_raw))) {
      fd_memset( acc_hash->hash, 0, FD_HASH_FOOTPRINT );

      /* If we erase records instantly, this causes problems with the
         iterator.  Instead, we will store away the record and erase
         it later where appropriate.  */
      erase_recs[erase_rec_cnt++] = rec;
    } else {
      // Maybe instead of going through the whole hash mechanism, we
      // can find the parent funky record and just compare the data?
      fd_hash_account_current( acc_hash->hash, NULL, acc_meta, acc_key->key, acc_data, slot_ctx );
    }

    /* If hash didn't change, nothing to do */
    if( 0==memcmp( acc_hash->hash, acc_meta->hash, sizeof(fd_hash_t) ) ) {
      if( FD_FEATURE_ACTIVE( slot_ctx, account_hash_ignore_slot )
        && acc_meta->slot == slot_ctx->slot_bank.slot ) {
        /* no-op */
      } else {
        continue;
      }
    }

    /* Upgrade to writable record */

    // How the heck do we deal with new accounts?  test that
    FD_BORROWED_ACCOUNT_DECL(acc_rec);
    acc_rec->const_rec = rec;

    err = fd_acc_mgr_modify( acc_mgr, txn, acc_key, 0, 0UL, acc_rec);
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_ERR(( "failed to modify account during bank hash" ));
    }

    /* Update hash */

    memcpy( acc_rec->meta->hash, acc_hash->hash, sizeof(fd_hash_t) );
    acc_rec->meta->slot = slot_ctx->slot_bank.slot;

    /* Logging ... */
    FD_LOG_DEBUG(( "fd_acc_mgr_update_hash: %s "
        "slot: %ld "
        "lamports: %ld  "
        "owner: %s  "
        "executable: %s,  "
        "rent_epoch: %ld, "
        "data_len: %ld",
        FD_BASE58_ENC_32_ALLOCA( acc_key ),
        slot_ctx->slot_bank.slot,
        acc_rec->meta->info.lamports,
        FD_BASE58_ENC_32_ALLOCA( acc_rec->meta->info.owner ),
        acc_rec->meta->info.executable ? "true" : "false",
        acc_rec->meta->info.rent_epoch,
        acc_rec->meta->dlen ));


    /* Add account to "dirty keys" list, which will be added to the
       bank hash. */

    fd_pubkey_hash_pair_t * dirty_entry = &dirty_keys[dirty_key_cnt++];
    dirty_entry->rec = rec;
    dirty_entry->hash = (fd_hash_t const *)acc_rec->meta->hash;

    /* Add to capture */
    if( capture_ctx != NULL && capture_ctx->capture != NULL ) {
      err = fd_solcap_write_account(
          capture_ctx->capture,
          acc_key->uc,
          &acc_rec->meta->info,
          acc_data,
          acc_rec->meta->dlen,
          acc_hash->hash );
    }
    FD_TEST( err==0 );
  }

  /* Sort and hash "dirty keys" to the accounts delta hash. */

  // FD_LOG_DEBUG(("slot %ld, dirty %ld", slot_ctx->slot_bank.slot, dirty_key_cnt));

  slot_ctx->signature_cnt = signature_cnt;
  fd_hash_bank( slot_ctx, capture_ctx, hash, dirty_keys, dirty_key_cnt );

//  if( FD_FEATURE_ACTIVE( slot_ctx, lattice_account_hash ) ) {
//    // Sanity-check LT Hash
//    fd_accounts_check_lthash( slot_ctx );

    // Check that the old account_delta_hash is the same as the lthash
//    FD_TEST( 0==memcmp( slot_ctx->slot_bank.lthash.lthash, slot_ctx->account_delta_hash.hash, sizeof(fd_hash_t) ) );
//  }

  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  if (slot_ctx->slot_bank.slot >= epoch_bank->eah_start_slot) {
    if ( FD_UNLIKELY (FD_FEATURE_ACTIVE(slot_ctx, epoch_accounts_hash) ) ) {
      fd_accounts_hash( slot_ctx, NULL, &slot_ctx->slot_bank.epoch_account_hash );
      epoch_bank->eah_start_slot = ULONG_MAX;
    }
  }

  for (ulong i = 0; i < erase_rec_cnt; i++) {
    fd_funk_rec_t const * erase_rec = erase_recs[i];
    fd_funk_rec_remove(funk, fd_funk_rec_modify(funk, erase_rec), 1);
  }

  fd_valloc_free( slot_ctx->valloc, dirty_keys );
  fd_valloc_free( slot_ctx->valloc, erase_recs );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

void const *
fd_hash_account_v0( uchar                     hash[ static 32 ],
                    fd_lthash_value_t        *lthash,
                    fd_account_meta_t const  *m,
                    uchar const               pubkey[ static 32 ],
                    uchar const             * data,
                    ulong                     slot ) {
  ulong         lamports   = m->info.lamports;  /* >0UL */
  ulong         rent_epoch = m->info.rent_epoch;
  uchar         executable = m->info.executable & 0x1;
  uchar const * owner      = (uchar const *)m->info.owner;

  fd_blake3_t b3[1];
  fd_blake3_init  ( b3 );
  fd_blake3_append( b3, &lamports,   sizeof( ulong ) );
  fd_blake3_append( b3, &slot,       sizeof( ulong ) );
  fd_blake3_append( b3, &rent_epoch, sizeof( ulong ) );
  fd_blake3_append( b3, data,        m->dlen         );
  fd_blake3_append( b3, &executable, sizeof( uchar ) );
  fd_blake3_append( b3, owner,       32UL            );
  fd_blake3_append( b3, pubkey,      32UL            );
  if( NULL == lthash ) {
    fd_blake3_fini  ( b3, hash );
  } else {
    fd_blake3_fini_varlen( b3, lthash->bytes, FD_LTHASH_LEN_BYTES );
    fd_memcpy( hash, lthash->bytes, 32);
  }

  return hash;
}

void const *
fd_hash_account_v1( uchar                     hash[ static 32 ],
                    fd_lthash_value_t        *lthash,
                    fd_account_meta_t const * m,
                    uchar const               pubkey[ static 32 ],
                    uchar const             * data ) {
  ulong         lamports   = m->info.lamports;  /* >0UL */
  ulong         rent_epoch = m->info.rent_epoch;
  uchar         executable = m->info.executable & 0x1;
  uchar const * owner      = (uchar const *)m->info.owner;

  fd_blake3_t b3[1];
  fd_blake3_init  ( b3 );
  fd_blake3_append( b3, &lamports,   sizeof( ulong ) );
  fd_blake3_append( b3, &rent_epoch, sizeof( ulong ) );
  fd_blake3_append( b3, data,        m->dlen         );
  fd_blake3_append( b3, &executable, sizeof( uchar ) );
  fd_blake3_append( b3, owner,       32UL            );
  fd_blake3_append( b3, pubkey,      32UL            );
  if( NULL == lthash ) {
    fd_blake3_fini  ( b3, hash );
  } else {
    fd_blake3_fini_varlen( b3, lthash->bytes, FD_LTHASH_LEN_BYTES );
    fd_memcpy( hash, lthash->bytes, 32);
  }

  return hash;
}

void const *
fd_hash_account_current( uchar                      hash  [ static 32 ],
                         fd_lthash_value_t         *lthash,
                         fd_account_meta_t const   *account,
                         uchar const                pubkey[ static 32 ],
                         uchar const               *data,
                         fd_exec_slot_ctx_t const  *slot_ctx ) {
  if( FD_FEATURE_ACTIVE( slot_ctx, account_hash_ignore_slot ) )
    return fd_hash_account_v1( hash, lthash, account, pubkey, data );
  else
    return fd_hash_account_v0( hash, lthash, account, pubkey, data, slot_ctx->slot_bank.slot );
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

static fd_pubkey_hash_pair_t *
fd_accounts_sorted_subrange( fd_exec_slot_ctx_t * slot_ctx, uint range_idx, uint range_cnt, ulong * num_pairs_out, fd_lthash_value_t *lthash_values, ulong n0
 ) {
  fd_funk_t *     funk = slot_ctx->acc_mgr->funk;
  fd_wksp_t *     wksp = fd_funk_wksp( funk );
  fd_funk_rec_t * rec_map  = fd_funk_rec_map( funk, wksp );
  ulong           num_iter_accounts = fd_funk_rec_map_key_max( rec_map );
  ulong           max_pairs = ( range_cnt == 1U ? num_iter_accounts : 2UL*num_iter_accounts/range_cnt ); /* Initial estimate */
  ulong           num_pairs = 0;
  fd_pubkey_hash_pair_t * pairs = fd_valloc_malloc( slot_ctx->valloc, FD_PUBKEY_HASH_PAIR_ALIGN, max_pairs * sizeof(fd_pubkey_hash_pair_t) );
  FD_TEST(NULL != pairs);
  ulong           range_len = ULONG_MAX/range_cnt;
  ulong           range_min = range_len*range_idx;
  ulong           range_max = ( range_idx+1U < range_cnt ? range_min+range_len-1U : ULONG_MAX );

  fd_lthash_value_t accum;
  fd_lthash_zero(&accum);

  for( ulong i = num_iter_accounts; i; --i ) {
    fd_funk_rec_t const * rec = rec_map + (i-1UL);
    if ( ( rec->map_next >> 63 ) /* unused map entry */ ||
         !fd_funk_key_is_acc( rec->pair.key ) /* not a solana record */ ||
         ( rec->pair.xid->ul[0] | rec->pair.xid->ul[1] ) != 0 /* not root xid */ ) {
      continue;
    }

    ulong n = __builtin_bswap64(rec->pair.key->ul[0]);
    if( n < range_min || n > range_max ) {
      continue;
    }

    fd_account_meta_t * metadata = (fd_account_meta_t *) fd_funk_val_const( rec, wksp );
    int is_empty = (metadata->info.lamports == 0);
    if( is_empty ) {
      continue;
    }

    uchar hash[32];
    fd_lthash_value_t new_lthash_value;
    fd_lthash_zero(&new_lthash_value);

    fd_hash_account_current( (uchar *) hash, &new_lthash_value, metadata, rec->pair.key->uc, fd_account_get_data(metadata), slot_ctx );
    fd_lthash_add( &accum, &new_lthash_value );

    fd_hash_t * h = (fd_hash_t *) metadata->hash;
    if( (h->ul[0] | h->ul[1] | h->ul[2] | h->ul[3]) != 0 ) {
      if( fd_acc_exists( metadata ) && memcmp( metadata->hash, &hash, 32 ) != 0 ) {
        FD_LOG_WARNING(( "snapshot hash (%s) doesn't match calculated hash (%s)", FD_BASE58_ENC_32_ALLOCA( metadata->hash ), FD_BASE58_ENC_32_ALLOCA( &hash ) ));
      }
    } else
      fd_memcpy( metadata->hash, &hash, 32 );

    if( (metadata->info.executable & ~1) != 0 )
      continue;

    if( num_pairs == max_pairs ) {
      /* Try again with a larger array */
      fd_valloc_free( slot_ctx->valloc, pairs );
      max_pairs *= 2;
      pairs = fd_valloc_malloc( slot_ctx->valloc, FD_PUBKEY_HASH_PAIR_ALIGN, max_pairs * sizeof(fd_pubkey_hash_pair_t) );
      FD_TEST(NULL != pairs);
      num_pairs = 0;
      fd_lthash_zero(&accum);
      i = num_iter_accounts+1;
      continue;
    }

    fd_pubkey_hash_pair_t * pair = &pairs[num_pairs++];
    pair->rec = rec;
    pair->hash = (const fd_hash_t *)metadata->hash;
  }

  sort_pubkey_hash_pair_inplace( pairs, num_pairs );

  // FD_LOG_NOTICE(( "sorted_subrange %lx ... %lx => %lu pairs", range_min, range_max, num_pairs ));
  *num_pairs_out = num_pairs;

  fd_lthash_add( &lthash_values[n0], &accum  );
  return pairs;
}

struct fd_subrange_task_info {
  fd_exec_slot_ctx_t * slot_ctx;
  ulong num_lists;
  fd_pubkey_hash_pair_list_t * lists;
  fd_lthash_value_t *lthash_values;
};
typedef struct fd_subrange_task_info fd_subrange_task_info_t;

static void
fd_accounts_sorted_subrange_task( void *tpool,
                                  ulong t0 FD_PARAM_UNUSED, ulong t1 FD_PARAM_UNUSED,
                                  void *args FD_PARAM_UNUSED,
                                  void *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                                  ulong l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
                                  ulong m0, ulong m1 FD_PARAM_UNUSED,
                                  ulong n0, ulong n1 FD_PARAM_UNUSED) {
  fd_subrange_task_info_t * task_info = (fd_subrange_task_info_t *)tpool;
  fd_pubkey_hash_pair_list_t * list = task_info->lists + m0;
  list->pairs = fd_accounts_sorted_subrange( task_info->slot_ctx, (uint)m0, (uint)task_info->num_lists, &list->pairs_len, task_info->lthash_values, n0 );
}

int
fd_accounts_hash( fd_exec_slot_ctx_t * slot_ctx, fd_tpool_t * tpool, fd_hash_t * accounts_hash ) {
  FD_LOG_NOTICE(("accounts_hash start"));

  if( tpool == NULL || fd_tpool_worker_cnt( tpool ) <= 1U ) {
    ulong                   num_pairs = 0;
    fd_lthash_value_t *lthash_values = fd_valloc_malloc( slot_ctx->valloc, FD_LTHASH_VALUE_ALIGN, FD_LTHASH_VALUE_FOOTPRINT );
    fd_lthash_zero(&lthash_values[0]);

    fd_pubkey_hash_pair_t * pairs = fd_accounts_sorted_subrange( slot_ctx, 0, 1, &num_pairs, lthash_values, 0 );
    FD_TEST(NULL != pairs);
    fd_pubkey_hash_pair_list_t list1 = { .pairs = pairs, .pairs_len = num_pairs };
    fd_hash_account_deltas( &list1, 1, accounts_hash, slot_ctx );
    fd_valloc_free( slot_ctx->valloc, pairs );

    fd_lthash_value_t * acc = (fd_lthash_value_t *)fd_type_pun(slot_ctx->slot_bank.lthash.lthash);
    fd_lthash_add( acc, &lthash_values[0] );

    fd_valloc_free( slot_ctx->valloc, lthash_values );
  } else {
    ulong num_lists = fd_tpool_worker_cnt( tpool );
    FD_LOG_NOTICE(( "launching %lu hash tasks", num_lists ));
    fd_pubkey_hash_pair_list_t lists[num_lists];

    fd_lthash_value_t *lthash_values = fd_valloc_malloc( slot_ctx->valloc, FD_LTHASH_VALUE_ALIGN, num_lists * FD_LTHASH_VALUE_FOOTPRINT );
    for( ulong i = 0; i < num_lists; i++ ) {
      fd_lthash_zero(&lthash_values[i]);
    }

    fd_subrange_task_info_t task_info = {
      .slot_ctx = slot_ctx,
      .num_lists = num_lists,
      .lists = lists,
      .lthash_values = lthash_values};
    fd_tpool_exec_all_rrobin( tpool, 0, num_lists, fd_accounts_sorted_subrange_task, &task_info, NULL, NULL, 1, 0, num_lists );
    fd_hash_account_deltas( lists, num_lists, accounts_hash, slot_ctx );
    for( ulong i = 0; i < num_lists; ++i ) {
      fd_valloc_free( slot_ctx->valloc, lists[i].pairs );
    }
    fd_lthash_value_t * acc = (fd_lthash_value_t *)fd_type_pun(slot_ctx->slot_bank.lthash.lthash);
    for( ulong i = 0; i < num_lists; i++ ) {
      fd_lthash_add( acc, &lthash_values[i] );
    }

    fd_valloc_free( slot_ctx->valloc, lthash_values );
  }
  FD_LOG_NOTICE(("accounts_lthash %s", FD_LTHASH_ENC_32_ALLOCA( (fd_lthash_value_t *) slot_ctx->slot_bank.lthash.lthash )));

  // fd_accounts_check_lthash( slot_ctx );

  FD_LOG_INFO(("accounts_hash %s", FD_BASE58_ENC_32_ALLOCA( accounts_hash->hash) ));

  return 0;
}

int
fd_accounts_hash_inc_only( fd_exec_slot_ctx_t * slot_ctx, fd_hash_t *accounts_hash, fd_funk_txn_t * child_txn, ulong do_hash_verify ) {
  FD_LOG_NOTICE(("accounts_hash_inc_only start for txn %p, do_hash_verify=%s", (void *)child_txn, do_hash_verify ? "true" : "false" ));

  fd_funk_t *     funk = slot_ctx->acc_mgr->funk;
  fd_wksp_t *     wksp = fd_funk_wksp( funk );
  fd_funk_rec_t * rec_map  = fd_funk_rec_map( funk, wksp );

  // How many total records are we dealing with?
  ulong                   num_iter_accounts = fd_funk_rec_map_key_cnt( rec_map );
  ulong                   num_pairs = 0;
  fd_pubkey_hash_pair_t * pairs = fd_valloc_malloc( slot_ctx->valloc, FD_PUBKEY_HASH_PAIR_ALIGN, num_iter_accounts * sizeof(fd_pubkey_hash_pair_t) );
  FD_TEST(NULL != pairs);

  fd_blake3_t *b3 = NULL;
  fd_scratch_push();

  for (fd_funk_rec_t const *rec = fd_funk_txn_first_rec( funk, child_txn ); NULL != rec; rec = fd_funk_txn_next_rec(funk, rec)) {
    if ( !fd_funk_key_is_acc( rec->pair.key ) )
      continue;

    fd_account_meta_t * metadata = (fd_account_meta_t *) fd_funk_val_const( rec, wksp );
    int is_empty = (metadata->info.lamports == 0);

    if (is_empty) {
      pairs[num_pairs].rec = rec;

      fd_hash_t * hash = fd_scratch_alloc(alignof(fd_hash_t), sizeof(fd_hash_t));
      if (NULL == b3)
        b3 = fd_scratch_alloc(alignof(fd_blake3_t), sizeof(fd_blake3_t));
      fd_blake3_init  ( b3 );
      fd_blake3_append( b3, rec->pair.key->uc,   sizeof( fd_pubkey_t ) );
      fd_blake3_fini  ( b3, hash );

      pairs[num_pairs].hash = hash;
      num_pairs++;
      continue;
    } else {
      fd_hash_t *h = (fd_hash_t *) metadata->hash;
      if ((h->ul[0] | h->ul[1] | h->ul[2] | h->ul[3]) == 0) {
        // By the time we fall into this case, we can assume the ignore_slot feature is enabled...
        fd_hash_account_current( (uchar *) metadata->hash, NULL, metadata, rec->pair.key->uc, fd_account_get_data(metadata), slot_ctx );
      } else if( do_hash_verify ) {
        uchar hash[32];
        ulong old_slot = slot_ctx->slot_bank.slot;
        slot_ctx->slot_bank.slot = metadata->slot;
        fd_hash_account_current( (uchar *) &hash, NULL, metadata, rec->pair.key->uc, fd_account_get_data(metadata), slot_ctx );
        slot_ctx->slot_bank.slot = old_slot;
        if ( fd_acc_exists( metadata ) && memcmp( metadata->hash, &hash, 32 ) != 0 ) {
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
  fd_hash_account_deltas( &list1, 1, accounts_hash, slot_ctx );

  fd_valloc_free( slot_ctx->valloc, pairs );
  fd_scratch_pop();

  FD_LOG_INFO(( "accounts_hash %s", FD_BASE58_ENC_32_ALLOCA( accounts_hash->hash) ));

  return 0;
}

int
fd_snapshot_hash( fd_exec_slot_ctx_t * slot_ctx, fd_tpool_t * tpool, fd_hash_t * accounts_hash, uint check_hash ) {
  (void) check_hash;

  if( FD_FEATURE_ACTIVE(slot_ctx, epoch_accounts_hash ) ) {
    if( fd_should_snapshot_include_epoch_accounts_hash (slot_ctx) ) {
      FD_LOG_NOTICE(( "snapshot is including epoch account hash" ));
      fd_sha256_t h;
      fd_hash_t hash;
      fd_accounts_hash( slot_ctx, tpool, &hash );

      fd_sha256_init( &h );
      fd_sha256_append( &h, (uchar const *) hash.hash, sizeof( fd_hash_t ) );
      fd_sha256_append( &h, (uchar const *) slot_ctx->slot_bank.epoch_account_hash.hash, sizeof( fd_hash_t ) );
      fd_sha256_fini( &h, accounts_hash );

      return 0;
    }
  }
  return fd_accounts_hash( slot_ctx, tpool, accounts_hash );
}

/* Re-computes the lthash from the current slot */
void
fd_accounts_check_lthash( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_funk_t *     funk = slot_ctx->acc_mgr->funk;
  fd_wksp_t *     wksp = fd_funk_wksp( funk );
  fd_funk_rec_t * rec_map  = fd_funk_rec_map( funk, wksp );
  fd_funk_txn_t * txn_map  = fd_funk_txn_map( funk, wksp );

  // How many txns are we dealing with?
  ulong txn_cnt = 1;
  fd_funk_txn_t * txn = slot_ctx->funk_txn;
  while (NULL != txn) {
    txn_cnt++;
    txn = fd_funk_txn_parent( txn, txn_map );
  }

  fd_funk_txn_t ** txns = fd_alloca_check(sizeof(fd_funk_txn_t *), sizeof(fd_funk_txn_t *) * txn_cnt);
  if ( FD_UNLIKELY(NULL == txns))
    FD_LOG_ERR(("Out of scratch space?"));

  // Lay it flat to make it easier to walk backwards up the chain from
  // the root
  txn = slot_ctx->funk_txn;
  ulong txn_idx = txn_cnt;
  while (1) {
    txns[--txn_idx] = txn;
    if (NULL == txn)
      break;
    txn = fd_funk_txn_parent( txn, txn_map );
  }

  // How many total records are we dealing with?
  ulong           num_iter_accounts = fd_funk_rec_map_key_cnt( rec_map );

  int accounts_hash_slots = fd_ulong_find_msb(num_iter_accounts  ) + 1;

  FD_LOG_WARNING(("allocating memory for hash.  num_iter_accounts: %ld   slots: %d", num_iter_accounts, accounts_hash_slots));
  void * hashmem = fd_valloc_malloc( slot_ctx->valloc, accounts_hash_align(), accounts_hash_footprint(accounts_hash_slots));
  FD_LOG_WARNING(("initializing memory for hash"));
  accounts_hash_t * hash_map = accounts_hash_join(accounts_hash_new(hashmem, accounts_hash_slots));

  FD_LOG_WARNING(("copying in accounts"));

  // walk up the transactions...
  for (ulong idx = 0; idx < txn_cnt; idx++) {
    FD_LOG_WARNING(("txn idx %ld", idx));
    for (fd_funk_rec_t const *rec = fd_funk_txn_first_rec( funk, txns[idx]);
         NULL != rec;
         rec = fd_funk_txn_next_rec(funk, rec)) {
      if ( fd_funk_key_is_acc( rec->pair.key ) ) {
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
        uchar *             acc_data = fd_account_get_data(metadata);
        uchar hash  [ 32 ];
        fd_lthash_value_t new_lthash_value;
        fd_lthash_zero(&new_lthash_value);
        fd_hash_account_current( hash, &new_lthash_value, metadata, slot->key->pair.key[0].uc, acc_data, slot_ctx );
        fd_lthash_add( &acc_lthash, &new_lthash_value );

        if (fd_acc_exists( metadata ) && memcmp( metadata->hash, &hash, 32 ) != 0 ) {
          FD_LOG_WARNING(( "snapshot hash (%s) doesn't match calculated hash (%s)", FD_BASE58_ENC_32_ALLOCA( metadata->hash ), FD_BASE58_ENC_32_ALLOCA( &hash ) ));
        }
      }
    }
  }

  // Compare the accumulator to the slot
  fd_lthash_value_t * acc = (fd_lthash_value_t *)fd_type_pun_const( slot_ctx->slot_bank.lthash.lthash );
  if ( memcmp( acc, &acc_lthash, sizeof( fd_lthash_value_t ) ) == 0 ) {
    FD_LOG_NOTICE(("accounts_lthash %s == %s", FD_LTHASH_ENC_32_ALLOCA (acc), FD_LTHASH_ENC_32_ALLOCA (&acc_lthash)));
  } else {
    FD_LOG_ERR(("accounts_lthash %s != %s", FD_LTHASH_ENC_32_ALLOCA (acc), FD_LTHASH_ENC_32_ALLOCA (&acc_lthash)));
  }
}
