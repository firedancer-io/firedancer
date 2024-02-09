#include "fd_hashes.h"
#include "../../ballet/blake3/fd_blake3.h"
#include "../../ballet/sha256/fd_sha256.h"
#include <assert.h>
#include <stdio.h>
#include "../../ballet/lthash/fd_lthash.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/ed25519/fd_ristretto255_ge.h"
#include "fd_acc_mgr.h"
#include "fd_runtime.h"
#include "fd_account.h"
#include "context/fd_capture_ctx.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"

#define SORT_NAME sort_pubkey_hash_pair
#define SORT_KEY_T fd_pubkey_hash_pair_t
static int
fd_pubkey_hash_pair_compare(fd_pubkey_hash_pair_t const * a, fd_pubkey_hash_pair_t const * b) {
  for (uint i = 0; i < 32U/sizeof(ulong); ++i) {
    /* First byte is least significant when seen as a long. Make it most significant. */
    ulong al = __builtin_bswap64(a->pubkey->ul[i]);
    ulong bl = __builtin_bswap64(b->pubkey->ul[i]);
    if (al != bl) return (al < bl);
  }
  return 0;
}
#define SORT_BEFORE(a,b) fd_pubkey_hash_pair_compare(&a, &b)
#include "../../util/tmpl/fd_sort.c"

#define FD_ACCOUNT_DELTAS_MERKLE_FANOUT (16UL)
#define FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT (16UL)

void
fd_hash_account_deltas( fd_pubkey_hash_pair_t * pairs, ulong pairs_len, fd_hash_t * hash, fd_exec_slot_ctx_t * slot_ctx FD_PARAM_UNUSED ) {
  fd_sha256_t shas[FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT];
  uchar       num_hashes[FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT+1];

  // Init the number of hashes
  fd_memset( num_hashes, 0, sizeof(num_hashes) );

  // FD_LOG_DEBUG(("sorting %d", pairs_len));
  // long timer_sort = -fd_log_wallclock();
  sort_pubkey_hash_pair_inplace( pairs, pairs_len );
  // timer_sort += fd_log_wallclock();
  // FD_LOG_DEBUG(("sorting done %6.3f ms", (double)timer_sort*(1e-6)));

  // FD_LOG_DEBUG(("fancy bmtree started"));
  for( ulong j = 0; j < FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT; ++j ) {
    fd_sha256_init( &shas[j] );
}

  if( pairs_len == 0 ) {
    fd_sha256_fini( &shas[0], hash->hash );
    return;
  }

  for( ulong i = 0; i < pairs_len; ++i ) {
#ifdef VLOG
    {
    // if ( slot_ctx->slot_bank.slot == 240182076 ) {
      FD_LOG_NOTICE(( "account delta hash X { \"key\":%ld, \"pubkey\":\"%32J\", \"hash\":\"%32J\" },", i, pairs[i].pubkey->key, pairs[i].hash->hash));

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
      uchar * raw_acc_data = (uchar*) fd_acc_mgr_view_raw(slot_ctx->acc_mgr, slot_ctx->funk_txn, pairs[i].pubkey, NULL, &err);
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

        FD_LOG_NOTICE(( "account_delta_hash_compare pubkey: (%32J) slot: (%lu) lamports: (%lu), owner: (%32J), executable: (%d), rent_epoch: (%lu), data_len: (%ld), hash: (%32J) ",  pairs[i].pubkey->uc, slot_ctx->slot_bank.slot, metadata->info.lamports, metadata->info.owner, metadata->info.executable, metadata->info.rent_epoch, metadata->dlen, pairs[i].hash->hash ));
//          fprintf(stderr, "account_delta_hash pubkey: %32J, slot: (%lu), lamports: %lu, owner: %32J, executable: %d, rent_epoch: %lu, data_len: %ld, data: [%s] = %32J\n",  pairs[i].pubkey->uc, slot_ctx->slot_bank.slot, metadata->info.lamports, metadata->info.owner, metadata->info.executable, metadata->info.rent_epoch, metadata->dlen, acc_data_str, pairs[i].hash->hash );

        fd_valloc_free(slot_ctx->valloc, acc_data_str);
      }
    }
#endif

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
  ulong epoch = fd_slot_to_epoch( &slot_ctx->epoch_ctx->epoch_bank.epoch_schedule, slot_ctx->slot_bank.slot, &slot_idx );

  ulong slots_per_epoch = fd_epoch_slot_cnt( &slot_ctx->epoch_ctx->epoch_bank.epoch_schedule, epoch );
  ulong first_slot_in_epoch           = fd_epoch_slot0   ( &slot_ctx->epoch_ctx->epoch_bank.epoch_schedule, epoch );

  ulong calculation_offset_start = slots_per_epoch / 4;
  ulong calculation_offset_stop = slots_per_epoch / 4 * 3;
  ulong calculation_interval = fd_ulong_sat_sub(calculation_offset_stop, calculation_offset_start);

  // This came from the vote program.. maybe we need to put it into a header?
  const ulong MAX_LOCKOUT_HISTORY = 31UL;
  const ulong CALCULATION_INTERVAL_BUFFER = 150UL;
  const ulong MINIMUM_CALCULATION_INTERVAL = MAX_LOCKOUT_HISTORY + CALCULATION_INTERVAL_BUFFER;

  if (calculation_interval < MINIMUM_CALCULATION_INTERVAL) {
    slot_ctx->epoch_ctx->epoch_bank.eah_start_slot = ULONG_MAX;
    slot_ctx->epoch_ctx->epoch_bank.eah_stop_slot = ULONG_MAX;
    slot_ctx->epoch_ctx->epoch_bank.eah_interval = ULONG_MAX;
    return;
  }

  slot_ctx->epoch_ctx->epoch_bank.eah_start_slot = first_slot_in_epoch + calculation_offset_start;
  if (slot_ctx->slot_bank.slot > slot_ctx->epoch_ctx->epoch_bank.eah_start_slot)
    slot_ctx->epoch_ctx->epoch_bank.eah_start_slot = ULONG_MAX;
  slot_ctx->epoch_ctx->epoch_bank.eah_stop_slot = first_slot_in_epoch + calculation_offset_stop;
  if (slot_ctx->slot_bank.slot > slot_ctx->epoch_ctx->epoch_bank.eah_stop_slot)
    slot_ctx->epoch_ctx->epoch_bank.eah_stop_slot = ULONG_MAX;
  slot_ctx->epoch_ctx->epoch_bank.eah_interval = calculation_interval;
}

// https://github.com/solana-labs/solana/blob/b0dcaf29e358c37a0fcb8f1285ce5fff43c8ec55/runtime/src/bank/epoch_accounts_hash_utils.rs#L13
static int
fd_should_include_epoch_accounts_hash(fd_exec_slot_ctx_t * slot_ctx) {
  if( !FD_FEATURE_ACTIVE( slot_ctx, epoch_accounts_hash ) )
    return 0;

  ulong calculation_stop = slot_ctx->epoch_ctx->epoch_bank.eah_stop_slot;
  return slot_ctx->slot_bank.prev_slot < calculation_stop && (slot_ctx->slot_bank.slot >= calculation_stop);
}

static int
fd_should_snapshot_include_epoch_accounts_hash(fd_exec_slot_ctx_t * slot_ctx) {
  if( !FD_FEATURE_ACTIVE( slot_ctx, epoch_accounts_hash ) )
    return 0;

  // We need to find the correct logic
  if (slot_ctx->epoch_ctx->epoch_bank.eah_start_slot != ULONG_MAX)
    return 0;
  if (slot_ctx->epoch_ctx->epoch_bank.eah_stop_slot == ULONG_MAX)
    return 0;
  return 1;
}

void
fd_account_lthash( fd_lthash_value_t *       lthash_value,
                   fd_exec_slot_ctx_t const * slot_ctx,
                   fd_account_meta_t const * acc_meta,
                   fd_pubkey_t const *       acc_key,
                   uchar const *             acc_data
 ) {
  fd_lthash_zero( lthash_value );

  // If the account has no lamports, we treat it as deleted, and do not include it in the hash
  if ( acc_meta->info.lamports == 0 ) {
    return;
  }

  uchar hash[32];
  fd_hash_account_current( (uchar *)&hash, acc_meta, acc_key->key, acc_data, slot_ctx );

  fd_lthash_t lthash;
  fd_lthash_init( &lthash );
  fd_lthash_append( &lthash, &hash, 32 );

  fd_lthash_fini( &lthash, lthash_value );
  return;
}

// slot_ctx should be const.
static void
fd_hash_bank( fd_exec_slot_ctx_t * slot_ctx,
              fd_capture_ctx_t * capture_ctx,
              fd_hash_t * hash,
              fd_pubkey_hash_pair_t * dirty_keys,
              ulong dirty_key_cnt ) {
  slot_ctx->prev_banks_hash = slot_ctx->slot_bank.banks_hash;

  fd_hash_account_deltas( dirty_keys, dirty_key_cnt, &slot_ctx->account_delta_hash, slot_ctx );

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

  if( capture_ctx != NULL ) {
    fd_solcap_write_bank_preimage(
        capture_ctx->capture,
        hash->hash,
        slot_ctx->prev_banks_hash.hash,
        slot_ctx->account_delta_hash.hash,
        &slot_ctx->slot_bank.poh.hash,
        slot_ctx->signature_cnt );
  }

  FD_LOG_NOTICE(( "bank_hash slot: %lu,  hash: %32J,  parent_hash: %32J,  accounts_delta: %32J,  signature_count: %ld,  last_blockhash: %32J",
                 slot_ctx->slot_bank.slot, hash->hash, slot_ctx->prev_banks_hash.hash, slot_ctx->account_delta_hash.hash, slot_ctx->signature_cnt, slot_ctx->slot_bank.poh.hash ));
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

static void
fd_account_hash_task( void *tpool,
                      ulong t0 FD_PARAM_UNUSED, ulong t1 FD_PARAM_UNUSED,
                      void *args FD_PARAM_UNUSED,
                      void *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                      ulong l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
                      ulong m0, ulong m1 FD_PARAM_UNUSED,
                      ulong n0 FD_PARAM_UNUSED, ulong n1 FD_PARAM_UNUSED) {
  fd_accounts_hash_task_info_t * task_info = (fd_accounts_hash_task_info_t *)tpool + m0;
  fd_exec_slot_ctx_t * slot_ctx = task_info->slot_ctx;
  int err = 0;
  fd_account_meta_t const * acc_meta = fd_acc_mgr_view_raw( slot_ctx->acc_mgr, slot_ctx->funk_txn, task_info->acc_pubkey, &task_info->rec, &err);
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "failed to view account during bank hash" ));
    return;
  }

  uchar const *       acc_data = (uchar *)acc_meta + acc_meta->hlen;
  fd_pubkey_t const * acc_key  = fd_type_pun_const( task_info->rec->pair.key[0].uc );

  if (FD_UNLIKELY(acc_meta->info.lamports == 0)) {
    fd_memset( task_info->acc_hash->hash, 0, FD_HASH_FOOTPRINT );

    /* If we erase records instantly, this causes problems with the
        iterator.  Instead, we will store away the record and erase
        it later where appropriate.  */
    task_info->should_erase = 1;

  } else {
    // Maybe instead of going through the whole hash mechanism, we
    // can find the parent funky record and just compare the data?
    fd_hash_account_current( task_info->acc_hash->hash, acc_meta, acc_key->key, acc_data, slot_ctx );
  }

  /* If hash didn't change, nothing to do */
  if( memcmp( task_info->acc_hash->hash, acc_meta->hash, sizeof(fd_hash_t) ) != 0 ) {
    task_info->hash_changed = 1;
  } else if( FD_FEATURE_ACTIVE( slot_ctx, account_hash_ignore_slot )
    && acc_meta->slot == slot_ctx->slot_bank.slot ) {
    /* Even if the hash didnt change, in this scenario, the record did! */
    task_info->hash_changed = 1;
  }
}

void
fd_collect_modified_accounts( fd_exec_slot_ctx_t * slot_ctx,
                              fd_accounts_hash_task_info_t ** out_task_infos,
                              ulong * out_task_infos_sz ) {
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

  fd_accounts_hash_task_info_t * task_infos = fd_valloc_malloc( slot_ctx->valloc, 8UL, rec_cnt * sizeof(fd_accounts_hash_task_info_t) );

  /* Iterate over accounts that have been changed in the current
     database transaction. */
  ulong task_info_idx = 0;
  for( fd_funk_rec_t const * rec = fd_funk_txn_first_rec( funk, txn );
       NULL != rec;
       rec = fd_funk_txn_next_rec( funk, rec ) ) {

    fd_pubkey_t const * acc_key  = fd_type_pun_const( rec->pair.key[0].uc );

    if( !fd_funk_key_is_acc( rec->pair.key  ) )
      continue;

    // If you bring this back in, hashes at the epoch boundry fail... don't do it

//    if( !fd_funk_rec_is_modified( funk, rec ) )
//      continue;

    fd_accounts_hash_task_info_t * task_info = &task_infos[task_info_idx++];

    *task_info->acc_pubkey = *acc_key;
    task_info->slot_ctx = slot_ctx;
    task_info->hash_changed = 0;
    task_info->should_erase = 0;
  }

  *out_task_infos = task_infos;
  *out_task_infos_sz = task_info_idx;
}

int
fd_update_hash_bank_tpool( fd_exec_slot_ctx_t * slot_ctx,
                           fd_capture_ctx_t *   capture_ctx,
                           fd_hash_t *          hash,
                           ulong                signature_cnt,
                           fd_tpool_t *         tpool,
                           ulong                max_workers ) {
  fd_acc_mgr_t *  acc_mgr = slot_ctx->acc_mgr;
  fd_funk_t *     funk    = acc_mgr->funk;
  fd_funk_txn_t * txn     = slot_ctx->funk_txn;

  /* Collect list of changed accounts to be added to bank hash */
  fd_accounts_hash_task_info_t * task_infos = NULL;
  ulong task_infos_sz = 0;

  fd_collect_modified_accounts( slot_ctx, &task_infos, &task_infos_sz );

  fd_pubkey_hash_pair_t * dirty_keys = fd_valloc_malloc( slot_ctx->valloc, FD_PUBKEY_HASH_PAIR_ALIGN, task_infos_sz * FD_PUBKEY_HASH_PAIR_FOOTPRINT );
  ulong dirty_key_cnt = 0;

  /* Find accounts which have changed */
  fd_tpool_exec_all_rrobin( tpool, 0, max_workers, fd_account_hash_task, task_infos, NULL, NULL, 1, 0, task_infos_sz );

  for( ulong i = 0; i < task_infos_sz; i++ ) {
    fd_accounts_hash_task_info_t * task_info = &task_infos[i];
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

#ifdef _ENABLE_LTHASH
  // Subtract the previous hash from the running total
  fd_lthash_t lthash;

  fd_lthash_init( &lthash );
  fd_lthash_append( &lthash, acc_rec->meta->hash, 32 );
  fd_lthash_value_t old_lthash_value;
  fd_lthash_fini( &lthash, &old_lthash_value );

  fd_lthash_value_t * acc = (fd_lthash_value_t *)fd_type_pun(slot_ctx->slot_bank.lthash);

  fd_lthash_sub( acc, &old_lthash_value );

  // Add the new hash
  fd_lthash_value_t new_lthash_value;
  fd_account_lthash( &new_lthash_value, slot_ctx, acc_rec->meta, acc_key, acc_rec->const_data );

  fd_lthash_add( acc, &new_lthash_value );
#endif

    /* Update hash */

    memcpy( acc_rec->meta->hash, task_info->acc_hash->hash, sizeof(fd_hash_t) );
    acc_rec->meta->slot = slot_ctx->slot_bank.slot;

    /* Add account to "dirty keys" list, which will be added to the
       bank hash. */

    fd_pubkey_hash_pair_t * dirty_entry = &dirty_keys[dirty_key_cnt++];
    dirty_entry->pubkey = acc_key;
    dirty_entry->hash = (fd_hash_t const *)acc_rec->meta->hash;


    if( capture_ctx != NULL ) {
      fd_account_meta_t const * acc_meta = fd_acc_mgr_view_raw( slot_ctx->acc_mgr, slot_ctx->funk_txn, task_info->acc_pubkey, &task_info->rec, &err);
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

#ifdef _ENABLE_LTHASH
  // Sanity-check LT Hash
  fd_accounts_check_lthash( slot_ctx );
#endif

  for( ulong i = 0; i < task_infos_sz; i++ ) {
    fd_accounts_hash_task_info_t * task_info = &task_infos[i];
    /* Upgrade to writable record */
    if( FD_LIKELY( !task_info->should_erase ) ) {
      continue;
    }

    fd_funk_rec_remove(funk, fd_funk_rec_modify(funk, task_info->rec), 1);
  }

  fd_valloc_free( slot_ctx->valloc, task_infos );
  fd_valloc_free( slot_ctx->valloc, dirty_keys );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_print_account_hashes( fd_exec_slot_ctx_t * slot_ctx,
                         fd_tpool_t *         tpool,
                         ulong                max_workers ) {

  // fd_acc_mgr_t *  acc_mgr = slot_ctx->acc_mgr;
  // fd_funk_txn_t * txn     = slot_ctx->funk_txn;

  /* Collect list of changed accounts to be added to bank hash */
  fd_accounts_hash_task_info_t * task_infos = NULL;
  ulong task_infos_sz = 0;

  fd_collect_modified_accounts( slot_ctx, &task_infos, &task_infos_sz );

  fd_pubkey_hash_pair_t * dirty_keys = fd_valloc_malloc( slot_ctx->valloc, FD_PUBKEY_HASH_PAIR_ALIGN, task_infos_sz * FD_PUBKEY_HASH_PAIR_FOOTPRINT );
  ulong dirty_key_cnt = 0;

  /* Find accounts which have changed */
  fd_tpool_exec_all_rrobin( tpool, 0, max_workers, fd_account_hash_task, task_infos, NULL, NULL, 1, 0, task_infos_sz );

  for( ulong i = 0; i < task_infos_sz; i++ ) {
    fd_accounts_hash_task_info_t * task_info = &task_infos[i];
    /* Upgrade to writable record */
    if( !task_info->hash_changed ) {
      continue;
    }

    FD_BORROWED_ACCOUNT_DECL(acc_rec);
    acc_rec->const_rec = task_info->rec;

    fd_pubkey_t const * acc_key = fd_type_pun_const( task_info->rec->pair.key[0].uc );
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
    dirty_entry->pubkey = acc_key;
    dirty_entry->hash = (fd_hash_t const *)task_info->acc_hash->hash;

    // FD_TEST( err==0 );
  }

  /* Sort and hash "dirty keys" to the accounts delta hash. */

#ifdef VLOG
  for( ulong i = 0; i < dirty_key_cnt; ++i ) {
    FD_LOG_NOTICE(( "account delta hash X { \"key\":%ld, \"pubkey\":\"%32J\", \"hash\":\"%32J\" },", i, dirty_keys[i].pubkey->key, dirty_keys[i].hash->hash));

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
    uchar * raw_acc_data = (uchar*) fd_acc_mgr_view_raw(slot_ctx->acc_mgr, slot_ctx->funk_txn, dirty_keys[i].pubkey, NULL, &err);
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

      FD_LOG_NOTICE(( "account_delta_hash_compare pubkey: (%32J) slot: (%lu) lamports: (%lu), owner: (%32J), executable: (%d), rent_epoch: (%lu), data_len: (%ld), hash: (%32J) ",  dirty_keys[i].pubkey->uc, slot_ctx->slot_bank.slot, metadata->info.lamports, metadata->info.owner, metadata->info.executable, metadata->info.rent_epoch, metadata->dlen, dirty_keys[i].hash->hash ));
      fprintf(stderr, "account_delta_hash pubkey: %32J, slot: (%lu), lamports: %lu, owner: %32J, executable: %d, rent_epoch: %lu, data_len: %ld, data: [%s] = %32J\n",  dirty_keys[i].pubkey->uc, slot_ctx->slot_bank.slot, metadata->info.lamports, metadata->info.owner, metadata->info.executable, metadata->info.rent_epoch, metadata->dlen, acc_data_str, dirty_keys[i].hash->hash );

      fd_valloc_free(slot_ctx->valloc, acc_data_str);
    }
  }
#endif

  fd_valloc_free( slot_ctx->valloc, task_infos );
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
    fd_account_meta_t const * acc_meta = fd_acc_mgr_view_raw( acc_mgr, txn, acc_key, &rec, &err);
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
      fd_hash_account_current( acc_hash->hash, acc_meta, acc_key->key, acc_data, slot_ctx );
    }

    /* If hash didn't change, nothing to do */
    if( 0==memcmp( acc_hash->hash, acc_meta->hash, sizeof(fd_hash_t) ) ) {
      /* But in this esoteric confluence of features, there is something to do! */
      if( FD_FEATURE_ACTIVE( slot_ctx, account_hash_ignore_slot )
        && !FD_FEATURE_ACTIVE( slot_ctx, skip_rent_rewrites )
        && acc_meta->slot == slot_ctx->slot_bank.slot ) {
        /* no-op */
      } else {
        continue;
      }
      // FD_LOG_DEBUG(("Acc hash no change %32J for account %32J", acc_meta->hash, acc_key->uc));
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

    // /* Logging ... */
#ifdef VLOG
    FD_LOG_DEBUG(( "fd_acc_mgr_update_hash: %32J "
        "slot: %ld "
        "lamports: %ld  "
        "owner: %32J  "
        "executable: %s,  "
        "rent_epoch: %ld, "
        "data_len: %ld",
        acc_key,
        slot_ctx->slot_bank.slot,
        acc_rec->meta->info.lamports,
        acc_rec->meta->info.owner,
        acc_rec->meta->info.executable ? "true" : "false",
        acc_rec->meta->info.rent_epoch,
        acc_rec->meta->dlen ));
#endif

    /* Add account to "dirty keys" list, which will be added to the
       bank hash. */

    fd_pubkey_hash_pair_t * dirty_entry = &dirty_keys[dirty_key_cnt++];
    dirty_entry->pubkey = acc_key;
    dirty_entry->hash = (fd_hash_t const *)acc_rec->meta->hash;

    /* Add to capture */
    if( capture_ctx != NULL ) {
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

#ifdef _ENABLE_LTHASH
  // Sanity-check LT Hash
  fd_accounts_check_lthash( slot_ctx );

  // Check that the old account_delta_hash is the same as the lthash
  FD_TEST( 0==memcmp( slot_ctx->slot_bank.lthash, slot_ctx->account_delta_hash.hash, sizeof(fd_hash_t) ) );
#endif


  if (slot_ctx->slot_bank.slot >= slot_ctx->epoch_ctx->epoch_bank.eah_start_slot) {
    if (FD_FEATURE_ACTIVE(slot_ctx, epoch_accounts_hash)) {
      fd_accounts_hash(slot_ctx, &slot_ctx->slot_bank.epoch_account_hash, NULL, 0, 0);
      slot_ctx->epoch_ctx->epoch_bank.eah_start_slot = ULONG_MAX;
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
  fd_blake3_fini  ( b3, hash );

  return hash;
}

void const *
fd_hash_account_v1( uchar                     hash[ static 32 ],
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
  fd_blake3_fini  ( b3, hash );

  return hash;
}

void const *
fd_hash_account_current( uchar                      hash  [ static 32 ],
                         fd_account_meta_t const *  account,
                         uchar const                pubkey[ static 32 ],
                         uchar const              * data,
                         fd_exec_slot_ctx_t const * slot_ctx ) {
  if( FD_FEATURE_ACTIVE( slot_ctx, account_hash_ignore_slot ) )
    return fd_hash_account_v1( hash, account, pubkey, data );
  else
    return fd_hash_account_v0( hash, account, pubkey, data, slot_ctx->slot_bank.slot );
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

int
fd_accounts_hash( fd_exec_slot_ctx_t * slot_ctx, fd_hash_t *accounts_hash, fd_funk_txn_t * child_txn, ulong do_hash_verify, int with_dead ) {
  FD_LOG_NOTICE(("accounts_hash start for txn %p", (void *)child_txn));

  fd_funk_t *     funk = slot_ctx->acc_mgr->funk;
  fd_wksp_t *     wksp = fd_funk_wksp( funk );
  fd_funk_rec_t * rec_map  = fd_funk_rec_map( funk, wksp );

  // How many total records are we dealing with?
  ulong                   num_iter_accounts = fd_funk_rec_map_key_cnt( rec_map );
  ulong                   num_pairs = 0;
  fd_pubkey_hash_pair_t * pairs = fd_valloc_malloc( slot_ctx->valloc, FD_PUBKEY_HASH_PAIR_ALIGN, num_iter_accounts * sizeof(fd_pubkey_hash_pair_t) );
  FD_TEST(NULL != pairs);

  for (fd_funk_rec_t const *rec = fd_funk_txn_first_rec( funk, child_txn ); NULL != rec; rec = fd_funk_txn_next_rec(funk, rec)) {
    if ( !fd_funk_key_is_acc( rec->pair.key ) )
      continue;

    fd_account_meta_t * metadata = (fd_account_meta_t *) fd_funk_val_const( rec, wksp );
    int is_dead = (metadata->info.lamports == 0) | ((metadata->info.executable & ~1) != 0);
    /* Why check the executable high bits??? Aren't those just garbage?? */

    if( !is_dead && do_hash_verify ) {
      FD_LOG_NOTICE(( "DO HASH VERIFY" ));
      uchar hash[32];
      ulong old_slot = slot_ctx->slot_bank.slot;
      slot_ctx->slot_bank.slot = metadata->slot;
      fd_hash_account_current( (uchar *) &hash, metadata, rec->pair.key->uc, fd_account_get_data(metadata), slot_ctx );
      slot_ctx->slot_bank.slot = old_slot;
      if ( fd_acc_exists( metadata ) && memcmp( metadata->hash, &hash, 32 ) != 0 ) {
        FD_LOG_WARNING(( "snapshot hash (%32J) doesn't match calculated hash (%32J)", metadata->hash, &hash ));
      }
    }

    // Should this just be the dead check?!
    if( is_dead ) {
      if( !with_dead )
        continue;
    }
    // FD_LOG_DEBUG(( "including %s account %32J => %32J (modified at slot %lu)",
    //                is_dead ? "dead" : "live",
    //                rec->pair.key->uc,
    //                metadata->hash,
    //                metadata->slot ));

    pairs[num_pairs].pubkey = (const fd_pubkey_t *)rec->pair.key->uc;
    pairs[num_pairs].hash = (const fd_hash_t *)metadata->hash;
    num_pairs++;
  }

  fd_hash_account_deltas( pairs, num_pairs, accounts_hash, slot_ctx );

  fd_valloc_free( slot_ctx->valloc, pairs );

  FD_LOG_INFO(("accounts_hash %32J", accounts_hash->hash));

  return 0;
}

int
fd_snapshot_hash( fd_exec_slot_ctx_t * slot_ctx, fd_hash_t *accounts_hash, fd_funk_txn_t * child_txn, uint check_hash, int with_dead ) {
  if (FD_FEATURE_ACTIVE(slot_ctx, epoch_accounts_hash)) {
    if (fd_should_snapshot_include_epoch_accounts_hash (slot_ctx)) {
      FD_LOG_NOTICE(( "snapshot is including epoch account hash" ));
      fd_sha256_t h;
      fd_hash_t hash;
      fd_accounts_hash(slot_ctx, &hash, child_txn, 1, 0);

      fd_sha256_init( &h );
      fd_sha256_append( &h, (uchar const *) hash.hash, sizeof( fd_hash_t ) );
      fd_sha256_append( &h, (uchar const *) slot_ctx->slot_bank.epoch_account_hash.hash, sizeof( fd_hash_t ) );
      fd_sha256_fini( &h, accounts_hash );

      return 0;
    }
  }
  return fd_accounts_hash(slot_ctx, accounts_hash, child_txn, check_hash, with_dead );
}

#ifdef _ENABLE_LTHASH
int
fd_accounts_init_lthash( fd_exec_slot_ctx_t * slot_ctx ) {
  // Initialize the lhash value to zero
  fd_lthash_value_t * acc_lthash = (fd_lthash_value_t *)fd_type_pun_const( slot_ctx->slot_bank.lthash );
  fd_lthash_zero( acc_lthash );

  // Iterate over all accounts in the database
  fd_funk_t *     funk = slot_ctx->acc_mgr->funk;

  for (
    fd_funk_rec_t const *rec = fd_funk_txn_first_rec( funk, NULL); NULL != rec; rec = fd_funk_txn_next_rec(funk, rec))
    {
      if ( fd_funk_key_is_acc( rec->pair.key ) ) {
        void const * data = fd_funk_val( rec, fd_funk_wksp(funk) );
        fd_account_meta_t const * metadata = (fd_account_meta_t const *)fd_type_pun_const( data );
        FD_TEST ( metadata->magic == FD_ACCOUNT_META_MAGIC );

        // Create the lthash for this account, by hashing the account hash
        fd_lthash_t lthash;
        fd_lthash_init( &lthash );
        fd_lthash_append( &lthash, metadata->hash, 32 );

        fd_lthash_value_t lthash_val;
        fd_lthash_fini( &lthash, &lthash_val );

        // Add this to the accumulator
        fd_lthash_add( acc_lthash, &lthash_val );
      } // if ( fd_funk_key_is_acc( rec->pair.key ) )
    } // fd_funk_rec_t const *rec = fd_f

    return 0;
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

  FD_LOG_WARNING(("allocating memory for hash.  num_iter_accounts: %d   slots: %d", num_iter_accounts, accounts_hash_slots));
  void * hashmem = fd_valloc_malloc( slot_ctx->valloc, accounts_hash_align(), accounts_hash_footprint(accounts_hash_slots));
  FD_LOG_WARNING(("initializing memory for hash"));
  accounts_hash_t * hash_map = accounts_hash_join(accounts_hash_new(hashmem, accounts_hash_slots));

  FD_LOG_WARNING(("copying in accounts"));

  // walk up the transactions...
  for (ulong idx = 0; idx < txn_cnt; idx++) {
    FD_LOG_WARNING(("txn idx %d", idx));
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

  // Initialize the accumulator to zero
  fd_lthash_value_t acc_lthash;
  fd_lthash_zero( &acc_lthash );

  ulong slot_cnt = accounts_hash_slot_cnt(hash_map);;
  for( ulong slot_idx=0UL; slot_idx<slot_cnt; slot_idx++ ) {
    accounts_hash_t *slot = &hash_map[slot_idx];
    if (FD_UNLIKELY (NULL != slot->key)) {
      void const * data = fd_funk_val_const( slot->key, wksp );
      fd_account_meta_t const * metadata = (fd_account_meta_t const *)fd_type_pun_const( data );

      // Add the hash to the accumulator
      fd_lthash_t lthash;
      fd_lthash_init( &lthash );
      fd_lthash_append( &lthash, metadata->hash, 32 );
      fd_lthash_value_t lthash_val;
      fd_lthash_fini( &lthash, &lthash_val );
      fd_lthash_add( &acc_lthash, &lthash_val );
    }
  }

  // Compare the accumulator to the slot
  fd_lthash_value_t * acc = (fd_lthash_value_t *)fd_type_pun_const( slot_ctx->slot_bank.lthash );
  FD_TEST( memcmp( acc, &acc_lthash, sizeof( fd_lthash_value_t ) ) == 0 );
}
#endif
