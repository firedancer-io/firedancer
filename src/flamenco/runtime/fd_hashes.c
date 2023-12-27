#include "fd_hashes.h"
#include "../../ballet/blake3/fd_blake3.h"
#include "../../ballet/sha256/fd_sha256.h"
#include <assert.h>
#include <stdio.h>
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/ed25519/fd_ristretto255_ge.h"
#include "fd_acc_mgr.h"
#include "fd_runtime.h"
#include "fd_account.h"
#include "context/fd_capture_ctx.h"

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

  FD_LOG_DEBUG(("sorting %d", pairs_len));
  // long timer_sort = -fd_log_wallclock();
  sort_pubkey_hash_pair_inplace( pairs, pairs_len );
  // timer_sort += fd_log_wallclock();
  // FD_LOG_DEBUG(("sorting done %6.3f ms", (double)timer_sort*(1e-6)));

  FD_LOG_DEBUG(("fancy bmtree started"));
  for( ulong j = 0; j < FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT; ++j ) {
    fd_sha256_init( &shas[j] );
  }

  if( pairs_len == 0 ) {
    fd_sha256_fini( &shas[0], hash->hash );
    return;
  }

  for( ulong i = 0; i < pairs_len; ++i ) {
    if (0) {
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
        fprintf(stderr, "account_delta_hash pubkey: %32J, slot: %lu, lamports: %lu, owner: %32J, executable: %d, rent_epoch: %lu, data_len: %ld, data: [%s] = %32J\n",  pairs[i].pubkey->uc, slot_ctx->slot_bank.slot, metadata->info.lamports, metadata->info.owner, metadata->info.executable, metadata->info.rent_epoch, metadata->dlen, acc_data_str, pairs[i].hash->hash );

        fd_valloc_free(slot_ctx->valloc, acc_data_str);
      }
    }

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


  FD_LOG_DEBUG(( "T %lu", height ));
  for( ulong i = 0; i < height; ++i ) {
    FD_LOG_DEBUG(("Q %lu", i));
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
    FD_LOG_DEBUG(("N %lu %lu", i, tot_num_hashes));
    if (i == (height-1)) {
      assert(tot_num_hashes == 1);
      return;
    }
    fd_sha256_append( &shas[i+1], (uchar const *) hash->hash, sizeof( fd_hash_t ) );

    // There is now one more hash at level i+1

    // check, have we filled this level and ones above it.
    for( ulong j = i+1; j < height; ++j ) {
      FD_LOG_DEBUG(("P %lu", j));
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
  return !fd_should_include_epoch_accounts_hash( slot_ctx );
}

// slot_ctx should be const.
static void
fd_hash_bank( fd_exec_slot_ctx_t * slot_ctx, fd_hash_t * hash, fd_pubkey_hash_pair_t * dirty_keys, ulong dirty_key_cnt ) {
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

  // fd_solcap_write_bank_preimage(
  //     capture_ctx->capture,
  //     hash->hash,
  //     slot_ctx->prev_banks_hash.hash,
  //     slot_ctx->account_delta_hash.hash,
  //     &slot_ctx->slot_bank.poh.hash,
  //     slot_ctx->signature_cnt );

  FD_LOG_DEBUG(( "bank_hash slot: %lu,  hash: %32J,  parent_hash: %32J,  accounts_delta: %32J,  signature_count: %ld,  last_blockhash: %32J",
                 slot_ctx->slot_bank.slot, hash->hash, slot_ctx->prev_banks_hash.hash, slot_ctx->account_delta_hash.hash, slot_ctx->signature_cnt, slot_ctx->slot_bank.poh.hash ));
  }


int
fd_update_hash_bank( fd_exec_slot_ctx_t * slot_ctx,
                     fd_capture_ctx_t *   capture_ctx,
                     fd_hash_t *          hash,
                     ulong                signature_cnt ) {

  fd_acc_mgr_t *       acc_mgr  = slot_ctx->acc_mgr;
  fd_funk_t *          funk     = acc_mgr->funk;
  fd_funk_txn_t *      txn      = slot_ctx->funk_txn;
  // ulong                slot     = slot_ctx->slot_bank.slot;
  // fd_solcap_writer_t * capture  = capture_ctx->capture;
  (void)capture_ctx;

  /* Collect list of changed accounts to be added to bank hash */


  ulong rec_cnt = 0;
  for( fd_funk_rec_t const * rec = fd_funk_txn_first_rec( funk, txn );
       NULL != rec;
       rec = fd_funk_txn_next_rec( funk, rec ) ) {

    if( !fd_acc_mgr_is_key( rec->pair.key  ) ) continue;

    rec_cnt++;
  }

  /* Iterate over accounts that have been changed in the current
     database transaction. */

#ifdef _ENABLE_RHASH
  fd_ristretto255_point_t rhash;
  fd_ristretto255_extended_frombytes( &rhash, slot_ctx->slot_bank.rhash );
#endif

  fd_pubkey_hash_pair_t * dirty_keys = fd_valloc_malloc( slot_ctx->valloc, FD_PUBKEY_HASH_PAIR_ALIGN, rec_cnt * FD_PUBKEY_ACCOUNT_PAIR_FOOTPRINT );
  fd_funk_rec_t const * * erase_recs = fd_valloc_malloc( slot_ctx->valloc, 8UL, rec_cnt * sizeof(fd_funk_rec_t *) );

  ulong dirty_key_cnt = 0;
  ulong erase_rec_cnt = 0;

  for( fd_funk_rec_t const * rec = fd_funk_txn_first_rec( funk, txn );
       NULL != rec;
       rec = fd_funk_txn_next_rec( funk, rec ) ) {

    fd_pubkey_t const *       acc_key  = fd_type_pun_const( rec->pair.key[0].uc );

    if( !fd_acc_mgr_is_key( rec->pair.key  ) ) continue;
    if( !fd_funk_rec_is_modified( funk, rec ) ) continue;

    /* Get dirty account */

    fd_funk_rec_t const *     rec      = NULL;

    int           err = 0;
    uchar const * _raw = fd_acc_mgr_view_raw( acc_mgr, txn, acc_key, &rec, &err);
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_ERR(( "failed to view account during bank hash" ));
    }
    fd_account_meta_t const * acc_meta = (fd_account_meta_t const *)_raw;
    uchar const *             acc_data = _raw + acc_meta->hlen;

    /* Hash account */

    fd_hash_t acc_hash[1];
    uchar acc_rhash[128];
#ifdef _ENABLE_RHASH
    uchar deleted = 0;
#endif
    // TODO: talk to jsiegel about this
    if (FD_UNLIKELY(acc_meta->info.lamports == 0)) { //!FD_RAW_ACCOUNT_EXISTS(_raw))) {
      fd_memset( acc_hash->hash, 0, FD_HASH_FOOTPRINT );

      /* If we erase records instantly, this causes problems with the
         iterator.  Instead, we will store away the record and erase
         it later where appropriate.  */
      erase_recs[erase_rec_cnt++] = rec;
#ifdef _ENABLE_RHASH
      deleted = 1;
#endif
    } else {
      // Maybe instead of going through the whole hash mechanism, we
      // can find the parent funky record and just compare the data?
      fd_hash_account_current( acc_hash->hash, acc_rhash, acc_meta, acc_key->key, acc_data, slot_ctx );
    }

    /* If hash didn't change, nothing to do */
    if( 0==memcmp( acc_hash->hash, acc_meta->hash, sizeof(fd_hash_t) ) ) {
      // FD_LOG_DEBUG(("Acc hash no change %32J for account %32J", acc_meta->hash, acc_key->uc));
      continue;
    }

    /* Upgrade to writable record */

    // How the heck do we deal with new accounts?  test that

#ifdef _ENABLE_RHASH
    // Lets remove the effect of this account on the rhash...
    fd_ristretto255_point_t p2;
    fd_ristretto255_extended_frombytes( &p2, acc_meta->rhash );
    fd_ristretto255_point_sub( &rhash, &rhash, &p2 );

    if (!deleted) {
      fd_ristretto255_extended_frombytes( &p2, acc_rhash );
      fd_ristretto255_point_add( &rhash, &rhash, &p2 );
    }
#endif

    FD_BORROWED_ACCOUNT_DECL(acc_rec);
    acc_rec->const_rec = rec;

    err = fd_acc_mgr_modify( acc_mgr, txn, acc_key, 0, 0UL, acc_rec);
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_ERR(( "failed to modify account during bank hash" ));
    }

    /* Update hash */

    memcpy( acc_rec->meta->hash, acc_hash->hash, sizeof(fd_hash_t) );
#ifdef _ENABLE_RHASH
    memcpy( acc_rec->meta->rhash, acc_rhash, sizeof(acc_rhash) );
#endif
    acc_rec->meta->slot = slot_ctx->slot_bank.slot;

    // /* Logging ... */
    if (0)
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

    /* Add account to "dirty keys" list, which will be added to the
       bank hash. */

    fd_pubkey_hash_pair_t * dirty_entry = &dirty_keys[dirty_key_cnt++];
    dirty_entry->pubkey = acc_key;
    dirty_entry->hash = (fd_hash_t const *)acc_rec->meta->hash;

    /* Add to capture */

    // TODO: fix
    // err = fd_solcap_write_account(
    //     capture,
    //     acc_key->uc,
    //     &acc_rec->meta->info,
    //     acc_data,
    //     acc_rec->meta->dlen,
    //     acc_hash->hash );
    FD_TEST( err==0 );
  }

#ifdef _ENABLE_RHASH
  // We have a new ristretto hash
  fd_ristretto255_extended_tobytes( slot_ctx->slot_bank.rhash, &rhash );

  // Lets make sure everything lines up...
  fd_accounts_check_rhash( slot_ctx );
#endif

  /* Sort and hash "dirty keys" to the accounts delta hash. */

  FD_LOG_DEBUG(("slot %ld, dirty %ld", slot_ctx->slot_bank.slot, dirty_key_cnt));

  slot_ctx->signature_cnt = signature_cnt;
  fd_hash_bank( slot_ctx, hash, dirty_keys, dirty_key_cnt );

  if (slot_ctx->slot_bank.slot >= slot_ctx->epoch_ctx->epoch_bank.eah_start_slot) {
    if (FD_FEATURE_ACTIVE(slot_ctx, epoch_accounts_hash)) {
      fd_accounts_hash(slot_ctx, &slot_ctx->slot_bank.epoch_account_hash);
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
                    uchar                    *rhash,
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

#ifdef _ENABLE_RHASH
  if (NULL != rhash) {
    fd_ristretto255_point_t p;
    fd_ristretto255_map_to_curve( &p, hash );
    fd_ristretto255_extended_tobytes( rhash, &p );
  }
#else
  (void) rhash;
#endif

  return hash;
}

void const *
fd_hash_account_v1( uchar                     hash[ static 32 ],
                    uchar                    *rhash,
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

#ifdef _ENABLE_RHASH
  if (NULL != rhash) {
    fd_ristretto255_point_t p;
    fd_ristretto255_map_to_curve( &p, hash );
    fd_ristretto255_extended_tobytes( rhash, &p );
  }
#else
  (void) rhash;
#endif

  return hash;
}

void const *
fd_hash_account_current( uchar                      hash  [ static 32 ],
                         uchar                     *rhash,
                         fd_account_meta_t const *  account,
                         uchar const                pubkey[ static 32 ],
                         uchar const              * data,
                         fd_exec_slot_ctx_t const * slot_ctx ) {
  if( FD_FEATURE_ACTIVE( slot_ctx, account_hash_ignore_slot ) )
    return fd_hash_account_v1( hash, rhash, account, pubkey, data );
  else
    return fd_hash_account_v0( hash, rhash, account, pubkey, data, slot_ctx->slot_bank.slot );
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
fd_accounts_hash( fd_exec_slot_ctx_t * slot_ctx, fd_hash_t *accounts_hash ) {
  FD_LOG_DEBUG(("accounts_hash start"));

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

  FD_LOG_DEBUG(("allocating memory for hash.  num_iter_accounts: %d   slots: %d", num_iter_accounts, accounts_hash_slots));
  void * hashmem = fd_valloc_malloc( slot_ctx->valloc, accounts_hash_align(), accounts_hash_footprint(accounts_hash_slots));
  FD_LOG_DEBUG(("initializing memory for hash"));
  accounts_hash_t * hash_map = accounts_hash_join(accounts_hash_new(hashmem, accounts_hash_slots));

  FD_LOG_WARNING(("copying in accounts"));

  // walk up the transactions...
  for (ulong idx = 0; idx < txn_cnt; idx++) {
    FD_LOG_DEBUG(("txn idx %d", idx));
    for (fd_funk_rec_t const *rec = fd_funk_txn_first_rec( funk, txns[idx]);
         NULL != rec;
         rec = fd_funk_txn_next_rec(funk, rec)) {
      if ( fd_acc_mgr_is_key( rec->pair.key ) ) {
        accounts_hash_t * q = accounts_hash_query(hash_map, (fd_funk_rec_t *) rec, NULL);
        if (NULL != q)
          accounts_hash_remove(hash_map, q);
        if (!(rec->flags & FD_FUNK_REC_FLAG_ERASE))
          accounts_hash_insert(hash_map, (fd_funk_rec_t *) rec);
      }
    }
  }

  FD_LOG_DEBUG(("creating flat array that account_deltas expects"));

  ulong slot_cnt = accounts_hash_slot_cnt(hash_map);;

  ulong                   num_pairs = 0;
  fd_pubkey_hash_pair_t * pairs = fd_valloc_malloc( slot_ctx->valloc, FD_PUBKEY_HASH_PAIR_ALIGN, num_iter_accounts * sizeof(fd_pubkey_hash_pair_t) );
  FD_TEST(NULL != pairs);
  for( ulong slot_idx=0UL; slot_idx<slot_cnt; slot_idx++ ) {
    accounts_hash_t *slot = &hash_map[slot_idx];
    if (FD_UNLIKELY (NULL != slot->key)) {
      fd_account_meta_t * metadata = (fd_account_meta_t *) fd_funk_val_const( slot->key, wksp );
      if (FD_UNLIKELY (metadata->magic != FD_ACCOUNT_META_MAGIC) )
        FD_LOG_ERR(("invalid magic on metadata"));

      // Should this just be the dead check?!
      if ((metadata->info.lamports == 0) | ((metadata->info.executable & ~1) != 0))
        continue;

      pairs[num_pairs].pubkey = (const fd_pubkey_t *)slot->key->pair.key->uc;
      pairs[num_pairs].hash = (const fd_hash_t *)metadata->hash;
      num_pairs++;
    }
  }

  fd_hash_account_deltas( pairs, num_pairs, accounts_hash, slot_ctx );

  fd_valloc_free( slot_ctx->valloc, pairs );
  fd_valloc_free( slot_ctx->valloc, hashmem );

  FD_LOG_WARNING(("accounts_hash %32J", accounts_hash->hash));

  return 0;
}

int
fd_snapshot_hash( fd_exec_slot_ctx_t * slot_ctx, fd_hash_t *accounts_hash ) {
  if (FD_FEATURE_ACTIVE(slot_ctx, epoch_accounts_hash)) {
    if (fd_should_snapshot_include_epoch_accounts_hash (slot_ctx)) {
      fd_sha256_t h;
      fd_hash_t hash;
      fd_accounts_hash(slot_ctx, &hash);

      fd_sha256_init( &h );
      fd_sha256_append( &h, (uchar const *) hash.hash, sizeof( fd_hash_t ) );
      fd_sha256_append( &h, (uchar const *) slot_ctx->slot_bank.epoch_account_hash.hash, sizeof( fd_hash_t ) );
      fd_sha256_fini( &h, accounts_hash );

      return 0;
    } else
      return fd_accounts_hash(slot_ctx, accounts_hash);
  } else
    return fd_accounts_hash(slot_ctx, accounts_hash);
}


#ifdef _ENABLE_RHASH
// This is bad.. everything I am doing here is a violation of data
// boundries...  such is the life of POC code...
int
fd_accounts_init_rhash( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_funk_t *     funk = slot_ctx->acc_mgr->funk;
  ulong oldslot = slot_ctx->slot_bank.slot;

  // Lets initialize this to zero
  fd_ristretto255_point_t rhash;
  fd_ristretto255_point_0(&rhash);

  for (
    fd_funk_rec_t const *rec = fd_funk_txn_first_rec( funk, NULL); NULL != rec; rec = fd_funk_txn_next_rec(funk, rec))
    {
      if ( fd_acc_mgr_is_key( rec->pair.key ) ) {
        void const * data = fd_funk_val( rec, fd_funk_wksp(funk) );
        fd_account_meta_t const * metadata = (fd_account_meta_t const *)fd_type_pun_const( data );
        FD_TEST ( metadata->magic == FD_ACCOUNT_META_MAGIC );

        uchar                      hash[32];
        void const * d   = (void const *)( (ulong)data + metadata->hlen );
        slot_ctx->slot_bank.slot = metadata->slot;

        // I really should do a funk_view here.. to get a writable metadata object but this is POC code...
        fd_hash_account_current(hash, (uchar *) metadata->rhash, metadata, (uchar *) rec->pair.key, d, slot_ctx);
        FD_TEST(memcmp(hash, metadata->hash, 32) == 0);

        // We maybe should refactor fd_hash_account_current to save
        // away the point so that we can use it.. but that will be
        // done after the POC
        fd_ristretto255_point_t p2;
        fd_ristretto255_extended_frombytes( &p2, metadata->rhash );

        fd_ristretto255_point_add( &rhash, &rhash, &p2 );
      } // if ( fd_acc_mgr_is_key( rec->pair.key ) )
    } // fd_funk_rec_t const *rec = fd_f

  // I kinda wish we could just put the point itself into the slot
  // context.  Problem is, the point is a opaque handle.. we could use
  // a "sizeof" against it to save the raw bytes but I don't know how
  // stable it is.  It just feels performance stupid to be doing this
  // conversion but maybe on the grand scale of things, it doesn't
  // really matter?
  fd_ristretto255_extended_tobytes( slot_ctx->slot_bank.rhash, &rhash );

  slot_ctx->slot_bank.slot = oldslot;
  return 0;
} // fd_accounts_init_

/*
 Confirms we can recreate the ristretto hash at any time and things
 still match
 */

void
fd_accounts_check_rhash( fd_exec_slot_ctx_t * slot_ctx ) {
  ulong oldslot = slot_ctx->slot_bank.slot;

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
      if ( fd_acc_mgr_is_key( rec->pair.key ) ) {
        accounts_hash_t * q = accounts_hash_query(hash_map, (fd_funk_rec_t *) rec, NULL);
        if (NULL != q)
          accounts_hash_remove(hash_map, q);
        if (!(rec->flags & FD_FUNK_REC_FLAG_ERASE))
          accounts_hash_insert(hash_map, (fd_funk_rec_t *) rec);
      }
    }
  }

  // Lets initialize this to zero
  fd_ristretto255_point_t rhash;
  fd_ristretto255_point_0(&rhash);

  ulong slot_cnt = accounts_hash_slot_cnt(hash_map);;
  for( ulong slot_idx=0UL; slot_idx<slot_cnt; slot_idx++ ) {
    accounts_hash_t *slot = &hash_map[slot_idx];
    if (FD_UNLIKELY (NULL != slot->key)) {
//      FD_LOG_WARNING(( "newcase: %32J ", (uchar *) slot->key->pair.key));

      void const * data = fd_funk_val_const( slot->key, wksp );
      fd_account_meta_t const * metadata = (fd_account_meta_t const *)fd_type_pun_const( data );

      uchar                      hash[32];
      uchar                      account_rhash[128];

      void const * d   = (void const *)( (ulong)data + metadata->hlen );

      // This goes away... soon... but not soon enough as far as I
      // am concerned...  It is gone on testnet and I think it might
      // also be gone on mainnet.. if so, maybe I should create a
      // new test ledger...
      slot_ctx->slot_bank.slot = metadata->slot;

      fd_hash_account_current(hash, account_rhash, metadata, (uchar *) slot->key->pair.key, d, slot_ctx);

      FD_TEST(memcmp(hash, metadata->hash, 32) == 0);
      FD_TEST(memcmp(account_rhash, metadata->rhash, 128) == 0);

      fd_ristretto255_point_t p2;
      fd_ristretto255_extended_frombytes( &p2, metadata->rhash );

      fd_ristretto255_point_add( &rhash, &rhash, &p2 );
    }
  }

  uchar                      v1[32];
  fd_ristretto255_point_compress(v1, &rhash);

  fd_ristretto255_point_t p2;
  fd_ristretto255_extended_frombytes( &p2, slot_ctx->slot_bank.rhash );
  uchar                      v2[32];
  fd_ristretto255_point_compress(v2, &p2);

  FD_TEST(memcmp(v1, v2, 32) == 0);

  slot_ctx->slot_bank.slot = oldslot;
} // fd_accounts_check_rhash
#endif
