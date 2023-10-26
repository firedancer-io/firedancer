#include "fd_hashes.h"
#include "../../ballet/blake3/fd_blake3.h"
#include "../../ballet/sha256/fd_sha256.h"
#include <assert.h>
#include <stdio.h>
#include "../../ballet/base58/fd_base58.h"
#include "fd_acc_mgr.h"
#include "fd_runtime.h"
#include "fd_account.h"

#define SORT_NAME sort_pubkey_hash_pair
#define SORT_KEY_T fd_pubkey_hash_pair_t
#define SORT_BEFORE(a,b) ((memcmp(&a, &b, 32) < 0))
#include "../../util/tmpl/fd_sort.c"

#define FD_ACCOUNT_DELTAS_MERKLE_FANOUT (16UL)
#define FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT (16UL)

void
fd_hash_account_deltas(fd_pubkey_hash_pair_t * pairs, ulong pairs_len, fd_hash_t * hash, fd_exec_slot_ctx_t * slot_ctx ) {
  fd_sha256_t shas[FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT];
  uchar num_hashes[FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT+1];

  // Init the number of hashes
  fd_memset( num_hashes, 0, sizeof(num_hashes) );

  sort_pubkey_hash_pair_inplace( pairs, pairs_len );
  for( ulong j = 0; j < FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT; ++j ) {
    fd_sha256_init( &shas[j] );
  }

  if( pairs_len == 0 ) {
    fd_sha256_fini( &shas[0], hash->hash );
    return;
  }

  for( ulong i = 0; i < pairs_len; ++i ) {

    if (0) {
      FD_LOG_NOTICE(( "account delta hash X { \"key\":%ld, \"pubkey\":\"%32J\", \"hash\":\"%32J\" },", i, pairs[i].pubkey.key, pairs[i].hash.hash));

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
      int err;
      uchar * raw_acc_data = (uchar*) fd_acc_mgr_view_raw(slot_ctx->acc_mgr, slot_ctx->funk_txn, (fd_pubkey_t *) &pairs[i].pubkey, NULL, &err);
      if (NULL != raw_acc_data) {

        fd_account_meta_t * metadata = (fd_account_meta_t *)raw_acc_data;
        uchar * acc_data = fd_account_get_data(metadata);
        char * acc_data_str = malloc(5*metadata->dlen + 1);

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

        FD_LOG_NOTICE(( "account_delta_hash_compare pubkey: (%32J) slot: (%lu) lamports: (%lu), owner: (%32J), executable: (%d), rent_epoch: (%lu), data_len: (%ld), hash: (%32J) ",  pairs[i].pubkey.uc, slot_ctx->slot_bank.slot, metadata->info.lamports, metadata->info.owner, metadata->info.executable, metadata->info.rent_epoch, metadata->dlen, pairs[i].hash.hash ));
        fprintf(stderr, "account_delta_hash pubkey: %32J, slot: %lu, lamports: %lu, owner: %32J, executable: %d, rent_epoch: %lu, data_len: %ld, data: [%s] = %32J\n",  pairs[i].pubkey.uc, slot_ctx->slot_bank.slot, metadata->info.lamports, metadata->info.owner, metadata->info.executable, metadata->info.rent_epoch, metadata->dlen, acc_data_str, pairs[i].hash.hash );

        free(acc_data_str);
      }
    }

    fd_sha256_append( &shas[0] , (uchar const *) pairs[i].hash.hash, sizeof( fd_hash_t ) );
    num_hashes[0]++;

    for( ulong j = 0; j < FD_ACCOUNT_DELTAS_MAX_MERKLE_HEIGHT; ++j ) {
      if (num_hashes[j] == FD_ACCOUNT_DELTAS_MERKLE_FANOUT) {
        num_hashes[j] = 0;
        num_hashes[j+1]++;
        fd_hash_t sub_hash;
        fd_sha256_fini( &shas[j], &sub_hash );
        fd_sha256_init( &shas[j] );
        fd_sha256_append( &shas[j+1], (uchar const *) sub_hash.hash, sizeof( fd_hash_t ) );
      } else {
        break;
      }
    }
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
    FD_LOG_DEBUG(("N %lu", tot_num_hashes));
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

// https://github.com/solana-labs/solana/blob/b0dcaf29e358c37a0fcb8f1285ce5fff43c8ec55/runtime/src/bank/epoch_accounts_hash_utils.rs#L13

static int
fd_should_include_epoch_accounts_hash(fd_exec_slot_ctx_t * slot_ctx) {
  if( !FD_FEATURE_ACTIVE( slot_ctx, epoch_accounts_hash ) )
    return 0;

  // This came from the vote program.. maybe we need to put it into a header?
  const ulong MAX_LOCKOUT_HISTORY = 31UL;

  const ulong CALCULATION_INTERVAL_BUFFER = 150UL;
  const ulong MINIMUM_CALCULATION_INTERVAL = MAX_LOCKOUT_HISTORY + CALCULATION_INTERVAL_BUFFER;

  // The calculation buffer is a best-attempt at median worst-case for how many bank ancestors can
  // accumulate before the bank is rooted.
  // [brooks] On Wed Oct 26 12:15:21 2022, over the previous 6 hour period against mainnet-beta,
  // I saw multiple validators reporting metrics in the 120s for `total_parent_banks`.  The mean
  // is 2 to 3, but a number of nodes also reported values in the low 20s.  A value of 150 should
  // capture the majority of validators, and will not be an issue for clusters running with
  // normal slots-per-epoch; this really will only affect tests and epoch schedule warmup.

  ulong slot_idx = 0;
  ulong epoch = fd_slot_to_epoch( &slot_ctx->epoch_ctx->epoch_bank.epoch_schedule, slot_ctx->slot_bank.slot, &slot_idx );

  ulong slots_per_epoch = fd_epoch_slot_cnt( &slot_ctx->epoch_ctx->epoch_bank.epoch_schedule, epoch );
  ulong calculation_offset_start = slots_per_epoch / 4;
  ulong calculation_offset_stop = slots_per_epoch / 4 * 3;

  ulong first_slot_in_epoch           = fd_epoch_slot0   ( &slot_ctx->epoch_ctx->epoch_bank.epoch_schedule, epoch );

  ulong calculation_stop = first_slot_in_epoch + calculation_offset_stop;
  ulong calculation_interval = fd_ulong_sat_sub(calculation_offset_stop, calculation_offset_start);

  if (calculation_interval < MINIMUM_CALCULATION_INTERVAL)
    return 0;

  return slot_ctx->slot_bank.prev_slot < calculation_stop && (slot_ctx->slot_bank.slot >= calculation_stop);
}

// slot_ctx should be const.
static void
fd_hash_bank( fd_exec_slot_ctx_t * slot_ctx, fd_hash_t * hash, fd_pubkey_hash_vector_t * dirty_keys) {
  slot_ctx->prev_banks_hash = slot_ctx->slot_bank.banks_hash;

  fd_hash_account_deltas( dirty_keys->elems, dirty_keys->cnt, &slot_ctx->account_delta_hash, slot_ctx );

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

    fd_hash_t epoch_accounts_hash;
    fd_accounts_hash(slot_ctx, &epoch_accounts_hash);
    fd_sha256_append( &sha, (uchar const *) &epoch_accounts_hash.hash, sizeof( fd_hash_t ) );

    fd_sha256_fini( &sha, hash->hash );
  }

  fd_solcap_write_bank_preimage(
      slot_ctx->capture,
      hash->hash,
      slot_ctx->prev_banks_hash.hash,
      slot_ctx->account_delta_hash.hash,
      &slot_ctx->slot_bank.poh.hash,
      slot_ctx->signature_cnt );

  FD_LOG_DEBUG(( "bank_hash slot: %lu,  hash: %32J,  parent_hash: %32J,  accounts_delta: %32J,  signature_count: %ld,  last_blockhash: %32J",
      slot_ctx->slot_bank.slot, hash->hash, slot_ctx->prev_banks_hash.hash, slot_ctx->account_delta_hash.hash, slot_ctx->signature_cnt, slot_ctx->slot_bank.poh.hash ));
}


int
fd_update_hash_bank( fd_exec_slot_ctx_t * slot_ctx,
                     fd_hash_t *       hash,
                     ulong             signature_cnt ) {

  fd_acc_mgr_t *       acc_mgr  = slot_ctx->acc_mgr;
  fd_funk_t *          funk     = acc_mgr->funk;
  fd_funk_txn_t *      txn      = slot_ctx->funk_txn;
  ulong                slot     = slot_ctx->slot_bank.slot;
  fd_solcap_writer_t * capture  = slot_ctx->capture;

  /* Collect list of changed accounts to be added to bank hash */

  fd_pubkey_hash_vector_t dirty_keys __attribute__ ((cleanup(fd_pubkey_hash_vector_destroy)));
  fd_pubkey_hash_vector_new(&dirty_keys);

  fd_funk_rec_vector_t erase_recs __attribute__((cleanup(fd_funk_rec_vector_destroy)));
  fd_funk_rec_vector_new(&erase_recs);
  /* Iterate over accounts that have been changed in the current
     database transaction. */

  for( fd_funk_rec_t const * rec = fd_funk_txn_first_rec( funk, txn );
       NULL != rec;
       rec = fd_funk_txn_next_rec( funk, rec ) ) {

    if( !fd_acc_mgr_is_key( rec->pair.key  ) ) continue;
    if( !fd_funk_rec_is_modified(funk, rec ) ) continue;

    /* Get dirty account */

    fd_pubkey_t const *       acc_key  = fd_type_pun_const( rec->pair.key[0].uc );
    fd_funk_rec_t const *     rec      = NULL;

    int err = 0;
    uchar const * _raw = fd_acc_mgr_view_raw( acc_mgr, txn, acc_key, &rec, &err);
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) )
      return err;
    fd_account_meta_t const * acc_meta = (fd_account_meta_t const *)_raw;
    uchar const *             acc_data = _raw + acc_meta->hlen;

    /* Hash account */

    fd_hash_t acc_hash[1];
    // TODO: talk to jsiegel about this
    if (FD_UNLIKELY(acc_meta->info.lamports == 0)) { //!FD_RAW_ACCOUNT_EXISTS(_raw))) {
      fd_memset( acc_hash->hash, 0, FD_HASH_FOOTPRINT );
      /* If we erase records instantly, this causes problems with the
         iterator.  Instead, we will store away the record and erase
         it later where appropriate.  */
      fd_funk_rec_vector_push(&erase_recs, rec);
    } else {
      fd_hash_account_current( acc_hash->hash, acc_meta, acc_key->key, acc_data, slot_ctx );
    }

    /* If hash didn't change, nothing to do */

    if( 0==memcmp( acc_hash->hash, acc_meta->hash, sizeof(fd_hash_t) ) ) {
      FD_LOG_WARNING(("Acc hash no change %32J for account %32J", acc_meta->hash, acc_key->uc));
      continue;
    }

    /* Upgrade to writable record */

    FD_BORROWED_ACCOUNT_DECL(acc_rec);
    acc_rec->const_rec = rec;

    err = fd_acc_mgr_modify( acc_mgr, txn, acc_key, 0, 0UL, acc_rec);
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) return err;

    /* Update hash */

    memcpy( acc_rec->meta->hash, acc_hash->hash, sizeof(fd_hash_t) );

    /* Logging ... */
    FD_LOG_DEBUG(( "fd_acc_mgr_update_hash: %32J "
                   "slot: %ld "
                   "lamports: %ld  "
                   "owner: %32J  "
                   "executable: %s,  "
                   "rent_epoch: %ld, "
                   "data_len: %ld",
                   acc_key,
                   slot,
                   acc_rec->meta->info.lamports,
                   acc_rec->meta->info.owner,
                   acc_rec->meta->info.executable ? "true" : "false",
                   acc_rec->meta->info.rent_epoch,
                   acc_rec->meta->dlen ));

    /* Add account to "dirty keys" list, which will be added to the
       bank hash. */

    fd_pubkey_hash_pair_t dirty_entry;
    memcpy( dirty_entry.pubkey.key, acc_key,        sizeof(fd_pubkey_t) );
    memcpy( dirty_entry.hash.hash,  acc_hash->hash, sizeof(fd_hash_t  ) );
    fd_pubkey_hash_vector_push( &dirty_keys, dirty_entry );

    /* Add to capture */

    err = fd_solcap_write_account(
        capture,
        acc_key->uc,
        &acc_rec->meta->info,
        acc_data,
        acc_rec->meta->dlen,
        acc_hash->hash );
    FD_TEST( err==0 );
  }

  /* Sort and hash "dirty keys" to the accounts delta hash. */

  FD_LOG_DEBUG(("slot %ld, dirty %ld", slot_ctx->slot_bank.slot, dirty_keys.cnt));

  slot_ctx->signature_cnt = signature_cnt;
  fd_hash_bank( slot_ctx, hash, &dirty_keys );

  for (ulong i = 0; i < erase_recs.cnt; i++) {
    fd_funk_rec_t const * erase_rec = erase_recs.elems[i];
    fd_funk_rec_remove(funk, fd_funk_rec_modify(funk, erase_rec), 1);
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

void const *
fd_hash_account_v0( uchar                     hash[ static 32 ],
                    fd_account_meta_t const * m,
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
