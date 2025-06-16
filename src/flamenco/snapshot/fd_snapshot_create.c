#include "fd_snapshot_create.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../ballet/zstd/fd_zstd.h"
#include "../runtime/fd_hashes.h"
#include "../runtime/fd_runtime.h"
#include "../runtime/fd_cost_tracker.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zstd.h>

static uchar             padding[ FD_SNAPSHOT_ACC_ALIGN ] = {0};
static fd_account_meta_t default_meta = { .magic = FD_ACCOUNT_META_MAGIC };

static inline fd_account_meta_t *
fd_snapshot_create_get_default_meta( ulong slot ) {
  default_meta.slot = slot;
  return &default_meta;
}

static inline void
fd_snapshot_create_populate_acc_vecs( fd_snapshot_ctx_t *    snapshot_ctx,
                                      fd_solana_manifest_t * manifest,
                                      fd_tar_writer_t *      writer,
                                      ulong *                out_cap ) {

  /* The append vecs need to be described in an index in the manifest so a
     reader knows what account files to look for. These files are technically
     slot indexed, but the Firedancer implementation of the Solana snapshot
     produces far fewer indices. These storages are for the accounts
     that were modified and deleted in the most recent slot because that
     information is used by the Agave client to calculate and verify the
     bank hash for the given slot. This is done as an optimization to avoid
     having to slot index the Firedancer accounts db which would incur a large
     performance hit.

     To avoid iterating through the root twice to determine what accounts were
     touched in the snapshot slot and what accounts were touched in the
     other slots, we will create an array of pubkey pointers for all accounts
     that were touched in the snapshot slot. This buffer can be safely sized to
     the maximum amount of writable accounts that are possible in a non-epoch
     boundary slot. The rationale for this bound is explained in fd_runtime.h.
     We will not attempt to create a snapshot on an epoch boundary.

     TODO: We must add compaction here. */

  fd_pubkey_t * * snapshot_slot_keys    = fd_spad_alloc( snapshot_ctx->spad, alignof(fd_pubkey_t*), sizeof(fd_pubkey_t*) * FD_WRITABLE_ACCS_IN_SLOT );
  ulong           snapshot_slot_key_cnt = 0UL;

  /* We will dynamically resize the number of incremental keys because the upper
     bound will be roughly 8 bytes * writable accs in a slot * number of slots
     since the last full snapshot which can quickly grow to be severalgigabytes
     or more. In the normal case, this won't require dynamic resizing. */
  #define FD_INCREMENTAL_KEY_INIT_BOUND (100000UL)
  ulong                          incremental_key_bound = FD_INCREMENTAL_KEY_INIT_BOUND;
  ulong                          incremental_key_cnt   = 0UL;
  fd_funk_rec_key_t const * * incremental_keys         = snapshot_ctx->is_incremental ?
                                                      fd_spad_alloc( snapshot_ctx->spad, alignof(fd_funk_rec_key_t*), sizeof(fd_funk_rec_key_t*) * incremental_key_bound ) :
                                                      NULL;

  #undef FD_INCREMENTAL_KEY_INIT_BOUND

  /* In order to size out the accounts DB index in the manifest, we must
     iterate through funk and accumulate the size of all of the records
     from all slots before the snapshot_slot. */

  fd_funk_t * funk           = snapshot_ctx->funk;
  ulong       prev_sz        = 0UL;
  ulong       tombstones_cnt = 0UL;
  for( fd_funk_rec_t const * rec = fd_funk_txn_first_rec( funk, NULL ); NULL != rec; rec = fd_funk_txn_next_rec( funk, rec ) ) {

    if( !fd_funk_key_is_acc( rec->pair.key ) ) {
      continue;
    }

    tombstones_cnt++;

    int                 is_tombstone = rec->flags & FD_FUNK_REC_FLAG_ERASE;
    uchar const *       raw          = fd_funk_val( rec, fd_funk_wksp( funk ) );
    fd_account_meta_t * metadata     = is_tombstone ? fd_snapshot_create_get_default_meta( fd_funk_rec_get_erase_data( rec ) ) :
                                                      (fd_account_meta_t*)raw;

    if( !metadata ) {
      continue;
    }

    if( metadata->magic!=FD_ACCOUNT_META_MAGIC ) {
      continue;
    }

    if( snapshot_ctx->is_incremental ) {
      /* We only care about accounts that were modified since the last
         snapshot slot for incremental snapshots.

         We also need to keep track of the capitalization for all of the
         accounts that are in the incremental as this is verified. */
      if( metadata->slot<=snapshot_ctx->last_snap_slot ) {
        continue;
      }
      incremental_keys[ incremental_key_cnt++ ] = rec->pair.key;
      *out_cap += metadata->info.lamports;

      if( FD_UNLIKELY( incremental_key_cnt==incremental_key_bound ) ) {
        /* Dynamically resize if needed. */
        incremental_key_bound *= 2UL;
        fd_funk_rec_key_t const * * new_incremental_keys = fd_spad_alloc( snapshot_ctx->spad,
                                                                         alignof(fd_funk_rec_key_t*),
                                                                            sizeof(fd_funk_rec_key_t*) * incremental_key_bound );
        fd_memcpy( new_incremental_keys, incremental_keys, sizeof(fd_funk_rec_key_t*) * incremental_key_cnt );
        fd_valloc_free( fd_spad_virtual( snapshot_ctx->spad ), incremental_keys );
        incremental_keys = new_incremental_keys;
      }
    }

    /* We know that all of the accounts from the snapshot slot can fit into
       one append vec, so we ignore all accounts from the snapshot slot. */

    if( metadata->slot==snapshot_ctx->slot ) {
      continue;
    }

    prev_sz += metadata->dlen + sizeof(fd_solana_account_hdr_t);

  }

  /* At this point we have sized out all of the relevant accounts that will
     be included in the snapshot. Now we must populate each of the append vecs
     and update the index as we go.

     When we account for the number of slots we need to consider one append vec
     for the snapshot slot and try to maximally fill up the others: an append
     vec has a protocol-defined maximum size in Agave.  */

  ulong num_slots = 1UL + prev_sz / FD_SNAPSHOT_APPEND_VEC_SZ_MAX +
                    (prev_sz % FD_SNAPSHOT_APPEND_VEC_SZ_MAX ? 1UL : 0UL);

  fd_solana_accounts_db_fields_t * accounts_db = &manifest->accounts_db;

  accounts_db->storages_len                    = num_slots;
  accounts_db->storages                        = fd_spad_alloc( snapshot_ctx->spad,
                                                                FD_SNAPSHOT_SLOT_ACC_VECS_ALIGN,
                                                                sizeof(fd_snapshot_slot_acc_vecs_t) * accounts_db->storages_len );
  accounts_db->version                        = 1UL;
  accounts_db->slot                           = snapshot_ctx->slot;
  accounts_db->historical_roots_len           = 0UL;
  accounts_db->historical_roots               = NULL;
  accounts_db->historical_roots_with_hash_len = 0UL;
  accounts_db->historical_roots_with_hash     = NULL;

  for( ulong i=0UL; i<num_slots; i++ ) {
    /* Populate the storages for each slot. As a note, the slot number only
       matters for the snapshot slot. The other slot numbers don't affect
       consensus at all. Agave also maintains an invariant that there can
       only be one account vec per storage. */

    accounts_db->storages[ i ].account_vecs_len          = 1UL;
    accounts_db->storages[ i ].account_vecs              = fd_spad_alloc( snapshot_ctx->spad,
                                                                          FD_SNAPSHOT_ACC_VEC_ALIGN,
                                                                          sizeof(fd_snapshot_acc_vec_t) * accounts_db->storages[ i ].account_vecs_len );
    accounts_db->storages[ i ].account_vecs[ 0 ].file_sz = 0UL;
    accounts_db->storages[ i ].account_vecs[ 0 ].id      = i + 1UL;
    accounts_db->storages[ i ].slot                      = snapshot_ctx->slot - i;
  }

  /* At this point we have iterated through all of the accounts and created
     the index. We are now ready to generate a snapshot hash. For both
     snapshots we need to generate two hashes:
     1. The accounts hash. This is a simple hash of all of the accounts
        included in the snapshot.
     2. The snapshot hash. This is a hash of the accounts hash and the epoch
        account hash. If the EAH is not included, then the accounts hash ==
        snapshot hash.

    There is some nuance as to which hash goes where. For full snapshots,
    the accounts hash in the bank hash info is the accounts hash. The hash in
    the filename is the snapshot hash.

    For incremental snapshots, the account hash in the bank hash info field is
    left zeroed out. The full snapshot's hash is in the incremental persistence
    field. The incremental snapshot's accounts hash is included in the
    incremental persistence field. The hash in the filename is the snapshot
    hash. */

  int err;
  if( !snapshot_ctx->is_incremental ) {

    err = fd_snapshot_service_hash( &snapshot_ctx->acc_hash,
                                    &snapshot_ctx->snap_hash,
                                    &snapshot_ctx->slot_bank,
                                    &snapshot_ctx->epoch_bank,
                                    snapshot_ctx->funk,
                                    snapshot_ctx->tpool,
                                    snapshot_ctx->spad,
                                    snapshot_ctx->features );
    accounts_db->bank_hash_info.accounts_hash = snapshot_ctx->acc_hash;
  } else {
    err = fd_snapshot_service_inc_hash( &snapshot_ctx->acc_hash,
                                        &snapshot_ctx->snap_hash,
                                        &snapshot_ctx->slot_bank,
                                        &snapshot_ctx->epoch_bank,
                                        snapshot_ctx->funk,
                                        incremental_keys,
                                        incremental_key_cnt,
                                        snapshot_ctx->spad,
                                        snapshot_ctx->features );
    fd_valloc_free( fd_spad_virtual( snapshot_ctx->spad ), incremental_keys );

    fd_memset( &accounts_db->bank_hash_info.accounts_hash, 0, sizeof(fd_hash_t) );
  }

  FD_LOG_NOTICE(( "Hashes calculated acc_hash=%s snapshot_hash=%s",
                  FD_BASE58_ENC_32_ALLOCA(&snapshot_ctx->acc_hash),
                  FD_BASE58_ENC_32_ALLOCA(&snapshot_ctx->snap_hash) ));

  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Unable to calculate snapshot hash" ));
  }

  fd_memset( &accounts_db->bank_hash_info.stats, 0, sizeof(fd_bank_hash_stats_t) );

  /* Now, we have calculated the relevant hashes for the accounts.
     Because the files are serially written out for tar and we need to prepend
     the manifest, we must reserve space in the archive for the solana manifest. */

  if( snapshot_ctx->is_incremental ) {
    manifest->bank_incremental_snapshot_persistence = fd_spad_alloc( snapshot_ctx->spad,
                                                                     FD_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_ALIGN,
                                                                     sizeof(fd_bank_incremental_snapshot_persistence_t) );
  }

  ulong manifest_sz = fd_solana_manifest_size( manifest );

  char buffer[ FD_SNAPSHOT_DIR_MAX ];
  err = snprintf( buffer, FD_SNAPSHOT_DIR_MAX, "snapshots/%lu/%lu", snapshot_ctx->slot, snapshot_ctx->slot );
  if( FD_UNLIKELY( err<0 ) ) {
    FD_LOG_ERR(( "Unable to format manifest name string" ));
  }

  err = fd_tar_writer_new_file( writer, buffer );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Unable to create snapshot manifest file" ));
  }

  /* TODO: We want to eliminate having to write back into the tar file. This
     will enable the snapshot service to only use one file per snapshot.
     In order to do this, we must precompute the index in the manifest
     completely. This will allow us to stream out a compressed snapshot. */

  err = fd_tar_writer_make_space( writer, manifest_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Unable to make space for snapshot manifest file" ));
  }

  err = fd_tar_writer_fini_file( writer );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Unable to finalize snapshot manifest file" ));
  }

  /* We have made space for the manifest and are ready to append the append
     vec files directly into the tar archive. We will iterate through all of
     the records in the funk root and create/populate an append vec for
     previous slots. Just record the pubkeys for the latest slot to populate
     the append vec after. If the append vec is full, write into the next one. */

  ulong curr_slot = 1UL;
  fd_snapshot_acc_vec_t * prev_accs = &accounts_db->storages[ curr_slot ].account_vecs[ 0UL ];

  err = snprintf( buffer, FD_SNAPSHOT_DIR_MAX, "accounts/%lu.%lu", snapshot_ctx->slot - curr_slot, prev_accs->id );
  if( FD_UNLIKELY( err<0 ) ) {
    FD_LOG_ERR(( "Unable to format previous accounts name string" ));
  }

  err = fd_tar_writer_new_file( writer, buffer );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Unable to create previous accounts file" ));
  }

  fd_funk_rec_t * * tombstones = snapshot_ctx->is_incremental ? NULL :
    fd_spad_alloc( snapshot_ctx->spad, alignof(fd_funk_rec_t*), sizeof(fd_funk_rec_t*) * tombstones_cnt );
  tombstones_cnt = 0UL;

  for( fd_funk_rec_t const * rec = fd_funk_txn_first_rec( funk, NULL ); NULL != rec; rec = fd_funk_txn_next_rec( funk, rec ) ) {

    /* Get the account data. */

    if( !fd_funk_key_is_acc( rec->pair.key ) ) {
      continue;
    }

    fd_pubkey_t const * pubkey       = fd_type_pun_const( rec->pair.key[0].uc );
    int                 is_tombstone = rec->flags & FD_FUNK_REC_FLAG_ERASE;
    uchar const *       raw          = fd_funk_val( rec, fd_funk_wksp( funk ) );
    fd_account_meta_t * metadata     = is_tombstone ? fd_snapshot_create_get_default_meta( fd_funk_rec_get_erase_data( rec ) ) :
                                                      (fd_account_meta_t*)raw;

    if( !snapshot_ctx->is_incremental && is_tombstone ) {
      /* If we are in a full snapshot, we need to gather all of the accounts
         that we plan on deleting. */
      tombstones[ tombstones_cnt++ ] = (fd_funk_rec_t*)rec;
    }

    if( !metadata ) {
      continue;
    }

    if( metadata->magic!=FD_ACCOUNT_META_MAGIC ) {
      continue;
    }

    /* Don't iterate through accounts that were touched before the last full
       snapshot. */
    if( snapshot_ctx->is_incremental && metadata->slot<=snapshot_ctx->last_snap_slot ) {
      continue;
    }

    uchar const * acc_data = raw + metadata->hlen;

    /* All accounts that were touched in the snapshot slot should be in
       a different append vec so that Agave can calculate the snapshot slot's
       bank hash. We don't want to include them in an arbitrary append vec. */

    if( metadata->slot==snapshot_ctx->slot ) {
      snapshot_slot_keys[ snapshot_slot_key_cnt++ ] = (fd_pubkey_t*)pubkey;
      continue;
    }

    /* We don't want to iterate over tombstones if the snapshot is not
       incremental */
    if( !snapshot_ctx->is_incremental && is_tombstone ) {
      continue;
    }

    ulong new_sz = prev_accs->file_sz + sizeof(fd_solana_account_hdr_t) + fd_ulong_align_up( metadata->dlen, FD_SNAPSHOT_ACC_ALIGN );

    if( new_sz>FD_SNAPSHOT_APPEND_VEC_SZ_MAX ) {

      /* When the current append vec is full, finish writing it, start writing
         into the next append vec. */

      err = fd_tar_writer_fini_file( writer );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_ERR(( "Unable to finalize previous accounts file" ));
      }

      prev_accs = &accounts_db->storages[ ++curr_slot ].account_vecs[ 0UL ];

      err = snprintf( buffer, FD_SNAPSHOT_DIR_MAX, "accounts/%lu.%lu", snapshot_ctx->slot - curr_slot, prev_accs->id );
      if( FD_UNLIKELY( err<0 ) ) {
        FD_LOG_ERR(( "Unable to format previous accounts name string" ));
      }

      err = fd_tar_writer_new_file( writer, buffer );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_ERR(( "Unable to create previous accounts file" ));
      }
    }

    prev_accs->file_sz += sizeof(fd_solana_account_hdr_t) + fd_ulong_align_up( metadata->dlen, FD_SNAPSHOT_ACC_ALIGN );


    /* Write out the header. */

    fd_solana_account_hdr_t header = {0};
    /* Stored meta */
    header.meta.write_version_obsolete = 0UL;
    header.meta.data_len               = metadata->dlen;
    fd_memcpy( header.meta.pubkey, pubkey, sizeof(fd_pubkey_t) );
    /* Account Meta */
    header.info.lamports               = metadata->info.lamports;
    header.info.rent_epoch             = header.info.lamports ? metadata->info.rent_epoch : 0UL;
    fd_memcpy( header.info.owner, metadata->info.owner, sizeof(fd_pubkey_t) );
    header.info.executable             = metadata->info.executable;
    /* Hash */
    fd_memcpy( &header.hash, metadata->hash, sizeof(fd_hash_t) );

    err = fd_tar_writer_write_file_data( writer, &header, sizeof(fd_solana_account_hdr_t) );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "Unable to stream out account header to tar archive" ));
    }

    /* Write out the file data. */

    err = fd_tar_writer_write_file_data( writer, acc_data, metadata->dlen );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "Unable to stream out account data to tar archive" ));
    }

    ulong align_sz = fd_ulong_align_up( metadata->dlen, FD_SNAPSHOT_ACC_ALIGN ) - metadata->dlen;
    err = fd_tar_writer_write_file_data( writer, padding, align_sz );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR( ("Unable to stream out account padding to tar archive" ));
    }
  }

  err = fd_tar_writer_fini_file( writer );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Unable to finalize previous accounts file" ));
  }

  /* Now write out the append vec for the snapshot slot. Again, this is needed
     because the snapshot slot's accounts must be in their append vec in order
     to verify the bank hash for the snapshot slot in the Agave client. */

  fd_snapshot_acc_vec_t * curr_accs = &accounts_db->storages[ 0UL ].account_vecs[ 0UL ];
  err = snprintf( buffer, FD_SNAPSHOT_DIR_MAX, "accounts/%lu.%lu", snapshot_ctx->slot, curr_accs->id );
  if( FD_UNLIKELY( err<0 ) ) {
    FD_LOG_ERR(( "Unable to format current accounts name string" ));
  }

  err = fd_tar_writer_new_file( writer, buffer );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Unable to create current accounts file" ));
  }

  for( ulong i=0UL; i<snapshot_slot_key_cnt; i++ ) {

    fd_pubkey_t const * pubkey = snapshot_slot_keys[i];
    fd_funk_rec_key_t key = fd_funk_acc_key( pubkey );

    fd_funk_rec_query_t query[1];
    fd_funk_rec_t const * rec = fd_funk_rec_query_try( funk, NULL, &key, query );
    if( FD_UNLIKELY( !rec ) ) {
      FD_LOG_ERR(( "Previously found record can no longer be found" ));
    }

    int                 is_tombstone = rec->flags & FD_FUNK_REC_FLAG_ERASE;
    uchar       const * raw          = fd_funk_val( rec, fd_funk_wksp( funk ) );
    fd_account_meta_t * metadata     = is_tombstone ? fd_snapshot_create_get_default_meta( fd_funk_rec_get_erase_data( rec ) ) :
                                                      (fd_account_meta_t*)raw;

    if( FD_UNLIKELY( !metadata ) ) {
      FD_LOG_ERR(( "Record should have non-NULL metadata" ));
    }

    if( FD_UNLIKELY( metadata->magic!=FD_ACCOUNT_META_MAGIC ) ) {
      FD_LOG_ERR(( "Record should have valid magic" ));
    }

    uchar const * acc_data = raw + metadata->hlen;

    curr_accs->file_sz += sizeof(fd_solana_account_hdr_t) + fd_ulong_align_up( metadata->dlen, FD_SNAPSHOT_ACC_ALIGN );

    /* Write out the header. */
    fd_solana_account_hdr_t header = {0};
    /* Stored meta */
    header.meta.write_version_obsolete = 0UL;
    header.meta.data_len               = metadata->dlen;
    fd_memcpy( header.meta.pubkey, pubkey, sizeof(fd_pubkey_t) );
    /* Account Meta */
    header.info.lamports               = metadata->info.lamports;
    header.info.rent_epoch             = header.info.lamports ? metadata->info.rent_epoch : 0UL;
    fd_memcpy( header.info.owner, metadata->info.owner, sizeof(fd_pubkey_t) );
    header.info.executable             = metadata->info.executable;
    /* Hash */
    fd_memcpy( &header.hash, metadata->hash, sizeof(fd_hash_t) );


    err = fd_tar_writer_write_file_data( writer, &header, sizeof(fd_solana_account_hdr_t) );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "Unable to stream out account header to tar archive" ));
    }
    err = fd_tar_writer_write_file_data( writer, acc_data, metadata->dlen );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "Unable to stream out account data to tar archive" ));
    }
    ulong align_sz = fd_ulong_align_up( metadata->dlen, FD_SNAPSHOT_ACC_ALIGN ) - metadata->dlen;
    err = fd_tar_writer_write_file_data( writer, padding, align_sz );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "Unable to stream out account padding to tar archive" ));
    }

    FD_TEST( !fd_funk_rec_query_test( query ) );
  }

  err = fd_tar_writer_fini_file( writer );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Unable to finish writing out file" ));
  }

  /* TODO: At this point we must implement compaction to the snapshot service.
     Without this, we are actually not cleaning up any tombstones from funk. */

  if( snapshot_ctx->is_incremental ) {
    err = fd_funk_rec_forget( funk, tombstones, tombstones_cnt );
    if( FD_UNLIKELY( err!=FD_FUNK_SUCCESS ) ) {
      FD_LOG_ERR(( "Unable to forget tombstones" ));
    }
    FD_LOG_NOTICE(( "Compacted %lu tombstone records", tombstones_cnt ));
  }

  fd_valloc_free( fd_spad_virtual( snapshot_ctx->spad ), snapshot_slot_keys );
  fd_valloc_free( fd_spad_virtual( snapshot_ctx->spad ), tombstones );

}

static void
fd_snapshot_create_serialiable_stakes( fd_snapshot_ctx_t * snapshot_ctx,
                                       fd_stakes_delegation_t *       old_stakes,
                                       fd_stakes_delegation_t *       new_stakes ) {

  /* The deserialized stakes cache that is used by the runtime can't be
     reserialized into the format that Agave uses. For every vote account
     in the stakes struct, the Firedancer client holds a decoded copy of the
     vote state. However, this vote state can't be reserialized back into the
     full vote account data.

     This poses a problem in the Agave client client because upon boot, Agave
     verifies that for all of the vote accounts in the stakes struct, the data
     in the cache is the same as the data in the accounts db.

     The other problem is that the Firedancer stakes cache does not evict old
     entries and doesn't update delegations within the cache. The cache will
     just insert new pubkeys as stake accounts are created/delegated to. To
     make the cache conformant for the snapshot, old accounts should be removed
     from the snapshot and all of the delegations should be updated. */

  /* First populate the vote accounts using the vote accounts/stakes cache.
     We can populate over all of the fields except we can't reserialize the
     vote account data. Instead we will copy over the raw contents of all of
     the vote accounts. */

  ulong   vote_accounts_len                    = fd_vote_accounts_pair_t_map_size( old_stakes->vote_accounts.vote_accounts_pool, old_stakes->vote_accounts.vote_accounts_root );
  uchar * pool_mem                             = fd_spad_alloc( snapshot_ctx->spad, fd_vote_accounts_pair_t_map_align(), fd_vote_accounts_pair_t_map_footprint( vote_accounts_len ) );
  new_stakes->vote_accounts.vote_accounts_pool = fd_vote_accounts_pair_t_map_join( fd_vote_accounts_pair_t_map_new( pool_mem, vote_accounts_len ) );
  new_stakes->vote_accounts.vote_accounts_root = NULL;

  for( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum(
       old_stakes->vote_accounts.vote_accounts_pool,
       old_stakes->vote_accounts.vote_accounts_root );
       n;
       n = fd_vote_accounts_pair_t_map_successor( old_stakes->vote_accounts.vote_accounts_pool, n ) ) {

    fd_vote_accounts_pair_t_mapnode_t * new_node = fd_vote_accounts_pair_t_map_acquire( new_stakes->vote_accounts.vote_accounts_pool );
    new_node->elem.key   = n->elem.key;
    new_node->elem.stake = n->elem.stake;
    /* Now to populate the value, lookup the account using the acc mgr */
    FD_TXN_ACCOUNT_DECL( vote_acc );
    int err = fd_txn_account_init_from_funk_readonly( vote_acc, &n->elem.key, snapshot_ctx->funk, NULL );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "Failed to view vote account from stakes cache %s", FD_BASE58_ENC_32_ALLOCA(&n->elem.key) ));
    }

    new_node->elem.value.lamports   = vote_acc->vt->get_lamports( vote_acc );
    new_node->elem.value.data_len   = vote_acc->vt->get_data_len( vote_acc );
    new_node->elem.value.data       = fd_spad_alloc( snapshot_ctx->spad, 8UL, vote_acc->vt->get_data_len( vote_acc ) );
    fd_memcpy( new_node->elem.value.data, vote_acc->vt->get_data( vote_acc ), vote_acc->vt->get_data_len( vote_acc ) );
    new_node->elem.value.owner      = *vote_acc->vt->get_owner( vote_acc );
    new_node->elem.value.executable = (uchar)vote_acc->vt->is_executable( vote_acc );
    new_node->elem.value.rent_epoch = vote_acc->vt->get_rent_epoch( vote_acc );
    fd_vote_accounts_pair_t_map_insert( new_stakes->vote_accounts.vote_accounts_pool, &new_stakes->vote_accounts.vote_accounts_root, new_node );

  }

  /* Stale stake delegations should also be removed or updated in the cache.
     TODO: This will likely be changed in the near future as the stake
     program is migrated to a bpf program. It will likely be replaced by an
     index of stake/vote accounts. */

  FD_TXN_ACCOUNT_DECL( stake_acc );
  fd_delegation_pair_t_mapnode_t *      nn = NULL;
  for( fd_delegation_pair_t_mapnode_t * n  = fd_delegation_pair_t_map_minimum(
      old_stakes->stake_delegations_pool, old_stakes->stake_delegations_root ); n; n=nn ) {

    nn = fd_delegation_pair_t_map_successor( old_stakes->stake_delegations_pool, n );

    int err = fd_txn_account_init_from_funk_readonly( stake_acc, &n->elem.account, snapshot_ctx->funk, NULL );
    if( FD_UNLIKELY( err ) ) {
      /* If the stake account doesn't exist, the cache is stale and the entry
         just needs to be evicted. */
      fd_delegation_pair_t_map_remove( old_stakes->stake_delegations_pool, &old_stakes->stake_delegations_root, n );
      fd_delegation_pair_t_map_release( old_stakes->stake_delegations_pool, n );
    } else {
      /* Otherwise, just update the delegation in case it is stale. */
      fd_stake_state_v2_t * stake_state = fd_bincode_decode_spad(
          stake_state_v2, snapshot_ctx->spad,
          stake_acc->vt->get_data( stake_acc ),
          stake_acc->vt->get_data_len( stake_acc ),
          &err );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_ERR(( "Failed to decode stake state" ));
      }
      n->elem.delegation = stake_state->inner.stake.stake.delegation;
    }
  }

  /* Copy over the rest of the fields as they are the same. */

  new_stakes->stake_delegations_pool = old_stakes->stake_delegations_pool;
  new_stakes->stake_delegations_root = old_stakes->stake_delegations_root;
  new_stakes->unused                 = old_stakes->unused;
  new_stakes->epoch                  = old_stakes->epoch;
  new_stakes->stake_history          = old_stakes->stake_history;

}

static inline void
fd_snapshot_create_populate_bank( fd_snapshot_ctx_t *   snapshot_ctx,
                                  fd_versioned_bank_t * bank ) {

  fd_slot_bank_t  * slot_bank  = &snapshot_ctx->slot_bank;
  fd_epoch_bank_t * epoch_bank = &snapshot_ctx->epoch_bank;

  /* The blockhash queue has to be copied over along with all of its entries.
     As a note, the size is 300 but in fact is of size 301 due to a knwon bug
     in the agave client that is emulated by the firedancer client. */

  bank->blockhash_queue.last_hash_index = slot_bank->block_hash_queue.last_hash_index;
  bank->blockhash_queue.last_hash       = fd_spad_alloc( snapshot_ctx->spad, FD_HASH_ALIGN, FD_HASH_FOOTPRINT );
  *bank->blockhash_queue.last_hash      = *slot_bank->block_hash_queue.last_hash;

  bank->blockhash_queue.ages_len = fd_hash_hash_age_pair_t_map_size( slot_bank->block_hash_queue.ages_pool, slot_bank->block_hash_queue.ages_root);
  bank->blockhash_queue.ages     = fd_spad_alloc( snapshot_ctx->spad, FD_HASH_HASH_AGE_PAIR_ALIGN, bank->blockhash_queue.ages_len * sizeof(fd_hash_hash_age_pair_t) );
  bank->blockhash_queue.max_age  = FD_BLOCKHASH_QUEUE_SIZE;

  fd_block_hash_queue_t             * queue               = &slot_bank->block_hash_queue;
  fd_hash_hash_age_pair_t_mapnode_t * nn                  = NULL;
  ulong                               blockhash_queue_idx = 0UL;
  for( fd_hash_hash_age_pair_t_mapnode_t * n = fd_hash_hash_age_pair_t_map_minimum( queue->ages_pool, queue->ages_root ); n; n = nn ) {
    nn = fd_hash_hash_age_pair_t_map_successor( queue->ages_pool, n );
    bank->blockhash_queue.ages[ blockhash_queue_idx++ ] = n->elem;
  }



  /* Ancestor can be omitted to boot off of for both clients */

  bank->ancestors_len                         = 0UL;
  bank->ancestors                             = NULL;

  bank->hash                                  = slot_bank->banks_hash;
  bank->parent_hash                           = slot_bank->prev_banks_hash;
  bank->parent_slot                           = slot_bank->prev_slot;
  bank->hard_forks                            = slot_bank->hard_forks;
  bank->transaction_count                     = slot_bank->transaction_count;
  bank->signature_count                       = slot_bank->parent_signature_cnt;
  bank->capitalization                        = slot_bank->capitalization;
  bank->tick_height                           = slot_bank->tick_height;
  bank->max_tick_height                       = slot_bank->max_tick_height;

  /* The hashes_per_tick needs to be copied over from the epoch bank because
     the pointer could go out of bounds during an epoch boundary. */
  bank->hashes_per_tick                       = fd_spad_alloc( snapshot_ctx->spad, alignof(ulong), sizeof(ulong) );
  *bank->hashes_per_tick                      = epoch_bank->hashes_per_tick;

  bank->ticks_per_slot                        = FD_TICKS_PER_SLOT;
  bank->ns_per_slot                           = epoch_bank->ns_per_slot;
  bank->genesis_creation_time                 = epoch_bank->genesis_creation_time;
  bank->slots_per_year                        = epoch_bank->slots_per_year;

  /* This value can be set to 0 because the Agave client recomputes this value
     and the firedancer client doesn't use it. */

  bank->accounts_data_len                     = 0UL;

  bank->slot                                  = snapshot_ctx->slot;
  bank->epoch                                 = fd_slot_to_epoch( &epoch_bank->epoch_schedule, bank->slot, NULL );
  bank->block_height                          = slot_bank->block_height;

  /* Collector id can be left as null for both clients */

  fd_memset( &bank->collector_id, 0, sizeof(fd_pubkey_t) );

  bank->collector_fees                        = slot_bank->collected_execution_fees + slot_bank->collected_priority_fees;
  bank->fee_calculator.lamports_per_signature = slot_bank->lamports_per_signature;
  bank->fee_rate_governor                     = slot_bank->fee_rate_governor;
  bank->collected_rent                        = slot_bank->collected_rent;

  bank->rent_collector.epoch                  = bank->epoch;
  bank->rent_collector.epoch_schedule         = epoch_bank->rent_epoch_schedule;
  bank->rent_collector.slots_per_year         = epoch_bank->slots_per_year;
  bank->rent_collector.rent                   = epoch_bank->rent;

  bank->epoch_schedule                        = epoch_bank->epoch_schedule;
  bank->inflation                             = epoch_bank->inflation;

  /* Unused accounts can be left as NULL for both clients. */

  fd_memset( &bank->unused_accounts, 0, sizeof(fd_unused_accounts_t) );

  /* We need to copy over the stakes for two epochs despite the Agave client
     providing the stakes for 6 epochs. These stakes need to be copied over
     because of the fact that the leader schedule computation uses the two
     previous epoch stakes.

     TODO: This field has been deprecated by agave and has instead been
     replaced with the versioned epoch stakes field in the manifest. The
     firedancer client will populate the deprecated field. */

  fd_epoch_epoch_stakes_pair_t * relevant_epoch_stakes = fd_spad_alloc( snapshot_ctx->spad, FD_EPOCH_EPOCH_STAKES_PAIR_ALIGN, 2UL * sizeof(fd_epoch_epoch_stakes_pair_t) );
  fd_memset( &relevant_epoch_stakes[0], 0UL, sizeof(fd_epoch_epoch_stakes_pair_t) );
  fd_memset( &relevant_epoch_stakes[1], 0UL, sizeof(fd_epoch_epoch_stakes_pair_t) );
  relevant_epoch_stakes[0].key                        = bank->epoch;
  relevant_epoch_stakes[0].value.stakes.vote_accounts = slot_bank->epoch_stakes;
  relevant_epoch_stakes[1].key                        = bank->epoch+1UL;
  relevant_epoch_stakes[1].value.stakes.vote_accounts = epoch_bank->next_epoch_stakes;

  bank->epoch_stakes_len = 2UL;
  bank->epoch_stakes     = relevant_epoch_stakes;
  bank->is_delta         = snapshot_ctx->is_incremental;

  /* The firedancer runtime currently maintains a version of the stakes which
     can't be reserialized into a format that is compatible with the Solana
     snapshot format. Therefore, we must recompute the data structure using
     the pubkeys from the stakes cache that is currently in the epoch context. */

  fd_snapshot_create_serialiable_stakes( snapshot_ctx, &epoch_bank->stakes, &bank->stakes );

}

static inline void
fd_snapshot_create_setup_and_validate_ctx( fd_snapshot_ctx_t * snapshot_ctx ) {

  fd_funk_t * funk = snapshot_ctx->funk;

  /* First the epoch bank. */

  fd_funk_rec_key_t     epoch_id  = fd_runtime_epoch_bank_key();
  fd_funk_rec_query_t   query[1];
  fd_funk_rec_t const * epoch_rec = fd_funk_rec_query_try( funk, NULL, &epoch_id, query );
  if( FD_UNLIKELY( !epoch_rec ) ) {
    FD_LOG_ERR(( "Failed to read epoch bank record: missing record" ));
  }
  void * epoch_val = fd_funk_val( epoch_rec, fd_funk_wksp( funk ) );

  if( FD_UNLIKELY( fd_funk_val_sz( epoch_rec )<sizeof(uint) ) ) {
    FD_LOG_ERR(( "Failed to read epoch bank record: empty record" ));
  }

  uint epoch_magic = *(uint*)epoch_val;
  if( FD_UNLIKELY( epoch_magic!=FD_RUNTIME_ENC_BINCODE ) ) {
    FD_LOG_ERR(( "Epoch bank record has wrong magic" ));
  }

  int err;
  fd_epoch_bank_t * epoch_bank = fd_bincode_decode_spad(
      epoch_bank, snapshot_ctx->spad,
      (uchar *)epoch_val          + sizeof(uint),
      fd_funk_val_sz( epoch_rec ) - sizeof(uint),
      &err );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_ERR(( "Failed to decode epoch bank" ));
  }

  snapshot_ctx->epoch_bank = *epoch_bank;

  FD_TEST( !fd_funk_rec_query_test( query ) );

  /* Now the slot bank. */

  fd_funk_rec_key_t     slot_id  = fd_runtime_slot_bank_key();
  fd_funk_rec_t const * slot_rec = fd_funk_rec_query_try( funk, NULL, &slot_id, query );
  if( FD_UNLIKELY( !slot_rec ) ) {
    FD_LOG_ERR(( "Failed to read slot bank record: missing record" ));
  }
  void * slot_val = fd_funk_val( slot_rec, fd_funk_wksp( funk ) );

  if( FD_UNLIKELY( fd_funk_val_sz( slot_rec )<sizeof(uint) ) ) {
    FD_LOG_ERR(( "Failed to read slot bank record: empty record" ));
  }

  uint slot_magic = *(uint*)slot_val;
  if( FD_UNLIKELY( slot_magic!=FD_RUNTIME_ENC_BINCODE ) ) {
    FD_LOG_ERR(( "Slot bank record has wrong magic" ));
  }

  fd_slot_bank_t * slot_bank = fd_bincode_decode_spad(
      slot_bank, snapshot_ctx->spad,
      (uchar *)slot_val          + sizeof(uint),
      fd_funk_val_sz( slot_rec ) - sizeof(uint),
      &err );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_ERR(( "Failed to decode slot bank" ));
  }

  snapshot_ctx->slot_bank = *slot_bank;

  FD_TEST( !fd_funk_rec_query_test( query ) );

  /* Validate that the snapshot context is setup correctly */

  if( FD_UNLIKELY( !snapshot_ctx->out_dir ) ) {
    FD_LOG_ERR(( "Snapshot directory is not set" ));
  }

  if( FD_UNLIKELY( snapshot_ctx->slot>snapshot_ctx->slot_bank.slot ) ) {
    FD_LOG_ERR(( "Snapshot slot=%lu is greater than the current slot=%lu",
                     snapshot_ctx->slot, snapshot_ctx->slot_bank.slot ));
  }

  /* Truncate the two files used for snapshot creation and seek to its start. */

  long seek = lseek( snapshot_ctx->tmp_fd, 0, SEEK_SET );
  if( FD_UNLIKELY( seek ) ) {
    FD_LOG_ERR(( "Failed to seek to the start of the file" ));
  }

  if( FD_UNLIKELY( ftruncate( snapshot_ctx->tmp_fd, 0UL ) < 0 ) ) {
    FD_LOG_ERR(( "Failed to truncate the temporary file" ));
  }

  seek = lseek( snapshot_ctx->snapshot_fd, 0, SEEK_SET );
  if( FD_UNLIKELY( seek ) ) {
    FD_LOG_ERR(( "Failed to seek to the start of the file" ));
  }

  if( FD_UNLIKELY( ftruncate( snapshot_ctx->snapshot_fd, 0UL ) < 0 ) ) {
    FD_LOG_ERR(( "Failed to truncate the snapshot file" ));
  }

}

static inline void
fd_snapshot_create_setup_writer( fd_snapshot_ctx_t * snapshot_ctx ) {

  /* Setup a tar writer. */

  uchar * writer_mem   = fd_spad_alloc( snapshot_ctx->spad, fd_tar_writer_align(), fd_tar_writer_footprint() );
  snapshot_ctx->writer = fd_tar_writer_new( writer_mem, snapshot_ctx->tmp_fd );
  if( FD_UNLIKELY( !snapshot_ctx->writer ) ) {
    FD_LOG_ERR(( "Unable to create a tar writer" ));
  }
}

static inline void
fd_snapshot_create_write_version( fd_snapshot_ctx_t * snapshot_ctx ) {

  /* The first file in the tar archive should be the version file.. */

  int err = fd_tar_writer_new_file( snapshot_ctx->writer, FD_SNAPSHOT_VERSION_FILE );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Failed to create the version file" ));
  }

  err = fd_tar_writer_write_file_data( snapshot_ctx->writer, FD_SNAPSHOT_VERSION, FD_SNAPSHOT_VERSION_LEN);
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Failed to create the version file" ));
  }

  err = fd_tar_writer_fini_file( snapshot_ctx->writer );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Failed to create the version file" ));
  }

}

static inline void
fd_snapshot_create_write_status_cache( fd_snapshot_ctx_t * snapshot_ctx ) {

  /* First convert the existing status cache into a snapshot-friendly format. */

  fd_bank_slot_deltas_t slot_deltas_new = {0};
  int err = fd_txncache_get_entries( snapshot_ctx->status_cache,
                                     &slot_deltas_new,
                                     snapshot_ctx->spad );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Failed to get entries from the status cache" ));
  }
  ulong   bank_slot_deltas_sz = fd_bank_slot_deltas_size( &slot_deltas_new );
  uchar * out_status_cache    = fd_spad_alloc( snapshot_ctx->spad,
                                               FD_BANK_SLOT_DELTAS_ALIGN,
                                               bank_slot_deltas_sz );
  fd_bincode_encode_ctx_t encode_status_cache = {
    .data    = out_status_cache,
    .dataend = out_status_cache + bank_slot_deltas_sz,
  };
  if( FD_UNLIKELY( fd_bank_slot_deltas_encode( &slot_deltas_new, &encode_status_cache ) ) ) {
    FD_LOG_ERR(( "Failed to encode the status cache" ));
  }

  /* Now write out the encoded buffer to the tar archive. */

  err = fd_tar_writer_new_file( snapshot_ctx->writer, FD_SNAPSHOT_STATUS_CACHE_FILE );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Failed to create the status cache file" ));
  }
  err = fd_tar_writer_write_file_data( snapshot_ctx->writer, out_status_cache, bank_slot_deltas_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Failed to create the status cache file" ));
  }
  err = fd_tar_writer_fini_file( snapshot_ctx->writer );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Failed to create the status cache file" ));
  }

  /* Registers all roots and unconstipates the status cache. */

  fd_txncache_flush_constipated_slots( snapshot_ctx->status_cache );

}

static inline void
fd_snapshot_create_write_manifest_and_acc_vecs( fd_snapshot_ctx_t * snapshot_ctx,
                                                fd_hash_t *         out_hash,
                                                ulong *             out_capitalization ) {


  fd_solana_manifest_t manifest = {0};

  /* Copy in all the fields of the bank. */

  fd_snapshot_create_populate_bank( snapshot_ctx, &manifest.bank );

  /* Populate the rest of the manifest, except for the append vec index. */

  manifest.lamports_per_signature                = snapshot_ctx->slot_bank.lamports_per_signature;
  manifest.epoch_account_hash                    = &snapshot_ctx->slot_bank.epoch_account_hash;

  /* FIXME: The versioned epoch stakes needs to be implemented. Right now if
     we try to create a snapshot on or near an epoch boundary, we will produce
     an invalid snapshot. */

  manifest.versioned_epoch_stakes_len            = 0UL;
  manifest.versioned_epoch_stakes                = NULL;

  /* Populate the append vec index and write out the corresponding acc files. */

  ulong incr_capitalization = 0UL;
  fd_snapshot_create_populate_acc_vecs( snapshot_ctx, &manifest, snapshot_ctx->writer, &incr_capitalization );

  /* Once the append vec index is populated and the hashes are calculated,
     propogate the hashes to the correct fields. As a note, the last_snap_hash
     is the full snapshot's account hash. */

  if( snapshot_ctx->is_incremental ) {
    manifest.bank_incremental_snapshot_persistence->full_slot                  = snapshot_ctx->last_snap_slot;
    manifest.bank_incremental_snapshot_persistence->full_hash                  = *snapshot_ctx->last_snap_acc_hash;
    manifest.bank_incremental_snapshot_persistence->full_capitalization        = snapshot_ctx->last_snap_capitalization;
    manifest.bank_incremental_snapshot_persistence->incremental_hash           = snapshot_ctx->acc_hash;
    manifest.bank_incremental_snapshot_persistence->incremental_capitalization = incr_capitalization;
  } else {
    *out_hash           = manifest.accounts_db.bank_hash_info.accounts_hash;
    *out_capitalization = snapshot_ctx->slot_bank.capitalization;
  }

  /* At this point, all of the account files are written out and the append
     vec index is populated in the manifest. We have already reserved space
     in the archive for the manifest. All we need to do now is encode the
     manifest and write it in. */

  ulong   manifest_sz  = fd_solana_manifest_size( &manifest );
  uchar * out_manifest = fd_spad_alloc( snapshot_ctx->spad, fd_solana_manifest_align(), manifest_sz );

  fd_bincode_encode_ctx_t encode = {
    .data    = out_manifest,
    .dataend = out_manifest + manifest_sz
  };

  int err = fd_solana_manifest_encode( &manifest, &encode );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Failed to encode the manifest" ));
  }

  err = fd_tar_writer_fill_space( snapshot_ctx->writer, out_manifest, manifest_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Failed to write out the manifest" ));
  }

  void * mem = fd_tar_writer_delete( snapshot_ctx->writer );
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_ERR(( "Unable to delete the tar writer" ));
  }

}

static inline void
fd_snapshot_create_compress( fd_snapshot_ctx_t * snapshot_ctx ) {

  /* Compress the file using zstd. First open the non-compressed file and
     create a file for the compressed file. The reason why we can't do this
     as we stream out the snapshot archive is that we write back into the
     manifest buffer.

     TODO: A way to eliminate this and to just stream out
     1 compressed file would be to totally precompute the index such that
     we don't have to write back into funk.

     TODO: Currently, the snapshot service interfaces directly with the zstd
     library but a generalized cstream defined in fd_zstd should be used
     instead. */

  ulong in_buf_sz   = ZSTD_CStreamInSize();
  ulong zstd_buf_sz = ZSTD_CStreamOutSize();
  ulong out_buf_sz  = ZSTD_CStreamOutSize();

  char * in_buf   = fd_spad_alloc( snapshot_ctx->spad, FD_ZSTD_CSTREAM_ALIGN, in_buf_sz );
  char * zstd_buf = fd_spad_alloc( snapshot_ctx->spad, FD_ZSTD_CSTREAM_ALIGN, out_buf_sz );
  char * out_buf  = fd_spad_alloc( snapshot_ctx->spad, FD_ZSTD_CSTREAM_ALIGN, out_buf_sz );

  /* Reopen the tarball and open/overwrite the filename for the compressed,
     finalized full snapshot. Setup the zstd compression stream. */

  int err = 0;

  ZSTD_CStream * cstream = ZSTD_createCStream();
  if( FD_UNLIKELY( !cstream ) ) {
    FD_LOG_ERR(( "Failed to create the zstd compression stream" ));
  }
  ZSTD_initCStream( cstream, ZSTD_CLEVEL_DEFAULT );

  fd_io_buffered_ostream_t ostream[1];

  if( FD_UNLIKELY( !fd_io_buffered_ostream_init( ostream, snapshot_ctx->snapshot_fd, out_buf, out_buf_sz ) ) ) {
    FD_LOG_ERR(( "Failed to initialize the ostream" ));
  }

  long seek = lseek( snapshot_ctx->snapshot_fd, 0, SEEK_SET );
  if( FD_UNLIKELY( seek!=0L ) ) {
    FD_LOG_ERR(( "Failed to seek to the start of the file" ));
  }

  /* At this point, the tar archive and the new zstd file is open. The zstd
     streamer is still open. Now, we are ready to read in bytes and stream
     compress them. We will keep going until we see an EOF in a tar archive. */

  ulong in_sz = in_buf_sz;

  ulong off = (ulong)lseek( snapshot_ctx->tmp_fd, 0, SEEK_SET );
  if( FD_UNLIKELY( off ) ) {
    FD_LOG_ERR(( "Failed to seek to the beginning of the file" ));
  }

  while( in_sz==in_buf_sz ) {

    /* Read chunks from the file. There isn't really a need to use a streamed
       reader here because we will read in the max size buffer for every single
       file read except for the very last one.

       in_sz will only not equal in_buf_sz on the last read. */
    err = fd_io_read( snapshot_ctx->tmp_fd, in_buf, 0UL, in_buf_sz, &in_sz );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "Failed to read in the file" ));
    }

    /* Compress the in memory buffer and add it to the output stream. */

    ZSTD_inBuffer input = { in_buf, in_sz, 0UL };
    while( input.pos<input.size ) {
      ZSTD_outBuffer output = { zstd_buf, zstd_buf_sz, 0UL };
      ulong          ret    = ZSTD_compressStream( cstream, &output, &input );

      if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
        FD_LOG_ERR(( "Compression error: %s\n", ZSTD_getErrorName( ret ) ));
      }

      err = fd_io_buffered_ostream_write( ostream, zstd_buf, output.pos );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_ERR(( "Failed to write out the compressed file" ));
      }
    }
  }

  /* Now flush any bytes left in the zstd buffer, cleanup open file
     descriptors, and deinit any data structures.  */

  ZSTD_outBuffer output    = { zstd_buf, zstd_buf_sz, 0UL };
  ulong          remaining = ZSTD_endStream(  cstream, &output );

  if( FD_UNLIKELY( ZSTD_isError( remaining ) ) ) {
    FD_LOG_ERR(( "Unable to end the zstd stream" ));
  }
  if( output.pos>0UL ) {
    fd_io_buffered_ostream_write( ostream, zstd_buf, output.pos );
  }

  ZSTD_freeCStream( cstream ); /* Works even if cstream is null */
  err = fd_io_buffered_ostream_flush( ostream );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Failed to flush the ostream" ));
  }

  /* Assuming that there was a successful write, make the compressed
     snapshot file readable and servable. */

  char tmp_directory_buf_zstd[ FD_SNAPSHOT_DIR_MAX ];
  err = snprintf( tmp_directory_buf_zstd, FD_SNAPSHOT_DIR_MAX, "%s/%s", snapshot_ctx->out_dir, snapshot_ctx->is_incremental ? FD_SNAPSHOT_TMP_INCR_ARCHIVE_ZSTD : FD_SNAPSHOT_TMP_FULL_ARCHIVE_ZSTD );
  if( FD_UNLIKELY( err<0 ) ) {
    FD_LOG_ERR(( "Failed to format directory string" ));
  }

  char directory_buf_zstd[ FD_SNAPSHOT_DIR_MAX ];
  if( !snapshot_ctx->is_incremental ) {
    err = snprintf( directory_buf_zstd, FD_SNAPSHOT_DIR_MAX, "%s/snapshot-%lu-%s.tar.zst",
                    snapshot_ctx->out_dir, snapshot_ctx->slot, FD_BASE58_ENC_32_ALLOCA(&snapshot_ctx->snap_hash) );
  } else {
    err = snprintf( directory_buf_zstd, FD_SNAPSHOT_DIR_MAX, "%s/incremental-snapshot-%lu-%lu-%s.tar.zst",
                    snapshot_ctx->out_dir, snapshot_ctx->last_snap_slot, snapshot_ctx->slot, FD_BASE58_ENC_32_ALLOCA(&snapshot_ctx->snap_hash) );
  }

  if( FD_UNLIKELY( err<0 ) ) {
    FD_LOG_ERR(( "Failed to format directory string" ));
  }

  err = rename( tmp_directory_buf_zstd, directory_buf_zstd );
  if( FD_UNLIKELY( err<0 ) ) {
    FD_LOG_ERR(( "Failed to rename file from %s to %s (%i-%s)", tmp_directory_buf_zstd, directory_buf_zstd, errno, fd_io_strerror( errno ) ));
  }

}

void
fd_snapshot_create_new_snapshot( fd_snapshot_ctx_t * snapshot_ctx,
                                 fd_hash_t *         out_hash,
                                 ulong *             out_capitalization ) {

  FD_LOG_NOTICE(( "Starting to produce a snapshot for slot=%lu in directory=%s", snapshot_ctx->slot, snapshot_ctx->out_dir ));

  /* Validate that the snapshot_ctx is setup correctly. */

  fd_snapshot_create_setup_and_validate_ctx( snapshot_ctx );

  /* Setup the tar archive writer. */

  fd_snapshot_create_setup_writer( snapshot_ctx );

  /* Write out the version file. */

  fd_snapshot_create_write_version( snapshot_ctx );

  /* Dump the status cache and append it to the tar archive. */

  fd_snapshot_create_write_status_cache( snapshot_ctx );

  /* Populate and write out the manifest and append vecs. */

  fd_snapshot_create_write_manifest_and_acc_vecs( snapshot_ctx, out_hash, out_capitalization );

  /* Compress the tar file and write it out to the specified directory. */

  fd_snapshot_create_compress( snapshot_ctx );

  FD_LOG_NOTICE(( "Finished producing a snapshot" ));

}
