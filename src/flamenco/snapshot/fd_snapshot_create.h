#ifndef HEADER_fd_src_flamenco_snapshot_fd_snapshot_create_h
#define HEADER_fd_src_flamenco_snapshot_fd_snapshot_create_h

/* fd_snapshot_create.h provides APIs for creating a Labs-compatible
   snapshot from a slot execution context. */

#include "../fd_flamenco_base.h"
#include "../runtime/context/fd_exec_slot_ctx.h"
#include "../runtime/context/fd_exec_epoch_ctx.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>

struct fd_key_build {
  ulong key;
  ulong count;
  ulong next;
};
typedef struct fd_key_build fd_key_build_t;

  /* clang-format off */
  #define MAP_NAME         fd_key_build
  #define MAP_T            fd_key_build_t
  #define MAP_KEY          key
  #include "../../util/tmpl/fd_map_giant.c"
  /* clang-format on */

struct fd_snapshot_create_private;
typedef struct fd_snapshot_create_private fd_snapshot_create_t;

FD_PROTOTYPES_BEGIN

/* fd_snapshot_create_{align,footprint} return required memory region
   parameters for the fd_snapshot_create_t object.

   worker_cnt is the number of workers for parallel snapshot create
   (treated as 1UL parallel mode not available). compress_lvl is the
   Zstandard compression level.  compress_bufsz is the in-memory buffer
   for writes (larger buffers results in less frequent but larger write
   ops).  funk_rec_cnt is the number of slots in the funk rec hashmap.
   batch_acc_cnt is the max number of accounts per account vec.

   Resulting footprint approximates

     O( funk_rec_cnt + (worker_cnt * (compress_lvl + compress_bufsz + batch_acc_cnt)) ) */

FD_FN_CONST ulong
fd_snapshot_create_align( void );

ulong
fd_snapshot_create_footprint( ulong worker_cnt,
                              int   compress_lvl,
                              ulong compress_bufsz,
                              ulong funk_rec_cnt,
                              ulong batch_acc_cnt );

/* fd_snapshot_create_new creates a new snapshot create object in the
   given mem region, which adheres to above alignment/footprint
   requirements.  Returns qualified handle to object given create object
   on success.  Serializes data from given slot context.  snap_path is
   the final snapshot path.  May create temporary files adject to
   snap_path.  {worker_cnt,compress_lvl,compress_bufsz,funk_rec_cnt,
   batch_acc_cnt} must match arguments to footprint when mem was
   created.  On failure, returns NULL. Reasons for failure include
   invalid memory region or invalid file descriptor.  Logs reasons for
   failure. */

fd_snapshot_create_t *
fd_snapshot_create_new( void *               mem,
                        fd_exec_slot_ctx_t * slot_ctx,
                        const char *         snap_path,
                        ulong                worker_cnt,
                        int                  compress_lvl,
                        ulong                compress_bufsz,
                        ulong                funk_rec_cnt,
                        ulong                batch_acc_cnt,
                        ulong                max_accv_sz,
                        fd_rng_t *           rng );

/* fd_snapshot_create_delete destroys the given snapshot create object
   and frees any resources.  Returns memory region and fd back to caller. */

void *
fd_snapshot_create_delete( fd_snapshot_create_t * create );

/* fd_snapshot_create exports the 'snapshot manifest' and a copy of all
   accounts from the slot ctx that the create object is attached to.
   Writes a .tar.zst stream out to the fd.  Returns 1 on success, and
   0 on failure.  Reason for failure is logged. */

int
fd_snapshot_create( fd_snapshot_create_t * create, 
                    fd_exec_slot_ctx_t *   slot_ctx );


static void
fd_snapshot_create_serialiable_stakes( fd_exec_slot_ctx_t       * slot_ctx,
                                       fd_stakes_t              * old_stakes,
                                       fd_stakes_serializable_t * new_stakes ) {

  /* First populate the vote accounts using the vote accounts/stakes cache. 
     We can populate over all of the fields except we can't reserialize the
     vote account data. Instead we will copy over the raw contents of all of
     the vote accounts. */

  ulong vote_accounts_len = fd_vote_accounts_pair_t_map_size( old_stakes->vote_accounts.vote_accounts_pool, old_stakes->vote_accounts.vote_accounts_root );
  new_stakes->vote_accounts.vote_accounts_pool = fd_vote_accounts_pair_serializable_t_map_alloc( slot_ctx->valloc, fd_ulong_max(vote_accounts_len, 15000 ) );
  new_stakes->vote_accounts.vote_accounts_root = NULL;

  for( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum(
        old_stakes->vote_accounts.vote_accounts_pool,
        old_stakes->vote_accounts.vote_accounts_root );
       n;
       n = fd_vote_accounts_pair_t_map_successor( old_stakes->vote_accounts.vote_accounts_pool, n ) ) {
    
    fd_vote_accounts_pair_serializable_t_mapnode_t * new_node = fd_vote_accounts_pair_serializable_t_map_acquire( new_stakes->vote_accounts.vote_accounts_pool );
    new_node->elem.key   = n->elem.key;
    fd_memcpy( &new_node->elem.key, &n->elem.key, sizeof(fd_pubkey_t) );
    new_node->elem.stake = n->elem.stake;
    /* Now to populate the value, lookup the account using the acc mgr */
    FD_BORROWED_ACCOUNT_DECL( vote_acc );
    int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, &n->elem.key, vote_acc );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "Failed to view vote account %s", FD_BASE58_ENC_32_ALLOCA(&n->elem.key) ));
    }
    new_node->elem.value.lamports   = vote_acc->const_meta->info.lamports;
    new_node->elem.value.data_len   = vote_acc->const_meta->dlen;
    new_node->elem.value.data       = fd_scratch_alloc( 16UL, vote_acc->const_meta->dlen );
    fd_memcpy( new_node->elem.value.data, vote_acc->const_data, vote_acc->const_meta->dlen );
    fd_memcpy( &new_node->elem.value.owner, &vote_acc->const_meta->info.owner, sizeof(fd_pubkey_t) );
    new_node->elem.value.executable = vote_acc->const_meta->info.executable;
    new_node->elem.value.rent_epoch = vote_acc->const_meta->info.rent_epoch;
    fd_vote_accounts_pair_serializable_t_map_insert( new_stakes->vote_accounts.vote_accounts_pool, &new_stakes->vote_accounts.vote_accounts_root, new_node );

  }

  /* Copy over the rest of the fields as they are the same. */
  new_stakes->stake_delegations_pool = old_stakes->stake_delegations_pool;
  new_stakes->stake_delegations_root = old_stakes->stake_delegations_root;
  new_stakes->unused                 = old_stakes->unused;
  new_stakes->epoch                  = old_stakes->epoch;
  new_stakes->stake_history          = old_stakes->stake_history;
}

int
fd_snapshot_create_populate_acc_vec_idx( fd_exec_slot_ctx_t *                FD_FN_UNUSED slot_ctx,
                                         fd_solana_manifest_serializable_t * FD_FN_UNUSED manifest ) {

  ulong rec_cnt = fd_funk_rec_global_cnt( slot_ctx->acc_mgr->funk, fd_funk_wksp( slot_ctx->acc_mgr->funk) );
  void * mem = fd_valloc_malloc( slot_ctx->valloc, fd_key_build_align(), fd_key_build_footprint( rec_cnt ) );
  fd_key_build_t * key_build = fd_key_build_join( fd_key_build_new( mem, rec_cnt, 0UL) );

  ulong num_accs = 0UL;
  for (fd_funk_rec_t const *rec = fd_funk_txn_first_rec( slot_ctx->acc_mgr->funk, NULL );
       NULL != rec;
       rec = fd_funk_txn_next_rec( slot_ctx->acc_mgr->funk, rec )) {
    if( !fd_funk_key_is_acc( rec->pair.key ) ) {
      continue;
    }

    fd_pubkey_t const * pubkey = fd_type_pun_const( rec->pair.key[0].uc );
    num_accs++;

    FD_BORROWED_ACCOUNT_DECL( acc );
    if( fd_acc_mgr_view( slot_ctx->acc_mgr, NULL, pubkey, acc ) != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_ERR(( "Can't find record" ));
    }

    ulong record_slot = acc->const_meta->slot;
    fd_key_build_insert( key_build, const ulong *key)
  }
  FD_LOG_ERR(("NUM ACCOUNTS %lu", num_accs));




  // fd_solana_accounts_db_fields_t * fields = &manifest->accounts_db;

  // char * dir_buf = fd_scratch_alloc( 8UL, 256UL );
  // fd_memset( dir_buf, '\0', 256UL );
  // dir_buf = "/data/ibhatt/dump/mainnet-254462437/extracted_snapshot/accounts/";
  // ulong dir_len = strlen( dir_buf );
  
  // char * filename_buffer = fd_scratch_alloc( 8UL, 256UL );
  // fd_memset( filename_buffer, '\0', 256UL );
  // fd_memcpy( filename_buffer, dir_buf, dir_len );

  // char * oldname = fd_scratch_alloc( 8UL, 256UL );
  // fd_memset( oldname, '\0', 256UL );
  // fd_memcpy( oldname, dir_buf, dir_len );

  // ulong id = 1000000000UL;
  // for( ulong i=0UL; i<fields->storages_len; i++ ) {
  //   fd_snapshot_slot_acc_vecs_t * storage = &fields->storages[i];
  //   //FD_LOG_NOTICE(("SLOT %lu ENTRIES %lu", storage->slot, storage->account_vecs_len));
  //   for( ulong j=0UL; j<storage->account_vecs_len; j++ ) {
  //     fd_snapshot_acc_vec_t * acc_vec = &storage->account_vecs[j];
  //     //FD_LOG_NOTICE(("acc vec %lu %lu", acc_vec->file_sz, acc_vec->id));

  //     sprintf( filename_buffer+dir_len, "%lu.%lu", storage->slot, id );
  //     sprintf( oldname+dir_len, "%lu.%lu", storage->slot, acc_vec->id );

  //     acc_vec->id = id;
  //     id++;
  //     // FD_LOG_WARNING(("OLD FILENAME %s", oldname));
  //     // FD_LOG_WARNING(("NEW FILENAME %s", filename_buffer));
  //     struct stat buffer;
  //     if( !stat( oldname, &buffer ) ) {
  //       //rename( oldname, filename_buffer );
  //     }
  //     else {
  //       FD_LOG_WARNING(("CANT RENAME FILE %s %s", oldname, filename_buffer));
  //     }      
  //   }
  // }
  // FD_LOG_WARNING(("PROCESSED %lu FILES", id));

  // return 0;

  // #undef FD_DT_REG
}

int FD_FN_UNUSED
fd_snapshot_create_manifest( fd_exec_slot_ctx_t * slot_ctx ) {

  // /****************** HACK TO GET THE ACC DB FROM THE NEWEST ***************/

  // FILE * ahead_manifest = fopen("/data/ibhatt/dump/mainnet-254462437/254462442", "rb");
  // FD_TEST(ahead_manifest);
  // fseek( ahead_manifest, 0, SEEK_END );
  // ulong file_sz = (ulong)ftell( ahead_manifest );
  // // rewind( ahead_manifest );
  // // uchar * buffer = fd_scratch_alloc( 8UL, file_sz );
  // // ulong fread_res = fread( buffer, 1, file_sz, ahead_manifest );
  // // FD_TEST(fread_res == file_sz);

  // // fclose( ahead_manifest );


  // fd_bincode_decode_ctx_t decode_ctx = {
  //   .data = buffer,
  //   .dataend = buffer + file_sz,
  //   .valloc = slot_ctx->valloc,
  // };
  // fd_solana_manifest_t newest_manifest = {0};
  // int decode_res = fd_solana_manifest_decode( &newest_manifest, &decode_ctx );
  // FD_TEST(!decode_res);


  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );

  /* Populate the fields of the new manifest */
  fd_solana_manifest_serializable_t new_manifest = {0};
  //fd_solana_manifest_t              new_manifest = {0};
  fd_solana_manifest_t            * old_manifest = slot_ctx->solana_manifest;
  
  /* Copy in all the fields of the bank */

  /* The blockhash queue can be populated */
  fd_block_hash_vec_t blockhash_queue = {0};
  blockhash_queue.last_hash_index = slot_ctx->slot_bank.block_hash_queue.last_hash_index;
  blockhash_queue.last_hash = fd_scratch_alloc( 1UL, FD_HASH_FOOTPRINT );
  fd_memcpy( blockhash_queue.last_hash ,slot_ctx->slot_bank.block_hash_queue.last_hash, sizeof(fd_hash_t) );
  blockhash_queue.ages_len = fd_hash_hash_age_pair_t_map_size( slot_ctx->slot_bank.block_hash_queue.ages_pool, slot_ctx->slot_bank.block_hash_queue.ages_root);

  blockhash_queue.ages = fd_scratch_alloc( 1UL, blockhash_queue.ages_len * sizeof(fd_hash_hash_age_pair_t) );
  fd_block_hash_queue_t * queue = &slot_ctx->slot_bank.block_hash_queue;
  fd_hash_hash_age_pair_t_mapnode_t * nn;
  ulong blockhash_queue_idx = 0UL;
  for( fd_hash_hash_age_pair_t_mapnode_t * n = fd_hash_hash_age_pair_t_map_minimum( queue->ages_pool, queue->ages_root ); n; n = nn ) {
    nn = fd_hash_hash_age_pair_t_map_successor( queue->ages_pool, n );
    fd_hash_hash_age_pair_t elem = n->elem;
    fd_memcpy( &blockhash_queue.ages[ blockhash_queue_idx++ ], &elem, sizeof(fd_hash_hash_age_pair_t) );
  }

  blockhash_queue.max_age = 300UL; /* TODO: define this as a constant */
  new_manifest.bank.blockhash_queue       = blockhash_queue /* DONE! */;

  /* Ancestor can be omitted to boot off of for both clients */
  new_manifest.bank.ancestors_len         = 0UL; /* DONE!*/
  new_manifest.bank.ancestors             = NULL; /* DONE! */
  
  // new_manifest.bank.ancestors_len         = old_manifest->bank.ancestors_len;
  // new_manifest.bank.ancestors             = old_manifest->bank.ancestors;

  fd_pubkey_t pubkey_empty = {0};
  fd_unused_accounts_t unused_accounts = {0};

  // FD_LOG_WARNING(("FIREDANCER slot, epoch %lu %lu", slot_ctx->slot_bank.slot, fd_slot_to_epoch( &epoch_bank->epoch_schedule, slot_ctx->slot_bank.slot, NULL)));
  // FD_LOG_WARNING(("AGAVE slot, epoch %lu %lu", old_manifest->bank.slot, old_manifest->bank.epoch));
  // FD_LOG_WARNING(("BLOCK HEIGHT %lu %lu", slot_ctx->slot_bank.block_height, old_manifest->bank.block_height));
  // FD_LOG_WARNING(("ACCOUNTS DATA LEN %lu", old_manifest->bank.accounts_data_len));
  // FD_LOG_WARNING(("PREVIOUS SLOT %lu %lu", slot_ctx->slot_bank.prev_slot, old_manifest->bank.parent_slot));
  // FD_LOG_WARNING(("signature count %lu %lu %lu", slot_ctx->signature_cnt, slot_ctx->parent_signature_cnt, old_manifest->bank.signature_count));

  /* TODO:FIXME: Will likely need to adjust how we calculate the slot and prev slot. Maybe
     we have to get forks into play? We currently generate the snapshot before the start of
     a new slot. I think that this is mostly okay for now. See parent_signature_cnt too */

  FD_LOG_WARNING(("TICKS PER SLOT %lu %lu", epoch_bank->ticks_per_slot, old_manifest->bank.ticks_per_slot));
  FD_LOG_WARNING(("MAX BANK TICK HEIGHT %lu %lu", slot_ctx->slot_bank.max_tick_height, old_manifest->bank.max_tick_height));
  FD_LOG_WARNING(("MAX BANK TICK HEIGHT %lu %lu", slot_ctx->slot_bank.max_tick_height, old_manifest->bank.max_tick_height));
  FD_LOG_WARNING(("TICK HEIGHT %lu", old_manifest->bank.tick_height));
  FD_LOG_WARNING(("TICK HEIGHT %lu", old_manifest->bank.max_tick_height));

  new_manifest.bank.hash                  = slot_ctx->slot_bank.banks_hash; /* DONE! */
  new_manifest.bank.parent_hash           = slot_ctx->prev_banks_hash; /* DONE! */

  new_manifest.bank.parent_slot           = slot_ctx->slot_bank.prev_slot - 1UL; /* DONE! Need to subtract 1 here because of how agave does accounting. */

  new_manifest.bank.hard_forks.hard_forks     = NULL; /* DONE! */
  new_manifest.bank.hard_forks.hard_forks_len = 0UL;

  new_manifest.bank.transaction_count     = slot_ctx->slot_bank.transaction_count; /* DONE! */
  new_manifest.bank.tick_height           = slot_ctx->tick_height; /* DONE! */
  new_manifest.bank.signature_count       = slot_ctx->parent_signature_cnt; /* DONE! */

  new_manifest.bank.capitalization        = slot_ctx->slot_bank.capitalization; /* DONE! */

  new_manifest.bank.max_tick_height       = slot_ctx->tick_height; /* DONE! */

  new_manifest.bank.hashes_per_tick       = &epoch_bank->hashes_per_tick; /* DONE */

  new_manifest.bank.ticks_per_slot        = old_manifest->bank.ticks_per_slot;

  new_manifest.bank.ns_per_slot           = epoch_bank->ns_per_slot; /* DONE! */

  new_manifest.bank.genesis_creation_time = epoch_bank->genesis_creation_time; /* DONE! */

  new_manifest.bank.slots_per_year        = epoch_bank->slots_per_year; /* DONE! */

  new_manifest.bank.accounts_data_len     = 0UL; /* DONE! Agave recomputes this value from the accounts db that is loaded in anyway  */

  new_manifest.bank.slot                  = slot_ctx->slot_bank.slot - 1UL; /* DONE! Need to subtract 1 here because of how agave does accounting */

  new_manifest.bank.epoch                 = fd_slot_to_epoch( &epoch_bank->epoch_schedule, 
                                                              new_manifest.bank.slot,
                                                              NULL ); /* DONE! */

  new_manifest.bank.block_height          = slot_ctx->slot_bank.block_height; /* DONE! */

  new_manifest.bank.collector_id          = pubkey_empty; /* DONE! Can be omitted for both clients */

  new_manifest.bank.collector_fees        = slot_ctx->slot_bank.collected_execution_fees + 
                                            slot_ctx->slot_bank.collected_priority_fees; /* DONE! */

  new_manifest.bank.fee_calculator.lamports_per_signature = slot_ctx->slot_bank.lamports_per_signature; /* DONE! */

  new_manifest.bank.fee_rate_governor     = slot_ctx->slot_bank.fee_rate_governor; /* DONE! */
  new_manifest.bank.collected_rent        = slot_ctx->slot_bank.collected_rent; /* DONE! */

  /* TODO: This needs to get tested on testnet/devnet where rent is real */
  new_manifest.bank.rent_collector.epoch          = new_manifest.bank.epoch; /* DONE! */
  new_manifest.bank.rent_collector.epoch_schedule = epoch_bank->rent_epoch_schedule;
  new_manifest.bank.rent_collector.slots_per_year = epoch_bank->slots_per_year;
  new_manifest.bank.rent_collector.rent           = epoch_bank->rent;

  new_manifest.bank.epoch_schedule        = epoch_bank->epoch_schedule; /* DONE! */

  new_manifest.bank.inflation             = epoch_bank->inflation; /* DONE! */

  new_manifest.bank.unused_accounts       = unused_accounts; /* DONE! */

  FD_LOG_WARNING(("UNVERSIONED EPOCH STAKES %lu", old_manifest->bank.epoch_stakes_len));
  FD_LOG_WARNING(("new_manifest ticks %lu %lu", new_manifest.bank.tick_height, new_manifest.bank.max_tick_height));
  /* DONE! */
  /* We need to copy over the stakes for two epochs*/
  fd_epoch_epoch_stakes_pair_t relevant_epoch_stakes[2];
  fd_memset( &relevant_epoch_stakes[0], 0UL, sizeof(fd_epoch_epoch_stakes_pair_t) );
  relevant_epoch_stakes[0].key                        = new_manifest.bank.epoch;
  relevant_epoch_stakes[0].value.stakes.vote_accounts = slot_ctx->slot_bank.epoch_stakes;

  fd_memset( &relevant_epoch_stakes[1], 0UL, sizeof(fd_epoch_epoch_stakes_pair_t) );
  relevant_epoch_stakes[1].key                        = new_manifest.bank.epoch+1UL;
  relevant_epoch_stakes[1].value.stakes.vote_accounts = epoch_bank->next_epoch_stakes;

  new_manifest.bank.epoch_stakes_len                  = 2UL;
  new_manifest.bank.epoch_stakes                      = relevant_epoch_stakes;

  new_manifest.bank.is_delta                          = 0; /* DONE! */

  /* Deserialized stakes cache is NOT equivalent to the one that we need to
     serialize because of the way vote accounts are stored */
  fd_snapshot_create_serialiable_stakes( slot_ctx, &epoch_bank->stakes, &new_manifest.bank.stakes ); /* DONE! */

  /* AT THIS POINT THE BANK IS DONE *******************************************/
  /* Assign the other fields of the manifest to the serializable manifest */
  new_manifest.accounts_db                           = old_manifest->accounts_db; // newest_manifest.accounts_db;

  new_manifest.lamports_per_signature                = slot_ctx->slot_bank.lamports_per_signature; /* DONE! */

  new_manifest.bank_incremental_snapshot_persistence = NULL;
  new_manifest.epoch_account_hash                    = &slot_ctx->slot_bank.epoch_account_hash; /* DONE! */

  /* TODO: This needs to be properly populated instead of the epoch stakes in
     the bank when 2.1 gets activated on testnet. DONE! */
  new_manifest.versioned_epoch_stakes_len            = 0UL;
  new_manifest.versioned_epoch_stakes                = NULL;

  fd_snapshot_create_populate_acc_vec_idx( slot_ctx, &new_manifest );

  FD_LOG_WARNING(("ACCOUNTS DB HEADER %lu %lu %lu", new_manifest.accounts_db.storages_len, new_manifest.accounts_db.version, new_manifest.accounts_db.slot));

  // /* Encode and output the manifest to a file */
  ulong old_manifest_sz = fd_solana_manifest_size( old_manifest );
  ulong new_manifest_sz = fd_solana_manifest_serializable_size( &new_manifest ); 
  FD_LOG_WARNING(("OLD MANIFEST SIZE %lu", old_manifest_sz));
  FD_LOG_WARNING(("NEW MANIFEST SIZE %lu", new_manifest_sz));
  uchar * out_manifest = fd_scratch_alloc( 1UL, new_manifest_sz );
  fd_bincode_encode_ctx_t encode =
    { .data    = out_manifest,
      .dataend = out_manifest + new_manifest_sz + 1 };
  FD_TEST( 0==fd_solana_manifest_serializable_encode( &new_manifest, &encode ) );

  FILE * file = fopen( "/data/ibhatt/manifest", "wb" );
  ulong  bytes_written= fwrite( out_manifest, 1, new_manifest_sz, file );
  if( bytes_written != new_manifest_sz ) {
    FD_LOG_ERR(("FAILED TO WRITE OUT"));
  }
  fclose(file);

  return 0;
}

int FD_FN_UNUSED
fd_snapshot_create_status_cache( void ) {
  return 0;
}

int FD_FN_UNUSED
fd_snapshot_create_acc_vecs( void ) {
  /* This should reference funk as well as the index and populate the actual
     append vecs */

  return 0;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_snapshot_fd_snapshot_create_h */
