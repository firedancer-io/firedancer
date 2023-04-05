#include "fd_runtime.h"
#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar.h"
#include "../base58/fd_base58.h"

#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize ("O0")
#endif

// boot the global state at slot zero...
//
// We have an issue with a lot of the sysvars when we do not start at
// state zero or bounce around.  For example, if you bounce block_execute around,
// recent_hashes will make zero sense...

void
fd_runtime_boot_slot_zero( fd_global_ctx_t *global ) {
  fd_memcpy(global->poh.state, global->genesis_hash, sizeof(global->genesis_hash));
  global->poh_booted = 1;

  fd_sysvar_recent_hashes_init(global );
  fd_sysvar_clock_init( global );
  fd_sysvar_slot_history_init( global );
  fd_sysvar_slot_hashes_init( global );
  fd_sysvar_epoch_schedule_init( global );
  fd_sysvar_fees_init( global );
  fd_sysvar_rent_init( global );
  fd_sysvar_stake_history_init( global );

  fd_builtin_programs_init( global );
}

// fd_runtime_block_execute
//
// If you bounce around slots, the poh state
// will not match AND the sysvars will be set incorrectly.  Since the
// verify WILL also fail, the runtime will detect incorrect usage..

// TODO: add tracking account_state hashes so that we can verify our
// banks hash... this has interesting threading implications since we
// could execute the cryptography in another thread for tracking this
// but we don't actually have anything to compare it to until we hit
// another snapshot...  Probably we should just store the results into
// the global state (a slot/hash map)?
//
// What slots exactly do cache'd account_updates go into?  how are
// they hashed (which slot?)?

int
fd_runtime_block_execute( fd_global_ctx_t *global, fd_slot_blocks_t *slot_data ) {
  uchar *blob = slot_data->last_blob;

  if (NULL == blob)  // empty slot
    return FD_RUNTIME_EXECUTE_SUCCESS;

  uchar *blob_ptr = blob + FD_BLOB_DATA_START;
  uint   cnt = *((uint *) (blob + 8));

  if (0 == cnt)  {
    // can you have an empty last tick?
    return FD_RUNTIME_EXECUTE_SUCCESS;
  }

  // It sucks that we need to know the current block hash which is
  // stored at the END of the block.  Lets have a fever dream another
  // time and optimize this...
  while (cnt > 0) {
    fd_microblock_t * micro_block = fd_microblock_join( blob_ptr );

    blob_ptr = (uchar *) fd_ulong_align_up((ulong)blob_ptr + fd_microblock_footprint( micro_block->hdr.txn_cnt ), FD_MICROBLOCK_ALIGN);

    if (1 == cnt)
      fd_memcpy(global->block_hash, micro_block->hdr.hash, sizeof(micro_block->hdr.hash));
    fd_microblock_leave(micro_block);

    cnt--;
  } // while (cnt > 0)

  // TODO: move all these out to a fd_sysvar_update() call...
  fd_sysvar_clock_update( global);
  fd_sysvar_recent_hashes_update ( global, global->current_slot);

  blob = slot_data->first_blob;
  while (NULL != blob) {
    uchar *blob_ptr = blob + FD_BLOB_DATA_START;
    uint   cnt = *((uint *) (blob + 8));
    while (cnt > 0) {
      fd_microblock_t * micro_block = fd_microblock_join( blob_ptr );
      for ( ulong txn_idx = 0; txn_idx < micro_block->txn_max_cnt; txn_idx++ ) {
        fd_txn_t*      txn_descriptor = (fd_txn_t *)&micro_block->txn_tbl[ txn_idx ];
        fd_rawtxn_b_t* txn_raw   = (fd_rawtxn_b_t *)&micro_block->raw_tbl[ txn_idx ];
        // TODO: fork and commit a new funk_txn for each txn and properly
        // cancel if it fails
        fd_execute_txn( &global->executor, txn_descriptor, txn_raw );
      }
      fd_microblock_leave(micro_block);

      blob_ptr = (uchar *) fd_ulong_align_up((ulong)blob_ptr + fd_microblock_footprint( micro_block->hdr.txn_cnt ), FD_MICROBLOCK_ALIGN);

      cnt--;
    } // while (cnt > 0)
    blob = *((uchar **) blob);
  } // while (NULL != blob)

  fd_sysvar_slot_history_update( global );
  /* TODO: generate this slot's bank hash and call fd_sysvar_slot_hash_update */

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

// TODO: add solana txn verify to this as well since, again, it can be
// done in parallel...
int
fd_runtime_block_verify( fd_global_ctx_t *global, fd_slot_blocks_t *slot_data ) {
  if (NULL == slot_data) {
    FD_LOG_WARNING(("NULL slot passed to fd_runtime_block_execute at slot %ld", global->current_slot));
    return FD_RUNTIME_EXECUTE_GENERIC_ERR;
  }

  uchar *blob = slot_data->first_blob;

  while (NULL != blob) {
    uchar *blob_ptr = blob + FD_BLOB_DATA_START;
    uint   cnt = *((uint *) (blob + 8));
    while (cnt > 0) {
      fd_microblock_t * micro_block = fd_microblock_join( blob_ptr );
      if (micro_block->txn_max_cnt > 0) {
        if (micro_block->hdr.hash_cnt > 0)
          fd_poh_append(&global->poh, micro_block->hdr.hash_cnt - 1);
        uchar outhash[32];
        fd_microblock_mixin(micro_block, outhash);
        fd_poh_mixin(&global->poh, outhash);
      } else
        fd_poh_append(&global->poh, micro_block->hdr.hash_cnt);
      if (memcmp(micro_block->hdr.hash, global->poh.state, sizeof(global->poh.state))) {
        if (global->poh_booted) {
          // TODO should this log and return?  instead of knocking the
          // whole system over via a _ERR?
          FD_LOG_ERR(( "poh missmatch at slot: %ld", global->current_slot));
        } else {
          fd_memcpy(global->poh.state, micro_block->hdr.hash, sizeof(global->poh.state));
          global->poh_booted = 1;
        }
      }
      fd_microblock_leave(micro_block);

      blob_ptr = (uchar *) fd_ulong_align_up((ulong)blob_ptr + fd_microblock_footprint( micro_block->hdr.txn_cnt ), FD_MICROBLOCK_ALIGN);

      cnt--;
    } // while (cnt > 0)
    blob = *((uchar **) blob);
  } // while (NULL != blob)

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int
fd_runtime_block_eval( fd_global_ctx_t *global, fd_slot_blocks_t *slot_data ) {
  if (NULL == slot_data) {
    FD_LOG_WARNING(("NULL slot passed to fd_runtime_block_execute at slot %ld", global->current_slot));
    return FD_RUNTIME_EXECUTE_GENERIC_ERR;
  }
  uchar *blob = slot_data->last_blob;
  if (NULL == blob) {
    FD_LOG_WARNING(("empty slot passed to fd_runtime_block_execute at slot %ld", global->current_slot));
    return FD_RUNTIME_EXECUTE_GENERIC_ERR;
  }

  // this makes my head hurt... need some sleep...
  struct fd_funk_xactionid*  parent_txn = global->funk_txn;
  global->funk_txn_index = (global->funk_txn_index + 1) & 31;
  global->funk_txn = &global->funk_txn_tower[global->funk_txn_index];

  // Reasonable to let the compiler figure this out?
  if ( memcmp(global->funk_txn, fd_funk_root(global->funk), sizeof(fd_funk_xactionid_t) ) )
    if (fd_funk_commit(global->funk, global->funk_txn) == 0)
      FD_LOG_ERR(("fd_funk_commit failed"));

  ulong *p = (ulong *) &global->funk_txn->id[0];
  p[0] = fd_rng_ulong( global->rng );
  p[1] = fd_rng_ulong( global->rng );
  p[2] = fd_rng_ulong( global->rng );
  p[3] = fd_rng_ulong( global->rng );

  if (fd_funk_fork(global->funk, parent_txn, global->funk_txn) == 0)
    FD_LOG_ERR(("fd_funk_fork failed"));

  // This is simple now but really we need to execute block_verify in
  // its own thread/tile and IT needs to parallelize the
  // microblock verifies in that out into worker threads as well.
  //
  // Then, start executing the slot in the main thread, wait for the
  // block_verify to complete, and only return successful when the
  // verify threads complete successfully..

  int ret = fd_runtime_block_verify( global, slot_data );
  if ( FD_RUNTIME_EXECUTE_SUCCESS == ret ) 
    ret = fd_runtime_block_execute( global, slot_data );

  if (FD_RUNTIME_EXECUTE_SUCCESS != ret ) {
    // Not exactly sure what I am supposed to do if execute fails to
    // this point...  is this a "log and fall over?"
    fd_funk_cancel(global->funk, global->funk_txn);
    *global->funk_txn = *fd_funk_root(global->funk);
    global->funk_txn_index = (global->funk_txn_index - 1) & 31;
    global->funk_txn = &global->funk_txn_tower[global->funk_txn_index];
  }

  return ret;
}

void *
fd_global_ctx_new        ( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_GLOBAL_CTX_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_memset(mem, 0, FD_GLOBAL_CTX_FOOTPRINT);

  fd_global_ctx_t * self = (fd_global_ctx_t *) mem;

  self->rng  = fd_rng_join( fd_rng_new(&self->rnd_mem, 0, 0) );

  // Yeah, maybe we should get rid of this?
  fd_executor_new ( &self->executor, self, FD_EXECUTOR_FOOTPRINT );

  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (unsigned char *) self->sysvar_owner);
  fd_base58_decode_32( "SysvarRecentB1ockHashes11111111111111111111",  (unsigned char *) self->sysvar_recent_block_hashes);
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (unsigned char *) self->sysvar_clock);
  fd_base58_decode_32( "SysvarS1otHistory11111111111111111111111111",  (unsigned char *) self->sysvar_slot_history);
  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (unsigned char *) self->sysvar_slot_hashes);
  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (unsigned char *) self->sysvar_epoch_schedule);
  fd_base58_decode_32( "SysvarFees111111111111111111111111111111111",  (unsigned char *) self->sysvar_fees);
  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (unsigned char *) self->sysvar_rent);
  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (unsigned char *) self->sysvar_stake_history);

  fd_base58_decode_32( "NativeLoader1111111111111111111111111111111",  (unsigned char *) self->solana_native_loader);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) self->solana_config_program);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) self->solana_stake_program);
  fd_base58_decode_32( "11111111111111111111111111111111",             (unsigned char *) self->solana_system_program);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) self->solana_vote_program);
  fd_base58_decode_32( "BPFLoader1111111111111111111111111111111111",  (unsigned char *) self->solana_bpf_loader_deprecated_program);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) self->solana_bpf_loader_program_with_jit);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) self->solana_bpf_loader_upgradeable_program_with_jit);
  fd_base58_decode_32( "Ed25519SigVerify111111111111111111111111111",  (unsigned char *) self->solana_ed25519_sig_verify_program);
  fd_base58_decode_32( "KeccakSecp256k11111111111111111111111111111",  (unsigned char *) self->solana_keccak_secp_256k_program);
  fd_base58_decode_32( "ComputeBudget111111111111111111111111111111",  (unsigned char *) self->solana_compute_budget_program);
  fd_base58_decode_32( "ZkTokenProof1111111111111111111111111111111",  (unsigned char *) self->solana_zk_token_proof_program);
  fd_base58_decode_32( "AddressLookupTab1e1111111111111111111111111",  (unsigned char *) self->solana_address_lookup_table_program);

  fd_base58_decode_32( "So11111111111111111111111111111111111111112",  (unsigned char *) self->solana_spl_native_mint);
  fd_base58_decode_32( "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  (unsigned char *) self->solana_spl_token);

  FD_COMPILER_MFENCE();
  self->magic = FD_GLOBAL_CTX_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_global_ctx_t *
fd_global_ctx_join       ( void * mem ) {
  if( FD_UNLIKELY( !mem) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  fd_global_ctx_t * ctx = (fd_global_ctx_t *) mem;

  if( FD_UNLIKELY( ctx->magic!=FD_GLOBAL_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ctx;
}
void *
fd_global_ctx_leave      ( fd_global_ctx_t * ctx) {
  if( FD_UNLIKELY( !ctx ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  if( FD_UNLIKELY( ctx->magic!=FD_GLOBAL_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (void *) ctx;
}

void *
fd_global_ctx_delete     ( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_GLOBAL_CTX_ALIGN) ) )  {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_global_ctx_t * hdr = (fd_global_ctx_t *)mem;
  if( FD_UNLIKELY( hdr->magic!=FD_GLOBAL_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return mem;
}
