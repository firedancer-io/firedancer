#include "fd_runtime.h"
#include "fd_hashes.h"
#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar.h"
#include "../base58/fd_base58.h"

#include "program/fd_stake_program_config.h"

#include "program/fd_system_program.h"
#include "program/fd_vote_program.h"

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

  fd_memcpy(&global->fee_rate_governor, &global->genesis_block.fee_rate_governor, sizeof(global->genesis_block.fee_rate_governor));
  global->poh_booted = 1;

  fd_sysvar_recent_hashes_init(global );
  fd_sysvar_clock_init( global );
  fd_sysvar_slot_history_init( global );
//  fd_sysvar_slot_hashes_init( global );
  fd_sysvar_epoch_schedule_init( global );
  fd_sysvar_fees_init( global );
  fd_sysvar_rent_init( global );
  fd_sysvar_stake_history_init( global );

  fd_builtin_programs_init( global );
  fd_stake_program_config_init( global );
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
  fd_sysvar_recent_hashes_update ( global );
  // It has to go into the current txn previous info but is not in slot 0
  if (global->bank.solana_bank.slot != 0)
    fd_sysvar_slot_hashes_update( global );

  ulong signature_cnt = 0;

  blob = slot_data->first_blob;
  while (NULL != blob) {
    uchar *blob_ptr = blob + FD_BLOB_DATA_START;
    uint   cnt = *((uint *) (blob + 8));
    while (cnt > 0) {
      fd_microblock_t * micro_block = fd_microblock_join( blob_ptr );
      for ( ulong txn_idx = 0; txn_idx < micro_block->txn_max_cnt; txn_idx++ ) {
        fd_txn_t*      txn_descriptor = (fd_txn_t *)&micro_block->txn_tbl[ txn_idx ];
        fd_rawtxn_b_t* txn_raw   = (fd_rawtxn_b_t *)&micro_block->raw_tbl[ txn_idx ];

        // needed for block hashes
        signature_cnt += txn_descriptor->signature_cnt;

        fd_execute_txn( &global->executor, txn_descriptor, txn_raw );
      }
      fd_microblock_leave(micro_block);

      blob_ptr = (uchar *) fd_ulong_align_up((ulong)blob_ptr + fd_microblock_footprint( micro_block->hdr.txn_cnt ), FD_MICROBLOCK_ALIGN);

      cnt--;
    } // while (cnt > 0)
    blob = *((uchar **) blob);
  } // while (NULL != blob)

  fd_sysvar_slot_history_update( global );

  // this slot is frozen... and cannot change anymore...
  fd_runtime_freeze( global );

  // Time to make the donuts...

  ulong dirty = global->acc_mgr->keys.cnt;
  if (FD_UNLIKELY(global->log_level > 2))
    FD_LOG_WARNING(("slot %ld   dirty %ld", global->bank.solana_bank.slot, dirty));
  if (dirty > 0) {
    global->signature_cnt = signature_cnt;
    fd_hash_bank( global, &global->banks_hash );

    fd_dirty_dup_delete_all (global->acc_mgr->shmap);
    fd_pubkey_hash_vector_clear(&global->acc_mgr->keys);
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

// TODO: add solana txn verify to this as well since, again, it can be
// done in parallel...
int
fd_runtime_block_verify( fd_global_ctx_t *global, fd_slot_blocks_t *slot_data ) {
  if (NULL == slot_data) {
    FD_LOG_WARNING(("NULL slot passed to fd_runtime_block_execute at slot %ld", global->bank.solana_bank.slot));
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
        fd_microblock_batched_mixin(micro_block, outhash, global->alloc);
        fd_poh_mixin(&global->poh, outhash);
      } else
        fd_poh_append(&global->poh, micro_block->hdr.hash_cnt);
      if (memcmp(micro_block->hdr.hash, global->poh.state, sizeof(global->poh.state))) {
        if (global->poh_booted) {
          // TODO should this log and return?  instead of knocking the
          // whole system over via a _ERR?
          FD_LOG_ERR(( "poh missmatch at slot: %ld", global->bank.solana_bank.slot));
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
    FD_LOG_WARNING(("NULL slot passed to fd_runtime_block_execute at slot %ld", global->bank.solana_bank.slot));
    return FD_RUNTIME_EXECUTE_GENERIC_ERR;
  }
  uchar *blob = slot_data->last_blob;
  if (NULL == blob) {
    FD_LOG_WARNING(("empty slot passed to fd_runtime_block_execute at slot %ld", global->bank.solana_bank.slot));
    return FD_RUNTIME_EXECUTE_GENERIC_ERR;
  }

  fd_funk_txn_t* parent_txn = global->funk_txn;
  fd_funk_txn_xid_t xid;
  xid.ul[0] = fd_rng_ulong( global->rng );
  xid.ul[1] = fd_rng_ulong( global->rng );
  xid.ul[2] = fd_rng_ulong( global->rng );
  xid.ul[3] = fd_rng_ulong( global->rng );
  fd_funk_txn_t * txn = fd_funk_txn_prepare( global->funk, parent_txn, &xid, 0 );
    
  global->funk_txn_index = (global->funk_txn_index + 1) & 31;
  fd_funk_txn_t * old_txn = global->funk_txn_tower[global->funk_txn_index];
  if (old_txn != NULL )
    fd_funk_txn_publish( global->funk, old_txn, 0 );
  global->funk_txn_tower[global->funk_txn_index] = global->funk_txn = txn;

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
    /*
    fd_funk_cancel(global->funk, global->funk_txn, 0);
    *global->funk_txn = *fd_funk_root(global->funk);
    global->funk_txn_index = (global->funk_txn_index - 1) & 31;
    global->funk_txn = &global->funk_txn_tower[global->funk_txn_index];
    */
    FD_LOG_ERR(( "need to rollback" ));
  }

  return ret;
}

ulong
fd_runtime_txn_lamports_per_signature( fd_global_ctx_t *global, FD_FN_UNUSED fd_txn_t * txn_descriptor, FD_FN_UNUSED fd_rawtxn_b_t* txn_raw ) {
  //   lamports_per_signature = (transaction has a DurableNonce, use the lamports_per_signature from that nonce instead of looking up the recent_block_hash and using the lamports_per_signature associated with that hash
//                        let TransactionExecutionDetails {
//                            status,
//                            log_messages,
//                            inner_instructions,
//                            durable_nonce_fee,
//                            ..
//                        } = details;
//                        let lamports_per_signature = match durable_nonce_fee {
//                            Some(DurableNonceFee::Valid(lamports_per_signature)) => {
//                                Some(lamports_per_signature)
//                            }
//                            Some(DurableNonceFee::Invalid) => None,
//                            None => bank.get_lamports_per_signature_for_blockhash(
//                                transaction.message().recent_blockhash(),
//                            ),
//                        }
  return global->fee_rate_governor.target_lamports_per_signature / 2;
}

ulong
fd_runtime_calculate_fee( fd_global_ctx_t *global, fd_txn_t * txn_descriptor, fd_rawtxn_b_t* txn_raw ) {
// https://github.com/firedancer-io/solana/blob/08a1ef5d785fe58af442b791df6c4e83fe2e7c74/runtime/src/bank.rs#L4443
// TODO: implement fee distribution to the collector ... and then charge us the correct amount

  fd_pubkey_t *tx_accs   = (fd_pubkey_t *)((uchar *)txn_raw->raw + txn_descriptor->acct_addr_off);

  for ( ushort i = 0; i < txn_descriptor->instr_cnt; ++i ) {
    fd_txn_instr_t *           instr = &txn_descriptor->instr[i];
    execute_instruction_func_t exec_instr_func = fd_executor_lookup_native_program( global, &tx_accs[instr->program_id] );
    if (exec_instr_func == fd_executor_system_program_execute_instruction)
      return 5000;
    else
      return 10000;
  }

  return 10000;

  // Pseudo code:
  //   lamports_per_signature = (transaction has a DurableNonce, use the lamports_per_signature from that nonce instead of looking up the recent_block_hash and using the lamports_per_signature associated with that hash
//                        let TransactionExecutionDetails {
//                            status,
//                            log_messages,
//                            inner_instructions,
//                            durable_nonce_fee,
//                            ..
//                        } = details;
//                        let lamports_per_signature = match durable_nonce_fee {
//                            Some(DurableNonceFee::Valid(lamports_per_signature)) => {
//                                Some(lamports_per_signature)
//                            }
//                            Some(DurableNonceFee::Invalid) => None,
//                            None => bank.get_lamports_per_signature_for_blockhash(
//                                transaction.message().recent_blockhash(),
//                            ),
//                        }

//    pub fn calculate_fee(
//        lamports_per_signature: u64,
//        fee_structure: &FeeStructure,
//    ) -> u64 {
//            // Fee based on compute units and signatures
//            const BASE_CONGESTION: f64 = 5_000.0;
//            let current_congestion = BASE_CONGESTION.max(lamports_per_signature as f64);
//            let congestion_multiplier = if lamports_per_signature == 0 {
//                0.0 // test only
//            } else {
//                BASE_CONGESTION / current_congestion
//            };
//
//            let mut compute_budget = ComputeBudget::default();
//            let prioritization_fee_details = compute_budget
//                .process_instructions(
//                    message.program_instructions_iter(),
//                    false,
//                    false,
//                    true
//                )
//                .unwrap_or_default();
//            let prioritization_fee = prioritization_fee_details.get_fee();
//            let signature_fee = Self::get_num_signatures_in_message(message)
//                .saturating_mul(fee_structure.lamports_per_signature);
//            let write_lock_fee = Self::get_num_write_locks_in_message(message)
//                .saturating_mul(fee_structure.lamports_per_write_lock);
//            let compute_fee = fee_structure
//                .compute_fee_bins
//                .iter()
//                .find(|bin| compute_budget.compute_unit_limit <= bin.limit)
//                .map(|bin| bin.fee)
//                .unwrap_or_else(|| {
//                    fee_structure
//                        .compute_fee_bins
//                        .last()
//                        .map(|bin| bin.fee)
//                        .unwrap_or_default()
//                });
//
//            ((prioritization_fee
//                .saturating_add(signature_fee)
//                .saturating_add(write_lock_fee)
//                .saturating_add(compute_fee) as f64)
//                * congestion_multiplier)
//                .round() as u64
//

//calculate_fee lamports: 5000 tx_wide_compute_cap: true support_set_: true   bt:    0: solana_runtime::bank::Bank::calculate_fee
//                 at /solana/runtime/src/bank.rs:4450:18
//       1: solana_runtime::bank::Bank::get_fee_for_message_with_lamports_per_signature
//                 at /solana/runtime/src/bank.rs:3390:9
//       2: solana_rpc::transaction_status_service::TransactionStatusService::write_transaction_status_batch
//                 at /solana/rpc/src/transaction_status_service.rs:114:35
//
//calculate_fee lamports: 5000 tx_wide_compute_cap: true support_set_: true   bt:    0: solana_runtime::bank::Bank::calculate_fee
//                 at /solana/runtime/src/bank.rs:4450:18
//       1: solana_runtime::bank::Bank::filter_program_errors_and_collect_fee::{{closure}}
//                 at /solana/runtime/src/bank.rs:4533:27
//
//calculate_fee lamports: 5000 tx_wide_compute_cap: true support_set_: true   bt:    0: solana_runtime::bank::Bank::calculate_fee
//                 at /solana/runtime/src/bank.rs:4450:18
//       1: solana_runtime::accounts::Accounts::load_accounts::{{closure}}
//                 at /solana/runtime/src/accounts.rs:570:25

}

void
fd_runtime_freeze( fd_global_ctx_t *global ) {
  // solana/runtime/src/bank.rs::freeze(....)
  //self.collect_rent_eagerly();
  //self.collect_fees();

  // Look at collect_fees... I think this was where I saw the fee payout..
  if (global->collector_set && global->collected) {
    fd_acc_lamports_t lamps;
    int               ret = fd_acc_mgr_get_lamports ( global->acc_mgr, global->funk_txn, &global->collector_id, &lamps);
    if (ret != FD_ACC_MGR_SUCCESS)
      FD_LOG_ERR(( "The collector_id is wrong?!" ));

    // TODO: half get burned?!
    ret = fd_acc_mgr_set_lamports ( global->acc_mgr, global->funk_txn, global->bank.solana_bank.slot, &global->collector_id, lamps + (global->collected/2));
    if (ret != FD_ACC_MGR_SUCCESS)
      FD_LOG_ERR(( "lamport update failed" ));

    global->collected = 0;
  }

  //self.distribute_rent();
  //self.update_slot_history();
  //self.run_incinerator();
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
  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (unsigned char *) self->solana_stake_program_config);
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

void
fd_global_process_genesis_config     ( fd_global_ctx_t *global  ) 
{
  // Bootstrap validator collects fees until `new_from_parent` is called.

  // fd_fee_rate_governor_copy_to(&global->bank.solana_bank.fee_rate_governor, &global->genesis_block.fee_rate_governor, global->allocf, global->allocf_arg);
  global->bank.solana_bank.fee_rate_governor = global->genesis_block.fee_rate_governor;

  // global->bank.solana_bank.fee_calculator = self.fee_rate_governor.create_fee_calculator();
  global->bank.solana_bank.fee_calculator.lamports_per_signature = 10000;

  //  // highest staked node is the first collector
  //  self.collector_id = self
  //    .stakes_cache
  //    .stakes()
  //    .highest_staked_node()
  //    .unwrap_or_default();

//  self.blockhash_queue.write().unwrap().genesis_hash(
//    &genesis_config.hash(),
//      self.fee_rate_governor.lamports_per_signature,
//    );
//

  fd_poh_config_t *poh = &global->genesis_block.poh_config;

  if (poh->hashes_per_tick) {
    global->bank.solana_bank.hashes_per_tick = (ulong*)(*global->allocf)(global->allocf_arg, 8, sizeof(ulong));
    *global->bank.solana_bank.hashes_per_tick = *poh->hashes_per_tick;
  }
  global->bank.solana_bank.ticks_per_slot = global->genesis_block.ticks_per_slot;
  global->bank.solana_bank.genesis_creation_time = global->genesis_block.creation_time;

  uint128 target_tick_duration = ((uint128) poh->target_tick_duration.seconds * 1000000000UL + (uint128) poh->target_tick_duration.nanoseconds);
  global->bank.solana_bank.ns_per_slot = target_tick_duration * global->bank.solana_bank.ticks_per_slot;

#define SECONDS_PER_YEAR ((double) (365.25 * 24.0 * 60.0 * 60.0))

  global->bank.solana_bank.slots_per_year = SECONDS_PER_YEAR * (1000000000.0 / (double) target_tick_duration) / (double) global->bank.solana_bank.ticks_per_slot;

  global->bank.solana_bank.genesis_creation_time = global->genesis_block.creation_time;
  global->bank.solana_bank.max_tick_height = global->bank.solana_bank.ticks_per_slot * (global->bank.solana_bank.slot + 1);

  global->bank.solana_bank.epoch_schedule = global->genesis_block.epoch_schedule;
  global->bank.solana_bank.inflation = global->genesis_block.inflation;

//  self.rent_collector = RentCollector::new(
//    self.epoch,
//      *self.epoch_schedule(),
//      self.slots_per_year,
//      genesis_config.rent,
//    );

}
