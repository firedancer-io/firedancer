#include "fd_runtime.h"
#include "fd_hashes.h"
#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar.h"
#include "../base58/fd_base58.h"
#include "../txn/fd_txn.h"
#include "../bmtree/fd_bmtree.h"

#include "program/fd_stake_program.h"

#include "program/fd_system_program.h"
#include "program/fd_vote_program.h"
#include <stdio.h>
#include <ctype.h>

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

  fd_memcpy(&global->bank.solana_bank.fee_rate_governor, &global->genesis_block.fee_rate_governor, sizeof(global->genesis_block.fee_rate_governor));
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
fd_runtime_block_execute( fd_global_ctx_t *global, fd_slot_meta_t* m, const void* block, ulong blocklen ) {
  (void)m;
  // It sucks that we need to know the current block hash which is
  // stored at the END of the block.  Lets have a fever dream another
  // time and optimize this...
  /* Loop across batches */
  ulong blockoff = 0;
  while (blockoff < blocklen) {
    if ( blockoff + sizeof(ulong) > blocklen )
      FD_LOG_ERR(("premature end of block"));
    ulong mcount = *(const ulong *)((const uchar *)block + blockoff);
    blockoff += sizeof(ulong);

    /* Loop across microblocks */
    for (ulong mblk = 0; mblk < mcount; ++mblk) {
      if ( blockoff + sizeof(fd_microblock_hdr_t) > blocklen )
        FD_LOG_ERR(("premature end of block"));
      fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)((const uchar *)block + blockoff);
      blockoff += sizeof(fd_microblock_hdr_t);

      /* Keep track of the last header hash */
      fd_memcpy(global->block_hash, hdr->hash, sizeof(hdr->hash));

      /* Loop across transactions */
      for ( ulong txn_idx = 0; txn_idx < hdr->txn_cnt; txn_idx++ ) {
        fd_txn_xray_result_t xray;
        const uchar* raw = (const uchar *)block + blockoff;
        ulong pay_sz = fd_txn_xray(raw, blocklen - blockoff, &xray);
        if ( pay_sz == 0UL )
          FD_LOG_ERR(("failed to parse transaction %lu in microblock %lu in slot %lu", txn_idx, mblk, m->slot));
        blockoff += pay_sz;
      }
    }
  }
  if ( blockoff != blocklen )
    FD_LOG_ERR(("garbage at end of block"));
  
  // TODO: move all these out to a fd_sysvar_update() call...
  fd_sysvar_clock_update( global);
  // It has to go into the current txn previous info but is not in slot 0
  if (global->bank.solana_bank.slot != 0)
    fd_sysvar_slot_hashes_update( global );

  ulong signature_cnt = 0;
  blockoff = 0;
  while (blockoff < blocklen) {
    if ( blockoff + sizeof(ulong) > blocklen )
      FD_LOG_ERR(("premature end of block"));
    ulong mcount = *(const ulong *)((const uchar *)block + blockoff);
    blockoff += sizeof(ulong);

    /* Loop across microblocks */
    for (ulong mblk = 0; mblk < mcount; ++mblk) {
      if ( blockoff + sizeof(fd_microblock_hdr_t) > blocklen )
        FD_LOG_ERR(("premature end of block"));
      fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)((const uchar *)block + blockoff);
      blockoff += sizeof(fd_microblock_hdr_t);

      /* Loop across transactions */
      for ( ulong txn_idx = 0; txn_idx < hdr->txn_cnt; txn_idx++ ) {
        uchar txn_out[FD_TXN_MAX_SZ];
        ulong pay_sz = 0;
        const uchar* raw = (const uchar *)block + blockoff;
        ulong txn_sz = fd_txn_parse_core(raw, blocklen - blockoff, txn_out, NULL, &pay_sz, 0);
        if ( txn_sz == 0 || txn_sz > FD_TXN_MAX_SZ )
          FD_LOG_ERR(("failed to parse transaction"));
        
        fd_txn_t* txn = (fd_txn_t *)txn_out;
        fd_rawtxn_b_t rawtxn;
        rawtxn.raw = (void*)raw;
        rawtxn.txn_sz = (ushort)txn_sz;
        signature_cnt += txn->signature_cnt;
        fd_execute_txn( &global->executor, txn, &rawtxn );

        blockoff += pay_sz;
      }
    }
  }
  if ( blockoff != blocklen )
    FD_LOG_ERR(("garbage at end of block"));

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

    fd_dirty_dup_clear(global->acc_mgr->dup);
    fd_pubkey_hash_vector_clear(&global->acc_mgr->keys);
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

// TODO: add solana txn verify to this as well since, again, it can be
// done in parallel...
int
fd_runtime_block_verify( fd_global_ctx_t *global, fd_slot_meta_t* m, const void* block, ulong blocklen ) {
  fd_txn_parse_counters_t counters;
  fd_memset(&counters, 0, sizeof(counters));

  uchar commit_mem[FD_BMTREE32_COMMIT_FOOTPRINT] __attribute__((aligned(FD_BMTREE32_COMMIT_ALIGN)));

  /* Loop across batches */
  ulong blockoff = 0;
  while (blockoff < blocklen) {
    if ( blockoff + sizeof(ulong) > blocklen )
      FD_LOG_ERR(("premature end of block"));
    ulong mcount = *(const ulong *)((const uchar *)block + blockoff);
    blockoff += sizeof(ulong);

    /* Loop across microblocks */
    for (ulong mblk = 0; mblk < mcount; ++mblk) {
      if ( blockoff + sizeof(fd_microblock_hdr_t) > blocklen )
        FD_LOG_ERR(("premature end of block"));
      fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)((const uchar *)block + blockoff);
      blockoff += sizeof(fd_microblock_hdr_t);

      if (hdr->txn_cnt == 0) {
        fd_poh_append(&global->poh, hdr->hash_cnt);

      } else {
        if (hdr->hash_cnt > 0)
          fd_poh_append(&global->poh, hdr->hash_cnt - 1);

        fd_bmtree32_commit_t * tree = fd_bmtree32_commit_init( commit_mem );
      
        /* Loop across transactions */
        for ( ulong txn_idx = 0; txn_idx < hdr->txn_cnt; txn_idx++ ) {
          fd_txn_xray_result_t xray;
          const uchar* raw = (const uchar *)block + blockoff;
          ulong pay_sz = fd_txn_xray(raw, blocklen - blockoff, &xray);
          if ( pay_sz == 0UL )
            FD_LOG_ERR(("failed to parse transaction %lu in microblock %lu in slot %lu", txn_idx, mblk, m->slot));

          /* Loop across signatures */
          fd_ed25519_sig_t const * sigs = (fd_ed25519_sig_t const *)((ulong)raw + (ulong)xray.signature_off);
          for ( ulong j = 0; j < xray.signature_cnt; j++ ) {
            fd_bmtree32_node_t leaf;
            fd_bmtree32_hash_leaf( &leaf, &sigs[j], sizeof(fd_ed25519_sig_t) );
            fd_bmtree32_commit_append( tree, (fd_bmtree32_node_t const *)&leaf, 1 );
          }

          blockoff += pay_sz;
        }

        uchar * root = fd_bmtree32_commit_fini( tree );
        fd_poh_mixin(&global->poh, root);
      }
      
      if (memcmp(hdr->hash, global->poh.state, sizeof(global->poh.state))) {
        if (global->poh_booted) {
          // TODO should this log and return?  instead of knocking the
          // whole system over via a _ERR?
          FD_LOG_ERR(( "poh missmatch at slot: %ld", m->slot));
        } else {
          fd_memcpy(global->poh.state, hdr->hash, sizeof(global->poh.state));
          global->poh_booted = 1;
        }
      }
    }
  }

  if (blockoff != blocklen)
    FD_LOG_ERR(("garbage at end of block"));

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

struct __attribute__((aligned(64))) fd_runtime_block_micro {
    fd_microblock_hdr_t * hdr;
    fd_poh_state_t poh;
    int failed;
};

static void fd_runtime_block_verify_task( void * tpool,
                                          ulong  t0,     ulong t1,
                                          void * args,
                                          void * reduce, ulong stride,
                                          ulong  l0,     ulong l1,
                                          ulong  m0,     ulong m1,
                                          ulong  n0,     ulong n1 ) {
  struct fd_runtime_block_micro * micro = (struct fd_runtime_block_micro *)tpool;
  (void)t0;
  (void)t1;
  (void)args;
  (void)reduce;
  (void)stride;
  (void)l0;
  (void)l1;
  (void)m0;
  (void)m1;
  (void)n0;
  (void)n1;

  fd_microblock_hdr_t * hdr = micro->hdr;
  ulong blockoff = sizeof(fd_microblock_hdr_t);
  if (hdr->txn_cnt == 0) {
    fd_poh_append(&micro->poh, hdr->hash_cnt);

  } else {
    if (hdr->hash_cnt > 0)
      fd_poh_append(&micro->poh, hdr->hash_cnt - 1);

    uchar commit_mem[FD_BMTREE32_COMMIT_FOOTPRINT] __attribute__((aligned(FD_BMTREE32_COMMIT_ALIGN)));
    fd_bmtree32_commit_t * tree = fd_bmtree32_commit_init( commit_mem );
      
    /* Loop across transactions */
    for ( ulong txn_idx = 0; txn_idx < hdr->txn_cnt; txn_idx++ ) {
      fd_txn_xray_result_t xray;
      const uchar* raw = (const uchar *)hdr + blockoff;
      ulong pay_sz = fd_txn_xray(raw, ULONG_MAX /* no need to check here */, &xray);
      if ( pay_sz == 0UL ) {
        micro->failed = 1;
        return;
      }

      /* Loop across signatures */
      fd_ed25519_sig_t const * sigs = (fd_ed25519_sig_t const *)((ulong)raw + (ulong)xray.signature_off);
      for ( ulong j = 0; j < xray.signature_cnt; j++ ) {
        fd_bmtree32_node_t leaf;
        fd_bmtree32_hash_leaf( &leaf, &sigs[j], sizeof(fd_ed25519_sig_t) );
        fd_bmtree32_commit_append( tree, (fd_bmtree32_node_t const *)&leaf, 1 );
      }

      blockoff += pay_sz;
    }

    uchar * root = fd_bmtree32_commit_fini( tree );
    fd_poh_mixin(&micro->poh, root);
  }
      
  micro->failed = (memcmp(hdr->hash, micro->poh.state, sizeof(micro->poh.state)) ? 1 : 0);
}

int fd_runtime_block_verify_tpool( fd_global_ctx_t *global, fd_slot_meta_t *m, const void* block, ulong blocklen, fd_tpool_t * tpool, ulong max_workers ) {
  /* Find all the microblock headers */
  static const ulong MAX_MICROS = 1000;
  struct fd_runtime_block_micro micros[MAX_MICROS];
  ulong num_micros = 0;

  /* Loop across batches */
  ulong blockoff = 0;
  while (blockoff < blocklen) {
    if ( blockoff + sizeof(ulong) > blocklen )
      FD_LOG_ERR(("premature end of block"));
    ulong mcount = *(const ulong *)((const uchar *)block + blockoff);
    blockoff += sizeof(ulong);

    /* Loop across microblocks */
    for (ulong mblk = 0; mblk < mcount; ++mblk) {
      if ( blockoff + sizeof(fd_microblock_hdr_t) > blocklen )
        FD_LOG_ERR(("premature end of block"));
      fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)((const uchar *)block + blockoff);
      blockoff += sizeof(fd_microblock_hdr_t);

      if (global->poh_booted) {
        /* Setup a task using the previous poh as the input state */
        if ( num_micros == MAX_MICROS )
          FD_LOG_ERR(("too many microblocks in slot %lu", m->slot));
        struct fd_runtime_block_micro * micro = &(micros[num_micros++]);
        micro->hdr = hdr;
        fd_memcpy(micro->poh.state, global->poh.state, sizeof(global->poh.state));
        micro->failed = 0;
      }
      /* Remember the new poh state */
      fd_memcpy(global->poh.state, hdr->hash, sizeof(global->poh.state));
      global->poh_booted = 1;

      /* Loop across transactions */
      for ( ulong txn_idx = 0; txn_idx < hdr->txn_cnt; txn_idx++ ) {
        fd_txn_xray_result_t xray;
        const uchar* raw = (const uchar *)block + blockoff;
        ulong pay_sz = fd_txn_xray(raw, blocklen - blockoff, &xray);
        if ( pay_sz == 0UL )
          FD_LOG_ERR(("failed to parse transaction %lu in microblock %lu in slot %lu", txn_idx, mblk, m->slot));
        blockoff += pay_sz;
      }
    }
  }
  if (blockoff != blocklen)
    FD_LOG_ERR(("garbage at end of block"));

  /* Spawn jobs to thread pool */
  for (ulong mblk = 0; mblk < num_micros; ++mblk) {
    ulong i = mblk%max_workers + 1UL; /* Do not use thread 0 */
    if ( i != mblk+1UL ) {
      /* Wrapped around. Wait for the previous job to finish */
      fd_tpool_wait( tpool, i );
    }
    fd_tpool_exec( tpool, i, fd_runtime_block_verify_task, micros + mblk,
                   0, 0, NULL, NULL, 0, 0, 0, 0, 0, 0, 0 );
  }
  /* Wait for everything to finish */
  for (ulong i = 1; i < max_workers; ++i)
    fd_tpool_wait( tpool, i );
  
  /* Loop across microblocks, perform final hashing */
  for (ulong mblk = 0; mblk < num_micros; ++mblk) {
    if ( micros[mblk].failed )
      FD_LOG_ERR(( "poh missmatch at slot %ld, microblock %lu", m->slot, mblk));
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int
fd_runtime_block_eval( fd_global_ctx_t *global, fd_slot_meta_t *m, const void* block, ulong blocklen ) {
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

  int ret = fd_runtime_block_verify( global, m, block, blocklen );
  if ( FD_RUNTIME_EXECUTE_SUCCESS == ret )
    ret = fd_runtime_block_execute( global, m, block, blocklen );

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
fd_runtime_lamports_per_signature( fd_global_ctx_t *global ) {
  // https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/fee_calculator.rs#L110
  return global->bank.solana_bank.fee_rate_governor.target_lamports_per_signature / 2;
}

ulong
fd_runtime_lamports_per_signature_for_blockhash( fd_global_ctx_t *global, FD_FN_UNUSED fd_hash_t *blockhash ) {
  // https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/fee_calculator.rs#L110
  return global->bank.solana_bank.fee_rate_governor.target_lamports_per_signature / 2;
}

ulong
fd_runtime_txn_lamports_per_signature( fd_global_ctx_t *global, fd_txn_t * txn_descriptor, fd_rawtxn_b_t* txn_raw ) {
  fd_nonce_state_versions_t state;
  if ((NULL != txn_descriptor) && fd_load_nonce_account(global, txn_descriptor, txn_raw, &state)) {
    if (state.inner.current.discriminant == fd_nonce_state_enum_initialized)
      return state.inner.current.inner.initialized.fee_calculator.lamports_per_signature;
  }

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

  return fd_runtime_lamports_per_signature_for_blockhash( global, NULL );
}

ulong
fd_runtime_calculate_fee( fd_global_ctx_t *global, fd_txn_t * txn_descriptor, fd_rawtxn_b_t* txn_raw ) {
// https://github.com/firedancer-io/solana/blob/08a1ef5d785fe58af442b791df6c4e83fe2e7c74/runtime/src/bank.rs#L4443
// TODO: implement fee distribution to the collector ... and then charge us the correct amount

  ulong lamports_per_signature = fd_runtime_txn_lamports_per_signature(global, txn_descriptor, txn_raw);
  
  double BASE_CONGESTION = 5000.0;
  double current_congestion = (BASE_CONGESTION > lamports_per_signature) ? BASE_CONGESTION : (double)lamports_per_signature;
  double congestion_multiplier = (lamports_per_signature == 0) ? 0.0 : (BASE_CONGESTION / current_congestion);

//  bool support_set_compute_unit_price_ix = false;
//  bool use_default_units_per_instruction = false;
//  bool enable_request_heap_frame_ix = true;

//        let mut compute_budget = ComputeBudget::default();
//        let prioritization_fee_details = compute_budget
//            .process_instructions(
//                message.program_instructions_iter(),
//                use_default_units_per_instruction,
//                support_set_compute_unit_price_ix,
//                enable_request_heap_frame_ix,
//            )
//            .unwrap_or_default();
//        let prioritization_fee = prioritization_fee_details.get_fee();
  double prioritization_fee = 0;

  // let signature_fee = Self::get_num_signatures_in_message(message) .saturating_mul(fee_structure.lamports_per_signature);
  double signature_fee = (double)fd_runtime_lamports_per_signature(global) * txn_descriptor->signature_cnt;

// TODO: as far as I can tell, this is always 0
//
//            let write_lock_fee = Self::get_num_write_locks_in_message(message)
//                .saturating_mul(fee_structure.lamports_per_write_lock);
  double write_lock_fee = 0;

// TODO: the fee_structure bin is static and default.. 
//
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
  double compute_fee = 0;

  double fee = (prioritization_fee + signature_fee + write_lock_fee + compute_fee) * congestion_multiplier;

  if (FD_UNLIKELY(global->log_level > 2)) {
      FD_LOG_WARNING(( "fd_runtime_calculate_fee_compare: slot=%ld fee(%lf) = (prioritization_fee(%f) + signature_fee(%f) + write_lock_fee(%f) + compute_fee(%f)) * congestion_multiplier(%f)", global->bank.solana_bank.slot, fee, prioritization_fee, signature_fee, write_lock_fee, compute_fee, congestion_multiplier));
  }

  if (fee >= ULONG_MAX)
    return ULONG_MAX;
  else
    return (ulong) fee;
}

void
fd_runtime_freeze( fd_global_ctx_t *global ) {
  // solana/runtime/src/bank.rs::freeze(....)
  //self.collect_rent_eagerly();
  //self.collect_fees();

  fd_sysvar_recent_hashes_update ( global );

  // Look at collect_fees... I think this was where I saw the fee payout..
  if (global->collector_set && global->collected) {

    if (FD_UNLIKELY(global->log_level > 2)) {
      FD_LOG_WARNING(( "fd_runtime_freeze: slot:%ld global->collected: %ld", global->bank.solana_bank.slot, global->collected ));
    }

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

  fd_acc_mgr_delete(fd_acc_mgr_leave(hdr->acc_mgr));
  fd_genesis_solana_destroy(&hdr->genesis_block, hdr->freef, hdr->allocf_arg);
  fd_firedancer_banks_destroy(&hdr->bank, hdr->freef, hdr->allocf_arg);

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

void fd_printer_walker(void *arg, const char* name, int type, const char *type_name, int level) {
  if (NULL == arg)
    return;
  while (level-- > 0)
    printf("  ");
  switch (type) {
    case 1:
    case 9:
      if (isprint(*((char *) arg)))
        printf("\"%s\": \"%c\",  // %s\n", name, *((char *) arg), type_name);
      else
        printf("\"%s\": \"%d\",  // %s\n", name, *((char *) arg), type_name);
      break;
    case 2:
    case 3:
    case 4:
      printf("\"%s\": \"%s\",  // %s\n", name, ((char *) arg), type_name);
      break;
    case 5:
      printf("\"%s\": \"%f\",  // %s\n", name, *((double *) arg), type_name);
      break;
    case 6:
      printf("\"%s\": \"%ld\",  // %s\n", name, *((long *) arg), type_name);
      break;
    case 7:
      printf("\"%s\": \"%d\",  // %s\n", name, *((uint *) arg), type_name);
      break;
    case 8:
      printf("\"%s\": \"%llx\",  // %s\n", name, (unsigned long long) *((uint128 *) arg), type_name);
      break;
    case 11:
      printf("\"%s\": \"%ld\",  // %s\n", name, *((ulong *) arg), type_name);
      break;
    case 12:
      printf("\"%s\": \"%d\",  // %s\n", name, *((ushort *) arg), type_name);
      break;
    case 32:
      printf("\"%s\": {\n", name);
      break;
    case 33:
      printf("},\n");
      break;
    case 35: {
      char buf[50];
      fd_base58_encode_32((uchar *) arg, NULL, buf);
      printf("\"%s\": \"%s\",\n", name, buf);
      break;
    }
  default: 
    printf("arg: %ld  name: %s  type: %d   type_name: %s\n", (ulong) arg, name, type, type_name);
    break;
  }
}

fd_funk_rec_key_t fd_runtime_block_key(ulong slot) {
  fd_funk_rec_key_t id;
  fd_memset( &id, 0, sizeof(id) );
  id.ul[ 0 ] = slot;
  id.c[ FD_FUNK_REC_KEY_FOOTPRINT - 1 ] = FD_BLOCK_KEY_TYPE;

  return id;
}

fd_funk_rec_key_t fd_runtime_block_meta_key(ulong slot) {
  fd_funk_rec_key_t id;
  fd_memset( &id, 0, sizeof(id) );
  id.ul[ 0 ] = slot;
  id.c[ FD_FUNK_REC_KEY_FOOTPRINT - 1 ] = FD_BLOCK_META_KEY_TYPE;

  return id;
}

/// Number of bytes in a pubkey
//pub const PUBKEY_BYTES: usize = 32;
/// maximum length of derived `Pubkey` seed
//pub const MAX_SEED_LEN: usize = 32;
/// Maximum number of seeds
//pub const MAX_SEEDS: usize = 16;
/// Maximum string length of a base58 encoded pubkey
// const MAX_BASE58_LEN: usize = 44;
//
// const PDA_MARKER: &[u8; 21] = b"ProgramDerivedAddress";

void fd_pubkey_create_with_seed(FD_FN_UNUSED fd_pubkey_t *base, FD_FN_UNUSED char *seed, FD_FN_UNUSED fd_pubkey_t *owner, FD_FN_UNUSED fd_pubkey_t *out ) {
//  if seed.len() > MAX_SEED_LEN {
//      return Err(PubkeyError::MaxSeedLengthExceeded);
//    }
//
//  let owner = owner.as_ref();
//  if owner.len() >= PDA_MARKER.len() {
//      let slice = &owner[owner.len() - PDA_MARKER.len()..];
//      if slice == PDA_MARKER {
//          return Err(PubkeyError::IllegalOwner);
//        }
//    }
//
//  Ok(Pubkey::new(
//      hashv(&[base.as_ref(), seed.as_ref(), owner]).as_ref(),
//      ))
}
