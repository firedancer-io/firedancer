#include "time.h"
#include "fd_runtime.h"
#include "fd_hashes.h"
#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/bmtree/fd_bmtree.h"

#include "program/fd_stake_program.h"

#include "program/fd_system_program.h"
#include "program/fd_vote_program.h"
#include <stdio.h>
#include <ctype.h>

#define MICRO_LAMPORTS_PER_LAMPORT (1000000UL)

#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize ("O0")
#endif

void
fd_runtime_init_bank_from_genesis( fd_global_ctx_t * global, fd_genesis_solana_t * genesis_block, uchar genesis_hash[FD_SHA256_HASH_SZ] ) {
  global->bank.slot = 0;

  fd_memcpy(&global->bank.poh, genesis_hash, FD_SHA256_HASH_SZ);

  global->bank.fee_rate_governor = genesis_block->fee_rate_governor;
  global->bank.lamports_per_signature = 10000;

  fd_poh_config_t * poh = &genesis_block->poh_config;

  if (poh->hashes_per_tick)
    global->bank.hashes_per_tick = *poh->hashes_per_tick;
  else
    global->bank.hashes_per_tick = 0;
  global->bank.ticks_per_slot = genesis_block->ticks_per_slot;
  global->bank.genesis_creation_time = genesis_block->creation_time;
  uint128 target_tick_duration = ((uint128) poh->target_tick_duration.seconds * 1000000000UL + (uint128) poh->target_tick_duration.nanoseconds);
  global->bank.ns_per_slot = target_tick_duration * global->bank.ticks_per_slot;

#define SECONDS_PER_YEAR ((double) (365.25 * 24.0 * 60.0 * 60.0))

  global->bank.slots_per_year = SECONDS_PER_YEAR * (1000000000.0 / (double) target_tick_duration) / (double) global->bank.ticks_per_slot;
  global->bank.genesis_creation_time = genesis_block->creation_time;
  global->bank.max_tick_height = global->bank.ticks_per_slot * (global->bank.slot + 1);
  global->bank.epoch_schedule = genesis_block->epoch_schedule;
  global->bank.inflation = genesis_block->inflation;
  global->bank.rent = genesis_block->rent;

  fd_block_block_hash_entry_t * hashes = global->bank.recent_block_hashes.hashes =
    deq_fd_block_block_hash_entry_t_alloc( global->valloc );
  fd_block_block_hash_entry_t * elem = deq_fd_block_block_hash_entry_t_push_head_nocopy(hashes);
  fd_block_block_hash_entry_new(elem);
  fd_memcpy(elem->blockhash.hash, genesis_hash, FD_SHA256_HASH_SZ);
  elem->fee_calculator.lamports_per_signature = 0;

  global->signature_cnt = 0;
}

void
fd_runtime_init_program( fd_global_ctx_t * global ) {
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
  // TODO: move all these out to a fd_sysvar_update() call...
  fd_sysvar_clock_update( global);
  // It has to go into the current txn previous info but is not in slot 0
  if (global->bank.slot != 0)
    fd_sysvar_slot_hashes_update( global );

  ulong signature_cnt = 0;
  ulong blockoff = 0;
  ulong txn_idx_in_block = 1;
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
        ulong txn_sz = fd_txn_parse_core(raw, fd_ulong_min(blocklen - blockoff, USHORT_MAX), txn_out, NULL, &pay_sz, 0);
        if ( txn_sz == 0 || txn_sz > FD_TXN_MAX_SZ )
          FD_LOG_ERR(("failed to parse transaction"));

        fd_txn_t* txn = (fd_txn_t *)txn_out;
        fd_rawtxn_b_t rawtxn;
        rawtxn.raw = (void*)raw;
        rawtxn.txn_sz = (ushort)txn_sz;
        signature_cnt += txn->signature_cnt;

        char sig[FD_BASE58_ENCODED_64_SZ];
        fd_base58_encode_64(raw+txn->signature_off, NULL, sig);
        FD_LOG_NOTICE(("executing txn -  slot: %lu, txn_idx_in_block: %lu, mblk: %lu, txn_idx: %lu, sig: %s", global->bank.slot, txn_idx_in_block, mblk, txn_idx, sig));
        fd_execute_txn( &global->executor, txn, &rawtxn );

        blockoff += pay_sz;
        txn_idx_in_block++;
      }
    }
  }
  if ( blockoff != blocklen )
    FD_LOG_ERR(("garbage at end of block"));

  fd_sysvar_slot_history_update( global );

  // this slot is frozen... and cannot change anymore...
  fd_runtime_freeze( global );

  int result = fd_update_hash_bank( global, &global->bank.banks_hash, signature_cnt );
  if (result != FD_EXECUTOR_INSTR_SUCCESS) {
    return result;
  }

  return fd_runtime_save_banks( global );
}

// TODO: add solana txn verify to this as well since, again, it can be
// done in parallel...
int
fd_runtime_block_verify( fd_global_ctx_t * global,
                         fd_slot_meta_t *  m,
                         void const *      block,
                         ulong             blocklen ) {

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
        fd_poh_append(&global->bank.poh, hdr->hash_cnt);

      } else {
        if (hdr->hash_cnt > 0)
          fd_poh_append(&global->bank.poh, hdr->hash_cnt - 1);

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
        fd_poh_mixin(&global->bank.poh, root);
      }

      if( FD_UNLIKELY( 0!=memcmp(hdr->hash, &global->bank.poh, sizeof(fd_hash_t) ) ) ) {
        FD_LOG_ERR(( "poh missmatch at slot: %ld (bank: %32J, entry: %32J)", m->slot, global->bank.poh.uc, hdr->hash ));
        return -1;
      }
    }
  }

  if (blockoff != blocklen)
    FD_LOG_ERR(("garbage at end of block"));

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

struct __attribute__((aligned(64))) fd_runtime_block_micro {
    fd_microblock_hdr_t * hdr;
    fd_hash_t poh;
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

  micro->failed = (memcmp(hdr->hash, &micro->poh, sizeof(micro->poh)) ? 1 : 0);
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

      /* Setup a task using the previous poh as the input state */
      if ( num_micros == MAX_MICROS )
        FD_LOG_ERR(("too many microblocks in slot %lu", m->slot));
      struct fd_runtime_block_micro * micro = &(micros[num_micros++]);
      micro->hdr = hdr;
      fd_memcpy(&micro->poh, &global->bank.poh, sizeof(global->bank.poh));
      micro->failed = 0;

      /* Remember the new poh state */
      fd_memcpy(&global->bank.poh, hdr->hash, sizeof(global->bank.poh));

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
  fd_funk_txn_t * txn = fd_funk_txn_prepare( global->funk, parent_txn, &xid, 1 );

  if (NULL == txn)
    FD_LOG_ERR(("fd_funk_txn_prepare failed"));

  global->funk_txn_index = (global->funk_txn_index + 1) & 0x1F;
  fd_funk_txn_t * old_txn = global->funk_txn_tower[global->funk_txn_index];
  if (old_txn != NULL ) {
    FD_LOG_WARNING(( "publishing funk txn in tower: idx: %u", global->funk_txn_index ));
    fd_funk_txn_publish( global->funk, old_txn, 0 );
  }
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
  return global->bank.fee_rate_governor.target_lamports_per_signature / 2;
}

ulong
fd_runtime_lamports_per_signature_for_blockhash( fd_global_ctx_t *global, FD_FN_UNUSED fd_hash_t *blockhash ) {

  // https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/fee_calculator.rs#L110

  // https://github.com/firedancer-io/solana/blob/53a4e5d6c58b2ffe89b09304e4437f8ca198dadd/runtime/src/blockhash_queue.rs#L55
  ulong default_fee = global->bank.fee_rate_governor.target_lamports_per_signature / 2;

  if (blockhash == 0) {
    return default_fee;
  }

  fd_block_block_hash_entry_t * hashes = global->bank.recent_block_hashes.hashes;
  for ( deq_fd_block_block_hash_entry_t_iter_t iter = deq_fd_block_block_hash_entry_t_iter_init( hashes ); !deq_fd_block_block_hash_entry_t_iter_done( hashes, iter ); iter = deq_fd_block_block_hash_entry_t_iter_next( hashes, iter ) ) {
    fd_block_block_hash_entry_t * curr_elem = deq_fd_block_block_hash_entry_t_iter_ele( hashes, iter );
    if (memcmp(&curr_elem->blockhash, blockhash, sizeof(fd_hash_t)) == 0) {
      return curr_elem->fee_calculator.lamports_per_signature;
    }
  }

  return default_fee;
}

ulong
fd_runtime_txn_lamports_per_signature( fd_global_ctx_t *global, fd_txn_t * txn_descriptor, fd_rawtxn_b_t* txn_raw ) {
  // why is asan not detecting access to uninitialized memory here?!
  fd_nonce_state_versions_t state;
  int err;
  if ((NULL != txn_descriptor) && fd_load_nonce_account(global, txn_descriptor, txn_raw, &state, &err)) {
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

  return (txn_raw == 0) ?
    fd_runtime_lamports_per_signature_for_blockhash( global, NULL ) :
    fd_runtime_lamports_per_signature_for_blockhash( global, (fd_hash_t *)((uchar *)txn_raw->raw + txn_descriptor->recent_blockhash_off) );

}

void compute_priority_fee( transaction_ctx_t const * txn_ctx, ulong * fee, ulong * priority ) {
  switch (txn_ctx->prioritization_fee_type) {
    case FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_DEPRECATED: {
      if( txn_ctx->compute_unit_limit == 0 ) {
        *priority = 0;
      } else {
        uint128 micro_lamport_fee = (uint128)txn_ctx->compute_unit_price * (uint128)MICRO_LAMPORTS_PER_LAMPORT;
        uint128 _priority = micro_lamport_fee / (uint128)txn_ctx->compute_unit_limit;
        *priority = _priority > (uint128)ULONG_MAX ? ULONG_MAX : (ulong)_priority;
      }

      *fee = txn_ctx->compute_unit_price;
      return;
    }
    case FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_COMPUTE_UNIT_PRICE: {

      uint128 micro_lamport_fee = (uint128)txn_ctx->compute_unit_price * (uint128)txn_ctx->compute_unit_limit;

      *priority = txn_ctx->compute_unit_price;
      uint128 _fee = (micro_lamport_fee + (uint128)(MICRO_LAMPORTS_PER_LAMPORT - 1))/(uint128)(MICRO_LAMPORTS_PER_LAMPORT);
      *fee = _fee > (uint128)ULONG_MAX ? ULONG_MAX : (ulong)_fee;
      FD_LOG_WARNING(("CPF: %lu %lu %lu", *fee, (ulong)txn_ctx->compute_unit_price, txn_ctx->compute_unit_limit));
      return;
    }
    default:
      __builtin_unreachable();
  }
}

ulong
fd_runtime_calculate_fee( fd_global_ctx_t *global, transaction_ctx_t * txn_ctx, fd_txn_t * txn_descriptor, fd_rawtxn_b_t* txn_raw ) {
// https://github.com/firedancer-io/solana/blob/08a1ef5d785fe58af442b791df6c4e83fe2e7c74/runtime/src/bank.rs#L4443
// TODO: implement fee distribution to the collector ... and then charge us the correct amount
  ulong priority = 0;
  ulong priority_fee = 0;
  compute_priority_fee(txn_ctx, &priority_fee, &priority);
  ulong lamports_per_signature = fd_runtime_txn_lamports_per_signature(global, txn_descriptor, txn_raw);

  double BASE_CONGESTION = 5000.0;
  double current_congestion = (BASE_CONGESTION > (double)lamports_per_signature) ? BASE_CONGESTION : (double)lamports_per_signature;
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
  double prioritization_fee = (double)priority_fee;

  // let signature_fee = Self::get_num_signatures_in_message(message) .saturating_mul(fee_structure.lamports_per_signature);
  double signature_fee = (double)fd_runtime_lamports_per_signature(global) * txn_descriptor->signature_cnt;

// TODO: as far as I can tell, this is always 0
//
//            let write_lock_fee = Self::get_num_write_locks_in_message(message)
//                .saturating_mul(fee_structure.lamports_per_write_lock);
  ulong lamports_per_write_lock = 0;
  double write_lock_fee = (double)fd_ulong_sat_mul( fd_txn_num_writable_accounts( txn_descriptor ), lamports_per_write_lock );

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
      FD_LOG_WARNING(( "fd_runtime_calculate_fee_compare: slot=%ld fee(%lf) = (prioritization_fee(%f) + signature_fee(%f) + write_lock_fee(%f) + compute_fee(%f)) * congestion_multiplier(%f)", global->bank.slot, fee, prioritization_fee, signature_fee, write_lock_fee, compute_fee, congestion_multiplier));
      FD_LOG_WARNING(( "fd_rcfc2: lps: %lu, pp: %lu, pf: %lu, cul: %lu, cup: %lu, pft: %u", lamports_per_signature, priority, priority_fee, txn_ctx->compute_unit_limit, txn_ctx->compute_unit_price, txn_ctx->prioritization_fee_type));
  }

  if (fee >= (double)ULONG_MAX)
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
  if (global->collector_set && global->bank.collected) {

    if (FD_UNLIKELY(global->log_level > 2)) {
      FD_LOG_WARNING(( "fd_runtime_freeze: slot:%ld global->collected: %ld", global->bank.slot, global->bank.collected ));
    }

    fd_acc_lamports_t lamps;
    int               ret = fd_acc_mgr_get_lamports ( global->acc_mgr, global->funk_txn, &global->bank.collector_id, &lamps);
    if (ret != FD_ACC_MGR_SUCCESS)
      FD_LOG_ERR(( "The collector_id is wrong?!" ));

    // TODO: half get burned?!
    ret = fd_acc_mgr_set_lamports ( global->acc_mgr, global->funk_txn, global->bank.slot, &global->bank.collector_id, lamps + (global->bank.collected/2));
    if (ret != FD_ACC_MGR_SUCCESS)
      FD_LOG_ERR(( "lamport update failed" ));

    global->bank.collected = 0;
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

  self->rng  = fd_rng_join( fd_rng_new(&self->rnd_mem, (uint) time(0), 0) );

  // Yeah, maybe we should get rid of this?
  fd_executor_new ( &self->executor, self, FD_EXECUTOR_FOOTPRINT );

  fd_firedancer_banks_new(&self->bank);

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

  fd_bincode_destroy_ctx_t ctx = { .valloc = hdr->valloc };
  fd_firedancer_banks_destroy(&hdr->bank, &ctx);

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return mem;
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
    case 36:
      printf("\"%s\": [\n", name);
      break;
    case 37:
      printf("],\n");
      break;
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

fd_funk_rec_key_t fd_runtime_banks_key(void) {
  fd_funk_rec_key_t id;
  fd_memset( &id, 1, sizeof(id) );
  id.c[ FD_FUNK_REC_KEY_FOOTPRINT - 1 ] = FD_BLOCK_BANKS_TYPE;

  return id;
}

const size_t MAX_SEED_LEN = 32;
//
const char PDA_MARKER[] = {"ProgramDerivedAddress"};

int
fd_pubkey_create_with_seed( fd_pubkey_t const * base,
                            char const *        seed,  /* FIXME add sz param */
                            fd_pubkey_t const * owner,
                            fd_pubkey_t *       out ) {
//  if seed.len() > MAX_SEED_LEN {
//      return Err(PubkeyError::MaxSeedLengthExceeded);
//    }

  size_t slen = strlen(seed);

  if (slen > MAX_SEED_LEN)
    return FD_EXECUTOR_SYSTEM_ERR_MAX_SEED_LENGTH_EXCEEDED;

  if (memcmp(&owner->hash[sizeof(owner->hash) - sizeof(PDA_MARKER) - 1], PDA_MARKER, sizeof(PDA_MARKER) - 1) == 0)
    return FD_EXECUTOR_INSTR_ERR_ILLEGAL_OWNER;
//  let owner = owner.as_ref();
//  if owner.len() >= PDA_MARKER.len() {
//      let slice = &owner[owner.len() - PDA_MARKER.len()..];
//      if slice == PDA_MARKER {
//          return Err(PubkeyError::IllegalOwner);
//        }
//    }

  fd_sha256_t sha;
  fd_sha256_init( &sha );

  fd_sha256_append( &sha, base->hash, sizeof( fd_hash_t ) );
  fd_sha256_append( &sha, seed, slen );
  fd_sha256_append( &sha, owner->hash, sizeof( fd_hash_t ) );

  fd_sha256_fini( &sha, out->hash );

//  Ok(Pubkey::new(
//      hashv(&[base.as_ref(), seed.as_ref(), owner]).as_ref(),
//      ))

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int
fd_runtime_save_banks( fd_global_ctx_t * global ) {
  ulong sz = fd_firedancer_banks_size(&global->bank);

  fd_funk_rec_key_t id = fd_runtime_banks_key();
  int opt_err = 0;
  fd_funk_rec_t * rec = fd_funk_rec_write_prepare( global->funk, global->funk_txn, &id, sz, 1, NULL, &opt_err );
  if (NULL == rec) {
    FD_LOG_WARNING(("fd_runtime_save_banks failed: %s", fd_funk_strerror(opt_err)));
    return opt_err;
  }

  uchar * buf = fd_funk_val_cache( global->funk, rec, &opt_err );
  if (NULL == buf) {
    FD_LOG_WARNING(("fd_runtime_save_banks failed: %s", fd_funk_strerror(opt_err)));
    return opt_err;
  }

  fd_bincode_encode_ctx_t ctx = {
    .data = buf,
    .dataend = buf + sz,
  };
  if( FD_UNLIKELY( fd_firedancer_banks_encode( &global->bank, &ctx )!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_WARNING(( "fd_runtime_save_banks: fd_firedancer_banks_encode failed" ));
    return -1;
  }

  FD_LOG_NOTICE(( "saved banks_hash %32J  poh_hash %32J", global->bank.banks_hash.hash, global->bank.poh.hash));

  fd_funk_rec_persist(global->funk, rec);

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

static int
fd_global_import_stakes(fd_global_ctx_t * global, fd_solana_manifest_t * manifest) {
  ulong raw_stakes_sz = fd_stakes_size( &manifest->bank.stakes );
  void * raw_stakes = fd_valloc_malloc( global->valloc, 1UL, raw_stakes_sz );
  fd_memset( raw_stakes, 0, raw_stakes_sz );

  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = raw_stakes,
    .dataend = (void *)( (ulong)raw_stakes + raw_stakes_sz )
  };
  if( FD_UNLIKELY( 0!=fd_stakes_encode( &manifest->bank.stakes, &encode_ctx ) ) ) {
    FD_LOG_ERR(( "fd_stakes_encode failed" ));
  }

  fd_bincode_decode_ctx_t decode_ctx = {
    .data    = raw_stakes,
    .dataend = (void const *)( (ulong)raw_stakes + raw_stakes_sz ),
    /* TODO: Make this a instruction-scoped allocator */
    .valloc  = global->valloc,
  };
  if( FD_UNLIKELY( 0!=fd_stakes_decode( &global->bank.stakes, &decode_ctx ) ) ) {
    FD_LOG_ERR(( "fd_stakes_decode failed" ));
  }

  fd_vote_accounts_pair_t_mapnode_t * vote_accounts_pool = global->bank.stakes.vote_accounts.vote_accounts_pool;
  fd_vote_accounts_pair_t_mapnode_t * vote_accounts_root = global->bank.stakes.vote_accounts.vote_accounts_root;

  for( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum(vote_accounts_pool, vote_accounts_root);
    n;
    n = fd_vote_accounts_pair_t_map_successor(vote_accounts_pool, n)
  ) {
      /* Deserialize content */
    fd_bincode_decode_ctx_t vote_state_decode_ctx = {
      .data    = n->elem.value.data,
      .dataend = (void const *)( (ulong) n->elem.value.data +  n->elem.value.data_len ),
      /* TODO: Make this a instruction-scoped allocator */
      .valloc  = global->valloc,
    };

    fd_vote_state_versioned_t vote_state_versioned;
    if( FD_UNLIKELY( 0!=fd_vote_state_versioned_decode( &vote_state_versioned, &vote_state_decode_ctx ) ) ) {
      FD_LOG_ERR(( "fd_vote_state_versioned_decode failed" ));
    }

    fd_vote_block_timestamp_t vote_state_timestamp;
    switch( vote_state_versioned.discriminant ) {
    case fd_vote_state_versioned_enum_current:
      vote_state_timestamp = vote_state_versioned.inner.current.latest_timestamp;
      break;
    case fd_vote_state_versioned_enum_v0_23_5:
      vote_state_timestamp = vote_state_versioned.inner.v0_23_5.latest_timestamp;
      break;
    default:
      __builtin_unreachable();
    }

    if( vote_state_timestamp.slot!=0 || n->elem.stake!=0 ) {
      record_timestamp_vote_with_slot( global, &n->elem.key, vote_state_timestamp.timestamp, vote_state_timestamp.slot );
    }
  }

  fd_valloc_free( global->valloc, raw_stakes );

  return 0;
}

int fd_global_import_solana_manifest(fd_global_ctx_t * global, fd_solana_manifest_t * manifest) {
  /* Clean out prior bank */
  fd_bincode_destroy_ctx_t ctx = { .valloc = global->valloc };
  fd_firedancer_banks_t * bank = &global->bank;
  fd_firedancer_banks_destroy(bank, &ctx);
  fd_firedancer_banks_new(bank);

  fd_deserializable_versioned_bank_t * oldbank = &manifest->bank;
  fd_global_import_stakes( global, manifest );

  if ( oldbank->blockhash_queue.last_hash )
    fd_memcpy(&global->bank.poh, oldbank->blockhash_queue.last_hash, FD_SHA256_HASH_SZ);
  // bank->timestamp_votes = oldbank->timestamp_votes;
  bank->slot = oldbank->slot;
  fd_memcpy(&bank->banks_hash, &oldbank->hash, sizeof(oldbank->hash));
  fd_memcpy(&bank->fee_rate_governor, &oldbank->fee_rate_governor, sizeof(oldbank->fee_rate_governor));
  bank->lamports_per_signature = oldbank->fee_calculator.lamports_per_signature;
  if ( oldbank->hashes_per_tick )
    bank->hashes_per_tick = *oldbank->hashes_per_tick;
  else
    bank->hashes_per_tick = 0;
  bank->ticks_per_slot = oldbank->ticks_per_slot;
  fd_memcpy(&bank->ns_per_slot, &oldbank->ns_per_slot, sizeof(oldbank->ns_per_slot));
  bank->genesis_creation_time = oldbank->genesis_creation_time;
  bank->slots_per_year = oldbank->slots_per_year;
  bank->max_tick_height = oldbank->max_tick_height;
  bank->inflation = oldbank->inflation;
  bank->epoch_schedule = oldbank->rent_collector.epoch_schedule;
  bank->rent = oldbank->rent_collector.rent;
  fd_memcpy(&bank->collector_id, &oldbank->collector_id, sizeof(oldbank->collector_id));
  bank->collected = oldbank->collected_rent;

  return fd_runtime_save_banks( global );
}

void fd_update_feature(FD_FN_UNUSED fd_global_ctx_t * global, ulong * f, const char *key) {
  unsigned char              acct[32];
  fd_base58_decode_32( key,  (unsigned char *) acct);

  char * raw_acc_data = (char*) fd_acc_mgr_view_data(global->acc_mgr, global->funk_txn, (fd_pubkey_t *) acct, NULL, NULL);
  if (NULL == raw_acc_data)
    return;
  fd_account_meta_t *m = (fd_account_meta_t *) raw_acc_data;

  fd_feature_t feature;
  fd_feature_new(&feature);

  fd_bincode_decode_ctx_t ctx = {
    .data = raw_acc_data + m->hlen,
    .dataend = (char *) ctx.data + m->dlen,
    .valloc  = global->valloc,
  };
  if ( fd_feature_decode( &feature, &ctx ) )
    return;

  if (NULL != feature.activated_at)
    *f = *feature.activated_at;

  fd_bincode_destroy_ctx_t destroy = { .valloc = global->valloc };
  fd_feature_destroy( &feature, &destroy );
}
