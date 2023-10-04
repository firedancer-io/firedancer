#include "fd_acc_mgr.h"
#include "time.h"
#include "fd_runtime.h"
#include "fd_account.h"
#include "fd_hashes.h"
#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "sysvar/fd_sysvar.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/bmtree/fd_bmtree.h"

#include "../stakes/fd_stake_program.h"
#include "../rewards/fd_rewards.h"
#include "program/fd_system_program.h"
#include "program/fd_vote_program.h"
#include <stdio.h>
#include <ctype.h>

#define MICRO_LAMPORTS_PER_LAMPORT (1000000UL)

void
fd_runtime_init_bank_from_genesis( fd_global_ctx_t *     global,
                                   fd_genesis_solana_t * genesis_block,
                                   uchar                 genesis_hash[FD_SHA256_HASH_SZ] ) {
  global->bank.slot = 0;

  memcpy( &global->bank.poh, genesis_hash, FD_SHA256_HASH_SZ );
  memset( global->bank.banks_hash.hash, 0, FD_SHA256_HASH_SZ );

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

#define SECONDS_PER_YEAR ((double) (365.242199 * 24.0 * 60.0 * 60.0))

  global->bank.slots_per_year = SECONDS_PER_YEAR * (1000000000.0 / (double) target_tick_duration) / (double) global->bank.ticks_per_slot;
  global->bank.genesis_creation_time = genesis_block->creation_time;
  global->bank.max_tick_height = global->bank.ticks_per_slot * (global->bank.slot + 1);
  global->bank.epoch_schedule = genesis_block->epoch_schedule;
  global->bank.inflation = genesis_block->inflation;
  global->bank.rent = genesis_block->rent;
  global->bank.block_height = 0UL;

  fd_block_block_hash_entry_t * hashes = global->bank.recent_block_hashes.hashes =
    deq_fd_block_block_hash_entry_t_alloc( global->valloc );
  fd_block_block_hash_entry_t * elem = deq_fd_block_block_hash_entry_t_push_head_nocopy(hashes);
  fd_block_block_hash_entry_new(elem);
  fd_memcpy(elem->blockhash.hash, genesis_hash, FD_SHA256_HASH_SZ);
  elem->fee_calculator.lamports_per_signature = 0;

  global->signature_cnt = 0;

  /* Derive epoch stakes */

  ulong vote_acc_cnt = 0UL;
  for( ulong i=0UL; i < genesis_block->accounts_len; i++ ) {
    fd_pubkey_account_pair_t const * acc = &genesis_block->accounts[ i ];
    if( 0==memcmp( acc->account.owner.key, global->solana_vote_program, sizeof(fd_pubkey_t) ) )
      vote_acc_cnt++;
  }

  fd_vote_accounts_pair_t_mapnode_t * vacc_pool =
    fd_vote_accounts_pair_t_map_alloc( global->valloc, vote_acc_cnt++ );
  FD_TEST( vacc_pool );
  fd_vote_accounts_pair_t_mapnode_t * vacc_root = NULL;

  fd_delegation_pair_t_mapnode_t * sacc_pool = fd_delegation_pair_t_map_alloc(global->valloc, 10000);
  fd_delegation_pair_t_mapnode_t * sacc_root = NULL;

  fd_stake_history_entries_treap_t * stake_history_treap = fd_stake_history_entries_treap_alloc( global->valloc );
  fd_stake_history_epochentry_pair_t * stake_history_pool = fd_stake_history_entries_pool_alloc( global->valloc );

  fd_acc_lamports_t capitalization = 0UL;

  for( ulong i=0UL; i < genesis_block->accounts_len; i++ ) {
    fd_pubkey_account_pair_t const * acc = &genesis_block->accounts[ i ];
    capitalization = fd_ulong_sat_add( capitalization, acc->account.lamports );

    if( 0==memcmp( acc->account.owner.key, global->solana_vote_program, sizeof(fd_pubkey_t) ) ) {
      /* Vote Program Account */

      fd_vote_accounts_pair_t_mapnode_t * node =
        fd_vote_accounts_pair_t_map_acquire( vacc_pool );
      FD_TEST( node );

      fd_memcpy( node->elem.key.key, acc->key.key, sizeof(fd_pubkey_t) );
      node->elem.stake = acc->account.lamports;
      node->elem.value = (fd_solana_account_t) {
        .lamports   = acc->account.lamports,
        .data_len   = acc->account.data_len,
        .data       = fd_valloc_malloc( global->valloc, 1UL, acc->account.data_len ),
        .owner      = acc->account.owner,
        .executable = acc->account.executable,
        .rent_epoch = acc->account.rent_epoch
      };
      fd_memcpy( node->elem.value.data, acc->account.data, acc->account.data_len );

      fd_vote_accounts_pair_t_map_insert( vacc_pool, &vacc_root, node );

      FD_LOG_INFO(( "Adding genesis vote account: key=%32J stake=%lu",
                    node->elem.key.key,
                    node->elem.stake ));


    } else if ( 0==memcmp( acc->account.owner.key , global->solana_stake_program, sizeof(fd_pubkey_t ) ) ) {
      /* stake program account */
      fd_stake_state_t stake_state;

      fd_bincode_decode_ctx_t decode = {  .data    = acc->account.data,
                                          .dataend = acc->account.data + acc->account.data_len,
                                          .valloc  = global->valloc };
      FD_TEST( fd_stake_state_decode( &stake_state, &decode ) == 0);

      fd_delegation_pair_t_mapnode_t query_node;
      fd_memcpy( &query_node.elem.account, acc->key.key, sizeof(fd_pubkey_t) );
      fd_delegation_pair_t_mapnode_t * node = fd_delegation_pair_t_map_find( sacc_pool, sacc_root, &query_node);

      fd_vote_accounts_pair_t_mapnode_t query_voter;
      fd_pubkey_t * voter_pubkey = &stake_state.inner.stake.stake.delegation.voter_pubkey;
      fd_memcpy( &query_voter.elem.key, voter_pubkey, sizeof(fd_pubkey_t) );
      fd_vote_accounts_pair_t_mapnode_t * voter = fd_vote_accounts_pair_t_map_find( vacc_pool, vacc_root, &query_voter);

      if ( node == NULL ) {
        node = fd_delegation_pair_t_map_acquire( sacc_pool );
        fd_memcpy( &node->elem.account, acc->key.key, sizeof(fd_pubkey_t) );
        fd_memcpy( &node->elem.delegation, &stake_state.inner.stake.stake.delegation, sizeof(fd_delegation_t) );
        if (voter != NULL)
          voter->elem.stake = fd_ulong_sat_add(voter->elem.stake, stake_state.inner.stake.stake.delegation.stake);
        fd_delegation_pair_t_map_insert( sacc_pool, &sacc_root, node );
      } else {
        if (memcmp( &node->elem.delegation.voter_pubkey, voter_pubkey, sizeof(fd_pubkey_t)) != 0 || node->elem.delegation.stake != stake_state.inner.stake.stake.delegation.stake ) {
          // add stake to the new voter account
          if (voter != NULL)
            voter->elem.stake = fd_ulong_sat_add( voter->elem.stake, stake_state.inner.stake.stake.delegation.stake );

          // remove stake from the old voter account
          fd_memcpy( &query_voter.elem.key, &node->elem.delegation.voter_pubkey, sizeof(fd_pubkey_t) );
          voter = fd_vote_accounts_pair_t_map_find( vacc_pool, vacc_root, &query_voter);
          if (voter != NULL)
            voter->elem.stake = fd_ulong_sat_sub( voter->elem.stake, node->elem.delegation.stake );
        }
        fd_memcpy( &node->elem.account, acc->key.key, sizeof(fd_pubkey_t) );
        fd_memcpy( &node->elem.delegation, &stake_state.inner.stake.stake.delegation, sizeof(fd_delegation_t) );
      }
    } else if( 0==memcmp( acc->account.owner.key, global->solana_feature_program, sizeof(fd_pubkey_t) ) ) {
      /* Feature Account */

      /* Scan list of feature IDs to resolve address => feature offset */
      fd_feature_id_t const * found = NULL;
      for( fd_feature_id_t const * id = fd_feature_iter_init();
                                       !fd_feature_iter_done( id );
                                   id = fd_feature_iter_next( id ) ) {
        if( 0==memcmp( acc->key.key, id->id.key, sizeof(fd_pubkey_t) ) ) {
          found = id;
          break;
        }
      }

      if( found ) {
        /* Load feature activation */
        FD_SCRATCH_SCOPED_FRAME;
        fd_bincode_decode_ctx_t decode = { .data    = acc->account.data,
                                           .dataend = acc->account.data + acc->account.data_len,
                                           .valloc  = fd_scratch_virtual() };
        fd_feature_t feature;
        int err = fd_feature_decode( &feature, &decode );
        FD_TEST( err==FD_BINCODE_SUCCESS );
        if( feature.activated_at ) {
          FD_LOG_DEBUG(( "Feature %32J activated at %lu (genesis)", acc->key.key, *feature.activated_at ));
          *fd_features_ptr( &global->features, found ) = *feature.activated_at;
        } else {
          FD_LOG_DEBUG(( "Feature %32J not activated (genesis)", acc->key.key, *feature.activated_at ));
          *fd_features_ptr( &global->features, found ) = ULONG_MAX;
        }
      }

    }
  }

  global->bank.epoch_stakes = (fd_vote_accounts_t) {
    .vote_accounts_pool = vacc_pool,
    .vote_accounts_root = vacc_root,
  };

  /* Initializes the stakes cache in the Bank structure. */
  global->bank.stakes = (fd_stakes_t) {
    .stake_delegations_pool = sacc_pool,
    .stake_delegations_root = sacc_root,
    .epoch = 0,
    .unused = 0,
    .vote_accounts = (fd_vote_accounts_t) {
      .vote_accounts_pool = vacc_pool,
      .vote_accounts_root = vacc_root
    },
    .stake_history = (fd_stake_history_t) {
      .pool = stake_history_pool,
      .treap = stake_history_treap
    }
  };

  global->bank.capitalization = capitalization;

}

void
fd_runtime_init_program( fd_global_ctx_t * global ) {
  fd_sysvar_recent_hashes_init( global );
  fd_sysvar_clock_init( global );
  fd_sysvar_slot_history_init( global );
//  fd_sysvar_slot_hashes_init( global );
  fd_sysvar_epoch_schedule_init( global );
  fd_sysvar_fees_init( global );
  fd_sysvar_rent_init( global );
  fd_sysvar_stake_history_init( global );
  fd_sysvar_last_restart_slot_init( global );

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

  fd_solcap_writer_set_slot( global->capture, m->slot );
  if( global->bank.slot != 0 ) {
    ulong slot_idx;
    ulong new_epoch = fd_slot_to_epoch( &global->bank.epoch_schedule, m->slot, &slot_idx );
    FD_LOG_NOTICE(( "executing block - slot: %lu, epoch: %lu, slot_idx: %lu", m->slot, new_epoch, slot_idx ));
    if (slot_idx==1UL && new_epoch==0UL) {
      /* the block after genesis has a height of 1*/
      global->bank.block_height = 1UL;
    }
    if( slot_idx==0UL ) {
      /* Epoch boundary! */
      fd_process_new_epoch( global, new_epoch - 1UL );
    }
    if ( FD_FEATURE_ACTIVE( global, enable_partitioned_epoch_reward ) ) {
      distribute_partitioned_epoch_rewards(&global->bank, global);
    }

  }

  /* Get current leader */
  ulong slot_rel;
  fd_slot_to_epoch( &global->bank.epoch_schedule, m->slot, &slot_rel );
  global->leader = fd_epoch_leaders_get( global->leaders, m->slot );
  if (NULL == global->leader )
    FD_TEST( NULL != global->leader );
  FD_LOG_NOTICE(( "executing block - slot: %lu leader: %32J", m->slot, global->leader->key ));

  // let (fee_rate_governor, fee_components_time_us) = measure_us!(
  //     FeeRateGovernor::new_derived(&parent.fee_rate_governor, parent.signature_count())
  // );
  /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L1312-L1314 */
  fd_sysvar_fees_new_derived( global, global->bank.fee_rate_governor, global->signature_cnt );

  // TODO: move all these out to a fd_sysvar_update() call...
  fd_sysvar_clock_update( global );
  fd_sysvar_fees_update( global );
  // It has to go into the current txn previous info but is not in slot 0
  if (global->bank.slot != 0)
    fd_sysvar_slot_hashes_update( global );
  fd_sysvar_last_restart_slot_update( global );

  ulong signature_cnt = 0;
  ulong blockoff = 0;
  ulong txn_idx_in_block = 1;
  ulong total_mblks = 0;
  while (blockoff < blocklen) {
    if ( blockoff + sizeof(ulong) > blocklen )
      FD_LOG_ERR(("premature end of block"));
    ulong mcount = *(const ulong *)((const uchar *)block + blockoff);
    blockoff += sizeof(ulong);

    /* Loop across microblocks */
    for (ulong mblk = 0; mblk < mcount; ++mblk, ++total_mblks) {
      if ( blockoff + sizeof(fd_microblock_hdr_t) > blocklen )
        FD_LOG_ERR(("premature end of block"));
      fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)((const uchar *)block + blockoff);
      blockoff += sizeof(fd_microblock_hdr_t);

      /* Loop across transactions */
      for ( ulong txn_idx = 0; txn_idx < hdr->txn_cnt; txn_idx++ ) {
        uchar txn_out[FD_TXN_MAX_SZ];
        ulong pay_sz = 0;
        const uchar* raw = (const uchar *)block + blockoff;
        ulong txn_sz = fd_txn_parse_core(raw, fd_ulong_min(blocklen - blockoff, FD_TXN_MTU), txn_out, NULL, &pay_sz, 0);
        if ( txn_sz == 0 || txn_sz > FD_TXN_MTU ) {
          txn_sz = fd_txn_parse_core(raw, fd_ulong_min(blocklen - blockoff, FD_TXN_MTU), txn_out, NULL, &pay_sz, 0);
          FD_LOG_ERR(("failed to parse transaction -  slot: %lu, txn_idx_in_block: %lu, mblk: %lu, txn_idx: %lu", global->bank.slot, txn_idx_in_block, mblk, txn_idx));
        }

        fd_txn_t* txn = (fd_txn_t *)txn_out;
        fd_rawtxn_b_t rawtxn;
        rawtxn.raw = (void*)raw;
        rawtxn.txn_sz = (ushort)txn_sz;
        signature_cnt += txn->signature_cnt;

        char sig[FD_BASE58_ENCODED_64_SZ];
        fd_base58_encode_64(raw+txn->signature_off, NULL, sig);
        FD_LOG_NOTICE(("executing txn - slot: %lu, txn_idx_in_block: %lu, mblk: %lu, txn_idx: %lu, sig: %s", global->bank.slot, txn_idx_in_block, total_mblks, txn_idx, sig));
        fd_pubkey_t const * txn_accs = (fd_pubkey_t *)((uchar *)rawtxn.raw + txn->acct_addr_off);
        for (ulong i = 0; i < txn->acct_addr_cnt; i++) {
          FD_BORROWED_ACCOUNT_DECL(accs_rec);
          int err = fd_acc_mgr_view(global->acc_mgr, global->funk_txn, &txn_accs[i], accs_rec);
          if( FD_UNLIKELY( err ==FD_ACC_MGR_SUCCESS ) )
            FD_LOG_WARNING(("ACCT FOR TXN: %lu - %32J, lamps: %lu", i, &txn_accs[i], accs_rec->const_meta->info.lamports));
        }

        fd_txn_acct_addr_lut_t * addr_luts = fd_txn_get_address_tables( txn );
        for (ulong i = 0; i < txn->addr_table_lookup_cnt; i++) {
          fd_txn_acct_addr_lut_t * addr_lut = &addr_luts[i];
          fd_pubkey_t const * addr_lut_acc = (fd_pubkey_t *)((uchar *)rawtxn.raw + addr_lut->addr_off);

          FD_BORROWED_ACCOUNT_DECL(lut_acc_rec);
          int err = fd_acc_mgr_view(global->acc_mgr, global->funk_txn, (fd_pubkey_t *) addr_lut_acc, lut_acc_rec);
          if( FD_UNLIKELY( err !=FD_ACC_MGR_SUCCESS ) )
            FD_LOG_ERR(( "addr lut not found" ));

          FD_LOG_WARNING(( "LUT ACC: idx: %lu, acc: %32J, meta.dlen; %lu", i, addr_lut_acc, lut_acc_rec->const_meta->dlen ));

          fd_address_lookup_table_state_t addr_lookup_table_state;
          fd_bincode_decode_ctx_t decode_ctx = {
            .data = lut_acc_rec->const_data,
            .dataend = &lut_acc_rec->const_data[56], // TODO macro const.
            .valloc  = global->valloc,
          };
          if (fd_address_lookup_table_state_decode( &addr_lookup_table_state, &decode_ctx )) {
            FD_LOG_ERR(("fd_address_lookup_table_state_decode failed"));
          }
          if (addr_lookup_table_state.discriminant != fd_address_lookup_table_state_enum_lookup_table) {
            FD_LOG_ERR(("addr lut is uninit"));
          }

          fd_pubkey_t * lookup_addrs = (fd_pubkey_t *)&lut_acc_rec->const_data[56];
          uchar * writable_lut_idxs = (uchar *)rawtxn.raw + addr_lut->writable_off;
          for (ulong j = 0; j < addr_lut->writable_cnt; j++) {
            FD_LOG_WARNING(( "LUT ACC WRITABLE: idx: %3lu, acc: %32J, lut_idx: %3lu, acct_idx: %3lu, %32J", i, addr_lut_acc, j, writable_lut_idxs[j], &lookup_addrs[writable_lut_idxs[j]] ));
          }

          uchar * readonly_lut_idxs = (uchar *)rawtxn.raw + addr_lut->readonly_off;
          for (ulong j = 0; j < addr_lut->readonly_cnt; j++) {
            FD_LOG_WARNING(( "LUT ACC READONLY: idx: %3lu, acc: %32J, lut_idx: %3lu, acct_idx: %3lu, %32J", i, addr_lut_acc, j, readonly_lut_idxs[j], &lookup_addrs[readonly_lut_idxs[j]] ));
          }
        }
        fd_execute_txn( global, txn, &rawtxn );

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

  fd_bmtree_commit_t commit_mem[1];

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

        fd_bmtree_commit_t * tree = fd_bmtree_commit_init( commit_mem, 32UL, 1UL, 0UL );

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
            fd_bmtree_node_t leaf;
            fd_bmtree_hash_leaf( &leaf, &sigs[j], sizeof(fd_ed25519_sig_t) , 1);
            fd_bmtree_commit_append( tree, (fd_bmtree_node_t const *)&leaf, 1 );
          }

          blockoff += pay_sz;
        }

        uchar * root = fd_bmtree_commit_fini( tree );
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
  struct fd_runtime_block_micro * micro = (struct fd_runtime_block_micro *)tpool + m0;
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

    fd_bmtree_commit_t commit_mem[1];

    fd_bmtree_commit_t * tree = fd_bmtree_commit_init( commit_mem, 32UL, 1UL, 0UL );

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
        fd_bmtree_node_t leaf;
        fd_bmtree_hash_leaf( &leaf, &sigs[j], sizeof(fd_ed25519_sig_t), 1 );
        fd_bmtree_commit_append( tree, (fd_bmtree_node_t const *)&leaf, 1 );
      }

      blockoff += pay_sz;
    }

    uchar * root = fd_bmtree_commit_fini( tree );
    fd_poh_mixin(&micro->poh, root);
  }

  micro->failed = (memcmp(hdr->hash, &micro->poh, sizeof(micro->poh)) ? 1 : 0);

  if (micro->failed)
    FD_LOG_ERR(( "poh missmatch at slot %ld, microblock %lu", stride, m0));

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
        // parallel prefix-sum ?
        ulong pay_sz = fd_txn_xray(raw, blocklen - blockoff, &xray);
        if ( pay_sz == 0UL )
          FD_LOG_ERR(("failed to parse transaction %lu in microblock %lu in slot %lu", txn_idx, mblk, m->slot));
        blockoff += pay_sz;
      }
    }
  }
  if (blockoff != blocklen)
    FD_LOG_ERR(("garbage at end of block"));

  /* Spawn jobs to thread pool
    Note here: we repurposed the usage of `stride` variable here for the slot number `m->slot` to get out the same error message as before
   */
  fd_tpool_exec_all_taskq( tpool, 0, max_workers, fd_runtime_block_verify_task, micros, NULL, NULL, m->slot, 0, num_micros);

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
fd_runtime_txn_lamports_per_signature( fd_global_ctx_t *global, transaction_ctx_t * txn_ctx, fd_txn_t * txn_descriptor, fd_rawtxn_b_t const * txn_raw ) {
  // why is asan not detecting access to uninitialized memory here?!
  fd_nonce_state_versions_t state;
  int err;
  if ((NULL != txn_descriptor) && fd_load_nonce_account(global, txn_ctx, txn_descriptor, txn_raw, &state, &err)) {
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
      return;
    }
    default:
      __builtin_unreachable();
  }
}

ulong
fd_runtime_calculate_fee( fd_global_ctx_t *     global,
                          transaction_ctx_t *   txn_ctx,
                          fd_txn_t *            txn_descriptor,
                          fd_rawtxn_b_t const * txn_raw ) {

// https://github.com/firedancer-io/solana/blob/08a1ef5d785fe58af442b791df6c4e83fe2e7c74/runtime/src/bank.rs#L4443
// TODO: implement fee distribution to the collector ... and then charge us the correct amount
  ulong priority = 0;
  ulong priority_fee = 0;
  compute_priority_fee(txn_ctx, &priority_fee, &priority);
  ulong lamports_per_signature = fd_runtime_txn_lamports_per_signature(global, txn_ctx, txn_descriptor, txn_raw);

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
  double write_lock_fee = (double)fd_ulong_sat_mul( fd_txn_account_cnt( txn_descriptor, FD_TXN_ACCT_CAT_WRITABLE ), lamports_per_write_lock );

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
  }

  if (fee >= (double)ULONG_MAX)
    return ULONG_MAX;
  else
    return (ulong) fee;
}

/* sadness */

//static double
//fd_slots_per_year( ulong ticks_per_slot,
//                   ulong ns_per_tick ) {
//  return 365.242199 * 24.0 * 60.0 * 60.0
//    * (1000000000.0 / (double)ns_per_tick)
//    / (double)ticks_per_slot;
//}

#define FD_RENT_EXEMPT (-1L)

static long
fd_rent_due( fd_account_meta_t *         acc,
             ulong                       epoch,
             fd_rent_t const *           rent,
             fd_epoch_schedule_t const * schedule,
             double                      slots_per_year ) {

  fd_solana_account_meta_t * info = &acc->info;

  /* Nothing due if account is rent-exempt */

  ulong min_balance = fd_rent_exempt_minimum_balance2( rent, acc->dlen );
  if( info->lamports >= min_balance ) {
    return FD_RENT_EXEMPT;
  }

  /* Count the number of slots that have passed since last collection */

  ulong slots_elapsed = 0UL;
  if( FD_LIKELY( epoch >= schedule->first_normal_epoch ) ) {
    slots_elapsed = (epoch - info->rent_epoch) * schedule->slots_per_epoch;
  } else {
    for( ulong i = info->rent_epoch; i<epoch; i++ ) {
      slots_elapsed += fd_epoch_slot_cnt( schedule, i );
    }
  }
  /* Consensus-critical use of doubles :( */

  double years_elapsed;
  if( FD_LIKELY( slots_per_year != 0.0 ) ) {
    years_elapsed = (double)slots_elapsed / slots_per_year;
  } else {
    years_elapsed = 0.0;
  }

  ulong lamports_per_year = rent->lamports_per_uint8_year * (acc->dlen + 128UL);
  return (long)(ulong)( years_elapsed * (double)lamports_per_year );
}

/* fd_runtime_collect_rent_account performs rent collection duties.
   Although the Solana runtime prevents the creation of new accounts
   that are subject to rent, some older accounts are still undergo the
   rent collection process.  Updates the account's 'rent_epoch' if
   needed. Returns 1 if the account was changed, and 0 if it is
   unchanged. */

static int
fd_runtime_collect_rent_account( fd_global_ctx_t *   global,
                                 fd_account_meta_t * acc,
                                 fd_pubkey_t const * key,
                                 ulong               epoch ) {

  // RentCollector::collect_from_existing_account (enter)
  // RentCollector::calculate_rent_result         (enter)

  fd_solana_account_meta_t * info = &acc->info;

  // RentCollector::can_skip_rent_collection (enter)
  // RentCollector::should_collect_rent      (enter)

  if( info->executable ) return 0;

  /* TODO this is dumb */
  fd_pubkey_t incinerator;
  fd_base58_decode_32( "1nc1nerator11111111111111111111111111111111", incinerator.key );
  if( 0==memcmp( key, &incinerator, sizeof(fd_pubkey_t) ) ) return 0;

  // RentCollector::should_collect_rent      (exit)
  // RentCollector::can_skip_rent_collection (exit)

  // RentCollector::get_rent_due
  long due = fd_rent_due( acc, epoch + 1,
      &global->bank.rent,
      &global->bank.epoch_schedule,
       global->bank.slots_per_year );

  /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/accounts-db/src/rent_collector.rs#L170-L182 */

  /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/accounts-db/src/rent_collector.rs#L117-L146 */

  /* RentResult: Exempt situation of fn collect_from_existing_account */
  if( due == FD_RENT_EXEMPT ) {
    /* let set_exempt_rent_epoch_max: bool = self
            .feature_set
            .is_active(&solana_sdk::feature_set::set_exempt_rent_epoch_max::id()); */
    /* entry point here: https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L5972-L5982 */
    if( FD_FEATURE_ACTIVE( global, set_exempt_rent_epoch_max ) ) {
      info->rent_epoch = ULONG_MAX;
      return 0;
    }

    return 1;
  }

  // RentCollector::calculate_rent_result (cont)

  if( due == 0L ) {
    return 0;
  }

  info->rent_epoch = epoch + 1UL;

  // RentCollector::calculate_rent_result         (exit)
  // RentCollector::collect_from_existing_account (cont)

  ulong due_ = (ulong)due;
  if( FD_UNLIKELY( due_ >= info->lamports ) ) {
    global->bank.collected_rent += info->lamports;
    acc->info.lamports = 0UL;
    fd_memset(acc->info.owner, 0, sizeof(acc->info.owner));
    acc->dlen = 0;

    return 1;
  }

  info->lamports -= (ulong)due;
  global->bank.collected_rent += (ulong)due;
  return 1;

  // RentCollector::collect_from_existing_account (exit)
}

static int
fd_runtime_collect_rent_cb( fd_funk_rec_t const * encountered_rec_ro,
                            void *                arg ) {

  fd_global_ctx_t *   global   = (fd_global_ctx_t *)arg;
  fd_funk_txn_t *     txn      = global->funk_txn;
  fd_acc_mgr_t *      acc_mgr  = global->acc_mgr;
  fd_pubkey_t const * key      = fd_type_pun_const( &encountered_rec_ro->pair.key[0].uc );

  FD_BORROWED_ACCOUNT_DECL(rec);
  int err = fd_acc_mgr_view( acc_mgr, txn, key, rec);

  /* Account might not exist anymore in the current world */
  if( err==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
    return 0; /* Don't walk again */
  }
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "fd_runtime_collect_rent_cb: fd_acc_mgr_view failed (%d)", err ));
    return 0; /* Don't walk again */
  }

  /* Filter accounts that we've already visited */
  ulong epoch = global->rent_epoch;
  if( rec->const_meta->info.rent_epoch > epoch ) return 1;

  /* Upgrade read-only handle to writable */
  err = fd_acc_mgr_modify(
    acc_mgr, txn, key,
      /* do_create   */ 0,
      /* min_data_sz */ 0UL,
                        rec);
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "fd_runtime_collect_rent_range: fd_acc_mgr_modify failed (%d)", err ));
    return err;
  }

  /* Actually invoke rent collection */
  (void) fd_runtime_collect_rent_account( global, rec->meta, key, epoch );

  if ( !FD_FEATURE_ACTIVE( global, skip_rent_rewrites ) )
    // By changing the slot, this forces the account to be updated
    // in the account_delta_hash which matches the "rent rewrite"
    // behavior in solana.
    rec->meta->slot = global->bank.slot;

  return 1;
}

static void
fd_runtime_collect_rent( fd_global_ctx_t * global ) {
  // Bank::collect_rent_eagerly (enter)

  fd_epoch_schedule_t const * schedule = &global->bank.epoch_schedule;

  // Bank::rent_collection_partitions              (enter)
  // Bank::variable_cycle_partitions               (enter)
  // Bank::variable_cycle_partitions_between_slots (enter)

  ulong slot0 = global->bank.prev_slot;
  ulong slot1 = global->bank.slot;

  /* TODO For whatever reason, when replaying from genesis, our slot0 is
     ULONG_MAX */
  if( slot0==ULONG_MAX ) slot0 = 0UL;
  FD_TEST( slot0<=slot1 );

  for( ulong s = slot0+1; s <= slot1; ++s ) {
    ulong off;
    ulong epoch = fd_slot_to_epoch( schedule, s, &off );

    /* Reconstruct rent lists if the number of slots per epoch changes */
    if ( fd_rent_lists_get_slots_per_epoch( global->rentlists ) != fd_epoch_slot_cnt( schedule, epoch ) ) {
      fd_rent_lists_delete( global->rentlists);
      global->rentlists = fd_rent_lists_new(fd_epoch_slot_cnt( schedule, epoch ));
      fd_funk_set_notify(global->funk, fd_rent_lists_cb, global->rentlists);
      fd_rent_lists_startup_done(global->rentlists);
    }

    global->rent_epoch = epoch;
    fd_rent_lists_walk( global->rentlists, off, fd_runtime_collect_rent_cb, global );
  }

  FD_LOG_NOTICE(( "Rent collected - lamports: %lu", global->bank.collected_rent ));
}

ulong
fd_runtime_calculate_rent_burn( ulong rent_collected, fd_rent_t const * rent ) {
  return ( rent_collected * rent->burn_percent ) / 100;
}


struct fd_validator_stake_pair {
  fd_pubkey_t pubkey;
  ulong       stake;
};
typedef struct fd_validator_stake_pair fd_validator_stake_pair_t;

int
fd_validator_stake_pair_compare_before( fd_validator_stake_pair_t const * a,
                                        fd_validator_stake_pair_t const * b ) {
  if( a->stake > b->stake ) {
    return 1;
  } else if ( a->stake == b->stake ) {
    return memcmp( &a->pubkey, &b->pubkey, sizeof( fd_pubkey_t ) ) < 0;
  } else { // a->stake < b->stake
    return 0;
  }
}

#define SORT_NAME sort_validator_stake_pair
#define SORT_KEY_T fd_validator_stake_pair_t
#define SORT_BEFORE(a,b) (fd_validator_stake_pair_compare_before((fd_validator_stake_pair_t const *)&a, (fd_validator_stake_pair_t const *)&b))
#include "../../util/tmpl/fd_sort.c"
#undef SORT_NAME
#undef SORT_KEY_T
#undef SORT_BERFORE

void
fd_runtime_distribute_rent_to_validators( fd_global_ctx_t * global, ulong rent_to_be_distributed ) {
  ulong total_staked = 0;

  fd_vote_accounts_pair_t_mapnode_t * vote_accounts_pool = global->bank.stakes.vote_accounts.vote_accounts_pool;
  fd_vote_accounts_pair_t_mapnode_t * vote_accounts_root = global->bank.stakes.vote_accounts.vote_accounts_root;

  ulong num_validator_stakes = fd_vote_accounts_pair_t_map_size( vote_accounts_pool, vote_accounts_root );
  fd_validator_stake_pair_t * validator_stakes = fd_valloc_malloc( global->valloc, 1UL, sizeof( fd_validator_stake_pair_t ) * num_validator_stakes );
  ulong i = 0;

  fd_bincode_destroy_ctx_t destroy_ctx = { .valloc = global->valloc };
  for( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum(vote_accounts_pool, vote_accounts_root);
    n;
    n = fd_vote_accounts_pair_t_map_successor(vote_accounts_pool, n), i++
  ) {
    fd_vote_state_versioned_t vote_state_versioned;
    fd_vote_state_versioned_new( &vote_state_versioned );
    fd_bincode_decode_ctx_t decode_ctx = {
      .data = n->elem.value.data,
      .dataend = &n->elem.value.data[n->elem.value.data_len],
      .valloc  = global->valloc,
    };
    if ( fd_vote_state_versioned_decode( &vote_state_versioned, &decode_ctx ) ) {
      FD_LOG_WARNING(("fd_vote_state_versioned_decode failed"));
      return;
    }

    validator_stakes[i].pubkey = vote_state_versioned.inner.current.node_pubkey;
    validator_stakes[i].stake = n->elem.stake;

    total_staked += n->elem.stake;

    fd_vote_state_versioned_destroy( &vote_state_versioned, &destroy_ctx );
  }

  sort_validator_stake_pair_inplace( validator_stakes, num_validator_stakes );

  ulong enforce_fix = global->features.no_overflow_rent_distribution;

  ulong rent_distributed_in_initial_round = 0;

  // We now do distribution, reusing the validator stakes array for the rent stares
  if( enforce_fix ) {
    for( i = 0; i < num_validator_stakes; i++ ) {
      ulong staked = validator_stakes[i].stake;
      ulong rent_share = (ulong)( ( (uint128)staked * (uint128)rent_to_be_distributed ) / (uint128)total_staked );

      validator_stakes[i].stake = rent_share;
      rent_distributed_in_initial_round += rent_share;
    }
  } else {
    // TODO: implement old functionality!
    FD_LOG_ERR(( "unimplemented feature" ));
  }

  ulong leftover_lamports = rent_to_be_distributed - rent_distributed_in_initial_round;

  for( i = 0; i < num_validator_stakes; i++ ) {
    if( leftover_lamports == 0 ) {
      break;
    }

    leftover_lamports--;
    validator_stakes[i].stake++;
  }

  for( i = 0; i < num_validator_stakes; i++ ) {
    ulong rent_to_be_paid = validator_stakes[i].stake;

    // TODO: handle the prevent_rent_paying_rent_recipients feature
    if( !enforce_fix || rent_to_be_paid > 0 ) {
      fd_pubkey_t pubkey = validator_stakes[i].pubkey;

      FD_BORROWED_ACCOUNT_DECL(rec);

      int err = fd_acc_mgr_modify( global->acc_mgr, global->funk_txn, &pubkey, 0, 0UL, rec );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "fd_acc_mgr_modify_raw failed (%d)", err ));
      }

      rec->meta->info.lamports += rent_to_be_paid;

      err = fd_acc_mgr_commit_raw(global->acc_mgr, rec->rec, &pubkey, rec->meta, global->bank.slot);
      if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
        FD_LOG_WARNING(( "fd_runtime_distribute_rent_to_validators: fd_acc_mgr_commit_raw failed (%d)", err ));
      }
    }
  } // end of iteration over validator_stakes
  if (enforce_fix) {
    FD_TEST( leftover_lamports == 0);
  } else {
    ulong old = global->bank.capitalization;
    global->bank.capitalization = fd_ulong_sat_sub( global->bank.capitalization, leftover_lamports);
    FD_LOG_WARNING(( "fd_runtime_distribute_rent_to_validators: burn %lu, capitalization %ld->%ld ", leftover_lamports, old, global->bank.capitalization));
  }
  fd_valloc_free( global->valloc, validator_stakes );
}

void
fd_runtime_distribute_rent( fd_global_ctx_t * global ) {
  ulong total_rent_collected = global->bank.collected_rent;
  ulong burned_portion = fd_runtime_calculate_rent_burn( total_rent_collected, &global->bank.rent );
  ulong rent_to_be_distributed = total_rent_collected - burned_portion;

  FD_LOG_NOTICE(( "rent distribution - slot: %lu, burned_lamports: %lu, distributed_lamports: %lu, total_rent_collected: %lu", global->bank.slot, burned_portion, rent_to_be_distributed, total_rent_collected ));
  if( rent_to_be_distributed == 0 ) {
    return;
  }

  fd_runtime_distribute_rent_to_validators( global, rent_to_be_distributed );
}

void
fd_runtime_freeze( fd_global_ctx_t * global ) {
  // solana/runtime/src/bank.rs::freeze(....)
  fd_runtime_collect_rent( global );
  //self.collect_fees();

  fd_sysvar_recent_hashes_update ( global );

  if (global->bank.collected_fees > 0) {
    // Look at collect_fees... I think this was where I saw the fee payout..
    FD_BORROWED_ACCOUNT_DECL(rec);

    int err = fd_acc_mgr_modify( global->acc_mgr, global->funk_txn, global->leader, 0, 0UL, rec );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "fd_runtime_freeze: fd_acc_mgr_modify_raw for leader (%32J) failed (%d)", global->leader, err ));
      return;
    }

    ulong fees = ( global->bank.collected_fees / 2 );

    if (FD_UNLIKELY(global->log_level > 2))
      FD_LOG_WARNING(( "fd_runtime_freeze: slot:%ld global->collected_fees: %ld, sending %ld to leader (%32J), burning %ld", global->bank.slot, global->bank.collected_fees, fees, global->leader, fees ));

    rec->meta->info.lamports += fees;

    ulong old = global->bank.capitalization;
    global->bank.capitalization = fd_ulong_sat_sub( global->bank.capitalization, fees);
    FD_LOG_WARNING(( "fd_runtime_freeze: burn %lu, capitalization %ld->%ld ", fees, old, global->bank.capitalization));

    global->bank.collected_fees = 0;
  }

  //self.distribute_rent();
  //self.update_slot_history();
  //self.run_incinerator();

  fd_runtime_distribute_rent( global );

  global->bank.collected_rent = 0;
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

  self->rng  = fd_rng_join( fd_rng_new(&self->rnd_mem, (uint) time(0), 0) );;

  fd_firedancer_banks_new(&self->bank);

  // all features are disabled by default.
  fd_features_disable_all(&self->features);

  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (unsigned char *) self->sysvar_owner);
  fd_base58_decode_32( "SysvarRecentB1ockHashes11111111111111111111",  (unsigned char *) self->sysvar_recent_block_hashes);
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (unsigned char *) self->sysvar_clock);
  fd_base58_decode_32( "SysvarS1otHistory11111111111111111111111111",  (unsigned char *) self->sysvar_slot_history);
  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (unsigned char *) self->sysvar_slot_hashes);
  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (unsigned char *) self->sysvar_epoch_schedule);
  fd_base58_decode_32( "SysvarFees111111111111111111111111111111111",  (unsigned char *) self->sysvar_fees);
  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (unsigned char *) self->sysvar_rent);
  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (unsigned char *) self->sysvar_stake_history);
  fd_base58_decode_32( "SysvarLastRestartS1ot1111111111111111111111",  (unsigned char *) self->sysvar_last_restart_slot);
  fd_base58_decode_32( "Sysvar1nstructions1111111111111111111111111",  (unsigned char *) self->sysvar_instructions);
  fd_base58_decode_32( "SysvarEpochRewards1111111111111111111111111",  (unsigned char *) self->sysvar_epoch_rewards);

  fd_base58_decode_32( "NativeLoader1111111111111111111111111111111",  (unsigned char *) self->solana_native_loader);
  fd_base58_decode_32( "Feature111111111111111111111111111111111111",                    self->solana_feature_program);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) self->solana_config_program);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) self->solana_stake_program);
  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (unsigned char *) self->solana_stake_program_config);
  fd_base58_decode_32( "11111111111111111111111111111111",             (unsigned char *) self->solana_system_program);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) self->solana_vote_program);
  fd_base58_decode_32( "BPFLoader1111111111111111111111111111111111",  (unsigned char *) self->solana_bpf_loader_deprecated_program);
  fd_base58_decode_32( "BPFLoader2111111111111111111111111111111111",  (unsigned char *) self->solana_bpf_loader_program);
  fd_base58_decode_32( "BPFLoaderUpgradeab1e11111111111111111111111",  (unsigned char *) self->solana_bpf_loader_upgradeable_program);
  fd_base58_decode_32( "LoaderV411111111111111111111111111111111111",                    self->solana_bpf_loader_v4_program->key);

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
fd_pubkey_create_with_seed( uchar const  base [ static 32 ],
                            char const * seed,
                            ulong        seed_sz,
                            uchar const  owner[ static 32 ],
                            uchar        out  [ static 32 ] ) {
//  if seed.len() > MAX_SEED_LEN {
//      return Err(PubkeyError::MaxSeedLengthExceeded);
//    }

  if (seed_sz > MAX_SEED_LEN)
    return FD_EXECUTOR_SYSTEM_ERR_MAX_SEED_LENGTH_EXCEEDED;

  if( memcmp( &owner[32UL - sizeof(PDA_MARKER)-1], PDA_MARKER, sizeof(PDA_MARKER)-1 ) == 0)
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

  fd_sha256_append( &sha, base,  32UL    );
  fd_sha256_append( &sha, seed,  seed_sz );
  fd_sha256_append( &sha, owner, 32UL    );

  fd_sha256_fini( &sha, out );

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

  uchar * buf = fd_funk_val( rec, fd_funk_wksp(global->funk) );
  fd_bincode_encode_ctx_t ctx = {
    .data = buf,
    .dataend = buf + sz,
  };
  if( FD_UNLIKELY( fd_firedancer_banks_encode( &global->bank, &ctx )!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_WARNING(( "fd_runtime_save_banks: fd_firedancer_banks_encode failed" ));
    return -1;
  }

  FD_LOG_NOTICE(( "Slot frozen, slot=%d bank_hash=%32J poh_hash=%32J", global->bank.slot, global->bank.banks_hash.hash, global->bank.poh.hash ));
  global->bank.block_height += 1UL;

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

static int
fd_global_import_stakes(fd_global_ctx_t * global, fd_solana_manifest_t * manifest) {
  // ulong epoch = fd_slot_to_epoch( &global->bank.epoch_schedule, global->bank.slot, NULL );
  // fd_epoch_stakes_t const * stakes = NULL;
  // fd_epoch_epoch_stakes_pair_t const * epochs = manifest->bank.epoch_stakes;
  // for( ulong i=0; i < manifest->bank.epoch_stakes_len; i++ ) {
  //   if( epochs[ i ].key==epoch ) {
  //     stakes = &epochs[i].value;
  //     break;
  //   }
  // }


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
      vote_state_timestamp = vote_state_versioned.inner.current.last_timestamp;
      break;
    case fd_vote_state_versioned_enum_v0_23_5:
      vote_state_timestamp = vote_state_versioned.inner.v0_23_5.last_timestamp;
      break;
    case fd_vote_state_versioned_enum_v1_14_11:
      vote_state_timestamp = vote_state_versioned.inner.v1_14_11.last_timestamp;
      break;
    default:
      __builtin_unreachable();
    }

    if( vote_state_timestamp.slot!=0 || n->elem.stake!=0 ) {
      fd_vote_record_timestamp_vote_with_slot( global, &n->elem.key, vote_state_timestamp.timestamp, vote_state_timestamp.slot );
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
  bank->prev_slot = oldbank->parent_slot;
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
  bank->collected_rent = oldbank->collected_rent;
  bank->collected_fees = oldbank->collector_fees;
  bank->capitalization = oldbank->capitalization;
  bank->block_height = oldbank->block_height;

  /* Update last restart slot
     https://github.com/solana-labs/solana/blob/30531d7a5b74f914dde53bfbb0bc2144f2ac92bb/runtime/src/bank.rs#L2152

     oldbank->hard_forks is sorted ascending by slot number.
     To find the last restart slot, take the highest hard fork slot
     number that is less or equal than the current slot number.
     (There might be some hard forks in the future, ignore these) */
  do {
    bank->last_restart_slot.slot = 0UL;
    if( FD_UNLIKELY( oldbank->hard_forks.hard_forks_len==0 ) ) {
      FD_LOG_WARNING(( "Snapshot missing hard forks. What is the correct 'last restart slot' value?" ));
      break;
    }

    fd_slot_pair_t const * head = oldbank->hard_forks.hard_forks;
    fd_slot_pair_t const * tail = head + oldbank->hard_forks.hard_forks_len - 1UL;

    for( fd_slot_pair_t const * pair = tail; pair >= head; pair-- ) {
      if( pair->slot <= bank->slot ) {
        bank->last_restart_slot.slot = pair->slot;
        break;
      }
    }
  } while(0);

  /* Find EpochStakes for next slot */
  {
    FD_SCRATCH_SCOPED_FRAME;

    ulong epoch = fd_slot_to_epoch( &bank->epoch_schedule, bank->slot, NULL );
    fd_epoch_stakes_t const * stakes = NULL;
    fd_epoch_epoch_stakes_pair_t const * epochs = oldbank->epoch_stakes;
    for( ulong i=0; i < manifest->bank.epoch_stakes_len; i++ ) {
      if( epochs[ i ].key==epoch ) {
        stakes = &epochs[i].value;
        break;
      }
    }

    if( FD_UNLIKELY( !stakes ) )
      FD_LOG_ERR(( "Snapshot missing EpochStakes for epoch %lu", epoch ));

    /* TODO Hacky way to copy by serialize/deserialize :( */
    fd_vote_accounts_t const * vaccs = &stakes->stakes.vote_accounts;
    ulong   bufsz = fd_vote_accounts_size( vaccs );
    uchar * buf   = fd_scratch_alloc( 1UL, bufsz );
    fd_bincode_encode_ctx_t encode_ctx = {
      .data    = buf,
      .dataend = (void *)( (ulong)buf + bufsz )
    };
    FD_TEST( fd_vote_accounts_encode( vaccs, &encode_ctx )
             ==FD_BINCODE_SUCCESS );
    fd_bincode_decode_ctx_t decode_ctx = {
      .data    = buf,
      .dataend = (void const *)( (ulong)buf + bufsz ),
      .valloc  = global->valloc,
    };
    FD_TEST( fd_vote_accounts_decode( &bank->epoch_stakes, &decode_ctx )
             ==FD_BINCODE_SUCCESS );
  }

  return fd_runtime_save_banks( global );
}

/* fd_feature_restore loads a feature from the accounts database and
   updates the bank's feature activation state, given a feature account
   address. */

static void
fd_feature_restore( fd_global_ctx_t * global,
                    ulong *           f,
                    uchar const       acct[ static 32 ] ) {

  FD_BORROWED_ACCOUNT_DECL(acct_rec);
  int err = fd_acc_mgr_view(global->acc_mgr, global->funk_txn, (fd_pubkey_t *) acct, acct_rec);
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) )
    return;

  fd_feature_t feature[1];

  FD_SCRATCH_SCOPED_FRAME;

  fd_bincode_decode_ctx_t ctx = {
    .data    = acct_rec->const_data,
    .dataend = acct_rec->const_data + acct_rec->const_meta->dlen,
    .valloc  = fd_scratch_virtual(),
  };
  int decode_err = fd_feature_decode( feature, &ctx );
  if( FD_UNLIKELY( decode_err!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_ERR(( "Failed to decode feature account %32J (%d)", acct, decode_err ));
    return;
  }

  if( feature->activated_at ) {
    FD_LOG_DEBUG(( "Feature %32J activated at %lu", acct, *feature->activated_at ));
    *f = *feature->activated_at;
  }

  /* No need to call destroy, since we are using fd_scratch allocator. */
}

void
fd_features_restore( fd_global_ctx_t * global ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init();
                                   !fd_feature_iter_done( id );
                               id = fd_feature_iter_next( id ) ) {
    fd_feature_restore( global, fd_features_ptr( &global->features, id ), id->id.key );
  }
}

void fd_runtime_update_leaders( fd_global_ctx_t * global, ulong slot) {
  FD_SCRATCH_SCOPED_FRAME;

  fd_epoch_schedule_t schedule;
  fd_sysvar_epoch_schedule_read( global, &schedule );
  FD_LOG_INFO(( "schedule->slots_per_epoch = %lu", schedule.slots_per_epoch ));
  FD_LOG_INFO(( "schedule->leader_schedule_slot_offset = %lu", schedule.leader_schedule_slot_offset ));
  FD_LOG_INFO(( "schedule->warmup = %d", schedule.warmup ));
  FD_LOG_INFO(( "schedule->first_normal_epoch = %lu", schedule.first_normal_epoch ));
  FD_LOG_INFO(( "schedule->first_normal_slot = %lu", schedule.first_normal_slot ));

  fd_vote_accounts_t const * epoch_vaccs = &global->bank.epoch_stakes;

  ulong epoch           = fd_slot_to_epoch( &schedule, slot, NULL );
  ulong slot0           = fd_epoch_slot0   ( &schedule, epoch );
  ulong slot_cnt        = fd_epoch_slot_cnt( &schedule, epoch );

  FD_LOG_INFO(( "starting rent list init" ));
  if (NULL != global->rentlists)
    fd_rent_lists_delete(global->rentlists);
  global->rentlists = fd_rent_lists_new(fd_epoch_slot_cnt( &schedule, epoch ));
  fd_funk_set_notify(global->funk, fd_rent_lists_cb, global->rentlists);
  fd_rent_lists_startup_done_tpool(global->rentlists, global->tpool, global->max_workers);
  FD_LOG_INFO(( "rent list init done" ));

  ulong vote_acc_cnt = fd_vote_accounts_pair_t_map_size( epoch_vaccs->vote_accounts_pool, epoch_vaccs->vote_accounts_root );
  fd_stake_weight_t * epoch_weights = fd_scratch_alloc( alignof(fd_stake_weight_t), vote_acc_cnt * sizeof(fd_stake_weight_t) );
  if( FD_UNLIKELY( !epoch_weights ) ) FD_LOG_ERR(( "fd_scratch_alloc() failed" ));

  ulong stake_weight_cnt = fd_stake_weights_by_node( epoch_vaccs, epoch_weights );

  if( FD_UNLIKELY( stake_weight_cnt==ULONG_MAX ) ) FD_LOG_ERR(( "fd_stake_weights_by_node() failed" ));

  /* Derive leader schedule */

  FD_LOG_INFO(( "stake_weight_cnt=%lu slot_cnt=%lu", stake_weight_cnt, slot_cnt ));
  ulong epoch_leaders_footprint = fd_epoch_leaders_footprint( stake_weight_cnt, slot_cnt );
  FD_LOG_INFO(( "epoch_leaders_footprint=%lu", epoch_leaders_footprint ));
  if( FD_LIKELY( epoch_leaders_footprint ) ) {
    void * epoch_leaders_mem = fd_valloc_malloc(global->valloc, fd_epoch_leaders_align(), epoch_leaders_footprint );
    if (NULL != global->leaders)
      fd_valloc_free(global->valloc, global->leaders);
    global->leaders = fd_epoch_leaders_join( fd_epoch_leaders_new( epoch_leaders_mem, epoch, slot0,  slot_cnt, stake_weight_cnt, epoch_weights ) );
    FD_TEST( global->leaders );
    /* Derive */
    fd_epoch_leaders_derive( global->leaders, epoch_weights, epoch );
  }
}

/* process for the start of a new epoch */
void
fd_process_new_epoch(
    fd_global_ctx_t * global,
    ulong parent_epoch
) {
  ulong slot;
  ulong epoch = fd_slot_to_epoch(&global->bank.epoch_schedule, global->bank.slot, &slot);
  global->bank.collected_fees = 0;
  global->bank.collected_rent = 0;
  global->bank.max_tick_height = (slot + 1) * global->bank.ticks_per_slot;

  // activate feature flags
  fd_features_restore( global );

  // Add new entry to stakes.stake_history, set appropriate epoch and
  // update vote accounts with warmed up stakes before saving a
  // snapshot of stakes in epoch stakes
  fd_stakes_activate_epoch( global, epoch );

  // (We might not implement this part)
  /* Save a snapshot of stakes for use in consensus and stake weighted networking
  let leader_schedule_epoch = self.epoch_schedule.get_leader_schedule_epoch(slot);

  */

  fd_runtime_update_leaders(global, global->bank.slot);

      /*
  let (_, update_epoch_stakes_time) = measure!(
           self.update_epoch_stakes(leader_schedule_epoch),
           "update_epoch_stakes",
       ); */
  if ( FD_FEATURE_ACTIVE( global, enable_partitioned_epoch_reward ) ) {
    begin_partitioned_rewards( &global->bank, global, parent_epoch );
  } else {
    // TODO: need to complete this path
    update_rewards( global, parent_epoch);
  }

  // (TODO) Update sysvars before processing transactions
  // new.update_slot_hashes();
  // new.update_stake_history(Some(parent_epoch));
  // new.update_clock(Some(parent_epoch));
  // new.update_fees();
  fd_sysvar_fees_init( global );
  // new.update_last_restart_slot()


}
