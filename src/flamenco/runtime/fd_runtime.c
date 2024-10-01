#include "fd_runtime.h"
#include "fd_acc_mgr.h"
#include "fd_runtime_err.h"
#include "fd_runtime_init.h"

#include "fd_executor.h"
#include "fd_account.h"
#include "fd_hashes.h"
#include "sysvar/fd_sysvar_cache.h"
#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "sysvar/fd_sysvar_recent_hashes.h"
#include "sysvar/fd_sysvar_stake_history.h"
#include "sysvar/fd_sysvar.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/bmtree/fd_wbmtree.h"

#include "../stakes/fd_stakes.h"
#include "../rewards/fd_rewards.h"

#include "context/fd_exec_txn_ctx.h"
#include "context/fd_exec_instr_ctx.h"
#include "info/fd_microblock_batch_info.h"
#include "info/fd_microblock_info.h"

#include "program/fd_stake_program.h"
#include "program/fd_builtin_programs.h"
#include "program/fd_system_program.h"
#include "program/fd_vote_program.h"
#include "program/fd_bpf_program_util.h"
#include "program/fd_bpf_loader_program.h"
#include "program/fd_compute_budget_program.h"

#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar_fees.h"
#include "sysvar/fd_sysvar_last_restart_slot.h"
#include "sysvar/fd_sysvar_recent_hashes.h"
#include "sysvar/fd_sysvar_rent.h"
#include "sysvar/fd_sysvar_slot_hashes.h"
#include "sysvar/fd_sysvar_slot_history.h"

#include "../nanopb/pb_decode.h"
#include "../nanopb/pb_encode.h"
#include "../types/fd_solana_block.pb.h"

#include "fd_system_ids.h"
#include "../vm/fd_vm.h"
#include "fd_blockstore.h"
#include "../../ballet/pack/fd_pack.h"
#include "../fd_rwlock.h"

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>

#define MICRO_LAMPORTS_PER_LAMPORT                 (1000000UL)

void
fd_runtime_init_bank_from_genesis( fd_exec_slot_ctx_t *  slot_ctx,
                                   fd_genesis_solana_t * genesis_block,
                                   fd_hash_t const *     genesis_hash ) {
  slot_ctx->slot_bank.slot = 0;

  memcpy(&slot_ctx->slot_bank.poh, genesis_hash->hash, FD_SHA256_HASH_SZ);
  memset(slot_ctx->slot_bank.banks_hash.hash, 0, FD_SHA256_HASH_SZ);

  slot_ctx->slot_bank.fee_rate_governor = genesis_block->fee_rate_governor;
  slot_ctx->slot_bank.lamports_per_signature = 0UL;
  slot_ctx->prev_lamports_per_signature = 0UL;

  fd_poh_config_t *poh = &genesis_block->poh_config;
  fd_exec_epoch_ctx_t * epoch_ctx = slot_ctx->epoch_ctx;
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( epoch_ctx );
  if (poh->has_hashes_per_tick)
    epoch_bank->hashes_per_tick = poh->hashes_per_tick;
  else
    epoch_bank->hashes_per_tick = 0;
  epoch_bank->ticks_per_slot = genesis_block->ticks_per_slot;
  epoch_bank->genesis_creation_time = genesis_block->creation_time;
  uint128 target_tick_duration = ((uint128)poh->target_tick_duration.seconds * 1000000000UL + (uint128)poh->target_tick_duration.nanoseconds);
  epoch_bank->ns_per_slot = target_tick_duration * epoch_bank->ticks_per_slot;

  epoch_bank->slots_per_year = SECONDS_PER_YEAR * (1000000000.0 / (double)target_tick_duration) / (double)epoch_bank->ticks_per_slot;
  epoch_bank->genesis_creation_time = genesis_block->creation_time;
  slot_ctx->slot_bank.max_tick_height = epoch_bank->ticks_per_slot * (slot_ctx->slot_bank.slot + 1);
  epoch_bank->epoch_schedule = genesis_block->epoch_schedule;
  epoch_bank->inflation = genesis_block->inflation;
  epoch_bank->rent = genesis_block->rent;
  slot_ctx->slot_bank.block_height = 0UL;

  fd_block_block_hash_entry_t *hashes = slot_ctx->slot_bank.recent_block_hashes.hashes =
      deq_fd_block_block_hash_entry_t_alloc( slot_ctx->valloc, FD_SYSVAR_RECENT_HASHES_CAP );
  fd_block_block_hash_entry_t *elem = deq_fd_block_block_hash_entry_t_push_head_nocopy(hashes);
  fd_block_block_hash_entry_new(elem);
  fd_memcpy(elem->blockhash.hash, genesis_hash, FD_SHA256_HASH_SZ);
  elem->fee_calculator.lamports_per_signature = 0UL;

  slot_ctx->slot_bank.block_hash_queue.ages_root = NULL;
  slot_ctx->slot_bank.block_hash_queue.ages_pool = fd_hash_hash_age_pair_t_map_alloc( slot_ctx->valloc, 400 );
  fd_hash_hash_age_pair_t_mapnode_t * node = fd_hash_hash_age_pair_t_map_acquire( slot_ctx->slot_bank.block_hash_queue.ages_pool );
  node->elem = (fd_hash_hash_age_pair_t){
    .key = *genesis_hash,
    .val = (fd_hash_age_t){ .hash_index = 0, .fee_calculator = (fd_fee_calculator_t){.lamports_per_signature = 0UL}, .timestamp = (ulong)fd_log_wallclock() }
  };
  fd_hash_hash_age_pair_t_map_insert( slot_ctx->slot_bank.block_hash_queue.ages_pool, &slot_ctx->slot_bank.block_hash_queue.ages_root, node );
  slot_ctx->slot_bank.block_hash_queue.last_hash_index = 0;
  slot_ctx->slot_bank.block_hash_queue.last_hash = fd_valloc_malloc( slot_ctx->valloc, FD_HASH_ALIGN, FD_HASH_FOOTPRINT );
  fd_memcpy( slot_ctx->slot_bank.block_hash_queue.last_hash, genesis_hash, FD_SHA256_HASH_SZ );
  slot_ctx->slot_bank.block_hash_queue.max_age = FD_BLOCKHASH_QUEUE_MAX_ENTRIES;

  slot_ctx->signature_cnt = 0;

  /* Derive epoch stakes */

  fd_vote_accounts_pair_t_mapnode_t * vacc_pool = fd_exec_epoch_ctx_stake_votes_join( epoch_ctx );

  FD_TEST(vacc_pool);
  fd_vote_accounts_pair_t_mapnode_t * vacc_root = NULL;

  fd_delegation_pair_t_mapnode_t * sacc_pool = fd_exec_epoch_ctx_stake_delegations_join( epoch_ctx );
  fd_delegation_pair_t_mapnode_t * sacc_root = NULL;

  fd_stake_history_treap_t * stake_history_treap = fd_exec_epoch_ctx_stake_history_treap_join( epoch_ctx );
  fd_stake_history_entry_t * stake_history_pool  = fd_exec_epoch_ctx_stake_history_pool_join ( epoch_ctx );

  fd_acc_lamports_t capitalization = 0UL;

  for (ulong i = 0UL; i < genesis_block->accounts_len; i++) {
    fd_pubkey_account_pair_t const *acc = &genesis_block->accounts[i];
    capitalization = fd_ulong_sat_add(capitalization, acc->account.lamports);

    if (0 == memcmp(acc->account.owner.key, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t))) {
      /* Vote Program Account */

      fd_vote_accounts_pair_t_mapnode_t *node =
          fd_vote_accounts_pair_t_map_acquire(vacc_pool);
      FD_TEST(node);

      fd_vote_block_timestamp_t last_timestamp;
      fd_pubkey_t node_pubkey;
      FD_SCRATCH_SCOPE_BEGIN {
        /* Deserialize content */
        fd_vote_state_versioned_t vs[1];
        fd_bincode_decode_ctx_t decode =
            { .data    = acc->account.data,
              .dataend = acc->account.data + acc->account.data_len,
              .valloc  = fd_scratch_virtual() };
        int decode_err = fd_vote_state_versioned_decode( vs, &decode );
        if( FD_UNLIKELY( decode_err!=FD_BINCODE_SUCCESS ) ) {
          FD_LOG_WARNING(( "fd_vote_state_versioned_decode failed (%d)", decode_err ));
          return;
        }

        switch( vs->discriminant )
        {
        case fd_vote_state_versioned_enum_current:
          last_timestamp = vs->inner.current.last_timestamp;
          node_pubkey    = vs->inner.current.node_pubkey;
          break;
        case fd_vote_state_versioned_enum_v0_23_5:
          last_timestamp = vs->inner.v0_23_5.last_timestamp;
          node_pubkey    = vs->inner.v0_23_5.node_pubkey;
          break;
        case fd_vote_state_versioned_enum_v1_14_11:
          last_timestamp = vs->inner.v1_14_11.last_timestamp;
          node_pubkey    = vs->inner.v1_14_11.node_pubkey;
          break;
        default:
          __builtin_unreachable();
        }

      } FD_SCRATCH_SCOPE_END;

      fd_memcpy(node->elem.key.key, acc->key.key, sizeof(fd_pubkey_t));
      node->elem.stake = acc->account.lamports;
      node->elem.value = (fd_solana_vote_account_t){
          .lamports = acc->account.lamports,
          .node_pubkey = node_pubkey,
          .last_timestamp_ts = last_timestamp.timestamp,
          .last_timestamp_slot = last_timestamp.slot,
          .owner = acc->account.owner,
          .executable = acc->account.executable,
          .rent_epoch = acc->account.rent_epoch};

      fd_vote_accounts_pair_t_map_insert(vacc_pool, &vacc_root, node);

      FD_LOG_INFO(( "Adding genesis vote account: key=%s stake=%lu",
                   FD_BASE58_ENC_32_ALLOCA( node->elem.key.key ),
                   node->elem.stake ));
    } else if (0 == memcmp(acc->account.owner.key, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t))) {
      /* stake program account */
      fd_stake_state_v2_t stake_state = {0};

      fd_account_meta_t meta = {.dlen = acc->account.data_len};
      fd_borrowed_account_t stake_account = {
          .const_data = acc->account.data,
          .const_meta = &meta,
          .data = acc->account.data,
          .meta = &meta};
      FD_TEST(fd_stake_get_state(&stake_account, &slot_ctx->valloc, &stake_state) == 0);
      if( stake_state.inner.stake.stake.delegation.stake == 0 ) continue;
      fd_delegation_pair_t_mapnode_t query_node;
      fd_memcpy(&query_node.elem.account, acc->key.key, sizeof(fd_pubkey_t));
      fd_delegation_pair_t_mapnode_t *node = fd_delegation_pair_t_map_find(sacc_pool, sacc_root, &query_node);

      if (node == NULL) {
        node = fd_delegation_pair_t_map_acquire(sacc_pool);
        fd_memcpy(&node->elem.account, acc->key.key, sizeof(fd_pubkey_t));
        fd_memcpy(&node->elem.delegation, &stake_state.inner.stake.stake.delegation, sizeof(fd_delegation_t));
        fd_delegation_pair_t_map_insert(sacc_pool, &sacc_root, node);
      } else {
        fd_memcpy(&node->elem.account, acc->key.key, sizeof(fd_pubkey_t));
        fd_memcpy(&node->elem.delegation, &stake_state.inner.stake.stake.delegation, sizeof(fd_delegation_t));
      }
    } else if (0 == memcmp(acc->account.owner.key, fd_solana_feature_program_id.key, sizeof(fd_pubkey_t))) {
      /* Feature Account */

      /* Scan list of feature IDs to resolve address => feature offset */
      fd_feature_id_t const *found = NULL;
      for (fd_feature_id_t const *id = fd_feature_iter_init();
           !fd_feature_iter_done(id);
           id = fd_feature_iter_next(id)) {
        if (0 == memcmp(acc->key.key, id->id.key, sizeof(fd_pubkey_t)))
        {
          found = id;
          break;
        }
      }

      if (found) {
        /* Load feature activation */
        FD_SCRATCH_SCOPE_BEGIN {
          fd_bincode_decode_ctx_t decode = {.data = acc->account.data,
                                            .dataend = acc->account.data + acc->account.data_len,
                                            .valloc = fd_scratch_virtual()};
          fd_feature_t feature;
          int err = fd_feature_decode( &feature, &decode );
          FD_TEST( err==FD_BINCODE_SUCCESS );
          if( feature.has_activated_at ) {
            FD_LOG_DEBUG(( "Feature %s activated at %lu (genesis)", FD_BASE58_ENC_32_ALLOCA( acc->key.key ), feature.activated_at ));
            fd_features_set( &slot_ctx->epoch_ctx->features, found, feature.activated_at);
          } else {
            FD_LOG_DEBUG(( "Feature %s not activated (genesis)", FD_BASE58_ENC_32_ALLOCA( acc->key.key ) ));
            fd_features_set( &slot_ctx->epoch_ctx->features, found, ULONG_MAX);
          }
        } FD_SCRATCH_SCOPE_END;
      }
    }
  }

  slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool = fd_vote_accounts_pair_t_map_alloc( slot_ctx->valloc, 100000 );  /* FIXME remove magic constant */
  slot_ctx->slot_bank.epoch_stakes.vote_accounts_root = NULL;

  fd_vote_accounts_pair_t_mapnode_t * next_pool = fd_exec_epoch_ctx_next_epoch_stakes_join( slot_ctx->epoch_ctx );
  fd_vote_accounts_pair_t_mapnode_t * next_root = NULL;

  for( fd_vote_accounts_pair_t_mapnode_t *n = fd_vote_accounts_pair_t_map_minimum( vacc_pool, vacc_root );
        n;
        n = fd_vote_accounts_pair_t_map_successor( vacc_pool, n )) {
    fd_vote_accounts_pair_t_mapnode_t * e = fd_vote_accounts_pair_t_map_acquire( slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool );
    fd_memcpy( &e->elem, &n->elem, sizeof(fd_vote_accounts_pair_t));
    fd_vote_accounts_pair_t_map_insert( slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool, &slot_ctx->slot_bank.epoch_stakes.vote_accounts_root, e );

    fd_vote_accounts_pair_t_mapnode_t * next_e = fd_vote_accounts_pair_t_map_acquire( next_pool );
    fd_memcpy( &next_e->elem, &n->elem, sizeof(fd_vote_accounts_pair_t));
    fd_vote_accounts_pair_t_map_insert( next_pool, &next_root, next_e );
  }

  for( fd_delegation_pair_t_mapnode_t *n = fd_delegation_pair_t_map_minimum( sacc_pool, sacc_root );
        n;
        n = fd_delegation_pair_t_map_successor( sacc_pool, n )) {
    fd_vote_accounts_pair_t_mapnode_t query_voter;
    fd_pubkey_t *voter_pubkey = &n->elem.delegation.voter_pubkey;
    fd_memcpy(&query_voter.elem.key, voter_pubkey, sizeof(fd_pubkey_t));

    fd_vote_accounts_pair_t_mapnode_t *voter = fd_vote_accounts_pair_t_map_find(vacc_pool, vacc_root, &query_voter);

    if (voter != NULL)
          voter->elem.stake = fd_ulong_sat_add(voter->elem.stake, n->elem.delegation.stake);
  }

  epoch_bank->next_epoch_stakes = (fd_vote_accounts_t){
    .vote_accounts_pool = next_pool,
    .vote_accounts_root = next_root,
  };

  /* Initializes the stakes cache in the Bank structure. */
  epoch_bank->stakes = (fd_stakes_t){
      .stake_delegations_pool = sacc_pool,
      .stake_delegations_root = sacc_root,
      .epoch = 0,
      .unused = 0,
      .vote_accounts = (fd_vote_accounts_t){
          .vote_accounts_pool = vacc_pool,
          .vote_accounts_root = vacc_root},
      .stake_history = (fd_stake_history_t){.pool = stake_history_pool, .treap = stake_history_treap}};

  slot_ctx->slot_bank.capitalization = capitalization;

  slot_ctx->slot_bank.timestamp_votes.votes_pool =
        fd_clock_timestamp_vote_t_map_alloc( slot_ctx->valloc, 10000 ); /* FIXME: remove magic constant */
  slot_ctx->slot_bank.timestamp_votes.votes_root = NULL;

}

void fd_runtime_init_program(fd_exec_slot_ctx_t *slot_ctx)
{
  fd_sysvar_recent_hashes_init(slot_ctx);
  fd_sysvar_clock_init(slot_ctx);
  fd_sysvar_slot_history_init(slot_ctx);
  //  fd_sysvar_slot_hashes_init( slot_ctx );
  fd_sysvar_epoch_schedule_init(slot_ctx);
  if( !FD_FEATURE_ACTIVE(slot_ctx, disable_fees_sysvar) ) {
    fd_sysvar_fees_init(slot_ctx);
  }
  fd_sysvar_rent_init(slot_ctx);
  fd_sysvar_stake_history_init(slot_ctx);
  fd_sysvar_last_restart_slot_init(slot_ctx);

  fd_builtin_programs_init(slot_ctx);
  fd_stake_program_config_init(slot_ctx);
}

int fd_runtime_parse_microblock_hdr(void const *buf,
                                    ulong buf_sz,
                                    fd_microblock_hdr_t *opt_microblock_hdr,
                                    ulong *opt_microblock_hdr_size)
{
  if (buf_sz < sizeof(fd_microblock_hdr_t))
  {
    return -1;
  }

  if (opt_microblock_hdr != NULL)
  {
    *opt_microblock_hdr = *(fd_microblock_hdr_t *)buf;
  }

  if (opt_microblock_hdr_size != NULL)
  {
    *opt_microblock_hdr_size = sizeof(fd_microblock_hdr_t);
  }

  return 0;
}

int fd_runtime_parse_microblock_txns( void const * buf,
                                      ulong buf_sz,
                                      fd_microblock_hdr_t const * microblock_hdr,
                                      fd_txn_p_t * out_txns,
                                      ulong * out_signature_cnt,
                                      ulong * out_account_cnt,
                                      ulong * out_microblock_txns_sz ) {
  ulong buf_off = 0;
  ulong signature_cnt = 0;
  ulong account_cnt = 0;

  for (ulong i = 0; i < microblock_hdr->txn_cnt; i++) {
    ulong payload_sz = 0;
    ulong txn_sz = fd_txn_parse_core( (uchar const *)buf + buf_off, fd_ulong_min( buf_sz-buf_off, FD_TXN_MTU), TXN(&out_txns[i]), NULL, &payload_sz );
    if (txn_sz == 0 || txn_sz > FD_TXN_MTU) {
      return -1;
    }

    fd_memcpy( out_txns[i].payload, (uchar *)buf + buf_off, payload_sz );
    out_txns[i].payload_sz = (ushort)payload_sz;

    signature_cnt += TXN(&out_txns[i])->signature_cnt;
    account_cnt += fd_txn_account_cnt( TXN(&out_txns[i]), FD_TXN_ACCT_CAT_ALL );
    buf_off += payload_sz;
  }

  *out_signature_cnt = signature_cnt;
  *out_account_cnt = account_cnt;
  *out_microblock_txns_sz = buf_off;

  return 0;
}

int fd_runtime_microblock_prepare(void const *buf,
                                  ulong buf_sz,
                                  fd_valloc_t valloc,
                                  fd_microblock_info_t *out_microblock_info) {
  fd_microblock_info_t microblock_info = {
      .raw_microblock = buf,
      .signature_cnt = 0,
  };
  ulong buf_off = 0;

  ulong hdr_sz = 0;
  if (fd_runtime_parse_microblock_hdr(buf, buf_sz, &microblock_info.microblock_hdr, &hdr_sz) != 0)
  {
    return -1;
  }
  buf_off += hdr_sz;

  ulong txn_cnt = microblock_info.microblock_hdr.txn_cnt;
  microblock_info.txns = fd_valloc_malloc(valloc, alignof(fd_txn_p_t), txn_cnt * sizeof(fd_txn_p_t));

  ulong txns_sz = 0;
  if (fd_runtime_parse_microblock_txns((uchar *)buf + buf_off,
                                       buf_sz - buf_off,
                                       &microblock_info.microblock_hdr,
                                       microblock_info.txns,
                                       &microblock_info.signature_cnt,
                                       &microblock_info.account_cnt,
                                       &txns_sz) != 0)
  {
    fd_valloc_free(valloc, microblock_info.txns);
    return -1;
  }
  buf_off += txns_sz;

  microblock_info.raw_microblock_sz = buf_off;

  *out_microblock_info = microblock_info;

  return 0;
}

int fd_runtime_microblock_batch_prepare(void const *buf,
                                        ulong buf_sz,
                                        fd_valloc_t valloc,
                                        fd_microblock_batch_info_t * out_microblock_batch_info) {
  fd_microblock_batch_info_t microblock_batch_info = {
      .raw_microblock_batch = buf,
      .signature_cnt = 0,
      .txn_cnt = 0,
      .account_cnt = 0,
  };
  ulong buf_off = 0;

  if (FD_UNLIKELY(buf_sz < sizeof(ulong)))
  {
    FD_LOG_WARNING(("microblock batch buffer too small"));
    return -1;
  }
  ulong microblock_cnt = FD_LOAD(ulong, buf);
  buf_off += sizeof(ulong);

  microblock_batch_info.microblock_cnt = microblock_cnt;
  microblock_batch_info.microblock_infos = fd_valloc_malloc(valloc, alignof(fd_microblock_info_t), microblock_cnt * sizeof(fd_microblock_info_t));

  ulong signature_cnt = 0;
  ulong txn_cnt = 0;
  ulong account_cnt = 0;
  for (ulong i = 0; i < microblock_cnt; i++) {
    fd_microblock_info_t * microblock_info = &microblock_batch_info.microblock_infos[i];
    if (fd_runtime_microblock_prepare((uchar const *)buf + buf_off, buf_sz - buf_off, valloc, microblock_info) != 0)
    {
      fd_valloc_free(valloc, microblock_batch_info.microblock_infos);
      return -1;
    }

    signature_cnt += microblock_info->signature_cnt;
    txn_cnt += microblock_info->microblock_hdr.txn_cnt;
    account_cnt += microblock_info->account_cnt;
    buf_off += microblock_info->raw_microblock_sz;
  }

  microblock_batch_info.signature_cnt = signature_cnt;
  microblock_batch_info.txn_cnt = txn_cnt;
  microblock_batch_info.account_cnt = account_cnt;
  microblock_batch_info.raw_microblock_batch_sz = buf_off;

  *out_microblock_batch_info = microblock_batch_info;

  return 0;
}

// static void dump_iter( fd_raw_block_txn_iter_t iter ) {
//   FD_LOG_WARNING(( "Curr iter data sz %lu offset %lu num txns %lu num mblks %lu curr txn sz %lu", iter.data_sz, iter.curr_offset, iter.remaining_txns, iter.remaining_microblocks, iter.curr_txn_sz ));
// }

static fd_raw_block_txn_iter_t
find_next_txn_in_raw_block( uchar const * data, ulong data_sz, ulong existing_offset, ulong num_microblocks ) {
  uchar const * base = data;
  ulong num_txns = 0UL;
  ulong sz = (ulong)data - (ulong)base;
  while( !num_txns && (sz < data_sz) ) {
    while( num_microblocks == 0 && (sz < data_sz) ) {
      num_microblocks = FD_LOAD( ulong, data );
      data += sizeof( ulong );
      sz = (ulong)data - (ulong)base;
    }

    fd_microblock_info_t microblock_info = {
        .raw_microblock = data,
        .signature_cnt = 0,
    };

    while( microblock_info.microblock_hdr.txn_cnt == 0 && num_microblocks && sz < data_sz ) {
      ulong hdr_sz = 0;
      memset( &microblock_info, 0UL, sizeof(fd_microblock_info_t) );
      microblock_info.raw_microblock = data;
      if (fd_runtime_parse_microblock_hdr(data, data_sz - sz, &microblock_info.microblock_hdr, &hdr_sz) != 0) {
        return (fd_raw_block_txn_iter_t){
          .data_sz = 0,
          .curr_offset = data_sz,
          .remaining_microblocks = 0,
          .remaining_txns = 0,
          .curr_txn_sz = ULONG_MAX
        };
      }
      data += hdr_sz;
      sz = (ulong)data - (ulong)base;
      num_microblocks--;
    }

    num_txns = microblock_info.microblock_hdr.txn_cnt;
  }

  ulong curr_off = sz;
  return (fd_raw_block_txn_iter_t){
    .data_sz = fd_ulong_sat_sub(data_sz, curr_off),
    .curr_offset = existing_offset + curr_off,
    .remaining_microblocks = num_microblocks,
    .remaining_txns = num_txns,
    .curr_txn_sz = ULONG_MAX
  };
}

fd_raw_block_txn_iter_t
fd_raw_block_txn_iter_init( uchar const * data, ulong data_sz ) {
  return find_next_txn_in_raw_block( data, data_sz, 0, 0 );
}

ulong
fd_raw_block_txn_iter_done( fd_raw_block_txn_iter_t iter ) {
  return iter.data_sz == 0;
}

fd_raw_block_txn_iter_t
fd_raw_block_txn_iter_next( uchar const * data, fd_raw_block_txn_iter_t iter ) {
  fd_txn_p_t out_txn;
  if( iter.curr_txn_sz == ULONG_MAX ) {
    ulong payload_sz = 0;
    ulong txn_sz = fd_txn_parse_core( data + iter.curr_offset, fd_ulong_min( iter.data_sz, FD_TXN_MTU), TXN(&out_txn), NULL, &payload_sz );
    if (txn_sz == 0 || txn_sz > FD_TXN_MTU) {
      FD_LOG_ERR(("Invalid txn parse"));
    }
    iter.data_sz -= payload_sz;
    iter.curr_offset += payload_sz;
  } else {
    iter.data_sz -= iter.curr_txn_sz;
    iter.curr_offset += iter.curr_txn_sz;
    iter.curr_txn_sz = ULONG_MAX;
  }

  if( --iter.remaining_txns ) {
    return iter;
  }

  return find_next_txn_in_raw_block( data + iter.curr_offset, iter.data_sz, iter.curr_offset, iter.remaining_microblocks );
}

void
fd_raw_block_txn_iter_ele( uchar const * data, fd_raw_block_txn_iter_t iter, fd_txn_p_t * out_txn ) {
  ulong payload_sz = 0;
  ulong txn_sz = fd_txn_parse_core( data + iter.curr_offset, fd_ulong_min( iter.data_sz, FD_TXN_MTU), TXN(out_txn), NULL, &payload_sz );
  if (txn_sz == 0 || txn_sz > FD_TXN_MTU) {
    FD_LOG_ERR(("Invalid txn parse %lu", txn_sz));
  }
  fd_memcpy( out_txn->payload, data + iter.curr_offset, payload_sz );
  out_txn->payload_sz = (ushort)payload_sz;
  iter.curr_txn_sz = payload_sz;
}

fd_microblock_txn_iter_t
fd_microblock_txn_iter_init( fd_microblock_info_t const * microblock_info FD_PARAM_UNUSED ) {
  return 0UL;
}

ulong
fd_microblock_txn_iter_done( fd_microblock_info_t const * microblock_info, fd_microblock_txn_iter_t iter ) {
  return iter >= microblock_info->microblock_hdr.txn_cnt;
}

fd_microblock_txn_iter_t
fd_microblock_txn_iter_next( fd_microblock_info_t const * microblock_info FD_PARAM_UNUSED, fd_microblock_txn_iter_t iter ) {
  return iter + 1UL;
}

fd_txn_p_t *
fd_microblock_txn_iter_ele( fd_microblock_info_t const * microblock_info, fd_microblock_txn_iter_t iter ) {
  return &microblock_info->txns[iter];
}

fd_microblock_batch_txn_iter_t
fd_microblock_batch_txn_iter_init( fd_microblock_batch_info_t const * microblock_batch_info ) {
  fd_microblock_batch_txn_iter_t iter = {
    .curr_microblock = ULONG_MAX,
  };

  for( ulong i = 0UL; i < microblock_batch_info->microblock_cnt; i++ ) {
    if( microblock_batch_info->microblock_infos[i].microblock_hdr.txn_cnt > 0 ) {
      iter.curr_microblock = i;
      break;
    }
  }

  iter.microblock_iter = fd_microblock_txn_iter_init( &microblock_batch_info->microblock_infos[iter.curr_microblock] );
  return iter;
  }

ulong
fd_microblock_batch_txn_iter_done( fd_microblock_batch_info_t const * microblock_batch_info, fd_microblock_batch_txn_iter_t iter ) {
  return iter.curr_microblock >= microblock_batch_info->microblock_cnt;
}

fd_microblock_batch_txn_iter_t
fd_microblock_batch_txn_iter_next( fd_microblock_batch_info_t const * microblock_batch_info, fd_microblock_batch_txn_iter_t iter ) {
  iter.microblock_iter = fd_microblock_txn_iter_next( &microblock_batch_info->microblock_infos[iter.curr_microblock], iter.microblock_iter );
  while( fd_microblock_txn_iter_done( &microblock_batch_info->microblock_infos[iter.curr_microblock], iter.microblock_iter ) ) {
    iter.curr_microblock++;
    if( iter.curr_microblock >= microblock_batch_info->microblock_cnt ) {
      break;
    }
    iter.microblock_iter = fd_microblock_txn_iter_init( &microblock_batch_info->microblock_infos[iter.curr_microblock] );
  }
  return iter;
}

fd_txn_p_t *
fd_microblock_batch_txn_iter_ele( fd_microblock_batch_info_t const * microblock_batch_info, fd_microblock_batch_txn_iter_t iter ) {
  return fd_microblock_txn_iter_ele( &microblock_batch_info->microblock_infos[iter.curr_microblock], iter.microblock_iter );
}

fd_block_txn_iter_t
fd_block_txn_iter_init( fd_block_info_t const * block_info ) {
  fd_block_txn_iter_t iter = {
    .curr_batch = ULONG_MAX,
  };

  for( ulong i = 0UL; i < block_info->microblock_batch_cnt; i++ ) {
    if( block_info->microblock_batch_infos[i].txn_cnt > 0 ) {
      iter.curr_batch = i;
      break;
    }
  }

  iter.microblock_batch_iter = fd_microblock_batch_txn_iter_init( &block_info->microblock_batch_infos[iter.curr_batch] );
  return iter;
}

ulong
fd_block_txn_iter_done( fd_block_info_t const * block_info, fd_block_txn_iter_t iter ) {
  return iter.curr_batch >= block_info->microblock_batch_cnt;
}

fd_block_txn_iter_t
fd_block_txn_iter_next( fd_block_info_t const * block_info, fd_block_txn_iter_t iter ) {
  iter.microblock_batch_iter = fd_microblock_batch_txn_iter_next( &block_info->microblock_batch_infos[iter.curr_batch], iter.microblock_batch_iter );
  while( fd_microblock_batch_txn_iter_done( &block_info->microblock_batch_infos[iter.curr_batch], iter.microblock_batch_iter ) ) {
    iter.curr_batch++;
    if( iter.curr_batch >= block_info->microblock_batch_cnt ) {
      break;
    }
    iter.microblock_batch_iter = fd_microblock_batch_txn_iter_init( &block_info->microblock_batch_infos[iter.curr_batch] );

  }
  return iter;
}

fd_txn_p_t *
fd_block_txn_iter_ele( fd_block_info_t const * block_info, fd_block_txn_iter_t iter ) {
  return fd_microblock_batch_txn_iter_ele( &block_info->microblock_batch_infos[iter.curr_batch], iter.microblock_batch_iter );
}

ulong
fd_runtime_microblock_collect_txns( fd_microblock_info_t const * microblock_info,
                                    fd_txn_p_t * out_txns ) {
  ulong txn_cnt = microblock_info->microblock_hdr.txn_cnt;
  fd_memcpy( out_txns, microblock_info->txns, txn_cnt * sizeof(fd_txn_p_t) );

  return txn_cnt;
}

ulong
fd_runtime_microblock_batch_collect_txns( fd_microblock_batch_info_t const * microblock_batch_info,
                                          fd_txn_p_t * out_txns ) {
  for( ulong i = 0; i < microblock_batch_info->microblock_cnt; i++ ) {
    ulong txns_collected = fd_runtime_microblock_collect_txns( &microblock_batch_info->microblock_infos[i], out_txns );
    out_txns += txns_collected;
  }

  return microblock_batch_info->txn_cnt;
}

ulong
fd_runtime_block_collect_txns( fd_block_info_t const * block_info,
                               fd_txn_p_t * out_txns ) {
  for( ulong i = 0; i < block_info->microblock_batch_cnt; i++ ) {
    ulong txns_collected = fd_runtime_microblock_batch_collect_txns( &block_info->microblock_batch_infos[i], out_txns );
    out_txns += txns_collected;
  }

  return block_info->txn_cnt;
}

/* This is also the maximum number of microblock batches per block */
#define FD_MAX_DATA_SHREDS_PER_SLOT (32768UL)

int fd_runtime_block_prepare(void const *buf,
                             ulong buf_sz,
                             fd_valloc_t valloc,
                             fd_block_info_t *out_block_info) {
  fd_block_info_t block_info = {
      .raw_block = buf,
      .signature_cnt = 0,
      .txn_cnt = 0,
  };
  ulong buf_off = 0;

  ulong microblock_batch_cnt = 0;
  ulong microblock_cnt = 0;
  ulong signature_cnt = 0;
  ulong txn_cnt = 0;
  ulong account_cnt = 0;
  block_info.microblock_batch_infos = fd_valloc_malloc(valloc, alignof(fd_microblock_batch_info_t), FD_MAX_DATA_SHREDS_PER_SLOT * sizeof(fd_microblock_batch_info_t));
  while (buf_off < buf_sz)
  {
    fd_microblock_batch_info_t *microblock_batch_info = &block_info.microblock_batch_infos[microblock_batch_cnt];
    if (fd_runtime_microblock_batch_prepare((uchar const *)buf + buf_off, buf_sz - buf_off, valloc, microblock_batch_info) != 0)
    {
      return -1;
    }

    signature_cnt += microblock_batch_info->signature_cnt;
    txn_cnt += microblock_batch_info->txn_cnt;
    account_cnt += microblock_batch_info->account_cnt;
    buf_off += microblock_batch_info->raw_microblock_batch_sz;
    microblock_batch_cnt++;
    microblock_cnt += microblock_batch_info->microblock_cnt;
  }

  block_info.microblock_batch_cnt = microblock_batch_cnt;
  block_info.microblock_cnt = microblock_cnt;
  block_info.signature_cnt = signature_cnt;
  block_info.txn_cnt = txn_cnt;
  block_info.account_cnt += account_cnt;
  block_info.raw_block_sz = buf_off;

  if (buf_off != buf_sz)
  {
    FD_LOG_WARNING(("junk at end of block - consumed: %lu, size: %lu", buf_off, buf_sz));
    return -1;
  }

  *out_block_info = block_info;

  return 0;
}

// TODO: this function doesnt do anything!
int
fd_runtime_block_verify_ticks( fd_block_info_t const * block_info,
                               ulong                   tick_height,
                               ulong                   max_tick_height ) {
  (void)tick_height; (void)max_tick_height;
  ulong tick_count = 0UL;
  for( ulong i = 0UL; i < block_info->microblock_batch_cnt; i++ ) {
    fd_microblock_batch_info_t const * microblock_batch_info = &block_info->microblock_batch_infos[ i ];
    for( ulong j = 0UL; j < microblock_batch_info->microblock_cnt; j++ ) {
      fd_microblock_info_t const * microblock_info = &microblock_batch_info->microblock_infos[ i ];
      if( microblock_info->microblock_hdr.txn_cnt == 0UL ) {
        /* if this mblk is a tick */
        tick_count++;
      }
    }
  }
  (void)tick_count;
  return 0;
}

void
fd_runtime_microblock_destroy( fd_valloc_t valloc,
                               fd_microblock_info_t * microblock_info ) {
  if( microblock_info == NULL ) {
    return;
  }

  fd_valloc_free( valloc, microblock_info->txns );
}

void
fd_runtime_microblock_batch_destroy( fd_valloc_t valloc,
                                      fd_microblock_batch_info_t * microblock_batch_info ) {
  if( microblock_batch_info == NULL ) {
    return;
  }

  for( ulong i = 0; i < microblock_batch_info->microblock_cnt; i++ ) {
    fd_runtime_microblock_destroy( valloc, &microblock_batch_info->microblock_infos[i] );
  }

  fd_valloc_free( valloc, microblock_batch_info->microblock_infos );
}

void
fd_runtime_block_destroy( fd_valloc_t valloc,
                          fd_block_info_t * block_info ) {
  for( ulong i = 0; i < block_info->microblock_batch_cnt; i++ ) {
    fd_runtime_microblock_batch_destroy( valloc, &block_info->microblock_batch_infos[i] );
  }

  fd_valloc_free( valloc, block_info->microblock_batch_infos );
}

static void FD_FN_UNUSED
fd_runtime_execute_txn_task(void *tpool,
                            ulong t0 FD_PARAM_UNUSED, ulong t1 FD_PARAM_UNUSED,
                            void *args FD_PARAM_UNUSED,
                            void *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                            ulong l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
                            ulong m0, ulong m1 FD_PARAM_UNUSED,
                            ulong n0 FD_PARAM_UNUSED, ulong n1 FD_PARAM_UNUSED) {

  fd_execute_txn_task_info_t * task_info = (fd_execute_txn_task_info_t *)tpool + m0;

  if( !( task_info->txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) {
    task_info->exec_res = -1;
    return;
  }

  task_info->txn->flags |= FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
  // fd_txn_t const *txn = task_info->txn_ctx->txn_descriptor;
  // fd_rawtxn_b_t const *raw_txn = task_info->txn_ctx->_txn_raw;
#ifdef VLOG
  FD_LOG_WARNING(("executing txn - slot: %lu, txn_idx: %lu, sig: %s",
                   task_info->txn_ctx->slot_ctx->slot_bank.slot,
                   m0,
                   FD_BASE58_ENC_64_ALLOCA( (uchar *)raw_txn->raw + txn->signature_off )));
#endif

  // Leave this here for debugging...
  // char txnbuf[100];
  // fd_base58_encode_64((uchar *)raw_txn->raw + txn->signature_off , NULL, txnbuf );

// if (!strcmp(txnbuf, "4RGULZH1tkq5naQzD5zmvPf9T8U5Ei7U2oTExnELf8EyHLyWNQzrDukmzNBVvde2p9NrHn5EW4N38oELejX1MDZq"))
//   FD_LOG_WARNING(("hi mom"));

  task_info->exec_res = fd_execute_txn( task_info->txn_ctx );
  if( task_info->exec_res != 0 ) {
    return;
  }
  fd_txn_reclaim_accounts( task_info->txn_ctx );

  // FD_LOG_WARNING(( "Transaction result %d for %s %lu %lu %lu",
  //                  task_info->exec_res,
  //                  FD_BASE58_ENC_64_ALLOCA( (uchar *)raw_txn->raw + txn->signature_off ),
  //                  task_info->txn_ctx->compute_meter,
  //                  task_info->txn_ctx->compute_unit_limit,
  //                  task_info->txn_ctx->num_instructions ));
}

int
fd_runtime_prepare_txns_start( fd_exec_slot_ctx_t *         slot_ctx,
                               fd_execute_txn_task_info_t * task_info,
                               fd_txn_p_t *                 txns,
                               ulong                        txn_cnt ) {
  int res = 0;
  /* Loop across transactions */
  for (ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++) {
    fd_txn_p_t * txn = &txns[txn_idx];

    /* Allocate/setup transaction context and task infos */
    task_info[txn_idx].txn_ctx      = fd_valloc_malloc( fd_scratch_virtual(), FD_EXEC_TXN_CTX_ALIGN, FD_EXEC_TXN_CTX_FOOTPRINT );
    fd_exec_txn_ctx_t * txn_ctx     = task_info[txn_idx].txn_ctx;
    task_info[txn_idx].exec_res     = 0;
    task_info[txn_idx].txn          = txn;
    fd_txn_t const * txn_descriptor = (fd_txn_t const *) txn->_;

    fd_rawtxn_b_t raw_txn = { .raw = txn->payload, .txn_sz = (ushort)txn->payload_sz };

    int err = fd_execute_txn_prepare_start( slot_ctx, txn_ctx, txn_descriptor, &raw_txn );
    if( FD_UNLIKELY( err ) ) {
      task_info[txn_idx].exec_res = err;
      txn->flags                  = 0U;
      res |= err;
    }
  }

  return res;
}

/* fd_txn_sigverify_task and fd_txn_pre_execute_checks_task are responisble
   for the bulk of the pre-transaction execution checks in the runtime.
   They aim to preserve the ordering present in the Agave client to match
   parity in terms of error codes. Sigverify is kept seperate from the rest
   of the transaction checks for fuzzing convenience.

   For reference this is the general code path which contains all relevant
   pre-transactions checks in the v2.0.x Agave client from upstream
   to downstream is as follows:

   confirm_slot_entries() which calls verify_ticks()
   (which is currently unimplemented in firedancer) and
   verify_transaction(). verify_transaction() calls verify_and_hash_message()
   and verify_precompiles() which parallels fd_executor_txn_verify() and
   fd_executor_verify_precompiles().

   process_entries() contains a duplicate account check which is part of
   agave account lock acquiring. This is checked inline in
   fd_txn_pre_execute_checks_task().

   load_and_execute_transactions() contains the function check_transactions().
   This contains check_age() and check_status_cache() which is paralleled by
   fd_check_transaction_age() and fd_executor_check_status_cache()
   respectively.

   load_and_execute_sanitized_transactions() contains validate_fees()
   which is responsible for executing the compute budget instructions,
   validating the fee payer and collecting the fee. This is mirrored in
   firedancer with fd_executor_compute_budget_program_execute_instructions()
   and fd_executor_collect_fees(). load_and_execute_sanitized_transactions()
   also checks the total data size of the accounts in load_accounts() and
   validates the program accounts in load_transaction_accounts(). This
   is paralled by fd_executor_load_transaction_accounts(). */

static void FD_FN_UNUSED
fd_txn_sigverify_task( void *tpool,
                                       ulong t0 FD_PARAM_UNUSED, ulong t1 FD_PARAM_UNUSED,
                                       void *args FD_PARAM_UNUSED,
                                       void *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                                       ulong l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
                                       ulong m0, ulong m1 FD_PARAM_UNUSED,
                                       ulong n0 FD_PARAM_UNUSED, ulong n1 FD_PARAM_UNUSED ) {
  fd_execute_txn_task_info_t * task_info = (fd_execute_txn_task_info_t *)tpool + m0;

  /* the txn failed sanitize sometime earlier */
  if( FD_UNLIKELY( !( task_info->txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) ) {
    return;
  }

  fd_exec_txn_ctx_t * txn_ctx = task_info->txn_ctx;
  if( FD_UNLIKELY( fd_executor_txn_verify( txn_ctx )!=0 ) ) {
    FD_LOG_WARNING(("sigverify failed: %s", FD_BASE58_ENC_64_ALLOCA( (uchar *)txn_ctx->_txn_raw->raw+txn_ctx->txn_descriptor->signature_off ) ));
    task_info->txn->flags = 0U;
    task_info->exec_res   = FD_RUNTIME_TXN_ERR_SIGNATURE_FAILURE;
  }

}

void
fd_runtime_pre_execute_check( fd_execute_txn_task_info_t * task_info ) {
  if( FD_UNLIKELY( !( task_info->txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) ) {
    return;
  }

  fd_exec_txn_ctx_t *          txn_ctx   = task_info->txn_ctx;

  fd_funk_txn_t * parent_txn = txn_ctx->slot_ctx->funk_txn;
  txn_ctx->funk_txn          = parent_txn;
  fd_executor_setup_borrowed_accounts_for_txn( txn_ctx );

  int err;

  /* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/sdk/src/transaction/sanitized.rs#L263-L275
     TODO: Agave's precompile verification is done at the slot level, before batching and executing transactions. This logic should probably
     be moved in the future. The Agave call heirarchy looks something like this:
            process_single_slot
                   v
            confirm_full_slot
                   v
            confirm_slot_entries --------->
                   v                      v
            verify_transaction      process_entries
                   v                      v
            verify_precompiles      process_batches
                                          v
                                         ...
                                          v
                              load_and_execute_transactions
                                          v
                                         ...
                                          v
                                    load_accounts --> load_transaction_accounts
                                          v
                              general transaction execution

  */
  err = fd_executor_verify_precompiles( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    task_info->txn->flags = 0U;
    task_info->exec_res   = err;
    return;
  }

  /* Post-sanitization checks. Called from `prepare_sanitized_batch()` which, for now, only is used
     to lock the accounts and perform a couple basic validations.
     https://github.com/anza-xyz/agave/blob/v2.0.9/sdk/src/transaction/sanitized.rs#L277-L289 */
  err = fd_executor_validate_account_locks( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    task_info->txn->flags = 0U;
    task_info->exec_res   = err;
    return;
  }

  /* `load_and_execute_transactions()` -> `check_transactions()`
     https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/runtime/src/bank.rs#L3667-L3672 */
  err = fd_executor_check_transactions( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    task_info->txn->flags = 0U;
    task_info->exec_res = err;
    return;
  }

  /* `load_and_execute_sanitized_transactions()` -> `validate_fees()` -> `validate_transaction_fee_payer()`
     https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/svm/src/transaction_processor.rs#L236-L249 */
  err = fd_executor_validate_transaction_fee_payer( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    task_info->txn->flags = 0U;
    task_info->exec_res = err;
    return;
  }

  /* https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/svm/src/transaction_processor.rs#L284-L296 */
  err = fd_executor_load_transaction_accounts( txn_ctx );
  if( FD_UNLIKELY( err!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    task_info->txn->flags = 0U;
    task_info->exec_res   = err;
    return;
  }
}

void
fd_runtime_execute_txn( fd_execute_txn_task_info_t * task_info ) {

  /* Transaction sanitization is complete at this point. Now finish account
    setup, execute the transaction, and reclaim dead accounts. */
  if( FD_UNLIKELY( task_info->exec_res ) ) {
    return;
  }

  task_info->txn->flags |= FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
  task_info->exec_res    = fd_execute_txn( task_info->txn_ctx );
  fd_txn_reclaim_accounts( task_info->txn_ctx );
}

static void FD_FN_UNUSED
fd_txn_prep_and_exec_task( void  *tpool,
                           ulong t0 FD_PARAM_UNUSED,      ulong t1 FD_PARAM_UNUSED,
                           void  *args FD_PARAM_UNUSED,
                           void  *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                           ulong l0 FD_PARAM_UNUSED,      ulong l1 FD_PARAM_UNUSED,
                           ulong m0,                      ulong m1 FD_PARAM_UNUSED,
                           ulong n0 FD_PARAM_UNUSED,      ulong n1 FD_PARAM_UNUSED ) {

  fd_execute_txn_task_info_t * task_info = (fd_execute_txn_task_info_t *)tpool + m0;
  fd_exec_slot_ctx_t * slot_ctx = (fd_exec_slot_ctx_t *)args;
  // fd_capture_ctx_t * capture_ctx = (fd_capture_ctx_t *)reduce;

  /* It is important to note that there is currently a 1-1 mapping between the
     tiles and tpool threads at the time of this comment. Eventually, this will
     change and the transaction context's spad will not be queried by tile
     index as every tile will correspond to one CPU core. */    
  ulong tile_idx = fd_tile_idx();
  task_info->txn_ctx->spad = task_info->spads[ tile_idx ];
  if( FD_UNLIKELY( !task_info->txn_ctx->spad ) ) {
    FD_LOG_ERR(("spad is NULL"));
  }

  fd_runtime_pre_execute_check( task_info );
  fd_runtime_execute_txn( task_info );

  ulong curr = slot_ctx->slot_bank.collected_execution_fees;
  FD_COMPILER_MFENCE();
  while( FD_UNLIKELY( FD_ATOMIC_CAS( &slot_ctx->slot_bank.collected_execution_fees, curr, curr + task_info->txn_ctx->execution_fee ) != curr ) ) {
    FD_SPIN_PAUSE();
    curr = slot_ctx->slot_bank.collected_execution_fees;
    FD_COMPILER_MFENCE();
  }

  curr = slot_ctx->slot_bank.collected_priority_fees;
  FD_COMPILER_MFENCE();
  while( FD_UNLIKELY( FD_ATOMIC_CAS( &slot_ctx->slot_bank.collected_priority_fees, curr, curr + task_info->txn_ctx->priority_fee ) != curr ) ) {
    FD_SPIN_PAUSE();
    curr = slot_ctx->slot_bank.collected_priority_fees;
    FD_COMPILER_MFENCE();
  }

  // fd_runtime_finalize_txn( slot_ctx, capture_ctx, task_info );

}

/* This task could be combined with the rest of the transaction checks that
   exist in fd_runtime_prepare_txns_phase2_tpool, but creates a lot more
   complexity to make the transaction fuzzer work. */
int
fd_runtime_verify_txn_signatures_tpool( fd_execute_txn_task_info_t * task_info,
                                        ulong txn_cnt,
                                        fd_tpool_t * tpool ) {
  int res = 0;
  fd_tpool_exec_all_rrobin( tpool, 0, fd_tpool_worker_cnt( tpool ), fd_txn_sigverify_task, task_info, NULL, NULL, 1, 0, txn_cnt );
  for( ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++ ) {
    if( FD_UNLIKELY(!( task_info[txn_idx].txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS )) ) {
      task_info->exec_res = FD_RUNTIME_TXN_ERR_SIGNATURE_FAILURE;
      res |= FD_RUNTIME_TXN_ERR_SIGNATURE_FAILURE;
      break;
    }
  }
  return res;
}

int
fd_runtime_prepare_execute_finalize_txn( fd_exec_slot_ctx_t *         slot_ctx,
                                         fd_capture_ctx_t *           capture_ctx,
                                         fd_txn_p_t *                 txn,
                                         fd_execute_txn_task_info_t * task_info ) {

  FD_SCRATCH_SCOPE_BEGIN {

  int res = 0;

  task_info->txn_ctx              = fd_valloc_malloc( fd_scratch_virtual(), FD_EXEC_TXN_CTX_ALIGN, FD_EXEC_TXN_CTX_FOOTPRINT );
  fd_exec_txn_ctx_t * txn_ctx     = task_info->txn_ctx;
  task_info->exec_res             = -1;
  task_info->txn                  = txn;
  fd_txn_t const * txn_descriptor = (fd_txn_t const *) txn->_;

  fd_rawtxn_b_t raw_txn = { .raw = txn->payload, .txn_sz = (ushort)txn->payload_sz };

  res = fd_execute_txn_prepare_start( slot_ctx, txn_ctx, txn_descriptor, &raw_txn );
  if( FD_UNLIKELY( res ) ) {
    txn->flags = 0U;
    return -1;
  }

  txn_ctx->valloc = fd_scratch_virtual();

  /* NOTE: This intentionally does not have sigverify */

  fd_runtime_pre_execute_check( task_info );
  if( FD_UNLIKELY( !( task_info->txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) ) {
    res  = task_info->exec_res;
    return -1;
  }

  /* execute */
  task_info->txn->flags |= FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
  task_info->exec_res = fd_execute_txn( task_info->txn_ctx );

  if( task_info->exec_res==0 ) {
    fd_txn_reclaim_accounts( task_info->txn_ctx );
  }

  ulong curr = slot_ctx->slot_bank.collected_execution_fees;
  FD_COMPILER_MFENCE();
  while( FD_UNLIKELY( FD_ATOMIC_CAS( &slot_ctx->slot_bank.collected_execution_fees, curr, curr + task_info->txn_ctx->execution_fee ) != curr ) ) {
    FD_SPIN_PAUSE();
    curr = slot_ctx->slot_bank.collected_execution_fees;
    FD_COMPILER_MFENCE();
  }

  curr = slot_ctx->slot_bank.collected_priority_fees;
  FD_COMPILER_MFENCE();
  while( FD_UNLIKELY( FD_ATOMIC_CAS( &slot_ctx->slot_bank.collected_priority_fees, curr, curr + task_info->txn_ctx->priority_fee ) != curr ) ) {
    FD_SPIN_PAUSE();
    curr = slot_ctx->slot_bank.collected_priority_fees;
    FD_COMPILER_MFENCE();
  }

  fd_runtime_finalize_txn( slot_ctx, capture_ctx, task_info );

  return res;

  } FD_SCRATCH_SCOPE_END;
}


/* This setup phase sets up the borrowed accounts in each transaction and
   performs a series of checks on each of the transactions. */
int
fd_runtime_prep_and_exec_txns_tpool( fd_exec_slot_ctx_t *         slot_ctx,
                                     fd_execute_txn_task_info_t * task_info,
                                     ulong                        txn_cnt,
                                     fd_tpool_t *                 tpool ) {
  int res = 0;
  FD_SCRATCH_SCOPE_BEGIN {

    fd_tpool_exec_all_rrobin( tpool, 0, fd_tpool_worker_cnt( tpool ), fd_txn_prep_and_exec_task, task_info, slot_ctx, task_info->txn_ctx->capture_ctx, 1, 0, txn_cnt );

    for( ulong txn_idx=0UL; txn_idx<txn_cnt; txn_idx++ ) {
      if( FD_UNLIKELY( !( task_info[txn_idx].txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) ) {
        res |= task_info[txn_idx].exec_res;
        continue;
      }
    }

  } FD_SCRATCH_SCOPE_END;
  return res;
}

int
fd_runtime_prepare_txns_phase3( fd_exec_slot_ctx_t *         slot_ctx,
                                fd_execute_txn_task_info_t * task_info,
                                ulong                        txn_cnt ) {

  int result = 0;
  /* Loop across transactions */
  for (ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++) {
    fd_exec_txn_ctx_t * txn_ctx = task_info[txn_idx].txn_ctx;

    if( !( task_info[txn_idx].txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) {
      continue;
    }

    int res = fd_execute_txn_prepare_phase3( slot_ctx, txn_ctx, task_info[txn_idx].txn );
    if( res != 0 ) {
      FD_LOG_DEBUG(("could not prepare txn phase 3"));
      task_info[txn_idx].txn->flags = 0;
      result = res;
    }

  }

  return result;
}

void
fd_runtime_copy_program_data_acc_to_pruned_funk( fd_funk_t * pruned_funk,
                                                 fd_funk_txn_t * prune_txn,
                                                 fd_exec_slot_ctx_t * slot_ctx,
                                                 fd_pubkey_t const * program_pubkey ) {
  /* If account corresponds to bpf_upgradeable, copy over the programdata as well.
     This is necessary for executing any bpf upgradeable program. */

  fd_account_meta_t const * program_acc = fd_acc_mgr_view_raw( slot_ctx->acc_mgr, NULL,
                                                               program_pubkey, NULL, NULL, NULL );

  if( memcmp( program_acc->info.owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return;
  }

  fd_bincode_decode_ctx_t ctx = {
    .data    = (uchar *)program_acc + program_acc->hlen,
    .dataend = (char *) ctx.data + program_acc->dlen,
    .valloc  = slot_ctx->valloc,
  };

  fd_bpf_upgradeable_loader_state_t loader_state;
  if ( fd_bpf_upgradeable_loader_state_decode( &loader_state, &ctx ) ) {
    FD_LOG_ERR(( "fd_bpf_upgradeable_loader_state_decode failed" ));
  }

  if( !fd_bpf_upgradeable_loader_state_is_program( &loader_state ) ) {
    FD_LOG_ERR(( "fd_bpf_upgradeable_loader_state_is_program failed" ));
  }

  fd_pubkey_t * programdata_pubkey = (fd_pubkey_t *)&loader_state.inner.program.programdata_address;
  fd_funk_rec_key_t programdata_reckey = fd_acc_funk_key( programdata_pubkey );

  /* Copy over programdata record */
  fd_funk_rec_t * new_rec_pd = fd_funk_rec_write_prepare( pruned_funk, prune_txn, &programdata_reckey,
                                                          0, 1, NULL, NULL );
  FD_TEST(( !!new_rec_pd ));
}

void
fd_runtime_copy_accounts_to_pruned_funk( fd_funk_t * pruned_funk,
                                         fd_funk_txn_t * prune_txn,
                                         fd_exec_slot_ctx_t * slot_ctx,
                                         fd_exec_txn_ctx_t * txn_ctx ) {
  /* This function is only responsible for copying over the account ids that are
     modified. The account data is copied over after execution is complete. */

  /* Copy over ALUTs */
  fd_txn_acct_addr_lut_t * addr_luts = fd_txn_get_address_tables( (fd_txn_t *) txn_ctx->txn_descriptor );
  for( ulong i = 0; i < txn_ctx->txn_descriptor->addr_table_lookup_cnt; i++ ) {
    fd_txn_acct_addr_lut_t * addr_lut = &addr_luts[i];
    fd_pubkey_t const * addr_lut_acc = (fd_pubkey_t *)((uchar *)txn_ctx->_txn_raw->raw + addr_lut->addr_off);
    if ( addr_lut_acc ) {
      fd_funk_rec_key_t acc_lut_rec_key = fd_acc_funk_key( addr_lut_acc );
      fd_funk_rec_write_prepare( pruned_funk, prune_txn, &acc_lut_rec_key, 0, 1, NULL, NULL );
    }
  }

  /* Get program id from top level instructions and copy over programdata */
  fd_instr_info_t instrs[txn_ctx->txn_descriptor->instr_cnt];
  for ( ushort i = 0; i < txn_ctx->txn_descriptor->instr_cnt; i++ ) {
    fd_txn_instr_t const * txn_instr = &txn_ctx->txn_descriptor->instr[i];
    fd_convert_txn_instr_to_instr( txn_ctx, txn_instr, txn_ctx->borrowed_accounts, &instrs[i] );
    fd_pubkey_t program_pubkey = instrs[i].program_id_pubkey;
    fd_funk_rec_key_t program_rec_key = fd_acc_funk_key( &program_pubkey );
    fd_funk_rec_t *new_rec = fd_funk_rec_write_prepare(pruned_funk, prune_txn, &program_rec_key, 0, 1, NULL, NULL);
    if ( !new_rec ) {
      FD_LOG_NOTICE(("fd_funk_rec_write_prepare failed %s", FD_BASE58_ENC_32_ALLOCA( &program_pubkey ) ));
      continue;
    }

    /* If account corresponds to bpf_upgradeable, copy over the programdata as well */
    fd_runtime_copy_program_data_acc_to_pruned_funk( pruned_funk, prune_txn, slot_ctx, &program_pubkey );
  }

  /* Write out all accounts touched during the transaction, copy over all program data accounts for
     any BPF upgradeable accounts in case they are a CPI's program account. */
  for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
    fd_pubkey_t * acc_pubkey = (fd_pubkey_t *)&txn_ctx->accounts[i].key;
    fd_funk_rec_key_t rec_key = fd_acc_funk_key( acc_pubkey );
    fd_funk_rec_t * rec = fd_funk_rec_write_prepare( pruned_funk, prune_txn, &rec_key, 0, 1, NULL, NULL );
    FD_TEST(( !!rec ));
    fd_runtime_copy_program_data_acc_to_pruned_funk( pruned_funk, prune_txn, slot_ctx, acc_pubkey );
  }
}

void
fd_runtime_write_transaction_status( fd_capture_ctx_t * capture_ctx,
                                     fd_exec_slot_ctx_t * slot_ctx,
                                     fd_exec_txn_ctx_t * txn_ctx,
                                     int exec_txn_err) {
  /* Look up solana-side transaction status details */
  fd_blockstore_t * blockstore = txn_ctx->slot_ctx->blockstore;
  uchar * sig = (uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->signature_off;
  fd_blockstore_txn_map_t * txn_map_entry = fd_blockstore_txn_query( blockstore, sig );
  if ( txn_map_entry != NULL ) {
    void * meta = fd_wksp_laddr_fast( fd_blockstore_wksp( blockstore ), txn_map_entry->meta_gaddr );

    fd_solblock_TransactionStatusMeta txn_status = {0};
    /* Need to handle case for ledgers where transaction status is not available.
        This case will be handled in fd_solcap_diff. */
    ulong fd_cus_consumed     = txn_ctx->compute_unit_limit - txn_ctx->compute_meter;
    ulong solana_cus_consumed = ULONG_MAX;
    ulong solana_txn_err      = ULONG_MAX;
    if ( meta != NULL ) {
      pb_istream_t stream = pb_istream_from_buffer( meta, txn_map_entry->meta_sz );
      if ( pb_decode( &stream, fd_solblock_TransactionStatusMeta_fields, &txn_status ) == false ) {
        FD_LOG_WARNING(("no txn_status decoding found sig=%s (%s)", FD_BASE58_ENC_64_ALLOCA( sig ), PB_GET_ERROR(&stream)));
      }
      if ( txn_status.has_compute_units_consumed ) {
        solana_cus_consumed = txn_status.compute_units_consumed;
      }
      if ( txn_status.has_err ) {
        solana_txn_err = txn_status.err.err->bytes[0];
      }

      fd_solcap_Transaction txn = {
        .slot            = slot_ctx->slot_bank.slot,
        .fd_txn_err      = exec_txn_err,
        .fd_custom_err   = txn_ctx->custom_err,
        .solana_txn_err  = solana_txn_err,
        .fd_cus_used     = fd_cus_consumed,
        .solana_cus_used = solana_cus_consumed,
        .instr_err_idx = txn_ctx->instr_err_idx == INT_MAX ? -1 : txn_ctx->instr_err_idx,
      };
      memcpy( txn.txn_sig, sig, sizeof(fd_signature_t) );

      fd_exec_instr_ctx_t const * failed_instr = txn_ctx->failed_instr;
      if( failed_instr ) {
        assert( failed_instr->depth < 4 );
        txn.instr_err               = failed_instr->instr_err;
        txn.failed_instr_path_count = failed_instr->depth + 1;
        for( long j = failed_instr->depth; j>=0L; j-- ) {
          txn.failed_instr_path[j] = failed_instr->index;
          failed_instr             = failed_instr->parent;
        }
      }

      fd_solcap_write_transaction2( capture_ctx->capture, &txn );
    }
  }
}

int
fd_runtime_finalize_txn( fd_exec_slot_ctx_t *         slot_ctx,
                         fd_capture_ctx_t *           capture_ctx,
                         fd_execute_txn_task_info_t * task_info ) {

  fd_exec_txn_ctx_t * txn_ctx      = task_info->txn_ctx;
  int                 exec_txn_err = task_info->exec_res;

  fd_funk_txn_t * prune_txn = NULL;
  if( capture_ctx != NULL && capture_ctx->pruned_funk != NULL ) {
    fd_funk_txn_xid_t prune_xid;
    fd_memset( &prune_xid, 0x42, sizeof(fd_funk_txn_xid_t) );
    fd_funk_txn_t * txn_map = fd_funk_txn_map( capture_ctx->pruned_funk, fd_funk_wksp( capture_ctx->pruned_funk ) );
    prune_txn = fd_funk_txn_query( &prune_xid, txn_map );
  }

  /* Add all involved records to pruned funk */
  if( capture_ctx != NULL && capture_ctx->pruned_funk != NULL ) {
    fd_funk_start_write( capture_ctx->pruned_funk );
    fd_runtime_copy_accounts_to_pruned_funk( capture_ctx->pruned_funk, prune_txn, slot_ctx, txn_ctx );
    fd_funk_end_write( capture_ctx->pruned_funk );
  }

  /* For ledgers that contain txn status, decode and write out for solcap */
  if( capture_ctx != NULL && capture_ctx->capture && capture_ctx->capture_txns ) {
    // TODO: probably need to get rid of this lock or special case it to not use funk's lock.
    fd_funk_start_write( slot_ctx->acc_mgr->funk );
    fd_runtime_write_transaction_status( capture_ctx, slot_ctx, txn_ctx, exec_txn_err );
    fd_funk_end_write( slot_ctx->acc_mgr->funk );
  }

  if( slot_ctx->status_cache ) {
    fd_txncache_insert_t * status_insert = fd_scratch_alloc( alignof(fd_txncache_insert_t), sizeof(fd_txncache_insert_t) );
    uchar *                results       = fd_scratch_alloc( alignof(uchar), sizeof(uchar) );

    results[0] = exec_txn_err == 0 ? 1 : 0;
    fd_txncache_insert_t * curr_insert = &status_insert[0];
    curr_insert->blockhash = ((uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->recent_blockhash_off);
    curr_insert->slot = slot_ctx->slot_bank.slot;
    fd_hash_t * hash = &txn_ctx->blake_txn_msg_hash;
    curr_insert->txnhash = hash->uc;
    curr_insert->result = &results[0];
    if( !fd_txncache_insert_batch( slot_ctx->status_cache, status_insert, 1UL ) ) {
      FD_LOG_DEBUG(("Status cache is full, this should not be possible"));
    }
  }

  if( FD_UNLIKELY( exec_txn_err ) ) {

    /* Save the fee_payer. Everything but the fee balance should be reset.
       TODO: an optimization here could be to use a dirty flag in the
       borrowed account. If the borrowed account data has been changed in
       any way, then the full account can be rolled back as it is done now.
       However, most of the time the account data is not changed, and only
       the lamport balance has to change. */
    fd_borrowed_account_t * borrowed_account = fd_borrowed_account_init( &txn_ctx->borrowed_accounts[0] );

    fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, &txn_ctx->accounts[0], borrowed_account );
    memcpy( borrowed_account->pubkey->key, &txn_ctx->accounts[0], sizeof(fd_pubkey_t) );

    void * borrowed_account_data = fd_spad_alloc( txn_ctx->spad, FD_SPAD_ALIGN, FD_ACC_TOT_SZ_MAX );
    fd_borrowed_account_make_modifiable( borrowed_account, borrowed_account_data );
    borrowed_account->meta->info.lamports -= (txn_ctx->execution_fee + txn_ctx->priority_fee);

    fd_acc_mgr_save_non_tpool( slot_ctx->acc_mgr, slot_ctx->funk_txn, &txn_ctx->borrowed_accounts[0] );

    for( ulong i=1UL; i<txn_ctx->accounts_cnt; i++ ) {
      if( txn_ctx->nonce_accounts[i] ) {
        ushort                recent_blockhash_off = txn_ctx->txn_descriptor->recent_blockhash_off;
        fd_hash_t *           recent_blockhash     = (fd_hash_t *)((uchar *)txn_ctx->_txn_raw->raw + recent_blockhash_off);
        fd_block_hash_queue_t queue                = slot_ctx->slot_bank.block_hash_queue;
        ulong                 queue_sz             = fd_hash_hash_age_pair_t_map_size( queue.ages_pool, queue.ages_root );
        if( FD_UNLIKELY( !queue_sz ) ) {
          FD_LOG_ERR(( "Blockhash queue is empty" ));
        }

        if( !fd_executor_is_blockhash_valid_for_age( &queue, recent_blockhash, FD_RECENT_BLOCKHASHES_MAX_ENTRIES ) ) {
          fd_acc_mgr_save_non_tpool( slot_ctx->acc_mgr, slot_ctx->funk_txn, &txn_ctx->borrowed_accounts[i] );
        }
      }
    }
  } else {

    int dirty_vote_acc  = txn_ctx->dirty_vote_acc;
    int dirty_stake_acc = txn_ctx->dirty_stake_acc;

    for( ulong i=0UL; i<txn_ctx->accounts_cnt; i++ ) {
      if( !fd_txn_account_is_writable_idx( txn_ctx, (int)i ) ) {
        continue;
      }

      fd_borrowed_account_t * acc_rec = &txn_ctx->borrowed_accounts[i];

      if( dirty_vote_acc && 0==memcmp( acc_rec->const_meta->info.owner, &fd_solana_vote_program_id, sizeof(fd_pubkey_t) ) ) {
        /* lock for inserting/modifying vote accounts in slot ctx. */
        fd_funk_start_write( slot_ctx->acc_mgr->funk );
        fd_vote_store_account( slot_ctx, acc_rec );
        FD_SCRATCH_SCOPE_BEGIN {
          fd_vote_state_versioned_t vsv[1];
          fd_bincode_decode_ctx_t decode_vsv =
            { .data    = acc_rec->const_data,
              .dataend = acc_rec->const_data + acc_rec->const_meta->dlen,
              .valloc  = fd_scratch_virtual() };

          int err = fd_vote_state_versioned_decode( vsv, &decode_vsv );
          if( err ) break; /* out of scratch scope */

          fd_vote_block_timestamp_t const * ts = NULL;
          switch( vsv->discriminant ) {
          case fd_vote_state_versioned_enum_v0_23_5:
            ts = &vsv->inner.v0_23_5.last_timestamp;
            break;
          case fd_vote_state_versioned_enum_v1_14_11:
            ts = &vsv->inner.v1_14_11.last_timestamp;
            break;
          case fd_vote_state_versioned_enum_current:
            ts = &vsv->inner.current.last_timestamp;
            break;
          default:
            __builtin_unreachable();
          }

          fd_vote_record_timestamp_vote_with_slot( slot_ctx, acc_rec->pubkey, ts->timestamp, ts->slot );
        }
        FD_SCRATCH_SCOPE_END;
        fd_funk_end_write( slot_ctx->acc_mgr->funk );
      }

      if( dirty_stake_acc && 0==memcmp( acc_rec->const_meta->info.owner, &fd_solana_stake_program_id, sizeof(fd_pubkey_t) ) ) {
        // TODO: does this correctly handle stake account close?
        fd_funk_start_write( slot_ctx->acc_mgr->funk );
        fd_store_stake_delegation( slot_ctx, acc_rec );
        fd_funk_end_write( slot_ctx->acc_mgr->funk );
      }

      fd_acc_mgr_save_non_tpool( slot_ctx->acc_mgr, slot_ctx->funk_txn, &txn_ctx->borrowed_accounts[i] );
    }
  }
  ulong curr = slot_ctx->signature_cnt;
  FD_COMPILER_MFENCE();
  while( FD_UNLIKELY( FD_ATOMIC_CAS( &slot_ctx->signature_cnt, curr, curr + txn_ctx->txn_descriptor->signature_cnt ) != curr ) ) {
    FD_SPIN_PAUSE();
    curr = slot_ctx->signature_cnt;
    FD_COMPILER_MFENCE();
  }

  return 0;
}

static bool
encode_return_data( pb_ostream_t *stream, const pb_field_t *field, void * const *arg ) {
  fd_exec_txn_ctx_t * txn_ctx = (fd_exec_txn_ctx_t *)(*arg);
  pb_encode_tag_for_field(stream, field);
  pb_encode_string(stream, txn_ctx->return_data.data, txn_ctx->return_data.len );
  return 1;
}

static ulong
fd_txn_copy_meta( fd_exec_txn_ctx_t * txn_ctx, uchar * dest, ulong dest_sz ) {
  fd_solblock_TransactionStatusMeta txn_status = {0};

  txn_status.has_fee = 1;
  txn_status.fee = txn_ctx->execution_fee + txn_ctx->priority_fee;

  txn_status.has_compute_units_consumed = 1;
  txn_status.compute_units_consumed = txn_ctx->compute_unit_limit - txn_ctx->compute_meter;

  ulong readonly_cnt = 0;
  ulong writable_cnt = 0;
  if( txn_ctx->txn_descriptor->transaction_version == FD_TXN_V0 ) {
    fd_txn_acct_addr_lut_t const * addr_luts = fd_txn_get_address_tables_const( txn_ctx->txn_descriptor );
    for( ulong i = 0; i < txn_ctx->txn_descriptor->addr_table_lookup_cnt; i++ ) {
      fd_txn_acct_addr_lut_t const * addr_lut = &addr_luts[i];
      readonly_cnt += addr_lut->readonly_cnt;
      writable_cnt += addr_lut->writable_cnt;
    }
  }

  typedef PB_BYTES_ARRAY_T(32) my_ba_t;
  typedef union { my_ba_t my; pb_bytes_array_t normal; } union_ba_t;
  union_ba_t writable_ba[writable_cnt];
  pb_bytes_array_t * writable_baptr[writable_cnt];
  txn_status.loaded_writable_addresses_count = (uint)writable_cnt;
  txn_status.loaded_writable_addresses = writable_baptr;
  ulong idx2 = txn_ctx->txn_descriptor->acct_addr_cnt;
  for (ulong idx = 0; idx < writable_cnt; idx++) {
    pb_bytes_array_t * ba = writable_baptr[ idx ] = &writable_ba[ idx ].normal;
    ba->size = 32;
    fd_memcpy(ba->bytes, &txn_ctx->accounts[idx2++], 32);
  }

  union_ba_t readonly_ba[readonly_cnt];
  pb_bytes_array_t * readonly_baptr[readonly_cnt];
  txn_status.loaded_readonly_addresses_count = (uint)readonly_cnt;
  txn_status.loaded_readonly_addresses = readonly_baptr;
  for (ulong idx = 0; idx < readonly_cnt; idx++) {
    pb_bytes_array_t * ba = readonly_baptr[ idx ] = &readonly_ba[ idx ].normal;
    ba->size = 32;
    fd_memcpy(ba->bytes, &txn_ctx->accounts[idx2++], 32);
  }
  ulong acct_cnt = txn_ctx->accounts_cnt;
  FD_TEST(acct_cnt == idx2);

  txn_status.pre_balances_count = txn_status.post_balances_count = (pb_size_t)acct_cnt;
  uint64_t pre_balances[acct_cnt];
  txn_status.pre_balances = pre_balances;
  uint64_t post_balances[acct_cnt];
  txn_status.post_balances = post_balances;

  for (ulong idx = 0; idx < acct_cnt; idx++) {
    fd_borrowed_account_t const * acct = &txn_ctx->borrowed_accounts[idx];
    ulong pre = ( acct->starting_lamports == ULONG_MAX ? 0UL : acct->starting_lamports );
    pre_balances[idx] = pre;
    post_balances[idx] = ( acct->meta ? acct->meta->info.lamports :
                           ( acct->orig_meta ? acct->orig_meta->info.lamports : pre ) );
  }

  if( txn_ctx->return_data.len ) {
    txn_status.has_return_data = 1;
    txn_status.return_data.has_program_id = 1;
    fd_memcpy( txn_status.return_data.program_id, txn_ctx->return_data.program_id.uc, 32U );
    pb_callback_t data = { .funcs.encode = encode_return_data, .arg = txn_ctx };
    txn_status.return_data.data = data;
  }

  union {
    pb_bytes_array_t arr;
    uchar space[64];
  } errarr;
  pb_byte_t * errptr = errarr.arr.bytes;
  if( txn_ctx->custom_err != UINT_MAX ) {
    *(uint*)errptr = 8 /* Instruction error */;
    errptr += sizeof(uint);
    *errptr = (uchar)txn_ctx->instr_err_idx;
    errptr += 1;
    *(int*)errptr = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    errptr += sizeof(int);
    *(uint*)errptr = txn_ctx->custom_err;
    errptr += sizeof(uint);
    errarr.arr.size = (uint)(errptr - errarr.arr.bytes);
    txn_status.has_err = 1;
    txn_status.err.err = &errarr.arr;
  } else if( txn_ctx->exec_err ) {
    switch( txn_ctx->exec_err_kind ) {
      case FD_EXECUTOR_ERR_KIND_SYSCALL:
        break;
      case FD_EXECUTOR_ERR_KIND_INSTR:
        *(uint*)errptr = 8 /* Instruction error */;
        errptr += sizeof(uint);
        *errptr = (uchar)txn_ctx->instr_err_idx;
        errptr += 1;
        *(int*)errptr = txn_ctx->exec_err;
        errptr += sizeof(int);
        errarr.arr.size = (uint)(errptr - errarr.arr.bytes);
        txn_status.has_err = 1;
        txn_status.err.err = &errarr.arr;
        break;
      case FD_EXECUTOR_ERR_KIND_EBPF:
        break;
    }
  }

  if( dest == NULL ) {
    size_t sz = 0;
    bool r = pb_get_encoded_size( &sz, fd_solblock_TransactionStatusMeta_fields, &txn_status );
    if( !r ) {
      FD_LOG_WARNING(( "pb_get_encoded_size failed" ));
      return 0;
    }
    return sz + txn_ctx->log_collector.buf_sz;
  }

  pb_ostream_t stream = pb_ostream_from_buffer( dest, dest_sz );
  bool r = pb_encode( &stream, fd_solblock_TransactionStatusMeta_fields, &txn_status );
  if( !r ) {
    FD_LOG_WARNING(( "pb_encode failed" ));
    return 0;
  }
  pb_write( &stream, txn_ctx->log_collector.buf, txn_ctx->log_collector.buf_sz );
  return stream.bytes_written;
}

/* fd_runtime_finalize_txns_update_blockstore_meta() updates transaction metadata
   after execution.

   Execution recording is controlled by slot_ctx->enable_exec_recording, and this
   function does nothing if execution recording is off.  The following comments
   only apply when execution recording is on.

   Transaction metadata includes execution result (success/error), balance changes,
   transaction logs, ...  All this info is not part of consensus but can be retrieved,
   for instace, via RPC getTransaction.  Firedancer stores txn meta in the blockstore,
   in the same binary format as Agave, protobuf TransactionStatusMeta. */
void
fd_runtime_finalize_txns_update_blockstore_meta( fd_exec_slot_ctx_t *         slot_ctx,
                                                 fd_execute_txn_task_info_t * task_info,
                                                 ulong                        txn_cnt ) {
  /* Nothing to do if execution recording is off */
  if( !slot_ctx->enable_exec_recording ) {
    return;
  }

  fd_blockstore_t * blockstore      = slot_ctx->blockstore;
  fd_wksp_t * blockstore_wksp       = fd_blockstore_wksp( blockstore );
  fd_alloc_t * blockstore_alloc     = fd_wksp_laddr_fast( blockstore_wksp, blockstore->alloc_gaddr );
  fd_blockstore_txn_map_t * txn_map = fd_wksp_laddr_fast( blockstore_wksp, blockstore->txn_map_gaddr );

  /* Get the total size of all logs */
  ulong tot_meta_sz = 2*sizeof(ulong);
  for( ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++ ) {
    /* Prebalance compensation */
    fd_exec_txn_ctx_t * txn_ctx = task_info[txn_idx].txn_ctx;
    txn_ctx->borrowed_accounts[0].starting_lamports += (txn_ctx->execution_fee + txn_ctx->priority_fee);
    /* Get the size without the copy */
    tot_meta_sz += fd_txn_copy_meta( txn_ctx, NULL, 0 );
  }
  uchar * cur_laddr = fd_alloc_malloc( blockstore_alloc, 1, tot_meta_sz );
  if( cur_laddr == NULL ) {
    return;
  }
  uchar * const end_laddr = cur_laddr + tot_meta_sz;

  fd_blockstore_start_write( blockstore );
  fd_block_t * blk = slot_ctx->block;
  /* Link to previous allocation */
  ((ulong*)cur_laddr)[0] = blk->txns_meta_gaddr;
  ((ulong*)cur_laddr)[1] = blk->txns_meta_sz;
  blk->txns_meta_gaddr = fd_wksp_gaddr_fast( blockstore_wksp, cur_laddr );
  blk->txns_meta_sz    = tot_meta_sz;
  cur_laddr += 2*sizeof(ulong);

  for( ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++ ) {
    fd_exec_txn_ctx_t * txn_ctx = task_info[txn_idx].txn_ctx;
    ulong meta_sz = fd_txn_copy_meta( txn_ctx, cur_laddr, (size_t)(end_laddr - cur_laddr) );
    if( meta_sz ) {
      ulong  meta_gaddr = fd_wksp_gaddr_fast( blockstore_wksp, cur_laddr );

      /* Update all the signatures */
      char const * sig_p = (char const *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->signature_off;
      fd_blockstore_txn_key_t sig;
      for( uchar i=0U; i<txn_ctx->txn_descriptor->signature_cnt; i++ ) {
        fd_memcpy( &sig, sig_p, sizeof(fd_blockstore_txn_key_t) );
        fd_blockstore_txn_map_t * txn_map_entry = fd_blockstore_txn_map_query( txn_map, &sig, NULL );
        if( FD_LIKELY( txn_map_entry ) ) {
          txn_map_entry->meta_gaddr = meta_gaddr;
          txn_map_entry->meta_sz    = meta_sz;
        }
        sig_p += FD_ED25519_SIG_SZ;
      }

      cur_laddr += meta_sz;
    }
    fd_log_collector_delete( &txn_ctx->log_collector );
  }

  FD_TEST( cur_laddr == end_laddr );

  fd_blockstore_end_write( blockstore );
}

/* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/accounts-db/src/accounts.rs#L700 */
int
fd_runtime_finalize_txns_tpool( fd_exec_slot_ctx_t *         slot_ctx,
                                fd_capture_ctx_t *           capture_ctx,
                                fd_execute_txn_task_info_t * task_info,
                                ulong                        txn_cnt,
                                fd_tpool_t *                 tpool ) {
  FD_SCRATCH_SCOPE_BEGIN {

    fd_funk_txn_t * prune_txn = NULL;
    if( capture_ctx != NULL && capture_ctx->pruned_funk != NULL ) {
      fd_funk_txn_xid_t prune_xid;
      fd_memset( &prune_xid, 0x42, sizeof(fd_funk_txn_xid_t) );
      fd_funk_txn_t * txn_map = fd_funk_txn_map( capture_ctx->pruned_funk, fd_funk_wksp( capture_ctx->pruned_funk ) );
      prune_txn = fd_funk_txn_query( &prune_xid, txn_map );
    }

    /* Store transaction metadata, including logs */
    fd_runtime_finalize_txns_update_blockstore_meta( slot_ctx, task_info, txn_cnt );

    fd_txncache_insert_t * status_insert  = NULL;
    uchar *                results        = NULL;
    ulong                  num_cache_txns = 0UL;


    if( FD_LIKELY( slot_ctx->status_cache ) ) {
      status_insert = fd_scratch_alloc( alignof(fd_txncache_insert_t), txn_cnt * sizeof(fd_txncache_insert_t) );
      results       = fd_scratch_alloc( alignof(uchar), txn_cnt * sizeof(uchar) );
    }

    fd_borrowed_account_t * * accounts_to_save = fd_scratch_alloc( 8UL, 128UL * txn_cnt * sizeof(fd_borrowed_account_t *) );
    ulong acc_idx = 0UL;
    for( ulong txn_idx=0UL; txn_idx<txn_cnt; txn_idx++ ) {
      /* Transaction was skipped due to preparation failure. */
      if( FD_UNLIKELY( !( task_info[txn_idx].txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS ) ) ) {
        continue;
      }
      fd_exec_txn_ctx_t * txn_ctx      = task_info[txn_idx].txn_ctx;
      int                 exec_txn_err = task_info[txn_idx].exec_res;

      /* Add all involved records to pruned funk */
      if( FD_UNLIKELY( capture_ctx != NULL && capture_ctx->pruned_funk != NULL ) ) {
        fd_funk_start_write( capture_ctx->pruned_funk );
        fd_runtime_copy_accounts_to_pruned_funk( capture_ctx->pruned_funk, prune_txn, slot_ctx, txn_ctx );
        fd_funk_end_write( capture_ctx->pruned_funk );
      }

      /* For ledgers that contain txn status, decode and write out for solcap */
      if( FD_UNLIKELY( capture_ctx != NULL && capture_ctx->capture && capture_ctx->capture_txns ) ) {
        fd_runtime_write_transaction_status( capture_ctx, slot_ctx, txn_ctx, exec_txn_err );
      }

      slot_ctx->signature_cnt += txn_ctx->txn_descriptor->signature_cnt;

      if( FD_LIKELY( slot_ctx->status_cache ) ) {
        results[num_cache_txns] = exec_txn_err == 0 ? 1 : 0;
        fd_txncache_insert_t * curr_insert = &status_insert[num_cache_txns];
        curr_insert->blockhash = ((uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->recent_blockhash_off);
        curr_insert->slot = slot_ctx->slot_bank.slot;
        fd_hash_t * hash = &txn_ctx->blake_txn_msg_hash;
        curr_insert->txnhash = hash->uc;
        curr_insert->result = &results[num_cache_txns];
        num_cache_txns++;
      }

      if( FD_UNLIKELY( exec_txn_err ) ) {
        /* Save the fee_payer. Everything but the fee balance should be reset.
           TODO: an optimization here could be to use a dirty flag in the
           borrowed account. If the borrowed account data has been changed in
           any way, then the full account can be rolled back as it is done now.
           However, most of the time the account data is not changed, and only
           the lamport balance has to change. */
        fd_borrowed_account_t * borrowed_account = fd_borrowed_account_init( &txn_ctx->borrowed_accounts[0] );

        fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, &txn_ctx->accounts[0], borrowed_account );
        memcpy( borrowed_account->pubkey->key, &txn_ctx->accounts[0], sizeof(fd_pubkey_t) );

        void * borrowed_account_data = fd_spad_alloc( txn_ctx->spad, FD_SPAD_ALIGN, FD_ACC_TOT_SZ_MAX );
        fd_borrowed_account_make_modifiable( borrowed_account, borrowed_account_data );
        borrowed_account->meta->info.lamports -= (txn_ctx->execution_fee + txn_ctx->priority_fee);

        accounts_to_save[acc_idx++] = &txn_ctx->borrowed_accounts[0];
        for( ulong i=1UL; i<txn_ctx->accounts_cnt; i++ ) {
          if( txn_ctx->nonce_accounts[i] ) {
            ushort                recent_blockhash_off = txn_ctx->txn_descriptor->recent_blockhash_off;
            fd_hash_t *           recent_blockhash     = (fd_hash_t *)((uchar *)txn_ctx->_txn_raw->raw + recent_blockhash_off);
            fd_block_hash_queue_t queue                = slot_ctx->slot_bank.block_hash_queue;
            ulong                 queue_sz             = fd_hash_hash_age_pair_t_map_size( queue.ages_pool, queue.ages_root );
            if( FD_UNLIKELY( !queue_sz ) ) {
              FD_LOG_ERR(( "Blockhash queue is empty" ));
            }

            if( !fd_executor_is_blockhash_valid_for_age( &queue, recent_blockhash, FD_RECENT_BLOCKHASHES_MAX_ENTRIES ) ) {
              accounts_to_save[acc_idx++] = &txn_ctx->borrowed_accounts[i];
            }
            break;
          }
        }
      } else {
        int dirty_vote_acc  = txn_ctx->dirty_vote_acc;
        int dirty_stake_acc = txn_ctx->dirty_stake_acc;

        for( ulong i=0UL; i<txn_ctx->accounts_cnt; i++ ) {
          if( !fd_txn_account_is_writable_idx( txn_ctx, (int)i ) ) {
            continue;
          }

          fd_borrowed_account_t * acc_rec = &txn_ctx->borrowed_accounts[i];

          if( dirty_vote_acc && !memcmp( acc_rec->const_meta->info.owner, &fd_solana_vote_program_id, sizeof(fd_pubkey_t) ) ) {
            fd_vote_store_account( slot_ctx, acc_rec );
            FD_SCRATCH_SCOPE_BEGIN {
              fd_vote_state_versioned_t vsv[1];
              fd_bincode_decode_ctx_t decode_vsv =
                { .data    = acc_rec->const_data,
                  .dataend = acc_rec->const_data + acc_rec->const_meta->dlen,
                  .valloc  = fd_scratch_virtual() };

              int err = fd_vote_state_versioned_decode( vsv, &decode_vsv );
              if( err ) break; /* out of scratch scope */

              fd_vote_block_timestamp_t const * ts = NULL;
              switch( vsv->discriminant ) {
              case fd_vote_state_versioned_enum_v0_23_5:
                ts = &vsv->inner.v0_23_5.last_timestamp;
                break;
              case fd_vote_state_versioned_enum_v1_14_11:
                ts = &vsv->inner.v1_14_11.last_timestamp;
                break;
              case fd_vote_state_versioned_enum_current:
                ts = &vsv->inner.current.last_timestamp;
                break;
              default:
                __builtin_unreachable();
              }

              fd_vote_record_timestamp_vote_with_slot( slot_ctx, acc_rec->pubkey, ts->timestamp, ts->slot );
            }
            FD_SCRATCH_SCOPE_END;
          }

          if( dirty_stake_acc && !memcmp( acc_rec->const_meta->info.owner, &fd_solana_stake_program_id, sizeof(fd_pubkey_t) ) ) {
            // TODO: does this correctly handle stake account close?
            fd_store_stake_delegation( slot_ctx, acc_rec );
          }

          accounts_to_save[acc_idx++] = acc_rec;
        }
      }
    }

    /* All the accounts have been accumulated and can be saved */

    // TODO: we need to use the txn ctx funk_txn, valloc, etc.
    int err = fd_acc_mgr_save_many_tpool( slot_ctx->acc_mgr, slot_ctx->funk_txn, accounts_to_save, acc_idx, tpool );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_ERR(( "failed to save edits to accounts" ));
      return -1;
    }

    fd_funk_start_write( slot_ctx->acc_mgr->funk );
    int ret = fd_funk_txn_merge_all_children( slot_ctx->acc_mgr->funk, slot_ctx->funk_txn, 0 );
    fd_funk_end_write( slot_ctx->acc_mgr->funk );

    if( FD_UNLIKELY( ret!=FD_FUNK_SUCCESS ) ) {
      FD_LOG_ERR(( "failed merging funk transaction: (%i-%s) ", ret, fd_funk_strerror(ret) ));
    }

    if( FD_LIKELY( slot_ctx->status_cache ) ) {
      if( FD_UNLIKELY( !fd_txncache_insert_batch( slot_ctx->status_cache, status_insert, num_cache_txns ) ) ) {
        FD_LOG_WARNING(("Status cache is full, this should not be possible"));
      }
    }

  return 0;
  } FD_SCRATCH_SCOPE_END;
}

struct fd_pubkey_map_node {
  ulong       pubkey;
  uint        hash;
};
typedef struct fd_pubkey_map_node fd_pubkey_map_node_t;

#define MAP_NAME                fd_pubkey_map
#define MAP_T                   fd_pubkey_map_node_t
#define MAP_KEY                 pubkey
// #define MAP_KEY_T               fd_pubkey_t
#define MAP_KEY_T               ulong
// #define MAP_KEY_NULL            pubkey_null
#define MAP_KEY_NULL            0
// #define MAP_KEY_INVAL( k )      !( memcmp( &k, &pubkey_null, sizeof( fd_pubkey_t ) ) )
#define MAP_KEY_INVAL( k )      k==0
// #define MAP_KEY_EQUAL( k0, k1 ) !( memcmp( ( &k0 ), ( &k1 ), sizeof( fd_pubkey_t ) ) )
#define MAP_KEY_EQUAL( k0, k1 ) k0==k1
#define MAP_KEY_EQUAL_IS_SLOW   1
// #define MAP_KEY_HASH( key )     ( (uint)( fd_hash( 0UL, &key, sizeof( fd_pubkey_t ) ) ) )
#define MAP_KEY_HASH( key )     ( (uint)key )
#define MAP_MEMOIZE             1
#include "../../util/tmpl/fd_map_dynamic.c"

/* return 0 on failure, 1 if exists, 2 if inserted */
static uint
fd_pubkey_map_insert_if_not_in( fd_pubkey_map_node_t * map,
                                fd_pubkey_t            pubkey ) {
  /* Check if entry already exists */
  ulong h = fd_hash( 0UL, &pubkey, sizeof( fd_pubkey_t ) );
  fd_pubkey_map_node_t * entry = fd_pubkey_map_query( map, h, NULL );
  if( entry )
    return 1;

  /* Insert new */
  entry = fd_pubkey_map_insert( map, h );
  if( FD_UNLIKELY( !entry ) ) return 0;  /* check for internal map collision */

  return 2;
}

void
fd_runtime_generate_wave( fd_execute_txn_task_info_t * task_infos,
                          ulong * prev_incomplete_txn_idxs,
                          ulong prev_incomplete_txn_idxs_cnt,
                          ulong prev_accounts_cnt,
                          ulong * incomplete_txn_idxs,
                          ulong * _incomplete_txn_idxs_cnt,
                          ulong * _incomplete_accounts_cnt,
                          fd_execute_txn_task_info_t * wave_task_infos,
                          ulong * _wave_task_infos_cnt ) {
  FD_SCRATCH_SCOPE_BEGIN {
    int lg_slot_cnt = fd_ulong_find_msb( prev_accounts_cnt ) + 1;
    void * read_map_mem = fd_scratch_alloc( fd_pubkey_map_align(), fd_pubkey_map_footprint( lg_slot_cnt ) );
    fd_pubkey_map_node_t * read_map = fd_pubkey_map_join( fd_pubkey_map_new( read_map_mem, lg_slot_cnt ) );

    void * write_map_mem = fd_scratch_alloc( fd_pubkey_map_align(), fd_pubkey_map_footprint( lg_slot_cnt ) );
    fd_pubkey_map_node_t * write_map = fd_pubkey_map_join( fd_pubkey_map_new( write_map_mem, lg_slot_cnt ) );

    ulong incomplete_txn_idxs_cnt = 0;
    ulong wave_task_infos_cnt = 0;
    ulong accounts_in_wave = 0;
    for( ulong i = 0; i < prev_incomplete_txn_idxs_cnt; i++ ) {
      ulong txn_idx = prev_incomplete_txn_idxs[i];
      uint is_executable_now = 1;
      fd_execute_txn_task_info_t * task_info = &task_infos[txn_idx];
      // if( FD_UNLIKELY( accounts_in_wave >= (() - FD_TXN_ACCT_ADDR_MAX) ) ) {
      //   incomplete_txn_idxs[incomplete_txn_idxs_cnt++] = txn_idx;
      //   continue;
      // }

      for( ulong j = 0; j < task_info->txn_ctx->accounts_cnt; j++ ) {
        ulong h = fd_hash( 0UL, &task_info->txn_ctx->accounts[j], sizeof( fd_pubkey_t ) );
        if( fd_pubkey_map_query( write_map, h, NULL ) != NULL ) {
          is_executable_now = 0;
          break;
        }
        if( fd_txn_account_is_writable_idx( task_info->txn_ctx, (int)j ) ) {
          if( fd_pubkey_map_query( read_map, h, NULL ) != NULL ) {
            is_executable_now = 0;
            break;
          }
        }
      }

      if( !is_executable_now ) {
        incomplete_txn_idxs[incomplete_txn_idxs_cnt++] = txn_idx;
      } else {
        wave_task_infos[wave_task_infos_cnt++] = *task_info;
      }

      /* Include txn in wave */
      for( ulong j = 0; j < task_info->txn_ctx->accounts_cnt; j++ ) {
        if( fd_txn_account_is_writable_idx( task_info->txn_ctx, (int)j ) ) {
          uint ins_res = fd_pubkey_map_insert_if_not_in( write_map, task_info->txn_ctx->accounts[j] );
          if( ins_res == 2 ) {
            accounts_in_wave++;
          }
        } else {
          uint ins_res = fd_pubkey_map_insert_if_not_in( read_map, task_info->txn_ctx->accounts[j] );
          if( ins_res == 2 ) {
            accounts_in_wave++;
          }
        }
      }

    }

    *_incomplete_txn_idxs_cnt = incomplete_txn_idxs_cnt;
    *_incomplete_accounts_cnt = prev_accounts_cnt - accounts_in_wave;
    *_wave_task_infos_cnt = wave_task_infos_cnt;
  } FD_SCRATCH_SCOPE_END;
}

int
fd_runtime_execute_pack_txns( fd_exec_slot_ctx_t * slot_ctx,
                              fd_capture_ctx_t *   capture_ctx,
                              fd_txn_p_t *         txns,
                              ulong                txn_cnt ) {

  FD_SCRATCH_SCOPE_BEGIN {

    fd_execute_txn_task_info_t * task_infos = fd_scratch_alloc( 8, txn_cnt * sizeof(fd_execute_txn_task_info_t));

    for( ulong i=0UL; i<txn_cnt; i++ ) {
      txns[i].flags = FD_TXN_P_FLAGS_SANITIZE_SUCCESS;
    }

    for( ulong i=0UL; i<txn_cnt; i++ ) {
      fd_runtime_prepare_execute_finalize_txn( slot_ctx, capture_ctx, &txns[i], &task_infos[i] );
    }

    ulong curr_cnt = slot_ctx->slot_bank.transaction_count;
    FD_COMPILER_MFENCE();
    while( FD_UNLIKELY( FD_ATOMIC_CAS( &slot_ctx->slot_bank.transaction_count, curr_cnt, curr_cnt + txn_cnt ) != curr_cnt ) ) {
      FD_SPIN_PAUSE();
      curr_cnt = slot_ctx->slot_bank.transaction_count;
      FD_COMPILER_MFENCE();
    }

    return 0;
  } FD_SCRATCH_SCOPE_END;

}

/* NOTE: Don't mess with this call without updating the transaction fuzzing harness appropriately!
   fd_exec_instr_test.c:_txn_context_create_and_exec */
int
fd_runtime_execute_txns_in_waves_tpool( fd_exec_slot_ctx_t * slot_ctx,
                                        fd_capture_ctx_t *   capture_ctx,
                                        fd_txn_p_t *         all_txns,
                                        ulong                total_txn_cnt,
                                        fd_tpool_t *         tpool,
                                        fd_spad_t * *        spads,
                                        ulong                spad_cnt ) {
    int dump_txn = capture_ctx && slot_ctx->slot_bank.slot >= capture_ctx->dump_proto_start_slot && capture_ctx->dump_txn_to_pb;

    /* As a note, the batch size of 128 is a relatively arbitrary number. The
       notion of batching here will change as the transaction execution model
       changes with respect to transaction execution. */
    #define BATCH_SIZE (128UL)
    ulong batch_size = fd_ulong_min( fd_tile_cnt(), BATCH_SIZE );

    for( ulong i=0UL; i<total_txn_cnt; i++ ) {
      all_txns[i].flags = FD_TXN_P_FLAGS_SANITIZE_SUCCESS;
    }

    ulong num_batches = total_txn_cnt/batch_size;
    ulong rem         = total_txn_cnt%batch_size;
    num_batches      += rem ? 1UL : 0UL;

    int res = 0;
    for( ulong i=0UL; i<num_batches; i++ ) {
      FD_SCRATCH_SCOPE_BEGIN {

      fd_txn_p_t * txns    = all_txns + (batch_size * i);
      ulong        txn_cnt = ((i+1UL==num_batches) && rem) ? rem : batch_size;

      fd_execute_txn_task_info_t * task_infos = fd_scratch_alloc( 8, txn_cnt * sizeof(fd_execute_txn_task_info_t));
      fd_execute_txn_task_info_t * wave_task_infos = fd_scratch_alloc( 8, txn_cnt * sizeof(fd_execute_txn_task_info_t));
      ulong wave_task_infos_cnt = 0;

      res = fd_runtime_prepare_txns_start( slot_ctx, task_infos, txns, txn_cnt );
      if( res != 0 ) {
        FD_LOG_DEBUG(("Fail prep 1"));
      }

      ulong * incomplete_txn_idxs = fd_scratch_alloc( 8UL, txn_cnt * sizeof(ulong) );
      ulong incomplete_txn_idxs_cnt = 0;
      ulong incomplete_accounts_cnt = 0;

      /* Setup sanitized txns as incomplete and set the capture context */
      for( ulong i = 0; i < txn_cnt; i++ ) {
        if( FD_UNLIKELY( !( task_infos[i].txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) ) {
          continue;
        }
        incomplete_txn_idxs[incomplete_txn_idxs_cnt++] = i;
        incomplete_accounts_cnt += task_infos[i].txn_ctx->accounts_cnt;
        task_infos[i].txn_ctx->capture_ctx = capture_ctx;
      }

      ulong * next_incomplete_txn_idxs = fd_scratch_alloc( 8UL, txn_cnt * sizeof(ulong) );
      ulong next_incomplete_txn_idxs_cnt = 0;
      ulong next_incomplete_accounts_cnt = 0;

      while( incomplete_txn_idxs_cnt > 0 ) {
        fd_runtime_generate_wave( task_infos, incomplete_txn_idxs, incomplete_txn_idxs_cnt, incomplete_accounts_cnt,
                                  next_incomplete_txn_idxs, &next_incomplete_txn_idxs_cnt, &next_incomplete_accounts_cnt,
                                  wave_task_infos, &wave_task_infos_cnt );
        ulong * temp_incomplete_txn_idxs = incomplete_txn_idxs;
        incomplete_txn_idxs      = next_incomplete_txn_idxs;
        next_incomplete_txn_idxs = temp_incomplete_txn_idxs;
        incomplete_txn_idxs_cnt  = next_incomplete_txn_idxs_cnt;

        // Dump txns in waves
        if( dump_txn ) {
          for( ulong i = 0; i < wave_task_infos_cnt; ++i ) {
            dump_txn_to_protobuf( wave_task_infos[i].txn_ctx, spads[0] );
          }
        }

        /* Assign out spads to the transaction contexts */
        for( ulong i=0UL; i<wave_task_infos_cnt; i++ ) {
          wave_task_infos[i].spads = spads;
        }

        res |= fd_runtime_verify_txn_signatures_tpool( wave_task_infos, wave_task_infos_cnt, tpool );
        if( res != 0 ) {
          FD_LOG_WARNING(("Fail signature verification"));
        }

        res |= fd_runtime_prep_and_exec_txns_tpool( slot_ctx, wave_task_infos, wave_task_infos_cnt, tpool );
        if( res != 0 ) {
          FD_LOG_DEBUG(("Fail prep 2"));
        }

        int finalize_res = fd_runtime_finalize_txns_tpool( slot_ctx, capture_ctx, wave_task_infos, wave_task_infos_cnt, tpool );
        if( finalize_res != 0 ) {
          FD_LOG_ERR(("Fail finalize"));
        }

        /* Resetting the spad is a O(1) operation */
        for( ulong i=0UL; i<spad_cnt; i++ ) {
          fd_spad_reset( spads[i] );
        }

        // wave_time += fd_log_wallclock();
        // double wave_time_ms = (double)wave_time * 1e-6;
        // cum_wave_time_ms += wave_time_ms;
        // (void)cum_wave_time_ms;
        // FD_LOG_INFO(( "wave executed - sz: %lu, accounts: %lu, elapsed: %6.6f ms, cum: %6.6f ms", wave_task_infos_cnt, incomplete_accounts_cnt - next_incomplete_accounts_cnt, wave_time_ms, cum_wave_time_ms ));
      }
      } FD_SCRATCH_SCOPE_END;
    }
    slot_ctx->slot_bank.transaction_count += total_txn_cnt;

    #undef BATCH_SIZE

    return res;
}

// TODO: add tracking account_state hashes so that we can verify our
// banks hash... this has interesting threading implications since we
// could execute the cryptography in another thread for tracking this
// but we don't actually have anything to compare it to until we hit
// another snapshot...  Probably we should just store the results into
// the slot_ctx state (a slot/hash map)?
//
// What slots exactly do cache'd account_updates go into?  how are
// they hashed (which slot?)?

int
fd_runtime_block_sysvar_update_pre_execute( fd_exec_slot_ctx_t * slot_ctx ) {
  // let (fee_rate_governor, fee_components_time_us) = measure_us!(
  //     FeeRateGovernor::new_derived(&parent.fee_rate_governor, parent.signature_count())
  // );
  /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L1312-L1314 */
  fd_sysvar_fees_new_derived(slot_ctx, slot_ctx->slot_bank.fee_rate_governor, slot_ctx->parent_signature_cnt);

  // TODO: move all these out to a fd_sysvar_update() call...
  long clock_update_time = -fd_log_wallclock();
  fd_sysvar_clock_update(slot_ctx);
  clock_update_time += fd_log_wallclock();
  double clock_update_time_ms = (double)clock_update_time * 1e-6;
  FD_LOG_INFO(( "clock updated - slot: %lu, elapsed: %6.6f ms", slot_ctx->slot_bank.slot, clock_update_time_ms ));
  if (!FD_FEATURE_ACTIVE(slot_ctx, disable_fees_sysvar))
    fd_sysvar_fees_update(slot_ctx);
  // It has to go into the current txn previous info but is not in slot 0
  if (slot_ctx->slot_bank.slot != 0)
    fd_sysvar_slot_hashes_update(slot_ctx);
  fd_sysvar_last_restart_slot_update(slot_ctx);

  return 0;
}

int
fd_runtime_block_update_current_leader( fd_exec_slot_ctx_t * slot_ctx ) {
  ulong slot_rel;
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_slot_to_epoch(&epoch_bank->epoch_schedule, slot_ctx->slot_bank.slot, &slot_rel);
  slot_ctx->leader = fd_epoch_leaders_get( fd_exec_epoch_ctx_leaders( slot_ctx->epoch_ctx ), slot_ctx->slot_bank.slot );
  if( slot_ctx->leader == NULL ) {
    return -1;
  }

  return 0;
}

int
fd_runtime_block_execute_prepare( fd_exec_slot_ctx_t * slot_ctx ) {
  /* Update block height */
  slot_ctx->slot_bank.block_height += 1UL;
  fd_blockstore_block_height_update(
        slot_ctx->blockstore,
        slot_ctx->slot_bank.slot,
        slot_ctx->slot_bank.block_height );

  // TODO: this is not part of block execution, move it.
  if( slot_ctx->slot_bank.slot != 0 ) {
    slot_ctx->block = fd_blockstore_block_query( slot_ctx->blockstore, slot_ctx->slot_bank.slot );

    ulong slot_idx;
    fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
    ulong prev_epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, slot_ctx->slot_bank.prev_slot, &slot_idx );
    ulong new_epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, slot_ctx->slot_bank.slot, &slot_idx );
    if (slot_idx==1UL && new_epoch==0UL) {
      /* the block after genesis has a height of 1*/
      slot_ctx->slot_bank.block_height = 1UL;
    }

    if( prev_epoch < new_epoch || slot_idx == 0 ) {
      FD_LOG_DEBUG(("Epoch boundary"));
      /* Epoch boundary! */
      fd_funk_start_write(slot_ctx->acc_mgr->funk);
      fd_process_new_epoch(slot_ctx, new_epoch - 1UL);
      fd_funk_end_write(slot_ctx->acc_mgr->funk);
    }
  }

  slot_ctx->slot_bank.collected_execution_fees = 0;
  slot_ctx->slot_bank.collected_priority_fees = 0;
  slot_ctx->slot_bank.collected_rent = 0;
  slot_ctx->signature_cnt = 0;

  if( slot_ctx->slot_bank.slot != 0 && (
      FD_FEATURE_ACTIVE( slot_ctx, enable_partitioned_epoch_reward ) ||
      FD_FEATURE_ACTIVE( slot_ctx, partitioned_epoch_rewards_superfeature ) ) ) {
    fd_funk_start_write( slot_ctx->acc_mgr->funk );
    fd_distribute_partitioned_epoch_rewards( slot_ctx );
    fd_funk_end_write( slot_ctx->acc_mgr->funk );
  }

  int result = fd_runtime_block_update_current_leader( slot_ctx );
  if (result != 0) {
    FD_LOG_WARNING(("updating current leader"));
    return result;
  }

  fd_funk_start_write( slot_ctx->acc_mgr->funk );
  result = fd_runtime_block_sysvar_update_pre_execute( slot_ctx );
  fd_funk_end_write( slot_ctx->acc_mgr->funk );
  if (result != 0) {
    FD_LOG_WARNING(("updating sysvars failed"));
    return result;
  }

  /* Load sysvars into cache */
  if( FD_UNLIKELY( result = fd_runtime_sysvar_cache_load( slot_ctx ) ) ) {
    /* non-zero error */
    return result;
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int fd_runtime_block_execute_finalize(fd_exec_slot_ctx_t *slot_ctx,
                                      fd_capture_ctx_t *capture_ctx,
                                      fd_block_info_t const *block_info) {
  fd_sysvar_slot_history_update(slot_ctx);

  // this slot is frozen... and cannot change anymore...
  fd_runtime_freeze(slot_ctx);

  int result = fd_bpf_scan_and_create_bpf_program_cache_entry( slot_ctx, slot_ctx->funk_txn, 0 );
  if( result != 0 ) {
    FD_LOG_WARNING(("update bpf program cache failed"));
    return result;
  }

  result = fd_update_hash_bank(slot_ctx, capture_ctx, &slot_ctx->slot_bank.banks_hash, block_info->signature_cnt);
  if( result != FD_EXECUTOR_INSTR_SUCCESS ) {
    FD_LOG_WARNING(("hashing bank failed"));
    return result;
  }

  // result = fd_runtime_save_epoch_bank( slot_ctx );
  // if (result != FD_EXECUTOR_INSTR_SUCCESS) {
  //   FD_LOG_WARNING(( "save epoch bank failed" ));
  //   return result;
  // }

  result = fd_runtime_save_slot_bank(slot_ctx);
  if( result != FD_RUNTIME_EXECUTE_SUCCESS ) {
    FD_LOG_WARNING(("failed to save slot bank"));
    return result;
  }

  fd_bincode_destroy_ctx_t destroy_sysvar_ctx = {
    .valloc = slot_ctx->valloc,
  };

  // Clean up sysvar cache
  fd_slot_hashes_destroy( slot_ctx->sysvar_cache_old.slot_hashes, &destroy_sysvar_ctx );

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int
fd_runtime_block_execute_finalize_tpool( fd_exec_slot_ctx_t * slot_ctx,
                                         fd_capture_ctx_t * capture_ctx,
                                         fd_block_info_t const * block_info,
                                         fd_tpool_t * tpool ) {
  fd_funk_start_write( slot_ctx->acc_mgr->funk );

  fd_sysvar_slot_history_update(slot_ctx);

  // this slot is frozen... and cannot change anymore...
  fd_runtime_freeze(slot_ctx);

  int result = fd_bpf_scan_and_create_bpf_program_cache_entry( slot_ctx, slot_ctx->funk_txn, 0 );
  if( result != 0 ) {
    FD_LOG_WARNING(("update bpf program cache failed"));
    fd_funk_end_write( slot_ctx->acc_mgr->funk );
    return result;
  }

  result = fd_update_hash_bank_tpool(slot_ctx, capture_ctx, &slot_ctx->slot_bank.banks_hash, block_info->signature_cnt, tpool );
  if( result != FD_EXECUTOR_INSTR_SUCCESS ) {
    FD_LOG_WARNING(("hashing bank failed"));
    fd_funk_end_write( slot_ctx->acc_mgr->funk );
    return result;
  }

  // result = fd_runtime_save_epoch_bank( slot_ctx );
  // if (result != FD_EXECUTOR_INSTR_SUCCESS) {
  //   FD_LOG_WARNING(( "save epoch bank failed" ));
  //   return result;
  // }

  result = fd_runtime_save_slot_bank(slot_ctx);
  if( result != FD_RUNTIME_EXECUTE_SUCCESS ) {
    FD_LOG_WARNING(("failed to save slot bank"));
    fd_funk_end_write( slot_ctx->acc_mgr->funk );
    return result;
  }

  fd_funk_end_write( slot_ctx->acc_mgr->funk );

  fd_bincode_destroy_ctx_t destroy_sysvar_ctx = {
    .valloc = slot_ctx->valloc,
  };

  // Clean up sysvar cache
  fd_slot_hashes_destroy( slot_ctx->sysvar_cache_old.slot_hashes, &destroy_sysvar_ctx );
  slot_ctx->total_compute_units_requested = 0;
  for ( fd_account_compute_table_iter_t iter = fd_account_compute_table_iter_init( slot_ctx->account_compute_table );
        !fd_account_compute_table_iter_done( slot_ctx->account_compute_table, iter );
        iter = fd_account_compute_table_iter_next( slot_ctx->account_compute_table, iter ) ) {
    fd_account_compute_elem_t * e = fd_account_compute_table_iter_ele( slot_ctx->account_compute_table, iter );
    fd_account_compute_table_remove( slot_ctx->account_compute_table, &e->key );
  }
  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int 
fd_runtime_block_execute_tpool_v2( fd_exec_slot_ctx_t * slot_ctx,
                                   fd_capture_ctx_t * capture_ctx,
                                   fd_block_info_t const * block_info,
                                   fd_tpool_t * tpool,
                                   fd_spad_t * * spads,
                                   ulong spad_cnt ) {
  FD_SCRATCH_SCOPE_BEGIN {
    if ( capture_ctx != NULL && capture_ctx->capture ) {
      fd_solcap_writer_set_slot( capture_ctx->capture, slot_ctx->slot_bank.slot );
    }

    long block_execute_time = -fd_log_wallclock();

    int res = fd_runtime_block_execute_prepare( slot_ctx );
    if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
      return res;
    }

    ulong txn_cnt = block_info->txn_cnt;
    fd_txn_p_t * txn_ptrs = fd_scratch_alloc( alignof(fd_txn_p_t), txn_cnt * sizeof(fd_txn_p_t) );

    fd_runtime_block_collect_txns( block_info, txn_ptrs );

    res = fd_runtime_execute_txns_in_waves_tpool( slot_ctx, capture_ctx, txn_ptrs, txn_cnt, tpool, spads, spad_cnt );
    if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
      return res;
    }

    long block_finalize_time = -fd_log_wallclock();
    res = fd_runtime_block_execute_finalize_tpool( slot_ctx, capture_ctx, block_info, tpool );
    if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
      return res;
    }

    slot_ctx->slot_bank.transaction_count += txn_cnt;

    block_finalize_time += fd_log_wallclock();
    double block_finalize_time_ms = (double)block_finalize_time * 1e-6;
    FD_LOG_INFO(( "finalized block successfully - slot: %lu, elapsed: %6.6f ms", slot_ctx->slot_bank.slot, block_finalize_time_ms ));

    block_execute_time += fd_log_wallclock();
    double block_execute_time_ms = (double)block_execute_time * 1e-6;

    FD_LOG_INFO(( "executed block successfully - slot: %lu, elapsed: %6.6f ms", slot_ctx->slot_bank.slot, block_execute_time_ms ));

    return FD_RUNTIME_EXECUTE_SUCCESS;
  } FD_SCRATCH_SCOPE_END;
}


struct fd_poh_verification_info {
  fd_microblock_info_t const *microblock_info;
  fd_hash_t const *in_poh_hash;
  int success;
};
typedef struct fd_poh_verification_info fd_poh_verification_info_t;

void fd_runtime_microblock_verify_info_collect( fd_microblock_info_t const *microblock_info,
                                                fd_hash_t const *in_poh_hash,
                                                fd_poh_verification_info_t *poh_verification_info ) {
  poh_verification_info->microblock_info = microblock_info;
  poh_verification_info->in_poh_hash = in_poh_hash;
  poh_verification_info->success = 0;
}

void fd_runtime_microblock_batch_verify_info_collect(fd_microblock_batch_info_t const *microblock_batch_info,
                                                     fd_hash_t const *in_poh_hash,
                                                     fd_poh_verification_info_t *poh_verification_info)
{
  for (ulong i = 0; i < microblock_batch_info->microblock_cnt; i++)
  {
    fd_microblock_info_t const *microblock_info = &microblock_batch_info->microblock_infos[i];
    fd_runtime_microblock_verify_info_collect(microblock_info, in_poh_hash, &poh_verification_info[i]);
    in_poh_hash = (fd_hash_t const *)&microblock_info->microblock_hdr.hash;
  }
}

void fd_runtime_block_verify_info_collect(fd_block_info_t const *block_info,
                                          fd_hash_t const *in_poh_hash,
                                          fd_poh_verification_info_t *poh_verification_info)
{
  for (ulong i = 0; i < block_info->microblock_batch_cnt; i++)
  {
    fd_microblock_batch_info_t const *microblock_batch_info = &block_info->microblock_batch_infos[i];

    fd_runtime_microblock_batch_verify_info_collect(microblock_batch_info, in_poh_hash, poh_verification_info);
    in_poh_hash = (fd_hash_t const *)poh_verification_info[microblock_batch_info->microblock_cnt - 1].microblock_info->microblock_hdr.hash;
    poh_verification_info += microblock_batch_info->microblock_cnt;
  }
}

static void FD_FN_UNUSED
fd_runtime_poh_verify_task( void *tpool,
                            ulong t0 FD_PARAM_UNUSED, ulong t1 FD_PARAM_UNUSED,
                            void *args FD_PARAM_UNUSED,
                            void *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                            ulong l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
                            ulong m0, ulong m1 FD_PARAM_UNUSED,
                            ulong n0 FD_PARAM_UNUSED, ulong n1 FD_PARAM_UNUSED ) {
  fd_poh_verification_info_t *poh_info = (fd_poh_verification_info_t *)tpool + m0;
  fd_bmtree_commit_t commit_mem[1];

  fd_hash_t out_poh_hash = *poh_info->in_poh_hash;

  fd_microblock_info_t const *microblock_info = poh_info->microblock_info;
  ulong hash_cnt = microblock_info->microblock_hdr.hash_cnt;
  ulong txn_cnt = microblock_info->microblock_hdr.txn_cnt;

  if (txn_cnt == 0) {
    fd_poh_append(&out_poh_hash, hash_cnt);
  } else {
    if (hash_cnt > 0) {
      fd_poh_append(&out_poh_hash, hash_cnt - 1);
    }

    fd_bmtree_commit_t *tree = fd_bmtree_commit_init(commit_mem, 32UL, 1UL, 0UL);

    /* Loop across transactions */
    for (ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++) {
      fd_txn_p_t * txn_p = &microblock_info->txns[txn_idx];

      fd_txn_t const *txn = (fd_txn_t const *) txn_p->_;
      fd_rawtxn_b_t const raw_txn[1] = {{.raw = txn_p->payload, .txn_sz = (ushort)txn_p->payload_sz}};

      /* Loop across signatures */
      fd_ed25519_sig_t const *sigs = (fd_ed25519_sig_t const *)((ulong)raw_txn->raw + (ulong)txn->signature_off);
      for (ulong j = 0; j < txn->signature_cnt; j++) {
        fd_bmtree_node_t leaf;
        fd_bmtree_hash_leaf(&leaf, &sigs[j], sizeof(fd_ed25519_sig_t), 1);
        fd_bmtree_commit_append(tree, (fd_bmtree_node_t const *)&leaf, 1);
      }
    }

    uchar *root = fd_bmtree_commit_fini(tree);
    fd_poh_mixin(&out_poh_hash, root);
  }

  if (FD_UNLIKELY(0 != memcmp(microblock_info->microblock_hdr.hash, out_poh_hash.hash, sizeof(fd_hash_t)))) {
    FD_LOG_WARNING(( "poh mismatch (bank: %s, entry: %s)", FD_BASE58_ENC_32_ALLOCA( out_poh_hash.hash ), FD_BASE58_ENC_32_ALLOCA( microblock_info->microblock_hdr.hash ) ));
    poh_info->success = -1;
  }
}

static void
fd_runtime_poh_verify_wide_task( void *tpool,
                                 ulong t0 FD_PARAM_UNUSED, ulong t1 FD_PARAM_UNUSED,
                                 void *args FD_PARAM_UNUSED,
                                 void *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                                 ulong l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
                                 ulong m0, ulong m1 FD_PARAM_UNUSED,
                                 ulong n0 FD_PARAM_UNUSED, ulong n1 FD_PARAM_UNUSED ) {
  fd_poh_verification_info_t * poh_info = (fd_poh_verification_info_t *)tpool + m0;

  fd_hash_t out_poh_hash = *poh_info->in_poh_hash;

  fd_microblock_info_t const *microblock_info = poh_info->microblock_info;
  ulong hash_cnt = microblock_info->microblock_hdr.hash_cnt;
  ulong txn_cnt = microblock_info->microblock_hdr.txn_cnt;

  if( txn_cnt == 0 ) {
    fd_poh_append( &out_poh_hash, hash_cnt );
  } else {
    if( hash_cnt > 0 ) {
      fd_poh_append(&out_poh_hash, hash_cnt - 1);
    }

    ulong leaf_cnt = microblock_info->signature_cnt;
    unsigned char * commit = fd_alloca_check( FD_WBMTREE32_ALIGN, fd_wbmtree32_footprint(leaf_cnt));
    fd_wbmtree32_leaf_t * leafs = fd_alloca_check(alignof(fd_wbmtree32_leaf_t), sizeof(fd_wbmtree32_leaf_t) * leaf_cnt);
    unsigned char * mbuf = fd_alloca_check(1UL, leaf_cnt * (sizeof(fd_ed25519_sig_t) + 1));

    fd_wbmtree32_t *tree = fd_wbmtree32_init(commit, leaf_cnt);
    fd_wbmtree32_leaf_t *l = &leafs[0];

    /* Loop across transactions */
    for (ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++) {
      fd_txn_p_t * txn_p = &microblock_info->txns[txn_idx];

      fd_txn_t const *txn = (fd_txn_t const *) txn_p->_;
      fd_rawtxn_b_t const raw_txn[1] = {{.raw = txn_p->payload, .txn_sz = (ushort)txn_p->payload_sz}};

      /* Loop across signatures */
      fd_ed25519_sig_t const *sigs = (fd_ed25519_sig_t const *)((ulong)raw_txn->raw + (ulong)txn->signature_off);
      for( ulong j = 0; j < txn->signature_cnt; j++ ) {
        l->data = (uchar *)&sigs[j];
        l->data_len = sizeof(fd_ed25519_sig_t);
        l++;
      }
    }

    fd_wbmtree32_append(tree, leafs, leaf_cnt, mbuf);
    uchar *root = fd_wbmtree32_fini(tree);
    fd_poh_mixin(&out_poh_hash, root);
  }

  if (FD_UNLIKELY(0 != memcmp(microblock_info->microblock_hdr.hash, out_poh_hash.hash, sizeof(fd_hash_t)))) {
    FD_LOG_WARNING(( "poh mismatch (bank: %s, entry: %s)", FD_BASE58_ENC_32_ALLOCA( out_poh_hash.hash ), FD_BASE58_ENC_32_ALLOCA( microblock_info->microblock_hdr.hash ) ));
    poh_info->success = -1;
  }
}

int
fd_runtime_poh_verify_tpool( fd_poh_verification_info_t *poh_verification_info,
                             ulong poh_verification_info_cnt,
                             fd_tpool_t * tpool ) {
  fd_tpool_exec_all_rrobin(tpool, 0, fd_tpool_worker_cnt( tpool ), fd_runtime_poh_verify_wide_task, poh_verification_info, NULL, NULL, 1, 0, poh_verification_info_cnt);

  for (ulong i = 0; i < poh_verification_info_cnt; i++) {
    if (poh_verification_info[i].success != 0)
    {
      return -1;
    }
  }

  return 0;
}

int fd_runtime_block_verify_tpool(fd_block_info_t const *block_info,
                                  fd_hash_t const *in_poh_hash,
                                  fd_hash_t *out_poh_hash,
                                  fd_valloc_t valloc,
                                  fd_tpool_t *tpool) {
  long block_verify_time = -fd_log_wallclock();

  fd_hash_t tmp_in_poh_hash = *in_poh_hash;
  ulong poh_verification_info_cnt = block_info->microblock_cnt;
  fd_poh_verification_info_t *poh_verification_info = fd_valloc_malloc(valloc,
                                                                       alignof(fd_poh_verification_info_t),
                                                                       poh_verification_info_cnt * sizeof(fd_poh_verification_info_t));
  fd_runtime_block_verify_info_collect(block_info, &tmp_in_poh_hash, poh_verification_info);
  int result = fd_runtime_poh_verify_tpool(poh_verification_info, poh_verification_info_cnt, tpool );
  fd_memcpy(out_poh_hash->hash, poh_verification_info[poh_verification_info_cnt - 1].microblock_info->microblock_hdr.hash, sizeof(fd_hash_t));
  fd_valloc_free(valloc, poh_verification_info);

  block_verify_time += fd_log_wallclock();
  double block_verify_time_ms = (double)block_verify_time * 1e-6;

  FD_LOG_INFO(("verified block successfully - elapsed: %6.6f ms", block_verify_time_ms));

  return result;
}

int fd_runtime_microblock_wide_verify(fd_microblock_info_t const *microblock_info,
                                      fd_hash_t const *in_poh_hash,
                                      fd_hash_t *out_poh_hash) {
  ulong hash_cnt = microblock_info->microblock_hdr.hash_cnt;
  ulong txn_cnt = microblock_info->microblock_hdr.txn_cnt;
  FD_LOG_WARNING(( "poh input %lu %lu %s %s", hash_cnt, txn_cnt, FD_BASE58_ENC_32_ALLOCA( in_poh_hash->hash ), FD_BASE58_ENC_32_ALLOCA( microblock_info->microblock_hdr.hash ) ));

  *out_poh_hash = *in_poh_hash;

  if (txn_cnt == 0)
    fd_poh_append(out_poh_hash, hash_cnt);
  else
  {
    if (hash_cnt > 0)
      fd_poh_append(out_poh_hash, hash_cnt - 1);

    ulong leaf_cnt = 0;
    for (ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++)
    {
      fd_txn_p_t * txn_p = &microblock_info->txns[txn_idx];
      fd_txn_t const *txn = (fd_txn_t const *) txn_p->_;
      leaf_cnt += txn->signature_cnt;
    }

    // TODO: optimize this... .. and, we cannot use alloca...
    unsigned char *commit = fd_alloca_check(FD_WBMTREE32_ALIGN, fd_wbmtree32_footprint(leaf_cnt));
    fd_wbmtree32_leaf_t *leafs = fd_alloca_check(alignof(fd_wbmtree32_leaf_t), sizeof(fd_wbmtree32_leaf_t) * leaf_cnt);
    unsigned char *mbuf = fd_alloca_check(1UL, leaf_cnt * (sizeof(fd_ed25519_sig_t) + 1));

    fd_wbmtree32_t *tree = fd_wbmtree32_init(commit, leaf_cnt);
    fd_wbmtree32_leaf_t *l = &leafs[0];

    /* Loop acro ss transactions */
    for( ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++ ) {
      fd_txn_p_t * txn_p = &microblock_info->txns[txn_idx];

      fd_txn_t const *txn = (fd_txn_t const *) txn_p->_;
      fd_rawtxn_b_t const raw_txn[1] = {{.raw = txn_p->payload, .txn_sz = (ushort)txn_p->payload_sz}};

      /* Loop across signatures */
      fd_ed25519_sig_t const *sigs = (fd_ed25519_sig_t const *)((ulong)raw_txn->raw + (ulong)txn->signature_off);
      for( ulong j = 0; j < txn->signature_cnt; j++ ) {
        l->data = (uchar *)&sigs[j];
        l->data_len = sizeof(fd_ed25519_sig_t);
        l++;
      }
    }

    fd_wbmtree32_append(tree, leafs, leaf_cnt, mbuf);
    uchar *root = fd_wbmtree32_fini(tree);
    fd_poh_mixin(out_poh_hash, root);
  }

  if (FD_UNLIKELY(0 != memcmp(microblock_info->microblock_hdr.hash, out_poh_hash->hash, sizeof(fd_hash_t))))
  {
    FD_LOG_WARNING(( "poh mismatch (bank: %s, entry: %s)", FD_BASE58_ENC_32_ALLOCA( out_poh_hash->hash ), FD_BASE58_ENC_32_ALLOCA( microblock_info->microblock_hdr.hash ) ));
    return -1;
  }

  return 0;
}

int fd_runtime_microblock_verify(fd_microblock_info_t const *microblock_info,
                                 fd_hash_t const * in_poh_hash,
                                 fd_hash_t * out_poh_hash) {
  fd_bmtree_commit_t commit_mem[1];

  *out_poh_hash = *in_poh_hash;

  ulong hash_cnt = microblock_info->microblock_hdr.hash_cnt;
  ulong txn_cnt = microblock_info->microblock_hdr.txn_cnt;

  if (txn_cnt == 0) {
    fd_poh_append(out_poh_hash, hash_cnt);
  } else {
    if (hash_cnt > 0) {
      fd_poh_append(out_poh_hash, hash_cnt - 1);
    }

    fd_bmtree_commit_t *tree = fd_bmtree_commit_init(commit_mem, 32UL, 1UL, 0UL);

    /* Loop across transactions */
    for (ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++) {
      fd_txn_p_t * txn_p = &microblock_info->txns[txn_idx];

      fd_txn_t const *txn = (fd_txn_t const *) txn_p->_;
      fd_rawtxn_b_t const raw_txn[1] = {{.raw = txn_p->payload, .txn_sz = (ushort)txn_p->payload_sz}};

      /* Loop across signatures */
      fd_ed25519_sig_t const *sigs = (fd_ed25519_sig_t const *)((ulong)raw_txn->raw + (ulong)txn->signature_off);
      for (ulong j = 0; j < txn->signature_cnt; j++) {
        fd_bmtree_node_t leaf;
        fd_bmtree_hash_leaf(&leaf, &sigs[j], sizeof(fd_ed25519_sig_t), 1);
        fd_bmtree_commit_append(tree, (fd_bmtree_node_t const *)&leaf, 1);
      }
    }

    uchar *root = fd_bmtree_commit_fini(tree);
    fd_poh_mixin(out_poh_hash, root);
  }

  if (FD_UNLIKELY(0 != memcmp(microblock_info->microblock_hdr.hash, out_poh_hash->hash, sizeof(fd_hash_t)))) {
    FD_LOG_WARNING(("poh mismatch (bank: %s, entry: %s)", FD_BASE58_ENC_32_ALLOCA( out_poh_hash->hash ), FD_BASE58_ENC_32_ALLOCA( microblock_info->microblock_hdr.hash) ));
    return -1;
  }

  return 0;
}

int fd_runtime_microblock_batch_verify(fd_microblock_batch_info_t const *microblock_batch_info,
                                       fd_hash_t const *in_poh_hash,
                                       fd_hash_t *out_poh_hash) {
  fd_hash_t tmp_poh_hash = *in_poh_hash;
  for (ulong i = 0; i < microblock_batch_info->microblock_cnt; i++)
  {
    if (fd_runtime_microblock_wide_verify(&microblock_batch_info->microblock_infos[i], &tmp_poh_hash, out_poh_hash) != 0)
    {
      FD_LOG_WARNING(("poh mismatch in microblock - idx: %lu", i));
      return -1;
    }

    tmp_poh_hash = *out_poh_hash;
  }

  return 0;
}

// TODO: add back in the total_hashes == bank.hashes_per_slot
// TODO: add solana txn verify to this as well since, again, it can be
// done in parallel...
int
fd_runtime_block_verify(fd_block_info_t const *block_info,
                            fd_hash_t const *in_poh_hash,
                            fd_hash_t *out_poh_hash) {
  fd_hash_t tmp_poh_hash = *in_poh_hash;
  for( ulong i = 0; i < block_info->microblock_batch_cnt; i++ ) {
    if( fd_runtime_microblock_batch_verify(&block_info->microblock_batch_infos[i], &tmp_poh_hash, out_poh_hash) != 0 ) {
      FD_LOG_WARNING(("poh mismatch in microblock batch - idx: %lu", i));
      return -1;
    }

    tmp_poh_hash = *out_poh_hash;
  }

  return 0;
}

// int
// fd_runtime_slot_bank_from_parent(child_slot_ctx ) {
//   child_slot_bank.collected_fees = 0;
//   child_slot_ctx->slot_bank.collected_rent = 0;
//   child_slot_ctx->slot_bank.max_tick_height = (slot + 1) * slot_ctx->epoch_ctx->epoch_bank->ticks_per_slot;
// }

void
fd_runtime_checkpt( fd_capture_ctx_t * capture_ctx,
                    fd_exec_slot_ctx_t * slot_ctx,
                    ulong slot ) {
  int is_checkpt_freq = capture_ctx != NULL && slot % capture_ctx->checkpt_freq == 0;
  int is_abort_slot   = slot == ULONG_MAX;
  if( !is_checkpt_freq && !is_abort_slot ) {
    return;
  }

  if( capture_ctx->checkpt_path != NULL ) {
    if( !is_abort_slot ) {
      FD_LOG_NOTICE(( "checkpointing at slot=%lu to file=%s", slot, capture_ctx->checkpt_path ));
      fd_funk_end_write( slot_ctx->acc_mgr->funk );
    } else {
      FD_LOG_NOTICE(( "checkpointing after mismatch to file=%s", capture_ctx->checkpt_path ));
    }

    unlink( capture_ctx->checkpt_path );
    int err = fd_wksp_checkpt( fd_funk_wksp( slot_ctx->acc_mgr->funk ), capture_ctx->checkpt_path, 0666, 0, NULL );
    if ( err ) {
      FD_LOG_ERR(( "backup failed: error %d", err ));
    }

    if( !is_abort_slot ) {
      fd_funk_start_write( slot_ctx->acc_mgr->funk );
    }
  }

  if( capture_ctx->checkpt_archive != NULL ) {
    if( !is_abort_slot ) {
      FD_LOG_NOTICE(( "archiving at slot=%lu to file=%s", slot, capture_ctx->checkpt_archive ));
      fd_funk_end_write( slot_ctx->acc_mgr->funk );
    } else {
      FD_LOG_NOTICE(( "archiving after mismatch to file=%s", capture_ctx->checkpt_archive ));
    }

    int err = fd_funk_archive( slot_ctx->acc_mgr->funk, capture_ctx->checkpt_archive );
    if ( err ) {
      FD_LOG_ERR(( "archive failed: error %d", err ));
    }

    if( !is_abort_slot ) {
      fd_funk_start_write( slot_ctx->acc_mgr->funk );
    }
  }
}

static int
fd_runtime_publish_old_txns( fd_exec_slot_ctx_t * slot_ctx,
                             fd_capture_ctx_t * capture_ctx,
                             fd_tpool_t * tpool ) {
  /* Publish any transaction older than 31 slots */
  fd_funk_t * funk = slot_ctx->acc_mgr->funk;
  fd_funk_txn_t * txnmap = fd_funk_txn_map(funk, fd_funk_wksp(funk));
  uint depth = 0;
  for( fd_funk_txn_t * txn = slot_ctx->funk_txn; txn; txn = fd_funk_txn_parent(txn, txnmap) ) {
    /* TODO: tmp change */
    if (++depth == (FD_RUNTIME_NUM_ROOT_BLOCKS - 1) ) {
      FD_LOG_DEBUG(("publishing %s (slot %ld)", FD_BASE58_ENC_32_ALLOCA( &txn->xid ), txn->xid.ul[0]));

      fd_funk_start_write(funk);
      ulong publish_err = fd_funk_txn_publish(funk, txn, 1);
      if (publish_err == 0) {
        FD_LOG_ERR(("publish err"));
        return -1;
      }
      if( slot_ctx->status_cache ) {
        fd_txncache_register_root_slot( slot_ctx->status_cache, txn->xid.ul[0] );
      }

      if( FD_UNLIKELY( FD_FEATURE_ACTIVE(slot_ctx, epoch_accounts_hash) ) ) {
        fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
        if( txn->xid.ul[0] >= epoch_bank->eah_start_slot ) {
          fd_accounts_hash( slot_ctx, tpool, &slot_ctx->slot_bank.epoch_account_hash );
          epoch_bank->eah_start_slot = ULONG_MAX;
        }
      }

      if( capture_ctx != NULL ) {
        fd_runtime_checkpt( capture_ctx, slot_ctx, txn->xid.ul[0] );
      }

      fd_funk_end_write(funk);

      break;
    }
  }

  return 0;
}

int
fd_runtime_block_eval_tpool( fd_exec_slot_ctx_t * slot_ctx,
                             fd_capture_ctx_t *   capture_ctx,
                             void const *         block,
                             ulong                blocklen,
                             fd_tpool_t *         tpool,
                             ulong                scheduler,
                             ulong *              txn_cnt,
                             fd_spad_t * *        spads,
                             ulong                spad_cnt ) {
  (void)scheduler;

  int err = fd_runtime_publish_old_txns( slot_ctx, capture_ctx, tpool );
  if( err != 0 ) {
    return err;
  }

  fd_funk_t * funk = slot_ctx->acc_mgr->funk;

  long block_eval_time = -fd_log_wallclock();
  fd_block_info_t block_info;
  int ret = fd_runtime_block_prepare(block, blocklen, slot_ctx->valloc, &block_info);
  *txn_cnt = block_info.txn_cnt;

  /* Use the blockhash as the funk xid */
  fd_funk_txn_xid_t xid;

  fd_blockstore_start_read(slot_ctx->blockstore);
  ulong slot = slot_ctx->slot_bank.slot;
  fd_hash_t const * hash = fd_blockstore_block_hash_query(slot_ctx->blockstore, slot);
  if( hash == NULL ) {
    ret = FD_RUNTIME_EXECUTE_GENERIC_ERR;
    FD_LOG_WARNING(("missing blockhash for %lu", slot));
  } else {
    fd_memcpy(xid.uc, hash->uc, sizeof(fd_funk_txn_xid_t));
    xid.ul[0] = slot_ctx->slot_bank.slot;
    /* push a new transaction on the stack */
    fd_funk_start_write( funk );
    slot_ctx->funk_txn = fd_funk_txn_prepare(funk, slot_ctx->funk_txn, &xid, 1);
    fd_funk_end_write( funk );
  }
  fd_blockstore_end_read(slot_ctx->blockstore);

  if( FD_RUNTIME_EXECUTE_SUCCESS == ret ) {
    ret = fd_runtime_block_verify_tpool(&block_info, &slot_ctx->slot_bank.poh, &slot_ctx->slot_bank.poh, slot_ctx->valloc, tpool );
  }
  if( FD_RUNTIME_EXECUTE_SUCCESS == ret ) {
    ret = fd_runtime_block_execute_tpool_v2( slot_ctx, capture_ctx, &block_info, tpool, spads, spad_cnt );
  }

  fd_runtime_block_destroy( slot_ctx->valloc, &block_info );

  // FIXME: better way of using starting slot
  if( FD_UNLIKELY( FD_RUNTIME_EXECUTE_SUCCESS != ret ) ) {
    FD_LOG_WARNING(("execution failure, code %d", ret));
    /* Skip over slot next time */
    slot_ctx->slot_bank.slot = slot+1;
    return 0;
  }

  block_eval_time += fd_log_wallclock();
  double block_eval_time_ms = (double)block_eval_time * 1e-6;
  double tps = (double) block_info.txn_cnt / ((double)block_eval_time * 1e-9);
  FD_LOG_INFO(( "evaluated block successfully - slot: %lu, elapsed: %6.6f ms, signatures: %lu, txns: %lu, tps: %6.6f, bank_hash: %s, leader: %s",
                slot_ctx->slot_bank.slot,
                block_eval_time_ms,
                block_info.signature_cnt,
                block_info.txn_cnt,
                tps,
                FD_BASE58_ENC_32_ALLOCA( slot_ctx->slot_bank.banks_hash.hash ),
                FD_BASE58_ENC_32_ALLOCA( slot_ctx->leader->key ) ));

  slot_ctx->slot_bank.transaction_count += block_info.txn_cnt;

  /* progress to next slot next time */
  slot_ctx->blockstore->smr++;

  fd_funk_start_write( slot_ctx->acc_mgr->funk );
  fd_runtime_save_slot_bank( slot_ctx );
  fd_funk_end_write( slot_ctx->acc_mgr->funk );

  slot_ctx->slot_bank.prev_slot = slot;
  // FIXME: this shouldn't be doing this, it doesn't work with forking. punting changing it though
  slot_ctx->slot_bank.slot = slot+1;

  return 0;
}

/* rollback to the state where the given slot just FINISHED executing */
int
fd_runtime_rollback_to( fd_exec_slot_ctx_t * slot_ctx, ulong slot ) {
  FD_LOG_NOTICE(( "rolling back to %lu", slot ));
  fd_funk_t * funk = slot_ctx->acc_mgr->funk;
  fd_funk_txn_t * txnmap = fd_funk_txn_map(funk, fd_funk_wksp(funk));
  fd_blockstore_t * blockstore = slot_ctx->blockstore;
  FD_LOG_WARNING(("rolling back to slot %lu", slot));
  /* Get the blockhash, which is used as the funk transaction id */
  fd_blockstore_start_read(blockstore);
  fd_hash_t const * hash = fd_blockstore_block_hash_query(blockstore, slot);
  if( !hash ) {
    fd_blockstore_end_read(blockstore);
    return -1;
  }
  fd_funk_txn_xid_t xid;
  fd_memcpy(xid.uc, hash, sizeof(fd_funk_txn_xid_t));
  xid.ul[0] = slot;
  fd_blockstore_end_read(blockstore);
  /* Switch to the funk transaction */
  fd_funk_txn_t * txn = fd_funk_txn_query(&xid, txnmap);
  if( !txn) return -1;
  slot_ctx->funk_txn = txn;
  /* Recover the old bank state */
  fd_runtime_recover_banks(slot_ctx, 1, 1);
  return 0;
}

ulong
fd_runtime_lamports_per_signature( fd_slot_bank_t const *slot_bank ) {
  // https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/fee_calculator.rs#L110
  return slot_bank->fee_rate_governor.target_lamports_per_signature / 2;
}

ulong
fd_runtime_lamports_per_signature_for_blockhash( fd_exec_slot_ctx_t const * slot_ctx,
                                                 fd_hash_t const * blockhash ) {

  // https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/fee_calculator.rs#L110

  // https://github.com/firedancer-io/solana/blob/53a4e5d6c58b2ffe89b09304e4437f8ca198dadd/runtime/src/blockhash_queue.rs#L55
  ulong default_fee = slot_ctx->slot_bank.fee_rate_governor.target_lamports_per_signature / 2;

  if( blockhash == NULL ) {
    return default_fee;
  }

  fd_block_block_hash_entry_t *hashes = slot_ctx->slot_bank.recent_block_hashes.hashes;
  for( deq_fd_block_block_hash_entry_t_iter_t iter = deq_fd_block_block_hash_entry_t_iter_init(hashes);
       !deq_fd_block_block_hash_entry_t_iter_done(hashes, iter);
       iter = deq_fd_block_block_hash_entry_t_iter_next(hashes, iter) ) {
    fd_block_block_hash_entry_t *curr_elem = deq_fd_block_block_hash_entry_t_iter_ele(hashes, iter);
    if (memcmp(&curr_elem->blockhash, blockhash, sizeof(fd_hash_t)) == 0) {
      return curr_elem->fee_calculator.lamports_per_signature;
    }
  }

  return default_fee;
}

ulong
fd_runtime_txn_lamports_per_signature( fd_exec_txn_ctx_t * txn_ctx,
                                       fd_txn_t const * txn_descriptor,
                                       fd_rawtxn_b_t const * txn_raw ) {
  // why is asan not detecting access to uninitialized memory here?!
  fd_nonce_state_versions_t state;
  int err;
  if ((NULL != txn_descriptor) && fd_load_nonce_account(txn_ctx, &state, txn_ctx->valloc, &err)) {
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

  return (txn_raw == NULL) ? fd_runtime_lamports_per_signature_for_blockhash(txn_ctx->slot_ctx, NULL) : fd_runtime_lamports_per_signature_for_blockhash(txn_ctx->slot_ctx, (fd_hash_t *)((uchar *)txn_raw->raw + txn_descriptor->recent_blockhash_off));
}

void compute_priority_fee(fd_exec_txn_ctx_t const *txn_ctx, ulong *fee, ulong *priority)
{
  switch (txn_ctx->prioritization_fee_type)
  {
  case FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_DEPRECATED:
  {
    if (txn_ctx->compute_unit_limit == 0)
    {
      *priority = 0;
    }
    else
    {
      uint128 micro_lamport_fee = (uint128)txn_ctx->compute_unit_price * (uint128)MICRO_LAMPORTS_PER_LAMPORT;
      uint128 _priority = micro_lamport_fee / (uint128)txn_ctx->compute_unit_limit;
      *priority = _priority > (uint128)ULONG_MAX ? ULONG_MAX : (ulong)_priority;
    }

    *fee = txn_ctx->compute_unit_price;
    return;
  }
  case FD_COMPUTE_BUDGET_PRIORITIZATION_FEE_TYPE_COMPUTE_UNIT_PRICE:
  {

    uint128 micro_lamport_fee = (uint128)txn_ctx->compute_unit_price * (uint128)txn_ctx->compute_unit_limit;

    *priority = txn_ctx->compute_unit_price;
    uint128 _fee = (micro_lamport_fee + (uint128)(MICRO_LAMPORTS_PER_LAMPORT - 1)) / (uint128)(MICRO_LAMPORTS_PER_LAMPORT);
    *fee = _fee > (uint128)ULONG_MAX ? ULONG_MAX : (ulong)_fee;
    return;
  }
  default:
    __builtin_unreachable();
  }
}

// https://github.com/anza-xyz/agave/blob/2e6ca8c1f62db62c1db7f19c9962d4db43d0d550/sdk/src/fee.rs#L82
#define ACCOUNT_DATA_COST_PAGE_SIZE fd_ulong_sat_mul(32, 1024)

void
fd_runtime_calculate_fee(fd_exec_txn_ctx_t *txn_ctx,
                         fd_txn_t const *txn_descriptor,
                         fd_rawtxn_b_t const *txn_raw,
                         ulong *ret_execution_fee,
                         ulong *ret_priority_fee)
{
  // https://github.com/firedancer-io/solana/blob/08a1ef5d785fe58af442b791df6c4e83fe2e7c74/runtime/src/bank.rs#L4443
  // TODO: implement fee distribution to the collector ... and then charge us the correct amount
  ulong priority = 0;
  ulong priority_fee = 0;
  compute_priority_fee(txn_ctx, &priority_fee, &priority);

  // let signature_fee = Self::get_num_signatures_in_message(message) .saturating_mul(fee_structure.lamports_per_signature);
  ulong num_signatures = txn_descriptor->signature_cnt;
  for (ushort i = 0; i < txn_descriptor->instr_cnt; ++i)
  {
    fd_txn_instr_t const *txn_instr = &txn_descriptor->instr[i];
    fd_pubkey_t *program_id = &txn_ctx->accounts[txn_instr->program_id];
    if (memcmp(program_id->uc, fd_solana_keccak_secp_256k_program_id.key, sizeof(fd_pubkey_t)) == 0 ||
        memcmp(program_id->uc, fd_solana_ed25519_sig_verify_program_id.key, sizeof(fd_pubkey_t)) == 0)
    {
      if (txn_instr->data_sz == 0)
      {
        continue;
      }
      uchar *data = (uchar *)txn_raw->raw + txn_instr->data_off;
      num_signatures = fd_ulong_sat_add(num_signatures, (ulong)(data[0]));
    }
  }

  ulong signature_fee = fd_runtime_lamports_per_signature(&txn_ctx->slot_ctx->slot_bank) * num_signatures;

  // TODO: as far as I can tell, this is always 0
  //
  //            let write_lock_fee = Self::get_num_write_locks_in_message(message)
  //                .saturating_mul(fee_structure.lamports_per_write_lock);
  ulong lamports_per_write_lock = 0;
  ulong write_lock_fee = fd_ulong_sat_mul(fd_txn_account_cnt(txn_descriptor, FD_TXN_ACCT_CAT_WRITABLE), lamports_per_write_lock);

  // TODO: the fee_structure bin is static and default..
  //        let loaded_accounts_data_size_cost = if include_loaded_account_data_size_in_fee {
  //            FeeStructure::calculate_memory_usage_cost(
  //                budget_limits.loaded_accounts_data_size_limit,
  //                budget_limits.heap_cost,
  //            )
  //        } else {
  //            0_u64
  //        };
  //        let total_compute_units =
  //            loaded_accounts_data_size_cost.saturating_add(budget_limits.compute_unit_limit);
  //        let compute_fee = self
  //            .compute_fee_bins
  //            .iter()
  //            .find(|bin| total_compute_units <= bin.limit)
  //            .map(|bin| bin.fee)
  //            .unwrap_or_else(|| {
  //                self.compute_fee_bins
  //                    .last()
  //                    .map(|bin| bin.fee)
  //                    .unwrap_or_default()
  //            });

  // https://github.com/anza-xyz/agave/blob/2e6ca8c1f62db62c1db7f19c9962d4db43d0d550/sdk/src/fee.rs#L116
  ulong MEMORY_USAGE_COST = (((txn_ctx->loaded_accounts_data_size_limit + (ACCOUNT_DATA_COST_PAGE_SIZE - 1)) / ACCOUNT_DATA_COST_PAGE_SIZE) * FD_VM_HEAP_COST);
  // https://github.com/anza-xyz/agave/blob/2e6ca8c1f62db62c1db7f19c9962d4db43d0d550/sdk/src/fee.rs#L180
  ulong loaded_accounts_data_size_cost = FD_FEATURE_ACTIVE(txn_ctx->slot_ctx, include_loaded_accounts_data_size_in_fee_calculation) ? MEMORY_USAGE_COST : 0;
  ulong total_compute_units = loaded_accounts_data_size_cost + txn_ctx->compute_unit_limit;
  /* unused */
  (void)total_compute_units;
  ulong compute_fee = 0;

  // https://github.com/anza-xyz/agave/blob/2e6ca8c1f62db62c1db7f19c9962d4db43d0d550/sdk/src/fee.rs#L203-L206
  ulong execution_fee = (signature_fee + write_lock_fee + compute_fee);

  // FD_LOG_DEBUG(("fd_runtime_calculate_fee_compare: slot=%ld fee(%lf) = (prioritization_fee(%f) + signature_fee(%f) + write_lock_fee(%f) + compute_fee(%f)) * congestion_multiplier(%f)", txn_ctx->slot_ctx->slot_bank.slot, fee, prioritization_fee, signature_fee, write_lock_fee, compute_fee, congestion_multiplier));

  if (execution_fee >= ULONG_MAX)
    *ret_execution_fee = ULONG_MAX;
  else
    *ret_execution_fee = execution_fee;

  if (priority_fee >= ULONG_MAX)
    *ret_priority_fee = ULONG_MAX;
  else
    *ret_priority_fee = priority_fee;
}

/* sadness */

// static double
// fd_slots_per_year( ulong ticks_per_slot,
//                    ulong ns_per_tick ) {
//   return 365.242199 * 24.0 * 60.0 * 60.0
//     * (1000000000.0 / (double)ns_per_tick)
//     / (double)ticks_per_slot;
// }

#define FD_RENT_EXEMPT (-1L)

static long
fd_runtime_get_rent_due( fd_exec_slot_ctx_t * slot_ctx, fd_account_meta_t * acc, ulong epoch ) {

  fd_epoch_bank_t     * epoch_bank     = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_epoch_schedule_t * schedule       = &epoch_bank->rent_epoch_schedule;
  fd_rent_t           * rent           = &epoch_bank->rent;
  double                slots_per_year = epoch_bank->slots_per_year;

  fd_solana_account_meta_t *info = &acc->info;

  /* Nothing due if account is rent-exempt
     https://github.com/anza-xyz/agave/blob/v2.0.10/sdk/src/rent_collector.rs#L90 */
  ulong min_balance = fd_rent_exempt_minimum_balance( rent, acc->dlen );
  if( info->lamports>=min_balance ) {
    return FD_RENT_EXEMPT;
  }

  /* Count the number of slots that have passed since last collection. This
     inlines the agave function get_slots_in_peohc
     https://github.com/anza-xyz/agave/blob/v2.0.10/sdk/src/rent_collector.rs#L93-L98 */
  ulong slots_elapsed = 0UL;
  if( FD_UNLIKELY( info->rent_epoch<schedule->first_normal_epoch ) ) {
    /* Count the slots before the first normal epoch separately */
    for( ulong i=info->rent_epoch; i<schedule->first_normal_epoch && i<=epoch; i++ ) {
      slots_elapsed += fd_epoch_slot_cnt( schedule, i+1UL );
    }
    slots_elapsed += fd_ulong_sat_sub( epoch+1UL, schedule->first_normal_epoch ) * schedule->slots_per_epoch;
  }
  else {
    slots_elapsed = (epoch - info->rent_epoch + 1UL) * schedule->slots_per_epoch;
  }
  /* Consensus-critical use of doubles :( */

  double years_elapsed;
  if( FD_LIKELY( slots_per_year!=0.0 ) ) {
    years_elapsed = (double)slots_elapsed / slots_per_year;
  } else {
    years_elapsed = 0.0;
  }

  ulong lamports_per_year = rent->lamports_per_uint8_year * (acc->dlen + 128UL);
  /* https://github.com/anza-xyz/agave/blob/d2124a995f89e33c54f41da76bfd5b0bd5820898/sdk/src/rent_collector.rs#L108 */
  /* https://github.com/anza-xyz/agave/blob/d2124a995f89e33c54f41da76bfd5b0bd5820898/sdk/program/src/rent.rs#L95 */
  return (long)fd_rust_cast_double_to_ulong(years_elapsed * (double)lamports_per_year);
}

/* https://github.com/anza-xyz/agave/blob/v2.0.10/sdk/src/rent_collector.rs#L117-149 */
void
fd_runtime_collect_from_existing_account( fd_exec_slot_ctx_t * slot_ctx,
                                          fd_account_meta_t  * acc,
                                          fd_pubkey_t const  * pubkey,
                                          ulong                epoch ) {
  #define NO_RENT_COLLECTION_NOW (-1)
  #define EXEMPT                 (-2)
  #define COLLECT_RENT           (-3)

  /* An account must be hashed regardless of if rent is collected from it. */
  acc->slot = slot_ctx->slot_bank.slot;

  /* Inlining calculate_rent_result
     https://github.com/anza-xyz/agave/blob/v2.0.10/sdk/src/rent_collector.rs#L153-184 */
  int calculate_rent_result = COLLECT_RENT;

  /* RentResult::NoRentCollectionNow */
  if( FD_LIKELY( acc->info.rent_epoch==FD_RENT_EXEMPT_RENT_EPOCH || acc->info.rent_epoch>epoch ) ) {
    calculate_rent_result = NO_RENT_COLLECTION_NOW;
    goto rent_calculation;
  }
  /* RentResult::Exempt */
  /* Inlining should_collect_rent() */
  int should_collect_rent = !( acc->info.executable ||
                               !memcmp( pubkey, &fd_sysvar_incinerator_id, sizeof(fd_pubkey_t) ) );
  if( !should_collect_rent ) {
    calculate_rent_result = EXEMPT;
    goto rent_calculation;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.0.10/sdk/src/rent_collector.rs#L167-180 */
  long rent_due = fd_runtime_get_rent_due( slot_ctx, acc, epoch );
  if( rent_due==FD_RENT_EXEMPT ) {
    calculate_rent_result = EXEMPT;
  } else if( rent_due==0L ) {
    calculate_rent_result = NO_RENT_COLLECTION_NOW;
  } else {
    calculate_rent_result = COLLECT_RENT;
  }

  rent_calculation:
  switch( calculate_rent_result ) {
    case EXEMPT:
      acc->info.rent_epoch = FD_RENT_EXEMPT_RENT_EPOCH;
      break;
    case NO_RENT_COLLECTION_NOW:
      break;
    case COLLECT_RENT:
      if( FD_UNLIKELY( (ulong)rent_due>=acc->info.lamports ) ) {
        /* Reclaim account */
        slot_ctx->slot_bank.collected_rent += (ulong)acc->info.lamports;
        acc->info.lamports                  = 0UL;
        acc->dlen                           = 0UL;
        fd_memset( acc->info.owner, 0, sizeof(acc->info.owner) );
      } else {
        slot_ctx->slot_bank.collected_rent += (ulong)rent_due;
        acc->info.lamports                 -= (ulong)rent_due;
        acc->info.rent_epoch                = epoch+1UL;
      }
  }


  #undef NO_RENT_COLLECTION_NOW
  #undef EXEMPT
  #undef COLLECT_RENT
}

/* fd_runtime_collect_rent_from_account performs rent collection duties.
   Although the Solana runtime prevents the creation of new accounts
   that are subject to rent, some older accounts are still undergo the
   rent collection process.  Updates the account's 'rent_epoch' if
   needed. Returns 1 if the account was changed, and 0 if it is
   unchanged. */
/* https://github.com/anza-xyz/agave/blob/v2.0.10/svm/src/account_loader.rs#L71-96 */
int
fd_runtime_collect_rent_from_account( fd_exec_slot_ctx_t *  slot_ctx,
                                      fd_account_meta_t  *  acc,
                                      fd_pubkey_t const  *  key,
                                      ulong                 epoch ) {

  if( !FD_FEATURE_ACTIVE( slot_ctx, disable_rent_fees_collection ) ) {
    fd_runtime_collect_from_existing_account( slot_ctx, acc, key, epoch );
  } else {
    if( FD_UNLIKELY( acc->info.rent_epoch!=FD_RENT_EXEMPT_RENT_EPOCH &&
                     fd_runtime_get_rent_due( slot_ctx, acc, epoch ) )==FD_RENT_EXEMPT ) {
      acc->info.rent_epoch = ULONG_MAX;
    }
  }
  return FD_RUNTIME_EXECUTE_SUCCESS;
}

static void
fd_runtime_collect_rent_for_slot( fd_exec_slot_ctx_t * slot_ctx, ulong off, ulong epoch ) {
  fd_funk_txn_t * txn     = slot_ctx->funk_txn;
  fd_acc_mgr_t *  acc_mgr = slot_ctx->acc_mgr;
  fd_funk_t *     funk    = slot_ctx->acc_mgr->funk;
  fd_wksp_t *     wksp    = fd_funk_wksp( funk );

  fd_funk_partvec_t * partvec = fd_funk_get_partvec( funk, wksp );

  fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, wksp );

  for( fd_funk_rec_t const *rec_ro = fd_funk_part_head( partvec, (uint)off, rec_map );
       rec_ro != NULL;
       rec_ro = fd_funk_part_next( rec_ro, rec_map ) ) {

    if ( FD_UNLIKELY( !fd_funk_key_is_acc( rec_ro->pair.key ) ) ) {
      continue;
    }

    fd_pubkey_t const *key = fd_type_pun_const( rec_ro->pair.key[0].uc );
    FD_BORROWED_ACCOUNT_DECL( rec );
    int err = fd_acc_mgr_view( acc_mgr, txn, key, rec );

    /* Account might not exist anymore in the current world */
    if( err==FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
      continue;
    }
    if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "fd_runtime_collect_rent: fd_acc_mgr_view failed (%d)", err ));
      continue;
    }

    /* Check if latest version in this transaction */
    if( rec_ro!=rec->const_rec ) {
      continue;
    }

    /* Upgrade read-only handle to writable */
    err = fd_acc_mgr_modify(
        acc_mgr, txn, key,
        /* do_create   */ 0,
        /* min_data_sz */ 0UL,
        rec);
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "fd_runtime_collect_rent_range: fd_acc_mgr_modify failed (%d)", err ));
      continue;
    }

    /* Actually invoke rent collection */
    fd_runtime_collect_rent_from_account( slot_ctx, rec->meta, key, epoch );
  }
}

/* Yes, this is a real function that exists in Solana. Yes, I am ashamed I have had to replicate it. */
// https://github.com/firedancer-io/solana/blob/d8292b427adf8367d87068a3a88f6fd3ed8916a5/runtime/src/bank.rs#L5618
static ulong
fd_runtime_slot_count_in_two_day( ulong ticks_per_slot ) {
  return 2UL * FD_SYSVAR_CLOCK_DEFAULT_TICKS_PER_SECOND * 86400UL /* seconds per day */ / ticks_per_slot;
}

// https://github.com/firedancer-io/solana/blob/d8292b427adf8367d87068a3a88f6fd3ed8916a5/runtime/src/bank.rs#L5594
static int
fd_runtime_use_multi_epoch_collection( fd_exec_slot_ctx_t const * slot_ctx, ulong slot ) {
  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_epoch_schedule_t const * schedule = &epoch_bank->epoch_schedule;

  ulong off;
  ulong epoch = fd_slot_to_epoch( schedule, slot, &off );
  ulong slots_per_normal_epoch = fd_epoch_slot_cnt( schedule, schedule->first_normal_epoch );

  ulong slot_count_in_two_day = fd_runtime_slot_count_in_two_day( epoch_bank->ticks_per_slot );

  int use_multi_epoch_collection = ( epoch >= schedule->first_normal_epoch )
      && ( slots_per_normal_epoch < slot_count_in_two_day );

  return use_multi_epoch_collection;
}

static ulong
fd_runtime_num_rent_partitions( fd_exec_slot_ctx_t const * slot_ctx, ulong slot ) {
  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_epoch_schedule_t const * schedule = &epoch_bank->epoch_schedule;

  ulong off;
  ulong epoch = fd_slot_to_epoch( schedule, slot, &off );
  ulong slots_per_epoch = fd_epoch_slot_cnt( schedule, epoch );

  ulong slot_count_in_two_day = fd_runtime_slot_count_in_two_day( epoch_bank->ticks_per_slot );

  int use_multi_epoch_collection = fd_runtime_use_multi_epoch_collection( slot_ctx, slot );

  if( use_multi_epoch_collection ) {
    ulong epochs_in_cycle = slot_count_in_two_day / slots_per_epoch;
    return slots_per_epoch * epochs_in_cycle;
  } else {
    return slots_per_epoch;
  }
}

// https://github.com/anza-xyz/agave/blob/2bdcc838c18d262637524274cbb2275824eb97b8/accounts-db/src/accounts_partition.rs#L30
static ulong
fd_runtime_get_rent_partition( fd_exec_slot_ctx_t const * slot_ctx, ulong slot ) {
  int use_multi_epoch_collection = fd_runtime_use_multi_epoch_collection( slot_ctx, slot );

  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_epoch_schedule_t const * schedule = &epoch_bank->epoch_schedule;

  ulong off;
  ulong epoch = fd_slot_to_epoch( schedule, slot, &off );
  ulong slot_count_per_epoch = fd_epoch_slot_cnt( schedule, epoch );
  ulong slot_count_in_two_day = fd_runtime_slot_count_in_two_day( epoch_bank->ticks_per_slot );

  ulong base_epoch;
  ulong epoch_count_in_cycle;
  if( use_multi_epoch_collection ) {
    base_epoch = schedule->first_normal_epoch;
    epoch_count_in_cycle = slot_count_in_two_day / slot_count_per_epoch;
  } else {
    base_epoch = 0;
    epoch_count_in_cycle = 1;
  }

  ulong epoch_offset = epoch - base_epoch;
  ulong epoch_index_in_cycle = epoch_offset % epoch_count_in_cycle;
  return off + ( epoch_index_in_cycle * slot_count_per_epoch );
}

static void
fd_runtime_collect_rent( fd_exec_slot_ctx_t * slot_ctx ) {
  // Bank::collect_rent_eagerly (enter)

  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_epoch_schedule_t const * schedule = &epoch_bank->epoch_schedule;

  // Bank::rent_collection_partitions              (enter)
  // Bank::variable_cycle_partitions               (enter)
  // Bank::variable_cycle_partitions_between_slots (enter)

  ulong slot0 = slot_ctx->slot_bank.prev_slot;
  ulong slot1 = slot_ctx->slot_bank.slot;

  /* For genesis, we collect rent for slot 0. */
  if (slot1 == 0) {
    ulong s = slot1;
    ulong off;
    ulong epoch = fd_slot_to_epoch(schedule, s, &off);

    /* FIXME: This will not necessarily support warmup_epochs */
    ulong num_partitions = fd_runtime_num_rent_partitions( slot_ctx, s );
    /* Reconstruct rent lists if the number of slots per epoch changes */
    fd_acc_mgr_set_slots_per_epoch( slot_ctx, num_partitions );
    fd_runtime_collect_rent_for_slot( slot_ctx, fd_runtime_get_rent_partition( slot_ctx, s ), epoch );
    return;
  }

  FD_TEST(slot0 <= slot1);

  for( ulong s = slot0 + 1; s <= slot1; ++s ) {
    ulong off;
    ulong epoch = fd_slot_to_epoch(schedule, s, &off);

    /* FIXME: This will not necessarily support warmup_epochs */
    ulong num_partitions = fd_runtime_num_rent_partitions( slot_ctx, s );
    /* Reconstruct rent lists if the number of slots per epoch changes */
    fd_acc_mgr_set_slots_per_epoch( slot_ctx, num_partitions );
    fd_runtime_collect_rent_for_slot( slot_ctx, fd_runtime_get_rent_partition( slot_ctx, s ), epoch );
  }

  // FD_LOG_DEBUG(("rent collected - lamports: %lu", slot_ctx->slot_bank.collected_rent));
}

void
fd_runtime_collect_rent_accounts_prune( ulong slot, fd_exec_slot_ctx_t * slot_ctx, fd_capture_ctx_t * capture_ctx ) {
  /* TODO: Test if this works across epoch boundaries */

  /* As a note, the number of partitions are determined before execution begins.
     The rent accounts for each slot are added to the pruned funk. The data in
     the accounts is populated after execution is completed. */
  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank_const( slot_ctx->epoch_ctx );
  fd_epoch_schedule_t const * schedule = &epoch_bank->epoch_schedule;

  ulong off;

  fd_slot_to_epoch( schedule, slot, &off );

  fd_funk_t * funk = slot_ctx->acc_mgr->funk;
  fd_wksp_t * wksp = fd_funk_wksp( funk );
  fd_funk_partvec_t * partvec = fd_funk_get_partvec( funk, wksp );
  fd_funk_rec_t * rec_map = fd_funk_rec_map( funk, wksp );

  for (fd_funk_rec_t const *rec_ro = fd_funk_part_head(partvec, (uint)off, rec_map);
      rec_ro != NULL;
      rec_ro = fd_funk_part_next(rec_ro, rec_map)) {

    fd_pubkey_t const * key = fd_type_pun_const(rec_ro->pair.key[0].uc);
    fd_funk_rec_key_t rec_key = fd_acc_funk_key( key );

    fd_funk_txn_xid_t prune_xid;
    fd_memset( &prune_xid, 0x42, sizeof(fd_funk_txn_xid_t));

    fd_funk_txn_t * txn_map = fd_funk_txn_map( capture_ctx->pruned_funk, fd_funk_wksp( capture_ctx->pruned_funk ) );
    fd_funk_txn_t * prune_txn = fd_funk_txn_query( &prune_xid, txn_map );

    fd_funk_rec_t * rec = fd_funk_rec_write_prepare( capture_ctx->pruned_funk, prune_txn, &rec_key, 0, 1, NULL, NULL );
    FD_TEST(( !!rec ));

    int res = fd_funk_part_set( capture_ctx->pruned_funk, rec, (uint)off );
    FD_TEST(( res == 0 ));
  }
}

ulong fd_runtime_calculate_rent_burn( ulong rent_collected,
                                      fd_rent_t const * rent ) {
  return ( rent_collected * rent->burn_percent ) / 100UL;
}

struct fd_validator_stake_pair {
  fd_pubkey_t pubkey;
  ulong stake;
};
typedef struct fd_validator_stake_pair fd_validator_stake_pair_t;

int fd_validator_stake_pair_compare_before( fd_validator_stake_pair_t const * a,
                                            fd_validator_stake_pair_t const * b ) {
  if( a->stake > b->stake ) {
    return 1;
  } else if (a->stake == b->stake) {
    return memcmp(&a->pubkey, &b->pubkey, sizeof(fd_pubkey_t)) > 0;
  }
  else
  { // a->stake < b->stake
    return 0;
  }
}

#define SORT_NAME sort_validator_stake_pair
#define SORT_KEY_T fd_validator_stake_pair_t
#define SORT_BEFORE(a, b) (fd_validator_stake_pair_compare_before((fd_validator_stake_pair_t const *)&a, (fd_validator_stake_pair_t const *)&b))
#include "../../util/tmpl/fd_sort.c"
#undef SORT_NAME
#undef SORT_KEY_T
#undef SORT_BERFORE

void fd_runtime_distribute_rent_to_validators( fd_exec_slot_ctx_t * slot_ctx,
                                               ulong rent_to_be_distributed ) {

  FD_SCRATCH_SCOPE_BEGIN {
    ulong total_staked = 0;

    fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
    fd_vote_accounts_pair_t_mapnode_t *vote_accounts_pool = epoch_bank->stakes.vote_accounts.vote_accounts_pool;
    fd_vote_accounts_pair_t_mapnode_t *vote_accounts_root = epoch_bank->stakes.vote_accounts.vote_accounts_root;

    ulong num_validator_stakes = fd_vote_accounts_pair_t_map_size( vote_accounts_pool, vote_accounts_root );
    fd_validator_stake_pair_t * validator_stakes = fd_scratch_alloc( 8UL, sizeof(fd_validator_stake_pair_t) * num_validator_stakes );
    ulong i = 0;

    for( fd_vote_accounts_pair_t_mapnode_t *n = fd_vote_accounts_pair_t_map_minimum( vote_accounts_pool, vote_accounts_root );
        n;
        n = fd_vote_accounts_pair_t_map_successor( vote_accounts_pool, n ), i++) {

      validator_stakes[i].pubkey = n->elem.value.node_pubkey;
      validator_stakes[i].stake = n->elem.stake;

      total_staked += n->elem.stake;

    }

    sort_validator_stake_pair_inplace(validator_stakes, num_validator_stakes);

    ulong enforce_fix = FD_FEATURE_ACTIVE(slot_ctx, no_overflow_rent_distribution);
    ulong prevent_rent_fix = FD_FEATURE_ACTIVE(slot_ctx, prevent_rent_paying_rent_recipients);
    ulong validate_fee_collector_account = FD_FEATURE_ACTIVE(slot_ctx, validate_fee_collector_account);

    ulong rent_distributed_in_initial_round = 0;

    // We now do distribution, reusing the validator stakes array for the rent stares
    if( enforce_fix ) {
      for( i = 0; i < num_validator_stakes; i++ ) {
        ulong staked = validator_stakes[i].stake;
        ulong rent_share = (ulong)(((uint128)staked * (uint128)rent_to_be_distributed) / (uint128)total_staked);

        validator_stakes[i].stake = rent_share;
        rent_distributed_in_initial_round += rent_share;
      }
    } else {
      // TODO: implement old functionality!
      FD_LOG_ERR(( "unimplemented feature" ));
    }

    ulong leftover_lamports = rent_to_be_distributed - rent_distributed_in_initial_round;

    for( i = 0; i < num_validator_stakes; i++ ) {
      if (leftover_lamports == 0) {
        break;
      }

      leftover_lamports--;
      validator_stakes[i].stake++;
    }

    for( i = 0; i < num_validator_stakes; i++ ) {
      ulong rent_to_be_paid = validator_stakes[i].stake;

      if( !enforce_fix || rent_to_be_paid > 0 ) {
        fd_pubkey_t pubkey = validator_stakes[i].pubkey;

        FD_BORROWED_ACCOUNT_DECL(rec);

        int err = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, &pubkey, 0, 0UL, rec );
        if( FD_UNLIKELY(err) ) {
          FD_LOG_WARNING(( "cannot modify pubkey %s. fd_acc_mgr_modify failed (%d)", FD_BASE58_ENC_32_ALLOCA( &pubkey ), err ));
          leftover_lamports += rent_to_be_paid;
          continue;
        }

        if (validate_fee_collector_account) {
          if (memcmp(rec->meta->info.owner, fd_solana_system_program_id.key, sizeof(rec->meta->info.owner)) != 0) {
            FD_LOG_WARNING(( "cannot pay a non-system-program owned account (%s)", FD_BASE58_ENC_32_ALLOCA( &pubkey ) ));
            leftover_lamports += rent_to_be_paid;
            continue;
          }
        }

        if( prevent_rent_fix | validate_fee_collector_account) {
          // https://github.com/solana-labs/solana/blob/8c5b5f18be77737f0913355f17ddba81f14d5824/accounts-db/src/account_rent_state.rs#L39

          ulong minbal = fd_rent_exempt_minimum_balance( slot_ctx->sysvar_cache_old.rent, rec->const_meta->dlen );
          if( rec->const_meta->info.lamports + rent_to_be_paid < minbal ) {
            FD_LOG_WARNING(("cannot pay a rent paying account (%s)", FD_BASE58_ENC_32_ALLOCA( &pubkey ) ));
            leftover_lamports += rent_to_be_paid;
            continue;
          }
        }

        rec->meta->info.lamports += rent_to_be_paid;
      }
    } // end of iteration over validator_stakes
    if( enforce_fix && !prevent_rent_fix ) {
      FD_TEST( leftover_lamports == 0 );
    } else {
      ulong old = slot_ctx->slot_bank.capitalization;
      slot_ctx->slot_bank.capitalization = fd_ulong_sat_sub(slot_ctx->slot_bank.capitalization, leftover_lamports);
      FD_LOG_DEBUG(( "fd_runtime_distribute_rent_to_validators: burn %lu, capitalization %ld->%ld ", leftover_lamports, old, slot_ctx->slot_bank.capitalization ));
    }
  } FD_SCRATCH_SCOPE_END;
}

void
fd_runtime_distribute_rent( fd_exec_slot_ctx_t * slot_ctx ) {
  ulong total_rent_collected = slot_ctx->slot_bank.collected_rent;
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  ulong burned_portion = fd_runtime_calculate_rent_burn( total_rent_collected, &epoch_bank->rent );
  slot_ctx->slot_bank.capitalization = fd_ulong_sat_sub( slot_ctx->slot_bank.capitalization, burned_portion );
  ulong rent_to_be_distributed = total_rent_collected - burned_portion;

  FD_LOG_DEBUG(( "rent distribution - slot: %lu, burned_lamports: %lu, distributed_lamports: %lu, total_rent_collected: %lu", slot_ctx->slot_bank.slot, burned_portion, rent_to_be_distributed, total_rent_collected ));
  if( rent_to_be_distributed == 0 ) {
    return;
  }

  fd_runtime_distribute_rent_to_validators( slot_ctx, rent_to_be_distributed );
}

int
fd_runtime_run_incinerator( fd_exec_slot_ctx_t * slot_ctx ) {
  FD_BORROWED_ACCOUNT_DECL(rec);

  int err = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, &fd_sysvar_incinerator_id, 0, 0UL, rec );
  if( FD_UNLIKELY(err != FD_ACC_MGR_SUCCESS) ) {
    // TODO: not really an error! This is fine!
    return -1;
  }

  slot_ctx->slot_bank.capitalization = fd_ulong_sat_sub( slot_ctx->slot_bank.capitalization, rec->const_meta->info.lamports );
  rec->meta->info.lamports = 0;

  return 0;
}

void
fd_runtime_cleanup_incinerator( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_funk_rec_key_t id   = fd_acc_funk_key( &fd_sysvar_incinerator_id );
  fd_funk_t * funk = slot_ctx->acc_mgr->funk;
  fd_funk_rec_t const * rec = fd_funk_rec_query( funk, slot_ctx->funk_txn, &id );
  if( rec )
    fd_funk_rec_remove( funk, fd_funk_rec_modify( funk, rec ), 1 );
}

void
fd_runtime_freeze( fd_exec_slot_ctx_t * slot_ctx ) {

  /* https://github.com/anza-xyz/agave/blob/ced98f1ebe73f7e9691308afa757323003ff744f/runtime/src/bank.rs#L2820-L2821 */
  fd_runtime_collect_rent( slot_ctx );
  // self.collect_fees();

  fd_sysvar_recent_hashes_update( slot_ctx );

  if( !FD_FEATURE_ACTIVE(slot_ctx, disable_fees_sysvar) )
    fd_sysvar_fees_update(slot_ctx);

  ulong fees = fd_ulong_sat_add (slot_ctx->slot_bank.collected_execution_fees, slot_ctx->slot_bank.collected_priority_fees );
  if( FD_LIKELY( fees ) ) {
    // Look at collect_fees... I think this was where I saw the fee payout..
    FD_BORROWED_ACCOUNT_DECL(rec);

    int err = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, slot_ctx->leader, 0, 0UL, rec );
    if( FD_UNLIKELY(err != FD_ACC_MGR_SUCCESS) ) {
      FD_LOG_WARNING(("fd_runtime_freeze: fd_acc_mgr_modify for leader (%s) failed (%d)", FD_BASE58_ENC_32_ALLOCA( slot_ctx->leader ), err));
      return;
    }

    do {
      if ( FD_FEATURE_ACTIVE( slot_ctx, validate_fee_collector_account ) ) {
        if (memcmp(rec->meta->info.owner, fd_solana_system_program_id.key, sizeof(rec->meta->info.owner)) != 0) {
          FD_LOG_WARNING(("fd_runtime_freeze: burn %lu due to invalid owner", fees ));
          slot_ctx->slot_bank.capitalization = fd_ulong_sat_sub(slot_ctx->slot_bank.capitalization, fees);
          break;
        }

        uchar not_exempt = fd_rent_exempt_minimum_balance( slot_ctx->sysvar_cache_old.rent, rec->meta->dlen ) > rec->meta->info.lamports;
        if( not_exempt ) {
          FD_LOG_WARNING(("fd_runtime_freeze: burn %lu due to non-rent-exempt account", fees ));
          slot_ctx->slot_bank.capitalization = fd_ulong_sat_sub(slot_ctx->slot_bank.capitalization, fees);
          break;
        }
      }

      ulong fees = 0;
      ulong burn = 0;

      if ( FD_FEATURE_ACTIVE( slot_ctx, reward_full_priority_fee ) ) {
        ulong half_fee = slot_ctx->slot_bank.collected_execution_fees / 2;
        fees = fd_ulong_sat_add(slot_ctx->slot_bank.collected_priority_fees, slot_ctx->slot_bank.collected_execution_fees - half_fee);
        burn = half_fee;
      } else {
        ulong total_fees = fd_ulong_sat_add(slot_ctx->slot_bank.collected_execution_fees, slot_ctx->slot_bank.collected_priority_fees);
        ulong half_fee = total_fees / 2;
        fees = total_fees - half_fee;
        burn = half_fee;
      }

      rec->meta->info.lamports += fees;
      rec->meta->slot = slot_ctx->slot_bank.slot;

      fd_blockstore_start_write( slot_ctx->blockstore );
      fd_block_t * blk = slot_ctx->block;
      blk->rewards.collected_fees = fees;
      blk->rewards.post_balance = rec->meta->info.lamports;
      memcpy( blk->rewards.leader.uc, slot_ctx->leader->uc, sizeof(fd_hash_t) );
      fd_blockstore_end_write( slot_ctx->blockstore );

      ulong old = slot_ctx->slot_bank.capitalization;
      slot_ctx->slot_bank.capitalization = fd_ulong_sat_sub( slot_ctx->slot_bank.capitalization, burn);
      FD_LOG_DEBUG(( "fd_runtime_freeze: burn %lu, capitalization %ld->%ld ", burn, old, slot_ctx->slot_bank.capitalization));
    } while (false);

    slot_ctx->slot_bank.collected_execution_fees = 0;
    slot_ctx->slot_bank.collected_priority_fees = 0;
  }

  // self.distribute_rent();
  // self.update_slot_history();
  // self.run_incinerator();

  fd_runtime_distribute_rent( slot_ctx );
  fd_runtime_run_incinerator( slot_ctx );

  FD_LOG_DEBUG(( "fd_runtime_freeze: capitalization %ld ", slot_ctx->slot_bank.capitalization));
  slot_ctx->slot_bank.collected_rent = 0;
}

static void
fd_feature_activate( fd_exec_slot_ctx_t * slot_ctx,
                    fd_feature_id_t const * id,
                    uchar const       acct[ static 32 ] ) {

  // Skip reverted features from being activated
  if ( id->reverted==1 ) {
    return;
  }

  FD_BORROWED_ACCOUNT_DECL(acct_rec);
  int err = fd_acc_mgr_view(slot_ctx->acc_mgr, slot_ctx->funk_txn, (fd_pubkey_t *)acct, acct_rec);
  if (FD_UNLIKELY(err != FD_ACC_MGR_SUCCESS))
    return;

  fd_feature_t feature[1];

  FD_SCRATCH_SCOPE_BEGIN
  {

    fd_bincode_decode_ctx_t ctx = {
        .data = acct_rec->const_data,
        .dataend = acct_rec->const_data + acct_rec->const_meta->dlen,
        .valloc = fd_scratch_virtual(),
    };
    int decode_err = fd_feature_decode(feature, &ctx);
    if (FD_UNLIKELY(decode_err != FD_BINCODE_SUCCESS)) {
      FD_LOG_ERR(( "Failed to decode feature account %s (%d)", FD_BASE58_ENC_32_ALLOCA( acct ), decode_err ));
    }

    if( feature->has_activated_at ) {
      FD_LOG_INFO(( "feature already activated - acc: %s, slot: %lu", FD_BASE58_ENC_32_ALLOCA( acct ), feature->activated_at ));
      fd_features_set(&slot_ctx->epoch_ctx->features, id, feature->activated_at);
    } else {
      FD_LOG_INFO(( "Feature %s not activated at %lu, activating", FD_BASE58_ENC_32_ALLOCA( acct ), feature->activated_at ));

      FD_BORROWED_ACCOUNT_DECL(modify_acct_rec);
      err = fd_acc_mgr_modify(slot_ctx->acc_mgr, slot_ctx->funk_txn, (fd_pubkey_t *)acct, 0, 0UL, modify_acct_rec);
      if (FD_UNLIKELY(err != FD_ACC_MGR_SUCCESS)) {
        return;
      }

      feature->has_activated_at = 1;
      feature->activated_at = slot_ctx->slot_bank.slot;
      fd_bincode_encode_ctx_t encode_ctx = {
        .data = modify_acct_rec->data,
        .dataend = modify_acct_rec->data + modify_acct_rec->meta->dlen,
      };
      int encode_err = fd_feature_encode(feature, &encode_ctx);
      if (FD_UNLIKELY(encode_err != FD_BINCODE_SUCCESS)) {
        FD_LOG_ERR(( "Failed to encode feature account %s (%d)", FD_BASE58_ENC_32_ALLOCA( acct ), decode_err ));
      }
    }
    /* No need to call destroy, since we are using fd_scratch allocator. */
  } FD_SCRATCH_SCOPE_END;
}


void
fd_features_activate( fd_exec_slot_ctx_t * slot_ctx ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init();
                                   !fd_feature_iter_done( id );
                               id = fd_feature_iter_next( id ) ) {
    fd_feature_activate( slot_ctx, id, id->id.key );
  }
}

void fd_runtime_update_leaders(fd_exec_slot_ctx_t *slot_ctx, ulong slot)
{
  FD_SCRATCH_SCOPE_BEGIN
  {
    fd_epoch_schedule_t schedule = slot_ctx->epoch_ctx->epoch_bank.epoch_schedule;

    FD_LOG_INFO(("schedule->slots_per_epoch = %lu", schedule.slots_per_epoch));
    FD_LOG_INFO(("schedule->leader_schedule_slot_offset = %lu", schedule.leader_schedule_slot_offset));
    FD_LOG_INFO(("schedule->warmup = %d", schedule.warmup));
    FD_LOG_INFO(("schedule->first_normal_epoch = %lu", schedule.first_normal_epoch));
    FD_LOG_INFO(("schedule->first_normal_slot = %lu", schedule.first_normal_slot));

    fd_vote_accounts_t const * epoch_vaccs = &slot_ctx->slot_bank.epoch_stakes;

    ulong epoch = fd_slot_to_epoch(&schedule, slot, NULL);
    ulong slot0 = fd_epoch_slot0(&schedule, epoch);
    ulong slot_cnt = fd_epoch_slot_cnt(&schedule, epoch);

    FD_LOG_INFO(("starting rent list init"));

    fd_acc_mgr_set_slots_per_epoch(slot_ctx, fd_epoch_slot_cnt(&schedule, epoch));
    FD_LOG_INFO(("rent list init done"));

    ulong vote_acc_cnt = fd_vote_accounts_pair_t_map_size(epoch_vaccs->vote_accounts_pool, epoch_vaccs->vote_accounts_root);
    fd_stake_weight_t *epoch_weights = fd_scratch_alloc(alignof(fd_stake_weight_t), vote_acc_cnt * sizeof(fd_stake_weight_t));
    if (FD_UNLIKELY(!epoch_weights))
      FD_LOG_ERR(("fd_scratch_alloc() failed"));

    ulong stake_weight_cnt = fd_stake_weights_by_node(epoch_vaccs, epoch_weights);

    if (FD_UNLIKELY(stake_weight_cnt == ULONG_MAX))
      FD_LOG_ERR(("fd_stake_weights_by_node() failed"));

    /* Derive leader schedule */

    FD_LOG_INFO(("stake_weight_cnt=%lu slot_cnt=%lu", stake_weight_cnt, slot_cnt));
    ulong epoch_leaders_footprint = fd_epoch_leaders_footprint(stake_weight_cnt, slot_cnt);
    FD_LOG_INFO(("epoch_leaders_footprint=%lu", epoch_leaders_footprint));
    if (FD_LIKELY(epoch_leaders_footprint))
    {
      FD_TEST( stake_weight_cnt <= MAX_PUB_CNT );
      FD_TEST( slot_cnt <= MAX_SLOTS_CNT );
      void *epoch_leaders_mem = fd_exec_epoch_ctx_leaders( slot_ctx->epoch_ctx );
      fd_epoch_leaders_t * leaders = fd_epoch_leaders_join(fd_epoch_leaders_new(epoch_leaders_mem, epoch, slot0, slot_cnt, stake_weight_cnt, epoch_weights, 0UL));
      FD_TEST(leaders);
    }
  }
  FD_SCRATCH_SCOPE_END;
}

/* Update the epoch bank stakes cache with the delegated stake values from the slot bank cache.
The slot bank cache will have been accumulating this epoch, and now we are at an epoch boundary
we can safely update the epoch stakes cache with the latest values.

In Solana, the stakes cache is updated after every transaction
  (https://github.com/solana-labs/solana/blob/c091fd3da8014c0ef83b626318018f238f506435/runtime/src/bank.rs#L7587).
As delegations have to warm up, the contents of the cache will not change inter-epoch. We can therefore update
the cache only at epoch boundaries.

https://github.com/solana-labs/solana/blob/c091fd3da8014c0ef83b626318018f238f506435/runtime/src/stakes.rs#L65 */
void fd_update_stake_delegations(fd_exec_slot_ctx_t * slot_ctx ) {
FD_SCRATCH_SCOPE_BEGIN {
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  fd_stakes_t * stakes = &epoch_bank->stakes;

  // TODO: is this size correct if the same stake account is in both the slot and epoch cache? Is this possible?
  ulong stake_delegations_size = fd_delegation_pair_t_map_size(
    stakes->stake_delegations_pool, stakes->stake_delegations_root );
  stake_delegations_size += fd_stake_accounts_pair_t_map_size(
    slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, slot_ctx->slot_bank.stake_account_keys.stake_accounts_root );

  // Create a new epoch stake delegations cache, which will hold the union of the slot and epoch caches.
  fd_delegation_pair_t_mapnode_t * new_stake_root = NULL;
  fd_delegation_pair_t_mapnode_t * new_stake_pool = fd_delegation_pair_t_map_alloc( fd_scratch_virtual(), stake_delegations_size );

  // Add the stake delegations from the epoch bank to the new epoch stake delegations cache.
  for( fd_delegation_pair_t_mapnode_t const * n = fd_delegation_pair_t_map_minimum_const( stakes->stake_delegations_pool, stakes->stake_delegations_root );
        n;
        n = fd_delegation_pair_t_map_successor_const( stakes->stake_delegations_pool, n ) ) {
      fd_pubkey_t const * stake_acc = &n->elem.account;
      FD_BORROWED_ACCOUNT_DECL(stake_acc_rec);
      if (fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, stake_acc, stake_acc_rec ) != FD_ACC_MGR_SUCCESS  ) {
          continue;
      }

      fd_stake_state_v2_t stake_state;
      if (fd_stake_get_state( stake_acc_rec, &slot_ctx->valloc, &stake_state) != 0) {
          continue;
      }
      fd_delegation_pair_t_mapnode_t * entry = fd_delegation_pair_t_map_acquire( new_stake_pool );
      fd_memcpy(&entry->elem.account, stake_acc, sizeof(fd_pubkey_t));
      fd_memcpy(&entry->elem.delegation, &stake_state.inner.stake.stake.delegation, sizeof(fd_delegation_t));
      fd_delegation_pair_t_map_insert( new_stake_pool, &new_stake_root, entry );
  }

  // Add the stake delegations from the slot bank to the new epoch stake delegations cache.
  for( fd_stake_accounts_pair_t_mapnode_t const * n = fd_stake_accounts_pair_t_map_minimum_const(
    slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, slot_ctx->slot_bank.stake_account_keys.stake_accounts_root );
        n;
        n = fd_stake_accounts_pair_t_map_successor_const( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, n ) ) {
      fd_pubkey_t const * stake_acc = &n->elem.key;
      FD_BORROWED_ACCOUNT_DECL(stake_acc_rec);
      if (fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, stake_acc, stake_acc_rec ) != FD_ACC_MGR_SUCCESS ) {
          continue;
      }

      fd_stake_state_v2_t stake_state;
      if (fd_stake_get_state( stake_acc_rec, &slot_ctx->valloc, &stake_state) != 0) {
          continue;
      }
      fd_delegation_pair_t_mapnode_t * entry = fd_delegation_pair_t_map_acquire( new_stake_pool );
      fd_memcpy(&entry->elem.account, stake_acc, sizeof(fd_pubkey_t));
      fd_memcpy(&entry->elem.delegation, &stake_state.inner.stake.stake.delegation, sizeof(fd_delegation_t));
      fd_delegation_pair_t_map_insert( new_stake_pool, &new_stake_root, entry );
  }

  // Update the epoch bank vote_accounts with the latest values from the slot bank
  // FIXME: resize the vote_accounts_pool if necessary
  for ( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum(
    slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool,
    slot_ctx->slot_bank.vote_account_keys.vote_accounts_root );
        n;
        n = fd_vote_accounts_pair_t_map_successor( slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool, n ) ) {

    // If the vote account is not in the epoch stakes cache, insert it
    fd_vote_accounts_pair_t_mapnode_t key;
    fd_memcpy( &key.elem.key, &n->elem.key, FD_PUBKEY_FOOTPRINT );
    fd_vote_accounts_pair_t_mapnode_t * epoch_cache_node = fd_vote_accounts_pair_t_map_find( stakes->vote_accounts.vote_accounts_pool, stakes->vote_accounts.vote_accounts_root, &key );
    if( epoch_cache_node == NULL ) {
      fd_vote_accounts_pair_t_mapnode_t * new_entry = fd_vote_accounts_pair_t_map_acquire( stakes->vote_accounts.vote_accounts_pool );

      fd_memcpy(&new_entry->elem.key, &n->elem.key, sizeof(fd_pubkey_t));
      fd_memcpy(&new_entry->elem.stake, &n->elem.stake, sizeof(ulong));
      fd_memcpy(&new_entry->elem.value, &n->elem.value, sizeof(fd_solana_account_t));

      fd_vote_accounts_pair_t_map_insert( stakes->vote_accounts.vote_accounts_pool, &stakes->vote_accounts.vote_accounts_root, new_entry );
    } else {
      epoch_cache_node->elem.stake = n->elem.stake;
    }
  }

  fd_bincode_destroy_ctx_t destroy_slot = {.valloc = slot_ctx->valloc};
  fd_vote_accounts_destroy( &slot_ctx->slot_bank.vote_account_keys, &destroy_slot );
  fd_stake_accounts_destroy(&slot_ctx->slot_bank.stake_account_keys, &destroy_slot );

  /* Release all nodes in tree.
     FIXME sweep pool and ignore tree nodes might is probably faster
           than recursive descent */
  fd_delegation_pair_t_map_release_tree( stakes->stake_delegations_pool, stakes->stake_delegations_root );
  stakes->stake_delegations_root = NULL;

  for( fd_delegation_pair_t_mapnode_t * n = fd_delegation_pair_t_map_minimum( new_stake_pool, new_stake_root ); n; n = fd_delegation_pair_t_map_successor( new_stake_pool, n ) ) {
    fd_delegation_pair_t_mapnode_t * e = fd_delegation_pair_t_map_acquire( stakes->stake_delegations_pool );
    if( FD_UNLIKELY( !e ) ) {
      FD_LOG_CRIT(( "Stake delegation map overflowed! (capacity=%lu)", fd_delegation_pair_t_map_max( stakes->stake_delegations_pool ) ));
    }
    fd_memcpy( &e->elem.account, &n->elem.account, sizeof(fd_pubkey_t));
    fd_memcpy( &e->elem.delegation, &n->elem.delegation, sizeof(fd_delegation_t));
    fd_delegation_pair_t_map_insert( stakes->stake_delegations_pool, &stakes->stake_delegations_root, e );
  }

  slot_ctx->slot_bank.stake_account_keys.stake_accounts_root = NULL;
  slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool = fd_stake_accounts_pair_t_map_alloc( slot_ctx->valloc, 100000 );

  slot_ctx->slot_bank.vote_account_keys.vote_accounts_root = NULL;
  slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool = fd_vote_accounts_pair_t_map_alloc( slot_ctx->valloc, 100000 );
} FD_SCRATCH_SCOPE_END;
}

/* Replace the stakes in T-2 (slot_ctx->slot_bank.epoch_stakes) by the stakes at T-1 (epoch_bank->next_epoch_stakes) */
static
void fd_update_epoch_stakes( fd_exec_slot_ctx_t * slot_ctx ) {
  FD_SCRATCH_SCOPE_BEGIN
  {
    fd_epoch_bank_t * epoch_bank = &slot_ctx->epoch_ctx->epoch_bank;

    /* Copy epoch_bank->next_epoch_stakes into slot_ctx->slot_bank.epoch_stakes */
    fd_vote_accounts_pair_t_map_release_tree(
      slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool,
      slot_ctx->slot_bank.epoch_stakes.vote_accounts_root );
    slot_ctx->slot_bank.epoch_stakes.vote_accounts_root = NULL;

    for ( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum(
      epoch_bank->next_epoch_stakes.vote_accounts_pool,
      epoch_bank->next_epoch_stakes.vote_accounts_root );
          n;
          n = fd_vote_accounts_pair_t_map_successor( epoch_bank->next_epoch_stakes.vote_accounts_pool, n ) ) {

      const fd_pubkey_t null_pubkey = {{ 0 }};
      if ( memcmp( &n->elem.key, &null_pubkey, FD_PUBKEY_FOOTPRINT ) == 0 ) {
        continue;
      }

      fd_vote_accounts_pair_t_mapnode_t * elem = fd_vote_accounts_pair_t_map_acquire(
        slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool );
      if ( FD_UNLIKELY(
          fd_vote_accounts_pair_t_map_free( slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool ) == 0 ) ) {
        FD_LOG_ERR(( "slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool full" ));
      }

      fd_memcpy( &elem->elem, &n->elem, sizeof(fd_vote_accounts_pair_t));
      fd_vote_accounts_pair_t_map_insert(
        slot_ctx->slot_bank.epoch_stakes.vote_accounts_pool,
        &slot_ctx->slot_bank.epoch_stakes.vote_accounts_root,
        elem );
    }
  }
  FD_SCRATCH_SCOPE_END;
}

/* Copy epoch_bank->stakes.vote_accounts into epoch_bank->next_epoch_stakes. */
static
void fd_update_next_epoch_stakes( fd_exec_slot_ctx_t * slot_ctx ) {
  FD_SCRATCH_SCOPE_BEGIN
  {
    fd_epoch_bank_t * epoch_bank = &slot_ctx->epoch_ctx->epoch_bank;

    /* Copy epoch_ctx->epoch_bank->stakes.vote_accounts into epoch_bank->next_epoch_stakes */
    fd_vote_accounts_pair_t_map_release_tree(
      epoch_bank->next_epoch_stakes.vote_accounts_pool,
      epoch_bank->next_epoch_stakes.vote_accounts_root );

    epoch_bank->next_epoch_stakes.vote_accounts_pool = fd_exec_epoch_ctx_next_epoch_stakes_join( slot_ctx->epoch_ctx );
    epoch_bank->next_epoch_stakes.vote_accounts_root = NULL;

    for ( fd_vote_accounts_pair_t_mapnode_t * n = fd_vote_accounts_pair_t_map_minimum(
      epoch_bank->stakes.vote_accounts.vote_accounts_pool,
      epoch_bank->stakes.vote_accounts.vote_accounts_root );
          n;
          n = fd_vote_accounts_pair_t_map_successor( epoch_bank->stakes.vote_accounts.vote_accounts_pool, n ) ) {
      fd_vote_accounts_pair_t_mapnode_t * elem = fd_vote_accounts_pair_t_map_acquire( epoch_bank->next_epoch_stakes.vote_accounts_pool );
      fd_memcpy( &elem->elem, &n->elem, sizeof(fd_vote_accounts_pair_t));
      fd_vote_accounts_pair_t_map_insert( epoch_bank->next_epoch_stakes.vote_accounts_pool, &epoch_bank->next_epoch_stakes.vote_accounts_root, elem );
    }
  }
  FD_SCRATCH_SCOPE_END;
}

/* Starting a new epoch.
  New epoch:        T
  Just ended epoch: T-1
  Epoch before:     T-2

  In this function:
  - stakes in T-2 (slot_ctx->slot_bank.epoch_stakes) should be replaced by T-1 (epoch_bank->next_epoch_stakes)
  - stakes at T-1 (epoch_bank->next_epoch_stakes) should be replaced by updated stakes at T (stakes->vote_accounts)
  - leader schedule should be calculated using new T-2 stakes (slot_ctx->slot_bank.epoch_stakes)

  Invariant during an epoch T:
  epoch_bank->next_epoch_stakes    holds the stakes at T-1
  slot_ctx->slot_bank.epoch_stakes holds the stakes at T-2
 */
/* process for the start of a new epoch */
void fd_process_new_epoch(
    fd_exec_slot_ctx_t *slot_ctx,
    ulong parent_epoch )
{
  ulong slot;
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  ulong epoch = fd_slot_to_epoch(&epoch_bank->epoch_schedule, slot_ctx->slot_bank.slot, &slot);

  // activate feature flags
  fd_features_activate( slot_ctx );
  fd_features_restore( slot_ctx );

  // Change the speed of the poh clock
  if (FD_FEATURE_ACTIVE(slot_ctx, update_hashes_per_tick6))
    epoch_bank->hashes_per_tick = UPDATED_HASHES_PER_TICK6;
  else if (FD_FEATURE_ACTIVE(slot_ctx, update_hashes_per_tick5))
    epoch_bank->hashes_per_tick = UPDATED_HASHES_PER_TICK5;
  else if (FD_FEATURE_ACTIVE(slot_ctx, update_hashes_per_tick4))
    epoch_bank->hashes_per_tick = UPDATED_HASHES_PER_TICK4;
  else if (FD_FEATURE_ACTIVE(slot_ctx, update_hashes_per_tick3))
    epoch_bank->hashes_per_tick = UPDATED_HASHES_PER_TICK3;
  else if (FD_FEATURE_ACTIVE(slot_ctx, update_hashes_per_tick2))
    epoch_bank->hashes_per_tick = UPDATED_HASHES_PER_TICK2;

  /* Updates stake history sysvar accumulated values. */
  fd_stakes_activate_epoch( slot_ctx );

  /* Update the stakes epoch value to the new epoch */
  epoch_bank->stakes.epoch = epoch;

  /* If appropiate, use the stakes at T-1 to generate the leader schedule instead of T-2.
     This is due to a subtlety in how Agave's stake caches interact when loading from snapshots.
     See the comment in fd_exec_slot_ctx_recover_. */
  if( slot_ctx->slot_bank.has_use_preceeding_epoch_stakes && slot_ctx->slot_bank.use_preceeding_epoch_stakes == epoch ) {
    fd_update_epoch_stakes( slot_ctx );
  }

  /* Distribute rewards */
  fd_hash_t const * parent_blockhash = slot_ctx->slot_bank.block_hash_queue.last_hash;
  if ( ( FD_FEATURE_ACTIVE( slot_ctx, enable_partitioned_epoch_reward ) ||
         FD_FEATURE_ACTIVE( slot_ctx, partitioned_epoch_rewards_superfeature ) ) ) {
    fd_begin_partitioned_rewards( slot_ctx, parent_blockhash, parent_epoch );
  } else {
    fd_update_rewards( slot_ctx, parent_blockhash, parent_epoch );
  }

  /* Updates stakes at time T */
  fd_stake_history_t const * history = fd_sysvar_cache_stake_history( slot_ctx->sysvar_cache );
  if( FD_UNLIKELY( !history ) ) FD_LOG_ERR(( "StakeHistory sysvar is missing from sysvar cache" ));

  refresh_vote_accounts( slot_ctx, history );
  fd_update_stake_delegations( slot_ctx );

  /* Replace stakes at T-2 (slot_ctx->slot_bank.epoch_stakes) by stakes at T-1 (epoch_bank->next_epoch_stakes) */
  fd_update_epoch_stakes( slot_ctx );

  /* Replace stakes at T-1 (epoch_bank->next_epoch_stakes) by updated stakes at T (stakes->vote_accounts) */
  fd_update_next_epoch_stakes( slot_ctx );

  /* Update current leaders using slot_ctx->slot_bank.epoch_stakes (new T-2 stakes) */
  fd_runtime_update_leaders( slot_ctx, slot_ctx->slot_bank.slot );

  fd_calculate_epoch_accounts_hash_values( slot_ctx );
}

/* Loads the sysvar cache. Expects acc_mgr, funk_txn, valloc to be non-NULL and valid. */
int fd_runtime_sysvar_cache_load( fd_exec_slot_ctx_t * slot_ctx ) {
  if (FD_UNLIKELY(!slot_ctx->acc_mgr)) return -1;
  // if (FD_UNLIKELY(!slot_ctx->funk_txn)) return -1;
  /* TODO check valloc */

  fd_sysvar_cache_restore( slot_ctx->sysvar_cache, slot_ctx->acc_mgr, slot_ctx->funk_txn );

  fd_slot_hashes_new( slot_ctx->sysvar_cache_old.slot_hashes );
  if( FD_UNLIKELY( !fd_sysvar_slot_hashes_read( slot_ctx->sysvar_cache_old.slot_hashes, slot_ctx ) ) ) {
    FD_LOG_WARNING(("reading sysvars failed"));
    return -1;
  }

  fd_rent_new( slot_ctx->sysvar_cache_old.rent );
  if( FD_UNLIKELY( !fd_sysvar_rent_read( slot_ctx->sysvar_cache_old.rent, slot_ctx ) ) ) {
    FD_LOG_WARNING(("reading sysvars failed"));
    return -1;
  }

  fd_sol_sysvar_clock_new( slot_ctx->sysvar_cache_old.clock );
  if( FD_UNLIKELY( !fd_sysvar_clock_read( slot_ctx->sysvar_cache_old.clock, slot_ctx ) ) ) {
    FD_LOG_WARNING(("reading sysvars failed"));
    return -1;
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int
fd_runtime_process_genesis_block( fd_exec_slot_ctx_t * slot_ctx, fd_capture_ctx_t * capture_ctx ) {
  ulong hashcnt_per_slot = slot_ctx->epoch_ctx->epoch_bank.hashes_per_tick * slot_ctx->epoch_ctx->epoch_bank.ticks_per_slot;
  while(hashcnt_per_slot--) {
    fd_sha256_hash( slot_ctx->slot_bank.poh.uc, 32UL, slot_ctx->slot_bank.poh.uc );
  }

  slot_ctx->slot_bank.collected_execution_fees = 0;
  slot_ctx->slot_bank.collected_priority_fees = 0;
  slot_ctx->slot_bank.collected_rent = 0;
  slot_ctx->signature_cnt = 0;

  fd_sysvar_slot_history_update(slot_ctx);

  fd_runtime_freeze( slot_ctx );

  /* sort and update bank hash */
  int result = fd_update_hash_bank( slot_ctx, capture_ctx, &slot_ctx->slot_bank.banks_hash, slot_ctx->signature_cnt );
  if (result != FD_EXECUTOR_INSTR_SUCCESS) {
    FD_LOG_ERR(("Failed to update bank hash with error=%d", result));
  }

  FD_TEST( FD_RUNTIME_EXECUTE_SUCCESS == fd_runtime_save_epoch_bank( slot_ctx ) );

  FD_TEST( FD_RUNTIME_EXECUTE_SUCCESS == fd_runtime_save_slot_bank( slot_ctx ) );

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

void
fd_runtime_read_genesis( fd_exec_slot_ctx_t * slot_ctx,
                         char const         * genesis_filepath,
                         uchar                is_snapshot,
                         fd_capture_ctx_t   * capture_ctx
 ) {
  if ( strlen( genesis_filepath ) == 0 ) return;

  struct stat sbuf;
  if( FD_UNLIKELY( stat( genesis_filepath, &sbuf) < 0 ) ) {
    FD_LOG_ERR(("cannot open %s : %s", genesis_filepath, strerror(errno)));
  }
  int fd = open( genesis_filepath, O_RDONLY );
  if( FD_UNLIKELY( fd < 0 ) ) {
    FD_LOG_ERR(("cannot open %s : %s", genesis_filepath, strerror(errno)));
  }

  fd_genesis_solana_t genesis_block;
  fd_genesis_solana_new(&genesis_block);
  fd_hash_t genesis_hash;

  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );

  FD_SCRATCH_SCOPE_BEGIN {
    uchar * buf = fd_scratch_alloc(1UL, (ulong) sbuf.st_size);  /* TODO Make this a scratch alloc */
    ssize_t n = read(fd, buf, (ulong) sbuf.st_size);
    close(fd);


    fd_bincode_decode_ctx_t decode_ctx = {
      .data    = buf,
      .dataend = buf + n,
      .valloc  = slot_ctx->valloc,
    };
    if( fd_genesis_solana_decode(&genesis_block, &decode_ctx) )
      FD_LOG_ERR(("fd_genesis_solana_decode failed"));

    // The hash is generated from the raw data... don't mess with this..
    fd_sha256_hash( buf, (ulong)n, genesis_hash.uc );

  } FD_SCRATCH_SCOPE_END;

  fd_memcpy( epoch_bank->genesis_hash.uc, genesis_hash.uc, 32U );
  epoch_bank->cluster_type = genesis_block.cluster_type;

  fd_funk_start_write( slot_ctx->acc_mgr->funk );

  if ( !is_snapshot ) {
    fd_runtime_init_bank_from_genesis( slot_ctx, &genesis_block, &genesis_hash );

    fd_runtime_init_program( slot_ctx );

    FD_LOG_DEBUG(( "start genesis accounts - count: %lu", genesis_block.accounts_len));

    for( ulong i=0; i < genesis_block.accounts_len; i++ ) {
      fd_pubkey_account_pair_t * a = &genesis_block.accounts[i];

      FD_BORROWED_ACCOUNT_DECL(rec);

      int err = fd_acc_mgr_modify(
        slot_ctx->acc_mgr,
        slot_ctx->funk_txn,
        &a->key,
        /* do_create */ 1,
        a->account.data_len,
        rec);
      if( FD_UNLIKELY( err ) )
        FD_LOG_ERR(( "fd_acc_mgr_modify failed (%d)", err ));

      rec->meta->dlen            = a->account.data_len;
      rec->meta->info.lamports   = a->account.lamports;
      rec->meta->info.rent_epoch = a->account.rent_epoch;
      rec->meta->info.executable = a->account.executable;
      memcpy( rec->meta->info.owner, a->account.owner.key, 32UL );
      if( a->account.data_len )
        memcpy( rec->data, a->account.data, a->account.data_len );
    }

    FD_LOG_DEBUG(( "end genesis accounts"));

    FD_LOG_DEBUG(( "native instruction processors - count: %lu", genesis_block.native_instruction_processors_len));

    for( ulong i=0; i < genesis_block.native_instruction_processors_len; i++ ) {
      fd_string_pubkey_pair_t * a = &genesis_block.native_instruction_processors[i];
      fd_write_builtin_bogus_account( slot_ctx, a->pubkey.uc, (const char *) a->string, a->string_len );
    }

    fd_features_restore( slot_ctx );

    slot_ctx->slot_bank.slot = 0UL;

    int err = fd_runtime_process_genesis_block( slot_ctx, capture_ctx );
    if( FD_UNLIKELY( err  ) ) {
      FD_LOG_ERR(( "Genesis slot 0 execute failed with error %d", err ));
    }
  }

  slot_ctx->slot_bank.stake_account_keys.stake_accounts_root = NULL;
  slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool = fd_stake_accounts_pair_t_map_alloc(slot_ctx->valloc, 100000);

  slot_ctx->slot_bank.vote_account_keys.vote_accounts_root = NULL;
  slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool = fd_vote_accounts_pair_t_map_alloc(slot_ctx->valloc, 100000);

  fd_funk_end_write( slot_ctx->acc_mgr->funk );

  fd_bincode_destroy_ctx_t ctx2 = { .valloc = slot_ctx->valloc };
  fd_genesis_solana_destroy(&genesis_block, &ctx2);

  // if( capture_ctx )  {
  //   fd_solcap_writer_fini( capture_ctx->capture );
  // }
}
