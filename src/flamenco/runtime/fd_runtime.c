#include "fd_acc_mgr.h"
#include "fd_runtime.h"
#include "fd_account.h"
#include "fd_hashes.h"
#include "sysvar/fd_sysvar_cache.h"
#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "sysvar/fd_sysvar.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/bmtree/fd_wbmtree.h"

#include "../stakes/fd_stakes.h"
#include "../rewards/fd_rewards.h"
#include "program/fd_stake_program.h"

#include "context/fd_exec_txn_ctx.h"
#include "context/fd_exec_instr_ctx.h"
#include "info/fd_block_info.h"
#include "info/fd_microblock_batch_info.h"
#include "info/fd_microblock_info.h"
#include "program/fd_builtin_programs.h"
#include "program/fd_system_program.h"
#include "program/fd_vote_program.h"
#include "program/fd_bpf_program_util.h"

#include "../nanopb/pb_decode.h"
#include "../types/fd_solana_block.pb.h"

#include "fd_system_ids.h"
#include "../vm/fd_vm_context.h"
#include "fd_blockstore.h"

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>

#define MICRO_LAMPORTS_PER_LAMPORT (1000000UL)

void
fd_runtime_init_bank_from_genesis( fd_exec_slot_ctx_t * slot_ctx,
                                   fd_genesis_solana_t * genesis_block,
                                   fd_hash_t const * genesis_hash ) {
  slot_ctx->slot_bank.slot = 0;

  memcpy(&slot_ctx->slot_bank.poh, genesis_hash->hash, FD_SHA256_HASH_SZ);
  memset(slot_ctx->slot_bank.banks_hash.hash, 0, FD_SHA256_HASH_SZ);

  slot_ctx->slot_bank.fee_rate_governor = genesis_block->fee_rate_governor;
  slot_ctx->slot_bank.lamports_per_signature = 5000;

  fd_poh_config_t *poh = &genesis_block->poh_config;

  if (poh->hashes_per_tick)
    slot_ctx->epoch_ctx->epoch_bank.hashes_per_tick = *poh->hashes_per_tick;
  else
    slot_ctx->epoch_ctx->epoch_bank.hashes_per_tick = 0;
  slot_ctx->epoch_ctx->epoch_bank.ticks_per_slot = genesis_block->ticks_per_slot;
  slot_ctx->epoch_ctx->epoch_bank.genesis_creation_time = genesis_block->creation_time;
  uint128 target_tick_duration = ((uint128)poh->target_tick_duration.seconds * 1000000000UL + (uint128)poh->target_tick_duration.nanoseconds);
  slot_ctx->epoch_ctx->epoch_bank.ns_per_slot = target_tick_duration * slot_ctx->epoch_ctx->epoch_bank.ticks_per_slot;

#define SECONDS_PER_YEAR ((double)(365.242199 * 24.0 * 60.0 * 60.0))

  slot_ctx->epoch_ctx->epoch_bank.slots_per_year = SECONDS_PER_YEAR * (1000000000.0 / (double)target_tick_duration) / (double)slot_ctx->epoch_ctx->epoch_bank.ticks_per_slot;
  slot_ctx->epoch_ctx->epoch_bank.genesis_creation_time = genesis_block->creation_time;
  slot_ctx->slot_bank.max_tick_height = slot_ctx->epoch_ctx->epoch_bank.ticks_per_slot * (slot_ctx->slot_bank.slot + 1);
  slot_ctx->epoch_ctx->epoch_bank.epoch_schedule = genesis_block->epoch_schedule;
  slot_ctx->epoch_ctx->epoch_bank.inflation = genesis_block->inflation;
  slot_ctx->epoch_ctx->epoch_bank.rent = genesis_block->rent;
  slot_ctx->slot_bank.block_height = 0UL;

  fd_block_block_hash_entry_t *hashes = slot_ctx->slot_bank.recent_block_hashes.hashes =
      deq_fd_block_block_hash_entry_t_alloc(slot_ctx->valloc);
  fd_block_block_hash_entry_t *elem = deq_fd_block_block_hash_entry_t_push_head_nocopy(hashes);
  fd_block_block_hash_entry_new(elem);
  fd_memcpy(elem->blockhash.hash, genesis_hash, FD_SHA256_HASH_SZ);
  elem->fee_calculator.lamports_per_signature = 0;

  slot_ctx->signature_cnt = 0;

  /* Derive epoch stakes */

  ulong vote_acc_cnt = 0UL;
  for (ulong i = 0UL; i < genesis_block->accounts_len; i++)
  {
    fd_pubkey_account_pair_t const *acc = &genesis_block->accounts[i];
    if (0 == memcmp(acc->account.owner.key, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t)))
      vote_acc_cnt++;
  }

  fd_vote_accounts_pair_t_mapnode_t *vacc_pool =
      fd_vote_accounts_pair_t_map_alloc(slot_ctx->valloc, vote_acc_cnt++);
  FD_TEST(vacc_pool);
  fd_vote_accounts_pair_t_mapnode_t *vacc_root = NULL;

  fd_delegation_pair_t_mapnode_t *sacc_pool = fd_delegation_pair_t_map_alloc(slot_ctx->valloc, 10000);
  fd_delegation_pair_t_mapnode_t *sacc_root = NULL;

  fd_stake_history_treap_t *stake_history_treap = fd_stake_history_treap_alloc(slot_ctx->valloc);
  fd_stake_history_entry_t *stake_history_pool = fd_stake_history_pool_alloc(slot_ctx->valloc);

  fd_acc_lamports_t capitalization = 0UL;

  for (ulong i = 0UL; i < genesis_block->accounts_len; i++)
  {
    fd_pubkey_account_pair_t const *acc = &genesis_block->accounts[i];
    capitalization = fd_ulong_sat_add(capitalization, acc->account.lamports);

    if (0 == memcmp(acc->account.owner.key, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t)))
    {
      /* Vote Program Account */

      fd_vote_accounts_pair_t_mapnode_t *node =
          fd_vote_accounts_pair_t_map_acquire(vacc_pool);
      FD_TEST(node);

      fd_memcpy(node->elem.key.key, acc->key.key, sizeof(fd_pubkey_t));
      node->elem.stake = acc->account.lamports;
      node->elem.value = (fd_solana_account_t){
          .lamports = acc->account.lamports,
          .data_len = acc->account.data_len,
          .data = fd_valloc_malloc(slot_ctx->valloc, 1UL, acc->account.data_len),
          .owner = acc->account.owner,
          .executable = acc->account.executable,
          .rent_epoch = acc->account.rent_epoch};
      fd_memcpy(node->elem.value.data, acc->account.data, acc->account.data_len);

      fd_vote_accounts_pair_t_map_insert(vacc_pool, &vacc_root, node);

      FD_LOG_INFO(("Adding genesis vote account: key=%32J stake=%lu",
                   node->elem.key.key,
                   node->elem.stake));
    }
    else if (0 == memcmp(acc->account.owner.key, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t)))
    {
      /* stake program account */
      fd_stake_state_v2_t stake_state = {0};

      fd_bincode_decode_ctx_t decode = {.data = acc->account.data,
                                        .dataend = acc->account.data + acc->account.data_len,
                                        .valloc = slot_ctx->valloc};
      // TODO
      (void)decode;
#if 1
      // FIXME broken borrowed account
      fd_account_meta_t meta = {.dlen = acc->account.data_len};
      fd_borrowed_account_t stake_account = {
          .const_data = acc->account.data,
          .const_meta = &meta,
          .data = acc->account.data,
          .meta = &meta};
      FD_TEST(fd_stake_get_state(&stake_account, &slot_ctx->valloc, &stake_state) == 0);
#else
      FD_TEST(fd_stake_get_state(acc, &slot_ctx->valloc, &stake_state) == 1);
#endif

      fd_delegation_pair_t_mapnode_t query_node;
      fd_memcpy(&query_node.elem.account, acc->key.key, sizeof(fd_pubkey_t));
      fd_delegation_pair_t_mapnode_t *node = fd_delegation_pair_t_map_find(sacc_pool, sacc_root, &query_node);

      fd_vote_accounts_pair_t_mapnode_t query_voter;
      fd_pubkey_t *voter_pubkey = &stake_state.inner.stake.stake.delegation.voter_pubkey;
      fd_memcpy(&query_voter.elem.key, voter_pubkey, sizeof(fd_pubkey_t));
      fd_vote_accounts_pair_t_mapnode_t *voter = fd_vote_accounts_pair_t_map_find(vacc_pool, vacc_root, &query_voter);

      if (node == NULL)
      {
        node = fd_delegation_pair_t_map_acquire(sacc_pool);
        fd_memcpy(&node->elem.account, acc->key.key, sizeof(fd_pubkey_t));
        fd_memcpy(&node->elem.delegation, &stake_state.inner.stake.stake.delegation, sizeof(fd_delegation_t));
        if (voter != NULL)
          voter->elem.stake = fd_ulong_sat_add(voter->elem.stake, stake_state.inner.stake.stake.delegation.stake);
        fd_delegation_pair_t_map_insert(sacc_pool, &sacc_root, node);
      }
      else
      {
        if (memcmp(&node->elem.delegation.voter_pubkey, voter_pubkey, sizeof(fd_pubkey_t)) != 0 || node->elem.delegation.stake != stake_state.inner.stake.stake.delegation.stake)
        {
          // add stake to the new voter account
          if (voter != NULL)
            voter->elem.stake = fd_ulong_sat_add(voter->elem.stake, stake_state.inner.stake.stake.delegation.stake);

          // remove stake from the old voter account
          fd_memcpy(&query_voter.elem.key, &node->elem.delegation.voter_pubkey, sizeof(fd_pubkey_t));
          voter = fd_vote_accounts_pair_t_map_find(vacc_pool, vacc_root, &query_voter);
          if (voter != NULL)
            voter->elem.stake = fd_ulong_sat_sub(voter->elem.stake, node->elem.delegation.stake);
        }
        fd_memcpy(&node->elem.account, acc->key.key, sizeof(fd_pubkey_t));
        fd_memcpy(&node->elem.delegation, &stake_state.inner.stake.stake.delegation, sizeof(fd_delegation_t));
      }
    }
    else if (0 == memcmp(acc->account.owner.key, fd_solana_feature_program_id.key, sizeof(fd_pubkey_t)))
    {
      /* Feature Account */

      /* Scan list of feature IDs to resolve address => feature offset */
      fd_feature_id_t const *found = NULL;
      for (fd_feature_id_t const *id = fd_feature_iter_init();
           !fd_feature_iter_done(id);
           id = fd_feature_iter_next(id))
      {
        if (0 == memcmp(acc->key.key, id->id.key, sizeof(fd_pubkey_t)))
        {
          found = id;
          break;
        }
      }

      if (found)
      {
        /* Load feature activation */
        FD_SCRATCH_SCOPE_BEGIN
        {
          fd_bincode_decode_ctx_t decode = {.data = acc->account.data,
                                            .dataend = acc->account.data + acc->account.data_len,
                                            .valloc = fd_scratch_virtual()};
          fd_feature_t feature;
          int err = fd_feature_decode( &feature, &decode );
          FD_TEST( err==FD_BINCODE_SUCCESS );
          if( feature.has_activated_at ) {
            FD_LOG_DEBUG(( "Feature %32J activated at %lu (genesis)", acc->key.key, feature.activated_at ));
            fd_features_set( &slot_ctx->epoch_ctx->features, found, feature.activated_at);
          } else {
            FD_LOG_DEBUG(( "Feature %32J not activated (genesis)", acc->key.key, feature.activated_at ));
            fd_features_set( &slot_ctx->epoch_ctx->features, found, ULONG_MAX);
          }
        }
        FD_SCRATCH_SCOPE_END;
      }
    }
  }

  slot_ctx->slot_bank.epoch_stakes = (fd_vote_accounts_t){
      .vote_accounts_pool = vacc_pool,
      .vote_accounts_root = vacc_root,
  };

  slot_ctx->epoch_ctx->epoch_bank.next_epoch_stakes = (fd_vote_accounts_t){
    .vote_accounts_pool = vacc_pool,
    .vote_accounts_root = vacc_root,
  };

  /* Initializes the stakes cache in the Bank structure. */
  slot_ctx->epoch_ctx->epoch_bank.stakes = (fd_stakes_t){
      .stake_delegations_pool = sacc_pool,
      .stake_delegations_root = sacc_root,
      .epoch = 0,
      .unused = 0,
      .vote_accounts = (fd_vote_accounts_t){
          .vote_accounts_pool = vacc_pool,
          .vote_accounts_root = vacc_root},
      .stake_history = (fd_stake_history_t){.pool = stake_history_pool, .treap = stake_history_treap}};

  slot_ctx->slot_bank.capitalization = capitalization;
}

void fd_runtime_init_program(fd_exec_slot_ctx_t *slot_ctx)
{
  fd_sysvar_recent_hashes_init(slot_ctx);
  fd_sysvar_clock_init(slot_ctx);
  fd_sysvar_slot_history_init(slot_ctx);
  //  fd_sysvar_slot_hashes_init( slot_ctx );
  fd_sysvar_epoch_schedule_init(slot_ctx);
  fd_sysvar_fees_init(slot_ctx);
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
                                      void * out_txn_buf,
                                      fd_rawtxn_b_t * out_raw_txns,
                                      fd_txn_t ** out_txn_ptrs,
                                      ulong * out_signature_cnt,
                                      ulong * out_account_cnt,
                                      ulong * out_microblock_txns_sz ) {
  ulong buf_off = 0;
  ulong signature_cnt = 0;
  ulong account_cnt = 0;

  for (ulong i = 0; i < microblock_hdr->txn_cnt; i++)
  {
    out_raw_txns[i].raw = (uchar *)buf + buf_off;
    out_txn_ptrs[i] = out_txn_buf;
    ulong payload_sz = 0;
    ulong txn_sz = fd_txn_parse_core((uchar const *)buf + buf_off, fd_ulong_min(buf_sz - buf_off, FD_TXN_MTU), out_txn_buf, NULL, &payload_sz, 0);
    if (txn_sz == 0 || txn_sz > FD_TXN_MTU)
    {
      return -1;
    }

    out_raw_txns[i].txn_sz = (ushort)payload_sz;

    signature_cnt += out_txn_ptrs[i]->signature_cnt;
    account_cnt += fd_txn_account_cnt( out_txn_ptrs[i], FD_TXN_ACCT_CAT_ALL );
    buf_off += payload_sz;
    out_txn_buf = (uchar *)out_txn_buf + FD_TXN_MAX_SZ;
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
  microblock_info.txn_buf = fd_valloc_malloc(valloc, fd_txn_align(), txn_cnt * FD_TXN_MAX_SZ);
  microblock_info.txn_ptrs = fd_valloc_malloc(valloc, alignof(fd_txn_t *), txn_cnt * sizeof(fd_txn_t *));
  microblock_info.raw_txns = fd_valloc_malloc(valloc, alignof(fd_rawtxn_b_t), txn_cnt * sizeof(fd_rawtxn_b_t));

  ulong txns_sz = 0;
  if (fd_runtime_parse_microblock_txns((uchar *)buf + buf_off,
                                       buf_sz - buf_off,
                                       &microblock_info.microblock_hdr,
                                       microblock_info.txn_buf,
                                       microblock_info.raw_txns,
                                       microblock_info.txn_ptrs,
                                       &microblock_info.signature_cnt,
                                       &microblock_info.account_cnt,
                                       &txns_sz) != 0)
  {
    fd_valloc_free(valloc, microblock_info.txn_buf);
    fd_valloc_free(valloc, microblock_info.txn_ptrs);
    fd_valloc_free(valloc, microblock_info.raw_txns);
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
  for (ulong i = 0; i < microblock_cnt; i++)
  {
    fd_microblock_info_t *microblock_info = &microblock_batch_info.microblock_infos[i];
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

ulong
fd_runtime_microblock_collect_txns( fd_microblock_info_t const * microblock_info,
                                    fd_rawtxn_b_t * raw_txns,
                                    fd_txn_t * * txn_ptrs ) {
  ulong txn_cnt = microblock_info->microblock_hdr.txn_cnt;
  fd_memcpy( raw_txns, microblock_info->raw_txns, txn_cnt * sizeof(fd_rawtxn_b_t) );
  fd_memcpy( txn_ptrs, microblock_info->txn_ptrs, txn_cnt * sizeof(fd_txn_t *) );

  return txn_cnt;
}

ulong
fd_runtime_microblock_batch_collect_txns( fd_microblock_batch_info_t const * microblock_batch_info,
                                          fd_rawtxn_b_t * raw_txns,
                                          fd_txn_t * * txn_ptrs ) {
  for( ulong i = 0; i < microblock_batch_info->microblock_cnt; i++ ) {
    ulong txns_collected = fd_runtime_microblock_collect_txns( &microblock_batch_info->microblock_infos[i], raw_txns, txn_ptrs );
    raw_txns += txns_collected;
    txn_ptrs += txns_collected;
  }

  return microblock_batch_info->txn_cnt;
}

ulong
fd_runtime_block_collect_txns( fd_block_info_t const * block_info,
                               fd_rawtxn_b_t * raw_txns,
                               fd_txn_t * * txn_ptrs ) {
  for( ulong i = 0; i < block_info->microblock_batch_cnt; i++ ) {
    ulong txns_collected = fd_runtime_microblock_batch_collect_txns( &block_info->microblock_batch_infos[i], raw_txns, txn_ptrs );
    raw_txns += txns_collected;
    txn_ptrs += txns_collected;
  }

  return block_info->txn_cnt;
}

/* This is also the maximum number of microblock batches per block */
#define FD_MAX_DATA_SHREDS_PER_SLOT (32768UL)

int fd_runtime_block_prepare(void const *buf,
                             ulong buf_sz,
                             fd_valloc_t valloc,
                             fd_block_info_t *out_block_info)
{
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

void
fd_runtime_microblock_destroy( fd_valloc_t valloc,
                               fd_microblock_info_t * microblock_info ) {
  if( microblock_info == NULL ) {
    return;
  }

  fd_valloc_free(valloc, microblock_info->txn_buf);
  fd_valloc_free(valloc, microblock_info->txn_ptrs);
  fd_valloc_free(valloc, microblock_info->raw_txns);
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

  fd_valloc_free(valloc, block_info->microblock_batch_infos);
}

int
fd_runtime_microblock_execute( fd_exec_slot_ctx_t * slot_ctx,
                               fd_microblock_info_t const * microblock_info ) {
  fd_microblock_hdr_t const * hdr = &microblock_info->microblock_hdr;

  /* Loop across transactions */
  for (ulong txn_idx = 0; txn_idx < hdr->txn_cnt; txn_idx++) {
    fd_txn_t const *txn = microblock_info->txn_ptrs[txn_idx];
    fd_rawtxn_b_t const *raw_txn = &microblock_info->raw_txns[txn_idx];

    // FD_LOG_DEBUG(("executing txn - slot: %lu, txn_idx: %lu, sig: %64J", slot_ctx->slot_bank.slot, txn_idx, (uchar *)raw_txn->raw + txn->signature_off));

    fd_exec_txn_ctx_t txn_ctx;
    int res = fd_execute_txn_prepare_phase1(slot_ctx, &txn_ctx, txn, raw_txn);
    if (res != 0) {
      FD_LOG_ERR(("could not prepare txn"));
      return -1;
    }

    res = fd_execute_txn_prepare_phase2( slot_ctx, &txn_ctx );
    if (res != 0) {
      FD_LOG_ERR(("could not prepare txn"));
      return -1;
    }

    res = fd_execute_txn_prepare_phase3( slot_ctx, &txn_ctx );
    if (res != 0) {
      FD_LOG_ERR(("could not prepare txn"));
      return -1;
    }

    int exec_res = fd_execute_txn(&txn_ctx);

    res = fd_execute_txn_finalize(slot_ctx, &txn_ctx, exec_res);
    if (res != 0) {
      FD_LOG_ERR(("could not finalize txn"));
      return -1;
    }
  }

  slot_ctx->slot_bank.transaction_count += hdr->txn_cnt;

  return 0;
}

struct fd_execute_txn_task_info {
  fd_exec_txn_ctx_t * txn_ctx;
  int exec_res;
};
typedef struct fd_execute_txn_task_info fd_execute_txn_task_info_t;

static void
fd_runtime_execute_txn_task(void *tpool,
                            ulong t0 FD_PARAM_UNUSED, ulong t1 FD_PARAM_UNUSED,
                            void *args FD_PARAM_UNUSED,
                            void *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                            ulong l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
                            ulong m0, ulong m1 FD_PARAM_UNUSED,
                            ulong n0 FD_PARAM_UNUSED, ulong n1 FD_PARAM_UNUSED) {

  fd_execute_txn_task_info_t * task_info = (fd_execute_txn_task_info_t *)tpool + m0;


  int res = fd_execute_txn_prepare_phase4( task_info->txn_ctx->slot_ctx, task_info->txn_ctx );
  if( res != 0 ) {
    FD_LOG_ERR(("could not prepare txn"));
  }
  fd_txn_t const *txn = task_info->txn_ctx->txn_descriptor;
  fd_rawtxn_b_t const *raw_txn = task_info->txn_ctx->_txn_raw;
#ifdef VLOG
  FD_LOG_WARNING(("executing txn - slot: %lu, txn_idx: %lu, sig: %64J", task_info->txn_ctx->slot_ctx->slot_bank.slot, m0, (uchar *)raw_txn->raw + txn->signature_off));
#endif

  // Leave this here for debugging...
  char txnbuf[100];
  fd_base58_encode_64((uchar *)raw_txn->raw + txn->signature_off , NULL, txnbuf );

// if (!strcmp(txnbuf, "4RGULZH1tkq5naQzD5zmvPf9T8U5Ei7U2oTExnELf8EyHLyWNQzrDukmzNBVvde2p9NrHn5EW4N38oELejX1MDZq"))
//   FD_LOG_WARNING(("hi mom"));

  task_info->exec_res = fd_execute_txn( task_info->txn_ctx );
  // FD_LOG_WARNING(("Transaction result %d for %64J %lu %lu %lu", task_info->exec_res, (uchar *)raw_txn->raw + txn->signature_off, task_info->txn_ctx->compute_meter, task_info->txn_ctx->compute_unit_limit, task_info->txn_ctx->num_instructions));
}

// struct fd_execute_txn_task_info {
//   fd_exec_txn_ctx_t * txn_ctx;
//   int exec_res;
// };
// typedef struct fd_execute_txn_task_info fd_execute_txn_task_info_t;

// static void
// fd_runtime_prepare_and_execute_txn_task(void *tpool,
//                             ulong t0 FD_PARAM_UNUSED, ulong t1 FD_PARAM_UNUSED,
//                             void *args FD_PARAM_UNUSED,
//                             void *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
//                             ulong l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
//                             ulong m0, ulong m1 FD_PARAM_UNUSED,
//                             ulong n0 FD_PARAM_UNUSED, ulong n1 FD_PARAM_UNUSED) {

//   fd_execute_txn_task_info_t * task_info = (fd_execute_txn_task_info_t *)tpool + m0;

//   // fd_txn_t const *txn = task_info->txn_ctx->txn_descriptor;
//   // fd_rawtxn_b_t const *raw_txn = task_info->txn_ctx->_txn_raw;
//   // FD_LOG_DEBUG(("executing txn - slot: %lu, txn_idx: %lu, sig: %64J", task_info->txn_ctx->slot_ctx->slot_bank.slot, m0, (uchar *)raw_txn->raw + txn->signature_off));

//   task_info->exec_res = fd_execute_txn( task_info->txn_ctx );
// }

int
fd_runtime_prepare_txns_phase1( fd_exec_slot_ctx_t * slot_ctx,
                         fd_execute_txn_task_info_t * task_info,
                         fd_txn_t * * txn_ptrs,
                         fd_rawtxn_b_t * raw_txns,
                         ulong txn_cnt ) {
  /* Loop across transactions */
  for (ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++) {
    fd_txn_t const * txn = txn_ptrs[txn_idx];
    fd_rawtxn_b_t const * raw_txn = &raw_txns[txn_idx];

    // FD_LOG_DEBUG(("preparing txn - slot: %lu, txn_idx: %lu, sig: %64J", slot_ctx->slot_bank.slot, txn_idx, (uchar *)raw_txn->raw + txn->signature_off));

    task_info[txn_idx].txn_ctx = fd_valloc_malloc( slot_ctx->valloc, FD_EXEC_TXN_CTX_ALIGN, FD_EXEC_TXN_CTX_FOOTPRINT );
    fd_exec_txn_ctx_t * txn_ctx = task_info[txn_idx].txn_ctx;
    task_info[txn_idx].exec_res = -1;

    int res = fd_execute_txn_prepare_phase1(slot_ctx, txn_ctx, txn, raw_txn);
    if( res != 0 ) {
      FD_LOG_ERR(("could not prepare txn"));
      return -1;
    }
  }

  return 0;
}

int
fd_runtime_prepare_txns_phase2( fd_exec_slot_ctx_t * slot_ctx,
                                fd_execute_txn_task_info_t * task_info,
                                ulong txn_cnt ) {
  /* Loop across transactions */
  for (ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++) {
    fd_exec_txn_ctx_t * txn_ctx = task_info[txn_idx].txn_ctx;
    // FD_LOG_DEBUG(("preparing txn (phase 2) - slot: %lu, txn_idx: %lu, sig: %64J", slot_ctx->slot_bank.slot, txn_idx, (uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->signature_off));

    int res = fd_execute_txn_prepare_phase2( slot_ctx, txn_ctx );
    if( res != 0 ) {
      FD_LOG_ERR(("could not prepare txn"));
      return -1;
    }
  }

  return 0;
}

struct fd_collect_fee_task_info {
  fd_exec_txn_ctx_t * txn_ctx;
  fd_borrowed_account_t fee_payer_rec;
  ulong fee;
  int result;
};
typedef struct fd_collect_fee_task_info fd_collect_fee_task_info_t;

static void FD_FN_UNUSED
fd_collect_fee_task( void *tpool,
                     ulong t0 FD_PARAM_UNUSED, ulong t1 FD_PARAM_UNUSED,
                     void *args FD_PARAM_UNUSED,
                     void *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                     ulong l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
                     ulong m0, ulong m1 FD_PARAM_UNUSED,
                     ulong n0 FD_PARAM_UNUSED, ulong n1 FD_PARAM_UNUSED ) {
  fd_collect_fee_task_info_t * task_info = (fd_collect_fee_task_info_t *)tpool + m0;
  fd_exec_txn_ctx_t * txn_ctx = task_info->txn_ctx;
  fd_exec_slot_ctx_t * slot_ctx = task_info->txn_ctx->slot_ctx;

  fd_pubkey_t * tx_accs = (fd_pubkey_t *)((uchar *)txn_ctx->_txn_raw->raw + txn_ctx->txn_descriptor->acct_addr_off);

  fd_pubkey_t const * fee_payer_acc = &tx_accs[0];
  int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, fee_payer_acc, &task_info->fee_payer_rec );

  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "fd_acc_mgr_view(%32J) failed (%d-%s)", fee_payer_acc->uc, err, fd_acc_mgr_strerror( err ) ));
    // TODO: The fee payer does not seem to exist?!  what now?
    task_info->result = -1;
    return;
  }
  void * fee_payer_rec_data = fd_valloc_malloc( slot_ctx->valloc, 8UL, fd_borrowed_account_raw_size( &task_info->fee_payer_rec ) );
  fd_borrowed_account_make_modifiable( &task_info->fee_payer_rec, fee_payer_rec_data );

  ulong fee = fd_runtime_calculate_fee( txn_ctx, txn_ctx->txn_descriptor, txn_ctx->_txn_raw );
  if( fd_executor_collect_fee( slot_ctx, &task_info->fee_payer_rec, fee ) ) {
    task_info->result = -1;
    return;
  }

  task_info->fee = fee;
}

int
fd_runtime_prepare_txns_phase2_tpool( fd_exec_slot_ctx_t * slot_ctx,
                                      fd_execute_txn_task_info_t * task_info,
                                      ulong txn_cnt,
                                      fd_tpool_t * tpool,
                                      ulong max_workers ) {
  FD_SCRATCH_SCOPE_BEGIN  {
    fd_borrowed_account_t * * fee_payer_accs = fd_scratch_alloc( FD_BORROWED_ACCOUNT_ALIGN, txn_cnt * FD_BORROWED_ACCOUNT_FOOTPRINT );
    fd_collect_fee_task_info_t * collect_fee_task_infos = fd_scratch_alloc( 8UL, txn_cnt * sizeof(fd_collect_fee_task_info_t) );

    /* Loop across transactions */
    for (ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++) {
      fd_exec_txn_ctx_t * txn_ctx = task_info[txn_idx].txn_ctx;

      fee_payer_accs[txn_idx] = fd_borrowed_account_init( &collect_fee_task_infos[txn_idx].fee_payer_rec );
      collect_fee_task_infos[txn_idx].txn_ctx = txn_ctx;
      collect_fee_task_infos[txn_idx].result = 0;
    }

    fd_tpool_exec_all_rrobin( tpool, 0, max_workers, fd_collect_fee_task, collect_fee_task_infos, NULL, NULL, 1, 0, txn_cnt );

    for (ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++) {
      fd_collect_fee_task_info_t * collect_fee_task_info = &collect_fee_task_infos[txn_idx];
      if( FD_UNLIKELY( collect_fee_task_info->result ) ) {
        FD_LOG_WARNING(( "failed to collect fees" ));
        return -1;
      }
      slot_ctx->slot_bank.collected_fees += collect_fee_task_info->fee;
    }

    int err = fd_acc_mgr_save_many_tpool( slot_ctx->acc_mgr, slot_ctx->funk_txn, slot_ctx->valloc, fee_payer_accs, txn_cnt, tpool, max_workers );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "fd_acc_mgr_save_many failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
      return -1;
    }

    return 0;
  } FD_SCRATCH_SCOPE_END;
}

int
fd_runtime_prepare_txns_phase3( fd_exec_slot_ctx_t * slot_ctx,
                                fd_execute_txn_task_info_t * task_info,
                                ulong txn_cnt ) {
  /* Loop across transactions */
  for (ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++) {
    fd_exec_txn_ctx_t * txn_ctx = task_info[txn_idx].txn_ctx;

    int res = fd_execute_txn_prepare_phase3( slot_ctx, txn_ctx );
    if( res != 0 ) {
      FD_LOG_ERR(("could not prepare txn"));
      return -1;
    }
  }

  return 0;
}

int
fd_runtime_prepare_txns_phase4( fd_exec_slot_ctx_t * slot_ctx,
                                fd_execute_txn_task_info_t * task_info,
                                ulong txn_cnt ) {
  /* Loop across transactions */
  for (ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++) {
    fd_exec_txn_ctx_t * txn_ctx = task_info[txn_idx].txn_ctx;

    int res = fd_execute_txn_prepare_phase4( slot_ctx, txn_ctx );
    if( res != 0 ) {
      FD_LOG_ERR(("could not prepare txn"));
      return -1;
    }
  }

  return 0;
}

int
fd_runtime_prepare_txns( fd_exec_slot_ctx_t * slot_ctx,
                         fd_execute_txn_task_info_t * task_info,
                         fd_txn_t * * txn_ptrs,
                         fd_rawtxn_b_t * raw_txns,
                         ulong txn_cnt ) {
  int res = fd_runtime_prepare_txns_phase1( slot_ctx, task_info, txn_ptrs, raw_txns, txn_cnt );
  if( res != 0 ) {
    return res;
  }

  res = fd_runtime_prepare_txns_phase2( slot_ctx, task_info, txn_cnt );
  if( res != 0 ) {
    return res;
  }

  res = fd_runtime_prepare_txns_phase3( slot_ctx, task_info, txn_cnt );
  if( res != 0 ) {
    return res;
  }

  return 0;
}

int
fd_runtime_prepare_txns_tpool( fd_exec_slot_ctx_t * slot_ctx,
                         fd_execute_txn_task_info_t * task_info,
                         fd_txn_t * * txn_ptrs,
                         fd_rawtxn_b_t * raw_txns,
                         ulong txn_cnt,
                         fd_tpool_t * tpool,
                         ulong max_workers ) {
  int res = fd_runtime_prepare_txns_phase1( slot_ctx, task_info, txn_ptrs, raw_txns, txn_cnt );
  if( res != 0 ) {
    return res;
  }

  res = fd_runtime_prepare_txns_phase2_tpool( slot_ctx, task_info, txn_cnt, tpool, max_workers );
  if( res != 0 ) {
    return res;
  }

  res = fd_runtime_prepare_txns_phase3( slot_ctx, task_info, txn_cnt );
  if( res != 0 ) {
    return res;
  }

  return 0;
}

int
fd_runtime_finalize_txns_tpool( fd_exec_slot_ctx_t * slot_ctx,
                                fd_capture_ctx_t * capture_ctx,
                                fd_execute_txn_task_info_t * task_info,
                                ulong txn_cnt,
                                fd_tpool_t * tpool,
                                ulong max_workers ) {
  FD_SCRATCH_SCOPE_BEGIN {
    ulong accounts_to_save_cnt = 0;
    /* Finalize */
    for( ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++ ) {
      fd_exec_txn_ctx_t * txn_ctx = task_info[txn_idx].txn_ctx;
      int exec_txn_err = task_info[txn_idx].exec_res;

      /* For ledgers that contain txn status, decode and write out for solcap */
      if ( capture_ctx != NULL && capture_ctx->capture_txns ) {
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
              FD_LOG_WARNING(("no txn_status decoding found sig=%64J (%s)", sig, PB_GET_ERROR(&stream)));
            }
            if ( txn_status.has_compute_units_consumed ) {
              solana_cus_consumed = txn_status.compute_units_consumed;
            }
            if ( txn_status.has_err ) {
              solana_txn_err = txn_status.err.err->bytes[0];
            }

            fd_solcap_write_transaction( capture_ctx->capture, sig, exec_txn_err,
                                        txn_ctx->custom_err, slot_ctx->slot_bank.slot,
                                        fd_cus_consumed, solana_cus_consumed, solana_txn_err );
          }
        }
      }

      for ( ulong i = 0; i < txn_ctx->accounts_cnt; i++) {
        if ( txn_ctx->nonce_accounts[i] ) {
          accounts_to_save_cnt++;
        }
      }
      if( exec_txn_err != 0 ) {
        // fd_funk_txn_cancel( slot_ctx->acc_mgr->funk, txn_ctx->funk_txn, 0 );
        continue;
      }

      int dirty_vote_acc  = txn_ctx->dirty_vote_acc;
      int dirty_stake_acc = txn_ctx->dirty_stake_acc;

      for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
        if( !fd_txn_account_is_writable_idx(txn_ctx->txn_descriptor, txn_ctx->accounts, (int)i) ) {
          continue;
        }

        fd_borrowed_account_t * acc_rec = &txn_ctx->borrowed_accounts[i];

        if( dirty_vote_acc && 0==memcmp( acc_rec->meta->info.owner, &fd_solana_vote_program_id, sizeof(fd_pubkey_t) ) ) {
          FD_SCRATCH_SCOPE_BEGIN {
            fd_vote_state_versioned_t vsv[1];
            fd_bincode_decode_ctx_t decode_vsv =
              { .data    = acc_rec->data,
                .dataend = acc_rec->data + acc_rec->meta->dlen,
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

        if( dirty_stake_acc && 0==memcmp( acc_rec->meta->info.owner, &fd_solana_stake_program_id, sizeof(fd_pubkey_t) ) ) {
          // TODO does this correctly handle stake account close?
          fd_store_stake_delegation( slot_ctx, acc_rec );
        }

        if( txn_ctx->unknown_accounts[i] ) {
          memset( acc_rec->meta->hash, 0xFF, sizeof(fd_hash_t) );
          if( FD_FEATURE_ACTIVE( slot_ctx, set_exempt_rent_epoch_max ) ) {
            fd_set_exempt_rent_epoch_max( txn_ctx, &txn_ctx->accounts[i] );
          }
        }

        accounts_to_save_cnt++;
      }
    }

    fd_borrowed_account_t * * accounts_to_save = fd_scratch_alloc( 8UL, accounts_to_save_cnt * sizeof(fd_borrowed_account_t *) );
    ulong accounts_to_save_idx = 0;
    for( ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++ ) {
      fd_exec_txn_ctx_t * txn_ctx = task_info[txn_idx].txn_ctx;
      int exec_txn_err = task_info[txn_idx].exec_res;

      for ( ulong i = 0; i < txn_ctx->accounts_cnt; i++) {
        if ( txn_ctx->nonce_accounts[i] ) {
          fd_borrowed_account_t * acc_rec = &txn_ctx->borrowed_accounts[i];
          accounts_to_save[accounts_to_save_idx++] = acc_rec;
        }
      }

      if( exec_txn_err != 0 ) {
        continue;
      }

      for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
        if( !fd_txn_account_is_writable_idx(txn_ctx->txn_descriptor, txn_ctx->accounts, (int)i) ) {
          continue;
        }

        fd_borrowed_account_t * acc_rec = &txn_ctx->borrowed_accounts[i];
        accounts_to_save[accounts_to_save_idx++] = acc_rec;
      }
    }

    // TODO: we need to use the txn ctx funk_txn, valloc, etc.
    int err = fd_acc_mgr_save_many_tpool( slot_ctx->acc_mgr, slot_ctx->funk_txn, slot_ctx->valloc, accounts_to_save, accounts_to_save_cnt, tpool, max_workers );
    if( err != FD_ACC_MGR_SUCCESS ) {
      FD_LOG_ERR(( "failed to save edits to accounts" ));
      return -1;
    }

    for( ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++ ) {
      fd_exec_txn_ctx_t * txn_ctx = task_info[txn_idx].txn_ctx;

      for( ulong i = 0; i < txn_ctx->accounts_cnt; i++ ) {
        fd_borrowed_account_t * acc_rec = &txn_ctx->borrowed_accounts[i];
        void * acc_rec_data = fd_borrowed_account_destroy( acc_rec );
        if( acc_rec_data != NULL ) {
          fd_valloc_free( txn_ctx->valloc, acc_rec_data );
        }
      }
    }

    int ret = fd_funk_txn_merge_all_children(slot_ctx->acc_mgr->funk, slot_ctx->funk_txn, 1);
    if( ret != FD_FUNK_SUCCESS ) {
      FD_LOG_ERR(( "failed merging funk transaction: (%i-%s) ", ret, fd_funk_strerror(ret) ));
    }

    for (ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++) {
      fd_exec_txn_ctx_t * txn_ctx = task_info[txn_idx].txn_ctx;
      fd_valloc_free( slot_ctx->valloc, txn_ctx );
    }

    return 0;
  } FD_SCRATCH_SCOPE_END;
}


int
fd_runtime_finalize_txns( fd_exec_slot_ctx_t * slot_ctx,
                          fd_execute_txn_task_info_t * task_info,
                          ulong txn_cnt ) {
  /* Finalize */
  for (ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++) {
    fd_exec_txn_ctx_t * txn_ctx = task_info[txn_idx].txn_ctx;
    int exec_res = task_info[txn_idx].exec_res;

    int res = fd_execute_txn_finalize( slot_ctx, txn_ctx, exec_res );
    if( res != 0 ) {
      FD_LOG_ERR(( "could not finalize txn" ));
      return -1;
    }
  }

  int ret = fd_funk_txn_merge_all_children(slot_ctx->acc_mgr->funk, slot_ctx->funk_txn, 1);
  if( ret != FD_FUNK_SUCCESS ) {
    FD_LOG_ERR(( "failed merging funk transaction: (%i-%s) ", ret, fd_funk_strerror(ret) ));
  }

  for (ulong txn_idx = 0; txn_idx < txn_cnt; txn_idx++) {
    fd_exec_txn_ctx_t * txn_ctx = task_info[txn_idx].txn_ctx;
    fd_valloc_free( slot_ctx->valloc, txn_ctx );
  }

  return 0;
}

/* Make sure there are no dependent txns! */
int
fd_runtime_execute_txns_tpool( fd_exec_slot_ctx_t * slot_ctx,
                               fd_capture_ctx_t * capture_ctx,
                               fd_txn_t * * txn_ptrs,
                               fd_rawtxn_b_t * raw_txns,
                               ulong txn_cnt,
                               fd_tpool_t * tpool,
                               ulong max_workers ) {
  fd_execute_txn_task_info_t * task_info = fd_valloc_malloc(slot_ctx->valloc, 8UL, txn_cnt * sizeof(fd_execute_txn_task_info_t));
  int res = fd_runtime_prepare_txns_tpool( slot_ctx, task_info, txn_ptrs, raw_txns, txn_cnt, tpool, max_workers );
  if( res != 0 ) {
    return res;
  }
  fd_funk_set_readonly( slot_ctx->acc_mgr->funk, 1 ); /* Funk is not safe for concurrent writes */
  fd_tpool_exec_all_taskq( tpool, 0, max_workers, fd_runtime_execute_txn_task, task_info, NULL, NULL, 1, 0, txn_cnt );
  fd_funk_set_readonly( slot_ctx->acc_mgr->funk, 0 );
  res = fd_runtime_finalize_txns_tpool( slot_ctx, capture_ctx, task_info, txn_cnt, tpool, max_workers );
  if( res != 0 ) {
    return res;
  }

  fd_valloc_free( slot_ctx->valloc, task_info );
  return 0;
}

struct fd_pubkey_map_node {
  fd_pubkey_t pubkey;
  uint        hash;
};
typedef struct fd_pubkey_map_node fd_pubkey_map_node_t;

#define MAP_NAME                fd_pubkey_map
#define MAP_T                   fd_pubkey_map_node_t
#define MAP_KEY                 pubkey
#define MAP_KEY_T               fd_pubkey_t
#define MAP_KEY_NULL            pubkey_null
#define MAP_KEY_INVAL( k )      !( memcmp( &k, &pubkey_null, sizeof( fd_pubkey_t ) ) )
#define MAP_KEY_EQUAL( k0, k1 ) !( memcmp( ( &k0 ), ( &k1 ), sizeof( fd_pubkey_t ) ) )
#define MAP_KEY_EQUAL_IS_SLOW   1
#define MAP_KEY_HASH( key )     ( (uint)( fd_hash( 0UL, &key, sizeof( fd_pubkey_t ) ) ) )
#define MAP_MEMOIZE             1
#include "../../util/tmpl/fd_map_dynamic.c"

/* return 0 on failure, 1 if exists, 2 if inserted */
static uint
fd_pubkey_map_insert_if_not_in( fd_pubkey_map_node_t * map,
                                fd_pubkey_t            pubkey ) {
  /* Check if entry already exists */
  fd_pubkey_map_node_t * entry = fd_pubkey_map_query( map, pubkey, NULL );
  if( entry )
    return 1;

  /* Insert new */
  entry = fd_pubkey_map_insert( map, pubkey );
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
        if( fd_pubkey_map_query( write_map, task_info->txn_ctx->accounts[j], NULL ) != NULL ) {
          is_executable_now = 0;
          break;
        }
        if( fd_txn_account_is_writable_idx( task_info->txn_ctx->txn_descriptor, task_info->txn_ctx->accounts, (int)j ) ) {
          if( fd_pubkey_map_query( read_map, task_info->txn_ctx->accounts[j], NULL ) != NULL ) {
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
        if( fd_txn_account_is_writable_idx( task_info->txn_ctx->txn_descriptor, task_info->txn_ctx->accounts, (int)j) ) {
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
fd_runtime_execute_txns_in_waves_tpool( fd_exec_slot_ctx_t * slot_ctx,
                                        fd_capture_ctx_t * capture_ctx,
                                        fd_txn_t * * txn_ptrs,
                                        fd_rawtxn_b_t * raw_txns,
                                        ulong txn_cnt,
                                        fd_tpool_t * tpool,
                                        ulong max_workers ) {
  FD_SCRATCH_SCOPE_BEGIN {
    fd_execute_txn_task_info_t * task_infos = fd_scratch_alloc( 8, txn_cnt * sizeof(fd_execute_txn_task_info_t));
    fd_execute_txn_task_info_t * wave_task_infos = fd_scratch_alloc( 8, txn_cnt * sizeof(fd_execute_txn_task_info_t));
    ulong wave_task_infos_cnt = 0;
    int res = fd_runtime_prepare_txns_phase1( slot_ctx, task_infos, txn_ptrs, raw_txns, txn_cnt );
    if( res != 0 ) {
      return res;
    }

    ulong * incomplete_txn_idxs = fd_scratch_alloc( 8UL, txn_cnt * sizeof(ulong) );
    ulong incomplete_txn_idxs_cnt = txn_cnt;
    ulong incomplete_accounts_cnt = 0;

    /* Setup all txns as incomplete */
    for( ulong i = 0; i < txn_cnt; i++ ) {
      incomplete_txn_idxs[i] = i;
      incomplete_accounts_cnt += task_infos[i].txn_ctx->accounts_cnt;
    }

    ulong * next_incomplete_txn_idxs = fd_scratch_alloc( 8UL, txn_cnt * sizeof(ulong) );
    ulong next_incomplete_txn_idxs_cnt = 0;
    ulong next_incomplete_accounts_cnt = 0;

    double cum_wave_time_ms = 0.0;
    while( incomplete_txn_idxs_cnt > 0 ) {
      long wave_time = -fd_log_wallclock();
      fd_runtime_generate_wave( task_infos, incomplete_txn_idxs, incomplete_txn_idxs_cnt, incomplete_accounts_cnt,
                                next_incomplete_txn_idxs, &next_incomplete_txn_idxs_cnt, &next_incomplete_accounts_cnt,
                                wave_task_infos, &wave_task_infos_cnt );
      ulong * temp_incomplete_txn_idxs = incomplete_txn_idxs;
      incomplete_txn_idxs = next_incomplete_txn_idxs;
      next_incomplete_txn_idxs = temp_incomplete_txn_idxs;
      incomplete_txn_idxs_cnt = next_incomplete_txn_idxs_cnt;

      res = fd_runtime_prepare_txns_phase2_tpool( slot_ctx, wave_task_infos, wave_task_infos_cnt, tpool, max_workers );
      if( res != 0 ) {
        return res;
      }

      res = fd_runtime_prepare_txns_phase3( slot_ctx, wave_task_infos, wave_task_infos_cnt );
      if( res != 0 ) {
        return res;
      }

      fd_funk_set_readonly( slot_ctx->acc_mgr->funk, 1 ); /* Funk is not safe for concurrent writes */
      fd_tpool_exec_all_taskq( tpool, 0, max_workers, fd_runtime_execute_txn_task, wave_task_infos, NULL, NULL, 1, 0, wave_task_infos_cnt );
      fd_funk_set_readonly( slot_ctx->acc_mgr->funk, 0 );
      res = fd_runtime_finalize_txns_tpool( slot_ctx, capture_ctx, wave_task_infos, wave_task_infos_cnt, tpool, max_workers );
      if( res != 0 ) {
        return res;
      }

      wave_time += fd_log_wallclock();
      double wave_time_ms = (double)wave_time * 1e-6;
      cum_wave_time_ms += wave_time_ms;
      (void)cum_wave_time_ms;
      // FD_LOG_INFO(( "wave executed - sz: %lu, accounts: %lu, elapsed: %6.6f ms, cum: %6.6f ms", wave_task_infos_cnt, incomplete_accounts_cnt - next_incomplete_accounts_cnt, wave_time_ms, cum_wave_time_ms ));
    }
    slot_ctx->slot_bank.transaction_count += txn_cnt;

    return 0;
  } FD_SCRATCH_SCOPE_END;
}

int fd_runtime_microblock_batch_execute(fd_exec_slot_ctx_t * slot_ctx,
                                        fd_capture_ctx_t * capture_ctx FD_PARAM_UNUSED,
                                        fd_microblock_batch_info_t const * microblock_batch_info) {
  /* Loop across microblocks */
  for (ulong i = 0; i < microblock_batch_info->microblock_cnt; i++) {
    fd_microblock_info_t const * microblock_info = &microblock_batch_info->microblock_infos[i];

    // FD_LOG_DEBUG(("executing microblock - slot: %lu, mblk_idx: %lu", slot_ctx->slot_bank.slot, i));
    fd_runtime_microblock_execute(slot_ctx, microblock_info);
  }

  return 0;
}

int
fd_runtime_microblock_execute_tpool( fd_exec_slot_ctx_t *slot_ctx,
                                     fd_capture_ctx_t *capture_ctx,
                                     fd_microblock_info_t const * microblock_info,
                                     fd_tpool_t *tpool,
                                     ulong max_workers ) {
  fd_microblock_hdr_t const * hdr = &microblock_info->microblock_hdr;

  int res = fd_runtime_execute_txns_tpool( slot_ctx, capture_ctx, microblock_info->txn_ptrs, microblock_info->raw_txns, hdr->txn_cnt, tpool, max_workers );
  return res;
}

int fd_runtime_microblock_batch_execute_tpool(fd_exec_slot_ctx_t *slot_ctx,
                                              fd_capture_ctx_t *capture_ctx,
                                              fd_microblock_batch_info_t const * microblock_batch_info,
                                              fd_tpool_t *tpool,
                                              ulong max_workers) {
  /* Loop across microblocks */
  for (ulong i = 0; i < microblock_batch_info->microblock_cnt; i++) {
    fd_microblock_info_t const * microblock_info = &microblock_batch_info->microblock_infos[i];

    // FD_LOG_DEBUG(("executing microblock - slot: %lu, mblk_idx: %lu", slot_ctx->slot_bank.slot, i));
    fd_runtime_microblock_execute_tpool(slot_ctx, capture_ctx, microblock_info, tpool, max_workers);
  }

  return 0;
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
  fd_sysvar_fees_new_derived(slot_ctx, slot_ctx->slot_bank.fee_rate_governor, slot_ctx->signature_cnt);

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
  fd_slot_to_epoch(&slot_ctx->epoch_ctx->epoch_bank.epoch_schedule, slot_ctx->slot_bank.slot, &slot_rel);
  slot_ctx->leader = fd_epoch_leaders_get(slot_ctx->epoch_ctx->leaders, slot_ctx->slot_bank.slot);
  if( slot_ctx->leader == NULL ) {
    return -1;
  }

  return 0;
}

int
fd_runtime_block_execute_prepare( fd_exec_slot_ctx_t *slot_ctx ) {
  // TODO: this is not part of block execution, move it.
  if( slot_ctx->slot_bank.slot != 0 ) {
    ulong slot_idx;
    ulong prev_epoch = fd_slot_to_epoch( &slot_ctx->epoch_ctx->epoch_bank.epoch_schedule, slot_ctx->slot_bank.prev_slot, &slot_idx );
    ulong new_epoch = fd_slot_to_epoch( &slot_ctx->epoch_ctx->epoch_bank.epoch_schedule, slot_ctx->slot_bank.slot, &slot_idx );
    if (slot_idx==1UL && new_epoch==0UL) {
      /* the block after genesis has a height of 1*/
      slot_ctx->slot_bank.block_height = 1UL;
    }

    if( prev_epoch < new_epoch || slot_idx == 0 ) {
      FD_LOG_DEBUG(("Epoch boundary"));
      /* Epoch boundary! */
      fd_process_new_epoch(slot_ctx, new_epoch - 1UL);
    }
  }

  if( slot_ctx->slot_bank.slot != 0 && FD_FEATURE_ACTIVE( slot_ctx, enable_partitioned_epoch_reward ) ) {
    distribute_partitioned_epoch_rewards(slot_ctx);
  }

  int result = fd_runtime_block_update_current_leader( slot_ctx );
  if (result != 0) {
    FD_LOG_WARNING(("updating current leader"));
    return result;
  }

  result = fd_runtime_block_sysvar_update_pre_execute( slot_ctx );
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

  int result = fd_bpf_scan_and_create_bpf_program_cache_entry( slot_ctx, slot_ctx->funk_txn );
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
                                         fd_tpool_t * tpool,
                                         ulong max_workers ) {
  fd_sysvar_slot_history_update(slot_ctx);

  // this slot is frozen... and cannot change anymore...
  fd_runtime_freeze(slot_ctx);


  int result = fd_bpf_scan_and_create_bpf_program_cache_entry( slot_ctx, slot_ctx->funk_txn );
  if( result != 0 ) {
    FD_LOG_WARNING(("update bpf program cache failed"));
    return result;
  }

  result = fd_update_hash_bank_tpool(slot_ctx, capture_ctx, &slot_ctx->slot_bank.banks_hash, block_info->signature_cnt, tpool, max_workers);
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

int fd_runtime_block_execute(fd_exec_slot_ctx_t *slot_ctx,
                             fd_capture_ctx_t *capture_ctx,
                             fd_block_info_t const *block_info) {
  if (NULL != capture_ctx)
    fd_solcap_writer_set_slot( capture_ctx->capture, slot_ctx->slot_bank.slot );
  int res = fd_runtime_block_execute_prepare(slot_ctx);
  if (res != FD_RUNTIME_EXECUTE_SUCCESS) {
    return res;
  }

  for (ulong i = 0; i < block_info->microblock_batch_cnt; i++) {
    fd_microblock_batch_info_t const *microblock_batch_info = &block_info->microblock_batch_infos[i];

    if (fd_runtime_microblock_batch_execute(slot_ctx, capture_ctx, microblock_batch_info) != 0) {
      return -1;
    }
  }

  res = fd_runtime_block_execute_finalize(slot_ctx, capture_ctx, block_info);
  if (res != FD_RUNTIME_EXECUTE_SUCCESS) {
    return res;
  }

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int fd_runtime_block_execute_tpool( fd_exec_slot_ctx_t * slot_ctx,
                                    fd_capture_ctx_t * capture_ctx,
                                    fd_block_info_t const * block_info,
                                    fd_tpool_t * tpool,
                                    ulong max_workers ) {
  if (NULL != capture_ctx)
    fd_solcap_writer_set_slot( capture_ctx->capture, slot_ctx->slot_bank.slot );

  long block_execute_time = -fd_log_wallclock();

  int res = fd_runtime_block_execute_prepare( slot_ctx );
  if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
    return res;
  }

  for( ulong i = 0; i < block_info->microblock_batch_cnt; i++ ) {
    fd_microblock_batch_info_t const *microblock_batch_info = &block_info->microblock_batch_infos[i];

    if( fd_runtime_microblock_batch_execute_tpool( slot_ctx, capture_ctx, microblock_batch_info, tpool, max_workers ) != 0 ) {
      return -1;
    }
  }

  res = fd_runtime_block_execute_finalize_tpool( slot_ctx, capture_ctx, block_info, tpool, max_workers );
  if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
    return res;
  }

  block_execute_time += fd_log_wallclock();
  double block_execute_time_ms = (double)block_execute_time * 1e-6;

  FD_LOG_INFO(( "executed block successfully - slot: %lu, txns: %lu, accounts: %lu, elapsed: %6.6f ms", slot_ctx->slot_bank.slot, block_info->txn_cnt, block_info->account_cnt, block_execute_time_ms ));

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int fd_runtime_block_execute_tpool_v2( fd_exec_slot_ctx_t * slot_ctx,
                                       fd_capture_ctx_t * capture_ctx,
                                       fd_block_info_t const * block_info,
                                       fd_tpool_t * tpool,
                                       ulong max_workers ) {
  FD_SCRATCH_SCOPE_BEGIN {
    if ( capture_ctx != NULL )
      fd_solcap_writer_set_slot( capture_ctx->capture, slot_ctx->slot_bank.slot );

    long block_execute_time = -fd_log_wallclock();

    int res = fd_runtime_block_execute_prepare( slot_ctx );
    if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
      return res;
    }

    ulong txn_cnt = block_info->txn_cnt;
    fd_txn_t ** txn_ptrs = fd_scratch_alloc( alignof(fd_txn_t *), txn_cnt * sizeof(fd_txn_t *) );
    fd_rawtxn_b_t * raw_txns = fd_scratch_alloc( alignof(fd_rawtxn_b_t), txn_cnt * sizeof(fd_rawtxn_b_t) );

    fd_runtime_block_collect_txns( block_info, raw_txns, txn_ptrs );

    res = fd_runtime_execute_txns_in_waves_tpool( slot_ctx, capture_ctx, txn_ptrs, raw_txns, txn_cnt, tpool, max_workers );
    if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
      return res;
    }

    long block_finalize_time = -fd_log_wallclock();
    res = fd_runtime_block_execute_finalize_tpool( slot_ctx, capture_ctx, block_info, tpool, max_workers );
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
      fd_txn_t const *txn = microblock_info->txn_ptrs[txn_idx];
      fd_rawtxn_b_t const *raw_txn = &microblock_info->raw_txns[txn_idx];

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
    FD_LOG_WARNING(("poh mismatch (bank: %32J, entry: %32J)", out_poh_hash.hash, microblock_info->microblock_hdr.hash));
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
      fd_txn_t const *txn = microblock_info->txn_ptrs[txn_idx];
      fd_rawtxn_b_t const *raw_txn = &microblock_info->raw_txns[txn_idx];

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
    FD_LOG_WARNING(("poh mismatch (bank: %32J, entry: %32J)", out_poh_hash.hash, microblock_info->microblock_hdr.hash));
    poh_info->success = -1;
  }
}

int
fd_runtime_poh_verify_tpool( fd_poh_verification_info_t *poh_verification_info,
                             ulong poh_verification_info_cnt,
                             fd_tpool_t * tpool,
                             ulong max_workers ) {
  fd_tpool_exec_all_rrobin(tpool, 0, max_workers, fd_runtime_poh_verify_wide_task, poh_verification_info, NULL, NULL, 1, 0, poh_verification_info_cnt);

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
                                  fd_tpool_t *tpool,
                                  ulong max_workers) {
  long block_verify_time = -fd_log_wallclock();

  fd_hash_t tmp_in_poh_hash = *in_poh_hash;
  ulong poh_verification_info_cnt = block_info->microblock_cnt;
  fd_poh_verification_info_t *poh_verification_info = fd_valloc_malloc(valloc,
                                                                       alignof(fd_poh_verification_info_t),
                                                                       poh_verification_info_cnt * sizeof(fd_poh_verification_info_t));
  fd_runtime_block_verify_info_collect(block_info, &tmp_in_poh_hash, poh_verification_info);
  int result = fd_runtime_poh_verify_tpool(poh_verification_info, poh_verification_info_cnt, tpool, max_workers);
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
  FD_LOG_WARNING(("poh input %lu %lu %32J %32J", hash_cnt, txn_cnt, in_poh_hash->hash, microblock_info->microblock_hdr.hash));

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
      fd_txn_t const *txn = microblock_info->txn_ptrs[txn_idx];
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
      fd_txn_t const *txn = microblock_info->txn_ptrs[txn_idx];
      fd_rawtxn_b_t const *raw_txn = &microblock_info->raw_txns[txn_idx];

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
    FD_LOG_WARNING(("poh mismatch (bank: %32J, entry: %32J)", out_poh_hash->hash, microblock_info->microblock_hdr.hash));
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
      fd_txn_t const *txn = microblock_info->txn_ptrs[txn_idx];
      fd_rawtxn_b_t const *raw_txn = &microblock_info->raw_txns[txn_idx];

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
    FD_LOG_WARNING(("poh mismatch (bank: %32J, entry: %32J)", out_poh_hash->hash, microblock_info->microblock_hdr.hash));
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
//   child_slot_ctx->slot_bank.max_tick_height = (slot + 1) * slot_ctx->epoch_ctx->epoch_bank.ticks_per_slot;
// }

int
fd_runtime_block_eval_tpool(fd_exec_slot_ctx_t *slot_ctx,
                                fd_capture_ctx_t *capture_ctx,
                                void const *block,
                                ulong blocklen,
                                fd_tpool_t *tpool,
                                ulong max_workers,
                                ulong scheduler,
                                ulong * txn_cnt ) {
  (void)scheduler;

  /* Publish any transaction older than 31 slots */
  fd_funk_t * funk = slot_ctx->acc_mgr->funk;
  fd_funk_txn_t * txnmap = fd_funk_txn_map(funk, fd_funk_wksp(funk));
  uint depth = 0;
  for( fd_funk_txn_t * txn = slot_ctx->funk_txn; txn; txn = fd_funk_txn_parent(txn, txnmap) ) {
    if (++depth == 31U) {
      FD_LOG_DEBUG(("publishing %32J (slot %ld)", &txn->xid, txn->xid.ul[0]));
      ulong publish_err = fd_funk_txn_publish(funk, txn, 1);
      if (publish_err == 0) {
        FD_LOG_ERR(("publish err"));
        return -1;
      }

      if (FD_FEATURE_ACTIVE(slot_ctx, epoch_accounts_hash)) {
        if (txn->xid.ul[0] >= slot_ctx->epoch_ctx->epoch_bank.eah_start_slot) {
          fd_accounts_hash( slot_ctx, &slot_ctx->slot_bank.epoch_account_hash, NULL, 0, 0 );
          slot_ctx->epoch_ctx->epoch_bank.eah_start_slot = ULONG_MAX;
        }
      }

      if (capture_ctx != NULL && txn->xid.ul[0] == capture_ctx->checkpt_slot) {
        FD_LOG_NOTICE(("checkpointing at slot=%lu", capture_ctx->checkpt_slot));
        unlink(capture_ctx->checkpt_path);
        int err = fd_wksp_checkpt(fd_funk_wksp(funk), capture_ctx->checkpt_path, 0666, 0, NULL);
        if (err)
          FD_LOG_ERR(("backup failed: error %d", err));
      }

      break;
    }
  }

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
    slot_ctx->funk_txn = fd_funk_txn_prepare(funk, slot_ctx->funk_txn, &xid, 1);
  }
  fd_blockstore_end_read(slot_ctx->blockstore);

  if( FD_RUNTIME_EXECUTE_SUCCESS == ret ) {
    ret = fd_runtime_block_verify_tpool(&block_info, &slot_ctx->slot_bank.poh, &slot_ctx->slot_bank.poh, slot_ctx->valloc, tpool, max_workers);
  }
  if( FD_RUNTIME_EXECUTE_SUCCESS == ret ) {
    ret = fd_runtime_block_execute_tpool_v2(slot_ctx, capture_ctx, &block_info, tpool, max_workers);
  }

  fd_runtime_block_destroy( slot_ctx->valloc, &block_info );

  // FIXME: better way of using starting slot
  if( FD_UNLIKELY( FD_RUNTIME_EXECUTE_SUCCESS != ret ) ) {
    FD_LOG_WARNING(("execution failure, code %lu", ret));
    /* Skip over slot next time */
    slot_ctx->slot_bank.slot = slot+1;
    return 0;
  }

  block_eval_time += fd_log_wallclock();
  double block_eval_time_ms = (double)block_eval_time * 1e-6;
  double tps = (double) block_info.txn_cnt / ((double)block_eval_time * 1e-9);
  FD_LOG_INFO(("evaluated block successfully - slot: %lu, elapsed: %6.6f ms, signatures: %lu, txns: %lu, tps: %6.6f, bank_hash: %32J, leader: %32J", slot_ctx->slot_bank.slot, block_eval_time_ms, block_info.signature_cnt, block_info.txn_cnt, tps, slot_ctx->slot_bank.banks_hash.hash, slot_ctx->leader->key ));

  slot_ctx->slot_bank.transaction_count += block_info.txn_cnt;

  /* progress to next slot next time */
  slot_ctx->blockstore->root++;

  fd_runtime_save_slot_bank( slot_ctx );

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
  fd_runtime_recover_banks(slot_ctx, 1);
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

#define ACCOUNT_DATA_COST_PAGE_SIZE ((double)32 * 1024)

ulong fd_runtime_calculate_fee(fd_exec_txn_ctx_t *txn_ctx, fd_txn_t const *txn_descriptor, fd_rawtxn_b_t const *txn_raw)
{
  // https://github.com/firedancer-io/solana/blob/08a1ef5d785fe58af442b791df6c4e83fe2e7c74/runtime/src/bank.rs#L4443
  // TODO: implement fee distribution to the collector ... and then charge us the correct amount
  ulong priority = 0;
  ulong priority_fee = 0;
  compute_priority_fee(txn_ctx, &priority_fee, &priority);
  ulong lamports_per_signature = fd_runtime_txn_lamports_per_signature(txn_ctx, txn_descriptor, txn_raw);

  double BASE_CONGESTION = 5000.0;
  double current_congestion = (BASE_CONGESTION > (double)lamports_per_signature) ? BASE_CONGESTION : (double)lamports_per_signature;
  double congestion_multiplier = (lamports_per_signature == 0)                                                             ? 0.0
                                 : FD_FEATURE_ACTIVE(txn_ctx->slot_ctx, remove_congestion_multiplier_from_fee_calculation) ? 1.0
                                                                                                                           : (BASE_CONGESTION / current_congestion);

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
  double signature_fee = (double)fd_runtime_lamports_per_signature(&txn_ctx->slot_ctx->slot_bank) * (double)num_signatures;

  // TODO: as far as I can tell, this is always 0
  //
  //            let write_lock_fee = Self::get_num_write_locks_in_message(message)
  //                .saturating_mul(fee_structure.lamports_per_write_lock);
  ulong lamports_per_write_lock = 0;
  double write_lock_fee = (double)fd_ulong_sat_mul(fd_txn_account_cnt(txn_descriptor, FD_TXN_ACCT_CAT_WRITABLE), lamports_per_write_lock);

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

  double MEMORY_USAGE_COST = ((((double)txn_ctx->loaded_accounts_data_size_limit + (ACCOUNT_DATA_COST_PAGE_SIZE - 1)) / ACCOUNT_DATA_COST_PAGE_SIZE) * (double)vm_compute_budget.heap_cost);
  double loaded_accounts_data_size_cost = FD_FEATURE_ACTIVE(txn_ctx->slot_ctx, include_loaded_accounts_data_size_in_fee_calculation) ? MEMORY_USAGE_COST : 0.0;
  double total_compute_units = loaded_accounts_data_size_cost + (double)txn_ctx->compute_unit_limit;
  /* unused */
  (void)total_compute_units;
  double compute_fee = 0;

  double fee = (prioritization_fee + signature_fee + write_lock_fee + compute_fee) * congestion_multiplier;

  // FD_LOG_DEBUG(("fd_runtime_calculate_fee_compare: slot=%ld fee(%lf) = (prioritization_fee(%f) + signature_fee(%f) + write_lock_fee(%f) + compute_fee(%f)) * congestion_multiplier(%f)", txn_ctx->slot_ctx->slot_bank.slot, fee, prioritization_fee, signature_fee, write_lock_fee, compute_fee, congestion_multiplier));

  if (fee >= (double)ULONG_MAX)
    return ULONG_MAX;
  else
    return (ulong)fee;
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
fd_rent_due(fd_account_meta_t *acc,
            ulong epoch,
            fd_rent_t const *rent,
            fd_epoch_schedule_t const *schedule,
            double slots_per_year)
{

  fd_solana_account_meta_t *info = &acc->info;

  /* Nothing due if account is rent-exempt */

  ulong min_balance = fd_rent_exempt_minimum_balance2(rent, acc->dlen);
  if (info->lamports >= min_balance)
  {
    return FD_RENT_EXEMPT;
  }

  /* Count the number of slots that have passed since last collection */

  ulong slots_elapsed = 0UL;
  if (FD_LIKELY(epoch >= schedule->first_normal_epoch))
  {
    slots_elapsed = (epoch - info->rent_epoch) * schedule->slots_per_epoch;
  }
  else
  {
    for (ulong i = info->rent_epoch; i < epoch; i++)
    {
      slots_elapsed += fd_epoch_slot_cnt(schedule, i);
    }
  }
  /* Consensus-critical use of doubles :( */

  double years_elapsed;
  if (FD_LIKELY(slots_per_year != 0.0))
  {
    years_elapsed = (double)slots_elapsed / slots_per_year;
  }
  else
  {
    years_elapsed = 0.0;
  }

  ulong lamports_per_year = rent->lamports_per_uint8_year * (acc->dlen + 128UL);
  return (long)(ulong)(years_elapsed * (double)lamports_per_year);
}

/* fd_runtime_collect_rent_account performs rent collection duties.
   Although the Solana runtime prevents the creation of new accounts
   that are subject to rent, some older accounts are still undergo the
   rent collection process.  Updates the account's 'rent_epoch' if
   needed. Returns 1 if the account was changed, and 0 if it is
   unchanged. */

static int
fd_runtime_collect_rent_account( fd_exec_slot_ctx_t * slot_ctx,
                                 fd_account_meta_t * acc,
                                 fd_pubkey_t const * key,
                                 ulong epoch ) {

  // RentCollector::collect_from_existing_account (enter)
  // RentCollector::calculate_rent_result         (enter)

  fd_solana_account_meta_t *info = &acc->info;

  // RentCollector::can_skip_rent_collection (enter)

  // RentCollector::should_collect_rent      (enter)
  // https://github.com/solana-labs/solana/blob/e1e70f2c3c35f6bddf214b33810ea48d1ec6ed3c/accounts-db/src/rent_collector.rs#L74

  fd_pubkey_t incinerator;
  fd_base58_decode_32("1nc1nerator11111111111111111111111111111111", incinerator.key);
  if (0 == memcmp(key, &incinerator, sizeof(fd_pubkey_t)))
    return 0;

  long due = fd_rent_due(acc, epoch + 1,
                         &slot_ctx->epoch_ctx->epoch_bank.rent,
                         &slot_ctx->epoch_ctx->epoch_bank.epoch_schedule,
                         slot_ctx->epoch_ctx->epoch_bank.slots_per_year);

  if (!FD_FEATURE_ACTIVE(slot_ctx, skip_rent_rewrites) || !(due == 0 && info->rent_epoch != 0)) {
    // By changing the slot, this forces the account to be updated
    // in the account_delta_hash which matches the "rent rewrite"
    // behavior in solana.

    acc->slot = slot_ctx->slot_bank.slot;
  }

  if (info->executable)
    return 0;

  // RentCollector::should_collect_rent      (exit)
  // RentCollector::can_skip_rent_collection (exit)

  // RentCollector::get_rent_due


  /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/accounts-db/src/rent_collector.rs#L170-L182 */

  /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/accounts-db/src/rent_collector.rs#L117-L146 */

  /* RentResult: Exempt situation of fn collect_from_existing_account */
  if (due == FD_RENT_EXEMPT) {
    /* let set_exempt_rent_epoch_max: bool = self
            .feature_set
            .is_active(&solana_sdk::feature_set::set_exempt_rent_epoch_max::id()); */
    /* entry point here: https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L5972-L5982 */
    if( FD_FEATURE_ACTIVE( slot_ctx, set_exempt_rent_epoch_max ) ) {
      if( !fd_pubkey_is_sysvar_id( key ) ) {
        info->rent_epoch = ULONG_MAX;
      }
      return 0;
    }
    return 1;
  }

  // RentCollector::calculate_rent_result (cont)

  if (due == 0L) {
    return 0;
  }

  info->rent_epoch = epoch + 1UL;

  // RentCollector::calculate_rent_result         (exit)
  // RentCollector::collect_from_existing_account (cont)

  ulong due_ = (ulong)due;
  if (FD_UNLIKELY(due_ >= info->lamports)) {
    slot_ctx->slot_bank.collected_rent += info->lamports;
    acc->info.lamports = 0UL;
    fd_memset(acc->info.owner, 0, sizeof(acc->info.owner));
    acc->dlen = 0;

    return 1;
  }

  info->lamports -= (ulong)due;
  slot_ctx->slot_bank.collected_rent += (ulong)due;

  return 1;

  // RentCollector::collect_from_existing_account (exit)
}

static void
fd_runtime_collect_rent_for_slot( fd_exec_slot_ctx_t * slot_ctx, ulong off, ulong epoch) {
  fd_funk_txn_t *txn = slot_ctx->funk_txn;
  fd_acc_mgr_t *acc_mgr = slot_ctx->acc_mgr;
  fd_funk_t *funk = slot_ctx->acc_mgr->funk;
  fd_wksp_t *wksp = fd_funk_wksp(funk);
  fd_funk_partvec_t *partvec = fd_funk_get_partvec(funk, wksp);
  fd_funk_rec_t *rec_map = fd_funk_rec_map(funk, wksp);

  for (fd_funk_rec_t const *rec_ro = fd_funk_part_head(partvec, (uint)off, rec_map);
       rec_ro != NULL;
       rec_ro = fd_funk_part_next(rec_ro, rec_map)) {
    fd_pubkey_t const *key = fd_type_pun_const(rec_ro->pair.key[0].uc);
    // FD_LOG_WARNING(("Collecting rent from %32J", key));
    FD_BORROWED_ACCOUNT_DECL(rec);
    int err = fd_acc_mgr_view(acc_mgr, txn, key, rec);

    /* Account might not exist anymore in the current world */
    if( err == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
      continue;
    }
    if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS )) {
      FD_LOG_WARNING(("fd_runtime_collect_rent: fd_acc_mgr_view failed (%d)", err));
      continue;
    }

    /* Check if latest version in this transaction */
    if (rec_ro != rec->const_rec)
      continue;

    /* Upgrade read-only handle to writable */
    err = fd_acc_mgr_modify(
        acc_mgr, txn, key,
        /* do_create   */ 0,
        /* min_data_sz */ 0UL,
        rec);
    if (FD_UNLIKELY(err != FD_ACC_MGR_SUCCESS))
    {
      FD_LOG_WARNING(("fd_runtime_collect_rent_range: fd_acc_mgr_modify failed (%d)", err));
      continue;
    }

    /* Filter accounts that we've already visited */
    if (rec->const_meta->info.rent_epoch <= epoch || FD_FEATURE_ACTIVE(slot_ctx, set_exempt_rent_epoch_max)) {
      /* Actually invoke rent collection */
      (void)fd_runtime_collect_rent_account(slot_ctx, rec->meta, key, epoch);
    }
  }
}

static void
fd_runtime_collect_rent( fd_exec_slot_ctx_t * slot_ctx ) {
  // Bank::collect_rent_eagerly (enter)

  fd_epoch_schedule_t const * schedule = &slot_ctx->epoch_ctx->epoch_bank.epoch_schedule;

  // Bank::rent_collection_partitions              (enter)
  // Bank::variable_cycle_partitions               (enter)
  // Bank::variable_cycle_partitions_between_slots (enter)

  ulong slot0 = slot_ctx->slot_bank.prev_slot;
  ulong slot1 = slot_ctx->slot_bank.slot;

  /* TODO For whatever reason, when replaying from genesis, our slot0 is
     ULONG_MAX */
  if (slot0 == ULONG_MAX)
    slot0 = 0UL;
  FD_TEST(slot0 <= slot1);

  for( ulong s = slot0 + 1; s <= slot1; ++s ) {
    ulong off;
    ulong epoch = fd_slot_to_epoch(schedule, s, &off);

    /* Reconstruct rent lists if the number of slots per epoch changes */
    fd_acc_mgr_set_slots_per_epoch( slot_ctx, fd_epoch_slot_cnt( schedule, epoch ) );
    fd_runtime_collect_rent_for_slot( slot_ctx, off, epoch );
  }

  // FD_LOG_DEBUG(("rent collected - lamports: %lu", slot_ctx->slot_bank.collected_rent));
}

ulong fd_runtime_calculate_rent_burn( ulong rent_collected,
                                      fd_rent_t const * rent ) {
  return ( rent_collected * rent->burn_percent ) / 100;
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

    fd_vote_accounts_pair_t_mapnode_t *vote_accounts_pool = slot_ctx->epoch_ctx->epoch_bank.stakes.vote_accounts.vote_accounts_pool;
    fd_vote_accounts_pair_t_mapnode_t *vote_accounts_root = slot_ctx->epoch_ctx->epoch_bank.stakes.vote_accounts.vote_accounts_root;

    ulong num_validator_stakes = fd_vote_accounts_pair_t_map_size( vote_accounts_pool, vote_accounts_root );
    fd_validator_stake_pair_t * validator_stakes = fd_scratch_alloc( 8UL, sizeof(fd_validator_stake_pair_t) * num_validator_stakes );
    ulong i = 0;

    fd_bincode_destroy_ctx_t destroy_ctx = { .valloc = fd_scratch_virtual() };
    for( fd_vote_accounts_pair_t_mapnode_t *n = fd_vote_accounts_pair_t_map_minimum( vote_accounts_pool, vote_accounts_root );
        n;
        n = fd_vote_accounts_pair_t_map_successor( vote_accounts_pool, n ), i++) {
      fd_vote_state_versioned_t vote_state_versioned;
      fd_vote_state_versioned_new(&vote_state_versioned);
      fd_bincode_decode_ctx_t decode_ctx = {
          .data = n->elem.value.data,
          .dataend = &n->elem.value.data[n->elem.value.data_len],
          .valloc = fd_scratch_virtual()
      };
      if( fd_vote_state_versioned_decode( &vote_state_versioned, &decode_ctx ) ) {
        FD_LOG_WARNING(( "fd_vote_state_versioned_decode failed" ));
        return;
      }

      validator_stakes[i].pubkey = vote_state_versioned.inner.current.node_pubkey;
      validator_stakes[i].stake = n->elem.stake;

      total_staked += n->elem.stake;

      fd_vote_state_versioned_destroy(&vote_state_versioned, &destroy_ctx);
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
          FD_LOG_WARNING(("fd_acc_mgr_modify_raw failed (%d)", err));
        }

        if (validate_fee_collector_account) {
          if (memcmp(rec->meta->info.owner, fd_solana_system_program_id.key, sizeof(rec->meta->info.owner)) != 0) {
            FD_LOG_WARNING(("cannot pay a non-system-program owned account (%32J)", &pubkey));
            leftover_lamports += rent_to_be_paid;
            continue;
          }
        }

        if( prevent_rent_fix | validate_fee_collector_account) {
          // https://github.com/solana-labs/solana/blob/8c5b5f18be77737f0913355f17ddba81f14d5824/accounts-db/src/account_rent_state.rs#L39

          ulong minbal = fd_rent_exempt_minimum_balance2(slot_ctx->sysvar_cache_old.rent, rec->const_meta->dlen);
          if( rec->const_meta->info.lamports + rent_to_be_paid < minbal ) {
            FD_LOG_WARNING(("cannot pay a rent paying account (%32J)", &pubkey));
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
      FD_LOG_WARNING(( "fd_runtime_distribute_rent_to_validators: burn %lu, capitalization %ld->%ld ", leftover_lamports, old, slot_ctx->slot_bank.capitalization ));
    }
  } FD_SCRATCH_SCOPE_END;
}

void
fd_runtime_distribute_rent( fd_exec_slot_ctx_t * slot_ctx ) {
  ulong total_rent_collected = slot_ctx->slot_bank.collected_rent;
  ulong burned_portion = fd_runtime_calculate_rent_burn( total_rent_collected, &slot_ctx->epoch_ctx->epoch_bank.rent );
  slot_ctx->slot_bank.capitalization = fd_ulong_sat_sub( slot_ctx->slot_bank.capitalization, burned_portion );
  ulong rent_to_be_distributed = total_rent_collected - burned_portion;

  FD_LOG_DEBUG(( "rent distribution - slot: %lu, burned_lamports: %lu, distributed_lamports: %lu, total_rent_collected: %lu", slot_ctx->slot_bank.slot, burned_portion, rent_to_be_distributed, total_rent_collected ));
  if( rent_to_be_distributed == 0 ) {
    return;
  }

  fd_runtime_distribute_rent_to_validators(slot_ctx, rent_to_be_distributed);
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
  // solana/runtime/src/bank.rs::freeze(....)
  fd_runtime_collect_rent(slot_ctx);
  // self.collect_fees();

  fd_sysvar_recent_hashes_update(slot_ctx);

  if( !FD_FEATURE_ACTIVE(slot_ctx, disable_fees_sysvar) )
    fd_sysvar_fees_update(slot_ctx);

  if( slot_ctx->slot_bank.collected_fees > 0 ) {
    // Look at collect_fees... I think this was where I saw the fee payout..
    FD_BORROWED_ACCOUNT_DECL(rec);

    int err = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, slot_ctx->leader, 0, 0UL, rec );
    if( FD_UNLIKELY(err != FD_ACC_MGR_SUCCESS) ) {
      FD_LOG_WARNING(("fd_runtime_freeze: fd_acc_mgr_modify for leader (%32J) failed (%d)", slot_ctx->leader, err));
      return;
    }

    do {
      if ( FD_FEATURE_ACTIVE( slot_ctx, validate_fee_collector_account ) ) {
        if (memcmp(rec->meta->info.owner, fd_solana_system_program_id.key, sizeof(rec->meta->info.owner)) != 0) {
          FD_LOG_WARNING(("fd_runtime_freeze: burn %lu due to invalid owner", slot_ctx->slot_bank.collected_fees ));
          slot_ctx->slot_bank.capitalization = fd_ulong_sat_sub(slot_ctx->slot_bank.capitalization, slot_ctx->slot_bank.collected_fees);
          break;
        }

        uchar not_exempt = fd_rent_exempt_minimum_balance2( slot_ctx->sysvar_cache_old.rent, rec->meta->dlen) > rec->meta->info.lamports;
        if (not_exempt) {
          FD_LOG_WARNING(("fd_runtime_freeze: burn %lu due to non-rent-exempt account", slot_ctx->slot_bank.collected_fees ));
          slot_ctx->slot_bank.capitalization = fd_ulong_sat_sub(slot_ctx->slot_bank.capitalization, slot_ctx->slot_bank.collected_fees);
          break;
        }
      }

      ulong fees = (slot_ctx->slot_bank.collected_fees - (slot_ctx->slot_bank.collected_fees / 2) );
      ulong burn = slot_ctx->slot_bank.collected_fees / 2;
      rec->meta->info.lamports += fees;
      rec->meta->slot = slot_ctx->slot_bank.slot;
      // FD_LOG_DEBUG(( "fd_runtime_freeze: slot:%ld global->collected_fees: %ld, sending %ld to leader (%32J) (resulting %ld), burning %ld", slot_ctx->slot_bank.slot, slot_ctx->slot_bank.collected_fees, fees, slot_ctx->leader, rec->meta->info.lamports, fees ));

      ulong old = slot_ctx->slot_bank.capitalization;
      slot_ctx->slot_bank.capitalization = fd_ulong_sat_sub( slot_ctx->slot_bank.capitalization, burn);
      FD_LOG_DEBUG(( "fd_runtime_freeze: burn %lu, capitalization %ld->%ld ", burn, old, slot_ctx->slot_bank.capitalization));
    } while (false);

    slot_ctx->slot_bank.collected_fees = 0;
  }

  // self.distribute_rent();
  // self.update_slot_history();
  // self.run_incinerator();

  fd_runtime_distribute_rent( slot_ctx );
  fd_runtime_run_incinerator( slot_ctx );

  FD_LOG_DEBUG(( "fd_runtime_freeze: capitalization %ld ", slot_ctx->slot_bank.capitalization));
  slot_ctx->slot_bank.collected_rent = 0;
}

fd_funk_rec_key_t
fd_runtime_firedancer_bank_key( void ) {
  fd_funk_rec_key_t id;
  fd_memset(&id, 1, sizeof(id));
  id.c[FD_FUNK_REC_KEY_FOOTPRINT - 1] = FD_BLOCK_BANKS_TYPE;

  return id;
}

fd_funk_rec_key_t
fd_runtime_epoch_bank_key( void ) {
  fd_funk_rec_key_t id;
  fd_memset(&id, 1, sizeof(id));
  id.c[FD_FUNK_REC_KEY_FOOTPRINT - 1] = FD_BLOCK_EPOCH_BANK_TYPE;

  return id;
}

fd_funk_rec_key_t
fd_runtime_slot_bank_key( void ) {
  fd_funk_rec_key_t id;
  fd_memset(&id, 1, sizeof(id));
  id.c[FD_FUNK_REC_KEY_FOOTPRINT - 1] = FD_BLOCK_SLOT_BANK_TYPE;

  return id;
}

int
fd_runtime_save_epoch_bank( fd_exec_slot_ctx_t * slot_ctx ) {
  ulong sz = fd_epoch_bank_size(&slot_ctx->epoch_ctx->epoch_bank);
  fd_funk_rec_key_t id = fd_runtime_epoch_bank_key();
  int opt_err = 0;
  fd_funk_rec_t *rec = fd_funk_rec_write_prepare(slot_ctx->acc_mgr->funk, slot_ctx->funk_txn, &id, sz, 1, NULL, &opt_err);
  if (NULL == rec)
  {
    FD_LOG_WARNING(("fd_runtime_save_banks failed: %s", fd_funk_strerror(opt_err)));
    return opt_err;
  }

  uchar *buf = fd_funk_val(rec, fd_funk_wksp(slot_ctx->acc_mgr->funk));
  fd_bincode_encode_ctx_t ctx = {
      .data = buf,
      .dataend = buf + sz,
  };
  if (FD_UNLIKELY(fd_epoch_bank_encode(&slot_ctx->epoch_ctx->epoch_bank, &ctx) != FD_BINCODE_SUCCESS))
  {
    FD_LOG_WARNING(("fd_runtime_save_banks: fd_firedancer_banks_encode failed"));
    return -1;
  }

  FD_LOG_DEBUG(("epoch frozen, slot=%d bank_hash=%32J poh_hash=%32J", slot_ctx->slot_bank.slot, slot_ctx->slot_bank.banks_hash.hash, slot_ctx->slot_bank.poh.hash));

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int fd_runtime_save_slot_bank(fd_exec_slot_ctx_t *slot_ctx)
{
  ulong sz = fd_slot_bank_size(&slot_ctx->slot_bank);

  fd_funk_rec_key_t id = fd_runtime_slot_bank_key();
  int opt_err = 0;
  fd_funk_rec_t *rec = fd_funk_rec_write_prepare(slot_ctx->acc_mgr->funk, slot_ctx->funk_txn, &id, sz, 1, NULL, &opt_err);
  if (NULL == rec)
  {
    FD_LOG_WARNING(("fd_runtime_save_banks failed: %s", fd_funk_strerror(opt_err)));
    return opt_err;
  }

  uchar *buf = fd_funk_val(rec, fd_funk_wksp(slot_ctx->acc_mgr->funk));
  fd_bincode_encode_ctx_t ctx = {
      .data = buf,
      .dataend = buf + sz,
  };
  if (FD_UNLIKELY(fd_slot_bank_encode(&slot_ctx->slot_bank, &ctx) != FD_BINCODE_SUCCESS))
  {
    FD_LOG_WARNING(("fd_runtime_save_banks: fd_firedancer_banks_encode failed"));
    return -1;
  }

  // FD_LOG_DEBUG(("slot frozen, slot=%d bank_hash=%32J poh_hash=%32J", slot_ctx->slot_bank.slot, slot_ctx->slot_bank.banks_hash.hash, slot_ctx->slot_bank.poh.hash));
  slot_ctx->slot_bank.block_height += 1UL;

  // Update blockstore
  fd_blockstore_block_height_update( slot_ctx->blockstore,
                            slot_ctx->slot_bank.slot,
                            slot_ctx->slot_bank.block_height );

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

static int
fd_global_import_stakes(fd_exec_slot_ctx_t *slot_ctx, fd_solana_manifest_t *manifest) {
  // ulong epoch = fd_slot_to_epoch( &slot_ctx->slot_bank.epoch_schedule, slot_ctx->slot_bank.slot, NULL );
  // fd_epoch_stakes_t const * stakes = NULL;
  // fd_epoch_epoch_stakes_pair_t const * epochs = manifest->bank.epoch_stakes;
  // for( ulong i=0; i < manifest->bank.epoch_stakes_len; i++ ) {
  //   if( epochs[ i ].key==epoch ) {
  //     stakes = &epochs[i].value;
  //     break;
  //   }
  // }

  ulong raw_stakes_sz = fd_stakes_size(&manifest->bank.stakes);
  void *raw_stakes = fd_valloc_malloc(slot_ctx->valloc, 1UL, raw_stakes_sz);
  fd_memset(raw_stakes, 0, raw_stakes_sz);

  fd_bincode_encode_ctx_t encode_ctx = {
      .data = raw_stakes,
      .dataend = (void *)((ulong)raw_stakes + raw_stakes_sz)};
  if (FD_UNLIKELY(0 != fd_stakes_encode(&manifest->bank.stakes, &encode_ctx)))
  {
    FD_LOG_ERR(("fd_stakes_encode failed"));
  }

  fd_bincode_decode_ctx_t decode_ctx = {
      .data = raw_stakes,
      .dataend = (void const *)((ulong)raw_stakes + raw_stakes_sz),
      /* TODO: Make this a instruction-scoped allocator */
      .valloc = slot_ctx->valloc,
  };
  if (FD_UNLIKELY(0 != fd_stakes_decode(&slot_ctx->epoch_ctx->epoch_bank.stakes, &decode_ctx)))
  {
    FD_LOG_ERR(("fd_stakes_decode failed"));
  }

  fd_vote_accounts_pair_t_mapnode_t const *vote_accounts_pool = slot_ctx->epoch_ctx->epoch_bank.stakes.vote_accounts.vote_accounts_pool;
  fd_vote_accounts_pair_t_mapnode_t const *vote_accounts_root = slot_ctx->epoch_ctx->epoch_bank.stakes.vote_accounts.vote_accounts_root;

  for (fd_vote_accounts_pair_t_mapnode_t const *n = fd_vote_accounts_pair_t_map_minimum_const(vote_accounts_pool, vote_accounts_root);
       n;
       n = fd_vote_accounts_pair_t_map_successor_const(vote_accounts_pool, n))
  {
    /* Deserialize content */
    fd_bincode_decode_ctx_t vote_state_decode_ctx = {
        .data = n->elem.value.data,
        .dataend = (void const *)((ulong)n->elem.value.data + n->elem.value.data_len),
        /* TODO: Make this a instruction-scoped allocator */
        .valloc = slot_ctx->valloc,
    };

    fd_vote_state_versioned_t vote_state_versioned;
    if (FD_UNLIKELY(0 != fd_vote_state_versioned_decode(&vote_state_versioned, &vote_state_decode_ctx))) {
      FD_LOG_ERR(("fd_vote_state_versioned_decode failed"));
    }

    fd_vote_block_timestamp_t vote_state_timestamp;
    switch (vote_state_versioned.discriminant)
    {
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

    if (vote_state_timestamp.slot != 0 || n->elem.stake != 0) {
      fd_vote_record_timestamp_vote_with_slot(slot_ctx, &n->elem.key, vote_state_timestamp.timestamp, vote_state_timestamp.slot);
    }
  }

  fd_valloc_free(slot_ctx->valloc, raw_stakes);

  return 0;
}

int fd_global_import_solana_manifest(fd_exec_slot_ctx_t *slot_ctx,
                                     fd_solana_manifest_t *manifest)
{
  /* Clean out prior bank */
  fd_bincode_destroy_ctx_t ctx = {.valloc = slot_ctx->valloc};
  fd_slot_bank_t *slot_bank = &slot_ctx->slot_bank;
  fd_slot_bank_destroy(slot_bank, &ctx);
  fd_slot_bank_new(slot_bank);

  fd_epoch_bank_t *epoch_bank = &slot_ctx->epoch_ctx->epoch_bank;
  fd_epoch_bank_destroy(epoch_bank, &ctx);
  fd_epoch_bank_new(epoch_bank);

  fd_deserializable_versioned_bank_t *oldbank = &manifest->bank;
  fd_global_import_stakes(slot_ctx, manifest);

  if (oldbank->blockhash_queue.last_hash)
    fd_memcpy(&slot_bank->poh, oldbank->blockhash_queue.last_hash, FD_SHA256_HASH_SZ);
  slot_bank->slot = oldbank->slot;
  slot_bank->prev_slot = oldbank->parent_slot;
  fd_memcpy(&slot_bank->banks_hash, &oldbank->hash, sizeof(oldbank->hash));
  fd_memcpy(&slot_bank->fee_rate_governor, &oldbank->fee_rate_governor, sizeof(oldbank->fee_rate_governor));
  FD_LOG_WARNING(("POOP: %lu %lu",oldbank->fee_calculator.lamports_per_signature, manifest->lamports_per_signature ));
  slot_bank->lamports_per_signature = oldbank->fee_calculator.lamports_per_signature;
  if (oldbank->hashes_per_tick)
    epoch_bank->hashes_per_tick = *oldbank->hashes_per_tick;
  else
    epoch_bank->hashes_per_tick = 0;
  epoch_bank->ticks_per_slot = oldbank->ticks_per_slot;
  fd_memcpy(&epoch_bank->ns_per_slot, &oldbank->ns_per_slot, sizeof(oldbank->ns_per_slot));
  epoch_bank->genesis_creation_time = oldbank->genesis_creation_time;
  epoch_bank->slots_per_year = oldbank->slots_per_year;
  slot_bank->max_tick_height = oldbank->max_tick_height;
  epoch_bank->inflation = oldbank->inflation;
  epoch_bank->epoch_schedule = oldbank->rent_collector.epoch_schedule;
  epoch_bank->rent = oldbank->rent_collector.rent;

  if (NULL != manifest->epoch_account_hash)
    fd_memcpy(&slot_bank->epoch_account_hash, manifest->epoch_account_hash, FD_SHA256_HASH_SZ);

  slot_bank->collected_rent = oldbank->collected_rent;
  slot_bank->collected_fees = oldbank->collector_fees;
  slot_bank->capitalization = oldbank->capitalization;
  slot_bank->block_height = oldbank->block_height;
  slot_bank->transaction_count = oldbank->transaction_count;

  /* Update last restart slot
     https://github.com/solana-labs/solana/blob/30531d7a5b74f914dde53bfbb0bc2144f2ac92bb/runtime/src/bank.rs#L2152

     oldbank->hard_forks is sorted ascending by slot number.
     To find the last restart slot, take the highest hard fork slot
     number that is less or equal than the current slot number.
     (There might be some hard forks in the future, ignore these) */
  do
  {
    slot_bank->last_restart_slot.slot = 0UL;
    if (FD_UNLIKELY(oldbank->hard_forks.hard_forks_len == 0))
    {
      FD_LOG_WARNING(("Snapshot missing hard forks. What is the correct 'last restart slot' value?"));
      break;
    }

    fd_slot_pair_t const *head = oldbank->hard_forks.hard_forks;
    fd_slot_pair_t const *tail = head + oldbank->hard_forks.hard_forks_len - 1UL;

    for (fd_slot_pair_t const *pair = tail; pair >= head; pair--)
    {
      if (pair->slot <= slot_bank->slot)
      {
        slot_bank->last_restart_slot.slot = pair->slot;
        break;
      }
    }
  } while (0);

  /* Find EpochStakes for next slot */
  {
    FD_SCRATCH_SCOPE_BEGIN
    {

      ulong epoch = fd_slot_to_epoch(&epoch_bank->epoch_schedule, slot_bank->slot, NULL);
      fd_epoch_stakes_t const *stakes = NULL;
      fd_epoch_epoch_stakes_pair_t const *epochs = oldbank->epoch_stakes;
      for (ulong i = 0; i < manifest->bank.epoch_stakes_len; i++)
      {
        if (epochs[i].key == epoch)
        {
          stakes = &epochs[i].value;
          break;
        }
      }

      if (FD_UNLIKELY(!stakes))
        FD_LOG_ERR(("Snapshot missing EpochStakes for epoch %lu", epoch));

      /* TODO Hacky way to copy by serialize/deserialize :( */
      fd_vote_accounts_t const *vaccs = &stakes->stakes.vote_accounts;
      ulong bufsz = fd_vote_accounts_size(vaccs);
      uchar *buf = fd_scratch_alloc(1UL, bufsz);
      fd_bincode_encode_ctx_t encode_ctx = {
          .data = buf,
          .dataend = (void *)((ulong)buf + bufsz)};
      FD_TEST(fd_vote_accounts_encode(vaccs, &encode_ctx) == FD_BINCODE_SUCCESS);
      fd_bincode_decode_ctx_t decode_ctx = {
          .data = buf,
          .dataend = (void const *)((ulong)buf + bufsz),
          .valloc = slot_ctx->valloc,
      };
      FD_TEST(fd_vote_accounts_decode(&slot_bank->epoch_stakes, &decode_ctx) == FD_BINCODE_SUCCESS);
    }
    FD_SCRATCH_SCOPE_END;
  }

  // Stash epoch stakes for next epoch
  {
    FD_SCRATCH_SCOPE_BEGIN
    {
      ulong epoch = fd_slot_to_epoch(&epoch_bank->epoch_schedule, slot_bank->slot, NULL) + 1;
      fd_epoch_stakes_t const *stakes = NULL;
      fd_epoch_epoch_stakes_pair_t const *epochs = oldbank->epoch_stakes;
      for (ulong i = 0; i < manifest->bank.epoch_stakes_len; i++)
      {
        if (epochs[i].key == epoch)
        {
          stakes = &epochs[i].value;
          break;
        }
      }

      if (FD_UNLIKELY(!stakes))
        FD_LOG_ERR(("Snapshot missing EpochStakes for epoch %lu", epoch));

      /* TODO Hacky way to copy by serialize/deserialize :( */
      fd_vote_accounts_t const *vaccs = &stakes->stakes.vote_accounts;
      ulong bufsz = fd_vote_accounts_size(vaccs);
      uchar *buf = fd_scratch_alloc(1UL, bufsz);
      fd_bincode_encode_ctx_t encode_ctx = {
          .data = buf,
          .dataend = (void *)((ulong)buf + bufsz)};
      FD_TEST(fd_vote_accounts_encode(vaccs, &encode_ctx) == FD_BINCODE_SUCCESS);
      fd_bincode_decode_ctx_t decode_ctx = {
          .data = buf,
          .dataend = (void const *)((ulong)buf + bufsz),
          .valloc = slot_ctx->epoch_ctx->valloc,
      };
      FD_TEST(fd_vote_accounts_decode(&epoch_bank->next_epoch_stakes, &decode_ctx) == FD_BINCODE_SUCCESS);
    }
    FD_SCRATCH_SCOPE_END;
  }

  int result = fd_runtime_save_epoch_bank(slot_ctx);
  if (result != FD_EXECUTOR_INSTR_SUCCESS)
  {
    FD_LOG_WARNING(("save epoch bank failed"));
    return result;
  }

  return fd_runtime_save_slot_bank(slot_ctx);
}

/* fd_feature_restore loads a feature from the accounts database and
   updates the bank's feature activation state, given a feature account
   address. */

static void
fd_feature_restore( fd_exec_slot_ctx_t * slot_ctx,
                    fd_feature_id_t const * id,
                    uchar const       acct[ static 32 ] ) {

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
    if (FD_UNLIKELY(decode_err != FD_BINCODE_SUCCESS))
    {
      FD_LOG_ERR(("Failed to decode feature account %32J (%d)", acct, decode_err));
      return;
    }

    if( feature->has_activated_at ) {
      FD_LOG_INFO(( "Feature %32J activated at %lu", acct, feature->activated_at ));
      fd_features_set(&slot_ctx->epoch_ctx->features, id, feature->activated_at);
    } else {
      FD_LOG_DEBUG(( "Feature %32J not activated at %lu", acct, feature->activated_at ));
    }
    /* No need to call destroy, since we are using fd_scratch allocator. */
  } FD_SCRATCH_SCOPE_END;
}

void
fd_features_restore( fd_exec_slot_ctx_t * slot_ctx ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init();
                                   !fd_feature_iter_done( id );
                               id = fd_feature_iter_next( id ) ) {
    fd_feature_restore( slot_ctx, id, id->id.key );
  }
}

static void
fd_feature_activate( fd_exec_slot_ctx_t * slot_ctx,
                    fd_feature_id_t const * id,
                    uchar const       acct[ static 32 ] ) {

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
      FD_LOG_ERR(("Failed to decode feature account %32J (%d)", acct, decode_err));
      return;
    }

    if( feature->has_activated_at ) {
      FD_LOG_INFO(( "feature already activated - acc: %32J, slot: %lu", acct, feature->activated_at ));
      fd_features_set(&slot_ctx->epoch_ctx->features, id, feature->activated_at);
    } else {
      FD_LOG_INFO(( "Feature %32J not activated at %lu, activating", acct, feature->activated_at ));

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
        FD_LOG_ERR(("Failed to encode feature account %32J (%d)", acct, decode_err));
        return;
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

    fd_epoch_schedule_t schedule;
    fd_sysvar_epoch_schedule_read( &schedule, slot_ctx );
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
      void *epoch_leaders_mem = fd_valloc_malloc(slot_ctx->valloc, fd_epoch_leaders_align(), epoch_leaders_footprint);
      if (NULL != slot_ctx->epoch_ctx->leaders)
        fd_valloc_free(slot_ctx->valloc, slot_ctx->epoch_ctx->leaders);
      slot_ctx->epoch_ctx->leaders = fd_epoch_leaders_join(fd_epoch_leaders_new(epoch_leaders_mem, epoch, slot0, slot_cnt, stake_weight_cnt, epoch_weights));
      FD_TEST(slot_ctx->epoch_ctx->leaders);
      /* Derive */
      fd_epoch_leaders_derive(slot_ctx->epoch_ctx->leaders, epoch_weights, epoch);
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
  fd_stakes_t * stakes = &slot_ctx->epoch_ctx->epoch_bank.stakes;

  // TODO: do we need to update the vote accounts as well? Trying to update them breaks things

  // TODO: is this size correct if the same stake account is in both the slot and epoch cache? Is this possible?
  ulong stake_delegations_size = fd_delegation_pair_t_map_size(
    stakes->stake_delegations_pool, stakes->stake_delegations_root );
  stake_delegations_size += fd_stake_accounts_pair_t_map_size(
    slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, slot_ctx->slot_bank.stake_account_keys.stake_accounts_root );

  // Create a new epoch stake delegations cache, which will hold the union of the slot and epoch caches.
  fd_delegation_pair_t_mapnode_t * new_stake_root = NULL;
  fd_delegation_pair_t_mapnode_t * new_stake_pool = fd_delegation_pair_t_map_alloc( slot_ctx->epoch_ctx->valloc, stake_delegations_size );

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
    slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool, slot_ctx->slot_bank.vote_account_keys.vote_accounts_root );
        n;
        n = fd_vote_accounts_pair_t_map_successor( slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool, n ) ) {
    // If the vote account is not in the epoch cache, insert it
    if( fd_vote_accounts_pair_t_map_find( stakes->vote_accounts.vote_accounts_pool, stakes->vote_accounts.vote_accounts_root, n ) == NULL ) {
      fd_vote_accounts_pair_t_mapnode_t * new_entry = fd_vote_accounts_pair_t_map_acquire( stakes->vote_accounts.vote_accounts_pool );

      fd_memcpy(&new_entry->elem.key, &n->elem.key, sizeof(fd_pubkey_t));
      fd_memcpy(&new_entry->elem.stake, &n->elem.stake, sizeof(ulong));
      fd_memcpy(&new_entry->elem.value, &n->elem.value, sizeof(fd_solana_account_t));

      fd_vote_accounts_pair_t_map_insert( stakes->vote_accounts.vote_accounts_pool, &stakes->vote_accounts.vote_accounts_root, new_entry );
    }
  }

  fd_bincode_destroy_ctx_t destroy_slot = {.valloc = slot_ctx->valloc};
  fd_vote_accounts_destroy( &slot_ctx->slot_bank.vote_account_keys, &destroy_slot );
  fd_stake_accounts_destroy(&slot_ctx->slot_bank.stake_account_keys, &destroy_slot );

  fd_bincode_destroy_ctx_t destroy_epoch = {.valloc = slot_ctx->epoch_ctx->valloc};
  for ( fd_delegation_pair_t_mapnode_t* n = fd_delegation_pair_t_map_minimum(stakes->stake_delegations_pool, stakes->stake_delegations_root); n; n = fd_delegation_pair_t_map_successor(stakes->stake_delegations_pool, n) ) {
    fd_delegation_pair_destroy(&n->elem, &destroy_epoch);
  }
  fd_valloc_free( slot_ctx->epoch_ctx->valloc, fd_delegation_pair_t_map_delete(fd_delegation_pair_t_map_leave( stakes->stake_delegations_pool) ) );

  stakes->stake_delegations_root = new_stake_root;
  stakes->stake_delegations_pool = new_stake_pool;

  slot_ctx->slot_bank.stake_account_keys.stake_accounts_root = NULL;
  slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool = fd_stake_accounts_pair_t_map_alloc( slot_ctx->valloc, 100000 );

  slot_ctx->slot_bank.vote_account_keys.vote_accounts_root = NULL;
  slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool = fd_vote_accounts_pair_t_map_alloc( slot_ctx->valloc, 100000 );
}

void fd_update_epoch_stakes( fd_exec_slot_ctx_t * slot_ctx ) {
  FD_SCRATCH_SCOPE_BEGIN
  {
    fd_vote_accounts_t const * vaccs = &slot_ctx->epoch_ctx->epoch_bank.next_epoch_stakes;
    ulong bufsz = fd_vote_accounts_size(vaccs);
    uchar *buf = fd_scratch_alloc(1UL, bufsz);
    fd_bincode_encode_ctx_t encode_ctx = {
        .data = buf,
        .dataend = (void *)((ulong)buf + bufsz)};
    FD_TEST(fd_vote_accounts_encode(vaccs, &encode_ctx) == FD_BINCODE_SUCCESS);
    fd_bincode_decode_ctx_t decode_ctx = {
        .data = buf,
        .dataend = (void const *)((ulong)buf + bufsz),
        .valloc = slot_ctx->valloc,
    };
    fd_bincode_destroy_ctx_t slot_destroy = {.valloc = slot_ctx->valloc};
    fd_vote_accounts_destroy(&slot_ctx->slot_bank.epoch_stakes, &slot_destroy);
    FD_TEST(fd_vote_accounts_decode(&slot_ctx->slot_bank.epoch_stakes, &decode_ctx) == FD_BINCODE_SUCCESS);

    fd_bincode_destroy_ctx_t epoch_destroy = {.valloc = slot_ctx->epoch_ctx->valloc};
    fd_vote_accounts_destroy(&slot_ctx->epoch_ctx->epoch_bank.next_epoch_stakes, &epoch_destroy);

    ulong next_bufsz = fd_vote_accounts_size(&slot_ctx->epoch_ctx->epoch_bank.stakes.vote_accounts);
    uchar * next_buf = fd_scratch_alloc(1UL, next_bufsz);
    fd_bincode_encode_ctx_t next_encode = {
      .data = next_buf,
      .dataend = (void *)((ulong)next_buf + next_bufsz)
    };
    FD_TEST(fd_vote_accounts_encode(&slot_ctx->epoch_ctx->epoch_bank.stakes.vote_accounts, &next_encode) == FD_BINCODE_SUCCESS);
    fd_bincode_decode_ctx_t next_decode = {
      .data = buf,
      .dataend = (void *)((ulong)next_buf + next_bufsz),
      .valloc = slot_ctx->epoch_ctx->valloc
    };
    FD_TEST(fd_vote_accounts_decode(&slot_ctx->epoch_ctx->epoch_bank.next_epoch_stakes, &next_decode) == FD_BINCODE_SUCCESS);

  }
  FD_SCRATCH_SCOPE_END;
}

/* process for the start of a new epoch */
void fd_process_new_epoch(
    fd_exec_slot_ctx_t *slot_ctx,
    ulong parent_epoch)
{
  ulong slot;
  ulong epoch = fd_slot_to_epoch(&slot_ctx->epoch_ctx->epoch_bank.epoch_schedule, slot_ctx->slot_bank.slot, &slot);
  (void)epoch;

  // activate feature flags
  fd_features_restore( slot_ctx );
  fd_features_activate( slot_ctx );

  // Change the speed of the poh clock
  if (FD_FEATURE_ACTIVE(slot_ctx, update_hashes_per_tick6))
    slot_ctx->epoch_ctx->epoch_bank.hashes_per_tick = UPDATED_HASHES_PER_TICK6;
  else if (FD_FEATURE_ACTIVE(slot_ctx, update_hashes_per_tick5))
    slot_ctx->epoch_ctx->epoch_bank.hashes_per_tick = UPDATED_HASHES_PER_TICK5;
  else if (FD_FEATURE_ACTIVE(slot_ctx, update_hashes_per_tick4))
    slot_ctx->epoch_ctx->epoch_bank.hashes_per_tick = UPDATED_HASHES_PER_TICK4;
  else if (FD_FEATURE_ACTIVE(slot_ctx, update_hashes_per_tick3))
    slot_ctx->epoch_ctx->epoch_bank.hashes_per_tick = UPDATED_HASHES_PER_TICK3;
  else if (FD_FEATURE_ACTIVE(slot_ctx, update_hashes_per_tick2))
    slot_ctx->epoch_ctx->epoch_bank.hashes_per_tick = UPDATED_HASHES_PER_TICK2;

  // Add new entry to stakes.stake_history, set appropriate epoch and
  // update vote accounts with warmed up stakes before saving a
  // snapshot of stakes in epoch stakes
  fd_stakes_activate_epoch(slot_ctx, epoch);

  // (We might not implement this part)
  /* Save a snapshot of stakes for use in consensus and stake weighted networking
  let leader_schedule_epoch = self.epoch_schedule.get_leader_schedule_epoch(slot);

  */


      /*
  let (_, update_epoch_stakes_time) = measure!(
           self.update_epoch_stakes(leader_schedule_epoch),
           "update_epoch_stakes",
       ); */
  if ( FD_FEATURE_ACTIVE( slot_ctx, enable_partitioned_epoch_reward ) ) {
    begin_partitioned_rewards( slot_ctx, parent_epoch );
  } else {
    update_rewards( slot_ctx, parent_epoch);
  }

  fd_update_stake_delegations( slot_ctx );

  fd_stake_history_t history;
  fd_sysvar_stake_history_read( &history, slot_ctx, &slot_ctx->valloc );
  refresh_vote_accounts( slot_ctx, &history );
  fd_bincode_destroy_ctx_t ctx;
  ctx.valloc  = slot_ctx->valloc;
  fd_stake_history_destroy( &history, &ctx );

  fd_calculate_epoch_accounts_hash_values( slot_ctx );
  FD_LOG_WARNING(("Leader schedule epoch %lu", fd_slot_to_leader_schedule_epoch( &slot_ctx->epoch_ctx->epoch_bank.epoch_schedule, slot_ctx->slot_bank.slot)));
  fd_update_epoch_stakes( slot_ctx );

  fd_runtime_update_leaders(slot_ctx, slot_ctx->slot_bank.slot);
}

void
fd_runtime_recover_banks( fd_exec_slot_ctx_t * slot_ctx, int delete_first ) {
  fd_funk_t * funk = slot_ctx->acc_mgr->funk;
  fd_funk_txn_t * txn = slot_ctx->funk_txn;

  {
    if ( delete_first ) {
      fd_bincode_destroy_ctx_t ctx;
      ctx.valloc  = slot_ctx->valloc;
      fd_epoch_bank_destroy(&slot_ctx->epoch_ctx->epoch_bank, &ctx);
    }
    fd_funk_rec_key_t id = fd_runtime_epoch_bank_key();
    fd_funk_rec_t const * rec = fd_funk_rec_query_global(funk, txn, &id);
    if ( rec == NULL )
      __asm__("int $3");
      // FD_LOG_ERR(("failed to read banks record"));
    void * val = fd_funk_val( rec, fd_funk_wksp(funk) );
    fd_bincode_decode_ctx_t ctx;
    ctx.data = val;
    ctx.dataend = (uchar*)val + fd_funk_val_sz( rec );
    ctx.valloc  = slot_ctx->valloc;
    FD_TEST( fd_epoch_bank_decode(&slot_ctx->epoch_ctx->epoch_bank, &ctx )==FD_BINCODE_SUCCESS );

    FD_LOG_NOTICE(( "recovered epoch_bank" ));
  }

  {
    if ( delete_first ) {
      fd_bincode_destroy_ctx_t ctx;
      ctx.valloc  = slot_ctx->valloc;
      fd_slot_bank_destroy(&slot_ctx->slot_bank, &ctx);
    }
    fd_funk_rec_key_t id = fd_runtime_slot_bank_key();
    fd_funk_rec_t const * rec = fd_funk_rec_query_global(funk, txn, &id);
    if ( rec == NULL )
      FD_LOG_ERR(("failed to read banks record"));
    void * val = fd_funk_val( rec, fd_funk_wksp(funk) );
    fd_bincode_decode_ctx_t ctx;
    ctx.data = val;
    ctx.dataend = (uchar*)val + fd_funk_val_sz( rec );
    ctx.valloc  = slot_ctx->valloc;
    FD_TEST( fd_slot_bank_decode(&slot_ctx->slot_bank, &ctx )==FD_BINCODE_SUCCESS );

    FD_LOG_NOTICE(( "recovered slot_bank for slot=%ld banks_hash=%32J poh_hash %32J lthash %32J",
                    (long)slot_ctx->slot_bank.slot,
                    slot_ctx->slot_bank.banks_hash.hash,
                    slot_ctx->slot_bank.poh.hash,
                    slot_ctx->slot_bank.lthash ));

    slot_ctx->slot_bank.collected_fees = 0;
    slot_ctx->slot_bank.collected_rent = 0;
  }
}

void
fd_runtime_delete_banks( fd_exec_slot_ctx_t * slot_ctx ) {
  {
    fd_bincode_destroy_ctx_t ctx;
    ctx.valloc  = slot_ctx->valloc;
    fd_epoch_bank_destroy(&slot_ctx->epoch_ctx->epoch_bank, &ctx);
  }

  {
    fd_bincode_destroy_ctx_t ctx;
    ctx.valloc  = slot_ctx->valloc;
    fd_slot_bank_destroy(&slot_ctx->slot_bank, &ctx);
  }
}

ulong
fd_runtime_ctx_align( void ) {
  return alignof( fd_runtime_ctx_t );
}

ulong
fd_runtime_ctx_footprint( void ) {
  return sizeof( fd_runtime_ctx_t );
}

void *
fd_runtime_ctx_new( void * shmem ) {
  fd_runtime_ctx_t * replay_state = (fd_runtime_ctx_t *)shmem;

  if( FD_UNLIKELY( !replay_state ) ) {
    FD_LOG_WARNING( ( "NULL replay_state" ) );
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)replay_state, fd_runtime_ctx_align() ) ) ) {
    FD_LOG_WARNING( ( "misaligned replay_state" ) );
    return NULL;
  }

  return (void *)replay_state;
}

/* fd_runtime_ctx_join returns the local join to the wksp backing the funk.
   The lifetime of the returned pointer is at least as long as the
   lifetime of the local join.  Assumes funk is a current local join. */

fd_runtime_ctx_t *
fd_runtime_ctx_join( void * state ) {
  return (fd_runtime_ctx_t *)state;
}

/* fd_runtime_ctx_leave leaves an existing join.  Returns the underlying
   shfunk on success and NULL on failure.  (logs details). */

void *
fd_runtime_ctx_leave( fd_runtime_ctx_t * state ) {
  return state;
}

/* fd_runtime_ctx_delete unformats a wksp allocation used as a replay_state */
void *
fd_runtime_ctx_delete( void * state ) {
  return state;
}

int
fd_runtime_replay( fd_runtime_ctx_t * state, fd_runtime_args_t * args ) {
  ulong r = fd_funk_txn_cancel_all( state->slot_ctx->acc_mgr->funk, 1 );
  FD_LOG_INFO( ( "Cancelled old transactions %lu", r ) );

  fd_features_restore( state->slot_ctx );

  if( state->slot_ctx->blockstore->max < args->end_slot )
    args->end_slot = state->slot_ctx->blockstore->max;
  // FD_LOG_WARNING(("Failing here"))
  fd_runtime_update_leaders( state->slot_ctx, state->slot_ctx->slot_bank.slot );

  fd_calculate_epoch_accounts_hash_values( state->slot_ctx );

  long              replay_time = -fd_log_wallclock();
  ulong             txn_cnt     = 0;
  ulong             slot_cnt    = 0;
  fd_blockstore_t * blockstore  = state->slot_ctx->blockstore;

  ulong prev_slot = state->slot_ctx->slot_bank.slot;
  for( ulong slot = state->slot_ctx->slot_bank.slot + 1; slot <= args->end_slot; ++slot ) {
    state->slot_ctx->slot_bank.prev_slot = prev_slot;
    state->slot_ctx->slot_bank.slot      = slot;

    FD_LOG_DEBUG( ( "reading slot %ld", slot ) );

    fd_blockstore_start_read( blockstore );
    fd_block_t * blk = fd_blockstore_block_query( blockstore, slot );
    if( blk == NULL ) {
      FD_LOG_WARNING( ( "failed to read slot %ld", slot ) );
      fd_blockstore_end_read( blockstore );
      continue;
    }
    uchar * val = fd_blockstore_block_data_laddr( blockstore, blk );
    ulong   sz  = blk->sz;
    fd_blockstore_end_read( blockstore );

    ulong blk_txn_cnt = 0;
    FD_TEST( fd_runtime_block_eval_tpool( state->slot_ctx,
                                          state->capture_ctx,
                                          val,
                                          sz,
                                          state->tpool,
                                          state->max_workers,
                                          1,
                                          &blk_txn_cnt ) == FD_RUNTIME_EXECUTE_SUCCESS );
    txn_cnt += blk_txn_cnt;
    slot_cnt++;

    fd_blockstore_start_read( blockstore );
    fd_hash_t const * expected = fd_blockstore_block_hash_query( blockstore, slot );
    if( FD_UNLIKELY( !expected ) ) FD_LOG_ERR( ( "slot %lu is missing its hash", slot ) );
    else if( FD_UNLIKELY( 0 !=
                          memcmp( state->slot_ctx->slot_bank.poh.hash, expected->hash, 32UL ) ) ) {
      FD_LOG_WARNING( ( "PoH hash mismatch! slot=%lu expected=%32J, got=%32J",
                        slot,
                        expected->hash,
                        state->slot_ctx->slot_bank.poh.hash ) );
      if( state->abort_on_mismatch ) {
        //__asm__( "int $3" );
        fd_blockstore_end_read( blockstore );
        return 1;
      }
    }

    expected = fd_blockstore_bank_hash_query( blockstore, slot );
    if( FD_UNLIKELY( !expected ) ) {
      FD_LOG_ERR( ( "slot %lu is missing its bank hash", slot ) );
    } else if( FD_UNLIKELY( 0 != memcmp( state->slot_ctx->slot_bank.banks_hash.hash,
                                         expected->hash,
                                         32UL ) ) ) {
      FD_LOG_WARNING( ( "Bank hash mismatch! slot=%lu expected=%32J, got=%32J",
                        slot,
                        expected->hash,
                        state->slot_ctx->slot_bank.banks_hash.hash ) );
      if( state->abort_on_mismatch ) {
        //__asm__( "int $3" );
        fd_blockstore_end_read( blockstore );
        return 1;
      }
    }
    fd_blockstore_end_read( blockstore );

#if 0
    if (NULL != args->capitalization_file) {
      slot_capitalization_t *c = capitalization_map_query(state->map, slot, NULL);
      if (NULL != c) {
        if (state->slot_ctx->slot_bank.capitalization != c->capitalization)
          FD_LOG_ERR(( "capitalization missmatch!  slot=%lu got=%ld != expected=%ld  (%ld)", slot, state->slot_ctx->slot_bank.capitalization, c->capitalization,  state->slot_ctx->slot_bank.capitalization - c->capitalization  ));
      }
    }
#endif

    prev_slot = slot;
  }

  replay_time += fd_log_wallclock();
  double replay_time_s = (double)replay_time * 1e-9;
  double tps           = (double)txn_cnt / replay_time_s;
  double sec_per_slot  = replay_time_s / (double)slot_cnt;
  FD_LOG_NOTICE(
      ( "replay completed - slots: %lu, elapsed: %6.6f s, txns: %lu, tps: %6.6f, sec/slot: %6.6f",
        slot_cnt,
        replay_time_s,
        txn_cnt,
        tps,
        sec_per_slot ) );

  // fd_funk_txn_publish( state->slot_ctx->acc_mgr->funk, state->slot_ctx->acc_mgr->funk_txn, 1);

  return 0;
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
