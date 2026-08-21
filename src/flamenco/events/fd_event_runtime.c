#include "fd_event_runtime.h"
#include "../../disco/events/fd_event_report.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/sysvar/fd_sysvar_last_restart_slot.h"
#include "../stakes/fd_stakes.h"
#include "../../ballet/blake3/fd_blake3.h"

void
fd_event_runtime_txn_emit( fd_txn_in_t  const * txn_in,
                           fd_txn_out_t const * txn_out,
                           fd_bank_t    const * bank ) {
  if( FD_LIKELY( !fd_event_tl ) ) return;
  if( FD_UNLIKELY( !txn_in->txn || !bank ) ) return;

  fd_event_runtime_txn_t ev = {0};

  /* Identity */
  uchar const *    payload = (uchar const *)txn_in->txn->payload;
  fd_txn_t const * txn_d   = TXN( txn_in->txn );
  fd_memcpy( ev.signature, payload + txn_d->signature_off, 64UL );
  fd_memcpy( ev.blockhash,       txn_out->details.blockhash.uc, 32UL );
  fd_memcpy( ev.fec_merkle_root, txn_in->fec_merkle_root,       32UL );
  if( FD_LIKELY( txn_out->accounts.cnt>0UL ) ) {
    fd_memcpy( ev.fee_payer, txn_out->accounts.keys[ 0 ].uc, 32UL );
  }

  ev.bank_seq             = bank->bank_seq;
  ev.slot                 = bank->f.slot;
  ev.epoch                = bank->f.epoch;
  ev.index_in_slot        = txn_in->index_in_slot;
  ev.commit_index_in_slot = txn_out->err.is_committable ? txn_out->details.commit_index_in_slot : 0UL;

  /* Flags */
  ev.is_simple_vote = !!txn_out->details.is_simple_vote;
  ev.is_bundle      = !!txn_in->bundle.is_bundle;
  ev.is_committable = !!txn_out->err.is_committable;
  ev.is_fees_only   = !!txn_out->err.is_fees_only;

  /* Errors */
  ev.txn_err       = fd_event_txn_err_from_txn_err( txn_out->err.txn_err );
  int is_instr_err = ( txn_out->err.txn_err==FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR );
  ev.exec_err      = is_instr_err ? fd_event_exec_err_from_exec_err          ( txn_out->err.exec_err      ) : FD_EVENT_RUNTIME_TXN_EXEC_ERR_SUCCESS;
  ev.exec_err_kind = is_instr_err ? fd_event_exec_err_kind_from_exec_err_kind( txn_out->err.exec_err_kind ) : FD_EVENT_RUNTIME_TXN_EXEC_ERR_KIND_NONE;
  ev.exec_err_idx  = is_instr_err ? txn_out->err.exec_err_idx : UINT_MAX;
  ev.custom_err    = ( is_instr_err && txn_out->err.exec_err==FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR )
                       ? txn_out->err.custom_err : UINT_MAX;

  /* Compute budget */
  fd_compute_budget_details_t const * cb = &txn_out->details.compute_budget;
  ev.compute_unit_limit              = cb->compute_unit_limit;
  ev.compute_unit_price              = cb->compute_unit_price;
  ev.compute_units_consumed          = (cb->compute_unit_limit > cb->compute_meter)
                                         ? cb->compute_unit_limit - cb->compute_meter : 0UL;
  ev.heap_size                       = cb->heap_size;
  ev.num_builtin_instrs              = cb->num_builtin_instrs;
  ev.num_non_builtin_instrs          = cb->num_non_builtin_instrs;
  ev.loaded_accounts_data_size       = txn_out->details.loaded_accounts_data_size;
  ev.loaded_accounts_data_size_limit = cb->loaded_accounts_data_size_limit;
  ev.accounts_resize_delta           = txn_out->details.accounts_resize_delta;

  /* Fees */
  ev.execution_fee   = txn_out->details.execution_fee;
  ev.priority_fee    = txn_out->details.priority_fee;
  ev.tips            = txn_out->details.tips;
  ev.signature_count = txn_out->details.signature_count;

  /* Cost-tracker (non-vote only) */
  if( txn_out->details.txn_cost.type==FD_TXN_COST_TYPE_TRANSACTION ) {
    fd_usage_cost_details_t const * c = &txn_out->details.txn_cost.transaction;
    ev.cost_signature                    = c->signature_cost;
    ev.cost_write_lock                   = c->write_lock_cost;
    ev.cost_data_bytes                   = c->data_bytes_cost;
    ev.cost_programs_execution           = c->programs_execution_cost;
    ev.cost_loaded_accounts_data_size    = c->loaded_accounts_data_size_cost;
    ev.cost_allocated_accounts_data_size = c->allocated_accounts_data_size;
  }

  /* account_diffs: walk per-txn writable accounts, compare prior vs current */
  ulong diff_cnt = 0UL;
  for( ulong i=0UL; i<txn_out->accounts.cnt; i++ ) {
    if( diff_cnt>=64UL ) break;
    fd_acc_t const * acc = txn_out->accounts.account[ i ];
    if( FD_UNLIKELY( !acc ) ) continue;
    if( !txn_out->accounts.is_writable[ i ] ) continue;

    int changed = ( acc->prior_lamports   != acc->lamports   ) ||
                  ( acc->prior_executable != acc->executable ) ||
                  ( acc->prior_data_len   != acc->data_len   ) ||
                  ( memcmp( acc->prior_owner, acc->owner, 32UL )!=0 );
    if( !changed && acc->prior_data && acc->data &&
        memcmp( acc->prior_data, acc->data, acc->data_len )!=0 ) {
      changed = 1;
    }
    if( !changed ) continue;

    fd_event_runtime_txn_account_diffs_t * d = &ev.account_diffs[ diff_cnt++ ];
    fd_memcpy( d->pubkey,     txn_out->accounts.keys[ i ].uc, 32UL );
    fd_memcpy( d->owner,      acc->owner,                     32UL );
    fd_memcpy( d->prev_owner, acc->prior_owner,               32UL );
    d->lamports      = acc->lamports;
    d->prev_lamports = acc->prior_lamports;
    d->data_sz       = acc->data_len;
    d->prev_data_sz  = acc->prior_data_len;
    d->is_executable   = !!acc->executable;
    d->is_stake_update = !!txn_out->accounts.stake_update[ i ];
    d->is_vote_update  = !!txn_out->accounts.vote_update [ i ];
    d->is_new_vote     = !!txn_out->accounts.new_vote    [ i ];
    d->is_rm_vote      = !!txn_out->accounts.rm_vote     [ i ];
  }
  ev.account_diffs_cnt = diff_cnt;

  /* writable / readonly account lists */
  ulong w_cnt = 0UL, r_cnt = 0UL;
  for( ulong i=0UL; i<txn_out->accounts.cnt; i++ ) {
    fd_acc_t const * acc = txn_out->accounts.account[ i ];
    if( FD_UNLIKELY( !acc ) ) continue;
    if( txn_out->accounts.is_writable[ i ] ) {
      if( w_cnt<64UL ) fd_memcpy( ev.writable_accounts[ w_cnt++ ], txn_out->accounts.keys[ i ].uc, 32UL );
    } else {
      if( r_cnt<64UL ) fd_memcpy( ev.readonly_accounts[ r_cnt++ ], txn_out->accounts.keys[ i ].uc, 32UL );
    }
  }
  ev.writable_accounts_cnt = w_cnt;
  ev.readonly_accounts_cnt = r_cnt;

  /* program_ids: walk top-level instructions, dedupe in first-occurrence order */
  ulong p_cnt = 0UL;
  for( ushort ii=0; ii<txn_d->instr_cnt; ii++ ) {
    if( p_cnt>=64UL ) break;
    uchar pid_idx = txn_d->instr[ ii ].program_id;
    if( (ulong)pid_idx>=txn_out->accounts.cnt ) continue;
    uchar const * pid = txn_out->accounts.keys[ pid_idx ].uc;
    int seen = 0;
    for( ulong j=0UL; j<p_cnt; j++ ) {
      if( memcmp( ev.program_ids[ j ], pid, 32UL )==0 ) { seen = 1; break; }
    }
    if( !seen ) fd_memcpy( ev.program_ids[ p_cnt++ ], pid, 32UL );
  }
  ev.program_ids_cnt = p_cnt;

  fd_event_report_runtime_txn( &ev );
}

void
fd_event_runtime_stake_delegation_emit( fd_txn_in_t      const * txn_in,
                                        fd_bank_t        const * bank,
                                        fd_pubkey_t      const * pubkey,
                                        fd_stake_state_t const * stake_state ) {
  if( FD_LIKELY( !fd_event_tl ) ) return;
  if( FD_UNLIKELY( !txn_in->txn || !bank ) ) return;

  fd_event_runtime_stake_delegation_t ev = {0};

  ev.bank_seq      = bank->bank_seq;
  ev.slot          = bank->f.slot;
  ev.epoch         = bank->f.epoch;
  ev.index_in_slot = txn_in->index_in_slot;

  uchar const *    payload = (uchar const *)txn_in->txn->payload;
  fd_txn_t const * txn_d   = TXN( txn_in->txn );
  fd_memcpy( ev.signature, payload + txn_d->signature_off, 64UL );

  fd_memcpy( ev.stake_account, pubkey->uc, 32UL );

  if( FD_LIKELY( stake_state ) ) {
    ev.kind = FD_EVENT_RUNTIME_STAKE_DELEGATION_KIND_UPSERT;
    fd_memcpy( ev.vote_account, stake_state->stake.stake.delegation.voter_pubkey.uc, 32UL );
    ev.stake              = stake_state->stake.stake.delegation.stake;
    ev.activation_epoch   = stake_state->stake.stake.delegation.activation_epoch;
    ev.deactivation_epoch = stake_state->stake.stake.delegation.deactivation_epoch;
    ev.credits_observed   = stake_state->stake.stake.credits_observed;
  } else {
    ev.kind = FD_EVENT_RUNTIME_STAKE_DELEGATION_KIND_REMOVE;
  }

  fd_event_report_runtime_stake_delegation( &ev );
}

static void
fd_event_runtime_stake_delegation_entry_emit( ulong             bank_seq,
                                              ulong             slot,
                                              ulong             epoch,
                                              int               kind,
                                              uchar const *     stake_account,
                                              uchar const *     vote_account,
                                              ulong             stake,
                                              ulong             activation_epoch,
                                              ulong             deactivation_epoch,
                                              ulong             credits_observed ) {
  if( FD_UNLIKELY( !fd_event_tl ) ) return;

  fd_event_runtime_stake_delegation_t ev = {0};

  ev.bank_seq      = bank_seq;
  ev.slot          = slot;
  ev.epoch         = epoch;
  ev.index_in_slot = ULONG_MAX;
  ev.kind          = kind;

  fd_memcpy( ev.stake_account, stake_account, 32UL );
  fd_memcpy( ev.vote_account,  vote_account,  32UL );
  ev.stake              = stake;
  ev.activation_epoch   = activation_epoch;
  ev.deactivation_epoch = deactivation_epoch;
  ev.credits_observed   = credits_observed;

  fd_event_report_runtime_stake_delegation( &ev );
}

void
fd_event_runtime_stake_delegation_bootup_emit( ulong         slot,
                                               ulong         epoch,
                                               uchar const * stake_account,
                                               uchar const * vote_account,
                                               ulong         stake,
                                               ulong         activation_epoch,
                                               ulong         deactivation_epoch,
                                               ulong         credits_observed ) {
  if( FD_LIKELY( !fd_event_tl ) ) return;
  fd_event_runtime_stake_delegation_entry_emit( 0UL, slot, epoch, FD_EVENT_RUNTIME_STAKE_DELEGATION_KIND_BOOTUP,
                                                stake_account, vote_account, stake,
                                                activation_epoch, deactivation_epoch, credits_observed );
}

void
fd_event_runtime_stake_delegation_payout_emit( fd_bank_t const * bank,
                                               uchar const *     stake_account,
                                               uchar const *     vote_account,
                                               ulong             stake,
                                               ulong             activation_epoch,
                                               ulong             deactivation_epoch,
                                               ulong             credits_observed ) {
  if( FD_LIKELY( !fd_event_tl ) ) return;
  fd_event_runtime_stake_delegation_entry_emit( bank->bank_seq, bank->f.slot, bank->f.epoch, FD_EVENT_RUNTIME_STAKE_DELEGATION_KIND_REWARD,
                                                stake_account, vote_account, stake,
                                                activation_epoch, deactivation_epoch, credits_observed );
}

/* Boundary processing runs single-threaded; pieces of the runtime_epoch event computed 
   at different points are stashed here and emitted together at the end of the boundary. */

static FD_TL struct {
  fd_event_runtime_epoch_stake_history_sysvar_t stake_history;
  fd_event_runtime_epoch_epoch_rewards_sysvar_t epoch_rewards;

  ulong staked_vote_accounts;
  ulong top_votes_eligible;

  ulong vote_cnt;  /* runtime_vote_account rows emitted this boundary */
  ulong min_stake; /* smallest stake among them */

  uchar features[ 16 ][ 32 ];
  ulong feature_cnt;
} fd_event_runtime_epoch_summary;

void
fd_event_runtime_epoch_feature( uchar const * feature_id ) {
  if( FD_LIKELY( !fd_event_tl ) ) return;
  if( FD_UNLIKELY( fd_event_runtime_epoch_summary.feature_cnt>=16UL ) ) return;
  fd_memcpy( fd_event_runtime_epoch_summary.features[ fd_event_runtime_epoch_summary.feature_cnt++ ], feature_id, 32UL );
}

void
fd_event_runtime_epoch_stake_history( fd_stake_history_entry_t const * entry ) {
  if( FD_LIKELY( !fd_event_tl ) ) return;
  fd_event_runtime_epoch_summary.stake_history.epoch        = entry->epoch;
  fd_event_runtime_epoch_summary.stake_history.effective    = entry->effective;
  fd_event_runtime_epoch_summary.stake_history.activating   = entry->activating;
  fd_event_runtime_epoch_summary.stake_history.deactivating = entry->deactivating;
}

void
fd_event_runtime_epoch_rewards( fd_sysvar_epoch_rewards_t const * epoch_rewards ) {
  if( FD_LIKELY( !fd_event_tl ) ) return;
  fd_event_runtime_epoch_summary.epoch_rewards.total_rewards                      = epoch_rewards->total_rewards;
  fd_event_runtime_epoch_summary.epoch_rewards.distributed                        = epoch_rewards->distributed_rewards;
  fd_event_runtime_epoch_summary.epoch_rewards.distribution_starting_block_height = epoch_rewards->distribution_starting_block_height;
  fd_event_runtime_epoch_summary.epoch_rewards.num_partitions                     = epoch_rewards->num_partitions;
  fd_event_runtime_epoch_summary.epoch_rewards.total_points                       = epoch_rewards->total_points.ud;
  fd_memcpy( fd_event_runtime_epoch_summary.epoch_rewards.parent_blockhash, epoch_rewards->parent_blockhash.uc, 32UL );
}

void
fd_event_runtime_epoch_votes( ulong staked_vote_accounts,
                              ulong top_votes_eligible ) {
  if( FD_LIKELY( !fd_event_tl ) ) return;
  fd_event_runtime_epoch_summary.staked_vote_accounts = staked_vote_accounts;
  /* top_votes_eligible is 0 pre-VAT */
  fd_event_runtime_epoch_summary.top_votes_eligible   = top_votes_eligible;
}

void
fd_event_runtime_vote_account_emit( fd_bank_t const *          bank,
                                    uchar const *              pubkey,
                                    uchar const *              node_account,
                                    ulong                      stake,
                                    uint                       commission_bps,
                                    int                        has_commission_t_2,
                                    uint                       commission_t_2_bps,
                                    int                        has_commission_t_3,
                                    uint                       commission_t_3_bps,
                                    uint                       reward_commission_bps,
                                    fd_epoch_credits_t const * epoch_credits ) {
  if( FD_LIKELY( !fd_event_tl ) ) return;

  if( !fd_event_runtime_epoch_summary.vote_cnt || stake<fd_event_runtime_epoch_summary.min_stake ) 
    fd_event_runtime_epoch_summary.min_stake = stake;

  fd_event_runtime_epoch_summary.vote_cnt++;

  fd_event_runtime_vote_account_t ev = {0};

  ev.bank_seq = bank->bank_seq;
  ev.slot     = bank->f.slot;
  ev.epoch    = bank->f.epoch;

  fd_memcpy( ev.pubkey,       pubkey,       32UL );
  fd_memcpy( ev.node_account, node_account, 32UL );

  ev.stake                 = stake;
  ev.commission_bps        = commission_bps;
  ev.has_commission_t_2    = !!has_commission_t_2;
  ev.commission_t_2_bps    = has_commission_t_2 ? commission_t_2_bps : 0U;
  ev.has_commission_t_3    = !!has_commission_t_3;
  ev.commission_t_3_bps    = has_commission_t_3 ? commission_t_3_bps : 0U;
  ev.reward_commission_bps = reward_commission_bps;
  ev.credits               = epoch_credits->cnt ? epoch_credits->base_credits + epoch_credits->credits_delta     [ epoch_credits->cnt-1UL ] : 0UL;
  ev.prev_credits          = epoch_credits->cnt ? epoch_credits->base_credits + epoch_credits->prev_credits_delta[ epoch_credits->cnt-1UL ] : 0UL;
  ev.epoch_credits_cnt     = epoch_credits->cnt;

  fd_event_report_runtime_vote_account( &ev );
}

void
fd_event_runtime_epoch_emit( fd_bank_t const * bank ) {
  if( FD_LIKELY( !fd_event_tl ) ) return;

  fd_event_runtime_epoch_t ev = {0};

  ev.bank_seq    = bank->bank_seq;
  ev.slot        = bank->f.slot;
  ev.parent_slot = bank->f.parent_slot;
  ev.epoch       = bank->f.epoch;

  ev.total_effective_stake    = bank->f.total_effective_stake;
  ev.total_activating_stake   = bank->f.total_activating_stake;
  ev.total_deactivating_stake = bank->f.total_deactivating_stake;
  ev.total_epoch_stake        = bank->f.total_epoch_stake;

  ev.num_staked_vote_accounts = fd_event_runtime_epoch_summary.staked_vote_accounts;
  ev.num_vote_accounts        = fd_event_runtime_epoch_summary.vote_cnt;
  ev.num_top_votes_eligible   = fd_event_runtime_epoch_summary.top_votes_eligible;
  ev.top_votes_min_stake      = fd_event_runtime_epoch_summary.min_stake;

  ev.stake_history_sysvar[0]  = fd_event_runtime_epoch_summary.stake_history;
  ev.stake_history_sysvar_cnt = 1UL;

  ev.epoch_schedule_sysvar[0].slots_per_epoch             = bank->f.epoch_schedule.slots_per_epoch;
  ev.epoch_schedule_sysvar[0].leader_schedule_slot_offset = bank->f.epoch_schedule.leader_schedule_slot_offset;
  ev.epoch_schedule_sysvar[0].warmup                      = !!bank->f.epoch_schedule.warmup;
  ev.epoch_schedule_sysvar[0].first_normal_epoch          = bank->f.epoch_schedule.first_normal_epoch;
  ev.epoch_schedule_sysvar[0].first_normal_slot           = bank->f.epoch_schedule.first_normal_slot;
  ev.epoch_schedule_sysvar_cnt                            = 1UL;

  for( ulong i=0UL; i<fd_event_runtime_epoch_summary.feature_cnt; i++ ) {
    fd_memcpy( ev.feature_activations[ i ], fd_event_runtime_epoch_summary.features[ i ], 32UL );
  }
  ev.feature_activations_cnt = fd_event_runtime_epoch_summary.feature_cnt;

  ev.epoch_rewards_sysvar[0]  = fd_event_runtime_epoch_summary.epoch_rewards;
  ev.epoch_rewards_sysvar_cnt = 1UL;

  fd_event_report_runtime_epoch( &ev );

  fd_memset( &fd_event_runtime_epoch_summary, 0, sizeof(fd_event_runtime_epoch_summary) );
}

void
fd_event_runtime_rooted_emit( fd_bank_t const *                          bank,
                              ulong                                      prev_root_slot,
                              fd_stake_delegations_t const *             stake_delegations,
                              fd_stake_delegations_delta_stats_t const * stake_delegations_delta_stats ) {
  if( FD_LIKELY( !fd_event_tl ) ) return;

  fd_event_runtime_rooted_t ev = {0};

  ev.bank_seq       = bank->bank_seq;
  ev.slot           = bank->f.slot;
  ev.epoch          = bank->f.epoch;
  ev.prev_root_slot = prev_root_slot;

  ev.stake_delegations_upserts = stake_delegations_delta_stats->upserts;
  ev.stake_delegations_removes = stake_delegations_delta_stats->removes;
  ev.stake_delegations_cnt     = fd_stake_delegations_base_cnt( stake_delegations );
  ev.effective_stake           = stake_delegations->effective_stake;
  ev.activating_stake          = stake_delegations->activating_stake;
  ev.deactivating_stake        = stake_delegations->deactivating_stake;

  fd_event_report_runtime_rooted( &ev );
}

void
fd_event_runtime_reward_emit( fd_bank_t const * bank,
                              int               kind,
                              uchar const *     pubkey,
                              uchar const *     owner,
                              ulong             prev_lamports,
                              ulong             lamports,
                              ulong             partition_idx,
                              ulong             credits_observed,
                              ulong             stake ) {
  if( FD_LIKELY( !fd_event_tl ) ) return;

  fd_event_runtime_reward_t ev = {
    .bank_seq         = bank->bank_seq,
    .slot             = bank->f.slot,
    .epoch            = bank->f.epoch,
    .kind             = kind,
    .prev_lamports    = prev_lamports,
    .lamports         = lamports,
    .partition_idx    = partition_idx,
    .credits_observed = credits_observed,
    .stake            = stake,
  };
  fd_memcpy( ev.pubkey, pubkey, 32UL );
  fd_memcpy( ev.owner,  owner,  32UL );
  fd_event_report_runtime_reward( &ev );
}

/* Accumulator for slot-level account diffs, which get staged in the bank
   and emitted to the runtime_block event at block finalize. */

struct fd_event_runtime_account_diff {
  uchar pubkey    [ 32 ];
  uchar owner     [ 32 ];
  uchar prev_owner[ 32 ];
  ulong prev_lamports;
  ulong lamports;
  ulong prev_data_sz;
  ulong data_sz;
  int   executable;
};

typedef struct fd_event_runtime_account_diff fd_event_runtime_account_diff_t;

struct fd_event_runtime_slot_diffs {
  fd_event_runtime_account_diff_t sysvar[ 16UL ]; ulong sysvar_cnt;
  fd_event_runtime_account_diff_t other [ 32UL ]; ulong other_cnt;
};

typedef struct fd_event_runtime_slot_diffs fd_event_runtime_slot_diffs_t;

static void
fd_event_runtime_account_diff_set( fd_event_runtime_account_diff_t * e,
                                   uchar const *                     pubkey,
                                   uchar const *                     prev_owner,
                                   uchar const *                     owner,
                                   ulong                             prev_lamports,
                                   ulong                             lamports,
                                   ulong                             prev_data_sz,
                                   ulong                             data_sz,
                                   int                               executable ) {
  fd_memcpy( e->pubkey,     pubkey,     32UL );
  fd_memcpy( e->owner,      owner,      32UL );
  fd_memcpy( e->prev_owner, prev_owner, 32UL );
  e->prev_lamports = prev_lamports;
  e->lamports      = lamports;
  e->prev_data_sz  = prev_data_sz;
  e->data_sz       = data_sz;
  e->executable    = executable;
}

void
fd_event_runtime_block_account( fd_bank_t *   bank,
                                uchar const * pubkey,
                                uchar const * prev_owner,
                                uchar const * owner,
                                ulong         prev_lamports,
                                ulong         lamports,
                                ulong         prev_data_sz,
                                ulong         data_sz,
                                int           executable ) {
  if( FD_LIKELY( !fd_event_tl ) ) return;

  fd_event_runtime_slot_diffs_t * diffs = fd_type_pun( bank->event_slot_diffs );

  if( FD_UNLIKELY( !memcmp( owner, fd_solana_vote_program_id.uc, 32UL ) ) ) {
    fd_event_runtime_reward_emit( bank, FD_EVENT_RUNTIME_REWARD_KIND_VOTE,
                                  pubkey, owner, prev_lamports, lamports, 0UL, 0UL, 0UL );
    return;
  } 

  fd_event_runtime_account_diff_t * arr; ulong * cnt; ulong cap;
  if( FD_UNLIKELY( !memcmp( owner, fd_sysvar_owner_id.uc, 32UL ) ) ) {
    arr = diffs->sysvar;
    cnt = &diffs->sysvar_cnt;
    cap = 16UL;
  } else {
    arr = diffs->other;
    cnt = &diffs->other_cnt;
    cap = 32UL;
  }

  if( FD_UNLIKELY( *cnt>=cap ) ) return;
  fd_event_runtime_account_diff_set( &arr[ (*cnt)++ ], pubkey, prev_owner, owner, prev_lamports, lamports, prev_data_sz, data_sz, executable );
}

void
fd_event_runtime_block_emit( fd_bank_t const *             bank,
                             uchar const *                 block_id,
                             uchar const *                 parent_block_id,
                             uchar const *                 leader,
                             ulong                         execution_fees,
                             ulong                         priority_fees,
                             ulong                         tips,
                             fd_sol_sysvar_clock_t const * clock,
                             fd_hash_t const *             fec_mrs,
                             ulong                         fec_mr_cnt ) {
  if( FD_LIKELY( !fd_event_tl ) ) return;

  static fd_event_runtime_block_t ev;
  fd_memset( &ev, 0, sizeof(ev) );

  ev.bank_seq     = bank->bank_seq;
  ev.slot         = bank->f.slot;
  ev.parent_slot  = bank->f.parent_slot;
  ev.epoch        = bank->f.epoch;
  ev.block_height = bank->f.block_height;

  fd_memcpy( ev.block_id,        block_id,        32UL );
  fd_memcpy( ev.parent_block_id, parent_block_id, 32UL );
  fd_memcpy( ev.leader,          leader,          32UL );

  fd_memcpy( ev.bank_hash,      bank->f.bank_hash.uc,      32UL );
  fd_memcpy( ev.prev_bank_hash, bank->f.prev_bank_hash.uc, 32UL );
  fd_memcpy( ev.poh_hash,       bank->f.poh.uc,            32UL );

  fd_lthash_value_t const * lthash = fd_bank_lthash_locking_query( (fd_bank_t *)bank );
  fd_blake3_t b3[1];
  fd_blake3_init( b3 );
  fd_blake3_append( b3, lthash->bytes, FD_LTHASH_LEN_BYTES );
  fd_blake3_fini( b3, ev.accounts_lt_hash_checksum );
  fd_bank_lthash_end_locking_query( (fd_bank_t *)bank );

  ev.num_transactions        = bank->f.txn_count;
  ev.num_failed_txns         = bank->f.failed_txn_count;
  ev.num_nonvote_txns        = bank->f.nonvote_txn_count;
  ev.num_nonvote_failed_txns = bank->f.nonvote_failed_txn_count;
  ev.num_signatures          = bank->f.signature_count;
  ev.num_shreds              = bank->f.shred_cnt;
  ev.tick_height             = bank->f.tick_height;

  /* Mirrors fd_runtime_settle_fees for fees burned and leader fee reward. */
  ulong fees_burned    = execution_fees / 2UL;

  ev.execution_fees    = execution_fees;
  ev.priority_fees     = priority_fees;
  ev.tips              = tips;
  ev.fees_burned       = fees_burned;
  ev.leader_fee_reward = fd_ulong_sat_add( priority_fees, execution_fees-fees_burned );

  ev.capitalization           = bank->f.capitalization;
  ev.total_effective_stake    = bank->f.total_effective_stake;
  ev.total_activating_stake   = bank->f.total_activating_stake;
  ev.total_deactivating_stake = bank->f.total_deactivating_stake;
  ev.total_epoch_stake        = bank->f.total_epoch_stake;

  ev.clock_sysvar[0].slot                  = clock->slot;
  ev.clock_sysvar[0].epoch_start_timestamp = clock->epoch_start_timestamp;
  ev.clock_sysvar[0].epoch                 = clock->epoch;
  ev.clock_sysvar[0].leader_schedule_epoch = clock->leader_schedule_epoch;
  ev.clock_sysvar[0].unix_timestamp        = clock->unix_timestamp;
  ev.clock_sysvar_cnt                      = 1UL;

  fd_event_runtime_slot_diffs_t const * diffs = fd_type_pun_const( bank->event_slot_diffs );

  ulong bh_cnt = 0UL;
  fd_blockhash_info_t const * bhq = bank->f.block_hash_queue.d.deque;
  for( fd_blockhash_deq_iter_t iter = fd_blockhash_deq_iter_init_rev( bhq );
       !fd_blockhash_deq_iter_done_rev( bhq, iter ) && bh_cnt<150UL;
       iter = fd_blockhash_deq_iter_prev( bhq, iter ) ) {
    fd_blockhash_info_t const * info = fd_blockhash_deq_iter_ele_const( bhq, iter );
    fd_memcpy( ev.recent_blockhashes_sysvar[ bh_cnt++ ], info->hash.uc, 32UL );
  }
  ev.recent_blockhashes_sysvar_cnt = bh_cnt;

  ev.last_restart_slot_sysvar = fd_sysvar_last_restart_slot_derive( bank );

  for( ulong i=0UL; i<diffs->sysvar_cnt; i++ ) {
    fd_event_runtime_block_sysvar_diffs_t * d = &ev.sysvar_diffs[ i ];
    fd_memcpy( d->pubkey,     diffs->sysvar[ i ].pubkey,     32UL );
    fd_memcpy( d->owner,      diffs->sysvar[ i ].owner,      32UL );
    fd_memcpy( d->prev_owner, diffs->sysvar[ i ].prev_owner, 32UL );
    d->lamports      = diffs->sysvar[ i ].lamports;
    d->prev_lamports = diffs->sysvar[ i ].prev_lamports;
    d->data_sz       = diffs->sysvar[ i ].data_sz;
    d->prev_data_sz  = diffs->sysvar[ i ].prev_data_sz;
    d->is_executable = diffs->sysvar[ i ].executable;
  }
  ev.sysvar_diffs_cnt = diffs->sysvar_cnt;

  for( ulong i=0UL; i<diffs->other_cnt; i++ ) {
    fd_event_runtime_block_other_diffs_t * d = &ev.other_diffs[ i ];
    fd_memcpy( d->pubkey,     diffs->other[ i ].pubkey,     32UL );
    fd_memcpy( d->owner,      diffs->other[ i ].owner,      32UL );
    fd_memcpy( d->prev_owner, diffs->other[ i ].prev_owner, 32UL );
    d->lamports      = diffs->other[ i ].lamports;
    d->prev_lamports = diffs->other[ i ].prev_lamports;
    d->data_sz       = diffs->other[ i ].data_sz;
    d->prev_data_sz  = diffs->other[ i ].prev_data_sz;
    d->is_executable = diffs->other[ i ].executable;
  }
  ev.other_diffs_cnt = diffs->other_cnt;

  ulong fec_cnt = fd_ulong_min( fec_mr_cnt, sizeof(ev.fec_merkle_roots)/sizeof(ev.fec_merkle_roots[0]) );
  for( ulong i=0UL; i<fec_cnt; i++ ) fd_memcpy( ev.fec_merkle_roots[ i ], fec_mrs[ i ].uc, 32UL );
  ev.fec_count            = fec_mr_cnt;
  ev.fec_merkle_roots_cnt = fec_cnt;

  fd_event_report_runtime_block( &ev );
}
