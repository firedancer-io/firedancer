#include "fd_event_runtime.h"
#include "../../disco/events/fd_event_report.h"

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
