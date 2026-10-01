#include "fd_event_internal.h"
#include "../runtime/fd_bank.h"
#include "../runtime/fd_runtime_err.h"
#include "../runtime/fd_executor_err.h"
#include "../log_collector/fd_log_collector_base.h"
#include "../../disco/events/generated/fd_event_internal_gen.h"

/* Staging for the parts of a commit record that the runtime does not
   already hold contiguously: the instruction descriptors and their
   account index lists, the post balances, and the post state of the
   written accounts.  Instruction data and account data stay where the
   runtime holds them and are packed from there, so no large buffer is
   ever copied twice. */

struct event_commit_stage {
  fd_event_internal_commit_trace_t   trace        [ FD_EVENT_INTERNAL_COMMIT_TRACE_MAX       ];
  uchar                              accts        [ FD_EVENT_INTERNAL_COMMIT_TRACE_ACCTS_MAX ];
  ulong                              post_lamports[ FD_EVENT_INTERNAL_COMMIT_KEYS_MAX        ];
  fd_event_internal_commit_touched_t touched      [ FD_EVENT_INTERNAL_COMMIT_TOUCHED_MAX      ];
};

typedef struct event_commit_stage event_commit_stage_t;

/* A trace entry names the accounts of its instruction by their index
   in the transaction's key set, which is one byte per account. */

FD_STATIC_ASSERT( FD_TXN_ACCT_ADDR_MAX             <=256UL, event_trace_accts_idx );
FD_STATIC_ASSERT( FD_EVENT_INTERNAL_COMMIT_KEYS_MAX<=256UL, event_trace_accts_keys );

/* A record's account writes are ordered against each other by their
   position in the record, which the write version holds in 8 bits. */

FD_STATIC_ASSERT( FD_EVENT_INTERNAL_COMMIT_TOUCHED_MAX-1UL<=FD_EVENT_INTERNAL_WRITE_SUB_MAX,
                  event_commit_touched_sub );
FD_STATIC_ASSERT( FD_EVENT_INTERNAL_RUNTIME_WRITE_TOUCHED_MAX-1UL<=FD_EVENT_INTERNAL_WRITE_SUB_MAX,
                  event_write_touched_sub );

static FD_TL event_commit_stage_t event_commit_stage;

/* The phase the runtime writes of this thread belong to. */

static FD_TL int   event_write_phase;
static FD_TL ulong event_write_seq;      /* counts the writes of (bank, phase) */
static FD_TL ulong event_write_bank_seq; /* the bank write_seq counts within */

static void
event_account_write_emit( fd_bank_t const * bank,
                          int               phase,
                          ulong             write_seq,
                          ulong             commit_index_in_slot,
                          uint              touched_idx,
                          uchar const *     signature,
                          uchar const *     pubkey,
                          uchar const *     owner,
                          ulong             lamports,
                          int               executable,
                          uchar const *     data,
                          ulong             data_sz,
                          int               with_accounts );

void
fd_event_internal_write_phase( int phase ) {
  event_write_phase    = phase;
  event_write_seq      = 0UL;
  event_write_bank_seq = 0UL;
}

/* event_cost_units is the cost the cost tracker charges the block for
   the transaction.
   https://github.com/anza-xyz/agave/blob/v2.2.0/cost-model/src/transaction_cost.rs#L164-L171 */

static ulong
event_cost_units( fd_txn_out_t const * txn_out ) {
  fd_usage_cost_details_t const * c = &txn_out->details.txn_cost.transaction;
  return (ulong)c->signature_cost + (ulong)c->write_lock_cost + (ulong)c->data_bytes_cost +
         (ulong)c->programs_execution_cost + (ulong)c->loaded_accounts_data_size_cost;
}

void
fd_event_internal_commit_emit( fd_runtime_t const * runtime,
                               fd_bank_t const *    bank,
                               fd_txn_in_t const *  txn_in,
                               fd_txn_out_t const * txn_out,
                               int                  with_accounts ) {
  if( FD_LIKELY( !fd_event_internal_tl ) ) return;
  if( FD_UNLIKELY( !txn_in || !txn_in->txn || !bank ) ) return;

  event_commit_stage_t * stage = &event_commit_stage;

  fd_txn_t const * txn_d   = TXN( txn_in->txn );
  uchar const *    payload = (uchar const *)txn_in->txn->payload;

  fd_event_internal_commit_t ev[1];
  fd_memset( ev, 0, sizeof(fd_event_internal_commit_t) );

  ev->bank_seq             = bank->bank_seq;
  ev->slot                 = bank->f.slot;
  ev->index_in_slot        = txn_in->index_in_slot;
  ev->commit_index_in_slot = fd_ulong_min( txn_out->details.commit_index_in_slot,
                                           FD_EVENT_INTERNAL_WRITE_INDEX_MAX );
  ev->is_leader            = !!bank->is_leader;
  ev->is_simple_vote       = !!txn_out->details.is_simple_vote;
  ev->is_fees_only         = !!txn_out->err.is_fees_only;
  fd_memcpy( ev->signature, txn_out->details.signature.uc, 64UL );

  int is_instr_err = txn_out->err.txn_err==FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR;
  ev->txn_err              = (long)txn_out->err.txn_err;
  ev->exec_err             = is_instr_err ? (long)txn_out->err.exec_err      : 0L;
  ev->exec_err_kind        = is_instr_err ? (long)txn_out->err.exec_err_kind : 0L;
  ev->exec_err_idx         = is_instr_err ? txn_out->err.exec_err_idx : UINT_MAX;
  ev->custom_err           = ( is_instr_err && txn_out->err.exec_err==FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR )
                               ? txn_out->err.custom_err : UINT_MAX;
  ev->rent_err_account_idx = txn_out->err.txn_err==FD_RUNTIME_TXN_ERR_INSUFFICIENT_FUNDS_FOR_RENT
                               ? txn_out->err.rent_err_account_idx : UINT_MAX;

  fd_compute_budget_details_t const * cb = &txn_out->details.compute_budget;
  ev->execution_fee          = txn_out->details.execution_fee;
  ev->priority_fee           = txn_out->details.priority_fee;
  ev->compute_unit_limit     = cb->compute_unit_limit;
  ev->compute_units_consumed = cb->compute_unit_limit>cb->compute_meter
                                 ? cb->compute_unit_limit-cb->compute_meter : 0UL;
  ev->cost_units             = event_cost_units( txn_out );

  ev->payload_cnt       = fd_ulong_min( txn_in->txn->payload_sz, FD_EVENT_INTERNAL_COMMIT_PAYLOAD_MAX );
  ev->acct_addr_cnt     = txn_d->acct_addr_cnt;
  ev->adtl_writable_cnt = txn_d->addr_table_adtl_writable_cnt;

  ulong acct_cnt        = fd_ulong_min( txn_out->accounts.cnt, FD_EVENT_INTERNAL_COMMIT_KEYS_MAX );
  ev->keys_cnt          = acct_cnt;
  ev->pre_lamports_cnt  = acct_cnt;
  ev->post_lamports_cnt = acct_cnt;
  ev->is_writable_cnt   = acct_cnt;
  for( ulong i=0UL; i<acct_cnt; i++ ) {
    stage->post_lamports[ i ] = fd_event_internal_post_lamports( txn_out, i );
  }

  fd_log_collector_t const * log = runtime->log.log_collector;
  if( FD_LIKELY( log && !log->disabled ) ) {
    ev->logs_cnt       = fd_ulong_min( (ulong)log->buf_sz, FD_EVENT_INTERNAL_COMMIT_LOGS_MAX );
    ev->logs_truncated = !!log->warn;
  }

  /* The instruction trace is still the one this transaction produced:
     the runtime resets it when the next transaction starts. */
  ulong trace_cnt = fd_ulong_min( runtime->instr.trace_length, FD_EVENT_INTERNAL_COMMIT_TRACE_MAX );
  ulong accts_cnt = 0UL;
  ulong instr_sz  = 0UL;
  for( ulong i=0UL; i<trace_cnt; i++ ) {
    fd_instr_info_t const *            instr = &runtime->instr.trace[ i ];
    fd_event_internal_commit_trace_t * t     = &stage->trace[ i ];

    ulong cnt = fd_ulong_min( (ulong)instr->acct_cnt, FD_EVENT_INTERNAL_COMMIT_TRACE_ACCTS_MAX-accts_cnt );
    t->program_id_idx = (uint)instr->program_id;
    t->stack_height   = (uint)instr->stack_height;
    t->acct_cnt       = (uint)cnt;
    t->acct_off       = (uint)accts_cnt;
    t->data_off       = (uint)instr_sz;
    t->data_sz        = (uint)instr->data_sz;

    /* An account index of a transaction is below MAX_TX_ACCOUNT_LOCKS. */
    for( ulong j=0UL; j<cnt; j++ ) stage->accts[ accts_cnt+j ] = (uchar)instr->accounts[ j ].index_in_transaction;
    accts_cnt += cnt;

    /* Each instruction's data is packed at an 8 byte boundary, because
       it goes on the wire as its own piece. */
    instr_sz += fd_ulong_align_up( (ulong)instr->data_sz, 8UL );
  }
  ev->trace_cnt       = trace_cnt;
  ev->trace_accts_cnt = accts_cnt;
  ev->trace_data_cnt  = instr_sz;

  fd_memcpy( ev->return_data_program_id, txn_out->details.return_data.program_id.uc, 32UL );
  ev->return_data_cnt = fd_ulong_min( txn_out->details.return_data.len, FD_EVENT_INTERNAL_COMMIT_RETURN_DATA_MAX );

  /* The accounts the transaction wrote are the ones it marked for
     commit.  In a bundle an account is committed by its last writable
     user, so no two records of one bundle report the same account. */
  /* The accounts the transaction wrote are the ones it marked for
     commit.  In a bundle an account is committed by its last writable
     user, so no two records of one bundle report the same account.
     The record names them; what each holds follows in one account
     record per entry, in this order. */
  ulong touched_cnt = 0UL;
  if( FD_LIKELY( with_accounts ) ) {
    for( ulong i=0UL; i<acct_cnt; i++ ) {
      fd_acc_t const * acc = txn_out->accounts.account[ i ];
      if( FD_UNLIKELY( !acc || !acc->commit || !txn_out->accounts.is_writable[ i ] ) ) continue;

      fd_event_internal_commit_touched_t * t = &stage->touched[ touched_cnt ];
      t->key_idx    = (uint)i;
      t->executable = !!acc->executable;
      t->lamports   = acc->lamports;
      t->data_sz    = acc->data_len;
      fd_memcpy( t->owner, acc->owner, 32UL );
      touched_cnt++;
    }
    ev->touched_cnt       = touched_cnt;
    ev->accounts_included = 1;
  }

  fd_event_internal_commit_parts_t parts = {
    .prefix        = ev,
    .payload       = payload,
    .keys          = (uchar const (*)[ 32UL ])txn_out->accounts.keys,
    .pre_lamports  = txn_out->accounts.starting_lamports,
    .post_lamports = stage->post_lamports,
    .is_writable   = txn_out->accounts.is_writable,
    .logs          = log ? log->buf : NULL,
    .trace         = stage->trace,
    .trace_accts   = stage->accts,
    .trace_data    = NULL, /* packed per instruction below */
    .return_data   = txn_out->details.return_data.data,
    .touched       = stage->touched
  };

  fd_event_report_iov_t iov[ FD_EVENT_INTERNAL_COMMIT_IOV_MAX +
                             2UL*FD_EVENT_INTERNAL_COMMIT_TRACE_MAX ];
  iov[ 0 ].base = (void const *)ev;
  iov[ 0 ].sz   = FD_EVENT_INTERNAL_COMMIT_PREFIX_SZ;
  ulong iov_cnt = fd_event_internal_commit_iov( &parts, iov, 1UL, 0UL, FD_EVENT_INTERNAL_COMMIT_ARR_TRACE_DATA );

  for( ulong i=0UL; i<trace_cnt; i++ ) {
    ulong sz = (ulong)stage->trace[ i ].data_sz;
    if( FD_UNLIKELY( !sz ) ) continue;
    ulong pad = fd_ulong_align_up( sz, 8UL )-sz;
    iov[ iov_cnt   ].base = (void const *)runtime->instr.trace[ i ].data;
    iov[ iov_cnt++ ].sz   = sz;
    if( FD_UNLIKELY( pad ) ) {
      iov[ iov_cnt   ].base = fd_event_internal_pad();
      iov[ iov_cnt++ ].sz   = pad;
    }
  }

  iov_cnt = fd_event_internal_commit_iov( &parts, iov, iov_cnt,
                                          FD_EVENT_INTERNAL_COMMIT_ARR_TRACE_DATA+1UL,
                                          FD_EVENT_INTERNAL_COMMIT_ARR_CNT );

  fd_event_report_chunked_( FD_EVENT_INTERNAL_COMMIT_ID, iov, iov_cnt );

  /* One account record per written account, right behind the commit
     record on the same link.  A closed account travels as the
     transaction left it. */
  for( ulong i=0UL; i<touched_cnt; i++ ) {
    fd_event_internal_commit_touched_t const * t = &stage->touched[ i ];
    fd_acc_t const * acc = txn_out->accounts.account[ t->key_idx ];
    event_account_write_emit( bank, 1, 0UL, ev->commit_index_in_slot, (uint)i, ev->signature,
                              txn_out->accounts.keys[ t->key_idx ].uc, acc->owner, acc->lamports,
                              !!acc->executable, acc->data, acc->data_len, with_accounts );
  }
}

/* event_account_write_emit reports the post state of one account.  A
   transaction's write (phase 1) names its transaction and its position
   in that transaction's touched list; a runtime write names its order
   among the runtime writes of the bank and phase. */

static void
event_account_write_emit( fd_bank_t const * bank,
                          int               phase,
                          ulong             write_seq,
                          ulong             commit_index_in_slot,
                          uint              touched_idx,
                          uchar const *     signature,
                          uchar const *     pubkey,
                          uchar const *     owner,
                          ulong             lamports,
                          int               executable,
                          uchar const *     data,
                          ulong             data_sz,
                          int               with_accounts ) {
  if( FD_UNLIKELY( data_sz>FD_EVENT_INTERNAL_RUNTIME_WRITE_ACCOUNT_DATA_MAX ) ) return;

  fd_event_internal_runtime_write_t ev[1];
  fd_memset( ev, 0, sizeof(fd_event_internal_runtime_write_t) );

  ev->bank_seq             = bank->bank_seq;
  ev->slot                 = bank->f.slot;
  ev->phase                = (uint)phase;
  if( signature ) fd_memcpy( ev->signature, signature, 64UL );
  ev->commit_index_in_slot = commit_index_in_slot;
  ev->touched_idx          = touched_idx;
  ev->is_leader            = !!bank->is_leader;
  ev->accounts_included    = !!with_accounts;
  ev->write_seq            = fd_ulong_min( write_seq, FD_EVENT_INTERNAL_WRITE_INDEX_MAX );
  ev->keys_cnt             = 1UL;
  ev->touched_cnt       = 1UL;
  ev->account_data_cnt  = with_accounts ? data_sz : 0UL;

  uchar keys[ 1 ][ 32 ];
  fd_memcpy( keys[ 0 ], pubkey, 32UL );

  fd_event_internal_runtime_write_touched_t touched[1];
  touched->key_idx    = 0U;
  touched->executable = !!executable;
  touched->lamports   = lamports;
  touched->data_off   = 0UL;
  touched->data_sz    = ev->account_data_cnt;
  fd_memcpy( touched->owner, owner, 32UL );

  fd_event_internal_runtime_write_parts_t parts = {
    .prefix       = ev,
    .keys         = (uchar const (*)[ 32UL ])keys,
    .touched      = touched,
    .account_data = data
  };
  fd_event_report_internal_runtime_write( &parts );
}

void
fd_event_internal_write_emit( fd_bank_t const * bank,
                              uchar const *     pubkey,
                              uchar const *     owner,
                              ulong             lamports,
                              int               executable,
                              uchar const *     data,
                              ulong             data_sz,
                              int               with_accounts ) {
  if( FD_LIKELY( !fd_event_internal_tl ) ) return;
  if( FD_UNLIKELY( !bank ) ) return;

  /* A closed account reports no data. */
  if( FD_UNLIKELY( !lamports ) ) {
    data_sz    = 0UL;
    executable = 0;
  }

  if( FD_UNLIKELY( bank->bank_seq!=event_write_bank_seq ) ) {
    event_write_bank_seq = bank->bank_seq;
    event_write_seq      = 0UL;
  }
  ulong write_seq = event_write_seq++;

  event_account_write_emit( bank, event_write_phase, write_seq, 0UL, 0U, NULL,
                            pubkey, owner, lamports, executable, data, data_sz, with_accounts );
}
