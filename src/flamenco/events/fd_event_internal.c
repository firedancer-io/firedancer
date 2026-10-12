#include "fd_event_internal.h"
#include "../runtime/fd_bank.h"
#include "../runtime/fd_runtime_err.h"
#include "../runtime/fd_executor_err.h"
#include "../log_collector/fd_log_collector_base.h"
#include "../runtime/fd_system_ids.h"
#include "../../disco/events/generated/fd_event_internal_gen.h"

/* Staging for the parts of a commit record that the runtime does not
   already hold contiguously: the instruction descriptors and their
   account index lists, the post balances, and the post state of the
   written accounts.  Instruction data and account data stay where the
   runtime holds them and are packed from there, so no large buffer is
   ever copied twice. */

/* A mint looked up for the token balances of one transaction.  A mint
   outside the transaction is read from the accounts database at most
   once per transaction; only the bytes the validity rules and the
   decimals live in are copied.

   The read never waits inside the accounts database: a mint another
   joiner is committing in place or evicting is reported busy, and the
   read is retried until the other joiner's step is done.  The retry
   count is bounded so that a wedged joiner cannot hold the executor;
   a mint given up on leaves its balances out of the record, so the
   bound is far above the few steps a commit or an eviction takes. */

#define EVENT_MINT_READ_SZ        (166UL)
#define EVENT_MINT_READ_RETRY_MAX (65536UL)

struct event_mint {
  uchar pubkey[ 32UL ];
  uchar owner [ 32UL ];
  ulong data_len;
  int   exists;
  uchar data[ EVENT_MINT_READ_SZ ];
};

typedef struct event_mint event_mint_t;

struct event_commit_stage {
  fd_event_internal_commit_trace_t          trace        [ FD_EVENT_INTERNAL_COMMIT_TRACE_MAX          ];
  uchar                                     accts        [ FD_EVENT_INTERNAL_COMMIT_TRACE_ACCTS_MAX    ];
  ulong                                     post_lamports[ FD_EVENT_INTERNAL_COMMIT_KEYS_MAX           ];
  fd_event_internal_commit_touched_t        touched      [ FD_EVENT_INTERNAL_COMMIT_TOUCHED_MAX        ];
  fd_event_internal_commit_token_balances_t token        [ FD_EVENT_INTERNAL_COMMIT_TOKEN_BALANCES_MAX ];
  event_mint_t                              mint         [ FD_EVENT_INTERNAL_COMMIT_KEYS_MAX           ];
  ulong                                     mint_cnt;
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

/* The epoch rewards staged for the bank being prepared. */

static FD_TL fd_event_internal_reward_rewards_t event_reward_stage[ FD_EVENT_INTERNAL_REWARD_REWARDS_MAX ];
static FD_TL ulong                              event_reward_stage_cnt;

/* Every key of a transaction fits the bitmask of invoked programs. */

FD_STATIC_ASSERT( MAX_TX_ACCOUNT_LOCKS<=64UL, event_invoked_mask );

/* A transaction has at most one token balance entry per key, before
   and after. */

FD_STATIC_ASSERT( 2UL*FD_EVENT_INTERNAL_COMMIT_KEYS_MAX<=FD_EVENT_INTERNAL_COMMIT_TOKEN_BALANCES_MAX,
                  event_token_balances_max );

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
fd_event_internal_reward_flush( fd_bank_t const * bank ) {
  ulong cnt = event_reward_stage_cnt;
  event_reward_stage_cnt = 0UL;
  if( FD_LIKELY( !cnt ) ) return;
  if( FD_UNLIKELY( !fd_event_internal_tl || !bank ) ) return;

  fd_event_internal_reward_t ev[1];
  fd_memset( ev, 0, sizeof(fd_event_internal_reward_t) );
  ev->bank_seq    = bank->bank_seq;
  ev->slot        = bank->f.slot;
  ev->is_leader   = !!bank->is_leader;
  ev->rewards_cnt = cnt;

  fd_event_internal_reward_parts_t parts = { .prefix = ev, .rewards = event_reward_stage };
  fd_event_report_internal_reward( &parts );
}

void
fd_event_internal_reward_add( fd_bank_t const * bank,
                              uint              reward_type,
                              uint              commission_bps,
                              uchar const *     pubkey,
                              ulong             lamports,
                              ulong             post_balance ) {
  if( FD_LIKELY( !fd_event_internal_tl ) ) return;
  if( FD_UNLIKELY( !bank || !fd_bank_dragon_enabled( bank ) ) ) return;

  fd_event_internal_reward_rewards_t * r = &event_reward_stage[ event_reward_stage_cnt++ ];
  r->reward_type    = reward_type;
  r->commission_bps = commission_bps;
  r->lamports       = lamports;
  r->post_balance   = post_balance;
  fd_memcpy( r->pubkey, pubkey, 32UL );
  if( FD_UNLIKELY( event_reward_stage_cnt==FD_EVENT_INTERNAL_REWARD_REWARDS_MAX ) ) fd_event_internal_reward_flush( bank );
}

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

/* Token balances, as agave's BalanceCollector collects them before and
   after a transaction (svm/src/transaction_balances.rs:78-108,
   161-194): a key that is not invoked as a program and is not a token
   program itself, whose account is owned by SPL Token or Token-2022
   and holds an initialized token account, whose mint account is owned
   by the same program and holds an initialized mint.  The layouts are
   spl-generic-token's (token.rs, token_2022.rs). */

#define EVENT_TOKEN_ACCOUNT_LEN   (165UL)
#define EVENT_TOKEN_MINT_LEN      ( 82UL)
#define EVENT_TOKEN_MULTISIG_LEN  (355UL)
#define EVENT_TOKEN_ACCOUNT_STATE (108UL)
#define EVENT_TOKEN_MINT_DECIMALS ( 44UL)
#define EVENT_TOKEN_MINT_INIT     ( 45UL)
#define EVENT_TOKEN_2022_TYPE     (165UL) /* the account type byte of Token-2022 */
#define EVENT_TOKEN_2022_MINT     (1)
#define EVENT_TOKEN_2022_ACCOUNT  (2)

/* The state of one account at one point in time, as the collector
   reads it. */

struct event_acct_view {
  uchar const * owner;
  uchar const * data;
  ulong         data_len;
  int           exists;
};

typedef struct event_acct_view event_acct_view_t;

static inline int
event_token_program( uchar const * owner ) {
  if( !memcmp( owner, fd_solana_spl_token_id.uc,      32UL ) ) return 0;
  if( !memcmp( owner, fd_solana_spl_token_2022_id.uc, 32UL ) ) return 1;
  return -1;
}

static inline int
event_token_account_valid( uchar const * data,
                           ulong         len,
                           int           program ) {
  int base = len==EVENT_TOKEN_ACCOUNT_LEN;
  int ext  = program==1 && len>EVENT_TOKEN_ACCOUNT_LEN && len!=EVENT_TOKEN_MULTISIG_LEN &&
             data[ EVENT_TOKEN_2022_TYPE ]==EVENT_TOKEN_2022_ACCOUNT;
  return ( base || ext ) && data[ EVENT_TOKEN_ACCOUNT_STATE ]!=0;
}

/* data holds at least the first EVENT_MINT_READ_SZ bytes of the
   account, or all of it when it is shorter. */

static inline int
event_token_mint_valid( uchar const * data,
                        ulong         len,
                        int           program ) {
  int base = len==EVENT_TOKEN_MINT_LEN;
  int ext  = program==1 && len>EVENT_TOKEN_ACCOUNT_LEN && len!=EVENT_TOKEN_MULTISIG_LEN &&
             data[ EVENT_TOKEN_2022_TYPE ]==EVENT_TOKEN_2022_MINT;
  return ( base || ext ) && data[ EVENT_TOKEN_MINT_INIT ]!=0;
}

/* event_acct_pre and event_acct_post are the state a transaction
   account had before the transaction and the state a consumer must see
   after it, under the same rule as fd_event_internal_post_lamports. */

static inline event_acct_view_t
event_acct_pre( fd_acc_t const * acc ) {
  event_acct_view_t v = { .exists = 0 };
  if( FD_LIKELY( acc && acc->prior_data && acc->prior_lamports ) ) {
    v.owner    = acc->prior_owner;
    v.data     = acc->prior_data;
    v.data_len = acc->prior_data_len;
    v.exists   = 1;
  }
  return v;
}

static inline event_acct_view_t
event_acct_post( fd_txn_out_t const * txn_out,
                 ulong                idx ) {
  fd_acc_t const * acc = txn_out->accounts.account[ idx ];
  int rolled_back = txn_out->err.txn_err && !txn_out->err.is_noop;
  int is_rollback = ( idx==FD_FEE_PAYER_TXN_IDX ) | ( idx==txn_out->accounts.nonce_idx_in_txn );
  if( rolled_back && !is_rollback ) return event_acct_pre( acc );
  event_acct_view_t v = { .exists = 0 };
  if( FD_LIKELY( acc && acc->data && acc->lamports ) ) {
    v.owner    = acc->owner;
    v.data     = acc->data;
    v.data_len = acc->data_len;
    v.exists   = 1;
  }
  return v;
}

/* event_mint_view is the state of the mint at pubkey: the
   transaction's own account when the mint is one of its keys, so that
   it is seen as of before or after the transaction like every other
   key, and otherwise the accounts database as it stands, read once per
   transaction.  A mint's decimals never change after it is initialized,
   so the time of that read matters only for a mint created or closed in
   the same slot by a transaction this one does not conflict with: the
   answer then depends on replay scheduling, as it does in agave's
   loader.  The read is not cached:
   mints are hot accounts, and one that is not in the cache is read
   from disk, as agave's loader does. */

static event_acct_view_t
event_mint_view( fd_runtime_t const *   runtime,
                 fd_bank_t const *      bank,
                 fd_txn_out_t const *   txn_out,
                 event_commit_stage_t * stage,
                 uchar const *          pubkey,
                 int                    post ) {
  ulong acct_cnt = fd_ulong_min( txn_out->accounts.cnt, FD_EVENT_INTERNAL_COMMIT_KEYS_MAX );
  for( ulong j=0UL; j<acct_cnt; j++ ) {
    if( !memcmp( txn_out->accounts.keys[ j ].uc, pubkey, 32UL ) )
      return post ? event_acct_post( txn_out, j ) : event_acct_pre( txn_out->accounts.account[ j ] );
  }

  event_mint_t * m = NULL;
  for( ulong j=0UL; j<stage->mint_cnt; j++ ) {
    if( !memcmp( stage->mint[ j ].pubkey, pubkey, 32UL ) ) { m = &stage->mint[ j ]; break; }
  }
  if( !m ) {
    if( FD_UNLIKELY( stage->mint_cnt>=FD_EVENT_INTERNAL_COMMIT_KEYS_MAX ) ) {
      event_acct_view_t none = { .exists = 0 };
      return none;
    }
    m = &stage->mint[ stage->mint_cnt++ ];
    fd_memcpy( m->pubkey, pubkey, 32UL );
    ulong lamports = 0UL;
    int   executable;
    m->data_len = 0UL;
    int res;
    for( ulong attempt=0UL;; attempt++ ) {
      res = fd_accdb_read_one_nocache_max( runtime->accdb, bank->accdb_fork_id, pubkey,
                                           &lamports, &executable, m->owner,
                                           m->data, EVENT_MINT_READ_SZ, 1, &m->data_len );
      if( FD_LIKELY( res!=FD_ACCDB_READ_ONE_NOCACHE_BUSY ) ) break;
      if( FD_UNLIKELY( attempt>=EVENT_MINT_READ_RETRY_MAX ) ) break;
      FD_SPIN_PAUSE();
    }
    m->exists = res!=FD_ACCDB_READ_ONE_NOCACHE_MISS && res!=FD_ACCDB_READ_ONE_NOCACHE_BUSY && lamports!=0UL;
  }

  event_acct_view_t v = { .owner = m->owner, .data = m->data, .data_len = m->data_len, .exists = m->exists };
  return v;
}

/* event_token_balance fills out with the token balance of key idx in
   state v, if that state is a token account with a valid mint.
   Returns 1 if it did. */

static int
event_token_balance( fd_runtime_t const *                        runtime,
                     fd_bank_t const *                           bank,
                     fd_txn_out_t const *                        txn_out,
                     event_commit_stage_t *                      stage,
                     ulong                                       idx,
                     event_acct_view_t                           v,
                     int                                         post,
                     fd_event_internal_commit_token_balances_t * out ) {
  if( !v.exists ) return 0;
  int program = event_token_program( v.owner );
  if( program<0 ) return 0;
  if( !event_token_account_valid( v.data, v.data_len, program ) ) return 0;

  uchar const * mint = v.data;
  event_acct_view_t mv = event_mint_view( runtime, bank, txn_out, stage, mint, post );
  if( !mv.exists || memcmp( mv.owner, v.owner, 32UL ) ) return 0;
  if( !event_token_mint_valid( mv.data, mv.data_len, program ) ) return 0;

  out->key_idx  = (uint)idx;
  out->decimals = (uint)mv.data[ EVENT_TOKEN_MINT_DECIMALS ];
  out->program  = (uint)program;
  out->amount   = FD_LOAD( ulong, v.data+64UL );
  fd_memcpy( out->mint,  mint,        32UL );
  fd_memcpy( out->owner, v.data+32UL, 32UL );
  return 1;
}

/* event_token_balances fills stage->token with the pre entries followed
   by the post entries and returns the pre count in *pre_cnt and the
   total in the return value. */

static ulong
event_token_balances( fd_runtime_t const *   runtime,
                      fd_bank_t const *      bank,
                      fd_txn_t const *       txn_d,
                      fd_txn_out_t const *   txn_out,
                      event_commit_stage_t * stage,
                      ulong *                pre_cnt ) {
  ulong acct_cnt = fd_ulong_min( txn_out->accounts.cnt, FD_EVENT_INTERNAL_COMMIT_KEYS_MAX );
  *pre_cnt = 0UL;
  stage->mint_cnt = 0UL;

  int has_token_program = 0;
  for( ulong i=0UL; i<acct_cnt; i++ ) has_token_program |= event_token_program( txn_out->accounts.keys[ i ].uc )>=0;
  if( !has_token_program ) return 0UL;

  ulong invoked = 0UL;
  for( ulong k=0UL; k<txn_d->instr_cnt; k++ ) invoked |= 1UL<<txn_d->instr[ k ].program_id;

  ulong cnt = 0UL;
  for( int post=0; post<2; post++ ) {
    for( ulong i=0UL; i<acct_cnt; i++ ) {
      if( (invoked>>i)&1UL ) continue;
      if( event_token_program( txn_out->accounts.keys[ i ].uc )>=0 ) continue;
      event_acct_view_t v = post ? event_acct_post( txn_out, i ) : event_acct_pre( txn_out->accounts.account[ i ] );
      cnt += (ulong)event_token_balance( runtime, bank, txn_out, stage, i, v, post, &stage->token[ cnt ] );
    }
    if( !post ) *pre_cnt = cnt;
  }
  return cnt;
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

  ulong token_pre_cnt    = 0UL;
  ev->token_balances_cnt = event_token_balances( runtime, bank, txn_d, txn_out, stage, &token_pre_cnt );
  ev->token_pre_cnt      = (uint)token_pre_cnt;
  ev->accdb_fork         = (uint)bank->accdb_fork_id.val;

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
    .return_data    = txn_out->details.return_data.data,
    .token_balances = stage->token,
    .touched        = stage->touched
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

  /* One account record per written account, ahead of the commit record
     on the same link, so that a consumer sees the writes a transaction
     made before the transaction itself, the order the validator's
     plugin interface reports them in.  A closed account travels as the
     transaction left it. */
  for( ulong i=0UL; i<touched_cnt; i++ ) {
    fd_event_internal_commit_touched_t const * t = &stage->touched[ i ];
    fd_acc_t const * acc = txn_out->accounts.account[ t->key_idx ];
    event_account_write_emit( bank, 1, 0UL, ev->commit_index_in_slot, (uint)i, ev->signature,
                              txn_out->accounts.keys[ t->key_idx ].uc, acc->owner, acc->lamports,
                              !!acc->executable, acc->data, acc->data_len, with_accounts );
  }

  fd_event_report_chunked_( FD_EVENT_INTERNAL_COMMIT_ID, iov, iov_cnt );
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
