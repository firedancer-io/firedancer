/* Test for delay_commission_updates

   Vote Program Tests:
    Feature OFF: commission increases blocked in second half of epoch
    Feature ON:  commission increases always allowed

   Rewards Tests:
    Feature OFF: uses current commission for rewards payout
    Feature ON:  uses delayed commission if available (fallbacks: prev_prev -> prev -> current) */

#include "../fd_acc_pool.h"
#include "../fd_runtime.h"
#include "../fd_runtime_stack.h"
#include "../fd_bank.h"
#include "../fd_system_ids.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"
#include "../sysvar/fd_sysvar_stake_history.h"
#include "../sysvar/fd_sysvar_clock.h"
#include "../sysvar/fd_sysvar_cache.h"
#include "../program/fd_builtin_programs.h"
#include "../program/fd_vote_program.h"
#include "../program/fd_stake_program.h"
#include "../../accdb/fd_accdb_admin_v1.h"
#include "../../accdb/fd_accdb_impl_v1.h"
#include "../../features/fd_features.h"
#include "../../accdb/fd_accdb_sync.h"
#include "../../log_collector/fd_log_collector.h"
#include "../../stakes/fd_vote_states.h"
#include "../../stakes/fd_stake_delegations.h"
#include "../../types/fd_types.h"

#define TEST_SLOTS_PER_EPOCH       (4UL)
#define TEST_ACC_POOL_ACCOUNT_CNT  (32UL)
#define TEST_LAMPORTS              (10000UL)
#define TEST_STAKE_AMOUNT          (10000000000UL)
#define TEST_VOTE_CREDITS          (1000UL)
#define VOTE_IX_UPDATE_COMMISSION  (5U)
#define FD_VOTE_STATE_V3_SZ        (3762UL)
#define TEST_CAPITALIZATION        (259526316000UL)

struct test_env {
  fd_wksp_t *          wksp;
  ulong                tag;
  fd_banks_t           banks[1];
  fd_bank_t            bank[1];
  void *               funk_mem;
  fd_accdb_admin_t     accdb_admin[1];
  fd_accdb_user_t      accdb[1];
  fd_funk_txn_xid_t    xid;
  int                  xid_is_rooted;
  fd_runtime_stack_t * runtime_stack;
  fd_runtime_t *       runtime;
  fd_txn_in_t          txn_in;
  fd_txn_out_t         txn_out[1];
  fd_log_collector_t   log_collector[1];
  int                  txn_needs_cancel;
};
typedef struct test_env test_env_t;

static fd_pubkey_t const validator_key = { .ul = { 0x1111111111111111UL, 0, 0, 0 } };
static fd_pubkey_t const authority_key = { .ul = { 0xAAAAAAAAAAAAAAAAUL, 0, 0, 0 } };
static fd_pubkey_t const staker_key    = { .ul = { 0x4444444444444444UL, 0, 0, 0 } };

/* ============================================================================
   Environment Setup
   ============================================================================ */

static void
create_account_raw( fd_accdb_user_t *         user,
                    fd_funk_txn_xid_t const * xid,
                    fd_pubkey_t const *       pubkey,
                    ulong                     lamports,
                    uint                      dlen,
                    uchar *                   data,
                    fd_pubkey_t const *       owner ) {
  fd_accdb_rw_t rw[1];
  FD_TEST( fd_accdb_open_rw( user, rw, xid, pubkey, dlen, FD_ACCDB_FLAG_CREATE ) );
  if( data && dlen ) fd_accdb_ref_data_set( user, rw, data, dlen );
  rw->meta->lamports   = lamports;
  rw->meta->slot       = 0UL;
  rw->meta->executable = 0;
  if( owner ) memcpy( rw->meta->owner, owner->key, 32UL );
  else        memset( rw->meta->owner, 0UL, 32UL );
  fd_accdb_close_rw( user, rw );
}

static test_env_t *
test_env_create( test_env_t * env,
                 fd_wksp_t *  wksp,
                 int          feature_enabled ) {
  fd_memset( env, 0, sizeof(test_env_t) );
  env->wksp = wksp;
  env->tag  = 1UL;

  env->funk_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( 16UL, 1024UL ), env->tag );
  FD_TEST( env->funk_mem );
  FD_TEST( fd_funk_new( env->funk_mem, env->tag, 17UL, 16UL, 1024UL ) );
  FD_TEST( fd_accdb_admin_v1_init( env->accdb_admin, env->funk_mem ) );
  FD_TEST( fd_accdb_user_v1_init( env->accdb, env->funk_mem ) );

  fd_banks_data_t * banks_data   = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( 2UL, 2UL ), env->tag );
  fd_banks_locks_t * banks_locks = fd_wksp_alloc_laddr( wksp, alignof(fd_banks_locks_t), sizeof(fd_banks_locks_t), env->tag );
  FD_TEST( banks_data && banks_locks );
  fd_banks_locks_init( banks_locks );
  FD_TEST( fd_banks_join( env->banks, fd_banks_new( banks_data, 2UL, 2UL, 0, 8888UL ), banks_locks ) );
  FD_TEST( fd_banks_init_bank( env->bank, env->banks ) );

  env->bank->data->flags                    &= (ulong)~FD_BANK_FLAGS_FROZEN;
  fd_bank_cost_tracker_t * cost_tracker_pool = fd_bank_get_cost_tracker_pool( env->bank->data );
  env->bank->data->cost_tracker_pool_idx     = fd_bank_cost_tracker_pool_idx_acquire( cost_tracker_pool );

  env->runtime_stack = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_stack_t), sizeof(fd_runtime_stack_t), env->tag );
  FD_TEST( env->runtime_stack );
  fd_memset( env->runtime_stack, 0, sizeof(fd_runtime_stack_t) );

  fd_funk_txn_xid_t root[1];
  fd_funk_txn_xid_set_root( root );
  env->xid = (fd_funk_txn_xid_t){ .ul = { 0UL, env->bank->data->idx } };
  fd_accdb_attach_child( env->accdb_admin, root, &env->xid );

  /* Sysvars */
  fd_rent_t rent = { .lamports_per_uint8_year = 3480UL, .exemption_threshold = 2.0, .burn_percent = 50 };
  fd_bank_rent_set( env->bank, rent );
  fd_sysvar_rent_write( env->bank, env->accdb, &env->xid, NULL, &rent );

  fd_epoch_schedule_t epoch_schedule = {
    .slots_per_epoch = TEST_SLOTS_PER_EPOCH, .leader_schedule_slot_offset = TEST_SLOTS_PER_EPOCH,
    .warmup = 0, .first_normal_epoch = 0UL, .first_normal_slot = 0UL
  };
  fd_bank_epoch_schedule_set( env->bank, epoch_schedule );
  fd_sysvar_epoch_schedule_write( env->bank, env->accdb, &env->xid, NULL, &epoch_schedule );
  fd_sysvar_stake_history_init( env->bank, env->accdb, &env->xid, NULL );
  fd_sysvar_clock_init( env->bank, env->accdb, &env->xid, NULL );

  fd_blockhashes_t * bhq = fd_blockhashes_init( fd_bank_block_hash_queue_modify( env->bank ), 12345UL );
  fd_hash_t dummy_hash = {0};
  fd_memset( dummy_hash.uc, 0xAB, FD_HASH_FOOTPRINT );
  fd_blockhashes_push_new( bhq, &dummy_hash )->fee_calculator.lamports_per_signature = 0UL;

  fd_inflation_t inflation = { .initial = 0.08, .terminal = 0.015, .taper = 0.15,
                               .foundation = 0.05, .foundation_term = 7.0, .unused = 0.0 };
  fd_bank_inflation_set( env->bank, inflation );
  fd_bank_slots_per_year_set( env->bank, 78892314UL );
  fd_bank_capitalization_set( env->bank, TEST_CAPITALIZATION );

  fd_bank_slot_set( env->bank, 0UL );
  fd_bank_epoch_set( env->bank, 0UL );

  fd_features_t features = {0};
  fd_features_disable_all( &features );
  if( feature_enabled ) features.delay_commission_updates = 0UL;
  fd_bank_features_set( env->bank, features );

  fd_builtin_programs_init( env->bank, env->accdb, &env->xid, NULL );

  env->runtime = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t), sizeof(fd_runtime_t), env->tag );
  uchar * acc_pool_mem = fd_wksp_alloc_laddr( wksp, fd_acc_pool_align(), fd_acc_pool_footprint( TEST_ACC_POOL_ACCOUNT_CNT ), env->tag );
  fd_acc_pool_t * acc_pool = fd_acc_pool_join( fd_acc_pool_new( acc_pool_mem, TEST_ACC_POOL_ACCOUNT_CNT ) );
  FD_TEST( acc_pool );

  env->runtime->accdb        = &env->accdb[0];
  env->runtime->progcache    = NULL;
  env->runtime->status_cache = NULL;
  env->runtime->acc_pool     = acc_pool;
  fd_log_collector_init( env->log_collector, 0 );
  env->runtime->log.log_collector        = env->log_collector;
  env->runtime->log.enable_log_collector = 0;
  env->runtime->log.dumping_mem          = NULL;
  env->runtime->log.enable_vm_tracing    = 0;
  env->runtime->log.tracing_mem          = NULL;
  env->runtime->log.capture_ctx          = NULL;

  return env;
}

static void
test_env_destroy( test_env_t * env ) {
  if( env->txn_needs_cancel ) {
    env->txn_out[0].err.is_committable = 0;
    fd_runtime_cancel_txn( env->runtime, &env->txn_out[0] );
  }
  if( !env->xid_is_rooted ) fd_accdb_cancel( env->accdb_admin, &env->xid );
  if( env->runtime ) {
    if( env->runtime->acc_pool ) fd_wksp_free_laddr( env->runtime->acc_pool );
    fd_wksp_free_laddr( env->runtime );
  }
  fd_wksp_free_laddr( env->runtime_stack );
  fd_wksp_free_laddr( env->banks->data );
  fd_wksp_free_laddr( env->banks->locks );
  void * accdb_shfunk = fd_accdb_admin_v1_funk( env->accdb_admin )->shmem;
  fd_accdb_admin_fini( env->accdb_admin );
  fd_accdb_user_fini( env->accdb );
  fd_wksp_free_laddr( fd_funk_delete( accdb_shfunk ) );
  fd_wksp_reset( env->wksp, (uint)env->tag );
}

/* ============================================================================
   Account Creation Helpers
   ============================================================================ */

static void
create_vote_account( test_env_t * env, uchar commission, ulong epoch_credits_epoch ) {
  uchar * vote_state_data = fd_wksp_alloc_laddr( env->wksp, 8UL, FD_VOTE_STATE_V3_SZ, env->tag );
  uchar * pool_mem        = fd_wksp_alloc_laddr( env->wksp, 16UL, 1024UL, env->tag );
  uchar * treap_mem       = fd_wksp_alloc_laddr( env->wksp, 16UL, 1024UL, env->tag );
  uchar * epoch_cred_mem  = fd_wksp_alloc_laddr( env->wksp, 16UL, 2048UL, env->tag );
  fd_memset( vote_state_data, 0, FD_VOTE_STATE_V3_SZ );

  fd_vote_state_versioned_t vsv[1];
  fd_vote_state_versioned_new_disc( vsv, fd_vote_state_versioned_enum_v3 );
  fd_vote_state_v3_t * vs = &vsv->inner.v3;
  vs->node_pubkey           = authority_key;
  vs->authorized_withdrawer = authority_key;
  vs->commission            = commission;

  vs->authorized_voters.pool = fd_vote_authorized_voters_pool_join( fd_vote_authorized_voters_pool_new( pool_mem, 1UL ) );
  vs->authorized_voters.treap = fd_vote_authorized_voters_treap_join( fd_vote_authorized_voters_treap_new( treap_mem, 1UL ) );
  fd_vote_authorized_voter_t * voter_ele = fd_vote_authorized_voters_pool_ele_acquire( vs->authorized_voters.pool );
  *voter_ele = (fd_vote_authorized_voter_t){ .epoch = 0UL, .pubkey = authority_key, .prio = authority_key.ul[0] };
  fd_vote_authorized_voters_treap_ele_insert( vs->authorized_voters.treap, voter_ele, vs->authorized_voters.pool );

  vs->epoch_credits = deq_fd_vote_epoch_credits_t_join( deq_fd_vote_epoch_credits_t_new( epoch_cred_mem, 64UL ) );
  if( epoch_credits_epoch != ULONG_MAX ) {
    fd_vote_epoch_credits_t * cred = deq_fd_vote_epoch_credits_t_push_tail_nocopy( vs->epoch_credits );
    cred->epoch = epoch_credits_epoch;
    cred->credits = TEST_VOTE_CREDITS;
    cred->prev_credits = 0UL;
  }

  fd_bincode_encode_ctx_t encode = { .data = vote_state_data, .dataend = vote_state_data + FD_VOTE_STATE_V3_SZ };
  FD_TEST( fd_vote_state_versioned_encode( vsv, &encode ) == FD_BINCODE_SUCCESS );

  fd_pubkey_t vote_program = fd_solana_vote_program_id;
  create_account_raw( env->accdb, &env->xid, &validator_key, TEST_LAMPORTS, FD_VOTE_STATE_V3_SZ, vote_state_data, &vote_program );

  fd_vote_states_t * vote_states = fd_bank_vote_states_locking_modify( env->bank );
  fd_vote_state_ele_t * ele = fd_vote_states_update( vote_states, &validator_key );
  ele->node_account = authority_key;
  ele->commission   = commission;
  ele->stake        = TEST_LAMPORTS;
  fd_bank_vote_states_end_locking_modify( env->bank );

  fd_wksp_free_laddr( epoch_cred_mem );
  fd_wksp_free_laddr( treap_mem );
  fd_wksp_free_laddr( pool_mem );
  fd_wksp_free_laddr( vote_state_data );
}

static void
create_stake_account( test_env_t * env ) {
  uchar * stake_data = fd_wksp_alloc_laddr( env->wksp, 8UL, FD_STAKE_STATE_V2_SZ, env->tag );
  fd_memset( stake_data, 0, FD_STAKE_STATE_V2_SZ );

  fd_stake_state_v2_t state[1];
  fd_stake_state_v2_new_disc( state, fd_stake_state_v2_enum_stake );
  state->inner.stake.meta = (fd_stake_meta_t){
    .rent_exempt_reserve = 2282880UL,
    .authorized = { .staker = authority_key, .withdrawer = authority_key }
  };
  state->inner.stake.stake = (fd_stake_t){
    .delegation = (fd_delegation_t){
      .voter_pubkey = validator_key, .stake = TEST_STAKE_AMOUNT,
      .activation_epoch = 0UL, .deactivation_epoch = ULONG_MAX, .warmup_cooldown_rate = 0.25
    },
    .credits_observed = 0UL
  };

  fd_bincode_encode_ctx_t encode = { .data = stake_data, .dataend = stake_data + FD_STAKE_STATE_V2_SZ };
  FD_TEST( fd_stake_state_v2_encode( state, &encode ) == FD_BINCODE_SUCCESS );

  fd_pubkey_t stake_program = fd_solana_stake_program_id;
  create_account_raw( env->accdb, &env->xid, &staker_key, TEST_STAKE_AMOUNT + 2282880UL, FD_STAKE_STATE_V2_SZ, stake_data, &stake_program );
  fd_wksp_free_laddr( stake_data );

  fd_stake_delegations_t * delegations = fd_bank_stake_delegations_delta_locking_modify( env->bank );
  fd_stake_delegations_update( delegations, &staker_key, &validator_key, TEST_STAKE_AMOUNT, 0UL, ULONG_MAX, 0UL, 0.25 );
  fd_bank_stake_delegations_delta_end_locking_modify( env->bank );
}

static void
set_commission_prev( test_env_t * env, uchar commission ) {
  fd_vote_states_t * vs = fd_bank_vote_states_prev_modify( env->bank );
  fd_vote_state_ele_t * ele = fd_vote_states_update( vs, &validator_key );
  ele->node_account = authority_key;
  ele->commission = commission;
  ele->stake = TEST_LAMPORTS;
}

static void
set_commission_prev_prev( test_env_t * env, uchar commission ) {
  fd_vote_states_t * vs = fd_bank_vote_states_prev_prev_modify( env->bank );
  fd_vote_state_ele_t * ele = fd_vote_states_update( vs, &validator_key );
  ele->node_account = authority_key;
  ele->commission = commission;
  ele->stake = TEST_LAMPORTS;
}

/* ============================================================================
   Account Query Helpers
   ============================================================================ */

static uchar
get_vote_commission( test_env_t * env ) {
  fd_accdb_ro_t ro[1];
  FD_TEST( fd_accdb_open_ro( env->accdb, ro, &env->xid, &validator_key ) );
  uchar const * data = fd_accdb_ref_data_const( ro );
  ulong dlen = fd_accdb_ref_data_sz( ro );

  fd_bincode_decode_ctx_t decode = { .data = data, .dataend = data + dlen };
  ulong total_sz = 0;
  FD_TEST( fd_vote_state_versioned_decode_footprint( &decode, &total_sz ) == 0 );

  uchar * mem = fd_wksp_alloc_laddr( env->wksp, 8UL, total_sz, env->tag );
  decode.data = data;
  fd_vote_state_versioned_t * vsv = fd_vote_state_versioned_decode( mem, &decode );

  uchar commission = 0;
  if( vsv->discriminant == fd_vote_state_versioned_enum_v3 )
    commission = vsv->inner.v3.commission;
  else if( vsv->discriminant == fd_vote_state_versioned_enum_v1_14_11 )
    commission = vsv->inner.v1_14_11.commission;

  fd_wksp_free_laddr( mem );
  fd_accdb_close_ro( env->accdb, ro );
  return commission;
}

static ulong
get_balance( test_env_t * env, fd_pubkey_t const * pubkey ) {
  fd_accdb_ro_t ro[1];
  if( !fd_accdb_open_ro( env->accdb, ro, &env->xid, pubkey ) ) return 0UL;
  ulong balance = fd_accdb_ref_lamports( ro );
  fd_accdb_close_ro( env->accdb, ro );
  return balance;
}

/* ============================================================================
   Slot Processing
   ============================================================================ */

static void
setup_slot( test_env_t * env, ulong slot ) {
  fd_funk_txn_xid_t parent_xid = env->xid;
  fd_funk_txn_xid_t new_xid = { .ul = { slot, env->bank->data->idx } };
  fd_accdb_attach_child( env->accdb_admin, &parent_xid, &new_xid );
  env->xid = new_xid;
  fd_bank_slot_set( env->bank, slot );

  fd_epoch_schedule_t const * es = fd_bank_epoch_schedule_query( env->bank );
  ulong epoch = fd_slot_to_epoch( es, slot, NULL );
  fd_sol_sysvar_clock_t clock = { .slot = slot, .epoch = epoch };
  fd_sysvar_clock_write( env->bank, env->accdb, &env->xid, NULL, &clock );
  FD_TEST( fd_sysvar_cache_restore( env->bank, env->accdb, &env->xid ) );
}

static int
process_slot( test_env_t * env, ulong slot ) {
  fd_bank_t * parent = env->bank;
  ulong parent_slot = fd_bank_slot_get( parent );
  ulong parent_idx  = parent->data->idx;
  FD_TEST( parent->data->flags & FD_BANK_FLAGS_FROZEN );

  ulong new_idx = fd_banks_new_bank( env->bank, env->banks, parent_idx, 0L )->data->idx;
  fd_bank_t * new_bank = fd_banks_clone_from_parent( env->bank, env->banks, new_idx );
  fd_bank_slot_set( new_bank, slot );
  fd_bank_parent_slot_set( new_bank, parent_slot );

  fd_epoch_schedule_t const * es = fd_bank_epoch_schedule_query( new_bank );
  fd_bank_epoch_set( new_bank, fd_slot_to_epoch( es, slot, NULL ) );

  fd_funk_txn_xid_t xid = { .ul = { slot, new_idx } };
  fd_funk_txn_xid_t parent_xid = { .ul = { parent_slot, parent_idx } };
  fd_accdb_attach_child( env->accdb_admin, &parent_xid, &xid );
  env->xid = xid;

  int is_epoch_boundary = 0;
  fd_runtime_block_execute_prepare( env->banks, env->bank, env->accdb, env->runtime_stack, NULL, &is_epoch_boundary );

  fd_banks_mark_bank_frozen( env->banks, new_bank );
  fd_accdb_advance_root( env->accdb_admin, &xid );
  fd_banks_advance_root( env->banks, new_idx );
  env->xid_is_rooted = 1;

  return is_epoch_boundary;
}

static void
advance_to_epoch( test_env_t * env, ulong target_epoch ) {
  ulong current = fd_bank_slot_get( env->bank );
  ulong target  = target_epoch * TEST_SLOTS_PER_EPOCH;
  for( ulong slot = current + 1; slot <= target; slot++ ) {
    int boundary = process_slot( env, slot );
    if( slot == target ) FD_TEST( boundary );
  }
}

/* ============================================================================
   Transaction Building
   ============================================================================ */

struct txn_instr { uchar program_id_idx; uchar * account_idxs; ushort account_idxs_cnt; uchar * data; ushort data_sz; };
typedef struct txn_instr txn_instr_t;

static uchar *
txn_add( uchar * cur, void const * data, ulong sz ) {
  FD_TEST( cur );
  FD_TEST( data );
  fd_memcpy( cur, data, sz );
  FD_TEST( !memcmp( cur, data, sz ) );
  return cur + sz;
}

static uchar *
txn_add_u8( uchar * cur, uchar val ) {
  FD_TEST( cur );
  *cur = val;
  FD_TEST( *cur == val );
  return cur + 1;
}

static uchar *
txn_add_cu16( uchar * cur, ushort val ) {
  FD_TEST( cur );
  uchar buf[3];
  fd_bincode_encode_ctx_t ctx = { .data = buf, .dataend = buf + 3 };
  FD_TEST( fd_bincode_compact_u16_encode( &val, &ctx ) == FD_BINCODE_SUCCESS );
  ulong sz = (ulong)((uchar *)ctx.data - buf);
  FD_TEST( sz >= 1 && sz <= 3 );
  FD_TEST( (val < 0x80)   ? (sz == 1) : 1 );
  FD_TEST( (val < 0x4000) ? (sz <= 2) : 1 );
  return txn_add( cur, buf, sz );
}

static ulong
txn_serialize( uchar * buf,
               ulong num_signers,
               ulong num_readonly_unsigned,
               ulong num_keys,
               fd_pubkey_t * keys,
               txn_instr_t * instrs,
               ushort instr_cnt ) {
  uchar * cur = buf;
  fd_signature_t sig = {0};
  fd_hash_t blockhash = {0};
  fd_memset( blockhash.uc, 0xAB, FD_HASH_FOOTPRINT );

  cur = txn_add_u8( cur, 1 );                                     /* signature count */
  cur = txn_add( cur, &sig, FD_TXN_SIGNATURE_SZ );                /* signature */
  cur = txn_add_u8( cur, (uchar)num_signers );                    /* num required signatures */
  cur = txn_add_u8( cur, 0 );                                     /* num readonly signed */
  cur = txn_add_u8( cur, (uchar)num_readonly_unsigned );          /* num readonly unsigned */
  cur = txn_add_cu16( cur, (ushort)num_keys );                    /* account keys count */
  for( ushort i = 0; i < num_keys; i++ )
    cur = txn_add( cur, &keys[i], sizeof(fd_pubkey_t) );          /* account keys */
  cur = txn_add( cur, &blockhash, sizeof(fd_hash_t) );            /* recent blockhash */
  cur = txn_add_cu16( cur, instr_cnt );                           /* instruction count */
  for( ushort i = 0; i < instr_cnt; i++ ) {
    cur = txn_add_u8( cur, instrs[i].program_id_idx );            /* program id index */
    cur = txn_add_cu16( cur, instrs[i].account_idxs_cnt );        /* account indices count */
    cur = txn_add( cur, instrs[i].account_idxs, instrs[i].account_idxs_cnt );
    cur = txn_add_cu16( cur, instrs[i].data_sz );                 /* instruction data size */
    cur = txn_add( cur, instrs[i].data, instrs[i].data_sz );      /* instruction data */
  }
  return (ulong)(cur - buf);
}

static int
execute_update_commission( test_env_t * env, uchar new_commission ) {
  uchar instr_data[5];
  FD_STORE( uint, instr_data, VOTE_IX_UPDATE_COMMISSION );
  instr_data[4] = new_commission;

  fd_pubkey_t vote_program = fd_solana_vote_program_id;
  fd_pubkey_t keys[3] = { authority_key, validator_key, vote_program };
  uchar account_idxs[2] = { 1, 0 };
  txn_instr_t instrs[1] = {{ .program_id_idx = 2, .account_idxs = account_idxs, .account_idxs_cnt = 2, .data = instr_data, .data_sz = 5 }};

  fd_txn_p_t txn_p = {0};
  ulong sz = txn_serialize( txn_p.payload, 1, 1, 3, keys, instrs, 1 );
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

  env->txn_in.txn = &txn_p;
  env->txn_in.bundle.is_bundle = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  env->txn_needs_cancel = 1;

  int success = env->txn_out[0].err.is_committable && env->txn_out[0].err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS;
  if( success ) {
    fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[0] );
    env->txn_needs_cancel = 0;
  }
  return success;
}
static void
verify_epoch_rewards( test_env_t * env, ulong vote_rewards, ulong expected_stake_rewards ) {
  fd_epoch_rewards_t const * er = fd_bank_epoch_rewards_query( env->bank );
  FD_TEST( er );

  ulong stake_diff = (er->total_stake_rewards > expected_stake_rewards)
    ? (er->total_stake_rewards - expected_stake_rewards)
    : (expected_stake_rewards - er->total_stake_rewards);
  FD_TEST( stake_diff <= 1UL );

  ulong sum = vote_rewards + er->total_stake_rewards;
  ulong diff = (er->total_rewards > sum) ? (er->total_rewards - sum) : (sum - er->total_rewards);
  FD_TEST( diff <= 1UL );
}

static void
test_vote_commission_update( fd_wksp_t * wksp,
                             int         feature_enabled,
                             ulong       slot,
                             uchar       old_commission,
                             uchar       new_commission,
                             int         expect_success ) {
  test_env_t env[1];
  test_env_create( env, wksp, feature_enabled );
  setup_slot( env, slot );

  create_account_raw( env->accdb, &env->xid, &authority_key, TEST_LAMPORTS, 0, NULL, NULL );
  create_vote_account( env, old_commission, ULONG_MAX );

  FD_TEST( get_vote_commission( env ) == old_commission );
  int success = execute_update_commission( env, new_commission );
  FD_TEST( success == expect_success );
  FD_TEST( get_vote_commission( env ) == (expect_success ? new_commission : old_commission) );

  if( !expect_success ) {
    FD_TEST( env->txn_out[0].err.custom_err == FD_VOTE_ERR_COMMISSION_UPDATE_TOO_LATE );
  }

  test_env_destroy( env );
}
typedef struct {
  int   feature_enabled;
  uchar current_commission;
  uchar prev_commission;      /* UCHAR_MAX = don't set */
  uchar prev_prev_commission; /* UCHAR_MAX = don't set */
  ulong expected_vote_balance;
  ulong expected_stake_rewards;
} rewards_test_params_t;

static void
test_rewards( fd_wksp_t * wksp, rewards_test_params_t const * p ) {
  test_env_t env[1];
  test_env_create( env, wksp, p->feature_enabled );

  create_account_raw( env->accdb, &env->xid, &authority_key, TEST_LAMPORTS, 0, NULL, NULL );
  create_vote_account( env, p->current_commission, 1UL );
  create_stake_account( env );

  if( p->prev_commission != UCHAR_MAX )      set_commission_prev( env, p->prev_commission );
  if( p->prev_prev_commission != UCHAR_MAX ) set_commission_prev_prev( env, p->prev_prev_commission );

  ulong initial_vote = get_balance( env, &validator_key );
  FD_TEST( initial_vote == TEST_LAMPORTS );

  fd_banks_mark_bank_frozen( env->banks, env->bank );
  fd_accdb_advance_root( env->accdb_admin, &env->xid );

  advance_to_epoch( env, 2UL );

  ulong final_vote = get_balance( env, &validator_key );
  FD_TEST( final_vote == p->expected_vote_balance );

  ulong vote_rewards = final_vote - initial_vote;
  verify_epoch_rewards( env, vote_rewards, p->expected_stake_rewards );

  test_env_destroy( env );
}

/* ============================================================================
   Main
   ============================================================================ */

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx > fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr( &argc, &argv, "--page-sz", NULL, "normal" );
  ulong page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1572864UL );
  ulong numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /* Vote Program Tests: testing setting the commission rate */

  FD_LOG_NOTICE(( "Vote Program: delay_commission_updates OFF, first half of epoch" ));
  test_vote_commission_update( wksp, 0, 1, 5, 10, 1 );

  FD_LOG_NOTICE(( "Vote Program: delay_commission_updates OFF, second half of epoch" ));
  test_vote_commission_update( wksp, 0, 3, 5, 10, 0 );

  FD_LOG_NOTICE(( "Vote Program: delay_commission_updates OFF, second half of epoch" ));
  test_vote_commission_update( wksp, 0, 3, 10, 5, 1 );

  FD_LOG_NOTICE(( "Vote Program: delay_commission_updates ON, second half of epoch" ));
  test_vote_commission_update( wksp, 1, 3, 5, 10, 1 );

  /* Rewards Tests: testing the delayed commission rate behavior */

  FD_LOG_NOTICE(( "Rewards: delay_commission_updates OFF, 10%% commission: vote=100, stake=900" ));
  test_rewards( wksp, &(rewards_test_params_t){
    .feature_enabled        = 0,
    .current_commission     = 10,
    .prev_commission        = 5,
    .prev_prev_commission   = 2,
    .expected_vote_balance  = 10100UL,  /* 10000 + 100 */
    .expected_stake_rewards = 900UL,
  });

  FD_LOG_NOTICE(( "Rewards: delay_commission_updates ON, uses prev (20%%): vote=200, stake=800" ));
  test_rewards( wksp, &(rewards_test_params_t){
    .feature_enabled        = 1,
    .current_commission     = 10,
    .prev_commission        = 20,
    .prev_prev_commission   = 5,
    .expected_vote_balance  = 10200UL,  /* 10000 + 200 */
    .expected_stake_rewards = 800UL,
  });

  FD_LOG_NOTICE(( "Rewards: delay_commission_updates ON, no prev_prev, falls back to prev (20%%): vote=200, stake=800" ));
  test_rewards( wksp, &(rewards_test_params_t){
    .feature_enabled        = 1,
    .current_commission     = 10,
    .prev_commission        = 20,
    .prev_prev_commission   = UCHAR_MAX,
    .expected_vote_balance  = 10200UL,  /* 10000 + 200 */
    .expected_stake_rewards = 800UL,
  });

  FD_LOG_NOTICE(( "Rewards: delay_commission_updates ON, no prev or prev_prev, uses current (10%%): vote=100, stake=900" ));
  test_rewards( wksp, &(rewards_test_params_t){
    .feature_enabled        = 1,
    .current_commission     = 10,
    .prev_commission        = UCHAR_MAX,
    .prev_prev_commission   = UCHAR_MAX,
    .expected_vote_balance  = 10100UL,  /* 10000 + 100 */
    .expected_stake_rewards = 900UL,
  });

  fd_wksp_delete_anonymous( wksp );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
