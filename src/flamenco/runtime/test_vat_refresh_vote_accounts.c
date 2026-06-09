/* Test for the validator_admission_ticket (VAT, SIMD-0357) epoch
   boundary behaviour, focusing on the activation epoch and the one or
   two epochs that follow it.

   Two things are exercised across the transition:

   1. Filtering: the non-VAT refresh tracks every valid vote account,
      but once VAT activates only the V4 accounts that carry a BLS
      pubkey (and clear the rent-exempt minimum) survive in top_votes.

   2. Clock: the stake-weighted timestamp is computed from the t-2 stake
      snapshot of a set of vote accounts.  Pre-VAT (and AT vat_epoch) the
      clock reads the unfiltered vote_stakes t-2 set; only at vat_epoch+1
      does it switch to the filtered top_votes_t_2 set.  By giving a
      filtered-out "whale" a far-future vote timestamp and a dominant
      stake, the computed timestamp reveals exactly which set + stakes
      are referenced: it stays pinned to the slow drift bound while the
      whale is counted and drops to the fast bound once the whale is
      filtered out at vat_epoch+1.  This also exercises the t-1 -> t-2
      carry-forward that the VAT activation epoch performs. */

#include "fd_runtime.h"
#include "fd_runtime_stack.h"
#include "fd_bank.h"
#include "fd_system_ids.h"
#include "program/fd_vote_program.h"
#include "program/vote/fd_vote_codec.h"
#include "sysvar/fd_sysvar_rent.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "sysvar/fd_sysvar_stake_history.h"
#include "sysvar/fd_sysvar_clock.h"
#include "../accdb/fd_accdb_admin_v1.h"
#include "../accdb/fd_accdb_impl_v1.h"
#include "../accdb/fd_accdb_sync.h"
#include "../features/fd_features.h"
#include "../stakes/fd_stake_types.h"
#include "../stakes/fd_top_votes.h"
#include "../stakes/fd_vote_stakes.h"

#define TEST_SLOTS_PER_EPOCH (3UL)
#define TEST_VAT_EPOCH       (3UL)
#define TEST_VAT_ACTIVATION_SLOT (TEST_SLOTS_PER_EPOCH * TEST_VAT_EPOCH) /* 9 */

/* 4s per slot: drift bounds at k=1 become whole seconds
     poh_offset      = 4s
     slow bound 150% = +6s -> unix-epoch_start = 10 (whale counted)
     fast bound  25% = -1s -> unix-epoch_start =  3 (whale filtered) */
#define NS_PER_SLOT          (4000000000UL)
#define D_SLOT_SECONDS       (4L)
#define CLOCK_DELTA_WHALE     (10L) /* slow-bound at k=1 */
#define CLOCK_DELTA_NO_WHALE  (3L)  /* fast-bound at k=1 */

#define GENESIS_CREATION_TIME (1700000000L)

#define VOTE_ACCOUNT_LAMPORTS (1000000000UL)
#define BASE_STAKE            (1000000000UL)
#define WHALE_STAKE           (5UL*BASE_STAKE) /* > sum of eligible -> dominates median */

/* far-past / far-future vote timestamps relative to the (large) genesis
   epoch_start_timestamp: past -> fast bound, future -> slow bound */
#define VOTE_TS_PAST          (1L)
#define VOTE_TS_FUTURE        (1000000000000L)

/* Voter layout:
     0,1 -> V4 + BLS, BASE_STAKE, past vote ts   (VAT-eligible)
     2   -> V4 no BLS, WHALE_STAKE, future vote ts (VAT-filtered) */
#define NUM_VOTERS       (3UL)
#define NUM_VAT_ELIGIBLE (2UL)

struct test_env {
  fd_wksp_t *          wksp;
  ulong                tag;
  fd_banks_t *         banks;
  fd_bank_t *          bank;
  void *               funk_mem;
  void *               funk_locks;
  fd_accdb_admin_t     accdb_admin[1];
  fd_accdb_user_t      accdb[1];
  fd_funk_txn_xid_t    xid;
  fd_runtime_stack_t * runtime_stack;
};
typedef struct test_env test_env_t;

static fd_pubkey_t vote_key ( ulong i ) { return (fd_pubkey_t){ .ul[0] = 0x100UL + i }; }
static fd_pubkey_t stake_key( ulong i ) { return (fd_pubkey_t){ .ul[0] = 0x200UL + i }; }

static int    voter_has_bls( ulong i ) { return i<NUM_VAT_ELIGIBLE; }
static ulong  voter_stake  ( ulong i ) { return voter_has_bls( i ) ? BASE_STAKE : WHALE_STAKE; }
static long   voter_vote_ts( ulong i ) { return voter_has_bls( i ) ? VOTE_TS_PAST : VOTE_TS_FUTURE; }
static ushort voter_commission( ulong i ) { return (ushort)(100U*(i+1U)); }

/* ---------------------------------------------------------------- */
/* sysvar / bank setup                                              */
/* ---------------------------------------------------------------- */

static void
init_rent_sysvar( test_env_t * env ) {
  fd_rent_t rent = { .lamports_per_uint8_year = 3480UL, .exemption_threshold = 2.0, .burn_percent = 50 };
  env->bank->f.rent = rent;
  fd_sysvar_rent_write( env->bank, env->accdb, &env->xid, NULL, &rent );
}

static void
init_epoch_schedule_sysvar( test_env_t * env ) {
  fd_epoch_schedule_t epoch_schedule = {
    .slots_per_epoch             = TEST_SLOTS_PER_EPOCH,
    .leader_schedule_slot_offset = TEST_SLOTS_PER_EPOCH,
    .warmup                      = 0,
    .first_normal_epoch          = 0UL,
    .first_normal_slot           = 0UL
  };
  env->bank->f.epoch_schedule = epoch_schedule;
  fd_sysvar_epoch_schedule_write( env->bank, env->accdb, &env->xid, NULL, &epoch_schedule );
}

static void
init_blockhash_queue( test_env_t * env ) {
  fd_blockhashes_t * bhq = fd_blockhashes_init( &env->bank->f.block_hash_queue, 12345UL );
  fd_hash_t dummy_hash = {0};
  fd_memset( dummy_hash.uc, 0xAB, FD_HASH_FOOTPRINT );
  fd_blockhash_info_t * info = fd_blockhashes_push_new( bhq, &dummy_hash );
  info->lamports_per_signature = 0UL;
}

/* ---------------------------------------------------------------- */
/* account helpers                                                  */
/* ---------------------------------------------------------------- */

/* Mint (or overwrite) a V4 vote account.  has_bls controls whether a
   BLS pubkey is present (VAT eligibility); last_vote_{slot,ts} seed the
   account's last vote used by the clock. */
static void
put_vote_account_v4( test_env_t *        env,
                     fd_pubkey_t const * vote_account,
                     fd_pubkey_t const * node_pubkey,
                     ushort              commission_bps,
                     ulong               lamports,
                     int                 has_bls,
                     ulong               last_vote_slot,
                     long                last_vote_ts ) {
  uchar vote_state_data[ FD_VOTE_STATE_V4_SZ ] = {0};

  fd_vote_state_versioned_t versioned[1];
  FD_TEST( fd_vote_state_versioned_new( versioned, fd_vote_state_versioned_enum_v4 ) );

  fd_vote_state_v4_t * vs = &versioned->v4;
  vs->node_pubkey                      = *node_pubkey;
  vs->authorized_withdrawer            = *node_pubkey;
  vs->inflation_rewards_collector      = *vote_account;
  vs->block_revenue_collector          = *node_pubkey;
  vs->inflation_rewards_commission_bps = commission_bps;
  vs->has_bls_pubkey_compressed        = (uchar)( !!has_bls );
  if( has_bls ) fd_memset( vs->bls_pubkey_compressed, 0xBB, FD_BLS_PUBKEY_COMPRESSED_SZ );
  vs->last_timestamp = (fd_vote_block_timestamp_t){ .slot = last_vote_slot, .timestamp = last_vote_ts };

  fd_vote_authorized_voter_t * voter = fd_vote_authorized_voters_pool_ele_acquire( vs->authorized_voters.pool );
  fd_memset( voter, 0, sizeof(fd_vote_authorized_voter_t) );
  voter->epoch  = 0UL;
  voter->pubkey = *node_pubkey;
  voter->prio   = node_pubkey->uc[0];
  fd_vote_authorized_voters_treap_ele_insert( vs->authorized_voters.treap, voter, vs->authorized_voters.pool );

  FD_TEST( !fd_vote_state_versioned_serialize( versioned, vote_state_data, sizeof(vote_state_data) ) );

  fd_accdb_rw_t rw[1];
  FD_TEST( fd_accdb_open_rw( env->accdb, rw, &env->xid, vote_account, sizeof(vote_state_data), FD_ACCDB_FLAG_CREATE ) );
  fd_accdb_ref_data_set( env->accdb, rw, vote_state_data, sizeof(vote_state_data) );
  fd_accdb_ref_lamports_set( rw, lamports );
  fd_accdb_ref_exec_bit_set( rw, 0 );
  fd_memcpy( rw->meta->owner, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) );
  fd_accdb_close_rw( env->accdb, rw );
}

static void
add_delegated_stake_account( test_env_t *        env,
                             fd_pubkey_t const * stake_account,
                             fd_pubkey_t const * vote_account,
                             ulong               stake ) {
  fd_accdb_rw_t rw[1];
  FD_TEST( fd_accdb_open_rw( env->accdb, rw, &env->xid, stake_account, FD_STAKE_STATE_SZ, FD_ACCDB_FLAG_CREATE ) );
  fd_accdb_ref_lamports_set( rw, stake + VOTE_ACCOUNT_LAMPORTS );
  fd_accdb_ref_exec_bit_set( rw, 0 );
  fd_memcpy( rw->meta->owner, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) );
  fd_accdb_ref_data_sz_set( env->accdb, rw, FD_STAKE_STATE_SZ, 0 );
  FD_STORE( fd_stake_state_t, fd_accdb_ref_data( rw ), ((fd_stake_state_t) {
    .stake_type = FD_STAKE_STATE_STAKE,
    .stake = {
      .meta = { .staker = *stake_account, .withdrawer = *stake_account },
      .stake = {
        .delegation = {
          .voter_pubkey         = *vote_account,
          .stake                = stake,
          .activation_epoch     = 0UL,
          .deactivation_epoch   = (ulong)-1,
          .warmup_cooldown_rate = 0.25
        }
      }
    }
  }) );
  fd_accdb_close_rw( env->accdb, rw );
}

static void
add_bank_stake_delegation_entry( test_env_t *        env,
                                 fd_pubkey_t const * stake_account,
                                 fd_pubkey_t const * vote_account,
                                 ulong               stake ) {
  fd_stake_delegations_t * stake_delegations = fd_bank_stake_delegations_modify( env->bank );
  fd_stake_delegations_fork_update( stake_delegations,
                                    env->bank->stake_delegations_fork_id,
                                    stake_account, vote_account,
                                    stake, 0UL, ULONG_MAX, 0UL,
                                    FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
}

static void
add_feature_account( test_env_t * env, fd_feature_id_t const * id, ulong activation_slot ) {
  fd_feature_t feature = { .is_active = 1, .activation_slot = activation_slot };
  uchar feature_data[ sizeof(fd_feature_t) ];
  fd_memcpy( feature_data, &feature, sizeof(feature) );
  fd_accdb_rw_t rw[1];
  FD_TEST( fd_accdb_open_rw( env->accdb, rw, &env->xid, &id->id, sizeof(feature_data), FD_ACCDB_FLAG_CREATE ) );
  fd_accdb_ref_data_set( env->accdb, rw, feature_data, sizeof(feature_data) );
  fd_accdb_ref_lamports_set( rw, 1UL );
  fd_accdb_ref_exec_bit_set( rw, 0 );
  fd_memcpy( rw->meta->owner, fd_solana_feature_program_id.key, sizeof(fd_pubkey_t) );
  fd_accdb_close_rw( env->accdb, rw );
}

static void
enable_feature( test_env_t * env, ulong byte_offset, ulong activation_slot ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init(); !fd_feature_iter_done( id ); id = fd_feature_iter_next( id ) ) {
    if( id->index == (byte_offset>>3) ) { add_feature_account( env, id, activation_slot ); return; }
  }
  FD_LOG_ERR(( "feature id not found" ));
}

/* (Re)write every voter's vote account so its cached last vote points at
   the first slot of `for_epoch` (kept non-delinquent for the clock check
   at that epoch). */
static void
prep_votes( test_env_t * env, ulong for_epoch ) {
  ulong slot0 = for_epoch * TEST_SLOTS_PER_EPOCH;
  for( ulong i=0UL; i<NUM_VOTERS; i++ ) {
    fd_pubkey_t v = vote_key( i );
    put_vote_account_v4( env, &v, &v, voter_commission( i ), VOTE_ACCOUNT_LAMPORTS,
                         voter_has_bls( i ), slot0, voter_vote_ts( i ) );
  }
}

/* ---------------------------------------------------------------- */
/* env lifecycle                                                    */
/* ---------------------------------------------------------------- */

static test_env_t *
test_env_create( test_env_t * env, fd_wksp_t * wksp ) {
  fd_memset( env, 0, sizeof(test_env_t) );
  env->wksp = wksp;
  env->tag  = 1UL;

  ulong const txn_max         = 8UL;
  ulong const rec_max         = 256UL;
  ulong const max_total_banks = 8UL;
  ulong const max_fork_width  = 4UL;

  env->funk_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_shmem_footprint( txn_max, rec_max ), env->tag );
  FD_TEST( env->funk_mem );
  env->funk_locks = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_locks_footprint( txn_max, rec_max ), env->tag );
  FD_TEST( env->funk_locks );
  FD_TEST( fd_funk_shmem_new( env->funk_mem, env->tag, 17UL, txn_max, rec_max ) );
  FD_TEST( fd_funk_locks_new( env->funk_locks, txn_max, rec_max ) );

  FD_TEST( fd_accdb_admin_v1_init( env->accdb_admin, env->funk_mem, env->funk_locks ) );
  FD_TEST( fd_accdb_user_v1_init( env->accdb, env->funk_mem, env->funk_locks, txn_max ) );

  void * banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( max_total_banks, max_fork_width, 2048UL, 2048UL ), env->tag );
  FD_TEST( banks_mem );
  env->banks = fd_banks_join( fd_banks_new( banks_mem, max_total_banks, max_fork_width, 2048UL, 2048UL, 0, 8888UL ) );
  FD_TEST( env->banks );

  env->bank = fd_banks_init_bank( env->banks );
  FD_TEST( env->bank );
  env->bank->f.slot                 = 1UL;
  env->bank->f.epoch                = 1UL;
  env->bank->f.genesis_creation_time = (ulong)GENESIS_CREATION_TIME;
  env->bank->f.ns_per_slot          = (fd_w_u128_t){ .ud = (uint128)NS_PER_SLOT };
  env->bank->f.ticks_per_slot       = 64UL;

  env->runtime_stack = fd_wksp_alloc_laddr( wksp, fd_runtime_stack_align(), fd_runtime_stack_footprint( 2048UL, 2048UL, 2048UL ), env->tag );
  FD_TEST( env->runtime_stack );
  FD_TEST( fd_runtime_stack_join( fd_runtime_stack_new( env->runtime_stack, 2048UL, 2048UL, 2048UL, 999UL ) ) );

  fd_funk_txn_xid_t root[1];
  fd_funk_txn_xid_set_root( root );
  env->xid = fd_bank_xid( env->bank );
  fd_accdb_attach_child( env->accdb_admin, root, &env->xid );

  init_rent_sysvar( env );
  init_epoch_schedule_sysvar( env );
  fd_sysvar_stake_history_init( env->bank, env->accdb, &env->xid, NULL );
  fd_sysvar_clock_init( env->bank, env->accdb, &env->xid, NULL );
  init_blockhash_queue( env );

  fd_bank_top_votes_t_2_modify( env->bank );
  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( env->bank );
  fd_vote_stakes_reset( vote_stakes );

  fd_stake_delegations_t * stake_delegations = fd_bank_stake_delegations_modify( env->bank );
  env->bank->stake_delegations_fork_id = fd_stake_delegations_new_fork( stake_delegations );

  for( ulong i=0UL; i<NUM_VOTERS; i++ ) {
    fd_pubkey_t v = vote_key( i );
    fd_pubkey_t s = stake_key( i );
    ushort      commission = voter_commission( i );
    ulong       stake      = voter_stake( i );
    put_vote_account_v4( env, &v, &v, commission, VOTE_ACCOUNT_LAMPORTS,
                         voter_has_bls( i ), 0UL, voter_vote_ts( i ) );
    fd_vote_stakes_root_insert_key ( vote_stakes, &v, &v, stake, commission, 0UL );
    fd_vote_stakes_root_update_meta( vote_stakes, &v, &v, stake, commission, 0UL );
    add_delegated_stake_account     ( env, &s, &v, stake );
    add_bank_stake_delegation_entry ( env, &s, &v, stake );
  }

  fd_features_t features = {0};
  fd_features_disable_all( &features );
  env->bank->f.features = features;

  enable_feature( env, offsetof( fd_features_t, delay_commission_updates ),        0UL );
  enable_feature( env, offsetof( fd_features_t, commission_rate_in_basis_points ), 0UL );
  enable_feature( env, offsetof( fd_features_t, warp_timestamp_again ),            0UL );
  enable_feature( env, offsetof( fd_features_t, validator_admission_ticket ),      TEST_VAT_ACTIVATION_SLOT );

  fd_accdb_advance_root( env->accdb_admin, &env->xid );
  return env;
}

static void
test_env_destroy( test_env_t * env ) {
  fd_wksp_free_laddr( env->runtime_stack );
  fd_wksp_free_laddr( env->banks );
  fd_accdb_admin_fini( env->accdb_admin );
  fd_accdb_user_fini( env->accdb );
  fd_wksp_free_laddr( fd_funk_delete( env->funk_mem ) );
  fd_wksp_free_laddr( env->funk_locks );
  fd_memset( env, 0, sizeof(test_env_t) );
}

/* ---------------------------------------------------------------- */
/* epoch stepping + inspection                                      */
/* ---------------------------------------------------------------- */

/* Advance one slot.  If prep_epoch!=0, (re)write the voters' cached last
   vote for that epoch into this slot's (still un-rooted) xid so it is
   visible to the next slot's epoch-boundary refresh. */
static void
step_slot( test_env_t * env, ulong prep_epoch ) {
  fd_bank_t * parent_bank = env->bank;
  ulong parent_slot       = parent_bank->f.slot;
  ulong slot              = parent_slot + 1UL;

  FD_TEST( parent_bank->state==FD_BANK_STATE_FROZEN );
  ulong new_bank_idx = fd_banks_new_bank( env->banks, parent_bank->idx, 0L )->idx;
  fd_bank_t * new_bank = fd_banks_clone_from_parent( env->banks, new_bank_idx );
  FD_TEST( new_bank );

  new_bank->f.slot        = slot;
  new_bank->f.parent_slot = parent_slot;
  new_bank->f.epoch       = fd_slot_to_epoch( &new_bank->f.epoch_schedule, slot, NULL );

  fd_funk_txn_xid_t xid        = fd_bank_xid( new_bank    );
  fd_funk_txn_xid_t parent_xid = fd_bank_xid( parent_bank );
  fd_accdb_attach_child( env->accdb_admin, &parent_xid, &xid );

  env->xid  = xid;
  env->bank = new_bank;

  int is_epoch_boundary = 0;
  fd_runtime_block_execute_prepare( env->banks, env->bank, env->accdb, env->runtime_stack, NULL, &is_epoch_boundary );

  if( prep_epoch ) prep_votes( env, prep_epoch );

  fd_banks_mark_bank_frozen( new_bank );
  fd_accdb_advance_root( env->accdb_admin, &xid );
  fd_banks_advance_root( env->banks, new_bank_idx );
}

static ulong
top_votes_t1_cnt( fd_bank_t * bank ) {
  fd_top_votes_t const * tv = fd_bank_top_votes_t_1_query( bank );
  ulong cnt = 0UL;
  uchar __attribute__((aligned(FD_TOP_VOTES_ITER_ALIGN))) iter_mem[ FD_TOP_VOTES_ITER_FOOTPRINT ];
  for( fd_top_votes_iter_t * it = fd_top_votes_iter_init( tv, iter_mem ); !fd_top_votes_iter_done( tv, it ); fd_top_votes_iter_next( tv, it ) ) cnt++;
  return cnt;
}

static int
voter_in_top_votes_t1( fd_bank_t * bank, ulong i ) {
  fd_pubkey_t v = vote_key( i );
  return fd_top_votes_query( fd_bank_top_votes_t_1_query( bank ), &v, NULL, NULL, NULL, NULL, NULL, NULL );
}

static long
clock_delta( test_env_t * env ) {
  fd_sol_sysvar_clock_t clock[1];
  FD_TEST( fd_sysvar_clock_read( env->accdb, &env->xid, clock ) );
  return clock->unix_timestamp - clock->epoch_start_timestamp;
}

/* Advance to the k=1 (second) slot of epoch E.  Voters' cached last
   vote is primed for E at the last slot of E-1 so that the boundary
   refresh seeds the clock's top_votes_t_2 with a non-delinquent vote. */
static void
advance_into_epoch_k1( test_env_t * env, ulong epoch ) {
  ulong boundary = epoch*TEST_SLOTS_PER_EPOCH;          /* first slot of E   */
  while( env->bank->f.slot < boundary-2UL ) step_slot( env, 0UL );
  step_slot( env, epoch );   /* last slot of E-1: prep votes for E */
  step_slot( env, 0UL );     /* boundary slot of E (refresh seeds top_votes_t_2) */
  step_slot( env, 0UL );     /* k=1 slot of E */
  FD_TEST( env->bank->f.epoch==epoch );
  FD_TEST( env->bank->f.slot==boundary+1UL );
}

/* ---------------------------------------------------------------- */
/* tests                                                            */
/* ---------------------------------------------------------------- */

/* total_epoch_stake / top_votes membership before and after VAT
   filtering kicks in. */
#define EXP_TOTAL_STAKE_PRE  (2UL*BASE_STAKE + WHALE_STAKE) /* all voters     */
#define EXP_TOTAL_STAKE_POST (NUM_VAT_ELIGIBLE*BASE_STAKE)  /* eligible only  */

static void
test_vat_transition( fd_wksp_t * wksp ) {
  test_env_t env[1];
  test_env_create( env, wksp );

  for( ulong epoch=2UL; epoch<=TEST_VAT_EPOCH+2UL; epoch++ ) {
    advance_into_epoch_k1( env, epoch );
    fd_bank_t * bank = env->bank;

    int filtered = epoch>=TEST_VAT_EPOCH; /* VAT feature active -> top_votes filtered */

    /* top_votes (leader-schedule / reward set): every valid voter pre-VAT,
       only the BLS voters once VAT is active. */
    FD_TEST( top_votes_t1_cnt( bank )==( filtered ? NUM_VAT_ELIGIBLE : NUM_VOTERS ) );
    for( ulong i=0UL; i<NUM_VOTERS; i++ )
      FD_TEST( voter_in_top_votes_t1( bank, i )==( !filtered || voter_has_bls( i ) ) );

    FD_TEST( bank->f.total_epoch_stake==( filtered ? EXP_TOTAL_STAKE_POST : EXP_TOTAL_STAKE_PRE ) );

    /* Clock stake-weighted timestamp.  It reads the unfiltered
       vote_stakes t-2 snapshot up to and including vat_epoch, and only
       switches to the filtered top_votes_t_2 at vat_epoch+1.  The no-BLS
       whale votes far in the future with a dominant stake, so while it is
       counted the estimate is pinned to the slow drift bound; once it is
       filtered out the eligible (past-voting) accounts pull the estimate
       to the fast bound.  k=1 -> 10s (whale) vs 3s (no whale). */
    long expected_delta = ( epoch>=TEST_VAT_EPOCH+1UL ) ? CLOCK_DELTA_NO_WHALE : CLOCK_DELTA_WHALE;
    FD_TEST( clock_delta( env )==expected_delta );

    /* At the activation epoch, the VAT branch performs the t-1 -> t-2
       carry-forward by hand.  Verify the unfiltered snapshot (including
       the filtered-out whale) lives in the child's t-2 with t-1 empty;
       this is exactly what the clock above reads at vat_epoch. */
    if( epoch==TEST_VAT_EPOCH ) {
      fd_vote_stakes_t * vs       = fd_bank_vote_stakes( bank );
      ushort             fork_idx = bank->vote_stakes_fork_id;
      for( ulong i=0UL; i<NUM_VOTERS; i++ ) {
        fd_pubkey_t v = vote_key( i );
        ulong stake_t_2 = 0UL;
        FD_TEST( !fd_vote_stakes_query_t_1( vs, fork_idx, &v, NULL, NULL, NULL ) );
        FD_TEST(  fd_vote_stakes_query_t_2( vs, fork_idx, &v, &stake_t_2, NULL, NULL ) );
        FD_TEST(  stake_t_2==voter_stake( i ) );
      }
    }

    FD_LOG_NOTICE(( "epoch=%lu top_votes_t1=%lu total_epoch_stake=%lu clock_delta=%ld ok",
                    epoch, top_votes_t1_cnt( bank ), bank->f.total_epoch_stake, clock_delta( env ) ));
  }

  test_env_destroy( env );
  FD_LOG_NOTICE(( "test_vat_transition: ok" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx > fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 2UL );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );
  ulong        page_sz  = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_vat_transition( wksp );

  fd_wksp_delete_anonymous( wksp );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
