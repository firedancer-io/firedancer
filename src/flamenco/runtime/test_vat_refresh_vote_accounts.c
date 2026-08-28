/* Test post-VAT (SIMD-0357) epoch-boundary behavior.  The runtime always
   filters to eligible V4+BLS vote accounts and uses vote stakes for
   historical stake, commission, and clock calculations. */

#define _GNU_SOURCE
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
#include "../accdb/fd_accdb.h"
#include "../accdb/fd_accdb_shmem.h"
#include "../features/fd_features.h"
#include "../stakes/fd_stake_types.h"
#include "../stakes/fd_vote_stakes.h"

#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#define SENTINEL ((fd_accdb_fork_id_t){ .val = USHORT_MAX })

#define TEST_SLOTS_PER_EPOCH (FD_EPOCH_LEN_MIN)
#define TEST_VAT_EPOCH       (3UL)

/* Firedancer derives the clock's slot duration from the slot-time
   feature gates, using a default of 400ms, so the test cannot choose
   an arbitrary slot length.  Instead we measure the clock
   TEST_CLOCK_SLOTS slots into the epoch, where 10 * 400ms = 4s makes
   the drift bounds land on whole seconds:
     poh_offset      = 10 slots * 400ms = 4s
     slow bound 150% = +6s -> unix - epoch_start = 10 (whale counted)
     fast bound  25% = -1s -> unix - epoch_start =  3 (whale filtered)
   (TEST_SLOTS_PER_EPOCH must exceed TEST_CLOCK_SLOTS so k stays
   within the epoch.) */
#define TEST_CLOCK_SLOTS      (10UL)
#define CLOCK_DELTA_WHALE     (10L) /* slow-bound at k=TEST_CLOCK_SLOTS (poh_offset 4s) */
#define CLOCK_DELTA_NO_WHALE  (3L)  /* fast-bound at k=TEST_CLOCK_SLOTS (poh_offset 4s) */

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
  fd_accdb_t *         accdb;
  void *               accdb_shmem;
  void *               accdb_join;
  int                  accdb_fd;
  fd_runtime_stack_t * runtime_stack;
};
typedef struct test_env test_env_t;

static fd_pubkey_t vote_key ( ulong i ) { return (fd_pubkey_t){ .ul[0] = 0x100UL + i }; }
static fd_pubkey_t stake_key( ulong i ) { return (fd_pubkey_t){ .ul[0] = 0x200UL + i }; }

/* Which voters carry a BLS pubkey (VAT-eligible).  Default: the first
   NUM_VAT_ELIGIBLE.  bls_mask lets a test override per-voter (bit i set
   -> voter i has a BLS pubkey), so the "whale" can be made VAT-eligible
   for the invalidate/revalidate scenario. */
static int  bls_mask_override = 0;   /* 0 -> use default rule */
static uint bls_mask_bits     = 0u;

static int    voter_has_bls( ulong i ) { return bls_mask_override ? !!( bls_mask_bits & (1u<<i) ) : ( i<NUM_VAT_ELIGIBLE ); }
static long   voter_vote_ts( ulong i ) { return ( i==NUM_VOTERS-1UL ) ? VOTE_TS_FUTURE : VOTE_TS_PAST; }
static ushort voter_commission( ulong i ) { return (ushort)(100U*(i+1U)); }

/* Per-voter base stake (whale dominates).  Each voter's delegated stake
   for a given epoch is this base plus a distinct per-epoch bump, so the
   stake snapshot referenced by each consumer (t-1 for vote stakes /
   total_epoch_stake, t-2 for the clock) is unique per epoch and any
   mix-up between snapshots is observable.

   The bump is deliberately small relative to the stakes so it never
   reorders the whale below the small voters (the clock's dominant-stake
   assumption is preserved). */
static ulong  voter_base_stake( ulong i ) { return ( i==NUM_VOTERS-1UL ) ? WHALE_STAKE : BASE_STAKE; }
#define STAKE_EPOCH_BUMP (1000000UL) /* 0.001 SOL per epoch, << BASE_STAKE */
static ulong  stake_for_epoch( ulong i, ulong epoch ) { return voter_base_stake( i ) + epoch*STAKE_EPOCH_BUMP; }

/* Genesis stake used to seed the root vote-stakes sets before the first
   boundary.  Treated as "epoch 0" stake. */
static ulong  voter_stake( ulong i ) { return stake_for_epoch( i, 0UL ); }

/* ---------------------------------------------------------------- */
/* sysvar / bank setup                                              */
/* ---------------------------------------------------------------- */

static void
init_rent_sysvar( test_env_t * env ) {
  fd_rent_t rent = { .lamports_per_uint8_year = 3480UL, .exemption_threshold = 2.0, .burn_percent = 50 };
  env->bank->f.rent = rent;
  fd_sysvar_rent_write( env->bank, env->accdb, NULL, &rent );
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
  fd_sysvar_epoch_schedule_write( env->bank, env->accdb, NULL, &epoch_schedule );
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

  fd_acc_t acc = fd_accdb_write_one( env->accdb, env->bank->accdb_fork_id, vote_account->uc );
  acc.lamports   = lamports;
  acc.executable = 0;
  fd_memcpy( acc.owner, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) );
  acc.data_len   = sizeof(vote_state_data);
  fd_memcpy( acc.data, vote_state_data, sizeof(vote_state_data) );
  acc.commit     = 1;
  fd_accdb_unwrite_one( env->accdb, &acc );
}

static void
add_delegated_stake_account( test_env_t *        env,
                             fd_pubkey_t const * stake_account,
                             fd_pubkey_t const * vote_account,
                             ulong               stake ) {
  fd_acc_t acc = fd_accdb_write_one( env->accdb, env->bank->accdb_fork_id, stake_account->uc );
  acc.lamports   = stake + VOTE_ACCOUNT_LAMPORTS;
  acc.executable = 0;
  fd_memcpy( acc.owner, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) );
  acc.data_len   = FD_STAKE_STATE_SZ;
  FD_STORE( fd_stake_state_t, acc.data, ((fd_stake_state_t) {
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
  acc.commit     = 1;
  fd_accdb_unwrite_one( env->accdb, &acc );
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
                                    stake + VOTE_ACCOUNT_LAMPORTS,
                                    (uint)FD_STAKE_STATE_SZ,
                                    FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
}

static void
add_feature_account( test_env_t * env, fd_feature_id_t const * id, ulong activation_slot ) {
  fd_feature_t feature = { .is_active = 1, .activation_slot = activation_slot };
  uchar feature_data[ sizeof(fd_feature_t) ];
  fd_memcpy( feature_data, &feature, sizeof(feature) );
  fd_acc_t acc = fd_accdb_write_one( env->accdb, env->bank->accdb_fork_id, id->id.uc );
  acc.lamports   = 1UL;
  acc.executable = 0;
  fd_memcpy( acc.owner, fd_solana_feature_program_id.key, sizeof(fd_pubkey_t) );
  acc.data_len   = sizeof(feature_data);
  fd_memcpy( acc.data, feature_data, sizeof(feature_data) );
  acc.commit     = 1;
  fd_accdb_unwrite_one( env->accdb, &acc );
}

static void
enable_feature( test_env_t * env, ulong byte_offset, ulong activation_slot ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init(); !fd_feature_iter_done( id ); id = fd_feature_iter_next( id ) ) {
    if( id->index == (byte_offset>>3) ) { add_feature_account( env, id, activation_slot ); return; }
  }
  FD_LOG_ERR(( "feature id not found" ));
}

/* Prep state for the upcoming epoch `for_epoch`, written into the
   current (still un-rooted) slot so the next boundary refresh sees it:
     - rewrite each voter's vote account (cached last vote -> first slot
       of for_epoch, so it is non-delinquent for the clock), and
     - set each voter's delegated stake (account + cache) to the
       per-epoch value.  This becomes the t-1 effective stake for the
       boundary into for_epoch. */
static void
prep_votes( test_env_t * env, ulong for_epoch ) {
  ulong slot0 = for_epoch * TEST_SLOTS_PER_EPOCH;
  for( ulong i=0UL; i<NUM_VOTERS; i++ ) {
    fd_pubkey_t v = vote_key( i );
    fd_pubkey_t s = stake_key( i );
    ulong       stake = stake_for_epoch( i, for_epoch );
    put_vote_account_v4( env, &v, &v, voter_commission( i ), VOTE_ACCOUNT_LAMPORTS,
                         voter_has_bls( i ), slot0, voter_vote_ts( i ) );
    add_delegated_stake_account    ( env, &s, &v, stake );
    add_bank_stake_delegation_entry( env, &s, &v, stake );
  }
}

/* Flip a vote account's owner to the system program, which makes it fail
   fd_vsv_is_correct_size_owner_and_init() exactly as if the account had
   been closed and recreated as a non-vote account.  This invalidates it
   in the vote-stakes clock path.  Setting `valid` restores the vote-program
   owner. */
static void
set_vote_account_owner_valid( test_env_t * env, ulong i, int valid ) {
  fd_pubkey_t v = vote_key( i );
  /* Open the existing account; write_one returns its current fields, so
     lamports/data are preserved and we only overwrite the owner. */
  fd_acc_t acc = fd_accdb_write_one( env->accdb, env->bank->accdb_fork_id, v.uc );
  fd_memcpy( acc.owner,
             valid ? fd_solana_vote_program_id.key : fd_solana_system_program_id.key,
             sizeof(fd_pubkey_t) );
  acc.commit = 1;
  fd_accdb_unwrite_one( env->accdb, &acc );
}

/* ---------------------------------------------------------------- */
/* env lifecycle                                                    */
/* ---------------------------------------------------------------- */

/* The new accdb dispatches advance_root/purge work to a background
   thread (T2) and attach_child spins (wait_cmd) until that work
   completes.  This test is single-threaded, so pump the background work
   on the calling thread after each command-issuing op. */
static void
drain_background( fd_accdb_t * accdb ) {
  int charge_busy = 0;
  fd_accdb_background( accdb, &charge_busy );
}

static test_env_t *
test_env_create( test_env_t * env, fd_wksp_t * wksp ) {
  fd_memset( env, 0, sizeof(test_env_t) );
  env->wksp = wksp;
  env->tag  = 1UL;

  ulong const max_total_banks = 8UL;
  ulong const max_fork_width  = 4UL;

  /* accdb sizing -- kept small; this is a unit test. */
  ulong const accdb_max_accounts   = 1024UL;
  ulong const accdb_max_live_slots = 16UL;
  ulong const accdb_writes_per_slot = 256UL;
  ulong const accdb_partition_cnt  = 8UL;
  ulong const accdb_partition_sz   = 1UL<<26UL; /* 64 MiB */
  ulong const accdb_cache_footprint   = 4UL<<30UL; /* 4 GiB (cache minimum) */
  ulong const accdb_cache_min_reserved = fd_accdb_cache_min_reserved( 0 );
  ulong const accdb_joiner_cnt     = 1UL;

  ulong accdb_shmem_sz = fd_accdb_shmem_footprint( accdb_max_accounts, accdb_max_live_slots,
                                                   accdb_writes_per_slot, accdb_partition_cnt,
                                                   accdb_cache_footprint, accdb_cache_min_reserved,
                                                   accdb_joiner_cnt, 0UL );
  ulong accdb_join_sz  = fd_accdb_footprint( accdb_max_live_slots );

  env->accdb_shmem = fd_wksp_alloc_laddr( wksp, fd_accdb_shmem_align(), accdb_shmem_sz, env->tag );
  FD_TEST( env->accdb_shmem );
  env->accdb_join  = fd_wksp_alloc_laddr( wksp, fd_accdb_align(), accdb_join_sz, env->tag );
  FD_TEST( env->accdb_join );

  env->accdb_fd = memfd_create( "vat_test", 0 );
  if( FD_UNLIKELY( env->accdb_fd<0 ) ) FD_LOG_ERR(( "memfd_create failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join(
      fd_accdb_shmem_new( env->accdb_shmem, accdb_max_accounts, accdb_max_live_slots,
                          accdb_writes_per_slot, accdb_partition_cnt, accdb_partition_sz,
                          accdb_cache_footprint, accdb_cache_min_reserved, 0, 42UL, accdb_joiner_cnt, 0UL ) );
  FD_TEST( shmem );
  env->accdb = fd_accdb_join( fd_accdb_new( env->accdb_join, shmem, env->accdb_fd, 0UL, NULL ) );
  FD_TEST( env->accdb );

  void * banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( max_total_banks, max_fork_width, 2048UL, 32768UL, 2048UL ), env->tag );
  FD_TEST( banks_mem );
  env->banks = fd_banks_join( fd_banks_new( banks_mem, max_total_banks, max_fork_width, 2048UL, 32768UL, 2048UL, 0, 8888UL ) );
  FD_TEST( env->banks );

  env->bank = fd_banks_init_bank( env->banks );
  FD_TEST( env->bank );
  env->bank->f.slot                    = 1UL;
  env->bank->f.epoch                   = 1UL;
  env->bank->f.genesis_creation_time   = (ulong)GENESIS_CREATION_TIME;
  env->bank->f.slot_params             = FD_SLOT_PARAMS_400MS;
  env->bank->f.slot_params_default     = FD_SLOT_PARAMS_400MS;
  env->bank->f.ticks_per_slot          = 64UL;

  env->runtime_stack = fd_wksp_alloc_laddr( wksp, fd_runtime_stack_align(), fd_runtime_stack_footprint( 2048UL, 2048UL, 2048UL ), env->tag );
  FD_TEST( env->runtime_stack );
  FD_TEST( fd_runtime_stack_join( fd_runtime_stack_new( env->runtime_stack, 2048UL, 2048UL, 2048UL, 999UL ) ) );

  env->bank->accdb_fork_id = fd_accdb_attach_child( env->accdb, SENTINEL );

  init_rent_sysvar( env );
  init_epoch_schedule_sysvar( env );
  fd_sysvar_stake_history_init( env->bank, env->accdb, NULL );
  fd_sysvar_clock_init( env->bank, env->accdb, NULL );
  init_blockhash_queue( env );

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( env->bank );
  fd_vote_stakes_reset( vote_stakes );
  env->bank->vote_stakes_fork_id = fd_vote_stakes_init( vote_stakes, env->bank->f.epoch );
  ulong fork_id = env->bank->vote_stakes_fork_id;

  fd_stake_delegations_t * stake_delegations = fd_bank_stake_delegations_modify( env->bank );
  env->bank->stake_delegations_fork_id = fd_stake_delegations_new_fork( stake_delegations );

  for( ulong i=0UL; i<NUM_VOTERS; i++ ) {
    fd_pubkey_t v = vote_key( i );
    fd_pubkey_t s = stake_key( i );
    ushort      commission = voter_commission( i );
    ulong       stake      = voter_stake( i );
    put_vote_account_v4( env, &v, &v, commission, VOTE_ACCOUNT_LAMPORTS,
                         voter_has_bls( i ), 0UL, voter_vote_ts( i ) );
    if( voter_has_bls( i ) ) {
      /* Match the 0xBB key pattern put_vote_account_v4 writes into the
         account data. */
      uchar bls[ FD_BLS_PUBKEY_COMPRESSED_SZ ];
      fd_memset( bls, 0xBB, sizeof(bls) );
      fd_vote_stakes_snap_insert_t_1( vote_stakes, fork_id, &v, &v, stake, commission, bls );
      fd_vote_stakes_snap_insert_t_2( vote_stakes, fork_id, &v, &v, stake, commission, bls );
      fd_vote_stakes_update_state( vote_stakes, fork_id, &v, 0UL, voter_vote_ts( i ), 1 );
    }
    add_delegated_stake_account     ( env, &s, &v, stake );
    add_bank_stake_delegation_entry ( env, &s, &v, stake );
  }

  fd_features_t features = {0};
  fd_features_disable_all( &features );
  env->bank->f.features = features;

  enable_feature( env, offsetof( fd_features_t, delay_commission_updates ),        0UL );
  enable_feature( env, offsetof( fd_features_t, commission_rate_in_basis_points ), 0UL );

  /* The fork created by attach_child(SENTINEL) is already the root; it
     must not be advance_root'd (its parent is the sentinel, not a prior
     root).  Genesis state is written directly onto it above. */
  return env;
}

static void
test_env_destroy( test_env_t * env ) {
  fd_wksp_free_laddr( env->runtime_stack );
  fd_wksp_free_laddr( env->banks );
  fd_wksp_free_laddr( env->accdb_join );
  fd_wksp_free_laddr( env->accdb_shmem );
  if( FD_LIKELY( env->accdb_fd>=0 ) ) close( env->accdb_fd );
  fd_memset( env, 0, sizeof(test_env_t) );
}

/* ---------------------------------------------------------------- */
/* epoch stepping + inspection                                      */
/* ---------------------------------------------------------------- */

/* Optional owner-flip applied inside step_slot (in the same un-rooted
   xid as prep_votes) when flip_i>=0. */
static long flip_i_pending     = -1L;
static int  flip_valid_pending = 0;

/* Advance one slot.  If prep_epoch!=0, (re)write the voters' cached last
   vote for that epoch into this slot's (still un-rooted) xid so it is
   visible to the next slot's epoch-boundary refresh.  Any pending owner
   flip is applied in the same xid, after the vote prep. */
static void
step_slot( test_env_t * env, ulong prep_epoch ) {
  fd_bank_t * parent_bank = env->bank;
  ulong parent_slot       = parent_bank->f.slot;
  ulong slot              = parent_slot + 1UL;

  FD_TEST( parent_bank->state==FD_BANK_STATE_FROZEN );
  ulong new_bank_idx = fd_banks_new_bank( env->banks, parent_bank->idx, 0L, 0 )->idx;
  fd_bank_t * new_bank = fd_banks_clone_from_parent( env->banks, new_bank_idx );
  FD_TEST( new_bank );

  new_bank->f.slot        = slot;
  new_bank->f.parent_slot = parent_slot;
  new_bank->f.epoch       = fd_slot_to_epoch( &new_bank->f.epoch_schedule, slot, NULL );

  new_bank->accdb_fork_id = fd_accdb_attach_child( env->accdb, parent_bank->accdb_fork_id );

  env->bank = new_bank;

  int is_epoch_boundary = 0;
  fd_runtime_block_execute_prepare( env->banks, env->bank, env->accdb, env->runtime_stack, NULL, &is_epoch_boundary );

  if( prep_epoch ) prep_votes( env, prep_epoch );
  if( flip_i_pending>=0L ) {
    set_vote_account_owner_valid( env, (ulong)flip_i_pending, flip_valid_pending );
    flip_i_pending = -1L;
  }

  fd_banks_mark_bank_frozen( new_bank );
  fd_accdb_advance_root( env->accdb, new_bank->accdb_fork_id );
  drain_background( env->accdb );
  fd_banks_advance_root( env->banks, new_bank_idx );
}

static ulong
vote_stakes_t1_cnt( fd_bank_t * bank ) {
  return fd_vote_stakes_cnt_t_1( fd_bank_vote_stakes( bank ), bank->vote_stakes_fork_id );
}

static long
clock_delta( test_env_t * env ) {
  fd_sol_sysvar_clock_t clock[1];
  FD_TEST( fd_sysvar_clock_read( env->accdb, env->bank->accdb_fork_id, clock ) );
  return clock->unix_timestamp - clock->epoch_start_timestamp;
}

/* Advance to slot k=TEST_CLOCK_SLOTS of epoch E, so that the POH offset
   is a whole number of seconds.  Voters' cached last vote is primed
   for E at the last slot of E-1 so that the boundary refresh seeds
   the clock's t-2 vote stakes with a non-delinquent
   vote. */
static void
advance_into_epoch( test_env_t * env, ulong epoch ) {
  ulong boundary = epoch*TEST_SLOTS_PER_EPOCH;          /* first slot of E   */
  while( env->bank->f.slot < boundary-2UL ) step_slot( env, 0UL );
  step_slot( env, epoch );   /* last slot of E-1: prep votes for E */
  step_slot( env, 0UL );     /* boundary slot of E (refresh seeds t-2 vote stakes) */
  for( ulong k=0UL; k<TEST_CLOCK_SLOTS; k++ ) step_slot( env, 0UL ); /* advance to slot k=TEST_CLOCK_SLOTS of E */
  FD_TEST( env->bank->f.epoch==epoch );
  FD_TEST( env->bank->f.slot==boundary+TEST_CLOCK_SLOTS );
}

/* Like advance_into_epoch, but additionally flips voter `flip_i`'s
   validity (vote-program owner) at the last slot of E-1, before the
   epoch-E boundary refresh runs.  This models a vote account being
   closed/recreated as a non-vote account (set_valid=0) or restored
   (set_valid=1) right before the boundary. */
static void
advance_into_epoch_flip( test_env_t * env, ulong epoch, ulong flip_i, int set_valid ) {
  ulong boundary = epoch*TEST_SLOTS_PER_EPOCH;
  while( env->bank->f.slot < boundary-2UL ) step_slot( env, 0UL );

  /* Last slot of E-1: prep votes for E and (in the same un-rooted xid,
     after the vote prep) flip the chosen voter's owner. */
  flip_i_pending     = (long)flip_i;
  flip_valid_pending = set_valid;
  step_slot( env, epoch );

  step_slot( env, 0UL );     /* boundary slot of E (refresh sees the flip) */
  for( ulong k=0UL; k<TEST_CLOCK_SLOTS; k++ ) step_slot( env, 0UL ); /* advance to slot k=TEST_CLOCK_SLOTS of E */
  FD_TEST( env->bank->f.epoch==epoch );
  FD_TEST( env->bank->f.slot==boundary+TEST_CLOCK_SLOTS );
}

/* ---------------------------------------------------------------- */
/* tests                                                            */
/* ---------------------------------------------------------------- */

/* Sum of the VAT-eligible t-1 effective stakes. */
static ulong
expected_total_epoch_stake( ulong epoch ) {
  ulong sum = 0UL;
  for( ulong i=0UL; i<NUM_VOTERS; i++ )
    if( voter_has_bls( i ) ) sum += stake_for_epoch( i, epoch );
  return sum;
}

static void
test_vat_path_unconditional( fd_wksp_t * wksp ) {
  test_env_t env[1];
  test_env_create( env, wksp );

  /* The runtime only supports post-VAT banks. */
  ulong const epoch = TEST_VAT_EPOCH-1UL;
  advance_into_epoch( env, epoch );
  FD_TEST( vote_stakes_t1_cnt( env->bank )==NUM_VAT_ELIGIBLE );
  for( ulong i=0UL; i<NUM_VOTERS; i++ ) {
    fd_pubkey_t v = vote_key( i );
    ulong stake = 0UL;
    int found = fd_vote_stakes_query_t_1( fd_bank_vote_stakes( env->bank ), env->bank->vote_stakes_fork_id, &v, NULL, &stake, NULL );
    FD_TEST( found==voter_has_bls( i ) );
    if( found ) FD_TEST( stake==stake_for_epoch( i, epoch ) );
  }
  FD_TEST( env->bank->f.total_epoch_stake==expected_total_epoch_stake( epoch ) );
  FD_TEST( clock_delta( env )==CLOCK_DELTA_NO_WHALE );

  test_env_destroy( env );
}

/* Whether the whale's last vote made it into the clock this epoch,
   inferred from the stake-weighted timestamp: 10s when the dominant
   future-voting whale is counted, 3s when it is not. */
static int
whale_counted_in_clock( test_env_t * env ) {
  long d = clock_delta( env );
  if( d==CLOCK_DELTA_WHALE )    return 1;
  if( d==CLOCK_DELTA_NO_WHALE ) return 0;
  FD_LOG_ERR(( "unexpected clock_delta=%ld", d ));
  return -1;
}

/* Invalidate then revalidate a vote account across epochs and observe
   the clock react, while VAT is active.

   All three voters (including the dominant-stake, future-voting whale)
   carry a BLS pubkey, so the whale survives VAT filtering and lives in
   the t-2 vote-stakes set the clock reads from vat_epoch+1 on.

   The vote-stakes sets are a two-epoch pipeline (t-1 built this epoch,
   promoted to t-2 next epoch).  A vote account that stops parsing is
   marked invalid in the live t-2 set (not evicted), and -- because the
   invalid account is not re-inserted into t-1 -- the exclusion then
   propagates as t-1 is promoted to t-2.  Recreating the account makes it
   eligible for t-1 again, and it re-enters t-2 one epoch later.  So:

     vat+1: whale valid                       -> counted (delta 10)
     vat+2: whale invalidated before boundary -> in t-2 but invalid -> dropped (delta 3)
     vat+3: whale valid again, but absent from t-2 (pipeline) -> still dropped (delta 3)
     vat+4: whale back in t-2 and valid       -> counted again (delta 10) */
static void
test_vat_invalidate_revalidate( fd_wksp_t * wksp ) {
  /* All voters BLS-eligible (set before genesis seeding) so the whale is
     retained under VAT and lives in t-2 vote stakes. */
  bls_mask_override = 1;
  bls_mask_bits     = (1u<<NUM_VOTERS)-1u;

  test_env_t env[1];
  test_env_create( env, wksp ); /* vat_epoch = 3 */

  ulong const whale = NUM_VOTERS-1UL;

  /* vat+1: first epoch the clock reads the filtered t-2 vote stakes.
     Whale present, valid, counted. */
  advance_into_epoch( env, TEST_VAT_EPOCH+1UL );
  FD_TEST( vote_stakes_t1_cnt( env->bank )==NUM_VOTERS );
  FD_TEST( whale_counted_in_clock( env )==1 );

  /* vat+2: whale closed/recreated as a non-vote account right before the
     boundary.  Its t-2 vote-stakes entry is marked invalid (still present)
     and the clock drops it. */
  advance_into_epoch_flip( env, TEST_VAT_EPOCH+2UL, whale, 0 /*invalid*/ );
  FD_TEST( whale_counted_in_clock( env )==0 );

  /* vat+3: whale restored to a valid vote account, but it has been
     flushed out of the t-2 snapshot by the pipeline, so it is still not
     counted this epoch. */
  advance_into_epoch_flip( env, TEST_VAT_EPOCH+3UL, whale, 1 /*valid*/ );
  FD_TEST( whale_counted_in_clock( env )==0 );

  /* vat+4: whale has re-entered t-2 and is valid -> counted again. */
  advance_into_epoch( env, TEST_VAT_EPOCH+4UL );
  FD_TEST( whale_counted_in_clock( env )==1 );

  bls_mask_override = 0;
  test_env_destroy( env );
  FD_LOG_NOTICE(( "test_vat_invalidate_revalidate: ok" ));
}

static void
test_runtime_stack_stake_accum_map_sizing( fd_wksp_t * wksp ) {
  ulong const max_vote_accounts        = 4UL;
  ulong const max_staked_vote_accounts = 256UL;
  ulong const max_stake_accounts       = 1UL;
  ulong const footprint = fd_runtime_stack_footprint( max_vote_accounts,
                                                      max_staked_vote_accounts,
                                                      max_stake_accounts );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_runtime_stack_align(), footprint, 1234UL );
  FD_TEST( mem );
  fd_runtime_stack_t * stack = fd_runtime_stack_join(
      fd_runtime_stack_new( mem,
                            max_vote_accounts,
                            max_staked_vote_accounts,
                            max_stake_accounts,
                            999UL ) );
  FD_TEST( stack );
  FD_TEST( fd_stake_accum_map_chain_cnt( stack->stakes.stake_accum_map )==
           fd_stake_accum_map_chain_cnt_est( max_staked_vote_accounts ) );
  fd_wksp_free_laddr( mem );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx > fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 6UL );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );
  ulong        page_sz  = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_runtime_stack_stake_accum_map_sizing( wksp );
  test_vat_path_unconditional( wksp );
  test_vat_invalidate_revalidate( wksp );

  fd_wksp_delete_anonymous( wksp );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
