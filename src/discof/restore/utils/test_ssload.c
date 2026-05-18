#include "fd_ssload.h"
#include "../../../util/fd_util.h"
#include "../../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include <limits.h>

/* Use generous runtime limits so that tests exercise the manifest
   array bounds (FD_VOTE_ACCOUNTS_MAX, FD_STAKE_DELEGATIONS_MAX, etc.)
   rather than the runtime capacity limits. */
#define TEST_MAX_VOTE_ACCOUNTS  ULONG_MAX
#define TEST_MAX_STAKE_ACCOUNTS ULONG_MAX

/* Shorthand for the common validate call pattern. */
#define VALIDATE_MANIFEST(m) fd_ssload_manifest_validate( (m), TEST_MAX_VOTE_ACCOUNTS, TEST_MAX_STAKE_ACCOUNTS )

/* Set up the minimum valid manifest state so that all validation
   stages can be reached.  Adds 1 blockhash with hash_index=0 and
   sets valid epoch schedule params.
   With defaults (slot=0, warmup=0, first_normal_epoch=0,
   first_normal_slot=0): epoch=0, leader_schedule_epoch=1,
   epoch_stakes_base=0, t_1_idx=1 (valid). */
static void
setup_valid_manifest_base( fd_snapshot_manifest_t * manifest ) {
  manifest->blockhashes_len = 1UL;
  manifest->blockhashes[0].hash_index = 0UL;
  manifest->epoch_schedule_params.slots_per_epoch             = 432000UL;
  manifest->epoch_schedule_params.leader_schedule_slot_offset = 432000UL;
}

/* Positive tests — verify that a valid base manifest passes. */

static void
test_valid_base_manifest( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing valid base manifest" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );
  FD_LOG_NOTICE(( "... pass" ));
}

/* Epoch schedule sanity tests */

static void
test_epoch_schedule_min_slots_per_epoch( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing epoch schedule exactly min slots_per_epoch" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->epoch_schedule_params.slots_per_epoch             = FD_EPOCH_LEN_MIN;
  manifest->epoch_schedule_params.leader_schedule_slot_offset = FD_EPOCH_LEN_MIN;

  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_epoch_schedule_zero_slots_per_epoch( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing epoch schedule zero slots_per_epoch" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->epoch_schedule_params.slots_per_epoch = 0UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_epoch_schedule_below_min_slots_per_epoch( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing epoch schedule below min slots_per_epoch" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->epoch_schedule_params.slots_per_epoch = FD_EPOCH_LEN_MIN - 1UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_epoch_schedule_warmup_invalid( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing epoch schedule invalid warmup" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->epoch_schedule_params.warmup = 2;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

/* Blockhash queue validation tests */

static void
test_valid_sorted_blockhashes( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing valid sorted blockhashes" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->blockhashes_len = 3UL;
  manifest->blockhashes[0].hash_index = 0UL;
  manifest->blockhashes[1].hash_index = 1UL;
  manifest->blockhashes[2].hash_index = 2UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_valid_unsorted_blockhashes( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing valid unsorted blockhashes" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->blockhashes_len = 3UL;
  manifest->blockhashes[0].hash_index = 2UL;
  manifest->blockhashes[1].hash_index = 0UL;
  manifest->blockhashes[2].hash_index = 1UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_empty_blockhashes( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing empty blockhashes" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->blockhashes_len = 0UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_blockhash_count_exceeds_max( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing blockhash count exceeds max" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->blockhashes_len = FD_BLOCKHASHES_MAX + 1UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_blockhash_count_at_max( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing blockhash count exactly at max" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->blockhashes_len = FD_BLOCKHASHES_MAX;
  for( ulong i=0UL; i<FD_BLOCKHASHES_MAX; i++ ) {
    manifest->blockhashes[i].hash_index = i;
  }

  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_blockhash_gap( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing blockhash gap" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->blockhashes_len = 3UL;
  manifest->blockhashes[0].hash_index = 0UL;
  manifest->blockhashes[1].hash_index = 1UL;
  manifest->blockhashes[2].hash_index = 3UL; /* gap at 2 */

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_blockhash_duplicate( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing blockhash duplicate" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->blockhashes_len = 3UL;
  manifest->blockhashes[0].hash_index = 0UL;
  manifest->blockhashes[1].hash_index = 1UL;
  manifest->blockhashes[2].hash_index = 1UL; /* duplicate */

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_blockhash_sequence_wraparound( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing blockhash sequence wraparound" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  /* seq_min=ULONG_MAX-1, age_cnt=2, seq_min+age_cnt overflows */
  manifest->blockhashes_len = 2UL;
  manifest->blockhashes[0].hash_index = ULONG_MAX - 1UL;
  manifest->blockhashes[1].hash_index = ULONG_MAX;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_blockhash_single_near_max_index( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing single blockhash with near-max index" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  /* A single blockhash with hash_index=ULONG_MAX-1 should be valid.
     seq_min=ULONG_MAX-1, age_cnt=1, seq_max=ULONG_MAX (no overflow),
     idx=0 (in range).  Previously rejected due to seq_min init of
     ULONG_MAX-1 instead of ULONG_MAX. */
  manifest->blockhashes_len = 1UL;
  manifest->blockhashes[0].hash_index = ULONG_MAX - 1UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_blockhash_single_max_index( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing single blockhash with hash_index=ULONG_MAX" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  /* seq_min=ULONG_MAX, age_cnt=1, seq_max=ULONG_MAX+1 overflows.
     Should be rejected by the wraparound check. */
  manifest->blockhashes_len = 1UL;
  manifest->blockhashes[0].hash_index = ULONG_MAX;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

/* Array bounds validation tests */

static void
test_hard_forks_at_max( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing hard forks exactly at max" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->hard_fork_cnt = FD_HARD_FORKS_MAX;

  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_hard_forks_exceeds_max( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing hard forks exceeds max" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->hard_fork_cnt = FD_HARD_FORKS_MAX + 1UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_stake_delegations_at_max( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing stake delegations exactly at max" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->stake_delegations_len = FD_STAKE_DELEGATIONS_MAX;

  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_stake_delegations_exceeds_max( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing stake delegations exceeds max" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->stake_delegations_len = FD_STAKE_DELEGATIONS_MAX + 1UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_vote_accounts_exceeds_max( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing vote accounts exceeds max" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->vote_accounts_len = FD_VOTE_ACCOUNTS_MAX + 1UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_vote_accounts_epoch_credits_exceeds_max( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing vote accounts epoch credits exceeds max" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->vote_accounts_len = 1UL;
  manifest->vote_accounts[0].epoch_credits_history_len = FD_EPOCH_CREDITS_MAX + 1UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_stake_delegations_exceeds_runtime_max( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing stake delegations exceeds runtime max_stake_accounts" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  /* Set a count within the static manifest array bound but above our
     runtime capacity limit. */
  ulong small_max = 100UL;
  manifest->stake_delegations_len = small_max + 1UL;

  FD_TEST( fd_ssload_manifest_validate( manifest, TEST_MAX_VOTE_ACCOUNTS, small_max )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_vote_accounts_exceeds_runtime_max( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing vote accounts exceeds runtime max_vote_accounts" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  ulong small_max = 100UL;
  manifest->vote_accounts_len = small_max + 1UL;

  FD_TEST( fd_ssload_manifest_validate( manifest, small_max, TEST_MAX_STAKE_ACCOUNTS )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_epoch_vote_stakes_exceeds_runtime_max( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing epoch vote stakes exceeds runtime max_vote_accounts" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  ulong small_max = 100UL;
  manifest->epoch_stakes[0].vote_stakes_len = small_max + 1UL;

  FD_TEST( fd_ssload_manifest_validate( manifest, small_max, TEST_MAX_STAKE_ACCOUNTS )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

/* Epoch credits narrowing validation tests */

static void
test_valid_epoch_credits( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing valid epoch credits" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->epoch_stakes[0].vote_stakes_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits_history_len = 2UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].epoch        = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].credits      = 100UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].prev_credits = 0UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[1].epoch        = 2UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[1].credits      = 200UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[1].prev_credits = 100UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_epoch_credits_at_ushort_max( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing epoch credits epoch exactly at USHORT_MAX" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->epoch_stakes[0].vote_stakes_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits_history_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].epoch        = (ulong)USHORT_MAX;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].credits      = 100UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].prev_credits = 0UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_epoch_credits_delta_at_uint_max( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing epoch credits delta exactly at UINT_MAX" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  /* ec_base = epoch_credits[0].prev_credits = 0.
     credits - ec_base = UINT_MAX, exactly at boundary. */
  manifest->epoch_stakes[0].vote_stakes_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits_history_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].epoch        = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].credits      = (ulong)UINT_MAX;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].prev_credits = 0UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_epoch_credits_epoch_exceeds_ushort( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing epoch credits epoch exceeds ushort" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->epoch_stakes[0].vote_stakes_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits_history_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].epoch        = (ulong)USHORT_MAX + 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].credits      = 100UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].prev_credits = 0UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_epoch_credits_delta_exceeds_uint( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing epoch credits delta exceeds uint" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  /* ec_base = epoch_credits[0].prev_credits = 0.
     credits - ec_base = UINT_MAX+1 > UINT_MAX. */
  manifest->epoch_stakes[0].vote_stakes_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits_history_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].epoch        = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].credits      = (ulong)UINT_MAX + 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].prev_credits = 0UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_epoch_prev_credits_delta_exceeds_uint( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing epoch prev credits delta exceeds uint" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  /* Need 2 entries: the first entry's prev_credits sets ec_base.
     For the second entry, prev_credits - ec_base > UINT_MAX. */
  manifest->epoch_stakes[0].vote_stakes_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits_history_len = 2UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].epoch        = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].credits      = 100UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].prev_credits = 0UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[1].epoch        = 2UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[1].credits      = 200UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[1].prev_credits = (ulong)UINT_MAX + 1UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_vote_stakes_len_exceeds_max( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing vote stakes len exceeds max" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->epoch_stakes[0].vote_stakes_len = FD_EPOCH_VOTE_STAKES_MAX + 1UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_epoch_credits_len_exceeds_max( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing epoch credits len exceeds max" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  manifest->epoch_stakes[0].vote_stakes_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits_history_len = FD_EPOCH_CREDITS_MAX + 1UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_leader_schedule_slot_offset_overflow( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing leader_schedule_slot_offset overflow" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  /* slot=432000 (in the normal period), leader_schedule_slot_offset
     near ULONG_MAX causes the internal (slot - first_normal_slot) +
     leader_schedule_slot_offset addition to wrap. */
  manifest->slot = 432000UL;
  manifest->epoch_schedule_params.leader_schedule_slot_offset = ULONG_MAX;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_leader_schedule_slot_offset_large_no_overflow( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing large leader_schedule_slot_offset without addition overflow" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  /* leader_schedule_slot_offset chosen so that
     (slot - first_normal_slot) + leader_schedule_slot_offset does NOT
     overflow, but produces such a large leader_schedule_epoch that
     t_1_idx exceeds FD_EPOCH_STAKES_LEN. */
  manifest->epoch_schedule_params.slots_per_epoch             = 64UL;
  manifest->epoch_schedule_params.leader_schedule_slot_offset = ULONG_MAX - 32UL;
  manifest->epoch_schedule_params.warmup                      = 1;
  manifest->slot = 32UL; /* first_normal_slot */

  /* Derive correct first_normal_epoch/slot for validation to reach
     the epoch stakes index check. */
  fd_epoch_schedule_t derived;
  FD_TEST( fd_epoch_schedule_derive( &derived, 64UL, ULONG_MAX - 32UL, 1 ) );
  manifest->epoch_schedule_params.first_normal_epoch = derived.first_normal_epoch;
  manifest->epoch_schedule_params.first_normal_slot  = derived.first_normal_slot;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_epoch_stakes_index_out_of_range( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing epoch stakes index out of range" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  /* slots_per_epoch=432000, leader_schedule_slot_offset=432000*3,
     slot=432000.  This yields epoch=1, leader_schedule_epoch=4,
     epoch_stakes_base=0, t_1_idx=4 >= FD_EPOCH_STAKES_LEN(3). */
  manifest->epoch_schedule_params.slots_per_epoch             = 432000UL;
  manifest->epoch_schedule_params.leader_schedule_slot_offset = 432000UL * 3UL;
  manifest->slot = 432000UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_epoch_schedule_first_normal_epoch_rejected( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing first_normal_epoch/slot rejected (warmup=0)" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  /* warmup=0 means derived first_normal_epoch=0, first_normal_slot=0.
     Adversarial ULONG_MAX values must be rejected. */
  manifest->epoch_schedule_params.warmup             = 0;
  manifest->epoch_schedule_params.first_normal_epoch = ULONG_MAX;
  manifest->epoch_schedule_params.first_normal_slot  = ULONG_MAX;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_epoch_schedule_warmup_first_normal_rejected( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing first_normal_epoch/slot rejected (warmup=1)" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  /* warmup=1 with slots_per_epoch=432000 derives specific non-zero
     first_normal_epoch/slot.  Adversarial zeros must be rejected. */
  manifest->epoch_schedule_params.warmup             = 1;
  manifest->epoch_schedule_params.first_normal_epoch = 0UL;
  manifest->epoch_schedule_params.first_normal_slot  = 0UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_epoch_schedule_overflow_epoch_rejected( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing first_normal values that would overflow epoch rejected" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  /* first_normal_epoch=ULONG_MAX with first_normal_slot=0 would cause
     fd_slot_to_epoch to compute epoch = ULONG_MAX + n_epoch, wrapping.
     Validation must reject the mismatch. */
  manifest->epoch_schedule_params.first_normal_epoch = ULONG_MAX;
  manifest->epoch_schedule_params.first_normal_slot  = 0UL;
  manifest->slot = 432000UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_epoch_schedule_correct_derived_values_accepted( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing correct derived first_normal_epoch/slot accepted" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  /* warmup=0: derived first_normal_epoch=0, first_normal_slot=0.
     Manifest matches — should pass. */
  manifest->epoch_schedule_params.warmup             = 0;
  manifest->epoch_schedule_params.first_normal_epoch = 0UL;
  manifest->epoch_schedule_params.first_normal_slot  = 0UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* warmup=1 with slots_per_epoch=432000: derive and set matching
     values.  Should also pass. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_schedule_params.warmup = 1;

  fd_epoch_schedule_t expected;
  FD_TEST( fd_epoch_schedule_derive( &expected,
                                      manifest->epoch_schedule_params.slots_per_epoch,
                                      manifest->epoch_schedule_params.leader_schedule_slot_offset,
                                      1 ) );
  manifest->epoch_schedule_params.first_normal_epoch = expected.first_normal_epoch;
  manifest->epoch_schedule_params.first_normal_slot  = expected.first_normal_slot;

  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );
  FD_LOG_NOTICE(( "... pass" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt = 1;
  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  if( FD_UNLIKELY( !wksp ) ) {
    /* Fall back to normal pages if huge/gigantic pages are not available */
    page_cnt = 256000;
    _page_sz = "normal";
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  }
  FD_TEST( wksp );

  fd_snapshot_manifest_t * manifest = (fd_snapshot_manifest_t *)fd_wksp_alloc_laddr( wksp, alignof(fd_snapshot_manifest_t), sizeof(fd_snapshot_manifest_t), 1UL );
  FD_TEST( manifest );
  fd_memset( manifest, 0, sizeof(*manifest) );

  test_valid_base_manifest( manifest );
  test_epoch_schedule_min_slots_per_epoch( manifest );
  test_epoch_schedule_zero_slots_per_epoch( manifest );
  test_epoch_schedule_below_min_slots_per_epoch( manifest );
  test_epoch_schedule_warmup_invalid( manifest );
  test_valid_sorted_blockhashes( manifest );
  test_valid_unsorted_blockhashes( manifest );
  test_empty_blockhashes( manifest );
  test_blockhash_count_exceeds_max( manifest );
  test_blockhash_count_at_max( manifest );
  test_blockhash_gap( manifest );
  test_blockhash_duplicate( manifest );
  test_blockhash_sequence_wraparound( manifest );
  test_blockhash_single_near_max_index( manifest );
  test_blockhash_single_max_index( manifest );
  test_hard_forks_at_max( manifest );
  test_hard_forks_exceeds_max( manifest );
  test_stake_delegations_at_max( manifest );
  test_stake_delegations_exceeds_max( manifest );
  test_vote_accounts_exceeds_max( manifest );
  test_vote_accounts_epoch_credits_exceeds_max( manifest );
  test_stake_delegations_exceeds_runtime_max( manifest );
  test_vote_accounts_exceeds_runtime_max( manifest );
  test_epoch_vote_stakes_exceeds_runtime_max( manifest );
  test_valid_epoch_credits( manifest );
  test_epoch_credits_at_ushort_max( manifest );
  test_epoch_credits_delta_at_uint_max( manifest );
  test_epoch_credits_epoch_exceeds_ushort( manifest );
  test_epoch_credits_delta_exceeds_uint( manifest );
  test_epoch_prev_credits_delta_exceeds_uint( manifest );
  test_vote_stakes_len_exceeds_max( manifest );
  test_epoch_credits_len_exceeds_max( manifest );
  test_leader_schedule_slot_offset_overflow( manifest );
  test_leader_schedule_slot_offset_large_no_overflow( manifest );
  test_epoch_stakes_index_out_of_range( manifest );
  test_epoch_schedule_first_normal_epoch_rejected( manifest );
  test_epoch_schedule_warmup_first_normal_rejected( manifest );
  test_epoch_schedule_overflow_epoch_rejected( manifest );
  test_epoch_schedule_correct_derived_values_accepted( manifest );

  fd_wksp_free_laddr( manifest );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "all ssload tests passed" ));

  fd_halt();
  return 0;
}
