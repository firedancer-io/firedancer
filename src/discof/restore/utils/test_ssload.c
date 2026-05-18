#include "fd_ssload.h"
#include "../../../util/fd_util.h"
#include "../../../flamenco/runtime/fd_runtime_const.h"
#include "../../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include <limits.h>

/* Shorthand for the common validate call pattern using the production
   capacity limits.  fd_ssload_manifest_validate rejects calls where
   the limits differ from FD_RUNTIME_MAX_{VOTE,STAKE}_ACCOUNTS. */
#define VALIDATE_MANIFEST(m) fd_ssload_manifest_validate( (m), FD_RUNTIME_MAX_VOTE_ACCOUNTS, FD_RUNTIME_MAX_STAKE_ACCOUNTS )

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

static void
test_valid_base_manifest( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing valid base manifest" ));
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );

  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_capacity_mismatch( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing capacity mismatch" ));

  /* Mismatched max_vote_accounts. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  FD_TEST( fd_ssload_manifest_validate( manifest, 100UL, FD_RUNTIME_MAX_STAKE_ACCOUNTS )==-1 );

  /* Mismatched max_stake_accounts. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  FD_TEST( fd_ssload_manifest_validate( manifest, FD_RUNTIME_MAX_VOTE_ACCOUNTS, 100UL )==-1 );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_epoch_schedule( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing epoch schedule" ));

  /* Exactly min slots_per_epoch. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_schedule_params.slots_per_epoch             = FD_EPOCH_LEN_MIN;
  manifest->epoch_schedule_params.leader_schedule_slot_offset = FD_EPOCH_LEN_MIN;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Zero slots_per_epoch. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_schedule_params.slots_per_epoch = 0UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Below min slots_per_epoch. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_schedule_params.slots_per_epoch = FD_EPOCH_LEN_MIN - 1UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* slots_per_epoch too large with warmup (would cause 1UL<<64 UB in
     fd_epoch_schedule_derive without the upper-bound guard). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_schedule_params.slots_per_epoch             = (1UL<<63) + 1UL;
  manifest->epoch_schedule_params.leader_schedule_slot_offset = (1UL<<63) + 1UL;
  manifest->epoch_schedule_params.warmup                      = 1;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* slots_per_epoch exactly at 2^63 with warmup (valid, no UB). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_schedule_params.slots_per_epoch             = 1UL<<63;
  manifest->epoch_schedule_params.leader_schedule_slot_offset = 1UL<<63;
  manifest->epoch_schedule_params.warmup                      = 1;
  fd_epoch_schedule_t huge_derived;
  FD_TEST( fd_epoch_schedule_derive( &huge_derived, 1UL<<63, 1UL<<63, 1 ) );
  manifest->epoch_schedule_params.first_normal_epoch = huge_derived.first_normal_epoch;
  manifest->epoch_schedule_params.first_normal_slot  = huge_derived.first_normal_slot;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Invalid warmup. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_schedule_params.warmup = 2;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Invalid first_normal_epoch/slot rejected (warmup=0). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_schedule_params.warmup             = 0;
  manifest->epoch_schedule_params.first_normal_epoch = ULONG_MAX;
  manifest->epoch_schedule_params.first_normal_slot  = ULONG_MAX;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Invalid first_normal_epoch/slot rejected (warmup=1). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_schedule_params.warmup             = 1;
  manifest->epoch_schedule_params.first_normal_epoch = 0UL;
  manifest->epoch_schedule_params.first_normal_slot  = 0UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Invalid first_normal_epoch rejected by consistency check
     (derived first_normal_epoch=0 does not match ULONG_MAX). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_schedule_params.first_normal_epoch = ULONG_MAX;
  manifest->epoch_schedule_params.first_normal_slot  = 0UL;
  manifest->slot = 432000UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Correct derived first_normal values accepted (warmup=0). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_schedule_params.warmup             = 0;
  manifest->epoch_schedule_params.first_normal_epoch = 0UL;
  manifest->epoch_schedule_params.first_normal_slot  = 0UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Correct derived first_normal values accepted (warmup=1). */
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

  /* Valid warmup-region slot (slot < first_normal_slot).  Exercises
     the warmup branch of epoch stakes index validation. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_schedule_params.slots_per_epoch             = 64UL;
  manifest->epoch_schedule_params.leader_schedule_slot_offset = 64UL;
  manifest->epoch_schedule_params.warmup                      = 1;
  fd_epoch_schedule_t warmup_derived;
  FD_TEST( fd_epoch_schedule_derive( &warmup_derived, 64UL, 64UL, 1 ) );
  manifest->epoch_schedule_params.first_normal_epoch = warmup_derived.first_normal_epoch;
  manifest->epoch_schedule_params.first_normal_slot  = warmup_derived.first_normal_slot;
  manifest->slot = 16UL; /* 16 < first_normal_slot(32), enters warmup branch */
  manifest->blockhashes_len = 1UL;
  manifest->blockhashes[0].hash_index = 0UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* leader_schedule_slot_offset overflow. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->slot = 432000UL;
  manifest->epoch_schedule_params.leader_schedule_slot_offset = ULONG_MAX;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Large leader_schedule_slot_offset without addition overflow
     but t_1_idx exceeds FD_EPOCH_STAKES_LEN. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_schedule_params.slots_per_epoch             = 64UL;
  manifest->epoch_schedule_params.leader_schedule_slot_offset = ULONG_MAX - 32UL;
  manifest->epoch_schedule_params.warmup                      = 1;
  manifest->slot = 32UL;
  fd_epoch_schedule_t derived;
  FD_TEST( fd_epoch_schedule_derive( &derived, 64UL, ULONG_MAX - 32UL, 1 ) );
  manifest->epoch_schedule_params.first_normal_epoch = derived.first_normal_epoch;
  manifest->epoch_schedule_params.first_normal_slot  = derived.first_normal_slot;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Epoch stakes index out of range. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_schedule_params.slots_per_epoch             = 432000UL;
  manifest->epoch_schedule_params.leader_schedule_slot_offset = 432000UL * 3UL;
  manifest->slot = 432000UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_blockhash_queue( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing blockhash queue" ));

  /* Valid sorted blockhashes. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->blockhashes_len = 3UL;
  manifest->blockhashes[0].hash_index = 0UL;
  manifest->blockhashes[1].hash_index = 1UL;
  manifest->blockhashes[2].hash_index = 2UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Valid unsorted blockhashes. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->blockhashes_len = 3UL;
  manifest->blockhashes[0].hash_index = 2UL;
  manifest->blockhashes[1].hash_index = 0UL;
  manifest->blockhashes[2].hash_index = 1UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Empty blockhashes. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->blockhashes_len = 0UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Count exceeds max. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->blockhashes_len = FD_BLOCKHASHES_MAX + 1UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Count exactly at max. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->blockhashes_len = FD_BLOCKHASHES_MAX;
  for( ulong i=0UL; i<FD_BLOCKHASHES_MAX; i++ ) {
    manifest->blockhashes[i].hash_index = i;
  }
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Gap in sequence. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->blockhashes_len = 3UL;
  manifest->blockhashes[0].hash_index = 0UL;
  manifest->blockhashes[1].hash_index = 1UL;
  manifest->blockhashes[2].hash_index = 3UL; /* gap at 2 */
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Duplicate index. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->blockhashes_len = 3UL;
  manifest->blockhashes[0].hash_index = 0UL;
  manifest->blockhashes[1].hash_index = 1UL;
  manifest->blockhashes[2].hash_index = 1UL; /* duplicate */
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Sequence wraparound (seq_min+age_cnt overflows). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->blockhashes_len = 2UL;
  manifest->blockhashes[0].hash_index = ULONG_MAX - 1UL;
  manifest->blockhashes[1].hash_index = ULONG_MAX;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Single blockhash with near-max index (valid). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->blockhashes_len = 1UL;
  manifest->blockhashes[0].hash_index = ULONG_MAX - 1UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Single blockhash with hash_index=ULONG_MAX (wraparound). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->blockhashes_len = 1UL;
  manifest->blockhashes[0].hash_index = ULONG_MAX;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_hard_forks( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing hard forks" ));

  /* Exactly at max. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->hard_fork_cnt = FD_HARD_FORKS_MAX;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Exceeds max. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->hard_fork_cnt = FD_HARD_FORKS_MAX + 1UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_stake_delegations( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing stake delegations" ));

  /* Exactly at max. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->stake_delegations_len = FD_STAKE_DELEGATIONS_MAX;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Exceeds max. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->stake_delegations_len = FD_STAKE_DELEGATIONS_MAX + 1UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Exceeds runtime max_stake_accounts. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->stake_delegations_len = FD_RUNTIME_MAX_STAKE_ACCOUNTS + 1UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_vote_accounts( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing vote accounts" ));

  /* vote_accounts_len exceeds max. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->vote_accounts_len = FD_VOTE_ACCOUNTS_MAX + 1UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* vote_accounts epoch_credits_history_len exceeds max. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->vote_accounts_len = 1UL;
  manifest->vote_accounts[0].epoch_credits_history_len = FD_EPOCH_CREDITS_MAX + 1UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* vote_accounts_len exceeds runtime max. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->vote_accounts_len = FD_RUNTIME_MAX_VOTE_ACCOUNTS + 1UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* epoch_stakes vote_stakes_len exceeds runtime max. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_stakes[0].vote_stakes_len = FD_RUNTIME_MAX_VOTE_ACCOUNTS + 1UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* epoch_stakes vote_stakes_len exceeds max. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_stakes[0].vote_stakes_len = FD_EPOCH_VOTE_STAKES_MAX + 1UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* epoch_stakes epoch_credits_history_len exceeds max. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_stakes[0].vote_stakes_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits_history_len = FD_EPOCH_CREDITS_MAX + 1UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_epoch_credits_downcasting( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing epoch credits downcasting" ));

  /* Valid epoch credits (vote_accounts path). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->vote_accounts_len = 1UL;
  manifest->vote_accounts[0].epoch_credits_history_len = 2UL;
  manifest->vote_accounts[0].epoch_credits[0].epoch        = 1UL;
  manifest->vote_accounts[0].epoch_credits[0].credits      = 100UL;
  manifest->vote_accounts[0].epoch_credits[0].prev_credits = 0UL;
  manifest->vote_accounts[0].epoch_credits[1].epoch        = 2UL;
  manifest->vote_accounts[0].epoch_credits[1].credits      = 200UL;
  manifest->vote_accounts[0].epoch_credits[1].prev_credits = 100UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Epoch at USHORT_MAX boundary (vote_accounts path). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->vote_accounts_len = 1UL;
  manifest->vote_accounts[0].epoch_credits_history_len = 1UL;
  manifest->vote_accounts[0].epoch_credits[0].epoch        = (ulong)USHORT_MAX;
  manifest->vote_accounts[0].epoch_credits[0].credits      = 100UL;
  manifest->vote_accounts[0].epoch_credits[0].prev_credits = 0UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Credits delta at UINT_MAX boundary (vote_accounts path). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->vote_accounts_len = 1UL;
  manifest->vote_accounts[0].epoch_credits_history_len = 1UL;
  manifest->vote_accounts[0].epoch_credits[0].epoch        = 1UL;
  manifest->vote_accounts[0].epoch_credits[0].credits      = (ulong)UINT_MAX;
  manifest->vote_accounts[0].epoch_credits[0].prev_credits = 0UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Epoch exceeds USHORT_MAX (vote_accounts path). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->vote_accounts_len = 1UL;
  manifest->vote_accounts[0].epoch_credits_history_len = 1UL;
  manifest->vote_accounts[0].epoch_credits[0].epoch        = (ulong)USHORT_MAX + 1UL;
  manifest->vote_accounts[0].epoch_credits[0].credits      = 100UL;
  manifest->vote_accounts[0].epoch_credits[0].prev_credits = 0UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Credits delta exceeds UINT_MAX (vote_accounts path). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->vote_accounts_len = 1UL;
  manifest->vote_accounts[0].epoch_credits_history_len = 1UL;
  manifest->vote_accounts[0].epoch_credits[0].epoch        = 1UL;
  manifest->vote_accounts[0].epoch_credits[0].credits      = (ulong)UINT_MAX + 1UL;
  manifest->vote_accounts[0].epoch_credits[0].prev_credits = 0UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Prev credits delta exceeds UINT_MAX (vote_accounts path). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->vote_accounts_len = 1UL;
  manifest->vote_accounts[0].epoch_credits_history_len = 2UL;
  manifest->vote_accounts[0].epoch_credits[0].epoch        = 1UL;
  manifest->vote_accounts[0].epoch_credits[0].credits      = 100UL;
  manifest->vote_accounts[0].epoch_credits[0].prev_credits = 0UL;
  manifest->vote_accounts[0].epoch_credits[1].epoch        = 2UL;
  manifest->vote_accounts[0].epoch_credits[1].credits      = 200UL;
  manifest->vote_accounts[0].epoch_credits[1].prev_credits = (ulong)UINT_MAX + 1UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Credits below base (vote_accounts path). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->vote_accounts_len = 1UL;
  manifest->vote_accounts[0].epoch_credits_history_len = 2UL;
  manifest->vote_accounts[0].epoch_credits[0].epoch        = 1UL;
  manifest->vote_accounts[0].epoch_credits[0].credits      = 600UL;
  manifest->vote_accounts[0].epoch_credits[0].prev_credits = 500UL;
  manifest->vote_accounts[0].epoch_credits[1].epoch        = 2UL;
  manifest->vote_accounts[0].epoch_credits[1].credits      = 400UL;
  manifest->vote_accounts[0].epoch_credits[1].prev_credits = 500UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Valid epoch credits (epoch_stakes path). */
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

  /* Epoch at USHORT_MAX boundary (epoch_stakes path). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_stakes[0].vote_stakes_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits_history_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].epoch        = (ulong)USHORT_MAX;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].credits      = 100UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].prev_credits = 0UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Credits delta at UINT_MAX boundary (epoch_stakes path). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_stakes[0].vote_stakes_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits_history_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].epoch        = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].credits      = (ulong)UINT_MAX;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].prev_credits = 0UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Epoch exceeds USHORT_MAX (epoch_stakes path). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_stakes[0].vote_stakes_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits_history_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].epoch        = (ulong)USHORT_MAX + 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].credits      = 100UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].prev_credits = 0UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Credits delta exceeds UINT_MAX (epoch_stakes path). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_stakes[0].vote_stakes_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits_history_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].epoch        = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].credits      = (ulong)UINT_MAX + 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].prev_credits = 0UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Prev credits delta exceeds UINT_MAX (epoch_stakes path). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
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

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt = 1;
  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_snapshot_manifest_t * manifest = (fd_snapshot_manifest_t *)fd_wksp_alloc_laddr( wksp, alignof(fd_snapshot_manifest_t), sizeof(fd_snapshot_manifest_t), 1UL );
  FD_TEST( manifest );
  fd_memset( manifest, 0, sizeof(*manifest) );

  test_valid_base_manifest( manifest );
  test_capacity_mismatch( manifest );
  test_epoch_schedule( manifest );
  test_blockhash_queue( manifest );
  test_hard_forks( manifest );
  test_stake_delegations( manifest );
  test_vote_accounts( manifest );
  test_epoch_credits_downcasting( manifest );

  fd_wksp_free_laddr( manifest );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "all ssload tests passed" ));

  fd_halt();
  return 0;
}
