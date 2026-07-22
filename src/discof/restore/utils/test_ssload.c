#include "fd_ssload.h"
#include "../../../util/fd_util.h"
#include "../../../flamenco/runtime/fd_bank.h"
#include "../../../flamenco/runtime/fd_runtime_const.h"
#include "../../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../../flamenco/stakes/fd_stake_delegations.h"
#include "../../../flamenco/stakes/fd_vote_stakes.h"
#include "../../../flamenco/stakes/fd_new_votes.h"
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

static void
test_recover_back_to_back_reset( fd_wksp_t * wksp, fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing recover back-to-back reset" ));

  /* Set up a tiny-capacity fd_banks_t.  Call fd_ssload_recover_apply
     directly (bypassing fd_ssload_recover_validate) because the
     validate step requires production-sized capacities outside the
     scope of this test. */

  ulong max_banks = 16UL;
  ulong max_forks =  4UL;
  ulong max_stake = 64UL;
  ulong max_vote  = 64UL;
  ulong seed      = 42UL;

  ulong banks_footprint = fd_banks_footprint( max_banks, max_forks,
                                              max_stake, max_vote );
  void * banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(),
                                          banks_footprint, 2UL );
  FD_TEST( banks_mem );

  fd_banks_t * banks = fd_banks_join( fd_banks_new( banks_mem, max_banks, max_forks,
                                                    max_stake, max_vote,
                                                    0 /* larger_max_cost_per_block */, seed ) );
  FD_TEST( banks );

  fd_bank_t * bank = fd_banks_init_bank( banks );
  FD_TEST( bank );

  /* Manifest A: one stake delegation (pubkey_A), one vote stake
    (pubkey_X).  With slot=0, epoch=0, leader_schedule_epoch=1,
     epoch_stakes_base=0, t_1_idx=1. */

  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->accdb_fork_id    = 37U;
  manifest->txncache_fork_id = 38U;

  uchar pubkey_a[32]; fd_memset( pubkey_a, 0xAA, 32 );
  uchar vote_a[32];   fd_memset( vote_a,   0xA1, 32 );
  manifest->stake_delegations_len = 1UL;
  fd_memcpy( manifest->stake_delegations[0].stake_pubkey, pubkey_a, 32 );
  fd_memcpy( manifest->stake_delegations[0].vote_pubkey,  vote_a,   32 );
  manifest->stake_delegations[0].stake_delegation   = 1000UL;
  manifest->stake_delegations[0].activation_epoch   = 0UL;
  manifest->stake_delegations[0].deactivation_epoch = ULONG_MAX;

  uchar pubkey_x[32]; fd_memset( pubkey_x, 0xBB, 32 );
  uchar ident_x[32];  fd_memset( ident_x,  0xB1, 32 );
  manifest->epoch_stakes[1].vote_stakes_len = 1UL;
  fd_memcpy( manifest->epoch_stakes[1].vote_stakes[0].vote,     pubkey_x, 32 );
  fd_memcpy( manifest->epoch_stakes[1].vote_stakes[0].identity, ident_x,  32 );
  manifest->epoch_stakes[1].vote_stakes[0].stake      = 5000UL;
  manifest->epoch_stakes[1].vote_stakes[0].commission = 10;
  manifest->epoch_stakes[1].total_stake               = 5000UL;

  /* Also add a new_votes entry (vote account with stake==0). */
  uchar nv_pubkey_a[32]; fd_memset( nv_pubkey_a, 0xE1, 32 );
  manifest->vote_accounts_len = 1UL;
  fd_memcpy( manifest->vote_accounts[0].vote_account_pubkey, nv_pubkey_a, 32 );
  manifest->vote_accounts[0].stake = 0UL;

  /* First apply: simulate initial full snapshot load. */
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );
  FD_TEST( fd_ssload_recover_apply( manifest, banks, bank, seed )==0 );
  FD_TEST( bank->accdb_fork_id.val==37U );
  FD_TEST( bank->parent_accdb_fork_id.val==37U );
  FD_TEST( bank->txncache_fork_id.val==38U );

  /* Verify entries from first apply are present. */
  fd_stake_delegations_t * sd = fd_banks_stake_delegations_root_query( banks );
  FD_TEST( fd_stake_delegation_root_query( sd, (fd_pubkey_t *)pubkey_a )!=NULL );
  FD_TEST( fd_stake_delegations_cnt( sd )==1UL );

  fd_vote_stakes_t * vs = fd_bank_vote_stakes( bank );
  ushort root_idx = fd_vote_stakes_get_root_idx( vs );
  FD_TEST( fd_vote_stakes_ele_cnt( vs, root_idx )==1 );

  fd_new_votes_t * nv = fd_bank_new_votes( bank );
  FD_TEST( fd_new_votes_cnt( nv )==1UL );

  /* Manifest B: different stake delegation (pubkey_B),
     different vote stake (pubkey_Y), different new_votes entry. */

  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->accdb_fork_id    = 39U;
  manifest->txncache_fork_id = 40U;

  uchar pubkey_b[32]; fd_memset( pubkey_b, 0xCC, 32 );
  uchar vote_b[32];   fd_memset( vote_b,   0xC1, 32 );
  manifest->stake_delegations_len = 1UL;
  fd_memcpy( manifest->stake_delegations[0].stake_pubkey, pubkey_b, 32 );
  fd_memcpy( manifest->stake_delegations[0].vote_pubkey,  vote_b,   32 );
  manifest->stake_delegations[0].stake_delegation   = 2000UL;
  manifest->stake_delegations[0].activation_epoch   = 0UL;
  manifest->stake_delegations[0].deactivation_epoch = ULONG_MAX;

  uchar pubkey_y[32]; fd_memset( pubkey_y, 0xDD, 32 );
  uchar ident_y[32];  fd_memset( ident_y,  0xD1, 32 );
  manifest->epoch_stakes[1].vote_stakes_len = 1UL;
  fd_memcpy( manifest->epoch_stakes[1].vote_stakes[0].vote,     pubkey_y, 32 );
  fd_memcpy( manifest->epoch_stakes[1].vote_stakes[0].identity, ident_y,  32 );
  manifest->epoch_stakes[1].vote_stakes[0].stake      = 7000UL;
  manifest->epoch_stakes[1].vote_stakes[0].commission = 5;
  manifest->epoch_stakes[1].total_stake               = 7000UL;

  uchar nv_pubkey_b[32]; fd_memset( nv_pubkey_b, 0xE2, 32 );
  manifest->vote_accounts_len = 1UL;
  fd_memcpy( manifest->vote_accounts[0].vote_account_pubkey, nv_pubkey_b, 32 );
  manifest->vote_accounts[0].stake = 0UL;

  /* Second apply: simulate back-to-back retry after a failed first
     attempt.  Stale entries must be cleared. */
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );
  FD_TEST( fd_ssload_recover_apply( manifest, banks, bank, seed )==0 );
  FD_TEST( bank->accdb_fork_id.val==39U );
  FD_TEST( bank->parent_accdb_fork_id.val==39U );
  FD_TEST( bank->txncache_fork_id.val==40U );

  /* Stake delegations: pubkey_A must have been removed, pubkey_B must
     be present, exactly 1 entry (not 2). */
  FD_TEST( fd_stake_delegation_root_query( sd, (fd_pubkey_t *)pubkey_a )==NULL );
  FD_TEST( fd_stake_delegation_root_query( sd, (fd_pubkey_t *)pubkey_b )!=NULL );
  FD_TEST( fd_stake_delegations_cnt( sd )==1UL );

  /* Vote stakes: pubkey_X must have been removed, pubkey_Y must be
     present, exactly 1 entry (not 2). */
  root_idx = fd_vote_stakes_get_root_idx( vs );
  FD_TEST( fd_vote_stakes_ele_cnt( vs, root_idx )==1 );

  ulong stake_out;
  FD_TEST( fd_vote_stakes_query_t_1( vs, root_idx, (fd_pubkey_t *)pubkey_x, &stake_out, NULL, NULL )==0 );
  FD_TEST( fd_vote_stakes_query_t_1( vs, root_idx, (fd_pubkey_t *)pubkey_y, &stake_out, NULL, NULL )==1 );
  FD_TEST( stake_out==7000UL );

  /* New votes: old entry must have been removed, new entry must be
     present, exactly 1 entry (not 2). */
  FD_TEST( fd_new_votes_cnt( nv )==1UL );
  fd_pubkey_t nv_pk_a; fd_memcpy( nv_pk_a.uc, nv_pubkey_a, 32UL );
  fd_pubkey_t nv_pk_b; fd_memcpy( nv_pk_b.uc, nv_pubkey_b, 32UL );
  uchar __attribute__((aligned(FD_NEW_VOTES_ITER_ALIGN))) iter_mem[ FD_NEW_VOTES_ITER_FOOTPRINT ];
  fd_new_votes_iter_t * it = fd_new_votes_iter_init( nv, NULL, 0UL, iter_mem );
  ulong nv_cnt = 0UL;
  int saw_a = 0;
  int saw_b = 0;
  for( ; !fd_new_votes_iter_done( it ); fd_new_votes_iter_next( it ) ) {
    int is_tombstone = 0;
    fd_pubkey_t const * pk = fd_new_votes_iter_ele( it, &is_tombstone );
    if( FD_UNLIKELY( is_tombstone ) ) continue;
    nv_cnt++;
    saw_a |= fd_pubkey_eq( pk, &nv_pk_a );
    saw_b |= fd_pubkey_eq( pk, &nv_pk_b );
  }
  fd_new_votes_iter_fini( it );
  FD_TEST( nv_cnt==1UL );
  FD_TEST( !saw_a );
  FD_TEST(  saw_b );

  fd_wksp_free_laddr( banks_mem );

  FD_LOG_NOTICE(( "... pass" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"               );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL                      );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0UL ) );
  fd_wksp_t * wksp      = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
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
  test_recover_back_to_back_reset( wksp, manifest );

  fd_wksp_free_laddr( manifest );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "all ssload tests passed" ));

  fd_halt();
  return 0;
}
