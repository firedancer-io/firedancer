#include "fd_ssload.h"
#include "../../../util/fd_util.h"
#include "../../../flamenco/runtime/fd_bank.h"
#include "../../../flamenco/runtime/fd_runtime_const.h"
#include "../../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../../flamenco/stakes/fd_stake_delegations.h"
#include "../../../ballet/hex/fd_hex.h"
#include <limits.h>

/* Staging for the epoch stakes digests fd_ssload_recover_apply
   computes.  Static rather than automatic: at the VAT bound this is
   ~140 KiB. */

static fd_vote_stake_weight_t digest_scratch[ FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS ];

/* Shorthand for the common validate call pattern using the production
   capacity limits.  fd_ssload_manifest_validate rejects calls where
   the limits differ from FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS and
   FD_RUNTIME_MAX_STAKE_ACCOUNTS. */
#define VALIDATE_MANIFEST(m) fd_ssload_manifest_validate( (m), FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS, FD_RUNTIME_MAX_STAKE_ACCOUNTS )

/* Set up the minimum valid manifest state so that all validation
   stages can be reached.  Adds 1 blockhash with hash_index=0 and
   sets valid epoch schedule params.
   With defaults (slot=0, warmup=0, first_normal_epoch=0,
   first_normal_slot=0): epoch=0, leader_schedule_epoch=1,
   epoch_stakes_base=0, t_1_idx=1 (valid). */
static void
setup_valid_manifest_base( fd_snapshot_manifest_t * manifest ) {
  manifest->ticks_per_slot = 64UL;
  manifest->blockhashes_len = 1UL;
  manifest->blockhashes[0].hash_index = 0UL;
  manifest->epoch_schedule_params.slots_per_epoch             = 432000UL;
  manifest->epoch_schedule_params.leader_schedule_slot_offset = 432000UL;
}

static void
test_ticks_per_slot( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing ticks_per_slot" ));

  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  manifest->ticks_per_slot = 0UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  FD_LOG_NOTICE(( "... pass" ));
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
  FD_TEST( fd_ssload_manifest_validate( manifest, FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS, 100UL )==-1 );

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
     but t_1_idx exceeds FD_RUNTIME_MANIFEST_EPOCH_STAKES_LEN. */
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
test_vote_accounts( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing vote accounts" ));

  /* Historical pre-VAT epoch stakes still obey the runtime VAT bound. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->slot = manifest->epoch_schedule_params.slots_per_epoch;
  manifest->epoch_stakes[0].vote_stakes_len = FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS + 1UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* The vote accounts map covers every staked voter, so it is bounded
     by the snapshot limit rather than the VAT limit. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->vote_accounts_len = FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS + 1UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* vote_accounts_len at the snapshot bound is valid. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->vote_accounts_len = FD_RUNTIME_MAX_SNAPSHOT_VOTE_ACCOUNTS;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* vote_accounts_len exceeds the snapshot bound. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->vote_accounts_len = FD_RUNTIME_MAX_SNAPSHOT_VOTE_ACCOUNTS + 1UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* T-1 epoch stakes exceed the VAT bound. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_stakes[1].vote_stakes_len = FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS + 1UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* T-2 epoch stakes exceed the VAT bound. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_stakes[0].vote_stakes_len = FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS + 1UL;
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

  /* Valid epoch credits with an epoch gap (epoch_stakes path). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_stakes[0].vote_stakes_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].has_identity_bls = 1;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits_history_len = 2UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].epoch        = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].credits      = 100UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].prev_credits = 0UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[1].epoch        = 3UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[1].credits      = 200UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[1].prev_credits = 100UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Epoch at USHORT_MAX boundary (epoch_stakes path). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_stakes[0].vote_stakes_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].has_identity_bls = 1;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits_history_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].epoch        = (ulong)USHORT_MAX;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].credits      = 100UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].prev_credits = 0UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Credits delta at UINT_MAX boundary (epoch_stakes path). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_stakes[0].vote_stakes_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].has_identity_bls = 1;
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

  /* Credits delta exceeds UINT_MAX (epoch_stakes path).  Alpenglow
     accumulates reward lamports here, so this is ordinary data. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_stakes[0].vote_stakes_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].has_identity_bls = 1;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits_history_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].epoch        = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].credits      = (ulong)UINT_MAX + 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].prev_credits = 0UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Prev credits break the chain and exceed the final credits
     (epoch_stakes path). */
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

  /* Discontinuous credits (epoch_stakes path). */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_stakes[0].vote_stakes_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].has_identity_bls = 1;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits_history_len = 2UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].epoch        = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].credits      = 100UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[0].prev_credits = 0UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[1].epoch        = 2UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[1].credits      = 200UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[1].prev_credits = 101UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Duplicate epoch (epoch_stakes path).  Legal: the two entries either
     side of an Alpenglow migration marker both carry the migration
     epoch, so epochs are only required to be non-decreasing. */
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[1].epoch        = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[1].prev_credits = 100UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Descending epoch (epoch_stakes path). */
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[1].epoch = 0UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Initial credits exceed final credits while continuity holds
     (epoch_stakes path). */
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[1].epoch   = 2UL;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[1].credits = 99UL;
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  FD_LOG_NOTICE(( "... pass" ));
}

/* SIMD-0326: Agave splices AG_MIGRATION_EPOCH_CREDIT into a migrating
   vote account's epoch credits.  It is a delimiter, not a credits
   record, so the surrounding entries chain across it. */

static void
set_epoch_credit( fd_snapshot_manifest_t * manifest,
                  ulong                    k,
                  ulong                    epoch,
                  ulong                    credits,
                  ulong                    prev_credits ) {
  epoch_credits_t * epc = &manifest->epoch_stakes[0].vote_stakes[0].epoch_credits[k];
  epc->epoch        = epoch;
  epc->credits      = credits;
  epc->prev_credits = prev_credits;
}

static void
setup_migration_marker_case( fd_snapshot_manifest_t * manifest,
                             ulong                    history_len ) {
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->epoch_stakes[0].vote_stakes_len = 1UL;
  manifest->epoch_stakes[0].vote_stakes[0].has_identity_bls = 1;
  manifest->epoch_stakes[0].vote_stakes[0].epoch_credits_history_len = history_len;
}

static void
test_epoch_credits_migration_marker( fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing alpenglow migration marker in epoch credits" ));

  /* Marker mid-history.  The post-marker entry repeats the migration
     epoch and chains back to the last tower-era entry, then jumps to
     lamport scale. */
  setup_migration_marker_case( manifest, 4UL );
  set_epoch_credit( manifest, 0UL, 5UL, 3184235UL, 2360133UL );
  set_epoch_credit( manifest, 1UL, 6UL, 3260485UL, 3184235UL );
  set_epoch_credit( manifest, 2UL, ULONG_MAX, ULONG_MAX, ULONG_MAX );
  set_epoch_credit( manifest, 3UL, 6UL, 216746563450UL, 3260485UL );
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Marker at index 0: nothing precedes it, so the following entry may
     start from any base. */
  setup_migration_marker_case( manifest, 2UL );
  set_epoch_credit( manifest, 0UL, ULONG_MAX, ULONG_MAX, ULONG_MAX );
  set_epoch_credit( manifest, 1UL, 6UL, 9013356638607UL, 8892273541624UL );
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Marker as the only entry. */
  setup_migration_marker_case( manifest, 1UL );
  set_epoch_credit( manifest, 0UL, ULONG_MAX, ULONG_MAX, ULONG_MAX );
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );

  /* Agave never pushes a second marker. */
  setup_migration_marker_case( manifest, 3UL );
  set_epoch_credit( manifest, 0UL, ULONG_MAX, ULONG_MAX, ULONG_MAX );
  set_epoch_credit( manifest, 1UL, 6UL, 100UL, 0UL );
  set_epoch_credit( manifest, 2UL, ULONG_MAX, ULONG_MAX, ULONG_MAX );
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* The chain must still hold across the marker. */
  setup_migration_marker_case( manifest, 3UL );
  set_epoch_credit( manifest, 0UL, 5UL, 100UL, 0UL );
  set_epoch_credit( manifest, 1UL, ULONG_MAX, ULONG_MAX, ULONG_MAX );
  set_epoch_credit( manifest, 2UL, 6UL, 300UL, 101UL );
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* Epochs must still be non-decreasing across the marker. */
  setup_migration_marker_case( manifest, 3UL );
  set_epoch_credit( manifest, 0UL, 5UL, 100UL, 0UL );
  set_epoch_credit( manifest, 1UL, ULONG_MAX, ULONG_MAX, ULONG_MAX );
  set_epoch_credit( manifest, 2UL, 4UL, 300UL, 100UL );
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  /* A near miss on the sentinel is not a marker, it is corruption. */
  setup_migration_marker_case( manifest, 2UL );
  set_epoch_credit( manifest, 0UL, 5UL, 100UL, 0UL );
  set_epoch_credit( manifest, 1UL, ULONG_MAX, ULONG_MAX, 100UL );
  FD_TEST( VALIDATE_MANIFEST( manifest )==-1 );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_recover_preserves_snapin_stake_delegations( fd_wksp_t * wksp, fd_snapshot_manifest_t * manifest ) {
  FD_LOG_NOTICE(( "testing recover preserves snapin stake delegations" ));

  /* Set up a tiny-capacity fd_banks_t.  Call fd_ssload_recover_apply
     directly (bypassing fd_ssload_recover_validate) because the
     validate step requires production-sized capacities outside the
     scope of this test. */

  ulong max_banks = 16UL;
  ulong max_forks =  4UL;
  ulong max_stake          = 64UL;
  ulong max_fallback_stake = 1024UL;
  ulong max_vote           = 64UL;
  ulong seed               = 42UL;

  ulong banks_footprint = fd_banks_footprint( max_banks, max_forks,
                                              max_stake, max_fallback_stake, max_vote );
  void * banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(),
                                          banks_footprint, 2UL );
  FD_TEST( banks_mem );

  fd_banks_t * banks = fd_banks_join( fd_banks_new( banks_mem, max_banks, max_forks,
                                                    max_stake, max_fallback_stake, max_vote,
                                                    0 /* larger_max_cost_per_block */, seed ) );
  FD_TEST( banks );

  fd_bank_t * bank = fd_banks_init_bank( banks );
  FD_TEST( bank );

  /* snapin has already populated the root cache directly from account
     data by the time ssload applies either manifest. */
  uchar pubkey_s[32]; fd_memset( pubkey_s, 0x99, 32 );
  uchar vote_s[32];   fd_memset( vote_s,   0x91, 32 );
  fd_stake_delegations_t * sd = fd_banks_stake_delegations_root_query( banks );
  fd_stake_delegations_root_update( sd,
                                    (fd_pubkey_t *)pubkey_s,
                                    (fd_pubkey_t *)vote_s,
                                    9000UL,
                                    0UL,
                                    ULONG_MAX,
                                    123UL,
                                    456UL,
                                    197U,
                                    FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );

  /* Manifest A: one vote stake (pubkey_X).  With slot=0, epoch=0,
     leader_schedule_epoch=1,
     epoch_stakes_base=0, t_1_idx=1. */

  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->accdb_fork_id    = 37U;
  manifest->txncache_fork_id = 38U;

  uchar pubkey_x[32]; fd_memset( pubkey_x, 0xBB, 32 );
  uchar ident_x[32];  fd_memset( ident_x,  0xB1, 32 );
  manifest->epoch_stakes[1].vote_stakes_len = 1UL;
  fd_memcpy( manifest->epoch_stakes[1].vote_stakes[0].vote,     pubkey_x, 32 );
  fd_memcpy( manifest->epoch_stakes[1].vote_stakes[0].identity, ident_x,  32 );
  manifest->epoch_stakes[1].vote_stakes[0].stake      = 5000UL;
  manifest->epoch_stakes[1].vote_stakes[0].commission = 10;
  manifest->epoch_stakes[1].vote_stakes[0].has_identity_bls = 1;
  fd_memset( manifest->epoch_stakes[1].vote_stakes[0].identity_bls, 0xB2, sizeof(manifest->epoch_stakes[1].vote_stakes[0].identity_bls) );
  manifest->epoch_stakes[1].total_stake               = 5000UL;

  /* First apply: simulate initial full snapshot load. */
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );
  FD_TEST( fd_ssload_recover_apply( manifest, bank, seed, digest_scratch )==0 );
  FD_TEST( bank->accdb_fork_id.val==37U );
  FD_TEST( bank->parent_accdb_fork_id.val==37U );
  FD_TEST( bank->txncache_fork_id.val==38U );

  /* ssload must leave the cache populated by snapin untouched. */
  FD_TEST( fd_stake_delegation_root_query( sd, (fd_pubkey_t *)pubkey_s )!=NULL );
  FD_TEST( fd_stake_delegations_base_cnt( sd )==1UL );

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
  FD_TEST( fd_vote_stakes_cnt_t_1( vote_stakes, bank->vote_stakes_fork_id )==1UL );
  ulong stake_out;
  FD_TEST( fd_vote_stakes_query_t_1( vote_stakes, bank->vote_stakes_fork_id, (fd_pubkey_t *)pubkey_x, NULL, &stake_out, NULL ) );
  FD_TEST( stake_out==5000UL );

  /* Manifest B: different vote stake (pubkey_Y). */

  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->accdb_fork_id    = 39U;
  manifest->txncache_fork_id = 40U;

  uchar pubkey_y[32]; fd_memset( pubkey_y, 0xDD, 32 );
  uchar ident_y[32];  fd_memset( ident_y,  0xD1, 32 );
  manifest->epoch_stakes[1].vote_stakes_len = 1UL;
  fd_memcpy( manifest->epoch_stakes[1].vote_stakes[0].vote,     pubkey_y, 32 );
  fd_memcpy( manifest->epoch_stakes[1].vote_stakes[0].identity, ident_y,  32 );
  manifest->epoch_stakes[1].vote_stakes[0].stake      = 7000UL;
  manifest->epoch_stakes[1].vote_stakes[0].commission = 5;
  manifest->epoch_stakes[1].vote_stakes[0].has_identity_bls = 1;
  fd_memset( manifest->epoch_stakes[1].vote_stakes[0].identity_bls, 0xD2, sizeof(manifest->epoch_stakes[1].vote_stakes[0].identity_bls) );
  manifest->epoch_stakes[1].total_stake               = 7000UL;

  /* A second manifest apply must also leave snapin's cache untouched. */
  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );
  FD_TEST( fd_ssload_recover_apply( manifest, bank, seed, digest_scratch )==0 );
  FD_TEST( bank->accdb_fork_id.val==39U );
  FD_TEST( bank->parent_accdb_fork_id.val==39U );
  FD_TEST( bank->txncache_fork_id.val==40U );

  /* snapin's delegation remains present. */
  FD_TEST( fd_stake_delegation_root_query( sd, (fd_pubkey_t *)pubkey_s )!=NULL );
  FD_TEST( fd_stake_delegations_base_cnt( sd )==1UL );

  /* Top votes: pubkey_X must have been removed, pubkey_Y must be
     present, exactly 1 entry (not 2). */
  FD_TEST( fd_vote_stakes_cnt_t_1( vote_stakes, bank->vote_stakes_fork_id )==1UL );
  FD_TEST( !fd_vote_stakes_query_t_1( vote_stakes, bank->vote_stakes_fork_id, (fd_pubkey_t *)pubkey_x, NULL, &stake_out, NULL ) );
  FD_TEST(  fd_vote_stakes_query_t_1( vote_stakes, bank->vote_stakes_fork_id, (fd_pubkey_t *)pubkey_y, NULL, &stake_out, NULL ) );
  FD_TEST( stake_out==7000UL );

  /* Manifest C: an epoch-2 snapshot with a T-3 vote stake that is not
     present in T-1. */
  fd_memset( manifest, 0, sizeof(*manifest) );
  setup_valid_manifest_base( manifest );
  manifest->slot = 2UL*manifest->epoch_schedule_params.slots_per_epoch;

  manifest->epoch_stakes[2].vote_stakes_len = 1UL;
  fd_memcpy( manifest->epoch_stakes[2].vote_stakes[0].vote,     pubkey_x, 32UL );
  fd_memcpy( manifest->epoch_stakes[2].vote_stakes[0].identity, ident_x,  32UL );
  manifest->epoch_stakes[2].vote_stakes[0].stake      = 5000UL;
  manifest->epoch_stakes[2].vote_stakes[0].commission = 10U;
  manifest->epoch_stakes[2].vote_stakes[0].has_identity_bls = 1;

  uchar valid_bls[2][ FD_BLS_PUBKEY_COMPRESSED_SZ ];
  fd_hex_decode( valid_bls[0], "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb", sizeof(valid_bls[0]) );
  fd_hex_decode( valid_bls[1], "af9ff5448e60bc9a718f463ac102bd6f8772e6460c19076a6c89d5806e5a8ef44b6f3b8af09e37a4e564987a26b9deda", sizeof(valid_bls[1]) );

  uchar pubkey_w[32]; fd_memset( pubkey_w, 0xEF, 32UL );
  uchar ident_w[32];  fd_memset( ident_w,  0xE2, 32UL );
  manifest->epoch_stakes[1].vote_stakes_len = 1UL;
  fd_memcpy( manifest->epoch_stakes[1].vote_stakes[0].vote,         pubkey_w,     32UL );
  fd_memcpy( manifest->epoch_stakes[1].vote_stakes[0].identity,     ident_w,      32UL );
  fd_memcpy( manifest->epoch_stakes[1].vote_stakes[0].identity_bls, valid_bls[1], sizeof(valid_bls[1]) );
  manifest->epoch_stakes[1].vote_stakes[0].stake            = 4000UL;
  manifest->epoch_stakes[1].vote_stakes[0].commission       = 11U;
  manifest->epoch_stakes[1].vote_stakes[0].has_identity_bls = 1;
  manifest->epoch_stakes[1].total_stake                     = 4000UL;

  uchar pubkey_z[32]; fd_memset( pubkey_z, 0xEE, 32UL );
  uchar ident_z[32];  fd_memset( ident_z,  0xE1, 32UL );
  manifest->epoch_stakes[0].vote_stakes_len = 1UL;
  fd_memcpy( manifest->epoch_stakes[0].vote_stakes[0].vote,         pubkey_z,     32UL );
  fd_memcpy( manifest->epoch_stakes[0].vote_stakes[0].identity,     ident_z,      32UL );
  fd_memcpy( manifest->epoch_stakes[0].vote_stakes[0].identity_bls, valid_bls[0], sizeof(valid_bls[0]) );
  manifest->epoch_stakes[0].vote_stakes[0].stake            = 3000UL;
  manifest->epoch_stakes[0].vote_stakes[0].commission       = 17U;
  manifest->epoch_stakes[0].vote_stakes[0].has_identity_bls = 1;
  manifest->epoch_stakes[0].total_stake                     = 3000UL;

  FD_TEST( VALIDATE_MANIFEST( manifest )==0 );
  FD_TEST( fd_ssload_recover_apply( manifest, bank, seed, digest_scratch )==0 );

  fd_pubkey_t node_out;
  ushort      commission_out;
  FD_TEST( fd_vote_stakes_query_t_3( vote_stakes, bank->vote_stakes_fork_id, (fd_pubkey_t *)pubkey_z,
                                     &node_out, &stake_out, &commission_out ) );
  FD_TEST( fd_pubkey_eq( &node_out, (fd_pubkey_t *)ident_z ) );
  FD_TEST( stake_out==3000UL && commission_out==17U );
  FD_TEST( fd_vote_stakes_total_stake( vote_stakes, 1UL )==3000UL );

  ushort rank_out = FD_VOTE_STAKES_ALPENGLOW_RANK_NULL;
  uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
  fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, bank->vote_stakes_fork_id, FD_VOTE_STAKES_ITER_T_2, iter_mem );
  FD_TEST( !fd_vote_stakes_iter_done( vote_stakes, bank->vote_stakes_fork_id, FD_VOTE_STAKES_ITER_T_2, iter ) );
  fd_pubkey_t iter_pubkey;
  fd_vote_stakes_iter_ele( vote_stakes, bank->vote_stakes_fork_id, FD_VOTE_STAKES_ITER_T_2, iter,
                           &iter_pubkey, NULL, NULL, NULL, NULL, NULL, NULL, &rank_out, NULL );
  FD_TEST( fd_pubkey_eq( &iter_pubkey, (fd_pubkey_t *)pubkey_w ) && rank_out==0U );

  rank_out = FD_VOTE_STAKES_ALPENGLOW_RANK_NULL;
  iter = fd_vote_stakes_iter_init( vote_stakes, bank->vote_stakes_fork_id, FD_VOTE_STAKES_ITER_T_3, iter_mem );
  FD_TEST( !fd_vote_stakes_iter_done( vote_stakes, bank->vote_stakes_fork_id, FD_VOTE_STAKES_ITER_T_3, iter ) );
  fd_vote_stakes_iter_ele( vote_stakes, bank->vote_stakes_fork_id, FD_VOTE_STAKES_ITER_T_3, iter,
                           &iter_pubkey, NULL, NULL, NULL, NULL, NULL, NULL, &rank_out, NULL );
  FD_TEST( fd_pubkey_eq( &iter_pubkey, (fd_pubkey_t *)pubkey_z ) && rank_out==0U );

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
  test_ticks_per_slot( manifest );
  test_epoch_schedule( manifest );
  test_blockhash_queue( manifest );
  test_hard_forks( manifest );
  test_vote_accounts( manifest );
  test_epoch_credits_downcasting( manifest );
  test_epoch_credits_migration_marker( manifest );
  test_recover_preserves_snapin_stake_delegations( wksp, manifest );

  fd_wksp_free_laddr( manifest );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "all ssload tests passed" ));

  fd_halt();
  return 0;
}
