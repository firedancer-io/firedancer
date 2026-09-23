#define _GNU_SOURCE
#include "fd_stake_delegations.c"
#include "test_stake_delegations_util.h"
#include "fd_stakes.h"
#include "fd_stake_types.h"
#include "../runtime/fd_system_ids.h"
#include "../../disco/store/fd_store.h"
#include "../../util/fd_hash32.h"

#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

FD_STATIC_ASSERT( FD_STAKE_DELEGATIONS_FD!=FD_STORE_FD_RW, stake_spill_fd_store_rw );
FD_STATIC_ASSERT( FD_STAKE_DELEGATIONS_FD!=FD_STORE_FD_RO, stake_spill_fd_store_ro );
FD_STATIC_ASSERT( FD_STAKE_DELEGATIONS_FD!=FD_ACCDB_FD_RW, stake_spill_fd_accdb_rw );
FD_STATIC_ASSERT( FD_STAKE_DELEGATIONS_FD!=FD_ACCDB_FD_RO, stake_spill_fd_accdb_ro );

FD_STATIC_ASSERT( offsetof( fd_stake_state_t, stake_type  )==  0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_state_t, initialized )==  4UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_state_t, stake       )==  4UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_stake_state_t              )==197UL, layout );

FD_STATIC_ASSERT( offsetof( fd_stake_meta_t, rent_exempt_reserve )==  0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_meta_t, staker              )==  8UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_meta_t, withdrawer          )== 40UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_meta_t, unix_timestamp      )== 72UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_meta_t, epoch               )== 80UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_meta_t, custodian           )== 88UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_stake_meta_t                      )==120UL, layout );

FD_STATIC_ASSERT( offsetof( fd_delegation_t, voter_pubkey              )== 0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_delegation_t, stake                     )==32UL, layout );
FD_STATIC_ASSERT( offsetof( fd_delegation_t, activation_epoch          )==40UL, layout );
FD_STATIC_ASSERT( offsetof( fd_delegation_t, deactivation_epoch        )==48UL, layout );
FD_STATIC_ASSERT( offsetof( fd_delegation_t, warmup_cooldown_rate_bits )==56UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_delegation_t                            )==64UL, layout );

FD_STATIC_ASSERT( offsetof( fd_stake_t, delegation       )== 0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_t, credits_observed )==64UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_stake_t                   )==72UL, layout );
FD_STATIC_ASSERT( sizeof  ( fd_stake_delegation_t        )==112UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_delegation_t, stake_account        )==  0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_delegation_t, key                  )==  0UL, layout );
FD_STATIC_ASSERT( sizeof(fd_stake_delegation_key_t)==34UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_delegation_key_t, stake_account )== 0UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_delegation_key_t, fork_idx      )==32UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_delegation_t, vote_account         )== 40UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_delegation_t, stake                )== 72UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_delegation_t, lamports             )== 80UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_delegation_t, credits_observed     )== 88UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_delegation_t, acc_dlen             )== 96UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_delegation_t, next_                )==100UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_delegation_t, delta_idx            )==104UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_delegation_t, fork_next            )==104UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_delegation_t, activation_epoch     )== 34UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_delegation_t, deactivation_epoch   )== 36UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_delegation_t, is_tombstone         )== 38UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_delegation_t, dne_in_root          )== 38UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_delegation_t, slot                 )==108UL, layout );
FD_STATIC_ASSERT( offsetof( fd_stake_delegation_t, fork_idx             )== 32UL, layout );

#define TEST_STAKE_DELEGATION_LAMPORTS (123456789UL)
#define TEST_STAKE_DELEGATION_ACC_DLEN ((uint)sizeof(fd_stake_state_t))

static inline ulong
test_stake_delegations_disk_cnt( fd_stake_delegations_t const * stake_delegations ) {
  return stake_delegations->disk_root_cnt_ + stake_delegations->disk_delta_cnt_;
}

static ulong
count_visible_delegations( fd_stake_delegations_t const * stake_delegations ) {
  ulong cnt = 0UL;
  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * d = fd_stake_delegations_iter_ele( iter );
    if( FD_LIKELY( !d->is_tombstone ) ) cnt++;
  }
  return cnt;
}

static void
assert_delegation( fd_stake_delegation_t const * d,
                  fd_pubkey_t const *            stake_account,
                  fd_pubkey_t const *            vote_account,
                  ulong                          stake,
                  ushort                         activation_epoch,
                  ushort                         deactivation_epoch ) {
  FD_TEST( d );
  FD_TEST( !memcmp( &d->stake_account, stake_account, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &d->vote_account, vote_account, sizeof(fd_pubkey_t) ) );
  FD_TEST( d->stake == stake );
  FD_TEST( d->lamports == TEST_STAKE_DELEGATION_LAMPORTS );
  FD_TEST( d->acc_dlen == TEST_STAKE_DELEGATION_ACC_DLEN );
  FD_TEST( d->activation_epoch == activation_epoch );
  FD_TEST( d->deactivation_epoch == deactivation_epoch );
}

static void
test_footprint( void ) {
  ulong const small_forks = 32UL;
  ulong const large_forks = FD_STAKE_DELEGATIONS_FORK_MAX;
  ulong small = fd_stake_delegations_footprint( 1024UL, small_forks );
  ulong large = fd_stake_delegations_footprint( 1024UL, large_forks );
  FD_TEST( large>small );
  FD_TEST( large-small<64UL*(large_forks-small_forks) );
}

static void
test_inactive_predicates( void ) {
  ulong const epoch = 4UL;
  ulong       warmup_cooldown_rate_epoch = ULONG_MAX;
  fd_stake_history_t history[1] = {0};

  fd_delegation_t active = {
    .stake               = 100UL,
    .activation_epoch    = ULONG_MAX,
    .deactivation_epoch  = ULONG_MAX,
  };
  fd_delegation_t activating = {
    .stake               = 100UL,
    .activation_epoch    = epoch,
    .deactivation_epoch  = ULONG_MAX,
  };
  fd_delegation_t deactivating = {
    .stake               = 100UL,
    .activation_epoch    = ULONG_MAX,
    .deactivation_epoch  = epoch,
  };
  fd_delegation_t inactive = {
    .stake               = 100UL,
    .activation_epoch    = epoch,
    .deactivation_epoch  = epoch,
  };

  FD_TEST( !fd_delegation_is_inactive( &active,       epoch, history, &warmup_cooldown_rate_epoch, 1 ) );
  FD_TEST( !fd_delegation_is_inactive( &activating,   epoch, history, &warmup_cooldown_rate_epoch, 1 ) );
  FD_TEST( !fd_delegation_is_inactive( &deactivating, epoch, history, &warmup_cooldown_rate_epoch, 1 ) );
  FD_TEST(  fd_delegation_is_inactive( &inactive,     epoch, history, &warmup_cooldown_rate_epoch, 1 ) );

  fd_stake_delegation_t cached_inactive = {
    .stake              = 100UL,
    .activation_epoch   = (ushort)epoch,
    .deactivation_epoch = (ushort)epoch,
  };
  FD_TEST( fd_stake_delegation_is_inactive(
      &cached_inactive, epoch, history, &warmup_cooldown_rate_epoch, 1 ) );
}

static void
test_instance_disk_isolation( void ) {
  int fd_a = memfd_create( "stake_delegations_a", 0 );
  int fd_b = memfd_create( "stake_delegations_b", 0 );
  FD_TEST( fd_a>=0 && fd_b>=0 );

  ulong align     = fd_stake_delegations_align();
  ulong footprint = fd_ulong_align_up( fd_stake_delegations_footprint( 1UL, 1UL ), align );
  void * mem_a = aligned_alloc( align, footprint );
  void * mem_b = aligned_alloc( align, footprint );
  FD_TEST( mem_a && mem_b );

  FD_TEST( fd_stake_delegations_new( mem_a, fd_a, 1UL, 1UL, 8UL, 1UL ) );
  FD_TEST( fd_stake_delegations_new( mem_b, fd_b, 1UL, 1UL, 8UL, 1UL ) );
  FD_TEST( !fd_stake_delegations_join( mem_a, fd_b ) );
  fd_stake_delegations_t * a = fd_stake_delegations_join( mem_a, fd_a );
  fd_stake_delegations_t * b = fd_stake_delegations_join( mem_b, fd_b );
  FD_TEST( a && b );

  fd_pubkey_t root_key = { .ul = { 1UL } };
  fd_pubkey_t disk_key = { .ul = { 2UL } };
  fd_pubkey_t vote_key = { .ul = { 3UL } };
  fd_stake_delegations_root_update( a, &root_key, &vote_key, 1UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
  fd_stake_delegations_root_update( a, &disk_key, &vote_key, 11UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
  fd_stake_delegations_root_update( b, &root_key, &vote_key, 2UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
  fd_stake_delegations_root_update( b, &disk_key, &vote_key, 22UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );

  fd_stake_delegation_t found[1];
  FD_TEST( test_stake_delegations_find_copy( a, &disk_key, found ) && found->stake==11UL );
  FD_TEST( test_stake_delegations_find_copy( b, &disk_key, found ) && found->stake==22UL );

  free( mem_a );
  free( mem_b );
  FD_TEST( !close( fd_a ) );
  FD_TEST( !close( fd_b ) );
}

static void
test_stake_delegations_mark_fork_delta( fd_stake_delegations_t *   stake_delegations,
                                        ulong                      epoch,
                                        fd_stake_history_t const * stake_history,
                                        ulong *                    warmup_cooldown_rate_epoch,
                                        int                        use_fixed_point_stake_math,
                                        ushort                     fork_id ) {
  fd_stake_delegations_view_begin( stake_delegations, epoch, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_id );
}

static void
test_stake_delegations_unmark_fork_delta( fd_stake_delegations_t *   stake_delegations,
                                          fd_stake_history_t const * stake_history,
                                          ulong *                    warmup_cooldown_rate_epoch,
                                          int                        use_fixed_point_stake_math ) {
  fd_stake_delegations_view_end( stake_delegations, stake_history, warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
}

/* Aggregate totals remain available without exposing the store layout. */
static void
test_totals( void ) {
  int spill_fd = memfd_create( "stake_delegations_totals", 0 );
  FD_TEST( spill_fd>=0 );
  ulong footprint = fd_stake_delegations_footprint( 2UL, 2UL );
  void * mem = aligned_alloc( fd_stake_delegations_align(), footprint );
  FD_TEST( mem );
  fd_stake_delegations_t * stake_delegations = fd_stake_delegations_join(
      fd_stake_delegations_new( mem, spill_fd, 23UL, 2UL, 8UL, 2UL ), spill_fd );
  FD_TEST( stake_delegations );

  fd_stake_history_entry_t totals = fd_stake_delegations_totals( stake_delegations );
  FD_TEST( !totals.epoch && !totals.effective && !totals.activating && !totals.deactivating );
  fd_stake_delegations_set_totals( stake_delegations, 101UL, 202UL, 303UL );
  totals = fd_stake_delegations_totals( stake_delegations );
  FD_TEST( !totals.epoch && totals.effective==101UL && totals.activating==202UL && totals.deactivating==303UL );

  fd_pubkey_t key = { .ul = { 7UL, 11UL } };
  ushort fork = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
  fd_stake_delegations_fork_update( stake_delegations, fork, &key, &key, 19UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
  fd_stake_history_t history[1] = {0};
  fd_stake_delegations_view_begin( stake_delegations, 1UL, history, NULL, 1, fork );
  totals = fd_stake_delegations_totals( stake_delegations );
  FD_TEST( totals.effective==120UL && totals.activating==202UL && totals.deactivating==303UL );
  fd_stake_delegations_view_end( stake_delegations, history, NULL, 1 );
  totals = fd_stake_delegations_totals( stake_delegations );
  FD_TEST( totals.effective==101UL && totals.activating==202UL && totals.deactivating==303UL );
  fd_stake_delegations_evict_fork( stake_delegations, fork );
  fd_stake_delegations_reset( stake_delegations );
  totals = fd_stake_delegations_totals( stake_delegations );
  FD_TEST( !totals.effective && !totals.activating && !totals.deactivating );

  free( mem );
  FD_TEST( !close( spill_fd ) );
}

/* All forks share one account.  Their other accounts differ only in the
   last eight bytes and deliberately share a bucket.  Replacing either
   list link during overwrite or failing to unlink a cancelled fork must
   not change another fork's visible delegations. */

static void
test_shared_forks( ulong max_stake_accounts ) {
  int spill_fd = memfd_create( "stake_delegations_shared_forks", 0 );
  FD_TEST( spill_fd>=0 );
  ulong footprint = fd_stake_delegations_footprint( max_stake_accounts, 16UL );
  void * mem = aligned_alloc( fd_stake_delegations_align(), footprint );
  FD_TEST( mem );
  fd_stake_delegations_t * stake_delegations = fd_stake_delegations_join(
      fd_stake_delegations_new( mem, spill_fd, 9UL, max_stake_accounts, 128UL, 16UL ), spill_fd );
  FD_TEST( stake_delegations );

  fd_stake_history_t history[1] = {0};
  ulong warmup_cooldown_rate_epoch = ULONG_MAX;
  fd_pubkey_t shared_key = { .ul = { 42UL, 17UL, 99UL, 1UL } };
  fd_pubkey_t vote_key   = { .ul = { 43UL, 18UL, 98UL, 3UL } };
  ulong delta_max  = max_stake_accounts/FD_STAKE_DELEGATIONS_DELTA_POOL_DIVISOR;
  ulong bucket_cnt = fd_ulong_pow2_up( delta_max );
  ulong candidate  = 2UL;

  for( ulong round=0UL; round<2UL; round++ ) {
    /* Reset with live deltas left over from the preceding round. */
    fd_stake_delegations_reset( stake_delegations );
    fd_stake_delegations_root_update( stake_delegations, &shared_key, &vote_key, 7UL, ULONG_MAX, ULONG_MAX, 7UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    stake_delegations->effective_stake = 7UL;

    ushort      forks[ 16 ];
    fd_pubkey_t keys[ 16 ][ 4 ];
    ulong       stakes[ 16 ];
    for( ulong f=0UL; f<16UL; f++ ) {
      forks[ f ] = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
      stakes[ f ] = 100UL+10UL*f+1000UL*round;
      keys[ f ][ 0 ] = shared_key;
      for( ulong k=1UL; k<4UL; k++ ) {
        do {
          keys[ f ][ k ] = (fd_pubkey_t){ .ul = { 42UL, 17UL, 99UL, candidate++ } };
        } while( fd_hash32( keys[ f ][ k ].uc, 9UL^(ulong)forks[ f ] ) & (bucket_cnt-1UL) );
      }
      for( ulong pass=0UL; pass<3UL; pass++ ) {
        for( ulong k=0UL; k<4UL; k++ ) {
          fd_stake_delegations_fork_remove( stake_delegations, forks[ f ], &keys[ f ][ k ] );
          fd_stake_delegations_fork_update( stake_delegations, forks[ f ], &keys[ f ][ k ], &vote_key, stakes[ f ]+k, ULONG_MAX, ULONG_MAX, stakes[ f ]+k, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
        }
      }
      fd_stake_delegations_fork_remove( stake_delegations, forks[ f ], &keys[ f ][ 2 ] );
    }
    FD_TEST( stake_delegations->disk_delta_cnt_==64UL-delta_max );

    for( ulong step=0UL; step<=16UL; step++ ) {
      for( ulong f=0UL; f<16UL; f++ ) {
        fd_stake_delegations_view_begin( stake_delegations, 1UL, history, &warmup_cooldown_rate_epoch, 1, forks[ f ] );
        for( ulong k=0UL; k<4UL; k++ ) {
          fd_stake_delegation_t found[1];
          int exists = test_stake_delegations_find_copy( stake_delegations, &keys[ f ][ k ], found );
          FD_TEST( exists==(k!=2UL) );
          if( exists ) {
            assert_delegation( found, &keys[ f ][ k ], &vote_key, stakes[ f ]+k, USHORT_MAX, USHORT_MAX );
            FD_TEST( found->credits_observed==stakes[ f ]+k );
          }
        }
        FD_TEST( count_visible_delegations( stake_delegations )==3UL );
        FD_TEST( stake_delegations->effective_stake==3UL*stakes[ f ]+4UL );
        FD_TEST( !stake_delegations->activating_stake );
        FD_TEST( !stake_delegations->deactivating_stake );
        fd_stake_delegations_view_end( stake_delegations, history, &warmup_cooldown_rate_epoch, 1 );
        FD_TEST( count_visible_delegations( stake_delegations )==1UL );
        FD_TEST( stake_delegations->effective_stake==7UL );
      }
      if( step==16UL ) break;

      ulong f = (5UL*step+3UL)%16UL;
      ushort old_fork = forks[ f ];
      fd_stake_delegations_evict_fork( stake_delegations, old_fork );
      forks[ f ] = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
      FD_TEST( forks[ f ]==old_fork ); /* The only free fork ID. */
      fd_stake_delegations_view_begin( stake_delegations, 1UL, history, &warmup_cooldown_rate_epoch, 1, forks[ f ] );
      FD_TEST( count_visible_delegations( stake_delegations )==1UL );
      FD_TEST( stake_delegations->effective_stake==7UL );
      fd_stake_delegations_view_end( stake_delegations, history, &warmup_cooldown_rate_epoch, 1 );

      stakes[ f ] += 10000UL;
      for( ulong k=0UL; k<4UL; k++ ) {
        if( k ) {
          do {
            keys[ f ][ k ] = (fd_pubkey_t){ .ul = { 42UL, 17UL, 99UL, candidate++ } };
          } while( fd_hash32( keys[ f ][ k ].uc, 9UL^(ulong)forks[ f ] ) & (bucket_cnt-1UL) );
        }
        fd_stake_delegations_fork_update( stake_delegations, forks[ f ], &keys[ f ][ k ], &vote_key, stakes[ f ]+k, ULONG_MAX, ULONG_MAX, stakes[ f ]+k, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
      }
      fd_stake_delegations_fork_remove( stake_delegations, forks[ f ], &keys[ f ][ 2 ] );
      FD_TEST( stake_delegations->disk_delta_cnt_==64UL-delta_max );
    }

    ushort rooted[ 2 ] = { forks[ 1 ], forks[ 10 ] };
    fd_stake_delegations_delta_stats_t stats = {0};
    fd_stake_delegations_advance_root( 1UL, history, &warmup_cooldown_rate_epoch, 1, stake_delegations, rooted[ 0 ], &stats );
    fd_stake_delegations_advance_root( 1UL, history, &warmup_cooldown_rate_epoch, 1, stake_delegations, rooted[ 1 ], &stats );
    FD_TEST( stats.upserts==6UL );
    FD_TEST( stats.removes==2UL );
    FD_TEST( stats.root_cnt==5UL );
    FD_TEST( count_visible_delegations( stake_delegations )==5UL );
    FD_TEST( stake_delegations->effective_stake==2UL*stakes[ 1 ]+3UL*stakes[ 10 ]+8UL );
    fd_stake_delegation_t found[1];
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &shared_key, found ) );
    FD_TEST( found->stake==stakes[ 10 ] );

    /* Resident deltas remain available after apply until eviction. */
    fd_stake_delegations_advance_root( 1UL, history, &warmup_cooldown_rate_epoch, 1, stake_delegations, rooted[ 0 ], &stats );
    FD_TEST( stats.upserts==9UL );
    FD_TEST( stats.removes==3UL );
    FD_TEST( stats.root_cnt==5UL );
    fd_stake_delegations_evict_fork( stake_delegations, rooted[ 0 ] );
    fd_stake_delegations_evict_fork( stake_delegations, rooted[ 1 ] );
    FD_TEST( count_visible_delegations( stake_delegations )==5UL );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &shared_key, found ) );
    FD_TEST( found->stake==stakes[ 1 ] );
    FD_TEST( stake_delegations->effective_stake==3UL*stakes[ 1 ]+2UL*stakes[ 10 ]+8UL );
  }

  free( mem );
  FD_TEST( !close( spill_fd ) );
}

/* Exercise disk batches with independent iterators, delta overrides,
   a fully tombstoned batch, and a partial final batch. */
static void
test_disk_iterator_batches( void ) {
  int spill_fd = memfd_create( "stake_delegations_iter_batches", 0 );
  FD_TEST( spill_fd>=0 );
  ulong footprint = fd_stake_delegations_footprint( 8UL, 4UL );
  void * mem = aligned_alloc( fd_stake_delegations_align(), footprint );
  FD_TEST( mem );
  fd_stake_delegations_t * stake_delegations = fd_stake_delegations_join(
      fd_stake_delegations_new( mem, spill_fd, 17UL, 8UL, 512UL, 4UL ), spill_fd );
  FD_TEST( stake_delegations );

  fd_pubkey_t keys[ 269 ];
  ulong       expected[ 269 ];
  fd_pubkey_t vote_key = { .ul = { 99UL, 7UL, 0UL, 0UL } };
  for( ulong i=0UL; i<269UL; i++ ) {
    keys[ i ] = (fd_pubkey_t){ .ul = { i+1UL, 17UL, 0UL, 0UL } };
    expected[ i ] = i<267UL ? i+1UL : 0UL;
    if( i>=267UL ) continue;
    fd_stake_delegations_root_update( stake_delegations, &keys[ i ], &vote_key, i+1UL, ULONG_MAX, ULONG_MAX, i, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    stake_delegations->effective_stake += i+1UL;
  }
  FD_TEST( stake_delegations->disk_root_cnt_==259UL );

  fd_stake_history_t history[1] = {0};
  for( ulong phase=0UL; phase<3UL; phase++ ) {
    ushort fork = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    if( phase==1UL ) {
      /* The first four deltas stay resident.  Later deltas spill. */
      ulong const modified[ 9 ] = { 0UL, 8UL, 135UL, 136UL, 7UL, 134UL, 264UL, 266UL, 267UL };
      for( ulong j=0UL; j<9UL; j++ ) {
        ulong i = modified[ j ];
        expected[ i ] = i+1000UL;
        fd_stake_delegations_fork_update( stake_delegations, fork, &keys[ i ], &vote_key, expected[ i ], ULONG_MAX, ULONG_MAX, i, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
      }
      fd_stake_delegations_fork_remove( stake_delegations, fork, &keys[ 8 ] );
      expected[ 8 ] = 0UL;
      for( ulong i=136UL; i<264UL; i++ ) {
        fd_stake_delegations_fork_remove( stake_delegations, fork, &keys[ i ] );
        expected[ i ] = 0UL;
      }
      FD_TEST( stake_delegations->disk_delta_cnt_>0UL );
    }

    fd_stake_delegations_view_begin( stake_delegations, 1UL, history, NULL, 1, fork );
    fd_stake_delegations_iter_t iter[ 2 ];
    uchar seen[ 2 ][ 269 ] = {{0}};
    uchar seen_idx[ 2 ][ 269 ] = {{0}};
    ulong count[ 2 ] = {0};
    for( ulong j=0UL; j<2UL; j++ ) fd_stake_delegations_iter_init( &iter[ j ], stake_delegations );
    while( !fd_stake_delegations_iter_done( &iter[ 0 ] ) || !fd_stake_delegations_iter_done( &iter[ 1 ] ) ) {
      /* Pause iterator 1 on its first disk root while iterator 0 crosses
         batches and reads disk deltas using its own scratch record. */
      ulong j = count[ 1 ]<8UL || fd_stake_delegations_iter_done( &iter[ 0 ] ) ? 1UL : 0UL;
      fd_stake_delegation_t const * d = fd_stake_delegations_iter_ele( &iter[ j ] );
      ulong i = d->stake_account.ul[ 0 ]-1UL;
      ulong idx = fd_stake_delegations_iter_idx( &iter[ j ] );
      FD_TEST( i<269UL && expected[ i ] && !seen[ j ][ i ] );
      FD_TEST( idx<269UL && !seen_idx[ j ][ idx ] );
      FD_TEST( d->stake==expected[ i ] && fd_pubkey_eq( &d->vote_account, &vote_key ) );
      FD_TEST( d->credits_observed==i && !d->is_tombstone );
      if( i<267UL ) FD_TEST( idx==i );
      seen[ j ][ i ] = seen_idx[ j ][ idx ] = 1;
      count[ j ]++;
      fd_stake_delegation_t saved;
      fd_stake_delegation_t const * paused = NULL;
      if( !fd_stake_delegations_iter_done( &iter[ 1UL-j ] ) ) {
        paused = fd_stake_delegations_iter_ele( &iter[ 1UL-j ] );
        saved = *paused;
      }
      fd_stake_delegations_iter_next( &iter[ j ] );
      if( paused ) FD_TEST( !memcmp( paused, &saved, sizeof(saved) ) );
    }
    for( ulong j=0UL; j<2UL; j++ ) {
      ulong expected_count = 0UL;
      for( ulong i=0UL; i<269UL; i++ ) {
        FD_TEST( !!seen[ j ][ i ]==!!expected[ i ] );
        expected_count += !!expected[ i ];
      }
      FD_TEST( count[ j ]==expected_count );
    }
    fd_stake_delegations_view_end( stake_delegations, history, NULL, 1 );
    fd_stake_delegations_evict_fork( stake_delegations, fork );
    FD_TEST( stake_delegations->disk_root_cnt_==259UL );
    for( ulong i=0UL; i<269UL; i++ ) expected[ i ] = i<267UL ? i+1UL : 0UL;
  }

  free( mem );
  FD_TEST( !close( spill_fd ) );
}

/* Interleaved disk-only fork lists exercise neighbor relinking and
   swap-with-last.  Keys collide at the last bucket to force wraparound. */
static void
test_disk_delta_links( void ) {
  int spill_fd = memfd_create( "stake_delegations_delta_links", 0 );
  FD_TEST( spill_fd>=0 );
  ulong footprint = fd_stake_delegations_footprint( 2UL, 4UL );
  void * mem = aligned_alloc( fd_stake_delegations_align(), footprint );
  FD_TEST( mem );
  fd_stake_delegations_t * stake_delegations = fd_stake_delegations_join(
      fd_stake_delegations_new( mem, spill_fd, 19UL, 2UL, 64UL, 4UL ), spill_fd );
  FD_TEST( stake_delegations );
  fd_pubkey_t vote_key = { .ul = { 19UL, 23UL } };
  fd_pubkey_t filler_key = { .ul = { 29UL, 31UL } };
  fd_stake_history_t history[1] = {0};
  ulong candidate = 1UL;

  for( ulong round=0UL; round<3UL; round++ ) {
    fd_stake_delegations_reset( stake_delegations );
    ushort filler = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, filler, &filler_key, &vote_key, 1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    ushort forks[ 3 ];
    fd_pubkey_t keys[ 3 ][ 3 ];
    ulong stakes[ 3 ][ 3 ];
    for( ulong f=0UL; f<3UL; f++ ) forks[ f ] = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    for( ulong j=0UL; j<3UL; j++ ) {
      for( ulong f=0UL; f<3UL; f++ ) {
        do {
          keys[ f ][ j ] = (fd_pubkey_t){ .ul = { candidate++, 37UL } };
        } while( (fd_hash32( keys[ f ][ j ].uc, 19UL^(ulong)forks[ f ] ) & (stake_delegations->disk_bucket_cnt_-1UL))!=stake_delegations->disk_bucket_cnt_-1UL );
        stakes[ f ][ j ] = 100UL+10UL*f+j;
        fd_stake_delegations_fork_update( stake_delegations, forks[ f ], &keys[ f ][ j ], &vote_key, stakes[ f ][ j ], ULONG_MAX, ULONG_MAX, j, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
      }
    }
    FD_TEST( stake_delegations->disk_delta_cnt_==9UL );
    ulong removed_fork = round;
    fd_stake_delegations_evict_fork( stake_delegations, forks[ removed_fork ] );
    FD_TEST( stake_delegations->disk_delta_cnt_==6UL );
    FD_TEST( stake_delegations->disk_delta_tombstone_cnt_==3UL );
    ushort recycled = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    FD_TEST( recycled==forks[ removed_fork ] );

    /* A matching key beyond a tombstone must be overwritten, not inserted. */
    ulong survivor = (removed_fork+1UL)%3UL;
    stakes[ survivor ][ 1 ] += 1000UL;
    fd_stake_delegations_fork_update( stake_delegations, forks[ survivor ], &keys[ survivor ][ 1 ], &vote_key, stakes[ survivor ][ 1 ], ULONG_MAX, ULONG_MAX, 1UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    FD_TEST( stake_delegations->disk_delta_cnt_==6UL );
    for( ulong j=0UL; j<3UL; j++ ) {
      stakes[ removed_fork ][ j ] += 2000UL;
      fd_stake_delegations_fork_update( stake_delegations, recycled, &keys[ removed_fork ][ j ], &vote_key, stakes[ removed_fork ][ j ], ULONG_MAX, ULONG_MAX, j, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
      FD_TEST( stake_delegations->disk_delta_tombstone_cnt_==2UL-j );
    }
    FD_TEST( stake_delegations->disk_delta_cnt_==9UL );
    for( ulong f=0UL; f<3UL; f++ ) {
      fd_stake_delegations_view_begin( stake_delegations, 1UL, history, NULL, 1, forks[ f ] );
      FD_TEST( count_visible_delegations( stake_delegations )==3UL );
      for( ulong j=0UL; j<3UL; j++ ) {
        fd_stake_delegation_t found[1];
        FD_TEST( test_stake_delegations_find_copy( stake_delegations, &keys[ f ][ j ], found ) );
        FD_TEST( found->stake==stakes[ f ][ j ] && found->credits_observed==j );
        FD_TEST( fd_pubkey_eq( &found->vote_account, &vote_key ) );
      }
      fd_stake_delegations_view_end( stake_delegations, history, NULL, 1 );
    }
    /* Applying the reinserted list removes adjacent last records. */
    fd_stake_delegations_delta_stats_t stats = {0};
    fd_stake_delegations_advance_root( 1UL, history, NULL, 1, stake_delegations, recycled, &stats );
    FD_TEST( stats.upserts==3UL && !stats.removes && stats.root_cnt==3UL );
    fd_stake_delegations_evict_fork( stake_delegations, recycled );
    for( ulong f=0UL; f<3UL; f++ ) {
      if( f!=removed_fork ) fd_stake_delegations_evict_fork( stake_delegations, forks[ f ] );
    }
    FD_TEST( !stake_delegations->disk_delta_cnt_ && !stake_delegations->disk_delta_tombstone_cnt_ );
    fd_stake_delegations_evict_fork( stake_delegations, filler );
    for( ulong j=0UL; j<3UL; j++ ) {
      fd_stake_delegation_t found[1];
      FD_TEST( test_stake_delegations_find_copy( stake_delegations, &keys[ removed_fork ][ j ], found ) );
      FD_TEST( found->stake==stakes[ removed_fork ][ j ] && found->credits_observed==j );
    }
  }
  free( mem );
  FD_TEST( !close( spill_fd ) );
}

/* A target fork inherits only its parent chain.  Rooting and recycling
   ancestors must not attach surviving descendants to a reused ID. */
static void
test_ancestry( ulong root_max ) {
  int spill_fd = memfd_create( "stake_delegations_ancestry", 0 );
  FD_TEST( spill_fd>=0 );
  ulong footprint = fd_stake_delegations_footprint( root_max, 16UL );
  void * mem = aligned_alloc( fd_stake_delegations_align(), footprint );
  FD_TEST( mem );
  fd_stake_delegations_t * sd = fd_stake_delegations_join(
      fd_stake_delegations_new( mem, spill_fd, 7UL, root_max, 64UL, 16UL ), spill_fd );
  FD_TEST( sd );
  fd_pubkey_t a = { .ul = { 1UL } };
  fd_pubkey_t b = { .ul = { 2UL } };
  fd_pubkey_t c = { .ul = { 3UL } };
  fd_stake_history_t history[1] = {0};
  fd_stake_delegations_root_update( sd, &a, &a, 10UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
  fd_stake_delegations_set_totals( sd, 10UL, 0UL, 0UL );
  ushort parent  = fd_stake_delegations_new_fork( sd, USHORT_MAX );
  ushort child   = fd_stake_delegations_new_fork( sd, parent );
  ushort sibling = fd_stake_delegations_new_fork( sd, parent );
  ushort tip     = fd_stake_delegations_new_fork( sd, child );
  fd_stake_delegations_fork_update( sd, parent, &a, &a, 20UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
  fd_stake_delegations_fork_update( sd, parent, &b, &b, 7UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
  fd_stake_delegations_fork_remove( sd, child, &a );
  fd_stake_delegations_fork_update( sd, child, &b, &b, 30UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
  fd_stake_delegations_fork_update( sd, sibling, &a, &a, 90UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
  fd_stake_delegation_t found[1];
  for( ulong round=0UL; round<2UL; round++ ) {
    fd_stake_delegations_view_begin( sd, 1UL, history, NULL, 1, tip );
    FD_TEST( !test_stake_delegations_find_copy( sd, &a, found ) );
    FD_TEST( test_stake_delegations_find_copy( sd, &b, found ) && found->stake==30UL );
    FD_TEST( fd_stake_delegations_totals( sd ).effective==30UL );
    fd_stake_delegations_view_end( sd, history, NULL, 1 );
    FD_TEST( fd_stake_delegations_totals( sd ).effective==10UL );
    fd_stake_delegations_view_begin( sd, 1UL, history, NULL, 1, sibling );
    FD_TEST( test_stake_delegations_find_copy( sd, &a, found ) && found->stake==90UL );
    FD_TEST( test_stake_delegations_find_copy( sd, &b, found ) && found->stake==7UL );
    fd_stake_delegations_view_end( sd, history, NULL, 1 );
  }
  fd_stake_delegations_delta_stats_t stats = {0};
  fd_stake_delegations_advance_root( 1UL, history, NULL, 1, sd, child, &stats );
  FD_TEST( stats.upserts==3UL && stats.removes==1UL && stats.root_cnt==1UL );
  FD_TEST( get_fork_pool( sd )[ tip ].parent==USHORT_MAX );
  fd_stake_delegations_evict_fork( sd, child );
  fd_stake_delegations_evict_fork( sd, parent );
  fd_stake_delegations_evict_fork( sd, sibling );
  ushort reused[3];
  for( ulong i=0UL; i<3UL; i++ ) {
    reused[i] = fd_stake_delegations_new_fork( sd, USHORT_MAX );
    fd_stake_delegations_fork_update( sd, reused[i], &c, &c, 999UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
  }
  fd_stake_delegations_view_begin( sd, 1UL, history, NULL, 1, tip );
  FD_TEST( !test_stake_delegations_find_copy( sd, &a, found ) );
  FD_TEST( !test_stake_delegations_find_copy( sd, &c, found ) );
  FD_TEST( test_stake_delegations_find_copy( sd, &b, found ) && found->stake==30UL );
  fd_stake_delegations_view_end( sd, history, NULL, 1 );
  fd_stake_delegations_reset( sd );
  fd_stake_delegations_view_begin( sd, 1UL, history, NULL, 1, USHORT_MAX );
  FD_TEST( !count_visible_delegations( sd ) );
  fd_stake_delegations_view_end( sd, history, NULL, 1 );
  free( mem );
  FD_TEST( !close( spill_fd ) );
}

/* Full-depth ancestry and invalid fork IDs. */
static void
test_ancestry_lifetimes( void ) {
  int spill_fd = memfd_create( "stake_delegations_ancestry_lifetimes", 0 );
  FD_TEST( spill_fd>=0 );
  ulong footprint = fd_stake_delegations_footprint( 2UL, FD_STAKE_DELEGATIONS_FORK_MAX );
  void * mem = aligned_alloc( fd_stake_delegations_align(), footprint );
  FD_TEST( mem );
  fd_stake_delegations_t * sd = fd_stake_delegations_join(
      fd_stake_delegations_new( mem, spill_fd, 11UL, 2UL, 64UL, FD_STAKE_DELEGATIONS_FORK_MAX ), spill_fd );
  FD_TEST( sd );
  fd_pubkey_t key = { .ul = { 17UL } };
  fd_stake_history_t history[1] = {0};
  fd_stake_delegation_t found[1];
  ushort parent = USHORT_MAX;

  ushort chain[ FD_STAKE_DELEGATIONS_FORK_MAX ];
  for( ulong i=0UL; i<FD_STAKE_DELEGATIONS_FORK_MAX; i++ ) {
    chain[ i ] = fd_stake_delegations_new_fork( sd, parent );
    parent = chain[ i ];
  }
  fd_stake_delegations_fork_update( sd, chain[0], &key, &key, 11UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
  fd_stake_delegations_fork_update( sd, parent, &key, &key, 42UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
  fd_stake_delegations_view_begin( sd, 1UL, history, NULL, 1, parent );
  FD_TEST( test_stake_delegations_find_copy( sd, &key, found ) && found->stake==42UL );
  fd_stake_delegations_view_end( sd, history, NULL, 1 );
  fd_stake_delegations_delta_stats_t stats = {0};
  fd_stake_delegations_advance_root( 1UL, history, NULL, 1, sd, parent, &stats );
  FD_TEST( stats.upserts==2UL && !stats.removes && stats.root_cnt==1UL );
  for( ulong i=0UL; i<FD_STAKE_DELEGATIONS_FORK_MAX; i++ ) fd_stake_delegations_evict_fork( sd, chain[ i ] );
  FD_TEST( fork_pool_free( get_fork_pool( sd ) )==FD_STAKE_DELEGATIONS_FORK_MAX );

  /* Invalid parents and freed query targets must fail before reuse. */
  for( int mode=0; mode<3; mode++ ) {
    pid_t pid = fork();
    FD_TEST( pid>=0 );
    if( !pid ) {
      if( mode==0 ) fd_stake_delegations_new_fork( sd, chain[0] );
      else if( mode==1 ) fd_stake_delegations_new_fork( sd, FORK_PARENT_FREE );
      else fd_stake_delegations_view_begin( sd, 1UL, history, NULL, 1, chain[0] );
      _exit( 0 );
    }
    int status;
    FD_TEST( waitpid( pid, &status, 0 )==pid );
    FD_TEST( (WIFEXITED( status ) && WEXITSTATUS( status )!=0) || WIFSIGNALED( status ) );
  }
  free( mem );
  FD_TEST( !close( spill_fd ) );
}

int main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  test_ancestry_lifetimes();
  test_ancestry( 2UL );
  test_ancestry( 64UL );
  test_footprint();
  test_totals();
  test_disk_delta_links();
  test_disk_iterator_batches();
  test_shared_forks( 128UL );
  test_shared_forks( 32UL );
  test_inactive_predicates();
  test_instance_disk_isolation();

  int spill_fd = memfd_create( "stakedel_spill", 0 );
  FD_TEST( spill_fd>=0 );
  if( spill_fd!=FD_STAKE_DELEGATIONS_FD ) {
    FD_TEST( dup2( spill_fd, FD_STAKE_DELEGATIONS_FD )==FD_STAKE_DELEGATIONS_FD );
    FD_TEST( !close( spill_fd ) );
  }

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL,            NULL );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL,      "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL,             1UL );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  ulong        wksp_tag = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",  NULL,          1234UL );

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  /* Test stake delegations where is_tombstone == 0 */

  ulong const max_stake_accounts = 10UL;
  ulong const max_delta_accounts = fd_ulong_max(
      max_stake_accounts/FD_STAKE_DELEGATIONS_DELTA_POOL_DIVISOR, 1UL );

  /* Sets disk-delta capacity and derives disk-root capacity. */
  ulong const max_disk_records = 512UL;

  ulong const max_live_slots = 32UL;

  void * stake_delegations_mem = fd_wksp_alloc_laddr( wksp, fd_stake_delegations_align(), fd_stake_delegations_footprint( max_stake_accounts, max_live_slots ), wksp_tag );
  FD_TEST( stake_delegations_mem );

  FD_TEST( fd_stake_delegations_align()>=alignof(fd_stake_delegations_t)  );
  FD_TEST( fd_stake_delegations_align()==FD_STAKE_DELEGATIONS_ALIGN );

  FD_TEST( !fd_stake_delegations_new( NULL, FD_STAKE_DELEGATIONS_FD, 0UL, max_stake_accounts, max_disk_records, max_live_slots ) );
  FD_TEST( !fd_stake_delegations_new( stake_delegations_mem, -1, 0UL, max_stake_accounts, max_disk_records, max_live_slots ) );
  FD_TEST( !fd_stake_delegations_new( stake_delegations_mem, FD_STAKE_DELEGATIONS_FD, 0UL, 0UL, max_disk_records, max_live_slots ) );
  void * new_stake_delegations_mem = fd_stake_delegations_new( stake_delegations_mem, FD_STAKE_DELEGATIONS_FD, 0UL, max_stake_accounts, max_disk_records, max_live_slots );
  FD_TEST( new_stake_delegations_mem );

  FD_TEST( !fd_stake_delegations_join( NULL, FD_STAKE_DELEGATIONS_FD ) );
  void * junk_mem = fd_wksp_alloc_laddr( wksp, fd_stake_delegations_align(), sizeof(fd_stake_delegations_t), 999UL );
  FD_TEST( junk_mem );
  memset( junk_mem, 0, sizeof(fd_stake_delegations_t) );
  FD_TEST( !fd_stake_delegations_join( junk_mem, FD_STAKE_DELEGATIONS_FD ) );

  fd_stake_delegations_t * stake_delegations = fd_stake_delegations_join( new_stake_delegations_mem, FD_STAKE_DELEGATIONS_FD );
  FD_TEST( stake_delegations );

  fd_pubkey_t stake_account_0 = { .ul = { 999UL, 999UL} };
  fd_pubkey_t stake_account_1 = { .ul = { 1, 2 } };
  fd_pubkey_t stake_account_2 = { .ul = { 3, 4 } };
  fd_pubkey_t stake_account_3 = { .ul = { 5, 6 } };

  fd_pubkey_t voter_pubkey_0 = { .ul = { 5, 6 } };
  fd_pubkey_t voter_pubkey_1 = { .ul = { 7, 8 } };

  /* Fill the in-memory delta tier, then verify the next delta spills. */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    for( ulong i=0UL; i<=max_delta_accounts; i++ ) {
      FD_TEST( !stake_delegations->disk_delta_cnt_ );
      fd_pubkey_t key = { .ul = { i, 999UL } };
      fd_stake_delegations_fork_update( stake_delegations, fork_idx, &key, &voter_pubkey_0, i+1UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    }
    FD_TEST( stake_delegations->disk_delta_cnt_==1UL );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    FD_TEST( !stake_delegations->disk_delta_cnt_ );
  }

  FD_TEST( test_stake_delegations_base_cnt( stake_delegations ) == 0UL );
  fd_stake_delegations_root_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 100UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
  FD_TEST( test_stake_delegations_base_cnt( stake_delegations ) == 1UL );
  fd_stake_delegations_root_update( stake_delegations, &stake_account_1, &voter_pubkey_1, 200UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
  FD_TEST( test_stake_delegations_base_cnt( stake_delegations ) == 2UL );
  fd_stake_delegations_root_update( stake_delegations, &stake_account_2, &voter_pubkey_1, 300UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
  FD_TEST( test_stake_delegations_base_cnt( stake_delegations ) == 3UL );

  fd_stake_delegation_t stake_delegation_0[1];
  FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
  FD_TEST( !memcmp( &stake_delegation_0->stake_account, &stake_account_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_0->vote_account, &voter_pubkey_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_0->stake == 100UL );
  FD_TEST( stake_delegation_0->lamports == TEST_STAKE_DELEGATION_LAMPORTS );
  FD_TEST( stake_delegation_0->acc_dlen == TEST_STAKE_DELEGATION_ACC_DLEN );
  FD_TEST( stake_delegation_0->activation_epoch == 0UL );
  FD_TEST( stake_delegation_0->deactivation_epoch == 0UL );

  fd_stake_delegation_t stake_delegation_1[1];
  FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_1, stake_delegation_1 ) );
  FD_TEST( !memcmp( &stake_delegation_1->stake_account, &stake_account_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_1->vote_account, &voter_pubkey_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_1->stake == 200UL );
  FD_TEST( stake_delegation_1->lamports == TEST_STAKE_DELEGATION_LAMPORTS );
  FD_TEST( stake_delegation_1->acc_dlen == TEST_STAKE_DELEGATION_ACC_DLEN );
  FD_TEST( stake_delegation_1->activation_epoch == 0UL );
  FD_TEST( stake_delegation_1->deactivation_epoch == 0UL );

  fd_stake_delegation_t stake_delegation_2[1];
  FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_2, stake_delegation_2 ) );
  FD_TEST( !memcmp( &stake_delegation_2->stake_account, &stake_account_2, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_2->vote_account, &voter_pubkey_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_2->stake == 300UL );
  FD_TEST( stake_delegation_2->lamports == TEST_STAKE_DELEGATION_LAMPORTS );
  FD_TEST( stake_delegation_2->acc_dlen == TEST_STAKE_DELEGATION_ACC_DLEN );
  FD_TEST( stake_delegation_2->activation_epoch == 0UL );
  FD_TEST( stake_delegation_2->deactivation_epoch == 0UL );

  FD_TEST( !test_stake_delegations_contains( stake_delegations, &stake_account_3 ) );

  fd_stake_delegations_root_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
  FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
  FD_TEST( !memcmp( &stake_delegation_0->stake_account, &stake_account_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_0->vote_account, &voter_pubkey_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_0->stake == 200UL );
  FD_TEST( stake_delegation_0->lamports == TEST_STAKE_DELEGATION_LAMPORTS );
  FD_TEST( stake_delegation_0->acc_dlen == TEST_STAKE_DELEGATION_ACC_DLEN );
  FD_TEST( stake_delegation_0->activation_epoch == 0UL );
  FD_TEST( stake_delegation_0->deactivation_epoch == 0UL );
  FD_TEST( test_stake_delegations_base_cnt( stake_delegations ) == 3UL );

  ushort remove_fork = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
  fd_stake_delegations_fork_remove( stake_delegations, remove_fork, &stake_account_1 );

  ulong epoch = 10;
  fd_stake_history_t stake_history[1] = {0};
  ulong warmup_cooldown_rate_epoch = 0UL;
  int   use_fixed_point_stake_math = 0;
  fd_stake_delegations_delta_stats_t remove_stats = {0};
  fd_stake_delegations_advance_root( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, remove_fork, &remove_stats );
  FD_TEST( remove_stats.upserts==0UL );
  FD_TEST( remove_stats.removes==1UL );
  FD_TEST( remove_stats.root_cnt==test_stake_delegations_base_cnt( stake_delegations ) );
  fd_stake_delegations_evict_fork( stake_delegations, remove_fork );
  FD_TEST( !test_stake_delegations_contains( stake_delegations, &stake_account_1 ) );
  FD_TEST( test_stake_delegations_base_cnt( stake_delegations ) == 2UL );

  fd_stake_delegations_root_update( stake_delegations, &stake_account_1, &voter_pubkey_1, 10000UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
  FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_1, stake_delegation_1 ) );
  FD_TEST( !memcmp( &stake_delegation_1->stake_account, &stake_account_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_1->vote_account, &voter_pubkey_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_1->stake == 10000UL );
  FD_TEST( stake_delegation_1->lamports == TEST_STAKE_DELEGATION_LAMPORTS );
  FD_TEST( stake_delegation_1->acc_dlen == TEST_STAKE_DELEGATION_ACC_DLEN );
  FD_TEST( stake_delegation_1->activation_epoch == 0UL );
  FD_TEST( stake_delegation_1->deactivation_epoch == 0UL );
  FD_TEST( test_stake_delegations_base_cnt( stake_delegations ) == 3UL );

  /* Test stake delegation delta mark/unmark */

  /* Case 1: Empty fork */
  {
    ushort empty_fork = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    ulong  cnt_before = count_visible_delegations( stake_delegations );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, empty_fork );
    FD_TEST( count_visible_delegations( stake_delegations ) == cnt_before );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( count_visible_delegations( stake_delegations ) == cnt_before );
    fd_stake_delegations_evict_fork( stake_delegations, empty_fork );
  }

  /* Case 2: Delta for existing root (update) */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 500UL, 1UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_1, 500UL, 1UL, 0UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 3: Delta for non-existing root (insert) */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &stake_account_3 ) );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 777UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    fd_stake_delegation_t d3[1];
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_3, d3 ) );
    assert_delegation( d3, &stake_account_3, &voter_pubkey_0, 777UL, 0UL, 0UL );
    FD_TEST( test_stake_delegations_base_cnt( stake_delegations ) == 4UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &stake_account_3 ) );
    FD_TEST( test_stake_delegations_base_cnt( stake_delegations ) == 3UL );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 4: Tombstone for existing root */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &stake_account_0 ) );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 6: Multiple updates - last wins */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 100UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    FD_TEST( stake_delegation_0->stake == 200UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 7: Update then tombstone */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 999UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &stake_account_0 ) );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 8: Tombstone then update */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 111UL, 2UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_1, 111UL, 2UL, 0UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 9: Sequential fork mark/unmark */
  {
    ushort fork0 = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    ushort fork1 = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork0, &stake_account_0, &voter_pubkey_0, 10UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_update( stake_delegations, fork1, &stake_account_0, &voter_pubkey_0, 20UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork0 );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    FD_TEST( stake_delegation_0->stake == 10UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork1 );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    FD_TEST( stake_delegation_0->stake == 20UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    FD_TEST( stake_delegation_0->stake == 200UL );
    fd_stake_delegations_evict_fork( stake_delegations, fork0 );
    fd_stake_delegations_evict_fork( stake_delegations, fork1 );
  }

  /* Case 10a: Remove then re-add across forks */
  {
    ushort fork1 = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    ushort fork2 = fd_stake_delegations_new_fork( stake_delegations, fork1 );
    fd_stake_delegations_fork_remove( stake_delegations, fork1, &stake_account_0 );
    fd_stake_delegations_fork_update( stake_delegations, fork2, &stake_account_0, &voter_pubkey_1, 333UL, 5UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    ushort fork_ids[] = { fork1, fork2 };
    fd_stake_delegations_view_begin( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_ids[ 1 ] );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_1, 333UL, 5UL, 0UL );
    fd_stake_delegations_view_end( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL );
    fd_stake_delegations_evict_fork( stake_delegations, fork1 );
    fd_stake_delegations_evict_fork( stake_delegations, fork2 );
  }

  /* Case 12: test_stake_delegations_base_cnt */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    ulong  cnt_before = test_stake_delegations_base_cnt( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 1UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( test_stake_delegations_base_cnt( stake_delegations ) == cnt_before + 1UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( test_stake_delegations_base_cnt( stake_delegations ) == cnt_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 15: Mixed fork */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 111UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_1 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 222UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_1, 111UL, 0UL, 0UL );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &stake_account_1 ) );
    fd_stake_delegation_t d3[1];
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_3, d3 ) );
    assert_delegation( d3, &stake_account_3, &voter_pubkey_0, 222UL, 0UL, 0UL );
    FD_TEST( count_visible_delegations( stake_delegations ) == 3UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( count_visible_delegations( stake_delegations ) == 3UL );
    FD_TEST( test_stake_delegations_contains( stake_delegations, &stake_account_1 ) );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &stake_account_3 ) );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Stake total tests.

     The existing tests all use activation_epoch=0, deactivation_epoch=0
     which produces zero effective stake.  To exercise the totals
     accounting we reinitialize the root with epochs that yield non-zero
     effective stake: activation_epoch=ULONG_MAX and
     deactivation_epoch=ULONG_MAX.  With an empty stake history and
     target_epoch=10 this gives effective=stake, activating=0,
     deactivating=0. */

  fd_stake_delegations_reset( stake_delegations );
  stake_delegations->effective_stake    = 0UL;
  stake_delegations->activating_stake   = 0UL;
  stake_delegations->deactivating_stake = 0UL;

  fd_stake_delegations_root_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 200UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
  fd_stake_delegations_root_update( stake_delegations, &stake_account_1, &voter_pubkey_1, 300UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
  fd_stake_delegations_root_update( stake_delegations, &stake_account_2, &voter_pubkey_1, 500UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );

  stake_delegations->effective_stake = 200UL + 300UL + 500UL;

  /* Case 16: Duplicate updates -- totals must reflect only the last delta */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 100UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 400UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before - 200UL + 400UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 17: Update then tombstone -- totals must subtract base, not double-count */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 999UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before - 200UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 18: Tombstone then update -- totals must reflect only the update */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 777UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before - 200UL + 777UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 19: Triple update -- totals must reflect only the last */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 10UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 20UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 30UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before - 200UL + 30UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 20: Duplicate updates for a new account (dne_in_root) */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 50UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 80UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before + 80UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &stake_account_3 ) );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* The query end must reuse the begin epoch when unwinding totals. */
  {
    fd_pubkey_t activating_account   = { .ul = { 0xaaaaUL, 0xbbbbUL } };
    fd_pubkey_t deactivating_account = { .ul = { 0xccccUL, 0xddddUL } };
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &activating_account,   &voter_pubkey_0, 70UL, epoch,     ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &deactivating_account, &voter_pubkey_0, 90UL, ULONG_MAX, epoch,     0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );

    ushort fork_ids[] = { fork_idx };
    fd_stake_delegations_view_begin( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_ids[ 0 ] );
    FD_TEST( stake_delegations->effective_stake==1090UL );
    FD_TEST( stake_delegations->activating_stake==70UL );
    FD_TEST( stake_delegations->deactivating_stake==90UL );

    fd_stake_delegations_view_end( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( stake_delegations->effective_stake==1000UL );
    FD_TEST( stake_delegations->activating_stake==0UL );
    FD_TEST( stake_delegations->deactivating_stake==0UL );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &activating_account ) );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &deactivating_account ) );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 21: New account insert then tombstone -- totals unchanged */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 123UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_3 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 22: Same-fork updates must consume only one delta pool element. */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    for( ulong i=0UL; i<=max_stake_accounts; i++ ) {
      fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 600UL+i, ULONG_MAX, ULONG_MAX, i, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    }
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    fd_stake_delegation_t d[1];
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, d ) );
    assert_delegation( d, &stake_account_0, &voter_pubkey_1, 600UL+max_stake_accounts, USHORT_MAX, USHORT_MAX );
    FD_TEST( d->credits_observed==max_stake_accounts );
    FD_TEST( stake_delegations->effective_stake==eff_before-200UL+600UL+max_stake_accounts );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( stake_delegations->effective_stake==eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 23: The same stake account has independent deltas across forks. */
  {
    ushort fork_a = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    ushort fork_b = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_a, &stake_account_0, &voter_pubkey_0, 901UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_update( stake_delegations, fork_b, &stake_account_0, &voter_pubkey_1, 902UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );

    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_a );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 901UL, USHORT_MAX, USHORT_MAX );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );

    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_b );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_1, 902UL, USHORT_MAX, USHORT_MAX );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );

    fd_stake_delegations_evict_fork( stake_delegations, fork_a );
    fd_stake_delegations_evict_fork( stake_delegations, fork_b );
  }

  /* Case 24: Same-fork removals must consume only one delta pool element. */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    for( ulong i=0UL; i<=max_stake_accounts; i++ ) {
      fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    }
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &stake_account_0 ) );
    FD_TEST( stake_delegations->effective_stake==eff_before-200UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( stake_delegations->effective_stake==eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 25: Reused fork indices start with an empty delta map. */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 903UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );

    ushort reused_fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    FD_TEST( reused_fork_idx==fork_idx );
    fd_stake_delegations_fork_update( stake_delegations, reused_fork_idx, &stake_account_0, &voter_pubkey_1, 904UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, reused_fork_idx );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_1, 904UL, USHORT_MAX, USHORT_MAX );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    fd_stake_delegations_evict_fork( stake_delegations, reused_fork_idx );
  }

  /* Case 26: Applying a deduplicated delta commits only the latest state. */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 905UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 906UL, ULONG_MAX, ULONG_MAX, 1UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_advance_root( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, fork_idx, NULL );
    fd_stake_delegation_t d[1];
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, d ) );
    assert_delegation( d, &stake_account_0, &voter_pubkey_1, 906UL, USHORT_MAX, USHORT_MAX );
    FD_TEST( d->credits_observed==1UL );
    FD_TEST( stake_delegations->effective_stake==eff_before-200UL+906UL );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );

    fd_stake_delegations_root_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 200UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    stake_delegations->effective_stake = eff_before;
  }

  /* Case 27: Reset clears the delta map before fork indices are reused. */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 907UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_reset( stake_delegations );
    FD_TEST( test_stake_delegations_base_cnt( stake_delegations )==0UL );

    ushort reset_fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, reset_fork_idx, &stake_account_0, &voter_pubkey_1, 908UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, reset_fork_idx );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_1, 908UL, USHORT_MAX, USHORT_MAX );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &stake_account_0 ) );
    fd_stake_delegations_evict_fork( stake_delegations, reset_fork_idx );
  }

  /* Case 28: The delta pool holds one eighth of the root capacity and
     excess entries spill to disk. */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    for( ulong i=0UL; i<max_stake_accounts; i++ ) {
      fd_pubkey_t stake_account = { .ul = { 1000UL+i, 2000UL+i } };
      fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    }
    FD_TEST( test_stake_delegations_disk_cnt( stake_delegations )==max_stake_accounts-max_delta_accounts );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    FD_TEST( !test_stake_delegations_disk_cnt( stake_delegations ) );
  }

  /* Case 29: Root and delta tiers consume the disk budget
     independently. */
  {
    fd_stake_delegations_reset( stake_delegations );
    FD_TEST( !test_stake_delegations_disk_cnt( stake_delegations ) );

    fd_stake_delegations_root_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 100UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    FD_TEST( !test_stake_delegations_disk_cnt( stake_delegations ) );

    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 101UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_1, &voter_pubkey_1, 102UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    FD_TEST( test_stake_delegations_disk_cnt( stake_delegations )==fd_ulong_sat_sub( 2UL, max_delta_accounts ) );

    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    FD_TEST( !test_stake_delegations_disk_cnt( stake_delegations ) );

    ushort remove_fork = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_remove( stake_delegations, remove_fork, &stake_account_0 );
    fd_stake_delegations_advance_root( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, remove_fork, NULL );
    fd_stake_delegations_evict_fork( stake_delegations, remove_fork );
    FD_TEST( !test_stake_delegations_disk_cnt( stake_delegations ) );
    FD_TEST( !test_stake_delegations_base_cnt( stake_delegations ) );
  }

  /* Case 30: Exhausting the root pool spills an exact full root record,
     and removing that record reclaims the disk slot. */
  {
    fd_stake_delegations_reset( stake_delegations );

    for( ulong i=0UL; i<max_stake_accounts; i++ ) {
      fd_pubkey_t k = { .ul = { 5000UL+i, 6000UL+i } };
      fd_stake_delegations_root_update( stake_delegations, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    }
    FD_TEST( test_stake_delegations_base_cnt( stake_delegations )==max_stake_accounts );
    FD_TEST( !test_stake_delegations_disk_cnt( stake_delegations ) );

    fd_pubkey_t overflow = { .ul = { 7777UL, 8888UL } };
    fd_stake_delegations_root_update( stake_delegations, &overflow, &voter_pubkey_1, 123UL, 1UL, 2UL, 3UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    FD_TEST( test_stake_delegations_base_cnt( stake_delegations )==max_stake_accounts+1UL );
    FD_TEST( test_stake_delegations_disk_cnt( stake_delegations )==1UL );
    fd_stake_delegation_t found[1];
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &overflow, found ) );
    assert_delegation( found, &overflow, &voter_pubkey_1, 123UL, 1U, 2U );
    FD_TEST( found->credits_observed==3UL );

    fd_pubkey_t first       = { .ul = { 5000UL, 6000UL } };
    ushort      remove_fork = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_remove( stake_delegations, remove_fork, &first );
    fd_stake_delegations_advance_root( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, remove_fork, NULL );
    fd_stake_delegations_evict_fork( stake_delegations, remove_fork );
    FD_TEST( test_stake_delegations_base_cnt( stake_delegations )==max_stake_accounts );
    FD_TEST( test_stake_delegations_disk_cnt( stake_delegations )==1UL );

    remove_fork = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_remove( stake_delegations, remove_fork, &overflow );
    fd_stake_delegations_advance_root( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, remove_fork, NULL );
    fd_stake_delegations_evict_fork( stake_delegations, remove_fork );
    FD_TEST( test_stake_delegations_base_cnt( stake_delegations )==max_stake_accounts-1UL );
    FD_TEST( !test_stake_delegations_disk_cnt( stake_delegations ) );

    fd_stake_delegations_reset( stake_delegations );
    FD_TEST( !test_stake_delegations_disk_cnt( stake_delegations ) );
  }

  /* Case 31: Exhausting the shared delta pool spills full, same-fork
     overwriteable delta records and eviction reclaims them. */
  {
    fd_stake_delegations_reset( stake_delegations );

    ushort      fork_idx  = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    ulong const delta_max = max_delta_accounts;
    for( ulong i=0UL; i<delta_max; i++ ) {
      fd_pubkey_t k = { .ul = { 20000UL+i, 30000UL+i } };
      fd_stake_delegations_fork_update( stake_delegations, fork_idx, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    }
    FD_TEST( !test_stake_delegations_disk_cnt( stake_delegations ) );

    fd_pubkey_t overflow = { .ul = { 40000UL, 50000UL } };
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &overflow, &voter_pubkey_0, 1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &overflow, &voter_pubkey_1, 456UL, 3UL, 8UL, 9UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    FD_TEST( test_stake_delegations_disk_cnt( stake_delegations )==1UL );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    fd_stake_delegation_t found[1];
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &overflow, found ) );
    assert_delegation( found, &overflow, &voter_pubkey_1, 456UL, 3U, 8U );
    FD_TEST( found->credits_observed==9UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );

    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    FD_TEST( !test_stake_delegations_disk_cnt( stake_delegations ) );
    fd_stake_delegations_reset( stake_delegations );
  }

  /* Case 32: Every configured or derived disk index fits below the
     delta tag bit. */
  {
    FD_TEST( stake_delegations->max_disk_records_==max_disk_records );
    FD_TEST( stake_delegations->max_disk_records_<(ulong)FD_STAKE_DELEGATIONS_DELTA_DISK_TAG );
    FD_TEST( 2UL*max_disk_records+max_stake_accounts<=(ulong)FD_STAKE_DELEGATIONS_DELTA_IDX_MASK );
  }

  /* Case 33: fp_warmed_awarded lifecycle + invalidate_warmed. */
  {
    FD_TEST( stake_delegations->fp_warmed_awarded==0 );

    /* Awarding a WARMED tag under the float math sets the flag. */
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 200UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_advance_root( epoch, stake_history, &warmup_cooldown_rate_epoch, 0 /* float */, stake_delegations, fork_idx, NULL );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    FD_TEST( stake_delegation_0->state==FD_STAKE_DELEGATION_STATE_WARMED );
    FD_TEST( stake_delegations->fp_warmed_awarded==1 );

    /* A conditional wipe demotes float-awarded tags and clears the flag. */
    fd_stake_delegations_invalidate_warmed( stake_delegations, 0 );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    FD_TEST( stake_delegation_0->state==FD_STAKE_DELEGATION_STATE_UNKNOWN );
    FD_TEST( stake_delegations->fp_warmed_awarded==0 );

    /* Awarding a WARMED tag under the fixed point math leaves the flag
       clear. */
    fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 200UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_advance_root( epoch, stake_history, &warmup_cooldown_rate_epoch, 1 /* fixed */, stake_delegations, fork_idx, NULL );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    FD_TEST( stake_delegation_0->state==FD_STAKE_DELEGATION_STATE_WARMED );
    FD_TEST( stake_delegations->fp_warmed_awarded==0 );

    /* Conditional invalidation retains a fixed-point WARMED tag, while
       forced invalidation clears it when stake history is incomplete. */
    fd_stake_delegations_invalidate_warmed( stake_delegations, 0 );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    FD_TEST( stake_delegation_0->state==FD_STAKE_DELEGATION_STATE_WARMED );
    fd_stake_delegations_invalidate_warmed( stake_delegations, 1 );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    FD_TEST( stake_delegation_0->state==FD_STAKE_DELEGATION_STATE_UNKNOWN );

    /* A COOLING award never touches the flag ... */
    fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 200UL, ULONG_MAX, 10UL /* deactivating at epoch */, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_advance_root( epoch, stake_history, &warmup_cooldown_rate_epoch, 0 /* float */, stake_delegations, fork_idx, NULL );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, stake_delegation_0 ) );
    FD_TEST( stake_delegation_0->state==FD_STAKE_DELEGATION_STATE_COOLING );
    FD_TEST( stake_delegations->fp_warmed_awarded==0 );

    /* ... and a later float WARMED re-award sets it again. */
    fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 200UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_advance_root( epoch, stake_history, &warmup_cooldown_rate_epoch, 0 /* float */, stake_delegations, fork_idx, NULL );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    FD_TEST( stake_delegations->fp_warmed_awarded==1 );
    fd_stake_delegations_invalidate_warmed( stake_delegations, 1 );
    FD_TEST( stake_delegations->fp_warmed_awarded==0 );
  }

  /* Case 34: Root pruning removes only delegations that are inactive
     in both the current and previous epochs. */
  {
    fd_stake_delegations_reset( stake_delegations );
    ulong const prune_epoch = 4UL;

    fd_stake_delegations_root_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_root_update( stake_delegations, &stake_account_1, &voter_pubkey_0, 1UL, ULONG_MAX, 3UL,       0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_root_update( stake_delegations, &stake_account_2, &voter_pubkey_0, 1UL, ULONG_MAX, 2UL,       0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_root_update( stake_delegations, &stake_account_3, &voter_pubkey_0, 1UL, 4UL,       4UL,       0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );

    fd_stake_delegations_prune_inactive_root(
        stake_delegations,
        prune_epoch,
        stake_history,
        &warmup_cooldown_rate_epoch,
        use_fixed_point_stake_math,
        NULL );
    FD_TEST(  test_stake_delegations_contains( stake_delegations, &stake_account_0 ) );
    FD_TEST(  test_stake_delegations_contains( stake_delegations, &stake_account_1 ) );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &stake_account_2 ) );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &stake_account_3 ) );
    FD_TEST( test_stake_delegations_base_cnt( stake_delegations )==2UL );
    FD_TEST( !test_stake_delegations_disk_cnt( stake_delegations ) );

    /* Applying the winning fork before pruning preserves a delegation
       that was reactivated after it became inert. */
    fd_stake_delegations_reset( stake_delegations );
    fd_stake_delegations_root_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 1UL, ULONG_MAX, 2UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_advance_root( prune_epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, fork_idx, NULL );
    fd_stake_delegations_prune_inactive_root(
        stake_delegations,
        prune_epoch,
        stake_history,
        &warmup_cooldown_rate_epoch,
        use_fixed_point_stake_math,
        NULL );
    fd_stake_delegation_t reactivated[1];
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, reactivated ) );
    FD_TEST( !memcmp( &reactivated->vote_account, &voter_pubkey_1, sizeof(fd_pubkey_t) ) );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 35: Dense disk records are reclaimed by reset/eviction, and
     boot refresh validates and prunes disk roots. */
  {
    fd_stake_delegations_reset( stake_delegations );

    ushort      fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    ulong const in_memory_max = max_delta_accounts;
    for( ulong i=0UL; i<in_memory_max; i++ ) {
      fd_pubkey_t k = { .ul = { 60000UL+i, 70000UL+i } };
      fd_stake_delegations_fork_update( stake_delegations, fork_idx, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    }
    FD_TEST( !test_stake_delegations_disk_cnt( stake_delegations ) );

    fd_pubkey_t overflow = { .ul = { 60000UL+in_memory_max, 70000UL+in_memory_max } };
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &overflow, &voter_pubkey_0, in_memory_max+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    FD_TEST( test_stake_delegations_disk_cnt( stake_delegations )==1UL );
    FD_TEST( lseek( FD_STAKE_DELEGATIONS_FD, 0L, SEEK_END )>0L );

    /* Reset must make stale disk records reusable. */
    fd_stake_delegations_reset( stake_delegations );
    FD_TEST( !test_stake_delegations_disk_cnt( stake_delegations ) );
    fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    ulong const disk_cnt = 12UL;
    for( ulong i=0UL; i<in_memory_max+disk_cnt; i++ ) {
      fd_pubkey_t k = { .ul = { 60000UL+i, 70000UL+i } };
      fd_stake_delegations_fork_update( stake_delegations, fork_idx, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    }
    FD_TEST( test_stake_delegations_disk_cnt( stake_delegations )==disk_cnt );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    FD_TEST( !test_stake_delegations_disk_cnt( stake_delegations ) );

    /* Refresh must apply remove_inactive_stakes to disk-tier entries,
       just as it does to in-memory-tier entries. */
    fd_stake_delegations_reset( stake_delegations );
    for( ulong i=0UL; i<max_stake_accounts; i++ ) {
      fd_pubkey_t k = { .ul = { 62000UL+i, 72000UL+i } };
      fd_stake_delegations_root_update( stake_delegations, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    }
    fd_stake_delegations_root_update( stake_delegations, &overflow, &voter_pubkey_0, 1UL, 2UL, 2UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    FD_TEST( test_stake_delegations_disk_cnt( stake_delegations )==1UL );

    ulong refresh_warmup_epoch = ULONG_MAX;
    fd_stake_delegations_iter_t iter_[1];
    int found_overflow = 0;
    for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
         !fd_stake_delegations_iter_done( iter );
         fd_stake_delegations_iter_next( iter ) ) {
      fd_stake_delegation_t const * delegation = fd_stake_delegations_iter_ele( iter );
      if( !fd_pubkey_eq( &delegation->stake_account, &overflow ) ) continue;
      assert_delegation( delegation, &overflow, &voter_pubkey_0, 1UL, 2U, 2U );
      FD_TEST( fd_stake_delegations_iter_idx( iter )>=max_stake_accounts );
      found_overflow = 1;
    }
    FD_TEST( found_overflow );

    /* Bootstrap delegations stay, the inactive disk-tier entry goes. */
    fd_stake_delegations_refresh(
        stake_delegations,
        4UL,
        stake_history,
        &refresh_warmup_epoch,
        1,
        1 );
    FD_TEST( test_stake_delegations_base_cnt( stake_delegations )==max_stake_accounts );
    FD_TEST( !test_stake_delegations_disk_cnt( stake_delegations ) );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &overflow ) );

    fd_stake_delegations_reset( stake_delegations );
  }

  /* Case 36: A root entry that exceeds the in-memory pool remains fully
     iterable without consulting accdb. */
  {
    fd_stake_delegations_reset( stake_delegations );

    for( ulong i=0UL; i<max_stake_accounts; i++ ) {
      fd_pubkey_t k = { .ul = { 80000UL+i, 90000UL+i } };
      fd_stake_delegations_root_update( stake_delegations, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    }

    fd_pubkey_t overflow = { .ul = { 81111UL, 92222UL } };
    fd_stake_delegations_root_update( stake_delegations, &overflow, &voter_pubkey_1, 424242UL, 3UL, 9UL, 17UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );

    fd_stake_delegation_t queried[1];
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &overflow, queried ) );
    assert_delegation( queried, &overflow, &voter_pubkey_1, 424242UL, 3U, 9U );
    fd_stake_delegation_t found[1];
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &overflow, found ) );
    assert_delegation( found, &overflow, &voter_pubkey_1, 424242UL, 3U, 9U );
    FD_TEST( found->credits_observed==17UL );
    FD_TEST( count_visible_delegations( stake_delegations )==max_stake_accounts+1UL );

    fd_pubkey_t overflow2 = { .ul = { 83333UL, 94444UL } };
    fd_stake_delegations_root_update( stake_delegations, &overflow2, &voter_pubkey_0, 515151UL, 4UL, 10UL, 18UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    ushort remove_fork = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_remove( stake_delegations, remove_fork, &overflow );
    fd_stake_delegations_advance_root( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, remove_fork, NULL );
    fd_stake_delegations_evict_fork( stake_delegations, remove_fork );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &overflow ) );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &overflow2, found ) );
    assert_delegation( found, &overflow2, &voter_pubkey_0, 515151UL, 4U, 10U );
    FD_TEST( found->credits_observed==18UL );
  }

  /* Case 37: Disk-spilled deltas retain independent state for sibling
     forks, honor ancestry order and tombstones, and can be rooted. */
  {
    fd_stake_delegations_reset( stake_delegations );

    for( ulong i=0UL; i<max_stake_accounts; i++ ) {
      fd_pubkey_t k = { .ul = { 100000UL+i, 110000UL+i } };
      fd_stake_delegations_root_update( stake_delegations, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    }
    fd_pubkey_t disk_existing = { .ul = { 101111UL, 112222UL } };
    fd_stake_delegations_root_update( stake_delegations, &disk_existing, &voter_pubkey_0, 44UL, 1UL, 6UL, 4UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );

    ushort filler_fork = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    for( ulong i=0UL; i<max_stake_accounts; i++ ) {
      fd_pubkey_t k = { .ul = { 120000UL+i, 130000UL+i } };
      fd_stake_delegations_fork_update( stake_delegations, filler_fork, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    }

    ushort fork0 = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    ushort fork1 = fd_stake_delegations_new_fork( stake_delegations, fork0 );
    fd_pubkey_t overflow = { .ul = { 141111UL, 152222UL } };
    fd_stake_delegations_fork_update( stake_delegations, fork0, &overflow, &voter_pubkey_0, 111UL, 1UL, 7UL, 11UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_update( stake_delegations, fork1, &overflow, &voter_pubkey_1, 222UL, 2UL, 8UL, 22UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_pubkey_t overflow2 = { .ul = { 163333UL, 174444UL } };
    fd_stake_delegations_fork_update( stake_delegations, fork0, &overflow2, &voter_pubkey_0, 333UL, 4UL, 10UL, 33UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_update( stake_delegations, fork0, &disk_existing, &voter_pubkey_0, 444UL, 5UL, 11UL, 44UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_update( stake_delegations, fork1, &disk_existing, &voter_pubkey_1, 555UL, 6UL, 12UL, 55UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );

    fd_stake_delegation_t found[1];
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork0 );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &overflow, found ) );
    assert_delegation( found, &overflow, &voter_pubkey_0, 111UL, 1U, 7U );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &overflow2, found ) );
    assert_delegation( found, &overflow2, &voter_pubkey_0, 333UL, 4U, 10U );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &disk_existing, found ) );
    assert_delegation( found, &disk_existing, &voter_pubkey_0, 444UL, 5U, 11U );
    test_stake_delegations_unmark_fork_delta( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );

    ushort fork_ids[2] = { fork0, fork1 };
    fd_stake_delegations_view_begin( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_ids[ 1 ] );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &overflow, found ) );
    assert_delegation( found, &overflow, &voter_pubkey_1, 222UL, 2U, 8U );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &disk_existing, found ) );
    assert_delegation( found, &disk_existing, &voter_pubkey_1, 555UL, 6U, 12U );
    fd_stake_delegations_view_end( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );

    fd_stake_delegations_fork_remove( stake_delegations, fork1, &overflow );
    fd_stake_delegations_view_begin( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_ids[ 1 ] );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &overflow ) );
    fd_stake_delegations_view_end( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );

    fd_stake_delegations_evict_fork( stake_delegations, fork1 );
    fd_stake_delegations_delta_stats_t disk_stats = {0};
    fd_stake_delegations_advance_root( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, fork0, &disk_stats );
    FD_TEST( disk_stats.upserts==3UL );
    FD_TEST( disk_stats.removes==0UL );
    FD_TEST( disk_stats.root_cnt==test_stake_delegations_base_cnt( stake_delegations ) );
    fd_stake_delegations_evict_fork( stake_delegations, fork0 );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &overflow, found ) );
    assert_delegation( found, &overflow, &voter_pubkey_0, 111UL, 1U, 7U );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &overflow2, found ) );
    assert_delegation( found, &overflow2, &voter_pubkey_0, 333UL, 4U, 10U );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &disk_existing, found ) );
    assert_delegation( found, &disk_existing, &voter_pubkey_0, 444UL, 5U, 11U );

    fd_stake_delegations_evict_fork( stake_delegations, filler_fork );
    fd_stake_delegations_reset( stake_delegations );
  }

  /* Case 38: Root-index tombstones are rebuilt before they can turn
     successful misses into full-table probes. */
  {
    fd_stake_delegations_reset( stake_delegations );

    for( ulong i=0UL; i<max_stake_accounts; i++ ) {
      fd_pubkey_t k = { .ul = { 180000UL+i, 190000UL+i } };
      fd_stake_delegations_root_update( stake_delegations, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    }

    fd_pubkey_t disk_keys[3] = {
      { .ul = { 181001UL, 191001UL } },
      { .ul = { 181002UL, 191002UL } },
      { .ul = { 181003UL, 191003UL } },
    };
    for( ulong i=0UL; i<3UL; i++ ) {
      fd_stake_delegations_root_update( stake_delegations, &disk_keys[i], &voter_pubkey_1, 100UL+i, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    }
    FD_TEST( stake_delegations->disk_root_cnt_==3UL );

    uint root_gen = stake_delegations->disk_root_gen_;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &disk_keys[0] );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &disk_keys[1] );
    fd_stake_delegations_advance_root( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, fork_idx, NULL );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );

    FD_TEST( stake_delegations->disk_root_cnt_==1UL );
    FD_TEST( stake_delegations->disk_root_gen_!=root_gen );
    FD_TEST( !stake_delegations->disk_root_tombstone_cnt_ );
    FD_TEST( test_stake_delegations_contains( stake_delegations, &disk_keys[2] ) );

    root_gen = stake_delegations->disk_root_gen_;
    fork_idx = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &disk_keys[2] );
    fd_stake_delegations_advance_root( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, fork_idx, NULL );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    FD_TEST( !stake_delegations->disk_root_cnt_ );
    FD_TEST( stake_delegations->disk_root_gen_!=root_gen );
    FD_TEST( !stake_delegations->disk_root_tombstone_cnt_ );
  }

  /* Case 39: Frontier projection uses ordinary disk-root capacity for
     temporary placeholders. */
  {
    int small_fd = memfd_create( "stake_delegations_small_frontier", 0 );
    FD_TEST( small_fd>=0 );

    ulong const small_max      = 1UL;
    ulong const small_disk_max = 1UL;
    ulong const small_forks    = 2UL;
    void * small_mem = fd_wksp_alloc_laddr(
        wksp,
        fd_stake_delegations_align(),
        fd_stake_delegations_footprint( small_max, small_forks ),
        wksp_tag );
    FD_TEST( small_mem );
    fd_stake_delegations_t * small = fd_stake_delegations_join(
        fd_stake_delegations_new( small_mem, small_fd, 1UL, small_max, small_disk_max, small_forks ),
        small_fd );
    FD_TEST( small );

    fd_pubkey_t root_key  = { .ul = { 160001UL, 170001UL } };
    fd_pubkey_t delta_key = { .ul = { 160002UL, 170002UL } };
    fd_pubkey_t disk_key  = { .ul = { 160003UL, 170003UL } };
    fd_stake_delegations_root_update( small, &root_key, &voter_pubkey_0, 1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    small->effective_stake    = 1UL;
    small->activating_stake   = 0UL;
    small->deactivating_stake = 0UL;

    ushort fork_idx = fd_stake_delegations_new_fork( small, USHORT_MAX );
    fd_stake_delegations_fork_update( small, fork_idx, &delta_key, &voter_pubkey_0, 2UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_update( small, fork_idx, &disk_key,  &voter_pubkey_1, 3UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    FD_TEST( test_stake_delegations_disk_cnt( small )==1UL );

    test_stake_delegations_mark_fork_delta( small, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( small->disk_root_cnt_==2UL );
    fd_stake_delegation_t found[1];
    FD_TEST( test_stake_delegations_find_copy( small, &delta_key, found ) );
    assert_delegation( found, &delta_key, &voter_pubkey_0, 2UL, USHORT_MAX, USHORT_MAX );
    FD_TEST( test_stake_delegations_find_copy( small, &disk_key, found ) );
    assert_delegation( found, &disk_key, &voter_pubkey_1, 3UL, USHORT_MAX, USHORT_MAX );
    FD_TEST( small->effective_stake==6UL );
    FD_TEST( !small->activating_stake );
    FD_TEST( !small->deactivating_stake );
    test_stake_delegations_unmark_fork_delta( small, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math );

    FD_TEST( small->effective_stake==1UL );
    FD_TEST( !small->activating_stake );
    FD_TEST( !small->deactivating_stake );
    FD_TEST( test_stake_delegations_disk_cnt( small )==1UL );
    fd_stake_delegations_evict_fork( small, fork_idx );
    FD_TEST( !test_stake_delegations_disk_cnt( small ) );
    FD_TEST( !close( small_fd ) );
    fd_wksp_free_laddr( small_mem );
  }

  /* Case 40: The root tier uses its full derived capacity without
     starving the independent disk-delta tier. */
  {
    int small_fd = memfd_create( "stake_delegations_small_capacity", 0 );
    FD_TEST( small_fd>=0 );

    ulong const small_max      = 1UL;
    ulong const small_disk_max = 1UL;
    ulong const small_forks    = 2UL;
    void * small_mem = fd_wksp_alloc_laddr(
        wksp,
        fd_stake_delegations_align(),
        fd_stake_delegations_footprint( small_max, small_forks ),
        wksp_tag );
    FD_TEST( small_mem );
    fd_stake_delegations_t * small = fd_stake_delegations_join(
        fd_stake_delegations_new( small_mem, small_fd, 3UL, small_max, small_disk_max, small_forks ),
        small_fd );
    FD_TEST( small );

    fd_pubkey_t root0  = { .ul = { 270001UL, 280001UL } };
    fd_pubkey_t root1  = { .ul = { 270002UL, 280002UL } };
    fd_pubkey_t root2  = { .ul = { 270003UL, 280003UL } };
    fd_pubkey_t root3  = { .ul = { 270004UL, 280004UL } };
    fd_pubkey_t delta0 = { .ul = { 270005UL, 280005UL } };
    fd_pubkey_t delta1 = { .ul = { 270006UL, 280006UL } };
    fd_stake_delegations_root_update( small, &root0, &voter_pubkey_0, 1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_root_update( small, &root1, &voter_pubkey_0, 2UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_root_update( small, &root2, &voter_pubkey_0, 3UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_root_update( small, &root3, &voter_pubkey_0, 4UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );

    ushort fork_idx = fd_stake_delegations_new_fork( small, USHORT_MAX );
    fd_stake_delegations_fork_update( small, fork_idx, &delta0, &voter_pubkey_1, 3UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_update( small, fork_idx, &delta1, &voter_pubkey_1, 4UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );

    FD_TEST( small->disk_root_cnt_==small_max+2UL*small_disk_max );
    FD_TEST( small->disk_delta_cnt_==1UL );
    FD_TEST( test_stake_delegations_disk_cnt( small )==small_max+3UL*small_disk_max );
    fd_stake_delegations_evict_fork( small, fork_idx );
    FD_TEST( small->disk_root_cnt_==small_max+2UL*small_disk_max );
    FD_TEST( !small->disk_delta_cnt_ );
    FD_TEST( !close( small_fd ) );
    fd_wksp_free_laddr( small_mem );
  }

  /* advance_root stats.  Stats count delta entries applied:
     a fork keeps at most one entry per stake account (last update
     wins), stats accumulate across applies, and tombstones for
     accounts absent from the root still count. */
  {
    fd_stake_delegations_delta_stats_t stats = {0};

    ushort fork_up = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_update( stake_delegations, fork_up, &stake_account_3, &voter_pubkey_0, 100UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_fork_update( stake_delegations, fork_up, &stake_account_3, &voter_pubkey_0, 200UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN );
    fd_stake_delegations_advance_root( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, fork_up, &stats );
    fd_stake_delegations_evict_fork( stake_delegations, fork_up );
    FD_TEST( stats.upserts==1UL ); /* duplicate update to one account dedups to one delta entry */
    FD_TEST( stats.removes==0UL );
    fd_stake_delegation_t stake_delegation_3[1];
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_3, stake_delegation_3 ) );
    FD_TEST( stake_delegation_3->stake==200UL ); /* last entry wins */

    ushort fork_rm = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_remove( stake_delegations, fork_rm, &stake_account_3 );
    fd_stake_delegations_fork_remove( stake_delegations, fork_rm, &stake_account_3 );
    fd_stake_delegations_advance_root( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, fork_rm, &stats );
    fd_stake_delegations_evict_fork( stake_delegations, fork_rm );
    FD_TEST( stats.upserts==1UL );
    FD_TEST( stats.removes==1UL ); /* removal of a root-present account */
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &stake_account_3 ) );

    /* Now that stake_account_3 is absent from the root, a tombstone for
       it must still be counted (the counter is per delta entry, not per
       actual map removal). */
    ushort fork_rm2 = fd_stake_delegations_new_fork( stake_delegations, USHORT_MAX );
    fd_stake_delegations_fork_remove( stake_delegations, fork_rm2, &stake_account_3 );
    fd_stake_delegations_advance_root( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, fork_rm2, &stats );
    fd_stake_delegations_evict_fork( stake_delegations, fork_rm2 );
    FD_TEST( stats.upserts==1UL );
    FD_TEST( stats.removes==2UL ); /* tombstone for a root-absent account still counts */
  }

  /* Case 41: Snapshot loader writes: newest slot wins, tombstones, and
     the incremental fork. */
  {
    ushort const ROOT = USHORT_MAX;
    ulong const snap_epoch = 4UL;
    ulong snap_warmup_epoch = 0UL;
    fd_stake_delegation_t d[1];
    fd_stake_delegations_iter_t iter_[1];
#   define SNAP_UPD( fork_, slot_, acct, voter, stake_ ) fd_stake_delegations_snapshot_upsert( stake_delegations, (fork_), (slot_), (acct), (voter), (stake_), ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN )

    /* Root: newest slot wins in either arrival order; equal slots
       overwrite. */
    fd_stake_delegations_reset( stake_delegations );
    SNAP_UPD( ROOT, 100UL, &stake_account_0, &voter_pubkey_0, 1UL );
    SNAP_UPD( ROOT, 200UL, &stake_account_0, &voter_pubkey_1, 2UL );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, d ) );
    assert_delegation( d, &stake_account_0, &voter_pubkey_1, 2UL, USHORT_MAX, USHORT_MAX );
    FD_TEST( d->slot==200U );
    SNAP_UPD( ROOT, 150UL, &stake_account_0, &voter_pubkey_0, 9UL );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, d ) && d->stake==2UL );
    SNAP_UPD( ROOT, 200UL, &stake_account_0, &voter_pubkey_1, 3UL );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, d ) && d->stake==3UL );

    /* Root tombstones: block older upserts, lose to newer ones, may
       precede any record unless cross_fork, and refresh sweeps. */
    SNAP_UPD( ROOT, 100UL, &stake_account_1, &voter_pubkey_0, 1UL );
    fd_stake_delegations_snapshot_remove( stake_delegations, ROOT, 200UL, &stake_account_1, 0 );
    fd_stake_delegations_snapshot_remove( stake_delegations, ROOT, 200UL, &stake_account_2, 0 );
    SNAP_UPD( ROOT, 100UL, &stake_account_2, &voter_pubkey_0, 1UL );
    fd_stake_delegations_snapshot_remove( stake_delegations, ROOT, 200UL, &stake_account_3, 0 );
    SNAP_UPD( ROOT, 300UL, &stake_account_3, &voter_pubkey_0, 5UL );
    fd_pubkey_t stake_account_4 = { .ul = { 40404UL, 1UL } };
    fd_pubkey_t stake_account_5 = { .ul = { 50505UL, 1UL } };
    fd_stake_delegations_snapshot_remove( stake_delegations, ROOT, 200UL, &stake_account_4, 1 );
    fd_stake_delegations_snapshot_remove( stake_delegations, ROOT, 200UL, &stake_account_5, 0 );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_1, d ) && !d->lamports );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_2, d ) && !d->lamports );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_3, d ) && d->stake==5UL );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &stake_account_4 ) );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_5, d ) && !d->lamports );
    FD_TEST( test_stake_delegations_base_cnt( stake_delegations )==5UL );
    fd_stake_delegations_refresh( stake_delegations, snap_epoch, stake_history, &snap_warmup_epoch, 1, 0 );
    FD_TEST(  test_stake_delegations_contains( stake_delegations, &stake_account_0 ) );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &stake_account_1 ) );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &stake_account_2 ) );
    FD_TEST(  test_stake_delegations_find_copy( stake_delegations, &stake_account_3, d ) );
    assert_delegation( d, &stake_account_3, &voter_pubkey_0, 5UL, USHORT_MAX, USHORT_MAX );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &stake_account_5 ) );
    FD_TEST( test_stake_delegations_base_cnt( stake_delegations )==2UL );
    FD_TEST( stake_delegations->effective_stake==3UL+5UL );

    /* Tombstones beyond the pool spill to disk; refresh drops every
       one, in both tiers, and repacks the pool. */
    fd_stake_delegations_reset( stake_delegations );
    for( ulong i=0UL; i<max_stake_accounts; i++ ) {
      fd_pubkey_t k = { .ul = { 90000UL+i, 1UL } };
      SNAP_UPD( ROOT, 10UL, &k, &voter_pubkey_0, i+1UL );
    }
    for( ulong i=0UL; i<3UL; i++ ) {  /* over live entries */
      fd_pubkey_t k = { .ul = { 90000UL+i, 1UL } };
      fd_stake_delegations_snapshot_remove( stake_delegations, ROOT, 20UL, &k, 0 );
    }
    for( ulong i=0UL; i<25UL; i++ ) { /* for accounts never in the cache */
      fd_pubkey_t k = { .ul = { 90500UL+i, 1UL } };
      fd_stake_delegations_snapshot_remove( stake_delegations, ROOT, 20UL, &k, 0 );
    }
    FD_TEST( test_stake_delegations_base_cnt( stake_delegations )==max_stake_accounts+25UL );
    FD_TEST( test_stake_delegations_disk_cnt( stake_delegations )==25UL );
    fd_stake_delegations_refresh( stake_delegations, snap_epoch, stake_history, &snap_warmup_epoch, 1, 0 );
    FD_TEST( test_stake_delegations_base_cnt( stake_delegations )==max_stake_accounts-3UL );
    FD_TEST( !test_stake_delegations_disk_cnt( stake_delegations ) );
    for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
         !fd_stake_delegations_iter_done( iter );
         fd_stake_delegations_iter_next( iter ) ) {
      FD_TEST( fd_stake_delegations_iter_ele( iter )->lamports );
    }
    FD_TEST( stake_delegations->effective_stake==4UL+5UL+6UL+7UL+8UL+9UL+10UL );

    /* Disk root tier behaves the same. */
    fd_stake_delegations_reset( stake_delegations );
    for( ulong i=0UL; i<max_stake_accounts; i++ ) {
      fd_pubkey_t k = { .ul = { 91000UL+i, 1UL } };
      SNAP_UPD( ROOT, 10UL, &k, &voter_pubkey_0, i+1UL );
    }
    fd_pubkey_t disk_a = { .ul = { 92001UL, 1UL } };
    fd_pubkey_t disk_b = { .ul = { 92002UL, 1UL } };
    SNAP_UPD( ROOT, 100UL, &disk_a, &voter_pubkey_0, 1UL );
    SNAP_UPD( ROOT, 200UL, &disk_a, &voter_pubkey_1, 2UL );
    fd_stake_delegations_snapshot_remove( stake_delegations, ROOT, 200UL, &disk_b, 0 );
    SNAP_UPD( ROOT, 100UL, &disk_b, &voter_pubkey_0, 1UL );
    FD_TEST( test_stake_delegations_disk_cnt( stake_delegations )==2UL );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &disk_a, d ) && d->stake==2UL );
    fd_stake_delegations_refresh( stake_delegations, snap_epoch, stake_history, &snap_warmup_epoch, 1, 0 );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &disk_a, d ) && d->stake==2UL );
    FD_TEST( !test_stake_delegations_contains( stake_delegations, &disk_b ) );
    FD_TEST( test_stake_delegations_base_cnt( stake_delegations )==max_stake_accounts+1UL );
    FD_TEST( test_stake_delegations_disk_cnt( stake_delegations )==1UL );

    /* Incremental fork: newest slot wins per account, publish applies
       the fork to the root, and eviction discards it. */
    fd_stake_delegations_reset( stake_delegations );
    SNAP_UPD( ROOT, 10UL,  &stake_account_0, &voter_pubkey_0, 1UL );
    SNAP_UPD( ROOT, 10UL,  &stake_account_1, &voter_pubkey_0, 1UL );
    SNAP_UPD( ROOT, 500UL, &stake_account_2, &voter_pubkey_0, 1UL );
    ushort snap_fork = fd_stake_delegations_new_fork( stake_delegations );
    SNAP_UPD( snap_fork, 100UL, &stake_account_0, &voter_pubkey_1, 2UL );
    SNAP_UPD( snap_fork, 200UL, &stake_account_0, &voter_pubkey_1, 3UL );
    SNAP_UPD( snap_fork, 150UL, &stake_account_0, &voter_pubkey_1, 9UL );
    fd_stake_delegations_snapshot_remove( stake_delegations, snap_fork, 300UL, &stake_account_1, 1 ); /* closed, was in root */
    fd_stake_delegations_snapshot_remove( stake_delegations, snap_fork, 100UL, &stake_account_3, 0 );
    SNAP_UPD( snap_fork, 200UL, &stake_account_3, &voter_pubkey_0, 4UL );                            /* re-created after close */
    SNAP_UPD( snap_fork, 400UL, &stake_account_2, &voter_pubkey_1, 8UL );                            /* older than root */
    for( ulong i=0UL; i<max_delta_accounts+2UL; i++ ) {
      fd_pubkey_t k = { .ul = { 93000UL+i, 1UL } };
      SNAP_UPD( snap_fork, 100UL, &k, &voter_pubkey_0, 10UL+i );
    }
    FD_TEST( test_stake_delegations_disk_cnt( stake_delegations )>0UL ); /* spilled */
    /* Duplicates that spill are resolved by slot on disk. */
    fd_pubkey_t spilled_dup = { .ul = { 94000UL, 1UL } };
    SNAP_UPD( snap_fork, 100UL, &spilled_dup, &voter_pubkey_0, 1UL );
    SNAP_UPD( snap_fork, 200UL, &spilled_dup, &voter_pubkey_1, 2UL );
    SNAP_UPD( snap_fork, 150UL, &spilled_dup, &voter_pubkey_0, 9UL );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, d ) && d->stake==1UL ); /* root untouched */

    fd_stake_delegations_snapshot_publish_fork( stake_delegations, snap_fork );
    FD_TEST( !stake_delegations->disk_delta_cnt_ );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_0, d ) && d->stake==3UL && d->slot==200U );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_1, d ) && !d->lamports );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_2, d ) && d->stake==1UL && d->slot==500U );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &stake_account_3, d ) && d->stake==4UL );
    for( ulong i=0UL; i<max_delta_accounts+2UL; i++ ) {
      fd_pubkey_t k = { .ul = { 93000UL+i, 1UL } };
      FD_TEST( test_stake_delegations_find_copy( stake_delegations, &k, d ) && d->stake==10UL+i );
    }
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &spilled_dup, d ) && d->stake==2UL && d->slot==200U );
    FD_TEST( fd_stake_delegations_new_fork( stake_delegations )==snap_fork ); /* fork released */
    fd_stake_delegations_evict_fork( stake_delegations, snap_fork );

    fd_stake_delegations_reset( stake_delegations );
#   undef SNAP_UPD
  }

  /* Test stake delegations refresh */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
