#define _GNU_SOURCE
#include "fd_stake_delegations.h"
#include "fd_stakes.h"
#include "fd_stake_types.h"
#include "../runtime/fd_system_ids.h"
#include "../../disco/store/fd_store.h"
#include "../../util/fd_hash32.h"

#include <stdlib.h>
#include <sys/mman.h>
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

#define TEST_STAKE_DELEGATION_LAMPORTS (123456789UL)
#define TEST_STAKE_DELEGATION_ACC_DLEN ((uint)sizeof(fd_stake_state_t))

#define TEST_ACCDB_CACHE_FOOTPRINT    (32UL<<20)
#define TEST_ACCDB_CACHE_MIN_RESERVED (2UL)

struct test_accdb {
  fd_accdb_t * accdb;
  void *       shmem_mem;
  int          fd;
};
typedef struct test_accdb test_accdb_t;

static test_accdb_t
test_accdb_new( void ) {
  test_accdb_t test = { .fd = memfd_create( "stake_delegations_accdb", 0 ) };
  FD_TEST( test.fd>=0 );

  ulong shmem_footprint = fd_accdb_shmem_footprint( 64UL, 3UL, 64UL, 64UL, TEST_ACCDB_CACHE_FOOTPRINT, TEST_ACCDB_CACHE_MIN_RESERVED, 1UL, 0UL );
  FD_TEST( shmem_footprint );
  test.shmem_mem = aligned_alloc( fd_accdb_shmem_align(), shmem_footprint );
  FD_TEST( test.shmem_mem );
  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join(
      fd_accdb_shmem_new( test.shmem_mem, 64UL, 3UL, 64UL, 64UL, 1UL<<30, TEST_ACCDB_CACHE_FOOTPRINT, TEST_ACCDB_CACHE_MIN_RESERVED, 0, 42UL, 1UL, 0UL ) );
  FD_TEST( shmem );

  void * accdb_mem = aligned_alloc( fd_accdb_align(), fd_accdb_footprint( 3UL ) );
  FD_TEST( accdb_mem );
  test.accdb = fd_accdb_join( fd_accdb_new( accdb_mem, shmem, test.fd, 0UL, NULL ) );
  FD_TEST( test.accdb );
  return test;
}

static void
test_accdb_delete( test_accdb_t * test ) {
  free( test->shmem_mem );
  free( test->accdb );
  FD_TEST( !close( test->fd ) );
}

static void
test_accdb_write_stake( fd_accdb_t *             accdb,
                        fd_accdb_fork_id_t       fork_id,
                        fd_pubkey_t const *      pubkey,
                        fd_stake_state_t const * stake ) {
  uchar const * keys[ 1 ] = { pubkey->uc };
  int           writable[ 1 ] = { 1 };
  fd_acc_t      acc[ 1 ] = {0};
  fd_accdb_acquire( accdb, fork_id, 1UL, keys, writable, acc );
  acc[ 0 ].lamports = TEST_STAKE_DELEGATION_LAMPORTS;
  acc[ 0 ].data_len = sizeof(fd_stake_state_t);
  memcpy( acc[ 0 ].owner, &fd_solana_stake_program_id, sizeof(fd_pubkey_t) );
  memcpy( acc[ 0 ].data, stake, sizeof(fd_stake_state_t) );
  acc[ 0 ].commit = 1;
  fd_accdb_release( accdb, 1UL, acc );
}

/* Iterator accdb inputs are retained only for caller compatibility. */
#define NO_RESOLVE NULL, ((fd_accdb_fork_id_t){ .val = USHORT_MAX }), 0UL, NULL

static fd_stake_delegation_t const *
test_stake_delegations_find( fd_stake_delegations_t const * stake_delegations,
                             fd_pubkey_t const *            stake_account ) {
  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations, NO_RESOLVE );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * d = fd_stake_delegations_iter_ele( iter );
    if( FD_UNLIKELY( d->is_tombstone ) ) continue;
    if( FD_LIKELY( !memcmp( &d->stake_account, stake_account, sizeof(fd_pubkey_t) ) ) ) return d;
  }
  return NULL;
}

static int
test_stake_delegations_find_copy( fd_stake_delegations_t const * stake_delegations,
                                  fd_pubkey_t const *            stake_account,
                                  fd_stake_delegation_t *        out ) {
  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations, NO_RESOLVE );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * d = fd_stake_delegations_iter_ele( iter );
    if( FD_UNLIKELY( d->is_tombstone ) ) continue;
    if( FD_LIKELY( !memcmp( &d->stake_account, stake_account, sizeof(fd_pubkey_t) ) ) ) {
      *out = *d;
      return 1;
    }
  }
  return 0;
}

static ulong
count_visible_delegations( fd_stake_delegations_t const * stake_delegations ) {
  ulong cnt = 0UL;
  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations, NO_RESOLVE );
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
                  ushort                         deactivation_epoch,
                  uchar                          warmup_cooldown_rate ) {
  FD_TEST( d );
  FD_TEST( !memcmp( &d->stake_account, stake_account, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &d->vote_account, vote_account, sizeof(fd_pubkey_t) ) );
  FD_TEST( d->stake == stake );
  FD_TEST( d->lamports == TEST_STAKE_DELEGATION_LAMPORTS );
  FD_TEST( d->acc_dlen == TEST_STAKE_DELEGATION_ACC_DLEN );
  FD_TEST( d->activation_epoch == activation_epoch );
  FD_TEST( d->deactivation_epoch == deactivation_epoch );
  FD_TEST( d->warmup_cooldown_rate == warmup_cooldown_rate );
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
test_stake_delegations_mark_fork_delta( fd_stake_delegations_t *   stake_delegations,
                                        ulong                      epoch,
                                        fd_stake_history_t const * stake_history,
                                        ulong *                    warmup_cooldown_rate_epoch,
                                        int                        use_fixed_point_stake_math,
                                        ushort                     fork_id ) {
  fd_stake_delegations_frontier_query_begin( stake_delegations,
                                             epoch,
                                             stake_history,
                                             warmup_cooldown_rate_epoch,
                                             use_fixed_point_stake_math,
                                             &fork_id,
                                             1UL );
}

static void
test_stake_delegations_unmark_fork_delta( fd_stake_delegations_t *   stake_delegations,
                                          ulong                      epoch FD_PARAM_UNUSED,
                                          fd_stake_history_t const * stake_history,
                                          ulong *                    warmup_cooldown_rate_epoch,
                                          int                        use_fixed_point_stake_math,
                                          ushort                     fork_id ) {
  fd_stake_delegations_frontier_query_end( stake_delegations,
                                           stake_history,
                                           warmup_cooldown_rate_epoch,
                                           use_fixed_point_stake_math,
                                           &fork_id,
                                           1UL );
}

int main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  test_inactive_predicates();

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

  /* Leaves disk headroom for root, delta, and frontier spill records. */
  ulong const max_fallback_stake_accounts = 512UL;

  ulong const max_live_slots = 32UL;

  ulong const expected_stake_accounts = max_stake_accounts;

  void * stake_delegations_mem = fd_wksp_alloc_laddr( wksp, fd_stake_delegations_align(), fd_stake_delegations_footprint( max_stake_accounts, max_fallback_stake_accounts, expected_stake_accounts, max_live_slots ), wksp_tag );
  FD_TEST( stake_delegations_mem );

  FD_TEST( fd_stake_delegations_align()>=alignof(fd_stake_delegations_t)  );
  FD_TEST( fd_stake_delegations_align()==FD_STAKE_DELEGATIONS_ALIGN );

  FD_TEST( !fd_stake_delegations_new( NULL, 0UL, max_stake_accounts, max_fallback_stake_accounts, expected_stake_accounts, max_live_slots ) );
  FD_TEST( !fd_stake_delegations_new( stake_delegations_mem, 0UL, 0UL, max_fallback_stake_accounts, expected_stake_accounts, max_live_slots ) );
  void * new_stake_delegations_mem = fd_stake_delegations_new( stake_delegations_mem, 0UL, max_stake_accounts, max_fallback_stake_accounts, expected_stake_accounts, max_live_slots );
  FD_TEST( new_stake_delegations_mem );

  FD_TEST( !fd_stake_delegations_join( NULL ) );
  void * junk_mem = fd_wksp_alloc_laddr( wksp, fd_stake_delegations_align(), sizeof(fd_stake_delegations_t), 999UL );
  FD_TEST( junk_mem );
  memset( junk_mem, 0, sizeof(fd_stake_delegations_t) );
  FD_TEST( !fd_stake_delegations_join( junk_mem ) );

  fd_stake_delegations_t * stake_delegations = fd_stake_delegations_join( new_stake_delegations_mem );
  FD_TEST( stake_delegations );

  fd_pubkey_t stake_account_0 = { .ul = { 999UL, 999UL} };
  fd_pubkey_t stake_account_1 = { .ul = { 1, 2 } };
  fd_pubkey_t stake_account_2 = { .ul = { 3, 4 } };
  fd_pubkey_t stake_account_3 = { .ul = { 5, 6 } };

  fd_pubkey_t voter_pubkey_0 = { .ul = { 5, 6 } };
  fd_pubkey_t voter_pubkey_1 = { .ul = { 7, 8 } };

  FD_TEST( fd_stake_delegations_base_cnt( stake_delegations ) == 0UL );
  fd_stake_delegations_root_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 100UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
  FD_TEST( fd_stake_delegations_base_cnt( stake_delegations ) == 1UL );
  fd_stake_delegations_root_update( stake_delegations, &stake_account_1, &voter_pubkey_1, 200UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
  FD_TEST( fd_stake_delegations_base_cnt( stake_delegations ) == 2UL );
  fd_stake_delegations_root_update( stake_delegations, &stake_account_2, &voter_pubkey_1, 300UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
  FD_TEST( fd_stake_delegations_base_cnt( stake_delegations ) == 3UL );

  fd_stake_delegation_t const * stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
  FD_TEST( stake_delegation_0 );
  FD_TEST( !memcmp( &stake_delegation_0->stake_account, &stake_account_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_0->vote_account, &voter_pubkey_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_0->stake == 100UL );
  FD_TEST( stake_delegation_0->lamports == TEST_STAKE_DELEGATION_LAMPORTS );
  FD_TEST( stake_delegation_0->acc_dlen == TEST_STAKE_DELEGATION_ACC_DLEN );
  FD_TEST( stake_delegation_0->activation_epoch == 0UL );
  FD_TEST( stake_delegation_0->deactivation_epoch == 0UL );
  FD_TEST( stake_delegation_0->warmup_cooldown_rate == FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );

  fd_stake_delegation_t const * stake_delegation_1 = test_stake_delegations_find( stake_delegations, &stake_account_1 );
  FD_TEST( stake_delegation_1 );
  FD_TEST( !memcmp( &stake_delegation_1->stake_account, &stake_account_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_1->vote_account, &voter_pubkey_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_1->stake == 200UL );
  FD_TEST( stake_delegation_1->lamports == TEST_STAKE_DELEGATION_LAMPORTS );
  FD_TEST( stake_delegation_1->acc_dlen == TEST_STAKE_DELEGATION_ACC_DLEN );
  FD_TEST( stake_delegation_1->activation_epoch == 0UL );
  FD_TEST( stake_delegation_1->deactivation_epoch == 0UL );
  FD_TEST( stake_delegation_1->warmup_cooldown_rate == FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );

  fd_stake_delegation_t const * stake_delegation_2 = test_stake_delegations_find( stake_delegations, &stake_account_2 );
  FD_TEST( stake_delegation_2 );
  FD_TEST( !memcmp( &stake_delegation_2->stake_account, &stake_account_2, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_2->vote_account, &voter_pubkey_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_2->stake == 300UL );
  FD_TEST( stake_delegation_2->lamports == TEST_STAKE_DELEGATION_LAMPORTS );
  FD_TEST( stake_delegation_2->acc_dlen == TEST_STAKE_DELEGATION_ACC_DLEN );
  FD_TEST( stake_delegation_2->activation_epoch == 0UL );
  FD_TEST( stake_delegation_2->deactivation_epoch == 0UL );
  FD_TEST( stake_delegation_2->warmup_cooldown_rate == FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );

  FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_3 ) );

  fd_stake_delegations_root_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
  FD_TEST( stake_delegation_0 );
  FD_TEST( !memcmp( &stake_delegation_0->stake_account, &stake_account_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_0->vote_account, &voter_pubkey_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_0->stake == 200UL );
  FD_TEST( stake_delegation_0->lamports == TEST_STAKE_DELEGATION_LAMPORTS );
  FD_TEST( stake_delegation_0->acc_dlen == TEST_STAKE_DELEGATION_ACC_DLEN );
  FD_TEST( stake_delegation_0->activation_epoch == 0UL );
  FD_TEST( stake_delegation_0->deactivation_epoch == 0UL );
  FD_TEST( stake_delegation_0->warmup_cooldown_rate == FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
  FD_TEST( fd_stake_delegations_base_cnt( stake_delegations ) == 3UL );

  ushort remove_fork = fd_stake_delegations_new_fork( stake_delegations );
  fd_stake_delegations_fork_remove( stake_delegations, remove_fork, &stake_account_1 );

  ulong epoch = 10;
  fd_stake_history_t stake_history[1] = {0};
  ulong warmup_cooldown_rate_epoch = 0UL;
  int   use_fixed_point_stake_math = 0;
  fd_stake_delegations_apply_fork_delta( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, remove_fork );
  fd_stake_delegations_evict_fork( stake_delegations, remove_fork );
  FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_1 ) );
  FD_TEST( fd_stake_delegations_base_cnt( stake_delegations ) == 2UL );

  fd_stake_delegations_root_update( stake_delegations, &stake_account_1, &voter_pubkey_1, 10000UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
  stake_delegation_1 = test_stake_delegations_find( stake_delegations, &stake_account_1 );
  FD_TEST( stake_delegation_1 );
  FD_TEST( !memcmp( &stake_delegation_1->stake_account, &stake_account_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_1->vote_account, &voter_pubkey_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_1->stake == 10000UL );
  FD_TEST( stake_delegation_1->lamports == TEST_STAKE_DELEGATION_LAMPORTS );
  FD_TEST( stake_delegation_1->acc_dlen == TEST_STAKE_DELEGATION_ACC_DLEN );
  FD_TEST( stake_delegation_1->activation_epoch == 0UL );
  FD_TEST( stake_delegation_1->deactivation_epoch == 0UL );
  FD_TEST( stake_delegation_1->warmup_cooldown_rate == FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
  FD_TEST( fd_stake_delegations_base_cnt( stake_delegations ) == 3UL );

  /* Test stake delegation delta mark/unmark */

  /* Case 1: Empty fork */
  {
    ushort empty_fork = fd_stake_delegations_new_fork( stake_delegations );
    ulong  cnt_before = count_visible_delegations( stake_delegations );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, empty_fork );
    FD_TEST( count_visible_delegations( stake_delegations ) == cnt_before );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, empty_fork );
    FD_TEST( count_visible_delegations( stake_delegations ) == cnt_before );
    fd_stake_delegations_evict_fork( stake_delegations, empty_fork );
  }

  /* Case 2: Delta for existing root (update) */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 500UL, 1UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_1, 500UL, 1UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 3: Delta for non-existing root (insert) */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_3 ) );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 777UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    fd_stake_delegation_t const * d3 = test_stake_delegations_find( stake_delegations, &stake_account_3 );
    assert_delegation( d3, &stake_account_3, &voter_pubkey_0, 777UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( fd_stake_delegations_base_cnt( stake_delegations ) == 4UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_3 ) );
    FD_TEST( fd_stake_delegations_base_cnt( stake_delegations ) == 3UL );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 4: Tombstone for existing root */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_0 ) );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 6: Multiple updates - last wins */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 100UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    FD_TEST( stake_delegation_0->stake == 200UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 7: Update then tombstone */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 999UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_0 ) );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 8: Tombstone then update */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 111UL, 2UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_1, 111UL, 2UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 9: Sequential fork mark/unmark */
  {
    ushort fork0 = fd_stake_delegations_new_fork( stake_delegations );
    ushort fork1 = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork0, &stake_account_0, &voter_pubkey_0, 10UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_fork_update( stake_delegations, fork1, &stake_account_0, &voter_pubkey_0, 20UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork0 );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    FD_TEST( stake_delegation_0->stake == 10UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork0 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork1 );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    FD_TEST( stake_delegation_0->stake == 20UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork1 );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    FD_TEST( stake_delegation_0->stake == 200UL );
    fd_stake_delegations_evict_fork( stake_delegations, fork0 );
    fd_stake_delegations_evict_fork( stake_delegations, fork1 );
  }

  /* Case 10a: Remove then re-add across forks */
  {
    ushort fork1 = fd_stake_delegations_new_fork( stake_delegations );
    ushort fork2 = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_remove( stake_delegations, fork1, &stake_account_0 );
    fd_stake_delegations_fork_update( stake_delegations, fork2, &stake_account_0, &voter_pubkey_1, 333UL, 5UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    ushort fork_ids[] = { fork1, fork2 };
    fd_stake_delegations_frontier_query_begin( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_ids, 2UL );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_1, 333UL, 5UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_frontier_query_end( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_ids, 2UL );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_evict_fork( stake_delegations, fork1 );
    fd_stake_delegations_evict_fork( stake_delegations, fork2 );
  }

  /* Case 12: fd_stake_delegations_base_cnt */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    ulong  cnt_before = fd_stake_delegations_base_cnt( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 1UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( fd_stake_delegations_base_cnt( stake_delegations ) == cnt_before + 1UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( fd_stake_delegations_base_cnt( stake_delegations ) == cnt_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 15: Mixed fork */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 111UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_1 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 222UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_1, 111UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_1 ) );
    fd_stake_delegation_t const * d3 = test_stake_delegations_find( stake_delegations, &stake_account_3 );
    assert_delegation( d3, &stake_account_3, &voter_pubkey_0, 222UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( count_visible_delegations( stake_delegations ) == 3UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( count_visible_delegations( stake_delegations ) == 3UL );
    FD_TEST( test_stake_delegations_find( stake_delegations, &stake_account_1 ) );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_3 ) );
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

  fd_stake_delegations_root_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 200UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
  fd_stake_delegations_root_update( stake_delegations, &stake_account_1, &voter_pubkey_1, 300UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
  fd_stake_delegations_root_update( stake_delegations, &stake_account_2, &voter_pubkey_1, 500UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );

  stake_delegations->effective_stake = 200UL + 300UL + 500UL;

  /* Case 16: Duplicate updates -- totals must reflect only the last delta */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 100UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 400UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before - 200UL + 400UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 17: Update then tombstone -- totals must subtract base, not double-count */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 999UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before - 200UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 18: Tombstone then update -- totals must reflect only the update */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 777UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before - 200UL + 777UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 19: Triple update -- totals must reflect only the last */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 10UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 20UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 30UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before - 200UL + 30UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 20: Duplicate updates for a new account (dne_in_root) */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 50UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 80UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before + 80UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_3 ) );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* The query end must reuse the begin epoch when unwinding totals. */
  {
    fd_pubkey_t activating_account   = { .ul = { 0xaaaaUL, 0xbbbbUL } };
    fd_pubkey_t deactivating_account = { .ul = { 0xccccUL, 0xddddUL } };
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &activating_account,   &voter_pubkey_0, 70UL, epoch,     ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &deactivating_account, &voter_pubkey_0, 90UL, ULONG_MAX, epoch,     0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );

    ushort fork_ids[] = { fork_idx };
    fd_stake_delegations_frontier_query_begin( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_ids, 1UL );
    FD_TEST( stake_delegations->effective_stake==1090UL );
    FD_TEST( stake_delegations->activating_stake==70UL );
    FD_TEST( stake_delegations->deactivating_stake==90UL );

    fd_stake_delegations_frontier_query_end( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_ids, 1UL );
    FD_TEST( stake_delegations->effective_stake==1000UL );
    FD_TEST( stake_delegations->activating_stake==0UL );
    FD_TEST( stake_delegations->deactivating_stake==0UL );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &activating_account ) );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &deactivating_account ) );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 21: New account insert then tombstone -- totals unchanged */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 123UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_3 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 22: Same-fork updates must consume only one delta pool element. */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    for( ulong i=0UL; i<=max_stake_accounts; i++ ) {
      fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 600UL+i, ULONG_MAX, ULONG_MAX, i, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    }
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    fd_stake_delegation_t const * d = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( d, &stake_account_0, &voter_pubkey_1, 600UL+max_stake_accounts, USHORT_MAX, USHORT_MAX, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    FD_TEST( d->credits_observed==max_stake_accounts );
    FD_TEST( stake_delegations->effective_stake==eff_before-200UL+600UL+max_stake_accounts );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake==eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 23: The same stake account has independent deltas across forks. */
  {
    ushort fork_a = fd_stake_delegations_new_fork( stake_delegations );
    ushort fork_b = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_a, &stake_account_0, &voter_pubkey_0, 901UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_fork_update( stake_delegations, fork_b, &stake_account_0, &voter_pubkey_1, 902UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );

    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_a );
    assert_delegation( test_stake_delegations_find( stake_delegations, &stake_account_0 ), &stake_account_0, &voter_pubkey_0, 901UL, USHORT_MAX, USHORT_MAX, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_a );

    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_b );
    assert_delegation( test_stake_delegations_find( stake_delegations, &stake_account_0 ), &stake_account_0, &voter_pubkey_1, 902UL, USHORT_MAX, USHORT_MAX, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_b );

    fd_stake_delegations_evict_fork( stake_delegations, fork_a );
    fd_stake_delegations_evict_fork( stake_delegations, fork_b );
  }

  /* Case 24: Same-fork removals must consume only one delta pool element. */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    for( ulong i=0UL; i<=max_stake_accounts; i++ ) {
      fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    }
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_0 ) );
    FD_TEST( stake_delegations->effective_stake==eff_before-200UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake==eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 25: Reused fork indices start with an empty delta map. */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 903UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );

    ushort reused_fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    FD_TEST( reused_fork_idx==fork_idx );
    fd_stake_delegations_fork_update( stake_delegations, reused_fork_idx, &stake_account_0, &voter_pubkey_1, 904UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, reused_fork_idx );
    assert_delegation( test_stake_delegations_find( stake_delegations, &stake_account_0 ), &stake_account_0, &voter_pubkey_1, 904UL, USHORT_MAX, USHORT_MAX, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, reused_fork_idx );
    fd_stake_delegations_evict_fork( stake_delegations, reused_fork_idx );
  }

  /* Case 26: Applying a deduplicated delta commits only the latest state. */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 905UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 906UL, ULONG_MAX, ULONG_MAX, 1UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_apply_fork_delta( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, fork_idx );
    fd_stake_delegation_t const * d = fd_stake_delegation_root_query( stake_delegations, &stake_account_0 );
    assert_delegation( d, &stake_account_0, &voter_pubkey_1, 906UL, USHORT_MAX, USHORT_MAX, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    FD_TEST( d->credits_observed==1UL );
    FD_TEST( stake_delegations->effective_stake==eff_before-200UL+906UL );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );

    fd_stake_delegations_root_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 200UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    stake_delegations->effective_stake = eff_before;
  }

  /* Case 27: Reset clears populated fork maps before fork indices are reused. */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 907UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_reset( stake_delegations );
    FD_TEST( fd_stake_delegations_base_cnt( stake_delegations )==0UL );

    ushort reset_fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, reset_fork_idx, &stake_account_0, &voter_pubkey_1, 908UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, reset_fork_idx );
    assert_delegation( test_stake_delegations_find( stake_delegations, &stake_account_0 ), &stake_account_0, &voter_pubkey_1, 908UL, USHORT_MAX, USHORT_MAX, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, reset_fork_idx );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_0 ) );
    fd_stake_delegations_evict_fork( stake_delegations, reset_fork_idx );
  }

  /* Case 28: Delta entries are drawn from the delta pool, which has its
     own capacity separate from the root pool. */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    for( ulong i=0UL; i<max_stake_accounts; i++ ) {
      fd_pubkey_t stake_account = { .ul = { 1000UL+i, 2000UL+i } };
      fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    }
    FD_TEST( !fd_stake_delegations_disk_spill( stake_delegations ) );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 29: Entries that fit in the two RAM pools do not consume the
     full-record disk budget. */
  {
    fd_stake_delegations_reset( stake_delegations );
    FD_TEST( !fd_stake_delegations_disk_cnt( stake_delegations ) );
    FD_TEST( !fd_stake_delegations_disk_spill( stake_delegations ) );

    fd_stake_delegations_root_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 100UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    FD_TEST( !fd_stake_delegations_disk_cnt( stake_delegations ) );

    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 101UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_1, &voter_pubkey_1, 102UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    FD_TEST( !fd_stake_delegations_disk_cnt( stake_delegations ) );

    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    FD_TEST( !fd_stake_delegations_disk_cnt( stake_delegations ) );

    ushort remove_fork = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_remove( stake_delegations, remove_fork, &stake_account_0 );
    fd_stake_delegations_apply_fork_delta( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, remove_fork );
    fd_stake_delegations_evict_fork( stake_delegations, remove_fork );
    FD_TEST( !fd_stake_delegations_disk_cnt( stake_delegations ) );
    FD_TEST( !fd_stake_delegations_base_cnt( stake_delegations ) );
    FD_TEST( !fd_stake_delegations_disk_spill( stake_delegations ) );
  }

  /* Case 30: Exhausting the root pool spills an exact full root record,
     and removing that record clears the non-sticky spill predicate. */
  {
    fd_stake_delegations_reset( stake_delegations );

    for( ulong i=0UL; i<max_stake_accounts; i++ ) {
      fd_pubkey_t k = { .ul = { 5000UL+i, 6000UL+i } };
      fd_stake_delegations_root_update( stake_delegations, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    }
    FD_TEST( fd_stake_delegations_base_cnt( stake_delegations )==max_stake_accounts );
    FD_TEST( !fd_stake_delegations_disk_cnt( stake_delegations ) );
    FD_TEST( !fd_stake_delegations_disk_spill( stake_delegations ) );

    fd_pubkey_t overflow = { .ul = { 7777UL, 8888UL } };
    fd_stake_delegations_root_update( stake_delegations, &overflow, &voter_pubkey_1, 123UL, 1UL, 2UL, 3UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( fd_stake_delegations_disk_spill( stake_delegations ) );
    FD_TEST( fd_stake_delegations_base_cnt( stake_delegations )==max_stake_accounts+1UL );
    FD_TEST( fd_stake_delegations_disk_cnt( stake_delegations )==1UL );
    fd_stake_delegation_t found[1];
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &overflow, found ) );
    assert_delegation( found, &overflow, &voter_pubkey_1, 123UL, 1U, 2U, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( found->credits_observed==3UL );

    fd_pubkey_t first       = { .ul = { 5000UL, 6000UL } };
    ushort      remove_fork = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_remove( stake_delegations, remove_fork, &first );
    fd_stake_delegations_apply_fork_delta( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, remove_fork );
    fd_stake_delegations_evict_fork( stake_delegations, remove_fork );
    FD_TEST( fd_stake_delegations_base_cnt( stake_delegations )==max_stake_accounts );
    FD_TEST( fd_stake_delegations_disk_cnt( stake_delegations )==1UL );

    remove_fork = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_remove( stake_delegations, remove_fork, &overflow );
    fd_stake_delegations_apply_fork_delta( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, remove_fork );
    fd_stake_delegations_evict_fork( stake_delegations, remove_fork );
    FD_TEST( fd_stake_delegations_base_cnt( stake_delegations )==max_stake_accounts-1UL );
    FD_TEST( !fd_stake_delegations_disk_cnt( stake_delegations ) );
    FD_TEST( !fd_stake_delegations_disk_spill( stake_delegations ) );

    fd_stake_delegations_reset( stake_delegations );
    FD_TEST( !fd_stake_delegations_disk_spill( stake_delegations ) );
    FD_TEST( !fd_stake_delegations_disk_cnt( stake_delegations ) );
  }

  /* Case 31: Exhausting the shared delta pool spills full, same-fork
     overwriteable delta records and eviction reclaims them. */
  {
    fd_stake_delegations_reset( stake_delegations );

    ushort      fork_idx  = fd_stake_delegations_new_fork( stake_delegations );
    ulong const delta_max = max_stake_accounts;
    for( ulong i=0UL; i<delta_max; i++ ) {
      fd_pubkey_t k = { .ul = { 20000UL+i, 30000UL+i } };
      fd_stake_delegations_fork_update( stake_delegations, fork_idx, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    }
    FD_TEST( !fd_stake_delegations_disk_spill( stake_delegations ) );
    FD_TEST( !fd_stake_delegations_disk_cnt( stake_delegations ) );

    fd_pubkey_t overflow = { .ul = { 40000UL, 50000UL } };
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &overflow, &voter_pubkey_0, 1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &overflow, &voter_pubkey_1, 456UL, 3UL, 8UL, 9UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( fd_stake_delegations_disk_spill( stake_delegations ) );
    FD_TEST( fd_stake_delegations_disk_cnt( stake_delegations )==1UL );
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    fd_stake_delegation_t found[1];
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &overflow, found ) );
    assert_delegation( found, &overflow, &voter_pubkey_1, 456UL, 3U, 8U, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( found->credits_observed==9UL );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );

    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    FD_TEST( !fd_stake_delegations_disk_cnt( stake_delegations ) );
    FD_TEST( !fd_stake_delegations_disk_spill( stake_delegations ) );
    fd_stake_delegations_reset( stake_delegations );
  }

  /* Case 32: max_fallback_stake_accounts bounds each full-record disk
     tier, and every disk index fits below the delta tag bit. */
  {
    FD_TEST( stake_delegations->max_disk_records_==max_fallback_stake_accounts );
    FD_TEST( stake_delegations->max_disk_records_<(ulong)FD_STAKE_DELEGATIONS_DELTA_DISK_TAG );
  }

  /* Case 33: fp_warmed_awarded lifecycle + invalidate_warmed. */
  {
    FD_TEST( stake_delegations->fp_warmed_awarded==0 );

    /* Awarding a WARMED tag under the float math sets the flag. */
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 200UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_apply_fork_delta( epoch, stake_history, &warmup_cooldown_rate_epoch, 0 /* float */, stake_delegations, fork_idx );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    FD_TEST( stake_delegation_0->state==FD_STAKE_DELEGATION_STATE_WARMED );
    FD_TEST( stake_delegations->fp_warmed_awarded==1 );

    /* The wipe demotes WARMED to UNKNOWN and clears the flag. */
    fd_stake_delegations_invalidate_warmed( stake_delegations );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    FD_TEST( stake_delegation_0->state==FD_STAKE_DELEGATION_STATE_UNKNOWN );
    FD_TEST( stake_delegations->fp_warmed_awarded==0 );

    /* Awarding a WARMED tag under the fixed point math leaves the flag
       clear. */
    fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 200UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_apply_fork_delta( epoch, stake_history, &warmup_cooldown_rate_epoch, 1 /* fixed */, stake_delegations, fork_idx );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    FD_TEST( stake_delegation_0->state==FD_STAKE_DELEGATION_STATE_WARMED );
    FD_TEST( stake_delegations->fp_warmed_awarded==0 );

    /* A COOLING award never touches the flag ... */
    fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 200UL, ULONG_MAX, 10UL /* deactivating at epoch */, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_apply_fork_delta( epoch, stake_history, &warmup_cooldown_rate_epoch, 0 /* float */, stake_delegations, fork_idx );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    FD_TEST( stake_delegation_0->state==FD_STAKE_DELEGATION_STATE_COOLING );
    FD_TEST( stake_delegations->fp_warmed_awarded==0 );

    /* ... and a later float WARMED re-award sets it again. */
    fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 200UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_apply_fork_delta( epoch, stake_history, &warmup_cooldown_rate_epoch, 0 /* float */, stake_delegations, fork_idx );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    FD_TEST( stake_delegations->fp_warmed_awarded==1 );
    fd_stake_delegations_invalidate_warmed( stake_delegations );
    FD_TEST( stake_delegations->fp_warmed_awarded==0 );
  }

  /* Case 34: Root pruning removes only delegations that are inactive
     in both the current and previous epochs. */
  {
    fd_stake_delegations_reset( stake_delegations );
    ulong const prune_epoch = 4UL;

    fd_stake_delegations_root_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_root_update( stake_delegations, &stake_account_1, &voter_pubkey_0, 1UL, ULONG_MAX, 3UL,       0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_root_update( stake_delegations, &stake_account_2, &voter_pubkey_0, 1UL, ULONG_MAX, 2UL,       0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_root_update( stake_delegations, &stake_account_3, &voter_pubkey_0, 1UL, 4UL,       4UL,       0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );

    fd_stake_delegations_prune_inactive_root(
        stake_delegations,
        prune_epoch,
        stake_history,
        &warmup_cooldown_rate_epoch,
        use_fixed_point_stake_math );
    FD_TEST(  fd_stake_delegation_root_query( stake_delegations, &stake_account_0 ) );
    FD_TEST(  fd_stake_delegation_root_query( stake_delegations, &stake_account_1 ) );
    FD_TEST( !fd_stake_delegation_root_query( stake_delegations, &stake_account_2 ) );
    FD_TEST( !fd_stake_delegation_root_query( stake_delegations, &stake_account_3 ) );
    FD_TEST( fd_stake_delegations_base_cnt( stake_delegations )==2UL );
    FD_TEST( !fd_stake_delegations_disk_cnt( stake_delegations ) );

    /* Applying the winning fork before pruning preserves a delegation
       that was reactivated after it became inert. */
    fd_stake_delegations_reset( stake_delegations );
    fd_stake_delegations_root_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 1UL, ULONG_MAX, 2UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_apply_fork_delta( prune_epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, fork_idx );
    fd_stake_delegations_prune_inactive_root(
        stake_delegations,
        prune_epoch,
        stake_history,
        &warmup_cooldown_rate_epoch,
        use_fixed_point_stake_math );
    fd_stake_delegation_t const * reactivated =
        fd_stake_delegation_root_query( stake_delegations, &stake_account_0 );
    FD_TEST( reactivated );
    FD_TEST( !memcmp( &reactivated->vote_account, &voter_pubkey_1, sizeof(fd_pubkey_t) ) );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 35: Dense disk records are reclaimed by reset/eviction, and
     boot refresh validates and prunes disk roots. */
  {
    fd_stake_delegations_reset( stake_delegations );

    ushort      fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    ulong const ram_max  = max_stake_accounts;
    for( ulong i=0UL; i<ram_max; i++ ) {
      fd_pubkey_t k = { .ul = { 60000UL+i, 70000UL+i } };
      fd_stake_delegations_fork_update( stake_delegations, fork_idx, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    }
    FD_TEST( !fd_stake_delegations_disk_spill( stake_delegations ) );
    FD_TEST( !fd_stake_delegations_disk_cnt( stake_delegations ) );

    fd_pubkey_t overflow = { .ul = { 60000UL+ram_max, 70000UL+ram_max } };
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &overflow, &voter_pubkey_0, ram_max+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    FD_TEST( fd_stake_delegations_disk_cnt( stake_delegations )==1UL );
    FD_TEST( lseek( FD_STAKE_DELEGATIONS_FD, 0L, SEEK_END )>0L );

    /* Reset must make stale disk records reusable. */
    fd_stake_delegations_reset( stake_delegations );
    FD_TEST( !fd_stake_delegations_disk_cnt( stake_delegations ) );
    fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    ulong const disk_cnt = 12UL;
    for( ulong i=0UL; i<ram_max+disk_cnt; i++ ) {
      fd_pubkey_t k = { .ul = { 60000UL+i, 70000UL+i } };
      fd_stake_delegations_fork_update( stake_delegations, fork_idx, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    }
    FD_TEST( fd_stake_delegations_disk_cnt( stake_delegations )==disk_cnt );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    FD_TEST( !fd_stake_delegations_disk_cnt( stake_delegations ) );

    /* Refresh must apply remove_inactive_stakes to disk-tier entries,
       just as it does to RAM-tier entries. */
    fd_stake_delegations_reset( stake_delegations );
    for( ulong i=0UL; i<max_stake_accounts; i++ ) {
      fd_pubkey_t k = { .ul = { 62000UL+i, 72000UL+i } };
      fd_stake_delegations_root_update( stake_delegations, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    }
    fd_stake_delegations_root_update( stake_delegations, &overflow, &voter_pubkey_0, 1UL, 2UL, 2UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    FD_TEST( fd_stake_delegations_disk_cnt( stake_delegations )==1UL );

    test_accdb_t accdb = test_accdb_new();
    fd_accdb_fork_id_t accdb_fork = fd_accdb_attach_child(
        accdb.accdb,
        (fd_accdb_fork_id_t){ .val = USHORT_MAX } );
    fd_stake_state_t inactive = {
      .stake_type = FD_STAKE_STATE_STAKE,
      .stake = {
        .stake = {
          .delegation = {
            .voter_pubkey         = voter_pubkey_0,
            .stake                = 1UL,
            .activation_epoch     = 2UL,
            .deactivation_epoch   = 2UL,
            .warmup_cooldown_rate = FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_025,
          },
        },
      },
    };
    test_accdb_write_stake( accdb.accdb, accdb_fork, &overflow, &inactive );

    ulong refresh_warmup_epoch = ULONG_MAX;
    fd_stake_delegations_iter_t iter_[1];
    int found_overflow = 0;
    for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations, NO_RESOLVE );
         !fd_stake_delegations_iter_done( iter );
         fd_stake_delegations_iter_next( iter ) ) {
      fd_stake_delegation_t const * delegation = fd_stake_delegations_iter_ele( iter );
      if( !fd_pubkey_eq( &delegation->stake_account, &overflow ) ) continue;
      assert_delegation( delegation, &overflow, &voter_pubkey_0, 1UL, 2U, 2U, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
      FD_TEST( fd_stake_delegations_iter_idx( iter )>=max_stake_accounts );
      found_overflow = 1;
    }
    FD_TEST( found_overflow );

    fd_stake_delegations_refresh(
        stake_delegations,
        4UL,
        stake_history,
        &refresh_warmup_epoch,
        1,
        1,
        accdb.accdb,
        accdb_fork );
    FD_TEST( !fd_stake_delegations_base_cnt( stake_delegations ) );
    FD_TEST( !fd_stake_delegations_disk_cnt( stake_delegations ) );
    test_accdb_delete( &accdb );

    fd_stake_delegations_reset( stake_delegations );
  }

  /* Case 36: A root entry that exceeds the RAM pool remains fully
     iterable without consulting accdb. */
  {
    fd_stake_delegations_reset( stake_delegations );

    for( ulong i=0UL; i<max_stake_accounts; i++ ) {
      fd_pubkey_t k = { .ul = { 80000UL+i, 90000UL+i } };
      fd_stake_delegations_root_update( stake_delegations, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    }

    fd_pubkey_t overflow = { .ul = { 81111UL, 92222UL } };
    fd_stake_delegations_root_update( stake_delegations, &overflow, &voter_pubkey_1, 424242UL, 3UL, 9UL, 17UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );

    fd_stake_delegation_t found[1];
    fd_stake_delegation_t const * queried = fd_stake_delegation_root_query( stake_delegations, &overflow );
    assert_delegation( queried, &overflow, &voter_pubkey_1, 424242UL, 3U, 9U, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &overflow, found ) );
    assert_delegation( found, &overflow, &voter_pubkey_1, 424242UL, 3U, 9U, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( found->credits_observed==17UL );
    FD_TEST( count_visible_delegations( stake_delegations )==max_stake_accounts+1UL );

    fd_pubkey_t overflow2 = { .ul = { 83333UL, 94444UL } };
    fd_stake_delegations_root_update( stake_delegations, &overflow2, &voter_pubkey_0, 515151UL, 4UL, 10UL, 18UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    ushort remove_fork = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_remove( stake_delegations, remove_fork, &overflow );
    fd_stake_delegations_apply_fork_delta( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, remove_fork );
    fd_stake_delegations_evict_fork( stake_delegations, remove_fork );
    FD_TEST( !test_stake_delegations_find_copy( stake_delegations, &overflow, found ) );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &overflow2, found ) );
    assert_delegation( found, &overflow2, &voter_pubkey_0, 515151UL, 4U, 10U, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    FD_TEST( found->credits_observed==18UL );
  }

  /* Case 37: Disk-spilled deltas retain independent state for sibling
     forks, honor ancestry order and tombstones, and can be rooted. */
  {
    fd_stake_delegations_reset( stake_delegations );

    for( ulong i=0UL; i<max_stake_accounts; i++ ) {
      fd_pubkey_t k = { .ul = { 100000UL+i, 110000UL+i } };
      fd_stake_delegations_root_update( stake_delegations, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    }
    fd_pubkey_t disk_existing = { .ul = { 101111UL, 112222UL } };
    fd_stake_delegations_root_update( stake_delegations, &disk_existing, &voter_pubkey_0, 44UL, 1UL, 6UL, 4UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );

    ushort filler_fork = fd_stake_delegations_new_fork( stake_delegations );
    for( ulong i=0UL; i<max_stake_accounts; i++ ) {
      fd_pubkey_t k = { .ul = { 120000UL+i, 130000UL+i } };
      fd_stake_delegations_fork_update( stake_delegations, filler_fork, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    }

    ushort fork0 = fd_stake_delegations_new_fork( stake_delegations );
    ushort fork1 = fd_stake_delegations_new_fork( stake_delegations );
    fd_pubkey_t overflow = { .ul = { 141111UL, 152222UL } };
    fd_stake_delegations_fork_update( stake_delegations, fork0, &overflow, &voter_pubkey_0, 111UL, 1UL, 7UL, 11UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_fork_update( stake_delegations, fork1, &overflow, &voter_pubkey_1, 222UL, 2UL, 8UL, 22UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_pubkey_t overflow2 = { .ul = { 163333UL, 174444UL } };
    fd_stake_delegations_fork_update( stake_delegations, fork0, &overflow2, &voter_pubkey_0, 333UL, 4UL, 10UL, 33UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_fork_update( stake_delegations, fork0, &disk_existing, &voter_pubkey_0, 444UL, 5UL, 11UL, 44UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_fork_update( stake_delegations, fork1, &disk_existing, &voter_pubkey_1, 555UL, 6UL, 12UL, 55UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );

    fd_stake_delegation_t found[1];
    test_stake_delegations_mark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork0 );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &overflow, found ) );
    assert_delegation( found, &overflow, &voter_pubkey_0, 111UL, 1U, 7U, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &overflow2, found ) );
    assert_delegation( found, &overflow2, &voter_pubkey_0, 333UL, 4U, 10U, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &disk_existing, found ) );
    assert_delegation( found, &disk_existing, &voter_pubkey_0, 444UL, 5U, 11U, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    test_stake_delegations_unmark_fork_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork0 );

    ushort fork_ids[2] = { fork0, fork1 };
    fd_stake_delegations_frontier_query_begin( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_ids, 2UL );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &overflow, found ) );
    assert_delegation( found, &overflow, &voter_pubkey_1, 222UL, 2U, 8U, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &disk_existing, found ) );
    assert_delegation( found, &disk_existing, &voter_pubkey_1, 555UL, 6U, 12U, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_frontier_query_end( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_ids, 2UL );

    fd_stake_delegations_fork_remove( stake_delegations, fork1, &overflow );
    fd_stake_delegations_frontier_query_begin( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_ids, 2UL );
    FD_TEST( !test_stake_delegations_find_copy( stake_delegations, &overflow, found ) );
    fd_stake_delegations_frontier_query_end( stake_delegations, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_ids, 2UL );

    fd_stake_delegations_evict_fork( stake_delegations, fork1 );
    fd_stake_delegations_apply_fork_delta( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, fork0 );
    fd_stake_delegations_evict_fork( stake_delegations, fork0 );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &overflow, found ) );
    assert_delegation( found, &overflow, &voter_pubkey_0, 111UL, 1U, 7U, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &overflow2, found ) );
    assert_delegation( found, &overflow2, &voter_pubkey_0, 333UL, 4U, 10U, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    FD_TEST( test_stake_delegations_find_copy( stake_delegations, &disk_existing, found ) );
    assert_delegation( found, &disk_existing, &voter_pubkey_0, 444UL, 5U, 11U, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );

    fd_stake_delegations_evict_fork( stake_delegations, filler_fork );
    fd_stake_delegations_reset( stake_delegations );
  }

  /* Case 38: Root-index tombstones are rebuilt before they can turn
     successful misses into full-table probes. */
  {
    fd_stake_delegations_reset( stake_delegations );

    for( ulong i=0UL; i<max_stake_accounts; i++ ) {
      fd_pubkey_t k = { .ul = { 180000UL+i, 190000UL+i } };
      fd_stake_delegations_root_update( stake_delegations, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    }

    fd_pubkey_t disk_keys[3] = {
      { .ul = { 181001UL, 191001UL } },
      { .ul = { 181002UL, 191002UL } },
      { .ul = { 181003UL, 191003UL } },
    };
    for( ulong i=0UL; i<3UL; i++ ) {
      fd_stake_delegations_root_update( stake_delegations, &disk_keys[i], &voter_pubkey_1, 100UL+i, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    }
    FD_TEST( stake_delegations->disk_root_cnt_==3UL );

    uint root_gen = stake_delegations->disk_root_gen_;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &disk_keys[0] );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &disk_keys[1] );
    fd_stake_delegations_apply_fork_delta( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, fork_idx );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );

    FD_TEST( stake_delegations->disk_root_cnt_==1UL );
    FD_TEST( stake_delegations->disk_root_gen_!=root_gen );
    FD_TEST( !stake_delegations->disk_root_tombstone_cnt_ );
    FD_TEST( fd_stake_delegation_root_query( stake_delegations, &disk_keys[2] ) );

    root_gen = stake_delegations->disk_root_gen_;
    fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &disk_keys[2] );
    fd_stake_delegations_apply_fork_delta( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, fork_idx );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    FD_TEST( !stake_delegations->disk_root_cnt_ );
    FD_TEST( stake_delegations->disk_root_gen_!=root_gen );
    FD_TEST( !stake_delegations->disk_root_tombstone_cnt_ );
  }

  /* Case 39: The configured disk capacity bounds persistent spill
     records, but frontier projection has separate temporary headroom. */
  {
    FD_TEST( !ftruncate( FD_STAKE_DELEGATIONS_FD, 0L ) );

    ulong const small_max      = 1UL;
    ulong const small_disk_max = 1UL;
    ulong const small_forks    = 2UL;
    void * small_mem = fd_wksp_alloc_laddr(
        wksp,
        fd_stake_delegations_align(),
        fd_stake_delegations_footprint( small_max, small_disk_max, small_max, small_forks ),
        wksp_tag );
    FD_TEST( small_mem );
    fd_stake_delegations_t * small = fd_stake_delegations_join(
        fd_stake_delegations_new( small_mem, 1UL, small_max, small_disk_max, small_max, small_forks ) );
    FD_TEST( small );

    fd_pubkey_t root_key  = { .ul = { 160001UL, 170001UL } };
    fd_pubkey_t delta_key = { .ul = { 160002UL, 170002UL } };
    fd_pubkey_t disk_key  = { .ul = { 160003UL, 170003UL } };
    fd_stake_delegations_root_update( small, &root_key, &voter_pubkey_0, 1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    small->effective_stake    = 1UL;
    small->activating_stake   = 0UL;
    small->deactivating_stake = 0UL;

    ushort fork_idx = fd_stake_delegations_new_fork( small );
    fd_stake_delegations_fork_update( small, fork_idx, &delta_key, &voter_pubkey_0, 2UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_fork_update( small, fork_idx, &disk_key,  &voter_pubkey_1, 3UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( fd_stake_delegations_disk_cnt( small )==1UL );

    test_stake_delegations_mark_fork_delta( small, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    fd_stake_delegation_t found[1];
    FD_TEST( test_stake_delegations_find_copy( small, &delta_key, found ) );
    assert_delegation( found, &delta_key, &voter_pubkey_0, 2UL, USHORT_MAX, USHORT_MAX, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    FD_TEST( test_stake_delegations_find_copy( small, &disk_key, found ) );
    assert_delegation( found, &disk_key, &voter_pubkey_1, 3UL, USHORT_MAX, USHORT_MAX, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( small->effective_stake==6UL );
    FD_TEST( !small->activating_stake );
    FD_TEST( !small->deactivating_stake );
    test_stake_delegations_unmark_fork_delta( small, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );

    FD_TEST( small->effective_stake==1UL );
    FD_TEST( !small->activating_stake );
    FD_TEST( !small->deactivating_stake );
    FD_TEST( fd_stake_delegations_disk_cnt( small )==1UL );
    fd_stake_delegations_evict_fork( small, fork_idx );
    FD_TEST( !fd_stake_delegations_disk_cnt( small ) );
    fd_wksp_free_laddr( small_mem );
  }

  /* Case 40: Rooting applies RAM tombstones before insertions so a fork
     whose final disk occupancy fits cannot fail due to map order. */
  {
    FD_TEST( !ftruncate( FD_STAKE_DELEGATIONS_FD, 0L ) );

    ulong const small_max      = 2UL;
    ulong const small_disk_max = 1UL;
    ulong const small_forks    = 2UL;
    void * small_mem = fd_wksp_alloc_laddr(
        wksp,
        fd_stake_delegations_align(),
        fd_stake_delegations_footprint( small_max, small_disk_max, small_max, small_forks ),
        wksp_tag );
    FD_TEST( small_mem );
    fd_stake_delegations_t * small = fd_stake_delegations_join(
        fd_stake_delegations_new( small_mem, 1UL, small_max, small_disk_max, small_max, small_forks ) );
    FD_TEST( small );

    fd_pubkey_t root0 = { .ul = { 210001UL, 220001UL } };
    fd_pubkey_t root1 = { .ul = { 210002UL, 220002UL } };
    fd_pubkey_t remove_key = { .ul = { 210003UL, 220003UL } };
    while( (fd_hash32( remove_key.uc, 1UL ) & (FD_STAKE_DELEGATIONS_FORK_MAP_CHAIN_CNT-1UL)) ==
           FD_STAKE_DELEGATIONS_FORK_MAP_CHAIN_CNT-1UL ) remove_key.ul[0]++;
    fd_stake_delegations_root_update( small, &root0,      &voter_pubkey_0, 1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_root_update( small, &root1,      &voter_pubkey_0, 2UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_root_update( small, &remove_key, &voter_pubkey_0, 3UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );

    ulong remove_chain = fd_hash32( remove_key.uc, 1UL ) & (FD_STAKE_DELEGATIONS_FORK_MAP_CHAIN_CNT-1UL);
    fd_pubkey_t insert_key = { .ul = { 230001UL, 240001UL } };
    while( (fd_hash32( insert_key.uc, 1UL ) & (FD_STAKE_DELEGATIONS_FORK_MAP_CHAIN_CNT-1UL)) <= remove_chain ) insert_key.ul[0]++;

    ushort fork_idx = fd_stake_delegations_new_fork( small );
    fd_stake_delegations_fork_update( small, fork_idx, &insert_key, &voter_pubkey_1, 4UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_fork_remove( small, fork_idx, &remove_key );
    fd_stake_delegations_apply_fork_delta( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, small, fork_idx );

    FD_TEST( !fd_stake_delegation_root_query( small, &remove_key ) );
    fd_stake_delegation_t const * inserted = fd_stake_delegation_root_query( small, &insert_key );
    assert_delegation( inserted, &insert_key, &voter_pubkey_1, 4UL, USHORT_MAX, USHORT_MAX, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( small->disk_root_cnt_==1UL );
    fd_stake_delegations_evict_fork( small, fork_idx );
    fd_wksp_free_laddr( small_mem );
  }

  /* Case 41: Rooting a multi-fork ancestry releases capacity across
     descendants before committing RAM insertions from ancestors. */
  {
    FD_TEST( !ftruncate( FD_STAKE_DELEGATIONS_FD, 0L ) );

    ulong const small_max      = 2UL;
    ulong const small_disk_max = 1UL;
    ulong const small_forks    = 3UL;
    void * small_mem = fd_wksp_alloc_laddr(
        wksp,
        fd_stake_delegations_align(),
        fd_stake_delegations_footprint( small_max, small_disk_max, small_max, small_forks ),
        wksp_tag );
    FD_TEST( small_mem );
    fd_stake_delegations_t * small = fd_stake_delegations_join(
        fd_stake_delegations_new( small_mem, 2UL, small_max, small_disk_max, small_max, small_forks ) );
    FD_TEST( small );

    fd_pubkey_t root0      = { .ul = { 250001UL, 260001UL } };
    fd_pubkey_t root1      = { .ul = { 250002UL, 260002UL } };
    fd_pubkey_t remove_key = { .ul = { 250003UL, 260003UL } };
    fd_pubkey_t insert_key = { .ul = { 250004UL, 260004UL } };
    fd_stake_delegations_root_update( small, &root0,      &voter_pubkey_0, 1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_root_update( small, &root1,      &voter_pubkey_0, 2UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_root_update( small, &remove_key, &voter_pubkey_0, 3UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );

    ushort fork0 = fd_stake_delegations_new_fork( small );
    ushort fork1 = fd_stake_delegations_new_fork( small );
    fd_stake_delegations_fork_update( small, fork0, &insert_key, &voter_pubkey_1, 4UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_fork_remove( small, fork1, &remove_key );

    ushort fork_ids[2] = { fork0, fork1 };
    fd_stake_delegations_apply_fork_deltas( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, small, fork_ids, 2UL );

    FD_TEST( !fd_stake_delegation_root_query( small, &remove_key ) );
    fd_stake_delegation_t const * inserted = fd_stake_delegation_root_query( small, &insert_key );
    assert_delegation( inserted, &insert_key, &voter_pubkey_1, 4UL, USHORT_MAX, USHORT_MAX, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( small->disk_root_cnt_==1UL );
    fd_stake_delegations_evict_fork( small, fork0 );
    fd_stake_delegations_evict_fork( small, fork1 );
    fd_wksp_free_laddr( small_mem );
  }

  /* Case 42: Root and fork-delta disk tiers each retain their configured
     capacity; a full root tier does not starve fork versioning. */
  {
    FD_TEST( !ftruncate( FD_STAKE_DELEGATIONS_FD, 0L ) );

    ulong const small_max      = 1UL;
    ulong const small_disk_max = 1UL;
    ulong const small_forks    = 2UL;
    void * small_mem = fd_wksp_alloc_laddr(
        wksp,
        fd_stake_delegations_align(),
        fd_stake_delegations_footprint( small_max, small_disk_max, small_max, small_forks ),
        wksp_tag );
    FD_TEST( small_mem );
    fd_stake_delegations_t * small = fd_stake_delegations_join(
        fd_stake_delegations_new( small_mem, 3UL, small_max, small_disk_max, small_max, small_forks ) );
    FD_TEST( small );

    fd_pubkey_t root0  = { .ul = { 270001UL, 280001UL } };
    fd_pubkey_t root1  = { .ul = { 270002UL, 280002UL } };
    fd_pubkey_t delta0 = { .ul = { 270003UL, 280003UL } };
    fd_pubkey_t delta1 = { .ul = { 270004UL, 280004UL } };
    fd_stake_delegations_root_update( small, &root0, &voter_pubkey_0, 1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_root_update( small, &root1, &voter_pubkey_0, 2UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );

    ushort fork_idx = fd_stake_delegations_new_fork( small );
    fd_stake_delegations_fork_update( small, fork_idx, &delta0, &voter_pubkey_1, 3UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_fork_update( small, fork_idx, &delta1, &voter_pubkey_1, 4UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );

    FD_TEST( small->disk_root_cnt_==1UL );
    FD_TEST( small->disk_delta_cnt_==1UL );
    FD_TEST( fd_stake_delegations_disk_cnt( small )==2UL );
    fd_stake_delegations_evict_fork( small, fork_idx );
    FD_TEST( small->disk_root_cnt_==1UL );
    FD_TEST( !small->disk_delta_cnt_ );
    fd_wksp_free_laddr( small_mem );
  }

  /* Case 43: Temporary roots return to RAM when a descendant frees a
     root-pool slot, including configurations with no persistent disk
     root capacity. */
  {
    FD_TEST( !ftruncate( FD_STAKE_DELEGATIONS_FD, 0L ) );

    ulong const small_max      = 2UL;
    ulong const small_disk_max = 0UL;
    ulong const small_forks    = 3UL;
    void * small_mem = fd_wksp_alloc_laddr(
        wksp,
        fd_stake_delegations_align(),
        fd_stake_delegations_footprint( small_max, small_disk_max, small_max, small_forks ),
        wksp_tag );
    FD_TEST( small_mem );
    fd_stake_delegations_t * small = fd_stake_delegations_join(
        fd_stake_delegations_new( small_mem, 4UL, small_max, small_disk_max, small_max, small_forks ) );
    FD_TEST( small );

    fd_pubkey_t root0      = { .ul = { 290001UL, 300001UL } };
    fd_pubkey_t root1      = { .ul = { 290002UL, 300002UL } };
    fd_pubkey_t insert_key = { .ul = { 290003UL, 300003UL } };
    fd_stake_delegations_root_update( small, &root0, &voter_pubkey_0, 1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_root_update( small, &root1, &voter_pubkey_0, 2UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );

    ushort fork0 = fd_stake_delegations_new_fork( small );
    ushort fork1 = fd_stake_delegations_new_fork( small );
    fd_stake_delegations_fork_update( small, fork0, &insert_key, &voter_pubkey_1, 3UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_fork_remove( small, fork1, &root0 );

    ushort fork_ids[2] = { fork0, fork1 };
    fd_stake_delegations_apply_fork_deltas( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, small, fork_ids, 2UL );

    FD_TEST( !fd_stake_delegation_root_query( small, &root0 ) );
    fd_stake_delegation_t const * inserted = fd_stake_delegation_root_query( small, &insert_key );
    assert_delegation( inserted, &insert_key, &voter_pubkey_1, 3UL, USHORT_MAX, USHORT_MAX, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( fd_stake_delegations_base_cnt( small )==small_max );
    FD_TEST( !fd_stake_delegations_disk_cnt( small ) );
    fd_stake_delegations_evict_fork( small, fork0 );
    fd_stake_delegations_evict_fork( small, fork1 );
    fd_wksp_free_laddr( small_mem );
  }

  /* Case 44: Temporary root headroom covers disk as well as RAM deltas
     when an ancestor adds records that a descendant later removes. */
  {
    FD_TEST( !ftruncate( FD_STAKE_DELEGATIONS_FD, 0L ) );

    ulong const small_max      = 1UL;
    ulong const small_disk_max = 3UL;
    ulong const small_forks    = 3UL;
    void * small_mem = fd_wksp_alloc_laddr(
        wksp,
        fd_stake_delegations_align(),
        fd_stake_delegations_footprint( small_max, small_disk_max, small_max, small_forks ),
        wksp_tag );
    FD_TEST( small_mem );
    fd_stake_delegations_t * small = fd_stake_delegations_join(
        fd_stake_delegations_new( small_mem, 5UL, small_max, small_disk_max, small_max, small_forks ) );
    FD_TEST( small );

    fd_pubkey_t root0   = { .ul = { 310001UL, 320001UL } };
    fd_pubkey_t remove0 = { .ul = { 310002UL, 320002UL } };
    fd_pubkey_t remove1 = { .ul = { 310003UL, 320003UL } };
    fd_pubkey_t keep    = { .ul = { 310004UL, 320004UL } };
    fd_pubkey_t insert0 = { .ul = { 310005UL, 320005UL } };
    fd_pubkey_t insert1 = { .ul = { 310006UL, 320006UL } };
    fd_stake_delegations_root_update( small, &root0,   &voter_pubkey_0, 1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_root_update( small, &remove0, &voter_pubkey_0, 2UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_root_update( small, &remove1, &voter_pubkey_0, 3UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_root_update( small, &keep,    &voter_pubkey_0, 4UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );

    ushort fork0 = fd_stake_delegations_new_fork( small );
    ushort fork1 = fd_stake_delegations_new_fork( small );
    fd_stake_delegations_fork_update( small, fork0, &insert0, &voter_pubkey_1, 5UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_fork_update( small, fork0, &insert1, &voter_pubkey_1, 6UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_fork_remove( small, fork1, &remove0 );
    fd_stake_delegations_fork_remove( small, fork1, &remove1 );

    ushort fork_ids[2] = { fork0, fork1 };
    fd_stake_delegations_apply_fork_deltas( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, small, fork_ids, 2UL );

    FD_TEST( !fd_stake_delegation_root_query( small, &remove0 ) );
    FD_TEST( !fd_stake_delegation_root_query( small, &remove1 ) );
    FD_TEST( fd_stake_delegation_root_query( small, &keep ) );
    FD_TEST( fd_stake_delegation_root_query( small, &insert0 ) );
    FD_TEST( fd_stake_delegation_root_query( small, &insert1 ) );
    FD_TEST( small->disk_root_cnt_==small_disk_max );
    fd_stake_delegations_evict_fork( small, fork0 );
    fd_stake_delegations_evict_fork( small, fork1 );
    fd_wksp_free_laddr( small_mem );
  }

  /* Test stake delegations refresh */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
