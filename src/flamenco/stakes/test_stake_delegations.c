#include "fd_stake_delegations.h"
#include "fd_stake_types.h"
#include "../runtime/fd_runtime_const.h"

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

/* These tests never drive the struct into pubkey fallback mode, so the
   iterator never needs to resolve anything out of an accounts database. */
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

int main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

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

  /* Leaves headroom above the root plus delta maximum of 90 so that the
     fallback cases below have somewhere to put entries. */
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
  void * junk_mem = fd_wksp_alloc_laddr( wksp, 1UL, 1UL, 999UL );
  FD_TEST( junk_mem );
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
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, empty_fork );
    FD_TEST( count_visible_delegations( stake_delegations ) == cnt_before );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, empty_fork );
    FD_TEST( count_visible_delegations( stake_delegations ) == cnt_before );
    fd_stake_delegations_evict_fork( stake_delegations, empty_fork );
  }

  /* Case 2: Delta for existing root (update) */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 500UL, 1UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_1, 500UL, 1UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 3: Delta for non-existing root (insert) */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_3 ) );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 777UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    fd_stake_delegation_t const * d3 = test_stake_delegations_find( stake_delegations, &stake_account_3 );
    assert_delegation( d3, &stake_account_3, &voter_pubkey_0, 777UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( fd_stake_delegations_base_cnt( stake_delegations ) == 4UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_3 ) );
    FD_TEST( fd_stake_delegations_base_cnt( stake_delegations ) == 3UL );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 4: Tombstone for existing root */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_0 ) );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 6: Multiple updates - last wins */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 100UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    FD_TEST( stake_delegation_0->stake == 200UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 7: Update then tombstone */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 999UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_0 ) );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 8: Tombstone then update */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 111UL, 2UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_1, 111UL, 2UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
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
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork0 );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    FD_TEST( stake_delegation_0->stake == 10UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork0 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork1 );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    FD_TEST( stake_delegation_0->stake == 20UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork1 );
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
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork1 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork2 );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_1, 333UL, 5UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork1 );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork2 );
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
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( fd_stake_delegations_base_cnt( stake_delegations ) == cnt_before + 1UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( fd_stake_delegations_base_cnt( stake_delegations ) == cnt_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 13: Double unmark */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 42UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 14: Double mark */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 88UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    FD_TEST( stake_delegation_0->stake == 88UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 15: Mixed fork */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 111UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_1 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 222UL, 0UL, 0UL, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_1, 111UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_1 ) );
    fd_stake_delegation_t const * d3 = test_stake_delegations_find( stake_delegations, &stake_account_3 );
    assert_delegation( d3, &stake_account_3, &voter_pubkey_0, 222UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( count_visible_delegations( stake_delegations ) == 3UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
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
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before - 200UL + 400UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 17: Update then tombstone -- totals must subtract base, not double-count */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 999UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before - 200UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 18: Tombstone then update -- totals must reflect only the update */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 777UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before - 200UL + 777UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
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
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before - 200UL + 30UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 20: Duplicate updates for a new account (dne_in_root) */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 50UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 80UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before + 80UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_3 ) );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 21: New account insert then tombstone -- totals unchanged */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 123UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_3 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
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
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    fd_stake_delegation_t const * d = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( d, &stake_account_0, &voter_pubkey_1, 600UL+max_stake_accounts, USHORT_MAX, USHORT_MAX, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    FD_TEST( d->credits_observed==max_stake_accounts );
    FD_TEST( stake_delegations->effective_stake==eff_before-200UL+600UL+max_stake_accounts );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( stake_delegations->effective_stake==eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 23: The same stake account has independent deltas across forks. */
  {
    ushort fork_a = fd_stake_delegations_new_fork( stake_delegations );
    ushort fork_b = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_a, &stake_account_0, &voter_pubkey_0, 901UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_fork_update( stake_delegations, fork_b, &stake_account_0, &voter_pubkey_1, 902UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );

    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_a );
    assert_delegation( test_stake_delegations_find( stake_delegations, &stake_account_0 ), &stake_account_0, &voter_pubkey_0, 901UL, USHORT_MAX, USHORT_MAX, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_a );

    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_b );
    assert_delegation( test_stake_delegations_find( stake_delegations, &stake_account_0 ), &stake_account_0, &voter_pubkey_1, 902UL, USHORT_MAX, USHORT_MAX, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_b );

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
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_0 ) );
    FD_TEST( stake_delegations->effective_stake==eff_before-200UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, fork_idx );
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
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, reused_fork_idx );
    assert_delegation( test_stake_delegations_find( stake_delegations, &stake_account_0 ), &stake_account_0, &voter_pubkey_1, 904UL, USHORT_MAX, USHORT_MAX, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, reused_fork_idx );
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
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, reset_fork_idx );
    assert_delegation( test_stake_delegations_find( stake_delegations, &stake_account_0 ), &stake_account_0, &voter_pubkey_1, 908UL, USHORT_MAX, USHORT_MAX, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, reset_fork_idx );
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
    FD_TEST( !fd_stake_delegations_pubkey_fallback( stake_delegations ) );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 29: The pubkey fallback tier tracks one entry per stake account
     and refcounts the root and delta references, so it drains back to
     empty once every reference is dropped. */
  {
    fd_stake_delegations_reset( stake_delegations );
    FD_TEST( !fd_stake_delegations_pubkey_cnt( stake_delegations ) );
    FD_TEST( !fd_stake_delegations_pubkey_fallback( stake_delegations ) );

    fd_stake_delegations_root_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 100UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    FD_TEST( fd_stake_delegations_pubkey_cnt( stake_delegations )==1UL );

    /* A fork touching an account the root already has takes a second
       reference rather than adding a second entry. */
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 101UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    FD_TEST( fd_stake_delegations_pubkey_cnt( stake_delegations )==1UL );

    /* An account only a fork has seen still gets an entry. */
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_1, &voter_pubkey_1, 102UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    FD_TEST( fd_stake_delegations_pubkey_cnt( stake_delegations )==2UL );

    /* Discarding the fork drops its references, leaving the root's. */
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    FD_TEST( fd_stake_delegations_pubkey_cnt( stake_delegations )==1UL );

    /* Rooting a tombstone drops the last reference. */
    ushort remove_fork = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_remove( stake_delegations, remove_fork, &stake_account_0 );
    FD_TEST( fd_stake_delegations_pubkey_cnt( stake_delegations )==1UL );
    fd_stake_delegations_apply_fork_delta( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, remove_fork );
    fd_stake_delegations_evict_fork( stake_delegations, remove_fork );
    FD_TEST( !fd_stake_delegations_pubkey_cnt( stake_delegations ) );
    FD_TEST( !fd_stake_delegations_base_cnt( stake_delegations ) );
    FD_TEST( !fd_stake_delegations_pubkey_fallback( stake_delegations ) );
  }

  /* Case 30: Exhausting the root pool enters fallback mode.  The stake
     account is still recorded in the pubkey tier, but it does not reach
     the root map, and the mode is sticky. */
  {
    fd_stake_delegations_reset( stake_delegations );

    for( ulong i=0UL; i<max_stake_accounts; i++ ) {
      fd_pubkey_t k = { .ul = { 5000UL+i, 6000UL+i } };
      fd_stake_delegations_root_update( stake_delegations, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    }
    FD_TEST( fd_stake_delegations_base_cnt( stake_delegations )==max_stake_accounts );
    FD_TEST( fd_stake_delegations_pubkey_cnt( stake_delegations )==max_stake_accounts );
    FD_TEST( !fd_stake_delegations_pubkey_fallback( stake_delegations ) );

    fd_pubkey_t overflow = { .ul = { 7777UL, 8888UL } };
    fd_stake_delegations_root_update( stake_delegations, &overflow, &voter_pubkey_0, 1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    FD_TEST( fd_stake_delegations_pubkey_fallback( stake_delegations ) );
    FD_TEST( fd_stake_delegations_base_cnt( stake_delegations )==max_stake_accounts );
    FD_TEST( fd_stake_delegations_pubkey_cnt( stake_delegations )==max_stake_accounts+1UL );
    FD_TEST( !fd_stake_delegation_root_query( stake_delegations, &overflow ) );

    /* Freeing a root slot does not clear the mode, and because refcounts
       are no longer paired the tier retains the entry. */
    fd_pubkey_t first       = { .ul = { 5000UL, 6000UL } };
    ushort      remove_fork = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_remove( stake_delegations, remove_fork, &first );
    fd_stake_delegations_apply_fork_delta( epoch, stake_history, &warmup_cooldown_rate_epoch, use_fixed_point_stake_math, stake_delegations, remove_fork );
    fd_stake_delegations_evict_fork( stake_delegations, remove_fork );
    FD_TEST( fd_stake_delegations_base_cnt( stake_delegations )==max_stake_accounts-1UL );
    FD_TEST( fd_stake_delegations_pubkey_cnt( stake_delegations )==max_stake_accounts+1UL );
    FD_TEST( fd_stake_delegations_pubkey_fallback( stake_delegations ) );

    /* Reset is the other way out of fallback mode. */
    fd_stake_delegations_reset( stake_delegations );
    FD_TEST( !fd_stake_delegations_pubkey_fallback( stake_delegations ) );
    FD_TEST( !fd_stake_delegations_pubkey_cnt( stake_delegations ) );
  }

  /* Case 31: Exhausting the delta pool enters fallback mode too, and the
     pubkey tier has room to spare because it is sized to cover both pools
     plus headroom. */
  {
    fd_stake_delegations_reset( stake_delegations );

    ushort      fork_idx  = fd_stake_delegations_new_fork( stake_delegations );
    ulong const delta_max = max_stake_accounts;
    for( ulong i=0UL; i<delta_max; i++ ) {
      fd_pubkey_t k = { .ul = { 20000UL+i, 30000UL+i } };
      fd_stake_delegations_fork_update( stake_delegations, fork_idx, &k, &voter_pubkey_0, i+1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    }
    FD_TEST( !fd_stake_delegations_pubkey_fallback( stake_delegations ) );
    FD_TEST( fd_stake_delegations_pubkey_cnt( stake_delegations )==delta_max );

    fd_pubkey_t overflow = { .ul = { 40000UL, 50000UL } };
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &overflow, &voter_pubkey_0, 1UL, ULONG_MAX, ULONG_MAX, 0UL, TEST_STAKE_DELEGATION_LAMPORTS, TEST_STAKE_DELEGATION_ACC_DLEN, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    FD_TEST( fd_stake_delegations_pubkey_fallback( stake_delegations ) );
    FD_TEST( fd_stake_delegations_pubkey_cnt( stake_delegations )==delta_max+1UL );

    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
    fd_stake_delegations_reset( stake_delegations );
  }

  /* Case 32: The pubkey tier is large enough to hold the root and delta
     pools simultaneously.  If it were not, filling the delta pool would
     exhaust the tier at the same moment fallback mode engaged, turning the
     graceful degradation back into a crash. */
  {
    FD_TEST( stake_delegations->max_pubkeys_==max_fallback_stake_accounts );
    FD_TEST( stake_delegations->max_pubkeys_ > 2UL*max_stake_accounts );
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

  /* Test stake delegations refresh */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
