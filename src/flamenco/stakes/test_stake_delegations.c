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

static fd_stake_delegation_t const *
test_stake_delegations_find( fd_stake_delegations_t const * stake_delegations,
                             fd_pubkey_t const *            stake_account ) {
  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
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
                  ushort                         deactivation_epoch,
                  uchar                          warmup_cooldown_rate ) {
  FD_TEST( d );
  FD_TEST( !memcmp( &d->stake_account, stake_account, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &d->vote_account, vote_account, sizeof(fd_pubkey_t) ) );
  FD_TEST( d->stake == stake );
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
  ulong const expected_stake_accounts = fd_ulong_min( max_stake_accounts, FD_RUNTIME_EXPECTED_STAKE_ACCOUNTS );

  ulong const max_live_slots = 32UL;
  void * stake_delegations_mem = fd_wksp_alloc_laddr( wksp, fd_stake_delegations_align(), fd_stake_delegations_footprint( max_stake_accounts, expected_stake_accounts, max_live_slots ), wksp_tag );
  FD_TEST( stake_delegations_mem );

  FD_TEST( fd_stake_delegations_align()>=alignof(fd_stake_delegations_t)  );
  FD_TEST( fd_stake_delegations_align()==FD_STAKE_DELEGATIONS_ALIGN );

  FD_TEST( !fd_stake_delegations_new( NULL, 0UL, max_stake_accounts, expected_stake_accounts, max_live_slots ) );
  FD_TEST( !fd_stake_delegations_new( stake_delegations_mem, 0UL, 0UL, expected_stake_accounts, max_live_slots ) );
  void * new_stake_delegations_mem = fd_stake_delegations_new( stake_delegations_mem, 0UL, max_stake_accounts, expected_stake_accounts, max_live_slots );
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

  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 0UL );
  fd_stake_delegations_root_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 100UL, 0UL, 0UL, 0UL, 0.09 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 1UL );
  fd_stake_delegations_root_update( stake_delegations, &stake_account_1, &voter_pubkey_1, 200UL, 0UL, 0UL, 0UL, 0.09 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 2UL );
  fd_stake_delegations_root_update( stake_delegations, &stake_account_2, &voter_pubkey_1, 300UL, 0UL, 0UL, 0UL, 0.09 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 3UL );

  fd_stake_delegation_t const * stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
  FD_TEST( stake_delegation_0 );
  FD_TEST( !memcmp( &stake_delegation_0->stake_account, &stake_account_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_0->vote_account, &voter_pubkey_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_0->stake == 100UL );
  FD_TEST( stake_delegation_0->activation_epoch == 0UL );
  FD_TEST( stake_delegation_0->deactivation_epoch == 0UL );
  FD_TEST( stake_delegation_0->warmup_cooldown_rate == FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );

  fd_stake_delegation_t const * stake_delegation_1 = test_stake_delegations_find( stake_delegations, &stake_account_1 );
  FD_TEST( stake_delegation_1 );
  FD_TEST( !memcmp( &stake_delegation_1->stake_account, &stake_account_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_1->vote_account, &voter_pubkey_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_1->stake == 200UL );
  FD_TEST( stake_delegation_1->activation_epoch == 0UL );
  FD_TEST( stake_delegation_1->deactivation_epoch == 0UL );
  FD_TEST( stake_delegation_1->warmup_cooldown_rate == FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );

  fd_stake_delegation_t const * stake_delegation_2 = test_stake_delegations_find( stake_delegations, &stake_account_2 );
  FD_TEST( stake_delegation_2 );
  FD_TEST( !memcmp( &stake_delegation_2->stake_account, &stake_account_2, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_2->vote_account, &voter_pubkey_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_2->stake == 300UL );
  FD_TEST( stake_delegation_2->activation_epoch == 0UL );
  FD_TEST( stake_delegation_2->deactivation_epoch == 0UL );
  FD_TEST( stake_delegation_2->warmup_cooldown_rate == FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );

  FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_3 ) );

  fd_stake_delegations_root_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, 0UL, 0.09 );
  FD_TEST( stake_delegation_0 );
  FD_TEST( !memcmp( &stake_delegation_0->stake_account, &stake_account_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_0->vote_account, &voter_pubkey_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_0->stake == 200UL );
  FD_TEST( stake_delegation_0->activation_epoch == 0UL );
  FD_TEST( stake_delegation_0->deactivation_epoch == 0UL );
  FD_TEST( stake_delegation_0->warmup_cooldown_rate == FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 3UL );

  ushort remove_fork = fd_stake_delegations_new_fork( stake_delegations );
  fd_stake_delegations_fork_remove( stake_delegations, remove_fork, &stake_account_1 );

  ulong epoch = 10;
  fd_stake_history_t stake_history[1] = {0};
  ulong warmup_cooldown_rate_epoch = 0UL;
  fd_stake_delegations_apply_fork_delta( epoch, stake_history, &warmup_cooldown_rate_epoch, stake_delegations, remove_fork );
  fd_stake_delegations_evict_fork( stake_delegations, remove_fork );
  FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_1 ) );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 2UL );

  fd_stake_delegations_root_update( stake_delegations, &stake_account_1, &voter_pubkey_1, 10000UL, 0UL, 0UL, 0UL, 0.09 );
  stake_delegation_1 = test_stake_delegations_find( stake_delegations, &stake_account_1 );
  FD_TEST( stake_delegation_1 );
  FD_TEST( !memcmp( &stake_delegation_1->stake_account, &stake_account_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_1->vote_account, &voter_pubkey_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_1->stake == 10000UL );
  FD_TEST( stake_delegation_1->activation_epoch == 0UL );
  FD_TEST( stake_delegation_1->deactivation_epoch == 0UL );
  FD_TEST( stake_delegation_1->warmup_cooldown_rate == FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 3UL );

  /* Test stake delegation delta mark/unmark */

  /* Case 1: Empty fork */
  {
    ushort empty_fork = fd_stake_delegations_new_fork( stake_delegations );
    ulong  cnt_before = count_visible_delegations( stake_delegations );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, empty_fork );
    FD_TEST( count_visible_delegations( stake_delegations ) == cnt_before );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, empty_fork );
    FD_TEST( count_visible_delegations( stake_delegations ) == cnt_before );
    fd_stake_delegations_evict_fork( stake_delegations, empty_fork );
  }

  /* Case 2: Delta for existing root (update) */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 500UL, 1UL, 0UL, 0UL, 0.09 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_1, 500UL, 1UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 3: Delta for non-existing root (insert) */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_3 ) );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 777UL, 0UL, 0UL, 0UL, 0.09 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    fd_stake_delegation_t const * d3 = test_stake_delegations_find( stake_delegations, &stake_account_3 );
    assert_delegation( d3, &stake_account_3, &voter_pubkey_0, 777UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 4UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_3 ) );
    FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 3UL );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 4: Tombstone for existing root */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_0 ) );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 6: Multiple updates - last wins */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 100UL, 0UL, 0UL, 0UL, 0.09 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, 0UL, 0.09 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    FD_TEST( stake_delegation_0->stake == 200UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 7: Update then tombstone */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 999UL, 0UL, 0UL, 0UL, 0.09 );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_0 ) );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 8: Tombstone then update */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 111UL, 2UL, 0UL, 0UL, 0.09 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_1, 111UL, 2UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 9: Sequential fork mark/unmark */
  {
    ushort fork0 = fd_stake_delegations_new_fork( stake_delegations );
    ushort fork1 = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork0, &stake_account_0, &voter_pubkey_0, 10UL, 0UL, 0UL, 0UL, 0.09 );
    fd_stake_delegations_fork_update( stake_delegations, fork1, &stake_account_0, &voter_pubkey_0, 20UL, 0UL, 0UL, 0UL, 0.09 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork0 );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    FD_TEST( stake_delegation_0->stake == 10UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork0 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork1 );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    FD_TEST( stake_delegation_0->stake == 20UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork1 );
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
    fd_stake_delegations_fork_update( stake_delegations, fork2, &stake_account_0, &voter_pubkey_1, 333UL, 5UL, 0UL, 0UL, 0.25 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork1 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork2 );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_1, 333UL, 5UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork1 );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork2 );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_evict_fork( stake_delegations, fork1 );
    fd_stake_delegations_evict_fork( stake_delegations, fork2 );
  }

  /* Case 12: fd_stake_delegations_cnt */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    ulong  cnt_before = fd_stake_delegations_cnt( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 1UL, 0UL, 0UL, 0UL, 0.09 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == cnt_before + 1UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == cnt_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 13: Double unmark */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 42UL, 0UL, 0UL, 0UL, 0.09 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 14: Double mark */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 88UL, 0UL, 0UL, 0UL, 0.09 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    FD_TEST( stake_delegation_0->stake == 88UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 15: Mixed fork */
  {
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 111UL, 0UL, 0UL, 0UL, 0.09 );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_1 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 222UL, 0UL, 0UL, 0UL, 0.09 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    stake_delegation_0 = test_stake_delegations_find( stake_delegations, &stake_account_0 );
    assert_delegation( stake_delegation_0, &stake_account_0, &voter_pubkey_1, 111UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_1 ) );
    fd_stake_delegation_t const * d3 = test_stake_delegations_find( stake_delegations, &stake_account_3 );
    assert_delegation( d3, &stake_account_3, &voter_pubkey_0, 222UL, 0UL, 0UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
    FD_TEST( count_visible_delegations( stake_delegations ) == 3UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    FD_TEST( count_visible_delegations( stake_delegations ) == 3UL );
    FD_TEST( test_stake_delegations_find( stake_delegations, &stake_account_1 ) );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_3 ) );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Stake total tests.

     The existing tests all use activation_epoch=0, deactivation_epoch=0
     which produces zero effective stake.  To exercise the totals
     accounting we reinitialize the root with epochs that yield non-zero
     effective stake: activation_epoch=USHORT_MAX (→ULONG_MAX) and
     deactivation_epoch=USHORT_MAX (→ULONG_MAX).  With an empty stake
     history and target_epoch=10 this gives effective=stake,
     activating=0, deactivating=0. */

  fd_stake_delegations_reset( stake_delegations );
  stake_delegations->effective_stake    = 0UL;
  stake_delegations->activating_stake   = 0UL;
  stake_delegations->deactivating_stake = 0UL;

  fd_stake_delegations_root_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 200UL, USHORT_MAX, USHORT_MAX, 0UL, 0.25 );
  fd_stake_delegations_root_update( stake_delegations, &stake_account_1, &voter_pubkey_1, 300UL, USHORT_MAX, USHORT_MAX, 0UL, 0.25 );
  fd_stake_delegations_root_update( stake_delegations, &stake_account_2, &voter_pubkey_1, 500UL, USHORT_MAX, USHORT_MAX, 0UL, 0.25 );

  stake_delegations->effective_stake = 200UL + 300UL + 500UL;

  /* Case 16: Duplicate updates -- totals must reflect only the last delta */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 100UL, USHORT_MAX, USHORT_MAX, 0UL, 0.25 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 400UL, USHORT_MAX, USHORT_MAX, 0UL, 0.25 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before - 200UL + 400UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 17: Update then tombstone -- totals must subtract base, not double-count */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 999UL, USHORT_MAX, USHORT_MAX, 0UL, 0.25 );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before - 200UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 18: Tombstone then update -- totals must reflect only the update */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_0 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_1, 777UL, USHORT_MAX, USHORT_MAX, 0UL, 0.25 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before - 200UL + 777UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 19: Triple update -- totals must reflect only the last */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 10UL, USHORT_MAX, USHORT_MAX, 0UL, 0.25 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 20UL, USHORT_MAX, USHORT_MAX, 0UL, 0.25 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_0, &voter_pubkey_0, 30UL, USHORT_MAX, USHORT_MAX, 0UL, 0.25 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before - 200UL + 30UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 20: Duplicate updates for a new account (dne_in_root) */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 50UL, USHORT_MAX, USHORT_MAX, 0UL, 0.25 );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 80UL, USHORT_MAX, USHORT_MAX, 0UL, 0.25 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before + 80UL );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    FD_TEST( !test_stake_delegations_find( stake_delegations, &stake_account_3 ) );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Case 21: New account insert then tombstone -- totals unchanged */
  {
    ulong eff_before = stake_delegations->effective_stake;
    ushort fork_idx = fd_stake_delegations_new_fork( stake_delegations );
    fd_stake_delegations_fork_update( stake_delegations, fork_idx, &stake_account_3, &voter_pubkey_0, 123UL, USHORT_MAX, USHORT_MAX, 0UL, 0.25 );
    fd_stake_delegations_fork_remove( stake_delegations, fork_idx, &stake_account_3 );
    fd_stake_delegations_mark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_unmark_delta( stake_delegations, epoch, stake_history, &warmup_cooldown_rate_epoch, fork_idx );
    FD_TEST( stake_delegations->effective_stake == eff_before );
    fd_stake_delegations_evict_fork( stake_delegations, fork_idx );
  }

  /* Test stake delegations refresh */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
