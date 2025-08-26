#include "fd_stake_delegations.h"
#include "../runtime/fd_runtime_const.h"

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

  /* We need to make sure that the hard constant is at least large
     enough to actually hold the footprint of stake delegations for
     the max number of stake accounts that the runtime can support. */
  FD_TEST( fd_stake_delegations_footprint( FD_RUNTIME_MAX_STAKE_ACCOUNTS ) <= FD_STAKE_DELEGATIONS_FOOTPRINT );
  FD_TEST( fd_stake_delegations_footprint( FD_RUNTIME_MAX_STAKE_ACCS_IN_SLOT ) <= FD_STAKE_DELEGATIONS_DELTA_FOOTPRINT );

  /* Test stake delegations where is_tombstone == 0 */

  ulong const max_stake_accounts = 10UL;

  void * stake_delegations_mem = fd_wksp_alloc_laddr( wksp, fd_stake_delegations_align(), fd_stake_delegations_footprint( max_stake_accounts ), wksp_tag );
  FD_TEST( stake_delegations_mem );

  FD_TEST( fd_stake_delegations_align()>=alignof(fd_stake_delegations_t)  );
  FD_TEST( fd_stake_delegations_align()==FD_STAKE_DELEGATIONS_ALIGN );

  FD_TEST( !fd_stake_delegations_new( NULL, max_stake_accounts, 0 ) );
  FD_TEST( !fd_stake_delegations_new( stake_delegations_mem, 0UL, 0 ) );
  void * new_stake_delegations_mem = fd_stake_delegations_new( stake_delegations_mem, max_stake_accounts, 0 );
  FD_TEST( new_stake_delegations_mem );

  FD_TEST( !fd_stake_delegations_join( NULL ) );
  void * junk_mem = fd_wksp_alloc_laddr( wksp, 1UL, 1UL, 999UL );
  FD_TEST( junk_mem );
  FD_TEST( !fd_stake_delegations_join( junk_mem ) );

  fd_stake_delegations_t * stake_delegations = fd_stake_delegations_join( new_stake_delegations_mem );
  FD_TEST( stake_delegations );

  FD_TEST( !fd_stake_delegations_leave( NULL ) );
  FD_TEST( fd_stake_delegations_join( fd_stake_delegations_leave( stake_delegations ) ) );
  FD_TEST( fd_stake_delegations_join( fd_stake_delegations_leave( stake_delegations ) )==stake_delegations );

  FD_TEST( fd_stake_delegations_max( stake_delegations ) == max_stake_accounts );

  fd_pubkey_t stake_account_0 = { .ul = { 999UL, 999UL} };
  fd_pubkey_t stake_account_1 = { .ul = { 1, 2 } };
  fd_pubkey_t stake_account_2 = { .ul = { 3, 4 } };
  fd_pubkey_t stake_account_3 = { .ul = { 5, 6 } };

  fd_pubkey_t voter_pubkey_0 = { .ul = { 5, 6 } };
  fd_pubkey_t voter_pubkey_1 = { .ul = { 7, 8 } };

  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 0UL );
  fd_stake_delegations_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 100UL, 0UL, 0UL, 0UL, 0.0 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 1UL );
  fd_stake_delegations_update( stake_delegations, &stake_account_1, &voter_pubkey_1, 200UL, 0UL, 0UL, 0UL, 0.0 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 2UL );
  fd_stake_delegations_update( stake_delegations, &stake_account_2, &voter_pubkey_1, 300UL, 0UL, 0UL, 0UL, 0.0 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 3UL );

  fd_stake_delegation_t const * stake_delegation_0 = fd_stake_delegations_query( stake_delegations, &stake_account_0 );
  FD_TEST( stake_delegation_0 );
  FD_TEST( !memcmp( &stake_delegation_0->stake_account, &stake_account_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_0->vote_account, &voter_pubkey_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_0->stake == 100UL );
  FD_TEST( stake_delegation_0->activation_epoch == 0UL );
  FD_TEST( stake_delegation_0->deactivation_epoch == 0UL );
  FD_TEST( stake_delegation_0->warmup_cooldown_rate == 0.0 );

  fd_stake_delegation_t const * stake_delegation_1 = fd_stake_delegations_query( stake_delegations, &stake_account_1 );
  FD_TEST( stake_delegation_1 );
  FD_TEST( !memcmp( &stake_delegation_1->stake_account, &stake_account_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_1->vote_account, &voter_pubkey_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_1->stake == 200UL );
  FD_TEST( stake_delegation_1->activation_epoch == 0UL );
  FD_TEST( stake_delegation_1->deactivation_epoch == 0UL );
  FD_TEST( stake_delegation_1->warmup_cooldown_rate == 0.0 );

  fd_stake_delegation_t const * stake_delegation_2 = fd_stake_delegations_query( stake_delegations, &stake_account_2 );
  FD_TEST( stake_delegation_2 );
  FD_TEST( !memcmp( &stake_delegation_2->stake_account, &stake_account_2, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_2->vote_account, &voter_pubkey_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_2->stake == 300UL );
  FD_TEST( stake_delegation_2->activation_epoch == 0UL );
  FD_TEST( stake_delegation_2->deactivation_epoch == 0UL );
  FD_TEST( stake_delegation_2->warmup_cooldown_rate == 0.0 );

  FD_TEST( !fd_stake_delegations_query( stake_delegations, &stake_account_3 ) );

  fd_stake_delegations_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 200UL, 0UL, 0UL, 0UL, 0.0 );
  FD_TEST( stake_delegation_0 );
  FD_TEST( !memcmp( &stake_delegation_0->stake_account, &stake_account_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_0->vote_account, &voter_pubkey_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_0->stake == 200UL );
  FD_TEST( stake_delegation_0->activation_epoch == 0UL );
  FD_TEST( stake_delegation_0->deactivation_epoch == 0UL );
  FD_TEST( stake_delegation_0->warmup_cooldown_rate == 0.0 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 3UL );

  fd_stake_delegations_remove( stake_delegations, &stake_account_1 );
  FD_TEST( !fd_stake_delegations_query( stake_delegations, &stake_account_1 ) );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 2UL );

  fd_stake_delegations_update( stake_delegations, &stake_account_1, &voter_pubkey_1, 10000UL, 0UL, 0UL, 0UL, 0.0 );
  stake_delegation_1 = fd_stake_delegations_query( stake_delegations, &stake_account_1 );
  FD_TEST( stake_delegation_1 );
  FD_TEST( !memcmp( &stake_delegation_1->stake_account, &stake_account_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation_1->vote_account, &voter_pubkey_1, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation_1->stake == 10000UL );
  FD_TEST( stake_delegation_1->activation_epoch == 0UL );
  FD_TEST( stake_delegation_1->deactivation_epoch == 0UL );
  FD_TEST( stake_delegation_1->warmup_cooldown_rate == 0.0 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 3UL );

  FD_TEST( !fd_stake_delegations_delete( NULL ) );
  uchar * deleted_mem = fd_stake_delegations_delete( fd_stake_delegations_leave( stake_delegations ) );
  FD_TEST( deleted_mem );
  FD_TEST( !fd_stake_delegations_join( deleted_mem ) );

  /* Test stake_delegations where is_tombstone == 1. */
  stake_delegations = fd_stake_delegations_join( fd_stake_delegations_new( stake_delegations_mem, max_stake_accounts, 1 ) );
  FD_TEST( stake_delegations );

  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 0UL );
  fd_stake_delegations_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 100UL, 0UL, 0UL, 0UL, 0.0 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 1UL );
  fd_stake_delegations_update( stake_delegations, &stake_account_1, &voter_pubkey_1, 200UL, 0UL, 0UL, 0UL, 0.0 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 2UL );
  fd_stake_delegation_t const * stake_delegation = fd_stake_delegations_query( stake_delegations, &stake_account_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->is_tombstone == 0 );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &stake_account_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->is_tombstone == 0 );

  fd_stake_delegations_remove( stake_delegations, &stake_account_0 );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &stake_account_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->is_tombstone == 1 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 2UL );

  fd_stake_delegations_remove( stake_delegations, &stake_account_2 );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &stake_account_2 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->is_tombstone == 1 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 3UL );

  fd_stake_delegations_update( stake_delegations, &stake_account_0, &voter_pubkey_0, 100UL, 0UL, 0UL, 0UL, 0.0 );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &stake_account_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->is_tombstone == 0 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 3UL );

  /* Test stake delegations refresh */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
