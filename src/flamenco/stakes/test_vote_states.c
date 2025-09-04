#include "fd_vote_states.h"
#include "../runtime/fd_runtime_const.h"

int main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL, NULL            );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"      );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 1UL             );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  ulong        wksp_tag = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",  NULL, 1234UL          );

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
     enough to actually hold the footprint of vote states for the max
     number of vote accounts that the runtime can support. */
  FD_TEST( fd_vote_states_footprint( FD_RUNTIME_MAX_VOTE_ACCOUNTS ) <= FD_VOTE_STATES_FOOTPRINT );

  ulong const max_vote_accounts = 10UL;

  void * vote_states_mem = fd_wksp_alloc_laddr( wksp, fd_vote_states_align(), fd_vote_states_footprint( max_vote_accounts ), wksp_tag );
  FD_TEST( vote_states_mem );

  FD_TEST( fd_vote_states_align()>=alignof(fd_vote_states_t) );
  FD_TEST( fd_vote_states_align()==FD_VOTE_STATES_ALIGN );

  FD_TEST( !fd_vote_states_new( NULL, max_vote_accounts, 999UL ) );
  FD_TEST( !fd_vote_states_new( vote_states_mem, 0UL, 999UL ) );
  void * new_vote_states_mem = fd_vote_states_new( vote_states_mem, max_vote_accounts, 999UL );
  FD_TEST( new_vote_states_mem );

  FD_TEST( !fd_vote_states_join( NULL ) );
  void * junk_mem = fd_wksp_alloc_laddr( wksp, 1UL, 1UL, 999UL );
  FD_TEST( junk_mem );
  FD_TEST( !fd_vote_states_join( junk_mem ) );

  fd_vote_states_t * vote_states = fd_vote_states_join( new_vote_states_mem );
  FD_TEST( vote_states );

  fd_pubkey_t vote_account_0 = { .ul = { 0, 1, 2, 3 } };
  fd_pubkey_t vote_account_1 = { .ul = { 1, 2, 3, 6 } };
  fd_pubkey_t node_account_0 = { .ul = { 4, 5, 6, 7 } };

  ushort epoch[100] = { 1 };
  ulong  credits[100] = { 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000 };
  ulong  prev_credits[100] = { 102, 200, 300, 400, 500, 600, 700, 800, 900, 1000 };

  fd_vote_states_update(
      vote_states,
      &vote_account_0,
      &node_account_0,
      50,
      100L,
      1000UL,
      0UL,
      epoch,
      credits,
      prev_credits );

  FD_TEST( fd_vote_states_cnt( vote_states ) == 1UL );

  fd_vote_states_update(
      vote_states,
      &vote_account_1,
      &node_account_0,
      51,
      100L,
      10000UL,
      1UL,
      epoch,
      credits,
      prev_credits );

  FD_TEST( fd_vote_states_cnt( vote_states ) == 2UL );

  fd_vote_state_ele_t * vote_state_ele = fd_vote_states_query( vote_states, &vote_account_0 );
  FD_TEST( vote_state_ele );
  FD_TEST( memcmp( &vote_state_ele->vote_account, &vote_account_0, sizeof(fd_pubkey_t) ) == 0 );
  FD_TEST( memcmp( &vote_state_ele->node_account, &node_account_0, sizeof(fd_pubkey_t) ) == 0 );
  FD_TEST( vote_state_ele->last_vote_slot == 1000UL );
  FD_TEST( vote_state_ele->last_vote_timestamp == 100L );
  FD_TEST( vote_state_ele->commission == 50 );
  FD_TEST( vote_state_ele->credits_cnt == 0UL );

  fd_vote_state_ele_t * vote_state_ele_1 = fd_vote_states_query( vote_states, &vote_account_1 );
  FD_TEST( vote_state_ele_1 );
  FD_TEST( memcmp( &vote_state_ele_1->vote_account, &vote_account_1, sizeof(fd_pubkey_t) ) == 0 );
  FD_TEST( memcmp( &vote_state_ele_1->node_account, &node_account_0, sizeof(fd_pubkey_t) ) == 0 );
  FD_TEST( vote_state_ele_1->last_vote_slot == 10000UL );
  FD_TEST( vote_state_ele_1->last_vote_timestamp == 100L );
  FD_TEST( vote_state_ele_1->commission == 51 );
  FD_TEST( vote_state_ele_1->credits_cnt == 1UL );
  FD_TEST( vote_state_ele_1->credits[0] == 100 );
  FD_TEST( vote_state_ele_1->epoch[0] == 1 );
  FD_TEST( vote_state_ele_1->epoch[0] == 1 );
  FD_TEST( vote_state_ele_1->prev_credits[0] == 102 );

  fd_vote_states_update_stake( vote_states, &vote_account_0, 10UL );

  vote_state_ele = fd_vote_states_query( vote_states, &vote_account_0 );
  FD_TEST( vote_state_ele->stake == 10UL );

  fd_vote_states_reset_stakes( vote_states );

  vote_state_ele = fd_vote_states_query( vote_states, &vote_account_0 );
  FD_TEST( vote_state_ele->stake == 0UL );

  fd_vote_states_update_stake( vote_states, &vote_account_0, 100UL );

  vote_state_ele = fd_vote_states_query( vote_states, &vote_account_0 );
  FD_TEST( vote_state_ele->stake == 100UL );

  fd_vote_states_remove( vote_states, &vote_account_0 );

  FD_TEST( fd_vote_states_cnt( vote_states ) == 1UL );

  vote_state_ele = fd_vote_states_query( vote_states, &vote_account_0 );
  FD_TEST( !vote_state_ele );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
