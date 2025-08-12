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
  FD_TEST( fd_vote_state_map_chain_cnt_est( FD_RUNTIME_MAX_VOTE_ACCOUNTS ) == FD_VOTE_STATES_CHAIN_CNT_EST );

  ulong const max_vote_accounts = 10UL;

  void * vote_states_mem = fd_wksp_alloc_laddr( wksp, fd_vote_states_align(), fd_vote_states_footprint( max_vote_accounts ), wksp_tag );
  FD_TEST( vote_states_mem );

  FD_TEST( fd_vote_states_align()>=alignof(fd_vote_states_t)  );
  FD_TEST( fd_vote_states_align()>=fd_vote_state_pool_align() );
  FD_TEST( fd_vote_states_align()>=fd_vote_state_map_align()  );
  FD_TEST( fd_vote_states_align()==FD_VOTE_STATES_ALIGN );

  ulong chain_cnt = fd_vote_state_map_chain_cnt_est( max_vote_accounts );
  FD_TEST( fd_vote_states_footprint( max_vote_accounts ) >= fd_vote_states_align() + fd_vote_state_pool_footprint( max_vote_accounts ) + fd_vote_state_map_footprint( chain_cnt ) );

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

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
