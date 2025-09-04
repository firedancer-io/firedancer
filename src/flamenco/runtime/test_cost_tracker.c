#include "fd_cost_tracker.h"

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

  void * cost_tracker_mem = fd_wksp_alloc_laddr( wksp, fd_cost_tracker_align(), fd_cost_tracker_footprint(), wksp_tag );
  FD_TEST( cost_tracker_mem );

  FD_TEST( fd_cost_tracker_align()>=alignof(fd_cost_tracker_t) );
  FD_TEST( fd_cost_tracker_align()<=FD_COST_TRACKER_ALIGN );

  FD_TEST( fd_cost_tracker_footprint()<=FD_COST_TRACKER_FOOTPRINT );
  FD_LOG_WARNING(( "fd_cost_tracker_footprint: %lu", fd_cost_tracker_footprint() ));

  fd_features_t features = {0};
  FD_TEST( !fd_cost_tracker_new( NULL, &features, 999UL, 999UL ) );
  FD_TEST( !fd_cost_tracker_new( cost_tracker_mem, NULL, 999UL, 999UL ) );
  void * new_cost_tracker_mem = fd_cost_tracker_new( cost_tracker_mem, &features, 999UL, 999UL );
  FD_TEST( new_cost_tracker_mem );

  FD_TEST( !fd_cost_tracker_join( NULL ) );
  void * junk_mem = fd_wksp_alloc_laddr( wksp, 1UL, 1UL, 999UL );
  FD_TEST( junk_mem );
  FD_TEST( !fd_cost_tracker_join( junk_mem ) );

  fd_cost_tracker_t * cost_tracker = fd_cost_tracker_join( new_cost_tracker_mem );
  FD_TEST( cost_tracker );

  /* TODO: Add more sophisticated tests for the cost tracker. */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
