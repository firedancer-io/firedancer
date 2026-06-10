#include "fd_cost_tracker.h"

int main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong        wksp_tag = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",  NULL, 1234UL          );
  fd_wksp_t *  wksp     = fd_wksp_from_env( &argc, &argv, "gigantic", 1UL, "wksp", 0UL, NULL );

  void * cost_tracker_mem = fd_wksp_alloc_laddr( wksp, fd_cost_tracker_align(), fd_cost_tracker_footprint(), wksp_tag );
  FD_TEST( cost_tracker_mem );

  FD_TEST( fd_cost_tracker_align()>=alignof(fd_cost_tracker_t) );
  FD_TEST( fd_cost_tracker_align()<=FD_COST_TRACKER_ALIGN );

  FD_TEST( fd_cost_tracker_footprint()<=FD_COST_TRACKER_FOOTPRINT );
  FD_LOG_WARNING(( "fd_cost_tracker_footprint: %lu", fd_cost_tracker_footprint() ));

  FD_TEST( !fd_cost_tracker_new( NULL, 0, 999UL ) );
  void * new_cost_tracker_mem = fd_cost_tracker_new( cost_tracker_mem, 0, 999UL );

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
