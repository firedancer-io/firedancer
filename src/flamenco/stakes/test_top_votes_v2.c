#include "fd_top_votes_v2.h"
#include "../../util/fd_util.h"

#include <stdlib.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong const max_fork_width = 3UL;
  ulong const max_live_banks = 3UL;
  ulong const align          = fd_top_votes_v2_align();
  ulong const footprint      = fd_top_votes_v2_footprint( max_fork_width, max_live_banks );

  FD_TEST( align );
  FD_TEST( footprint );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );
  FD_TEST( !fd_top_votes_v2_footprint( 0UL,           max_live_banks ) );
  FD_TEST( !fd_top_votes_v2_footprint( max_fork_width, 0UL            ) );
  FD_TEST( !fd_top_votes_v2_new( NULL, max_fork_width, max_live_banks, 1234UL ) );

  void * mem = aligned_alloc( align, footprint );
  FD_TEST( mem );
  fd_top_votes_v2_t * top_votes = fd_top_votes_v2_join(
      fd_top_votes_v2_new( mem, max_fork_width, max_live_banks, 1234UL ) );
  FD_TEST( top_votes );
  fd_top_votes_v2_new_child( top_votes, 0UL, 1UL );
  fd_top_votes_v2_new_epoch_child( top_votes, 1UL, 2UL );

  /* All persisted references are offsets, so copying the complete object
     to a different address must preserve a valid join. */

  void * relocated = aligned_alloc( align, footprint );
  FD_TEST( relocated );
  memcpy( relocated, mem, footprint );
  FD_TEST( fd_top_votes_v2_join( relocated ) );
  FD_TEST( !fd_top_votes_v2_join( (uchar *)relocated+1UL ) );

  free( relocated );
  free( mem );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
