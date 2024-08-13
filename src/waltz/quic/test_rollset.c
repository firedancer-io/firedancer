#include "fd_rollset.h"
#include "../../util/fd_util.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rollset_t rs[1];
# define ROLLSET_SET( min_, set_ ) rs->min = (min_); rs->set = (set_)
# define ROLLSET_TEST( min_, set_ ) do {                             \
    ulong min2=(min_); ulong set2=(set_);                            \
    if( FD_UNLIKELY( rs->min!=min2 || rs->set!=set2 ) ) {            \
      FD_LOG_ERR(( "expected min=%#lx set=%#lx; have min=%#lx set=%#lx", \
                   min2, set2, rs->min, rs->set ));                  \
    }                                                                \
  } while(0);

  ROLLSET_SET( 0, 0 );
  for( ulong j=0UL; j<64UL; j++ ) {
    fd_rollset_insert( rs, j );
    ROLLSET_TEST( 0, (0XFFFFFFFFFFFFFFFFUL)>>(63-j) );
    for( ulong k=0UL; k<=j; k++ ) {
      FD_TEST( fd_rollset_query( rs, k ) );
    }
    for( ulong k=j+1; k<64UL; k++ ) {
      FD_TEST( !fd_rollset_query( rs, k ) );
    }
  }

  ROLLSET_SET( 0, 0XAAAAAAAAAAAAAAAAUL );
  for( ulong j=0UL; j<64UL; j++ ) {
    FD_TEST( fd_rollset_query( rs, j )==!!(j&1) );
  }
  fd_rollset_insert( rs, 64 );
  ROLLSET_TEST( 1, 0xd555555555555555UL );

  for( ulong j=0UL; j<64UL; j++ ) {
    ROLLSET_SET( 0, 0XFFFFFFFFFFFFFFFFUL );
    fd_rollset_insert( rs, j );
    ROLLSET_TEST( 0, 0XFFFFFFFFFFFFFFFFUL );
    FD_TEST( fd_rollset_query( rs, j ) );
  }
  for( ulong j=64UL; j<128UL; j++ ) {
    ROLLSET_SET( 0, 0XFFFFFFFFFFFFFFFFUL );
    fd_rollset_insert( rs, j );
    ROLLSET_TEST( j-63UL, 0X8000000000000000UL | (0XFFFFFFFFFFFFFFFFUL>>(j-63UL)) );
  }
  for( ulong j=128UL; j<256UL; j++ ) {
    ROLLSET_SET( 0, 0XFFFFFFFFFFFFFFFFUL );
    fd_rollset_insert( rs, j );
    ROLLSET_TEST( j-63UL, 0X8000000000000000UL );
    for( ulong k=0UL; k<(j-64UL); k++ ) {
      FD_TEST( fd_rollset_query( rs, k ) );
    }
  }

  fd_halt();
  return 0;
}
