/* Bit wasteful to have this as a separate test executable, consider
   merging this with another test. */

#include "../../util/fd_util.h"
#include "fd_find_16x16.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ushort ti[16];
#define INIT_TI( EXPR ) do { for( ulong j=0UL; j<16UL; j++ ) { ti[j] = (EXPR); } } while( 0 )

  INIT_TI( 0 );
  FD_TEST( fd_find_16x16( ti, 0 )==0 );
  for( ulong j=0UL; j<16UL; j++ ) {
    ti[ j ] = (ushort)( USHORT_MAX-j );
    FD_TEST( fd_find_16x16( ti, 0       )==j+1UL );
    FD_TEST( fd_find_16x16( ti, ti[ j ] )==j     );
  }

#undef INIT_TI

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
