#include "test_neon_common.c"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "Testing wwi (4x32-bit int)..." ));

  int p[4] V_ATTR = { 1, 2, 3, 4 };
  wwi_t x = wwi_ld( p );

  if( FD_UNLIKELY( wwi_extract( x, 0 )!=1 || wwi_extract( x, 1 )!=2 || 
                   wwi_extract( x, 2 )!=3 || wwi_extract( x, 3 )!=4 ) ) {
    FD_LOG_ERR(( "wwi_ld / wwi_extract failed" ));
  }

  wwi_t y = wwi_add( x, wwi_one() );
  if( FD_UNLIKELY( wwi_extract( y, 0 )!=2 || wwi_extract( y, 1 )!=3 || 
                   wwi_extract( y, 2 )!=4 || wwi_extract( y, 3 )!=5 ) ) {
    FD_LOG_ERR(( "wwi_add failed" ));
  }

  FD_LOG_NOTICE(( "Testing wwu (4x32-bit uint)..." ));

  uint up[4] V_ATTR = { 10U, 20U, 30U, 40U };
  wwu_t ux = wwu_ld( up );
  if( FD_UNLIKELY( wwu_extract( ux, 0 )!=10U || wwu_extract( ux, 1 )!=20U || 
                   wwu_extract( ux, 2 )!=30U || wwu_extract( ux, 3 )!=40U ) ) {
    FD_LOG_ERR(( "wwu_ld failed" ));
  }

  wwu_t uy = wwu_sub( ux, wwu_one() );
  if( FD_UNLIKELY( wwu_extract( uy, 0 )!=9U || wwu_extract( uy, 1 )!=19U || 
                   wwu_extract( uy, 2 )!=29U || wwu_extract( uy, 3 )!=39U ) ) {
    FD_LOG_ERR(( "wwu_sub failed" ));
  }

  FD_LOG_NOTICE(( "NEON tests passed" ));

  fd_halt();
  return 0;
}
