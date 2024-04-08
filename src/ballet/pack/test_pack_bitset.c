#include "../fd_ballet_base.h"
#include "fd_pack_bitset.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "FD_PACK_BITSET_MODE=%i", FD_PACK_BITSET_MODE ));

  FD_PACK_BITSET_DECLARE( x );
  FD_PACK_BITSET_CLEAR  ( x );

  FD_TEST( FD_PACK_BITSET_ISNULL( x ) );
  for( ulong i=0UL; i<FD_PACK_BITSET_MAX; i++ ) {
    FD_PACK_BITSET_SETN  ( x, i );    FD_TEST( !FD_PACK_BITSET_ISNULL( x ) );
    FD_PACK_BITSET_SETN  ( x, i );    FD_TEST( !FD_PACK_BITSET_ISNULL( x ) );
    FD_PACK_BITSET_CLEARN( x, i );    FD_TEST(  FD_PACK_BITSET_ISNULL( x ) );
    FD_PACK_BITSET_CLEARN( x, i );    FD_TEST(  FD_PACK_BITSET_ISNULL( x ) );
  }
  /* Set OOB bits, which is a no-op */
  FD_PACK_BITSET_SETN  ( x, FD_PACK_BITSET_MAX            );  FD_TEST(  FD_PACK_BITSET_ISNULL( x ) );
  FD_PACK_BITSET_SETN  ( x, FD_PACK_BITSET_SLOWPATH       );  FD_TEST(  FD_PACK_BITSET_ISNULL( x ) );
  FD_PACK_BITSET_SETN  ( x, FD_PACK_BITSET_FIRST_INSTANCE );  FD_TEST(  FD_PACK_BITSET_ISNULL( x ) );
  FD_PACK_BITSET_SETN  ( x, FD_PACK_BITSET_MAX-1UL        );  FD_TEST( !FD_PACK_BITSET_ISNULL( x ) );
  FD_PACK_BITSET_CLEARN( x, FD_PACK_BITSET_MAX            );  FD_TEST( !FD_PACK_BITSET_ISNULL( x ) );
  FD_PACK_BITSET_CLEARN( x, FD_PACK_BITSET_SLOWPATH       );  FD_TEST( !FD_PACK_BITSET_ISNULL( x ) );
  FD_PACK_BITSET_CLEARN( x, FD_PACK_BITSET_FIRST_INSTANCE );  FD_TEST( !FD_PACK_BITSET_ISNULL( x ) );


  FD_PACK_BITSET_DECLARE( y );
  FD_PACK_BITSET_CLEAR  ( y );
  FD_PACK_BITSET_CLEAR  ( x );

  for( ulong i=0UL; i<FD_PACK_BITSET_MAX; i++ ) {
    if( i&1UL ) FD_PACK_BITSET_SETN( y, i );
    for( ulong j=0UL; j<i; j+=2UL ) FD_PACK_BITSET_SETN( x, j );

    FD_PACK_BITSET_OR  ( x, y ); /* x has bits [0, i] set */
    for( ulong j=i; j>0UL; j-- ) {
      FD_PACK_BITSET_CLEARN( x, j ); FD_TEST( !FD_PACK_BITSET_ISNULL( x ) );
    }
    FD_PACK_BITSET_CLEARN( x, 0 ); FD_TEST(  FD_PACK_BITSET_ISNULL( x ) );
  }

  FD_PACK_BITSET_CLEAR  ( y );
  for( ulong i=0UL; i<FD_PACK_BITSET_MAX; i++ ) {
    FD_PACK_BITSET_SETN( y, i );
    FD_PACK_BITSET_COPY( x, y ); /* x has bits [0, i] set */
    for( ulong j=i; j>0UL; j-- ) {
      FD_PACK_BITSET_CLEARN( x, j ); FD_TEST( !FD_PACK_BITSET_ISNULL( x ) );
    }
    FD_PACK_BITSET_CLEARN( x, 0 ); FD_TEST(  FD_PACK_BITSET_ISNULL( x ) );
  }

  FD_PACK_BITSET_DECLARE( z );  FD_PACK_BITSET_CLEAR( z );
  FD_PACK_BITSET_DECLARE( w );  FD_PACK_BITSET_CLEAR( w );
  FD_PACK_BITSET_CLEAR  ( y );
  FD_PACK_BITSET_CLEAR  ( x );

  FD_TEST( FD_PACK_BITSET_INTERSECT4_EMPTY( x, y, z, w ) );
  for( ulong i=0UL; i<FD_PACK_BITSET_MAX; i++ ) {
    FD_PACK_BITSET_SETN  ( x, i );  FD_TEST(  FD_PACK_BITSET_INTERSECT4_EMPTY( x, y, z, w ) );
    FD_PACK_BITSET_SETN  ( w, i );  FD_TEST(  FD_PACK_BITSET_INTERSECT4_EMPTY( x, y, z, w ) );
    FD_PACK_BITSET_SETN  ( y, i );  FD_TEST( !FD_PACK_BITSET_INTERSECT4_EMPTY( x, y, z, w ) );
    FD_PACK_BITSET_SETN  ( z, i );  FD_TEST( !FD_PACK_BITSET_INTERSECT4_EMPTY( x, y, z, w ) );

    FD_PACK_BITSET_CLEARN( y, i );  FD_TEST( !FD_PACK_BITSET_INTERSECT4_EMPTY( x, y, z, w ) );
    FD_PACK_BITSET_CLEARN( w, i );  FD_TEST( !FD_PACK_BITSET_INTERSECT4_EMPTY( x, y, z, w ) );
    FD_PACK_BITSET_CLEARN( x, i );  FD_TEST(  FD_PACK_BITSET_INTERSECT4_EMPTY( x, y, z, w ) );
    /* Intentionally don't clear z so that it fills up */
  }

  for( ulong j=FD_PACK_BITSET_MAX; j>0UL; j-- ) {
    FD_PACK_BITSET_CLEARN( z, j ); FD_TEST( !FD_PACK_BITSET_ISNULL( z ) );
  }
  FD_PACK_BITSET_CLEARN( z, 0 ); FD_TEST(  FD_PACK_BITSET_ISNULL( z ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
