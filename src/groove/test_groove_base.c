#include "fd_groove.h"

FD_STATIC_ASSERT( FD_GROOVE_SUCCESS    == 0, unit_test );
FD_STATIC_ASSERT( FD_GROOVE_ERR_INVAL  ==-1, unit_test );
FD_STATIC_ASSERT( FD_GROOVE_ERR_AGAIN  ==-2, unit_test );
FD_STATIC_ASSERT( FD_GROOVE_ERR_CORRUPT==-3, unit_test );
FD_STATIC_ASSERT( FD_GROOVE_ERR_EMPTY  ==-4, unit_test );
FD_STATIC_ASSERT( FD_GROOVE_ERR_FULL   ==-5, unit_test );
FD_STATIC_ASSERT( FD_GROOVE_ERR_KEY    ==-6, unit_test );

FD_STATIC_ASSERT( FD_GROOVE_KEY_ALIGN    == 8UL, unit_test );
FD_STATIC_ASSERT( FD_GROOVE_KEY_FOOTPRINT==32UL, unit_test );

FD_STATIC_ASSERT( FD_GROOVE_KEY_ALIGN    ==alignof(fd_groove_key_t), unit_test );
FD_STATIC_ASSERT( FD_GROOVE_KEY_FOOTPRINT==sizeof (fd_groove_key_t), unit_test );

FD_STATIC_ASSERT( FD_GROOVE_BLOCK_ALIGN    ==512UL, unit_test );
FD_STATIC_ASSERT( FD_GROOVE_BLOCK_FOOTPRINT==512UL, unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );

  FD_LOG_NOTICE(( "bad error code        (%i-%s)", 1,                     fd_groove_strerror( 1                     ) ));
  FD_LOG_NOTICE(( "FD_GROOVE_SUCCESS     (%i-%s)", FD_GROOVE_SUCCESS,     fd_groove_strerror( FD_GROOVE_SUCCESS     ) ));
  FD_LOG_NOTICE(( "FD_GROOVE_ERR_INVAL   (%i-%s)", FD_GROOVE_ERR_INVAL,   fd_groove_strerror( FD_GROOVE_ERR_INVAL   ) ));
  FD_LOG_NOTICE(( "FD_GROOVE_ERR_AGAIN   (%i-%s)", FD_GROOVE_ERR_AGAIN,   fd_groove_strerror( FD_GROOVE_ERR_AGAIN   ) ));
  FD_LOG_NOTICE(( "FD_GROOVE_ERR_CORRUPT (%i-%s)", FD_GROOVE_ERR_CORRUPT, fd_groove_strerror( FD_GROOVE_ERR_CORRUPT ) ));
  FD_LOG_NOTICE(( "FD_GROOVE_ERR_EMPTY   (%i-%s)", FD_GROOVE_ERR_EMPTY,   fd_groove_strerror( FD_GROOVE_ERR_EMPTY   ) ));
  FD_LOG_NOTICE(( "FD_GROOVE_ERR_FULL    (%i-%s)", FD_GROOVE_ERR_FULL,    fd_groove_strerror( FD_GROOVE_ERR_FULL    ) ));
  FD_LOG_NOTICE(( "FD_GROOVE_ERR_KEY     (%i-%s)", FD_GROOVE_ERR_KEY,     fd_groove_strerror( FD_GROOVE_ERR_KEY     ) ));

  for( ulong rem=1000000UL; rem; rem-- ) {
    ulong seed = fd_rng_ulong( rng );
    ulong limb[8]; for( ulong idx=0UL; idx<8UL; idx++ ) limb[idx] = fd_rng_ulong( rng );

    fd_groove_key_t ka[1]; FD_TEST( fd_groove_key_init_ulong( ka, limb[0], limb[1], limb[2], limb[3] )==ka );
    fd_groove_key_t kb[1]; FD_TEST( fd_groove_key_init_ulong( kb, limb[4], limb[5], limb[6], limb[7] )==kb );

    FD_TEST( ka->ul[0]==limb[0] && ka->ul[1]==limb[1] && ka->ul[2]==limb[2] && ka->ul[3]==limb[3] &&
             kb->ul[0]==limb[4] && kb->ul[1]==limb[5] && kb->ul[2]==limb[6] && kb->ul[3]==limb[7] );

    int   eq = (ka->ul[0]==kb->ul[0]) && (ka->ul[1]==kb->ul[1]) && (ka->ul[2]==kb->ul[2]) && (ka->ul[3]==kb->ul[3]);
    ulong ma = fd_groove_key_hash( ka, seed );
    ulong mb = fd_groove_key_hash( kb, seed );

    FD_TEST( fd_groove_key_eq( ka, ka )== 1 ); FD_TEST( fd_groove_key_eq( ka, kb )==eq );
    FD_TEST( fd_groove_key_eq( kb, ka )==eq ); FD_TEST( fd_groove_key_eq( kb, kb )== 1 );
    if( eq ) FD_TEST( ma==mb );

    /* zero padding copy */

    ulong csz = seed % FD_GROOVE_KEY_FOOTPRINT;

    FD_TEST( fd_groove_key_init( kb, ka, csz )==kb );

    eq = (ka->ul[0]==kb->ul[0]) && (ka->ul[1]==kb->ul[1]) && (ka->ul[2]==kb->ul[2]) && (ka->ul[3]==kb->ul[3]);
    mb = fd_groove_key_hash( kb, seed );

    for( ulong idx=csz; idx<FD_GROOVE_KEY_FOOTPRINT; idx++ ) FD_TEST( !kb->c[idx] );

    FD_TEST( fd_groove_key_eq( ka, ka )== 1 ); FD_TEST( fd_groove_key_eq( ka, kb )==eq );
    FD_TEST( fd_groove_key_eq( kb, ka )==eq ); FD_TEST( fd_groove_key_eq( kb, kb )== 1 );
    if( eq ) FD_TEST( ma==mb );

    /* normal copy and truncating copy */

    csz += FD_GROOVE_KEY_FOOTPRINT;

    FD_TEST( fd_groove_key_init( kb, ka, csz )==kb );

    eq = 1;
    mb = fd_groove_key_hash( kb, seed );

    FD_TEST( fd_groove_key_eq( ka, ka )== 1 ); FD_TEST( fd_groove_key_eq( ka, kb )==eq );
    FD_TEST( fd_groove_key_eq( kb, ka )==eq ); FD_TEST( fd_groove_key_eq( kb, kb )== 1 );
    if( eq ) FD_TEST( ma==mb );
  }

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
