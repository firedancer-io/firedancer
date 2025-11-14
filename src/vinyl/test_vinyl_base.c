#include "fd_vinyl.h"

FD_STATIC_ASSERT( FD_VINYL_SUCCESS    == 0, unit_test );
FD_STATIC_ASSERT( FD_VINYL_ERR_INVAL  ==-1, unit_test );
FD_STATIC_ASSERT( FD_VINYL_ERR_AGAIN  ==-2, unit_test );
FD_STATIC_ASSERT( FD_VINYL_ERR_CORRUPT==-3, unit_test );
FD_STATIC_ASSERT( FD_VINYL_ERR_EMPTY  ==-4, unit_test );
FD_STATIC_ASSERT( FD_VINYL_ERR_FULL   ==-5, unit_test );
FD_STATIC_ASSERT( FD_VINYL_ERR_KEY    ==-6, unit_test );

FD_STATIC_ASSERT( FD_VINYL_KEY_ALIGN    == 8UL, unit_test );
FD_STATIC_ASSERT( FD_VINYL_KEY_FOOTPRINT==32UL, unit_test );

FD_STATIC_ASSERT( FD_VINYL_KEY_ALIGN    ==alignof(fd_vinyl_key_t), unit_test );
FD_STATIC_ASSERT( FD_VINYL_KEY_FOOTPRINT==sizeof (fd_vinyl_key_t), unit_test );

FD_STATIC_ASSERT( FD_VINYL_VAL_MAX==10486200UL, unit_test );
FD_STATIC_ASSERT( FD_VINYL_INFO_SZ==16UL,       unit_test );

FD_STATIC_ASSERT( alignof(fd_vinyl_info_t)== 8UL, unit_test );
FD_STATIC_ASSERT( sizeof (fd_vinyl_info_t)==16UL, unit_test );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );

  FD_LOG_NOTICE(( "bad error code       (%i-%s)", 1,                    fd_vinyl_strerror( 1                    ) ));
  FD_LOG_NOTICE(( "FD_VINYL_SUCCESS     (%i-%s)", FD_VINYL_SUCCESS,     fd_vinyl_strerror( FD_VINYL_SUCCESS     ) ));
  FD_LOG_NOTICE(( "FD_VINYL_ERR_INVAL   (%i-%s)", FD_VINYL_ERR_INVAL,   fd_vinyl_strerror( FD_VINYL_ERR_INVAL   ) ));
  FD_LOG_NOTICE(( "FD_VINYL_ERR_AGAIN   (%i-%s)", FD_VINYL_ERR_AGAIN,   fd_vinyl_strerror( FD_VINYL_ERR_AGAIN   ) ));
  FD_LOG_NOTICE(( "FD_VINYL_ERR_CORRUPT (%i-%s)", FD_VINYL_ERR_CORRUPT, fd_vinyl_strerror( FD_VINYL_ERR_CORRUPT ) ));
  FD_LOG_NOTICE(( "FD_VINYL_ERR_EMPTY   (%i-%s)", FD_VINYL_ERR_EMPTY,   fd_vinyl_strerror( FD_VINYL_ERR_EMPTY   ) ));
  FD_LOG_NOTICE(( "FD_VINYL_ERR_FULL    (%i-%s)", FD_VINYL_ERR_FULL,    fd_vinyl_strerror( FD_VINYL_ERR_FULL    ) ));
  FD_LOG_NOTICE(( "FD_VINYL_ERR_KEY     (%i-%s)", FD_VINYL_ERR_KEY,     fd_vinyl_strerror( FD_VINYL_ERR_KEY     ) ));

  fd_rng_delete( fd_rng_leave( rng ) );

  for( ulong rem=1000000UL; rem; rem-- ) {
    ulong seed = fd_rng_ulong( rng );
    ulong limb[8]; for( ulong idx=0UL; idx<8UL; idx++ ) limb[idx] = fd_rng_ulong( rng );

    fd_vinyl_key_t ka[1]; FD_TEST( fd_vinyl_key_init_ulong( ka, limb[0], limb[1], limb[2], limb[3] )==ka );
    fd_vinyl_key_t kb[1]; FD_TEST( fd_vinyl_key_init_ulong( kb, limb[4], limb[5], limb[6], limb[7] )==kb );

    FD_TEST( ka->ul[0]==limb[0] && ka->ul[1]==limb[1] && ka->ul[2]==limb[2] && ka->ul[3]==limb[3] &&
             kb->ul[0]==limb[4] && kb->ul[1]==limb[5] && kb->ul[2]==limb[6] && kb->ul[3]==limb[7] );

    int eq = (ka->ul[0]==kb->ul[0]) && (ka->ul[1]==kb->ul[1]) &&
             (ka->ul[2]==kb->ul[2]) && (ka->ul[3]==kb->ul[3]);

    ulong ma = fd_vinyl_key_memo( seed, ka );
    ulong mb = fd_vinyl_key_memo( seed, kb );

    FD_TEST( fd_vinyl_key_eq( ka, ka )== 1 ); FD_TEST( fd_vinyl_key_eq( ka, kb )==eq );
    FD_TEST( fd_vinyl_key_eq( kb, ka )==eq ); FD_TEST( fd_vinyl_key_eq( kb, kb )== 1 );

    if( eq ) FD_TEST( ma==mb );

    /* zero padding copy */

    ulong csz = seed % FD_VINYL_KEY_FOOTPRINT;

    FD_TEST( fd_vinyl_key_init( kb, ka, csz )==kb );

    eq = (ka->ul[0]==kb->ul[0]) && (ka->ul[1]==kb->ul[1]) &&
         (ka->ul[2]==kb->ul[2]) && (ka->ul[3]==kb->ul[3]);

    mb = fd_vinyl_key_memo( seed, kb );

    for( ulong idx=csz; idx<FD_VINYL_KEY_FOOTPRINT; idx++ ) FD_TEST( !kb->c[idx] );

    FD_TEST( fd_vinyl_key_eq( ka, ka )== 1 ); FD_TEST( fd_vinyl_key_eq( ka, kb )==eq );
    FD_TEST( fd_vinyl_key_eq( kb, ka )==eq ); FD_TEST( fd_vinyl_key_eq( kb, kb )== 1 );
    if( eq ) FD_TEST( ma==mb );

    /* normal copy and truncating copy */

    csz += FD_VINYL_KEY_FOOTPRINT;

    FD_TEST( fd_vinyl_key_init( kb, ka, csz )==kb );

    eq = 1;
    mb = fd_vinyl_key_memo( seed, kb );

    FD_TEST( fd_vinyl_key_eq( ka, ka )== 1 ); FD_TEST( fd_vinyl_key_eq( ka, kb )==eq );
    FD_TEST( fd_vinyl_key_eq( kb, ka )==eq ); FD_TEST( fd_vinyl_key_eq( kb, kb )== 1 );
    if( eq ) FD_TEST( ma==mb );
  }

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
