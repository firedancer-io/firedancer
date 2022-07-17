#include "../fd_tango.h"

FD_STATIC_ASSERT( FD_CHUNK_ALIGN    ==64UL, unit_test );
FD_STATIC_ASSERT( FD_CHUNK_FOOTPRINT==64UL, unit_test );
FD_STATIC_ASSERT( FD_CHUNK_SZ       ==64UL, unit_test );

FD_STATIC_ASSERT( FD_DCACHE_ALIGN                 ==128UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_FOOTPRINT(  0UL,  0UL)==256UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_FOOTPRINT(  0UL,  1UL)==384UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_FOOTPRINT(  0UL,128UL)==384UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_FOOTPRINT(  0UL,129UL)==512UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_FOOTPRINT(  1UL,  0UL)==384UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_FOOTPRINT(  1UL,  1UL)==512UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_FOOTPRINT(  1UL,128UL)==512UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_FOOTPRINT(  1UL,129UL)==640UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_FOOTPRINT(128UL,  0UL)==384UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_FOOTPRINT(128UL,  1UL)==512UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_FOOTPRINT(128UL,128UL)==512UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_FOOTPRINT(128UL,129UL)==640UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_FOOTPRINT(129UL,  0UL)==512UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_FOOTPRINT(129UL,  1UL)==640UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_FOOTPRINT(129UL,128UL)==640UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_FOOTPRINT(129UL,129UL)==768UL, unit_test );

FD_STATIC_ASSERT( FD_DCACHE_GUARD_FOOTPRINT==128UL, unit_test );

FD_STATIC_ASSERT( FD_DCACHE_SLOT_FOOTPRINT(      0UL)==  0UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_SLOT_FOOTPRINT(      1UL)==128UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_SLOT_FOOTPRINT(    128UL)==128UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_SLOT_FOOTPRINT(    129UL)==256UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_SLOT_FOOTPRINT(ULONG_MAX)==  0UL, unit_test );

FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(  1UL,1UL,1UL,0)== 256UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(128UL,1UL,1UL,0)== 256UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(129UL,1UL,1UL,0)== 512UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(  1UL,2UL,1UL,0)== 384UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(128UL,2UL,1UL,0)== 384UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(129UL,2UL,1UL,0)== 768UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(  1UL,1UL,2UL,0)== 384UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(128UL,1UL,2UL,0)== 384UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(129UL,1UL,2UL,0)== 768UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(  1UL,2UL,2UL,0)== 512UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(128UL,2UL,2UL,0)== 512UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(129UL,2UL,2UL,0)==1024UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(  1UL,1UL,1UL,1)== 384UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(128UL,1UL,1UL,1)== 384UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(129UL,1UL,1UL,1)== 768UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(  1UL,2UL,1UL,1)== 512UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(128UL,2UL,1UL,1)== 512UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(129UL,2UL,1UL,1)==1024UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(  1UL,1UL,2UL,1)== 512UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(128UL,1UL,2UL,1)== 512UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(129UL,1UL,2UL,1)==1024UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(  1UL,2UL,2UL,1)== 640UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(128UL,2UL,2UL,1)== 640UL, unit_test );
FD_STATIC_ASSERT( FD_DCACHE_REQ_DATA_SZ(129UL,2UL,2UL,1)==1280UL, unit_test );

#define DATA_MAX (28416UL)
#define APP_MAX  (4096UL)

static ulong __attribute__((aligned(FD_DCACHE_ALIGN))) shmem[ FD_DCACHE_FOOTPRINT( DATA_MAX, APP_MAX ) ];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong data_sz = fd_env_strip_cmdline_ulong( &argc, &argv, "--data-sz", NULL, DATA_MAX );
  ulong  app_sz = fd_env_strip_cmdline_ulong( &argc, &argv,  "--app-sz", NULL,  APP_MAX );

  if( FD_UNLIKELY( data_sz>DATA_MAX ) ) FD_LOG_ERR(( "Increase unit test DATA_MAX to support this large --data-sz" ));
  if( FD_UNLIKELY(  app_sz> APP_MAX ) ) FD_LOG_ERR(( "Increase unit test APP_MAX to support this large --app-sz" ));

  FD_LOG_NOTICE(( "Testing with --data-sz %lu and --app-sz %lu", data_sz, app_sz ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

# define TEST(c) do if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: " #c )); return 1; } while(0)

  /* Test dcache procurement */

  TEST( fd_dcache_align()==FD_DCACHE_ALIGN );

  /* FIXME: MORE fd_cache_footprint and fd_cache_req_data_sz TESTS */
  for( ulong iter=0UL; iter<1000000UL; iter++ ) {
    ulong _data_sz = fd_rng_ulong_roll( rng, DATA_MAX+1UL ); /* In [0,DATA_MAX] */
    ulong  _app_sz = fd_rng_ulong_roll( rng,  APP_MAX+1UL ); /* In [0, APP_MAX] */
    TEST( fd_dcache_footprint( _data_sz, _app_sz )==FD_DCACHE_FOOTPRINT( _data_sz, _app_sz ) );

    uint r = fd_rng_uint( rng );
    ulong mtu     = (ulong)(r & 63U); r >>= 6;
    ulong depth   = (ulong)(r & 63U); r >>= 6;
    ulong burst   = (ulong)(r & 63U); r >>= 6;
    int   compact = (int)  (r &  1U); r >>= 1;
    TEST( fd_dcache_req_data_sz( mtu, depth, burst, compact )
          ==fd_ulong_if( (!!mtu) & (!!depth) & (!!burst), FD_DCACHE_REQ_DATA_SZ( mtu, depth, burst, compact ), 0UL ) );
  }

  /* Test dcache creation */

  ulong footprint = fd_dcache_footprint( data_sz, app_sz );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "Bad --data-sz or --app-sz" ));
  TEST( footprint==FD_DCACHE_FOOTPRINT( data_sz,  app_sz  ) );
  TEST( footprint<=FD_DCACHE_FOOTPRINT( DATA_MAX, APP_MAX ) );

  void *  shdcache = fd_dcache_new( shmem, data_sz, app_sz ); TEST( shdcache );
  uchar * dcache   = fd_dcache_join( shdcache );              TEST( dcache );
  TEST( fd_ulong_is_aligned( (ulong)dcache, FD_DCACHE_ALIGN ) );

  /* Test the accessors */

  TEST( fd_dcache_data_sz( dcache )==data_sz );
  TEST( fd_dcache_app_sz ( dcache )== app_sz );

  uchar const * _app_const = fd_dcache_app_laddr_const( dcache ); TEST( _app_const );
  uchar *       _app       = fd_dcache_app_laddr      ( dcache ); TEST( _app );
  TEST( (ulong)_app==(ulong)_app_const );
  TEST( fd_ulong_is_aligned( (ulong)_app, FD_DCACHE_ALIGN ) );

  /* Test the regions were initialized correctly and fill them with
     a test pattern */

  uchar * p;
  p = dcache - FD_DCACHE_GUARD_FOOTPRINT;
  for( ulong rem=FD_DCACHE_GUARD_FOOTPRINT; rem; rem-- ) { TEST( !*p ); *p = (uchar)'g'; p++; }
  p = dcache;
  for( ulong rem=data_sz; rem; rem-- ) { TEST( !*p ); *p = (uchar)'d'; p++; }
  p = _app;
  for( ulong rem=app_sz; rem; rem-- ) { TEST( !*p ); *p = (uchar)'a'; p++; }

  /* Test that filling the dcache didn't corrupt it and that the
     test pattern was written as expected. */

  TEST( fd_dcache_data_sz        ( dcache )==data_sz    );
  TEST( fd_dcache_app_sz         ( dcache )== app_sz    );
  TEST( fd_dcache_app_laddr_const( dcache )==_app_const );
  TEST( fd_dcache_app_laddr      ( dcache )==_app       );

  uchar const * q;
  q = dcache - FD_DCACHE_GUARD_FOOTPRINT;
  for( ulong rem=FD_DCACHE_GUARD_FOOTPRINT; rem; rem-- ) { TEST( (*q)==(uchar)'g' ); q++; }
  q = dcache;
  for( ulong rem=data_sz; rem; rem-- ) { TEST( (*q)==(uchar)'d' ); q++; }
  q = _app_const;
  for( ulong rem=app_sz; rem; rem-- ) { TEST( (*q)==(uchar)'a' ); q++; }

  /* Test mcache destruction */

  TEST( fd_dcache_leave ( dcache   )==shdcache );
  TEST( fd_dcache_delete( shdcache )==shmem    );

# undef TEST

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

