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

  /* Test dcache procurement */

  FD_TEST( fd_dcache_align()==FD_DCACHE_ALIGN );

  /* FIXME: MORE fd_cache_footprint and fd_cache_req_data_sz TESTS */
  for( ulong iter=0UL; iter<1000000UL; iter++ ) {
    ulong _data_sz = fd_rng_ulong_roll( rng, DATA_MAX+1UL ); /* In [0,DATA_MAX] */
    ulong  _app_sz = fd_rng_ulong_roll( rng,  APP_MAX+1UL ); /* In [0, APP_MAX] */
    FD_TEST( fd_dcache_footprint( _data_sz, _app_sz )==FD_DCACHE_FOOTPRINT( _data_sz, _app_sz ) );

    uint r = fd_rng_uint( rng );
    ulong mtu     = (ulong)(r & 63U); r >>= 6;
    ulong depth   = (ulong)(r & 63U); r >>= 6;
    ulong burst   = (ulong)(r & 63U); r >>= 6;
    int   compact = (int)  (r &  1U); r >>= 1;
    FD_TEST( fd_dcache_req_data_sz( mtu, depth, burst, compact )
             ==fd_ulong_if( (!!mtu) & (!!depth) & (!!burst), FD_DCACHE_REQ_DATA_SZ( mtu, depth, burst, compact ), 0UL ) );
  }

  /* Test dcache creation */

  ulong footprint = fd_dcache_footprint( data_sz, app_sz );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "Bad --data-sz or --app-sz" ));
  FD_TEST( footprint==FD_DCACHE_FOOTPRINT( data_sz,  app_sz  ) );
  FD_TEST( footprint<=FD_DCACHE_FOOTPRINT( DATA_MAX, APP_MAX ) );

  /* Test failure cases for fd_dcache_new */
  FD_TEST( fd_dcache_new( NULL,      data_sz, app_sz )==NULL ); /* null        */
  FD_TEST( fd_dcache_new( shmem+1UL, data_sz, app_sz )==NULL ); /* misaligned  */
  FD_TEST( fd_dcache_new( shmem,     ~0x0UL,  app_sz )==NULL ); /* bad data_sz */
  FD_TEST( fd_dcache_new( shmem,     data_sz, ~0x0UL )==NULL ); /* bad app_sz  */

  void *  shdcache = fd_dcache_new( shmem, data_sz, app_sz ); FD_TEST( shdcache );

  /* Test failure cases for fd_dcache_join */
  FD_TEST( fd_dcache_join( NULL          )==NULL ); /* null */
  FD_TEST( fd_dcache_join( (void *)0x1UL )==NULL ); /* misaligned */

  uchar * dcache   = fd_dcache_join( shdcache );              FD_TEST( dcache );
  FD_TEST( fd_ulong_is_aligned( (ulong)dcache, FD_DCACHE_ALIGN ) );

  /* Test the accessors */

  FD_TEST( fd_dcache_data_sz( dcache )==data_sz );
  FD_TEST( fd_dcache_app_sz ( dcache )== app_sz );

  uchar const * _app_const = fd_dcache_app_laddr_const( dcache ); FD_TEST( _app_const );
  uchar *       _app       = fd_dcache_app_laddr      ( dcache ); FD_TEST( _app );
  FD_TEST( (ulong)_app==(ulong)_app_const );
  FD_TEST( fd_ulong_is_aligned( (ulong)_app, FD_DCACHE_ALIGN ) );

  /* Test the regions were initialized correctly and fill them with
     a test pattern */

  uchar * p;
  p = dcache - FD_DCACHE_GUARD_FOOTPRINT;
  for( ulong rem=FD_DCACHE_GUARD_FOOTPRINT; rem; rem-- ) { FD_TEST( !*p ); *p = (uchar)'g'; p++; }
  p = dcache;
  for( ulong rem=data_sz; rem; rem-- ) { FD_TEST( !*p ); *p = (uchar)'d'; p++; }
  p = _app;
  for( ulong rem=app_sz; rem; rem-- ) { FD_TEST( !*p ); *p = (uchar)'a'; p++; }

  /* Test that filling the dcache didn't corrupt it and that the
     test pattern was written as expected. */

  FD_TEST( fd_dcache_data_sz        ( dcache )==data_sz    );
  FD_TEST( fd_dcache_app_sz         ( dcache )== app_sz    );
  FD_TEST( fd_dcache_app_laddr_const( dcache )==_app_const );
  FD_TEST( fd_dcache_app_laddr      ( dcache )==_app       );

  uchar const * q;
  q = dcache - FD_DCACHE_GUARD_FOOTPRINT;
  for( ulong rem=FD_DCACHE_GUARD_FOOTPRINT; rem; rem-- ) { FD_TEST( (*q)==(uchar)'g' ); q++; }
  q = dcache;
  for( ulong rem=data_sz; rem; rem-- ) { FD_TEST( (*q)==(uchar)'d' ); q++; }
  q = _app_const;
  for( ulong rem=app_sz; rem; rem-- ) { FD_TEST( (*q)==(uchar)'a' ); q++; }

  ulong mtu   = 256UL;
  ulong depth =   2UL;
  if( FD_LIKELY( data_sz >= fd_dcache_req_data_sz( mtu, depth, 1UL /*burst*/, 1 /*compact*/ ) ) ) {
    uchar const * ref = dcache;
    ulong chunk_mtu = fd_ulong_align_up( mtu, 2UL*FD_CHUNK_SZ ) >> FD_CHUNK_LG_SZ;

    /* Test failure cases for fd_dcache_compact_is_safe */
    FD_TEST( fd_dcache_compact_is_safe( ref+1UL, dcache,     mtu,  depth )==0 ); /* misaligned base    */
    FD_TEST( fd_dcache_compact_is_safe( NULL,    NULL,       mtu,  depth )==0 ); /* null               */
    FD_TEST( fd_dcache_compact_is_safe( ref,     ref-128UL,  mtu,  depth )==0 ); /* dcache before base */
    FD_TEST( fd_dcache_compact_is_safe( NULL,    dcache+1UL, mtu,  depth )==0 ); /* misaligned dcache  */
    FD_TEST( fd_dcache_compact_is_safe( ref,     dcache,     0UL,  depth )==0 ); /* zero mtu           */
    FD_TEST( fd_dcache_compact_is_safe( ref,     dcache,     ~0UL, depth )==0 ); /* oversz mtu         */
    FD_TEST( fd_dcache_compact_is_safe( ref,     dcache,     mtu,  0UL   )==0 ); /* zero depth         */

    FD_TEST( fd_dcache_compact_is_safe( ref, dcache, mtu, depth ) );
    ulong chunk0 = fd_dcache_compact_chunk0( ref, dcache );      FD_TEST( chunk0==0UL );
    ulong chunk1 = fd_dcache_compact_chunk1( ref, dcache );      FD_TEST( chunk1==(data_sz>>FD_CHUNK_LG_SZ) );
    ulong wmark  = fd_dcache_compact_wmark ( ref, dcache, mtu ); FD_TEST( wmark ==chunk1-chunk_mtu );

    ulong delta = fd_ulong_max( footprint, 1UL<<(31+FD_CHUNK_LG_SZ) ) - footprint;
    ref = (uchar const *)((ulong)shdcache - fd_ulong_min( (ulong)shdcache, delta ));

    FD_TEST( fd_dcache_compact_is_safe( ref, dcache, mtu, depth ) );
    chunk0 = fd_dcache_compact_chunk0( ref, dcache );      FD_TEST( chunk0==(((ulong)(dcache-ref))>>FD_CHUNK_LG_SZ) );
    chunk1 = fd_dcache_compact_chunk1( ref, dcache );      FD_TEST( chunk1==chunk0+(data_sz>>FD_CHUNK_LG_SZ)        );
    wmark  = fd_dcache_compact_wmark ( ref, dcache, mtu ); FD_TEST( wmark ==chunk1-chunk_mtu                        );

    /* Clang seems to put the global variables in a far away memory
       region such that using NULL is not a usable base.  So we only run
       these tests if it is safe. */

    if( FD_LIKELY( fd_dcache_compact_is_safe( NULL, dcache, mtu, depth ) ) ) {
      chunk0 = fd_dcache_compact_chunk0( NULL, dcache );      FD_TEST( chunk0==(((ulong)dcache)>>FD_CHUNK_LG_SZ) );
      chunk1 = fd_dcache_compact_chunk1( NULL, dcache );      FD_TEST( chunk1==chunk0+(data_sz>>FD_CHUNK_LG_SZ)  );
      wmark  = fd_dcache_compact_wmark ( NULL, dcache, mtu ); FD_TEST( wmark ==chunk1-chunk_mtu                  );
    }

    for( ulong iter=0UL; iter<100000UL; iter++ ) {
      ulong chunk = chunk0 + fd_rng_ulong_roll( rng, wmark-chunk0+1UL ); /* In [chunk0,wmark] */
      ulong sz    = fd_rng_ulong_roll( rng, mtu+1UL );                   /* In [0,mtu] */
      ulong next  = fd_dcache_compact_next( chunk, sz, chunk0, wmark );
      FD_TEST( chunk0<=next ); FD_TEST( next<=wmark );
      ulong fp    = fd_ulong_align_up( sz, 2UL*FD_CHUNK_SZ ) >> FD_CHUNK_LG_SZ;
      FD_TEST( next==fd_ulong_if( (chunk+fp)>wmark, chunk0, chunk+fp ) );
    }
  }

  /* Test mcache destruction */

  FD_TEST( fd_dcache_leave( NULL   )==NULL     ); /* null dcache */
  FD_TEST( fd_dcache_leave( dcache )==shdcache ); /* ok */

  FD_TEST( fd_dcache_delete( NULL                    )==NULL  ); /* null dcache */
  FD_TEST( fd_dcache_delete( ((uchar *)shdcache)+1UL )==NULL  ); /* misaligned  */
  FD_TEST( fd_dcache_delete( shdcache                )==shmem ); /* ok */

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

