#include "fd_libc_zstd.h"
#include "../../util/fd_util.h"
#include <stdlib.h>
#include <zstd.h>

/* pattern_fill produces bursts of repeating patterns. */

static void
pattern_fill( uchar *    buf,
              ulong      sz,
              fd_rng_t * rng ) {
  for( ulong off=0UL; off<sz; ) {
    ulong burst_sz = 1UL + fd_rng_uint_roll( rng, (uint)fd_ulong_min( sz-off, 256UL ) );
    uchar pattern  = (uchar)fd_rng_uint_roll( rng, 256U );
    fd_memset( buf+off, pattern, burst_sz );
    off += burst_sz;
  }
}

static void
test_rstream_empty( void ) {
  /* fmemopen returns NULL when passing sz==0UL, work aroung glibc bug. */
  FILE * c_file = fmemopen( NULL, 1UL, "wb+" ); FD_TEST( c_file );
  FD_TEST( fseek( c_file, 0L, SEEK_END )==0L );
  ZSTD_DStream * dstream = ZSTD_createDStream();
  FILE * p_file = fd_zstd_rstream_open( c_file, dstream ); FD_TEST( p_file );
  FD_TEST( ftell( p_file )==0L );
  FD_TEST( fread( NULL, 1, 1, p_file )==0UL );
  FD_TEST( feof( p_file )==1 );
  FD_TEST( ftell( p_file )==0L );
  FD_TEST( fclose( p_file )==0 );
  ZSTD_freeDStream( dstream );
}

static void
test_rstream_simple( void ) {
  fd_rng_t rng_[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_, 0UL, 0UL ) );
  ulong iter = 10000UL;
  ulong rem  = iter;
  while( rem-- ) {
    uchar   p [ 65536 ];
    uchar   p2[ 65536 ];
    ulong   c_max     = ZSTD_compressBound( sizeof(p) );
    uchar * c         = malloc( c_max ); FD_TEST( c );
    ulong   p_sz      = fd_rng_uint_roll( rng, (uint)sizeof(p) );
    pattern_fill( p, p_sz, rng );
    ulong   c_sz      = ZSTD_compress( c, c_max, p, p_sz, 1 );
    FD_TEST( !ZSTD_isError( c_sz ) );

    FILE *         c_file  = fmemopen( c, c_sz, "rb" ); FD_TEST( c_file );
    ZSTD_DStream * dstream = ZSTD_createDStream();
    FILE *         p_file  = fd_zstd_rstream_open( c_file, dstream ); FD_TEST( p_file );

    FD_TEST( ftell( p_file )==0L );
    ulong rd_off;
    for( rd_off=0uL; rd_off<p_sz; ) {
      ulong p2_rem = p_sz - rd_off;
      ulong rd_sz  = fd_rng_uint_roll( rng, (uint)(p2_rem+1UL) );
      ulong rd_cnt = fread( p2+rd_off, 1, rd_sz, p_file );
      FD_TEST( rd_cnt<=rd_sz );
      rd_off += rd_cnt;
      FD_TEST( ftell( p_file )==(long)rd_off );
      if( feof( p_file ) ) break;
    }
    FD_TEST( rd_off==p_sz );
    FD_TEST( ferror( p_file )==0 );
    if( !feof( p_file ) ) {
      uchar dummy[1];
      FD_TEST( fread( dummy, 1UL, 1UL, p_file )==0UL );
    }
    FD_TEST( feof( p_file )==1 );
    FD_TEST( fd_memeq( p, p2, p_sz ) );

    FD_TEST( fclose( p_file )==0 );
    ZSTD_freeDStream( dstream );
    free( c );
  }
  fd_rng_delete( fd_rng_leave( rng ) );
}

static void
test_rstream_multi_frame( void ) {
  ulong   c_max = 2*ZSTD_compressBound( 5UL );
  uchar * c     = malloc( c_max ); FD_TEST( c );
  ulong   c_sz  = 0UL;

  ulong c_csz = ZSTD_compress( c+c_sz, c_max-c_sz, "hello", 5UL, 3 );
  FD_TEST( !ZSTD_isError( c_csz ) );
  c_sz += c_csz;
  FD_TEST( c_max-c_sz>=c_csz );
  fd_memcpy( c+c_sz, c, c_csz );
  c_sz += c_csz;

  FILE *         c_file  = fmemopen( c, c_sz, "rb" ); FD_TEST( c_file );
  ZSTD_DStream * dstream = ZSTD_createDStream();
  FILE *         p_file  = fd_zstd_rstream_open( c_file, dstream ); FD_TEST( p_file );

  uchar p[ 11 ];
  ulong rd_off;
  for( rd_off=0uL; rd_off<sizeof(p); ) {
    FD_TEST( ftell( p_file )==(long)rd_off );
    ulong rd_sz = fread( p+rd_off, 1, sizeof(p)-rd_off, p_file );
    rd_off += rd_sz;
    if( feof( p_file ) ) break;
  }
  FD_TEST( ferror( p_file )==0 );
  FD_TEST( rd_off==10UL );
  fd_memeq( p, "hellohello", 10UL );
  FD_TEST( fclose( p_file )==0 );
  ZSTD_freeDStream( dstream );
  free( c );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_rstream_empty();
  test_rstream_simple();
  test_rstream_multi_frame();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
