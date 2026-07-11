/* fd_gzip_pack: build-time asset compressor.
     Usage: fd_gzip_pack <level> <in> <out> */

#include <stdio.h>
#include <stdlib.h>

#include "../../third_party/zlib/zlib.h"

#define DIE(...) do { fprintf( stderr, __VA_ARGS__ ); fputc( '\n', stderr ); exit( 1 ); } while( 0 )

/* zlib is vendored with Z_SOLO (no default allocator) */
static voidpf zalloc_( voidpf o, uInt n, uInt sz ) { (void)o; return calloc( n, sz ); }
static void   zfree_ ( voidpf o, voidpf p )        { (void)o; free( p ); }

int
main( int     argc,
      char ** argv ) {
  if( argc!=4 ) DIE( "usage: %s <level> <in> <out>", argv[0] );

  int level = atoi( argv[1] );
  if( level<1 || level>9 ) DIE( "bad level %s", argv[1] );

  FILE * in  = fopen( argv[2], "rb" );  if( !in  ) DIE( "open %s failed", argv[2] );
  FILE * out = fopen( argv[3], "wb" );  if( !out ) DIE( "open %s failed", argv[3] );

  z_stream strm = { .zalloc = zalloc_, .zfree = zfree_ };
  /* windowBits 15+16: deflate with gzip framing (RFC 1952) */
  if( deflateInit2( &strm, level, Z_DEFLATED, 15+16, 9, Z_DEFAULT_STRATEGY )!=Z_OK ) DIE( "deflateInit2 failed" );

  static unsigned char ibuf[ 1<<17 ];
  static unsigned char obuf[ 1<<17 ];

  for(;;) {
    size_t rd = fread( ibuf, 1UL, sizeof(ibuf), in );
    if( ferror( in ) ) DIE( "read %s failed", argv[2] );
    int flush = feof( in ) ? Z_FINISH : Z_NO_FLUSH;

    strm.next_in  = ibuf;
    strm.avail_in = (uInt)rd;
    do {
      strm.next_out  = obuf;
      strm.avail_out = (uInt)sizeof(obuf);
      if( deflate( &strm, flush )==Z_STREAM_ERROR ) DIE( "deflate failed" );
      size_t wr = sizeof(obuf) - strm.avail_out;
      if( wr && fwrite( obuf, 1UL, wr, out )!=wr ) DIE( "write %s failed", argv[3] );
    } while( !strm.avail_out );
    if( flush==Z_FINISH ) break;
  }

  deflateEnd( &strm );
  fclose( in );
  if( fclose( out ) ) DIE( "close %s failed", argv[3] );
  return 0;
}
