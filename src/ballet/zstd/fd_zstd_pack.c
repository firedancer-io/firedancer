/* fd_zstd_pack: build-time asset compressor.
     Usage: fd_zstd_pack <level> <in> <out> */

#include <stdio.h>
#include <stdlib.h>

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#define DIE(...) do { fprintf( stderr, __VA_ARGS__ ); fputc( '\n', stderr ); exit( 1 ); } while( 0 )

int
main( int     argc,
      char ** argv ) {
  if( argc!=4 ) DIE( "usage: %s <level> <in> <out>", argv[0] );

  int level = atoi( argv[1] );
  if( level<ZSTD_minCLevel() || level>ZSTD_maxCLevel() ) DIE( "bad level %s", argv[1] );

  FILE * in  = fopen( argv[2], "rb" );  if( !in  ) DIE( "open %s failed", argv[2] );
  FILE * out = fopen( argv[3], "wb" );  if( !out ) DIE( "open %s failed", argv[3] );

  ZSTD_CCtx * cctx = ZSTD_createCCtx();
  if( !cctx ) DIE( "ZSTD_createCCtx failed" );
  ZSTD_CCtx_setParameter( cctx, ZSTD_c_compressionLevel, level );

  static unsigned char ibuf[ 1<<17 ];
  static unsigned char obuf[ 1<<17 ];

  for(;;) {
    size_t rd = fread( ibuf, 1UL, sizeof(ibuf), in );
    if( ferror( in ) ) DIE( "read %s failed", argv[2] );
    int last = feof( in );

    ZSTD_inBuffer src = { ibuf, rd, 0UL };
    for(;;) {
      ZSTD_outBuffer dst = { obuf, sizeof(obuf), 0UL };
      size_t ret = ZSTD_compressStream2( cctx, &dst, &src, last ? ZSTD_e_end : ZSTD_e_continue );
      if( ZSTD_isError( ret ) ) DIE( "compress failed: %s", ZSTD_getErrorName( ret ) );
      if( dst.pos && fwrite( obuf, 1UL, dst.pos, out )!=dst.pos ) DIE( "write %s failed", argv[3] );
      if( last ? !ret : src.pos==src.size ) break;
    }
    if( last ) break;
  }

  ZSTD_freeCCtx( cctx );
  fclose( in );
  if( fclose( out ) ) DIE( "close %s failed", argv[3] );
  return 0;
}
