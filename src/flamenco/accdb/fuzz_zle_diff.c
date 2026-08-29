#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include "fd_zle.h"
#include "../../util/fd_util.h"
#include "../../util/sanitize/fd_fuzz.h"

#include <stdlib.h>

/* fuzz_zle_diff differentially fuzzes fd_zle_compress against a scalar
   transcription of the wire format.  The fuzzer input is the data to
   compress. */

#define MAX_SZ (1UL<<20)

/* fd_zle reference implementation */

static ulong
ref_vput( uchar * p,
          ulong   v ) {
  ulong k = 0UL;
  do {
    p[k] = (uchar)( v & 0x7fUL );
    v >>= 7;
    if( v ) p[k] = (uchar)( p[k] | 0x80 );
    k++;
  } while( v );
  return k;
}

static ulong
ref_ext( ulong v ) {
  if( v<15UL ) return 0UL;
  v -= 15UL;
  ulong k = 1UL;
  while( v>=128UL ) { v >>= 7; k++; }
  return k;
}

static uchar *
ref_emit( uchar *       o,
          uchar const * lit,
          ulong         L,
          ulong         Z ) {
  ulong ln = L<15UL ? L : 15UL;
  ulong zn = Z<15UL ? Z : 15UL;
  *o++ = (uchar)( (ln<<4) | zn );
  if( L>=15UL ) o += ref_vput( o, L-15UL );
  if( L ) memcpy( o, lit, L );
  o += L;
  if( Z>=15UL ) o += ref_vput( o, Z-15UL );
  return o;
}

static ulong
ref_compress( uchar *       dst,
              uchar const * src,
              ulong         n ) {
  if( !n ) return 0UL;
  ulong   esc_sz = 1UL + ref_ext( n ) + n;
  uchar * o      = dst;
  ulong   pos    = 0UL;
  ulong   fs     = 0UL;
  while( pos<n ) {
    ulong zs = pos;
    while( (zs<n) &&  src[zs] ) zs++;
    if( zs==n ) break;
    ulong ze = zs;
    while( (ze<n) && !src[ze] ) ze++;
    if( ze-zs>=2UL ) {
      ulong L = zs-fs;
      ulong Z = ze-zs;
      if( (ulong)( o-dst )+1UL+ref_ext( L )+L+ref_ext( Z )>=esc_sz ) goto escape;
      o  = ref_emit( o, src+fs, L, Z );
      fs = ze;
    }
    pos = ze;
  }
  if( fs<n ) {
    ulong L = n-fs;
    if( (ulong)( o-dst )+1UL+ref_ext( L )+L>=esc_sz ) goto escape;
    o = ref_emit( o, src+fs, L, 0UL );
  }
  return (ulong)( o-dst );
escape:
  return (ulong)( ref_emit( dst, src, n, 0UL )-dst );
}

static uchar ref[ FD_ZLE_COMPRESS_BOUND( MAX_SZ ) ];
static uchar out[ MAX_SZ ];

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  putenv( "FD_LOG_BACKTRACE=0" );
  setenv( "FD_LOG_PATH", "", 0 );
  fd_boot( argc, argv );
  atexit( fd_halt );
  fd_log_level_core_set( 3 ); /* crash on warning log */
  return 0;
}

static void
check_at( uchar const * data,
          ulong         sz,
          ulong         off ) {

  ulong   span = off + fd_ulong_align_up( fd_ulong_max( sz, 1UL ), 64UL );
  uchar * buf  = aligned_alloc( 64UL, fd_ulong_align_up( span, 64UL ) );
  FD_TEST( buf );
  uchar * src = buf+off;
  memcpy( src, data, sz );
  memset( src+sz, 0xff, span-off-sz );   /* pad must not affect the output */

  ulong   bound = FD_ZLE_COMPRESS_BOUND( sz );
  uchar * comp  = malloc( bound );
  FD_TEST( comp );

  ulong csz = fd_zle_compress( comp, src, sz );
  FD_TEST( csz<=bound );

  ulong rsz = ref_compress( ref, src, sz );
  if( FD_UNLIKELY( ( csz!=rsz ) || ( csz && memcmp( comp, ref, csz ) ) ) )
    FD_LOG_ERR(( "encoder mismatch at sz %lu off %lu (got %lu bytes, ref %lu bytes)",
                 sz, off, csz, rsz ));

  long res = fd_zle_decompress( out, sz, comp, csz );
  FD_TEST( res==(long)sz );
  FD_TEST( 0==memcmp( out, src, sz ) );

  free( comp );
  free( buf  );
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         data_sz ) {
  if( FD_UNLIKELY( data_sz>MAX_SZ ) ) data_sz = MAX_SZ;

  ulong hash = fd_ulong_hash( data_sz ^ ( data_sz ? ( ( (ulong)data[0]<<8 ) | (ulong)data[data_sz-1] ) : 0UL ) );
  check_at( data, data_sz, 0UL         );
  check_at( data, data_sz, hash & 63UL );   /* fd_zle.h permits an unaligned input */

  FD_FUZZ_MUST_BE_COVERED;
  return 0;
}
