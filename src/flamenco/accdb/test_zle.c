#include "fd_zle.h"
#include "../../util/fd_util.h"
#include <unistd.h>

#define MAX_SZ (1UL<<20)

static uchar in  [ MAX_SZ ] __attribute__((aligned(64)));
static uchar comp[ FD_ZLE_COMPRESS_BOUND( MAX_SZ ) ] __attribute__((aligned(64)));
static uchar out [ MAX_SZ ] __attribute__((aligned(64)));
static uchar ref [ FD_ZLE_COMPRESS_BOUND( MAX_SZ ) ] __attribute__((aligned(64)));

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

static ulong
ref_frame_sz( ulong L,
              ulong Z ) {
  return 1UL + ref_ext( L ) + L + ref_ext( Z );
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
  if( L        ) memcpy( o, lit, L );
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
      if( (ulong)( o-dst )+ref_frame_sz( L, Z )>=esc_sz ) return (ulong)( ref_emit( dst, src, n, 0UL )-dst );
      o  = ref_emit( o, src+fs, L, Z );
      fs = ze;
    }
    pos = ze;
  }
  if( fs<n ) {
    ulong L = n-fs;
    if( (ulong)( o-dst )+ref_frame_sz( L, 0UL )>=esc_sz ) return (ulong)( ref_emit( dst, src, n, 0UL )-dst );
    o = ref_emit( o, src+fs, L, 0UL );
  }
  return (ulong)( o-dst );
}

/* diff_case asserts, for src[0,sz), that the encoder matches the oracle
   byte for byte, stays inside FD_ZLE_COMPRESS_BOUND, and round trips. */

static void
diff_case( uchar const * src,
           ulong         sz ) {
  fd_memset( comp, 0xcc, FD_ZLE_COMPRESS_BOUND( sz )+1UL );
  ulong comp_sz = fd_zle_compress( comp, src, sz );
  ulong ref_sz  = ref_compress( ref, src, sz );
  FD_TEST( comp_sz<=FD_ZLE_COMPRESS_BOUND( sz ) );
  FD_TEST( comp[ FD_ZLE_COMPRESS_BOUND( sz ) ]==0xcc ); /* no write past bound */
  FD_TEST( comp_sz==ref_sz );
  FD_TEST( 0==memcmp( comp, ref, comp_sz ) );
  fd_memset( out, 0xcc, sz );
  FD_TEST( fd_zle_decompress( out, sz, comp, comp_sz )==(long)sz );
  FD_TEST( 0==memcmp( out, src, sz ) );
}

static ulong
round_trip( ulong sz ) {
  fd_memset( comp, 0xcc, sizeof(comp) );
  ulong comp_sz = fd_zle_compress( comp, in, sz );
  FD_TEST( comp_sz<=FD_ZLE_COMPRESS_BOUND( sz ) );
  fd_memset( out, 0xcc, sizeof(out) );
  long res = fd_zle_decompress( out, sz, comp, comp_sz );
  FD_TEST( res==(long)sz );
  FD_TEST( 0==memcmp( out, in, sz ) );
  return comp_sz;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* empty input */

  FD_TEST( fd_zle_compress( comp, in, 0UL )==0UL );
  FD_TEST( fd_zle_decompress( out, 0UL, comp, 0UL )==0L );

  /* known vectors */

  fd_memcpy( in, "AB\0\0\0CD", 7UL );
  FD_TEST( round_trip( 7UL )==6UL );
  FD_TEST( 0==memcmp( comp, "\x23" "AB" "\x20" "CD", 6UL ) );

  /* 00 00 -> single (L=0,Z=2) frame */
  fd_memset( in, 0, 2UL );
  FD_TEST( round_trip( 2UL )==1UL );
  FD_TEST( comp[0]==0x02 );

  /* all zeros -> token + varint(85) */
  fd_memset( in, 0, 100UL );
  FD_TEST( round_trip( 100UL )==2UL );
  FD_TEST( comp[0]==0x0f && comp[1]==85 );

  /* single zero byte -> escape, 2 bytes */
  in[0] = 0;
  FD_TEST( round_trip( 1UL )==2UL );
  FD_TEST( comp[0]==0x10 && comp[1]==0x00 );

  /* all zeros, various sizes */

  fd_memset( in, 0, MAX_SZ );
  for( ulong sz=2UL; sz<=MAX_SZ; sz<<=1 ) FD_TEST( round_trip( sz )<=4UL );

  /* zero-free input escapes with bounded overhead */

  for( ulong j=0UL; j<MAX_SZ; j++ ) in[j] = (uchar)( 1U+( fd_rng_uint( rng )%255U ) );
  for( ulong sz=1UL; sz<=MAX_SZ; sz<<=1 ) FD_TEST( round_trip( sz )<=FD_ZLE_COMPRESS_BOUND( sz ) );

  /* max frame density: 00 00 X repeated */

  for( ulong j=0UL; j<MAX_SZ; j++ ) in[j] = ( j%3UL==2UL ) ? (uchar)0xff : (uchar)0;
  FD_TEST( round_trip( MAX_SZ )<=( MAX_SZ*2UL )/3UL+8UL );

  /* SPL-token-shaped: 165 bytes, zero runs interleaved with pubkeys */

  fd_memset( in, 0, 165UL );
  for( ulong j= 0UL; j< 32UL; j++ ) in[j] = (uchar)fd_rng_uint( rng );
  for( ulong j=32UL; j< 64UL; j++ ) in[j] = (uchar)fd_rng_uint( rng );
  in[64] = 1; in[105] = 1;
  FD_TEST( round_trip( 165UL )<165UL );

  /* random fuzz: random sizes, random zero density */

  for( ulong iter=0UL; iter<50000UL; iter++ ) {
    ulong sz     = 1UL+fd_rng_ulong_roll( rng, 4096UL );
    uint  thresh = fd_rng_uint( rng )%256U;  /* zero probability */
    for( ulong j=0UL; j<sz; j++ )
      in[j] = ( ( fd_rng_uint( rng )&255U )<thresh ) ? (uchar)0 : (uchar)( fd_rng_uint( rng ) | 1U );
    ulong comp_sz = round_trip( sz );

    /* truncated streams must not round-trip cleanly */
    if( comp_sz>1UL ) {
      long res = fd_zle_decompress( out, sz, comp, comp_sz-1UL );
      FD_TEST( res<(long)sz );
    }

    /* a bit flip must decode within sz bytes or report an error */
    ulong bit = fd_rng_ulong_roll( rng, comp_sz*8UL );
    comp[ bit/8UL ] = (uchar)( comp[ bit/8UL ] ^ (uchar)( 1U<<( bit%8UL ) ) );
    long res = fd_zle_decompress( out, sz, comp, comp_sz );
    FD_TEST( res<=(long)sz );
  }

  /* invalid inputs */

  comp[0] = 0x00;                                       /* empty frame */
  FD_TEST( fd_zle_decompress( out, MAX_SZ, comp, 1UL )==FD_ZLE_ERR_CORRUPT );

  comp[0] = 0x1f; comp[1] = 0x00;                       /* L=1, Z=15, no literal or zero_ext */
  FD_TEST( fd_zle_decompress( out, MAX_SZ, comp, 2UL )==FD_ZLE_ERR_CORRUPT );

  comp[0] = 0x10;                                       /* L=1, truncated */
  FD_TEST( fd_zle_decompress( out, MAX_SZ, comp, 1UL )==FD_ZLE_ERR_CORRUPT );

  comp[0] = 0xf0;                                       /* L>=15, missing varint */
  FD_TEST( fd_zle_decompress( out, MAX_SZ, comp, 1UL )==FD_ZLE_ERR_CORRUPT );

  comp[0] = 0xf0;
  for( ulong j=1UL; j<9UL; j++ ) comp[j] = 0x80;        /* unterminated varint */
  FD_TEST( fd_zle_decompress( out, MAX_SZ, comp, 9UL )==FD_ZLE_ERR_CORRUPT );

  comp[0] = 0x0f; comp[1] = 0xff; comp[2] = 0x7f;     /* zero run larger than dst */
  FD_TEST( fd_zle_decompress( out, 16UL, comp, 3UL )==FD_ZLE_ERR_SPACE );

  comp[0] = 0x21; comp[1] = 0x41; comp[2] = 0x42;    /* output exceeds capacity */
  FD_TEST( fd_zle_decompress( out, 2UL, comp, 3UL )==FD_ZLE_ERR_SPACE );

  /* the decompressor accepts a wider variety of encodings than the
     compress function emits */

  do {
    static uchar const alt[][8] = {
      { 0x20, 0x41, 0x42             }, /* canonical  "AB" */
      { 0x10, 0x41, 0x10, 0x42       }, /* split into two frames */
      { 0x11, 0x41, 0x10, 0x42, 0x00 }, /* fails: trailing 0x00 token */
    };
    static ulong const alt_sz[] = { 3UL, 4UL, 5UL };
    FD_TEST( fd_zle_decompress( out, MAX_SZ, alt[0], alt_sz[0] )==2L && out[0]=='A' && out[1]=='B' );
    FD_TEST( fd_zle_decompress( out, MAX_SZ, alt[1], alt_sz[1] )==2L && out[0]=='A' && out[1]=='B' );
    FD_TEST( fd_zle_decompress( out, MAX_SZ, alt[2], alt_sz[2] )==FD_ZLE_ERR_CORRUPT );

    /* non-minimal varints are accepted (up to the 7 byte cap) */
    comp[0] = 0xf0; comp[1] = 0x00;
    for( ulong j=0UL; j<15UL; j++ ) comp[2UL+j] = (uchar)( 'a'+j );
    FD_TEST( fd_zle_decompress( out, MAX_SZ, comp, 17UL )==15L );
    comp[0] = 0xf0; comp[1] = 0x80; comp[2] = 0x80; comp[3] = 0x00;
    for( ulong j=0UL; j<15UL; j++ ) comp[4UL+j] = (uchar)( 'a'+j );
    FD_TEST( fd_zle_decompress( out, MAX_SZ, comp, 19UL )==15L );
    FD_TEST( 0==memcmp( out, "abcdefghijklmno", 15UL ) );

    /* a varint longer than 7 bytes is rejected, which is what keeps
       FD_ZLE_OVERHEAD at 8 consistent with FD_ZLE_MAX_SZ */
    comp[0] = 0xf0;
    for( ulong j=1UL; j<8UL; j++ ) comp[j] = 0x80;
    comp[8] = 0x01;
    FD_TEST( fd_zle_decompress( out, MAX_SZ, comp, 9UL )==FD_ZLE_ERR_CORRUPT );

    /* Z=1 is below FD_ZLE_MIN_Z but still decodes */
    comp[0] = 0x01; comp[1] = 0x01; comp[2] = 0x01; comp[3] = 0x01;
    FD_TEST( fd_zle_decompress( out, MAX_SZ, comp, 4UL )==4L );
    FD_TEST( !out[0] && !out[1] && !out[2] && !out[3] );

    /* decompress writes only what it returns: the tail is untouched */
    fd_memset( out, 0xcc, 64UL );
    comp[0] = 0x20; comp[1] = 0x41; comp[2] = 0x42;
    FD_TEST( fd_zle_decompress( out, 64UL, comp, 3UL )==2L );
    for( ulong j=2UL; j<64UL; j++ ) FD_TEST( out[j]==0xcc );
  } while(0);

  /* randomised differential battery against the scalar oracle */

  {
    /* every size 0..4096 at a spread of zero densities, so that runs
       land on and straddle both the 64 B word and the 256 B block
       boundary at every possible phase */

    static uint const dens[] = { 0U, 1U, 8U, 64U, 128U, 192U, 248U, 255U, 256U };
    for( ulong sz=0UL; sz<=4096UL; sz++ ) {
      for( ulong k=0UL; k<sizeof(dens)/sizeof(dens[0]); k++ ) {
        for( ulong j=0UL; j<sz; j++ )
          in[j] = ( fd_rng_uint( rng )&255U )<dens[k] ? (uchar)0 : (uchar)( fd_rng_uint( rng ) | 1U );
        diff_case( in, sz );
      }
    }

    /* one long run, swept across every offset and length that can touch
       a word or block boundary, plus the very first and very last byte */

    for( ulong sz=1UL; sz<=1024UL; sz++ ) {
      for( ulong off=0UL; off<sz; off++ ) {
        ulong len = sz-off;
        if( !( ( off%64UL )<=1UL || ( off%64UL )>=63UL || ( off%256UL )<=1UL || ( off%256UL )>=255UL ||
               off==0UL || off==sz-1UL ) ) continue;
        for( ulong j=0UL; j<sz; j++ ) in[j] = (uchar)( fd_rng_uint( rng ) | 1U );
        for( ulong j=off; j<off+len && j<sz; j++ ) in[j] = 0;
        diff_case( in, sz );
        if( len>1UL ) {                    /* and a bounded run, not a suffix */
          for( ulong j=0UL; j<sz; j++ ) in[j] = (uchar)( fd_rng_uint( rng ) | 1U );
          ulong e = off+( len>320UL ? 320UL : len )-1UL;
          for( ulong j=off; j<e; j++ ) in[j] = 0;
          diff_case( in, sz );
        }
      }
    }

    /* larger sizes, random shapes */

    for( ulong t=0UL; t<300UL; t++ ) {
      ulong sz = 1UL + (ulong)( fd_rng_uint( rng )%100000U );
      uint  d  = fd_rng_uint( rng )%257U;
      ulong j  = 0UL;
      while( j<sz ) {                      /* run structured, not i.i.d. */
        ulong run = 1UL + (ulong)( fd_rng_uint( rng )%600U );
        int   z   = ( fd_rng_uint( rng )&255U )<d;
        for( ulong q=0UL; q<run && j<sz; q++, j++ ) in[j] = z ? (uchar)0 : (uchar)( fd_rng_uint( rng ) | 1U );
      }
      diff_case( in, sz );
    }

    /* all-zero and all-nonzero at the interesting sizes */

    for( ulong sz=0UL; sz<=8192UL; sz++ ) {
      fd_memset( in, 0, sz );
      diff_case( in, sz );
      for( ulong j=0UL; j<sz; j++ ) in[j] = (uchar)( fd_rng_uint( rng ) | 1U );
      diff_case( in, sz );
    }
  }

  /* strerror */

  FD_TEST( 0==strcmp( fd_zle_strerror( 0L                 ), "empty"                     ) );
  FD_TEST( 0==strcmp( fd_zle_strerror( 1L                 ), "ok"                        ) );
  FD_TEST( 0==strcmp( fd_zle_strerror( FD_ZLE_ERR_SPACE   ), "out of buffer space"       ) );
  FD_TEST( 0==strcmp( fd_zle_strerror( FD_ZLE_ERR_CORRUPT ), "malformed compressed data" ) );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
