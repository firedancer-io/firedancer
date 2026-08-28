#include "fd_zle.h"
#include "../../util/fd_util.h"

#define MAX_SZ (1UL<<20)

static uchar in  [ MAX_SZ ];
static uchar comp[ FD_ZLE_COMPRESS_BOUND( MAX_SZ ) ];
static uchar out [ MAX_SZ ];

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

    /* bit flips must never crash and never overflow the output */
    ulong bit = fd_rng_ulong_roll( rng, comp_sz*8UL );
    comp[ bit/8UL ] = (uchar)( comp[ bit/8UL ] ^ (uchar)( 1U<<( bit%8UL ) ) );
    long res = fd_zle_decompress( out, sz, comp, comp_sz );
    FD_TEST( res<=(long)sz );
  }

  /* invalid inputs */

  comp[0] = 0x00;                                       /* empty frame */
  FD_TEST( fd_zle_decompress( out, MAX_SZ, comp, 1UL )==FD_ZLE_ERR_CORRUPT );

  comp[0] = 0x1f; comp[1] = 0x00;                       /* L=1 but no literal bytes... */
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
