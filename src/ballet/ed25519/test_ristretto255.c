#include "../fd_ballet.h"
#include "fd_ristretto255_ge.h"
#include "fd_ristretto255_ge_private.h"
#include "../hex/fd_hex.h"

/* base_point_multiples was imported from
   draft-irtf-cfrg-ristretto255-decaf448-08 Appendix A.1 */

static uchar const base_point_multiples[][32] = {
  /* B[ 0] */ "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
  /* B[ 1] */ "\xe2\xf2\xae\x0a\x6a\xbc\x4e\x71\xa8\x84\xa9\x61\xc5\x00\x51\x5f\x58\xe3\x0b\x6a\xa5\x82\xdd\x8d\xb6\xa6\x59\x45\xe0\x8d\x2d\x76",
  /* B[ 2] */ "\x6a\x49\x32\x10\xf7\x49\x9c\xd1\x7f\xec\xb5\x10\xae\x0c\xea\x23\xa1\x10\xe8\xd5\xb9\x01\xf8\xac\xad\xd3\x09\x5c\x73\xa3\xb9\x19",
  /* B[ 3] */ "\x94\x74\x1f\x5d\x5d\x52\x75\x5e\xce\x4f\x23\xf0\x44\xee\x27\xd5\xd1\xea\x1e\x2b\xd1\x96\xb4\x62\x16\x6b\x16\x15\x2a\x9d\x02\x59",
  /* B[ 4] */ "\xda\x80\x86\x27\x73\x35\x8b\x46\x6f\xfa\xdf\xe0\xb3\x29\x3a\xb3\xd9\xfd\x53\xc5\xea\x6c\x95\x53\x58\xf5\x68\x32\x2d\xaf\x6a\x57",
  /* B[ 5] */ "\xe8\x82\xb1\x31\x01\x6b\x52\xc1\xd3\x33\x70\x80\x18\x7c\xf7\x68\x42\x3e\xfc\xcb\xb5\x17\xbb\x49\x5a\xb8\x12\xc4\x16\x0f\xf4\x4e",
  /* B[ 6] */ "\xf6\x47\x46\xd3\xc9\x2b\x13\x05\x0e\xd8\xd8\x02\x36\xa7\xf0\x00\x7c\x3b\x3f\x96\x2f\x5b\xa7\x93\xd1\x9a\x60\x1e\xbb\x1d\xf4\x03",
  /* B[ 7] */ "\x44\xf5\x35\x20\x92\x6e\xc8\x1f\xbd\x5a\x38\x78\x45\xbe\xb7\xdf\x85\xa9\x6a\x24\xec\xe1\x87\x38\xbd\xcf\xa6\xa7\x82\x2a\x17\x6d",
  /* B[ 8] */ "\x90\x32\x93\xd8\xf2\x28\x7e\xbe\x10\xe2\x37\x4d\xc1\xa5\x3e\x0b\xc8\x87\xe5\x92\x69\x9f\x02\xd0\x77\xd5\x26\x3c\xdd\x55\x60\x1c",
  /* B[ 9] */ "\x02\x62\x2a\xce\x8f\x73\x03\xa3\x1c\xaf\xc6\x3f\x8f\xc4\x8f\xdc\x16\xe1\xc8\xc8\xd2\x34\xb2\xf0\xd6\x68\x52\x82\xa9\x07\x60\x31",
  /* B[10] */ "\x20\x70\x6f\xd7\x88\xb2\x72\x0a\x1e\xd2\xa5\xda\xd4\x95\x2b\x01\xf4\x13\xbc\xf0\xe7\x56\x4d\xe8\xcd\xc8\x16\x68\x9e\x2d\xb9\x5f",
  /* B[11] */ "\xbc\xe8\x3f\x8b\xa5\xdd\x2f\xa5\x72\x86\x4c\x24\xba\x18\x10\xf9\x52\x2b\xc6\x00\x4a\xfe\x95\x87\x7a\xc7\x32\x41\xca\xfd\xab\x42",
  /* B[12] */ "\xe4\x54\x9e\xe1\x6b\x9a\xa0\x30\x99\xca\x20\x8c\x67\xad\xaf\xca\xfa\x4c\x3f\x3e\x4e\x53\x03\xde\x60\x26\xe3\xca\x8f\xf8\x44\x60",
  /* B[13] */ "\xaa\x52\xe0\x00\xdf\x2e\x16\xf5\x5f\xb1\x03\x2f\xc3\x3b\xc4\x27\x42\xda\xd6\xbd\x5a\x8f\xc0\xbe\x01\x67\x43\x6c\x59\x48\x50\x1f",
  /* B[14] */ "\x46\x37\x6b\x80\xf4\x09\xb2\x9d\xc2\xb5\xf6\xf0\xc5\x25\x91\x99\x08\x96\xe5\x71\x6f\x41\x47\x7c\xd3\x00\x85\xab\x7f\x10\x30\x1e",
  /* B[15] */ "\xe0\xc4\x18\xf7\xc8\xd9\xc4\xcd\xd7\x39\x5b\x93\xea\x12\x4f\x3a\xd9\x90\x21\xbb\x68\x1d\xfc\x33\x02\xa9\xd9\x9a\x2e\x53\xe6\x4e",
};

/* bad_encodings was imported from
   draft-irtf-cfrg-ristretto255-decaf448-08 Appendix A.2 */

static uchar const bad_encodings[][32] = {
  /* Non-canonical field encodings */
  "\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f",
  "\xf3\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f",
  "\xed\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f",
  /* Negative field elements */
  "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
  "\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f",
  "\xed\x57\xff\xd8\xc9\x14\xfb\x20\x14\x71\xd1\xc3\xd2\x45\xce\x3c\x74\x6f\xcb\xe6\x3a\x36\x79\xd5\x1b\x6a\x51\x6e\xbe\xbe\x0e\x20",
  "\xc3\x4c\x4e\x18\x26\xe5\xd4\x03\xb7\x8e\x24\x6e\x88\xaa\x05\x1c\x36\xcc\xf0\xaa\xfe\xbf\xfe\x13\x7d\x14\x8a\x2b\xf9\x10\x45\x62",
  "\xc9\x40\xe5\xa4\x40\x41\x57\xcf\xb1\x62\x8b\x10\x8d\xb0\x51\xa8\xd4\x39\xe1\xa4\x21\x39\x4e\xc4\xeb\xcc\xb9\xec\x92\xa8\xac\x78",
  "\x47\xcf\xc5\x49\x7c\x53\xdc\x8e\x61\xc9\x1d\x17\xfd\x62\x6f\xfb\x1c\x49\xe2\xbc\xa9\x4e\xed\x05\x22\x81\xb5\x10\xb1\x11\x7a\x24",
  "\xf1\xc6\x16\x5d\x33\x36\x73\x51\xb0\xda\x8f\x6e\x45\x11\x01\x0c\x68\x17\x4a\x03\xb6\x58\x12\x12\xc7\x1c\x0e\x1d\x02\x6c\x3c\x72",
  "\x87\x26\x0f\x7a\x2f\x12\x49\x51\x18\x36\x0f\x02\xc2\x6a\x47\x0f\x45\x0d\xad\xf3\x4a\x41\x3d\x21\x04\x2b\x43\xb9\xd9\x3e\x13\x09",
  /* Non-square x^2 */
  "\x26\x94\x8d\x35\xca\x62\xe6\x43\xe2\x6a\x83\x17\x73\x32\xe6\xb6\xaf\xeb\x9d\x08\xe4\x26\x8b\x65\x0f\x1f\x5b\xbd\x8d\x81\xd3\x71",
  "\x4e\xac\x07\x7a\x71\x3c\x57\xb4\xf4\x39\x76\x29\xa4\x14\x59\x82\xc6\x61\xf4\x80\x44\xdd\x3f\x96\x42\x7d\x40\xb1\x47\xd9\x74\x2f",
  "\xde\x6a\x7b\x00\xde\xad\xc7\x88\xeb\x6b\x6c\x8d\x20\xc0\xae\x96\xc2\xf2\x01\x90\x78\xfa\x60\x4f\xee\x5b\x87\xd6\xe9\x89\xad\x7b",
  "\xbc\xab\x47\x7b\xe2\x08\x61\xe0\x1e\x4a\x0e\x29\x52\x84\x14\x6a\x51\x01\x50\xd9\x81\x77\x63\xca\xf1\xa6\xf4\xb4\x22\xd6\x70\x42",
  "\x2a\x29\x2d\xf7\xe3\x2c\xab\xab\xbd\x9d\xe0\x88\xd1\xd1\xab\xec\x9f\xc0\x44\x0f\x63\x7e\xd2\xfb\xa1\x45\x09\x4d\xc1\x4b\xea\x08",
  "\xf4\xa9\xe5\x34\xfc\x0d\x21\x6c\x44\xb2\x18\xfa\x0c\x42\xd9\x96\x35\xa0\x12\x7e\xe2\xe5\x3c\x71\x2f\x70\x60\x96\x49\xfd\xff\x22",
  "\x82\x68\x43\x6f\x8c\x41\x26\x19\x6c\xf6\x4b\x3c\x7d\xdb\xda\x90\x74\x6a\x37\x86\x25\xf9\x81\x3d\xd9\xb8\x45\x70\x77\x25\x67\x31",
  "\x28\x10\xe5\xcb\xc2\xcc\x4d\x4e\xec\xe5\x4f\x61\xc6\xf6\x97\x58\xe2\x89\xaa\x7a\xb4\x40\xb3\xcb\xea\xa2\x19\x95\xc2\xf4\x23\x2b",
  /* Negative xy value */
  "\x3e\xb8\x58\xe7\x8f\x5a\x72\x54\xd8\xc9\x73\x11\x74\xa9\x4f\x76\x75\x5f\xd3\x94\x1c\x0a\xc9\x37\x35\xc0\x7b\xa1\x45\x79\x63\x0e",
  "\xa4\x5f\xdc\x55\xc7\x64\x48\xc0\x49\xa1\xab\x33\xf1\x70\x23\xed\xfb\x2b\xe3\x58\x1e\x9c\x7a\xad\xe8\xa6\x12\x52\x15\xe0\x42\x20",
  "\xd4\x83\xfe\x81\x3c\x6b\xa6\x47\xeb\xbf\xd3\xec\x41\xad\xca\x1c\x61\x30\xc2\xbe\xee\xe9\xd9\xbf\x06\x5c\x8d\x15\x1c\x5f\x39\x6e",
  "\x8a\x2e\x1d\x30\x05\x01\x98\xc6\x5a\x54\x48\x31\x23\x96\x0c\xcc\x38\xae\xf6\x84\x8e\x1e\xc8\xf5\xf7\x80\xe8\x52\x37\x69\xba\x32",
  "\x32\x88\x84\x62\xf8\xb4\x86\xc6\x8a\xd7\xdd\x96\x10\xbe\x51\x92\xbb\xea\xf3\xb4\x43\x95\x1a\xc1\xa8\x11\x84\x19\xd9\xfa\x09\x7b",
  "\x22\x71\x42\x50\x1b\x9d\x43\x55\xcc\xba\x29\x04\x04\xbd\xe4\x15\x75\xb0\x37\x69\x3c\xef\x1f\x43\x8c\x47\xf8\xfb\xf3\x5d\x11\x65",
  "\x5c\x37\xcc\x49\x1d\xa8\x47\xcf\xeb\x92\x81\xd4\x07\xef\xc4\x1e\x15\x14\x4c\x87\x6e\x01\x70\xb4\x99\xa9\x6a\x22\xed\x31\xe0\x1e",
  "\x44\x54\x25\x11\x7c\xb8\xc9\x0e\xdc\xbc\x7c\x1c\xc0\xe7\x4f\x74\x7f\x2c\x1e\xfa\x56\x30\xa9\x67\xc6\x4f\x28\x77\x92\xa4\x8a\x4b",
  /* s = -1, which causes y = 0 */
  "\xec\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f",
};

static void
log_bench( char const * descr,
           ulong        iter,
           long         dt ) {
  float khz = 1e6f *(float)iter/(float)dt;
  float tau = (float)dt /(float)iter;
  FD_LOG_NOTICE(( "%-31s %11.3fK/s/core %10.3f ns/call", descr, (double)khz, (double)tau ));
}

static void
fd_ed25519_fe_print (fd_ed25519_fe_t * f) {
  uchar s[32];
  fd_ed25519_fe_tobytes(s, f);
  for ( int i=0; i<32; i++ ) { printf("%02x", s[i]); } printf("\n");
}

FD_FN_UNUSED static void
fd_ed25519_ge_print (fd_ed25519_point_t * _p) {
  fd_ed25519_ge_p3_t * p = (fd_ed25519_ge_p3_t *)_p;
  printf("X = "); fd_ed25519_fe_print(p->X);
  printf("Y = "); fd_ed25519_fe_print(p->Y);
  printf("Z = "); fd_ed25519_fe_print(p->Z);
  printf("T = "); fd_ed25519_fe_print(p->T);
}

FD_FN_UNUSED static int
fd_ed25519_point_eq (fd_ed25519_point_t * _p, fd_ed25519_point_t * _q) {
  fd_ed25519_ge_p3_t * p = (fd_ed25519_ge_p3_t *)_p;
  fd_ed25519_ge_p3_t * q = (fd_ed25519_ge_p3_t *)_q;
  return fd_ed25519_ge_eq(p, q);
}

static void
test_point_decompress( FD_FN_UNUSED fd_rng_t * rng ) {
  uchar                   _s[32]; uchar *                   s = _s;
  fd_ristretto255_point_t _h[1];  fd_ristretto255_point_t * h = _h;

  /* Decompress & compress base point multiples */
  for( uchar const * s = base_point_multiples[0];
                     s < (uchar const *)base_point_multiples + sizeof base_point_multiples;
                     s += 32 ) {
    fd_ristretto255_point_t h[1];
    if( FD_UNLIKELY( !fd_ristretto255_point_decompress( h, s ) ) ) {
      FD_LOG_ERR(( "FAIL"
                   "\n\tfd_ristretto255_point_decompress failed to decode point:"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
                   FD_LOG_HEX16_FMT_ARGS( s ), FD_LOG_HEX16_FMT_ARGS( s+16 ) ));
    }
  }

  /* Reject bad encodings */
  for( uchar const * s  = *bad_encodings;
                     s  < (uchar const *)bad_encodings + sizeof bad_encodings;
                     s += 32 ) {
    fd_ristretto255_point_t h[1];
    if( FD_UNLIKELY( !!fd_ristretto255_point_decompress( h, s ) ) ) {
      FD_LOG_ERR(( "FAIL"
                   "\n\tBad encoding was not rejected:"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
                   FD_LOG_HEX16_FMT_ARGS( s ), FD_LOG_HEX16_FMT_ARGS( s+16 ) ));
    }
  }

  /* Benchmarks */
  fd_memcpy( s, base_point_multiples[5], 32 );
  ulong iter = 100000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( s ); FD_COMPILER_FORGET( h ); fd_ristretto255_point_decompress( h, s ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ristretto255_point_decompress", iter, dt );
}

static void
test_point_compress( FD_FN_UNUSED fd_rng_t * rng ) {
  uchar                   _s[32]; uchar *                   s = _s;
  fd_ristretto255_point_t _h[1];  fd_ristretto255_point_t * h = _h;

  /* Decompress & compress base point multiples */
  for( uchar const * s = base_point_multiples[0];
                     s < (uchar const *)base_point_multiples + sizeof base_point_multiples;
                     s += 32 ) {
    fd_ristretto255_point_t h[1];
    if( FD_UNLIKELY( !fd_ristretto255_point_decompress( h, s ) ) ) {
      FD_LOG_ERR(( "FAIL"
                   "\n\tfd_ristretto255_point_decompress failed to decode point:"
                   "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
                   FD_LOG_HEX16_FMT_ARGS( s ), FD_LOG_HEX16_FMT_ARGS( s+16 ) ));
    }
    uchar t[32];
    fd_ristretto255_point_compress( t, h );
    if( FD_UNLIKELY( !!memcmp( s, t, 32 ) ) ) {
      FD_LOG_ERR(( "FAIL"
                   "\n\tfd_ristretto255_point_compress returned incorrect result:"
                   "\n\t\tExpected" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\t\tGot     " FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
                   FD_LOG_HEX16_FMT_ARGS( s ), FD_LOG_HEX16_FMT_ARGS( s+16 ),
                   FD_LOG_HEX16_FMT_ARGS( t ), FD_LOG_HEX16_FMT_ARGS( t+16 ) ));
    }

    /* Multiply all coordinates by const c */
    fd_ed25519_ge_p3_t * p = fd_type_pun(h);
    fd_ed25519_fe_t _c[1]; fd_ed25519_fe_t * c = _c;
    fd_ed25519_fe_rng(c, rng);
    fd_ed25519_fe_mul(p->X, p->X, c);
    fd_ed25519_fe_mul(p->Y, p->Y, c);
    fd_ed25519_fe_mul(p->Z, p->Z, c);
    fd_ed25519_fe_mul(p->T, p->T, c);

    fd_ristretto255_point_compress( t, h );
    if( FD_UNLIKELY( !!memcmp( s, t, 32 ) ) ) {
      FD_LOG_ERR(( "FAIL"
                   "\n\tfd_ristretto255_point_compress returned incorrect result:"
                   "\n\t\tExpected" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                   "\n\t\tGot     " FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
                   FD_LOG_HEX16_FMT_ARGS( s ), FD_LOG_HEX16_FMT_ARGS( s+16 ),
                   FD_LOG_HEX16_FMT_ARGS( t ), FD_LOG_HEX16_FMT_ARGS( t+16 ) ));
    }
  }

  /* Benchmarks */
  fd_ristretto255_point_decompress( h, base_point_multiples[5] );
  ulong iter = 100000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( s ); FD_COMPILER_FORGET( h ); fd_ristretto255_point_compress( s, h ); }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_ristretto255_point_compress", iter, dt );
}

static void
test_extended_bytes( FD_FN_UNUSED fd_rng_t * rng ) {
  uchar                   _s[32*4]; uchar *                   s = _s;
  fd_ristretto255_point_t _h[1];    fd_ristretto255_point_t * h = _h;

  /* Benchmarks */
  fd_ristretto255_point_decompress( h, base_point_multiples[5] );
  ulong iter = 100000UL;

  {
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( s ); FD_COMPILER_FORGET( h ); fd_ristretto255_extended_tobytes( s, h ); }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_ristretto255_extended_tobytes", iter, dt );
  }

  {
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( s ); FD_COMPILER_FORGET( h ); fd_ristretto255_extended_frombytes( h, s ); }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_ristretto255_extended_frombytes", iter, dt );
  }
}

static void
test_hash_to_curve( FD_FN_UNUSED fd_rng_t * rng ) {
  uchar                   _s[64]; uchar *                   s = _s;
  uchar                   _e[32]; uchar *                   e = _e;
  fd_ristretto255_point_t _h[1];  fd_ristretto255_point_t * h = _h;
  fd_ristretto255_point_t _g[1];  fd_ristretto255_point_t * g = _g;

  /* sha512("Ristretto is traditionally a short shot of espresso coffee") */
  fd_hex_decode( s, "5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c14d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6", 128 );
  fd_hex_decode( e, "3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46", 64 );
  fd_ristretto255_point_decompress( g, e );

  fd_ristretto255_hash_to_curve( h, s );
  FD_TEST( fd_ristretto255_point_eq( h, g ) );
  FD_TEST( !fd_ed25519_point_eq( h, g ) );

  uchar t[32];
  fd_ristretto255_point_compress( t, h );
  if( FD_UNLIKELY( !!memcmp( e, t, 32 ) ) ) {
    FD_LOG_ERR(( "FAIL"
                  "\n\tfd_ristretto255_hash_to_curve returned incorrect result:"
                  "\n\t\tExpected" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                  "\n\t\tGot     " FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
                  FD_LOG_HEX16_FMT_ARGS( e ), FD_LOG_HEX16_FMT_ARGS( e+16 ),
                  FD_LOG_HEX16_FMT_ARGS( t ), FD_LOG_HEX16_FMT_ARGS( t+16 ) ));
  }

  /* Benchmarks */
  ulong iter = 100000UL;

  {
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) { FD_COMPILER_FORGET( s ); FD_COMPILER_FORGET( h ); fd_ristretto255_hash_to_curve( h, s ); }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_ristretto255_hash_to_curve", iter, dt );
  }
}

static void
test_point_add_sub( FD_FN_UNUSED fd_rng_t * rng ) {
  fd_ristretto255_point_t _f[1];  fd_ristretto255_point_t * f = _f;
  fd_ristretto255_point_t _g[1];  fd_ristretto255_point_t * g = _g;
  fd_ristretto255_point_t _h[1];  fd_ristretto255_point_t * h = _h;

  /* Correctness */
  fd_ristretto255_point_t _t[1];  fd_ristretto255_point_t * t = _t;

  fd_ristretto255_point_decompress( t, base_point_multiples[0] );
  fd_ristretto255_point_decompress( f, base_point_multiples[5] );
  fd_ristretto255_point_add(h, f, t); /* P = P + 0 */
  FD_TEST( fd_ristretto255_point_eq( h, f ) );
  fd_ristretto255_point_add(h, t, f); /* P = 0 + P */
  FD_TEST( fd_ristretto255_point_eq( h, f ) );
  fd_ristretto255_point_sub(h, f, t); /* P = P - 0 */
  FD_TEST( fd_ristretto255_point_eq( h, f ) );

  fd_ristretto255_point_sub(g, t, f); /* 0 - P */
  fd_ristretto255_point_add(h, f, g); /* 0 = P + (-P) */
  FD_TEST( fd_ristretto255_point_eq( h, t ) );
  fd_ristretto255_point_add(h, g, f); /* 0 = (-P) + P */
  FD_TEST( fd_ristretto255_point_eq( h, t ) );

  for ( int i=1; i<=15; i++ ) {
    for ( int j=1; i+j<=15; j++ ) {
      fd_ristretto255_point_decompress( f, base_point_multiples[i] );
      fd_ristretto255_point_decompress( g, base_point_multiples[j] );
      fd_ristretto255_point_decompress( t, base_point_multiples[i+j] );
      fd_ristretto255_point_add(h, f, g); /* (i+j)P = iP + jP */
      FD_TEST( fd_ristretto255_point_eq( h, t ) );

      fd_ristretto255_point_sub(h, t, g); /* iP = (i+j)P - jP */
      FD_TEST( fd_ristretto255_point_eq( h, f ) );
    }
  }

  /* Benchmarks */
  ulong iter = 1000000UL;

  {
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( g ); FD_COMPILER_FORGET( h );
      fd_ristretto255_point_add( h, f, g );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_ristretto255_point_add", iter, dt );
  }

  {
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      FD_COMPILER_FORGET( f ); FD_COMPILER_FORGET( g ); FD_COMPILER_FORGET( h );
      fd_ristretto255_point_sub( h, f, g );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "fd_ristretto255_point_sub", iter, dt );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  test_point_decompress ( rng );
  test_point_compress   ( rng );
  test_extended_bytes   ( rng );

  test_hash_to_curve    ( rng );

  test_point_add_sub    ( rng );
  // test_point_scalarmult ( rng );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
