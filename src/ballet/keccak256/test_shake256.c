#include "../../util/fd_util.h"
#include "fd_shake256.h"
#include "../hex/fd_hex.h"

struct shake256_vec {
  char const * msg_hex;
  char const * out_hex;
};
typedef struct shake256_vec shake256_vec_t;

static shake256_vec_t const test_vectors[] = {
  /* empty */
  { "", "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f" },
  /* "abc" */
  { "616263", "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739" },
  /* 1 byte */
  { "13", "c1e5ede9e80b48488746c06c3b29fa5a895070a9998371ad3bab311da54c9756" },
  /* 17 bytes */
  { "000102030405060708090a0b0c0d0e0f10", "160bb0184ba68ad3c5ac0bfaf1b1d5be6a06e1e39ed853c68edb5d8f2bd4673a" },
  /* 135 bytes (rate-1) */
  { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283848586",
    "c45dae624ad8a2f5aa7bac9d7557737fd91c96eedb70a6be5574d57a844eade0" },
  /* 136 bytes (exactly one rate block) */
  { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384858687",
    "b7ff4073b3f5a8eabd6e17705ca7f6761a31058f9df781a6a47e3a3063b9d67a" },
  /* 137 bytes (rate+1) */
  { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788",
    "01d90952c642a5eb2a8fc9d713f843a45d7ac05132dddcb2efc9bebc27e37bcb" },
  /* 200 bytes */
  { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
    "4ee1ca03272b05d3bfb1e1c79a967f823b9fc5e4bb3987b1ba9e9cb5afb07a5e" },
  /* empty, 64-byte output */
  { "", "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be" },
  /* "abc", 64-byte output */
  { "616263", "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4" },
  /* empty, 136-byte output (full rate block) */
  { "", "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86f3d122109e3b1fdd" },
  { NULL, NULL }
};

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  uchar msg[ 256 ];
  uchar expected[ 256 ];
  uchar out[ 256 ];

  for( shake256_vec_t const * vec = test_vectors; vec->msg_hex; vec++ ) {
    ulong msg_sz = strlen( vec->msg_hex ) / 2UL;
    ulong out_sz = strlen( vec->out_hex ) / 2UL;

    if( msg_sz ) fd_hex_decode( msg, vec->msg_hex, msg_sz );
    fd_hex_decode( expected, vec->out_hex, out_sz );

    fd_shake256_t sha[1];
    fd_shake256_init( sha );
    fd_shake256_absorb( sha, msg, msg_sz );
    fd_shake256_fini( sha );
    memset( out, 0, out_sz );
    fd_shake256_squeeze( sha, out, out_sz );

    FD_TEST( 0==memcmp( out, expected, out_sz ) );

    fd_shake256_init( sha );

    uchar const * nxt = msg;
    ulong         rem = msg_sz;
    while( rem ) {
      ulong nxt_sz = 1UL + fd_rng_ulong_roll( rng, rem );
      fd_shake256_absorb( sha, nxt, nxt_sz );
      nxt += nxt_sz;
      rem -= nxt_sz;
      if( fd_rng_uint( rng ) & 1U ) fd_shake256_absorb( sha, NULL, 0UL );
    }
    fd_shake256_fini( sha );

    memset( out, 0, out_sz );
    fd_shake256_squeeze( sha, out, out_sz );

    FD_TEST( 0==memcmp( out, expected, out_sz ) );

    fd_shake256_init( sha );
    fd_shake256_absorb( sha, msg, msg_sz );
    fd_shake256_fini( sha );

    memset( out, 0, out_sz );
    uchar * dst     = out;
    ulong   out_rem = out_sz;
    while( out_rem ) {
      ulong chunk = fd_ulong_min( out_rem, 1UL + fd_rng_ulong_roll( rng, out_sz ) );
      fd_shake256_squeeze( sha, dst, chunk );
      dst     += chunk;
      out_rem -= chunk;
    }

    FD_TEST( 0==memcmp( out, expected, out_sz ) );
  }

  uchar bench_buf[ 1472 ] __attribute__((aligned(128)));
  for( ulong b=0UL; b<1472UL; b++ ) bench_buf[b] = fd_rng_uchar( rng );

  static ulong const bench_sz[2] = { 14UL, 1472UL };

  FD_LOG_NOTICE(( "Benchmarking shake256 absorb+squeeze" ));
  for( ulong idx=0UL; idx<2UL; idx++ ) {
    ulong sz = bench_sz[ idx ];

    fd_shake256_t sha[1];

    for( ulong rem=10UL; rem; rem-- ) {
      fd_shake256_init( sha );
      fd_shake256_absorb( sha, bench_buf, sz );
      fd_shake256_fini( sha );
      fd_shake256_squeeze( sha, out, 32UL );
    }

    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      fd_shake256_init( sha );
      fd_shake256_absorb( sha, bench_buf, sz );
      fd_shake256_fini( sha );
      fd_shake256_squeeze( sha, out, 32UL );
    }
    dt += fd_log_wallclock();
    float gbps = ((float)(8UL*(70UL+sz)*iter)) / ((float)dt);
    FD_LOG_NOTICE(( "~%.3f Gbps Ethernet equiv throughput / core (sz %4lu)", (double)gbps, sz ));
  }

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
