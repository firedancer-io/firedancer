#include "fd_bench_sign8.h"
#include "../../../../ballet/ed25519/fd_ed25519.h"
#include "../../../../ballet/ed25519/fd_curve25519.h"

/* The batch signer must reproduce fd_ed25519_sign byte for byte, since
   Ed25519 signing is deterministic. */

#define CNT (8UL*FD_BENCH_SIGN8_N_MAX)

/* Scalars that stress the signed digit recoding: no carries, a carry
   out of every byte, carries stopping at each byte, and the top of the
   scalar range. */
static void
test_mul_base( fd_bench_sign8_t const * s8,
               fd_rng_t *               rng ) {
  uchar r[ 8 ][ 32 ], out[ 8 ][ 32 ], ref[ 32 ];
  for( ulong it=0UL; it<64UL; it++ ) {
    for( ulong j=0UL; j<8UL; j++ ) {
      ulong v = 8UL*it+j;
      fd_memset( r[ j ], 0, 32UL );
      switch( v ) {
        case 0: break;
        case 1: r[ j ][ 0 ] = 1; break;
        case 2: fd_memset( r[ j ], 0xFF, 31UL ); r[ j ][ 31 ] = 0x0F; break;     /* carry through every byte */
        case 3: fd_memset( r[ j ], 0x80, 31UL ); r[ j ][ 31 ] = 0x0F; break;     /* -128 then 0x81 -> -127 ... */
        case 4: fd_memset( r[ j ], 0x7F, 31UL ); r[ j ][ 31 ] = 0x0F; break;     /* no carries */
        case 5: for( ulong b=0UL; b<31UL; b++ ) r[ j ][ b ] = (b&1UL) ? 0x7F : 0x80; r[ j ][ 31 ] = 0x0F; break;
        case 6: r[ j ][ 0 ] = 0x80; break;                                        /* one carry */
        case 7: r[ j ][ 0 ] = 0xED; r[ j ][ 1 ] = 0xD3; r[ j ][ 2 ] = 0xF5; r[ j ][ 3 ] = 0x5C; r[ j ][ 4 ] = 0x1A;
                r[ j ][ 5 ] = 0x63; r[ j ][ 6 ] = 0x12; r[ j ][ 7 ] = 0x58; r[ j ][ 8 ] = 0xD6; r[ j ][ 9 ] = 0x9C;
                r[ j ][10 ] = 0xF7; r[ j ][11 ] = 0xA2; r[ j ][12 ] = 0xDE; r[ j ][13 ] = 0xF9; r[ j ][14 ] = 0xDE;
                r[ j ][15 ] = 0x14; r[ j ][31 ] = 0x10; r[ j ][ 0 ]--; break;   /* L-1 */
        default:
          if( v<8UL+31UL ) { fd_memset( r[ j ], 0xFF, v-8UL ); r[ j ][ v-8UL ] = 0x80; }             /* carry chain ending at byte v-8 */
          else if( v<8UL+62UL ) { r[ j ][ v-39UL ] = 0x80; if( v-39UL<30UL ) r[ j ][ v-38UL ] = 0x7F; else r[ j ][ 31 ] = 0x10; } /* carry into 0x7F, or into the top byte */
          else { uchar wide[ 64 ]; for( ulong b=0UL; b<64UL; b++ ) wide[ b ] = fd_rng_uchar( rng ); fd_curve25519_scalar_reduce( r[ j ], wide ); }
      }
    }
    fd_bench_sign8_mul_base( s8, out, (uchar const (*)[ 32 ])r );
    for( ulong j=0UL; j<8UL; j++ ) {
      fd_ed25519_point_t P[1];
      fd_ed25519_scalar_mul_base_const_time( P, r[ j ] );
      fd_ed25519_point_tobytes( ref, P );
      if( FD_UNLIKELY( memcmp( ref, out[ j ], 32UL ) ) ) FD_LOG_ERR(( "mul_base mismatch vector %lu", 8UL*it+j ));
    }
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  fd_sha512_t _sha[1]; fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );

  static uchar mem[ 1UL<<20 ] __attribute__((aligned(64)));
  FD_TEST( fd_bench_sign8_footprint()<=sizeof(mem) );
  long tnew = -fd_log_wallclock();
  fd_bench_sign8_t * s8 = fd_bench_sign8_new( mem );
  tnew += fd_log_wallclock();
  FD_LOG_NOTICE(( "fd_bench_sign8_new %.1f ms, footprint %lu KiB", (double)tnew/1e6, fd_bench_sign8_footprint()>>10 ));

  ulong iter   = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter",   NULL, 1000UL );
  ulong msg_sz = fd_env_strip_cmdline_ulong( &argc, &argv, "--msg-sz", NULL, 121UL ); /* benchg noop */
  int   bench  = fd_env_strip_cmdline_contains( &argc, &argv, "--bench" );

  test_mul_base( s8, rng );

  static uchar priv[ CNT ][ 32 ], pub[ CNT ][ 32 ], msg[ CNT ][ FD_BENCH_SIGN8_MSG_MAX ], sig[ CNT ][ 64 ], ref[ 64 ];
  ulong msg_szs[ CNT ];
  uchar * sigs[ CNT ]; uchar const * msgs[ CNT ], * pubs[ CNT ], * privs[ CNT ];
  for( ulong j=0UL; j<CNT; j++ ) { sigs[j]=sig[j]; msgs[j]=msg[j]; pubs[j]=pub[j]; privs[j]=priv[j]; }

  for( ulong it=0UL; it<iter; it++ ) {
    ulong n = 1UL + it%FD_BENCH_SIGN8_N_MAX; /* every batch count */
    for( ulong j=0UL; j<8UL*n; j++ ) {
      for( ulong b=0UL; b<32UL; b++ ) priv[ j ][ b ] = fd_rng_uchar( rng );
      if( it&1UL ) { fd_memset( priv[ j ], 0, 32UL ); FD_STORE( ulong, priv[ j ], it*CNT+j ); } /* benchg style keys */
      fd_ed25519_public_from_private( pub[ j ], priv[ j ], sha );
      /* cover empty, tiny, block boundary and full size messages */
      ulong sz_pick[ 8 ] = { 0UL, 1UL, 63UL, 64UL, 111UL, 112UL, 1175UL, FD_BENCH_SIGN8_MSG_MAX };
      msg_szs[ j ] = (it<8UL) ? sz_pick[ (it+j)%8UL ] : fd_rng_ulong_roll( rng, FD_BENCH_SIGN8_MSG_MAX+1UL );
      for( ulong b=0UL; b<msg_szs[ j ]; b++ ) msg[ j ][ b ] = fd_rng_uchar( rng );
    }
    fd_bench_sign8_n( s8, n, sigs, msgs, msg_szs, pubs, privs );
    for( ulong j=0UL; j<8UL*n; j++ ) {
      fd_ed25519_sign( ref, msg[ j ], msg_szs[ j ], pub[ j ], priv[ j ], sha );
      if( FD_UNLIKELY( memcmp( ref, sig[ j ], 64UL ) ) ) FD_LOG_ERR(( "mismatch iter %lu n %lu lane %lu sz %lu", it, n, j, msg_szs[ j ] ));
      FD_TEST( fd_ed25519_verify( msg[ j ], msg_szs[ j ], sig[ j ], pub[ j ], sha )==FD_ED25519_SUCCESS );
    }
  }

  if( bench ) {
    for( ulong j=0UL; j<CNT; j++ ) msg_szs[ j ] = msg_sz;
    ulong cnt = 160000UL; /* signatures per timing */
    long t0 = fd_log_wallclock();
    for( ulong i=0UL; i<cnt/8UL; i++ ) fd_bench_sign8( s8, sigs, msgs, msg_szs, pubs, privs );
    long t1 = fd_log_wallclock();
    for( ulong i=0UL; i<cnt/CNT; i++ ) fd_bench_sign8_n( s8, FD_BENCH_SIGN8_N_MAX, sigs, msgs, msg_szs, pubs, privs );
    long t2 = fd_log_wallclock();
    for( ulong i=0UL; i<cnt/8UL; i++ ) fd_ed25519_sign( sig[ i&7UL ], msg[ i&7UL ], msg_szs[ i&7UL ], pub[ i&7UL ], priv[ i&7UL ], sha );
    long t3 = fd_log_wallclock();
    FD_LOG_NOTICE(( "msg %lu B: fd_bench_sign8 %.1f ns/sig, fd_bench_sign8_n(%lu) %.1f ns/sig, fd_ed25519_sign %.1f ns/sig",
                    msg_sz, (double)(t1-t0)/(double)cnt, FD_BENCH_SIGN8_N_MAX, (double)(t2-t1)/(double)cnt, 8.0*(double)(t3-t2)/(double)cnt ));
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
