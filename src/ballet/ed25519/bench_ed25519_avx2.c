#include "fd_ed25519.h"
#include "fd_f25519.h"
#include <stdio.h>

/* Synthetic fixtures only.  Build this driver with both scalar and AVX2
   libraries and compare DIFF lines before comparing BENCH timings. */
#define FIXTURE_CNT (64UL)
#define MSG_MAX     (1232UL)

struct fixture {
  uchar msg[MSG_MAX];
  uchar pub[32];
  uchar sig[64];
};
typedef struct fixture fixture_t;

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  ulong iterations = fd_env_strip_cmdline_ulong( &argc, &argv, "--iterations", NULL, 10000UL );
  FD_TEST( iterations>0UL );

  fd_rng_t rng[1];
  fd_rng_new( rng, 0U, 0UL );
  fd_sha512_t sha[1];
  fd_sha512_new( sha );
  fixture_t fixtures[FIXTURE_CNT];
  ulong const sizes[] = { 128UL, 512UL, MSG_MAX };
  printf( "CONFIG avx2=%i fixtures=%lu iterations=%lu\n", FD_F25519_AVX2, FIXTURE_CNT, iterations );

  for( ulong sz_idx=0UL; sz_idx<sizeof(sizes)/sizeof(sizes[0]); sz_idx++ ) {
    ulong msg_sz = sizes[sz_idx];
    ulong fixture_digest = 0UL;
    ulong histogram[4] = {0};
    uchar outcomes[FIXTURE_CNT][4];

    /* Key generation and signing are deliberately outside timed regions. */
    for( ulong i=0UL; i<FIXTURE_CNT; i++ ) {
      fixture_t * f = fixtures+i;
      uchar private_key[32];
      for( ulong j=0UL; j<32UL; j++ ) private_key[j] = fd_rng_uchar( rng );
      for( ulong j=0UL; j<msg_sz; j++ ) f->msg[j] = fd_rng_uchar( rng );
      fd_ed25519_public_from_private( f->pub, private_key, sha );
      fd_ed25519_sign( f->sig, f->msg, msg_sz, f->pub, private_key, sha );
      fd_memzero_explicit( private_key, sizeof(private_key) );
      fixture_digest = fd_hash( fixture_digest, f->msg, msg_sz );
      fixture_digest = fd_hash( fixture_digest, f->pub, sizeof(f->pub) );
      fixture_digest = fd_hash( fixture_digest, f->sig, sizeof(f->sig) );

      int rc[4];
      rc[0] = fd_ed25519_verify( f->msg, msg_sz, f->sig, f->pub, sha );

      ulong msg_byte = (13UL*i+17UL)%msg_sz;
      uchar bit = (uchar)(1U<<(i%8UL));
      f->msg[msg_byte] ^= bit;
      rc[1] = fd_ed25519_verify( f->msg, msg_sz, f->sig, f->pub, sha );
      f->msg[msg_byte] ^= bit;

      /* Cover both R and S, including the scalar's highest bit. */
      bit = (uchar)(1U<<((i/8UL)%8UL));
      f->sig[i%64UL] ^= bit;
      rc[2] = fd_ed25519_verify( f->msg, msg_sz, f->sig, f->pub, sha );
      f->sig[i%64UL] ^= bit;

      f->pub[i%32UL] ^= bit;
      rc[3] = fd_ed25519_verify( f->msg, msg_sz, f->sig, f->pub, sha );
      f->pub[i%32UL] ^= bit;

      FD_TEST( rc[0]==FD_ED25519_SUCCESS );
      for( ulong kind=0UL; kind<4UL; kind++ ) {
        FD_TEST( rc[kind]<=FD_ED25519_SUCCESS && rc[kind]>=FD_ED25519_ERR_MSG );
        FD_TEST( kind==0UL || rc[kind]!=FD_ED25519_SUCCESS );
        outcomes[i][kind] = (uchar)(-rc[kind]);
        histogram[(ulong)(-rc[kind])]++;
      }
    }

    printf( "DIFF bytes=%lu fixtures=%lu input_digest=%016lx result_digest=%016lx "
            "ok=%lu err_sig=%lu err_pubkey=%lu err_msg=%lu\n",
            msg_sz, FIXTURE_CNT, fixture_digest, fd_hash( 0UL, outcomes, sizeof(outcomes) ),
            histogram[0], histogram[1], histogram[2], histogram[3] );

    /* Warm every fixture, then rotate through independent public keys. */
    for( ulong i=0UL; i<FIXTURE_CNT; i++ ) {
      fixture_t const * f = fixtures+i;
      FD_TEST( fd_ed25519_verify( f->msg, msg_sz, f->sig, f->pub, sha )==FD_ED25519_SUCCESS );
    }
    int failed = 0;
    long elapsed = fd_log_wallclock();
    for( ulong i=0UL; i<iterations; i++ ) {
      fixture_t const * f = fixtures+(i%FIXTURE_CNT);
      failed |= fd_ed25519_verify( f->msg, msg_sz, f->sig, f->pub, sha );
    }
    elapsed = fd_log_wallclock()-elapsed;
    FD_TEST( !failed );
    FD_TEST( elapsed>0L );
    printf( "BENCH bytes=%lu iterations=%lu elapsed_ns=%ld ns_per_verify=%.3f\n",
            msg_sz, iterations, elapsed, (double)elapsed/(double)iterations );
    fflush( stdout );
  }

  fd_sha512_delete( sha );
  fd_rng_delete( rng );
  fd_halt();
  return 0;
}
