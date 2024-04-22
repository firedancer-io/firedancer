#include "fd_types.h"
#include "../../util/fd_util.h"
#include "../fd_flamenco.h"

#include <immintrin.h>

/* TODO add description: what does this thing achieve? */

#define NUM_KEYS  (16*1024)
#define NUM_ITERS (16)

int
main( int     argc,
      char ** argv ) {
  fd_boot         ( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* do a quick benchmark of sha-256 on small and large UDP payload
     packets from UDP/IP4/VLAN/Ethernet */

  fd_pubkey_t pubkeys_a[ 16*1024 ] __attribute__((aligned(128)));
  fd_pubkey_t pubkeys_b[ 16*1024 ] __attribute__((aligned(128)));
  fd_pubkey_t pubkeys_c[ 16*1024 ] __attribute__((aligned(128)));

  for( ulong b=0UL; b<sizeof(pubkeys_a); b++ ) {
    ((uchar *)pubkeys_a)[b] = fd_rng_uchar( rng );
    ((uchar *)pubkeys_b)[b] = fd_rng_uchar( rng );
    ((uchar *)pubkeys_c)[b] = ((uchar *)pubkeys_a)[b];
  }

  FD_LOG_NOTICE(( "Benchmarking memcmp negative match" ));
  {
    /* warmup */
    for( ulong rem=10UL; rem; rem-- ) FD_TEST(FD_LIKELY(memcmp(&pubkeys_a[rem], &pubkeys_b[rem], sizeof(fd_pubkey_t))!=0));

    /* for real */
    ulong iter = 16*1024;
    long  dt   = -fd_log_wallclock();
    for( ulong i = 0; i < iter; i++) FD_TEST(FD_LIKELY(memcmp(&pubkeys_a[i], &pubkeys_b[i], sizeof(fd_pubkey_t))!=0));
    dt += fd_log_wallclock();
    float time_per_op = ((float)iter) / ((float)dt);

    FD_LOG_NOTICE(( "negative: %f", (double)time_per_op ));
  }

  FD_LOG_NOTICE(( "Benchmarking memcmp positive match" ));
  {
    /* warmup */
    for( ulong rem=10UL; rem; rem-- ) FD_TEST(FD_LIKELY(memcmp(&pubkeys_a[rem], &pubkeys_c[rem], sizeof(fd_pubkey_t))==0));

    /* for real */
    ulong iter = 16*1024;
    long  dt   = -fd_log_wallclock();
    for( ulong i = 0; i < iter; i++) FD_TEST(FD_LIKELY(memcmp(&pubkeys_a[i], &pubkeys_c[i], sizeof(fd_pubkey_t))==0));
    dt += fd_log_wallclock();
    float time_per_op = ((float)iter) / ((float)dt);

    FD_LOG_NOTICE(( "positive: %f", (double)time_per_op ));
  }

  FD_LOG_NOTICE(( "Benchmarking negative match" ));
  {
    /* warmup */
    for( ulong rem=10UL; rem; rem-- ) {
      __m256i a = *(__m256i*) &pubkeys_a[rem];
      __m256i b = *(__m256i*) &pubkeys_b[rem];

      __m256i c = ~a ^ b;
      FD_TEST(_mm256_testz_si256(c,c)| 0x1);
    }

    /* for real */
    ulong iter = 16*1024;
    long  dt   = -fd_log_wallclock();
    for( ulong i = 0; i < iter; i++) {
      __m256i cmp_res = _mm256_cmpeq_epi64(*(__m256i*) &pubkeys_a[i], *(__m256i*) &pubkeys_b[i]);
      FD_TEST(_mm256_testz_si256(cmp_res, cmp_res));
    }
    dt += fd_log_wallclock();
    float time_per_op = ((float)iter) / ((float)dt);

    FD_LOG_NOTICE(( "negative: %f", (double)time_per_op ));
  }

  FD_LOG_NOTICE(( "Benchmarking positive match" ));
  {
    /* warmup */
    for( ulong rem=10UL; rem; rem-- ) {
      __m256i cmp_res = _mm256_cmpeq_epi64(*(__m256i*) &pubkeys_a[rem], *(__m256i*) &pubkeys_c[rem]);
      FD_TEST(~_mm256_testz_si256(cmp_res, cmp_res));
    }

    /* for real */
    ulong iter = 16*1024;
    long  dt   = -fd_log_wallclock();
    for( ulong i = 0; i < iter; i++) {

      __m256i cmp_res = _mm256_cmpeq_epi64(*(__m256i*) &pubkeys_a[i], *(__m256i*) &pubkeys_c[i]);
      FD_TEST(~_mm256_testz_si256(cmp_res, cmp_res));
    }
    dt += fd_log_wallclock();
    float time_per_op = ((float)iter) / ((float)dt);

    FD_LOG_NOTICE(( "positive: %f", (double)time_per_op ));
  }


  /* clean up */
  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_flamenco_halt();
  fd_halt();
  return 0;
}

