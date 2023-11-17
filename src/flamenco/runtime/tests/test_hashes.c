#include "../../fd_flamenco_base.h"
#include "../../../ballet/blake3/fd_blake3.h"
#include "../../../ballet/ed25519/fd_ristretto255_ge.h"

static ulong const bench_sz[] = { 100UL, 1472UL, 10000UL, 100000UL, 1000000UL };
static ulong const bench_iter[] = { 100000UL, 100000UL, 100000UL, 100000UL, 10000UL };
static uchar rnd_buf [ 1000000 ] __attribute__((aligned(128)));

// How fast is a blake3_256
//
// This is the old path used for creating the account hash
void time_blake3_256(void) {
  uchar hash[   64 ] __attribute__((aligned(64)));

  FD_LOG_NOTICE(( "blake3_256 tests "));

  for( ulong idx=0U; idx<(sizeof(bench_sz) / sizeof(bench_sz[0])); idx++ ) {
    ulong sz = bench_sz[ idx ];

    /* warmup */
    for( ulong rem=10UL; rem; rem-- ) {
      fd_blake3_t b3[1];
      fd_blake3_init  ( b3 );
      fd_blake3_append( b3, rnd_buf, sz );
      fd_blake3_fini  ( b3, hash );
    }

    /* for real */
    ulong iter = bench_iter[idx];
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      fd_blake3_t b3[1];
      fd_blake3_init  ( b3 );
      fd_blake3_append( b3, rnd_buf, sz );
      fd_blake3_fini  ( b3, hash );
    }
    dt += fd_log_wallclock();
    float gbps = ((float)(8UL*(70UL+sz)*iter)) / ((float)dt);
    FD_LOG_NOTICE(( "~%.3f Gbps Ethernet equiv throughput / core (sz %4lu)", (double)gbps, sz ));
  }
}

// How fast is a blake3_512
//
// This is the new path used for creating the account hash still using blake3 hashing
void time_blake3_512(void) {
  uchar hash[   64 ] __attribute__((aligned(64)));

  FD_LOG_NOTICE(( "blake3_512 tests "));

  for( ulong idx=0U; idx<(sizeof(bench_sz) / sizeof(bench_sz[0])); idx++ ) {
    ulong sz = bench_sz[ idx ];

    /* warmup */
    for( ulong rem=10UL; rem; rem-- ) {
      fd_blake3_t b3[1];
      fd_blake3_init  ( b3 );
      fd_blake3_append( b3, rnd_buf, sz );
      fd_blake3_fini_512  ( b3, hash );
    }

    /* for real */
    ulong iter = bench_iter[idx];
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      fd_blake3_t b3[1];
      fd_blake3_init  ( b3 );
      fd_blake3_append( b3, rnd_buf, sz );
      fd_blake3_fini_512  ( b3, hash );
    }
    dt += fd_log_wallclock();
    float gbps = ((float)(8UL*(70UL+sz)*iter)) / ((float)dt);
    FD_LOG_NOTICE(( "~%.3f Gbps Ethernet equiv throughput / core (sz %4lu)", (double)gbps, sz ));
  }
}

// How fast is a sha512
//
// This is the new path used for creating the account hash using sha512 before curve creation
void time_sha512(void) {
  uchar hash[   64 ] __attribute__((aligned(64)));

  FD_LOG_NOTICE(( "sha512_512 tests serial"));

  for( ulong idx=0U; idx<(sizeof(bench_sz) / sizeof(bench_sz[0])); idx++ ) {
    ulong sz = bench_sz[ idx ];

    /* warmup */
    for( ulong rem=10UL; rem; rem-- ) {
      fd_sha512_t b3[1];
      fd_sha512_init  ( b3 );
      fd_sha512_append( b3, rnd_buf, sz );
      fd_sha512_fini ( b3, hash );
    }

    /* for real */
    ulong iter = bench_iter[idx];
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      fd_sha512_t b3[1];
      fd_sha512_init  ( b3 );
      fd_sha512_append( b3, rnd_buf, sz );
      fd_sha512_fini ( b3, hash );
    }
    dt += fd_log_wallclock();
    float gbps = ((float)(8UL*(70UL+sz)*iter)) / ((float)dt);
    FD_LOG_NOTICE(( "~%.3f Gbps Ethernet equiv throughput / core (sz %4lu)", (double)gbps, sz ));
  }

  FD_LOG_NOTICE(( "sha512_512 tests batch"));

  // This is not as accurate as the sha512_batch test in test_sha512
  // since I am hitting the same memory over and over...   Still, it
  // gives the feel of the performance...
  for( ulong idx=0U; idx<(sizeof(bench_sz) / sizeof(bench_sz[0])); idx++ ) {
    ulong sz = bench_sz[ idx ];

    fd_sha512_batch_t b3[1];
    fd_sha512_batch_init  ( b3 );

    /* warmup */
    for( ulong rem=10UL; rem; rem-- )
      fd_sha512_batch_add( b3, rnd_buf, sz, hash );
    fd_sha512_batch_fini(b3);

    /* for real */
    ulong iter = bench_iter[idx];
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- )
      fd_sha512_batch_add( b3, rnd_buf, sz, hash );
    fd_sha512_batch_fini(b3);
    dt += fd_log_wallclock();
    float gbps = ((float)(8UL*(70UL+sz)*iter)) / ((float)dt);
    FD_LOG_NOTICE(( "~%.3f Gbps Ethernet equiv throughput / core (sz %4lu)", (double)gbps, sz ));
  }
}

// How long does it take to get from account data to uncompressed ristretto bytes in the account db
void time_ristretto_bytes(void) {
  uchar hash[   64 ] __attribute__((aligned(64)));

  FD_LOG_NOTICE(( "ristretto point bytes generated using sha512_512 batch"));

  // This is not as accurate as the sha512_batch test in test_sha512
  // since I am hitting the same memory over and over...   Still, it
  // gives the feel of the performance...
  for( ulong idx=0U; idx<(sizeof(bench_sz) / sizeof(bench_sz[0])); idx++ ) {
    ulong sz = bench_sz[ idx ];

    fd_sha512_batch_t b3[1];
    fd_sha512_batch_init  ( b3 );

    /* warmup */
    for( ulong rem=10UL; rem; rem-- )
      fd_sha512_batch_add( b3, rnd_buf, sz, hash );
    fd_sha512_batch_fini(b3);

    /* Yes, we don't have a batch version of ristretto... more
      importantly,  there is a barrier between the 512 batch stuff and
      the ristretto stuff...*/

    for( ulong rem=10UL; rem; rem-- ) {
      fd_ristretto255_point_t p;
      fd_ristretto255_hash_to_curve( &p, hash );
      uchar rhash[512];
      fd_ristretto255_extended_tobytes( rhash, &p );
    }

    /* for real */
    ulong iter = bench_iter[idx];
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- )
      fd_sha512_batch_add( b3, rnd_buf, sz, hash );
    fd_sha512_batch_fini(b3);

    for( ulong rem=iter; rem; rem-- ) {
      fd_ristretto255_point_t p;
      fd_ristretto255_hash_to_curve( &p, hash );
      uchar rhash[512];
      fd_ristretto255_extended_tobytes( rhash, &p );
    }

    dt += fd_log_wallclock();
    float gbps = ((float)(8UL*(70UL+sz)*iter)) / ((float)dt);
    FD_LOG_NOTICE(( "~%.3f Gbps Ethernet equiv throughput / core (sz %4lu)", (double)gbps, sz ));
  }
}

#if 0
// How long does it take to get from account data to uncompressed ristretto bytes in the account db
void time_ed25519_bytes(void) {
  uchar hash[   64 ] __attribute__((aligned(64)));

  FD_LOG_NOTICE(( "ristretto point bytes generated using sha512_512 batch"));

  // This is not as accurate as the sha512_batch test in test_sha512
  // since I am hitting the same memory over and over...   Still, it
  // gives the feel of the performance...
  for( ulong idx=0U; idx<(sizeof(bench_sz) / sizeof(bench_sz[0])); idx++ ) {
    ulong sz = bench_sz[ idx ];

    fd_sha512_batch_t b3[1];
    fd_sha512_batch_init  ( b3 );

    /* warmup */
    for( ulong rem=10UL; rem; rem-- )
      fd_sha512_batch_add( b3, rnd_buf, sz, hash );
    fd_sha512_batch_fini(b3);

    /* Yes, we don't have a batch version of ristretto... more
      importantly,  there is a barrier between the 512 batch stuff and
      the ristretto stuff...*/

    for( ulong rem=10UL; rem; rem-- ) {
      fd_ed25519_point_t p;
      fd_ed25519_hash_to_curve( &p, hash );
      uchar rhash[512];
      fd_ed25519_ge_tobytes( rhash, &p );
    }

    /* for real */
    ulong iter = bench_iter[idx];
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- )
      fd_sha512_batch_add( b3, rnd_buf, sz, hash );
    fd_sha512_batch_fini(b3);

    for( ulong rem=iter; rem; rem-- ) {
      fd_ed25519_point_t p;
      fd_ed25519_hash_to_curve( &p, hash );
      uchar rhash[512];
      fd_ed25519_extended_tobytes( rhash, &p );
    }

    dt += fd_log_wallclock();
    float gbps = ((float)(8UL*(70UL+sz)*iter)) / ((float)dt);
    FD_LOG_NOTICE(( "~%.3f Gbps Ethernet equiv throughput / core (sz %4lu)", (double)gbps, sz ));
  }
}

#endif

void time_ristretto_adh(fd_rng_t * rng) {
  FD_LOG_NOTICE(( "timing root generation"));

#define MAX_ACCTS 10000
#define RBYTES ((size_t) 64 * (size_t) MAX_ACCTS)

  FD_LOG_NOTICE(( "Generating random data for %ld accounts (%ld bytes)", MAX_ACCTS, RBYTES));

  uchar *rdata = (uchar *) malloc(RBYTES);
  for( ulong b=0UL; b<RBYTES; b += sizeof(ulong) ) *((ulong *) &rdata[b]) = fd_rng_ulong( rng );

  FD_LOG_NOTICE(( "Generating curves from the hashes of %ld accounts", MAX_ACCTS ));
  uchar *curves = (uchar *) malloc((size_t) (128 * MAX_ACCTS));

  for( ulong b=0UL; b<MAX_ACCTS; b ++ ) {
    fd_ristretto255_point_t p;
    fd_ristretto255_hash_to_curve( &p, &rdata[b * 64] );
    fd_ristretto255_extended_tobytes(&curves[b * 128], &p );
  }

  FD_LOG_NOTICE(( "Creating the account delta hash for %ld accounts", MAX_ACCTS ));

  fd_ristretto255_point_t rhash;
  fd_ristretto255_point_0(&rhash);

  for( ulong b=0UL; b<MAX_ACCTS; b++ ) {
    fd_ristretto255_point_t p;
    fd_ristretto255_extended_frombytes(&p, &curves[(b & 63) * 128]);
    fd_ristretto255_point_add( &rhash, &rhash, &p );
  }

  uchar adh[128];
  fd_ristretto255_extended_tobytes(adh, &rhash);

  FD_LOG_NOTICE(( "We have a hash" ));
}

#if 0
void time_eoh(fd_rng_t * rng) {
  // 300M accounts...  Is this worth all doing in a large page?

  FD_LOG_NOTICE(( "timing root generation"));

// #define MAX_ACCTS 300000000
#define MAX_ACCTS 3000000

#define RBYTES ((size_t) 64 * (size_t) MAX_ACCTS)

  FD_LOG_NOTICE(( "Generating random data for %ld accounts (%ld bytes)", MAX_ACCTS, RBYTES));

  uchar *rdata = (uchar *) malloc(RBYTES);
  for( ulong b=0UL; b<RBYTES; b += sizeof(ulong) ) *((ulong *) &rdata[b]) = fd_rng_ulong( rng );

  FD_LOG_NOTICE(( "Generating curves from the hashes of 64 accounts" ));
  uchar *curves = (uchar *) malloc((size_t) (128 * 64));

  for( ulong b=0UL; b<64; b ++ ) {
    fd_ristretto255_point_t p;
    fd_ristretto255_hash_to_curve( &p, &rdata[b * 64] );
    fd_ristretto255_extended_tobytes(&curves[b * 128], &p );
  }

  FD_LOG_NOTICE(( "How quick can we sum %d accounts up?", MAX_ACCTS ));

  fd_ristretto255_point_t rhash;
  fd_ristretto255_point_0(&rhash);

  for( ulong b=0UL; b<MAX_ACCTS; b++ ) {
    fd_ristretto255_point_t p;
    fd_ristretto255_extended_frombytes(&p, &curves[(b & 63) * 128]);
    fd_ristretto255_point_add( &rhash, &rhash, &p );
  }
}
#endif

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  if ( FD_UNLIKELY( argc > 1 ) )
    FD_LOG_ERR( ( "unrecognized argument: %s", argv[1] ) );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  for( ulong b=0UL; b<1000000UL; b++ ) rnd_buf[b] = fd_rng_uchar( rng );

//  time_blake3_256();
//  time_blake3_512();
//  time_sha512();
//  time_ristretto_bytes();
  time_ristretto_adh(rng);

  FD_LOG_NOTICE( ( "pass" ) );
  fd_halt();
  return 0;
}
