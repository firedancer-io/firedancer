#include <stdio.h>
/* #define FD_CHACHA_RNG_DEBUG 1 */
#include "fd_chacha_rng.h"

int
usage( void ) {
  fprintf( stderr,
    "usage: test_chacha_rng_roll --range <ulong> --count <ulong> --key <ulong>\n"
    "\n"
    "Debug ChaCha20Rng stream of leader schedule derivation.\n"
    "\n"
    "  --range <ulong>  Exclusive upper bound of RNG range\n"
    "  --count <ulong>  Number of RNG rolls to perform\n"
    "  --key   <ulong>  First 8 bytes of ChaCha20 key, little-endian\n"
    "\n" );
  return 1;
}

static void
test_matches_rust_sample_single( void ) {
  fd_chacha_rng_t _rng[1];
  fd_chacha_rng_t * rng = fd_chacha_rng_join( fd_chacha_rng_new( _rng, FD_CHACHA_RNG_MODE_SHIFT ) );
  FD_TEST( rng );

  uchar key[ 32 ];
  memset( key, 0x41, 32UL );
  fd_chacha_rng_init( rng, key, FD_CHACHA_RNG_ALGO_CHACHA20 );
  /* Generated with this:
      use rand::distributions::uniform::SampleUniform;
      use rand::distributions::uniform::UniformSampler;
      use rand::SeedableRng;
      use rand_chacha::ChaChaRng;
      fn main() {
          let seed = [0x41u8; 32];
          let mut rng = ChaChaRng::from_seed(seed);
          for _ in 0..10 {
              println!(
                  "{}",
                  <u64 as SampleUniform>::Sampler::sample_single(0u64, 10u64, &mut rng)
              );
          }
          for _ in 0..10 {
              println!(
                  "{}",
                  <u64 as SampleUniform>::Sampler::sample_single(0u64, 4294967231u64, &mut rng)
              );
          }
      }
  */

  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 8UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 7UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 2UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 5UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 7UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 6UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 5UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 6UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 9UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 6UL );

  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) == 3252524226UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) == 3847107912UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) == 2388546007UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) == 1795840680UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) == 1493882641UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) == 2627412178UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) == 2509655068UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) == 2770564418UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) ==  368683988UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) ==  318451188UL );

  FD_TEST( (ulong)fd_chacha_rng_delete( fd_chacha_rng_leave( rng ) )==(ulong)_rng );
}

static void
test_matches_rust_sample( void ) {
  fd_chacha_rng_t _rng[1];
  fd_chacha_rng_t * rng = fd_chacha_rng_join( fd_chacha_rng_new( _rng, FD_CHACHA_RNG_MODE_MOD ) );
  FD_TEST( rng );

  uchar key[ 32 ];
  memset( key, 0x41, 32UL );
  fd_chacha_rng_init( rng, key, FD_CHACHA_RNG_ALGO_CHACHA20 );
  /* Generated with this:
     use rand::distributions::uniform::SampleUniform;
     use rand::distributions::uniform::UniformSampler;
     use rand::SeedableRng;
     use rand_chacha::ChaChaRng;
     fn main() {
         let seed = [0x41u8; 32];
         let mut rng = ChaChaRng::from_seed(seed);
         let sampler1 = <u64 as SampleUniform>::Sampler::new(0, 10u64);
         for _ in 0..10 {
             println!("{}", sampler1.sample(&mut rng));
         }
         let sampler2 = <u64 as SampleUniform>::Sampler::new(0, 4294967231u64);
         for _ in 0..10 {
             println!("{}", sampler2.sample(&mut rng));
         }
     } */

  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 8UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 7UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 1UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 2UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 5UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 7UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 6UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 2UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 9UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 10UL ) == 5UL );

  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) == 2659576357UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) == 4036770383UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) == 2578672018UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) == 3252524226UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) == 3847107912UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) == 2388546007UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) == 1795840680UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) == 1493882641UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) == 2627412178UL );
  FD_TEST( fd_chacha_rng_ulong_roll( rng, 4294967231UL ) == 2509655068UL );

  FD_TEST( (ulong)fd_chacha_rng_delete( fd_chacha_rng_leave( rng ) )==(ulong)_rng );
}

static void
test_iterated( void ) {
  fd_chacha_rng_t _rng[1];
  fd_chacha_rng_t * rng = fd_chacha_rng_join( fd_chacha_rng_new( _rng, FD_CHACHA_RNG_MODE_MOD ) );
  FD_TEST( rng );

  uchar key[ 32 ];
  memset( key, 0x41, 32UL );
  fd_chacha_rng_init( rng, key, FD_CHACHA_RNG_ALGO_CHACHA20 );
  /* Generated with this:
     use rand::distributions::uniform::SampleUniform;
     use rand::distributions::uniform::UniformSampler;
     use rand::SeedableRng;
     use rand_chacha::ChaChaRng;
     fn main() {
         let seed = [0x41u8; 32];
         let mut rng = ChaChaRng::from_seed(seed);
         let mut n = 100000000u64;
         for _ in 0..1000000000u64 {
             let sampler = <u64 as SampleUniform>::Sampler::new(0, n);
             n = sampler.sample(&mut rng).wrapping_mul(3).wrapping_add(3);
         }
         println!("{}", n);
     } */

  ulong n = 100000000UL;
  for( ulong i=0UL; i<1000000000UL; i++ ) n = 3UL*fd_chacha_rng_ulong_roll( rng, n )+3UL;

  FD_TEST( n==10620388038139726539UL );
}

void
test_decreasing( void ) {
  fd_chacha_rng_t _rng1[1];
  fd_chacha_rng_t _rng2[1];
  fd_chacha_rng_t * rng1 = fd_chacha_rng_join( fd_chacha_rng_new( _rng1, FD_CHACHA_RNG_MODE_SHIFT ) );
  fd_chacha_rng_t * rng2 = fd_chacha_rng_join( fd_chacha_rng_new( _rng2, FD_CHACHA_RNG_MODE_SHIFT ) );
  FD_TEST( rng1 );
  FD_TEST( rng2 );

  uchar key[ 32 ];
  memset( key, 0x41, 32UL );
  fd_chacha_rng_init( rng1, key, FD_CHACHA_RNG_ALGO_CHACHA8 );
  fd_chacha_rng_init( rng2, key, FD_CHACHA_RNG_ALGO_CHACHA8 );

  const ulong OUTER = 200000UL;

  ulong sum = 0UL;
  ulong output[500UL];
  long time = -fd_log_wallclock();
  for( ulong outer=0UL; outer<OUTER; outer++ ) {
    fd_chacha_rng_ulong_roll_decreasing( rng2, 3068UL, output, 500UL );
    for( ulong i=0UL; i<500UL; i++ ) sum += output[i];
  }
  time += fd_log_wallclock();
  FD_LOG_NOTICE(( "%lx in %f ns/roll optimized", sum, (double)time/(double)(OUTER*500UL) ));
  ulong sum0 = sum;

  sum = 0UL;
  time = -fd_log_wallclock();
  for( ulong outer=0UL; outer<OUTER-1UL; outer++ ) {
    for( ulong i=0UL; i<500UL; i++ ) sum += fd_chacha_rng_ulong_roll( rng1, 3068UL-i );
  }
  time += fd_log_wallclock();
  for( ulong i=0UL; i<500UL; i++ ) {
    ulong v = fd_chacha_rng_ulong_roll( rng1, 3068UL-i );
    FD_TEST( output[i]==v );
    sum += v;
  }
  FD_TEST( sum0==sum );
  FD_LOG_NOTICE(( "%lx in %f ns/roll default", sum, (double)time/(double)((OUTER-1UL)*500UL) ));


  FD_TEST( (ulong)fd_chacha_rng_delete( fd_chacha_rng_leave( rng2 ) )==(ulong)_rng2 );
  FD_TEST( (ulong)fd_chacha_rng_delete( fd_chacha_rng_leave( rng1 ) )==(ulong)_rng1 );
}

int
main( int     argc,
      char ** argv ) {
  for( int i=1; i<argc; i++ ) if( 0==strcmp( argv[i], "--help" ) ) return usage();

  fd_boot( &argc, &argv );

  /* Use debug logging, as debug contains the interesting info */
  fd_log_level_logfile_set( 0 );
  fd_log_level_stderr_set ( 0 );

  test_matches_rust_sample_single();
  test_matches_rust_sample();

  test_iterated();

  test_decreasing();

  FD_LOG_NOTICE(( "Passed built-in tests" ));

  /* Read command-line params */

  ulong n    = fd_env_strip_cmdline_ulong( &argc, &argv, "--range", NULL, 0UL );
  ulong c    = fd_env_strip_cmdline_ulong( &argc, &argv, "--count", NULL, 0UL );
  ulong _key = fd_env_strip_cmdline_ulong( &argc, &argv, "--key",   NULL, 0UL );

  if( FD_UNLIKELY( (!n) | (!c) ) ) return usage();

  /* Create RNG */

  fd_chacha_rng_t _rng[1];
  fd_chacha_rng_t * rng = fd_chacha_rng_join( fd_chacha_rng_new( _rng, FD_CHACHA_RNG_MODE_MOD ) );
  FD_TEST( rng );

  uchar key[ 32 ] = {0};
  memcpy( key, &_key, sizeof(ulong) );
  fd_chacha_rng_init( rng, key, FD_CHACHA_RNG_ALGO_CHACHA20 );

  /* Roll RNG */

  for( ulong i=0UL; i<c; i++ ) {
    /* Logs debug info */
    fd_chacha_rng_ulong_roll( rng, n );
  }

  /* Cleanup */

  FD_TEST( (ulong)fd_chacha_rng_delete( fd_chacha_rng_leave( rng ) )==(ulong)_rng );
  fd_halt();
  return 0;
}
