#include "fd_zle.h"
#include "../../util/fd_util.h"

/* bench_zle: single-thread cache-hot encode/decode throughput on
   account-shaped inputs. */

#define MAX_SZ (8UL<<20)

static uchar in  [ MAX_SZ ];
static uchar comp[ FD_ZLE_COMPRESS_BOUND( MAX_SZ ) ];
static uchar out [ MAX_SZ ];

static ulong volatile sink;

static void
bench( char const * name,
       ulong        sz ) {
  ulong comp_sz = fd_zle_compress( comp, in, sz );
  FD_TEST( fd_zle_decompress( out, sz, comp, comp_sz )==(long)sz );
  FD_TEST( 0==memcmp( out, in, sz ) );

  ulong iter = 1UL + (1UL<<30)/sz;

  for( ulong i=0UL; i<iter/8UL+1UL; i++ ) sink += fd_zle_compress( comp, in, sz );

  long t0 = fd_log_wallclock();
  for( ulong i=0UL; i<iter; i++ ) sink += fd_zle_compress( comp, in, sz );
  long t1 = fd_log_wallclock();
  for( ulong i=0UL; i<iter; i++ ) sink += (ulong)fd_zle_decompress( out, sz, comp, comp_sz );
  long t2 = fd_log_wallclock();

  double bytes = (double)sz*(double)iter;
  FD_LOG_NOTICE(( "%-24s sz %8lu -> %6.2f%%  enc %6.2f GB/s (%6.3f ns/B)  dec %6.2f GB/s",
                  name, sz, 100.*(double)comp_sz/(double)sz,
                  bytes/(double)(t1-t0), (double)(t1-t0)/bytes,
                  bytes/(double)(t2-t1) ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  uint seed = fd_env_strip_cmdline_uint( &argc, &argv, "--seed", NULL, 42U );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  FD_TEST( rng );

  /* SPL-Token-shaped: mint+owner+amount random, COption fields zero */
  fd_memset( in, 0, 165UL );
  for( ulong j=0UL; j<72UL; j++ ) in[j] = (uchar)( fd_rng_uint( rng ) | 1U );
  in[108] = 1;
  bench( "spl-token 165 B", 165UL );

  /* Serum-shaped: 256 KiB orderbook, ~99.6% zero */
  fd_memset( in, 0, 256UL<<10 );
  for( ulong j=0UL; j<1024UL; j++ ) in[j] = (uchar)( fd_rng_uint( rng ) | 1U );
  bench( "serum 256 KiB", 256UL<<10 );

  /* uniform random: a stray zero every ~256 bytes, none elidable */
  for( ulong j=0UL; j<MAX_SZ; j++ ) in[j] = (uchar)fd_rng_uint( rng );
  bench( "uniform random 8 MiB", MAX_SZ );

  fd_memset( in, 0, MAX_SZ );
  bench( "all-zero 8 MiB", MAX_SZ );

  fd_rng_delete( fd_rng_leave( rng ) );
  fd_halt();
  return 0;
}
