#include "../fd_vinyl.h"

uchar buffers[8][2048];

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t rng[1]; fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );

  ulong const sz_distr[8] = {
    0UL,
    512UL, 512UL, 512UL, 512UL, 512UL,
    1024UL,
    2048UL };

  long time = 0L;
  ulong useful_sz = 0UL;

  void const * bufs[ 8 ] = { buffers[0], buffers[1], buffers[2], buffers[3], buffers[4], buffers[5], buffers[6], buffers[7] };

  for( ulong rem=1000000UL; rem; rem-- ) {
    ulong szs[8];
    for( ulong i=0UL; i<8UL; i++ ) {
      ulong sz = sz_distr[ fd_rng_uint_roll( rng, 8UL ) ];
      useful_sz += sz;
      szs[ i ] = sz;
      for( ulong j=0UL; j<sz; j+=4UL ) {
        uint r = fd_rng_uint( rng );
        buffers[ i ][ j+0UL ] = (uchar)(r    );
        buffers[ i ][ j+1UL ] = (uchar)(r>> 8);
        buffers[ i ][ j+2UL ] = (uchar)(r>>16);
        buffers[ i ][ j+3UL ] = (uchar)(r>>24);
      }
    }
    ulong seed = fd_rng_ulong( rng );
    ulong out[ 8 ];
    time -= fd_tickcount();
    fd_vinyl_bstream_hash_batch8( seed, out, bufs, szs );
    time += fd_tickcount();

    for( ulong i=0UL; i<8UL; i++ ) {
      ulong expected = szs[i] ? fd_hash( seed, buffers[i], szs[i] ) : seed;
      if( FD_UNLIKELY( expected!=out[ i ] ) ) {
        FD_LOG_ERR(( "mismatch at %lu %lu. sz=%lu. %lx != %lx", rem, i, szs[ i ], out[ i ], expected ));
      }
    }
  }
  double ticks_per_ns = fd_tempo_tick_per_ns( NULL );
  FD_LOG_NOTICE(( "%f byte/ns", (double)useful_sz/((double)time/ticks_per_ns) ));

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
