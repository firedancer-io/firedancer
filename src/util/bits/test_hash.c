#include "../fd_util.h"

int
main( int     argc,
      char ** argv ) {

  fd_boot( &argc, &argv );

  int extra_benchmark = fd_env_strip_cmdline_contains( &argc, &argv, "--extra-bench" );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_LOG_NOTICE(( "Testing hash sequences" ));

  static uint const ref32[10] = {
    0x00000000U,
    0x514e28b7U,
    0x30f4c306U,
    0x85f0b427U,
    0x249cb285U,
    0xcc0d53cdU,
    0x5ceb4d08U,
    0x18c9aec4U,
    0x4939650bU,
    0xc27c2913U
  };

  for( int i=0; i<10; i++ ) {
    uint x = (uint)i;
    uint y = fd_uint_hash( x );
    uint z = fd_uint_hash_inverse( y );
    if( y!=ref32[i] ) FD_LOG_ERR(( "FAIL: ref32" ));
    if( x!=z        ) FD_LOG_ERR(( "FAIL: inv32" ));
    if( fd_uint_hash( fd_uint_hash_inverse( x ) )!=x ) FD_LOG_ERR(( "FAIL: INV32" ));
  }

  static ulong const ref64[10] = {
    0x0000000000000000UL,
    0xb456bcfc34c2cb2cUL,
    0x3abf2a20650683e7UL,
    0x0b5181c509f8d8ceUL,
    0x47900468a8f01875UL,
    0xd66ad737d54c5575UL,
    0xe8b4b3b1c77c4573UL,
    0x740729cbe468d1ddUL,
    0x46abcca593a3c687UL,
    0x91209a1ff7f4f1d5UL
  };

  for( int i=0; i<10; i++ ) {
    ulong x = (ulong)i;
    ulong y = fd_ulong_hash( x );
    ulong z = fd_ulong_hash_inverse( y );
    if( y!=ref64[i] ) FD_LOG_ERR(( "FAIL: ref64" ));
    if( x!=z        ) FD_LOG_ERR(( "FAIL: inv64" ));
    if( fd_ulong_hash( fd_ulong_hash_inverse( x ) )!=x ) FD_LOG_ERR(( "FAIL: INV64" ));
  }

  do {
    char const * buf = "The quick brown fox jumps over the lazy dog.";
    ulong        sz  = strlen(buf)+1UL;
    FD_TEST( fd_hash( 0UL, buf, sz )==0xf3f632730b075fa5UL );
    FD_TEST( fd_hash( 1UL, buf, sz )==0x9d33e5e77b3544ceUL );
  } while(0);

  do {
    uchar src[2048]; memset( src, 0, 2048UL );
    uchar dst[2048]; memset( dst, 0, 2048UL );
    for( ulong iter=0UL; iter<1000000UL; iter++ )  {

      ulong _s0 = (ulong)fd_rng_uint_roll( rng, 2049UL );
      ulong _s1 = (ulong)fd_rng_uint_roll( rng, 2049UL );
      ulong s0  = fd_ulong_min( _s0, _s1 );
      ulong s1  = fd_ulong_max( _s0, _s1 );
      ulong sz  = s1-s0;

      ulong d0 = (ulong)fd_rng_uint_roll( rng, (uint)(2049UL-sz) );
      ulong d1 = d0 + sz;

      ulong hs0 = fd_hash( 0UL, src, s0 ); ulong hs1 = fd_hash( 0UL, src+s1, 2048UL-s1 );
      ulong hd0 = fd_hash( 0UL, dst, d0 ); ulong hd1 = fd_hash( 0UL, dst+d1, 2048UL-d1 );

      int c = (int)fd_rng_uchar( rng );
      memset( src+s0, c, sz );
      FD_TEST( fd_memset( dst+d0, c, sz )==(dst+d0) );
      FD_TEST( !memcmp ( dst+d0, src+s0, sz ) );
      FD_TEST( fd_memeq( dst+d0, src+s0, sz ) );
      FD_TEST( fd_hash( 0UL, src, s0 )==hs0 ); FD_TEST( fd_hash( 0UL, src+s1, 2048UL-s1 )==hs1 );
      FD_TEST( fd_hash( 0UL, dst, d0 )==hd0 ); FD_TEST( fd_hash( 0UL, dst+d1, 2048UL-d1 )==hd1 );

      for( ulong b=s0; b<s1; b++ ) src[b] = fd_rng_uchar( rng );

      FD_TEST( fd_memcpy( dst+d0, src+s0, sz )==(dst+d0) );
      FD_TEST( !memcmp ( dst+d0, src+s0, sz ) );
      FD_TEST( fd_memeq( dst+d0, src+s0, sz ) );
      FD_TEST( fd_hash( 0UL, src, s0 )==hs0 ); FD_TEST( fd_hash( 0UL, src+s1, 2048UL-s1 )==hs1 );
      FD_TEST( fd_hash( 0UL, dst, d0 )==hd0 ); FD_TEST( fd_hash( 0UL, dst+d1, 2048UL-d1 )==hd1 );

      for( ulong b=s0; b<s1; b++ ) src[b] = fd_rng_uchar( rng );

      ulong seed = fd_rng_ulong( rng );
      ulong hash = fd_hash( seed, src+s0, sz );
      FD_TEST( fd_hash_memcpy( seed, dst+d0, src+s0, sz )==hash );
      FD_TEST( !memcmp ( dst+d0, src+s0, sz ) );
      FD_TEST( fd_memeq( dst+d0, src+s0, sz ) );

      /* Flip some bits */

      if( sz>0UL ) {
        ulong dflip = d0 + (ulong)fd_rng_uint_roll( rng, (uint)sz );
        int c2 = (int)fd_rng_uchar( rng );
        dst[ dflip ] = (uchar)(dst[ dflip ] ^ (uchar)c2);
        FD_TEST( fd_memeq( dst+d0, src+s0, sz )==(!c2) );
      }
    }
  } while(0);

  ulong seq      = 0UL;
  int   iter_cnt = 1048576;
  int   cnt[ 64*64 ];

  FD_LOG_NOTICE(( "Testing fd_uint_hash avalanche" ));

  do {
    for( int i=0; i<32*32; i++ ) cnt[i] = 0;
    int ctr = 0;
    for( int iter=0; iter<iter_cnt; iter++ ) {
      if( !ctr ) { FD_LOG_NOTICE(( "On iter %i", iter )); ctr = 100000; }
      ctr--;
      uint x    = (uint)(((++seq)*0x9e3779b97f4a7c17UL)>>32); /* Pick a pseudo random-ish x */
      uint hash = fd_uint_hash( x ); /* Get the hash */
      for( int i=0; i<32; i++ ) {
        uint delta = hash ^ fd_uint_hash( hash ^ (1U<<i) );
        for( int j=0; j<32; j++ ) { cnt[i*32+j] += (int)(delta & 1U); delta >>= 1; }
      }
    }
    int  cnt_avg = iter_cnt / 2;
    uint jit_max = 0U;
    for( int i=0; i<32; i++ )
      for( int j=0; j<32; j++ )
        jit_max = fd_uint_max( jit_max, fd_int_abs( cnt[i*32+j] - cnt_avg ) );
    float fluct_max = ((float)jit_max)/((float)iter_cnt);
    if( !(fluct_max<0.005f) ) FD_LOG_ERR(( "FAIL: fluct_max %f", (double)fluct_max ));
    FD_LOG_NOTICE(( "fluct_max %f", (double)fluct_max ));
  } while(0);

  FD_LOG_NOTICE(( "Testing fd_uint_hash_inverse avalanche" ));

  do {
    for( int i=0; i<32*32; i++ ) cnt[i] = 0;
    int ctr = 0;
    for( int iter=0; iter<iter_cnt; iter++ ) {
      if( !ctr ) { FD_LOG_NOTICE(( "On iter %i", iter )); ctr = 100000; }
      ctr--;
      uint x    = (uint)(((++seq)*0x9e3779b97f4a7c17UL)>>32); /* Pick a pseudo random-ish x */
      uint hash = fd_uint_hash_inverse( x ); /* Get the hash */
      for( int i=0; i<32; i++ ) {
        uint delta = hash ^ fd_uint_hash_inverse( hash ^ (1U<<i) );
        for( int j=0; j<32; j++ ) { cnt[i*32+j] += (int)(delta & 1U); delta >>= 1; }
      }
    }
    int  cnt_avg = iter_cnt / 2;
    uint jit_max = 0U;
    for( int i=0; i<32; i++ )
      for( int j=0; j<32; j++ )
        jit_max = fd_uint_max( jit_max, fd_int_abs( cnt[i*32+j] - cnt_avg ) );
    float fluct_max = ((float)jit_max)/((float)iter_cnt);
    if( !(fluct_max<0.005f) ) FD_LOG_ERR(( "FAIL: fluct_max %f", (double)fluct_max ));
    FD_LOG_NOTICE(( "fluct_max %f", (double)fluct_max ));
  } while(0);

  FD_LOG_NOTICE(( "Testing fd_ulong_hash avalanche" ));

  do {
    for( int i=0; i<64*64; i++ ) cnt[i] = 0;
    int ctr = 0;
    for( int iter=0; iter<iter_cnt; iter++ ) {
      if( !ctr ) { FD_LOG_NOTICE(( "On iter %i", iter )); ctr = 100000; }
      ctr--;
      ulong x    = (++seq)*0x9e3779b97f4a7c17UL; /* Pick a pseudo random-ish x */
      ulong hash = fd_ulong_hash( x ); /* Get the hash */
      for( int i=0; i<64; i++ ) {
        ulong delta = hash ^ fd_ulong_hash( hash ^ (1UL<<i) );
        for( int j=0; j<64; j++ ) { cnt[i*64+j] += (int)(delta & 1UL); delta >>= 1; }
      }
    }
    int  cnt_avg = iter_cnt / 2;
    uint jit_max = 0U;
    for( int i=0; i<64; i++ )
      for( int j=0; j<64; j++ )
        jit_max = fd_uint_max( jit_max, fd_int_abs( cnt[i*64+j] - cnt_avg ) );
    float fluct_max = ((float)jit_max)/((float)iter_cnt);
    if( !(fluct_max<0.005f) ) FD_LOG_ERR(( "FAIL: fluct_max %f", (double)fluct_max ));
    FD_LOG_NOTICE(( "fluct_max %f", (double)fluct_max ));
  } while(0);

  FD_LOG_NOTICE(( "Testing fd_ulong_hash_inverse avalanche" ));

  do {
    for( int i=0; i<64*64; i++ ) cnt[i] = 0;
    int ctr = 0;
    for( int iter=0; iter<iter_cnt; iter++ ) {
      if( !ctr ) { FD_LOG_NOTICE(( "On iter %i", iter )); ctr = 100000; }
      ctr--;
      ulong x    = (++seq)*0x9e3779b97f4a7c17UL; /* Pick a pseudo random-ish x */
      ulong hash = fd_ulong_hash_inverse( x ); /* Get the hash */
      for( int i=0; i<64; i++ ) {
        ulong delta = hash ^ fd_ulong_hash_inverse( hash ^ (1UL<<i) );
        for( int j=0; j<64; j++ ) { cnt[i*64+j] += (int)(delta & 1UL); delta >>= 1; }
      }
    }
    int  cnt_avg = iter_cnt / 2;
    uint jit_max = 0U;
    for( int i=0; i<64; i++ )
      for( int j=0; j<64; j++ )
        jit_max = fd_uint_max( jit_max, fd_int_abs( cnt[i*64+j] - cnt_avg ) );
    float fluct_max = ((float)jit_max)/((float)iter_cnt);
    if( !(fluct_max<0.005f) ) FD_LOG_ERR(( "FAIL: fluct_max %f", (double)fluct_max ));
    FD_LOG_NOTICE(( "fluct_max %f", (double)fluct_max ));
  } while(0);

  if( extra_benchmark ) {
    ulong const workload_iter = 1048576UL;
    ulong const warmup        =    1024UL;

    ulong const sizes[] = { 32UL, 64UL, 128UL, 512UL, 4096UL };
    ulong const size_cnt = sizeof(sizes) / sizeof(sizes[0]);
    char buf[ 4096 ] = {0};

    for( ulong j = 0UL; j < size_cnt; j++ ) {
      ulong sz = sizes[j];
      ulong hash = 0UL;
      for( ulong i=0UL; i<warmup; i++ ) {
        hash = fd_hash( hash, buf, sz );
      }
      FD_HW_MFENCE();
      long dt = -fd_log_wallclock();
      for( ulong i = 0UL; i<workload_iter; i++ ) {
        hash = fd_hash( hash, buf, sz );
      }
      dt += fd_log_wallclock();
      FD_COMPILER_UNPREDICTABLE( hash );
      double ns_byte = (double)dt / ((double)workload_iter * (double)sz);
      double gbps    = 8.0 / ns_byte;
      FD_LOG_NOTICE(( "fd_hash: %.3f ns/byte, %.3f Gbps (sz %lu)", ns_byte, gbps, sz ));
    }
  }

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
