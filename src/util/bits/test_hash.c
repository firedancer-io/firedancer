#include "../fd_util.h"

int
main( int     argc,
      char ** argv ) {

  fd_boot( &argc, &argv );

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

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

