#include "fd_lthash_adder.h"

#define TEST_LTHASH_INPUT_MAX (1U<<20) /* 1 MiB */

static uchar
test_lthash_adder_buf[ TEST_LTHASH_INPUT_MAX ];

static void
test_lthash_adder_fill( fd_rng_t * rng,
                        ulong      sz ) {
  FD_TEST( sz<=TEST_LTHASH_INPUT_MAX );
  uchar * p = test_lthash_adder_buf;
  while( sz>4 ) {
    FD_STORE( uint, p, fd_rng_uint( rng ) );
    p  += 4;
    sz -= 4;
  }
  while( sz-- ) {
    *p++ = fd_rng_uchar( rng );
  }
}

void
test_lthash_adder( void ) {
  fd_rng_t rng_[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_, 1234U, 0UL ) );

  FD_TEST( fd_lthash_adder_new( NULL        )==NULL );
  FD_TEST( fd_lthash_adder_new( (void *)1UL )==NULL );
  FD_TEST( fd_lthash_adder_delete( NULL )==NULL );

  fd_lthash_adder_t adder[1];
  fd_lthash_adder_new( adder );
  fd_lthash_adder_delete( adder );

  fd_lthash_value_t sum  [1]; /* sum accumulated by fast hasher */
  fd_lthash_value_t check[1]; /* sum accumulated by reference test code */
  fd_lthash_value_t tmp  [1];
  fd_lthash_zero( sum   );
  fd_lthash_zero( check );
  fd_blake3_t blake
  [1];

  ulong iter_rem = 100000UL;
  int   checked  = 0;
  for(;;) {
    /* Pick a method */
    uint sample            = fd_rng_uint( rng );
    uint method_sample     =  sample     & 127;
    uint size_class_sample = (sample>>7) &  15;
    uint method;
    if(      method_sample< 64 ) method = 0U; /* p ~ 50% */
    else if( method_sample<126 ) method = 1U; /* p ~ 49% */
    else                         method = 2U; /* p ~  1% */
    uint size_class = size_class_sample==0;

    /* Pick an input size */
    uint input_sz = fd_rng_uint( rng );
    if( size_class==1 ) input_sz &= (TEST_LTHASH_INPUT_MAX-1U); /* mod by pow2 */
    else                input_sz  = 128U + (input_sz&256U);

    switch( method ) {
    case 0U: /* test fd_lthash_adder_push */
      /* Generate a random input */
      test_lthash_adder_fill( rng, input_sz );
      fd_blake3_init( blake );
      fd_blake3_append( blake, test_lthash_adder_buf, input_sz );
      fd_blake3_fini_2048( blake, tmp->bytes );
      fd_lthash_add( check, tmp );
      fd_lthash_adder_push( adder, sum, test_lthash_adder_buf, input_sz );
      break;
    case 1U: { /* test fd_lthash_adder_push_solana_account */
      /* Generate an account input */
      input_sz = fd_uint_max( input_sz, 73U ); /* account metadata overhead */
      test_lthash_adder_fill( rng, input_sz );
      fd_blake3_init( blake );
      fd_blake3_append( blake, test_lthash_adder_buf, input_sz );
      fd_blake3_fini_2048( blake, tmp );
      fd_lthash_add( check, tmp );
      ulong         lamports   = FD_LOAD( ulong, test_lthash_adder_buf );
      // /* clobber */ FD_STORE( ulong, test_lthash_adder_buf, 0x4141414141414141UL );
      uchar const * data       = test_lthash_adder_buf + sizeof(ulong);
      ulong const   data_sz    = input_sz - 73U;
      uchar const * tail       = test_lthash_adder_buf + sizeof(ulong) + data_sz;
      uchar         executable = FD_LOAD( uchar, tail );
      uchar const * owner      = tail  +  1;
      uchar const * pubkey     = owner + 32;
      fd_lthash_adder_push_solana_account( adder, sum, pubkey, data, data_sz, lamports, executable, owner );
      break;
    }
    case 2U: /* test fd_lthash_adder_flush */
    check:
      fd_lthash_adder_flush( adder, sum );
      if( FD_UNLIKELY( !fd_memeq( sum, check, sizeof(fd_lthash_value_t) ) ) ) {
        FD_LOG_ERR(( "lthash_adder diverged (iter_rem=%lu)", iter_rem ));
      }
      break;
    }
    if( iter_rem==0UL ) break;
    iter_rem--;
  }

  /* Do a final check before exiting */
  if( !checked ) { checked = 1; goto check; }

  fd_rng_delete( fd_rng_leave( rng ) );
}

/* Regression test: without the FD_LTHASH_ADDER_PARA_CNT<=1 guards,
   builds without AVX crash here due to reads from uninitialized
   batch_ptrs. */

static void
test_lthash_adder_no_avx_regression( void ) {
  fd_lthash_value_t sum[1];
  fd_lthash_value_t check[1];
  fd_lthash_value_t tmp[1];
  fd_lthash_zero( sum );
  fd_lthash_zero( check );

  fd_lthash_adder_t adder[1];
  fd_lthash_adder_new( adder );

  uchar input[128];
  fd_memset( input, 0x42, sizeof(input) );

  /* Push a few small inputs (< 512 bytes) — these take the batching
     path when FD_LTHASH_ADDER_PARA_CNT>1.  On builds without AVX
     (PARA_CNT==1), the old code would dereference NULL batch_ptrs. */
  for( uint i=0; i<4; i++ ) {
    input[0] = (uchar)i;

    fd_blake3_t blake[1];
    fd_blake3_init( blake );
    fd_blake3_append( blake, input, sizeof(input) );
    fd_blake3_fini_2048( blake, tmp->bytes );
    fd_lthash_add( check, tmp );

    fd_lthash_adder_push( adder, sum, input, sizeof(input) );
  }
  fd_lthash_adder_flush( adder, sum );

  FD_TEST( fd_memeq( sum, check, sizeof(fd_lthash_value_t) ) );

  /* Same test via push_solana_account */
  fd_lthash_zero( sum );
  fd_lthash_zero( check );
  fd_lthash_adder_new( adder );

  uchar data[64];
  fd_memset( data, 0xAA, sizeof(data) );
  uchar pubkey[32]; fd_memset( pubkey, 0x01, 32 );
  uchar owner [32]; fd_memset( owner,  0x02, 32 );

  for( uint i=0; i<4; i++ ) {
    data[0] = (uchar)i;
    ulong lamports   = 1000UL + i;
    uchar executable = 0;

    /* Reference: hash the same serialization that push_solana_account
       would produce. */
    fd_blake3_t blake[1];
    fd_blake3_init( blake );
    fd_blake3_append( blake, &lamports, sizeof(ulong) );
    fd_blake3_append( blake, data, sizeof(data) );
    uchar footer[65];
    footer[0] = executable;
    memcpy( footer+1,  owner,  32 );
    memcpy( footer+33, pubkey, 32 );
    fd_blake3_append( blake, footer, sizeof(footer) );
    fd_blake3_fini_2048( blake, tmp->bytes );
    fd_lthash_add( check, tmp );

    fd_lthash_adder_push_solana_account( adder, sum, pubkey, data, sizeof(data), lamports, executable, owner );
  }
  fd_lthash_adder_flush( adder, sum );

  FD_TEST( fd_memeq( sum, check, sizeof(fd_lthash_value_t) ) );

  fd_lthash_adder_delete( adder );
}

static void
bench_lthash_adder( void ) {
  FD_LOG_NOTICE(( "Benchmarking lthash_adder (128 byte input)" ));

  uchar input[ 128 ];
  fd_memset( input, 0x41, sizeof(input) );

  fd_lthash_value_t out[1];
  fd_lthash_adder_t adder[1];

  /* warmup */
  ulong iter_target = 1<<22UL;
  ulong iter = iter_target>>7;
  long dt = fd_log_wallclock();
  fd_lthash_adder_new( adder );
  for( ulong rem=iter; rem; rem-- ) fd_lthash_adder_push( adder, out, input, 128UL );
  fd_lthash_adder_flush( adder, out );
  fd_lthash_adder_delete( adder );
  dt = fd_log_wallclock() - dt;

  /* for real */
  iter = iter_target;
  dt = fd_log_wallclock();
  fd_lthash_adder_new( adder );
  for( ulong rem=iter; rem; rem-- ) fd_lthash_adder_push( adder, out, input, 128UL );
  fd_lthash_adder_flush( adder, out );
  fd_lthash_adder_delete( adder );
  dt = fd_log_wallclock() - dt;

  FD_LOG_NOTICE(( "~%.2e hash/s; %f ns per hash",
                  (double)(((float)(iter))/((float)dt*1e-9f)),
                  (double)dt/(double)iter ));
}
