#include "../fd_ballet.h"
#include "fd_blake3.h"
#include "fd_blake3_private.h"
#include "fd_blake3_test_vector.c"

FD_STATIC_ASSERT( FD_BLAKE3_ALIGN    ==128UL, unit_test );

FD_STATIC_ASSERT( FD_BLAKE3_ALIGN    ==alignof(fd_blake3_t), unit_test );
FD_STATIC_ASSERT( FD_BLAKE3_FOOTPRINT==sizeof (fd_blake3_t), unit_test );

static uchar rand_buf[ 1<<24 ] __attribute__((aligned(64)));
#define chunks_16_hash      (0x9e6ba4480745792fUL)
#define lthash_1024_16_hash (0x565ac69fdbeb1154UL)

static fd_rng_t rng[1];

/* lthash_1024_root_cv is the input chaining value of the root block of
   the hash of the first 1024 bytes of rand buf (so, the output chaining
   value after compressing 960 bytes). */
// __attribute__((aligned(32))) static uchar
// lthash_1024_root_cv[ 32 ] = {
//   0x3f, 0x38, 0x49, 0x5d, 0x8d, 0x95, 0xca, 0x24, 0x94, 0x53, 0xbe, 0xc4, 0xe8, 0x29, 0x7d, 0xb2,
//   0x49, 0xbc, 0x4d, 0xaa, 0xab, 0x91, 0x27, 0x31, 0x12, 0xdb, 0x67, 0xfd, 0x4c, 0x6c, 0x66, 0x3c
// };

static void
check_fixture( uchar const * expected,
               uchar const * msg,
               ulong         sz,
               fd_blake3_t * blake,
               fd_rng_t *    rng ) {

  uchar hash[ 32 ] __attribute__((aligned(32)));

  /* test single shot hashing */

  FD_TEST( fd_blake3_init( blake )==blake );
  FD_TEST( fd_blake3_append( blake, msg, sz )==blake );
  FD_TEST( fd_blake3_fini( blake, hash )==hash );
  if( FD_UNLIKELY( memcmp( hash, expected, 32UL ) ) )
    FD_LOG_ERR(( "FAIL (sz %lu)"
                  "\n\tGot"
                  "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                  "\n\tExpected"
                  "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT, sz,
                  FD_LOG_HEX16_FMT_ARGS(     hash    ), FD_LOG_HEX16_FMT_ARGS(     hash+16 ),
                  FD_LOG_HEX16_FMT_ARGS( expected    ), FD_LOG_HEX16_FMT_ARGS( expected+16 ) ));

  /* test incremental hashing */

  memset( hash, 0, 32UL );
  FD_TEST( fd_blake3_init( blake )==blake );

  uchar const * nxt = msg;
  ulong         rem = sz;
  while( rem ) {
    ulong nxt_sz = fd_ulong_min( rem, fd_rng_ulong_roll( rng, sz+1UL ) );
    FD_TEST( fd_blake3_append( blake, nxt, nxt_sz )==blake );
    nxt += nxt_sz;
    rem -= nxt_sz;
    if( fd_rng_uint( rng ) & 1UL ) FD_TEST( fd_blake3_append( blake, NULL, 0UL )==blake ); /* test zero append too */
  }

  FD_TEST( fd_blake3_fini( blake, hash )==hash );

  if( FD_UNLIKELY( memcmp( hash, expected, 32UL ) ) )
    FD_LOG_ERR(( "FAIL (sz %lu)"
                  "\n\tGot"
                  "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                  "\n\tExpected"
                  "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT, sz,
                  FD_LOG_HEX16_FMT_ARGS(     hash    ), FD_LOG_HEX16_FMT_ARGS(     hash+16 ),
                  FD_LOG_HEX16_FMT_ARGS( expected    ), FD_LOG_HEX16_FMT_ARGS( expected+16 ) ));

  /* test streamlined hashing */

  FD_TEST( fd_blake3_hash( msg, sz, hash )==hash );
  if( FD_UNLIKELY( memcmp( hash, expected, 32UL ) ) )
    FD_LOG_ERR(( "FAIL (sz %lu)"
                  "\n\tGot"
                  "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                  "\n\tExpected"
                  "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT, sz,
                  FD_LOG_HEX16_FMT_ARGS(     hash    ), FD_LOG_HEX16_FMT_ARGS(     hash+16 ),
                  FD_LOG_HEX16_FMT_ARGS( expected    ), FD_LOG_HEX16_FMT_ARGS( expected+16 ) ));
}


static void
test_constructor( void ) {
  FD_TEST( fd_blake3_align    ()==FD_BLAKE3_ALIGN     );
  FD_TEST( fd_blake3_footprint()==FD_BLAKE3_FOOTPRINT );

  fd_blake3_t mem[1];

  FD_TEST( fd_blake3_new( NULL          )==NULL ); /* null shmem       */
  FD_TEST( fd_blake3_new( (void *)0x1UL )==NULL ); /* misaligned shmem */

  void * obj = fd_blake3_new( mem ); FD_TEST( obj );

  FD_TEST( fd_blake3_join( NULL           )==NULL ); /* null shsha       */
  FD_TEST( fd_blake3_join( (void *) 0x1UL )==NULL ); /* misaligned shsha */

  fd_blake3_t * blake = fd_blake3_join( obj ); FD_TEST( blake );

  FD_TEST( fd_blake3_leave( NULL )==NULL ); /* null sha */
  FD_TEST( fd_blake3_leave( blake  )==obj  ); /* ok */

  FD_TEST( fd_blake3_delete( NULL          )==NULL ); /* null shsha       */
  FD_TEST( fd_blake3_delete( (void *)0x1UL )==NULL ); /* misaligned shsha */
  FD_TEST( fd_blake3_delete( obj           )==mem  ); /* ok */
}

static void
test_small_fixtures( void ) {
  fd_blake3_t blake_[1];
  fd_blake3_t * blake = fd_blake3_join( fd_blake3_new( blake_ ) );
  for( fd_blake3_test_vector_t const * vec = fd_blake3_test_vector; vec->msg; vec++ ) {
    check_fixture( vec->hash, (uchar const *)vec->msg, vec->sz, blake, rng );
  }
  fd_blake3_delete( fd_blake3_leave( blake ) );
}

#if FD_HAS_AVX

static void
test_avx_compress8_fast( void ) {
  uchar block_res[ 512 ] __attribute__((aligned(32)));
  uchar const * block_in = rand_buf;
  fd_blake3_avx_compress8_fast( block_in,      block_res,     0UL, 0 );
  fd_blake3_avx_compress8_fast( block_in+8192, block_res+256, 8UL, 0 );
  ulong chunks_16_have = fd_hash( 0UL, block_res, 512UL );
  if( FD_UNLIKELY( chunks_16_hash!=chunks_16_have ) ) {
    FD_LOG_ERR(( "fd_blake3_avx_compress8_fast failed (expected %016lx got %016lx)",
                 chunks_16_hash, chunks_16_have ));
  }
}

static void
test_avx_compress8( void ) {
  uchar block_res[ 512 ] __attribute__((aligned(32)));
  uchar const * block_in = rand_buf;
  ulong  batch_data [ 8 ] __attribute__((aligned(32)));
  /*                    */ for( uint i=0; i<8; i++ ) batch_data [i] = (ulong)( block_in + 1024*i );
  uint   batch_sz   [ 8 ]; for( uint i=0; i<8; i++ ) batch_sz   [i] = 1024UL;
  void * batch_hash [ 8 ]; for( uint i=0; i<8; i++ ) batch_hash [i] = block_res + 32*i;
  ulong  ctr_vec    [ 8 ]; for( uint i=0; i<8; i++ ) ctr_vec    [i] = i;
  uint   batch_flags[ 8 ]; for( uint i=0; i<8; i++ ) batch_flags[i] = 0;
  fd_blake3_avx_compress8( 8UL, batch_data, batch_sz, ctr_vec, batch_flags, batch_hash, NULL, 32U, NULL );
  for( uint i=0; i<8; i++ ) batch_data[ i ] = (ulong)( block_in + 1024*(8+i) );
  for( uint i=0; i<8; i++ ) batch_hash[ i ] = block_res + 32*(8+i);
  for( uint i=0; i<8; i++ ) ctr_vec   [ i ] = 8+i;
  fd_blake3_avx_compress8( 8UL, batch_data, batch_sz, ctr_vec, batch_flags, batch_hash, NULL, 32U, NULL );
  ulong chunks_16_have = fd_hash( 0UL, block_res, 512UL );
  if( FD_UNLIKELY( chunks_16_hash!=chunks_16_have ) ) {
    FD_LOG_ERR(( "fd_blake3_avx_compress8 failed (expected %016lx got %016lx)",
                  chunks_16_hash, chunks_16_have ));
  }
}

static void
test_avx_compress8_xof2048_para( void ) {
  void const * data[ 16 ] __attribute__((aligned(32)));
  for( uint i=0; i<16; i++ ) data[ i ] = rand_buf + 1024*i;
  uint sz[ 8 ];
  for( uint i=0; i< 8; i++ ) sz  [ i ] = 1024UL;

  ushort lthash0[ 1024 ] __attribute__((aligned(32)));
  ushort lthash1[ 1024 ] __attribute__((aligned(32)));
  fd_blake3_lthash_batch8( data,   sz, lthash0 );
  fd_blake3_lthash_batch8( data+8, sz, lthash1 );

  for( ulong i=0UL; i<1024UL; i++ ) lthash0[i] = (ushort)( lthash0[i] + lthash1[i] );
  FD_TEST( fd_hash( 0UL, lthash0, 2048UL )==lthash_1024_16_hash );

  ulong iter = 100000UL;
  while( iter-- ) {
    for( ulong i=0UL; i<8UL; i++ ) {
      data[ i ] = rand_buf + fd_rng_uint_roll( rng, (uint)sizeof(rand_buf)-1024U );
      sz  [ i ] = fd_rng_uint_roll( rng, 1025UL );
    }
    fd_blake3_lthash_batch8( data, sz, lthash0 );
    ushort lthash2[ 1024 ] = {0};
    for( ulong i=0UL; i<8UL; i++ ) {
      fd_blake3_t blake[1];
      fd_blake3_init( blake );
      fd_blake3_append( blake, data[i], sz[i] );
      ushort lthash3[ 1024 ] __attribute__((aligned(64)));
      fd_blake3_fini_2048( blake, lthash3 );
      for( ulong j=0UL; j<1024UL; j++ ) lthash2[j] = (ushort)( lthash2[j] + lthash3[j] );
    }
    if( FD_UNLIKELY( !fd_memeq( lthash0, lthash2, 2048 ) ) ) {
      FD_LOG_ERR(( "fd_blake3_lthash_batch8 computed wrong result: sz=[%u %u %u %u %u %u %u %u]",
                   sz[0x0], sz[0x1], sz[0x2], sz[0x3], sz[0x4], sz[0x5], sz[0x6], sz[0x7] ));
    }
  }
}

static void
test_avx_compress8_xof2048_seq( void ) {
  ushort lthash[ 1024 ] = {0};
  for( ulong j=0UL; j<16UL; j++ ) {
    uchar root_msg   [ 64 ] __attribute__((aligned(64)));
    uchar root_cv_pre[ 32 ] __attribute__((aligned(32)));
    fd_blake3_t blake[1];
    fd_blake3_init( blake );
    fd_blake3_append( blake, rand_buf+(1024*j), 1024UL );
    fd_blake3_fini_xof_compress( blake, root_msg, root_cv_pre );

    ulong  batch_data [  8 ] __attribute__((aligned(32)));
    /*                     */ for( uint i=0; i< 8; i++ ) batch_data [i] = (ulong)root_msg;
    uint   batch_sz   [  8 ]; for( uint i=0; i< 8; i++ ) batch_sz   [i] = 64UL;
    ulong  ctr_vec    [ 32 ]; for( uint i=0; i<32; i++ ) ctr_vec    [i] = i;
    uint   batch_flags[  8 ]; for( uint i=0; i< 8; i++ ) batch_flags[i] = FD_BLAKE3_FLAG_ROOT | FD_BLAKE3_FLAG_CHUNK_END;
    ulong  batch_cv   [  8 ]; for( uint i=0; i< 8; i++ ) batch_cv   [i] = (ulong)root_cv_pre;
    ushort xof2048[ 1024 ] __attribute__((aligned(32)));
    void * batch_hash [ 32 ]; for( uint i=0; i<32; i++ ) batch_hash [i] = xof2048 + 32*i; /* 64 byte stride */
    fd_blake3_avx_compress8( 8UL, batch_data, batch_sz, ctr_vec,    batch_flags, batch_hash,    NULL, 64U, batch_cv );
    fd_blake3_avx_compress8( 8UL, batch_data, batch_sz, ctr_vec+ 8, batch_flags, batch_hash+ 8, NULL, 64U, batch_cv );
    fd_blake3_avx_compress8( 8UL, batch_data, batch_sz, ctr_vec+16, batch_flags, batch_hash+16, NULL, 64U, batch_cv );
    fd_blake3_avx_compress8( 8UL, batch_data, batch_sz, ctr_vec+24, batch_flags, batch_hash+24, NULL, 64U, batch_cv );
    for( ulong i=0UL; i<1024UL; i++ ) lthash[i] = (ushort)( lthash[i] + xof2048[i] );
  }

  if( FD_UNLIKELY( fd_hash( 0UL, lthash, sizeof(lthash) )!=lthash_1024_16_hash ) ) {
    FD_LOG_ERR(( "test_avx_compress8_xof2048_seq computed wrong result" ));
  }
}

#endif /* FD_HAS_AVX */

#if FD_HAS_AVX512

static void
test_avx512_compress16_fast( void ) {
  uchar block_res[ 512 ] __attribute__((aligned(32)));
  fd_blake3_avx512_compress16_fast( rand_buf, block_res, 0UL, 0 );
  ulong chunks_16_have = fd_hash( 0UL, block_res, 512UL );
  if( FD_UNLIKELY( chunks_16_hash!=chunks_16_have ) ) {
    FD_LOG_ERR(( "fd_blake3_avx512_compress16_fast failed (expected %016lx got %016lx)",
                 chunks_16_hash, chunks_16_have ));
  }
}

static void
test_avx512_compress16( void ) {
  uchar block_res[ 512 ] __attribute__((aligned(32)));
  ulong  batch_data [ 16 ] __attribute__((aligned(64)));
  /*                     */ for( uint i=0; i<16; i++ ) batch_data [i] = (ulong)( rand_buf + 1024*i );
  uint   batch_sz   [ 16 ]; for( uint i=0; i<16; i++ ) batch_sz   [i] = 1024UL;
  void * batch_hash [ 16 ]; for( uint i=0; i<16; i++ ) batch_hash [i] = block_res + 32*i;
  ulong  ctr_vec    [ 16 ]; for( uint i=0; i<16; i++ ) ctr_vec    [i] = i;
  uint   batch_flags[ 16 ]; for( uint i=0; i<16; i++ ) batch_flags[i] = 0;
  fd_blake3_avx512_compress16( 16UL, batch_data, batch_sz, ctr_vec, batch_flags, batch_hash, NULL, 32U, NULL );
  ulong chunks_16_have = fd_hash( 0UL, block_res, 512UL );
  if( FD_UNLIKELY( chunks_16_hash!=chunks_16_have ) ) {
    FD_LOG_ERR(( "fd_blake3_avx512_compress16 failed (expected %016lx got %016lx)",
                  chunks_16_hash, chunks_16_have ));
  }
}

static void
test_avx512_compress16_xof2048_para( void ) {
  void const * data[ 16 ] __attribute__((aligned(64)));
  for( uint i=0; i<16; i++ ) data[ i ] = rand_buf + 1024*i;
  uint sz[ 16 ];
  for( uint i=0; i<16; i++ ) sz  [ i ] = 1024UL;

  ushort lthash[ 1024 ] __attribute__((aligned(64)));
  fd_blake3_lthash_batch16( data, sz, lthash );
  if( FD_UNLIKELY( fd_hash( 0UL, lthash, sizeof(lthash) )!=lthash_1024_16_hash ) ) {
    uchar expected32[ 32 ];
    fd_blake3_hash( rand_buf, 1024UL, expected32 );
    FD_LOG_HEXDUMP_WARNING(( "lthash[0..32] want", expected32, 32 ));
    FD_LOG_HEXDUMP_WARNING(( "lthash[0..32] have", lthash,     32 ));
    FD_LOG_ERR(( "test_avx512_compress16_xof2048_para computed wrong result" ));
  }

  ulong iter = 100000UL;
  while( iter-- ) {
    for( ulong i=0UL; i<16UL; i++ ) {
      data[ i ] = rand_buf + fd_rng_uint_roll( rng, (uint)sizeof(rand_buf)-1024U );
      sz  [ i ] = fd_rng_uint_roll( rng, 1025UL );
    }
    fd_blake3_lthash_batch16( data, sz, lthash );
    ushort lthash2[ 1024 ] = {0};
    for( ulong i=0UL; i<16UL; i++ ) {
      fd_blake3_t blake[1];
      fd_blake3_init( blake );
      fd_blake3_append( blake, data[i], sz[i] );
      ushort lthash3[ 1024 ] __attribute__((aligned(64)));
      fd_blake3_fini_2048( blake, lthash3 );
      for( ulong j=0UL; j<1024UL; j++ ) lthash2[j] = (ushort)( lthash2[j] + lthash3[j] );
    }
    if( FD_UNLIKELY( !fd_memeq( lthash, lthash2, 2048 ) ) ) {
      FD_LOG_ERR(( "fd_blake3_lthash_batch16 computed wrong result: sz=[%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u]",
                   sz[0x0], sz[0x1], sz[0x2], sz[0x3], sz[0x4], sz[0x5], sz[0x6], sz[0x7],
                   sz[0x8], sz[0x9], sz[0xa], sz[0xb], sz[0xc], sz[0xd], sz[0xe], sz[0xf] ));
    }
  }
}

static void
test_avx512_compress16_xof2048_seq( void ) {
  ushort lthash[ 1024 ] = {0};
  for( ulong j=0UL; j<16UL; j++ ) {
    uchar root_msg   [ 64 ] __attribute__((aligned(64)));
    uchar root_cv_pre[ 32 ] __attribute__((aligned(32)));
    fd_blake3_t blake[1];
    fd_blake3_init( blake );
    fd_blake3_append( blake, rand_buf+(1024*j), 1024UL );
    fd_blake3_fini_xof_compress( blake, root_msg, root_cv_pre );

    ulong  batch_data [ 16 ] __attribute__((aligned(64)));
    /*                     */ for( uint i=0; i<16; i++ ) batch_data [i] = (ulong)root_msg;
    uint   batch_sz   [ 16 ]; for( uint i=0; i<16; i++ ) batch_sz   [i] = 64UL;
    ulong  ctr_vec    [ 32 ]; for( uint i=0; i<32; i++ ) ctr_vec    [i] = i;
    uint   batch_flags[ 16 ]; for( uint i=0; i<16; i++ ) batch_flags[i] = FD_BLAKE3_FLAG_ROOT | FD_BLAKE3_FLAG_CHUNK_END;
    ulong  batch_cv   [ 16 ]; for( uint i=0; i<16; i++ ) batch_cv   [i] = (ulong)root_cv_pre;
    ushort xof2048[ 1024 ] __attribute__((aligned(64)));
    void * batch_hash [ 32 ]; for( uint i=0; i<32; i++ ) batch_hash [i] = xof2048 + 32*i; /* 64 byte stride */
    fd_blake3_avx512_compress16( 16UL, batch_data, batch_sz, ctr_vec,    batch_flags, batch_hash,    NULL, 64U, batch_cv );
    fd_blake3_avx512_compress16( 16UL, batch_data, batch_sz, ctr_vec+16, batch_flags, batch_hash+16, NULL, 64U, batch_cv );
    for( ulong i=0UL; i<1024UL; i++ ) lthash[i] = (ushort)( lthash[i] + xof2048[i] );
  }

  if( FD_UNLIKELY( fd_hash( 0UL, lthash, sizeof(lthash) )!=lthash_1024_16_hash ) ) {
    FD_LOG_ERR(( "test_avx512_compress16_xof2048_seq computed wrong result" ));
  }
}

#endif /* FD_HAS_AVX512 */

  /* Run through random preimage tests */

  static const struct { ulong sz; uchar hash[32]; } test_fixtures[] = {
    {     64, {0x8e,0x78,0x6e,0x0a,0x39,0x5b,0xff,0x26,0x43,0x11,0x5e,0x32,0x12,0xc0,0xb3,0x01,0xa9,0xf8,0xd7,0x82,0x9c,0xe5,0x55,0x7b,0x12,0x53,0x63,0x48,0x11,0xb3,0x07,0x0a} },
    {    128, {0x16,0xbb,0x9d,0x92,0x1f,0xf7,0x75,0x0b,0xd6,0xe1,0xf3,0x60,0xa2,0x7b,0x2f,0x5f,0xe7,0x85,0x38,0xb3,0xbf,0xfe,0xcb,0x4d,0x21,0x25,0xd9,0x4f,0x8a,0xc7,0xfb,0x99} },
    {    256, {0x69,0x33,0x78,0x3f,0xc6,0x50,0x4e,0x8c,0x19,0x06,0x96,0x1f,0x96,0xda,0xa6,0xcb,0xe3,0x30,0xa9,0x08,0xe4,0x4f,0x22,0x50,0x73,0x62,0x4e,0x2a,0xc7,0xf0,0xf4,0xc2} },
    {    512, {0x58,0xea,0xbd,0x0c,0xa7,0xea,0x6c,0x70,0x41,0xb3,0x21,0x7b,0x53,0x27,0xbd,0x00,0xda,0xc6,0xb2,0x15,0x72,0x9a,0xbe,0x19,0x74,0x30,0x17,0x05,0xd4,0xe2,0xfa,0xfd} },
    {   1024, {0xe6,0x0f,0x0a,0xd7,0xc9,0xdb,0x47,0xa9,0x1b,0x7c,0xe4,0x49,0xeb,0x1d,0xc6,0x5f,0xee,0xf2,0xcf,0x43,0x12,0xd6,0xe1,0xb1,0xfa,0xd7,0x3e,0x79,0x03,0xce,0xb2,0xe3} },
    {   1536, {0xcb,0xe6,0x93,0x8f,0x0d,0x73,0x6c,0xd9,0xad,0x5e,0x9f,0x0b,0x37,0x06,0x6c,0xfe,0xaa,0xfa,0x83,0x83,0x8a,0x13,0x95,0x53,0x49,0x3a,0xd8,0xb5,0xe3,0xa6,0x9d,0x2c} },
    {   2048, {0x46,0x24,0x6b,0xc2,0xf5,0xc0,0x5d,0xe6,0xbc,0xd8,0xad,0x81,0xc1,0x74,0xbe,0xe8,0x6f,0xe6,0xde,0xce,0xf9,0x0f,0xca,0x81,0x08,0x1a,0x97,0xc1,0x80,0xf2,0x34,0x25} },
    {   2560, {0x1a,0x75,0x49,0x9f,0x44,0x64,0xe4,0xe9,0xa9,0x3c,0xa6,0x9b,0x0c,0xc1,0x48,0xed,0x77,0xc7,0x6e,0x06,0xc0,0xb0,0x50,0xcd,0x92,0xbc,0x5b,0x62,0x72,0xbb,0xce,0x63} },
    {   3072, {0x91,0xaf,0x45,0x38,0x21,0x83,0xc4,0x6d,0xa1,0x22,0x28,0x8c,0x32,0x2b,0x80,0xf9,0xb1,0x9f,0x94,0xbc,0x24,0x06,0xe8,0xcc,0x9d,0x13,0xc9,0x4f,0xbe,0x2b,0x5d,0xe2} },
    {   4096, {0xbc,0xdb,0x49,0xf0,0x74,0x15,0x9b,0x24,0x20,0xaa,0x52,0x0a,0x9c,0x94,0x83,0x67,0xa5,0xe7,0xa0,0x17,0xa8,0x77,0x87,0xf9,0x4f,0x74,0x99,0x9e,0x75,0x40,0x15,0xcf} },
    {   5120, {0x62,0x62,0x30,0xf7,0x3f,0x2f,0x66,0x76,0x0c,0x28,0x50,0x8c,0xf5,0x21,0x69,0x92,0x41,0xf1,0xa7,0xe8,0x48,0x03,0x68,0xe0,0xe5,0x34,0xcd,0x43,0x36,0x0b,0xeb,0x2e} },
    {   6144, {0x31,0xbf,0x52,0x72,0x5d,0xf1,0xd6,0xc5,0xb7,0x08,0x05,0x99,0x1b,0x81,0x06,0xe9,0x25,0x57,0x42,0xaa,0x29,0xd2,0x96,0x9f,0x8f,0xb9,0x74,0xf4,0xf1,0xef,0x89,0x29} },
    {   7168, {0x9b,0x5a,0x42,0x31,0xda,0x7a,0x8d,0xf0,0x2d,0xa4,0x88,0x7a,0xd6,0x67,0x4d,0xa1,0x01,0x49,0x1d,0x43,0xa4,0x34,0xfc,0x21,0xbb,0x0b,0x8c,0x1d,0xcd,0x9d,0x0a,0xa5} },
    {   8192, {0x93,0x01,0x1d,0x11,0x98,0xfb,0x6a,0xe5,0xfc,0x93,0xc0,0x7a,0xf6,0x74,0xc8,0x79,0x30,0x8d,0xd2,0x4d,0x74,0x45,0x68,0xde,0xc9,0xc0,0x7d,0x52,0x81,0x57,0xb4,0xc9} },
    {   8704, {0x7e,0x1f,0x44,0x9b,0xc1,0x5b,0x33,0x7a,0x4f,0x59,0x37,0xfd,0x4a,0xa0,0xa6,0xfb,0x86,0xe0,0x8a,0xa6,0x4d,0x6b,0xde,0x1e,0x59,0x4e,0xc0,0x65,0x33,0xcc,0x25,0x96} },
    {   9216, {0xa8,0x8d,0xc5,0xe8,0xbd,0x3f,0xd9,0xd7,0x1e,0x58,0xcd,0x06,0x71,0x7d,0x37,0xd8,0x84,0xaa,0x04,0xd0,0xcf,0x4f,0x84,0x86,0xe4,0xbc,0x13,0x12,0xd5,0xf1,0x31,0x83} },
    {   9728, {0x1f,0xd1,0xf8,0x74,0xec,0xa7,0x73,0x18,0x17,0x1d,0x41,0x3a,0xf1,0x5b,0x47,0xe1,0x72,0xe6,0x87,0xcd,0x39,0x38,0xdb,0x55,0xb2,0x25,0x21,0xaa,0x54,0xdc,0x7f,0x80} },
    {  10240, {0x4f,0x97,0x7f,0x5f,0xa1,0x07,0xa2,0xb9,0xf9,0x74,0x88,0xae,0xc2,0xdd,0x96,0x17,0x72,0xb0,0xad,0x1c,0x3b,0xe1,0xb0,0x0f,0x71,0x5a,0x70,0xec,0x9e,0xa2,0x74,0x32} },
    {  10752, {0xc9,0xea,0xd9,0x36,0x34,0x7d,0xb7,0xf4,0xd2,0xb4,0xfe,0xd0,0xf7,0x2d,0x0b,0x63,0xc9,0x57,0x26,0x17,0x6e,0xda,0x2e,0x0a,0xeb,0x1d,0xb4,0x77,0x30,0xb9,0x19,0x43} },
    {  11264, {0x2a,0xb7,0x37,0x0b,0x8f,0x48,0xf2,0xa7,0x12,0x7c,0x3f,0xc3,0xad,0xcb,0x0f,0x89,0x98,0x8b,0x35,0xe6,0x0c,0x36,0x33,0x9d,0xd0,0xb5,0x13,0x29,0x2f,0xcc,0x0c,0x4d} },
    {  11776, {0x1f,0xc8,0x45,0xff,0x4a,0xe1,0xb6,0x3f,0x07,0xaa,0xd8,0xf2,0x1c,0x4f,0x5f,0x43,0x4c,0xd2,0x1f,0x61,0xd5,0x32,0x32,0xac,0x0c,0xaf,0x60,0x0b,0x95,0xa4,0xef,0x6d} },
    {  12288, {0x28,0x78,0x16,0xb9,0x63,0x6d,0x20,0xb0,0x61,0xab,0xb4,0x95,0xf4,0xc4,0x6a,0x0d,0xe3,0x5f,0x51,0x82,0x9c,0x60,0xe7,0x92,0xad,0xdf,0xf1,0x9f,0x24,0x9d,0x9e,0x41} },
    {  12800, {0xb2,0x86,0xff,0x43,0xbe,0x3b,0xbb,0xf0,0x60,0x05,0x00,0xdd,0x17,0x9e,0x6b,0xc6,0x3f,0x7f,0x3a,0x1e,0x29,0x3e,0xda,0x5a,0xcc,0x5c,0x67,0x87,0xea,0x72,0xe4,0xec} },
    {  13312, {0x31,0xf8,0x25,0x9d,0x9b,0x5f,0xe5,0xf8,0xac,0xaf,0x6d,0x1a,0xf7,0x53,0x48,0x6d,0x08,0x8e,0xcb,0x2d,0x38,0xbb,0xb7,0x29,0xf8,0xde,0xad,0x09,0x3d,0xc8,0xe0,0x55} },
    {  13824, {0x2c,0xa0,0x2a,0x8f,0x4b,0x78,0xf8,0x3b,0xf0,0x65,0x11,0xe0,0x21,0x31,0xb4,0xd9,0x5c,0xbc,0x33,0x64,0x33,0x87,0xbc,0x55,0xf5,0x1d,0x34,0xb4,0x02,0x27,0x2d,0x25} },
    {  14336, {0x6b,0x2e,0xb8,0xf6,0xf1,0x73,0x8b,0xe2,0x05,0xb5,0x5a,0x91,0xb8,0x66,0xac,0x1a,0x0b,0xcd,0x66,0xa2,0x79,0x42,0xff,0x4c,0xaa,0x28,0x9d,0xb3,0x3d,0x6a,0x14,0x5e} },
    {  14848, {0x34,0x20,0x76,0x40,0x87,0xdf,0xc1,0xda,0x72,0xd3,0xf7,0xf3,0xaa,0x0d,0xb9,0x51,0x73,0xb9,0x06,0x50,0x1b,0xe2,0x03,0x52,0xfd,0xfb,0xca,0x50,0xf5,0x3e,0xbc,0x77} },
    {  15360, {0x8f,0x81,0x9f,0x30,0x42,0x44,0x8d,0xc8,0xcf,0xc0,0xc6,0x4a,0x36,0x31,0x61,0x41,0x44,0x76,0x89,0x3b,0x9c,0x50,0x31,0x85,0xa3,0x65,0x9d,0x38,0xbc,0xdf,0xc1,0x32} },
    {  15872, {0xc6,0xd2,0x5b,0x4e,0x48,0xf3,0x77,0xef,0x42,0x5d,0xb4,0x9f,0xb4,0xe7,0x49,0x7d,0x8e,0x11,0xd9,0xa9,0x0c,0x22,0xf3,0x10,0xe5,0x3c,0xe2,0x2d,0x40,0xc1,0x28,0xe8} },
    {  16384, {0x18,0xdf,0x04,0xb9,0xd9,0x39,0x65,0x64,0x5a,0xd3,0x1d,0x32,0x31,0x71,0xf0,0x04,0x3b,0x52,0x7f,0x59,0x64,0x02,0x42,0x40,0xee,0x18,0xda,0x24,0xe1,0x02,0xe8,0xa2} },
    {  16385, {0xac,0xe0,0x15,0xdd,0xfa,0x44,0x1a,0x5c,0x30,0x90,0x89,0x74,0xd0,0xaf,0xe3,0x19,0xf6,0x82,0xa3,0x6d,0x8b,0xdd,0x6e,0x3a,0x19,0xc8,0xd4,0x2a,0xb7,0x09,0xeb,0x03} },
    {  24575, {0x2b,0x7d,0xe4,0x8d,0x19,0x74,0x8a,0x5e,0xac,0x1b,0x10,0xd1,0xcb,0x06,0x07,0x1a,0xc7,0x02,0x51,0x75,0x61,0x8d,0x76,0xd7,0x41,0xee,0x57,0x33,0x20,0xe9,0xc4,0x8f} },
    {  32768, {0x14,0x93,0x4b,0x79,0x56,0xa6,0x43,0x6a,0x67,0x9d,0x01,0x37,0x43,0x10,0x9c,0x28,0xea,0x2f,0x10,0x88,0xc7,0xfc,0xb3,0x31,0x87,0x38,0x6b,0xe0,0x00,0xe0,0x83,0x3d} },
    {  32769, {0x7b,0xdb,0xe3,0xc9,0xe9,0xcd,0x48,0x7d,0x8f,0xc5,0x03,0x0b,0x9c,0x16,0x46,0x14,0x72,0xb3,0x3e,0xae,0x42,0xa0,0x33,0xf3,0x9c,0x79,0x3f,0xe5,0xa7,0x7c,0x3b,0x87} },
    { 131072, {0x8a,0x98,0xa1,0x96,0x6a,0x97,0x30,0xb3,0xc8,0xb8,0x2e,0x2a,0xd6,0x06,0xed,0x57,0xfa,0xc2,0x12,0x27,0x3a,0xf3,0xcb,0x76,0xe1,0xf1,0x3f,0x7a,0x1e,0x44,0xfd,0xc6} },
    { 131073, {0x8f,0xd1,0x92,0x3a,0x05,0x03,0x09,0xe2,0x8f,0x99,0x0c,0x33,0xf9,0xa2,0x7b,0xb3,0x86,0x50,0x29,0xa6,0xdc,0x39,0x26,0x96,0x58,0xda,0x03,0x65,0xa3,0x60,0xbf,0x4a} },
    { 262144, {0x94,0xda,0x5d,0x5f,0xb7,0x48,0xe7,0x2e,0x94,0x47,0xfc,0x52,0x90,0x8f,0x6e,0xf0,0x51,0x91,0xd9,0xf8,0xee,0x4b,0x48,0x6a,0x50,0x41,0x6f,0xa7,0xa4,0x57,0x5d,0x24} },
    { 262145, {0xba,0xf8,0x15,0x48,0xde,0xc6,0x2b,0x7c,0xea,0x70,0xd1,0x71,0x98,0x31,0xae,0x21,0x2a,0xf0,0x8d,0xf8,0xb8,0xfe,0x46,0xe8,0x9d,0xce,0x7d,0xdc,0xac,0xd5,0x5f,0x28} },
    { 524288, {0xd3,0xb4,0x34,0xce,0x23,0x3d,0x85,0xa5,0xeb,0x07,0xe7,0x33,0x1d,0x9f,0xc1,0xcf,0x51,0xa6,0x3f,0x36,0x1d,0xa2,0x23,0xfb,0x35,0xea,0x6b,0x2f,0x84,0xaf,0x95,0xce} },
    { 524289, {0x9f,0x05,0x67,0xce,0xbe,0xce,0x9c,0xdf,0x80,0xb1,0x45,0x7f,0xd8,0x3a,0x45,0xaf,0x0b,0xfc,0xa2,0x51,0x23,0xd6,0xf8,0x57,0x62,0xc2,0xad,0x67,0xeb,0xad,0x73,0x8c} },
    {0}
  };

static void
test_rand_fixtures( void ) {
  fd_blake3_t blake_[1];
  fd_blake3_t * blake = fd_blake3_join( fd_blake3_new( blake_ ) );
  for( ulong j=0UL; test_fixtures[j].sz; j++ ) {
    check_fixture( test_fixtures[j].hash, rand_buf, test_fixtures[j].sz, blake, rng );
  }
  fd_blake3_delete( fd_blake3_leave( blake ) );
}

static void
test_reduced( void ) {
  fd_blake3_t blake_[1];
  fd_blake3_t * blake = fd_blake3_join( fd_blake3_new( blake_ ) );

  /* Hash every message from 0 to 16MiB and ensure that the various APIs agree */

  uchar hash [ 32 ] __attribute__((aligned(32)));
  uchar hash2[ 32 ] __attribute__((aligned(32)));

  static uchar buf[ 1<<24 ] __attribute__((aligned(32)));
  for( ulong b=0UL; b<sizeof(buf); b+=8 ) FD_STORE( ulong, buf+b, fd_rng_ulong( rng ) );

  for( ulong sz=0UL; sz<=524289; sz+=61 ) {
    /* test streamlined hashing */
    fd_blake3_hash( buf, sz, hash );

    /* test single shot hashing */
    fd_blake3_fini( fd_blake3_append( fd_blake3_init( blake ), buf, sz ), hash2 );
    FD_TEST( 0==memcmp( hash, hash2, 32UL ) );

    /* test incremental hashing */
    fd_blake3_init( blake );
    uchar const * nxt = buf;
    ulong         rem = sz;
    while( rem ) {
      ulong nxt_sz = fd_ulong_min( rem, fd_rng_ulong_roll( rng, sz+1UL ) );
      fd_blake3_append( blake, nxt, nxt_sz );
      nxt += nxt_sz;
      rem -= nxt_sz;
      if( fd_rng_uint( rng ) & 1UL ) fd_blake3_append( blake, NULL, 0UL ); /* test zero append too */
    }
    fd_blake3_fini( blake, hash2 );
    FD_TEST( 0==memcmp( hash, hash2, 32UL ) );
  }

  fd_blake3_delete( fd_blake3_leave( blake ) );
}

static void
test_reduced_xof2048( void ) {
  fd_rng_t rng_[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_, 1U, 0UL ) );

  ulong acc = 0UL;
  uchar input[ 65536 ];
  uchar hash [  2048 ];
  for( ulong sz=0UL; sz<=sizeof(input); sz++ ) {
    fd_blake3_t blake[1];
    fd_blake3_init( blake );
    for( ulong j=0UL; j<sz; j++ ) input[ j ] = fd_rng_uchar( rng );
    fd_blake3_append( blake, input, sz );
    fd_blake3_fini_2048( blake, hash );
    acc ^= fd_hash( 0UL, hash, sizeof(hash) );
  }
  FD_TEST( acc==0x79836ea1df1a342aUL );

  fd_rng_delete( fd_rng_leave( rng ) );
}

static void
test_lthash( void ) {
  fd_blake3_t blake_[1];
  fd_blake3_t * blake = fd_blake3_join( fd_blake3_new( blake_ ) );

  uchar const * in = rand_buf;
  ushort lthash[ 1024 ] = {0};
  for( ulong i=0UL; i<16UL; i++ ) {
    fd_blake3_init( blake );
    fd_blake3_append( blake, in, 1024UL );
    uchar ele2[32];
    fd_blake3_fini( blake, ele2 );

    fd_blake3_init( blake );
    fd_blake3_append( blake, in, 1024UL );
    in += 1024UL;
    ushort ele[ 1024 ] = {0};
    fd_blake3_fini_2048( blake, ele );
    FD_TEST( fd_memeq( ele, ele2, 32UL ) );
    for( ulong j=0UL; j<1024UL; j++ ) lthash[ j ] = (ushort)( lthash[ j ] + ele[ j ] );
  }
  FD_TEST( fd_hash( 0UL, lthash, sizeof(lthash) )==lthash_1024_16_hash );

  fd_blake3_delete( fd_blake3_leave( blake ) );
}

  /* Benchmarks */

  static ulong const bench_sz[] =
    {     64,    128,    256,    512,
        1024,   1536,   2048,   2560,
        3072,   4096,   5120,   6144,
        7168,   8192,   8704,   9216,
        9728,  10240,  10752,  11264,
       11776,  12288,  12800,  13312,
       13824,  14336,  14848,  15360,
       15872,  16384,  32768, 131072,
      262144, 524288 };
  ulong bench_cnt = sizeof(bench_sz)/sizeof(bench_sz[0]);

static void
bench_incremental( void ) {
  fd_blake3_t blake_[1];
  fd_blake3_t * blake = fd_blake3_join( fd_blake3_new( blake_ ) );

  FD_LOG_NOTICE(( "Benchmarking incremental (best case)" ));

  for( ulong j=0UL; j<bench_cnt; j++ ) {
    ulong sz          = bench_sz[j];
    ulong iter_target = (1UL<<28)/sz;

    /* warmup */
    uchar hash[ 32 ];
    ulong iter = iter_target / 100;
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_blake3_fini( fd_blake3_append( fd_blake3_init( blake ), rand_buf, sz ), hash );
    dt = fd_log_wallclock() - dt;

    /* for real */
    iter = iter_target;
    dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_blake3_fini( fd_blake3_append( fd_blake3_init( blake ), rand_buf, sz ), hash );
    dt = fd_log_wallclock() - dt;

    FD_LOG_NOTICE(( "  ~%6.3f Gbps per core; %f ns per byte (sz %6lu)",
                    (double)(((float)(8UL*sz*iter))/((float)dt)),
                    (double)dt/((double)sz*(double)iter),
                    sz ));
  }

  fd_blake3_delete( fd_blake3_leave( blake ) );
}

static void
bench_incremental_xof_2048( void ) {
  fd_blake3_t blake_[1];
  fd_blake3_t * blake = fd_blake3_join( fd_blake3_new( blake_ ) );

  FD_LOG_NOTICE(( "Benchmarking incremental XOF(2048) (best case)" ));

  for( ulong j=0UL; j<bench_cnt; j++ ) {
    ulong sz          = bench_sz[j];
    ulong iter_target = (1UL<<28)/sz;

    /* warmup */
    uchar hash[ 2048 ] __attribute__((aligned(64)));
    ulong iter = iter_target / 100;
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_blake3_fini_2048( fd_blake3_append( fd_blake3_init( blake ), rand_buf, sz ), hash );
    dt = fd_log_wallclock() - dt;

    /* for real */
    iter = iter_target;
    dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_blake3_fini_2048( fd_blake3_append( fd_blake3_init( blake ), rand_buf, sz ), hash );
    dt = fd_log_wallclock() - dt;

    FD_LOG_NOTICE(( "  ~%6.3f Gbps per core input;  ~%6.3f Gbps per core total;  %f ns per byte (sz %6lu)",
                    (double)(((float)( 8UL*sz      *iter))/((float)dt)),
                    (double)(((float)((8UL*sz+2048)*iter))/((float)dt)),
                    (double)dt/((double)sz*(double)iter),
                    sz ));
  }

  fd_blake3_delete( fd_blake3_leave( blake ) );
}

static void
bench_streamlined( void ) {
  FD_LOG_NOTICE(( "Benchmarking streamlined" ));
  for( ulong j=0UL; j<bench_cnt; j++ ) {
    ulong sz          = bench_sz[j];
    ulong iter_target = (1UL<<28)/sz;

    /* warmup */
    uchar hash[ 32 ];
    ulong iter = iter_target / 100;
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_blake3_hash( rand_buf, sz, hash );
    dt = fd_log_wallclock() - dt;

    /* for real */
    iter = iter_target;
    dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_blake3_hash( rand_buf, sz, hash );
    dt = fd_log_wallclock() - dt;

    double gbps = (double)(((float)(8UL*sz*iter))/((float)dt));
    FD_LOG_NOTICE(( "  ~%6.3f Gbps per core; %f ns per byte (sz %6lu)",
                    gbps, (double)dt/((double)sz*(double)iter), sz ));
  }
}

#if FD_HAS_AVX512

static void
bench_avx512_compress16_fast( void ) {
  FD_LOG_NOTICE(( "Benchmarking AVX512 backend (compress16_fast)" ));
  uchar batch_hash[ 1024 ] __attribute__((aligned(64)));
  for( uint sz=1024; sz>4; sz>>=4 ) {
    uchar const flags = sz==64 ? FD_BLAKE3_FLAG_PARENT : 0;
    /* warmup */
    for( ulong rem=100UL; rem; rem-- )
      fd_blake3_avx512_compress16_fast( rand_buf, batch_hash, 0UL, flags );
    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- )
      fd_blake3_avx512_compress16_fast( rand_buf, batch_hash, 0UL, flags );
    dt += fd_log_wallclock();
    FD_LOG_NOTICE(( "  ~%6.3f Gbps throughput / core (par 16 sz %u)", (double)(16UL*8UL*sz*iter) / (double)dt, sz ));
    FD_LOG_NOTICE(( "  %6.3g * 16 blocks / second / core", (double)iter * 1e9 / (double)dt ));
  }
}

static void
bench_avx512_compress16( void ) {
  FD_LOG_NOTICE(( "Benchmarking AVX512 backend (compress16)" ));
  for( uint sz=1024; sz>4; sz>>=4 ) {
    uchar        block_res[ 1024 ] __attribute__((aligned(64)));
    ulong        batch_data2[ 16 ]; for( uint i=0; i<16; i++ ) batch_data2[i] = (ulong)rand_buf;
    uint         batch_sz   [ 16 ]; for( uint i=0; i<16; i++ ) batch_sz   [i] = sz;
    void *       batch_hash [ 16 ]; for( uint i=0; i<16; i++ ) batch_hash [i] = block_res;
    ulong        ctr_vec    [ 16 ] = {0UL};
    uint         batch_flags[ 16 ] = {0U};
    /* warmup */
    for( ulong rem=100UL; rem; rem-- )
      fd_blake3_avx512_compress16( 16UL, batch_data2, batch_sz, ctr_vec, batch_flags, batch_hash, NULL, 32U, NULL );
    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- )
      fd_blake3_avx512_compress16( 16UL, batch_data2, batch_sz, ctr_vec, batch_flags, batch_hash, NULL, 32U, NULL );
    dt += fd_log_wallclock();
    FD_LOG_NOTICE(( "  ~%6.3f Gbps throughput / core (par 16 sz %u)", (double)(16UL*8UL*sz*iter) / (double)dt, sz ));
    FD_LOG_NOTICE(( "  %6.3g * 16 blocks / second / core", (double)iter * 1e9 / (double)dt ));
  }
}

static void
bench_avx512_lthash( void ) {
  FD_LOG_NOTICE(( "Benchmarking AVX512 backend (LtHash)" ));
    ulong  batch_data2[ 16 ]; for( uint i=0; i<16; i++ ) batch_data2[i] = (ulong)rand_buf;
    uint   batch_sz   [ 16 ]; for( uint i=0; i<16; i++ ) batch_sz   [i] = 64;
    ulong  ctr_vec    [ 16 ] = {0UL};
    uint   batch_flags[ 16 ]; for( uint i=0; i<16; i++ ) batch_flags[i] = FD_BLAKE3_FLAG_ROOT;
    ushort lthash     [ 1024 ] __attribute__((aligned(64)));
    /* warmup */
    for( ulong rem=100UL; rem; rem-- ) {
      fd_blake3_avx512_compress16( 16UL, batch_data2, batch_sz, ctr_vec, batch_flags, NULL, lthash, 32U, NULL );
    }
    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) {
      fd_blake3_avx512_compress16( 16UL, batch_data2, batch_sz, ctr_vec, batch_flags, NULL, lthash, 32U, NULL );
    }
    dt += fd_log_wallclock();
    FD_LOG_NOTICE(( "  %6.3g LtHash updates / second / core", (double)(iter*16) * 1e9 / (double)dt ));
}


#endif

#if FD_HAS_AVX

static void
bench_avx_compress8_fast( void ) {
  FD_LOG_NOTICE(( "Benchmarking AVX2 backend (compress8_fast)" ));
  for( uint sz=1024; sz>4; sz>>=4 ) {
    uchar batch_hash[ 512 ] __attribute__((aligned(32)));
    uchar const flags = sz==64 ? FD_BLAKE3_FLAG_PARENT : 0;
    /* warmup */
    for( ulong rem=100UL; rem; rem-- )
      fd_blake3_avx_compress8_fast( rand_buf, batch_hash, 0UL, flags );
    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- )
      fd_blake3_avx_compress8_fast( rand_buf, batch_hash, 0UL, flags );
    dt += fd_log_wallclock();
    FD_LOG_NOTICE(( "  ~%6.3f Gbps throughput / core (par 8 sz %u)", (double)(8UL*8UL*sz*iter) / (double)dt, sz ));
    FD_LOG_NOTICE(( "  %6.3g * 8 blocks / second / core", (double)iter * 1e9 / (double)dt ));
  }
}

static void
bench_avx_compress8( void ) {
  FD_LOG_NOTICE(( "Benchmarking AVX2 backend (compress8)" ));
  for( uint sz=1024; sz>4; sz>>=4 ) {
    ulong        batch_data2[ 8 ] __attribute__((aligned(32)));
    /*                          */ for( uint i=0; i<8; i++ ) batch_data2[i] = (ulong)rand_buf;
    uint         batch_sz   [ 8 ]; for( uint i=0; i<8; i++ ) batch_sz   [i] = sz;
    void *       batch_hash [ 8 ]; for( uint i=0; i<8; i++ ) batch_hash [i] = rand_buf;
    ulong        ctr_vec    [ 8 ] = {0UL};
    uint         batch_flags[ 8 ] = {0U};
    /* warmup */
    for( ulong rem=100UL; rem; rem-- )
      fd_blake3_avx_compress8( 8UL, batch_data2, batch_sz, ctr_vec, batch_flags, batch_hash, NULL, 32U, NULL );
    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- )
      fd_blake3_avx_compress8( 8UL, batch_data2, batch_sz, ctr_vec, batch_flags, batch_hash, NULL, 32U, NULL );
    dt += fd_log_wallclock();
    FD_LOG_NOTICE(( "  ~%6.3f Gbps throughput / core (par 8 sz %u)", (double)(8UL*8UL*sz*iter) / (double)dt, sz ));
    FD_LOG_NOTICE(( "  %6.3g batches / second / core", (double)iter     * 1e9 / (double)dt ));
    FD_LOG_NOTICE(( "  %6.3g blocks  / second / core", (double)(iter*8) * 1e9 / (double)dt ));
  }
}

static void
bench_avx_lthash( void ) {
  FD_LOG_NOTICE(( "Benchmarking AVX2 backend (LtHash)" ));
  ulong  batch_data [ 8 ] __attribute__((aligned(32)));
  /*                    */ for( uint i=0; i<8; i++ ) batch_data[i] = (ulong)rand_buf;
  uint   batch_sz   [ 8 ]; for( uint i=0; i<8; i++ ) batch_sz[i] = 64;
  ulong  batch_ctr  [ 8 ] = {0UL};
  uint   batch_flags[ 8 ]; for( uint i=0; i<8; i++ ) batch_flags[i] = FD_BLAKE3_FLAG_ROOT;
  ushort lthash     [ 1024 ] __attribute__((aligned(32)));
  /* warmup */
  for( ulong rem=100UL; rem; rem-- ) {
    fd_blake3_avx_compress8( 8UL, batch_data, batch_sz, batch_ctr, batch_flags, NULL, lthash, 32U, NULL );
  }
  /* for real */
  ulong iter = 100000UL;
  long  dt   = -fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    fd_blake3_avx_compress8( 8UL, batch_data, batch_sz, batch_ctr, batch_flags, NULL, lthash, 32U, NULL );
  }
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "  %6.3g LtHash updates / second / core", (double)(iter*8) * 1e9 / (double)dt ));
}

#endif

#if FD_HAS_SSE

static void
bench_sse_compress1( void ) {
  FD_LOG_NOTICE(( "Benchmarking SSE4.1 backend (compress1)" ));
  do {
    FD_LOG_NOTICE(( "Benchmarking SSE4.1 backend (compress1)" ));
    uchar batch_hash[ 32 ] __attribute__((aligned(16)));
    /* warmup */
    for( ulong rem=100UL; rem; rem-- )
      fd_blake3_sse_compress1( batch_hash, rand_buf, FD_BLAKE3_CHUNK_SZ, 0UL, 0, NULL, NULL );
    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- )
      fd_blake3_sse_compress1( batch_hash, rand_buf, FD_BLAKE3_CHUNK_SZ, 0UL, 0, NULL, NULL );
    dt += fd_log_wallclock();
    FD_LOG_NOTICE(( "  ~%6.3f Gbps throughput / core (par 1 sz 1024)", (double)(8UL*1024UL*iter) / (double)dt ));
    FD_LOG_NOTICE(( "  %6.3g blocks / second / core", (double)iter * 1e9 / (double)dt ));
  } while(0);
}

#endif /* FD_HAS_SSE */

static void
bench_ref_compress1( void ) {
  do {
    FD_LOG_NOTICE(( "Benchmarking ref backend (compress1)" ));
    uchar batch_hash[ 32 ];
    /* warmup */
    for( ulong rem=100UL; rem; rem-- )
      fd_blake3_ref_compress1( batch_hash, rand_buf, FD_BLAKE3_CHUNK_SZ, 0UL, 0, NULL, NULL );
    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- )
      fd_blake3_ref_compress1( batch_hash, rand_buf, FD_BLAKE3_CHUNK_SZ, 0UL, 0, NULL, NULL );
    dt += fd_log_wallclock();
    FD_LOG_NOTICE(( "  ~%6.3f Gbps throughput / core (par 1 sz 1024)", (double)(8UL*1024UL*iter) / (double)dt ));
    FD_LOG_NOTICE(( "  %6.3g blocks / second / core", (double)iter * 1e9 / (double)dt ));
  } while(0);
}

struct test_fn {
  char const * name;
  void (* fn)( void );
};

static struct test_fn const tests[] = {
  { "lthash",           test_lthash },
  { "constructor",      test_constructor },
  { "small_fixtures",   test_small_fixtures },
  { "rand_fixtures",    test_rand_fixtures },
  { "reduced",          test_reduced },
  { "reduced xof2048",  test_reduced_xof2048 },

#if FD_HAS_AVX512
  { "test avx512_compress16_fast",         test_avx512_compress16_fast },
  { "test avx512_compress16",              test_avx512_compress16 },
  { "test avx512_compress16_xof2048_para", test_avx512_compress16_xof2048_para },
  { "test avx512_compress16_xof2048_seq",  test_avx512_compress16_xof2048_seq },
#endif
#if FD_HAS_AVX
  { "test avx_compress8_fast",         test_avx_compress8_fast },
  { "test avx_compress8",              test_avx_compress8 },
  { "test avx_compress8_xof2048_para", test_avx_compress8_xof2048_para },
  { "test avx_compress8_xof2048_seq",  test_avx_compress8_xof2048_seq },
#endif

  { "bench incremental",            bench_incremental },
  { "bench streamlined",            bench_streamlined },
  { "bench incremental xof 2048",   bench_incremental_xof_2048 },
#if FD_HAS_AVX512
  { "bench avx512_compress16_fast", bench_avx512_compress16_fast },
  { "bench avx512_compress16",      bench_avx512_compress16 },
  { "bench avx512_lthash",          bench_avx512_lthash },
#endif
#if FD_HAS_AVX
  { "bench avx_compress8_fast",     bench_avx_compress8_fast },
  { "bench avx_compress8",          bench_avx_compress8 },
  { "bench avx_lthash",             bench_avx_lthash },
#endif
#if FD_HAS_SSE
  { "bench sse_compress1",          bench_sse_compress1 },
#endif
  { "bench ref_compress1",          bench_ref_compress1 },

  {0}
};

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  do {
    fd_rng_t _rng2[1]; fd_rng_t * rng2 = fd_rng_join( fd_rng_new( _rng2, 0x6a09e667, 0UL ) );
    for( ulong b=0UL; b<sizeof(rand_buf); b++ ) rand_buf[b] = fd_rng_uchar( rng2 );
    fd_rng_delete( fd_rng_leave( rng2 ) );
  } while(0);

  fd_rng_join( fd_rng_new( rng, 0U, 0UL ) );
  for( struct test_fn const * t=tests; t->name; t++ ) {
    t->fn();
    FD_LOG_NOTICE(( "OK: %s", t->name ));
  }
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

