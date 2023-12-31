#include "../fd_ballet.h"
#include "fd_blake3.h"
#include "fd_blake3_private.h"
#include "fd_blake3_test_vector.c"

FD_STATIC_ASSERT( FD_BLAKE3_ALIGN    ==128UL, unit_test );

FD_STATIC_ASSERT( FD_BLAKE3_ALIGN    ==alignof(fd_blake3_t), unit_test );
FD_STATIC_ASSERT( FD_BLAKE3_FOOTPRINT==sizeof (fd_blake3_t), unit_test );

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

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  int detail = fd_env_strip_cmdline_int( &argc, &argv, "--detail", NULL, 0 );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* Create hasher instance */

  FD_TEST( fd_blake3_align    ()==FD_BLAKE3_ALIGN     );
  FD_TEST( fd_blake3_footprint()==FD_BLAKE3_FOOTPRINT );

  fd_blake3_t mem[1];

  FD_TEST( fd_blake3_new( NULL          )==NULL ); /* null shmem       */
  FD_TEST( fd_blake3_new( (void *)0x1UL )==NULL ); /* misaligned shmem */

  void * obj = fd_blake3_new( mem ); FD_TEST( obj );

  FD_TEST( fd_blake3_join( NULL           )==NULL ); /* null shsha       */
  FD_TEST( fd_blake3_join( (void *) 0x1UL )==NULL ); /* misaligned shsha */

  fd_blake3_t * blake = fd_blake3_join( obj ); FD_TEST( blake );

  /* Run through known test vectors */

  for( fd_blake3_test_vector_t const * vec = fd_blake3_test_vector; vec->msg; vec++ )
    check_fixture( vec->hash, (uchar const *)vec->msg, vec->sz, blake, rng );

  /* Run through random preimage tests */

  fd_rng_t _rng2[1]; fd_rng_t * rng2 = fd_rng_join( fd_rng_new( _rng2, 0x6a09e667, 0UL ) );
  static uchar rand_buf[ 1<<24 ] __attribute__((aligned(32)));
  for( ulong b=0UL; b<sizeof(rand_buf); b++ ) rand_buf[b] = fd_rng_uchar( rng2 );
  fd_rng_delete( fd_rng_leave( rng2 ) );

  static const struct { ulong sz; uchar hash[32]; } test_fixtures[] = {
    {     64, "\x8e\x78\x6e\x0a\x39\x5b\xff\x26\x43\x11\x5e\x32\x12\xc0\xb3\x01\xa9\xf8\xd7\x82\x9c\xe5\x55\x7b\x12\x53\x63\x48\x11\xb3\x07\x0a" },
    {    128, "\x16\xbb\x9d\x92\x1f\xf7\x75\x0b\xd6\xe1\xf3\x60\xa2\x7b\x2f\x5f\xe7\x85\x38\xb3\xbf\xfe\xcb\x4d\x21\x25\xd9\x4f\x8a\xc7\xfb\x99" },
    {    256, "\x69\x33\x78\x3f\xc6\x50\x4e\x8c\x19\x06\x96\x1f\x96\xda\xa6\xcb\xe3\x30\xa9\x08\xe4\x4f\x22\x50\x73\x62\x4e\x2a\xc7\xf0\xf4\xc2" },
    {    512, "\x58\xea\xbd\x0c\xa7\xea\x6c\x70\x41\xb3\x21\x7b\x53\x27\xbd\x00\xda\xc6\xb2\x15\x72\x9a\xbe\x19\x74\x30\x17\x05\xd4\xe2\xfa\xfd" },
    {   1024, "\xe6\x0f\x0a\xd7\xc9\xdb\x47\xa9\x1b\x7c\xe4\x49\xeb\x1d\xc6\x5f\xee\xf2\xcf\x43\x12\xd6\xe1\xb1\xfa\xd7\x3e\x79\x03\xce\xb2\xe3" },
    {   1536, "\xcb\xe6\x93\x8f\x0d\x73\x6c\xd9\xad\x5e\x9f\x0b\x37\x06\x6c\xfe\xaa\xfa\x83\x83\x8a\x13\x95\x53\x49\x3a\xd8\xb5\xe3\xa6\x9d\x2c" },
    {   2048, "\x46\x24\x6b\xc2\xf5\xc0\x5d\xe6\xbc\xd8\xad\x81\xc1\x74\xbe\xe8\x6f\xe6\xde\xce\xf9\x0f\xca\x81\x08\x1a\x97\xc1\x80\xf2\x34\x25" },
    {   2560, "\x1a\x75\x49\x9f\x44\x64\xe4\xe9\xa9\x3c\xa6\x9b\x0c\xc1\x48\xed\x77\xc7\x6e\x06\xc0\xb0\x50\xcd\x92\xbc\x5b\x62\x72\xbb\xce\x63" },
    {   3072, "\x91\xaf\x45\x38\x21\x83\xc4\x6d\xa1\x22\x28\x8c\x32\x2b\x80\xf9\xb1\x9f\x94\xbc\x24\x06\xe8\xcc\x9d\x13\xc9\x4f\xbe\x2b\x5d\xe2" },
    {   4096, "\xbc\xdb\x49\xf0\x74\x15\x9b\x24\x20\xaa\x52\x0a\x9c\x94\x83\x67\xa5\xe7\xa0\x17\xa8\x77\x87\xf9\x4f\x74\x99\x9e\x75\x40\x15\xcf" },
    {   5120, "\x62\x62\x30\xf7\x3f\x2f\x66\x76\x0c\x28\x50\x8c\xf5\x21\x69\x92\x41\xf1\xa7\xe8\x48\x03\x68\xe0\xe5\x34\xcd\x43\x36\x0b\xeb\x2e" },
    {   6144, "\x31\xbf\x52\x72\x5d\xf1\xd6\xc5\xb7\x08\x05\x99\x1b\x81\x06\xe9\x25\x57\x42\xaa\x29\xd2\x96\x9f\x8f\xb9\x74\xf4\xf1\xef\x89\x29" },
    {   7168, "\x9b\x5a\x42\x31\xda\x7a\x8d\xf0\x2d\xa4\x88\x7a\xd6\x67\x4d\xa1\x01\x49\x1d\x43\xa4\x34\xfc\x21\xbb\x0b\x8c\x1d\xcd\x9d\x0a\xa5" },
    {   8192, "\x93\x01\x1d\x11\x98\xfb\x6a\xe5\xfc\x93\xc0\x7a\xf6\x74\xc8\x79\x30\x8d\xd2\x4d\x74\x45\x68\xde\xc9\xc0\x7d\x52\x81\x57\xb4\xc9" },
    {   8704, "\x7e\x1f\x44\x9b\xc1\x5b\x33\x7a\x4f\x59\x37\xfd\x4a\xa0\xa6\xfb\x86\xe0\x8a\xa6\x4d\x6b\xde\x1e\x59\x4e\xc0\x65\x33\xcc\x25\x96" },
    {   9216, "\xa8\x8d\xc5\xe8\xbd\x3f\xd9\xd7\x1e\x58\xcd\x06\x71\x7d\x37\xd8\x84\xaa\x04\xd0\xcf\x4f\x84\x86\xe4\xbc\x13\x12\xd5\xf1\x31\x83" },
    {   9728, "\x1f\xd1\xf8\x74\xec\xa7\x73\x18\x17\x1d\x41\x3a\xf1\x5b\x47\xe1\x72\xe6\x87\xcd\x39\x38\xdb\x55\xb2\x25\x21\xaa\x54\xdc\x7f\x80" },
    {  10240, "\x4f\x97\x7f\x5f\xa1\x07\xa2\xb9\xf9\x74\x88\xae\xc2\xdd\x96\x17\x72\xb0\xad\x1c\x3b\xe1\xb0\x0f\x71\x5a\x70\xec\x9e\xa2\x74\x32" },
    {  10752, "\xc9\xea\xd9\x36\x34\x7d\xb7\xf4\xd2\xb4\xfe\xd0\xf7\x2d\x0b\x63\xc9\x57\x26\x17\x6e\xda\x2e\x0a\xeb\x1d\xb4\x77\x30\xb9\x19\x43" },
    {  11264, "\x2a\xb7\x37\x0b\x8f\x48\xf2\xa7\x12\x7c\x3f\xc3\xad\xcb\x0f\x89\x98\x8b\x35\xe6\x0c\x36\x33\x9d\xd0\xb5\x13\x29\x2f\xcc\x0c\x4d" },
    {  11776, "\x1f\xc8\x45\xff\x4a\xe1\xb6\x3f\x07\xaa\xd8\xf2\x1c\x4f\x5f\x43\x4c\xd2\x1f\x61\xd5\x32\x32\xac\x0c\xaf\x60\x0b\x95\xa4\xef\x6d" },
    {  12288, "\x28\x78\x16\xb9\x63\x6d\x20\xb0\x61\xab\xb4\x95\xf4\xc4\x6a\x0d\xe3\x5f\x51\x82\x9c\x60\xe7\x92\xad\xdf\xf1\x9f\x24\x9d\x9e\x41" },
    {  12800, "\xb2\x86\xff\x43\xbe\x3b\xbb\xf0\x60\x05\x00\xdd\x17\x9e\x6b\xc6\x3f\x7f\x3a\x1e\x29\x3e\xda\x5a\xcc\x5c\x67\x87\xea\x72\xe4\xec" },
    {  13312, "\x31\xf8\x25\x9d\x9b\x5f\xe5\xf8\xac\xaf\x6d\x1a\xf7\x53\x48\x6d\x08\x8e\xcb\x2d\x38\xbb\xb7\x29\xf8\xde\xad\x09\x3d\xc8\xe0\x55" },
    {  13824, "\x2c\xa0\x2a\x8f\x4b\x78\xf8\x3b\xf0\x65\x11\xe0\x21\x31\xb4\xd9\x5c\xbc\x33\x64\x33\x87\xbc\x55\xf5\x1d\x34\xb4\x02\x27\x2d\x25" },
    {  14336, "\x6b\x2e\xb8\xf6\xf1\x73\x8b\xe2\x05\xb5\x5a\x91\xb8\x66\xac\x1a\x0b\xcd\x66\xa2\x79\x42\xff\x4c\xaa\x28\x9d\xb3\x3d\x6a\x14\x5e" },
    {  14848, "\x34\x20\x76\x40\x87\xdf\xc1\xda\x72\xd3\xf7\xf3\xaa\x0d\xb9\x51\x73\xb9\x06\x50\x1b\xe2\x03\x52\xfd\xfb\xca\x50\xf5\x3e\xbc\x77" },
    {  15360, "\x8f\x81\x9f\x30\x42\x44\x8d\xc8\xcf\xc0\xc6\x4a\x36\x31\x61\x41\x44\x76\x89\x3b\x9c\x50\x31\x85\xa3\x65\x9d\x38\xbc\xdf\xc1\x32" },
    {  15872, "\xc6\xd2\x5b\x4e\x48\xf3\x77\xef\x42\x5d\xb4\x9f\xb4\xe7\x49\x7d\x8e\x11\xd9\xa9\x0c\x22\xf3\x10\xe5\x3c\xe2\x2d\x40\xc1\x28\xe8" },
    {  16384, "\x18\xdf\x04\xb9\xd9\x39\x65\x64\x5a\xd3\x1d\x32\x31\x71\xf0\x04\x3b\x52\x7f\x59\x64\x02\x42\x40\xee\x18\xda\x24\xe1\x02\xe8\xa2" },
    {  16385, "\xac\xe0\x15\xdd\xfa\x44\x1a\x5c\x30\x90\x89\x74\xd0\xaf\xe3\x19\xf6\x82\xa3\x6d\x8b\xdd\x6e\x3a\x19\xc8\xd4\x2a\xb7\x09\xeb\x03" },
    {  24575, "\x2b\x7d\xe4\x8d\x19\x74\x8a\x5e\xac\x1b\x10\xd1\xcb\x06\x07\x1a\xc7\x02\x51\x75\x61\x8d\x76\xd7\x41\xee\x57\x33\x20\xe9\xc4\x8f" },
    {  32768, "\x14\x93\x4b\x79\x56\xa6\x43\x6a\x67\x9d\x01\x37\x43\x10\x9c\x28\xea\x2f\x10\x88\xc7\xfc\xb3\x31\x87\x38\x6b\xe0\x00\xe0\x83\x3d" },
    {  32769, "\x7b\xdb\xe3\xc9\xe9\xcd\x48\x7d\x8f\xc5\x03\x0b\x9c\x16\x46\x14\x72\xb3\x3e\xae\x42\xa0\x33\xf3\x9c\x79\x3f\xe5\xa7\x7c\x3b\x87" },
    { 131072, "\x8a\x98\xa1\x96\x6a\x97\x30\xb3\xc8\xb8\x2e\x2a\xd6\x06\xed\x57\xfa\xc2\x12\x27\x3a\xf3\xcb\x76\xe1\xf1\x3f\x7a\x1e\x44\xfd\xc6" },
    { 131073, "\x8f\xd1\x92\x3a\x05\x03\x09\xe2\x8f\x99\x0c\x33\xf9\xa2\x7b\xb3\x86\x50\x29\xa6\xdc\x39\x26\x96\x58\xda\x03\x65\xa3\x60\xbf\x4a" },
    { 262144, "\x94\xda\x5d\x5f\xb7\x48\xe7\x2e\x94\x47\xfc\x52\x90\x8f\x6e\xf0\x51\x91\xd9\xf8\xee\x4b\x48\x6a\x50\x41\x6f\xa7\xa4\x57\x5d\x24" },
    { 262145, "\xba\xf8\x15\x48\xde\xc6\x2b\x7c\xea\x70\xd1\x71\x98\x31\xae\x21\x2a\xf0\x8d\xf8\xb8\xfe\x46\xe8\x9d\xce\x7d\xdc\xac\xd5\x5f\x28" },
    { 524288, "\xd3\xb4\x34\xce\x23\x3d\x85\xa5\xeb\x07\xe7\x33\x1d\x9f\xc1\xcf\x51\xa6\x3f\x36\x1d\xa2\x23\xfb\x35\xea\x6b\x2f\x84\xaf\x95\xce" },
    { 524289, "\x9f\x05\x67\xce\xbe\xce\x9c\xdf\x80\xb1\x45\x7f\xd8\x3a\x45\xaf\x0b\xfc\xa2\x51\x23\xd6\xf8\x57\x62\xc2\xad\x67\xeb\xad\x73\x8c" },
    {0}
  };
  for( ulong j=0UL; test_fixtures[j].sz; j++ )
    check_fixture( test_fixtures[j].hash, rand_buf, test_fixtures[j].sz, blake, rng );

  /* Hash every message from 0 to 16MiB and ensure that the various APIs agree */

  uchar hash [ 32 ] __attribute__((aligned(32)));
  uchar hash2[ 32 ] __attribute__((aligned(32)));
  uchar hash3[ 32 ] __attribute__((aligned(32)));

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

    /* test batched hashing */
    fd_blake3_batch_t _batch[1];
    fd_blake3_batch_t * batch = fd_blake3_batch_init( _batch );
    fd_blake3_batch_add( batch, buf, sz, hash2 );
    fd_blake3_batch_add( batch, buf, fd_ulong_min( sizeof(buf), sz+fd_rng_ulong_roll( rng, 1024 ) ), hash3 );
    fd_blake3_batch_add( batch, buf, fd_ulong_min( sizeof(buf), sz+fd_rng_ulong_roll( rng, 1024 ) ), hash3 );
    fd_blake3_batch_add( batch, buf, fd_ulong_min( sizeof(buf), sz+fd_rng_ulong_roll( rng, 1024 ) ), hash3 );
    fd_blake3_batch_fini( batch );
    FD_TEST( 0==memcmp( hash, hash2, 32UL ) );
  }

  /* Test batching */

  FD_TEST( fd_ulong_is_pow2( FD_BLAKE3_BATCH_ALIGN )                                              );
  FD_TEST( (FD_BLAKE3_BATCH_FOOTPRINT>0UL) & !(FD_BLAKE3_BATCH_FOOTPRINT % FD_BLAKE3_BATCH_ALIGN) );

# define BATCH_MAX (32UL)
# define DATA_MAX  (256UL)
  uchar data_mem[ DATA_MAX       ]; for( ulong idx=0UL; idx<DATA_MAX; idx++ ) data_mem[ idx ] = fd_rng_uchar( rng );
  uchar hash_mem[ 32UL*BATCH_MAX ];

  uchar batch_mem[ FD_BLAKE3_BATCH_FOOTPRINT ] __attribute__((aligned(FD_BLAKE3_BATCH_ALIGN)));
  for( ulong trial_rem=262144UL; trial_rem; trial_rem-- ) {
    uchar const * data[ BATCH_MAX ];
    ulong         sz  [ BATCH_MAX ];
    uchar *       hash[ BATCH_MAX ];

    fd_blake3_batch_t * batch = fd_blake3_batch_init( batch_mem ); FD_TEST( batch );

    int   batch_abort = !(fd_rng_ulong( rng ) & 31UL);
    ulong batch_cnt   = fd_rng_ulong( rng ) & (BATCH_MAX-1UL);
    for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {
      ulong off0 = fd_rng_ulong( rng ) & (DATA_MAX-1UL);
      ulong off1 = fd_rng_ulong( rng ) & (DATA_MAX-1UL);
      data[ batch_idx ] = data_mem + fd_ulong_min( off0, off1 );
      sz  [ batch_idx ] = fd_ulong_max( off0, off1 ) - fd_ulong_min( off0, off1 );
      hash[ batch_idx ] = hash_mem + batch_idx*32UL;
      FD_TEST( fd_blake3_batch_add( batch, data[ batch_idx ], sz[ batch_idx ], hash[ batch_idx ] )==batch );
    }

    if( FD_UNLIKELY( batch_abort ) ) FD_TEST( fd_blake3_batch_abort( batch )==(void *)batch_mem );
    else {
      FD_TEST( fd_blake3_batch_fini( batch )==(void *)batch_mem );
      for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {
        uchar ref_hash[ 32 ];
        fd_blake3_hash( data[ batch_idx ], sz[ batch_idx ], ref_hash );
        if( FD_UNLIKELY( memcmp( ref_hash, hash[ batch_idx ], 32UL ) ) )
          FD_LOG_ERR(( "FAIL (sz %lu)"
                      "\n\tStreamlined returned"
                      "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                      "\n\tBatch returned"
                      "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT, sz[ batch_idx ],
                      FD_LOG_HEX16_FMT_ARGS( ref_hash          ), FD_LOG_HEX16_FMT_ARGS( ref_hash          ),
                      FD_LOG_HEX16_FMT_ARGS( hash[ batch_idx ] ), FD_LOG_HEX16_FMT_ARGS( hash[ batch_idx ] ) ));
      }
    }
  }
# undef DATA_MAX
# undef BATCH_MAX

  FD_LOG_NOTICE(( "Correctness tests OK" ));

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

  FD_LOG_NOTICE(( "Benchmarking incremental (best case)" ));

  for( ulong j=0UL; j<bench_cnt; j++ ) {
    ulong sz          = bench_sz[j];
    ulong iter_target = (1UL<<28)/sz;

    /* warmup */
    ulong iter = iter_target / 100;
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_blake3_fini( fd_blake3_append( fd_blake3_init( blake ), buf, sz ), hash );
    dt = fd_log_wallclock() - dt;

    /* for real */
    iter = iter_target;
    dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_blake3_fini( fd_blake3_append( fd_blake3_init( blake ), buf, sz ), hash );
    dt = fd_log_wallclock() - dt;

    FD_LOG_NOTICE(( "  ~%6.3f Gbps per core; %f ns per byte (sz %6lu)",
                    (double)(((float)(8UL*sz*iter))/((float)dt)),
                    (double)dt/((double)sz*(double)iter),
                    sz ));
  }

  double streamlined_gbps[bench_cnt];

  FD_LOG_NOTICE(( "Benchmarking streamlined" ));
  for( ulong j=0UL; j<bench_cnt; j++ ) {
    ulong sz          = bench_sz[j];
    ulong iter_target = (1UL<<28)/sz;

    /* warmup */
    ulong iter = iter_target / 100;
    long dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_blake3_hash( buf, sz, hash );
    dt = fd_log_wallclock() - dt;

    /* for real */
    iter = iter_target;
    dt = fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- ) fd_blake3_hash( buf, sz, hash );
    dt = fd_log_wallclock() - dt;

    double gbps = (double)(((float)(8UL*sz*iter))/((float)dt));
    streamlined_gbps[ j ] = gbps;
    FD_LOG_NOTICE(( "  ~%6.3f Gbps per core; %f ns per byte (sz %6lu)",
                    gbps, (double)dt/((double)sz*(double)iter), sz ));
  }

  FD_LOG_NOTICE(( "Benchmarking batched" ));
  ulong batch_cnt_min;  ulong batch_cnt_max;
  if( detail ) { batch_cnt_min = 1UL;                 batch_cnt_max = 2*FD_BLAKE3_BATCH_MAX; }
  else         { batch_cnt_min = FD_BLAKE3_BATCH_MAX; batch_cnt_max =   FD_BLAKE3_BATCH_MAX; }
  for( ulong j=0UL; j<bench_cnt; j++ ) {
    ulong sz          = bench_sz[j];
    ulong iter_target = (1UL<<25)/sz;
    for( ulong batch_cnt=batch_cnt_min; batch_cnt<=batch_cnt_max; batch_cnt++ ) {
      /* warmup */
      for( ulong rem=iter_target/100; rem; rem-- ) {
        fd_blake3_batch_t * batch = fd_blake3_batch_init( batch_mem );
        for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) fd_blake3_batch_add( batch, buf, sz, hash );
        fd_blake3_batch_fini( batch );
      }

      /* for real */
      ulong iter = iter_target;
      long  dt   = -fd_log_wallclock();
      for( ulong rem=iter; rem; rem-- ) {
        fd_blake3_batch_t * batch = fd_blake3_batch_init( batch_mem );
        for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) fd_blake3_batch_add( batch, buf, sz, hash );
        fd_blake3_batch_fini( batch );
      }
      dt += fd_log_wallclock();
      double gbps = ((double)(batch_cnt*8UL*sz*iter)) / ((double)dt);
      double diff_p = 100.0 * (gbps - streamlined_gbps[ j ]) / streamlined_gbps[ j ];
      FD_LOG_NOTICE(( "  ~%6.3f Gbps throughput / core (batch_cnt %2lu sz %6lu) (%+6.1f %%)", (double)gbps, batch_cnt, sz, diff_p ));
    }
  }

  /* Raw benchmarks */

  uchar const batch_data[ 16*64 ] __attribute__((aligned(32))) = {0};
  uchar       batch_hash[ 16*32 ] __attribute__((aligned(32)));

# if FD_HAS_AVX512
  do {
    FD_LOG_NOTICE(( "Benchmarking AVX512 backend (compress16_fast)" ));
    /* warmup */
    for( ulong rem=100UL; rem; rem-- )
      fd_blake3_avx512_compress16_fast( batch_data, batch_hash, 0UL, 0 );
    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- )
      fd_blake3_avx512_compress16_fast( batch_data, batch_hash, 0UL, 0 );
    dt += fd_log_wallclock();
    FD_LOG_NOTICE(( "  ~%6.3f Gbps throughput / core (par 16 sz 1024)", (double)(16UL*8UL*1024UL*iter) / (double)dt ));
    FD_LOG_NOTICE(( "  %6.3g * 16 blocks / second / core", (double)iter * 1e9 / (double)dt ));
  } while(0);
# endif /* FD_HAS_AVX512 */

# if FD_HAS_AVX
  do {
    FD_LOG_NOTICE(( "Benchmarking AVX2 backend (compress8_fast)" ));
    /* warmup */
    for( ulong rem=100UL; rem; rem-- )
      fd_blake3_avx_compress8_fast( batch_data, batch_hash, 0UL, 0 );
    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- )
      fd_blake3_avx_compress8_fast( batch_data, batch_hash, 0UL, 0 );
    dt += fd_log_wallclock();
    FD_LOG_NOTICE(( "  ~%6.3f Gbps throughput / core (par 8 sz 1024)", (double)(8UL*8UL*1024UL*iter) / (double)dt ));
    FD_LOG_NOTICE(( "  %6.3g * 8 blocks / second / core", (double)iter * 1e9 / (double)dt ));
  } while(0);
# endif /* FD_HAS_AVX */

# if FD_HAS_SSE
  do {
    FD_LOG_NOTICE(( "Benchmarking SSE4.1 backend (compress4_fast)" ));
    /* warmup */
    for( ulong rem=100UL; rem; rem-- )
      fd_blake3_sse_compress4_fast( batch_data, batch_hash, 0UL, 0 );
    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- )
      fd_blake3_sse_compress4_fast( batch_data, batch_hash, 0UL, 0 );
    dt += fd_log_wallclock();
    FD_LOG_NOTICE(( "  ~%6.3f Gbps throughput / core (par 4 sz 1024)", (double)(4UL*8UL*1024UL*iter) / (double)dt ));
    FD_LOG_NOTICE(( "  %6.3g * 4 blocks / second / core", (double)iter * 1e9 / (double)dt ));
  } while(0);

  do {
    FD_LOG_NOTICE(( "Benchmarking SSE4.1 backend (compress1)" ));
    /* warmup */
    for( ulong rem=100UL; rem; rem-- )
      fd_blake3_sse_compress1( batch_hash, batch_data, FD_BLAKE3_CHUNK_SZ, 0UL, 0 );
    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- )
      fd_blake3_sse_compress1( batch_hash, batch_data, FD_BLAKE3_CHUNK_SZ, 0UL, 0 );
    dt += fd_log_wallclock();
    FD_LOG_NOTICE(( "  ~%6.3f Gbps throughput / core (par 1 sz 1024)", (double)(8UL*1024UL*iter) / (double)dt ));
    FD_LOG_NOTICE(( "  %6.3g blocks / second / core", (double)iter * 1e9 / (double)dt ));
  } while(0);
# endif /* FD_HAS_SSE */

  do {
    FD_LOG_NOTICE(( "Benchmarking ref backend (compress1)" ));
    /* warmup */
    for( ulong rem=100UL; rem; rem-- )
      fd_blake3_ref_compress1( batch_hash, batch_data, FD_BLAKE3_CHUNK_SZ, 0UL, 0 );
    /* for real */
    ulong iter = 100000UL;
    long  dt   = -fd_log_wallclock();
    for( ulong rem=iter; rem; rem-- )
      fd_blake3_ref_compress1( batch_hash, batch_data, FD_BLAKE3_CHUNK_SZ, 0UL, 0 );
    dt += fd_log_wallclock();
    FD_LOG_NOTICE(( "  ~%6.3f Gbps throughput / core (par 1 sz 1024)", (double)(8UL*1024UL*iter) / (double)dt ));
    FD_LOG_NOTICE(( "  %6.3g blocks / second / core", (double)iter * 1e9 / (double)dt ));
  } while(0);

  /* clean up */

  FD_TEST( fd_blake3_leave( NULL )==NULL ); /* null sha */
  FD_TEST( fd_blake3_leave( blake  )==obj  ); /* ok */

  FD_TEST( fd_blake3_delete( NULL          )==NULL ); /* null shsha       */
  FD_TEST( fd_blake3_delete( (void *)0x1UL )==NULL ); /* misaligned shsha */
  FD_TEST( fd_blake3_delete( obj           )==mem  ); /* ok */

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

