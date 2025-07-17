#include "fd_blockhashes.h"
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "../types/fd_types.h"

FD_IMPORT_BINARY( test_blockhash_queue_bin, "src/flamenco/runtime/tests/blockhash_queue.bin" );

#define TEST_ITER 10000

static void
test_blockhashes_verify( fd_blockhashes_t const * blockhashes ) {
  ulong age = 0UL;
  for( fd_blockhash_deq_iter_t iter = fd_blockhash_deq_iter_init_rev( blockhashes->d.deque );
       !fd_blockhash_deq_iter_done_rev( blockhashes->d.deque, iter );
       iter = fd_blockhash_deq_iter_prev( blockhashes->d.deque, iter ),
       age++ ) {
    fd_blockhash_info_t const * info = fd_blockhash_deq_iter_ele_const( blockhashes->d.deque, iter );
    if( FD_UNLIKELY( age==0UL ) ) {
      fd_hash_t const * last_hash = fd_blockhashes_peek_last( blockhashes );
      FD_TEST( fd_hash_eq( &info->hash, last_hash ) );
    }
    FD_TEST( info->exists );
    FD_TEST( fd_blockhashes_check_age( blockhashes, &info->hash, age )==1 );
    if( age>0UL ) FD_TEST( fd_blockhashes_check_age( blockhashes, &info->hash, age-1 )==0 );
  }
}

static void
test_blockhashes_recover( fd_blockhashes_t * blockhashes ) {

  /* Load an example 'blockhash queue' from a serialized bank (snapshot) */

  fd_bincode_decode_ctx_t ctx = {
    .data    = test_blockhash_queue_bin,
    .dataend = test_blockhash_queue_bin+test_blockhash_queue_bin_sz
  };
  static uchar decode_scratch[ 0x8000 ] __attribute__((aligned(FD_BLOCK_HASH_VEC_ALIGN)));
  ulong alloc_sz = 0UL;
  FD_TEST( fd_block_hash_vec_decode_footprint( &ctx, &alloc_sz )==FD_BINCODE_SUCCESS );
  FD_TEST( alloc_sz<=sizeof(decode_scratch) );
  fd_block_hash_vec_decode( decode_scratch, &ctx );
  fd_block_hash_vec_t const * bhv = fd_type_pun_const( decode_scratch );

  FD_TEST( fd_blockhashes_recover( blockhashes, bhv->ages, bhv->ages_len, 0UL ) );

  FD_TEST( fd_blockhash_deq_cnt( blockhashes->d.deque )==301 );

  for( ulong i=0UL; i<(bhv->ages_len); i++ ) {
    fd_hash_t hash = bhv->ages[i].key;
    FD_TEST( fd_blockhashes_check_age( blockhashes, &hash, 300 )==1 );
    hash.ul[0]++;
    FD_TEST( fd_blockhashes_check_age( blockhashes, &hash, 300 )==0 );
  }

  test_blockhashes_verify( blockhashes );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_TEST( fd_ulong_is_aligned( offsetof( fd_blockhashes_t, map_mem ), fd_blockhash_map_align() ) );
  FD_TEST( sizeof(((fd_blockhashes_t *)NULL)->map_mem)==fd_blockhash_map_footprint( FD_BLOCKHASH_MAP_CHAIN_MAX ) );

  FD_TEST( fd_ulong_is_aligned( offsetof( fd_blockhashes_t, d ), fd_blockhash_deq_align() ) );
  FD_TEST( sizeof(((fd_blockhashes_t *)NULL)->d)==fd_blockhash_deq_footprint() );

  /* Load existing blockhash queue */
  fd_blockhashes_t blockhashes[1];
  fd_blockhashes_init( blockhashes, 0UL );
  test_blockhashes_recover( blockhashes );

  /* Keep pushing new entries */
  for( ulong i=0UL; i<TEST_ITER; i++ ) {
    fd_hash_t hash;
    for( ulong j=0; j<(sizeof(fd_hash_t)/sizeof(uint)); j++ ) {
      hash.ui[j] = fd_rng_uint( rng );
    }
    fd_blockhash_info_t * info = fd_blockhashes_push_new( blockhashes, &hash );
    FD_TEST( info && info->exists );
    test_blockhashes_recover( blockhashes );
  }

  /* Start from scratch */
  fd_blockhashes_init( blockhashes, 0UL );
  for( ulong i=0UL; i<TEST_ITER; i++ ) {
    fd_hash_t hash;
    for( ulong j=0; j<(sizeof(fd_hash_t)/sizeof(uint)); j++ ) {
      hash.ui[j] = fd_rng_uint( rng );
    }
    fd_blockhash_info_t * info = fd_blockhashes_push_new( blockhashes, &hash );
    FD_TEST( info && info->exists );
    test_blockhashes_recover( blockhashes );
  }

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
