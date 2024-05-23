#include "fd_tpu.h"
#include "fd_tpu_reasm_private.h"

/* An arbitrary valid transaction */
FD_IMPORT_BINARY( transaction4, "src/ballet/txn/fixtures/transaction4.bin" );

/* verify_state checks various data structure invariants */

static uint
verify_state( fd_tpu_reasm_t * reasm,
              fd_frag_meta_t * mcache ) {

  FD_TEST( reasm->slots_off  );
  FD_TEST( reasm->chunks_off );

  fd_tpu_reasm_slot_t * slots     = fd_tpu_reasm_slots_laddr   ( reasm );
  uint *                pub_slots = fd_tpu_reasm_pub_slots_laddr( reasm );

  uint depth    = reasm->depth;
  uint burst    = reasm->burst;
  uint slot_cnt = reasm->slot_cnt;
  uint free_cnt = 0U;

  FD_TEST( depth+burst==slot_cnt );
  FD_TEST( reasm->head <slot_cnt );
  FD_TEST( reasm->tail <slot_cnt );

  /* Check for invalid state and duplicates in mcache */

  for( ulong i = 0UL; i < depth; i++ ) {
    fd_frag_meta_t * frag = mcache + i;
    uint slot_idx = pub_slots[ i ];

    FD_TEST( frag->sz < FD_TPU_REASM_MTU );

    FD_TEST( slot_idx<slot_cnt );

    fd_tpu_reasm_slot_t * slot = slots + slot_idx;
    FD_TEST( slot->state==FD_TPU_REASM_STATE_PUB );

    slot->state = (uchar)0x42;  /* mark as visited */
  }
  for( ulong i = 0UL; i < depth; i++ ) {
    slots[ pub_slots[ i ] ].state = FD_TPU_REASM_STATE_PUB;  /* undo */
  }

  /* Scan slots via queue (head to tail) */

  ulong queue_head_depth = 0UL;
  for( uint node = reasm->head; node!=UINT_MAX; ) {
    FD_TEST( node<slot_cnt );
    fd_tpu_reasm_slot_t * slot = slots + node;
    queue_head_depth++;
    FD_TEST( queue_head_depth<=burst );
    FD_TEST( !((node==reasm->tail) ^ (queue_head_depth==burst)) );
    node = slot->next_idx;
    free_cnt += (slot->state==FD_TPU_REASM_STATE_FREE);
  }
  FD_TEST( queue_head_depth==burst );

  /* Scan slots via queue (tail to head) */

  ulong queue_tail_depth = 0UL;
  for( uint node = reasm->tail; node!=UINT_MAX; ) {
    FD_TEST( node<slot_cnt );
    fd_tpu_reasm_slot_t * slot = slots + node;
    queue_tail_depth++;
    FD_TEST( queue_tail_depth<=burst );
    FD_TEST( !((node==reasm->head) ^ (queue_tail_depth==burst)) );
    node = slot->prev_idx;
  }
  FD_TEST( queue_tail_depth==burst );

  return free_cnt;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0x573dc407UL, 0UL ) );

  FD_TEST( fd_tpu_reasm_align()==FD_TPU_REASM_ALIGN );

  /* Test invalid params */

  FD_TEST( fd_tpu_reasm_footprint( 0UL, 0UL )==0UL );
  FD_TEST( fd_tpu_reasm_footprint( 3UL, 4UL )==0UL );  /* depth not power of 2 */
  FD_TEST( fd_tpu_reasm_footprint( 4UL, 0UL )==0UL );  /* burst too small */
  FD_TEST( fd_tpu_reasm_footprint( 4UL, 1UL )==0UL );  /* burst too small */
  FD_TEST( fd_tpu_reasm_footprint( 0x80000000UL, 0x80000000UL )==0UL );  /* oversz depth, burst */

  /* Create test objects */

# define depth    (128UL)
# define burst    (128UL)
# define slot_cnt (depth+burst)
  ulong orig  = 48UL;

  static uchar __attribute__((aligned(FD_MCACHE_ALIGN)))
  mcache_mem[ FD_MCACHE_FOOTPRINT( depth, 0UL ) ] = {0};

  fd_frag_meta_t * mcache = fd_mcache_join( fd_mcache_new( mcache_mem, depth, 0UL, 1UL ) );
  FD_TEST( mcache );
  ulong seq = fd_mcache_seq0( mcache );

  static uchar __attribute__((aligned(FD_TPU_REASM_ALIGN)))
  tpu_reasm_mem[ FD_TPU_REASM_FOOTPRINT( depth, burst ) ];

  fd_tpu_reasm_t * reasm = fd_tpu_reasm_join( fd_tpu_reasm_new( tpu_reasm_mem, depth, burst, orig ) );
  FD_TEST( reasm );

  FD_LOG_INFO(( "Test initialization" ));

  fd_tpu_reasm_slot_t * slots = fd_tpu_reasm_slots_laddr( reasm );
  FD_TEST( slots );
  uint * pub_slots = fd_tpu_reasm_pub_slots_laddr( reasm );
  FD_TEST( pub_slots );
  uchar * chunks = fd_tpu_reasm_chunks_laddr( reasm );
  FD_TEST( chunks );

  verify_state( reasm, mcache );

  /* Confirm that memory regions are within bounds */

  FD_TEST( reasm->slots_off     + (slot_cnt * sizeof(fd_tpu_reasm_slot_t)) <= sizeof(tpu_reasm_mem) );
  FD_TEST( reasm->pub_slots_off + (depth    * sizeof(uint))                <= sizeof(tpu_reasm_mem) );
  FD_TEST( reasm->chunks_off    + (slot_cnt * FD_TPU_REASM_MTU)            <= sizeof(tpu_reasm_mem) );

  /* Confirm that the data regions of slots don't overlap */

  memset( (uchar *)( (ulong)reasm + reasm->chunks_off ), 0, slot_cnt * FD_TPU_REASM_MTU );

  for( ulong j=0UL; j<burst; j++ ) {
    fd_tpu_reasm_slot_t * slot = fd_tpu_reasm_prepare( reasm, 0UL );
    FD_TEST( slot );
    uint idx = slot_get_idx( reasm, slot );

    uchar * data = slot_get_data( reasm, idx );
    FD_TEST( (ulong)data                    >= (ulong)reasm + reasm->chunks_off     );
    FD_TEST( (ulong)data + FD_TPU_REASM_MTU <= (ulong)reasm + sizeof(tpu_reasm_mem) );

    for( ulong b=0UL; b<FD_TPU_REASM_MTU; b++ )
      FD_TEST( data[b]==0 );

    memset( data, 0xFF, FD_TPU_REASM_MTU );
  }

  FD_LOG_INFO(( "Test fd_tpu_reasm_reset" ));

  fd_tpu_reasm_reset( reasm );
  verify_state( reasm, mcache );

  FD_LOG_INFO(( "Test basic publishing" ));

  do {
    fd_tpu_reasm_slot_t * slot = fd_tpu_reasm_prepare( reasm, 0UL );
    FD_TEST( slot->state == FD_TPU_REASM_STATE_BUSY );
    FD_TEST( fd_tpu_reasm_append( reasm, slot, transaction4, transaction4_sz, 0UL )
             == FD_TPU_REASM_SUCCESS );
    FD_TEST( fd_tpu_reasm_publish( reasm, slot, mcache, reasm, seq, 0UL )
             == FD_TPU_REASM_SUCCESS );
    FD_TEST( slot->state == FD_TPU_REASM_STATE_PUB );
    verify_state( reasm, mcache );

    ulong            line_idx = fd_mcache_line_idx( seq, depth );
    fd_frag_meta_t * mline    = mcache + line_idx;

    FD_TEST( mline->seq == seq );
    FD_TEST( mline->sz == transaction4_sz );
    FD_TEST( (ulong)(slot - slots) == pub_slots[ line_idx ] );

    uchar const * data = fd_chunk_to_laddr_const( tpu_reasm_mem, mline->chunk );
    FD_TEST( 0==memcmp( data, transaction4, transaction4_sz ) );

    seq = fd_seq_inc( seq, 1UL );
  } while(0);

  FD_LOG_INFO(( "Test fd_tpu_reasm_prepare" ));

  uint free_cnt;
  for( ulong j=0UL; j<2*burst; j++ ) {
    fd_tpu_reasm_slot_t * slot = fd_tpu_reasm_prepare( reasm, j );
    FD_TEST( slot->state == FD_TPU_REASM_STATE_BUSY );
    free_cnt = verify_state( reasm, mcache );
    FD_TEST( (long)free_cnt==fd_long_max( (long)burst-(long)j-1L, 0L ) );
  }

  FD_LOG_INFO(( "Test fd_tpu_reasm_{cancel,publish}" ));

# define check_free_diff( free_cnt_new, diff ) do {        \
    uint free_cnt_new_ = (free_cnt_new);                   \
    FD_TEST( (long)free_cnt_new_==(long)free_cnt+(diff) ); \
    free_cnt = free_cnt_new_;                              \
  } while(0)

  ulong iter=100000UL;
  for( ulong j=0UL; j<iter; j++ ) {
    uint slot_idx = fd_rng_uint( rng ) & (slot_cnt-1U);
    FD_TEST( slot_idx<slot_cnt );
    fd_tpu_reasm_slot_t * slot = slots + slot_idx;

    switch( slot->state ) {
    case FD_TPU_REASM_STATE_FREE:
      FD_TEST( fd_tpu_reasm_prepare( reasm, fd_rng_ulong( rng ) ) );
        check_free_diff( verify_state( reasm, mcache ), -1L );
      continue;
    case FD_TPU_REASM_STATE_BUSY: {
      uint roll = fd_rng_uint( rng );
      if( roll<0x20000000U ) {
        fd_tpu_reasm_cancel( reasm, slot );
        FD_TEST( slot->state == FD_TPU_REASM_STATE_FREE );
        FD_TEST( reasm->tail == slot_idx );
        check_free_diff( verify_state( reasm, mcache ), +1L );
      } else {
        FD_TEST( fd_tpu_reasm_append( reasm, slot, transaction4, transaction4_sz, 0UL )
                 == FD_TPU_REASM_SUCCESS );
        FD_TEST( fd_tpu_reasm_publish( reasm, slot, mcache, reasm, seq, fd_rng_ulong( rng ) )
                 == FD_TPU_REASM_SUCCESS );
        seq = fd_seq_inc( seq, 1UL );
        check_free_diff( verify_state( reasm, mcache ), +1L );
      }
      break;
    }
    case FD_TPU_REASM_STATE_PUB:
      continue;
    default:
      __builtin_unreachable();
    }
  }

  /* Clean up */

  fd_tpu_reasm_delete( fd_tpu_reasm_leave( reasm  ) );
  fd_mcache_delete   ( fd_mcache_leave   ( mcache ) );
# undef depth
# undef burst
# undef slot_cnt
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
