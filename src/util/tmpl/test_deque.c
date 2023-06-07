#include "../fd_util.h"

#define TEST_DEQUE_MAX (8UL)

static int   buf[ TEST_DEQUE_MAX ];
static ulong buf_start = 0UL;
static ulong buf_end   = 0UL;
static ulong buf_cnt   = 0UL;

static void
buf_push_head( int i ) {
  FD_TEST( buf_cnt<TEST_DEQUE_MAX );
  buf_cnt++; buf_start--; if( buf_start>=TEST_DEQUE_MAX ) buf_start = TEST_DEQUE_MAX-1UL;
  buf[ buf_start ] = i;
}

static void
buf_push_tail( int i ) {
  FD_TEST( buf_cnt<TEST_DEQUE_MAX );
  buf[ buf_end ] = i;
  buf_cnt++; buf_end++; if( buf_end>=TEST_DEQUE_MAX ) buf_end = 0UL;
}

static int
buf_pop_head( void ) {
  FD_TEST( buf_cnt );
  int i = buf[ buf_start ];
  buf_cnt--; buf_start++; if( buf_start>=TEST_DEQUE_MAX ) buf_start = 0UL;
  return i;
}

static int
buf_pop_tail( void ) {
  FD_TEST( buf_cnt );
  buf_cnt--; buf_end--; if( buf_end>=TEST_DEQUE_MAX ) buf_end = TEST_DEQUE_MAX-1UL;
  return buf[ buf_end ];
}

#define DEQUE_NAME test_deque
#define DEQUE_T    int
#define DEQUE_MAX  TEST_DEQUE_MAX
#include "fd_deque.c"

#define SCRATCH_ALIGN     (128UL)
#define SCRATCH_FOOTPRINT (1024UL)
uchar scratch[ SCRATCH_FOOTPRINT ] __attribute__((aligned(SCRATCH_ALIGN)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  if( FD_UNLIKELY( (test_deque_align()>SCRATCH_ALIGN) | (test_deque_footprint()>SCRATCH_FOOTPRINT) ) ) {
    FD_LOG_WARNING(( "skip: adjust scratch region and footprint for test" ));
    return 0;
  }

  FD_LOG_NOTICE(( "Testing construction" ));

  ulong align = test_deque_align();
  FD_TEST( fd_ulong_is_pow2( align ) );

  ulong footprint = test_deque_footprint();
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  void * shdeque = test_deque_new ( scratch ); FD_TEST( shdeque );
  int *  deque   = test_deque_join( shdeque ); FD_TEST( deque   );

  FD_LOG_NOTICE(( "Testing accessors" ));

  FD_TEST( test_deque_max( deque )==TEST_DEQUE_MAX );
  FD_TEST( test_deque_cnt( deque )==0UL            );

  FD_LOG_NOTICE(( "Testing operations" ));

  for( ulong iter=0UL; iter<100000000UL; iter++ ) {

    /* Randomly pick an operation to do */

    ulong r = fd_rng_ulong( rng );
    int   op    = (int)(r & 0xfUL); r >>= 4;
    int   val   = (int)(uint)r;   r >>= 32;
    int   reset = !(r & 65535UL); r >>= 16;

    if( FD_UNLIKELY( reset ) ) {
      buf_start = 0UL;
      buf_end   = 0UL;
      buf_cnt   = 0UL;
      FD_TEST( test_deque_remove_all( deque )==deque );
    }

    switch( op ) {

    case 0: /* push head */
      if( FD_UNLIKELY( buf_cnt>=TEST_DEQUE_MAX ) ) break; /* skip when full */
      buf_push_head( val ); FD_TEST( test_deque_push_head( deque, val )==deque );
      break;

    case 1: /* push tail */
      if( FD_UNLIKELY( buf_cnt>=TEST_DEQUE_MAX ) ) break; /* skip when full */
      buf_push_tail( val ); FD_TEST( test_deque_push_tail( deque, val )==deque );
      break;

    case 2: /* pop head */
      if( FD_UNLIKELY( !buf_cnt ) ) break; /* skip when empty */
      val = buf_pop_head(); FD_TEST( test_deque_pop_head( deque )==val );
      break;

    case 3: /* pop tail */
      if( FD_UNLIKELY( !buf_cnt ) ) break; /* skip when empty */
      val = buf_pop_tail(); FD_TEST( test_deque_pop_tail( deque )==val );
      break;

    case 4: /* zero-copy push head */
      if( FD_UNLIKELY( buf_cnt>=TEST_DEQUE_MAX ) ) break; /* skip when full */
      buf_push_head( val );
      FD_TEST( test_deque_insert_head( deque )==deque );
      *test_deque_peek_head( deque ) = val;
      break;

    case 5: /* zero-copy push tail */
      if( FD_UNLIKELY( buf_cnt>=TEST_DEQUE_MAX ) ) break; /* skip when full */
      buf_push_tail( val );
      FD_TEST( test_deque_insert_tail( deque )==deque );
      *test_deque_peek_tail( deque ) = val;
      break;

    case 6: /* zero-copy pop head */
      if( FD_UNLIKELY( !buf_cnt ) ) break; /* skip when empty */
      val = buf_pop_head();
      FD_TEST( (*test_deque_peek_head_const( deque ))==val );
      FD_TEST( test_deque_remove_head( deque )==deque      );
      break;

    case 7: /* zero-copy pop tail */
      if( FD_UNLIKELY( !buf_cnt ) ) break; /* skip when empty */
      val = buf_pop_tail();
      FD_TEST( (*test_deque_peek_tail_const( deque ))==val );
      FD_TEST( test_deque_remove_tail( deque )==deque      );
      break;

    case 8: /* push head nocopy */
      if( FD_UNLIKELY( buf_cnt>=TEST_DEQUE_MAX ) ) break; /* skip when full */
      buf_push_head( val ); *test_deque_push_head_nocopy( deque ) = val;
      break;

    case 9: /* push tail nocopy */
      if( FD_UNLIKELY( buf_cnt>=TEST_DEQUE_MAX ) ) break; /* skip when full */
      buf_push_tail( val ); *test_deque_push_tail_nocopy( deque ) = val;
      break;

    case 10: /* pop head nocopy */
      if( FD_UNLIKELY( !buf_cnt ) ) break; /* skip when empty */
      val = buf_pop_head(); FD_TEST( *test_deque_pop_head_nocopy( deque )==val );
      break;

    case 12: /* pop tail nocopy */
      if( FD_UNLIKELY( !buf_cnt ) ) break; /* skip when empty */
      val = buf_pop_tail(); FD_TEST( *test_deque_pop_tail_nocopy( deque )==val );
      break;

    case 13: {
      ulong i = buf_start;
      for( test_deque_iter_t iter = test_deque_iter_init( deque ); !test_deque_iter_done( deque, iter ); iter = test_deque_iter_next( deque, iter ) ) {
        int * ele = test_deque_iter_ele( deque, iter );
        FD_TEST( buf[i] == *ele );
        if ( ++i >= TEST_DEQUE_MAX )
          i = 0;
      }
      FD_TEST( i == buf_end );
      break;
    }
      
    default: /* never get here */
      break;
    }

    FD_TEST( test_deque_max  ( deque )==TEST_DEQUE_MAX            );
    FD_TEST( test_deque_cnt  ( deque )==buf_cnt                   );
    FD_TEST( test_deque_avail( deque )==(TEST_DEQUE_MAX-buf_cnt)  );
    FD_TEST( test_deque_empty( deque )==(!buf_cnt)                );
    FD_TEST( test_deque_full ( deque )==(buf_cnt==TEST_DEQUE_MAX) );
  }

  FD_TEST( test_deque_leave ( deque   )==shdeque         );
  FD_TEST( test_deque_delete( shdeque )==(void *)scratch );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

