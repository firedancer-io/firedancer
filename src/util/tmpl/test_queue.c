#include "../fd_util.h"

#define TEST_QUEUE_MAX (8UL)

static int   buf[ TEST_QUEUE_MAX ];
static ulong buf_start = 0UL;
static ulong buf_end   = 0UL;
static ulong buf_cnt   = 0UL;

static void
buf_push( int i ) {
  FD_TEST( buf_cnt<TEST_QUEUE_MAX );
  buf[ buf_end ] = i;
  buf_cnt++; buf_end++; if( buf_end>=TEST_QUEUE_MAX ) buf_end = 0UL;
}

static int
buf_pop( void ) {
  FD_TEST( buf_cnt );
  int i = buf[ buf_start ];
  buf_cnt--; buf_start++; if( buf_start>=TEST_QUEUE_MAX ) buf_start = 0UL;
  return i;
}

#define QUEUE_NAME test_queue
#define QUEUE_T    int
#define QUEUE_MAX  TEST_QUEUE_MAX
#include "fd_queue.c"

#define SCRATCH_ALIGN     (128UL)
#define SCRATCH_FOOTPRINT (1024UL)
uchar scratch[ SCRATCH_FOOTPRINT ] __attribute__((aligned(SCRATCH_ALIGN)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_LOG_NOTICE(( "Testing construction" ));

  ulong align = test_queue_align();
  FD_TEST( fd_ulong_is_pow2( align ) );

  ulong footprint = test_queue_footprint();
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  void * shqueue = test_queue_new ( scratch ); FD_TEST( shqueue );
  int *  queue   = test_queue_join( shqueue ); FD_TEST( queue   );

  FD_LOG_NOTICE(( "Testing accessors" ));

  FD_TEST( test_queue_max( queue )==TEST_QUEUE_MAX );
  FD_TEST( test_queue_cnt( queue )==0UL            );

  FD_LOG_NOTICE(( "Testing operations" ));

  for( ulong iter=0UL; iter<100000000UL; iter++ ) {

    /* Randomly pick an operation to do */

    ulong r = fd_rng_ulong( rng );
    int   op    = (int)(r & 3UL); r >>= 2;
    int   val   = (int)(uint)r;   r >>= 32;
    int   reset = !(r & 65535UL); r >>= 16;

    if( FD_UNLIKELY( reset ) ) {
      buf_start = 0UL;
      buf_end   = 0UL;
      buf_cnt   = 0UL;
      FD_TEST( test_queue_remove_all( queue )==queue );
    }

    switch( op ) {

    case 0: /* push */
      if( FD_UNLIKELY( buf_cnt>=TEST_QUEUE_MAX ) ) break; /* skip when full */
      buf_push( val ); FD_TEST( test_queue_push( queue, val )==queue );
      break;

    case 1: /* pop */
      if( FD_UNLIKELY( !buf_cnt ) ) break; /* skip when empty */
      val = buf_pop(); FD_TEST( test_queue_pop( queue )==val );
      break;

    case 2: /* zero-copy push */
      if( FD_UNLIKELY( buf_cnt>=TEST_QUEUE_MAX ) ) break; /* skip when full */
      buf_push( val );
      FD_TEST( test_queue_insert( queue )==queue );
      *test_queue_peek_insert( queue ) = val;
      FD_TEST( (*test_queue_peek_insert      ( queue ))==val );
      FD_TEST( (*test_queue_peek_insert_const( queue ))==val );
      break;

    case 3: /* zero-copy pop */
      if( FD_UNLIKELY( !buf_cnt ) ) break; /* skip when empty */
      val = buf_pop();
      FD_TEST( (*test_queue_peek_remove      ( queue ))==val );
      FD_TEST( (*test_queue_peek_remove_const( queue ))==val );
      FD_TEST( test_queue_remove( queue )==queue             );
      break;

    default: /* never get here */
      break;
    }

    FD_TEST( test_queue_max  ( queue )==TEST_QUEUE_MAX            );
    FD_TEST( test_queue_cnt  ( queue )==buf_cnt                   );
    FD_TEST( test_queue_avail( queue )==(TEST_QUEUE_MAX-buf_cnt)  );
    FD_TEST( test_queue_empty( queue )==(!buf_cnt)                );
    FD_TEST( test_queue_full ( queue )==(buf_cnt==TEST_QUEUE_MAX) );
  }

  FD_TEST( test_queue_leave ( queue   )==shqueue         );
  FD_TEST( test_queue_delete( shqueue )==(void *)scratch );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

