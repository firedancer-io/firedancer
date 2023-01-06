#include "../fd_util.h"

#define BUF_MAX (8UL)
static int   buf[ BUF_MAX ];
static ulong buf_cnt = 0UL;
static void  buf_push( int i ) { FD_TEST( buf_cnt<BUF_MAX ); buf[ buf_cnt++ ] = i; } 
static int   buf_pop ( void  ) { FD_TEST( buf_cnt ); return buf[ --buf_cnt ]; }

#define STACK_NAME test_stack
#define STACK_T    int
#include "fd_stack.c"

#define SCRATCH_ALIGN     (128UL)
#define SCRATCH_FOOTPRINT (1024UL)
uchar scratch[ SCRATCH_FOOTPRINT ] __attribute__((aligned(SCRATCH_ALIGN)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong max = fd_env_strip_cmdline_ulong( &argc, &argv, "--max", NULL, BUF_MAX );
  if( FD_UNLIKELY( max>BUF_MAX ) )  {
    FD_LOG_WARNING(( "skip: increase BUF_MAX to support this level of --max" ));
    return 0;
  }
  if( FD_UNLIKELY( (test_stack_align()>SCRATCH_ALIGN) | (test_stack_footprint( max )>SCRATCH_FOOTPRINT) ) ) {
    FD_LOG_WARNING(( "skip: adjust scratch region and footprint to support this level of --max" ));
    return 0;
  }
  FD_LOG_NOTICE(( "--max %lu", max ));

  FD_LOG_NOTICE(( "Testing construction" ));

  ulong align = test_stack_align();
  FD_TEST( fd_ulong_is_pow2( align ) );

  ulong footprint = test_stack_footprint( max );
  FD_TEST( fd_ulong_is_aligned( footprint, align ) );

  void * shstack = test_stack_new ( scratch, max ); FD_TEST( shstack );
  int *  stack   = test_stack_join( shstack      ); FD_TEST( stack   );

  FD_LOG_NOTICE(( "Testing accessors" ));

  FD_TEST( test_stack_max( stack )==max );
  FD_TEST( test_stack_cnt( stack )==0UL );

  FD_LOG_NOTICE(( "Testing operations" ));

  for( ulong iter=0UL; iter<100000000UL; iter++ ) {

    /* Randomly pick an operation to do */

    ulong r = fd_rng_ulong( rng );
    int   op    = (int)(r & 3UL); r >>= 2;
    int   val   = (int)(uint)r;   r >>= 32;
    int   reset = !(r & 65535UL); r >>= 16;

    if( FD_UNLIKELY( reset ) ) {
      buf_cnt = 0UL;
      FD_TEST( test_stack_remove_all( stack )==stack );
    }

    switch( op ) {

    case 0: /* push */
      if( FD_UNLIKELY( buf_cnt>=max ) ) break; /* skip when full */
      buf_push( val ); FD_TEST( test_stack_push( stack, val )==stack );
      break;

    case 1: /* pop */
      if( FD_UNLIKELY( !buf_cnt ) ) break; /* skip when empty */
      val = buf_pop(); FD_TEST( test_stack_pop( stack )==val );
      break;

    case 2: /* zero-copy push */
      if( FD_UNLIKELY( buf_cnt>=max ) ) break; /* skip when full */
      buf_push( val );
      FD_TEST( test_stack_insert( stack )==stack );
      *test_stack_peek( stack ) = val;
      break;

    case 3: /* zero-copy pop */
      if( FD_UNLIKELY( !buf_cnt ) ) break; /* skip when empty */
      val = buf_pop();
      FD_TEST( (*test_stack_peek_const( stack ))==val );
      FD_TEST( test_stack_remove( stack )==stack );
      break;

    default: /* never get here */
      break;
    }

    FD_TEST( test_stack_cnt  ( stack )==buf_cnt        );
    FD_TEST( test_stack_max  ( stack )==max            );
    FD_TEST( test_stack_avail( stack )==(max-buf_cnt)  );
    FD_TEST( test_stack_full ( stack )==(max==buf_cnt) );
    FD_TEST( test_stack_empty( stack )==(!buf_cnt)     );
  }

  FD_TEST( test_stack_leave ( stack   )==shstack         );
  FD_TEST( test_stack_delete( shstack )==(void *)scratch );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

