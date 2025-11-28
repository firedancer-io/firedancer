#include "fd_racesan.h"
#include "fd_racesan_async.h"
#include "fd_racesan_target.h"
#include "fd_racesan_weave.h"
#include "../../util/fd_util.h"

#define FIBER_MAX 2
#define FIBER_STACK_MAX (1UL<<20)
static void * g_fiber_stack[ FIBER_MAX ];

static void
cas_inc( uint * p ) {
  for(;;) {
    uint v = FD_VOLATILE_CONST( *p );
    fd_racesan_hook( "cas_inc:post_load" );
    if( FD_LIKELY( __sync_bool_compare_and_swap( p, v, v+1U ) ) ) break;
  }
}

static void
inject_inc( void * ctx,
            ulong  name_hash ) {
  (void)name_hash;
  uint * p = ctx;
  if( FD_VOLATILE_CONST( *p )==0U ) FD_VOLATILE( *p ) = 1U;
}

static void
test_racesan_inject( void ) {
  uint ctx = 0U;
  fd_racesan_t racesan[1];
  FD_TEST( fd_racesan_new( racesan, &ctx ) );

  fd_racesan_inject( racesan, "cas_inc:post_load", inject_inc );
  FD_RACESAN_INJECT_BEGIN( racesan ) {
    cas_inc( &ctx );
  }
  FD_RACESAN_INJECT_END;

  FD_TEST( FD_VOLATILE_CONST( ctx )==2U );
  fd_racesan_delete( racesan );
}

static void
async_cas_inc( void * ctx ) {
  uint * seq = ctx;
  cas_inc( seq );
}

static void
test_racesan_async( void ) {
  uint seq = 0U;

  fd_racesan_async_t async[1];
  fd_racesan_async_new( async, g_fiber_stack[0], FIBER_STACK_MAX, async_cas_inc, &seq );

  FD_TEST( fd_racesan_async_step( async )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( fd_racesan_async_hook_name_eq( async, "cas_inc:post_load" ) );

  FD_VOLATILE( seq )++;
  FD_TEST( fd_racesan_async_step( async )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( fd_racesan_async_hook_name_eq( async, "cas_inc:post_load" ) );
  FD_TEST( fd_racesan_async_step( async )==FD_RACESAN_ASYNC_RET_EXIT );
  FD_TEST( fd_racesan_async_step( async )==FD_RACESAN_ASYNC_RET_EXIT );
  FD_TEST( fd_racesan_async_step( async )==FD_RACESAN_ASYNC_RET_EXIT );

  FD_TEST( FD_VOLATILE_CONST( seq )==2 );

  fd_racesan_async_delete( async );
}

static void
async_cas_dbl( void * ctx ) {
  uint * seq = ctx;
  for(;;) {
    uint v = FD_VOLATILE_CONST( *seq );
    fd_racesan_hook( "cas_dbl:post_load" );
    if( FD_LIKELY( __sync_bool_compare_and_swap( seq, v, (v<<1) ) ) ) break;
  }
}

static void
test_racesan_weave( void ) {
  uint seq = 0U;

  fd_racesan_weave_t weave[1];
  fd_racesan_weave_new( weave );

  fd_racesan_async_t async_dbl[1];
  FD_TEST( fd_racesan_async_new( async_dbl, g_fiber_stack[0], FIBER_STACK_MAX, async_cas_dbl, &seq ) );
  fd_racesan_weave_add( weave, async_dbl );

  fd_racesan_async_t async_inc[1];
  FD_TEST( fd_racesan_async_new( async_inc, g_fiber_stack[1], FIBER_STACK_MAX, async_cas_inc, &seq ) );
  fd_racesan_weave_add( weave, async_inc );

  /* Run random interleavings */
  ulong iter     = (ulong)1e4;
  ulong step_max = 1024UL;
  for( ulong rem=iter; rem; rem-- ) {
    FD_VOLATILE( seq ) = 5U;
    fd_racesan_weave_exec_rand( weave, rem, step_max );
    uint res = FD_VOLATILE_CONST( seq );
    FD_TEST( res==11U || res==12U );
  }

  fd_racesan_weave_delete( weave );
  fd_racesan_async_delete( async_inc );
  fd_racesan_async_delete( async_dbl );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  for( ulong i=0UL; i<FIBER_MAX; i++ ) {
    g_fiber_stack[ i ] = fd_racesan_stack_create( FIBER_STACK_MAX );
  }

  test_racesan_async();
  test_racesan_weave();
  test_racesan_inject();

  for( ulong i=0UL; i<FIBER_MAX; i++ ) {
    fd_racesan_stack_destroy( g_fiber_stack[ i ], FIBER_STACK_MAX );
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
