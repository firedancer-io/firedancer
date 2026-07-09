#include "../util/racesan/fd_racesan_async.h"
#include "../util/racesan/fd_racesan_weave.h"
#include "../util/fd_util.h"
#include "fd_rwlock.h"

/* Racesan interleaving tests for fd_rwlock.
   Each test runs many random interleavings of concurrent lock
   operations and validates that invariants are maintained. */

#define FIBER_MAX       4
#define FIBER_STACK_MAX (1UL<<20)
#define ITER_MAX        (10000UL)
#define STEP_MAX        (4096UL)

static void * g_fiber_stack[ FIBER_MAX ];

/* Shared state for fibers */

struct test_ctx {
  fd_rwlock_t lock[1];
  uint        shared_ctr;  /* Protected by lock */
};

typedef struct test_ctx test_ctx_t;

/* async_write_inc: acquire write lock, increment counter, release */

static void
async_write_inc( void * _ctx ) {
  test_ctx_t * ctx = _ctx;
  fd_rwlock_write( ctx->lock );
  ctx->shared_ctr++;
  fd_rwlock_unwrite( ctx->lock );
}

/* async_read_check: acquire read lock, observe counter, release */

static void
async_read_check( void * _ctx ) {
  test_ctx_t * ctx = _ctx;
  fd_rwlock_read( ctx->lock );
  /* Under read lock, counter should not change.
     Just touch it to generate memory accesses. */
  FD_COMPILER_MFENCE();
  FD_VOLATILE_CONST( ctx->shared_ctr );
  fd_rwlock_unread( ctx->lock );
}

/* async_trywrite_inc: attempt write lock, increment if acquired */

static void
async_trywrite_inc( void * _ctx ) {
  test_ctx_t * ctx = _ctx;
  if( fd_rwlock_trywrite( ctx->lock ) ) {
    ctx->shared_ctr++;
    fd_rwlock_unwrite( ctx->lock );
  }
}

/* async_tryread_check: attempt read lock, observe if acquired */

static void
async_tryread_check( void * _ctx ) {
  test_ctx_t * ctx = _ctx;
  if( fd_rwlock_tryread( ctx->lock ) ) {
    FD_COMPILER_MFENCE();
    FD_VOLATILE_CONST( ctx->shared_ctr );
    fd_rwlock_unread( ctx->lock );
  }
}

/* async_demote: acquire write lock, increment, demote to read, observe,
   release read */

static void
async_demote( void * _ctx ) {
  test_ctx_t * ctx = _ctx;
  fd_rwlock_write( ctx->lock );
  ctx->shared_ctr++;
  fd_rwlock_demote( ctx->lock );
  FD_COMPILER_MFENCE();
  FD_VOLATILE_CONST( ctx->shared_ctr );
  fd_rwlock_unread( ctx->lock );
}

/* Test: two concurrent writers */

static void
test_write_write( void ) {
  FD_LOG_NOTICE(( "Testing write vs write" ));

  test_ctx_t ctx[1];
  fd_rwlock_new( ctx->lock );

  fd_racesan_async_t async0[1];
  fd_racesan_async_t async1[1];

  fd_racesan_weave_t weave[1];
  fd_racesan_weave_new( weave );
  fd_racesan_async_new( async0, g_fiber_stack[0], FIBER_STACK_MAX, async_write_inc, ctx );
  fd_racesan_async_new( async1, g_fiber_stack[1], FIBER_STACK_MAX, async_write_inc, ctx );
  fd_racesan_weave_add( weave, async0 );
  fd_racesan_weave_add( weave, async1 );

  for( ulong i=0UL; i<ITER_MAX; i++ ) {
    ctx->shared_ctr = 0U;
    atomic_store_explicit( &ctx->lock->value, 0, memory_order_relaxed );
    fd_racesan_weave_exec_rand( weave, i, STEP_MAX );
    FD_TEST( !weave->rem_cnt );
    FD_TEST( ctx->shared_ctr==2U );
    fd_racesan_async_reset( async0 );
    fd_racesan_async_reset( async1 );
  }

  fd_racesan_weave_delete( weave );
  fd_racesan_async_delete( async1 );
  fd_racesan_async_delete( async0 );
}

/* Test: two concurrent readers */

static void
test_read_read( void ) {
  FD_LOG_NOTICE(( "Testing read vs read" ));

  test_ctx_t ctx[1];
  fd_rwlock_new( ctx->lock );
  ctx->shared_ctr = 42U;

  fd_racesan_async_t async0[1];
  fd_racesan_async_t async1[1];

  fd_racesan_weave_t weave[1];
  fd_racesan_weave_new( weave );
  fd_racesan_async_new( async0, g_fiber_stack[0], FIBER_STACK_MAX, async_read_check, ctx );
  fd_racesan_async_new( async1, g_fiber_stack[1], FIBER_STACK_MAX, async_read_check, ctx );
  fd_racesan_weave_add( weave, async0 );
  fd_racesan_weave_add( weave, async1 );

  for( ulong i=0UL; i<ITER_MAX; i++ ) {
    atomic_store_explicit( &ctx->lock->value, 0, memory_order_relaxed );
    fd_racesan_weave_exec_rand( weave, i, STEP_MAX );
    FD_TEST( !weave->rem_cnt );
    fd_racesan_async_reset( async0 );
    fd_racesan_async_reset( async1 );
  }

  fd_racesan_weave_delete( weave );
  fd_racesan_async_delete( async1 );
  fd_racesan_async_delete( async0 );
}

/* Test: reader vs writer contention */

static void
test_read_write( void ) {
  FD_LOG_NOTICE(( "Testing read vs write" ));

  test_ctx_t ctx[1];
  fd_rwlock_new( ctx->lock );

  fd_racesan_async_t async0[1];
  fd_racesan_async_t async1[1];

  fd_racesan_weave_t weave[1];
  fd_racesan_weave_new( weave );
  fd_racesan_async_new( async0, g_fiber_stack[0], FIBER_STACK_MAX, async_write_inc, ctx );
  fd_racesan_async_new( async1, g_fiber_stack[1], FIBER_STACK_MAX, async_read_check, ctx );
  fd_racesan_weave_add( weave, async0 );
  fd_racesan_weave_add( weave, async1 );

  for( ulong i=0UL; i<ITER_MAX; i++ ) {
    ctx->shared_ctr = 0U;
    atomic_store_explicit( &ctx->lock->value, 0, memory_order_relaxed );
    fd_racesan_weave_exec_rand( weave, i, STEP_MAX );
    FD_TEST( !weave->rem_cnt );
    FD_TEST( ctx->shared_ctr==1U );
    fd_racesan_async_reset( async0 );
    fd_racesan_async_reset( async1 );
  }

  fd_racesan_weave_delete( weave );
  fd_racesan_async_delete( async1 );
  fd_racesan_async_delete( async0 );
}

/* Test: trywrite vs trywrite */

static void
test_trywrite_trywrite( void ) {
  FD_LOG_NOTICE(( "Testing trywrite vs trywrite" ));

  test_ctx_t ctx[1];
  fd_rwlock_new( ctx->lock );

  fd_racesan_async_t async0[1];
  fd_racesan_async_t async1[1];

  fd_racesan_weave_t weave[1];
  fd_racesan_weave_new( weave );
  fd_racesan_async_new( async0, g_fiber_stack[0], FIBER_STACK_MAX, async_trywrite_inc, ctx );
  fd_racesan_async_new( async1, g_fiber_stack[1], FIBER_STACK_MAX, async_trywrite_inc, ctx );
  fd_racesan_weave_add( weave, async0 );
  fd_racesan_weave_add( weave, async1 );

  for( ulong i=0UL; i<ITER_MAX; i++ ) {
    ctx->shared_ctr = 0U;
    atomic_store_explicit( &ctx->lock->value, 0, memory_order_relaxed );
    fd_racesan_weave_exec_rand( weave, i, STEP_MAX );
    FD_TEST( !weave->rem_cnt );
    /* Each trywrite either succeeds or fails, so counter is 0, 1, or 2 */
    FD_TEST( ctx->shared_ctr<=2U );
    fd_racesan_async_reset( async0 );
    fd_racesan_async_reset( async1 );
  }

  fd_racesan_weave_delete( weave );
  fd_racesan_async_delete( async1 );
  fd_racesan_async_delete( async0 );
}

/* Test: tryread vs write */

static void
test_tryread_write( void ) {
  FD_LOG_NOTICE(( "Testing tryread vs write" ));

  test_ctx_t ctx[1];
  fd_rwlock_new( ctx->lock );

  fd_racesan_async_t async0[1];
  fd_racesan_async_t async1[1];

  fd_racesan_weave_t weave[1];
  fd_racesan_weave_new( weave );
  fd_racesan_async_new( async0, g_fiber_stack[0], FIBER_STACK_MAX, async_write_inc,    ctx );
  fd_racesan_async_new( async1, g_fiber_stack[1], FIBER_STACK_MAX, async_tryread_check, ctx );
  fd_racesan_weave_add( weave, async0 );
  fd_racesan_weave_add( weave, async1 );

  for( ulong i=0UL; i<ITER_MAX; i++ ) {
    ctx->shared_ctr = 0U;
    atomic_store_explicit( &ctx->lock->value, 0, memory_order_relaxed );
    fd_racesan_weave_exec_rand( weave, i, STEP_MAX );
    FD_TEST( !weave->rem_cnt );
    FD_TEST( ctx->shared_ctr==1U );
    fd_racesan_async_reset( async0 );
    fd_racesan_async_reset( async1 );
  }

  fd_racesan_weave_delete( weave );
  fd_racesan_async_delete( async1 );
  fd_racesan_async_delete( async0 );
}

/* Test: demote vs read */

static void
test_demote_read( void ) {
  FD_LOG_NOTICE(( "Testing demote vs read" ));

  test_ctx_t ctx[1];
  fd_rwlock_new( ctx->lock );

  fd_racesan_async_t async0[1];
  fd_racesan_async_t async1[1];

  fd_racesan_weave_t weave[1];
  fd_racesan_weave_new( weave );
  fd_racesan_async_new( async0, g_fiber_stack[0], FIBER_STACK_MAX, async_demote,     ctx );
  fd_racesan_async_new( async1, g_fiber_stack[1], FIBER_STACK_MAX, async_read_check, ctx );
  fd_racesan_weave_add( weave, async0 );
  fd_racesan_weave_add( weave, async1 );

  for( ulong i=0UL; i<ITER_MAX; i++ ) {
    ctx->shared_ctr = 0U;
    atomic_store_explicit( &ctx->lock->value, 0, memory_order_relaxed );
    fd_racesan_weave_exec_rand( weave, i, STEP_MAX );
    FD_TEST( !weave->rem_cnt );
    FD_TEST( ctx->shared_ctr==1U );
    fd_racesan_async_reset( async0 );
    fd_racesan_async_reset( async1 );
  }

  fd_racesan_weave_delete( weave );
  fd_racesan_async_delete( async1 );
  fd_racesan_async_delete( async0 );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  for( ulong i=0UL; i<FIBER_MAX; i++ ) {
    g_fiber_stack[ i ] = fd_racesan_stack_create( FIBER_STACK_MAX );
  }

  test_write_write();
  test_read_read();
  test_read_write();
  test_trywrite_trywrite();
  test_tryread_write();
  test_demote_read();

  for( ulong i=0UL; i<FIBER_MAX; i++ ) {
    fd_racesan_stack_destroy( g_fiber_stack[ i ], FIBER_STACK_MAX );
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
