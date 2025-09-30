#include "fd_racesan_async.h"
#include "../../util/fd_util.h"
#include <errno.h>

/* fd_racesan_async_yield context switches out to the caller of the
   fd_racesan_async_step function. */

static void
fd_racesan_async_yield( fd_racesan_async_t * async ) {
  if( FD_UNLIKELY( 0!=swapcontext( &async->ctx, FD_VOLATILE_CONST( async->caller ) ) ) ) {
    FD_LOG_ERR(( "failed to yield from async fn: swapcontext failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

/* fd_racesan_async_hook is called whenever the target reaches a racesan
   hook.  The racesan_async logic here context-switches out back to the
   caller of step. */

static void
fd_racesan_async_hook( void * ctx,
                       ulong  name_hash ) {
  fd_racesan_async_t * async = ctx;
  async->name_hash = name_hash;
  fd_racesan_exit();
  fd_racesan_async_yield( async );
}

/* fd_racesan_async_target is a long-lived / async function with its own
   stack. */

static void
fd_racesan_async_target( fd_racesan_async_t * async ) {
  fd_racesan_t racesan[1];
  fd_racesan_new( racesan, async );
  fd_racesan_inject_default( racesan, fd_racesan_async_hook );
  fd_racesan_enter( racesan );
  async->fn( async->fn_ctx );
  fd_racesan_delete( racesan );

  async->done = 1;
  fd_racesan_async_yield( async );
}

fd_racesan_async_t *
fd_racesan_async_new( fd_racesan_async_t *    async,
                      fd_racesan_async_fn_t * async_fn,
                      void *                  ctx ) {
  memset( async, 0, sizeof(fd_racesan_async_t) );

  async->fn_ctx = ctx;
  async->fn     = async_fn;

  if( FD_UNLIKELY( 0!=getcontext( &async->ctx ) ) ) {
    FD_LOG_ERR(( "getcontext failed" ));
  }
  async->ctx.uc_stack.ss_sp   = async->stack;
  async->ctx.uc_stack.ss_size = sizeof(async->stack);
  makecontext( &async->ctx, (void (*)( void ))fd_racesan_async_target, 1, async );

  return async;
}

void *
fd_racesan_async_delete( fd_racesan_async_t * async ) {
  (void)async;
  return NULL;
}

int
fd_racesan_async_step( fd_racesan_async_t * async ) {
  if( FD_UNLIKELY( async->done ) ) return 0;

  ucontext_t caller;
  async->caller = &caller;
  if( FD_UNLIKELY( 0!=swapcontext( &caller, &async->ctx ) ) ) {
    FD_LOG_ERR(( "failed to step into async fn: swapcontext failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  /* fd_racesan_async_yield jumps to here */
  return 1;
}

int
fd_racesan_async_hook_name_eq( fd_racesan_async_t * async,
                               char const *         hook_name ) {
  ulong len  = strlen( hook_name );
  ulong hash = fd_racesan_strhash( hook_name, len );
  return async->name_hash==hash;
}

void
fd_racesan_async_reset( fd_racesan_async_t * async ) {
  makecontext( &async->ctx, (void (*)( void ))fd_racesan_async_target, 1, async );
  async->done = 0;
}
