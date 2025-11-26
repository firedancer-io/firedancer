#define _GNU_SOURCE
#include "fd_racesan_async.h"
#include "../../util/fd_util.h"
#include <errno.h>

#if FD_HAS_HOSTED

#include <sys/mman.h>

void *
fd_racesan_stack_create( ulong stack_sz ) {
  if( FD_UNLIKELY( !stack_sz || !fd_ulong_is_aligned( stack_sz, FD_SHMEM_NORMAL_PAGE_SZ ) ) ) {
    FD_LOG_ERR(( "invalid stack_sz %lu", stack_sz ));
  }

  void * mem = mmap( NULL, stack_sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( mem==MAP_FAILED ) ) {
    FD_LOG_ERR(( "mmap(NULL,%lu,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0) failed (%i-%s)",
                 stack_sz, errno, fd_io_strerror( errno ) ));
  }

  return mem;
}

void
fd_racesan_stack_destroy( void * stack_bottom,
                          ulong  stack_sz ) {
  if( FD_UNLIKELY( munmap( stack_bottom, stack_sz )!=0 ) ) {
    FD_LOG_ERR(( "munmap(%p,%lu) failed (%i-%s)",
                 stack_bottom, stack_sz, errno, fd_io_strerror( errno ) ));
  }
}

#endif /* FD_HAS_HOSTED */

/* AddressSanitizer routines for switching stacks.  These are called
   immediately before calling swapcontext(2) and just after control flow
   has entered the target context we swapped to. */

static inline void
fd_racesan_async_enter_start( fd_racesan_async_t * async ) {
  // FD_LOG_NOTICE(( "enter_start frame=%p stack=[%p,%p)", __builtin_frame_address(0), async->stack_bottom, (void *)( (ulong)async->stack_bottom+async->stack_sz ) ));
  FD_COMPILER_MFENCE();
  fd_asan_start_switch_fiber( NULL, async->stack_bottom, async->stack_sz );
  FD_COMPILER_MFENCE();
}

static inline void
fd_racesan_async_enter_finish( fd_racesan_async_t * async ) {
  /* Back up the main context's stack parameters */
  FD_COMPILER_MFENCE();
  fd_asan_finish_switch_fiber( NULL, &async->asan_stack_bottom_old, &async->asan_stack_size_old );
  FD_COMPILER_MFENCE();
  // FD_LOG_NOTICE(( "enter_finish frame=%p", __builtin_frame_address(0) ));
}

static inline void
fd_racesan_async_exit_start( fd_racesan_async_t * async ) {
  /* Restore the main context's stack parameters */
  // FD_LOG_NOTICE(( "exit_start frame=%p stack_old=[%p,%p)", __builtin_frame_address(0), async->asan_stack_bottom_old, (void *)( (ulong)async->asan_stack_bottom_old+async->asan_stack_size_old ) ));
  FD_COMPILER_MFENCE();
  fd_asan_start_switch_fiber( NULL, async->asan_stack_bottom_old, async->asan_stack_size_old );
  FD_COMPILER_MFENCE();
}

static inline void
fd_racesan_async_exit_finish( fd_racesan_async_t * async ) {
  (void)async;
  FD_COMPILER_MFENCE();
  fd_asan_finish_switch_fiber( NULL, NULL, 0UL );
  FD_COMPILER_MFENCE();
  // FD_LOG_NOTICE(( "exit_finish frame=%p", __builtin_frame_address(0) ));
}

/* fd_racesan_async_yield context switches out to the caller of the
   fd_racesan_async_step function. */

__attribute__((no_sanitize_address)) static void
fd_racesan_async_yield( fd_racesan_async_t * async ) {
  FD_COMPILER_MFENCE();
  fd_racesan_async_exit_start( async );
  FD_COMPILER_MFENCE();
  if( FD_UNLIKELY( 0!=swapcontext( &async->ctx, &async->caller ) ) ) {
    FD_LOG_ERR(( "failed to yield from async fn: swapcontext failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  FD_COMPILER_MFENCE();
  fd_racesan_async_enter_finish( async );
  FD_COMPILER_MFENCE();
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
  fd_racesan_async_enter_finish( async );
  async->fn( async->fn_ctx );
  async->done = 1;
  fd_racesan_exit();
  fd_racesan_async_yield( async );
}

fd_racesan_async_t *
fd_racesan_async_new( fd_racesan_async_t *    async,
                      void *                  stack_bottom,  /* lowest address of stack */
                      ulong                   stack_max,
                      fd_racesan_async_fn_t * async_fn,
                      void *                  ctx ) {
  if( FD_UNLIKELY( !stack_bottom ) ) {
    FD_LOG_WARNING(( "NULL stack_bottom" ));
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)stack_bottom, 16UL ) ) ) {
    FD_LOG_WARNING(( "misaligned stack_bottom" ));
  }
  if( FD_UNLIKELY( !stack_max ) ) {
    FD_LOG_WARNING(( "zero stack_max" ));
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( stack_max, 16UL ) ) ) {
    FD_LOG_WARNING(( "misaligned stack_max" ));
  }

  memset( async, 0, sizeof(fd_racesan_async_t) );
  async->stack_bottom = stack_bottom;
  async->stack_sz     = stack_max;

  fd_racesan_new( async->racesan, async );
  fd_racesan_inject_default( async->racesan, fd_racesan_async_hook );

  async->fn_ctx = ctx;
  async->fn     = async_fn;

  if( FD_UNLIKELY( 0!=getcontext( &async->ctx ) ) ) {
    FD_LOG_ERR(( "getcontext failed" ));
  }
  async->ctx.uc_stack.ss_sp   = async->stack_bottom;
  async->ctx.uc_stack.ss_size = async->stack_sz;
  makecontext( &async->ctx, (void (*)( void ))fd_racesan_async_target, 1, async );

  return async;
}

void *
fd_racesan_async_delete( fd_racesan_async_t * async ) {
  fd_racesan_delete( async->racesan );
  return async;
}

int
fd_racesan_async_step_private( fd_racesan_async_t * async ) {
  if( FD_UNLIKELY( async->done ) ) return FD_RACESAN_ASYNC_RET_EXIT;

  fd_racesan_enter( async->racesan );
  fd_racesan_async_enter_start( async );
  if( FD_UNLIKELY( 0!=swapcontext( &async->caller, &async->ctx ) ) ) {
    FD_LOG_ERR(( "failed to step into async fn: swapcontext failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  fd_racesan_async_exit_finish( async );

  return async->done ? FD_RACESAN_ASYNC_RET_EXIT : FD_RACESAN_ASYNC_RET_HOOK;
}

int
fd_racesan_async_hook_name_eq( fd_racesan_async_t * async,
                               char const *         hook_name ) {
  ulong len  = strlen( hook_name );
  ulong hash = fd_racesan_strhash( hook_name, len );
  return async->name_hash==hash;
}

int
fd_racesan_async_step_until( fd_racesan_async_t * async,
                             char const *         hook_name,
                             ulong                step_max ) {
  ulong len  = strlen( hook_name );
  ulong hash = fd_racesan_strhash( hook_name, len );
  for( ulong step=0UL; step<step_max; step++ ) {
    int step_ret = fd_racesan_async_step( async );
    if( FD_UNLIKELY( step_ret==FD_RACESAN_ASYNC_RET_EXIT ) ) return FD_RACESAN_ASYNC_RET_EXIT;
    if( FD_LIKELY( async->name_hash==hash ) ) return FD_RACESAN_ASYNC_RET_HOOK;
  }
  return FD_RACESAN_ASYNC_RET_TIMEOUT;
}

void
fd_racesan_async_reset( fd_racesan_async_t * async ) {
  makecontext( &async->ctx, (void (*)( void ))fd_racesan_async_target, 1, async );
  async->done = 0;
}
