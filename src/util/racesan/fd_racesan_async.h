#ifndef HEADER_fd_src_util_racesan_fd_racesan_async_h
#define HEADER_fd_src_util_racesan_fd_racesan_async_h

#include "fd_racesan.h"
#include <stddef.h>
#include <ucontext.h>

#define FD_RACESAN_ASYNC_RET_EXIT    (0)
#define FD_RACESAN_ASYNC_RET_HOOK    (1)
#define FD_RACESAN_ASYNC_RET_TIMEOUT (2)

typedef void
fd_racesan_async_fn_t( void * ctx );

struct fd_racesan_async {
  fd_racesan_t racesan[1];

  ucontext_t ctx;
  ucontext_t caller;

  void *                  fn_ctx;
  fd_racesan_async_fn_t * fn;

  ulong name_hash;
  uint  done : 1;

  void * stack_bottom;
  ulong  stack_sz;

  /* When using ASan, remember stack params of caller/main thread */
  void const * asan_stack_bottom_old;
  ulong        asan_stack_size_old;
};

typedef struct fd_racesan_async fd_racesan_async_t;

FD_PROTOTYPES_BEGIN

#if FD_HAS_HOSTED

/* fd_racesan_stack_create requests a new private anonymous memory
   region from the OS suitable for use as a racesan_async stack, and
   maps it at an address chosen by the OS.  Returns the lowest address
   (bottom) of that stack.  Terminates with FD_LOG_ERR on failure to
   map stack region.  stack_sz MUST be FD_SHMEM_NORMAL_PAGE_SZ aligned. */

void *
fd_racesan_stack_create( ulong stack_sz );

/* fd_racesan_stack_destroy undoes the effects of
   fd_racesan_stack_create.  Terminates with FD_LOG_ERR on failure to
   unmap stack. */

void
fd_racesan_stack_destroy( void * stack_bottom,
                          ulong  stack_sz );

#endif /* FD_HAS_HOSTED */

/* fd_racesan_async_new begins an async function call.

   WARNING: stack_bottom SHOULD be normal page-aligned.  Technically,
   16 byte alignment is sufficient on x86-psABI.  LLVM compiler-rt ASan,
   however, uses munmap() when pivoting stacks in swapcontext().  Due to
   a bug in that code, if the stack is less than 4K aligned, the munmap
   call will blow away random other data that happens to be in the same
   page.

   Use fd_racesan_stack_{create,destroy} to get new (reusable) stack
   regions instead. */

fd_racesan_async_t *
fd_racesan_async_new( fd_racesan_async_t *    async,
                      void *                  stack_bottom,  /* lowest address of stack */
                      ulong                   stack_max,
                      fd_racesan_async_fn_t * async_fn,
                      void *                  ctx );

void *
fd_racesan_async_delete( fd_racesan_async_t * async );

/* fd_progcache_async_step continues executing an async function call
   until it reaches a hook or until the function exits.  Returns
   RET_HOOK if a hook was reached (call still in-progress), or RET_EXIT
   if the function call exited. */

int
fd_racesan_async_step_private( fd_racesan_async_t * async );

#define fd_racesan_async_step( async )              \
  __extension__({                                   \
    FD_COMPILER_MFENCE();                           \
    int r = fd_racesan_async_step_private( async ); \
    FD_COMPILER_MFENCE();                           \
    r;                                              \
  })

/* fd_racesan_async_hook_name_eq returns 1 if the async function call is
   currently suspended at a hook with the given name.  Else returns 0. */

int
fd_racesan_async_hook_name_eq( fd_racesan_async_t * async,
                               char const *         hook_name );

/* fd_progcache_async_step_until continues executing an async function
   call until it reaches a hook with the given name.  Returns RET_HOOK
   if the hook was reached, RET_EXIT if the call exited, or RET_TIMEOUT
   if more than step_max steps were made.  */

int
fd_racesan_async_step_until( fd_racesan_async_t * async,
                             char const *         hook_name,
                             ulong                step_max );

void
fd_racesan_async_reset( fd_racesan_async_t * async );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_racesan_fd_racesan_async_h */
