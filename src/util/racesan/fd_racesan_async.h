#ifndef HEADER_fd_src_flamenco_racesan_fd_racesan_async_h
#define HEADER_fd_src_flamenco_racesan_fd_racesan_async_h

#include "fd_racesan.h"
#include <ucontext.h>

#define FD_RACESAN_ASYNC_STACK_MAX (1UL<<19) /* 512 KiB */

typedef void
fd_racesan_async_fn_t( void * ctx );

struct fd_racesan_async {
  ucontext_t   ctx;
  ucontext_t * caller;

  void *                  fn_ctx;
  fd_racesan_async_fn_t * fn;

  ulong name_hash;
  uint  done : 1;

  uchar stack[ FD_RACESAN_ASYNC_STACK_MAX ] __attribute__((aligned(64)));
};

typedef struct fd_racesan_async fd_racesan_async_t;

FD_PROTOTYPES_BEGIN

fd_racesan_async_t *
fd_racesan_async_new( fd_racesan_async_t *    async,
                      fd_racesan_async_fn_t * async_fn,
                      void *                  ctx );

void *
fd_racesan_async_delete( fd_racesan_async_t * async );

int
fd_racesan_async_step( fd_racesan_async_t * async );

int
fd_racesan_async_hook_name_eq( fd_racesan_async_t * async,
                               char const *         hook_name );

void
fd_racesan_async_reset( fd_racesan_async_t * async );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_racesan_fd_racesan_async_h */
