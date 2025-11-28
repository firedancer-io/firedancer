#ifndef HEADER_fd_src_util_racesan_fd_racesan_weave_h
#define HEADER_fd_src_util_racesan_fd_racesan_weave_h

/* fd_racesan_weave.h tests interleavings of concurrent algorithms. */

#include "fd_racesan_async.h"

#define FD_RACESAN_WEAVE_MAX (16UL)

struct fd_racesan_weave {
  fd_racesan_async_t * async[ FD_RACESAN_WEAVE_MAX ];
  uint                 async_cnt;

  fd_racesan_async_t * rem[ FD_RACESAN_WEAVE_MAX ];
  uint                 rem_cnt;
};

typedef struct fd_racesan_weave fd_racesan_weave_t;

FD_PROTOTYPES_BEGIN

fd_racesan_weave_t *
fd_racesan_weave_new( fd_racesan_weave_t * weave );

void *
fd_racesan_weave_delete( fd_racesan_weave_t * weave );

void
fd_racesan_weave_add( fd_racesan_weave_t * weave,
                      fd_racesan_async_t * async );

void
fd_racesan_weave_exec_rand( fd_racesan_weave_t * weave,
                            ulong                seed,
                            ulong                step_max );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_racesan_fd_racesan_weave_h */
