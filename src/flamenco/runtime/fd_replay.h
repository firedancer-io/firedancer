#ifndef HEADER_fd_src_flamenco_runtime_fd_replay_h
#define HEADER_fd_src_flamenco_runtime_fd_replay_h

struct slot_capitalization {
  ulong key;
  uint  hash;
  ulong capitalization;
};
typedef struct slot_capitalization slot_capitalization_t;

#define MAP_NAME        capitalization_map
#define MAP_T           slot_capitalization_t
#define LG_SLOT_CNT 15
#define MAP_LG_SLOT_CNT LG_SLOT_CNT
#include "../../util/tmpl/fd_map.c"

#include "fd_tvu.h"

#define FD_REPLAY_STATE_ALIGN     (8UL)

#define FD_REPLAY_STATE_FOOTPRINT (sizeof(struct fd_runtime_ctx))

FD_PROTOTYPES_BEGIN

/* fd_runtime_ctx_{align,footprint} return FD_REPLAY_STATE_{ALIGN,FOOTPRINT}. */

FD_FN_CONST ulong
fd_runtime_ctx_align( void );

FD_FN_CONST ulong
fd_runtime_ctx_footprint( void );

void *
fd_runtime_ctx_new( void * shmem );

/* fd_runtime_ctx_join returns the local join to the wksp backing the funk.
   The lifetime of the returned pointer is at least as long as the
   lifetime of the local join.  Assumes funk is a current local join. */

fd_runtime_ctx_t *
fd_runtime_ctx_join( void * state );

/* fd_runtime_ctx_leave leaves an existing join.  Returns the underlying
   shfunk on success and NULL on failure.  (logs details). */

void *
fd_runtime_ctx_leave( fd_runtime_ctx_t * state );

/* fd_runtime_ctx_delete unformats a wksp allocation used as a replay_state */
void *
fd_runtime_ctx_delete( void * state );

int fd_replay( fd_runtime_ctx_t * state, fd_runtime_args_t *args );

FD_PROTOTYPES_END


#endif
