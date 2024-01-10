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


#define FD_REPLAY_STATE_ALIGN     (8UL)

struct __attribute__((aligned(FD_REPLAY_STATE_ALIGN))) fd_replay_state {
  fd_exec_slot_ctx_t *   slot_ctx;
  fd_exec_epoch_ctx_t *  epoch_ctx;
  fd_capture_ctx_t *     capture_ctx;

  int                    argc;
  char       **          argv;

  char const *           name;
  ulong                  pages;
  ulong                  end_slot;
  char const *           cmd;
  char const *           reset;
  char const *           load;
  char const *           capitalization_file;
  slot_capitalization_t  capitalization_map_mem[ 1UL << LG_SLOT_CNT ];
  slot_capitalization_t *map;

  FILE                *  capture_file;
  fd_tpool_t          *  tpool;
  ulong                  max_workers;
  uchar                  abort_on_mismatch;

  fd_wksp_t           * local_wksp;
};
typedef struct fd_replay_state fd_replay_state_t;

#define FD_REPLAY_STATE_FOOTPRINT (sizeof(struct fd_replay_state))

FD_PROTOTYPES_BEGIN

/* fd_replay_state_{align,footprint} return FD_REPLAY_STATE_{ALIGN,FOOTPRINT}. */

FD_FN_CONST ulong
fd_replay_state_align( void );

FD_FN_CONST ulong
fd_replay_state_footprint( void );

void *
fd_replay_state_new( void * shmem );

/* fd_replay_state_join returns the local join to the wksp backing the funk.
   The lifetime of the returned pointer is at least as long as the
   lifetime of the local join.  Assumes funk is a current local join. */

fd_replay_state_t *
fd_replay_state_join( void * state );

/* fd_replay_state_leave leaves an existing join.  Returns the underlying
   shfunk on success and NULL on failure.  (logs details). */

void *
fd_replay_state_leave( fd_replay_state_t * state );

/* fd_replay_state_delete unformats a wksp allocation used as a replay_state */
void *
fd_replay_state_delete( void * state );

int fd_replay( fd_replay_state_t * state );

FD_PROTOTYPES_END


#endif
