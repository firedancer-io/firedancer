#ifndef HEADER_fd_src_discof_restore_utils_fd_snapin_shmem_h
#define HEADER_fd_src_discof_restore_utils_fd_snapin_shmem_h

/* Shared memory state for parallel snapshot loaders. */

#include "../../../util/fd_util_base.h"

/* Tile 0 publishes the attempt after setup.  Workers hold data until
   the attempt number matches, then claim appendvecs from next_appendvec. */
struct fd_snapin_shmem {
  ulong magic;
  ulong worker_cnt;

  /* Tile 0 publishes the attempt number and fork ID after setup.  Each
     INIT increments the number, including retries and the transition
     from full to incremental. */
  struct __attribute__((aligned(64))) {
    ulong number;
    ulong fork_id;
  } attempt;

  /* Isolate the hot claim counter on its own cache line. */
  ulong next_appendvec __attribute__((aligned(128)));

  /* Workers add attempt totals before ACKing FINI. */
  struct {
    ulong loaded;
    ulong duplicates;
    ulong input_lamports;
    ulong duplicate_lamports;
  } totals;
};

typedef struct fd_snapin_shmem fd_snapin_shmem_t;

#define FD_SNAPIN_SHMEM_MAGIC (0xF17EDA2C0501A910UL)

static inline ulong
fd_snapin_shmem_align( void ) {
  return alignof(fd_snapin_shmem_t);
}

static inline ulong
fd_snapin_shmem_footprint( void ) {
  return sizeof(fd_snapin_shmem_t);
}

static inline void *
fd_snapin_shmem_new( void * mem,
                     ulong  worker_cnt ) {
  fd_snapin_shmem_t * shmem = (fd_snapin_shmem_t *)mem;
  fd_memset( shmem, 0, sizeof(*shmem) );
  shmem->worker_cnt = worker_cnt;
  FD_COMPILER_MFENCE();
  shmem->magic = FD_SNAPIN_SHMEM_MAGIC;
  return mem;
}

static inline fd_snapin_shmem_t *
fd_snapin_shmem_join( void * mem ) {
  fd_snapin_shmem_t * shmem = (fd_snapin_shmem_t *)mem;
  if( FD_UNLIKELY( shmem->magic!=FD_SNAPIN_SHMEM_MAGIC ) ) return NULL;
  return shmem;
}

#endif /* HEADER_fd_src_discof_restore_utils_fd_snapin_shmem_h */
