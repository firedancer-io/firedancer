#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_io_uring_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_io_uring_h

/* fd_accdb_io_uring.h provides io_uring functionality to accdb joins. */

#include "../../util/fd_util.h"
#include "../../util/io_uring/fd_io_uring.h"

/* FD_ACCDB_IO_URING_WORKER_MAX bounds the number of kernel io-wq
   workers per ring (used when the backing filesystem does not support
   non-blocking reads, e.g. buffered ext4 misses). */

#define FD_ACCDB_IO_URING_WORKER_MAX (8U)

/* FD_ACCDB_IO_URING_RLIMIT_NPROC is the RLIMIT_NPROC a sandboxed tile
   using an accdb io_uring needs.  io-wq workers are created lazily and
   count against RLIMIT_NPROC (the sandbox default of 0 makes requests
   that need a worker, e.g. buffered writes, fail with ECANCELED). */

#define FD_ACCDB_IO_URING_RLIMIT_NPROC (1024UL)

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_accdb_io_uring_align( void ) {
  return FD_SHMEM_NORMAL_PAGE_SZ;
}

ulong
fd_accdb_io_uring_footprint( ulong depth );

#if defined(__linux__)

/* fd_accdb_io_uring_init creates an io_uring in shmem with depth
   submission and completion queue entries, registers accdb_fd as fixed
   file 0, restricts the ring to positional readv (and writev if
   writable) on fixed files, and enables it.  The ring may only be used
   by the calling thread.  Returns ring  on success.  On failure, logs a
   warning and returns NULL (errno is set, e.g. EPERM if io_uring is
   disabled via sysctl). */

fd_io_uring_t *
fd_accdb_io_uring_init( fd_io_uring_t * ring,
                        void *          shmem,
                        ulong           depth,
                        int             accdb_fd,
                        int             writable );

/* fd_accdb_io_uring_fini destroys a ring created with
   fd_accdb_io_uring_init. */

void
fd_accdb_io_uring_fini( fd_io_uring_t * ring );

#endif /* defined(__linux__) */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_io_uring_h */
