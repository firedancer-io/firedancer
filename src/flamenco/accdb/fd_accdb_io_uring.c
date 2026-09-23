#include "fd_accdb_io_uring.h"
#include "../../util/io_uring/fd_io_uring_setup.h"

#include "../../util/io_uring/fd_io_uring_register.h"
#include <errno.h>

ulong
fd_accdb_io_uring_footprint( ulong depth ) {
  return fd_io_uring_shmem_footprint( depth, depth );
}

#if defined(__linux__)

fd_io_uring_t *
fd_accdb_io_uring_init( fd_io_uring_t * ring,
                        void *          shmem,
                        ulong           depth,
                        int             accdb_fd,
                        int             writable ) {
  ring->ioring_fd = -1;
  if( FD_UNLIKELY( !fd_accdb_io_uring_footprint( depth ) ) ) {
    FD_LOG_WARNING(( "invalid io_uring depth %lu", depth ));
    errno = EINVAL;
    return NULL;
  }

  FD_TEST( fd_io_uring_shmem_align()==fd_accdb_io_uring_align() );

  fd_io_uring_params_t params[1];
  fd_io_uring_params_init( params, (uint)depth );
  params->flags |= FD_IORING_SETUP_COOP_TASKRUN | FD_IORING_SETUP_DEFER_TASKRUN;

  if( FD_UNLIKELY( !fd_io_uring_init_shmem( ring, params, shmem, depth, depth ) ) ) {
    FD_LOG_WARNING(( "io_uring_setup failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return NULL;
  }
  int ring_fd = ring->ioring_fd;

  if( FD_UNLIKELY( fd_io_uring_register_files( ring_fd, &accdb_fd, 1U )<0 ) ) {
    FD_LOG_WARNING(( "io_uring_register(IORING_REGISTER_FILES) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    goto fail;
  }

  uint max_workers[2] = { FD_ACCDB_IO_URING_WORKER_MAX, FD_ACCDB_IO_URING_WORKER_MAX };
  if( FD_UNLIKELY( fd_io_uring_register( ring_fd, FD_IORING_REGISTER_IOWQ_MAX_WORKERS, max_workers, 2U )<0 ) ) {
    FD_LOG_WARNING(( "io_uring_register(IORING_REGISTER_IOWQ_MAX_WORKERS) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    goto fail;
  }

  fd_io_uring_restriction_t restrictions[ 3 ];
  uint                      restriction_cnt = 0U;
  restrictions[ restriction_cnt++ ] = (fd_io_uring_restriction_t){ .opcode = FD_IORING_RESTRICTION_SQE_FLAGS_REQUIRED, .sqe_flags = FD_IOSQE_FIXED_FILE };
  restrictions[ restriction_cnt++ ] = (fd_io_uring_restriction_t){ .opcode = FD_IORING_RESTRICTION_SQE_OP, .sqe_op = FD_IORING_OP_READV };
  if( writable ) {
    restrictions[ restriction_cnt++ ] = (fd_io_uring_restriction_t){ .opcode = FD_IORING_RESTRICTION_SQE_OP, .sqe_op = FD_IORING_OP_WRITEV };
  }
  if( FD_UNLIKELY( fd_io_uring_register_restrictions( ring_fd, restrictions, restriction_cnt )<0 ) ) {
    FD_LOG_WARNING(( "io_uring_register(IORING_REGISTER_RESTRICTIONS) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    goto fail;
  }

  if( FD_UNLIKELY( fd_io_uring_enable_rings( ring_fd )<0 ) ) {
    FD_LOG_WARNING(( "io_uring_register(IORING_REGISTER_ENABLE_RINGS) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    goto fail;
  }

  return ring;

fail:;
  int err = errno;
  fd_io_uring_fini( ring );
  errno = err;
  return NULL;
}

void
fd_accdb_io_uring_fini( fd_io_uring_t * ring ) {
  fd_io_uring_fini( ring );
}

#endif /* defined(__linux__) */
