#include "../../util/fd_util.h"
#include "fd_mvcc.h"

ulong *
fd_mvcc_version_laddr( fd_mvcc_t * mvcc ) {
  return &mvcc->version;
}

ulong
fd_mvcc_begin_write( fd_mvcc_t * mvcc ) {
  ulong version = FD_ATOMIC_FETCH_AND_ADD( fd_mvcc_version_laddr( mvcc ), 1 );
  FD_COMPILER_MFENCE();
  return version;
}

ulong
fd_mvcc_end_write( fd_mvcc_t * mvcc ) {
  FD_COMPILER_MFENCE();
  return FD_ATOMIC_FETCH_AND_ADD( fd_mvcc_version_laddr( mvcc ), 1 );
}

ulong
fd_mvcc_read( fd_mvcc_t * mvcc ) {
  FD_COMPILER_MFENCE();
  ulong version = FD_VOLATILE_CONST( mvcc->version );
  FD_COMPILER_MFENCE();
  return version;
}

ulong
fd_mvcc_begin_read( fd_mvcc_t * mvcc ) {
  return fd_mvcc_read( mvcc );
}

ulong
fd_mvcc_end_read( fd_mvcc_t * mvcc ) {
  return fd_mvcc_read( mvcc );
}
