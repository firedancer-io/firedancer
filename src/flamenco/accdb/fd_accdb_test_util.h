#ifndef HEADER_fd_src_flamenco_accdb_fd_accdb_test_util_h
#define HEADER_fd_src_flamenco_accdb_fd_accdb_test_util_h

#include "../../util/fd_util.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/mman.h>
#endif

static inline int
fd_accdb_test_file_create( char const * name ) {
#if defined(__linux__)
  int fd = memfd_create( name, 0 );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "memfd_create(%s) failed (%i-%s)", name, errno, fd_io_strerror( errno ) ));
  return fd;
#elif defined(__APPLE__)
  char path[] = "/tmp/fd_accdb_XXXXXX";
  int fd = mkstemp( path );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "mkstemp(%s) failed (%i-%s)", name, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( unlink( path ) ) ) FD_LOG_ERR(( "unlink(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  return fd;
#else
#error "accdb test file creation is unsupported on this platform"
#endif
}

#endif /* HEADER_fd_src_flamenco_accdb_fd_accdb_test_util_h */
