#define _GNU_SOURCE
#include "fd_pkeys.h"
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#if defined(__x86_64__)
#ifndef SYS_pkey_mprotect
#define SYS_pkey_mprotect 329
#endif
#ifndef SYS_pkey_alloc
#define SYS_pkey_alloc 330
#endif
#ifndef SYS_pkey_free
#define SYS_pkey_free 331
#endif
#endif

int
fd_syscall_pkey_alloc( uint flags,
                       uint access_rights ) {
  return (int)syscall( SYS_pkey_alloc, flags, access_rights );
}

int
fd_syscall_pkey_mprotect( void * addr,
                          ulong  size,
                          int    prot,
                          int    pkey ) {
  return (int)syscall( SYS_pkey_mprotect, addr, size, prot, pkey );
}

int
fd_syscall_pkey_free( int pkey ) {
  return (int)syscall( SYS_pkey_free, pkey );
}

int
fd_wksp_pkey_install( fd_wksp_t * wksp,
                      int         pkey ) {
  fd_shmem_join_info_t info[1];
  int err = fd_shmem_join_query_by_join( wksp, info );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "failed to query shmem join info for wksp (err %i-%s)", err, fd_io_strerror( err ) ));
    return err;
  }
  return fd_shmem_pkey_install( info, pkey );
}

int
fd_shmem_pkey_install( fd_shmem_join_info_t const * join_info,
                       int                          pkey ) {
  int prot = PROT_READ;
  if( join_info->mode==FD_SHMEM_JOIN_MODE_READ_WRITE ) prot |= PROT_WRITE;
  if( FD_UNLIKELY( fd_syscall_pkey_mprotect( join_info->shmem, join_info->page_sz * join_info->page_cnt, prot, pkey ) ) ) {
    FD_LOG_WARNING(( "pkey_mprotect failed (err %i-%s)", errno, fd_io_strerror( errno ) ));
    return errno;
  }
  return 0;
}
