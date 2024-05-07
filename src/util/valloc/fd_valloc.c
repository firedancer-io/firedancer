#ifndef FD_HAS_BACKTRACE
#if __has_include( <execinfo.h> )
#define FD_HAS_BACKTRACE 1
#else
#define FD_HAS_BACKTRACE 0
#endif
#endif

#include "fd_valloc.h"
#include "../bits/fd_bits.h"
#include "../log/fd_log.h"

#include <stdlib.h>
#include <unistd.h>

// #if FD_HAS_BACKTRACE
#include <execinfo.h>
// #endif

static void *
fd_libc_malloc_virtual( void * _self FD_PARAM_UNUSED,
                        ulong  align,
                        ulong  sz ) {
  return aligned_alloc( align, fd_ulong_align_up( sz, align ) );
}

static void
fd_libc_free_virtual( void * _self FD_PARAM_UNUSED,
                      void * _addr ) {
  free( _addr );
}

const fd_valloc_vtable_t
fd_libc_vtable = {
  .malloc = fd_libc_malloc_virtual,
  .free   = fd_libc_free_virtual
};

static void *
fd_backtrace_malloc_virtual( void * _self ,
                             ulong  align,
                             ulong  sz ) {
  void * btrace[128];
  int btrace_cnt = backtrace( btrace, 128 );

  fd_valloc_t * self = (fd_valloc_t *)_self;
  void * addr =  fd_valloc_malloc( *self, align, sz );

  fd_log_private_fprintf_0( STDERR_FILENO, "malloc - addr: 0x%016lx align: %lu size: %lu\n", (ulong)addr, align, sz );
  backtrace_symbols_fd( btrace, btrace_cnt, STDERR_FILENO );
  fd_log_private_fprintf_0( STDERR_FILENO, "---\n" );
  fsync( STDERR_FILENO );

  return addr;
}

static void
fd_backtrace_free_virtual( void * _self __attribute__((unused)),
                           void * _addr ) {
  void * btrace[128];
  int btrace_cnt = backtrace( btrace, 128 );
  
  fd_log_private_fprintf_0( STDERR_FILENO, "free - addr: 0x%016lx\n", (ulong)_addr );
  backtrace_symbols_fd( btrace, btrace_cnt, STDERR_FILENO );
  fd_log_private_fprintf_0( STDERR_FILENO, "---\n" );

  fd_valloc_t * self = (fd_valloc_t *)_self;
  fd_valloc_free( *self, _addr );
}

const fd_valloc_vtable_t
fd_backtrace_vtable = {
  .malloc = fd_backtrace_malloc_virtual,
  .free   = fd_backtrace_free_virtual
};
