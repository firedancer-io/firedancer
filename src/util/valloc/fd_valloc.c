#include "fd_valloc.h"
#include "../bits/fd_bits.h"
#include "../log/fd_log.h"
#include <stdlib.h>
#include <stdio.h>
#include <execinfo.h>
#include <unistd.h>

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

#if FD_HAS_HOSTED
static volatile ushort backtracing_lock = 0;

static void *
fd_backtracing_malloc_virtual( void * self,
                               ulong  align,
                               ulong  sz ) {
  for(;;) {
    if( FD_LIKELY( !backtracing_lock ) ) {
      if( FD_LIKELY( !FD_ATOMIC_CAS( &backtracing_lock, 0, 0xFFFF ) ) ) break;
    }
    FD_SPIN_PAUSE();
  }
  FD_COMPILER_MFENCE();

  void * addr = fd_valloc_malloc( *(fd_valloc_t *)self, align, sz );
  void * btrace[128];
  int btrace_cnt = backtrace( btrace, 128 );

  char buf[1024];
  int len = sprintf(buf,"+++ ALLOC:%d:0x%016lx:%lu:%lu\n", btrace_cnt, (ulong)addr, align, sz );
  if( write( STDOUT_FILENO, buf, (ulong)len )<0 ) {
    FD_LOG_ERR(( "cannot write to stdout" ));
  }
  backtrace_symbols_fd( btrace, btrace_cnt, STDOUT_FILENO );
  if( write( STDOUT_FILENO, "---\n", 4UL )<0 ) {
    FD_LOG_ERR(( "cannot write to stdout" ));
  }
  FD_COMPILER_MFENCE();
  backtracing_lock = 0;
  return addr;
}

static void
fd_backtracing_free_virtual( void * self,
                             void * addr ) {
  for(;;) {
  if( FD_LIKELY( !backtracing_lock ) ) {
      if( FD_LIKELY( !FD_ATOMIC_CAS( &backtracing_lock, 0, 0xFFFF ) ) ) break;
    }
    FD_SPIN_PAUSE();
  }
  FD_COMPILER_MFENCE();
  fd_valloc_free( *(fd_valloc_t *)self, addr );
  void * btrace[128];
  int btrace_cnt = backtrace( btrace, 128 );
  char buf[1024];
  int len = sprintf(buf, "+++ FREE:%d:0x%016lx\n", btrace_cnt, (ulong)addr );
  if( write( STDOUT_FILENO, buf, (ulong)len )<0 ) {
    FD_LOG_ERR(( "cannot write to stdout" ));
  }
  backtrace_symbols_fd( btrace, btrace_cnt, STDOUT_FILENO );

  if( write( STDOUT_FILENO, "---\n", 4UL )<0 ) {
    FD_LOG_ERR(( "cannot write to stdout" ));
  }
  FD_COMPILER_MFENCE();
  backtracing_lock = 0;
}
#endif

const fd_valloc_vtable_t
fd_libc_vtable = {
  .malloc = fd_libc_malloc_virtual,
  .free   = fd_libc_free_virtual
};

#if FD_HAS_HOSTED
const fd_valloc_vtable_t
fd_backtracing_vtable = {
  .malloc = fd_backtracing_malloc_virtual,
  .free   = fd_backtracing_free_virtual
};
#endif
