#include "fd_valloc.h"
#include "../bits/fd_bits.h"
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

static volatile ushort lock = 0;

static void *
fd_backtracing_malloc_virtual( void * self,
                               ulong  align,
                               ulong  sz ) {
  for(;;) {
    if( FD_LIKELY( !lock ) ) {
      if( FD_LIKELY( !FD_ATOMIC_CAS( &lock, 0, 0xFFFF ) ) ) break;
    }
    FD_SPIN_PAUSE();
  }
  FD_COMPILER_MFENCE();

  void * addr = fd_valloc_malloc( *(fd_valloc_t *)self, align, sz );
  void * btrace[128];
  int btrace_cnt = backtrace( btrace, 128 );

  char buf[1024];
  int len = sprintf(buf,"+++ ALLOC:%d:0x%016lx:%lu:%lu\n", btrace_cnt, (ulong)addr, align, sz );
  long x = write(1, buf, (ulong)len);
  backtrace_symbols_fd( btrace, btrace_cnt, 1 );
  x=write(1, "---\n", 4UL);
  (void)x;
  FD_COMPILER_MFENCE();
  lock = 0;
  return addr;
}

static void
fd_backtracing_free_virtual( void * self,
                             void * addr ) {
  for(;;) {
  if( FD_LIKELY( !lock ) ) {
      if( FD_LIKELY( !FD_ATOMIC_CAS( &lock, 0, 0xFFFF ) ) ) break;
    }
    FD_SPIN_PAUSE();
  }
  FD_COMPILER_MFENCE();
  fd_valloc_free( *(fd_valloc_t *)self, addr );
  void * btrace[128];
  int btrace_cnt = backtrace( btrace, 128 );
  char buf[1024];
  int len = sprintf(buf, "+++ FREE:%d:0x%016lx\n", btrace_cnt, (ulong)addr );
  long x = write(1, buf, (ulong)len);
  backtrace_symbols_fd( btrace, btrace_cnt, 1 );

  x=write(1, "---\n", 4UL);
  (void)x;
  FD_COMPILER_MFENCE();
  lock = 0;
}


const fd_valloc_vtable_t
fd_libc_vtable = {
  .malloc = fd_libc_malloc_virtual,
  .free   = fd_libc_free_virtual
};

const fd_valloc_vtable_t
fd_backtracing_vtable = {
  .malloc = fd_backtracing_malloc_virtual,
  .free   = fd_backtracing_free_virtual
};
