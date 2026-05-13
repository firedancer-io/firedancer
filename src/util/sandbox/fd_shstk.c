#define _GNU_SOURCE
#include "fd_shstk.h"
#include "../fd_util.h"
#include <errno.h>
#include <stdlib.h>
/* GCC 11 complains about "unused parameters" on naked functions */
#pragma GCC diagnostic ignored "-Wunused-parameter"

#if FD_HAS_HOSTED && defined(__linux__) && defined(__x86_64__) && !FD_HAS_ASAN && !FD_HAS_MSAN && !FD_HAS_UBSAN

#ifndef ARCH_SHSTK_ENABLE
#define ARCH_SHSTK_ENABLE 0x5001
#endif

#ifndef ARCH_SHSTK_LOCK
#define ARCH_SHSTK_LOCK 0x5003
#endif

#ifndef ARCH_SHSTK_STATUS
#define ARCH_SHSTK_STATUS 0x5005
#endif

#ifndef ARCH_SHSTK_SHSTK
#define ARCH_SHSTK_SHSTK 1
#endif

#include <asm/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

__attribute__((noreturn))
void
fd_shstk_enter( int (* main_fn)( int     argc,
                                 char ** argv ),
                int     argc,
                char ** argv ) {

  ulong feature;
  int status = (int)syscall( SYS_arch_prctl, ARCH_SHSTK_STATUS, &feature );
  if( FD_UNLIKELY( status ) ) {
    FD_LOG_WARNING(( "sandbox: could not detect if shadow stack is enabled (%i-%s), trying to enable them anyway", errno, fd_io_strerror( errno ) ));
  } else if( feature & ARCH_SHSTK_SHSTK ) {
    FD_LOG_INFO(( "sandbox: shadow stack enabled by libc" ));
    /* Lock shadow stack feature in case libc did not */
    (void)syscall( SYS_arch_prctl, ARCH_SHSTK_LOCK, ARCH_SHSTK_SHSTK );
    exit( main_fn( argc, argv ) );
  } else {
    FD_LOG_INFO(( "sandbox: shadow stack not enabled by libc, enabling" ));
  }

  /* Dispatch a syscall without using the stack */

  long enable_res;
  __asm__ volatile (
    "syscall"
    : "=a" (enable_res)
    : "a" ((ulong)SYS_arch_prctl),
      "D" ((ulong)ARCH_SHSTK_ENABLE),
      "S" ((ulong)ARCH_SHSTK_SHSTK)
    : "rcx", "r11", "memory"
  );

  /* Now that shadow stack is enabled, we can no longer return from this
     function, since that would cause a CET violation. */

  if( FD_UNLIKELY( enable_res!=0 ) ) {
    FD_LOG_WARNING(( "sandbox: failed to enable shadow stack (%ld-%s), running with weakened sandbox", -enable_res, fd_io_strerror( -(int)enable_res ) ));
  } else {
    int rc = (int)syscall( SYS_arch_prctl, ARCH_SHSTK_LOCK, ARCH_SHSTK_SHSTK );
    if( FD_UNLIKELY( rc ) ) FD_LOG_WARNING(( "sandbox: failed to enforce shadow stack (arch_prctl(ARCH_SHSTK_LOCK,ARCH_SHSTK_SHSTK) failed (%i-%s))", errno, fd_io_strerror( errno ) ));
    FD_LOG_INFO(( "sandbox: shadow stack enabled" ));
  }
  exit( main_fn( argc, argv ) );
}

#else /* portable variant */

__attribute__((noreturn))
void
fd_shstk_enter( int (* main_fn)( int     argc,
                                 char ** argv ),
                int     argc,
                char ** argv ) {
  FD_LOG_INFO(( "sandbox: build does not support shadow stack" ));
  exit( main_fn( argc, argv ) );
}

#endif
