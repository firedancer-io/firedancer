#include "fd_funk_pkeys.h"

#if defined(FD_HAS_HOSTED) && FD_HAS_HOSTED && defined(__linux__) && defined(__x86_64__)
#define HAS_PKEYS 1
#else
#define HAS_PKEYS 0
#endif

#if HAS_PKEYS
#include "../util/sandbox/fd_pkeys.h"
#include "../util/sandbox/fd_sandbox.h"
#include <errno.h>
#endif

int
fd_funk_pkey_setup( fd_wksp_t * funk_wksp ) {
  FD_TEST( funk_wksp );

#if HAS_PKEYS
  if( FD_UNLIKELY( fd_sandbox_getpid()!=fd_sandbox_gettid() ) ) {
    FD_LOG_INFO(( "userland memory protection disabled: not compatible with single-process mode" ));
    return -1;
  }

  int pkey = fd_syscall_pkey_alloc( 0, 0 );
  if( FD_UNLIKELY( pkey<0 ) ) {
    FD_LOG_INFO(( "userland memory protection disabled: pkey_alloc(0,0) failed (%i-%s)",
                  errno, fd_io_strerror( errno ) ));
    return -1;
  }

  int err = fd_wksp_pkey_install( funk_wksp, pkey );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "error while setting up userland memory protection: fd_wksp_pkey_install(funk_wksp,pkey=%d) failed (%i-%s)",
                 pkey, err, fd_io_strerror( err ) ));
  }

  fd_funk_pkey_protect( pkey );
  FD_LOG_INFO(( "userland memory protection enabled (pkey=%d)", pkey ));
  return pkey;
#else
  (void)funk_wksp;
  return -1;
#endif
}

void
fd_funk_pkey_protect( int funk_pkey ) {
#if HAS_PKEYS
  if( FD_LIKELY( funk_pkey>=0 ) ) fd_x86_pkey_update( funk_pkey, 0, 1 );
#else
  (void)funk_pkey;
#endif
}

void
fd_funk_pkey_unprotect( int funk_pkey ) {
#if HAS_PKEYS
  if( FD_LIKELY( funk_pkey>=0 ) ) fd_x86_pkey_update( funk_pkey, 0, 0 );
#else
  (void)funk_pkey;
#endif
}
