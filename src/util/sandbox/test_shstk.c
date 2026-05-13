#define _GNU_SOURCE
#include "fd_shstk.h"
#include "../fd_util.h"
#include <asm/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef ARCH_SHSTK_ENABLE
#define ARCH_SHSTK_ENABLE  (0x5001)
#endif

#ifndef ARCH_SHSTK_STATUS
#define ARCH_SHSTK_STATUS  (0x5005)
#endif

#ifndef ARCH_SHSTK_SHSTK
#define ARCH_SHSTK_SHSTK   (1ULL << 0)
#endif

static int
test_shstk_enabled( void ) {
  ulong features = 0UL;
  if( FD_LIKELY( 0==syscall( SYS_arch_prctl, ARCH_SHSTK_STATUS, &features ) ) ) {
    return !!(features & ARCH_SHSTK_SHSTK);
  }
  return 0;
}

static int
main1( int     argc,
       char ** argv ) {
  (void)argc; (void)argv;
#if !defined(__CET__)
    FD_LOG_NOTICE(( "compiler CET support: no" ));
#else
#  if (__CET__ & 0x1) != 0
     FD_LOG_NOTICE(( "compiler CET support: indirect branch" ));
#  endif
#  if (__CET__ & 0x2) != 0
     FD_LOG_NOTICE(( "compiler CET support: return" ));
#  endif
#endif
  FD_LOG_NOTICE(( "shadow stack enabled: %s", test_shstk_enabled() ? "yes" : "no" ));
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_shstk_enter( main1, argc, argv );
}
