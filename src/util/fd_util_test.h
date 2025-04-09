#ifndef HEADER_fd_src_util_fd_util_test_h
#define HEADER_fd_src_util_fd_util_test_h

#include "fd_util.h"

FD_PROTOTYPES_BEGIN

/* fd_test_suppress_coredump attempts to disable coredump creation for
   the caller's PID.  On Linux, uses pr_set_dumpable, and silently
   ignores failure to disable coredumps.  No-op on platforms other than
   Linux. */

void
fd_test_suppress_coredump( void );

FD_PROTOTYPES_END

#if FD_HAS_HOSTED

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define FD_TEST_FORCE_USE( EXPR ) do { \
    __typeof__(EXPR) res = (EXPR); \
    __asm__("" : "+r"(res)); \
  } while(0)

/* FD_EXPECT_SIGABRT verifies that running 'CALL' throws a SIGABRT
   signal.  Forks the current process and runs 'CALL' in the child.
   The caller blocks until the child is done, then checks that the exit
   reason is SIGABRT.  If this is not the case, exits the caller with
   FD_LOG_ERR. */

#define FD_EXPECT_SIGABRT( CALL ) do {                                 \
    FD_LOG_DEBUG(( "Testing that %s causes SIGABRT", #CALL ));         \
    pid_t pid = fork();                                                \
    FD_TEST( pid >= 0 );                                               \
    if( pid == 0 ) {                                                   \
      fd_test_suppress_coredump();                                     \
      /* we don't want to confuse the user with a CRIT log */          \
      fd_log_level_logfile_set( 6 );                                   \
      CALL;                                                            \
      _exit( 0 );                                                      \
    }                                                                  \
    int status = 0;                                                    \
    wait( &status );                                                   \
    FD_TEST( WIFSIGNALED(status) && WTERMSIG(status)==6 );             \
  } while(0)                                                           \

#define FD_EXPECT_LOG_CRIT( CALL ) FD_EXPECT_SIGABRT( FD_TEST_FORCE_USE( CALL ) )
#define FD_EXPECT_LOG_CRIT_VOID( CALL ) FD_EXPECT_SIGABRT( CALL )

/* FD_EXPECT_EXIT1 verifies that running 'CALL' results in the process
   exiting with exit code 1.  Forks the current process and runs 'CALL'
   in the child.  The caller blocks until the child is done, then checks
   that the exit code is 1.  If this is not the case, exits the caller
   with FD_LOG_ERR. */

#define FD_EXPECT_EXIT1( CALL ) do {                                   \
    FD_LOG_DEBUG(( "Testing that %s causes SIGABRT", #CALL ));         \
    pid_t pid = fork();                                                \
    FD_TEST( pid >= 0 );                                               \
    if( pid == 0 ) {                                                   \
      /* we don't want to confuse the user with an ERR log */          \
      fd_log_level_logfile_set( 5 );                                   \
      CALL;                                                            \
      _exit( 0 );                                                      \
    }                                                                  \
    int status = 0;                                                    \
    wait( &status );                                                   \
    FD_TEST( WIFEXITED(status) && WEXITSTATUS(status)==1 );            \
  } while(0)

#endif /* FD_HAS_HOSTED */

#endif /* HEADER_fd_src_util_fd_util_test_h */
