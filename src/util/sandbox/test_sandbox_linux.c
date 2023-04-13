#ifndef FD_HAS_SANDBOX
#define FD_HAS_SANDBOX
#endif

#ifdef FD_HAS_SANDBOX_LINUX

#define _GNU_SOURCE

#include "../fd_util.h"
#include "fd_sandbox_linux_private.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h> /* Definition of CAP_* and
                                 _LINUX_CAPABILITY_* constants */
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>      /* Definition of SYS_* constants */

#include <sys/types.h>
#include <sys/wait.h>

/* test_should_close_open_fds ensures that, after calling `fd_sandbox_close_fds_beyond`,
   no FDs beyond the specified numbers are opened. */
int
test_should_close_open_fds( void ) {
  int fd = open("/etc/passwd", O_RDONLY);
  // open should not fail
  if ( FD_UNLIKELY( fd == -1 ) )
    FD_LOG_ERR(( "open: %s", strerror(errno) ));

  // Make sure that the new FD is greater than 2. If not, this test is pointless.
  if (fd < 3) {
    FD_LOG_ERR(( "expected opened fd to be at least 3"));
  }

  if ( FD_UNLIKELY( fcntl( fd, F_GETFD ) == -1 ) )
    FD_LOG_ERR( ( "not expecting fcntl(fd, F_GETFD) to be -1" ) );

  fd_sandbox_set_highest_fd_to_keep( fd - 1 );
  fd_sandbox_private_close_fds_beyond();

  if (FD_UNLIKELY ( fcntl( fd, F_GETFD ) != -1 ) )
    FD_LOG_ERR(( "expected fcntl(fd, F_GETFD) to be -1" ));

  return 0;
}

/* test_should_change_user ensures that, after calling `fd_sandbox_change_user`,
   the process' {real,effective}x{uid,gid} are matching the desired user's. */
int
test_should_change_userns( int *    pargc,
                           char *** pargv ) {
  pid_t pid, w;

  if (( pid = fork() )) { // parent
    int wstatus;
    w = waitpid( pid, &wstatus, WUNTRACED );
    if ( FD_UNLIKELY ( w == -1 ) ) {
      FD_LOG_WARNING(( "waitpid: %s", strerror( errno ) ));
      return -1;
    }
    if ( FD_UNLIKELY ( WIFEXITED( wstatus ) && WEXITSTATUS( wstatus ) ) ) {
      FD_LOG_WARNING(( "expected fd_sandbox_change_user to exit gracefully but " "exited with non-zero status, status=%d", WEXITSTATUS(wstatus) ));
      return -1;
    } else if ( FD_UNLIKELY ( WIFSIGNALED( wstatus ) ) ) {
      FD_LOG_WARNING(( "expected fd_sandbox_change_user to exit gracefully but " "killed by signal %s", strsignal(WTERMSIG(wstatus)) ));
      return -1;
    } else if ( FD_UNLIKELY ( WIFSTOPPED( wstatus ) ) ) {
      FD_LOG_WARNING(( "expected fd_sandbox_change_user to exit gracefully but " "stopped by signal %s", strsignal(WSTOPSIG(wstatus)) ));
      return -1;
    }
    return 0;

  } else { // child
    fd_boot_secure( pargc, pargv );
    fd_sandbox_private_setup_user();

    if ( FD_UNLIKELY ( getuid() != fd_oveflow_user ) ) {
      FD_LOG_NOTICE(( "expected uid to not be 0 but was" ));
      exit(-1);
    }

    if ( FD_UNLIKELY( getgid() != fd_oveflow_group ) ) {
      FD_LOG_NOTICE(( "expected gid to be 0 but was" ));
    }
    fd_halt();
  }
  exit(0);
}

/* test_should_set_resource_limits ensures that, after calling `fd_sandbox_private_set_resource_limits`,
   the set limits cannot be exceeded. */
int
test_should_set_resource_limits( void ) {
  pid_t pid, w;

  if (( pid = fork() )) { // parent
    int wstatus;
    w = waitpid( pid, &wstatus, WUNTRACED );
    if ( FD_UNLIKELY ( w == -1 ) ) {
      FD_LOG_WARNING(( "waitpid: %s", strerror( errno ) ));
      return -1;
    }
    if ( FD_UNLIKELY ( WIFEXITED( wstatus ) && WEXITSTATUS( wstatus ) ) ) {
      FD_LOG_WARNING(( "expected fd_sandbox_private_set_resource_limits to exit gracefully but " "exited with non-zero status, status=%d", WEXITSTATUS(wstatus) ));
      return -1;
    } else if ( FD_UNLIKELY ( WIFSIGNALED( wstatus ) ) ) {
      FD_LOG_WARNING(( "expected fd_sandbox_private_set_resource_limits to exit gracefully but " "killed by signal %s", strsignal(WTERMSIG(wstatus)) ));
      return -1;
    } else if ( FD_UNLIKELY ( WIFSTOPPED( wstatus ) ) ) {
      FD_LOG_WARNING(( "expected fd_sandbox_private_set_resource_limits to exit gracefully but " "stopped by signal %s", strsignal(WSTOPSIG(wstatus)) ));
      return -1;
    }
    return 0;

  } else { // child
    // open should not fail
    int fd = open("/etc/passwd", O_RDONLY);
    if ( FD_UNLIKELY ( fd == -1 ) ) {
      FD_LOG_WARNING(( "open: %s", strerror(errno) ));
      return -1;
    }
    close(fd);

    fd_sandbox_set_max_open_files( 2U );
    fd_sandbox_private_set_resource_limits();

    // open should fail
    fd = open("/etc/passwd", O_RDONLY);
    if ( FD_UNLIKELY ( fd == -1 && errno != EMFILE ) ) {
      FD_LOG_WARNING(( "open: expected to fail for -24: %s", strerror(errno) ));
      return -1;
    } else if ( FD_UNLIKELY ( fd != -1 ) ) {
      FD_LOG_WARNING(( "open expected to fail for -24 'Too many open files' but succedded" ));
      exit(1);
    }
    exit(0);
  }

  return -1;
}

/* test_setup_netns ensures that, after calling `fd_sandbox_private_setup_netns`,
   the process' view of the network interfaces is limited to the expected. */
int
test_setup_netns( void ) {
  pid_t pid, w;

  // Pick a test ns name.
  char nsname[ 20 ];
  snprintf( nsname, 20, "fdtestsbx-%u", getpid() );

  // Create the new ns.
  char cmd[ 64 ];
  snprintf( cmd, 64, "ip netns add %s", nsname );
  if ( FD_UNLIKELY( system( cmd ) ) ) {
    FD_LOG_WARNING(( "system(\"%s\") as %d: %s", cmd, getuid(), strerror(errno) ));
    return -1;
  }

  if (( pid = fork() )) { // parent
    int wstatus;
    w = waitpid( pid, &wstatus, WUNTRACED );

    // The test ns is not needed anymore: delete it.
    snprintf( cmd, 64, "ip netns del %s", nsname );
    if ( FD_UNLIKELY( system( cmd ) ) ) {
      FD_LOG_WARNING(( "system(\"%s\"): %s", cmd, strerror(errno) ));
      return -1;
    }

    if ( FD_UNLIKELY ( w == -1 ) ) {
      FD_LOG_WARNING(( "waitpid: %s", strerror(errno) ));
      return -1;
    }
    if ( FD_UNLIKELY ( WIFEXITED( wstatus ) && WEXITSTATUS( wstatus ) ) ) {
      FD_LOG_WARNING(("expected fd_sandbox_private_setup_netns to exit gracefully but " "exited with non-zero status, status=%d", WEXITSTATUS(wstatus) ));
      return -1;
    } else if ( FD_UNLIKELY ( WIFSIGNALED( wstatus ) ) ) {
      FD_LOG_WARNING(( "expected fd_sandbox_private_setup_netns to exit gracefully but " "killed by signal %s", strsignal(WTERMSIG(wstatus)) ));
      return -1;
    } else if ( FD_UNLIKELY ( WIFSTOPPED( wstatus ) ) ) {
      FD_LOG_WARNING(( "expected fd_sandbox_private_setup_netns to exit gracefully but " "stopped by signal %s", strsignal(WSTOPSIG(wstatus)) ));
      return -1;
    }
    return 0;

  } else { // child
    fd_sandbox_private_setup_netns();
    // loopback should be the only intrface available at this point

    struct if_nameindex *if_nidxs, *intf;

    if_nidxs = if_nameindex();
    if ( FD_LIKELY ( if_nidxs != NULL ) ) {
      for (intf = if_nidxs; intf->if_index != 0 || intf->if_name != NULL; intf++) {
        if( FD_UNLIKELY ( strcmp( "lo", intf->if_name ) ) ) {
          FD_LOG_WARNING(( "seen non-loopback interface after sandboxing ns: %s", intf->if_name ));
          if_freenameindex(if_nidxs);
          exit(1);
        }
      }
      if_freenameindex(if_nidxs);
    }
    exit(0);
  }

  return -1;
}

/* test_seccomp_default_filter ensures that, after calling `fd_sandbox_private_seccomp`,
   seccomp is effective. */
int
test_seccomp_default_filter( void ) {

  pid_t pid, w;

  if (( pid = fork() )) { // parent
    int wstatus;
    w = waitpid( pid, &wstatus, WUNTRACED );
    if ( FD_UNLIKELY ( w == -1 ) ) {
      FD_LOG_WARNING(( "waitpid: %s", strerror(errno) ));
      return -1;
    }
    if ( FD_UNLIKELY ( !wstatus ) ) {
      FD_LOG_WARNING(( "expected execl to get killed by signal but child exited normally" ));
      return -1;
    } else if ( FD_UNLIKELY ( WIFEXITED( wstatus ) && WEXITSTATUS( wstatus ) ) ) {
      FD_LOG_WARNING(( "expected execl to get killed by signal but " "exited with status, status=%d", WEXITSTATUS(wstatus) ));
      return -1;
    } else if ( FD_UNLIKELY ( WTERMSIG( wstatus ) == SIGSYS ) ) {
      return 0;
    } else if ( FD_UNLIKELY ( WIFSIGNALED( wstatus ) ) ) {
      if ( WTERMSIG(wstatus) != SIGSYS ) {
        FD_LOG_WARNING(( "expected execl to get SIGSYS : " "killed by %s", strsignal(WTERMSIG(wstatus)) ));
        return -1;
      }
      return 0;
    } else if ( FD_UNLIKELY ( WIFSTOPPED( wstatus ) ) ) {
      FD_LOG_WARNING(( "expected execl to get killed by signal but " "stopped by signal %s", strsignal(WSTOPSIG(wstatus)) ));
      return -1;
    } else {
      FD_LOG_WARNING(( "unexpected termination: wstatus(%d)", wstatus ));
      return -1;
    }
    return -1;

  } else { // child
    fd_sandbox_private_seccomp();

    // The call to execl is expected to have the kernel send a
    // SIGSYS to the process group. The branch should not execute.
    if ( execl( "/bin/true", "" ) ) {
      // This could change if we ever switch stance on seccomp violations.
      FD_LOG_WARNING(( "execl: should not have been executed %s", strerror(errno) ));
    }
    exit(0);
  }

  return -1;
}

/* test_setup_netns_null ensures that, after calling `fd_sandbox_private_setup_mountns`,
   the root mount should be empty and belong to root. */
int
test_setup_netns_null( void ) {
  pid_t pid, w;

  if (( pid = fork() )) { // parent
    int wstatus;
    w = waitpid( pid, &wstatus, WUNTRACED );
    if ( FD_UNLIKELY ( w == -1 ) ) {
      FD_LOG_WARNING(( "waitpid: %s", strerror(errno) ));
      return -1;
    }
    if ( FD_LIKELY ( !wstatus ) ) {
      return 0;
    } else if ( FD_UNLIKELY ( WIFEXITED( wstatus ) ) ) {
      FD_LOG_WARNING(( "expected fd_sandbox_setup_mountfs to exit normally: " "exited with status, status=%d", WEXITSTATUS(wstatus) ));
      return -1;
    } else if ( FD_LIKELY ( WIFSIGNALED( wstatus ) ) ) {
      FD_LOG_WARNING(( "expected fd_sandbox_setup_mountfs to exit normally: " "killed by signal %s", strsignal(WTERMSIG(wstatus)) ));
      return 0;
    } else if ( FD_UNLIKELY ( WIFSTOPPED( wstatus ) ) ) {
      FD_LOG_WARNING(( "expected fd_sandbox_setup_mountfs to exit normally: " "stopped by signal %s", strsignal(WSTOPSIG(wstatus)) ));
      return -1;
    } else {
      FD_LOG_WARNING(( "unexpected termination: wstatus(%d)", wstatus ));
      return -2;
    }
    return -1;

  } else { // child
    fd_sandbox_private_setup_mountns();

    struct dirent * entry;
    DIR *           dir = opendir("/");
    if ( FD_UNLIKELY ( !dir ) ) {
      FD_LOG_WARNING(( "open: expected to work on `/`: %s", strerror(errno) ));
      return -1;
    }

    // Ensure that directory is empty
    while ((entry = readdir(dir))) {
      if ( FD_UNLIKELY ( strcmp( ".", entry->d_name ) && strcmp( "..", entry->d_name ) ) ) {
        FD_LOG_WARNING(( "root directory is not empty" ));
        exit(1);
      }
    }

    // Ensure that `/` is owned by root
    struct stat sb;
    if ( FD_UNLIKELY ( stat( "/", &sb ) )) {
      FD_LOG_WARNING(( "stat: expected to work on `/`: %s", strerror(errno) ));
      exit(1);
    }

    if ( FD_UNLIKELY ( sb.st_uid ) ) {
      FD_LOG_WARNING(( "root directory should be owned by user root but is owned by uid=%d", sb.st_uid ));
      exit(1);
    }

    if ( FD_UNLIKELY ( sb.st_gid ) ) {
      FD_LOG_WARNING(( "root directory should be owned by group root but is owned by gid=%d", sb.st_gid ));
      exit(1);
    }

    exit(0);
  }

  return -1;
}


int
main( int     argc,
      char ** argv ) {
  (void) argc;
  (void) argv;

  uint failed_cnt = 0;

  if( FD_UNLIKELY ( test_seccomp_default_filter() ) ) {
    failed_cnt++;
    FD_LOG_WARNING(( "[FAIL] test_seccomp_default_filter" ));
  } else {
    FD_LOG_NOTICE(( "[PASS] test_seccomp_default_filter" ));
  }

  if( FD_UNLIKELY ( test_should_close_open_fds() ) ) {
    failed_cnt++;
    FD_LOG_WARNING(( "[FAIL] test_should_close_open_fds" ));
  } else {
    FD_LOG_NOTICE(( "[PASS] test_should_close_open_fds" ));
  }

  if( FD_UNLIKELY ( test_should_change_userns( &argc, &argv ) ) ) {
    failed_cnt++;
    FD_LOG_WARNING(( "[FAIL] test_should_change_user" ));
  } else {
    FD_LOG_NOTICE(( "[PASS] test_should_change_user" ));
  }

  if( FD_UNLIKELY ( test_should_set_resource_limits() ) ) {
    failed_cnt++;
    FD_LOG_WARNING(( "[FAIL] test_should_set_resource_limits" ));
  } else {
    FD_LOG_NOTICE(( "[PASS] test_should_set_resource_limits" ));
  }

  if( FD_UNLIKELY ( test_setup_netns() ) ) {
    failed_cnt++;
    FD_LOG_WARNING(( "[FAIL] test_setup_netns" ));
  } else {
    FD_LOG_NOTICE(( "[PASS] test_setup_netns" ));
  }

  if( FD_UNLIKELY ( test_setup_netns_null() ) ) {
    failed_cnt++;
    FD_LOG_WARNING(( "[FAIL] test_setup_netns_null" ));
  } else {
    FD_LOG_NOTICE(( "[PASS] test_setup_netns_null" ));
  }

  if (failed_cnt) {
    FD_LOG_ERR(( "failed %d sandbox tests", failed_cnt ));
  }

  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  (void) argc;
  (void) argv;
  FD_LOG_WARNING(( "target does not support FD_SANDBOX" ));
  return 0;
}

#endif
