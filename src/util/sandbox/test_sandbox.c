#if !defined(__linux__)
# error "Target operating system is unsupported by seccomp."
#endif

#if !FD_HAS_ASAN

#define _GNU_SOURCE

#include "../fd_util.h"
#include "generated/test_sandbox_seccomp.h"

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

#include "fd_sandbox.c"

#define SIZEOFA(arr) sizeof( arr ) / sizeof ( arr[0] )

#define TEST_FORK_OK(child) do {                                    \
    pid_t pid = fork();                                             \
    if ( pid ) {                                                    \
      int wstatus;                                                  \
      FD_TEST( -1 != waitpid( pid, &wstatus, WUNTRACED ) );         \
      FD_TEST( WIFEXITED( wstatus ) );                              \
      FD_TEST( !WEXITSTATUS( wstatus ) );                           \
      FD_TEST( !WIFSIGNALED( wstatus ) );                           \
      FD_TEST( !WIFSTOPPED( wstatus ) );                            \
    } else {                                                        \
      do { child } while ( 0 );                                     \
      exit( EXIT_SUCCESS );                                         \
    }                                                               \
} while( 0 )

#define TEST_FORK_SIG(child) do {                                   \
    pid_t pid = fork();                                             \
    if ( pid ) {                                                    \
      int wstatus;                                                  \
      FD_TEST( -1 != waitpid( pid, &wstatus, WUNTRACED ) );         \
      FD_TEST( !WIFEXITED( wstatus ) );                             \
      FD_TEST( !WEXITSTATUS( wstatus ) );                           \
      FD_TEST( WIFSIGNALED( wstatus ) );                            \
      FD_TEST( !WIFSTOPPED( wstatus ) );                            \
    } else {                                                        \
      do { child } while ( 0 );                                     \
      exit( EXIT_SUCCESS );                                         \
    }                                                               \
} while( 0 )

#define TEST_FORK_EXIT_NON_0(child) do {                            \
    pid_t pid = fork();                                             \
    if ( pid ) {                                                    \
      int wstatus;                                                  \
      FD_TEST( -1 != waitpid( pid, &wstatus, WUNTRACED ) );         \
      FD_TEST( WIFEXITED( wstatus ) );                              \
      FD_TEST( !WIFSIGNALED( wstatus ) );                           \
      FD_TEST( !WIFSTOPPED( wstatus ) );                            \
      FD_TEST( WEXITSTATUS( wstatus ) != 0 );                       \
    } else {                                                        \
      do { child } while ( 0 );                                     \
      exit( EXIT_SUCCESS );                                         \
    }                                                               \
} while( 0 )

/* check_open_fds ensures that `sandbox_unthreaded` verifies
   the file descriptors we allow are exactly those that are matched. */
void
check_open_fds( void ) {
  TEST_FORK_EXIT_NON_0(
    sandbox_unthreaded( 0, NULL, getuid(), getgid() );
  );

  int fds[ 5 ] = { 0, 1, 2, 3, 101 };
  TEST_FORK_EXIT_NON_0(
    sandbox_unthreaded( SIZEOFA( fds ), fds, getuid(), getgid() );
  );

  int fds2[ 4 ] = { 0, 1, 2, 3 };
  TEST_FORK_OK(
    sandbox_unthreaded( SIZEOFA( fds2 ), fds2, getuid(), getgid() );
  );
}

/* resource_limits ensures that, after calling `sandbox_unthreaded`,
   the set limits cannot be exceeded. */
void
resource_limits( void ) {
  int fds[ 4 ] = { 0, 1, 2, 3 };
  TEST_FORK_OK(
    FD_TEST( -1 != open( "/etc/passwd", O_RDONLY ) );
  );
  TEST_FORK_OK(
    sandbox_unthreaded( SIZEOFA( fds ), fds, getuid(), getgid() );
    FD_TEST( -1 == open( "/etc/passwd", O_RDONLY ) );
    FD_TEST( EMFILE == errno );
  );
}

void
not_dumpable( void ) {
  int fds[ 4 ] = { 0, 1, 2, 3 };
  TEST_FORK_OK(
    FD_TEST( prctl( PR_GET_DUMPABLE ) );
    sandbox_unthreaded( SIZEOFA( fds ), fds, getuid(), getgid() );
    FD_TEST( !prctl( PR_GET_DUMPABLE ) );
  );
}

void
no_capabilities( void ) {
  struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
  struct __user_cap_data_struct   data[2] = { { 0 } };
  int fds[ 4 ] = { 0, 1, 2, 3 };
  TEST_FORK_OK(
    FD_TEST( 0 == syscall( SYS_capget, &hdr, data ) );
    FD_TEST( data[0].effective || data[1].effective );

    sandbox_unthreaded( SIZEOFA( fds ), fds, getuid(), getgid() );

    FD_TEST( 0 == syscall( SYS_capget, &hdr, data ) );
    FD_TEST( !data[0].effective && !data[1].effective );
  );
}

/* change_userns ensures that, after calling `unshare_user`,
   the process' {real,effective}x{uid,gid} are matching the desired user's. */
void
change_userns( void ) {
  TEST_FORK_OK(
    unshare_user( getuid(), getgid() );

    // Inside the sandbox
    FD_TEST( getuid() == 0 );
    FD_TEST( geteuid() == 0 );
    FD_TEST( getgid() == 0 );
    FD_TEST( getegid() == 0 );

    char buffer[34];
    FILE * file = fopen( "/proc/self/uid_map", "r" );
    FD_TEST( 33 == fread( buffer, 1, 34, file ) );
    buffer[33] = '\0';
    FD_TEST( strcmp( buffer, "         0          0          1\n" ) == 0 );

    file = fopen( "/proc/self/gid_map", "r" );
    FD_TEST( 33 == fread( buffer, 1, 34, file ) );
    buffer[33] = '\0';
    FD_TEST( strcmp( buffer, "         0          0          1\n" ) == 0 );
  );
}

/* netns ensures that, after calling `unshare_user`,
   the process' view of the network interfaces is limited. */
void
netns( void ) {
  TEST_FORK_OK(
    struct if_nameindex * ifs = if_nameindex();
    FD_TEST( ifs[1].if_name != NULL );

    /* can't call fd_sandbox_private_unthreaded here because
       we wouldn't be able to call if_nameindex after */
    unshare_user( getuid(), getgid() );

    ifs = if_nameindex();
    if( !ifs ) FD_LOG_ERR(( "if_nameindex failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    FD_TEST( !strcmp( ifs[0].if_name, "lo" ) );
    FD_TEST( ifs[1].if_name == NULL );
  );
}

/* mountns_null ensures that, after calling `setup_mountns`,
   the root mount should be empty and belong to root. */
void
mountns_null( void ) {
  TEST_FORK_OK(
    setup_mountns();

    DIR * dir = opendir( "/" );
    FD_TEST( dir != NULL );

    struct dirent * entry;
    while(( entry = readdir( dir ) )) {
      if( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) )
        continue;

      FD_LOG_ERR(( "entry: %s", entry->d_name ));
    }

    struct stat sb;
    FD_TEST( 0 == stat( "/", &sb ) );
    FD_TEST( 0 == sb.st_uid );
    FD_TEST( 0 == sb.st_gid );
  );
}

/* test_seccomp_default_filter ensures that, after calling `fd_sandbox`,
   seccomp is effective. */
void
seccomp_default_filter( void ) {
  int fds[ 4 ] = { 0, 1, 2, 3 };

  struct sock_filter seccomp_filter[ 128UL ];
  populate_sock_filter_policy_test_sandbox( 128UL, seccomp_filter );

  TEST_FORK_OK( fd_sandbox( 1, getuid(), getgid(), SIZEOFA( fds ), fds, sock_filter_policy_test_sandbox_instr_cnt, seccomp_filter ); );

  pid_t pid = fork();
  if ( pid ) {
    int wstatus;
    FD_TEST( -1 != waitpid( pid, &wstatus, WUNTRACED ) );
    FD_TEST( WIFSIGNALED( wstatus ) && WTERMSIG( wstatus ) == SIGSYS );
  } else { // child

    fd_sandbox( 1, getuid(), getgid(), SIZEOFA( fds ), fds, sock_filter_policy_test_sandbox_instr_cnt, seccomp_filter );
    // This should fail with SIGSYS
    execl( "/bin/true", "" );
  }
}


void
test_protected_pages( void ) {

  pid_t pid = fork();
  if ( pid ) {
    int wstatus;
    FD_TEST( -1 != waitpid( pid, &wstatus, WUNTRACED ) );
    FD_TEST( WIFSIGNALED( wstatus ) && WTERMSIG( wstatus ) == SIGSEGV );
  } else { // child
    uchar * allocated = fd_sandbox_alloc_protected_pages( 1UL, 1UL );
    /* This should trigger a segfault */
    uchar c = FD_VOLATILE_CONST( allocated[ 4096 ] );
    (void)c;
    exit( EXIT_FAILURE );
  }

  pid = fork();
  if ( pid ) {
    int wstatus;
    FD_TEST( -1 != waitpid( pid, &wstatus, WUNTRACED ) );
    FD_TEST( WIFSIGNALED( wstatus ) && WTERMSIG( wstatus ) == SIGSEGV );
  } else { // child
    uchar * allocated = fd_sandbox_alloc_protected_pages( 1UL, 1UL );
    /* This should trigger a segfault */
    uchar c = FD_VOLATILE_CONST( allocated[ -1 ] );
    (void)c;
    exit( EXIT_FAILURE );
  }

  uchar * allocated = fd_sandbox_alloc_protected_pages( 1UL, 1UL );
  for( ulong i=0UL; i<4096UL; i++ ) FD_TEST( allocated[i]==0 );
  for( ulong i=0UL; i<4096UL; i++ ) allocated[i]=1;

  /* Wiped on fork */
  TEST_FORK_OK( for( ulong i=0UL; i<4096UL; i++ ) FD_TEST( allocated[i]==0 ); );
  /* But not in parent */
  for( ulong i=0UL; i<4096UL; i++ ) FD_TEST( allocated[i]==1 );
}

int
main( int     argc,
      char ** argv ) {
  (void) argc;
  (void) argv;

  fd_log_private_boot( &argc, &argv );

  FD_LOG_NOTICE(( "check_open_fds.." ));
  check_open_fds();
  FD_LOG_NOTICE(( "resource_limits.." ));
  resource_limits();
  FD_LOG_NOTICE(( "not_dumpable.." ));
  not_dumpable();
  FD_LOG_NOTICE(( "no_capabilities.." ));
  no_capabilities();
  FD_LOG_NOTICE(( "change_userns.." ));
  change_userns();
  FD_LOG_NOTICE(( "netns.." ));
  netns();
  FD_LOG_NOTICE(( "mountns_null.." ));
  mountns_null();
  FD_LOG_NOTICE(( "seccomp_default_filter.." ));
  seccomp_default_filter();
  FD_LOG_NOTICE(( "test_protected_pages.." ));
  test_protected_pages();
  FD_LOG_NOTICE(( "pass" ));
  return 0;
}

#else
#include <stdio.h>
int main( int argc,
          char ** argv ) {
  (void) argc;
  (void) argv;
  printf( "sandbox tests not supported in this configuration\n" );
  return 0;
}

#endif /* FD_HAS_ASAN */
