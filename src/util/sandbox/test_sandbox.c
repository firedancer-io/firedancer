#if !defined(__linux__)
# error "Target operating system is unsupported by seccomp."
#endif

#if !FD_HAS_ASAN

#define _GNU_SOURCE

#include "../fd_util.h"

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

#define TEST_FORK(child) do {                                       \
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


/* close_open_fds ensures that, after calling `fd_sandbox_private`, no FDs
   beyond an allowed number are opened. */
void
close_open_fds( void ) {
  int fd = open( "/etc/passwd", O_RDONLY );
  FD_TEST( -1 != fd && fd >= 3 );

  TEST_FORK(
    FD_TEST( fcntl( fd, F_GETFD ) != -1 );
    fd_sandbox_private_no_seccomp();
    FD_TEST( fcntl( fd, F_GETFD ) == -1 );
  );
}

/* close_open_fds_proc ensures that, after calling `fd_sandbox_private`, no FDs
   beyond an allowed number are opened. Uses the /proc implementation
   directly. */
void
close_open_fds2( void ) {
  int fd = open( "/etc/passwd", O_RDONLY );
  FD_TEST( -1 != fd && fd >= 3 );

  TEST_FORK(
    FD_TEST( fcntl( fd, F_GETFD ) != -1 );
    close_fds_proc();
    FD_TEST( fcntl( fd, F_GETFD ) == -1 );
  );
}

/* resource_limits ensures that, after calling `fd_sandbox_private`,
   the set limits cannot be exceeded. */
void
resource_limits( void ) {
  TEST_FORK(
    FD_TEST( -1 != open("/etc/passwd", O_RDONLY) );
    fd_sandbox_private_no_seccomp();
    FD_TEST( -1 == open("/etc/passwd", O_RDONLY) );
    FD_TEST( EMFILE == errno );
  );
}

void
not_dumpable( void ) {
  TEST_FORK(
    FD_TEST( prctl( PR_GET_DUMPABLE ) );
    fd_sandbox_private_privileged( (int[]){0}, (char**[]){&(char*[]){NULL}[0]} );
    FD_TEST( !prctl( PR_GET_DUMPABLE ) );
  );
}

void
no_capabilities( void ) {
  struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
  struct __user_cap_data_struct   data[2] = { { 0 } };
  TEST_FORK(
    FD_TEST( 0 == syscall( SYS_capget, &hdr, data ) );
    FD_TEST( data[0].effective || data[1].effective );

    fd_sandbox_private_privileged( (int[]){0}, (char**[]){&(char*[]){NULL}[0]} );

    FD_TEST( 0 == syscall( SYS_capget, &hdr, data ) );
    FD_TEST( !data[0].effective && !data[1].effective );
  );
}

/* change_userns ensures that, after calling `fd_sandbox_private_privileged`,
   the process' {real,effective}x{uid,gid} are matching the desired user's. */
void
change_userns( void ) {
  FD_TEST( getuid() != 65534 );
  FD_TEST( geteuid() != 65534 );
  FD_TEST( getgid() != 65534 );
  FD_TEST( getegid() != 65534 );

  TEST_FORK(
    unshare_user( (int[]){0}, (char**[]){&(char*[]){NULL}[0]} );

    // Inside the sandbox
    FD_TEST( getuid() == 0 );
    FD_TEST( geteuid() == 0 );
    FD_TEST( getgid() == 0 );
    FD_TEST( getegid() == 0 );

    char buffer[34];
    FILE * file = fopen( "/proc/self/uid_map", "r" );
    FD_TEST( 33 == fread( buffer, 1, 34, file ) );
    buffer[33] = '\0';
    FD_TEST( strcmp( buffer, "         0      65534          1\n" ) == 0 );

    file = fopen( "/proc/self/gid_map", "r" );
    FD_TEST( 33 == fread( buffer, 1, 34, file ) );
    buffer[33] = '\0';
    FD_TEST( strcmp( buffer, "         0      65534          1\n" ) == 0 );
  );
}

/* netns ensures that, after calling `fd_sandbox_private_privileged`,
   the process' view of the network interfaces is limited to the expected. */
void
netns( void ) {
  TEST_FORK(
    struct if_nameindex * ifs = if_nameindex();
    FD_TEST( ifs[1].if_name != NULL );

    fd_sandbox_private_privileged( (int[]){0}, (char**[]){&(char*[]){NULL}[0]} );

    ifs = if_nameindex();
    FD_TEST( !strcmp(ifs[0].if_name, "lo") );
    FD_TEST( ifs[1].if_name == NULL );
  );
}

/* mountns_null ensures that, after calling `fd_sandbox_private`,
   the root mount should be empty and belong to root. */
void
mountns_null( void ) {
  TEST_FORK(
    fd_sandbox_private_privileged( (int[]){0}, (char**[]){&(char*[]){NULL}[0]} );
    DIR * dir = opendir( "/" );
    FD_TEST( dir != NULL );

    struct dirent * entry;
    while(( entry = readdir( dir ) )) {
      FD_TEST( !strcmp( entry->d_name, "." ) || !strcmp( entry->d_name, ".." ) );
    }

    struct stat sb;
    FD_TEST( 0 == stat( "/", &sb ) );
    FD_TEST( 0 == sb.st_uid );
    FD_TEST( 0 == sb.st_gid );
  );
}

/* test_seccomp_default_filter ensures that, after calling `fd_sandbox_private`,
   seccomp is effective. */
void
seccomp_default_filter( void ) {
  pid_t pid = fork();
  if ( pid ) {
    int wstatus;
    FD_TEST( -1 != waitpid( pid, &wstatus, WUNTRACED ) );
    FD_TEST( WIFSIGNALED( wstatus) && WTERMSIG( wstatus ) == SIGSYS );
  } else { // child
    fd_sandbox_private( NULL, NULL );
    // This should fail with SIGSYS
    execl( "/bin/true", "" );
    exit( EXIT_FAILURE );
  }
}

int
main( int     argc,
      char ** argv ) {
  (void) argc;
  (void) argv;

  close_open_fds();
  close_open_fds2();
  resource_limits();
  not_dumpable();
  no_capabilities();
  change_userns();
  netns();
  mountns_null();
  seccomp_default_filter();
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
