#if !defined(__linux__)
# error "Target operating system is unsupported by seccomp."
#endif

#define _GNU_SOURCE

#include "fd_sandbox.h"

#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/securebits.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/capability.h>
#include <limits.h>
#include <sched.h>        /* CLONE_*, setns, unshare */
#include <stddef.h>
#include <stdlib.h>       /* clearenv, mkdtemp*/
#include <sys/mount.h>    /* MS_*, MNT_*, mount, umount2 */
#include <sys/prctl.h>
#include <sys/resource.h> /* RLIMIT_*, rlimit, setrlimit */
#include <sys/stat.h>     /* mkdir */
#include <sys/syscall.h>  /* SYS_* */
#include <unistd.h>       /* set*id, sysconf, close, chdir, rmdir syscall */

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define X32_SYSCALL_BIT 0x40000000

#define ALLOW_SYSCALL(name)                                \
  /* If the syscall does not match, jump over RET_ALLOW */ \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##name, 0, 1),  \
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

#if defined(__i386__)
# define ARCH_NR  AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define ARCH_NR  AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
# define ARCH_NR AUDIT_ARCH_AARCH64
#else
# error "Target architecture is unsupported by seccomp."
#endif

static void
secure_clear_environment( void ) {
  char** env = environ;
  while ( *env ) {
    size_t len = strlen( *env );
    explicit_bzero( *env, len );
    env++;
  }
  clearenv();
}

static void
setup_mountns( void ) {
  assert( unshare ( CLONE_NEWNS ) == 0 );

  char temp_dir [] = "/tmp/fd-sandbox-XXXXXX";
  assert( mkdtemp( temp_dir ) );
  assert( 0 == mount( NULL, "/", NULL, MS_SLAVE | MS_REC, NULL ) );
  assert( 0 == mount( temp_dir, temp_dir, NULL, MS_BIND | MS_REC, NULL ) );
  assert( 0 == chdir( temp_dir ) );
  assert( 0 == mkdir( "old-root", S_IRUSR | S_IWUSR ));
  assert( 0 == syscall( SYS_pivot_root, ".", "old-root" ) );
  assert( 0 == chdir( "/" ) );
  assert( 0 == umount2( "old-root", MNT_DETACH ) );
  assert( 0 == rmdir( "old-root" ) );
}

static void
close_fds( void ) {
  if( syscall( SYS_close_range, 3, UINT_MAX ) ) {
    // No SYS_close_range, close one by one
    int max_fds = (int)sysconf( _SC_OPEN_MAX );
    for ( int fd = 3; fd < max_fds; fd++ ) {
      assert( 0 == close( fd ) );
    }
  }
}

static void
install_seccomp( void ) {
  struct sock_filter filter [] = {
    // [0] Validate architecture
    // Load the arch number
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, ( offsetof( struct seccomp_data, arch ) ) ),
    // Do not jump (and die) if the compile arch is neq the runtime arch.
    // Otherwise, jump over the SECCOMP_RET_KILL_PROCESS statement.
    BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, ARCH_NR, 1, 0 ),
    BPF_STMT( BPF_RET | BPF_K, SECCOMP_RET_ALLOW ),

    // [1] Verify that the syscall is allowed
    // Load the syscall
    BPF_STMT( BPF_LD | BPF_W | BPF_ABS, ( offsetof( struct seccomp_data, nr ) ) ),

    // Attempt to sort syscalls by call frequency.
    ALLOW_SYSCALL( writev       ),
    ALLOW_SYSCALL( write        ),
    ALLOW_SYSCALL( fsync        ),
    ALLOW_SYSCALL( gettimeofday ),
    ALLOW_SYSCALL( futex        ),
    // sched_yield is useful for both floating threads and hyperthreaded pairs.
    ALLOW_SYSCALL( sched_yield  ),
    // The rules under this line are expected to be used in fewer occasions.
    // exit is needed to let tiles exit gracefully.
    ALLOW_SYSCALL( exit         ),
    // exit_group is needed to let any tile crash the whole group.
    ALLOW_SYSCALL( exit_group   ),
    // munmap is needed for a clean exit.
    ALLOW_SYSCALL( munmap       ),
    // nanosleep is needed for a clean exit.
    ALLOW_SYSCALL( nanosleep    ),
    ALLOW_SYSCALL( rt_sigaction ),
    ALLOW_SYSCALL( rt_sigreturn ),
    ALLOW_SYSCALL( sync         ),
    // close is needed for a clean exit and for closing logs.
    ALLOW_SYSCALL( close        ),
    ALLOW_SYSCALL( sendto       ),

    // [2] None of the syscalls approved were matched: die
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
  };

  assert( 0 == prctl( PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0 ) );

  struct sock_fprog default_prog = {
    .len = ARRAY_SIZE( filter ),
    .filter = filter,
  };
  assert( 0 == syscall( SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &default_prog ) );
}

static void
drop_capabilities( void ) {
  assert( 0 == prctl (
    PR_SET_SECUREBITS,
    SECBIT_KEEP_CAPS_LOCKED | SECBIT_NO_SETUID_FIXUP |
      SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_NOROOT |
      SECBIT_NOROOT_LOCKED | SECBIT_NO_CAP_AMBIENT_RAISE |
      SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED ) );

  struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
  struct __user_cap_data_struct   data[2] = { { 0 } };
  assert( 0 == syscall( SYS_capset, &hdr, data ) );

  assert( 0 == prctl( PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0 ) );
}

static uint overflow_id(const char * path) {
  int fd = open( path, O_RDONLY );
  assert( fd >= 0 );
  char buf[16];
  ssize_t len = read( fd, buf, sizeof(buf) );
  assert( len > 0 );
  close( fd );
  buf[len] = '\0';
  int result = atoi( buf );
  assert( result >= 0 );
  return (uint)result;
}

static void userns_map( uint id, const char * map ) {
  char path[64];
  assert( sprintf( path, "/proc/self/%s", map ) > 0);
  int fd = open( path, O_WRONLY );
  assert( fd >= 0 );
  char line[64];
  assert( sprintf( line, "0 %u 1\n", id ) > 0 );
  assert( write( fd, line, strlen( line ) ) > 0 );
  assert( 0 == close( fd ) );
}

static void deny_setgroups() {
  int fd = open( "/proc/self/setgroups", O_WRONLY );
  assert( fd >= 0 );
  assert( write( fd, "deny", strlen( "deny" ) ) > 0 );
  assert( 0 == close( fd ) );
}

void
fd_sandbox_private_privileged( int *    pargc,
                               char *** pargv ) {
  (void) pargc;
  for( char ** argv = *pargv; *argv; argv++ ) {
    if( !strcmp( *argv, "--no-sandbox" ) ) {
      return;
    }
  }

  uint overflow_uid = overflow_id( "/proc/sys/kernel/overflowuid" );
  uint overflow_gid = overflow_id( "/proc/sys/kernel/overflowgid" );
  uint uid = fd_env_strip_cmdline_uint( pargc, pargv, "--uid", "FD_UID", overflow_uid );
  uint gid = fd_env_strip_cmdline_uint( pargc, pargv, "--gid", "FD_GID", overflow_gid );

  assert( uid != 0 && gid != 0 );

  assert( 0 == setresgid( gid, gid, gid ) );
  assert( 0 == setresuid( uid, uid, uid ) );
  assert( 0 == prctl( PR_SET_DUMPABLE, 1, 0, 0, 0 ) );

  assert( 0 == unshare( CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET ) );
  deny_setgroups();
  userns_map( getuid(), "uid_map" );
  userns_map( getgid(), "gid_map" );

  assert( 0 == prctl( PR_SET_DUMPABLE, 0, 0, 0, 0 ) );
  for ( int cap = 0; cap <= CAP_LAST_CAP; cap++ ) {
    assert( 0 == prctl( PR_CAPBSET_DROP, cap, 0, 0, 0 ) );
  }

  setup_mountns();
  drop_capabilities();
  secure_clear_environment();
}

void
fd_sandbox_private( int *    pargc,
                    char *** pargv ) {
  if( fd_env_strip_cmdline_contains( pargc, pargv, "--no-sandbox" ) ) {
    return;
  }

  struct rlimit limit = { .rlim_cur = 3, .rlim_max = 3 };
  assert( 0 == setrlimit( RLIMIT_NOFILE, &limit ));

  close_fds();
  install_seccomp();
}
