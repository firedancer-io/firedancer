#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fd_sandbox_linux_private.h"

#include <errno.h>        /* errno */
#include <linux/audit.h>
#include <linux/capability.h> /* Definition of CAP_* and _LINUX_CAPABILITY_* constants */
#include <linux/filter.h>
#include <linux/securebits.h>
#include <linux/seccomp.h>
#include <pwd.h>
#include <sched.h>        /* CLONE_*, setns, unshare */
#include <stddef.h>
#include <stdio.h>        /* snprintf */
#include <stdlib.h>       /* clearenv, mkdtemp*/
#include <sys/mount.h>    /* MS_*, MNT_*, mount, umount2 */
#include <sys/prctl.h>
#include <sys/resource.h> /* RLIMIT_*, rlimit, setrlimit */
#include <sys/stat.h>     /* mkdir */
#include <sys/syscall.h>  /* SYS_* */
#include <unistd.h>       /* set*id, sysconf, close, chdir, rmdir syscall */
#include <inttypes.h>
#include <sys/wait.h>


#include "../fd_util.h"

#define FD_TEST_LOG_ERRNO(c) do { if( FD_UNLIKELY( !(c) ) ) FD_LOG_ERR(( "FAIL: (%d:%s) %s...", errno, strerror( errno ), #c )); } while(0)


#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* seccomp macros */
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

/* user api */

static int conf_sandbox_disabled = 0;
void
fd_sandbox_disable( void ) {
  conf_sandbox_disabled = 1;
}

static uint conf_max_fd = 3;
void
fd_sandbox_set_max_open_files( uint max ) {
  conf_max_fd = max;
}

static int conf_highest_fd_to_keep = 3;
void
fd_sandbox_set_highest_fd_to_keep( int max ) {
  conf_highest_fd_to_keep = max;
}

static pid_t fd_sandbox_private_userns_child_pid = 0;
static int   fd_sandbox_private_userns_signals[2] = { 0 };

/* hooks */

static int conf_fd_boot_secure_called = 0;
void
fd_sandbox_proc_boot_hook( int *    pargc,
                           char *** pargv ) {
  conf_fd_boot_secure_called = 1;
  if ( FD_UNLIKELY( fd_env_strip_cmdline_contains( pargc, pargv, "--no-sandbox" ) ) ) {
    /* tiles must still be created */
    FD_LOG_WARNING(( "sandbox disabled" ));
    fd_sandbox_disable();
    return;
  }
  /* prevent coredumps and ptraces */
  FD_TEST_LOG_ERRNO( prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 );

  fd_sandbox_private_drop_bounding_ambient_inheritable_set();
  fd_sandbox_private_set_and_lock_securebits();

  uint env_uid = fd_env_strip_cmdline_uint( pargc, pargv, "--run-uid", "FD_SANDBOX_UID", fd_oveflow_user );
  uint env_gid = fd_env_strip_cmdline_uint( pargc, pargv, "--run-gid", "FD_SANDBOX_GID", fd_oveflow_group );

  if ( FD_UNLIKELY( env_uid == fd_oveflow_user ) ) {
    FD_LOG_WARNING(( "the process will run as its default overflow user" ));
  }

  if ( FD_UNLIKELY( env_gid == fd_oveflow_group ) ) {
    FD_LOG_WARNING(( "the process will run under its default overflow group" ));
  }

  FD_TEST_LOG_ERRNO( pipe( fd_sandbox_private_userns_signals ) == 0 );
  pid_t parent_pid = getpid();
  pid_t child_pid = 0;
  FD_TEST_LOG_ERRNO( ( child_pid = fork() ) >= 0 );

  if ( !child_pid ) {
    char dummy = 1;
    /* wait on the parent to be ready to have its userns configured */
    FD_TEST_LOG_ERRNO( read( fd_sandbox_private_userns_signals[0], &dummy, 1 ) == 1 );
    fd_sandbox_private_write_id_maps( env_uid, fd_oveflow_user, env_gid, fd_oveflow_group, parent_pid );
    exit(0);
  } else {
    fd_sandbox_private_userns_child_pid = child_pid;
  }
}

void
fd_sandbox_tile_boot_hook( void ) {
  if ( FD_UNLIKELY( conf_sandbox_disabled )) {
    return;
  }

  fd_sandbox_private_drop_current_thread_capabilities();
  fd_sandbox_private_assert_thread_no_capabilities();
}

void
fd_sandbox( int *    pargc,
            char *** pargv ) {

  /* fd_sandbox is only callable after an fd_boot_secure call.
     This sanity check will prevent the caller from being hit with an opaque EPERM. */
  if ( FD_UNLIKELY( !conf_fd_boot_secure_called ) ) {
    FD_LOG_ERR(( "fd_sandbox is called without a prior call to fd_boot_secure. If this was to ever work (which it shouldn't), "
                 "it would leave the program in an unsound state regarding security and safety." ));
  }

  if ( FD_UNLIKELY( conf_sandbox_disabled )) {
    /* tiles must still be created */
    fd_tile_private_boot( pargc, pargv );
    return;
  }

  fd_sandbox_private_setup_user();
  fd_sandbox_private_drop_bounding_ambient_inheritable_set();

  fd_sandbox_private_setup_netns();

  /* tiles must be created before any resource limits or mountns unshare because fd_log_private_stack_discover opens `/proc/self/maps` */
  fd_sandbox_private_drop_bounding_ambient_inheritable_set();

  fd_tile_private_boot( pargc, pargv );
  fd_sandbox_private_setup_mountns();
  fd_sandbox_private_set_resource_limits();
  fd_sandbox_private_close_fds_beyond();

  /* since the current thread will be tile 0, it needs to run the tile boot hook */
  fd_sandbox_tile_boot_hook();

  fd_sandbox_private_seccomp();

  /* beyond this point, no mitigations that require the process to be sigle-threaded can be initialized */
  fd_sandbox_private_secure_clear_environment();
  FD_LOG_NOTICE(( "sandbox: initialized" ));
  return;
}


/* private api */

typedef struct capdata64 {
  ulong effective;
  ulong permitted;
  ulong inherritable;
} cap_user_data_64_t;

static void
capdata_to_capdata64( cap_user_data_64_t * dst,
                      cap_user_data_t      src ) {
  dst->effective =    (((ulong)src[1].effective)   <<32) | ( (ulong)src[0].effective   );
  dst->inherritable = (((ulong)src[1].inheritable) <<32) | ( (ulong)src[0].inheritable );
  dst->permitted =    (((ulong)src[1].permitted)   <<32) | ( (ulong)src[0].permitted   );
}

static void
fd_sandbox_private_log_capdata( cap_user_data_64_t * data ) {
  FD_LOG_NOTICE(( "CapEff: %016lx\n", data->effective ));
  FD_LOG_NOTICE(( "CapPrm: %016lx\n", data->permitted ));
  FD_LOG_NOTICE(( "CapInh: %016lx\n", data->inherritable ));
}

void fd_sandbox_getcaps64( cap_user_data_64_t * dst ) {
  struct __user_cap_header_struct caphead = {
    .version = _LINUX_CAPABILITY_VERSION_3,
    .pid = 0,
  };
  struct __user_cap_data_struct capdata[2] = {{0}, {0}};
  FD_TEST_LOG_ERRNO( syscall( SYS_capget, &caphead, &capdata ) == 0 );
  capdata_to_capdata64( dst, capdata );
}

void
fd_sandbox_private_assert_thread_no_capabilities( void ) {
  cap_user_data_64_t caps;
  fd_sandbox_getcaps64( &caps );

  if ( FD_UNLIKELY( !( caps.effective    == 0UL &&
                       caps.inherritable == 0UL &&
                       caps.permitted    == 0UL    ) ) ) {
    fd_sandbox_private_log_capdata( &caps );
    FD_LOG_ERR(( "thread has caps when it should not" ));
  }
}

void
fd_sandbox_private_drop_current_thread_capabilities( void ) {
  struct __user_cap_header_struct caphead = {
    .version = _LINUX_CAPABILITY_VERSION_3,
    .pid = 0,
  };

  struct __user_cap_data_struct capdata[2] = {{0}, {0}};
  FD_TEST_LOG_ERRNO( syscall(SYS_capset, &caphead, &capdata) == 0 );
}

void
fd_sandbox_private_drop_bounding_ambient_inheritable_set( void ) {
  /* drop all capabilities from the bounding set */
  for ( int cap = 0; cap <= CAP_LAST_CAP; cap++ ) {
    FD_TEST_LOG_ERRNO( prctl( PR_CAPBSET_DROP, cap, 0, 0, 0 ) == 0 );
    FD_TEST_LOG_ERRNO( prctl( PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, cap, 0, 0 ) == 0 );
  }

  struct __user_cap_header_struct caphead = {
    .version = _LINUX_CAPABILITY_VERSION_3,
    .pid = 0,
  };

  struct __user_cap_data_struct capdata[2] = {{0}, {0}};
  FD_TEST_LOG_ERRNO( syscall(SYS_capget, &caphead, &capdata) == 0 );
  capdata[0].inheritable = 0;
  capdata[1].inheritable = 0;
  FD_TEST_LOG_ERRNO( syscall(SYS_capset, &caphead, &capdata) == 0 );
}

void
fd_sandbox_private_set_and_lock_securebits( void ) {
  FD_TEST_LOG_ERRNO( prctl (
    PR_SET_SECUREBITS,
    SECBIT_KEEP_CAPS_LOCKED | SECBIT_NO_SETUID_FIXUP |
      SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_NOROOT |
      SECBIT_NOROOT_LOCKED | SECBIT_NO_CAP_AMBIENT_RAISE |
      SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED ) == 0 );
}

void fd_sandbox_private_write_id_maps ( uint  outer_uid,
                                        uint  inner_uid,
                                        uint  outer_gid,
                                        uint  inner_gid,
                                        pid_t parent_pid ) {
  /* warn if the call might fail and hint to why */
  /* fetch capabilities so a warning can be emitted on missing capabilities */
  cap_user_data_64_t caps;
  fd_sandbox_getcaps64( &caps );

  if (getuid() != 0 && (caps.effective & (1<<CAP_SETUID)) == 0) {
    FD_LOG_WARNING(( "setresuid likely going to fail as CAP_SETUID is missing"));
  }
  if (getuid() != 0 && (caps.effective & (1<<CAP_SETGID)) == 0 ) {
    FD_LOG_WARNING(( "setresgid likely going to fail as CAP_SETGID is missing"));
  }

  /* write to parent's maps */
  char   map_path [100];
  FILE * mapfile;

  FD_TEST_LOG_ERRNO( sprintf(map_path, "/proc/%d/uid_map", parent_pid ) );
  FD_TEST_LOG_ERRNO( ( mapfile = fopen( map_path, "w+" ) ) != NULL );
  /* map inner root to outer nobody along with inner uid to outer uid */
  FD_TEST_LOG_ERRNO( fprintf( mapfile, "0 65534 1\n%u %u 1\n", inner_uid, outer_uid) > 0 );
  FD_TEST_LOG_ERRNO( fclose( mapfile ) == 0 );

  /* write deny to setgroups */
  FD_TEST_LOG_ERRNO( sprintf(map_path, "/proc/%d/setgroups", parent_pid ) );
  FD_TEST_LOG_ERRNO( ( mapfile = fopen( map_path, "w+" ) ) != NULL );
  FD_TEST_LOG_ERRNO( fprintf( mapfile, "deny" ) == strlen("deny") );
  FD_TEST_LOG_ERRNO( fclose( mapfile ) == 0 );

  // /* write to gid_map */
  FD_TEST_LOG_ERRNO( sprintf(map_path, "/proc/%d/gid_map", parent_pid ) );
  FD_TEST_LOG_ERRNO( ( mapfile = fopen( map_path, "w+" ) ) != NULL );
  FD_TEST_LOG_ERRNO( fprintf( mapfile, "0 65534 1\n%d %d 1", inner_gid, outer_gid ) > 0 );
  FD_TEST_LOG_ERRNO( fclose( mapfile ) == 0 );
}

void fd_sandbox_private_setup_user ( void ) {
  char dummy = 1;
  /* jump into a new userns */
  FD_TEST_LOG_ERRNO( unshare( CLONE_NEWUSER ) == 0 );

  FD_TEST_LOG_ERRNO( write( fd_sandbox_private_userns_signals[1], &dummy, 1 ) == 1 );

  /* wait for the child process to end */
  int exit_status = 0;
  FD_TEST_LOG_ERRNO( waitpid( fd_sandbox_private_userns_child_pid, &exit_status, 0 ) == fd_sandbox_private_userns_child_pid );

  FD_TEST_LOG_ERRNO( setresuid( fd_oveflow_user, fd_oveflow_user, fd_oveflow_user) == 0 );
  FD_TEST_LOG_ERRNO( setresgid( fd_oveflow_group, fd_oveflow_group, fd_oveflow_group) == 0);
  return;
}

void
fd_sandbox_private_close_fds_beyond( void ) {
  FD_LOG_INFO(( "closing all fds beyond %d", conf_highest_fd_to_keep ));
  long max_fds = sysconf( _SC_OPEN_MAX );
  for ( long fd = max_fds - 1; fd > conf_highest_fd_to_keep; fd-- ) {
    close( (int)fd );
  }
}

void
fd_sandbox_private_set_resource_limits( void ) {
  struct rlimit l = {
    .rlim_cur = conf_max_fd,
    .rlim_max = conf_max_fd,
  };

  FD_TEST_LOG_ERRNO( setrlimit( RLIMIT_NOFILE, &l ) == 0 );
}

void
fd_sandbox_private_setup_netns( void ) {
  FD_TEST_LOG_ERRNO( unshare( CLONE_NEWNET ) == 0 );
}

void
fd_sandbox_private_setup_mountns( void ) {
  FD_TEST_LOG_ERRNO( unshare( CLONE_NEWNS ) == 0 );
  FD_TEST_LOG_ERRNO( mount( NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) == 0 );

  char chroot_path [] = "/tmp/fd-sandbox-XXXXXX";
  FD_TEST_LOG_ERRNO( mkdtemp( chroot_path ) != NULL );

  FD_LOG_INFO(( "using %s as root mount", chroot_path ));

  FD_TEST_LOG_ERRNO( mount( chroot_path, chroot_path, NULL, MS_BIND | MS_REC, NULL ) == 0 );
  FD_TEST_LOG_ERRNO( chdir(chroot_path) == 0 );
  FD_TEST_LOG_ERRNO( mkdir(".old-root", 0600) == 0 );
  FD_TEST_LOG_ERRNO( syscall(SYS_pivot_root, "./", ".old-root" ) == 0 );
  FD_TEST_LOG_ERRNO( umount2(".old-root", MNT_DETACH) == 0 );
  FD_TEST_LOG_ERRNO( rmdir(".old-root") == 0 );
}

/* seccomp */
void
fd_sandbox_private_seccomp( void ) {
  struct sock_filter filter[] = {
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

  struct sock_fprog prog = {
    .len = ARRAY_SIZE( filter ),
    .filter = filter,
  };

  FD_TEST_LOG_ERRNO( prctl( PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0 ) == 0 );
  FD_TEST_LOG_ERRNO( syscall( SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog ) == 0 );
}

void
fd_sandbox_private_secure_clear_environment( void ) {
  char** env = environ;
  while ( *env ) {
    size_t len = strlen( *env );
    explicit_bzero( *env, len );
    env++;
  }
  clearenv();
}
