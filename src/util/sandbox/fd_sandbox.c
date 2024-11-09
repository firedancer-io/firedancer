#define _GNU_SOURCE
#include "fd_sandbox.h"

#include "../cstr/fd_cstr.h"
#include "../log/fd_log.h"

#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <linux/keyctl.h>
#include <linux/seccomp.h>
#include <linux/securebits.h>
#include <linux/capability.h>

#if !defined(__linux__)
#error "Target operating system is unsupported by seccomp."
#endif

#if !defined(__x86_64__) && !defined(__aarch64__)
#error "Target architecture is unsupported by seccomp."
#else

#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#endif

#ifndef SYS_landlock_restrict_self
#define SYS_landlock_restrict_self 446
#endif

#endif

void
fd_sandbox_private_switch_uid_gid( uint desired_uid,
                                   uint desired_gid );

static int
check_unshare_eacces_main( void * _arg ) {
  ulong arg = (ulong)_arg;
  uint desired_uid = (uint)((arg >>  0UL) & 0xFFFFUL);
  uint desired_gid = (uint)((arg >> 32UL) & 0xFFFFUL);

  fd_sandbox_private_switch_uid_gid( desired_uid, desired_gid );
  int result = unshare( CLONE_NEWUSER );
  if( -1==result && errno==EACCES ) return 255;
  else if( -1==result ) FD_LOG_ERR(( "unshare(CLONE_NEWUSER) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  result = open( "/proc/self/setgroups", O_WRONLY );
  if( -1==result && errno==EACCES ) return 255;
  if( -1==result ) FD_LOG_ERR(( "open(/proc/self/setgroups) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  return 0;
}

int
fd_sandbox_requires_cap_sys_admin( uint desired_uid,
                                   uint desired_gid ) {

  /* Check for the `unprivileged_userns_clone` sysctl which restricts
     unprivileged user namespaces on Debian. */

  int fd = open( "/proc/sys/kernel/unprivileged_userns_clone", O_RDONLY );
  if( -1==fd && errno!=ENOENT ) FD_LOG_ERR(( "open(/proc/sys/kernel/unprivileged_userns_clone) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  else if( -1!=fd ) {
    char buf[ 16 ] = {0};
    long count = read( fd, buf, sizeof( buf ) );
    if( -1L==count )                         FD_LOG_ERR(( "read(/proc/sys/kernel/unprivileged_userns_clone) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( (ulong)count>=sizeof( buf ) )        FD_LOG_ERR(( "read(/proc/sys/kernel/unprivileged_userns_clone) returned truncated data" ));
    if( 0L!=read( fd, buf, sizeof( buf ) ) ) FD_LOG_ERR(( "read(/proc/sys/kernel/unprivileged_userns_clone) did not return all the data" ));

    char * end;
    ulong unprivileged_userns_clone = strtoul( buf, &end, 10 );
    if( *end!='\n' ) FD_LOG_ERR(( "read(/proc/sys/kernel/unprivileged_userns_clone) returned malformed data" ));
    if( close( fd ) ) FD_LOG_ERR(( "close(/proc/sys/kernel/unprivileged_userns_clone) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    if( unprivileged_userns_clone!=0 && unprivileged_userns_clone!=1 ) FD_LOG_ERR(( "unprivileged_userns_clone has unexpected value %lu", unprivileged_userns_clone ));

    if( !unprivileged_userns_clone ) return 1;
  }

  /* Check for EACCES when actually trying to create a user namespace,
     which indicates an Ubuntu, AppArmor, or SELinux restriction.  We do
     this in a forked process so it doesn't unintentionally sandbox the
     caller.  Actually we can't fork here, because the stack might be
     MAP_SHARED, so do it in a clone with a new stack instead.

     From Ubuntu 23.10 til 24.04, user namespace creation is disallowed
     by default and trying to create one as an unprivileged user will
     return EACCES.

     From Ubuntu 24.04 onwards, user namespace creation is allowed, but
     trying to write to /proc/self/setgroups or set the UID/GID maps
     within the namespace will return EACCES. */

  do {
    uchar child_stack[ 2097152 ]; /* 2 MiB */
    ulong arg = ((ulong)desired_uid << 0UL) | (((ulong)desired_gid) << 32UL);
    int child_pid = clone( check_unshare_eacces_main, child_stack+sizeof(child_stack), 0, (void*)arg );
    if( -1==child_pid ) FD_LOG_ERR(( "clone() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    int wstatus;
    if( -1==waitpid( child_pid, &wstatus, __WALL ) )            FD_LOG_ERR(( "waitpid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( WIFSIGNALED( wstatus ) )                                FD_LOG_ERR(( "user namespace privilege checking process terminated by signal %i-%s", WTERMSIG( wstatus ), fd_io_strsignal( WTERMSIG( wstatus ) ) ));
    if( WEXITSTATUS( wstatus ) && WEXITSTATUS( wstatus )!=255 ) FD_LOG_ERR(( "user namespace privilege checking process exited with status %i", WEXITSTATUS( wstatus ) ));

    if( WEXITSTATUS( wstatus ) ) return 1;
  } while(0);

  return 0;
}

extern char ** environ;

void FD_FN_SENSITIVE
fd_sandbox_private_explicit_clear_environment_variables( void ) {
  if( !environ ) return;

  for( char * const * env = environ; *env; env++ ) {
    ulong len = strlen( *env );
    explicit_bzero( *env, len );
  }

  if( clearenv() ) FD_LOG_ERR(( "clearenv failed" ));
}

void
fd_sandbox_private_check_exact_file_descriptors( ulong       allowed_file_descriptor_cnt,
                                                 int const * allowed_file_descriptor ) {
  if( allowed_file_descriptor_cnt>256UL ) FD_LOG_ERR(( "allowed_file_descriptors_cnt must not be more than 256" ));
  int seen_fds[ 256 ] = {0};

  for( ulong i=0UL; i<allowed_file_descriptor_cnt; i++ ) {
    if( allowed_file_descriptor[ i ]<0 || allowed_file_descriptor[ i ]==INT_MAX )
      FD_LOG_ERR(( "allowed_file_descriptors contains invalid file descriptor %d", allowed_file_descriptor[ i ] ));
  }

  for( ulong i=0UL; i<allowed_file_descriptor_cnt; i++ ) {
    for( ulong j=0UL; j<allowed_file_descriptor_cnt; j++ ) {
      if( i==j ) continue;
      if( allowed_file_descriptor[ i ]==allowed_file_descriptor[ j ] )
        FD_LOG_ERR(( "allowed_file_descriptor contains duplicate entry %d", allowed_file_descriptor[ i ] ));
    }
  }

  int dirfd = open( "/proc/self/fd", O_RDONLY | O_DIRECTORY );
  if( dirfd<0 ) FD_LOG_ERR(( "open(/proc/self/fd) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  for(;;) {
    /* The getdents64() syscall ABI does not require that buf is aligned,
       since dent->d_name field is variable length, the records are not
       always aligned and the cast below is going to be unaligned anyway
       however...

       If we don't align it the compiler might prove somthing weird and
       trash this code, and also ASAN would flag it as an error.  So we
       just align it anyway. */
    uchar buf[ 4096 ] __attribute__((aligned(alignof(struct dirent64))));

    long dents_bytes = syscall( SYS_getdents64, dirfd, buf, sizeof( buf ) );
    if( !dents_bytes ) break;
    else if( -1L==dents_bytes ) FD_LOG_ERR(( "getdents64() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    ulong offset = 0UL;
    while( offset<(ulong)dents_bytes ) {
      struct dirent64 const * dent = (struct dirent64 const *)(buf + offset);
      if( !strcmp( dent->d_name, "." ) || !strcmp( dent->d_name, ".." ) ) {
        offset += dent->d_reclen;
        continue;
      }

      char * end;
      long _fd = strtol( dent->d_name, &end, 10 );
      if( *end != '\0' ) FD_LOG_ERR(( "/proc/self/pid has unrecognized entry name %s", dent->d_name ));
      if( _fd>=INT_MAX ) FD_LOG_ERR(( "/proc/self/pid has file descriptor number %ld which is too large", _fd ));
      int fd = (int)_fd;

      if( fd==dirfd ) {
        offset += dent->d_reclen;
        continue;
      }

      int found = 0;
      for( ulong i=0UL; i<allowed_file_descriptor_cnt; i++ ) {
        if( fd==allowed_file_descriptor[ i ] ) {
          if( seen_fds[ i ] ) FD_LOG_ERR(( "/proc/self/fd contained the same file descriptor (%d) twice", fd ));
          seen_fds[ i ] = 1;
          found = 1;
          break;
        }
      }

      if( !found ) {
        char path[ PATH_MAX ];
        FD_TEST( fd_cstr_printf_check( path, sizeof( path ), NULL, "/proc/self/fd/%d", fd ) );

        char target[ PATH_MAX ];
        long count = readlink( path, target, PATH_MAX );
        if( count<0L        ) FD_LOG_ERR(( "readlink(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
        if( count>=PATH_MAX ) FD_LOG_ERR(( "readlink(%s) returned truncated path", path ));
        target[ count ] = '\0';

        FD_LOG_ERR(( "unexpected file descriptor %d open %s", fd, target ));
      }

      offset += dent->d_reclen;
    }
  }

  for( ulong i=0UL; i<allowed_file_descriptor_cnt; i++ ) {
    if( !seen_fds[ i ] ) FD_LOG_ERR(( "allowed file descriptor %d not present", allowed_file_descriptor[ i ] ));
  }

  if( close( dirfd ) ) FD_LOG_ERR(( "close(/proc/self/fd) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

void
fd_sandbox_private_switch_uid_gid( uint desired_uid,
                                   uint desired_gid ) {
  /* We do a small hack: in development environments we sometimes want
     to run all tiles in a single process.  In that case, the sandbox
     doesn't get created except that we still switch to the desired uid
     and gid.

     There's a problem with this: POSIX states that all threads in a
     process must have the same uid and gid, so glibc does some wacky
     stuff... from man 2 setresgid

        C library/kernel differences
            At the kernel level, user IDs and group IDs are a per-thread
            attribute.  However, POSIX requires that all threads in a
            process share the same credentials.  The NPTL threading
            implementation handles the POSIX requirements by providing
            wrapper functions for the various system calls that change
            process UIDs and GIDs.  These  wrap‐ per functions
            (including those for setresuid() and setresgid()) employ a
            signal-based technique to ensure that when one thread
            changes credentials, all of the other threads in the process
            also change their credentials.  For details, see nptl(7).

      We know all of our threads in this development case are going to
      switch to the target uid/gid at their own leisure (they need to
      so they can do privileged steps before dropping root), so to
      align this behavior between production and development, we invoke
      the syscall directly and do not let glibc switch uid/gid on the
      other threads in the process. */
  int changed = 0;
  gid_t curgid, curegid, cursgid;
  if( -1==getresgid( &curgid, &curegid, &cursgid ) ) FD_LOG_ERR(( "getresgid failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( desired_gid!=curgid || desired_gid!=curegid || desired_gid!=cursgid ) {
    if( -1==syscall( __NR_setresgid, desired_gid, desired_gid, desired_gid ) ) FD_LOG_ERR(( "setresgid failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    changed = 1;
  }

  uid_t curuid, cureuid, cursuid;
  if( -1==getresuid( &curuid, &cureuid, &cursuid ) ) FD_LOG_ERR(( "getresuid failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( desired_uid!=curuid || desired_uid!=cureuid || desired_uid!=cursuid ) {
    if( -1==syscall( __NR_setresuid, desired_uid, desired_uid, desired_uid ) ) FD_LOG_ERR(( "setresuid failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    changed = 1;
  }

  /* Calling setresgid/setresuid sets the dumpable bit to 0 which
     prevents debugging and stops us from setting our uid/gid maps in
     the user namespace so restore it if it was changed. */
  if( changed ) {
    if( -1==prctl( PR_SET_DUMPABLE, 1 ) ) FD_LOG_ERR(( "prctl(PR_SET_DUMPABLE, 1) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
}

void
fd_sandbox_private_write_userns_uid_gid_maps( uint uid_in_parent,
                                              uint gid_in_parent ) {
  int setgroups_fd = open( "/proc/self/setgroups", O_WRONLY );
  if( FD_UNLIKELY( setgroups_fd<0 ) )                       FD_LOG_ERR(( "open(/proc/self/setgroups) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  long written = write( setgroups_fd, "deny", strlen( "deny" ) );
  if( FD_UNLIKELY( -1L==written ) )                         FD_LOG_ERR(( "write(/proc/self/setgroups) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  else if( FD_UNLIKELY( written!=(long)strlen( "deny" ) ) ) FD_LOG_ERR(( "write(/proc/self/setgroups) failed to write all data" ));
  if( FD_UNLIKELY( close( setgroups_fd ) ) )                FD_LOG_ERR(( "close(/proc/self/setgroups) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  static char const * MAP_PATHS[] = {
    "/proc/self/uid_map",
    "/proc/self/gid_map",
  };

  uint ids[] = {
    uid_in_parent,
    gid_in_parent
  };

  for( ulong i=0UL; i<2UL; i++ ) {
    int fd = open( MAP_PATHS[ i ], O_WRONLY );
    if( -1==fd )                              FD_LOG_ERR(( "open(%s) failed (%i-%s)", MAP_PATHS[ i ], errno, fd_io_strerror( errno ) ));

    char map_line[ 64 ];
    FD_TEST( fd_cstr_printf_check( map_line, sizeof( map_line ), NULL, "1 %u 1\n", ids[ i ] ) );
    long written = write( fd, map_line, strlen( map_line ) );
    if( -1L==written )                        FD_LOG_ERR(( "write(%s) failed (%i-%s)", MAP_PATHS[ i ], errno, fd_io_strerror( errno ) ));
    if( written != (long)strlen( map_line ) ) FD_LOG_ERR(( "write(%s) failed to write all data", MAP_PATHS[ i ] ));
    if( close( fd ) )                         FD_LOG_ERR(( "close(%s) failed (%i-%s)", MAP_PATHS[ i ], errno, fd_io_strerror( errno ) ));
  }
}

void
fd_sandbox_private_deny_namespaces( void ) {
  static char const * SYSCTLS[] = {
    "/proc/sys/user/max_user_namespaces",
    "/proc/sys/user/max_mnt_namespaces",
    "/proc/sys/user/max_cgroup_namespaces",
    "/proc/sys/user/max_ipc_namespaces",
    "/proc/sys/user/max_net_namespaces",
    "/proc/sys/user/max_pid_namespaces",
    "/proc/sys/user/max_uts_namespaces",
  };

  static char const * VALUES[] = {
    "1", /* One user namespace is allowed, to created the nested child. */
    "2", /* Two mount namespaces are allowed, the one in the parent user namespace, and the one we will use to pivot the root in the child namespace */
    "0",
    "0",
    "0",
    "0",
    "0",
  };

  for( ulong i=0UL; i<sizeof(SYSCTLS)/sizeof(SYSCTLS[ 0 ]); i++) {
    int fd = open( SYSCTLS[ i ], O_WRONLY );
    if( fd<0 )                       FD_LOG_ERR(( "open(%s) failed (%i-%s)", SYSCTLS[ i ], errno, fd_io_strerror( errno ) ));

    long written = write( fd, VALUES[ i ], 1 );
    if( written==-1 )                FD_LOG_ERR(( "write(%s) failed (%i-%s)", SYSCTLS[ i ], errno, fd_io_strerror( errno ) ));
    else if( written!=1 )            FD_LOG_ERR(( "write(%s) failed to write data", SYSCTLS[ i ] ));
    if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close(%s) failed (%i-%s)", SYSCTLS[ i ], errno, fd_io_strerror( errno ) ));
  }
}

void
fd_sandbox_private_pivot_root( void ) {
  /* The steps taken here to unmount the filesystem and jail us into an
     empty location look incredibly strange, but are a somewhat standard
     pattern copied from other sandboxes.  For a couple of examples, see

        https://github.com/firecracker-microvm/firecracker/blob/main/src/jailer/src/chroot.rs
        https://github.com/hpc/charliecloud/blob/master/bin/ch-checkns.c
        https://github.com/opencontainers/runc/blob/HEAD/libcontainer/rootfs_linux.go#L671
        https://github.com/lxc/lxc/blob/HEAD/src/lxc/conf.c#L1121
        https://github.com/containers/bubblewrap/blob/main/bubblewrap.c#L3196

     The core problem is that calling pivot_root(2) will fail if the
     list of mounts in the namespace is not arranged very carefully. */

  if( -1==unshare( CLONE_NEWNS ) )                                              FD_LOG_ERR(( "unshare(CLONE_NEWNS) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  ulong bytes;
  if( 8UL!=getrandom( &bytes, sizeof( bytes ), 0 ) )                            FD_LOG_ERR(( "getrandom() failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  char new_root_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( new_root_path, sizeof( new_root_path ), NULL, "/tmp/fd_sandbox_%lu", bytes ) );

  if( -1==mkdir( new_root_path, S_IRUSR | S_IWUSR | S_IXUSR ) )                 FD_LOG_ERR(( "mkdir(%s, 0700) failed (%i-%s)", new_root_path, errno, fd_io_strerror( errno ) ));
  if( -1==mount( NULL, "/", NULL, MS_SLAVE | MS_REC, NULL ) )                   FD_LOG_ERR(( "mount(NULL, /, NULL, MS_SLAVE | MS_REC, NULL) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( -1==mount( new_root_path, new_root_path, NULL, MS_BIND | MS_REC, NULL ) ) FD_LOG_ERR(( "mount(%s, %s, NULL, MS_BIND | MS_REC, NULL) failed (%i-%s)", new_root_path, new_root_path, errno, fd_io_strerror( errno ) ));
  if( -1==chdir( new_root_path ) )                                              FD_LOG_ERR(( "chdir(%s) failed (%i-%s)", new_root_path, errno, fd_io_strerror( errno ) ));
  if( -1==syscall( SYS_pivot_root, ".", "." ) )                                 FD_LOG_ERR(( "pivot_root(., .) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( -1==umount2( ".", MNT_DETACH ) )                                          FD_LOG_ERR(( "umount2(., MNT_DETACH) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( -1==chdir( "/" ) )                                                        FD_LOG_ERR(( "chdir(/) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

struct rlimit_setting {
#ifdef __GLIBC__
  __rlimit_resource_t resource;
#else /* non-glibc */
  int resource;
#endif /* __GLIBC__ */

  ulong limit;
};

void
fd_sandbox_private_set_rlimits( ulong rlimit_file_cnt ) {
  struct rlimit_setting rlimits[] = {
    { .resource=RLIMIT_NOFILE,     .limit=rlimit_file_cnt },
    /* The man page for setrlimit(2) states about RLIMIT_NICE:

          The useful range for this limit is thus from 1 (corresponding
          to a nice value of 19) to 40 (corresponding to a nice value of
          -20).

       But this is misleading.  The range of values is from 0 to 40,
       even though the "useful" range is 1 to 40, because a value of 0
       and a value of 1 for the rlimit both map to a nice value of 19.

       But... if you attempt to call setrlimit( RLIMIT_NICE, 1 ) without
       CAP_SYS_RESOURCE, and the hard limit is already 0, you will get
       EPERM, so we actually have to set the limit to 0 here, not 1. */
    { .resource=RLIMIT_NICE,       .limit=0UL             },

    { .resource=RLIMIT_AS,         .limit=0UL             },
    { .resource=RLIMIT_CORE,       .limit=0UL             },
    { .resource=RLIMIT_DATA,       .limit=0UL             },
    { .resource=RLIMIT_MEMLOCK,    .limit=0UL             },
    { .resource=RLIMIT_MSGQUEUE,   .limit=0UL             },
    { .resource=RLIMIT_NPROC,      .limit=0UL             },
    { .resource=RLIMIT_RTPRIO,     .limit=0UL             },
    { .resource=RLIMIT_RTTIME,     .limit=0UL             },
    { .resource=RLIMIT_SIGPENDING, .limit=0UL             },
    { .resource=RLIMIT_STACK,      .limit=0UL             },

    /* Resources that can't be restricted. */
    // { .resource=RLIMIT_CPU,        .limit=0UL             },
    // { .resource=RLIMIT_FSIZE,      .limit=0UL             },

    /* Deprecated resources, not used. */
    // { .resource=RLIMIT_LOCKS,      .limit=0UL             },
    // { .resource=RLIMIT_RSS,        .limit=0UL             },
  };

  for( ulong i=0UL; i<sizeof(rlimits)/sizeof(rlimits[ 0 ]); i++ ) {
    struct rlimit limit = { .rlim_cur=rlimits[ i ].limit, .rlim_max=rlimits[ i ].limit };
    if( -1==setrlimit( rlimits[ i ].resource, &limit ) ) FD_LOG_ERR(( "setrlimit(%u) failed (%i-%s)", rlimits[ i ].resource, errno, fd_io_strerror( errno ) ));
  }
}

void
fd_sandbox_private_drop_caps( ulong cap_last_cap ) {
  if( -1==prctl( PR_SET_SECUREBITS,
                 SECBIT_KEEP_CAPS_LOCKED | SECBIT_NO_SETUID_FIXUP |
                    SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_NOROOT |
                    SECBIT_NOROOT_LOCKED | SECBIT_NO_CAP_AMBIENT_RAISE |
                    SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED ) ) FD_LOG_ERR(( "prctl(PR_SET_SECUREBITS) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  for( ulong cap=0UL; cap<=cap_last_cap; cap++ ) {
    if( -1==prctl( PR_CAPBSET_DROP, cap, 0, 0, 0 ) ) FD_LOG_ERR(( "prctl(PR_CAPBSET_DROP) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
  struct __user_cap_data_struct   data[2] = { { 0 } };
  if( -1==syscall( SYS_capset, &hdr, data ) )                          FD_LOG_ERR(( "syscall(SYS_capset) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( -1==prctl( PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0 ) ) FD_LOG_ERR(( "prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)

#define LANDLOCK_ACCESS_FS_EXECUTE      (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE   (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE    (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR     (1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR   (1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE  (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR    (1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR     (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG     (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK    (1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO    (1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK   (1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM     (1ULL << 12)
#define LANDLOCK_ACCESS_FS_REFER        (1ULL << 13)
#define LANDLOCK_ACCESS_FS_TRUNCATE     (1ULL << 14)
#define LANDLOCK_ACCESS_FS_IOCTL_DEV    (1ULL << 15)

#define LANDLOCK_ACCESS_NET_BIND_TCP    (1ULL << 0)
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)

struct landlock_ruleset_attr {
    __u64 handled_access_fs;
    __u64 handled_access_net;
};

void
fd_sandbox_private_landlock_restrict_self( void ) {
  struct landlock_ruleset_attr attr = {
    .handled_access_fs =
      LANDLOCK_ACCESS_FS_EXECUTE |
      LANDLOCK_ACCESS_FS_WRITE_FILE |
      LANDLOCK_ACCESS_FS_READ_FILE |
      LANDLOCK_ACCESS_FS_READ_DIR |
      LANDLOCK_ACCESS_FS_REMOVE_DIR |
      LANDLOCK_ACCESS_FS_REMOVE_FILE |
      LANDLOCK_ACCESS_FS_MAKE_CHAR |
      LANDLOCK_ACCESS_FS_MAKE_DIR |
      LANDLOCK_ACCESS_FS_MAKE_REG |
      LANDLOCK_ACCESS_FS_MAKE_SOCK |
      LANDLOCK_ACCESS_FS_MAKE_FIFO |
      LANDLOCK_ACCESS_FS_MAKE_BLOCK |
      LANDLOCK_ACCESS_FS_MAKE_SYM |
      LANDLOCK_ACCESS_FS_REFER |
      LANDLOCK_ACCESS_FS_TRUNCATE |
      LANDLOCK_ACCESS_FS_IOCTL_DEV,
    .handled_access_net =
      LANDLOCK_ACCESS_NET_BIND_TCP |
      LANDLOCK_ACCESS_NET_CONNECT_TCP,
  };

  long abi = syscall( SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION );
  if( -1L==abi && (errno==ENOSYS || errno==EOPNOTSUPP ) ) return;
  else if( -1L==abi ) FD_LOG_ERR(( "landlock_create_ruleset() failed (%i-%s).", errno, fd_io_strerror( errno ) ));

  switch (abi) {
  case 1L:
      /* Removes LANDLOCK_ACCESS_FS_REFER for ABI < 2 */
      attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
      __attribute__((fallthrough));
  case 2L:
      /* Removes LANDLOCK_ACCESS_FS_TRUNCATE for ABI < 3 */
      attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
      __attribute__((fallthrough));
  case 3L:
      /* Removes network support for ABI < 4 */
      attr.handled_access_net &=
          ~(LANDLOCK_ACCESS_NET_BIND_TCP |
            LANDLOCK_ACCESS_NET_CONNECT_TCP);
      __attribute__((fallthrough));
  case 4L:
      /* Removes LANDLOCK_ACCESS_FS_IOCTL_DEV for ABI < 5 */
      attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;
  }

  long landlock_fd = syscall( SYS_landlock_create_ruleset, &attr, 16, 0 );
  if( -1L==landlock_fd ) FD_LOG_ERR(( "landlock_create_ruleset() failed (%i-%s).", errno, fd_io_strerror( errno ) ));

  if( syscall( SYS_landlock_restrict_self, landlock_fd, 0 ) ) FD_LOG_ERR(( "landlock_restrict_self() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

void
fd_sandbox_private_set_seccomp_filter( ushort               seccomp_filter_cnt,
                                       struct sock_filter * seccomp_filter ) {
  struct sock_fprog program = {
    .len    = seccomp_filter_cnt,
    .filter = seccomp_filter,
  };

  if( syscall( SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program ) ) FD_LOG_ERR(( "seccomp() failed (%i-%s)", errno, fd_io_strerror( errno ) ) );
}

ulong
fd_sandbox_private_read_cap_last_cap( void ) {
  int fd = open( "/proc/sys/kernel/cap_last_cap", O_RDONLY );
  if( -1==fd ) FD_LOG_ERR(( "open(/proc/sys/kernel/cap_last_cap) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  char buf[ 16 ] = {0};
  long count = read( fd, buf, sizeof( buf ) );
  if( -1L==count ) FD_LOG_ERR(( "read(/proc/sys/kernel/cap_last_cap) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( (ulong)count>=sizeof( buf ) ) FD_LOG_ERR(( "read(/proc/sys/kernel/cap_last_cap) returned truncated data" ));
  if( 0L!=read( fd, buf, sizeof( buf ) ) ) FD_LOG_ERR(( "read(/proc/sys/kernel/cap_last_cap) did not return all the data" ));

  char * end;
  ulong cap_last_cap = strtoul( buf, &end, 10 );
  if( *end!='\n' ) FD_LOG_ERR(( "read(/proc/sys/kernel/cap_last_cap) returned malformed data" ));
  if( close( fd ) ) FD_LOG_ERR(( "close(/proc/sys/kernel/cap_last_cap) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( !cap_last_cap || cap_last_cap>128 ) FD_LOG_ERR(( "read(/proc/sys/kernel/cap_last_cap) returned invalid data" ));

  return cap_last_cap;
}

void
fd_sandbox_private_enter_no_seccomp( uint        desired_uid,
                                     uint        desired_gid,
                                     int         keep_host_networking,
                                     int         keep_controlling_terminal,
                                     ulong       rlimit_file_cnt,
                                     ulong       allowed_file_descriptor_cnt,
                                     int const * allowed_file_descriptor ) {
  /* Read the highest capability index on the currently running kernel
     from /proc */
  ulong cap_last_cap = fd_sandbox_private_read_cap_last_cap();

  /* The ordering here is quite delicate and should be preserved ...

      | Action                 | Must happen before          | Reason
      |------------------------|-----------------------------|-------------------------------------
      | Check file descriptors | Pivot root                  | Requires access to /proc filesystem
      | Clear groups           | Unshare namespaces          | Cannot call setgroups(2) in user namespace
      | Unshare namespaces     | Pivot root                  | Pivot root requires CAP_SYS_ADMIN
      | Pivot root             | Drop caps                   | Requires CAP_SYS_ADMIN
      | Pivot root             | Landlock                    | Accesses the filesystem
      | Landlock               | Set resource limits         | Creates a file descriptor
      | Set resource limits    | Drop caps                   | Requires CAP_SYS_RESOURCE */
  fd_sandbox_private_explicit_clear_environment_variables();
  fd_sandbox_private_check_exact_file_descriptors( allowed_file_descriptor_cnt, allowed_file_descriptor );

  /* Dropping groups can increase privileges to resources that deny
     certain groups so don't do that, just check that we have no
     supplementary group IDs. */
  int getgroups_cnt = getgroups( 0UL, NULL );
  if( -1==getgroups_cnt )                                            FD_LOG_ERR(( "getgroups() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( getgroups_cnt>1 )                                              FD_LOG_WARNING(( "getgroups() returned multiple supplementary groups (%d), run `id` to see them. "
                                                                                      "Continuing, but it is suggested to run Firedancer with a sandbox user that has as few permissions as possible.", getgroups_cnt ));

  /* Replace the session keyring in the process with a new
     anonymous one, in case the systemd or other launcher
     provided us with something by mistake. */
  if( -1==syscall( SYS_keyctl, KEYCTL_JOIN_SESSION_KEYRING, NULL ) ) FD_LOG_ERR(( "syscall(SYS_keyctl) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* Detach from the controlling terminal to prevent TIOCSTI type of
     escapes.  See https://github.com/containers/bubblewrap/issues/142 */
  if( !keep_controlling_terminal ) {
    if( -1==setsid() )                                               FD_LOG_ERR(( "setsid() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* Certain Linux kernels are configured to not allow user namespaces
     from an unprivileged process, since it's a common security exploit
     vector.  You can still make the namespace if you have CAP_SYS_ADMIN
     so we need to make sure to carry this through the switch_uid_gid
     which would drop all capabilities by default. */
  int userns_requires_cap_sys_admin = fd_sandbox_requires_cap_sys_admin( desired_uid, desired_gid );
  if( userns_requires_cap_sys_admin ) {
    if( -1==prctl( PR_SET_KEEPCAPS, 1 ) ) FD_LOG_ERR(( "prctl(PR_SET_KEEPCAPS, 1) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  fd_sandbox_private_switch_uid_gid( desired_uid, desired_gid );

  /* Now raise CAP_SYS_ADMIN again after we switched UID/GID, if it's
     required to create the user namespace. */
  if( userns_requires_cap_sys_admin ) {
    struct __user_cap_header_struct capheader;
    capheader.version = _LINUX_CAPABILITY_VERSION_3;
    capheader.pid = 0;
    struct __user_cap_data_struct capdata[2] = { {0} };
    if( -1==syscall( SYS_capget, &capheader, capdata ) ) FD_LOG_ERR(( "syscall(SYS_capget) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    capdata[ CAP_TO_INDEX( CAP_SYS_ADMIN ) ].effective |= CAP_TO_MASK( CAP_SYS_ADMIN );
    if( -1==syscall( SYS_capset, &capheader, capdata ) ) FD_LOG_ERR(( "syscall(SYS_capset) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  /* Now unshare the user namespace, disallow creating any more
     namespaces except one child user namespace, and then create the
     child user namespace so that the sandbox can't undo the change. */
  if( -1==unshare( CLONE_NEWUSER ) ) FD_LOG_ERR(( "unshare(CLONE_NEWUSER) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  fd_sandbox_private_write_userns_uid_gid_maps( desired_uid, desired_gid );

  /* Unshare everything in the parent user namespace, so that the nested
     user namespace does not have privileges over them. */
  int flags = CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWUTS;
  if( !keep_host_networking ) flags |= CLONE_NEWNET;

  if( -1==unshare( flags ) ) FD_LOG_ERR(( "unshare(CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWUTS) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  fd_sandbox_private_deny_namespaces();

  if( -1==unshare( CLONE_NEWUSER ) ) FD_LOG_ERR(( "unshare(CLONE_NEWUSER) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  fd_sandbox_private_write_userns_uid_gid_maps( 1, 1 );

  /* PR_SET_KEEPCAPS will already be 0 if we didn't need to raise
     CAP_SYS_ADMIN, but we always clear it anyway. */
  if( -1==prctl( PR_SET_KEEPCAPS, 0 ) ) FD_LOG_ERR(( "prctl(PR_SET_KEEPCAPS, 0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( -1==prctl( PR_SET_DUMPABLE, 0 ) ) FD_LOG_ERR(( "prctl(PR_SET_DUMPABLE, 0) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* Now remount the filesystem root so no files are accessible any more. */
  fd_sandbox_private_pivot_root();

  /* Add an empty landlock restriction to further prevent filesystem
     access. */
  fd_sandbox_private_landlock_restrict_self();

  /* And trim all the resource limits down to zero. */
  fd_sandbox_private_set_rlimits( rlimit_file_cnt );

  /* And drop all the capabilities we have in the new user namespace. */
  fd_sandbox_private_drop_caps( cap_last_cap );

  if( -1==prctl( PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0 ) ) FD_LOG_ERR(( "prctl(PR_SET_NO_NEW_PRIVS, 1) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

void
fd_sandbox_enter( uint                 desired_uid,
                  uint                 desired_gid,
                  int                  keep_host_networking,
                  int                  keep_controlling_terminal,
                  ulong                rlimit_file_cnt,
                  ulong                allowed_file_descriptor_cnt,
                  int const *          allowed_file_descriptor,
                  ulong                seccomp_filter_cnt,
                  struct sock_filter * seccomp_filter ) {
  if( seccomp_filter_cnt>USHORT_MAX ) FD_LOG_ERR(( "seccomp_filter_cnt must not be more than %d", USHORT_MAX ));

  fd_sandbox_private_enter_no_seccomp( desired_uid,
                                       desired_gid,
                                       keep_host_networking,
                                       keep_controlling_terminal,
                                       rlimit_file_cnt,
                                       allowed_file_descriptor_cnt,
                                       allowed_file_descriptor );

  FD_LOG_INFO(( "sandbox: full sandbox is being enabled" )); /* log before seccomp in-case logging not allowed in sandbox */

  /* Now finally install the seccomp-bpf filter. */
  fd_sandbox_private_set_seccomp_filter( (ushort)seccomp_filter_cnt, seccomp_filter );
}

void
fd_sandbox_switch_uid_gid( uint desired_uid,
                           uint desired_gid ) {
  fd_sandbox_private_switch_uid_gid( desired_uid, desired_gid );
  FD_LOG_INFO(( "sandbox: sandbox disabled" ));
}

ulong
fd_sandbox_getpid( void ) {
  char pid[ 11 ] = {0}; /* 10 characters for INT_MAX, and then a NUL terminator. */
  long count = readlink( "/proc/self", pid, sizeof(pid) );
  if( -1L==count )                FD_LOG_ERR(( "readlink(/proc/self) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( (ulong)count>=sizeof(pid) ) FD_LOG_ERR(( "readlink(/proc/self) returned truncated pid" ));

  char * endptr;
  ulong result = strtoul( pid, &endptr, 10 );
  /* A pid > INT_MAX is malformed, even if we can represent it in the
     ulong we are returning. */
  if( *endptr!='\0' || result>INT_MAX ) FD_LOG_ERR(( "strtoul(/proc/self) returned invalid pid" ));

  return result;
}

ulong
fd_sandbox_gettid( void ) {
  char tid[ 27 ] = {0}; /* 10 characters for INT_MAX, twice, + /task/ and then a NUL terminator. */
  long count = readlink( "/proc/thread-self", tid, sizeof(tid) );
  if( count<0L )                  FD_LOG_ERR(( "readlink(/proc/thread-self) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( (ulong)count>=sizeof(tid) ) FD_LOG_ERR(( "readlink(/proc/thread-self) returned truncated tid" ));

  char * taskstr = strchr( tid, '/' );
  if( !taskstr ) FD_LOG_ERR(( "readlink(/proc/thread-self) returned invalid tid" ));
  taskstr++;

  char * task = strchr( taskstr, '/' );
  if( !task ) FD_LOG_ERR(( "readlink(/proc/thread-self) returned invalid tid" ));

  char * endptr;
  ulong result = strtoul( task+1UL, &endptr, 10 );
  /* A tid > INT_MAX is malformed, even if we can represent it in the
     ulong we are returning. */
  if( *endptr!='\0' || result>INT_MAX ) FD_LOG_ERR(( "strtoul(/proc/self) returned invalid tid" ));

  return result;
}
