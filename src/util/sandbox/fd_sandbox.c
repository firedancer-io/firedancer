#if !defined(__linux__)
# error "Target operating system is unsupported by seccomp."
#endif

#define _GNU_SOURCE

#include "fd_sandbox.h"

#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/securebits.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/capability.h>
#include <dirent.h>
#include <limits.h>
#include <sched.h>        /* CLONE_*, setns, unshare */
#include <stddef.h>
#include <stdlib.h>       /* clearenv, mkdtemp*/
#include <sys/mman.h>     /* For mmap, etc. */
#include <sys/mount.h>    /* MS_*, MNT_*, mount, umount2 */
#include <sys/prctl.h>
#include <sys/resource.h> /* RLIMIT_*, rlimit, setrlimit */
#include <sys/stat.h>     /* mkdir */
#include <sys/syscall.h>  /* SYS_* */
#include <unistd.h>       /* set*id, sysconf, close, chdir, rmdir syscall */

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define X32_SYSCALL_BIT 0x40000000

#if defined(__i386__)
# define ARCH_NR  AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define ARCH_NR  AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
# define ARCH_NR AUDIT_ARCH_AARCH64
#else
# error "Target architecture is unsupported by seccomp."
#endif

#define FD_TESTV(c) \
  do { if( FD_UNLIKELY( !(c) ) ) FD_LOG_ERR(( "FAIL: %s (%i-%s)", #c, errno, fd_io_strerror( errno ) )); } while(0)

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
  FD_TESTV( unshare ( CLONE_NEWNS ) == 0 );

  char temp_dir [] = "/tmp/fd-sandbox-XXXXXX";
  FD_TESTV( mkdtemp( temp_dir ) );
  FD_TESTV( !mount( NULL, "/", NULL, MS_SLAVE | MS_REC, NULL ) );
  FD_TESTV( !mount( temp_dir, temp_dir, NULL, MS_BIND | MS_REC, NULL ) );
  FD_TESTV( !chdir( temp_dir ) );
  FD_TESTV( !mkdir( "old-root", S_IRUSR | S_IWUSR ));
  FD_TESTV( !syscall( SYS_pivot_root, ".", "old-root" ) );
  FD_TESTV( !chdir( "/" ) );
  FD_TESTV( !umount2( "old-root", MNT_DETACH ) );
  FD_TESTV( !rmdir( "old-root" ) );
}

static void
check_fds( ulong allow_fds_cnt,
           int * allow_fds ) {
  DIR * dir = opendir( "/proc/self/fd" );
  FD_TESTV( dir );
  int dirfd1 = dirfd( dir );
  FD_TESTV( dirfd1 >= 0 );

  struct dirent *dp;

  int seen_fds[ 256 ] = {0};
  FD_TESTV( allow_fds_cnt < 256 );

  while( ( dp = readdir( dir ) ) ) {
    char *end;
    long fd = strtol( dp->d_name, &end, 10 );
    FD_TESTV( fd < INT_MAX && fd > INT_MIN );
    if ( *end != '\0' ) {
      continue;
    }

    if( FD_LIKELY( fd == dirfd1 ) ) continue;

    int found = 0;
    for( ulong i=0; i<allow_fds_cnt; i++ ) {
      if ( FD_LIKELY( fd==allow_fds[ i ] ) ) {
        seen_fds[ i ] = 1;
        found = 1;
        break;
      }
    }

    if( !found ) {
      char path[ PATH_MAX ];
      int len = snprintf( path, PATH_MAX, "/proc/self/fd/%ld", fd );
      FD_TEST( len>0 && len < PATH_MAX );
      char target[ PATH_MAX ];
      long count = readlink( path, target, PATH_MAX );
      if( FD_UNLIKELY( count < 0 ) ) FD_LOG_ERR(( "readlink(%s) failed (%i-%s)", target, errno, fd_io_strerror( errno ) ));
      if( FD_UNLIKELY( count >= PATH_MAX ) ) FD_LOG_ERR(( "readlink(%s) returned truncated path", path ));
      target[ count ] = '\0';

      FD_LOG_ERR(( "unexpected file descriptor %ld open %s", fd, target ));
    }
  }

  for( ulong i=0; i<allow_fds_cnt; i++ ) {
    if( FD_UNLIKELY( !seen_fds[ i ] ) ) {
      FD_LOG_ERR(( "allowed file descriptor %d not present", allow_fds[ i ] ));
    }
  }

  FD_TESTV( !closedir( dir ) );
}

static void
install_seccomp( ushort               seccomp_filter_cnt,
                 struct sock_filter * seccomp_filter ) {
  struct sock_fprog program = {
    .len    = seccomp_filter_cnt,
    .filter = seccomp_filter,
  };
  FD_TESTV( 0 == syscall( SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program ) );
}

static void
drop_capabilities( void ) {
  FD_TESTV( 0 == prctl (
    PR_SET_SECUREBITS,
    SECBIT_KEEP_CAPS_LOCKED | SECBIT_NO_SETUID_FIXUP |
      SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_NOROOT |
      SECBIT_NOROOT_LOCKED | SECBIT_NO_CAP_AMBIENT_RAISE |
      SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED ) );

  struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
  struct __user_cap_data_struct   data[2] = { { 0 } };
  FD_TESTV( 0 == syscall( SYS_capset, &hdr, data ) );

  FD_TESTV( 0 == prctl( PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0 ) );
}

static void
userns_map( uint id, const char * map ) {
  char path[64];
  FD_TESTV( sprintf( path, "/proc/self/%s", map ) > 0);
  int fd = open( path, O_WRONLY );
  FD_TESTV( fd >= 0 );
  char line[64];
  FD_TESTV( sprintf( line, "0 %u 1\n", id ) > 0 );
  FD_TESTV( write( fd, line, strlen( line ) ) > 0 );
  FD_TESTV( !close( fd ) );
}

static void
deny_setgroups( void ) {
  int fd = open( "/proc/self/setgroups", O_WRONLY );
  FD_TESTV( fd >= 0 );
  FD_TESTV( write( fd, "deny", strlen( "deny" ) ) > 0 );
  FD_TESTV( !close( fd ) );
}

static void
switch_user( uint uid, uint gid ) {
  /* calling setresgid/setresuid sets the dumpable bit to 0
     which prevents debugging and stops us from setting our
     uid/gid maps in the user namespace, so set it back for
     now */
  int undumpable = 0;
  gid_t curgid, curegid, cursgid;
  FD_TESTV( !getresgid( &curgid, &curegid, &cursgid ) );
  if( FD_LIKELY( gid != curgid || gid != curegid || gid != cursgid )) {
    FD_TESTV( !setresgid( gid, gid, gid ) );
    undumpable = 1;
  }
  uid_t curuid, cureuid, cursuid;
  FD_TESTV( !getresuid( &curuid, &cureuid, &cursuid ) );
  if( FD_LIKELY( uid != curuid || uid != cureuid || uid != cursuid )) {
    FD_TESTV( !setresuid( uid, uid, uid ) );
    undumpable = 1;
  }
  if( FD_LIKELY( undumpable ) )
    FD_TESTV( !prctl( PR_SET_DUMPABLE, 1, 0, 0, 0 ) );
}

static void
unshare_user( uint uid, uint gid ) {
  switch_user( uid, gid );
  FD_TESTV( !unshare( CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWUTS ) );
  deny_setgroups();
  userns_map( uid, "uid_map" );
  userns_map( gid, "gid_map" );

  FD_TESTV( !prctl( PR_SET_DUMPABLE, 0, 0, 0, 0 ) );
  for ( int cap = 0; cap <= CAP_LAST_CAP; cap++ ) {
    FD_TESTV( !prctl( PR_CAPBSET_DROP, cap, 0, 0, 0 ) );
  }
}

/* Sandbox the current process by dropping all privileges and entering various
   restricted namespaces, but leave it able to make system calls. This should be
   done as a first step before later calling`install_seccomp`.

   You should call `unthreaded` before creating any threads in the process, and
   then install the seccomp profile afterwards. */
static void
sandbox_unthreaded( ulong allow_fds_cnt,
                    int * allow_fds,
                    uint uid,
                    uint gid ) {
  check_fds( allow_fds_cnt, allow_fds );
  unshare_user( uid, gid );
  struct rlimit limit = { .rlim_cur = 0, .rlim_max = 0 };
  FD_TESTV( !setrlimit( RLIMIT_NOFILE, &limit ));
  setup_mountns();
  drop_capabilities();
  secure_clear_environment();
}

void
fd_sandbox( int                  full_sandbox,
            uint                 uid,
            uint                 gid,
            ulong                allow_fds_cnt,
            int *                allow_fds,
            ulong                seccomp_filter_cnt,
            struct sock_filter * seccomp_filter ) {
  if( FD_LIKELY( full_sandbox ) ) {
    sandbox_unthreaded( allow_fds_cnt, allow_fds, uid, gid );
    FD_TESTV( !prctl( PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0 ) );
    FD_TEST( seccomp_filter_cnt <= USHORT_MAX );
    FD_LOG_INFO(( "sandbox: full sandbox is being enabled" )); /* log before seccomp in-case tile doesn't use logfile */
    install_seccomp( (ushort)seccomp_filter_cnt, seccomp_filter );
  } else {
    switch_user( uid, gid );
    FD_LOG_INFO(( "sandbox: no sandbox enabled" ));
  }
}

void *
fd_sandbox_alloc_protected_pages( ulong page_cnt,
                                  ulong guard_page_cnt ) {
#define PAGE_SZ (4096UL)
  void * pages = mmap( NULL, (2UL*guard_page_cnt+page_cnt)*PAGE_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0UL );
  if( FD_UNLIKELY( pages==MAP_FAILED ) ) FD_LOG_ERR(( "mmap failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  uchar * middle_pages = (uchar *)( (ulong)pages + guard_page_cnt*PAGE_SZ );

  /* Make the guard pages untouchable */
  if( FD_UNLIKELY( mprotect( pages, guard_page_cnt*PAGE_SZ, PROT_NONE ) ) )
    FD_LOG_ERR(( "mprotect failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( mprotect( middle_pages+page_cnt*PAGE_SZ, guard_page_cnt*PAGE_SZ, PROT_NONE ) ) )
    FD_LOG_ERR(( "mprotect failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* Lock the key page so that it doesn't page to disk */
  if( FD_UNLIKELY( mlock( middle_pages, page_cnt*PAGE_SZ ) ) )
    FD_LOG_ERR(( "mlock failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  /* Prevent the key page from showing up in core dumps. It shouldn't be
     possible to fork this process typically, but we also prevent any
     forked child from having this page. */
  if( FD_UNLIKELY( madvise( middle_pages, page_cnt*PAGE_SZ, MADV_WIPEONFORK | MADV_DONTDUMP ) ) )
    FD_LOG_ERR(( "madvise failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  return middle_pages;
#undef PAGE_SZ
}
