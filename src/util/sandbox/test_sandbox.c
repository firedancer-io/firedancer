#define _GNU_SOURCE
#include "fd_sandbox.h"
#include "fd_sandbox_private.h"

#include "../fd_util.h"
#include "generated/test_sandbox_seccomp.h"

#include <sys/file.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <dirent.h>
#include <net/if.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <linux/securebits.h>
#include <linux/capability.h>

#define TEST_FORK_EXIT_CODE(child, code) do {             \
    pid_t pid = fork();                                   \
    if ( pid ) {                                          \
      int wstatus;                                        \
      FD_TEST( -1!=waitpid( pid, &wstatus, WUNTRACED ) ); \
      if( !WIFEXITED( wstatus ) ) {                       \
        FD_LOG_ERR(( "child exited with signal %d(%s)", WTERMSIG( wstatus ), fd_io_strsignal( WTERMSIG( wstatus ) ) )); \
      }                                                   \
      FD_TEST( WIFEXITED( wstatus ) );                    \
      FD_TEST( !WIFSIGNALED( wstatus ) );                 \
      FD_TEST( !WIFSTOPPED( wstatus ) );                  \
      FD_TEST( WEXITSTATUS( wstatus )==code );            \
    } else {                                              \
      do { child; } while ( 0 );                          \
      exit( EXIT_SUCCESS );                               \
    }                                                     \
} while( 0 )

#define TEST_FORK_SIGNAL(child, code) do {                \
    pid_t pid = fork();                                   \
    if ( pid ) {                                          \
      int wstatus;                                        \
      FD_TEST( -1!=waitpid( pid, &wstatus, WUNTRACED ) ); \
      FD_TEST( !WIFEXITED( wstatus ) );                   \
      FD_TEST( !WEXITSTATUS( wstatus ) );                 \
      FD_TEST( WIFSIGNALED( wstatus ) );                  \
      FD_TEST( !WIFSTOPPED( wstatus ) );                  \
      FD_TEST( WTERMSIG( wstatus )==code );               \
    } else {                                              \
      do { child; } while ( 0 );                          \
      exit( EXIT_SUCCESS );                               \
    }                                                     \
} while( 0 )

extern char ** environ;

void
test_clear_environment( void ) {
  FD_TEST( !clearenv() );
  FD_TEST( !environ );
  FD_TEST( !setenv( "TEST", "value", 1 ) );
  FD_TEST( !setenv( "TEST2", "value2", 1 ) );
  FD_TEST( !setenv( "AAAAAAAAAAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBB", 1 ) );

  char const * test1 = *(environ+0); ulong test1_len = strlen( test1 );
  char const * test2 = *(environ+1); ulong test2_len = strlen( test1 );
  char const * test3 = *(environ+2); ulong test3_len = strlen( test1 );
  FD_TEST( !strcmp( test1, "TEST=value" ) );
  FD_TEST( !strcmp( test2, "TEST2=value2" ) );
  FD_TEST( !strcmp( test3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAA=BBBBBBBBBBBBB" ) );

  fd_sandbox_private_explicit_clear_environment_variables();
  FD_TEST( !environ );

  /* Make sure memory was actually zeroed. */
  for( ulong i=0UL; i<test1_len; i++ ) FD_TEST( !test1[ i ] );
  for( ulong i=0UL; i<test2_len; i++ ) FD_TEST( !test2[ i ] );
  for( ulong i=0UL; i<test3_len; i++ ) FD_TEST( !test3[ i ] );
}

void
test_check_file_descriptors_inner( void ) {
  int allow_fds[] = { 0, 1, 2, 3 };
  TEST_FORK_EXIT_CODE( fd_sandbox_private_check_exact_file_descriptors( 4UL, allow_fds ), 0 );
  TEST_FORK_EXIT_CODE( fd_sandbox_private_check_exact_file_descriptors( 3UL, allow_fds ), 1 );
  TEST_FORK_EXIT_CODE( fd_sandbox_private_check_exact_file_descriptors( 0UL, allow_fds ), 1 );

  int allow_fds2[] = { 0, 1, 2, 3, 4 };
  TEST_FORK_EXIT_CODE( fd_sandbox_private_check_exact_file_descriptors( 5UL, allow_fds2 ), 1 );

  int allow_fds3[] = { 1, 2, 3 };
  TEST_FORK_EXIT_CODE( fd_sandbox_private_check_exact_file_descriptors( 3UL, allow_fds3 ), 1 );

  int allow_fds4[] = { 0, 1, 3 };
  TEST_FORK_EXIT_CODE( fd_sandbox_private_check_exact_file_descriptors( 3UL, allow_fds4 ), 1 );

  int allow_fds5[] = { 0, 1, 2, 3, 1 };
  TEST_FORK_EXIT_CODE( fd_sandbox_private_check_exact_file_descriptors( 5UL, allow_fds5 ), 1 );

  int allow_fds6[] = { 0, 1, 2, 3, -1 };
  TEST_FORK_EXIT_CODE( fd_sandbox_private_check_exact_file_descriptors( 5UL, allow_fds6 ), 1 );

  FD_TEST( -1!=dup2( 3, 4 ) );
  TEST_FORK_EXIT_CODE( fd_sandbox_private_check_exact_file_descriptors( 4UL, allow_fds ), 1 );
  TEST_FORK_EXIT_CODE( fd_sandbox_private_check_exact_file_descriptors( 5UL, allow_fds2 ), 0 );

  int too_many_fds[ 257 ];
  for( int i=0UL; i<257; i++) too_many_fds[ i ] = i;
  for( int i=5UL; i<256; i++) FD_TEST(-1!=dup2( 3, i ));
  TEST_FORK_EXIT_CODE( fd_sandbox_private_check_exact_file_descriptors( 256UL, too_many_fds ), 0 );
  FD_TEST( -1!=dup2( 3, 256 ) );
  TEST_FORK_EXIT_CODE( fd_sandbox_private_check_exact_file_descriptors( 257UL, too_many_fds ), 1 );
}

void
test_check_file_descriptors( void ) {
  TEST_FORK_EXIT_CODE( test_check_file_descriptors_inner(), 0 );
}

void
test_deny_namespaces_inner( void ) {
  uint uid = getuid();
  uint gid = getgid();
  FD_TEST( -1!=unshare( CLONE_NEWUSER ) );
  fd_sandbox_private_write_userns_uid_gid_maps( uid, gid );

  static char const * SYSCTLS[] = {
    "/proc/sys/user/max_user_namespaces",
    "/proc/sys/user/max_mnt_namespaces",
    "/proc/sys/user/max_cgroup_namespaces",
    "/proc/sys/user/max_ipc_namespaces",
    "/proc/sys/user/max_net_namespaces",
    "/proc/sys/user/max_pid_namespaces",
    "/proc/sys/user/max_uts_namespaces",
  };

  for( ulong i=0UL; i<sizeof( SYSCTLS )/sizeof( SYSCTLS[ 0 ] ); i++ ) {
    int fd = open( SYSCTLS[ i ], O_RDONLY );
    FD_TEST( fd>=0 );
    char buf[ 16 ] = {0};
    long count = read( fd, buf, sizeof( buf ) );
    FD_TEST( count>=0 && (ulong)count<sizeof( buf ) );
    FD_TEST( !read( fd, buf, sizeof( buf ) ) );
    FD_TEST( !close( fd ) );

    char * endptr;
    ulong value = strtoul( buf, &endptr, 10 );
    FD_TEST( *endptr=='\n' );
    FD_TEST( value>1UL );
  }

  fd_sandbox_private_deny_namespaces();

  for( ulong i=0UL; i<sizeof( SYSCTLS )/sizeof( SYSCTLS[ 0 ] ); i++ ) {
    int fd = open( SYSCTLS[ i ], O_RDONLY );
    FD_TEST( fd>=0 );
    char buf[ 16 ] = {0};
    long count = read( fd, buf, sizeof( buf ) );
    FD_TEST( count>=0 && (ulong)count<sizeof( buf ) );
    FD_TEST( !read( fd, buf, sizeof( buf ) ) );
    FD_TEST( !close( fd ) );

    char * endptr;
    ulong value = strtoul( buf, &endptr, 10 );
    FD_TEST( *endptr=='\n' );
    if( !strcmp( SYSCTLS[ i ], "/proc/sys/user/max_user_namespaces" ) || !strcmp( SYSCTLS[ i ], "/proc/sys/user/max_mnt_namespaces" ) ) FD_TEST( value==1UL );
    else FD_TEST( !value );
  }

  TEST_FORK_EXIT_CODE( FD_TEST( -1==unshare( CLONE_NEWNET ) ), 0 );
  TEST_FORK_EXIT_CODE( FD_TEST( -1==unshare( CLONE_NEWCGROUP ) ), 0 );
  TEST_FORK_EXIT_CODE( FD_TEST( -1==unshare( CLONE_NEWIPC ) ), 0 );
  TEST_FORK_EXIT_CODE( FD_TEST( -1==unshare( CLONE_NEWPID ) ), 0 );
  TEST_FORK_EXIT_CODE( FD_TEST( -1==unshare( CLONE_NEWUTS ) ), 0 );

  TEST_FORK_EXIT_CODE( FD_TEST( !unshare( CLONE_NEWNS ) ), 0 );
  TEST_FORK_EXIT_CODE( FD_TEST( !unshare( CLONE_NEWNS ) ), 0 );
  TEST_FORK_EXIT_CODE( do { FD_TEST( !unshare( CLONE_NEWNS ) ); FD_TEST( -1==unshare( CLONE_NEWNS ) ); } while(0), 0 );

  TEST_FORK_EXIT_CODE( do { FD_TEST( !unshare( CLONE_NEWUSER ) ); FD_TEST( -1==unshare( CLONE_NEWUSER ) ); } while(0), 0 );
  TEST_FORK_EXIT_CODE( FD_TEST( -1==unshare( CLONE_NEWUSER ) ), 0 );
}

void
test_deny_namespaces( void ) {
  TEST_FORK_EXIT_CODE( test_deny_namespaces_inner(), 0 );
}

static void
test_switch_uid_gid1( uint check_uid,
                      uint check_gid ) {
  fd_sandbox_private_switch_uid_gid( check_uid, check_gid );
  uint uid, euid, suid;
  FD_TEST( !getresuid( &uid, &euid, &suid ) );
  FD_TEST( check_uid==uid && check_uid==euid && check_uid==suid );
  uint gid, egid, sgid;
  FD_TEST( !getresgid( &gid, &egid, &sgid ) );
  FD_TEST( check_gid==gid && check_gid==egid && check_gid==sgid );
  FD_TEST( 1==prctl( PR_GET_DUMPABLE ) );
}

void
test_switch_uid_gid( void ) {
  uint uid = getuid(); uint gid = getgid();
  TEST_FORK_EXIT_CODE( test_switch_uid_gid1( 2, 2 ), 0 );
  TEST_FORK_EXIT_CODE( test_switch_uid_gid1( 3, 4 ), 0 );
  TEST_FORK_EXIT_CODE( test_switch_uid_gid1( 4, 3 ), 0 );
  TEST_FORK_EXIT_CODE( test_switch_uid_gid1( 1, 2 ), 0 );
  TEST_FORK_EXIT_CODE( test_switch_uid_gid1( 2, 1 ), 0 );
  TEST_FORK_EXIT_CODE( test_switch_uid_gid1( 1, 1 ), 0 );
  TEST_FORK_EXIT_CODE( test_switch_uid_gid1( 0, 0 ), 0 );
  TEST_FORK_EXIT_CODE( test_switch_uid_gid1( 0, 1 ), 0 );
  TEST_FORK_EXIT_CODE( test_switch_uid_gid1( 1, 0 ), 0 );
  TEST_FORK_EXIT_CODE( test_switch_uid_gid1( 6, 6 ), 0 );
  TEST_FORK_EXIT_CODE( test_switch_uid_gid1( 6, 1 ), 0 );
  TEST_FORK_EXIT_CODE( test_switch_uid_gid1( 1, 6 ), 0 );
  TEST_FORK_EXIT_CODE( test_switch_uid_gid1( uid, gid ), 0 );
}

void
test_pivot_root_inner( void ) {
  uint uid = getuid();
  uint gid = getgid();
  FD_TEST( -1!=unshare( CLONE_NEWUSER ) );
  fd_sandbox_private_write_userns_uid_gid_maps( uid, gid );

  int mnt_fd = open( "/mnt", O_RDONLY );
  FD_TEST( mnt_fd>=0 );
  FD_TEST( !close( mnt_fd ) );

  int proc_fd = open( "/proc", O_RDONLY );
  FD_TEST( proc_fd>=0 );
  FD_TEST( !close( proc_fd ) );

  fd_sandbox_private_pivot_root();

  mnt_fd = open( "/mnt", O_RDONLY );
  FD_TEST( -1==mnt_fd && errno==ENOENT );

  proc_fd = open( "/proc", O_RDONLY );
  FD_TEST( -1==proc_fd && errno==ENOENT );

  int dirfd = open( "/", O_RDONLY );
  FD_TEST( dirfd>=0 );

  for(;;) {
    uchar buf[ 4096 ];
    long dents_bytes = syscall( SYS_getdents64, dirfd, buf, sizeof( buf ) );
    if( !dents_bytes ) break;
    FD_TEST( dents_bytes>=0L );

    ulong offset = 0UL;
    while( offset<(ulong)dents_bytes ) {
      struct dirent64 const * dent = (struct dirent64 const *)(buf + offset);
      FD_TEST( !strcmp( dent->d_name, "." ) || !strcmp( dent->d_name, "..") );
      offset += dent->d_reclen;
    }
  }

  FD_TEST( !close( dirfd ) );

  char cwd[ PATH_MAX ];
  FD_TEST( getcwd( cwd, sizeof( cwd ) ) );
  FD_TEST( !strcmp( cwd, "/" ) );

  FD_TEST( !chdir( ".." ) );
  FD_TEST( getcwd( cwd, sizeof( cwd ) ) );
  FD_TEST( !strcmp( cwd, "/" ) );
}

void
test_pivot_root( void ) {
  TEST_FORK_EXIT_CODE( test_pivot_root_inner(), 0 );
}

void
test_drop_caps_inner( void ) {
  uint uid = getuid();
  uint gid = getgid();
  FD_TEST( -1!=unshare( CLONE_NEWUSER ) );
  fd_sandbox_private_write_userns_uid_gid_maps( uid, gid );

  int secbits = prctl( PR_GET_SECUREBITS );
  FD_TEST( !secbits );
  ulong cap_last_cap = 40UL;
  for( ulong i=0UL; i<=cap_last_cap; i++ ) {
    FD_TEST( prctl( PR_CAPBSET_READ, i ) );
    FD_TEST( prctl( PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, i ) );
  }

  struct __user_cap_header_struct capheader;
  capheader.version = _LINUX_CAPABILITY_VERSION_3;
  capheader.pid = 0;
  struct __user_cap_data_struct capdata[2] = { {0} };
  FD_TEST( -1!=syscall( SYS_capget, &capheader, capdata ) );
  FD_TEST( capdata[ 0 ].effective  ==0xFFFFFFFF );
  FD_TEST( capdata[ 0 ].permitted  ==0xFFFFFFFF );
  FD_TEST( capdata[ 0 ].inheritable==0 );
  FD_TEST( capdata[ 1 ].effective  ==0x000001FF );
  FD_TEST( capdata[ 1 ].permitted  ==0x000001FF );
  FD_TEST( capdata[ 1 ].inheritable==0 );

  capdata[ 0 ].inheritable = 0xFFFFFFFF;
  capdata[ 1 ].inheritable = 0x000001FF;
  FD_TEST( -1!=syscall( SYS_capset, &capheader, capdata ) );

  FD_TEST( -1!=syscall( SYS_capget, &capheader, capdata ) );
  FD_TEST( capdata[ 0 ].effective  ==0xFFFFFFFF );
  FD_TEST( capdata[ 0 ].permitted  ==0xFFFFFFFF );
  FD_TEST( capdata[ 0 ].inheritable==0xFFFFFFFF );
  FD_TEST( capdata[ 1 ].effective  ==0x000001FF );
  FD_TEST( capdata[ 1 ].permitted  ==0x000001FF );
  FD_TEST( capdata[ 1 ].inheritable==0x000001FF );

  fd_sandbox_private_drop_caps( cap_last_cap );

  secbits = prctl( PR_GET_SECUREBITS );
  FD_TEST( secbits==(SECBIT_KEEP_CAPS_LOCKED | SECBIT_NO_SETUID_FIXUP |
                     SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_NOROOT |
                     SECBIT_NOROOT_LOCKED | SECBIT_NO_CAP_AMBIENT_RAISE |
                     SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED ) );
  for( ulong i=0UL; i<=cap_last_cap; i++ ) {
    FD_TEST( !prctl( PR_CAPBSET_READ, i ) );
    FD_TEST( !prctl( PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, i, 0, 0 ) );
  }

  FD_TEST( -1!=syscall( SYS_capget, &capheader, capdata ) );
  FD_TEST( capdata[ 0 ].effective  ==0U );
  FD_TEST( capdata[ 0 ].permitted  ==0U );
  FD_TEST( capdata[ 0 ].inheritable==0U );
  FD_TEST( capdata[ 1 ].effective  ==0U );
  FD_TEST( capdata[ 1 ].permitted  ==0U );
  FD_TEST( capdata[ 1 ].inheritable==0U );
}

void
test_drop_caps( void ) {
  TEST_FORK_EXIT_CODE( test_drop_caps_inner(), 0 );
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
test_resource_limits_inner( void ) {
  uint uid = getuid();
  uint gid = getgid();
  FD_TEST( -1!=unshare( CLONE_NEWUSER ) );
  fd_sandbox_private_write_userns_uid_gid_maps( uid, gid );

  static struct rlimit_setting rlimits[] = {
    { .resource=RLIMIT_NOFILE,     .limit=0UL },
    { .resource=RLIMIT_NICE,       .limit=1UL },

    { .resource=RLIMIT_AS,         .limit=0UL },
    { .resource=RLIMIT_CORE,       .limit=0UL },
    { .resource=RLIMIT_DATA,       .limit=0UL },
    { .resource=RLIMIT_MEMLOCK,    .limit=0UL },
    { .resource=RLIMIT_MSGQUEUE,   .limit=0UL },
    { .resource=RLIMIT_NPROC,      .limit=0UL },
    { .resource=RLIMIT_RTPRIO,     .limit=0UL },
    { .resource=RLIMIT_RTTIME,     .limit=0UL },
    { .resource=RLIMIT_SIGPENDING, .limit=0UL },
    { .resource=RLIMIT_STACK,      .limit=0UL },
  };

  int dirfd = open( "/", O_RDONLY );
  FD_TEST( dirfd>=0 );
  FD_TEST( !close( dirfd ) );

  void * mem = mmap( NULL, 4096UL, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0 );
  FD_TEST( mem!=MAP_FAILED );
  FD_TEST( -1!=munmap( mem, 4096UL ) );

  void * mem2 = mmap( NULL, 4096UL, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0 );
  FD_TEST( mem2!=MAP_FAILED );
  FD_TEST( -1!=mlock( mem2, 4096UL ) );
  FD_TEST( -1!=munlock( mem2, 4096UL ) );

  TEST_FORK_EXIT_CODE( (void)0, 0 );

  fd_sandbox_private_set_rlimits( 0UL, 0UL, 0UL );

  for( ulong i=0UL; i<sizeof( rlimits )/sizeof( rlimits[ 0 ] ); i++ ) {
    struct rlimit rlim;
    FD_TEST( !getrlimit( rlimits[ i ].resource, &rlim ) );
    FD_TEST( rlim.rlim_cur==rlimits[ i ].limit );
    FD_TEST( rlim.rlim_max==rlimits[ i ].limit );
  }

  dirfd = open( "/", O_RDONLY );
  FD_TEST( dirfd==-1 && errno==EMFILE );

  mem = mmap( NULL, 4096UL, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0 );
  FD_TEST( mem==MAP_FAILED && errno==ENOMEM );

  FD_TEST( -1==mlock( mem2, 4096UL ) && errno==EPERM );
  /* If started as root, fork is always allowed, even with the rlimit */
  if( uid ) FD_TEST( -1==fork() && errno==EAGAIN );
}

void
test_resource_limits( void ) {
  TEST_FORK_EXIT_CODE( test_resource_limits_inner(), 0 );
}

#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#endif

struct landlock_ruleset_attr {
    __u64 handled_access_fs;
};

void
test_landlock_inner( void ) {
  struct landlock_ruleset_attr attr = {
    .handled_access_fs = 0, /* No access to anything. */
  };

  int landlock_fd = (int)syscall( SYS_landlock_create_ruleset, &attr, 8, 0 );
  if( FD_UNLIKELY( landlock_fd==-1 && errno==ENOSYS ) ) {
    FD_LOG_WARNING(( "Test skipped - landlock not supported" ));
    return;
  }
  FD_TEST( landlock_fd>=0 );
  FD_TEST( !close( landlock_fd ) );

  int dirfd = open( "/", O_RDONLY );
  FD_TEST( dirfd>=0 );
  FD_TEST( !close( dirfd ) );

  fd_sandbox_private_landlock_restrict_self();

  int fd = open( "/", O_RDONLY );
  FD_LOG_WARNING(( "%d %d %s", fd, errno, fd_io_strerror( errno ) ));
  FD_TEST( -1==fd && errno==EPERM );
}

void
test_landlock( void ) {
  TEST_FORK_EXIT_CODE( test_landlock_inner(), 0 );
}

void
test_read_last_cap( void ) {
  FD_TEST( fd_sandbox_private_read_cap_last_cap()==40UL );
}

void
test_seccomp( void ) {
  struct sock_filter seccomp_filter[ 128UL ];
  populate_sock_filter_policy_test_sandbox( 128UL, seccomp_filter );

#define TEST_FORK_SECCOMP_SIGNAL(child, code)                                                           \
  TEST_FORK_SIGNAL( do {                                                                                \
    FD_TEST( -1!=prctl( PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0 ) );                                            \
    fd_sandbox_private_set_seccomp_filter( (ushort) sock_filter_policy_test_sandbox_instr_cnt, seccomp_filter ); \
    child;                                                                                              \
  } while(0), code )

#define TEST_FORK_SECCOMP_EXIT_CODE(child, code)                                                        \
  TEST_FORK_EXIT_CODE( do {                                                                             \
    FD_TEST( -1!=prctl( PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0 ) );                                            \
    fd_sandbox_private_set_seccomp_filter( (ushort) sock_filter_policy_test_sandbox_instr_cnt, seccomp_filter ); \
    child;                                                                                              \
  } while(0), code )

  TEST_FORK_SECCOMP_EXIT_CODE( FD_LOG_DEBUG(( "Allowed!" )), 0 );
  TEST_FORK_SECCOMP_EXIT_CODE( fsync( 3 ), 0 );
  TEST_FORK_SECCOMP_SIGNAL( getpid(), SIGSYS );
  TEST_FORK_SECCOMP_SIGNAL( fsync( 2 ), SIGSYS );
  TEST_FORK_SECCOMP_SIGNAL( alarm( 1 ), SIGSYS );
  TEST_FORK_SECCOMP_SIGNAL( fork(), SIGSYS );
  TEST_FORK_SECCOMP_SIGNAL( kill( 0, 0 ), SIGSYS );
  TEST_FORK_SECCOMP_SIGNAL( mkdir( "/test", 0700 ), SIGSYS );
}

void
test_undumpable_inner( void ) {
  int allow_fds[] = { 0, 1, 2, 3 };
  fd_sandbox_private_enter_no_seccomp( getuid(), getgid(), 0, 0, 0UL, 0UL, 0UL, 4UL, allow_fds );
  FD_TEST( !prctl( PR_GET_DUMPABLE ) );
  FD_TEST( !prctl( PR_GET_KEEPCAPS ) );

  uid_t ruid, euid, suid;
  FD_TEST( -1!=getresuid( &ruid, &euid, &suid ) );
  FD_TEST( ruid==1 && euid==1 && suid==1 );

  gid_t rgid, egid, sgid;
  FD_TEST( -1!=getresgid( &rgid, &egid, &sgid ) );
  FD_TEST( rgid==1 && egid==1 && sgid==1 );
}

void
test_undumpable( void ) {
  TEST_FORK_EXIT_CODE( test_undumpable_inner(), 0 );
}

void
test_controlling_terminal_inner( void ) {
  int sid1 = getsid( 0 );
  FD_TEST( -1!=sid1 );
  int allow_fds[] = { 0, 1, 2, 3 };
  fd_sandbox_private_enter_no_seccomp( getuid(), getgid(), 0, 0, 0UL, 0UL, 0UL, 4UL, allow_fds );
  int sid2 = getsid( 1 );
  FD_TEST( -1!=sid2 );
  FD_TEST( sid1!=sid2 );
}

void
test_controlling_terminal( void ) {
  TEST_FORK_EXIT_CODE( test_controlling_terminal_inner(), 0 );
}

void
test_netns_inner( void ) {
  struct if_nameindex * ifs = if_nameindex();
  FD_TEST( ifs[ 1 ].if_name != NULL );

  int allow_fds[] = { 0, 1, 2, 3 };
  fd_sandbox_private_enter_no_seccomp( getuid(), getgid(), 0, 0, 0UL, 0UL, 0UL, 4UL, allow_fds );

  ifs = if_nameindex();
  FD_TEST( !ifs );
}

void
test_netns( void ) {
  TEST_FORK_EXIT_CODE( test_netns_inner(), 0 );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "Test clear environment" ));
  test_clear_environment();

  FD_LOG_NOTICE(( "Test check file descriptors" ));
  test_check_file_descriptors();

  /* There is unfortunately no way to test this without being root,
     since we wouldn't be able to map nested UIDs in the child
     namespace to unique entries in the parent without CAP_SETUID
     or CAP_SETGID. */
  FD_LOG_NOTICE(( "Test switch UID and GID" ));
  if( FD_LIKELY( !geteuid() ) ) test_switch_uid_gid();
  else FD_LOG_WARNING(( "Test skipped - must be run as root" ));

  FD_LOG_NOTICE(( "Test deny namespaces" ));
  test_deny_namespaces();

  FD_LOG_NOTICE(( "Test pivot root" ));
  test_pivot_root();

  FD_LOG_NOTICE(( "Test drop caps" ));
  test_drop_caps();

  FD_LOG_NOTICE(( "Test resource limits" ));
  test_resource_limits();

  FD_LOG_NOTICE(( "Test landlock" ));
  test_landlock();

  FD_LOG_NOTICE(( "Testing cap last cap" ));
  test_read_last_cap();

  FD_LOG_NOTICE(( "Testing seccomp" ));
  test_seccomp();

  FD_LOG_NOTICE(( "Testing undumpable" ));
  if( FD_LIKELY( !geteuid() ) ) test_undumpable();
  else FD_LOG_WARNING(( "Test skipped - must be run as root" ));

  FD_LOG_NOTICE(( "Testing netns" ));
  if( FD_LIKELY( !geteuid() ) ) test_netns();
  else FD_LOG_WARNING(( "Test skipped - must be run as root" ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
