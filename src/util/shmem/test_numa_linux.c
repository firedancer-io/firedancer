#if !FD_HAS_HOSTED || !defined(__linux__)
#error "This unit test requires FD_HAS_HOSTED and Linux"
#endif

/* test_numa_linux creates a sandbox mocking sysfs to ensure NUMA
   detection works correctly on kernels with and without NUMA. */

#define _GNU_SOURCE
#include <unistd.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "../fd_util.h"
#include "fd_shmem_private.h"

/* Helper function to write a uid/gid mapping file */
static inline void
map_id( char const * file, uint to ) {
  FILE * fp;
  FD_TEST( fp = fopen( file, "w" ) );
  int nprint = fprintf( fp, "0 %u 1", to );
  FD_TEST( nprint>0 );
  FD_TEST( fclose( fp )==0 );
}

/* Test enumeration for a typical Linux host with NUMA support */

void
test_numa_linux_typical( void ) {
  /* Create mock sysfs */
  FD_TEST( 0==mkdir( "/sys",                                   0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices",                           0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices/system",                    0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices/system/node",               0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices/system/node/node0",         0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices/system/node/node1",         0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices/system/cpu",                0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices/system/cpu/cpu0",           0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices/system/cpu/cpu0/node0",     0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices/system/cpu/cpu1",           0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices/system/cpu/cpu1/node1",     0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices/system/cpu/cpu2",           0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices/system/cpu/cpu2/node0",     0755 ) );

  /* Tests */
  FD_TEST( fd_numa_node_cnt()==2UL );
  FD_TEST( fd_numa_node_idx( 0UL )==0UL );
  FD_TEST( fd_numa_node_idx( 1UL )==1UL );
  FD_TEST( fd_numa_node_idx( 2UL )==0UL );

  /* Clean up */
  FD_TEST( 0==rmdir( "/sys/devices/system/cpu/cpu2/node0"           ) );
  FD_TEST( 0==rmdir( "/sys/devices/system/cpu/cpu2"                 ) );
  FD_TEST( 0==rmdir( "/sys/devices/system/cpu/cpu1/node1"           ) );
  FD_TEST( 0==rmdir( "/sys/devices/system/cpu/cpu1"                 ) );
  FD_TEST( 0==rmdir( "/sys/devices/system/cpu/cpu0/node0"           ) );
  FD_TEST( 0==rmdir( "/sys/devices/system/cpu/cpu0"                 ) );
  FD_TEST( 0==rmdir( "/sys/devices/system/cpu"                      ) );
  FD_TEST( 0==rmdir( "/sys/devices/system/node/node1"               ) );
  FD_TEST( 0==rmdir( "/sys/devices/system/node/node0"               ) );
  FD_TEST( 0==rmdir( "/sys/devices/system/node"                     ) );
  FD_TEST( 0==rmdir( "/sys/devices/system"                          ) );
  FD_TEST( 0==rmdir( "/sys/devices"                                 ) );
  FD_TEST( 0==rmdir( "/sys"                                         ) );

  FD_LOG_NOTICE(( "pass NUMA typical" ));
}

/* Test enumeration for a Linux kernel without NUMA support */

void
test_numa_linux_disabled( void ) {
  /* Create mock sysfs */
  FD_TEST( 0==mkdir( "/sys",                                   0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices",                           0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices/system",                    0755 ) );
  /* /sys/devices/system/node is absent */
  FD_TEST( 0==mkdir( "/sys/devices/system/cpu",                0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices/system/cpu/cpu0",           0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices/system/cpu/cpu1",           0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices/system/cpu/cpu2",           0755 ) );

  /* Tests */
  FD_TEST( fd_numa_node_cnt()==1UL );
  FD_TEST( fd_numa_node_idx( 0UL )==0UL );
  FD_TEST( fd_numa_node_idx( 1UL )==0UL );
  FD_TEST( fd_numa_node_idx( 2UL )==0UL );

  /* Clean up */
  FD_TEST( 0==rmdir( "/sys/devices/system/cpu/cpu2"                 ) );
  FD_TEST( 0==rmdir( "/sys/devices/system/cpu/cpu1"                 ) );
  FD_TEST( 0==rmdir( "/sys/devices/system/cpu/cpu0"                 ) );
  FD_TEST( 0==rmdir( "/sys/devices/system/cpu"                      ) );
  FD_TEST( 0==rmdir( "/sys/devices/system"                          ) );
  FD_TEST( 0==rmdir( "/sys/devices"                                 ) );
  FD_TEST( 0==rmdir( "/sys"                                         ) );

  FD_LOG_NOTICE(( "pass NUMA disabled" ));
}

/* test_numa_linux tests sysfs handling code.

   This test
     - enters separate user and filesystem namespaces
     - pretends to be root
     - enters a new chroot
     - creates a fake /sysfs

   This does not require any special capabilities.
   However, the kernel needs to support user namespaces. */
void
test_numa_linux( void ) {
  /* Pivot to temporary dir */

  char pivot[17];
  fd_memcpy( pivot, "/tmp/pivotXXXXXX", 17 );
  FD_TEST( mkdtemp( pivot ) );
  FD_TEST( 0==chdir( pivot ) );

  char oldroot[25];
  fd_memcpy( oldroot,    pivot,      16 );
  fd_memcpy( oldroot+16, "/oldroot",  9 );
  FD_TEST( 0==mkdir( oldroot, 0755 ) );

  /* Get original effective user IDs */
  uid_t uid = geteuid();
  gid_t gid = getegid();

  /* Unshare namespaces */
  FD_TEST( 0==unshare( CLONE_NEWUSER|CLONE_NEWNS ) );

  /* Map current user to (fake) root */
  FILE * fp;
  FD_TEST( fp = fopen( "/proc/self/setgroups", "w" ) );
  FD_TEST( 0< fputs( "deny", fp ) );
  FD_TEST( 0==fclose( fp )        );

  map_id( "/proc/self/uid_map", uid );
  map_id( "/proc/self/gid_map", gid );

  /* Unshare mount namespace */
  FD_TEST( 0==mount( "none", "/",  NULL,   MS_REC|MS_PRIVATE, NULL ) );
  FD_TEST( 0==mount( pivot, pivot, "none", MS_BIND,           NULL ) );

  /* Pivot to root where /sysfs does not exist */
  FD_TEST( 0==syscall( SYS_pivot_root, pivot, oldroot ) );
  FD_TEST( 0==chdir( "/" ) );

  /* Run tests */
  test_numa_linux_typical();
  test_numa_linux_disabled();

  /* Undo pivot */
  FD_TEST( 0==syscall( SYS_pivot_root, "/oldroot", "/oldroot" ) );
  FD_TEST( 0==chdir("/") );

  /* Cleanup */
  FD_TEST( 0==rmdir( oldroot ) );
  FD_TEST( 0==rmdir( pivot   ) );

  /* Abnormal exit */
  exit( 0 );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Create sandboxed child process to run tests in */

  pid_t pid;
  FD_TEST( (pid = fork()) >= 0 );
  if( pid==0 ) {
    test_numa_linux();
  } else {
    int status;
    pid = waitpid( pid, &status, 0 );
    FD_TEST( pid>=0                   );
    FD_TEST( WIFEXITED( status )      );
    FD_TEST( WEXITSTATUS( status )==0 );
  }

  fd_halt();
  return 0;
}
