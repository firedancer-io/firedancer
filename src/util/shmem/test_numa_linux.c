#ifndef SOURCE_fd_src_util_shmem_test_numa
#error "Do not compile this file directly"
#endif

#include <unistd.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "fd_shmem_private.h"

void
test_numa_syscalls( void ) {
  ulong nodemask[ 8 ] = {0};
  ulong const maxnode = sizeof(nodemask)*8UL;

  long res = get_mempolicy( NULL, nodemask, maxnode, NULL, 0 );
  FD_TEST( res==0L );
}

static inline void
map_id( char const * file, uint to ) {
  FILE * fp;
  FD_TEST( fp = fopen( file, "w" ) );
  int nprint = fprintf( fp, "0 %u 1", to );
  FD_TEST( nprint>0 );
  FD_TEST( fclose( fp )==0 );
}

/* test_numa_sysfs_error_handling_inner tests sysfs handling code,
   specifically error paths.

   This test
     - enters separate user and filesystem namespaces
     - pretends to be root
     - enters a new chroot
     - creates a fake /sysfs

   This does not require any special capabilities.
   However, the kernel needs to support user namespaces. */
void
test_numa_sysfs_error_handling_inner( void ) {
  /* Prepare pivot directories */
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

  /* Map current user to root */
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

  /* Accesses to sysfs should fail */
  FD_TEST( fd_shmem_numa_cnt_private()==-ENOENT );

  /* Create weird sysfs */
  FD_TEST( 0==mkdir( "/sys",                                   0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices",                           0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices/system",                    0755 ) );

  FD_TEST( 0==mkdir( "/sys/devices/system/node",               0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices/system/node/nodeBLA",       0755 ) );
  FD_TEST( fd_shmem_numa_cnt_private()==0 );
  FD_TEST( 0==rmdir( "/sys/devices/system/node/nodeBLA"             ) );
  FD_TEST( 0==rmdir( "/sys/devices/system/node"                     ) );

  FD_TEST( 0==mkdir( "/sys/devices/system/cpu",                0755 ) );

  FD_TEST( 0==mkdir( "/sys/devices/system/cpu/cpu1",           0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices/system/cpu/cpu1/nodeBLA",   0755 ) );
  FD_TEST( fd_numa_node_of_cpu( 1 )==-ENOENT );
  FD_TEST( 0==rmdir( "/sys/devices/system/cpu/cpu1/nodeBLA"         ) );
  FD_TEST( 0==rmdir( "/sys/devices/system/cpu/cpu1"                 ) );

  FD_TEST( 0==mkdir( "/sys/devices/system/cpu/cpu2147483647",       0755 ) );
  FD_TEST( 0==mkdir( "/sys/devices/system/cpu/cpu2147483647/node2", 0755 ) );
  FD_TEST( fd_numa_node_of_cpu( INT_MAX )==2 );
  FD_TEST( 0==rmdir( "/sys/devices/system/cpu/cpu2147483647/node2"  ) );
  FD_TEST( 0==rmdir( "/sys/devices/system/cpu/cpu2147483647"        ) );

  FD_TEST( 0==rmdir( "/sys/devices/system/cpu"                      ) );

  FD_TEST( 0==rmdir( "/sys/devices/system"                          ) );
  FD_TEST( 0==rmdir( "/sys/devices"                                 ) );
  FD_TEST( 0==rmdir( "/sys"                                         ) );

  /* Undo pivot */
  FD_TEST( 0==syscall( SYS_pivot_root, "/oldroot", "/oldroot" ) );
  FD_TEST( 0==chdir("/") );

  /* Cleanup */
  FD_TEST( 0==rmdir( oldroot ) );
  FD_TEST( 0==rmdir( pivot   ) );

  FD_LOG_NOTICE(( "pass sysfs error handling" ));

  /* Abnormal exit */
  exit( 0 );
}

void
test_numa_sys_error_handling( void ) {
  /* Spawn test in separate process */
  pid_t pid;
  FD_TEST( (pid = fork()) >= 0 );
  if( pid==0 ) {
    test_numa_sysfs_error_handling_inner();
  } else {
    int status;
    pid = waitpid( pid, &status, 0 );
    FD_TEST( pid>=0                   );
    FD_TEST( WIFEXITED( status )      );
    FD_TEST( WEXITSTATUS( status )==0 );
  }
}

void
test_numa_linux( void ) {
  test_numa_syscalls();

  test_numa_sys_error_handling();
}
