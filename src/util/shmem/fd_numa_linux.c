#ifndef SOURCE_fd_src_util_shmem_fd_shmem_admin
#error "Do not compile this file directly"
#endif

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>

#include "../fd_util_base.h"
#include "../cstr/fd_cstr.h"

/* Syscall wrappers are defined as weak symbols to allow
   instrumentation like strace, ASan to override them. */

__attribute__((weak)) long
get_mempolicy( int *   mode,
               ulong * nodemask,
               ulong   maxnode,
               void *  addr,
               uint    flags ) {
  return syscall( SYS_get_mempolicy,
                  mode, nodemask, maxnode, addr, flags );
}

__attribute__((weak)) long
set_mempolicy( int           mode,
               ulong const * nodemask,
               ulong         maxnode ) {
  return syscall( SYS_set_mempolicy,
                  mode, nodemask, maxnode );
}

__attribute__((weak)) long
mbind( void *        addr,
       ulong         len,
       int           mode,
       ulong const * nodemask,
       ulong         maxnode,
       uint          flags ) {
  return syscall( SYS_mbind,
                  addr, len, mode, nodemask, maxnode, flags );
}

__attribute__((weak)) long
move_pages( int         pid,
            ulong       count,
            void **     pages,
            int const * nodes,
            int *       status,
            int         flags ) {
  return syscall( SYS_move_pages,
                  pid, count, pages, nodes, status, flags );
}

int
fd_numa_available( void ) {
  long res = get_mempolicy( NULL, NULL, 0, NULL, 0 );
  return res == 0;
}

/* cstr_is_base10: returns 1 if cstr matches `[0-9]+`, else 0. */
static inline int
cstr_is_base10( char const * s ) {
  if( FD_UNLIKELY( *s == '\0' )) return 0;
  do {
    if( FD_UNLIKELY( *s < '0' || *s > '9' ) )
      return 0;
  } while( FD_UNLIKELY( *(++s) ) );
  return 1;
}

/* sysfs_node_idx: parses cstr `node%d` and returns %d, else -1.
   May return negative integers for  */
static inline int
sysfs_node_idx( char const * s ) {
  if( strncmp( s, "node", 4 ) ) return -1;
  s += 4;

  if( FD_UNLIKELY( !cstr_is_base10( s ) ) ) return -1;

  return fd_cstr_to_int( s );
}

int
fd_shmem_numa_cnt_private( void ) {
  DIR * d = opendir( "/sys/devices/system/node" );
  if( FD_UNLIKELY( !d ) ) return -errno;

  int node_cnt = 0;
  struct dirent * ent;
  while( (ent = readdir( d ))!=NULL ) {
    if( sysfs_node_idx( ent->d_name )>=0 )
      node_cnt++;
  }
  closedir( d );

  return node_cnt;
}

int
fd_shmem_cpu_cnt_private( void ) {
  return get_nprocs();
}

int
fd_numa_cpu_max_cnt( void ) {
  return get_nprocs_conf();
}

int
fd_numa_node_of_cpu( int cpu_idx ) {
  /* Uses sysfs API added ~2009-Dec
     See https://github.com/torvalds/linux/commit/1830794ae6392ce12d36dbcc5ff52f11298ddab6 */

  /* Find sysfs dir containing CPU config */
  char node_path[38];
  fd_cstr_printf( node_path, sizeof(node_path), NULL,
                  "/sys/devices/system/cpu/cpu%d", cpu_idx );

  /* Open dir and scan for symlinks */
  DIR * d = opendir( node_path );
  if( FD_UNLIKELY( !d ) ) return -errno;

  /* Scan for a node%d symlink */
  int node_idx = -ENOENT;
  struct dirent * ent;
  while( (ent = readdir( d ))!=NULL ) {
    int i = sysfs_node_idx( ent->d_name );
    if( i>=0 ) {
      node_idx = i;
      break;
    }
  }
  closedir( d );

  return node_idx;
}
