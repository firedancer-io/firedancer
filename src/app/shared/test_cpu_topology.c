#define _GNU_SOURCE
#include "../../util/fd_util.h"
#include "../../util/shmem/fd_shmem_private.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/ethtool.h>
#include <linux/mempolicy.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include "commands/configure/fd_ethtool_ioctl.h"

/* Supply only the sysfs topology and ethtool responses.  The shared
   memory boot, CPU bounds, file creation, mmap and mlock are real. */
static char sysfs[128];
static int online_cnt;
static int mock_numa;
static struct ethtool_channels channels;
static struct ethtool_channels channels_set;
static DIR * scan_dir;
static int scan_error;
static int scan_step;

static char const *
sysfs_path( char const * path, char buf[256] ) {
  char const prefix[] = "/sys/devices/system/";
  if( strncmp( path, prefix, sizeof(prefix)-1UL ) ) return path;
  FD_TEST( fd_cstr_printf_check( buf, 256UL, NULL, "%s/%s", sysfs, path+sizeof(prefix)-1UL ) );
  return buf;
}

static DIR *
test_opendir( char const * path ) {
  char buf[256];
  DIR * dir = opendir( sysfs_path( path, buf ) );
  if( scan_error && !strcmp( path, "/sys/devices/system/cpu" ) ) { scan_dir=dir; scan_step=0; }
  return dir;
}

static struct dirent *
test_readdir( DIR * dir ) {
  if( dir==scan_dir ) {
    /* Fail after one low CPU ID, before the real directory entries. */
    static struct dirent first = { .d_name="cpu0" };
    if( scan_step++==0 ) return &first;
    if( scan_step==2 ) { errno=scan_error; return NULL; }
  }
  return readdir( dir );
}

static int
test_closedir( DIR * dir ) {
  if( dir==scan_dir ) scan_dir=NULL;
  return closedir( dir );
}

static int test_open( char const * path, int flags, ... ) { char buf[256]; FD_TEST( !(flags&O_CREAT) ); return open( sysfs_path( path, buf ), flags ); }
int __wrap_get_nprocs( void ) { return online_cnt; }

int
__wrap_ioctl( int fd FD_PARAM_UNUSED, ulong request FD_PARAM_UNUSED, ... ) {
  va_list ap;
  va_start( ap, request );
  struct ifreq * ifr = va_arg( ap, struct ifreq * );
  va_end( ap );
  struct ethtool_channels * ech = (struct ethtool_channels *)ifr->ifr_data;
  if( ech->cmd==ETHTOOL_GCHANNELS ) *ech = channels;
  else { FD_TEST( ech->cmd==ETHTOOL_SCHANNELS ); channels_set = *ech; }
  return 0;
}

#define opendir test_opendir
#define readdir test_readdir
#define closedir test_closedir
#define get_nprocs __wrap_get_nprocs
#define fd_numa_get_mempolicy real_get_mempolicy
#define fd_numa_set_mempolicy real_set_mempolicy
#define fd_numa_mbind real_mbind
#define fd_numa_move_pages real_move_pages
#include "../../util/shmem/fd_numa_linux.c"
#undef fd_numa_get_mempolicy
#undef fd_numa_set_mempolicy
#undef fd_numa_mbind
#undef fd_numa_move_pages
#undef opendir
#undef readdir
#undef closedir
#define open test_open
#include "commands/configure/fd_cpu_isolation.c"
#undef open
#undef get_nprocs

/* --mock-numa is for test hosts without CONFIG_NUMA.  It mocks only
   NUMA policy/query syscalls, never allocation, locking or CPU bounds.
   Without this option the complete NUMA allocation path is exercised. */
long
fd_numa_get_mempolicy( int * mode, ulong * mask, ulong maxnode, void * addr, uint flags ) {
  if( !mock_numa ) return real_get_mempolicy( mode, mask, maxnode, addr, flags );
  FD_TEST( !addr && !flags );
  *mode = MPOL_DEFAULT;
  memset( mask, 0, 8UL*((maxnode+63UL)/64UL) );
  return 0L;
}
long
fd_numa_set_mempolicy( int mode, ulong const * mask, ulong maxnode ) {
  if( !mock_numa ) return real_set_mempolicy( mode, mask, maxnode );
  FD_TEST( mode==MPOL_DEFAULT || (mode==(MPOL_BIND|MPOL_F_STATIC_NODES) && mask[0]==1UL) );
  return 0L;
}
long
fd_numa_mbind( void * addr, ulong len, int mode, ulong const * mask, ulong maxnode, uint flags ) {
  if( !mock_numa ) return real_mbind( addr, len, mode, mask, maxnode, flags );
  FD_TEST( addr && len && mode==MPOL_BIND && mask[0]==1UL );
  return 0L;
}
long
fd_numa_move_pages( int pid, ulong cnt, void ** pages, int const * nodes, int * status, int flags ) {
  if( !mock_numa ) return real_move_pages( pid, cnt, pages, nodes, status, flags );
  FD_TEST( !pid && !nodes && !flags );
  for( ulong i=0UL; i<cnt; i++ ) { FD_TEST( pages[i] ); status[i]=0; }
  return 0L;
}

static void
make_dir( char const * suffix ) {
  char path[256];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/%s", sysfs, suffix ) );
  FD_TEST( !mkdir( path, 0700 ) );
}

static void
write_file( char const * suffix, char const * value ) {
  char path[256];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/%s", sysfs, suffix ) );
  FILE * fp = fopen( path, "w" );
  FD_TEST( fp && fputs( value, fp )>=0 && !fclose( fp ) );
}

static void
set_online( char const * list ) {
  FD_CPUSET_DECL( cpus );
  FD_TEST( fd_cpu_isolation_parse_list( cpus, list ) );
  online_cnt = (int)fd_cpuset_cnt( cpus );
  write_file( "cpu/online", list );
  for( ulong i=0UL; i<48UL; i++ ) {
    char path[64];
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "cpu/cpu%lu/online", i ) );
    write_file( path, fd_cpuset_test( cpus, i ) ? "1\n" : "0\n" );
  }
}

static void
check_memory( ulong cpu ) {
  /* run.c creates tile stacks with six pages and the tile's CPU ID.
     Normal pages avoid requiring a hugepage mount for this regression. */
  ulong page_cnt = 6UL;
  FD_TEST( !fd_shmem_create_multi( "stack", FD_SHMEM_NORMAL_PAGE_SZ, 1UL, &page_cnt, &cpu, 0600UL ) );
  FD_TEST( !fd_shmem_unlink( "stack", FD_SHMEM_NORMAL_PAGE_SZ ) );
  void * mem = fd_shmem_acquire_multi( FD_SHMEM_NORMAL_PAGE_SZ, 1UL, &page_cnt, &cpu );
  FD_TEST( mem );
  memset( mem, 0xa5, page_cnt*FD_SHMEM_NORMAL_PAGE_SZ );
  FD_TEST( !fd_shmem_numa_validate( mem, FD_SHMEM_NORMAL_PAGE_SZ, page_cnt, cpu ) );
  FD_TEST( !fd_shmem_release( mem, FD_SHMEM_NORMAL_PAGE_SZ, page_cnt ) );
}

static void
check_online( char const * list ) {
  set_online( list );
  FD_TEST( fd_numa_cpu_cnt()==48UL && fd_shmem_cpu_cnt()==48UL );
  FD_CPUSET_DECL( expected );
  FD_CPUSET_DECL( host );
  FD_TEST( fd_cpu_isolation_parse_list( expected, list ) );
  fd_cpu_isolation_host_cpus( host );
  FD_TEST( fd_cpuset_eq( host, expected ) );

  static fd_topo_t topo;
  memset( &topo, 0, sizeof(topo) );
  for( ulong i=0UL; i<48UL; i++ ) if( fd_cpuset_test( host, i ) ) topo.tiles[topo.tile_cnt++].cpu_idx=i;
  FD_CPUSET_DECL( fixed );
  fd_cpu_isolation_tile_cpus( fixed, &topo );
  FD_TEST( fd_cpuset_eq( fixed, host ) );
  fd_ethtool_ioctl_t ioc = { .fd=-1 };
  fd_ethtool_ioctl_channels_t got;
  for( int combined=0; combined<2; combined++ ) {
    memset( &channels, 0, sizeof(channels) );
    channels.cmd=ETHTOOL_GCHANNELS;
    if( combined ) { channels.max_combined=128U; channels.combined_count=1U; }
    else           { channels.max_rx=128U; channels.rx_count=channels.tx_count=1U; }
    FD_TEST( !fd_ethtool_ioctl_channels_get_num( &ioc, &got ) );
    FD_TEST( got.max==(uint)online_cnt );
    FD_TEST( !fd_ethtool_ioctl_channels_set_num( &ioc, 0U ) );
    FD_TEST( (combined ? channels_set.combined_count : channels_set.rx_count)==(uint)online_cnt );
  }
}

int
main( int argc, char ** argv ) {
  mock_numa = fd_env_strip_cmdline_int( &argc, &argv, "--mock-numa", NULL, 0 );
  strcpy( sysfs, "/tmp/fd-cpu-topology-XXXXXX" );
  FD_TEST( mkdtemp( sysfs ) );
  make_dir( "node" ); make_dir( "node/node0" ); make_dir( "cpu" ); make_dir( ".normal" );
  write_file( "cpu/present", "0-47\n" );
  write_file( "cpu/possible", "0-255\n" );
  make_dir( "cpu/cpufreq" ); /* non-CPU directory must be ignored */
  for( ulong i=0UL; i<48UL; i++ ) {
    char path[64];
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "cpu/cpu%lu", i ) ); make_dir( path );
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "cpu/cpu%lu/node0", i ) ); make_dir( path );
  }
  set_online( "0-12,14-47\n" );
  FD_TEST( !setenv( "FD_SHMEM_PATH", sysfs, 1 ) );
  fd_boot( &argc, &argv );

  scan_error=EIO;
  FD_TEST( fd_numa_cpu_cnt()==0UL );
  FD_TEST( !scan_dir );
  scan_error=EINTR;
  FD_TEST( fd_numa_cpu_cnt()==48UL );
  FD_TEST( !scan_dir );
  scan_error=0;
  errno=EIO; /* A successful scan must not use a stale errno. */
  FD_TEST( fd_numa_cpu_cnt()==48UL );

  check_memory( 47UL ); /* failed with the old online-count CPU bound */
  FD_TEST( fd_shmem_numa_idx( 13UL )==0UL && fd_shmem_numa_idx( 47UL )==0UL );
  FD_TEST( fd_shmem_numa_idx( 48UL )==ULONG_MAX );
  check_online( "0-47\n" );
  check_online( "0-12,14-47\n" );
  check_online( "0-44\n" );
  check_memory( 44UL );
  check_online( "0-12,14-27,30,32-38\n" );
  FD_TEST( online_cnt==35 );
  /* Rebuild the shmem cache with the sparse 35-CPU online set, as on
     service startup after all critical SMT siblings are offlined. */
  fd_shmem_private_halt();
  fd_shmem_private_boot( &argc, &argv );
  check_memory( 37UL );
  check_memory( 38UL );

  for( ulong i=0UL; i<48UL; i++ ) {
    char path[256];
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/cpu/cpu%lu/online", sysfs, i ) ); FD_TEST( !unlink( path ) );
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/cpu/cpu%lu/node0", sysfs, i ) ); FD_TEST( !rmdir( path ) );
    FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/cpu/cpu%lu", sysfs, i ) ); FD_TEST( !rmdir( path ) );
  }
  char const * files[] = { "cpu/present", "cpu/possible", "cpu/online" };
  char const * dirs[] = { "cpu/cpufreq", "cpu", "node/node0", "node", ".normal" };
  for( ulong i=0UL; i<sizeof(files)/sizeof(files[0]); i++ ) { char path[256]; FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/%s", sysfs, files[i] ) ); FD_TEST( !unlink( path ) ); }
  for( ulong i=0UL; i<sizeof(dirs)/sizeof(dirs[0]); i++ ) { char path[256]; FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "%s/%s", sysfs, dirs[i] ) ); FD_TEST( !rmdir( path ) ); }
  FD_TEST( !rmdir( sysfs ) );
  FD_LOG_NOTICE(( "pass (NUMA policy syscalls %s)", mock_numa ? "mocked" : "real" ));
  fd_halt();
  return 0;
}
