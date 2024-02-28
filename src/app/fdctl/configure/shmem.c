#define _GNU_SOURCE
#include "configure.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>

#define NAME "shmem"

static void
init_perm( fd_caps_ctx_t *  caps,
           config_t * const config ) {
  (void)config;
  fd_caps_check_root( caps, NAME, "create directories in `/mnt`, mount hugetlbfs filesystems" );
}

static void
fini_perm( fd_caps_ctx_t *  caps,
           config_t * const config ) {
  (void)config;
  fd_caps_check_root( caps, NAME, "remove directories from `/mnt`, unmount filesystems" );
}

static ulong
read_mem_total( void ) {
  FILE * fp = fopen( "/proc/meminfo", "r" );
  if( FD_UNLIKELY( !fp ) ) FD_LOG_ERR(( "failed to open `/proc/meminfo`" ));

  ulong mem_total = 0;

  char line[ 4096 ];
  while( FD_LIKELY( fgets( line, 4096, fp ) ) ) {
    if( FD_UNLIKELY( strlen( line ) == 4095 ) ) FD_LOG_ERR(( "line too long in /proc/meminfo" ));
    if( FD_LIKELY( !strncmp( line, "MemTotal:", 9 ) ) ) {
      char * endptr;
      mem_total = strtoul( line + 9, &endptr, 10 ) << 10;
      if( FD_UNLIKELY( *endptr != ' ' || *(endptr + 1) != 'k' || *(endptr + 2) != 'B' ) )
        FD_LOG_ERR(( "failed to parse MemTotal line from `/proc/meminfo`" ));
      break;
    }
  }
  if( FD_UNLIKELY( ferror( fp ) ) )
    FD_LOG_ERR(( "error reading `/proc/meminfo` (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( fclose( fp ) ) )
    FD_LOG_ERR(( "error closing `/proc/meminfo` (%i-%s)", errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( !mem_total ) ) FD_LOG_ERR(( "failed to find MemTotal line in `/proc/meminfo`" ));
  return mem_total;
}

static void
init( config_t * const config ) {
  const char * mount_path[ 2 ] = {
    config->shmem.gigantic_page_mount_path,
    config->shmem.huge_page_mount_path,
  };
  ulong page_size[ 2 ] = { 1073741824, 2097152 };
  ulong mem_total = read_mem_total();

  try_defragment_memory();
  for( int i=0; i<2; i++ ) {
    mkdir_all( mount_path[ i ], config->uid, config->gid );
    ulong mount_size = page_size[ i ] * (mem_total / page_size[ i ] );
    char options[ 256 ];
    FD_TEST( fd_cstr_printf_check( options, sizeof(options), NULL, "pagesize=%lu,size=%lu", page_size[ i ], mount_size ) );
    if( FD_UNLIKELY( mount( "none", mount_path[ i ], "hugetlbfs", 0, options) ) )
      FD_LOG_ERR(( "mount of hugetlbfs at `%s` failed (%i-%s)", mount_path[ i ], errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( chown( mount_path[ i ], config->uid, config->gid ) ) )
      FD_LOG_ERR(( "chown of hugetlbfs at `%s` failed (%i-%s)", mount_path[ i ], errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( chmod( mount_path[ i ], S_IRUSR | S_IWUSR | S_IXUSR ) ) )
      FD_LOG_ERR(( "chmod of hugetlbfs at `%s` failed (%i-%s)", mount_path[ i ], errno, fd_io_strerror( errno ) ));
    try_defragment_memory();
  }
}

static void
fini( config_t * const config ) {
  const char * mount_path[ 2 ] = {
    config->shmem.gigantic_page_mount_path,
    config->shmem.huge_page_mount_path,
  };

  try_defragment_memory();
  for( int i=0; i<2; i++ ) {
    FILE * fp = fopen( "/proc/self/mounts", "r" );
    if( FD_UNLIKELY( !fp ) ) FD_LOG_ERR(( "failed to open `/proc/self/mounts`" ));

    char line[ 4096 ];
    while( FD_LIKELY( fgets( line, 4096, fp ) ) ) {
      if( FD_UNLIKELY( strlen( line ) == 4095 ) ) FD_LOG_ERR(( "line too long in `/proc/self/mounts`" ));
      if( FD_UNLIKELY( strstr( line, mount_path[ i ] ) ) ) {
        if( FD_UNLIKELY( umount( mount_path[ i ] ) ) )
          FD_LOG_ERR(( "umount of hugetlbfs at `%s` failed (%i-%s)", mount_path[ i ], errno, fd_io_strerror( errno ) ));
      }
    }
    if( FD_UNLIKELY( ferror( fp ) ) )
      FD_LOG_ERR(( "error reading `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_LIKELY( fclose( fp ) ) )
      FD_LOG_ERR(( "error closing `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));

    if( FD_UNLIKELY( rmdir( mount_path[i] ) && errno != ENOENT ) )
      FD_LOG_ERR(( "error removing hugetlbfs mount path at `%s` (%i-%s)", mount_path[ i ], errno, fd_io_strerror( errno ) ));
  }
  try_defragment_memory();
}

static configure_result_t
check( config_t * const config ) {
  const char * huge     = config->shmem.huge_page_mount_path;
  const char * gigantic = config->shmem.gigantic_page_mount_path;

  struct stat st;
  int result1 = stat( huge, &st );
  if( FD_UNLIKELY( result1 && errno != ENOENT ) )
    PARTIALLY_CONFIGURED( "failed to stat `%s` (%i-%s)", huge, errno, fd_io_strerror( errno ) );
  int result2 = stat( gigantic, &st );
  if( FD_UNLIKELY( result2 && errno != ENOENT ) )
    PARTIALLY_CONFIGURED( "failed to stat `%s` (%i-%s)", gigantic, errno, fd_io_strerror( errno ) );

  if( FD_UNLIKELY( result1 && result2 ) )
    NOT_CONFIGURED( "mounts `%s` and `%s` do not exist", huge, gigantic );
  else if( FD_UNLIKELY( result1 || result2 ) )
    PARTIALLY_CONFIGURED( "only one of `%s` and `%s` exists", huge, gigantic );

  const char * path[ 2 ] = { huge, gigantic };
  const char * size[ 2 ] = { "2M", "1024M" };

  for( int i=0; i<2; i++ ) {
    CHECK( check_dir( path[ i ], config->uid, config->gid, S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR ) );

    FILE * fp = fopen( "/proc/self/mounts", "r" );
    if( FD_UNLIKELY( !fp ) ) FD_LOG_ERR(( "failed to open `/proc/self/mounts`" ));

    char line[ 4096 ];
    int found = 0;
    while( FD_LIKELY( fgets( line, 4096, fp ) ) ) {
      if( FD_UNLIKELY( strlen( line ) == 4095 ) ) FD_LOG_ERR(( "line too long in `/proc/self/mounts`" ));
      if( FD_UNLIKELY( strstr( line, path[i] ) ) ) {
        found = 1;

        char * saveptr;
        char * device = strtok_r( line, " ", &saveptr );
        if( FD_UNLIKELY( !device ) ) FD_LOG_ERR(( "error parsing `/proc/self/mounts`, line `%s`", line ));
        if( FD_UNLIKELY( strcmp( device, "none" ) ) ) {
          if( FD_UNLIKELY( fclose( fp ) ) )
            FD_LOG_ERR(( "error closing `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));
          PARTIALLY_CONFIGURED( "mount `%s` is on unrecognized device, expected `none`", path[i] );
        }

        char * path1 = strtok_r( NULL, " ", &saveptr );
        if( FD_UNLIKELY( !path1 ) ) FD_LOG_ERR(( "error parsing `/proc/self/mounts`, line `%s`", line ));
        if( FD_UNLIKELY( strcmp( path1, path[i] ) ) ) {
          if( FD_UNLIKELY( fclose( fp ) ) )
            FD_LOG_ERR(( "error closing `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));
          PARTIALLY_CONFIGURED( "mount `%s` is on unrecognized path, expected `%s`", path[i], path[i] );
        }

        char * type = strtok_r( NULL, " ", &saveptr );
        if( FD_UNLIKELY( !type ) ) FD_LOG_ERR(( "error parsing `/proc/self/mounts`, line `%s`", line ));
        if( FD_UNLIKELY( strcmp( type, "hugetlbfs" ) ) ) {
          if( FD_UNLIKELY( fclose( fp ) ) )
            FD_LOG_ERR(( "error closing `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));
          PARTIALLY_CONFIGURED( "mount `%s` has unrecognized type, expected `hugetlbfs`", path[i] );
        }

        char * options = strtok_r( NULL, " ", &saveptr );
        if( FD_UNLIKELY( !options ) ) FD_LOG_ERR(( "error parsing `/proc/self/mounts`, line `%s`", line ));
        char search[ 256 ];
        FD_TEST( fd_cstr_printf_check( search, sizeof(search), NULL, "pagesize=%s", size[i] ) );
        if( FD_UNLIKELY( !strstr( options, search ) ) ) {
          if( FD_UNLIKELY( fclose( fp ) ) )
            FD_LOG_ERR(( "error closing `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));
          PARTIALLY_CONFIGURED( "mount `%s` has unrecognized pagesize, expected `%s`", path[i], search );
        }

        if( FD_UNLIKELY( !strstr( options, "rw" ) ) ) {
          if( FD_UNLIKELY( fclose( fp ) ) )
            FD_LOG_ERR(( "error closing `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));
          PARTIALLY_CONFIGURED( "mount `%s` is not mounted read/write, expected `rw`", path[i] );
        }
        break;
      }
    }

    if( FD_UNLIKELY( ferror( fp ) ) )
      FD_LOG_ERR(( "error reading `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_LIKELY( fclose( fp ) ) )
      FD_LOG_ERR(( "error closing `/proc/self/mounts` (%i-%s)", errno, fd_io_strerror( errno ) ));

    if( FD_UNLIKELY( !found ) )
      PARTIALLY_CONFIGURED( "mount `%s` not found in `/proc/self/mounts`", path[i] );
  }

  CONFIGURE_OK();
}

configure_stage_t shmem = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = NULL,
  .init_perm       = init_perm,
  .fini_perm       = fini_perm,
  .init            = init,
  .fini            = fini,
  .check           = check,
};

#undef NAME
