#include "configure.h"

#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>

#define NAME "workspace-leftover"

void
fini_perm( fd_caps_ctx_t *  caps,
           config_t * const config ) {
  (void)config;
  fd_caps_check_root( caps, NAME, "check all open file descriptors in `/proc/`" );
}

static configure_result_t
check_page_size( char * name,
                 ulong  size,
                 ulong  expected ) {
  char page_path[ PATH_MAX ];
  snprintf1( page_path,
             PATH_MAX,
             "/sys/devices/system/node/node0/hugepages/hugepages-%lukB/free_hugepages",
             size );

  FILE * fp = fopen( page_path, "r" );
  if( FD_UNLIKELY( !fp ) ) FD_LOG_ERR(( "error opening `%s` (%i-%s)", page_path, errno, fd_io_strerror( errno ) ));
  ulong free_pages;
  if( FD_UNLIKELY( fscanf( fp, "%lu", &free_pages ) != 1 ) )
    FD_LOG_ERR(( "error reading `%s` (%i-%s)", page_path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( fclose( fp ) ) )
    FD_LOG_ERR(( "error closing `%s` (%i-%s)", page_path, errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( free_pages < expected ) )
    PARTIALLY_CONFIGURED( "expected at least %lu free %s pages, but there are %lu, "
                          "run `fini` to see which processes are using them",
                          expected, name, free_pages );

  CONFIGURE_OK();
}

static configure_result_t
check( config_t * const config ) {
  const char * huge     = config->shmem.huge_page_mount_path;
  const char * gigantic = config->shmem.gigantic_page_mount_path;

  struct stat st;
  int result1 = stat( huge, &st );
  if( FD_UNLIKELY( result1 && errno != ENOENT ) )
    PARTIALLY_CONFIGURED( "error reading `%s` (%i-%s)", huge, errno, fd_io_strerror( errno ) );

  int result2 = stat( gigantic, &st );
  if( FD_UNLIKELY( result2 && errno != ENOENT ) )
    PARTIALLY_CONFIGURED( "error reading `%s` (%i-%s)", gigantic, errno, fd_io_strerror( errno ) );

  /* if our mounts are present, it's OK to have used pages, we will be
     able to clean up the workspace later */
  if( FD_UNLIKELY( !result1 || !result2 ) ) CONFIGURE_OK();

  fd_topo_memory_t memory = fd_topo_memory_required_pages( config->pod );
  ulong expected[ 2 ] = { memory.huge_page_cnt, memory.gigantic_page_cnt };

  CHECK( check_page_size( "huge", 2048, expected[ 0 ] ) );
  CHECK( check_page_size( "gigantic", 1048576, expected[ 1 ] ) );

  CONFIGURE_OK();
}

static void
cmdline( char * buf,
         size_t len) {
  FILE * fp = fopen( "/proc/self/cmdline", "r" );
  if( FD_UNLIKELY( !fp ) ) FD_LOG_ERR(( "error opening `/proc/self/cmdline` (%i-%s)", errno, fd_io_strerror( errno ) ));

  ulong read = fread( buf, 1, len - 1, fp );
  if( FD_UNLIKELY( ferror( fp ) ) ) FD_LOG_ERR(( "error reading `/proc/self/cmdline` (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( fclose( fp ) ) ) FD_LOG_ERR(( "error closing `/proc/self/cmdline` (%i-%s)", errno, fd_io_strerror( errno ) ));

  buf[ read ] = '\0';
}

static void
fini( config_t * const config ) {
  DIR * dir = opendir( "/proc" );
  if( FD_UNLIKELY( !dir ) ) FD_LOG_ERR(( "error opening `/proc` (%i-%s)", errno, fd_io_strerror( errno ) ));

  struct dirent * entry;
  while(( FD_LIKELY( entry = readdir( dir ) ) )) {
    if( FD_UNLIKELY( entry->d_name[0] == '.' ) ) continue;
    char * endptr;
    ulong pid = strtoul( entry->d_name, &endptr, 10 );
    if( FD_UNLIKELY( *endptr ) ) continue;

    char path[ PATH_MAX ];
    snprintf1( path, PATH_MAX, "/proc/%lu/maps", pid );
    FILE * fp = fopen( path, "r" );
    if( FD_UNLIKELY( !fp && errno != ENOENT ) ) FD_LOG_ERR(( "error opening `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));

    char self_cmdline[ PATH_MAX ];
    cmdline( self_cmdline, PATH_MAX );

    char line[ 4096 ];
    while( FD_LIKELY( fgets( line, 4096, fp ) ) ) {
      if( FD_UNLIKELY( strlen( line ) == 4095 ) ) FD_LOG_ERR(( "line too long in `%s`", path ));
      if( FD_UNLIKELY( strstr( line, config->shmem.gigantic_page_mount_path ) ||
                       strstr( line, config->shmem.huge_page_mount_path ) ) ) {
        FD_LOG_WARNING(( "process `%lu`:`%s` has a workspace file descriptor open in `/proc/%lu/maps`", pid, self_cmdline, pid ));
        break;
      }
    }
    if( FD_UNLIKELY( ferror( fp ) ) )
      FD_LOG_ERR(( "error reading `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    if( FD_LIKELY( fclose( fp ) ) )
      FD_LOG_ERR(( "error closing `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));

    snprintf1( path, PATH_MAX, "/proc/%lu/numa_maps", pid );
    fp = fopen( path, "r" );
    if( FD_UNLIKELY( !fp ) ) FD_LOG_ERR(( "error opening `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));

    while( FD_LIKELY( fgets( line, 4096, fp ) ) ) {
      if( FD_UNLIKELY( strlen( line ) == 4095 ) ) FD_LOG_ERR(( "line too long in `%s`", path ));
      if( FD_UNLIKELY( strstr( line, "huge" ) && strstr( line, "anon" ) ) ) {
        FD_LOG_WARNING(( "process `%lu`:`%s` has anonymous hugepages leftover", pid, self_cmdline ));
        break;
      }
    }
    if( FD_UNLIKELY( ferror( fp ) ) )
      FD_LOG_ERR(( "error reading `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    if( FD_LIKELY( fclose( fp ) ) )
      FD_LOG_ERR(( "error closing `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }

  configure_result_t result = check( config );
  if( FD_UNLIKELY( result.result != CONFIGURE_OK ) )
    FD_LOG_ERR(( "not enough free huge/gigantic pages left to proceed, "
                 "see log for details of processes using them" ));

  if( FD_UNLIKELY( -1==closedir( dir ) ) ) FD_LOG_ERR(( "closedir (%i-%s)", errno, fd_io_strerror( errno ) ));
}

configure_stage_t workspace_leftover = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = NULL,
  .init_perm       = NULL,
  .fini_perm       = fini_perm,
  .init            = NULL,
  .fini            = fini,
  .check           = check,
};

#undef NAME
