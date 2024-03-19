#define _GNU_SOURCE
#include "../../fdctl/configure/configure.h"

#include <stdio.h>
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

#define NAME "kill"

static void
init_perm( fd_caps_ctx_t *  caps,
           config_t * const config ) {
  (void)config;
  fd_caps_check_root( caps, NAME, "check all open file descriptors in `/proc/`" );
}

static void
cmdline( char * buf,
         size_t len,
         ulong  pid ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/proc/%lu/cmdline", pid ) );

  FILE * fp = fopen( path, "r" );
  if( FD_UNLIKELY( !fp && errno==ENOENT ) ) {
    buf[ 0 ] = '\0';
    return;
  }
  if( FD_UNLIKELY( !fp ) ) FD_LOG_ERR(( "error opening `/proc/%lu/cmdline` (%i-%s)", pid, errno, fd_io_strerror( errno ) ));

  ulong read = fread( buf, 1, len - 1, fp );
  if( FD_UNLIKELY( ferror( fp ) ) ) FD_LOG_ERR(( "error reading `/proc/%lu/cmdline` (%i-%s)", pid, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( fclose( fp ) ) ) FD_LOG_ERR(( "error closing `/proc/%lu/cmdline` (%i-%s)", pid, errno, fd_io_strerror( errno ) ));

  buf[ read ] = '\0';
}

static int
maybe_kill( config_t * const config,
            ulong            pid ) {
  int killed = 0;

  char proc_cmdline[ PATH_MAX ];
  cmdline( proc_cmdline, PATH_MAX, pid );

  ulong cmdline_len = strlen( proc_cmdline );
  if( FD_LIKELY( cmdline_len>=5UL ) ) {
    if( FD_UNLIKELY( !strcmp( proc_cmdline + (cmdline_len-5), "fddev" ) ) ) {
      killed = 1;
      FD_LOG_NOTICE(( "killing process `%s` (%lu): is fddev", proc_cmdline, pid ));
      if( FD_UNLIKELY( -1==kill( (int)pid, SIGKILL ) && errno!=ESRCH ) ) FD_LOG_ERR(( "kill failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    } else if( FD_UNLIKELY( !strcmp( proc_cmdline + (cmdline_len-5), "fdctl" ) ) ) {
      killed = 1;
      FD_LOG_NOTICE(( "killing process `%s` (%lu): is fdctl", proc_cmdline, pid ));
      if( FD_UNLIKELY( -1==kill( (int)pid, SIGKILL ) && errno!=ESRCH ) ) FD_LOG_ERR(( "kill failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
  }

  if( FD_UNLIKELY( killed ) ) return killed;

  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/proc/%lu/maps", pid ) );
  FILE * fp = fopen( path, "r" );
  if( FD_UNLIKELY( !fp && errno==ENOENT ) ) return 0;
  else if( FD_UNLIKELY( !fp ) ) FD_LOG_ERR(( "error opening `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  char line[ 4096 ];
  while( FD_LIKELY( fgets( line, 4096, fp ) ) ) {
    if( FD_UNLIKELY( strlen( line ) == 4095 ) ) FD_LOG_ERR(( "line too long in `%s`", path ));
    if( FD_UNLIKELY( strstr( line, config->hugetlbfs.gigantic_page_mount_path ) ||
                      strstr( line, config->hugetlbfs.huge_page_mount_path ) ) ) {
      killed = 1;
      FD_LOG_NOTICE(( "killing process `%s` (%lu): has a workspace file descriptor open", proc_cmdline, pid ));
      if( FD_UNLIKELY( -1==kill( (int)pid, SIGKILL ) && errno!=ESRCH ) ) FD_LOG_ERR(( "kill failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      break;
    }
  }
  if( FD_UNLIKELY( ferror( fp ) ) )
    FD_LOG_ERR(( "error reading `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( fclose( fp ) ) )
    FD_LOG_ERR(( "error closing `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( killed ) ) return killed;

  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/proc/%lu/numa_maps", pid ) );
  fp = fopen( path, "r" );
  if( FD_UNLIKELY( !fp ) ) FD_LOG_ERR(( "error opening `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  while( FD_LIKELY( fgets( line, 4096, fp ) ) ) {
    if( FD_UNLIKELY( strlen( line ) == 4095 ) ) FD_LOG_ERR(( "line too long in `%s`", path ));
    if( FD_UNLIKELY( strstr( line, "huge" ) && strstr( line, "anon" ) ) ) {
      killed = 1;
      FD_LOG_NOTICE(( "killing process `%s` (%lu): has anonymous hugepages mapped", proc_cmdline, pid ));
      if( FD_UNLIKELY( -1==kill( (int)pid, SIGKILL ) && errno!=ESRCH ) ) FD_LOG_ERR(( "kill failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      break;
    }
  }
  if( FD_UNLIKELY( ferror( fp ) ) )
    FD_LOG_ERR(( "error reading `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( fclose( fp ) ) )
    FD_LOG_ERR(( "error closing `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  return killed;
}

static void
wait_dead( long  started,
           ulong pid ) {
  /* We need to do this to prevent a race condition, since kill(SIGKILL) returns
     before the kernel actually terminates and reclaims the resources from the
     process. */
  while( 1 ) {
    int err = kill( (int)pid, 0 );
    if( FD_LIKELY( err==-1 && errno==ESRCH) ) return;
    else if( FD_LIKELY( err==-1 ) ) FD_LOG_ERR(( "kill failed (%i-%s)", errno, fd_io_strerror( errno ) ));

    if( FD_UNLIKELY( fd_log_wallclock() - started >= (long)1e9 ) )
      FD_LOG_ERR(( "waited too long for process to exit" ));
  }
}

static void
init( config_t * const config ) {
  DIR * dir = opendir( "/proc" );
  if( FD_UNLIKELY( !dir ) ) FD_LOG_ERR(( "error opening `/proc` (%i-%s)", errno, fd_io_strerror( errno ) ));

  ulong wait_killed_cnt = 0UL;
  ulong wait_killed[ 1024 ] = { 0 };

  struct dirent * entry;
  while(( FD_LIKELY( entry = readdir( dir ) ) )) {
    if( FD_UNLIKELY( entry->d_name[0] == '.' ) ) continue;
    char * endptr;
    ulong pid = strtoul( entry->d_name, &endptr, 10 );
    if( FD_UNLIKELY( *endptr || pid==(ulong)getpid() ) ) continue;

    int killed = maybe_kill( config, pid );
    if( FD_UNLIKELY( killed ) ) {
      if( FD_UNLIKELY( wait_killed_cnt==sizeof(wait_killed) ) ) FD_LOG_ERR(( "too many processes to kill" ));
      wait_killed[ wait_killed_cnt ] = pid;
    }
  }

  if( FD_UNLIKELY( -1==closedir( dir ) ) ) FD_LOG_ERR(( "closedir (%i-%s)", errno, fd_io_strerror( errno ) ));

  long started = fd_log_wallclock();
  for( ulong i=0; i<wait_killed_cnt; i++ ) wait_dead( started, wait_killed[ i ] );
}

static configure_result_t
check( config_t * const config ) {
  (void)config;

  PARTIALLY_CONFIGURED( "kill existing instances" );
}

configure_stage_t _kill = {
  .name            = NAME,
  .always_recreate = 1,
  .enabled         = NULL,
  .init_perm       = init_perm,
  .fini_perm       = NULL,
  .init            = init,
  .fini            = NULL,
  .check           = check,
};

#undef NAME
