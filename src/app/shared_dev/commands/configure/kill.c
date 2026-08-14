#define _GNU_SOURCE
#include "../../../shared/commands/configure/configure.h"

#include <errno.h>
#include <stdlib.h> /* strtoul */
#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>

#define NAME "kill"

static void
init_perm( fd_cap_chk_t *   chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "check all open file descriptors in `/proc/`" );
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

/* hugetlb_kib returns the process's HugetlbPages: usage from
   /proc/<pid>/status (cheap counter read, no page table walk), or
   ULONG_MAX if the field is missing.  Both hugetlbfs file mappings
   (workspaces) and anonymous MAP_HUGETLB pages count toward it, so a
   zero here proves the expensive maps/numa_maps scans can be
   skipped. */

static ulong
hugetlb_kib( ulong pid ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/proc/%lu/status", pid ) );

  int fd = open( path, O_RDONLY|O_CLOEXEC );
  if( FD_UNLIKELY( -1==fd && errno==ENOENT ) ) return 0UL;
  if( FD_UNLIKELY( -1==fd ) ) FD_LOG_ERR(( "error opening `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  /* status is small (~1.5 KiB); one read gets it all */
  char buf[ 4096 ];
  long sz;
  do {
    sz = read( fd, buf, sizeof(buf)-1UL );
  }while( FD_UNLIKELY( -1L==sz && errno==EINTR ) );
  if( FD_UNLIKELY( sz<0L ) ) FD_LOG_ERR(( "error reading `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==close( fd ) ) ) FD_LOG_ERR(( "error closing `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  buf[ sz ] = '\0';

  char const * line = strstr( buf, "\nHugetlbPages:" );
  if( FD_UNLIKELY( !line ) ) return ULONG_MAX;
  return strtoul( line+14UL, NULL, 10 );
}

/* proc_start_time reads /proc/<pid>/stat field 22 (starttime, clock
   ticks since boot), 0 if the process is gone.  (pid, starttime)
   uniquely identifies a process; pids alone recycle.  stat is world
   readable except under hidepid, where a 0 would silently skip the
   process; fail loudly instead (like every other /proc error here).
   The comm field can contain spaces and parens, so parse from the
   last ')'. */

static ulong
proc_start_time( ulong pid ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/proc/%lu/stat", pid ) );

  char buf[ 4096 ];
  int fd = open( path, O_RDONLY|O_CLOEXEC );
  if( FD_UNLIKELY( -1==fd && (errno==EACCES || errno==EPERM) ) )
    FD_LOG_ERR(( "error opening `%s` (%i-%s); /proc is restricted (hidepid?), run as root", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==fd ) ) return 0UL;
  long sz;
  do sz = read( fd, buf, sizeof(buf)-1UL ); while( FD_UNLIKELY( -1L==sz && errno==EINTR ) );
  if( FD_UNLIKELY( -1==close( fd ) ) ) FD_LOG_ERR(( "error closing `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( sz<=0L ) ) return 0UL;
  buf[ sz ] = '\0';

  char * p = strrchr( buf, ')' );
  if( FD_UNLIKELY( !p ) ) return 0UL;

  ulong start_time = 0UL;
  if( FD_UNLIKELY( 1!=sscanf( p+1UL, " %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %lu", &start_time ) ) ) return 0UL;
  return start_time;
}

#define KILL_NO                ( 0)
#define KILL_IS_FDDEV          (-1)
#define KILL_IS_FDCTL          (-2)
#define KILL_IS_FIREDANCER     (-3)
#define KILL_IS_FIREDANCER_DEV (-4)
#define KILL_HAS_WORKSPACE_FD  (-5)
#define KILL_HAS_HUGEPAGES     (-6)
#define KILL_CANT_INSPECT      (-7) /* check ran unprivileged; init (as root) decides */

static char const *
kill_reason( int err ) {
  switch( err ) {
    case KILL_IS_FDDEV:          return "is fddev";
    case KILL_IS_FDCTL:          return "is fdctl";
    case KILL_IS_FIREDANCER:     return "is firedancer";
    case KILL_IS_FIREDANCER_DEV: return "is firedancer-dev";
    case KILL_HAS_WORKSPACE_FD:  return "has a workspace file descriptor open";
    case KILL_HAS_HUGEPAGES:     return "has anonymous hugepages mapped";
    case KILL_CANT_INSPECT:      return "cannot be inspected without root";
    default: FD_LOG_ERR(( "unexpected error code" ));
  }
}

static int
check_binary( ulong pid ) {
  /* Match the executable name via one readlink rather than reading
     /proc/<pid>/cmdline for every process. */
  char exe_path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( exe_path, PATH_MAX, NULL, "/proc/%lu/exe", pid ) );
  char exe[ PATH_MAX ];
  long exe_len = readlink( exe_path, exe, PATH_MAX-1UL );
  if( FD_UNLIKELY( exe_len<0L && errno==EACCES ) ) {
    /* Unprivileged check of another user's process: exe is protected
       but cmdline is world-readable; match its suffix like the
       historical scan. */
    char proc_cmdline[ PATH_MAX ];
    cmdline( proc_cmdline, PATH_MAX, pid );
    ulong cmdline_len = strlen( proc_cmdline );
    exe_len = (long)fd_ulong_min( cmdline_len, PATH_MAX-1UL );
    fd_memcpy( exe, proc_cmdline, (ulong)exe_len );
  } else if( FD_UNLIKELY( exe_len<0L ) ) {
    return KILL_NO; /* kernel thread or gone */
  }
  exe[ exe_len ] = '\0';
  /* An overwritten binary reads "/path/binary (deleted)" */
  if( FD_UNLIKELY( exe_len>=10L && !strcmp( exe+exe_len-10L, " (deleted)" ) ) ) exe[ exe_len-10L ] = '\0';
  char const * base = strrchr( exe, '/' );
  base = base ? base+1UL : exe;

  static char const * binaries[] = { "fddev",       "fdctl",       "firedancer",       "firedancer-dev"       };
  static int const    errors[]   = { KILL_IS_FDDEV, KILL_IS_FDCTL, KILL_IS_FIREDANCER, KILL_IS_FIREDANCER_DEV };
  for( ulong i=0UL; i<sizeof(binaries)/sizeof(binaries[0]); i++ ) {
    if( FD_UNLIKELY( !strcmp( base, binaries[ i ] ) ) ) return errors[ i ];
  }
  return KILL_NO;
}

static int
check_hugepages( config_t const * config,
                 ulong            pid ) {
  /* No hugetlb usage -> cannot hold a workspace mapping or anonymous
     hugepages, skip the expensive maps scan. */
  if( FD_LIKELY( !hugetlb_kib( pid ) ) ) return KILL_NO;

  int result = KILL_NO;

  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/proc/%lu/maps", pid ) );
  FILE * fp = fopen( path, "r" );
  if( FD_UNLIKELY( !fp && errno==ENOENT ) ) return KILL_NO;
  else if( FD_UNLIKELY( !fp && errno==EACCES ) ) return KILL_CANT_INSPECT; /* unprivileged check; hugetlb user needs root inspection */
  else if( FD_UNLIKELY( !fp ) ) FD_LOG_ERR(( "error opening `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  int maybe_huge = 0;
  char line[ 4096 ];
  while( FD_LIKELY( fgets( line, 4096, fp ) ) ) {
    if( FD_UNLIKELY( strlen( line ) == 4095 ) ) FD_LOG_ERR(( "line too long in `%s`", path ));
    if( FD_UNLIKELY( strstr( line, config->hugetlbfs.gigantic_page_mount_path ) ||
                      strstr( line, config->hugetlbfs.huge_page_mount_path ) ) ) {
      result = KILL_HAS_WORKSPACE_FD;
      break;
    }

    if( FD_UNLIKELY( strstr( line, "anon_hugepage" ) || strstr( line, "memfd:" ) ) ) maybe_huge = 1;
  }
  if( FD_UNLIKELY( ferror( fp ) ) )
    FD_LOG_ERR(( "error reading `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( fclose( fp ) ) )
    FD_LOG_ERR(( "error closing `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( result ) ) return result;

  /* No hugepage mappings in maps -> cannot have anonymous hugepages, so
     skip the expensive numa_maps read entirely. */
  if( FD_LIKELY( !maybe_huge ) ) return KILL_NO;

  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/proc/%lu/numa_maps", pid ) );
  fp = fopen( path, "r" );
  if( FD_UNLIKELY( !fp && errno==ENOENT ) ) return KILL_NO;
  else if( FD_UNLIKELY( !fp ) ) FD_LOG_ERR(( "error opening `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  while( FD_LIKELY( fgets( line, 4096, fp ) ) ) {
    if( FD_UNLIKELY( strlen( line ) == 4095 ) ) FD_LOG_ERR(( "line too long in `%s`", path ));
    if( FD_UNLIKELY( strstr( line, "huge" ) && strstr( line, "anon" ) ) ) {
      result = KILL_HAS_HUGEPAGES;
      break;
    }
  }
  if( FD_UNLIKELY( ferror( fp ) ) )
    FD_LOG_ERR(( "error reading `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_LIKELY( fclose( fp ) ) )
    FD_LOG_ERR(( "error closing `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  return result;
}

static int
check_kill( config_t const * config,
            ulong            pid ) {
  int err = check_binary( pid );
  if( FD_UNLIKELY( err ) ) return err;
  return check_hugepages( config, pid );
}

static void
wait_dead( long  started,
           ulong pid,
           ulong start_time ) {
  /* We need to do this to prevent a race condition, since kill(SIGKILL) returns
     before the kernel actually terminates and reclaims the resources from the
     process.  A task blocked in an uninterruptible syscall (e.g. an
     fsync queued behind heavy writeback) does not die until the
     syscall completes, which can take seconds. */
  int notified = 0;
  while( 1 ) {
    /* starttime mismatch means the pid was recycled: ours is dead */
    if( FD_LIKELY( proc_start_time( pid )!=start_time ) ) return;

    long waited = fd_log_wallclock() - started;
    if( FD_UNLIKELY( waited>=(long)1e9 && !notified ) ) {
      FD_LOG_WARNING(( "waiting for killed process to exit %s(blocked in uninterruptible disk I/O)%s", fd_log_style_dim(), fd_log_style_normal() ));
      notified = 1;
    }
    if( FD_UNLIKELY( waited >= (long)5e9 ) ) FD_LOG_ERR(( "waited too long for process to exit" ));
  }
}

#define SCAN_THREADS  (16UL)
#define SCAN_PIDS_MAX (65536UL)
#define MATCHED_MAX   (1024UL)

struct kill_scan {
  config_t const * config;
  ulong const *    pids;
  ulong            pid_cnt;
  ulong            idx;      /* this worker's stride offset */
  ulong            matched      [ MATCHED_MAX ];
  ulong            matched_start[ MATCHED_MAX ];
  int              match_err    [ MATCHED_MAX ];
  ulong            matched_cnt;
};

static void *
kill_scan_thread( void * arg ) {
  struct kill_scan * scan = arg;
  for( ulong i=scan->idx; i<scan->pid_cnt; i+=SCAN_THREADS ) {
    /* Bind identity before inspecting: (pid, starttime) is unique,
       pids recycle.  0 (gone) drops the match, sidestepping reuse. */
    ulong start_time = proc_start_time( scan->pids[ i ] );
    if( FD_UNLIKELY( !start_time ) ) continue;
    int err = check_kill( scan->config, scan->pids[ i ] );
    if( FD_UNLIKELY( err ) ) {
      if( FD_UNLIKELY( scan->matched_cnt==MATCHED_MAX ) ) FD_LOG_ERR(( "too many processes to kill" ));
      scan->match_err    [ scan->matched_cnt ] = err;
      scan->matched_start[ scan->matched_cnt ] = start_time;
      scan->matched      [ scan->matched_cnt++ ] = scan->pids[ i ];
    }
  }
  return NULL;
}

/* kill_scan runs check_kill over every pid in /proc on SCAN_THREADS
   threads (the per-process checks are independent kernel reads).
   Writes up to MATCHED_MAX (pid, starttime, reason) triples; returns
   the count. */

static ulong
kill_scan( config_t const * config,
           ulong            matched[ static MATCHED_MAX ],
           ulong            matched_start[ static MATCHED_MAX ],
           int              match_err[ static MATCHED_MAX ] ) {
  DIR * dir = opendir( "/proc" );
  if( FD_UNLIKELY( !dir ) ) FD_LOG_ERR(( "error opening `/proc` (%i-%s)", errno, fd_io_strerror( errno ) ));

  static ulong pids[ SCAN_PIDS_MAX ];
  ulong matched_cnt = 0UL;

  int done = 0;
  while( !done ) {
    ulong pid_cnt = 0UL;
    for(;;) {
      errno = 0;
      struct dirent * entry = readdir( dir );
      if( FD_UNLIKELY( !entry ) ) { done = 1; break; }
      if( FD_UNLIKELY( entry->d_name[0] == '.' ) ) continue;
      char * endptr;
      ulong pid = strtoul( entry->d_name, &endptr, 10 );
      if( FD_UNLIKELY( *endptr || pid==(ulong)getpid() ) ) continue;
      pids[ pid_cnt++ ] = pid;
      if( FD_UNLIKELY( pid_cnt==SCAN_PIDS_MAX ) ) break;
    }
    if( FD_UNLIKELY( errno ) ) FD_LOG_ERR(( "readdir() (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( !pid_cnt ) ) break;

    static struct kill_scan scans[ SCAN_THREADS ];
    pthread_t threads[ SCAN_THREADS ];
    for( ulong t=0UL; t<SCAN_THREADS; t++ ) {
      /* Scalars only: a struct assignment would memset the ~20 KiB
         match arrays per thread per batch for nothing (matched_cnt
         bounds all reads). */
      scans[ t ].config      = config;
      scans[ t ].pids        = pids;
      scans[ t ].pid_cnt     = pid_cnt;
      scans[ t ].idx         = t;
      scans[ t ].matched_cnt = 0UL;
      if( FD_UNLIKELY( pthread_create( &threads[ t ], NULL, kill_scan_thread, &scans[ t ] ) ) ) FD_LOG_ERR(( "pthread_create failed" ));
    }

    for( ulong t=0UL; t<SCAN_THREADS; t++ ) {
      if( FD_UNLIKELY( pthread_join( threads[ t ], NULL ) ) ) FD_LOG_ERR(( "pthread_join failed" ));
      for( ulong i=0UL; i<scans[ t ].matched_cnt; i++ ) {
        if( FD_UNLIKELY( matched_cnt==MATCHED_MAX ) ) FD_LOG_ERR(( "too many processes to kill" ));
        match_err    [ matched_cnt ] = scans[ t ].match_err    [ i ];
        matched_start[ matched_cnt ] = scans[ t ].matched_start[ i ];
        matched      [ matched_cnt++ ] = scans[ t ].matched    [ i ];
      }
    }
  }

  if( FD_UNLIKELY( -1==closedir( dir ) ) ) FD_LOG_ERR(( "closedir (%i-%s)", errno, fd_io_strerror( errno ) ));
  return matched_cnt;
}

static void
init( config_t const * config ) {
  ulong matched[ MATCHED_MAX ];
  ulong matched_start[ MATCHED_MAX ];
  int   match_err[ MATCHED_MAX ];
  ulong matched_cnt = kill_scan( config, matched, matched_start, match_err );

  for( ulong i=0UL; i<matched_cnt; i++ ) {
    /* Revalidate identity right before the signal: if the pid was
       recycled since the scan, the new owner is not our target. */
    if( FD_UNLIKELY( proc_start_time( matched[ i ] )!=matched_start[ i ] ) ) continue;
    char proc_cmdline[ PATH_MAX ];
    cmdline( proc_cmdline, PATH_MAX, matched[ i ] );
    FD_LOG_NOTICE(( "killing process `%s` (%lu): %s", proc_cmdline, matched[ i ], kill_reason( match_err[ i ] ) ));
    if( FD_UNLIKELY( -1==kill( (int)matched[ i ], SIGKILL ) && errno!=ESRCH ) ) FD_LOG_ERR(( "kill failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  long started = fd_log_wallclock();
  for( ulong i=0; i<matched_cnt; i++ ) wait_dead( started, matched[ i ], matched_start[ i ] );
}

static configure_result_t
check( config_t const * config,
       int              check_type FD_PARAM_UNUSED ) {
  ulong matched[ MATCHED_MAX ];
  ulong matched_start[ MATCHED_MAX ];
  int   match_err[ MATCHED_MAX ];
  ulong matched_cnt = kill_scan( config, matched, matched_start, match_err );

  if( FD_UNLIKELY( matched_cnt ) ) {
    char proc_cmdline[ PATH_MAX ];
    cmdline( proc_cmdline, PATH_MAX, matched[ 0 ] );
    NOT_CONFIGURED( "process `%s` (%lu) %s", proc_cmdline, matched[ 0 ], kill_reason( match_err[ 0 ] ) );
  }

  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_kill = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = NULL,
  .init_perm       = init_perm,
  .fini_perm       = NULL,
  .init            = init,
  .fini            = NULL,
  .check           = check,
};

#undef NAME
