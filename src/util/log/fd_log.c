#if !FD_HAS_HOSTED
#error "Implement logging support for this build target"
#endif

/* FIXME: SANITIZE VARIOUS USER SET STRINGS */

#define _GNU_SOURCE

#include "fd_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>
#include <time.h>
#include <syscall.h>
#include <execinfo.h>

/* APPLICATION LOGICAL ID APIS ****************************************/

/* App id */

static ulong fd_log_private_app_id; /* 0 outside boot/halt, init on boot */

void fd_log_private_app_id_set( ulong app_id ) { fd_log_private_app_id = app_id; }

ulong fd_log_app_id( void ) { return fd_log_private_app_id; }

/* App */

static char fd_log_private_app[ FD_LOG_NAME_MAX ]; /* "" outside boot/halt, init on boot */

char const * fd_log_app( void ) { return fd_log_private_app; }

/* Thread ID */

#if FD_HAS_THREADS
static ulong fd_log_private_thread_id_ctr; /* 0 outside boot/halt, init on boot */

static ulong
fd_log_private_thread_id_next( void ) {
  return FD_ATOMIC_FETCH_AND_ADD( &fd_log_private_thread_id_ctr, 1UL );
}
#endif

static FD_TLS ulong fd_log_private_thread_id;      /* 0 at thread start */
static FD_TLS int   fd_log_private_thread_id_init; /* 0 at thread start */

void
fd_log_private_thread_id_set( ulong thread_id ) {
  fd_log_private_thread_id      = thread_id;
  fd_log_private_thread_id_init = 1;
}

ulong
fd_log_thread_id( void ) {
# if FD_HAS_THREADS
  if( FD_UNLIKELY( !fd_log_private_thread_id_init ) ) fd_log_private_thread_id_set( fd_log_private_thread_id_next() );
# else
  FD_COMPILER_MFENCE(); /* Work around FD_FN_CONST */
# endif
  return fd_log_private_thread_id;
}

/* Thread */

/* Initialize name to a reasonable default thread description (FIXME:
   WEEN THIS OFF STDLIB) */

static void
fd_log_private_thread_default( char * name ) { /* FD_LOG_NAME_MAX bytes */
  sprintf( name, "%lu", fd_log_thread_id() );
}

static FD_TLS char fd_log_private_thread[ FD_LOG_NAME_MAX ]; /* "" at thread start */
static FD_TLS int  fd_log_private_thread_init;               /* 0 at thread start */

void
fd_log_thread_set( char const * thread ) {
  if( FD_UNLIKELY( !thread ) || FD_UNLIKELY( thread[0]=='\0') ) {
    fd_log_private_thread_default( fd_log_private_thread );
    fd_log_private_thread_init = 1;
  } else if( FD_LIKELY( thread!=fd_log_private_thread ) ) {
    fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( fd_log_private_thread ), thread, (ulong)(FD_LOG_NAME_MAX-1) ) );
    fd_log_private_thread_init = 1;
  }
}

char const *
fd_log_thread( void ) {
  if( FD_UNLIKELY( !fd_log_private_thread_init ) ) fd_log_thread_set( NULL );
  return fd_log_private_thread;
}

void
fd_log_private_app_set( char const * app ) {
  if( FD_UNLIKELY( !app ) ) app = "[app]";
  if( FD_LIKELY( app!=fd_log_private_app ) )
    fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( fd_log_private_app ), app, (ulong)(FD_LOG_NAME_MAX-1) ) );
}

/* APPLICATION PHYSICAL ID APIS ***************************************/

/* Host id */

static ulong fd_log_private_host_id; /* 0 outside boot/halt, initialized on boot */

void fd_log_private_host_id_set( ulong host_id ) { fd_log_private_host_id = host_id; }

ulong fd_log_host_id( void ) { return fd_log_private_host_id; }

/* Host */

static char  fd_log_private_host[ FD_LOG_NAME_MAX ]; /* "" outside boot/halt, initialized on boot */

char const * fd_log_host( void ) { return fd_log_private_host; }

void
fd_log_private_host_set( char const * host ) {
  if( FD_UNLIKELY( !host ) || FD_UNLIKELY( host[0]=='\0') ) host = "[host]";
  if( FD_LIKELY( host!=fd_log_private_host ) )
    fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( fd_log_private_host ), host, (ulong)(FD_LOG_NAME_MAX-1) ) );
}

/* CPU_ID */

/* First CPU scheduled to run on or ULONG_MAX on failure */

static ulong
fd_log_private_cpu_id_default( void ) {
  cpu_set_t cpu_set[1];
  if( FD_UNLIKELY( sched_getaffinity( (pid_t)0, sizeof( cpu_set_t ), cpu_set ) ) ) return ULONG_MAX;
  for( ulong idx=0UL; idx<CPU_SETSIZE; idx++ ) if( CPU_ISSET( idx, cpu_set ) ) return idx;
  return ULONG_MAX;
}

static FD_TLS ulong fd_log_private_cpu_id;      /* 0 at thread start */
static FD_TLS int   fd_log_private_cpu_id_init; /* 0 at thread start */

void
fd_log_private_cpu_id_set( ulong cpu_id ) {
  fd_log_private_cpu_id      = cpu_id;
  fd_log_private_cpu_id_init = 1;
}

ulong
fd_log_cpu_id( void ) {
  if( FD_UNLIKELY( !fd_log_private_cpu_id_init ) ) fd_log_private_cpu_id_set( fd_log_private_cpu_id_default() );
  return fd_log_private_cpu_id;
}

/* Initialize name to a reasonable default CPU description (FIXME: WEEN
   THIS OFF STDLIB) */

static void
fd_log_private_cpu_default( char * name ) { /* FD_LOG_NAME_MAX bytes */
  cpu_set_t set[1];

  int err = sched_getaffinity( (pid_t)0, sizeof(cpu_set_t), set );
  if( FD_UNLIKELY( err ) ) { sprintf( name, "e%i", err ); return; }

  ulong cnt = (ulong)CPU_COUNT( set );
  if( FD_UNLIKELY( !((0UL<cnt) & (cnt<=CPU_SETSIZE)) ) ) { sprintf( name, "ec" ); return; }

  ulong idx; for( idx=0UL; idx<CPU_SETSIZE; idx++ ) if( CPU_ISSET( idx, set ) ) break;
  sprintf( name, (cnt>1) ? "f%lu" : "%lu", idx );
}

/* CPU */

static FD_TLS char fd_log_private_cpu[ FD_LOG_NAME_MAX ]; /* "" at thread start */
static FD_TLS int  fd_log_private_cpu_init;               /* 0  at thread start */

void
fd_log_cpu_set( char const * cpu ) {
  if( FD_UNLIKELY( !cpu ) || FD_UNLIKELY( cpu[0]=='\0') ) {
    fd_log_private_cpu_default( fd_log_private_cpu );
    fd_log_private_cpu_init = 1;
  } else if( FD_LIKELY( cpu!=fd_log_private_cpu ) ) {
    fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( fd_log_private_cpu ), cpu, (ulong)(FD_LOG_NAME_MAX-1) ) );
    fd_log_private_cpu_init = 1;
  }
}

char const *
fd_log_cpu( void ) {
  if( FD_UNLIKELY( !fd_log_private_cpu_init ) ) fd_log_cpu_set( NULL );
  return fd_log_private_cpu;
}

/* THREAD GROUP ID APIS ***********************************************/

/* Group id */

static ulong fd_log_private_group_id; /* 0 outside boot/halt, init on boot */

void fd_log_private_group_id_set( ulong group_id ) { fd_log_private_group_id = group_id; }

ulong fd_log_group_id( void ) { return fd_log_private_group_id; }

/* Group */

static char fd_log_private_group[ FD_LOG_NAME_MAX ]; /* "" outside boot/halt, init on boot */

char const * fd_log_group( void ) { return fd_log_private_group; }

void
fd_log_private_group_set( char const * group ) {
  if( FD_UNLIKELY( !group ) || FD_UNLIKELY( group[0]=='\0') ) group = "[group]";
  if( FD_LIKELY( group!=fd_log_private_group ) )
    fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( fd_log_private_group ), group, (ulong)(FD_LOG_NAME_MAX-1) ) );
}

/* System TID or ULONG_MAX on failure */

static ulong
fd_log_private_tid_default( void ) {
  long tid = syscall( SYS_gettid );
  return fd_ulong_if( tid>0L, (ulong)tid, ULONG_MAX );
}

static FD_TLS ulong fd_log_private_tid;      /* 0 at thread start */
static FD_TLS int   fd_log_private_tid_init; /* 0 at thread start */

void
fd_log_private_tid_set( ulong tid ) {
  fd_log_private_tid      = tid;
  fd_log_private_tid_init = 1;
}

ulong
fd_log_tid( void ) {
  if( FD_UNLIKELY( !fd_log_private_tid_init ) ) fd_log_private_tid_set( fd_log_private_tid_default() );
  return fd_log_private_tid;
}

/* User */

static char  fd_log_private_user[ FD_LOG_NAME_MAX ]; /* "" outside boot/halt, init on boot */

char const * fd_log_user( void ) { return fd_log_private_user; }

void
fd_log_private_user_set( char const * user ) {
  if( FD_UNLIKELY( !user ) || FD_UNLIKELY( user[0]=='\0') ) user = "[user]";
  if( FD_LIKELY( user!=fd_log_private_user ) )
    fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( fd_log_private_user ), user, (ulong)(FD_LOG_NAME_MAX-1) ) );
}

/* WALLCLOCK APIS *****************************************************/

long
fd_log_wallclock( void ) {
  struct timespec ts[1];
  clock_gettime( CLOCK_REALTIME, ts );
  return ((long)1e9)*((long)ts->tv_sec) + (long)ts->tv_nsec;
}

char *
fd_log_wallclock_cstr( long   now,
                       char * buf ) {
  uint  YYYY;
  uint  MM;
  uint  DD;
  uint  hh;
  uint  mm;
  ulong ns;
  int   tz;

  static long const ns_per_m = 60000000000L;
  static long const ns_per_s =  1000000000L;

  static FD_TLS long now_ref  = 1262325600000000000L; /* 2010-01-01 00:00:00.000000000 GMT-06 */
  static FD_TLS uint YYYY_ref = 2010U;                /* Initialized to what now0 corresponds to */
  static FD_TLS uint MM_ref   = 1U;                   /* " */
  static FD_TLS uint DD_ref   = 1U;                   /* " */
  static FD_TLS uint hh_ref   = 0U;                   /* " */
  static FD_TLS uint mm_ref   = 0U;                   /* " */
  static FD_TLS int  tz_ref   = -6;                   /* " */

  if( FD_LIKELY( (now_ref<=now) & (now<(now_ref+ns_per_m)) ) ) {

    /* now is near the reference timestamp so we reuse the the reference
       calculation timestamp.  USINGS HOURS FOR CACHE TIMESCALE (LESS
       FREQUENT RECOMPUTING THE CACHE BUT MORE DIVISION HERE) OR USING
       SECONDS (NO DIVISION HERE BUT MORE FREQUENT CACHE RECOMPUTE)?
       THE ONE DIVISION HERE WILL PROBABLY BE DONE VIA BIT TRICKS IN THE
       COMPILER. */

    YYYY = YYYY_ref;
    MM   = MM_ref;
    DD   = DD_ref;
    hh   = hh_ref;
    mm   = mm_ref;
    ns   = (ulong)(now - now_ref);
    tz   = tz_ref;

  } else {

    long _t  = now / ns_per_s;
    long _ns = now - ns_per_s*_t;
    if( _ns<0L ) _ns += ns_per_s, _t--;
    time_t t = (time_t)_t;

    struct tm tm[1];
    static FD_TLS int localtime_broken = 0;
    if( FD_UNLIKELY( !localtime_broken && !localtime_r( &t, tm ) ) ) localtime_broken = 1;
    if( FD_UNLIKELY( localtime_broken ) ) { /* If localtime_r doesn't work, pretty print as a raw UNIX time */
      /* Note: These can all run in parallel */
      fd_cstr_append_fxp10_as_text( buf,    ' ', fd_char_if( now<0L, '-', '\0' ), 9UL, fd_long_abs( now ), 29UL );
      fd_cstr_append_text         ( buf+29, " s UNIX",                                                      7UL );
      fd_cstr_append_char         ( buf+36, '\0'                                                                );
      return buf;
    }

    YYYY = (uint)(1900+tm->tm_year);
    MM   = (uint)(   1+tm->tm_mon );
    DD   = (uint)tm->tm_mday;
    hh   = (uint)tm->tm_hour;
    mm   = (uint)tm->tm_min;
    ns   = ((ulong)((uint)tm->tm_sec))*((ulong)ns_per_s) + ((ulong)_ns);
    tz   = (int)(-timezone/3600L+(long)tm->tm_isdst);

    now_ref  = now - (long)ns;
    YYYY_ref = YYYY;
    MM_ref   = MM;
    DD_ref   = DD;
    hh_ref   = hh;
    mm_ref   = mm;
    tz_ref   = tz;

  }

  /* Note: These can all run in parallel! */
  fd_cstr_append_uint_as_text ( buf,    '0', '\0',    YYYY,            4UL );
  fd_cstr_append_char         ( buf+ 4, '-'                                );
  fd_cstr_append_uint_as_text ( buf+ 5, '0', '\0',      MM,            2UL );
  fd_cstr_append_char         ( buf+ 7, '-'                                );
  fd_cstr_append_uint_as_text ( buf+ 8, '0', '\0',      DD,            2UL );
  fd_cstr_append_char         ( buf+10, ' '                                );
  fd_cstr_append_uint_as_text ( buf+11, '0', '\0',      hh,            2UL );
  fd_cstr_append_char         ( buf+13, ':'                                );
  fd_cstr_append_uint_as_text ( buf+14, '0', '\0',      mm,            2UL );
  fd_cstr_append_char         ( buf+16, ':'                                );
  fd_cstr_append_fxp10_as_text( buf+17, '0', '\0', 9UL, ns,           12UL );
  fd_cstr_append_text         ( buf+29, " GMT",                        4UL );
  fd_cstr_append_char         ( buf+33, fd_char_if( tz<0, '-', '+' )       );
  fd_cstr_append_uint_as_text ( buf+34, '0', '\0', fd_int_abs( tz ),   2UL );
  fd_cstr_append_char         ( buf+36, '\0'                               );
  return buf;
}

/* LOG APIS ***********************************************************/

static char   fd_log_private_path[ 1024 ]; /* empty string on start */
static FILE * fd_log_private_file;         /* NULL on start */
static int    fd_log_private_dedup;        /* 0 on start */

void
fd_log_flush( void ) {
  FILE * log_file = FD_VOLATILE_CONST( fd_log_private_file );
  if( log_file ) {
    fflush( log_file );
    fsync( fileno( log_file ) );
  }
  fflush( stderr );
}

static int fd_log_private_level_logfile; /* 0 outside boot/halt, init at boot */
static int fd_log_private_level_stderr;  /* 0 outside boot/halt, init at boot */
static int fd_log_private_level_flush;   /* 0 outside boot/halt, init at boot */
static int fd_log_private_level_core;    /* 0 outside boot/halt, init at boot */

int fd_log_level_logfile( void ) { return FD_VOLATILE_CONST( fd_log_private_level_logfile ); }
int fd_log_level_stderr ( void ) { return FD_VOLATILE_CONST( fd_log_private_level_stderr  ); }
int fd_log_level_flush  ( void ) { return FD_VOLATILE_CONST( fd_log_private_level_flush   ); }
int fd_log_level_core   ( void ) { return FD_VOLATILE_CONST( fd_log_private_level_core    ); }

void fd_log_level_logfile_set( int level ) { FD_VOLATILE( fd_log_private_level_logfile ) = level; }
void fd_log_level_stderr_set ( int level ) { FD_VOLATILE( fd_log_private_level_stderr  ) = level; }
void fd_log_level_flush_set  ( int level ) { FD_VOLATILE( fd_log_private_level_flush   ) = level; }
void fd_log_level_core_set   ( int level ) { FD_VOLATILE( fd_log_private_level_core    ) = level; }

char const *
fd_log_private_0( char const * fmt, ... ) {
  static FD_TLS char msg[ 4096 ];
  va_list ap;
  va_start( ap, fmt );
  int len = vsnprintf( msg, 4096, fmt, ap );
  if( len<0    ) len = 0;    /* cmov */
  if( len>4095 ) len = 4095; /* cmov */
  msg[ len ] = '\0';
  va_end( ap );
  return msg;
}

void
fd_log_private_1( int          level,
                  long         now,
                  char const * file,
                  int          line,
                  char const * func,
                  char const * msg ) {

  static char const * level_str[] = {
    /* 0 */ "DEBUG  ",
    /* 1 */ "INFO   ",
    /* 2 */ "NOTICE ",
    /* 3 */ "WARNING",
    /* 4 */ "ERR    ",
    /* 5 */ "CRIT   ",
    /* 6 */ "ALERT  ",
    /* 7 */ "EMERG  "
  };

  if( level<fd_log_level_logfile() ) return;

  /* These are thread init so we call them regardless of permanent log
     enabled to their initialization time is guaranteed independent of
     whether the permanent log is enabled. */

  char const * thread = fd_log_thread();
  char const * cpu    = fd_log_cpu();
  ulong        tid    = fd_log_tid();

  FILE * log_file   = FD_VOLATILE_CONST( fd_log_private_file );
  int    to_logfile = (!!log_file);
  int    to_stderr  = (level>=fd_log_level_stderr());
  if( !(to_logfile | to_stderr) ) return;

  /* Deduplicate the log if requested */

  if( fd_log_private_dedup ) {

    /* Compute if this message appears to be a recent duplicate of
       a previous log message */

    ulong hash = fd_cstr_hash_append( fd_cstr_hash_append( fd_cstr_hash_append( fd_ulong_hash(
                                      (ulong)(uint)(8*line+level) ), file ), func ), msg );

    static long const dedup_interval = 20000000L; /* 1/50 s */

    static FD_TLS int   init;      /* 0   on thread start */
    static FD_TLS ulong last_hash; /* 0UL on thread start */
    static FD_TLS long  then;      /* 0L  on thread start */

    int is_dup = init & (hash==last_hash) & ((now-then)<dedup_interval);
    init = 1;

    /* Update how many messages from this thread in row have been
       dubplicates */

    static FD_TLS ulong dedup_cnt;   /* 0UL on thread start */
    static FD_TLS int   in_dedup;    /* 0   on thread start */

    if( is_dup ) dedup_cnt++;
    else {
      if( in_dedup ) {

        /* This message appears to end a long string of duplicates.
           Log the end of the deduplication. */

        char then_cstr[ FD_LOG_WALLCLOCK_CSTR_BUF_SZ ];
        fd_log_wallclock_cstr( then, then_cstr );

        if( to_logfile ) fprintf( log_file, "SNIP    %s %6lu:%-6lu %s:%s:%-4s %s:%s:%-4s "
                                  "stopped repeating (%lu identical messages)\n",
                                  then_cstr, fd_log_group_id(),tid, fd_log_user(),fd_log_host(),cpu,
                                  fd_log_app(),fd_log_group(),thread, dedup_cnt+1UL );

        if( to_stderr ) {
          char * then_short_cstr = then_cstr+5; then_short_cstr[21] = '\0'; /* Lop off the year, ns resolution and timezone */
          fprintf( stderr, "SNIP    %s %-6lu %-4s %-4s stopped repeating (%lu identical messages)\n",
                           then_short_cstr, tid,cpu,thread, dedup_cnt+1UL );
        }

        in_dedup = 0;
      }

      dedup_cnt = 0UL;
    }

    /* dedup_cnt previous messages from this thread appear to be
       duplicates.  Decide whether to let the raw message print or
       deduplicate to the log.  FIXME: CONSIDER RANDOMIZING THE
       THROTTLE. */

    static ulong const dedup_thresh   = 3UL;         /* let initial dedup_thresh duplicates go out the door */
    static long  const dedup_throttle = 1000000000L; /* ~1s, how often to update status on current duplication */

    static FD_TLS long dedup_last; /* 0L on thread start */

    if( dedup_cnt < dedup_thresh ) dedup_last = now;
    else {
      if( (now-dedup_last) >= dedup_throttle ) {
        char now_cstr[ FD_LOG_WALLCLOCK_CSTR_BUF_SZ ];
        fd_log_wallclock_cstr( now, now_cstr );
        if( to_logfile ) fprintf( log_file, "SNIP    %s %6lu:%-6lu %s:%s:%-4s %s:%s:%-4s repeating (%lu identical messages)\n",
                                  now_cstr, fd_log_group_id(),tid, fd_log_user(),fd_log_host(),cpu,
                                  fd_log_app(),fd_log_group(),thread, dedup_cnt+1UL );
        if( to_stderr ) {
          char * now_short_cstr = now_cstr+5; now_short_cstr[21] = '\0'; /* Lop off the year, ns resolution and timezone */
          fprintf( stderr, "SNIP    %s %-6lu %-4s %-4s repeating (%lu identical messages)\n",
                   now_short_cstr, tid,cpu,thread, dedup_cnt+1UL );
        }
        dedup_last = now;
      }
      in_dedup = 1;
    }

    last_hash = hash;
    then      = now;

    if( in_dedup ) return;
  }

  char now_cstr[ FD_LOG_WALLCLOCK_CSTR_BUF_SZ ];
  fd_log_wallclock_cstr( now, now_cstr );

  if( to_logfile ) fprintf( log_file, "%s %s %6lu:%-6lu %s:%s:%-4s %s:%s:%-4s %s(%i)[%s]: %s\n",
                            level_str[level], now_cstr, fd_log_group_id(),tid, fd_log_user(),fd_log_host(),cpu,
                            fd_log_app(),fd_log_group(),thread, file,line,func, msg );

  if( to_stderr ) {
    char * now_short_cstr = now_cstr+5; now_short_cstr[21] = '\0'; /* Lop off the year, ns resolution and timezone */
    fprintf( stderr, "%s %s %-6lu %-4s %-4s %s(%i): %s\n", level_str[level], now_short_cstr, tid,cpu,thread, file, line, msg );
  }

  if( level<fd_log_level_flush() ) return;

  fd_log_flush();
}

void
fd_log_private_2( int          level,
                  long         now,
                  char const * file,
                  int          line,
                  char const * func,
                  char const * msg ) {
  fd_log_private_1( level, now, file, line, func, msg );

  if( level<fd_log_level_core() ) exit(1); /* atexit will call fd_log_private_cleanup implicitly */

  abort();
}

/* BOOT/HALT APIS *****************************************************/

static void
fd_log_private_cleanup( void ) {

  /* The atexit below means  that all calls to "exit();" implicitly
     become "fd_log_private_cleanup(); exit();".  It also implies that
     programs that terminate via a top level return from main implicitly
     call fd_log_private_cleanup().

     As such it is possible that a thread other than the booter will
     trigger cleanup either by triggering this directly (e.g. calling
     exit) or indirectly (e.g. by logging a message with an exit
     triggering priority) and that the booter itself might call this
     more than once sequentially (e.g. fd_halt() calling cleanup
     explicitly followed by return from main triggering it again.

     Accordingly we protect this with a ONCE block so it only will
     execute once per program.  Further cleanup gets triggered by
     multiple threads concurrently, the ONCE block will prevent them
     from progressing until the first thread that hits the once block
     has completed cleanup. */

  FD_ONCE_BEGIN {
    FILE * log_file = FD_VOLATILE_CONST( fd_log_private_file );
    if(      !log_file                           ) fprintf( stderr, "No log\n" );
    else if( !strcmp( fd_log_private_path, "-" ) ) fprintf( stderr, "Log to stdout\n" );
    else {
#     if FD_HAS_THREADS
      if( fd_log_private_thread_id_ctr>1UL ) { /* There are potentially other log users running */
        /* Just closing the permanent log file is not multithreading
           safe in the case where other threads are still running
           normally and thus potentially logging to the permanent log.
           Such should not happen in a correctly written and functioning
           application but logging exists in large part to help
           understand when applications misbehave.  So we try to be as
           robust and informative as we can here.  FIXME: THE SECOND
           USLEEP IS AN UGLY HACK TO REDUCE (BUT NOT FULLY ELIMINATE)
           THE RISK OF USE AFTER CLOSE BY THOSE OTHER THREADS.  IT IS
           POSSIBLE WITH A MORE INVASIVE CHANGES TO FULLY ELIMINATE THIS
           RISK. */
        usleep( (useconds_t)40000 ); /* Give potentially concurrent users a chance to get their dying messages out */
        FD_COMPILER_MFENCE();
        FD_VOLATILE( fd_log_private_file ) = NULL; /* Turn off the permanent log for concurrent users */
        FD_COMPILER_MFENCE();
        usleep( (useconds_t)40000 ); /* Give any concurrent log operations progress at turn off a chance to wrap */
      }
#     else
      FD_VOLATILE( fd_log_private_file ) = NULL;
#     endif
      fclose( log_file );
      sync();
      fprintf( stderr, "Log at \"%s\"\n", fd_log_private_path );
    }
    fflush( stderr );
  } FD_ONCE_END;
}

static void
fd_log_private_sig_abort( int         sig,
                          siginfo_t * info,
                          void *      context ) {
  (void)info; (void)context;

  fflush( stdout );

  /* Hopefully all out streams are idle now and we have flushed out
     all non-logging activity ... log a backtrace */

  void * btrace[128];
  int n_btrace = backtrace( btrace, 128 );

  FILE * log_file = FD_VOLATILE_CONST( fd_log_private_file );
  if( log_file ) {
    fprintf( log_file, "Caught signal %i, backtrace:\n", sig );
    fflush( log_file );
    int fd = fileno( log_file );
    backtrace_symbols_fd( btrace, n_btrace, fd );
    fsync( fd );
  }

  fprintf( stderr, "\nCaught signal %i, backtrace:\n", sig );
  fflush( stderr );
  int fd = fileno( stderr );
  backtrace_symbols_fd( btrace, n_btrace, fd );
  fsync( fd );

  /* Do final log cleanup */

  fd_log_private_cleanup();

  usleep( (useconds_t)1000000 ); /* Give some time to let streams drain */

  raise( sig ); /* Contiue with the original handler (probably the default and that will produce the core) */
}

static void
fd_log_private_sig_trap( int sig ) {
  struct sigaction act[1];
  /* FIXME: CONSIDER NOT OVERRIDING IF THE SIGNAL HANDLER HAS ALREADY
     BEEN SET BY THE USER. */
  act->sa_sigaction = fd_log_private_sig_abort;
  if( sigemptyset( &act->sa_mask ) ) FD_LOG_ERR(( "sigempty set failed" ));
  act->sa_flags = (int)(SA_SIGINFO | SA_RESETHAND);
  if( sigaction( sig, act, NULL ) ) FD_LOG_ERR(( "unable to override signal %i", sig ));
}

void
fd_log_private_boot( int  *   pargc,
                     char *** pargv ) {
//FD_LOG_INFO(( "fd_log: booting" )); /* Log not online yet */

  char buf[ FD_LOG_NAME_MAX ];

  /* Init our our application logical ids */
  /* FIXME: CONSIDER EXPLICIT SPECIFICATION OF RANGE OF THREADS
     INSTEAD OF ATOMIC COUNTER FROM BASE */

  fd_log_private_app_id_set( fd_env_strip_cmdline_ulong( pargc, pargv, "--log-app-id", "FD_LOG_APP_ID", 0UL ) );

  fd_log_private_app_set( fd_env_strip_cmdline_cstr( pargc, pargv, "--log-app", "FD_LOG_APP", NULL ) );

# if FD_HAS_THREADS
  fd_log_private_thread_id_ctr = fd_env_strip_cmdline_ulong( pargc, pargv, "--log-thread-id", "FD_LOG_THREAD_ID", 0UL );
  ulong thread_id = fd_log_private_thread_id_next();
# else
  ulong thread_id = fd_env_strip_cmdline_ulong( pargc, pargv, "--log-thread-id", "FD_LOG_THREAD_ID", 0UL );
# endif
  fd_log_private_thread_id_set( thread_id );

  fd_log_thread_set( fd_env_strip_cmdline_cstr( pargc, pargv, "--log-thread", "FD_LOG_THREAD", NULL ) );

  /* Init our our application physical ids */
  /* We ignore any user specified cpu-id in favor of the actual core
     assigned by the host OS.  We strip it from the command line so
     downstream command line handling is identical from user's point of
     view. */

  fd_log_private_host_id_set( fd_env_strip_cmdline_ulong( pargc, pargv, "--log-host-id", "FD_LOG_HOST_ID", 0UL ) );

  char const * host = fd_env_strip_cmdline_cstr( pargc, pargv, "--log-host", "FD_LOG_HOST", NULL );
  if( !host ) { if( !gethostname( buf, (ulong)FD_LOG_NAME_MAX ) ) buf[ FD_LOG_NAME_MAX-1 ] = '\0', host = buf; }
  fd_log_private_host_set( host );

  fd_env_strip_cmdline_ulong( pargc, pargv, "--log-cpu-id", "FD_LOG_CPU_ID", 0UL ); /* FIXME: LOG IGNORING? */
  fd_log_private_cpu_id_set( fd_log_private_cpu_id_default() );

  fd_log_cpu_set( fd_env_strip_cmdline_cstr( pargc, pargv, "--log-cpu", "FD_LOG_CPU", NULL ) );

  /* Init our thread group ids */
  /* We ignore any user specified group id and tid in favor of the actual
     group id and tid assigned by the host OS.  We strip it from the
     command line so downstream command line handling is identical from
     user's point of view. */

  fd_env_strip_cmdline_ulong( pargc, pargv, "--log-group-id", "FD_LOG_GROUP_ID", 0UL ); /* FIXME: LOG IGNORING? */
  pid_t pid = getpid();
  fd_log_private_group_id_set( fd_ulong_if( pid>(pid_t)0, (ulong)pid, ULONG_MAX ) );

  char const * group = fd_env_strip_cmdline_cstr( pargc, pargv, "--log-group", "FD_LOG_GROUP", NULL );
  if( !group ) group = program_invocation_short_name;
  if( !group ) group = (pargc && pargv && (*pargc)>0) ? (*pargv)[0] : NULL;
  fd_log_private_group_set( group );

  fd_env_strip_cmdline_ulong( pargc, pargv, "--log-tid", "FD_LOG_TID", 0UL ); /* FIXME: LOG IGNORING? */
  fd_log_private_tid_set( fd_log_private_tid_default() );

  char const * user = fd_env_strip_cmdline_cstr( pargc, pargv, "--log-user", "FD_LOG_USER", NULL );
  if( !user )  user = getenv( "LOGNAME" );
  if( !user )  user = getlogin();
  fd_log_private_user_set( user );

  /* Configure the log */

  fd_log_private_dedup = fd_env_strip_cmdline_int( pargc, pargv, "--log-dedup", "FD_LOG_DEDUP", 1 );

  fd_log_level_logfile_set( fd_env_strip_cmdline_int( pargc, pargv, "--log-level-logfile", "FD_LOG_LEVEL_LOGFILE", 1 ) );
  fd_log_level_stderr_set ( fd_env_strip_cmdline_int( pargc, pargv, "--log-level-stderr",  "FD_LOG_LEVEL_STDERR",  2 ) );
  fd_log_level_flush_set  ( fd_env_strip_cmdline_int( pargc, pargv, "--log-level-flush",   "FD_LOG_LEVEL_FLUSH",   3 ) );
  fd_log_level_core_set   ( fd_env_strip_cmdline_int( pargc, pargv, "--log-level-core",    "FD_LOG_LEVEL_CORE",    5 ) );

  /* Hook up signal handlers */

  int log_backtrace = fd_env_strip_cmdline_int( pargc, pargv, "--log-backtrace", "FD_LOG_BACKTRACE", 1 );
  if( log_backtrace ) {
    /* This is all overridable POSIX sigs whose default behavior is to
       abort the program.  It will backtrace and then fallback to the
       default behavior. */
    fd_log_private_sig_trap( SIGABRT   );
    fd_log_private_sig_trap( SIGALRM   );
    fd_log_private_sig_trap( SIGFPE    );
    fd_log_private_sig_trap( SIGHUP    );
    fd_log_private_sig_trap( SIGILL    );
    fd_log_private_sig_trap( SIGINT    );
    fd_log_private_sig_trap( SIGQUIT   );
    fd_log_private_sig_trap( SIGPIPE   );
    fd_log_private_sig_trap( SIGSEGV   );
    fd_log_private_sig_trap( SIGTERM   );
    fd_log_private_sig_trap( SIGUSR1   );
    fd_log_private_sig_trap( SIGUSR2   );
    fd_log_private_sig_trap( SIGBUS    );
    fd_log_private_sig_trap( SIGPOLL   );
    fd_log_private_sig_trap( SIGPROF   );
    fd_log_private_sig_trap( SIGSYS    );
    fd_log_private_sig_trap( SIGTRAP   );
    fd_log_private_sig_trap( SIGVTALRM );
    fd_log_private_sig_trap( SIGXCPU   );
    fd_log_private_sig_trap( SIGXFSZ   );
  }

  /* At this point, ephemeral log online. */

  /* Hook up the permanent log */

  char const * log_path    = fd_env_strip_cmdline_cstr( pargc, pargv, "--log-path", "FD_LOG_PATH", NULL );
  ulong        log_path_sz = log_path ? (strlen( log_path )+1UL) : 0UL;

  if( !log_path_sz ) { /* Use default log path */
    char tag[ FD_LOG_WALLCLOCK_CSTR_BUF_SZ ];
    fd_log_wallclock_cstr( fd_log_wallclock(), tag );
    for( ulong b=0UL; tag[b]; b++ ) if( tag[b]==' ' || tag[b]=='-' || tag[b]=='.' || tag[b]==':' ) tag[b] = '_';
    ulong len; fd_cstr_printf( fd_log_private_path, 1024UL, &len, "/tmp/fd-%i.%i.%i_%lu_%s_%s_%s",
                               FD_VERSION_MAJOR, FD_VERSION_MINOR, FD_VERSION_PATCH,
                               fd_log_group_id(), fd_log_user(), fd_log_host(), tag );
    if( len==1023UL ) { fprintf( stderr, "default log path too long; unable to boot\n" ); exit(1); }
  }
  else if( log_path_sz==1UL    ) fd_log_private_path[0] = '\0'; /* User disabled */
  else if( log_path_sz<=1024UL ) memcpy( fd_log_private_path, log_path, log_path_sz ); /* User specified */
  else                           { fprintf( stderr, "--log-path too long; unable to boot\n" ); exit(1); } /* Invalid */

  FILE * log_file;
  if( fd_log_private_path[0]=='\0' ) {
    fprintf( stderr, "--log-path \"\"\nNo log\n" );
    log_file = NULL;
  } else if( !strcmp( fd_log_private_path, "-" ) ) {
    fprintf( stderr, "--log-path \"-\"\nLog to stdout\n" );
    log_file = stdout;
  } else {
    if( !log_path_sz ) fprintf( stderr, "--log-path not specified; using autogenerated path\n" );
    log_file = fopen( fd_log_private_path, "a" );
    if( !log_file ) {
      fprintf( stderr, "fopen failed (--log-path \"%s\"); unable to boot\n", fd_log_private_path );
      exit(1);
    }
    fprintf( stderr, "Log at \"%s\"\n", fd_log_private_path );
  }
  FD_VOLATILE( fd_log_private_file ) = log_file;

  if( atexit( fd_log_private_cleanup ) ) { fprintf( stderr, "atexit failed; unable to boot\n" ); exit(1); }

  /* At this point, logging online */

  FD_LOG_INFO(( "fd_log: --log-path          %s",  fd_log_private_path    ));
  FD_LOG_INFO(( "fd_log: --log-dedup         %i",  fd_log_private_dedup   ));
  FD_LOG_INFO(( "fd_log: --log-backtrace     %i",  log_backtrace          ));
  FD_LOG_INFO(( "fd_log: --log-level-logfile %i",  fd_log_level_logfile() ));
  FD_LOG_INFO(( "fd_log: --log-level-stderr  %i",  fd_log_level_stderr()  ));
  FD_LOG_INFO(( "fd_log: --log-level-flush   %i",  fd_log_level_flush()   ));
  FD_LOG_INFO(( "fd_log: --log-level-core    %i",  fd_log_level_core()    ));
  FD_LOG_INFO(( "fd_log: --log-app-id        %lu", fd_log_app_id()        ));
  FD_LOG_INFO(( "fd_log: --log-app           %s",  fd_log_app()           ));
  FD_LOG_INFO(( "fd_log: --log-thread-id     %lu", fd_log_thread_id()     ));
  FD_LOG_INFO(( "fd_log: --log-thread        %s",  fd_log_thread()        ));
  FD_LOG_INFO(( "fd_log: --log-host-id       %lu", fd_log_host_id()       ));
  FD_LOG_INFO(( "fd_log: --log-host          %s",  fd_log_host()          ));
  FD_LOG_INFO(( "fd_log: --log-cpu-id        %lu", fd_log_cpu_id()        ));
  FD_LOG_INFO(( "fd_log: --log-cpu           %s",  fd_log_cpu()           ));
  FD_LOG_INFO(( "fd_log: --log-group-id      %lu", fd_log_group_id()      ));
  FD_LOG_INFO(( "fd_log: --log-group         %s",  fd_log_group()         ));
  FD_LOG_INFO(( "fd_log: --log-tid           %lu", fd_log_tid()           ));
  FD_LOG_INFO(( "fd_log: --log-user          %s",  fd_log_user()          ));

  FD_LOG_INFO(( "fd_log: boot success" ));
}

void
fd_log_private_halt( void ) {
  FD_LOG_INFO(( "fd_log: halting" ));

  fd_log_flush();
  fd_log_private_cleanup();

  /* At this point, log is offline */

  fd_log_private_path[0]        = '\0';
/*fd_log_private_file           = NULL;*/ /* Already handled by cleanup */
  fd_log_private_dedup          = 0;

  fd_log_private_level_core     = 0;
  fd_log_private_level_flush    = 0;
  fd_log_private_level_stderr   = 0;
  fd_log_private_level_logfile  = 0;

  fd_log_private_user[0]        = '\0';
  fd_log_private_tid_init       = 0;
  fd_log_private_tid            = 0UL;
  fd_log_private_group[0]       = '\0';
  fd_log_private_group_id       = 0UL;

  fd_log_private_cpu_init       = 0;
  fd_log_private_cpu[0]         = '\0';
  fd_log_private_cpu_id_init    = 0;
  fd_log_private_cpu_id         = 0UL;
  fd_log_private_host[0]        = '\0';
  fd_log_private_host_id        = 0UL;

  fd_log_private_thread_init    = 0;
  fd_log_private_thread[0]      = '\0';
  fd_log_private_thread_id_init = 0;
  fd_log_private_thread_id      = 0UL;
# if FD_HAS_THREADS
  fd_log_private_thread_id_ctr  = 0UL;
# endif
  fd_log_private_app[0]         = '\0';
  fd_log_private_app_id         = 0UL;

//FD_LOG_INFO(( "fd_log: halt success" )); /* Log not online anymore */
}

