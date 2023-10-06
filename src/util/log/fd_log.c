#ifndef FD_LOG_STYLE
#if FD_HAS_HOSTED
#define FD_LOG_STYLE 0
#else
#error "Define FD_LOG_STYLE for this platform"
#endif
#endif

#if FD_LOG_STYLE==0 /* POSIX style */

#ifndef FD_HAS_BACKTRACE
#if __has_include( <execinfo.h> )
#define FD_HAS_BACKTRACE 1
#else
#define FD_HAS_BACKTRACE 0
#endif
#endif

/* FIXME: SANITIZE VARIOUS USER SET STRINGS */

#define _GNU_SOURCE

#include "fd_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>
#include <time.h>
#include <syscall.h>
#include <sys/mman.h>

#if FD_HAS_BACKTRACE
#include <execinfo.h>
#endif

#ifdef FD_BUILD_INFO
FD_IMPORT_CSTR( fd_log_build_info, FD_BUILD_INFO );
#else
char const  fd_log_build_info[1] __attribute__((aligned(1))) = { '\0' };
ulong const fd_log_build_info_sz                             = 1UL;
#endif

/* TEXT_* are quick-and-dirty color terminal hacks.  Probably should
   do something more robust longer term. */

#define TEXT_NORMAL    "\033[0m"
#define TEXT_BOLD      "\033[1m"
#define TEXT_UNDERLINE "\033[4m"
#define TEXT_BLINK     "\033[5m"

#define TEXT_BLUE      "\033[34m"
#define TEXT_GREEN     "\033[32m"
#define TEXT_YELLOW    "\033[93m"
#define TEXT_RED       "\033[31m"

/* APPLICATION LOGICAL ID APIS ****************************************/

/* App id */

static ulong fd_log_private_app_id; /* 0 outside boot/halt, init on boot */

void fd_log_private_app_id_set( ulong app_id ) { fd_log_private_app_id = app_id; }

ulong fd_log_app_id( void ) { return fd_log_private_app_id; }

/* App */

static char fd_log_private_app[ FD_LOG_NAME_MAX ]; /* "" outside boot/halt, init on boot */

void
fd_log_private_app_set( char const * app ) {
  if( FD_UNLIKELY( !app ) ) app = "[app]";
  if( FD_LIKELY( app!=fd_log_private_app ) )
    fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( fd_log_private_app ), app, FD_LOG_NAME_MAX-1UL ) );
}

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
    fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( fd_log_private_thread ), thread, FD_LOG_NAME_MAX-1UL ) );
    fd_log_private_thread_init = 1;
  }
}

char const *
fd_log_thread( void ) {
  if( FD_UNLIKELY( !fd_log_private_thread_init ) ) fd_log_thread_set( NULL );
  return fd_log_private_thread;
}

/* APPLICATION PHYSICAL ID APIS ***************************************/

/* Host ID */

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
    fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( fd_log_private_host ), host, FD_LOG_NAME_MAX-1UL ) );
}

/* CPU ID */

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

/* CPU */

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

static FD_TLS char fd_log_private_cpu[ FD_LOG_NAME_MAX ]; /* "" at thread start */
static FD_TLS int  fd_log_private_cpu_init;               /* 0  at thread start */

void
fd_log_cpu_set( char const * cpu ) {
  if( FD_UNLIKELY( !cpu ) || FD_UNLIKELY( cpu[0]=='\0') ) {
    fd_log_private_cpu_default( fd_log_private_cpu );
    fd_log_private_cpu_init = 1;
  } else if( FD_LIKELY( cpu!=fd_log_private_cpu ) ) {
    fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( fd_log_private_cpu ), cpu, FD_LOG_NAME_MAX-1UL ) );
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
    fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( fd_log_private_group ), group, FD_LOG_NAME_MAX-1UL ) );
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

/* User id */

static ulong
fd_log_private_user_id_default( void ) {
  return (ulong)getuid(); /* POSIX spec seems ambiguous as to whether or not this is a signed type */
}

static ulong fd_log_private_user_id;      /* 0 outside boot/halt, init on boot */
static int   fd_log_private_user_id_init;

void
fd_log_private_user_id_set( ulong user_id ) {
  fd_log_private_user_id      = user_id;
  fd_log_private_user_id_init = 1;
}

ulong
fd_log_user_id( void ) {
  if( FD_UNLIKELY( !fd_log_private_user_id_init ) ) {
    fd_log_private_user_id      = fd_log_private_user_id_default();
    fd_log_private_user_id_init = 1;
  }
  return fd_log_private_user_id;
}

/* User */

static char  fd_log_private_user[ FD_LOG_NAME_MAX ]; /* "" outside boot/halt, init on boot */

char const * fd_log_user( void ) { return fd_log_private_user; }

void
fd_log_private_user_set( char const * user ) {
  if( FD_UNLIKELY( !user ) || FD_UNLIKELY( user[0]=='\0') ) user = "[user]";
  if( FD_LIKELY( user!=fd_log_private_user ) )
    fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( fd_log_private_user ), user, FD_LOG_NAME_MAX-1UL ) );
}

int
fd_log_group_id_query( ulong group_id ) {
  if( group_id==fd_log_group_id() ) return FD_LOG_GROUP_ID_QUERY_LIVE; /* Avoid O/S call for self queries */
  pid_t pid = (pid_t)group_id;
  if( FD_UNLIKELY( ((group_id!=(ulong)pid) | (pid<=(pid_t)0)) ) ) return FD_LOG_GROUP_ID_QUERY_INVAL;
  if( !kill( (pid_t)group_id, 0 ) ) return FD_LOG_GROUP_ID_QUERY_LIVE;
  if( FD_LIKELY( errno==ESRCH ) ) return FD_LOG_GROUP_ID_QUERY_DEAD;
  if( FD_LIKELY( errno==EPERM ) ) return FD_LOG_GROUP_ID_QUERY_PERM;
  return FD_LOG_GROUP_ID_QUERY_FAIL;
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

    /* now is near the reference timestamp so we reuse the reference
       calculation timestamp. */

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

long
fd_log_sleep( long dt ) {
  if( FD_UNLIKELY( dt < 1L ) ) {
    sched_yield();
    return 0L;
  }

  /* dt is in [1,LONG_MAX] at this point */
  long ns_dt = fd_long_min( dt, (((long)1e9)<<31)-1L ); /* in [1,2^31*1e9) and <= dt at this point */
  dt -= ns_dt;

  struct timespec req[1];
  struct timespec rem[1];
  req->tv_sec  = (time_t)( ((ulong)ns_dt) / ((ulong)1e9) ); /* in [0,2^31-1] */
  req->tv_nsec = (long)  ( ((ulong)ns_dt) % ((ulong)1e9) ); /* in [0,1e9) */
  if( FD_UNLIKELY( nanosleep( req, rem ) ) && FD_LIKELY( errno==EINTR ) ) dt += ((long)1e9)*((long)rem->tv_sec) + rem->tv_nsec;
  return dt;
}

long
fd_log_wait_until( long then ) {
  long now;
  for(;;) {
    now = fd_log_wallclock();
    long rem = then - now;
    if( FD_LIKELY( rem<=0L ) ) break; /* we've waited long enough */
    if( FD_UNLIKELY( rem>(long)1e9 ) ) { /* long wait (over ~1 s) ... sleep until medium long */
      fd_log_sleep( rem-(long)0.1e9 );
      continue;
    }
    if( FD_UNLIKELY( rem>(long)0.1e9 ) ) { /* medium long wait (over ~0.1 s) ... yield */
      FD_YIELD();
      continue;
    }
    if( FD_UNLIKELY( rem>(long)1e3 ) ) { /* medium short wait (over ~1 us) ... hyperthreading friendly spin */
      FD_SPIN_PAUSE();
      continue;
    }
    /* short wait ... spin on fd_log_wallclock */
  }
  return now;
}

/* LOG APIS ***********************************************************/

char       fd_log_private_path[ 1024 ]; /* "" outside boot/halt, init at boot */
static int fd_log_private_fileno = -1;  /* -1 outside boot/halt, init at boot */
static int fd_log_private_dedup;        /*  0 outside boot/halt, init at boot */

void
fd_log_flush( void ) {
  int log_fileno = FD_VOLATILE_CONST( fd_log_private_fileno );
  if( FD_LIKELY( log_fileno!=-1 ) ) fsync( log_fileno );
}

static int fd_log_private_colorize;      /* 0 outside boot/halt, init at boot */
static int fd_log_private_level_logfile; /* 0 outside boot/halt, init at boot */
static int fd_log_private_level_stderr;  /* 0 outside boot/halt, init at boot */
static int fd_log_private_level_flush;   /* 0 outside boot/halt, init at boot */
static int fd_log_private_level_core;    /* 0 outside boot/halt, init at boot */

int fd_log_colorize     ( void ) { return FD_VOLATILE_CONST( fd_log_private_colorize      ); }
int fd_log_level_logfile( void ) { return FD_VOLATILE_CONST( fd_log_private_level_logfile ); }
int fd_log_level_stderr ( void ) { return FD_VOLATILE_CONST( fd_log_private_level_stderr  ); }
int fd_log_level_flush  ( void ) { return FD_VOLATILE_CONST( fd_log_private_level_flush   ); }
int fd_log_level_core   ( void ) { return FD_VOLATILE_CONST( fd_log_private_level_core    ); }

void fd_log_colorize_set     ( int mode  ) { FD_VOLATILE( fd_log_private_colorize      ) = mode;  }
void fd_log_level_logfile_set( int level ) { FD_VOLATILE( fd_log_private_level_logfile ) = level; }
void fd_log_level_stderr_set ( int level ) { FD_VOLATILE( fd_log_private_level_stderr  ) = level; }
void fd_log_level_flush_set  ( int level ) { FD_VOLATILE( fd_log_private_level_flush   ) = level; }
void fd_log_level_core_set   ( int level ) { FD_VOLATILE( fd_log_private_level_core    ) = level; }

/* Buffer size used for vsnprintf calls (this is also one more than the
   maximum size that this can passed to fd_io_write) */

#define FD_LOG_BUF_SZ (4UL*4096UL)

/* Lock to used by fd_log_private_fprintf_0 to sequence calls writes
   between different _processes_ that share the same fd. */

static int * fd_log_private_shared_lock; /* NULL outside boot/halt, init at boot */

static int fd_log_private_shared_lock_local[1] __attribute__((aligned(128))); /* location of lock if boot mmap fails */

void
fd_log_private_fprintf_0( int          fd,
                          char const * fmt, ... ) {

  /* Note: while this function superfically looks vdprintf-ish, we don't
     use that as it can do all sorts of unpleasantness under the hood
     (fflush, mutex / futex on fd, non-AS-safe buffering, ...) that this
     function deliberately avoids.  Also, the function uses the shared
     lock to help keep messages generated from processes that share the
     same log fd sane. */

  /* TODO:
     - Consider moving to util/io as fd_io_printf or renaming to
       fd_log_printf?
     - Is msg better to have on stack or in thread local storage?
     - Is msg even necessary given shared lock? (probably still useful to
       keep the message write to be a single-system-call best effort)
     - Allow partial write to fd_io_write?  (e.g. src_min=0 such that
       the fd_io_write below is guaranteed to be a single system call) */

  char msg[ FD_LOG_BUF_SZ ];

  va_list ap;
  va_start( ap, fmt );
  int len = vsnprintf( msg, FD_LOG_BUF_SZ, fmt, ap );
  if( len<0                        ) len = 0;                        /* cmov */
  if( len>(int)(FD_LOG_BUF_SZ-1UL) ) len = (int)(FD_LOG_BUF_SZ-1UL); /* cmov */
  msg[ len ] = '\0';
  va_end( ap );

# if FD_HAS_ATOMIC
  FD_COMPILER_MFENCE();
  while(( FD_LIKELY( FD_ATOMIC_CAS( fd_log_private_shared_lock, 0, 1 ) ) )) ;
  FD_COMPILER_MFENCE();
# endif

  ulong wsz;
  fd_io_write( fd, msg, (ulong)len, (ulong)len, &wsz ); /* Note: we ignore errors because what are we doing to do? log them? */

# if FD_HAS_ATOMIC
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *fd_log_private_shared_lock ) = 0;
  FD_COMPILER_MFENCE();
# endif

}

/* This is the same as fd_log_private_fprintf_0 except that it does not try to
   take a lock when writing to the log file.  This should almost never be used
   except in exceptional cases when logging while the process is shutting down.
   
   It exists because if a child process dies while holding the lock, we may
   want to log some diagnostic messages when tearing down the process tree. */
void
fd_log_private_fprintf_nolock_0( int          fd,
                                 char const * fmt, ... ) {

  /* Note: while this function superfically looks vdprintf-ish, we don't
     use that as it can do all sorts of unpleasantness under the hood
     (fflush, mutex / futex on fd, non-AS-safe buffering, ...) that this
     function deliberately avoids.  Also, the function uses the shared
     lock to help keep messages generated from processes that share the
     same log fd sane. */

  /* TODO:
     - Consider moving to util/io as fd_io_printf or renaming to
       fd_log_printf?
     - Is msg better to have on stack or in thread local storage?
     - Is msg even necessary given shared lock? (probably still useful to
       keep the message write to be a single-system-call best effort)
     - Allow partial write to fd_io_write?  (e.g. src_min=0 such that
       the fd_io_write below is guaranteed to be a single system call) */

  char msg[ FD_LOG_BUF_SZ ];

  va_list ap;
  va_start( ap, fmt );
  int len = vsnprintf( msg, FD_LOG_BUF_SZ, fmt, ap );
  if( len<0                        ) len = 0;                        /* cmov */
  if( len>(int)(FD_LOG_BUF_SZ-1UL) ) len = (int)(FD_LOG_BUF_SZ-1UL); /* cmov */
  msg[ len ] = '\0';
  va_end( ap );

# if FD_HAS_ATOMIC
  FD_COMPILER_MFENCE();
  while(( FD_LIKELY( FD_ATOMIC_CAS( fd_log_private_shared_lock, 0, 1 ) ) )) ;
  FD_COMPILER_MFENCE();
# endif

  ulong wsz;
  fd_io_write( fd, msg, (ulong)len, (ulong)len, &wsz ); /* Note: we ignore errors because what are we doing to do? log them? */

# if FD_HAS_ATOMIC
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *fd_log_private_shared_lock ) = 0;
  FD_COMPILER_MFENCE();
# endif

}

/* Log buffer used by fd_log_private_0 and fd_log_private_hexdump_msg */

static FD_TLS char fd_log_private_log_msg[ FD_LOG_BUF_SZ ];

char const *
fd_log_private_0( char const * fmt, ... ) {
  va_list ap;
  va_start( ap, fmt );
  int len = vsnprintf( fd_log_private_log_msg, FD_LOG_BUF_SZ, fmt, ap );
  if( len<0                        ) len = 0;                        /* cmov */
  if( len>(int)(FD_LOG_BUF_SZ-1UL) ) len = (int)(FD_LOG_BUF_SZ-1UL); /* cmov */
  fd_log_private_log_msg[ len ] = '\0';
  va_end( ap );
  return fd_log_private_log_msg;
}

char const *
fd_log_private_hexdump_msg( char const * descr,
                            void const * mem,
                            ulong        sz ) {

# define FD_LOG_HEXDUMP_BYTES_PER_LINE           (16UL)
# define FD_LOG_HEXDUMP_BLOB_DESCRIPTION_MAX_LEN (32UL)
# define FD_LOG_HEXDUMP_MAX_INPUT_BLOB_SZ        (1664UL) /* multiple of 128 >= 1542 */

# define FD_LOG_HEXDUMP_ADD_TO_LOG_BUF(...)  do { log_buf_ptr += fd_int_max( sprintf( log_buf_ptr, __VA_ARGS__ ), 0 ); } while(0)
  char * log_buf_ptr = fd_log_private_log_msg; /* used by FD_LOG_HEXDUMP_ADD_TO_LOG_BUF macro */

  /* Print the hexdump header */
  /* FIXME: consider additional sanitization of descr or using compiler
     tricks to prevent user from passing a non-const-char string (i.e.
     data they got from somewhere else that might not be sanitized). */

  if( FD_UNLIKELY( !descr ) ) {

    FD_LOG_HEXDUMP_ADD_TO_LOG_BUF( "HEXDUMP - (%lu bytes at 0x%lx)", sz, (ulong)mem );

  } else if( FD_UNLIKELY( strlen( descr )>FD_LOG_HEXDUMP_BLOB_DESCRIPTION_MAX_LEN ) ) {

    char tmp[ FD_LOG_HEXDUMP_BLOB_DESCRIPTION_MAX_LEN + 1UL ];
    fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( tmp ), descr, FD_LOG_HEXDUMP_BLOB_DESCRIPTION_MAX_LEN ) );
    FD_LOG_HEXDUMP_ADD_TO_LOG_BUF( "HEXDUMP \"%s\"... (%lu bytes at 0x%lx)", tmp, sz, (ulong)mem );

  } else {

    FD_LOG_HEXDUMP_ADD_TO_LOG_BUF( "HEXDUMP \"%s\" (%lu bytes at 0x%lx)", descr, sz, (ulong)mem );

  }

  if( FD_UNLIKELY( !sz ) ) return fd_log_private_log_msg;

  FD_LOG_HEXDUMP_ADD_TO_LOG_BUF( "\n" );

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_HEXDUMP_ADD_TO_LOG_BUF( "\t... snip (unreadable memory) ..." );
    return fd_log_private_log_msg;
  }

  char         line_buf[ FD_LOG_HEXDUMP_BYTES_PER_LINE+1 ];
  char const * blob     = (char const *)mem;
  ulong        blob_off = 0UL;
  ulong        blob_sz  = fd_ulong_min( sz, FD_LOG_HEXDUMP_MAX_INPUT_BLOB_SZ );

  for( ; blob_off<blob_sz; blob_off++ ) {
    ulong col_idx = blob_off % FD_LOG_HEXDUMP_BYTES_PER_LINE;

    /* New line. Print previous line's ASCII representation and then print the offset. */
    if( FD_UNLIKELY( !col_idx ) ) {
      if( FD_LIKELY( blob_off ) ) FD_LOG_HEXDUMP_ADD_TO_LOG_BUF( "  %s\n", line_buf );
      FD_LOG_HEXDUMP_ADD_TO_LOG_BUF( "\t%04lx: ", blob_off );
    }
    /* FIXME: consider extra space between col 7 and 8 to make easier
       for visual inspection */

    char c = blob[blob_off];
    FD_LOG_HEXDUMP_ADD_TO_LOG_BUF( " %02x", (uint)(uchar)c );

    /* If not a printable ASCII character, output a dot. */
    line_buf[ col_idx     ] = fd_char_if( isalnum( (int)c ) | ispunct( (int)c ) | (c==' '), c, '.' );
    line_buf[ col_idx+1UL ] = '\0';
  }

  /* Print the 2nd column of last blob line */
  while( blob_off % FD_LOG_HEXDUMP_BYTES_PER_LINE ) {
    FD_LOG_HEXDUMP_ADD_TO_LOG_BUF( "   " );
    blob_off++;
  }
  FD_LOG_HEXDUMP_ADD_TO_LOG_BUF( "  %s", line_buf );

  if( FD_UNLIKELY( blob_sz < sz ) )
    FD_LOG_HEXDUMP_ADD_TO_LOG_BUF( "\n\t... snip (printed %lu bytes, omitted %lu bytes) ...", blob_sz, sz-blob_sz );

  return fd_log_private_log_msg;

# undef FD_LOG_HEXDUMP_BYTES_PER_LINE
# undef FD_LOG_HEXDUMP_BLOB_DESCRIPTION_MAX_LEN
# undef FD_LOG_HEXDUMP_MAX_INPUT_BLOB_SZ
# undef FD_LOG_HEXDUMP_ADD_TO_LOG_BUF
}

void
fd_log_private_1( int          level,
                  long         now,
                  char const * file,
                  int          line,
                  char const * func,
                  char const * msg ) {

  if( level<fd_log_level_logfile() ) return;

  /* These are thread init so we call them regardless of permanent log
     enabled to their initialization time is guaranteed independent of
     whether the permanent log is enabled. */

  char const * thread = fd_log_thread();
  char const * cpu    = fd_log_cpu();
  ulong        tid    = fd_log_tid();

  int log_fileno = FD_VOLATILE_CONST( fd_log_private_fileno );
  int to_logfile = (log_fileno!=-1);
  int to_stderr  = (level>=fd_log_level_stderr());
  if( !(to_logfile | to_stderr) ) return;

  /* Deduplicate the log if requested */

  if( fd_log_private_dedup ) {

    /* Compute if this message appears to be a recent duplicate of
       a previous log message */

    ulong hash = fd_cstr_hash_append( fd_cstr_hash_append( fd_cstr_hash_append( fd_ulong_hash(
                   (ulong)(8L*(long)line+(long)level) ), file ), func ), msg );

    static long const dedup_interval = 20000000L; /* 1/50 s */

    static FD_TLS int   init;      /* 0   on thread start */
    static FD_TLS ulong last_hash; /* 0UL on thread start */
    static FD_TLS long  then;      /* 0L  on thread start */

    int is_dup = init & (hash==last_hash) & ((now-then)<dedup_interval);
    init = 1;

    /* Update how many messages from this thread in row have been
       duplicates */

    static FD_TLS ulong dedup_cnt;   /* 0UL on thread start */
    static FD_TLS int   in_dedup;    /* 0   on thread start */

    if( is_dup ) dedup_cnt++;
    else {
      if( in_dedup ) {

        /* This message appears to end a long string of duplicates.
           Log the end of the deduplication. */

        char then_cstr[ FD_LOG_WALLCLOCK_CSTR_BUF_SZ ];
        fd_log_wallclock_cstr( then, then_cstr );

        if( to_logfile )
          fd_log_private_fprintf_0( log_fileno, "SNIP    %s %6lu:%-6lu %s:%s:%-4s %s:%s:%-4s "
                                    "stopped repeating (%lu identical messages)\n",
                                    then_cstr, fd_log_group_id(),tid, fd_log_user(),fd_log_host(),cpu,
                                    fd_log_app(),fd_log_group(),thread, dedup_cnt+1UL );

        if( to_stderr ) {
          char * then_short_cstr = then_cstr+5; then_short_cstr[21] = '\0'; /* Lop off the year, ns resolution and timezone */
          fd_log_private_fprintf_0( STDERR_FILENO, "SNIP    %s %-6lu %-4s %-4s stopped repeating (%lu identical messages)\n",
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
        if( to_logfile )
          fd_log_private_fprintf_0( log_fileno, "SNIP    %s %6lu:%-6lu %s:%s:%-4s %s:%s:%-4s repeating (%lu identical messages)\n",
                                    now_cstr, fd_log_group_id(),tid, fd_log_user(),fd_log_host(),cpu,
                                    fd_log_app(),fd_log_group(),thread, dedup_cnt+1UL );
        if( to_stderr ) {
          char * now_short_cstr = now_cstr+5; now_short_cstr[21] = '\0'; /* Lop off the year, ns resolution and timezone */
          fd_log_private_fprintf_0( STDERR_FILENO, "SNIP    %s %-6lu %-4s %-4s repeating (%lu identical messages)\n",
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

  static char const * level_cstr[] = {
    /* 0 */ "DEBUG  ",
    /* 1 */ "INFO   ",
    /* 2 */ "NOTICE ",
    /* 3 */ "WARNING",
    /* 4 */ "ERR    ",
    /* 5 */ "CRIT   ",
    /* 6 */ "ALERT  ",
    /* 7 */ "EMERG  "
  };

  if( to_logfile )
    fd_log_private_fprintf_0( log_fileno, "%s %s %6lu:%-6lu %s:%s:%-4s %s:%s:%-4s %s(%i)[%s]: %s\n",
                              level_cstr[level], now_cstr, fd_log_group_id(),tid, fd_log_user(),fd_log_host(),cpu,
                              fd_log_app(),fd_log_group(),thread, file,line,func, msg );

  if( to_stderr ) {
    static char const * color_level_cstr[] = {
      /* 0 */ TEXT_NORMAL                                  "DEBUG  ",
      /* 1 */ TEXT_BLUE                                    "INFO   " TEXT_NORMAL,
      /* 2 */ TEXT_GREEN                                   "NOTICE " TEXT_NORMAL,
      /* 3 */ TEXT_YELLOW                                  "WARNING" TEXT_NORMAL,
      /* 4 */ TEXT_RED                                     "ERR    " TEXT_NORMAL,
      /* 5 */ TEXT_RED TEXT_BOLD                           "CRIT   " TEXT_NORMAL,
      /* 6 */ TEXT_RED TEXT_BOLD TEXT_UNDERLINE            "ALERT  " TEXT_NORMAL,
      /* 7 */ TEXT_RED TEXT_BOLD TEXT_UNDERLINE TEXT_BLINK "EMERG  " TEXT_NORMAL
    };
    char * now_short_cstr = now_cstr+5; now_short_cstr[21] = '\0'; /* Lop off the year, ns resolution and timezone */
    fd_log_private_fprintf_0( STDERR_FILENO, "%s %s %-6lu %-4s %-4s %s(%i): %s\n",
                              fd_log_private_colorize ? color_level_cstr[level] : level_cstr[level],
                              now_short_cstr, tid,cpu,thread, file, line, msg );
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

# if FD_LOG_UNCLEAN_EXIT
  if( level<fd_log_level_core() ) syscall(SYS_exit_group, 1);
# else
  if( level<fd_log_level_core() ) exit(1); /* atexit will call fd_log_private_cleanup implicitly */
# endif

  abort();
}

/* BOOT/HALT APIS *****************************************************/

static void
fd_log_private_cleanup( void ) {

  /* The atexit below means that all calls to "exit();" implicitly
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
     execute once per program.  Further, if cleanup gets triggered by
     multiple threads concurrently, the ONCE block will prevent them
     from progressing until the first thread that hits the once block
     has completed cleanup. */

  FD_ONCE_BEGIN {
    int log_fileno = FD_VOLATILE_CONST( fd_log_private_fileno );
    if(      log_fileno==-1                      ) fd_log_private_fprintf_0( STDERR_FILENO, "No log\n" );
    else if( !strcmp( fd_log_private_path, "-" ) ) fd_log_private_fprintf_0( STDERR_FILENO, "Log to stdout\n" );
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
        FD_VOLATILE( fd_log_private_fileno ) = -1; /* Turn off the permanent log for concurrent users */
        FD_COMPILER_MFENCE();
        usleep( (useconds_t)40000 ); /* Give any concurrent log operations progress at turn off a chance to wrap */
      }
#     else
      FD_VOLATILE( fd_log_private_fileno ) = -1;
#     endif

      fsync( log_fileno );
      sync();
      fd_log_private_fprintf_0( STDERR_FILENO, "Log at \"%s\"\n", fd_log_private_path );
    }
  } FD_ONCE_END;
}

#ifndef FD_LOG_UNCLEAN_EXIT
static void
fd_log_private_sig_abort( int         sig,
                          siginfo_t * info,
                          void *      context ) {
  (void)info; (void)context;

  /* Hopefully all out streams are idle now and we have flushed out
     all non-logging activity ... log a backtrace */

# if FD_HAS_BACKTRACE

  void * btrace[128];
  int btrace_cnt = backtrace( btrace, 128 );

  int log_fileno = FD_VOLATILE_CONST( fd_log_private_fileno );
  if( log_fileno!=-1 ) {
    fd_log_private_fprintf_0( log_fileno, "Caught signal %i, backtrace:\n", sig );
    backtrace_symbols_fd( btrace, btrace_cnt, log_fileno );
    fsync( log_fileno );
  }

  fd_log_private_fprintf_0( STDERR_FILENO, "\nCaught signal %i, backtrace:\n", sig );
  backtrace_symbols_fd( btrace, btrace_cnt, STDERR_FILENO );
  fsync( STDERR_FILENO );

# else /* !FD_HAS_BACKTRACE */

  int log_fileno = FD_VOLATILE_CONST( fd_log_private_fileno );
  if( log_fileno!=-1 ) fd_log_private_fprintf_0( log_fileno, "Caught signal %i.\n", sig );

  fd_log_private_fprintf_0( STDERR_FILENO, "\nCaught signal %i.\n", sig );

# endif /* FD_HAS_BACKTRACE */

  /* Do final log cleanup */

  fd_log_private_cleanup();

  usleep( (useconds_t)1000000 ); /* Give some time to let streams drain */

  raise( sig ); /* Continue with the original handler (probably the default and that will produce the core) */
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
#endif

void
fd_log_private_boot( int  *   pargc,
                     char *** pargv ) {
//FD_LOG_INFO(( "fd_log: booting" )); /* Log not online yet */

  char buf[ FD_LOG_NAME_MAX ];

  /* Try to allocate a _shared_ _anonymous_ page of memory for the
     fd_log_private_shared_lock such that the log can strictly sequence
     messages written by clones of the caller made after the caller has
     finished booting the log.  If this cannot be done, warn the caller
     and just try to use a local lock. */

  void * shmem = mmap( NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, (off_t)0 );
  if( FD_UNLIKELY( shmem==MAP_FAILED ) ) {
    fd_log_private_fprintf_0( STDERR_FILENO,
                              "mmap(NULL,sizeof(int),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,(off_t)0) (%i-%s); "
                              "log messages generated from clones (if any) may not be well sequenced; attempting to continue\n",
                              errno, fd_io_strerror( errno ) );
    shmem = fd_log_private_shared_lock_local;
  }
  fd_log_private_shared_lock = shmem;

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
  if( !host ) { if( !gethostname( buf, FD_LOG_NAME_MAX ) ) buf[ FD_LOG_NAME_MAX-1UL ] = '\0', host = buf; }
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

  fd_env_strip_cmdline_ulong( pargc, pargv, "--log-user-id", "FD_LOG_USER_ID", 0UL ); /* FIXME: LOG IGNORING? */
  fd_log_private_user_id_set( fd_log_private_user_id_default() );

  char const * user = fd_env_strip_cmdline_cstr( pargc, pargv, "--log-user", "FD_LOG_USER", NULL );
  if( !user )  user = getenv( "LOGNAME" );
  if( !user )  user = getlogin();
  fd_log_private_user_set( user );

  /* Configure the log */

  fd_log_private_dedup = fd_env_strip_cmdline_int( pargc, pargv, "--log-dedup", "FD_LOG_DEDUP", 1 );

  int colorize = 0;
  do {
    char const * cstr = fd_env_strip_cmdline_cstr( pargc, pargv, "--log-colorize", "FD_LOG_COLORIZE", NULL );
    if( cstr ) { colorize = fd_cstr_to_int( cstr ); break; }

    cstr = fd_env_strip_cmdline_cstr( NULL, NULL, NULL, "COLORTERM", NULL );
    if( cstr && !strcmp( cstr, "truecolor" ) ) { colorize = 1; break; }

    cstr = fd_env_strip_cmdline_cstr( NULL, NULL, NULL, "TERM", NULL );
    if( cstr && !strcmp( cstr, "xterm-256color" ) ) { colorize = 1; break; }

  } while(0);
  fd_log_colorize_set( colorize );

  fd_log_level_logfile_set( fd_env_strip_cmdline_int( pargc, pargv, "--log-level-logfile", "FD_LOG_LEVEL_LOGFILE", 1 ) );
  fd_log_level_stderr_set ( fd_env_strip_cmdline_int( pargc, pargv, "--log-level-stderr",  "FD_LOG_LEVEL_STDERR",  2 ) );
  fd_log_level_flush_set  ( fd_env_strip_cmdline_int( pargc, pargv, "--log-level-flush",   "FD_LOG_LEVEL_FLUSH",   3 ) );
  fd_log_level_core_set   ( fd_env_strip_cmdline_int( pargc, pargv, "--log-level-core",    "FD_LOG_LEVEL_CORE",    5 ) );

  /* Hook up signal handlers */

  int log_backtrace = fd_env_strip_cmdline_int( pargc, pargv, "--log-backtrace", "FD_LOG_BACKTRACE", 1 );
  if( log_backtrace ) {

#   if FD_HAS_BACKTRACE
    /* If libgcc isn't already linked into the program when a trapped
       signal is received by an application, calls to backtrace and
       backtrace_symbols_fd within the signal handler can silently
       invoke the dynamic linker, which in turn can do silent async
       signal unsafe behavior behind our back.  We do dummy calls to
       backtrace and backtrace_symbols_fd here to avoid dynamic linking
       surprises in the signal handler.  (Hat tip to runtimeverification
       for finding this.) */

    void * btrace[128];
    int btrace_cnt = backtrace( btrace, 128 );
    int fd = open( "/dev/null", O_WRONLY | O_APPEND );
    if( FD_UNLIKELY( fd==-1 ) )
      fd_log_private_fprintf_0( STDERR_FILENO,
                                "open( \"/dev/null\", O_WRONLY | O_APPEND ) failed (%i-%s); attempting to continue\n",
                                errno, fd_io_strerror( errno ) );
    else {
      backtrace_symbols_fd( btrace, btrace_cnt, fd );
      if( FD_UNLIKELY( close( fd ) ) )
        fd_log_private_fprintf_0( STDERR_FILENO,
                                  "close( \"/dev/null\" ) failed (%i-%s); attempting to continue\n",
                                  errno, fd_io_strerror( errno ) );
    }
#   endif /* FD_HAS_BACKTRACE */

    /* This is all overridable POSIX sigs whose default behavior is to
       abort the program.  It will backtrace and then fallback to the
       default behavior. */
#ifndef FD_LOG_UNCLEAN_EXIT
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
#endif
  }

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
    if( len==1023UL ) { fd_log_private_fprintf_0( STDERR_FILENO, "default log path too long; unable to boot\n" ); exit(1); }
  }
  else if( log_path_sz==1UL    ) fd_log_private_path[0] = '\0'; /* User disabled */
  else if( log_path_sz<=1024UL ) fd_memcpy( fd_log_private_path, log_path, log_path_sz ); /* User specified */
  else                          { fd_log_private_fprintf_0( STDERR_FILENO, "--log-path too long; unable to boot\n" ); exit(1); } /* Invalid */

  int log_fileno;
  if( fd_log_private_path[0]=='\0' ) {
    fd_log_private_fprintf_0( STDERR_FILENO, "--log-path \"\"\nNo log\n" );
    log_fileno = -1;
  } else if( !strcmp( fd_log_private_path, "-" ) ) {
    fd_log_private_fprintf_0( STDERR_FILENO, "--log-path \"-\"\nLog to stdout\n" );
    log_fileno = STDOUT_FILENO;
  } else {
    if( !log_path_sz ) fd_log_private_fprintf_0( STDERR_FILENO, "--log-path not specified; using autogenerated path\n" );
    log_fileno = open( fd_log_private_path, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH );
    if( log_fileno==-1 ) {
      fd_log_private_fprintf_0( STDERR_FILENO, "fopen failed (--log-path \"%s\"); unable to boot\n", fd_log_private_path );
      exit(1);
    }
    fd_log_private_fprintf_0( STDERR_FILENO, "Log at \"%s\"\n", fd_log_private_path );
  }
  FD_VOLATILE( fd_log_private_fileno ) = log_fileno;

  if( atexit( fd_log_private_cleanup ) ) { fd_log_private_fprintf_0( STDERR_FILENO, "atexit failed; unable to boot\n" ); exit(1); }

  /* At this point, logging online */
  if( fd_log_build_info_sz>1UL ) FD_LOG_INFO(( "fd_log: build info:\n%s", fd_log_build_info ));
  else                           FD_LOG_INFO(( "fd_log: build info not available"           ));
  FD_LOG_INFO(( "fd_log: --log-path          %s",  fd_log_private_path    ));
  FD_LOG_INFO(( "fd_log: --log-dedup         %i",  fd_log_private_dedup   ));
  FD_LOG_INFO(( "fd_log: --log-colorize      %i",  fd_log_colorize()      ));
  FD_LOG_INFO(( "fd_log: --log-level-logfile %i",  fd_log_level_logfile() ));
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
  FD_LOG_INFO(( "fd_log: --log-user-id       %lu", fd_log_user_id()       ));
  FD_LOG_INFO(( "fd_log: --log-user          %s",  fd_log_user()          ));

  FD_LOG_INFO(( "fd_log: boot success" ));
}

void
fd_log_private_halt( void ) {
  FD_LOG_INFO(( "fd_log: halting" ));

  fd_log_private_cleanup();

  /* At this point, log is offline */

  fd_log_private_path[0]        = '\0';
//fd_log_private_fileno         = -1;   /* Already handled by cleanup */
  fd_log_private_dedup          = 0;

  fd_log_private_level_core     = 0;
  fd_log_private_level_flush    = 0;
  fd_log_private_level_stderr   = 0;
  fd_log_private_level_logfile  = 0;
  fd_log_private_colorize       = 0;

  fd_log_private_user[0]        = '\0';
  fd_log_private_user_id_init   = 0;
  fd_log_private_user_id        = 0UL;
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

  if( FD_LIKELY( fd_log_private_shared_lock!=fd_log_private_shared_lock_local ) ) {
    /* Note: the below will not unmap this in any clones that also
       inherited this mapping unless they were cloned with CLONE_VM.  In
       cases like this, the caller is expected to handle the cleanup
       semantics sanely (e.g. only have the parent do boot/halt and then
       children only use log while parent has log booted). */
    if( FD_UNLIKELY( munmap( fd_log_private_shared_lock, sizeof(int) ) ) )
      fd_log_private_fprintf_0( STDERR_FILENO,
                                "munmap( fd_log_private_shared_lock, sizeof(int) ) failed (%i-%s); attempting to continue",
                                errno, fd_io_strerror( errno ) );
  }
  fd_log_private_shared_lock = NULL;

//FD_LOG_INFO(( "fd_log: halt success" )); /* Log not online anymore */
}

#include <sys/resource.h>

ulong
fd_log_private_main_stack_sz( void ) {

  /* We are extra paranoid about what rlimit returns and we don't trust
     environments that claim an unlimited stack size (because it just
     isn't unlimited ... even if rlimit says otherwise ... which it will
     if a user tries to be clever with a "ulimit -s unlimited" ... e.g.
     tile0's stack highest address is at 128 TiB-4KiB typically on
     modern Linux and grows down while the text / data / heap grow up
     from 0B ... so stack size is practically always going to be << 128
     TiB irrespective of any getrlimit claim).  TODO: It looks like
     pthead_attr_getstack might be getrlimit based under the hood, so
     maybe just use pthread_attr_getstack here too? */

  struct rlimit rlim[1];
  int err = getrlimit( RLIMIT_STACK, rlim );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "fd_log: getrlimit failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return 0UL;
  }

  ulong stack_sz = (ulong)rlim->rlim_cur;
  if( FD_UNLIKELY( (rlim->rlim_cur>rlim->rlim_max) | (rlim->rlim_max>RLIM_INFINITY    ) |
                   (rlim->rlim_cur==RLIM_INFINITY) | (rlim->rlim_cur!=(rlim_t)stack_sz) ) ) {
    FD_LOG_WARNING(( "fd_log: unexpected stack limits (rlim_cur %lu, rlim_max %lu)",
                     (ulong)rlim->rlim_cur, (ulong)rlim->rlim_max ));
    return 0UL;
  }

  return stack_sz;
}

/* When pthread_setstack is not used to explicitly set the memory region
   for a new thread's stack, pthread_create will create a memory region
   (using either the requested size or a default size).  And, while
   pthread allows us to set and get the size of the stack region it
   creates and we can get a pointer into a thread's stack by just
   declaring a stack variable in that thread and we obviously know where
   a thread's stack is when we explicitly specify it to pthread create,
   pthreads does not seem to provide a simple way to get the extents of
   the stacks it creates.

   But the relationship between a pointer in the stack and the stack
   extents is non-trival because pthreads will use some of the stack for
   things like thread local storage (and it will not tell us how much
   stack was used by that and this is practically only known after
   linking is complete and then it is not simply exposed to the
   application).

   Similar uncertainty applies to the first thread's stack.  We can
   learn how large the stack is and get a pointer into the stack via a
   stack variable but we have no simple way to get the extents.  And, in
   this case on recent Linux, things like command line strings and
   environment strings are typically allowed to consume up to 1/4 of
   main's thread stack ... these are only known at application load
   time.  (There is the additional caveat that the main stack might be
   dynamically allocated such that the address space reserved for it
   might not be backed by memory yet.)

   But, if we want to do useful run-time stack diagnostics (e.g. alloca
   bounds checking / stack overflow prevention / etc), having explicit
   knowledge of a thread's stack extents is very useful.  Hence the
   below.  It would be nice if there was portable and non-horrific way
   to do this (an even more horrific way is trigger seg faults by
   scanning for the guard pages and then recover from the seg fault via
   a longjmp ... shivers). */

void
fd_log_private_stack_discover( ulong   stack_sz,
                               ulong * _stack0,
                               ulong * _stack1 ) {

  if( FD_UNLIKELY( !stack_sz ) ) {
    *_stack0 = 0UL;
    *_stack1 = 0UL;
    return;
  }

  ulong stack0 = 0UL;
  ulong stack1 = 0UL;

  /* Create a variable on the caller's stack and scan the thread group's
     memory map for the memory region holding the variable.  That should
     be the caller's stack. */

  uchar stack_mem[1];
  FD_VOLATILE( stack_mem[0] ) = (uchar)1; /* Paranoia to make sure compiler puts this in stack */
  ulong stack_addr = (ulong)stack_mem;

  FILE * file = fopen( "/proc/self/maps", "r" );
  if( FD_UNLIKELY( !file ) )
    FD_LOG_WARNING(( "fopen( \"/proc/self/maps\", \"r\" ) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  else {

    while( FD_LIKELY( !feof( file ) ) ) {

      /* Get the next memory region */

      char buf[ 1024 ];
      if( FD_UNLIKELY( !fgets( buf, 1024UL, file ) ) ) break;
      ulong m0;
      ulong m1;
      if( FD_UNLIKELY( sscanf( buf, "%lx-%lx", &m0, &m1 )!=2 ) ) continue;

      /* Test if the stack allocation is in the discovered region */

      if( FD_UNLIKELY( (m0<=stack_addr) & (stack_addr<m1) ) ) {
        ulong msz = m1 - m0;
        if( msz==stack_sz ) { /* Memory region matches expectations */
          stack0 = m0;
          stack1 = m1;
        } else if( ((fd_log_group_id()==fd_log_tid()) & (msz<stack_sz)) ) {
          /* This is the main thread, which, on recent Linux, seems to
             just reserve address space for main's stack at program
             start up to the application stack size limits then uses
             page faults to dynamically back the stack with DRAM as the
             stack grows (which is awful for performance, jitter and
             reliability ... sigh).  This assumes stack grows down such
             that m1 is the fixed value in this process. */
          stack0 = m1 - stack_sz;
          stack1 = m1;
        } else {
          FD_LOG_WARNING(( "unexpected caller stack memory region size (got %lu bytes, expected %lu bytes)", msz, stack_sz ));
          /* don't trust the discovered region */
        }
        break;
      }

    }

    if( FD_UNLIKELY( fclose( file ) ) )
      FD_LOG_WARNING(( "fclose( \"/proc/self/maps\" ) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  }

  *_stack0 = stack0;
  *_stack1 = stack1;
}

#else
#error "Unknown FD_LOG_STYLE"
#endif
