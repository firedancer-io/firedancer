#include "../metrics/fd_metrics.h"
#include "../stem/fd_stem.h"
#include "../topo/fd_topo.h"

#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h> /* SEEK_SET */
#include <time.h>
#include <unistd.h>

#include "generated/fd_diag_tile_seccomp.h"

#define REPORT_INTERVAL_MILLIS (100L)

struct fd_diag_tile {
  long next_report_nanos;

  ulong tile_cnt;

  ulong starttime_nanos[ FD_TILE_MAX ];
  long  first_seen_died[ FD_TILE_MAX ];

  int stat_fds[ FD_TILE_MAX ];
  int sched_fds[ FD_TILE_MAX ];

  volatile ulong * metrics[ FD_TILE_MAX ];
};

typedef struct fd_diag_tile fd_diag_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_diag_tile_t ), sizeof( fd_diag_tile_t ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static int
read_stat_file( int              fd,
                ulong            ns_per_tick,
                volatile ulong * metrics ) {
  if( FD_UNLIKELY( -1==lseek( fd, 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));

  char contents[ 4096 ] = {0};
  ulong contents_len = 0UL;

  while( 1 ) {
    if( FD_UNLIKELY( contents_len>=sizeof( contents ) ) ) FD_LOG_ERR(( "stat contents overflow" ));
    long n = read( fd, contents + contents_len, sizeof( contents ) - contents_len );
    if( FD_UNLIKELY( -1==n ) ) {
      if( FD_UNLIKELY( errno==ESRCH ) ) return 1;
      FD_LOG_ERR(( "read failed (%i-%s)", errno, strerror( errno ) ));
    }
    if( FD_LIKELY( 0==n ) ) break;
    contents_len += (ulong)n;
  }

  /* Parse stat file: fields are space-separated.
     Field 10 (1-indexed) = minflt, field 12 = majflt,
     field 14 = utime, field 15 = stime (all in clock ticks). */
  char * saveptr;
  char * token = strtok_r( contents, " ", &saveptr );
  ulong field_idx = 0UL;

  while( token ) {
    if( FD_UNLIKELY( 9UL==field_idx ) ) {
      char * endptr;
      ulong minflt = strtoul( token, &endptr, 10 );
      if( FD_UNLIKELY( *endptr!='\0' || minflt==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul failed for minflt" ));
      metrics[ FD_METRICS_COUNTER_TILE_PAGE_FAULT_MINOR_COUNT_OFF ] = minflt;
    } else if( FD_UNLIKELY( 11UL==field_idx ) ) {
      char * endptr;
      ulong majflt = strtoul( token, &endptr, 10 );
      if( FD_UNLIKELY( *endptr!='\0' || majflt==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul failed for majflt" ));
      metrics[ FD_METRICS_COUNTER_TILE_PAGE_FAULT_MAJOR_COUNT_OFF ] = majflt;
    } else if( FD_UNLIKELY( 13UL==field_idx ) ) {
      char * endptr;
      ulong utime_ticks = strtoul( token, &endptr, 10 );
      if( FD_UNLIKELY( *endptr!='\0' || utime_ticks==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul failed for utime" ));
      metrics[ FD_METRICS_COUNTER_TILE_CPU_DURATION_NANOS_USER_OFF ] = utime_ticks*ns_per_tick;
    } else if( FD_UNLIKELY( 14UL==field_idx ) ) {
      char * endptr;
      ulong stime_ticks = strtoul( token, &endptr, 10 );
      if( FD_UNLIKELY( *endptr!='\0' || stime_ticks==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul failed for stime" ));
      metrics[ FD_METRICS_COUNTER_TILE_CPU_DURATION_NANOS_SYSTEM_OFF ] = stime_ticks*ns_per_tick;
      break; /* No need to parse stat further */
    }
    token = strtok_r( NULL, " ", &saveptr );
    field_idx++;
  }

  if( FD_UNLIKELY( field_idx!=14UL ) ) FD_LOG_ERR(( "stime (field 15) not found in stat" ));

  return 0;
}

static int
read_sched_file( int              fd,
                 volatile ulong * metrics ) {
  if( FD_UNLIKELY( -1==lseek( fd, 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));

  char contents[ 8192 ] = {0};
  ulong contents_len = 0UL;

  while( 1 ) {
    if( FD_UNLIKELY( contents_len>=sizeof( contents ) ) ) FD_LOG_ERR(( "sched contents overflow" ));
    long n = read( fd, contents + contents_len, sizeof( contents ) - contents_len );
    if( FD_UNLIKELY( -1==n ) ) {
      if( FD_UNLIKELY( errno==ESRCH ) ) return 1;
      FD_LOG_ERR(( "read failed (%i-%s)", errno, strerror( errno ) ));
    }
    if( FD_LIKELY( 0==n ) ) break;
    contents_len += (ulong)n;
  }

  int found_wait_sum = 0;
  int found_voluntary = 0;
  int found_involuntary = 0;

  char * line = contents;
  while( 1 ) {
    char * next_line = strchr( line, '\n' );
    if( FD_UNLIKELY( NULL==next_line ) ) break;
    *next_line = '\0';

    if( FD_UNLIKELY( !strncmp( line, "wait_sum", 8UL ) ) ) {
      char * colon = strchr( line, ':' );
      if( FD_LIKELY( colon ) ) {
        char * value = colon + 1;
        while( ' '==*value || '\t'==*value ) value++;
        /* wait_sum is displayed as seconds.microseconds (e.g., "123.456789").
           Parse both components as integers and convert to nanoseconds. */
        char * endptr;
        ulong seconds = strtoul( value, &endptr, 10 );
        if( FD_UNLIKELY( '.'!=*endptr ) ) FD_LOG_ERR(( "expected '.' after seconds in wait_sum" ));
        if( FD_UNLIKELY( seconds==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul overflow for wait_sum seconds" ));
        ulong microseconds = strtoul( endptr + 1, &endptr, 10 );
        if( FD_UNLIKELY( '\0'!=*endptr ) ) FD_LOG_ERR(( "unexpected char after microseconds in wait_sum" ));
        if( FD_UNLIKELY( microseconds==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul overflow for wait_sum microseconds" ));
        ulong wait_sum_ns = seconds*1000000000UL + microseconds*1000UL;
        metrics[ FD_METRICS_COUNTER_TILE_CPU_DURATION_NANOS_WAIT_OFF ] = wait_sum_ns;
        found_wait_sum = 1;
      }
    } else if( FD_UNLIKELY( !strncmp( line, "nr_voluntary_switches", 21UL ) ) ) {
      char * colon = strchr( line, ':' );
      if( FD_LIKELY( colon ) ) {
        char * value = colon + 1;
        while( ' '==*value || '\t'==*value ) value++;
        char * endptr;
        ulong voluntary_switches = strtoul( value, &endptr, 10 );
        if( FD_UNLIKELY( '\0'!=*endptr ) ) FD_LOG_ERR(( "unexpected char after nr_voluntary_switches" ));
        if( FD_UNLIKELY( voluntary_switches==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul overflow for nr_voluntary_switches" ));
        metrics[ FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_VOLUNTARY_COUNT_OFF ] = voluntary_switches;
        found_voluntary = 1;
      }
    } else if( FD_UNLIKELY( !strncmp( line, "nr_involuntary_switches", 23UL ) ) ) {
      char * colon = strchr( line, ':' );
      if( FD_LIKELY( colon ) ) {
        char * value = colon + 1;
        while( ' '==*value || '\t'==*value ) value++;
        char * endptr;
        ulong involuntary_switches = strtoul( value, &endptr, 10 );
        if( FD_UNLIKELY( '\0'!=*endptr ) ) FD_LOG_ERR(( "unexpected char after nr_involuntary_switches" ));
        if( FD_UNLIKELY( involuntary_switches==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul overflow for nr_involuntary_switches" ));
        metrics[ FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_INVOLUNTARY_COUNT_OFF ] = involuntary_switches;
        found_involuntary = 1;
      }
    }

    line = next_line + 1;
  }

  // wait_sum not present on kernels compiled without CONFIG_SCHEDSTATS=y
  // if( FD_UNLIKELY( !found_wait_sum ) ) FD_LOG_ERR(( "wait_sum not found in sched file" ));
  (void)found_wait_sum;
  if( FD_UNLIKELY( !found_voluntary ) ) FD_LOG_ERR(( "nr_voluntary_switches not found in sched file" ));
  if( FD_UNLIKELY( !found_involuntary ) ) FD_LOG_ERR(( "nr_involuntary_switches not found in sched file" ));

  return 0;
}

static void
before_credit( fd_diag_tile_t *    ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  long now = fd_log_wallclock();
  if( now<ctx->next_report_nanos ) {
    long diff = ctx->next_report_nanos - now;
    diff = fd_long_min( diff, 2e6 /* 2ms */ );
    struct timespec const ts = {
      .tv_sec  = diff / (long)1e9,
      .tv_nsec = diff % (long)1e9
    };
    clock_nanosleep( CLOCK_REALTIME, 0, &ts, NULL );
    return;
  }
  ctx->next_report_nanos += REPORT_INTERVAL_MILLIS*1000L*1000L;

  *charge_busy = 1;

  struct timespec boottime;
  if( FD_UNLIKELY( -1==clock_gettime( CLOCK_BOOTTIME, &boottime ) ) ) FD_LOG_ERR(( "clock_gettime(CLOCK_BOOTTIME) failed (%i-%s)", errno, strerror( errno ) ));
  ulong now_since_boot_nanos = (ulong)boottime.tv_sec*1000000000UL + (ulong)boottime.tv_nsec;

  for( ulong i=0UL; i<ctx->tile_cnt; i++ ) {
    if( FD_UNLIKELY( -1==ctx->stat_fds[ i ] ) ) continue;

    /* CLK_TCK is typically 100, so 1 tick = 10ms = 10,000,000 ns */
    int process_died1 = read_stat_file( ctx->stat_fds[ i ], 10000000UL, ctx->metrics[ i ] );
    int process_died2 = read_sched_file( ctx->sched_fds[ i ], ctx->metrics[ i ] );

    if( FD_UNLIKELY( process_died1 || process_died2 ) ) {
      ctx->stat_fds[ i ] = -1;
      continue;
    }

    ulong task_lifetime_nanos = now_since_boot_nanos - ctx->starttime_nanos[ i ];
    ulong user_nanos   = ctx->metrics[ i ][ FD_METRICS_COUNTER_TILE_CPU_DURATION_NANOS_USER_OFF ];
    ulong system_nanos = ctx->metrics[ i ][ FD_METRICS_COUNTER_TILE_CPU_DURATION_NANOS_SYSTEM_OFF ];
    ulong wait_nanos   = ctx->metrics[ i ][ FD_METRICS_COUNTER_TILE_CPU_DURATION_NANOS_WAIT_OFF ];
    ulong busy_nanos   = user_nanos+system_nanos+wait_nanos;
    ulong idle_nanos   = (task_lifetime_nanos>busy_nanos) ? (task_lifetime_nanos-busy_nanos) : 0UL;

    /* Counter can't go backwards in Prometheus else it thinks the
       application restarted.  Use max to ensure monotonicity. */
    ctx->metrics[ i ][ FD_METRICS_COUNTER_TILE_CPU_DURATION_NANOS_IDLE_OFF ] = fd_ulong_max( idle_nanos, ctx->metrics[ i ][ FD_METRICS_COUNTER_TILE_CPU_DURATION_NANOS_IDLE_OFF ] );
  }

  for( ulong i=0UL; i<ctx->tile_cnt; i++ ) {
    if( FD_LIKELY( -1!=ctx->stat_fds[ i ] ) ) continue;

    /* The tile died, but it's a tile which is allowed to shutdown, so
       just stop updating metrics for it. */
    if( FD_LIKELY( 2UL==ctx->metrics[ i ][ FD_METRICS_GAUGE_TILE_STATUS_OFF ] ) ) continue;

    /* Supervisor is going to bring the whole process tree down if any
       of the target PIDs died, so we can ignore this and wait. */
    if( FD_UNLIKELY( !ctx->first_seen_died[ i ] ) ) {
      ctx->first_seen_died[ i ] = now;
    } else if( FD_LIKELY( ctx->first_seen_died[ i ]==LONG_MAX ) ) {
      /* We already reported this, so we can ignore it. */
    } else if( FD_UNLIKELY( now-ctx->first_seen_died[ i ] < 10L*1000L*1000L*1000L ) ) {
      /* Wait 10 seconds for supervisor to kill us before reporting WARNING */
    } else {
      FD_LOG_WARNING(( "cannot get metrics for dead tile idx %lu", i ));
      ctx->first_seen_died[ i ] = LONG_MAX;
    }
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_diag_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_diag_tile_t), sizeof(fd_diag_tile_t) );

  FD_TEST( topo->tile_cnt<FD_TILE_MAX );

  FD_TEST( 100L == sysconf( _SC_CLK_TCK ) );

  ctx->tile_cnt = topo->tile_cnt;
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) {
    ctx->stat_fds[ i ]  = -1;
    ctx->sched_fds[ i ] = -1;
  }

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    ulong * metrics = fd_metrics_join( fd_topo_obj_laddr( topo, topo->tiles[ i ].metrics_obj_id ) );

    for(;;) {
      ulong pid, tid;
      if( FD_UNLIKELY( tile->id==i ) ) {
        pid = fd_sandbox_getpid();
        tid = fd_sandbox_gettid();
      } else {
        pid = fd_metrics_tile( metrics )[ FD_METRICS_GAUGE_TILE_PID_OFF ];
        tid = fd_metrics_tile( metrics )[ FD_METRICS_GAUGE_TILE_TID_OFF ];
        if( FD_UNLIKELY( !pid || !tid ) ) {
          FD_SPIN_PAUSE();
          continue;
        }
      }

      ctx->metrics[ i ] = fd_metrics_tile( metrics );

      char path[ 64UL ];
      FD_TEST( fd_cstr_printf_check( path, sizeof( path ), NULL, "/proc/%lu/task/%lu/stat", pid, tid ) );
      ctx->stat_fds[ i ] = open( path, O_RDONLY );
      if( FD_UNLIKELY( -1==ctx->stat_fds[ i ] ) ) {
        /* Might be a tile that's allowed to shutdown already did so
           before we got to here, due to a race condition.  Just
           proceed, we will not be able to get metrics for the shut
           down process. */
        if( FD_LIKELY( 2UL!=ctx->metrics[ i ][ FD_METRICS_GAUGE_TILE_STATUS_OFF ] ) ) FD_LOG_ERR(( "open stat failed (%i-%s)", errno, strerror( errno ) ));
        break;
      }

      FD_TEST( fd_cstr_printf_check( path, sizeof( path ), NULL, "/proc/%lu/task/%lu/sched", pid, tid ) );
      ctx->sched_fds[ i ] = open( path, O_RDONLY );
      if( FD_UNLIKELY( -1==ctx->sched_fds[ i ] ) ) {
        if( FD_LIKELY( 2UL!=ctx->metrics[ i ][ FD_METRICS_GAUGE_TILE_STATUS_OFF ] ) ) FD_LOG_ERR(( "open sched failed (%i-%s)", errno, strerror( errno ) ));
        ctx->stat_fds[ i ] = -1;
      }
      break;
    }
  }
}

/* Read starttime (field 22) from stat file. Returns 0 on success, 1 if
   process died (ESRCH). */

static int
read_starttime( int     fd,
                ulong   ns_per_tick,
                ulong * out_starttime_nanos ) {
  char contents[ 4096 ] = {0};
  ulong contents_len = 0UL;

  while( 1 ) {
    if( FD_UNLIKELY( contents_len>=sizeof( contents ) ) ) FD_LOG_ERR(( "stat contents overflow" ));
    long n = read( fd, contents + contents_len, sizeof( contents ) - contents_len );
    if( FD_UNLIKELY( -1==n ) ) {
      if( FD_UNLIKELY( errno==ESRCH ) ) return 1;
      FD_LOG_ERR(( "read stat failed (%i-%s)", errno, strerror( errno ) ));
    }
    if( FD_LIKELY( 0L==n ) ) break;
    contents_len += (ulong)n;
  }

  /* Parse field 22 (starttime) from stat file */
  char * saveptr;
  char * token = strtok_r( contents, " ", &saveptr );
  ulong field_idx = 0UL;

  while( token && field_idx<21UL ) {
    token = strtok_r( NULL, " ", &saveptr );
    field_idx++;
  }

  if( FD_UNLIKELY( !token || field_idx!=21UL ) ) FD_LOG_ERR(( "starttime (field 22) not found in stat" ));

  char * endptr;
  ulong starttime_ticks = strtoul( token, &endptr, 10 );
  if( FD_UNLIKELY( *endptr!=' ' && *endptr!='\0' ) ) FD_LOG_ERR(( "strtoul failed for starttime" ));
  if( FD_UNLIKELY( starttime_ticks==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul overflow for starttime" ));

  *out_starttime_nanos = starttime_ticks * ns_per_tick;
  return 0;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_diag_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_diag_tile_t), sizeof(fd_diag_tile_t) );

  memset( ctx->first_seen_died, 0, sizeof( ctx->first_seen_died ) );
  ctx->next_report_nanos = fd_log_wallclock();

  /* Read starttime (field 22) once at init for idle time calculation.
     CLK_TCK is always 100, so 1 tick = 10ms = 10,000,000 ns. */
  for( ulong i=0UL; i<ctx->tile_cnt; i++ ) {
    if( FD_LIKELY( -1!=ctx->stat_fds[ i ] ) ) {
      int died = read_starttime( ctx->stat_fds[ i ], 10000000UL, &ctx->starttime_nanos[ i ] );
      if( FD_UNLIKELY( died ) ) ctx->stat_fds[ i ] = -1;
    }
  }

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_diag_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_diag_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_diag_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_diag_tile_t), sizeof(fd_diag_tile_t) );

  if( FD_UNLIKELY( out_fds_cnt<2UL+2UL*ctx->tile_cnt ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  for( ulong i=0UL; i<ctx->tile_cnt; i++ ) {
    if( -1!=ctx->stat_fds[ i ] )  out_fds[ out_cnt++ ] = ctx->stat_fds[ i ];  /* /proc/<pid>/task/<tid>/stat */
    if( -1!=ctx->sched_fds[ i ] ) out_fds[ out_cnt++ ] = ctx->sched_fds[ i ]; /* /proc/<pid>/task/<tid>/sched */
  }
  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  ((long)10e6) /* 10ms */

#define STEM_CALLBACK_CONTEXT_TYPE  fd_diag_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_diag_tile_t)

#define STEM_CALLBACK_BEFORE_CREDIT before_credit

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_diag = {
  .name                     = "diag",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
