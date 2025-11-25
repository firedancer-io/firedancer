#include "../metrics/fd_metrics.h"
#include "../stem/fd_stem.h"
#include "../topo/fd_topo.h"

#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h> /* SEEK_SET */
#include <time.h>
#include <unistd.h>

#include "generated/fd_cswtch_tile_seccomp.h"

#define REPORT_INTERVAL_MILLIS (100L)

typedef struct {
  long next_report_nanos;

  ulong            tile_cnt;
  long             first_seen_died[ FD_TILE_MAX ];
  int              status_fds[ FD_TILE_MAX ];
  volatile ulong * metrics[ FD_TILE_MAX ];
} fd_cswtch_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_cswtch_ctx_t ), sizeof( fd_cswtch_ctx_t ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
before_credit( fd_cswtch_ctx_t *   ctx,
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

  for( ulong i=0UL; i<ctx->tile_cnt; i++ ) {
    if( FD_UNLIKELY( -1==lseek( ctx->status_fds[ i ], 0, SEEK_SET ) ) ) FD_LOG_ERR(( "lseek failed (%i-%s)", errno, strerror( errno ) ));

    char contents[ 4096 ] = {0};
    ulong contents_len = 0UL;

    int process_died = 0;
    while( 1 ) {
      if( FD_UNLIKELY( contents_len>=sizeof( contents ) ) ) FD_LOG_ERR(( "contents overflow" ));
      long n = read( ctx->status_fds[ i ], contents + contents_len, sizeof( contents ) - contents_len );
      if( FD_UNLIKELY( -1==n ) ) {
        if( FD_UNLIKELY( errno==ESRCH ) ) {
          process_died = 1;
          break;
        }
        FD_LOG_ERR(( "read failed (%i-%s)", errno, strerror( errno ) ));
      }
      if( FD_LIKELY( 0==n ) ) break;
      contents_len += (ulong)n;
    }

    if( FD_UNLIKELY( process_died ) ) {
      /* The tile died, but it's a tile which is allowed to shutdown, so
         just stop updating metrics for it. */
      if( FD_UNLIKELY( ctx->metrics[ i ][ FD_METRICS_GAUGE_TILE_STATUS_OFF ] ) ) continue;
    }

    /* Supervisor is going to bring the whole process tree down if any
       of the target PIDs died, so we can ignore this and wait. */
    if( FD_UNLIKELY( process_died ) ) {
      if( FD_UNLIKELY( !ctx->first_seen_died[ i ] ) ) {
        ctx->first_seen_died[ i ] = now;
      } else if( FD_LIKELY( ctx->first_seen_died[ i ]==LONG_MAX ) ) {
        /* We already reported this, so we can ignore it. */
      } else if( FD_UNLIKELY( now-ctx->first_seen_died[ i ] < 10L*1000L*1000L*1000L ) ) {
        /* Wait 10 seconds for supervisor to kill us before reporting WARNING */
      } else {
        FD_LOG_WARNING(( "cannot get context switch metrics for dead tile idx %lu", i ));
        ctx->first_seen_died[ i ] = LONG_MAX;
      }
      continue;
    }

    int found_voluntary = 0;
    int found_involuntary = 0;

    char * line = contents;
    while( 1 ) {
      char * next_line = strchr( line, '\n' );
      if( FD_UNLIKELY( NULL==next_line ) ) break;
      *next_line = '\0';

      char * colon = strchr( line, ':' );
      if( FD_UNLIKELY( NULL==colon ) ) FD_LOG_ERR(( "no colon in line '%s'", line ));

      *colon = '\0';
      char * key = line;
      char * value = colon + 1;

      while( ' '==*value || '\t'==*value ) value++;

      if( FD_LIKELY( !strncmp( key, "voluntary_ctxt_switches", 23UL ) ) ) {
        char * endptr;
        ulong voluntary_ctxt_switches = strtoul( value, &endptr, 10 );
        if( FD_UNLIKELY( *endptr!='\0' || voluntary_ctxt_switches==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul failed" ));
        ctx->metrics[ i ][ FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_VOLUNTARY_COUNT_OFF ] = voluntary_ctxt_switches;
        found_voluntary = 1;
      } else if( FD_LIKELY( !strncmp( key, "nonvoluntary_ctxt_switches", 26UL ) ) ) {
        char * endptr;
        ulong involuntary_ctxt_switches = strtoul( value, &endptr, 10 );
        if( FD_UNLIKELY( *endptr!='\0' || involuntary_ctxt_switches==ULONG_MAX ) ) FD_LOG_ERR(( "strtoul failed" ));
        ctx->metrics[ i ][ FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_INVOLUNTARY_COUNT_OFF ] = involuntary_ctxt_switches;
        found_involuntary = 1;
      }

      line = next_line + 1;
    }

    if( FD_UNLIKELY( !found_voluntary   ) ) FD_LOG_ERR(( "voluntary_ctxt_switches not found" ));
    if( FD_UNLIKELY( !found_involuntary ) ) FD_LOG_ERR(( "nonvoluntary_ctxt_switches not found" ));
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_cswtch_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_cswtch_ctx_t ), sizeof( fd_cswtch_ctx_t ) );

  FD_TEST( topo->tile_cnt<FD_TILE_MAX );

  ctx->tile_cnt = topo->tile_cnt;
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

      char path[ 64 ];
      FD_TEST( fd_cstr_printf_check( path, sizeof( path ), NULL, "/proc/%lu/task/%lu/status", pid, tid ) );
      ctx->status_fds[ i ] = open( path, O_RDONLY );
      ctx->metrics[ i ] = fd_metrics_tile( metrics );
      if( FD_UNLIKELY( -1==ctx->status_fds[ i ] ) ) FD_LOG_ERR(( "open failed (%i-%s)", errno, strerror( errno ) ));
      break;
    }
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_cswtch_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_cswtch_ctx_t ), sizeof( fd_cswtch_ctx_t ) );

  memset( ctx->first_seen_died, 0, sizeof( ctx->first_seen_died ) );
  ctx->next_report_nanos = fd_log_wallclock();

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

  populate_sock_filter_policy_fd_cswtch_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_cswtch_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_cswtch_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_cswtch_ctx_t ), sizeof( fd_cswtch_ctx_t ) );

  if( FD_UNLIKELY( out_fds_cnt<2UL+ctx->tile_cnt ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  for( ulong i=0UL; i<ctx->tile_cnt; i++ )
    out_fds[ out_cnt++ ] = ctx->status_fds[ i ]; /* /proc/<pid>/task/<tid>/status descriptor */
  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  ((long)10e6) /* 10ms */
#define STEM_IDLE_SLEEP_ENABLED (0)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_cswtch_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_cswtch_ctx_t)

#define STEM_CALLBACK_BEFORE_CREDIT before_credit

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_cswtch = {
  .name                     = "cswtch",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
