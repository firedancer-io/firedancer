#define _GNU_SOURCE
#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"
#include "../../../disco/metrics/fd_metrics.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define CTXSW_MAX_TILES   FD_TILE_MAX
#define CTXSW_MAX_COMP    128UL /* per-CPU competing-task table size */

typedef struct {
  ulong tile_idx;       /* index into topo->tiles */
  ulong cpu_idx;
  ulong pid;
  ulong tid;

  /* schedstat snapshots: run_ns, wait_ns, slices */
  ulong run_ns_0,    run_ns_1;
  ulong wait_ns_0,   wait_ns_1;
  ulong slices_0,    slices_1;

  /* tile-self-reported metric snapshots */
  ulong nvcsw_0,  nvcsw_1;
  ulong nivcsw_0, nivcsw_1;

  /* perf fds (per-CPU, opened against cpu_idx) */
  int fd_ctxsw;
  int fd_migr;
  int fd_cycles;

  ulong ctxsw_count;   /* perf read */
  ulong migr_count;    /* perf read */
  ulong cycles_count;  /* perf read */

  /* sampling result: number of samples in window where this tile's own
     thread was the one currently running on its CPU */
  ulong on_cpu_samples;
} ctxsw_target_t;

typedef struct {
  ulong pid;
  ulong tid;
  char  comm[ 32 ];
  ulong samples; /* number of samples in window where this task was seen runnable on the cpu */
} ctxsw_comp_t;

typedef struct {
  ulong cpu_idx;
  ulong comp_cnt;
  ctxsw_comp_t comp[ CTXSW_MAX_COMP ];
  ulong overflow_cnt; /* number of distinct competitors we couldn't fit */
  ulong total_samples;
} ctxsw_cpu_t;

static long
ctxsw_perf_event_open( struct perf_event_attr * attr,
                       pid_t                    pid,
                       int                      cpu,
                       int                      group_fd,
                       unsigned long            flags ) {
  return syscall( SYS_perf_event_open, attr, pid, cpu, group_fd, flags );
}

static int
ctxsw_open_perf( uint type, ulong config, int cpu ) {
  struct perf_event_attr attr;
  memset( &attr, 0, sizeof(attr) );
  attr.type           = type;
  attr.size           = sizeof(attr);
  attr.config         = config;
  attr.disabled       = 1;
  attr.exclude_kernel = 0;
  attr.exclude_hv     = 1;
  attr.inherit        = 0;
  long fd = ctxsw_perf_event_open( &attr, -1, cpu, -1, 0UL );
  if( fd<0 ) return -1;
  return (int)fd;
}

/* Read /proc/<pid>/task/<tid>/schedstat into three counters.
   Returns 0 on success, -1 on failure. */
static int
ctxsw_read_schedstat( ulong   pid,
                      ulong   tid,
                      ulong * run_ns,
                      ulong * wait_ns,
                      ulong * slices ) {
  char path[ 128 ];
  snprintf( path, sizeof(path), "/proc/%lu/task/%lu/schedstat", pid, tid );
  FILE * f = fopen( path, "r" );
  if( !f ) return -1;
  int n = fscanf( f, "%lu %lu %lu", run_ns, wait_ns, slices );
  fclose( f );
  return n==3 ? 0 : -1;
}

/* Read /proc/<pid>/task/<tid>/stat and extract: comm (field 2), state
   (field 3), processor (field 39).  comm is bracketed and may contain
   parens/spaces; locate it via the last ')' as kernel docs recommend. */
static int
ctxsw_read_stat( ulong   pid,
                 ulong   tid,
                 char *  comm_out,   ulong comm_sz,
                 char *  state_out,
                 ulong * processor_out ) {
  char path[ 128 ];
  snprintf( path, sizeof(path), "/proc/%lu/task/%lu/stat", pid, tid );
  int fd = open( path, O_RDONLY );
  if( fd<0 ) return -1;
  char buf[ 4096 ];
  ssize_t n = read( fd, buf, sizeof(buf)-1UL );
  close( fd );
  if( n<=0 ) return -1;
  buf[ n ] = '\0';

  char * lp = strchr( buf, '(' );
  char * rp = strrchr( buf, ')' );
  if( !lp || !rp || rp<=lp ) return -1;

  ulong comm_len = (ulong)(rp - lp - 1);
  if( comm_len >= comm_sz ) comm_len = comm_sz - 1UL;
  memcpy( comm_out, lp+1, comm_len );
  comm_out[ comm_len ] = '\0';

  /* After ')' the fields are space-separated starting with state (field 3).
     We want field 3 (state) and field 39 (processor). After rp+2 (skip
     "ARGFLD ") we are at field 3. */
  char * p = rp + 2;
  *state_out = *p;

  /* skip ahead to field 39. We are currently at field 3, need to skip
     36 more fields. */
  for( int i=0; i<36; i++ ) {
    p = strchr( p, ' ' );
    if( !p ) return -1;
    p++;
  }
  *processor_out = strtoul( p, NULL, 10 );
  return 0;
}

/* Look up a competitor in the per-CPU table; insert if new.  Returns the
   slot, or NULL if the table is full (overflow). */
static ctxsw_comp_t *
ctxsw_comp_lookup( ctxsw_cpu_t * c, ulong tid ) {
  for( ulong i=0UL; i<c->comp_cnt; i++ ) {
    if( c->comp[ i ].tid==tid ) return &c->comp[ i ];
  }
  if( c->comp_cnt >= CTXSW_MAX_COMP ) {
    c->overflow_cnt++;
    return NULL;
  }
  ctxsw_comp_t * s = &c->comp[ c->comp_cnt++ ];
  memset( s, 0, sizeof(*s) );
  s->tid = tid;
  return s;
}

static int
ctxsw_cpu_for( ctxsw_cpu_t * cpus, ulong cpu_cnt, ulong cpu_idx ) {
  for( ulong i=0UL; i<cpu_cnt; i++ )
    if( cpus[ i ].cpu_idx==cpu_idx ) return (int)i;
  return -1;
}

/* Sweep all /proc task stat files and update per-CPU competitor tables.
   Also bumps on_cpu_samples for tile threads found running on their cpu. */
static void
ctxsw_sample_competitors( ctxsw_cpu_t *     cpus,
                          ulong             cpu_cnt,
                          ctxsw_target_t *  targets,
                          ulong             target_cnt ) {
  DIR * proc = opendir( "/proc" );
  if( !proc ) return;
  struct dirent * de;
  while( ( de = readdir( proc ) )!=NULL ) {
    if( de->d_name[0]<'0' || de->d_name[0]>'9' ) continue;
    ulong pid = strtoul( de->d_name, NULL, 10 );
    if( !pid ) continue;
    char tdir[ 64 ];
    snprintf( tdir, sizeof(tdir), "/proc/%lu/task", pid );
    DIR * td = opendir( tdir );
    if( !td ) continue;
    struct dirent * te;
    while( ( te = readdir( td ) )!=NULL ) {
      if( te->d_name[0]<'0' || te->d_name[0]>'9' ) continue;
      ulong tid = strtoul( te->d_name, NULL, 10 );
      if( !tid ) continue;
      char comm[ 32 ];
      char state;
      ulong processor;
      if( ctxsw_read_stat( pid, tid, comm, sizeof(comm), &state, &processor ) ) continue;
      int ci = ctxsw_cpu_for( cpus, cpu_cnt, processor );
      if( ci<0 ) continue; /* not a tile CPU */
      ctxsw_cpu_t * c = &cpus[ ci ];

      /* identify if this tid is a tile we already track on this CPU */
      int is_self_tile = 0;
      for( ulong t=0UL; t<target_cnt; t++ ) {
        if( targets[ t ].tid==tid ) {
          if( targets[ t ].cpu_idx==processor && state=='R' )
            targets[ t ].on_cpu_samples++;
          is_self_tile = 1;
          break;
        }
      }
      if( is_self_tile ) continue;
      if( state!='R' ) continue; /* only count actively-running competitors */
      c->total_samples++;
      ctxsw_comp_t * s = ctxsw_comp_lookup( c, tid );
      if( !s ) continue;
      if( !s->samples ) {
        s->pid = pid;
        strncpy( s->comm, comm, sizeof(s->comm)-1 );
        s->comm[ sizeof(s->comm)-1 ] = '\0';
      }
      s->samples++;
    }
    closedir( td );
  }
  closedir( proc );
}

static int
ctxsw_comp_cmp( const void * a, const void * b ) {
  const ctxsw_comp_t * ca = a;
  const ctxsw_comp_t * cb = b;
  if( cb->samples > ca->samples ) return 1;
  if( cb->samples < ca->samples ) return -1;
  return 0;
}

void
context_switch_cmd_args( int *    pargc,
                         char *** pargv,
                         args_t * args ) {
  args->context_switch.duration_s = fd_env_strip_cmdline_ulong( pargc, pargv, "--duration", NULL, 5UL );
}

void
context_switch_cmd_fn( args_t *   args,
                       config_t * config ) {
  fd_topo_t * topo = &config->topo;

  ulong duration_s = args->context_switch.duration_s;
  if( !duration_s ) duration_s = 5UL;

  /* Attach to all workspaces read-only so we can read tile metrics. */
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );

  /* Build the target list: every non-floating tile. */
  static ctxsw_target_t targets[ CTXSW_MAX_TILES ];
  ulong target_cnt = 0UL;

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    if( tile->cpu_idx>=ULONG_MAX ) continue; /* floating */
    if( target_cnt>=CTXSW_MAX_TILES ) break;
    ctxsw_target_t * t = &targets[ target_cnt++ ];
    memset( t, 0, sizeof(*t) );
    t->tile_idx = i;
    t->cpu_idx  = tile->cpu_idx;
    t->fd_ctxsw = -1;
    t->fd_migr  = -1;
    t->fd_cycles= -1;
    t->pid = fd_metrics_tile( tile->metrics )[ FD_METRICS_GAUGE_TILE_PID_OFF ];
    t->tid = fd_metrics_tile( tile->metrics )[ FD_METRICS_GAUGE_TILE_TID_OFF ];
    t->nvcsw_0  = fd_metrics_tile( tile->metrics )[ FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_VOLUNTARY_COUNT_OFF   ];
    t->nivcsw_0 = fd_metrics_tile( tile->metrics )[ FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_INVOLUNTARY_COUNT_OFF ];
    if( !t->tid ) {
      FD_LOG_WARNING(( "tile %s:%lu has no TID published yet; skipping", tile->name, tile->kind_id ));
      target_cnt--;
      continue;
    }
  }

  if( !target_cnt ) FD_LOG_ERR(( "no pinned tiles found" ));

  /* Build the per-CPU table (one entry per distinct cpu_idx in targets). */
  static ctxsw_cpu_t cpus[ CTXSW_MAX_TILES ];
  ulong cpu_cnt = 0UL;
  for( ulong i=0UL; i<target_cnt; i++ ) {
    if( ctxsw_cpu_for( cpus, cpu_cnt, targets[ i ].cpu_idx )>=0 ) continue;
    cpus[ cpu_cnt ].cpu_idx       = targets[ i ].cpu_idx;
    cpus[ cpu_cnt ].comp_cnt      = 0UL;
    cpus[ cpu_cnt ].overflow_cnt  = 0UL;
    cpus[ cpu_cnt ].total_samples = 0UL;
    cpu_cnt++;
  }

  /* Open per-CPU perf counters.  Failures are non-fatal: just leave the
     fd as -1 and the report will show "n/a". */
  int perf_warned = 0;
  for( ulong i=0UL; i<target_cnt; i++ ) {
    ctxsw_target_t * t = &targets[ i ];
    t->fd_ctxsw  = ctxsw_open_perf( PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES, (int)t->cpu_idx );
    t->fd_migr   = ctxsw_open_perf( PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_MIGRATIONS,   (int)t->cpu_idx );
    t->fd_cycles = ctxsw_open_perf( PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES,       (int)t->cpu_idx );
    if( t->fd_ctxsw<0 && !perf_warned ) {
      FD_LOG_WARNING(( "perf_event_open(CONTEXT_SWITCHES, cpu=%lu) failed (%i-%s); "
                       "needs CAP_PERFMON, CAP_SYS_ADMIN, or kernel.perf_event_paranoid<=0",
                       t->cpu_idx, errno, fd_io_strerror( errno ) ));
      perf_warned = 1;
    }
    if( t->fd_ctxsw >=0 ) { ioctl( t->fd_ctxsw,  PERF_EVENT_IOC_RESET, 0 ); ioctl( t->fd_ctxsw,  PERF_EVENT_IOC_ENABLE, 0 ); }
    if( t->fd_migr  >=0 ) { ioctl( t->fd_migr,   PERF_EVENT_IOC_RESET, 0 ); ioctl( t->fd_migr,   PERF_EVENT_IOC_ENABLE, 0 ); }
    if( t->fd_cycles>=0 ) { ioctl( t->fd_cycles, PERF_EVENT_IOC_RESET, 0 ); ioctl( t->fd_cycles, PERF_EVENT_IOC_ENABLE, 0 ); }
  }

  /* Snapshot schedstat. */
  for( ulong i=0UL; i<target_cnt; i++ ) {
    ctxsw_target_t * t = &targets[ i ];
    if( ctxsw_read_schedstat( t->pid, t->tid, &t->run_ns_0, &t->wait_ns_0, &t->slices_0 ) ) {
      FD_LOG_WARNING(( "could not read schedstat for tile %s:%lu (pid=%lu tid=%lu)",
                       topo->tiles[ t->tile_idx ].name,
                       topo->tiles[ t->tile_idx ].kind_id,
                       t->pid, t->tid ));
    }
  }

  FD_LOG_NOTICE(( "collecting context-switch info for %lu seconds across %lu tiles on %lu CPUs",
                  duration_s, target_cnt, cpu_cnt ));

  /* Sample loop: every 50 ms, sweep /proc to identify competitors. */
  long start_ns    = fd_log_wallclock();
  long deadline_ns = start_ns + (long)duration_s * 1000L*1000L*1000L;
  long next_ns     = start_ns;
  ulong sweep_cnt  = 0UL;
  for(;;) {
    long now = fd_log_wallclock();
    if( now>=deadline_ns ) break;
    if( now<next_ns ) {
      struct timespec ts = { 0, (next_ns-now) };
      nanosleep( &ts, NULL );
      continue;
    }
    ctxsw_sample_competitors( cpus, cpu_cnt, targets, target_cnt );
    sweep_cnt++;
    next_ns += 50L*1000L*1000L;
  }

  /* Snapshot schedstat + tile metrics again, read perf counters. */
  for( ulong i=0UL; i<target_cnt; i++ ) {
    ctxsw_target_t *       t    = &targets[ i ];
    fd_topo_tile_t const * tile = &topo->tiles[ t->tile_idx ];
    ctxsw_read_schedstat( t->pid, t->tid, &t->run_ns_1, &t->wait_ns_1, &t->slices_1 );
    t->nvcsw_1  = fd_metrics_tile( tile->metrics )[ FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_VOLUNTARY_COUNT_OFF   ];
    t->nivcsw_1 = fd_metrics_tile( tile->metrics )[ FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_INVOLUNTARY_COUNT_OFF ];
    if( t->fd_ctxsw>=0 ) {
      ioctl( t->fd_ctxsw, PERF_EVENT_IOC_DISABLE, 0 );
      if( read( t->fd_ctxsw, &t->ctxsw_count, sizeof(ulong) )!=(ssize_t)sizeof(ulong) ) t->ctxsw_count = ULONG_MAX;
      close( t->fd_ctxsw );
    } else t->ctxsw_count = ULONG_MAX;
    if( t->fd_migr>=0 ) {
      ioctl( t->fd_migr, PERF_EVENT_IOC_DISABLE, 0 );
      if( read( t->fd_migr, &t->migr_count, sizeof(ulong) )!=(ssize_t)sizeof(ulong) ) t->migr_count = ULONG_MAX;
      close( t->fd_migr );
    } else t->migr_count = ULONG_MAX;
    if( t->fd_cycles>=0 ) {
      ioctl( t->fd_cycles, PERF_EVENT_IOC_DISABLE, 0 );
      if( read( t->fd_cycles, &t->cycles_count, sizeof(ulong) )!=(ssize_t)sizeof(ulong) ) t->cycles_count = ULONG_MAX;
      close( t->fd_cycles );
    } else t->cycles_count = ULONG_MAX;
  }

  long actual_ns = fd_log_wallclock() - start_ns;
  double actual_s = (double)actual_ns / 1e9;

  /* Report. */
  printf( "\n" );
  printf( "context-switch report (window: %.3fs, %lu sweeps @ ~50ms)\n", actual_s, sweep_cnt );
  printf( "\n" );
  printf( "%-12s %-3s %-4s %-7s %-7s %12s %12s %10s %10s %7s %7s %7s\n",
          "tile", "id", "cpu", "pid", "tid",
          "ksw(perf)", "migr(perf)", "nvcsw", "nivcsw",
          "%run", "%wait", "%other" );
  printf( "%-12s %-3s %-4s %-7s %-7s %12s %12s %10s %10s %7s %7s %7s\n",
          "------------", "---", "----", "-------", "-------",
          "------------", "------------", "----------", "----------",
          "-------", "-------", "-------" );

  for( ulong i=0UL; i<target_cnt; i++ ) {
    ctxsw_target_t *       t    = &targets[ i ];
    fd_topo_tile_t const * tile = &topo->tiles[ t->tile_idx ];

    ulong run_d  = t->run_ns_1  - t->run_ns_0;
    ulong wait_d = t->wait_ns_1 - t->wait_ns_0;
    double pct_run  = 100.0 * (double)run_d  / (double)actual_ns;
    double pct_wait = 100.0 * (double)wait_d / (double)actual_ns;
    double pct_other = 100.0 - pct_run - pct_wait;
    if( pct_other<0.0 ) pct_other = 0.0;

    char ksw_s [ 24 ]; char migr_s[ 24 ];
    if( t->ctxsw_count==ULONG_MAX ) snprintf( ksw_s,  sizeof(ksw_s),  "n/a" );
    else                            snprintf( ksw_s,  sizeof(ksw_s),  "%lu", t->ctxsw_count );
    if( t->migr_count ==ULONG_MAX ) snprintf( migr_s, sizeof(migr_s), "n/a" );
    else                            snprintf( migr_s, sizeof(migr_s), "%lu", t->migr_count  );

    printf( "%-12s %-3lu %-4lu %-7lu %-7lu %12s %12s %10lu %10lu %6.2f%% %6.2f%% %6.2f%%\n",
            tile->name, tile->kind_id, t->cpu_idx, t->pid, t->tid,
            ksw_s, migr_s,
            t->nvcsw_1 - t->nvcsw_0,
            t->nivcsw_1 - t->nivcsw_0,
            pct_run, pct_wait, pct_other );
  }

  printf( "\n  ksw(perf):  PERF_COUNT_SW_CONTEXT_SWITCHES on the tile's CPU (includes all tasks scheduled on that CPU)\n" );
  printf( "  migr(perf): PERF_COUNT_SW_CPU_MIGRATIONS on the tile's CPU\n" );
  printf( "  nvcsw/nivcsw: tile-self-reported voluntary/involuntary switches (getrusage) over the window\n" );
  printf( "  %%run/%%wait: tile thread time on-CPU / runnable-but-waiting, from /proc/[tid]/schedstat\n" );
  printf( "  %%other: time the thread was neither running nor runnable (sleeping in a syscall, blocked, etc.)\n" );

  /* Per-CPU competitor breakdown. */
  printf( "\ncompeting tasks observed on tile CPUs (top by sample count; %lu sweeps total)\n", sweep_cnt );
  for( ulong i=0UL; i<cpu_cnt; i++ ) {
    ctxsw_cpu_t * c = &cpus[ i ];

    /* find which tile(s) own this cpu, for context */
    char owner_buf[ 128 ];
    int  off = 0;
    for( ulong j=0UL; j<target_cnt; j++ ) {
      if( targets[ j ].cpu_idx!=c->cpu_idx ) continue;
      fd_topo_tile_t const * tile = &topo->tiles[ targets[ j ].tile_idx ];
      int w = snprintf( owner_buf+off, sizeof(owner_buf)-(ulong)off, "%s%s:%lu",
                        off?",":"", tile->name, tile->kind_id );
      if( w<=0 || off+w>=(int)sizeof(owner_buf) ) break;
      off += w;
    }
    owner_buf[ sizeof(owner_buf)-1 ] = '\0';

    /* on-cpu fraction for the tile itself */
    ulong on_cpu = 0UL;
    for( ulong j=0UL; j<target_cnt; j++ ) {
      if( targets[ j ].cpu_idx==c->cpu_idx ) on_cpu += targets[ j ].on_cpu_samples;
    }

    printf( "\n  cpu %lu  (tile: %s)\n", c->cpu_idx, owner_buf );
    if( sweep_cnt ) {
      printf( "    tile thread was the current task in %lu/%lu sweeps (%.1f%%)\n",
              on_cpu, sweep_cnt, 100.0 * (double)on_cpu / (double)sweep_cnt );
    }
    if( !c->comp_cnt ) {
      printf( "    no competing runnable tasks observed\n" );
      continue;
    }
    qsort( c->comp, c->comp_cnt, sizeof(ctxsw_comp_t), ctxsw_comp_cmp );
    ulong show = c->comp_cnt < 8UL ? c->comp_cnt : 8UL;
    printf( "    %-7s %-7s %-20s %10s\n", "pid", "tid", "comm", "samples" );
    for( ulong j=0UL; j<show; j++ ) {
      ctxsw_comp_t * s = &c->comp[ j ];
      printf( "    %-7lu %-7lu %-20s %10lu\n", s->pid, s->tid, s->comm, s->samples );
    }
    if( c->comp_cnt > show ) {
      printf( "    ... (%lu more)\n", c->comp_cnt - show );
    }
    if( c->overflow_cnt ) {
      printf( "    note: %lu samples from competitors exceeded the per-CPU table size\n", c->overflow_cnt );
    }
  }
  printf( "\n" );
}

action_t fd_action_context_switch = {
  .name           = "context-switch",
  .args           = context_switch_cmd_args,
  .fn             = context_switch_cmd_fn,
  .require_config = 1,
  .perm           = NULL,
  .description    = "Sample tile CPUs for ~5 seconds and report context-switch activity and competing tasks",
};
