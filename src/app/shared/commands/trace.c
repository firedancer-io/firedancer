#include "../fd_action.h"
#include "../../platform/fd_cap_chk.h"
#include "../../../disco/topo/fd_topo.h"
#include "../../../disco/trace/fd_trace_export.h"
#include "../../../disco/metrics/fd_metrics.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <linux/capability.h>

/* Tile that busy polls metric links */

#define FXT_COLLECT_MAX 256 /* fxt source limit */

struct fxt_in {
  fd_frag_meta_t const * mcache;
  void const *           base;
  ulong                  seq;
  ulong                  depth;
};

typedef struct fxt_in fxt_in_t;

struct fxt_collect {
  fd_trace_fxt_o_t * fxt;

  uint rng_seed;

  fxt_in_t in[ FXT_COLLECT_MAX ];
  ulong    in_cnt;

  ulong drop_cnt;
};

typedef struct fxt_collect fxt_collect_t;

static void
fxt_collect_run( fxt_collect_t * collect,
                 char const *    out_path ) {

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, collect->rng_seed, 0UL ) );

  fxt_in_t * in     = collect->in;
  ulong      in_seq = 0UL;
  ulong      in_cnt = collect->in_cnt;
  if( FD_UNLIKELY( !in_cnt ) ) FD_LOG_ERR(( "no links to poll" ));

  long  lazy = (long)10e6; /* flush every 10ms */
  ulong async_min = fd_tempo_async_min( lazy, 1UL, (float)fd_tempo_tick_per_ns( NULL ) );

  FILE * out = collect->fxt->file;

  FD_LOG_NOTICE(( "Exporting events to %s", out_path ));
  long then = fd_tickcount();
  long now  = then;
  for(;;) {

    /* Do housekeeping at a low rate in the background */

    if( FD_UNLIKELY( (now-then)>=0L ) ) {
      if( FD_UNLIKELY( 0!=fflush( out ) ) ) FD_LOG_ERR(( "fflush(%s) failed: %i-%s", out_path, errno, fd_io_strerror( errno ) ));
      if( FD_UNLIKELY( collect->drop_cnt ) ) {
        FD_LOG_NOTICE(( "Detected %lu drop events", collect->drop_cnt ));
        collect->drop_cnt = 0UL;
      }

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    /* Select which in to poll next (randomized round robin) */

    if( FD_UNLIKELY( !in_cnt ) ) { now = fd_tickcount(); continue; }
    fxt_in_t * this_in = &in[ in_seq ];
    in_seq++;
    if( in_seq>=in_cnt ) in_seq = 0UL; /* cmov */

    /* Check if this in has any new fragments to consume */

    ulong                  this_in_seq   = this_in->seq;
    fd_frag_meta_t const * this_in_mline = this_in->mcache + fd_mcache_line_idx( this_in_seq, this_in->depth );

    ulong seq_found = fd_frag_meta_seq_query( this_in_mline );

    long diff = fd_seq_diff( this_in_seq, seq_found );
    if( FD_UNLIKELY( diff ) ) { /* Caught up or overrun, optimize for new frag case */
      if( FD_UNLIKELY( diff<0L ) ) { /* Overrun (impossible if in is honoring our flow control) */
        collect->drop_cnt++;
        this_in->seq = seq_found; /* Resume from here (probably reasonably current, could query in mcache sync directly instead) */
      }
      /* Don't bother with spin as polling multiple locations */
      now = fd_tickcount();
      continue;
    }

    /* We have a new fragment to consume */

    FD_COMPILER_MFENCE();
    ulong word0    =        this_in_mline->sig;
    ulong chunk    = (ulong)this_in_mline->chunk;
    ulong sz       = (ulong)this_in_mline->sz;
    ulong ctl      = (ulong)this_in_mline->ctl;
    ulong word1lo  = (ulong)this_in_mline->tsorig;
    ulong word2hi  = (ulong)this_in_mline->tspub;

    if( FD_UNLIKELY( !sz || !fd_ulong_is_aligned( sz, 8UL ) ) ) {
      FD_LOG_CRIT(( "Invalid FTF record size %#lx", sz ));
    }

    if( ctl ) {

      /* external record */
      void const * buf = fd_chunk_to_laddr_const( this_in->base, chunk );
      /* FIXME missing bounds check */
      ulong written = fwrite( buf, sz, 1UL, out );
      if( FD_UNLIKELY( written!=1UL ) ) FD_LOG_ERR(( "fwrite(%s,%lu bytes) failed: %i-%s", out_path, sz, errno, fd_io_strerror( errno ) ));

    } else {

      /* inline record */
      if( FD_UNLIKELY( sz>16UL ) ) FD_LOG_CRIT(( "Invalid internal FTF record size %#lx", sz ));
      ulong words[ 2 ] = { word0, word1lo+(word2hi<<32) };
      ulong written = fwrite( words, sz, 1UL, out );
      if( FD_UNLIKELY( written!=1UL ) ) FD_LOG_ERR(( "fwrite(%s,%lu bytes) failed: %i-%s", out_path, sz, errno, fd_io_strerror( errno ) ));

    }

    ulong seq_test = fd_frag_meta_seq_query( this_in_mline );

    if( FD_UNLIKELY( fd_seq_ne( seq_test, seq_found ) ) ) { /* Overrun while reading (impossible if this_in honoring our fctl) */
      this_in->seq = seq_test; /* Resume from here (probably reasonably current, could query in mcache sync instead) */
      /* FIXME recover from overrun */
      collect->drop_cnt++;
      /* Don't bother with spin as polling multiple locations */
      now = fd_tickcount();
      continue;
    }

    /* Windup for the next in poll */

    this_in_seq  = fd_seq_inc( this_in_seq, 1UL );
    this_in->seq = this_in_seq;
  }

  /* Technically unreachable ... */

  fd_rng_delete( fd_rng_leave( rng ) );

}

/* Command-line plumbing */

extern action_t * ACTIONS[];

static void
trace_args( int *    pargc,
            char *** pargv,
            args_t * args ) {
  char const * out_file  = fd_env_strip_cmdline_cstr( pargc, pargv, "--out-file", NULL, NULL );
  char const * topo_name = fd_env_strip_cmdline_cstr( pargc, pargv, "--topo",     NULL, ""   );
  if( !out_file ) FD_LOG_ERR(( "Usage: firedancer trace --out-file <trace.fxt>" ));
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( args->trace.fxt_path ), out_file,  sizeof(args->trace.fxt_path)-1UL ) );
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( args->trace.topo     ), topo_name, sizeof(args->trace.topo    )-1UL ) );
}

static void
reconstruct_topo( config_t *   config,
                  char const * topo_name ) {
  if( !topo_name[0] ) return; /* keep default action topo */

  action_t const * selected = NULL;
  for( action_t ** a=ACTIONS; a; a++ ) {
    action_t const * action = *a;
    if( 0==strcmp( action->name, topo_name ) ) {
      selected = action;
      break;
    }
  }

  if( !selected       ) FD_LOG_ERR(( "Unknown --topo %s", topo_name ));
  if( !selected->topo ) FD_LOG_ERR(( "Cannot recover topology for --topo %s", topo_name ));

  selected->topo( config );
}

static void
trace_fn( args_t *   args,
          config_t * config ) {
  reconstruct_topo( config, args->trace.topo );

  ulong metric_wksp_idx = fd_topo_find_wksp( &config->topo, "metric_in" );
  if( FD_UNLIKELY( metric_wksp_idx==ULONG_MAX ) ) FD_LOG_ERR(( "metric_in wksp not found" ));
  fd_topo_wksp_t * metric_wksp = &config->topo.workspaces[ metric_wksp_idx ];
  fd_topo_join_workspace( &config->topo, metric_wksp, FD_SHMEM_JOIN_MODE_READ_ONLY );

  /* Join FXT tracing shared memory rings */

  static fxt_collect_t collect[1];
  collect->rng_seed = (uint)fd_tickcount();
  for( ulong i=0UL; i<(config->topo.tile_cnt); i++ ) {
    fd_topo_tile_t const * tile = &config->topo.tiles[ i ];
    if( FD_UNLIKELY( tile->metrics_obj_id==ULONG_MAX ) ) continue;
    fd_topo_obj_t const * metrics_obj = &config->topo.objs[ tile->metrics_obj_id ];
    if( FD_UNLIKELY( metrics_obj->wksp_id!=metric_wksp_idx ) ) continue;
    ulong * metrics = (ulong *)( (ulong)metric_wksp->wksp + metrics_obj->offset );

    /* Found a new tile-metric region, join it */
    if( FD_UNLIKELY( collect->in_cnt>=FXT_COLLECT_MAX ) ) {
      FD_LOG_WARNING(( "Too many fxt sources, too many tiles? Only exporting the first %u", (uint)FXT_COLLECT_MAX ));
    }
    fxt_in_t * in = &collect->in[ collect->in_cnt++ ];
    in->mcache = fd_metrics_fxt_mcache_const( metrics ); FD_TEST( in->mcache );
    in->base   = fd_metrics_fxt_dcache_const( metrics ); FD_TEST( in->base   );
    in->seq    = 0UL;
    in->depth  = fd_mcache_depth( in->mcache );
    FD_LOG_NOTICE(( "Joined tile `%s`", tile->name ));
  }

  /* Set up a new FXT file */

  int trace_fd = open( args->trace.fxt_path, O_WRONLY|O_CREAT|O_TRUNC, 0664 );
  if( FD_UNLIKELY( trace_fd<0 ) ) FD_LOG_ERR(( "open(%s) failed (%i-%s)", args->trace.fxt_path, errno, fd_io_strerror( errno ) ));

  fd_trace_fxt_o_t writer[1];
  if( FD_UNLIKELY( !fd_trace_fxt_o_new( writer, trace_fd ) ) ) {
    FD_LOG_ERR(( "fd_trace_fxt_o_new failed" ));
  }
  int err = fd_trace_fxt_o_start( writer, &config->topo );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "Failed to write .fxt header: %i-%s", err, fd_io_strerror( err ) ));
  collect->fxt = writer;

  /* Busy poll events and export */

  fxt_collect_run( collect, args->trace.fxt_path );

  /* Done */

  fd_trace_fxt_o_delete( writer );
}

void
trace_perm( args_t *         args FD_PARAM_UNUSED,
            fd_cap_chk_t *   chk,
            config_t const * config ) {
  ulong mlock_limit = fd_topo_mlock( &config->topo );

  fd_cap_chk_raise_rlimit( chk, "trace", RLIMIT_MEMLOCK, mlock_limit, "call `rlimit(2)` to increase `RLIMIT_MEMLOCK` so all memory can be locked with `mlock(2)`" );

  if( fd_sandbox_requires_cap_sys_admin( config->uid, config->gid ) )
    fd_cap_chk_cap( chk, "trace", CAP_SYS_ADMIN,               "call `unshare(2)` with `CLONE_NEWUSER` to sandbox the process in a user namespace" );
  if( FD_LIKELY( getuid() != config->uid ) )
    fd_cap_chk_cap( chk, "trace", CAP_SETUID,                  "call `setresuid(2)` to switch uid to the sandbox user" );
  if( FD_LIKELY( getgid() != config->gid ) )
    fd_cap_chk_cap( chk, "trace", CAP_SETGID,                  "call `setresgid(2)` to switch gid to the sandbox user" );
}

action_t fd_action_trace = {
  .name        = "trace",
  .args        = trace_args,
  .fn          = trace_fn,
  .perm        = trace_perm,
  .description = "Export .fxt trace"
};
