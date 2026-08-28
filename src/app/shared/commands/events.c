#include "../fd_config.h"
#include "../fd_action.h"
#include "../fd_bootinfo.h"

#include "../../../disco/events/fd_event_report.h"
#include "../../../disco/events/generated/fd_event_gen.h"
#include "../../../disco/fd_clock_tile.h"
#include "../../../disco/metrics/fd_metrics.h"

#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>

extern action_t * ACTIONS[];

static void
events_cmd_args( int *    pargc,
                 char *** pargv,
                 args_t * args ) {
  char const * topo_name = fd_env_strip_cmdline_cstr( pargc, pargv, "--topo", NULL, "" );
  char const * tile      = fd_env_strip_cmdline_cstr( pargc, pargv, "--tile", NULL, "" );
  args->events.tail       = fd_env_strip_cmdline_contains( pargc, pargv, "--tail" );

  ulong topo_name_len = strlen( topo_name );
  if( FD_UNLIKELY( topo_name_len > sizeof(args->events.topo)-1 ) ) FD_LOG_ERR(( "Unknown --topo %s", topo_name ));
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( args->events.topo ), topo_name, topo_name_len ) );

  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( args->events.tile ), tile, sizeof(args->events.tile)-1UL ) );
}

static void
reconstruct_topo( config_t *   config,
                  char const * topo_name ) {
  if( !topo_name[0] ) return; /* keep default action topo */

  action_t const * selected = NULL;
  for( action_t ** a=ACTIONS; *a; a++ ) {
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

struct events_link {
  fd_topo_link_t const * topo;
  void const *            dcache_base;
  char                    tile_name[ 8UL ]; /* fd_topo_tile_t.name is char[7] */
};

struct events_ctx {
  struct events_link links[ FD_TOPO_MAX_LINKS ];
  ulong               link_cnt;

  fd_clock_tile_t      clock[ 1 ];
  uchar *              event_buf; /* FD_EVENT_GEN_STRUCT_MAX bytes */
  char *               line_buf;  /* FD_EVENT_GEN_JSON_BUF_MAX+1 bytes (+1 for the trailing '\n') */
  ulong                event_type;
  ulong                event_sz;
  int                  event_pending;
};
typedef struct events_ctx events_ctx_t;

static void
write_stdout( char const * buf,
             ulong        sz ) {
  ulong written = 0UL;
  while( written<sz ) {
    long n = write( STDOUT_FILENO, buf+written, sz-written );
    if( FD_UNLIKELY( n<0L ) ) {
      if( FD_LIKELY( errno==EINTR ) ) continue;
      FD_LOG_ERR(( "write(STDOUT_FILENO) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    written += (ulong)n;
  }
}

static ulong
events_decode( struct events_link const * link,
               ulong                       seq,
               ulong                       sig,
               ulong                       chunk,
               ulong                       tspub,
               fd_clock_tile_t *           clock,
               char *                      line_buf ) {
  ulong        type  = FD_EVENT_SIG_TYPE( sig );
  ulong        ev_sz = FD_EVENT_SIG_SZ( sig );
  void const * ev    = fd_chunk_to_laddr_const( link->dcache_base, chunk );
  if( FD_UNLIKELY( fd_clock_tile_recal_due( clock ) ) ) fd_clock_tile_recal( clock );
  long ts_ns = fd_clock_tile_tickcomp_to_wallclock( clock, tspub );
  return fd_event_json_by_type( type, ev, ev_sz, link->tile_name, seq, ts_ns, line_buf, FD_EVENT_GEN_JSON_BUF_MAX );
}

static void
events_link_once( struct events_link const * link,
                  fd_clock_tile_t *           clock,
                  char *                      line_buf ) {
  fd_frag_meta_t const * mcache   = link->topo->mcache;
  ulong                   seq0     = fd_mcache_seq0( mcache );
  ulong                   seq_init = fd_mcache_seq_query( fd_mcache_seq_laddr_const( mcache ) );
  ulong                   depth    = fd_mcache_depth( mcache );

  ulong min_seq_seen = seq_init; /* what we actually looked at is [min_seq_seen, seq_init) */
  for( ulong seq=fd_seq_dec( seq_init, 1UL ); fd_seq_ge( seq, seq0 ); seq=fd_seq_dec( seq, 1UL ) ) {
    fd_frag_meta_t const * frag     = mcache + fd_mcache_line_idx( seq, depth );
    ulong                   read_seq = fd_frag_meta_seq_query( frag );
    if( FD_UNLIKELY( read_seq!=seq ) ) break;
    min_seq_seen = seq;
  }

  for( ulong seq=min_seq_seen; fd_seq_lt( seq, seq_init ); seq=fd_seq_inc( seq, 1UL ) ) {
    fd_frag_meta_t const * frag     = mcache + fd_mcache_line_idx( seq, depth );
    ulong                   read_seq = fd_frag_meta_seq_query( frag );
    if( FD_UNLIKELY( read_seq!=seq ) ) continue;

    ulong sz = events_decode( link, seq, frag->sig, frag->chunk, frag->tspub, clock, line_buf );
    if( FD_LIKELY( sz ) ) { line_buf[ sz ] = '\n'; write_stdout( line_buf, sz+1UL ); }
  }

  /* Anything published after seq_init, capped at one depth so a
     still-running producer can't make this loop forever. */
  for( ulong off=0UL; off<depth; off++ ) {
    ulong seq = fd_seq_inc( seq_init, off );

    fd_frag_meta_t const * frag     = mcache + fd_mcache_line_idx( seq, depth );
    ulong                   read_seq = fd_frag_meta_seq_query( frag );
    if( FD_UNLIKELY( (fd_seq_le( min_seq_seen, read_seq ) & fd_seq_lt( read_seq, seq_init )) | (frag->ctl & (1<<2)) ) ) continue;

    ulong sz = events_decode( link, seq, frag->sig, frag->chunk, frag->tspub, clock, line_buf );
    if( FD_LIKELY( sz ) ) { line_buf[ sz ] = '\n'; write_stdout( line_buf, sz+1UL ); }
  }
}

static int running = 1;

static void
exit_signal( int sig FD_PARAM_UNUSED ) {
  running = 0;
}

static int
should_shutdown( events_ctx_t * ctx FD_PARAM_UNUSED ) {
  return !running;
}

static void
during_frag( events_ctx_t * ctx,
             ulong          in_idx,
             ulong          seq,
             ulong          sig,
             ulong          chunk,
             ulong          sz,
             ulong          ctl ) {
  (void)in_idx; (void)seq; (void)sz; (void)ctl;
  struct events_link const * link  = &ctx->links[ in_idx ];
  ulong                       type  = FD_EVENT_SIG_TYPE( sig );
  ulong                       ev_sz = FD_EVENT_SIG_SZ( sig );
  if( FD_UNLIKELY( ev_sz>FD_EVENT_GEN_STRUCT_MAX ) ) {
    ctx->event_pending = 0;
    return;
  }
  fd_memcpy( ctx->event_buf, fd_chunk_to_laddr_const( link->dcache_base, chunk ), ev_sz );
  ctx->event_type    = type;
  ctx->event_sz      = ev_sz;
  ctx->event_pending = 1;
}

static void
after_frag( events_ctx_t *      ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig     FD_PARAM_UNUSED,
            ulong               sz      FD_PARAM_UNUSED,
            ulong               tsorig  FD_PARAM_UNUSED,
            ulong               tspub,
            fd_stem_context_t * stem    FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( !ctx->event_pending ) ) return;
  ctx->event_pending = 0;

  if( FD_UNLIKELY( fd_clock_tile_recal_due( ctx->clock ) ) ) fd_clock_tile_recal( ctx->clock );
  long  ts_ns = fd_clock_tile_tickcomp_to_wallclock( ctx->clock, tspub );
  ulong out_sz = fd_event_json_by_type( ctx->event_type, ctx->event_buf, ctx->event_sz,
                                       ctx->links[ in_idx ].tile_name, seq, ts_ns,
                                       ctx->line_buf, FD_EVENT_GEN_JSON_BUF_MAX );
  if( FD_UNLIKELY( !out_sz ) ) return;
  ctx->line_buf[ out_sz ] = '\n';
  write_stdout( ctx->line_buf, out_sz+1UL );
}

#define STEM_BURST                    (0UL)
#define STEM_CALLBACK_CONTEXT_TYPE    events_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(events_ctx_t)
#define STEM_CALLBACK_DURING_FRAG     during_frag
#define STEM_CALLBACK_AFTER_FRAG      after_frag
#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#include "../../../disco/stem/fd_stem.c"

static void
events_cmd_fn( args_t *   args,
               config_t * config ) {
  static char const EVENT_SUFFIX[] = "_event";
  ulong              suffix_len    = strlen( EVENT_SUFFIX );

  char * tokens[ 16 ];
  ulong  token_count = fd_cstr_tokenize( tokens, 16UL, args->events.tile, ',' );

  fd_topo_t * topo = &config->topo;
  fd_bootinfo_adopt( config );
  reconstruct_topo( config, args->events.topo );
  fd_bootinfo_check_layout( config );
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_fill( topo );

  events_ctx_t ctx = { 0 };
  fd_clock_tile_init( ctx.clock );
  ctx.event_buf = malloc( FD_EVENT_GEN_STRUCT_MAX );
  ctx.line_buf  = malloc( FD_EVENT_GEN_JSON_BUF_MAX+1UL );
  FD_TEST( ctx.event_buf );
  FD_TEST( ctx.line_buf  );

  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    fd_topo_link_t * link     = &topo->links[ i ];
    ulong            name_len = strlen( link->name );
    if( FD_LIKELY( name_len<=suffix_len || 0!=strcmp( link->name+name_len-suffix_len, EVENT_SUFFIX ) ) ) continue;

    ulong tile_name_len = name_len-suffix_len;
    char  tile_name[ 8UL ];
    FD_TEST( tile_name_len<sizeof(tile_name) );
    fd_memcpy( tile_name, link->name, tile_name_len );
    tile_name[ tile_name_len ] = '\0';

    int found = (token_count==0UL);
    for( ulong j=0UL; (!found)&(j<token_count); j++ ) found |= !strcmp( tokens[ j ], tile_name );
    if( !found ) continue;

    if( FD_UNLIKELY( NULL==link->mcache ) ) FD_LOG_ERR(( "link %s:%lu mcache is null", link->name, link->kind_id ));

    struct events_link * l = &ctx.links[ ctx.link_cnt++ ];
    l->topo        = link;
    l->dcache_base = link->mtu ? fd_topo_obj_wksp_base( topo, link->dcache_obj_id ) : NULL;
    fd_memcpy( l->tile_name, tile_name, tile_name_len+1UL );
  }

  if( FD_UNLIKELY( !ctx.link_cnt ) ) {
    FD_LOG_WARNING(( "no event links matched --tile %s; available producer tiles:", token_count ? args->events.tile : "*" ));
    for( ulong i=0UL; i<topo->link_cnt; i++ ) {
      ulong name_len = strlen( topo->links[ i ].name );
      if( FD_LIKELY( name_len>suffix_len && 0==strcmp( topo->links[ i ].name+name_len-suffix_len, EVENT_SUFFIX ) ) )
        FD_LOG_WARNING(( "  %.*s", (int)(name_len-suffix_len), topo->links[ i ].name ));
    }
    FD_LOG_ERR(( "no matching event links found" ));
  }

  if( !args->events.tail ) {
    for( ulong i=0UL; i<ctx.link_cnt; i++ ) events_link_once( &ctx.links[ i ], ctx.clock, ctx.line_buf );
  } else {
    struct sigaction sa = { .sa_handler = exit_signal, .sa_flags = 0 };
    if( FD_UNLIKELY( sigaction( SIGTERM, &sa, NULL ) ) ) FD_LOG_ERR(( "sigaction(SIGTERM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    if( FD_UNLIKELY( sigaction( SIGINT,  &sa, NULL ) ) ) FD_LOG_ERR(( "sigaction(SIGINT) failed (%i-%s)",  errno, fd_io_strerror( errno ) ));

    fd_frag_meta_t const * mcaches[ FD_TOPO_MAX_LINKS ];
    for( ulong i=0UL; i<ctx.link_cnt; i++ ) mcaches[ i ] = ctx.links[ i ].topo->mcache;

    uchar   fseq_mem[ FD_TOPO_MAX_LINKS ][ FD_FSEQ_FOOTPRINT ] __attribute__((aligned(FD_FSEQ_ALIGN)));
    ulong * fseqs[ FD_TOPO_MAX_LINKS ];
    for( ulong i=0UL; i<ctx.link_cnt; i++ ) fseqs[ i ] = fd_fseq_join( fd_fseq_new( fseq_mem[ i ], 0UL ) );

    fd_rng_t   _rng[1];
    fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, (uint)fd_tickcount(), 0UL ) );

    uchar __attribute__((aligned(FD_STEM_SCRATCH_ALIGN))) scratch[ stem_scratch_footprint( ctx.link_cnt, 0UL, 0UL ) ];
    uchar __attribute__((aligned(FD_METRICS_ALIGN)))      metrics_mem[ FD_METRICS_FOOTPRINT( ctx.link_cnt ) ];

    ulong * metrics_base = fd_metrics_join( fd_metrics_new( metrics_mem, ctx.link_cnt ) );
    fd_metrics_register( metrics_base );

    stem_run1( ctx.link_cnt, /* in_cnt     */
               mcaches,      /* in_mcache  */
               fseqs,        /* in_fseq    */
               0UL,          /* out_cnt    */
               NULL,         /* out_mcache */
               0UL,          /* cons_cnt   */
               NULL,         /* _cons_out  */
               NULL,         /* _cons_fseq */
               NULL,         /* cons_slow  */
               0UL,          /* burst      */
               0UL,          /* lazy       */
               rng,          /* rng        */
               scratch,      /* scratch    */
               &ctx );       /* ctx        */

    fd_metrics_delete( fd_metrics_leave( metrics_base ) );
    fd_rng_delete( fd_rng_leave( rng ) );
    for( ulong i=0UL; i<ctx.link_cnt; i++ ) fd_fseq_delete( fd_fseq_leave( fseqs[ i ] ) );
  }

  free( ctx.line_buf  );
  free( ctx.event_buf );
  fd_topo_leave_workspaces( topo );
}

static void
events_args_help( fd_action_help_t * help ) {
  fd_action_help_arg( help, "--topo", "<command>",
      "Build the topology from another subcommand (e.g. `gossip`) instead of\n"
      "the default validator topology.  <command> is the name of a subcommand\n"
      "that builds its own topology" );
  fd_action_help_arg( help, "--tile", "<name>[,<name>...]",
      "Only show events from these producer tiles (e.g. `replay,tower`).\n"
      "Default is all tiles with an event link" );
  fd_action_help_arg( help, "--tail", NULL,
      "Continuously stream new events instead of dumping a one-time snapshot" );
}

action_t fd_action_events = {
  .name          = "events",
  .args          = events_cmd_args,
  .fn            = events_cmd_fn,
  .perm          = NULL,
  .description   = "Print structured validator events as NDJSON to STDOUT",
  .detail        = "Connects to a running validator and writes structured events (votes,\n"
                   "block completions, slot confirmations, ...) to stdout as one JSON object\n"
                   "per line.  Without --tail, dumps whatever events are still live in each\n"
                   "producer tile's event ring and exits; with --tail, streams new events\n"
                   "continuously until interrupted.  This is a best-effort diagnostic view:\n"
                   "events are dropped if the tool falls behind a busy producer.",
  .usage         = "events [OPTIONS]",
  .args_help     = events_args_help,
  .is_immediate  = 0,
  .is_diagnostic = 1,
};
