/* The rotor command attaches to a running validator's rotor tile and
   prints per-second repair request / response counters and network
   drop counters. */

#include "../../../disco/topo/fd_topob.h"
#include "../../shared/fd_config.h" /* config_t */
#include "../../shared_dev/commands/dev.h" /* dev_cmd_perm */

#include "../../../disco/metrics/fd_metrics.h"
#include "../../../disco/net/fd_net_tile.h" /* fd_net_tile_name */

#include <stdio.h>
#include <time.h>   /* localtime_r */
#include <unistd.h> /* sleep */

extern action_t fd_action_rotor;

/* metrics_src holds the shared-memory metric arrays the command
   samples.  Link arrays are the consumer-side in-link metrics
   (overruns are counted by the consumer). */

#define ROTOR_METRICS_LINK_MAX (256UL)

struct metrics_src {
  volatile ulong * rotor;                                    /* rotor tile metrics */
  volatile ulong * shred[ ROTOR_METRICS_LINK_MAX ];          /* shred tile metrics */
  ulong            shred_cnt;
  volatile ulong * net[ ROTOR_METRICS_LINK_MAX ];            /* net tile metrics */
  ulong            net_cnt;
  int              net_kind;                                 /* 0 xdp "net", 1 "mlx5", 2 "sock" */
  volatile ulong * net_shred [ ROTOR_METRICS_LINK_MAX ];     /* net->shred links, consumer side (shred tiles) */
  ulong            net_shred_cnt;
  volatile ulong * net_repair[ ROTOR_METRICS_LINK_MAX ];     /* net->rotor links, consumer side (rotor) */
  ulong            net_repair_cnt;
  volatile ulong * repair_net[ ROTOR_METRICS_LINK_MAX ];     /* rotor->net link, consumer side (net tiles) */
  ulong            repair_net_cnt;
};
typedef struct metrics_src metrics_src_t;

/* metrics_snap is one sample of the counters we print. */

struct metrics_snap {
  long  ts;

  ulong req[ FD_METRICS_ENUM_ROTOR_REQUEST_TYPE_CNT ];
  ulong pkt_tx;
  ulong rerequest;
  ulong meta_failed;   /* shred_block_id + fec_root + parent_fec_count verify failures */
  ulong shred_old;
  ulong resp_cnt;      /* responses matched to an inflight request (latency histogram count) */
  ulong resp_sum_ns;   /* latency histogram sum */

  ulong inflight, slot_current, slot_highest_repaired, slot_last_requested, orphan_last_requested, peers;

  ulong shred_repair_rx, shred_turbine_rx;
  ulong shred_okay, shred_dup, shred_bad_slot, shred_ignored, shred_completes;

  struct { ulong overrun, consumed, filtered; } net_shred, net_repair, repair_net;
  ulong net_rx, net_rx_drop, net_tx, net_tx_drop;

  /* tile regime nanos: [0] rotor, [1..] shred tiles.  Same idle
     definition as the GUI: caught-up postfrag (spinning for input),
     caught-up sleeping, and backpressure prefrag / sleeping are idle,
     everything else is busy.  backp = the backpressure share (stalled
     on a downstream consumer). */
  struct { ulong total, busy, backp; } regime[ 1UL+ROTOR_METRICS_LINK_MAX ];
};
typedef struct metrics_snap metrics_snap_t;

static void
metrics_snap_regime( volatile ulong * m, ulong * total, ulong * busy, ulong * backp ) {
  ulong r[ FD_METRICS_ENUM_TILE_REGIME_CNT ];
  for( ulong i=0UL; i<FD_METRICS_ENUM_TILE_REGIME_CNT; i++ ) r[ i ] = m[ MIDX( COUNTER, TILE, REGIME_DURATION_NANOS )+i ];
  ulong bp   = r[ FD_METRICS_ENUM_TILE_REGIME_V_BACKPRESSURE_PREFRAG_IDX ] + r[ FD_METRICS_ENUM_TILE_REGIME_V_BACKPRESSURE_SLEEPING_IDX ];
  ulong idle = r[ FD_METRICS_ENUM_TILE_REGIME_V_CAUGHT_UP_POSTFRAG_IDX ] + r[ FD_METRICS_ENUM_TILE_REGIME_V_CAUGHT_UP_SLEEPING_IDX ] + bp;
  *total = 0UL; for( ulong i=0UL; i<FD_METRICS_ENUM_TILE_REGIME_CNT; i++ ) *total += r[ i ];
  *busy  = *total-idle;
  *backp = bp;
}

static void
metrics_src_link( fd_topo_t *       topo,
                  fd_topo_tile_t *  tile,
                  char const *      link_name,
                  ulong             kind_id,
                  volatile ulong ** out,
                  ulong *           cnt ) {
  ulong in_idx = fd_topo_find_tile_in_link( topo, tile, link_name, kind_id );
  if( FD_UNLIKELY( in_idx==ULONG_MAX ) ) return; /* not every tile has every link */
  if( FD_UNLIKELY( *cnt>=ROTOR_METRICS_LINK_MAX ) ) FD_LOG_ERR(( "too many %s links", link_name ));
  out[ (*cnt)++ ] = fd_metrics_link_in( tile->metrics, in_idx );
}

static void
metrics_src_init( metrics_src_t * src,
                  config_t *      config ) {
  fd_topo_t * topo = &config->topo;
  memset( src, 0, sizeof(*src) );

  /* Every tile's metrics object lives in the metric_in workspace, so
     joining that one and filling it resolves tile->metrics for all. */
  ulong wksp_id = fd_topo_find_wksp( topo, "metric_in" );
  if( FD_UNLIKELY( wksp_id==ULONG_MAX ) ) FD_LOG_ERR(( "metric_in workspace not found" ));
  fd_topo_join_workspace( topo, &topo->workspaces[ wksp_id ], FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_workspace_fill( topo, &topo->workspaces[ wksp_id ] );

  ulong rotor_id = fd_topo_find_tile( topo, "rotor", 0UL );
  if( FD_UNLIKELY( rotor_id==ULONG_MAX ) ) FD_LOG_ERR(( "rotor tile not found (is the validator running with --alpenglow?)" ));
  fd_topo_tile_t * rotor_tile = &topo->tiles[ rotor_id ];
  src->rotor = fd_metrics_tile( rotor_tile->metrics );

  char const * net_name = fd_net_tile_name( config->net.provider );
  src->net_kind = !strcmp( net_name, "net" ) ? 0 : !strcmp( net_name, "mlx5" ) ? 1 : 2;

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &topo->tiles[ i ];
    if( !strcmp( tile->name, "shred" ) ) {
      if( FD_UNLIKELY( src->shred_cnt>=ROTOR_METRICS_LINK_MAX ) ) FD_LOG_ERR(( "too many shred tiles" ));
      src->shred[ src->shred_cnt++ ] = fd_metrics_tile( tile->metrics );
      for( ulong j=0UL; j<tile->in_cnt; j++ ) {
        if( !strcmp( topo->links[ tile->in_link_id[ j ] ].name, "net_shred" ) ) {
          if( FD_UNLIKELY( src->net_shred_cnt>=ROTOR_METRICS_LINK_MAX ) ) FD_LOG_ERR(( "too many net_shred links" ));
          src->net_shred[ src->net_shred_cnt++ ] = fd_metrics_link_in( tile->metrics, j );
        }
      }
    } else if( !strcmp( tile->name, net_name ) ) {
      if( FD_UNLIKELY( src->net_cnt>=ROTOR_METRICS_LINK_MAX ) ) FD_LOG_ERR(( "too many net tiles" ));
      src->net[ src->net_cnt++ ] = fd_metrics_tile( tile->metrics );
      metrics_src_link( topo, tile, "repair_net", 0UL, src->repair_net, &src->repair_net_cnt );
    }
  }
  for( ulong j=0UL; j<rotor_tile->in_cnt; j++ ) {
    if( !strcmp( topo->links[ rotor_tile->in_link_id[ j ] ].name, "net_repair" ) ) {
      if( FD_UNLIKELY( src->net_repair_cnt>=ROTOR_METRICS_LINK_MAX ) ) FD_LOG_ERR(( "too many net_repair links" ));
      src->net_repair[ src->net_repair_cnt++ ] = fd_metrics_link_in( rotor_tile->metrics, j );
    }
  }
}

static void
metrics_snap_links( volatile ulong ** links, ulong cnt, ulong * overrun, ulong * consumed, ulong * filtered ) {
  *overrun = *consumed = *filtered = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    *overrun  += links[ i ][ MIDX( COUNTER, LINK, FRAG_READING_OVERRUN ) ] + links[ i ][ MIDX( COUNTER, LINK, FRAG_POLLING_OVERRUN ) ];
    *consumed += links[ i ][ MIDX( COUNTER, LINK, FRAG_CONSUMED ) ];
    *filtered += links[ i ][ MIDX( COUNTER, LINK, FRAG_FILTERED ) ];
  }
}

static void
metrics_snap_take( metrics_snap_t * s, metrics_src_t const * src ) {
  volatile ulong * r = src->rotor;
  memset( s, 0, sizeof(*s) );
  s->ts = fd_log_wallclock();

  for( ulong i=0UL; i<FD_METRICS_ENUM_ROTOR_REQUEST_TYPE_CNT; i++ ) s->req[ i ] = r[ MIDX( COUNTER, ROTOR, REQUEST_TX )+i ];
  s->pkt_tx      = r[ MIDX( COUNTER, ROTOR, PKT_TX ) ];
  /* The rotor tile does not produce SHRED_REREQUESTED. */
  s->rerequest   = 0UL;
  s->shred_old   = r[ MIDX( COUNTER, ROTOR, SHRED_OLD ) ];
  s->meta_failed = r[ MIDX( COUNTER, ROTOR, SHRED_RX_UNMATCHED ) ] + r[ MIDX( COUNTER, ROTOR, FEC_SET_ROOT_FAILED ) ] + r[ MIDX( COUNTER, ROTOR, PARENT_AND_FEC_SET_COUNT_FAILED ) ];
  for( ulong k=0UL; k<FD_HISTF_BUCKET_CNT; k++ ) s->resp_cnt += r[ MIDX( HISTOGRAM, ROTOR, RESPONSE_LATENCY_NANOS )+k ];
  s->resp_sum_ns = r[ MIDX( HISTOGRAM, ROTOR, RESPONSE_LATENCY_NANOS )+FD_HISTF_BUCKET_CNT ];

  s->inflight              = r[ MIDX( GAUGE, ROTOR, PENDING_CNT ) ];
  s->slot_current          = r[ MIDX( GAUGE, ROTOR, SLOT_HIGHEST_RECEIVED ) ];
  s->slot_highest_repaired = r[ MIDX( GAUGE, ROTOR, SLOT_HIGHEST_DELIVERED ) ];
  /* Nor SLOT_LAST_REQUESTED, ORPHAN_LAST_REQUESTED, PEER_REQUESTED. */
  s->slot_last_requested   = 0UL;
  s->orphan_last_requested = 0UL;
  s->peers                 = 0UL;

  for( ulong i=0UL; i<src->shred_cnt; i++ ) {
    volatile ulong * m = src->shred[ i ];
    s->shred_repair_rx  += m[ MIDX( COUNTER, SHRED, SHRED_REPAIR_RX ) ];
    s->shred_turbine_rx += m[ MIDX( COUNTER, SHRED, SHRED_TURBINE_RX ) ];
    s->shred_okay       += m[ MIDX( COUNTER, SHRED, SHRED_PROCESSED_OKAY ) ];
    s->shred_dup        += m[ MIDX( COUNTER, SHRED, SHRED_PROCESSED_DUPLICATE ) ];
    s->shred_bad_slot   += m[ MIDX( COUNTER, SHRED, SHRED_PROCESSED_BAD_SLOT ) ];
    s->shred_ignored    += m[ MIDX( COUNTER, SHRED, SHRED_PROCESSED_IGNORED ) ];
    s->shred_completes  += m[ MIDX( COUNTER, SHRED, SHRED_PROCESSED_COMPLETES ) ];
  }

  metrics_snap_regime( src->rotor, &s->regime[ 0 ].total, &s->regime[ 0 ].busy, &s->regime[ 0 ].backp );
  for( ulong i=0UL; i<src->shred_cnt; i++ ) metrics_snap_regime( src->shred[ i ], &s->regime[ 1UL+i ].total, &s->regime[ 1UL+i ].busy, &s->regime[ 1UL+i ].backp );

  metrics_snap_links( (volatile ulong **)src->net_shred,  src->net_shred_cnt,  &s->net_shred.overrun,  &s->net_shred.consumed,  &s->net_shred.filtered  );
  metrics_snap_links( (volatile ulong **)src->net_repair, src->net_repair_cnt, &s->net_repair.overrun, &s->net_repair.consumed, &s->net_repair.filtered );
  metrics_snap_links( (volatile ulong **)src->repair_net, src->repair_net_cnt, &s->repair_net.overrun, &s->repair_net.consumed, &s->repair_net.filtered );

  for( ulong i=0UL; i<src->net_cnt; i++ ) {
    volatile ulong * m = src->net[ i ];
    switch( src->net_kind ) {
    case 0: /* xdp */
      s->net_rx      += m[ MIDX( COUNTER, NET, PKT_RX ) ];
      s->net_tx      += m[ MIDX( COUNTER, NET, PKT_TX_SUBMITTED ) ];
      s->net_rx_drop += m[ MIDX( COUNTER, NET, PKT_RX_FILL_RING_FULL ) ] + m[ MIDX( COUNTER, NET, PKT_RX_BACKPRESSURE ) ]
                      + m[ MIDX( COUNTER, NET, XDP_RX_RING_FULL ) ]      + m[ MIDX( COUNTER, NET, XDP_RX_OTHER_DROPPED ) ]
                      + m[ MIDX( COUNTER, NET, PKT_RX_MALFORMED ) ]      + m[ MIDX( COUNTER, NET, PKT_RX_ROUTE_FAIL ) ];
      s->net_tx_drop += m[ MIDX( COUNTER, NET, PKT_TX_RING_FULL ) ]      + m[ MIDX( COUNTER, NET, PKT_TX_NO_NEIGHBOR ) ]
                      + m[ MIDX( COUNTER, NET, PKT_TX_ROUTE_FAIL ) ]      + m[ MIDX( COUNTER, NET, PKT_TX_INVALID ) ];
      break;
    case 1: /* mlx5 */
      s->net_rx      += m[ MIDX( COUNTER, MLX5, PKT_RX ) ];
      s->net_tx      += m[ MIDX( COUNTER, MLX5, PKT_TX_COMPLETED ) ];
      s->net_rx_drop += m[ MIDX( COUNTER, MLX5, PKT_RX_MALFORMED ) ]     + m[ MIDX( COUNTER, MLX5, PKT_RX_ROUTE_FAIL ) ];
      s->net_tx_drop += m[ MIDX( COUNTER, MLX5, PKT_TX_NO_BUFFER ) ]     + m[ MIDX( COUNTER, MLX5, PKT_TX_NO_NEIGHBOR ) ]
                      + m[ MIDX( COUNTER, MLX5, PKT_TX_ROUTE_FAIL ) ]     + m[ MIDX( COUNTER, MLX5, PKT_TX_INVALID ) ];
      break;
    default: /* sock */
      s->net_rx      += m[ MIDX( COUNTER, SOCK, PKT_RX ) ];
      s->net_tx      += m[ MIDX( COUNTER, SOCK, PKT_TX ) ];
      s->net_tx_drop += m[ MIDX( COUNTER, SOCK, PKT_TX_FAILED ) ];
      break;
    }
  }
}

/* fmt_num renders v with thousands separators into buf (>=32 bytes)
   and returns buf. */

static char *
fmt_num( char * buf, double v ) {
  char raw[ 32 ];
  snprintf( raw, sizeof(raw), "%.0f", v<0.0 ? 0.0 : v );
  ulong len = strlen( raw ), o = 0UL;
  for( ulong i=0UL; i<len; i++ ) {
    if( i && (len-i)%3==0 ) buf[ o++ ] = ',';
    buf[ o++ ] = raw[ i ];
  }
  buf[ o ] = '\0';
  return buf;
}

/* col prints one "label value" cell of fixed width so rows line up. */

static void
col( char const * label, double v ) {
  char b[ 32 ];
  printf( "%-12s %12s   ", label, fmt_num( b, v ) );
}

static void
col_pct( char const * label, double v, double pct ) {
  char b[ 32 ];
  printf( "%-12s %12s (%3.0f%%)", label, fmt_num( b, v ), pct );
}

static void
metrics_snap_print( metrics_snap_t const * s,
                    metrics_snap_t const * p,
                    metrics_src_t const *  src ) {
  struct tm tm; time_t t = (time_t)(s->ts/(long)1e9); localtime_r( &t, &tm );
  char tbuf[ 16 ]; strftime( tbuf, sizeof(tbuf), "%H:%M:%S", &tm );

  /* Everything below is the cumulative counter value since the tile
     booted (gauges are the current value).  Only the tile busy line is
     computed over the last interval, since a lifetime average would
     hide what the tiles are doing right now. */

  ulong req_tot = 0UL;
  for( ulong i=0UL; i<FD_METRICS_ENUM_ROTOR_REQUEST_TYPE_CNT; i++ ) {
    if( i==FD_METRICS_ENUM_ROTOR_REQUEST_TYPE_V_PONG_IDX ) continue;
    req_tot += s->req[ i ];
  }
  double resp_pct  = req_tot ? 100.0*(double)s->resp_cnt /(double)req_tot : 0.0;
  double rereq_pct = req_tot ? 100.0*(double)s->rerequest/(double)req_tot : 0.0;
  double lat_ms    = s->resp_cnt ? (double)s->resp_sum_ns/(double)s->resp_cnt/1e6 : 0.0;
  long   gap       = (long)s->slot_current-(long)s->slot_highest_repaired;

# define T(field) ((double)s->field)
# define Q(idx)   ((double)s->req[ idx ])

  printf( "==== %s %s\n", tbuf,
          "======================================================================================================================" );

  printf( "  slots        " );
  col( "current",    (double)s->slot_current          );
  col( "repaired",   (double)s->slot_highest_repaired );
  col( "gap",        (double)gap                      );
  col( "last_req",   (double)s->slot_last_requested   );
  col( "orphan_req", (double)s->orphan_last_requested );
  printf( "\n  state        " );
  col( "inflight",   (double)s->inflight );
  col( "peers",      (double)s->peers    );
  printf( "\n\n" );

  printf( "  requests     " );
  col( "window",     Q( FD_METRICS_ENUM_ROTOR_REQUEST_TYPE_V_WINDOW_INDEX_IDX               ) );
  col( "highest",    Q( FD_METRICS_ENUM_ROTOR_REQUEST_TYPE_V_HIGHEST_WINDOW_INDEX_IDX       ) );
  col( "orphan",     Q( FD_METRICS_ENUM_ROTOR_REQUEST_TYPE_V_ORPHAN_IDX                     ) );
  col( "parent_fec", Q( FD_METRICS_ENUM_ROTOR_REQUEST_TYPE_V_PARENT_AND_FEC_SET_COUNT_IDX   ) );
  printf( "\n               " );
  col( "fec_root",   Q( FD_METRICS_ENUM_ROTOR_REQUEST_TYPE_V_FEC_SET_ROOT_IDX               ) );
  col( "shred_bid",  Q( FD_METRICS_ENUM_ROTOR_REQUEST_TYPE_V_WINDOW_INDEX_FOR_BLOCK_ID_IDX  ) );
  col( "pong",       Q( FD_METRICS_ENUM_ROTOR_REQUEST_TYPE_V_PONG_IDX                  ) );
  printf( "\n               " );
  col( "total",      (double)req_tot );
  col_pct( "rerequest", T( rerequest ), rereq_pct ); printf( "   " );
  col( "pkt_tx",     T( pkt_tx ) );
  printf( "\n\n" );

  printf( "  responses    " );
  col_pct( "matched", T( resp_cnt ), resp_pct ); printf( " of requests   " );
  printf( "%-12s %9.1f ms   ", "latency", lat_ms );
  col( "meta_failed", T( meta_failed ) );
  col( "shred_old",   T( shred_old ) );
  printf( "\n" );

  printf( "  shred        " );
  col( "repair_rx",  T( shred_repair_rx  ) );
  col( "turbine_rx", T( shred_turbine_rx ) );
  col( "okay",       T( shred_okay       ) );
  col( "duplicate",  T( shred_dup        ) );
  printf( "\n               " );
  col( "bad_slot",   T( shred_bad_slot   ) );
  col( "ignored",    T( shred_ignored    ) );
  col( "completes",  T( shred_completes  ) );
  printf( "\n\n" );

  printf( "  drops        " );
  col( "net_shred",  T( net_shred.overrun  ) );
  col( "consumed",   T( net_shred.consumed ) );
  col( "filtered",   T( net_shred.filtered ) );
  printf( "(%lu links, overrun = frags skipped)", src->net_shred_cnt );
  printf( "\n               " );
  col( "net_repair", T( net_repair.overrun  ) );
  col( "consumed",   T( net_repair.consumed ) );
  printf( "\n               " );
  col( "repair_net", T( repair_net.overrun  ) );
  col( "consumed",   T( repair_net.consumed ) );
  printf( "\n               " );
  col( "net_rx",     T( net_rx      ) );
  col( "rx_drop",    T( net_rx_drop ) );
  col( "net_tx",     T( net_tx      ) );
  col( "tx_drop",    T( net_tx_drop ) );
  printf( "\n\n" );

  printf( "  tile busy    " );
  for( ulong i=0UL; i<1UL+src->shred_cnt; i++ ) {
    ulong  dtot  = s->regime[ i ].total-p->regime[ i ].total;
    double busy  = dtot ? 100.0*(double)(s->regime[ i ].busy -p->regime[ i ].busy )/(double)dtot : 0.0;
    double backp = dtot ? 100.0*(double)(s->regime[ i ].backp-p->regime[ i ].backp)/(double)dtot : 0.0;
    char label[ 16 ];
    if( !i ) snprintf( label, sizeof(label), "rotor" );
    else     snprintf( label, sizeof(label), "shred:%lu", i-1UL );
    printf( "%-12s %5.1f%% (bp %4.1f%%)   ", label, busy, backp );
  }
  printf( "  (last interval)\n\n" );

# undef T
# undef Q
  fflush( stdout );
}

static void
rotor_metrics_fn( args_t *   args,
                  config_t * config ) {
  metrics_src_t src[1];
  metrics_src_init( src, config );
  FD_LOG_NOTICE(( "rotor metrics: %lu shred tiles, %lu %s tiles, %lu net_shred links, %lu net_repair links, %lu repair_net links",
                  src->shred_cnt, src->net_cnt, fd_net_tile_name( config->net.provider ), src->net_shred_cnt, src->net_repair_cnt, src->repair_net_cnt ));

  metrics_snap_t prev[1], cur[1];
  metrics_snap_take( prev, src );
  for(;;) {
    sleep( 1 );
    metrics_snap_take( cur, src );
    metrics_snap_print( cur, prev, src );
    *prev = *cur;
    if( args->rotor.once ) break;
  }
}

static void
rotor_cmd_args( int *    pargc,
                char *** pargv,
                args_t * args ) {
  args->rotor.once = fd_env_strip_cmdline_contains( pargc, pargv, "--once" );
}

action_t fd_action_rotor = {
  .name        = "rotor",
  .args        = rotor_cmd_args,
  .fn          = rotor_metrics_fn,
  .perm        = dev_cmd_perm,
  .description = "Inspect a running validator's alpenglow rotor tile",
  .detail      = "Attaches to a running validator's rotor tile and prints once a second\n"
                 "per-second repair request counters by type, matched responses and\n"
                 "mean latency, shred tile receive counters, and net / link drop\n"
                 "counters (net_shred, net_repair, repair_net overruns, net tile rx/tx\n"
                 "drops).\n"
                 "\n"
                 "  --once  print a single snapshot and exit",
  .usage       = "rotor [--once]",
};
