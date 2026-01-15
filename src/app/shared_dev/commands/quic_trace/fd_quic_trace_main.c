/* This directory provides the 'fddev quic-trace' subcommand.

   The goal of quic-trace is to tap QUIC traffic on a live system, which
   requires encryption keys and other annoying connection state.

   quic-trace does this by tapping into the shared memory segments of a
   target tile running on the same host.  It does so strictly read-only
   to minimize impact to a production system.

   This file (fd_quic_trace_main.c) provides the glue code required to
   join remote target tile objects.

   fd_quic_trace_rx_tile.c provides a fd_tango consumer for incoming
   QUIC packets. */

#include "fd_quic_trace.h"

#include "../../../../disco/metrics/fd_metrics.h"
#include "../../../../disco/quic/fd_quic_tile.h"
#include "../../../../discof/send/fd_send_tile.h"
#include "../../../../waltz/quic/log/fd_quic_log_user.h"
#include "../../../../ballet/hex/fd_hex.h"
#include <stdlib.h>

/* Define global variables */

void const         * fd_quic_trace_tile_ctx_remote;
ulong                fd_quic_trace_tile_ctx_raddr;
ulong             ** fd_quic_trace_target_fseq;
ulong volatile     * fd_quic_trace_link_metrics;
void const         * fd_quic_trace_log_base;
peer_conn_id_map_t   _fd_quic_trace_peer_map[1UL << PEER_MAP_LG_SLOT_CNT];
peer_conn_id_map_t * fd_quic_trace_peer_map;

#define EVENT_STREAM 0
#define EVENT_ERROR  1

static void
quic_trace_cmd_args( int    * pargc,
                     char *** pargv,
                     args_t * args ) {
  char const * event = fd_env_strip_cmdline_cstr( pargc, pargv, "--event", NULL, "stream" );
  if( 0==strcmp( event, "stream" ) ) {
    args->quic_trace.event = EVENT_STREAM;
  } else if( 0==strcmp( event, "error" ) ) {
    args->quic_trace.event = EVENT_ERROR;
  } else {
    FD_LOG_ERR(( "Unsupported QUIC event type \"%s\"", event ));
  }

  args->quic_trace.dump        = fd_env_strip_cmdline_contains( pargc, pargv, "--dump" );
  args->quic_trace.dump_config = fd_env_strip_cmdline_contains( pargc, pargv, "--dump-config" );
  args->quic_trace.dump_conns  = fd_env_strip_cmdline_contains( pargc, pargv, "--dump-conns" );
  args->quic_trace.trace_send  = fd_env_strip_cmdline_contains( pargc, pargv, "--send-tile" );
}

static char const *
dump_val_enum_role( int role ) {
  switch( role ) {
    case FD_QUIC_ROLE_CLIENT:
      return "ROLE_CLIENT";
    case FD_QUIC_ROLE_SERVER:
      return "ROLE_SERVER";
    default:
      return "ROLE_UNKNOWN";
  }
}

static char const *
dump_val_bool( int value ) {
  switch( value ) {
    case 0:  return "false";
    case 1:  return "true";
    default: return "invalid"; /* in case something is assuming a config is in {0,1} */
  }
}

void
dump_quic_config( fd_quic_config_t * config ) {
  switch( config->role ) {
    case FD_QUIC_ROLE_CLIENT:
      FD_LOG_NOTICE(( "CONFIG: role: %d FD_QUIC_ROLE_CLIENT", config->role ));
      break;
    case FD_QUIC_ROLE_SERVER:
      FD_LOG_NOTICE(( "CONFIG: role: %d FD_QUIC_ROLE_SERVER", config->role ));
      break;
    default:
      FD_LOG_NOTICE(( "CONFIG: role: %d UNKNOWN",             config->role ));
  }

#define HEXFMT32 "%02x%02x%02x%02x" "%02x%02x%02x%02x" \
                 "%02x%02x%02x%02x" "%02x%02x%02x%02x" \
                 "%02x%02x%02x%02x" "%02x%02x%02x%02x" \
                 "%02x%02x%02x%02x" "%02x%02x%02x%02x"
#define HEXARG32(X) (X)[0],  (X)[1],  (X)[2],  (X)[3],  \
                    (X)[4],  (X)[5],  (X)[6],  (X)[7],  \
                    (X)[8],  (X)[9],  (X)[10], (X)[11], \
                    (X)[12], (X)[13], (X)[14], (X)[15], \
                    (X)[16], (X)[17], (X)[18], (X)[19], \
                    (X)[20], (X)[21], (X)[22], (X)[23], \
                    (X)[24], (X)[25], (X)[26], (X)[27], \
                    (X)[28], (X)[29], (X)[30], (X)[31]

#define dump_val_class_enum( NAME, FMT, CLASS, UNIT, VAL ) \
  FD_LOG_NOTICE(( "CONFIG: " #NAME ": " FMT " - %s", config->NAME, dump_val_enum_##NAME( config->NAME ) ));
#define dump_val_class_bool( NAME, FMT, CLASS, UNIT, VAL ) \
  FD_LOG_NOTICE(( "CONFIG: " #NAME ": " FMT " - %s", config->NAME, dump_val_bool( config->NAME ) ));
#define dump_val_class_units( NAME, FMT, CLASS, UNIT, VAL ) \
  FD_LOG_NOTICE(( "CONFIG: " #NAME ": " FMT " %s", config->NAME, UNIT ));
#define dump_val_class_value( NAME, FMT, CLASS, UNIT, VAL ) \
  FD_LOG_NOTICE(( "CONFIG: " #NAME ": " FMT, config->NAME ));
#define dump_val_class_ptr( NAME, FMT, CLASS, UNIT, VAL ) \
  FD_LOG_NOTICE(( "CONFIG: " #NAME ": 0x%lx", (ulong)config->NAME ));
#define dump_val_class_hex32( NAME, FMT, CLASS, UNIT, VAL ) \
  FD_LOG_NOTICE(( "CONFIG: " #NAME ": 0x" HEXFMT32, HEXARG32(config->NAME) ));

#define dump_val( NAME, FMT, CLASS, UNIT, VAL ) \
  dump_val_class_##CLASS( NAME, FMT, CLASS, UNIT, VAL )

  FD_QUIC_CONFIG_LIST( dump_val, x )
}

static char const *
peer_cid_str( fd_quic_conn_t const * conn ) {
  static char buf[FD_QUIC_MAX_CONN_ID_SZ*2];
  ulong         sz  = conn->peer_cids[0].sz;
  uchar const * cid = conn->peer_cids[0].conn_id;
  sz = fd_ulong_min( sz, FD_QUIC_MAX_CONN_ID_SZ );

  fd_hex_encode( buf, cid, sz );

  return buf;
}

static void
dump_connection( fd_quic_conn_t const * conn ) {

#define CONN_MEMB_LIST(X,CONN,...) \
  X( conn_idx,               "%u",         ( (CONN).conn_idx               ), __VA_ARGS__ ) \
  X( state,                  "%u",         ( (CONN).state                  ), __VA_ARGS__ ) \
  X( reason,                 "%u",         ( (CONN).reason                 ), __VA_ARGS__ ) \
  X( app_reason,             "%u",         ( (CONN).app_reason             ), __VA_ARGS__ ) \
  X( tx_ptr,                 "%p",         ( ((void*)(CONN).tx_ptr)        ), __VA_ARGS__ ) \
  X( unacked_sz,             "%lu",        ( (CONN).unacked_sz             ), __VA_ARGS__ ) \
  X( flags,                  "%x",         ( (CONN).flags                  ), __VA_ARGS__ ) \
  X( conn_gen,               "%u",         ( (CONN).conn_gen               ), __VA_ARGS__ ) \
  X( server,                 "%d",         ( (CONN).server                 ), __VA_ARGS__ ) \
  X( established,            "%d",         ( (CONN).established            ), __VA_ARGS__ ) \
  X( transport_params_set,   "%d",         ( (CONN).transport_params_set   ), __VA_ARGS__ ) \
  X( called_conn_new,        "%d",         ( (CONN).called_conn_new        ), __VA_ARGS__ ) \
  X( visited,                "%d",         ( (CONN).visited                ), __VA_ARGS__ ) \
  X( key_phase,              "%d",         ( (CONN).key_phase              ), __VA_ARGS__ ) \
  X( key_update,             "%d",         ( (CONN).key_update             ), __VA_ARGS__ ) \
  X( our_conn_id,            "%016lx",     ( (CONN).our_conn_id            ), __VA_ARGS__ ) \
  X( peer[0].ip_addr,        "%08x",       ( (uint)(CONN).peer[0].ip_addr  ), __VA_ARGS__ ) \
  X( peer[0].udp_port,       "%u",         ( (uint)(CONN).peer[0].udp_port ), __VA_ARGS__ ) \
  X( handshake_complete,     "%d",         ( (CONN).handshake_complete     ), __VA_ARGS__ ) \
  X( handshake_done_send,    "%d",         ( (CONN).handshake_done_send    ), __VA_ARGS__ ) \
  X( handshake_done_ackd,    "%d",         ( (CONN).handshake_done_ackd    ), __VA_ARGS__ ) \
  X( exp_pkt_number[0],      "%lu",        ( (CONN).exp_pkt_number[0]      ), __VA_ARGS__ ) \
  X( exp_pkt_number[1],      "%lu",        ( (CONN).exp_pkt_number[1]      ), __VA_ARGS__ ) \
  X( exp_pkt_number[2],      "%lu",        ( (CONN).exp_pkt_number[2]      ), __VA_ARGS__ ) \
  X( pkt_number[0],          "%lu",        ( (CONN).pkt_number[0]          ), __VA_ARGS__ ) \
  X( pkt_number[1],          "%lu",        ( (CONN).pkt_number[1]          ), __VA_ARGS__ ) \
  X( pkt_number[2],          "%lu",        ( (CONN).pkt_number[2]          ), __VA_ARGS__ ) \
  X( last_pkt_number[0],     "%lu",        ( (CONN).last_pkt_number[0]     ), __VA_ARGS__ ) \
  X( last_pkt_number[1],     "%lu",        ( (CONN).last_pkt_number[1]     ), __VA_ARGS__ ) \
  X( last_pkt_number[2],     "%lu",        ( (CONN).last_pkt_number[2]     ), __VA_ARGS__ ) \
  X( idle_timeout_ns,        "%ld",        ( (CONN).idle_timeout_ns        ), __VA_ARGS__ ) \
  X( last_activity,          "%ld",        ( (CONN).last_activity          ), __VA_ARGS__ ) \
  X( last_ack,               "%ld",        ( (CONN).last_ack               ), __VA_ARGS__ ) \
  X( used_pkt_meta,          "%lu",        ( (CONN).used_pkt_meta          ), __VA_ARGS__ ) \
  X( peer_cid,               "%s",         ( peer_cid_str(&(CONN))         ), __VA_ARGS__ )

#define UNPACK(...) __VA_ARGS__
#define CONN_MEMB_FMT(NAME,FMT,ARGS,...)  " " #NAME "=" FMT
#define CONN_MEMB_ARGS(NAME,FMT,ARGS,...) , UNPACK ARGS
  FD_LOG_NOTICE(( "CONN: "
        CONN_MEMB_LIST(CONN_MEMB_FMT,*conn,_)
        CONN_MEMB_LIST(CONN_MEMB_ARGS,*conn,_)
        ));
}

void
quic_trace_cmd_fn( args_t *   args,
                   config_t * config ) {
  fd_topo_t * topo = &config->topo;
  fd_topo_join_workspaces( topo, FD_SHMEM_JOIN_MODE_READ_ONLY, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  fd_topo_fill( topo );

  int trace_send = args->quic_trace.trace_send;

  char const     * tile_names[] = {"quic", "send"};
  fd_topo_tile_t * target_tile  = NULL;
  for( ulong tile_idx=0UL; tile_idx<topo->tile_cnt; tile_idx++ ) {
    if( 0==strcmp( topo->tiles[tile_idx].name, tile_names[trace_send] ) ) {
      target_tile = &topo->tiles[tile_idx];
      break;
    }
  }
  if( !target_tile ) FD_LOG_ERR(( "%s tile not found in topology", tile_names[trace_send] ));

  ulong const target_in_cnt  = target_tile->in_cnt;
  ulong const target_out_cnt = target_tile->out_cnt;
  if( FD_UNLIKELY( !trace_send && target_in_cnt != 1UL ) ) { /* FIXME */
    FD_LOG_ERR(( "Sorry, fd_quic_trace does not support multiple net tiles yet" ));
  }

  /* Ugly: fd_quic_ctx_t uses non-relocatable object addressing.
     We need to rebase pointers. _remote{...} is local pointer to original
     objects in shared memory, _raddr is the remote address of the original
     object. */

  fd_quic_trace_tile_ctx_remote = fd_topo_obj_laddr( topo, target_tile->tile_obj_id );
  ulong quic_raddr              = (ulong)tile_member( fd_quic_trace_tile_ctx_remote, quic, trace_send );
  ulong tile_align              = fd_ulong_if( trace_send, alignof(fd_send_tile_ctx_t), alignof(fd_quic_ctx_t) );
  ulong tile_ctx_sz             = fd_ulong_if( trace_send, sizeof(fd_send_tile_ctx_t), sizeof(fd_quic_ctx_t) );
  fd_quic_trace_tile_ctx_raddr  = quic_raddr - fd_ulong_align_up( tile_ctx_sz, fd_ulong_max( tile_align, fd_quic_align() ) );

  FD_LOG_INFO(("quic_raddr %p", (void *)quic_raddr));
  FD_LOG_INFO((
      "%s tile state at %p in tile address space and %p in local address space",
      tile_names[trace_send], (void *)fd_quic_trace_tile_ctx_raddr, fd_quic_trace_tile_ctx_remote));

  /* target_net link tracking */
  char out_link_name[16];
  snprintf( out_link_name, sizeof(out_link_name), "%s_net", tile_names[trace_send] );
  ulong link_id = fd_topo_find_link( topo, out_link_name, 0 );
  if( FD_UNLIKELY( link_id == ULONG_MAX ) ) FD_LOG_ERR(("%s not found", out_link_name));
  fd_topo_link_t * target_net = &topo->links[link_id];

  /* net_target link tracking */
  snprintf( out_link_name, sizeof(out_link_name), "net_%s", tile_names[trace_send] );
  link_id = fd_topo_find_link( topo, out_link_name, 0 );
  if( FD_UNLIKELY( link_id == ULONG_MAX ) ) FD_LOG_ERR(("%s not found", out_link_name));

  fd_topo_link_t * net_target = &topo->links[link_id];
  fd_net_rx_bounds_t net_in_bounds;
  fd_net_rx_bounds_init(&net_in_bounds, net_target->dcache);
  FD_LOG_INFO(("net->%s dcache at %p", tile_names[trace_send], (void *)net_target->dcache));

  /* Join shared memory objects
     Mostly nops but verifies object magic numbers to ensure that
     derived pointers are correct. */

  FD_LOG_INFO(( "Joining fd_quic in %s tile", tile_names[trace_send] ));
  fd_quic_t * quic_remote = fd_type_pun( translate_ptr( (void*)quic_raddr ) );
  fd_quic_t * quic        = fd_quic_join( quic_remote );
  if( !quic ) FD_LOG_ERR( ("Failed to join fd_quic in %s tile", tile_names[trace_send]));

  /* build ctx */
  fd_quic_trace_ctx_t trace_ctx[1] = {
    {.dump          = args->quic_trace.dump,
     .dump_config   = args->quic_trace.dump_config,
     .dump_conns    = args->quic_trace.dump_conns,
     .trace_send    = args->quic_trace.trace_send,
     .net_out_base  = (ulong)fd_wksp_containing(target_net->dcache),
     .quic          = quic,
     .net_in_bounds = {net_in_bounds} } };

  /* dump config */
  if( trace_ctx->dump_config ) {
    dump_quic_config( &quic->config );
  }

  /* initialize peer conn_id map */
  void               * shmap    = peer_conn_id_map_new( _fd_quic_trace_peer_map );
  peer_conn_id_map_t * peer_map = peer_conn_id_map_join( shmap );

  /* set the global */
  fd_quic_trace_peer_map = peer_map;

  /* iterate connections - dump and/or insert */

#define CONN_STATE_LIST(X,SEP,...) \
  X( INVALID            , __VA_ARGS__ ) SEP \
  X( HANDSHAKE          , __VA_ARGS__ ) SEP \
  X( HANDSHAKE_COMPLETE , __VA_ARGS__ ) SEP \
  X( ACTIVE             , __VA_ARGS__ ) SEP \
  X( PEER_CLOSE         , __VA_ARGS__ ) SEP \
  X( ABORT              , __VA_ARGS__ ) SEP \
  X( CLOSE_PENDING      , __VA_ARGS__ ) SEP \
  X( DEAD               , __VA_ARGS__ )
  ulong conn_cnt      = quic->limits.conn_cnt;
  ulong state_unknown = 0;
#define COMMA ,
#define _(X,Y) [FD_QUIC_CONN_STATE_##X] = 0
  ulong state_cnt[] = { CONN_STATE_LIST(_,COMMA,Y) };
  ulong state_cap = sizeof( state_cnt) / sizeof( state_cnt[0] );
#undef _

  for( ulong j=0UL; j<conn_cnt; ++j ) {
    fd_quic_conn_t const * conn = fd_quic_trace_conn_at_idx( quic, j );
    ulong state = conn->state;
    ulong * state_bucket = state < state_cap ? &state_cnt[state] : &state_unknown;

    (*state_bucket)++;

    switch( conn->state ) {
      case FD_QUIC_CONN_STATE_INVALID:
        /* indicates the connection is free */
        break;
      default:
        if( trace_ctx->dump_conns ) {
          dump_connection( conn );
        }

        /* add connection to the peer_conn_id_map */

        /* when we receive a one-rtt quic packet, we don't know the conn_id
           size, so we assume its longer than 8 bytes, and truncate the rest */
        ulong key;
        memcpy( &key, conn->peer_cids[0].conn_id, sizeof( key ) );
        peer_conn_id_map_t * entry = peer_conn_id_map_insert( peer_map, key );
        if( entry ) {
          entry->conn_idx = (uint)j;
        } else {
          /* this is a diagnostics tool, so we'll continue here */
          FD_LOG_WARNING(( "Peer connection id map full. Continuing with partial functionality" ));
        }
    }
  }

#define _FMT(X,Y) "%s=%lu"
#define _ARG(X,Y) #X, state_cnt[FD_QUIC_CONN_STATE_##X]
  FD_LOG_NOTICE(( "Total connections: %lu  "
        CONN_STATE_LIST(_FMT,"  ",Y), conn_cnt,
        CONN_STATE_LIST(_ARG,COMMA,Y) ));
#undef _FMT
#undef _ARG

  /* Locate original fseq objects
     These are monitored to ensure the trace RX tile doesn't skip ahead
     of the target tile. */
  fd_quic_trace_target_fseq = malloc( target_in_cnt * sizeof(ulong) );
  for( ulong i=0UL; i<target_in_cnt; i++ ) {
    fd_quic_trace_target_fseq[i] = target_tile->in_link_fseq[i];
  }

  /* Locate log buffer */

  void * log = (void *)((ulong)quic_remote + quic->layout.log_off);
  fd_quic_log_rx_t log_rx[1];
  FD_LOG_DEBUG(( "Joining %s log", tile_names[trace_send] ));
  if( FD_UNLIKELY( !fd_quic_log_rx_join( log_rx, log ) ) ) {
    FD_LOG_ERR(( "fd_quic_log_rx_join failed" ));
  }
  fd_quic_trace_log_base = log_rx->base;

  /* Redirect metadata writes to dummy buffers.
     Without this hack, stem_run would attempt to write metadata updates
     into the target topology which is read-only. */

  /* ... redirect metric updates */
  ulong * metrics = aligned_alloc( FD_METRICS_ALIGN, FD_METRICS_FOOTPRINT( target_in_cnt, target_out_cnt ) );
  if( !metrics ) FD_LOG_ERR(( "out of memory" ));
  fd_memset( metrics, 0, FD_METRICS_FOOTPRINT( target_in_cnt, target_out_cnt ) );
  fd_metrics_register( metrics );

  fd_quic_trace_link_metrics = fd_metrics_link_in( fd_metrics_base_tl, 0 );

  /* Join net->target link consumer */

  fd_frag_meta_t const *rx_mcache = net_target->mcache;
  fd_frag_meta_t const *tx_mcache = target_net->mcache;

  trace_ctx->quic = quic;

  FD_LOG_NOTICE(( "quic-trace on %s tile starting ...", tile_names[trace_send] ));
  switch( args->quic_trace.event ) {
  case EVENT_STREAM:
    fd_quic_trace_rx_tile( trace_ctx, rx_mcache, tx_mcache );
    break;
  case EVENT_ERROR:
    fd_quic_trace_log_tile( trace_ctx, log_rx->mcache );
    break;
  default:
    __builtin_unreachable();
  }

  fd_quic_log_rx_leave( log_rx );
}

action_t fd_action_quic_trace = {
  .name          = "quic-trace",
  .args          = quic_trace_cmd_args,
  .fn            = quic_trace_cmd_fn,
  .description   = "Trace quic tile",
  .is_diagnostic = 1
};
