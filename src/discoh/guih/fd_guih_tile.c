/* The frontend assets are pre-built and statically compiled into the
   binary here.  To regenerate them, run

    $ git clone https://github.com/firedancer-io/firedancer-frontend.git frontend
    $ make frontend FRONTEND_CLIENT=Frankendancer

   from the repository root. */

#include "generated/http_import_dist.h"

/* STATIC_FILES is the null-terminated list of frontend assets baked into
   the binary.  It is defined in generated/http_import_dist.c and accessed
   in the gui_http_request callback. */

#include <sys/socket.h> /* SOCK_CLOEXEC, SOCK_NONBLOCK needed for seccomp filter */

#include "generated/fd_guih_tile_seccomp.h"

#include "../../disco/tiles.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "fd_guih.h"
#include "../../discoh/plugin/fd_plugin.h"
#include "../../discof/replay/fd_execrp.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/fd_clock_tile.h"
#include "../../discof/genesis/fd_genesi_tile.h" // TODO: Layering violation
#include "../../waltz/http/fd_http_server.h"
#include "../../waltz/http/fd_http_server_private.h"
#include "../../third_party/cjson/cJSON_alloc.h"
#include "../../discof/repair/fd_repair.h"
#include "../../discof/replay/fd_replay_tile.h"
#include "../../disco/shred/fd_shred_tile.h"

#define IN_KIND_PLUGIN        ( 0UL)
#define IN_KIND_POH_PACK      ( 1UL)
#define IN_KIND_PACK_EXECLE   ( 2UL)
#define IN_KIND_PACK_POH      ( 3UL)
#define IN_KIND_EXECLE_POH    ( 4UL)
#define IN_KIND_BUNDLE        (17UL)

FD_IMPORT_BINARY( firedancer_svg, "book/public/fire.svg" );

#define FD_HTTP_SERVER_GUI_MAX_REQUEST_LEN       65536
#define FD_HTTP_SERVER_GUI_MAX_WS_RECV_FRAME_LEN 65536
#define FD_HTTP_SERVER_GUI_MAX_WS_SEND_FRAME_CNT 8192

static fd_http_server_params_t
derive_http_params( fd_topo_tile_t const * tile ) {
  return (fd_http_server_params_t) {
    .max_connection_cnt    = tile->gui.max_http_connections,
    .max_ws_connection_cnt = tile->gui.max_websocket_connections,
    .max_request_len       = FD_HTTP_SERVER_GUI_MAX_REQUEST_LEN,
    .max_ws_recv_frame_len = FD_HTTP_SERVER_GUI_MAX_WS_RECV_FRAME_LEN,
    .max_ws_send_frame_cnt = FD_HTTP_SERVER_GUI_MAX_WS_SEND_FRAME_CNT,
    .outgoing_buffer_sz    = tile->gui.send_buffer_size_mb * (1UL<<20UL),
    .compress_websocket    = tile->gui.websocket_compression,
  };
}

struct fd_guih_in_ctx {
  fd_wksp_t * mem;
  ulong       mtu;
  ulong       chunk0;
  ulong       wmark;
};

typedef struct fd_guih_in_ctx fd_guih_in_ctx_t;

struct fd_guih_out_ctx {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
};

typedef struct fd_guih_out_ctx fd_guih_out_ctx_t;

typedef struct {
  fd_topo_t const * topo;

  fd_guih_t * gui;

  ulong in_cnt;
  ulong idle_cnt;

  /* Most of the gui tile uses fd_clock for timing, but some stem
     timestamps still used tickcounts, so we keep separate timestamps
     here to handle those cases until fd_clock is more widely adopted. */
  long ref_wallclock;
  long ref_tickcount;
  double tick_per_ns;

  fd_clock_tile_t clock[1];

  ulong chunk;

  fd_http_server_t * gui_server;

  long next_poll_deadline;

  fd_keyswitch_t * keyswitch;
  uchar const *    identity_key;

  int               has_vote_key;
  fd_pubkey_t const vote_key[ 1UL ];

  ulong           in_kind[ 64UL ];
  int             in_reliable[ 64UL ];
  ulong           in_bank_idx[ 64UL ];
  fd_guih_in_ctx_t in[ 64UL ];
} fd_guih_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  ulong a = alignof( fd_guih_ctx_t );
  a = fd_ulong_max( a, fd_http_server_align() );
  a = fd_ulong_max( a, fd_guih_align() );
  a = fd_ulong_max( a, fd_alloc_align() );
  return a;
}

static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  fd_http_server_params_t http_param = derive_http_params( tile );
  ulong http_fp = fd_http_server_footprint( http_param );
  if( FD_UNLIKELY( !http_fp ) ) FD_LOG_ERR(( "Invalid [tiles.gui] config parameters" ));

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_guih_ctx_t ), sizeof( fd_guih_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, fd_http_server_align(),  http_fp );
  l = FD_LAYOUT_APPEND( l, fd_guih_align(),          fd_guih_footprint( tile->gui.tile_cnt ) );
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(),        fd_alloc_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 256UL * (1UL<<20UL); /* 256MiB of heap space for the cJSON allocator */
}

static inline void
during_housekeeping( fd_guih_ctx_t * ctx ) {
  ctx->ref_wallclock = fd_log_wallclock();
  ctx->ref_tickcount = fd_tickcount();

  if( FD_UNLIKELY( fd_clock_tile_recal_due( ctx->clock ) ) ) {
    fd_clock_tile_recal( ctx->clock );
  }

  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    fd_guih_set_identity( ctx->gui, ctx->keyswitch->bytes );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static inline void
metrics_write( fd_guih_ctx_t * ctx ) {
  FD_MGAUGE_SET( GUIH, CONN_ACTIVE, ctx->gui_server->metrics.connection_cnt );
  FD_MGAUGE_SET( GUIH, WEBSOCKET_CONN_ACTIVE, ctx->gui_server->metrics.ws_connection_cnt );

  FD_MCNT_SET( GUIH, WEBSOCKET_FRAME_TX, ctx->gui_server->metrics.frames_written );
  FD_MCNT_SET( GUIH, WEBSOCKET_FRAME_RX, ctx->gui_server->metrics.frames_read );

  FD_MCNT_SET( GUIH, BYTES_WRITTEN, ctx->gui_server->metrics.bytes_written );
  FD_MCNT_SET( GUIH, BYTES_READ,    ctx->gui_server->metrics.bytes_read );
}

static void
before_credit( fd_guih_ctx_t *      ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  ctx->idle_cnt++;
  if( FD_LIKELY( ctx->idle_cnt<2UL*ctx->in_cnt ) ) return;
  ctx->idle_cnt = 0UL;

  int charge_busy_server = 0;
  long now = fd_tickcount();
  if( FD_UNLIKELY( now>=ctx->next_poll_deadline ) ) {
    charge_busy_server = fd_http_server_poll( ctx->gui_server, 0 );
    ctx->next_poll_deadline = fd_tickcount() + (long)(ctx->tick_per_ns * 128L * 1000L);
  }

  int charge_poll = 0;
  charge_poll |= fd_guih_poll( ctx->gui, fd_clock_tile_now( ctx->clock ) );

  *charge_busy = charge_busy_server | charge_poll;
}

static int
before_frag( fd_guih_ctx_t * ctx,
             ulong          in_idx,
             ulong          seq,
             ulong          sig ) {
  (void)seq;

  /* Ignore "done draining banks" and "reduce microblock bound" signals from pack->poh */
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_PACK_POH && (sig==FD_PACK_MSG_DONE_DRAINING || sig==FD_PACK_MSG_REDUCE_MB_BOUND) ) ) return 1;

  return 0;
}

static inline void
during_frag( fd_guih_ctx_t * ctx,
             ulong          in_idx,
             ulong          seq FD_PARAM_UNUSED,
             ulong          sig,
             ulong          chunk,
             ulong          sz,
             ulong          ctl FD_PARAM_UNUSED ) {

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_PLUGIN ) ) {
    /* ... todo... sigh, sz is not correct since it's too big */
    if( FD_LIKELY( sig==FD_PLUGIN_MSG_GOSSIP_UPDATE ) ) {
      ulong peer_cnt = FD_LOAD( ulong, src );
      FD_TEST( peer_cnt<=FD_GUIH_MAX_PEER_CNT );
      sz = 8UL + peer_cnt*FD_GOSSIP_LINK_MSG_SIZE;
    } else if( FD_LIKELY( sig==FD_PLUGIN_MSG_VOTE_ACCOUNT_UPDATE ) ) {
      ulong peer_cnt = FD_LOAD( ulong, src );
      FD_TEST( peer_cnt<=FD_GUIH_MAX_PEER_CNT );
      sz = 8UL + peer_cnt*112UL;
    } else if( FD_UNLIKELY( sig==FD_PLUGIN_MSG_LEADER_SCHEDULE ) ) {
      ulong staked_vote_cnt = FD_LOAD( ulong, src+8UL );
      ulong staked_id_cnt   = FD_LOAD( ulong, src+16UL );
      FD_TEST( staked_vote_cnt<=MAX_COMPRESSED_STAKE_WEIGHTS );
      FD_TEST( staked_id_cnt<=MAX_SHRED_DESTS );
      sz = fd_stake_weight_msg_sz( staked_vote_cnt, staked_id_cnt );
    }
  }

  if( FD_UNLIKELY( (sz>0UL && (chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark)) || sz>ctx->in[ in_idx ].mtu ) )
    FD_LOG_ERR(( "in_kind %lu chunk %lu %lu corrupt, not in range [%lu,%lu] or too large (%lu)", ctx->in_kind[ in_idx ], chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark, ctx->in[ in_idx ].mtu ));

  ctx->chunk = chunk;
}

static inline void
after_frag( fd_guih_ctx_t *      ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig FD_PARAM_UNUSED,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)seq; (void)stem;

  if( FD_LIKELY( ctx->in_reliable[ in_idx ] ) ) ctx->idle_cnt = 0UL;

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, ctx->chunk );

  switch( ctx->in_kind[ in_idx ] ) {
    case IN_KIND_PLUGIN: {
      fd_guih_plugin_message( ctx->gui, sig, src, fd_clock_tile_now( ctx->clock ) );
      break;
    }
    case IN_KIND_POH_PACK: {
      FD_TEST( fd_disco_poh_sig_pkt_type( sig )==POH_PKT_TYPE_BECAME_LEADER );
      fd_became_leader_t * became_leader = (fd_became_leader_t *)src;
      fd_guih_became_leader( ctx->gui, fd_disco_poh_sig_slot( sig ), became_leader->slot_start_ns, became_leader->slot_end_ns, became_leader->limits.slot_max_cost, became_leader->max_microblocks_in_slot );
      break;
    }
    case IN_KIND_PACK_POH: {
      fd_guih_unbecame_leader( ctx->gui, fd_disco_execle_sig_slot( sig ), (fd_done_packing_t const *)src, fd_clock_tile_now( ctx->clock ) );
      break;
    }
    case IN_KIND_PACK_EXECLE: {
      FD_TEST( sz>=sizeof(fd_microblock_execle_trailer_t) );
      FD_TEST( (sz-sizeof(fd_microblock_execle_trailer_t))%sizeof(fd_txn_e_t)==0UL );

      if( FD_LIKELY( fd_disco_poh_sig_pkt_type( sig )==POH_PKT_TYPE_MICROBLOCK ) ) {
        fd_microblock_execle_trailer_t trailer[1];
        fd_memcpy( trailer, src+sz-sizeof(fd_microblock_execle_trailer_t), sizeof(fd_microblock_execle_trailer_t) );
        long tspub_ns = ctx->ref_wallclock + (long)((double)(fd_frag_meta_ts_decomp( tspub, fd_tickcount() ) - ctx->ref_tickcount) / ctx->tick_per_ns);
        fd_guih_microblock_execution_begin( ctx->gui,
                                          tspub_ns,
                                          fd_disco_poh_sig_slot( sig ),
                                          (fd_txn_e_t *)src,
                                          (sz-sizeof( fd_microblock_execle_trailer_t ))/sizeof( fd_txn_e_t ),
                                          (uint)trailer->microblock_idx,
                                          trailer->pack_txn_idx );
      } else {
        FD_LOG_ERR(( "unexpected poh packet type %lu", fd_disco_poh_sig_pkt_type( sig ) ));
      }
      break;
    }
    case IN_KIND_EXECLE_POH: {
      FD_TEST( sz>=sizeof(fd_microblock_trailer_t) );
      FD_TEST( (sz-sizeof(fd_microblock_trailer_t))%sizeof(fd_txn_p_t)==0UL );

      fd_microblock_trailer_t trailer[1];
      fd_memcpy( trailer, src+sz-sizeof(fd_microblock_trailer_t), sizeof(fd_microblock_trailer_t) );
      long tspub_ns = ctx->ref_wallclock + (long)((double)(fd_frag_meta_ts_decomp( tspub, fd_tickcount() ) - ctx->ref_tickcount) / ctx->tick_per_ns);
      ulong txn_cnt = (sz-sizeof( fd_microblock_trailer_t ))/sizeof(fd_txn_p_t);
      fd_guih_microblock_execution_end( ctx->gui,
                                      tspub_ns,
                                      ctx->in_bank_idx[ in_idx ],
                                      fd_disco_execle_sig_slot( sig ),
                                      txn_cnt,
                                      (fd_txn_p_t *)src,
                                      trailer->pack_txn_idx,
                                      trailer->txn_ns_dt,
                                      trailer->tips );
      break;
    }
    case IN_KIND_BUNDLE: {
      fd_guih_handle_block_engine_update( ctx->gui, (fd_bundle_block_engine_update_t *)src );
      break;
    }
    default: FD_LOG_ERR(( "unexpected in_kind %lu", ctx->in_kind[ in_idx ] ));
  }
}

static fd_http_server_response_t
gui_http_request( fd_http_server_request_t const * request ) {
  if( FD_UNLIKELY( request->method!=FD_HTTP_SERVER_METHOD_GET ) ) {
    return (fd_http_server_response_t){
      .status = 405,
    };
  }

  if( FD_LIKELY( !strcmp( request->path, "/websocket" ) ) ) {
    return (fd_http_server_response_t){
      .status            = 200,
      .upgrade_websocket = 1,
#ifdef FD_HAS_ZSTD
      .compress_websocket = request->headers.compress_websocket,
#else
      .compress_websocket = 0,
#endif
    };
  } else if( FD_LIKELY( !strcmp( request->path, "/favicon.svg" ) ) ) {
    return (fd_http_server_response_t){
      .status            = 200,
      .static_body       = firedancer_svg,
      .static_body_len   = firedancer_svg_sz,
      .content_type      = "image/svg+xml",
      .upgrade_websocket = 0,
    };
  }

  int is_vite_page = !strcmp( request->path, "/" ) ||
                     !strcmp( request->path, "/slotDetails" ) ||
                     !strcmp( request->path, "/leaderSchedule" ) ||
                     !strcmp( request->path, "/gossip") ||
                     !strncmp( request->path, "/?", strlen("/?") ) ||
                     !strncmp( request->path, "/slotDetails?", strlen("/slotDetails?") ) ||
                     !strncmp( request->path, "/leaderSchedule?", strlen("/leaderSchedule?") ) ||
                     !strncmp( request->path, "/gossip?", strlen("/gossip?") );

  for( fd_http_static_file_t const * f = STATIC_FILES; f->name; f++ ) {
    if( !strcmp( request->path, f->name ) ||
        (!strcmp( f->name, "/index.html" ) && is_vite_page) ) {
      char const * content_type = NULL;

      char const * ext = strrchr( f->name, '.' );
      if( FD_LIKELY( ext ) ) {
        if( !strcmp( ext, ".html" ) ) content_type = "text/html; charset=utf-8";
        else if( !strcmp( ext, ".css" ) ) content_type = "text/css";
        else if( !strcmp( ext, ".js" ) ) content_type = "application/javascript";
        else if( !strcmp( ext, ".svg" ) ) content_type = "image/svg+xml";
        else if( !strcmp( ext, ".woff" ) ) content_type = "font/woff";
        else if( !strcmp( ext, ".woff2" ) ) content_type = "font/woff2";
      }

      char const * cache_control = NULL;
      if( FD_LIKELY( !strncmp( request->path, "/assets", 7 ) ) ) cache_control = "public, max-age=31536000, immutable";
      else if( FD_LIKELY( !strcmp( f->name, "/index.html" ) ) )  cache_control = "no-cache";

      const uchar * data = f->data;
      ulong data_len = *(f->data_len);

      int accepts_zstd = 0;
      if( FD_LIKELY( request->headers.accept_encoding ) ) {
        accepts_zstd = !!strstr( request->headers.accept_encoding, "zstd" );
      }

      int accepts_gzip = 0;
      if( FD_LIKELY( request->headers.accept_encoding ) ) {
        accepts_gzip = !!strstr( request->headers.accept_encoding, "gzip" );
      }

      char const * content_encoding = NULL;
      if( FD_LIKELY( accepts_zstd && f->zstd_data ) ) {
        content_encoding = "zstd";
        data = f->zstd_data;
        data_len = *(f->zstd_data_len);
      } else if( FD_LIKELY( accepts_gzip && f->gzip_data ) ) {
        content_encoding = "gzip";
        data = f->gzip_data;
        data_len = *(f->gzip_data_len);
      }

      return (fd_http_server_response_t){
        .status            = 200,
        .static_body       = data,
        .static_body_len   = data_len,
        .content_type      = content_type,
        .cache_control     = cache_control,
        .content_encoding  = content_encoding,
        .upgrade_websocket = 0,
      };
    }
  }

  return (fd_http_server_response_t){
    .status            = 404,
  };
}

static void
gui_ws_open( ulong  conn_id,
             void * _ctx ) {
  fd_guih_ctx_t * ctx = (fd_guih_ctx_t *)_ctx;

  fd_guih_ws_open( ctx->gui, conn_id, fd_clock_tile_now( ctx->clock ) );
}

static void
gui_ws_close( ulong  conn_id,
              int    reason,
              void * _ctx ) {
  (void) reason;
  (void) conn_id;
  (void) _ctx;
}

static void
gui_ws_message( ulong         ws_conn_id,
                uchar const * data,
                ulong         data_len,
                void *        _ctx ) {
  fd_guih_ctx_t * ctx = (fd_guih_ctx_t *)_ctx;

  int reason = fd_guih_ws_message( ctx->gui, ws_conn_id, data, data_len );

  if( FD_UNLIKELY( reason<0 ) ) fd_http_server_ws_close( ctx->gui_server, ws_conn_id, reason );
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_guih_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_guih_ctx_t ), sizeof( fd_guih_ctx_t ) );

  fd_http_server_params_t http_param = derive_http_params( tile );
  fd_http_server_t * _gui = FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(), fd_http_server_footprint( http_param ) );

  fd_http_server_callbacks_t gui_callbacks = {
    .request    = gui_http_request,
    .ws_open    = gui_ws_open,
    .ws_close   = gui_ws_close,
    .ws_message = gui_ws_message,
  };
  ctx->gui_server = fd_http_server_join( fd_http_server_new( _gui, http_param, gui_callbacks, ctx ) );
  fd_http_server_listen( ctx->gui_server, tile->gui.listen_addr, tile->gui.listen_port );

  FD_LOG_NOTICE(( "gui server listening at http://" FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS( tile->gui.listen_addr ), tile->gui.listen_port ));

  if( FD_UNLIKELY( !strcmp( tile->gui.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key = fd_keyload_load( tile->gui.identity_key_path, /* pubkey only: */ 1 );

  if( FD_UNLIKELY( !strcmp( tile->gui.vote_key_path, "" ) ) ) {
    ctx->has_vote_key = 0;
  } else {
    ctx->has_vote_key = 1;
    if( FD_UNLIKELY( !fd_base58_decode_32( tile->gui.vote_key_path, (uchar *)ctx->vote_key->uc ) ) ) {
      const uchar * vote_key = fd_keyload_load( tile->gui.vote_key_path, /* pubkey only: */ 1 );
      fd_memcpy( (uchar *)ctx->vote_key->uc, vote_key, 32UL );
    }
  }
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  fd_http_server_params_t http_param = derive_http_params( tile );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_guih_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_guih_ctx_t ), sizeof( fd_guih_ctx_t )                                    );
                       FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(),  fd_http_server_footprint( http_param )                    );
  void * _gui        = FD_SCRATCH_ALLOC_APPEND( l, fd_guih_align(),          fd_guih_footprint( tile->gui.tile_cnt )                    );
  void * _alloc      = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(),        fd_alloc_footprint()                                      );

  fd_clock_tile_init( ctx->clock );

  ctx->ref_wallclock = fd_log_wallclock();
  ctx->ref_tickcount = fd_tickcount();
  ctx->tick_per_ns = fd_tempo_tick_per_ns( NULL );

  ctx->topo = topo;
  ctx->gui   = fd_guih_join( fd_guih_new( _gui, ctx->gui_server, fd_version_cstr, tile->gui.cluster, ctx->identity_key, ctx->has_vote_key, ctx->vote_key->uc, 0, 0, tile->gui.is_voting, tile->gui.schedule_strategy, tile->gui.wfs_bank_hash, tile->gui.expected_shred_version, ctx->topo, fd_clock_tile_now( ctx->clock ) ) );
  FD_TEST( ctx->gui );

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( _alloc, 1UL ), 1UL );
  FD_TEST( alloc );
  cJSON_alloc_install( alloc );

  ctx->next_poll_deadline = fd_tickcount();

  ctx->idle_cnt = 0UL;
  ctx->in_cnt = tile->in_cnt;

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if( FD_LIKELY( !strcmp( link->name, "plugin_out"        ) ) ) ctx->in_kind[ i ] = IN_KIND_PLUGIN;
    else if( FD_LIKELY( !strcmp( link->name, "pohh_pack"    ) ) ) ctx->in_kind[ i ] = IN_KIND_POH_PACK;
    else if( FD_LIKELY( !strcmp( link->name, "pack_bank"    ) ) ) ctx->in_kind[ i ] = IN_KIND_PACK_EXECLE;
    else if( FD_LIKELY( !strcmp( link->name, "pack_pohh"    ) ) ) ctx->in_kind[ i ] = IN_KIND_PACK_POH;
    else if( FD_LIKELY( !strcmp( link->name, "bank_pohh"    ) ) ) ctx->in_kind[ i ] = IN_KIND_EXECLE_POH;
    else if( FD_LIKELY( !strcmp( link->name, "bundle_status" ) ) ) ctx->in_kind[ i ] = IN_KIND_BUNDLE;
    else FD_LOG_ERR(( "gui tile has unexpected input link %lu %s", i, link->name ));

    if( FD_LIKELY( !strcmp( link->name, "bank_pohh" ) ) ) {
      ulong producer = fd_topo_find_link_producer( topo, &topo->links[ tile->in_link_id[ i ] ] );
      ctx->in_bank_idx[ i ] = topo->tiles[ producer ].kind_id;
    }

    ctx->in_reliable[ i ] = tile->in_link_reliable[ i ];
    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].mtu    = link->mtu;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_guih_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_guih_ctx_t ), sizeof( fd_guih_ctx_t ) );

  populate_sock_filter_policy_fd_guih_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)fd_http_server_fd( ctx->gui_server ) );
  return sock_filter_policy_fd_guih_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_guih_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_guih_ctx_t ), sizeof( fd_guih_ctx_t ) );

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = fd_http_server_fd( ctx->gui_server ); /* gui listen socket */
  return out_cnt;
}

static ulong
rlimit_file_cnt( fd_topo_t const *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t const * tile ) {
  /* pipefd, socket, stderr, logfile, and one spare for new accept() connections */
  ulong base = 5UL;
  return base + tile->gui.max_http_connections + tile->gui.max_websocket_connections;
}

#define STEM_BURST (2UL)

/* See explanation in fd_pack */
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_guih_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_guih_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_guih = {
  .name                     = "guih",
  .rlimit_file_cnt_fn       = rlimit_file_cnt,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .loose_footprint          = loose_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
