#include "tiles.h"

#include "generated/http_seccomp.h"

#include "../../version.h"

#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../disco/shred/fd_stake_ci.h"
#include "../../../../disco/metrics/fd_prometheus.h"
#include "../../../../disco/gui/fd_gui.h"
#include "../../../../ballet/base58/fd_base58.h"
#include "../../../../ballet/http/fd_http_server.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <stdio.h>

#define FD_HTTP_SERVER_METRICS_MAX_CONNS        8
#define FD_HTTP_SERVER_METRICS_MAX_REQUEST_LEN  1024
#define FD_HTTP_SERVER_METRICS_MAX_RESPONSE_LEN 16777216

#define FD_HTTP_SERVER_GUI_MAX_CONNS             8
#define FD_HTTP_SERVER_GUI_MAX_REQUEST_LEN       1024
#define FD_HTTP_SERVER_GUI_MAX_WS_CONNS          1024
#define FD_HTTP_SERVER_GUI_MAX_WS_RECV_FRAME_LEN 1024
#define FD_HTTP_SERVER_GUI_MAX_WS_SEND_FRAME_CNT 1024
#define FD_HTTP_SERVER_GUI_SEND_BUFFER_SZ        (1024UL*1024UL*1024UL) /* 1GiB reserved for buffering GUI websockets */

FD_IMPORT_BINARY( firedancer_svg, "book/public/fire.svg" );
FD_IMPORT_BINARY( index_html, "src/app/fdctl/run/tiles/index.html" );

typedef struct {
  fd_topo_t * topo;

  fd_gui_t * gui;
  uchar      buf[ 8UL+40200UL*38UL ];

  fd_http_server_t * gui_server;

  fd_http_server_t * metrics_server;
  char               metrics_responses[ FD_HTTP_SERVER_METRICS_MAX_CONNS ][ FD_HTTP_SERVER_METRICS_MAX_RESPONSE_LEN ];

  char         version_string[ 16UL ];
  char         identity_key_str[ FD_BASE58_ENCODED_32_SZ ];

  fd_wksp_t * in_mem;
  ulong       in_chunk0;
  ulong       in_wmark;
} fd_http_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  return 5UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_http_ctx_t ), sizeof( fd_http_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, fd_http_server_align(), fd_http_server_footprint( FD_HTTP_SERVER_GUI_MAX_CONNS, FD_HTTP_SERVER_GUI_MAX_WS_CONNS, FD_HTTP_SERVER_GUI_MAX_REQUEST_LEN, FD_HTTP_SERVER_GUI_MAX_WS_RECV_FRAME_LEN, FD_HTTP_SERVER_GUI_MAX_WS_SEND_FRAME_CNT ) );
  l = FD_LAYOUT_APPEND( l, fd_http_server_align(), fd_http_server_footprint( FD_HTTP_SERVER_METRICS_MAX_CONNS, 0UL, FD_HTTP_SERVER_METRICS_MAX_REQUEST_LEN, 0UL, 0UL ) );
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(),       fd_alloc_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_gui_align(),         fd_gui_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof( fd_http_ctx_t ) );
}

static void
before_credit( void *             _ctx,
               fd_mux_context_t * mux ) {
  (void)mux;

  fd_http_ctx_t * ctx = (fd_http_ctx_t *)_ctx;
  fd_http_server_poll( ctx->gui_server );
  fd_http_server_poll( ctx->metrics_server );
}

static inline void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)in_idx;
  (void)seq;
  (void)sig;
  (void)opt_filter;

  fd_http_ctx_t * ctx = (fd_http_ctx_t *)_ctx;

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in_mem, chunk );
  fd_memcpy( ctx->buf, src, sz );
}

static inline void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            ulong *            opt_tsorig,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)in_idx;
  (void)seq;
  (void)opt_chunk;
  (void)opt_tsorig;
  (void)opt_filter;
  (void)mux;

  fd_http_ctx_t * ctx = (fd_http_ctx_t *)_ctx;

  fd_gui_plugin_message( ctx->gui, *opt_sig, ctx->buf, *opt_sz );
}

static fd_http_server_response_t
metrics_http_request( ulong        conn_id,
                      char const * path,
                      void *       _ctx ) {
  fd_http_ctx_t * ctx = (fd_http_ctx_t *)_ctx;

  if( FD_LIKELY( !strcmp( path, "/metrics" ) ) ) {
    ulong out_len = FD_HTTP_SERVER_METRICS_MAX_RESPONSE_LEN;
    int failed = fd_prometheus_format( ctx->topo, ctx->metrics_responses[ conn_id ], &out_len );
    return (fd_http_server_response_t){
      .status            = failed ? 500 : 200,
      .body              = (uchar const *)ctx->metrics_responses[ conn_id ],
      .body_len          = FD_HTTP_SERVER_METRICS_MAX_RESPONSE_LEN-out_len,
      .content_type      = "text/plain; version=0.0.4",
      .upgrade_websocket = 0,
    };
  } else {
    return (fd_http_server_response_t){
      .status            = 404,
    };
  }
}

static fd_http_server_response_t
gui_http_request( ulong        conn_id,
                  char const * path,
                  void *       _ctx ) {
  (void)conn_id;
  (void)_ctx;

  if( FD_LIKELY( !strcmp( path, "/" ) ) ) {
    return (fd_http_server_response_t){
      .status            = 200,
      .body              = index_html,
      .body_len          = index_html_sz,
      .content_type      = "text/html; charset=utf-8",
      .upgrade_websocket = 0,
    };
  } else if( FD_LIKELY( !strcmp( path, "/favicon.svg" ) ) ) {
    return (fd_http_server_response_t){
      .status            = 200,
      .body              = firedancer_svg,
      .body_len          = firedancer_svg_sz,
      .content_type      = "image/svg+xml",
      .upgrade_websocket = 0,
    };
  } else if( FD_LIKELY( !strcmp( path, "/websocket" ) ) ) {
    return (fd_http_server_response_t){
      .status            = 200,
      .upgrade_websocket = 1,
    };
  } else {
    return (fd_http_server_response_t){
      .status            = 404,
    };
  }
}

static void
gui_ws_open( ulong   conn_id,
             void *  _ctx ) {
  fd_http_ctx_t * ctx = (fd_http_ctx_t *)_ctx;

  fd_gui_ws_open( ctx->gui, conn_id );
}

static void
gui_ws_message( ulong              conn_id,
                uchar const *      data,
                ulong              data_len,
                void *             _ctx ) {
  fd_http_ctx_t * ctx = (fd_http_ctx_t *)_ctx;

  (void)data;
  (void)data_len;

  FD_LOG_WARNING(( "message: %s", (char*)data ));
  fd_http_server_ws_send( ctx->gui_server, conn_id, (uchar const *)"pong", 4UL );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  (void)topo;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_http_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_http_ctx_t ), sizeof( fd_http_ctx_t ) );

  fd_http_server_t * _gui     = FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(), fd_http_server_footprint( FD_HTTP_SERVER_GUI_MAX_CONNS, FD_HTTP_SERVER_GUI_MAX_WS_CONNS, FD_HTTP_SERVER_GUI_MAX_REQUEST_LEN, FD_HTTP_SERVER_GUI_MAX_WS_RECV_FRAME_LEN, FD_HTTP_SERVER_GUI_MAX_WS_SEND_FRAME_CNT ) );
  fd_http_server_t * _metrics = FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(), fd_http_server_footprint( FD_HTTP_SERVER_METRICS_MAX_CONNS, 0UL, FD_HTTP_SERVER_METRICS_MAX_REQUEST_LEN, 0UL, 0UL ) );

  fd_http_server_callbacks_t gui_callbacks = {
    .request    = gui_http_request,
    .ws_open    = gui_ws_open,
    .ws_message = gui_ws_message,
  };
  ctx->gui_server = fd_http_server_join( fd_http_server_new( _gui, FD_HTTP_SERVER_GUI_MAX_CONNS, FD_HTTP_SERVER_GUI_MAX_WS_CONNS, FD_HTTP_SERVER_GUI_MAX_REQUEST_LEN, FD_HTTP_SERVER_GUI_MAX_WS_RECV_FRAME_LEN, FD_HTTP_SERVER_GUI_MAX_WS_SEND_FRAME_CNT, gui_callbacks, ctx ) );
  fd_http_server_listen( ctx->gui_server, tile->http.gui_listen_port );

  fd_http_server_callbacks_t metrics_callbacks = {
    .request = metrics_http_request,
  };
  ctx->metrics_server = fd_http_server_join( fd_http_server_new( _metrics, FD_HTTP_SERVER_METRICS_MAX_CONNS, 0UL, FD_HTTP_SERVER_METRICS_MAX_REQUEST_LEN, 0UL, 0UL, metrics_callbacks, ctx ) );
  fd_http_server_listen( ctx->metrics_server, tile->http.prometheus_listen_port );

  if( FD_UNLIKELY( !strcmp( tile->http.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  const uchar * identity_key = fd_keyload_load( tile->http.identity_key_path, /* pubkey only: */ 1 );
  fd_base58_encode_32( identity_key, NULL, ctx->identity_key_str );
  ctx->identity_key_str[ FD_BASE58_ENCODED_32_SZ-1UL ] = '\0';
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  (void)topo;

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_http_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_http_ctx_t ), sizeof( fd_http_ctx_t ) );

                  FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(), fd_http_server_footprint( FD_HTTP_SERVER_GUI_MAX_CONNS, FD_HTTP_SERVER_GUI_MAX_WS_CONNS, FD_HTTP_SERVER_GUI_MAX_REQUEST_LEN, FD_HTTP_SERVER_GUI_MAX_WS_RECV_FRAME_LEN, FD_HTTP_SERVER_GUI_MAX_WS_SEND_FRAME_CNT ) );
                  FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(), fd_http_server_footprint( FD_HTTP_SERVER_METRICS_MAX_CONNS, 0UL, FD_HTTP_SERVER_METRICS_MAX_REQUEST_LEN, 0UL, 0UL ) );
  void * _alloc = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(),       fd_alloc_footprint() );
  void * _gui   = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_align(),         fd_gui_footprint() );

  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( _alloc, 1UL ), tile->kind_id );
  FD_TEST( alloc );

  FD_TEST( fd_cstr_printf_check( ctx->version_string, sizeof( ctx->version_string ), NULL, "%d.%d.%d", FD_VERSION_MAJOR, FD_VERSION_MINOR, FD_VERSION_PATCH ) );

  ctx->topo    = topo;
  ctx->gui     = fd_gui_join( fd_gui_new( _gui, ctx->gui_server, alloc, ctx->version_string, tile->http.cluster, ctx->identity_key_str ) );
  FD_TEST( ctx->gui );

  fd_topo_link_t * link = &topo->links[ tile->in_link_id[ 0 ] ];
  fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

  ctx->in_mem    = link_wksp->wksp;
  ctx->in_chunk0 = fd_dcache_compact_chunk0( ctx->in_mem, link->dcache );
  ctx->in_wmark  = fd_dcache_compact_wmark ( ctx->in_mem, link->dcache, link->mtu );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  FD_LOG_NOTICE(( "GUI server listening on port %u", tile->http.gui_listen_port ));
  FD_LOG_NOTICE(( "Prometheus server listening on port %u", tile->http.prometheus_listen_port ));
}

static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_http_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_http_ctx_t ), sizeof( fd_http_ctx_t ) );

  populate_sock_filter_policy_http( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->gui_server->socket_fd, (uint)ctx->metrics_server->socket_fd );
  return sock_filter_policy_http_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_http_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_http_ctx_t ), sizeof( fd_http_ctx_t ) );

  if( FD_UNLIKELY( out_fds_cnt<4UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->gui_server->socket_fd; /* gui listen socket */
  out_fds[ out_cnt++ ] = ctx->metrics_server->socket_fd; /* metrics listen socket */
  return out_cnt;
}

fd_topo_run_tile_t fd_tile_http = {
  .name                     = "http",
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .rlimit_file_cnt          = FD_HTTP_SERVER_METRICS_MAX_CONNS+FD_HTTP_SERVER_GUI_MAX_CONNS+FD_HTTP_SERVER_GUI_MAX_WS_CONNS+5UL, /* pipefd, socket, stderr, logfile, and one spare for new accept() connections */
  .mux_ctx                  = mux_ctx,
  .mux_before_credit        = before_credit,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .loose_footprint          = loose_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};
