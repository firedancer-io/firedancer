#include "../../../../disco/tiles.h"

/* The frontend assets are pre-built and statically compiled into the
   binary here.  To regenerate them, run

    $ git clone https://github.com/firedancer-io/firedancer-frontend.git frontend
    $ make frontend

   from the repository root. */

#include "generated/http_import_dist.h"

#include <sys/socket.h> /* SOCK_CLOEXEC, SOCK_NONBLOCK needed for seccomp filter */
#if defined(__aarch64__)
#include "generated/gui.arm64_seccomp.h"
#else
#include "generated/gui_seccomp.h"
#endif

#include "../../version.h"

#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../disco/shred/fd_stake_ci.h"
#include "../../../../disco/gui/fd_gui.h"
#include "../../../../disco/plugin/fd_plugin.h"
#include "../../../../ballet/base58/fd_base58.h"
#include "../../../../ballet/http/fd_http_server.h"

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <stdio.h>

FD_IMPORT_BINARY( firedancer_svg, "book/public/fire.svg" );

#define FD_HTTP_SERVER_GUI_MAX_CONNS             1024
#define FD_HTTP_SERVER_GUI_MAX_REQUEST_LEN       1024
#define FD_HTTP_SERVER_GUI_MAX_WS_CONNS          1024
#define FD_HTTP_SERVER_GUI_MAX_WS_RECV_FRAME_LEN 1024
#define FD_HTTP_SERVER_GUI_MAX_WS_SEND_FRAME_CNT 8192
#define FD_HTTP_SERVER_GUI_OUTGOING_BUFFER_SZ    (5UL<<30UL) /* 5GiB reserved for buffering GUI websockets */

const fd_http_server_params_t GUI_PARAMS = {
  .max_connection_cnt    = FD_HTTP_SERVER_GUI_MAX_CONNS,
  .max_ws_connection_cnt = FD_HTTP_SERVER_GUI_MAX_WS_CONNS,
  .max_request_len       = FD_HTTP_SERVER_GUI_MAX_REQUEST_LEN,
  .max_ws_recv_frame_len = FD_HTTP_SERVER_GUI_MAX_WS_RECV_FRAME_LEN,
  .max_ws_send_frame_cnt = FD_HTTP_SERVER_GUI_MAX_WS_SEND_FRAME_CNT,
  .outgoing_buffer_sz    = FD_HTTP_SERVER_GUI_OUTGOING_BUFFER_SZ,
};

typedef struct {
  fd_topo_t * topo;

  fd_gui_t * gui;

  /* This needs to be max(plugin_msg) across all kinds of messages.
     Currently this is just figured out manually, it's a gossip update
     message assuming the table is completely full (40200) of peers. */
  uchar      buf[ 8UL+40200UL*(58UL+12UL*34UL) ] __attribute__((aligned(8)));

  fd_http_server_t * gui_server;

  char          version_string[ 16UL ];
  uchar const * identity_key;

  fd_wksp_t * in_mem;
  ulong       in_chunk0;
  ulong       in_wmark;
} fd_gui_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_gui_ctx_t ), sizeof( fd_gui_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, fd_http_server_align(),  fd_http_server_footprint( GUI_PARAMS ) );
  l = FD_LAYOUT_APPEND( l, fd_gui_align(),          fd_gui_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static int
before_credit( fd_gui_ctx_t *      ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  int charge_busy_server = fd_http_server_poll( ctx->gui_server );
  int charge_poll        = fd_gui_poll( ctx->gui );

  *charge_busy = charge_busy_server | charge_poll;

  return 0;
}

static inline void
during_frag( fd_gui_ctx_t * ctx,
             ulong          in_idx,
             ulong          seq,
             ulong          sig,
             ulong          chunk,
             ulong          sz ) {
  (void)in_idx;
  (void)seq;
  (void)sig;

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in_mem, chunk );

   /* ... todo... sigh, sz is not correct since it's too big */
  if( sig==FD_PLUGIN_MSG_GOSSIP_UPDATE || sig==FD_PLUGIN_MSG_VOTE_ACCOUNT_UPDATE || sig==FD_PLUGIN_MSG_VALIDATOR_INFO ) {
    ulong peer_cnt = ((ulong *)src)[ 0 ];
    FD_TEST( peer_cnt<=40200 );
    sz = 8UL + peer_cnt*(58UL+12UL*34UL);
  } else if( sig==FD_PLUGIN_MSG_LEADER_SCHEDULE ) {
    ulong leader_cnt = ((ulong *)src)[ 1 ];
    FD_TEST( leader_cnt<=40200 );
    sz = 40UL + leader_cnt*40UL;
  }

  if( FD_UNLIKELY( chunk<ctx->in_chunk0 || chunk>ctx->in_wmark || sz>sizeof( ctx->buf ) ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_chunk0, ctx->in_wmark ));

  fd_memcpy( ctx->buf, src, sz );
}

static inline void
after_frag( fd_gui_ctx_t *      ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               chunk,
            ulong               sz,
            ulong               tsorig,
            fd_stem_context_t * stem ) {
  (void)in_idx;
  (void)seq;
  (void)chunk;
  (void)sz;
  (void)tsorig;
  (void)stem;

  fd_gui_plugin_message( ctx->gui, sig, ctx->buf );
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
                     !strcmp( request->path, "/leaderSchedule" ) ||
                     !strcmp( request->path, "/gossip" );

  for( ulong i=0UL; i<sizeof(STATIC_FILES)/sizeof(STATIC_FILES[0]); i++ ) {
    if( !strcmp( request->path, STATIC_FILES[ i ].name ) ||
        (!strcmp( STATIC_FILES[ i ].name, "/index.html" ) && is_vite_page) ) {
      char const * content_type = NULL;

      char const * ext = strrchr( STATIC_FILES[ i ].name, '.' );
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

      const uchar * data = STATIC_FILES[ i ].data;
      ulong data_len = *(STATIC_FILES[ i ].data_len);

      int accepts_zstd = 0;
      if( FD_LIKELY( request->headers.accept_encoding ) ) {
        accepts_zstd = !!strstr( request->headers.accept_encoding, "zstd" );
      }

      char const * content_encoding = NULL;
      if( FD_LIKELY( accepts_zstd && STATIC_FILES[ i ].zstd_data ) ) {
        content_encoding = "zstd";
        data = STATIC_FILES[ i ].zstd_data;
        data_len = *(STATIC_FILES[ i ].zstd_data_len);
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
  fd_gui_ctx_t * ctx = (fd_gui_ctx_t *)_ctx;

  fd_gui_ws_open( ctx->gui, conn_id );
}

static void
gui_ws_message( ulong         ws_conn_id,
                uchar const * data,
                ulong         data_len,
                void *        _ctx ) {
  fd_gui_ctx_t * ctx = (fd_gui_ctx_t *)_ctx;

  int close = fd_gui_ws_message( ctx->gui, ws_conn_id, data, data_len );
  if( FD_UNLIKELY( close<0 ) ) fd_http_server_ws_close( ctx->gui_server, ws_conn_id, close );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gui_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_gui_ctx_t ), sizeof( fd_gui_ctx_t ) );

  fd_http_server_t * _gui = FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(), fd_http_server_footprint( GUI_PARAMS ) );

  fd_http_server_callbacks_t gui_callbacks = {
    .request    = gui_http_request,
    .ws_open    = gui_ws_open,
    .ws_message = gui_ws_message,
  };
  ctx->gui_server = fd_http_server_join( fd_http_server_new( _gui, GUI_PARAMS, gui_callbacks, ctx ) );
  fd_http_server_listen( ctx->gui_server, tile->gui.listen_addr, tile->gui.listen_port );

  if( FD_UNLIKELY( !strcmp( tile->gui.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key = fd_keyload_load( tile->gui.identity_key_path, /* pubkey only: */ 1 );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gui_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_gui_ctx_t ), sizeof( fd_gui_ctx_t ) );
                       FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(), fd_http_server_footprint( GUI_PARAMS ) );
  void * _gui        = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_align(),         fd_gui_footprint() );

  FD_TEST( fd_cstr_printf_check( ctx->version_string, sizeof( ctx->version_string ), NULL, "%lu.%lu.%lu", FDCTL_MAJOR_VERSION, FDCTL_MINOR_VERSION, FDCTL_PATCH_VERSION ) );

  ctx->topo = topo;
  ctx->gui  = fd_gui_join( fd_gui_new( _gui, ctx->gui_server, ctx->version_string, tile->gui.cluster, ctx->identity_key, tile->gui.is_voting, ctx->topo ) );
  FD_TEST( ctx->gui );

  fd_topo_link_t * link = &topo->links[ tile->in_link_id[ 0 ] ];
  fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

  ctx->in_mem    = link_wksp->wksp;
  ctx->in_chunk0 = fd_dcache_compact_chunk0( ctx->in_mem, link->dcache );
  ctx->in_wmark  = fd_dcache_compact_wmark ( ctx->in_mem, link->dcache, link->mtu );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  FD_LOG_WARNING(( "GUI server listening at http://" FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS( tile->gui.listen_addr ), tile->gui.listen_port ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gui_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_gui_ctx_t ), sizeof( fd_gui_ctx_t ) );

  populate_sock_filter_policy_gui( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)fd_http_server_fd( ctx->gui_server ) );
  return sock_filter_policy_gui_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gui_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_gui_ctx_t ), sizeof( fd_gui_ctx_t ) );

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = fd_http_server_fd( ctx->gui_server ); /* gui listen socket */
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_gui_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_gui_ctx_t)

#define STEM_CALLBACK_BEFORE_CREDIT before_credit
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_gui = {
  .name                     = "gui",
  .rlimit_file_cnt          = FD_HTTP_SERVER_GUI_MAX_CONNS+FD_HTTP_SERVER_GUI_MAX_WS_CONNS+5UL, /* pipefd, socket, stderr, logfile, and one spare for new accept() connections */
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
