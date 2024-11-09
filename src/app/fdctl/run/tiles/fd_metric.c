#include "../../../../disco/tiles.h"

#include <sys/socket.h> /* SOCK_CLOEXEC, SOCK_NONBLOCK needed for seccomp filter */
#if defined(__aarch64__)
#include "generated/metric.arm64_seccomp.h"
#else
#include "generated/metric_seccomp.h"
#endif

#include "../../version.h"

#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../disco/metrics/fd_prometheus.h"
#include "../../../../ballet/http/fd_http_server.h"
#include "../../../../util/net/fd_ip4.h"

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define FD_HTTP_SERVER_METRICS_MAX_CONNS          128
#define FD_HTTP_SERVER_METRICS_MAX_REQUEST_LEN    1024
#define FD_HTTP_SERVER_METRICS_OUTGOING_BUFFER_SZ (32UL<<20UL) /* 32MiB reserved for buffering metrics responses */

const fd_http_server_params_t METRICS_PARAMS = {
  .max_connection_cnt    = FD_HTTP_SERVER_METRICS_MAX_CONNS,
  .max_ws_connection_cnt = 0UL,
  .max_request_len       = FD_HTTP_SERVER_METRICS_MAX_REQUEST_LEN,
  .max_ws_recv_frame_len = 0UL,
  .max_ws_send_frame_cnt = 0UL,
  .outgoing_buffer_sz    = FD_HTTP_SERVER_METRICS_OUTGOING_BUFFER_SZ,
};

typedef struct {
  fd_topo_t * topo;

  fd_http_server_t * metrics_server;
} fd_metric_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_metric_ctx_t ), sizeof( fd_metric_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, fd_http_server_align(), fd_http_server_footprint( METRICS_PARAMS ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
before_credit( fd_metric_ctx_t *   ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  *charge_busy = fd_http_server_poll( ctx->metrics_server );
}

static fd_http_server_response_t
metrics_http_request( fd_http_server_request_t const * request ) {
  fd_metric_ctx_t * ctx = (fd_metric_ctx_t *)request->ctx;

  if( FD_UNLIKELY( request->method!=FD_HTTP_SERVER_METHOD_GET ) ) {
    return (fd_http_server_response_t){
      .status = 400,
    };
  }

  if( FD_LIKELY( !strcmp( request->path, "/metrics" ) ) ) {
    fd_prometheus_format( ctx->topo, ctx->metrics_server );

    fd_http_server_response_t response = {
      .status       = 200,
      .content_type = "text/plain; version=0.0.4",
    };
    if( FD_UNLIKELY( fd_http_server_stage_body( ctx->metrics_server, &response ) ) ) {
      FD_LOG_WARNING(( "fd_http_server_stage_body failed, metrics response too long" ));
      return (fd_http_server_response_t){
        .status = 500,
      };
    }
    return response;
  } else {
    return (fd_http_server_response_t){
      .status = 404,
    };
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_metric_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_metric_ctx_t ), sizeof( fd_metric_ctx_t ) );

  fd_http_server_t * _metrics = FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(), fd_http_server_footprint( METRICS_PARAMS ) );

  fd_http_server_callbacks_t metrics_callbacks = {
    .request = metrics_http_request,
  };
  ctx->metrics_server = fd_http_server_join( fd_http_server_new( _metrics, METRICS_PARAMS, metrics_callbacks, ctx ) );
  fd_http_server_listen( ctx->metrics_server, tile->metric.prometheus_listen_addr, tile->metric.prometheus_listen_port );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_metric_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_metric_ctx_t ), sizeof( fd_metric_ctx_t ) );

  ctx->topo = topo;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  FD_LOG_WARNING(( "Prometheus metrics endpoint listening at http://" FD_IP4_ADDR_FMT ":%u/metrics", FD_IP4_ADDR_FMT_ARGS( tile->metric.prometheus_listen_addr ), tile->metric.prometheus_listen_port ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_metric_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_metric_ctx_t ), sizeof( fd_metric_ctx_t ) );

  populate_sock_filter_policy_metric( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)fd_http_server_fd( ctx->metrics_server ) );
  return sock_filter_policy_metric_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_metric_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_metric_ctx_t ), sizeof( fd_metric_ctx_t ) );

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = fd_http_server_fd( ctx->metrics_server ); /* metrics listen socket */
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_metric_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_metric_ctx_t)

#define STEM_CALLBACK_BEFORE_CREDIT before_credit

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_metric = {
  .name                     = "metric",
  .rlimit_file_cnt          = FD_HTTP_SERVER_METRICS_MAX_CONNS+5UL, /* pipefd, socket, stderr, logfile, and one spare for new accept() connections */
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
