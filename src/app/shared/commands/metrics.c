#include "../fd_config.h"
#include "../fd_action.h"

#include "../../../disco/metrics/fd_prometheus.h"
#include "../../../waltz/http/fd_http_server_private.h"

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

extern action_t * ACTIONS[];

void
metrics_cmd_fn( args_t *   args   FD_PARAM_UNUSED,
                config_t * config ) {
  fd_http_server_params_t params = {
    .max_connection_cnt    = 0UL,
    .max_ws_connection_cnt = 0UL,
    .max_request_len       = 0UL,
    .max_ws_recv_frame_len = 0UL,
    .max_ws_send_frame_cnt = 0UL,
    .outgoing_buffer_sz    = (1UL<<28UL), /* 256MiB */
  };

  fd_topo_join_workspaces( &config->topo, FD_SHMEM_JOIN_MODE_READ_ONLY );
  fd_topo_fill( &config->topo );

  void * mem = aligned_alloc( fd_http_server_align(), fd_http_server_footprint( params ) );
  FD_TEST( mem );
  fd_http_server_t * http = fd_http_server_new( mem, params, (fd_http_server_callbacks_t){0}, NULL );
  fd_prometheus_render_all( &config->topo, http );

  ulong bytes_written = 0UL;
  while( bytes_written<http->oring_sz ) {
    long written = write( STDOUT_FILENO, http->oring+bytes_written, http->oring_sz-bytes_written );
    if( FD_UNLIKELY( -1==written ) ) FD_LOG_ERR(( "write() failed: %d (%s)", errno, fd_io_strerror( errno ) ));
    bytes_written += http->oring_sz;
  }
}

action_t fd_action_metrics = {
  .name          = "metrics",
  .args          = NULL,
  .fn            = metrics_cmd_fn,
  .perm          = NULL,
  .description   = "Print the current validator Prometheus metrics to STDOUT",
  .is_immediate  = 0,
  .is_diagnostic = 1,
};
