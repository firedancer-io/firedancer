#ifndef HEADER_fd_src_disco_metrics_fd_prometheus_h
#define HEADER_fd_src_disco_metrics_fd_prometheus_h

#include "fd_metrics_base.h"
#include "../../waltz/http/fd_http_server.h"
#include "../topo/fd_topo.h"

FD_PROTOTYPES_BEGIN

/* Format all of the metrics for the given topology as a Prometheus
   text-based exposition format into the HTTP server outgoing ring
   buffer.  See https://prometheus.io/docs/instrumenting/exposition_formats/
   for more information on the format. */

void
fd_prometheus_render_all( fd_topo_t const *  topo,
                          fd_http_server_t * http );

void
fd_prometheus_render_tile( fd_http_server_t *        http,
                           fd_topo_tile_t const *    tile,
                           fd_metrics_meta_t const * metrics,
                           ulong                     metrics_cnt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_metrics_fd_prometheus_h */
