#ifndef HEADER_fd_src_disco_metrics_fd_prometheus_h
#define HEADER_fd_src_disco_metrics_fd_prometheus_h

#include "../fd_disco_base.h"

#include "../../ballet/http/fd_http_server.h"
#include "../topo/fd_topo.h"

FD_PROTOTYPES_BEGIN

/* Format all of the metrics for the given topology as a Prometheus
   text-based exposition format into the HTTP server outgoing ring
   buffer.  See https://prometheus.io/docs/instrumenting/exposition_formats/
   for more information on the format. */

void
fd_prometheus_format( fd_topo_t const *  topo,
                      fd_http_server_t * http );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_metrics_fd_prometheus_h */
