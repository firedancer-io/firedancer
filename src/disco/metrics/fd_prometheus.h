#ifndef HEADER_fd_src_disco_metrics_fd_prometheus_h
#define HEADER_fd_src_disco_metrics_fd_prometheus_h

#include "../fd_disco_base.h"

#include "../topo/fd_topo.h"
#include "../../ballet/http/fd_hcache.h"

FD_PROTOTYPES_BEGIN

void
fd_prometheus_format( fd_topo_t const * topo,
                      fd_hcache_t *     hcache );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_metrics_fd_prometheus_h */
