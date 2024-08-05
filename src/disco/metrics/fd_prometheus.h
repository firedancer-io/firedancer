#ifndef HEADER_fd_src_disco_metrics_fd_prometheus_h
#define HEADER_fd_src_disco_metrics_fd_prometheus_h

#include "../fd_disco_base.h"

#include "../topo/fd_topo.h"

FD_PROTOTYPES_BEGIN

int
fd_prometheus_format( fd_topo_t const * topo,
                      char *            out,
                      ulong *           out_len );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_metrics_fd_prometheus_h */
