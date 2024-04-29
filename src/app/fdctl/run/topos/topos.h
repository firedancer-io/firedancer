#ifndef HEADER_fd_src_app_fdctl_run_topos_h
#define HEADER_fd_src_app_fdctl_run_topos_h

#include "../../config.h"

struct fd_topo_config {
  void (*configure)( config_t * config );
};
typedef struct fd_topo_config fd_topo_config_t;

extern fd_topo_config_t fd_topo_frankendancer;
extern fd_topo_config_t fd_topo_firedancer;

FD_FN_CONST fd_topo_config_t *
fd_topo_kind_str_to_topo_config( char const * topo_kind_str );

#endif /* HEADER_fd_src_app_fdctl_run_topos_h */
