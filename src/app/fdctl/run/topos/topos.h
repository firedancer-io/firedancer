#ifndef HEADER_fd_src_app_fdctl_run_topos_h
#define HEADER_fd_src_app_fdctl_run_topos_h

#include "../../config.h"

typedef void (fd_topo_config_fn)( config_t * config );

extern fd_topo_config_fn fd_topo_tvu;
extern fd_topo_config_fn fd_topo_firedancer;
extern fd_topo_config_fn fd_topo_frankendancer;

FD_FN_CONST fd_topo_config_fn *
fd_topo_kind_to_topo_config_fn( ulong topo_kind );

FD_FN_CONST char const *
fd_topo_kind_to_cstr( ulong topo_kind );

FD_FN_CONST ulong
fd_topo_kind_from_cstr( char * topo_kind_str );

#endif /* HEADER_fd_src_app_fdctl_run_topos_h */
