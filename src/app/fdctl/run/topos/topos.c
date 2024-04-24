#include "topos.h"

#define FD_TOPO_KIND_CSTR_LEN_MAX (32UL)

FD_FN_CONST fd_topo_config_fn *
fd_topo_kind_str_to_topo_config_fn( char const * topo_kind_str ) {
  if( strncmp( topo_kind_str, "frankendancer", FD_TOPO_KIND_CSTR_LEN_MAX )==0 ) { return &fd_topo_frankendancer; }
  else {
    FD_LOG_ERR(( "unknown topo kind %s", topo_kind_str ));
  }
}
