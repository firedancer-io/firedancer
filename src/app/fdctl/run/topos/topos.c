#include "topos.h"
#include "../../topology.h"

#define FD_TOPO_KIND_CSTR_LEN_MAX (32UL)

FD_FN_CONST fd_topo_config_fn *
fd_topo_kind_to_topo_config_fn( ulong topo_kind ) {
  switch( topo_kind ) {
    case FD_TOPO_KIND_TVU:        return &fd_topo_tvu;
    case FD_TOPO_KIND_FIREDANCER: return &fd_topo_firedancer;
    default: FD_LOG_ERR(( "unknown topo kind %lu", topo_kind ));
  }
}

FD_FN_CONST char const *
fd_topo_kind_to_cstr( ulong topo_kind ) {
  switch( topo_kind ) {
    case FD_TOPO_KIND_TVU:            return "tvu";
    case FD_TOPO_KIND_FIREDANCER:     return "firedancer";
    case FD_TOPO_KIND_FRANKENDANCER:  return "frankendancer";
    default: FD_LOG_ERR(( "unknown topo kind %lu", topo_kind ));
  }
}

FD_FN_CONST ulong
fd_topo_kind_from_cstr( char * topo_kind_str ) {
  if( strlen( topo_kind_str ) >= FD_TOPO_KIND_CSTR_LEN_MAX ) {
    FD_LOG_ERR(( "topo kind string too long" ));  
  }

  for( ulong i = 0; i < FD_TOPO_KIND_MAX; i++ ) {
    char const * cmp_topo_kind = fd_topo_kind_to_cstr( i );
    if( strncmp( topo_kind_str, cmp_topo_kind, FD_TOPO_KIND_CSTR_LEN_MAX )==0 ) {
      return i;
    }
  }

  FD_LOG_ERR(( "unknown topo kind string %s", topo_kind_str ));  
}

