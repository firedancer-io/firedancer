#include "tiles.h"

#include <stdarg.h>
#include <stdio.h>

FD_FN_CONST fd_tile_config_t *
fd_topo_tile_to_config( fd_topo_tile_t const * tile ) {
  if( FD_UNLIKELY( !strcmp( tile->name, "net"          ) ) ) return &fd_tile_net;
  else if ( FD_UNLIKELY( !strcmp( tile->name, "netmux" ) ) ) return &fd_tile_netmux;
  else if ( FD_UNLIKELY( !strcmp( tile->name, "quic"   ) ) ) return &fd_tile_quic;
  else if ( FD_UNLIKELY( !strcmp( tile->name, "verify" ) ) ) return &fd_tile_verify;
  else if ( FD_UNLIKELY( !strcmp( tile->name, "dedup"  ) ) ) return &fd_tile_dedup;
  else if ( FD_UNLIKELY( !strcmp( tile->name, "pack"   ) ) ) return &fd_tile_pack;
  else if ( FD_UNLIKELY( !strcmp( tile->name, "bank"   ) ) ) return &fd_tile_bank;
  else if ( FD_UNLIKELY( !strcmp( tile->name, "poh"    ) ) ) return &fd_tile_poh;
  else if ( FD_UNLIKELY( !strcmp( tile->name, "shred"  ) ) ) return &fd_tile_shred;
  else if ( FD_UNLIKELY( !strcmp( tile->name, "store"  ) ) ) return &fd_tile_store;
  else if ( FD_UNLIKELY( !strcmp( tile->name, "sign"   ) ) ) return &fd_tile_sign;
  else if ( FD_UNLIKELY( !strcmp( tile->name, "metric" ) ) ) return &fd_tile_metric;
  else FD_LOG_ERR(( "unknown tile name %s", tile->name ));
}

void *
fd_wksp_pod_map1( uchar const * pod,
                  char const *  format,
                  ... ) {
  char s[ 256 ];

  va_list args;
  va_start( args, format );
  int len = vsnprintf( s, sizeof(s), format, args );
  va_end( args );
  if( FD_UNLIKELY( len < 0 ) )
    FD_LOG_ERR(( "vsnprintf failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( (ulong)len >= sizeof(s) ) )
    FD_LOG_ERR(( "vsnprintf truncated output (maxlen=%lu)", sizeof(s) ));

  return fd_wksp_pod_map( pod, s );
}
