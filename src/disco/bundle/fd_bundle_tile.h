#ifndef HEADER_fd_src_disco_bundle_fd_bundle_tile_h
#define HEADER_fd_src_disco_bundle_fd_bundle_tile_h

/* fd_bundle_tile.h provides a bundle client tile.

   - Requires HTTP/2 over TLS connections
   - Uses TCP sockets
   - Uses OpenSSL to drive socket I/O, and provide handshake and record
     layers.
   - Uses Firedancer's fd_h2 and fd_grpc for HTTP/2 and gRPC logic.
   - Does busy polling (no power saving features) */

#include "../topo/fd_topo.h"

struct fd_bundle_tile;
typedef struct fd_bundle_tile fd_bundle_tile_t;

FD_PROTOTYPES_BEGIN

extern fd_topo_run_tile_t fd_tile_bundle;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_bundle_fd_bundle_tile_h */
