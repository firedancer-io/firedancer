#ifndef HEADER_fd_src_disco_bundle_fd_bundle_tile_h
#define HEADER_fd_src_disco_bundle_fd_bundle_tile_h

/* fd_bundle_tile.h provides a bundle client tile.

   - Uses HTTP/2 over TCP sockets, with TLS (https) or plaintext (http)
   - Uses fd_tls for handshake and record layers
   - Uses Firedancer's fd_h2 and fd_grpc for HTTP/2 and gRPC logic
   - Cooperatively scheduled
   - Disconnects and sleeps while the next leader slot is far away */

#include "../topo/fd_topo.h"
#include "../../waltz/http/fd_url.h"

struct fd_bundle_tile;
typedef struct fd_bundle_tile fd_bundle_tile_t;

#define FD_BUNDLE_STATE_DISCONNECTED (0)
#define FD_BUNDLE_STATE_CONNECTING   (1)
#define FD_BUNDLE_STATE_CONNECTED    (2)
#define FD_BUNDLE_STATE_SLEEPING     (3)

#define FD_BUNDLE_PROTOCOL_JITO     (0)
#define FD_BUNDLE_PROTOCOL_HARMONIC (1)
#define FD_BUNDLE_PROTOCOL_BAM      (2)

/* fd_bundle_builder_protocol returns the FD_BUNDLE_PROTOCOL_* of the
   block builder at url, detected from its host, or -1 if the host is
   not a known block builder. */

static inline int
fd_bundle_builder_protocol( char const * url ) {
  static struct {
    char const * suffix;
    int          protocol;
  } const builders[] = {
    { ".harmonic.gg",  FD_BUNDLE_PROTOCOL_HARMONIC },
    { ".bam.jito.wtf", FD_BUNDLE_PROTOCOL_BAM      },
  };
  fd_url_t parsed[1];
  if( FD_UNLIKELY( !fd_url_parse_cstr( parsed, url, strlen( url ), NULL ) ) ) return -1;
  for( ulong i=0UL; i<sizeof(builders)/sizeof(builders[0]); i++ ) {
    ulong suffix_len = strlen( builders[ i ].suffix );
    if( parsed->host_len>=suffix_len && fd_memeq( parsed->host+parsed->host_len-suffix_len, builders[ i ].suffix, suffix_len ) ) {
      return builders[ i ].protocol;
    }
  }
  return -1;
}

/* fd_bundle_tile_add_server adds a server at url speaking protocol to
   the bundle tile's connections, with TLS server name sni (empty for
   url's host).  Does nothing if url is empty. */

static inline void
fd_bundle_tile_add_server( fd_topo_tile_t * tile,
                           char const *     url,
                           char const *     sni,
                           int              protocol ) {
  if( !url[ 0 ] ) return;
  FD_TEST( tile->bundle.conn_cnt<FD_TOPO_BUNDLE_CONN_MAX );
  ulong idx = tile->bundle.conn_cnt++;
  fd_cstr_ncpy( tile->bundle.conn[ idx ].url, url, sizeof(tile->bundle.conn[ idx ].url) );
  tile->bundle.conn[ idx ].url_len = strnlen( tile->bundle.conn[ idx ].url, sizeof(tile->bundle.conn[ idx ].url)-1UL );
  fd_cstr_ncpy( tile->bundle.conn[ idx ].sni, sni, sizeof(tile->bundle.conn[ idx ].sni) );
  tile->bundle.conn[ idx ].sni_len = strnlen( tile->bundle.conn[ idx ].sni, sizeof(tile->bundle.conn[ idx ].sni)-1UL );
  tile->bundle.conn[ idx ].protocol = protocol;
}

struct fd_bundle_block_engine_update {
  char name[ 16 ];
  char url[ FD_URL_MAX ];
  char ip_cstr[ 40 ]; /* IPv4 or IPv6 cstr */
};
typedef struct fd_bundle_block_engine_update fd_bundle_block_engine_update_t;

FD_PROTOTYPES_BEGIN

extern fd_topo_run_tile_t fd_tile_bundle;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_bundle_fd_bundle_tile_h */
