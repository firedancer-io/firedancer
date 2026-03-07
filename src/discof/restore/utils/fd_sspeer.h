#ifndef HEADER_fd_src_discof_restore_utils_fd_sspeer_h
#define HEADER_fd_src_discof_restore_utils_fd_sspeer_h

#include "../../../flamenco/types/fd_types_custom.h"
#include "../../../util/net/fd_net_headers.h"

struct fd_sspeer_key {
  union {
    fd_pubkey_t pubkey[ 1 ];        /* gossip peers: key by pubkey. */
    struct {                        /* HTTP server peers: key by hostname + addr. */
      char          hostname[ 256 ];
      fd_ip4_port_t resolved_addr;  /* disambiguates multiple IPs for same hostname. */
    } url;
  };
  int           is_url;
};

typedef struct fd_sspeer_key fd_sspeer_key_t;

#endif /* HEADER_fd_src_discof_restore_utils_fd_sspeer_h */
