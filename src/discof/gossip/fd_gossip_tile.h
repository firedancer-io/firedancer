#ifndef HEADER_fd_src_discof_gossip_fd_gossip_tile_h
#define HEADER_fd_src_discof_gossip_fd_gossip_tile_h

#include "../../disco/topo/fd_topo.h"

static inline ulong
fd_gossvf_sig( uint   addr,
               ushort port,
               ushort kind ) {
  return (ulong)addr | ((ulong)port<<32) | ((ulong)kind<<48);
}

static inline uint
fd_gossvf_sig_addr( ulong sig ) {
  return (uint)(sig & 0xFFFFFFFFUL);
}

static inline ushort
fd_gossvf_sig_port( ulong sig ) {
  return (ushort)(sig>>32);
}

static inline ushort
fd_gossvf_sig_kind( ulong sig ) {
  return (ushort)(sig>>48);
}

struct fd_gossip_pingreq {
  fd_pubkey_t pubkey;
};

typedef struct fd_gossip_pingreq fd_gossip_pingreq_t;

struct fd_gossip_ping_update {
  fd_pubkey_t   pubkey;
  fd_ip4_port_t gossip_addr;
  int           remove;
};

typedef struct fd_gossip_ping_update fd_gossip_ping_update_t;

extern fd_topo_run_tile_t fd_tile_gossip;

#endif /* HEADER_fd_src_discof_gossip_fd_gossip_tile_h */
