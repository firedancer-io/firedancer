#ifndef HEADER_fd_src_discof_gossip_fd_gossip_tile_h
#define HEADER_fd_src_discof_gossip_fd_gossip_tile_h

#include "../../disco/topo/fd_topo.h"
#include "../../flamenco/gossip/fd_gossip.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/keyguard/fd_keyswitch.h"

typedef struct {
  int         kind;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
} fd_gossip_in_ctx_t;

struct fd_gossip_tile_ctx {
  fd_gossip_t * gossip;

  fd_contact_info_t my_contact_info[1];

  fd_stem_context_t * stem;

  uint  rng_seed;
  ulong rng_idx;

  double ticks_per_ns;
  long   last_wallclock;
  long   last_tickcount;

  fd_stake_weight_t * stake_weights_converted;

  fd_gossip_in_ctx_t in[ 128UL ];

  fd_gossip_out_ctx_t net_out[ 1 ];
  fd_gossip_out_ctx_t gossip_out[ 1 ];
  fd_gossip_out_ctx_t gossvf_out[ 1 ];
  fd_gossip_out_ctx_t sign_out[ 1 ];

  fd_keyguard_client_t keyguard_client[ 1 ];
  fd_keyswitch_t * keyswitch;

  ushort            net_id;
  fd_ip4_udp_hdrs_t net_out_hdr[ 1 ];
  fd_rng_t          rng[ 1 ];
};

typedef struct fd_gossip_tile_ctx fd_gossip_tile_ctx_t;

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
  int           change_type;
  ulong         idx;
};

typedef struct fd_gossip_ping_update fd_gossip_ping_update_t;

#endif /* HEADER_fd_src_discof_gossip_fd_gossip_tile_h */
