#ifndef HEADER_fd_src_discof_txsend_fd_txsend_tile_h
#define HEADER_fd_src_discof_txsend_fd_txsend_tile_h

#include "../../waltz/quic/fd_quic.h"
#include "../../flamenco/types/fd_types_custom.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"
#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../util/net/fd_net_headers.h"

struct fd_txsend_in {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
};

typedef struct fd_txsend_in fd_txsend_in_t;

struct fd_txsend_out {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
};

typedef struct fd_txsend_out fd_txsend_out_t;

struct peer_entry {
  int tombstoned;
  fd_pubkey_t pubkey;

  uint             quic_ip_addrs[ 2UL ];
  ushort           quic_ports[ 2UL ];

  fd_quic_conn_t * quic_conns[ 2UL ];
  long             quic_last_connected[ 2UL ];

  uint   udp_ip_addrs[ 2UL ];
  ushort udp_ports[ 2UL ];

  struct {
    ulong prev;
    ulong next;
  } map;
};

typedef struct peer_entry peer_entry_t;

#define MAP_NAME               peer_map
#define MAP_KEY                pubkey
#define MAP_ELE_T              peer_entry_t
#define MAP_KEY_T              fd_pubkey_t
#define MAP_PREV               map.prev
#define MAP_NEXT               map.next
#define MAP_KEY_EQ(k0,k1)      fd_pubkey_eq( k0, k1 )
#define MAP_KEY_HASH(key,seed) (seed^fd_ulong_load_8( (key)->uc ))
#define MAP_IMPL_STYLE         1
#include "../../util/tmpl/fd_map_chain.c"

struct quic_entry {
  fd_quic_conn_t * conn;
  fd_pubkey_t      pubkey;
};

typedef struct quic_entry quic_entry_t;

struct fd_txsend_tile {
  fd_quic_t * quic;

  ulong leader_schedules;
  fd_multi_epoch_leaders_t * mleaders;

  ulong seed;
  peer_map_t * peer_map;

  peer_entry_t peers[ FD_CONTACT_INFO_TABLE_SIZE ];

  ulong conns_len;
  quic_entry_t conns[ 128UL ];

  ulong voted_slot;

  fd_stem_context_t * stem;

  ulong chunk;
  uchar quic_buf[ FD_NET_MTU ];

  uint               src_ip_addr;
  ushort             src_port;
  fd_ip4_udp_hdrs_t  packet_hdr[1]; /* template, but will be modified directly */
  ushort             net_id;

  fd_aio_t    quic_tx_aio[1];

  int in_kind[ 32UL ];
  fd_txsend_in_t in[ 32UL ];
  fd_net_rx_bounds_t net_in_bounds[ 64UL ];

  fd_txsend_out_t txsend_out[1];
  fd_txsend_out_t net_out[1];

  fd_pubkey_t identity_key[1];
  fd_keyguard_client_t keyguard_client[1];

  uchar __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN))) mleaders_mem[ FD_MULTI_EPOCH_LEADERS_FOOTPRINT ];
};

typedef struct fd_txsend_tile fd_txsend_tile_t;

#endif /* HEADER_fd_src_discof_txsend_fd_txsend_tile_h */
