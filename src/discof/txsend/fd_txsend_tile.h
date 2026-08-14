#ifndef HEADER_fd_src_discof_txsend_fd_txsend_tile_h
#define HEADER_fd_src_discof_txsend_fd_txsend_tile_h

#include "../../waltz/quic/fd_quic.h"
#include "../../flamenco/progcache/fd_progcache_xid.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"
#include "../../flamenco/gossip/fd_gossip_message.h"
#include "../../disco/stem/fd_stem.h"
#include "../../disco/net/fd_net_tile.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../util/net/fd_net_headers.h"
#include "../fd_startup.h"

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

/* QUIC conn table state management

   fd_quic_conn_t objects are managed by fd_quic_t.
   peer_map holds pointers to quic_conns (up to 2 conns per peer).
   The lifetime of these must be synchronized with quic_conn state.

   This implies the following:
   - fd_quic must inform txsend via a conn_final callback before freeing
     a conn object
   - in rare cases, txsend may see conn alloc failures even if peer_map
     has free conn slots

   The following procedure closes a conn:
   - call fd_quic_conn_close (enqueues an immediate conn close)
   - deregister the conn from the table
   - call fd_quic_service (sends out CONN_CLOSE packet, conn_final
     callback, frees conn) */

struct txsend_conn {
  uint             quic_ip_addr;
  ushort           quic_port;
  fd_quic_conn_t * quic_conn;
  long             quic_last_connected;
};
typedef struct txsend_conn txsend_conn_t;

struct peer_entry {
  /* Key */
  fd_pubkey_t pubkey;

  /* State */
  txsend_conn_t quic_conns[ 2UL ];
  uint   udp_ip_addrs[ 2UL ];
  ushort udp_ports[ 2UL ];
  int    tombstoned;

  struct {
    ulong next;
  } map;
};

typedef struct peer_entry peer_entry_t;

#define MAP_NAME               peer_map
#define MAP_KEY                pubkey
#define MAP_ELE_T              peer_entry_t
#define MAP_KEY_T              fd_pubkey_t
#define MAP_NEXT               map.next
#define MAP_KEY_EQ(k0,k1)      fd_pubkey_eq( k0, k1 )
#define MAP_KEY_HASH(key,seed) fd_progcache_rec_key_hash1( (key)->uc, (seed) )
#define MAP_IMPL_STYLE         1
#include "../../util/tmpl/fd_map_chain.c"

struct quic_entry {
  fd_quic_conn_t * conn;
  fd_pubkey_t      pubkey;
};

typedef struct quic_entry quic_entry_t;

/* txsend tile data structure

   notable data structures:
   - the quic instance manages quic_conns
   - the conns array is a list of pointers to quic_conns, kept in sync
     with quic instance
   - the peers table is replicated from gossip ContactInfo updates
   - the peer_map hashmap maps pubkey to peers[i] entry; drift is
     tolerated
   - peers[i] contains pointers to quic_conn */

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

  fd_keyswitch_t * keyswitch;
  fd_keyswitch_t * av_keyswitch;
  ulong tower_in_expect_seq;
  int   halt_net_frags;

  fd_startup_gate_t startup_gate[1];

  fd_pubkey_t identity_key[1];
  fd_keyguard_client_t keyguard_client[1];

  uchar __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN))) mleaders_mem[ FD_MULTI_EPOCH_LEADERS_FOOTPRINT ];
};

typedef struct fd_txsend_tile fd_txsend_tile_t;

#endif /* HEADER_fd_src_discof_txsend_fd_txsend_tile_h */
