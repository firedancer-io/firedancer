#ifndef HEADER_fd_src_flamenco_gossip_fd_crds_value_h
#define HEADER_fd_src_flamenco_gossip_fd_crds_value_h

#include "../../util/fd_util.h"
#include "../../util/net/fd_net_headers.h"

#define FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP            ( 0)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_SERVE_REPAIR_QUIC ( 1)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_RPC               ( 2)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_RPC_PUBSUB        ( 3)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_SERVE_REPAIR      ( 4)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_TPU               ( 5)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_FORWARDS      ( 6)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_FORWARDS_QUIC ( 7)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_QUIC          ( 8)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_VOTE          ( 9)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_TVU               (10)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_TVU_QUIC          (11)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_VOTE_QUIC     (12)

#define FD_GOSSIP_CLIENT_SOLANA (0)
#define FD_GOSSIP_CLIENT_JITO   (1)
#define FD_GOSSIP_CLIENT_FD     (2)
#define FD_GOSSIP_CLIENT_AGAVE  (3)

struct fd_gossip_contact_info {
  long   instance_creation_wallclock_nanos;
  ushort shred_version;

  struct {
    uchar client;

    ushort major;
    ushort minor;
    ushort patch;

    int   has_commit;
    uint  commit;
    uint  feature_set;
  } version;

  struct {
    /* WARNING: in gossip contact info message,
       ports are encoded in host form. The parser will
       perform the conversion */
    fd_ip4_port_t addr; 
  } sockets[ 13UL ];
};

typedef struct fd_gossip_contact_info fd_gossip_contact_info_t;

struct fd_gossip_vote {
  ulong slot;
  uchar vote_tower_index;
  uchar txn[ 1232UL ];
};

typedef struct fd_gossip_vote fd_gossip_vote_t;

struct fd_gossip_crds_value {
  uchar                 signature[ 64UL ];
  // fd_gossip_crds_data_t data[  ];
};
typedef struct fd_gossip_crds_value fd_gossip_crds_value_t;

#endif /* HEADER_fd_src_flamenco_gossip_fd_crds_value_h */
