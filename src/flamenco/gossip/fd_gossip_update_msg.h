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

#define FD_GOSSIP_UPDATE_TAG_CONTACT_INFO  (0)
#define FD_GOSSIP_UPDATE_TAG_VOTE          (1)
#define FD_GOSSIP_UPDATE_TAG_LOWEST_SLOT   (2)

/* Gossip messages encode wallclock in millis, while we
   parse them into nanoseconds for internal use. */
#define FD_NANOSEC_TO_MILLI(_ts_) ((long)(_ts_/1000000))
#define FD_MILLI_TO_NANOSEC(_ts_) ((long)(_ts_*1000000))




struct fd_gossip_crds_contact_info {
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

typedef struct fd_gossip_crds_contact_info fd_gossip_crds_contact_info_t;

struct fd_gossip_crds_vote {
  ulong slot;
  uchar vote_tower_index; /* TODO: Is this needed? */
  uchar txn[ 1232UL ];
};

typedef struct fd_gossip_crds_vote fd_gossip_crds_vote_t;

struct fd_gossip_lowest_slot {
  ulong lowest_slot;
};

typedef struct fd_gossip_lowest_slot fd_gossip_lowest_slot_t;

struct fd_gossip_update_message {

  uchar tag;
  uchar origin_pubkey[ 32UL ];

  long  wallclock_nanos;

  union {
    fd_gossip_crds_contact_info_t  contact_info;
    fd_gossip_crds_vote_t          vote;
    fd_gossip_lowest_slot_t        lowest_slot;
  };
};
typedef struct fd_gossip_update_message fd_gossip_update_message_t;
#endif /* HEADER_fd_src_flamenco_gossip_fd_crds_value_h */
