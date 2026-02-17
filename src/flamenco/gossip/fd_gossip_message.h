#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_message_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_message_h

#include "../../util/fd_util_base.h"

#include <stddef.h>

/* The maximum number of contact infos that may be present at any one
   time.  If new contact infos are added, a removal will be issued first
   to make space.  This is a hard limit, and the consumer of the contact
   info messages can assume it is always respected.

   The contact info messages are designed to be consumed in an
   incremental way.  In particular, CONTACT_INFO and CONTACT_INFO_REMOVE
   messages are both sent with an idx field, which is the index of the
   contact info in an imaginary array of contact infos.  Updates will
   always have the same idx for the same pubkey, and removes will
   likewise have the same idx for the pubkey being removed.  A consumer
   of contact info updates can therefore simply maintain a local array
   of contact infos, and update it with the idx field.  */

#define FD_CONTACT_INFO_TABLE_SIZE (32768UL)

/* Tightest bound for a single CrdsValue given network constraints.

     IPv6 minimum MTU             = 1280
     IPv6 header                  =   40
     UDP header                   =    8
     PACKET_DATA_SIZE             = 1232   (= 1280 - 40 - 8)

     Maximum CrdsValue size inside PushMessage/PullResponse:
       PACKET_DATA_SIZE - tag(4) - from(32) - values_len(8)  = 1188  */

#define FD_GOSSIP_VALUE_MAX_SZ (1188UL)

#define FD_GOSSIP_UPDATE_SZ_CONTACT_INFO        (offsetof(fd_gossip_update_message_t, contact_info)        + sizeof((fd_gossip_update_message_t *)0)->contact_info)
#define FD_GOSSIP_UPDATE_SZ_CONTACT_INFO_REMOVE (offsetof(fd_gossip_update_message_t, contact_info_remove) + sizeof((fd_gossip_update_message_t *)0)->contact_info_remove)
#define FD_GOSSIP_UPDATE_SZ_VOTE                (offsetof(fd_gossip_update_message_t, vote)                + sizeof((fd_gossip_update_message_t *)0)->vote)
#define FD_GOSSIP_UPDATE_SZ_DUPLICATE_SHRED     (offsetof(fd_gossip_update_message_t, duplicate_shred)     + sizeof((fd_gossip_update_message_t *)0)->duplicate_shred)
#define FD_GOSSIP_UPDATE_SZ_SNAPSHOT_HASHES     (offsetof(fd_gossip_update_message_t, snapshot_hashes)     + sizeof((fd_gossip_update_message_t *)0)->snapshot_hashes)

/* Gossip messages encode wallclock in millis*, while we
   parse them into nanoseconds for internal use.

   * exceptions:
     - Contact Info outset (AKA instance creation wallclock) is encoded
       in micros */
#define FD_NANOSEC_TO_MILLI(_ts_) ((long)(_ts_/1000000))
#define FD_MILLI_TO_NANOSEC(_ts_) ((long)(_ts_*1000000))
#define FD_NANOSEC_TO_MICRO(_ts_) ((long)(_ts_/1000))
#define FD_MICRO_TO_NANOSEC(_ts_) ((long)(_ts_*1000))

#define FD_GOSSIP_UPDATE_TAG_CONTACT_INFO        (0)
#define FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE (1)
#define FD_GOSSIP_UPDATE_TAG_VOTE                (2)
#define FD_GOSSIP_UPDATE_TAG_DUPLICATE_SHRED     (3)
#define FD_GOSSIP_UPDATE_TAG_SNAPSHOT_HASHES     (4)

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
#define FD_GOSSIP_CONTACT_INFO_SOCKET_ALPENGLOW         (13)
#define FD_GOSSIP_CONTACT_INFO_SOCKET_CNT               (14)

#define FD_GOSSIP_CONTACT_INFO_CLIENT_SOLANA_LABS   (0)
#define FD_GOSSIP_CONTACT_INFO_CLIENT_JITO_LABS     (1)
#define FD_GOSSIP_CONTACT_INFO_CLIENT_FRANKENDANCER (2)
#define FD_GOSSIP_CONTACT_INFO_CLIENT_AGAVE         (3)
#define FD_GOSSIP_CONTACT_INFO_CLIENT_AGAVE_PALADIN (4)
#define FD_GOSSIP_CONTACT_INFO_CLIENT_FIREDANCER    (5)
#define FD_GOSSIP_CONTACT_INFO_CLIENT_AGAVE_BAM     (6)
#define FD_GOSSIP_CONTACT_INFO_CLIENT_SIG           (7)

#define FD_GOSSIP_VALUE_LEGACY_CONTACT_INFO           ( 0)
#define FD_GOSSIP_VALUE_VOTE                          ( 1)
#define FD_GOSSIP_VALUE_LOWEST_SLOT                   ( 2)
#define FD_GOSSIP_VALUE_LEGACY_SNAPSHOT_HASHES        ( 3)
#define FD_GOSSIP_VALUE_ACCOUNT_HASHES                ( 4)
#define FD_GOSSIP_VALUE_EPOCH_SLOTS                   ( 5)
#define FD_GOSSIP_VALUE_LEGACY_VERSION                ( 6)
#define FD_GOSSIP_VALUE_VERSION                       ( 7)
#define FD_GOSSIP_VALUE_NODE_INSTANCE                 ( 8)
#define FD_GOSSIP_VALUE_DUPLICATE_SHRED               ( 9)
#define FD_GOSSIP_VALUE_SNAPSHOT_HASHES               (10)
#define FD_GOSSIP_VALUE_CONTACT_INFO                  (11)
#define FD_GOSSIP_VALUE_RESTART_LAST_VOTED_FORK_SLOTS (12)
#define FD_GOSSIP_VALUE_RESTART_HEAVIEST_FORK         (13)
#define FD_GOSSIP_VALUE_CNT                           (14)

#define FD_GOSSIP_MESSAGE_PULL_REQUEST  (0)
#define FD_GOSSIP_MESSAGE_PULL_RESPONSE (1)
#define FD_GOSSIP_MESSAGE_PUSH          (2)
#define FD_GOSSIP_MESSAGE_PRUNE         (3)
#define FD_GOSSIP_MESSAGE_PING          (4)
#define FD_GOSSIP_MESSAGE_PONG          (5)
#define FD_GOSSIP_MESSAGE_CNT           (6)

struct fd_gossip_vote {
  uchar index;
  ulong transaction_len;
  uchar transaction[ 1232UL ];
};

typedef struct fd_gossip_vote fd_gossip_vote_t;

struct fd_gossip_node_instance {
  ulong timestamp;
  ulong token;
};

typedef struct fd_gossip_node_instance fd_gossip_node_instance_t;

/* Tightest bound for chunk[] given network constraints.

     IPv6 minimum MTU             = 1280
     IPv6 header                  =   40
     UDP header                   =    8
     PACKET_DATA_SIZE             = 1232   (= 1280 - 40 - 8)

     Maximum CrdsValue size inside PushMessage/PullResponse:
       PACKET_DATA_SIZE - tag(4) - from(32) - values_len(8) = 1188

     Minimum bytes consumed before chunk data:
       signature(64) + CrdsData tag(4) + index(2) + origin(32) +
       wallclock(8) + slot(8) + unused(4) + shred_type(1) +
       num_chunks(1) + chunk_index(1) + chunk_len(8)         = 133

     Remaining: 1188 - 133 = 1055  */

struct fd_gossip_duplicate_shred {
  ushort index;
  ulong  slot;
  uchar  num_chunks;
  uchar  chunk_index;
  ulong  chunk_len;
  uchar  chunk[ 1055UL ];
};

typedef struct fd_gossip_duplicate_shred fd_gossip_duplicate_shred_t;

/* Tightest bound for incremental[] given network constraints.

     IPv6 minimum MTU             = 1280
     IPv6 header                  =   40
     UDP header                   =    8
     PACKET_DATA_SIZE             = 1232   (= 1280 - 40 - 8)

     Maximum CrdsValue size inside PushMessage/PullResponse:
       PACKET_DATA_SIZE - tag(4) - from(32) - values_len(8) = 1188

     Bytes consumed before incremental loop:
       signature(64) + CrdsData tag(4) + origin(32) +
       full_slot(8) + full_hash(32) + inc_len(8)             = 148

     Remaining: 1188 - 148 = 1040
     Each entry: slot(8) + hash(32) = 40 bytes
     Max entries = floor(1040/40) = 26  */

struct fd_gossip_snapshot_hashes {
  ulong full_slot;
  uchar full_hash[ 32UL ];

  ulong incremental_len;
  struct {
    ulong slot;
    uchar hash[ 32UL ];
  } incremental[ 26UL ];
};

typedef struct fd_gossip_snapshot_hashes fd_gossip_snapshot_hashes_t;

struct fd_gossip_socket {
  ushort port;
  uint   is_ipv6;
  union {
    uint ip4;
    uchar ip6[ 16UL ];
  };
};

typedef struct fd_gossip_socket fd_gossip_socket_t;

struct fd_gossip_contact_info {
  ulong  outset;
  ushort shred_version;

  struct {
    ushort major;
    ushort minor;
    ushort patch;

    uint   commit;
    uint   feature_set;

    ushort client;
  } version;

  fd_gossip_socket_t sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_CNT ];
};

typedef struct fd_gossip_contact_info fd_gossip_contact_info_t;

struct fd_gossip_epoch_slots {
  uchar index;
};

typedef struct fd_gossip_epoch_slots fd_gossip_epoch_slots_t;

struct fd_gossip_value {
  uint tag;

  uchar signature[ 64UL ];
  uchar origin[ 32UL ];
  ulong wallclock;

  ulong offset;
  ulong length;

  union {
    // DEPRECATED OR UNUSED
    // fd_gossip_legacy_contact_info_t           legacy_contact_info[ 1 ];
    // fd_gossip_lowest_slot_t                   lowest_slot[ 1 ];
    // fd_gossip_legacy_snapshot_hashes_t        legacy_snapshot_hashes[ 1 ];
    // fd_gossip_account_hashes_t                account_hashes[ 1 ];
    // fd_gossip_legacy_version_t                legacy_version[ 1 ];
    // fd_gossip_version_t                       version[ 1 ];
    // fd_gossip_restart_last_voted_fork_slots_t restart_last_voted_fork_slots[ 1 ];
    // fd_gossip_restart_heaviest_fork_t         restart_heaviest_fork[ 1 ];

    fd_gossip_vote_t            vote[ 1 ];
    fd_gossip_node_instance_t   node_instance[ 1 ];
    fd_gossip_duplicate_shred_t duplicate_shred[ 1 ];
    fd_gossip_snapshot_hashes_t snapshot_hashes[ 1 ];
    fd_gossip_contact_info_t    contact_info[ 1 ];
    fd_gossip_epoch_slots_t     epoch_slots[ 1 ];
  };
};

typedef struct fd_gossip_value fd_gossip_value_t;

/* Tightest bounds for Bloom keys[]/bits[] given network constraints.

     IPv6 minimum MTU             = 1280
     IPv6 header                  =   40
     UDP header                   =    8
     PACKET_DATA_SIZE             = 1232   (= 1280 - 40 - 8)

     PullRequest is the only message containing a Bloom filter.

     Bytes consumed before keys loop:
       Protocol tag(4) + keys_len(8)                         =  12

     Remaining: 1232 - 12 = 1220
     Each key: 8 bytes
     Max keys = floor(1220/8) = 152

     Bytes consumed before bits data:
       Protocol tag(4) + keys_len(8) + has_bits(1) +
       bits_cap(8)                                           =  21

     Remaining: 1232 - 21 = 1211
     Each u64: 8 bytes
     Max bits = floor(1211/8) = 151  */

struct fd_gossip_bloom {
  ulong keys_len;
  ulong keys[ 152UL ];
  ulong bits_cap;
  ulong bits_len;
  ulong bits[ 151UL ];
  ulong num_bits_set;
};

typedef struct fd_gossip_bloom fd_gossip_bloom_t;

struct fd_gossip_crds_filter {
  fd_gossip_bloom_t filter[ 1 ];
  ulong mask;
  uint mask_bits;
};

typedef struct fd_gossip_crds_filter fd_gossip_crds_filter_t;

struct fd_gossip_pull_request {
  fd_gossip_crds_filter_t crds_filter[ 1 ];

  fd_gossip_value_t contact_info[ 1 ];
};

typedef struct fd_gossip_pull_request fd_gossip_pull_request_t;

/* Tightest bound for values[] given network constraints.

     IPv6 minimum MTU             = 1280
     IPv6 header                  =   40
     UDP header                   =    8
     PACKET_DATA_SIZE             = 1232   (= 1280 - 40 - 8)

     Minimum bytes consumed before values loop:
       Protocol tag(4) + from(32) + values_len(8)             =  44

     Remaining: 1232 - 44 = 1188
     Each CrdsValue: signature(64) + CrdsData tag(4) = 68 bytes minimum
     Max values = floor(1188/68) = 17  */

struct fd_gossip_pull_response {
  uchar from[ 32UL ];
  ulong values_len;
  fd_gossip_value_t values[ 17UL ];
};

typedef struct fd_gossip_pull_response fd_gossip_pull_response_t;

struct fd_gossip_push {
  uchar from[ 32UL ];
  ulong values_len;
  fd_gossip_value_t values[ 17UL ];
};

typedef struct fd_gossip_push fd_gossip_push_t;

/* Tightest bound for prunes[] given network constraints.

     IPv6 minimum MTU             = 1280
     IPv6 header                  =   40
     UDP header                   =    8
     PACKET_DATA_SIZE             = 1232   (= 1280 - 40 - 8)

     Bytes consumed before prunes loop:
       Protocol tag(4) + sender(32) + pubkey(32) +
       prunes_len(8)                                         =  76

     Remaining: 1232 - 76 = 1156
     Each prune: 32 bytes
     Max prunes = floor(1156/32) = 36  */

struct fd_gossip_prune {
  uchar sender[ 32UL ];
  uchar pubkey[ 32UL ];
  ulong prunes_len;
  uchar prunes[ 36UL ][ 32UL ];
  uchar signature[ 64UL ];
  uchar destination[ 32UL ];
  ulong wallclock;
};

typedef struct fd_gossip_prune fd_gossip_prune_t;

struct fd_gossip_ping {
  uchar from[ 32UL ];
  uchar token[ 32UL ];
  uchar signature[ 64UL ];
};

typedef struct fd_gossip_ping fd_gossip_ping_t;

struct fd_gossip_pong {
  uchar from[ 32UL ];
  uchar hash[ 32UL ];
  uchar signature[ 64UL ];
};

typedef struct fd_gossip_pong fd_gossip_pong_t;

struct fd_gossip_message {
  uint tag;

  union {
    fd_gossip_pull_request_t  pull_request[ 1 ];
    fd_gossip_pull_response_t pull_response[ 1 ];
    fd_gossip_push_t          push[ 1 ];
    fd_gossip_prune_t         prune[ 1 ];
    fd_gossip_ping_t          ping[ 1 ];
    fd_gossip_pong_t          pong[ 1 ];
  };
};

typedef struct fd_gossip_message fd_gossip_message_t;

int
fd_gossip_message_deserialize( fd_gossip_message_t * message,
                               uchar const *         payload,
                               ulong                 payload_sz );

long
fd_gossip_value_serialize( fd_gossip_value_t const * value,
                           uchar *                   out,
                           ulong                     out_sz );

struct fd_gossip_update_message {
  int tag;

  uchar origin[ 32UL ];
  ulong wallclock;

  union {
    struct {
      ulong idx;
      fd_gossip_contact_info_t value[ 1 ];
    } contact_info[ 1 ];

    struct {
      ulong idx;
    } contact_info_remove[ 1 ];

    struct {
      fd_gossip_socket_t socket[ 1 ];
      fd_gossip_vote_t value[ 1 ];
    } vote[ 1 ];

    fd_gossip_duplicate_shred_t duplicate_shred[ 1 ];
    fd_gossip_snapshot_hashes_t snapshot_hashes[ 1 ];
  };
};

typedef struct fd_gossip_update_message fd_gossip_update_message_t;

long
fd_gossip_pull_request_init( uchar *       payload,
                             ulong         payload_sz,
                             ulong         num_keys,
                             ulong         num_bits,
                             ulong         mask,
                             uint          mask_bits,
                             uchar const * contact_info_crds,
                             ulong         contact_info_crds_sz,
                             ulong **      out_bloom_keys,
                             ulong **      out_bloom_bits,
                             ulong **      out_bits_set );

#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_message_h */
