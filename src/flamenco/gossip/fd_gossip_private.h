
#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_msg_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_msg_h

// #include "fd_gossip_types.h"
// #include "fd_crds_value.h"
#include "../../util/fd_util.h"
#include "fd_gossip_types.h"

/* Deriving maximum number of CRDS values a message can hold:
  - Maximum bytes the CRDS array can hold is
    1232(MTU)-4(msg disc)-32(pubkey)-8(crds len)=1188b
  - Smallest CRDS value is 64+4+48=116b
    (64b signature + 4b discriminant + 48b slot hashes)
  - So, maximum number of CRDS values is 1188/(64+4+48) ~= 10
  - TODO: We might want to use a more conservative estimate that only includes
    the size of the signature and discriminant. */
#define FD_GOSSIP_MSG_MAX_CRDS (10UL)

#define FD_GOSSIP_MESSAGE_PULL_REQUEST  (0)
#define FD_GOSSIP_MESSAGE_PULL_RESPONSE (1)
#define FD_GOSSIP_MESSAGE_PUSH          (2)
#define FD_GOSSIP_MESSAGE_PRUNE         (3)
#define FD_GOSSIP_MESSAGE_PING          (4)
#define FD_GOSSIP_MESSAGE_PONG          (5)
#define FD_GOSSIP_MESSAGE_LAST          (FD_GOSSIP_MESSAGE_PONG)

#define FD_GOSSIP_VALUE_LEGACY_CONTACT_INFO           ( 0)
#define FD_GOSSIP_VALUE_VOTE                          ( 1)
#define FD_GOSSIP_VALUE_LOWEST_SLOT                   ( 2) // SOME FIELDS DEPRECATED
#define FD_GOSSIP_VALUE_LEGACY_SNAPSHOT_HASHES        ( 3) // DEPRECATED
#define FD_GOSSIP_VALUE_ACCOUNT_HASHES                ( 4) // DEPRECATED
#define FD_GOSSIP_VALUE_EPOCH_SLOTS                   ( 5)
#define FD_GOSSIP_VALUE_LEGACY_VERSION                ( 6)
#define FD_GOSSIP_VALUE_VERSION                       ( 7)
#define FD_GOSSIP_VALUE_NODE_INSTANCE                 ( 8)
#define FD_GOSSIP_VALUE_DUPLICATE_SHRED               ( 9)
#define FD_GOSSIP_VALUE_INC_SNAPSHOT_HASHES           (10)
#define FD_GOSSIP_VALUE_CONTACT_INFO                  (11)
#define FD_GOSSIP_VALUE_RESTART_LAST_VOTED_FORK_SLOTS (12)
#define FD_GOSSIP_VALUE_RESTART_HEAVIEST_FORK         (13)
#define FD_GOSSIP_VALUE_LAST                          (FD_GOSSIP_VALUE_RESTART_HEAVIEST_FORK)

/* Gossip messages encode wallclock in millis, while we
   parse them into nanoseconds for internal use. */
#define FD_NANOSEC_TO_MILLI(_ts_) ((long)(_ts_/1000000))
#define FD_MILLI_TO_NANOSEC(_ts_) ((long)(_ts_*1000000))

/* Bound max inc entries by
    1188b (max CRDS encoded buffer size )
  - 64b (signature)
  - 4b  (tag)
  - 32b (pubkey)
  - 40b (full pair)
  - 8b  (inc len)
  - 8b  (wallclock)
  = 1032b

  1032b/40 ~= 25 */
FD_STATIC_ASSERT( FD_GOSSIP_SNAPSHOT_HASHES_MAX_INCREMENTAL==25UL,
                 "FD_GOSSIP_SNAPSHOT_HASHES_MAX_INCREMENTAL must be 25" );


#define FD_GOSSIP_UPDATE_SZ_CONTACT_INFO        (offsetof(fd_gossip_update_message_t, contact_info)    + sizeof(fd_contact_info_t) + sizeof(ulong))
#define FD_GOSSIP_UPDATE_SZ_CONTACT_INFO_REMOVE (offsetof(fd_gossip_update_message_t, contact_info)    + sizeof(ulong))
#define FD_GOSSIP_UPDATE_SZ_LOWEST_SLOT         (offsetof(fd_gossip_update_message_t, lowest_slot)     + sizeof(ulong))
#define FD_GOSSIP_UPDATE_SZ_VOTE                (offsetof(fd_gossip_update_message_t, vote)            + sizeof(fd_gossip_vote_t))
#define FD_GOSSIP_UPDATE_SZ_DUPLICATE_SHRED     (offsetof(fd_gossip_update_message_t, duplicate_shred) + sizeof(fd_gossip_duplicate_shred_t))
#define FD_GOSSIP_UPDATE_SZ_SNAPSHOT_HASHES     (offsetof(fd_gossip_update_message_t, snapshot_hashes) + sizeof(fd_gossip_snapshot_hashes_t))

struct fd_gossip_view_ipaddr {
  uchar   is_ip6;
  union {
    uint   ip4_addr;
    ushort ip6_addr_off;
  };
};

typedef struct fd_gossip_view_ipaddr fd_gossip_view_ipaddr_t;

struct fd_gossip_view_socket {
  uchar   key;
  uchar   index;
  ushort  offset; /* NOTE: this is a varint in encoded form */
};

typedef struct fd_gossip_view_socket fd_gossip_view_socket_t;

struct fd_gossip_view_version {
  ushort major;
  ushort minor;
  ushort patch;
  uint   commit;      /* First 4 bytes of the commit hash */
  uint   feature_set; /* Feature set encoded as a bitmask */
  ushort client;
};

typedef struct fd_gossip_view_version fd_gossip_view_version_t;

struct fd_gossip_view_contact_info {
  long                     instance_creation_wallclock_nanos;
  ushort                   shred_version;
  fd_gossip_view_version_t version[ 1 ];

  ushort                   addrs_len;
  fd_gossip_view_ipaddr_t  addrs[ 16UL ];    /* TODO: calculate length bounds */

  ushort                   sockets_len;
  fd_gossip_view_socket_t  sockets[ 16UL ];  /* TODO: calculate length bounds */

  ushort                   ext_len;
  ushort                   ext_off;
};

typedef struct fd_gossip_view_contact_info fd_gossip_view_contact_info_t;

struct fd_gossip_view_node_instance {
  ushort token_off;
};

typedef struct fd_gossip_view_node_instance fd_gossip_view_node_instance_t;

struct fd_gossip_view_vote {
  uchar  index;
  ulong  txn_sz;
  ushort txn_off;
};

typedef struct fd_gossip_view_vote fd_gossip_view_vote_t;

struct fd_gossip_view_epoch_slots {
  uchar  index;
};

typedef struct fd_gossip_view_epoch_slots fd_gossip_view_epoch_slots_t;

struct fd_gossip_view_duplicate_shred {
  ushort index;
  ulong  slot;
  uchar  num_chunks;
  uchar  chunk_index;
  ulong  chunk_len;
  ushort chunk_off;
};

typedef struct fd_gossip_view_duplicate_shred fd_gossip_view_duplicate_shred_t;

typedef struct fd_gossip_view_snapshot_hash_pair fd_gossip_view_snapshot_hash_pair_t;
struct fd_gossip_view_snapshot_hashes {
  ushort full_off; /* Offset to the full snapshot hashes (slot, hash) pair */
  ulong  inc_len;
  ushort inc_off;  /* Offset to start of incremental snapshot hashes pair */
};

typedef struct fd_gossip_view_snapshot_hashes fd_gossip_view_snapshot_hashes_t;

 /* Offsets are within full message payload, not the subset where the encoded
    CRDS value lies. */
struct fd_gossip_view_crds_value {
  union{
    ushort value_off; /* Start of CRDS value data in payload */
    ushort signature_off;
  };
  ushort pubkey_off;
  long   wallclock_nanos;
  ushort length; /* Length of the value in bytes (incl. signature) */

  uchar tag;
  union{
    fd_gossip_view_contact_info_t    contact_info[ 1 ];
    fd_gossip_view_node_instance_t   node_instance[ 1 ];
    fd_gossip_view_vote_t            vote[ 1 ];
    fd_gossip_view_epoch_slots_t     epoch_slots[ 1 ];
    fd_gossip_view_duplicate_shred_t duplicate_shred[ 1 ];
    ulong                            lowest_slot;
    fd_gossip_view_snapshot_hashes_t snapshot_hashes[ 1 ];
  };
};

typedef struct fd_gossip_view_crds_value fd_gossip_view_crds_value_t;

struct fd_gossip_view_crds_container {
  ushort from_off;
  ushort crds_values_len;

  fd_gossip_view_crds_value_t crds_values[ FD_GOSSIP_MSG_MAX_CRDS ];
};

typedef struct fd_gossip_view_crds_container fd_gossip_view_crds_container_t;
typedef struct fd_gossip_view_crds_container fd_gossip_view_pull_response_t;
typedef struct fd_gossip_view_crds_container fd_gossip_view_push_t;
struct fd_gossip_view_pull_request {
  ulong bloom_keys_len;
  ulong bloom_keys_offset;

  ulong bloom_len;
  ulong bloom_bits_offset;
  ulong bloom_bits_cnt;

  ulong bloom_num_bits_set;
  ulong mask;
  uint  mask_bits;

  fd_gossip_view_crds_value_t contact_info[ 1 ];
};

typedef struct fd_gossip_view_pull_request fd_gossip_view_pull_request_t;

struct fd_gossip_view_prune {
  ushort origin_off;
  ulong  prunes_len;
  ushort prunes_off;
  ushort destination_off;
  ulong  wallclock;
  ushort signature_off;

  long   wallclock_nanos;
};

typedef struct fd_gossip_view_prune fd_gossip_view_prune_t;

/* Ping/Pong can be casted on to the payload bytes
   directly */
struct __attribute__((__packed__)) fd_gossip_view_ping {
  uchar pubkey[ 32UL ];
  uchar ping_token[ 32UL ];
  uchar signature[ 64UL ];
};

typedef struct fd_gossip_view_ping fd_gossip_view_ping_t;

struct __attribute__((__packed__)) fd_gossip_view_pong {
  uchar pubkey[ 32UL ];
  uchar ping_hash[ 32UL ];
  uchar signature[ 64UL ];
};

typedef struct fd_gossip_view_pong fd_gossip_view_pong_t;

struct fd_gossip_view {
  uchar tag; // uint in rust bincode
  union {
    fd_gossip_view_pull_request_t  pull_request[ 1 ];
    fd_gossip_view_pull_response_t pull_response[ 1 ];
    fd_gossip_view_push_t          push[ 1 ];
    fd_gossip_view_prune_t         prune[ 1 ];
    fd_gossip_view_ping_t *        ping;
    fd_gossip_view_pong_t *        pong;
  };
};

typedef struct fd_gossip_view fd_gossip_view_t;

static inline fd_ip4_port_t
fd_contact_info_get_socket( fd_contact_info_t const * ci,
                            uchar                     tag ) {
  if( FD_UNLIKELY( tag>FD_CONTACT_INFO_SOCKET_LAST ) ) {
    FD_LOG_ERR(( "Invalid socket tag %u", tag ));
  }
  return ci->sockets[ tag ];
}

static inline fd_ip4_port_t
fd_contact_info_gossip_socket( fd_contact_info_t const * ci ) {
  return fd_contact_info_get_socket( ci, FD_CONTACT_INFO_SOCKET_GOSSIP );
}

ulong
fd_gossip_msg_parse( fd_gossip_view_t *   view,
                     uchar const *        payload,
                     ulong                payload_sz );

int
fd_gossip_pull_request_init( uchar *       payload,
                             ulong         payload_sz,
                             ulong         num_keys,
                             ulong         bloom_bits_cnt,
                             ulong         mask,
                             uint          mask_bits,
                             uchar const * contact_info_crds,
                             ulong         contact_info_crds_sz,
                             ulong **      out_bloom_keys,
                             ulong **      out_bloom_bits,
                             ulong **      out_bits_set,
                             ulong *       out_payload_sz );

int
fd_gossip_contact_info_encode( fd_contact_info_t const * contact_info,
                               uchar *                   out_buf,
                               ulong                     out_buf_cap,
                               ulong *                   opt_encoded_sz );

int
fd_gossip_crds_vote_encode( uchar *       out_buf,
                            ulong         out_buf_sz,
                            uchar const * txn,
                            ulong         txn_sz,
                            uchar const * identity_pubkey,
                            long          now,
                            ulong *       opt_encoded_sz );
#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_msg_h */
