
#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_private_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_private_h

#include "fd_gossip_types.h"
#include "../../util/fd_util.h"
#include "../../disco/fd_disco_base.h"

#include <stddef.h> // offsetof

/* Constants used in deriving size bounds
   - 1232b (MTU)
   - 1188b = 1232b-4b(discriminant)-32b(pubkey)-8(crds len) max CRDS sz
     largest CRDS value seen so far is duplicate shreds at 1187b*/

#define FD_GOSSIP_CRDS_MAX_SZ (1188UL)

/* Deriving maximum number of CRDS values a message can hold:
  - Each CRDS value contains a 64b signature and a 4b discriminant.
    So, each CRDS value is at least 68b.
  - Smallest CRDS data is technically slot hashes with zero hashes,
    which is 32b (pubkey) + 8b (wallclock) + 8b (vector len), bringing
    total to 68b+32b+8b+8b=116b
  - However, we take a more conservative approach and assume just the
    signature and discriminant.
  - So, maximum number of CRDS values is 1188/(68) ~= 18 */
#define FD_GOSSIP_MSG_MAX_CRDS (18UL)

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

/* Gossip messages encode wallclock in millis*, while we
   parse them into nanoseconds for internal use.

   * exceptions:
     - Contact Info outset (AKA instance creation wallclock) is encoded
       in micros */
#define FD_NANOSEC_TO_MILLI(_ts_) ((long)(_ts_/1000000))
#define FD_MILLI_TO_NANOSEC(_ts_) ((long)(_ts_*1000000))
#define FD_NANOSEC_TO_MICRO(_ts_) ((long)(_ts_/1000))
#define FD_MICRO_TO_NANOSEC(_ts_) ((long)(_ts_*1000))

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


#define FD_GOSSIP_UPDATE_SZ_CONTACT_INFO        (offsetof(fd_gossip_update_message_t, contact_info)        + sizeof(ulong) + sizeof(fd_contact_info_t))
#define FD_GOSSIP_UPDATE_SZ_CONTACT_INFO_REMOVE (offsetof(fd_gossip_update_message_t, contact_info_remove) + sizeof(ulong))
#define FD_GOSSIP_UPDATE_SZ_LOWEST_SLOT         (offsetof(fd_gossip_update_message_t, lowest_slot)         + sizeof(ulong))
#define FD_GOSSIP_UPDATE_SZ_VOTE                (offsetof(fd_gossip_update_message_t, vote)                + sizeof(fd_gossip_vote_t))
#define FD_GOSSIP_UPDATE_SZ_DUPLICATE_SHRED     (offsetof(fd_gossip_update_message_t, duplicate_shred)     + sizeof(fd_gossip_duplicate_shred_t))
#define FD_GOSSIP_UPDATE_SZ_SNAPSHOT_HASHES     (offsetof(fd_gossip_update_message_t, snapshot_hashes)     + sizeof(fd_gossip_snapshot_hashes_t))

struct fd_gossip_view_ipaddr {
  uchar   is_ip6;
  union {
    uint   ip4;
    ushort ip6_off;
  };
};

typedef struct fd_gossip_view_ipaddr fd_gossip_view_ipaddr_t;

struct fd_gossip_view_socket {
  uchar   key;
  uchar   index;
  ushort  offset; /* NOTE: this is a varint in encoded form */
};

typedef struct fd_gossip_view_socket fd_gossip_view_socket_t;

/* To get the minimum possible wire size of a Version message, we use
   version 0.0.0 client 0 (anything less than 128 works):

     1b (major)
   + 1b (minor)
   + 1b (patch)
   + 4b (commit)
   + 4b (feature set)
   + 1b (client)
   = 12b */
struct fd_gossip_view_version {
  ushort major;
  ushort minor;
  ushort patch;
  uint   commit;      /* First 4 bytes of the commit hash */
  uint   feature_set; /* Feature set encoded as a bitmask */
  ushort client;
};

typedef struct fd_gossip_view_version fd_gossip_view_version_t;

/* Contact info size bound calculations:

   The minimal valid contact info would hold 0 addrs, 0 sockets,
   and an empty extensions array. This ends up taking

     32b (pubkey)
   + 8b  (wallclock)
   + 8b  (outset)
   + 2b  (shred version)
   + 12b (minimum version)
   + 1b  (addrs_len)
   + 1b  (sockets_len)
   + 1b  (ext_len)
   = 65b

  This leaves us with 1188b - 65b = 1123b to hold addrs, sockets or
  extensions. Extension is just a byte array, so we can ignore sizing it
  and instead offset it in the payload.

  Before analyzing size bounds for addrs and sockets, we establish the
  minimum size socket entry:
     1b (key)
   + 1b (index)
   + 1b (offset, compact-u16)
   = 3b

  According to Agave's ContactInfo verifier (linked below), every IP
  address must be unique, and must be referenced by at least one socket.
  This means that the number of addrs must be at most the number of
  sockets. So to find the maximum n (addr, socket) pairs we can fit in
  1123b:
    1123b / (8b (addr) + 3b (socket)) ~= 102 pairs.

  This bounds the number of addrs to 102. We cannot apply this bound to
  sockets, because the socket entries can reference the same addr
  multiple times, so we can have just 1 addr and use the remaining space
  to hold sockets.

  Agave's verifier enforces a unique socket tag (key) across all
  sockets, and since the key is 1b, this bounds us to 256 sockets.

  https://github.com/anza-xyz/agave/blob/540d5bc56cd44e3cc61b179bd52e9a782a2c99e4/gossip/src/contact_info.rs#L599-L643 */

#define FD_GOSSIP_CONTACT_INFO_MAX_ADDRESSES (102UL)
#define FD_GOSSIP_CONTACT_INFO_MAX_SOCKETS   (256UL)

struct fd_gossip_view_contact_info {
  fd_contact_info_t contact_info[1];
  ulong             ip6_cnt;
  ulong             unrecognized_socket_tag_cnt;

  ushort            ext_len;
  ushort            ext_off;
};

typedef struct fd_gossip_view_contact_info fd_gossip_view_contact_info_t;

struct fd_gossip_view_node_instance {
  ulong token;
};

typedef struct fd_gossip_view_node_instance fd_gossip_view_node_instance_t;

#define FD_GOSSIP_VOTE_IDX_MAX (32U)
struct fd_gossip_view_vote {
  uchar  index;
  ulong  txn_sz;
  ushort txn_off;
};

typedef struct fd_gossip_view_vote fd_gossip_view_vote_t;

#define FD_GOSSIP_EPOCH_SLOTS_IDX_MAX (255U)
struct fd_gossip_view_epoch_slots {
  uchar  index;
};

typedef struct fd_gossip_view_epoch_slots fd_gossip_view_epoch_slots_t;

#define FD_GOSSIP_DUPLICATE_SHRED_IDX_MAX (512U)
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
  union {
    ushort value_off; /* Start of CRDS value data in payload */
    ushort signature_off;
  };
  ushort pubkey_off;
  long   wallclock_nanos;
  ushort length; /* Length of the value in bytes (incl. signature) */

  uchar  tag;
  ushort gossvf_outcome; /* Outcome from gossvf pass (uses FD_METRICS_ENUM_GOSSVF_CRDS_OUTCOME_* indices) */

  union{
    fd_gossip_view_contact_info_t    ci_view[ 1 ];
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

  fd_gossip_view_crds_value_t pr_ci[ 1 ];
};

typedef struct fd_gossip_view_pull_request fd_gossip_view_pull_request_t;

struct fd_gossip_view_prune {
  ushort pubkey_off;
  ulong  origins_len;
  ushort origins_off;
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
    ushort                         ping_pong_off;
  };
};

typedef struct fd_gossip_view fd_gossip_view_t;

static inline fd_ip4_port_t
fd_contact_info_get_socket( fd_contact_info_t const * ci,
                            uchar                     tag ) {
  if( FD_UNLIKELY( tag>=FD_CONTACT_INFO_SOCKET_CNT ) ) {
    FD_LOG_ERR(( "Invalid socket tag %u", tag ));
  }
  return ci->sockets[ tag ];
}

static inline fd_ip4_port_t
fd_contact_info_gossip_socket( fd_contact_info_t const * ci ) {
  return fd_contact_info_get_socket( ci, FD_CONTACT_INFO_SOCKET_GOSSIP );
}

ulong
fd_gossip_msg_parse( fd_gossip_view_t * view,
                     uchar const *      payload,
                     ulong              payload_sz );

FD_FN_CONST static inline ulong
fd_gossip_pull_request_max_filter_bits( ulong num_keys,
                                        ulong contact_info_crds_sz,
                                        ulong payload_sz ) {
  return 8UL*( payload_sz
             - 4UL          /* discriminant */
             - 8UL          /* keys len */
             - 8UL*num_keys /* keys */
             - 1UL          /* has_bits */
             - 8UL          /* bloom vec len */
             - 8UL          /* bloom bits count */
             - 8UL          /* bloom num bits set */
             - 8UL          /* mask */
             - 4UL          /* mask bits */
             - contact_info_crds_sz ); /* contact info CRDS val */
}

int
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
#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_private_h */
