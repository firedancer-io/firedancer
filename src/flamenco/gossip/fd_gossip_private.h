
#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_msg_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_msg_h

// #include "fd_gossip_types.h"
// #include "fd_crds_value.h"
#include "../../util/fd_util.h"
#include "fd_contact_info.h"

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

/* Gossip message tag can never exceed this. */
#define FD_GOSSIP_MESSAGE_LAST          (FD_GOSSIP_MESSAGE_PONG)

#define FD_GOSSIP_VALUE_VOTE                          ( 1)
#define FD_GOSSIP_VALUE_LOWEST_SLOT                   ( 2)
#define FD_GOSSIP_VALUE_EPOCH_SLOTS                   ( 5)
#define FD_GOSSIP_VALUE_DUPLICATE_SHRED               ( 9)
#define FD_GOSSIP_VALUE_SNAPSHOT_HASHES               (10)
#define FD_GOSSIP_VALUE_CONTACT_INFO                  (11)
#define FD_GOSSIP_VALUE_RESTART_LAST_VOTED_FORK_SLOTS (12)
#define FD_GOSSIP_VALUE_RESTART_HEAVIEST_FORK         (13)


/* Gossip messages encode wallclock in millis, while we
   parse them into nanoseconds for internal use. */
#define FD_NANOSEC_TO_MILLI(_ts_) ((long)(_ts_/1000000))
#define FD_MILLI_TO_NANOSEC(_ts_) ((long)(_ts_*1000000))

typedef ushort offset_t;

/* For some primitive fields, we store both the actual value and
   its payload offset. */
typedef struct { uchar  val; offset_t off; } uchar_view_t;
typedef struct { ushort val; offset_t off; } ushort_view_t;
typedef struct { uint   val; offset_t off; } uint_view_t;
typedef struct { ulong  val; offset_t off; } ulong_view_t;

/* All timestamp fields (wallclock, instance creation, etc.,)
   will be converted to nanos. We also save the offset. */
typedef struct { long ts_nanos; offset_t off; } timestamp_view_t;

/* Varint field. TODO: store some metadata like encoded sz? */
typedef struct { ulong val;     offset_t off; } varint_view_t;

struct fd_gossip_view_ipaddr {
  uchar   is_ip6;
  union {
    uint_view_t ip4_addr;
    offset_t    ip6_addr_off; /* Offset to 16-byte value */
  };
};

typedef struct fd_gossip_view_ipaddr fd_gossip_view_ipaddr_t;

struct fd_gossip_view_socket {
  uchar_view_t  key; /* Socket tag */

  uchar_view_t  index;

  /* NOTE: offset is a varint in encoded form */
  ushort_view_t offset;
};

typedef struct fd_gossip_view_socket fd_gossip_view_socket_t;

struct fd_gossip_view_contact_info {
  timestamp_view_t        instance_creation_wallclock;
  ushort_view_t           shred_version;

  /* NOTE: Contact Info wallclock is encoded as a compact-u64 */
  timestamp_view_t        wallclock;

  /* Note: All contact info arrays below are short_vec, which means length is in varint */
  varint_view_t           addrs_len;
  fd_gossip_view_ipaddr_t addr_views[ 16UL ];    /* TODO: calculate length bounds */

  varint_view_t           sockets_len;
  fd_gossip_view_socket_t socket_views[ 16UL ];  /* TODO: calculate length bounds */

  varint_view_t           ext_len;
  offset_t                ext_off;
};

typedef struct fd_gossip_view_contact_info fd_gossip_view_contact_info_t;

struct fd_gossip_view_node_instance {
  ushort token_off;
};

typedef struct fd_gossip_view_node_instance fd_gossip_view_node_instance_t;

struct fd_gossip_view_vote {
  uchar_view_t  index;
  ulong_view_t  transaction_sz;
  ushort        transaction_off;
};

typedef struct fd_gossip_view_vote fd_gossip_view_vote_t;

struct fd_gossip_view_epoch_slots {
  uchar_view_t  index;
};

typedef struct fd_gossip_view_epoch_slots fd_gossip_view_epoch_slots_t;

struct fd_gossip_view_duplicate_shred {
  uchar_view_t index;
};

typedef struct fd_gossip_view_duplicate_shred fd_gossip_view_duplicate_shred_t;

 /* Offsets are within full message payload, not the subset where the encoded
    CRDS value lies. */
struct fd_gossip_view_crds_value {
  union{
    offset_t value_off; /* Start of CRDS value data in payload */
    offset_t signature_off;
  };
  offset_t         pubkey_off;
  timestamp_view_t wallclock;

  ushort           length; /* Length of the value in bytes (incl. signature) */

  uchar_view_t     tag; /* Discriminant */
  union{
    fd_gossip_view_contact_info_t    contact_info[ 1 ];
    fd_gossip_view_node_instance_t   node_instance[ 1 ];
    fd_gossip_view_vote_t            vote[ 1 ];
    fd_gossip_view_epoch_slots_t     epoch_slots[ 1 ];
    fd_gossip_view_duplicate_shred_t duplicate_shred[ 1 ];
  };
};

typedef struct fd_gossip_view_crds_value fd_gossip_view_crds_value_t;

struct fd_gossip_view_crds_composite {
  offset_t                    from_off;        /* Offset to the sender's pubkey */
  ulong_view_t                crds_values_len; /* Number of CRDS values in the response */

  fd_gossip_view_crds_value_t crds_values[ FD_GOSSIP_MSG_MAX_CRDS ]; /* CRDS values */
};

typedef struct fd_gossip_view_crds_composite fd_gossip_view_pull_response_t;
typedef struct fd_gossip_view_crds_composite fd_gossip_view_push_t;
struct fd_gossip_view_pull_request {
  ulong_view_t bloom_keys_len;     /* number of keys in the bloom filter */
  offset_t     bloom_keys_offset;  /* offset to start of bloom keys in payload */

  ulong_view_t bloom_bits_len;     /* length of bloom bits vector (ulong *) */
  offset_t     bloom_bits_offset;  /* offset to start of bloom bits in payload */
  ulong_view_t bloom_len;

  ulong_view_t bloom_num_bits_set; /* number of bits set in the bloom filter */
  ulong_view_t mask;               /* mask used to filter the CRDS values */
  uint_view_t  mask_bits;          /* number of bits in the mask */

  fd_gossip_view_crds_value_t contact_info[ 1 ]; /* Pull Req holds contact info */
};

typedef struct fd_gossip_view_pull_request fd_gossip_view_pull_request_t;

struct fd_gossip_view_prune {
  offset_t         origin_off;      /* Offset to the origin pubkey */
  ulong_view_t     prunes_len;      /* Number of prunes in the message */
  offset_t         prunes_off;      /* Offset to the start of pubkeys to prune */
  offset_t         destination_off; /* Offset to the destination pubkey */
  ushort           signature_off;   /* Offset to the signature */
  timestamp_view_t wallclock;
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
  uchar_view_t tag;
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

/* Begin Encoding related structs */

/* TODO: These end up looking very similar to views. Can we merge them? */
struct fd_gossip_pull_request_encode_ctx {
  uchar * tag;
  ulong * bloom_keys_len;
  ulong * bloom_keys; /* Offset to start of bloom keys in payload */

  uchar * has_bits;
  ulong * bloom_vec_len;   /* Length of bloom bits vector */
  ulong * bloom_bits;       /* Start of bloom bits in payload */
  ulong * bloom_bits_count; /* Number of bloom filter bits */
  ulong * bloom_num_bits_set; /* Number of bits set in the bloom filter */

  ulong * mask;      /* Mask used to filter the CRDS values */
  ulong * mask_bits; /* Number of bits in the mask */

  uchar * contact_info; /* Offset to the start of contact info in payload */
};

typedef struct fd_gossip_pull_request_encode_ctx fd_gossip_pull_request_encode_ctx_t;

ulong
fd_gossip_msg_parse( fd_gossip_view_t *   view,
                     uchar const *        payload,
                     ulong                payload_sz );

int
fd_gossip_pull_request_encode_ctx_init( uchar *                               payload,
                                        ulong                                 payload_sz,
                                        ulong                                 num_keys,
                                        ulong                                 bloom_bits_len,
                                        fd_gossip_pull_request_encode_ctx_t * out_ctx );

int
fd_gossip_pull_request_encode_bloom_keys( fd_gossip_pull_request_encode_ctx_t * ctx,
                                          ulong const *                         bloom_keys,
                                          ulong                                 bloom_keys_len );

int
fd_gossip_pull_request_encode_bloom_bits( fd_gossip_pull_request_encode_ctx_t * ctx,
                                          ulong const *                         bloom_bits,
                                          ulong                                 bloom_bits_len );

int
fd_gossip_crds_contact_info_encode( fd_contact_info_t const * contact_info,
                                    uchar *                   out_buf,
                                    ulong                     out_buf_cap,
                                    ulong *                   opt_encoded_sz );

/* Handles case where new wallclock changes encoded representation of
   compact-64 bit value */
int
fd_gossip_crds_contact_info_update_wallclock( ulong * contact_info_buf,
                                              ulong * contact_info_buf_sz,
                                              ulong   contact_info_buf_cap,
                                              long    wallclock_nanos );

/* Initializes a payload buffer for a gossip message with tag encoded.
   Returns offset into the buffer after tag, where the inner message
   should begin. */
int
fd_gossip_init_msg_payload( uchar * payload,
                            ulong   payload_sz,
                            uchar   tag,
                            ulong * start_cursor );
#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_msg_h */
