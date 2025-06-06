
#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_msg_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_msg_h

// #include "fd_gossip_types.h"
// #include "fd_crds_value.h"
#include "../../util/fd_util.h"

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

struct fd_gossip_view_ipaddr {
  uchar   is_ip6;
  union {
    uint   ip4_addr;
    ushort ip6_addr_off; /* Offset to 16-byte value */
  };
};

typedef struct fd_gossip_view_ipaddr fd_gossip_view_ipaddr_t;

struct fd_gossip_view_socket {
  uchar   key;
  uchar   index;
  ushort  offset; /* NOTE: this is a varint in encoded form */
};

typedef struct fd_gossip_view_socket fd_gossip_view_socket_t;

struct fd_gossip_view_contact_info {
  long                    instance_creation_wallclock_nanos;
  ushort                  shred_version;

  ushort                  addrs_len;
  fd_gossip_view_ipaddr_t addrs[ 16UL ];    /* TODO: calculate length bounds */

  ushort                  sockets_len;
  fd_gossip_view_socket_t sockets[ 16UL ];  /* TODO: calculate length bounds */

  ushort                  ext_len;
  ushort                  ext_off;
};

typedef struct fd_gossip_view_contact_info fd_gossip_view_contact_info_t;

struct fd_gossip_view_node_instance {
  ushort token_off;
};

typedef struct fd_gossip_view_node_instance fd_gossip_view_node_instance_t;

struct fd_gossip_view_vote {
  uchar  index;
  ulong  transaction_sz;
  ushort transaction_off;
};

typedef struct fd_gossip_view_vote fd_gossip_view_vote_t;

struct fd_gossip_view_epoch_slots {
  uchar  index;
};

typedef struct fd_gossip_view_epoch_slots fd_gossip_view_epoch_slots_t;

struct fd_gossip_view_duplicate_shred {
  ushort index;
};

typedef struct fd_gossip_view_duplicate_shred fd_gossip_view_duplicate_shred_t;

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

  uchar tag; /* Discriminant */
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
  ushort from_off; /* Offset to the sender's pubkey */
  ushort crds_values_len; /* Number of CRDS values in the response */

  fd_gossip_view_crds_value_t crds_values[ FD_GOSSIP_MSG_MAX_CRDS ]; /* CRDS values */
};

typedef struct fd_gossip_view_crds_composite fd_gossip_view_pull_response_t;
typedef struct fd_gossip_view_crds_composite fd_gossip_view_push_t;
struct fd_gossip_view_pull_request {
  ulong bloom_keys_len;     /* number of keys in the bloom filter */
  ulong bloom_keys_offset;  /* offset to start of bloom keys in payload */

  ulong bloom_bits_len;     /* length of bloom bits vector (ulong *) */
  ulong bloom_bits_offset;  /* offset to start of bloom bits in payload */
  ulong bloom_len;

  ulong bloom_num_bits_set; /* number of bits set in the bloom filter */
  ulong mask;               /* mask used to filter the CRDS values */
  uint  mask_bits;          /* number of bits in the mask */

  fd_gossip_view_crds_value_t contact_info[ 1 ]; /* Pull Req holds contact info */
};

typedef struct fd_gossip_view_pull_request fd_gossip_view_pull_request_t;

struct fd_gossip_view_prune {
  ushort origin_off;      /* Offset to the origin pubkey */
  ushort prunes_len;      /* Number of prunes in the message */
  ushort prunes_off;      /* Offset to the start of pubkeys to prune */
  ushort destination_off; /* Offset to the destination pubkey */
  ulong  wallclock;       /* Wallclock encoded by sender (for sigverify) */
  ushort signature_off;   /* Offset to the signature */

  long   wallclock_nanos;
};

typedef struct fd_gossip_view_prune fd_gossip_view_prune_t;

struct fd_gossip_view_ping {
  ushort from_off;
  ushort token_off;
  ushort signature_off;
};

typedef struct fd_gossip_view_ping fd_gossip_view_ping_t;

struct fd_gossip_view_pong {
  ushort from_off;
  ushort hash_off;
  ushort signature_off;
};

typedef struct fd_gossip_view_pong fd_gossip_view_pong_t;

struct fd_gossip_view {
  uchar tag; // uint in rust bincode
  union {
    fd_gossip_view_pull_request_t  pull_request[ 1 ];
    fd_gossip_view_pull_response_t pull_response[ 1 ];
    fd_gossip_view_push_t          push[ 1 ];
    fd_gossip_view_prune_t         prune[ 1 ];
    fd_gossip_view_ping_t          ping[ 1 ];
    fd_gossip_view_pong_t          pong[ 1 ];
  };
};

typedef struct fd_gossip_view fd_gossip_view_t;

void
fd_gossip_msg_init( fd_gossip_view_t * msg );

ulong
fd_gossip_view_pubkey_offset( fd_gossip_view_t const * view );

ulong
fd_gossip_msg_parse( fd_gossip_view_t *   view,
                     uchar const *        payload,
                     ulong                payload_sz );

/* Initializes a payload buffer for a gossip message with tag encoded.
   Returns offset into the buffer after tag, where the inner message
   should begin. */
ulong
fd_gossip_init_msg_payload( uchar * payload,
                            ulong   payload_sz,
                            uchar   tag );
#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_msg_h */
