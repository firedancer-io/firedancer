#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_types_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_types_h

#include "fd_gossip.h"
#include "fd_crds_value.h"

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

struct fd_gossip_bloom {
  ulong keys_len;
  ulong keys[ 150UL ]; /* max num keys if len(bits) == 1 */
  ulong bits_len;
  ulong bits[ 150UL ]; /* max num bits if len(keys) == 1 */
  ulong num_bits_set;
};

typedef struct fd_gossip_bloom fd_gossip_bloom_t;

struct fd_gossip_crds_filter {
  fd_gossip_bloom_t bloom[ 1 ];
  ulong             mask;
  uint              mask_bits;
};

typedef struct fd_gossip_crds_filter fd_gossip_crds_filter_t;


typedef struct fd_gossip_crds_data fd_gossip_crds_data_t;



struct fd_gossip_pull_request {
  fd_gossip_crds_filter_t filter[ 1 ];
  // fd_gossip_crds_value_t  value[ 1 ];
};

typedef struct fd_gossip_pull_request fd_gossip_pull_request_t;

struct fd_gossip_pull_response {
  uchar sender_pubkey[ 32UL ];
  ulong values_len;
  // fd_gossip_crds_value_t   values[ ];
};

typedef struct fd_gossip_pull_response fd_gossip_pull_response_t;

struct fd_gossip_push {
  uchar sender_pubkey[ 32UL ];
  ulong values_len;
  // fd_gossip_crds_value_t values[ ];
};

typedef struct fd_gossip_push fd_gossip_push_t;

struct fd_gossip_message_ping_pong {
  uchar from[ 32UL ];
  union{
    uchar hash[ 32UL ]; /* Hash of the last ping */
    uchar token[ 32UL ]; /* Token to be used in the pong */
  };
  uchar signature[ 64UL ];
};

typedef struct fd_gossip_message_ping_pong fd_gossip_ping_pong_t;

struct fd_gossip_message_prune {
  uchar from[ 32UL ];
  ulong prunes_len;
  /* 33 pubkeys fit in MTU (rounded down):
       1232b                      (MTU)
     - 4b                         (discriminant in gossip message)
     - 32b + 8b + 64b + 32b + 8b  (other fields in prune message)
     = 1084b                      (remaining for prunes arr)

    1084b/32 ~= 33 */
  uchar prunes[ 33UL ][ 32UL ];
  uchar signature[ 64UL ];
  uchar destination[ 32UL ];
  long  wallclock_nanos; /* needs to be converted when parsed from a gossip message */

};
typedef struct fd_gossip_message_prune fd_gossip_prune_t;

#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_types_h */
