#ifndef HEADER_fd_src_flamenco_gossip_fd_gossip_h
#define HEADER_fd_src_flamenco_gossip_fd_gossip_h

#include "../types/fd_types.h"
#include "../../util/valloc/fd_valloc.h"
#include "../../disco/metrics/generated/fd_metrics_gossip.h"

/* Max number of validators that can be known */
#define FD_PEER_KEY_MAX (1<<14)
/* Number of recognized CRDS enum members */
#define FD_KNOWN_CRDS_ENUM_MAX (14UL)

/* Contact info v2 socket tag constants */
#define FD_GOSSIP_SOCKET_TAG_GOSSIP             (0)
#define FD_GOSSIP_SOCKET_TAG_RPC                (2)
#define FD_GOSSIP_SOCKET_TAG_RPC_PUBSUB         (3)
#define FD_GOSSIP_SOCKET_TAG_SERVE_REPAIR       (4)
#define FD_GOSSIP_SOCKET_TAG_SERVE_REPAIR_QUIC  (1)
#define FD_GOSSIP_SOCKET_TAG_TPU                (5)
#define FD_GOSSIP_SOCKET_TAG_TPU_FORWARDS       (6)
#define FD_GOSSIP_SOCKET_TAG_TPU_FORWARDS_QUIC  (7)
#define FD_GOSSIP_SOCKET_TAG_TPU_QUIC           (8)
#define FD_GOSSIP_SOCKET_TAG_TPU_VOTE           (9)
#define FD_GOSSIP_SOCKET_TAG_TVU                (10)
#define FD_GOSSIP_SOCKET_TAG_TVU_QUIC           (11)

/* Global state of gossip protocol */
typedef struct fd_gossip fd_gossip_t;
ulong         fd_gossip_align    ( void );
ulong         fd_gossip_footprint( void );
void *        fd_gossip_new      ( void * shmem, ulong seed );
fd_gossip_t * fd_gossip_join     ( void * shmap );
void *        fd_gossip_leave    ( fd_gossip_t * join );
void *        fd_gossip_delete   ( void * shmap );


union fd_gossip_peer_addr {
    struct {
        uint   addr;  /* IPv4 address, network byte order (big endian) */
        ushort port;  /* port number, network byte order (big endian) */
        ushort pad;   /* Must be zero */
    };
    ulong l;          /* Combined port and address */
};
typedef union fd_gossip_peer_addr fd_gossip_peer_addr_t;

int
fd_gossip_from_soladdr(fd_gossip_peer_addr_t * dst, fd_gossip_socket_addr_t const * src );

int
fd_gossip_to_soladdr( fd_gossip_socket_addr_t * dst, fd_gossip_peer_addr_t const * src );


void
fd_gossip_contact_info_v2_to_v1( fd_gossip_contact_info_v2_t const * v2,
                                 fd_gossip_contact_info_v1_t *       v1 );

int
fd_gossip_contact_info_v2_find_proto_ident( fd_gossip_contact_info_v2_t const * contact_info,
                                            uchar                               proto_ident,
                                            fd_gossip_socket_addr_t *           out_addr );

/* Callback when a new message is received */
typedef void (*fd_gossip_data_deliver_fun)(fd_crds_data_t* data, void* arg);

/* Callback for sending a packet. addr is the address of the destination. */
typedef void (*fd_gossip_send_packet_fun)( uchar const * msg, size_t msglen, fd_gossip_peer_addr_t const * addr, void * arg );

/* Callback for signing */
typedef void (*fd_gossip_sign_fun)( void * ctx, uchar * sig, uchar const * buffer, ulong len, int sign_type );

struct fd_gossip_config {
    fd_pubkey_t * public_key;
    uchar * private_key;
    fd_gossip_peer_addr_t my_addr;
    fd_gossip_version_v2_t my_version;
    ushort shred_version;
    fd_gossip_data_deliver_fun deliver_fun;
    void * deliver_arg;
    fd_gossip_send_packet_fun send_fun;
    void * send_arg;
    fd_gossip_sign_fun sign_fun;
    void * sign_arg;
};
typedef struct fd_gossip_config fd_gossip_config_t;

/* Initialize the gossip data structure */
int fd_gossip_set_config( fd_gossip_t * glob, const fd_gossip_config_t * config );

/* Update the binding addr */
int fd_gossip_update_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * addr );

/* Update the repair service addr */
int fd_gossip_update_repair_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * serve );

/* Update the tvu rx addr */
int
fd_gossip_update_tvu_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * tvu, const fd_gossip_peer_addr_t * tvu_fwd );

/* Update the tpu addr */
int
fd_gossip_update_tpu_addr( fd_gossip_t * glob,
                           fd_gossip_peer_addr_t const * tpu,
                           fd_gossip_peer_addr_t const * tpu_fwd );

/* Update the tpu vote addr */
int fd_gossip_update_tpu_vote_addr( fd_gossip_t * glob, const fd_gossip_peer_addr_t * tpu_vote );

/* Set the shred version (after receiving a contact info msg) */
void fd_gossip_set_shred_version( fd_gossip_t * glob, ushort shred_version );

/* Add a peer to talk to */
int fd_gossip_add_active_peer( fd_gossip_t * glob, fd_gossip_peer_addr_t * addr );

/* Publish an outgoing value. The source id and wallclock are set by this function. The gossip key for the value is optionally returned. */
int fd_gossip_push_value( fd_gossip_t * glob, fd_crds_data_t* data, fd_hash_t * key_opt );

/* Set the current protocol time in nanosecs. Call this as often as feasible. */
void fd_gossip_settime( fd_gossip_t * glob, long ts );

/* Get the current protocol time in nanosecs */
long fd_gossip_gettime( fd_gossip_t * glob );

/* Start timed events and other protocol behavior. settime MUST be called before this. */
int fd_gossip_start( fd_gossip_t * glob );

/* Dispatch timed events and other protocol behavior. This should be
 * called inside the main spin loop. calling settime first is recommended. */
int fd_gossip_continue( fd_gossip_t * glob );

/* Pass a raw gossip packet into the protocol. addr is the address of the sender */
int fd_gossip_recv_packet( fd_gossip_t * glob, uchar const * msg, ulong msglen, fd_gossip_peer_addr_t const * addr );

const char * fd_gossip_addr_str( char * dst, ulong dstlen, fd_gossip_peer_addr_t const * src );

ushort fd_gossip_get_shred_version( fd_gossip_t const * glob );

void fd_gossip_set_stake_weights( fd_gossip_t * gossip, fd_stake_weight_t const * stake_weights, ulong stake_weights_cnt );

/* fd_gossip_set_entrypoints sets ip and ports for initial known
   validators to gossip to.  These values are set by the operator
   at startup.  This function should only be called at startup. */
void fd_gossip_set_entrypoints( fd_gossip_t * gossip,
                                uint const * allowed_entrypoints, /* big endian ipv4 addresses (allowed_entrypoints_cnt many) */
                                ulong allowed_entrypoints_cnt,    /* number of allowed entrypoints, assumed to be in [1, FD_ACTIVE_KEY_MAX] */
                                ushort const * ports );           /* gossip ports of the peers (allowed_entrypoints_cnt many) */

uint fd_gossip_is_allowed_entrypoint( fd_gossip_t * gossip, fd_gossip_peer_addr_t * addr );

/* Gossip Metrics */
struct fd_gossip_metrics {
  /* Receive Packets */
  ulong recv_pkt_cnt;
  ulong recv_pkt_corrupted_msg;

  /* Receive Gossip Messages */
  ulong recv_message[FD_METRICS_COUNTER_GOSSIP_RECEIVED_GOSSIP_MESSAGES_CNT];
  ulong recv_unknown_message;

  /* Receive CRDS */
  /* TODO: seperate into Push/Pull */
  ulong recv_crds[FD_METRICS_COUNTER_GOSSIP_RECEIVED_CRDS_CNT];
  ulong recv_crds_duplicate_message[FD_METRICS_COUNTER_GOSSIP_RECEIVED_CRDS_DUPLICATE_MESSAGE_CNT];
  ulong recv_crds_drop_reason[FD_METRICS_COUNTER_GOSSIP_RECEIVED_CRDS_DROP_CNT];


  /* Push CRDS value */
  ulong push_crds[FD_KNOWN_CRDS_ENUM_MAX];
  ulong push_crds_duplicate[FD_METRICS_COUNTER_GOSSIP_PUSH_CRDS_DUPLICATE_MESSAGE_CNT];
  ulong push_crds_drop_reason[FD_METRICS_COUNTER_GOSSIP_PUSH_CRDS_DROP_CNT];
  ulong push_crds_queue_cnt;

  /* Active Push Destinations */
  ulong active_push_destinations;
  ulong refresh_push_states_failcnt;

  /* Pull Requests/Responses */
  ulong handle_pull_req_fails[FD_METRICS_COUNTER_GOSSIP_PULL_REQ_FAIL_CNT];
  ulong handle_pull_req_bloom_filter_result[FD_METRICS_COUNTER_GOSSIP_PULL_REQ_BLOOM_FILTER_CNT]; /* TODO: per host? */
  ulong handle_pull_req_npackets; /* TODO: per host? */

  /* Receive Prune Messages */
  ulong handle_prune_fails[FD_METRICS_COUNTER_GOSSIP_PRUNE_FAIL_COUNT_CNT];

  /* Send Prune Messages */
  ulong make_prune_stale_entry; /* TODO: per host? */
  ulong make_prune_high_duplicates; /* TODO: per host? */
  ulong make_prune_requested_origins; /* TODO: per host? */
  ulong make_prune_sign_data_encode_failed;

  /* Send Gossip Messages */
  ulong send_message[FD_METRICS_COUNTER_GOSSIP_SENT_GOSSIP_MESSAGES_CNT];

  /* Send Packets */
  ulong send_packet_cnt;

  /* Ping/Pong */
  ulong send_ping_events[FD_METRICS_COUNTER_GOSSIP_SEND_PING_EVENT_CNT];
  ulong recv_ping_invalid_signature;

  ulong recv_pong_events[FD_METRICS_COUNTER_GOSSIP_RECV_PONG_EVENT_CNT];

  /* Peers (all known validators) */
  ulong gossip_peer_cnt[FD_METRICS_GAUGE_GOSSIP_GOSSIP_PEER_COUNTS_CNT];
  /* TODO: Lock metrics */
};
typedef struct fd_gossip_metrics fd_gossip_metrics_t;
#define FD_GOSSIP_METRICS_FOOTPRINT ( sizeof( fd_gossip_metrics_t ) )

fd_gossip_metrics_t *
fd_gossip_get_metrics( fd_gossip_t * gossip );

#endif /* HEADER_fd_src_flamenco_gossip_fd_gossip_h */
