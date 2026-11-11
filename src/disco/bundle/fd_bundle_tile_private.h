#ifndef HEADER_fd_src_disco_bundle_fd_bundle_tile_private_h
#define HEADER_fd_src_disco_bundle_fd_bundle_tile_private_h

#include "fd_bundle_auth.h"
#include "fd_bundle_tile.h"
#include "fd_keepalive.h"
#include "../fd_clock_tile.h"
#include "../fd_txn_m.h"
#include "../tiles.h"
#include "../stem/fd_stem.h"
#include "../keyguard/fd_keyswitch.h"
#include "../keyguard/fd_keyguard_client.h"
#include "../../waltz/grpc/fd_grpc_client.h"
#include "../../waltz/http/fd_url.h"
#include "../../waltz/resolv/fd_netdb.h"
#include "../../waltz/fd_rtt_est.h"
#include "../../util/hist/fd_histf.h"

#define FD_BUNDLE_CLIENT_MAX_TXN_PER_BUNDLE (5UL)

#include "../../waltz/tlsrec/fd_tlsrec.h"
#include "../../ballet/x509/fd_x509_ca_store.h"
#include "../../ballet/x509/fd_x509_verify.h"

struct fd_bundle_out_ctx {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
};

typedef struct fd_bundle_out_ctx fd_bundle_out_ctx_t;

/* fd_bundle_metrics_t contains private metric counters.  These get
   published to fd_metrics periodically. */

struct fd_bundle_metrics {
  ulong txn_received_cnt;
  ulong bundle_received_cnt;
  ulong packet_received_cnt;
  ulong proto_received_bytes;
  ulong ping_ack_cnt;

  ulong decode_fail_cnt;
  ulong transport_fail_cnt;
  ulong missing_builder_info_fail_cnt;
  ulong backpressure_drop_cnt;

  fd_histf_t msg_rx_delay[1];
};

typedef struct fd_bundle_metrics fd_bundle_metrics_t;

typedef struct fd_bundle_tile fd_bundle_tile_t;

/* fd_bundle_builder_t is the block builder whose tips the validator
   cranks for a bundle, and when to next ask the server for it. */

struct fd_bundle_builder {
  uchar pubkey[ 32 ];
  uchar commission; /* in [0,100] (percent) */
  uchar avail;      /* known (potentially stale)? */
  uchar wait;       /* request in flight? */
  long  next;       /* when the next request is due */
};

typedef struct fd_bundle_builder fd_bundle_builder_t;

/* Streams a Jito protocol session subscribes to */

#define FD_BUNDLE_SUB_PACKETS (0) /* SubscribePackets */
#define FD_BUNDLE_SUB_BUNDLES (1) /* SubscribeBundles or SubscribeBundles2 */
#define FD_BUNDLE_SUB_BLOCKS  (2) /* SubscribeBlocks2, Harmonic only */
#define FD_BUNDLE_SUB_RELAYER (3) /* relayer.Relayer/SubscribePackets */
#define FD_BUNDLE_SUB_CNT     (4)

/* fd_bundle_conn_t is the state of one connection to a bundle server.
   Its gRPC client's app_ctx is the conn. */

struct fd_bundle_conn {
  fd_bundle_tile_t * ctx;
  int                protocol; /* FD_BUNDLE_PROTOCOL_* */

  /* Session state, reset with the conn (auther unused in BAM mode) */
  fd_bundle_auther_t  auther;
  fd_bundle_builder_t builder; /* refreshed every 5 minutes, BAM's from GetBuilderConfig, or for the relayer, its TPU */

  /* Leader notice of ctx->leader_state, queued by the protocol's
     leader_update and dropped once its slot ends */
  uchar leader_pending : 1;

  /* Subscriptions, indexed by FD_BUNDLE_SUB_* */
  struct {
    uchar live; /* stream open */
    uchar wait; /* request in flight */
  } sub[ FD_BUNDLE_SUB_CNT ];

  /* Harmonic scheduling strategy, acknowledged once per connection */
  int   strategy; /* FD_BUNDLE_STRATEGY_* */
  uchar strategy_set  : 1;
  uchar strategy_wait : 1;

  /* Session state specific to the protocol */
  union {
    /* Harmonic block stream, reset at the start of each leader slot */
    struct {
      ulong block_seq;       /* bundles numbered so far in the current leader slot */
      ulong block_bundle_id; /* bundle_id of the bundle being decoded */
      uchar block_lost : 1;  /* a reset cut off the current leader slot's block */
    } harmonic;

    /* BAM session, reset with the conn */
    struct {
      fd_grpc_h2_stream_t * stream;              /* InitSchedulerStream, NULL until opened */
      uchar                 challenge_wait  : 1; /* GetAuthChallenge in flight */
      uchar                 stream_accepted : 1; /* the node sent a message on the stream */
      uchar                 pong_pending    : 1;
      uchar                 heartbeat_seen  : 1; /* a BuilderHeartBeat arrived on this stream */
      uint                  pong_id;
      long                  heartbeat_next;      /* next ValidatorHeartBeat */
      long                  heartbeat_rx;        /* last BuilderHeartBeat, or stream open */
      char                  challenge[ 128 ];    /* cstr, empty if none */
    } bam;
  };

  /* TPU the server offers for gossip, kept across reconnects, zero if
     none */
  fd_bundle_tpu_t tpu;

  /* Endpoint */
  uint   is_ssl : 1;
  char   server_fqdn[ FD_FQDN_BUF_MAX ]; /* cstr */
  ulong  server_fqdn_len;
  char   server_sni[ FD_SNI_BUF_MAX ]; /* cstr */
  ulong  server_sni_len;
  ushort server_tcp_port;
  uint   server_ip4_addr; /* last DNS lookup result */

  /* Native TLS, configured with this conn's server name */
  fd_tls_t         tls[1];
  fd_tlsrec_conn_t tls_conn[1];

  /* TCP socket */
  int  tcp_sock;
  uint tcp_sock_connected : 1;
  uint defer_reset : 1;
  uint sock_in_epoll : 1;
  uint epoll_out_armed : 1;
  long conn_deadline;

  /* Keepalive via HTTP/2 PINGs (randomized) */
  fd_keepalive_t    keepalive[1];
  fd_rtt_estimate_t rtt[1];

  /* gRPC client */
  void *                   grpc_client_mem;
  fd_grpc_client_t *       grpc_client;
  fd_grpc_client_metrics_t grpc_metrics[1];

  /* Error backoff */
  uint backoff_iter;
  long backoff_until;
  long backoff_reset;
};

typedef struct fd_bundle_conn fd_bundle_conn_t;

#define FD_BUNDLE_CONN_MAX FD_TOPO_BUNDLE_CONN_MAX

/* fd_bundle_tile_t is the context object provided to callbacks from
   stem, and contains all state needed to progress the tile. */

struct fd_bundle_tile {
  /* Key switch */
  fd_keyswitch_t * keyswitch;

  /* Key guard */
  fd_keyguard_client_t keyguard_client[1];

  int keylog_fd;

  /* Native TLS, shared by all conns */
  fd_chacha_rng_t    tls_rng[1];
  fd_x509_ca_store_t ca_store[1];

  /* Resolver */
  fd_netdb_fds_t netdb_fds[1];

  fd_bundle_conn_t conn[ FD_BUNDLE_CONN_MAX ];
  ulong            conn_cnt;
  int              so_rcvbuf;
  long             keepalive_interval;
  ulong            grpc_buf_max;
  ulong            map_seed;
  long             cached_ts;

  ulong   waker_client_idx;
  ulong * waker_fseq;
  long    next_step_deadline;

  /* Validator identity, which BAM logs in as.  Each conn's auther
     keeps its own copy. */
  uchar identity_pubkey[ 32 ];

  /* Bundle state */
  ulong bundle_seq;

  /* Bundle being decoded, published on close */
  struct {
    fd_bundle_builder_t const * builder;
    ulong txn_cnt;     /* transactions seen, including dropped ones */
    uchar atomic;
    uchar want_result;
    ulong slot;        /* fd_txn_m_t block_engine.slot, set on close */
    ulong seq;         /* fd_txn_m_t block_engine.seq, set on close */
    uchar invalid : 1; /* dropped on close */
    struct {
      void const * data; /* in the message being decoded */
      ulong        data_sz;
      uint         source_ipv4;
    } txn[ FD_BUNDLE_CLIENT_MAX_TXN_PER_BUNDLE ];
  } bundle;

  fd_rng_t rng[1];

  /* Stem publish */
  fd_stem_context_t *       stem;
  fd_bundle_out_ctx_t       verify_out;
  fd_bundle_out_ctx_t       plugin_out;

  /* The block builder conn is read first, and messages from other conns
     leave cr_reserve (half) of verify_out's credits free, so they cannot
     crowd out the builder's ordered bundles. */
  ulong cr_reserve; /* credits the message being decoded must leave */

  /* App metrics */
  fd_bundle_metrics_t metrics;

  /* 1 while the builder conn is healthy (for BAM, logged in with a
     builder and heartbeats), 0 otherwise, for pack.  NULL if the
     topology has none. */
  ulong * active_fseq;

  /* tpu_advertised is the last TPU published to gossip, from a healthy
     conn that offers one (zero for ours), tpu_dirty is set until it is. */
  fd_bundle_tpu_t     tpu_advertised;
  uchar               tpu_dirty;
  fd_bundle_out_ctx_t tpu_out;

  /* Check engine light */
  uchar bundle_status_recent;  /* most recently observed 'check engine light' */
  uchar bundle_status_plugin;  /* last 'plugin' update written */
  uchar bundle_status_logged;
  long  last_bundle_status_log_nanos;

  ulong next_leader_slot; /* from replay became leader and next leader messages, or ULONG_MAX */
  ulong reset_slot;       /* from replay became leader and next leader messages, or ULONG_MAX */
  int   sleep_mode;       /* 1 means sleeping, 0 means connecting/connected */
  long  sleep_check_ns;   /* next wallclock time to re-evaluate sleeping */

  fd_clock_tile_t clock[1]; /* fast wallclock-ns source for fd_bundle_now */
  int   halt_signing;     /* 1 means signing is halted, 0 means signing is not halted */

  /* Staged values from during_frag, committed in after_frag */
  ulong                  next_leader_slot_staged;
  ulong                  reset_slot_staged;
  fd_pack_leader_state_t leader_state_staged[1];

  fd_pack_leader_state_t leader_state[1]; /* latest from pack, slot is ULONG_MAX before the first */

  int   in_kind[ 64 ];
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
  } replay_in;
  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
  } pack_in;
};

/* Define 'request_ctx' IDs to identify different types of gRPC calls */

#define FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets            4
#define FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles            5
#define FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo      6
#define FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBlocks             7
#define FD_BUNDLE_CLIENT_REQ_Bundle_SetStrategy                 8
#define FD_BUNDLE_CLIENT_REQ_Bundle_SubmitLeaderWindowInfo      9
#define FD_BUNDLE_CLIENT_REQ_Bam_GetAuthChallenge              10
#define FD_BUNDLE_CLIENT_REQ_Bam_InitSchedulerStream           11
#define FD_BUNDLE_CLIENT_REQ_Bam_GetBuilderConfig              12
#define FD_BUNDLE_CLIENT_REQ_Relayer_SubscribePackets         13
#define FD_BUNDLE_CLIENT_REQ_Relayer_GetTpuConfigs            14

FD_PROTOTYPES_BEGIN

/* fd_bundle_now returns wallclock nanoseconds from the tile's
   fd_clock.  Backed by a weak symbol, allowing tests to override the
   clock source. */

long
fd_bundle_now( fd_bundle_tile_t const * ctx );

/* fd_bundle_client_grpc_callbacks provides callbacks for grpc_client. */

extern fd_grpc_client_callbacks_t fd_bundle_client_grpc_callbacks;

/* fd_bundle_client_step is an all-in-one routine to drive client logic.
   As long as the tile calls this periodically, the client will
   reconnect to the bundle server, authenticate, and subscribe to
   packets and bundles. */

void
fd_bundle_client_step( fd_bundle_tile_t * bundle,
                       int *              charge_busy );

/* fd_bundle_client_step_reconnect drives the session on conn once the
   HTTP/2 conn is established (SETTINGS exchanged), e.g. for a Jito
   session the auth logic, block builder info requests, subscriptions
   and PINGs.  Returns 1 if it did work. */

int
fd_bundle_client_step_reconnect( fd_bundle_conn_t * conn,
                                 long               now );

/* fd_bundle_client_next_deadline returns when fd_bundle_client_step
   next needs to run absent any fd event.  While TCP is connecting,
   returns the connection setup deadline; while disconnected, returns
   the reconnect time (at least now).  Once connected, considers gRPC
   deadlines, keepalive, builder info expiry and connection setup.
   Returns now if decrypted bytes are buffered in the native TLS/gRPC
   client and TLS TX is not blocked; blocked TX waits for EPOLLOUT. */

long
fd_bundle_client_next_deadline( fd_bundle_tile_t const * ctx,
                                long                     now );

/* fd_bundle_conn_backoff is called whenever an error occurs on conn.
   Stalls its forward progress for a randomized amount of time to
   prevent error floods. */

void
fd_bundle_conn_backoff( fd_bundle_conn_t * conn,
                        long               now );

/* fd_bundle_conn_should_stall returns 1 if forward progress on conn
   should be temporarily prevented due to an error. */

FD_FN_PURE static inline int
fd_bundle_conn_should_stall( fd_bundle_conn_t const * conn,
                             long                     now ) {
  return now < conn->backoff_until;
}

/* fd_bundle_tile_housekeeping runs periodically at a low frequency. */

void
fd_bundle_tile_housekeeping( fd_bundle_tile_t * ctx );

/* fd_bundle_client_grpc_rx_start is the first RX callback of a stream. */

void
fd_bundle_client_grpc_rx_start(
    void * app_ctx,
    ulong  request_ctx
) ;

/* fd_bundle_client_grpc_rx_msg is called by grpc_client when a gRPC
   message arrives (unary or server-streaming response). */

void
fd_bundle_client_grpc_rx_msg(
    void *       app_ctx,      /* (fd_bundle_conn_t *) */
    void const * protobuf,
    ulong        protobuf_sz,
    ulong        request_ctx   /* FD_BUNDLE_CLIENT_REQ_{...} */
);

/* fd_bundle_client_grpc_rx_end is called by grpc_client when a gRPC
   server-streaming response finishes. */

void
fd_bundle_client_grpc_rx_end(
    void *                app_ctx,
    ulong                 request_ctx,
    fd_grpc_resp_hdrs_t * resp
);

/* fd_bundle_client_grpc_rx_timeout is called by grpc_client when a
   gRPC request deadline gets exceeded. */

void
fd_bundle_client_grpc_rx_timeout(
    void * app_ctx,
    ulong  request_ctx, /* FD_BUNDLE_CLIENT_REQ_{...} */
    int    deadline_kind /* FD_GRPC_DEADLINE_{HEADER|RX_END} */
);

/* fd_bundle_conn_status provides a "check engine light" for conn using
   FD_BUNDLE_STATE_{DISCONNECTED,CONNECTING,CONNECTED}.

   DISCONNECTED means TCP or HTTP/2 is unavailable/dead, GOAWAY is being
   sent, or keepalive has timed out.  CONNECTING means HTTP/2 setup,
   authentication, builder info or a subscription is not ready.
   CONNECTED means these checks pass and the gRPC client is connected.

   fd_bundle_client_status is the worst status of all conns. */

int
fd_bundle_conn_status( fd_bundle_conn_t const * conn );

int
fd_bundle_client_status( fd_bundle_tile_t const * ctx );

/* fd_bundle_client_builder returns the block builder conn, which pack
   follows, or NULL if there is none. */

fd_bundle_conn_t *
fd_bundle_client_builder( fd_bundle_tile_t * ctx );

/* fd_bundle_conn_name returns the name of conn's protocol, e.g. "jito". */

char const *
fd_bundle_conn_name( fd_bundle_conn_t const * conn );

/* fd_bundle_request_ctx_cstr returns the gRPC method name for a
   FD_BUNDLE_CLIENT_REQ_* ID.  Returns "unknown" the ID is not
   recognized. */

FD_FN_CONST char const *
fd_bundle_request_ctx_cstr( ulong request_ctx );

/* fd_bundle_conn_reset closes conn and resets the session on it, and
   backs off before it reconnects.  fd_bundle_client_reset resets every
   conn. */

void
fd_bundle_conn_reset( fd_bundle_conn_t * conn );

void
fd_bundle_client_reset( fd_bundle_tile_t * ctx );

/* fd_bundle_conn_send_ping enqueues an HTTP/2 PING on conn and starts
   the keepalive deadline.  Does nothing if the connection is
   unavailable, busy, or lacks TX ring space. */

void
fd_bundle_conn_send_ping( fd_bundle_conn_t * conn );

/* fd_bundle_client_leader_state_update is called for every leader state
   update from pack, now in ctx->leader_state.  new_slot is set on the
   first update of a leader slot.  Queues whatever the protocol sends in
   response, and returns 1 if anything was queued (so the client should
   be stepped soon), 0 otherwise. */

int
fd_bundle_client_leader_state_update( fd_bundle_tile_t * ctx,
                                      int                new_slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_bundle_fd_bundle_tile_private_h */
