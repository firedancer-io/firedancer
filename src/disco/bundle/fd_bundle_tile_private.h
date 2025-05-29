#ifndef HEADER_fd_src_disco_bundle_fd_bundle_tile_private_h
#define HEADER_fd_src_disco_bundle_fd_bundle_tile_private_h

#include "fd_bundle_auth.h"
#include "../stem/fd_stem.h"
#include "../keyguard/fd_keyswitch.h"
#include "../keyguard/fd_keyguard_client.h"
#include "../../waltz/grpc/fd_grpc_client.h"
#include "../../waltz/resolv/fd_netdb.h"
#include "../../util/alloc/fd_alloc.h"

#if FD_HAS_OPENSSL
#include <openssl/ssl.h> /* SSL_CTX */
#endif

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
  ulong shredstream_heartbeat_cnt;
  ulong ping_ack_cnt;

  ulong decode_fail_cnt;
  ulong transport_fail_cnt;
  ulong missing_builder_info_fail_cnt;
};

typedef struct fd_bundle_metrics fd_bundle_metrics_t;

/* fd_bundle_tile_t is the context object provided to callbacks from the
   mux tile, and contains all state needed to progress the tile. */

struct fd_bundle_tile {
  /* Key switch */
  fd_keyswitch_t * keyswitch;
  uint             identity_switched : 1;

  /* Key guard */
  fd_keyguard_client_t keyguard_client[1];

  uint is_ssl : 1;
  int  keylog_fd;
# if FD_HAS_OPENSSL
  /* OpenSSL */
  SSL_CTX *    ssl_ctx;
  SSL *        ssl;
  fd_alloc_t * ssl_alloc;
  uint         skip_cert_verify : 1;
# endif /* FD_HAS_OPENSSL */

  /* Config */
  char   server_fqdn[ 256 ]; /* cstr */
  ulong  server_fqdn_len;
  char   server_sni[ 256 ]; /* cstr */
  ulong  server_sni_len;
  ushort server_tcp_port;

  /* Resolver */
  fd_netdb_fds_t netdb_fds[1];
  uint server_ip4_addr; /* last DNS lookup result */

  /* TCP socket */
  int  tcp_sock;
  int  so_rcvbuf;
  uint tcp_sock_connected : 1;
  uint defer_reset : 1;

  /* Keepalive via HTTP/2 PINGs (randomized) */
  long  last_ping_tx_ts;       /* last TX tickcount */
  long  last_ping_rx_ts;       /* last RX tickcount */
  ulong ping_randomize;        /* random 64 bits */
  ulong ping_threshold_ticks;  /* avg keepalive timeout in ticks, 2^n-1 */

  /* gRPC client */
  void *                   grpc_client_mem;
  fd_grpc_client_t *       grpc_client;
  fd_grpc_client_metrics_t grpc_metrics[1];
  ulong                    map_seed;

  /* Bundle authenticator */
  fd_bundle_auther_t auther;

  /* Bundle block builder info */
  uchar builder_pubkey[ 32 ];
  uchar builder_commission;  /* in [0,100] (percent) */
  uchar builder_info_avail : 1;  /* Block builder info available? (potentially stale) */
  uchar builder_info_live  : 1;  /* Block builder info recent enough? */
  uchar builder_info_wait  : 1;  /* Request already in-flight? */

  /* Bundle subscriptions */
  uchar packet_subscription_live : 1;  /* Want to subscribe to a stream? */
  uchar packet_subscription_wait : 1;  /* Request already in-flight? */
  uchar bundle_subscription_live : 1;
  uchar bundle_subscription_wait : 1;

  /* Bundle state */
  ulong bundle_seq;
  ulong bundle_txn_cnt;

  /* Error backoff */
  fd_rng_t rng[1];
  uint     backoff_iter;
  long     backoff_until;
  long     backoff_reset;

  /* Stem publish */
  fd_stem_context_t * stem;
  fd_bundle_out_ctx_t verify_out;
  fd_bundle_out_ctx_t plugin_out;

  /* App metrics */
  fd_bundle_metrics_t metrics;

  /* Check engine light */
  uchar bundle_status_recent;  /* most recently observed 'check engine light' */
  uchar bundle_status_plugin;  /* last 'plugin' update written */
};

typedef struct fd_bundle_tile fd_bundle_tile_t;

/* Define 'request_ctx' IDs to identify different types of gRPC calls */

#define FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets            4
#define FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles            5
#define FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo      6

FD_PROTOTYPES_BEGIN

/* fd_bundle_client_grpc_callbacks provides callbacks for grpc_client. */

extern fd_grpc_client_callbacks_t fd_bundle_client_grpc_callbacks;

/* fd_bundle_client_step is an all-in-one routine to drive client logic.
   As long as the tile calls this periodically, the client will
   reconnect to the bundle server, authenticate, and subscribe to
   packets and bundles. */

void
fd_bundle_client_step( fd_bundle_tile_t * bundle,
                       int *              charge_busy );

/* fd_bundle_tile_backoff is called whenever an error occurs.  Stalls
   forward progress for a randomized amount of time to prevent error
   floods. */

void
fd_bundle_tile_backoff( fd_bundle_tile_t * ctx,
                        long               tickcount );

/* fd_bundle_tile_should_stall returns 1 if forward progress should be
   temporarily prevented due to an error. */

FD_FN_PURE static inline int
fd_bundle_tile_should_stall( fd_bundle_tile_t const * ctx,
                             long                     tickcount ) {
  return tickcount < ctx->backoff_until;
}

/* fd_bundle_client_grpc_rx_msg is called by grpc_client when a gRPC
   message arrives (unary or server-streaming response). */

void
fd_bundle_client_grpc_rx_msg(
    void *       app_ctx,      /* (fd_bundle_tile_t *) */
    void const * protobuf,
    ulong        protobuf_sz,
    ulong        request_ctx   /* FD_BUNDLE_CLIENT_REQ_{...} */
);

/* fd_bundle_client_status provides a "check engine light".

   Returns 0 if the client has recently failed and is currently backing
   off from a reconnect attempt.

   Returns 1 if the client is currently reconnecting.

   Returns 2 if all of the following conditions are met:
   - TCP socket is alive
   - SSL session is not in an error state
   - HTTP/2 connection is established (SETTINGS exchange done)
   - gRPC bundle and packet subscriptions are live
   - HTTP/2 PING exchange was done recently

   Return codes are compatible with FD_PLUGIN_MSG_BLOCK_ENGINE_UPDATE_STATUS_{...}. */

int
fd_bundle_client_status( fd_bundle_tile_t const * ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_bundle_fd_bundle_tile_private_h */
