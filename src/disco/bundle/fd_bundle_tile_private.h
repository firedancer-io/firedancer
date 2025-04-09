#ifndef HEADER_fd_src_disco_bundle_fd_bundle_tile_private_h
#define HEADER_fd_src_disco_bundle_fd_bundle_tile_private_h

#include "fd_bundle_auth.h"
#include "../stem/fd_stem.h"
#include "../keyguard/fd_keyswitch.h"
#include "../keyguard/fd_keyguard_client.h"
#include "../../waltz/grpc/fd_grpc_client.h"

#if !FD_HAS_OPENSSL
#error "The bundle tile requires OpenSSL"
#endif

#include <openssl/ssl.h> /* SSL_CTX */

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
  ulong decode_fail_cnt;
};

typedef struct fd_bundle_metrics fd_bundle_metrics_t;

/* fd_bundle_tile_t is the context object provided to callbacks from the
   mux tile, and contains all state needed to progress the tile. */

struct fd_bundle_tile {
  /* Key switch */
  fd_keyswitch_t * keyswitch;
  uint             identity_switched : 1;
  uchar            identity_public_key[ 32UL ];

  /* Key guard */
  fd_keyguard_client_t keyguard_client[1];

  /* OpenSSL */
  SSL_CTX * ssl_ctx;
  SSL *     ssl;
  uint      skip_cert_verify : 1;

  /* Config */
  char   server_fqdn[ 256 ]; /* cstr */
  ulong  server_fqdn_len;
  uint   server_ip4_addr;
  ushort server_tcp_port;

  /* TCP socket */
  int tcp_sock;

  /* gRPC client */
  void *                   grpc_client_mem;
  fd_grpc_client_t *       grpc_client;
  fd_grpc_client_metrics_t grpc_metrics[1];

  /* Bundle authenticator */
  fd_bundle_auther_t auther;

  /* Bundle block builder info */
  uchar builder_pubkey[ 32 ];
  uchar builder_commission;
  uchar builder_info_avail : 1;

  /* Bundle state */
  ulong bundle_seq;
  ulong bundle_txn_cnt;

  /* Stem publish */
  fd_stem_context_t * stem;
  fd_bundle_out_ctx_t verify_out;
  fd_bundle_out_ctx_t plugin_out;

  /* App metrics */
  fd_bundle_metrics_t metrics;
};

typedef struct fd_bundle_tile fd_bundle_tile_t;

/* Define 'request_ctx' IDs to identify different types of gRPC calls */

#define FD_BUNDLE_CLIENT_REQ_Bundle_SubscribePackets            4
#define FD_BUNDLE_CLIENT_REQ_Bundle_SubscribeBundles            5
#define FD_BUNDLE_CLIENT_REQ_Bundle_GetBlockBuilderFeeInfo      6

#define FD_BUNDLE_CLIENT_REQ_Shredstream_SendHeartbeat          7

FD_PROTOTYPES_BEGIN

/* fd_bundle_client_grpc_callbacks provides callbacks for grpc_client. */

extern fd_grpc_client_callbacks_t fd_bundle_client_grpc_callbacks;

/* fd_bundle_client_step is an all-in-one routine to drive client logic.
   As long as the tile calls this periodically, the client will
   reconnect to the bundle server, authenticate, and subscribe to
   packets and bundles. */

void
fd_bundle_client_step( fd_bundle_tile_t * bundle );

/* fd_bundle_client_grpc_rx_msg is called by grpc_client when a gRPC
   message arrives (unary or server-streaming response). */

void
fd_bundle_client_grpc_rx_msg(
    void *       app_ctx,      /* (fd_bundle_tile_t *) */
    void const * protobuf,
    ulong        protobuf_sz,
    ulong        request_ctx   /* FD_BUNDLE_CLIENT_REQ_{...} */
);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_bundle_fd_bundle_tile_private_h */
