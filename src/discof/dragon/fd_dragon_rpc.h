#ifndef HEADER_fd_src_discof_dragon_fd_dragon_rpc_h
#define HEADER_fd_src_discof_dragon_fd_dragon_rpc_h

/* fd_dragon_rpc.h serves the Yellowstone Dragon's Mouth API (the
   geyser.Geyser service) on top of fd_grpc_server.

   The layer owns everything that is specific to the API: routing on
   :path, the x-token shared secret, the protobuf encoding of requests
   and responses, per-stream subscription state, and the gRPC statuses
   and messages that a yellowstone client expects.  It knows nothing
   about stem, links or the waker, so a test drives it over the
   server's direct (in memory) transport.

   fd_grpc_server owns the sockets; a tile that puts those sockets in
   its own epoll set installs the conn_open / conn_close hooks of
   fd_dragon_rpc_params_t.

   The layer is a consumer of the geyser core: the core turns replay's
   notifications into the callbacks of fd_geyser_api.h, and this layer
   turns those into what a subscriber asked for, plus the small store
   the unary calls answer from (block metas and blockhash statuses,
   yellowstone's BlockMetaStorage).

   Call order for an owner:

     fd_dragon_rpc_new / _join
     fd_grpc_server_new( ..., fd_dragon_rpc_callbacks(), rpc )
     fd_geyser_core_register( core, fd_dragon_rpc_consumer( rpc, c ) )
     per loop: fd_dragon_rpc_service( rpc, now )  timers, created_at
               fd_grpc_server_poll( server, 0 )   socket work */

#include "fd_dragon_session.h"
#include "fd_dragon_buf.h"
#include "fd_dragon_tile.h"
#include "fd_geyser_core.h"
#include "../../waltz/grpc/fd_grpc_server.h"

#define FD_DRAGON_RPC_ALIGN (128UL)

/* FD_DRAGON_RPC_TOKEN_MAX bounds the configured x_token.
   FD_DRAGON_RPC_VERSION_MAX bounds the GetVersion JSON document.
   FD_DRAGON_CLIENT_MAX bounds [tiles.dragon.max_clients]. */

#define FD_DRAGON_RPC_TOKEN_MAX   (256UL)
#define FD_DRAGON_RPC_VERSION_MAX (640UL)
#define FD_DRAGON_CLIENT_MAX       (64UL)

/* Methods of the Geyser service, in the order of geyser.proto,
   followed by the standard health service of health.proto.
   FD_DRAGON_METHOD_UNKNOWN is any other :path. */

#define FD_DRAGON_METHOD_UNKNOWN               (0)
#define FD_DRAGON_METHOD_SUBSCRIBE             (1)
#define FD_DRAGON_METHOD_SUBSCRIBE_DESHRED     (2)
#define FD_DRAGON_METHOD_SUBSCRIBE_GOSSIP      (3)
#define FD_DRAGON_METHOD_SUBSCRIBE_REPLAY_INFO (4)
#define FD_DRAGON_METHOD_PING                  (5)
#define FD_DRAGON_METHOD_GET_LATEST_BLOCKHASH  (6)
#define FD_DRAGON_METHOD_GET_BLOCK_HEIGHT      (7)
#define FD_DRAGON_METHOD_GET_SLOT              (8)
#define FD_DRAGON_METHOD_IS_BLOCKHASH_VALID    (9)
#define FD_DRAGON_METHOD_GET_VERSION          (10)
#define FD_DRAGON_METHOD_HEALTH_CHECK         (11)
#define FD_DRAGON_METHOD_HEALTH_WATCH         (12)
#define FD_DRAGON_METHOD_CNT                  (13)

/* FD_DRAGON_PROTO_VERSION is the version of the yellowstone protocol
   definitions this server implements, reported by GetVersion. */

#define FD_DRAGON_PROTO_VERSION "13.0.0-rc3"

struct fd_dragon_rpc;
typedef struct fd_dragon_rpc fd_dragon_rpc_t;

struct fd_dragon_rpc_params {
  /* stream_max is the number of concurrent calls the server can have,
     which is max_conn_cnt*max_stream_cnt of the server params.  A call
     occupies one client slot, and a deferred subscriber is a bit of a
     mask over those slots, so stream_max is at most
     FD_DRAGON_CLIENT_MAX. */
  ulong stream_max;

  /* finalized enables serving the commitment levels above processed
     and whole blocks, from the buffer.  With it off, a subscription
     that asks for one is rejected, and nothing is buffered. */
  int finalized;

  /* filter_at is where the subscription filters of the buffered
     levels run (FD_DRAGON_FILTER_AT_*).  At ingest, an entry is
     buffered only if some subscriber matched it, with the masks of
     who did, and an account's data is buffered as the union of the
     slices they asked for; a subscriber then sees the banks created
     after its filters were installed.  At send, every entry is
     buffered whole and the filters run when the bank is served, so a
     subscriber sees every bank the buffer holds. */
  int filter_at;

  /* The ring the buffer writes to, joined by the owner: an mcache of
     buf_depth entries, a dcache, and the address its chunk indexes
     are relative to.  bank_max is how many banks the buffer keeps
     state for at once.  All ignored when finalized is off; the
     footprint depends on buf_depth and bank_max only. */
  fd_frag_meta_t * buf_mcache;
  uchar *          buf_dcache;
  void *           buf_base;
  ulong            buf_depth;
  ulong            bank_max;

  /* msg_max_bytes bounds one assembled update that carries an account
     or a block, which are the only two messages whose size is not
     bounded by the schema of a record.  A message that does not fit is
     not sent, and neither could it be: the bound belongs at the
     capacity of a client's send queue, which is what the owner passes
     here. */
  ulong msg_max_bytes;

  /* ping_interval_nanos is the cadence of the server side
     SubscribeUpdatePing on every Subscribe stream.  0 disables it. */
  long ping_interval_nanos;

  /* filter_limits bounds what one SubscribeRequest may ask for.  NULL
     is the most permissive set of limits the server can serve. */
  fd_dragon_filter_limits_t const * filter_limits;

  /* cuckoo_bytes is the bucket arena that the cuckoo filters of one
     subscription share, which is one of these per concurrent call plus
     one to decode into.  0 refuses every request carrying a cuckoo
     filter. */
  ulong cuckoo_bytes;

  /* x_token, if non-empty, is the value every request must carry in
     the x-token metadata header. */
  char const * x_token;

  /* conn_open and conn_close, if non-NULL, report the socket of a
     connection the server accepted and of one it is about to close.
     conn_close is called after the socket was closed. */
  void * conn_ctx;
  void (* conn_open )( void * ctx, int sock );
  void (* conn_close)( void * ctx, int sock );
};

typedef struct fd_dragon_rpc_params fd_dragon_rpc_params_t;

struct fd_dragon_rpc_metrics {
  ulong request_cnt[ FD_DRAGON_METHOD_CNT ];
  ulong conn_cnt;               /* connections currently open */
  ulong stream_cnt;             /* calls currently open */
  ulong subscription_cnt;       /* Subscribe streams currently open */
  ulong auth_fail_cnt;
  ulong unimplemented_cnt;
  ulong filter_reject_cnt;
  ulong from_slot_reject_cnt;
  ulong stream_full_cnt;        /* calls refused for lack of a stream slot */
  ulong update_sent_cnt;        /* SubscribeUpdate messages sent */
  ulong server_ping_cnt;
  ulong pong_cnt;
  ulong lagged_close_cnt;
  ulong lagged_reap_cnt;
  ulong decode_fail_cnt;
  ulong slot_update_cnt;      /* SubscribeUpdateSlot messages sent */
  ulong block_meta_cnt;       /* block metas stored */
  ulong blockhash_cnt;        /* blockhash statuses retained right now */
  ulong block_meta_tracked;   /* block metas retained right now */

  ulong txn_update_cnt;       /* SubscribeUpdateTransaction messages sent */
  ulong txn_status_cnt;       /* SubscribeUpdateTransactionStatus messages sent */
  ulong block_meta_sent_cnt;  /* SubscribeUpdateBlockMeta messages sent */
  ulong txn_byte_cnt;         /* bytes of transaction messages sent */
  ulong status_byte_cnt;      /* bytes of transaction status messages sent */
  ulong block_meta_byte_cnt;  /* bytes of block meta messages sent */
  ulong slot_byte_cnt;        /* bytes of slot status messages sent */
  ulong cuckoo_filter_cnt;    /* cuckoo account filters installed by subscriptions */
  ulong meta_fail_cnt;        /* records whose meta could not be built */
  ulong encode_fail_cnt;      /* messages that did not fit the encoder's buffer */
  ulong deferred_reject_cnt;  /* subscriptions refused a commitment this server does not serve */
  ulong degrade_cnt;          /* banks given up on at the buffered levels */
  ulong content_lost_cnt;     /* banks whose content could not be served at a buffered level */
  ulong content_lost_close_cnt; /* subscriptions closed because a bank's content was lost */

  ulong acct_update_cnt;      /* SubscribeUpdateAccount messages sent */
  ulong acct_byte_cnt;        /* bytes of those messages */
  ulong acct_skipped_cnt;     /* account writes not served at processed for want of their data */
  ulong acct_entry_cnt;       /* account writes buffered */
  ulong acct_partial_cnt;     /* account updates not sent because the buffer holds less of the data than the subscriber asked for */
  ulong block_sent_cnt;       /* SubscribeUpdateBlock messages sent */
  ulong block_byte_cnt;       /* bytes of those messages */
  ulong acct_oversize_cnt;    /* account updates larger than one message may be */
  ulong block_oversize_cnt;   /* blocks larger than one message may be */
};

typedef struct fd_dragon_rpc_metrics fd_dragon_rpc_metrics_t;

FD_PROTOTYPES_BEGIN

/* fd_dragon_rpc_{align,footprint} describe the memory backing the
   layer.  The footprint is the object, one session per concurrent
   call, and the buffer's own state; the ring the buffer writes to is
   the owner's:

     footprint = sizeof(fd_dragon_rpc_t)
               + stream_max*sizeof(fd_dragon_session_t)
               + (stream_max+1)*cuckoo_bytes
               + msg_max_bytes for assembling an account update
               + FD_DRAGON_BLOCK_OPEN_MAX*msg_max_bytes for the blocks
                 of one delivery pass, with finalized
               + the buffer's bank and deduplication tables, with
                 finalized

   The footprint is 0 for parameters the layer cannot serve, which is a
   stream_max of 0 or above FD_DRAGON_CLIENT_MAX, or finalized with a
   depth that is not a power of two or no banks. */

FD_FN_CONST ulong
fd_dragon_rpc_align( void );

ulong
fd_dragon_rpc_footprint( fd_dragon_rpc_params_t const * params );

/* fd_dragon_rpc_new formats a memory region.  Fills in the GetVersion
   document from the build's version, commit and compiler and from the
   host name, so it must run before the sandbox blocks those lookups.
   Returns mem on success, or NULL on failure (logs warning). */

void *
fd_dragon_rpc_new( void *                         mem,
                   fd_dragon_rpc_params_t const * params );

fd_dragon_rpc_t *
fd_dragon_rpc_join( void * mem );

/* fd_dragon_rpc_callbacks returns the handler table to pass to
   fd_grpc_server_new, whose ctx must be the fd_dragon_rpc_t. */

FD_FN_CONST fd_grpc_server_callbacks_t const *
fd_dragon_rpc_callbacks( void );

/* fd_dragon_rpc_service advances the layer's wallclock, which stamps
   created_at on every update, and sends the periodic server ping on
   each Subscribe stream.  Safe to call as often as the owner likes. */

void
fd_dragon_rpc_service( fd_dragon_rpc_t * rpc,
                       long              now_nanos );

/* fd_dragon_rpc_consumer fills out with the layer's registration with
   the geyser core and returns it.  The layer keeps the core, which
   builds the meta object of a transaction on request. */

fd_geyser_consumer_t *
fd_dragon_rpc_consumer( fd_dragon_rpc_t *      rpc,
                        fd_geyser_core_t *     core,
                        fd_geyser_consumer_t * out );

/* fd_dragon_rpc_buf returns the buffer, or NULL if finalized is
   off. */

FD_FN_PURE fd_dragon_buf_t *
fd_dragon_rpc_buf( fd_dragon_rpc_t * rpc );

/* fd_dragon_rpc_is_ready returns 1 once a bank is known at every
   commitment level, which is when a server with delay_startup set
   starts serving. */

FD_FN_PURE int
fd_dragon_rpc_is_ready( fd_dragon_rpc_t const * rpc );

/* fd_dragon_rpc_set_serving is what the health service of
   grpc.health.v1 reports: 1 once the owner serves requests, 0 before
   that and once it starts shutting down.  A change is sent to every
   Watch stream that is open and does not already have it.  The
   starting value is 0. */

void
fd_dragon_rpc_set_serving( fd_dragon_rpc_t * rpc,
                           int               serving );

/* fd_dragon_rpc_version_json returns the NUL terminated GetVersion
   document. */

FD_FN_PURE char const *
fd_dragon_rpc_version_json( fd_dragon_rpc_t const * rpc );

FD_FN_PURE fd_dragon_rpc_metrics_t const *
fd_dragon_rpc_metrics( fd_dragon_rpc_t const * rpc );

/* fd_dragon_rpc_ref_hi_drain takes up to out_max pending segment high
   water marks of calls that have ended since the last drain, and
   returns how many it wrote.  The layer keeps the last
   FD_DRAGON_CLIENT_MAX of them. */

ulong
fd_dragon_rpc_ref_hi_drain( fd_dragon_rpc_t * rpc,
                            ulong *           out,
                            ulong             out_max );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_dragon_fd_dragon_rpc_h */
