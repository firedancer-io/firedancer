#ifndef HEADER_fd_src_waltz_quic_fd_quic_h
#define HEADER_fd_src_waltz_quic_fd_quic_h

/* fd_quic_t is a partial implementation of QUIC -- an encrypted,
   multiplexing transport layer network protocol.

   For now, IPv4 over Ethernet (EN10MB) flows are supported.

   This API is non-blocking and single-threaded.  Any requests to the
   peer (such as "open a connection") are queued and processed on RX
   or service call.  The user is notified of events via callbacks.
   The user must further ensure that RX (via fd_aio_t) is dispatched
   only from the thread with the active join to the target fd_quic_t.

   Scaling is achieved via fd_quic_t instances and steering of RX flows.
   For example, incoming RX that exceeds the throughput of one fd_quic_t
   may be load balanced based on QUIC dest conn ID, or UDP src flow ID.

   This implementation aims to be compliant to RFC 9000 and RFC 9001:
   - https://datatracker.ietf.org/doc/html/rfc9000
   - https://datatracker.ietf.org/doc/html/rfc9001

   ### Memory Management

   fd_quic is entirely pre-allocated.  Currently, a QUIC object reserves
   space for a number of connection slots, with uniform stream,
   reassembly, and ACK buffers.

   ### Memory Layout

   fd_quic_t is the publicly exported memory layout of a QUIC object.
   The private memory region of a QUIC object extends beyond the end of
   this struct.  fd_quic_t is not intended to be allocated directly,
   refer to the below for details.

   ### Lifecycle

   The below state diagram shows the lifecycle of an fd_quic_t.

      ┌───────────┐  new   ┌───────────┐ join  ┌──────────┐
      │           ├───────►│           ├──────►│          │
      │ allocated │        │ formatted │       │  joined  │
      │           │◄───────┤           │◄──────┤          │
      └───────────┘ delete └───────────┘ leave └───▲───┬──┘
                                                   │   │ set config
                                                   │   │ set callbacks
                                              fini │   │ init
                                                ┌──┴───▼──┐
                                            ┌───│         │
                                    service │   │  ready  │
                                            └──►│         │
                                                └─────────┘

   ### Lifecycle: Allocation & Formatting

   A QUIC object resides in a contiguous pre-allocated memory region.
   (Usually, in a Firedancer workspace)  The footprint and internal
   layout depends on the pre-configured fd_quic_limits_t parameters.
   These limits are constant throughout the lifetime of an fd_quic_t.

   Use fd_quic_{align,footprint} to determine size and alignment of the
   memory region to be used.  Use fd_quic_new to format such a memory
   region and to obtain an opaque handle.  In the formatted state, the
   fd_quic_t is position-independent (may be mapped at different virtual
   addresses).  This is useful for separating allocation and runtime use
   into different steps.

   ### Lifecycle: Joining

   Given an opaque handle, fd_quic_join runs basic coherence checks and
   returns a typed pointer to the object.  The object is not modified
   by this operation.  Each object may have multiple active joins, but
   only one of them may write.  (Typically, a single join is used for
   service, and secondary joins for read-only monitoring)

   ### Lifecycle: Usage

   fd_quic_init initializes an fd_quic_t for use.  On success, the QUIC
   becomes ready to serve from the thread that init was called from (it
   is invalid to service QUIC from another thread). */

/* TODO provide fd_quic on non-hosted targets */

#include "fd_quic_common.h"
#include "fd_quic_enum.h"

#include "../aio/fd_aio.h"
#include "../tls/fd_tls.h"
#include "../../util/hist/fd_histf.h"

/* FD_QUIC_API marks public API declarations.  No-op for now. */
#define FD_QUIC_API

/* Forward declarations */

struct fd_quic_conn;
typedef struct fd_quic_conn fd_quic_conn_t;

struct fd_quic_stream;
typedef struct fd_quic_stream fd_quic_stream_t;

struct fd_quic_state_private;
typedef struct fd_quic_state_private fd_quic_state_t;

/* fd_quic_limits_t defines the memory layout of an fd_quic_t object.
   Limits are immutable and valid for the lifetime of an fd_quic_t
   (i.e. outlasts joins, until fd_quic_delete) */

struct __attribute__((aligned(16UL))) fd_quic_limits {
  ulong  conn_cnt;                  /* instance-wide, max concurrent conn count       */
  ulong  handshake_cnt;             /* instance-wide, max concurrent handshake count  */
  ulong  log_depth;                 /* instance-wide, depth of shm log cache          */

  ulong  conn_id_cnt;                 /* per-conn, max conn ID count (min 4UL)          */
  ulong  stream_id_cnt;               /* per-conn, max concurrent stream ID count       */
  ulong  inflight_frame_cnt;          /* instance-wide, total max inflight frame count  */
  ulong  min_inflight_frame_cnt_conn; /* per-conn, min inflight frame count             */

  ulong  tx_buf_sz;                 /* per-stream, tx buf sz in bytes                 */
  /* the user consumes rx directly from the network buffer */

  ulong  stream_pool_cnt;           /* instance-wide, number of streams in stream pool */
};
typedef struct fd_quic_limits fd_quic_limits_t;

/* fd_quic_layout_t is an offset table describing the memory layout of
   an fd_quic_t object.  It is deived from fd_quic_limits_t. */

struct fd_quic_layout {
  ulong meta_sz;           /* size of this struct */
  ulong log_off;           /* offset to quic_log */
  ulong conns_off;         /* offset of connection mem region  */
  ulong conn_footprint;    /* sizeof a conn                    */
  ulong conn_map_off;      /* offset of conn map mem region    */
  int   lg_slot_cnt;       /* see conn_map_new                 */
  ulong hs_pool_off;       /* offset of the handshake pool     */
  ulong stream_pool_off;   /* offset of the stream pool        */
  ulong pkt_meta_pool_off; /* offset of the pkt_meta pool      */
};

typedef struct fd_quic_layout fd_quic_layout_t;

/* fd_quic_now_t is the clock source used internally by quic for
   scheduling events.  context is an arbitrary pointer earlier provided
   by the caller during config. */

typedef ulong
(*fd_quic_now_t)( void * context );

/* fd_quic_config_t defines mutable config of an fd_quic_t.  The config is
   immutable during an active join. */

struct __attribute__((aligned(16UL))) fd_quic_config {
  /* Used by tracing/logging code */
#define FD_QUIC_CONFIG_ENUM_LIST_role(X,...) \
  X( FD_QUIC_ROLE_CLIENT, "ROLE_CLIENT" )    \
  X( FD_QUIC_ROLE_SERVER, "ROLE_SERVER" )

#define FD_QUIC_CONFIG_LIST(X,...) \
  X( role,                        "%d",     enum,  "enum",         __VA_ARGS__ ) \
  X( retry,                       "%d",     bool,  "bool",         __VA_ARGS__ ) \
  X( tick_per_us,                 "%f",     units, "ticks per ms", __VA_ARGS__ ) \
  X( idle_timeout,                "%lu",    units, "ns",           __VA_ARGS__ ) \
  X( keep_alive,                  "%d",     bool,  "bool",         __VA_ARGS__ ) \
  X( ack_delay,                   "%lu",    units, "ns",           __VA_ARGS__ ) \
  X( ack_threshold,               "%lu",    units, "bytes",        __VA_ARGS__ ) \
  X( retry_ttl,                   "%lu",    units, "ns",           __VA_ARGS__ ) \
  X( tls_hs_ttl,                  "%lu",    units, "ns",           __VA_ARGS__ ) \
  X( identity_public_key,         "%x",     hex32, "",             __VA_ARGS__ ) \
  X( sign,                        "%p",     ptr,   "",             __VA_ARGS__ ) \
  X( sign_ctx,                    "%p",     ptr,   "",             __VA_ARGS__ ) \
  X( keylog_file,                 "%s",     value, "",             __VA_ARGS__ ) \
  X( initial_rx_max_stream_data,  "%lu",    units, "bytes",        __VA_ARGS__ ) \
  X( net.dscp,                    "0x%02x", value, "",             __VA_ARGS__ )

  /* Protocol config ***************************************/

  /* role: one of FD_QUIC_ROLE_{CLIENT,SERVER} */
  int role;

  /* retry: whether address validation using retry packets is enabled (RFC 9000, Section 8.1.2) */
  int retry;

  /* tick_per_us: clock ticks per microsecond */
  double tick_per_us;

  /* idle_timeout: Upper bound on conn idle timeout.
     Also sent to peer via max_idle_timeout transport param.
     If the peer specifies a lower idle timeout, that is used instead. */
  ulong idle_timeout;
# define FD_QUIC_DEFAULT_IDLE_TIMEOUT (ulong)(1e9) /* 1s */

/* keep_alive
 * whether the fd_quic should use QUIC PING frames to keep connections alive
 * Set to 1 to keep connections alive
 * Set to 0 to allow connections to close on idle
 * default is 0 */
  int keep_alive;

  /* ack_delay: median delay on outgoing ACKs.  Greater delays allow
     fd_quic to coalesce packet ACKs. */
  ulong ack_delay;
# define FD_QUIC_DEFAULT_ACK_DELAY (ulong)(50e6) /* 50ms */

  /* ack_threshold: immediately send an ACK when the number of
     unacknowledged stream bytes exceeds this value. */
  ulong ack_threshold;
# define FD_QUIC_DEFAULT_ACK_THRESHOLD (65536UL) /* 64 KiB */

  /* retry_ttl: time-to-live for retry tokens */
  ulong retry_ttl;
# define FD_QUIC_DEFAULT_RETRY_TTL (ulong)(1e9) /* 1s */

  /* hs_ttl: time-to-live for tls_hs */
  ulong tls_hs_ttl;
# define FD_QUIC_DEFAULT_TLS_HS_TTL (ulong)(3e9) /* 3s */

  /* TLS config ********************************************/

  /* identity_key: Ed25519 public key of node identity */
  uchar identity_public_key[ 32 ];

  /* Callback for signing TLS 1.3 certificate verify payload */
  fd_tls_sign_fn_t sign;
  void *           sign_ctx;

# define FD_QUIC_PATH_LEN 1023UL
  char keylog_file[ FD_QUIC_PATH_LEN+1UL ];

  ulong initial_rx_max_stream_data; /* per-stream, rx buf sz in bytes, set by the user. */

  /* Network config ****************************************/

  struct { /* Internet config */
    /* dscp: Differentiated services code point.
       Set on all outgoing IPv4 packets. */
    uchar dscp;
  } net;
};

/* Callback API *******************************************************/

/* Note: QUIC library invokes callbacks during RX or service.  Callback
   may only invoke fd_quic API methods labelled CB-safe.  Callbacks are
   not re-entrant. */

/* fd_quic_cb_conn_new_t: server received a new conn and completed
   handshakes. */
typedef void
(* fd_quic_cb_conn_new_t)( fd_quic_conn_t * conn,
                           void *           quic_ctx );

/* fd_quic_cb_conn_handshake_complete_t: client completed a handshake
   of a conn it created. */
typedef void
(* fd_quic_cb_conn_handshake_complete_t)( fd_quic_conn_t * conn,
                                          void *           quic_ctx );

/* fd_quic_cb_conn_final_t: Conn termination notification.  The conn
   object is freed immediately after returning.  User should destroy any
   remaining references to conn in this callback. */
typedef void
(* fd_quic_cb_conn_final_t)( fd_quic_conn_t * conn,
                             void *           quic_ctx );

/* fd_quic_cb_stream_notify_t signals a notable stream event.
   stream_ctx object is the user-provided stream context set in the new
   callback.

   TODO will only one notify max be served?
   TODO will stream be deallocated immediately after callback?

   notify_type is one of FD_QUIC_NOTIFY_{...} */
typedef void
(* fd_quic_cb_stream_notify_t)( fd_quic_stream_t * stream,
                                void *             stream_ctx,
                                int                notify_type );

typedef int
(* fd_quic_cb_stream_rx_t)( fd_quic_conn_t * conn,
                            ulong            stream_id,
                            ulong            offset,
                            uchar const *    data,
                            ulong            data_sz,
                            int              fin );

/* fd_quic_cb_tls_keylog_t is called when a new encryption secret
   becomes available.  line is a cstr containing the secret in NSS key
   log format (intended for tests only). */

typedef void
(* fd_quic_cb_tls_keylog_t)( void *       quic_ctx,
                             char const * line );

/* fd_quic_callbacks_t defines the set of user-provided callbacks that
   are invoked by the QUIC library.  Resets on leave. */

struct fd_quic_callbacks {
  /* Function pointers to user callbacks */

  void * quic_ctx; /* user-provided context pointer
                      for instance-wide callbacks */

  fd_quic_cb_conn_new_t                conn_new;          /* non-NULL, with quic_ctx   */
  fd_quic_cb_conn_handshake_complete_t conn_hs_complete;  /* non-NULL, with quic_ctx   */
  fd_quic_cb_conn_final_t              conn_final;        /* non-NULL, with quic_ctx   */
  fd_quic_cb_stream_notify_t           stream_notify;     /* non-NULL, with stream_ctx */
  fd_quic_cb_stream_rx_t               stream_rx;         /* non-NULL, with stream_ctx */
  fd_quic_cb_tls_keylog_t              tls_keylog;        /* nullable, with quic_ctx   */

  /* Clock source */

  fd_quic_now_t now;     /* non-NULL */
  void *        now_ctx; /* user-provided context pointer for now_fn calls */

};
typedef struct fd_quic_callbacks fd_quic_callbacks_t;

/* fd_quic metrics ****************************************************/

/* TODO: evaluate performance impact of metrics */

union fd_quic_metrics {
  struct {
    /* Network metrics */
    ulong net_rx_pkt_cnt;  /* number of IP packets received */
    ulong net_rx_byte_cnt; /* total bytes received (including IP, UDP, QUIC headers) */
    ulong net_tx_pkt_cnt;  /* number of IP packets sent */
    ulong net_tx_byte_cnt; /* total bytes sent */
    ulong retry_tx_cnt;    /* number of Retry packets sent */

    /* Conn metrics */
    ulong conn_alloc_cnt;          /* number of conns currently allocated */
    ulong conn_created_cnt;        /* number of conns created */
    ulong conn_closed_cnt;         /* number of conns gracefully closed */
    ulong conn_aborted_cnt;        /* number of conns aborted */
    ulong conn_timeout_cnt;        /* number of conns timed out */
    ulong conn_retry_cnt;          /* number of conns established with retry */
    ulong conn_err_no_slots_cnt;   /* number of conns that failed to create due to lack of slots */
    ulong conn_err_retry_fail_cnt; /* number of conns that failed during retry (e.g. invalid token) */
    ulong conn_state_cnt[ 8 ];     /* current number of conns in each state */

    /* Packet metrics */
    ulong pkt_net_hdr_err_cnt;      /* number of packets dropped due to weird IPv4/UDP headers */
    ulong pkt_quic_hdr_err_cnt;     /* number of packets dropped due to weird QUIC header */
    ulong pkt_undersz_cnt;          /* number of QUIC packets dropped due to being too small */
    ulong pkt_oversz_cnt;           /* number of QUIC packets dropped due to being too large */
    ulong pkt_decrypt_fail_cnt[4];  /* number of packets that failed decryption due to auth tag */
    ulong pkt_no_key_cnt[4];        /* number of packets that failed decryption due to missing key */
    ulong pkt_no_conn_cnt;          /* number of packets with unknown conn ID (excl. Initial) */
    ulong frame_tx_alloc_cnt[3];    /* number of pkt_meta alloc successes, fails for empty pool, fails at conn max */
    ulong pkt_verneg_cnt;           /* number of QUIC version negotiation packets or packets with wrong version */
    ulong pkt_retransmissions_cnt;  /* number of pkt_meta retries */
    ulong initial_token_len_cnt[3]; /* number of Initial packets grouped by token length */

    /* Frame metrics */
    ulong frame_rx_cnt[ 22 ];      /* number of frames received (indexed by implementation-defined IDs) */
    ulong frame_rx_err_cnt;        /* number of frames failed */

    /* Handshake metrics */
    ulong hs_created_cnt;          /* number of handshake flows created */
    ulong hs_err_alloc_fail_cnt;   /* number of handshakes dropped due to alloc fail */
    ulong hs_evicted_cnt;          /* number of handshakes evicted */

    /* Stream metrics */
    ulong stream_opened_cnt;        /* number of streams opened */
    ulong stream_closed_cnt[5];     /* indexed by FD_QUIC_STREAM_NOTIFY_{...} */
    ulong stream_active_cnt;        /* number of active streams */
    ulong stream_rx_event_cnt;      /* number of stream RX events */
    ulong stream_rx_byte_cnt;       /* total stream payload bytes received */

    /* ACK metrics */
    ulong ack_tx[ 5 ];

    /* Performance metrics */
    fd_histf_t service_duration[ 1 ]; /* time spent in service */
    fd_histf_t receive_duration[ 1 ]; /* time spent in process_packet calls */
  };
};
typedef union fd_quic_metrics fd_quic_metrics_t;

/* fd_quic_t memory layout ********************************************/

struct fd_quic {
  ulong magic;   /* ==FD_QUIC_MAGIC */

  fd_quic_layout_t    layout;  /* position-independent, persistent,    read only */
  fd_quic_limits_t    limits;  /* position-independent, persistent,    read only */
  fd_quic_config_t    config;  /* position-independent, persistent,    writable pre init */
  fd_quic_callbacks_t cb;      /* position-dependent,   reset on join, writable pre init  */
  fd_quic_metrics_t   metrics; /* position-independent, persistent,    read only */

  fd_aio_t aio_rx; /* local AIO */
  fd_aio_t aio_tx; /* remote AIO */

  /* ... private variable-length structures follow ... */
};

FD_PROTOTYPES_BEGIN

/* Object lifecycle ***************************************************/

/* fd_quic_{align,footprint} return the required alignment and footprint
   of a memory region suitable for use as an fd_quic_t.  align returns
   FD_QUIC_ALIGN.  limits is a temporary reference to the requested

   On failure, footprint will silently return 0 (and thus can be used by
   the caller to validate fd_quic_new params) */

FD_QUIC_API FD_FN_CONST ulong
fd_quic_align( void );

FD_QUIC_API ulong
fd_quic_footprint( fd_quic_limits_t const * limits );

/* fd_quic_new formats an unused memory region for use as a QUIC client
   or server.  mem is a non-NULL pointer to this region in the local
   address with the required footprint and alignment.  limits is a
   temporary reference, identical to the one given to fd_quic_footprint
   used to figure out the required footprint. */

FD_QUIC_API void *
fd_quic_new( void *                   mem,
             fd_quic_limits_t const * limits );

/* fd_quic_join joins the caller to the fd_quic.  shquic points to the
   first byte of the memory region backing the QUIC in the caller's
   address space.

   Returns a pointer in the local address space to the public fd_quic_t
   region on success (do not assume this to be just a cast of shquic)
   and NULL on failure (logs details).  Reasons for failure are that
   shquic is obviously not a pointer to a correctly formatted QUIC
   object.  Every successful join should have a matching leave.  The
   lifetime of the join is until the matching leave or the thread group
   is terminated. */

FD_QUIC_API fd_quic_t *
fd_quic_join( void * shquic );

/* fd_quic_leave leaves a current local join and frees all dynamically
   managed resources (heap allocs, OS handles).  Returns the given quic
   on success and NULL on failure (logs details).  Reasons for failure
   include quic is NULL or no active join */

FD_QUIC_API void *
fd_quic_leave( fd_quic_t * quic );

/* fd_quic_delete unformats a memory region used as an fd_quic_t.
   Assumes nobody is joined to the region.  Returns the given quic
   pointer on success and NULL if used obviously in error (e.g. quic is
   obviously not an fd_quic_t ... logs details).  The ownership of the
   memory region is transferred ot the caller. */

FD_QUIC_API void *
fd_quic_delete( fd_quic_t * quic );

/* Configuration ******************************************************/

/* fd_quic_{limits,config}_from_env populates the given QUIC limits or
   config from command-line args and env vars.  If parg{c,v} are non-
   NULL, they are updated to strip the parsed args.  The last element of
   the *argv array must be NULL.  Returns given config on success and
   NULL on failure (logs details).  It is up to the caller to properly
   initialize the given limits/config. */

FD_QUIC_API fd_quic_limits_t *
fd_quic_limits_from_env( int  *   pargc,
                         char *** pargv,
                         fd_quic_limits_t * limits );

FD_QUIC_API fd_quic_config_t *
fd_quic_config_from_env( int  *   pargc,
                         char *** pargv,
                         fd_quic_config_t * config );

/* fd_quic_get_aio_net_rx returns this QUIC's aio base class.  Valid
   for lifetime of QUIC.  While pointer to aio can be obtained before
   init, calls to aio may only be dispatched by the thread with
   exclusive access to QUIC that owns it. */

FD_QUIC_API fd_aio_t const *
fd_quic_get_aio_net_rx( fd_quic_t * quic );

/* fd_quic_set_aio_net_tx sets the fd_aio_t used by the fd_quic_t to
   send tx data to the network driver.  Cleared on fini. */

FD_QUIC_API void
fd_quic_set_aio_net_tx( fd_quic_t *      quic,
                        fd_aio_t const * aio_tx );

/* fd_quic_set_clock sets the clock source.  Converts all timing values
   in the config to the new time scale. */

FD_QUIC_API void
fd_quic_set_clock( fd_quic_t *   quic,
                   fd_quic_now_t now_fn,
                   void *        now_ctx,
                   double        tick_per_us );

/* fd_quic_set_clock_tickcount sets fd_tickcount as the clock source. */

FD_QUIC_API void
fd_quic_set_clock_tickcount( fd_quic_t * quic );

/* Initialization *****************************************************/

/* fd_quic_init initializes the QUIC such that it is ready to serve.
   permits the calling thread exclusive access during which no other
   thread may write to the QUIC.  Exclusive rights get released when the
   thread exits or calls fd_quic_fini.

   Requires valid configuration and external objects (aio, callbacks).
   Returns given quic on success and NULL on failure (logs details).
   Performs various heap allocations and file system accesses such
   reading certs.  Reasons for failure include invalid config or
   fd_tls error. */

FD_QUIC_API fd_quic_t *
fd_quic_init( fd_quic_t * quic );

/* fd_quic_fini releases exclusive access over a QUIC.  Zero-initializes
   references to external objects (aio, callbacks).  Frees any heap
   allocs made by fd_quic_init.  Returns quic. */

FD_QUIC_API fd_quic_t *
fd_quic_fini( fd_quic_t * quic );

/* NOTE: Calling any of the below requires valid initialization from
   this thread group. */

/* Connection API *****************************************************/

/* fd_quic_connect initiates a new client connection to a remote QUIC
   server.  On success, returns a pointer to the conn object managed by
   QUIC.  On failure, returns NULL.  Reasons for failure include quic
   not a valid join or out of free conns.  Lifetime of returned conn is
   until conn_final callback.

   args
     dst_ip_addr   destination ip address
     dst_udp_port  destination port number */

FD_QUIC_API fd_quic_conn_t *
fd_quic_connect( fd_quic_t *  quic,  /* requires exclusive access */
                 uint         dst_ip_addr,
                 ushort       dst_udp_port,
                 uint         src_ip_addr,
                 ushort       src_udp_port );

/* fd_quic_conn_close asynchronously initiates a shutdown of the conn.
   The given reason code is returned to the peer via a CONNECTION_CLOSE
   frame, if possible.  Causes conn_final callback to be issued
   eventually. */

FD_QUIC_API void
fd_quic_conn_close( fd_quic_conn_t * conn,
                    uint             reason );

/* fd_quic_conn_let_die stops keeping a conn alive after
   'keep_alive_duration_ticks'. No-op if keep-alive is not configured.
   Safe to call on a connection in any state.

   If called multiple times on the same connection, only the latest
   call will stay in effect. However, it may not take effect if we
   already skipped a keep-alive due to a previous call. 'Undoing' a
   previous call can be done by passing ULONG_MAX.

   This function does NOT guarantee that the connection will be closed
   immediately after the given duration. Rather, it just disables keep-alive
   behavior after the given duration. */

FD_QUIC_API void
fd_quic_conn_let_die( fd_quic_conn_t * conn,
                      ulong            keep_alive_duration_ticks );

/* Service API ********************************************************/

/* fd_quic_get_next_wakeup returns the next requested service time.
   This is only intended for unit tests. */

FD_QUIC_API ulong
fd_quic_get_next_wakeup( fd_quic_t * quic );

/* fd_quic_service services the next QUIC connection, including stream
   transmit ops, ACK transmit, loss timeout, and idle timeout.   The
   user should call service at high frequency.  Returns 1 if the service
   call did any work, or 0 otherwise. */

FD_QUIC_API int
fd_quic_service( fd_quic_t * quic );

/* fd_quic_svc_validate checks for violations of service queue and free
   list invariants, such as cycles in linked lists.  Prints to warning/
   error log and exits the process if checks fail.  Intended for use in
   tests. */

void
fd_quic_svc_validate( fd_quic_t * quic );

/* Stream Send API ****************************************************/

/* fd_quic_conn_new_stream creates a new unidirectional stream on the
   given conn.  On success, returns the newly created stream.
   On failure, returns NULL.  Reasons for failure include invalid conn
   state or out of stream quota.

   The user does not own the returned pointer: its lifetime is managed
   by the connection. */

FD_QUIC_API fd_quic_stream_t *
fd_quic_conn_new_stream( fd_quic_conn_t * conn );

/* fd_quic_stream_send sends a chunk on a stream in order.

   Use fd_quic_conn_new_stream to create a new stream for sending
   or use the new stream callback to obtain a stream for replying.

   args
     stream         the stream to send on
     data           points to first byte of buffer (ignored if data_sz==0)
     data_sz        number of bytes to send
     fin            final: bool
                      set to indicate the stream is finalized by the last byte
                      in the batch
                      If the last buffer in the batch was rejected, the FIN
                        flag is not set, and may be applied in a future send
                        or via the fd_quic_stream_fin(...) function

   returns
       0   success
      <0   one of FD_QUIC_SEND_ERR_{INVAL_STREAM,INVAL_CONN,AGAIN} */
FD_QUIC_API int
fd_quic_stream_send( fd_quic_stream_t *  stream,
                     void const *        data,
                     ulong               data_sz,
                     int                 fin );

/* fd_quic_stream_fin: finish sending on a stream.  Called to signal
   no more data will be sent to self-to-peer flow of stream.  Peer may
   continue sending data on their side of the stream.  Caller should
   only call stream_fin once per stream, except when fin was already
   indicated via stream_send. */

FD_QUIC_API void
fd_quic_stream_fin( fd_quic_stream_t * stream );

FD_QUIC_API void
fd_quic_process_packet( fd_quic_t * quic,
                        uchar *     data,
                        ulong       data_sz );

uint
fd_quic_tx_buffered_raw( fd_quic_t * quic,
                         uchar **    tx_ptr_ptr,
                         uchar *     tx_buf,
                         ushort *    ipv4_id,
                         uint        dst_ipv4_addr,
                         ushort      dst_udp_port,
                         uint        src_ipv4_addr,
                         ushort      src_udp_port );

FD_PROTOTYPES_END

/* Convenience exports for consumers of API */
#include "fd_quic_conn.h"
#include "fd_quic_stream.h"

/* FD_DEBUG_MODE: set to enable debug-only code
   TODO move to util? */
#ifdef FD_DEBUG_MODE
#define FD_DEBUG(...) __VA_ARGS__
#else
#define FD_DEBUG(...)
#endif

#endif /* HEADER_fd_src_waltz_quic_fd_quic_h */
