#ifndef HEADER_fd_src_tango_quic_fd_quic_h
#define HEADER_fd_src_tango_quic_fd_quic_h

/* fd_quic_t is an implementation of QUIC -- an encrypted, multiplexing
   transport layer network protocol.

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

#include "../aio/fd_aio.h"
#include "../tls/fd_tls.h"
#include "../../util/fd_util.h"

/* FD_QUIC_API marks public API declarations.  No-op for now. */
#define FD_QUIC_API

/* FD_QUIC_{SUCCESS,FAILED} are used for error return codes. */
#define FD_QUIC_SUCCESS (0)
#define FD_QUIC_FAILED  (1)

/* FD_QUIC_TYPE_{UNI,BI}DIR indicate stream type. */
#define FD_QUIC_TYPE_BIDIR  (0)
#define FD_QUIC_TYPE_UNIDIR (1)

/* FD_QUIC_ALIGN specifies the alignment needed for an fd_quic_t.
   This is provided to facilitate compile-time QUIC declarations.
   Also see fd_quic_align() */
#define FD_QUIC_ALIGN (4096UL)  /* 4KiB */

/* FD_QUIC_MTU is the assumed network link MTU in bytes, including L2
   and L3 headers. */
#define FD_QUIC_MTU (1500)

/* FD_QUIC_INITIAL_PAYLOAD_SZ_MIN is the min byte size of the UDP payload
   of Initial-type packets.  Mandated for both clients and servers as a
   form of MTU discovery and to mitigate amplification attacks.  See
   RFC 9000 Section 14.1:
   https://datatracker.ietf.org/doc/html/rfc9000#name-initial-datagram-size */
#define FD_QUIC_INITIAL_PAYLOAD_SZ_MIN (1200)
#define FD_QUIC_INITIAL_PAYLOAD_SZ_MAX (FD_QUIC_INITIAL_PAYLOAD_SZ_MIN)

/* Tokens (both RETRY and NEW_TOKEN) are specified by varints. We bound it to
   77 bytes. Both our and quinn's RETRY tokens are 77 bytes, but our client
   needs to be able to handle other server impl's of RETRY too.

   FIXME change this bound (requires variable-length encoding). */
#define FD_QUIC_TOKEN_SZ_MAX (77)
/* Retry packets don't carry a token length field, so we infer it from the
   footprint of a packet with a zero-length token and zero-length conn ids. */
#define FD_QUIC_EMPTY_RETRY_PKT_SZ (23)

/* FD_QUIC_MAX_PAYLOAD_SZ is the max byte size of the UDP payload of any
   QUIC packets.  Derived from FD_QUIC_MTU by subtracting the typical
   IPv4 header (no options) and UDP header sizes. */
#define FD_QUIC_MAX_PAYLOAD_SZ (FD_QUIC_MTU - 20 - 8)

/* FD_QUIC_ROLE_{CLIENT,SERVER} identify the fd_quic_t's role as a
   client or server. */
#define FD_QUIC_ROLE_CLIENT 1
#define FD_QUIC_ROLE_SERVER 2

/* FD_QUIC_SEND_ERR_* are negative int error codes indicating a stream
   send failure.
   ...INVAL_STREAM: Not allowed to send for stream ID (e.g. not open)
   ...INVAL_CONN:   Connection not in valid state for sending
   ...FIN:          Not allowed to send, stream finished */
#define FD_QUIC_SEND_ERR_INVAL_STREAM (-1)
#define FD_QUIC_SEND_ERR_INVAL_CONN   (-2)
#define FD_QUIC_SEND_ERR_STREAM_FIN   (-3)

/* FD_QUIC_MIN_CONN_ID_CNT: min permitted conn ID count per conn */
#define FD_QUIC_MIN_CONN_ID_CNT (4UL)

/* FD_QUIC_DEFAULT_SPARSITY: default fd_quic_limits_t->conn_id_sparsity */
#define FD_QUIC_DEFAULT_SPARSITY (2.5)

/* FD_QUIC_STREAM_TYPE_* indicate stream type (two least significant
   bits of a stream ID).  These values are persisted to logs.  Entries
   should not be renumbered and numeric values should never be reused. */
#define FD_QUIC_STREAM_TYPE_BIDI_CLIENT 0
#define FD_QUIC_STREAM_TYPE_BIDI_SERVER 1
#define FD_QUIC_STREAM_TYPE_UNI_CLIENT  2
#define FD_QUIC_STREAM_TYPE_UNI_SERVER  3

/* FD_QUIC_NOTIFY_* indicate stream notification types.
   ...END:   Stream lifetime has ended, no more callbacks will be
             generated for it.  Stream will be freed after event
             delivery.
   ...RESET: Peer has reset the stream (will not send)
   ...ABORT: Peer has aborted the stream (will not receive) */
#define FD_QUIC_NOTIFY_END   (100)
#define FD_QUIC_NOTIFY_RESET (101)
#define FD_QUIC_NOTIFY_ABORT (102)

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
  ulong  conn_cnt;         /* instance-wide, max concurrent conn count      */
  ulong  handshake_cnt;    /* instance-wide, max concurrent handshake count */

  ulong  conn_id_cnt;      /* per-conn, max conn ID count (min 4UL) */
  double conn_id_sparsity; /* per-conn, conn ID hashmap sparsity    */

  ulong  stream_cnt[4];    /* per-conn, max concurrent stream count */
  double stream_sparsity;  /* per-conn, stream hashmap sparsity     */

  ulong  inflight_pkt_cnt; /* per-conn, max inflight packet count   */

  ulong  tx_buf_sz;        /* per-stream, tx buf sz in bytes          */
  /* the user consumes rx directly from the network buffer */
};
typedef struct fd_quic_limits fd_quic_limits_t;

/* fd_quic_now_t is the clock source used internally by quic for
   scheduling events.  context is an arbitrary pointer earlier provided
   by the caller during config.  Returns the time in ns since epoch.
   epoch is arbitrary but must stay consistent. */

typedef ulong
(*fd_quic_now_t)( void * context );

/* fd_quic_config_t defines mutable config of an fd_quic_t.  The config is
   immutable during an active join. */

struct __attribute__((aligned(16UL))) fd_quic_config {
  /* Protocol config ***************************************/

  /* role: one of FD_QUIC_ROLE_{CLIENT,SERVER} */
  int role;

  /* service_interval: time interval in ns for background services
     (sending ACKs).  Caller should introduce additional jitter in
     event loop. */
  /* TODO are there any other duties than ACKs? */
  ulong service_interval;

  /* ping_interval: inactivity time in ns before sending a
     ping request to peer. */
  /* TODO unused for now */
  ulong ping_interval;

  /* idle_timeout: time in ns before timing out a conn.
     Also sent to peer via max_idle_timeout transport param */
  ulong idle_timeout;

   /* retry: whether address validation using retry packets is enabled (RFC 9000, Section 8.1.2) */
  int retry;

  /* TLS config ********************************************/

  /* identity_key: Ed25519 public key of node identity
     (Can be random bytes) */
  uchar identity_public_key[ 32 ];

  /* Callback for signing TLS 1.3 certificate verify payload */
  fd_tls_sign_fn_t sign;
  void *           sign_ctx;

# define FD_QUIC_PATH_LEN 1023UL
  char keylog_file[ FD_QUIC_PATH_LEN+1UL ];

  /* Server name indication (client only)
     FIXME: Extend server to validate SNI */
# define FD_QUIC_SNI_LEN (255UL)
  char sni[ FD_QUIC_SNI_LEN+1UL ];

  ulong initial_rx_max_stream_data; /* per-stream, rx buf sz in bytes, set by the user. */

  /* Network config ****************************************/

  struct { /* Link layer config */
    /* src_mac_addr: Source MAC address to set for outgoing traffic */
    uchar src_mac_addr[6];

    /* dst_mac_addr: Destination MAC address to set for outgoing traffic
       Usually corresponds to the MAC address of the host's default gateway.
       FIXME: Replace with ARP table
       FIXME: This shouldn't be part of QUIC, but the fd_aio_out */
    uchar dst_mac_addr[6];
  } link;

  struct { /* Internet config */
    uint   ip_addr;         /* IP address (for outgoing traffic) */
    ushort listen_udp_port; /* UDP port (server only) */

    struct { /* Ephemeral UDP port range (client only) */
      ushort lo;
      ushort hi;
      /* we need an ephemeral UDP port range for at least two reasons:
         1. Some network hardware assumes src_ip:src_port:dst_ip:dst_port is a unique connection
         2. For receive-side scaling, the server will be using the source port for load balancing */
    } ephem_udp_port;

    /* dscp: Differentiated services code point.
       Set on all outgoing IPv4 packets. */
    uchar dscp;
  } net;
};
typedef struct fd_quic_config fd_quic_config_t;

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

/* fd_quic_cb_stream_new_t is called when the peer creates a new stream.
   Callback should set "context" within the supplied stream object but
   may not change any other stream fields. quic_ctx is the user-provided
   QUIC context.  Note that this differs from the stream context.
   stream_type is one of FD_QUIC_TYPE_{UNI,BI}DIR. */
typedef void
(* fd_quic_cb_stream_new_t)( fd_quic_stream_t * stream,
                             void *             quic_ctx,
                             int                stream_type );

/* fd_quic_cb_stream_notify_t signals a notable stream event.
   stream_ctx object is the user-provided stream context set in the new
   callback.

   TODO will only one notify max be served?
   TODO will stream be deallocated immediately after callback?

   notify_type is in FD_QUIC_NOTIFY_{END,RESET,ABORT} */
typedef void
(* fd_quic_cb_stream_notify_t)( fd_quic_stream_t * stream,
                                void *             stream_ctx,
                                int                notify_type );

/* fd_quic_cb_stream_receive_t is called when new data is received from
   stream.  Each buffer is received in a separate callback.

   args
     stream_context   is user supplied stream context set in callback
     stream_id        the quic stream id
     data             the bytes received
     data_sz          the number of bytes received
     offset           the offset in the stream of the first byte in data
     fin              bool - true if the last byte of data is the last
                      byte on the receive side of the stream */
typedef void
(* fd_quic_cb_stream_receive_t)( fd_quic_stream_t * stream,
                                 void *             stream_ctx,
                                 uchar const *      data,
                                 ulong              data_sz,
                                 ulong              offset,
                                 int                fin );

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
  fd_quic_cb_stream_new_t              stream_new;        /* non-NULL, with stream_ctx */
  fd_quic_cb_stream_notify_t           stream_notify;     /* non-NULL, with stream_ctx */
  fd_quic_cb_stream_receive_t          stream_receive;    /* non-NULL, with stream_ctx */
  fd_quic_cb_tls_keylog_t              tls_keylog;        /* nullable, with quic_ctx   */

  /* Clock source */

  fd_quic_now_t now;     /* non-NULL */
  void *        now_ctx; /* user-provided context pointer for now_fn calls */

};
typedef struct fd_quic_callbacks fd_quic_callbacks_t;

/* fd_quic metrics ****************************************************/

/* TODO: evaluate performance impact of metrics */

union fd_quic_metrics {
  ulong  ul[ 30 ];
  struct {
    /* Network metrics */
    ulong net_rx_pkt_cnt;  /* number of IP packets received */
    ulong net_rx_byte_cnt; /* total bytes received (including IP, UDP, QUIC headers) */
    ulong net_tx_pkt_cnt;  /* number of IP packets sent */
    ulong net_tx_byte_cnt; /* total bytes sent */

    /* Conn metrics */
    ulong conn_active_cnt;        /* number of active conns */
    ulong conn_created_cnt;        /* number of conns created */
    ulong conn_closed_cnt;         /* number of conns gracefully closed */
    ulong conn_aborted_cnt;        /* number of conns aborted */
    ulong conn_retry_cnt;          /* number of conns established with retry */
    ulong conn_err_no_slots_cnt;   /* number of conns that failed to create due to lack of slots */
    ulong conn_err_tls_fail_cnt;   /* number of conns that aborted due to TLS failure */
    ulong conn_err_retry_fail_cnt; /* number of conns that failed during retry (e.g. invalid token) */

    /* Handshake metrics */
    ulong hs_created_cnt;          /* number of handshake flows created */
    ulong hs_err_alloc_fail_cnt;   /* number of handshakes dropped due to alloc fail */

    /* Stream metrics */
    ulong stream_opened_cnt  [ 4 ]; /* number of streams opened (per type) */
    ulong stream_closed_cnt  [ 4 ]; /* number of streams closed (per type) */
       /* TODO differentiate between FIN (graceful) and STOP_SENDING/RESET_STREAM (forcibly)? */
    ulong stream_active_cnt  [ 4 ]; /* number of active streams (per type) */
    ulong stream_rx_event_cnt;      /* number of stream RX events */
    ulong stream_rx_byte_cnt;       /* total stream payload bytes received */
  };
};
typedef union fd_quic_metrics fd_quic_metrics_t;

/* Assertion: fd_quic_metrics_t::ul must cover the whole struct */

FD_STATIC_ASSERT( sizeof(((fd_quic_metrics_t *)(0))->ul)==sizeof(fd_quic_metrics_t), layout );

/* fd_quic_t memory layout ********************************************/

struct fd_quic {
  ulong magic; /* ==FD_QUIC_MAGIC */

  fd_quic_limits_t    limits;  /* position-independent, persistent,    read only */
  fd_quic_config_t    config;  /* position-independent, persistent,    writable pre init */
  fd_quic_callbacks_t cb;      /* position-dependent,   reset on join, writable pre init  */
  fd_quic_metrics_t   metrics; /* position-independent, persistent,    read only */

  fd_aio_t aio_rx; /* local AIO */
  fd_aio_t aio_tx; /* remote AIO */

  /* ... private variable-length structures follow ... */
};
typedef struct fd_quic fd_quic_t;

FD_PROTOTYPES_BEGIN

/* debugging */

ulong
fd_quic_conn_get_pkt_meta_free_count( fd_quic_conn_t * conn );


/* Object lifecycle ***************************************************/

/* fd_quic_{align,footprint} return the required alignment and footprint
   of a memory region suitable for use as an fd_quic_t.  align returns
   FD_QUIC_ALIGN.  limits is a temporary reference to the requested

   On failure, footprint will silently return 0 (and thus can be used by
   the caller to validate fd_quic_new params) */

FD_QUIC_API FD_FN_CONST ulong
fd_quic_align( void );

FD_QUIC_API FD_FN_PURE ulong
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
     dst_udp_port  destination port number
     sni           server name indication cstr, max 253 chars, nullable */

FD_QUIC_API fd_quic_conn_t *
fd_quic_connect( fd_quic_t *  quic,  /* requires exclusive access */
                 uint         dst_ip_addr,
                 ushort       dst_udp_port,
                 char const * sni );

/* fd_quic_conn_close asynchronously initiates a shutdown of the conn.
   The given reason code is returned to the peer via a CONNECTION_CLOSE
   frame, if possible.  Causes conn_final callback to be issued
   eventually. */

FD_QUIC_API void
fd_quic_conn_close( fd_quic_conn_t * conn,
                    uint             reason );

/* Service API ********************************************************/

/* fd_quic_get_next_wakeup returns the next requested service time.
   The returned timestamp is relative to a value previously returned by
   fd_quic_now_t. */

FD_QUIC_API ulong
fd_quic_get_next_wakeup( fd_quic_t * quic );

/* fd_quic_service services QUIC conns and housekeeps fd_quic_t internal
   state.  The user should call service regularly. */

FD_QUIC_API void
fd_quic_service( fd_quic_t * quic );

/* Stream Send API ****************************************************/

/* fd_quic_conn_new_stream creates a new stream on the given conn.
   type is one of FD_QUIC_TYPE_{UNI,BI}DIR.  On success, returns the
   newly created stream.  On failure, returns NULL.  Reasons for failure
   include invalid conn state or out of stream quota.

   The user does not own the returned pointer: its lifetime is managed
   by the connection. */

FD_QUIC_API fd_quic_stream_t *
fd_quic_conn_new_stream( fd_quic_conn_t * conn,
                         int              type );

/* fd_quic_stream_send sends a vector of buffers on a stream in order.

   Use fd_quic_conn_new_stream to create a new stream for sending
   or use the new stream callback to obtain a stream for replying.

   args
     stream         the stream to send on
     batch          a pointer to an array of buffers
     batch_sz       the size of the batch
     fin            final: bool
                      set to indicate the stream is finalized by the last byte
                      in the batch
                      If the last buffer in the batch was rejected, the FIN
                        flag is not set, and may be applied in a future send
                        or via the fd_quic_stream_fin(...) function

   returns
     >=0   number of buffers sent - remaining blocked
      <0   one of FD_QUIC_SEND_ERR_{INVAL_STREAM,INVAL_CONN,AGAIN} */
FD_QUIC_API int
fd_quic_stream_send( fd_quic_stream_t *  stream,
                     fd_aio_pkt_info_t * batch,
                     ulong               batch_sz,
                     int                 fin );

/* fd_quic_stream_fin: finish sending on a stream.  Called to signal
   no more data will be sent to self-to-peer flow of stream.  Peer may
   continue sending data on their side of the stream.  Caller should
   only call stream_fin once per stream, except when fin was already
   indicated via stream_send. */

FD_QUIC_API void
fd_quic_stream_fin( fd_quic_stream_t * stream );

/* TODO: fd_quic_stream_close */
//void
//fd_quic_stream_close( fd_quic_stream_t * stream, int direction_flags );

FD_PROTOTYPES_END

uint fd_quic_tx_buffered_raw( fd_quic_t      * quic,
                              uchar **         tx_ptr_ptr,
                              uchar *          tx_buf,
                              ulong            tx_buf_sz,
                              ulong *          tx_sz,
                              uchar *          crypt_scratch,
                              ulong            crypt_scratch_sz,
                              uchar const      dst_mac_addr[ static 6 ],
                              ushort *         ipv4_id,
                              uint             dst_ipv4_addr,
                              ushort           src_udp_port,
                              ushort           dst_udp_port,
                              int              flush );

/* Convenience exports for consumers of API */
#include "fd_quic_conn.h"
#include "fd_quic_stream.h"

/* FD_DEBUG_MODE: set to enable debug-only code
   TODO move to util? */
#ifndef FD_DEBUG_MODE
#define FD_DEBUG(...) __VA_ARGS__
#else
#define FD_DEBUG(...)
#endif

#endif /* HEADER_fd_src_tango_quic_fd_quic_h */
