#ifndef HEADER_fd_src_tango_quic_fd_quic_h
#define HEADER_fd_src_tango_quic_fd_quic_h

#if FD_HAS_HOSTED && FD_HAS_OPENSSL

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
   - https://datatracker.ietf.org/doc/html/rfc9001 */

/* TODO provide fd_quic on non-hosted targets */

#include "../aio/fd_aio.h"
#include "../../util/fd_util.h"

#include "templ/fd_quic_transport_params.h"

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
   ...AGAIN:        Blocked from sending, try again later
   ...FIN:          Not allowed to send, stream finished */
#define FD_QUIC_SEND_ERR_INVAL_STREAM (-1)
#define FD_QUIC_SEND_ERR_INVAL_CONN   (-2)
#define FD_QUIC_SEND_ERR_AGAIN        (-3)
#define FD_QUIC_SEND_ERR_STREAM_FIN   (-4)

/* fd_quic_t is the main handle for a QUIC client/server.

   fd_quic_t contains the following structures in a single continuous
   memory region (usually in an fd_wksp):

   - fd_quic_limits_t    describing its memory layout
   - fd_quic_config_t    various config params that don't change memory layout
   - fd_quic_conn_t[]    pre-allocated list of active conns
   - fd_quic_stream_t[]  pre-allocated list of active streams */

/* FD_QUIC_MIN_CONN_ID_CNT: min permitted conn ID count per conn */
#define FD_QUIC_MIN_CONN_ID_CNT (4UL)

/* FD_QUIC_DEFAULT_SPARSITY: default fd_quic_limits_t->conn_id_sparsity */
#define FD_QUIC_DEFAULT_SPARSITY (2.5)

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

  ulong  stream_cnt;       /* per-conn, max concurrent stream count */
  double stream_sparsity;  /* per-conn, stream hashmap sparsity     */

  ulong  inflight_pkt_cnt; /* per-conn, max inflight packet count   */

  ulong  tx_buf_sz;        /* per-conn, tx buf sz in bytes          */
  ulong  rx_buf_sz;        /* per-conn, rx buf sz in bytes          */
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

  /* ping_interval: inactivity time in ns before requesting sending a
     ping request to peer. */
  /* TODO unused for now */
  ulong ping_interval;

  /* TLS config ********************************************/

  /* cstrs containing TLS PEM cert and key file path */
# define FD_QUIC_CERT_PATH_LEN (1024UL)
  char cert_file  [ FD_QUIC_CERT_PATH_LEN ];
  char key_file   [ FD_QUIC_CERT_PATH_LEN ];
  char keylog_file[ FD_QUIC_CERT_PATH_LEN ];

  /* alpns: List of supported ALPN IDs in OpenSSL format.
     Contains packed list of uchar length prefixed strings
     with total buffer size alpns_sz.
       e.g.: <0x0a> "solana-tpu" <0x02> "h2" */
  char alpns[ 256 ];
  uint alpns_sz;

  /* Server name indication (client only)
     FIXME: Extend server to validate SNI */
# define FD_QUIC_SNI_LEN (255UL)
  char sni[ FD_QUIC_SNI_LEN+1UL ];

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
         1. Some nextwork hardware assumes src_ip:src_port:dst_ip:dst_port is a unique connection
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

/* fd_quic_cb_conn_handshake_complete_t: client completed handshakes
   TODO how does this differ from conn_new?
   TODO invoked for client too? */
typedef void
(* fd_quic_cb_conn_handshake_complete_t)( fd_quic_conn_t * conn,
                                          void *           quic_ctx );

/* fd_quic_cb_conn_final_t: lifetime of conn is about to end
   TODO add note regarding lifetime of pointers to same conn object
   TODO will conn be deallocated immediately after callback? */
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

  /* Clock source */

  fd_quic_now_t now;     /* non-NULL */
  void *        now_ctx; /* user-provided context pointer for now_fn calls */

};
typedef struct fd_quic_callbacks fd_quic_callbacks_t;

/* fd_quic_t memory layout ********************************************/

/* fd_quic_join_t contains externally provided objects that are
   required to join an fd_quic_t. */

struct __attribute__((aligned(16UL))) fd_quic_join {
  /* User-provided callbacks */

  fd_quic_callbacks_t cb;

  /* fd_aio I/O abstraction */

  fd_aio_t aio_tx; /* owned externally, used by fd_quic_t
                      to send tx data to net driver */
};
typedef struct fd_quic_join fd_quic_join_t;

/* fd_quic_t is the publicly exported memory layout of a QUIC memory
   region.  fd_quic_t should not be statically allocated.  Instead, use
   fd_quic_footprint() and fd_quic_join(). */

struct fd_quic {
  ulong            magic;   /* ==FD_QUIC_MAGIC */
  fd_quic_limits_t limits;
  fd_quic_config_t config;
  fd_quic_join_t   join;

  /* ... variable length structures follow ... */
};
typedef struct fd_quic fd_quic_t;

FD_PROTOTYPES_BEGIN

/* debugging */

ulong
fd_quic_conn_get_pkt_meta_free_count( fd_quic_conn_t * conn );


/* Construction API ***************************************************/

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

FD_QUIC_API fd_quic_t *
fd_quic_new( void *                   mem,
             fd_quic_limits_t const * limits );

/* fd_quic_get_config returns the config struct in the caller's local
   address space.  Used to configure a QUIC object before a join. Only
   caller may modify the config object (fd_quic_t functions won't).
   Writes to the returned config persist for the lifetime of the quic
   object.  Assumes given quic is a valid fd_quic_t without an active
   join (U.B. otherwise).  The lifetime of the returned pointer is the
   same as the given quic. */

FD_QUIC_API FD_FN_CONST fd_quic_config_t *
fd_quic_get_config( fd_quic_t * quic );

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

/* fd_quic_get_callbacks returns the callback struct in the caller's
   local address space.  Used to configure a QUIC object before a join.
   Cleared on next leave.  Assumes given quic is a valid fd_quic_t
   without an active join (U.B. otherwise).  The lifetime of the
   returned pointer is the same as the given QUIC. */

FD_QUIC_API FD_FN_CONST fd_quic_callbacks_t *
fd_quic_get_callbacks( fd_quic_t * quic );

/* fd_quic_get_aio_net_rx configures the given aio to receive data into
   quic instance.  aio should be deleted before lifetime of quic ends.
   Returns given aio on success. */

FD_QUIC_API fd_aio_t *
fd_quic_get_aio_net_rx( fd_quic_t * quic,
                        fd_aio_t *  aio );

/* fd_quic_set_aio_net_tx sets the fd_aio_t used by the fd_quic_t to
   send tx data to the network driver.  Cleared on leave.

   The given aio will handle  */

FD_QUIC_API void
fd_quic_set_aio_net_tx( fd_quic_t *      quic,
                        fd_aio_t const * aio_tx );

/* fd_quic_join joins the caller to the QUIC such that it is ready to
   serve.  There may only be one active join at a time.  Returns the
   given quic on success and NULL on failure (logs details).  Performs
   various heap allocations and file system accesses such reading certs,
   as required by OpenSSL.  Reasons for failure include invalid config
   or OpenSSL error. */

FD_QUIC_API fd_quic_t *
fd_quic_join( fd_quic_t * quic );

/* fd_quic_leave leaves a current local join and frees all dynamically
   managed resources (heap allocs, OS handles).  Returns the given quic
   on success and NULL on failure (logs details).  Reasons for failure
   include quic is NULL, no active join, or OpenSSL error. */

FD_QUIC_API fd_quic_t *
fd_quic_leave( fd_quic_t * quic );

/* fd_quic_reset clears all join-related memory.  Used to recover from
   unclean shutdowns.  Assumes nobody is joined to quic.  Returns quic. */

FD_QUIC_API fd_quic_t *
fd_quic_reset( fd_quic_t * quic );

/* fd_quic_delete unformats a memory region used as an fd_quic_t.
   Assumes nobody is joined to the region.  Returns the given quic
   pointer on success and NULL if used obviously in error (e.g. quic is
   obviously not an fd_quic_t ... logs details).  The ownership of the
   memory region is transferred ot the caller. */

FD_QUIC_API void *
fd_quic_delete( fd_quic_t * quic );

/* Connection API *****************************************************/

/* fd_quic_connect initiates a new client connection to a remote QUIC
   server.  On success, returns a conn object to manage it.  On failure,
   returns NULL.  Reasons for failure include quic not a valid join or
   out of free conns.

   TODO who is responsible for freeing the returned conn object?

   args
     dst_ip_addr   destination ip address
     dst_udp_port  destination port number
     sni           server name indication cstr, max 253 chars, nullable */

FD_QUIC_API fd_quic_conn_t *
fd_quic_connect( fd_quic_t *  quic,
                 uint         dst_ip_addr,
                 ushort       dst_udp_port,
                 char const * sni );

/* fd_quic_conn_close initiates a shutdown of the conn.  The given
   reason code is returned to the peer via a CONNECTION_CLOSE frame, if
   possible. */

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
   Each buf in batch must be at most FD_QUIC_MAX_TX_BUF bytes.

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

/* Convenience exports for consumers of API */

#include "fd_quic_conn.h"
#include "fd_quic_stream.h"

#endif /* FD_HAS_HOSTED && FD_HAS_OPENSSL */

#endif /* HEADER_fd_src_tango_quic_fd_quic_h */

