#ifndef HEADER_fd_quic_h
#define HEADER_fd_quic_h

#include "fd_quic_common.h"
#include "fd_quic_conn.h"
#include "fd_quic_conn_map.h"
#include "fd_quic_config.h"
#include "templ/fd_quic_transport_params.h"
#include "tls/fd_quic_tls.h"
#include "../aio/fd_aio.h"
#include "../../util/fd_util.h"

enum {
  FD_QUIC_SUCCESS = 0,
  FD_QUIC_FAILED  = 1,

  FD_QUIC_TYPE_BIDIR  = 0, /* BIDIR == 0, UNIDIR == 1 for masking internally */
  FD_QUIC_TYPE_UNIDIR = 1,

  FD_QUIC_TYPE_INGRESS = 1 << 0,
  FD_QUIC_TYPE_EGRESS  = 1 << 1,

  FD_QUIC_NOTIFY_END   = 100,
  FD_QUIC_NOTIFY_RESET = 101,
  FD_QUIC_NOTIFY_ABORT = 102,

  FD_QUIC_TRANSPORT_PARAMS_RAW_SZ = 1200,
};

#define FD_QUIC_PKT_NUM_UNUSED (~0ul)


/* forward declares */
typedef struct fd_quic                fd_quic_t;
typedef struct fd_quic_conn           fd_quic_conn_t;
typedef struct fd_quic_stream         fd_quic_stream_t;
typedef struct fd_quic_host_cfg       fd_quic_host_cfg_t;
typedef struct fd_quic_conn_id        fd_quic_conn_id_t;
typedef struct fd_quic_event          fd_quic_event_t;
typedef struct fd_quic_stream_meta    fd_quic_stream_meta_t;


struct fd_quic {
  ulong                         magic;

  /* directly from config */
  char const *                  cert_file;              /* certificate file */
  char const *                  key_file;               /* private key file */

  fd_quic_transport_params_t    transport_params;       /* copy of our transport parameters for connections */

  fd_quic_host_cfg_t            host_cfg;               /* networking info */

  int                           listen;                 /* are we listening for inbound connections */

  ulong                         max_concur_conns;       /* maximum number of concurrent connections */
                                                        /* allowed */

  uint                          max_concur_streams;     /* maximum number of concurrent streams */
                                                        /* allowed per connection */

  uint                          max_concur_handshakes;  /* maximum number of concurrent handshake */
                                                        /* allowed per connection */

  ulong                         max_in_flight_pkts;     /* max in-flight (tx) packets per connection */
  ulong                         max_in_flight_acks;     /* max in-flight (tx) acks per connection */

  fd_quic_now_t                 now_fn;                 /* now function - returns the current time in ns */
  void *                        now_ctx;                /* context supplied as argument to now_fn */

  ulong                         service_interval;       /* mean time between connection services */

  uchar                         dscp;                   /* differentiated services code point */

  fd_quic_conn_t *              conns;                  /* free list of unused connections */
  ulong                         cur_num_conns;          /* current number of connections */

  fd_quic_conn_map_t *          conn_map;               /* map connection ids -> connection */

  uchar                         aio_net_in_mem[sizeof( fd_aio_t )+16];
  fd_aio_t *                    aio_net_in;             /* abstract input/output interface */
  fd_aio_t *                    aio_net_out;            /* for network */
                                                        /* in is object configured by QUIC */
                                                        /* out is ptr to object configured externally */

  fd_quic_tls_t *               quic_tls;               /* the object for managing quic-tls */

  fd_quic_event_t *             service_queue;          /* priority queue of connections by service time */

  /* callbacks for user */
  fd_quic_cb_conn_new_t                cb_conn_new;
  fd_quic_cb_conn_handshake_complete_t cb_handshake_complete;
  fd_quic_cb_conn_final_t              cb_conn_final;
  fd_quic_cb_stream_new_t              cb_stream_new;          /* callback for new stream */
  fd_quic_cb_stream_notify_t           cb_stream_notify;       /* callback for notifications */
  fd_quic_cb_stream_receive_t          cb_stream_receive;      /* callback for receiving stream data */

  /* crypto members */
  fd_quic_crypto_ctx_t          crypto_ctx[1];          /* crypto context */

  /* user context for callbacks */
  void *                        context;

  fd_quic_pkt_meta_t *          pkt_meta;               /* records the metadata for the contents */
                                                        /* of each sent packet */


  /* flow control - configured initial limits */
  ulong                         initial_max_data;           /* directly from transport params */
  ulong                         initial_max_stream_data[4]; /* from 4 transport params
                                                               indexed by stream type */

  /* networking parameters */
  struct {
    /* forward traffic to this MAC address */
    uchar                              default_route_mac[6];

    /* source interface MAC address */
    uchar                              src_mac[6];
  } net;
};

/* events for time based processing */
struct fd_quic_event {
  ulong            timeout;

  fd_quic_conn_t * conn; /* connection or NULL */
  /* possibly "type", etc., for other kinds of service */
};


FD_PROTOTYPES_BEGIN

/* fd_quic_align returns the required alignment of the memory used for fd_quic_new */
ulong fd_quic_align();

/* fd_quic_footprint returns the required footprint of the memory used for fd_quic_new */
ulong
fd_quic_footprint( ulong tx_buf_sz,
                   ulong rx_buf_sz,
                   ulong max_concur_streams_per_type,
                   ulong max_in_flight_pkts,
                   ulong max_concur_conns,
                   ulong max_concur_conn_ids );

/* fd_quic_new

   create a new quic endpoint

   Args
     mem          the memory to use for the newly created quic object
                    must be aligned according to fd_quic_align()
                    must be sized according to fd_quic_footprint( config )
     config       an instance of fd_quic_config_t to supply configuration parameters

   Returns
     fd_quic_t *  pointer to the new instance */

fd_quic_t *
fd_quic_new( void * mem,
             ulong  tx_buf_sz,
             ulong  rx_buf_sz,
             ulong  max_concur_streams_per_type,
             ulong  max_in_flight_pkts,
             ulong  max_concur_conns,
             ulong  max_concur_conn_ids );


/* initialize fd_quic_t after fd_quic_new */
fd_quic_t *
fd_quic_init( fd_quic_t *        quic,
              fd_quic_config_t * config );

/* fd_quic_delete

   frees all related resources

   Args
     quic         the quic instance to delete */
void
fd_quic_delete( fd_quic_t * quic );


/* connect to remote server

   initiates a new client connection, and returns an object to
   manage it

   the fd_quic_t object owns the returned fd_quic_conn_t
   and manages its lifetime

   args
     dst_ip_addr       destination ip address
     dst_udp_port      destination port number */
fd_quic_conn_t *
fd_quic_connect( fd_quic_t * quic,
                 uint        dst_ip_addr,
                 ushort      dst_udp_port );


/* initiate the shutdown of a connection
   may select a reason code, or 0 if none */
void
fd_quic_conn_close( fd_quic_conn_t * conn, uint reason );


/* initiate a reset of a connection */
void
fd_quic_conn_reset( fd_quic_conn_t * conn );


/* check whether a handshake is complete

   args
     conn       the connection to check

   returns
     0          the handshake is ongoing
     1          the handshake is complete */
inline FD_FN_CONST
int
fd_quic_handshake_complete( fd_quic_conn_t * conn ) {
  return conn->handshake_complete;
}


/* do general processing
   user should call regularly to service connections

   args
     quic       the quic to run processing on
     now        the current time in ns
   */
void
fd_quic_service( fd_quic_t * quic );


/* service connection

   This is called periodically to perform pending operations and time based
   operations

   args
     quic        managing quic
     conn        connection to service
     now         the current time in ns */
void
fd_quic_conn_service( fd_quic_t * quic, fd_quic_conn_t * conn, ulong now );


/* free a connection

   frees up resources related to the connection and returns
   it to the connection free list */
void
fd_quic_conn_free( fd_quic_t * quic, fd_quic_conn_t * conn );


/* set up network IO input into QUIC
   returns an aio object for ingress into QUIC

   args
     aio_in         aio for input into QUIC from network */
inline
fd_aio_t *
fd_quic_get_aio_net_in( fd_quic_t * quic ) {
  return quic->aio_net_in;
}


/* set up network IO output to QUIC

   args
     aio_out        aio for output to QUIC from network */
inline
void
fd_quic_set_aio_net_out( fd_quic_t * quic, fd_aio_t * aio_out ) {
  quic->aio_net_out  = aio_out;
}


/* set up quic server and listen for incoming connections

   the udp port set in quic_config.host_cfg is used for listening

   args
     quic           the quic to configure for listening */
void
fd_quic_listen( fd_quic_t * quic );


/* start a new stream on a connection

   streams may be unidirectional or bidirectional
   a unidirectional stream passes data from the initiator to its peer

   the user does not own the returned pointer: its lifetime is managed
   by the connection

   args
     conn           the connection from which to derive the stream
     type           one of the following:
                      FD_QUIC_TYPE_UNIDIR - unidirectional stream
                      FD_QUIC_TYPE_BIDIR  - bidirectional stream

   return
     an initialized fd_quic_stream_t if successful, or
     NULL                            otherwise

*/
fd_quic_stream_t *
fd_quic_conn_new_stream( fd_quic_conn_t * conn, int type );


/* send data

   called to send arbitrary data to a peer

   args
     stream         the stream to send on
     batch          a pointer to an array of buffers
     batch_sz       the size of the batch

   */
int
fd_quic_stream_send( fd_quic_stream_t *  stream,
                     fd_aio_pkt_info_t * batch,
                     ulong               batch_sz );


/* closes tx or rx or both of a stream

   args
     direction_flags    mask of the following ORed together:
                          0x01  close TX
                          0x02  close RX */
void
fd_quic_stream_close( fd_quic_stream_t * stream, int direction_flags );


/* set context for connection callbacks */
inline
void
fd_quic_set_conn_cb_context( fd_quic_t * quic, void * context ) {
  quic->context = context;
}

/* set callback for receiving new connection notifications

   args
     quic           the instance of quic to receive from
     cb             the callback function that will be called upon notification */
inline
void
fd_quic_set_cb_conn_new( fd_quic_t * quic, fd_quic_cb_conn_new_t cb ) {
  quic->cb_conn_new = cb;
}


/* set callback for receiving connection handshake complete notifications

   args
     quic           the instance of quic to receive from
     cb             the callback function that will be called upon notification */
inline
void
fd_quic_set_cb_conn_handshake_complete( fd_quic_t * quic, fd_quic_cb_conn_handshake_complete_t cb ) {
  quic->cb_handshake_complete = cb;
}


/* set callback for receiving connection finalized notifications

   args
     quic           the instance of quic to receive from
     cb             the callback function that will be called upon notification */
inline
void
fd_quic_set_cb_conn_final( fd_quic_t * quic, fd_quic_cb_conn_final_t cb ) {
  quic->cb_conn_final = cb;
}

/* set context for stream callbacks */
inline
void
fd_quic_set_stream_cb_context( fd_quic_stream_t * stream, void * stream_context ) {
  stream->context = stream_context;
}


/* set callback for receiving data from a peer

   args
     quic           the instance of quic to receive from
     cb             the callback function that will be called upon receipt */
inline
void
fd_quic_set_cb_stream_receive( fd_quic_t * quic, fd_quic_cb_stream_receive_t cb ) {
  quic->cb_stream_receive = cb;
}


/* set callback for receiving new stream notification

   args
     quic           the instance of quic to receive from
     cb             the callback function that will be called upon new stream */
inline
void
fd_quic_set_cb_stream_new( fd_quic_t * quic, fd_quic_cb_stream_new_t cb ) {
  quic->cb_stream_new = cb;
}


/* set callback for receiving stream termination notifications

   args
     quic           the instance of quic to receive from
     cb             the callback function that will be called upon notification */
inline
void
fd_quic_set_cb_stream_notify( fd_quic_t * quic, fd_quic_cb_stream_notify_t cb ) {
  quic->cb_stream_notify = cb;
}

ulong
fd_quic_get_next_wakeup( fd_quic_t * quic );


FD_PROTOTYPES_END

#endif

