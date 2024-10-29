#ifndef HEADER_fd_src_waltz_quic_fd_quic_conn_h
#define HEADER_fd_src_waltz_quic_fd_quic_conn_h

#include "fd_quic.h"
#include "fd_quic_ack_tx.h"
#include "fd_quic_retry.h"
#include "fd_quic_stream.h"
#include "fd_quic_conn_id.h"
#include "crypto/fd_quic_crypto_suites.h"
#include "templ/fd_quic_transport_params.h"
#include "fd_quic_pkt_meta.h"

#define FD_QUIC_CONN_STATE_INVALID            0 /* dead object / freed */
#define FD_QUIC_CONN_STATE_HANDSHAKE          1 /* currently doing handshaking with peer */
#define FD_QUIC_CONN_STATE_HANDSHAKE_COMPLETE 2 /* handshake complete, confirming with peer */
#define FD_QUIC_CONN_STATE_ACTIVE             3 /* connection established - data may be transferred */
#define FD_QUIC_CONN_STATE_PEER_CLOSE         4 /* peer requested close */
#define FD_QUIC_CONN_STATE_ABORT              5 /* connection terminating due to error */
#define FD_QUIC_CONN_STATE_CLOSE_PENDING      6 /* connection is closing */
#define FD_QUIC_CONN_STATE_DEAD               7 /* connection about to be freed */

enum {
  FD_QUIC_CONN_REASON_NO_ERROR                     = 0x00,    /* No error */
  FD_QUIC_CONN_REASON_INTERNAL_ERROR               = 0x01,    /* Implementation error */
  FD_QUIC_CONN_REASON_CONNECTION_REFUSED           = 0x02,    /* Server refuses a connection */
  FD_QUIC_CONN_REASON_FLOW_CONTROL_ERROR           = 0x03,    /* Flow control error */
  FD_QUIC_CONN_REASON_STREAM_LIMIT_ERROR           = 0x04,    /* Too many streams opened */
  FD_QUIC_CONN_REASON_STREAM_STATE_ERROR           = 0x05,    /* Frame received in invalid stream state */
  FD_QUIC_CONN_REASON_FINAL_SIZE_ERROR             = 0x06,    /* Change to final size */
  FD_QUIC_CONN_REASON_FRAME_ENCODING_ERROR         = 0x07,    /* Frame encoding error */
  FD_QUIC_CONN_REASON_TRANSPORT_PARAMETER_ERROR    = 0x08,    /* Error in transport parameters */
  FD_QUIC_CONN_REASON_CONNECTION_ID_LIMIT_ERROR    = 0x09,    /* Too many connection IDs received */
  FD_QUIC_CONN_REASON_PROTOCOL_VIOLATION           = 0x0a,    /* Generic protocol violation */
  FD_QUIC_CONN_REASON_INVALID_TOKEN                = 0x0b,    /* Invalid Token received */
  FD_QUIC_CONN_REASON_APPLICATION_ERROR            = 0x0c,    /* Application error */
  FD_QUIC_CONN_REASON_CRYPTO_BUFFER_EXCEEDED       = 0x0d,    /* CRYPTO data buffer overflowed */
  FD_QUIC_CONN_REASON_KEY_UPDATE_ERROR             = 0x0e,    /* Invalid packet protection update */
  FD_QUIC_CONN_REASON_AEAD_LIMIT_REACHED           = 0x0f,    /* Excessive use of packet protection keys */
  FD_QUIC_CONN_REASON_NO_VIABLE_PATH               = 0x10,    /* No viable network path exists */
  FD_QUIC_CONN_REASON_CRYPTO_BASE                  = 0x100,   /* 0x0100-0x01ff CRYPTO_ERROR TLS alert code*/
  /* QUIC permits the use of a generic code in place of a specific error code [...]
     such as handshake_failure (0x0128 in QUIC). */
  FD_QUIC_CONN_REASON_HANDSHAKE_FAILURE            = 0x128    /* Handshake failed. */
};

typedef struct fd_quic_conn       fd_quic_conn_t;

struct fd_quic_conn {
  uint               conn_idx;            /* connection index */
                                          /* connections are sized at runtime */
                                          /* storing the index avoids a division */

  fd_quic_t *        quic;
  void *             context;             /* user context */

  uint               server      : 1;     /* role from self POV: 0=client, 1=server */
  uint               established : 1;     /* used by clients to determine whether to
                                             switch the destination conn id used */
  uint               transport_params_set : 1;
  uint               called_conn_new : 1; /* whether we need to call conn_final on teardown */
  uint               visited : 1;         /* scratch bit, no strict definition */

  /* Service queue dlist membership.  All active conns (state not INVALID)
     are in a service queue, FD_QUIC_SVC_TYPE_WAIT by default.
     Free conns (svc_type==UINT_MAX) are members of a singly linked list
     (only src_next set) */
  uint               svc_type;  /* FD_QUIC_SVC_{...} or UINT_MAX */
  uint               svc_prev;
  uint               svc_next;
  ulong              svc_time;  /* service may be delayed until this timestamp */

  ulong              our_conn_id;

  /* Save original destination connection id
     This will be used when we receive a retransmitted initial packet
     Also used when retransmitting the first initial packet */
  fd_quic_conn_id_t  orig_dst_conn_id;

  /* Save original retry_source_connection_id
   * This is used by clients to compare against the retry_source_connection_id
   * in the transport parameters as specified in rfc 9000 7.3 */
  fd_quic_conn_id_t  retry_src_conn_id;

  /* Host network endpoint
     - for server, just a copy of config->net
     - for client, an allocated ephemeral UDP port */
  fd_quic_net_endpoint_t host;

  /* Peer network endpoints – have multiple connection ids and ip:port */
  /* TODO: footprint allows specifying conn_id_cnt but hardcoded limit used here */
  fd_quic_net_endpoint_t peer[1];
  fd_quic_conn_id_t      peer_cids[1]; /* FIXME support new/retire conn ID */

  ulong              local_conn_id;       /* FIXME: hack to locally identify conns */

  /* initial source connection id */
  fd_quic_conn_id_t  initial_source_conn_id;

  uint               tx_max_datagram_sz;  /* size of maximum datagram allowed by peer */

  /* handshake members */
  uint               handshake_complete  : 1; /* have we completed a successful handshake? */
  uint               handshake_done_send : 1; /* do we need to send handshake-done to peer? */
  uint               handshake_done_ackd : 1; /* was handshake_done ack'ed? */
  uint               hs_data_empty       : 1; /* has all hs_data been consumed? */
  fd_quic_tls_hs_t * tls_hs;

  /* expected handshake data offset - one per encryption level
     data received lower than this on a new packet is a protocol error
       duplicate packets should already have been dropped
     data received higher than this would be a gap
       ignore at present, assuming will be resent in order */
  ulong rx_crypto_offset[4]; /* expected handshake data (crypto) offset
                                   one per encryption level */

  /* amount of handshake data already sent from head of queue */
  ulong hs_sent_bytes[4];

  /* amount of handshake data ack'ed by peer counted from head of queue */
  ulong hs_ackd_bytes[4];

  /* secret members */
  fd_quic_crypto_secrets_t secrets;
  fd_quic_crypto_keys_t    keys[4][2];  /* a set of keys for each of the encoding levels, and for client/server */
  fd_quic_crypto_keys_t    new_keys[2]; /* a set of keys for use during key update */
  uint                     keys_avail;  /* bit set, LSB indexed by encryption level */
  uint                     key_phase;   /* current key phase - represents the current phase of the
                                           value of keys */
  uint                     key_phase_upd; /* set to 1 if we're undertaking a key update */

  fd_quic_stream_t         send_streams[1];      /* sentinel of list of streams needing action */
  fd_quic_stream_t         used_streams[1];      /* sentinel of list of used streams */
  /* invariant: an allocated stream must be in exactly one of the following lists:
     send_streams
     used_streams */

  /* stream id members */
  ulong next_stream_id[4];      /* next unused stream id by type - see rfc9000 2.1 */
                                /* next_stream_id is used for streams coming from the stream pool */

  ulong rx_hi_stream_id;    /* highest RX stream ID sent by peer + 4 */
  ulong rx_sup_stream_id;   /* highest allowed RX stream ID + 4 */
  ulong tx_next_stream_id;  /* stream ID to be used for new stream */
  ulong tx_sup_stream_id;   /* highest allowed TX stream ID + 4 */

  ulong max_concur_streams[4];  /* user set concurrent max */

  /* stream id limits */
  /* limits->stream_cnt */
  /*   used to size stream_map, and provides an upper limit on the temporary limits */
  /*   on streams */

  /* max_concur_streams */
  /*   temporary limit on the number of streams */
  /*   currently only applies to peers */
  /*   may be adjusted via fd_quic_conn_set_max_streams */

  /* limits->initial_stream_cnt */
  /*   new connections attempt to assign initial_stream_cnt streams from the pool */
  /*   for peer initiated streams */
  /*   however many streams are assigned at this point becomes the limit imposed */
  /*   on the peer */

  /* peer initiated streams */
  /* the peer will create streams at will up to our imposed limit via max_streams */
  /* frames */
  /* max_streams frames are derived from changes to sup_stream_id */

  /* self initiated streams */
  /* we can create streams at will up to the peer imposed limit in peer_sup_stream_id */
  /* these streams also come from the stream pool, and so the size of the stream pool */
  /* also imposes a limit on self initiated streams */

  /* rfc9000:
       19.11 Note that these frames (and the corresponding transport parameters)
               do not describe the number of streams that can be opened concurrently.
        4.6  Only streams with a stream ID less than
               (max_streams * 4 + first_stream_id_of_type) can be opened
        2.1  Stream types:
             0x00 Client-Initiated, Bidirectional
             0x01 Server-Initiated, Bidirectional
             0x02 Client-Initiated, Unidirectional
             0x03 Server-Initiated, Unidirectional */

  ulong rx_max_streams_unidir_ackd; /* value of MAX_STREAMS acked for UNIDIR */

  fd_quic_stream_map_t *  stream_map;           /* map stream_id -> stream */

  /* packet number info
     each encryption level maps to a packet number space
     0-RTT and 1-RTT both map to APPLICATION
     pkt_number[j] represents the minimum acceptable packet number
       "expected packet number"
       packets with a number lower than this will be dropped */
  ulong exp_pkt_number[3]; /* different packet number spaces:
                                 INITIAL, HANDSHAKE and APPLICATION */
  ulong pkt_number[3];     /* tx packet number by pn space */
  ulong last_pkt_number[3]; /* last (highest) packet numer seen */

  ushort ipv4_id;           /* ipv4 id field */

  /* buffer to send next */
  /* rename tx_buf, since it's easy to confuse with stream->tx_buf */
  /* must be at least FD_QUIC_MAX_UDP_PAYLOAD_SZ */
  uchar   tx_buf[2048];
  uchar * tx_ptr; /* ptr to free space in tx_scratch */
  ulong   tx_sz;  /* sz remaining at ptr */

  uint state;
  uint reason;     /* quic reason for closing. see FD_QUIC_CONN_REASON_* */
  uint app_reason; /* application reason for closing */
  uint int_reason; /* internal reason */

  fd_quic_ack_gen_t ack_gen[1];
  ulong             unacked_sz;  /* Number of received stream frame payload bytes pending ACK */
                                 /* Resets to zero when conn is rescheduled or ACKs are sent */

  /* TODO find better name than pool */
  fd_quic_pkt_meta_pool_t pkt_meta_pool;
  fd_quic_pkt_meta_t *    pkt_meta_mem;    /* owns the memory */

  /* flow control */
  ulong                tx_max_data;        /* the limit on the number of bytes we are allowed
                                              to send to the peer across all streams */
                                           /* even if a bytes on a stream are not received,
                                              higher offsets received imply the usage of those bytes,
                                              and they count against the max */
  ulong                tx_tot_data;        /* total of all bytes received across all streams
                                              and including implied bytes */
  ulong                rx_max_data;        /* the limit on the number of bytes the peer is allowed to
                                              send to us */
  ulong                rx_tot_data;        /* total of all bytes received across all streams
                                              and including implied bytes */
  ulong                rx_max_data_ackd;   /* max max_data acked by peer */

  uint                 flags;
# define FD_QUIC_CONN_FLAGS_MAX_DATA           (1u<<0u)
# define FD_QUIC_CONN_FLAGS_CLOSE_SENT         (1u<<1u)
# define FD_QUIC_CONN_FLAGS_MAX_STREAMS_UNIDIR (1u<<2u)
# define FD_QUIC_CONN_FLAGS_PING               (1u<<4u)
# define FD_QUIC_CONN_FLAGS_PING_SENT          (1u<<5u)

  uchar                spin_bit;                   /* spin bit used for latency measurements */

  /* max stream data per stream type */
  ulong                tx_initial_max_stream_data_uni;

  /* last tx packet num with max_data frame referring to this stream
     set to next_pkt_number to indicate a new max_data frame should be sent
     if we time out this packet (or possibly a later packet) we resend the frame
       and update this value */
  ulong                upd_pkt_number;

  /* current round-trip-time (FIXME this never updates) */
  ulong                rtt;

  /* highest peer encryption level */
  uchar                peer_enc_level;

  /* idle timeout arguments */
  ulong                idle_timeout;
  ulong                last_activity;

  /* rx_limit_pktnum is the newest inflight packet number in which
     the current rx_{sup_stream_id,max_data} values were sent to the
     peer.  (via MAX_STREAMS and MAX_DATA quota frames)
     FD_QUIC_PKT_NUM_UNUSED indicates that the peer ACked the latest
     quota update, and thus is in sync with the server.
     FD_QUIC_PKT_NUM_PENDING indicates that no packet with the current
     rx_{sup_stream_id,max_data} value was sent yet.  Will trigger a
     send attempt at the next fd_quic_conn_tx call. */
  ulong rx_limit_pktnum;

  ulong token_len;
  uchar token[ FD_QUIC_RETRY_MAX_TOKEN_SZ ];
};

FD_PROTOTYPES_BEGIN

/* returns the alignment requirement of fd_quic_conn_t */
FD_FN_CONST ulong
fd_quic_conn_align( void );

/* returns the footprint of the connection object for given limits */
FD_FN_PURE ulong
fd_quic_conn_footprint( fd_quic_limits_t const * );

/* called by fd_quic_new to initialize the connection objects
   used by fd_quic */
fd_quic_conn_t *
fd_quic_conn_new( void *                   mem,
                  fd_quic_t *              quic,
                  fd_quic_limits_t const * limits );

/* set the user-defined context value on the connection */
void
fd_quic_conn_set_context( fd_quic_conn_t * conn, void * context );

/* get the user-defined context value from a connection */
void *
fd_quic_conn_get_context( fd_quic_conn_t * conn );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_fd_quic_conn_h */
