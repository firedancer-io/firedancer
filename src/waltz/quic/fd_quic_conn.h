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

struct fd_quic_conn_stream_rx {
  ulong rx_hi_stream_id;    /* highest RX stream ID sent by peer + 4 */
  ulong rx_sup_stream_id;   /* highest allowed RX stream ID + 4 */

  ulong rx_max_data;        /* the limit on the number of bytes the peer is allowed to send to us */
  ulong rx_tot_data;        /* total of all bytes received across all streams and including implied bytes */
  ulong rx_max_data_ackd;   /* max max_data acked by peer */

  ulong rx_max_streams_unidir_ackd; /* value of MAX_STREAMS acked for UNIDIR */

  long  rx_streams_active;  /* FIXME: This is a user scratch field, not in use by fd_quic */

  /* FIXME add a TLB */
};

typedef struct fd_quic_conn_stream_rx fd_quic_conn_stream_rx_t;

struct fd_quic_conn {
  uint               conn_idx;            /* connection index */
                                          /* connections are sized at runtime */
                                          /* storing the index avoids a division */
  uint               conn_gen;            /* generation of this connection slot */

  fd_quic_t *        quic;
  void *             context;             /* user context */

  uint               server      : 1;     /* role from self POV: 0=client, 1=server */
  uint               established : 1;     /* used by clients to determine whether to
                                             switch the destination conn id used */
  uint               transport_params_set : 1;
  uint               called_conn_new : 1; /* whether we need to call conn_final on teardown */
  uint               visited : 1;         /* scratch bit, no strict definition */
  uint               key_phase : 1;
  uint               key_update : 1;

  /* Service queue dlist membership.  All active conns (state not INVALID)
     are in a service queue, FD_QUIC_SVC_TYPE_WAIT by default.
     Free conns (svc_type==UINT_MAX) are members of a singly linked list
     (only src_next set) */
  uint               svc_type;  /* FD_QUIC_SVC_{...} or UINT_MAX */
  uint               svc_prev;
  uint               svc_next;
  ulong              svc_time;  /* service may be delayed until this timestamp */

  ulong              our_conn_id;

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

  /* initial source connection id */
  ulong              initial_source_conn_id;

  uint               tx_max_datagram_sz;  /* size of maximum datagram allowed by peer */

  /* handshake members */
  uint               handshake_complete  : 1; /* have we completed a successful handshake? */
  uint               handshake_done_send : 1; /* do we need to send handshake-done to peer? */
  uint               handshake_done_ackd : 1; /* was handshake_done ack'ed? */
  uint               hs_data_empty       : 1; /* has all hs_data been consumed? */
  fd_quic_tls_hs_t * tls_hs;

  /* amount of handshake data already sent from head of queue */
  ulong hs_sent_bytes[4];

  /* amount of handshake data ack'ed by peer counted from head of queue */
  ulong hs_ackd_bytes[4];

  /* Keys for header and packet protection
       secrets:    Contains 'master' secrets used to derive other keys
       keys:       Current pair of keys for each encryption level
       new_keys:   App keys to use for the next key update.  Once app
                   keys are available these are always kept up-to-date
       keys_avail: Bit set of available keys, LSB indexed by enc level */
  fd_quic_crypto_secrets_t secrets;
  fd_quic_crypto_keys_t    keys[FD_QUIC_NUM_ENC_LEVELS][2];
  fd_quic_crypto_keys_t    new_keys[2];
  uint                     keys_avail;

  fd_quic_stream_t         send_streams[1];      /* sentinel of list of streams needing action */
  fd_quic_stream_t         used_streams[1];      /* sentinel of list of used streams */
  /* invariant: an allocated stream must be in exactly one of the following lists:
     send_streams
     used_streams */

  /* stream id members */
  ulong tx_next_stream_id;  /* stream ID to be used for new stream */
  ulong tx_sup_stream_id;   /* highest allowed TX stream ID + 4 */

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

  uint                 flags;
# define FD_QUIC_CONN_FLAGS_MAX_DATA           (1u<<0u)
# define FD_QUIC_CONN_FLAGS_CLOSE_SENT         (1u<<1u)
# define FD_QUIC_CONN_FLAGS_MAX_STREAMS_UNIDIR (1u<<2u)
# define FD_QUIC_CONN_FLAGS_PING               (1u<<4u)
# define FD_QUIC_CONN_FLAGS_PING_SENT          (1u<<5u)

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

  fd_quic_conn_stream_rx_t srx[1];
};

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_quic_conn_uid( fd_quic_conn_t const * conn ) {
  return ( (ulong)conn->conn_idx << 32UL ) | ( (ulong)conn->conn_gen );
}

FD_FN_CONST static inline uint
fd_quic_conn_uid_idx( ulong conn_uid ) {
  return (uint)( conn_uid >> 32UL );
}

FD_FN_CONST static inline uint
fd_quic_conn_uid_gen( ulong conn_uid ) {
  return (uint)( conn_uid & 0xffffffffUL );
}

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
