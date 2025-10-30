#ifndef HEADER_fd_src_waltz_quic_fd_quic_conn_h
#define HEADER_fd_src_waltz_quic_fd_quic_conn_h

#include "fd_quic.h"
#include "fd_quic_common.h"
#include "fd_quic_ack_tx.h"
#include "fd_quic_stream.h"
#include "fd_quic_conn_id.h"
#include "crypto/fd_quic_crypto_suites.h"
#include "fd_quic_pkt_meta.h"
#include "fd_quic_svc_q.h"
#include "../fd_rtt_est.h"

#define FD_QUIC_CONN_STATE_INVALID            0 /* dead object / freed */
#define FD_QUIC_CONN_STATE_HANDSHAKE          1 /* currently doing handshaking with peer */
#define FD_QUIC_CONN_STATE_HANDSHAKE_COMPLETE 2 /* handshake complete, confirming with peer */
#define FD_QUIC_CONN_STATE_ACTIVE             3 /* connection established - data may be transferred */
#define FD_QUIC_CONN_STATE_PEER_CLOSE         4 /* peer requested close */
#define FD_QUIC_CONN_STATE_ABORT              5 /* connection terminating due to error */
#define FD_QUIC_CONN_STATE_CLOSE_PENDING      6 /* connection is closing */
#define FD_QUIC_CONN_STATE_DEAD               7 /* connection about to be freed */
#define FD_QUIC_CONN_STATE_CNT                8

FD_STATIC_ASSERT( FD_QUIC_CONN_STATE_CNT == sizeof(((fd_quic_metrics_t*)0)->conn_state_cnt)/sizeof(((fd_quic_metrics_t*)0)->conn_state_cnt[0]),
                  "metrics conn_state_cnt is the wrong size" );

#define FD_QUIC_REASON_CODES(X,SEP) \
  X(NO_ERROR                     , 0x00  , "No error"                                  ) SEP \
  X(INTERNAL_ERROR               , 0x01  , "Implementation error"                      ) SEP \
  X(CONNECTION_REFUSED           , 0x02  , "Server refuses a connection"               ) SEP \
  X(FLOW_CONTROL_ERROR           , 0x03  , "Flow control error"                        ) SEP \
  X(STREAM_LIMIT_ERROR           , 0x04  , "Too many streams opened"                   ) SEP \
  X(STREAM_STATE_ERROR           , 0x05  , "Frame received in invalid stream state"    ) SEP \
  X(FINAL_SIZE_ERROR             , 0x06  , "Change to final size"                      ) SEP \
  X(FRAME_ENCODING_ERROR         , 0x07  , "Frame encoding error"                      ) SEP \
  X(TRANSPORT_PARAMETER_ERROR    , 0x08  , "Error in transport parameters"             ) SEP \
  X(CONNECTION_ID_LIMIT_ERROR    , 0x09  , "Too many connection IDs received"          ) SEP \
  X(PROTOCOL_VIOLATION           , 0x0a  , "Generic protocol violation"                ) SEP \
  X(INVALID_TOKEN                , 0x0b  , "Invalid Token received"                    ) SEP \
  X(APPLICATION_ERROR            , 0x0c  , "Application error"                         ) SEP \
  X(CRYPTO_BUFFER_EXCEEDED       , 0x0d  , "CRYPTO data buffer overflowed"             ) SEP \
  X(KEY_UPDATE_ERROR             , 0x0e  , "Invalid packet protection update"          ) SEP \
  X(AEAD_LIMIT_REACHED           , 0x0f  , "Excessive use of packet protection keys"   ) SEP \
  X(NO_VIABLE_PATH               , 0x10  , "No viable network path exists"             ) SEP \
  X(CRYPTO_BASE                  , 0x100 , "0x0100-0x01ff CRYPTO_ERROR TLS alert code" ) SEP \
  X(HANDSHAKE_FAILURE            , 0x128 , "Handshake failed"                          )

enum {
# define COMMA ,
# define _(NAME,CODE,DESC) \
  FD_QUIC_CONN_REASON_##NAME = CODE
  FD_QUIC_REASON_CODES(_,COMMA)
# undef _
# undef COMMA
};

char const *
fd_quic_conn_reason_name( uint reason );


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
  /* 'PERSISTENT' means field should survive a conn_clear */
  uint               conn_idx;            /* connection index - PERSISTENT */
                                          /* connections are sized at runtime */
                                          /* storing the index avoids a division */
  uint               conn_gen;            /* generation of this connection slot - PERSISTENT */

  fd_quic_t *        quic;                /* PERSISTENT */
  void *             context;             /* user context */

  uint               server      : 1;     /* role from self POV: 0=client, 1=server */
  uint               established : 1;     /* used by clients to determine whether to
                                             switch the destination conn id used */
  uint               transport_params_set : 1;
  uint               called_conn_new : 1; /* whether we need to call conn_final on teardown */
  uint               visited : 1;         /* scratch bit, no strict definition */
  uint               key_phase : 1;
  uint               key_update : 1;

  /* metadata used by service queue */
  fd_quic_svc_timers_conn_meta_t svc_meta;

  /* Dlist membership  */
  uint               free_conn_next;

  ulong              our_conn_id;

  /* Save original retry_source_connection_id
   * This is used by clients to compare against the retry_source_connection_id
   * in the transport parameters as specified in rfc 9000 7.3 */
  fd_quic_conn_id_t  retry_src_conn_id;

  /* Host network endpoint. Used to determine src address and port */
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
  fd_quic_tls_hs_t * tls_hs;

  /* amount of handshake data already sent from head of queue */
  ulong hs_sent_bytes[4];

  /* amount of handshake data ack'ed by peer counted from head of queue */
  ulong hs_ackd_bytes[4];

  /* Keys for header and packet protection
       secrets:     Contains 'master' secrets used to derive other keys
       keys[e][d]:  Current pair of keys for each encryption level (e)
                    and direction (d==0 is incoming, d==1 is outgoing)
       new_keys[e]: App keys to use for the next key update.  Once app
                    keys are available these are always kept up-to-date
       keys_avail:  Bit set of available keys, LSB indexed by enc level */
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

  fd_quic_stream_map_t *  stream_map;           /* map stream_id -> stream - PERSISTENT */

  /* packet number info
     each encryption level maps to a packet number space
     0-RTT and 1-RTT both map to APPLICATION
     pkt_number[j] represents the minimum acceptable packet number
       "expected packet number"
       packets with a number lower than this will be dropped */
  ulong exp_pkt_number[3];  /* different packet number spaces:
                                 INITIAL, HANDSHAKE and APPLICATION */
  ulong pkt_number[3];      /* tx packet number by pn space */
  ulong last_pkt_number[3]; /* last (highest) packet number seen */

  ushort ipv4_id;           /* ipv4 id field */

  /* buffer to send next */
  /* must be at least FD_QUIC_MAX_UDP_PAYLOAD_SZ */
  uchar   tx_buf_conn[2048];
  uchar * tx_ptr; /* ptr to free space in tx_buf_conn */

  uint state;      /* PERSISTENT to keep state counters correct */
  uint reason;     /* quic reason for closing. see FD_QUIC_CONN_REASON_* */
  uint app_reason; /* application reason for closing */

  fd_quic_ack_gen_t ack_gen[1];
  ulong             unacked_sz;  /* Number of received stream frame payload bytes pending ACK */
                                 /* Resets to zero when conn is rescheduled or ACKs are sent */

  fd_quic_pkt_meta_tracker_t pkt_meta_tracker;

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

  /* idle timeout arguments */
  long                 idle_timeout_ns;
  long                 last_activity;
  long                 last_ack;
  long                 let_die_time_ns; /* stop keep-alive after this time */

  /* round trip time related members */
  fd_rtt_estimate_t rtt[1];
  float rtt_period_ns;         /* bound on time between RTT measurements */
  float peer_ack_delay_scale;  /* convert ACK delay units to nanoseconds */
  float peer_max_ack_delay_ns; /* peer max ack delay in nanoseconds */

  ulong token_len;
  uchar token[ FD_QUIC_RETRY_MAX_TOKEN_SZ ];

  fd_quic_conn_stream_rx_t srx[1];

  ulong used_pkt_meta;
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
ulong
fd_quic_conn_footprint( fd_quic_limits_t const * );

/* called by fd_quic_new to initialize the connection objects
   used by fd_quic */
fd_quic_conn_t *
fd_quic_conn_new( void *                   mem,
                  fd_quic_t *              quic,
                  fd_quic_limits_t const * limits );

/* clears all non-persistent members of the connection object */
static inline void
fd_quic_conn_clear( fd_quic_conn_t * conn ) {
  fd_quic_t            * quic       = conn->quic;
  uint                   conn_idx   = conn->conn_idx;
  uint                   conn_gen   = conn->conn_gen;
  uint                   conn_state = conn->state;
  fd_quic_stream_map_t * stream_map = conn->stream_map;

  fd_memset( conn, 0, sizeof( fd_quic_conn_t ) );

  conn->quic       = quic;
  conn->conn_idx   = conn_idx;
  conn->conn_gen   = conn_gen;
  conn->state      = conn_state;
  conn->stream_map = stream_map;
}

/* set the user-defined context value on the connection */
void
fd_quic_conn_set_context( fd_quic_conn_t * conn, void * context );

/* get the user-defined context value from a connection */
void *
fd_quic_conn_get_context( fd_quic_conn_t * conn );


/* set all conns to not visited, used for validation */
void
fd_quic_conn_validate_init( fd_quic_t * quic );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_fd_quic_conn_h */
