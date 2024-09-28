#ifndef HEADER_fd_src_waltz_quic_fd_quic_conn_h
#define HEADER_fd_src_waltz_quic_fd_quic_conn_h

#include "fd_quic_common.h"
#include "crypto/fd_quic_crypto_suites.h"
#include "fd_quic_ack_tx.h"
#include "fd_quic_conn_id.h"
#include "fd_quic_pkt_meta.h"
#include "fd_rollset.h"
#include "fd_quic_tx_streams.h"

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

  uint               version;             /* QUIC version of the connection */

  ulong              next_service_time;   /* time service should be called next */
  ulong              sched_service_time;  /* time service is scheduled for, if in_service=1 */
  int                in_service;          /* whether the conn is in the service queue */

  /* we can have multiple connection ids */
  ulong              our_conn_id[ FD_QUIC_MAX_CONN_ID_PER_CONN ];

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
  fd_quic_endpoint_t peer[ FD_QUIC_MAX_CONN_ID_PER_CONN ];

  ulong              local_conn_id;       /* FIXME: hack to locally identify conns */

  ushort             our_conn_id_cnt;     /* number of connection ids */
  ushort             peer_cnt;            /* number of peer endpoints */

  ushort             cur_conn_id_idx;     /* currently used conn id */
  ushort             cur_peer_idx;        /* currently used peer endpoint */

  /* initial source connection id */
  fd_quic_conn_id_t  initial_source_conn_id;

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

  /* packet number info
     each encryption level maps to a packet number space
     0-RTT and 1-RTT both map to APPLICATION
     pkt_number[j] represents the minimum acceptable packet number
       "expected packet number"
       packets with a number lower than this will be dropped */
  ulong exp_pkt_number[3]; /* different packet number spaces:
                                 INITIAL, HANDSHAKE and APPLICATION */
  ulong pkt_number[3];     /* tx packet number by pn space */
  ulong last_pkt_number[3]; /* last (highest) packet number seen */

  ushort ipv4_id;           /* ipv4 id field */

  uint state;
  uint reason;     /* quic reason for closing. see FD_QUIC_CONN_REASON_* */
  uint app_reason; /* application reason for closing */
  uint int_reason; /* internal reason */

  fd_quic_pkt_meta_list_t sent_pkt_meta[ FD_QUIC_NUM_ENC_LEVELS ];

  fd_quic_ack_gen_t ack_gen[1];

  uint                 flags;
# define FD_QUIC_CONN_FLAGS_CLOSE_SENT         (1u<<1u)
# define FD_QUIC_CONN_FLAGS_PING               (1u<<4u)
# define FD_QUIC_CONN_FLAGS_PING_SENT          (1u<<5u)

  uchar                spin_bit;                   /* spin bit used for latency measurements */

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

  /* Stream related (server only) *************************************/

    /* rx_limit_pktnum is the newest inflight packet number in which
       the current rx_{sup_stream_id,max_data} values were sent to the
       peer.  (via MAX_STREAMS and MAX_DATA quota frames)

       FD_QUIC_PKT_NUM_UNUSED indicates that the peer ACked the latest
       quota update, and thus is in sync with the server.

       FD_QUIC_PKT_NUM_PENDING indicates that no packet with the current
       rx_{sup_stream_id,max_data} value was sent yet.  Will trigger a
       send attempt at the next fd_quic_conn_tx call. */
    ulong rx_limit_pktnum;

    /* rx_sup_stream_id: smallest stream ID greater than all allowed
       stream IDs. Never decreases.  When modified, rx_limit_pktnum
       should be set to FD_QUIC_PKT_NUM_PENDING. */
    ulong rx_sup_stream_id;

    /* rx_max_data: limit on the number of bytes the peer is allowed to
       send to us.  If a high offset is received on a stream, all prior
       bytes count towards this limit, even those that were not yet
       received due to reordering.  When modified, rx_limit_pktnum
       should be set to FD_QUIC_PKT_NUM_PENDING. */
    ulong rx_max_data;

    /* fin_streams: bit set of RX streams that were completed */
    fd_rollset_t fin_streams;

  /* Stream related (client only) *************************************/

    /* tx_streams: in-flight outgoing streams */
    fd_quic_tx_stream_treap_t tx_streams[1];

    /* invariant: an allocated stream must be in exactly one of the following lists:
       send_streams, wait_streams */
    fd_quic_tx_stream_dlist_t send_streams[1];
    fd_quic_tx_stream_dlist_t wait_streams[1];

    /* tx_next_stream_id: next unused stream ID, see rfc9000 2.1 */
    ulong tx_next_stream_id;

    /* tx_sup_stream_id: peer imposed limit on self-initiated streams */
    ulong tx_sup_stream_id;

    /* tx_max_data: the limit on the number of bytes we are allowed to
       send to the peer across all streams. */
    ulong tx_max_data;

    /* tx_tot_data: total number of bytes sent across all streams */
    ulong tx_tot_data;

    /* tx_initial_max_stream_data_uni: number of bytes we are permitted
       to send for each new opened stream (further bytes permitted via
       further MAX_STREAM_DATA frames from the server) */
    ulong tx_initial_max_stream_data_uni;

  /* End stream related ***********************************************/

  ulong token_len;
  uchar token[ FD_QUIC_RETRY_MAX_TOKEN_SZ ];
  /* next connection in the free list, or in service list */
  uint next;
};

typedef struct fd_quic_conn fd_quic_conn_t;

#define POOL_NAME  fd_quic_conn_pool
#define POOL_T     fd_quic_conn_t
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

FD_PROTOTYPES_BEGIN

/* fd_quic_conn_rx_window_cnt returns the number of new streams the
   peer may deliver. */

FD_FN_PURE static inline ulong
fd_quic_conn_rx_window_cnt( fd_quic_conn_t * const conn ) {
  long max = (long)conn->rx_sup_stream_id >> 2;
  long min = (long)conn->fin_streams.min;
  long cnt = (max - min) - fd_ulong_popcnt( conn->fin_streams.set );
  FD_LOG_NOTICE(( "max: %ld min: %ld cnt: %ld", max, min, cnt ));
  return (ulong)fd_long_max( 0, cnt );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_fd_quic_conn_h */
