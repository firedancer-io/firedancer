#ifndef HEADER_fd_src_waltz_quic_fd_quic_conn_h
#define HEADER_fd_src_waltz_quic_fd_quic_conn_h

#include "fd_quic.h"
#include "fd_quic_stream.h"
#include "fd_quic_conn_id.h"
#include "crypto/fd_quic_crypto_suites.h"
#include "templ/fd_quic_transport_params.h"
#include "fd_quic_pkt_meta.h"
#include "templ/fd_quic_union.h"

#define FD_QUIC_CONN_STATE_INVALID            0 /* dead object / freed */
#define FD_QUIC_CONN_STATE_HANDSHAKE          1 /* currently doing handshaking with peer */
#define FD_QUIC_CONN_STATE_HANDSHAKE_COMPLETE 2 /* handshake complete, confirming with peer */
#define FD_QUIC_CONN_STATE_ACTIVE             3 /* connection established - data may be transferred */
#define FD_QUIC_CONN_STATE_PEER_CLOSE         4 /* peer requested close */
#define FD_QUIC_CONN_STATE_ABORT              5 /* connection terminating due to error */
#define FD_QUIC_CONN_STATE_CLOSE_PENDING      6 /* connection is closing */
#define FD_QUIC_CONN_STATE_DEAD               7 /* connection about to be freed */
#define FD_QUIC_CONN_STATE_CLOSING            8 /* waiting for a clean close (initiator) */
#define FD_QUIC_CONN_STATE_DRAIN              9 /* waiting for a clean close (peer) */

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
typedef struct fd_quic_ack        fd_quic_ack_t;

/* we track the range of offsets we acked for handshake and stream data
   these get freed when a packet containing the relevant acks is acked by the
     peer
   we try to send all acks stored each packet
     we will "over ack"
     it simplifies the ack logic since freeing one ack implies we can free
       all preceding acks. ack ids are only increasing
   enc_level of acks is implied by the list it's in */

struct fd_quic_ack {
  /* stores data about what was ack'ed */
  ulong           tx_pkt_number; /* the packet number this ack range was or will be transmitted in */
  ulong           tx_time;       /* the time the ack was sent, or should be sent */
  ulong           pkt_rcvd;      /* the time the original packet was received */
  fd_quic_range_t pkt_number;    /* range of packet numbers being acked */
  fd_quic_ack_t * next;          /* next ack in linked list - e.g. free list */
  uchar           enc_level;
  uchar           pn_space;
  uchar           flags;
# define FD_QUIC_ACK_FLAGS_SENT      (1u<<0u)
# define FD_QUIC_ACK_FLAGS_MANDATORY (1u<<1u)
};

struct fd_quic_conn {
  ulong              conn_idx;            /* connection index */
                                          /* connections are sized at runtime */
                                          /* storing the index avoids a division */

  fd_quic_t *        quic;
  void *             context;             /* user context */

  int                server;              /* role from self POV: 0=client, 1=server */
  int                established;         /* used by clients to determine whether to
                                             switch the destination conn id used */

  uint               version;             /* QUIC version of the connection */

  ulong              next_service_time;   /* time service should be called next */
  ulong              sched_service_time;  /* time service is scheduled for, if in_service=1 */
  int                in_service;          /* whether the conn is in the service queue */
  uchar              called_conn_new;     /* whether we need to call conn_final on teardown */

  /* we can have multiple connection ids */
  fd_quic_conn_id_t  our_conn_id[ FD_QUIC_MAX_CONN_ID_PER_CONN ];

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
  fd_quic_endpoint_t  peer[ FD_QUIC_MAX_CONN_ID_PER_CONN ];

  ulong              local_conn_id;       /* FIXME: hack to locally identify conns */

  ushort             our_conn_id_cnt;     /* number of connection ids */
  ushort             peer_cnt;            /* number of peer endpoints */

  ushort             cur_conn_id_idx;     /* currently used conn id */
  ushort             cur_peer_idx;        /* currently used peer endpoint */

  /* initial source connection id */
  fd_quic_conn_id_t  initial_source_conn_id;

  uint               tx_max_datagram_sz;  /* size of maximum datagram allowed by peer */

  /* handshake members */
  int                handshake_complete;  /* have we completed a successful handshake? */
  int                handshake_done_send; /* do we need to send handshake-done to peer? */
  int                handshake_done_ackd; /* was handshake_done ack'ed? */
  int                hs_data_empty;       /* has all hs_data been consumed? */
  fd_quic_tls_hs_t * tls_hs;

  /* expected handshake data offset - one per encryption level
     data received lower than this on a new packet is a protocol error
       duplicate packets should already have been dropped
     data received higher than this would be a gap
       ignore at present, assuming will be resent in order */
  ulong tx_crypto_offset[4]; /* next handshake data (crypto) offset
                                   one per encryption level */
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
  fd_quic_crypto_suite_t const * suites[4];
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

  /* use of supremum here:
       this is the smallest stream id greater than all the allowed stream ids
       so stream_id is valid if stream_id < sup_stream_id
       so sup_stream_id = max_stream_id + 4 */

  /* min_stream_id, sup_stream_id represent the "current range" */
  /* stream_ids within this range have been allocated to the connection */
  /* they may have been closed and deallocated */
  ulong min_stream_id[4];       /* minimum stream id by type */
  ulong sup_stream_id[4];       /* supremum stream id by type */
      /* sup_stream_id[j] == min_stream_id[j] implies no available stream_ids */
      /* valid range of stream ids is:                                        */
      /*     ( min_stream_id[j], sup_stream_id[j] ]                           */
      /* number of streams in valid range is:                                 */
      /* ( sup_stream_id[j] - min_stream_id[j]] ) / 4                         */

  /* peer_sup_stream_id[type] represents the peer imposed limit on self initiated */
  /* streams. */
  /* tgt_sup_stream_id[type] represents our limit on the stream_id of peer initiated */
  /* stream_ids */
  /* tgt_sup_stream_id is derived from max_concur_streams, cur_stream_cnt */
  /* and sup_stream_id thus: */
  /* tgt_sup_stream_id = sup_stream_id + ( max_concur_streams - cur_stream_cnt ) * 4 */
  ulong peer_sup_stream_id[4];  /* peer imposed supremum over stream_ids            */
  ulong tgt_sup_stream_id[4];   /* target value for sup_stream_id by type           */
                                /* sup_stream_id cannot drop                        */

  ulong max_concur_streams[4];  /* user set concurrent max */
  ulong cur_stream_cnt[4];      /* current number of streams by type */

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
  /* fd_quic_assign_streams assigns streams to connections in preparation for use */
  /* upon assignment, sup_stream_id and cur_stream_cnt are adjusted */

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

  /* some scratch space for frame encoding/decoding */
  fd_quic_frame_u frame_union;

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


  /* TODO find better name than pool */
  fd_quic_pkt_meta_pool_t pkt_meta_pool;
  ulong                   num_pkt_meta;
  fd_quic_pkt_meta_t *    pkt_meta_mem;    /* owns the memory */

  fd_quic_ack_t *      acks;               /* array of acks allocate during init */
  fd_quic_ack_t *      acks_free;          /* free list of acks */

  /* list of acks to be transmitted at each encryption level */
  fd_quic_ack_t *      acks_tx[4];
  fd_quic_ack_t *      acks_tx_end[4];     /* the ends of each list in acks_tx */

  ulong                peer_max_ack_delay; /* limit on the delay we intentionally impose on acks
                                              in nanoseconds */

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
# define FD_QUIC_CONN_FLAGS_MAX_STREAMS_BIDIR  (1u<<3u)
# define FD_QUIC_CONN_FLAGS_PING               (1u<<4u)
# define FD_QUIC_CONN_FLAGS_PING_SENT          (1u<<5u)

  uchar                spin_bit;                   /* spin bit used for latency measurements */

  /* max stream data per stream type */
  ulong                tx_initial_max_stream_data_uni;
  ulong                tx_initial_max_stream_data_bidi_local;
  ulong                tx_initial_max_stream_data_bidi_remote;
  ulong                rx_initial_max_stream_data_uni;
  ulong                rx_initial_max_stream_data_bidi_local;
  ulong                rx_initial_max_stream_data_bidi_remote;

  /* last tx packet num with max_data frame referring to this stream
     set to next_pkt_number to indicate a new max_data frame should be sent
     if we time out this packet (or possibly a later packet) we resend the frame
       and update this value */
  ulong                upd_pkt_number;

  /* current round-trip-time */
  ulong                rtt;

  /* highest peer encryption level */
  uchar                peer_enc_level;

  /* idle timeout arguments */
  ulong                idle_timeout;
  ulong                last_activity;

  /* next connection in the free list, or in service list */
  fd_quic_conn_t *     next;
  ulong token_len;
  uchar token[FD_QUIC_TOKEN_SZ_MAX];
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

/* fd_quic_handshake_complete checks whether the initial conn handshake
   is complete for the given conn.  Returns 1 if a handshake has been
   completed, 0 otherwise.  Will return 1 even if the conn has died
   since handshake. */

FD_QUIC_API FD_FN_PURE inline int
fd_quic_handshake_complete( fd_quic_conn_t * conn ) {
  return conn->handshake_complete;
}


/* set the max concurrent streams value for the specified type
   This is used to flow control the peer.

   type is one of:
     FD_QUIC_CONN_MAX_STREAM_TYPE_UNIDIR
     FD_QUIC_CONN_MAX_STREAM_TYPE_BIDIR */
FD_QUIC_API void
fd_quic_conn_set_max_streams( fd_quic_conn_t * conn, uint type, ulong stream_cnt );


/* get the current value for the concurrent streams for the specified type

   type is one of:
     FD_QUIC_CONN_MAX_STREAM_TYPE_UNIDIR
     FD_QUIC_CONN_MAX_STREAM_TYPE_BIDIR */
FD_QUIC_API ulong
fd_quic_conn_get_max_streams( fd_quic_conn_t * conn, uint type );


/* update the tree weight
   called whenever weight may have changed */
void
fd_quic_conn_update_weight( fd_quic_conn_t * conn, uint dirtype );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_quic_fd_quic_conn_h */
