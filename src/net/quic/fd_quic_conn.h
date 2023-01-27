#ifndef HEADER_fd_quic_conn_h
#define HEADER_fd_quic_conn_h

#include "fd_quic_config.h"
#include "../../util/fd_util.h"
#include "fd_quic_stream.h"
#include "fd_quic_conn_id.h"
#include "crypto/fd_quic_crypto_suites.h"
#include "tls/fd_quic_tls.h"
#include "templ/fd_quic_transport_params.h"

enum {
  FD_QUIC_CONN_STATE_HANDSHAKE,          /* currently doing handshaking with peer */
  FD_QUIC_CONN_STATE_HANDSHAKE_COMPLETE, /* handshake complete, confirming with peer */
  FD_QUIC_CONN_STATE_ACTIVE,             /* connection established - data may be transferred */
  FD_QUIC_CONN_STATE_PEER_CLOSE,         /* peer requested close */
  FD_QUIC_CONN_STATE_ABORT,              /* connection terminating due to error */
  FD_QUIC_CONN_STATE_CLOSE_PENDING,      /* connection is closing */
  FD_QUIC_CONN_STATE_DEAD                /* connection about to be freed */
};

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
/* 0x0100-0x01ff    CRYPTO_ERROR    TLS alert code*/
  FD_QUIC_CONN_REASON_CRYPTO_BASE                  = 0x100    /* base for crypto errors */
};

typedef struct fd_quic            fd_quic_t;
typedef struct fd_quic_conn       fd_quic_conn_t;
typedef struct fd_quic_pkt_meta   fd_quic_pkt_meta_t;
typedef struct fd_quic_ack        fd_quic_ack_t;
typedef struct fd_quic_range      fd_quic_range_t;

struct fd_quic_range {
  /* offset in [ offset_lo, offset_hi ) is considered inside the range */
  /* a zero-initialized range will be empty [0,0) */
  uint64_t offset_lo;
  uint64_t offset_hi;
};


/* fd_quic_pkt_meta

   tracks the metadata of data sent to the peer
   used when acks arrive to determine what is being acked specifically */
struct fd_quic_pkt_meta {
  /* stores meta data about what was sent in the identified packet */
  uint64_t        pkt_number;  /* the packet number */
  uint8_t         enc_level;   /* every packet is sent at a specific enc_level */
  uint8_t         pn_space;    /* packet number space (must be consistent with enc_level)  */

  /* does the referenced packet contain:
           FD_QUIC_PKT_META_FLAGS_HS_DATA           handshake data
           FD_QUIC_PKT_META_FLAGS_STREAM            stream data
           FD_QUIC_PKT_META_FLAGS_HS_DONE           handshake-done frame
           FD_QUIC_PKT_META_FLAGS_MAX_DATA          max_data frame
           FD_QUIC_PKT_META_FLAGS_MAX_STREAM_DATA   max_stream_data frame
           FD_QUIC_PKT_META_FLAGS_MAX_STREAMS       max_streams frame
           FD_QUIC_PKT_META_FLAGS_CLOSE             close frame */
  unsigned        flags;       /* flags */
# define          FD_QUIC_PKT_META_FLAGS_HS_DATA         (1u<<0u)
# define          FD_QUIC_PKT_META_FLAGS_STREAM          (1u<<1u)
# define          FD_QUIC_PKT_META_FLAGS_HS_DONE         (1u<<2u)
# define          FD_QUIC_PKT_META_FLAGS_MAX_DATA        (1u<<3u)
# define          FD_QUIC_PKT_META_FLAGS_MAX_STREAM_DATA (1u<<4u)
# define          FD_QUIC_PKT_META_FLAGS_MAX_STREAMS     (1u<<5u)
# define          FD_QUIC_PKT_META_FLAGS_ACK             (1u<<6u)
# define          FD_QUIC_PKT_META_FLAGS_CLOSE           (1u<<7u)
  fd_quic_range_t range;       /* range of bytes referred to by this meta */
                               /* stream data or crypto data */
                               /* we currently do not put both in the same packet */
  uint64_t        stream_id;   /* if this contains stream data, the stream id, else zero */

  /* TODO add timeout */

  fd_quic_pkt_meta_t * next;   /* next in current list */
};


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
  uint64_t        tx_pkt_number; /* the packet number this ack range was or will be transmitted in */
  uint64_t        tx_time;       /* the time the ack was sent, or should be sent */
  uint64_t        pkt_rcvd;      /* the time the original packet was received */
  fd_quic_range_t pkt_number;    /* range of packet numbers being acked */
  fd_quic_ack_t * next;          /* next ack in linked list - e.g. free list */
  uint8_t         enc_level;
  uint8_t         pn_space;
  uint8_t         flags;
# define FD_QUIC_ACK_FLAGS_SENT      (1u<<0u)
# define FD_QUIC_ACK_FLAGS_MANDATORY (1u<<1u)
};


struct fd_quic_conn {
  fd_quic_t *        quic;

  int                server;             /* 0=client, 1=server */
  int                established;        /* used by clients to determine whether to
                                            switch the destination conn id used */

  uint32_t           version;            /* QUIC version of the connection */

  uint64_t           next_service_time;  /* time service should be called next */

  fd_quic_host_cfg_t host;               /* host configuration */

  /* we can have multiple connection ids */
  fd_quic_conn_id_t  our_conn_id[FD_QUIC_MAX_CONN_ID_PER_CONN];

  /* the peer may have multiple connection ids and ip:port */
  fd_quic_endpoint_t peer[FD_QUIC_MAX_CONN_ID_PER_CONN];

  /* the original connection id is specified by the client */
  fd_quic_conn_id_t  orig_conn_id;       /* unused by client connections */

  uint16_t           our_conn_id_cnt;    /* number of connection ids */
  uint16_t           peer_cnt;           /* number of peer endpoints */

  uint16_t           cur_conn_id_idx;    /* currently used conn id */
  uint16_t           cur_peer_idx;       /* currently used peer endpoint */

  unsigned           max_datagram_sz;    /* size of maximum datagram allowed */

  /* handshake members */
  int                handshake_complete; /* have we completed a successful handshake? */
  int                handshake_done;     /* do we need to send handshake-done to peer? */
  fd_quic_tls_hs_t * tls_hs;

  /* expected handshake data offset - one per encryption level
     data received lower than this on a new packet is a protocol error
       duplicate packets should already have been dropped
     data received higher than this would be a gap
       ignore at present, assuming will be resent in order */
  uint64_t tx_crypto_offset[4]; /* next handshake data (crypto) offset
                                   one per encryption level */
  uint64_t rx_crypto_offset[4]; /* expected handshake data (crypto) offset
                                   one per encryption level */

  /* amount of handshade data already sent from head of queue */
  size_t hs_sent_bytes[4];

  /* secret members */
  fd_quic_crypto_secrets_t secrets;
  fd_quic_crypto_keys_t    keys[4][2]; /* a set of keys for each of the encoding levels, and for client/server */
  fd_quic_crypto_suite_t * suites[4];

  size_t             tot_num_streams;
  fd_quic_stream_t * streams;

  /* packet number info
     each encryption level maps to a packet number space
     0-RTT and 1-RTT both map to APPLICATION
     pkt_number[j] represents the minimum acceptable packet number 
       "expected packet number"
       packets with a number lower than this will be dropped */
  uint64_t exp_pkt_number[3]; /* different packet number spaces:
                                 INITIAL, HANDSHAKE and APPLICATION */
  uint64_t pkt_number[3];     /* tx packet number by pn space */

  uint16_t ipv4_id;           /* ipv4 id field */

  /* TODO these scratch areas may be moved to quic */
  /* some buffer space for encryption/decryption */
  uchar crypt_scratch[2048];

  /* some scratch space for frame encoding/decoding */
  uchar frame_scratch[2048];

  /* buffer to send next */
  uchar   tx_buf[2048];
  uchar * tx_ptr; /* ptr to free space in tx_scratch */
  size_t  tx_sz;  /* sz remaining at ptr */

  /* the peer transport parameters */
  fd_quic_transport_params_t peer_transport_params;

  unsigned state;
  unsigned reason;     /* quic reason for closing. see FD_QUIC_CONN_REASON_* */
  unsigned app_reason; /* application reason for closing */


  /* sent packet metadata */
  /* TODO */
  /* 3 linked lists of packet metadata for tracking what data was sent 
     one for each packet space:
       initial
       handshake
       app data */
  /* once a packet is ready to send, a metadata structure is added
     here, to the end of the relevant list
     if no metadata is available, we can defer, or do a reclaim/resend */
  /* we keep metadata for the following:
       sent stream offset range
         streams include:
           data streams
           crypto streams - one for each enc_level
       acks sent */

  /* indicates we need to send "handshake done"
     cleared once packet is acked */
  int handshake_done_send;

  uint64_t next_stream_id[4];      /* next stream id by type - see rfc9000 2.1 */

  unsigned max_concur_streams;     /* configured max concurrent streams by connection and type */
  unsigned max_streams[4];         /* maximum stream id by type */
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

  unsigned num_streams[4];         /* current number of streams of each type */

  fd_quic_pkt_meta_t * pkt_meta;           /* pkt_meta contiguous storage */
  fd_quic_pkt_meta_t * pkt_meta_free;      /* pkt_meta free list */
  fd_quic_pkt_meta_t * pkt_meta_tx[4];     /* pkt metadata head per enc level */
  fd_quic_pkt_meta_t * pkt_meta_tx_end[4]; /* pkt metadata end  per enc level */

  fd_quic_ack_t *      acks;               /* array of acks allocate during init */
  fd_quic_ack_t *      acks_free;          /* free list of acks */

  /* list of acks to be transmitted at each encryption level */
  fd_quic_ack_t *      acks_tx[4];
  fd_quic_ack_t *      acks_tx_end[4];     /* the ends of each list in acks_tx */

  uint64_t             peer_max_ack_delay; /* limit on the delay we intensionally impose on acks
                                              in nanoseconds */

  /* flow control */
  size_t               tx_max_data;        /* the limit on the number of bytes we are allowed
                                              to send to the peer across all streams */
                                           /* even if a bytes on a stream are not received,
                                              higher offsets received imply the usage of those bytes,
                                              and they count against the max */
  size_t               tx_tot_data;        /* total of all bytes received across all streams
                                              and including implied bytes */
  size_t               rx_max_data;        /* the limit on the number of bytes the peer is allowed to
                                              send to us */
  size_t               rx_tot_data;        /* total of all bytes received across all streams
                                              and including implied bytes */

  uint8_t              flags;
# define FD_QUIC_CONN_FLAGS_MAX_DATA   (1u<<0u)
# define FD_QUIC_CONN_FLAGS_CLOSE_SENT (1u<<1u)

  /* max stream data per stream type */
  size_t               tx_initial_max_stream_data_uni;
  size_t               tx_initial_max_stream_data_bidi_local;
  size_t               tx_initial_max_stream_data_bidi_remote;

  /* last tx packet num with max_data frame refering to this stream
     set to next_pkt_number to indicate a new max_data frame should be sent
     if we time out this packet (or possibly a later packet) we resend the frame
       and update this value */
  uint64_t             upd_pkt_number;

  /* for timing out data and resending
     should be at least the smoothed round-trip-time */
  uint64_t             base_timeout;

  fd_quic_conn_t *     next;               /* next connection in the free list, or in service list */
};

/* returns the alignment requirement of fd_quic_conn_t */
FD_FN_CONST
ulong
fd_quic_conn_align();

/* returns the footprint of the connection object given the number of streams */
FD_FN_CONST
ulong
fd_quic_conn_footprint( fd_quic_config_t const * config );


fd_quic_conn_t *
fd_quic_conn_new( void * mem, fd_quic_t * quic, fd_quic_config_t const * config );

#endif

