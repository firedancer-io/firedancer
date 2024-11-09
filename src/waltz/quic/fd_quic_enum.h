#ifndef HEADER_fd_src_tango_quic_fd_quic_enum_h
#define HEADER_fd_src_tango_quic_fd_quic_enum_h


/* FD_QUIC_STREAM_TYPE_* indicate stream type (two least significant
   bits of a stream ID) */
#define FD_QUIC_STREAM_TYPE_BIDI_CLIENT 0
#define FD_QUIC_STREAM_TYPE_BIDI_SERVER 1
#define FD_QUIC_STREAM_TYPE_UNI_CLIENT  2
#define FD_QUIC_STREAM_TYPE_UNI_SERVER  3

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

/* FD_QUIC_SHORTEST_PKT is the smallest possible byte size of a QUIC v1
   packet. */
#define FD_QUIC_SHORTEST_PKT (16)

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
   ...FIN:          Not allowed to send, stream finished
   ...STREAM_STATE: Stream is not (yet) in valid state to send
   ...FLOW:         Out of buffer space, retry later */
#define FD_QUIC_SEND_ERR_INVAL_STREAM (-1)
#define FD_QUIC_SEND_ERR_INVAL_CONN   (-2)
#define FD_QUIC_SEND_ERR_FIN          (-3)
#define FD_QUIC_SEND_ERR_STREAM_STATE (-4)
#define FD_QUIC_SEND_ERR_FLOW         (-5)

/* FD_QUIC_MIN_CONN_ID_CNT: min permitted conn ID count per conn */
#define FD_QUIC_MIN_CONN_ID_CNT (4UL)

/* FD_QUIC_DEFAULT_SPARSITY: default fd_quic_limits_t->conn_id_sparsity */
#define FD_QUIC_DEFAULT_SPARSITY (2.5)

/* FD_QUIC_STREAM_NOTIFY_* indicate stream notification types.
   All events indicate that stream lifetime has ended and no more
   callbacks will be generated for it.  The stream object will be freed
   after event delivery.

   ...END:        All stream data was transmitted successfully
   ...PEER_RESET: Peer has ceased sending non-gracefully
   ...PEER_STOP:  Peer has requested us to stop sending
   ...DROP:       Local side dropped the stream
   ...CONN:       Stream aborted due to conn close */
#define FD_QUIC_STREAM_NOTIFY_END        (0)
#define FD_QUIC_STREAM_NOTIFY_PEER_RESET (1)
#define FD_QUIC_STREAM_NOTIFY_PEER_STOP  (2)
#define FD_QUIC_STREAM_NOTIFY_DROP       (3)
#define FD_QUIC_STREAM_NOTIFY_CONN       (4)

/* FD_QUIC_PKT_TYPE_{...}: QUIC v1 packet types.
   INITIAL, ZERO_RTT, HANDSHAKE, and RETRY match the long_packet_type
   field. */
#define FD_QUIC_PKT_TYPE_INITIAL   (0)
#define FD_QUIC_PKT_TYPE_ZERO_RTT  (1)
#define FD_QUIC_PKT_TYPE_HANDSHAKE (2)
#define FD_QUIC_PKT_TYPE_RETRY     (3)
#define FD_QUIC_PKT_TYPE_ONE_RTT   (4)

/* FD_QUIC_PKT_COALESCE_LIMIT controls how many QUIC long packets are
   handled in the same datagram. */
#define FD_QUIC_PKT_COALESCE_LIMIT (4)

/* AES-128-GCM secret params */
#define FD_QUIC_INITIAL_SECRET_SZ 32
#define FD_QUIC_SECRET_SZ         32
#define FD_QUIC_HP_SAMPLE_SZ      16
#define FD_QUIC_NONCE_SZ          12

/* FD_QUIC_RETRY_MAX_TOKEN_SZ is the max permitted Retry Token size that
   fd_quic clients will accept.  This is unfortunately not specified by
   RFC 9000. */
#define FD_QUIC_RETRY_MAX_TOKEN_SZ (256UL)
/* RETRY secret size in bytes */
#define FD_QUIC_RETRY_SECRET_SZ 16
/* RETRY iv size in bytes */
#define FD_QUIC_RETRY_IV_SZ 12
/* Retry token lifetime in seconds */
#define FD_QUIC_RETRY_TOKEN_LIFETIME (3)

#endif

