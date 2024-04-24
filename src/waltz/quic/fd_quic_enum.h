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
   ...FIN:          Not allowed to send, stream finished
   ...STREAM_STATE: Stream is not (yet) in valid state to send */
#define FD_QUIC_SEND_ERR_INVAL_STREAM (-1)
#define FD_QUIC_SEND_ERR_INVAL_CONN   (-2)
#define FD_QUIC_SEND_ERR_STREAM_FIN   (-3)
#define FD_QUIC_SEND_ERR_STREAM_STATE (-3)

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


#endif

