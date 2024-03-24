#ifndef HEADER_fd_quic_transport_params_h
#define HEADER_fd_quic_transport_params_h

#include <stdio.h>

// TODO set proper defaults, and delete DFT_UNKNOWN
#define DFT_UNKNOWN 0

//23456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789
//........1.........2.........3.........4.........5.........6.........7.........8.........9.........0.........
#define FD_QUIC_TRANSPORT_PARAMS(X, ...)                                               \
X( original_destination_connection_id,                                                 \
  0x00,                                                                                \
  CONN_ID,                                                                             \
  DFT_UNKNOWN,                                                                         \
  "This parameter is the value of the Destination Connection ID field from the "       \
  "first Initial packet sent by the client; see Section 7.3. This transport "          \
  "parameter is only sent by a server.",                                               \
  __VA_ARGS__ )                                                                        \
X( max_idle_timeout,                                                                   \
  0x01,                                                                                \
  VARINT,                                                                              \
  DFT_UNKNOWN,                                                                         \
  "The maximum idle timeout is a value in milliseconds that is encoded as an "         \
  "integer; see (Section 10.1). Idle timeout is disabled when both endpoints omit "    \
  "this transport parameter or specify a value of 0.",                                 \
  __VA_ARGS__ )                                                                        \
X( stateless_reset_token,                                                              \
  0x02,                                                                                \
  TOKEN,                                                                               \
  DFT_UNKNOWN,                                                                         \
  "A stateless reset token is used in verifying a stateless reset; see Section "       \
  "10.3. This parameter is a sequence of 16 bytes. This transport parameter MUST "     \
  "NOT be sent by a client but MAY be sent by a server. A server that does not send "  \
  "this transport parameter cannot use stateless reset (Section 10.3) for the "        \
  "connection ID negotiated during the handshake.",                                    \
  __VA_ARGS__ )                                                                        \
X( max_udp_payload_size,                                                               \
  0x03,                                                                                \
  VARINT,                                                                              \
  65527,                                                                               \
  "The maximum UDP payload size parameter is an integer value that limits the size "   \
  "of UDP payloads that the endpoint is willing to receive. UDP datagrams with "       \
  "payloads larger than this limit are not likely to be processed by the receiver. "   \
  "The default for this parameter is the maximum permitted UDP payload of 65527. "     \
  "Values below 1200 are invalid.\n"                                                   \
  "This limit does act as an additional constraint on datagram size in the same way "  \
  "as the path MTU, but it is a property of the endpoint and not the path; see "       \
  "Section 14. It is expected that this is the space an endpoint dedicates to "        \
  "holding incoming packets.",                                                         \
  __VA_ARGS__ )                                                                        \
X( initial_max_data,                                                                   \
  0x04,                                                                                \
  VARINT,                                                                              \
  DFT_UNKNOWN,                                                                         \
  "The initial maximum data parameter is an integer value that contains the initial "  \
  "value for the maximum amount of data that can be sent on the connection. This is "  \
  "equivalent to sending a MAX_DATA (Section 19.9) for the connection immediately "    \
  "after completing the handshake.",                                                   \
  __VA_ARGS__ )                                                                        \
X( initial_max_stream_data_bidi_local,                                                 \
  0x05,                                                                                \
  VARINT,                                                                              \
  DFT_UNKNOWN,                                                                         \
  "This parameter is an integer value specifying the initial flow control limit for "  \
  "locally initiated bidirectional streams. This limit applies to newly created "      \
  "bidirectional streams opened by the endpoint that sends the transport parameter. "  \
  "In client transport parameters, this applies to streams with an identifier with "   \
  "the least significant two bits set to 0x00; in server transport parameters, this "  \
  "applies to streams with the least significant two bits set to 0x01.",               \
  __VA_ARGS__ )                                                                        \
X( initial_max_stream_data_bidi_remote,                                                \
  0x06,                                                                                \
  VARINT,                                                                              \
  DFT_UNKNOWN,                                                                         \
  "This parameter is an integer value specifying the initial flow control limit for "  \
  "peer-initiated bidirectional streams. This limit applies to newly created "         \
  "bidirectional streams opened by the endpoint that receives the transport "          \
  "parameter. In client transport parameters, this applies to streams with an "        \
  "identifier with the least significant two bits set to 0x01; in server transport "   \
  "parameters, this applies to streams with the least significant two bits set to "    \
  "0x00.",                                                                             \
  __VA_ARGS__ )                                                                        \
X( initial_max_stream_data_uni,                                                        \
  0x07,                                                                                \
  VARINT,                                                                              \
  DFT_UNKNOWN,                                                                         \
  "This parameter is an integer value specifying the initial flow control limit for "  \
  "unidirectional streams. This limit applies to newly created unidirectional "        \
  "streams opened by the endpoint that receives the transport parameter. In client "   \
  "transport parameters, this applies to streams with an identifier with the least "   \
  "significant two bits set to 0x03; in server transport parameters, this applies "    \
  "to streams with the least significant two bits set to 0x02.",                       \
  __VA_ARGS__ )                                                                        \
X( initial_max_streams_bidi,                                                           \
  0x08,                                                                                \
  VARINT,                                                                              \
  DFT_UNKNOWN,                                                                         \
  "The initial maximum bidirectional streams parameter is an integer value that "      \
  "contains the initial maximum number of bidirectional streams the endpoint that "    \
  "receives this transport parameter is permitted to initiate. If this parameter is "  \
  "absent or zero, the peer cannot open bidirectional streams until a MAX_STREAMS "    \
  "frame is sent. Setting this parameter is equivalent to sending a MAX_STREAMS "      \
  "(Section 19.11) of the corresponding type with the same value.",                    \
  __VA_ARGS__ )                                                                        \
X( initial_max_streams_uni,                                                            \
  0x09,                                                                                \
  VARINT,                                                                              \
  DFT_UNKNOWN,                                                                         \
  "The initial maximum unidirectional streams parameter is an integer value that "     \
  "contains the initial maximum number of unidirectional streams the endpoint that "   \
  "receives this transport parameter is permitted to initiate. If this parameter is "  \
  "absent or zero, the peer cannot open unidirectional streams until a MAX_STREAMS "   \
  "frame is sent. Setting this parameter is equivalent to sending a MAX_STREAMS "      \
  "(Section 19.11) of the corresponding type with the same value.",                    \
  __VA_ARGS__ )                                                                        \
X( ack_delay_exponent,                                                                 \
  0x0a,                                                                                \
  VARINT,                                                                              \
  DFT_UNKNOWN,                                                                         \
  "The acknowledgment delay exponent is an integer value indicating an exponent "      \
  "used to decode the ACK Delay field in the ACK frame (Section 19.3). If this "       \
  "value is absent, a default value of 3 is assumed (indicating a multiplier of 8).\n" \
  "Values above 20 are invalid.",                                                      \
  __VA_ARGS__ )                                                                        \
X( max_ack_delay,                                                                      \
  0x0b,                                                                                \
  VARINT,                                                                              \
  DFT_UNKNOWN,                                                                         \
  "The maximum acknowledgment delay is an integer value indicating the maximum "       \
  "amount of time in milliseconds by which the endpoint will delay sending "           \
  "acknowledgments. This value SHOULD include the receiver's expected delays in "      \
  "alarms firing. For example, if a receiver sets a timer for 5ms and alarms "         \
  "commonly fire up to 1ms late, then it should send a max_ack_delay of 6ms. If "      \
  "this value is absent, a default of 25 milliseconds is assumed. Values of 214 or "   \
  "greater are invalid.",                                                              \
  __VA_ARGS__ )                                                                        \
X( disable_active_migration,                                                           \
  0x0c,                                                                                \
  ZERO_LENGTH,                                                                         \
  DFT_UNKNOWN,                                                                         \
  "The disable active migration transport parameter is included if the endpoint "      \
  "does not support active connection migration (Section 9) on the address being "     \
  "used during the handshake. An endpoint that receives this transport parameter "     \
  "MUST NOT use a new local address when sending to the address that the peer used "   \
  "during the handshake. This transport parameter does not prohibit connection "       \
  "migration after a client has acted on a preferred_address transport parameter.\n"   \
  "This parameter is a zero-length value.",                                            \
  __VA_ARGS__ )                                                                        \
X( preferred_address,                                                                  \
  0x0d,                                                                                \
  PREFERRED_ADDRESS,                                                                   \
  DFT_UNKNOWN,                                                                         \
  "The server's preferred address is used to effect a change in server address at "    \
  "the end of the handshake, as described in Section 9.6. This transport parameter "   \
  "is only sent by a server. Servers MAY choose to only send a preferred address of "  \
  "one address family by sending an all-zero address and port (0.0.0.0:0 or [::]:0) "  \
  "for the other family. IP addresses are encoded in network byte order.\n"            \
  "The preferred_address transport parameter contains an address and port for both "   \
  "IPv4 and IPv6. The four-byte IPv4 Address field is followed by the associated "     \
  "two-byte IPv4 Port field. This is followed by a 16-byte IPv6 Address field and "    \
  "two-byte IPv6 Port field. After address and port pairs, a Connection ID Length "    \
  "field describes the length of the following Connection ID field. Finally, a "       \
  "16-byte Stateless Reset Token field includes the stateless reset token "            \
  "associated with the connection ID. The format of this transport parameter is "      \
  "shown in Figure 22 below.",                                                         \
  __VA_ARGS__ )                                                                        \
X( active_connection_id_limit,                                                         \
  0x0e,                                                                                \
  VARINT,                                                                              \
  2,                                                                                   \
  "This is an integer value specifying the maximum number of connection IDs from "     \
  "the peer that an endpoint is willing to store. This value includes the "            \
  "connection ID received during the handshake, that received in the "                 \
  "preferred_address transport parameter, and those received in NEW_CONNECTION_ID "    \
  "frames. The value of the active_connection_id_limit parameter MUST be at least "    \
  "2. An endpoint that receives a value less than 2 MUST close the connection with "   \
  "an error of type TRANSPORT_PARAMETER_ERROR. If this transport parameter is "        \
  "absent, a default of 2 is assumed. If an endpoint issues a zero-length "            \
  "connection ID, it will never send a NEW_CONNECTION_ID frame and therefore "         \
  "ignores the active_connection_id_limit value received from its peer.",              \
  __VA_ARGS__ )                                                                        \
X( initial_source_connection_id,                                                       \
  0x0f,                                                                                \
  CONN_ID,                                                                             \
  DFT_UNKNOWN,                                                                         \
  "This is the value that the endpoint included in the Source Connection ID field "    \
  "of the first Initial packet it sends for the connection; see Section 7.3.",         \
  __VA_ARGS__ )                                                                        \
X( retry_source_connection_id,                                                         \
  0x10,                                                                                \
  CONN_ID,                                                                             \
  DFT_UNKNOWN,                                                                         \
  "This is the value that the server included in the Source Connection ID field of "   \
  "a Retry packet; see Section 7.3. This transport parameter is only sent by a "       \
  "server.",                                                                           \
  __VA_ARGS__ )

void
fd_quic_dump_transport_param_desc( FILE * out );

// TODO verify max length on these - CONN_ID and TOKEN
// PREFERRED_ADDRESS is incomplete
#define FD_QUIC_MBR_TYPE_VARINT(NAME,TYPE)            \
  ulong  NAME;                                        \
  uchar  NAME##_present;
#define FD_QUIC_MBR_TYPE_CONN_ID(NAME,TYPE)           \
  uchar  NAME##_len;                                  \
  uchar  NAME[20];                                    \
  uchar  NAME##_present;
#define FD_QUIC_MBR_TYPE_ZERO_LENGTH(NAME,TYPE)       \
  uchar  NAME;                                        \
  uchar  NAME##_present;
#define FD_QUIC_MBR_TYPE_TOKEN(NAME,TYPE)             \
  uint   NAME##_len;                                  \
  uchar  NAME[1024];                                  \
  uchar  NAME##_present;
#define FD_QUIC_MBR_TYPE_PREFERRED_ADDRESS(NAME,TYPE) \
  uint   NAME##_len;                                  \
  uchar  NAME[1024];                                  \
  uchar  NAME##_present;

struct fd_quic_transport_params {
#define __( NAME, ID, TYPE, DFT, DESC, ... ) \
  FD_QUIC_MBR_TYPE_##TYPE(NAME,TYPE)
  FD_QUIC_TRANSPORT_PARAMS( __, _ )
#undef __
};
typedef struct fd_quic_transport_params fd_quic_transport_params_t;

#define FD_QUIC_TRANSPORT_PARAM_SET( TP, NAME, VALUE ) \
  do { (TP)->NAME##_present = 1; (TP)->NAME = VALUE; } while(0);
#define FD_QUIC_TRANSPORT_PARAM_UNSET( TP, NAME ) \
  do { (TP)->NAME##_present = 0;                     } while(0);

/* parses the varint at *buf (capacity *buf_sz)
   advances the *buf and reduces *buf_sz by the number of bytes
   consumed */
static inline
ulong
fd_quic_tp_parse_varint( uchar const ** buf,
                         ulong *        buf_sz ) {

  if( FD_UNLIKELY( *buf_sz == 0    ) ) return ~(ulong)0;

  uint width = 1u << ( (uint)(*buf)[0] >> 6u );
  if( FD_UNLIKELY( *buf_sz < width ) ) return ~(ulong)0;

  ulong value = (ulong)( (*buf)[0] & 0x3f );
  for( ulong j=1; j<width; ++j ) {
    value = ( value<<8UL ) + (ulong)(*buf)[j];
  }

  *buf    += width;
  *buf_sz -= width;

  return value;
}

/* parse a particular transport parameter into the corresponding
   member(s) of params

   args
     params       the parameters to populate with parsed data
     id           the id of the parameter to parse
     buf          the start of the raw encoded transport parameter
     sz           the size of the buffer

   returns the number of bytes consumed or -1 upon failure to parse */
int
fd_quic_decode_transport_param( fd_quic_transport_params_t * params,
                                uint                         id,
                                uchar const *                buf,
                                ulong                        sz );

/* parse the entire buffer into the supplied transport parameters

   unknown transport parameters are ignored as per spec

   returns
     0  success
     -1 failed to parse */
int
fd_quic_decode_transport_params( fd_quic_transport_params_t * params,
                                 uchar const *                buf,
                                 ulong                        buf_sz );

/* dump all transport parameters to stdout */
void
fd_quic_dump_transport_params( fd_quic_transport_params_t const * params,
                               FILE * out );


/* encode transport parameters into a buffer
   args
     buf           the buffer to write encoded transport params into
     buf_sz        the size of buffer buf
     params        the parameters to be encoded

   returns the number of bytes written */
ulong
fd_quic_encode_transport_params( uchar *                            buf,
                                 ulong                              buf_sz,
                                 fd_quic_transport_params_t const * params );


/* determine the footprint in bytes required for a particular transport params
   args
     params        the parameters to be encoded

   returns the number of bytes required */
ulong
fd_quic_transport_params_footprint( fd_quic_transport_params_t const * params );


/* validates whether the values in the transport params struct
   have valid lengths for varint encoding */
int
fd_quic_transport_params_validate( fd_quic_transport_params_t const * params );

#endif

