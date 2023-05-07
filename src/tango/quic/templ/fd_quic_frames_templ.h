/* frame common header

   COMMON Frag {
     Type (i)
   } */
FD_TEMPL_DEF_STRUCT_BEGIN(common_frag)
  FD_TEMPL_MBR_ELEM_VARINT( type, ulong )
FD_TEMPL_DEF_STRUCT_END(common_frag)


/* Padding Frame

   PADDING Frame {
       Type (i) = 0x00,
   }
   Figure 23: PADDING Frame Format
   19.2. PING Frames */

FD_TEMPL_DEF_STRUCT_BEGIN(padding_frame)
  FD_TEMPL_MBR_FRAME_TYPE( type, 0x00,0x00 )
FD_TEMPL_DEF_STRUCT_END(padding_frame)


/* Ping Frame

   PING Frame {
     Type (i) = 0x01,
   }
   Figure 24: PING Frame Format */

FD_TEMPL_DEF_STRUCT_BEGIN(ping_frame)
  FD_TEMPL_MBR_FRAME_TYPE( type, 0x01,0x01 )
FD_TEMPL_DEF_STRUCT_END(ping_frame)


/* Acknowledgement Frame

   ACK Frame {
     Type (i) = 0x02..0x03,
     Largest Acknowledged (i),
     ACK Delay (i),
     ACK Range Count (i),
     First ACK Range (i),
     ACK Range (..) ...,
     [ECN Counts (..)],
   }
   Figure 25: ACK Frame Format */

FD_TEMPL_DEF_STRUCT_BEGIN(ack_frame)
  FD_TEMPL_MBR_FRAME_TYPE( type, 0x02,0x03 )
  //FD_TEMPL_MBR_ELEM(type,uchar)
  FD_TEMPL_MBR_ELEM_VARINT( largest_ack,     ulong )
  FD_TEMPL_MBR_ELEM_VARINT( ack_delay,       ulong )
  FD_TEMPL_MBR_ELEM_VARINT( ack_range_count, ulong )
  FD_TEMPL_MBR_ELEM_VARINT( first_ack_range, ulong )
  /* N   ack_range_frag    (ack_range_count) */
  /* opt ecn_counts_frag   if type == 0x03 */
FD_TEMPL_DEF_STRUCT_END(ack_frame)


/* Acknowledgement Range Fragment

   ACK Range {
     Gap (i),
     ACK Range Length (i),
   }
   Figure 26: ACK Ranges */

FD_TEMPL_DEF_STRUCT_BEGIN(ack_range_frag)
  FD_TEMPL_MBR_ELEM_VARINT( gap,    ulong )
  FD_TEMPL_MBR_ELEM_VARINT( length, ulong )
FD_TEMPL_DEF_STRUCT_END(ack_range_frag)


/* ECN Counts Fragment

   ECN Counts {
     ECT0 Count (i),
     ECT1 Count (i),
     ECN-CE Count (i),
   }
   Figure 27: ECN Count Format
   The ECN count fields are:

   ECT0 Count:
   A variable-length integer representing the total number of packets received with the
     ECT(0) codepoint in the packet number space of the ACK frame.

   ECT1 Count:
   A variable-length integer representing the total number of packets received with the
     ECT(1) codepoint in the packet number space of the ACK frame.

   ECN-CE Count:
   A variable-length integer representing the total number of packets received with the
     ECN-CE codepoint in the packet number space of the ACK frame. */

FD_TEMPL_DEF_STRUCT_BEGIN(ecn_counts_frag)
  FD_TEMPL_MBR_ELEM_VARINT( ect0_count,   ulong )
  FD_TEMPL_MBR_ELEM_VARINT( ect1_count,   ulong )
  FD_TEMPL_MBR_ELEM_VARINT( ecn_ce_count, ulong )
FD_TEMPL_DEF_STRUCT_END(ecn_counts_frag)


/* Reset Stream Frame

   RESET_STREAM Frame {
     Type (i) = 0x04,
     Stream ID (i),
     Application Protocol Error Code (i),
     Final Size (i),
   }
   Figure 28: RESET_STREAM Frame Format */

FD_TEMPL_DEF_STRUCT_BEGIN(reset_stream_frame)
  FD_TEMPL_MBR_FRAME_TYPE ( type, 0x04,0x04 )
  FD_TEMPL_MBR_ELEM_VARINT( stream_id,          ulong )
  FD_TEMPL_MBR_ELEM_VARINT( app_proto_err_code, ulong )
  FD_TEMPL_MBR_ELEM_VARINT( final_size,         ulong )
FD_TEMPL_DEF_STRUCT_END(reset_stream_frame)


/* Stop Sending Frame

   STOP_SENDING Frame {
     Type (i) = 0x05,
     Stream ID (i),
     Application Protocol Error Code (i),
   }
   Figure 29: STOP_SENDING Frame Format */

FD_TEMPL_DEF_STRUCT_BEGIN(stop_sending_frame)
  FD_TEMPL_MBR_FRAME_TYPE ( type, 0x05,0x05           )
  FD_TEMPL_MBR_ELEM_VARINT( stream_id,          ulong )
  FD_TEMPL_MBR_ELEM_VARINT( app_proto_err_code, ulong )
FD_TEMPL_DEF_STRUCT_END(stop_sending_frame)


/* Crypto Frame

   CRYPTO Frame {
     Type (i) = 0x06,
     Offset (i),           // byte offset in the stream
     Length (i),
     Crypto Data (..),
   }
   Figure 30: CRYPTO Frame Format */

FD_TEMPL_DEF_STRUCT_BEGIN(crypto_frame)
  FD_TEMPL_MBR_FRAME_TYPE( type, 0x06,0x06 )
  FD_TEMPL_MBR_ELEM_VARINT ( offset,      ulong           )
  FD_TEMPL_MBR_ELEM_VARINT ( length,      ulong           )
  FD_TEMPL_MBR_ELEM_VAR_RAW( crypto_data, 0,12000, length )
FD_TEMPL_DEF_STRUCT_END(crypto_frame)


/* New Token Frame

   NEW_TOKEN Frame {
     Type (i) = 0x07,
     Token Length (i),
     Token (..),
   }
   Figure 31: NEW_TOKEN Frame Format */

FD_TEMPL_DEF_STRUCT_BEGIN(new_token_frame)
  FD_TEMPL_MBR_FRAME_TYPE  ( type, 0x07,0x07 )
  FD_TEMPL_MBR_ELEM_VARINT ( token_len, uint              )
  FD_TEMPL_MBR_ELEM_VAR_RAW( token,     0,8192, token_len )
FD_TEMPL_DEF_STRUCT_END(new_token_frame)


/* Stream Frame

   STREAM Frame {
     Type (i) = 0x08..0x0f,
     Stream ID (i),
     [Offset (i)],
     [Length (i)],
     Stream Data (..),
   }
   Figure 32: STREAM Frame Format */

/* The Type field in the STREAM frame takes the form 0b00001XXX (or the set of
   values from 0x08 to 0x0f). The three low-order bits of the frame type determine
   the fields that are present in the frame:

   The OFF bit (0x04) in the frame type is set to indicate that there is an Offset
     field present. When set to 1, the Offset field is present. When set to 0, the
     Offset field is absent and the Stream Data starts at an offset of 0 (that is,
     the frame contains the first bytes of the stream, or the end of a stream that
     includes no data).
   The LEN bit (0x02) in the frame type is set to indicate that there is a Length
     field present. If this bit is set to 0, the Length field is absent and the
     Stream Data field extends to the end of the packet. If this bit is set to 1,
     the Length field is present.
   The FIN bit (0x01) indicates that the frame marks the end of the stream. The
     final size of the stream is the sum of the offset and the length of this frame. */

FD_TEMPL_DEF_STRUCT_BEGIN(stream_frame)
  FD_TEMPL_MBR_FRAME_TYPE( type, 0x08,0x0f )

  FD_TEMPL_MBR_ELEM_VARINT( stream_id, ulong )

  // optional data processed in code
  FD_TEMPL_MBR_OPT( type, offset, 0x04,
    FD_TEMPL_MBR_ELEM_VARINT( offset,    ulong ) )

  FD_TEMPL_MBR_OPT( type, length,0x02,
    FD_TEMPL_MBR_ELEM_VARINT( length,    ulong ) )

  FD_TEMPL_MBR_OPT( type, fin, 0x01, )
FD_TEMPL_DEF_STRUCT_END(stream_frame)


/* Max Data Frame

   MAX_DATA Frame {
     Type (i) = 0x10,
     Maximum Data (i),
   }
   Figure 33: MAX_DATA Frame Format */

FD_TEMPL_DEF_STRUCT_BEGIN(max_data_frame)
  FD_TEMPL_MBR_FRAME_TYPE( type, 0x10,0x10 )
  FD_TEMPL_MBR_ELEM_VARINT( max_data, ulong )
FD_TEMPL_DEF_STRUCT_END(max_data_frame)


/* Max Stream Data Frame

   MAX_STREAM_DATA Frame {
     Type (i) = 0x11,
     Stream ID (i),
     Maximum Stream Data (i),
   }
   Figure 34: MAX_STREAM_DATA Frame Format */

  /* TODO rename to max_stream_data_frame for consistency */
FD_TEMPL_DEF_STRUCT_BEGIN(max_stream_data)
  FD_TEMPL_MBR_FRAME_TYPE( type,0x11,0x11 )
  FD_TEMPL_MBR_ELEM_VARINT( stream_id,       ulong )
  FD_TEMPL_MBR_ELEM_VARINT( max_stream_data, ulong )
FD_TEMPL_DEF_STRUCT_END(max_stream_data)


/* Max Streams Frame

   MAX_STREAMS Frame {
     Type (i) = 0x12..0x13,
     Maximum Streams (i),
   }
   Figure 35: MAX_STREAMS Frame Format */

FD_TEMPL_DEF_STRUCT_BEGIN(max_streams_frame)
  FD_TEMPL_MBR_FRAME_TYPE( type, 0x12,0x13 )
  FD_TEMPL_MBR_FRAME_TYPE_FLAG( stream_type, 0x01 )
  FD_TEMPL_MBR_ELEM_VARINT( max_streams, ulong )
FD_TEMPL_DEF_STRUCT_END(max_streams_frame)


/* Data Blocked Frame

   DATA_BLOCKED Frame {
     Type (i) = 0x14,
     Maximum Data (i),
   }
   Figure 36: DATA_BLOCKED Frame Format */

FD_TEMPL_DEF_STRUCT_BEGIN(data_blocked_frame)
  FD_TEMPL_MBR_FRAME_TYPE( type, 0x14,0x14 )
  FD_TEMPL_MBR_ELEM_VARINT( max_data, ulong )
FD_TEMPL_DEF_STRUCT_END(data_blocked_frame)


/* Stream Data Blocked Frame

   STREAM_DATA_BLOCKED Frame {
     Type (i) = 0x15,
     Stream ID (i),
     Maximum Stream Data (i),
   }
   Figure 37: STREAM_DATA_BLOCKED Frame Format */

FD_TEMPL_DEF_STRUCT_BEGIN(stream_data_blocked_frame)
  FD_TEMPL_MBR_FRAME_TYPE( type, 0x15,0x15 )
  FD_TEMPL_MBR_ELEM_VARINT( stream_id,       ulong )
  FD_TEMPL_MBR_ELEM_VARINT( max_stream_data, ulong )
FD_TEMPL_DEF_STRUCT_END(stream_data_blocked_frame)


/* Streams Blocked Frame

   STREAMS_BLOCKED Frame {
     Type (i) = 0x16..0x17,
     Maximum Streams (i),
   }
   Figure 38: STREAMS_BLOCKED Frame Format */

FD_TEMPL_DEF_STRUCT_BEGIN(streams_blocked_frame)
  FD_TEMPL_MBR_FRAME_TYPE( type, 0x16,0x17 )
  FD_TEMPL_MBR_ELEM_VARINT( max_streams, ulong )
FD_TEMPL_DEF_STRUCT_END(streams_blocked_frame)


/* New Connection ID Frame

   NEW_CONNECTION_ID Frame {
     Type (i) = 0x18,
     Sequence Number (i),
     Retire Prior To (i),
     Length (8),
     Connection ID (8..160),
     Stateless Reset Token (128),
   }
   Figure 39: NEW_CONNECTION_ID Frame Format */

FD_TEMPL_DEF_STRUCT_BEGIN(new_conn_id_frame)
  FD_TEMPL_MBR_FRAME_TYPE( type, 0x18,0x18 )
  FD_TEMPL_MBR_ELEM_VARINT ( seq_nbr,               ulong              )
  FD_TEMPL_MBR_ELEM_VARINT ( retire_prior_to,       ulong              )
  FD_TEMPL_MBR_ELEM        ( conn_id_len,           uchar              )
  FD_TEMPL_MBR_ELEM_VAR_RAW( conn_id,               0,160, conn_id_len )
  FD_TEMPL_MBR_ELEM_FIXED  ( stateless_reset_token, uchar, 16          )
FD_TEMPL_DEF_STRUCT_END(new_conn_id_frame)


/* Retire Connection ID Frame

   RETIRE_CONNECTION_ID Frame {
     Type (i) = 0x19,
     Sequence Number (i),
   }
   Figure 40: RETIRE_CONNECTION_ID Frame Format */

FD_TEMPL_DEF_STRUCT_BEGIN(retire_conn_id_frame)
  FD_TEMPL_MBR_FRAME_TYPE( type, 0x19,0x19 )
  FD_TEMPL_MBR_ELEM_VARINT( seq_nbr, ulong )
FD_TEMPL_DEF_STRUCT_END(retire_conn_id_frame)


/* Path Challenge Frame

   PATH_CHALLENGE Frame {
     Type (i) = 0x1a,
     Data (64),
   }
   Figure 41: PATH_CHALLENGE Frame Format */

FD_TEMPL_DEF_STRUCT_BEGIN(path_challenge_frame)
  FD_TEMPL_MBR_FRAME_TYPE( type, 0x1a,0x1a )
  FD_TEMPL_MBR_ELEM_VARINT( data, ulong )
FD_TEMPL_DEF_STRUCT_END(path_challenge_frame)


/* Path Response Frame

   PATH_RESPONSE Frame {
     Type (i) = 0x1b,
     Data (64),
   }
   Figure 42: PATH_RESPONSE Frame Format */

FD_TEMPL_DEF_STRUCT_BEGIN(path_response_frame)
  FD_TEMPL_MBR_FRAME_TYPE( type, 0x1b,0x1b )
  FD_TEMPL_MBR_ELEM_VARINT( data, ulong )
FD_TEMPL_DEF_STRUCT_END(path_response_frame)


/* Connection Close Frame

   CONNECTION_CLOSE Frame {
     Type (i) = 0x1c..0x1d,
     Error Code (i),
     [Frame Type (i)],
     Reason Phrase Length (i),
     Reason Phrase (..),
   }
   Figure 43: CONNECTION_CLOSE Frame Format */

FD_TEMPL_DEF_STRUCT_BEGIN(conn_close_0_frame)
  FD_TEMPL_MBR_FRAME_TYPE( type, 0x1c,0x1c )
  FD_TEMPL_MBR_ELEM_VARINT( error_code,           ulong )
  FD_TEMPL_MBR_ELEM_VARINT( frame_type,           ulong )
  FD_TEMPL_MBR_ELEM_VARINT( reason_phrase_length, ulong )

  /* phrase follows */
FD_TEMPL_DEF_STRUCT_END(conn_close_0_frame)


FD_TEMPL_DEF_STRUCT_BEGIN(conn_close_1_frame)
  FD_TEMPL_MBR_FRAME_TYPE( type, 0x1d,0x1d )
  FD_TEMPL_MBR_ELEM_VARINT( error_code,           ulong )
  FD_TEMPL_MBR_ELEM_VARINT( reason_phrase_length, ulong )

  /* phrase follows */
FD_TEMPL_DEF_STRUCT_END(conn_close_1_frame)


/* Handshake Done Frame

   HANDSHAKE_DONE Frame {
     Type (i) = 0x1e,
   }
   Figure 44: HANDSHAKE_DONE Frame Format */

FD_TEMPL_DEF_STRUCT_BEGIN(handshake_done_frame)
  FD_TEMPL_MBR_FRAME_TYPE( type, 0x1e,0x1e )
FD_TEMPL_DEF_STRUCT_END(handshake_done_frame)

