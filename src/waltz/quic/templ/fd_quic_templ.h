/* 17.2. Long Header Packets
   Long Header Packet {
     Header Form (1) = 1,
     Fixed Bit (1) = 1,
     Long Packet Type (2),
     Type-Specific Bits (4),
     Version (32),
     Destination Connection ID Length (8),
     Destination Connection ID (0..160),
     Source Connection ID Length (8),
     Source Connection ID (0..160),
     Type-Specific Payload (..),
   }
   Figure 13: Long Header Packet Format */

/* long header except first byte */
FD_TEMPL_DEF_STRUCT_BEGIN(long_hdr)
  FD_TEMPL_MBR_ELEM    ( version,         uint                   )
  FD_TEMPL_MBR_ELEM    ( dst_conn_id_len, uchar                  )
  FD_TEMPL_MBR_ELEM_VAR( dst_conn_id,     0,160, dst_conn_id_len )
  FD_TEMPL_MBR_ELEM    ( src_conn_id_len, uchar                  )
  FD_TEMPL_MBR_ELEM_VAR( src_conn_id,     0,160, src_conn_id_len )
FD_TEMPL_DEF_STRUCT_END(long_hdr)


/* 17.2.2 Version Negotiation Packet
   Version Negotiation Packet {
     Header Form (1) = 1,
     Unused (7),
     Version (32) = 0,
     Destination Connection ID Length (8),
     Destination Connection ID (0..2040),
     Source Connection ID Length (8),
     Source Connection ID (0..2040),
     Supported Version (32) ...,
   }
   Figure 14: Version Negotiation Packet */

FD_TEMPL_DEF_STRUCT_BEGIN(version_neg)
  FD_TEMPL_MBR_ELEM      ( h0,                 uchar                          )
  FD_TEMPL_MBR_ELEM      ( version,            uint                           )
  FD_TEMPL_MBR_ELEM      ( dst_conn_id_len,    uchar                          )
  FD_TEMPL_MBR_ELEM_VAR  ( dst_conn_id,        0,2040, dst_conn_id_len        )
  FD_TEMPL_MBR_ELEM      ( src_conn_id_len,    uchar                          )
  FD_TEMPL_MBR_ELEM_VAR  ( src_conn_id,        0,2040, src_conn_id_len        )
  /* TODO determine proper range here */
  FD_TEMPL_MBR_ELEM_ARRAY( supported_versions, uint,   1,FD_QUIC_MAX_VERSIONS )
FD_TEMPL_DEF_STRUCT_END(version_neg)


/* 17.2.2 Initial Packet
   Initial Packet {
     Header Form (1) = 1,
     Fixed Bit (1) = 1,
     Long Packet Type (2) = 0,
     Reserved Bits (2),
     Packet Number Length (2),
     Version (32),
     Destination Connection ID Length (8),
     Destination Connection ID (0..160),
     Source Connection ID Length (8),
     Source Connection ID (0..160),

     Token Length (i),
     Token (..),
     Length (i),
     Packet Number (8..32),
     Packet Payload (8..),
   }
   Figure 15: Initial Packet

   The first CRYPTO frame sent always begins at an offset of 0 */

FD_TEMPL_DEF_STRUCT_BEGIN(initial)
  FD_TEMPL_MBR_ELEM          ( h0,               uchar                   )
  FD_TEMPL_MBR_ELEM          ( version,          uint                    )
  FD_TEMPL_MBR_ELEM          ( dst_conn_id_len,  uchar                   )
  FD_TEMPL_MBR_ELEM_VAR      ( dst_conn_id,      0,160,  dst_conn_id_len )
  FD_TEMPL_MBR_ELEM          ( src_conn_id_len,  uchar                   )
  FD_TEMPL_MBR_ELEM_VAR      ( src_conn_id,      0,160,  src_conn_id_len )

  /* FIXME use a pointer here */
  FD_TEMPL_MBR_ELEM_VARINT   ( token_len,        ulong                   )
  FD_TEMPL_MBR_ELEM_VAR      ( token,            0,2048, token_len       )

  FD_TEMPL_MBR_ELEM_VARINT   ( len,              ulong                   )
  FD_TEMPL_MBR_ELEM_PKTNUM   ( pkt_num,          ulong                   )

  // CRYPTO frames, etc, may start here
FD_TEMPL_DEF_STRUCT_END(initial)


/* 17.2.3 0-RTT
   0-RTT Packet {
     Header Form (1) = 1,
     Fixed Bit (1) = 1,
     Long Packet Type (2) = 1,
     Reserved Bits (2),
     Packet Number Length (2),
     Version (32),
     Destination Connection ID Length (8),
     Destination Connection ID (0..160),
     Source Connection ID Length (8),
     Source Connection ID (0..160),
     Length (i),
     Packet Number (8..32),
     Packet Payload (8..),
   }
   Figure 16: 0-RTT Packet */
FD_TEMPL_DEF_STRUCT_BEGIN(zero_rtt)
  FD_TEMPL_MBR_ELEM          ( h0,               uchar                  )
  FD_TEMPL_MBR_ELEM          ( version,          uint                   )
  FD_TEMPL_MBR_ELEM          ( dst_conn_id_len,  uchar                  )
  FD_TEMPL_MBR_ELEM_VAR      ( dst_conn_id,      0,160, dst_conn_id_len )
  FD_TEMPL_MBR_ELEM          ( src_conn_id_len,  uchar                  )
  FD_TEMPL_MBR_ELEM_VAR      ( src_conn_id,      0,160, src_conn_id_len )

  FD_TEMPL_MBR_ELEM_VARINT   ( len,              ulong                  )
  FD_TEMPL_MBR_ELEM_VARINT   ( pkt_num,          ulong                  )

  // payload starts here
FD_TEMPL_DEF_STRUCT_END(zero_rtt)


/* 17.2.4 Handshake Packet
   Handshake Packet {
     Header Form (1) = 1,
     Fixed Bit (1) = 1,
     Long Packet Type (2) = 2,
     Reserved Bits (2),
     Packet Number Length (2),
     Version (32),
     Destination Connection ID Length (8),
     Destination Connection ID (0..160),
     Source Connection ID Length (8),
     Source Connection ID (0..160),
     Length (i),
     Packet Number (8..32),
     Packet Payload (8..),
   }
   Figure 17: Handshake Protected Packet */

FD_TEMPL_DEF_STRUCT_BEGIN(handshake)
  FD_TEMPL_MBR_ELEM          ( h0,               uchar                  )
  FD_TEMPL_MBR_ELEM          ( version,          uint                   )
  FD_TEMPL_MBR_ELEM          ( dst_conn_id_len,  uchar                  )
  FD_TEMPL_MBR_ELEM_VAR      ( dst_conn_id,      0,160, dst_conn_id_len )
  FD_TEMPL_MBR_ELEM          ( src_conn_id_len,  uchar                  )
  FD_TEMPL_MBR_ELEM_VAR      ( src_conn_id,      0,160, src_conn_id_len )

  FD_TEMPL_MBR_ELEM_VARINT   ( len,              ulong                  )
  FD_TEMPL_MBR_ELEM_PKTNUM   ( pkt_num,          ulong                  )

  // payload starts here
FD_TEMPL_DEF_STRUCT_END(handshake)


/* 17.2.5 Retry Packet
   Retry Packet {
     Header Form (1) = 1,
     Fixed Bit (1) = 1,
     Long Packet Type (2) = 3,
     Unused (4),
     Version (32),
     Destination Connection ID Length (8),
     Destination Connection ID (0..160),
     Source Connection ID Length (8),
     Source Connection ID (0..160),
     Retry Token (..),
     Retry Integrity Tag (128),
   }
 Figure 18: Retry Packet */
FD_TEMPL_DEF_STRUCT_BEGIN(retry_hdr)
  FD_TEMPL_MBR_ELEM          ( h0,                  uchar                  )
  FD_TEMPL_MBR_ELEM          ( version,             uint                   )
  FD_TEMPL_MBR_ELEM          ( dst_conn_id_len,     uchar                  )
  FD_TEMPL_MBR_ELEM_VAR      ( dst_conn_id,         0,160, dst_conn_id_len )
  FD_TEMPL_MBR_ELEM          ( src_conn_id_len,     uchar                  )
  FD_TEMPL_MBR_ELEM_VAR      ( src_conn_id,         8,160, src_conn_id_len )
FD_TEMPL_DEF_STRUCT_END(retry_hdr)



/* 17.2. Short Header Packets
   1-RTT Packet {
     Header Form (1) = 0,
     Fixed Bit (1) = 1,
     Spin Bit (1),
     Reserved Bits (2),
     Key Phase (1),
     Packet Number Length (2),
     Destination Connection ID (0..160),
     Packet Number (8..32),
     Packet Payload (8..),
   }
   Figure 19: 1-RTT Packet */
FD_TEMPL_DEF_STRUCT_BEGIN(one_rtt)
  FD_TEMPL_MBR_ELEM       ( h0,               uchar                 )
  FD_TEMPL_MBR_ELEM_HIDDEN( dst_conn_id_len, uint                   )
  FD_TEMPL_MBR_ELEM_VAR   ( dst_conn_id,     0,160, dst_conn_id_len )

  FD_TEMPL_MBR_ELEM_PKTNUM( pkt_num,         ulong                  )

  // payload starts here
FD_TEMPL_DEF_STRUCT_END(one_rtt)



/* 18. Transport Parameter Encoding
   Transport Parameters {
     Transport Parameter (..) ...,
   }
   Figure 20: Sequence of Transport Parameters
   Each transport parameter is encoded as an (identifier, length, value) tuple, as shown in Figure 21:

   Transport Parameter {
     Transport Parameter ID (i),
     Transport Parameter Length (i),
     Transport Parameter Value (..),
   }
   Figure 21: Transport Parameter Encoding */

// one transport entry - repeats
FD_TEMPL_DEF_STRUCT_BEGIN(transport_param_entry)
  FD_TEMPL_MBR_ELEM_VARINT ( param_id,  ulong             )
  FD_TEMPL_MBR_ELEM_VARINT ( param_len, ulong             )
  FD_TEMPL_MBR_ELEM_VAR_RAW( param_val, 0,8192, param_len )
FD_TEMPL_DEF_STRUCT_END(transport_param_entry)


/* 19. Frame common header

   COMMON Frag {
     Type (i)
   } */
FD_TEMPL_DEF_STRUCT_BEGIN(common_frag)
  FD_TEMPL_MBR_ELEM_VARINT( type, ulong )
FD_TEMPL_DEF_STRUCT_END(common_frag)


/* 19.3.1. ACK Ranges (part of ACK frame)

   ACK Range {
     Gap (i),
     ACK Range Length (i),
   }
   Figure 26: ACK Ranges */

FD_TEMPL_DEF_STRUCT_BEGIN(ack_range_frag)
  FD_TEMPL_MBR_ELEM_VARINT( gap,    ulong )
  FD_TEMPL_MBR_ELEM_VARINT( length, ulong )
FD_TEMPL_DEF_STRUCT_END(ack_range_frag)


/* 19.3.2. ECN Counts (part of ACK frame)

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


/* 18.2. Transport Parameter Definitions > Preferred Address */

FD_TEMPL_DEF_STRUCT_BEGIN(preferred_address)
  FD_TEMPL_MBR_ELEM_FIXED( ipv4_address, uchar,  4          )
  FD_TEMPL_MBR_ELEM      ( ipv4_port,    ushort             )
  FD_TEMPL_MBR_ELEM_FIXED( ipv6_address, uchar, 16          )
  FD_TEMPL_MBR_ELEM      ( ipv6_port,    ushort             )
  FD_TEMPL_MBR_ELEM      ( conn_id_len,  uchar              )
  FD_TEMPL_MBR_ELEM_VAR  ( conn_id,      0,160, conn_id_len )
  FD_TEMPL_MBR_ELEM_FIXED( reset_token,  uchar, 16          )
FD_TEMPL_DEF_STRUCT_END(preferred_address)
