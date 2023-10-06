/* TODO rename to fd_quic_pkt_templ.h */

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

/* common to long and short header */
FD_TEMPL_DEF_STRUCT_BEGIN(common_hdr)
  FD_TEMPL_MBR_ELEM_BITS( hdr_form,           uchar, 1 )
  FD_TEMPL_MBR_ELEM_BITS( fixed_bit,          uchar, 1 )
  FD_TEMPL_MBR_ELEM_BITS( long_packet_type,   uchar, 2 )
  FD_TEMPL_MBR_ELEM_BITS( type_specific_bits, uchar, 4 )
FD_TEMPL_DEF_STRUCT_END(common_hdr)

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
  FD_TEMPL_MBR_ELEM_BITS ( hdr_form,           uchar,  1                      )
  /* TODO add specification for unused to avoid extra work */
  FD_TEMPL_MBR_ELEM_BITS ( unused0,            uchar,  7                      )
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
  FD_TEMPL_MBR_ELEM_BITS     ( hdr_form,         uchar,  1               )
  FD_TEMPL_MBR_ELEM_BITS     ( fixed_bit,        uchar,  1               )
  FD_TEMPL_MBR_ELEM_BITS_TYPE( long_packet_type, uchar,  2, 0x00         )
  FD_TEMPL_MBR_ELEM_BITS     ( reserved_bits,    uchar,  2               )
  FD_TEMPL_MBR_ELEM_BITS     ( pkt_number_len,   uchar,  2               )
  FD_TEMPL_MBR_ELEM          ( version,          uint                    )
  FD_TEMPL_MBR_ELEM          ( dst_conn_id_len,  uchar                   )
  FD_TEMPL_MBR_ELEM_VAR      ( dst_conn_id,      0,160,  dst_conn_id_len )
  FD_TEMPL_MBR_ELEM          ( src_conn_id_len,  uchar                   )
  FD_TEMPL_MBR_ELEM_VAR      ( src_conn_id,      0,160,  src_conn_id_len )

  FD_TEMPL_MBR_ELEM_VARINT   ( token_len,        ulong                   )
  FD_TEMPL_MBR_ELEM_VAR      ( token,            0,616,  token_len       )
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
  FD_TEMPL_MBR_ELEM_BITS     ( hdr_form,         uchar, 1               )
  FD_TEMPL_MBR_ELEM_BITS     ( fixed_bit,        uchar, 1               )
  FD_TEMPL_MBR_ELEM_BITS_TYPE( long_packet_type, uchar, 2, 0x01         )
  FD_TEMPL_MBR_ELEM_BITS     ( reserved0,        uchar, 2               )
  FD_TEMPL_MBR_ELEM_BITS     ( pkt_number_len,   uchar, 2               )

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
  FD_TEMPL_MBR_ELEM_BITS     ( hdr_form,         uchar, 1               )
  FD_TEMPL_MBR_ELEM_BITS     ( fixed_bit,        uchar, 1               )
  FD_TEMPL_MBR_ELEM_BITS_TYPE( long_packet_type, uchar, 2, 0x02         )
  FD_TEMPL_MBR_ELEM_BITS     ( reserved_bits,    uchar, 2               )
  FD_TEMPL_MBR_ELEM_BITS     ( pkt_number_len,   uchar, 2               )

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
FD_TEMPL_DEF_STRUCT_BEGIN(retry)
  FD_TEMPL_MBR_ELEM_BITS     ( hdr_form,            uchar, 1               )
  FD_TEMPL_MBR_ELEM_BITS     ( fixed_bit,           uchar, 1               )
  FD_TEMPL_MBR_ELEM_BITS_TYPE( long_packet_type,    uchar, 2, 0x03         )
  FD_TEMPL_MBR_ELEM_BITS     ( unused,              uchar, 4               )

  FD_TEMPL_MBR_ELEM          ( version,             uint                   )
  FD_TEMPL_MBR_ELEM          ( dst_conn_id_len,     uchar                  )
  FD_TEMPL_MBR_ELEM_VAR      ( dst_conn_id,         0,160, dst_conn_id_len )
  FD_TEMPL_MBR_ELEM          ( src_conn_id_len,     uchar                  )
  FD_TEMPL_MBR_ELEM_VAR      ( src_conn_id,         0,160, src_conn_id_len )

  // TODO variable-length encoding with hidden len
  FD_TEMPL_MBR_ELEM_FIXED    ( retry_token,         uchar, 77              )
  FD_TEMPL_MBR_ELEM_FIXED    ( retry_integrity_tag, uchar, 16              )
FD_TEMPL_DEF_STRUCT_END(retry)


/* 5.8 (RFC 9001) Retry Packet Integrity
    Retry Pseudo-Packet {
     ODCID Length (8),
     Original Destination Connection ID (0..160),
     Header Form (1) = 1,
     Fixed Bit (1) = 1,
     Long Packet Type (2) = 3,
     Unused (4),
     Version (32),
     DCID Len (8),
     Destination Connection ID (0..160),
     SCID Len (8),
     Source Connection ID (0..160),
     Retry Token (..),
   }
   Figure 8: Retry Pseudo-Packet */
FD_TEMPL_DEF_STRUCT_BEGIN(retry_pseudo)
  FD_TEMPL_MBR_ELEM          ( odcid_len,           uchar                  ) 
  FD_TEMPL_MBR_ELEM_VAR      ( odcid,               0,160, odcid_len       )

  FD_TEMPL_MBR_ELEM_BITS     ( hdr_form,            uchar, 1               )
  FD_TEMPL_MBR_ELEM_BITS     ( fixed_bit,           uchar, 1               )
  FD_TEMPL_MBR_ELEM_BITS_TYPE( long_packet_type,    uchar, 2, 0x03         )
  FD_TEMPL_MBR_ELEM_BITS     ( unused,              uchar, 4               )

  FD_TEMPL_MBR_ELEM          ( version,             uint                   )
  FD_TEMPL_MBR_ELEM          ( dst_conn_id_len,     uchar                  )
  FD_TEMPL_MBR_ELEM_VAR      ( dst_conn_id,         0,160, dst_conn_id_len )
  FD_TEMPL_MBR_ELEM          ( src_conn_id_len,     uchar                  )
  FD_TEMPL_MBR_ELEM_VAR      ( src_conn_id,         0,160, src_conn_id_len )

  // TODO variable-length encoding with hidden len
  FD_TEMPL_MBR_ELEM_FIXED    ( retry_token,         uchar, 77              )
FD_TEMPL_DEF_STRUCT_END(retry_pseudo)



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
  FD_TEMPL_MBR_ELEM_BITS  ( hdr_form,        uchar, 1               )
  FD_TEMPL_MBR_ELEM_BITS  ( fixed_bit,       uchar, 1               )
  FD_TEMPL_MBR_ELEM_BITS  ( spin_bit,        uchar, 1               )
  FD_TEMPL_MBR_ELEM_BITS  ( reserved0,       uchar, 2               ) // must be set to zero
  FD_TEMPL_MBR_ELEM_BITS  ( key_phase,       uchar, 1               )
  FD_TEMPL_MBR_ELEM_BITS  ( pkt_number_len,  uchar, 2               )

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
