//
// IPv4 Header
// ipv4 {
//   version (4) = 4,
//   ihl (4) >= 5,
//   tos (8),
//   tot_len (16),
//   id (16),
//   frag_off (16),
//   ttl (8),
//   protocol (8),
//   check (16),
//   saddr (32),
//   daddr (32)
//   [options]
// }

FD_TEMPL_DEF_STRUCT_BEGIN(ipv4)
  FD_TEMPL_MBR_ELEM_BITS( version,  uchar, 4 )
  FD_TEMPL_MBR_ELEM_BITS( ihl,      uchar, 4 )
  FD_TEMPL_MBR_ELEM_BITS( dscp,     uchar, 6 )
  FD_TEMPL_MBR_ELEM_BITS( ecn,      uchar, 2 )
  FD_TEMPL_MBR_ELEM     ( tot_len,  ushort   )
  FD_TEMPL_MBR_ELEM     ( id,       ushort   )
  FD_TEMPL_MBR_ELEM     ( frag_off, ushort   )
  FD_TEMPL_MBR_ELEM     ( ttl,      uchar    )
  FD_TEMPL_MBR_ELEM     ( protocol, uchar    )
  FD_TEMPL_MBR_ELEM     ( check,    ushort   )
  FD_TEMPL_MBR_ELEM     ( saddr,    uint     )
  FD_TEMPL_MBR_ELEM     ( daddr,    uint     )
FD_TEMPL_DEF_STRUCT_END(ipv4)

