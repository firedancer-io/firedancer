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
  FD_TEMPL_MBR_ELEM_BITS(version,uint8,4)
  FD_TEMPL_MBR_ELEM_BITS(ihl,uint8,4)
  FD_TEMPL_MBR_ELEM_BITS(dscp,uint8,6)
  FD_TEMPL_MBR_ELEM_BITS(ecn,uint8,2)
  FD_TEMPL_MBR_ELEM(tot_len,uint16)
  FD_TEMPL_MBR_ELEM(id,uint16)
  FD_TEMPL_MBR_ELEM(frag_off,uint16)
  FD_TEMPL_MBR_ELEM(ttl,uint8)
  FD_TEMPL_MBR_ELEM(protocol,uint8)
  FD_TEMPL_MBR_ELEM(check,uint16)
  FD_TEMPL_MBR_ELEM(saddr,uint32)
  FD_TEMPL_MBR_ELEM(daddr,uint32)
FD_TEMPL_DEF_STRUCT_END(ipv4)

