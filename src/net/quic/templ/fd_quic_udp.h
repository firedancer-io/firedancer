//
// UDP Header
// UDP {
//   dstport (16),
//   srcport (16),
//   length (16)
//   check (16),
// }

FD_TEMPL_DEF_STRUCT_BEGIN(udp)
  FD_TEMPL_MBR_ELEM( srcport, ushort )
  FD_TEMPL_MBR_ELEM( dstport, ushort )
  FD_TEMPL_MBR_ELEM( length,  ushort )
  FD_TEMPL_MBR_ELEM( check,   ushort )
FD_TEMPL_DEF_STRUCT_END(udp)

