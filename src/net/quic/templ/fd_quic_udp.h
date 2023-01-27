// 
// UDP Header
// UDP {
//   dstport (16),
//   srcport (16),
//   length (16)
//   check (16),
// }

FD_TEMPL_DEF_STRUCT_BEGIN(udp)
  FD_TEMPL_MBR_ELEM(srcport,uint16)
  FD_TEMPL_MBR_ELEM(dstport,uint16)
  FD_TEMPL_MBR_ELEM(length,uint16)
  FD_TEMPL_MBR_ELEM(check,uint16)
FD_TEMPL_DEF_STRUCT_END(udp)

