// returns bytes consumed
#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME) \
  ulong fd_quic_decode_##NAME( fd_quic_##NAME##_t * FD_RESTRICT out, uchar const * FD_RESTRICT buf, ulong sz );

#include "fd_quic_dft.h"

