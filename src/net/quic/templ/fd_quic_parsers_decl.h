// returns bytes consumed
#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME) \
  size_t fd_quic_decode_##NAME( fd_quic_##NAME##_t * FD_RESTRICT out, uchar const * FD_RESTRICT buf, size_t sz );

#include "fd_quic_dft.h"

