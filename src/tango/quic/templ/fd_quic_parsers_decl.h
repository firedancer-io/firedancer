/* declare fd_quic_decode_* functions for decoding QUIC packets and frames
   decodes (parses) into "out"
   buf (size "sz") is aa byte array containing the input
   returns bytes consumed
   forces caller to check the result */
#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME) \
  FD_WARN_UNUSED \
  ulong fd_quic_decode_##NAME( fd_quic_##NAME##_t * FD_RESTRICT out, uchar const * FD_RESTRICT buf, ulong sz );

#include "fd_quic_dft.h"

