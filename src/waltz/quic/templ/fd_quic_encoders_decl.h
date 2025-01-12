/* QUIC encoders + footprints */

#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                       \
  static inline                                               \
  ulong                                                       \
  fd_quic_encode_##NAME( uchar *              buf,            \
                         ulong                sz ,            \
                         fd_quic_##NAME##_t * frame );        \
  static inline                                               \
  ulong                                                       \
  fd_quic_encode_footprint_##NAME( fd_quic_##NAME##_t * frame );

#include "fd_quic_dft.h"

