/* QUIC encoders + footprints */

#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                                    \
  size_t fd_quic_encode_##NAME( uchar *                          buf,      \
                                size_t                           sz ,      \
                                fd_quic_##NAME##_t *             frame );  \
  size_t fd_quic_encode_footprint_##NAME( fd_quic_##NAME##_t * frame );

#include "fd_quic_dft.h"

