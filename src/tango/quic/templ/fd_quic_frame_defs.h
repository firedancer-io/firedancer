// template for definitions

#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                                \
  int fd_quic_frame_handle_##NAME( void *               frame_context, \
                                   fd_quic_##NAME##_t * frame_data,    \
                                   uchar const *        p,             \
                                   ulong                p_sz );

#include "fd_quic_dft.h"

