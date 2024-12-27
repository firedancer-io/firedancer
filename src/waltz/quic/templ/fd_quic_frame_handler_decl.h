
#ifndef FD_TEMPL_FRAME_CTX
#  define FD_TEMPL_FRAME_CTX void
#endif

#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                    \
          static ulong                                     \
          fd_quic_handle_##NAME(                           \
                    FD_TEMPL_FRAME_CTX *      context,     \
                    fd_quic_##NAME##_t *      data,        \
                    uchar const *             p,           \
                    ulong                     p_sz );

#include "fd_quic_dft.h"

