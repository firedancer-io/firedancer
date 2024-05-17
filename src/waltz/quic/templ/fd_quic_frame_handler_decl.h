
#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                    \
          static ulong                                     \
          fd_quic_frame_handle_##NAME(                     \
                    void *                    context,     \
                    fd_quic_##NAME##_t *      data,        \
                    uchar const *             p,           \
                    ulong                     p_sz );

#include "fd_quic_dft.h"

