/* QUIC union declares

   This file is included, along with a template file, in a union */

#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                                   \
  fd_quic_##NAME##_t NAME;

#include "fd_quic_dft.h"

