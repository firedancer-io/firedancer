#define FD_TEMPL_DEF_STRUCT_BEGIN(NAME)                          \
  static inline                                                  \
  void                                                           \
  fd_quic_pretty_print_struct_##NAME( fd_quic_##NAME##_t const * data );

#include "fd_quic_dft.h"

