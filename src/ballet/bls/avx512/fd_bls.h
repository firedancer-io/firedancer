#ifndef HEADER_fd_src_ballet_bls_fd_bls_h
#error "Do not include this directly; use fd_bls.h"
#endif

#define FD_BLS_G2_PREPARED_ALIGN     (64UL)
#define FD_BLS_G2_PREPARED_FOOTPRINT (52224UL)

typedef union __attribute__((aligned(FD_BLS_G2_PREPARED_ALIGN))) {
  ulong align[ FD_BLS_G2_PREPARED_ALIGN/sizeof(ulong) ];
  uchar opaque[ FD_BLS_G2_PREPARED_FOOTPRINT ];
} fd_bls_g2_prepared_t;
