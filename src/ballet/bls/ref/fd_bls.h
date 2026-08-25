#ifndef HEADER_fd_src_ballet_bls_fd_bls_h
#error "Do not include this directly; use fd_bls.h"
#endif

/* BLST has no reusable public Miller-line representation.  Retaining the
   validated affine point gives the reference backend matching semantics. */
typedef struct {
  fd_bls_g2_t q;
} fd_bls_g2_prepared_t;
