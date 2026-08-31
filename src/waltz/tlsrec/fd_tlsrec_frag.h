#ifndef HEADER_fd_src_waltz_tlsrec_fd_tlsrec_frag_h
#define HEADER_fd_src_waltz_tlsrec_fd_tlsrec_frag_h

#include "../fd_waltz_base.h"

#define FD_TLSREC_CAP (0x8000UL)   /* 32 KiB max TLS record buffer */

struct fd_tlsrec_slice {
  uchar * data;
  uchar * data_end;
};
typedef struct fd_tlsrec_slice fd_tlsrec_slice_t;

static inline fd_tlsrec_slice_t *
fd_tlsrec_slice_init( fd_tlsrec_slice_t * frag, uchar * data, ulong data_sz ) {
  frag->data     = data;
  frag->data_end = data + data_sz;
  return frag;
}

static inline ulong
fd_tlsrec_slice_sz( fd_tlsrec_slice_t const * frag ) {
  return (ulong)frag->data_end - (ulong)frag->data;
}

FD_FN_PURE static inline int
fd_tlsrec_slice_is_empty( fd_tlsrec_slice_t const * frag ) {
  return frag->data >= frag->data_end;
}

static inline void *
fd_tlsrec_slice_pop( fd_tlsrec_slice_t * frag, ulong sz ) {
  void * data = frag->data;
  frag->data += sz;
  return data;
}

#endif /* HEADER_fd_src_waltz_tlsrec_fd_tlsrec_frag_h */
