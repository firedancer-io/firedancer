#ifndef HEADER_fd_src_waltz_tlsrec_fd_tlsrec_frag_h
#define HEADER_fd_src_waltz_tlsrec_fd_tlsrec_frag_h

#include "../fd_waltz_base.h"

#define FD_TLSREC_CAP (0x8000UL)   /* 32 KiB max TLS record buffer */

/* FD_TLSREC_PLAINTEXT_MAX is the most plaintext a single record may
   carry (RFC 8446 Section 5.1: 2^14).  FD_TLSREC_PAYLOAD_MAX is the
   largest TLSCiphertext.length a peer may send (Section 5.2: 2^14 +
   256).  Larger incoming records are a record_overflow error. */

#define FD_TLSREC_PLAINTEXT_MAX (16384UL)
#define FD_TLSREC_PAYLOAD_MAX   (FD_TLSREC_PLAINTEXT_MAX+256UL)

struct fd_tlsrec_slice {
  uchar * data;
  uchar * data_end;
};
typedef struct fd_tlsrec_slice fd_tlsrec_slice_t;

static inline fd_tlsrec_slice_t *
fd_tlsrec_slice_init( fd_tlsrec_slice_t * frag, uchar * data, ulong data_sz ) {
  frag->data     = data;
  frag->data_end = data_sz ? data + data_sz : data;
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
