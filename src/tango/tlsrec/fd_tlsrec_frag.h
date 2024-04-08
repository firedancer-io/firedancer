#ifndef HEADER_fd_src_tango_tlsrec_fd_tlsrec_frag_h
#define HEADER_fd_src_tango_tlsrec_fd_tlsrec_frag_h

/* fd_tlsrec_frag.h provides APIs for TLS record reassembly from TCP
   stream fragments. */

#include <assert.h>
#include <stddef.h>
#include "../fd_tango_base.h"

/* FD_TLSREC_CAP is the max TLS record size that a record buffer can
   accept. */

#define FD_TLSREC_CAP (0x8000UL)

/* fd_tlsrec_frag_t describes a contiguous slice of bytes.  Used as a
   building block for streaming processing in fd_tlsrec. */

struct fd_tlsrec_slice {
  uchar * data;
  uchar * data_end;
};

typedef struct fd_tlsrec_slice fd_tlsrec_slice_t;

FD_PROTOTYPES_BEGIN

static inline fd_tlsrec_slice_t *
fd_tlsrec_slice_init( fd_tlsrec_slice_t * frag,
                     uchar *              data,
                     ulong                data_sz ) {
  frag->data     = data;
  frag->data_end = data + data_sz;
  return frag;
}

static inline ulong
fd_tlsrec_slice_sz( fd_tlsrec_slice_t const * frag ) {
  assert( frag->data <= frag->data_end );  /* impure */
  return (ulong)frag->data_end - (ulong)frag->data;
}

FD_FN_PURE static inline int
fd_tlsrec_slice_is_empty( fd_tlsrec_slice_t const * frag ) {
  return frag->data >= frag->data_end;
}

static inline void *
fd_tlsrec_slice_pop( fd_tlsrec_slice_t * frag,
                     ulong                sz ) {
  assert( sz <= fd_tlsrec_slice_sz( frag ) );
  void * data = frag->data;
  frag->data += sz;
  return data;
}

FD_PROTOTYPES_END


#endif /* HEADER_fd_src_tango_tlsrec_fd_tlsrec_frag_h */
