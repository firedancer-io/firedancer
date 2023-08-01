#ifndef HEADER_fd_src_flamenco_capture_fd_solcap_reader_h
#define HEADER_fd_src_flamenco_capture_fd_solcap_reader_h

#include "fd_solcap_proto.h"

#if FD_HAS_HOSTED

#include <stdio.h>

struct fd_solcap_chunk_iter {
  FILE *            stream;
  fd_solcap_chunk_t chunk;
  int               err;
  ulong             next_chunk;
};
typedef struct fd_solcap_chunk_iter fd_solcap_chunk_iter_t;

FD_PROTOTYPES_BEGIN

fd_solcap_chunk_iter_t *
fd_solcap_chunk_iter_new( fd_solcap_chunk_iter_t * iter,
                          FILE *                   stream );

long
fd_solcap_chunk_iter_next( fd_solcap_chunk_iter_t * iter );

static inline int
fd_solcap_chunk_iter_err( fd_solcap_chunk_iter_t const * iter ) {
  return iter->err;
}

static inline int
fd_solcap_chunk_iter_done( fd_solcap_chunk_iter_t const * iter ) {
  return feof( iter->stream ) || fd_solcap_chunk_iter_err( iter );
}

static inline fd_solcap_chunk_t const *
fd_solcap_chunk_iter_item( fd_solcap_chunk_iter_t const * iter ) {
  return &iter->chunk;
}

FD_PROTOTYPES_END

#endif /* FD_HAS_HOSTED */

#endif /* HEADER_fd_src_flamenco_capture_fd_solcap_reader_h */

