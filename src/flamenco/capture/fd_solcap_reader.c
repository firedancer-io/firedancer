#include "fd_solcap_reader.h"
#include "fd_solcap_proto.h"

#if !FD_HAS_HOSTED
#error "fd_solcap_reader requires FD_HAS_HOSTED"
#endif

#include <errno.h>

fd_solcap_chunk_iter_t *
fd_solcap_chunk_iter_new( fd_solcap_chunk_iter_t * iter,
                          FILE *                   stream ) {

  long pos = ftell( stream );
  if( FD_UNLIKELY( pos<0L ) ) {
    iter->err = errno;
    return iter;
  }

  *iter = (fd_solcap_chunk_iter_t) {
    .stream     = stream,
    .chunk      = {0},
    .next_chunk = (ulong)pos,
  };
  return iter;
}

long
fd_solcap_chunk_iter_next( fd_solcap_chunk_iter_t * iter ) {

  FILE * stream = iter->stream;

  if( FD_UNLIKELY( 0!=fseek( iter->stream, (long)iter->next_chunk, SEEK_SET ) ) ) {
    FD_LOG_WARNING(( "fseek failed (%d-%s)", errno, strerror( errno ) ));
    iter->err = errno;
    return -1L;
  }

  long chunk_gaddr = ftell( stream );
  if( FD_UNLIKELY( chunk_gaddr<0L ) ) {
    FD_LOG_WARNING(( "ftell failed (%d-%s)", errno, strerror( errno ) ));
    iter->err = errno;
    return -1L;
  }

  ulong n = fread( &iter->chunk, sizeof(fd_solcap_chunk_t), 1UL, stream );
  if( FD_UNLIKELY( n!=1UL ) ) {
    int err = ferror( stream );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "fread failed (%d-%s)", errno, strerror( errno ) ));
      iter->err = err;
    }
    return -1L;
  }

  if( FD_UNLIKELY( ( !fd_solcap_is_chunk_magic( iter->chunk.magic )   )
                 | ( iter->chunk.total_sz < sizeof(fd_solcap_chunk_t) ) ) ) {
    FD_LOG_WARNING(( "invalid chunk (offset=%#lx magic=0x%016lx total_sz=%lu)",
                     chunk_gaddr, iter->chunk.magic, iter->chunk.total_sz ));
    iter->err = EPROTO;
    return -1L;
  }

  iter->next_chunk = (ulong)chunk_gaddr + iter->chunk.total_sz;

  return chunk_gaddr;
}
