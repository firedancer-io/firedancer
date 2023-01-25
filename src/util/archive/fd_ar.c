#include "fd_ar.h"

#include <errno.h>
#include <string.h>

static const char magic_expected[ 8 ] =
  { '!', '<', 'a', 'r', 'c', 'h', '>', '\n' };

int
fd_ar_open( FILE * stream ) {
  /* Check archive header magic */
  char magic[ 8 ];
  size_t n = fread( magic, sizeof(magic), 1, stream );
  if( FD_UNLIKELY( n!=1 ) ) return 0;
  if( 0!=memcmp( magic, magic_expected, sizeof(magic) ) ) {
    errno = EPROTO;
    return 0;
  }
  return 1;
}

int
fd_ar_next( FILE *    stream,
            fd_ar_t * hdr ) {
  long pos;
  size_t n;

  /* Headers are two-byte aligned */
  pos = ftell( stream );
  if( FD_UNLIKELY( pos<0L ) ) return 0;
  if( FD_UNLIKELY( (pos&1L)==1L && fseek( stream, 1L, SEEK_CUR )<0L ) ) goto io_error;

  /* Read file header */
  n = fread( hdr, sizeof(fd_ar_t), 1, stream );
  if( FD_UNLIKELY( n!=1 ) ) goto io_error;
  if( FD_UNLIKELY( hdr->magic!=FD_AR_FILE_MAGIC ) ) {
    errno = EPROTO;
    return 0;
  }

  /* Everything ok */
  return 1;

io_error:
  if( FD_LIKELY( feof( stream ) ) ) errno = ENOENT;
  return 0;
}
