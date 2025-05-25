#include "fd_io_readline.h"
#include "../../util/cstr/fd_cstr.h"

char *
fd_io_fgets( char * restrict            str,
             int                        str_max,
             fd_io_buffered_istream_t * istream,
             int *                      perr ) {
  *perr = 0;
  ulong const out_max = (ulong)fd_int_max( str_max, 1 ) - 1UL;

  for( ulong attempt=0UL; attempt<=1UL; attempt++ ) {
    char const * peek     = fd_io_buffered_istream_peek   ( istream );
    ulong        peek_max = fd_io_buffered_istream_peek_sz( istream );

    void * peek_found = memchr( peek, '\n', peek_max );
    if( peek_found ) {
      ulong peek_sz = (ulong)peek_found - (ulong)peek + 1UL;
      peek_sz = fd_ulong_min( peek_sz, out_max );
      fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( str ), peek, peek_sz ) );
      fd_io_buffered_istream_skip( istream, peek_sz );
      return str;
    }

    int err = fd_io_buffered_istream_fetch( istream );
    if( FD_UNLIKELY( err>0 ) ) {
      *perr = err;
      return NULL;
    }
    if( FD_UNLIKELY( err<0 ) ) {
      *perr = -1;
      /* continue */
    }
    if( FD_UNLIKELY( !fd_io_buffered_istream_peek_sz( istream ) ) ) {
      *perr = -1;
      return NULL;
    }
  }

  /* Could not find newline char even with full buffer, so just return
     what we have. */
  char const * peek     = fd_io_buffered_istream_peek   ( istream );
  ulong        peek_max = fd_io_buffered_istream_peek_sz( istream );
  ulong        peek_sz  = fd_ulong_min( out_max, peek_max );
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( str ), peek, peek_sz ) );
  return str;
}

int
fd_io_fgetc( fd_io_buffered_istream_t * istream,
             int *                      perr ) {
  for( ulong attempt=0UL; attempt<=1UL; attempt++ ) {
    uchar const * peek     = fd_io_buffered_istream_peek   ( istream );
    ulong         peek_max = fd_io_buffered_istream_peek_sz( istream );
    if( peek_max ) {
      *perr = 0;
      return (int)*peek;
    }

    int err = fd_io_buffered_istream_fetch( istream );
    if( FD_UNLIKELY( err!=0 ) ) {
      *perr = err;
      return -1;
    }
  }

  /* unreachable */
  *perr = -1;
  return -1;
}
