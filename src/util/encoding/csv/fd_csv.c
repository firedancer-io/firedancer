#include "fd_csv.h"
#include "fd_csv_private.h"

#include <errno.h>

#if FD_HAS_HOSTED

/* Defined by fd_util_base.h.
   Note that the _POSIX_C_SOURCE and _GNU_SOURCE strerror_r prototypes
   have different return types. */
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE<200112L || defined(_GNU_SOURCE)
#error "Needs _POSIX_C_SOURCE>=200112L for strerror_r"
#endif

#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "../../bits/fd_bits.h"
#include "../../cstr/fd_cstr.h"
#include "../../sanitize/fd_sanitize.h"

/* Thread-local error storage *****************************************/

static FD_TLS int csv_errno     =  0;
static FD_TLS int csv_err_srcln = -1;

static FD_TLS char csv_errbuf[ FD_CSVERR_BUFSZ ] = {0};

FD_TLS char csv_buf[ FD_CSV_BUFSZ ] = {0};

/* fd_csv_seterr: Persists the given error and source line number in
   thread-local storage, and returns `err`. */
int
fd_csv_seterr( int err,
               int srcln ) {
  csv_errno     = err;
  csv_err_srcln = srcln;
  return err;
}

/* FD_CSVERR: Persists the given error and the line number of the call
   site and returns `err` from the current function. */
#define FD_CSVERR( err ) return fd_csv_seterr( (err), __LINE__ )

char const *
fd_csv_strerror( void ) {
  char * str = fd_cstr_init( csv_errbuf );

  /* Write errno cstr to buffer.
     Leaves 32 chars space for line number info to be concatenated.
     The longest line number tag " (at fd_csv.c(-2147483648))" is 27
     chars long, so this is safe. */
  if( FD_UNLIKELY( 0!=strerror_r( csv_errno, str, FD_CSVERR_BUFSZ-32UL ) ) )
    strcpy( csv_errbuf, "Unknown error" );
  str += strlen( str );

  /* Append source line number info */
  fd_cstr_append_printf( str, " (at fd_csv.c(%d))", csv_err_srcln );

  return csv_errbuf;
}

/* CSV read implementation ********************************************/

/* ### Memory Management

   `fd_csv_read_record` is a stateless wrapper over a stream handle
   (`FILE *` on POSIX).  A static thread-local read buffer is used to
   temporarily store parsed cstrs (`csv_buf`).  The state of this buffer
   resets on every call.

     +-----------------------------:
     | column_1,column2,colu\0???? :
     ^----------^-----------^------:
     csv_buf    p           q

   Constraints on the buffer are as follows

   - p  points to the leftmost char that has not been parsed yet.
   - q  points to the rightmost char that has been read from the FILE.
   - *q is always '\0' */

/* fd_csv_iseol: Returns non-zero if `c` is <CR>, <LF> or end-of-cstr */
static inline int
fd_csv_iseol( int c ) {
  return c=='\n' || c=='\r' || c=='\0';
}

/* fd_csv_readbuf: Reads up to FD_CSV_READSZ chars into mem at q and
   returns the number of chars read on success, or 0 on failure.

   Sets `csv_err` to ENOMEM if less than `min_avail` chars are available
   due to lack of space in the read buffer or to EPROTO due to EOF. On
   any other error, sets csv_err fread(3) return value. On success,
   ensures that *q is '\0'. */
static ulong
fd_csv_readbuf( char * q,
                FILE * stream ) {
  /* Assert that q >= csv_buf */

  ulong freesz = (ulong)((csv_buf+FD_CSV_BUFSZ-1UL)-q); /* always >=0UL */
  ulong readsz = fd_ulong_min( FD_CSV_READSZ, freesz );

  /* Read next chunk */

  fd_asan_unpoison( q, readsz+1 );

  /* Clear errno and read buf. The return value does not indicate EOF or
     read error to the caller. Thus, `feof()` and `errno` has to be
     checked manually. */

  errno = 0;
  ulong res = fread( q, 1UL, readsz, stream );
  if( FD_UNLIKELY( res<readsz && ferror( stream ) ) ) {
    fd_csv_seterr( errno, __LINE__ );
    return 0UL;
  }

  q += res;
  q[0] = '\0';

  /* Assumes that res==read_sz if !ferror( stream ) && !feof( stream ) */

  return res;
}

#define FD_CSV_REFILL()                                                \
  do {                                                                 \
    ulong n = fd_csv_readbuf( q, stream );                             \
    if( FD_UNLIKELY( n==0UL ) ) return csv_errno;                      \
    q+=n;                                                              \
  } while(0)

static inline int
fd_csv_readbuf_full( char * q ) {
  return (q-csv_buf+1L)>=(long)FD_CSV_BUFSZ;
}

/* fd_csv_read_field: Reads a CSV field from `*cursor`.

   On success, returns zero, stores a pointer to the beginning of the
   field to `col`, and stores a pointer to the char following the end
   of the field to `cursor`.

   The return value, error handling, and the `sep`, `quote` arguments
   match the behavior of `fd_csv_read_record`. */
static int
fd_csv_read_field( char ** _p,
                   char ** _q,
                   char ** col,
                   int     sep,
                   int     quote,
                   FILE *  stream ) {
  char * p = *_p;
  char * q = *_q;

  /* TODO: Consider implementing lazy quote handling analagous to Go's
     encoding/csv `LazyQuotes` option.  This option allows unescaped
     quotes within a quoted field, i.e. `"my"field"`. */

  /* Expect printable char, start-of-quote, sep, EOL, EOF. */
  int quoted = (int)p[0]==quote;
  if( quoted ) {
    p++;
    *col = p;

    /* Expect any, end-of-quote, double-quote.
       Loop terminates when end-of-quote is found. */
    long shift = 0;
    for(;;) {
      if( FD_UNLIKELY( q-p<2L ) ) FD_CSV_REFILL();

      /* If insufficient chars available after refill, out of buf space. */
      if( FD_UNLIKELY( !feof( stream ) && fd_csv_readbuf_full( q ) ) ) return ENOMEM;

      /* On end-of-quote or double-quote */
      if( FD_UNLIKELY( p[0]==quote ) ) {
        if( FD_UNLIKELY( p[1]==quote ) ) {
          /* Shift subsequent tokens to left */
          p[ -shift ] = (char)quote;
          p++;
          shift++;
          continue;
        } else {
          /* Terminate field */
          p[ -shift ] = '\0';
          p++;
          break;
        }
      }

      /* Error if EOF, but any or end-of-quote expected */
      if( FD_UNLIKELY( p[0]=='\0' ) ) FD_CSVERR(EPROTO);

      /* On any quoted char */
      p[ -shift ] = p[0];
      p++;
    }

    /* Expect sep, EOL, EOF */
    if( FD_UNLIKELY( p[0]!=sep && !fd_csv_iseol( (int)p[0] ) ) )
      FD_CSVERR(EPROTO);

    p -= shift;
  } else {
    *col = p;
    /* Expect printable char, sep, EOL, EOF */
    while( FD_UNLIKELY( p[0]!=sep && !fd_csv_iseol( (int)p[0] ) ) ) {
      p++;
      if( FD_UNLIKELY( p==q ) ) FD_CSV_REFILL();
    }
    if( FD_UNLIKELY( !feof( stream ) && fd_csv_readbuf_full( q ) ) ) return ENOMEM;
  }

  /* Store cursor. */
  *_p = p;
  *_q = q;
  return 0;
}

int
fd_csv_read_record( char ** col_cstrs,
                    ulong   col_cnt,
                    int     sep,
                    int     quote,
                    void *  _stream ) {
  FILE * stream = _stream;

  /* Unpoison buffer as we go */

  fd_asan_poison  ( csv_buf, FD_CSV_BUFSZ );
  fd_asan_unpoison( csv_buf,          1UL );

  /* Check input args */

  if( FD_UNLIKELY( !col_cstrs  ) ) FD_CSVERR(EINVAL);
  if( FD_UNLIKELY( col_cnt==0  ) ) FD_CSVERR(EINVAL);

  if( FD_UNLIKELY( !stream     ) ) FD_CSVERR(EINVAL);

  if( FD_UNLIKELY( sep  =='\0'           ) ) FD_CSVERR(EINVAL);
  if( FD_UNLIKELY( quote=='\0'           ) ) FD_CSVERR(EINVAL);
  if( FD_UNLIKELY( quote==sep            ) ) FD_CSVERR(EINVAL);
  if( FD_UNLIKELY( isspace( (int)sep   ) ) ) FD_CSVERR(EINVAL);
  if( FD_UNLIKELY( isspace( (int)quote ) ) ) FD_CSVERR(EINVAL);

  /* p: Parsing cursor.
     Maintains invariant that `p` does not point past the nul terminator
     of the cstr in csv_buf. */
  char * p = csv_buf;
  p[0] = '\0';

  /* q: Readahead cursor.  (points to the end of the populated buffer)
     Maintains invariant that
     - q-csv_buf < FD_CSV_BUFSZ (leave space for nul terminator)
     - p..q interpreted as a cstr does not end past q */
  char * q;

  /* Seek past initial whitespace and copy buffer. */
  for(;;) {
    /* Reset buffer state, as whitespace can be discarded */
    p = csv_buf;
    q = csv_buf;

    /* Read chunk from buffer */
    ulong n = fd_csv_readbuf( p, stream );
    if( FD_UNLIKELY( n==0UL ) )
      FD_CSVERR( feof( stream ) ? ENOENT : errno );

    /* Skip initial whitespace and empty lines */
    while( isspace( (int)p[0] ) ) p++;

    /* Retry if end of buffer reached after skipping initial whitespace */
    if( FD_UNLIKELY( p[0]=='\0' ) ) continue;

    /* Remember amount of chars available in buffer */
    q+=n;
    break;
  }

  /* Read each field */
  for( ulong col=0UL; col<col_cnt; col++ ) {
    int err = fd_csv_read_field( &p, &q, &col_cstrs[ col ], sep, quote, stream );
    if( FD_UNLIKELY( err!=0 ) ) return err;

    /* Allow 1 char of readahead */
    if( FD_UNLIKELY( p==q ) ) FD_CSV_REFILL();

    if( col+1 < col_cnt ) {
      /* Expect sep */
      if( FD_UNLIKELY( p[0]!=sep ) ) return EPROTO;
      p[0] = '\0';
      p++;
    } else {
      /* Expect EOF or EOL */
      if( FD_UNLIKELY( !fd_csv_iseol( (int)p[0] ) ) ) return EPROTO;
      p[0] = '\0';
    }
  }

  return 0;
}

#undef READ_CHUNK
#undef FD_CSVERR

#else /* Not supported on this target */

int
fd_csv_read_record( char ** col_cstrs,
                    ulong   col_cnt,
                    int     sep,
                    int     quote,
                    void *  stream ) {
  return ENOSYS;
}

char const *
fd_csv_strerror( void ) {
  return "Not supported on this target";
}

#endif
