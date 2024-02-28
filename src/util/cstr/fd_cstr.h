#ifndef HEADER_fd_src_cstr_fd_cstr_h
#define HEADER_fd_src_cstr_fd_cstr_h

/* APIs for manipulating '\0'-terminated character strings ("cstr") */

#include "../bits/fd_bits.h"

FD_PROTOTYPES_BEGIN

/* cstr input *********************************************************/

/* fd_cstr_to_T converts the cstr pointed at by s into a T and returns
   its value.  Caller promises s is non-NULL and points at a cstr.

   Note fd_cstr_to_cstr just returns s.  As such the lifetime of the
   returned pointer is the lifetime s and ownership model of the
   underlying s is defined by the application.

   fd_cstr_to_char just returns the first character of the cstr (if cstr
   is the empty string, this will be the '\0' character ... otherwise,
   it will be a normal string character).  As char do not have a
   consistent interpretation between platforms due to issues with the
   language standard itself, the value here should just be treated as a
   character and not an integer.  Use fd_cstr_schar/fd_cstr_uchar if you
   need to treat a char as an integer.

   fd_cstr_to_cstr and fd_cstr_to_char exist primarily for type system
   completeness / facilitate various generic programming practices.

   The integer converters work in the strtol sense with base 0 (and thus
   ignore leading whitespace, handle leading signs and assume octal if
   the body is prefixed with 0, hexadecimal if prefixed with 0x and
   decimal otherwise). */

FD_FN_CONST char const * fd_cstr_to_cstr  ( char const * s );
FD_FN_PURE  char         fd_cstr_to_char  ( char const * s );
FD_FN_PURE  schar        fd_cstr_to_schar ( char const * s );
FD_FN_PURE  short        fd_cstr_to_short ( char const * s );
FD_FN_PURE  int          fd_cstr_to_int   ( char const * s );
FD_FN_PURE  long         fd_cstr_to_long  ( char const * s );
FD_FN_PURE  uchar        fd_cstr_to_uchar ( char const * s );
FD_FN_PURE  ushort       fd_cstr_to_ushort( char const * s );
FD_FN_PURE  uint         fd_cstr_to_uint  ( char const * s );
FD_FN_PURE  ulong        fd_cstr_to_ulong ( char const * s );
FD_FN_PURE  float        fd_cstr_to_float ( char const * s );
#if FD_HAS_DOUBLE
FD_FN_PURE  double       fd_cstr_to_double( char const * s );
#endif

/* fd_cstr_to_ulong_octal is the same as fd_cstr_to_ulong but assumes s
   points is octal.  This is mostly used when dealing parsing UNIX style
   file permissions. */

FD_FN_PURE ulong fd_cstr_to_ulong_octal( char const * s );

/* fd_cstr_to_ulong_seq populates seq (which has room for seq max items)
   with the sequenced specified by the given cstr.  Sequences are a
   comma separated list of ranges (e.g. "R0,R1,R2").  The ranges
   themselves can be themselves be individual integers (e.g. "5") or a
   simple range (e.g. "4-8", includes both endpoints, stop should be at
   least start), a range with a skip (e.g. "1-10/3" or "1-10:3", stop
   should be at least start and stride should be positive).  Ignores
   internal whitespace.  Robust against overflow / wrapping of ranges
   against ULONG_MAX.  Items may appear in multiple times and sequences
   can have an arbitrary order.  Caller promises seq is non-NULL if max
   is non-zero.  Returns 0 on NULL or malformed cstr or empty sequence
   (seq contents might have been arbitrarily clobbered on a malformed
   cstr). */

ulong                                         /* Actual sequence length, if greater than seq_max returned sequence truncated. */
fd_cstr_to_ulong_seq( char const * cstr,      /* String to parse, NULL returns 0 */
                      ulong *      seq,       /* Indexed [0,max), elements [0,min(actual sequence length,seq_max)) populated with
                                                 the leading portion of the seq.  Any remaining elements of seq are untouched. */
                      ulong        seq_max ); /* Maximum sequence length */

/* fd_cstr_hash hashes the cstr pointed to by key to a ulong.
   fd_cstr_hash_append updates the hash value (it will be as though the
   fd_cstr_hash was called on the string concatenation of the all the
   keys provided to hash / hash append in order).  Treats key==NULL the
   same as the empty string "".  Yields identical cross platform results
   regardless of how the platform treats the sign of char.  Based on one
   of the djb2 hash variants (public domain).

   FIXME: This is simple and fast and pretty good practically for string
   hashing but more robust and faster algos are probably out there. */

FD_FN_PURE static inline ulong
fd_cstr_hash_append( ulong        hash,
                     char const * key ) {
  if( FD_LIKELY( key ) ) {
    uchar const * p = (uchar const *)key;
    for(;;) {
      ulong c = p[0];
      if( FD_UNLIKELY( !c ) ) break;
      hash = (hash*33UL) ^ c;
      p++;
    }
  }
  return hash;
}

FD_FN_PURE static inline ulong fd_cstr_hash( char const * key ) { return fd_cstr_hash_append( 5381UL, key ); }

/* fd_cstr_casecmp is equivalent to strcasecmp but doesn't require
   FD_HAS_HOSTED (POSIX) support. */

FD_FN_PURE int
fd_cstr_casecmp( char const * a,
                 char const * b );

/* fd_cstr_nlen is equivalent to strnlen but doesn't require
   FD_HAS_HOSTED (POSIX) support. */

FD_FN_PURE ulong
fd_cstr_nlen( char const * s,
              ulong        m );

/* cstr output ********************************************************/

/* fd_cstr_printf printf a cstr into the sz byte memory region pointed
   to by buf.  Always returns buf.

   If buf is non-NULL and sz is non-zero, on return, buf will point to a
   cstr such that strlen(buf)<sz.  That is, bytes [0,strlen(buf)] will
   be non-'\0', byte strlen(buf) will be '\0' and bytes (len,sz) will be
   unchanged.  If more than sz bytes are needed to hold the requested
   cstr, the cstr will be truncated to its leading bytes such that
   strlen(buf)==sz-1.  If opt_len is non-NULL, *opt_len will be set to
   the strlen(buf) on return.

   buf==NULL and/or sz==0UL are treated as a no-op.  (If opt_len is
   non-NULL *opt_len wll be 0UL on return ... this is debatable though
   given the strlen(buf) property above.  Might be better to this case
   as U.B., or abort if opt_len is requested when buf==NULL and sz==NULL
   or return ULONG_MAX in opt_len (-1) to indicate ill defined usage or
   ...) */

char *
fd_cstr_printf( char *       buf,
                ulong        sz,
                ulong *      opt_len,
                char const * fmt, ... ) __attribute__((format(printf,4,5)));

/* fd_cstr_printf_check is the same as fd_cstr_printf except that it
   returns 1 if the entire cstr was written to buf and 0 otherwise.

   If the cstr was truncated, or there was an error in the printf
   formatting process, 0 will be returned.  Otherwise, on success, 1
   will be returned.  If zero bytes are written to buf because the
   format string is empty, the return value will be 1. */

int
fd_cstr_printf_check( char *       buf,
                      ulong        sz,
                      ulong *      opt_len,
                      char const * fmt, ... ) __attribute__((format(printf,4,5)));

/* fd_cstr_init start writing a cstr into buf.  Returns where the first
   character of the cstr should be written (==buf). */

static inline char * fd_cstr_init( char * buf ) { return buf; }

/* fd_cstr_fini finished writing a cstr to buf.  Assumes p is valid
   (non-NULL and room for the terminating '\0').  At this point, the buf
   passed to fd_cstr_init will be properly '\0' terminated. */

static inline void fd_cstr_fini( char * p ) { *p = '\0'; }

/* fd_cstr_append_char append character c to cstr.  Assumes p is valid
   (non-NULL and room for at least this char and a final terminating
   '\0') and c is not '\0' */

static inline char * fd_cstr_append_char( char * p, char c ) { *(p++) = c; return p; }

/* fd_cstr_append_text appends n characters of text pointed to by t to
   p.  Assumes p is valid (non-NULL and room for at least n characters
   and a final terminating '\0') and t is valid (points to n consecutive
   non-'\0' characters).  n is zero is fine. */

static inline char *
fd_cstr_append_text( char *       p,
                     char const * t,
                     ulong        n ) {
  fd_memcpy( p, t, n );
  return p + n;
}

/* fd_cstr_append_cstr appends the cstr pointed to by s to p.  Assumes p
   is valid (non-NULL and room for at least strlen( s ) characters and a
   final terminating '\0').  s==NULL is treated as a no-op. */

static inline char *
fd_cstr_append_cstr( char *       p,
                     char const * s ) {
  if( FD_UNLIKELY( !s ) ) return p;
  ulong n = strlen( s );
  fd_memcpy( p, s, n );
  return p + n;
}

/* fd_cstr_append_cstr_safe appends up to n chars of the cstr pointed
   to by to p.  Assumes p is valid (non-NULL and room for at least n
   characters and a final terminating '\0').  s==NULL is treated as a
   no-op. */

static inline char *
fd_cstr_append_cstr_safe( char *       p,
                          char const * s,
                          ulong        n ) {
  if( FD_UNLIKELY( !s ) ) return p;
  ulong l = fd_ulong_min( strlen( s ), n );
  fd_memcpy( p, s, l );
  return p + l;
}

/* fd_cstr_append_printf appends the printf of the fmt string into p.
   Assumes p is valid (non-NULL and room for printf characters and a
   final terminating '\0'). */

char *
fd_cstr_append_printf( char *       p,
                       char const * fmt, ... ) __attribute__((format(printf,2,3)));

/* fd_cstr_append_ulong_as_text pretty prints the ulong into p (and
   similarly for the other unsigned integer types).  Assumes p is valid
   (non-NULL and room for at least n characters and a final terminating
   '\0'), x is small enough to pretty print to n chars (which implies
   that n is at least 1).  ws is the character to left pad the converted
   value with.  pfx is prefix character to use (e.g. '+', '-'), '\0'
   indicates no prefix.  If a prefix is requested, it will be
   immediately before the most significant converted character. */

static inline char *
fd_cstr_append_uint_as_text( char * p,
                             char   ws,
                             char   pm,
                             uint   x,
                             ulong  n ) {
  char * p0 = p;
  p += n;
  char * q = p;
  do { uint d = x % 10U; x /= 10U; *(--q) = (char)( d + (uint)'0' ); } while( x );
  if( pm ) *(--q) = pm;
  while( p0<q ) *(p0++) = ws;
  return p;
}

static inline char *
fd_cstr_append_ulong_as_text( char * p,
                              char   ws,
                              char   pm,
                              ulong  x,
                              ulong  n ) {
  char * p0 = p;
  p += n;
  char * q = p;
  do { ulong d = x % 10UL; x /= 10UL; *(--q) = (char)( d + (ulong)'0' ); } while( x );
  if( pm ) *(--q) = pm;
  while( p0<q ) *(p0++) = ws;
  return p;
}

static inline char *
fd_cstr_append_uchar_as_text ( char * p,
                               char   ws,
                               char   pm,
                               uchar  x,
                               ulong  n ) {
  return fd_cstr_append_uint_as_text( p, ws, pm, (uint)x, n );
}

static inline char *
fd_cstr_append_ushort_as_text( char * p,
                               char   ws,
                               char   pm,
                               ushort x,
                               ulong  n ) {
  return fd_cstr_append_uint_as_text( p, ws, pm, (uint)x, n );
}

/* fd_cstr_append_fxp10_as_text same as the above but for the decimal
   fixed point value:
     x / 10^f
   Assumes p is valid (non-NULL and room for at least n characters and a
   final terminating '\0'), x / 10^f is not too large to fit within n
   characters (which implies that n is at least f+2).  ws is the
   character to left pad the converted value with.  pfx is prefix
   character to use (e.g. '+', '-'), '\0' indicates no prefix.  If a
   prefix is requested, it will be immediately before the most
   significant converted character. */

FD_FN_UNUSED static char * /* Work around -Winline */
fd_cstr_append_fxp10_as_text( char * p,
                              char   ws,
                              char   pm,
                              ulong  f,
                              ulong  x,
                              ulong  n ) {
  char * p0 = p;
  p += n;
  char * q = p;
  while( f ) { ulong d = x % 10UL; x /= 10UL; *(--q) = (char)( d + (ulong)'0' ); f--; }
  *(--q) = '.';
  do { ulong d = x % 10UL; x /= 10UL; *(--q) = (char)( d + (ulong)'0' ); } while( x );
  if( pm ) *(--q) = pm;
  while( p0<q ) *(p0++) = ws;
  return p;
}

/* fd_cstr_tokenize tokenizes the cstr of the form whose first
   byte is pointed to by cstr:

     [WS][TOKEN 0][DELIM][WS][TOKEN 1][DELIM]...[WS][TOKEN N]{[DELIM][WS][NUL],[NUL]}

   in-place, into:

     [WS][TOKEN 0][NUL][WS][TOKEN 1][NUL]...[WS][TOKEN tok_cnt-1][NUL]

   and returns tok_cnt.

   Further, on return, tok[i] for i in [0,min(tok_cnt,tok_max)) where
   tok_cnt is the number of tokens in cstr will point to the first
   byte of each token.  Due to the tokenization, each one of these will
   be properly '\0' terminated.

   Above, [WS] is a sequence of zero or more whitespace characters,
   [TOKEN *] are a sequence of zero or more non-delim and non-NUL
   characters and delim is assumed to be a non-NUL non-whitespace
   character (e.g. ',').

   As such:
   - The original cstr is clobbered by this call.
   - tok[*] point to a properly terminated cstr into the original cstr
     on return.  They thus have the same lifetime issues as the original
     cstr.
   - If tok_cnt > tok_max, tok wasn't large enough to hold all the
     tokens found in the cstr.  Only the first max are available in
     tok[*] (the entire string was still tokenized though).
   - Found tokens will not have any leading whitespace.
   - Found tokens might have internal or trailing whitespace.
   - Zero length tokens are possible.  E.g. assuming delim==':', the cstr
     "a: b::d: :f" has the tokens: "a", "b", "", "d", "", "f".
   - If the final token is zero length, it should use an explicit
     delimiter.  E.g. assuming delim=='|':
       "a|b"     has tokens "a", "b"
       "a|b|"    has tokens "a", "b"
       "a|b| "   has tokens "a", "b"
       "a|b||"   has tokens "a", "b", ""
       "a|b| |"  has tokens "a", "b", ""
       "a|b| | " has tokens "a", "b", ""
   - This is also true if the final token is the initial token.  E.g.
     assuming delim==';':
       ""    has no tokens
       " "   has no tokens
       ";"   has the token ""
       " ;"  has the token ""
       " ; " has the token "" */

ulong
fd_cstr_tokenize( char ** tok,
                  ulong   tok_max,
                  char *  cstr,
                  char    delim );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_cstr_fd_cstr_h */
