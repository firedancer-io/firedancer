#include "fd_jtok.h"

#include <errno.h>
#include <math.h>
#include <stdlib.h>

/* Every public entry point checks j->err first, so err is always zero
   when fail is reached.  cur is left at the offending byte so that
   fd_jtok_err_off is meaningful. */

static inline int
fail( fd_jtok_t * j,
      int         err ) {
  j->err = err;
  return 0;
}

static inline int
is_ws( char c ) {
  return c==' ' || c=='\t' || c=='\n' || c=='\r';
}

static inline int
is_digit( char c ) {
  return c>='0' && c<='9';
}

static inline void
skip_ws( fd_jtok_t * j ) {
  while( j->cur<j->end && is_ws( *j->cur ) ) j->cur++;
}

/* utf8_len returns the byte length of the well formed UTF-8 encoded
   code point at p (>=0x80), or 0 if the bytes are not well formed
   (truncated, overlong, surrogate, or above U+10FFFF). */

static ulong
utf8_len( uchar const * p,
          uchar const * end ) {
  ulong rem = (ulong)( end-p );
  uchar c   = p[0];
  ulong n;
  uchar lo = 0x80, hi = 0xBF;
  if(      c>=0xC2 && c<=0xDF ) n = 2UL;
  else if( c>=0xE0 && c<=0xEF ) { n = 3UL; if( c==0xE0 ) lo = 0xA0; else if( c==0xED ) hi = 0x9F; }
  else if( c>=0xF0 && c<=0xF4 ) { n = 4UL; if( c==0xF0 ) lo = 0x90; else if( c==0xF4 ) hi = 0x8F; }
  else return 0UL;
  if( FD_UNLIKELY( rem<n ) ) return 0UL;
  if( FD_UNLIKELY( p[1]<lo || p[1]>hi ) ) return 0UL;
  for( ulong i=2UL; i<n; i++ ) if( FD_UNLIKELY( (p[i]&0xC0)!=0x80 ) ) return 0UL;
  return n;
}

/* hex4 parses 4 hex digits at p (caller guarantees 4 bytes) into *cp.
   Returns 1 on success, 0 if a digit is invalid. */

static int
hex4( char const * p,
      uint *       cp ) {
  uint v = 0U;
  for( ulong i=0UL; i<4UL; i++ ) {
    char c = p[i];
    uint d;
    if(      c>='0' && c<='9' ) d = (uint)( c-'0' );
    else if( c>='a' && c<='f' ) d = (uint)( c-'a' ) + 10U;
    else if( c>='A' && c<='F' ) d = (uint)( c-'A' ) + 10U;
    else return 0;
    v = (v<<4) | d;
  }
  *cp = v;
  return 1;
}

/* lex_string validates the string starting at the opening quote at
   j->cur and advances past the closing quote.  Stores the raw contents
   in *out.  Escape syntax, surrogate pairing, UTF-8 well formedness
   and absence of control characters are all enforced here so that
   decoding can assume a valid view. */

static int
lex_string( fd_jtok_t *     j,
            fd_jtok_str_t * out ) {
  char const * p     = j->cur+1;
  char const * start = p;
  for(;;) {
    if( FD_UNLIKELY( p>=j->end ) ) { j->cur = p; return fail( j, FD_JTOK_ERR_SYNTAX ); }
    uchar c = (uchar)*p;
    if( c=='"' ) {
      out->ptr = start;
      out->sz  = (ulong)( p-start );
      j->cur = p+1;
      return 1;
    }
    if( c=='\\' ) {
      p++;
      if( FD_UNLIKELY( p>=j->end ) ) { j->cur = p; return fail( j, FD_JTOK_ERR_SYNTAX ); }
      switch( *p ) {
      case '"': case '\\': case '/': case 'b': case 'f': case 'n': case 'r': case 't':
        p++;
        break;
      case 'u': {
        uint cp;
        p++;
        if( FD_UNLIKELY( j->end-p<4L || !hex4( p, &cp ) ) ) { j->cur = p; return fail( j, FD_JTOK_ERR_SYNTAX ); }
        p += 4;
        if( cp>=0xD800U && cp<=0xDBFFU ) {
          uint lo;
          if( FD_UNLIKELY( j->end-p<6L || p[0]!='\\' || p[1]!='u' || !hex4( p+2, &lo ) || lo<0xDC00U || lo>0xDFFFU ) ) {
            j->cur = p; return fail( j, FD_JTOK_ERR_SYNTAX );
          }
          p += 6;
        } else if( FD_UNLIKELY( cp>=0xDC00U && cp<=0xDFFFU ) ) {
          j->cur = p-4; return fail( j, FD_JTOK_ERR_SYNTAX );
        }
        break;
      }
      default:
        j->cur = p; return fail( j, FD_JTOK_ERR_SYNTAX );
      }
      continue;
    }
    if( FD_UNLIKELY( c<0x20 ) ) { j->cur = p; return fail( j, FD_JTOK_ERR_SYNTAX ); }
    if( c<0x80 ) { p++; continue; }
    ulong n = utf8_len( (uchar const *)p, (uchar const *)j->end );
    if( FD_UNLIKELY( !n ) ) { j->cur = p; return fail( j, FD_JTOK_ERR_SYNTAX ); }
    p += n;
  }
}

/* lex_number validates the number starting at j->cur and advances past
   it.  Stores FD_JTOK_INT or FD_JTOK_NUM in *kind. */

static int
lex_number( fd_jtok_t * j,
            int *       kind ) {
  char const * p = j->cur;
  if( p<j->end && *p=='-' ) p++;
  if( FD_UNLIKELY( p>=j->end ) ) { j->cur = p; return fail( j, FD_JTOK_ERR_SYNTAX ); }
  if( *p=='0' ) p++;
  else if( *p>='1' && *p<='9' ) { while( p<j->end && is_digit( *p ) ) p++; }
  else { j->cur = p; return fail( j, FD_JTOK_ERR_SYNTAX ); }
  int k = FD_JTOK_INT;
  if( p<j->end && *p=='.' ) {
    p++;
    if( FD_UNLIKELY( p>=j->end || !is_digit( *p ) ) ) { j->cur = p; return fail( j, FD_JTOK_ERR_SYNTAX ); }
    while( p<j->end && is_digit( *p ) ) p++;
    k = FD_JTOK_NUM;
  }
  if( p<j->end && (*p=='e' || *p=='E') ) {
    p++;
    if( p<j->end && (*p=='+' || *p=='-') ) p++;
    if( FD_UNLIKELY( p>=j->end || !is_digit( *p ) ) ) { j->cur = p; return fail( j, FD_JTOK_ERR_SYNTAX ); }
    while( p<j->end && is_digit( *p ) ) p++;
    k = FD_JTOK_NUM;
  }
  j->cur = p;
  *kind  = k;
  return 1;
}

static int
lex_literal( fd_jtok_t *  j,
             char const * lit,
             ulong        sz ) {
  if( FD_UNLIKELY( (ulong)( j->end-j->cur )<sz || memcmp( j->cur, lit, sz ) ) ) return fail( j, FD_JTOK_ERR_SYNTAX );
  j->cur += sz;
  return 1;
}

/* lex_scalar validates and advances past one non-container value at
   j->cur (whitespace already skipped, cur<end). */

static int
lex_scalar( fd_jtok_t * j ) {
  fd_jtok_str_t s;
  int kind;
  switch( *j->cur ) {
  case '"': return lex_string( j, &s );
  case 't': return lex_literal( j, "true",  4UL );
  case 'f': return lex_literal( j, "false", 5UL );
  case 'n': return lex_literal( j, "null",  4UL );
  default:
    if( *j->cur=='-' || is_digit( *j->cur ) ) return lex_number( j, &kind );
    return fail( j, FD_JTOK_ERR_SYNTAX );
  }
}

/* skip_value validates and advances past one value of any kind at
   j->cur.  Container nesting is tracked in a bit stack (1 bit per
   level: object or array) bounded by FD_JTOK_SKIP_DEPTH_MAX. */

static int
skip_value( fd_jtok_t * j ) {
  ulong stack = 0UL;
  ulong depth = 0UL;
  fd_jtok_str_t key;

value:
  skip_ws( j );
  if( FD_UNLIKELY( j->cur>=j->end ) ) return fail( j, FD_JTOK_ERR_SYNTAX );
  if( *j->cur=='{' || *j->cur=='[' ) {
    if( FD_UNLIKELY( depth>=FD_JTOK_SKIP_DEPTH_MAX ) ) return fail( j, FD_JTOK_ERR_DEPTH );
    int is_obj = (*j->cur=='{');
    stack = (stack<<1) | (ulong)is_obj;
    depth++;
    j->cur++;
    skip_ws( j );
    if( FD_UNLIKELY( j->cur>=j->end ) ) return fail( j, FD_JTOK_ERR_SYNTAX );
    if( *j->cur==(is_obj ? '}' : ']') ) { j->cur++; goto close; }
    if( is_obj ) goto key;
    goto value;
  }
  if( FD_UNLIKELY( !lex_scalar( j ) ) ) return 0;

after:
  if( !depth ) return 1;
  skip_ws( j );
  if( FD_UNLIKELY( j->cur>=j->end ) ) return fail( j, FD_JTOK_ERR_SYNTAX );
  {
    int is_obj = (int)(stack&1UL);
    char c = *j->cur;
    if( c==',' ) {
      j->cur++;
      if( is_obj ) goto key;
      goto value;
    }
    if( FD_UNLIKELY( c!=(is_obj ? '}' : ']') ) ) return fail( j, FD_JTOK_ERR_SYNTAX );
    j->cur++;
  }

close:
  stack >>= 1;
  depth--;
  goto after;

key:
  skip_ws( j );
  if( FD_UNLIKELY( j->cur>=j->end || *j->cur!='"' ) ) return fail( j, FD_JTOK_ERR_SYNTAX );
  if( FD_UNLIKELY( !lex_string( j, &key ) ) ) return 0;
  skip_ws( j );
  if( FD_UNLIKELY( j->cur>=j->end || *j->cur!=':' ) ) return fail( j, FD_JTOK_ERR_SYNTAX );
  j->cur++;
  goto value;
}

/* begin is the common prologue of everything that consumes or inspects
   the pending value.  Returns 1 with j->cur at the first byte of the
   value, 0 with err set otherwise. */

static inline int
begin( fd_jtok_t * j ) {
  if( FD_UNLIKELY( j->err ) ) return 0;
  if( FD_UNLIKELY( !j->pending ) ) return fail( j, FD_JTOK_ERR_USAGE );
  skip_ws( j );
  if( FD_UNLIKELY( j->cur>=j->end ) ) return fail( j, FD_JTOK_ERR_SYNTAX );
  return 1;
}

/* peek_kind is fd_jtok_peek after begin. */

static int
peek_kind( fd_jtok_t * j ) {
  switch( *j->cur ) {
  case '{': return FD_JTOK_OBJ;
  case '[': return FD_JTOK_ARR;
  case '"': return FD_JTOK_STR;
  case 't': case 'f': return FD_JTOK_BOOL;
  case 'n': return FD_JTOK_NULL;
  default: {
    if( FD_UNLIKELY( !(*j->cur=='-' || is_digit( *j->cur )) ) ) return fail( j, FD_JTOK_ERR_SYNTAX );
    char const * save = j->cur;
    int kind;
    if( FD_UNLIKELY( !lex_number( j, &kind ) ) ) return 0;
    j->cur = save;
    return kind;
  }
  }
}

/* decode_unit decodes one raw string unit at *pp (a single UTF-8
   encoded byte, or a complete escape sequence) into out and advances
   *pp.  Returns the number of bytes written, 0 if *pp is at end or the
   input is not a valid view. */

static ulong
decode_unit( char const ** pp,
             char const *  end,
             uchar         out[ 4 ] ) {
  char const * p = *pp;
  if( FD_UNLIKELY( p>=end ) ) return 0UL;
  if( *p!='\\' ) { out[0] = (uchar)*p; *pp = p+1; return 1UL; }
  if( FD_UNLIKELY( end-p<2L ) ) return 0UL;
  uint cp;
  switch( p[1] ) {
  case '"':  out[0] = '"';  *pp = p+2; return 1UL;
  case '\\': out[0] = '\\'; *pp = p+2; return 1UL;
  case '/':  out[0] = '/';  *pp = p+2; return 1UL;
  case 'b':  out[0] = '\b'; *pp = p+2; return 1UL;
  case 'f':  out[0] = '\f'; *pp = p+2; return 1UL;
  case 'n':  out[0] = '\n'; *pp = p+2; return 1UL;
  case 'r':  out[0] = '\r'; *pp = p+2; return 1UL;
  case 't':  out[0] = '\t'; *pp = p+2; return 1UL;
  case 'u':
    if( FD_UNLIKELY( end-p<6L || !hex4( p+2, &cp ) ) ) return 0UL;
    p += 6;
    if( cp>=0xD800U && cp<=0xDBFFU ) {
      uint lo;
      if( FD_UNLIKELY( end-p<6L || p[0]!='\\' || p[1]!='u' || !hex4( p+2, &lo ) || lo<0xDC00U || lo>0xDFFFU ) ) return 0UL;
      cp = 0x10000U + ((cp-0xD800U)<<10) + (lo-0xDC00U);
      p += 6;
    } else if( FD_UNLIKELY( cp>=0xDC00U && cp<=0xDFFFU ) ) {
      return 0UL;
    }
    *pp = p;
    if( cp<0x80U ) {
      out[0] = (uchar)cp;
      return 1UL;
    }
    if( cp<0x800U ) {
      out[0] = (uchar)( 0xC0U | (cp>>6) );
      out[1] = (uchar)( 0x80U | (cp&0x3FU) );
      return 2UL;
    }
    if( cp<0x10000U ) {
      out[0] = (uchar)( 0xE0U | (cp>>12) );
      out[1] = (uchar)( 0x80U | ((cp>>6)&0x3FU) );
      out[2] = (uchar)( 0x80U | (cp&0x3FU) );
      return 3UL;
    }
    out[0] = (uchar)( 0xF0U | (cp>>18) );
    out[1] = (uchar)( 0x80U | ((cp>>12)&0x3FU) );
    out[2] = (uchar)( 0x80U | ((cp>>6)&0x3FU) );
    out[3] = (uchar)( 0x80U | (cp&0x3FU) );
    return 4UL;
  default:
    return 0UL;
  }
}

/* Public API */

fd_jtok_t *
fd_jtok_init( fd_jtok_t *  j,
              void const * buf,
              ulong        sz ) {
  static char const empty[1] = { '\0' };
  if( FD_UNLIKELY( !buf ) ) { buf = empty; sz = 0UL; }
  j->beg     = (char const *)buf;
  j->cur     = j->beg;
  j->end     = j->beg + sz;
  j->err     = sz ? 0 : FD_JTOK_ERR_SYNTAX;
  j->pending = 1;
  j->first   = 0;
  j->depth   = 0UL;
  return j;
}

int
fd_jtok_fini( fd_jtok_t * j ) {
  if( FD_UNLIKELY( j->err ) ) return j->err;
  if( FD_UNLIKELY( j->depth ) ) { fail( j, FD_JTOK_ERR_USAGE ); return j->err; }
  if( j->pending ) {
    skip_ws( j );
    if( FD_UNLIKELY( !skip_value( j ) ) ) return j->err;
    j->pending = 0;
  }
  skip_ws( j );
  if( FD_UNLIKELY( j->cur<j->end ) ) fail( j, FD_JTOK_ERR_TRAIL );
  return j->err;
}

int
fd_jtok_peek( fd_jtok_t * j ) {
  if( FD_UNLIKELY( !begin( j ) ) ) return 0;
  return peek_kind( j );
}

static void
enter( fd_jtok_t * j,
       char        open ) {
  if( FD_UNLIKELY( !begin( j ) ) ) return;
  if( FD_UNLIKELY( *j->cur!=open ) ) { fail( j, FD_JTOK_ERR_TYPE ); return; }
  j->cur++;
  j->pending = 0;
  j->first   = 1;
  j->depth++;
}

/* next is the shared body of obj_next / arr_next.  Returns 1 if the
   cursor is positioned at the next element (for objects: at the key),
   0 if the container was closed or an error occurred. */

static int
next( fd_jtok_t * j,
      char        close ) {
  if( FD_UNLIKELY( j->err ) ) return 0;
  if( FD_UNLIKELY( !j->depth ) ) return fail( j, FD_JTOK_ERR_USAGE );
  if( j->pending ) {
    skip_ws( j );
    if( FD_UNLIKELY( !skip_value( j ) ) ) return 0;
    j->pending = 0;
  }
  skip_ws( j );
  if( FD_UNLIKELY( j->cur>=j->end ) ) return fail( j, FD_JTOK_ERR_SYNTAX );
  if( *j->cur==close ) {
    j->cur++;
    j->first = 0;
    j->depth--;
    return 0;
  }
  if( j->first ) {
    j->first = 0;
  } else {
    if( FD_UNLIKELY( *j->cur!=',' ) ) return fail( j, FD_JTOK_ERR_SYNTAX );
    j->cur++;
    skip_ws( j );
  }
  j->pending = 1;
  return 1;
}

void
fd_jtok_obj_enter( fd_jtok_t * j ) {
  enter( j, '{' );
}

int
fd_jtok_obj_next( fd_jtok_t *     j,
                  fd_jtok_str_t * key ) {
  if( !next( j, '}' ) ) return 0;
  if( FD_UNLIKELY( j->cur>=j->end || *j->cur!='"' ) ) return fail( j, FD_JTOK_ERR_SYNTAX );
  if( FD_UNLIKELY( !lex_string( j, key ) ) ) return 0;
  skip_ws( j );
  if( FD_UNLIKELY( j->cur>=j->end || *j->cur!=':' ) ) return fail( j, FD_JTOK_ERR_SYNTAX );
  j->cur++;
  return 1;
}

void
fd_jtok_arr_enter( fd_jtok_t * j ) {
  enter( j, '[' );
}

int
fd_jtok_arr_next( fd_jtok_t * j ) {
  return next( j, ']' );
}

void
fd_jtok_ulong( fd_jtok_t * j,
               ulong *     out ) {
  if( FD_UNLIKELY( !begin( j ) ) ) return;
  int kind = peek_kind( j );
  if( FD_UNLIKELY( !kind ) ) return;
  if( FD_UNLIKELY( kind!=FD_JTOK_INT ) ) { fail( j, FD_JTOK_ERR_TYPE ); return; }
  char const * p = j->cur;
  if( FD_UNLIKELY( *p=='-' ) ) { fail( j, FD_JTOK_ERR_RANGE ); return; }
  lex_number( j, &kind );
  ulong v = 0UL;
  for( ; p<j->cur; p++ ) {
    ulong d = (ulong)( *p-'0' );
    if( FD_UNLIKELY( v>(ULONG_MAX-d)/10UL ) ) { j->cur = p; fail( j, FD_JTOK_ERR_RANGE ); return; }
    v = v*10UL + d;
  }
  j->pending = 0;
  *out = v;
}

void
fd_jtok_long( fd_jtok_t * j,
              long *      out ) {
  if( FD_UNLIKELY( !begin( j ) ) ) return;
  int kind = peek_kind( j );
  if( FD_UNLIKELY( !kind ) ) return;
  if( FD_UNLIKELY( kind!=FD_JTOK_INT ) ) { fail( j, FD_JTOK_ERR_TYPE ); return; }
  char const * p   = j->cur;
  int          neg = (*p=='-');
  if( neg ) p++;
  lex_number( j, &kind );
  ulong lim = neg ? (ulong)LONG_MAX+1UL : (ulong)LONG_MAX;
  ulong v   = 0UL;
  for( ; p<j->cur; p++ ) {
    ulong d = (ulong)( *p-'0' );
    if( FD_UNLIKELY( v>(lim-d)/10UL ) ) { j->cur = p; fail( j, FD_JTOK_ERR_RANGE ); return; }
    v = v*10UL + d;
  }
  j->pending = 0;
  *out = neg ? (long)( 0UL-v ) : (long)v;
}

void
fd_jtok_double( fd_jtok_t * j,
                double *    out ) {
  if( FD_UNLIKELY( !begin( j ) ) ) return;
  int kind = peek_kind( j );
  if( FD_UNLIKELY( !kind ) ) return;
  if( FD_UNLIKELY( kind!=FD_JTOK_INT && kind!=FD_JTOK_NUM ) ) { fail( j, FD_JTOK_ERR_TYPE ); return; }
  char const * start = j->cur;
  lex_number( j, &kind );
  ulong sz = (ulong)( j->cur-start );
  if( FD_UNLIKELY( sz>FD_JTOK_NUM_SZ_MAX ) ) { j->cur = start; fail( j, FD_JTOK_ERR_RANGE ); return; }
  char buf[ FD_JTOK_NUM_SZ_MAX+1UL ];
  fd_memcpy( buf, start, sz );
  buf[ sz ] = '\0';
  errno = 0;
  double v = strtod( buf, NULL );
  if( FD_UNLIKELY( errno==ERANGE || !isfinite( v ) ) ) { j->cur = start; fail( j, FD_JTOK_ERR_RANGE ); return; }
  j->pending = 0;
  *out = v;
}

void
fd_jtok_bool( fd_jtok_t * j,
              int *       out ) {
  if( FD_UNLIKELY( !begin( j ) ) ) return;
  int v;
  switch( *j->cur ) {
  case 't': if( FD_UNLIKELY( !lex_literal( j, "true",  4UL ) ) ) return; v = 1; break;
  case 'f': if( FD_UNLIKELY( !lex_literal( j, "false", 5UL ) ) ) return; v = 0; break;
  default:
    if( peek_kind( j ) ) fail( j, FD_JTOK_ERR_TYPE );
    return;
  }
  j->pending = 0;
  *out = v;
}

void
fd_jtok_null( fd_jtok_t * j ) {
  if( FD_UNLIKELY( !begin( j ) ) ) return;
  if( FD_UNLIKELY( *j->cur!='n' ) ) { if( peek_kind( j ) ) fail( j, FD_JTOK_ERR_TYPE ); return; }
  if( FD_UNLIKELY( !lex_literal( j, "null", 4UL ) ) ) return;
  j->pending = 0;
}

void
fd_jtok_str( fd_jtok_t *     j,
             fd_jtok_str_t * out ) {
  if( FD_UNLIKELY( !begin( j ) ) ) return;
  if( FD_UNLIKELY( *j->cur!='"' ) ) { if( peek_kind( j ) ) fail( j, FD_JTOK_ERR_TYPE ); return; }
  fd_jtok_str_t s;
  if( FD_UNLIKELY( !lex_string( j, &s ) ) ) return;
  j->pending = 0;
  *out = s;
}

long
fd_jtok_str_decode( fd_jtok_str_t const * s,
                    char *                out,
                    ulong                 out_sz ) {
  if( out_sz ) out[0] = '\0';
  char const * p   = s->ptr;
  char const * end = s->ptr+s->sz;
  ulong        o   = 0UL;
  while( p<end ) {
    uchar unit[ 4 ];
    ulong n = decode_unit( &p, end, unit );
    if( FD_UNLIKELY( !n || !unit[0] || o+n+1UL>out_sz ) ) {
      if( out_sz ) out[0] = '\0';
      return -1L;
    }
    fd_memcpy( out+o, unit, n );
    o += n;
  }
  if( FD_UNLIKELY( o>=out_sz ) ) return -1L;
  out[ o ] = '\0';
  return (long)o;
}

void
fd_jtok_cstr( fd_jtok_t * j,
              char *      out,
              ulong       out_sz ) {
  if( out_sz ) out[0] = '\0';
  fd_jtok_str_t s;
  char const * save = j->cur;
  fd_jtok_str( j, &s );
  if( FD_UNLIKELY( j->err ) ) return;
  if( FD_UNLIKELY( fd_jtok_str_decode( &s, out, out_sz )<0L ) ) {
    j->cur = save;
    fail( j, FD_JTOK_ERR_RANGE );
  }
}

void
fd_jtok_skip( fd_jtok_t * j ) {
  if( FD_UNLIKELY( !begin( j ) ) ) return;
  if( FD_UNLIKELY( !skip_value( j ) ) ) return;
  j->pending = 0;
}

void
fd_jtok_raw( fd_jtok_t *   j,
             char const ** ptr,
             ulong *       sz ) {
  if( FD_UNLIKELY( !begin( j ) ) ) return;
  char const * start = j->cur;
  if( FD_UNLIKELY( !skip_value( j ) ) ) return;
  j->pending = 0;
  *ptr = start;
  *sz  = (ulong)( j->cur-start );
}

int
fd_jtok_str_eq( fd_jtok_str_t const * s,
                char const *          lit ) {
  char const * p   = s->ptr;
  char const * end = s->ptr+s->sz;
  while( p<end ) {
    uchar unit[ 4 ];
    ulong n = decode_unit( &p, end, unit );
    if( FD_UNLIKELY( !n || !unit[0] ) ) return 0;
    for( ulong i=0UL; i<n; i++ ) if( (uchar)lit[i]!=unit[i] ) return 0;
    lit += n;
  }
  return *lit=='\0';
}
