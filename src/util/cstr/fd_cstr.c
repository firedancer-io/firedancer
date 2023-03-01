#include "fd_cstr.h"

/* FIXME: WEAN THIS OFF STDLIB FOR NON-HOSTED TARGETS */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <strings.h>
#include <ctype.h>

char const * fd_cstr_to_cstr  ( char const * cstr ) { return cstr;                             }
char         fd_cstr_to_char  ( char const * cstr ) { return cstr[0];                          }
schar        fd_cstr_to_schar ( char const * cstr ) { return (schar) strtol ( cstr, NULL, 0 ); }
short        fd_cstr_to_short ( char const * cstr ) { return (short) strtol ( cstr, NULL, 0 ); }
int          fd_cstr_to_int   ( char const * cstr ) { return (int)   strtol ( cstr, NULL, 0 ); }
long         fd_cstr_to_long  ( char const * cstr ) { return (long)  strtol ( cstr, NULL, 0 ); }
uchar        fd_cstr_to_uchar ( char const * cstr ) { return (uchar) strtoul( cstr, NULL, 0 ); }
ushort       fd_cstr_to_ushort( char const * cstr ) { return (ushort)strtoul( cstr, NULL, 0 ); }
uint         fd_cstr_to_uint  ( char const * cstr ) { return (uint)  strtoul( cstr, NULL, 0 ); }
ulong        fd_cstr_to_ulong ( char const * cstr ) { return (ulong) strtoul( cstr, NULL, 0 ); }
float        fd_cstr_to_float ( char const * cstr ) { return         strtof ( cstr, NULL    ); }
#if FD_HAS_DOUBLE
double       fd_cstr_to_double( char const * cstr ) { return         strtod ( cstr, NULL    ); }
#endif

ulong fd_cstr_to_ulong_octal( char const * cstr ) { return (ulong)strtoul( cstr, NULL, 8 ); }

#if FD_HAS_HOSTED
/* TODO: Provide a non-hosted implementation */
ulong
fd_cstr_to_ip4_addr( char const * s ) {
  int  n=0;
  uint x[4];

  int res = sscanf( s, "%u.%u.%u.%u%n", &x[0], &x[1], &x[2], &x[3], &n );

  if( FD_UNLIKELY( res!=4
                || n<0 || s[n]!='\0'
                || x[0]>UCHAR_MAX
                || x[1]>UCHAR_MAX
                || x[2]>UCHAR_MAX
                || x[3]>UCHAR_MAX ) )
    return ULONG_MAX;

  return ( x[0] | (x[1]<<8) | (x[2]<<16) | (x[3]<<24) );
}
#endif /* FD_HAS_HOSTED */

int
fd_cstr_casecmp( char const * a,
                 char const * b ) {
  return strcasecmp( a, b );
}

char *
fd_cstr_printf( char *       buf,
                ulong        sz,
                ulong *      opt_len,
                char const * fmt, ... ) {
  if( FD_UNLIKELY( (!buf) | (!sz) ) ) {
    if( opt_len ) *opt_len = 0UL;
    return buf;
  }
  va_list ap;
  va_start( ap, fmt );
  int   ret = vsnprintf( buf, sz, fmt, ap );
  ulong len = fd_ulong_if( ret<0, 0UL, fd_ulong_min( (ulong)ret, sz-1UL ) );
  buf[ len ] = '\0';
  va_end( ap );
  if( opt_len ) *opt_len = len;
  return buf;
}

char *
fd_cstr_append_printf( char *       buf,
                       char const * fmt, ... ) {
  if( FD_UNLIKELY( !buf ) ) return NULL;
  va_list ap;
  va_start( ap, fmt );
  int ret = vsprintf( buf, fmt, ap );
  va_end( ap );
  return buf + fd_ulong_if( ret<0, 0UL, (ulong)ret );
}

ulong
fd_cstr_tokenize( char ** tok,
                  ulong   tok_max,
                  char *  p,
                  char    delim ) {
  if( FD_UNLIKELY( !p ) ) return 0UL;

  ulong tok_cnt = 0UL;
  for(;;) {

    /* Find token start and record it (if possible) */
    while( isspace( (int)p[0] ) ) p++;
    if( p[0]=='\0' ) break;
    if( tok_cnt<tok_max ) tok[ tok_cnt ] = p;
    tok_cnt++;

    /* Find the token end and terminate it */
    while( ((p[0]!=delim) & (p[0]!='\0')) ) p++;
    if( p[0]=='\0' ) break;
    p[0] = '\0';
    p++;
  }

  return tok_cnt;
}

