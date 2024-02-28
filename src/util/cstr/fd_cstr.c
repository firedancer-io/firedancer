#define _GNU_SOURCE
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

ulong
fd_cstr_to_ulong_seq( char const * cstr,
                      ulong *      seq,
                      ulong        seq_max ) {
  ulong seq_cnt = 0UL;

  if( !cstr ) return seq_cnt;

  char const * p = cstr;
  for(;;) {

    char   c;
    char * q;

    c = *p; while( isspace( (int)c ) ) c = *(++p); /* Move and peek at next non-white-space character */
    if( c=='\0' ) break; /* end of sequence */

    ulong seq_ele_0 = strtoul( p, &q, 0 );
    if( FD_UNLIKELY( p==(char const *)q ) ) return 0UL; /* Malformed sequence, seq_ele_0 is not a ulong */
    p = (char const *)q;

    ulong seq_ele_1  = seq_ele_0;
    ulong seq_stride = 1UL;

    c = *p; while( isspace( (int)c ) ) c = *(++p); /* Move and peek at next non-white-space character */
    if( c=='-' ) {
      p++;

      seq_ele_1 = strtoul( p, &q, 0 );
      if( FD_UNLIKELY( p==(char const *)q ) ) return 0UL; /* Malformed sequence, seq_ele_1 is not a ulong */
      p = (char const *)q;

      c = *p; while( isspace( (int)c ) ) c = *(++p); /* Move and peek at next non-white-space character */
      if( c=='/' || c==':' ) {
        p++;

        seq_stride = strtoul( p, &q, 0 );
        if( FD_UNLIKELY( p==(char const *)q ) ) return 0UL; /* Malformed sequence, seq_stride is not a ulong */
        p = (char const *)q;
      }
    }

    c = *p; while( isspace( (int)c ) ) c = *(++p); /* Move and peek at next non-white-space character */
    if( !(c==',' || c=='\0' ) ) return 0UL; /* Malformed sequence, delimiter */
    if( c==',' ) p++;

    /* Append the range to sequence.  Written this slightly funny way to
       be robust against overflow with seq_ele_1 and/or seq_stride being
       near or equal to ULONG_MAX */

    if( FD_UNLIKELY( (seq_ele_1<seq_ele_0) | (!seq_stride) )) return 0UL; /* Malformed sequence, bad range */


    ulong seq_ele = seq_ele_0;
    while( ((seq_ele_0<=seq_ele) & (seq_ele<seq_ele_1)) ) {
      if( FD_LIKELY( seq_cnt<seq_max ) ) seq[ seq_cnt ] = seq_ele;
      seq_cnt++;
      seq_ele += seq_stride;
    }
    if( seq_ele==seq_ele_1 ) {
      if( FD_LIKELY( seq_cnt<seq_max ) ) seq[ seq_cnt ] = seq_ele;
      seq_cnt++;
    }
  }

  return seq_cnt;
}

int
fd_cstr_casecmp( char const * a,
                 char const * b ) {
  return strcasecmp( a, b );
}

ulong
fd_cstr_nlen( char const * s,
              ulong        m ) {
  return strnlen( s, m );
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

int
fd_cstr_printf_check( char *       buf,
                      ulong        sz,
                      ulong *      opt_len,
                      char const * fmt, ... ) {
  if( FD_UNLIKELY( (!buf) | (!sz) ) ) {
    if( opt_len ) *opt_len = 0UL;
    return 0;
  }
  va_list ap;
  va_start( ap, fmt );
  int   ret = vsnprintf( buf, sz, fmt, ap );
  ulong len = fd_ulong_if( ret<0, 0UL, fd_ulong_min( (ulong)ret, sz-1UL ) );
  buf[ len ] = '\0';
  va_end( ap );
  if( opt_len ) *opt_len = len;
  return fd_int_if( ret<0 || (ulong)ret>=sz, 0, 1 );
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

