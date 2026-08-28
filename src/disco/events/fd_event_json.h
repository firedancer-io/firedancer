#ifndef HEADER_fd_src_disco_events_fd_event_json_h
#define HEADER_fd_src_disco_events_fd_event_json_h

#include "../../util/cstr/fd_cstr.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/base64/fd_base64.h"

FD_PROTOTYPES_BEGIN

/* fd_cstr_append_json_escaped appends the JSON string-escaped form of
   the n bytes at s into p (without surrounding quotes).  Assumes p has
   room for the worst case of 6 bytes per input byte (\uXXXX). */

static inline char *
fd_cstr_append_json_escaped( char *       p,
                             char const * s,
                             ulong        n ) {
  static char const hex[] = "0123456789abcdef";
  for( ulong i=0UL; i<n; i++ ) {
    uchar c = (uchar)s[ i ];
    if( FD_UNLIKELY( c=='"' || c=='\\' ) ) { *(p++) = '\\'; *(p++) = (char)c; }
    else if( FD_UNLIKELY( c<0x20 ) ) {
      *(p++) = '\\'; *(p++) = 'u'; *(p++) = '0'; *(p++) = '0';
      *(p++) = hex[ (c>>4)&0xF ]; *(p++) = hex[ c&0xF ];
    } else *(p++) = (char)c;
  }
  return p;
}

/* fd_cstr_append_json_str appends a quoted, JSON-escaped string. */

static inline char *
fd_cstr_append_json_str( char *       p,
                         char const * s,
                         ulong        n ) {
  *(p++) = '"';
  p = fd_cstr_append_json_escaped( p, s, n );
  *(p++) = '"';
  return p;
}

/* fd_cstr_append_json_b58_32/64 append a quoted base58 encoding of a
   32 or 64 byte value (Solana pubkey/hash or signature). */

static inline char *
fd_cstr_append_json_b58_32( char * p, uchar const * b ) {
  ulong len;
  *(p++) = '"';
  fd_base58_encode_32( b, &len, p );
  p += len;
  *(p++) = '"';
  return p;
}

static inline char *
fd_cstr_append_json_b58_64( char * p, uchar const * b ) {
  ulong len;
  *(p++) = '"';
  fd_base58_encode_64( b, &len, p );
  p += len;
  *(p++) = '"';
  return p;
}

/* fd_cstr_append_json_b64 appends a quoted base64 encoding of sz
   bytes. */

static inline char *
fd_cstr_append_json_b64( char * p, uchar const * b, ulong sz ) {
  *(p++) = '"';
  p = fd_cstr_append_base64( p, b, sz );
  *(p++) = '"';
  return p;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_events_fd_event_json_h */
