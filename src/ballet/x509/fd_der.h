#ifndef HEADER_fd_src_ballet_x509_fd_der_h
#define HEADER_fd_src_ballet_x509_fd_der_h

/* fd_der.h provides a parser for DER (Distinguished Encoding Rules)
   parsing for ASN.1 structures.

   All reads are bounded by the cursor's [p, end) window.
   ENTER narrows end to the content of the current TLV.  LEAVE checks
   that exactly the right number of bytes were consumed and restores the
   outer window.

   All macros assume the enclosing function returns int, with the semantics
   success=0 & failure=nonzero.  On any parse error, the macro evaluates
   to "return -1".

   An example of parsing an ECDSA DER signature:

     FD_DER_CURSOR_FROM_BUF( c, der, der_len );
     FD_DER_ENTER( c, FD_DER_TAG_SEQUENCE );
       FD_DER_READ( c, FD_DER_TAG_INTEGER, r_ptr, r_len );
       FD_DER_READ( c, FD_DER_TAG_INTEGER, s_ptr, s_len );
     FD_DER_LEAVE( c );

  */

#include "../../util/fd_util_base.h"

/* DER tags */

#define FD_DER_TAG_BOOLEAN          ((uchar)0x01)
#define FD_DER_TAG_INTEGER          ((uchar)0x02)
#define FD_DER_TAG_BIT_STRING       ((uchar)0x03)
#define FD_DER_TAG_OCTET_STRING     ((uchar)0x04)
#define FD_DER_TAG_NULL             ((uchar)0x05)
#define FD_DER_TAG_OID              ((uchar)0x06)
#define FD_DER_TAG_UTF8_STRING      ((uchar)0x0c)
#define FD_DER_TAG_TELETEX_STRING   ((uchar)0x14)
#define FD_DER_TAG_SEQUENCE         ((uchar)0x30)
#define FD_DER_TAG_SET              ((uchar)0x31)
#define FD_DER_TAG_PRINTABLE_STR    ((uchar)0x13)
#define FD_DER_TAG_IA5_STRING       ((uchar)0x16)
#define FD_DER_TAG_UTC_TIME         ((uchar)0x17)
#define FD_DER_TAG_GENERALIZED_TIME ((uchar)0x18)
#define FD_DER_TAG_UNIVERSAL_STRING ((uchar)0x1c)
#define FD_DER_TAG_BMP_STRING       ((uchar)0x1e)

/* Context-specific tags [0]..[7] (EXPLICIT, constructed) */

#define FD_DER_TAG_CONTEXT(n)      ((uchar)(0xA0 | (n)))

/* Context-specific tags [0]..[7] (IMPLICIT, primitive) */

#define FD_DER_TAG_CONTEXT_PRIM(n) ((uchar)(0x80 | (n)))

/* fd_der_cursor_t is the read cursor into a DER buffer.
   p points to the next byte to read.
   end points one past the last readable byte.
   Always: p <= end. */

typedef struct {
  uchar const * p;
  uchar const * end;
} fd_der_cursor_t;

FD_PROTOTYPES_BEGIN

/* fd_der_read_tl reads a DER tag-length prefix from cursor c.

   On success, out_tag is the tag byte, out_len is the content length,
   c->p is advanced past the tag-length bytes, returns 0.

   On failure, c is in an undefined state, returns -1. */

static inline int
fd_der_read_tl( fd_der_cursor_t * c,
                int *             out_tag,
                ulong *           out_len ) {

  uchar const * p   = c->p;
  uchar const * end = c->end;

  /* Tag byte */
  if( FD_UNLIKELY( p == end ) ) return -1;
  if( FD_UNLIKELY( (*p & 0x1fU)==0x1fU ) ) return -1; /* unsupported high-tag-number form */
  *out_tag = (int)*p++;

  /* Length byte */
  if( FD_UNLIKELY( p == end ) ) return -1;
  ulong len = *p++;

  if( len & 0x80 ) {
    uint n_bytes = (uint)( len & 0x7F );
    if( FD_UNLIKELY( n_bytes > 4 || n_bytes == 0 ) ) return -1;
    if( FD_UNLIKELY( p == end || !p[0] ) ) return -1; /* no leading zero length octet */
    len = 0;
    for( uint i = 0; i < n_bytes; i++ ) {
      if( FD_UNLIKELY( p == end ) ) return -1;
      len = ( len << 8 ) | *p++;
    }
    if( FD_UNLIKELY( len<128UL ) ) return -1; /* long form must be necessary */
  }

  if( FD_UNLIKELY( (ulong)( end - p ) < len ) ) return -1;

  *out_len = len;
  c->p     = p;
  return 0;
}

/* fd_der_int_to_fixed strips DER INTEGER padding and right-justifies
   into a fixed-size output buffer.

   p points to the INTEGER content bytes, len is the content length.
   out is zero-filled and receives the value right-justified into out_sz
   bytes.

   Returns 0 on success, -1 on failure. */

static inline int
fd_der_int_to_fixed( uchar const * p,
                     ulong         len,
                     uchar *       out,
                     ulong         out_sz ) {

  if( FD_UNLIKELY( !len ) ) return -1;

  /* ECDSA scalars are positive INTEGERs.  DER uses a leading zero only
     when it is needed to keep the value positive. */
  if( p[0]==0x00 ) {
    if( FD_UNLIKELY( len==1UL || !(p[1] & 0x80U) ) ) return -1;
    p++;
    len--;
  } else if( FD_UNLIKELY( p[0] & 0x80U ) ) return -1;

  if( FD_UNLIKELY( len>out_sz ) ) return -1;

  fd_memset( out, 0, out_sz );
  fd_memcpy( out + ( out_sz - len ), p, len );
  return 0;
}

/* fd_der_oid_valid checks that p,len is a canonical DER OBJECT IDENTIFIER
   content encoding.  Each subidentifier uses base 128, with bit 7 marking
   continuation.  DER forbids leading zero base-128 digits. */

static inline int
fd_der_oid_valid( uchar const * p,
                  ulong         len ) {
  if( FD_UNLIKELY( !len ) ) return 0;

  int at_subidentifier_start = 1;
  for( ulong i=0UL; i<len; i++ ) {
    uchar octet = p[i];
    if( FD_UNLIKELY( at_subidentifier_start && octet==0x80U ) ) return 0;
    at_subidentifier_start = !(octet & 0x80U);
  }
  return at_subidentifier_start;
}

FD_PROTOTYPES_END

/* Initialize a cursor from a buffer pointer and length. */

#define FD_DER_CURSOR_FROM_BUF( c, buf, sz )  \
  fd_der_cursor_t c = { .p   = (uchar const *)(buf),                         \
                        .end = (sz) ? (uchar const *)(buf) + (sz)            \
                                    : (uchar const *)(buf) }

/* Enter a constructed type (SEQUENCE, SET, etc.).
   Must be paired with FD_DER_LEAVE. */

#define FD_DER_ENTER( c, expected_tag )                                   \
  do {                                                                    \
    uchar const * _fd_der_outer_end_ = (c).end;                           \
    do {                                                                  \
      int _fd_der_tag_; ulong _fd_der_len_;                               \
      if( FD_UNLIKELY( fd_der_read_tl( &(c), &_fd_der_tag_,               \
                                       &_fd_der_len_ ) ) )                \
        return -1;                                                        \
      if( FD_UNLIKELY( _fd_der_tag_ != (int)(expected_tag) ) )            \
        return -1;                                                        \
      (c).end = (c).p + _fd_der_len_;                                     \
    } while(0)

/* Leave a constructed type.  Checks that all content was consumed
   and restores the outer end pointer. */

#define FD_DER_LEAVE( c )                                                 \
    if( FD_UNLIKELY( (c).p != (c).end ) ) return -1;                      \
    (c).end = _fd_der_outer_end_;                                         \
  } while(0)

/* Leave a constructed type without requiring all content consumed.
   Advances past any remaining content. */

#define FD_DER_LEAVE_RELAXED( c )                                         \
    (c).p   = (c).end;                                                    \
    (c).end = _fd_der_outer_end_;                                         \
  } while(0)

/* Read a primitive TLV. Verifies the tag and sets ptr/len to the
   content bytes. Advances the cursor past the TLV.  OBJECT IDENTIFIER
   content is additionally checked for canonical DER encoding. */

#define FD_DER_READ( c, expected_tag, out_ptr, out_len )                  \
  do {                                                                    \
    int _fd_der_tag_; ulong _fd_der_len_;                                 \
    if( FD_UNLIKELY( fd_der_read_tl( &(c), &_fd_der_tag_,                 \
                                     &_fd_der_len_ ) ) )                  \
      return -1;                                                          \
    if( FD_UNLIKELY( _fd_der_tag_ != (int)(expected_tag) ) )              \
      return -1;                                                          \
    if( FD_UNLIKELY( _fd_der_tag_ == (int)FD_DER_TAG_OID &&               \
                     !fd_der_oid_valid( (c).p, _fd_der_len_ ) ) )         \
      return -1;                                                          \
    (out_ptr) = (c).p;                                                    \
    (out_len) = _fd_der_len_;                                             \
    (c).p += _fd_der_len_;                                                \
  } while(0)

/* Read a TLV including its tag+length prefix.  Sets raw_ptr to the
   start of the tag byte and raw_len to tag+length+content.  OBJECT
   IDENTIFIER content is additionally checked for canonical DER encoding. */

#define FD_DER_READ_RAW( c, expected_tag, raw_ptr, raw_len )              \
  do {                                                                    \
    (raw_ptr) = (c).p;                                                    \
    int _fd_der_tag_; ulong _fd_der_len_;                                 \
    if( FD_UNLIKELY( fd_der_read_tl( &(c), &_fd_der_tag_,                 \
                                     &_fd_der_len_ ) ) )                  \
      return -1;                                                          \
    if( FD_UNLIKELY( _fd_der_tag_ != (int)(expected_tag) ) )              \
      return -1;                                                          \
    if( FD_UNLIKELY( _fd_der_tag_ == (int)FD_DER_TAG_OID &&               \
                     !fd_der_oid_valid( (c).p, _fd_der_len_ ) ) )         \
      return -1;                                                          \
    (c).p += _fd_der_len_;                                                \
    (raw_len) = (ulong)( (c).p - (raw_ptr) );                             \
  } while(0)

/* Peek at the next tag byte without consuming it.
   Sets out_tag to the tag value. Returns -1 if cursor is exhausted. */

#define FD_DER_PEEK_TAG( c, out_tag )                                     \
  do {                                                                    \
    if( FD_UNLIKELY( (c).p == (c).end ) ) return -1;                      \
    (out_tag) = (int)*(c).p;                                              \
  } while(0)

/* Peek at the next tag byte, returning a default if cursor exhausted. */

#define FD_DER_PEEK_TAG_OR( c, out_tag, default_tag )                     \
  do {                                                                    \
    (out_tag) = ( (c).p != (c).end ) ? (int)*(c).p : (int)(default_tag);  \
  } while(0)

/* Skip one TLV. */

#define FD_DER_SKIP( c )                                                  \
  do {                                                                    \
    int _fd_der_tag_; ulong _fd_der_len_;                                 \
    if( FD_UNLIKELY( fd_der_read_tl( &(c), &_fd_der_tag_,                 \
                                     &_fd_der_len_ ) ) )                  \
      return -1;                                                          \
    (void)_fd_der_tag_;                                                   \
    (c).p += _fd_der_len_;                                                \
  } while(0)

/* Skip one TLV iff the next tag matches expected_tag.
   If the tag doesn't match or cursor is exhausted, does nothing. */

#define FD_DER_SKIP_IF( c, expected_tag )                                 \
  do {                                                                    \
    if( (c).p != (c).end && (int)*(c).p == (int)(expected_tag) ) {        \
      FD_DER_SKIP( c );                                                   \
    }                                                                     \
  } while(0)

/* Read a BIT STRING and strip the "unused bits" byte.
   DER BIT STRING content is represented as, unused_bits || actual_bits.
   For X.509 signatures and pubkeys, unused_bits is always 0x00.
   Sets ptr & len to the actual bits after the unused-bits byte. */

#define FD_DER_READ_BITS( c, out_ptr, out_len )                           \
  do {                                                                    \
    uchar const * _fd_der_bits_raw_; ulong _fd_der_bits_raw_len_;         \
    FD_DER_READ( c, FD_DER_TAG_BIT_STRING,                                \
                 _fd_der_bits_raw_, _fd_der_bits_raw_len_ );              \
    if( FD_UNLIKELY( _fd_der_bits_raw_len_ < 1 ||                         \
                     _fd_der_bits_raw_[0] != 0x00 ) )                     \
      return -1;                                                          \
    (out_ptr) = _fd_der_bits_raw_ + 1;                                    \
    (out_len) = _fd_der_bits_raw_len_ - 1;                                \
  } while(0)

/* Read a time field, either UTCTime or GeneralizedTime. */

#define FD_DER_READ_TIME( c, out_ptr, out_len )                           \
  do {                                                                    \
    int _fd_der_tag_; ulong _fd_der_len_;                                 \
    if( FD_UNLIKELY( fd_der_read_tl( &(c), &_fd_der_tag_,                 \
                                     &_fd_der_len_ ) ) )                  \
      return -1;                                                          \
    if( FD_UNLIKELY( _fd_der_tag_ != (int)FD_DER_TAG_UTC_TIME &&          \
                     _fd_der_tag_ != (int)FD_DER_TAG_GENERALIZED_TIME ) ) \
      return -1;                                                          \
    (out_ptr) = (c).p;                                                    \
    (out_len) = _fd_der_len_;                                             \
    (c).p += _fd_der_len_;                                                \
  } while(0)

/* Check if cursor has more content to read. */

#define FD_DER_HAS_MORE( c ) ( (c).p != (c).end )

static inline int
fd_der_oid_match( uchar const * tlv,
                  ulong         tlv_len,
                  uchar const * expected_oid,
                  ulong         expected_oid_len ) {
  return ( tlv_len == expected_oid_len &&
           0 == memcmp( tlv, expected_oid, expected_oid_len ) );
}

#endif /* HEADER_fd_src_ballet_x509_fd_der_h */
