#ifndef HEADER_fd_src_ballet_pb_fd_pb_tokenize_h
#define HEADER_fd_src_ballet_pb_fd_pb_tokenize_h

/* fd_pb_tokenize.h provides an API to iterate over tokens in Protobuf
   wire format.  It can be used to deserialize Protobuf. */

#include "fd_pb_wire.h"
#include "../base58/fd_base58.h"

struct fd_pb_inbuf {
  uchar const * cur;
  uchar const * end;
};

typedef struct fd_pb_inbuf fd_pb_inbuf_t;

FD_PROTOTYPES_BEGIN

static inline fd_pb_inbuf_t *
fd_pb_inbuf_init( fd_pb_inbuf_t * buf,
                  void const *    data,
                  ulong           data_sz ) {
  buf->cur = data;
  buf->end = buf->cur + data_sz;
  return buf;
}

static inline ulong
fd_pb_inbuf_sz( fd_pb_inbuf_t const * buf ) {
  return (ulong)( buf->end - buf->cur );
}

static inline void
fd_pb_inbuf_skip( fd_pb_inbuf_t * buf,
                  ulong           sz ) {
  FD_CRIT( sz<=fd_pb_inbuf_sz( buf ), "Attempt to skip past end of buffer" );
  buf->cur += sz;
}

FD_PROTOTYPES_END

struct fd_pb_tlv {
  uint wire_type; /* FD_PB_WIRE_TYPE_* */
  uint field_id;

  union {
    ulong varint;
    ulong i64;
    ulong len;
    uint  i32;
  };
};

typedef struct fd_pb_tlv fd_pb_tlv_t;

FD_PROTOTYPES_BEGIN

/* fd_pb_tlv_read reads a Protobuf TLV.  This includes a wire type, a
   field ID, and data.  Data is either a scalar value field, or a length
   prefix.  Populates *tlv, advances buf, and returns tlv on success.
   On failure, silently returns NULL without advancing buf.  Reasons for
   failure include: parse failure, unexpected EOF.

   buf is advanced as follows:
   - VARINT, I32, and I64 TLVs are fully consumed
   - For LEN TLVs, only the length prefix is consumed (the next tlv.len
     bytes of buf are the value) */

fd_pb_tlv_t *
fd_pb_tlv_read( fd_pb_inbuf_t * buf,
                fd_pb_tlv_t *   tlv );

/* fd_pb_tlv_bytes interprets a TLV as a byte array value. */

static inline uchar const *
fd_pb_tlv_bytes( fd_pb_inbuf_t const * buf,
                 fd_pb_tlv_t const *   tlv ) {
  if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_LEN ||
                   tlv->len > fd_pb_inbuf_sz( buf ) ) ) {
    return NULL;
  }
  return buf->cur;
}

/* fd_pb_tlv_cstr interprets converts a byte array TLV into a NULL-
   terminated C string.  cstr_max is the cstr buffer size and includes
   the NULL terminator. */

static inline char *
fd_pb_tlv_cstr( fd_pb_inbuf_t const * buf,
                fd_pb_tlv_t const *   tlv,
                char *                cstr,
                ulong                 cstr_max ) {
  if( FD_UNLIKELY( !cstr_max ||
                   tlv->wire_type!=FD_PB_WIRE_TYPE_LEN ||
                   tlv->len > fd_pb_inbuf_sz( buf ) ||
                   tlv->len > cstr_max-1UL ) ) {
    return NULL;
  }
  char * p = fd_cstr_init( cstr );
  p = fd_cstr_append_text( p, (char const *)buf->cur, tlv->len );
  fd_cstr_fini( p );
  return cstr;
}

/* fd_pb_tlv_base58_32 interprets a TLV as a Base58-encoded 32-byte
   string. */

static FD_FN_UNUSED uchar const *
fd_pb_tlv_base58_32( fd_pb_inbuf_t const * buf,
                     fd_pb_tlv_t const *   tlv,
                     uchar                 out[ 32 ] ) {
  char str[ FD_BASE58_ENCODED_32_SZ ];
  if( FD_UNLIKELY( !fd_pb_tlv_cstr( buf, tlv, str, sizeof(str) ) ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( !fd_base58_decode_32( str, out ) ) ) {
    return NULL;
  }
  return out;
}

/* fd_pb_tlv_submsg interprets a TLV as a Protobuf submessage. */

static FD_FN_UNUSED fd_pb_inbuf_t *
fd_pb_tlv_submsg( fd_pb_inbuf_t const * buf,
                  fd_pb_tlv_t const *   tlv,
                  fd_pb_inbuf_t *       submsg ) {
  if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_LEN ||
                   tlv->len > fd_pb_inbuf_sz( buf ) ) ) {
    return NULL;
  }
  submsg->cur = buf->cur;
  submsg->end = submsg->cur + tlv->len;
  return submsg;
}

/* fd_pb_tlv_skip skips the value of a TLV.  Returns the value that was
   skipped on success.  On failure (corrupt Protobuf), returns NULL. */

static inline uchar const *
fd_pb_tlv_skip( fd_pb_inbuf_t *     buf,
                fd_pb_tlv_t const * tlv ) {
  uchar const * ret = buf->cur;
  if( tlv->wire_type==FD_PB_WIRE_TYPE_LEN ) {
    if( FD_UNLIKELY( tlv->len > fd_pb_inbuf_sz( buf ) ) ) return NULL;
    buf->cur += tlv->len;
  }
  return ret;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_pb_fd_pb_tokenize_h */
