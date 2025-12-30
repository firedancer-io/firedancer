#ifndef HEADER_fd_src_ballet_pb_fd_pb_tokenize_h
#define HEADER_fd_src_ballet_pb_fd_pb_tokenize_h

/* fd_pb_tokenize.h provides an API to iterate over tokens in Protobuf
   wire format.  It can be used to deserialize Protobuf. */

#include "fd_pb_wire.h"

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
fd_pb_inbuf_sz( fd_pb_inbuf_t * buf ) {
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

/* fd_pb_read_tlv reads a Protobuf TLV.  This includes a wire type, a
   field ID, and data.  Data is either a scalar value field, or a length
   prefix.  Populates *tlv, advances buf, and returns tlv on success.
   On failure, silently returns NULL without advancing buf.  Reasons for
   failure include: parse failure, unexpected EOF. */

fd_pb_tlv_t *
fd_pb_read_tlv( fd_pb_inbuf_t * buf,
                fd_pb_tlv_t *   tlv );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_pb_fd_pb_tokenize_h */
