#include "fd_pb_tokenize.h"
#include "fd_pb_wire.h"

static fd_pb_inbuf_t *
read_varint( fd_pb_inbuf_t * buf,
             ulong *         out ) {
  ulong sz    = (ulong)( buf->end - buf->cur );
  ulong var   = 0UL;
  int   shift = 0;
  for( ulong i=0UL;; i++ ) {
    if( FD_UNLIKELY( i>=10 || i>=sz ) ) return NULL;
    /* FIXME check if one bits are shifted out of bounds */
    var |= (ulong)( buf->cur[i] & 0x7f ) << shift;
    shift += 7;
    if( !( buf->cur[i] & 0x80 ) ) {
      buf->cur += i+1;
      *out = var;
      return buf;
    }
  }
}

static fd_pb_tlv_t *
fd_pb_read_tlv_slow( fd_pb_inbuf_t * buf,
                     fd_pb_tlv_t *   tlv ) {
  fd_pb_inbuf_t buf2 = *buf;
  ulong tag;
  if( FD_UNLIKELY( !read_varint( &buf2, &tag ) ) ) return NULL;
  if( FD_UNLIKELY( tag>UINT_MAX ) ) return NULL;
  uint  wire_type = fd_pb_tag_wire_type( (uint)tag );
  uint  field_id  = fd_pb_tag_field_id ( (uint)tag );
  ulong val;
  switch( wire_type ) {
  case FD_PB_WIRE_TYPE_VARINT:
    if( FD_UNLIKELY( !read_varint( &buf2, &val ) ) ) return NULL;
    break;
  case FD_PB_WIRE_TYPE_LEN:
    if( FD_UNLIKELY( !read_varint( &buf2, &val ) ) ) return NULL;
    if( FD_UNLIKELY( val > fd_pb_inbuf_sz( &buf2 ) ) ) return NULL;
    break;
  case FD_PB_WIRE_TYPE_I64:
    if( FD_UNLIKELY( (ulong)( buf2.end - buf2.cur )<8UL ) ) return NULL;
    val       = FD_LOAD( ulong, buf2.cur );
    buf2.cur += 8UL;
    break;
  case FD_PB_WIRE_TYPE_I32:
    if( FD_UNLIKELY( (ulong)( buf2.end - buf2.cur )<4UL ) ) return NULL;
    val       = (ulong)FD_LOAD( uint, buf2.cur );
    buf2.cur += 4UL;
    break;
  default:
    return NULL;
  }
  *tlv = (fd_pb_tlv_t) {
    .wire_type = wire_type,
    .field_id  = field_id,
    .varint    = val
  };
  *buf = buf2;
  return tlv;
}

fd_pb_tlv_t *
fd_pb_read_tlv( fd_pb_inbuf_t * buf,
                fd_pb_tlv_t *   tlv ) {
  /* FIXME plenty of optimization opportunities here */
  return fd_pb_read_tlv_slow( buf, tlv );
}
