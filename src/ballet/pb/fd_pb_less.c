#include "fd_pb_less_private.h"
#include "fd_pb_tokenize.h"
#include "fd_pb_wire.h"

FD_FN_CONST ulong
fd_pb_less_align( void ) {
  return FD_PB_LESS_ALIGN;
}

static fd_pb_less_t *
fd_pb_less_parse_msg( fd_pb_less_root_t * root,
                      uchar const *       msg,
                      ulong               msg_sz,
                      int *               err ) {

  fd_pb_less_t * node = fd_pb_alloc( &root->alloc, alignof(fd_pb_less_t), sizeof(fd_pb_less_t) );
  if( FD_UNLIKELY( !node ) ) {
    *err = FD_PB_ERR_FULL;
    return NULL;
  }
  node->root     = root;
  node->desc_cnt = 0;

  fd_pb_inbuf_t buf[1];
  fd_pb_inbuf_init( buf, msg, msg_sz );
  while( fd_pb_inbuf_sz( buf ) ) {
    ulong off = (ulong)buf->cur - (ulong)msg;
    FD_CRIT( off<=msg_sz, "parse offset out of bounds" );

    fd_pb_tlv_t tlv[1];
    if( !fd_pb_read_tlv( buf, tlv ) ) {
      *err = FD_PB_ERR_PROTO;
      return NULL;
    }

    fd_pb_desc_t * desc = fd_pb_alloc( &root->alloc, alignof(fd_pb_desc_t), sizeof(fd_pb_desc_t) );
    if( FD_UNLIKELY( !desc ) ) {
      *err = FD_PB_ERR_FULL;
      return NULL;
    }
    desc->off = (uint)off & 0x3fffffffU; /* 30 bits */

    switch( tlv->wire_type ) {
    case FD_PB_WIRE_TYPE_VARINT:
    case FD_PB_WIRE_TYPE_I64:
    case FD_PB_WIRE_TYPE_I32:
      desc->desc = FD_PB_DESC_INT;
      break;
    case FD_PB_WIRE_TYPE_LEN:
      desc->desc = FD_PB_DESC_LP;
      fd_pb_inbuf_skip( buf, tlv->len );
      break;
    default:
      /* unreachable */
      *err = FD_PB_ERR_PROTO;
      return NULL;
    }

    node->desc_cnt++;
  }

  return node;
}

fd_pb_less_t *
fd_pb_less_parse( void *        scratch,
                  ulong         scratch_sz,
                  uchar const * msg,
                  ulong         msg_sz ) {

  /* Bootstrap the pb_less object */

  if( FD_UNLIKELY( msg_sz > UINT_MAX ) ) {
    FD_LOG_WARNING(( "cannot deserialize oversize message (%lu bytes exceeds max %u)",
                     msg_sz, UINT_MAX ));
  }

  if( FD_UNLIKELY( scratch_sz < sizeof(fd_pb_less_root_t)+sizeof(fd_pb_less_t) ) ) {
    FD_LOG_WARNING(( "invalid scratch_sz" ));
    return NULL;
  }

  if( FD_UNLIKELY( !scratch ) ) {
    FD_LOG_WARNING(( "NULL scratch" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)scratch, FD_PB_LESS_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned scratch" ));
    return NULL;
  }

  fd_pb_less_root_t * root = (fd_pb_less_root_t *)scratch;
  *root = (fd_pb_less_root_t){
    .alloc = {
      .laddr0 = (ulong)scratch,
      .laddr  = (ulong)scratch + sizeof(fd_pb_less_root_t),
      .laddr1 = (ulong)scratch + scratch_sz
    },
    .msg0 = msg,
    .msg1 = msg + msg_sz
  };

  /* Decode the root message */

  int err;
  return fd_pb_less_parse_msg( root, msg, msg_sz, &err );
}

/* fd_pb_find_get_field extracts the Protobuf field TLV at the given
   field_id.

   If field_id is not present in the message, returns NULL and leaves
   content of *tlv and *value undefined.

   If field_id is found, populates *tlv and points *value one byte past
   the (wire_type, field_id, number) tuple.  *value is thus only
   interesting for LEN fields, and points to the first byte of the LEN
   content.

   FIXME this function is inefficient, plenty of optimization possible */

static fd_pb_tlv_t *
fd_pb_get_field( fd_pb_less_t const * less,
                 uint                 field_id,
                 fd_pb_tlv_t *        tlv,
                 uchar const **       value ) {
  ulong desc_cnt = less->desc_cnt;
  for( ulong i=0UL; i<desc_cnt; i++ ) {
    fd_pb_desc_t const * desc = &less->desc[ i ];
    uchar const *        tok  = less->root->msg0 + desc->off;
    ulong                sz   = (ulong)less->root->msg1 - (ulong)tok;

    fd_pb_inbuf_t inbuf = fd_pb_inbuf( tok, sz );
    if( FD_UNLIKELY( !fd_pb_read_tlv( &inbuf, tlv ) ) ) {
      /* Failed to re-parse TLV.  This can only happen if this library
         is bugged or if the user modified the original message. */
      continue;
    }
    if( tlv->field_id==field_id ) {
      *value = inbuf.cur;
      return tlv;
    }
  }
  return NULL;
}

int
fd_pb_get_int32( fd_pb_less_t const * less,
                 uint                 field_id,
                 int                  def ) {
  fd_pb_tlv_t   tlv;
  uchar const * value;
  if( !fd_pb_get_field( less, field_id, &tlv, &value ) ) return def;
  if( tlv.wire_type!=FD_PB_WIRE_TYPE_VARINT ) return def;
  return (int)tlv.varint;
}
