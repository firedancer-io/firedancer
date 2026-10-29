#include "fd_pb_gen.h"
#include <stdlib.h>

uchar *
fd_pb_encode( fd_pb_msgdesc_t const * desc,
              void const *            msg,
              uchar *                 out,
              ulong *                 out_sz ) {
  fd_pb_encoder_t enc[1];
  fd_pb_encoder_init( enc, out, *out_sz );
  if( FD_UNLIKELY( !desc->encode( enc, msg ) ) ) return NULL;
  *out_sz = fd_pb_encoder_out_sz( enc );
  fd_pb_encoder_fini( enc );
  return out;
}

void *
fd_pb_decode( fd_pb_msgdesc_t const * desc,
              void *                  msg,
              void const *            in,
              ulong                   in_sz ) {
  fd_pb_inbuf_t buf[1];
  fd_pb_inbuf_init( buf, in, in_sz );
  if( FD_UNLIKELY( !desc->decode( buf, msg ) ) ) {
    desc->release( msg );
    return NULL;
  }
  return msg;
}

void
fd_pb_release( fd_pb_msgdesc_t const * desc,
               void *                  msg ) {
  desc->release( msg );
}

/* Scalar decoding */

static int
dec_varint( fd_pb_tlv_t const * tlv,
            ulong *             out ) {
  if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_VARINT ) ) return 0;
  *out = tlv->varint;
  return 1;
}

int
fd_pb_dec_bool( fd_pb_inbuf_t * in, fd_pb_tlv_t const * tlv, bool * out ) {
  (void)in; ulong v;
  if( FD_UNLIKELY( !dec_varint( tlv, &v ) ) ) return 0;
  *out = v!=0UL;
  return 1;
}

int
fd_pb_dec_int32( fd_pb_inbuf_t * in, fd_pb_tlv_t const * tlv, int * out ) {
  (void)in; ulong v;
  if( FD_UNLIKELY( !dec_varint( tlv, &v ) ) ) return 0;
  *out = (int)(uint)v;
  return 1;
}

int
fd_pb_dec_uint32( fd_pb_inbuf_t * in, fd_pb_tlv_t const * tlv, uint * out ) {
  (void)in; ulong v;
  if( FD_UNLIKELY( !dec_varint( tlv, &v ) ) ) return 0;
  if( FD_UNLIKELY( v>UINT_MAX ) ) return 0;
  *out = (uint)v;
  return 1;
}

int
fd_pb_dec_sint32( fd_pb_inbuf_t * in, fd_pb_tlv_t const * tlv, int * out ) {
  (void)in; ulong v;
  if( FD_UNLIKELY( !dec_varint( tlv, &v ) ) ) return 0;
  long s = fd_long_zz_dec( v );
  if( FD_UNLIKELY( s<INT_MIN || s>INT_MAX ) ) return 0;
  *out = (int)s;
  return 1;
}

int
fd_pb_dec_int64( fd_pb_inbuf_t * in, fd_pb_tlv_t const * tlv, long * out ) {
  (void)in; ulong v;
  if( FD_UNLIKELY( !dec_varint( tlv, &v ) ) ) return 0;
  *out = (long)v;
  return 1;
}

int
fd_pb_dec_uint64( fd_pb_inbuf_t * in, fd_pb_tlv_t const * tlv, ulong * out ) {
  (void)in;
  return dec_varint( tlv, out );
}

int
fd_pb_dec_sint64( fd_pb_inbuf_t * in, fd_pb_tlv_t const * tlv, long * out ) {
  (void)in; ulong v;
  if( FD_UNLIKELY( !dec_varint( tlv, &v ) ) ) return 0;
  *out = fd_long_zz_dec( v );
  return 1;
}

int
fd_pb_dec_fixed32( fd_pb_inbuf_t * in, fd_pb_tlv_t const * tlv, uint * out ) {
  (void)in;
  if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_I32 ) ) return 0;
  *out = tlv->i32;
  return 1;
}

int
fd_pb_dec_fixed64( fd_pb_inbuf_t * in, fd_pb_tlv_t const * tlv, ulong * out ) {
  (void)in;
  if( FD_UNLIKELY( tlv->wire_type!=FD_PB_WIRE_TYPE_I64 ) ) return 0;
  *out = tlv->i64;
  return 1;
}

/* Repeated fields */

void *
fd_pb_dec_grow( void ** arr,
                uint *  cnt,
                ulong   ele_sz ) {
  uint n = *cnt;
  if( FD_UNLIKELY( n==UINT_MAX ) ) return NULL;
  /* Capacity is the next power of two of n (geometric growth) */
  if( !n || fd_uint_is_pow2( n ) ) {
    ulong cap = n ? 2UL*n : 1UL;
    void * p = realloc( *arr, cap*ele_sz );
    if( FD_UNLIKELY( !p ) ) return NULL;
    *arr = p;
  }
  uchar * ele = (uchar *)*arr + n*ele_sz;
  memset( ele, 0, ele_sz );
  *cnt = n+1U;
  return ele;
}

static ulong
type_sz( int type ) {
  switch( type ) {
  case FD_PB_GEN_BOOL:    return sizeof(bool);
  case FD_PB_GEN_INT32:
  case FD_PB_GEN_UINT32:
  case FD_PB_GEN_SINT32:
  case FD_PB_GEN_FIXED32: return 4UL;
  default:                return 8UL;
  }
}

static int
dec_scalar( fd_pb_inbuf_t *     in,
            fd_pb_tlv_t const * tlv,
            int                 type,
            void *              out ) {
  switch( type ) {
  case FD_PB_GEN_BOOL:    return fd_pb_dec_bool   ( in, tlv, out );
  case FD_PB_GEN_INT32:   return fd_pb_dec_int32  ( in, tlv, out );
  case FD_PB_GEN_UINT32:  return fd_pb_dec_uint32 ( in, tlv, out );
  case FD_PB_GEN_SINT32:  return fd_pb_dec_sint32 ( in, tlv, out );
  case FD_PB_GEN_INT64:   return fd_pb_dec_int64  ( in, tlv, out );
  case FD_PB_GEN_UINT64:  return fd_pb_dec_uint64 ( in, tlv, out );
  case FD_PB_GEN_SINT64:  return fd_pb_dec_sint64 ( in, tlv, out );
  case FD_PB_GEN_FIXED32: return fd_pb_dec_fixed32( in, tlv, out );
  case FD_PB_GEN_FIXED64: return fd_pb_dec_fixed64( in, tlv, out );
  default:                return 0;
  }
}

static uint
type_wire( int type ) {
  switch( type ) {
  case FD_PB_GEN_FIXED32: return FD_PB_WIRE_TYPE_I32;
  case FD_PB_GEN_FIXED64: return FD_PB_WIRE_TYPE_I64;
  default:                return FD_PB_WIRE_TYPE_VARINT;
  }
}

static fd_pb_inbuf_t *
read_varint( fd_pb_inbuf_t * buf,
             ulong *         out ) {
  ulong sz  = fd_pb_inbuf_sz( buf );
  ulong var = 0UL;
  for( ulong i=0UL; i<fd_ulong_min( sz, 10UL ); i++ ) {
    var |= (ulong)( buf->cur[i] & 0x7f ) << (7*i);
    if( !( buf->cur[i] & 0x80 ) ) {
      buf->cur += i+1;
      *out = var;
      return buf;
    }
  }
  return NULL;
}

int
fd_pb_dec_repeated( fd_pb_inbuf_t *     in,
                    fd_pb_tlv_t const * tlv,
                    int                 type,
                    void **             arr,
                    uint *              cnt ) {
  ulong ele_sz = type_sz( type );
  if( tlv->wire_type!=FD_PB_WIRE_TYPE_LEN ) {
    void * ele = fd_pb_dec_grow( arr, cnt, ele_sz );
    if( FD_UNLIKELY( !ele ) ) return 0;
    return dec_scalar( in, tlv, type, ele );
  }

  /* Packed */
  fd_pb_inbuf_t sub[1];
  if( FD_UNLIKELY( !fd_pb_tlv_submsg( in, tlv, sub ) ) ) return 0;
  in->cur = sub->end;
  fd_pb_tlv_t vtlv[1] = {{ .wire_type = type_wire( type ), .field_id = tlv->field_id }};
  while( fd_pb_inbuf_sz( sub ) ) {
    switch( vtlv->wire_type ) {
    case FD_PB_WIRE_TYPE_VARINT:
      if( FD_UNLIKELY( !read_varint( sub, &vtlv->varint ) ) ) return 0;
      break;
    case FD_PB_WIRE_TYPE_I32:
      if( FD_UNLIKELY( fd_pb_inbuf_sz( sub )<4UL ) ) return 0;
      vtlv->varint = 0UL;
      vtlv->i32    = FD_LOAD( uint, sub->cur );
      sub->cur    += 4UL;
      break;
    case FD_PB_WIRE_TYPE_I64:
      if( FD_UNLIKELY( fd_pb_inbuf_sz( sub )<8UL ) ) return 0;
      vtlv->i64    = FD_LOAD( ulong, sub->cur );
      sub->cur    += 8UL;
      break;
    }
    void * ele = fd_pb_dec_grow( arr, cnt, ele_sz );
    if( FD_UNLIKELY( !ele ) ) return 0;
    if( FD_UNLIKELY( !dec_scalar( sub, vtlv, type, ele ) ) ) return 0;
  }
  return 1;
}

/* Length-delimited fields */

int
fd_pb_dec_submsg( fd_pb_inbuf_t *         in,
                  fd_pb_tlv_t const *     tlv,
                  fd_pb_msgdesc_t const * desc,
                  void *                  msg ) {
  fd_pb_inbuf_t sub[1];
  if( FD_UNLIKELY( !fd_pb_tlv_submsg( in, tlv, sub ) ) ) return 0;
  in->cur = sub->end;
  return desc->decode( sub, msg );
}

int
fd_pb_dec_bytes_ptr( fd_pb_inbuf_t *        in,
                     fd_pb_tlv_t const *    tlv,
                     fd_pb_bytes_array_t ** out ) {
  uchar const * data = fd_pb_tlv_bytes( in, tlv );
  if( FD_UNLIKELY( !data || tlv->len>UINT_MAX ) ) return 0;
  free( *out );
  *out = malloc( FD_PB_BYTES_ARRAY_T_ALLOCSIZE( tlv->len ) );
  if( FD_UNLIKELY( !*out ) ) return 0;
  (*out)->size = (uint)tlv->len;
  fd_memcpy( (*out)->bytes, data, tlv->len );
  in->cur += tlv->len;
  return 1;
}

int
fd_pb_dec_bytes_fixed( fd_pb_inbuf_t *     in,
                       fd_pb_tlv_t const * tlv,
                       uchar *             out,
                       ulong               sz ) {
  uchar const * data = fd_pb_tlv_bytes( in, tlv );
  if( FD_UNLIKELY( !data ) ) return 0;
  if( !tlv->len ) {
    /* Empty bytes decode as all zeros */
    memset( out, 0, sz );
    return 1;
  }
  if( FD_UNLIKELY( tlv->len!=sz ) ) return 0;
  fd_memcpy( out, data, sz );
  in->cur += sz;
  return 1;
}

int
fd_pb_dec_bytes_static( fd_pb_inbuf_t *     in,
                        fd_pb_tlv_t const * tlv,
                        uchar *             out,
                        uint *              out_sz,
                        ulong               max ) {
  uchar const * data = fd_pb_tlv_bytes( in, tlv );
  if( FD_UNLIKELY( !data || tlv->len>max ) ) return 0;
  fd_memcpy( out, data, tlv->len );
  *out_sz  = (uint)tlv->len;
  in->cur += tlv->len;
  return 1;
}

int
fd_pb_dec_string_static( fd_pb_inbuf_t *     in,
                         fd_pb_tlv_t const * tlv,
                         char *              out,
                         ulong               max ) {
  if( FD_UNLIKELY( !fd_pb_tlv_cstr( in, tlv, out, max ) ) ) return 0;
  in->cur += tlv->len;
  return 1;
}

/* Encoding */

/* lp_close_compact closes a LEN field opened with fd_pb_lp_open and
   rewrites the length prefix in its shortest form. */

static int
lp_close_compact( fd_pb_encoder_t * enc ) {
  uchar * lp   = enc->buf0 + enc->lp_off[ enc->depth-1U ];
  uchar * sub0 = lp + fd_pb_varint32_sz_max;
  ulong   sz   = (ulong)( enc->cur - sub0 );
  if( FD_UNLIKELY( sz>UINT_MAX ) ) return 0;
  fd_pb_lp_close( enc );
  uchar   tmp[ 8 ];
  ulong   lp_sz = (ulong)( fd_pb_append_varint32( tmp, (uint)sz ) - tmp );
  fd_memcpy( lp, tmp, lp_sz );
  memmove( lp+lp_sz, sub0, sz );
  enc->cur = lp + lp_sz + sz;
  return 1;
}

int
fd_pb_enc_submsg( fd_pb_encoder_t *       enc,
                  uint                    field_id,
                  fd_pb_msgdesc_t const * desc,
                  void const *            msg ) {
  if( FD_UNLIKELY( !fd_pb_submsg_open( enc, field_id ) ) ) return 0;
  if( FD_UNLIKELY( !desc->encode( enc, msg ) ) ) return 0;
  return lp_close_compact( enc );
}

int
fd_pb_enc_bytes_ptr( fd_pb_encoder_t *           enc,
                     uint                        field_id,
                     fd_pb_bytes_array_t const * bytes ) {
  static uchar const empty[1];
  if( !bytes ) return !!fd_pb_push_bytes( enc, field_id, empty, 0UL );
  return !!fd_pb_push_bytes( enc, field_id, bytes->bytes, bytes->size );
}

int
fd_pb_enc_packed( fd_pb_encoder_t * enc,
                  uint              field_id,
                  int               type,
                  void const *      arr,
                  ulong             cnt ) {
  if( !cnt ) return 1;
  if( FD_UNLIKELY( !fd_pb_lp_open( enc, field_id ) ) ) return 0;
  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( fd_pb_encoder_space( enc )<fd_pb_varint64_sz_max ) ) return 0;
    switch( type ) {
    case FD_PB_GEN_BOOL:    enc->cur = fd_pb_append_bool   ( enc->cur, ((bool  const *)arr)[i] );        break;
    case FD_PB_GEN_INT32:   enc->cur = fd_pb_append_int64  ( enc->cur, (long)((int const *)arr)[i] );    break;
    case FD_PB_GEN_UINT32:  enc->cur = fd_pb_append_uint32 ( enc->cur, ((uint  const *)arr)[i] );        break;
    case FD_PB_GEN_SINT32:  enc->cur = fd_pb_append_sint32 ( enc->cur, ((int   const *)arr)[i] );        break;
    case FD_PB_GEN_INT64:   enc->cur = fd_pb_append_int64  ( enc->cur, ((long  const *)arr)[i] );        break;
    case FD_PB_GEN_UINT64:  enc->cur = fd_pb_append_uint64 ( enc->cur, ((ulong const *)arr)[i] );        break;
    case FD_PB_GEN_SINT64:  enc->cur = fd_pb_append_sint64 ( enc->cur, ((long  const *)arr)[i] );        break;
    case FD_PB_GEN_FIXED32: enc->cur = fd_pb_append_fixed32( enc->cur, FD_LOAD( uint,  (uchar const *)arr+4UL*i ) ); break;
    case FD_PB_GEN_FIXED64: enc->cur = fd_pb_append_fixed64( enc->cur, FD_LOAD( ulong, (uchar const *)arr+8UL*i ) ); break;
    default: return 0;
    }
  }
  return lp_close_compact( enc );
}
