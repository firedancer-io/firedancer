#ifndef HEADER_fd_src_ballet_pb_fd_pb_encode_h
#define HEADER_fd_src_ballet_pb_fd_pb_encode_h

/* fd_pb_encode.h is a header-only Protobuf wire format encoder.  It
   is schema agnostic and designed for embedded use.  Data is written
   out in a streaming manner, with occasional fixups of length prefixes
   when writing submessages.

   Using this API requires understanding how Protobuf schemas map to the
   wire format: https://protobuf.dev/programming-guides/encoding/

   Here is how fd_pb_encode compares to a typical Protobuf encoding
   library:
   - No dependencies (no protoc)
   - No code generation (user hand-writes encoders)
   - No memory allocator needed
   - No streaming support (message written into a contiguous buffer)
   - User error can result in corrupt messages (duplicate or incorrect
     tags, etc)
   - Space efficiently is slightly worse (larger length-prefixes for
     submessages) */

#include "fd_pb_wire.h"
#include "../../util/log/fd_log.h"

/* FD_PB_ENCODE_DEPTH_MAX specifies the max submessage depth. */

#define FD_PB_ENCODER_DEPTH_MAX (63UL)

/* The pb_encoder class is used to serialize Protobuf messages.  The
   user calls fd_pb_encode_* with each field, top down. */

struct fd_pb_encoder {

  /* [buf0,buf1) is the encode buffer */
  uchar * buf0;
  uchar * buf1;

  /* cur points to where the next field is placed */
  uchar * cur;

  /* Sub-message nesting depth of new fields (0==topmost) */
  uint depth;

  /* offset to length prefix of each depth
     lp_off[0] points to the length prefix of a LEN field at depth 0
     (the LEN field's submessage is at depth 1) */
  uint lp_off[ FD_PB_ENCODER_DEPTH_MAX ];

};

typedef struct fd_pb_encoder fd_pb_encoder_t;

FD_PROTOTYPES_BEGIN

/* fd_pb_encoder_init creates a Protobuf encoder.  Data is written to
   the buffer at out (up to out_sz bytes).  Returns the initialized
   encoder object (has a mutable borrow on out).  On return, the
   encoder's current message is the topmost message of the encode op.

   out_sz should be slightly overallocated (by 32 bytes) since encoder
   bounds checks use overly conservative upper bounds for performance
   (i.e. the encoder might fail to add a field with "out of space" if
   less than 32 bytes of space is remaining, even if the field would
   still fit). */

static FD_FN_UNUSED fd_pb_encoder_t *
fd_pb_encoder_init( fd_pb_encoder_t * encoder,
                    uchar *           out,
                    ulong             out_sz ) {
  encoder->buf0  = out;
  encoder->buf1  = out + out_sz;
  encoder->cur   = out;
  encoder->depth = 0U;
  return encoder;
}

/* fd_pb_encoder_fini destroys a Protobuf encoder.  This is mostly
   provided for code cosmetics (does not do any work), since
   fd_pb_encoder ensures that the output buffer contains a valid
   Protobuf message after every topmost-level write. */

static FD_FN_UNUSED void *
fd_pb_encoder_fini( fd_pb_encoder_t * encoder ) {
  encoder->buf0  = NULL;
  encoder->buf1  = NULL;
  encoder->cur   = NULL;
  encoder->depth = 0;
  return encoder;
}

/* fd_pb_encoder_out returns a pointer to the first byte of the encoded
   output.  There is a valid serialized Protobuf message behind this
   pointer when the following conditions are true:
   - At least one field was fully written at the topmost message
   - No write is currently inflight (submessage, length-prefixed, etc) */

static inline uchar *
fd_pb_encoder_out( fd_pb_encoder_t * encoder ) {
  return encoder->buf0;
}

/* fd_pb_encoder_out_sz returns the number of bytes produced so far. */

static inline ulong
fd_pb_encoder_out_sz( fd_pb_encoder_t * encoder ) {
  FD_CRIT( encoder->cur >= encoder->buf0, "corrupt encoder state" );
  return (ulong)encoder->cur - (ulong)encoder->buf0;
}

/* fd_pb_encoder_space returns the number of encoded field bytes that
   can be appended to the current submessage. */

static inline ulong
fd_pb_encoder_space( fd_pb_encoder_t const * encoder ) {
  FD_CRIT( encoder->cur <= encoder->buf1, "corrupt encoder state" );
  return (ulong)encoder->buf1 - (ulong)encoder->cur;
}

/* fd_pb_lp_open adds a new unknown-sized LEN field to the encoder's
   current message.  Returns encoder on success.  On failure (no space),
   returns NULL.  Every successful call must be paired with a call to
   fd_pb_lp_close.  Use fd_pb_encoder_space to check how much free
   space the frame has, and fd_pb_encoder_push to append data.

   This method is useful for serializing Protobuf submessages with
   another library, moving encoded submessages without a deserialize/
   serialize pass, streaming out packed repated fields, iterating over
   an unknown-sized sequence, etc.  */

static FD_FN_UNUSED fd_pb_encoder_t *
fd_pb_lp_open( fd_pb_encoder_t * encoder,
               uint              field_id ) {
  if( FD_UNLIKELY( fd_pb_encoder_space( encoder ) <
                   (fd_pb_varint32_sz_max + fd_pb_varint32_sz_max) ) ) {
    return NULL;
  }
  uint depth = encoder->depth++;
  if( FD_UNLIKELY( depth >= FD_PB_ENCODER_DEPTH_MAX ) ) {
    /* unreachable for well-written clients */
    FD_LOG_WARNING(( "pb_encode failed: submessage nesting depth exceeded" ));
    return NULL;
  }
  /* Add tag, reserve worst-case space for length-prefix */
  uint tag = fd_pb_tag( FD_PB_WIRE_TYPE_LEN, field_id );
  encoder->cur              = fd_pb_append_uint32( encoder->cur, tag );
  encoder->lp_off[ depth ]  = (uint)( encoder->cur - encoder->buf0 );
  encoder->cur             += fd_pb_varint32_sz_max;
  return encoder;
}

/* fd_pb_lp_close closes the current LEN field (opened with
   fd_pb_lp_open)  Returns encoder on success and NULL on failure
   (LEN field exceeds max size). */

static FD_FN_UNUSED fd_pb_encoder_t *
fd_pb_lp_close( fd_pb_encoder_t * encoder ) {
  FD_CRIT( encoder->depth, "unmatched lp_close" );
  uint    depth = --encoder->depth;
  uchar * lp    = encoder->buf0 + encoder->lp_off[ depth ];
  uchar * sub0  = lp + fd_pb_varint32_sz_max;
  uchar * sub1  = encoder->cur;
  ulong   sz    = (ulong)( sub1-sub0 );
  FD_CRIT( sub0<=sub1,          "corrupt submessage state" );
  FD_CRIT( sub1<=encoder->buf1, "out-of-bounds write"      );
  if( FD_UNLIKELY( sz>UINT_MAX ) ) {
    FD_LOG_WARNING(( "pb_encode failed: submessage is too large" ));
  }
  fd_pb_append_varint32_sz5( lp, (uint)sz );
  return encoder;
}

/* fd_pb_submsg_open adds a new submessage to the encoder's current
   message, then pivots the current message to the newly created
   submessage.  Returns encoder on success, NULL on failure (no space
   remaining).  Every successful call must be paired with a call to
   fd_pb_submsg_close. */

static inline fd_pb_encoder_t *
fd_pb_submsg_open( fd_pb_encoder_t * encoder,
                   uint              field_id ) {
  return fd_pb_lp_open( encoder, field_id );
}

/* fd_pb_submsg_close finishes the encoder's current submessage.  Sets
   the encoder's current message to the parent message.  Returns
   encoder on success and NULL on failure (submessage exceeds max msg
   size). */

static inline fd_pb_encoder_t *
fd_pb_submsg_close( fd_pb_encoder_t * encoder ) {
  return fd_pb_lp_close( encoder );
}

/* The below fd_pb_push_<type> methods append a field to the encoder's
   current message.  type and field_id are the field's parameters as
   defined in the schema.  value depends on the message type.  Note that
   the provided type MUST match the schema (e.g. encoding uint32 where
   the schema says sint32 would result in memory corruption).  Returns
   encoder on success, or NULL on failure (out of space).

   fd_pb_push_bool adds a boolean field.  value==0 implies false,
   otherwise implies true.

   fd_pb_push_{int32,int64} add a signed integer field (optimized for
   small unsigned numbers).

   fd_pb_push_{uint32,uint64} add an unsigned integer field (optimized
   for small numbers).

   fd_pb_push_{sint32,sint64} add a signed integer field (optimized
   for numbers close to zero).

   fd_pb_push_{fixed32,fixed64} add an unsigned integer field
   (optimized for very large numbers).

   fd_pb_push_{sfixed32,sfixed64} add a signed integer field
   (optimized for very small or large numbers).

   fd_pb_push_{float,double} add a {32,64} bit precision floating-
   point field.

   fd_pb_push_bytes adds a byte array field.

   fd_pb_push_string adds a UTF-8 string field.

   fd_pb_push_cstr adds a UTF-8 string field from a NULL-delimited C
   string. */

static inline fd_pb_encoder_t *
fd_pb_push_bool( fd_pb_encoder_t * encoder,
                 uint              field_id,
                 int               value ) {
  if( FD_UNLIKELY( fd_pb_encoder_space( encoder ) <
                   (fd_pb_varint32_sz_max + 1) ) ) {
    return NULL;
  }
  uint tag = fd_pb_tag( FD_PB_WIRE_TYPE_VARINT, field_id );
  encoder->cur = fd_pb_append_uint32( encoder->cur, tag   );
  encoder->cur = fd_pb_append_bool  ( encoder->cur, value );
  return encoder;
}

static inline fd_pb_encoder_t *
fd_pb_push_int32( fd_pb_encoder_t * encoder,
                  uint              field_id,
                  int               value ) {
  if( FD_UNLIKELY( fd_pb_encoder_space( encoder ) <
                   (fd_pb_varint32_sz_max + fd_pb_varint32_sz_max) ) ) {
    return NULL;
  }
  uint tag = fd_pb_tag( FD_PB_WIRE_TYPE_VARINT, field_id );
  encoder->cur = fd_pb_append_uint32( encoder->cur, tag   );
  encoder->cur = fd_pb_append_int32 ( encoder->cur, value );
  return encoder;
}

static inline fd_pb_encoder_t *
fd_pb_push_int64( fd_pb_encoder_t * encoder,
                  uint              field_id,
                  long              value ) {
  if( FD_UNLIKELY( fd_pb_encoder_space( encoder ) <
                   (fd_pb_varint32_sz_max + fd_pb_varint64_sz_max) ) ) {
    return NULL;
  }
  uint tag = fd_pb_tag( FD_PB_WIRE_TYPE_VARINT, field_id );
  encoder->cur = fd_pb_append_uint32( encoder->cur, tag   );
  encoder->cur = fd_pb_append_int64 ( encoder->cur, value );
  return encoder;
}

static inline fd_pb_encoder_t *
fd_pb_push_uint32( fd_pb_encoder_t * encoder,
                   uint              field_id,
                   uint              value ) {
  if( FD_UNLIKELY( fd_pb_encoder_space( encoder ) <
                   (fd_pb_varint32_sz_max + fd_pb_varint32_sz_max) ) ) {
    return NULL;
  }
  uint tag = fd_pb_tag( FD_PB_WIRE_TYPE_VARINT, field_id );
  encoder->cur = fd_pb_append_uint32( encoder->cur, tag   );
  encoder->cur = fd_pb_append_uint32( encoder->cur, value );
  return encoder;
}

static inline fd_pb_encoder_t *
fd_pb_push_uint64( fd_pb_encoder_t * encoder,
                   uint              field_id,
                   ulong             value ) {
  if( FD_UNLIKELY( fd_pb_encoder_space( encoder ) <
                   (fd_pb_varint32_sz_max + fd_pb_varint64_sz_max) ) ) {
    return NULL;
  }
  uint tag = fd_pb_tag( FD_PB_WIRE_TYPE_VARINT, field_id );
  encoder->cur = fd_pb_append_uint32( encoder->cur, tag   );
  encoder->cur = fd_pb_append_uint64( encoder->cur, value );
  return encoder;
}

static inline fd_pb_encoder_t *
fd_pb_push_sint32( fd_pb_encoder_t * encoder,
                   uint              field_id,
                   int               value ) {
  if( FD_UNLIKELY( fd_pb_encoder_space( encoder ) <
                   (fd_pb_varint32_sz_max + fd_pb_varint32_sz_max) ) ) {
    return NULL;
  }
  uint tag = fd_pb_tag( FD_PB_WIRE_TYPE_VARINT, field_id );
  encoder->cur = fd_pb_append_uint32( encoder->cur, tag   );
  encoder->cur = fd_pb_append_sint32( encoder->cur, value );
  return encoder;
}

static inline fd_pb_encoder_t *
fd_pb_push_sint64( fd_pb_encoder_t * encoder,
                   uint              field_id,
                   long              value ) {
  if( FD_UNLIKELY( fd_pb_encoder_space( encoder ) <
                   (fd_pb_varint32_sz_max + fd_pb_varint64_sz_max) ) ) {
    return NULL;
  }
  uint tag = fd_pb_tag( FD_PB_WIRE_TYPE_VARINT, field_id );
  encoder->cur = fd_pb_append_uint32( encoder->cur, tag   );
  encoder->cur = fd_pb_append_sint64( encoder->cur, value );
  return encoder;
}

static inline fd_pb_encoder_t *
fd_pb_push_fixed32( fd_pb_encoder_t * encoder,
                    uint              field_id,
                    uint              value ) {
  if( FD_UNLIKELY( fd_pb_encoder_space( encoder ) <
                   (fd_pb_varint32_sz_max + sizeof(uint)) ) ) {
    return NULL;
  }
  uint tag = fd_pb_tag( FD_PB_WIRE_TYPE_VARINT, field_id );
  encoder->cur = fd_pb_append_uint32 ( encoder->cur, tag   );
  encoder->cur = fd_pb_append_fixed32( encoder->cur, value );
  return encoder;
}

static inline fd_pb_encoder_t *
fd_pb_push_fixed64( fd_pb_encoder_t * encoder,
                    uint              field_id,
                    ulong             value ) {
  if( FD_UNLIKELY( fd_pb_encoder_space( encoder ) <
                   (fd_pb_varint32_sz_max + sizeof(uint)) ) ) {
    return NULL;
  }
  uint tag = fd_pb_tag( FD_PB_WIRE_TYPE_VARINT, field_id );
  encoder->cur = fd_pb_append_uint32 ( encoder->cur, tag   );
  encoder->cur = fd_pb_append_fixed64( encoder->cur, value );
  return encoder;
}

static inline fd_pb_encoder_t *
fd_pb_push_float( fd_pb_encoder_t * encoder,
                  uint              field_id,
                  float             value ) {
  union { float f; uint u; } cast;
  cast.f = value;
  return fd_pb_push_fixed32( encoder, field_id, cast.u );
}

#if FD_HAS_DOUBLE
static inline fd_pb_encoder_t *
fd_pb_push_double( fd_pb_encoder_t * encoder,
                   uint              field_id,
                   double            value ) {
  union { double d; ulong v; } cast;
  cast.d = value;
  return fd_pb_push_fixed64( encoder, field_id, cast.v );
}
#endif

static inline fd_pb_encoder_t *
fd_pb_push_bytes( fd_pb_encoder_t * encoder,
                  uint              field_id,
                  void const *      buf,
                  ulong             sz ) {
  if( FD_UNLIKELY( fd_pb_encoder_space( encoder ) <
                   (fd_pb_varint32_sz_max + fd_pb_varint32_sz_max + sz) ||
                   sz>UINT_MAX ) ) {  /* max message size, overflow protect */
    return NULL;
  }
  uint tag = fd_pb_tag( FD_PB_WIRE_TYPE_LEN, field_id );
  encoder->cur = fd_pb_append_uint32( encoder->cur, tag      );
  encoder->cur = fd_pb_append_uint32( encoder->cur, (uint)sz );
  fd_memcpy( encoder->cur, buf, sz );
  encoder->cur += sz;
  return encoder;
}

static inline fd_pb_encoder_t *
fd_pb_push_string( fd_pb_encoder_t * encoder,
                   uint              field_id,
                   char const *      str,
                   ulong             len ) {
  return fd_pb_push_bytes( encoder, field_id, str, len );
}

static inline fd_pb_encoder_t *
fd_pb_push_cstr( fd_pb_encoder_t * encoder,
                 uint              field_id,
                 char const *      cstr ) {
  /* FIXME could do this in a single pass */
  return fd_pb_push_string( encoder, field_id, cstr, strlen( cstr ) );
}

/* The below fd_pb_push_packed_<type> methods append a packed repeated
   field (a sequence of scalars).  These are analogous to the above
   encoders, except that they encode multiple values.  values points to
   a contiguous array of values.  cnt is the number of values (zero is
   fine).

   On the wire, a packed repeated field is a LEN type field with the
   content set to the concatenated serializations of each element.

   These are all equivalent to the following pattern:

     fd_pb_lp_open()
     for( each element ) fd_pb_append_type()
     fd_pb_lp_close()

   fd_pb_push_packed_bool is deliberately omitted. */

#define FD_PB_PUSH_PACKED( type, ctype )                                  \
  fd_pb_encoder_t *                                                       \
  fd_pb_push_packed_##type( fd_pb_encoder_t * encoder,                    \
                            uint              field_id,                   \
                            ctype const *     values,                     \
                            ulong             cnt ) {                     \
    /* would exceed max message size? */                                  \
    if( FD_UNLIKELY( cnt>UINT_MAX ) ) return NULL;                        \
    if( FD_UNLIKELY( !fd_pb_lp_open( encoder, field_id ) ) ) return NULL; \
    if( FD_LIKELY( cnt*fd_pb_##type##_sz_max <                            \
                   fd_pb_encoder_space( encoder ) ) ) {                   \
      /* optimize for fast append */                                      \
      for( ulong i=0UL; i<cnt; i++ ) {                                    \
        encoder->cur = fd_pb_append_##type( encoder->cur, values[ i ] );  \
      }                                                                   \
    } else {                                                              \
      /* cold code */                                                     \
      for( ulong i=0UL; i<cnt; i++ ) {                                    \
        if( FD_UNLIKELY( fd_pb_encoder_space( encoder ) <                 \
                         fd_pb_##type##_sz_max ) ) return NULL;           \
        encoder->cur = fd_pb_append_##type( encoder->cur, values[ i ] );  \
      }                                                                   \
    }                                                                     \
    fd_pb_lp_close( encoder );                                            \
    return encoder;                                                       \
  }

FD_PB_PUSH_PACKED( int32,   int   )
FD_PB_PUSH_PACKED( int64,   long  )
FD_PB_PUSH_PACKED( uint32,  uint  )
FD_PB_PUSH_PACKED( uint64,  ulong )
FD_PB_PUSH_PACKED( sint32,  int   )
FD_PB_PUSH_PACKED( sint64,  long  )
FD_PB_PUSH_PACKED( fixed32, uint  )
FD_PB_PUSH_PACKED( fixed64, ulong )

#undef FD_PB_PUSH_PACKED

static inline fd_pb_encoder_t *
fd_pb_push_packed_float( fd_pb_encoder_t * encoder,
                         uint              field_id,
                         float const *     value,
                         ulong             cnt ) {
  return fd_pb_push_packed_fixed32( encoder, field_id, fd_type_pun_const( value ), cnt );
}

#if FD_HAS_DOUBLE
static inline fd_pb_encoder_t *
fd_pb_push_packed_double( fd_pb_encoder_t * encoder,
                          uint              field_id,
                          double const *    value,
                          ulong             cnt ) {
  return fd_pb_push_packed_fixed64( encoder, field_id, fd_type_pun_const( value ), cnt );
}
#endif

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_pb_fd_pb_encode_h */
