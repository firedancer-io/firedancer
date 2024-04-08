#ifndef HEADER_fd_src_util_encoders_fd_bincode_h
#define HEADER_fd_src_util_encoders_fd_bincode_h

#include "../../util/fd_util.h"

typedef void
(* fd_types_walk_fn_t)( void *       self,
                        void const * arg,
                        char const * name,
                        int          type,
                        char const * type_name,
                        uint         level );

/* Context argument used for encoding */
struct fd_bincode_encode_ctx {
  /* Current position in data buffer */
  void * data;
  /* End of buffer */
  void * dataend;
};
typedef struct fd_bincode_encode_ctx fd_bincode_encode_ctx_t;

/* Context argument used for decoding */
struct fd_bincode_decode_ctx {
  /* Current position in data buffer */
  void const *   data;
  /* End of buffer */
  void const *   dataend;
  /* Allocator for dynamic memory */
  fd_valloc_t    valloc;
};
typedef struct fd_bincode_decode_ctx fd_bincode_decode_ctx_t;

/* Context argument used for calling "destroy" on a structure */
struct fd_bincode_destroy_ctx {
  /* Allocator for dynamic memory */
  fd_valloc_t valloc;
};
typedef struct fd_bincode_destroy_ctx fd_bincode_destroy_ctx_t;

#define FD_BINCODE_SUCCESS         (    0)
#define FD_BINCODE_ERR_UNDERFLOW   (-1001) /* Attempted to read past end of buffer */
#define FD_BINCODE_ERR_OVERFLOW    (-1002) /* Attempted to write past end of buffer */
#define FD_BINCODE_ERR_ENCODING    (-1003) /* Invalid encoding */
#define FD_BINCODE_ERR_SMALL_DEQUE (-1004) /* deque max size is too small */

#define FD_BINCODE_PRIMITIVE_STUBS( name, type ) \
  static inline int \
  fd_bincode_##name##_decode( type *                    self, \
                              fd_bincode_decode_ctx_t * ctx ) { \
    uchar const * ptr = (uchar const *) ctx->data; \
    if ( FD_UNLIKELY((void const *)(ptr + sizeof(type)) > ctx->dataend ) ) \
      return FD_BINCODE_ERR_UNDERFLOW; \
    memcpy( self, ptr, sizeof(type) );  /* unaligned */ \
    ctx->data = ptr + sizeof(type); \
    return FD_BINCODE_SUCCESS; \
  } \
  static inline int \
  fd_bincode_##name##_decode_preflight( fd_bincode_decode_ctx_t * ctx ) { \
    uchar const * ptr = (uchar const *) ctx->data; \
    if ( FD_UNLIKELY((void const *)(ptr + sizeof(type)) > ctx->dataend ) ) \
      return FD_BINCODE_ERR_UNDERFLOW; \
    ctx->data = ptr + sizeof(type); \
    return FD_BINCODE_SUCCESS; \
  } \
  static inline void \
  fd_bincode_##name##_decode_unsafe( type *                    self, \
                                     fd_bincode_decode_ctx_t * ctx ) { \
    uchar const * ptr = (uchar const *) ctx->data; \
    memcpy( self, ptr, sizeof(type) );  /* unaligned */ \
    ctx->data = ptr + sizeof(type); \
  } \
  static inline int \
  fd_bincode_##name##_encode( type                      self, \
                              fd_bincode_encode_ctx_t * ctx ) { \
    uchar * ptr = (uchar *)ctx->data; \
    if ( FD_UNLIKELY((void *)(ptr + sizeof(type)) > ctx->dataend ) ) \
      return FD_BINCODE_ERR_OVERFLOW; \
    FD_STORE( type, ptr, self );  /* unaligned */ \
    ctx->data = ptr + sizeof(type); \
    return FD_BINCODE_SUCCESS; \
  }

FD_BINCODE_PRIMITIVE_STUBS( uint8,   uchar   )
FD_BINCODE_PRIMITIVE_STUBS( uint16,  ushort  )
FD_BINCODE_PRIMITIVE_STUBS( uint32,  uint    )
FD_BINCODE_PRIMITIVE_STUBS( uint64,  ulong   )
#if FD_HAS_INT128
FD_BINCODE_PRIMITIVE_STUBS( uint128, uint128 )
#endif
FD_BINCODE_PRIMITIVE_STUBS( double,  double  )

static inline int
fd_bincode_bool_decode( uchar *                   self,
                        fd_bincode_decode_ctx_t * ctx ) {

  uchar const * ptr = (uchar const *)ctx->data;
  if( FD_UNLIKELY( ptr+1 > (uchar const *)ctx->dataend ) )
    return FD_BINCODE_ERR_UNDERFLOW;

  if( FD_UNLIKELY( *ptr & (~1U) ) )
    return FD_BINCODE_ERR_ENCODING;

  *self = *ptr;
  ctx->data = ptr + 1;

  return FD_BINCODE_SUCCESS;
}

static inline int
fd_bincode_bool_decode_preflight( fd_bincode_decode_ctx_t * ctx ) {

  uchar const * ptr = (uchar const *)ctx->data;
  if( FD_UNLIKELY( ptr+1 > (uchar const *)ctx->dataend ) )
    return FD_BINCODE_ERR_UNDERFLOW;

  if( FD_UNLIKELY( *ptr & (~1U) ) )
    return FD_BINCODE_ERR_ENCODING;

  ctx->data = ptr + 1;

  return FD_BINCODE_SUCCESS;
}

static inline void
fd_bincode_bool_decode_unsafe( uchar *                   self,
                               fd_bincode_decode_ctx_t * ctx ) {
  fd_bincode_uint8_decode_unsafe( self, ctx );
}

static inline int
fd_bincode_bool_encode( uchar                     self,
                        fd_bincode_encode_ctx_t * ctx ) {

  uchar * ptr = (uchar *)ctx->data;
  if ( FD_UNLIKELY( (void *)(ptr + 1) > ctx->dataend ) )
    return FD_BINCODE_ERR_OVERFLOW;

  *ptr = !!self;
  ctx->data = ptr + 1;

  return FD_BINCODE_SUCCESS;
}

static inline int
fd_bincode_bytes_decode( uchar *                   self,
                         ulong                     len,
                         fd_bincode_decode_ctx_t * ctx ) {
  uchar * ptr = (uchar *) ctx->data;
  if ( FD_UNLIKELY((ulong)( (uchar *) ctx->dataend - ptr) < len ) ) // Get wrap-around case right
    return FD_BINCODE_ERR_UNDERFLOW;

  fd_memcpy(self, ptr, len);
  ctx->data = ptr + len;

  return FD_BINCODE_SUCCESS;
}

static inline int
fd_bincode_bytes_decode_preflight( ulong                     len,
                                   fd_bincode_decode_ctx_t * ctx ) {
  uchar * ptr = (uchar *) ctx->data;
  if ( FD_UNLIKELY((ulong)( (uchar *) ctx->dataend - ptr) < len ) ) // Get wrap-around case right
    return FD_BINCODE_ERR_UNDERFLOW;

  ctx->data = ptr + len;

  return FD_BINCODE_SUCCESS;
}

static inline void
fd_bincode_bytes_decode_unsafe( uchar *                   self,
                                ulong                     len,
                                fd_bincode_decode_ctx_t * ctx ) {
  uchar * ptr = (uchar *) ctx->data;
  fd_memcpy(self, ptr, len);
  ctx->data = ptr + len;
}

static inline int
fd_bincode_bytes_encode( uchar const *             self,
                         ulong                     len,
                         fd_bincode_encode_ctx_t * ctx ) {
  uchar *ptr = (uchar *) ctx->data;
  if ( FD_UNLIKELY((void *) (ptr + len) > ctx->dataend ) )
    return FD_BINCODE_ERR_OVERFLOW;

  fd_memcpy(ptr, self, len);
  ctx->data = ptr + len;

  return FD_BINCODE_SUCCESS;
}

/* Alternate versions of fd_cu16_dec to make the function signature more consistent with the
   other fd_bincode_decode functions.  */
static inline int
fd_bincode_compact_u16_decode( ushort *                  self,
                               fd_bincode_decode_ctx_t * ctx ) {
  const uchar * ptr = (const uchar*) ctx->data;

  if( FD_LIKELY( (void *) (ptr + 1) <= ctx->dataend && !(0x80U & ptr[0]) ) ) {
    *self = (ushort)ptr[0];
    ctx->data = ptr + 1;
    return FD_BINCODE_SUCCESS;
  }

  if( FD_LIKELY( (void *) (ptr + 2) <= ctx->dataend && !(0x80U & ptr[1]) ) ) {
    if( FD_UNLIKELY( !ptr[1] ) ) /* Detect non-minimal encoding */
      return FD_BINCODE_ERR_ENCODING;
    *self = (ushort)((ulong)(ptr[0]&0x7FUL) + (((ulong)ptr[1])<<7));
    ctx->data = ptr + 2;
    return FD_BINCODE_SUCCESS;
  }

  if( FD_LIKELY( (void *) (ptr + 3) <= ctx->dataend && !(0xFCU & ptr[2]) ) ) {
    if( FD_UNLIKELY( !ptr[2] ) ) /* Detect non-minimal encoding */
      return FD_BINCODE_ERR_ENCODING;
    *self = (ushort)((ulong)(ptr[0]&0x7FUL) + (((ulong)(ptr[1]&0x7FUL))<<7) + (((ulong)ptr[2])<<14));
    ctx->data = ptr + 3;
    return FD_BINCODE_SUCCESS;
  }

  return FD_BINCODE_ERR_UNDERFLOW;
}

static inline void
fd_bincode_compact_u16_decode_unsafe( ushort *                  self,
                                      fd_bincode_decode_ctx_t * ctx ) {
  const uchar * ptr = (const uchar*) ctx->data;

  if( !(0x80U & ptr[0]) ) {
    *self = (ushort)ptr[0];
    ctx->data = ptr + 1;
    return;
  }

  if( !(0x80U & ptr[1]) ) {
    *self = (ushort)((ulong)(ptr[0]&0x7FUL) + (((ulong)ptr[1])<<7));
    ctx->data = ptr + 2;
    return;
  }

  *self = (ushort)((ulong)(ptr[0]&0x7FUL) + (((ulong)(ptr[1]&0x7FUL))<<7) + (((ulong)ptr[2])<<14));
  ctx->data = ptr + 3;
}

static inline int
fd_bincode_compact_u16_encode( ushort const *            self,
                               fd_bincode_encode_ctx_t * ctx ) {
  uchar * ptr = (uchar*) ctx->data;
  ulong val = *self;

  if ( val < 0x80UL ) {
    if ( FD_UNLIKELY((void *) (ptr + 1) > ctx->dataend ) )
      return FD_BINCODE_ERR_OVERFLOW;
    *ptr = (uchar)val;
    ctx->data = ptr + 1;
    return FD_BINCODE_SUCCESS;
  }

  else if ( val < 0x4000UL ) {
    if ( FD_UNLIKELY((void *) (ptr + 2) > ctx->dataend ) )
      return FD_BINCODE_ERR_OVERFLOW;
    ptr[0] = (uchar)((val&0x7FUL)|0x80UL);
    ptr[1] = (uchar)(val>>7);
    ctx->data = ptr + 2;
    return FD_BINCODE_SUCCESS;
  }

  else {
    if ( FD_UNLIKELY((void *) (ptr + 3) > ctx->dataend ) )
      return FD_BINCODE_ERR_OVERFLOW;
    ptr[0] = (uchar)((val&0x7FUL)|0x80UL);
    ptr[1] = (uchar)(((val>>7)&0x7FUL)|0x80UL);
    ptr[2] = (uchar)(val>>14);
    ctx->data = ptr + 3;
    return FD_BINCODE_SUCCESS;
  }
}

static inline ulong
fd_bincode_compact_u16_size( ushort const * self ) {
  ulong val = *self;

  if ( val < 0x80UL ) {
    return 1;
  }
  else if ( val < 0x4000UL ) {
    return 2;
  }
  else {
    return 3;
  }
}

/* Decodes an integer encoded using the serde_varint algorithm:
   https://github.com/solana-labs/solana/blob/master/sdk/program/src/serde_varint.rs

   A variable number of bytes could have been used to encode the integer.
   The most significant bit of each byte indicates if more bytes have been used, so we keep consuming until
   we reach a byte where the most significant bit is 0.
*/
static inline int
fd_bincode_varint_decode( ulong *                   self,
                          fd_bincode_decode_ctx_t * ctx ) {
  ulong out   = 0UL;
  uint  shift = 0U;

  while( FD_LIKELY( shift < 64U ) ) {

    if( FD_UNLIKELY( ctx->data > ctx->dataend ) )
      return FD_BINCODE_ERR_UNDERFLOW;

    uint byte = *(uchar const *)ctx->data;
    ctx->data = (uchar const *)ctx->data + 1;
    out |= (byte & 0x7FUL) << shift;

    if( (byte & 0x80U) == 0U ) {
      if( (out>>shift) != byte )
        return FD_BINCODE_ERR_ENCODING;
      if( byte==0U && (shift!=0U || out!=0UL) )
        return FD_BINCODE_ERR_ENCODING;
      *self = out;
      return FD_BINCODE_SUCCESS;
    }

    shift += 7U;

  }

  return FD_BINCODE_ERR_ENCODING;
}

static inline int
fd_bincode_varint_decode_preflight( fd_bincode_decode_ctx_t * ctx ) {
  ulong out   = 0UL;
  uint  shift = 0U;

  while( FD_LIKELY( shift < 64U ) ) {

    if( FD_UNLIKELY( ctx->data > ctx->dataend ) )
      return FD_BINCODE_ERR_UNDERFLOW;

    uint byte = *(uchar const *)ctx->data;
    ctx->data = (uchar const *)ctx->data + 1;
    out |= (byte & 0x7FUL) << shift;

    if( (byte & 0x80U) == 0U ) {
      if( (out>>shift) != byte )
        return FD_BINCODE_ERR_ENCODING;
      if( byte==0U && (shift!=0U || out!=0UL) )
        return FD_BINCODE_ERR_ENCODING;
      return FD_BINCODE_SUCCESS;
    }

    shift += 7U;

  }

  return FD_BINCODE_ERR_ENCODING;
}

static inline void
fd_bincode_varint_decode_unsafe( ulong *                   self,
                                 fd_bincode_decode_ctx_t * ctx ) {
  ulong out   = 0UL;
  uint  shift = 0U;

  for(;;) {
    uint byte = *(uchar const *)ctx->data;
    ctx->data = (uchar const *)ctx->data + 1;
    out |= (byte & 0x7FUL) << shift;

    if( (byte & 0x80U) == 0U ) {
      *self = out;
      return;
    }

    shift += 7U;
  }
}

static inline int
fd_bincode_varint_encode( ulong                     val,
                          fd_bincode_encode_ctx_t * ctx ) {
  uchar * ptr = (uchar *) ctx->data;
  while (1) {
    if ( FD_UNLIKELY((void *) (ptr + 1) > ctx->dataend ) )
      return FD_BINCODE_ERR_OVERFLOW;
    if ( val < 0x80UL ) {
      *(ptr++) = (uchar)val;
      ctx->data = ptr;
      return FD_BINCODE_SUCCESS;
    }
    *(ptr++) = (uchar)((val&0x7FUL)|0x80UL);
    val >>= 7;
  }
}

static inline ulong
fd_bincode_varint_size( ulong val ) {
  ulong sz = 0;
  while (1) {
    if ( val < 0x80UL ) {
      return sz+1;
    }
    sz++;
    val >>= 7;
  }
}


#endif /* HEADER_fd_src_util_encoders_fd_bincode_h */
