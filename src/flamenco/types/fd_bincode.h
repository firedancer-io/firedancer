#ifndef HEADER_fd_src_flamenco_types_fd_bincode_h
#define HEADER_fd_src_flamenco_types_fd_bincode_h

#include "../../util/fd_util.h"

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
  void const * data;
  /* End of buffer */
  void const * dataend;
};
typedef struct fd_bincode_decode_ctx fd_bincode_decode_ctx_t;

#define FD_BINCODE_SUCCESS         (    0)
#define FD_BINCODE_ERR_UNDERFLOW   (-1001) /* Attempted to read past end of buffer */
#define FD_BINCODE_ERR_OVERFLOW    (-1002) /* Attempted to write past end of buffer */

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
  fd_bincode_##name##_decode_footprint( fd_bincode_decode_ctx_t * ctx ) { \
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
    memcpy( ptr, &self, sizeof(type) );  /* unaligned */ \
    ctx->data = ptr + sizeof(type); \
    return FD_BINCODE_SUCCESS; \
  }

/* fd_w_u128 is a wrapped "uint128" type providing basic 128-bit
   unsigned int functionality to fd_types, even if the compile target
   does not natively support uint128. */

union __attribute__((packed)) fd_w_u128 {
  uchar uc[16];
  ulong ul[2];
# if FD_HAS_INT128
  uint128 ud;
# endif
};

typedef union fd_w_u128 fd_w_u128_t;

FD_BINCODE_PRIMITIVE_STUBS( uint64,  ulong       )

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

/* Convenience API for deserializing */

/* fd_bincode_decode_static decodes a statically-sized bincode type.

   Example usage:

   fd_epoch_schedule_t es[1];
   if( FD_UNLIKELY( fd_bincode_decode_static( epoch_schedule, es, buf, bufsz ) ) ) {
     ... parse fail ...
     return;
   }
   ... parse success ... */

#define fd_bincode_decode_static1( type, suffix, out, buf, buf_sz )    \
  __extension__({                                                      \
    void const * const buf_    = (buf);                                \
    ulong        const buf_sz_ = (buf_sz);                             \
    fd_##type##suffix##_t *    res     = NULL;                         \
    fd_bincode_decode_ctx_t ctx = {0};                                 \
    ctx.data    = (void const *)( buf_ );                              \
    ctx.dataend = (void const *)( (ulong)ctx.data + buf_sz_ );         \
    ulong total_sz = 0UL;                                              \
    int err = fd_##type##_decode_footprint( &ctx, &total_sz );         \
    if( FD_LIKELY( err==FD_BINCODE_SUCCESS ) ) {                       \
      res = fd_##type##_decode##suffix( (out), &ctx );                 \
    }                                                                  \
    res;                                                               \
  })

#define fd_bincode_decode_static( t,o,b,s ) \
  fd_bincode_decode_static1( t, , o, b, s )

#endif /* HEADER_fd_src_flamenco_types_fd_bincode_h */
