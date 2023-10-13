#ifndef HEADER_fd_src_util_encoders_fd_bincode_h
#define HEADER_fd_src_util_encoders_fd_bincode_h

#include "../../util/fd_util.h"

/* Context argument used for encoding */
struct fd_bincode_encode_ctx {
  /* Current position in data buffer */
  void * data;
  /* End of buffer */
  void * dataend;
};
typedef struct fd_bincode_encode_ctx fd_bincode_encode_ctx_t;

/* Generic allocator prototype */
typedef char * (*fd_alloc_fun_t)(void * arg, ulong align, ulong len);
/* Generic deallocator prototype */
typedef void   (*fd_free_fun_t) (void * arg, void * ptr);

/* Context argument used for decoding */
struct fd_bincode_decode_ctx {
  /* Current position in data buffer */
  void const *   data;
  /* End of buffer */
  void const *   dataend;
  /* Allocator for dynamic memory */
  fd_alloc_fun_t allocf;
  void *         allocf_arg;
};
typedef struct fd_bincode_decode_ctx fd_bincode_decode_ctx_t;

/* Context argument used for calling "destroy" on a structure */
struct fd_bincode_destroy_ctx {
  /* Allocator for dynamic memory */
  fd_free_fun_t freef;
  void *        freef_arg;
};
typedef struct fd_bincode_destroy_ctx fd_bincode_destroy_ctx_t;

#define FD_BINCODE_SUCCESS 0
#define FD_BINCODE_ERR_UNDERFLOW -1 /* Attempted to read past end of buffer */
#define FD_BINCODE_ERR_OVERFLOW -2  /* Attempted to write past end of buffer */
#define FD_BINCODE_ERR_ENCODING -3  /* Invalid encoding */
#define FD_BINCODE_ERR_SMALL_DEQUE -4 /* deque max size is too small */
#define FD_BINCODE_ERR_ALLOC -5

static inline int
fd_bincode_uint128_decode(uint128 * self, fd_bincode_decode_ctx_t * ctx) {
  const uint128 * ptr = (const uint128 *) ctx->data;
  if ( FD_UNLIKELY((void const *) (ptr + 1) > ctx->dataend ) )
    return FD_BINCODE_ERR_UNDERFLOW;

  memcpy( self, ptr, sizeof(uint128) ); /* Do direct assignment (especially if ptr is aligned 16)? */
  ctx->data = ptr + 1;

  return FD_BINCODE_SUCCESS;
}

static inline int
fd_bincode_uint128_encode(uint128 const * self, fd_bincode_encode_ctx_t * ctx) {
  uint128 * ptr = (uint128 *) ctx->data;
  if ( FD_UNLIKELY((void const *) (ptr + 1) > ctx->dataend ) )
    return FD_BINCODE_ERR_OVERFLOW;

  memcpy( ptr, self, sizeof(uint128) ); /* Do direct assignment (especially if ptr is aligned 16)? */
  ctx->data = ptr + 1;

  return FD_BINCODE_SUCCESS;
}

static inline int
fd_bincode_uint64_decode( ulong *                   self,
                          fd_bincode_decode_ctx_t * ctx ) {
  const ulong *ptr = (const ulong *) ctx->data;
  if ( FD_UNLIKELY((void const *) (ptr + 1) > ctx->dataend ) )
    return FD_BINCODE_ERR_UNDERFLOW;

  *self = *ptr;
  ctx->data = ptr + 1;

  return FD_BINCODE_SUCCESS;
}

static inline int
fd_bincode_uint64_encode( ulong const *             self,
                          fd_bincode_encode_ctx_t * ctx ) {
  ulong * ptr = (ulong *) ctx->data;
  if ( FD_UNLIKELY((void const *) (ptr + 1) > ctx->dataend ) )
    return FD_BINCODE_ERR_OVERFLOW;

  *ptr = *self;
  ctx->data = ptr + 1;

  return FD_BINCODE_SUCCESS;
}

static inline int
fd_bincode_double_decode( double *                  self,
                          fd_bincode_decode_ctx_t * ctx ) {
  const double * ptr = (const double *) ctx->data;
  if ( FD_UNLIKELY((void const *) (ptr + 1) > ctx->dataend ) )
    return FD_BINCODE_ERR_UNDERFLOW;

  *self = *ptr;
  ctx->data = ptr + 1;

  return FD_BINCODE_SUCCESS;
}

static inline int
fd_bincode_double_encode( double const *            self,
                          fd_bincode_encode_ctx_t * ctx ) {
  double * ptr = (double *) ctx->data;
  if ( FD_UNLIKELY((void const *) (ptr + 1) > ctx->dataend ) )
    return FD_BINCODE_ERR_OVERFLOW;

  *ptr = *self;
  ctx->data = ptr + 1;

  return FD_BINCODE_SUCCESS;
}

static inline int
fd_bincode_uint32_decode( uint *                    self,
                          fd_bincode_decode_ctx_t * ctx ) {
  uint const * ptr = (uint const *) ctx->data;
  if ( FD_UNLIKELY((void const *) (ptr + 1) > ctx->dataend ) )
    return FD_BINCODE_ERR_UNDERFLOW;

  *self = *ptr;
  ctx->data = ptr + 1;

  return FD_BINCODE_SUCCESS;
}

static inline int
fd_bincode_uint32_encode( uint const *              self,
                          fd_bincode_encode_ctx_t * ctx ) {
  unsigned int * ptr = (unsigned int *) ctx->data;
  if ( FD_UNLIKELY((void const *) (ptr + 1) > ctx->dataend ) )
    return FD_BINCODE_ERR_OVERFLOW;

  *ptr = *self;
  ctx->data = ptr + 1;

  return FD_BINCODE_SUCCESS;
}

static inline int
fd_bincode_uint16_decode( ushort *                  self,
                          fd_bincode_decode_ctx_t * ctx ) {
  const ushort * ptr = (const ushort *) ctx->data;
  if ( FD_UNLIKELY((void const *) (ptr + 1) > ctx->dataend ) )
    return FD_BINCODE_ERR_UNDERFLOW;

  *self = *ptr;
  ctx->data = ptr + 1;

  return FD_BINCODE_SUCCESS;
}

static inline int
fd_bincode_uint16_encode( ushort const *            self,
                          fd_bincode_encode_ctx_t * ctx ) {
  ushort * ptr = (ushort *) ctx->data;
  if ( FD_UNLIKELY((void const *) (ptr + 1) > ctx->dataend ) )
    return FD_BINCODE_ERR_OVERFLOW;

  *ptr = *self;
  ctx->data = ptr + 1;

  return FD_BINCODE_SUCCESS;
}

static inline int
fd_bincode_uint8_decode( uchar *                   self,
                         fd_bincode_decode_ctx_t * ctx ) {
  uchar const * ptr = (uchar const *) ctx->data;
  if ( FD_UNLIKELY((void const *) (ptr + 1) > ctx->dataend ) )
    return FD_BINCODE_ERR_UNDERFLOW;

  *self = *ptr;
  ctx->data = ptr + 1;

  return FD_BINCODE_SUCCESS;
}

static inline int
fd_bincode_uint8_encode( uchar const *             self,
                         fd_bincode_encode_ctx_t * ctx ) {
  uchar * ptr = (uchar *) ctx->data;
  if ( FD_UNLIKELY((void const *) (ptr + 1) > ctx->dataend ) )
    return FD_BINCODE_ERR_OVERFLOW;

  *ptr = *self;
  ctx->data = ptr + 1;

  return FD_BINCODE_SUCCESS;
}

static inline int
fd_bincode_bytes_decode( uchar *                   self,
                         ulong                     len,
                         fd_bincode_decode_ctx_t * ctx ) {
  uchar * ptr = (uchar *) ctx->data;
  if ( FD_UNLIKELY((void *) (ptr + len) > ctx->dataend ) )
    return FD_BINCODE_ERR_UNDERFLOW;

  fd_memcpy(self, ptr, len);
  ctx->data = ptr + len;

  return FD_BINCODE_SUCCESS;
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

static inline int
fd_bincode_option_decode( uchar *                   self,
                          fd_bincode_decode_ctx_t * ctx ) {
  uchar * ptr = (uchar *) ctx->data;
  if ( FD_UNLIKELY((void *) (ptr + 1) > ctx->dataend ) )
    return FD_BINCODE_ERR_UNDERFLOW;

  *self = *ptr;
  ctx->data = ptr + 1;

  return FD_BINCODE_SUCCESS;
}

static inline int
fd_bincode_option_encode( uchar                     self,
                          fd_bincode_encode_ctx_t * ctx ) {
  uchar * ptr = (uchar *) ctx->data;
  if ( FD_UNLIKELY((void *) (ptr + 1) > ctx->dataend ) )
    return FD_BINCODE_ERR_OVERFLOW;

  *ptr = self;
  ctx->data = ptr + 1;

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

/* Decodes an integer encoded using the serde_varint algorithm:
   https://github.com/solana-labs/solana/blob/master/sdk/program/src/serde_varint.rs

   A variable number of bytes could have been used to encode the integer.
   The most significant bit of each byte indicates if more bytes have been used, so we keep consuming until
   we reach a byte where the most significant bit is 0.
*/
static inline int
fd_bincode_varint_decode( ulong *                   self,
                          fd_bincode_decode_ctx_t * ctx ) {
  const uchar * ptr = (const uchar*) ctx->data;
  ulong val = 0;
  ulong shift = 0;
  while (1) {
    if ( FD_UNLIKELY((void *) (ptr + 1) > ctx->dataend ) )
      return FD_BINCODE_ERR_UNDERFLOW;
    ulong c = *(ptr++);
    val += (c&0x7FUL)<<shift;
    if ( !(c&0x80UL) ) {
      *self = val;
      ctx->data = ptr;
      return FD_BINCODE_SUCCESS;
    }
    shift += 7;
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


#endif /* HEADER_fd_src_util_encoders_fd_bincode_h */
