#ifndef HEADER_fd_src_util_encoders_fd_bincode_h
#define HEADER_fd_src_util_encoders_fd_bincode_h

#include "../../util/fd_util.h"
#include "../../util/valloc/fd_valloc.h"

typedef void
(* fd_types_walk_fn_t)( void *       self,
                        void const * arg,
                        char const * name,
                        int          type,
                        char const * type_name,
                        uint         level,
                        uint         varint );

typedef void
(* fd_types_walk_fn_t)( void *       self,
                        void const * arg,
                        char const * name,
                        int          type,
                        char const * type_name,
                        uint         level,
                        uint         varint );

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
  /* error code on decode */
  int err;
};
typedef struct fd_bincode_decode_ctx fd_bincode_decode_ctx_t;

#define FD_BINCODE_SUCCESS         (    0)
#define FD_BINCODE_ERR_UNDERFLOW   (-1001) /* Attempted to read past end of buffer */
#define FD_BINCODE_ERR_OVERFLOW    (-1002) /* Attempted to write past end of buffer */
#define FD_BINCODE_ERR_ENCODING    (-1003) /* Invalid encoding */

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

FD_BINCODE_PRIMITIVE_STUBS( uint8,   uchar   )
FD_BINCODE_PRIMITIVE_STUBS( uint16,  ushort  )
FD_BINCODE_PRIMITIVE_STUBS( uint32,  uint    )
FD_BINCODE_PRIMITIVE_STUBS( uint64,  ulong   )
FD_BINCODE_PRIMITIVE_STUBS( int64,   long   )
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
fd_bincode_bool_decode_footprint( fd_bincode_decode_ctx_t * ctx ) {

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
fd_bincode_bytes_decode_footprint( ulong                     len,
                                   fd_bincode_decode_ctx_t * ctx ) {
  uchar * ptr = (uchar *) ctx->data;
  if ( FD_UNLIKELY((ulong)( (uchar *) ctx->dataend - ptr) < len ) ) { // Get wrap-around case right
    return FD_BINCODE_ERR_UNDERFLOW;
  }

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
  fd_msan_check( self, len );

  uchar * ptr = (uchar *)ctx->data;
  if( FD_UNLIKELY( (void *)( ptr+len ) > ctx->dataend ) )
    return FD_BINCODE_ERR_OVERFLOW;

  fd_memcpy( ptr, self, len );
  ctx->data = ptr + len;

  return FD_BINCODE_SUCCESS;
}

/* Alternate versions of fd_cu16_dec to make the function signature more consistent with the
   other fd_bincode_decode functions.  */
static inline int
fd_bincode_compact_u16_decode( ushort *                  self,
                               fd_bincode_decode_ctx_t * ctx ) {
  const uchar * ptr = (const uchar*) ctx->data;
  if( FD_UNLIKELY( ptr==NULL ) ) {
    return FD_BINCODE_ERR_UNDERFLOW;
  }

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

    if( FD_UNLIKELY( ctx->data >= ctx->dataend ) )
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
fd_bincode_varint_decode_footprint( fd_bincode_decode_ctx_t * ctx ) {
  ulong out   = 0UL;
  uint  shift = 0U;

  while( FD_LIKELY( shift < 64U ) ) {

    if( FD_UNLIKELY( ctx->data >= ctx->dataend ) )
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

enum {
  /* All meta tags must fit in 6 bits */

  /* Primitive types with an implicit encoding length */
  FD_ARCHIVE_META_CHAR = 0x1,
  FD_ARCHIVE_META_STRING = 0x2,
  FD_ARCHIVE_META_CHAR32 = 0x3,
  FD_ARCHIVE_META_DOUBLE = 0x4,
  FD_ARCHIVE_META_LONG = 0x5,
  FD_ARCHIVE_META_UINT = 0x6,
  FD_ARCHIVE_META_UINT128 = 0x7,
  FD_ARCHIVE_META_BOOL = 0x8,
  FD_ARCHIVE_META_UCHAR = 0x9,
  FD_ARCHIVE_META_UCHAR32 = 0xa,
  FD_ARCHIVE_META_UCHAR128 = 0xb,
  FD_ARCHIVE_META_UCHAR2048 = 0xc,
  FD_ARCHIVE_META_ULONG = 0xd,
  FD_ARCHIVE_META_USHORT = 0xe,

  /* Meta types which have an encoding length after the short tag */
  FD_ARCHIVE_META_STRUCT = 0x21,
  FD_ARCHIVE_META_VECTOR = 0x22,
  FD_ARCHIVE_META_DEQUE = 0x23,
  FD_ARCHIVE_META_MAP = 0x24,
  FD_ARCHIVE_META_TREAP = 0x25,
  FD_ARCHIVE_META_OPTION = 0x26,
  FD_ARCHIVE_META_ARRAY = 0x27,
  FD_ARCHIVE_META_STATIC_VECTOR = 0x28,
};

#define FD_ARCHIVE_META_SENTINAL (ushort)0 /* End of structure */

static inline int fd_archive_encode_setup_length( fd_bincode_encode_ctx_t * ctx, void ** offset_out ) {
  uchar * ptr = (uchar *)ctx->data;
  if ( FD_UNLIKELY((void *)(ptr + sizeof(uint)) > ctx->dataend ) )
    return FD_BINCODE_ERR_OVERFLOW;
  /* Skip over length for now but make space for it */
  *offset_out = ptr;
  ctx->data = ptr + sizeof(uint);
  return FD_BINCODE_SUCCESS;
}

static inline int fd_archive_encode_set_length( fd_bincode_encode_ctx_t * ctx, void * offset ) {
  *(uint *)offset = (uint)((uchar *)ctx->data - ((uchar *)offset + sizeof(uint)));
  return FD_BINCODE_SUCCESS;
}

static inline int fd_archive_decode_setup_length( fd_bincode_decode_ctx_t * ctx, void ** offset_out ) {
  uchar * ptr = (uchar *)ctx->data;
  if ( FD_UNLIKELY((void *)(ptr + sizeof(uint)) > ctx->dataend ) )
    return FD_BINCODE_ERR_UNDERFLOW;
  /* Skip over length for now and verify it later */
  *offset_out = ptr;
  ctx->data = ptr + sizeof(uint);
  return FD_BINCODE_SUCCESS;
}

static inline int fd_archive_decode_check_length( fd_bincode_decode_ctx_t * ctx, void * offset ) {
  if( *(uint *)offset != (uint)((uchar *)ctx->data - ((uchar *)offset + sizeof(uint))) )
    return FD_BINCODE_ERR_ENCODING;
  return FD_BINCODE_SUCCESS;
}

/* Convenience API for deserializing with common allocators */

/* fd_bincode_decode_spad decodes a bincode type.  The result is
   allocated into a spad on success.  On failure, no spad allocations
   are made.

   fd_bincode_decode1_spad optionally outputs the number of bytes read
   to *psz. */

#define fd_bincode_decode1_spad( type, spad, buf, buf_sz, perr, psz )  \
  __extension__({                                                      \
    fd_spad_t *  const spad_   = (spad);                               \
    void const * const buf_    = (buf);                                \
    ulong        const buf_sz_ = (buf_sz);                             \
    int *              perr_   = (perr);                               \
    ulong *            psz_    = (psz);                                \
    fd_bincode_decode_ctx_t ctx = {0};                                 \
    if( perr_ ) *perr_ = -1;                                           \
    ctx.data    = (void const *)( buf_ );                              \
    ctx.dataend = (void const *)( (ulong)ctx.data + buf_sz_ );         \
    ulong total_sz = 0UL;                                              \
    int err = fd_##type##_decode_footprint( &ctx, &total_sz );         \
    fd_##type##_t * out = NULL;                                        \
    if( FD_LIKELY( err==FD_BINCODE_SUCCESS ) ) {                       \
      ulong align = fd_##type##_align();                               \
      void * mem = fd_spad_alloc( spad_, align, total_sz );            \
      if( FD_UNLIKELY( !mem ) ) {                                      \
        FD_LOG_ERR(( "fd_bincode_" #type "_decode failed: out of memory (decode requires %lu+%lu bytes, but only %lu bytes free in spad)", align-1UL, total_sz, fd_spad_mem_free( spad_ ) )); \
      }                                                                \
      out = fd_##type##_decode( mem, &ctx );                           \
      if( FD_UNLIKELY ( ctx.err != FD_BINCODE_SUCCESS ) ) err = ctx.err; \
      if( psz_ ) *psz_ = (ulong)ctx.data - (ulong)buf_;                \
    }                                                                  \
    if( perr_ ) *perr_ = err;                                          \
    out;                                                               \
  })

#define fd_bincode_decode1_spad_global( type, spad, buf, buf_sz, perr, psz )  \
  __extension__({                                                             \
    fd_spad_t *  const spad_   = (spad);                                      \
    void const * const buf_    = (buf);                                       \
    ulong        const buf_sz_ = (buf_sz);                                    \
    int *              perr_   = (perr);                                      \
    ulong *            psz_    = (psz);                                       \
    fd_bincode_decode_ctx_t ctx = {0};                                        \
    if( perr_ ) *perr_ = -1;                                                  \
    ctx.data    = (void const *)( buf_ );                                     \
    ctx.dataend = (void const *)( (ulong)ctx.data + buf_sz_ );                \
    ulong total_sz = 0UL;                                                     \
    int err = fd_##type##_decode_footprint( &ctx, &total_sz );                \
    fd_##type##_global_t * out = NULL;                                        \
    if( FD_LIKELY( err==FD_BINCODE_SUCCESS ) ) {                              \
      ulong align = fd_##type##_align();                                      \
      void * mem = fd_spad_alloc( spad_, align, total_sz );                   \
      if( FD_UNLIKELY( !mem ) ) {                                             \
        FD_LOG_ERR(( "fd_bincode_" #type "_decode failed: out of memory (decode requires %lu+%lu bytes, but only %lu bytes free in spad)", align-1UL, total_sz, fd_spad_mem_free( spad_ ) )); \
      }                                                                       \
      out = fd_##type##_decode_global( mem, &ctx );                           \
      if( FD_UNLIKELY ( ctx.err != FD_BINCODE_SUCCESS ) ) err = ctx.err;     \
      if( psz_ ) *psz_ = (ulong)ctx.data - (ulong)buf_;                       \
    }                                                                         \
    if( perr_ ) *perr_ = err;                                                 \
    out;                                                                      \
  })

#define fd_bincode_decode_spad( type, spad, buf, buf_sz, perr ) \
  fd_bincode_decode1_spad( type, spad, buf, buf_sz, perr, NULL )

#define fd_bincode_decode_spad_global( type, spad, buf, buf_sz, perr ) \
  fd_bincode_decode1_spad_global( type, spad, buf, buf_sz, perr, NULL )

/* fd_bincode_decode_scratch decodes a bincode type.  The result is
   allocated into the thread's scratch region on success.  On failure,
   no allocations are made. */

#define fd_bincode_decode1_scratch( type, buf, buf_sz, perr, psz )     \
  __extension__({                                                      \
    void const * const buf_    = (buf);                                \
    ulong        const buf_sz_ = (buf_sz);                             \
    int *              perr_   = (perr);                               \
    ulong *            psz_    = (psz);                                \
    fd_bincode_decode_ctx_t ctx = {0};                                 \
    if( perr_ ) *perr_ = -1;                                           \
    ctx.data    = (void const *)( buf_ );                              \
    ctx.dataend = (void const *)( (ulong)ctx.data + buf_sz_ );         \
    ulong total_sz = 0UL;                                              \
    int err = fd_##type##_decode_footprint( &ctx, &total_sz );         \
    fd_##type##_t * out = NULL;                                        \
    if( FD_LIKELY( err==FD_BINCODE_SUCCESS ) ) {                       \
      ulong align = fd_##type##_align();                               \
      if( FD_UNLIKELY( !fd_scratch_alloc_is_safe( align, total_sz ) ) ) { \
        FD_LOG_ERR(( "fd_bincode_" #type "_decode failed: out of memory (decode requires %lu+%lu bytes, but only %lu bytes free in scratch region)", align-1UL, total_sz, fd_scratch_free() )); \
      }                                                                \
      void * mem = fd_scratch_alloc( align, total_sz );                \
      out = fd_##type##_decode( mem, &ctx );                           \
      if( FD_UNLIKELY ( ctx.err != FD_BINCODE_SUCCESS ) ) err = ctx.err; \
      if( psz_ ) *psz_ = (ulong)ctx.data - (ulong)buf_;                \
    }                                                                  \
    if( perr_ ) *perr_ = err;                                          \
    out;                                                               \
  })

#define fd_bincode_decode_scratch( type, buf, buf_sz, perr ) \
  fd_bincode_decode1_scratch( type, buf, buf_sz, perr, NULL )

#endif /* HEADER_fd_src_util_encoders_fd_bincode_h */
