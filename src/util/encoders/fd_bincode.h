#ifndef HEADER_fd_src_util_encoders_fd_bincode_h
#define HEADER_fd_src_util_encoders_fd_bincode_h

#include "../bits/fd_bits.h"
#include "../fd_util.h"
#include "../../ballet/txn/fd_compact_u16.h"

#include <immintrin.h>

static inline
void fd_bincode_uint128_decode(uint128* self, void const** data, void const* dataend) {
  const uint128 *ptr = (const uint128 *) *data;
  if (FD_UNLIKELY((void const *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }

#if FD_HAS_INT128 && FD_HAS_SSE
  *self = (uint128) _mm_loadu_si128((void const *) ptr);
#else
  memcpy(self, ptr, sizeof(uint128));
#endif
  *data = ptr + 1;
}

static inline
void fd_bincode_uint128_encode(uint128* self, void const** data) {
  uint128 *ptr = (uint128 *) *data;
#if FD_HAS_INT128 && FD_HAS_SSE
  _mm_storeu_si128((__m128i *) ptr, (__m128i) *self);
#else
  memcpy(ptr, *self, sizeof(uint128));
#endif
  *data = ptr + 1;
}

static inline
void fd_bincode_uint64_decode(ulong* self, void const** data, void const* dataend) {
  const ulong *ptr = (const ulong *) *data;
  if (FD_UNLIKELY((void const *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

static inline
void fd_bincode_uint64_encode(ulong* self, void const** data) {
  ulong *ptr = (ulong *) *data;
  *ptr = *self;
  *data = ptr + 1;
}

static inline
void fd_bincode_double_decode(double* self, void const** data, void const* dataend) {
  const double *ptr = (const double *) *data;
  if (FD_UNLIKELY((void const *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

static inline
void fd_bincode_double_encode(double* self, void const** data) {
  double *ptr = (double *) *data;
  *ptr = *self;
  *data = ptr + 1;
}

static inline
void fd_bincode_uint32_decode(unsigned int* self, void const** data, void const* dataend) {
  const unsigned int *ptr = (const unsigned int *) *data;
  if (FD_UNLIKELY((void const *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

static inline
void fd_bincode_uint32_encode(unsigned int* self, void const** data) {
  unsigned int *ptr = (unsigned int *) *data;
  *ptr = *self;
  *data = ptr + 1;
}

static inline
void fd_bincode_uint16_decode(ushort* self, void const** data, void const* dataend) {
  const ushort *ptr = (const ushort *) *data;
  if (FD_UNLIKELY((void const *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

static inline
void fd_bincode_uint16_encode(ushort* self, void const** data) {
  ushort *ptr = (ushort *) *data;
  *ptr = *self;
  *data = ptr + 1;
}

static inline
void fd_bincode_uint8_decode(unsigned char* self, void const** data, void const* dataend) {
  const unsigned char *ptr = (const unsigned char *) *data;
  if (FD_UNLIKELY((void const *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  *self = *ptr;
  *data = ptr + 1;
}

static inline
void fd_bincode_uint8_encode(unsigned char* self, void const** data) {
  unsigned char *ptr = (unsigned char *) *data;
  *ptr = *self;
  *data = ptr + 1;
}

static inline
void fd_bincode_bytes_decode(unsigned char* self, ulong len, void const** data, void const* dataend) {
  unsigned char *ptr = (unsigned char *) *data;
  if (FD_UNLIKELY((void *) (ptr + len) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  memcpy(self, ptr, len); // what is the FD way?
  *data = ptr + len;
}

static inline
void fd_bincode_bytes_encode(unsigned char* self, ulong len, void const** data) {
  unsigned char *ptr = (unsigned char *) *data;
  memcpy(ptr, self, len);
  *data = ptr + len;
}

static inline
unsigned char fd_bincode_option_decode(void const** data, void const* dataend) {
  unsigned char *ptr = (unsigned char *) *data;
  if (FD_UNLIKELY((void *) (ptr + 1) > dataend )) {
    FD_LOG_ERR(( "buffer underflow"));
  }
  unsigned char ret = *ptr;
  *data = ptr + 1;
  return ret;
}

static inline
void fd_bincode_option_encode(unsigned char val, void const** data) {
  unsigned char *ptr = (unsigned char *) *data;
  *ptr = val;
  *data = ptr + 1;
}

/* Wrapper around fd_cu16_dec, to make the function signature more consistent with the
   other fd_bincode_decode functions.  */
static inline
ulong fd_decode_short_u16( ushort* self, void const** data, FD_FN_UNUSED void const* dataend ) {
  const uchar *ptr = (const uchar*) *data;

  ulong size = fd_cu16_dec( (uchar const *)*data, 3, self );
  if ( size == 0 ) {
    FD_LOG_ERR(( "failed to decode short u16" ));
  }
  *data = ptr + size;

  return size;

}

static inline
void fd_encode_short_u16( ushort* self, void ** data) {
  uchar *ptr = (uchar*) *data;

  ulong size = fd_cu16_enc (*self, (uchar *)*data );
  if ( size == 0 ) {
    FD_LOG_ERR(( "failed to encode short u16" ));
  }
  *data = ptr + size;
}

/* Decodes an integer encoded using the serde_varint algorithm:
   https://github.com/solana-labs/solana/blob/master/sdk/program/src/serde_varint.rs 
   
   A variable number of bytes could have been used to encode the integer.
   The most significant bit of each byte indicates if more bytes have been used, so we keep consuming until
   we reach a byte where the most significant bit is 0.
*/
void fd_decode_varint( ulong* self, void const** data, void const* dataend );

static inline void
fd_encode_varint( ulong val, uchar ** out ) {
  uchar *ptr = *out;
  ulong _i = val;
  while( 1 ) {
    *ptr = _i&0x7F;
    _i >>= 7;
    if( _i ) 
      *(ptr++) |= 0x80;
    else {
      *out = ++ptr;
      return;
    }
  }
}


#endif /* HEADER_fd_src_util_encoders_fd_bincode_h */
