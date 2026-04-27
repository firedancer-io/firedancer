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

#define FD_BINCODE_SUCCESS         (    0)
#define FD_BINCODE_ERR_UNDERFLOW   (-1001) /* Attempted to read past end of buffer */
#define FD_BINCODE_ERR_OVERFLOW    (-1002) /* Attempted to write past end of buffer */

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

#endif /* HEADER_fd_src_flamenco_types_fd_bincode_h */
