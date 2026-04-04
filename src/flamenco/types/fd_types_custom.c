#include "fd_types_custom.h"
#include "fd_bincode.h"
#include "fd_types.h"
#ifndef SOURCE_fd_src_flamenco_types_fd_types_c
#error "fd_types_custom.c is part of the fd_types.c compile uint"
#endif /* !SOURCE_fd_src_flamenco_types_fd_types_c */

// https://github.com/serde-rs/serde/blob/49d098debdf8b5c38bfb6868f455c6ce542c422c/serde/src/de/impls.rs#L2374
//
// During the call to Duration::new(...), it normalizes the seconds and nanoseconds automatically.  We need to
// match this behavior correctly
//
void
fd_rust_duration_normalize ( fd_rust_duration_t * self ) {
  if( self->nanoseconds < 1000000000U )
    return;
  uint secs = self->nanoseconds/1000000000U;
  self->seconds += secs;
  self->nanoseconds -= secs * 1000000000U;
}

// https://github.com/serde-rs/serde/blob/49d098debdf8b5c38bfb6868f455c6ce542c422c/serde/src/de/impls.rs#L2203
//
// There is an overflow check at line 2373 that turns an overflow into an encoding error
//
int
fd_rust_duration_footprint_validator ( fd_bincode_decode_ctx_t * ctx ) {
  if( (ulong)ctx->data + ( sizeof(ulong) + sizeof(uint) ) > (ulong)ctx->dataend )
    return FD_BINCODE_ERR_OVERFLOW;

  ulong seconds    = FD_LOAD( ulong, ctx->data );
  uint nanoseconds = FD_LOAD( uint, (uchar*)ctx->data + sizeof(ulong) );

  if( nanoseconds < 1000000000U )
    return FD_BINCODE_SUCCESS;
  ulong out;
  if( __builtin_uaddl_overflow( seconds, nanoseconds/1000000000U, &out ) )
    return FD_BINCODE_ERR_ENCODING;
  return FD_BINCODE_SUCCESS;
}
