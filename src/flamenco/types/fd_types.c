// This is an auto-generated file. To add entries, edit fd_types.json
#include "fd_types.h"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#if defined(__GNUC__) && (__GNUC__ >= 9)
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif
#define SOURCE_fd_src_flamenco_types_fd_types_c
#include "fd_types_custom.h"
int fd_stake_history_entry_encode( fd_stake_history_entry_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->effective, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->activating, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->deactivating, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_stake_history_entry_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 24UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 24UL );
  return 0;
}
static void fd_stake_history_entry_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_history_entry_t * self = (fd_stake_history_entry_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->effective, ctx );
  fd_bincode_uint64_decode_unsafe( &self->activating, ctx );
  fd_bincode_uint64_decode_unsafe( &self->deactivating, ctx );
}
void * fd_stake_history_entry_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_history_entry_t * self = (fd_stake_history_entry_t *)mem;
  fd_stake_history_entry_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_stake_history_entry_t);
  void * * alloc_mem = &alloc_region;
  fd_stake_history_entry_decode_inner( mem, alloc_mem, ctx );
  return self;
}
int fd_epoch_stake_history_entry_pair_encode( fd_epoch_stake_history_entry_pair_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->epoch, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_stake_history_entry_encode( &self->entry, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_epoch_stake_history_entry_pair_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 32UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 32UL );
  return 0;
}
static void fd_epoch_stake_history_entry_pair_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_epoch_stake_history_entry_pair_t * self = (fd_epoch_stake_history_entry_pair_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->epoch, ctx );
  fd_stake_history_entry_decode_inner( &self->entry, alloc_mem, ctx );
}
void * fd_epoch_stake_history_entry_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_epoch_stake_history_entry_pair_t * self = (fd_epoch_stake_history_entry_pair_t *)mem;
  fd_epoch_stake_history_entry_pair_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_epoch_stake_history_entry_pair_t);
  void * * alloc_mem = &alloc_region;
  fd_epoch_stake_history_entry_pair_decode_inner( mem, alloc_mem, ctx );
  return self;
}
int fd_stake_history_encode( fd_stake_history_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->fd_stake_history_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( FD_UNLIKELY( 0 == self->fd_stake_history_len ) ) return FD_BINCODE_SUCCESS;
  for( ulong i=0; i<self->fd_stake_history_len; i++ ) {
    ulong idx = ( i + self->fd_stake_history_offset ) & (512 - 1);
    err = fd_epoch_stake_history_entry_pair_encode( self->fd_stake_history + idx, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_stake_history_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ulong fd_stake_history_len;
  err = fd_bincode_uint64_decode( &fd_stake_history_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( fd_stake_history_len ) {
    for( ulong i=0; i < fd_stake_history_len; i++ ) {
      err = fd_epoch_stake_history_entry_pair_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_stake_history_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_history_t);
  void const * start_data = ctx->data;
  int err = fd_stake_history_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_stake_history_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_history_t * self = (fd_stake_history_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->fd_stake_history_len, ctx );
  self->fd_stake_history_size = 512;
  self->fd_stake_history_offset = 0;
  for( ulong i=0; i<self->fd_stake_history_len; i++ ) {
    fd_epoch_stake_history_entry_pair_decode_inner( self->fd_stake_history + i, alloc_mem, ctx );
  }
}
void * fd_stake_history_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_history_t * self = (fd_stake_history_t *)mem;
  fd_stake_history_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_stake_history_t);
  void * * alloc_mem = &alloc_region;
  fd_stake_history_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_stake_history_new(fd_stake_history_t * self) {
  fd_memset( self, 0, sizeof(fd_stake_history_t) );
  self->fd_stake_history_size = 512;
  for( ulong i=0; i<512; i++ )
    fd_epoch_stake_history_entry_pair_new( self->fd_stake_history + i );
}
