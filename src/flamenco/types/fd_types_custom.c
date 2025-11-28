#include "fd_types_custom.h"
#include "fd_bincode.h"
#include "fd_types.h"
#include "fd_types_meta.h"
#ifndef SOURCE_fd_src_flamenco_types_fd_types_c
#error "fd_types_custom.c is part of the fd_types.c compile uint"
#endif /* !SOURCE_fd_src_flamenco_types_fd_types_c */

#include <stdio.h>

int fd_tower_sync_encode( fd_tower_sync_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  FD_LOG_ERR(( "todo"));
}

static void fd_hash_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx );
static int fd_hash_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
static void fd_lockout_offset_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx );
static int fd_lockout_offset_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );

int fd_tower_sync_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  /* This is a modified version of fd_compact_tower_sync_decode_footprint_inner() */
  int err = 0;
  if( FD_UNLIKELY( ctx->data>ctx->dataend ) ) { return FD_BINCODE_ERR_OVERFLOW; }
  err = fd_bincode_uint64_decode_footprint( ctx );

  /* The first modification is that we want to grab the value fo the root. */
  ulong root = 0UL;
  fd_bincode_decode_ctx_t root_ctx = { .data = (uchar*)ctx->data - sizeof(ulong), .dataend = ctx->data };
  if( FD_UNLIKELY( ((ulong)ctx->data)+sizeof(ulong)>(ulong)ctx->dataend ) ) { return FD_BINCODE_ERR_OVERFLOW; }
  fd_bincode_uint64_decode_unsafe( &root, &root_ctx );
  root = root != ULONG_MAX ? root : 0UL;
  /* Done with first modification */

  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ushort lockout_offsets_len;
  if( FD_UNLIKELY( ctx->data>=ctx->dataend ) ) { return FD_BINCODE_ERR_OVERFLOW; }
  err = fd_bincode_compact_u16_decode( &lockout_offsets_len, ctx );

  if( FD_UNLIKELY( err ) ) return err;
  ulong lockout_offsets_max = fd_ulong_max( lockout_offsets_len, 32 );
  *total_sz += deq_fd_lockout_offset_t_align() + deq_fd_lockout_offset_t_footprint( lockout_offsets_max );

  for( ulong i = 0; i < lockout_offsets_len; ++i ) {

    uchar const * start_data = ctx->data;
    err = fd_lockout_offset_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;

    /* The second modification is that we want to grab the lockout offset from
    the deque to make sure that we can do a checked add successfully. */
    fd_lockout_offset_t lockout_offset = {0};
    fd_bincode_decode_ctx_t lockout_ctx = { .data = start_data, .dataend = start_data+sizeof(fd_lockout_offset_t) };
    if( FD_UNLIKELY( ctx->data>=ctx->dataend ) ) { return FD_BINCODE_ERR_OVERFLOW; }
    fd_lockout_offset_decode_inner( &lockout_offset, NULL, &lockout_ctx );
    err = __builtin_uaddl_overflow( root, lockout_offset.offset, &root );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }
    /* Done with second modification. */
  }

  if( FD_UNLIKELY( ctx->data>=ctx->dataend ) ) { return FD_BINCODE_ERR_OVERFLOW; }
  err = fd_hash_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  {
    uchar o;
    if( FD_UNLIKELY( ctx->data>=ctx->dataend ) ) { return FD_BINCODE_ERR_OVERFLOW; }
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      if( FD_UNLIKELY( ctx->data>=ctx->dataend ) ) { return FD_BINCODE_ERR_OVERFLOW; }
      err = fd_bincode_int64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  if( FD_UNLIKELY( ctx->data>=ctx->dataend ) ) { return FD_BINCODE_ERR_OVERFLOW; }
  err = fd_hash_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}

int fd_tower_sync_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_tower_sync_t);
  void const * start_data = ctx->data;
  int err = fd_tower_sync_decode_footprint_inner( ctx, total_sz );
  ctx->data = start_data;
  return err;
}

void fd_tower_sync_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_tower_sync_t * self = (fd_tower_sync_t *)struct_mem;
  self->has_root = 1;
  fd_bincode_uint64_decode_unsafe( &self->root, ctx );
  self->has_root = self->root != ULONG_MAX;

  ushort lockout_offsets_len;
  fd_bincode_compact_u16_decode_unsafe( &lockout_offsets_len, ctx );
  ulong lockout_offsets_max = fd_ulong_max( lockout_offsets_len, 32 );
  self->lockouts = deq_fd_vote_lockout_t_join_new( alloc_mem, lockout_offsets_max );

  /* NOTE: Agave does a a checked add on the sum of the root with all of the
     lockout offsets in their custom deserializer for tower sync votes. If the
     checked add is violated (this should never happen), the deocder will
     return NULL.  */

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L1062-L1077
  ulong last_slot = ((self->root == ULONG_MAX) ? 0 : self->root);
  for( ulong i=0; i < lockout_offsets_len; i++ ) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy( self->lockouts );

    fd_lockout_offset_t o;
    fd_lockout_offset_decode_inner( &o, alloc_mem, ctx );

    elem->slot = last_slot + o.offset;
    elem->confirmation_count = o.confirmation_count;
    last_slot = elem->slot;
  }

  fd_hash_decode_inner( &self->hash, alloc_mem, ctx );
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_timestamp = !!o;
    if( o ) {
      fd_bincode_int64_decode_unsafe( &self->timestamp, ctx );
    }
  }
  fd_hash_decode_inner( &self->block_id, alloc_mem, ctx );
}

void * fd_tower_sync_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_tower_sync_t * self = (fd_tower_sync_t *)mem;
  fd_tower_sync_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_tower_sync_t);
  void * * alloc_mem = &alloc_region;
  fd_tower_sync_decode_inner( mem, alloc_mem, ctx );
  return self;
}

void fd_tower_sync_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  FD_LOG_ERR(("TODO: Implement"));
}

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
