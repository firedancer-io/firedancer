// This is an auto-generated file. To add entries, edit fd_types.json
#include "fd_types.h"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-variable"
#define SOURCE_fd_src_flamenco_types_fd_types_c
#include "fd_types_custom.c"
int fd_hash_decode(fd_hash_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_hash_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_hash_new(self);
  fd_hash_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_hash_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  return fd_bincode_bytes_decode_preflight( sizeof(fd_hash_t), ctx );
}
void fd_hash_decode_unsafe(fd_hash_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_bytes_decode_unsafe( (uchar*)self, sizeof(fd_hash_t), ctx );
}
void fd_hash_new(fd_hash_t* self) { }
void fd_hash_destroy(fd_hash_t* self, fd_bincode_destroy_ctx_t * ctx) { }
ulong fd_hash_footprint( void ){ return sizeof(fd_hash_t); }
ulong fd_hash_align( void ){ return alignof(fd_hash_t); }
ulong fd_hash_size(fd_hash_t const * self) { (void)self; return sizeof(fd_hash_t); }
int fd_hash_encode(fd_hash_t const * self, fd_bincode_encode_ctx_t * ctx) {
  return fd_bincode_bytes_encode( (uchar const *)self, sizeof(fd_hash_t), ctx );
}
void fd_hash_walk(void * w, fd_hash_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun( w, (uchar const*)self, name, FD_FLAMENCO_TYPE_HASH256, name, level );
}

int fd_signature_decode(fd_signature_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_signature_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_signature_new(self);
  fd_signature_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_signature_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  return fd_bincode_bytes_decode_preflight( sizeof(fd_signature_t), ctx );
}
void fd_signature_decode_unsafe(fd_signature_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_bytes_decode_unsafe( (uchar*)self, sizeof(fd_signature_t), ctx );
}
void fd_signature_new(fd_signature_t* self) { }
void fd_signature_destroy(fd_signature_t* self, fd_bincode_destroy_ctx_t * ctx) { }
ulong fd_signature_footprint( void ){ return sizeof(fd_signature_t); }
ulong fd_signature_align( void ){ return alignof(fd_signature_t); }
ulong fd_signature_size(fd_signature_t const * self) { (void)self; return sizeof(fd_signature_t); }
int fd_signature_encode(fd_signature_t const * self, fd_bincode_encode_ctx_t * ctx) {
  return fd_bincode_bytes_encode( (uchar const *)self, sizeof(fd_signature_t), ctx );
}
void fd_signature_walk(void * w, fd_signature_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun( w, (uchar const*)self, name, FD_FLAMENCO_TYPE_SIG512, name, level );
}

int fd_gossip_ip4_addr_decode(fd_gossip_ip4_addr_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_ip4_addr_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_ip4_addr_new(self);
  fd_gossip_ip4_addr_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_ip4_addr_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  return fd_bincode_bytes_decode_preflight( sizeof(fd_gossip_ip4_addr_t), ctx );
}
void fd_gossip_ip4_addr_decode_unsafe(fd_gossip_ip4_addr_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_bytes_decode_unsafe( (uchar*)self, sizeof(fd_gossip_ip4_addr_t), ctx );
}
void fd_gossip_ip4_addr_new(fd_gossip_ip4_addr_t* self) { }
void fd_gossip_ip4_addr_destroy(fd_gossip_ip4_addr_t* self, fd_bincode_destroy_ctx_t * ctx) { }
ulong fd_gossip_ip4_addr_footprint( void ){ return sizeof(fd_gossip_ip4_addr_t); }
ulong fd_gossip_ip4_addr_align( void ){ return alignof(fd_gossip_ip4_addr_t); }
ulong fd_gossip_ip4_addr_size(fd_gossip_ip4_addr_t const * self) { (void)self; return sizeof(fd_gossip_ip4_addr_t); }
int fd_gossip_ip4_addr_encode(fd_gossip_ip4_addr_t const * self, fd_bincode_encode_ctx_t * ctx) {
  return fd_bincode_bytes_encode( (uchar const *)self, sizeof(fd_gossip_ip4_addr_t), ctx );
}

int fd_gossip_ip6_addr_decode(fd_gossip_ip6_addr_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_ip6_addr_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_ip6_addr_new(self);
  fd_gossip_ip6_addr_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_ip6_addr_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  return fd_bincode_bytes_decode_preflight( sizeof(fd_gossip_ip6_addr_t), ctx );
}
void fd_gossip_ip6_addr_decode_unsafe(fd_gossip_ip6_addr_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_bytes_decode_unsafe( (uchar*)self, sizeof(fd_gossip_ip6_addr_t), ctx );
}
void fd_gossip_ip6_addr_new(fd_gossip_ip6_addr_t* self) { }
void fd_gossip_ip6_addr_destroy(fd_gossip_ip6_addr_t* self, fd_bincode_destroy_ctx_t * ctx) { }
ulong fd_gossip_ip6_addr_footprint( void ){ return sizeof(fd_gossip_ip6_addr_t); }
ulong fd_gossip_ip6_addr_align( void ){ return alignof(fd_gossip_ip6_addr_t); }
ulong fd_gossip_ip6_addr_size(fd_gossip_ip6_addr_t const * self) { (void)self; return sizeof(fd_gossip_ip6_addr_t); }
int fd_gossip_ip6_addr_encode(fd_gossip_ip6_addr_t const * self, fd_bincode_encode_ctx_t * ctx) {
  return fd_bincode_bytes_encode( (uchar const *)self, sizeof(fd_gossip_ip6_addr_t), ctx );
}

int fd_feature_decode(fd_feature_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_feature_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_feature_new(self);
  fd_feature_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_feature_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_feature_decode_unsafe(fd_feature_t* self, fd_bincode_decode_ctx_t * ctx) {
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_activated_at = !!o;
    if( o ) {
      fd_bincode_uint64_decode_unsafe( &self->activated_at, ctx );
    }
  }
}
int fd_feature_decode_offsets(fd_feature_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->activated_at_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_feature_new(fd_feature_t* self) {
  fd_memset(self, 0, sizeof(fd_feature_t));
}
void fd_feature_destroy(fd_feature_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if( self->has_activated_at ) {
    self->has_activated_at = 0;
  }
}

ulong fd_feature_footprint( void ){ return FD_FEATURE_FOOTPRINT; }
ulong fd_feature_align( void ){ return FD_FEATURE_ALIGN; }

void fd_feature_walk(void * w, fd_feature_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_feature", level++);
  if( !self->has_activated_at ) {
    fun( w, NULL, "activated_at", FD_FLAMENCO_TYPE_NULL, "ulong", level );
  } else {
    fun( w, &self->activated_at, "activated_at", FD_FLAMENCO_TYPE_ULONG, "ulong", level );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_feature", level--);
}
ulong fd_feature_size(fd_feature_t const * self) {
  ulong size = 0;
  size += sizeof(char);
  if( self->has_activated_at ) {
    size += sizeof(ulong);
  }
  return size;
}

int fd_feature_encode(fd_feature_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bool_encode( self->has_activated_at, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_activated_at ) {
    err = fd_bincode_uint64_encode( self->activated_at, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_fee_calculator_decode(fd_fee_calculator_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_fee_calculator_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_fee_calculator_new(self);
  fd_fee_calculator_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_fee_calculator_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_fee_calculator_decode_unsafe(fd_fee_calculator_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->lamports_per_signature, ctx);
}
int fd_fee_calculator_decode_offsets(fd_fee_calculator_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->lamports_per_signature_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_fee_calculator_new(fd_fee_calculator_t* self) {
  fd_memset(self, 0, sizeof(fd_fee_calculator_t));
}
void fd_fee_calculator_destroy(fd_fee_calculator_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_fee_calculator_footprint( void ){ return FD_FEE_CALCULATOR_FOOTPRINT; }
ulong fd_fee_calculator_align( void ){ return FD_FEE_CALCULATOR_ALIGN; }

void fd_fee_calculator_walk(void * w, fd_fee_calculator_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_fee_calculator", level++);
  fun( w, &self->lamports_per_signature, "lamports_per_signature", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_fee_calculator", level--);
}
ulong fd_fee_calculator_size(fd_fee_calculator_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  return size;
}

int fd_fee_calculator_encode(fd_fee_calculator_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->lamports_per_signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_epoch_rewards_decode(fd_epoch_rewards_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_epoch_rewards_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_epoch_rewards_new(self);
  fd_epoch_rewards_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_epoch_rewards_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_epoch_rewards_decode_unsafe(fd_epoch_rewards_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->total_rewards, ctx);
  fd_bincode_uint64_decode_unsafe(&self->distributed_rewards, ctx);
  fd_bincode_uint64_decode_unsafe(&self->distribution_complete_block_height, ctx);
}
int fd_epoch_rewards_decode_offsets(fd_epoch_rewards_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->total_rewards_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->distributed_rewards_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->distribution_complete_block_height_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_epoch_rewards_new(fd_epoch_rewards_t* self) {
  fd_memset(self, 0, sizeof(fd_epoch_rewards_t));
}
void fd_epoch_rewards_destroy(fd_epoch_rewards_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_epoch_rewards_footprint( void ){ return FD_EPOCH_REWARDS_FOOTPRINT; }
ulong fd_epoch_rewards_align( void ){ return FD_EPOCH_REWARDS_ALIGN; }

void fd_epoch_rewards_walk(void * w, fd_epoch_rewards_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_epoch_rewards", level++);
  fun( w, &self->total_rewards, "total_rewards", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->distributed_rewards, "distributed_rewards", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->distribution_complete_block_height, "distribution_complete_block_height", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_epoch_rewards", level--);
}
ulong fd_epoch_rewards_size(fd_epoch_rewards_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_epoch_rewards_encode(fd_epoch_rewards_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->total_rewards, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->distributed_rewards, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->distribution_complete_block_height, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_hash_age_decode(fd_hash_age_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_hash_age_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_hash_age_new(self);
  fd_hash_age_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_hash_age_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_fee_calculator_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_hash_age_decode_unsafe(fd_hash_age_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_fee_calculator_decode_unsafe(&self->fee_calculator, ctx);
  fd_bincode_uint64_decode_unsafe(&self->hash_index, ctx);
  fd_bincode_uint64_decode_unsafe(&self->timestamp, ctx);
}
int fd_hash_age_decode_offsets(fd_hash_age_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->fee_calculator_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_fee_calculator_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->hash_index_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->timestamp_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_hash_age_new(fd_hash_age_t* self) {
  fd_memset(self, 0, sizeof(fd_hash_age_t));
  fd_fee_calculator_new(&self->fee_calculator);
}
void fd_hash_age_destroy(fd_hash_age_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_fee_calculator_destroy(&self->fee_calculator, ctx);
}

ulong fd_hash_age_footprint( void ){ return FD_HASH_AGE_FOOTPRINT; }
ulong fd_hash_age_align( void ){ return FD_HASH_AGE_ALIGN; }

void fd_hash_age_walk(void * w, fd_hash_age_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_hash_age", level++);
  fd_fee_calculator_walk(w, &self->fee_calculator, fun, "fee_calculator", level);
  fun( w, &self->hash_index, "hash_index", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->timestamp, "timestamp", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_hash_age", level--);
}
ulong fd_hash_age_size(fd_hash_age_t const * self) {
  ulong size = 0;
  size += fd_fee_calculator_size(&self->fee_calculator);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_hash_age_encode(fd_hash_age_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_fee_calculator_encode(&self->fee_calculator, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->hash_index, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_hash_hash_age_pair_decode(fd_hash_hash_age_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_hash_hash_age_pair_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_hash_hash_age_pair_new(self);
  fd_hash_hash_age_pair_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_hash_hash_age_pair_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_age_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_hash_hash_age_pair_decode_unsafe(fd_hash_hash_age_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_hash_decode_unsafe(&self->key, ctx);
  fd_hash_age_decode_unsafe(&self->val, ctx);
}
int fd_hash_hash_age_pair_decode_offsets(fd_hash_hash_age_pair_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->key_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->val_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_age_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_hash_hash_age_pair_new(fd_hash_hash_age_pair_t* self) {
  fd_memset(self, 0, sizeof(fd_hash_hash_age_pair_t));
  fd_hash_new(&self->key);
  fd_hash_age_new(&self->val);
}
void fd_hash_hash_age_pair_destroy(fd_hash_hash_age_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_hash_destroy(&self->key, ctx);
  fd_hash_age_destroy(&self->val, ctx);
}

ulong fd_hash_hash_age_pair_footprint( void ){ return FD_HASH_HASH_AGE_PAIR_FOOTPRINT; }
ulong fd_hash_hash_age_pair_align( void ){ return FD_HASH_HASH_AGE_PAIR_ALIGN; }

void fd_hash_hash_age_pair_walk(void * w, fd_hash_hash_age_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_hash_hash_age_pair", level++);
  fd_hash_walk(w, &self->key, fun, "key", level);
  fd_hash_age_walk(w, &self->val, fun, "val", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_hash_hash_age_pair", level--);
}
ulong fd_hash_hash_age_pair_size(fd_hash_hash_age_pair_t const * self) {
  ulong size = 0;
  size += fd_hash_size(&self->key);
  size += fd_hash_age_size(&self->val);
  return size;
}

int fd_hash_hash_age_pair_encode(fd_hash_hash_age_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_hash_encode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_age_encode(&self->val, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_block_hash_queue_decode(fd_block_hash_queue_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_block_hash_queue_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_block_hash_queue_new(self);
  fd_block_hash_queue_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_block_hash_queue_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_hash_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  ulong ages_len;
  err = fd_bincode_uint64_decode(&ages_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (ages_len != 0) {
    for( ulong i = 0; i < ages_len; ++i) {
      err = fd_hash_hash_age_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_block_hash_queue_decode_unsafe(fd_block_hash_queue_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->last_hash_index, ctx);
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      self->last_hash = (fd_hash_t*)fd_valloc_malloc( ctx->valloc, FD_HASH_ALIGN, FD_HASH_FOOTPRINT );
      fd_hash_new( self->last_hash );
      fd_hash_decode_unsafe( self->last_hash, ctx );
    } else
      self->last_hash = NULL;
  }
  fd_bincode_uint64_decode_unsafe(&self->ages_len, ctx);
  if (self->ages_len != 0) {
    self->ages = (fd_hash_hash_age_pair_t *)fd_valloc_malloc( ctx->valloc, FD_HASH_HASH_AGE_PAIR_ALIGN, FD_HASH_HASH_AGE_PAIR_FOOTPRINT*self->ages_len);
    for( ulong i = 0; i < self->ages_len; ++i) {
      fd_hash_hash_age_pair_new(self->ages + i);
      fd_hash_hash_age_pair_decode_unsafe(self->ages + i, ctx);
    }
  } else
    self->ages = NULL;
  fd_bincode_uint64_decode_unsafe(&self->max_age, ctx);
}
int fd_block_hash_queue_decode_offsets(fd_block_hash_queue_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->last_hash_index_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->last_hash_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_hash_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->ages_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong ages_len;
  err = fd_bincode_uint64_decode(&ages_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (ages_len != 0) {
    for( ulong i = 0; i < ages_len; ++i) {
      err = fd_hash_hash_age_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->max_age_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_block_hash_queue_new(fd_block_hash_queue_t* self) {
  fd_memset(self, 0, sizeof(fd_block_hash_queue_t));
}
void fd_block_hash_queue_destroy(fd_block_hash_queue_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if( NULL != self->last_hash ) {
    fd_hash_destroy( self->last_hash, ctx );
    fd_valloc_free( ctx->valloc, self->last_hash );
    self->last_hash = NULL;
  }
  if (NULL != self->ages) {
    for (ulong i = 0; i < self->ages_len; ++i)
      fd_hash_hash_age_pair_destroy(self->ages + i, ctx);
    fd_valloc_free( ctx->valloc, self->ages );
    self->ages = NULL;
  }
}

ulong fd_block_hash_queue_footprint( void ){ return FD_BLOCK_HASH_QUEUE_FOOTPRINT; }
ulong fd_block_hash_queue_align( void ){ return FD_BLOCK_HASH_QUEUE_ALIGN; }

void fd_block_hash_queue_walk(void * w, fd_block_hash_queue_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_block_hash_queue", level++);
  fun( w, &self->last_hash_index, "last_hash_index", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  if( !self->last_hash ) {
    fun( w, NULL, "last_hash", FD_FLAMENCO_TYPE_NULL, "hash", level );
  } else {
    fd_hash_walk( w, self->last_hash, fun, "last_hash", level );
  }
  if (self->ages_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "ages", level++);
    for (ulong i = 0; i < self->ages_len; ++i)
      fd_hash_hash_age_pair_walk(w, self->ages + i, fun, "hash_hash_age_pair", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "ages", level-- );
  }
  fun( w, &self->max_age, "max_age", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_block_hash_queue", level--);
}
ulong fd_block_hash_queue_size(fd_block_hash_queue_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(char);
  if( NULL !=  self->last_hash ) {
    size += fd_hash_size( self->last_hash );
  }
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->ages_len; ++i)
      size += fd_hash_hash_age_pair_size(self->ages + i);
  } while(0);
  size += sizeof(ulong);
  return size;
}

int fd_block_hash_queue_encode(fd_block_hash_queue_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->last_hash_index, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if( self->last_hash != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_hash_encode( self->last_hash, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint64_encode(self->ages_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->ages_len != 0) {
    for (ulong i = 0; i < self->ages_len; ++i) {
      err = fd_hash_hash_age_pair_encode(self->ages + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(self->max_age, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_fee_rate_governor_decode(fd_fee_rate_governor_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_fee_rate_governor_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_fee_rate_governor_new(self);
  fd_fee_rate_governor_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_fee_rate_governor_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_fee_rate_governor_decode_unsafe(fd_fee_rate_governor_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->target_lamports_per_signature, ctx);
  fd_bincode_uint64_decode_unsafe(&self->target_signatures_per_slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->min_lamports_per_signature, ctx);
  fd_bincode_uint64_decode_unsafe(&self->max_lamports_per_signature, ctx);
  fd_bincode_uint8_decode_unsafe(&self->burn_percent, ctx);
}
int fd_fee_rate_governor_decode_offsets(fd_fee_rate_governor_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->target_lamports_per_signature_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->target_signatures_per_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->min_lamports_per_signature_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->max_lamports_per_signature_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->burn_percent_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_fee_rate_governor_new(fd_fee_rate_governor_t* self) {
  fd_memset(self, 0, sizeof(fd_fee_rate_governor_t));
}
void fd_fee_rate_governor_destroy(fd_fee_rate_governor_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_fee_rate_governor_footprint( void ){ return FD_FEE_RATE_GOVERNOR_FOOTPRINT; }
ulong fd_fee_rate_governor_align( void ){ return FD_FEE_RATE_GOVERNOR_ALIGN; }

void fd_fee_rate_governor_walk(void * w, fd_fee_rate_governor_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_fee_rate_governor", level++);
  fun( w, &self->target_lamports_per_signature, "target_lamports_per_signature", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->target_signatures_per_slot, "target_signatures_per_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->min_lamports_per_signature, "min_lamports_per_signature", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->max_lamports_per_signature, "max_lamports_per_signature", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->burn_percent, "burn_percent", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_fee_rate_governor", level--);
}
ulong fd_fee_rate_governor_size(fd_fee_rate_governor_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(char);
  return size;
}

int fd_fee_rate_governor_encode(fd_fee_rate_governor_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->target_lamports_per_signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->target_signatures_per_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->min_lamports_per_signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->max_lamports_per_signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->burn_percent), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_slot_pair_decode(fd_slot_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_slot_pair_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_slot_pair_new(self);
  fd_slot_pair_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_slot_pair_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_pair_decode_unsafe(fd_slot_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->val, ctx);
}
int fd_slot_pair_decode_offsets(fd_slot_pair_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->val_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_pair_new(fd_slot_pair_t* self) {
  fd_memset(self, 0, sizeof(fd_slot_pair_t));
}
void fd_slot_pair_destroy(fd_slot_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_slot_pair_footprint( void ){ return FD_SLOT_PAIR_FOOTPRINT; }
ulong fd_slot_pair_align( void ){ return FD_SLOT_PAIR_ALIGN; }

void fd_slot_pair_walk(void * w, fd_slot_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_slot_pair", level++);
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->val, "val", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_slot_pair", level--);
}
ulong fd_slot_pair_size(fd_slot_pair_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_slot_pair_encode(fd_slot_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->val, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_hard_forks_decode(fd_hard_forks_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_hard_forks_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_hard_forks_new(self);
  fd_hard_forks_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_hard_forks_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong hard_forks_len;
  err = fd_bincode_uint64_decode(&hard_forks_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (hard_forks_len != 0) {
    for( ulong i = 0; i < hard_forks_len; ++i) {
      err = fd_slot_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_hard_forks_decode_unsafe(fd_hard_forks_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->hard_forks_len, ctx);
  if (self->hard_forks_len != 0) {
    self->hard_forks = (fd_slot_pair_t *)fd_valloc_malloc( ctx->valloc, FD_SLOT_PAIR_ALIGN, FD_SLOT_PAIR_FOOTPRINT*self->hard_forks_len);
    for( ulong i = 0; i < self->hard_forks_len; ++i) {
      fd_slot_pair_new(self->hard_forks + i);
      fd_slot_pair_decode_unsafe(self->hard_forks + i, ctx);
    }
  } else
    self->hard_forks = NULL;
}
int fd_hard_forks_decode_offsets(fd_hard_forks_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->hard_forks_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong hard_forks_len;
  err = fd_bincode_uint64_decode(&hard_forks_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (hard_forks_len != 0) {
    for( ulong i = 0; i < hard_forks_len; ++i) {
      err = fd_slot_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_hard_forks_new(fd_hard_forks_t* self) {
  fd_memset(self, 0, sizeof(fd_hard_forks_t));
}
void fd_hard_forks_destroy(fd_hard_forks_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->hard_forks) {
    for (ulong i = 0; i < self->hard_forks_len; ++i)
      fd_slot_pair_destroy(self->hard_forks + i, ctx);
    fd_valloc_free( ctx->valloc, self->hard_forks );
    self->hard_forks = NULL;
  }
}

ulong fd_hard_forks_footprint( void ){ return FD_HARD_FORKS_FOOTPRINT; }
ulong fd_hard_forks_align( void ){ return FD_HARD_FORKS_ALIGN; }

void fd_hard_forks_walk(void * w, fd_hard_forks_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_hard_forks", level++);
  if (self->hard_forks_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "hard_forks", level++);
    for (ulong i = 0; i < self->hard_forks_len; ++i)
      fd_slot_pair_walk(w, self->hard_forks + i, fun, "slot_pair", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "hard_forks", level-- );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_hard_forks", level--);
}
ulong fd_hard_forks_size(fd_hard_forks_t const * self) {
  ulong size = 0;
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->hard_forks_len; ++i)
      size += fd_slot_pair_size(self->hard_forks + i);
  } while(0);
  return size;
}

int fd_hard_forks_encode(fd_hard_forks_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->hard_forks_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->hard_forks_len != 0) {
    for (ulong i = 0; i < self->hard_forks_len; ++i) {
      err = fd_slot_pair_encode(self->hard_forks + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_inflation_decode(fd_inflation_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_inflation_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_inflation_new(self);
  fd_inflation_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_inflation_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_inflation_decode_unsafe(fd_inflation_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_double_decode_unsafe(&self->initial, ctx);
  fd_bincode_double_decode_unsafe(&self->terminal, ctx);
  fd_bincode_double_decode_unsafe(&self->taper, ctx);
  fd_bincode_double_decode_unsafe(&self->foundation, ctx);
  fd_bincode_double_decode_unsafe(&self->foundation_term, ctx);
  fd_bincode_double_decode_unsafe(&self->__unused, ctx);
}
int fd_inflation_decode_offsets(fd_inflation_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->initial_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->terminal_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->taper_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->foundation_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->foundation_term_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->__unused_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_inflation_new(fd_inflation_t* self) {
  fd_memset(self, 0, sizeof(fd_inflation_t));
}
void fd_inflation_destroy(fd_inflation_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_inflation_footprint( void ){ return FD_INFLATION_FOOTPRINT; }
ulong fd_inflation_align( void ){ return FD_INFLATION_ALIGN; }

void fd_inflation_walk(void * w, fd_inflation_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_inflation", level++);
  fun( w, &self->initial, "initial", FD_FLAMENCO_TYPE_DOUBLE,  "double",    level );
  fun( w, &self->terminal, "terminal", FD_FLAMENCO_TYPE_DOUBLE,  "double",    level );
  fun( w, &self->taper, "taper", FD_FLAMENCO_TYPE_DOUBLE,  "double",    level );
  fun( w, &self->foundation, "foundation", FD_FLAMENCO_TYPE_DOUBLE,  "double",    level );
  fun( w, &self->foundation_term, "foundation_term", FD_FLAMENCO_TYPE_DOUBLE,  "double",    level );
  fun( w, &self->__unused, "__unused", FD_FLAMENCO_TYPE_DOUBLE,  "double",    level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_inflation", level--);
}
ulong fd_inflation_size(fd_inflation_t const * self) {
  ulong size = 0;
  size += sizeof(double);
  size += sizeof(double);
  size += sizeof(double);
  size += sizeof(double);
  size += sizeof(double);
  size += sizeof(double);
  return size;
}

int fd_inflation_encode(fd_inflation_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_double_encode( self->initial, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode( self->terminal, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode( self->taper, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode( self->foundation, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode( self->foundation_term, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode( self->__unused, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_rent_decode(fd_rent_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_rent_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_rent_new(self);
  fd_rent_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_rent_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_rent_decode_unsafe(fd_rent_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->lamports_per_uint8_year, ctx);
  fd_bincode_double_decode_unsafe(&self->exemption_threshold, ctx);
  fd_bincode_uint8_decode_unsafe(&self->burn_percent, ctx);
}
int fd_rent_decode_offsets(fd_rent_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->lamports_per_uint8_year_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->exemption_threshold_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->burn_percent_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_rent_new(fd_rent_t* self) {
  fd_memset(self, 0, sizeof(fd_rent_t));
}
void fd_rent_destroy(fd_rent_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_rent_footprint( void ){ return FD_RENT_FOOTPRINT; }
ulong fd_rent_align( void ){ return FD_RENT_ALIGN; }

void fd_rent_walk(void * w, fd_rent_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_rent", level++);
  fun( w, &self->lamports_per_uint8_year, "lamports_per_uint8_year", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->exemption_threshold, "exemption_threshold", FD_FLAMENCO_TYPE_DOUBLE,  "double",    level );
  fun( w, &self->burn_percent, "burn_percent", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_rent", level--);
}
ulong fd_rent_size(fd_rent_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(double);
  size += sizeof(char);
  return size;
}

int fd_rent_encode(fd_rent_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->lamports_per_uint8_year, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode( self->exemption_threshold, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->burn_percent), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_epoch_schedule_decode(fd_epoch_schedule_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_epoch_schedule_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_epoch_schedule_new(self);
  fd_epoch_schedule_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_epoch_schedule_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_epoch_schedule_decode_unsafe(fd_epoch_schedule_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->slots_per_epoch, ctx);
  fd_bincode_uint64_decode_unsafe(&self->leader_schedule_slot_offset, ctx);
  fd_bincode_uint8_decode_unsafe(&self->warmup, ctx);
  fd_bincode_uint64_decode_unsafe(&self->first_normal_epoch, ctx);
  fd_bincode_uint64_decode_unsafe(&self->first_normal_slot, ctx);
}
int fd_epoch_schedule_decode_offsets(fd_epoch_schedule_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->slots_per_epoch_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->leader_schedule_slot_offset_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->warmup_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->first_normal_epoch_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->first_normal_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_epoch_schedule_new(fd_epoch_schedule_t* self) {
  fd_memset(self, 0, sizeof(fd_epoch_schedule_t));
}
void fd_epoch_schedule_destroy(fd_epoch_schedule_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_epoch_schedule_footprint( void ){ return FD_EPOCH_SCHEDULE_FOOTPRINT; }
ulong fd_epoch_schedule_align( void ){ return FD_EPOCH_SCHEDULE_ALIGN; }

void fd_epoch_schedule_walk(void * w, fd_epoch_schedule_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_epoch_schedule", level++);
  fun( w, &self->slots_per_epoch, "slots_per_epoch", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->leader_schedule_slot_offset, "leader_schedule_slot_offset", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->warmup, "warmup", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  fun( w, &self->first_normal_epoch, "first_normal_epoch", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->first_normal_slot, "first_normal_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_epoch_schedule", level--);
}
ulong fd_epoch_schedule_size(fd_epoch_schedule_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(char);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_epoch_schedule_encode(fd_epoch_schedule_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->slots_per_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->leader_schedule_slot_offset, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->warmup), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->first_normal_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->first_normal_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_rent_collector_decode(fd_rent_collector_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_rent_collector_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_rent_collector_new(self);
  fd_rent_collector_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_rent_collector_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_epoch_schedule_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_rent_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_rent_collector_decode_unsafe(fd_rent_collector_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->epoch, ctx);
  fd_epoch_schedule_decode_unsafe(&self->epoch_schedule, ctx);
  fd_bincode_double_decode_unsafe(&self->slots_per_year, ctx);
  fd_rent_decode_unsafe(&self->rent, ctx);
}
int fd_rent_collector_decode_offsets(fd_rent_collector_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->epoch_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->epoch_schedule_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_epoch_schedule_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->slots_per_year_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->rent_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_rent_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_rent_collector_new(fd_rent_collector_t* self) {
  fd_memset(self, 0, sizeof(fd_rent_collector_t));
  fd_epoch_schedule_new(&self->epoch_schedule);
  fd_rent_new(&self->rent);
}
void fd_rent_collector_destroy(fd_rent_collector_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_epoch_schedule_destroy(&self->epoch_schedule, ctx);
  fd_rent_destroy(&self->rent, ctx);
}

ulong fd_rent_collector_footprint( void ){ return FD_RENT_COLLECTOR_FOOTPRINT; }
ulong fd_rent_collector_align( void ){ return FD_RENT_COLLECTOR_ALIGN; }

void fd_rent_collector_walk(void * w, fd_rent_collector_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_rent_collector", level++);
  fun( w, &self->epoch, "epoch", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_epoch_schedule_walk(w, &self->epoch_schedule, fun, "epoch_schedule", level);
  fun( w, &self->slots_per_year, "slots_per_year", FD_FLAMENCO_TYPE_DOUBLE,  "double",    level );
  fd_rent_walk(w, &self->rent, fun, "rent", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_rent_collector", level--);
}
ulong fd_rent_collector_size(fd_rent_collector_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_epoch_schedule_size(&self->epoch_schedule);
  size += sizeof(double);
  size += fd_rent_size(&self->rent);
  return size;
}

int fd_rent_collector_encode(fd_rent_collector_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_epoch_schedule_encode(&self->epoch_schedule, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode( self->slots_per_year, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_rent_encode(&self->rent, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_history_entry_decode(fd_stake_history_entry_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_history_entry_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_history_entry_new(self);
  fd_stake_history_entry_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_history_entry_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_history_entry_decode_unsafe(fd_stake_history_entry_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->epoch, ctx);
  fd_bincode_uint64_decode_unsafe(&self->effective, ctx);
  fd_bincode_uint64_decode_unsafe(&self->activating, ctx);
  fd_bincode_uint64_decode_unsafe(&self->deactivating, ctx);
}
int fd_stake_history_entry_decode_offsets(fd_stake_history_entry_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->epoch_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->effective_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->activating_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->deactivating_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->parent_off = (uint)((ulong)ctx->data - (ulong)data);
  self->left_off = (uint)((ulong)ctx->data - (ulong)data);
  self->right_off = (uint)((ulong)ctx->data - (ulong)data);
  self->prio_off = (uint)((ulong)ctx->data - (ulong)data);
  return FD_BINCODE_SUCCESS;
}
void fd_stake_history_entry_new(fd_stake_history_entry_t* self) {
  fd_memset(self, 0, sizeof(fd_stake_history_entry_t));
}
void fd_stake_history_entry_destroy(fd_stake_history_entry_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_stake_history_entry_footprint( void ){ return FD_STAKE_HISTORY_ENTRY_FOOTPRINT; }
ulong fd_stake_history_entry_align( void ){ return FD_STAKE_HISTORY_ENTRY_ALIGN; }

void fd_stake_history_entry_walk(void * w, fd_stake_history_entry_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_history_entry", level++);
  fun( w, &self->epoch, "epoch", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->effective, "effective", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->activating, "activating", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->deactivating, "deactivating", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_history_entry", level--);
}
ulong fd_stake_history_entry_size(fd_stake_history_entry_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_stake_history_entry_encode(fd_stake_history_entry_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->effective, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->activating, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->deactivating, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_history_decode(fd_stake_history_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_history_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_history_new(self);
  fd_stake_history_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_history_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong fd_stake_history_treap_len;
  err = fd_bincode_uint64_decode(&fd_stake_history_treap_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( fd_stake_history_treap_len > FD_STAKE_HISTORY_MAX ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < fd_stake_history_treap_len; ++i) {
    err = fd_stake_history_entry_decode_preflight( ctx );
    if ( FD_UNLIKELY ( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_stake_history_decode_unsafe(fd_stake_history_t* self, fd_bincode_decode_ctx_t * ctx) {
  ulong fd_stake_history_treap_len;
  fd_bincode_uint64_decode_unsafe(&fd_stake_history_treap_len, ctx);
  self->pool = fd_stake_history_pool_alloc( ctx->valloc );
  self->treap = fd_stake_history_treap_alloc( ctx->valloc );
  for (ulong i = 0; i < fd_stake_history_treap_len; ++i) {
    fd_stake_history_entry_t * ele = fd_stake_history_pool_ele_acquire( self->pool );
    fd_stake_history_entry_new( ele );
    fd_stake_history_entry_decode_unsafe( ele, ctx );
    fd_stake_history_treap_ele_insert( self->treap, ele, self->pool ); /* this cannot fail */
  }
}
int fd_stake_history_decode_offsets(fd_stake_history_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->fd_stake_history_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong fd_stake_history_treap_len;
  err = fd_bincode_uint64_decode(&fd_stake_history_treap_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( fd_stake_history_treap_len > FD_STAKE_HISTORY_MAX ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < fd_stake_history_treap_len; ++i) {
    err = fd_stake_history_entry_decode_preflight( ctx );
    if ( FD_UNLIKELY ( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_stake_history_new(fd_stake_history_t* self) {
  fd_memset(self, 0, sizeof(fd_stake_history_t));
}
void fd_stake_history_destroy(fd_stake_history_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if ( !self->treap || !self->pool ) return;
  for ( fd_stake_history_treap_fwd_iter_t iter = fd_stake_history_treap_fwd_iter_init( self->treap, self->pool );
          !fd_stake_history_treap_fwd_iter_done( iter );
          iter = fd_stake_history_treap_fwd_iter_next( iter, self->pool ) ) {
      fd_stake_history_entry_t * ele = fd_stake_history_treap_fwd_iter_ele( iter, self->pool );
      fd_stake_history_entry_destroy( ele, ctx );
    }
  fd_valloc_free( ctx->valloc, fd_stake_history_treap_delete(fd_stake_history_treap_leave( self->treap) ) );
  fd_valloc_free( ctx->valloc, fd_stake_history_pool_delete(fd_stake_history_pool_leave( self->pool) ) );
  self->pool = NULL;
  self->treap = NULL;
}

ulong fd_stake_history_footprint( void ){ return FD_STAKE_HISTORY_FOOTPRINT; }
ulong fd_stake_history_align( void ){ return FD_STAKE_HISTORY_ALIGN; }

void fd_stake_history_walk(void * w, fd_stake_history_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_history", level++);
  if (self->treap) {
    for ( fd_stake_history_treap_fwd_iter_t iter = fd_stake_history_treap_fwd_iter_init( self->treap, self->pool );
          !fd_stake_history_treap_fwd_iter_done( iter );
          iter = fd_stake_history_treap_fwd_iter_next( iter, self->pool ) ) {
      fd_stake_history_entry_t * ele = fd_stake_history_treap_fwd_iter_ele( iter, self->pool );
      fd_stake_history_entry_walk(w, ele, fun, "fd_stake_history_entry_t", level );
    }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_history", level--);
}
ulong fd_stake_history_size(fd_stake_history_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  if (self->treap) {
    for ( fd_stake_history_treap_fwd_iter_t iter = fd_stake_history_treap_fwd_iter_init( self->treap, self->pool );
          !fd_stake_history_treap_fwd_iter_done( iter );
          iter = fd_stake_history_treap_fwd_iter_next( iter, self->pool ) ) {
      fd_stake_history_entry_t * ele = fd_stake_history_treap_fwd_iter_ele( iter, self->pool );
      size += fd_stake_history_entry_size( ele );
    }
  }
  return size;
}

int fd_stake_history_encode(fd_stake_history_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if (self->treap) {
    ulong fd_stake_history_len = fd_stake_history_treap_ele_cnt( self->treap );
    err = fd_bincode_uint64_encode( fd_stake_history_len, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
    for ( fd_stake_history_treap_rev_iter_t iter = fd_stake_history_treap_rev_iter_init( self->treap, self->pool );
          !fd_stake_history_treap_rev_iter_done( iter );
          iter = fd_stake_history_treap_rev_iter_next( iter, self->pool ) ) {
      fd_stake_history_entry_t * ele = fd_stake_history_treap_rev_iter_ele( iter, self->pool );
      err = fd_stake_history_entry_encode( ele, ctx );
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong fd_stake_history_len = 0;
    err = fd_bincode_uint64_encode(fd_stake_history_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_solana_account_decode(fd_solana_account_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_solana_account_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_solana_account_new(self);
  fd_solana_account_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_solana_account_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ulong data_len;
  err = fd_bincode_uint64_decode(&data_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (data_len != 0) {
    err = fd_bincode_bytes_decode_preflight(data_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_solana_account_decode_unsafe(fd_solana_account_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->lamports, ctx);
  fd_bincode_uint64_decode_unsafe(&self->data_len, ctx);
  if (self->data_len != 0) {
    self->data = fd_valloc_malloc( ctx->valloc, 8UL, self->data_len );
    fd_bincode_bytes_decode_unsafe(self->data, self->data_len, ctx);
  } else
    self->data = NULL;
  fd_pubkey_decode_unsafe(&self->owner, ctx);
  fd_bincode_uint8_decode_unsafe(&self->executable, ctx);
  fd_bincode_uint64_decode_unsafe(&self->rent_epoch, ctx);
}
int fd_solana_account_decode_offsets(fd_solana_account_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->lamports_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->data_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong data_len;
  err = fd_bincode_uint64_decode(&data_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (data_len != 0) {
    err = fd_bincode_bytes_decode_preflight(data_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  self->owner_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->executable_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->rent_epoch_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_solana_account_new(fd_solana_account_t* self) {
  fd_memset(self, 0, sizeof(fd_solana_account_t));
  fd_pubkey_new(&self->owner);
}
void fd_solana_account_destroy(fd_solana_account_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->data) {
    fd_valloc_free( ctx->valloc, self->data );
    self->data = NULL;
  }
  fd_pubkey_destroy(&self->owner, ctx);
}

ulong fd_solana_account_footprint( void ){ return FD_SOLANA_ACCOUNT_FOOTPRINT; }
ulong fd_solana_account_align( void ){ return FD_SOLANA_ACCOUNT_ALIGN; }

void fd_solana_account_walk(void * w, fd_solana_account_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_solana_account", level++);
  fun( w, &self->lamports, "lamports", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self->data, "data", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );
  fd_pubkey_walk(w, &self->owner, fun, "owner", level);
  fun( w, &self->executable, "executable", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  fun( w, &self->rent_epoch, "rent_epoch", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_solana_account", level--);
}
ulong fd_solana_account_size(fd_solana_account_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  do {
    size += sizeof(ulong);
    size += self->data_len;
  } while(0);
  size += fd_pubkey_size(&self->owner);
  size += sizeof(char);
  size += sizeof(ulong);
  return size;
}

int fd_solana_account_encode(fd_solana_account_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->lamports, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->data_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->data_len != 0) {
    err = fd_bincode_bytes_encode(self->data, self->data_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_pubkey_encode(&self->owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->executable), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->rent_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_accounts_pair_decode(fd_vote_accounts_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_accounts_pair_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_accounts_pair_new(self);
  fd_vote_accounts_pair_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_accounts_pair_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_solana_account_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_accounts_pair_decode_unsafe(fd_vote_accounts_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->key, ctx);
  fd_bincode_uint64_decode_unsafe(&self->stake, ctx);
  fd_solana_account_decode_unsafe(&self->value, ctx);
}
int fd_vote_accounts_pair_decode_offsets(fd_vote_accounts_pair_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->key_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->stake_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->value_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_solana_account_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_accounts_pair_new(fd_vote_accounts_pair_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_accounts_pair_t));
  fd_pubkey_new(&self->key);
  fd_solana_account_new(&self->value);
}
void fd_vote_accounts_pair_destroy(fd_vote_accounts_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->key, ctx);
  fd_solana_account_destroy(&self->value, ctx);
}

ulong fd_vote_accounts_pair_footprint( void ){ return FD_VOTE_ACCOUNTS_PAIR_FOOTPRINT; }
ulong fd_vote_accounts_pair_align( void ){ return FD_VOTE_ACCOUNTS_PAIR_ALIGN; }

void fd_vote_accounts_pair_walk(void * w, fd_vote_accounts_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_accounts_pair", level++);
  fd_pubkey_walk(w, &self->key, fun, "key", level);
  fun( w, &self->stake, "stake", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_solana_account_walk(w, &self->value, fun, "value", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_accounts_pair", level--);
}
ulong fd_vote_accounts_pair_size(fd_vote_accounts_pair_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->key);
  size += sizeof(ulong);
  size += fd_solana_account_size(&self->value);
  return size;
}

int fd_vote_accounts_pair_encode(fd_vote_accounts_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->stake, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_solana_account_encode(&self->value, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_accounts_decode(fd_vote_accounts_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_accounts_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_accounts_new(self);
  fd_vote_accounts_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_accounts_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong vote_accounts_len;
  err = fd_bincode_uint64_decode(&vote_accounts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  for (ulong i = 0; i < vote_accounts_len; ++i) {
    err = fd_vote_accounts_pair_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_vote_accounts_decode_unsafe(fd_vote_accounts_t* self, fd_bincode_decode_ctx_t * ctx) {
  ulong vote_accounts_len;
  fd_bincode_uint64_decode_unsafe(&vote_accounts_len, ctx);
  self->vote_accounts_pool = fd_vote_accounts_pair_t_map_alloc(ctx->valloc, fd_ulong_max(vote_accounts_len, 10000));
  self->vote_accounts_root = NULL;
  for (ulong i = 0; i < vote_accounts_len; ++i) {
    fd_vote_accounts_pair_t_mapnode_t* node = fd_vote_accounts_pair_t_map_acquire(self->vote_accounts_pool);
    fd_vote_accounts_pair_new(&node->elem);
    fd_vote_accounts_pair_decode_unsafe(&node->elem, ctx);
    fd_vote_accounts_pair_t_map_insert(self->vote_accounts_pool, &self->vote_accounts_root, node);
  }
}
int fd_vote_accounts_decode_offsets(fd_vote_accounts_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->vote_accounts_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong vote_accounts_len;
  err = fd_bincode_uint64_decode(&vote_accounts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  for (ulong i = 0; i < vote_accounts_len; ++i) {
    err = fd_vote_accounts_pair_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_vote_accounts_new(fd_vote_accounts_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_accounts_t));
}
void fd_vote_accounts_destroy(fd_vote_accounts_t* self, fd_bincode_destroy_ctx_t * ctx) {
  for ( fd_vote_accounts_pair_t_mapnode_t* n = fd_vote_accounts_pair_t_map_minimum(self->vote_accounts_pool, self->vote_accounts_root); n; n = fd_vote_accounts_pair_t_map_successor(self->vote_accounts_pool, n) ) {
    fd_vote_accounts_pair_destroy(&n->elem, ctx);
  }
  fd_valloc_free( ctx->valloc, fd_vote_accounts_pair_t_map_delete(fd_vote_accounts_pair_t_map_leave( self->vote_accounts_pool) ) );
  self->vote_accounts_pool = NULL;
  self->vote_accounts_root = NULL;
}

ulong fd_vote_accounts_footprint( void ){ return FD_VOTE_ACCOUNTS_FOOTPRINT; }
ulong fd_vote_accounts_align( void ){ return FD_VOTE_ACCOUNTS_ALIGN; }

void fd_vote_accounts_walk(void * w, fd_vote_accounts_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_accounts", level++);
  if (self->vote_accounts_root) {
    for ( fd_vote_accounts_pair_t_mapnode_t* n = fd_vote_accounts_pair_t_map_minimum(self->vote_accounts_pool, self->vote_accounts_root); n; n = fd_vote_accounts_pair_t_map_successor(self->vote_accounts_pool, n) ) {
      fd_vote_accounts_pair_walk(w, &n->elem, fun, "vote_accounts", level );
    }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_accounts", level--);
}
ulong fd_vote_accounts_size(fd_vote_accounts_t const * self) {
  ulong size = 0;
  if (self->vote_accounts_root) {
    size += sizeof(ulong);
    for ( fd_vote_accounts_pair_t_mapnode_t* n = fd_vote_accounts_pair_t_map_minimum(self->vote_accounts_pool, self->vote_accounts_root); n; n = fd_vote_accounts_pair_t_map_successor(self->vote_accounts_pool, n) ) {
      size += fd_vote_accounts_pair_size(&n->elem);
    }
  } else {
    size += sizeof(ulong);
  }
  return size;
}

int fd_vote_accounts_encode(fd_vote_accounts_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if (self->vote_accounts_root) {
    ulong vote_accounts_len = fd_vote_accounts_pair_t_map_size(self->vote_accounts_pool, self->vote_accounts_root);
    err = fd_bincode_uint64_encode(vote_accounts_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( fd_vote_accounts_pair_t_mapnode_t* n = fd_vote_accounts_pair_t_map_minimum(self->vote_accounts_pool, self->vote_accounts_root); n; n = fd_vote_accounts_pair_t_map_successor(self->vote_accounts_pool, n) ) {
      err = fd_vote_accounts_pair_encode(&n->elem, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong vote_accounts_len = 0;
    err = fd_bincode_uint64_encode(vote_accounts_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_stake_accounts_pair_decode(fd_stake_accounts_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_accounts_pair_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_accounts_pair_new(self);
  fd_stake_accounts_pair_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_accounts_pair_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_accounts_pair_decode_unsafe(fd_stake_accounts_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->key, ctx);
  fd_bincode_uint32_decode_unsafe(&self->exists, ctx);
}
int fd_stake_accounts_pair_decode_offsets(fd_stake_accounts_pair_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->key_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->exists_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_accounts_pair_new(fd_stake_accounts_pair_t* self) {
  fd_memset(self, 0, sizeof(fd_stake_accounts_pair_t));
  fd_pubkey_new(&self->key);
}
void fd_stake_accounts_pair_destroy(fd_stake_accounts_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->key, ctx);
}

ulong fd_stake_accounts_pair_footprint( void ){ return FD_STAKE_ACCOUNTS_PAIR_FOOTPRINT; }
ulong fd_stake_accounts_pair_align( void ){ return FD_STAKE_ACCOUNTS_PAIR_ALIGN; }

void fd_stake_accounts_pair_walk(void * w, fd_stake_accounts_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_accounts_pair", level++);
  fd_pubkey_walk(w, &self->key, fun, "key", level);
  fun( w, &self->exists, "exists", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_accounts_pair", level--);
}
ulong fd_stake_accounts_pair_size(fd_stake_accounts_pair_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->key);
  size += sizeof(uint);
  return size;
}

int fd_stake_accounts_pair_encode(fd_stake_accounts_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_encode( self->exists, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_accounts_decode(fd_stake_accounts_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_accounts_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_accounts_new(self);
  fd_stake_accounts_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_accounts_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong stake_accounts_len;
  err = fd_bincode_uint64_decode(&stake_accounts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  for (ulong i = 0; i < stake_accounts_len; ++i) {
    err = fd_stake_accounts_pair_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_stake_accounts_decode_unsafe(fd_stake_accounts_t* self, fd_bincode_decode_ctx_t * ctx) {
  ulong stake_accounts_len;
  fd_bincode_uint64_decode_unsafe(&stake_accounts_len, ctx);
  self->stake_accounts_pool = fd_stake_accounts_pair_t_map_alloc(ctx->valloc, fd_ulong_max(stake_accounts_len, 100000));
  self->stake_accounts_root = NULL;
  for (ulong i = 0; i < stake_accounts_len; ++i) {
    fd_stake_accounts_pair_t_mapnode_t* node = fd_stake_accounts_pair_t_map_acquire(self->stake_accounts_pool);
    fd_stake_accounts_pair_new(&node->elem);
    fd_stake_accounts_pair_decode_unsafe(&node->elem, ctx);
    fd_stake_accounts_pair_t_map_insert(self->stake_accounts_pool, &self->stake_accounts_root, node);
  }
}
int fd_stake_accounts_decode_offsets(fd_stake_accounts_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->stake_accounts_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong stake_accounts_len;
  err = fd_bincode_uint64_decode(&stake_accounts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  for (ulong i = 0; i < stake_accounts_len; ++i) {
    err = fd_stake_accounts_pair_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_stake_accounts_new(fd_stake_accounts_t* self) {
  fd_memset(self, 0, sizeof(fd_stake_accounts_t));
}
void fd_stake_accounts_destroy(fd_stake_accounts_t* self, fd_bincode_destroy_ctx_t * ctx) {
  for ( fd_stake_accounts_pair_t_mapnode_t* n = fd_stake_accounts_pair_t_map_minimum(self->stake_accounts_pool, self->stake_accounts_root); n; n = fd_stake_accounts_pair_t_map_successor(self->stake_accounts_pool, n) ) {
    fd_stake_accounts_pair_destroy(&n->elem, ctx);
  }
  fd_valloc_free( ctx->valloc, fd_stake_accounts_pair_t_map_delete(fd_stake_accounts_pair_t_map_leave( self->stake_accounts_pool) ) );
  self->stake_accounts_pool = NULL;
  self->stake_accounts_root = NULL;
}

ulong fd_stake_accounts_footprint( void ){ return FD_STAKE_ACCOUNTS_FOOTPRINT; }
ulong fd_stake_accounts_align( void ){ return FD_STAKE_ACCOUNTS_ALIGN; }

void fd_stake_accounts_walk(void * w, fd_stake_accounts_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_accounts", level++);
  if (self->stake_accounts_root) {
    for ( fd_stake_accounts_pair_t_mapnode_t* n = fd_stake_accounts_pair_t_map_minimum(self->stake_accounts_pool, self->stake_accounts_root); n; n = fd_stake_accounts_pair_t_map_successor(self->stake_accounts_pool, n) ) {
      fd_stake_accounts_pair_walk(w, &n->elem, fun, "stake_accounts", level );
    }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_accounts", level--);
}
ulong fd_stake_accounts_size(fd_stake_accounts_t const * self) {
  ulong size = 0;
  if (self->stake_accounts_root) {
    size += sizeof(ulong);
    for ( fd_stake_accounts_pair_t_mapnode_t* n = fd_stake_accounts_pair_t_map_minimum(self->stake_accounts_pool, self->stake_accounts_root); n; n = fd_stake_accounts_pair_t_map_successor(self->stake_accounts_pool, n) ) {
      size += fd_stake_accounts_pair_size(&n->elem);
    }
  } else {
    size += sizeof(ulong);
  }
  return size;
}

int fd_stake_accounts_encode(fd_stake_accounts_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if (self->stake_accounts_root) {
    ulong stake_accounts_len = fd_stake_accounts_pair_t_map_size(self->stake_accounts_pool, self->stake_accounts_root);
    err = fd_bincode_uint64_encode(stake_accounts_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( fd_stake_accounts_pair_t_mapnode_t* n = fd_stake_accounts_pair_t_map_minimum(self->stake_accounts_pool, self->stake_accounts_root); n; n = fd_stake_accounts_pair_t_map_successor(self->stake_accounts_pool, n) ) {
      err = fd_stake_accounts_pair_encode(&n->elem, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong stake_accounts_len = 0;
    err = fd_bincode_uint64_encode(stake_accounts_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_stake_weight_decode(fd_stake_weight_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_weight_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_weight_new(self);
  fd_stake_weight_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_weight_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_weight_decode_unsafe(fd_stake_weight_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->key, ctx);
  fd_bincode_uint64_decode_unsafe(&self->stake, ctx);
}
int fd_stake_weight_decode_offsets(fd_stake_weight_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->key_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->stake_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_weight_new(fd_stake_weight_t* self) {
  fd_memset(self, 0, sizeof(fd_stake_weight_t));
  fd_pubkey_new(&self->key);
}
void fd_stake_weight_destroy(fd_stake_weight_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->key, ctx);
}

ulong fd_stake_weight_footprint( void ){ return FD_STAKE_WEIGHT_FOOTPRINT; }
ulong fd_stake_weight_align( void ){ return FD_STAKE_WEIGHT_ALIGN; }

void fd_stake_weight_walk(void * w, fd_stake_weight_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_weight", level++);
  fd_pubkey_walk(w, &self->key, fun, "key", level);
  fun( w, &self->stake, "stake", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_weight", level--);
}
ulong fd_stake_weight_size(fd_stake_weight_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->key);
  size += sizeof(ulong);
  return size;
}

int fd_stake_weight_encode(fd_stake_weight_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->stake, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_weights_decode(fd_stake_weights_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_weights_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_weights_new(self);
  fd_stake_weights_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_weights_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong stake_weights_len;
  err = fd_bincode_uint64_decode(&stake_weights_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  for (ulong i = 0; i < stake_weights_len; ++i) {
    err = fd_stake_weight_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_stake_weights_decode_unsafe(fd_stake_weights_t* self, fd_bincode_decode_ctx_t * ctx) {
  ulong stake_weights_len;
  fd_bincode_uint64_decode_unsafe(&stake_weights_len, ctx);
  self->stake_weights_pool = fd_stake_weight_t_map_alloc(ctx->valloc, stake_weights_len);
  self->stake_weights_root = NULL;
  for (ulong i = 0; i < stake_weights_len; ++i) {
    fd_stake_weight_t_mapnode_t* node = fd_stake_weight_t_map_acquire(self->stake_weights_pool);
    fd_stake_weight_new(&node->elem);
    fd_stake_weight_decode_unsafe(&node->elem, ctx);
    fd_stake_weight_t_map_insert(self->stake_weights_pool, &self->stake_weights_root, node);
  }
}
int fd_stake_weights_decode_offsets(fd_stake_weights_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->stake_weights_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong stake_weights_len;
  err = fd_bincode_uint64_decode(&stake_weights_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  for (ulong i = 0; i < stake_weights_len; ++i) {
    err = fd_stake_weight_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_stake_weights_new(fd_stake_weights_t* self) {
  fd_memset(self, 0, sizeof(fd_stake_weights_t));
}
void fd_stake_weights_destroy(fd_stake_weights_t* self, fd_bincode_destroy_ctx_t * ctx) {
  for ( fd_stake_weight_t_mapnode_t* n = fd_stake_weight_t_map_minimum(self->stake_weights_pool, self->stake_weights_root); n; n = fd_stake_weight_t_map_successor(self->stake_weights_pool, n) ) {
    fd_stake_weight_destroy(&n->elem, ctx);
  }
  fd_valloc_free( ctx->valloc, fd_stake_weight_t_map_delete(fd_stake_weight_t_map_leave( self->stake_weights_pool) ) );
  self->stake_weights_pool = NULL;
  self->stake_weights_root = NULL;
}

ulong fd_stake_weights_footprint( void ){ return FD_STAKE_WEIGHTS_FOOTPRINT; }
ulong fd_stake_weights_align( void ){ return FD_STAKE_WEIGHTS_ALIGN; }

void fd_stake_weights_walk(void * w, fd_stake_weights_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_weights", level++);
  if (self->stake_weights_root) {
    for ( fd_stake_weight_t_mapnode_t* n = fd_stake_weight_t_map_minimum(self->stake_weights_pool, self->stake_weights_root); n; n = fd_stake_weight_t_map_successor(self->stake_weights_pool, n) ) {
      fd_stake_weight_walk(w, &n->elem, fun, "stake_weights", level );
    }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_weights", level--);
}
ulong fd_stake_weights_size(fd_stake_weights_t const * self) {
  ulong size = 0;
  if (self->stake_weights_root) {
    size += sizeof(ulong);
    for ( fd_stake_weight_t_mapnode_t* n = fd_stake_weight_t_map_minimum(self->stake_weights_pool, self->stake_weights_root); n; n = fd_stake_weight_t_map_successor(self->stake_weights_pool, n) ) {
      size += fd_stake_weight_size(&n->elem);
    }
  } else {
    size += sizeof(ulong);
  }
  return size;
}

int fd_stake_weights_encode(fd_stake_weights_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if (self->stake_weights_root) {
    ulong stake_weights_len = fd_stake_weight_t_map_size(self->stake_weights_pool, self->stake_weights_root);
    err = fd_bincode_uint64_encode(stake_weights_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( fd_stake_weight_t_mapnode_t* n = fd_stake_weight_t_map_minimum(self->stake_weights_pool, self->stake_weights_root); n; n = fd_stake_weight_t_map_successor(self->stake_weights_pool, n) ) {
      err = fd_stake_weight_encode(&n->elem, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong stake_weights_len = 0;
    err = fd_bincode_uint64_encode(stake_weights_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_delegation_decode(fd_delegation_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_delegation_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_delegation_new(self);
  fd_delegation_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_delegation_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_delegation_decode_unsafe(fd_delegation_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->voter_pubkey, ctx);
  fd_bincode_uint64_decode_unsafe(&self->stake, ctx);
  fd_bincode_uint64_decode_unsafe(&self->activation_epoch, ctx);
  fd_bincode_uint64_decode_unsafe(&self->deactivation_epoch, ctx);
  fd_bincode_double_decode_unsafe(&self->warmup_cooldown_rate, ctx);
}
int fd_delegation_decode_offsets(fd_delegation_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->voter_pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->stake_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->activation_epoch_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->deactivation_epoch_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->warmup_cooldown_rate_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_delegation_new(fd_delegation_t* self) {
  fd_memset(self, 0, sizeof(fd_delegation_t));
  fd_pubkey_new(&self->voter_pubkey);
}
void fd_delegation_destroy(fd_delegation_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->voter_pubkey, ctx);
}

ulong fd_delegation_footprint( void ){ return FD_DELEGATION_FOOTPRINT; }
ulong fd_delegation_align( void ){ return FD_DELEGATION_ALIGN; }

void fd_delegation_walk(void * w, fd_delegation_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_delegation", level++);
  fd_pubkey_walk(w, &self->voter_pubkey, fun, "voter_pubkey", level);
  fun( w, &self->stake, "stake", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->activation_epoch, "activation_epoch", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->deactivation_epoch, "deactivation_epoch", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->warmup_cooldown_rate, "warmup_cooldown_rate", FD_FLAMENCO_TYPE_DOUBLE,  "double",    level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_delegation", level--);
}
ulong fd_delegation_size(fd_delegation_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->voter_pubkey);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(double);
  return size;
}

int fd_delegation_encode(fd_delegation_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->voter_pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->stake, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->activation_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->deactivation_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode( self->warmup_cooldown_rate, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_delegation_pair_decode(fd_delegation_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_delegation_pair_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_delegation_pair_new(self);
  fd_delegation_pair_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_delegation_pair_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_delegation_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_delegation_pair_decode_unsafe(fd_delegation_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->account, ctx);
  fd_delegation_decode_unsafe(&self->delegation, ctx);
}
int fd_delegation_pair_decode_offsets(fd_delegation_pair_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->account_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->delegation_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_delegation_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_delegation_pair_new(fd_delegation_pair_t* self) {
  fd_memset(self, 0, sizeof(fd_delegation_pair_t));
  fd_pubkey_new(&self->account);
  fd_delegation_new(&self->delegation);
}
void fd_delegation_pair_destroy(fd_delegation_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->account, ctx);
  fd_delegation_destroy(&self->delegation, ctx);
}

ulong fd_delegation_pair_footprint( void ){ return FD_DELEGATION_PAIR_FOOTPRINT; }
ulong fd_delegation_pair_align( void ){ return FD_DELEGATION_PAIR_ALIGN; }

void fd_delegation_pair_walk(void * w, fd_delegation_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_delegation_pair", level++);
  fd_pubkey_walk(w, &self->account, fun, "account", level);
  fd_delegation_walk(w, &self->delegation, fun, "delegation", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_delegation_pair", level--);
}
ulong fd_delegation_pair_size(fd_delegation_pair_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->account);
  size += fd_delegation_size(&self->delegation);
  return size;
}

int fd_delegation_pair_encode(fd_delegation_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->account, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_delegation_encode(&self->delegation, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stakes_decode(fd_stakes_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stakes_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stakes_new(self);
  fd_stakes_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stakes_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_vote_accounts_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong stake_delegations_len;
  err = fd_bincode_uint64_decode(&stake_delegations_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  for (ulong i = 0; i < stake_delegations_len; ++i) {
    err = fd_delegation_pair_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_stake_history_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stakes_decode_unsafe(fd_stakes_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_vote_accounts_decode_unsafe(&self->vote_accounts, ctx);
  ulong stake_delegations_len;
  fd_bincode_uint64_decode_unsafe(&stake_delegations_len, ctx);
  self->stake_delegations_pool = fd_delegation_pair_t_map_alloc(ctx->valloc, stake_delegations_len);
  self->stake_delegations_root = NULL;
  for (ulong i = 0; i < stake_delegations_len; ++i) {
    fd_delegation_pair_t_mapnode_t* node = fd_delegation_pair_t_map_acquire(self->stake_delegations_pool);
    fd_delegation_pair_new(&node->elem);
    fd_delegation_pair_decode_unsafe(&node->elem, ctx);
    fd_delegation_pair_t_map_insert(self->stake_delegations_pool, &self->stake_delegations_root, node);
  }
  fd_bincode_uint64_decode_unsafe(&self->unused, ctx);
  fd_bincode_uint64_decode_unsafe(&self->epoch, ctx);
  fd_stake_history_decode_unsafe(&self->stake_history, ctx);
}
int fd_stakes_decode_offsets(fd_stakes_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->vote_accounts_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_vote_accounts_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->stake_delegations_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong stake_delegations_len;
  err = fd_bincode_uint64_decode(&stake_delegations_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  for (ulong i = 0; i < stake_delegations_len; ++i) {
    err = fd_delegation_pair_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  self->unused_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->epoch_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->stake_history_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_stake_history_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stakes_new(fd_stakes_t* self) {
  fd_memset(self, 0, sizeof(fd_stakes_t));
  fd_vote_accounts_new(&self->vote_accounts);
  fd_stake_history_new(&self->stake_history);
}
void fd_stakes_destroy(fd_stakes_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_vote_accounts_destroy(&self->vote_accounts, ctx);
  for ( fd_delegation_pair_t_mapnode_t* n = fd_delegation_pair_t_map_minimum(self->stake_delegations_pool, self->stake_delegations_root); n; n = fd_delegation_pair_t_map_successor(self->stake_delegations_pool, n) ) {
    fd_delegation_pair_destroy(&n->elem, ctx);
  }
  fd_valloc_free( ctx->valloc, fd_delegation_pair_t_map_delete(fd_delegation_pair_t_map_leave( self->stake_delegations_pool) ) );
  self->stake_delegations_pool = NULL;
  self->stake_delegations_root = NULL;
  fd_stake_history_destroy(&self->stake_history, ctx);
}

ulong fd_stakes_footprint( void ){ return FD_STAKES_FOOTPRINT; }
ulong fd_stakes_align( void ){ return FD_STAKES_ALIGN; }

void fd_stakes_walk(void * w, fd_stakes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stakes", level++);
  fd_vote_accounts_walk(w, &self->vote_accounts, fun, "vote_accounts", level);
  if (self->stake_delegations_root) {
    for ( fd_delegation_pair_t_mapnode_t* n = fd_delegation_pair_t_map_minimum(self->stake_delegations_pool, self->stake_delegations_root); n; n = fd_delegation_pair_t_map_successor(self->stake_delegations_pool, n) ) {
      fd_delegation_pair_walk(w, &n->elem, fun, "stake_delegations", level );
    }
  }
  fun( w, &self->unused, "unused", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->epoch, "epoch", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_stake_history_walk(w, &self->stake_history, fun, "stake_history", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stakes", level--);
}
ulong fd_stakes_size(fd_stakes_t const * self) {
  ulong size = 0;
  size += fd_vote_accounts_size(&self->vote_accounts);
  if (self->stake_delegations_root) {
    size += sizeof(ulong);
    for ( fd_delegation_pair_t_mapnode_t* n = fd_delegation_pair_t_map_minimum(self->stake_delegations_pool, self->stake_delegations_root); n; n = fd_delegation_pair_t_map_successor(self->stake_delegations_pool, n) ) {
      size += fd_delegation_pair_size(&n->elem);
    }
  } else {
    size += sizeof(ulong);
  }
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_stake_history_size(&self->stake_history);
  return size;
}

int fd_stakes_encode(fd_stakes_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_vote_accounts_encode(&self->vote_accounts, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->stake_delegations_root) {
    ulong stake_delegations_len = fd_delegation_pair_t_map_size(self->stake_delegations_pool, self->stake_delegations_root);
    err = fd_bincode_uint64_encode(stake_delegations_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( fd_delegation_pair_t_mapnode_t* n = fd_delegation_pair_t_map_minimum(self->stake_delegations_pool, self->stake_delegations_root); n; n = fd_delegation_pair_t_map_successor(self->stake_delegations_pool, n) ) {
      err = fd_delegation_pair_encode(&n->elem, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong stake_delegations_len = 0;
    err = fd_bincode_uint64_encode(stake_delegations_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_uint64_encode(self->unused, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_history_encode(&self->stake_history, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_bank_incremental_snapshot_persistence_decode(fd_bank_incremental_snapshot_persistence_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_bank_incremental_snapshot_persistence_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_bank_incremental_snapshot_persistence_new(self);
  fd_bank_incremental_snapshot_persistence_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_bank_incremental_snapshot_persistence_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_bank_incremental_snapshot_persistence_decode_unsafe(fd_bank_incremental_snapshot_persistence_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->full_slot, ctx);
  fd_hash_decode_unsafe(&self->full_hash, ctx);
  fd_bincode_uint64_decode_unsafe(&self->full_capitalization, ctx);
  fd_hash_decode_unsafe(&self->incremental_hash, ctx);
  fd_bincode_uint64_decode_unsafe(&self->incremental_capitalization, ctx);
}
int fd_bank_incremental_snapshot_persistence_decode_offsets(fd_bank_incremental_snapshot_persistence_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->full_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->full_hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->full_capitalization_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->incremental_hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->incremental_capitalization_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_bank_incremental_snapshot_persistence_new(fd_bank_incremental_snapshot_persistence_t* self) {
  fd_memset(self, 0, sizeof(fd_bank_incremental_snapshot_persistence_t));
  fd_hash_new(&self->full_hash);
  fd_hash_new(&self->incremental_hash);
}
void fd_bank_incremental_snapshot_persistence_destroy(fd_bank_incremental_snapshot_persistence_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_hash_destroy(&self->full_hash, ctx);
  fd_hash_destroy(&self->incremental_hash, ctx);
}

ulong fd_bank_incremental_snapshot_persistence_footprint( void ){ return FD_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FOOTPRINT; }
ulong fd_bank_incremental_snapshot_persistence_align( void ){ return FD_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_ALIGN; }

void fd_bank_incremental_snapshot_persistence_walk(void * w, fd_bank_incremental_snapshot_persistence_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bank_incremental_snapshot_persistence", level++);
  fun( w, &self->full_slot, "full_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_hash_walk(w, &self->full_hash, fun, "full_hash", level);
  fun( w, &self->full_capitalization, "full_capitalization", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_hash_walk(w, &self->incremental_hash, fun, "incremental_hash", level);
  fun( w, &self->incremental_capitalization, "incremental_capitalization", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bank_incremental_snapshot_persistence", level--);
}
ulong fd_bank_incremental_snapshot_persistence_size(fd_bank_incremental_snapshot_persistence_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_hash_size(&self->full_hash);
  size += sizeof(ulong);
  size += fd_hash_size(&self->incremental_hash);
  size += sizeof(ulong);
  return size;
}

int fd_bank_incremental_snapshot_persistence_encode(fd_bank_incremental_snapshot_persistence_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->full_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->full_hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->full_capitalization, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->incremental_hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->incremental_capitalization, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_node_vote_accounts_decode(fd_node_vote_accounts_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_node_vote_accounts_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_node_vote_accounts_new(self);
  fd_node_vote_accounts_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_node_vote_accounts_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong vote_accounts_len;
  err = fd_bincode_uint64_decode(&vote_accounts_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (vote_accounts_len != 0) {
    for( ulong i = 0; i < vote_accounts_len; ++i) {
      err = fd_pubkey_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_node_vote_accounts_decode_unsafe(fd_node_vote_accounts_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->vote_accounts_len, ctx);
  if (self->vote_accounts_len != 0) {
    self->vote_accounts = (fd_pubkey_t *)fd_valloc_malloc( ctx->valloc, FD_PUBKEY_ALIGN, FD_PUBKEY_FOOTPRINT*self->vote_accounts_len);
    for( ulong i = 0; i < self->vote_accounts_len; ++i) {
      fd_pubkey_new(self->vote_accounts + i);
      fd_pubkey_decode_unsafe(self->vote_accounts + i, ctx);
    }
  } else
    self->vote_accounts = NULL;
  fd_bincode_uint64_decode_unsafe(&self->total_stake, ctx);
}
int fd_node_vote_accounts_decode_offsets(fd_node_vote_accounts_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->vote_accounts_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong vote_accounts_len;
  err = fd_bincode_uint64_decode(&vote_accounts_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (vote_accounts_len != 0) {
    for( ulong i = 0; i < vote_accounts_len; ++i) {
      err = fd_pubkey_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->total_stake_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_node_vote_accounts_new(fd_node_vote_accounts_t* self) {
  fd_memset(self, 0, sizeof(fd_node_vote_accounts_t));
}
void fd_node_vote_accounts_destroy(fd_node_vote_accounts_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->vote_accounts) {
    for (ulong i = 0; i < self->vote_accounts_len; ++i)
      fd_pubkey_destroy(self->vote_accounts + i, ctx);
    fd_valloc_free( ctx->valloc, self->vote_accounts );
    self->vote_accounts = NULL;
  }
}

ulong fd_node_vote_accounts_footprint( void ){ return FD_NODE_VOTE_ACCOUNTS_FOOTPRINT; }
ulong fd_node_vote_accounts_align( void ){ return FD_NODE_VOTE_ACCOUNTS_ALIGN; }

void fd_node_vote_accounts_walk(void * w, fd_node_vote_accounts_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_node_vote_accounts", level++);
  if (self->vote_accounts_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "vote_accounts", level++);
    for (ulong i = 0; i < self->vote_accounts_len; ++i)
      fd_pubkey_walk(w, self->vote_accounts + i, fun, "pubkey", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "vote_accounts", level-- );
  }
  fun( w, &self->total_stake, "total_stake", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_node_vote_accounts", level--);
}
ulong fd_node_vote_accounts_size(fd_node_vote_accounts_t const * self) {
  ulong size = 0;
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->vote_accounts_len; ++i)
      size += fd_pubkey_size(self->vote_accounts + i);
  } while(0);
  size += sizeof(ulong);
  return size;
}

int fd_node_vote_accounts_encode(fd_node_vote_accounts_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->vote_accounts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->vote_accounts_len != 0) {
    for (ulong i = 0; i < self->vote_accounts_len; ++i) {
      err = fd_pubkey_encode(self->vote_accounts + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(self->total_stake, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_pubkey_node_vote_accounts_pair_decode(fd_pubkey_node_vote_accounts_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_pubkey_node_vote_accounts_pair_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_pubkey_node_vote_accounts_pair_new(self);
  fd_pubkey_node_vote_accounts_pair_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_pubkey_node_vote_accounts_pair_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_node_vote_accounts_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_pubkey_node_vote_accounts_pair_decode_unsafe(fd_pubkey_node_vote_accounts_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->key, ctx);
  fd_node_vote_accounts_decode_unsafe(&self->value, ctx);
}
int fd_pubkey_node_vote_accounts_pair_decode_offsets(fd_pubkey_node_vote_accounts_pair_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->key_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->value_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_node_vote_accounts_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_pubkey_node_vote_accounts_pair_new(fd_pubkey_node_vote_accounts_pair_t* self) {
  fd_memset(self, 0, sizeof(fd_pubkey_node_vote_accounts_pair_t));
  fd_pubkey_new(&self->key);
  fd_node_vote_accounts_new(&self->value);
}
void fd_pubkey_node_vote_accounts_pair_destroy(fd_pubkey_node_vote_accounts_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->key, ctx);
  fd_node_vote_accounts_destroy(&self->value, ctx);
}

ulong fd_pubkey_node_vote_accounts_pair_footprint( void ){ return FD_PUBKEY_NODE_VOTE_ACCOUNTS_PAIR_FOOTPRINT; }
ulong fd_pubkey_node_vote_accounts_pair_align( void ){ return FD_PUBKEY_NODE_VOTE_ACCOUNTS_PAIR_ALIGN; }

void fd_pubkey_node_vote_accounts_pair_walk(void * w, fd_pubkey_node_vote_accounts_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_pubkey_node_vote_accounts_pair", level++);
  fd_pubkey_walk(w, &self->key, fun, "key", level);
  fd_node_vote_accounts_walk(w, &self->value, fun, "value", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_pubkey_node_vote_accounts_pair", level--);
}
ulong fd_pubkey_node_vote_accounts_pair_size(fd_pubkey_node_vote_accounts_pair_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->key);
  size += fd_node_vote_accounts_size(&self->value);
  return size;
}

int fd_pubkey_node_vote_accounts_pair_encode(fd_pubkey_node_vote_accounts_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_node_vote_accounts_encode(&self->value, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_pubkey_pubkey_pair_decode(fd_pubkey_pubkey_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_pubkey_pubkey_pair_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_pubkey_pubkey_pair_new(self);
  fd_pubkey_pubkey_pair_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_pubkey_pubkey_pair_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_pubkey_pubkey_pair_decode_unsafe(fd_pubkey_pubkey_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->key, ctx);
  fd_pubkey_decode_unsafe(&self->value, ctx);
}
int fd_pubkey_pubkey_pair_decode_offsets(fd_pubkey_pubkey_pair_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->key_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->value_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_pubkey_pubkey_pair_new(fd_pubkey_pubkey_pair_t* self) {
  fd_memset(self, 0, sizeof(fd_pubkey_pubkey_pair_t));
  fd_pubkey_new(&self->key);
  fd_pubkey_new(&self->value);
}
void fd_pubkey_pubkey_pair_destroy(fd_pubkey_pubkey_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->key, ctx);
  fd_pubkey_destroy(&self->value, ctx);
}

ulong fd_pubkey_pubkey_pair_footprint( void ){ return FD_PUBKEY_PUBKEY_PAIR_FOOTPRINT; }
ulong fd_pubkey_pubkey_pair_align( void ){ return FD_PUBKEY_PUBKEY_PAIR_ALIGN; }

void fd_pubkey_pubkey_pair_walk(void * w, fd_pubkey_pubkey_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_pubkey_pubkey_pair", level++);
  fd_pubkey_walk(w, &self->key, fun, "key", level);
  fd_pubkey_walk(w, &self->value, fun, "value", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_pubkey_pubkey_pair", level--);
}
ulong fd_pubkey_pubkey_pair_size(fd_pubkey_pubkey_pair_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->key);
  size += fd_pubkey_size(&self->value);
  return size;
}

int fd_pubkey_pubkey_pair_encode(fd_pubkey_pubkey_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->value, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_epoch_stakes_decode(fd_epoch_stakes_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_epoch_stakes_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_epoch_stakes_new(self);
  fd_epoch_stakes_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_epoch_stakes_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_stakes_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ulong node_id_to_vote_accounts_len;
  err = fd_bincode_uint64_decode(&node_id_to_vote_accounts_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (node_id_to_vote_accounts_len != 0) {
    for( ulong i = 0; i < node_id_to_vote_accounts_len; ++i) {
      err = fd_pubkey_node_vote_accounts_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  ulong epoch_authorized_voters_len;
  err = fd_bincode_uint64_decode(&epoch_authorized_voters_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (epoch_authorized_voters_len != 0) {
    for( ulong i = 0; i < epoch_authorized_voters_len; ++i) {
      err = fd_pubkey_pubkey_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_epoch_stakes_decode_unsafe(fd_epoch_stakes_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_stakes_decode_unsafe(&self->stakes, ctx);
  fd_bincode_uint64_decode_unsafe(&self->total_stake, ctx);
  fd_bincode_uint64_decode_unsafe(&self->node_id_to_vote_accounts_len, ctx);
  if (self->node_id_to_vote_accounts_len != 0) {
    self->node_id_to_vote_accounts = (fd_pubkey_node_vote_accounts_pair_t *)fd_valloc_malloc( ctx->valloc, FD_PUBKEY_NODE_VOTE_ACCOUNTS_PAIR_ALIGN, FD_PUBKEY_NODE_VOTE_ACCOUNTS_PAIR_FOOTPRINT*self->node_id_to_vote_accounts_len);
    for( ulong i = 0; i < self->node_id_to_vote_accounts_len; ++i) {
      fd_pubkey_node_vote_accounts_pair_new(self->node_id_to_vote_accounts + i);
      fd_pubkey_node_vote_accounts_pair_decode_unsafe(self->node_id_to_vote_accounts + i, ctx);
    }
  } else
    self->node_id_to_vote_accounts = NULL;
  fd_bincode_uint64_decode_unsafe(&self->epoch_authorized_voters_len, ctx);
  if (self->epoch_authorized_voters_len != 0) {
    self->epoch_authorized_voters = (fd_pubkey_pubkey_pair_t *)fd_valloc_malloc( ctx->valloc, FD_PUBKEY_PUBKEY_PAIR_ALIGN, FD_PUBKEY_PUBKEY_PAIR_FOOTPRINT*self->epoch_authorized_voters_len);
    for( ulong i = 0; i < self->epoch_authorized_voters_len; ++i) {
      fd_pubkey_pubkey_pair_new(self->epoch_authorized_voters + i);
      fd_pubkey_pubkey_pair_decode_unsafe(self->epoch_authorized_voters + i, ctx);
    }
  } else
    self->epoch_authorized_voters = NULL;
}
int fd_epoch_stakes_decode_offsets(fd_epoch_stakes_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->stakes_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_stakes_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->total_stake_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->node_id_to_vote_accounts_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong node_id_to_vote_accounts_len;
  err = fd_bincode_uint64_decode(&node_id_to_vote_accounts_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (node_id_to_vote_accounts_len != 0) {
    for( ulong i = 0; i < node_id_to_vote_accounts_len; ++i) {
      err = fd_pubkey_node_vote_accounts_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->epoch_authorized_voters_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong epoch_authorized_voters_len;
  err = fd_bincode_uint64_decode(&epoch_authorized_voters_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (epoch_authorized_voters_len != 0) {
    for( ulong i = 0; i < epoch_authorized_voters_len; ++i) {
      err = fd_pubkey_pubkey_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_epoch_stakes_new(fd_epoch_stakes_t* self) {
  fd_memset(self, 0, sizeof(fd_epoch_stakes_t));
  fd_stakes_new(&self->stakes);
}
void fd_epoch_stakes_destroy(fd_epoch_stakes_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stakes_destroy(&self->stakes, ctx);
  if (NULL != self->node_id_to_vote_accounts) {
    for (ulong i = 0; i < self->node_id_to_vote_accounts_len; ++i)
      fd_pubkey_node_vote_accounts_pair_destroy(self->node_id_to_vote_accounts + i, ctx);
    fd_valloc_free( ctx->valloc, self->node_id_to_vote_accounts );
    self->node_id_to_vote_accounts = NULL;
  }
  if (NULL != self->epoch_authorized_voters) {
    for (ulong i = 0; i < self->epoch_authorized_voters_len; ++i)
      fd_pubkey_pubkey_pair_destroy(self->epoch_authorized_voters + i, ctx);
    fd_valloc_free( ctx->valloc, self->epoch_authorized_voters );
    self->epoch_authorized_voters = NULL;
  }
}

ulong fd_epoch_stakes_footprint( void ){ return FD_EPOCH_STAKES_FOOTPRINT; }
ulong fd_epoch_stakes_align( void ){ return FD_EPOCH_STAKES_ALIGN; }

void fd_epoch_stakes_walk(void * w, fd_epoch_stakes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_epoch_stakes", level++);
  fd_stakes_walk(w, &self->stakes, fun, "stakes", level);
  fun( w, &self->total_stake, "total_stake", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  if (self->node_id_to_vote_accounts_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "node_id_to_vote_accounts", level++);
    for (ulong i = 0; i < self->node_id_to_vote_accounts_len; ++i)
      fd_pubkey_node_vote_accounts_pair_walk(w, self->node_id_to_vote_accounts + i, fun, "pubkey_node_vote_accounts_pair", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "node_id_to_vote_accounts", level-- );
  }
  if (self->epoch_authorized_voters_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "epoch_authorized_voters", level++);
    for (ulong i = 0; i < self->epoch_authorized_voters_len; ++i)
      fd_pubkey_pubkey_pair_walk(w, self->epoch_authorized_voters + i, fun, "pubkey_pubkey_pair", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "epoch_authorized_voters", level-- );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_epoch_stakes", level--);
}
ulong fd_epoch_stakes_size(fd_epoch_stakes_t const * self) {
  ulong size = 0;
  size += fd_stakes_size(&self->stakes);
  size += sizeof(ulong);
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->node_id_to_vote_accounts_len; ++i)
      size += fd_pubkey_node_vote_accounts_pair_size(self->node_id_to_vote_accounts + i);
  } while(0);
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->epoch_authorized_voters_len; ++i)
      size += fd_pubkey_pubkey_pair_size(self->epoch_authorized_voters + i);
  } while(0);
  return size;
}

int fd_epoch_stakes_encode(fd_epoch_stakes_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_stakes_encode(&self->stakes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->total_stake, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->node_id_to_vote_accounts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->node_id_to_vote_accounts_len != 0) {
    for (ulong i = 0; i < self->node_id_to_vote_accounts_len; ++i) {
      err = fd_pubkey_node_vote_accounts_pair_encode(self->node_id_to_vote_accounts + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(self->epoch_authorized_voters_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->epoch_authorized_voters_len != 0) {
    for (ulong i = 0; i < self->epoch_authorized_voters_len; ++i) {
      err = fd_pubkey_pubkey_pair_encode(self->epoch_authorized_voters + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_epoch_epoch_stakes_pair_decode(fd_epoch_epoch_stakes_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_epoch_epoch_stakes_pair_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_epoch_epoch_stakes_pair_new(self);
  fd_epoch_epoch_stakes_pair_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_epoch_epoch_stakes_pair_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_epoch_stakes_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_epoch_epoch_stakes_pair_decode_unsafe(fd_epoch_epoch_stakes_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->key, ctx);
  fd_epoch_stakes_decode_unsafe(&self->value, ctx);
}
int fd_epoch_epoch_stakes_pair_decode_offsets(fd_epoch_epoch_stakes_pair_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->key_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->value_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_epoch_stakes_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_epoch_epoch_stakes_pair_new(fd_epoch_epoch_stakes_pair_t* self) {
  fd_memset(self, 0, sizeof(fd_epoch_epoch_stakes_pair_t));
  fd_epoch_stakes_new(&self->value);
}
void fd_epoch_epoch_stakes_pair_destroy(fd_epoch_epoch_stakes_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_epoch_stakes_destroy(&self->value, ctx);
}

ulong fd_epoch_epoch_stakes_pair_footprint( void ){ return FD_EPOCH_EPOCH_STAKES_PAIR_FOOTPRINT; }
ulong fd_epoch_epoch_stakes_pair_align( void ){ return FD_EPOCH_EPOCH_STAKES_PAIR_ALIGN; }

void fd_epoch_epoch_stakes_pair_walk(void * w, fd_epoch_epoch_stakes_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_epoch_epoch_stakes_pair", level++);
  fun( w, &self->key, "key", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_epoch_stakes_walk(w, &self->value, fun, "value", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_epoch_epoch_stakes_pair", level--);
}
ulong fd_epoch_epoch_stakes_pair_size(fd_epoch_epoch_stakes_pair_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_epoch_stakes_size(&self->value);
  return size;
}

int fd_epoch_epoch_stakes_pair_encode(fd_epoch_epoch_stakes_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_epoch_stakes_encode(&self->value, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_pubkey_u64_pair_decode(fd_pubkey_u64_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_pubkey_u64_pair_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_pubkey_u64_pair_new(self);
  fd_pubkey_u64_pair_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_pubkey_u64_pair_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_pubkey_u64_pair_decode_unsafe(fd_pubkey_u64_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->_0, ctx);
  fd_bincode_uint64_decode_unsafe(&self->_1, ctx);
}
int fd_pubkey_u64_pair_decode_offsets(fd_pubkey_u64_pair_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->_0_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->_1_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_pubkey_u64_pair_new(fd_pubkey_u64_pair_t* self) {
  fd_memset(self, 0, sizeof(fd_pubkey_u64_pair_t));
  fd_pubkey_new(&self->_0);
}
void fd_pubkey_u64_pair_destroy(fd_pubkey_u64_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->_0, ctx);
}

ulong fd_pubkey_u64_pair_footprint( void ){ return FD_PUBKEY_U64_PAIR_FOOTPRINT; }
ulong fd_pubkey_u64_pair_align( void ){ return FD_PUBKEY_U64_PAIR_ALIGN; }

void fd_pubkey_u64_pair_walk(void * w, fd_pubkey_u64_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_pubkey_u64_pair", level++);
  fd_pubkey_walk(w, &self->_0, fun, "_0", level);
  fun( w, &self->_1, "_1", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_pubkey_u64_pair", level--);
}
ulong fd_pubkey_u64_pair_size(fd_pubkey_u64_pair_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->_0);
  size += sizeof(ulong);
  return size;
}

int fd_pubkey_u64_pair_encode(fd_pubkey_u64_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->_0, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->_1, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_unused_accounts_decode(fd_unused_accounts_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_unused_accounts_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_unused_accounts_new(self);
  fd_unused_accounts_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_unused_accounts_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong unused1_len;
  err = fd_bincode_uint64_decode(&unused1_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (unused1_len != 0) {
    for( ulong i = 0; i < unused1_len; ++i) {
      err = fd_pubkey_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  ulong unused2_len;
  err = fd_bincode_uint64_decode(&unused2_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (unused2_len != 0) {
    for( ulong i = 0; i < unused2_len; ++i) {
      err = fd_pubkey_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  ulong unused3_len;
  err = fd_bincode_uint64_decode(&unused3_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (unused3_len != 0) {
    for( ulong i = 0; i < unused3_len; ++i) {
      err = fd_pubkey_u64_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_unused_accounts_decode_unsafe(fd_unused_accounts_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->unused1_len, ctx);
  if (self->unused1_len != 0) {
    self->unused1 = (fd_pubkey_t *)fd_valloc_malloc( ctx->valloc, FD_PUBKEY_ALIGN, FD_PUBKEY_FOOTPRINT*self->unused1_len);
    for( ulong i = 0; i < self->unused1_len; ++i) {
      fd_pubkey_new(self->unused1 + i);
      fd_pubkey_decode_unsafe(self->unused1 + i, ctx);
    }
  } else
    self->unused1 = NULL;
  fd_bincode_uint64_decode_unsafe(&self->unused2_len, ctx);
  if (self->unused2_len != 0) {
    self->unused2 = (fd_pubkey_t *)fd_valloc_malloc( ctx->valloc, FD_PUBKEY_ALIGN, FD_PUBKEY_FOOTPRINT*self->unused2_len);
    for( ulong i = 0; i < self->unused2_len; ++i) {
      fd_pubkey_new(self->unused2 + i);
      fd_pubkey_decode_unsafe(self->unused2 + i, ctx);
    }
  } else
    self->unused2 = NULL;
  fd_bincode_uint64_decode_unsafe(&self->unused3_len, ctx);
  if (self->unused3_len != 0) {
    self->unused3 = (fd_pubkey_u64_pair_t *)fd_valloc_malloc( ctx->valloc, FD_PUBKEY_U64_PAIR_ALIGN, FD_PUBKEY_U64_PAIR_FOOTPRINT*self->unused3_len);
    for( ulong i = 0; i < self->unused3_len; ++i) {
      fd_pubkey_u64_pair_new(self->unused3 + i);
      fd_pubkey_u64_pair_decode_unsafe(self->unused3 + i, ctx);
    }
  } else
    self->unused3 = NULL;
}
int fd_unused_accounts_decode_offsets(fd_unused_accounts_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->unused1_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong unused1_len;
  err = fd_bincode_uint64_decode(&unused1_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (unused1_len != 0) {
    for( ulong i = 0; i < unused1_len; ++i) {
      err = fd_pubkey_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->unused2_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong unused2_len;
  err = fd_bincode_uint64_decode(&unused2_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (unused2_len != 0) {
    for( ulong i = 0; i < unused2_len; ++i) {
      err = fd_pubkey_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->unused3_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong unused3_len;
  err = fd_bincode_uint64_decode(&unused3_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (unused3_len != 0) {
    for( ulong i = 0; i < unused3_len; ++i) {
      err = fd_pubkey_u64_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_unused_accounts_new(fd_unused_accounts_t* self) {
  fd_memset(self, 0, sizeof(fd_unused_accounts_t));
}
void fd_unused_accounts_destroy(fd_unused_accounts_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->unused1) {
    for (ulong i = 0; i < self->unused1_len; ++i)
      fd_pubkey_destroy(self->unused1 + i, ctx);
    fd_valloc_free( ctx->valloc, self->unused1 );
    self->unused1 = NULL;
  }
  if (NULL != self->unused2) {
    for (ulong i = 0; i < self->unused2_len; ++i)
      fd_pubkey_destroy(self->unused2 + i, ctx);
    fd_valloc_free( ctx->valloc, self->unused2 );
    self->unused2 = NULL;
  }
  if (NULL != self->unused3) {
    for (ulong i = 0; i < self->unused3_len; ++i)
      fd_pubkey_u64_pair_destroy(self->unused3 + i, ctx);
    fd_valloc_free( ctx->valloc, self->unused3 );
    self->unused3 = NULL;
  }
}

ulong fd_unused_accounts_footprint( void ){ return FD_UNUSED_ACCOUNTS_FOOTPRINT; }
ulong fd_unused_accounts_align( void ){ return FD_UNUSED_ACCOUNTS_ALIGN; }

void fd_unused_accounts_walk(void * w, fd_unused_accounts_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_unused_accounts", level++);
  if (self->unused1_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "unused1", level++);
    for (ulong i = 0; i < self->unused1_len; ++i)
      fd_pubkey_walk(w, self->unused1 + i, fun, "pubkey", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "unused1", level-- );
  }
  if (self->unused2_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "unused2", level++);
    for (ulong i = 0; i < self->unused2_len; ++i)
      fd_pubkey_walk(w, self->unused2 + i, fun, "pubkey", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "unused2", level-- );
  }
  if (self->unused3_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "unused3", level++);
    for (ulong i = 0; i < self->unused3_len; ++i)
      fd_pubkey_u64_pair_walk(w, self->unused3 + i, fun, "pubkey_u64_pair", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "unused3", level-- );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_unused_accounts", level--);
}
ulong fd_unused_accounts_size(fd_unused_accounts_t const * self) {
  ulong size = 0;
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->unused1_len; ++i)
      size += fd_pubkey_size(self->unused1 + i);
  } while(0);
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->unused2_len; ++i)
      size += fd_pubkey_size(self->unused2 + i);
  } while(0);
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->unused3_len; ++i)
      size += fd_pubkey_u64_pair_size(self->unused3 + i);
  } while(0);
  return size;
}

int fd_unused_accounts_encode(fd_unused_accounts_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->unused1_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->unused1_len != 0) {
    for (ulong i = 0; i < self->unused1_len; ++i) {
      err = fd_pubkey_encode(self->unused1 + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(self->unused2_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->unused2_len != 0) {
    for (ulong i = 0; i < self->unused2_len; ++i) {
      err = fd_pubkey_encode(self->unused2 + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(self->unused3_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->unused3_len != 0) {
    for (ulong i = 0; i < self->unused3_len; ++i) {
      err = fd_pubkey_u64_pair_encode(self->unused3 + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_deserializable_versioned_bank_decode(fd_deserializable_versioned_bank_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_deserializable_versioned_bank_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_deserializable_versioned_bank_new(self);
  fd_deserializable_versioned_bank_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_deserializable_versioned_bank_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_block_hash_queue_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong ancestors_len;
  err = fd_bincode_uint64_decode(&ancestors_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (ancestors_len != 0) {
    for( ulong i = 0; i < ancestors_len; ++i) {
      err = fd_slot_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_hard_forks_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint128_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_fee_calculator_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_rate_governor_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_rent_collector_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_epoch_schedule_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_inflation_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stakes_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_unused_accounts_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong epoch_stakes_len;
  err = fd_bincode_uint64_decode(&epoch_stakes_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (epoch_stakes_len != 0) {
    for( ulong i = 0; i < epoch_stakes_len; ++i) {
      err = fd_epoch_epoch_stakes_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_bool_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_deserializable_versioned_bank_decode_unsafe(fd_deserializable_versioned_bank_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_block_hash_queue_decode_unsafe(&self->blockhash_queue, ctx);
  fd_bincode_uint64_decode_unsafe(&self->ancestors_len, ctx);
  if (self->ancestors_len != 0) {
    self->ancestors = (fd_slot_pair_t *)fd_valloc_malloc( ctx->valloc, FD_SLOT_PAIR_ALIGN, FD_SLOT_PAIR_FOOTPRINT*self->ancestors_len);
    for( ulong i = 0; i < self->ancestors_len; ++i) {
      fd_slot_pair_new(self->ancestors + i);
      fd_slot_pair_decode_unsafe(self->ancestors + i, ctx);
    }
  } else
    self->ancestors = NULL;
  fd_hash_decode_unsafe(&self->hash, ctx);
  fd_hash_decode_unsafe(&self->parent_hash, ctx);
  fd_bincode_uint64_decode_unsafe(&self->parent_slot, ctx);
  fd_hard_forks_decode_unsafe(&self->hard_forks, ctx);
  fd_bincode_uint64_decode_unsafe(&self->transaction_count, ctx);
  fd_bincode_uint64_decode_unsafe(&self->tick_height, ctx);
  fd_bincode_uint64_decode_unsafe(&self->signature_count, ctx);
  fd_bincode_uint64_decode_unsafe(&self->capitalization, ctx);
  fd_bincode_uint64_decode_unsafe(&self->max_tick_height, ctx);
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      self->hashes_per_tick = fd_valloc_malloc( ctx->valloc, 8, sizeof(ulong) );
      fd_bincode_uint64_decode_unsafe( self->hashes_per_tick, ctx );
    } else
      self->hashes_per_tick = NULL;
  }
  fd_bincode_uint64_decode_unsafe(&self->ticks_per_slot, ctx);
  fd_bincode_uint128_decode_unsafe(&self->ns_per_slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->genesis_creation_time, ctx);
  fd_bincode_double_decode_unsafe(&self->slots_per_year, ctx);
  fd_bincode_uint64_decode_unsafe(&self->accounts_data_len, ctx);
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->epoch, ctx);
  fd_bincode_uint64_decode_unsafe(&self->block_height, ctx);
  fd_pubkey_decode_unsafe(&self->collector_id, ctx);
  fd_bincode_uint64_decode_unsafe(&self->collector_fees, ctx);
  fd_fee_calculator_decode_unsafe(&self->fee_calculator, ctx);
  fd_fee_rate_governor_decode_unsafe(&self->fee_rate_governor, ctx);
  fd_bincode_uint64_decode_unsafe(&self->collected_rent, ctx);
  fd_rent_collector_decode_unsafe(&self->rent_collector, ctx);
  fd_epoch_schedule_decode_unsafe(&self->epoch_schedule, ctx);
  fd_inflation_decode_unsafe(&self->inflation, ctx);
  fd_stakes_decode_unsafe(&self->stakes, ctx);
  fd_unused_accounts_decode_unsafe(&self->unused_accounts, ctx);
  fd_bincode_uint64_decode_unsafe(&self->epoch_stakes_len, ctx);
  if (self->epoch_stakes_len != 0) {
    self->epoch_stakes = (fd_epoch_epoch_stakes_pair_t *)fd_valloc_malloc( ctx->valloc, FD_EPOCH_EPOCH_STAKES_PAIR_ALIGN, FD_EPOCH_EPOCH_STAKES_PAIR_FOOTPRINT*self->epoch_stakes_len);
    for( ulong i = 0; i < self->epoch_stakes_len; ++i) {
      fd_epoch_epoch_stakes_pair_new(self->epoch_stakes + i);
      fd_epoch_epoch_stakes_pair_decode_unsafe(self->epoch_stakes + i, ctx);
    }
  } else
    self->epoch_stakes = NULL;
  fd_bincode_bool_decode_unsafe(&self->is_delta, ctx);
}
int fd_deserializable_versioned_bank_decode_offsets(fd_deserializable_versioned_bank_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->blockhash_queue_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_block_hash_queue_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->ancestors_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong ancestors_len;
  err = fd_bincode_uint64_decode(&ancestors_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (ancestors_len != 0) {
    for( ulong i = 0; i < ancestors_len; ++i) {
      err = fd_slot_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->parent_hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->parent_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->hard_forks_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hard_forks_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->transaction_count_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->tick_height_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->signature_count_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->capitalization_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->max_tick_height_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->hashes_per_tick_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->ticks_per_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->ns_per_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint128_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->genesis_creation_time_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->slots_per_year_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->accounts_data_len_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->epoch_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->block_height_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->collector_id_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->collector_fees_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->fee_calculator_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_fee_calculator_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->fee_rate_governor_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_fee_rate_governor_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->collected_rent_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->rent_collector_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_rent_collector_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->epoch_schedule_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_epoch_schedule_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->inflation_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_inflation_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->stakes_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_stakes_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->unused_accounts_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_unused_accounts_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->epoch_stakes_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong epoch_stakes_len;
  err = fd_bincode_uint64_decode(&epoch_stakes_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (epoch_stakes_len != 0) {
    for( ulong i = 0; i < epoch_stakes_len; ++i) {
      err = fd_epoch_epoch_stakes_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->is_delta_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bool_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_deserializable_versioned_bank_new(fd_deserializable_versioned_bank_t* self) {
  fd_memset(self, 0, sizeof(fd_deserializable_versioned_bank_t));
  fd_block_hash_queue_new(&self->blockhash_queue);
  fd_hash_new(&self->hash);
  fd_hash_new(&self->parent_hash);
  fd_hard_forks_new(&self->hard_forks);
  fd_pubkey_new(&self->collector_id);
  fd_fee_calculator_new(&self->fee_calculator);
  fd_fee_rate_governor_new(&self->fee_rate_governor);
  fd_rent_collector_new(&self->rent_collector);
  fd_epoch_schedule_new(&self->epoch_schedule);
  fd_inflation_new(&self->inflation);
  fd_stakes_new(&self->stakes);
  fd_unused_accounts_new(&self->unused_accounts);
}
void fd_deserializable_versioned_bank_destroy(fd_deserializable_versioned_bank_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_block_hash_queue_destroy(&self->blockhash_queue, ctx);
  if (NULL != self->ancestors) {
    for (ulong i = 0; i < self->ancestors_len; ++i)
      fd_slot_pair_destroy(self->ancestors + i, ctx);
    fd_valloc_free( ctx->valloc, self->ancestors );
    self->ancestors = NULL;
  }
  fd_hash_destroy(&self->hash, ctx);
  fd_hash_destroy(&self->parent_hash, ctx);
  fd_hard_forks_destroy(&self->hard_forks, ctx);
  if( NULL != self->hashes_per_tick ) {
    fd_valloc_free( ctx->valloc, self->hashes_per_tick );
    self->hashes_per_tick = NULL;
  }
  fd_pubkey_destroy(&self->collector_id, ctx);
  fd_fee_calculator_destroy(&self->fee_calculator, ctx);
  fd_fee_rate_governor_destroy(&self->fee_rate_governor, ctx);
  fd_rent_collector_destroy(&self->rent_collector, ctx);
  fd_epoch_schedule_destroy(&self->epoch_schedule, ctx);
  fd_inflation_destroy(&self->inflation, ctx);
  fd_stakes_destroy(&self->stakes, ctx);
  fd_unused_accounts_destroy(&self->unused_accounts, ctx);
  if (NULL != self->epoch_stakes) {
    for (ulong i = 0; i < self->epoch_stakes_len; ++i)
      fd_epoch_epoch_stakes_pair_destroy(self->epoch_stakes + i, ctx);
    fd_valloc_free( ctx->valloc, self->epoch_stakes );
    self->epoch_stakes = NULL;
  }
}

ulong fd_deserializable_versioned_bank_footprint( void ){ return FD_DESERIALIZABLE_VERSIONED_BANK_FOOTPRINT; }
ulong fd_deserializable_versioned_bank_align( void ){ return FD_DESERIALIZABLE_VERSIONED_BANK_ALIGN; }

void fd_deserializable_versioned_bank_walk(void * w, fd_deserializable_versioned_bank_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_deserializable_versioned_bank", level++);
  fd_block_hash_queue_walk(w, &self->blockhash_queue, fun, "blockhash_queue", level);
  if (self->ancestors_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "ancestors", level++);
    for (ulong i = 0; i < self->ancestors_len; ++i)
      fd_slot_pair_walk(w, self->ancestors + i, fun, "slot_pair", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "ancestors", level-- );
  }
  fd_hash_walk(w, &self->hash, fun, "hash", level);
  fd_hash_walk(w, &self->parent_hash, fun, "parent_hash", level);
  fun( w, &self->parent_slot, "parent_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_hard_forks_walk(w, &self->hard_forks, fun, "hard_forks", level);
  fun( w, &self->transaction_count, "transaction_count", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->tick_height, "tick_height", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->signature_count, "signature_count", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->capitalization, "capitalization", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->max_tick_height, "max_tick_height", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  if( !self->hashes_per_tick ) {
    fun( w, NULL, "hashes_per_tick", FD_FLAMENCO_TYPE_NULL, "ulong", level );
  } else {
    fun( w, self->hashes_per_tick, "hashes_per_tick", FD_FLAMENCO_TYPE_ULONG, "ulong", level );
  }
  fun( w, &self->ticks_per_slot, "ticks_per_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->ns_per_slot, "ns_per_slot", FD_FLAMENCO_TYPE_UINT128, "uint128",   level );
  fun( w, &self->genesis_creation_time, "genesis_creation_time", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->slots_per_year, "slots_per_year", FD_FLAMENCO_TYPE_DOUBLE,  "double",    level );
  fun( w, &self->accounts_data_len, "accounts_data_len", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->epoch, "epoch", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->block_height, "block_height", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_pubkey_walk(w, &self->collector_id, fun, "collector_id", level);
  fun( w, &self->collector_fees, "collector_fees", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_fee_calculator_walk(w, &self->fee_calculator, fun, "fee_calculator", level);
  fd_fee_rate_governor_walk(w, &self->fee_rate_governor, fun, "fee_rate_governor", level);
  fun( w, &self->collected_rent, "collected_rent", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_rent_collector_walk(w, &self->rent_collector, fun, "rent_collector", level);
  fd_epoch_schedule_walk(w, &self->epoch_schedule, fun, "epoch_schedule", level);
  fd_inflation_walk(w, &self->inflation, fun, "inflation", level);
  fd_stakes_walk(w, &self->stakes, fun, "stakes", level);
  fd_unused_accounts_walk(w, &self->unused_accounts, fun, "unused_accounts", level);
  if (self->epoch_stakes_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "epoch_stakes", level++);
    for (ulong i = 0; i < self->epoch_stakes_len; ++i)
      fd_epoch_epoch_stakes_pair_walk(w, self->epoch_stakes + i, fun, "epoch_epoch_stakes_pair", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "epoch_stakes", level-- );
  }
  fun( w, &self->is_delta, "is_delta", FD_FLAMENCO_TYPE_BOOL,    "bool",      level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_deserializable_versioned_bank", level--);
}
ulong fd_deserializable_versioned_bank_size(fd_deserializable_versioned_bank_t const * self) {
  ulong size = 0;
  size += fd_block_hash_queue_size(&self->blockhash_queue);
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->ancestors_len; ++i)
      size += fd_slot_pair_size(self->ancestors + i);
  } while(0);
  size += fd_hash_size(&self->hash);
  size += fd_hash_size(&self->parent_hash);
  size += sizeof(ulong);
  size += fd_hard_forks_size(&self->hard_forks);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(char);
  if( NULL !=  self->hashes_per_tick ) {
    size += sizeof(ulong);
  }
  size += sizeof(ulong);
  size += sizeof(uint128);
  size += sizeof(ulong);
  size += sizeof(double);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_pubkey_size(&self->collector_id);
  size += sizeof(ulong);
  size += fd_fee_calculator_size(&self->fee_calculator);
  size += fd_fee_rate_governor_size(&self->fee_rate_governor);
  size += sizeof(ulong);
  size += fd_rent_collector_size(&self->rent_collector);
  size += fd_epoch_schedule_size(&self->epoch_schedule);
  size += fd_inflation_size(&self->inflation);
  size += fd_stakes_size(&self->stakes);
  size += fd_unused_accounts_size(&self->unused_accounts);
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->epoch_stakes_len; ++i)
      size += fd_epoch_epoch_stakes_pair_size(self->epoch_stakes + i);
  } while(0);
  size += sizeof(char);
  return size;
}

int fd_deserializable_versioned_bank_encode(fd_deserializable_versioned_bank_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_block_hash_queue_encode(&self->blockhash_queue, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->ancestors_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->ancestors_len != 0) {
    for (ulong i = 0; i < self->ancestors_len; ++i) {
      err = fd_slot_pair_encode(self->ancestors + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->parent_hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->parent_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hard_forks_encode(&self->hard_forks, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->transaction_count, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->tick_height, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->signature_count, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->capitalization, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->max_tick_height, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if( self->hashes_per_tick != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_bincode_uint64_encode( self->hashes_per_tick[0], ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint64_encode(self->ticks_per_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint128_encode( self->ns_per_slot, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->genesis_creation_time, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode( self->slots_per_year, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->accounts_data_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->block_height, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->collector_id, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->collector_fees, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_calculator_encode(&self->fee_calculator, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_rate_governor_encode(&self->fee_rate_governor, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->collected_rent, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_rent_collector_encode(&self->rent_collector, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_epoch_schedule_encode(&self->epoch_schedule, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_inflation_encode(&self->inflation, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stakes_encode(&self->stakes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_unused_accounts_encode(&self->unused_accounts, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->epoch_stakes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->epoch_stakes_len != 0) {
    for (ulong i = 0; i < self->epoch_stakes_len; ++i) {
      err = fd_epoch_epoch_stakes_pair_encode(self->epoch_stakes + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_bool_encode( (uchar)(self->is_delta), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_bank_hash_stats_decode(fd_bank_hash_stats_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_bank_hash_stats_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_bank_hash_stats_new(self);
  fd_bank_hash_stats_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_bank_hash_stats_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_bank_hash_stats_decode_unsafe(fd_bank_hash_stats_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->num_updated_accounts, ctx);
  fd_bincode_uint64_decode_unsafe(&self->num_removed_accounts, ctx);
  fd_bincode_uint64_decode_unsafe(&self->num_lamports_stored, ctx);
  fd_bincode_uint64_decode_unsafe(&self->total_data_len, ctx);
  fd_bincode_uint64_decode_unsafe(&self->num_executable_accounts, ctx);
}
int fd_bank_hash_stats_decode_offsets(fd_bank_hash_stats_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->num_updated_accounts_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->num_removed_accounts_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->num_lamports_stored_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->total_data_len_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->num_executable_accounts_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_bank_hash_stats_new(fd_bank_hash_stats_t* self) {
  fd_memset(self, 0, sizeof(fd_bank_hash_stats_t));
}
void fd_bank_hash_stats_destroy(fd_bank_hash_stats_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_bank_hash_stats_footprint( void ){ return FD_BANK_HASH_STATS_FOOTPRINT; }
ulong fd_bank_hash_stats_align( void ){ return FD_BANK_HASH_STATS_ALIGN; }

void fd_bank_hash_stats_walk(void * w, fd_bank_hash_stats_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bank_hash_stats", level++);
  fun( w, &self->num_updated_accounts, "num_updated_accounts", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->num_removed_accounts, "num_removed_accounts", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->num_lamports_stored, "num_lamports_stored", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->total_data_len, "total_data_len", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->num_executable_accounts, "num_executable_accounts", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bank_hash_stats", level--);
}
ulong fd_bank_hash_stats_size(fd_bank_hash_stats_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_bank_hash_stats_encode(fd_bank_hash_stats_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->num_updated_accounts, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->num_removed_accounts, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->num_lamports_stored, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->total_data_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->num_executable_accounts, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_bank_hash_info_decode(fd_bank_hash_info_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_bank_hash_info_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_bank_hash_info_new(self);
  fd_bank_hash_info_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_bank_hash_info_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bank_hash_stats_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_bank_hash_info_decode_unsafe(fd_bank_hash_info_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_hash_decode_unsafe(&self->hash, ctx);
  fd_hash_decode_unsafe(&self->snapshot_hash, ctx);
  fd_bank_hash_stats_decode_unsafe(&self->stats, ctx);
}
int fd_bank_hash_info_decode_offsets(fd_bank_hash_info_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->snapshot_hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->stats_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bank_hash_stats_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_bank_hash_info_new(fd_bank_hash_info_t* self) {
  fd_memset(self, 0, sizeof(fd_bank_hash_info_t));
  fd_hash_new(&self->hash);
  fd_hash_new(&self->snapshot_hash);
  fd_bank_hash_stats_new(&self->stats);
}
void fd_bank_hash_info_destroy(fd_bank_hash_info_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_hash_destroy(&self->hash, ctx);
  fd_hash_destroy(&self->snapshot_hash, ctx);
  fd_bank_hash_stats_destroy(&self->stats, ctx);
}

ulong fd_bank_hash_info_footprint( void ){ return FD_BANK_HASH_INFO_FOOTPRINT; }
ulong fd_bank_hash_info_align( void ){ return FD_BANK_HASH_INFO_ALIGN; }

void fd_bank_hash_info_walk(void * w, fd_bank_hash_info_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bank_hash_info", level++);
  fd_hash_walk(w, &self->hash, fun, "hash", level);
  fd_hash_walk(w, &self->snapshot_hash, fun, "snapshot_hash", level);
  fd_bank_hash_stats_walk(w, &self->stats, fun, "stats", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bank_hash_info", level--);
}
ulong fd_bank_hash_info_size(fd_bank_hash_info_t const * self) {
  ulong size = 0;
  size += fd_hash_size(&self->hash);
  size += fd_hash_size(&self->snapshot_hash);
  size += fd_bank_hash_stats_size(&self->stats);
  return size;
}

int fd_bank_hash_info_encode(fd_bank_hash_info_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->snapshot_hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bank_hash_stats_encode(&self->stats, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_slot_map_pair_decode(fd_slot_map_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_slot_map_pair_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_slot_map_pair_new(self);
  fd_slot_map_pair_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_slot_map_pair_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_map_pair_decode_unsafe(fd_slot_map_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
  fd_hash_decode_unsafe(&self->hash, ctx);
}
int fd_slot_map_pair_decode_offsets(fd_slot_map_pair_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_map_pair_new(fd_slot_map_pair_t* self) {
  fd_memset(self, 0, sizeof(fd_slot_map_pair_t));
  fd_hash_new(&self->hash);
}
void fd_slot_map_pair_destroy(fd_slot_map_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_hash_destroy(&self->hash, ctx);
}

ulong fd_slot_map_pair_footprint( void ){ return FD_SLOT_MAP_PAIR_FOOTPRINT; }
ulong fd_slot_map_pair_align( void ){ return FD_SLOT_MAP_PAIR_ALIGN; }

void fd_slot_map_pair_walk(void * w, fd_slot_map_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_slot_map_pair", level++);
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_hash_walk(w, &self->hash, fun, "hash", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_slot_map_pair", level--);
}
ulong fd_slot_map_pair_size(fd_slot_map_pair_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_hash_size(&self->hash);
  return size;
}

int fd_slot_map_pair_encode(fd_slot_map_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_snapshot_acc_vec_decode(fd_snapshot_acc_vec_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_snapshot_acc_vec_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_snapshot_acc_vec_new(self);
  fd_snapshot_acc_vec_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_snapshot_acc_vec_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_snapshot_acc_vec_decode_unsafe(fd_snapshot_acc_vec_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->id, ctx);
  fd_bincode_uint64_decode_unsafe(&self->file_sz, ctx);
}
int fd_snapshot_acc_vec_decode_offsets(fd_snapshot_acc_vec_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->id_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->file_sz_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_snapshot_acc_vec_new(fd_snapshot_acc_vec_t* self) {
  fd_memset(self, 0, sizeof(fd_snapshot_acc_vec_t));
}
void fd_snapshot_acc_vec_destroy(fd_snapshot_acc_vec_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_snapshot_acc_vec_footprint( void ){ return FD_SNAPSHOT_ACC_VEC_FOOTPRINT; }
ulong fd_snapshot_acc_vec_align( void ){ return FD_SNAPSHOT_ACC_VEC_ALIGN; }

void fd_snapshot_acc_vec_walk(void * w, fd_snapshot_acc_vec_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_snapshot_acc_vec", level++);
  fun( w, &self->id, "id", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->file_sz, "file_sz", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_snapshot_acc_vec", level--);
}
ulong fd_snapshot_acc_vec_size(fd_snapshot_acc_vec_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_snapshot_acc_vec_encode(fd_snapshot_acc_vec_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->id, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->file_sz, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_snapshot_slot_acc_vecs_decode(fd_snapshot_slot_acc_vecs_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_snapshot_slot_acc_vecs_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_snapshot_slot_acc_vecs_new(self);
  fd_snapshot_slot_acc_vecs_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_snapshot_slot_acc_vecs_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ulong account_vecs_len;
  err = fd_bincode_uint64_decode(&account_vecs_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (account_vecs_len != 0) {
    for( ulong i = 0; i < account_vecs_len; ++i) {
      err = fd_snapshot_acc_vec_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_snapshot_slot_acc_vecs_decode_unsafe(fd_snapshot_slot_acc_vecs_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->account_vecs_len, ctx);
  if (self->account_vecs_len != 0) {
    self->account_vecs = (fd_snapshot_acc_vec_t *)fd_valloc_malloc( ctx->valloc, FD_SNAPSHOT_ACC_VEC_ALIGN, FD_SNAPSHOT_ACC_VEC_FOOTPRINT*self->account_vecs_len);
    for( ulong i = 0; i < self->account_vecs_len; ++i) {
      fd_snapshot_acc_vec_new(self->account_vecs + i);
      fd_snapshot_acc_vec_decode_unsafe(self->account_vecs + i, ctx);
    }
  } else
    self->account_vecs = NULL;
}
int fd_snapshot_slot_acc_vecs_decode_offsets(fd_snapshot_slot_acc_vecs_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->account_vecs_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong account_vecs_len;
  err = fd_bincode_uint64_decode(&account_vecs_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (account_vecs_len != 0) {
    for( ulong i = 0; i < account_vecs_len; ++i) {
      err = fd_snapshot_acc_vec_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_snapshot_slot_acc_vecs_new(fd_snapshot_slot_acc_vecs_t* self) {
  fd_memset(self, 0, sizeof(fd_snapshot_slot_acc_vecs_t));
}
void fd_snapshot_slot_acc_vecs_destroy(fd_snapshot_slot_acc_vecs_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->account_vecs) {
    for (ulong i = 0; i < self->account_vecs_len; ++i)
      fd_snapshot_acc_vec_destroy(self->account_vecs + i, ctx);
    fd_valloc_free( ctx->valloc, self->account_vecs );
    self->account_vecs = NULL;
  }
}

ulong fd_snapshot_slot_acc_vecs_footprint( void ){ return FD_SNAPSHOT_SLOT_ACC_VECS_FOOTPRINT; }
ulong fd_snapshot_slot_acc_vecs_align( void ){ return FD_SNAPSHOT_SLOT_ACC_VECS_ALIGN; }

void fd_snapshot_slot_acc_vecs_walk(void * w, fd_snapshot_slot_acc_vecs_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_snapshot_slot_acc_vecs", level++);
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  if (self->account_vecs_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "account_vecs", level++);
    for (ulong i = 0; i < self->account_vecs_len; ++i)
      fd_snapshot_acc_vec_walk(w, self->account_vecs + i, fun, "snapshot_acc_vec", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "account_vecs", level-- );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_snapshot_slot_acc_vecs", level--);
}
ulong fd_snapshot_slot_acc_vecs_size(fd_snapshot_slot_acc_vecs_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->account_vecs_len; ++i)
      size += fd_snapshot_acc_vec_size(self->account_vecs + i);
  } while(0);
  return size;
}

int fd_snapshot_slot_acc_vecs_encode(fd_snapshot_slot_acc_vecs_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->account_vecs_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->account_vecs_len != 0) {
    for (ulong i = 0; i < self->account_vecs_len; ++i) {
      err = fd_snapshot_acc_vec_encode(self->account_vecs + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_reward_type_is_fee(fd_reward_type_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_reward_type_is_rent(fd_reward_type_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_reward_type_is_staking(fd_reward_type_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_reward_type_is_voting(fd_reward_type_t const * self) {
  return self->discriminant == 3;
}
void fd_reward_type_inner_new(fd_reward_type_inner_t* self, uint discriminant);
int fd_reward_type_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_reward_type_inner_decode_unsafe(fd_reward_type_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    break;
  }
  }
}
int fd_reward_type_decode(fd_reward_type_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_reward_type_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_reward_type_new(self);
  fd_reward_type_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_reward_type_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_reward_type_inner_decode_preflight(discriminant, ctx);
}
void fd_reward_type_decode_unsafe(fd_reward_type_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_reward_type_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_reward_type_inner_new(fd_reward_type_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_reward_type_new_disc(fd_reward_type_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_reward_type_inner_new(&self->inner, self->discriminant);
}
void fd_reward_type_new(fd_reward_type_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_reward_type_new_disc(self, UINT_MAX);
}
void fd_reward_type_inner_destroy(fd_reward_type_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_reward_type_destroy(fd_reward_type_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_reward_type_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_reward_type_footprint( void ){ return FD_REWARD_TYPE_FOOTPRINT; }
ulong fd_reward_type_align( void ){ return FD_REWARD_TYPE_ALIGN; }

void fd_reward_type_walk(void * w, fd_reward_type_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_reward_type", level++);
  switch (self->discriminant) {
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_reward_type", level--);
}
ulong fd_reward_type_size(fd_reward_type_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  }
  return size;
}

int fd_reward_type_inner_encode(fd_reward_type_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  return FD_BINCODE_SUCCESS;
}
int fd_reward_type_encode(fd_reward_type_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_reward_type_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_reward_info_decode(fd_reward_info_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_reward_info_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_reward_info_new(self);
  fd_reward_info_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_reward_info_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_reward_type_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_reward_info_decode_unsafe(fd_reward_info_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_reward_type_decode_unsafe(&self->reward_type, ctx);
  fd_bincode_uint64_decode_unsafe(&self->lamports, ctx);
  fd_bincode_uint64_decode_unsafe(&self->staker_rewards, ctx);
  fd_bincode_uint64_decode_unsafe(&self->new_credits_observed, ctx);
  fd_bincode_uint64_decode_unsafe(&self->post_balance, ctx);
  fd_bincode_uint64_decode_unsafe((ulong *) &self->commission, ctx);
}
int fd_reward_info_decode_offsets(fd_reward_info_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->reward_type_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_reward_type_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->lamports_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->staker_rewards_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->new_credits_observed_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->post_balance_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->commission_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_reward_info_new(fd_reward_info_t* self) {
  fd_memset(self, 0, sizeof(fd_reward_info_t));
  fd_reward_type_new(&self->reward_type);
}
void fd_reward_info_destroy(fd_reward_info_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_reward_type_destroy(&self->reward_type, ctx);
}

ulong fd_reward_info_footprint( void ){ return FD_REWARD_INFO_FOOTPRINT; }
ulong fd_reward_info_align( void ){ return FD_REWARD_INFO_ALIGN; }

void fd_reward_info_walk(void * w, fd_reward_info_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_reward_info", level++);
  fd_reward_type_walk(w, &self->reward_type, fun, "reward_type", level);
  fun( w, &self->lamports, "lamports", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->staker_rewards, "staker_rewards", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->new_credits_observed, "new_credits_observed", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->post_balance, "post_balance", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->commission, "commission", FD_FLAMENCO_TYPE_SLONG,   "long",      level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_reward_info", level--);
}
ulong fd_reward_info_size(fd_reward_info_t const * self) {
  ulong size = 0;
  size += fd_reward_type_size(&self->reward_type);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(long);
  return size;
}

int fd_reward_info_encode(fd_reward_info_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_reward_type_encode(&self->reward_type, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->lamports, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->staker_rewards, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->new_credits_observed, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->post_balance, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode( (ulong)self->commission, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_reward_decode(fd_stake_reward_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_reward_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_reward_new(self);
  fd_stake_reward_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_reward_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_reward_info_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_reward_decode_unsafe(fd_stake_reward_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->stake_pubkey, ctx);
  fd_reward_info_decode_unsafe(&self->reward_info, ctx);
}
int fd_stake_reward_decode_offsets(fd_stake_reward_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->stake_pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->reward_info_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_reward_info_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_reward_new(fd_stake_reward_t* self) {
  fd_memset(self, 0, sizeof(fd_stake_reward_t));
  fd_pubkey_new(&self->stake_pubkey);
  fd_reward_info_new(&self->reward_info);
}
void fd_stake_reward_destroy(fd_stake_reward_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->stake_pubkey, ctx);
  fd_reward_info_destroy(&self->reward_info, ctx);
}

ulong fd_stake_reward_footprint( void ){ return FD_STAKE_REWARD_FOOTPRINT; }
ulong fd_stake_reward_align( void ){ return FD_STAKE_REWARD_ALIGN; }

void fd_stake_reward_walk(void * w, fd_stake_reward_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_reward", level++);
  fd_pubkey_walk(w, &self->stake_pubkey, fun, "stake_pubkey", level);
  fd_reward_info_walk(w, &self->reward_info, fun, "reward_info", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_reward", level--);
}
ulong fd_stake_reward_size(fd_stake_reward_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->stake_pubkey);
  size += fd_reward_info_size(&self->reward_info);
  return size;
}

int fd_stake_reward_encode(fd_stake_reward_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->stake_pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_reward_info_encode(&self->reward_info, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_serializable_stake_rewards_decode(fd_serializable_stake_rewards_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_serializable_stake_rewards_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_serializable_stake_rewards_new(self);
  fd_serializable_stake_rewards_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_serializable_stake_rewards_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong body_len;
  err = fd_bincode_uint64_decode(&body_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (body_len != 0) {
    for( ulong i = 0; i < body_len; ++i) {
      err = fd_stake_reward_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_serializable_stake_rewards_decode_unsafe(fd_serializable_stake_rewards_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->body_len, ctx);
  if (self->body_len != 0) {
    self->body = (fd_stake_reward_t *)fd_valloc_malloc( ctx->valloc, FD_STAKE_REWARD_ALIGN, FD_STAKE_REWARD_FOOTPRINT*self->body_len);
    for( ulong i = 0; i < self->body_len; ++i) {
      fd_stake_reward_new(self->body + i);
      fd_stake_reward_decode_unsafe(self->body + i, ctx);
    }
  } else
    self->body = NULL;
}
int fd_serializable_stake_rewards_decode_offsets(fd_serializable_stake_rewards_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->body_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong body_len;
  err = fd_bincode_uint64_decode(&body_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (body_len != 0) {
    for( ulong i = 0; i < body_len; ++i) {
      err = fd_stake_reward_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_serializable_stake_rewards_new(fd_serializable_stake_rewards_t* self) {
  fd_memset(self, 0, sizeof(fd_serializable_stake_rewards_t));
}
void fd_serializable_stake_rewards_destroy(fd_serializable_stake_rewards_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->body) {
    for (ulong i = 0; i < self->body_len; ++i)
      fd_stake_reward_destroy(self->body + i, ctx);
    fd_valloc_free( ctx->valloc, self->body );
    self->body = NULL;
  }
}

ulong fd_serializable_stake_rewards_footprint( void ){ return FD_SERIALIZABLE_STAKE_REWARDS_FOOTPRINT; }
ulong fd_serializable_stake_rewards_align( void ){ return FD_SERIALIZABLE_STAKE_REWARDS_ALIGN; }

void fd_serializable_stake_rewards_walk(void * w, fd_serializable_stake_rewards_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_serializable_stake_rewards", level++);
  if (self->body_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "body", level++);
    for (ulong i = 0; i < self->body_len; ++i)
      fd_stake_reward_walk(w, self->body + i, fun, "stake_reward", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "body", level-- );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_serializable_stake_rewards", level--);
}
ulong fd_serializable_stake_rewards_size(fd_serializable_stake_rewards_t const * self) {
  ulong size = 0;
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->body_len; ++i)
      size += fd_stake_reward_size(self->body + i);
  } while(0);
  return size;
}

int fd_serializable_stake_rewards_encode(fd_serializable_stake_rewards_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->body_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->body_len != 0) {
    for (ulong i = 0; i < self->body_len; ++i) {
      err = fd_stake_reward_encode(self->body + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_start_block_height_and_rewards_decode(fd_start_block_height_and_rewards_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_start_block_height_and_rewards_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_start_block_height_and_rewards_new(self);
  fd_start_block_height_and_rewards_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_start_block_height_and_rewards_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ulong stake_rewards_by_partition_len;
  err = fd_bincode_uint64_decode(&stake_rewards_by_partition_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (stake_rewards_by_partition_len != 0) {
    for( ulong i = 0; i < stake_rewards_by_partition_len; ++i) {
      err = fd_serializable_stake_rewards_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_start_block_height_and_rewards_decode_unsafe(fd_start_block_height_and_rewards_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->start_block_height, ctx);
  fd_bincode_uint64_decode_unsafe(&self->stake_rewards_by_partition_len, ctx);
  if (self->stake_rewards_by_partition_len != 0) {
    self->stake_rewards_by_partition = (fd_serializable_stake_rewards_t *)fd_valloc_malloc( ctx->valloc, FD_SERIALIZABLE_STAKE_REWARDS_ALIGN, FD_SERIALIZABLE_STAKE_REWARDS_FOOTPRINT*self->stake_rewards_by_partition_len);
    for( ulong i = 0; i < self->stake_rewards_by_partition_len; ++i) {
      fd_serializable_stake_rewards_new(self->stake_rewards_by_partition + i);
      fd_serializable_stake_rewards_decode_unsafe(self->stake_rewards_by_partition + i, ctx);
    }
  } else
    self->stake_rewards_by_partition = NULL;
}
int fd_start_block_height_and_rewards_decode_offsets(fd_start_block_height_and_rewards_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->start_block_height_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->stake_rewards_by_partition_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong stake_rewards_by_partition_len;
  err = fd_bincode_uint64_decode(&stake_rewards_by_partition_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (stake_rewards_by_partition_len != 0) {
    for( ulong i = 0; i < stake_rewards_by_partition_len; ++i) {
      err = fd_serializable_stake_rewards_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_start_block_height_and_rewards_new(fd_start_block_height_and_rewards_t* self) {
  fd_memset(self, 0, sizeof(fd_start_block_height_and_rewards_t));
}
void fd_start_block_height_and_rewards_destroy(fd_start_block_height_and_rewards_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->stake_rewards_by_partition) {
    for (ulong i = 0; i < self->stake_rewards_by_partition_len; ++i)
      fd_serializable_stake_rewards_destroy(self->stake_rewards_by_partition + i, ctx);
    fd_valloc_free( ctx->valloc, self->stake_rewards_by_partition );
    self->stake_rewards_by_partition = NULL;
  }
}

ulong fd_start_block_height_and_rewards_footprint( void ){ return FD_START_BLOCK_HEIGHT_AND_REWARDS_FOOTPRINT; }
ulong fd_start_block_height_and_rewards_align( void ){ return FD_START_BLOCK_HEIGHT_AND_REWARDS_ALIGN; }

void fd_start_block_height_and_rewards_walk(void * w, fd_start_block_height_and_rewards_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_start_block_height_and_rewards", level++);
  fun( w, &self->start_block_height, "start_block_height", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  if (self->stake_rewards_by_partition_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "stake_rewards_by_partition", level++);
    for (ulong i = 0; i < self->stake_rewards_by_partition_len; ++i)
      fd_serializable_stake_rewards_walk(w, self->stake_rewards_by_partition + i, fun, "serializable_stake_rewards", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "stake_rewards_by_partition", level-- );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_start_block_height_and_rewards", level--);
}
ulong fd_start_block_height_and_rewards_size(fd_start_block_height_and_rewards_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->stake_rewards_by_partition_len; ++i)
      size += fd_serializable_stake_rewards_size(self->stake_rewards_by_partition + i);
  } while(0);
  return size;
}

int fd_start_block_height_and_rewards_encode(fd_start_block_height_and_rewards_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->start_block_height, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->stake_rewards_by_partition_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->stake_rewards_by_partition_len != 0) {
    for (ulong i = 0; i < self->stake_rewards_by_partition_len; ++i) {
      err = fd_serializable_stake_rewards_encode(self->stake_rewards_by_partition + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_serializable_epoch_reward_status_is_Active(fd_serializable_epoch_reward_status_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_serializable_epoch_reward_status_is_Inactive(fd_serializable_epoch_reward_status_t const * self) {
  return self->discriminant == 1;
}
void fd_serializable_epoch_reward_status_inner_new(fd_serializable_epoch_reward_status_inner_t* self, uint discriminant);
int fd_serializable_epoch_reward_status_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_start_block_height_and_rewards_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_serializable_epoch_reward_status_inner_decode_unsafe(fd_serializable_epoch_reward_status_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_start_block_height_and_rewards_decode_unsafe(&self->Active, ctx);
    break;
  }
  case 1: {
    break;
  }
  }
}
int fd_serializable_epoch_reward_status_decode(fd_serializable_epoch_reward_status_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_serializable_epoch_reward_status_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_serializable_epoch_reward_status_new(self);
  fd_serializable_epoch_reward_status_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_serializable_epoch_reward_status_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_serializable_epoch_reward_status_inner_decode_preflight(discriminant, ctx);
}
void fd_serializable_epoch_reward_status_decode_unsafe(fd_serializable_epoch_reward_status_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_serializable_epoch_reward_status_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_serializable_epoch_reward_status_inner_new(fd_serializable_epoch_reward_status_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_start_block_height_and_rewards_new(&self->Active);
    break;
  }
  case 1: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_serializable_epoch_reward_status_new_disc(fd_serializable_epoch_reward_status_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_serializable_epoch_reward_status_inner_new(&self->inner, self->discriminant);
}
void fd_serializable_epoch_reward_status_new(fd_serializable_epoch_reward_status_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_serializable_epoch_reward_status_new_disc(self, UINT_MAX);
}
void fd_serializable_epoch_reward_status_inner_destroy(fd_serializable_epoch_reward_status_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_start_block_height_and_rewards_destroy(&self->Active, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_serializable_epoch_reward_status_destroy(fd_serializable_epoch_reward_status_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_serializable_epoch_reward_status_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_serializable_epoch_reward_status_footprint( void ){ return FD_SERIALIZABLE_EPOCH_REWARD_STATUS_FOOTPRINT; }
ulong fd_serializable_epoch_reward_status_align( void ){ return FD_SERIALIZABLE_EPOCH_REWARD_STATUS_ALIGN; }

void fd_serializable_epoch_reward_status_walk(void * w, fd_serializable_epoch_reward_status_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_serializable_epoch_reward_status", level++);
  switch (self->discriminant) {
  case 0: {
    fd_start_block_height_and_rewards_walk(w, &self->inner.Active, fun, "Active", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_serializable_epoch_reward_status", level--);
}
ulong fd_serializable_epoch_reward_status_size(fd_serializable_epoch_reward_status_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_start_block_height_and_rewards_size(&self->inner.Active);
    break;
  }
  }
  return size;
}

int fd_serializable_epoch_reward_status_inner_encode(fd_serializable_epoch_reward_status_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_start_block_height_and_rewards_encode(&self->Active, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_serializable_epoch_reward_status_encode(fd_serializable_epoch_reward_status_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_serializable_epoch_reward_status_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_solana_accounts_db_fields_decode(fd_solana_accounts_db_fields_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_solana_accounts_db_fields_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_solana_accounts_db_fields_new(self);
  fd_solana_accounts_db_fields_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_solana_accounts_db_fields_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong storages_len;
  err = fd_bincode_uint64_decode(&storages_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (storages_len != 0) {
    for( ulong i = 0; i < storages_len; ++i) {
      err = fd_snapshot_slot_acc_vecs_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bank_hash_info_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong historical_roots_len;
  err = fd_bincode_uint64_decode(&historical_roots_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (historical_roots_len != 0) {
    for( ulong i = 0; i < historical_roots_len; ++i) {
      err = fd_bincode_uint64_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  ulong historical_roots_with_hash_len;
  err = fd_bincode_uint64_decode(&historical_roots_with_hash_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (historical_roots_with_hash_len != 0) {
    for( ulong i = 0; i < historical_roots_with_hash_len; ++i) {
      err = fd_slot_map_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_solana_accounts_db_fields_decode_unsafe(fd_solana_accounts_db_fields_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->storages_len, ctx);
  if (self->storages_len != 0) {
    self->storages = (fd_snapshot_slot_acc_vecs_t *)fd_valloc_malloc( ctx->valloc, FD_SNAPSHOT_SLOT_ACC_VECS_ALIGN, FD_SNAPSHOT_SLOT_ACC_VECS_FOOTPRINT*self->storages_len);
    for( ulong i = 0; i < self->storages_len; ++i) {
      fd_snapshot_slot_acc_vecs_new(self->storages + i);
      fd_snapshot_slot_acc_vecs_decode_unsafe(self->storages + i, ctx);
    }
  } else
    self->storages = NULL;
  fd_bincode_uint64_decode_unsafe(&self->version, ctx);
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
  fd_bank_hash_info_decode_unsafe(&self->bank_hash_info, ctx);
  fd_bincode_uint64_decode_unsafe(&self->historical_roots_len, ctx);
  if (self->historical_roots_len != 0) {
    self->historical_roots = fd_valloc_malloc( ctx->valloc, 8UL, sizeof(ulong)*self->historical_roots_len );
    for( ulong i = 0; i < self->historical_roots_len; ++i) {
      fd_bincode_uint64_decode_unsafe(self->historical_roots + i, ctx);
    }
  } else
    self->historical_roots = NULL;
  fd_bincode_uint64_decode_unsafe(&self->historical_roots_with_hash_len, ctx);
  if (self->historical_roots_with_hash_len != 0) {
    self->historical_roots_with_hash = (fd_slot_map_pair_t *)fd_valloc_malloc( ctx->valloc, FD_SLOT_MAP_PAIR_ALIGN, FD_SLOT_MAP_PAIR_FOOTPRINT*self->historical_roots_with_hash_len);
    for( ulong i = 0; i < self->historical_roots_with_hash_len; ++i) {
      fd_slot_map_pair_new(self->historical_roots_with_hash + i);
      fd_slot_map_pair_decode_unsafe(self->historical_roots_with_hash + i, ctx);
    }
  } else
    self->historical_roots_with_hash = NULL;
}
int fd_solana_accounts_db_fields_decode_offsets(fd_solana_accounts_db_fields_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->storages_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong storages_len;
  err = fd_bincode_uint64_decode(&storages_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (storages_len != 0) {
    for( ulong i = 0; i < storages_len; ++i) {
      err = fd_snapshot_slot_acc_vecs_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->version_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->bank_hash_info_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bank_hash_info_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->historical_roots_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong historical_roots_len;
  err = fd_bincode_uint64_decode(&historical_roots_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (historical_roots_len != 0) {
    for( ulong i = 0; i < historical_roots_len; ++i) {
      err = fd_bincode_uint64_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->historical_roots_with_hash_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong historical_roots_with_hash_len;
  err = fd_bincode_uint64_decode(&historical_roots_with_hash_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (historical_roots_with_hash_len != 0) {
    for( ulong i = 0; i < historical_roots_with_hash_len; ++i) {
      err = fd_slot_map_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_solana_accounts_db_fields_new(fd_solana_accounts_db_fields_t* self) {
  fd_memset(self, 0, sizeof(fd_solana_accounts_db_fields_t));
  fd_bank_hash_info_new(&self->bank_hash_info);
}
void fd_solana_accounts_db_fields_destroy(fd_solana_accounts_db_fields_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->storages) {
    for (ulong i = 0; i < self->storages_len; ++i)
      fd_snapshot_slot_acc_vecs_destroy(self->storages + i, ctx);
    fd_valloc_free( ctx->valloc, self->storages );
    self->storages = NULL;
  }
  fd_bank_hash_info_destroy(&self->bank_hash_info, ctx);
  if (NULL != self->historical_roots) {
    fd_valloc_free( ctx->valloc, self->historical_roots );
    self->historical_roots = NULL;
  }
  if (NULL != self->historical_roots_with_hash) {
    for (ulong i = 0; i < self->historical_roots_with_hash_len; ++i)
      fd_slot_map_pair_destroy(self->historical_roots_with_hash + i, ctx);
    fd_valloc_free( ctx->valloc, self->historical_roots_with_hash );
    self->historical_roots_with_hash = NULL;
  }
}

ulong fd_solana_accounts_db_fields_footprint( void ){ return FD_SOLANA_ACCOUNTS_DB_FIELDS_FOOTPRINT; }
ulong fd_solana_accounts_db_fields_align( void ){ return FD_SOLANA_ACCOUNTS_DB_FIELDS_ALIGN; }

void fd_solana_accounts_db_fields_walk(void * w, fd_solana_accounts_db_fields_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_solana_accounts_db_fields", level++);
  if (self->storages_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "storages", level++);
    for (ulong i = 0; i < self->storages_len; ++i)
      fd_snapshot_slot_acc_vecs_walk(w, self->storages + i, fun, "snapshot_slot_acc_vecs", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "storages", level-- );
  }
  fun( w, &self->version, "version", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_bank_hash_info_walk(w, &self->bank_hash_info, fun, "bank_hash_info", level);
  if (self->historical_roots_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "historical_roots", level++);
    for (ulong i = 0; i < self->historical_roots_len; ++i)
      fun( w, self->historical_roots + i, "historical_roots", FD_FLAMENCO_TYPE_ULONG,   "ulong",   level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "historical_roots", level-- );
  }
  if (self->historical_roots_with_hash_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "historical_roots_with_hash", level++);
    for (ulong i = 0; i < self->historical_roots_with_hash_len; ++i)
      fd_slot_map_pair_walk(w, self->historical_roots_with_hash + i, fun, "slot_map_pair", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "historical_roots_with_hash", level-- );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_solana_accounts_db_fields", level--);
}
ulong fd_solana_accounts_db_fields_size(fd_solana_accounts_db_fields_t const * self) {
  ulong size = 0;
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->storages_len; ++i)
      size += fd_snapshot_slot_acc_vecs_size(self->storages + i);
  } while(0);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_bank_hash_info_size(&self->bank_hash_info);
  do {
    size += sizeof(ulong);
    size += self->historical_roots_len * sizeof(ulong);
  } while(0);
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->historical_roots_with_hash_len; ++i)
      size += fd_slot_map_pair_size(self->historical_roots_with_hash + i);
  } while(0);
  return size;
}

int fd_solana_accounts_db_fields_encode(fd_solana_accounts_db_fields_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->storages_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->storages_len != 0) {
    for (ulong i = 0; i < self->storages_len; ++i) {
      err = fd_snapshot_slot_acc_vecs_encode(self->storages + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(self->version, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bank_hash_info_encode(&self->bank_hash_info, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->historical_roots_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->historical_roots_len != 0) {
    for (ulong i = 0; i < self->historical_roots_len; ++i) {
      err = fd_bincode_uint64_encode(self->historical_roots[i], ctx);
    }
  }
  err = fd_bincode_uint64_encode(self->historical_roots_with_hash_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->historical_roots_with_hash_len != 0) {
    for (ulong i = 0; i < self->historical_roots_with_hash_len; ++i) {
      err = fd_slot_map_pair_encode(self->historical_roots_with_hash + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_solana_manifest_decode(fd_solana_manifest_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_solana_manifest_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_solana_manifest_new(self);
  fd_solana_manifest_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_solana_manifest_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_deserializable_versioned_bank_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_solana_accounts_db_fields_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( ctx->data == ctx->dataend ) return FD_BINCODE_SUCCESS;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bank_incremental_snapshot_persistence_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  if( ctx->data == ctx->dataend ) return FD_BINCODE_SUCCESS;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_hash_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  if( ctx->data == ctx->dataend ) return FD_BINCODE_SUCCESS;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_serializable_epoch_reward_status_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_solana_manifest_decode_unsafe(fd_solana_manifest_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_deserializable_versioned_bank_decode_unsafe(&self->bank, ctx);
  fd_solana_accounts_db_fields_decode_unsafe(&self->accounts_db, ctx);
  fd_bincode_uint64_decode_unsafe(&self->lamports_per_signature, ctx);
  if( ctx->data == ctx->dataend ) return;
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      self->bank_incremental_snapshot_persistence = (fd_bank_incremental_snapshot_persistence_t*)fd_valloc_malloc( ctx->valloc, FD_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_ALIGN, FD_BANK_INCREMENTAL_SNAPSHOT_PERSISTENCE_FOOTPRINT );
      fd_bank_incremental_snapshot_persistence_new( self->bank_incremental_snapshot_persistence );
      fd_bank_incremental_snapshot_persistence_decode_unsafe( self->bank_incremental_snapshot_persistence, ctx );
    } else
      self->bank_incremental_snapshot_persistence = NULL;
  }
  if( ctx->data == ctx->dataend ) return;
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      self->epoch_account_hash = (fd_hash_t*)fd_valloc_malloc( ctx->valloc, FD_HASH_ALIGN, FD_HASH_FOOTPRINT );
      fd_hash_new( self->epoch_account_hash );
      fd_hash_decode_unsafe( self->epoch_account_hash, ctx );
    } else
      self->epoch_account_hash = NULL;
  }
  if( ctx->data == ctx->dataend ) return;
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      self->epoch_reward_status = (fd_serializable_epoch_reward_status_t*)fd_valloc_malloc( ctx->valloc, FD_SERIALIZABLE_EPOCH_REWARD_STATUS_ALIGN, FD_SERIALIZABLE_EPOCH_REWARD_STATUS_FOOTPRINT );
      fd_serializable_epoch_reward_status_new( self->epoch_reward_status );
      fd_serializable_epoch_reward_status_decode_unsafe( self->epoch_reward_status, ctx );
    } else
      self->epoch_reward_status = NULL;
  }
}
int fd_solana_manifest_decode_offsets(fd_solana_manifest_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->bank_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_deserializable_versioned_bank_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->accounts_db_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_solana_accounts_db_fields_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->lamports_per_signature_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->bank_incremental_snapshot_persistence_off = (uint)((ulong)ctx->data - (ulong)data);
  if (ctx->data == ctx->dataend) return FD_BINCODE_SUCCESS;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bank_incremental_snapshot_persistence_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->epoch_account_hash_off = (uint)((ulong)ctx->data - (ulong)data);
  if (ctx->data == ctx->dataend) return FD_BINCODE_SUCCESS;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_hash_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->epoch_reward_status_off = (uint)((ulong)ctx->data - (ulong)data);
  if (ctx->data == ctx->dataend) return FD_BINCODE_SUCCESS;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_serializable_epoch_reward_status_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_solana_manifest_new(fd_solana_manifest_t* self) {
  fd_memset(self, 0, sizeof(fd_solana_manifest_t));
  fd_deserializable_versioned_bank_new(&self->bank);
  fd_solana_accounts_db_fields_new(&self->accounts_db);
}
void fd_solana_manifest_destroy(fd_solana_manifest_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_deserializable_versioned_bank_destroy(&self->bank, ctx);
  fd_solana_accounts_db_fields_destroy(&self->accounts_db, ctx);
  if( NULL != self->bank_incremental_snapshot_persistence ) {
    fd_bank_incremental_snapshot_persistence_destroy( self->bank_incremental_snapshot_persistence, ctx );
    fd_valloc_free( ctx->valloc, self->bank_incremental_snapshot_persistence );
    self->bank_incremental_snapshot_persistence = NULL;
  }
  if( NULL != self->epoch_account_hash ) {
    fd_hash_destroy( self->epoch_account_hash, ctx );
    fd_valloc_free( ctx->valloc, self->epoch_account_hash );
    self->epoch_account_hash = NULL;
  }
  if( NULL != self->epoch_reward_status ) {
    fd_serializable_epoch_reward_status_destroy( self->epoch_reward_status, ctx );
    fd_valloc_free( ctx->valloc, self->epoch_reward_status );
    self->epoch_reward_status = NULL;
  }
}

ulong fd_solana_manifest_footprint( void ){ return FD_SOLANA_MANIFEST_FOOTPRINT; }
ulong fd_solana_manifest_align( void ){ return FD_SOLANA_MANIFEST_ALIGN; }

void fd_solana_manifest_walk(void * w, fd_solana_manifest_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_solana_manifest", level++);
  fd_deserializable_versioned_bank_walk(w, &self->bank, fun, "bank", level);
  fd_solana_accounts_db_fields_walk(w, &self->accounts_db, fun, "accounts_db", level);
  fun( w, &self->lamports_per_signature, "lamports_per_signature", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  if( !self->bank_incremental_snapshot_persistence ) {
    fun( w, NULL, "bank_incremental_snapshot_persistence", FD_FLAMENCO_TYPE_NULL, "bank_incremental_snapshot_persistence", level );
  } else {
    fd_bank_incremental_snapshot_persistence_walk( w, self->bank_incremental_snapshot_persistence, fun, "bank_incremental_snapshot_persistence", level );
  }
  if( !self->epoch_account_hash ) {
    fun( w, NULL, "epoch_account_hash", FD_FLAMENCO_TYPE_NULL, "hash", level );
  } else {
    fd_hash_walk( w, self->epoch_account_hash, fun, "epoch_account_hash", level );
  }
  if( !self->epoch_reward_status ) {
    fun( w, NULL, "epoch_reward_status", FD_FLAMENCO_TYPE_NULL, "serializable_epoch_reward_status", level );
  } else {
    fd_serializable_epoch_reward_status_walk( w, self->epoch_reward_status, fun, "epoch_reward_status", level );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_solana_manifest", level--);
}
ulong fd_solana_manifest_size(fd_solana_manifest_t const * self) {
  ulong size = 0;
  size += fd_deserializable_versioned_bank_size(&self->bank);
  size += fd_solana_accounts_db_fields_size(&self->accounts_db);
  size += sizeof(ulong);
  size += sizeof(char);
  if( NULL !=  self->bank_incremental_snapshot_persistence ) {
    size += fd_bank_incremental_snapshot_persistence_size( self->bank_incremental_snapshot_persistence );
  }
  size += sizeof(char);
  if( NULL !=  self->epoch_account_hash ) {
    size += fd_hash_size( self->epoch_account_hash );
  }
  size += sizeof(char);
  if( NULL !=  self->epoch_reward_status ) {
    size += fd_serializable_epoch_reward_status_size( self->epoch_reward_status );
  }
  return size;
}

int fd_solana_manifest_encode(fd_solana_manifest_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_deserializable_versioned_bank_encode(&self->bank, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_solana_accounts_db_fields_encode(&self->accounts_db, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->lamports_per_signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if( self->bank_incremental_snapshot_persistence != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_bank_incremental_snapshot_persistence_encode( self->bank_incremental_snapshot_persistence, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
  }
  if( self->epoch_account_hash != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_hash_encode( self->epoch_account_hash, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
  }
  if( self->epoch_reward_status != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_serializable_epoch_reward_status_encode( self->epoch_reward_status, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_rust_duration_decode(fd_rust_duration_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_rust_duration_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_rust_duration_new(self);
  fd_rust_duration_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_rust_duration_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_rust_duration_decode_unsafe(fd_rust_duration_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->seconds, ctx);
  fd_bincode_uint32_decode_unsafe(&self->nanoseconds, ctx);
}
int fd_rust_duration_decode_offsets(fd_rust_duration_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->seconds_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->nanoseconds_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_rust_duration_new(fd_rust_duration_t* self) {
  fd_memset(self, 0, sizeof(fd_rust_duration_t));
}
void fd_rust_duration_destroy(fd_rust_duration_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_rust_duration_footprint( void ){ return FD_RUST_DURATION_FOOTPRINT; }
ulong fd_rust_duration_align( void ){ return FD_RUST_DURATION_ALIGN; }

void fd_rust_duration_walk(void * w, fd_rust_duration_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_rust_duration", level++);
  fun( w, &self->seconds, "seconds", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->nanoseconds, "nanoseconds", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_rust_duration", level--);
}
ulong fd_rust_duration_size(fd_rust_duration_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(uint);
  return size;
}

int fd_rust_duration_encode(fd_rust_duration_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->seconds, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_encode( self->nanoseconds, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_poh_config_decode(fd_poh_config_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_poh_config_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_poh_config_new(self);
  fd_poh_config_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_poh_config_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_rust_duration_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_poh_config_decode_unsafe(fd_poh_config_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_rust_duration_decode_unsafe(&self->target_tick_duration, ctx);
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      self->target_tick_count = fd_valloc_malloc( ctx->valloc, 8, sizeof(ulong) );
      fd_bincode_uint64_decode_unsafe( self->target_tick_count, ctx );
    } else
      self->target_tick_count = NULL;
  }
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_hashes_per_tick = !!o;
    if( o ) {
      fd_bincode_uint64_decode_unsafe( &self->hashes_per_tick, ctx );
    }
  }
}
int fd_poh_config_decode_offsets(fd_poh_config_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->target_tick_duration_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_rust_duration_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->target_tick_count_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->hashes_per_tick_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_poh_config_new(fd_poh_config_t* self) {
  fd_memset(self, 0, sizeof(fd_poh_config_t));
  fd_rust_duration_new(&self->target_tick_duration);
}
void fd_poh_config_destroy(fd_poh_config_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_rust_duration_destroy(&self->target_tick_duration, ctx);
  if( NULL != self->target_tick_count ) {
    fd_valloc_free( ctx->valloc, self->target_tick_count );
    self->target_tick_count = NULL;
  }
  if( self->has_hashes_per_tick ) {
    self->has_hashes_per_tick = 0;
  }
}

ulong fd_poh_config_footprint( void ){ return FD_POH_CONFIG_FOOTPRINT; }
ulong fd_poh_config_align( void ){ return FD_POH_CONFIG_ALIGN; }

void fd_poh_config_walk(void * w, fd_poh_config_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_poh_config", level++);
  fd_rust_duration_walk(w, &self->target_tick_duration, fun, "target_tick_duration", level);
  if( !self->target_tick_count ) {
    fun( w, NULL, "target_tick_count", FD_FLAMENCO_TYPE_NULL, "ulong", level );
  } else {
    fun( w, self->target_tick_count, "target_tick_count", FD_FLAMENCO_TYPE_ULONG, "ulong", level );
  }
  if( !self->has_hashes_per_tick ) {
    fun( w, NULL, "hashes_per_tick", FD_FLAMENCO_TYPE_NULL, "ulong", level );
  } else {
    fun( w, &self->hashes_per_tick, "hashes_per_tick", FD_FLAMENCO_TYPE_ULONG, "ulong", level );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_poh_config", level--);
}
ulong fd_poh_config_size(fd_poh_config_t const * self) {
  ulong size = 0;
  size += fd_rust_duration_size(&self->target_tick_duration);
  size += sizeof(char);
  if( NULL !=  self->target_tick_count ) {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if( self->has_hashes_per_tick ) {
    size += sizeof(ulong);
  }
  return size;
}

int fd_poh_config_encode(fd_poh_config_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_rust_duration_encode(&self->target_tick_duration, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if( self->target_tick_count != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_bincode_uint64_encode( self->target_tick_count[0], ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_bool_encode( self->has_hashes_per_tick, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_hashes_per_tick ) {
    err = fd_bincode_uint64_encode( self->hashes_per_tick, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_string_pubkey_pair_decode(fd_string_pubkey_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_string_pubkey_pair_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_string_pubkey_pair_new(self);
  fd_string_pubkey_pair_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_string_pubkey_pair_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong slen;
  err = fd_bincode_uint64_decode( &slen, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_bytes_decode_preflight( slen, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_string_pubkey_pair_decode_unsafe(fd_string_pubkey_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  ulong slen;
  fd_bincode_uint64_decode_unsafe( &slen, ctx );
  self->string = fd_valloc_malloc( ctx->valloc, 1, slen + 1 );
  fd_bincode_bytes_decode_unsafe( (uchar *)self->string, slen, ctx );
  self->string[slen] = '\0';
  fd_pubkey_decode_unsafe(&self->pubkey, ctx);
}
int fd_string_pubkey_pair_decode_offsets(fd_string_pubkey_pair_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->string_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong slen;
  err = fd_bincode_uint64_decode( &slen, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_bytes_decode_preflight( slen, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_string_pubkey_pair_new(fd_string_pubkey_pair_t* self) {
  fd_memset(self, 0, sizeof(fd_string_pubkey_pair_t));
  fd_pubkey_new(&self->pubkey);
}
void fd_string_pubkey_pair_destroy(fd_string_pubkey_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->string) {
    fd_valloc_free( ctx->valloc, self->string);
    self->string = NULL;
  }
  fd_pubkey_destroy(&self->pubkey, ctx);
}

ulong fd_string_pubkey_pair_footprint( void ){ return FD_STRING_PUBKEY_PAIR_FOOTPRINT; }
ulong fd_string_pubkey_pair_align( void ){ return FD_STRING_PUBKEY_PAIR_ALIGN; }

void fd_string_pubkey_pair_walk(void * w, fd_string_pubkey_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_string_pubkey_pair", level++);
  fun( w,  self->string, "string", FD_FLAMENCO_TYPE_CSTR,    "char*",     level );
  fd_pubkey_walk(w, &self->pubkey, fun, "pubkey", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_string_pubkey_pair", level--);
}
ulong fd_string_pubkey_pair_size(fd_string_pubkey_pair_t const * self) {
  ulong size = 0;
  size += sizeof(ulong) + strlen(self->string);
  size += fd_pubkey_size(&self->pubkey);
  return size;
}

int fd_string_pubkey_pair_encode(fd_string_pubkey_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  ulong slen = strlen( (char *) self->string );
  err = fd_bincode_uint64_encode(slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_encode((uchar *) self->string, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_pubkey_account_pair_decode(fd_pubkey_account_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_pubkey_account_pair_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_pubkey_account_pair_new(self);
  fd_pubkey_account_pair_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_pubkey_account_pair_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_solana_account_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_pubkey_account_pair_decode_unsafe(fd_pubkey_account_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->key, ctx);
  fd_solana_account_decode_unsafe(&self->account, ctx);
}
int fd_pubkey_account_pair_decode_offsets(fd_pubkey_account_pair_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->key_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->account_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_solana_account_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_pubkey_account_pair_new(fd_pubkey_account_pair_t* self) {
  fd_memset(self, 0, sizeof(fd_pubkey_account_pair_t));
  fd_pubkey_new(&self->key);
  fd_solana_account_new(&self->account);
}
void fd_pubkey_account_pair_destroy(fd_pubkey_account_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->key, ctx);
  fd_solana_account_destroy(&self->account, ctx);
}

ulong fd_pubkey_account_pair_footprint( void ){ return FD_PUBKEY_ACCOUNT_PAIR_FOOTPRINT; }
ulong fd_pubkey_account_pair_align( void ){ return FD_PUBKEY_ACCOUNT_PAIR_ALIGN; }

void fd_pubkey_account_pair_walk(void * w, fd_pubkey_account_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_pubkey_account_pair", level++);
  fd_pubkey_walk(w, &self->key, fun, "key", level);
  fd_solana_account_walk(w, &self->account, fun, "account", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_pubkey_account_pair", level--);
}
ulong fd_pubkey_account_pair_size(fd_pubkey_account_pair_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->key);
  size += fd_solana_account_size(&self->account);
  return size;
}

int fd_pubkey_account_pair_encode(fd_pubkey_account_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_solana_account_encode(&self->account, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_genesis_solana_decode(fd_genesis_solana_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_genesis_solana_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_genesis_solana_new(self);
  fd_genesis_solana_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_genesis_solana_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ulong accounts_len;
  err = fd_bincode_uint64_decode(&accounts_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (accounts_len != 0) {
    for( ulong i = 0; i < accounts_len; ++i) {
      err = fd_pubkey_account_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  ulong native_instruction_processors_len;
  err = fd_bincode_uint64_decode(&native_instruction_processors_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (native_instruction_processors_len != 0) {
    for( ulong i = 0; i < native_instruction_processors_len; ++i) {
      err = fd_string_pubkey_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  ulong rewards_pools_len;
  err = fd_bincode_uint64_decode(&rewards_pools_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (rewards_pools_len != 0) {
    for( ulong i = 0; i < rewards_pools_len; ++i) {
      err = fd_pubkey_account_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_poh_config_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_fee_rate_governor_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_rent_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_inflation_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_epoch_schedule_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_genesis_solana_decode_unsafe(fd_genesis_solana_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->creation_time, ctx);
  fd_bincode_uint64_decode_unsafe(&self->accounts_len, ctx);
  if (self->accounts_len != 0) {
    self->accounts = (fd_pubkey_account_pair_t *)fd_valloc_malloc( ctx->valloc, FD_PUBKEY_ACCOUNT_PAIR_ALIGN, FD_PUBKEY_ACCOUNT_PAIR_FOOTPRINT*self->accounts_len);
    for( ulong i = 0; i < self->accounts_len; ++i) {
      fd_pubkey_account_pair_new(self->accounts + i);
      fd_pubkey_account_pair_decode_unsafe(self->accounts + i, ctx);
    }
  } else
    self->accounts = NULL;
  fd_bincode_uint64_decode_unsafe(&self->native_instruction_processors_len, ctx);
  if (self->native_instruction_processors_len != 0) {
    self->native_instruction_processors = (fd_string_pubkey_pair_t *)fd_valloc_malloc( ctx->valloc, FD_STRING_PUBKEY_PAIR_ALIGN, FD_STRING_PUBKEY_PAIR_FOOTPRINT*self->native_instruction_processors_len);
    for( ulong i = 0; i < self->native_instruction_processors_len; ++i) {
      fd_string_pubkey_pair_new(self->native_instruction_processors + i);
      fd_string_pubkey_pair_decode_unsafe(self->native_instruction_processors + i, ctx);
    }
  } else
    self->native_instruction_processors = NULL;
  fd_bincode_uint64_decode_unsafe(&self->rewards_pools_len, ctx);
  if (self->rewards_pools_len != 0) {
    self->rewards_pools = (fd_pubkey_account_pair_t *)fd_valloc_malloc( ctx->valloc, FD_PUBKEY_ACCOUNT_PAIR_ALIGN, FD_PUBKEY_ACCOUNT_PAIR_FOOTPRINT*self->rewards_pools_len);
    for( ulong i = 0; i < self->rewards_pools_len; ++i) {
      fd_pubkey_account_pair_new(self->rewards_pools + i);
      fd_pubkey_account_pair_decode_unsafe(self->rewards_pools + i, ctx);
    }
  } else
    self->rewards_pools = NULL;
  fd_bincode_uint64_decode_unsafe(&self->ticks_per_slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->unused, ctx);
  fd_poh_config_decode_unsafe(&self->poh_config, ctx);
  fd_bincode_uint64_decode_unsafe(&self->__backwards_compat_with_v0_23, ctx);
  fd_fee_rate_governor_decode_unsafe(&self->fee_rate_governor, ctx);
  fd_rent_decode_unsafe(&self->rent, ctx);
  fd_inflation_decode_unsafe(&self->inflation, ctx);
  fd_epoch_schedule_decode_unsafe(&self->epoch_schedule, ctx);
  fd_bincode_uint32_decode_unsafe(&self->cluster_type, ctx);
}
int fd_genesis_solana_decode_offsets(fd_genesis_solana_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->creation_time_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->accounts_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong accounts_len;
  err = fd_bincode_uint64_decode(&accounts_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (accounts_len != 0) {
    for( ulong i = 0; i < accounts_len; ++i) {
      err = fd_pubkey_account_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->native_instruction_processors_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong native_instruction_processors_len;
  err = fd_bincode_uint64_decode(&native_instruction_processors_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (native_instruction_processors_len != 0) {
    for( ulong i = 0; i < native_instruction_processors_len; ++i) {
      err = fd_string_pubkey_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->rewards_pools_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong rewards_pools_len;
  err = fd_bincode_uint64_decode(&rewards_pools_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (rewards_pools_len != 0) {
    for( ulong i = 0; i < rewards_pools_len; ++i) {
      err = fd_pubkey_account_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->ticks_per_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->unused_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->poh_config_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_poh_config_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->__backwards_compat_with_v0_23_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->fee_rate_governor_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_fee_rate_governor_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->rent_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_rent_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->inflation_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_inflation_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->epoch_schedule_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_epoch_schedule_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->cluster_type_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_genesis_solana_new(fd_genesis_solana_t* self) {
  fd_memset(self, 0, sizeof(fd_genesis_solana_t));
  fd_poh_config_new(&self->poh_config);
  fd_fee_rate_governor_new(&self->fee_rate_governor);
  fd_rent_new(&self->rent);
  fd_inflation_new(&self->inflation);
  fd_epoch_schedule_new(&self->epoch_schedule);
}
void fd_genesis_solana_destroy(fd_genesis_solana_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->accounts) {
    for (ulong i = 0; i < self->accounts_len; ++i)
      fd_pubkey_account_pair_destroy(self->accounts + i, ctx);
    fd_valloc_free( ctx->valloc, self->accounts );
    self->accounts = NULL;
  }
  if (NULL != self->native_instruction_processors) {
    for (ulong i = 0; i < self->native_instruction_processors_len; ++i)
      fd_string_pubkey_pair_destroy(self->native_instruction_processors + i, ctx);
    fd_valloc_free( ctx->valloc, self->native_instruction_processors );
    self->native_instruction_processors = NULL;
  }
  if (NULL != self->rewards_pools) {
    for (ulong i = 0; i < self->rewards_pools_len; ++i)
      fd_pubkey_account_pair_destroy(self->rewards_pools + i, ctx);
    fd_valloc_free( ctx->valloc, self->rewards_pools );
    self->rewards_pools = NULL;
  }
  fd_poh_config_destroy(&self->poh_config, ctx);
  fd_fee_rate_governor_destroy(&self->fee_rate_governor, ctx);
  fd_rent_destroy(&self->rent, ctx);
  fd_inflation_destroy(&self->inflation, ctx);
  fd_epoch_schedule_destroy(&self->epoch_schedule, ctx);
}

ulong fd_genesis_solana_footprint( void ){ return FD_GENESIS_SOLANA_FOOTPRINT; }
ulong fd_genesis_solana_align( void ){ return FD_GENESIS_SOLANA_ALIGN; }

void fd_genesis_solana_walk(void * w, fd_genesis_solana_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_genesis_solana", level++);
  fun( w, &self->creation_time, "creation_time", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  if (self->accounts_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "accounts", level++);
    for (ulong i = 0; i < self->accounts_len; ++i)
      fd_pubkey_account_pair_walk(w, self->accounts + i, fun, "pubkey_account_pair", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "accounts", level-- );
  }
  if (self->native_instruction_processors_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "native_instruction_processors", level++);
    for (ulong i = 0; i < self->native_instruction_processors_len; ++i)
      fd_string_pubkey_pair_walk(w, self->native_instruction_processors + i, fun, "string_pubkey_pair", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "native_instruction_processors", level-- );
  }
  if (self->rewards_pools_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "rewards_pools", level++);
    for (ulong i = 0; i < self->rewards_pools_len; ++i)
      fd_pubkey_account_pair_walk(w, self->rewards_pools + i, fun, "pubkey_account_pair", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "rewards_pools", level-- );
  }
  fun( w, &self->ticks_per_slot, "ticks_per_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->unused, "unused", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_poh_config_walk(w, &self->poh_config, fun, "poh_config", level);
  fun( w, &self->__backwards_compat_with_v0_23, "__backwards_compat_with_v0_23", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_fee_rate_governor_walk(w, &self->fee_rate_governor, fun, "fee_rate_governor", level);
  fd_rent_walk(w, &self->rent, fun, "rent", level);
  fd_inflation_walk(w, &self->inflation, fun, "inflation", level);
  fd_epoch_schedule_walk(w, &self->epoch_schedule, fun, "epoch_schedule", level);
  fun( w, &self->cluster_type, "cluster_type", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_genesis_solana", level--);
}
ulong fd_genesis_solana_size(fd_genesis_solana_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->accounts_len; ++i)
      size += fd_pubkey_account_pair_size(self->accounts + i);
  } while(0);
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->native_instruction_processors_len; ++i)
      size += fd_string_pubkey_pair_size(self->native_instruction_processors + i);
  } while(0);
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->rewards_pools_len; ++i)
      size += fd_pubkey_account_pair_size(self->rewards_pools + i);
  } while(0);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_poh_config_size(&self->poh_config);
  size += sizeof(ulong);
  size += fd_fee_rate_governor_size(&self->fee_rate_governor);
  size += fd_rent_size(&self->rent);
  size += fd_inflation_size(&self->inflation);
  size += fd_epoch_schedule_size(&self->epoch_schedule);
  size += sizeof(uint);
  return size;
}

int fd_genesis_solana_encode(fd_genesis_solana_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->creation_time, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->accounts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->accounts_len != 0) {
    for (ulong i = 0; i < self->accounts_len; ++i) {
      err = fd_pubkey_account_pair_encode(self->accounts + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(self->native_instruction_processors_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->native_instruction_processors_len != 0) {
    for (ulong i = 0; i < self->native_instruction_processors_len; ++i) {
      err = fd_string_pubkey_pair_encode(self->native_instruction_processors + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(self->rewards_pools_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->rewards_pools_len != 0) {
    for (ulong i = 0; i < self->rewards_pools_len; ++i) {
      err = fd_pubkey_account_pair_encode(self->rewards_pools + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(self->ticks_per_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->unused, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_poh_config_encode(&self->poh_config, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->__backwards_compat_with_v0_23, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_rate_governor_encode(&self->fee_rate_governor, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_rent_encode(&self->rent, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_inflation_encode(&self->inflation, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_epoch_schedule_encode(&self->epoch_schedule, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_encode( self->cluster_type, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_sol_sysvar_clock_decode(fd_sol_sysvar_clock_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_sol_sysvar_clock_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_sol_sysvar_clock_new(self);
  fd_sol_sysvar_clock_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_sol_sysvar_clock_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_sol_sysvar_clock_decode_unsafe(fd_sol_sysvar_clock_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
  fd_bincode_uint64_decode_unsafe((ulong *) &self->epoch_start_timestamp, ctx);
  fd_bincode_uint64_decode_unsafe(&self->epoch, ctx);
  fd_bincode_uint64_decode_unsafe(&self->leader_schedule_epoch, ctx);
  fd_bincode_uint64_decode_unsafe((ulong *) &self->unix_timestamp, ctx);
}
int fd_sol_sysvar_clock_decode_offsets(fd_sol_sysvar_clock_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->epoch_start_timestamp_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->epoch_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->leader_schedule_epoch_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->unix_timestamp_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_sol_sysvar_clock_new(fd_sol_sysvar_clock_t* self) {
  fd_memset(self, 0, sizeof(fd_sol_sysvar_clock_t));
}
void fd_sol_sysvar_clock_destroy(fd_sol_sysvar_clock_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_sol_sysvar_clock_footprint( void ){ return FD_SOL_SYSVAR_CLOCK_FOOTPRINT; }
ulong fd_sol_sysvar_clock_align( void ){ return FD_SOL_SYSVAR_CLOCK_ALIGN; }

void fd_sol_sysvar_clock_walk(void * w, fd_sol_sysvar_clock_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_sol_sysvar_clock", level++);
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->epoch_start_timestamp, "epoch_start_timestamp", FD_FLAMENCO_TYPE_SLONG,   "long",      level );
  fun( w, &self->epoch, "epoch", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->leader_schedule_epoch, "leader_schedule_epoch", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->unix_timestamp, "unix_timestamp", FD_FLAMENCO_TYPE_SLONG,   "long",      level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_sol_sysvar_clock", level--);
}
ulong fd_sol_sysvar_clock_size(fd_sol_sysvar_clock_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(long);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(long);
  return size;
}

int fd_sol_sysvar_clock_encode(fd_sol_sysvar_clock_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode( (ulong)self->epoch_start_timestamp, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->leader_schedule_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode( (ulong)self->unix_timestamp, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_sol_sysvar_last_restart_slot_decode(fd_sol_sysvar_last_restart_slot_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_sol_sysvar_last_restart_slot_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_sol_sysvar_last_restart_slot_new(self);
  fd_sol_sysvar_last_restart_slot_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_sol_sysvar_last_restart_slot_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_sol_sysvar_last_restart_slot_decode_unsafe(fd_sol_sysvar_last_restart_slot_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
}
int fd_sol_sysvar_last_restart_slot_decode_offsets(fd_sol_sysvar_last_restart_slot_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_sol_sysvar_last_restart_slot_new(fd_sol_sysvar_last_restart_slot_t* self) {
  fd_memset(self, 0, sizeof(fd_sol_sysvar_last_restart_slot_t));
}
void fd_sol_sysvar_last_restart_slot_destroy(fd_sol_sysvar_last_restart_slot_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_sol_sysvar_last_restart_slot_footprint( void ){ return FD_SOL_SYSVAR_LAST_RESTART_SLOT_FOOTPRINT; }
ulong fd_sol_sysvar_last_restart_slot_align( void ){ return FD_SOL_SYSVAR_LAST_RESTART_SLOT_ALIGN; }

void fd_sol_sysvar_last_restart_slot_walk(void * w, fd_sol_sysvar_last_restart_slot_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_sol_sysvar_last_restart_slot", level++);
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_sol_sysvar_last_restart_slot", level--);
}
ulong fd_sol_sysvar_last_restart_slot_size(fd_sol_sysvar_last_restart_slot_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  return size;
}

int fd_sol_sysvar_last_restart_slot_encode(fd_sol_sysvar_last_restart_slot_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_lockout_decode(fd_vote_lockout_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_lockout_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_lockout_new(self);
  fd_vote_lockout_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_lockout_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_lockout_decode_unsafe(fd_vote_lockout_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
  fd_bincode_uint32_decode_unsafe(&self->confirmation_count, ctx);
}
int fd_vote_lockout_decode_offsets(fd_vote_lockout_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->confirmation_count_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_lockout_new(fd_vote_lockout_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_lockout_t));
}
void fd_vote_lockout_destroy(fd_vote_lockout_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_vote_lockout_footprint( void ){ return FD_VOTE_LOCKOUT_FOOTPRINT; }
ulong fd_vote_lockout_align( void ){ return FD_VOTE_LOCKOUT_ALIGN; }

void fd_vote_lockout_walk(void * w, fd_vote_lockout_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_lockout", level++);
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->confirmation_count, "confirmation_count", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_lockout", level--);
}
ulong fd_vote_lockout_size(fd_vote_lockout_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(uint);
  return size;
}

int fd_vote_lockout_encode(fd_vote_lockout_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_encode( self->confirmation_count, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_lockout_offset_decode(fd_lockout_offset_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_lockout_offset_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_lockout_offset_new(self);
  fd_lockout_offset_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_lockout_offset_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_varint_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_lockout_offset_decode_unsafe(fd_lockout_offset_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_varint_decode_unsafe(&self->offset, ctx);
  fd_bincode_uint8_decode_unsafe(&self->confirmation_count, ctx);
}
int fd_lockout_offset_decode_offsets(fd_lockout_offset_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->offset_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_varint_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->confirmation_count_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_lockout_offset_new(fd_lockout_offset_t* self) {
  fd_memset(self, 0, sizeof(fd_lockout_offset_t));
}
void fd_lockout_offset_destroy(fd_lockout_offset_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_lockout_offset_footprint( void ){ return FD_LOCKOUT_OFFSET_FOOTPRINT; }
ulong fd_lockout_offset_align( void ){ return FD_LOCKOUT_OFFSET_ALIGN; }

void fd_lockout_offset_walk(void * w, fd_lockout_offset_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_lockout_offset", level++);
  fun( w, &self->offset, "offset", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->confirmation_count, "confirmation_count", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_lockout_offset", level--);
}
ulong fd_lockout_offset_size(fd_lockout_offset_t const * self) {
  ulong size = 0;
  size += fd_bincode_varint_size(self->offset);
  size += sizeof(char);
  return size;
}

int fd_lockout_offset_encode(fd_lockout_offset_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_varint_encode(self->offset, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->confirmation_count), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_authorized_voter_decode(fd_vote_authorized_voter_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_authorized_voter_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_authorized_voter_new(self);
  fd_vote_authorized_voter_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_authorized_voter_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_authorized_voter_decode_unsafe(fd_vote_authorized_voter_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->epoch, ctx);
  fd_pubkey_decode_unsafe(&self->pubkey, ctx);
}
int fd_vote_authorized_voter_decode_offsets(fd_vote_authorized_voter_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->epoch_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->parent_off = (uint)((ulong)ctx->data - (ulong)data);
  self->left_off = (uint)((ulong)ctx->data - (ulong)data);
  self->right_off = (uint)((ulong)ctx->data - (ulong)data);
  self->prio_off = (uint)((ulong)ctx->data - (ulong)data);
  return FD_BINCODE_SUCCESS;
}
void fd_vote_authorized_voter_new(fd_vote_authorized_voter_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_authorized_voter_t));
  fd_pubkey_new(&self->pubkey);
}
void fd_vote_authorized_voter_destroy(fd_vote_authorized_voter_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->pubkey, ctx);
}

ulong fd_vote_authorized_voter_footprint( void ){ return FD_VOTE_AUTHORIZED_VOTER_FOOTPRINT; }
ulong fd_vote_authorized_voter_align( void ){ return FD_VOTE_AUTHORIZED_VOTER_ALIGN; }

void fd_vote_authorized_voter_walk(void * w, fd_vote_authorized_voter_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_authorized_voter", level++);
  fun( w, &self->epoch, "epoch", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_pubkey_walk(w, &self->pubkey, fun, "pubkey", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_authorized_voter", level--);
}
ulong fd_vote_authorized_voter_size(fd_vote_authorized_voter_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_pubkey_size(&self->pubkey);
  return size;
}

int fd_vote_authorized_voter_encode(fd_vote_authorized_voter_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_prior_voter_decode(fd_vote_prior_voter_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_prior_voter_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_prior_voter_new(self);
  fd_vote_prior_voter_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_prior_voter_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_prior_voter_decode_unsafe(fd_vote_prior_voter_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->pubkey, ctx);
  fd_bincode_uint64_decode_unsafe(&self->epoch_start, ctx);
  fd_bincode_uint64_decode_unsafe(&self->epoch_end, ctx);
}
int fd_vote_prior_voter_decode_offsets(fd_vote_prior_voter_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->epoch_start_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->epoch_end_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_prior_voter_new(fd_vote_prior_voter_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_prior_voter_t));
  fd_pubkey_new(&self->pubkey);
}
void fd_vote_prior_voter_destroy(fd_vote_prior_voter_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->pubkey, ctx);
}

ulong fd_vote_prior_voter_footprint( void ){ return FD_VOTE_PRIOR_VOTER_FOOTPRINT; }
ulong fd_vote_prior_voter_align( void ){ return FD_VOTE_PRIOR_VOTER_ALIGN; }

void fd_vote_prior_voter_walk(void * w, fd_vote_prior_voter_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_prior_voter", level++);
  fd_pubkey_walk(w, &self->pubkey, fun, "pubkey", level);
  fun( w, &self->epoch_start, "epoch_start", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->epoch_end, "epoch_end", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_prior_voter", level--);
}
ulong fd_vote_prior_voter_size(fd_vote_prior_voter_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->pubkey);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_vote_prior_voter_encode(fd_vote_prior_voter_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->epoch_start, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->epoch_end, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_prior_voter_0_23_5_decode(fd_vote_prior_voter_0_23_5_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_prior_voter_0_23_5_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_prior_voter_0_23_5_new(self);
  fd_vote_prior_voter_0_23_5_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_prior_voter_0_23_5_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_prior_voter_0_23_5_decode_unsafe(fd_vote_prior_voter_0_23_5_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->pubkey, ctx);
  fd_bincode_uint64_decode_unsafe(&self->epoch_start, ctx);
  fd_bincode_uint64_decode_unsafe(&self->epoch_end, ctx);
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
}
int fd_vote_prior_voter_0_23_5_decode_offsets(fd_vote_prior_voter_0_23_5_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->epoch_start_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->epoch_end_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_prior_voter_0_23_5_new(fd_vote_prior_voter_0_23_5_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_prior_voter_0_23_5_t));
  fd_pubkey_new(&self->pubkey);
}
void fd_vote_prior_voter_0_23_5_destroy(fd_vote_prior_voter_0_23_5_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->pubkey, ctx);
}

ulong fd_vote_prior_voter_0_23_5_footprint( void ){ return FD_VOTE_PRIOR_VOTER_0_23_5_FOOTPRINT; }
ulong fd_vote_prior_voter_0_23_5_align( void ){ return FD_VOTE_PRIOR_VOTER_0_23_5_ALIGN; }

void fd_vote_prior_voter_0_23_5_walk(void * w, fd_vote_prior_voter_0_23_5_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_prior_voter_0_23_5", level++);
  fd_pubkey_walk(w, &self->pubkey, fun, "pubkey", level);
  fun( w, &self->epoch_start, "epoch_start", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->epoch_end, "epoch_end", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_prior_voter_0_23_5", level--);
}
ulong fd_vote_prior_voter_0_23_5_size(fd_vote_prior_voter_0_23_5_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->pubkey);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_vote_prior_voter_0_23_5_encode(fd_vote_prior_voter_0_23_5_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->epoch_start, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->epoch_end, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_epoch_credits_decode(fd_vote_epoch_credits_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_epoch_credits_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_epoch_credits_new(self);
  fd_vote_epoch_credits_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_epoch_credits_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_epoch_credits_decode_unsafe(fd_vote_epoch_credits_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->epoch, ctx);
  fd_bincode_uint64_decode_unsafe(&self->credits, ctx);
  fd_bincode_uint64_decode_unsafe(&self->prev_credits, ctx);
}
int fd_vote_epoch_credits_decode_offsets(fd_vote_epoch_credits_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->epoch_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->credits_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->prev_credits_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_epoch_credits_new(fd_vote_epoch_credits_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_epoch_credits_t));
}
void fd_vote_epoch_credits_destroy(fd_vote_epoch_credits_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_vote_epoch_credits_footprint( void ){ return FD_VOTE_EPOCH_CREDITS_FOOTPRINT; }
ulong fd_vote_epoch_credits_align( void ){ return FD_VOTE_EPOCH_CREDITS_ALIGN; }

void fd_vote_epoch_credits_walk(void * w, fd_vote_epoch_credits_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_epoch_credits", level++);
  fun( w, &self->epoch, "epoch", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->credits, "credits", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->prev_credits, "prev_credits", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_epoch_credits", level--);
}
ulong fd_vote_epoch_credits_size(fd_vote_epoch_credits_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_vote_epoch_credits_encode(fd_vote_epoch_credits_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->credits, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->prev_credits, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_block_timestamp_decode(fd_vote_block_timestamp_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_block_timestamp_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_block_timestamp_new(self);
  fd_vote_block_timestamp_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_block_timestamp_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_block_timestamp_decode_unsafe(fd_vote_block_timestamp_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->timestamp, ctx);
}
int fd_vote_block_timestamp_decode_offsets(fd_vote_block_timestamp_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->timestamp_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_block_timestamp_new(fd_vote_block_timestamp_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_block_timestamp_t));
}
void fd_vote_block_timestamp_destroy(fd_vote_block_timestamp_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_vote_block_timestamp_footprint( void ){ return FD_VOTE_BLOCK_TIMESTAMP_FOOTPRINT; }
ulong fd_vote_block_timestamp_align( void ){ return FD_VOTE_BLOCK_TIMESTAMP_ALIGN; }

void fd_vote_block_timestamp_walk(void * w, fd_vote_block_timestamp_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_block_timestamp", level++);
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->timestamp, "timestamp", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_block_timestamp", level--);
}
ulong fd_vote_block_timestamp_size(fd_vote_block_timestamp_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_vote_block_timestamp_encode(fd_vote_block_timestamp_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_prior_voters_decode(fd_vote_prior_voters_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_prior_voters_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_prior_voters_new(self);
  fd_vote_prior_voters_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_prior_voters_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  for (ulong i = 0; i < 32; ++i) {
    err = fd_vote_prior_voter_decode_preflight(ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_bool_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_prior_voters_decode_unsafe(fd_vote_prior_voters_t* self, fd_bincode_decode_ctx_t * ctx) {
  for (ulong i = 0; i < 32; ++i) {
    fd_vote_prior_voter_decode_unsafe(self->buf + i, ctx);
  }
  fd_bincode_uint64_decode_unsafe(&self->idx, ctx);
  fd_bincode_bool_decode_unsafe(&self->is_empty, ctx);
}
int fd_vote_prior_voters_decode_offsets(fd_vote_prior_voters_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->buf_off = (uint)((ulong)ctx->data - (ulong)data);
  for (ulong i = 0; i < 32; ++i) {
    err = fd_vote_prior_voter_decode_preflight(ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  self->idx_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->is_empty_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bool_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_prior_voters_new(fd_vote_prior_voters_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_prior_voters_t));
  for (ulong i = 0; i < 32; ++i)
    fd_vote_prior_voter_new(self->buf + i);
}
void fd_vote_prior_voters_destroy(fd_vote_prior_voters_t* self, fd_bincode_destroy_ctx_t * ctx) {
  for (ulong i = 0; i < 32; ++i)
    fd_vote_prior_voter_destroy(self->buf + i, ctx);
}

ulong fd_vote_prior_voters_footprint( void ){ return FD_VOTE_PRIOR_VOTERS_FOOTPRINT; }
ulong fd_vote_prior_voters_align( void ){ return FD_VOTE_PRIOR_VOTERS_ALIGN; }

void fd_vote_prior_voters_walk(void * w, fd_vote_prior_voters_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_prior_voters", level++);
  fun(w, NULL, "buf", FD_FLAMENCO_TYPE_ARR, "vote_prior_voter[]", level++);
  for (ulong i = 0; i < 32; ++i)
    fd_vote_prior_voter_walk(w, self->buf + i, fun, "vote_prior_voter", level );
  fun(w, NULL, "buf", FD_FLAMENCO_TYPE_ARR_END, "vote_prior_voter[]", level--);
  fun( w, &self->idx, "idx", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->is_empty, "is_empty", FD_FLAMENCO_TYPE_BOOL,    "bool",      level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_prior_voters", level--);
}
ulong fd_vote_prior_voters_size(fd_vote_prior_voters_t const * self) {
  ulong size = 0;
  for (ulong i = 0; i < 32; ++i)
    size += fd_vote_prior_voter_size(self->buf + i);
  size += sizeof(ulong);
  size += sizeof(char);
  return size;
}

int fd_vote_prior_voters_encode(fd_vote_prior_voters_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  for (ulong i = 0; i < 32; ++i) {
    err = fd_vote_prior_voter_encode(self->buf + i, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_uint64_encode(self->idx, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bool_encode( (uchar)(self->is_empty), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_prior_voters_0_23_5_decode(fd_vote_prior_voters_0_23_5_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_prior_voters_0_23_5_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_prior_voters_0_23_5_new(self);
  fd_vote_prior_voters_0_23_5_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_prior_voters_0_23_5_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  for (ulong i = 0; i < 32; ++i) {
    err = fd_vote_prior_voter_0_23_5_decode_preflight(ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_prior_voters_0_23_5_decode_unsafe(fd_vote_prior_voters_0_23_5_t* self, fd_bincode_decode_ctx_t * ctx) {
  for (ulong i = 0; i < 32; ++i) {
    fd_vote_prior_voter_0_23_5_decode_unsafe(self->buf + i, ctx);
  }
  fd_bincode_uint64_decode_unsafe(&self->idx, ctx);
}
int fd_vote_prior_voters_0_23_5_decode_offsets(fd_vote_prior_voters_0_23_5_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->buf_off = (uint)((ulong)ctx->data - (ulong)data);
  for (ulong i = 0; i < 32; ++i) {
    err = fd_vote_prior_voter_0_23_5_decode_preflight(ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  self->idx_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_prior_voters_0_23_5_new(fd_vote_prior_voters_0_23_5_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_prior_voters_0_23_5_t));
  for (ulong i = 0; i < 32; ++i)
    fd_vote_prior_voter_0_23_5_new(self->buf + i);
}
void fd_vote_prior_voters_0_23_5_destroy(fd_vote_prior_voters_0_23_5_t* self, fd_bincode_destroy_ctx_t * ctx) {
  for (ulong i = 0; i < 32; ++i)
    fd_vote_prior_voter_0_23_5_destroy(self->buf + i, ctx);
}

ulong fd_vote_prior_voters_0_23_5_footprint( void ){ return FD_VOTE_PRIOR_VOTERS_0_23_5_FOOTPRINT; }
ulong fd_vote_prior_voters_0_23_5_align( void ){ return FD_VOTE_PRIOR_VOTERS_0_23_5_ALIGN; }

void fd_vote_prior_voters_0_23_5_walk(void * w, fd_vote_prior_voters_0_23_5_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_prior_voters_0_23_5", level++);
  fun(w, NULL, "buf", FD_FLAMENCO_TYPE_ARR, "vote_prior_voter_0_23_5[]", level++);
  for (ulong i = 0; i < 32; ++i)
    fd_vote_prior_voter_0_23_5_walk(w, self->buf + i, fun, "vote_prior_voter_0_23_5", level );
  fun(w, NULL, "buf", FD_FLAMENCO_TYPE_ARR_END, "vote_prior_voter_0_23_5[]", level--);
  fun( w, &self->idx, "idx", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_prior_voters_0_23_5", level--);
}
ulong fd_vote_prior_voters_0_23_5_size(fd_vote_prior_voters_0_23_5_t const * self) {
  ulong size = 0;
  for (ulong i = 0; i < 32; ++i)
    size += fd_vote_prior_voter_0_23_5_size(self->buf + i);
  size += sizeof(ulong);
  return size;
}

int fd_vote_prior_voters_0_23_5_encode(fd_vote_prior_voters_0_23_5_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  for (ulong i = 0; i < 32; ++i) {
    err = fd_vote_prior_voter_0_23_5_encode(self->buf + i, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_uint64_encode(self->idx, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_landed_vote_decode(fd_landed_vote_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_landed_vote_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_landed_vote_new(self);
  fd_landed_vote_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_landed_vote_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_lockout_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_landed_vote_decode_unsafe(fd_landed_vote_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint8_decode_unsafe(&self->latency, ctx);
  fd_vote_lockout_decode_unsafe(&self->lockout, ctx);
}
int fd_landed_vote_decode_offsets(fd_landed_vote_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->latency_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->lockout_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_vote_lockout_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_landed_vote_new(fd_landed_vote_t* self) {
  fd_memset(self, 0, sizeof(fd_landed_vote_t));
  fd_vote_lockout_new(&self->lockout);
}
void fd_landed_vote_destroy(fd_landed_vote_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_vote_lockout_destroy(&self->lockout, ctx);
}

ulong fd_landed_vote_footprint( void ){ return FD_LANDED_VOTE_FOOTPRINT; }
ulong fd_landed_vote_align( void ){ return FD_LANDED_VOTE_ALIGN; }

void fd_landed_vote_walk(void * w, fd_landed_vote_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_landed_vote", level++);
  fun( w, &self->latency, "latency", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  fd_vote_lockout_walk(w, &self->lockout, fun, "lockout", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_landed_vote", level--);
}
ulong fd_landed_vote_size(fd_landed_vote_t const * self) {
  ulong size = 0;
  size += sizeof(char);
  size += fd_vote_lockout_size(&self->lockout);
  return size;
}

int fd_landed_vote_encode(fd_landed_vote_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint8_encode( (uchar)(self->latency), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_lockout_encode(&self->lockout, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_state_0_23_5_decode(fd_vote_state_0_23_5_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_state_0_23_5_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_state_0_23_5_new(self);
  fd_vote_state_0_23_5_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_state_0_23_5_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_vote_prior_voters_0_23_5_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong votes_len;
  err = fd_bincode_uint64_decode( &votes_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( votes_len > 1228 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  err = fd_bincode_bytes_decode_preflight(votes_len * 12, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  ulong epoch_credits_len;
  err = fd_bincode_uint64_decode( &epoch_credits_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( epoch_credits_len > 100 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  err = fd_bincode_bytes_decode_preflight(epoch_credits_len * 24, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_block_timestamp_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_state_0_23_5_decode_unsafe(fd_vote_state_0_23_5_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->node_pubkey, ctx);
  fd_pubkey_decode_unsafe(&self->authorized_voter, ctx);
  fd_bincode_uint64_decode_unsafe(&self->authorized_voter_epoch, ctx);
  fd_vote_prior_voters_0_23_5_decode_unsafe(&self->prior_voters, ctx);
  fd_pubkey_decode_unsafe(&self->authorized_withdrawer, ctx);
  fd_bincode_uint8_decode_unsafe(&self->commission, ctx);
  ulong votes_len;
  fd_bincode_uint64_decode_unsafe( &votes_len, ctx );
  self->votes = deq_fd_vote_lockout_t_alloc( ctx->valloc );
  for (ulong i = 0; i < votes_len; ++i) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy(self->votes);
    fd_vote_lockout_new(elem);
    fd_vote_lockout_decode_unsafe(elem, ctx);
  }
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_root_slot = !!o;
    if( o ) {
      fd_bincode_uint64_decode_unsafe( &self->root_slot, ctx );
    }
  }
  ulong epoch_credits_len;
  fd_bincode_uint64_decode_unsafe( &epoch_credits_len, ctx );
  self->epoch_credits = deq_fd_vote_epoch_credits_t_alloc( ctx->valloc );
  for (ulong i = 0; i < epoch_credits_len; ++i) {
    fd_vote_epoch_credits_t * elem = deq_fd_vote_epoch_credits_t_push_tail_nocopy(self->epoch_credits);
    fd_vote_epoch_credits_new(elem);
    fd_vote_epoch_credits_decode_unsafe(elem, ctx);
  }
  fd_vote_block_timestamp_decode_unsafe(&self->last_timestamp, ctx);
}
int fd_vote_state_0_23_5_decode_offsets(fd_vote_state_0_23_5_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->node_pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->authorized_voter_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->authorized_voter_epoch_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->prior_voters_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_vote_prior_voters_0_23_5_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->authorized_withdrawer_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->commission_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->votes_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong votes_len;
  err = fd_bincode_uint64_decode( &votes_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( votes_len > 1228 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  err = fd_bincode_bytes_decode_preflight(votes_len * 12, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->root_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->epoch_credits_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong epoch_credits_len;
  err = fd_bincode_uint64_decode( &epoch_credits_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( epoch_credits_len > 100 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  err = fd_bincode_bytes_decode_preflight(epoch_credits_len * 24, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->last_timestamp_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_vote_block_timestamp_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_state_0_23_5_new(fd_vote_state_0_23_5_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_state_0_23_5_t));
  fd_pubkey_new(&self->node_pubkey);
  fd_pubkey_new(&self->authorized_voter);
  fd_vote_prior_voters_0_23_5_new(&self->prior_voters);
  fd_pubkey_new(&self->authorized_withdrawer);
  fd_vote_block_timestamp_new(&self->last_timestamp);
}
void fd_vote_state_0_23_5_destroy(fd_vote_state_0_23_5_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->node_pubkey, ctx);
  fd_pubkey_destroy(&self->authorized_voter, ctx);
  fd_vote_prior_voters_0_23_5_destroy(&self->prior_voters, ctx);
  fd_pubkey_destroy(&self->authorized_withdrawer, ctx);
  if ( self->votes ) {
    for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes ); !deq_fd_vote_lockout_t_iter_done( self->votes, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->votes, iter );
      fd_vote_lockout_destroy(ele, ctx);
    }
    fd_valloc_free( ctx->valloc, deq_fd_vote_lockout_t_delete( deq_fd_vote_lockout_t_leave( self->votes) ) );
    self->votes = NULL;
  }
  if( self->has_root_slot ) {
    self->has_root_slot = 0;
  }
  if ( self->epoch_credits ) {
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      fd_vote_epoch_credits_destroy(ele, ctx);
    }
    fd_valloc_free( ctx->valloc, deq_fd_vote_epoch_credits_t_delete( deq_fd_vote_epoch_credits_t_leave( self->epoch_credits) ) );
    self->epoch_credits = NULL;
  }
  fd_vote_block_timestamp_destroy(&self->last_timestamp, ctx);
}

ulong fd_vote_state_0_23_5_footprint( void ){ return FD_VOTE_STATE_0_23_5_FOOTPRINT; }
ulong fd_vote_state_0_23_5_align( void ){ return FD_VOTE_STATE_0_23_5_ALIGN; }

void fd_vote_state_0_23_5_walk(void * w, fd_vote_state_0_23_5_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_state_0_23_5", level++);
  fd_pubkey_walk(w, &self->node_pubkey, fun, "node_pubkey", level);
  fd_pubkey_walk(w, &self->authorized_voter, fun, "authorized_voter", level);
  fun( w, &self->authorized_voter_epoch, "authorized_voter_epoch", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_vote_prior_voters_0_23_5_walk(w, &self->prior_voters, fun, "prior_voters", level);
  fd_pubkey_walk(w, &self->authorized_withdrawer, fun, "authorized_withdrawer", level);
  fun( w, &self->commission, "commission", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );

  /* Walk deque */
  fun( w, self->votes, "votes", FD_FLAMENCO_TYPE_ARR, "votes", level++ );
  if( self->votes ) {
    for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes );
         !deq_fd_vote_lockout_t_iter_done( self->votes, iter );
         iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->votes, iter );
      fd_vote_lockout_walk(w, ele, fun, "votes", level );
    }
  }
  fun( w, self->votes, "votes", FD_FLAMENCO_TYPE_ARR_END, "votes", level-- );
  /* Done walking deque */

  if( !self->has_root_slot ) {
    fun( w, NULL, "root_slot", FD_FLAMENCO_TYPE_NULL, "ulong", level );
  } else {
    fun( w, &self->root_slot, "root_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level );
  }

  /* Walk deque */
  fun( w, self->epoch_credits, "epoch_credits", FD_FLAMENCO_TYPE_ARR, "epoch_credits", level++ );
  if( self->epoch_credits ) {
    for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits );
         !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter );
         iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      fd_vote_epoch_credits_walk(w, ele, fun, "epoch_credits", level );
    }
  }
  fun( w, self->epoch_credits, "epoch_credits", FD_FLAMENCO_TYPE_ARR_END, "epoch_credits", level-- );
  /* Done walking deque */

  fd_vote_block_timestamp_walk(w, &self->last_timestamp, fun, "last_timestamp", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_state_0_23_5", level--);
}
ulong fd_vote_state_0_23_5_size(fd_vote_state_0_23_5_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->node_pubkey);
  size += fd_pubkey_size(&self->authorized_voter);
  size += sizeof(ulong);
  size += fd_vote_prior_voters_0_23_5_size(&self->prior_voters);
  size += fd_pubkey_size(&self->authorized_withdrawer);
  size += sizeof(char);
  if ( self->votes ) {
    size += sizeof(ulong);
    for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes ); !deq_fd_vote_lockout_t_iter_done( self->votes, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->votes, iter );
      size += fd_vote_lockout_size(ele);
    }
  } else {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if( self->has_root_slot ) {
    size += sizeof(ulong);
  }
  if ( self->epoch_credits ) {
    size += sizeof(ulong);
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      size += fd_vote_epoch_credits_size(ele);
    }
  } else {
    size += sizeof(ulong);
  }
  size += fd_vote_block_timestamp_size(&self->last_timestamp);
  return size;
}

int fd_vote_state_0_23_5_encode(fd_vote_state_0_23_5_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->node_pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->authorized_voter, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->authorized_voter_epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_prior_voters_0_23_5_encode(&self->prior_voters, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->authorized_withdrawer, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->commission), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( self->votes ) {
    ulong votes_len = deq_fd_vote_lockout_t_cnt(self->votes);
    err = fd_bincode_uint64_encode(votes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes ); !deq_fd_vote_lockout_t_iter_done( self->votes, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t const * ele = deq_fd_vote_lockout_t_iter_ele_const( self->votes, iter );
      err = fd_vote_lockout_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong votes_len = 0;
    err = fd_bincode_uint64_encode(votes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_bool_encode( self->has_root_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_root_slot ) {
    err = fd_bincode_uint64_encode( self->root_slot, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  if ( self->epoch_credits ) {
    ulong epoch_credits_len = deq_fd_vote_epoch_credits_t_cnt(self->epoch_credits);
    err = fd_bincode_uint64_encode(epoch_credits_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t const * ele = deq_fd_vote_epoch_credits_t_iter_ele_const( self->epoch_credits, iter );
      err = fd_vote_epoch_credits_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong epoch_credits_len = 0;
    err = fd_bincode_uint64_encode(epoch_credits_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_vote_block_timestamp_encode(&self->last_timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_authorized_voters_decode(fd_vote_authorized_voters_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_authorized_voters_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_authorized_voters_new(self);
  fd_vote_authorized_voters_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_authorized_voters_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong fd_vote_authorized_voters_treap_len;
  err = fd_bincode_uint64_decode(&fd_vote_authorized_voters_treap_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( fd_vote_authorized_voters_treap_len > FD_VOTE_AUTHORIZED_VOTERS_MAX ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < fd_vote_authorized_voters_treap_len; ++i) {
    err = fd_vote_authorized_voter_decode_preflight( ctx );
    if ( FD_UNLIKELY ( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_vote_authorized_voters_decode_unsafe(fd_vote_authorized_voters_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_destroy_ctx_t destroy_ctx = { .valloc = ctx->valloc };
  ulong fd_vote_authorized_voters_treap_len;
  fd_bincode_uint64_decode_unsafe(&fd_vote_authorized_voters_treap_len, ctx);
  self->pool = fd_vote_authorized_voters_pool_alloc( ctx->valloc );
  self->treap = fd_vote_authorized_voters_treap_alloc( ctx->valloc );
  for (ulong i = 0; i < fd_vote_authorized_voters_treap_len; ++i) {
    fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_pool_ele_acquire( self->pool );
    fd_vote_authorized_voter_new( ele );
    fd_vote_authorized_voter_decode_unsafe( ele, ctx );
    fd_vote_authorized_voter_t * repeated_entry = fd_vote_authorized_voters_treap_ele_query( self->treap, ele->epoch, self->pool );
    if ( repeated_entry ) {
        fd_vote_authorized_voters_treap_ele_remove( self->treap, repeated_entry, self->pool ); // Remove the element before inserting it back to avoid duplication
        fd_vote_authorized_voter_destroy( repeated_entry, &destroy_ctx );
        fd_vote_authorized_voters_pool_ele_release( self->pool, repeated_entry );
    }
    fd_vote_authorized_voters_treap_ele_insert( self->treap, ele, self->pool ); /* this cannot fail */
  }
}
int fd_vote_authorized_voters_decode_offsets(fd_vote_authorized_voters_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->fd_vote_authorized_voters_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong fd_vote_authorized_voters_treap_len;
  err = fd_bincode_uint64_decode(&fd_vote_authorized_voters_treap_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( fd_vote_authorized_voters_treap_len > FD_VOTE_AUTHORIZED_VOTERS_MAX ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < fd_vote_authorized_voters_treap_len; ++i) {
    err = fd_vote_authorized_voter_decode_preflight( ctx );
    if ( FD_UNLIKELY ( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_vote_authorized_voters_new(fd_vote_authorized_voters_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_authorized_voters_t));
}
void fd_vote_authorized_voters_destroy(fd_vote_authorized_voters_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if ( !self->treap || !self->pool ) return;
  for ( fd_vote_authorized_voters_treap_fwd_iter_t iter = fd_vote_authorized_voters_treap_fwd_iter_init( self->treap, self->pool );
          !fd_vote_authorized_voters_treap_fwd_iter_done( iter );
          iter = fd_vote_authorized_voters_treap_fwd_iter_next( iter, self->pool ) ) {
      fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_treap_fwd_iter_ele( iter, self->pool );
      fd_vote_authorized_voter_destroy( ele, ctx );
    }
  fd_valloc_free( ctx->valloc, fd_vote_authorized_voters_treap_delete(fd_vote_authorized_voters_treap_leave( self->treap) ) );
  fd_valloc_free( ctx->valloc, fd_vote_authorized_voters_pool_delete(fd_vote_authorized_voters_pool_leave( self->pool) ) );
  self->pool = NULL;
  self->treap = NULL;
}

ulong fd_vote_authorized_voters_footprint( void ){ return FD_VOTE_AUTHORIZED_VOTERS_FOOTPRINT; }
ulong fd_vote_authorized_voters_align( void ){ return FD_VOTE_AUTHORIZED_VOTERS_ALIGN; }

void fd_vote_authorized_voters_walk(void * w, fd_vote_authorized_voters_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_authorized_voters", level++);
  if (self->treap) {
    for ( fd_vote_authorized_voters_treap_fwd_iter_t iter = fd_vote_authorized_voters_treap_fwd_iter_init( self->treap, self->pool );
          !fd_vote_authorized_voters_treap_fwd_iter_done( iter );
          iter = fd_vote_authorized_voters_treap_fwd_iter_next( iter, self->pool ) ) {
      fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_treap_fwd_iter_ele( iter, self->pool );
      fd_vote_authorized_voter_walk(w, ele, fun, "fd_vote_authorized_voter_t", level );
    }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_authorized_voters", level--);
}
ulong fd_vote_authorized_voters_size(fd_vote_authorized_voters_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  if (self->treap) {
    for ( fd_vote_authorized_voters_treap_fwd_iter_t iter = fd_vote_authorized_voters_treap_fwd_iter_init( self->treap, self->pool );
          !fd_vote_authorized_voters_treap_fwd_iter_done( iter );
          iter = fd_vote_authorized_voters_treap_fwd_iter_next( iter, self->pool ) ) {
      fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_treap_fwd_iter_ele( iter, self->pool );
      size += fd_vote_authorized_voter_size( ele );
    }
  }
  return size;
}

int fd_vote_authorized_voters_encode(fd_vote_authorized_voters_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if (self->treap) {
    ulong fd_vote_authorized_voters_len = fd_vote_authorized_voters_treap_ele_cnt( self->treap );
    err = fd_bincode_uint64_encode( fd_vote_authorized_voters_len, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
    for ( fd_vote_authorized_voters_treap_fwd_iter_t iter = fd_vote_authorized_voters_treap_fwd_iter_init( self->treap, self->pool );
          !fd_vote_authorized_voters_treap_fwd_iter_done( iter );
          iter = fd_vote_authorized_voters_treap_fwd_iter_next( iter, self->pool ) ) {
      fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_treap_fwd_iter_ele( iter, self->pool );
      err = fd_vote_authorized_voter_encode( ele, ctx );
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong fd_vote_authorized_voters_len = 0;
    err = fd_bincode_uint64_encode(fd_vote_authorized_voters_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_vote_state_1_14_11_decode(fd_vote_state_1_14_11_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_state_1_14_11_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_state_1_14_11_new(self);
  fd_vote_state_1_14_11_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_state_1_14_11_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong votes_len;
  err = fd_bincode_uint64_decode( &votes_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( votes_len > 1228 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  err = fd_bincode_bytes_decode_preflight(votes_len * 12, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_vote_authorized_voters_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_prior_voters_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong epoch_credits_len;
  err = fd_bincode_uint64_decode( &epoch_credits_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( epoch_credits_len > 64 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  err = fd_bincode_bytes_decode_preflight(epoch_credits_len * 24, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_block_timestamp_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_state_1_14_11_decode_unsafe(fd_vote_state_1_14_11_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->node_pubkey, ctx);
  fd_pubkey_decode_unsafe(&self->authorized_withdrawer, ctx);
  fd_bincode_uint8_decode_unsafe(&self->commission, ctx);
  ulong votes_len;
  fd_bincode_uint64_decode_unsafe( &votes_len, ctx );
  self->votes = deq_fd_vote_lockout_t_alloc( ctx->valloc );
  for (ulong i = 0; i < votes_len; ++i) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy(self->votes);
    fd_vote_lockout_new(elem);
    fd_vote_lockout_decode_unsafe(elem, ctx);
  }
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_root_slot = !!o;
    if( o ) {
      fd_bincode_uint64_decode_unsafe( &self->root_slot, ctx );
    }
  }
  fd_vote_authorized_voters_decode_unsafe(&self->authorized_voters, ctx);
  fd_vote_prior_voters_decode_unsafe(&self->prior_voters, ctx);
  ulong epoch_credits_len;
  fd_bincode_uint64_decode_unsafe( &epoch_credits_len, ctx );
  self->epoch_credits = deq_fd_vote_epoch_credits_t_alloc( ctx->valloc );
  for (ulong i = 0; i < epoch_credits_len; ++i) {
    fd_vote_epoch_credits_t * elem = deq_fd_vote_epoch_credits_t_push_tail_nocopy(self->epoch_credits);
    fd_vote_epoch_credits_new(elem);
    fd_vote_epoch_credits_decode_unsafe(elem, ctx);
  }
  fd_vote_block_timestamp_decode_unsafe(&self->last_timestamp, ctx);
}
int fd_vote_state_1_14_11_decode_offsets(fd_vote_state_1_14_11_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->node_pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->authorized_withdrawer_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->commission_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->votes_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong votes_len;
  err = fd_bincode_uint64_decode( &votes_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( votes_len > 1228 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  err = fd_bincode_bytes_decode_preflight(votes_len * 12, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->root_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->authorized_voters_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_vote_authorized_voters_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->prior_voters_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_vote_prior_voters_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->epoch_credits_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong epoch_credits_len;
  err = fd_bincode_uint64_decode( &epoch_credits_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( epoch_credits_len > 64 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  err = fd_bincode_bytes_decode_preflight(epoch_credits_len * 24, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->last_timestamp_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_vote_block_timestamp_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_state_1_14_11_new(fd_vote_state_1_14_11_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_state_1_14_11_t));
  fd_pubkey_new(&self->node_pubkey);
  fd_pubkey_new(&self->authorized_withdrawer);
  fd_vote_authorized_voters_new(&self->authorized_voters);
  fd_vote_prior_voters_new(&self->prior_voters);
  fd_vote_block_timestamp_new(&self->last_timestamp);
}
void fd_vote_state_1_14_11_destroy(fd_vote_state_1_14_11_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->node_pubkey, ctx);
  fd_pubkey_destroy(&self->authorized_withdrawer, ctx);
  if ( self->votes ) {
    for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes ); !deq_fd_vote_lockout_t_iter_done( self->votes, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->votes, iter );
      fd_vote_lockout_destroy(ele, ctx);
    }
    fd_valloc_free( ctx->valloc, deq_fd_vote_lockout_t_delete( deq_fd_vote_lockout_t_leave( self->votes) ) );
    self->votes = NULL;
  }
  if( self->has_root_slot ) {
    self->has_root_slot = 0;
  }
  fd_vote_authorized_voters_destroy(&self->authorized_voters, ctx);
  fd_vote_prior_voters_destroy(&self->prior_voters, ctx);
  if ( self->epoch_credits ) {
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      fd_vote_epoch_credits_destroy(ele, ctx);
    }
    fd_valloc_free( ctx->valloc, deq_fd_vote_epoch_credits_t_delete( deq_fd_vote_epoch_credits_t_leave( self->epoch_credits) ) );
    self->epoch_credits = NULL;
  }
  fd_vote_block_timestamp_destroy(&self->last_timestamp, ctx);
}

ulong fd_vote_state_1_14_11_footprint( void ){ return FD_VOTE_STATE_1_14_11_FOOTPRINT; }
ulong fd_vote_state_1_14_11_align( void ){ return FD_VOTE_STATE_1_14_11_ALIGN; }

void fd_vote_state_1_14_11_walk(void * w, fd_vote_state_1_14_11_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_state_1_14_11", level++);
  fd_pubkey_walk(w, &self->node_pubkey, fun, "node_pubkey", level);
  fd_pubkey_walk(w, &self->authorized_withdrawer, fun, "authorized_withdrawer", level);
  fun( w, &self->commission, "commission", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );

  /* Walk deque */
  fun( w, self->votes, "votes", FD_FLAMENCO_TYPE_ARR, "votes", level++ );
  if( self->votes ) {
    for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes );
         !deq_fd_vote_lockout_t_iter_done( self->votes, iter );
         iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->votes, iter );
      fd_vote_lockout_walk(w, ele, fun, "votes", level );
    }
  }
  fun( w, self->votes, "votes", FD_FLAMENCO_TYPE_ARR_END, "votes", level-- );
  /* Done walking deque */

  if( !self->has_root_slot ) {
    fun( w, NULL, "root_slot", FD_FLAMENCO_TYPE_NULL, "ulong", level );
  } else {
    fun( w, &self->root_slot, "root_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level );
  }
  fd_vote_authorized_voters_walk(w, &self->authorized_voters, fun, "authorized_voters", level);
  fd_vote_prior_voters_walk(w, &self->prior_voters, fun, "prior_voters", level);

  /* Walk deque */
  fun( w, self->epoch_credits, "epoch_credits", FD_FLAMENCO_TYPE_ARR, "epoch_credits", level++ );
  if( self->epoch_credits ) {
    for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits );
         !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter );
         iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      fd_vote_epoch_credits_walk(w, ele, fun, "epoch_credits", level );
    }
  }
  fun( w, self->epoch_credits, "epoch_credits", FD_FLAMENCO_TYPE_ARR_END, "epoch_credits", level-- );
  /* Done walking deque */

  fd_vote_block_timestamp_walk(w, &self->last_timestamp, fun, "last_timestamp", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_state_1_14_11", level--);
}
ulong fd_vote_state_1_14_11_size(fd_vote_state_1_14_11_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->node_pubkey);
  size += fd_pubkey_size(&self->authorized_withdrawer);
  size += sizeof(char);
  if ( self->votes ) {
    size += sizeof(ulong);
    for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes ); !deq_fd_vote_lockout_t_iter_done( self->votes, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->votes, iter );
      size += fd_vote_lockout_size(ele);
    }
  } else {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if( self->has_root_slot ) {
    size += sizeof(ulong);
  }
  size += fd_vote_authorized_voters_size(&self->authorized_voters);
  size += fd_vote_prior_voters_size(&self->prior_voters);
  if ( self->epoch_credits ) {
    size += sizeof(ulong);
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      size += fd_vote_epoch_credits_size(ele);
    }
  } else {
    size += sizeof(ulong);
  }
  size += fd_vote_block_timestamp_size(&self->last_timestamp);
  return size;
}

int fd_vote_state_1_14_11_encode(fd_vote_state_1_14_11_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->node_pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->authorized_withdrawer, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->commission), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( self->votes ) {
    ulong votes_len = deq_fd_vote_lockout_t_cnt(self->votes);
    err = fd_bincode_uint64_encode(votes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes ); !deq_fd_vote_lockout_t_iter_done( self->votes, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t const * ele = deq_fd_vote_lockout_t_iter_ele_const( self->votes, iter );
      err = fd_vote_lockout_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong votes_len = 0;
    err = fd_bincode_uint64_encode(votes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_bool_encode( self->has_root_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_root_slot ) {
    err = fd_bincode_uint64_encode( self->root_slot, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_vote_authorized_voters_encode(&self->authorized_voters, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_prior_voters_encode(&self->prior_voters, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( self->epoch_credits ) {
    ulong epoch_credits_len = deq_fd_vote_epoch_credits_t_cnt(self->epoch_credits);
    err = fd_bincode_uint64_encode(epoch_credits_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t const * ele = deq_fd_vote_epoch_credits_t_iter_ele_const( self->epoch_credits, iter );
      err = fd_vote_epoch_credits_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong epoch_credits_len = 0;
    err = fd_bincode_uint64_encode(epoch_credits_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_vote_block_timestamp_encode(&self->last_timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_state_decode(fd_vote_state_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_state_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_state_new(self);
  fd_vote_state_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_state_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong votes_len;
  err = fd_bincode_uint64_decode( &votes_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( votes_len > 35 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < votes_len; ++i) {
    err = fd_landed_vote_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_vote_authorized_voters_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_prior_voters_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong epoch_credits_len;
  err = fd_bincode_uint64_decode( &epoch_credits_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( epoch_credits_len > 100 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  err = fd_bincode_bytes_decode_preflight(epoch_credits_len * 24, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_block_timestamp_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_state_decode_unsafe(fd_vote_state_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->node_pubkey, ctx);
  fd_pubkey_decode_unsafe(&self->authorized_withdrawer, ctx);
  fd_bincode_uint8_decode_unsafe(&self->commission, ctx);
  ulong votes_len;
  fd_bincode_uint64_decode_unsafe( &votes_len, ctx );
  self->votes = deq_fd_landed_vote_t_alloc( ctx->valloc );
  for (ulong i = 0; i < votes_len; ++i) {
    fd_landed_vote_t * elem = deq_fd_landed_vote_t_push_tail_nocopy(self->votes);
    fd_landed_vote_new(elem);
    fd_landed_vote_decode_unsafe(elem, ctx);
  }
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_root_slot = !!o;
    if( o ) {
      fd_bincode_uint64_decode_unsafe( &self->root_slot, ctx );
    }
  }
  fd_vote_authorized_voters_decode_unsafe(&self->authorized_voters, ctx);
  fd_vote_prior_voters_decode_unsafe(&self->prior_voters, ctx);
  ulong epoch_credits_len;
  fd_bincode_uint64_decode_unsafe( &epoch_credits_len, ctx );
  self->epoch_credits = deq_fd_vote_epoch_credits_t_alloc( ctx->valloc );
  for (ulong i = 0; i < epoch_credits_len; ++i) {
    fd_vote_epoch_credits_t * elem = deq_fd_vote_epoch_credits_t_push_tail_nocopy(self->epoch_credits);
    fd_vote_epoch_credits_new(elem);
    fd_vote_epoch_credits_decode_unsafe(elem, ctx);
  }
  fd_vote_block_timestamp_decode_unsafe(&self->last_timestamp, ctx);
}
int fd_vote_state_decode_offsets(fd_vote_state_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->node_pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->authorized_withdrawer_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->commission_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->votes_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong votes_len;
  err = fd_bincode_uint64_decode( &votes_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( votes_len > 35 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < votes_len; ++i) {
    err = fd_landed_vote_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  self->root_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->authorized_voters_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_vote_authorized_voters_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->prior_voters_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_vote_prior_voters_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->epoch_credits_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong epoch_credits_len;
  err = fd_bincode_uint64_decode( &epoch_credits_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( epoch_credits_len > 100 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  err = fd_bincode_bytes_decode_preflight(epoch_credits_len * 24, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->last_timestamp_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_vote_block_timestamp_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_state_new(fd_vote_state_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_state_t));
  fd_pubkey_new(&self->node_pubkey);
  fd_pubkey_new(&self->authorized_withdrawer);
  fd_vote_authorized_voters_new(&self->authorized_voters);
  fd_vote_prior_voters_new(&self->prior_voters);
  fd_vote_block_timestamp_new(&self->last_timestamp);
}
void fd_vote_state_destroy(fd_vote_state_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->node_pubkey, ctx);
  fd_pubkey_destroy(&self->authorized_withdrawer, ctx);
  if ( self->votes ) {
    for ( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( self->votes ); !deq_fd_landed_vote_t_iter_done( self->votes, iter ); iter = deq_fd_landed_vote_t_iter_next( self->votes, iter ) ) {
      fd_landed_vote_t * ele = deq_fd_landed_vote_t_iter_ele( self->votes, iter );
      fd_landed_vote_destroy(ele, ctx);
    }
    fd_valloc_free( ctx->valloc, deq_fd_landed_vote_t_delete( deq_fd_landed_vote_t_leave( self->votes) ) );
    self->votes = NULL;
  }
  if( self->has_root_slot ) {
    self->has_root_slot = 0;
  }
  fd_vote_authorized_voters_destroy(&self->authorized_voters, ctx);
  fd_vote_prior_voters_destroy(&self->prior_voters, ctx);
  if ( self->epoch_credits ) {
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      fd_vote_epoch_credits_destroy(ele, ctx);
    }
    fd_valloc_free( ctx->valloc, deq_fd_vote_epoch_credits_t_delete( deq_fd_vote_epoch_credits_t_leave( self->epoch_credits) ) );
    self->epoch_credits = NULL;
  }
  fd_vote_block_timestamp_destroy(&self->last_timestamp, ctx);
}

ulong fd_vote_state_footprint( void ){ return FD_VOTE_STATE_FOOTPRINT; }
ulong fd_vote_state_align( void ){ return FD_VOTE_STATE_ALIGN; }

void fd_vote_state_walk(void * w, fd_vote_state_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_state", level++);
  fd_pubkey_walk(w, &self->node_pubkey, fun, "node_pubkey", level);
  fd_pubkey_walk(w, &self->authorized_withdrawer, fun, "authorized_withdrawer", level);
  fun( w, &self->commission, "commission", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );

  /* Walk deque */
  fun( w, self->votes, "votes", FD_FLAMENCO_TYPE_ARR, "votes", level++ );
  if( self->votes ) {
    for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( self->votes );
         !deq_fd_landed_vote_t_iter_done( self->votes, iter );
         iter = deq_fd_landed_vote_t_iter_next( self->votes, iter ) ) {
      fd_landed_vote_t * ele = deq_fd_landed_vote_t_iter_ele( self->votes, iter );
      fd_landed_vote_walk(w, ele, fun, "votes", level );
    }
  }
  fun( w, self->votes, "votes", FD_FLAMENCO_TYPE_ARR_END, "votes", level-- );
  /* Done walking deque */

  if( !self->has_root_slot ) {
    fun( w, NULL, "root_slot", FD_FLAMENCO_TYPE_NULL, "ulong", level );
  } else {
    fun( w, &self->root_slot, "root_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level );
  }
  fd_vote_authorized_voters_walk(w, &self->authorized_voters, fun, "authorized_voters", level);
  fd_vote_prior_voters_walk(w, &self->prior_voters, fun, "prior_voters", level);

  /* Walk deque */
  fun( w, self->epoch_credits, "epoch_credits", FD_FLAMENCO_TYPE_ARR, "epoch_credits", level++ );
  if( self->epoch_credits ) {
    for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits );
         !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter );
         iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      fd_vote_epoch_credits_walk(w, ele, fun, "epoch_credits", level );
    }
  }
  fun( w, self->epoch_credits, "epoch_credits", FD_FLAMENCO_TYPE_ARR_END, "epoch_credits", level-- );
  /* Done walking deque */

  fd_vote_block_timestamp_walk(w, &self->last_timestamp, fun, "last_timestamp", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_state", level--);
}
ulong fd_vote_state_size(fd_vote_state_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->node_pubkey);
  size += fd_pubkey_size(&self->authorized_withdrawer);
  size += sizeof(char);
  if ( self->votes ) {
    size += sizeof(ulong);
    for ( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( self->votes ); !deq_fd_landed_vote_t_iter_done( self->votes, iter ); iter = deq_fd_landed_vote_t_iter_next( self->votes, iter ) ) {
      fd_landed_vote_t * ele = deq_fd_landed_vote_t_iter_ele( self->votes, iter );
      size += fd_landed_vote_size(ele);
    }
  } else {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if( self->has_root_slot ) {
    size += sizeof(ulong);
  }
  size += fd_vote_authorized_voters_size(&self->authorized_voters);
  size += fd_vote_prior_voters_size(&self->prior_voters);
  if ( self->epoch_credits ) {
    size += sizeof(ulong);
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      size += fd_vote_epoch_credits_size(ele);
    }
  } else {
    size += sizeof(ulong);
  }
  size += fd_vote_block_timestamp_size(&self->last_timestamp);
  return size;
}

int fd_vote_state_encode(fd_vote_state_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->node_pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->authorized_withdrawer, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->commission), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( self->votes ) {
    ulong votes_len = deq_fd_landed_vote_t_cnt(self->votes);
    err = fd_bincode_uint64_encode(votes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( self->votes ); !deq_fd_landed_vote_t_iter_done( self->votes, iter ); iter = deq_fd_landed_vote_t_iter_next( self->votes, iter ) ) {
      fd_landed_vote_t const * ele = deq_fd_landed_vote_t_iter_ele_const( self->votes, iter );
      err = fd_landed_vote_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong votes_len = 0;
    err = fd_bincode_uint64_encode(votes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_bool_encode( self->has_root_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_root_slot ) {
    err = fd_bincode_uint64_encode( self->root_slot, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_vote_authorized_voters_encode(&self->authorized_voters, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_prior_voters_encode(&self->prior_voters, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if ( self->epoch_credits ) {
    ulong epoch_credits_len = deq_fd_vote_epoch_credits_t_cnt(self->epoch_credits);
    err = fd_bincode_uint64_encode(epoch_credits_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t const * ele = deq_fd_vote_epoch_credits_t_iter_ele_const( self->epoch_credits, iter );
      err = fd_vote_epoch_credits_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong epoch_credits_len = 0;
    err = fd_bincode_uint64_encode(epoch_credits_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_vote_block_timestamp_encode(&self->last_timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_vote_state_versioned_is_v0_23_5(fd_vote_state_versioned_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_vote_state_versioned_is_v1_14_11(fd_vote_state_versioned_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_vote_state_versioned_is_current(fd_vote_state_versioned_t const * self) {
  return self->discriminant == 2;
}
void fd_vote_state_versioned_inner_new(fd_vote_state_versioned_inner_t* self, uint discriminant);
int fd_vote_state_versioned_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_vote_state_0_23_5_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_vote_state_1_14_11_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_vote_state_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_vote_state_versioned_inner_decode_unsafe(fd_vote_state_versioned_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_vote_state_0_23_5_decode_unsafe(&self->v0_23_5, ctx);
    break;
  }
  case 1: {
    fd_vote_state_1_14_11_decode_unsafe(&self->v1_14_11, ctx);
    break;
  }
  case 2: {
    fd_vote_state_decode_unsafe(&self->current, ctx);
    break;
  }
  }
}
int fd_vote_state_versioned_decode(fd_vote_state_versioned_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_state_versioned_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_state_versioned_new(self);
  fd_vote_state_versioned_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_state_versioned_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_vote_state_versioned_inner_decode_preflight(discriminant, ctx);
}
void fd_vote_state_versioned_decode_unsafe(fd_vote_state_versioned_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_vote_state_versioned_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_vote_state_versioned_inner_new(fd_vote_state_versioned_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_vote_state_0_23_5_new(&self->v0_23_5);
    break;
  }
  case 1: {
    fd_vote_state_1_14_11_new(&self->v1_14_11);
    break;
  }
  case 2: {
    fd_vote_state_new(&self->current);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_vote_state_versioned_new_disc(fd_vote_state_versioned_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_vote_state_versioned_inner_new(&self->inner, self->discriminant);
}
void fd_vote_state_versioned_new(fd_vote_state_versioned_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_vote_state_versioned_new_disc(self, UINT_MAX);
}
void fd_vote_state_versioned_inner_destroy(fd_vote_state_versioned_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_vote_state_0_23_5_destroy(&self->v0_23_5, ctx);
    break;
  }
  case 1: {
    fd_vote_state_1_14_11_destroy(&self->v1_14_11, ctx);
    break;
  }
  case 2: {
    fd_vote_state_destroy(&self->current, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_vote_state_versioned_destroy(fd_vote_state_versioned_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_vote_state_versioned_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_vote_state_versioned_footprint( void ){ return FD_VOTE_STATE_VERSIONED_FOOTPRINT; }
ulong fd_vote_state_versioned_align( void ){ return FD_VOTE_STATE_VERSIONED_ALIGN; }

void fd_vote_state_versioned_walk(void * w, fd_vote_state_versioned_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_state_versioned", level++);
  switch (self->discriminant) {
  case 0: {
    fd_vote_state_0_23_5_walk(w, &self->inner.v0_23_5, fun, "v0_23_5", level);
    break;
  }
  case 1: {
    fd_vote_state_1_14_11_walk(w, &self->inner.v1_14_11, fun, "v1_14_11", level);
    break;
  }
  case 2: {
    fd_vote_state_walk(w, &self->inner.current, fun, "current", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_state_versioned", level--);
}
ulong fd_vote_state_versioned_size(fd_vote_state_versioned_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_vote_state_0_23_5_size(&self->inner.v0_23_5);
    break;
  }
  case 1: {
    size += fd_vote_state_1_14_11_size(&self->inner.v1_14_11);
    break;
  }
  case 2: {
    size += fd_vote_state_size(&self->inner.current);
    break;
  }
  }
  return size;
}

int fd_vote_state_versioned_inner_encode(fd_vote_state_versioned_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_vote_state_0_23_5_encode(&self->v0_23_5, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 1: {
    err = fd_vote_state_1_14_11_encode(&self->v1_14_11, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 2: {
    err = fd_vote_state_encode(&self->current, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_vote_state_versioned_encode(fd_vote_state_versioned_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_vote_state_versioned_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_vote_state_update_decode(fd_vote_state_update_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_state_update_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_state_update_new(self);
  fd_vote_state_update_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_state_update_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong lockouts_len;
  err = fd_bincode_uint64_decode( &lockouts_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( lockouts_len > 1228 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  err = fd_bincode_bytes_decode_preflight(lockouts_len * 12, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_vote_state_update_decode_unsafe(fd_vote_state_update_t* self, fd_bincode_decode_ctx_t * ctx) {
  ulong lockouts_len;
  fd_bincode_uint64_decode_unsafe( &lockouts_len, ctx );
  self->lockouts = deq_fd_vote_lockout_t_alloc( ctx->valloc );
  for (ulong i = 0; i < lockouts_len; ++i) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy(self->lockouts);
    fd_vote_lockout_new(elem);
    fd_vote_lockout_decode_unsafe(elem, ctx);
  }
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_root = !!o;
    if( o ) {
      fd_bincode_uint64_decode_unsafe( &self->root, ctx );
    }
  }
  fd_hash_decode_unsafe(&self->hash, ctx);
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      self->timestamp = fd_valloc_malloc( ctx->valloc, 8, sizeof(ulong) );
      fd_bincode_uint64_decode_unsafe( self->timestamp, ctx );
    } else
      self->timestamp = NULL;
  }
}
int fd_vote_state_update_decode_offsets(fd_vote_state_update_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->lockouts_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong lockouts_len;
  err = fd_bincode_uint64_decode( &lockouts_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( lockouts_len > 1228 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  err = fd_bincode_bytes_decode_preflight(lockouts_len * 12, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->root_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->timestamp_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_vote_state_update_new(fd_vote_state_update_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_state_update_t));
  fd_hash_new(&self->hash);
}
void fd_vote_state_update_destroy(fd_vote_state_update_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if ( self->lockouts ) {
    for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->lockouts ); !deq_fd_vote_lockout_t_iter_done( self->lockouts, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->lockouts, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->lockouts, iter );
      fd_vote_lockout_destroy(ele, ctx);
    }
    fd_valloc_free( ctx->valloc, deq_fd_vote_lockout_t_delete( deq_fd_vote_lockout_t_leave( self->lockouts) ) );
    self->lockouts = NULL;
  }
  if( self->has_root ) {
    self->has_root = 0;
  }
  fd_hash_destroy(&self->hash, ctx);
  if( NULL != self->timestamp ) {
    fd_valloc_free( ctx->valloc, self->timestamp );
    self->timestamp = NULL;
  }
}

ulong fd_vote_state_update_footprint( void ){ return FD_VOTE_STATE_UPDATE_FOOTPRINT; }
ulong fd_vote_state_update_align( void ){ return FD_VOTE_STATE_UPDATE_ALIGN; }

void fd_vote_state_update_walk(void * w, fd_vote_state_update_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_state_update", level++);

  /* Walk deque */
  fun( w, self->lockouts, "lockouts", FD_FLAMENCO_TYPE_ARR, "lockouts", level++ );
  if( self->lockouts ) {
    for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->lockouts );
         !deq_fd_vote_lockout_t_iter_done( self->lockouts, iter );
         iter = deq_fd_vote_lockout_t_iter_next( self->lockouts, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->lockouts, iter );
      fd_vote_lockout_walk(w, ele, fun, "lockouts", level );
    }
  }
  fun( w, self->lockouts, "lockouts", FD_FLAMENCO_TYPE_ARR_END, "lockouts", level-- );
  /* Done walking deque */

  if( !self->has_root ) {
    fun( w, NULL, "root", FD_FLAMENCO_TYPE_NULL, "ulong", level );
  } else {
    fun( w, &self->root, "root", FD_FLAMENCO_TYPE_ULONG, "ulong", level );
  }
  fd_hash_walk(w, &self->hash, fun, "hash", level);
  if( !self->timestamp ) {
    fun( w, NULL, "timestamp", FD_FLAMENCO_TYPE_NULL, "ulong", level );
  } else {
    fun( w, self->timestamp, "timestamp", FD_FLAMENCO_TYPE_ULONG, "ulong", level );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_state_update", level--);
}
ulong fd_vote_state_update_size(fd_vote_state_update_t const * self) {
  ulong size = 0;
  if ( self->lockouts ) {
    size += sizeof(ulong);
    for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->lockouts ); !deq_fd_vote_lockout_t_iter_done( self->lockouts, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->lockouts, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->lockouts, iter );
      size += fd_vote_lockout_size(ele);
    }
  } else {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if( self->has_root ) {
    size += sizeof(ulong);
  }
  size += fd_hash_size(&self->hash);
  size += sizeof(char);
  if( NULL !=  self->timestamp ) {
    size += sizeof(ulong);
  }
  return size;
}

int fd_vote_state_update_encode(fd_vote_state_update_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if ( self->lockouts ) {
    ulong lockouts_len = deq_fd_vote_lockout_t_cnt(self->lockouts);
    err = fd_bincode_uint64_encode(lockouts_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->lockouts ); !deq_fd_vote_lockout_t_iter_done( self->lockouts, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->lockouts, iter ) ) {
      fd_vote_lockout_t const * ele = deq_fd_vote_lockout_t_iter_ele_const( self->lockouts, iter );
      err = fd_vote_lockout_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong lockouts_len = 0;
    err = fd_bincode_uint64_encode(lockouts_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_bool_encode( self->has_root, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_root ) {
    err = fd_bincode_uint64_encode( self->root, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if( self->timestamp != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_bincode_uint64_encode( self->timestamp[0], ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_compact_vote_state_update_decode(fd_compact_vote_state_update_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_compact_vote_state_update_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_compact_vote_state_update_new(self);
  fd_compact_vote_state_update_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_compact_vote_state_update_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ushort lockouts_len;
  err = fd_bincode_compact_u16_decode(&lockouts_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (lockouts_len != 0) {
    for( ulong i = 0; i < lockouts_len; ++i) {
      err = fd_lockout_offset_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_compact_vote_state_update_decode_unsafe(fd_compact_vote_state_update_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->root, ctx);
  fd_bincode_compact_u16_decode_unsafe(&self->lockouts_len, ctx);
  if (self->lockouts_len != 0) {
    self->lockouts = (fd_lockout_offset_t *)fd_valloc_malloc( ctx->valloc, FD_LOCKOUT_OFFSET_ALIGN, FD_LOCKOUT_OFFSET_FOOTPRINT*self->lockouts_len);
    for( ulong i = 0; i < self->lockouts_len; ++i) {
      fd_lockout_offset_new(self->lockouts + i);
      fd_lockout_offset_decode_unsafe(self->lockouts + i, ctx);
    }
  } else
    self->lockouts = NULL;
  fd_hash_decode_unsafe(&self->hash, ctx);
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      self->timestamp = fd_valloc_malloc( ctx->valloc, 8, sizeof(ulong) );
      fd_bincode_uint64_decode_unsafe( self->timestamp, ctx );
    } else
      self->timestamp = NULL;
  }
}
int fd_compact_vote_state_update_decode_offsets(fd_compact_vote_state_update_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->root_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->lockouts_off = (uint)((ulong)ctx->data - (ulong)data);
  ushort lockouts_len;
  err = fd_bincode_compact_u16_decode(&lockouts_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (lockouts_len != 0) {
    for( ulong i = 0; i < lockouts_len; ++i) {
      err = fd_lockout_offset_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->timestamp_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_compact_vote_state_update_new(fd_compact_vote_state_update_t* self) {
  fd_memset(self, 0, sizeof(fd_compact_vote_state_update_t));
  fd_hash_new(&self->hash);
}
void fd_compact_vote_state_update_destroy(fd_compact_vote_state_update_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->lockouts) {
    for (ulong i = 0; i < self->lockouts_len; ++i)
      fd_lockout_offset_destroy(self->lockouts + i, ctx);
    fd_valloc_free( ctx->valloc, self->lockouts );
    self->lockouts = NULL;
  }
  fd_hash_destroy(&self->hash, ctx);
  if( NULL != self->timestamp ) {
    fd_valloc_free( ctx->valloc, self->timestamp );
    self->timestamp = NULL;
  }
}

ulong fd_compact_vote_state_update_footprint( void ){ return FD_COMPACT_VOTE_STATE_UPDATE_FOOTPRINT; }
ulong fd_compact_vote_state_update_align( void ){ return FD_COMPACT_VOTE_STATE_UPDATE_ALIGN; }

void fd_compact_vote_state_update_walk(void * w, fd_compact_vote_state_update_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_compact_vote_state_update", level++);
  fun( w, &self->root, "root", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  if (self->lockouts_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "lockouts", level++);
    for (ulong i = 0; i < self->lockouts_len; ++i)
      fd_lockout_offset_walk(w, self->lockouts + i, fun, "lockout_offset", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "lockouts", level-- );
  }
  fd_hash_walk(w, &self->hash, fun, "hash", level);
  if( !self->timestamp ) {
    fun( w, NULL, "timestamp", FD_FLAMENCO_TYPE_NULL, "ulong", level );
  } else {
    fun( w, self->timestamp, "timestamp", FD_FLAMENCO_TYPE_ULONG, "ulong", level );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_compact_vote_state_update", level--);
}
ulong fd_compact_vote_state_update_size(fd_compact_vote_state_update_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  do {
    ushort tmp = (ushort)self->lockouts_len;
    size += fd_bincode_compact_u16_size(&tmp);
    for (ulong i = 0; i < self->lockouts_len; ++i)
      size += fd_lockout_offset_size(self->lockouts + i);
  } while(0);
  size += fd_hash_size(&self->hash);
  size += sizeof(char);
  if( NULL !=  self->timestamp ) {
    size += sizeof(ulong);
  }
  return size;
}

int fd_compact_vote_state_update_encode(fd_compact_vote_state_update_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->root, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_compact_u16_encode(&self->lockouts_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->lockouts_len != 0) {
    for (ulong i = 0; i < self->lockouts_len; ++i) {
      err = fd_lockout_offset_encode(self->lockouts + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if( self->timestamp != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_bincode_uint64_encode( self->timestamp[0], ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_compact_vote_state_update_switch_decode(fd_compact_vote_state_update_switch_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_compact_vote_state_update_switch_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_compact_vote_state_update_switch_new(self);
  fd_compact_vote_state_update_switch_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_compact_vote_state_update_switch_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_compact_vote_state_update_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_compact_vote_state_update_switch_decode_unsafe(fd_compact_vote_state_update_switch_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_compact_vote_state_update_decode_unsafe(&self->compact_vote_state_update, ctx);
  fd_hash_decode_unsafe(&self->hash, ctx);
}
int fd_compact_vote_state_update_switch_decode_offsets(fd_compact_vote_state_update_switch_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->compact_vote_state_update_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_compact_vote_state_update_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_compact_vote_state_update_switch_new(fd_compact_vote_state_update_switch_t* self) {
  fd_memset(self, 0, sizeof(fd_compact_vote_state_update_switch_t));
  fd_compact_vote_state_update_new(&self->compact_vote_state_update);
  fd_hash_new(&self->hash);
}
void fd_compact_vote_state_update_switch_destroy(fd_compact_vote_state_update_switch_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_compact_vote_state_update_destroy(&self->compact_vote_state_update, ctx);
  fd_hash_destroy(&self->hash, ctx);
}

ulong fd_compact_vote_state_update_switch_footprint( void ){ return FD_COMPACT_VOTE_STATE_UPDATE_SWITCH_FOOTPRINT; }
ulong fd_compact_vote_state_update_switch_align( void ){ return FD_COMPACT_VOTE_STATE_UPDATE_SWITCH_ALIGN; }

void fd_compact_vote_state_update_switch_walk(void * w, fd_compact_vote_state_update_switch_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_compact_vote_state_update_switch", level++);
  fd_compact_vote_state_update_walk(w, &self->compact_vote_state_update, fun, "compact_vote_state_update", level);
  fd_hash_walk(w, &self->hash, fun, "hash", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_compact_vote_state_update_switch", level--);
}
ulong fd_compact_vote_state_update_switch_size(fd_compact_vote_state_update_switch_t const * self) {
  ulong size = 0;
  size += fd_compact_vote_state_update_size(&self->compact_vote_state_update);
  size += fd_hash_size(&self->hash);
  return size;
}

int fd_compact_vote_state_update_switch_encode(fd_compact_vote_state_update_switch_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_compact_vote_state_update_encode(&self->compact_vote_state_update, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_slot_history_inner_decode(fd_slot_history_inner_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_slot_history_inner_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_slot_history_inner_new(self);
  fd_slot_history_inner_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_slot_history_inner_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong blocks_len;
  err = fd_bincode_uint64_decode(&blocks_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (blocks_len != 0) {
    for( ulong i = 0; i < blocks_len; ++i) {
      err = fd_bincode_uint64_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_slot_history_inner_decode_unsafe(fd_slot_history_inner_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->blocks_len, ctx);
  if (self->blocks_len != 0) {
    self->blocks = fd_valloc_malloc( ctx->valloc, 8UL, sizeof(ulong)*self->blocks_len );
    for( ulong i = 0; i < self->blocks_len; ++i) {
      fd_bincode_uint64_decode_unsafe(self->blocks + i, ctx);
    }
  } else
    self->blocks = NULL;
}
int fd_slot_history_inner_decode_offsets(fd_slot_history_inner_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->blocks_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong blocks_len;
  err = fd_bincode_uint64_decode(&blocks_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (blocks_len != 0) {
    for( ulong i = 0; i < blocks_len; ++i) {
      err = fd_bincode_uint64_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_slot_history_inner_new(fd_slot_history_inner_t* self) {
  fd_memset(self, 0, sizeof(fd_slot_history_inner_t));
}
void fd_slot_history_inner_destroy(fd_slot_history_inner_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->blocks) {
    fd_valloc_free( ctx->valloc, self->blocks );
    self->blocks = NULL;
  }
}

ulong fd_slot_history_inner_footprint( void ){ return FD_SLOT_HISTORY_INNER_FOOTPRINT; }
ulong fd_slot_history_inner_align( void ){ return FD_SLOT_HISTORY_INNER_ALIGN; }

void fd_slot_history_inner_walk(void * w, fd_slot_history_inner_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_slot_history_inner", level++);
  if (self->blocks_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "blocks", level++);
    for (ulong i = 0; i < self->blocks_len; ++i)
      fun( w, self->blocks + i, "blocks", FD_FLAMENCO_TYPE_ULONG,   "ulong",   level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "blocks", level-- );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_slot_history_inner", level--);
}
ulong fd_slot_history_inner_size(fd_slot_history_inner_t const * self) {
  ulong size = 0;
  do {
    size += sizeof(ulong);
    size += self->blocks_len * sizeof(ulong);
  } while(0);
  return size;
}

int fd_slot_history_inner_encode(fd_slot_history_inner_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->blocks_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->blocks_len != 0) {
    for (ulong i = 0; i < self->blocks_len; ++i) {
      err = fd_bincode_uint64_encode(self->blocks[i], ctx);
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_slot_history_bitvec_decode(fd_slot_history_bitvec_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_slot_history_bitvec_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_slot_history_bitvec_new(self);
  fd_slot_history_bitvec_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_slot_history_bitvec_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_slot_history_inner_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_history_bitvec_decode_unsafe(fd_slot_history_bitvec_t* self, fd_bincode_decode_ctx_t * ctx) {
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      self->bits = (fd_slot_history_inner_t*)fd_valloc_malloc( ctx->valloc, FD_SLOT_HISTORY_INNER_ALIGN, FD_SLOT_HISTORY_INNER_FOOTPRINT );
      fd_slot_history_inner_new( self->bits );
      fd_slot_history_inner_decode_unsafe( self->bits, ctx );
    } else
      self->bits = NULL;
  }
  fd_bincode_uint64_decode_unsafe(&self->len, ctx);
}
int fd_slot_history_bitvec_decode_offsets(fd_slot_history_bitvec_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->bits_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_slot_history_inner_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->len_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_history_bitvec_new(fd_slot_history_bitvec_t* self) {
  fd_memset(self, 0, sizeof(fd_slot_history_bitvec_t));
}
void fd_slot_history_bitvec_destroy(fd_slot_history_bitvec_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if( NULL != self->bits ) {
    fd_slot_history_inner_destroy( self->bits, ctx );
    fd_valloc_free( ctx->valloc, self->bits );
    self->bits = NULL;
  }
}

ulong fd_slot_history_bitvec_footprint( void ){ return FD_SLOT_HISTORY_BITVEC_FOOTPRINT; }
ulong fd_slot_history_bitvec_align( void ){ return FD_SLOT_HISTORY_BITVEC_ALIGN; }

void fd_slot_history_bitvec_walk(void * w, fd_slot_history_bitvec_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_slot_history_bitvec", level++);
  if( !self->bits ) {
    fun( w, NULL, "bits", FD_FLAMENCO_TYPE_NULL, "slot_history_inner", level );
  } else {
    fd_slot_history_inner_walk( w, self->bits, fun, "bits", level );
  }
  fun( w, &self->len, "len", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_slot_history_bitvec", level--);
}
ulong fd_slot_history_bitvec_size(fd_slot_history_bitvec_t const * self) {
  ulong size = 0;
  size += sizeof(char);
  if( NULL !=  self->bits ) {
    size += fd_slot_history_inner_size( self->bits );
  }
  size += sizeof(ulong);
  return size;
}

int fd_slot_history_bitvec_encode(fd_slot_history_bitvec_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if( self->bits != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_slot_history_inner_encode( self->bits, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint64_encode(self->len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_slot_history_decode(fd_slot_history_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_slot_history_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_slot_history_new(self);
  fd_slot_history_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_slot_history_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_slot_history_bitvec_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_history_decode_unsafe(fd_slot_history_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_slot_history_bitvec_decode_unsafe(&self->bits, ctx);
  fd_bincode_uint64_decode_unsafe(&self->next_slot, ctx);
}
int fd_slot_history_decode_offsets(fd_slot_history_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->bits_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_slot_history_bitvec_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->next_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_history_new(fd_slot_history_t* self) {
  fd_memset(self, 0, sizeof(fd_slot_history_t));
  fd_slot_history_bitvec_new(&self->bits);
}
void fd_slot_history_destroy(fd_slot_history_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_slot_history_bitvec_destroy(&self->bits, ctx);
}

ulong fd_slot_history_footprint( void ){ return FD_SLOT_HISTORY_FOOTPRINT; }
ulong fd_slot_history_align( void ){ return FD_SLOT_HISTORY_ALIGN; }

void fd_slot_history_walk(void * w, fd_slot_history_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_slot_history", level++);
  fd_slot_history_bitvec_walk(w, &self->bits, fun, "bits", level);
  fun( w, &self->next_slot, "next_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_slot_history", level--);
}
ulong fd_slot_history_size(fd_slot_history_t const * self) {
  ulong size = 0;
  size += fd_slot_history_bitvec_size(&self->bits);
  size += sizeof(ulong);
  return size;
}

int fd_slot_history_encode(fd_slot_history_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_slot_history_bitvec_encode(&self->bits, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->next_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_slot_hash_decode(fd_slot_hash_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_slot_hash_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_slot_hash_new(self);
  fd_slot_hash_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_slot_hash_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_hash_decode_unsafe(fd_slot_hash_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
  fd_hash_decode_unsafe(&self->hash, ctx);
}
int fd_slot_hash_decode_offsets(fd_slot_hash_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_hash_new(fd_slot_hash_t* self) {
  fd_memset(self, 0, sizeof(fd_slot_hash_t));
  fd_hash_new(&self->hash);
}
void fd_slot_hash_destroy(fd_slot_hash_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_hash_destroy(&self->hash, ctx);
}

ulong fd_slot_hash_footprint( void ){ return FD_SLOT_HASH_FOOTPRINT; }
ulong fd_slot_hash_align( void ){ return FD_SLOT_HASH_ALIGN; }

void fd_slot_hash_walk(void * w, fd_slot_hash_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_slot_hash", level++);
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_hash_walk(w, &self->hash, fun, "hash", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_slot_hash", level--);
}
ulong fd_slot_hash_size(fd_slot_hash_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_hash_size(&self->hash);
  return size;
}

int fd_slot_hash_encode(fd_slot_hash_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_slot_hashes_decode(fd_slot_hashes_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_slot_hashes_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_slot_hashes_new(self);
  fd_slot_hashes_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_slot_hashes_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong hashes_len;
  err = fd_bincode_uint64_decode( &hashes_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( hashes_len > 512 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < hashes_len; ++i) {
    err = fd_slot_hash_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_slot_hashes_decode_unsafe(fd_slot_hashes_t* self, fd_bincode_decode_ctx_t * ctx) {
  ulong hashes_len;
  fd_bincode_uint64_decode_unsafe( &hashes_len, ctx );
  self->hashes = deq_fd_slot_hash_t_alloc( ctx->valloc );
  for (ulong i = 0; i < hashes_len; ++i) {
    fd_slot_hash_t * elem = deq_fd_slot_hash_t_push_tail_nocopy(self->hashes);
    fd_slot_hash_new(elem);
    fd_slot_hash_decode_unsafe(elem, ctx);
  }
}
int fd_slot_hashes_decode_offsets(fd_slot_hashes_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->hashes_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong hashes_len;
  err = fd_bincode_uint64_decode( &hashes_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( hashes_len > 512 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < hashes_len; ++i) {
    err = fd_slot_hash_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_slot_hashes_new(fd_slot_hashes_t* self) {
  fd_memset(self, 0, sizeof(fd_slot_hashes_t));
}
void fd_slot_hashes_destroy(fd_slot_hashes_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if ( self->hashes ) {
    for ( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( self->hashes ); !deq_fd_slot_hash_t_iter_done( self->hashes, iter ); iter = deq_fd_slot_hash_t_iter_next( self->hashes, iter ) ) {
      fd_slot_hash_t * ele = deq_fd_slot_hash_t_iter_ele( self->hashes, iter );
      fd_slot_hash_destroy(ele, ctx);
    }
    fd_valloc_free( ctx->valloc, deq_fd_slot_hash_t_delete( deq_fd_slot_hash_t_leave( self->hashes) ) );
    self->hashes = NULL;
  }
}

ulong fd_slot_hashes_footprint( void ){ return FD_SLOT_HASHES_FOOTPRINT; }
ulong fd_slot_hashes_align( void ){ return FD_SLOT_HASHES_ALIGN; }

void fd_slot_hashes_walk(void * w, fd_slot_hashes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_slot_hashes", level++);

  /* Walk deque */
  fun( w, self->hashes, "hashes", FD_FLAMENCO_TYPE_ARR, "hashes", level++ );
  if( self->hashes ) {
    for( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( self->hashes );
         !deq_fd_slot_hash_t_iter_done( self->hashes, iter );
         iter = deq_fd_slot_hash_t_iter_next( self->hashes, iter ) ) {
      fd_slot_hash_t * ele = deq_fd_slot_hash_t_iter_ele( self->hashes, iter );
      fd_slot_hash_walk(w, ele, fun, "hashes", level );
    }
  }
  fun( w, self->hashes, "hashes", FD_FLAMENCO_TYPE_ARR_END, "hashes", level-- );
  /* Done walking deque */

  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_slot_hashes", level--);
}
ulong fd_slot_hashes_size(fd_slot_hashes_t const * self) {
  ulong size = 0;
  if ( self->hashes ) {
    size += sizeof(ulong);
    for ( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( self->hashes ); !deq_fd_slot_hash_t_iter_done( self->hashes, iter ); iter = deq_fd_slot_hash_t_iter_next( self->hashes, iter ) ) {
      fd_slot_hash_t * ele = deq_fd_slot_hash_t_iter_ele( self->hashes, iter );
      size += fd_slot_hash_size(ele);
    }
  } else {
    size += sizeof(ulong);
  }
  return size;
}

int fd_slot_hashes_encode(fd_slot_hashes_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if ( self->hashes ) {
    ulong hashes_len = deq_fd_slot_hash_t_cnt(self->hashes);
    err = fd_bincode_uint64_encode(hashes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( self->hashes ); !deq_fd_slot_hash_t_iter_done( self->hashes, iter ); iter = deq_fd_slot_hash_t_iter_next( self->hashes, iter ) ) {
      fd_slot_hash_t const * ele = deq_fd_slot_hash_t_iter_ele_const( self->hashes, iter );
      err = fd_slot_hash_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong hashes_len = 0;
    err = fd_bincode_uint64_encode(hashes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_block_block_hash_entry_decode(fd_block_block_hash_entry_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_block_block_hash_entry_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_block_block_hash_entry_new(self);
  fd_block_block_hash_entry_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_block_block_hash_entry_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_calculator_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_block_block_hash_entry_decode_unsafe(fd_block_block_hash_entry_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_hash_decode_unsafe(&self->blockhash, ctx);
  fd_fee_calculator_decode_unsafe(&self->fee_calculator, ctx);
}
int fd_block_block_hash_entry_decode_offsets(fd_block_block_hash_entry_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->blockhash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->fee_calculator_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_fee_calculator_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_block_block_hash_entry_new(fd_block_block_hash_entry_t* self) {
  fd_memset(self, 0, sizeof(fd_block_block_hash_entry_t));
  fd_hash_new(&self->blockhash);
  fd_fee_calculator_new(&self->fee_calculator);
}
void fd_block_block_hash_entry_destroy(fd_block_block_hash_entry_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_hash_destroy(&self->blockhash, ctx);
  fd_fee_calculator_destroy(&self->fee_calculator, ctx);
}

ulong fd_block_block_hash_entry_footprint( void ){ return FD_BLOCK_BLOCK_HASH_ENTRY_FOOTPRINT; }
ulong fd_block_block_hash_entry_align( void ){ return FD_BLOCK_BLOCK_HASH_ENTRY_ALIGN; }

void fd_block_block_hash_entry_walk(void * w, fd_block_block_hash_entry_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_block_block_hash_entry", level++);
  fd_hash_walk(w, &self->blockhash, fun, "blockhash", level);
  fd_fee_calculator_walk(w, &self->fee_calculator, fun, "fee_calculator", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_block_block_hash_entry", level--);
}
ulong fd_block_block_hash_entry_size(fd_block_block_hash_entry_t const * self) {
  ulong size = 0;
  size += fd_hash_size(&self->blockhash);
  size += fd_fee_calculator_size(&self->fee_calculator);
  return size;
}

int fd_block_block_hash_entry_encode(fd_block_block_hash_entry_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_hash_encode(&self->blockhash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_calculator_encode(&self->fee_calculator, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_recent_block_hashes_decode(fd_recent_block_hashes_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_recent_block_hashes_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_recent_block_hashes_new(self);
  fd_recent_block_hashes_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_recent_block_hashes_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong hashes_len;
  err = fd_bincode_uint64_decode( &hashes_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( hashes_len > 350 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < hashes_len; ++i) {
    err = fd_block_block_hash_entry_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_recent_block_hashes_decode_unsafe(fd_recent_block_hashes_t* self, fd_bincode_decode_ctx_t * ctx) {
  ulong hashes_len;
  fd_bincode_uint64_decode_unsafe( &hashes_len, ctx );
  self->hashes = deq_fd_block_block_hash_entry_t_alloc( ctx->valloc );
  for (ulong i = 0; i < hashes_len; ++i) {
    fd_block_block_hash_entry_t * elem = deq_fd_block_block_hash_entry_t_push_tail_nocopy(self->hashes);
    fd_block_block_hash_entry_new(elem);
    fd_block_block_hash_entry_decode_unsafe(elem, ctx);
  }
}
int fd_recent_block_hashes_decode_offsets(fd_recent_block_hashes_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->hashes_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong hashes_len;
  err = fd_bincode_uint64_decode( &hashes_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( hashes_len > 350 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < hashes_len; ++i) {
    err = fd_block_block_hash_entry_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_recent_block_hashes_new(fd_recent_block_hashes_t* self) {
  fd_memset(self, 0, sizeof(fd_recent_block_hashes_t));
}
void fd_recent_block_hashes_destroy(fd_recent_block_hashes_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if ( self->hashes ) {
    for ( deq_fd_block_block_hash_entry_t_iter_t iter = deq_fd_block_block_hash_entry_t_iter_init( self->hashes ); !deq_fd_block_block_hash_entry_t_iter_done( self->hashes, iter ); iter = deq_fd_block_block_hash_entry_t_iter_next( self->hashes, iter ) ) {
      fd_block_block_hash_entry_t * ele = deq_fd_block_block_hash_entry_t_iter_ele( self->hashes, iter );
      fd_block_block_hash_entry_destroy(ele, ctx);
    }
    fd_valloc_free( ctx->valloc, deq_fd_block_block_hash_entry_t_delete( deq_fd_block_block_hash_entry_t_leave( self->hashes) ) );
    self->hashes = NULL;
  }
}

ulong fd_recent_block_hashes_footprint( void ){ return FD_RECENT_BLOCK_HASHES_FOOTPRINT; }
ulong fd_recent_block_hashes_align( void ){ return FD_RECENT_BLOCK_HASHES_ALIGN; }

void fd_recent_block_hashes_walk(void * w, fd_recent_block_hashes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_recent_block_hashes", level++);

  /* Walk deque */
  fun( w, self->hashes, "hashes", FD_FLAMENCO_TYPE_ARR, "hashes", level++ );
  if( self->hashes ) {
    for( deq_fd_block_block_hash_entry_t_iter_t iter = deq_fd_block_block_hash_entry_t_iter_init( self->hashes );
         !deq_fd_block_block_hash_entry_t_iter_done( self->hashes, iter );
         iter = deq_fd_block_block_hash_entry_t_iter_next( self->hashes, iter ) ) {
      fd_block_block_hash_entry_t * ele = deq_fd_block_block_hash_entry_t_iter_ele( self->hashes, iter );
      fd_block_block_hash_entry_walk(w, ele, fun, "hashes", level );
    }
  }
  fun( w, self->hashes, "hashes", FD_FLAMENCO_TYPE_ARR_END, "hashes", level-- );
  /* Done walking deque */

  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_recent_block_hashes", level--);
}
ulong fd_recent_block_hashes_size(fd_recent_block_hashes_t const * self) {
  ulong size = 0;
  if ( self->hashes ) {
    size += sizeof(ulong);
    for ( deq_fd_block_block_hash_entry_t_iter_t iter = deq_fd_block_block_hash_entry_t_iter_init( self->hashes ); !deq_fd_block_block_hash_entry_t_iter_done( self->hashes, iter ); iter = deq_fd_block_block_hash_entry_t_iter_next( self->hashes, iter ) ) {
      fd_block_block_hash_entry_t * ele = deq_fd_block_block_hash_entry_t_iter_ele( self->hashes, iter );
      size += fd_block_block_hash_entry_size(ele);
    }
  } else {
    size += sizeof(ulong);
  }
  return size;
}

int fd_recent_block_hashes_encode(fd_recent_block_hashes_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if ( self->hashes ) {
    ulong hashes_len = deq_fd_block_block_hash_entry_t_cnt(self->hashes);
    err = fd_bincode_uint64_encode(hashes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_fd_block_block_hash_entry_t_iter_t iter = deq_fd_block_block_hash_entry_t_iter_init( self->hashes ); !deq_fd_block_block_hash_entry_t_iter_done( self->hashes, iter ); iter = deq_fd_block_block_hash_entry_t_iter_next( self->hashes, iter ) ) {
      fd_block_block_hash_entry_t const * ele = deq_fd_block_block_hash_entry_t_iter_ele_const( self->hashes, iter );
      err = fd_block_block_hash_entry_encode(ele, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong hashes_len = 0;
    err = fd_bincode_uint64_encode(hashes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_slot_meta_decode(fd_slot_meta_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_slot_meta_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_slot_meta_new(self);
  fd_slot_meta_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_slot_meta_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ulong next_slot_len;
  err = fd_bincode_uint64_decode(&next_slot_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (next_slot_len != 0) {
    for( ulong i = 0; i < next_slot_len; ++i) {
      err = fd_bincode_uint64_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong entry_end_indexes_len;
  err = fd_bincode_uint64_decode(&entry_end_indexes_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (entry_end_indexes_len != 0) {
    for( ulong i = 0; i < entry_end_indexes_len; ++i) {
      err = fd_bincode_uint32_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_slot_meta_decode_unsafe(fd_slot_meta_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->consumed, ctx);
  fd_bincode_uint64_decode_unsafe(&self->received, ctx);
  fd_bincode_uint64_decode_unsafe(&self->first_shred_timestamp, ctx);
  fd_bincode_uint64_decode_unsafe(&self->last_index, ctx);
  fd_bincode_uint64_decode_unsafe(&self->parent_slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->next_slot_len, ctx);
  if (self->next_slot_len != 0) {
    self->next_slot = fd_valloc_malloc( ctx->valloc, 8UL, sizeof(ulong)*self->next_slot_len );
    for( ulong i = 0; i < self->next_slot_len; ++i) {
      fd_bincode_uint64_decode_unsafe(self->next_slot + i, ctx);
    }
  } else
    self->next_slot = NULL;
  fd_bincode_uint8_decode_unsafe(&self->is_connected, ctx);
  fd_bincode_uint64_decode_unsafe(&self->entry_end_indexes_len, ctx);
  if (self->entry_end_indexes_len != 0) {
    self->entry_end_indexes = fd_valloc_malloc( ctx->valloc, 8UL, sizeof(uint)*self->entry_end_indexes_len );
    for( ulong i = 0; i < self->entry_end_indexes_len; ++i) {
      fd_bincode_uint32_decode_unsafe(self->entry_end_indexes + i, ctx);
    }
  } else
    self->entry_end_indexes = NULL;
}
int fd_slot_meta_decode_offsets(fd_slot_meta_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->consumed_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->received_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->first_shred_timestamp_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->last_index_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->parent_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->next_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong next_slot_len;
  err = fd_bincode_uint64_decode(&next_slot_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (next_slot_len != 0) {
    for( ulong i = 0; i < next_slot_len; ++i) {
      err = fd_bincode_uint64_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->is_connected_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->entry_end_indexes_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong entry_end_indexes_len;
  err = fd_bincode_uint64_decode(&entry_end_indexes_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (entry_end_indexes_len != 0) {
    for( ulong i = 0; i < entry_end_indexes_len; ++i) {
      err = fd_bincode_uint32_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_slot_meta_new(fd_slot_meta_t* self) {
  fd_memset(self, 0, sizeof(fd_slot_meta_t));
}
void fd_slot_meta_destroy(fd_slot_meta_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->next_slot) {
    fd_valloc_free( ctx->valloc, self->next_slot );
    self->next_slot = NULL;
  }
  if (NULL != self->entry_end_indexes) {
    fd_valloc_free( ctx->valloc, self->entry_end_indexes );
    self->entry_end_indexes = NULL;
  }
}

ulong fd_slot_meta_footprint( void ){ return FD_SLOT_META_FOOTPRINT; }
ulong fd_slot_meta_align( void ){ return FD_SLOT_META_ALIGN; }

void fd_slot_meta_walk(void * w, fd_slot_meta_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_slot_meta", level++);
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->consumed, "consumed", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->received, "received", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->first_shred_timestamp, "first_shred_timestamp", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->last_index, "last_index", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->parent_slot, "parent_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  if (self->next_slot_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "next_slot", level++);
    for (ulong i = 0; i < self->next_slot_len; ++i)
      fun( w, self->next_slot + i, "next_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",   level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "next_slot", level-- );
  }
  fun( w, &self->is_connected, "is_connected", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  if (self->entry_end_indexes_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "entry_end_indexes", level++);
    for (ulong i = 0; i < self->entry_end_indexes_len; ++i)
      fun( w, self->entry_end_indexes + i, "entry_end_indexes", FD_FLAMENCO_TYPE_UINT,    "uint",    level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "entry_end_indexes", level-- );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_slot_meta", level--);
}
ulong fd_slot_meta_size(fd_slot_meta_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  do {
    size += sizeof(ulong);
    size += self->next_slot_len * sizeof(ulong);
  } while(0);
  size += sizeof(char);
  do {
    size += sizeof(ulong);
    size += self->entry_end_indexes_len * sizeof(uint);
  } while(0);
  return size;
}

int fd_slot_meta_encode(fd_slot_meta_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->consumed, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->received, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->first_shred_timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->last_index, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->parent_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->next_slot_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->next_slot_len != 0) {
    for (ulong i = 0; i < self->next_slot_len; ++i) {
      err = fd_bincode_uint64_encode(self->next_slot[i], ctx);
    }
  }
  err = fd_bincode_uint8_encode( (uchar)(self->is_connected), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->entry_end_indexes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->entry_end_indexes_len != 0) {
    for (ulong i = 0; i < self->entry_end_indexes_len; ++i) {
      err = fd_bincode_uint32_encode(self->entry_end_indexes[i], ctx);
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_clock_timestamp_vote_decode(fd_clock_timestamp_vote_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_clock_timestamp_vote_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_clock_timestamp_vote_new(self);
  fd_clock_timestamp_vote_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_clock_timestamp_vote_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_clock_timestamp_vote_decode_unsafe(fd_clock_timestamp_vote_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->pubkey, ctx);
  fd_bincode_uint64_decode_unsafe((ulong *) &self->timestamp, ctx);
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
}
int fd_clock_timestamp_vote_decode_offsets(fd_clock_timestamp_vote_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->timestamp_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_clock_timestamp_vote_new(fd_clock_timestamp_vote_t* self) {
  fd_memset(self, 0, sizeof(fd_clock_timestamp_vote_t));
  fd_pubkey_new(&self->pubkey);
}
void fd_clock_timestamp_vote_destroy(fd_clock_timestamp_vote_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->pubkey, ctx);
}

ulong fd_clock_timestamp_vote_footprint( void ){ return FD_CLOCK_TIMESTAMP_VOTE_FOOTPRINT; }
ulong fd_clock_timestamp_vote_align( void ){ return FD_CLOCK_TIMESTAMP_VOTE_ALIGN; }

void fd_clock_timestamp_vote_walk(void * w, fd_clock_timestamp_vote_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_clock_timestamp_vote", level++);
  fd_pubkey_walk(w, &self->pubkey, fun, "pubkey", level);
  fun( w, &self->timestamp, "timestamp", FD_FLAMENCO_TYPE_SLONG,   "long",      level );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_clock_timestamp_vote", level--);
}
ulong fd_clock_timestamp_vote_size(fd_clock_timestamp_vote_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->pubkey);
  size += sizeof(long);
  size += sizeof(ulong);
  return size;
}

int fd_clock_timestamp_vote_encode(fd_clock_timestamp_vote_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode( (ulong)self->timestamp, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_clock_timestamp_votes_decode(fd_clock_timestamp_votes_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_clock_timestamp_votes_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_clock_timestamp_votes_new(self);
  fd_clock_timestamp_votes_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_clock_timestamp_votes_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong votes_len;
  err = fd_bincode_uint64_decode(&votes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  for (ulong i = 0; i < votes_len; ++i) {
    err = fd_clock_timestamp_vote_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_clock_timestamp_votes_decode_unsafe(fd_clock_timestamp_votes_t* self, fd_bincode_decode_ctx_t * ctx) {
  ulong votes_len;
  fd_bincode_uint64_decode_unsafe(&votes_len, ctx);
  self->votes_pool = fd_clock_timestamp_vote_t_map_alloc(ctx->valloc, fd_ulong_max(votes_len, 10000));
  self->votes_root = NULL;
  for (ulong i = 0; i < votes_len; ++i) {
    fd_clock_timestamp_vote_t_mapnode_t* node = fd_clock_timestamp_vote_t_map_acquire(self->votes_pool);
    fd_clock_timestamp_vote_new(&node->elem);
    fd_clock_timestamp_vote_decode_unsafe(&node->elem, ctx);
    fd_clock_timestamp_vote_t_map_insert(self->votes_pool, &self->votes_root, node);
  }
}
int fd_clock_timestamp_votes_decode_offsets(fd_clock_timestamp_votes_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->votes_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong votes_len;
  err = fd_bincode_uint64_decode(&votes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  for (ulong i = 0; i < votes_len; ++i) {
    err = fd_clock_timestamp_vote_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_clock_timestamp_votes_new(fd_clock_timestamp_votes_t* self) {
  fd_memset(self, 0, sizeof(fd_clock_timestamp_votes_t));
}
void fd_clock_timestamp_votes_destroy(fd_clock_timestamp_votes_t* self, fd_bincode_destroy_ctx_t * ctx) {
  for ( fd_clock_timestamp_vote_t_mapnode_t* n = fd_clock_timestamp_vote_t_map_minimum(self->votes_pool, self->votes_root); n; n = fd_clock_timestamp_vote_t_map_successor(self->votes_pool, n) ) {
    fd_clock_timestamp_vote_destroy(&n->elem, ctx);
  }
  fd_valloc_free( ctx->valloc, fd_clock_timestamp_vote_t_map_delete(fd_clock_timestamp_vote_t_map_leave( self->votes_pool) ) );
  self->votes_pool = NULL;
  self->votes_root = NULL;
}

ulong fd_clock_timestamp_votes_footprint( void ){ return FD_CLOCK_TIMESTAMP_VOTES_FOOTPRINT; }
ulong fd_clock_timestamp_votes_align( void ){ return FD_CLOCK_TIMESTAMP_VOTES_ALIGN; }

void fd_clock_timestamp_votes_walk(void * w, fd_clock_timestamp_votes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_clock_timestamp_votes", level++);
  if (self->votes_root) {
    for ( fd_clock_timestamp_vote_t_mapnode_t* n = fd_clock_timestamp_vote_t_map_minimum(self->votes_pool, self->votes_root); n; n = fd_clock_timestamp_vote_t_map_successor(self->votes_pool, n) ) {
      fd_clock_timestamp_vote_walk(w, &n->elem, fun, "votes", level );
    }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_clock_timestamp_votes", level--);
}
ulong fd_clock_timestamp_votes_size(fd_clock_timestamp_votes_t const * self) {
  ulong size = 0;
  if (self->votes_root) {
    size += sizeof(ulong);
    for ( fd_clock_timestamp_vote_t_mapnode_t* n = fd_clock_timestamp_vote_t_map_minimum(self->votes_pool, self->votes_root); n; n = fd_clock_timestamp_vote_t_map_successor(self->votes_pool, n) ) {
      size += fd_clock_timestamp_vote_size(&n->elem);
    }
  } else {
    size += sizeof(ulong);
  }
  return size;
}

int fd_clock_timestamp_votes_encode(fd_clock_timestamp_votes_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if (self->votes_root) {
    ulong votes_len = fd_clock_timestamp_vote_t_map_size(self->votes_pool, self->votes_root);
    err = fd_bincode_uint64_encode(votes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( fd_clock_timestamp_vote_t_mapnode_t* n = fd_clock_timestamp_vote_t_map_minimum(self->votes_pool, self->votes_root); n; n = fd_clock_timestamp_vote_t_map_successor(self->votes_pool, n) ) {
      err = fd_clock_timestamp_vote_encode(&n->elem, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  } else {
    ulong votes_len = 0;
    err = fd_bincode_uint64_encode(votes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_sysvar_fees_decode(fd_sysvar_fees_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_sysvar_fees_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_sysvar_fees_new(self);
  fd_sysvar_fees_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_sysvar_fees_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_fee_calculator_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_sysvar_fees_decode_unsafe(fd_sysvar_fees_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_fee_calculator_decode_unsafe(&self->fee_calculator, ctx);
}
int fd_sysvar_fees_decode_offsets(fd_sysvar_fees_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->fee_calculator_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_fee_calculator_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_sysvar_fees_new(fd_sysvar_fees_t* self) {
  fd_memset(self, 0, sizeof(fd_sysvar_fees_t));
  fd_fee_calculator_new(&self->fee_calculator);
}
void fd_sysvar_fees_destroy(fd_sysvar_fees_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_fee_calculator_destroy(&self->fee_calculator, ctx);
}

ulong fd_sysvar_fees_footprint( void ){ return FD_SYSVAR_FEES_FOOTPRINT; }
ulong fd_sysvar_fees_align( void ){ return FD_SYSVAR_FEES_ALIGN; }

void fd_sysvar_fees_walk(void * w, fd_sysvar_fees_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_sysvar_fees", level++);
  fd_fee_calculator_walk(w, &self->fee_calculator, fun, "fee_calculator", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_sysvar_fees", level--);
}
ulong fd_sysvar_fees_size(fd_sysvar_fees_t const * self) {
  ulong size = 0;
  size += fd_fee_calculator_size(&self->fee_calculator);
  return size;
}

int fd_sysvar_fees_encode(fd_sysvar_fees_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_fee_calculator_encode(&self->fee_calculator, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_sysvar_epoch_rewards_decode(fd_sysvar_epoch_rewards_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_sysvar_epoch_rewards_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_sysvar_epoch_rewards_new(self);
  fd_sysvar_epoch_rewards_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_sysvar_epoch_rewards_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_epoch_rewards_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_sysvar_epoch_rewards_decode_unsafe(fd_sysvar_epoch_rewards_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_epoch_rewards_decode_unsafe(&self->epoch_rewards, ctx);
}
int fd_sysvar_epoch_rewards_decode_offsets(fd_sysvar_epoch_rewards_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->epoch_rewards_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_epoch_rewards_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_sysvar_epoch_rewards_new(fd_sysvar_epoch_rewards_t* self) {
  fd_memset(self, 0, sizeof(fd_sysvar_epoch_rewards_t));
  fd_epoch_rewards_new(&self->epoch_rewards);
}
void fd_sysvar_epoch_rewards_destroy(fd_sysvar_epoch_rewards_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_epoch_rewards_destroy(&self->epoch_rewards, ctx);
}

ulong fd_sysvar_epoch_rewards_footprint( void ){ return FD_SYSVAR_EPOCH_REWARDS_FOOTPRINT; }
ulong fd_sysvar_epoch_rewards_align( void ){ return FD_SYSVAR_EPOCH_REWARDS_ALIGN; }

void fd_sysvar_epoch_rewards_walk(void * w, fd_sysvar_epoch_rewards_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_sysvar_epoch_rewards", level++);
  fd_epoch_rewards_walk(w, &self->epoch_rewards, fun, "epoch_rewards", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_sysvar_epoch_rewards", level--);
}
ulong fd_sysvar_epoch_rewards_size(fd_sysvar_epoch_rewards_t const * self) {
  ulong size = 0;
  size += fd_epoch_rewards_size(&self->epoch_rewards);
  return size;
}

int fd_sysvar_epoch_rewards_encode(fd_sysvar_epoch_rewards_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_epoch_rewards_encode(&self->epoch_rewards, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_config_keys_pair_decode(fd_config_keys_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_config_keys_pair_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_config_keys_pair_new(self);
  fd_config_keys_pair_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_config_keys_pair_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bool_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_config_keys_pair_decode_unsafe(fd_config_keys_pair_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->key, ctx);
  fd_bincode_bool_decode_unsafe(&self->signer, ctx);
}
int fd_config_keys_pair_decode_offsets(fd_config_keys_pair_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->key_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->signer_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bool_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_config_keys_pair_new(fd_config_keys_pair_t* self) {
  fd_memset(self, 0, sizeof(fd_config_keys_pair_t));
  fd_pubkey_new(&self->key);
}
void fd_config_keys_pair_destroy(fd_config_keys_pair_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->key, ctx);
}

ulong fd_config_keys_pair_footprint( void ){ return FD_CONFIG_KEYS_PAIR_FOOTPRINT; }
ulong fd_config_keys_pair_align( void ){ return FD_CONFIG_KEYS_PAIR_ALIGN; }

void fd_config_keys_pair_walk(void * w, fd_config_keys_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_config_keys_pair", level++);
  fd_pubkey_walk(w, &self->key, fun, "key", level);
  fun( w, &self->signer, "signer", FD_FLAMENCO_TYPE_BOOL,    "bool",      level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_config_keys_pair", level--);
}
ulong fd_config_keys_pair_size(fd_config_keys_pair_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->key);
  size += sizeof(char);
  return size;
}

int fd_config_keys_pair_encode(fd_config_keys_pair_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->key, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bool_encode( (uchar)(self->signer), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_config_decode(fd_stake_config_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_config_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_config_new(self);
  fd_stake_config_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_config_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ushort config_keys_len;
  err = fd_bincode_compact_u16_decode(&config_keys_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (config_keys_len != 0) {
    for( ulong i = 0; i < config_keys_len; ++i) {
      err = fd_config_keys_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_config_decode_unsafe(fd_stake_config_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_compact_u16_decode_unsafe(&self->config_keys_len, ctx);
  if (self->config_keys_len != 0) {
    self->config_keys = (fd_config_keys_pair_t *)fd_valloc_malloc( ctx->valloc, FD_CONFIG_KEYS_PAIR_ALIGN, FD_CONFIG_KEYS_PAIR_FOOTPRINT*self->config_keys_len);
    for( ulong i = 0; i < self->config_keys_len; ++i) {
      fd_config_keys_pair_new(self->config_keys + i);
      fd_config_keys_pair_decode_unsafe(self->config_keys + i, ctx);
    }
  } else
    self->config_keys = NULL;
  fd_bincode_double_decode_unsafe(&self->warmup_cooldown_rate, ctx);
  fd_bincode_uint8_decode_unsafe(&self->slash_penalty, ctx);
}
int fd_stake_config_decode_offsets(fd_stake_config_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->config_keys_off = (uint)((ulong)ctx->data - (ulong)data);
  ushort config_keys_len;
  err = fd_bincode_compact_u16_decode(&config_keys_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (config_keys_len != 0) {
    for( ulong i = 0; i < config_keys_len; ++i) {
      err = fd_config_keys_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->warmup_cooldown_rate_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->slash_penalty_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_config_new(fd_stake_config_t* self) {
  fd_memset(self, 0, sizeof(fd_stake_config_t));
}
void fd_stake_config_destroy(fd_stake_config_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->config_keys) {
    for (ulong i = 0; i < self->config_keys_len; ++i)
      fd_config_keys_pair_destroy(self->config_keys + i, ctx);
    fd_valloc_free( ctx->valloc, self->config_keys );
    self->config_keys = NULL;
  }
}

ulong fd_stake_config_footprint( void ){ return FD_STAKE_CONFIG_FOOTPRINT; }
ulong fd_stake_config_align( void ){ return FD_STAKE_CONFIG_ALIGN; }

void fd_stake_config_walk(void * w, fd_stake_config_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_config", level++);
  if (self->config_keys_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "config_keys", level++);
    for (ulong i = 0; i < self->config_keys_len; ++i)
      fd_config_keys_pair_walk(w, self->config_keys + i, fun, "config_keys_pair", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "config_keys", level-- );
  }
  fun( w, &self->warmup_cooldown_rate, "warmup_cooldown_rate", FD_FLAMENCO_TYPE_DOUBLE,  "double",    level );
  fun( w, &self->slash_penalty, "slash_penalty", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_config", level--);
}
ulong fd_stake_config_size(fd_stake_config_t const * self) {
  ulong size = 0;
  do {
    ushort tmp = (ushort)self->config_keys_len;
    size += fd_bincode_compact_u16_size(&tmp);
    for (ulong i = 0; i < self->config_keys_len; ++i)
      size += fd_config_keys_pair_size(self->config_keys + i);
  } while(0);
  size += sizeof(double);
  size += sizeof(char);
  return size;
}

int fd_stake_config_encode(fd_stake_config_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_compact_u16_encode(&self->config_keys_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->config_keys_len != 0) {
    for (ulong i = 0; i < self->config_keys_len; ++i) {
      err = fd_config_keys_pair_encode(self->config_keys + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_double_encode( self->warmup_cooldown_rate, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->slash_penalty), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_feature_entry_decode(fd_feature_entry_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_feature_entry_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_feature_entry_new(self);
  fd_feature_entry_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_feature_entry_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong slen;
  err = fd_bincode_uint64_decode( &slen, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_bytes_decode_preflight( slen, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_feature_entry_decode_unsafe(fd_feature_entry_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->pubkey, ctx);
  ulong slen;
  fd_bincode_uint64_decode_unsafe( &slen, ctx );
  self->description = fd_valloc_malloc( ctx->valloc, 1, slen + 1 );
  fd_bincode_bytes_decode_unsafe( (uchar *)self->description, slen, ctx );
  self->description[slen] = '\0';
  fd_bincode_uint64_decode_unsafe(&self->since_slot, ctx);
}
int fd_feature_entry_decode_offsets(fd_feature_entry_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->description_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong slen;
  err = fd_bincode_uint64_decode( &slen, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_bytes_decode_preflight( slen, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->since_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_feature_entry_new(fd_feature_entry_t* self) {
  fd_memset(self, 0, sizeof(fd_feature_entry_t));
  fd_pubkey_new(&self->pubkey);
}
void fd_feature_entry_destroy(fd_feature_entry_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->pubkey, ctx);
  if (NULL != self->description) {
    fd_valloc_free( ctx->valloc, self->description);
    self->description = NULL;
  }
}

ulong fd_feature_entry_footprint( void ){ return FD_FEATURE_ENTRY_FOOTPRINT; }
ulong fd_feature_entry_align( void ){ return FD_FEATURE_ENTRY_ALIGN; }

void fd_feature_entry_walk(void * w, fd_feature_entry_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_feature_entry", level++);
  fd_pubkey_walk(w, &self->pubkey, fun, "pubkey", level);
  fun( w,  self->description, "description", FD_FLAMENCO_TYPE_CSTR,    "char*",     level );
  fun( w, &self->since_slot, "since_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_feature_entry", level--);
}
ulong fd_feature_entry_size(fd_feature_entry_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->pubkey);
  size += sizeof(ulong) + strlen(self->description);
  size += sizeof(ulong);
  return size;
}

int fd_feature_entry_encode(fd_feature_entry_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong slen = strlen( (char *) self->description );
  err = fd_bincode_uint64_encode(slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_encode((uchar *) self->description, slen, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->since_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_firedancer_bank_decode(fd_firedancer_bank_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_firedancer_bank_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_firedancer_bank_new(self);
  fd_firedancer_bank_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_firedancer_bank_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_stakes_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_recent_block_hashes_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_clock_timestamp_votes_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_rate_governor_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint128_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_inflation_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_epoch_schedule_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_rent_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_vote_accounts_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_sol_sysvar_last_restart_slot_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_firedancer_bank_decode_unsafe(fd_firedancer_bank_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_stakes_decode_unsafe(&self->stakes, ctx);
  fd_recent_block_hashes_decode_unsafe(&self->recent_block_hashes, ctx);
  fd_clock_timestamp_votes_decode_unsafe(&self->timestamp_votes, ctx);
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->prev_slot, ctx);
  fd_hash_decode_unsafe(&self->poh, ctx);
  fd_hash_decode_unsafe(&self->banks_hash, ctx);
  fd_fee_rate_governor_decode_unsafe(&self->fee_rate_governor, ctx);
  fd_bincode_uint64_decode_unsafe(&self->capitalization, ctx);
  fd_bincode_uint64_decode_unsafe(&self->block_height, ctx);
  fd_bincode_uint64_decode_unsafe(&self->lamports_per_signature, ctx);
  fd_bincode_uint64_decode_unsafe(&self->hashes_per_tick, ctx);
  fd_bincode_uint64_decode_unsafe(&self->ticks_per_slot, ctx);
  fd_bincode_uint128_decode_unsafe(&self->ns_per_slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->genesis_creation_time, ctx);
  fd_bincode_double_decode_unsafe(&self->slots_per_year, ctx);
  fd_bincode_uint64_decode_unsafe(&self->max_tick_height, ctx);
  fd_inflation_decode_unsafe(&self->inflation, ctx);
  fd_epoch_schedule_decode_unsafe(&self->epoch_schedule, ctx);
  fd_rent_decode_unsafe(&self->rent, ctx);
  fd_bincode_uint64_decode_unsafe(&self->collected_fees, ctx);
  fd_bincode_uint64_decode_unsafe(&self->collected_rent, ctx);
  fd_vote_accounts_decode_unsafe(&self->epoch_stakes, ctx);
  fd_sol_sysvar_last_restart_slot_decode_unsafe(&self->last_restart_slot, ctx);
}
int fd_firedancer_bank_decode_offsets(fd_firedancer_bank_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->stakes_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_stakes_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->recent_block_hashes_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_recent_block_hashes_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->timestamp_votes_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_clock_timestamp_votes_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->prev_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->poh_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->banks_hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->fee_rate_governor_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_fee_rate_governor_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->capitalization_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->block_height_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->lamports_per_signature_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->hashes_per_tick_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->ticks_per_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->ns_per_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint128_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->genesis_creation_time_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->slots_per_year_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->max_tick_height_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->inflation_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_inflation_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->epoch_schedule_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_epoch_schedule_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->rent_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_rent_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->collected_fees_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->collected_rent_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->epoch_stakes_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_vote_accounts_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->last_restart_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_sol_sysvar_last_restart_slot_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_firedancer_bank_new(fd_firedancer_bank_t* self) {
  fd_memset(self, 0, sizeof(fd_firedancer_bank_t));
  fd_stakes_new(&self->stakes);
  fd_recent_block_hashes_new(&self->recent_block_hashes);
  fd_clock_timestamp_votes_new(&self->timestamp_votes);
  fd_hash_new(&self->poh);
  fd_hash_new(&self->banks_hash);
  fd_fee_rate_governor_new(&self->fee_rate_governor);
  fd_inflation_new(&self->inflation);
  fd_epoch_schedule_new(&self->epoch_schedule);
  fd_rent_new(&self->rent);
  fd_vote_accounts_new(&self->epoch_stakes);
  fd_sol_sysvar_last_restart_slot_new(&self->last_restart_slot);
}
void fd_firedancer_bank_destroy(fd_firedancer_bank_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stakes_destroy(&self->stakes, ctx);
  fd_recent_block_hashes_destroy(&self->recent_block_hashes, ctx);
  fd_clock_timestamp_votes_destroy(&self->timestamp_votes, ctx);
  fd_hash_destroy(&self->poh, ctx);
  fd_hash_destroy(&self->banks_hash, ctx);
  fd_fee_rate_governor_destroy(&self->fee_rate_governor, ctx);
  fd_inflation_destroy(&self->inflation, ctx);
  fd_epoch_schedule_destroy(&self->epoch_schedule, ctx);
  fd_rent_destroy(&self->rent, ctx);
  fd_vote_accounts_destroy(&self->epoch_stakes, ctx);
  fd_sol_sysvar_last_restart_slot_destroy(&self->last_restart_slot, ctx);
}

ulong fd_firedancer_bank_footprint( void ){ return FD_FIREDANCER_BANK_FOOTPRINT; }
ulong fd_firedancer_bank_align( void ){ return FD_FIREDANCER_BANK_ALIGN; }

void fd_firedancer_bank_walk(void * w, fd_firedancer_bank_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_firedancer_bank", level++);
  fd_stakes_walk(w, &self->stakes, fun, "stakes", level);
  fd_recent_block_hashes_walk(w, &self->recent_block_hashes, fun, "recent_block_hashes", level);
  fd_clock_timestamp_votes_walk(w, &self->timestamp_votes, fun, "timestamp_votes", level);
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->prev_slot, "prev_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_hash_walk(w, &self->poh, fun, "poh", level);
  fd_hash_walk(w, &self->banks_hash, fun, "banks_hash", level);
  fd_fee_rate_governor_walk(w, &self->fee_rate_governor, fun, "fee_rate_governor", level);
  fun( w, &self->capitalization, "capitalization", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->block_height, "block_height", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->lamports_per_signature, "lamports_per_signature", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->hashes_per_tick, "hashes_per_tick", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->ticks_per_slot, "ticks_per_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->ns_per_slot, "ns_per_slot", FD_FLAMENCO_TYPE_UINT128, "uint128",   level );
  fun( w, &self->genesis_creation_time, "genesis_creation_time", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->slots_per_year, "slots_per_year", FD_FLAMENCO_TYPE_DOUBLE,  "double",    level );
  fun( w, &self->max_tick_height, "max_tick_height", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_inflation_walk(w, &self->inflation, fun, "inflation", level);
  fd_epoch_schedule_walk(w, &self->epoch_schedule, fun, "epoch_schedule", level);
  fd_rent_walk(w, &self->rent, fun, "rent", level);
  fun( w, &self->collected_fees, "collected_fees", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->collected_rent, "collected_rent", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_vote_accounts_walk(w, &self->epoch_stakes, fun, "epoch_stakes", level);
  fd_sol_sysvar_last_restart_slot_walk(w, &self->last_restart_slot, fun, "last_restart_slot", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_firedancer_bank", level--);
}
ulong fd_firedancer_bank_size(fd_firedancer_bank_t const * self) {
  ulong size = 0;
  size += fd_stakes_size(&self->stakes);
  size += fd_recent_block_hashes_size(&self->recent_block_hashes);
  size += fd_clock_timestamp_votes_size(&self->timestamp_votes);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_hash_size(&self->poh);
  size += fd_hash_size(&self->banks_hash);
  size += fd_fee_rate_governor_size(&self->fee_rate_governor);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(uint128);
  size += sizeof(ulong);
  size += sizeof(double);
  size += sizeof(ulong);
  size += fd_inflation_size(&self->inflation);
  size += fd_epoch_schedule_size(&self->epoch_schedule);
  size += fd_rent_size(&self->rent);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_vote_accounts_size(&self->epoch_stakes);
  size += fd_sol_sysvar_last_restart_slot_size(&self->last_restart_slot);
  return size;
}

int fd_firedancer_bank_encode(fd_firedancer_bank_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_stakes_encode(&self->stakes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_recent_block_hashes_encode(&self->recent_block_hashes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_clock_timestamp_votes_encode(&self->timestamp_votes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->prev_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->poh, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->banks_hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_rate_governor_encode(&self->fee_rate_governor, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->capitalization, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->block_height, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->lamports_per_signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->hashes_per_tick, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->ticks_per_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint128_encode( self->ns_per_slot, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->genesis_creation_time, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode( self->slots_per_year, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->max_tick_height, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_inflation_encode(&self->inflation, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_epoch_schedule_encode(&self->epoch_schedule, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_rent_encode(&self->rent, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->collected_fees, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->collected_rent, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_accounts_encode(&self->epoch_stakes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_sol_sysvar_last_restart_slot_encode(&self->last_restart_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_epoch_bank_decode(fd_epoch_bank_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_epoch_bank_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_epoch_bank_new(self);
  fd_epoch_bank_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_epoch_bank_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_stakes_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint128_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_inflation_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_epoch_schedule_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_rent_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_accounts_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_epoch_bank_decode_unsafe(fd_epoch_bank_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_stakes_decode_unsafe(&self->stakes, ctx);
  fd_bincode_uint64_decode_unsafe(&self->hashes_per_tick, ctx);
  fd_bincode_uint64_decode_unsafe(&self->ticks_per_slot, ctx);
  fd_bincode_uint128_decode_unsafe(&self->ns_per_slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->genesis_creation_time, ctx);
  fd_bincode_double_decode_unsafe(&self->slots_per_year, ctx);
  fd_bincode_uint64_decode_unsafe(&self->max_tick_height, ctx);
  fd_inflation_decode_unsafe(&self->inflation, ctx);
  fd_epoch_schedule_decode_unsafe(&self->epoch_schedule, ctx);
  fd_rent_decode_unsafe(&self->rent, ctx);
  fd_bincode_uint64_decode_unsafe(&self->eah_start_slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->eah_stop_slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->eah_interval, ctx);
  fd_hash_decode_unsafe(&self->genesis_hash, ctx);
  fd_bincode_uint32_decode_unsafe(&self->cluster_type, ctx);
  fd_vote_accounts_decode_unsafe(&self->next_epoch_stakes, ctx);
}
int fd_epoch_bank_decode_offsets(fd_epoch_bank_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->stakes_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_stakes_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->hashes_per_tick_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->ticks_per_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->ns_per_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint128_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->genesis_creation_time_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->slots_per_year_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->max_tick_height_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->inflation_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_inflation_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->epoch_schedule_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_epoch_schedule_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->rent_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_rent_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->eah_start_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->eah_stop_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->eah_interval_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->genesis_hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->cluster_type_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->next_epoch_stakes_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_vote_accounts_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_epoch_bank_new(fd_epoch_bank_t* self) {
  fd_memset(self, 0, sizeof(fd_epoch_bank_t));
  fd_stakes_new(&self->stakes);
  fd_inflation_new(&self->inflation);
  fd_epoch_schedule_new(&self->epoch_schedule);
  fd_rent_new(&self->rent);
  fd_hash_new(&self->genesis_hash);
  fd_vote_accounts_new(&self->next_epoch_stakes);
}
void fd_epoch_bank_destroy(fd_epoch_bank_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stakes_destroy(&self->stakes, ctx);
  fd_inflation_destroy(&self->inflation, ctx);
  fd_epoch_schedule_destroy(&self->epoch_schedule, ctx);
  fd_rent_destroy(&self->rent, ctx);
  fd_hash_destroy(&self->genesis_hash, ctx);
  fd_vote_accounts_destroy(&self->next_epoch_stakes, ctx);
}

ulong fd_epoch_bank_footprint( void ){ return FD_EPOCH_BANK_FOOTPRINT; }
ulong fd_epoch_bank_align( void ){ return FD_EPOCH_BANK_ALIGN; }

void fd_epoch_bank_walk(void * w, fd_epoch_bank_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_epoch_bank", level++);
  fd_stakes_walk(w, &self->stakes, fun, "stakes", level);
  fun( w, &self->hashes_per_tick, "hashes_per_tick", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->ticks_per_slot, "ticks_per_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->ns_per_slot, "ns_per_slot", FD_FLAMENCO_TYPE_UINT128, "uint128",   level );
  fun( w, &self->genesis_creation_time, "genesis_creation_time", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->slots_per_year, "slots_per_year", FD_FLAMENCO_TYPE_DOUBLE,  "double",    level );
  fun( w, &self->max_tick_height, "max_tick_height", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_inflation_walk(w, &self->inflation, fun, "inflation", level);
  fd_epoch_schedule_walk(w, &self->epoch_schedule, fun, "epoch_schedule", level);
  fd_rent_walk(w, &self->rent, fun, "rent", level);
  fun( w, &self->eah_start_slot, "eah_start_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->eah_stop_slot, "eah_stop_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->eah_interval, "eah_interval", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_hash_walk(w, &self->genesis_hash, fun, "genesis_hash", level);
  fun( w, &self->cluster_type, "cluster_type", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
  fd_vote_accounts_walk(w, &self->next_epoch_stakes, fun, "next_epoch_stakes", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_epoch_bank", level--);
}
ulong fd_epoch_bank_size(fd_epoch_bank_t const * self) {
  ulong size = 0;
  size += fd_stakes_size(&self->stakes);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(uint128);
  size += sizeof(ulong);
  size += sizeof(double);
  size += sizeof(ulong);
  size += fd_inflation_size(&self->inflation);
  size += fd_epoch_schedule_size(&self->epoch_schedule);
  size += fd_rent_size(&self->rent);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_hash_size(&self->genesis_hash);
  size += sizeof(uint);
  size += fd_vote_accounts_size(&self->next_epoch_stakes);
  return size;
}

int fd_epoch_bank_encode(fd_epoch_bank_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_stakes_encode(&self->stakes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->hashes_per_tick, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->ticks_per_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint128_encode( self->ns_per_slot, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->genesis_creation_time, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode( self->slots_per_year, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->max_tick_height, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_inflation_encode(&self->inflation, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_epoch_schedule_encode(&self->epoch_schedule, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_rent_encode(&self->rent, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->eah_start_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->eah_stop_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->eah_interval, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->genesis_hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_encode( self->cluster_type, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_accounts_encode(&self->next_epoch_stakes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_slot_bank_decode(fd_slot_bank_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_slot_bank_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_slot_bank_new(self);
  fd_slot_bank_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_slot_bank_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_recent_block_hashes_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_clock_timestamp_votes_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_rate_governor_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_vote_accounts_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_sol_sysvar_last_restart_slot_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_accounts_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_accounts_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_bytes_decode_preflight(2048, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_bank_decode_unsafe(fd_slot_bank_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_recent_block_hashes_decode_unsafe(&self->recent_block_hashes, ctx);
  fd_clock_timestamp_votes_decode_unsafe(&self->timestamp_votes, ctx);
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->prev_slot, ctx);
  fd_hash_decode_unsafe(&self->poh, ctx);
  fd_hash_decode_unsafe(&self->banks_hash, ctx);
  fd_hash_decode_unsafe(&self->epoch_account_hash, ctx);
  fd_fee_rate_governor_decode_unsafe(&self->fee_rate_governor, ctx);
  fd_bincode_uint64_decode_unsafe(&self->capitalization, ctx);
  fd_bincode_uint64_decode_unsafe(&self->block_height, ctx);
  fd_bincode_uint64_decode_unsafe(&self->max_tick_height, ctx);
  fd_bincode_uint64_decode_unsafe(&self->collected_fees, ctx);
  fd_bincode_uint64_decode_unsafe(&self->collected_rent, ctx);
  fd_vote_accounts_decode_unsafe(&self->epoch_stakes, ctx);
  fd_sol_sysvar_last_restart_slot_decode_unsafe(&self->last_restart_slot, ctx);
  fd_stake_accounts_decode_unsafe(&self->stake_account_keys, ctx);
  fd_vote_accounts_decode_unsafe(&self->vote_account_keys, ctx);
  fd_bincode_uint64_decode_unsafe(&self->lamports_per_signature, ctx);
  fd_bincode_uint64_decode_unsafe(&self->transaction_count, ctx);
  fd_bincode_bytes_decode_unsafe(&self->lthash[0], sizeof(self->lthash), ctx);
}
int fd_slot_bank_decode_offsets(fd_slot_bank_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->recent_block_hashes_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_recent_block_hashes_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->timestamp_votes_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_clock_timestamp_votes_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->prev_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->poh_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->banks_hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->epoch_account_hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->fee_rate_governor_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_fee_rate_governor_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->capitalization_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->block_height_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->max_tick_height_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->collected_fees_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->collected_rent_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->epoch_stakes_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_vote_accounts_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->last_restart_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_sol_sysvar_last_restart_slot_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->stake_account_keys_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_stake_accounts_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->vote_account_keys_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_vote_accounts_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->lamports_per_signature_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->transaction_count_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->lthash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(2048, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_slot_bank_new(fd_slot_bank_t* self) {
  fd_memset(self, 0, sizeof(fd_slot_bank_t));
  fd_recent_block_hashes_new(&self->recent_block_hashes);
  fd_clock_timestamp_votes_new(&self->timestamp_votes);
  fd_hash_new(&self->poh);
  fd_hash_new(&self->banks_hash);
  fd_hash_new(&self->epoch_account_hash);
  fd_fee_rate_governor_new(&self->fee_rate_governor);
  fd_vote_accounts_new(&self->epoch_stakes);
  fd_sol_sysvar_last_restart_slot_new(&self->last_restart_slot);
  fd_stake_accounts_new(&self->stake_account_keys);
  fd_vote_accounts_new(&self->vote_account_keys);
}
void fd_slot_bank_destroy(fd_slot_bank_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_recent_block_hashes_destroy(&self->recent_block_hashes, ctx);
  fd_clock_timestamp_votes_destroy(&self->timestamp_votes, ctx);
  fd_hash_destroy(&self->poh, ctx);
  fd_hash_destroy(&self->banks_hash, ctx);
  fd_hash_destroy(&self->epoch_account_hash, ctx);
  fd_fee_rate_governor_destroy(&self->fee_rate_governor, ctx);
  fd_vote_accounts_destroy(&self->epoch_stakes, ctx);
  fd_sol_sysvar_last_restart_slot_destroy(&self->last_restart_slot, ctx);
  fd_stake_accounts_destroy(&self->stake_account_keys, ctx);
  fd_vote_accounts_destroy(&self->vote_account_keys, ctx);
}

ulong fd_slot_bank_footprint( void ){ return FD_SLOT_BANK_FOOTPRINT; }
ulong fd_slot_bank_align( void ){ return FD_SLOT_BANK_ALIGN; }

void fd_slot_bank_walk(void * w, fd_slot_bank_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_slot_bank", level++);
  fd_recent_block_hashes_walk(w, &self->recent_block_hashes, fun, "recent_block_hashes", level);
  fd_clock_timestamp_votes_walk(w, &self->timestamp_votes, fun, "timestamp_votes", level);
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->prev_slot, "prev_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_hash_walk(w, &self->poh, fun, "poh", level);
  fd_hash_walk(w, &self->banks_hash, fun, "banks_hash", level);
  fd_hash_walk(w, &self->epoch_account_hash, fun, "epoch_account_hash", level);
  fd_fee_rate_governor_walk(w, &self->fee_rate_governor, fun, "fee_rate_governor", level);
  fun( w, &self->capitalization, "capitalization", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->block_height, "block_height", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->max_tick_height, "max_tick_height", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->collected_fees, "collected_fees", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->collected_rent, "collected_rent", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_vote_accounts_walk(w, &self->epoch_stakes, fun, "epoch_stakes", level);
  fd_sol_sysvar_last_restart_slot_walk(w, &self->last_restart_slot, fun, "last_restart_slot", level);
  fd_stake_accounts_walk(w, &self->stake_account_keys, fun, "stake_account_keys", level);
  fd_vote_accounts_walk(w, &self->vote_account_keys, fun, "vote_account_keys", level);
  fun( w, &self->lamports_per_signature, "lamports_per_signature", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->transaction_count, "transaction_count", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w,  self->lthash, "lthash", FD_FLAMENCO_TYPE_HASH16384, "uchar[2048]", level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_slot_bank", level--);
}
ulong fd_slot_bank_size(fd_slot_bank_t const * self) {
  ulong size = 0;
  size += fd_recent_block_hashes_size(&self->recent_block_hashes);
  size += fd_clock_timestamp_votes_size(&self->timestamp_votes);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_hash_size(&self->poh);
  size += fd_hash_size(&self->banks_hash);
  size += fd_hash_size(&self->epoch_account_hash);
  size += fd_fee_rate_governor_size(&self->fee_rate_governor);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_vote_accounts_size(&self->epoch_stakes);
  size += fd_sol_sysvar_last_restart_slot_size(&self->last_restart_slot);
  size += fd_stake_accounts_size(&self->stake_account_keys);
  size += fd_vote_accounts_size(&self->vote_account_keys);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(char) * 2048;
  return size;
}

int fd_slot_bank_encode(fd_slot_bank_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_recent_block_hashes_encode(&self->recent_block_hashes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_clock_timestamp_votes_encode(&self->timestamp_votes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->prev_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->poh, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->banks_hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->epoch_account_hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_rate_governor_encode(&self->fee_rate_governor, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->capitalization, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->block_height, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->max_tick_height, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->collected_fees, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->collected_rent, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_accounts_encode(&self->epoch_stakes, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_sol_sysvar_last_restart_slot_encode(&self->last_restart_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_accounts_encode(&self->stake_account_keys, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_accounts_encode(&self->vote_account_keys, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->lamports_per_signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->transaction_count, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_encode( self->lthash, sizeof(self->lthash ), ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_prev_epoch_inflation_rewards_decode(fd_prev_epoch_inflation_rewards_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_prev_epoch_inflation_rewards_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_prev_epoch_inflation_rewards_new(self);
  fd_prev_epoch_inflation_rewards_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_prev_epoch_inflation_rewards_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_prev_epoch_inflation_rewards_decode_unsafe(fd_prev_epoch_inflation_rewards_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->validator_rewards, ctx);
  fd_bincode_double_decode_unsafe(&self->prev_epoch_duration_in_years, ctx);
  fd_bincode_double_decode_unsafe(&self->validator_rate, ctx);
  fd_bincode_double_decode_unsafe(&self->foundation_rate, ctx);
}
int fd_prev_epoch_inflation_rewards_decode_offsets(fd_prev_epoch_inflation_rewards_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->validator_rewards_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->prev_epoch_duration_in_years_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->validator_rate_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->foundation_rate_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_double_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_prev_epoch_inflation_rewards_new(fd_prev_epoch_inflation_rewards_t* self) {
  fd_memset(self, 0, sizeof(fd_prev_epoch_inflation_rewards_t));
}
void fd_prev_epoch_inflation_rewards_destroy(fd_prev_epoch_inflation_rewards_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_prev_epoch_inflation_rewards_footprint( void ){ return FD_PREV_EPOCH_INFLATION_REWARDS_FOOTPRINT; }
ulong fd_prev_epoch_inflation_rewards_align( void ){ return FD_PREV_EPOCH_INFLATION_REWARDS_ALIGN; }

void fd_prev_epoch_inflation_rewards_walk(void * w, fd_prev_epoch_inflation_rewards_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_prev_epoch_inflation_rewards", level++);
  fun( w, &self->validator_rewards, "validator_rewards", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->prev_epoch_duration_in_years, "prev_epoch_duration_in_years", FD_FLAMENCO_TYPE_DOUBLE,  "double",    level );
  fun( w, &self->validator_rate, "validator_rate", FD_FLAMENCO_TYPE_DOUBLE,  "double",    level );
  fun( w, &self->foundation_rate, "foundation_rate", FD_FLAMENCO_TYPE_DOUBLE,  "double",    level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_prev_epoch_inflation_rewards", level--);
}
ulong fd_prev_epoch_inflation_rewards_size(fd_prev_epoch_inflation_rewards_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(double);
  size += sizeof(double);
  size += sizeof(double);
  return size;
}

int fd_prev_epoch_inflation_rewards_encode(fd_prev_epoch_inflation_rewards_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->validator_rewards, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode( self->prev_epoch_duration_in_years, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode( self->validator_rate, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_double_encode( self->foundation_rate, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_decode(fd_vote_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_new(self);
  fd_vote_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong slots_len;
  err = fd_bincode_uint64_decode( &slots_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( slots_len > 35 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < slots_len; ++i) {
    err = fd_bincode_uint64_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_vote_decode_unsafe(fd_vote_t* self, fd_bincode_decode_ctx_t * ctx) {
  ulong slots_len;
  fd_bincode_uint64_decode_unsafe( &slots_len, ctx );
  self->slots = deq_ulong_alloc( ctx->valloc );
  for (ulong i = 0; i < slots_len; ++i) {
    ulong * elem = deq_ulong_push_tail_nocopy(self->slots);
    fd_bincode_uint64_decode_unsafe(elem, ctx);
  }
  fd_hash_decode_unsafe(&self->hash, ctx);
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      self->timestamp = fd_valloc_malloc( ctx->valloc, 8, sizeof(ulong) );
      fd_bincode_uint64_decode_unsafe( self->timestamp, ctx );
    } else
      self->timestamp = NULL;
  }
}
int fd_vote_decode_offsets(fd_vote_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->slots_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong slots_len;
  err = fd_bincode_uint64_decode( &slots_len, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  if ( slots_len > 35 ) return FD_BINCODE_ERR_SMALL_DEQUE;
  for (ulong i = 0; i < slots_len; ++i) {
    err = fd_bincode_uint64_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  self->hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->timestamp_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_vote_new(fd_vote_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_t));
  fd_hash_new(&self->hash);
}
void fd_vote_destroy(fd_vote_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if ( self->slots ) {
    fd_valloc_free( ctx->valloc, deq_ulong_delete( deq_ulong_leave( self->slots) ) );
    self->slots = NULL;
  }
  fd_hash_destroy(&self->hash, ctx);
  if( NULL != self->timestamp ) {
    fd_valloc_free( ctx->valloc, self->timestamp );
    self->timestamp = NULL;
  }
}

ulong fd_vote_footprint( void ){ return FD_VOTE_FOOTPRINT; }
ulong fd_vote_align( void ){ return FD_VOTE_ALIGN; }

void fd_vote_walk(void * w, fd_vote_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote", level++);

  /* Walk deque */
  fun( w, self->slots, "slots", FD_FLAMENCO_TYPE_ARR, "slots", level++ );
  if( self->slots ) {
    for( deq_ulong_iter_t iter = deq_ulong_iter_init( self->slots );
         !deq_ulong_iter_done( self->slots, iter );
         iter = deq_ulong_iter_next( self->slots, iter ) ) {
      ulong * ele = deq_ulong_iter_ele( self->slots, iter );
      fun(w, ele, "ele", FD_FLAMENCO_TYPE_ULONG, "long",  level );
    }
  }
  fun( w, self->slots, "slots", FD_FLAMENCO_TYPE_ARR_END, "slots", level-- );
  /* Done walking deque */

  fd_hash_walk(w, &self->hash, fun, "hash", level);
  if( !self->timestamp ) {
    fun( w, NULL, "timestamp", FD_FLAMENCO_TYPE_NULL, "ulong", level );
  } else {
    fun( w, self->timestamp, "timestamp", FD_FLAMENCO_TYPE_ULONG, "ulong", level );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote", level--);
}
ulong fd_vote_size(fd_vote_t const * self) {
  ulong size = 0;
  if ( self->slots ) {
    size += sizeof(ulong);
    ulong slots_len = deq_ulong_cnt(self->slots);
    size += slots_len * sizeof(ulong);
  } else {
    size += sizeof(ulong);
  }
  size += fd_hash_size(&self->hash);
  size += sizeof(char);
  if( NULL !=  self->timestamp ) {
    size += sizeof(ulong);
  }
  return size;
}

int fd_vote_encode(fd_vote_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if ( self->slots ) {
    ulong slots_len = deq_ulong_cnt(self->slots);
    err = fd_bincode_uint64_encode(slots_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    for ( deq_ulong_iter_t iter = deq_ulong_iter_init( self->slots ); !deq_ulong_iter_done( self->slots, iter ); iter = deq_ulong_iter_next( self->slots, iter ) ) {
      ulong const * ele = deq_ulong_iter_ele_const( self->slots, iter );
      err = fd_bincode_uint64_encode( ele[0], ctx );
    }
  } else {
    ulong slots_len = 0;
    err = fd_bincode_uint64_encode(slots_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if( self->timestamp != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_bincode_uint64_encode( self->timestamp[0], ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_vote_init_decode(fd_vote_init_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_init_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_init_new(self);
  fd_vote_init_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_init_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_init_decode_unsafe(fd_vote_init_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->node_pubkey, ctx);
  fd_pubkey_decode_unsafe(&self->authorized_voter, ctx);
  fd_pubkey_decode_unsafe(&self->authorized_withdrawer, ctx);
  fd_bincode_uint8_decode_unsafe(&self->commission, ctx);
}
int fd_vote_init_decode_offsets(fd_vote_init_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->node_pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->authorized_voter_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->authorized_withdrawer_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->commission_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_init_new(fd_vote_init_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_init_t));
  fd_pubkey_new(&self->node_pubkey);
  fd_pubkey_new(&self->authorized_voter);
  fd_pubkey_new(&self->authorized_withdrawer);
}
void fd_vote_init_destroy(fd_vote_init_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->node_pubkey, ctx);
  fd_pubkey_destroy(&self->authorized_voter, ctx);
  fd_pubkey_destroy(&self->authorized_withdrawer, ctx);
}

ulong fd_vote_init_footprint( void ){ return FD_VOTE_INIT_FOOTPRINT; }
ulong fd_vote_init_align( void ){ return FD_VOTE_INIT_ALIGN; }

void fd_vote_init_walk(void * w, fd_vote_init_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_init", level++);
  fd_pubkey_walk(w, &self->node_pubkey, fun, "node_pubkey", level);
  fd_pubkey_walk(w, &self->authorized_voter, fun, "authorized_voter", level);
  fd_pubkey_walk(w, &self->authorized_withdrawer, fun, "authorized_withdrawer", level);
  fun( w, &self->commission, "commission", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_init", level--);
}
ulong fd_vote_init_size(fd_vote_init_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->node_pubkey);
  size += fd_pubkey_size(&self->authorized_voter);
  size += fd_pubkey_size(&self->authorized_withdrawer);
  size += sizeof(char);
  return size;
}

int fd_vote_init_encode(fd_vote_init_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->node_pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->authorized_voter, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->authorized_withdrawer, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->commission), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_vote_authorize_is_voter(fd_vote_authorize_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_vote_authorize_is_withdrawer(fd_vote_authorize_t const * self) {
  return self->discriminant == 1;
}
void fd_vote_authorize_inner_new(fd_vote_authorize_inner_t* self, uint discriminant);
int fd_vote_authorize_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_vote_authorize_inner_decode_unsafe(fd_vote_authorize_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    break;
  }
  }
}
int fd_vote_authorize_decode(fd_vote_authorize_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_authorize_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_authorize_new(self);
  fd_vote_authorize_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_authorize_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_vote_authorize_inner_decode_preflight(discriminant, ctx);
}
void fd_vote_authorize_decode_unsafe(fd_vote_authorize_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_vote_authorize_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_vote_authorize_inner_new(fd_vote_authorize_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_vote_authorize_new_disc(fd_vote_authorize_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_vote_authorize_inner_new(&self->inner, self->discriminant);
}
void fd_vote_authorize_new(fd_vote_authorize_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_vote_authorize_new_disc(self, UINT_MAX);
}
void fd_vote_authorize_inner_destroy(fd_vote_authorize_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_vote_authorize_destroy(fd_vote_authorize_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_vote_authorize_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_vote_authorize_footprint( void ){ return FD_VOTE_AUTHORIZE_FOOTPRINT; }
ulong fd_vote_authorize_align( void ){ return FD_VOTE_AUTHORIZE_ALIGN; }

void fd_vote_authorize_walk(void * w, fd_vote_authorize_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_authorize", level++);
  switch (self->discriminant) {
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_authorize", level--);
}
ulong fd_vote_authorize_size(fd_vote_authorize_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  }
  return size;
}

int fd_vote_authorize_inner_encode(fd_vote_authorize_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  return FD_BINCODE_SUCCESS;
}
int fd_vote_authorize_encode(fd_vote_authorize_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_vote_authorize_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_vote_authorize_pubkey_decode(fd_vote_authorize_pubkey_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_authorize_pubkey_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_authorize_pubkey_new(self);
  fd_vote_authorize_pubkey_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_authorize_pubkey_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_authorize_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_authorize_pubkey_decode_unsafe(fd_vote_authorize_pubkey_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->pubkey, ctx);
  fd_vote_authorize_decode_unsafe(&self->vote_authorize, ctx);
}
int fd_vote_authorize_pubkey_decode_offsets(fd_vote_authorize_pubkey_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->vote_authorize_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_vote_authorize_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_authorize_pubkey_new(fd_vote_authorize_pubkey_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_authorize_pubkey_t));
  fd_pubkey_new(&self->pubkey);
  fd_vote_authorize_new(&self->vote_authorize);
}
void fd_vote_authorize_pubkey_destroy(fd_vote_authorize_pubkey_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->pubkey, ctx);
  fd_vote_authorize_destroy(&self->vote_authorize, ctx);
}

ulong fd_vote_authorize_pubkey_footprint( void ){ return FD_VOTE_AUTHORIZE_PUBKEY_FOOTPRINT; }
ulong fd_vote_authorize_pubkey_align( void ){ return FD_VOTE_AUTHORIZE_PUBKEY_ALIGN; }

void fd_vote_authorize_pubkey_walk(void * w, fd_vote_authorize_pubkey_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_authorize_pubkey", level++);
  fd_pubkey_walk(w, &self->pubkey, fun, "pubkey", level);
  fd_vote_authorize_walk(w, &self->vote_authorize, fun, "vote_authorize", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_authorize_pubkey", level--);
}
ulong fd_vote_authorize_pubkey_size(fd_vote_authorize_pubkey_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->pubkey);
  size += fd_vote_authorize_size(&self->vote_authorize);
  return size;
}

int fd_vote_authorize_pubkey_encode(fd_vote_authorize_pubkey_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_vote_authorize_encode(&self->vote_authorize, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_switch_decode(fd_vote_switch_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_switch_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_switch_new(self);
  fd_vote_switch_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_switch_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_vote_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_switch_decode_unsafe(fd_vote_switch_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_vote_decode_unsafe(&self->vote, ctx);
  fd_hash_decode_unsafe(&self->hash, ctx);
}
int fd_vote_switch_decode_offsets(fd_vote_switch_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->vote_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_vote_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_switch_new(fd_vote_switch_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_switch_t));
  fd_vote_new(&self->vote);
  fd_hash_new(&self->hash);
}
void fd_vote_switch_destroy(fd_vote_switch_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_vote_destroy(&self->vote, ctx);
  fd_hash_destroy(&self->hash, ctx);
}

ulong fd_vote_switch_footprint( void ){ return FD_VOTE_SWITCH_FOOTPRINT; }
ulong fd_vote_switch_align( void ){ return FD_VOTE_SWITCH_ALIGN; }

void fd_vote_switch_walk(void * w, fd_vote_switch_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_switch", level++);
  fd_vote_walk(w, &self->vote, fun, "vote", level);
  fd_hash_walk(w, &self->hash, fun, "hash", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_switch", level--);
}
ulong fd_vote_switch_size(fd_vote_switch_t const * self) {
  ulong size = 0;
  size += fd_vote_size(&self->vote);
  size += fd_hash_size(&self->hash);
  return size;
}

int fd_vote_switch_encode(fd_vote_switch_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_vote_encode(&self->vote, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_update_vote_state_switch_decode(fd_update_vote_state_switch_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_update_vote_state_switch_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_update_vote_state_switch_new(self);
  fd_update_vote_state_switch_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_update_vote_state_switch_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_vote_state_update_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_update_vote_state_switch_decode_unsafe(fd_update_vote_state_switch_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_vote_state_update_decode_unsafe(&self->vote_state_update, ctx);
  fd_hash_decode_unsafe(&self->hash, ctx);
}
int fd_update_vote_state_switch_decode_offsets(fd_update_vote_state_switch_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->vote_state_update_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_vote_state_update_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_update_vote_state_switch_new(fd_update_vote_state_switch_t* self) {
  fd_memset(self, 0, sizeof(fd_update_vote_state_switch_t));
  fd_vote_state_update_new(&self->vote_state_update);
  fd_hash_new(&self->hash);
}
void fd_update_vote_state_switch_destroy(fd_update_vote_state_switch_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_vote_state_update_destroy(&self->vote_state_update, ctx);
  fd_hash_destroy(&self->hash, ctx);
}

ulong fd_update_vote_state_switch_footprint( void ){ return FD_UPDATE_VOTE_STATE_SWITCH_FOOTPRINT; }
ulong fd_update_vote_state_switch_align( void ){ return FD_UPDATE_VOTE_STATE_SWITCH_ALIGN; }

void fd_update_vote_state_switch_walk(void * w, fd_update_vote_state_switch_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_update_vote_state_switch", level++);
  fd_vote_state_update_walk(w, &self->vote_state_update, fun, "vote_state_update", level);
  fd_hash_walk(w, &self->hash, fun, "hash", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_update_vote_state_switch", level--);
}
ulong fd_update_vote_state_switch_size(fd_update_vote_state_switch_t const * self) {
  ulong size = 0;
  size += fd_vote_state_update_size(&self->vote_state_update);
  size += fd_hash_size(&self->hash);
  return size;
}

int fd_update_vote_state_switch_encode(fd_update_vote_state_switch_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_vote_state_update_encode(&self->vote_state_update, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_authorize_with_seed_args_decode(fd_vote_authorize_with_seed_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_authorize_with_seed_args_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_authorize_with_seed_args_new(self);
  fd_vote_authorize_with_seed_args_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_authorize_with_seed_args_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_vote_authorize_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong current_authority_derived_key_seed_len;
  err = fd_bincode_uint64_decode(&current_authority_derived_key_seed_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (current_authority_derived_key_seed_len != 0) {
    err = fd_bincode_bytes_decode_preflight(current_authority_derived_key_seed_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_authorize_with_seed_args_decode_unsafe(fd_vote_authorize_with_seed_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_vote_authorize_decode_unsafe(&self->authorization_type, ctx);
  fd_pubkey_decode_unsafe(&self->current_authority_derived_key_owner, ctx);
  fd_bincode_uint64_decode_unsafe(&self->current_authority_derived_key_seed_len, ctx);
  if (self->current_authority_derived_key_seed_len != 0) {
    self->current_authority_derived_key_seed = fd_valloc_malloc( ctx->valloc, 8UL, self->current_authority_derived_key_seed_len );
    fd_bincode_bytes_decode_unsafe(self->current_authority_derived_key_seed, self->current_authority_derived_key_seed_len, ctx);
  } else
    self->current_authority_derived_key_seed = NULL;
  fd_pubkey_decode_unsafe(&self->new_authority, ctx);
}
int fd_vote_authorize_with_seed_args_decode_offsets(fd_vote_authorize_with_seed_args_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->authorization_type_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_vote_authorize_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->current_authority_derived_key_owner_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->current_authority_derived_key_seed_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong current_authority_derived_key_seed_len;
  err = fd_bincode_uint64_decode(&current_authority_derived_key_seed_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (current_authority_derived_key_seed_len != 0) {
    err = fd_bincode_bytes_decode_preflight(current_authority_derived_key_seed_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  self->new_authority_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_vote_authorize_with_seed_args_new(fd_vote_authorize_with_seed_args_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_authorize_with_seed_args_t));
  fd_vote_authorize_new(&self->authorization_type);
  fd_pubkey_new(&self->current_authority_derived_key_owner);
  fd_pubkey_new(&self->new_authority);
}
void fd_vote_authorize_with_seed_args_destroy(fd_vote_authorize_with_seed_args_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_vote_authorize_destroy(&self->authorization_type, ctx);
  fd_pubkey_destroy(&self->current_authority_derived_key_owner, ctx);
  if (NULL != self->current_authority_derived_key_seed) {
    fd_valloc_free( ctx->valloc, self->current_authority_derived_key_seed );
    self->current_authority_derived_key_seed = NULL;
  }
  fd_pubkey_destroy(&self->new_authority, ctx);
}

ulong fd_vote_authorize_with_seed_args_footprint( void ){ return FD_VOTE_AUTHORIZE_WITH_SEED_ARGS_FOOTPRINT; }
ulong fd_vote_authorize_with_seed_args_align( void ){ return FD_VOTE_AUTHORIZE_WITH_SEED_ARGS_ALIGN; }

void fd_vote_authorize_with_seed_args_walk(void * w, fd_vote_authorize_with_seed_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_authorize_with_seed_args", level++);
  fd_vote_authorize_walk(w, &self->authorization_type, fun, "authorization_type", level);
  fd_pubkey_walk(w, &self->current_authority_derived_key_owner, fun, "current_authority_derived_key_owner", level);
  fun(w, self->current_authority_derived_key_seed, "current_authority_derived_key_seed", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );
  fd_pubkey_walk(w, &self->new_authority, fun, "new_authority", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_authorize_with_seed_args", level--);
}
ulong fd_vote_authorize_with_seed_args_size(fd_vote_authorize_with_seed_args_t const * self) {
  ulong size = 0;
  size += fd_vote_authorize_size(&self->authorization_type);
  size += fd_pubkey_size(&self->current_authority_derived_key_owner);
  do {
    size += sizeof(ulong);
    size += self->current_authority_derived_key_seed_len;
  } while(0);
  size += fd_pubkey_size(&self->new_authority);
  return size;
}

int fd_vote_authorize_with_seed_args_encode(fd_vote_authorize_with_seed_args_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_vote_authorize_encode(&self->authorization_type, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->current_authority_derived_key_owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->current_authority_derived_key_seed_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->current_authority_derived_key_seed_len != 0) {
    err = fd_bincode_bytes_encode(self->current_authority_derived_key_seed, self->current_authority_derived_key_seed_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_pubkey_encode(&self->new_authority, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_vote_authorize_checked_with_seed_args_decode(fd_vote_authorize_checked_with_seed_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_authorize_checked_with_seed_args_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_authorize_checked_with_seed_args_new(self);
  fd_vote_authorize_checked_with_seed_args_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_authorize_checked_with_seed_args_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_vote_authorize_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong current_authority_derived_key_seed_len;
  err = fd_bincode_uint64_decode(&current_authority_derived_key_seed_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (current_authority_derived_key_seed_len != 0) {
    err = fd_bincode_bytes_decode_preflight(current_authority_derived_key_seed_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_vote_authorize_checked_with_seed_args_decode_unsafe(fd_vote_authorize_checked_with_seed_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_vote_authorize_decode_unsafe(&self->authorization_type, ctx);
  fd_pubkey_decode_unsafe(&self->current_authority_derived_key_owner, ctx);
  fd_bincode_uint64_decode_unsafe(&self->current_authority_derived_key_seed_len, ctx);
  if (self->current_authority_derived_key_seed_len != 0) {
    self->current_authority_derived_key_seed = fd_valloc_malloc( ctx->valloc, 8UL, self->current_authority_derived_key_seed_len );
    fd_bincode_bytes_decode_unsafe(self->current_authority_derived_key_seed, self->current_authority_derived_key_seed_len, ctx);
  } else
    self->current_authority_derived_key_seed = NULL;
}
int fd_vote_authorize_checked_with_seed_args_decode_offsets(fd_vote_authorize_checked_with_seed_args_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->authorization_type_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_vote_authorize_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->current_authority_derived_key_owner_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->current_authority_derived_key_seed_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong current_authority_derived_key_seed_len;
  err = fd_bincode_uint64_decode(&current_authority_derived_key_seed_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (current_authority_derived_key_seed_len != 0) {
    err = fd_bincode_bytes_decode_preflight(current_authority_derived_key_seed_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_vote_authorize_checked_with_seed_args_new(fd_vote_authorize_checked_with_seed_args_t* self) {
  fd_memset(self, 0, sizeof(fd_vote_authorize_checked_with_seed_args_t));
  fd_vote_authorize_new(&self->authorization_type);
  fd_pubkey_new(&self->current_authority_derived_key_owner);
}
void fd_vote_authorize_checked_with_seed_args_destroy(fd_vote_authorize_checked_with_seed_args_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_vote_authorize_destroy(&self->authorization_type, ctx);
  fd_pubkey_destroy(&self->current_authority_derived_key_owner, ctx);
  if (NULL != self->current_authority_derived_key_seed) {
    fd_valloc_free( ctx->valloc, self->current_authority_derived_key_seed );
    self->current_authority_derived_key_seed = NULL;
  }
}

ulong fd_vote_authorize_checked_with_seed_args_footprint( void ){ return FD_VOTE_AUTHORIZE_CHECKED_WITH_SEED_ARGS_FOOTPRINT; }
ulong fd_vote_authorize_checked_with_seed_args_align( void ){ return FD_VOTE_AUTHORIZE_CHECKED_WITH_SEED_ARGS_ALIGN; }

void fd_vote_authorize_checked_with_seed_args_walk(void * w, fd_vote_authorize_checked_with_seed_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_authorize_checked_with_seed_args", level++);
  fd_vote_authorize_walk(w, &self->authorization_type, fun, "authorization_type", level);
  fd_pubkey_walk(w, &self->current_authority_derived_key_owner, fun, "current_authority_derived_key_owner", level);
  fun(w, self->current_authority_derived_key_seed, "current_authority_derived_key_seed", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_authorize_checked_with_seed_args", level--);
}
ulong fd_vote_authorize_checked_with_seed_args_size(fd_vote_authorize_checked_with_seed_args_t const * self) {
  ulong size = 0;
  size += fd_vote_authorize_size(&self->authorization_type);
  size += fd_pubkey_size(&self->current_authority_derived_key_owner);
  do {
    size += sizeof(ulong);
    size += self->current_authority_derived_key_seed_len;
  } while(0);
  return size;
}

int fd_vote_authorize_checked_with_seed_args_encode(fd_vote_authorize_checked_with_seed_args_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_vote_authorize_encode(&self->authorization_type, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->current_authority_derived_key_owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->current_authority_derived_key_seed_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->current_authority_derived_key_seed_len != 0) {
    err = fd_bincode_bytes_encode(self->current_authority_derived_key_seed, self->current_authority_derived_key_seed_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_vote_instruction_is_initialize_account(fd_vote_instruction_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_vote_instruction_is_authorize(fd_vote_instruction_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_vote_instruction_is_vote(fd_vote_instruction_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_vote_instruction_is_withdraw(fd_vote_instruction_t const * self) {
  return self->discriminant == 3;
}
FD_FN_PURE uchar fd_vote_instruction_is_update_validator_identity(fd_vote_instruction_t const * self) {
  return self->discriminant == 4;
}
FD_FN_PURE uchar fd_vote_instruction_is_update_commission(fd_vote_instruction_t const * self) {
  return self->discriminant == 5;
}
FD_FN_PURE uchar fd_vote_instruction_is_vote_switch(fd_vote_instruction_t const * self) {
  return self->discriminant == 6;
}
FD_FN_PURE uchar fd_vote_instruction_is_authorize_checked(fd_vote_instruction_t const * self) {
  return self->discriminant == 7;
}
FD_FN_PURE uchar fd_vote_instruction_is_update_vote_state(fd_vote_instruction_t const * self) {
  return self->discriminant == 8;
}
FD_FN_PURE uchar fd_vote_instruction_is_update_vote_state_switch(fd_vote_instruction_t const * self) {
  return self->discriminant == 9;
}
FD_FN_PURE uchar fd_vote_instruction_is_authorize_with_seed(fd_vote_instruction_t const * self) {
  return self->discriminant == 10;
}
FD_FN_PURE uchar fd_vote_instruction_is_authorize_checked_with_seed(fd_vote_instruction_t const * self) {
  return self->discriminant == 11;
}
FD_FN_PURE uchar fd_vote_instruction_is_compact_update_vote_state(fd_vote_instruction_t const * self) {
  return self->discriminant == 12;
}
FD_FN_PURE uchar fd_vote_instruction_is_compact_update_vote_state_switch(fd_vote_instruction_t const * self) {
  return self->discriminant == 13;
}
void fd_vote_instruction_inner_new(fd_vote_instruction_inner_t* self, uint discriminant);
int fd_vote_instruction_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_vote_init_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_vote_authorize_pubkey_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_vote_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    err = fd_bincode_uint64_decode_preflight(ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    return FD_BINCODE_SUCCESS;
  }
  case 5: {
    err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 6: {
    err = fd_vote_switch_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 7: {
    err = fd_vote_authorize_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 8: {
    err = fd_vote_state_update_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 9: {
    err = fd_update_vote_state_switch_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 10: {
    err = fd_vote_authorize_with_seed_args_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 11: {
    err = fd_vote_authorize_checked_with_seed_args_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 12: {
    err = fd_compact_vote_state_update_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 13: {
    err = fd_compact_vote_state_update_switch_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_vote_instruction_inner_decode_unsafe(fd_vote_instruction_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_vote_init_decode_unsafe(&self->initialize_account, ctx);
    break;
  }
  case 1: {
    fd_vote_authorize_pubkey_decode_unsafe(&self->authorize, ctx);
    break;
  }
  case 2: {
    fd_vote_decode_unsafe(&self->vote, ctx);
    break;
  }
  case 3: {
    fd_bincode_uint64_decode_unsafe(&self->withdraw, ctx);
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    fd_bincode_uint8_decode_unsafe(&self->update_commission, ctx);
    break;
  }
  case 6: {
    fd_vote_switch_decode_unsafe(&self->vote_switch, ctx);
    break;
  }
  case 7: {
    fd_vote_authorize_decode_unsafe(&self->authorize_checked, ctx);
    break;
  }
  case 8: {
    fd_vote_state_update_decode_unsafe(&self->update_vote_state, ctx);
    break;
  }
  case 9: {
    fd_update_vote_state_switch_decode_unsafe(&self->update_vote_state_switch, ctx);
    break;
  }
  case 10: {
    fd_vote_authorize_with_seed_args_decode_unsafe(&self->authorize_with_seed, ctx);
    break;
  }
  case 11: {
    fd_vote_authorize_checked_with_seed_args_decode_unsafe(&self->authorize_checked_with_seed, ctx);
    break;
  }
  case 12: {
    fd_compact_vote_state_update_decode_unsafe(&self->compact_update_vote_state, ctx);
    break;
  }
  case 13: {
    fd_compact_vote_state_update_switch_decode_unsafe(&self->compact_update_vote_state_switch, ctx);
    break;
  }
  }
}
int fd_vote_instruction_decode(fd_vote_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_vote_instruction_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_vote_instruction_new(self);
  fd_vote_instruction_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_vote_instruction_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_vote_instruction_inner_decode_preflight(discriminant, ctx);
}
void fd_vote_instruction_decode_unsafe(fd_vote_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_vote_instruction_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_vote_instruction_inner_new(fd_vote_instruction_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_vote_init_new(&self->initialize_account);
    break;
  }
  case 1: {
    fd_vote_authorize_pubkey_new(&self->authorize);
    break;
  }
  case 2: {
    fd_vote_new(&self->vote);
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    fd_vote_switch_new(&self->vote_switch);
    break;
  }
  case 7: {
    fd_vote_authorize_new(&self->authorize_checked);
    break;
  }
  case 8: {
    fd_vote_state_update_new(&self->update_vote_state);
    break;
  }
  case 9: {
    fd_update_vote_state_switch_new(&self->update_vote_state_switch);
    break;
  }
  case 10: {
    fd_vote_authorize_with_seed_args_new(&self->authorize_with_seed);
    break;
  }
  case 11: {
    fd_vote_authorize_checked_with_seed_args_new(&self->authorize_checked_with_seed);
    break;
  }
  case 12: {
    fd_compact_vote_state_update_new(&self->compact_update_vote_state);
    break;
  }
  case 13: {
    fd_compact_vote_state_update_switch_new(&self->compact_update_vote_state_switch);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_vote_instruction_new_disc(fd_vote_instruction_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_vote_instruction_inner_new(&self->inner, self->discriminant);
}
void fd_vote_instruction_new(fd_vote_instruction_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_vote_instruction_new_disc(self, UINT_MAX);
}
void fd_vote_instruction_inner_destroy(fd_vote_instruction_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_vote_init_destroy(&self->initialize_account, ctx);
    break;
  }
  case 1: {
    fd_vote_authorize_pubkey_destroy(&self->authorize, ctx);
    break;
  }
  case 2: {
    fd_vote_destroy(&self->vote, ctx);
    break;
  }
  case 3: {
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    fd_vote_switch_destroy(&self->vote_switch, ctx);
    break;
  }
  case 7: {
    fd_vote_authorize_destroy(&self->authorize_checked, ctx);
    break;
  }
  case 8: {
    fd_vote_state_update_destroy(&self->update_vote_state, ctx);
    break;
  }
  case 9: {
    fd_update_vote_state_switch_destroy(&self->update_vote_state_switch, ctx);
    break;
  }
  case 10: {
    fd_vote_authorize_with_seed_args_destroy(&self->authorize_with_seed, ctx);
    break;
  }
  case 11: {
    fd_vote_authorize_checked_with_seed_args_destroy(&self->authorize_checked_with_seed, ctx);
    break;
  }
  case 12: {
    fd_compact_vote_state_update_destroy(&self->compact_update_vote_state, ctx);
    break;
  }
  case 13: {
    fd_compact_vote_state_update_switch_destroy(&self->compact_update_vote_state_switch, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_vote_instruction_destroy(fd_vote_instruction_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_vote_instruction_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_vote_instruction_footprint( void ){ return FD_VOTE_INSTRUCTION_FOOTPRINT; }
ulong fd_vote_instruction_align( void ){ return FD_VOTE_INSTRUCTION_ALIGN; }

void fd_vote_instruction_walk(void * w, fd_vote_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_instruction", level++);
  switch (self->discriminant) {
  case 0: {
    fd_vote_init_walk(w, &self->inner.initialize_account, fun, "initialize_account", level);
    break;
  }
  case 1: {
    fd_vote_authorize_pubkey_walk(w, &self->inner.authorize, fun, "authorize", level);
    break;
  }
  case 2: {
    fd_vote_walk(w, &self->inner.vote, fun, "vote", level);
    break;
  }
  case 3: {
  fun( w, &self->inner.withdraw, "withdraw", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
    break;
  }
  case 5: {
  fun( w, &self->inner.update_commission, "update_commission", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
    break;
  }
  case 6: {
    fd_vote_switch_walk(w, &self->inner.vote_switch, fun, "vote_switch", level);
    break;
  }
  case 7: {
    fd_vote_authorize_walk(w, &self->inner.authorize_checked, fun, "authorize_checked", level);
    break;
  }
  case 8: {
    fd_vote_state_update_walk(w, &self->inner.update_vote_state, fun, "update_vote_state", level);
    break;
  }
  case 9: {
    fd_update_vote_state_switch_walk(w, &self->inner.update_vote_state_switch, fun, "update_vote_state_switch", level);
    break;
  }
  case 10: {
    fd_vote_authorize_with_seed_args_walk(w, &self->inner.authorize_with_seed, fun, "authorize_with_seed", level);
    break;
  }
  case 11: {
    fd_vote_authorize_checked_with_seed_args_walk(w, &self->inner.authorize_checked_with_seed, fun, "authorize_checked_with_seed", level);
    break;
  }
  case 12: {
    fd_compact_vote_state_update_walk(w, &self->inner.compact_update_vote_state, fun, "compact_update_vote_state", level);
    break;
  }
  case 13: {
    fd_compact_vote_state_update_switch_walk(w, &self->inner.compact_update_vote_state_switch, fun, "compact_update_vote_state_switch", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_instruction", level--);
}
ulong fd_vote_instruction_size(fd_vote_instruction_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_vote_init_size(&self->inner.initialize_account);
    break;
  }
  case 1: {
    size += fd_vote_authorize_pubkey_size(&self->inner.authorize);
    break;
  }
  case 2: {
    size += fd_vote_size(&self->inner.vote);
    break;
  }
  case 3: {
    size += sizeof(ulong);
    break;
  }
  case 5: {
    size += sizeof(char);
    break;
  }
  case 6: {
    size += fd_vote_switch_size(&self->inner.vote_switch);
    break;
  }
  case 7: {
    size += fd_vote_authorize_size(&self->inner.authorize_checked);
    break;
  }
  case 8: {
    size += fd_vote_state_update_size(&self->inner.update_vote_state);
    break;
  }
  case 9: {
    size += fd_update_vote_state_switch_size(&self->inner.update_vote_state_switch);
    break;
  }
  case 10: {
    size += fd_vote_authorize_with_seed_args_size(&self->inner.authorize_with_seed);
    break;
  }
  case 11: {
    size += fd_vote_authorize_checked_with_seed_args_size(&self->inner.authorize_checked_with_seed);
    break;
  }
  case 12: {
    size += fd_compact_vote_state_update_size(&self->inner.compact_update_vote_state);
    break;
  }
  case 13: {
    size += fd_compact_vote_state_update_switch_size(&self->inner.compact_update_vote_state_switch);
    break;
  }
  }
  return size;
}

int fd_vote_instruction_inner_encode(fd_vote_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_vote_init_encode(&self->initialize_account, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 1: {
    err = fd_vote_authorize_pubkey_encode(&self->authorize, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 2: {
    err = fd_vote_encode(&self->vote, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 3: {
    err = fd_bincode_uint64_encode(self->withdraw, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 5: {
    err = fd_bincode_uint8_encode( (uchar)(self->update_commission), ctx );
  if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 6: {
    err = fd_vote_switch_encode(&self->vote_switch, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 7: {
    err = fd_vote_authorize_encode(&self->authorize_checked, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 8: {
    err = fd_vote_state_update_encode(&self->update_vote_state, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 9: {
    err = fd_update_vote_state_switch_encode(&self->update_vote_state_switch, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 10: {
    err = fd_vote_authorize_with_seed_args_encode(&self->authorize_with_seed, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 11: {
    err = fd_vote_authorize_checked_with_seed_args_encode(&self->authorize_checked_with_seed, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 12: {
    err = fd_compact_vote_state_update_encode(&self->compact_update_vote_state, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 13: {
    err = fd_compact_vote_state_update_switch_encode(&self->compact_update_vote_state_switch, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_vote_instruction_encode(fd_vote_instruction_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_vote_instruction_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_system_program_instruction_create_account_decode(fd_system_program_instruction_create_account_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_system_program_instruction_create_account_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_system_program_instruction_create_account_new(self);
  fd_system_program_instruction_create_account_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_system_program_instruction_create_account_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_system_program_instruction_create_account_decode_unsafe(fd_system_program_instruction_create_account_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->lamports, ctx);
  fd_bincode_uint64_decode_unsafe(&self->space, ctx);
  fd_pubkey_decode_unsafe(&self->owner, ctx);
}
int fd_system_program_instruction_create_account_decode_offsets(fd_system_program_instruction_create_account_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->lamports_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->space_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->owner_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_system_program_instruction_create_account_new(fd_system_program_instruction_create_account_t* self) {
  fd_memset(self, 0, sizeof(fd_system_program_instruction_create_account_t));
  fd_pubkey_new(&self->owner);
}
void fd_system_program_instruction_create_account_destroy(fd_system_program_instruction_create_account_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->owner, ctx);
}

ulong fd_system_program_instruction_create_account_footprint( void ){ return FD_SYSTEM_PROGRAM_INSTRUCTION_CREATE_ACCOUNT_FOOTPRINT; }
ulong fd_system_program_instruction_create_account_align( void ){ return FD_SYSTEM_PROGRAM_INSTRUCTION_CREATE_ACCOUNT_ALIGN; }

void fd_system_program_instruction_create_account_walk(void * w, fd_system_program_instruction_create_account_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_system_program_instruction_create_account", level++);
  fun( w, &self->lamports, "lamports", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->space, "space", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_pubkey_walk(w, &self->owner, fun, "owner", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_system_program_instruction_create_account", level--);
}
ulong fd_system_program_instruction_create_account_size(fd_system_program_instruction_create_account_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_pubkey_size(&self->owner);
  return size;
}

int fd_system_program_instruction_create_account_encode(fd_system_program_instruction_create_account_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->lamports, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->space, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_system_program_instruction_create_account_with_seed_decode(fd_system_program_instruction_create_account_with_seed_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_system_program_instruction_create_account_with_seed_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_system_program_instruction_create_account_with_seed_new(self);
  fd_system_program_instruction_create_account_with_seed_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_system_program_instruction_create_account_with_seed_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong seed_len;
  err = fd_bincode_uint64_decode(&seed_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (seed_len != 0) {
    err = fd_bincode_bytes_decode_preflight(seed_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_system_program_instruction_create_account_with_seed_decode_unsafe(fd_system_program_instruction_create_account_with_seed_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->base, ctx);
  fd_bincode_uint64_decode_unsafe(&self->seed_len, ctx);
  if (self->seed_len != 0) {
    self->seed = fd_valloc_malloc( ctx->valloc, 8UL, self->seed_len );
    fd_bincode_bytes_decode_unsafe(self->seed, self->seed_len, ctx);
  } else
    self->seed = NULL;
  fd_bincode_uint64_decode_unsafe(&self->lamports, ctx);
  fd_bincode_uint64_decode_unsafe(&self->space, ctx);
  fd_pubkey_decode_unsafe(&self->owner, ctx);
}
int fd_system_program_instruction_create_account_with_seed_decode_offsets(fd_system_program_instruction_create_account_with_seed_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->base_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->seed_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong seed_len;
  err = fd_bincode_uint64_decode(&seed_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (seed_len != 0) {
    err = fd_bincode_bytes_decode_preflight(seed_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  self->lamports_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->space_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->owner_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_system_program_instruction_create_account_with_seed_new(fd_system_program_instruction_create_account_with_seed_t* self) {
  fd_memset(self, 0, sizeof(fd_system_program_instruction_create_account_with_seed_t));
  fd_pubkey_new(&self->base);
  fd_pubkey_new(&self->owner);
}
void fd_system_program_instruction_create_account_with_seed_destroy(fd_system_program_instruction_create_account_with_seed_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->base, ctx);
  if (NULL != self->seed) {
    fd_valloc_free( ctx->valloc, self->seed );
    self->seed = NULL;
  }
  fd_pubkey_destroy(&self->owner, ctx);
}

ulong fd_system_program_instruction_create_account_with_seed_footprint( void ){ return FD_SYSTEM_PROGRAM_INSTRUCTION_CREATE_ACCOUNT_WITH_SEED_FOOTPRINT; }
ulong fd_system_program_instruction_create_account_with_seed_align( void ){ return FD_SYSTEM_PROGRAM_INSTRUCTION_CREATE_ACCOUNT_WITH_SEED_ALIGN; }

void fd_system_program_instruction_create_account_with_seed_walk(void * w, fd_system_program_instruction_create_account_with_seed_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_system_program_instruction_create_account_with_seed", level++);
  fd_pubkey_walk(w, &self->base, fun, "base", level);
  fun(w, self->seed, "seed", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );
  fun( w, &self->lamports, "lamports", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->space, "space", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_pubkey_walk(w, &self->owner, fun, "owner", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_system_program_instruction_create_account_with_seed", level--);
}
ulong fd_system_program_instruction_create_account_with_seed_size(fd_system_program_instruction_create_account_with_seed_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->base);
  do {
    size += sizeof(ulong);
    size += self->seed_len;
  } while(0);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_pubkey_size(&self->owner);
  return size;
}

int fd_system_program_instruction_create_account_with_seed_encode(fd_system_program_instruction_create_account_with_seed_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->base, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->seed_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->seed_len != 0) {
    err = fd_bincode_bytes_encode(self->seed, self->seed_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_uint64_encode(self->lamports, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->space, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_system_program_instruction_allocate_with_seed_decode(fd_system_program_instruction_allocate_with_seed_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_system_program_instruction_allocate_with_seed_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_system_program_instruction_allocate_with_seed_new(self);
  fd_system_program_instruction_allocate_with_seed_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_system_program_instruction_allocate_with_seed_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong seed_len;
  err = fd_bincode_uint64_decode(&seed_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (seed_len != 0) {
    err = fd_bincode_bytes_decode_preflight(seed_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_system_program_instruction_allocate_with_seed_decode_unsafe(fd_system_program_instruction_allocate_with_seed_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->base, ctx);
  fd_bincode_uint64_decode_unsafe(&self->seed_len, ctx);
  if (self->seed_len != 0) {
    self->seed = fd_valloc_malloc( ctx->valloc, 8UL, self->seed_len );
    fd_bincode_bytes_decode_unsafe(self->seed, self->seed_len, ctx);
  } else
    self->seed = NULL;
  fd_bincode_uint64_decode_unsafe(&self->space, ctx);
  fd_pubkey_decode_unsafe(&self->owner, ctx);
}
int fd_system_program_instruction_allocate_with_seed_decode_offsets(fd_system_program_instruction_allocate_with_seed_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->base_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->seed_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong seed_len;
  err = fd_bincode_uint64_decode(&seed_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (seed_len != 0) {
    err = fd_bincode_bytes_decode_preflight(seed_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  self->space_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->owner_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_system_program_instruction_allocate_with_seed_new(fd_system_program_instruction_allocate_with_seed_t* self) {
  fd_memset(self, 0, sizeof(fd_system_program_instruction_allocate_with_seed_t));
  fd_pubkey_new(&self->base);
  fd_pubkey_new(&self->owner);
}
void fd_system_program_instruction_allocate_with_seed_destroy(fd_system_program_instruction_allocate_with_seed_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->base, ctx);
  if (NULL != self->seed) {
    fd_valloc_free( ctx->valloc, self->seed );
    self->seed = NULL;
  }
  fd_pubkey_destroy(&self->owner, ctx);
}

ulong fd_system_program_instruction_allocate_with_seed_footprint( void ){ return FD_SYSTEM_PROGRAM_INSTRUCTION_ALLOCATE_WITH_SEED_FOOTPRINT; }
ulong fd_system_program_instruction_allocate_with_seed_align( void ){ return FD_SYSTEM_PROGRAM_INSTRUCTION_ALLOCATE_WITH_SEED_ALIGN; }

void fd_system_program_instruction_allocate_with_seed_walk(void * w, fd_system_program_instruction_allocate_with_seed_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_system_program_instruction_allocate_with_seed", level++);
  fd_pubkey_walk(w, &self->base, fun, "base", level);
  fun(w, self->seed, "seed", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );
  fun( w, &self->space, "space", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_pubkey_walk(w, &self->owner, fun, "owner", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_system_program_instruction_allocate_with_seed", level--);
}
ulong fd_system_program_instruction_allocate_with_seed_size(fd_system_program_instruction_allocate_with_seed_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->base);
  do {
    size += sizeof(ulong);
    size += self->seed_len;
  } while(0);
  size += sizeof(ulong);
  size += fd_pubkey_size(&self->owner);
  return size;
}

int fd_system_program_instruction_allocate_with_seed_encode(fd_system_program_instruction_allocate_with_seed_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->base, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->seed_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->seed_len != 0) {
    err = fd_bincode_bytes_encode(self->seed, self->seed_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_bincode_uint64_encode(self->space, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_system_program_instruction_assign_with_seed_decode(fd_system_program_instruction_assign_with_seed_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_system_program_instruction_assign_with_seed_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_system_program_instruction_assign_with_seed_new(self);
  fd_system_program_instruction_assign_with_seed_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_system_program_instruction_assign_with_seed_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong seed_len;
  err = fd_bincode_uint64_decode(&seed_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (seed_len != 0) {
    err = fd_bincode_bytes_decode_preflight(seed_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_system_program_instruction_assign_with_seed_decode_unsafe(fd_system_program_instruction_assign_with_seed_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->base, ctx);
  fd_bincode_uint64_decode_unsafe(&self->seed_len, ctx);
  if (self->seed_len != 0) {
    self->seed = fd_valloc_malloc( ctx->valloc, 8UL, self->seed_len );
    fd_bincode_bytes_decode_unsafe(self->seed, self->seed_len, ctx);
  } else
    self->seed = NULL;
  fd_pubkey_decode_unsafe(&self->owner, ctx);
}
int fd_system_program_instruction_assign_with_seed_decode_offsets(fd_system_program_instruction_assign_with_seed_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->base_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->seed_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong seed_len;
  err = fd_bincode_uint64_decode(&seed_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (seed_len != 0) {
    err = fd_bincode_bytes_decode_preflight(seed_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  self->owner_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_system_program_instruction_assign_with_seed_new(fd_system_program_instruction_assign_with_seed_t* self) {
  fd_memset(self, 0, sizeof(fd_system_program_instruction_assign_with_seed_t));
  fd_pubkey_new(&self->base);
  fd_pubkey_new(&self->owner);
}
void fd_system_program_instruction_assign_with_seed_destroy(fd_system_program_instruction_assign_with_seed_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->base, ctx);
  if (NULL != self->seed) {
    fd_valloc_free( ctx->valloc, self->seed );
    self->seed = NULL;
  }
  fd_pubkey_destroy(&self->owner, ctx);
}

ulong fd_system_program_instruction_assign_with_seed_footprint( void ){ return FD_SYSTEM_PROGRAM_INSTRUCTION_ASSIGN_WITH_SEED_FOOTPRINT; }
ulong fd_system_program_instruction_assign_with_seed_align( void ){ return FD_SYSTEM_PROGRAM_INSTRUCTION_ASSIGN_WITH_SEED_ALIGN; }

void fd_system_program_instruction_assign_with_seed_walk(void * w, fd_system_program_instruction_assign_with_seed_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_system_program_instruction_assign_with_seed", level++);
  fd_pubkey_walk(w, &self->base, fun, "base", level);
  fun(w, self->seed, "seed", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );
  fd_pubkey_walk(w, &self->owner, fun, "owner", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_system_program_instruction_assign_with_seed", level--);
}
ulong fd_system_program_instruction_assign_with_seed_size(fd_system_program_instruction_assign_with_seed_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->base);
  do {
    size += sizeof(ulong);
    size += self->seed_len;
  } while(0);
  size += fd_pubkey_size(&self->owner);
  return size;
}

int fd_system_program_instruction_assign_with_seed_encode(fd_system_program_instruction_assign_with_seed_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->base, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->seed_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->seed_len != 0) {
    err = fd_bincode_bytes_encode(self->seed, self->seed_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_pubkey_encode(&self->owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_system_program_instruction_transfer_with_seed_decode(fd_system_program_instruction_transfer_with_seed_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_system_program_instruction_transfer_with_seed_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_system_program_instruction_transfer_with_seed_new(self);
  fd_system_program_instruction_transfer_with_seed_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_system_program_instruction_transfer_with_seed_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ulong from_seed_len;
  err = fd_bincode_uint64_decode(&from_seed_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (from_seed_len != 0) {
    err = fd_bincode_bytes_decode_preflight(from_seed_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_system_program_instruction_transfer_with_seed_decode_unsafe(fd_system_program_instruction_transfer_with_seed_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->lamports, ctx);
  fd_bincode_uint64_decode_unsafe(&self->from_seed_len, ctx);
  if (self->from_seed_len != 0) {
    self->from_seed = fd_valloc_malloc( ctx->valloc, 8UL, self->from_seed_len );
    fd_bincode_bytes_decode_unsafe(self->from_seed, self->from_seed_len, ctx);
  } else
    self->from_seed = NULL;
  fd_pubkey_decode_unsafe(&self->from_owner, ctx);
}
int fd_system_program_instruction_transfer_with_seed_decode_offsets(fd_system_program_instruction_transfer_with_seed_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->lamports_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->from_seed_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong from_seed_len;
  err = fd_bincode_uint64_decode(&from_seed_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (from_seed_len != 0) {
    err = fd_bincode_bytes_decode_preflight(from_seed_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  self->from_owner_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_system_program_instruction_transfer_with_seed_new(fd_system_program_instruction_transfer_with_seed_t* self) {
  fd_memset(self, 0, sizeof(fd_system_program_instruction_transfer_with_seed_t));
  fd_pubkey_new(&self->from_owner);
}
void fd_system_program_instruction_transfer_with_seed_destroy(fd_system_program_instruction_transfer_with_seed_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->from_seed) {
    fd_valloc_free( ctx->valloc, self->from_seed );
    self->from_seed = NULL;
  }
  fd_pubkey_destroy(&self->from_owner, ctx);
}

ulong fd_system_program_instruction_transfer_with_seed_footprint( void ){ return FD_SYSTEM_PROGRAM_INSTRUCTION_TRANSFER_WITH_SEED_FOOTPRINT; }
ulong fd_system_program_instruction_transfer_with_seed_align( void ){ return FD_SYSTEM_PROGRAM_INSTRUCTION_TRANSFER_WITH_SEED_ALIGN; }

void fd_system_program_instruction_transfer_with_seed_walk(void * w, fd_system_program_instruction_transfer_with_seed_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_system_program_instruction_transfer_with_seed", level++);
  fun( w, &self->lamports, "lamports", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self->from_seed, "from_seed", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );
  fd_pubkey_walk(w, &self->from_owner, fun, "from_owner", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_system_program_instruction_transfer_with_seed", level--);
}
ulong fd_system_program_instruction_transfer_with_seed_size(fd_system_program_instruction_transfer_with_seed_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  do {
    size += sizeof(ulong);
    size += self->from_seed_len;
  } while(0);
  size += fd_pubkey_size(&self->from_owner);
  return size;
}

int fd_system_program_instruction_transfer_with_seed_encode(fd_system_program_instruction_transfer_with_seed_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->lamports, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->from_seed_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->from_seed_len != 0) {
    err = fd_bincode_bytes_encode(self->from_seed, self->from_seed_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_pubkey_encode(&self->from_owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_system_program_instruction_is_create_account(fd_system_program_instruction_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_system_program_instruction_is_assign(fd_system_program_instruction_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_system_program_instruction_is_transfer(fd_system_program_instruction_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_system_program_instruction_is_create_account_with_seed(fd_system_program_instruction_t const * self) {
  return self->discriminant == 3;
}
FD_FN_PURE uchar fd_system_program_instruction_is_advance_nonce_account(fd_system_program_instruction_t const * self) {
  return self->discriminant == 4;
}
FD_FN_PURE uchar fd_system_program_instruction_is_withdraw_nonce_account(fd_system_program_instruction_t const * self) {
  return self->discriminant == 5;
}
FD_FN_PURE uchar fd_system_program_instruction_is_initialize_nonce_account(fd_system_program_instruction_t const * self) {
  return self->discriminant == 6;
}
FD_FN_PURE uchar fd_system_program_instruction_is_authorize_nonce_account(fd_system_program_instruction_t const * self) {
  return self->discriminant == 7;
}
FD_FN_PURE uchar fd_system_program_instruction_is_allocate(fd_system_program_instruction_t const * self) {
  return self->discriminant == 8;
}
FD_FN_PURE uchar fd_system_program_instruction_is_allocate_with_seed(fd_system_program_instruction_t const * self) {
  return self->discriminant == 9;
}
FD_FN_PURE uchar fd_system_program_instruction_is_assign_with_seed(fd_system_program_instruction_t const * self) {
  return self->discriminant == 10;
}
FD_FN_PURE uchar fd_system_program_instruction_is_transfer_with_seed(fd_system_program_instruction_t const * self) {
  return self->discriminant == 11;
}
FD_FN_PURE uchar fd_system_program_instruction_is_upgrade_nonce_account(fd_system_program_instruction_t const * self) {
  return self->discriminant == 12;
}
void fd_system_program_instruction_inner_new(fd_system_program_instruction_inner_t* self, uint discriminant);
int fd_system_program_instruction_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_system_program_instruction_create_account_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_bincode_bytes_decode_preflight(32, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_bincode_uint64_decode_preflight(ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    err = fd_system_program_instruction_create_account_with_seed_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    return FD_BINCODE_SUCCESS;
  }
  case 5: {
    err = fd_bincode_uint64_decode_preflight(ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 6: {
    err = fd_bincode_bytes_decode_preflight(32, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 7: {
    err = fd_bincode_bytes_decode_preflight(32, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 8: {
    err = fd_bincode_uint64_decode_preflight(ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 9: {
    err = fd_system_program_instruction_allocate_with_seed_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 10: {
    err = fd_system_program_instruction_assign_with_seed_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 11: {
    err = fd_system_program_instruction_transfer_with_seed_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 12: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_system_program_instruction_inner_decode_unsafe(fd_system_program_instruction_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_system_program_instruction_create_account_decode_unsafe(&self->create_account, ctx);
    break;
  }
  case 1: {
    fd_pubkey_decode_unsafe(&self->assign, ctx);
    break;
  }
  case 2: {
    fd_bincode_uint64_decode_unsafe(&self->transfer, ctx);
    break;
  }
  case 3: {
    fd_system_program_instruction_create_account_with_seed_decode_unsafe(&self->create_account_with_seed, ctx);
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    fd_bincode_uint64_decode_unsafe(&self->withdraw_nonce_account, ctx);
    break;
  }
  case 6: {
    fd_pubkey_decode_unsafe(&self->initialize_nonce_account, ctx);
    break;
  }
  case 7: {
    fd_pubkey_decode_unsafe(&self->authorize_nonce_account, ctx);
    break;
  }
  case 8: {
    fd_bincode_uint64_decode_unsafe(&self->allocate, ctx);
    break;
  }
  case 9: {
    fd_system_program_instruction_allocate_with_seed_decode_unsafe(&self->allocate_with_seed, ctx);
    break;
  }
  case 10: {
    fd_system_program_instruction_assign_with_seed_decode_unsafe(&self->assign_with_seed, ctx);
    break;
  }
  case 11: {
    fd_system_program_instruction_transfer_with_seed_decode_unsafe(&self->transfer_with_seed, ctx);
    break;
  }
  case 12: {
    break;
  }
  }
}
int fd_system_program_instruction_decode(fd_system_program_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_system_program_instruction_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_system_program_instruction_new(self);
  fd_system_program_instruction_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_system_program_instruction_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_system_program_instruction_inner_decode_preflight(discriminant, ctx);
}
void fd_system_program_instruction_decode_unsafe(fd_system_program_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_system_program_instruction_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_system_program_instruction_inner_new(fd_system_program_instruction_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_system_program_instruction_create_account_new(&self->create_account);
    break;
  }
  case 1: {
    fd_pubkey_new(&self->assign);
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    fd_system_program_instruction_create_account_with_seed_new(&self->create_account_with_seed);
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    fd_pubkey_new(&self->initialize_nonce_account);
    break;
  }
  case 7: {
    fd_pubkey_new(&self->authorize_nonce_account);
    break;
  }
  case 8: {
    break;
  }
  case 9: {
    fd_system_program_instruction_allocate_with_seed_new(&self->allocate_with_seed);
    break;
  }
  case 10: {
    fd_system_program_instruction_assign_with_seed_new(&self->assign_with_seed);
    break;
  }
  case 11: {
    fd_system_program_instruction_transfer_with_seed_new(&self->transfer_with_seed);
    break;
  }
  case 12: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_system_program_instruction_new_disc(fd_system_program_instruction_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_system_program_instruction_inner_new(&self->inner, self->discriminant);
}
void fd_system_program_instruction_new(fd_system_program_instruction_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_system_program_instruction_new_disc(self, UINT_MAX);
}
void fd_system_program_instruction_inner_destroy(fd_system_program_instruction_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_system_program_instruction_create_account_destroy(&self->create_account, ctx);
    break;
  }
  case 1: {
    fd_pubkey_destroy(&self->assign, ctx);
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    fd_system_program_instruction_create_account_with_seed_destroy(&self->create_account_with_seed, ctx);
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    fd_pubkey_destroy(&self->initialize_nonce_account, ctx);
    break;
  }
  case 7: {
    fd_pubkey_destroy(&self->authorize_nonce_account, ctx);
    break;
  }
  case 8: {
    break;
  }
  case 9: {
    fd_system_program_instruction_allocate_with_seed_destroy(&self->allocate_with_seed, ctx);
    break;
  }
  case 10: {
    fd_system_program_instruction_assign_with_seed_destroy(&self->assign_with_seed, ctx);
    break;
  }
  case 11: {
    fd_system_program_instruction_transfer_with_seed_destroy(&self->transfer_with_seed, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_system_program_instruction_destroy(fd_system_program_instruction_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_system_program_instruction_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_system_program_instruction_footprint( void ){ return FD_SYSTEM_PROGRAM_INSTRUCTION_FOOTPRINT; }
ulong fd_system_program_instruction_align( void ){ return FD_SYSTEM_PROGRAM_INSTRUCTION_ALIGN; }

void fd_system_program_instruction_walk(void * w, fd_system_program_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_system_program_instruction", level++);
  switch (self->discriminant) {
  case 0: {
    fd_system_program_instruction_create_account_walk(w, &self->inner.create_account, fun, "create_account", level);
    break;
  }
  case 1: {
    fd_pubkey_walk(w, &self->inner.assign, fun, "assign", level);
    break;
  }
  case 2: {
  fun( w, &self->inner.transfer, "transfer", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
    break;
  }
  case 3: {
    fd_system_program_instruction_create_account_with_seed_walk(w, &self->inner.create_account_with_seed, fun, "create_account_with_seed", level);
    break;
  }
  case 5: {
  fun( w, &self->inner.withdraw_nonce_account, "withdraw_nonce_account", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
    break;
  }
  case 6: {
    fd_pubkey_walk(w, &self->inner.initialize_nonce_account, fun, "initialize_nonce_account", level);
    break;
  }
  case 7: {
    fd_pubkey_walk(w, &self->inner.authorize_nonce_account, fun, "authorize_nonce_account", level);
    break;
  }
  case 8: {
  fun( w, &self->inner.allocate, "allocate", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
    break;
  }
  case 9: {
    fd_system_program_instruction_allocate_with_seed_walk(w, &self->inner.allocate_with_seed, fun, "allocate_with_seed", level);
    break;
  }
  case 10: {
    fd_system_program_instruction_assign_with_seed_walk(w, &self->inner.assign_with_seed, fun, "assign_with_seed", level);
    break;
  }
  case 11: {
    fd_system_program_instruction_transfer_with_seed_walk(w, &self->inner.transfer_with_seed, fun, "transfer_with_seed", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_system_program_instruction", level--);
}
ulong fd_system_program_instruction_size(fd_system_program_instruction_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_system_program_instruction_create_account_size(&self->inner.create_account);
    break;
  }
  case 1: {
    size += fd_pubkey_size(&self->inner.assign);
    break;
  }
  case 2: {
    size += sizeof(ulong);
    break;
  }
  case 3: {
    size += fd_system_program_instruction_create_account_with_seed_size(&self->inner.create_account_with_seed);
    break;
  }
  case 5: {
    size += sizeof(ulong);
    break;
  }
  case 6: {
    size += fd_pubkey_size(&self->inner.initialize_nonce_account);
    break;
  }
  case 7: {
    size += fd_pubkey_size(&self->inner.authorize_nonce_account);
    break;
  }
  case 8: {
    size += sizeof(ulong);
    break;
  }
  case 9: {
    size += fd_system_program_instruction_allocate_with_seed_size(&self->inner.allocate_with_seed);
    break;
  }
  case 10: {
    size += fd_system_program_instruction_assign_with_seed_size(&self->inner.assign_with_seed);
    break;
  }
  case 11: {
    size += fd_system_program_instruction_transfer_with_seed_size(&self->inner.transfer_with_seed);
    break;
  }
  }
  return size;
}

int fd_system_program_instruction_inner_encode(fd_system_program_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_system_program_instruction_create_account_encode(&self->create_account, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 1: {
    err = fd_pubkey_encode(&self->assign, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 2: {
    err = fd_bincode_uint64_encode(self->transfer, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 3: {
    err = fd_system_program_instruction_create_account_with_seed_encode(&self->create_account_with_seed, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 5: {
    err = fd_bincode_uint64_encode(self->withdraw_nonce_account, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 6: {
    err = fd_pubkey_encode(&self->initialize_nonce_account, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 7: {
    err = fd_pubkey_encode(&self->authorize_nonce_account, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 8: {
    err = fd_bincode_uint64_encode(self->allocate, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 9: {
    err = fd_system_program_instruction_allocate_with_seed_encode(&self->allocate_with_seed, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 10: {
    err = fd_system_program_instruction_assign_with_seed_encode(&self->assign_with_seed, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 11: {
    err = fd_system_program_instruction_transfer_with_seed_encode(&self->transfer_with_seed, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_system_program_instruction_encode(fd_system_program_instruction_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_system_program_instruction_inner_encode(&self->inner, self->discriminant, ctx);
}

FD_FN_PURE uchar fd_system_error_is_account_already_in_use(fd_system_error_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_system_error_is_result_with_negative_lamports(fd_system_error_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_system_error_is_invalid_program_id(fd_system_error_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_system_error_is_invalid_account_data_length(fd_system_error_t const * self) {
  return self->discriminant == 3;
}
FD_FN_PURE uchar fd_system_error_is_max_seed_length_exceeded(fd_system_error_t const * self) {
  return self->discriminant == 4;
}
FD_FN_PURE uchar fd_system_error_is_address_with_seed_mismatch(fd_system_error_t const * self) {
  return self->discriminant == 5;
}
FD_FN_PURE uchar fd_system_error_is_nonce_no_recent_blockhashes(fd_system_error_t const * self) {
  return self->discriminant == 6;
}
FD_FN_PURE uchar fd_system_error_is_nonce_blockhash_not_expired(fd_system_error_t const * self) {
  return self->discriminant == 7;
}
FD_FN_PURE uchar fd_system_error_is_nonce_unexpected_blockhash_value(fd_system_error_t const * self) {
  return self->discriminant == 8;
}
void fd_system_error_inner_new(fd_system_error_inner_t* self, uint discriminant);
int fd_system_error_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    return FD_BINCODE_SUCCESS;
  }
  case 5: {
    return FD_BINCODE_SUCCESS;
  }
  case 6: {
    return FD_BINCODE_SUCCESS;
  }
  case 7: {
    return FD_BINCODE_SUCCESS;
  }
  case 8: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_system_error_inner_decode_unsafe(fd_system_error_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    break;
  }
  case 7: {
    break;
  }
  case 8: {
    break;
  }
  }
}
int fd_system_error_decode(fd_system_error_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_system_error_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_system_error_new(self);
  fd_system_error_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_system_error_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_system_error_inner_decode_preflight(discriminant, ctx);
}
void fd_system_error_decode_unsafe(fd_system_error_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_system_error_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_system_error_inner_new(fd_system_error_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    break;
  }
  case 7: {
    break;
  }
  case 8: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_system_error_new_disc(fd_system_error_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_system_error_inner_new(&self->inner, self->discriminant);
}
void fd_system_error_new(fd_system_error_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_system_error_new_disc(self, UINT_MAX);
}
void fd_system_error_inner_destroy(fd_system_error_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_system_error_destroy(fd_system_error_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_system_error_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_system_error_footprint( void ){ return FD_SYSTEM_ERROR_FOOTPRINT; }
ulong fd_system_error_align( void ){ return FD_SYSTEM_ERROR_ALIGN; }

void fd_system_error_walk(void * w, fd_system_error_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_system_error", level++);
  switch (self->discriminant) {
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_system_error", level--);
}
ulong fd_system_error_size(fd_system_error_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  }
  return size;
}

int fd_system_error_inner_encode(fd_system_error_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  return FD_BINCODE_SUCCESS;
}
int fd_system_error_encode(fd_system_error_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_system_error_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_stake_authorized_decode(fd_stake_authorized_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_authorized_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_authorized_new(self);
  fd_stake_authorized_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_authorized_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_authorized_decode_unsafe(fd_stake_authorized_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->staker, ctx);
  fd_pubkey_decode_unsafe(&self->withdrawer, ctx);
}
int fd_stake_authorized_decode_offsets(fd_stake_authorized_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->staker_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->withdrawer_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_authorized_new(fd_stake_authorized_t* self) {
  fd_memset(self, 0, sizeof(fd_stake_authorized_t));
  fd_pubkey_new(&self->staker);
  fd_pubkey_new(&self->withdrawer);
}
void fd_stake_authorized_destroy(fd_stake_authorized_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->staker, ctx);
  fd_pubkey_destroy(&self->withdrawer, ctx);
}

ulong fd_stake_authorized_footprint( void ){ return FD_STAKE_AUTHORIZED_FOOTPRINT; }
ulong fd_stake_authorized_align( void ){ return FD_STAKE_AUTHORIZED_ALIGN; }

void fd_stake_authorized_walk(void * w, fd_stake_authorized_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_authorized", level++);
  fd_pubkey_walk(w, &self->staker, fun, "staker", level);
  fd_pubkey_walk(w, &self->withdrawer, fun, "withdrawer", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_authorized", level--);
}
ulong fd_stake_authorized_size(fd_stake_authorized_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->staker);
  size += fd_pubkey_size(&self->withdrawer);
  return size;
}

int fd_stake_authorized_encode(fd_stake_authorized_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->staker, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->withdrawer, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_lockup_decode(fd_stake_lockup_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_lockup_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_lockup_new(self);
  fd_stake_lockup_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_lockup_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_lockup_decode_unsafe(fd_stake_lockup_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe((ulong *) &self->unix_timestamp, ctx);
  fd_bincode_uint64_decode_unsafe(&self->epoch, ctx);
  fd_pubkey_decode_unsafe(&self->custodian, ctx);
}
int fd_stake_lockup_decode_offsets(fd_stake_lockup_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->unix_timestamp_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->epoch_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->custodian_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_lockup_new(fd_stake_lockup_t* self) {
  fd_memset(self, 0, sizeof(fd_stake_lockup_t));
  fd_pubkey_new(&self->custodian);
}
void fd_stake_lockup_destroy(fd_stake_lockup_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->custodian, ctx);
}

ulong fd_stake_lockup_footprint( void ){ return FD_STAKE_LOCKUP_FOOTPRINT; }
ulong fd_stake_lockup_align( void ){ return FD_STAKE_LOCKUP_ALIGN; }

void fd_stake_lockup_walk(void * w, fd_stake_lockup_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_lockup", level++);
  fun( w, &self->unix_timestamp, "unix_timestamp", FD_FLAMENCO_TYPE_SLONG,   "long",      level );
  fun( w, &self->epoch, "epoch", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_pubkey_walk(w, &self->custodian, fun, "custodian", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_lockup", level--);
}
ulong fd_stake_lockup_size(fd_stake_lockup_t const * self) {
  ulong size = 0;
  size += sizeof(long);
  size += sizeof(ulong);
  size += fd_pubkey_size(&self->custodian);
  return size;
}

int fd_stake_lockup_encode(fd_stake_lockup_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode( (ulong)self->unix_timestamp, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->epoch, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->custodian, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_instruction_initialize_decode(fd_stake_instruction_initialize_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_instruction_initialize_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_instruction_initialize_new(self);
  fd_stake_instruction_initialize_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_instruction_initialize_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_stake_authorized_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_lockup_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_instruction_initialize_decode_unsafe(fd_stake_instruction_initialize_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_stake_authorized_decode_unsafe(&self->authorized, ctx);
  fd_stake_lockup_decode_unsafe(&self->lockup, ctx);
}
int fd_stake_instruction_initialize_decode_offsets(fd_stake_instruction_initialize_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->authorized_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_stake_authorized_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->lockup_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_stake_lockup_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_instruction_initialize_new(fd_stake_instruction_initialize_t* self) {
  fd_memset(self, 0, sizeof(fd_stake_instruction_initialize_t));
  fd_stake_authorized_new(&self->authorized);
  fd_stake_lockup_new(&self->lockup);
}
void fd_stake_instruction_initialize_destroy(fd_stake_instruction_initialize_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stake_authorized_destroy(&self->authorized, ctx);
  fd_stake_lockup_destroy(&self->lockup, ctx);
}

ulong fd_stake_instruction_initialize_footprint( void ){ return FD_STAKE_INSTRUCTION_INITIALIZE_FOOTPRINT; }
ulong fd_stake_instruction_initialize_align( void ){ return FD_STAKE_INSTRUCTION_INITIALIZE_ALIGN; }

void fd_stake_instruction_initialize_walk(void * w, fd_stake_instruction_initialize_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_instruction_initialize", level++);
  fd_stake_authorized_walk(w, &self->authorized, fun, "authorized", level);
  fd_stake_lockup_walk(w, &self->lockup, fun, "lockup", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_instruction_initialize", level--);
}
ulong fd_stake_instruction_initialize_size(fd_stake_instruction_initialize_t const * self) {
  ulong size = 0;
  size += fd_stake_authorized_size(&self->authorized);
  size += fd_stake_lockup_size(&self->lockup);
  return size;
}

int fd_stake_instruction_initialize_encode(fd_stake_instruction_initialize_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_stake_authorized_encode(&self->authorized, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_lockup_encode(&self->lockup, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_lockup_custodian_args_decode(fd_stake_lockup_custodian_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_lockup_custodian_args_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_lockup_custodian_args_new(self);
  fd_stake_lockup_custodian_args_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_lockup_custodian_args_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_stake_lockup_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_sol_sysvar_clock_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_pubkey_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_stake_lockup_custodian_args_decode_unsafe(fd_stake_lockup_custodian_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_stake_lockup_decode_unsafe(&self->lockup, ctx);
  fd_sol_sysvar_clock_decode_unsafe(&self->clock, ctx);
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      self->custodian = (fd_pubkey_t*)fd_valloc_malloc( ctx->valloc, FD_PUBKEY_ALIGN, FD_PUBKEY_FOOTPRINT );
      fd_pubkey_new( self->custodian );
      fd_pubkey_decode_unsafe( self->custodian, ctx );
    } else
      self->custodian = NULL;
  }
}
int fd_stake_lockup_custodian_args_decode_offsets(fd_stake_lockup_custodian_args_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->lockup_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_stake_lockup_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->clock_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_sol_sysvar_clock_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->custodian_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_pubkey_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_stake_lockup_custodian_args_new(fd_stake_lockup_custodian_args_t* self) {
  fd_memset(self, 0, sizeof(fd_stake_lockup_custodian_args_t));
  fd_stake_lockup_new(&self->lockup);
  fd_sol_sysvar_clock_new(&self->clock);
}
void fd_stake_lockup_custodian_args_destroy(fd_stake_lockup_custodian_args_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stake_lockup_destroy(&self->lockup, ctx);
  fd_sol_sysvar_clock_destroy(&self->clock, ctx);
  if( NULL != self->custodian ) {
    fd_pubkey_destroy( self->custodian, ctx );
    fd_valloc_free( ctx->valloc, self->custodian );
    self->custodian = NULL;
  }
}

ulong fd_stake_lockup_custodian_args_footprint( void ){ return FD_STAKE_LOCKUP_CUSTODIAN_ARGS_FOOTPRINT; }
ulong fd_stake_lockup_custodian_args_align( void ){ return FD_STAKE_LOCKUP_CUSTODIAN_ARGS_ALIGN; }

void fd_stake_lockup_custodian_args_walk(void * w, fd_stake_lockup_custodian_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_lockup_custodian_args", level++);
  fd_stake_lockup_walk(w, &self->lockup, fun, "lockup", level);
  fd_sol_sysvar_clock_walk(w, &self->clock, fun, "clock", level);
  if( !self->custodian ) {
    fun( w, NULL, "custodian", FD_FLAMENCO_TYPE_NULL, "pubkey", level );
  } else {
    fd_pubkey_walk( w, self->custodian, fun, "custodian", level );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_lockup_custodian_args", level--);
}
ulong fd_stake_lockup_custodian_args_size(fd_stake_lockup_custodian_args_t const * self) {
  ulong size = 0;
  size += fd_stake_lockup_size(&self->lockup);
  size += fd_sol_sysvar_clock_size(&self->clock);
  size += sizeof(char);
  if( NULL !=  self->custodian ) {
    size += fd_pubkey_size( self->custodian );
  }
  return size;
}

int fd_stake_lockup_custodian_args_encode(fd_stake_lockup_custodian_args_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_stake_lockup_encode(&self->lockup, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_sol_sysvar_clock_encode(&self->clock, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if( self->custodian != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_pubkey_encode( self->custodian, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_stake_authorize_is_staker(fd_stake_authorize_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_stake_authorize_is_withdrawer(fd_stake_authorize_t const * self) {
  return self->discriminant == 1;
}
void fd_stake_authorize_inner_new(fd_stake_authorize_inner_t* self, uint discriminant);
int fd_stake_authorize_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_stake_authorize_inner_decode_unsafe(fd_stake_authorize_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    break;
  }
  }
}
int fd_stake_authorize_decode(fd_stake_authorize_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_authorize_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_authorize_new(self);
  fd_stake_authorize_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_authorize_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_stake_authorize_inner_decode_preflight(discriminant, ctx);
}
void fd_stake_authorize_decode_unsafe(fd_stake_authorize_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_stake_authorize_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_stake_authorize_inner_new(fd_stake_authorize_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_stake_authorize_new_disc(fd_stake_authorize_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_stake_authorize_inner_new(&self->inner, self->discriminant);
}
void fd_stake_authorize_new(fd_stake_authorize_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_stake_authorize_new_disc(self, UINT_MAX);
}
void fd_stake_authorize_inner_destroy(fd_stake_authorize_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_stake_authorize_destroy(fd_stake_authorize_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stake_authorize_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_stake_authorize_footprint( void ){ return FD_STAKE_AUTHORIZE_FOOTPRINT; }
ulong fd_stake_authorize_align( void ){ return FD_STAKE_AUTHORIZE_ALIGN; }

void fd_stake_authorize_walk(void * w, fd_stake_authorize_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_authorize", level++);
  switch (self->discriminant) {
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_authorize", level--);
}
ulong fd_stake_authorize_size(fd_stake_authorize_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  }
  return size;
}

int fd_stake_authorize_inner_encode(fd_stake_authorize_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  return FD_BINCODE_SUCCESS;
}
int fd_stake_authorize_encode(fd_stake_authorize_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_stake_authorize_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_stake_instruction_authorize_decode(fd_stake_instruction_authorize_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_instruction_authorize_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_instruction_authorize_new(self);
  fd_stake_instruction_authorize_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_instruction_authorize_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_authorize_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_instruction_authorize_decode_unsafe(fd_stake_instruction_authorize_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->pubkey, ctx);
  fd_stake_authorize_decode_unsafe(&self->stake_authorize, ctx);
}
int fd_stake_instruction_authorize_decode_offsets(fd_stake_instruction_authorize_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->stake_authorize_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_stake_authorize_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_instruction_authorize_new(fd_stake_instruction_authorize_t* self) {
  fd_memset(self, 0, sizeof(fd_stake_instruction_authorize_t));
  fd_pubkey_new(&self->pubkey);
  fd_stake_authorize_new(&self->stake_authorize);
}
void fd_stake_instruction_authorize_destroy(fd_stake_instruction_authorize_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->pubkey, ctx);
  fd_stake_authorize_destroy(&self->stake_authorize, ctx);
}

ulong fd_stake_instruction_authorize_footprint( void ){ return FD_STAKE_INSTRUCTION_AUTHORIZE_FOOTPRINT; }
ulong fd_stake_instruction_authorize_align( void ){ return FD_STAKE_INSTRUCTION_AUTHORIZE_ALIGN; }

void fd_stake_instruction_authorize_walk(void * w, fd_stake_instruction_authorize_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_instruction_authorize", level++);
  fd_pubkey_walk(w, &self->pubkey, fun, "pubkey", level);
  fd_stake_authorize_walk(w, &self->stake_authorize, fun, "stake_authorize", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_instruction_authorize", level--);
}
ulong fd_stake_instruction_authorize_size(fd_stake_instruction_authorize_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->pubkey);
  size += fd_stake_authorize_size(&self->stake_authorize);
  return size;
}

int fd_stake_instruction_authorize_encode(fd_stake_instruction_authorize_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_authorize_encode(&self->stake_authorize, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_authorize_with_seed_args_decode(fd_authorize_with_seed_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_authorize_with_seed_args_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_authorize_with_seed_args_new(self);
  fd_authorize_with_seed_args_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_authorize_with_seed_args_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_authorize_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong authority_seed_len;
  err = fd_bincode_uint64_decode(&authority_seed_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (authority_seed_len != 0) {
    err = fd_bincode_bytes_decode_preflight(authority_seed_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_authorize_with_seed_args_decode_unsafe(fd_authorize_with_seed_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->new_authorized_pubkey, ctx);
  fd_stake_authorize_decode_unsafe(&self->stake_authorize, ctx);
  fd_bincode_uint64_decode_unsafe(&self->authority_seed_len, ctx);
  if (self->authority_seed_len != 0) {
    self->authority_seed = fd_valloc_malloc( ctx->valloc, 8UL, self->authority_seed_len );
    fd_bincode_bytes_decode_unsafe(self->authority_seed, self->authority_seed_len, ctx);
  } else
    self->authority_seed = NULL;
  fd_pubkey_decode_unsafe(&self->authority_owner, ctx);
}
int fd_authorize_with_seed_args_decode_offsets(fd_authorize_with_seed_args_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->new_authorized_pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->stake_authorize_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_stake_authorize_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->authority_seed_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong authority_seed_len;
  err = fd_bincode_uint64_decode(&authority_seed_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (authority_seed_len != 0) {
    err = fd_bincode_bytes_decode_preflight(authority_seed_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  self->authority_owner_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_authorize_with_seed_args_new(fd_authorize_with_seed_args_t* self) {
  fd_memset(self, 0, sizeof(fd_authorize_with_seed_args_t));
  fd_pubkey_new(&self->new_authorized_pubkey);
  fd_stake_authorize_new(&self->stake_authorize);
  fd_pubkey_new(&self->authority_owner);
}
void fd_authorize_with_seed_args_destroy(fd_authorize_with_seed_args_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->new_authorized_pubkey, ctx);
  fd_stake_authorize_destroy(&self->stake_authorize, ctx);
  if (NULL != self->authority_seed) {
    fd_valloc_free( ctx->valloc, self->authority_seed );
    self->authority_seed = NULL;
  }
  fd_pubkey_destroy(&self->authority_owner, ctx);
}

ulong fd_authorize_with_seed_args_footprint( void ){ return FD_AUTHORIZE_WITH_SEED_ARGS_FOOTPRINT; }
ulong fd_authorize_with_seed_args_align( void ){ return FD_AUTHORIZE_WITH_SEED_ARGS_ALIGN; }

void fd_authorize_with_seed_args_walk(void * w, fd_authorize_with_seed_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_authorize_with_seed_args", level++);
  fd_pubkey_walk(w, &self->new_authorized_pubkey, fun, "new_authorized_pubkey", level);
  fd_stake_authorize_walk(w, &self->stake_authorize, fun, "stake_authorize", level);
  fun(w, self->authority_seed, "authority_seed", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );
  fd_pubkey_walk(w, &self->authority_owner, fun, "authority_owner", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_authorize_with_seed_args", level--);
}
ulong fd_authorize_with_seed_args_size(fd_authorize_with_seed_args_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->new_authorized_pubkey);
  size += fd_stake_authorize_size(&self->stake_authorize);
  do {
    size += sizeof(ulong);
    size += self->authority_seed_len;
  } while(0);
  size += fd_pubkey_size(&self->authority_owner);
  return size;
}

int fd_authorize_with_seed_args_encode(fd_authorize_with_seed_args_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->new_authorized_pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_authorize_encode(&self->stake_authorize, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->authority_seed_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->authority_seed_len != 0) {
    err = fd_bincode_bytes_encode(self->authority_seed, self->authority_seed_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_pubkey_encode(&self->authority_owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_authorize_checked_with_seed_args_decode(fd_authorize_checked_with_seed_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_authorize_checked_with_seed_args_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_authorize_checked_with_seed_args_new(self);
  fd_authorize_checked_with_seed_args_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_authorize_checked_with_seed_args_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_stake_authorize_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong authority_seed_len;
  err = fd_bincode_uint64_decode(&authority_seed_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (authority_seed_len != 0) {
    err = fd_bincode_bytes_decode_preflight(authority_seed_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_authorize_checked_with_seed_args_decode_unsafe(fd_authorize_checked_with_seed_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_stake_authorize_decode_unsafe(&self->stake_authorize, ctx);
  fd_bincode_uint64_decode_unsafe(&self->authority_seed_len, ctx);
  if (self->authority_seed_len != 0) {
    self->authority_seed = fd_valloc_malloc( ctx->valloc, 8UL, self->authority_seed_len );
    fd_bincode_bytes_decode_unsafe(self->authority_seed, self->authority_seed_len, ctx);
  } else
    self->authority_seed = NULL;
  fd_pubkey_decode_unsafe(&self->authority_owner, ctx);
}
int fd_authorize_checked_with_seed_args_decode_offsets(fd_authorize_checked_with_seed_args_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->stake_authorize_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_stake_authorize_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->authority_seed_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong authority_seed_len;
  err = fd_bincode_uint64_decode(&authority_seed_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (authority_seed_len != 0) {
    err = fd_bincode_bytes_decode_preflight(authority_seed_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  self->authority_owner_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_authorize_checked_with_seed_args_new(fd_authorize_checked_with_seed_args_t* self) {
  fd_memset(self, 0, sizeof(fd_authorize_checked_with_seed_args_t));
  fd_stake_authorize_new(&self->stake_authorize);
  fd_pubkey_new(&self->authority_owner);
}
void fd_authorize_checked_with_seed_args_destroy(fd_authorize_checked_with_seed_args_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stake_authorize_destroy(&self->stake_authorize, ctx);
  if (NULL != self->authority_seed) {
    fd_valloc_free( ctx->valloc, self->authority_seed );
    self->authority_seed = NULL;
  }
  fd_pubkey_destroy(&self->authority_owner, ctx);
}

ulong fd_authorize_checked_with_seed_args_footprint( void ){ return FD_AUTHORIZE_CHECKED_WITH_SEED_ARGS_FOOTPRINT; }
ulong fd_authorize_checked_with_seed_args_align( void ){ return FD_AUTHORIZE_CHECKED_WITH_SEED_ARGS_ALIGN; }

void fd_authorize_checked_with_seed_args_walk(void * w, fd_authorize_checked_with_seed_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_authorize_checked_with_seed_args", level++);
  fd_stake_authorize_walk(w, &self->stake_authorize, fun, "stake_authorize", level);
  fun(w, self->authority_seed, "authority_seed", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );
  fd_pubkey_walk(w, &self->authority_owner, fun, "authority_owner", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_authorize_checked_with_seed_args", level--);
}
ulong fd_authorize_checked_with_seed_args_size(fd_authorize_checked_with_seed_args_t const * self) {
  ulong size = 0;
  size += fd_stake_authorize_size(&self->stake_authorize);
  do {
    size += sizeof(ulong);
    size += self->authority_seed_len;
  } while(0);
  size += fd_pubkey_size(&self->authority_owner);
  return size;
}

int fd_authorize_checked_with_seed_args_encode(fd_authorize_checked_with_seed_args_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_stake_authorize_encode(&self->stake_authorize, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->authority_seed_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->authority_seed_len != 0) {
    err = fd_bincode_bytes_encode(self->authority_seed, self->authority_seed_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  err = fd_pubkey_encode(&self->authority_owner, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_lockup_checked_args_decode(fd_lockup_checked_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_lockup_checked_args_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_lockup_checked_args_new(self);
  fd_lockup_checked_args_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_lockup_checked_args_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_lockup_checked_args_decode_unsafe(fd_lockup_checked_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      self->unix_timestamp = fd_valloc_malloc( ctx->valloc, 8, sizeof(ulong) );
      fd_bincode_uint64_decode_unsafe( self->unix_timestamp, ctx );
    } else
      self->unix_timestamp = NULL;
  }
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      self->epoch = fd_valloc_malloc( ctx->valloc, 8, sizeof(ulong) );
      fd_bincode_uint64_decode_unsafe( self->epoch, ctx );
    } else
      self->epoch = NULL;
  }
}
int fd_lockup_checked_args_decode_offsets(fd_lockup_checked_args_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->unix_timestamp_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->epoch_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_lockup_checked_args_new(fd_lockup_checked_args_t* self) {
  fd_memset(self, 0, sizeof(fd_lockup_checked_args_t));
}
void fd_lockup_checked_args_destroy(fd_lockup_checked_args_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if( NULL != self->unix_timestamp ) {
    fd_valloc_free( ctx->valloc, self->unix_timestamp );
    self->unix_timestamp = NULL;
  }
  if( NULL != self->epoch ) {
    fd_valloc_free( ctx->valloc, self->epoch );
    self->epoch = NULL;
  }
}

ulong fd_lockup_checked_args_footprint( void ){ return FD_LOCKUP_CHECKED_ARGS_FOOTPRINT; }
ulong fd_lockup_checked_args_align( void ){ return FD_LOCKUP_CHECKED_ARGS_ALIGN; }

void fd_lockup_checked_args_walk(void * w, fd_lockup_checked_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_lockup_checked_args", level++);
  if( !self->unix_timestamp ) {
    fun( w, NULL, "unix_timestamp", FD_FLAMENCO_TYPE_NULL, "ulong", level );
  } else {
    fun( w, self->unix_timestamp, "unix_timestamp", FD_FLAMENCO_TYPE_ULONG, "ulong", level );
  }
  if( !self->epoch ) {
    fun( w, NULL, "epoch", FD_FLAMENCO_TYPE_NULL, "ulong", level );
  } else {
    fun( w, self->epoch, "epoch", FD_FLAMENCO_TYPE_ULONG, "ulong", level );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_lockup_checked_args", level--);
}
ulong fd_lockup_checked_args_size(fd_lockup_checked_args_t const * self) {
  ulong size = 0;
  size += sizeof(char);
  if( NULL !=  self->unix_timestamp ) {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if( NULL !=  self->epoch ) {
    size += sizeof(ulong);
  }
  return size;
}

int fd_lockup_checked_args_encode(fd_lockup_checked_args_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if( self->unix_timestamp != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_bincode_uint64_encode( self->unix_timestamp[0], ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
  }
  if( self->epoch != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_bincode_uint64_encode( self->epoch[0], ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_lockup_args_decode(fd_lockup_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_lockup_args_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_lockup_args_new(self);
  fd_lockup_args_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_lockup_args_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_pubkey_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_lockup_args_decode_unsafe(fd_lockup_args_t* self, fd_bincode_decode_ctx_t * ctx) {
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      self->unix_timestamp = fd_valloc_malloc( ctx->valloc, 8, sizeof(ulong) );
      fd_bincode_uint64_decode_unsafe( self->unix_timestamp, ctx );
    } else
      self->unix_timestamp = NULL;
  }
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      self->epoch = fd_valloc_malloc( ctx->valloc, 8, sizeof(ulong) );
      fd_bincode_uint64_decode_unsafe( self->epoch, ctx );
    } else
      self->epoch = NULL;
  }
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      self->custodian = (fd_pubkey_t*)fd_valloc_malloc( ctx->valloc, FD_PUBKEY_ALIGN, FD_PUBKEY_FOOTPRINT );
      fd_pubkey_new( self->custodian );
      fd_pubkey_decode_unsafe( self->custodian, ctx );
    } else
      self->custodian = NULL;
  }
}
int fd_lockup_args_decode_offsets(fd_lockup_args_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->unix_timestamp_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->epoch_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->custodian_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_pubkey_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_lockup_args_new(fd_lockup_args_t* self) {
  fd_memset(self, 0, sizeof(fd_lockup_args_t));
}
void fd_lockup_args_destroy(fd_lockup_args_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if( NULL != self->unix_timestamp ) {
    fd_valloc_free( ctx->valloc, self->unix_timestamp );
    self->unix_timestamp = NULL;
  }
  if( NULL != self->epoch ) {
    fd_valloc_free( ctx->valloc, self->epoch );
    self->epoch = NULL;
  }
  if( NULL != self->custodian ) {
    fd_pubkey_destroy( self->custodian, ctx );
    fd_valloc_free( ctx->valloc, self->custodian );
    self->custodian = NULL;
  }
}

ulong fd_lockup_args_footprint( void ){ return FD_LOCKUP_ARGS_FOOTPRINT; }
ulong fd_lockup_args_align( void ){ return FD_LOCKUP_ARGS_ALIGN; }

void fd_lockup_args_walk(void * w, fd_lockup_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_lockup_args", level++);
  if( !self->unix_timestamp ) {
    fun( w, NULL, "unix_timestamp", FD_FLAMENCO_TYPE_NULL, "ulong", level );
  } else {
    fun( w, self->unix_timestamp, "unix_timestamp", FD_FLAMENCO_TYPE_ULONG, "ulong", level );
  }
  if( !self->epoch ) {
    fun( w, NULL, "epoch", FD_FLAMENCO_TYPE_NULL, "ulong", level );
  } else {
    fun( w, self->epoch, "epoch", FD_FLAMENCO_TYPE_ULONG, "ulong", level );
  }
  if( !self->custodian ) {
    fun( w, NULL, "custodian", FD_FLAMENCO_TYPE_NULL, "pubkey", level );
  } else {
    fd_pubkey_walk( w, self->custodian, fun, "custodian", level );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_lockup_args", level--);
}
ulong fd_lockup_args_size(fd_lockup_args_t const * self) {
  ulong size = 0;
  size += sizeof(char);
  if( NULL !=  self->unix_timestamp ) {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if( NULL !=  self->epoch ) {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if( NULL !=  self->custodian ) {
    size += fd_pubkey_size( self->custodian );
  }
  return size;
}

int fd_lockup_args_encode(fd_lockup_args_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if( self->unix_timestamp != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_bincode_uint64_encode( self->unix_timestamp[0], ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
  }
  if( self->epoch != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_bincode_uint64_encode( self->epoch[0], ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
  }
  if( self->custodian != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_pubkey_encode( self->custodian, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_stake_instruction_is_initialize(fd_stake_instruction_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_stake_instruction_is_authorize(fd_stake_instruction_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_stake_instruction_is_delegate_stake(fd_stake_instruction_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_stake_instruction_is_split(fd_stake_instruction_t const * self) {
  return self->discriminant == 3;
}
FD_FN_PURE uchar fd_stake_instruction_is_withdraw(fd_stake_instruction_t const * self) {
  return self->discriminant == 4;
}
FD_FN_PURE uchar fd_stake_instruction_is_deactivate(fd_stake_instruction_t const * self) {
  return self->discriminant == 5;
}
FD_FN_PURE uchar fd_stake_instruction_is_set_lockup(fd_stake_instruction_t const * self) {
  return self->discriminant == 6;
}
FD_FN_PURE uchar fd_stake_instruction_is_merge(fd_stake_instruction_t const * self) {
  return self->discriminant == 7;
}
FD_FN_PURE uchar fd_stake_instruction_is_authorize_with_seed(fd_stake_instruction_t const * self) {
  return self->discriminant == 8;
}
FD_FN_PURE uchar fd_stake_instruction_is_initialize_checked(fd_stake_instruction_t const * self) {
  return self->discriminant == 9;
}
FD_FN_PURE uchar fd_stake_instruction_is_authorize_checked(fd_stake_instruction_t const * self) {
  return self->discriminant == 10;
}
FD_FN_PURE uchar fd_stake_instruction_is_authorize_checked_with_seed(fd_stake_instruction_t const * self) {
  return self->discriminant == 11;
}
FD_FN_PURE uchar fd_stake_instruction_is_set_lockup_checked(fd_stake_instruction_t const * self) {
  return self->discriminant == 12;
}
FD_FN_PURE uchar fd_stake_instruction_is_get_minimum_delegation(fd_stake_instruction_t const * self) {
  return self->discriminant == 13;
}
FD_FN_PURE uchar fd_stake_instruction_is_deactivate_delinquent(fd_stake_instruction_t const * self) {
  return self->discriminant == 14;
}
FD_FN_PURE uchar fd_stake_instruction_is_redelegate(fd_stake_instruction_t const * self) {
  return self->discriminant == 15;
}
void fd_stake_instruction_inner_new(fd_stake_instruction_inner_t* self, uint discriminant);
int fd_stake_instruction_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_stake_instruction_initialize_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_stake_instruction_authorize_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    err = fd_bincode_uint64_decode_preflight(ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    err = fd_bincode_uint64_decode_preflight(ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 5: {
    return FD_BINCODE_SUCCESS;
  }
  case 6: {
    err = fd_lockup_args_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 7: {
    return FD_BINCODE_SUCCESS;
  }
  case 8: {
    err = fd_authorize_with_seed_args_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 9: {
    return FD_BINCODE_SUCCESS;
  }
  case 10: {
    err = fd_stake_authorize_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 11: {
    err = fd_authorize_checked_with_seed_args_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 12: {
    err = fd_lockup_checked_args_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 13: {
    return FD_BINCODE_SUCCESS;
  }
  case 14: {
    return FD_BINCODE_SUCCESS;
  }
  case 15: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_stake_instruction_inner_decode_unsafe(fd_stake_instruction_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_stake_instruction_initialize_decode_unsafe(&self->initialize, ctx);
    break;
  }
  case 1: {
    fd_stake_instruction_authorize_decode_unsafe(&self->authorize, ctx);
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    fd_bincode_uint64_decode_unsafe(&self->split, ctx);
    break;
  }
  case 4: {
    fd_bincode_uint64_decode_unsafe(&self->withdraw, ctx);
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    fd_lockup_args_decode_unsafe(&self->set_lockup, ctx);
    break;
  }
  case 7: {
    break;
  }
  case 8: {
    fd_authorize_with_seed_args_decode_unsafe(&self->authorize_with_seed, ctx);
    break;
  }
  case 9: {
    break;
  }
  case 10: {
    fd_stake_authorize_decode_unsafe(&self->authorize_checked, ctx);
    break;
  }
  case 11: {
    fd_authorize_checked_with_seed_args_decode_unsafe(&self->authorize_checked_with_seed, ctx);
    break;
  }
  case 12: {
    fd_lockup_checked_args_decode_unsafe(&self->set_lockup_checked, ctx);
    break;
  }
  case 13: {
    break;
  }
  case 14: {
    break;
  }
  case 15: {
    break;
  }
  }
}
int fd_stake_instruction_decode(fd_stake_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_instruction_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_instruction_new(self);
  fd_stake_instruction_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_instruction_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_stake_instruction_inner_decode_preflight(discriminant, ctx);
}
void fd_stake_instruction_decode_unsafe(fd_stake_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_stake_instruction_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_stake_instruction_inner_new(fd_stake_instruction_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_stake_instruction_initialize_new(&self->initialize);
    break;
  }
  case 1: {
    fd_stake_instruction_authorize_new(&self->authorize);
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    fd_lockup_args_new(&self->set_lockup);
    break;
  }
  case 7: {
    break;
  }
  case 8: {
    fd_authorize_with_seed_args_new(&self->authorize_with_seed);
    break;
  }
  case 9: {
    break;
  }
  case 10: {
    fd_stake_authorize_new(&self->authorize_checked);
    break;
  }
  case 11: {
    fd_authorize_checked_with_seed_args_new(&self->authorize_checked_with_seed);
    break;
  }
  case 12: {
    fd_lockup_checked_args_new(&self->set_lockup_checked);
    break;
  }
  case 13: {
    break;
  }
  case 14: {
    break;
  }
  case 15: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_stake_instruction_new_disc(fd_stake_instruction_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_stake_instruction_inner_new(&self->inner, self->discriminant);
}
void fd_stake_instruction_new(fd_stake_instruction_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_stake_instruction_new_disc(self, UINT_MAX);
}
void fd_stake_instruction_inner_destroy(fd_stake_instruction_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_stake_instruction_initialize_destroy(&self->initialize, ctx);
    break;
  }
  case 1: {
    fd_stake_instruction_authorize_destroy(&self->authorize, ctx);
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  case 6: {
    fd_lockup_args_destroy(&self->set_lockup, ctx);
    break;
  }
  case 8: {
    fd_authorize_with_seed_args_destroy(&self->authorize_with_seed, ctx);
    break;
  }
  case 10: {
    fd_stake_authorize_destroy(&self->authorize_checked, ctx);
    break;
  }
  case 11: {
    fd_authorize_checked_with_seed_args_destroy(&self->authorize_checked_with_seed, ctx);
    break;
  }
  case 12: {
    fd_lockup_checked_args_destroy(&self->set_lockup_checked, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_stake_instruction_destroy(fd_stake_instruction_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stake_instruction_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_stake_instruction_footprint( void ){ return FD_STAKE_INSTRUCTION_FOOTPRINT; }
ulong fd_stake_instruction_align( void ){ return FD_STAKE_INSTRUCTION_ALIGN; }

void fd_stake_instruction_walk(void * w, fd_stake_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_instruction", level++);
  switch (self->discriminant) {
  case 0: {
    fd_stake_instruction_initialize_walk(w, &self->inner.initialize, fun, "initialize", level);
    break;
  }
  case 1: {
    fd_stake_instruction_authorize_walk(w, &self->inner.authorize, fun, "authorize", level);
    break;
  }
  case 3: {
  fun( w, &self->inner.split, "split", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
    break;
  }
  case 4: {
  fun( w, &self->inner.withdraw, "withdraw", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
    break;
  }
  case 6: {
    fd_lockup_args_walk(w, &self->inner.set_lockup, fun, "set_lockup", level);
    break;
  }
  case 8: {
    fd_authorize_with_seed_args_walk(w, &self->inner.authorize_with_seed, fun, "authorize_with_seed", level);
    break;
  }
  case 10: {
    fd_stake_authorize_walk(w, &self->inner.authorize_checked, fun, "authorize_checked", level);
    break;
  }
  case 11: {
    fd_authorize_checked_with_seed_args_walk(w, &self->inner.authorize_checked_with_seed, fun, "authorize_checked_with_seed", level);
    break;
  }
  case 12: {
    fd_lockup_checked_args_walk(w, &self->inner.set_lockup_checked, fun, "set_lockup_checked", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_instruction", level--);
}
ulong fd_stake_instruction_size(fd_stake_instruction_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_stake_instruction_initialize_size(&self->inner.initialize);
    break;
  }
  case 1: {
    size += fd_stake_instruction_authorize_size(&self->inner.authorize);
    break;
  }
  case 3: {
    size += sizeof(ulong);
    break;
  }
  case 4: {
    size += sizeof(ulong);
    break;
  }
  case 6: {
    size += fd_lockup_args_size(&self->inner.set_lockup);
    break;
  }
  case 8: {
    size += fd_authorize_with_seed_args_size(&self->inner.authorize_with_seed);
    break;
  }
  case 10: {
    size += fd_stake_authorize_size(&self->inner.authorize_checked);
    break;
  }
  case 11: {
    size += fd_authorize_checked_with_seed_args_size(&self->inner.authorize_checked_with_seed);
    break;
  }
  case 12: {
    size += fd_lockup_checked_args_size(&self->inner.set_lockup_checked);
    break;
  }
  }
  return size;
}

int fd_stake_instruction_inner_encode(fd_stake_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_stake_instruction_initialize_encode(&self->initialize, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 1: {
    err = fd_stake_instruction_authorize_encode(&self->authorize, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 3: {
    err = fd_bincode_uint64_encode(self->split, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 4: {
    err = fd_bincode_uint64_encode(self->withdraw, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 6: {
    err = fd_lockup_args_encode(&self->set_lockup, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 8: {
    err = fd_authorize_with_seed_args_encode(&self->authorize_with_seed, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 10: {
    err = fd_stake_authorize_encode(&self->authorize_checked, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 11: {
    err = fd_authorize_checked_with_seed_args_encode(&self->authorize_checked_with_seed, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 12: {
    err = fd_lockup_checked_args_encode(&self->set_lockup_checked, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_stake_instruction_encode(fd_stake_instruction_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_stake_instruction_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_stake_meta_decode(fd_stake_meta_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_meta_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_meta_new(self);
  fd_stake_meta_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_meta_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_stake_authorized_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_lockup_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_meta_decode_unsafe(fd_stake_meta_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->rent_exempt_reserve, ctx);
  fd_stake_authorized_decode_unsafe(&self->authorized, ctx);
  fd_stake_lockup_decode_unsafe(&self->lockup, ctx);
}
int fd_stake_meta_decode_offsets(fd_stake_meta_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->rent_exempt_reserve_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->authorized_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_stake_authorized_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->lockup_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_stake_lockup_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_meta_new(fd_stake_meta_t* self) {
  fd_memset(self, 0, sizeof(fd_stake_meta_t));
  fd_stake_authorized_new(&self->authorized);
  fd_stake_lockup_new(&self->lockup);
}
void fd_stake_meta_destroy(fd_stake_meta_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stake_authorized_destroy(&self->authorized, ctx);
  fd_stake_lockup_destroy(&self->lockup, ctx);
}

ulong fd_stake_meta_footprint( void ){ return FD_STAKE_META_FOOTPRINT; }
ulong fd_stake_meta_align( void ){ return FD_STAKE_META_ALIGN; }

void fd_stake_meta_walk(void * w, fd_stake_meta_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_meta", level++);
  fun( w, &self->rent_exempt_reserve, "rent_exempt_reserve", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_stake_authorized_walk(w, &self->authorized, fun, "authorized", level);
  fd_stake_lockup_walk(w, &self->lockup, fun, "lockup", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_meta", level--);
}
ulong fd_stake_meta_size(fd_stake_meta_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_stake_authorized_size(&self->authorized);
  size += fd_stake_lockup_size(&self->lockup);
  return size;
}

int fd_stake_meta_encode(fd_stake_meta_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->rent_exempt_reserve, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_authorized_encode(&self->authorized, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_lockup_encode(&self->lockup, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_decode(fd_stake_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_new(self);
  fd_stake_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_delegation_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_decode_unsafe(fd_stake_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_delegation_decode_unsafe(&self->delegation, ctx);
  fd_bincode_uint64_decode_unsafe(&self->credits_observed, ctx);
}
int fd_stake_decode_offsets(fd_stake_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->delegation_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_delegation_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->credits_observed_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_new(fd_stake_t* self) {
  fd_memset(self, 0, sizeof(fd_stake_t));
  fd_delegation_new(&self->delegation);
}
void fd_stake_destroy(fd_stake_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_delegation_destroy(&self->delegation, ctx);
}

ulong fd_stake_footprint( void ){ return FD_STAKE_FOOTPRINT; }
ulong fd_stake_align( void ){ return FD_STAKE_ALIGN; }

void fd_stake_walk(void * w, fd_stake_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake", level++);
  fd_delegation_walk(w, &self->delegation, fun, "delegation", level);
  fun( w, &self->credits_observed, "credits_observed", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake", level--);
}
ulong fd_stake_size(fd_stake_t const * self) {
  ulong size = 0;
  size += fd_delegation_size(&self->delegation);
  size += sizeof(ulong);
  return size;
}

int fd_stake_encode(fd_stake_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_delegation_encode(&self->delegation, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->credits_observed, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_flags_decode(fd_stake_flags_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_flags_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_flags_new(self);
  fd_stake_flags_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_flags_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_flags_decode_unsafe(fd_stake_flags_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint8_decode_unsafe(&self->bits, ctx);
}
int fd_stake_flags_decode_offsets(fd_stake_flags_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->bits_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_flags_new(fd_stake_flags_t* self) {
  fd_memset(self, 0, sizeof(fd_stake_flags_t));
}
void fd_stake_flags_destroy(fd_stake_flags_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_stake_flags_footprint( void ){ return FD_STAKE_FLAGS_FOOTPRINT; }
ulong fd_stake_flags_align( void ){ return FD_STAKE_FLAGS_ALIGN; }

void fd_stake_flags_walk(void * w, fd_stake_flags_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_flags", level++);
  fun( w, &self->bits, "bits", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_flags", level--);
}
ulong fd_stake_flags_size(fd_stake_flags_t const * self) {
  ulong size = 0;
  size += sizeof(char);
  return size;
}

int fd_stake_flags_encode(fd_stake_flags_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint8_encode( (uchar)(self->bits), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_state_v2_initialized_decode(fd_stake_state_v2_initialized_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_state_v2_initialized_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_state_v2_initialized_new(self);
  fd_stake_state_v2_initialized_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_state_v2_initialized_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_stake_meta_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_state_v2_initialized_decode_unsafe(fd_stake_state_v2_initialized_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_stake_meta_decode_unsafe(&self->meta, ctx);
}
int fd_stake_state_v2_initialized_decode_offsets(fd_stake_state_v2_initialized_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->meta_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_stake_meta_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_state_v2_initialized_new(fd_stake_state_v2_initialized_t* self) {
  fd_memset(self, 0, sizeof(fd_stake_state_v2_initialized_t));
  fd_stake_meta_new(&self->meta);
}
void fd_stake_state_v2_initialized_destroy(fd_stake_state_v2_initialized_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stake_meta_destroy(&self->meta, ctx);
}

ulong fd_stake_state_v2_initialized_footprint( void ){ return FD_STAKE_STATE_V2_INITIALIZED_FOOTPRINT; }
ulong fd_stake_state_v2_initialized_align( void ){ return FD_STAKE_STATE_V2_INITIALIZED_ALIGN; }

void fd_stake_state_v2_initialized_walk(void * w, fd_stake_state_v2_initialized_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_state_v2_initialized", level++);
  fd_stake_meta_walk(w, &self->meta, fun, "meta", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_state_v2_initialized", level--);
}
ulong fd_stake_state_v2_initialized_size(fd_stake_state_v2_initialized_t const * self) {
  ulong size = 0;
  size += fd_stake_meta_size(&self->meta);
  return size;
}

int fd_stake_state_v2_initialized_encode(fd_stake_state_v2_initialized_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_stake_meta_encode(&self->meta, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_stake_state_v2_stake_decode(fd_stake_state_v2_stake_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_state_v2_stake_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_state_v2_stake_new(self);
  fd_stake_state_v2_stake_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_state_v2_stake_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_stake_meta_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_flags_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_state_v2_stake_decode_unsafe(fd_stake_state_v2_stake_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_stake_meta_decode_unsafe(&self->meta, ctx);
  fd_stake_decode_unsafe(&self->stake, ctx);
  fd_stake_flags_decode_unsafe(&self->stake_flags, ctx);
}
int fd_stake_state_v2_stake_decode_offsets(fd_stake_state_v2_stake_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->meta_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_stake_meta_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->stake_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_stake_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->stake_flags_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_stake_flags_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_stake_state_v2_stake_new(fd_stake_state_v2_stake_t* self) {
  fd_memset(self, 0, sizeof(fd_stake_state_v2_stake_t));
  fd_stake_meta_new(&self->meta);
  fd_stake_new(&self->stake);
  fd_stake_flags_new(&self->stake_flags);
}
void fd_stake_state_v2_stake_destroy(fd_stake_state_v2_stake_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stake_meta_destroy(&self->meta, ctx);
  fd_stake_destroy(&self->stake, ctx);
  fd_stake_flags_destroy(&self->stake_flags, ctx);
}

ulong fd_stake_state_v2_stake_footprint( void ){ return FD_STAKE_STATE_V2_STAKE_FOOTPRINT; }
ulong fd_stake_state_v2_stake_align( void ){ return FD_STAKE_STATE_V2_STAKE_ALIGN; }

void fd_stake_state_v2_stake_walk(void * w, fd_stake_state_v2_stake_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_state_v2_stake", level++);
  fd_stake_meta_walk(w, &self->meta, fun, "meta", level);
  fd_stake_walk(w, &self->stake, fun, "stake", level);
  fd_stake_flags_walk(w, &self->stake_flags, fun, "stake_flags", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_state_v2_stake", level--);
}
ulong fd_stake_state_v2_stake_size(fd_stake_state_v2_stake_t const * self) {
  ulong size = 0;
  size += fd_stake_meta_size(&self->meta);
  size += fd_stake_size(&self->stake);
  size += fd_stake_flags_size(&self->stake_flags);
  return size;
}

int fd_stake_state_v2_stake_encode(fd_stake_state_v2_stake_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_stake_meta_encode(&self->meta, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_encode(&self->stake, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_stake_flags_encode(&self->stake_flags, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_stake_state_v2_is_uninitialized(fd_stake_state_v2_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_stake_state_v2_is_initialized(fd_stake_state_v2_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_stake_state_v2_is_stake(fd_stake_state_v2_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_stake_state_v2_is_rewards_pool(fd_stake_state_v2_t const * self) {
  return self->discriminant == 3;
}
void fd_stake_state_v2_inner_new(fd_stake_state_v2_inner_t* self, uint discriminant);
int fd_stake_state_v2_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_stake_state_v2_initialized_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_stake_state_v2_stake_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_stake_state_v2_inner_decode_unsafe(fd_stake_state_v2_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_stake_state_v2_initialized_decode_unsafe(&self->initialized, ctx);
    break;
  }
  case 2: {
    fd_stake_state_v2_stake_decode_unsafe(&self->stake, ctx);
    break;
  }
  case 3: {
    break;
  }
  }
}
int fd_stake_state_v2_decode(fd_stake_state_v2_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_stake_state_v2_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_stake_state_v2_new(self);
  fd_stake_state_v2_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_stake_state_v2_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_stake_state_v2_inner_decode_preflight(discriminant, ctx);
}
void fd_stake_state_v2_decode_unsafe(fd_stake_state_v2_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_stake_state_v2_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_stake_state_v2_inner_new(fd_stake_state_v2_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_stake_state_v2_initialized_new(&self->initialized);
    break;
  }
  case 2: {
    fd_stake_state_v2_stake_new(&self->stake);
    break;
  }
  case 3: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_stake_state_v2_new_disc(fd_stake_state_v2_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_stake_state_v2_inner_new(&self->inner, self->discriminant);
}
void fd_stake_state_v2_new(fd_stake_state_v2_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_stake_state_v2_new_disc(self, UINT_MAX);
}
void fd_stake_state_v2_inner_destroy(fd_stake_state_v2_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 1: {
    fd_stake_state_v2_initialized_destroy(&self->initialized, ctx);
    break;
  }
  case 2: {
    fd_stake_state_v2_stake_destroy(&self->stake, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_stake_state_v2_destroy(fd_stake_state_v2_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_stake_state_v2_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_stake_state_v2_footprint( void ){ return FD_STAKE_STATE_V2_FOOTPRINT; }
ulong fd_stake_state_v2_align( void ){ return FD_STAKE_STATE_V2_ALIGN; }

void fd_stake_state_v2_walk(void * w, fd_stake_state_v2_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_state_v2", level++);
  switch (self->discriminant) {
  case 1: {
    fd_stake_state_v2_initialized_walk(w, &self->inner.initialized, fun, "initialized", level);
    break;
  }
  case 2: {
    fd_stake_state_v2_stake_walk(w, &self->inner.stake, fun, "stake", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_state_v2", level--);
}
ulong fd_stake_state_v2_size(fd_stake_state_v2_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 1: {
    size += fd_stake_state_v2_initialized_size(&self->inner.initialized);
    break;
  }
  case 2: {
    size += fd_stake_state_v2_stake_size(&self->inner.stake);
    break;
  }
  }
  return size;
}

int fd_stake_state_v2_inner_encode(fd_stake_state_v2_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 1: {
    err = fd_stake_state_v2_initialized_encode(&self->initialized, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 2: {
    err = fd_stake_state_v2_stake_encode(&self->stake, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_stake_state_v2_encode(fd_stake_state_v2_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_stake_state_v2_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_nonce_data_decode(fd_nonce_data_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_nonce_data_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_nonce_data_new(self);
  fd_nonce_data_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_nonce_data_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_calculator_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_nonce_data_decode_unsafe(fd_nonce_data_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->authority, ctx);
  fd_hash_decode_unsafe(&self->durable_nonce, ctx);
  fd_fee_calculator_decode_unsafe(&self->fee_calculator, ctx);
}
int fd_nonce_data_decode_offsets(fd_nonce_data_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->authority_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->durable_nonce_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->fee_calculator_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_fee_calculator_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_nonce_data_new(fd_nonce_data_t* self) {
  fd_memset(self, 0, sizeof(fd_nonce_data_t));
  fd_pubkey_new(&self->authority);
  fd_hash_new(&self->durable_nonce);
  fd_fee_calculator_new(&self->fee_calculator);
}
void fd_nonce_data_destroy(fd_nonce_data_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->authority, ctx);
  fd_hash_destroy(&self->durable_nonce, ctx);
  fd_fee_calculator_destroy(&self->fee_calculator, ctx);
}

ulong fd_nonce_data_footprint( void ){ return FD_NONCE_DATA_FOOTPRINT; }
ulong fd_nonce_data_align( void ){ return FD_NONCE_DATA_ALIGN; }

void fd_nonce_data_walk(void * w, fd_nonce_data_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_nonce_data", level++);
  fd_pubkey_walk(w, &self->authority, fun, "authority", level);
  fd_hash_walk(w, &self->durable_nonce, fun, "durable_nonce", level);
  fd_fee_calculator_walk(w, &self->fee_calculator, fun, "fee_calculator", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_nonce_data", level--);
}
ulong fd_nonce_data_size(fd_nonce_data_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->authority);
  size += fd_hash_size(&self->durable_nonce);
  size += fd_fee_calculator_size(&self->fee_calculator);
  return size;
}

int fd_nonce_data_encode(fd_nonce_data_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->authority, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->durable_nonce, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_fee_calculator_encode(&self->fee_calculator, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_nonce_state_is_uninitialized(fd_nonce_state_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_nonce_state_is_initialized(fd_nonce_state_t const * self) {
  return self->discriminant == 1;
}
void fd_nonce_state_inner_new(fd_nonce_state_inner_t* self, uint discriminant);
int fd_nonce_state_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_nonce_data_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_nonce_state_inner_decode_unsafe(fd_nonce_state_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_nonce_data_decode_unsafe(&self->initialized, ctx);
    break;
  }
  }
}
int fd_nonce_state_decode(fd_nonce_state_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_nonce_state_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_nonce_state_new(self);
  fd_nonce_state_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_nonce_state_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_nonce_state_inner_decode_preflight(discriminant, ctx);
}
void fd_nonce_state_decode_unsafe(fd_nonce_state_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_nonce_state_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_nonce_state_inner_new(fd_nonce_state_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_nonce_data_new(&self->initialized);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_nonce_state_new_disc(fd_nonce_state_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_nonce_state_inner_new(&self->inner, self->discriminant);
}
void fd_nonce_state_new(fd_nonce_state_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_nonce_state_new_disc(self, UINT_MAX);
}
void fd_nonce_state_inner_destroy(fd_nonce_state_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 1: {
    fd_nonce_data_destroy(&self->initialized, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_nonce_state_destroy(fd_nonce_state_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_nonce_state_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_nonce_state_footprint( void ){ return FD_NONCE_STATE_FOOTPRINT; }
ulong fd_nonce_state_align( void ){ return FD_NONCE_STATE_ALIGN; }

void fd_nonce_state_walk(void * w, fd_nonce_state_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_nonce_state", level++);
  switch (self->discriminant) {
  case 1: {
    fd_nonce_data_walk(w, &self->inner.initialized, fun, "initialized", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_nonce_state", level--);
}
ulong fd_nonce_state_size(fd_nonce_state_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 1: {
    size += fd_nonce_data_size(&self->inner.initialized);
    break;
  }
  }
  return size;
}

int fd_nonce_state_inner_encode(fd_nonce_state_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 1: {
    err = fd_nonce_data_encode(&self->initialized, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_nonce_state_encode(fd_nonce_state_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_nonce_state_inner_encode(&self->inner, self->discriminant, ctx);
}

FD_FN_PURE uchar fd_nonce_state_versions_is_legacy(fd_nonce_state_versions_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_nonce_state_versions_is_current(fd_nonce_state_versions_t const * self) {
  return self->discriminant == 1;
}
void fd_nonce_state_versions_inner_new(fd_nonce_state_versions_inner_t* self, uint discriminant);
int fd_nonce_state_versions_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_nonce_state_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_nonce_state_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_nonce_state_versions_inner_decode_unsafe(fd_nonce_state_versions_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_nonce_state_decode_unsafe(&self->legacy, ctx);
    break;
  }
  case 1: {
    fd_nonce_state_decode_unsafe(&self->current, ctx);
    break;
  }
  }
}
int fd_nonce_state_versions_decode(fd_nonce_state_versions_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_nonce_state_versions_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_nonce_state_versions_new(self);
  fd_nonce_state_versions_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_nonce_state_versions_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_nonce_state_versions_inner_decode_preflight(discriminant, ctx);
}
void fd_nonce_state_versions_decode_unsafe(fd_nonce_state_versions_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_nonce_state_versions_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_nonce_state_versions_inner_new(fd_nonce_state_versions_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_nonce_state_new(&self->legacy);
    break;
  }
  case 1: {
    fd_nonce_state_new(&self->current);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_nonce_state_versions_new_disc(fd_nonce_state_versions_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_nonce_state_versions_inner_new(&self->inner, self->discriminant);
}
void fd_nonce_state_versions_new(fd_nonce_state_versions_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_nonce_state_versions_new_disc(self, UINT_MAX);
}
void fd_nonce_state_versions_inner_destroy(fd_nonce_state_versions_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_nonce_state_destroy(&self->legacy, ctx);
    break;
  }
  case 1: {
    fd_nonce_state_destroy(&self->current, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_nonce_state_versions_destroy(fd_nonce_state_versions_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_nonce_state_versions_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_nonce_state_versions_footprint( void ){ return FD_NONCE_STATE_VERSIONS_FOOTPRINT; }
ulong fd_nonce_state_versions_align( void ){ return FD_NONCE_STATE_VERSIONS_ALIGN; }

void fd_nonce_state_versions_walk(void * w, fd_nonce_state_versions_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_nonce_state_versions", level++);
  switch (self->discriminant) {
  case 0: {
    fd_nonce_state_walk(w, &self->inner.legacy, fun, "legacy", level);
    break;
  }
  case 1: {
    fd_nonce_state_walk(w, &self->inner.current, fun, "current", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_nonce_state_versions", level--);
}
ulong fd_nonce_state_versions_size(fd_nonce_state_versions_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_nonce_state_size(&self->inner.legacy);
    break;
  }
  case 1: {
    size += fd_nonce_state_size(&self->inner.current);
    break;
  }
  }
  return size;
}

int fd_nonce_state_versions_inner_encode(fd_nonce_state_versions_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_nonce_state_encode(&self->legacy, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 1: {
    err = fd_nonce_state_encode(&self->current, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_nonce_state_versions_encode(fd_nonce_state_versions_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_nonce_state_versions_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_compute_budget_program_instruction_request_units_deprecated_decode(fd_compute_budget_program_instruction_request_units_deprecated_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_compute_budget_program_instruction_request_units_deprecated_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_compute_budget_program_instruction_request_units_deprecated_new(self);
  fd_compute_budget_program_instruction_request_units_deprecated_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_compute_budget_program_instruction_request_units_deprecated_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_compute_budget_program_instruction_request_units_deprecated_decode_unsafe(fd_compute_budget_program_instruction_request_units_deprecated_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->units, ctx);
  fd_bincode_uint32_decode_unsafe(&self->additional_fee, ctx);
}
int fd_compute_budget_program_instruction_request_units_deprecated_decode_offsets(fd_compute_budget_program_instruction_request_units_deprecated_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->units_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->additional_fee_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_compute_budget_program_instruction_request_units_deprecated_new(fd_compute_budget_program_instruction_request_units_deprecated_t* self) {
  fd_memset(self, 0, sizeof(fd_compute_budget_program_instruction_request_units_deprecated_t));
}
void fd_compute_budget_program_instruction_request_units_deprecated_destroy(fd_compute_budget_program_instruction_request_units_deprecated_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_compute_budget_program_instruction_request_units_deprecated_footprint( void ){ return FD_COMPUTE_BUDGET_PROGRAM_INSTRUCTION_REQUEST_UNITS_DEPRECATED_FOOTPRINT; }
ulong fd_compute_budget_program_instruction_request_units_deprecated_align( void ){ return FD_COMPUTE_BUDGET_PROGRAM_INSTRUCTION_REQUEST_UNITS_DEPRECATED_ALIGN; }

void fd_compute_budget_program_instruction_request_units_deprecated_walk(void * w, fd_compute_budget_program_instruction_request_units_deprecated_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_compute_budget_program_instruction_request_units_deprecated", level++);
  fun( w, &self->units, "units", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
  fun( w, &self->additional_fee, "additional_fee", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_compute_budget_program_instruction_request_units_deprecated", level--);
}
ulong fd_compute_budget_program_instruction_request_units_deprecated_size(fd_compute_budget_program_instruction_request_units_deprecated_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  size += sizeof(uint);
  return size;
}

int fd_compute_budget_program_instruction_request_units_deprecated_encode(fd_compute_budget_program_instruction_request_units_deprecated_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode( self->units, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_encode( self->additional_fee, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_compute_budget_program_instruction_is_request_units_deprecated(fd_compute_budget_program_instruction_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_compute_budget_program_instruction_is_request_heap_frame(fd_compute_budget_program_instruction_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_compute_budget_program_instruction_is_set_compute_unit_limit(fd_compute_budget_program_instruction_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_compute_budget_program_instruction_is_set_compute_unit_price(fd_compute_budget_program_instruction_t const * self) {
  return self->discriminant == 3;
}
FD_FN_PURE uchar fd_compute_budget_program_instruction_is_set_loaded_accounts_data_size_limit(fd_compute_budget_program_instruction_t const * self) {
  return self->discriminant == 4;
}
void fd_compute_budget_program_instruction_inner_new(fd_compute_budget_program_instruction_inner_t* self, uint discriminant);
int fd_compute_budget_program_instruction_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_compute_budget_program_instruction_request_units_deprecated_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    err = fd_bincode_uint64_decode_preflight(ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_compute_budget_program_instruction_inner_decode_unsafe(fd_compute_budget_program_instruction_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_compute_budget_program_instruction_request_units_deprecated_decode_unsafe(&self->request_units_deprecated, ctx);
    break;
  }
  case 1: {
    fd_bincode_uint32_decode_unsafe(&self->request_heap_frame, ctx);
    break;
  }
  case 2: {
    fd_bincode_uint32_decode_unsafe(&self->set_compute_unit_limit, ctx);
    break;
  }
  case 3: {
    fd_bincode_uint64_decode_unsafe(&self->set_compute_unit_price, ctx);
    break;
  }
  case 4: {
    fd_bincode_uint32_decode_unsafe(&self->set_loaded_accounts_data_size_limit, ctx);
    break;
  }
  }
}
int fd_compute_budget_program_instruction_decode(fd_compute_budget_program_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_compute_budget_program_instruction_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_compute_budget_program_instruction_new(self);
  fd_compute_budget_program_instruction_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_compute_budget_program_instruction_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  ushort discriminant = 0;
  int err = fd_bincode_compact_u16_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_compute_budget_program_instruction_inner_decode_preflight(discriminant, ctx);
}
void fd_compute_budget_program_instruction_decode_unsafe(fd_compute_budget_program_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  ushort tmp = 0;
  fd_bincode_compact_u16_decode_unsafe(&tmp, ctx);
  self->discriminant = tmp;
  fd_compute_budget_program_instruction_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_compute_budget_program_instruction_inner_new(fd_compute_budget_program_instruction_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_compute_budget_program_instruction_request_units_deprecated_new(&self->request_units_deprecated);
    break;
  }
  case 1: {
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_compute_budget_program_instruction_new_disc(fd_compute_budget_program_instruction_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_compute_budget_program_instruction_inner_new(&self->inner, self->discriminant);
}
void fd_compute_budget_program_instruction_new(fd_compute_budget_program_instruction_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_compute_budget_program_instruction_new_disc(self, UINT_MAX);
}
void fd_compute_budget_program_instruction_inner_destroy(fd_compute_budget_program_instruction_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_compute_budget_program_instruction_request_units_deprecated_destroy(&self->request_units_deprecated, ctx);
    break;
  }
  case 1: {
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_compute_budget_program_instruction_destroy(fd_compute_budget_program_instruction_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_compute_budget_program_instruction_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_compute_budget_program_instruction_footprint( void ){ return FD_COMPUTE_BUDGET_PROGRAM_INSTRUCTION_FOOTPRINT; }
ulong fd_compute_budget_program_instruction_align( void ){ return FD_COMPUTE_BUDGET_PROGRAM_INSTRUCTION_ALIGN; }

void fd_compute_budget_program_instruction_walk(void * w, fd_compute_budget_program_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_compute_budget_program_instruction", level++);
  switch (self->discriminant) {
  case 0: {
    fd_compute_budget_program_instruction_request_units_deprecated_walk(w, &self->inner.request_units_deprecated, fun, "request_units_deprecated", level);
    break;
  }
  case 1: {
  fun( w, &self->inner.request_heap_frame, "request_heap_frame", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
    break;
  }
  case 2: {
  fun( w, &self->inner.set_compute_unit_limit, "set_compute_unit_limit", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
    break;
  }
  case 3: {
  fun( w, &self->inner.set_compute_unit_price, "set_compute_unit_price", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
    break;
  }
  case 4: {
  fun( w, &self->inner.set_loaded_accounts_data_size_limit, "set_loaded_accounts_data_size_limit", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_compute_budget_program_instruction", level--);
}
ulong fd_compute_budget_program_instruction_size(fd_compute_budget_program_instruction_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_compute_budget_program_instruction_request_units_deprecated_size(&self->inner.request_units_deprecated);
    break;
  }
  case 1: {
    size += sizeof(uint);
    break;
  }
  case 2: {
    size += sizeof(uint);
    break;
  }
  case 3: {
    size += sizeof(ulong);
    break;
  }
  case 4: {
    size += sizeof(uint);
    break;
  }
  }
  return size;
}

int fd_compute_budget_program_instruction_inner_encode(fd_compute_budget_program_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_compute_budget_program_instruction_request_units_deprecated_encode(&self->request_units_deprecated, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 1: {
    err = fd_bincode_uint32_encode( self->request_heap_frame, ctx );
  if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 2: {
    err = fd_bincode_uint32_encode( self->set_compute_unit_limit, ctx );
  if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 3: {
    err = fd_bincode_uint64_encode(self->set_compute_unit_price, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 4: {
    err = fd_bincode_uint32_encode( self->set_loaded_accounts_data_size_limit, ctx );
  if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_compute_budget_program_instruction_encode(fd_compute_budget_program_instruction_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_compute_budget_program_instruction_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_config_keys_decode(fd_config_keys_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_config_keys_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_config_keys_new(self);
  fd_config_keys_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_config_keys_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ushort keys_len;
  err = fd_bincode_compact_u16_decode(&keys_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (keys_len != 0) {
    for( ulong i = 0; i < keys_len; ++i) {
      err = fd_config_keys_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_config_keys_decode_unsafe(fd_config_keys_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_compact_u16_decode_unsafe(&self->keys_len, ctx);
  if (self->keys_len != 0) {
    self->keys = (fd_config_keys_pair_t *)fd_valloc_malloc( ctx->valloc, FD_CONFIG_KEYS_PAIR_ALIGN, FD_CONFIG_KEYS_PAIR_FOOTPRINT*self->keys_len);
    for( ulong i = 0; i < self->keys_len; ++i) {
      fd_config_keys_pair_new(self->keys + i);
      fd_config_keys_pair_decode_unsafe(self->keys + i, ctx);
    }
  } else
    self->keys = NULL;
}
int fd_config_keys_decode_offsets(fd_config_keys_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->keys_off = (uint)((ulong)ctx->data - (ulong)data);
  ushort keys_len;
  err = fd_bincode_compact_u16_decode(&keys_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (keys_len != 0) {
    for( ulong i = 0; i < keys_len; ++i) {
      err = fd_config_keys_pair_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_config_keys_new(fd_config_keys_t* self) {
  fd_memset(self, 0, sizeof(fd_config_keys_t));
}
void fd_config_keys_destroy(fd_config_keys_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->keys) {
    for (ulong i = 0; i < self->keys_len; ++i)
      fd_config_keys_pair_destroy(self->keys + i, ctx);
    fd_valloc_free( ctx->valloc, self->keys );
    self->keys = NULL;
  }
}

ulong fd_config_keys_footprint( void ){ return FD_CONFIG_KEYS_FOOTPRINT; }
ulong fd_config_keys_align( void ){ return FD_CONFIG_KEYS_ALIGN; }

void fd_config_keys_walk(void * w, fd_config_keys_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_config_keys", level++);
  if (self->keys_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "keys", level++);
    for (ulong i = 0; i < self->keys_len; ++i)
      fd_config_keys_pair_walk(w, self->keys + i, fun, "config_keys_pair", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "keys", level-- );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_config_keys", level--);
}
ulong fd_config_keys_size(fd_config_keys_t const * self) {
  ulong size = 0;
  do {
    ushort tmp = (ushort)self->keys_len;
    size += fd_bincode_compact_u16_size(&tmp);
    for (ulong i = 0; i < self->keys_len; ++i)
      size += fd_config_keys_pair_size(self->keys + i);
  } while(0);
  return size;
}

int fd_config_keys_encode(fd_config_keys_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_compact_u16_encode(&self->keys_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->keys_len != 0) {
    for (ulong i = 0; i < self->keys_len; ++i) {
      err = fd_config_keys_pair_encode(self->keys + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_bpf_loader_program_instruction_write_decode(fd_bpf_loader_program_instruction_write_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_bpf_loader_program_instruction_write_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_bpf_loader_program_instruction_write_new(self);
  fd_bpf_loader_program_instruction_write_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_bpf_loader_program_instruction_write_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong bytes_len;
  err = fd_bincode_uint64_decode(&bytes_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (bytes_len != 0) {
    err = fd_bincode_bytes_decode_preflight(bytes_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_bpf_loader_program_instruction_write_decode_unsafe(fd_bpf_loader_program_instruction_write_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->offset, ctx);
  fd_bincode_uint64_decode_unsafe(&self->bytes_len, ctx);
  if (self->bytes_len != 0) {
    self->bytes = fd_valloc_malloc( ctx->valloc, 8UL, self->bytes_len );
    fd_bincode_bytes_decode_unsafe(self->bytes, self->bytes_len, ctx);
  } else
    self->bytes = NULL;
}
int fd_bpf_loader_program_instruction_write_decode_offsets(fd_bpf_loader_program_instruction_write_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->offset_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->bytes_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong bytes_len;
  err = fd_bincode_uint64_decode(&bytes_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (bytes_len != 0) {
    err = fd_bincode_bytes_decode_preflight(bytes_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_bpf_loader_program_instruction_write_new(fd_bpf_loader_program_instruction_write_t* self) {
  fd_memset(self, 0, sizeof(fd_bpf_loader_program_instruction_write_t));
}
void fd_bpf_loader_program_instruction_write_destroy(fd_bpf_loader_program_instruction_write_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->bytes) {
    fd_valloc_free( ctx->valloc, self->bytes );
    self->bytes = NULL;
  }
}

ulong fd_bpf_loader_program_instruction_write_footprint( void ){ return FD_BPF_LOADER_PROGRAM_INSTRUCTION_WRITE_FOOTPRINT; }
ulong fd_bpf_loader_program_instruction_write_align( void ){ return FD_BPF_LOADER_PROGRAM_INSTRUCTION_WRITE_ALIGN; }

void fd_bpf_loader_program_instruction_write_walk(void * w, fd_bpf_loader_program_instruction_write_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_loader_program_instruction_write", level++);
  fun( w, &self->offset, "offset", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
  fun(w, self->bytes, "bytes", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_loader_program_instruction_write", level--);
}
ulong fd_bpf_loader_program_instruction_write_size(fd_bpf_loader_program_instruction_write_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  do {
    size += sizeof(ulong);
    size += self->bytes_len;
  } while(0);
  return size;
}

int fd_bpf_loader_program_instruction_write_encode(fd_bpf_loader_program_instruction_write_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode( self->offset, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->bytes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->bytes_len != 0) {
    err = fd_bincode_bytes_encode(self->bytes, self->bytes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_bpf_loader_program_instruction_is_write(fd_bpf_loader_program_instruction_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_bpf_loader_program_instruction_is_finalize(fd_bpf_loader_program_instruction_t const * self) {
  return self->discriminant == 1;
}
void fd_bpf_loader_program_instruction_inner_new(fd_bpf_loader_program_instruction_inner_t* self, uint discriminant);
int fd_bpf_loader_program_instruction_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_bpf_loader_program_instruction_write_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_bpf_loader_program_instruction_inner_decode_unsafe(fd_bpf_loader_program_instruction_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_bpf_loader_program_instruction_write_decode_unsafe(&self->write, ctx);
    break;
  }
  case 1: {
    break;
  }
  }
}
int fd_bpf_loader_program_instruction_decode(fd_bpf_loader_program_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_bpf_loader_program_instruction_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_bpf_loader_program_instruction_new(self);
  fd_bpf_loader_program_instruction_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_bpf_loader_program_instruction_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_bpf_loader_program_instruction_inner_decode_preflight(discriminant, ctx);
}
void fd_bpf_loader_program_instruction_decode_unsafe(fd_bpf_loader_program_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_bpf_loader_program_instruction_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_bpf_loader_program_instruction_inner_new(fd_bpf_loader_program_instruction_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_bpf_loader_program_instruction_write_new(&self->write);
    break;
  }
  case 1: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_bpf_loader_program_instruction_new_disc(fd_bpf_loader_program_instruction_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_bpf_loader_program_instruction_inner_new(&self->inner, self->discriminant);
}
void fd_bpf_loader_program_instruction_new(fd_bpf_loader_program_instruction_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_bpf_loader_program_instruction_new_disc(self, UINT_MAX);
}
void fd_bpf_loader_program_instruction_inner_destroy(fd_bpf_loader_program_instruction_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_bpf_loader_program_instruction_write_destroy(&self->write, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_bpf_loader_program_instruction_destroy(fd_bpf_loader_program_instruction_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_bpf_loader_program_instruction_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_bpf_loader_program_instruction_footprint( void ){ return FD_BPF_LOADER_PROGRAM_INSTRUCTION_FOOTPRINT; }
ulong fd_bpf_loader_program_instruction_align( void ){ return FD_BPF_LOADER_PROGRAM_INSTRUCTION_ALIGN; }

void fd_bpf_loader_program_instruction_walk(void * w, fd_bpf_loader_program_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_loader_program_instruction", level++);
  switch (self->discriminant) {
  case 0: {
    fd_bpf_loader_program_instruction_write_walk(w, &self->inner.write, fun, "write", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_loader_program_instruction", level--);
}
ulong fd_bpf_loader_program_instruction_size(fd_bpf_loader_program_instruction_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_bpf_loader_program_instruction_write_size(&self->inner.write);
    break;
  }
  }
  return size;
}

int fd_bpf_loader_program_instruction_inner_encode(fd_bpf_loader_program_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_bpf_loader_program_instruction_write_encode(&self->write, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_bpf_loader_program_instruction_encode(fd_bpf_loader_program_instruction_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_bpf_loader_program_instruction_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_bpf_loader_v4_program_instruction_write_decode(fd_bpf_loader_v4_program_instruction_write_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_bpf_loader_v4_program_instruction_write_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_bpf_loader_v4_program_instruction_write_new(self);
  fd_bpf_loader_v4_program_instruction_write_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_bpf_loader_v4_program_instruction_write_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong bytes_len;
  err = fd_bincode_uint64_decode(&bytes_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (bytes_len != 0) {
    err = fd_bincode_bytes_decode_preflight(bytes_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_bpf_loader_v4_program_instruction_write_decode_unsafe(fd_bpf_loader_v4_program_instruction_write_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->offset, ctx);
  fd_bincode_uint64_decode_unsafe(&self->bytes_len, ctx);
  if (self->bytes_len != 0) {
    self->bytes = fd_valloc_malloc( ctx->valloc, 8UL, self->bytes_len );
    fd_bincode_bytes_decode_unsafe(self->bytes, self->bytes_len, ctx);
  } else
    self->bytes = NULL;
}
int fd_bpf_loader_v4_program_instruction_write_decode_offsets(fd_bpf_loader_v4_program_instruction_write_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->offset_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->bytes_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong bytes_len;
  err = fd_bincode_uint64_decode(&bytes_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (bytes_len != 0) {
    err = fd_bincode_bytes_decode_preflight(bytes_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_bpf_loader_v4_program_instruction_write_new(fd_bpf_loader_v4_program_instruction_write_t* self) {
  fd_memset(self, 0, sizeof(fd_bpf_loader_v4_program_instruction_write_t));
}
void fd_bpf_loader_v4_program_instruction_write_destroy(fd_bpf_loader_v4_program_instruction_write_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->bytes) {
    fd_valloc_free( ctx->valloc, self->bytes );
    self->bytes = NULL;
  }
}

ulong fd_bpf_loader_v4_program_instruction_write_footprint( void ){ return FD_BPF_LOADER_V4_PROGRAM_INSTRUCTION_WRITE_FOOTPRINT; }
ulong fd_bpf_loader_v4_program_instruction_write_align( void ){ return FD_BPF_LOADER_V4_PROGRAM_INSTRUCTION_WRITE_ALIGN; }

void fd_bpf_loader_v4_program_instruction_write_walk(void * w, fd_bpf_loader_v4_program_instruction_write_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_loader_v4_program_instruction_write", level++);
  fun( w, &self->offset, "offset", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
  fun(w, self->bytes, "bytes", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_loader_v4_program_instruction_write", level--);
}
ulong fd_bpf_loader_v4_program_instruction_write_size(fd_bpf_loader_v4_program_instruction_write_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  do {
    size += sizeof(ulong);
    size += self->bytes_len;
  } while(0);
  return size;
}

int fd_bpf_loader_v4_program_instruction_write_encode(fd_bpf_loader_v4_program_instruction_write_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode( self->offset, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->bytes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->bytes_len != 0) {
    err = fd_bincode_bytes_encode(self->bytes, self->bytes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_bpf_loader_v4_program_instruction_is_write(fd_bpf_loader_v4_program_instruction_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_bpf_loader_v4_program_instruction_is_truncate(fd_bpf_loader_v4_program_instruction_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_bpf_loader_v4_program_instruction_is_deploy(fd_bpf_loader_v4_program_instruction_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_bpf_loader_v4_program_instruction_is_retract(fd_bpf_loader_v4_program_instruction_t const * self) {
  return self->discriminant == 3;
}
FD_FN_PURE uchar fd_bpf_loader_v4_program_instruction_is_transfer_authority(fd_bpf_loader_v4_program_instruction_t const * self) {
  return self->discriminant == 4;
}
void fd_bpf_loader_v4_program_instruction_inner_new(fd_bpf_loader_v4_program_instruction_inner_t* self, uint discriminant);
int fd_bpf_loader_v4_program_instruction_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_bpf_loader_v4_program_instruction_write_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_bpf_loader_v4_program_instruction_inner_decode_unsafe(fd_bpf_loader_v4_program_instruction_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_bpf_loader_v4_program_instruction_write_decode_unsafe(&self->write, ctx);
    break;
  }
  case 1: {
    fd_bincode_uint32_decode_unsafe(&self->truncate, ctx);
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  }
}
int fd_bpf_loader_v4_program_instruction_decode(fd_bpf_loader_v4_program_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_bpf_loader_v4_program_instruction_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_bpf_loader_v4_program_instruction_new(self);
  fd_bpf_loader_v4_program_instruction_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_bpf_loader_v4_program_instruction_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_bpf_loader_v4_program_instruction_inner_decode_preflight(discriminant, ctx);
}
void fd_bpf_loader_v4_program_instruction_decode_unsafe(fd_bpf_loader_v4_program_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_bpf_loader_v4_program_instruction_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_bpf_loader_v4_program_instruction_inner_new(fd_bpf_loader_v4_program_instruction_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_bpf_loader_v4_program_instruction_write_new(&self->write);
    break;
  }
  case 1: {
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_bpf_loader_v4_program_instruction_new_disc(fd_bpf_loader_v4_program_instruction_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_bpf_loader_v4_program_instruction_inner_new(&self->inner, self->discriminant);
}
void fd_bpf_loader_v4_program_instruction_new(fd_bpf_loader_v4_program_instruction_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_bpf_loader_v4_program_instruction_new_disc(self, UINT_MAX);
}
void fd_bpf_loader_v4_program_instruction_inner_destroy(fd_bpf_loader_v4_program_instruction_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_bpf_loader_v4_program_instruction_write_destroy(&self->write, ctx);
    break;
  }
  case 1: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_bpf_loader_v4_program_instruction_destroy(fd_bpf_loader_v4_program_instruction_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_bpf_loader_v4_program_instruction_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_bpf_loader_v4_program_instruction_footprint( void ){ return FD_BPF_LOADER_V4_PROGRAM_INSTRUCTION_FOOTPRINT; }
ulong fd_bpf_loader_v4_program_instruction_align( void ){ return FD_BPF_LOADER_V4_PROGRAM_INSTRUCTION_ALIGN; }

void fd_bpf_loader_v4_program_instruction_walk(void * w, fd_bpf_loader_v4_program_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_loader_v4_program_instruction", level++);
  switch (self->discriminant) {
  case 0: {
    fd_bpf_loader_v4_program_instruction_write_walk(w, &self->inner.write, fun, "write", level);
    break;
  }
  case 1: {
  fun( w, &self->inner.truncate, "truncate", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_loader_v4_program_instruction", level--);
}
ulong fd_bpf_loader_v4_program_instruction_size(fd_bpf_loader_v4_program_instruction_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_bpf_loader_v4_program_instruction_write_size(&self->inner.write);
    break;
  }
  case 1: {
    size += sizeof(uint);
    break;
  }
  }
  return size;
}

int fd_bpf_loader_v4_program_instruction_inner_encode(fd_bpf_loader_v4_program_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_bpf_loader_v4_program_instruction_write_encode(&self->write, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 1: {
    err = fd_bincode_uint32_encode( self->truncate, ctx );
  if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_bpf_loader_v4_program_instruction_encode(fd_bpf_loader_v4_program_instruction_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_bpf_loader_v4_program_instruction_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_bpf_upgradeable_loader_program_instruction_write_decode(fd_bpf_upgradeable_loader_program_instruction_write_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_bpf_upgradeable_loader_program_instruction_write_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_bpf_upgradeable_loader_program_instruction_write_new(self);
  fd_bpf_upgradeable_loader_program_instruction_write_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_bpf_upgradeable_loader_program_instruction_write_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong bytes_len;
  err = fd_bincode_uint64_decode(&bytes_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (bytes_len != 0) {
    err = fd_bincode_bytes_decode_preflight(bytes_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_bpf_upgradeable_loader_program_instruction_write_decode_unsafe(fd_bpf_upgradeable_loader_program_instruction_write_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->offset, ctx);
  fd_bincode_uint64_decode_unsafe(&self->bytes_len, ctx);
  if (self->bytes_len != 0) {
    self->bytes = fd_valloc_malloc( ctx->valloc, 8UL, self->bytes_len );
    fd_bincode_bytes_decode_unsafe(self->bytes, self->bytes_len, ctx);
  } else
    self->bytes = NULL;
}
int fd_bpf_upgradeable_loader_program_instruction_write_decode_offsets(fd_bpf_upgradeable_loader_program_instruction_write_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->offset_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->bytes_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong bytes_len;
  err = fd_bincode_uint64_decode(&bytes_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (bytes_len != 0) {
    err = fd_bincode_bytes_decode_preflight(bytes_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_bpf_upgradeable_loader_program_instruction_write_new(fd_bpf_upgradeable_loader_program_instruction_write_t* self) {
  fd_memset(self, 0, sizeof(fd_bpf_upgradeable_loader_program_instruction_write_t));
}
void fd_bpf_upgradeable_loader_program_instruction_write_destroy(fd_bpf_upgradeable_loader_program_instruction_write_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->bytes) {
    fd_valloc_free( ctx->valloc, self->bytes );
    self->bytes = NULL;
  }
}

ulong fd_bpf_upgradeable_loader_program_instruction_write_footprint( void ){ return FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_WRITE_FOOTPRINT; }
ulong fd_bpf_upgradeable_loader_program_instruction_write_align( void ){ return FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_WRITE_ALIGN; }

void fd_bpf_upgradeable_loader_program_instruction_write_walk(void * w, fd_bpf_upgradeable_loader_program_instruction_write_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_upgradeable_loader_program_instruction_write", level++);
  fun( w, &self->offset, "offset", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
  fun(w, self->bytes, "bytes", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_upgradeable_loader_program_instruction_write", level--);
}
ulong fd_bpf_upgradeable_loader_program_instruction_write_size(fd_bpf_upgradeable_loader_program_instruction_write_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  do {
    size += sizeof(ulong);
    size += self->bytes_len;
  } while(0);
  return size;
}

int fd_bpf_upgradeable_loader_program_instruction_write_encode(fd_bpf_upgradeable_loader_program_instruction_write_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode( self->offset, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->bytes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->bytes_len != 0) {
    err = fd_bincode_bytes_encode(self->bytes, self->bytes_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_decode(fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_new(self);
  fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_decode_unsafe(fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->max_data_len, ctx);
}
int fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_decode_offsets(fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->max_data_len_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_new(fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t* self) {
  fd_memset(self, 0, sizeof(fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t));
}
void fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_destroy(fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_footprint( void ){ return FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_DEPLOY_WITH_MAX_DATA_LEN_FOOTPRINT; }
ulong fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_align( void ){ return FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_DEPLOY_WITH_MAX_DATA_LEN_ALIGN; }

void fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_walk(void * w, fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len", level++);
  fun( w, &self->max_data_len, "max_data_len", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len", level--);
}
ulong fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_size(fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  return size;
}

int fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_encode(fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->max_data_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_bpf_upgradeable_loader_program_instruction_extend_program_decode(fd_bpf_upgradeable_loader_program_instruction_extend_program_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_bpf_upgradeable_loader_program_instruction_extend_program_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_bpf_upgradeable_loader_program_instruction_extend_program_new(self);
  fd_bpf_upgradeable_loader_program_instruction_extend_program_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_bpf_upgradeable_loader_program_instruction_extend_program_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_bpf_upgradeable_loader_program_instruction_extend_program_decode_unsafe(fd_bpf_upgradeable_loader_program_instruction_extend_program_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->additional_bytes, ctx);
}
int fd_bpf_upgradeable_loader_program_instruction_extend_program_decode_offsets(fd_bpf_upgradeable_loader_program_instruction_extend_program_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->additional_bytes_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_bpf_upgradeable_loader_program_instruction_extend_program_new(fd_bpf_upgradeable_loader_program_instruction_extend_program_t* self) {
  fd_memset(self, 0, sizeof(fd_bpf_upgradeable_loader_program_instruction_extend_program_t));
}
void fd_bpf_upgradeable_loader_program_instruction_extend_program_destroy(fd_bpf_upgradeable_loader_program_instruction_extend_program_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_bpf_upgradeable_loader_program_instruction_extend_program_footprint( void ){ return FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_EXTEND_PROGRAM_FOOTPRINT; }
ulong fd_bpf_upgradeable_loader_program_instruction_extend_program_align( void ){ return FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_EXTEND_PROGRAM_ALIGN; }

void fd_bpf_upgradeable_loader_program_instruction_extend_program_walk(void * w, fd_bpf_upgradeable_loader_program_instruction_extend_program_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_upgradeable_loader_program_instruction_extend_program", level++);
  fun( w, &self->additional_bytes, "additional_bytes", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_upgradeable_loader_program_instruction_extend_program", level--);
}
ulong fd_bpf_upgradeable_loader_program_instruction_extend_program_size(fd_bpf_upgradeable_loader_program_instruction_extend_program_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  return size;
}

int fd_bpf_upgradeable_loader_program_instruction_extend_program_encode(fd_bpf_upgradeable_loader_program_instruction_extend_program_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode( self->additional_bytes, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_initialize_buffer(fd_bpf_upgradeable_loader_program_instruction_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_write(fd_bpf_upgradeable_loader_program_instruction_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_deploy_with_max_data_len(fd_bpf_upgradeable_loader_program_instruction_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_upgrade(fd_bpf_upgradeable_loader_program_instruction_t const * self) {
  return self->discriminant == 3;
}
FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_set_authority(fd_bpf_upgradeable_loader_program_instruction_t const * self) {
  return self->discriminant == 4;
}
FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_close(fd_bpf_upgradeable_loader_program_instruction_t const * self) {
  return self->discriminant == 5;
}
FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_extend_program(fd_bpf_upgradeable_loader_program_instruction_t const * self) {
  return self->discriminant == 6;
}
FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_set_authority_checked(fd_bpf_upgradeable_loader_program_instruction_t const * self) {
  return self->discriminant == 7;
}
void fd_bpf_upgradeable_loader_program_instruction_inner_new(fd_bpf_upgradeable_loader_program_instruction_inner_t* self, uint discriminant);
int fd_bpf_upgradeable_loader_program_instruction_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_bpf_upgradeable_loader_program_instruction_write_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    return FD_BINCODE_SUCCESS;
  }
  case 5: {
    return FD_BINCODE_SUCCESS;
  }
  case 6: {
    err = fd_bpf_upgradeable_loader_program_instruction_extend_program_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 7: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_bpf_upgradeable_loader_program_instruction_inner_decode_unsafe(fd_bpf_upgradeable_loader_program_instruction_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_bpf_upgradeable_loader_program_instruction_write_decode_unsafe(&self->write, ctx);
    break;
  }
  case 2: {
    fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_decode_unsafe(&self->deploy_with_max_data_len, ctx);
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    fd_bpf_upgradeable_loader_program_instruction_extend_program_decode_unsafe(&self->extend_program, ctx);
    break;
  }
  case 7: {
    break;
  }
  }
}
int fd_bpf_upgradeable_loader_program_instruction_decode(fd_bpf_upgradeable_loader_program_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_bpf_upgradeable_loader_program_instruction_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_bpf_upgradeable_loader_program_instruction_new(self);
  fd_bpf_upgradeable_loader_program_instruction_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_bpf_upgradeable_loader_program_instruction_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_bpf_upgradeable_loader_program_instruction_inner_decode_preflight(discriminant, ctx);
}
void fd_bpf_upgradeable_loader_program_instruction_decode_unsafe(fd_bpf_upgradeable_loader_program_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_bpf_upgradeable_loader_program_instruction_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_bpf_upgradeable_loader_program_instruction_inner_new(fd_bpf_upgradeable_loader_program_instruction_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_bpf_upgradeable_loader_program_instruction_write_new(&self->write);
    break;
  }
  case 2: {
    fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_new(&self->deploy_with_max_data_len);
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    fd_bpf_upgradeable_loader_program_instruction_extend_program_new(&self->extend_program);
    break;
  }
  case 7: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_bpf_upgradeable_loader_program_instruction_new_disc(fd_bpf_upgradeable_loader_program_instruction_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_bpf_upgradeable_loader_program_instruction_inner_new(&self->inner, self->discriminant);
}
void fd_bpf_upgradeable_loader_program_instruction_new(fd_bpf_upgradeable_loader_program_instruction_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_bpf_upgradeable_loader_program_instruction_new_disc(self, UINT_MAX);
}
void fd_bpf_upgradeable_loader_program_instruction_inner_destroy(fd_bpf_upgradeable_loader_program_instruction_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 1: {
    fd_bpf_upgradeable_loader_program_instruction_write_destroy(&self->write, ctx);
    break;
  }
  case 2: {
    fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_destroy(&self->deploy_with_max_data_len, ctx);
    break;
  }
  case 6: {
    fd_bpf_upgradeable_loader_program_instruction_extend_program_destroy(&self->extend_program, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_bpf_upgradeable_loader_program_instruction_destroy(fd_bpf_upgradeable_loader_program_instruction_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_bpf_upgradeable_loader_program_instruction_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_bpf_upgradeable_loader_program_instruction_footprint( void ){ return FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_FOOTPRINT; }
ulong fd_bpf_upgradeable_loader_program_instruction_align( void ){ return FD_BPF_UPGRADEABLE_LOADER_PROGRAM_INSTRUCTION_ALIGN; }

void fd_bpf_upgradeable_loader_program_instruction_walk(void * w, fd_bpf_upgradeable_loader_program_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_upgradeable_loader_program_instruction", level++);
  switch (self->discriminant) {
  case 1: {
    fd_bpf_upgradeable_loader_program_instruction_write_walk(w, &self->inner.write, fun, "write", level);
    break;
  }
  case 2: {
    fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_walk(w, &self->inner.deploy_with_max_data_len, fun, "deploy_with_max_data_len", level);
    break;
  }
  case 6: {
    fd_bpf_upgradeable_loader_program_instruction_extend_program_walk(w, &self->inner.extend_program, fun, "extend_program", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_upgradeable_loader_program_instruction", level--);
}
ulong fd_bpf_upgradeable_loader_program_instruction_size(fd_bpf_upgradeable_loader_program_instruction_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 1: {
    size += fd_bpf_upgradeable_loader_program_instruction_write_size(&self->inner.write);
    break;
  }
  case 2: {
    size += fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_size(&self->inner.deploy_with_max_data_len);
    break;
  }
  case 6: {
    size += fd_bpf_upgradeable_loader_program_instruction_extend_program_size(&self->inner.extend_program);
    break;
  }
  }
  return size;
}

int fd_bpf_upgradeable_loader_program_instruction_inner_encode(fd_bpf_upgradeable_loader_program_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 1: {
    err = fd_bpf_upgradeable_loader_program_instruction_write_encode(&self->write, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 2: {
    err = fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_encode(&self->deploy_with_max_data_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 6: {
    err = fd_bpf_upgradeable_loader_program_instruction_extend_program_encode(&self->extend_program, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_bpf_upgradeable_loader_program_instruction_encode(fd_bpf_upgradeable_loader_program_instruction_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_bpf_upgradeable_loader_program_instruction_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_bpf_upgradeable_loader_state_buffer_decode(fd_bpf_upgradeable_loader_state_buffer_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_bpf_upgradeable_loader_state_buffer_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_bpf_upgradeable_loader_state_buffer_new(self);
  fd_bpf_upgradeable_loader_state_buffer_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_bpf_upgradeable_loader_state_buffer_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_pubkey_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_bpf_upgradeable_loader_state_buffer_decode_unsafe(fd_bpf_upgradeable_loader_state_buffer_t* self, fd_bincode_decode_ctx_t * ctx) {
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      self->authority_address = (fd_pubkey_t*)fd_valloc_malloc( ctx->valloc, FD_PUBKEY_ALIGN, FD_PUBKEY_FOOTPRINT );
      fd_pubkey_new( self->authority_address );
      fd_pubkey_decode_unsafe( self->authority_address, ctx );
    } else
      self->authority_address = NULL;
  }
}
int fd_bpf_upgradeable_loader_state_buffer_decode_offsets(fd_bpf_upgradeable_loader_state_buffer_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->authority_address_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_pubkey_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_bpf_upgradeable_loader_state_buffer_new(fd_bpf_upgradeable_loader_state_buffer_t* self) {
  fd_memset(self, 0, sizeof(fd_bpf_upgradeable_loader_state_buffer_t));
}
void fd_bpf_upgradeable_loader_state_buffer_destroy(fd_bpf_upgradeable_loader_state_buffer_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if( NULL != self->authority_address ) {
    fd_pubkey_destroy( self->authority_address, ctx );
    fd_valloc_free( ctx->valloc, self->authority_address );
    self->authority_address = NULL;
  }
}

ulong fd_bpf_upgradeable_loader_state_buffer_footprint( void ){ return FD_BPF_UPGRADEABLE_LOADER_STATE_BUFFER_FOOTPRINT; }
ulong fd_bpf_upgradeable_loader_state_buffer_align( void ){ return FD_BPF_UPGRADEABLE_LOADER_STATE_BUFFER_ALIGN; }

void fd_bpf_upgradeable_loader_state_buffer_walk(void * w, fd_bpf_upgradeable_loader_state_buffer_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_upgradeable_loader_state_buffer", level++);
  if( !self->authority_address ) {
    fun( w, NULL, "authority_address", FD_FLAMENCO_TYPE_NULL, "pubkey", level );
  } else {
    fd_pubkey_walk( w, self->authority_address, fun, "authority_address", level );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_upgradeable_loader_state_buffer", level--);
}
ulong fd_bpf_upgradeable_loader_state_buffer_size(fd_bpf_upgradeable_loader_state_buffer_t const * self) {
  ulong size = 0;
  size += sizeof(char);
  if( NULL !=  self->authority_address ) {
    size += fd_pubkey_size( self->authority_address );
  }
  return size;
}

int fd_bpf_upgradeable_loader_state_buffer_encode(fd_bpf_upgradeable_loader_state_buffer_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  if( self->authority_address != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_pubkey_encode( self->authority_address, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_bpf_upgradeable_loader_state_program_decode(fd_bpf_upgradeable_loader_state_program_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_bpf_upgradeable_loader_state_program_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_bpf_upgradeable_loader_state_program_new(self);
  fd_bpf_upgradeable_loader_state_program_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_bpf_upgradeable_loader_state_program_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_bpf_upgradeable_loader_state_program_decode_unsafe(fd_bpf_upgradeable_loader_state_program_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->programdata_address, ctx);
}
int fd_bpf_upgradeable_loader_state_program_decode_offsets(fd_bpf_upgradeable_loader_state_program_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->programdata_address_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_bpf_upgradeable_loader_state_program_new(fd_bpf_upgradeable_loader_state_program_t* self) {
  fd_memset(self, 0, sizeof(fd_bpf_upgradeable_loader_state_program_t));
  fd_pubkey_new(&self->programdata_address);
}
void fd_bpf_upgradeable_loader_state_program_destroy(fd_bpf_upgradeable_loader_state_program_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->programdata_address, ctx);
}

ulong fd_bpf_upgradeable_loader_state_program_footprint( void ){ return FD_BPF_UPGRADEABLE_LOADER_STATE_PROGRAM_FOOTPRINT; }
ulong fd_bpf_upgradeable_loader_state_program_align( void ){ return FD_BPF_UPGRADEABLE_LOADER_STATE_PROGRAM_ALIGN; }

void fd_bpf_upgradeable_loader_state_program_walk(void * w, fd_bpf_upgradeable_loader_state_program_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_upgradeable_loader_state_program", level++);
  fd_pubkey_walk(w, &self->programdata_address, fun, "programdata_address", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_upgradeable_loader_state_program", level--);
}
ulong fd_bpf_upgradeable_loader_state_program_size(fd_bpf_upgradeable_loader_state_program_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->programdata_address);
  return size;
}

int fd_bpf_upgradeable_loader_state_program_encode(fd_bpf_upgradeable_loader_state_program_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->programdata_address, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_bpf_upgradeable_loader_state_program_data_decode(fd_bpf_upgradeable_loader_state_program_data_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_bpf_upgradeable_loader_state_program_data_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_bpf_upgradeable_loader_state_program_data_new(self);
  fd_bpf_upgradeable_loader_state_program_data_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_bpf_upgradeable_loader_state_program_data_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_pubkey_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_bpf_upgradeable_loader_state_program_data_decode_unsafe(fd_bpf_upgradeable_loader_state_program_data_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      self->upgrade_authority_address = (fd_pubkey_t*)fd_valloc_malloc( ctx->valloc, FD_PUBKEY_ALIGN, FD_PUBKEY_FOOTPRINT );
      fd_pubkey_new( self->upgrade_authority_address );
      fd_pubkey_decode_unsafe( self->upgrade_authority_address, ctx );
    } else
      self->upgrade_authority_address = NULL;
  }
}
int fd_bpf_upgradeable_loader_state_program_data_decode_offsets(fd_bpf_upgradeable_loader_state_program_data_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->upgrade_authority_address_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_pubkey_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_bpf_upgradeable_loader_state_program_data_new(fd_bpf_upgradeable_loader_state_program_data_t* self) {
  fd_memset(self, 0, sizeof(fd_bpf_upgradeable_loader_state_program_data_t));
}
void fd_bpf_upgradeable_loader_state_program_data_destroy(fd_bpf_upgradeable_loader_state_program_data_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if( NULL != self->upgrade_authority_address ) {
    fd_pubkey_destroy( self->upgrade_authority_address, ctx );
    fd_valloc_free( ctx->valloc, self->upgrade_authority_address );
    self->upgrade_authority_address = NULL;
  }
}

ulong fd_bpf_upgradeable_loader_state_program_data_footprint( void ){ return FD_BPF_UPGRADEABLE_LOADER_STATE_PROGRAM_DATA_FOOTPRINT; }
ulong fd_bpf_upgradeable_loader_state_program_data_align( void ){ return FD_BPF_UPGRADEABLE_LOADER_STATE_PROGRAM_DATA_ALIGN; }

void fd_bpf_upgradeable_loader_state_program_data_walk(void * w, fd_bpf_upgradeable_loader_state_program_data_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_upgradeable_loader_state_program_data", level++);
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  if( !self->upgrade_authority_address ) {
    fun( w, NULL, "upgrade_authority_address", FD_FLAMENCO_TYPE_NULL, "pubkey", level );
  } else {
    fd_pubkey_walk( w, self->upgrade_authority_address, fun, "upgrade_authority_address", level );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_upgradeable_loader_state_program_data", level--);
}
ulong fd_bpf_upgradeable_loader_state_program_data_size(fd_bpf_upgradeable_loader_state_program_data_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(char);
  if( NULL !=  self->upgrade_authority_address ) {
    size += fd_pubkey_size( self->upgrade_authority_address );
  }
  return size;
}

int fd_bpf_upgradeable_loader_state_program_data_encode(fd_bpf_upgradeable_loader_state_program_data_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if( self->upgrade_authority_address != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_pubkey_encode( self->upgrade_authority_address, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if ( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_bpf_upgradeable_loader_state_is_uninitialized(fd_bpf_upgradeable_loader_state_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_bpf_upgradeable_loader_state_is_buffer(fd_bpf_upgradeable_loader_state_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_bpf_upgradeable_loader_state_is_program(fd_bpf_upgradeable_loader_state_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_bpf_upgradeable_loader_state_is_program_data(fd_bpf_upgradeable_loader_state_t const * self) {
  return self->discriminant == 3;
}
void fd_bpf_upgradeable_loader_state_inner_new(fd_bpf_upgradeable_loader_state_inner_t* self, uint discriminant);
int fd_bpf_upgradeable_loader_state_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_bpf_upgradeable_loader_state_buffer_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_bpf_upgradeable_loader_state_program_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    err = fd_bpf_upgradeable_loader_state_program_data_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_bpf_upgradeable_loader_state_inner_decode_unsafe(fd_bpf_upgradeable_loader_state_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_bpf_upgradeable_loader_state_buffer_decode_unsafe(&self->buffer, ctx);
    break;
  }
  case 2: {
    fd_bpf_upgradeable_loader_state_program_decode_unsafe(&self->program, ctx);
    break;
  }
  case 3: {
    fd_bpf_upgradeable_loader_state_program_data_decode_unsafe(&self->program_data, ctx);
    break;
  }
  }
}
int fd_bpf_upgradeable_loader_state_decode(fd_bpf_upgradeable_loader_state_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_bpf_upgradeable_loader_state_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_bpf_upgradeable_loader_state_new(self);
  fd_bpf_upgradeable_loader_state_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_bpf_upgradeable_loader_state_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_bpf_upgradeable_loader_state_inner_decode_preflight(discriminant, ctx);
}
void fd_bpf_upgradeable_loader_state_decode_unsafe(fd_bpf_upgradeable_loader_state_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_bpf_upgradeable_loader_state_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_bpf_upgradeable_loader_state_inner_new(fd_bpf_upgradeable_loader_state_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_bpf_upgradeable_loader_state_buffer_new(&self->buffer);
    break;
  }
  case 2: {
    fd_bpf_upgradeable_loader_state_program_new(&self->program);
    break;
  }
  case 3: {
    fd_bpf_upgradeable_loader_state_program_data_new(&self->program_data);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_bpf_upgradeable_loader_state_new_disc(fd_bpf_upgradeable_loader_state_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_bpf_upgradeable_loader_state_inner_new(&self->inner, self->discriminant);
}
void fd_bpf_upgradeable_loader_state_new(fd_bpf_upgradeable_loader_state_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_bpf_upgradeable_loader_state_new_disc(self, UINT_MAX);
}
void fd_bpf_upgradeable_loader_state_inner_destroy(fd_bpf_upgradeable_loader_state_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 1: {
    fd_bpf_upgradeable_loader_state_buffer_destroy(&self->buffer, ctx);
    break;
  }
  case 2: {
    fd_bpf_upgradeable_loader_state_program_destroy(&self->program, ctx);
    break;
  }
  case 3: {
    fd_bpf_upgradeable_loader_state_program_data_destroy(&self->program_data, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_bpf_upgradeable_loader_state_destroy(fd_bpf_upgradeable_loader_state_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_bpf_upgradeable_loader_state_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_bpf_upgradeable_loader_state_footprint( void ){ return FD_BPF_UPGRADEABLE_LOADER_STATE_FOOTPRINT; }
ulong fd_bpf_upgradeable_loader_state_align( void ){ return FD_BPF_UPGRADEABLE_LOADER_STATE_ALIGN; }

void fd_bpf_upgradeable_loader_state_walk(void * w, fd_bpf_upgradeable_loader_state_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_upgradeable_loader_state", level++);
  switch (self->discriminant) {
  case 1: {
    fd_bpf_upgradeable_loader_state_buffer_walk(w, &self->inner.buffer, fun, "buffer", level);
    break;
  }
  case 2: {
    fd_bpf_upgradeable_loader_state_program_walk(w, &self->inner.program, fun, "program", level);
    break;
  }
  case 3: {
    fd_bpf_upgradeable_loader_state_program_data_walk(w, &self->inner.program_data, fun, "program_data", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_upgradeable_loader_state", level--);
}
ulong fd_bpf_upgradeable_loader_state_size(fd_bpf_upgradeable_loader_state_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 1: {
    size += fd_bpf_upgradeable_loader_state_buffer_size(&self->inner.buffer);
    break;
  }
  case 2: {
    size += fd_bpf_upgradeable_loader_state_program_size(&self->inner.program);
    break;
  }
  case 3: {
    size += fd_bpf_upgradeable_loader_state_program_data_size(&self->inner.program_data);
    break;
  }
  }
  return size;
}

int fd_bpf_upgradeable_loader_state_inner_encode(fd_bpf_upgradeable_loader_state_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 1: {
    err = fd_bpf_upgradeable_loader_state_buffer_encode(&self->buffer, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 2: {
    err = fd_bpf_upgradeable_loader_state_program_encode(&self->program, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 3: {
    err = fd_bpf_upgradeable_loader_state_program_data_encode(&self->program_data, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_bpf_upgradeable_loader_state_encode(fd_bpf_upgradeable_loader_state_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_bpf_upgradeable_loader_state_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_frozen_hash_status_decode(fd_frozen_hash_status_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_frozen_hash_status_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_frozen_hash_status_new(self);
  fd_frozen_hash_status_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_frozen_hash_status_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_frozen_hash_status_decode_unsafe(fd_frozen_hash_status_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_hash_decode_unsafe(&self->frozen_hash, ctx);
  fd_bincode_uint8_decode_unsafe(&self->frozen_status, ctx);
}
int fd_frozen_hash_status_decode_offsets(fd_frozen_hash_status_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->frozen_hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->frozen_status_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_frozen_hash_status_new(fd_frozen_hash_status_t* self) {
  fd_memset(self, 0, sizeof(fd_frozen_hash_status_t));
  fd_hash_new(&self->frozen_hash);
}
void fd_frozen_hash_status_destroy(fd_frozen_hash_status_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_hash_destroy(&self->frozen_hash, ctx);
}

ulong fd_frozen_hash_status_footprint( void ){ return FD_FROZEN_HASH_STATUS_FOOTPRINT; }
ulong fd_frozen_hash_status_align( void ){ return FD_FROZEN_HASH_STATUS_ALIGN; }

void fd_frozen_hash_status_walk(void * w, fd_frozen_hash_status_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_frozen_hash_status", level++);
  fd_hash_walk(w, &self->frozen_hash, fun, "frozen_hash", level);
  fun( w, &self->frozen_status, "frozen_status", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_frozen_hash_status", level--);
}
ulong fd_frozen_hash_status_size(fd_frozen_hash_status_t const * self) {
  ulong size = 0;
  size += fd_hash_size(&self->frozen_hash);
  size += sizeof(char);
  return size;
}

int fd_frozen_hash_status_encode(fd_frozen_hash_status_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_hash_encode(&self->frozen_hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->frozen_status), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_frozen_hash_versioned_is_current(fd_frozen_hash_versioned_t const * self) {
  return self->discriminant == 0;
}
void fd_frozen_hash_versioned_inner_new(fd_frozen_hash_versioned_inner_t* self, uint discriminant);
int fd_frozen_hash_versioned_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_frozen_hash_status_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_frozen_hash_versioned_inner_decode_unsafe(fd_frozen_hash_versioned_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_frozen_hash_status_decode_unsafe(&self->current, ctx);
    break;
  }
  }
}
int fd_frozen_hash_versioned_decode(fd_frozen_hash_versioned_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_frozen_hash_versioned_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_frozen_hash_versioned_new(self);
  fd_frozen_hash_versioned_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_frozen_hash_versioned_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_frozen_hash_versioned_inner_decode_preflight(discriminant, ctx);
}
void fd_frozen_hash_versioned_decode_unsafe(fd_frozen_hash_versioned_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_frozen_hash_versioned_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_frozen_hash_versioned_inner_new(fd_frozen_hash_versioned_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_frozen_hash_status_new(&self->current);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_frozen_hash_versioned_new_disc(fd_frozen_hash_versioned_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_frozen_hash_versioned_inner_new(&self->inner, self->discriminant);
}
void fd_frozen_hash_versioned_new(fd_frozen_hash_versioned_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_frozen_hash_versioned_new_disc(self, UINT_MAX);
}
void fd_frozen_hash_versioned_inner_destroy(fd_frozen_hash_versioned_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_frozen_hash_status_destroy(&self->current, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_frozen_hash_versioned_destroy(fd_frozen_hash_versioned_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_frozen_hash_versioned_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_frozen_hash_versioned_footprint( void ){ return FD_FROZEN_HASH_VERSIONED_FOOTPRINT; }
ulong fd_frozen_hash_versioned_align( void ){ return FD_FROZEN_HASH_VERSIONED_ALIGN; }

void fd_frozen_hash_versioned_walk(void * w, fd_frozen_hash_versioned_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_frozen_hash_versioned", level++);
  switch (self->discriminant) {
  case 0: {
    fd_frozen_hash_status_walk(w, &self->inner.current, fun, "current", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_frozen_hash_versioned", level--);
}
ulong fd_frozen_hash_versioned_size(fd_frozen_hash_versioned_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_frozen_hash_status_size(&self->inner.current);
    break;
  }
  }
  return size;
}

int fd_frozen_hash_versioned_inner_encode(fd_frozen_hash_versioned_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_frozen_hash_status_encode(&self->current, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_frozen_hash_versioned_encode(fd_frozen_hash_versioned_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_frozen_hash_versioned_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_lookup_table_meta_decode(fd_lookup_table_meta_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_lookup_table_meta_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_lookup_table_meta_new(self);
  fd_lookup_table_meta_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_lookup_table_meta_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_pubkey_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_lookup_table_meta_decode_unsafe(fd_lookup_table_meta_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->deactivation_slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->last_extended_slot, ctx);
  fd_bincode_uint8_decode_unsafe(&self->last_extended_slot_start_index, ctx);
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_authority = !!o;
    if( o ) {
      fd_pubkey_new( &self->authority );
      fd_pubkey_decode_unsafe( &self->authority, ctx );
    }
  }
  fd_bincode_uint16_decode_unsafe(&self->_padding, ctx);
}
int fd_lookup_table_meta_decode_offsets(fd_lookup_table_meta_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->deactivation_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->last_extended_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->last_extended_slot_start_index_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->authority_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_pubkey_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->_padding_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_lookup_table_meta_new(fd_lookup_table_meta_t* self) {
  fd_memset(self, 0, sizeof(fd_lookup_table_meta_t));
}
void fd_lookup_table_meta_destroy(fd_lookup_table_meta_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if( self->has_authority ) {
    fd_pubkey_destroy( &self->authority, ctx );
    self->has_authority = 0;
  }
}

ulong fd_lookup_table_meta_footprint( void ){ return FD_LOOKUP_TABLE_META_FOOTPRINT; }
ulong fd_lookup_table_meta_align( void ){ return FD_LOOKUP_TABLE_META_ALIGN; }

void fd_lookup_table_meta_walk(void * w, fd_lookup_table_meta_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_lookup_table_meta", level++);
  fun( w, &self->deactivation_slot, "deactivation_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->last_extended_slot, "last_extended_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->last_extended_slot_start_index, "last_extended_slot_start_index", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  if( !self->has_authority ) {
    fun( w, NULL, "authority", FD_FLAMENCO_TYPE_NULL, "pubkey", level );
  } else {
    fd_pubkey_walk( w, &self->authority, fun, "authority", level );
  }
  fun( w, &self->_padding, "_padding", FD_FLAMENCO_TYPE_USHORT,  "ushort",    level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_lookup_table_meta", level--);
}
ulong fd_lookup_table_meta_size(fd_lookup_table_meta_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(char);
  size += sizeof(char);
  if( self->has_authority ) {
    size += fd_pubkey_size( &self->authority );
  }
  size += sizeof(ushort);
  return size;
}

int fd_lookup_table_meta_encode(fd_lookup_table_meta_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->deactivation_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->last_extended_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->last_extended_slot_start_index), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bool_encode( self->has_authority, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_authority ) {
    err = fd_pubkey_encode( &self->authority, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint16_encode( (ushort)(self->_padding), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_address_lookup_table_decode(fd_address_lookup_table_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_address_lookup_table_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_address_lookup_table_new(self);
  fd_address_lookup_table_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_address_lookup_table_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_lookup_table_meta_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_address_lookup_table_decode_unsafe(fd_address_lookup_table_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_lookup_table_meta_decode_unsafe(&self->meta, ctx);
}
int fd_address_lookup_table_decode_offsets(fd_address_lookup_table_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->meta_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_lookup_table_meta_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_address_lookup_table_new(fd_address_lookup_table_t* self) {
  fd_memset(self, 0, sizeof(fd_address_lookup_table_t));
  fd_lookup_table_meta_new(&self->meta);
}
void fd_address_lookup_table_destroy(fd_address_lookup_table_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_lookup_table_meta_destroy(&self->meta, ctx);
}

ulong fd_address_lookup_table_footprint( void ){ return FD_ADDRESS_LOOKUP_TABLE_FOOTPRINT; }
ulong fd_address_lookup_table_align( void ){ return FD_ADDRESS_LOOKUP_TABLE_ALIGN; }

void fd_address_lookup_table_walk(void * w, fd_address_lookup_table_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_address_lookup_table", level++);
  fd_lookup_table_meta_walk(w, &self->meta, fun, "meta", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_address_lookup_table", level--);
}
ulong fd_address_lookup_table_size(fd_address_lookup_table_t const * self) {
  ulong size = 0;
  size += fd_lookup_table_meta_size(&self->meta);
  return size;
}

int fd_address_lookup_table_encode(fd_address_lookup_table_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_lookup_table_meta_encode(&self->meta, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_address_lookup_table_state_is_uninitialized(fd_address_lookup_table_state_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_address_lookup_table_state_is_lookup_table(fd_address_lookup_table_state_t const * self) {
  return self->discriminant == 1;
}
void fd_address_lookup_table_state_inner_new(fd_address_lookup_table_state_inner_t* self, uint discriminant);
int fd_address_lookup_table_state_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_address_lookup_table_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_address_lookup_table_state_inner_decode_unsafe(fd_address_lookup_table_state_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_address_lookup_table_decode_unsafe(&self->lookup_table, ctx);
    break;
  }
  }
}
int fd_address_lookup_table_state_decode(fd_address_lookup_table_state_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_address_lookup_table_state_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_address_lookup_table_state_new(self);
  fd_address_lookup_table_state_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_address_lookup_table_state_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_address_lookup_table_state_inner_decode_preflight(discriminant, ctx);
}
void fd_address_lookup_table_state_decode_unsafe(fd_address_lookup_table_state_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_address_lookup_table_state_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_address_lookup_table_state_inner_new(fd_address_lookup_table_state_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_address_lookup_table_new(&self->lookup_table);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_address_lookup_table_state_new_disc(fd_address_lookup_table_state_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_address_lookup_table_state_inner_new(&self->inner, self->discriminant);
}
void fd_address_lookup_table_state_new(fd_address_lookup_table_state_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_address_lookup_table_state_new_disc(self, UINT_MAX);
}
void fd_address_lookup_table_state_inner_destroy(fd_address_lookup_table_state_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 1: {
    fd_address_lookup_table_destroy(&self->lookup_table, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_address_lookup_table_state_destroy(fd_address_lookup_table_state_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_address_lookup_table_state_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_address_lookup_table_state_footprint( void ){ return FD_ADDRESS_LOOKUP_TABLE_STATE_FOOTPRINT; }
ulong fd_address_lookup_table_state_align( void ){ return FD_ADDRESS_LOOKUP_TABLE_STATE_ALIGN; }

void fd_address_lookup_table_state_walk(void * w, fd_address_lookup_table_state_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_address_lookup_table_state", level++);
  switch (self->discriminant) {
  case 1: {
    fd_address_lookup_table_walk(w, &self->inner.lookup_table, fun, "lookup_table", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_address_lookup_table_state", level--);
}
ulong fd_address_lookup_table_state_size(fd_address_lookup_table_state_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 1: {
    size += fd_address_lookup_table_size(&self->inner.lookup_table);
    break;
  }
  }
  return size;
}

int fd_address_lookup_table_state_inner_encode(fd_address_lookup_table_state_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 1: {
    err = fd_address_lookup_table_encode(&self->lookup_table, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_address_lookup_table_state_encode(fd_address_lookup_table_state_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_address_lookup_table_state_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_gossip_bitvec_u8_inner_decode(fd_gossip_bitvec_u8_inner_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_bitvec_u8_inner_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_bitvec_u8_inner_new(self);
  fd_gossip_bitvec_u8_inner_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_bitvec_u8_inner_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong vec_len;
  err = fd_bincode_uint64_decode(&vec_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (vec_len != 0) {
    err = fd_bincode_bytes_decode_preflight(vec_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_bitvec_u8_inner_decode_unsafe(fd_gossip_bitvec_u8_inner_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->vec_len, ctx);
  if (self->vec_len != 0) {
    self->vec = fd_valloc_malloc( ctx->valloc, 8UL, self->vec_len );
    fd_bincode_bytes_decode_unsafe(self->vec, self->vec_len, ctx);
  } else
    self->vec = NULL;
}
int fd_gossip_bitvec_u8_inner_decode_offsets(fd_gossip_bitvec_u8_inner_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->vec_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong vec_len;
  err = fd_bincode_uint64_decode(&vec_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (vec_len != 0) {
    err = fd_bincode_bytes_decode_preflight(vec_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_bitvec_u8_inner_new(fd_gossip_bitvec_u8_inner_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_bitvec_u8_inner_t));
}
void fd_gossip_bitvec_u8_inner_destroy(fd_gossip_bitvec_u8_inner_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->vec) {
    fd_valloc_free( ctx->valloc, self->vec );
    self->vec = NULL;
  }
}

ulong fd_gossip_bitvec_u8_inner_footprint( void ){ return FD_GOSSIP_BITVEC_U8_INNER_FOOTPRINT; }
ulong fd_gossip_bitvec_u8_inner_align( void ){ return FD_GOSSIP_BITVEC_U8_INNER_ALIGN; }

void fd_gossip_bitvec_u8_inner_walk(void * w, fd_gossip_bitvec_u8_inner_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_bitvec_u8_inner", level++);
  fun(w, self->vec, "vec", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_bitvec_u8_inner", level--);
}
ulong fd_gossip_bitvec_u8_inner_size(fd_gossip_bitvec_u8_inner_t const * self) {
  ulong size = 0;
  do {
    size += sizeof(ulong);
    size += self->vec_len;
  } while(0);
  return size;
}

int fd_gossip_bitvec_u8_inner_encode(fd_gossip_bitvec_u8_inner_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->vec_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->vec_len != 0) {
    err = fd_bincode_bytes_encode(self->vec, self->vec_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_bitvec_u8_decode(fd_gossip_bitvec_u8_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_bitvec_u8_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_bitvec_u8_new(self);
  fd_gossip_bitvec_u8_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_bitvec_u8_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_gossip_bitvec_u8_inner_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_bitvec_u8_decode_unsafe(fd_gossip_bitvec_u8_t* self, fd_bincode_decode_ctx_t * ctx) {
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_bits = !!o;
    if( o ) {
      fd_gossip_bitvec_u8_inner_new( &self->bits );
      fd_gossip_bitvec_u8_inner_decode_unsafe( &self->bits, ctx );
    }
  }
  fd_bincode_uint64_decode_unsafe(&self->len, ctx);
}
int fd_gossip_bitvec_u8_decode_offsets(fd_gossip_bitvec_u8_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->bits_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_gossip_bitvec_u8_inner_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->len_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_bitvec_u8_new(fd_gossip_bitvec_u8_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_bitvec_u8_t));
}
void fd_gossip_bitvec_u8_destroy(fd_gossip_bitvec_u8_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if( self->has_bits ) {
    fd_gossip_bitvec_u8_inner_destroy( &self->bits, ctx );
    self->has_bits = 0;
  }
}

ulong fd_gossip_bitvec_u8_footprint( void ){ return FD_GOSSIP_BITVEC_U8_FOOTPRINT; }
ulong fd_gossip_bitvec_u8_align( void ){ return FD_GOSSIP_BITVEC_U8_ALIGN; }

void fd_gossip_bitvec_u8_walk(void * w, fd_gossip_bitvec_u8_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_bitvec_u8", level++);
  if( !self->has_bits ) {
    fun( w, NULL, "bits", FD_FLAMENCO_TYPE_NULL, "gossip_bitvec_u8_inner", level );
  } else {
    fd_gossip_bitvec_u8_inner_walk( w, &self->bits, fun, "bits", level );
  }
  fun( w, &self->len, "len", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_bitvec_u8", level--);
}
ulong fd_gossip_bitvec_u8_size(fd_gossip_bitvec_u8_t const * self) {
  ulong size = 0;
  size += sizeof(char);
  if( self->has_bits ) {
    size += fd_gossip_bitvec_u8_inner_size( &self->bits );
  }
  size += sizeof(ulong);
  return size;
}

int fd_gossip_bitvec_u8_encode(fd_gossip_bitvec_u8_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bool_encode( self->has_bits, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_bits ) {
    err = fd_gossip_bitvec_u8_inner_encode( &self->bits, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint64_encode(self->len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_bitvec_u64_inner_decode(fd_gossip_bitvec_u64_inner_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_bitvec_u64_inner_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_bitvec_u64_inner_new(self);
  fd_gossip_bitvec_u64_inner_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_bitvec_u64_inner_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong vec_len;
  err = fd_bincode_uint64_decode(&vec_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (vec_len != 0) {
    for( ulong i = 0; i < vec_len; ++i) {
      err = fd_bincode_uint64_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_bitvec_u64_inner_decode_unsafe(fd_gossip_bitvec_u64_inner_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->vec_len, ctx);
  if (self->vec_len != 0) {
    self->vec = fd_valloc_malloc( ctx->valloc, 8UL, sizeof(ulong)*self->vec_len );
    for( ulong i = 0; i < self->vec_len; ++i) {
      fd_bincode_uint64_decode_unsafe(self->vec + i, ctx);
    }
  } else
    self->vec = NULL;
}
int fd_gossip_bitvec_u64_inner_decode_offsets(fd_gossip_bitvec_u64_inner_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->vec_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong vec_len;
  err = fd_bincode_uint64_decode(&vec_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (vec_len != 0) {
    for( ulong i = 0; i < vec_len; ++i) {
      err = fd_bincode_uint64_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_bitvec_u64_inner_new(fd_gossip_bitvec_u64_inner_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_bitvec_u64_inner_t));
}
void fd_gossip_bitvec_u64_inner_destroy(fd_gossip_bitvec_u64_inner_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->vec) {
    fd_valloc_free( ctx->valloc, self->vec );
    self->vec = NULL;
  }
}

ulong fd_gossip_bitvec_u64_inner_footprint( void ){ return FD_GOSSIP_BITVEC_U64_INNER_FOOTPRINT; }
ulong fd_gossip_bitvec_u64_inner_align( void ){ return FD_GOSSIP_BITVEC_U64_INNER_ALIGN; }

void fd_gossip_bitvec_u64_inner_walk(void * w, fd_gossip_bitvec_u64_inner_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_bitvec_u64_inner", level++);
  if (self->vec_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "vec", level++);
    for (ulong i = 0; i < self->vec_len; ++i)
      fun( w, self->vec + i, "vec", FD_FLAMENCO_TYPE_ULONG,   "ulong",   level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "vec", level-- );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_bitvec_u64_inner", level--);
}
ulong fd_gossip_bitvec_u64_inner_size(fd_gossip_bitvec_u64_inner_t const * self) {
  ulong size = 0;
  do {
    size += sizeof(ulong);
    size += self->vec_len * sizeof(ulong);
  } while(0);
  return size;
}

int fd_gossip_bitvec_u64_inner_encode(fd_gossip_bitvec_u64_inner_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->vec_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->vec_len != 0) {
    for (ulong i = 0; i < self->vec_len; ++i) {
      err = fd_bincode_uint64_encode(self->vec[i], ctx);
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_bitvec_u64_decode(fd_gossip_bitvec_u64_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_bitvec_u64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_bitvec_u64_new(self);
  fd_gossip_bitvec_u64_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_bitvec_u64_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_gossip_bitvec_u64_inner_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_bitvec_u64_decode_unsafe(fd_gossip_bitvec_u64_t* self, fd_bincode_decode_ctx_t * ctx) {
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_bits = !!o;
    if( o ) {
      fd_gossip_bitvec_u64_inner_new( &self->bits );
      fd_gossip_bitvec_u64_inner_decode_unsafe( &self->bits, ctx );
    }
  }
  fd_bincode_uint64_decode_unsafe(&self->len, ctx);
}
int fd_gossip_bitvec_u64_decode_offsets(fd_gossip_bitvec_u64_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->bits_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_gossip_bitvec_u64_inner_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->len_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_bitvec_u64_new(fd_gossip_bitvec_u64_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_bitvec_u64_t));
}
void fd_gossip_bitvec_u64_destroy(fd_gossip_bitvec_u64_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if( self->has_bits ) {
    fd_gossip_bitvec_u64_inner_destroy( &self->bits, ctx );
    self->has_bits = 0;
  }
}

ulong fd_gossip_bitvec_u64_footprint( void ){ return FD_GOSSIP_BITVEC_U64_FOOTPRINT; }
ulong fd_gossip_bitvec_u64_align( void ){ return FD_GOSSIP_BITVEC_U64_ALIGN; }

void fd_gossip_bitvec_u64_walk(void * w, fd_gossip_bitvec_u64_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_bitvec_u64", level++);
  if( !self->has_bits ) {
    fun( w, NULL, "bits", FD_FLAMENCO_TYPE_NULL, "gossip_bitvec_u64_inner", level );
  } else {
    fd_gossip_bitvec_u64_inner_walk( w, &self->bits, fun, "bits", level );
  }
  fun( w, &self->len, "len", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_bitvec_u64", level--);
}
ulong fd_gossip_bitvec_u64_size(fd_gossip_bitvec_u64_t const * self) {
  ulong size = 0;
  size += sizeof(char);
  if( self->has_bits ) {
    size += fd_gossip_bitvec_u64_inner_size( &self->bits );
  }
  size += sizeof(ulong);
  return size;
}

int fd_gossip_bitvec_u64_encode(fd_gossip_bitvec_u64_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bool_encode( self->has_bits, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_bits ) {
    err = fd_gossip_bitvec_u64_inner_encode( &self->bits, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint64_encode(self->len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_ping_decode(fd_gossip_ping_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_ping_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_ping_new(self);
  fd_gossip_ping_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_ping_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_signature_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_ping_decode_unsafe(fd_gossip_ping_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->from, ctx);
  fd_hash_decode_unsafe(&self->token, ctx);
  fd_signature_decode_unsafe(&self->signature, ctx);
}
int fd_gossip_ping_decode_offsets(fd_gossip_ping_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->from_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->token_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->signature_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_signature_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_ping_new(fd_gossip_ping_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_ping_t));
  fd_pubkey_new(&self->from);
  fd_hash_new(&self->token);
  fd_signature_new(&self->signature);
}
void fd_gossip_ping_destroy(fd_gossip_ping_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->from, ctx);
  fd_hash_destroy(&self->token, ctx);
  fd_signature_destroy(&self->signature, ctx);
}

ulong fd_gossip_ping_footprint( void ){ return FD_GOSSIP_PING_FOOTPRINT; }
ulong fd_gossip_ping_align( void ){ return FD_GOSSIP_PING_ALIGN; }

void fd_gossip_ping_walk(void * w, fd_gossip_ping_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_ping", level++);
  fd_pubkey_walk(w, &self->from, fun, "from", level);
  fd_hash_walk(w, &self->token, fun, "token", level);
  fd_signature_walk(w, &self->signature, fun, "signature", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_ping", level--);
}
ulong fd_gossip_ping_size(fd_gossip_ping_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->from);
  size += fd_hash_size(&self->token);
  size += fd_signature_size(&self->signature);
  return size;
}

int fd_gossip_ping_encode(fd_gossip_ping_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->from, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_hash_encode(&self->token, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_signature_encode(&self->signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_gossip_ip_addr_is_ip4(fd_gossip_ip_addr_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_gossip_ip_addr_is_ip6(fd_gossip_ip_addr_t const * self) {
  return self->discriminant == 1;
}
void fd_gossip_ip_addr_inner_new(fd_gossip_ip_addr_inner_t* self, uint discriminant);
int fd_gossip_ip_addr_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_ip4_addr_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_gossip_ip6_addr_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_gossip_ip_addr_inner_decode_unsafe(fd_gossip_ip_addr_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_gossip_ip4_addr_decode_unsafe(&self->ip4, ctx);
    break;
  }
  case 1: {
    fd_gossip_ip6_addr_decode_unsafe(&self->ip6, ctx);
    break;
  }
  }
}
int fd_gossip_ip_addr_decode(fd_gossip_ip_addr_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_ip_addr_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_ip_addr_new(self);
  fd_gossip_ip_addr_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_ip_addr_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_gossip_ip_addr_inner_decode_preflight(discriminant, ctx);
}
void fd_gossip_ip_addr_decode_unsafe(fd_gossip_ip_addr_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_gossip_ip_addr_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_gossip_ip_addr_inner_new(fd_gossip_ip_addr_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_gossip_ip4_addr_new(&self->ip4);
    break;
  }
  case 1: {
    fd_gossip_ip6_addr_new(&self->ip6);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_gossip_ip_addr_new_disc(fd_gossip_ip_addr_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_gossip_ip_addr_inner_new(&self->inner, self->discriminant);
}
void fd_gossip_ip_addr_new(fd_gossip_ip_addr_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_gossip_ip_addr_new_disc(self, UINT_MAX);
}
void fd_gossip_ip_addr_inner_destroy(fd_gossip_ip_addr_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_gossip_ip4_addr_destroy(&self->ip4, ctx);
    break;
  }
  case 1: {
    fd_gossip_ip6_addr_destroy(&self->ip6, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_gossip_ip_addr_destroy(fd_gossip_ip_addr_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_gossip_ip_addr_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_gossip_ip_addr_footprint( void ){ return FD_GOSSIP_IP_ADDR_FOOTPRINT; }
ulong fd_gossip_ip_addr_align( void ){ return FD_GOSSIP_IP_ADDR_ALIGN; }

void fd_gossip_ip_addr_walk(void * w, fd_gossip_ip_addr_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_ip_addr", level++);
  switch (self->discriminant) {
  case 0: {
    fd_gossip_ip4_addr_walk(w, &self->inner.ip4, fun, "ip4", level);
    break;
  }
  case 1: {
    fd_gossip_ip6_addr_walk(w, &self->inner.ip6, fun, "ip6", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_ip_addr", level--);
}
ulong fd_gossip_ip_addr_size(fd_gossip_ip_addr_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_gossip_ip4_addr_size(&self->inner.ip4);
    break;
  }
  case 1: {
    size += fd_gossip_ip6_addr_size(&self->inner.ip6);
    break;
  }
  }
  return size;
}

int fd_gossip_ip_addr_inner_encode(fd_gossip_ip_addr_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_ip4_addr_encode(&self->ip4, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 1: {
    err = fd_gossip_ip6_addr_encode(&self->ip6, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_ip_addr_encode(fd_gossip_ip_addr_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_gossip_ip_addr_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_gossip_prune_data_decode(fd_gossip_prune_data_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_prune_data_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_prune_data_new(self);
  fd_gossip_prune_data_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_prune_data_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong prunes_len;
  err = fd_bincode_uint64_decode(&prunes_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (prunes_len != 0) {
    for( ulong i = 0; i < prunes_len; ++i) {
      err = fd_pubkey_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_signature_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_prune_data_decode_unsafe(fd_gossip_prune_data_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->pubkey, ctx);
  fd_bincode_uint64_decode_unsafe(&self->prunes_len, ctx);
  if (self->prunes_len != 0) {
    self->prunes = (fd_pubkey_t *)fd_valloc_malloc( ctx->valloc, FD_PUBKEY_ALIGN, FD_PUBKEY_FOOTPRINT*self->prunes_len);
    for( ulong i = 0; i < self->prunes_len; ++i) {
      fd_pubkey_new(self->prunes + i);
      fd_pubkey_decode_unsafe(self->prunes + i, ctx);
    }
  } else
    self->prunes = NULL;
  fd_signature_decode_unsafe(&self->signature, ctx);
  fd_pubkey_decode_unsafe(&self->destination, ctx);
  fd_bincode_uint64_decode_unsafe(&self->wallclock, ctx);
}
int fd_gossip_prune_data_decode_offsets(fd_gossip_prune_data_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->prunes_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong prunes_len;
  err = fd_bincode_uint64_decode(&prunes_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (prunes_len != 0) {
    for( ulong i = 0; i < prunes_len; ++i) {
      err = fd_pubkey_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->signature_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_signature_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->destination_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->wallclock_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_prune_data_new(fd_gossip_prune_data_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_prune_data_t));
  fd_pubkey_new(&self->pubkey);
  fd_signature_new(&self->signature);
  fd_pubkey_new(&self->destination);
}
void fd_gossip_prune_data_destroy(fd_gossip_prune_data_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->pubkey, ctx);
  if (NULL != self->prunes) {
    for (ulong i = 0; i < self->prunes_len; ++i)
      fd_pubkey_destroy(self->prunes + i, ctx);
    fd_valloc_free( ctx->valloc, self->prunes );
    self->prunes = NULL;
  }
  fd_signature_destroy(&self->signature, ctx);
  fd_pubkey_destroy(&self->destination, ctx);
}

ulong fd_gossip_prune_data_footprint( void ){ return FD_GOSSIP_PRUNE_DATA_FOOTPRINT; }
ulong fd_gossip_prune_data_align( void ){ return FD_GOSSIP_PRUNE_DATA_ALIGN; }

void fd_gossip_prune_data_walk(void * w, fd_gossip_prune_data_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_prune_data", level++);
  fd_pubkey_walk(w, &self->pubkey, fun, "pubkey", level);
  if (self->prunes_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "prunes", level++);
    for (ulong i = 0; i < self->prunes_len; ++i)
      fd_pubkey_walk(w, self->prunes + i, fun, "pubkey", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "prunes", level-- );
  }
  fd_signature_walk(w, &self->signature, fun, "signature", level);
  fd_pubkey_walk(w, &self->destination, fun, "destination", level);
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_prune_data", level--);
}
ulong fd_gossip_prune_data_size(fd_gossip_prune_data_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->pubkey);
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->prunes_len; ++i)
      size += fd_pubkey_size(self->prunes + i);
  } while(0);
  size += fd_signature_size(&self->signature);
  size += fd_pubkey_size(&self->destination);
  size += sizeof(ulong);
  return size;
}

int fd_gossip_prune_data_encode(fd_gossip_prune_data_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->prunes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->prunes_len != 0) {
    for (ulong i = 0; i < self->prunes_len; ++i) {
      err = fd_pubkey_encode(self->prunes + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_signature_encode(&self->signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->destination, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->wallclock, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_prune_sign_data_decode(fd_gossip_prune_sign_data_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_prune_sign_data_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_prune_sign_data_new(self);
  fd_gossip_prune_sign_data_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_prune_sign_data_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong prunes_len;
  err = fd_bincode_uint64_decode(&prunes_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (prunes_len != 0) {
    for( ulong i = 0; i < prunes_len; ++i) {
      err = fd_pubkey_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_prune_sign_data_decode_unsafe(fd_gossip_prune_sign_data_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->pubkey, ctx);
  fd_bincode_uint64_decode_unsafe(&self->prunes_len, ctx);
  if (self->prunes_len != 0) {
    self->prunes = (fd_pubkey_t *)fd_valloc_malloc( ctx->valloc, FD_PUBKEY_ALIGN, FD_PUBKEY_FOOTPRINT*self->prunes_len);
    for( ulong i = 0; i < self->prunes_len; ++i) {
      fd_pubkey_new(self->prunes + i);
      fd_pubkey_decode_unsafe(self->prunes + i, ctx);
    }
  } else
    self->prunes = NULL;
  fd_pubkey_decode_unsafe(&self->destination, ctx);
  fd_bincode_uint64_decode_unsafe(&self->wallclock, ctx);
}
int fd_gossip_prune_sign_data_decode_offsets(fd_gossip_prune_sign_data_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->prunes_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong prunes_len;
  err = fd_bincode_uint64_decode(&prunes_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (prunes_len != 0) {
    for( ulong i = 0; i < prunes_len; ++i) {
      err = fd_pubkey_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->destination_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->wallclock_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_prune_sign_data_new(fd_gossip_prune_sign_data_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_prune_sign_data_t));
  fd_pubkey_new(&self->pubkey);
  fd_pubkey_new(&self->destination);
}
void fd_gossip_prune_sign_data_destroy(fd_gossip_prune_sign_data_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->pubkey, ctx);
  if (NULL != self->prunes) {
    for (ulong i = 0; i < self->prunes_len; ++i)
      fd_pubkey_destroy(self->prunes + i, ctx);
    fd_valloc_free( ctx->valloc, self->prunes );
    self->prunes = NULL;
  }
  fd_pubkey_destroy(&self->destination, ctx);
}

ulong fd_gossip_prune_sign_data_footprint( void ){ return FD_GOSSIP_PRUNE_SIGN_DATA_FOOTPRINT; }
ulong fd_gossip_prune_sign_data_align( void ){ return FD_GOSSIP_PRUNE_SIGN_DATA_ALIGN; }

void fd_gossip_prune_sign_data_walk(void * w, fd_gossip_prune_sign_data_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_prune_sign_data", level++);
  fd_pubkey_walk(w, &self->pubkey, fun, "pubkey", level);
  if (self->prunes_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "prunes", level++);
    for (ulong i = 0; i < self->prunes_len; ++i)
      fd_pubkey_walk(w, self->prunes + i, fun, "pubkey", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "prunes", level-- );
  }
  fd_pubkey_walk(w, &self->destination, fun, "destination", level);
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_prune_sign_data", level--);
}
ulong fd_gossip_prune_sign_data_size(fd_gossip_prune_sign_data_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->pubkey);
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->prunes_len; ++i)
      size += fd_pubkey_size(self->prunes + i);
  } while(0);
  size += fd_pubkey_size(&self->destination);
  size += sizeof(ulong);
  return size;
}

int fd_gossip_prune_sign_data_encode(fd_gossip_prune_sign_data_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->prunes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->prunes_len != 0) {
    for (ulong i = 0; i < self->prunes_len; ++i) {
      err = fd_pubkey_encode(self->prunes + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_pubkey_encode(&self->destination, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->wallclock, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_socket_addr_decode(fd_gossip_socket_addr_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_socket_addr_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_socket_addr_new(self);
  fd_gossip_socket_addr_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_socket_addr_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_gossip_ip_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_socket_addr_decode_unsafe(fd_gossip_socket_addr_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_gossip_ip_addr_decode_unsafe(&self->addr, ctx);
  fd_bincode_uint16_decode_unsafe(&self->port, ctx);
}
int fd_gossip_socket_addr_decode_offsets(fd_gossip_socket_addr_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->addr_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_gossip_ip_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->port_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_socket_addr_new(fd_gossip_socket_addr_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_socket_addr_t));
  fd_gossip_ip_addr_new(&self->addr);
}
void fd_gossip_socket_addr_destroy(fd_gossip_socket_addr_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_gossip_ip_addr_destroy(&self->addr, ctx);
}

ulong fd_gossip_socket_addr_footprint( void ){ return FD_GOSSIP_SOCKET_ADDR_FOOTPRINT; }
ulong fd_gossip_socket_addr_align( void ){ return FD_GOSSIP_SOCKET_ADDR_ALIGN; }

void fd_gossip_socket_addr_walk(void * w, fd_gossip_socket_addr_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_socket_addr", level++);
  fd_gossip_ip_addr_walk(w, &self->addr, fun, "addr", level);
  fun( w, &self->port, "port", FD_FLAMENCO_TYPE_USHORT,  "ushort",    level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_socket_addr", level--);
}
ulong fd_gossip_socket_addr_size(fd_gossip_socket_addr_t const * self) {
  ulong size = 0;
  size += fd_gossip_ip_addr_size(&self->addr);
  size += sizeof(ushort);
  return size;
}

int fd_gossip_socket_addr_encode(fd_gossip_socket_addr_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_gossip_ip_addr_encode(&self->addr, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_encode( (ushort)(self->port), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_contact_info_v1_decode(fd_gossip_contact_info_v1_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_contact_info_v1_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_contact_info_v1_new(self);
  fd_gossip_contact_info_v1_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_contact_info_v1_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_contact_info_v1_decode_unsafe(fd_gossip_contact_info_v1_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->id, ctx);
  fd_gossip_socket_addr_decode_unsafe(&self->gossip, ctx);
  fd_gossip_socket_addr_decode_unsafe(&self->tvu, ctx);
  fd_gossip_socket_addr_decode_unsafe(&self->tvu_fwd, ctx);
  fd_gossip_socket_addr_decode_unsafe(&self->repair, ctx);
  fd_gossip_socket_addr_decode_unsafe(&self->tpu, ctx);
  fd_gossip_socket_addr_decode_unsafe(&self->tpu_fwd, ctx);
  fd_gossip_socket_addr_decode_unsafe(&self->tpu_vote, ctx);
  fd_gossip_socket_addr_decode_unsafe(&self->rpc, ctx);
  fd_gossip_socket_addr_decode_unsafe(&self->rpc_pubsub, ctx);
  fd_gossip_socket_addr_decode_unsafe(&self->serve_repair, ctx);
  fd_bincode_uint64_decode_unsafe(&self->wallclock, ctx);
  fd_bincode_uint16_decode_unsafe(&self->shred_version, ctx);
}
int fd_gossip_contact_info_v1_decode_offsets(fd_gossip_contact_info_v1_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->id_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->gossip_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->tvu_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->tvu_fwd_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->repair_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->tpu_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->tpu_fwd_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->tpu_vote_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->rpc_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->rpc_pubsub_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->serve_repair_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_gossip_socket_addr_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->wallclock_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->shred_version_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_contact_info_v1_new(fd_gossip_contact_info_v1_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_contact_info_v1_t));
  fd_pubkey_new(&self->id);
  fd_gossip_socket_addr_new(&self->gossip);
  fd_gossip_socket_addr_new(&self->tvu);
  fd_gossip_socket_addr_new(&self->tvu_fwd);
  fd_gossip_socket_addr_new(&self->repair);
  fd_gossip_socket_addr_new(&self->tpu);
  fd_gossip_socket_addr_new(&self->tpu_fwd);
  fd_gossip_socket_addr_new(&self->tpu_vote);
  fd_gossip_socket_addr_new(&self->rpc);
  fd_gossip_socket_addr_new(&self->rpc_pubsub);
  fd_gossip_socket_addr_new(&self->serve_repair);
}
void fd_gossip_contact_info_v1_destroy(fd_gossip_contact_info_v1_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->id, ctx);
  fd_gossip_socket_addr_destroy(&self->gossip, ctx);
  fd_gossip_socket_addr_destroy(&self->tvu, ctx);
  fd_gossip_socket_addr_destroy(&self->tvu_fwd, ctx);
  fd_gossip_socket_addr_destroy(&self->repair, ctx);
  fd_gossip_socket_addr_destroy(&self->tpu, ctx);
  fd_gossip_socket_addr_destroy(&self->tpu_fwd, ctx);
  fd_gossip_socket_addr_destroy(&self->tpu_vote, ctx);
  fd_gossip_socket_addr_destroy(&self->rpc, ctx);
  fd_gossip_socket_addr_destroy(&self->rpc_pubsub, ctx);
  fd_gossip_socket_addr_destroy(&self->serve_repair, ctx);
}

ulong fd_gossip_contact_info_v1_footprint( void ){ return FD_GOSSIP_CONTACT_INFO_V1_FOOTPRINT; }
ulong fd_gossip_contact_info_v1_align( void ){ return FD_GOSSIP_CONTACT_INFO_V1_ALIGN; }

void fd_gossip_contact_info_v1_walk(void * w, fd_gossip_contact_info_v1_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_contact_info_v1", level++);
  fd_pubkey_walk(w, &self->id, fun, "id", level);
  fd_gossip_socket_addr_walk(w, &self->gossip, fun, "gossip", level);
  fd_gossip_socket_addr_walk(w, &self->tvu, fun, "tvu", level);
  fd_gossip_socket_addr_walk(w, &self->tvu_fwd, fun, "tvu_fwd", level);
  fd_gossip_socket_addr_walk(w, &self->repair, fun, "repair", level);
  fd_gossip_socket_addr_walk(w, &self->tpu, fun, "tpu", level);
  fd_gossip_socket_addr_walk(w, &self->tpu_fwd, fun, "tpu_fwd", level);
  fd_gossip_socket_addr_walk(w, &self->tpu_vote, fun, "tpu_vote", level);
  fd_gossip_socket_addr_walk(w, &self->rpc, fun, "rpc", level);
  fd_gossip_socket_addr_walk(w, &self->rpc_pubsub, fun, "rpc_pubsub", level);
  fd_gossip_socket_addr_walk(w, &self->serve_repair, fun, "serve_repair", level);
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->shred_version, "shred_version", FD_FLAMENCO_TYPE_USHORT,  "ushort",    level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_contact_info_v1", level--);
}
ulong fd_gossip_contact_info_v1_size(fd_gossip_contact_info_v1_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->id);
  size += fd_gossip_socket_addr_size(&self->gossip);
  size += fd_gossip_socket_addr_size(&self->tvu);
  size += fd_gossip_socket_addr_size(&self->tvu_fwd);
  size += fd_gossip_socket_addr_size(&self->repair);
  size += fd_gossip_socket_addr_size(&self->tpu);
  size += fd_gossip_socket_addr_size(&self->tpu_fwd);
  size += fd_gossip_socket_addr_size(&self->tpu_vote);
  size += fd_gossip_socket_addr_size(&self->rpc);
  size += fd_gossip_socket_addr_size(&self->rpc_pubsub);
  size += fd_gossip_socket_addr_size(&self->serve_repair);
  size += sizeof(ulong);
  size += sizeof(ushort);
  return size;
}

int fd_gossip_contact_info_v1_encode(fd_gossip_contact_info_v1_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->id, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_encode(&self->gossip, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_encode(&self->tvu, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_encode(&self->tvu_fwd, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_encode(&self->repair, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_encode(&self->tpu, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_encode(&self->tpu_fwd, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_encode(&self->tpu_vote, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_encode(&self->rpc, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_encode(&self->rpc_pubsub, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_socket_addr_encode(&self->serve_repair, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->wallclock, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_encode( (ushort)(self->shred_version), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_vote_decode(fd_gossip_vote_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_vote_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_vote_new(self);
  fd_gossip_vote_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_vote_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_flamenco_txn_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_vote_decode_unsafe(fd_gossip_vote_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint8_decode_unsafe(&self->index, ctx);
  fd_pubkey_decode_unsafe(&self->from, ctx);
  fd_flamenco_txn_decode_unsafe(&self->txn, ctx);
  fd_bincode_uint64_decode_unsafe(&self->wallclock, ctx);
}
int fd_gossip_vote_decode_offsets(fd_gossip_vote_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->index_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->from_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->txn_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_flamenco_txn_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->wallclock_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_vote_new(fd_gossip_vote_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_vote_t));
  fd_pubkey_new(&self->from);
  fd_flamenco_txn_new(&self->txn);
}
void fd_gossip_vote_destroy(fd_gossip_vote_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->from, ctx);
  fd_flamenco_txn_destroy(&self->txn, ctx);
}

ulong fd_gossip_vote_footprint( void ){ return FD_GOSSIP_VOTE_FOOTPRINT; }
ulong fd_gossip_vote_align( void ){ return FD_GOSSIP_VOTE_ALIGN; }

void fd_gossip_vote_walk(void * w, fd_gossip_vote_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_vote", level++);
  fun( w, &self->index, "index", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  fd_pubkey_walk(w, &self->from, fun, "from", level);
  fd_flamenco_txn_walk(w, &self->txn, fun, "txn", level);
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_vote", level--);
}
ulong fd_gossip_vote_size(fd_gossip_vote_t const * self) {
  ulong size = 0;
  size += sizeof(char);
  size += fd_pubkey_size(&self->from);
  size += fd_flamenco_txn_size(&self->txn);
  size += sizeof(ulong);
  return size;
}

int fd_gossip_vote_encode(fd_gossip_vote_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint8_encode( (uchar)(self->index), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->from, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_flamenco_txn_encode(&self->txn, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->wallclock, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_lowest_slot_decode(fd_gossip_lowest_slot_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_lowest_slot_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_lowest_slot_new(self);
  fd_gossip_lowest_slot_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_lowest_slot_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ulong slots_len;
  err = fd_bincode_uint64_decode(&slots_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (slots_len != 0) {
    for( ulong i = 0; i < slots_len; ++i) {
      err = fd_bincode_uint64_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_lowest_slot_decode_unsafe(fd_gossip_lowest_slot_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint8_decode_unsafe(&self->u8, ctx);
  fd_pubkey_decode_unsafe(&self->from, ctx);
  fd_bincode_uint64_decode_unsafe(&self->root, ctx);
  fd_bincode_uint64_decode_unsafe(&self->lowest, ctx);
  fd_bincode_uint64_decode_unsafe(&self->slots_len, ctx);
  if (self->slots_len != 0) {
    self->slots = fd_valloc_malloc( ctx->valloc, 8UL, sizeof(ulong)*self->slots_len );
    for( ulong i = 0; i < self->slots_len; ++i) {
      fd_bincode_uint64_decode_unsafe(self->slots + i, ctx);
    }
  } else
    self->slots = NULL;
  fd_bincode_uint64_decode_unsafe(&self->i_dont_know, ctx);
  fd_bincode_uint64_decode_unsafe(&self->wallclock, ctx);
}
int fd_gossip_lowest_slot_decode_offsets(fd_gossip_lowest_slot_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->u8_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->from_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->root_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->lowest_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->slots_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong slots_len;
  err = fd_bincode_uint64_decode(&slots_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (slots_len != 0) {
    for( ulong i = 0; i < slots_len; ++i) {
      err = fd_bincode_uint64_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->i_dont_know_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->wallclock_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_lowest_slot_new(fd_gossip_lowest_slot_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_lowest_slot_t));
  fd_pubkey_new(&self->from);
}
void fd_gossip_lowest_slot_destroy(fd_gossip_lowest_slot_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->from, ctx);
  if (NULL != self->slots) {
    fd_valloc_free( ctx->valloc, self->slots );
    self->slots = NULL;
  }
}

ulong fd_gossip_lowest_slot_footprint( void ){ return FD_GOSSIP_LOWEST_SLOT_FOOTPRINT; }
ulong fd_gossip_lowest_slot_align( void ){ return FD_GOSSIP_LOWEST_SLOT_ALIGN; }

void fd_gossip_lowest_slot_walk(void * w, fd_gossip_lowest_slot_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_lowest_slot", level++);
  fun( w, &self->u8, "u8", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  fd_pubkey_walk(w, &self->from, fun, "from", level);
  fun( w, &self->root, "root", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->lowest, "lowest", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  if (self->slots_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "slots", level++);
    for (ulong i = 0; i < self->slots_len; ++i)
      fun( w, self->slots + i, "slots", FD_FLAMENCO_TYPE_ULONG,   "ulong",   level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "slots", level-- );
  }
  fun( w, &self->i_dont_know, "i_dont_know", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_lowest_slot", level--);
}
ulong fd_gossip_lowest_slot_size(fd_gossip_lowest_slot_t const * self) {
  ulong size = 0;
  size += sizeof(char);
  size += fd_pubkey_size(&self->from);
  size += sizeof(ulong);
  size += sizeof(ulong);
  do {
    size += sizeof(ulong);
    size += self->slots_len * sizeof(ulong);
  } while(0);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_gossip_lowest_slot_encode(fd_gossip_lowest_slot_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint8_encode( (uchar)(self->u8), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->from, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->root, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->lowest, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->slots_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->slots_len != 0) {
    for (ulong i = 0; i < self->slots_len; ++i) {
      err = fd_bincode_uint64_encode(self->slots[i], ctx);
    }
  }
  err = fd_bincode_uint64_encode(self->i_dont_know, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->wallclock, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_slot_hashes_decode(fd_gossip_slot_hashes_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_slot_hashes_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_slot_hashes_new(self);
  fd_gossip_slot_hashes_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_slot_hashes_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong hashes_len;
  err = fd_bincode_uint64_decode(&hashes_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (hashes_len != 0) {
    for( ulong i = 0; i < hashes_len; ++i) {
      err = fd_slot_hash_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_slot_hashes_decode_unsafe(fd_gossip_slot_hashes_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->from, ctx);
  fd_bincode_uint64_decode_unsafe(&self->hashes_len, ctx);
  if (self->hashes_len != 0) {
    self->hashes = (fd_slot_hash_t *)fd_valloc_malloc( ctx->valloc, FD_SLOT_HASH_ALIGN, FD_SLOT_HASH_FOOTPRINT*self->hashes_len);
    for( ulong i = 0; i < self->hashes_len; ++i) {
      fd_slot_hash_new(self->hashes + i);
      fd_slot_hash_decode_unsafe(self->hashes + i, ctx);
    }
  } else
    self->hashes = NULL;
  fd_bincode_uint64_decode_unsafe(&self->wallclock, ctx);
}
int fd_gossip_slot_hashes_decode_offsets(fd_gossip_slot_hashes_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->from_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->hashes_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong hashes_len;
  err = fd_bincode_uint64_decode(&hashes_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (hashes_len != 0) {
    for( ulong i = 0; i < hashes_len; ++i) {
      err = fd_slot_hash_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->wallclock_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_slot_hashes_new(fd_gossip_slot_hashes_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_slot_hashes_t));
  fd_pubkey_new(&self->from);
}
void fd_gossip_slot_hashes_destroy(fd_gossip_slot_hashes_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->from, ctx);
  if (NULL != self->hashes) {
    for (ulong i = 0; i < self->hashes_len; ++i)
      fd_slot_hash_destroy(self->hashes + i, ctx);
    fd_valloc_free( ctx->valloc, self->hashes );
    self->hashes = NULL;
  }
}

ulong fd_gossip_slot_hashes_footprint( void ){ return FD_GOSSIP_SLOT_HASHES_FOOTPRINT; }
ulong fd_gossip_slot_hashes_align( void ){ return FD_GOSSIP_SLOT_HASHES_ALIGN; }

void fd_gossip_slot_hashes_walk(void * w, fd_gossip_slot_hashes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_slot_hashes", level++);
  fd_pubkey_walk(w, &self->from, fun, "from", level);
  if (self->hashes_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "hashes", level++);
    for (ulong i = 0; i < self->hashes_len; ++i)
      fd_slot_hash_walk(w, self->hashes + i, fun, "slot_hash", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "hashes", level-- );
  }
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_slot_hashes", level--);
}
ulong fd_gossip_slot_hashes_size(fd_gossip_slot_hashes_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->from);
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->hashes_len; ++i)
      size += fd_slot_hash_size(self->hashes + i);
  } while(0);
  size += sizeof(ulong);
  return size;
}

int fd_gossip_slot_hashes_encode(fd_gossip_slot_hashes_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->from, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->hashes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->hashes_len != 0) {
    for (ulong i = 0; i < self->hashes_len; ++i) {
      err = fd_slot_hash_encode(self->hashes + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(self->wallclock, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_slots_decode(fd_gossip_slots_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_slots_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_slots_new(self);
  fd_gossip_slots_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_slots_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_gossip_bitvec_u8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_slots_decode_unsafe(fd_gossip_slots_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->first_slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->num, ctx);
  fd_gossip_bitvec_u8_decode_unsafe(&self->slots, ctx);
}
int fd_gossip_slots_decode_offsets(fd_gossip_slots_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->first_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->num_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->slots_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_gossip_bitvec_u8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_slots_new(fd_gossip_slots_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_slots_t));
  fd_gossip_bitvec_u8_new(&self->slots);
}
void fd_gossip_slots_destroy(fd_gossip_slots_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_gossip_bitvec_u8_destroy(&self->slots, ctx);
}

ulong fd_gossip_slots_footprint( void ){ return FD_GOSSIP_SLOTS_FOOTPRINT; }
ulong fd_gossip_slots_align( void ){ return FD_GOSSIP_SLOTS_ALIGN; }

void fd_gossip_slots_walk(void * w, fd_gossip_slots_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_slots", level++);
  fun( w, &self->first_slot, "first_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->num, "num", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fd_gossip_bitvec_u8_walk(w, &self->slots, fun, "slots", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_slots", level--);
}
ulong fd_gossip_slots_size(fd_gossip_slots_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_gossip_bitvec_u8_size(&self->slots);
  return size;
}

int fd_gossip_slots_encode(fd_gossip_slots_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->first_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->num, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_bitvec_u8_encode(&self->slots, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_flate2_slots_decode(fd_gossip_flate2_slots_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_flate2_slots_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_flate2_slots_new(self);
  fd_gossip_flate2_slots_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_flate2_slots_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ulong compressed_len;
  err = fd_bincode_uint64_decode(&compressed_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (compressed_len != 0) {
    err = fd_bincode_bytes_decode_preflight(compressed_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_flate2_slots_decode_unsafe(fd_gossip_flate2_slots_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->first_slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->num, ctx);
  fd_bincode_uint64_decode_unsafe(&self->compressed_len, ctx);
  if (self->compressed_len != 0) {
    self->compressed = fd_valloc_malloc( ctx->valloc, 8UL, self->compressed_len );
    fd_bincode_bytes_decode_unsafe(self->compressed, self->compressed_len, ctx);
  } else
    self->compressed = NULL;
}
int fd_gossip_flate2_slots_decode_offsets(fd_gossip_flate2_slots_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->first_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->num_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->compressed_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong compressed_len;
  err = fd_bincode_uint64_decode(&compressed_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (compressed_len != 0) {
    err = fd_bincode_bytes_decode_preflight(compressed_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_flate2_slots_new(fd_gossip_flate2_slots_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_flate2_slots_t));
}
void fd_gossip_flate2_slots_destroy(fd_gossip_flate2_slots_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->compressed) {
    fd_valloc_free( ctx->valloc, self->compressed );
    self->compressed = NULL;
  }
}

ulong fd_gossip_flate2_slots_footprint( void ){ return FD_GOSSIP_FLATE2_SLOTS_FOOTPRINT; }
ulong fd_gossip_flate2_slots_align( void ){ return FD_GOSSIP_FLATE2_SLOTS_ALIGN; }

void fd_gossip_flate2_slots_walk(void * w, fd_gossip_flate2_slots_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_flate2_slots", level++);
  fun( w, &self->first_slot, "first_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->num, "num", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self->compressed, "compressed", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_flate2_slots", level--);
}
ulong fd_gossip_flate2_slots_size(fd_gossip_flate2_slots_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  do {
    size += sizeof(ulong);
    size += self->compressed_len;
  } while(0);
  return size;
}

int fd_gossip_flate2_slots_encode(fd_gossip_flate2_slots_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->first_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->num, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->compressed_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->compressed_len != 0) {
    err = fd_bincode_bytes_encode(self->compressed, self->compressed_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_gossip_slots_enum_is_flate2(fd_gossip_slots_enum_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_gossip_slots_enum_is_uncompressed(fd_gossip_slots_enum_t const * self) {
  return self->discriminant == 1;
}
void fd_gossip_slots_enum_inner_new(fd_gossip_slots_enum_inner_t* self, uint discriminant);
int fd_gossip_slots_enum_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_flate2_slots_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_gossip_slots_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_gossip_slots_enum_inner_decode_unsafe(fd_gossip_slots_enum_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_gossip_flate2_slots_decode_unsafe(&self->flate2, ctx);
    break;
  }
  case 1: {
    fd_gossip_slots_decode_unsafe(&self->uncompressed, ctx);
    break;
  }
  }
}
int fd_gossip_slots_enum_decode(fd_gossip_slots_enum_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_slots_enum_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_slots_enum_new(self);
  fd_gossip_slots_enum_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_slots_enum_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_gossip_slots_enum_inner_decode_preflight(discriminant, ctx);
}
void fd_gossip_slots_enum_decode_unsafe(fd_gossip_slots_enum_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_gossip_slots_enum_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_gossip_slots_enum_inner_new(fd_gossip_slots_enum_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_gossip_flate2_slots_new(&self->flate2);
    break;
  }
  case 1: {
    fd_gossip_slots_new(&self->uncompressed);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_gossip_slots_enum_new_disc(fd_gossip_slots_enum_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_gossip_slots_enum_inner_new(&self->inner, self->discriminant);
}
void fd_gossip_slots_enum_new(fd_gossip_slots_enum_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_gossip_slots_enum_new_disc(self, UINT_MAX);
}
void fd_gossip_slots_enum_inner_destroy(fd_gossip_slots_enum_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_gossip_flate2_slots_destroy(&self->flate2, ctx);
    break;
  }
  case 1: {
    fd_gossip_slots_destroy(&self->uncompressed, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_gossip_slots_enum_destroy(fd_gossip_slots_enum_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_gossip_slots_enum_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_gossip_slots_enum_footprint( void ){ return FD_GOSSIP_SLOTS_ENUM_FOOTPRINT; }
ulong fd_gossip_slots_enum_align( void ){ return FD_GOSSIP_SLOTS_ENUM_ALIGN; }

void fd_gossip_slots_enum_walk(void * w, fd_gossip_slots_enum_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_slots_enum", level++);
  switch (self->discriminant) {
  case 0: {
    fd_gossip_flate2_slots_walk(w, &self->inner.flate2, fun, "flate2", level);
    break;
  }
  case 1: {
    fd_gossip_slots_walk(w, &self->inner.uncompressed, fun, "uncompressed", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_slots_enum", level--);
}
ulong fd_gossip_slots_enum_size(fd_gossip_slots_enum_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_gossip_flate2_slots_size(&self->inner.flate2);
    break;
  }
  case 1: {
    size += fd_gossip_slots_size(&self->inner.uncompressed);
    break;
  }
  }
  return size;
}

int fd_gossip_slots_enum_inner_encode(fd_gossip_slots_enum_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_flate2_slots_encode(&self->flate2, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 1: {
    err = fd_gossip_slots_encode(&self->uncompressed, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_slots_enum_encode(fd_gossip_slots_enum_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_gossip_slots_enum_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_gossip_epoch_slots_decode(fd_gossip_epoch_slots_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_epoch_slots_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_epoch_slots_new(self);
  fd_gossip_epoch_slots_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_epoch_slots_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong slots_len;
  err = fd_bincode_uint64_decode(&slots_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (slots_len != 0) {
    for( ulong i = 0; i < slots_len; ++i) {
      err = fd_gossip_slots_enum_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_epoch_slots_decode_unsafe(fd_gossip_epoch_slots_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint8_decode_unsafe(&self->u8, ctx);
  fd_pubkey_decode_unsafe(&self->from, ctx);
  fd_bincode_uint64_decode_unsafe(&self->slots_len, ctx);
  if (self->slots_len != 0) {
    self->slots = (fd_gossip_slots_enum_t *)fd_valloc_malloc( ctx->valloc, FD_GOSSIP_SLOTS_ENUM_ALIGN, FD_GOSSIP_SLOTS_ENUM_FOOTPRINT*self->slots_len);
    for( ulong i = 0; i < self->slots_len; ++i) {
      fd_gossip_slots_enum_new(self->slots + i);
      fd_gossip_slots_enum_decode_unsafe(self->slots + i, ctx);
    }
  } else
    self->slots = NULL;
  fd_bincode_uint64_decode_unsafe(&self->wallclock, ctx);
}
int fd_gossip_epoch_slots_decode_offsets(fd_gossip_epoch_slots_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->u8_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->from_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->slots_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong slots_len;
  err = fd_bincode_uint64_decode(&slots_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (slots_len != 0) {
    for( ulong i = 0; i < slots_len; ++i) {
      err = fd_gossip_slots_enum_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->wallclock_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_epoch_slots_new(fd_gossip_epoch_slots_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_epoch_slots_t));
  fd_pubkey_new(&self->from);
}
void fd_gossip_epoch_slots_destroy(fd_gossip_epoch_slots_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->from, ctx);
  if (NULL != self->slots) {
    for (ulong i = 0; i < self->slots_len; ++i)
      fd_gossip_slots_enum_destroy(self->slots + i, ctx);
    fd_valloc_free( ctx->valloc, self->slots );
    self->slots = NULL;
  }
}

ulong fd_gossip_epoch_slots_footprint( void ){ return FD_GOSSIP_EPOCH_SLOTS_FOOTPRINT; }
ulong fd_gossip_epoch_slots_align( void ){ return FD_GOSSIP_EPOCH_SLOTS_ALIGN; }

void fd_gossip_epoch_slots_walk(void * w, fd_gossip_epoch_slots_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_epoch_slots", level++);
  fun( w, &self->u8, "u8", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  fd_pubkey_walk(w, &self->from, fun, "from", level);
  if (self->slots_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "slots", level++);
    for (ulong i = 0; i < self->slots_len; ++i)
      fd_gossip_slots_enum_walk(w, self->slots + i, fun, "gossip_slots_enum", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "slots", level-- );
  }
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_epoch_slots", level--);
}
ulong fd_gossip_epoch_slots_size(fd_gossip_epoch_slots_t const * self) {
  ulong size = 0;
  size += sizeof(char);
  size += fd_pubkey_size(&self->from);
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->slots_len; ++i)
      size += fd_gossip_slots_enum_size(self->slots + i);
  } while(0);
  size += sizeof(ulong);
  return size;
}

int fd_gossip_epoch_slots_encode(fd_gossip_epoch_slots_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint8_encode( (uchar)(self->u8), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->from, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->slots_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->slots_len != 0) {
    for (ulong i = 0; i < self->slots_len; ++i) {
      err = fd_gossip_slots_enum_encode(self->slots + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(self->wallclock, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_version_v1_decode(fd_gossip_version_v1_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_version_v1_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_version_v1_new(self);
  fd_gossip_version_v1_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_version_v1_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint32_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_version_v1_decode_unsafe(fd_gossip_version_v1_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->from, ctx);
  fd_bincode_uint64_decode_unsafe(&self->wallclock, ctx);
  fd_bincode_uint16_decode_unsafe(&self->major, ctx);
  fd_bincode_uint16_decode_unsafe(&self->minor, ctx);
  fd_bincode_uint16_decode_unsafe(&self->patch, ctx);
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_commit = !!o;
    if( o ) {
      fd_bincode_uint32_decode_unsafe( &self->commit, ctx );
    }
  }
}
int fd_gossip_version_v1_decode_offsets(fd_gossip_version_v1_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->from_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->wallclock_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->major_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->minor_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->patch_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->commit_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint32_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_version_v1_new(fd_gossip_version_v1_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_version_v1_t));
  fd_pubkey_new(&self->from);
}
void fd_gossip_version_v1_destroy(fd_gossip_version_v1_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->from, ctx);
  if( self->has_commit ) {
    self->has_commit = 0;
  }
}

ulong fd_gossip_version_v1_footprint( void ){ return FD_GOSSIP_VERSION_V1_FOOTPRINT; }
ulong fd_gossip_version_v1_align( void ){ return FD_GOSSIP_VERSION_V1_ALIGN; }

void fd_gossip_version_v1_walk(void * w, fd_gossip_version_v1_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_version_v1", level++);
  fd_pubkey_walk(w, &self->from, fun, "from", level);
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->major, "major", FD_FLAMENCO_TYPE_USHORT,  "ushort",    level );
  fun( w, &self->minor, "minor", FD_FLAMENCO_TYPE_USHORT,  "ushort",    level );
  fun( w, &self->patch, "patch", FD_FLAMENCO_TYPE_USHORT,  "ushort",    level );
  if( !self->has_commit ) {
    fun( w, NULL, "commit", FD_FLAMENCO_TYPE_NULL, "uint", level );
  } else {
    fun( w, &self->commit, "commit", FD_FLAMENCO_TYPE_UINT, "uint", level );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_version_v1", level--);
}
ulong fd_gossip_version_v1_size(fd_gossip_version_v1_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->from);
  size += sizeof(ulong);
  size += sizeof(ushort);
  size += sizeof(ushort);
  size += sizeof(ushort);
  size += sizeof(char);
  if( self->has_commit ) {
    size += sizeof(uint);
  }
  return size;
}

int fd_gossip_version_v1_encode(fd_gossip_version_v1_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->from, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->wallclock, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_encode( (ushort)(self->major), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_encode( (ushort)(self->minor), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_encode( (ushort)(self->patch), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bool_encode( self->has_commit, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_commit ) {
    err = fd_bincode_uint32_encode( self->commit, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_version_v2_decode(fd_gossip_version_v2_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_version_v2_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_version_v2_new(self);
  fd_gossip_version_v2_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_version_v2_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint32_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_version_v2_decode_unsafe(fd_gossip_version_v2_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->from, ctx);
  fd_bincode_uint64_decode_unsafe(&self->wallclock, ctx);
  fd_bincode_uint16_decode_unsafe(&self->major, ctx);
  fd_bincode_uint16_decode_unsafe(&self->minor, ctx);
  fd_bincode_uint16_decode_unsafe(&self->patch, ctx);
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_commit = !!o;
    if( o ) {
      fd_bincode_uint32_decode_unsafe( &self->commit, ctx );
    }
  }
  fd_bincode_uint32_decode_unsafe(&self->feature_set, ctx);
}
int fd_gossip_version_v2_decode_offsets(fd_gossip_version_v2_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->from_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->wallclock_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->major_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->minor_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->patch_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->commit_off = (uint)((ulong)ctx->data - (ulong)data);
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint32_decode_preflight( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->feature_set_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_version_v2_new(fd_gossip_version_v2_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_version_v2_t));
  fd_pubkey_new(&self->from);
}
void fd_gossip_version_v2_destroy(fd_gossip_version_v2_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->from, ctx);
  if( self->has_commit ) {
    self->has_commit = 0;
  }
}

ulong fd_gossip_version_v2_footprint( void ){ return FD_GOSSIP_VERSION_V2_FOOTPRINT; }
ulong fd_gossip_version_v2_align( void ){ return FD_GOSSIP_VERSION_V2_ALIGN; }

void fd_gossip_version_v2_walk(void * w, fd_gossip_version_v2_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_version_v2", level++);
  fd_pubkey_walk(w, &self->from, fun, "from", level);
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->major, "major", FD_FLAMENCO_TYPE_USHORT,  "ushort",    level );
  fun( w, &self->minor, "minor", FD_FLAMENCO_TYPE_USHORT,  "ushort",    level );
  fun( w, &self->patch, "patch", FD_FLAMENCO_TYPE_USHORT,  "ushort",    level );
  if( !self->has_commit ) {
    fun( w, NULL, "commit", FD_FLAMENCO_TYPE_NULL, "uint", level );
  } else {
    fun( w, &self->commit, "commit", FD_FLAMENCO_TYPE_UINT, "uint", level );
  }
  fun( w, &self->feature_set, "feature_set", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_version_v2", level--);
}
ulong fd_gossip_version_v2_size(fd_gossip_version_v2_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->from);
  size += sizeof(ulong);
  size += sizeof(ushort);
  size += sizeof(ushort);
  size += sizeof(ushort);
  size += sizeof(char);
  if( self->has_commit ) {
    size += sizeof(uint);
  }
  size += sizeof(uint);
  return size;
}

int fd_gossip_version_v2_encode(fd_gossip_version_v2_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->from, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->wallclock, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_encode( (ushort)(self->major), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_encode( (ushort)(self->minor), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_encode( (ushort)(self->patch), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bool_encode( self->has_commit, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_commit ) {
    err = fd_bincode_uint32_encode( self->commit, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint32_encode( self->feature_set, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_version_v3_decode(fd_gossip_version_v3_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_version_v3_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_version_v3_new(self);
  fd_gossip_version_v3_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_version_v3_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  do { ushort _tmp; err = fd_bincode_compact_u16_decode(&_tmp, ctx); } while(0);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  do { ushort _tmp; err = fd_bincode_compact_u16_decode(&_tmp, ctx); } while(0);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  do { ushort _tmp; err = fd_bincode_compact_u16_decode(&_tmp, ctx); } while(0);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  do { ushort _tmp; err = fd_bincode_compact_u16_decode(&_tmp, ctx); } while(0);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_version_v3_decode_unsafe(fd_gossip_version_v3_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_compact_u16_decode_unsafe(&self->major, ctx);
  fd_bincode_compact_u16_decode_unsafe(&self->minor, ctx);
  fd_bincode_compact_u16_decode_unsafe(&self->patch, ctx);
  fd_bincode_uint32_decode_unsafe(&self->commit, ctx);
  fd_bincode_uint32_decode_unsafe(&self->feature_set, ctx);
  fd_bincode_compact_u16_decode_unsafe(&self->client, ctx);
}
int fd_gossip_version_v3_decode_offsets(fd_gossip_version_v3_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->major_off = (uint)((ulong)ctx->data - (ulong)data);
  do { ushort _tmp; err = fd_bincode_compact_u16_decode(&_tmp, ctx); } while(0);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->minor_off = (uint)((ulong)ctx->data - (ulong)data);
  do { ushort _tmp; err = fd_bincode_compact_u16_decode(&_tmp, ctx); } while(0);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->patch_off = (uint)((ulong)ctx->data - (ulong)data);
  do { ushort _tmp; err = fd_bincode_compact_u16_decode(&_tmp, ctx); } while(0);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->commit_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->feature_set_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->client_off = (uint)((ulong)ctx->data - (ulong)data);
  do { ushort _tmp; err = fd_bincode_compact_u16_decode(&_tmp, ctx); } while(0);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_version_v3_new(fd_gossip_version_v3_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_version_v3_t));
}
void fd_gossip_version_v3_destroy(fd_gossip_version_v3_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_gossip_version_v3_footprint( void ){ return FD_GOSSIP_VERSION_V3_FOOTPRINT; }
ulong fd_gossip_version_v3_align( void ){ return FD_GOSSIP_VERSION_V3_ALIGN; }

void fd_gossip_version_v3_walk(void * w, fd_gossip_version_v3_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_version_v3", level++);
  fun( w, &self->major, "major", FD_FLAMENCO_TYPE_USHORT,  "ushort",    level );
  fun( w, &self->minor, "minor", FD_FLAMENCO_TYPE_USHORT,  "ushort",    level );
  fun( w, &self->patch, "patch", FD_FLAMENCO_TYPE_USHORT,  "ushort",    level );
  fun( w, &self->commit, "commit", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
  fun( w, &self->feature_set, "feature_set", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
  fun( w, &self->client, "client", FD_FLAMENCO_TYPE_USHORT,  "ushort",    level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_version_v3", level--);
}
ulong fd_gossip_version_v3_size(fd_gossip_version_v3_t const * self) {
  ulong size = 0;
  size += fd_bincode_compact_u16_size(&self->major);
  size += fd_bincode_compact_u16_size(&self->minor);
  size += fd_bincode_compact_u16_size(&self->patch);
  size += sizeof(uint);
  size += sizeof(uint);
  size += fd_bincode_compact_u16_size(&self->client);
  return size;
}

int fd_gossip_version_v3_encode(fd_gossip_version_v3_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint16_encode( (ushort)(self->major), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_encode( (ushort)(self->minor), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_encode( (ushort)(self->patch), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_encode( self->commit, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_encode( self->feature_set, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_encode( (ushort)(self->client), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_node_instance_decode(fd_gossip_node_instance_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_node_instance_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_node_instance_new(self);
  fd_gossip_node_instance_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_node_instance_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_node_instance_decode_unsafe(fd_gossip_node_instance_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->from, ctx);
  fd_bincode_uint64_decode_unsafe(&self->wallclock, ctx);
  fd_bincode_uint64_decode_unsafe(&self->timestamp, ctx);
  fd_bincode_uint64_decode_unsafe(&self->token, ctx);
}
int fd_gossip_node_instance_decode_offsets(fd_gossip_node_instance_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->from_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->wallclock_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->timestamp_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->token_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_node_instance_new(fd_gossip_node_instance_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_node_instance_t));
  fd_pubkey_new(&self->from);
}
void fd_gossip_node_instance_destroy(fd_gossip_node_instance_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->from, ctx);
}

ulong fd_gossip_node_instance_footprint( void ){ return FD_GOSSIP_NODE_INSTANCE_FOOTPRINT; }
ulong fd_gossip_node_instance_align( void ){ return FD_GOSSIP_NODE_INSTANCE_ALIGN; }

void fd_gossip_node_instance_walk(void * w, fd_gossip_node_instance_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_node_instance", level++);
  fd_pubkey_walk(w, &self->from, fun, "from", level);
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->timestamp, "timestamp", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->token, "token", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_node_instance", level--);
}
ulong fd_gossip_node_instance_size(fd_gossip_node_instance_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->from);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_gossip_node_instance_encode(fd_gossip_node_instance_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->from, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->wallclock, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->token, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_duplicate_shred_decode(fd_gossip_duplicate_shred_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_duplicate_shred_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_duplicate_shred_new(self);
  fd_gossip_duplicate_shred_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_duplicate_shred_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong chunk_len;
  err = fd_bincode_uint64_decode(&chunk_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (chunk_len != 0) {
    err = fd_bincode_bytes_decode_preflight(chunk_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_duplicate_shred_decode_unsafe(fd_gossip_duplicate_shred_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint16_decode_unsafe(&self->version, ctx);
  fd_pubkey_decode_unsafe(&self->from, ctx);
  fd_bincode_uint64_decode_unsafe(&self->wallclock, ctx);
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
  fd_bincode_uint32_decode_unsafe(&self->shred_index, ctx);
  fd_bincode_uint8_decode_unsafe(&self->shred_variant, ctx);
  fd_bincode_uint8_decode_unsafe(&self->chunk_cnt, ctx);
  fd_bincode_uint8_decode_unsafe(&self->chunk_idx, ctx);
  fd_bincode_uint64_decode_unsafe(&self->chunk_len, ctx);
  if (self->chunk_len != 0) {
    self->chunk = fd_valloc_malloc( ctx->valloc, 8UL, self->chunk_len );
    fd_bincode_bytes_decode_unsafe(self->chunk, self->chunk_len, ctx);
  } else
    self->chunk = NULL;
}
int fd_gossip_duplicate_shred_decode_offsets(fd_gossip_duplicate_shred_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->version_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->from_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->wallclock_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->shred_index_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->shred_variant_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->chunk_cnt_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->chunk_idx_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->chunk_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong chunk_len;
  err = fd_bincode_uint64_decode(&chunk_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (chunk_len != 0) {
    err = fd_bincode_bytes_decode_preflight(chunk_len, ctx);
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_duplicate_shred_new(fd_gossip_duplicate_shred_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_duplicate_shred_t));
  fd_pubkey_new(&self->from);
}
void fd_gossip_duplicate_shred_destroy(fd_gossip_duplicate_shred_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->from, ctx);
  if (NULL != self->chunk) {
    fd_valloc_free( ctx->valloc, self->chunk );
    self->chunk = NULL;
  }
}

ulong fd_gossip_duplicate_shred_footprint( void ){ return FD_GOSSIP_DUPLICATE_SHRED_FOOTPRINT; }
ulong fd_gossip_duplicate_shred_align( void ){ return FD_GOSSIP_DUPLICATE_SHRED_ALIGN; }

void fd_gossip_duplicate_shred_walk(void * w, fd_gossip_duplicate_shred_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_duplicate_shred", level++);
  fun( w, &self->version, "version", FD_FLAMENCO_TYPE_USHORT,  "ushort",    level );
  fd_pubkey_walk(w, &self->from, fun, "from", level);
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->shred_index, "shred_index", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
  fun( w, &self->shred_variant, "shred_variant", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  fun( w, &self->chunk_cnt, "chunk_cnt", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  fun( w, &self->chunk_idx, "chunk_idx", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  fun(w, self->chunk, "chunk", FD_FLAMENCO_TYPE_UCHAR, "uchar", level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_duplicate_shred", level--);
}
ulong fd_gossip_duplicate_shred_size(fd_gossip_duplicate_shred_t const * self) {
  ulong size = 0;
  size += sizeof(ushort);
  size += fd_pubkey_size(&self->from);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(uint);
  size += sizeof(char);
  size += sizeof(char);
  size += sizeof(char);
  do {
    size += sizeof(ulong);
    size += self->chunk_len;
  } while(0);
  return size;
}

int fd_gossip_duplicate_shred_encode(fd_gossip_duplicate_shred_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint16_encode( (ushort)(self->version), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->from, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->wallclock, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_encode( self->shred_index, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->shred_variant), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->chunk_cnt), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->chunk_idx), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->chunk_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->chunk_len != 0) {
    err = fd_bincode_bytes_encode(self->chunk, self->chunk_len, ctx);
    if ( FD_UNLIKELY(err) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_incremental_snapshot_hashes_decode(fd_gossip_incremental_snapshot_hashes_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_incremental_snapshot_hashes_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_incremental_snapshot_hashes_new(self);
  fd_gossip_incremental_snapshot_hashes_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_incremental_snapshot_hashes_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_slot_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong hashes_len;
  err = fd_bincode_uint64_decode(&hashes_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (hashes_len != 0) {
    for( ulong i = 0; i < hashes_len; ++i) {
      err = fd_slot_hash_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_incremental_snapshot_hashes_decode_unsafe(fd_gossip_incremental_snapshot_hashes_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->from, ctx);
  fd_slot_hash_decode_unsafe(&self->base_hash, ctx);
  fd_bincode_uint64_decode_unsafe(&self->hashes_len, ctx);
  if (self->hashes_len != 0) {
    self->hashes = (fd_slot_hash_t *)fd_valloc_malloc( ctx->valloc, FD_SLOT_HASH_ALIGN, FD_SLOT_HASH_FOOTPRINT*self->hashes_len);
    for( ulong i = 0; i < self->hashes_len; ++i) {
      fd_slot_hash_new(self->hashes + i);
      fd_slot_hash_decode_unsafe(self->hashes + i, ctx);
    }
  } else
    self->hashes = NULL;
  fd_bincode_uint64_decode_unsafe(&self->wallclock, ctx);
}
int fd_gossip_incremental_snapshot_hashes_decode_offsets(fd_gossip_incremental_snapshot_hashes_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->from_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->base_hash_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_slot_hash_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->hashes_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong hashes_len;
  err = fd_bincode_uint64_decode(&hashes_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (hashes_len != 0) {
    for( ulong i = 0; i < hashes_len; ++i) {
      err = fd_slot_hash_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->wallclock_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_incremental_snapshot_hashes_new(fd_gossip_incremental_snapshot_hashes_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_incremental_snapshot_hashes_t));
  fd_pubkey_new(&self->from);
  fd_slot_hash_new(&self->base_hash);
}
void fd_gossip_incremental_snapshot_hashes_destroy(fd_gossip_incremental_snapshot_hashes_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->from, ctx);
  fd_slot_hash_destroy(&self->base_hash, ctx);
  if (NULL != self->hashes) {
    for (ulong i = 0; i < self->hashes_len; ++i)
      fd_slot_hash_destroy(self->hashes + i, ctx);
    fd_valloc_free( ctx->valloc, self->hashes );
    self->hashes = NULL;
  }
}

ulong fd_gossip_incremental_snapshot_hashes_footprint( void ){ return FD_GOSSIP_INCREMENTAL_SNAPSHOT_HASHES_FOOTPRINT; }
ulong fd_gossip_incremental_snapshot_hashes_align( void ){ return FD_GOSSIP_INCREMENTAL_SNAPSHOT_HASHES_ALIGN; }

void fd_gossip_incremental_snapshot_hashes_walk(void * w, fd_gossip_incremental_snapshot_hashes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_incremental_snapshot_hashes", level++);
  fd_pubkey_walk(w, &self->from, fun, "from", level);
  fd_slot_hash_walk(w, &self->base_hash, fun, "base_hash", level);
  if (self->hashes_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "hashes", level++);
    for (ulong i = 0; i < self->hashes_len; ++i)
      fd_slot_hash_walk(w, self->hashes + i, fun, "slot_hash", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "hashes", level-- );
  }
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_incremental_snapshot_hashes", level--);
}
ulong fd_gossip_incremental_snapshot_hashes_size(fd_gossip_incremental_snapshot_hashes_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->from);
  size += fd_slot_hash_size(&self->base_hash);
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->hashes_len; ++i)
      size += fd_slot_hash_size(self->hashes + i);
  } while(0);
  size += sizeof(ulong);
  return size;
}

int fd_gossip_incremental_snapshot_hashes_encode(fd_gossip_incremental_snapshot_hashes_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->from, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_slot_hash_encode(&self->base_hash, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->hashes_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->hashes_len != 0) {
    for (ulong i = 0; i < self->hashes_len; ++i) {
      err = fd_slot_hash_encode(self->hashes + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_uint64_encode(self->wallclock, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_socket_entry_decode(fd_gossip_socket_entry_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_socket_entry_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_socket_entry_new(self);
  fd_gossip_socket_entry_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_socket_entry_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  do { ushort _tmp; err = fd_bincode_compact_u16_decode(&_tmp, ctx); } while(0);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_socket_entry_decode_unsafe(fd_gossip_socket_entry_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint8_decode_unsafe(&self->key, ctx);
  fd_bincode_uint8_decode_unsafe(&self->index, ctx);
  fd_bincode_compact_u16_decode_unsafe(&self->offset, ctx);
}
int fd_gossip_socket_entry_decode_offsets(fd_gossip_socket_entry_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->key_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->index_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->offset_off = (uint)((ulong)ctx->data - (ulong)data);
  do { ushort _tmp; err = fd_bincode_compact_u16_decode(&_tmp, ctx); } while(0);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_socket_entry_new(fd_gossip_socket_entry_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_socket_entry_t));
}
void fd_gossip_socket_entry_destroy(fd_gossip_socket_entry_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_gossip_socket_entry_footprint( void ){ return FD_GOSSIP_SOCKET_ENTRY_FOOTPRINT; }
ulong fd_gossip_socket_entry_align( void ){ return FD_GOSSIP_SOCKET_ENTRY_ALIGN; }

void fd_gossip_socket_entry_walk(void * w, fd_gossip_socket_entry_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_socket_entry", level++);
  fun( w, &self->key, "key", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  fun( w, &self->index, "index", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  fun( w, &self->offset, "offset", FD_FLAMENCO_TYPE_USHORT,  "ushort",    level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_socket_entry", level--);
}
ulong fd_gossip_socket_entry_size(fd_gossip_socket_entry_t const * self) {
  ulong size = 0;
  size += sizeof(char);
  size += sizeof(char);
  size += fd_bincode_compact_u16_size(&self->offset);
  return size;
}

int fd_gossip_socket_entry_encode(fd_gossip_socket_entry_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint8_encode( (uchar)(self->key), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->index), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_encode( (ushort)(self->offset), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_contact_info_v2_decode(fd_gossip_contact_info_v2_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_contact_info_v2_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_contact_info_v2_new(self);
  fd_gossip_contact_info_v2_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_contact_info_v2_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_varint_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_gossip_version_v3_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ushort addrs_len;
  err = fd_bincode_compact_u16_decode(&addrs_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (addrs_len != 0) {
    for( ulong i = 0; i < addrs_len; ++i) {
      err = fd_gossip_ip_addr_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  ushort sockets_len;
  err = fd_bincode_compact_u16_decode(&sockets_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (sockets_len != 0) {
    for( ulong i = 0; i < sockets_len; ++i) {
      err = fd_gossip_socket_entry_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  ushort extensions_len;
  err = fd_bincode_compact_u16_decode(&extensions_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (extensions_len != 0) {
    for( ulong i = 0; i < extensions_len; ++i) {
      err = fd_bincode_uint32_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_contact_info_v2_decode_unsafe(fd_gossip_contact_info_v2_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->from, ctx);
  fd_bincode_varint_decode_unsafe(&self->wallclock, ctx);
  fd_bincode_uint64_decode_unsafe(&self->outset, ctx);
  fd_bincode_uint16_decode_unsafe(&self->shred_version, ctx);
  fd_gossip_version_v3_decode_unsafe(&self->version, ctx);
  fd_bincode_compact_u16_decode_unsafe(&self->addrs_len, ctx);
  if (self->addrs_len != 0) {
    self->addrs = (fd_gossip_ip_addr_t *)fd_valloc_malloc( ctx->valloc, FD_GOSSIP_IP_ADDR_ALIGN, FD_GOSSIP_IP_ADDR_FOOTPRINT*self->addrs_len);
    for( ulong i = 0; i < self->addrs_len; ++i) {
      fd_gossip_ip_addr_new(self->addrs + i);
      fd_gossip_ip_addr_decode_unsafe(self->addrs + i, ctx);
    }
  } else
    self->addrs = NULL;
  fd_bincode_compact_u16_decode_unsafe(&self->sockets_len, ctx);
  if (self->sockets_len != 0) {
    self->sockets = (fd_gossip_socket_entry_t *)fd_valloc_malloc( ctx->valloc, FD_GOSSIP_SOCKET_ENTRY_ALIGN, FD_GOSSIP_SOCKET_ENTRY_FOOTPRINT*self->sockets_len);
    for( ulong i = 0; i < self->sockets_len; ++i) {
      fd_gossip_socket_entry_new(self->sockets + i);
      fd_gossip_socket_entry_decode_unsafe(self->sockets + i, ctx);
    }
  } else
    self->sockets = NULL;
  fd_bincode_compact_u16_decode_unsafe(&self->extensions_len, ctx);
  if (self->extensions_len != 0) {
    self->extensions = fd_valloc_malloc( ctx->valloc, 8UL, sizeof(uint)*self->extensions_len );
    for( ulong i = 0; i < self->extensions_len; ++i) {
      fd_bincode_uint32_decode_unsafe(self->extensions + i, ctx);
    }
  } else
    self->extensions = NULL;
}
int fd_gossip_contact_info_v2_decode_offsets(fd_gossip_contact_info_v2_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->from_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->wallclock_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_varint_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->outset_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->shred_version_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint16_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->version_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_gossip_version_v3_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->addrs_off = (uint)((ulong)ctx->data - (ulong)data);
  ushort addrs_len;
  err = fd_bincode_compact_u16_decode(&addrs_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (addrs_len != 0) {
    for( ulong i = 0; i < addrs_len; ++i) {
      err = fd_gossip_ip_addr_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->sockets_off = (uint)((ulong)ctx->data - (ulong)data);
  ushort sockets_len;
  err = fd_bincode_compact_u16_decode(&sockets_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (sockets_len != 0) {
    for( ulong i = 0; i < sockets_len; ++i) {
      err = fd_gossip_socket_entry_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->extensions_off = (uint)((ulong)ctx->data - (ulong)data);
  ushort extensions_len;
  err = fd_bincode_compact_u16_decode(&extensions_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (extensions_len != 0) {
    for( ulong i = 0; i < extensions_len; ++i) {
      err = fd_bincode_uint32_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_contact_info_v2_new(fd_gossip_contact_info_v2_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_contact_info_v2_t));
  fd_pubkey_new(&self->from);
  fd_gossip_version_v3_new(&self->version);
}
void fd_gossip_contact_info_v2_destroy(fd_gossip_contact_info_v2_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->from, ctx);
  fd_gossip_version_v3_destroy(&self->version, ctx);
  if (NULL != self->addrs) {
    for (ulong i = 0; i < self->addrs_len; ++i)
      fd_gossip_ip_addr_destroy(self->addrs + i, ctx);
    fd_valloc_free( ctx->valloc, self->addrs );
    self->addrs = NULL;
  }
  if (NULL != self->sockets) {
    for (ulong i = 0; i < self->sockets_len; ++i)
      fd_gossip_socket_entry_destroy(self->sockets + i, ctx);
    fd_valloc_free( ctx->valloc, self->sockets );
    self->sockets = NULL;
  }
  if (NULL != self->extensions) {
    fd_valloc_free( ctx->valloc, self->extensions );
    self->extensions = NULL;
  }
}

ulong fd_gossip_contact_info_v2_footprint( void ){ return FD_GOSSIP_CONTACT_INFO_V2_FOOTPRINT; }
ulong fd_gossip_contact_info_v2_align( void ){ return FD_GOSSIP_CONTACT_INFO_V2_ALIGN; }

void fd_gossip_contact_info_v2_walk(void * w, fd_gossip_contact_info_v2_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_contact_info_v2", level++);
  fd_pubkey_walk(w, &self->from, fun, "from", level);
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->outset, "outset", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->shred_version, "shred_version", FD_FLAMENCO_TYPE_USHORT,  "ushort",    level );
  fd_gossip_version_v3_walk(w, &self->version, fun, "version", level);
  if (self->addrs_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "addrs", level++);
    for (ulong i = 0; i < self->addrs_len; ++i)
      fd_gossip_ip_addr_walk(w, self->addrs + i, fun, "gossip_ip_addr", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "addrs", level-- );
  }
  if (self->sockets_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "sockets", level++);
    for (ulong i = 0; i < self->sockets_len; ++i)
      fd_gossip_socket_entry_walk(w, self->sockets + i, fun, "gossip_socket_entry", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "sockets", level-- );
  }
  if (self->extensions_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "extensions", level++);
    for (ulong i = 0; i < self->extensions_len; ++i)
      fun( w, self->extensions + i, "extensions", FD_FLAMENCO_TYPE_UINT,    "uint",    level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "extensions", level-- );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_contact_info_v2", level--);
}
ulong fd_gossip_contact_info_v2_size(fd_gossip_contact_info_v2_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->from);
  size += fd_bincode_varint_size(self->wallclock);
  size += sizeof(ulong);
  size += sizeof(ushort);
  size += fd_gossip_version_v3_size(&self->version);
  do {
    ushort tmp = (ushort)self->addrs_len;
    size += fd_bincode_compact_u16_size(&tmp);
    for (ulong i = 0; i < self->addrs_len; ++i)
      size += fd_gossip_ip_addr_size(self->addrs + i);
  } while(0);
  do {
    ushort tmp = (ushort)self->sockets_len;
    size += fd_bincode_compact_u16_size(&tmp);
    for (ulong i = 0; i < self->sockets_len; ++i)
      size += fd_gossip_socket_entry_size(self->sockets + i);
  } while(0);
  do {
    ushort tmp = (ushort)self->extensions_len;
    size += fd_bincode_compact_u16_size(&tmp);
    size += self->extensions_len * sizeof(uint);
  } while(0);
  return size;
}

int fd_gossip_contact_info_v2_encode(fd_gossip_contact_info_v2_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->from, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_varint_encode(self->wallclock, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->outset, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint16_encode( (ushort)(self->shred_version), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_version_v3_encode(&self->version, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_compact_u16_encode(&self->addrs_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->addrs_len != 0) {
    for (ulong i = 0; i < self->addrs_len; ++i) {
      err = fd_gossip_ip_addr_encode(self->addrs + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_compact_u16_encode(&self->sockets_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->sockets_len != 0) {
    for (ulong i = 0; i < self->sockets_len; ++i) {
      err = fd_gossip_socket_entry_encode(self->sockets + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  err = fd_bincode_compact_u16_encode(&self->extensions_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->extensions_len != 0) {
    for (ulong i = 0; i < self->extensions_len; ++i) {
      err = fd_bincode_uint32_encode(self->extensions[i], ctx);
    }
  }
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_crds_data_is_contact_info_v1(fd_crds_data_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_crds_data_is_vote(fd_crds_data_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_crds_data_is_lowest_slot(fd_crds_data_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_crds_data_is_snapshot_hashes(fd_crds_data_t const * self) {
  return self->discriminant == 3;
}
FD_FN_PURE uchar fd_crds_data_is_accounts_hashes(fd_crds_data_t const * self) {
  return self->discriminant == 4;
}
FD_FN_PURE uchar fd_crds_data_is_epoch_slots(fd_crds_data_t const * self) {
  return self->discriminant == 5;
}
FD_FN_PURE uchar fd_crds_data_is_version_v1(fd_crds_data_t const * self) {
  return self->discriminant == 6;
}
FD_FN_PURE uchar fd_crds_data_is_version_v2(fd_crds_data_t const * self) {
  return self->discriminant == 7;
}
FD_FN_PURE uchar fd_crds_data_is_node_instance(fd_crds_data_t const * self) {
  return self->discriminant == 8;
}
FD_FN_PURE uchar fd_crds_data_is_duplicate_shred(fd_crds_data_t const * self) {
  return self->discriminant == 9;
}
FD_FN_PURE uchar fd_crds_data_is_incremental_snapshot_hashes(fd_crds_data_t const * self) {
  return self->discriminant == 10;
}
FD_FN_PURE uchar fd_crds_data_is_contact_info_v2(fd_crds_data_t const * self) {
  return self->discriminant == 11;
}
void fd_crds_data_inner_new(fd_crds_data_inner_t* self, uint discriminant);
int fd_crds_data_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_contact_info_v1_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_gossip_vote_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_gossip_lowest_slot_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    err = fd_gossip_slot_hashes_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    err = fd_gossip_slot_hashes_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 5: {
    err = fd_gossip_epoch_slots_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 6: {
    err = fd_gossip_version_v1_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 7: {
    err = fd_gossip_version_v2_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 8: {
    err = fd_gossip_node_instance_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 9: {
    err = fd_gossip_duplicate_shred_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 10: {
    err = fd_gossip_incremental_snapshot_hashes_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 11: {
    err = fd_gossip_contact_info_v2_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_crds_data_inner_decode_unsafe(fd_crds_data_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_gossip_contact_info_v1_decode_unsafe(&self->contact_info_v1, ctx);
    break;
  }
  case 1: {
    fd_gossip_vote_decode_unsafe(&self->vote, ctx);
    break;
  }
  case 2: {
    fd_gossip_lowest_slot_decode_unsafe(&self->lowest_slot, ctx);
    break;
  }
  case 3: {
    fd_gossip_slot_hashes_decode_unsafe(&self->snapshot_hashes, ctx);
    break;
  }
  case 4: {
    fd_gossip_slot_hashes_decode_unsafe(&self->accounts_hashes, ctx);
    break;
  }
  case 5: {
    fd_gossip_epoch_slots_decode_unsafe(&self->epoch_slots, ctx);
    break;
  }
  case 6: {
    fd_gossip_version_v1_decode_unsafe(&self->version_v1, ctx);
    break;
  }
  case 7: {
    fd_gossip_version_v2_decode_unsafe(&self->version_v2, ctx);
    break;
  }
  case 8: {
    fd_gossip_node_instance_decode_unsafe(&self->node_instance, ctx);
    break;
  }
  case 9: {
    fd_gossip_duplicate_shred_decode_unsafe(&self->duplicate_shred, ctx);
    break;
  }
  case 10: {
    fd_gossip_incremental_snapshot_hashes_decode_unsafe(&self->incremental_snapshot_hashes, ctx);
    break;
  }
  case 11: {
    fd_gossip_contact_info_v2_decode_unsafe(&self->contact_info_v2, ctx);
    break;
  }
  }
}
int fd_crds_data_decode(fd_crds_data_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_crds_data_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_crds_data_new(self);
  fd_crds_data_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_crds_data_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_crds_data_inner_decode_preflight(discriminant, ctx);
}
void fd_crds_data_decode_unsafe(fd_crds_data_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_crds_data_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_crds_data_inner_new(fd_crds_data_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_gossip_contact_info_v1_new(&self->contact_info_v1);
    break;
  }
  case 1: {
    fd_gossip_vote_new(&self->vote);
    break;
  }
  case 2: {
    fd_gossip_lowest_slot_new(&self->lowest_slot);
    break;
  }
  case 3: {
    fd_gossip_slot_hashes_new(&self->snapshot_hashes);
    break;
  }
  case 4: {
    fd_gossip_slot_hashes_new(&self->accounts_hashes);
    break;
  }
  case 5: {
    fd_gossip_epoch_slots_new(&self->epoch_slots);
    break;
  }
  case 6: {
    fd_gossip_version_v1_new(&self->version_v1);
    break;
  }
  case 7: {
    fd_gossip_version_v2_new(&self->version_v2);
    break;
  }
  case 8: {
    fd_gossip_node_instance_new(&self->node_instance);
    break;
  }
  case 9: {
    fd_gossip_duplicate_shred_new(&self->duplicate_shred);
    break;
  }
  case 10: {
    fd_gossip_incremental_snapshot_hashes_new(&self->incremental_snapshot_hashes);
    break;
  }
  case 11: {
    fd_gossip_contact_info_v2_new(&self->contact_info_v2);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_crds_data_new_disc(fd_crds_data_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_crds_data_inner_new(&self->inner, self->discriminant);
}
void fd_crds_data_new(fd_crds_data_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_crds_data_new_disc(self, UINT_MAX);
}
void fd_crds_data_inner_destroy(fd_crds_data_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_gossip_contact_info_v1_destroy(&self->contact_info_v1, ctx);
    break;
  }
  case 1: {
    fd_gossip_vote_destroy(&self->vote, ctx);
    break;
  }
  case 2: {
    fd_gossip_lowest_slot_destroy(&self->lowest_slot, ctx);
    break;
  }
  case 3: {
    fd_gossip_slot_hashes_destroy(&self->snapshot_hashes, ctx);
    break;
  }
  case 4: {
    fd_gossip_slot_hashes_destroy(&self->accounts_hashes, ctx);
    break;
  }
  case 5: {
    fd_gossip_epoch_slots_destroy(&self->epoch_slots, ctx);
    break;
  }
  case 6: {
    fd_gossip_version_v1_destroy(&self->version_v1, ctx);
    break;
  }
  case 7: {
    fd_gossip_version_v2_destroy(&self->version_v2, ctx);
    break;
  }
  case 8: {
    fd_gossip_node_instance_destroy(&self->node_instance, ctx);
    break;
  }
  case 9: {
    fd_gossip_duplicate_shred_destroy(&self->duplicate_shred, ctx);
    break;
  }
  case 10: {
    fd_gossip_incremental_snapshot_hashes_destroy(&self->incremental_snapshot_hashes, ctx);
    break;
  }
  case 11: {
    fd_gossip_contact_info_v2_destroy(&self->contact_info_v2, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_crds_data_destroy(fd_crds_data_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_crds_data_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_crds_data_footprint( void ){ return FD_CRDS_DATA_FOOTPRINT; }
ulong fd_crds_data_align( void ){ return FD_CRDS_DATA_ALIGN; }

void fd_crds_data_walk(void * w, fd_crds_data_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_crds_data", level++);
  switch (self->discriminant) {
  case 0: {
    fd_gossip_contact_info_v1_walk(w, &self->inner.contact_info_v1, fun, "contact_info_v1", level);
    break;
  }
  case 1: {
    fd_gossip_vote_walk(w, &self->inner.vote, fun, "vote", level);
    break;
  }
  case 2: {
    fd_gossip_lowest_slot_walk(w, &self->inner.lowest_slot, fun, "lowest_slot", level);
    break;
  }
  case 3: {
    fd_gossip_slot_hashes_walk(w, &self->inner.snapshot_hashes, fun, "snapshot_hashes", level);
    break;
  }
  case 4: {
    fd_gossip_slot_hashes_walk(w, &self->inner.accounts_hashes, fun, "accounts_hashes", level);
    break;
  }
  case 5: {
    fd_gossip_epoch_slots_walk(w, &self->inner.epoch_slots, fun, "epoch_slots", level);
    break;
  }
  case 6: {
    fd_gossip_version_v1_walk(w, &self->inner.version_v1, fun, "version_v1", level);
    break;
  }
  case 7: {
    fd_gossip_version_v2_walk(w, &self->inner.version_v2, fun, "version_v2", level);
    break;
  }
  case 8: {
    fd_gossip_node_instance_walk(w, &self->inner.node_instance, fun, "node_instance", level);
    break;
  }
  case 9: {
    fd_gossip_duplicate_shred_walk(w, &self->inner.duplicate_shred, fun, "duplicate_shred", level);
    break;
  }
  case 10: {
    fd_gossip_incremental_snapshot_hashes_walk(w, &self->inner.incremental_snapshot_hashes, fun, "incremental_snapshot_hashes", level);
    break;
  }
  case 11: {
    fd_gossip_contact_info_v2_walk(w, &self->inner.contact_info_v2, fun, "contact_info_v2", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_crds_data", level--);
}
ulong fd_crds_data_size(fd_crds_data_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_gossip_contact_info_v1_size(&self->inner.contact_info_v1);
    break;
  }
  case 1: {
    size += fd_gossip_vote_size(&self->inner.vote);
    break;
  }
  case 2: {
    size += fd_gossip_lowest_slot_size(&self->inner.lowest_slot);
    break;
  }
  case 3: {
    size += fd_gossip_slot_hashes_size(&self->inner.snapshot_hashes);
    break;
  }
  case 4: {
    size += fd_gossip_slot_hashes_size(&self->inner.accounts_hashes);
    break;
  }
  case 5: {
    size += fd_gossip_epoch_slots_size(&self->inner.epoch_slots);
    break;
  }
  case 6: {
    size += fd_gossip_version_v1_size(&self->inner.version_v1);
    break;
  }
  case 7: {
    size += fd_gossip_version_v2_size(&self->inner.version_v2);
    break;
  }
  case 8: {
    size += fd_gossip_node_instance_size(&self->inner.node_instance);
    break;
  }
  case 9: {
    size += fd_gossip_duplicate_shred_size(&self->inner.duplicate_shred);
    break;
  }
  case 10: {
    size += fd_gossip_incremental_snapshot_hashes_size(&self->inner.incremental_snapshot_hashes);
    break;
  }
  case 11: {
    size += fd_gossip_contact_info_v2_size(&self->inner.contact_info_v2);
    break;
  }
  }
  return size;
}

int fd_crds_data_inner_encode(fd_crds_data_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_contact_info_v1_encode(&self->contact_info_v1, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 1: {
    err = fd_gossip_vote_encode(&self->vote, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 2: {
    err = fd_gossip_lowest_slot_encode(&self->lowest_slot, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 3: {
    err = fd_gossip_slot_hashes_encode(&self->snapshot_hashes, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 4: {
    err = fd_gossip_slot_hashes_encode(&self->accounts_hashes, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 5: {
    err = fd_gossip_epoch_slots_encode(&self->epoch_slots, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 6: {
    err = fd_gossip_version_v1_encode(&self->version_v1, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 7: {
    err = fd_gossip_version_v2_encode(&self->version_v2, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 8: {
    err = fd_gossip_node_instance_encode(&self->node_instance, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 9: {
    err = fd_gossip_duplicate_shred_encode(&self->duplicate_shred, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 10: {
    err = fd_gossip_incremental_snapshot_hashes_encode(&self->incremental_snapshot_hashes, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 11: {
    err = fd_gossip_contact_info_v2_encode(&self->contact_info_v2, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_crds_data_encode(fd_crds_data_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_crds_data_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_crds_bloom_decode(fd_crds_bloom_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_crds_bloom_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_crds_bloom_new(self);
  fd_crds_bloom_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_crds_bloom_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong keys_len;
  err = fd_bincode_uint64_decode(&keys_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (keys_len != 0) {
    for( ulong i = 0; i < keys_len; ++i) {
      err = fd_bincode_uint64_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_gossip_bitvec_u64_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_crds_bloom_decode_unsafe(fd_crds_bloom_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->keys_len, ctx);
  if (self->keys_len != 0) {
    self->keys = fd_valloc_malloc( ctx->valloc, 8UL, sizeof(ulong)*self->keys_len );
    for( ulong i = 0; i < self->keys_len; ++i) {
      fd_bincode_uint64_decode_unsafe(self->keys + i, ctx);
    }
  } else
    self->keys = NULL;
  fd_gossip_bitvec_u64_decode_unsafe(&self->bits, ctx);
  fd_bincode_uint64_decode_unsafe(&self->num_bits_set, ctx);
}
int fd_crds_bloom_decode_offsets(fd_crds_bloom_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->keys_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong keys_len;
  err = fd_bincode_uint64_decode(&keys_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (keys_len != 0) {
    for( ulong i = 0; i < keys_len; ++i) {
      err = fd_bincode_uint64_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  self->bits_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_gossip_bitvec_u64_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->num_bits_set_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_crds_bloom_new(fd_crds_bloom_t* self) {
  fd_memset(self, 0, sizeof(fd_crds_bloom_t));
  fd_gossip_bitvec_u64_new(&self->bits);
}
void fd_crds_bloom_destroy(fd_crds_bloom_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->keys) {
    fd_valloc_free( ctx->valloc, self->keys );
    self->keys = NULL;
  }
  fd_gossip_bitvec_u64_destroy(&self->bits, ctx);
}

ulong fd_crds_bloom_footprint( void ){ return FD_CRDS_BLOOM_FOOTPRINT; }
ulong fd_crds_bloom_align( void ){ return FD_CRDS_BLOOM_ALIGN; }

void fd_crds_bloom_walk(void * w, fd_crds_bloom_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_crds_bloom", level++);
  if (self->keys_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "keys", level++);
    for (ulong i = 0; i < self->keys_len; ++i)
      fun( w, self->keys + i, "keys", FD_FLAMENCO_TYPE_ULONG,   "ulong",   level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "keys", level-- );
  }
  fd_gossip_bitvec_u64_walk(w, &self->bits, fun, "bits", level);
  fun( w, &self->num_bits_set, "num_bits_set", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_crds_bloom", level--);
}
ulong fd_crds_bloom_size(fd_crds_bloom_t const * self) {
  ulong size = 0;
  do {
    size += sizeof(ulong);
    size += self->keys_len * sizeof(ulong);
  } while(0);
  size += fd_gossip_bitvec_u64_size(&self->bits);
  size += sizeof(ulong);
  return size;
}

int fd_crds_bloom_encode(fd_crds_bloom_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->keys_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->keys_len != 0) {
    for (ulong i = 0; i < self->keys_len; ++i) {
      err = fd_bincode_uint64_encode(self->keys[i], ctx);
    }
  }
  err = fd_gossip_bitvec_u64_encode(&self->bits, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->num_bits_set, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_crds_filter_decode(fd_crds_filter_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_crds_filter_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_crds_filter_new(self);
  fd_crds_filter_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_crds_filter_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_crds_bloom_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_crds_filter_decode_unsafe(fd_crds_filter_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_crds_bloom_decode_unsafe(&self->filter, ctx);
  fd_bincode_uint64_decode_unsafe(&self->mask, ctx);
  fd_bincode_uint32_decode_unsafe(&self->mask_bits, ctx);
}
int fd_crds_filter_decode_offsets(fd_crds_filter_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->filter_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_crds_bloom_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->mask_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->mask_bits_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_crds_filter_new(fd_crds_filter_t* self) {
  fd_memset(self, 0, sizeof(fd_crds_filter_t));
  fd_crds_bloom_new(&self->filter);
}
void fd_crds_filter_destroy(fd_crds_filter_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_crds_bloom_destroy(&self->filter, ctx);
}

ulong fd_crds_filter_footprint( void ){ return FD_CRDS_FILTER_FOOTPRINT; }
ulong fd_crds_filter_align( void ){ return FD_CRDS_FILTER_ALIGN; }

void fd_crds_filter_walk(void * w, fd_crds_filter_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_crds_filter", level++);
  fd_crds_bloom_walk(w, &self->filter, fun, "filter", level);
  fun( w, &self->mask, "mask", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->mask_bits, "mask_bits", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_crds_filter", level--);
}
ulong fd_crds_filter_size(fd_crds_filter_t const * self) {
  ulong size = 0;
  size += fd_crds_bloom_size(&self->filter);
  size += sizeof(ulong);
  size += sizeof(uint);
  return size;
}

int fd_crds_filter_encode(fd_crds_filter_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_crds_bloom_encode(&self->filter, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->mask, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_encode( self->mask_bits, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_crds_value_decode(fd_crds_value_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_crds_value_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_crds_value_new(self);
  fd_crds_value_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_crds_value_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_signature_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_crds_data_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_crds_value_decode_unsafe(fd_crds_value_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_signature_decode_unsafe(&self->signature, ctx);
  fd_crds_data_decode_unsafe(&self->data, ctx);
}
int fd_crds_value_decode_offsets(fd_crds_value_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->signature_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_signature_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->data_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_crds_data_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_crds_value_new(fd_crds_value_t* self) {
  fd_memset(self, 0, sizeof(fd_crds_value_t));
  fd_signature_new(&self->signature);
  fd_crds_data_new(&self->data);
}
void fd_crds_value_destroy(fd_crds_value_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_signature_destroy(&self->signature, ctx);
  fd_crds_data_destroy(&self->data, ctx);
}

ulong fd_crds_value_footprint( void ){ return FD_CRDS_VALUE_FOOTPRINT; }
ulong fd_crds_value_align( void ){ return FD_CRDS_VALUE_ALIGN; }

void fd_crds_value_walk(void * w, fd_crds_value_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_crds_value", level++);
  fd_signature_walk(w, &self->signature, fun, "signature", level);
  fd_crds_data_walk(w, &self->data, fun, "data", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_crds_value", level--);
}
ulong fd_crds_value_size(fd_crds_value_t const * self) {
  ulong size = 0;
  size += fd_signature_size(&self->signature);
  size += fd_crds_data_size(&self->data);
  return size;
}

int fd_crds_value_encode(fd_crds_value_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_signature_encode(&self->signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_crds_data_encode(&self->data, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_pull_req_decode(fd_gossip_pull_req_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_pull_req_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_pull_req_new(self);
  fd_gossip_pull_req_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_pull_req_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_crds_filter_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_crds_value_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_pull_req_decode_unsafe(fd_gossip_pull_req_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_crds_filter_decode_unsafe(&self->filter, ctx);
  fd_crds_value_decode_unsafe(&self->value, ctx);
}
int fd_gossip_pull_req_decode_offsets(fd_gossip_pull_req_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->filter_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_crds_filter_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->value_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_crds_value_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_pull_req_new(fd_gossip_pull_req_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_pull_req_t));
  fd_crds_filter_new(&self->filter);
  fd_crds_value_new(&self->value);
}
void fd_gossip_pull_req_destroy(fd_gossip_pull_req_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_crds_filter_destroy(&self->filter, ctx);
  fd_crds_value_destroy(&self->value, ctx);
}

ulong fd_gossip_pull_req_footprint( void ){ return FD_GOSSIP_PULL_REQ_FOOTPRINT; }
ulong fd_gossip_pull_req_align( void ){ return FD_GOSSIP_PULL_REQ_ALIGN; }

void fd_gossip_pull_req_walk(void * w, fd_gossip_pull_req_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_pull_req", level++);
  fd_crds_filter_walk(w, &self->filter, fun, "filter", level);
  fd_crds_value_walk(w, &self->value, fun, "value", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_pull_req", level--);
}
ulong fd_gossip_pull_req_size(fd_gossip_pull_req_t const * self) {
  ulong size = 0;
  size += fd_crds_filter_size(&self->filter);
  size += fd_crds_value_size(&self->value);
  return size;
}

int fd_gossip_pull_req_encode(fd_gossip_pull_req_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_crds_filter_encode(&self->filter, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_crds_value_encode(&self->value, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_pull_resp_decode(fd_gossip_pull_resp_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_pull_resp_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_pull_resp_new(self);
  fd_gossip_pull_resp_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_pull_resp_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong crds_len;
  err = fd_bincode_uint64_decode(&crds_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (crds_len != 0) {
    for( ulong i = 0; i < crds_len; ++i) {
      err = fd_crds_value_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_pull_resp_decode_unsafe(fd_gossip_pull_resp_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->pubkey, ctx);
  fd_bincode_uint64_decode_unsafe(&self->crds_len, ctx);
  if (self->crds_len != 0) {
    self->crds = (fd_crds_value_t *)fd_valloc_malloc( ctx->valloc, FD_CRDS_VALUE_ALIGN, FD_CRDS_VALUE_FOOTPRINT*self->crds_len);
    for( ulong i = 0; i < self->crds_len; ++i) {
      fd_crds_value_new(self->crds + i);
      fd_crds_value_decode_unsafe(self->crds + i, ctx);
    }
  } else
    self->crds = NULL;
}
int fd_gossip_pull_resp_decode_offsets(fd_gossip_pull_resp_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->crds_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong crds_len;
  err = fd_bincode_uint64_decode(&crds_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (crds_len != 0) {
    for( ulong i = 0; i < crds_len; ++i) {
      err = fd_crds_value_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_pull_resp_new(fd_gossip_pull_resp_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_pull_resp_t));
  fd_pubkey_new(&self->pubkey);
}
void fd_gossip_pull_resp_destroy(fd_gossip_pull_resp_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->pubkey, ctx);
  if (NULL != self->crds) {
    for (ulong i = 0; i < self->crds_len; ++i)
      fd_crds_value_destroy(self->crds + i, ctx);
    fd_valloc_free( ctx->valloc, self->crds );
    self->crds = NULL;
  }
}

ulong fd_gossip_pull_resp_footprint( void ){ return FD_GOSSIP_PULL_RESP_FOOTPRINT; }
ulong fd_gossip_pull_resp_align( void ){ return FD_GOSSIP_PULL_RESP_ALIGN; }

void fd_gossip_pull_resp_walk(void * w, fd_gossip_pull_resp_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_pull_resp", level++);
  fd_pubkey_walk(w, &self->pubkey, fun, "pubkey", level);
  if (self->crds_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "crds", level++);
    for (ulong i = 0; i < self->crds_len; ++i)
      fd_crds_value_walk(w, self->crds + i, fun, "crds_value", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "crds", level-- );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_pull_resp", level--);
}
ulong fd_gossip_pull_resp_size(fd_gossip_pull_resp_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->pubkey);
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->crds_len; ++i)
      size += fd_crds_value_size(self->crds + i);
  } while(0);
  return size;
}

int fd_gossip_pull_resp_encode(fd_gossip_pull_resp_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->crds_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->crds_len != 0) {
    for (ulong i = 0; i < self->crds_len; ++i) {
      err = fd_crds_value_encode(self->crds + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_push_msg_decode(fd_gossip_push_msg_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_push_msg_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_push_msg_new(self);
  fd_gossip_push_msg_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_push_msg_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  ulong crds_len;
  err = fd_bincode_uint64_decode(&crds_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (crds_len != 0) {
    for( ulong i = 0; i < crds_len; ++i) {
      err = fd_crds_value_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_push_msg_decode_unsafe(fd_gossip_push_msg_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->pubkey, ctx);
  fd_bincode_uint64_decode_unsafe(&self->crds_len, ctx);
  if (self->crds_len != 0) {
    self->crds = (fd_crds_value_t *)fd_valloc_malloc( ctx->valloc, FD_CRDS_VALUE_ALIGN, FD_CRDS_VALUE_FOOTPRINT*self->crds_len);
    for( ulong i = 0; i < self->crds_len; ++i) {
      fd_crds_value_new(self->crds + i);
      fd_crds_value_decode_unsafe(self->crds + i, ctx);
    }
  } else
    self->crds = NULL;
}
int fd_gossip_push_msg_decode_offsets(fd_gossip_push_msg_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->crds_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong crds_len;
  err = fd_bincode_uint64_decode(&crds_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (crds_len != 0) {
    for( ulong i = 0; i < crds_len; ++i) {
      err = fd_crds_value_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_push_msg_new(fd_gossip_push_msg_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_push_msg_t));
  fd_pubkey_new(&self->pubkey);
}
void fd_gossip_push_msg_destroy(fd_gossip_push_msg_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->pubkey, ctx);
  if (NULL != self->crds) {
    for (ulong i = 0; i < self->crds_len; ++i)
      fd_crds_value_destroy(self->crds + i, ctx);
    fd_valloc_free( ctx->valloc, self->crds );
    self->crds = NULL;
  }
}

ulong fd_gossip_push_msg_footprint( void ){ return FD_GOSSIP_PUSH_MSG_FOOTPRINT; }
ulong fd_gossip_push_msg_align( void ){ return FD_GOSSIP_PUSH_MSG_ALIGN; }

void fd_gossip_push_msg_walk(void * w, fd_gossip_push_msg_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_push_msg", level++);
  fd_pubkey_walk(w, &self->pubkey, fun, "pubkey", level);
  if (self->crds_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "crds", level++);
    for (ulong i = 0; i < self->crds_len; ++i)
      fd_crds_value_walk(w, self->crds + i, fun, "crds_value", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "crds", level-- );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_push_msg", level--);
}
ulong fd_gossip_push_msg_size(fd_gossip_push_msg_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->pubkey);
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->crds_len; ++i)
      size += fd_crds_value_size(self->crds + i);
  } while(0);
  return size;
}

int fd_gossip_push_msg_encode(fd_gossip_push_msg_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->crds_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->crds_len != 0) {
    for (ulong i = 0; i < self->crds_len; ++i) {
      err = fd_crds_value_encode(self->crds + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}

int fd_gossip_prune_msg_decode(fd_gossip_prune_msg_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_prune_msg_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_prune_msg_new(self);
  fd_gossip_prune_msg_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_prune_msg_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_prune_data_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_prune_msg_decode_unsafe(fd_gossip_prune_msg_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_pubkey_decode_unsafe(&self->pubkey, ctx);
  fd_gossip_prune_data_decode_unsafe(&self->data, ctx);
}
int fd_gossip_prune_msg_decode_offsets(fd_gossip_prune_msg_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->pubkey_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->data_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_gossip_prune_data_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_gossip_prune_msg_new(fd_gossip_prune_msg_t* self) {
  fd_memset(self, 0, sizeof(fd_gossip_prune_msg_t));
  fd_pubkey_new(&self->pubkey);
  fd_gossip_prune_data_new(&self->data);
}
void fd_gossip_prune_msg_destroy(fd_gossip_prune_msg_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_pubkey_destroy(&self->pubkey, ctx);
  fd_gossip_prune_data_destroy(&self->data, ctx);
}

ulong fd_gossip_prune_msg_footprint( void ){ return FD_GOSSIP_PRUNE_MSG_FOOTPRINT; }
ulong fd_gossip_prune_msg_align( void ){ return FD_GOSSIP_PRUNE_MSG_ALIGN; }

void fd_gossip_prune_msg_walk(void * w, fd_gossip_prune_msg_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_prune_msg", level++);
  fd_pubkey_walk(w, &self->pubkey, fun, "pubkey", level);
  fd_gossip_prune_data_walk(w, &self->data, fun, "data", level);
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_prune_msg", level--);
}
ulong fd_gossip_prune_msg_size(fd_gossip_prune_msg_t const * self) {
  ulong size = 0;
  size += fd_pubkey_size(&self->pubkey);
  size += fd_gossip_prune_data_size(&self->data);
  return size;
}

int fd_gossip_prune_msg_encode(fd_gossip_prune_msg_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_pubkey_encode(&self->pubkey, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_gossip_prune_data_encode(&self->data, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_gossip_msg_is_pull_req(fd_gossip_msg_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_gossip_msg_is_pull_resp(fd_gossip_msg_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_gossip_msg_is_push_msg(fd_gossip_msg_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_gossip_msg_is_prune_msg(fd_gossip_msg_t const * self) {
  return self->discriminant == 3;
}
FD_FN_PURE uchar fd_gossip_msg_is_ping(fd_gossip_msg_t const * self) {
  return self->discriminant == 4;
}
FD_FN_PURE uchar fd_gossip_msg_is_pong(fd_gossip_msg_t const * self) {
  return self->discriminant == 5;
}
void fd_gossip_msg_inner_new(fd_gossip_msg_inner_t* self, uint discriminant);
int fd_gossip_msg_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_pull_req_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_gossip_pull_resp_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_gossip_push_msg_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    err = fd_gossip_prune_msg_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    err = fd_gossip_ping_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 5: {
    err = fd_gossip_ping_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_gossip_msg_inner_decode_unsafe(fd_gossip_msg_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_gossip_pull_req_decode_unsafe(&self->pull_req, ctx);
    break;
  }
  case 1: {
    fd_gossip_pull_resp_decode_unsafe(&self->pull_resp, ctx);
    break;
  }
  case 2: {
    fd_gossip_push_msg_decode_unsafe(&self->push_msg, ctx);
    break;
  }
  case 3: {
    fd_gossip_prune_msg_decode_unsafe(&self->prune_msg, ctx);
    break;
  }
  case 4: {
    fd_gossip_ping_decode_unsafe(&self->ping, ctx);
    break;
  }
  case 5: {
    fd_gossip_ping_decode_unsafe(&self->pong, ctx);
    break;
  }
  }
}
int fd_gossip_msg_decode(fd_gossip_msg_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_gossip_msg_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_gossip_msg_new(self);
  fd_gossip_msg_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_msg_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_gossip_msg_inner_decode_preflight(discriminant, ctx);
}
void fd_gossip_msg_decode_unsafe(fd_gossip_msg_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_gossip_msg_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_gossip_msg_inner_new(fd_gossip_msg_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_gossip_pull_req_new(&self->pull_req);
    break;
  }
  case 1: {
    fd_gossip_pull_resp_new(&self->pull_resp);
    break;
  }
  case 2: {
    fd_gossip_push_msg_new(&self->push_msg);
    break;
  }
  case 3: {
    fd_gossip_prune_msg_new(&self->prune_msg);
    break;
  }
  case 4: {
    fd_gossip_ping_new(&self->ping);
    break;
  }
  case 5: {
    fd_gossip_ping_new(&self->pong);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_gossip_msg_new_disc(fd_gossip_msg_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_gossip_msg_inner_new(&self->inner, self->discriminant);
}
void fd_gossip_msg_new(fd_gossip_msg_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_gossip_msg_new_disc(self, UINT_MAX);
}
void fd_gossip_msg_inner_destroy(fd_gossip_msg_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_gossip_pull_req_destroy(&self->pull_req, ctx);
    break;
  }
  case 1: {
    fd_gossip_pull_resp_destroy(&self->pull_resp, ctx);
    break;
  }
  case 2: {
    fd_gossip_push_msg_destroy(&self->push_msg, ctx);
    break;
  }
  case 3: {
    fd_gossip_prune_msg_destroy(&self->prune_msg, ctx);
    break;
  }
  case 4: {
    fd_gossip_ping_destroy(&self->ping, ctx);
    break;
  }
  case 5: {
    fd_gossip_ping_destroy(&self->pong, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_gossip_msg_destroy(fd_gossip_msg_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_gossip_msg_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_gossip_msg_footprint( void ){ return FD_GOSSIP_MSG_FOOTPRINT; }
ulong fd_gossip_msg_align( void ){ return FD_GOSSIP_MSG_ALIGN; }

void fd_gossip_msg_walk(void * w, fd_gossip_msg_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_msg", level++);
  switch (self->discriminant) {
  case 0: {
    fd_gossip_pull_req_walk(w, &self->inner.pull_req, fun, "pull_req", level);
    break;
  }
  case 1: {
    fd_gossip_pull_resp_walk(w, &self->inner.pull_resp, fun, "pull_resp", level);
    break;
  }
  case 2: {
    fd_gossip_push_msg_walk(w, &self->inner.push_msg, fun, "push_msg", level);
    break;
  }
  case 3: {
    fd_gossip_prune_msg_walk(w, &self->inner.prune_msg, fun, "prune_msg", level);
    break;
  }
  case 4: {
    fd_gossip_ping_walk(w, &self->inner.ping, fun, "ping", level);
    break;
  }
  case 5: {
    fd_gossip_ping_walk(w, &self->inner.pong, fun, "pong", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_msg", level--);
}
ulong fd_gossip_msg_size(fd_gossip_msg_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_gossip_pull_req_size(&self->inner.pull_req);
    break;
  }
  case 1: {
    size += fd_gossip_pull_resp_size(&self->inner.pull_resp);
    break;
  }
  case 2: {
    size += fd_gossip_push_msg_size(&self->inner.push_msg);
    break;
  }
  case 3: {
    size += fd_gossip_prune_msg_size(&self->inner.prune_msg);
    break;
  }
  case 4: {
    size += fd_gossip_ping_size(&self->inner.ping);
    break;
  }
  case 5: {
    size += fd_gossip_ping_size(&self->inner.pong);
    break;
  }
  }
  return size;
}

int fd_gossip_msg_inner_encode(fd_gossip_msg_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_pull_req_encode(&self->pull_req, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 1: {
    err = fd_gossip_pull_resp_encode(&self->pull_resp, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 2: {
    err = fd_gossip_push_msg_encode(&self->push_msg, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 3: {
    err = fd_gossip_prune_msg_encode(&self->prune_msg, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 4: {
    err = fd_gossip_ping_encode(&self->ping, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 5: {
    err = fd_gossip_ping_encode(&self->pong, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_msg_encode(fd_gossip_msg_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_gossip_msg_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_addrlut_create_decode(fd_addrlut_create_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_addrlut_create_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_addrlut_create_new(self);
  fd_addrlut_create_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_addrlut_create_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_addrlut_create_decode_unsafe(fd_addrlut_create_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->recent_slot, ctx);
  fd_bincode_uint8_decode_unsafe(&self->bump_seed, ctx);
}
int fd_addrlut_create_decode_offsets(fd_addrlut_create_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->recent_slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->bump_seed_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint8_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_addrlut_create_new(fd_addrlut_create_t* self) {
  fd_memset(self, 0, sizeof(fd_addrlut_create_t));
}
void fd_addrlut_create_destroy(fd_addrlut_create_t* self, fd_bincode_destroy_ctx_t * ctx) {
}

ulong fd_addrlut_create_footprint( void ){ return FD_ADDRLUT_CREATE_FOOTPRINT; }
ulong fd_addrlut_create_align( void ){ return FD_ADDRLUT_CREATE_ALIGN; }

void fd_addrlut_create_walk(void * w, fd_addrlut_create_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_addrlut_create", level++);
  fun( w, &self->recent_slot, "recent_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->bump_seed, "bump_seed", FD_FLAMENCO_TYPE_UCHAR,   "uchar",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_addrlut_create", level--);
}
ulong fd_addrlut_create_size(fd_addrlut_create_t const * self) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(char);
  return size;
}

int fd_addrlut_create_encode(fd_addrlut_create_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->recent_slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->bump_seed), ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_addrlut_extend_decode(fd_addrlut_extend_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_addrlut_extend_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_addrlut_extend_new(self);
  fd_addrlut_extend_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_addrlut_extend_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  ulong new_addrs_len;
  err = fd_bincode_uint64_decode(&new_addrs_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (new_addrs_len != 0) {
    for( ulong i = 0; i < new_addrs_len; ++i) {
      err = fd_pubkey_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_addrlut_extend_decode_unsafe(fd_addrlut_extend_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint64_decode_unsafe(&self->new_addrs_len, ctx);
  if (self->new_addrs_len != 0) {
    self->new_addrs = (fd_pubkey_t *)fd_valloc_malloc( ctx->valloc, FD_PUBKEY_ALIGN, FD_PUBKEY_FOOTPRINT*self->new_addrs_len);
    for( ulong i = 0; i < self->new_addrs_len; ++i) {
      fd_pubkey_new(self->new_addrs + i);
      fd_pubkey_decode_unsafe(self->new_addrs + i, ctx);
    }
  } else
    self->new_addrs = NULL;
}
int fd_addrlut_extend_decode_offsets(fd_addrlut_extend_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->new_addrs_off = (uint)((ulong)ctx->data - (ulong)data);
  ulong new_addrs_len;
  err = fd_bincode_uint64_decode(&new_addrs_len, ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if (new_addrs_len != 0) {
    for( ulong i = 0; i < new_addrs_len; ++i) {
      err = fd_pubkey_decode_preflight(ctx);
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
void fd_addrlut_extend_new(fd_addrlut_extend_t* self) {
  fd_memset(self, 0, sizeof(fd_addrlut_extend_t));
}
void fd_addrlut_extend_destroy(fd_addrlut_extend_t* self, fd_bincode_destroy_ctx_t * ctx) {
  if (NULL != self->new_addrs) {
    for (ulong i = 0; i < self->new_addrs_len; ++i)
      fd_pubkey_destroy(self->new_addrs + i, ctx);
    fd_valloc_free( ctx->valloc, self->new_addrs );
    self->new_addrs = NULL;
  }
}

ulong fd_addrlut_extend_footprint( void ){ return FD_ADDRLUT_EXTEND_FOOTPRINT; }
ulong fd_addrlut_extend_align( void ){ return FD_ADDRLUT_EXTEND_ALIGN; }

void fd_addrlut_extend_walk(void * w, fd_addrlut_extend_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_addrlut_extend", level++);
  if (self->new_addrs_len != 0) {
    fun(w, NULL, NULL, FD_FLAMENCO_TYPE_ARR, "new_addrs", level++);
    for (ulong i = 0; i < self->new_addrs_len; ++i)
      fd_pubkey_walk(w, self->new_addrs + i, fun, "pubkey", level );
    fun( w, NULL, NULL, FD_FLAMENCO_TYPE_ARR_END, "new_addrs", level-- );
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_addrlut_extend", level--);
}
ulong fd_addrlut_extend_size(fd_addrlut_extend_t const * self) {
  ulong size = 0;
  do {
    size += sizeof(ulong);
    for (ulong i = 0; i < self->new_addrs_len; ++i)
      size += fd_pubkey_size(self->new_addrs + i);
  } while(0);
  return size;
}

int fd_addrlut_extend_encode(fd_addrlut_extend_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint64_encode(self->new_addrs_len, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  if (self->new_addrs_len != 0) {
    for (ulong i = 0; i < self->new_addrs_len; ++i) {
      err = fd_pubkey_encode(self->new_addrs + i, ctx);
      if ( FD_UNLIKELY(err) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_addrlut_instruction_is_create_lut(fd_addrlut_instruction_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_addrlut_instruction_is_freeze_lut(fd_addrlut_instruction_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_addrlut_instruction_is_extend_lut(fd_addrlut_instruction_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_addrlut_instruction_is_deactivate_lut(fd_addrlut_instruction_t const * self) {
  return self->discriminant == 3;
}
FD_FN_PURE uchar fd_addrlut_instruction_is_close_lut(fd_addrlut_instruction_t const * self) {
  return self->discriminant == 4;
}
void fd_addrlut_instruction_inner_new(fd_addrlut_instruction_inner_t* self, uint discriminant);
int fd_addrlut_instruction_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_addrlut_create_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_addrlut_extend_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_addrlut_instruction_inner_decode_unsafe(fd_addrlut_instruction_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_addrlut_create_decode_unsafe(&self->create_lut, ctx);
    break;
  }
  case 1: {
    break;
  }
  case 2: {
    fd_addrlut_extend_decode_unsafe(&self->extend_lut, ctx);
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  }
}
int fd_addrlut_instruction_decode(fd_addrlut_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_addrlut_instruction_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_addrlut_instruction_new(self);
  fd_addrlut_instruction_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_addrlut_instruction_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_addrlut_instruction_inner_decode_preflight(discriminant, ctx);
}
void fd_addrlut_instruction_decode_unsafe(fd_addrlut_instruction_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_addrlut_instruction_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_addrlut_instruction_inner_new(fd_addrlut_instruction_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_addrlut_create_new(&self->create_lut);
    break;
  }
  case 1: {
    break;
  }
  case 2: {
    fd_addrlut_extend_new(&self->extend_lut);
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_addrlut_instruction_new_disc(fd_addrlut_instruction_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_addrlut_instruction_inner_new(&self->inner, self->discriminant);
}
void fd_addrlut_instruction_new(fd_addrlut_instruction_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_addrlut_instruction_new_disc(self, UINT_MAX);
}
void fd_addrlut_instruction_inner_destroy(fd_addrlut_instruction_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_addrlut_create_destroy(&self->create_lut, ctx);
    break;
  }
  case 2: {
    fd_addrlut_extend_destroy(&self->extend_lut, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_addrlut_instruction_destroy(fd_addrlut_instruction_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_addrlut_instruction_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_addrlut_instruction_footprint( void ){ return FD_ADDRLUT_INSTRUCTION_FOOTPRINT; }
ulong fd_addrlut_instruction_align( void ){ return FD_ADDRLUT_INSTRUCTION_ALIGN; }

void fd_addrlut_instruction_walk(void * w, fd_addrlut_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_addrlut_instruction", level++);
  switch (self->discriminant) {
  case 0: {
    fd_addrlut_create_walk(w, &self->inner.create_lut, fun, "create_lut", level);
    break;
  }
  case 2: {
    fd_addrlut_extend_walk(w, &self->inner.extend_lut, fun, "extend_lut", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_addrlut_instruction", level--);
}
ulong fd_addrlut_instruction_size(fd_addrlut_instruction_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_addrlut_create_size(&self->inner.create_lut);
    break;
  }
  case 2: {
    size += fd_addrlut_extend_size(&self->inner.extend_lut);
    break;
  }
  }
  return size;
}

int fd_addrlut_instruction_inner_encode(fd_addrlut_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_addrlut_create_encode(&self->create_lut, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 2: {
    err = fd_addrlut_extend_encode(&self->extend_lut, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_addrlut_instruction_encode(fd_addrlut_instruction_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_addrlut_instruction_inner_encode(&self->inner, self->discriminant, ctx);
}

int fd_repair_request_header_decode(fd_repair_request_header_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_repair_request_header_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_repair_request_header_new(self);
  fd_repair_request_header_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_repair_request_header_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_signature_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_repair_request_header_decode_unsafe(fd_repair_request_header_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_signature_decode_unsafe(&self->signature, ctx);
  fd_pubkey_decode_unsafe(&self->sender, ctx);
  fd_pubkey_decode_unsafe(&self->recipient, ctx);
  fd_bincode_uint64_decode_unsafe(&self->timestamp, ctx);
  fd_bincode_uint32_decode_unsafe(&self->nonce, ctx);
}
int fd_repair_request_header_decode_offsets(fd_repair_request_header_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->signature_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_signature_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->sender_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->recipient_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_bytes_decode_preflight(32, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->timestamp_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->nonce_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint32_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_repair_request_header_new(fd_repair_request_header_t* self) {
  fd_memset(self, 0, sizeof(fd_repair_request_header_t));
  fd_signature_new(&self->signature);
  fd_pubkey_new(&self->sender);
  fd_pubkey_new(&self->recipient);
}
void fd_repair_request_header_destroy(fd_repair_request_header_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_signature_destroy(&self->signature, ctx);
  fd_pubkey_destroy(&self->sender, ctx);
  fd_pubkey_destroy(&self->recipient, ctx);
}

ulong fd_repair_request_header_footprint( void ){ return FD_REPAIR_REQUEST_HEADER_FOOTPRINT; }
ulong fd_repair_request_header_align( void ){ return FD_REPAIR_REQUEST_HEADER_ALIGN; }

void fd_repair_request_header_walk(void * w, fd_repair_request_header_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_repair_request_header", level++);
  fd_signature_walk(w, &self->signature, fun, "signature", level);
  fd_pubkey_walk(w, &self->sender, fun, "sender", level);
  fd_pubkey_walk(w, &self->recipient, fun, "recipient", level);
  fun( w, &self->timestamp, "timestamp", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->nonce, "nonce", FD_FLAMENCO_TYPE_UINT,    "uint",      level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_repair_request_header", level--);
}
ulong fd_repair_request_header_size(fd_repair_request_header_t const * self) {
  ulong size = 0;
  size += fd_signature_size(&self->signature);
  size += fd_pubkey_size(&self->sender);
  size += fd_pubkey_size(&self->recipient);
  size += sizeof(ulong);
  size += sizeof(uint);
  return size;
}

int fd_repair_request_header_encode(fd_repair_request_header_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_signature_encode(&self->signature, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->sender, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_pubkey_encode(&self->recipient, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->timestamp, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint32_encode( self->nonce, ctx );
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_repair_window_index_decode(fd_repair_window_index_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_repair_window_index_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_repair_window_index_new(self);
  fd_repair_window_index_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_repair_window_index_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_repair_request_header_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_repair_window_index_decode_unsafe(fd_repair_window_index_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_repair_request_header_decode_unsafe(&self->header, ctx);
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->shred_index, ctx);
}
int fd_repair_window_index_decode_offsets(fd_repair_window_index_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->header_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_repair_request_header_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->shred_index_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_repair_window_index_new(fd_repair_window_index_t* self) {
  fd_memset(self, 0, sizeof(fd_repair_window_index_t));
  fd_repair_request_header_new(&self->header);
}
void fd_repair_window_index_destroy(fd_repair_window_index_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_repair_request_header_destroy(&self->header, ctx);
}

ulong fd_repair_window_index_footprint( void ){ return FD_REPAIR_WINDOW_INDEX_FOOTPRINT; }
ulong fd_repair_window_index_align( void ){ return FD_REPAIR_WINDOW_INDEX_ALIGN; }

void fd_repair_window_index_walk(void * w, fd_repair_window_index_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_repair_window_index", level++);
  fd_repair_request_header_walk(w, &self->header, fun, "header", level);
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->shred_index, "shred_index", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_repair_window_index", level--);
}
ulong fd_repair_window_index_size(fd_repair_window_index_t const * self) {
  ulong size = 0;
  size += fd_repair_request_header_size(&self->header);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_repair_window_index_encode(fd_repair_window_index_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_repair_request_header_encode(&self->header, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->shred_index, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_repair_highest_window_index_decode(fd_repair_highest_window_index_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_repair_highest_window_index_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_repair_highest_window_index_new(self);
  fd_repair_highest_window_index_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_repair_highest_window_index_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_repair_request_header_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_repair_highest_window_index_decode_unsafe(fd_repair_highest_window_index_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_repair_request_header_decode_unsafe(&self->header, ctx);
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
  fd_bincode_uint64_decode_unsafe(&self->shred_index, ctx);
}
int fd_repair_highest_window_index_decode_offsets(fd_repair_highest_window_index_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->header_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_repair_request_header_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  self->shred_index_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_repair_highest_window_index_new(fd_repair_highest_window_index_t* self) {
  fd_memset(self, 0, sizeof(fd_repair_highest_window_index_t));
  fd_repair_request_header_new(&self->header);
}
void fd_repair_highest_window_index_destroy(fd_repair_highest_window_index_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_repair_request_header_destroy(&self->header, ctx);
}

ulong fd_repair_highest_window_index_footprint( void ){ return FD_REPAIR_HIGHEST_WINDOW_INDEX_FOOTPRINT; }
ulong fd_repair_highest_window_index_align( void ){ return FD_REPAIR_HIGHEST_WINDOW_INDEX_ALIGN; }

void fd_repair_highest_window_index_walk(void * w, fd_repair_highest_window_index_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_repair_highest_window_index", level++);
  fd_repair_request_header_walk(w, &self->header, fun, "header", level);
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun( w, &self->shred_index, "shred_index", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_repair_highest_window_index", level--);
}
ulong fd_repair_highest_window_index_size(fd_repair_highest_window_index_t const * self) {
  ulong size = 0;
  size += fd_repair_request_header_size(&self->header);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_repair_highest_window_index_encode(fd_repair_highest_window_index_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_repair_request_header_encode(&self->header, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->shred_index, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_repair_orphan_decode(fd_repair_orphan_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_repair_orphan_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_repair_orphan_new(self);
  fd_repair_orphan_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_repair_orphan_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_repair_request_header_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_repair_orphan_decode_unsafe(fd_repair_orphan_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_repair_request_header_decode_unsafe(&self->header, ctx);
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
}
int fd_repair_orphan_decode_offsets(fd_repair_orphan_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->header_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_repair_request_header_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_repair_orphan_new(fd_repair_orphan_t* self) {
  fd_memset(self, 0, sizeof(fd_repair_orphan_t));
  fd_repair_request_header_new(&self->header);
}
void fd_repair_orphan_destroy(fd_repair_orphan_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_repair_request_header_destroy(&self->header, ctx);
}

ulong fd_repair_orphan_footprint( void ){ return FD_REPAIR_ORPHAN_FOOTPRINT; }
ulong fd_repair_orphan_align( void ){ return FD_REPAIR_ORPHAN_ALIGN; }

void fd_repair_orphan_walk(void * w, fd_repair_orphan_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_repair_orphan", level++);
  fd_repair_request_header_walk(w, &self->header, fun, "header", level);
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_repair_orphan", level--);
}
ulong fd_repair_orphan_size(fd_repair_orphan_t const * self) {
  ulong size = 0;
  size += fd_repair_request_header_size(&self->header);
  size += sizeof(ulong);
  return size;
}

int fd_repair_orphan_encode(fd_repair_orphan_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_repair_request_header_encode(&self->header, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

int fd_repair_ancestor_hashes_decode(fd_repair_ancestor_hashes_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_repair_ancestor_hashes_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_repair_ancestor_hashes_new(self);
  fd_repair_ancestor_hashes_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_repair_ancestor_hashes_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  int err;
  err = fd_repair_request_header_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_repair_ancestor_hashes_decode_unsafe(fd_repair_ancestor_hashes_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_repair_request_header_decode_unsafe(&self->header, ctx);
  fd_bincode_uint64_decode_unsafe(&self->slot, ctx);
}
int fd_repair_ancestor_hashes_decode_offsets(fd_repair_ancestor_hashes_off_t* self, fd_bincode_decode_ctx_t * ctx) {
  uchar const * data = ctx->data;
  int err;
  self->header_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_repair_request_header_decode_preflight(ctx);
  if ( FD_UNLIKELY(err) ) return err;
  self->slot_off = (uint)((ulong)ctx->data - (ulong)data);
  err = fd_bincode_uint64_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return FD_BINCODE_SUCCESS;
}
void fd_repair_ancestor_hashes_new(fd_repair_ancestor_hashes_t* self) {
  fd_memset(self, 0, sizeof(fd_repair_ancestor_hashes_t));
  fd_repair_request_header_new(&self->header);
}
void fd_repair_ancestor_hashes_destroy(fd_repair_ancestor_hashes_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_repair_request_header_destroy(&self->header, ctx);
}

ulong fd_repair_ancestor_hashes_footprint( void ){ return FD_REPAIR_ANCESTOR_HASHES_FOOTPRINT; }
ulong fd_repair_ancestor_hashes_align( void ){ return FD_REPAIR_ANCESTOR_HASHES_ALIGN; }

void fd_repair_ancestor_hashes_walk(void * w, fd_repair_ancestor_hashes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_repair_ancestor_hashes", level++);
  fd_repair_request_header_walk(w, &self->header, fun, "header", level);
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",     level );
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_repair_ancestor_hashes", level--);
}
ulong fd_repair_ancestor_hashes_size(fd_repair_ancestor_hashes_t const * self) {
  ulong size = 0;
  size += fd_repair_request_header_size(&self->header);
  size += sizeof(ulong);
  return size;
}

int fd_repair_ancestor_hashes_encode(fd_repair_ancestor_hashes_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_repair_request_header_encode(&self->header, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  err = fd_bincode_uint64_encode(self->slot, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return FD_BINCODE_SUCCESS;
}

FD_FN_PURE uchar fd_repair_protocol_is_LegacyWindowIndex(fd_repair_protocol_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_repair_protocol_is_LegacyHighestWindowIndex(fd_repair_protocol_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_repair_protocol_is_LegacyOrphan(fd_repair_protocol_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_repair_protocol_is_LegacyWindowIndexWithNonce(fd_repair_protocol_t const * self) {
  return self->discriminant == 3;
}
FD_FN_PURE uchar fd_repair_protocol_is_LegacyHighestWindowIndexWithNonce(fd_repair_protocol_t const * self) {
  return self->discriminant == 4;
}
FD_FN_PURE uchar fd_repair_protocol_is_LegacyOrphanWithNonce(fd_repair_protocol_t const * self) {
  return self->discriminant == 5;
}
FD_FN_PURE uchar fd_repair_protocol_is_LegacyAncestorHashes(fd_repair_protocol_t const * self) {
  return self->discriminant == 6;
}
FD_FN_PURE uchar fd_repair_protocol_is_pong(fd_repair_protocol_t const * self) {
  return self->discriminant == 7;
}
FD_FN_PURE uchar fd_repair_protocol_is_window_index(fd_repair_protocol_t const * self) {
  return self->discriminant == 8;
}
FD_FN_PURE uchar fd_repair_protocol_is_highest_window_index(fd_repair_protocol_t const * self) {
  return self->discriminant == 9;
}
FD_FN_PURE uchar fd_repair_protocol_is_orphan(fd_repair_protocol_t const * self) {
  return self->discriminant == 10;
}
FD_FN_PURE uchar fd_repair_protocol_is_ancestor_hashes(fd_repair_protocol_t const * self) {
  return self->discriminant == 11;
}
void fd_repair_protocol_inner_new(fd_repair_protocol_inner_t* self, uint discriminant);
int fd_repair_protocol_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    return FD_BINCODE_SUCCESS;
  }
  case 5: {
    return FD_BINCODE_SUCCESS;
  }
  case 6: {
    return FD_BINCODE_SUCCESS;
  }
  case 7: {
    err = fd_gossip_ping_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 8: {
    err = fd_repair_window_index_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 9: {
    err = fd_repair_highest_window_index_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 10: {
    err = fd_repair_orphan_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 11: {
    err = fd_repair_ancestor_hashes_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_repair_protocol_inner_decode_unsafe(fd_repair_protocol_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    break;
  }
  case 7: {
    fd_gossip_ping_decode_unsafe(&self->pong, ctx);
    break;
  }
  case 8: {
    fd_repair_window_index_decode_unsafe(&self->window_index, ctx);
    break;
  }
  case 9: {
    fd_repair_highest_window_index_decode_unsafe(&self->highest_window_index, ctx);
    break;
  }
  case 10: {
    fd_repair_orphan_decode_unsafe(&self->orphan, ctx);
    break;
  }
  case 11: {
    fd_repair_ancestor_hashes_decode_unsafe(&self->ancestor_hashes, ctx);
    break;
  }
  }
}
int fd_repair_protocol_decode(fd_repair_protocol_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_repair_protocol_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_repair_protocol_new(self);
  fd_repair_protocol_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_repair_protocol_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_repair_protocol_inner_decode_preflight(discriminant, ctx);
}
void fd_repair_protocol_decode_unsafe(fd_repair_protocol_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_repair_protocol_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_repair_protocol_inner_new(fd_repair_protocol_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    break;
  }
  case 7: {
    fd_gossip_ping_new(&self->pong);
    break;
  }
  case 8: {
    fd_repair_window_index_new(&self->window_index);
    break;
  }
  case 9: {
    fd_repair_highest_window_index_new(&self->highest_window_index);
    break;
  }
  case 10: {
    fd_repair_orphan_new(&self->orphan);
    break;
  }
  case 11: {
    fd_repair_ancestor_hashes_new(&self->ancestor_hashes);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_repair_protocol_new_disc(fd_repair_protocol_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_repair_protocol_inner_new(&self->inner, self->discriminant);
}
void fd_repair_protocol_new(fd_repair_protocol_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_repair_protocol_new_disc(self, UINT_MAX);
}
void fd_repair_protocol_inner_destroy(fd_repair_protocol_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 7: {
    fd_gossip_ping_destroy(&self->pong, ctx);
    break;
  }
  case 8: {
    fd_repair_window_index_destroy(&self->window_index, ctx);
    break;
  }
  case 9: {
    fd_repair_highest_window_index_destroy(&self->highest_window_index, ctx);
    break;
  }
  case 10: {
    fd_repair_orphan_destroy(&self->orphan, ctx);
    break;
  }
  case 11: {
    fd_repair_ancestor_hashes_destroy(&self->ancestor_hashes, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_repair_protocol_destroy(fd_repair_protocol_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_repair_protocol_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_repair_protocol_footprint( void ){ return FD_REPAIR_PROTOCOL_FOOTPRINT; }
ulong fd_repair_protocol_align( void ){ return FD_REPAIR_PROTOCOL_ALIGN; }

void fd_repair_protocol_walk(void * w, fd_repair_protocol_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_repair_protocol", level++);
  switch (self->discriminant) {
  case 7: {
    fd_gossip_ping_walk(w, &self->inner.pong, fun, "pong", level);
    break;
  }
  case 8: {
    fd_repair_window_index_walk(w, &self->inner.window_index, fun, "window_index", level);
    break;
  }
  case 9: {
    fd_repair_highest_window_index_walk(w, &self->inner.highest_window_index, fun, "highest_window_index", level);
    break;
  }
  case 10: {
    fd_repair_orphan_walk(w, &self->inner.orphan, fun, "orphan", level);
    break;
  }
  case 11: {
    fd_repair_ancestor_hashes_walk(w, &self->inner.ancestor_hashes, fun, "ancestor_hashes", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_repair_protocol", level--);
}
ulong fd_repair_protocol_size(fd_repair_protocol_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 7: {
    size += fd_gossip_ping_size(&self->inner.pong);
    break;
  }
  case 8: {
    size += fd_repair_window_index_size(&self->inner.window_index);
    break;
  }
  case 9: {
    size += fd_repair_highest_window_index_size(&self->inner.highest_window_index);
    break;
  }
  case 10: {
    size += fd_repair_orphan_size(&self->inner.orphan);
    break;
  }
  case 11: {
    size += fd_repair_ancestor_hashes_size(&self->inner.ancestor_hashes);
    break;
  }
  }
  return size;
}

int fd_repair_protocol_inner_encode(fd_repair_protocol_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 7: {
    err = fd_gossip_ping_encode(&self->pong, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 8: {
    err = fd_repair_window_index_encode(&self->window_index, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 9: {
    err = fd_repair_highest_window_index_encode(&self->highest_window_index, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 10: {
    err = fd_repair_orphan_encode(&self->orphan, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  case 11: {
    err = fd_repair_ancestor_hashes_encode(&self->ancestor_hashes, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_repair_protocol_encode(fd_repair_protocol_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_repair_protocol_inner_encode(&self->inner, self->discriminant, ctx);
}

FD_FN_PURE uchar fd_repair_response_is_ping(fd_repair_response_t const * self) {
  return self->discriminant == 0;
}
void fd_repair_response_inner_new(fd_repair_response_inner_t* self, uint discriminant);
int fd_repair_response_inner_decode_preflight(uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_ping_decode_preflight(ctx);
    if ( FD_UNLIKELY(err) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
void fd_repair_response_inner_decode_unsafe(fd_repair_response_inner_t* self, uint discriminant, fd_bincode_decode_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_gossip_ping_decode_unsafe(&self->ping, ctx);
    break;
  }
  }
}
int fd_repair_response_decode(fd_repair_response_t* self, fd_bincode_decode_ctx_t * ctx) {
  void const * data = ctx->data;
  int err = fd_repair_response_decode_preflight(ctx);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ctx->data = data;
  fd_repair_response_new(self);
  fd_repair_response_decode_unsafe(self, ctx);
  return FD_BINCODE_SUCCESS;
}
int fd_repair_response_decode_preflight(fd_bincode_decode_ctx_t * ctx) {
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode(&discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_repair_response_inner_decode_preflight(discriminant, ctx);
}
void fd_repair_response_decode_unsafe(fd_repair_response_t* self, fd_bincode_decode_ctx_t * ctx) {
  fd_bincode_uint32_decode_unsafe(&self->discriminant, ctx);
  fd_repair_response_inner_decode_unsafe(&self->inner, self->discriminant, ctx);
}
void fd_repair_response_inner_new(fd_repair_response_inner_t* self, uint discriminant) {
  switch (discriminant) {
  case 0: {
    fd_gossip_ping_new(&self->ping);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_repair_response_new_disc(fd_repair_response_t* self, uint discriminant) {
  self->discriminant = discriminant;
  fd_repair_response_inner_new(&self->inner, self->discriminant);
}
void fd_repair_response_new(fd_repair_response_t* self) {
  fd_memset(self, 0, sizeof(*self));
  fd_repair_response_new_disc(self, UINT_MAX);
}
void fd_repair_response_inner_destroy(fd_repair_response_inner_t* self, uint discriminant, fd_bincode_destroy_ctx_t * ctx) {
  switch (discriminant) {
  case 0: {
    fd_gossip_ping_destroy(&self->ping, ctx);
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type" ));
  }
}
void fd_repair_response_destroy(fd_repair_response_t* self, fd_bincode_destroy_ctx_t * ctx) {
  fd_repair_response_inner_destroy(&self->inner, self->discriminant, ctx);
}

ulong fd_repair_response_footprint( void ){ return FD_REPAIR_RESPONSE_FOOTPRINT; }
ulong fd_repair_response_align( void ){ return FD_REPAIR_RESPONSE_ALIGN; }

void fd_repair_response_walk(void * w, fd_repair_response_t const * self, fd_types_walk_fn_t fun, const char *name, uint level) {
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_repair_response", level++);
  switch (self->discriminant) {
  case 0: {
    fd_gossip_ping_walk(w, &self->inner.ping, fun, "ping", level);
    break;
  }
  }
  fun(w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_repair_response", level--);
}
ulong fd_repair_response_size(fd_repair_response_t const * self) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_gossip_ping_size(&self->inner.ping);
    break;
  }
  }
  return size;
}

int fd_repair_response_inner_encode(fd_repair_response_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_ping_encode(&self->ping, ctx);
    if ( FD_UNLIKELY(err) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_repair_response_encode(fd_repair_response_t const * self, fd_bincode_encode_ctx_t * ctx) {
  int err;
  err = fd_bincode_uint32_encode(self->discriminant, ctx);
  if ( FD_UNLIKELY(err) ) return err;
  return fd_repair_response_inner_encode(&self->inner, self->discriminant, ctx);
}

#define REDBLK_T fd_vote_accounts_pair_t_mapnode_t
#define REDBLK_NAME fd_vote_accounts_pair_t_map
#define REDBLK_IMPL_STYLE 2
#include "../../util/tmpl/fd_redblack.c"
#undef REDBLK_T
#undef REDBLK_NAME
long fd_vote_accounts_pair_t_map_compare(fd_vote_accounts_pair_t_mapnode_t * left, fd_vote_accounts_pair_t_mapnode_t * right) {
  return memcmp(left->elem.key.uc, right->elem.key.uc, sizeof(right->elem.key));
}
#define REDBLK_T fd_stake_accounts_pair_t_mapnode_t
#define REDBLK_NAME fd_stake_accounts_pair_t_map
#define REDBLK_IMPL_STYLE 2
#include "../../util/tmpl/fd_redblack.c"
#undef REDBLK_T
#undef REDBLK_NAME
long fd_stake_accounts_pair_t_map_compare(fd_stake_accounts_pair_t_mapnode_t * left, fd_stake_accounts_pair_t_mapnode_t * right) {
  return memcmp(left->elem.key.uc, right->elem.key.uc, sizeof(right->elem.key));
}
#define REDBLK_T fd_stake_weight_t_mapnode_t
#define REDBLK_NAME fd_stake_weight_t_map
#define REDBLK_IMPL_STYLE 2
#include "../../util/tmpl/fd_redblack.c"
#undef REDBLK_T
#undef REDBLK_NAME
long fd_stake_weight_t_map_compare(fd_stake_weight_t_mapnode_t * left, fd_stake_weight_t_mapnode_t * right) {
  return memcmp(left->elem.key.uc, right->elem.key.uc, sizeof(right->elem.key));
}
#define REDBLK_T fd_delegation_pair_t_mapnode_t
#define REDBLK_NAME fd_delegation_pair_t_map
#define REDBLK_IMPL_STYLE 2
#include "../../util/tmpl/fd_redblack.c"
#undef REDBLK_T
#undef REDBLK_NAME
long fd_delegation_pair_t_map_compare(fd_delegation_pair_t_mapnode_t * left, fd_delegation_pair_t_mapnode_t * right) {
  return memcmp(left->elem.account.uc, right->elem.account.uc, sizeof(right->elem.account));
}
#define REDBLK_T fd_clock_timestamp_vote_t_mapnode_t
#define REDBLK_NAME fd_clock_timestamp_vote_t_map
#define REDBLK_IMPL_STYLE 2
#include "../../util/tmpl/fd_redblack.c"
#undef REDBLK_T
#undef REDBLK_NAME
long fd_clock_timestamp_vote_t_map_compare(fd_clock_timestamp_vote_t_mapnode_t * left, fd_clock_timestamp_vote_t_mapnode_t * right) {
  return memcmp(left->elem.pubkey.uc, right->elem.pubkey.uc, sizeof(right->elem.pubkey));
}
