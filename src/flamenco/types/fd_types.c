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
int fd_hash_encode( fd_hash_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  return fd_bincode_bytes_encode( (uchar const *)self, sizeof(fd_hash_t), ctx );
}
void fd_hash_walk( void * w, fd_hash_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  fun( w, (uchar const *)self, name, FD_FLAMENCO_TYPE_HASH256, name, level, varint );
}
static int fd_hash_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return fd_bincode_bytes_decode_footprint( sizeof(fd_hash_t), ctx );
}
int fd_hash_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_hash_t);
  void const * start_data = ctx->data;
  int err = fd_hash_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_hash_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bincode_bytes_decode_unsafe( struct_mem, sizeof(fd_hash_t), ctx );
  return;
}
void * fd_hash_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bincode_bytes_decode_unsafe( mem, sizeof(fd_hash_t), ctx );
  return mem;
}

int fd_signature_encode( fd_signature_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  return fd_bincode_bytes_encode( (uchar const *)self, sizeof(fd_signature_t), ctx );
}
void fd_signature_walk( void * w, fd_signature_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  fun( w, (uchar const *)self, name, FD_FLAMENCO_TYPE_SIG512, name, level, varint );
}
static int fd_signature_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return fd_bincode_bytes_decode_footprint( sizeof(fd_signature_t), ctx );
}
int fd_signature_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_signature_t);
  void const * start_data = ctx->data;
  int err = fd_signature_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_signature_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bincode_bytes_decode_unsafe( struct_mem, sizeof(fd_signature_t), ctx );
  return;
}
void * fd_signature_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bincode_bytes_decode_unsafe( mem, sizeof(fd_signature_t), ctx );
  return mem;
}

int fd_gossip_ip4_addr_encode( fd_gossip_ip4_addr_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  return fd_bincode_bytes_encode( (uchar const *)self, sizeof(fd_gossip_ip4_addr_t), ctx );
}
static int fd_gossip_ip4_addr_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return fd_bincode_bytes_decode_footprint( sizeof(fd_gossip_ip4_addr_t), ctx );
}
int fd_gossip_ip4_addr_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_ip4_addr_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_ip4_addr_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_ip4_addr_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bincode_bytes_decode_unsafe( struct_mem, sizeof(fd_gossip_ip4_addr_t), ctx );
  return;
}
void * fd_gossip_ip4_addr_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bincode_bytes_decode_unsafe( mem, sizeof(fd_gossip_ip4_addr_t), ctx );
  return mem;
}

int fd_gossip_ip6_addr_encode( fd_gossip_ip6_addr_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  return fd_bincode_bytes_encode( (uchar const *)self, sizeof(fd_gossip_ip6_addr_t), ctx );
}
static int fd_gossip_ip6_addr_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return fd_bincode_bytes_decode_footprint( sizeof(fd_gossip_ip6_addr_t), ctx );
}
int fd_gossip_ip6_addr_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_ip6_addr_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_ip6_addr_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_ip6_addr_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bincode_bytes_decode_unsafe( struct_mem, sizeof(fd_gossip_ip6_addr_t), ctx );
  return;
}
void * fd_gossip_ip6_addr_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bincode_bytes_decode_unsafe( mem, sizeof(fd_gossip_ip6_addr_t), ctx );
  return mem;
}

int fd_feature_encode( fd_feature_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_bool_encode( self->has_activated_at, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_activated_at ) {
    err = fd_bincode_uint64_encode( self->activated_at, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_feature_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_feature_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_feature_t);
  void const * start_data = ctx->data;
  int err = fd_feature_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_feature_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_feature_t * self = (fd_feature_t *)struct_mem;
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_activated_at = !!o;
    if( o ) {
      fd_bincode_uint64_decode_unsafe( &self->activated_at, ctx );
    }
  }
}
void * fd_feature_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_feature_t * self = (fd_feature_t *)mem;
  fd_feature_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_feature_t);
  void * * alloc_mem = &alloc_region;
  fd_feature_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_feature_new(fd_feature_t * self) {
  fd_memset( self, 0, sizeof(fd_feature_t) );
}
void fd_feature_walk( void * w, fd_feature_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_feature", level++, 0 );
  if( !self->has_activated_at ) {
    fun( w, NULL, "activated_at", FD_FLAMENCO_TYPE_NULL, "ulong", level, 0 );
  } else {
    fun( w, &self->activated_at, "activated_at", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_feature", level--, 0 );
}
ulong fd_feature_size( fd_feature_t const * self ) {
  ulong size = 0;
  size += sizeof(char);
  if( self->has_activated_at ) {
    size += sizeof(ulong);
  }
  return size;
}

int fd_fee_calculator_encode( fd_fee_calculator_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->lamports_per_signature, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_fee_calculator_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 8UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 8UL );
  return 0;
}
static void fd_fee_calculator_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_fee_calculator_t * self = (fd_fee_calculator_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->lamports_per_signature, ctx );
}
void * fd_fee_calculator_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_fee_calculator_t * self = (fd_fee_calculator_t *)mem;
  fd_fee_calculator_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_fee_calculator_t);
  void * * alloc_mem = &alloc_region;
  fd_fee_calculator_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_fee_calculator_walk( void * w, fd_fee_calculator_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_fee_calculator", level++, 0 );
  fun( w, &self->lamports_per_signature, "lamports_per_signature", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_fee_calculator", level--, 0 );
}
int fd_fee_rate_governor_encode( fd_fee_rate_governor_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->target_lamports_per_signature, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->target_signatures_per_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->min_lamports_per_signature, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->max_lamports_per_signature, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->burn_percent), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_fee_rate_governor_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 33UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 33UL );
  return 0;
}
static void fd_fee_rate_governor_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_fee_rate_governor_t * self = (fd_fee_rate_governor_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->target_lamports_per_signature, ctx );
  fd_bincode_uint64_decode_unsafe( &self->target_signatures_per_slot, ctx );
  fd_bincode_uint64_decode_unsafe( &self->min_lamports_per_signature, ctx );
  fd_bincode_uint64_decode_unsafe( &self->max_lamports_per_signature, ctx );
  fd_bincode_uint8_decode_unsafe( &self->burn_percent, ctx );
}
void * fd_fee_rate_governor_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_fee_rate_governor_t * self = (fd_fee_rate_governor_t *)mem;
  fd_fee_rate_governor_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_fee_rate_governor_t);
  void * * alloc_mem = &alloc_region;
  fd_fee_rate_governor_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_fee_rate_governor_walk( void * w, fd_fee_rate_governor_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_fee_rate_governor", level++, 0 );
  fun( w, &self->target_lamports_per_signature, "target_lamports_per_signature", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->target_signatures_per_slot, "target_signatures_per_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->min_lamports_per_signature, "min_lamports_per_signature", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->max_lamports_per_signature, "max_lamports_per_signature", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->burn_percent, "burn_percent", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_fee_rate_governor", level--, 0 );
}
int fd_slot_pair_encode( fd_slot_pair_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->val, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_slot_pair_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 16UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 16UL );
  return 0;
}
static void fd_slot_pair_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_slot_pair_t * self = (fd_slot_pair_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->slot, ctx );
  fd_bincode_uint64_decode_unsafe( &self->val, ctx );
}
void * fd_slot_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_slot_pair_t * self = (fd_slot_pair_t *)mem;
  fd_slot_pair_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_slot_pair_t);
  void * * alloc_mem = &alloc_region;
  fd_slot_pair_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_slot_pair_walk( void * w, fd_slot_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_slot_pair", level++, 0 );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->val, "val", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_slot_pair", level--, 0 );
}
int fd_hard_forks_encode( fd_hard_forks_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->hard_forks_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->hard_forks_len ) {
    for( ulong i=0; i < self->hard_forks_len; i++ ) {
      err = fd_slot_pair_encode( self->hard_forks + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_hard_forks_encode_global( fd_hard_forks_global_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->hard_forks_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->hard_forks_len ) {
    uchar * hard_forks_laddr = (uchar*)self + self->hard_forks_offset;
    fd_slot_pair_t * hard_forks = (fd_slot_pair_t *)hard_forks_laddr;
    for( ulong i=0; i < self->hard_forks_len; i++ ) {
      err = fd_slot_pair_encode( &hard_forks[i], ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_hard_forks_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ulong hard_forks_len;
  err = fd_bincode_uint64_decode( &hard_forks_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( hard_forks_len ) {
    *total_sz += FD_SLOT_PAIR_ALIGN + sizeof(fd_slot_pair_t)*hard_forks_len;
    for( ulong i=0; i < hard_forks_len; i++ ) {
      err = fd_slot_pair_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_hard_forks_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_hard_forks_t);
  void const * start_data = ctx->data;
  int err = fd_hard_forks_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_hard_forks_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_hard_forks_t * self = (fd_hard_forks_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->hard_forks_len, ctx );
  if( self->hard_forks_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_SLOT_PAIR_ALIGN );
    self->hard_forks = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_slot_pair_t)*self->hard_forks_len;
    for( ulong i=0; i < self->hard_forks_len; i++ ) {
      fd_slot_pair_new( self->hard_forks + i );
      fd_slot_pair_decode_inner( self->hard_forks + i, alloc_mem, ctx );
    }
  } else
    self->hard_forks = NULL;
}
void * fd_hard_forks_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_hard_forks_t * self = (fd_hard_forks_t *)mem;
  fd_hard_forks_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_hard_forks_t);
  void * * alloc_mem = &alloc_region;
  fd_hard_forks_decode_inner( mem, alloc_mem, ctx );
  return self;
}
static void fd_hard_forks_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_hard_forks_global_t * self = (fd_hard_forks_global_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->hard_forks_len, ctx );
  if( self->hard_forks_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_SLOT_PAIR_ALIGN );
    self->hard_forks_offset = (ulong)*alloc_mem - (ulong)struct_mem;
    uchar * cur_mem = (uchar *)(*alloc_mem);
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_slot_pair_t)*self->hard_forks_len;
    for( ulong i=0; i < self->hard_forks_len; i++ ) {
      fd_slot_pair_new( (fd_slot_pair_t *)fd_type_pun(cur_mem + sizeof(fd_slot_pair_t) * i) );
      fd_slot_pair_decode_inner( cur_mem + sizeof(fd_slot_pair_t) * i, alloc_mem, ctx );
    }
  } else {
    self->hard_forks_offset = 0UL;
  }
}
void * fd_hard_forks_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_hard_forks_global_t * self = (fd_hard_forks_global_t *)mem;
  fd_hard_forks_new( (fd_hard_forks_t *)self );
  void * alloc_region = (uchar *)mem + sizeof(fd_hard_forks_global_t);
  void * * alloc_mem = &alloc_region;
  fd_hard_forks_decode_inner_global( mem, alloc_mem, ctx );
  return self;
}
void fd_hard_forks_new(fd_hard_forks_t * self) {
  fd_memset( self, 0, sizeof(fd_hard_forks_t) );
}
void fd_hard_forks_walk( void * w, fd_hard_forks_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_hard_forks", level++, 0 );
  if( self->hard_forks_len ) {
    fun( w, NULL, "hard_forks", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->hard_forks_len; i++ )
      fd_slot_pair_walk(w, self->hard_forks + i, fun, "slot_pair", level, 0 );
    fun( w, NULL, "hard_forks", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_hard_forks", level--, 0 );
}
ulong fd_hard_forks_size( fd_hard_forks_t const * self ) {
  ulong size = 0;
  do {
    size += sizeof(ulong);
    for( ulong i=0; i < self->hard_forks_len; i++ )
      size += fd_slot_pair_size( self->hard_forks + i );
  } while(0);
  return size;
}

ulong fd_hard_forks_size_global( fd_hard_forks_global_t const * self ) {
  ulong size = 0;
  do {
    size += sizeof(ulong);
    fd_slot_pair_t * hard_forks = self->hard_forks_offset ? (fd_slot_pair_t *)fd_type_pun( (uchar *)self + self->hard_forks_offset ) : NULL;
    for( ulong i=0; i < self->hard_forks_len; i++ )
      size += fd_slot_pair_size( hard_forks + i );
  } while(0);
  return size;
}

int fd_inflation_encode( fd_inflation_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_double_encode( self->initial, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_double_encode( self->terminal, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_double_encode( self->taper, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_double_encode( self->foundation, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_double_encode( self->foundation_term, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_double_encode( self->unused, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_inflation_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 48UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 48UL );
  return 0;
}
static void fd_inflation_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_inflation_t * self = (fd_inflation_t *)struct_mem;
  fd_bincode_double_decode_unsafe( &self->initial, ctx );
  fd_bincode_double_decode_unsafe( &self->terminal, ctx );
  fd_bincode_double_decode_unsafe( &self->taper, ctx );
  fd_bincode_double_decode_unsafe( &self->foundation, ctx );
  fd_bincode_double_decode_unsafe( &self->foundation_term, ctx );
  fd_bincode_double_decode_unsafe( &self->unused, ctx );
}
void * fd_inflation_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_inflation_t * self = (fd_inflation_t *)mem;
  fd_inflation_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_inflation_t);
  void * * alloc_mem = &alloc_region;
  fd_inflation_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_inflation_walk( void * w, fd_inflation_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_inflation", level++, 0 );
  fun( w, &self->initial, "initial", FD_FLAMENCO_TYPE_DOUBLE, "double", level, 0  );
  fun( w, &self->terminal, "terminal", FD_FLAMENCO_TYPE_DOUBLE, "double", level, 0  );
  fun( w, &self->taper, "taper", FD_FLAMENCO_TYPE_DOUBLE, "double", level, 0  );
  fun( w, &self->foundation, "foundation", FD_FLAMENCO_TYPE_DOUBLE, "double", level, 0  );
  fun( w, &self->foundation_term, "foundation_term", FD_FLAMENCO_TYPE_DOUBLE, "double", level, 0  );
  fun( w, &self->unused, "unused", FD_FLAMENCO_TYPE_DOUBLE, "double", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_inflation", level--, 0 );
}
int fd_rent_encode( fd_rent_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->lamports_per_uint8_year, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_double_encode( self->exemption_threshold, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->burn_percent), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_rent_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 17UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 17UL );
  return 0;
}
static void fd_rent_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_rent_t * self = (fd_rent_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->lamports_per_uint8_year, ctx );
  fd_bincode_double_decode_unsafe( &self->exemption_threshold, ctx );
  fd_bincode_uint8_decode_unsafe( &self->burn_percent, ctx );
}
void * fd_rent_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_rent_t * self = (fd_rent_t *)mem;
  fd_rent_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_rent_t);
  void * * alloc_mem = &alloc_region;
  fd_rent_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_rent_walk( void * w, fd_rent_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_rent", level++, 0 );
  fun( w, &self->lamports_per_uint8_year, "lamports_per_uint8_year", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->exemption_threshold, "exemption_threshold", FD_FLAMENCO_TYPE_DOUBLE, "double", level, 0  );
  fun( w, &self->burn_percent, "burn_percent", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_rent", level--, 0 );
}
int fd_epoch_schedule_encode( fd_epoch_schedule_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->slots_per_epoch, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->leader_schedule_slot_offset, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_encode( (uchar)(self->warmup), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->first_normal_epoch, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->first_normal_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_epoch_schedule_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_bool_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_epoch_schedule_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_epoch_schedule_t);
  void const * start_data = ctx->data;
  int err = fd_epoch_schedule_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_epoch_schedule_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_epoch_schedule_t * self = (fd_epoch_schedule_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->slots_per_epoch, ctx );
  fd_bincode_uint64_decode_unsafe( &self->leader_schedule_slot_offset, ctx );
  fd_bincode_bool_decode_unsafe( &self->warmup, ctx );
  fd_bincode_uint64_decode_unsafe( &self->first_normal_epoch, ctx );
  fd_bincode_uint64_decode_unsafe( &self->first_normal_slot, ctx );
}
void * fd_epoch_schedule_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_epoch_schedule_t * self = (fd_epoch_schedule_t *)mem;
  fd_epoch_schedule_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_epoch_schedule_t);
  void * * alloc_mem = &alloc_region;
  fd_epoch_schedule_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_epoch_schedule_new(fd_epoch_schedule_t * self) {
  fd_memset( self, 0, sizeof(fd_epoch_schedule_t) );
}
void fd_epoch_schedule_walk( void * w, fd_epoch_schedule_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_epoch_schedule", level++, 0 );
  fun( w, &self->slots_per_epoch, "slots_per_epoch", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->leader_schedule_slot_offset, "leader_schedule_slot_offset", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->warmup, "warmup", FD_FLAMENCO_TYPE_BOOL, "bool", level, 0  );
  fun( w, &self->first_normal_epoch, "first_normal_epoch", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->first_normal_slot, "first_normal_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_epoch_schedule", level--, 0 );
}
int fd_rent_collector_encode( fd_rent_collector_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->epoch, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_epoch_schedule_encode( &self->epoch_schedule, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_double_encode( self->slots_per_year, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_rent_encode( &self->rent, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_rent_collector_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_epoch_schedule_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_double_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_rent_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_rent_collector_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_rent_collector_t);
  void const * start_data = ctx->data;
  int err = fd_rent_collector_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_rent_collector_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_rent_collector_t * self = (fd_rent_collector_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->epoch, ctx );
  fd_epoch_schedule_decode_inner( &self->epoch_schedule, alloc_mem, ctx );
  fd_bincode_double_decode_unsafe( &self->slots_per_year, ctx );
  fd_rent_decode_inner( &self->rent, alloc_mem, ctx );
}
void * fd_rent_collector_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_rent_collector_t * self = (fd_rent_collector_t *)mem;
  fd_rent_collector_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_rent_collector_t);
  void * * alloc_mem = &alloc_region;
  fd_rent_collector_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_rent_collector_new(fd_rent_collector_t * self) {
  fd_memset( self, 0, sizeof(fd_rent_collector_t) );
  fd_epoch_schedule_new( &self->epoch_schedule );
  fd_rent_new( &self->rent );
}
void fd_rent_collector_walk( void * w, fd_rent_collector_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_rent_collector", level++, 0 );
  fun( w, &self->epoch, "epoch", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_epoch_schedule_walk( w, &self->epoch_schedule, fun, "epoch_schedule", level, 0 );
  fun( w, &self->slots_per_year, "slots_per_year", FD_FLAMENCO_TYPE_DOUBLE, "double", level, 0  );
  fd_rent_walk( w, &self->rent, fun, "rent", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_rent_collector", level--, 0 );
}
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
void fd_stake_history_entry_walk( void * w, fd_stake_history_entry_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_history_entry", level++, 0 );
  fun( w, &self->effective, "effective", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->activating, "activating", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->deactivating, "deactivating", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_history_entry", level--, 0 );
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
void fd_epoch_stake_history_entry_pair_walk( void * w, fd_epoch_stake_history_entry_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_epoch_stake_history_entry_pair", level++, 0 );
  fun( w, &self->epoch, "epoch", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_stake_history_entry_walk( w, &self->entry, fun, "entry", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_epoch_stake_history_entry_pair", level--, 0 );
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
void fd_stake_history_walk( void * w, fd_stake_history_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_history", level++, 0 );
  fun( w, NULL, "fd_stake_history", FD_FLAMENCO_TYPE_ARR, "epoch_stake_history_entry_pair[]", level++, 0 );
  for( ulong i=0; i<self->fd_stake_history_len; i++ ) {
    ulong idx = ( i + self->fd_stake_history_offset ) & (512 - 1);
    fd_epoch_stake_history_entry_pair_walk( w, self->fd_stake_history + idx, fun, "epoch_stake_history_entry_pair", level, 0 );
  }
  fun( w, NULL, "fd_stake_history", FD_FLAMENCO_TYPE_ARR_END, "epoch_stake_history_entry_pair[]", level--, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_history", level--, 0 );
}
int fd_solana_account_encode( fd_solana_account_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->lamports, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->data_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->data_len ) {
    err = fd_bincode_bytes_encode( self->data, self->data_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_pubkey_encode( &self->owner, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_encode( (uchar)(self->executable), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->rent_epoch, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_solana_account_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ulong data_len;
  err = fd_bincode_uint64_decode( &data_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( data_len ) {
    *total_sz += 8UL + data_len;
    err = fd_bincode_bytes_decode_footprint( data_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_solana_account_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_solana_account_t);
  void const * start_data = ctx->data;
  int err = fd_solana_account_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_solana_account_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_solana_account_t * self = (fd_solana_account_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->lamports, ctx );
  fd_bincode_uint64_decode_unsafe( &self->data_len, ctx );
  if( self->data_len ) {
    self->data = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->data, self->data_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->data_len;
  } else
    self->data = NULL;
  fd_pubkey_decode_inner( &self->owner, alloc_mem, ctx );
  fd_bincode_bool_decode_unsafe( &self->executable, ctx );
  fd_bincode_uint64_decode_unsafe( &self->rent_epoch, ctx );
}
void * fd_solana_account_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_solana_account_t * self = (fd_solana_account_t *)mem;
  fd_solana_account_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_solana_account_t);
  void * * alloc_mem = &alloc_region;
  fd_solana_account_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_solana_account_new(fd_solana_account_t * self) {
  fd_memset( self, 0, sizeof(fd_solana_account_t) );
  fd_pubkey_new( &self->owner );
}
void fd_solana_account_walk( void * w, fd_solana_account_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_solana_account", level++, 0 );
  fun( w, &self->lamports, "lamports", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  if( self->data_len ) {
    fun( w, NULL, "data", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->data_len; i++ )
      fun( w, self->data + i, "data", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "data", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fd_pubkey_walk( w, &self->owner, fun, "owner", level, 0 );
  fun( w, &self->executable, "executable", FD_FLAMENCO_TYPE_BOOL, "bool", level, 0  );
  fun( w, &self->rent_epoch, "rent_epoch", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_solana_account", level--, 0 );
}
ulong fd_solana_account_size( fd_solana_account_t const * self ) {
  ulong size = 0;
  size += sizeof(ulong);
  do {
    size += sizeof(ulong);
    size += self->data_len;
  } while(0);
  size += fd_pubkey_size( &self->owner );
  size += sizeof(char);
  size += sizeof(ulong);
  return size;
}

int fd_solana_account_stored_meta_encode( fd_solana_account_stored_meta_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->write_version_obsolete, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->data_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bytes_encode( self->pubkey, sizeof(self->pubkey), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_solana_account_stored_meta_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 48UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 48UL );
  return 0;
}
static void fd_solana_account_stored_meta_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_solana_account_stored_meta_t * self = (fd_solana_account_stored_meta_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->write_version_obsolete, ctx );
  fd_bincode_uint64_decode_unsafe( &self->data_len, ctx );
  fd_bincode_bytes_decode_unsafe( &self->pubkey[0], sizeof(self->pubkey), ctx );
}
void * fd_solana_account_stored_meta_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_solana_account_stored_meta_t * self = (fd_solana_account_stored_meta_t *)mem;
  fd_solana_account_stored_meta_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_solana_account_stored_meta_t);
  void * * alloc_mem = &alloc_region;
  fd_solana_account_stored_meta_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_solana_account_stored_meta_walk( void * w, fd_solana_account_stored_meta_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_solana_account_stored_meta", level++, 0 );
  fun( w, &self->write_version_obsolete, "write_version_obsolete", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->data_len, "data_len", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self->pubkey, "pubkey", FD_FLAMENCO_TYPE_HASH256, "uchar[32]", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_solana_account_stored_meta", level--, 0 );
}
int fd_solana_account_meta_encode( fd_solana_account_meta_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->lamports, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->rent_epoch, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bytes_encode( self->owner, sizeof(self->owner), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_encode( (uchar)(self->executable), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bytes_encode( self->padding, 3, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_solana_account_meta_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_bytes_decode_footprint( 32, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bytes_decode_footprint( 3, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_solana_account_meta_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_solana_account_meta_t);
  void const * start_data = ctx->data;
  int err = fd_solana_account_meta_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_solana_account_meta_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_solana_account_meta_t * self = (fd_solana_account_meta_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->lamports, ctx );
  fd_bincode_uint64_decode_unsafe( &self->rent_epoch, ctx );
  fd_bincode_bytes_decode_unsafe( &self->owner[0], sizeof(self->owner), ctx );
  fd_bincode_bool_decode_unsafe( &self->executable, ctx );
  fd_bincode_bytes_decode_unsafe( self->padding, 3, ctx );
}
void * fd_solana_account_meta_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_solana_account_meta_t * self = (fd_solana_account_meta_t *)mem;
  fd_solana_account_meta_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_solana_account_meta_t);
  void * * alloc_mem = &alloc_region;
  fd_solana_account_meta_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_solana_account_meta_new(fd_solana_account_meta_t * self) {
  fd_memset( self, 0, sizeof(fd_solana_account_meta_t) );
}
void fd_solana_account_meta_walk( void * w, fd_solana_account_meta_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_solana_account_meta", level++, 0 );
  fun( w, &self->lamports, "lamports", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->rent_epoch, "rent_epoch", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self->owner, "owner", FD_FLAMENCO_TYPE_HASH256, "uchar[32]", level, 0  );
  fun( w, &self->executable, "executable", FD_FLAMENCO_TYPE_BOOL, "bool", level, 0  );
  fun(w, self->padding, "padding", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_solana_account_meta", level--, 0 );
}
int fd_solana_account_hdr_encode( fd_solana_account_hdr_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_solana_account_stored_meta_encode( &self->meta, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_solana_account_meta_encode( &self->info, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bytes_encode( self->padding, 4, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_hash_encode( &self->hash, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_solana_account_hdr_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_solana_account_stored_meta_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_solana_account_meta_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bytes_decode_footprint( 4, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_hash_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_solana_account_hdr_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_solana_account_hdr_t);
  void const * start_data = ctx->data;
  int err = fd_solana_account_hdr_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_solana_account_hdr_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_solana_account_hdr_t * self = (fd_solana_account_hdr_t *)struct_mem;
  fd_solana_account_stored_meta_decode_inner( &self->meta, alloc_mem, ctx );
  fd_solana_account_meta_decode_inner( &self->info, alloc_mem, ctx );
  fd_bincode_bytes_decode_unsafe( self->padding, 4, ctx );
  fd_hash_decode_inner( &self->hash, alloc_mem, ctx );
}
void * fd_solana_account_hdr_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_solana_account_hdr_t * self = (fd_solana_account_hdr_t *)mem;
  fd_solana_account_hdr_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_solana_account_hdr_t);
  void * * alloc_mem = &alloc_region;
  fd_solana_account_hdr_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_solana_account_hdr_new(fd_solana_account_hdr_t * self) {
  fd_memset( self, 0, sizeof(fd_solana_account_hdr_t) );
  fd_solana_account_stored_meta_new( &self->meta );
  fd_solana_account_meta_new( &self->info );
  fd_hash_new( &self->hash );
}
void fd_solana_account_hdr_walk( void * w, fd_solana_account_hdr_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_solana_account_hdr", level++, 0 );
  fd_solana_account_stored_meta_walk( w, &self->meta, fun, "meta", level, 0 );
  fd_solana_account_meta_walk( w, &self->info, fun, "info", level, 0 );
  fun(w, self->padding, "padding", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0 );
  fd_hash_walk( w, &self->hash, fun, "hash", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_solana_account_hdr", level--, 0 );
}
int fd_account_meta_encode( fd_account_meta_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint16_encode( self->magic, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint16_encode( self->hlen, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->dlen, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_solana_account_meta_encode( &self->info, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_account_meta_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint16_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint16_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_solana_account_meta_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_account_meta_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_account_meta_t);
  void const * start_data = ctx->data;
  int err = fd_account_meta_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_account_meta_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_account_meta_t * self = (fd_account_meta_t *)struct_mem;
  fd_bincode_uint16_decode_unsafe( &self->magic, ctx );
  fd_bincode_uint16_decode_unsafe( &self->hlen, ctx );
  fd_bincode_uint64_decode_unsafe( &self->dlen, ctx );
  fd_bincode_uint64_decode_unsafe( &self->slot, ctx );
  fd_solana_account_meta_decode_inner( &self->info, alloc_mem, ctx );
}
void * fd_account_meta_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_account_meta_t * self = (fd_account_meta_t *)mem;
  fd_account_meta_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_account_meta_t);
  void * * alloc_mem = &alloc_region;
  fd_account_meta_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_account_meta_new(fd_account_meta_t * self) {
  fd_memset( self, 0, sizeof(fd_account_meta_t) );
  fd_solana_account_meta_new( &self->info );
}
void fd_account_meta_walk( void * w, fd_account_meta_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_account_meta", level++, 0 );
  fun( w, &self->magic, "magic", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 0  );
  fun( w, &self->hlen, "hlen", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 0  );
  fun( w, &self->dlen, "dlen", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_solana_account_meta_walk( w, &self->info, fun, "info", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_account_meta", level--, 0 );
}
int fd_delegation_encode( fd_delegation_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->voter_pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->stake, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->activation_epoch, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->deactivation_epoch, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_double_encode( self->warmup_cooldown_rate, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_delegation_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 64UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 64UL );
  return 0;
}
static void fd_delegation_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_delegation_t * self = (fd_delegation_t *)struct_mem;
  fd_pubkey_decode_inner( &self->voter_pubkey, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->stake, ctx );
  fd_bincode_uint64_decode_unsafe( &self->activation_epoch, ctx );
  fd_bincode_uint64_decode_unsafe( &self->deactivation_epoch, ctx );
  fd_bincode_double_decode_unsafe( &self->warmup_cooldown_rate, ctx );
}
void * fd_delegation_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_delegation_t * self = (fd_delegation_t *)mem;
  fd_delegation_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_delegation_t);
  void * * alloc_mem = &alloc_region;
  fd_delegation_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_delegation_walk( void * w, fd_delegation_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_delegation", level++, 0 );
  fd_pubkey_walk( w, &self->voter_pubkey, fun, "voter_pubkey", level, 0 );
  fun( w, &self->stake, "stake", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->activation_epoch, "activation_epoch", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->deactivation_epoch, "deactivation_epoch", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->warmup_cooldown_rate, "warmup_cooldown_rate", FD_FLAMENCO_TYPE_DOUBLE, "double", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_delegation", level--, 0 );
}
int fd_stake_encode( fd_stake_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_delegation_encode( &self->delegation, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->credits_observed, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_stake_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 72UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 72UL );
  return 0;
}
static void fd_stake_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_t * self = (fd_stake_t *)struct_mem;
  fd_delegation_decode_inner( &self->delegation, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->credits_observed, ctx );
}
void * fd_stake_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_t * self = (fd_stake_t *)mem;
  fd_stake_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_stake_t);
  void * * alloc_mem = &alloc_region;
  fd_stake_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_stake_walk( void * w, fd_stake_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake", level++, 0 );
  fd_delegation_walk( w, &self->delegation, fun, "delegation", level, 0 );
  fun( w, &self->credits_observed, "credits_observed", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake", level--, 0 );
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
int fd_reward_type_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
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
static int fd_reward_type_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_reward_type_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_reward_type_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_reward_type_t);
  void const * start_data = ctx->data;
  int err =  fd_reward_type_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_reward_type_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_reward_type_t * self = (fd_reward_type_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
}
void * fd_reward_type_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_reward_type_t * self = (fd_reward_type_t *)mem;
  fd_reward_type_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_reward_type_t);
  void * * alloc_mem = &alloc_region;
  fd_reward_type_decode_inner( mem, alloc_mem, ctx );
  return self;
}

void fd_reward_type_walk( void * w, fd_reward_type_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_reward_type", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "fee", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "rent", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 2: {
    fun( w, self, "staking", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 3: {
    fun( w, self, "voting", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_reward_type", level--, 0 );
}
ulong fd_reward_type_size( fd_reward_type_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  }
  return size;
}

int fd_reward_type_encode( fd_reward_type_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return err;
}

int fd_reward_info_encode( fd_reward_info_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_reward_type_encode( &self->reward_type, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->lamports, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->post_balance, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->commission, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_reward_info_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_reward_type_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_reward_info_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_reward_info_t);
  void const * start_data = ctx->data;
  int err = fd_reward_info_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_reward_info_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_reward_info_t * self = (fd_reward_info_t *)struct_mem;
  fd_reward_type_decode_inner( &self->reward_type, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->lamports, ctx );
  fd_bincode_uint64_decode_unsafe( &self->post_balance, ctx );
  fd_bincode_uint64_decode_unsafe( &self->commission, ctx );
}
void * fd_reward_info_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_reward_info_t * self = (fd_reward_info_t *)mem;
  fd_reward_info_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_reward_info_t);
  void * * alloc_mem = &alloc_region;
  fd_reward_info_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_reward_info_new(fd_reward_info_t * self) {
  fd_memset( self, 0, sizeof(fd_reward_info_t) );
  fd_reward_type_new( &self->reward_type );
}
void fd_reward_info_walk( void * w, fd_reward_info_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_reward_info", level++, 0 );
  fd_reward_type_walk( w, &self->reward_type, fun, "reward_type", level, 0 );
  fun( w, &self->lamports, "lamports", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->post_balance, "post_balance", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->commission, "commission", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_reward_info", level--, 0 );
}
int fd_rust_duration_encode( fd_rust_duration_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->seconds, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint32_encode( self->nanoseconds, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_rust_duration_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 12UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = fd_rust_duration_footprint_validator( ctx );
  if( FD_UNLIKELY( err != FD_BINCODE_SUCCESS ) )
    return err;
  ctx->data = (void *)( (ulong)ctx->data + 12UL );
  return 0;
}
static void fd_rust_duration_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_rust_duration_t * self = (fd_rust_duration_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->seconds, ctx );
  fd_bincode_uint32_decode_unsafe( &self->nanoseconds, ctx );
  fd_rust_duration_normalize( self );
}
void * fd_rust_duration_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_rust_duration_t * self = (fd_rust_duration_t *)mem;
  fd_rust_duration_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_rust_duration_t);
  void * * alloc_mem = &alloc_region;
  fd_rust_duration_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_rust_duration_walk( void * w, fd_rust_duration_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_rust_duration", level++, 0 );
  fun( w, &self->seconds, "seconds", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->nanoseconds, "nanoseconds", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_rust_duration", level--, 0 );
}
int fd_poh_config_encode( fd_poh_config_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_rust_duration_encode( &self->target_tick_duration, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_encode( self->has_target_tick_count, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_target_tick_count ) {
    err = fd_bincode_uint64_encode( self->target_tick_count, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_bool_encode( self->has_hashes_per_tick, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_hashes_per_tick ) {
    err = fd_bincode_uint64_encode( self->hashes_per_tick, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_poh_config_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_rust_duration_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_poh_config_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_poh_config_t);
  void const * start_data = ctx->data;
  int err = fd_poh_config_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_poh_config_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_poh_config_t * self = (fd_poh_config_t *)struct_mem;
  fd_rust_duration_decode_inner( &self->target_tick_duration, alloc_mem, ctx );
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_target_tick_count = !!o;
    if( o ) {
      fd_bincode_uint64_decode_unsafe( &self->target_tick_count, ctx );
    }
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
void * fd_poh_config_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_poh_config_t * self = (fd_poh_config_t *)mem;
  fd_poh_config_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_poh_config_t);
  void * * alloc_mem = &alloc_region;
  fd_poh_config_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_poh_config_new(fd_poh_config_t * self) {
  fd_memset( self, 0, sizeof(fd_poh_config_t) );
  fd_rust_duration_new( &self->target_tick_duration );
}
void fd_poh_config_walk( void * w, fd_poh_config_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_poh_config", level++, 0 );
  fd_rust_duration_walk( w, &self->target_tick_duration, fun, "target_tick_duration", level, 0 );
  if( !self->has_target_tick_count ) {
    fun( w, NULL, "target_tick_count", FD_FLAMENCO_TYPE_NULL, "ulong", level, 0 );
  } else {
    fun( w, &self->target_tick_count, "target_tick_count", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0 );
  }
  if( !self->has_hashes_per_tick ) {
    fun( w, NULL, "hashes_per_tick", FD_FLAMENCO_TYPE_NULL, "ulong", level, 0 );
  } else {
    fun( w, &self->hashes_per_tick, "hashes_per_tick", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_poh_config", level--, 0 );
}
ulong fd_poh_config_size( fd_poh_config_t const * self ) {
  ulong size = 0;
  size += fd_rust_duration_size( &self->target_tick_duration );
  size += sizeof(char);
  if( self->has_target_tick_count ) {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if( self->has_hashes_per_tick ) {
    size += sizeof(ulong);
  }
  return size;
}

int fd_string_pubkey_pair_encode( fd_string_pubkey_pair_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->string_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->string_len ) {
    err = fd_bincode_bytes_encode( self->string, self->string_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_pubkey_encode( &self->pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_string_pubkey_pair_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ulong string_len;
  err = fd_bincode_uint64_decode( &string_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  *total_sz += string_len;
  if( string_len ) {
    err = fd_bincode_bytes_decode_footprint( string_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    err = !fd_utf8_verify( (char const *) ctx->data - string_len, string_len );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_string_pubkey_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_string_pubkey_pair_t);
  void const * start_data = ctx->data;
  int err = fd_string_pubkey_pair_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_string_pubkey_pair_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_string_pubkey_pair_t * self = (fd_string_pubkey_pair_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->string_len, ctx );
  if( self->string_len ) {
    self->string = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->string, self->string_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->string_len;
  } else
    self->string = NULL;
  fd_pubkey_decode_inner( &self->pubkey, alloc_mem, ctx );
}
void * fd_string_pubkey_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_string_pubkey_pair_t * self = (fd_string_pubkey_pair_t *)mem;
  fd_string_pubkey_pair_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_string_pubkey_pair_t);
  void * * alloc_mem = &alloc_region;
  fd_string_pubkey_pair_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_string_pubkey_pair_new(fd_string_pubkey_pair_t * self) {
  fd_memset( self, 0, sizeof(fd_string_pubkey_pair_t) );
  fd_pubkey_new( &self->pubkey );
}
void fd_string_pubkey_pair_walk( void * w, fd_string_pubkey_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_string_pubkey_pair", level++, 0 );
  if( self->string_len ) {
    fun( w, NULL, "string", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->string_len; i++ )
      fun( w, self->string + i, "string", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "string", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fd_pubkey_walk( w, &self->pubkey, fun, "pubkey", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_string_pubkey_pair", level--, 0 );
}
ulong fd_string_pubkey_pair_size( fd_string_pubkey_pair_t const * self ) {
  ulong size = 0;
  do {
    size += sizeof(ulong);
    size += self->string_len;
  } while(0);
  size += fd_pubkey_size( &self->pubkey );
  return size;
}

int fd_pubkey_account_pair_encode( fd_pubkey_account_pair_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->key, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_solana_account_encode( &self->account, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_pubkey_account_pair_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_solana_account_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_pubkey_account_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_pubkey_account_pair_t);
  void const * start_data = ctx->data;
  int err = fd_pubkey_account_pair_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_pubkey_account_pair_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_pubkey_account_pair_t * self = (fd_pubkey_account_pair_t *)struct_mem;
  fd_pubkey_decode_inner( &self->key, alloc_mem, ctx );
  fd_solana_account_decode_inner( &self->account, alloc_mem, ctx );
}
void * fd_pubkey_account_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_pubkey_account_pair_t * self = (fd_pubkey_account_pair_t *)mem;
  fd_pubkey_account_pair_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_pubkey_account_pair_t);
  void * * alloc_mem = &alloc_region;
  fd_pubkey_account_pair_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_pubkey_account_pair_new(fd_pubkey_account_pair_t * self) {
  fd_memset( self, 0, sizeof(fd_pubkey_account_pair_t) );
  fd_pubkey_new( &self->key );
  fd_solana_account_new( &self->account );
}
void fd_pubkey_account_pair_walk( void * w, fd_pubkey_account_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_pubkey_account_pair", level++, 0 );
  fd_pubkey_walk( w, &self->key, fun, "key", level, 0 );
  fd_solana_account_walk( w, &self->account, fun, "account", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_pubkey_account_pair", level--, 0 );
}
ulong fd_pubkey_account_pair_size( fd_pubkey_account_pair_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->key );
  size += fd_solana_account_size( &self->account );
  return size;
}

int fd_genesis_solana_encode( fd_genesis_solana_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->creation_time, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->accounts_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->accounts_len ) {
    for( ulong i=0; i < self->accounts_len; i++ ) {
      err = fd_pubkey_account_pair_encode( self->accounts + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  err = fd_bincode_uint64_encode( self->native_instruction_processors_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->native_instruction_processors_len ) {
    for( ulong i=0; i < self->native_instruction_processors_len; i++ ) {
      err = fd_string_pubkey_pair_encode( self->native_instruction_processors + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  err = fd_bincode_uint64_encode( self->rewards_pools_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->rewards_pools_len ) {
    for( ulong i=0; i < self->rewards_pools_len; i++ ) {
      err = fd_pubkey_account_pair_encode( self->rewards_pools + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  err = fd_bincode_uint64_encode( self->ticks_per_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->unused, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_poh_config_encode( &self->poh_config, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->__backwards_compat_with_v0_23, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_fee_rate_governor_encode( &self->fee_rate_governor, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_rent_encode( &self->rent, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_inflation_encode( &self->inflation, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_epoch_schedule_encode( &self->epoch_schedule, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint32_encode( self->cluster_type, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_genesis_solana_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ulong accounts_len;
  err = fd_bincode_uint64_decode( &accounts_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( accounts_len ) {
    *total_sz += FD_PUBKEY_ACCOUNT_PAIR_ALIGN + sizeof(fd_pubkey_account_pair_t)*accounts_len;
    for( ulong i=0; i < accounts_len; i++ ) {
      err = fd_pubkey_account_pair_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  ulong native_instruction_processors_len;
  err = fd_bincode_uint64_decode( &native_instruction_processors_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( native_instruction_processors_len ) {
    *total_sz += FD_STRING_PUBKEY_PAIR_ALIGN + sizeof(fd_string_pubkey_pair_t)*native_instruction_processors_len;
    for( ulong i=0; i < native_instruction_processors_len; i++ ) {
      err = fd_string_pubkey_pair_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  ulong rewards_pools_len;
  err = fd_bincode_uint64_decode( &rewards_pools_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( rewards_pools_len ) {
    *total_sz += FD_PUBKEY_ACCOUNT_PAIR_ALIGN + sizeof(fd_pubkey_account_pair_t)*rewards_pools_len;
    for( ulong i=0; i < rewards_pools_len; i++ ) {
      err = fd_pubkey_account_pair_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_poh_config_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_fee_rate_governor_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_rent_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_inflation_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_epoch_schedule_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint32_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_genesis_solana_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_genesis_solana_t);
  void const * start_data = ctx->data;
  int err = fd_genesis_solana_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_genesis_solana_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_genesis_solana_t * self = (fd_genesis_solana_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->creation_time, ctx );
  fd_bincode_uint64_decode_unsafe( &self->accounts_len, ctx );
  if( self->accounts_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_PUBKEY_ACCOUNT_PAIR_ALIGN );
    self->accounts = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_pubkey_account_pair_t)*self->accounts_len;
    for( ulong i=0; i < self->accounts_len; i++ ) {
      fd_pubkey_account_pair_new( self->accounts + i );
      fd_pubkey_account_pair_decode_inner( self->accounts + i, alloc_mem, ctx );
    }
  } else
    self->accounts = NULL;
  fd_bincode_uint64_decode_unsafe( &self->native_instruction_processors_len, ctx );
  if( self->native_instruction_processors_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_STRING_PUBKEY_PAIR_ALIGN );
    self->native_instruction_processors = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_string_pubkey_pair_t)*self->native_instruction_processors_len;
    for( ulong i=0; i < self->native_instruction_processors_len; i++ ) {
      fd_string_pubkey_pair_new( self->native_instruction_processors + i );
      fd_string_pubkey_pair_decode_inner( self->native_instruction_processors + i, alloc_mem, ctx );
    }
  } else
    self->native_instruction_processors = NULL;
  fd_bincode_uint64_decode_unsafe( &self->rewards_pools_len, ctx );
  if( self->rewards_pools_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_PUBKEY_ACCOUNT_PAIR_ALIGN );
    self->rewards_pools = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_pubkey_account_pair_t)*self->rewards_pools_len;
    for( ulong i=0; i < self->rewards_pools_len; i++ ) {
      fd_pubkey_account_pair_new( self->rewards_pools + i );
      fd_pubkey_account_pair_decode_inner( self->rewards_pools + i, alloc_mem, ctx );
    }
  } else
    self->rewards_pools = NULL;
  fd_bincode_uint64_decode_unsafe( &self->ticks_per_slot, ctx );
  fd_bincode_uint64_decode_unsafe( &self->unused, ctx );
  fd_poh_config_decode_inner( &self->poh_config, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->__backwards_compat_with_v0_23, ctx );
  fd_fee_rate_governor_decode_inner( &self->fee_rate_governor, alloc_mem, ctx );
  fd_rent_decode_inner( &self->rent, alloc_mem, ctx );
  fd_inflation_decode_inner( &self->inflation, alloc_mem, ctx );
  fd_epoch_schedule_decode_inner( &self->epoch_schedule, alloc_mem, ctx );
  fd_bincode_uint32_decode_unsafe( &self->cluster_type, ctx );
}
void * fd_genesis_solana_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_genesis_solana_t * self = (fd_genesis_solana_t *)mem;
  fd_genesis_solana_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_genesis_solana_t);
  void * * alloc_mem = &alloc_region;
  fd_genesis_solana_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_genesis_solana_new(fd_genesis_solana_t * self) {
  fd_memset( self, 0, sizeof(fd_genesis_solana_t) );
  fd_poh_config_new( &self->poh_config );
  fd_fee_rate_governor_new( &self->fee_rate_governor );
  fd_rent_new( &self->rent );
  fd_inflation_new( &self->inflation );
  fd_epoch_schedule_new( &self->epoch_schedule );
}
void fd_genesis_solana_walk( void * w, fd_genesis_solana_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_genesis_solana", level++, 0 );
  fun( w, &self->creation_time, "creation_time", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  if( self->accounts_len ) {
    fun( w, NULL, "accounts", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->accounts_len; i++ )
      fd_pubkey_account_pair_walk(w, self->accounts + i, fun, "pubkey_account_pair", level, 0 );
    fun( w, NULL, "accounts", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  if( self->native_instruction_processors_len ) {
    fun( w, NULL, "native_instruction_processors", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->native_instruction_processors_len; i++ )
      fd_string_pubkey_pair_walk(w, self->native_instruction_processors + i, fun, "string_pubkey_pair", level, 0 );
    fun( w, NULL, "native_instruction_processors", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  if( self->rewards_pools_len ) {
    fun( w, NULL, "rewards_pools", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->rewards_pools_len; i++ )
      fd_pubkey_account_pair_walk(w, self->rewards_pools + i, fun, "pubkey_account_pair", level, 0 );
    fun( w, NULL, "rewards_pools", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, &self->ticks_per_slot, "ticks_per_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->unused, "unused", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_poh_config_walk( w, &self->poh_config, fun, "poh_config", level, 0 );
  fun( w, &self->__backwards_compat_with_v0_23, "__backwards_compat_with_v0_23", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_fee_rate_governor_walk( w, &self->fee_rate_governor, fun, "fee_rate_governor", level, 0 );
  fd_rent_walk( w, &self->rent, fun, "rent", level, 0 );
  fd_inflation_walk( w, &self->inflation, fun, "inflation", level, 0 );
  fd_epoch_schedule_walk( w, &self->epoch_schedule, fun, "epoch_schedule", level, 0 );
  fun( w, &self->cluster_type, "cluster_type", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_genesis_solana", level--, 0 );
}
ulong fd_genesis_solana_size( fd_genesis_solana_t const * self ) {
  ulong size = 0;
  size += sizeof(ulong);
  do {
    size += sizeof(ulong);
    for( ulong i=0; i < self->accounts_len; i++ )
      size += fd_pubkey_account_pair_size( self->accounts + i );
  } while(0);
  do {
    size += sizeof(ulong);
    for( ulong i=0; i < self->native_instruction_processors_len; i++ )
      size += fd_string_pubkey_pair_size( self->native_instruction_processors + i );
  } while(0);
  do {
    size += sizeof(ulong);
    for( ulong i=0; i < self->rewards_pools_len; i++ )
      size += fd_pubkey_account_pair_size( self->rewards_pools + i );
  } while(0);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_poh_config_size( &self->poh_config );
  size += sizeof(ulong);
  size += fd_fee_rate_governor_size( &self->fee_rate_governor );
  size += fd_rent_size( &self->rent );
  size += fd_inflation_size( &self->inflation );
  size += fd_epoch_schedule_size( &self->epoch_schedule );
  size += sizeof(uint);
  return size;
}

int fd_sol_sysvar_clock_encode( fd_sol_sysvar_clock_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( (ulong)self->epoch_start_timestamp, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->epoch, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->leader_schedule_epoch, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( (ulong)self->unix_timestamp, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_sol_sysvar_clock_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 40UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 40UL );
  return 0;
}
static void fd_sol_sysvar_clock_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_sol_sysvar_clock_t * self = (fd_sol_sysvar_clock_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->slot, ctx );
  fd_bincode_uint64_decode_unsafe( (ulong *) &self->epoch_start_timestamp, ctx );
  fd_bincode_uint64_decode_unsafe( &self->epoch, ctx );
  fd_bincode_uint64_decode_unsafe( &self->leader_schedule_epoch, ctx );
  fd_bincode_uint64_decode_unsafe( (ulong *) &self->unix_timestamp, ctx );
}
void * fd_sol_sysvar_clock_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_sol_sysvar_clock_t * self = (fd_sol_sysvar_clock_t *)mem;
  fd_sol_sysvar_clock_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_sol_sysvar_clock_t);
  void * * alloc_mem = &alloc_region;
  fd_sol_sysvar_clock_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_sol_sysvar_clock_walk( void * w, fd_sol_sysvar_clock_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_sol_sysvar_clock", level++, 0 );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->epoch_start_timestamp, "epoch_start_timestamp", FD_FLAMENCO_TYPE_SLONG, "long", level, 0  );
  fun( w, &self->epoch, "epoch", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->leader_schedule_epoch, "leader_schedule_epoch", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->unix_timestamp, "unix_timestamp", FD_FLAMENCO_TYPE_SLONG, "long", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_sol_sysvar_clock", level--, 0 );
}
int fd_sol_sysvar_last_restart_slot_encode( fd_sol_sysvar_last_restart_slot_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_sol_sysvar_last_restart_slot_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 8UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 8UL );
  return 0;
}
static void fd_sol_sysvar_last_restart_slot_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_sol_sysvar_last_restart_slot_t * self = (fd_sol_sysvar_last_restart_slot_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->slot, ctx );
}
void * fd_sol_sysvar_last_restart_slot_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_sol_sysvar_last_restart_slot_t * self = (fd_sol_sysvar_last_restart_slot_t *)mem;
  fd_sol_sysvar_last_restart_slot_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_sol_sysvar_last_restart_slot_t);
  void * * alloc_mem = &alloc_region;
  fd_sol_sysvar_last_restart_slot_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_sol_sysvar_last_restart_slot_walk( void * w, fd_sol_sysvar_last_restart_slot_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_sol_sysvar_last_restart_slot", level++, 0 );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_sol_sysvar_last_restart_slot", level--, 0 );
}
int fd_vote_lockout_encode( fd_vote_lockout_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint32_encode( self->confirmation_count, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_vote_lockout_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 12UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 12UL );
  return 0;
}
static void fd_vote_lockout_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_lockout_t * self = (fd_vote_lockout_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->slot, ctx );
  fd_bincode_uint32_decode_unsafe( &self->confirmation_count, ctx );
}
void * fd_vote_lockout_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_lockout_t * self = (fd_vote_lockout_t *)mem;
  fd_vote_lockout_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_lockout_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_lockout_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_lockout_walk( void * w, fd_vote_lockout_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_lockout", level++, 0 );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->confirmation_count, "confirmation_count", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_lockout", level--, 0 );
}
int fd_lockout_offset_encode( fd_lockout_offset_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_varint_encode( self->offset, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->confirmation_count), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_lockout_offset_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_varint_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_lockout_offset_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_lockout_offset_t);
  void const * start_data = ctx->data;
  int err = fd_lockout_offset_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_lockout_offset_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_lockout_offset_t * self = (fd_lockout_offset_t *)struct_mem;
  fd_bincode_varint_decode_unsafe( &self->offset, ctx );
  fd_bincode_uint8_decode_unsafe( &self->confirmation_count, ctx );
}
void * fd_lockout_offset_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_lockout_offset_t * self = (fd_lockout_offset_t *)mem;
  fd_lockout_offset_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_lockout_offset_t);
  void * * alloc_mem = &alloc_region;
  fd_lockout_offset_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_lockout_offset_new(fd_lockout_offset_t * self) {
  fd_memset( self, 0, sizeof(fd_lockout_offset_t) );
}
void fd_lockout_offset_walk( void * w, fd_lockout_offset_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_lockout_offset", level++, 0 );
  fun( w, &self->offset, "offset", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 1  );
  fun( w, &self->confirmation_count, "confirmation_count", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_lockout_offset", level--, 0 );
}
ulong fd_lockout_offset_size( fd_lockout_offset_t const * self ) {
  ulong size = 0;
  size += fd_bincode_varint_size( self->offset );
  size += sizeof(char);
  return size;
}

int fd_vote_authorized_voter_encode( fd_vote_authorized_voter_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->epoch, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_vote_authorized_voter_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 40UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 40UL );
  return 0;
}
static void fd_vote_authorized_voter_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_authorized_voter_t * self = (fd_vote_authorized_voter_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->epoch, ctx );
  fd_pubkey_decode_inner( &self->pubkey, alloc_mem, ctx );
}
void * fd_vote_authorized_voter_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_authorized_voter_t * self = (fd_vote_authorized_voter_t *)mem;
  fd_vote_authorized_voter_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_authorized_voter_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_authorized_voter_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_authorized_voter_walk( void * w, fd_vote_authorized_voter_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_authorized_voter", level++, 0 );
  fun( w, &self->epoch, "epoch", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_pubkey_walk( w, &self->pubkey, fun, "pubkey", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_authorized_voter", level--, 0 );
}
int fd_vote_prior_voter_encode( fd_vote_prior_voter_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->epoch_start, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->epoch_end, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_vote_prior_voter_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 48UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 48UL );
  return 0;
}
static void fd_vote_prior_voter_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_prior_voter_t * self = (fd_vote_prior_voter_t *)struct_mem;
  fd_pubkey_decode_inner( &self->pubkey, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->epoch_start, ctx );
  fd_bincode_uint64_decode_unsafe( &self->epoch_end, ctx );
}
void * fd_vote_prior_voter_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_prior_voter_t * self = (fd_vote_prior_voter_t *)mem;
  fd_vote_prior_voter_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_prior_voter_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_prior_voter_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_prior_voter_walk( void * w, fd_vote_prior_voter_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_prior_voter", level++, 0 );
  fd_pubkey_walk( w, &self->pubkey, fun, "pubkey", level, 0 );
  fun( w, &self->epoch_start, "epoch_start", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->epoch_end, "epoch_end", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_prior_voter", level--, 0 );
}
int fd_vote_prior_voter_0_23_5_encode( fd_vote_prior_voter_0_23_5_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->epoch_start, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->epoch_end, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_vote_prior_voter_0_23_5_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 56UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 56UL );
  return 0;
}
static void fd_vote_prior_voter_0_23_5_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_prior_voter_0_23_5_t * self = (fd_vote_prior_voter_0_23_5_t *)struct_mem;
  fd_pubkey_decode_inner( &self->pubkey, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->epoch_start, ctx );
  fd_bincode_uint64_decode_unsafe( &self->epoch_end, ctx );
  fd_bincode_uint64_decode_unsafe( &self->slot, ctx );
}
void * fd_vote_prior_voter_0_23_5_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_prior_voter_0_23_5_t * self = (fd_vote_prior_voter_0_23_5_t *)mem;
  fd_vote_prior_voter_0_23_5_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_prior_voter_0_23_5_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_prior_voter_0_23_5_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_prior_voter_0_23_5_walk( void * w, fd_vote_prior_voter_0_23_5_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_prior_voter_0_23_5", level++, 0 );
  fd_pubkey_walk( w, &self->pubkey, fun, "pubkey", level, 0 );
  fun( w, &self->epoch_start, "epoch_start", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->epoch_end, "epoch_end", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_prior_voter_0_23_5", level--, 0 );
}
int fd_vote_epoch_credits_encode( fd_vote_epoch_credits_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->epoch, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->credits, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->prev_credits, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_vote_epoch_credits_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 24UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 24UL );
  return 0;
}
static void fd_vote_epoch_credits_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_epoch_credits_t * self = (fd_vote_epoch_credits_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->epoch, ctx );
  fd_bincode_uint64_decode_unsafe( &self->credits, ctx );
  fd_bincode_uint64_decode_unsafe( &self->prev_credits, ctx );
}
void * fd_vote_epoch_credits_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_epoch_credits_t * self = (fd_vote_epoch_credits_t *)mem;
  fd_vote_epoch_credits_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_epoch_credits_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_epoch_credits_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_epoch_credits_walk( void * w, fd_vote_epoch_credits_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_epoch_credits", level++, 0 );
  fun( w, &self->epoch, "epoch", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->credits, "credits", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->prev_credits, "prev_credits", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_epoch_credits", level--, 0 );
}
int fd_vote_block_timestamp_encode( fd_vote_block_timestamp_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( (ulong)self->timestamp, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_vote_block_timestamp_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 16UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 16UL );
  return 0;
}
static void fd_vote_block_timestamp_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_block_timestamp_t * self = (fd_vote_block_timestamp_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->slot, ctx );
  fd_bincode_uint64_decode_unsafe( (ulong *) &self->timestamp, ctx );
}
void * fd_vote_block_timestamp_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_block_timestamp_t * self = (fd_vote_block_timestamp_t *)mem;
  fd_vote_block_timestamp_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_block_timestamp_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_block_timestamp_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_block_timestamp_walk( void * w, fd_vote_block_timestamp_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_block_timestamp", level++, 0 );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->timestamp, "timestamp", FD_FLAMENCO_TYPE_SLONG, "long", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_block_timestamp", level--, 0 );
}
int fd_vote_prior_voters_encode( fd_vote_prior_voters_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  for( ulong i=0; i<32; i++ ) {
    err = fd_vote_prior_voter_encode( self->buf + i, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint64_encode( self->idx, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_encode( (uchar)(self->is_empty), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_vote_prior_voters_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  for( ulong i=0; i<32; i++ ) {
    err = fd_vote_prior_voter_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_bool_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_vote_prior_voters_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_prior_voters_t);
  void const * start_data = ctx->data;
  int err = fd_vote_prior_voters_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_vote_prior_voters_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_prior_voters_t * self = (fd_vote_prior_voters_t *)struct_mem;
  for( ulong i=0; i<32; i++ ) {
    fd_vote_prior_voter_decode_inner( self->buf + i, alloc_mem, ctx );
  }
  fd_bincode_uint64_decode_unsafe( &self->idx, ctx );
  fd_bincode_bool_decode_unsafe( &self->is_empty, ctx );
}
void * fd_vote_prior_voters_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_prior_voters_t * self = (fd_vote_prior_voters_t *)mem;
  fd_vote_prior_voters_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_prior_voters_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_prior_voters_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_prior_voters_new(fd_vote_prior_voters_t * self) {
  fd_memset( self, 0, sizeof(fd_vote_prior_voters_t) );
  for( ulong i=0; i<32; i++ )
    fd_vote_prior_voter_new( self->buf + i );
}
void fd_vote_prior_voters_walk( void * w, fd_vote_prior_voters_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_prior_voters", level++, 0 );
  fun( w, NULL, "buf", FD_FLAMENCO_TYPE_ARR, "vote_prior_voter[]", level++, 0 );
  for( ulong i=0; i<32; i++ )
    fd_vote_prior_voter_walk( w, self->buf + i, fun, "vote_prior_voter", level, 0 );
  fun( w, NULL, "buf", FD_FLAMENCO_TYPE_ARR_END, "vote_prior_voter[]", level--, 0 );
  fun( w, &self->idx, "idx", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->is_empty, "is_empty", FD_FLAMENCO_TYPE_BOOL, "bool", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_prior_voters", level--, 0 );
}
int fd_vote_prior_voters_0_23_5_encode( fd_vote_prior_voters_0_23_5_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  for( ulong i=0; i<32; i++ ) {
    err = fd_vote_prior_voter_0_23_5_encode( self->buf + i, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint64_encode( self->idx, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_vote_prior_voters_0_23_5_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 1800UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 1800UL );
  return 0;
}
static void fd_vote_prior_voters_0_23_5_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_prior_voters_0_23_5_t * self = (fd_vote_prior_voters_0_23_5_t *)struct_mem;
  for( ulong i=0; i<32; i++ ) {
    fd_vote_prior_voter_0_23_5_decode_inner( self->buf + i, alloc_mem, ctx );
  }
  fd_bincode_uint64_decode_unsafe( &self->idx, ctx );
}
void * fd_vote_prior_voters_0_23_5_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_prior_voters_0_23_5_t * self = (fd_vote_prior_voters_0_23_5_t *)mem;
  fd_vote_prior_voters_0_23_5_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_prior_voters_0_23_5_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_prior_voters_0_23_5_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_prior_voters_0_23_5_walk( void * w, fd_vote_prior_voters_0_23_5_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_prior_voters_0_23_5", level++, 0 );
  fun( w, NULL, "buf", FD_FLAMENCO_TYPE_ARR, "vote_prior_voter_0_23_5[]", level++, 0 );
  for( ulong i=0; i<32; i++ )
    fd_vote_prior_voter_0_23_5_walk( w, self->buf + i, fun, "vote_prior_voter_0_23_5", level, 0 );
  fun( w, NULL, "buf", FD_FLAMENCO_TYPE_ARR_END, "vote_prior_voter_0_23_5[]", level--, 0 );
  fun( w, &self->idx, "idx", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_prior_voters_0_23_5", level--, 0 );
}
int fd_landed_vote_encode( fd_landed_vote_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint8_encode( (uchar)(self->latency), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_vote_lockout_encode( &self->lockout, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_landed_vote_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 13UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 13UL );
  return 0;
}
static void fd_landed_vote_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_landed_vote_t * self = (fd_landed_vote_t *)struct_mem;
  fd_bincode_uint8_decode_unsafe( &self->latency, ctx );
  fd_vote_lockout_decode_inner( &self->lockout, alloc_mem, ctx );
}
void * fd_landed_vote_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_landed_vote_t * self = (fd_landed_vote_t *)mem;
  fd_landed_vote_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_landed_vote_t);
  void * * alloc_mem = &alloc_region;
  fd_landed_vote_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_landed_vote_walk( void * w, fd_landed_vote_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_landed_vote", level++, 0 );
  fun( w, &self->latency, "latency", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fd_vote_lockout_walk( w, &self->lockout, fun, "lockout", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_landed_vote", level--, 0 );
}
int fd_vote_state_0_23_5_encode( fd_vote_state_0_23_5_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->node_pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->authorized_voter, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->authorized_voter_epoch, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_vote_prior_voters_0_23_5_encode( &self->prior_voters, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->authorized_withdrawer, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->commission), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->votes ) {
    ulong votes_len = deq_fd_vote_lockout_t_cnt( self->votes );
    err = fd_bincode_uint64_encode( votes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes ); !deq_fd_vote_lockout_t_iter_done( self->votes, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t const * ele = deq_fd_vote_lockout_t_iter_ele_const( self->votes, iter );
      err = fd_vote_lockout_encode( ele, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  } else {
    ulong votes_len = 0;
    err = fd_bincode_uint64_encode( votes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_bool_encode( self->has_root_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_root_slot ) {
    err = fd_bincode_uint64_encode( self->root_slot, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  if( self->epoch_credits ) {
    ulong epoch_credits_len = deq_fd_vote_epoch_credits_t_cnt( self->epoch_credits );
    err = fd_bincode_uint64_encode( epoch_credits_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t const * ele = deq_fd_vote_epoch_credits_t_iter_ele_const( self->epoch_credits, iter );
      err = fd_vote_epoch_credits_encode( ele, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  } else {
    ulong epoch_credits_len = 0;
    err = fd_bincode_uint64_encode( epoch_credits_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_vote_block_timestamp_encode( &self->last_timestamp, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_vote_state_0_23_5_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_vote_prior_voters_0_23_5_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong votes_len;
  err = fd_bincode_uint64_decode( &votes_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong votes_max = fd_ulong_max( votes_len, 32 );
  *total_sz += deq_fd_vote_lockout_t_align() + deq_fd_vote_lockout_t_footprint( votes_max );
  ulong votes_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( votes_len, 12, &votes_sz ) ) ) return FD_BINCODE_ERR_UNDERFLOW;
  err = fd_bincode_bytes_decode_footprint( votes_sz, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  ulong epoch_credits_len;
  err = fd_bincode_uint64_decode( &epoch_credits_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong epoch_credits_max = fd_ulong_max( epoch_credits_len, 64 );
  *total_sz += deq_fd_vote_epoch_credits_t_align() + deq_fd_vote_epoch_credits_t_footprint( epoch_credits_max );
  ulong epoch_credits_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( epoch_credits_len, 24, &epoch_credits_sz ) ) ) return FD_BINCODE_ERR_UNDERFLOW;
  err = fd_bincode_bytes_decode_footprint( epoch_credits_sz, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_vote_block_timestamp_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_vote_state_0_23_5_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_state_0_23_5_t);
  void const * start_data = ctx->data;
  int err = fd_vote_state_0_23_5_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_vote_state_0_23_5_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_state_0_23_5_t * self = (fd_vote_state_0_23_5_t *)struct_mem;
  fd_pubkey_decode_inner( &self->node_pubkey, alloc_mem, ctx );
  fd_pubkey_decode_inner( &self->authorized_voter, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->authorized_voter_epoch, ctx );
  fd_vote_prior_voters_0_23_5_decode_inner( &self->prior_voters, alloc_mem, ctx );
  fd_pubkey_decode_inner( &self->authorized_withdrawer, alloc_mem, ctx );
  fd_bincode_uint8_decode_unsafe( &self->commission, ctx );
  ulong votes_len;
  fd_bincode_uint64_decode_unsafe( &votes_len, ctx );
  ulong votes_max = fd_ulong_max( votes_len, 32 );
  self->votes = deq_fd_vote_lockout_t_join_new( alloc_mem, votes_max );
  for( ulong i=0; i < votes_len; i++ ) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy( self->votes );
    fd_vote_lockout_new( elem );
    fd_vote_lockout_decode_inner( elem, alloc_mem, ctx );
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
  ulong epoch_credits_max = fd_ulong_max( epoch_credits_len, 64 );
  self->epoch_credits = deq_fd_vote_epoch_credits_t_join_new( alloc_mem, epoch_credits_max );
  for( ulong i=0; i < epoch_credits_len; i++ ) {
    fd_vote_epoch_credits_t * elem = deq_fd_vote_epoch_credits_t_push_tail_nocopy( self->epoch_credits );
    fd_vote_epoch_credits_new( elem );
    fd_vote_epoch_credits_decode_inner( elem, alloc_mem, ctx );
  }
  fd_vote_block_timestamp_decode_inner( &self->last_timestamp, alloc_mem, ctx );
}
void * fd_vote_state_0_23_5_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_state_0_23_5_t * self = (fd_vote_state_0_23_5_t *)mem;
  fd_vote_state_0_23_5_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_state_0_23_5_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_state_0_23_5_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_state_0_23_5_new(fd_vote_state_0_23_5_t * self) {
  fd_memset( self, 0, sizeof(fd_vote_state_0_23_5_t) );
  fd_pubkey_new( &self->node_pubkey );
  fd_pubkey_new( &self->authorized_voter );
  fd_vote_prior_voters_0_23_5_new( &self->prior_voters );
  fd_pubkey_new( &self->authorized_withdrawer );
  fd_vote_block_timestamp_new( &self->last_timestamp );
}
void fd_vote_state_0_23_5_walk( void * w, fd_vote_state_0_23_5_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_state_0_23_5", level++, 0 );
  fd_pubkey_walk( w, &self->node_pubkey, fun, "node_pubkey", level, 0 );
  fd_pubkey_walk( w, &self->authorized_voter, fun, "authorized_voter", level, 0 );
  fun( w, &self->authorized_voter_epoch, "authorized_voter_epoch", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_vote_prior_voters_0_23_5_walk( w, &self->prior_voters, fun, "prior_voters", level, 0 );
  fd_pubkey_walk( w, &self->authorized_withdrawer, fun, "authorized_withdrawer", level, 0 );
  fun( w, &self->commission, "commission", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );

  /* Walk deque */
  fun( w, self->votes, "votes", FD_FLAMENCO_TYPE_ARR, "votes", level++, 0 );
  if( self->votes ) {
    for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes );
         !deq_fd_vote_lockout_t_iter_done( self->votes, iter );
         iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->votes, iter );
      fd_vote_lockout_walk(w, ele, fun, "votes", level, 0 );
    }
  }
  fun( w, self->votes, "votes", FD_FLAMENCO_TYPE_ARR_END, "votes", level--, 0 );
  /* Done walking deque */

  if( !self->has_root_slot ) {
    fun( w, NULL, "root_slot", FD_FLAMENCO_TYPE_NULL, "ulong", level, 0 );
  } else {
    fun( w, &self->root_slot, "root_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0 );
  }

  /* Walk deque */
  fun( w, self->epoch_credits, "epoch_credits", FD_FLAMENCO_TYPE_ARR, "epoch_credits", level++, 0 );
  if( self->epoch_credits ) {
    for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits );
         !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter );
         iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      fd_vote_epoch_credits_walk(w, ele, fun, "epoch_credits", level, 0 );
    }
  }
  fun( w, self->epoch_credits, "epoch_credits", FD_FLAMENCO_TYPE_ARR_END, "epoch_credits", level--, 0 );
  /* Done walking deque */

  fd_vote_block_timestamp_walk( w, &self->last_timestamp, fun, "last_timestamp", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_state_0_23_5", level--, 0 );
}
ulong fd_vote_state_0_23_5_size( fd_vote_state_0_23_5_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->node_pubkey );
  size += fd_pubkey_size( &self->authorized_voter );
  size += sizeof(ulong);
  size += fd_vote_prior_voters_0_23_5_size( &self->prior_voters );
  size += fd_pubkey_size( &self->authorized_withdrawer );
  size += sizeof(char);
  if( self->votes ) {
    size += sizeof(ulong);
    for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes ); !deq_fd_vote_lockout_t_iter_done( self->votes, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->votes, iter );
      size += fd_vote_lockout_size( ele );
    }
  } else {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if( self->has_root_slot ) {
    size += sizeof(ulong);
  }
  if( self->epoch_credits ) {
    size += sizeof(ulong);
    for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      size += fd_vote_epoch_credits_size( ele );
    }
  } else {
    size += sizeof(ulong);
  }
  size += fd_vote_block_timestamp_size( &self->last_timestamp );
  return size;
}

int fd_vote_authorized_voters_encode( fd_vote_authorized_voters_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  if( self->treap ) {
    ulong fd_vote_authorized_voters_len = fd_vote_authorized_voters_treap_ele_cnt( self->treap );
    err = fd_bincode_uint64_encode( fd_vote_authorized_voters_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( fd_vote_authorized_voters_treap_fwd_iter_t iter = fd_vote_authorized_voters_treap_fwd_iter_init( self->treap, self->pool );
         !fd_vote_authorized_voters_treap_fwd_iter_done( iter );
         iter = fd_vote_authorized_voters_treap_fwd_iter_next( iter, self->pool ) ) {
      fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_treap_fwd_iter_ele( iter, self->pool );
      err = fd_vote_authorized_voter_encode( ele, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  } else {
    ulong fd_vote_authorized_voters_len = 0;
    err = fd_bincode_uint64_encode( fd_vote_authorized_voters_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_vote_authorized_voters_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ulong fd_vote_authorized_voters_treap_len;
  err = fd_bincode_uint64_decode( &fd_vote_authorized_voters_treap_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong fd_vote_authorized_voters_treap_max = fd_ulong_max( fd_ulong_max( fd_vote_authorized_voters_treap_len, FD_VOTE_AUTHORIZED_VOTERS_MIN ), 1UL );
  *total_sz += fd_vote_authorized_voters_pool_align() + fd_vote_authorized_voters_pool_footprint( fd_vote_authorized_voters_treap_max );
  *total_sz += fd_vote_authorized_voters_treap_align() + fd_vote_authorized_voters_treap_footprint( fd_vote_authorized_voters_treap_max );
  for( ulong i=0; i < fd_vote_authorized_voters_treap_len; i++ ) {
    err = fd_vote_authorized_voter_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY ( err ) ) return err;
  }
  return 0;
}
int fd_vote_authorized_voters_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_authorized_voters_t);
  void const * start_data = ctx->data;
  int err = fd_vote_authorized_voters_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_vote_authorized_voters_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_authorized_voters_t * self = (fd_vote_authorized_voters_t *)struct_mem;
  ulong fd_vote_authorized_voters_treap_len;
  fd_bincode_uint64_decode_unsafe( &fd_vote_authorized_voters_treap_len, ctx );
  ulong fd_vote_authorized_voters_treap_max = fd_ulong_max( fd_vote_authorized_voters_treap_len, FD_VOTE_AUTHORIZED_VOTERS_MIN );
  self->pool = fd_vote_authorized_voters_pool_join_new( alloc_mem, fd_vote_authorized_voters_treap_max );
  self->treap = fd_vote_authorized_voters_treap_join_new( alloc_mem, fd_vote_authorized_voters_treap_max );
  for( ulong i=0; i < fd_vote_authorized_voters_treap_len; i++ ) {
    fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_pool_ele_acquire( self->pool );
    fd_vote_authorized_voter_new( ele );
    fd_vote_authorized_voter_decode_inner( ele, alloc_mem, ctx );
    fd_vote_authorized_voter_t * repeated_entry = fd_vote_authorized_voters_treap_ele_query( self->treap, ele->epoch, self->pool );
    if( repeated_entry ) {
        fd_vote_authorized_voters_treap_ele_remove( self->treap, repeated_entry, self->pool ); // Remove the element before inserting it back to avoid duplication
        fd_vote_authorized_voters_pool_ele_release( self->pool, repeated_entry );
    }
    fd_vote_authorized_voters_treap_ele_insert( self->treap, ele, self->pool ); /* this cannot fail */
  }
}
void * fd_vote_authorized_voters_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_authorized_voters_t * self = (fd_vote_authorized_voters_t *)mem;
  fd_vote_authorized_voters_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_authorized_voters_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_authorized_voters_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_authorized_voters_new(fd_vote_authorized_voters_t * self) {
  fd_memset( self, 0, sizeof(fd_vote_authorized_voters_t) );
}
void fd_vote_authorized_voters_walk( void * w, fd_vote_authorized_voters_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_authorized_voters", level++, 0 );
  if( self->treap ) {
    for( fd_vote_authorized_voters_treap_fwd_iter_t iter = fd_vote_authorized_voters_treap_fwd_iter_init( self->treap, self->pool );
         !fd_vote_authorized_voters_treap_fwd_iter_done( iter );
         iter = fd_vote_authorized_voters_treap_fwd_iter_next( iter, self->pool ) ) {
      fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_treap_fwd_iter_ele( iter, self->pool );
      fd_vote_authorized_voter_walk( w, ele, fun, "fd_vote_authorized_voter_t", level, 0 );
    }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_authorized_voters", level--, 0 );
}
ulong fd_vote_authorized_voters_size( fd_vote_authorized_voters_t const * self ) {
  ulong size = 0;
  size += sizeof(ulong);
  if( self->treap ) {
    for( fd_vote_authorized_voters_treap_fwd_iter_t iter = fd_vote_authorized_voters_treap_fwd_iter_init( self->treap, self->pool );
         !fd_vote_authorized_voters_treap_fwd_iter_done( iter );
         iter = fd_vote_authorized_voters_treap_fwd_iter_next( iter, self->pool ) ) {
      fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_treap_fwd_iter_ele( iter, self->pool );
      size += fd_vote_authorized_voter_size( ele );
    }
  }
  return size;
}

int fd_vote_state_1_14_11_encode( fd_vote_state_1_14_11_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->node_pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->authorized_withdrawer, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->commission), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->votes ) {
    ulong votes_len = deq_fd_vote_lockout_t_cnt( self->votes );
    err = fd_bincode_uint64_encode( votes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes ); !deq_fd_vote_lockout_t_iter_done( self->votes, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t const * ele = deq_fd_vote_lockout_t_iter_ele_const( self->votes, iter );
      err = fd_vote_lockout_encode( ele, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  } else {
    ulong votes_len = 0;
    err = fd_bincode_uint64_encode( votes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_bool_encode( self->has_root_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_root_slot ) {
    err = fd_bincode_uint64_encode( self->root_slot, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_vote_authorized_voters_encode( &self->authorized_voters, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_vote_prior_voters_encode( &self->prior_voters, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->epoch_credits ) {
    ulong epoch_credits_len = deq_fd_vote_epoch_credits_t_cnt( self->epoch_credits );
    err = fd_bincode_uint64_encode( epoch_credits_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t const * ele = deq_fd_vote_epoch_credits_t_iter_ele_const( self->epoch_credits, iter );
      err = fd_vote_epoch_credits_encode( ele, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  } else {
    ulong epoch_credits_len = 0;
    err = fd_bincode_uint64_encode( epoch_credits_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_vote_block_timestamp_encode( &self->last_timestamp, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_vote_state_1_14_11_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong votes_len;
  err = fd_bincode_uint64_decode( &votes_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong votes_max = fd_ulong_max( votes_len, 32 );
  *total_sz += deq_fd_vote_lockout_t_align() + deq_fd_vote_lockout_t_footprint( votes_max );
  ulong votes_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( votes_len, 12, &votes_sz ) ) ) return FD_BINCODE_ERR_UNDERFLOW;
  err = fd_bincode_bytes_decode_footprint( votes_sz, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_vote_authorized_voters_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_vote_prior_voters_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ulong epoch_credits_len;
  err = fd_bincode_uint64_decode( &epoch_credits_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong epoch_credits_max = fd_ulong_max( epoch_credits_len, 64 );
  *total_sz += deq_fd_vote_epoch_credits_t_align() + deq_fd_vote_epoch_credits_t_footprint( epoch_credits_max );
  ulong epoch_credits_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( epoch_credits_len, 24, &epoch_credits_sz ) ) ) return FD_BINCODE_ERR_UNDERFLOW;
  err = fd_bincode_bytes_decode_footprint( epoch_credits_sz, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_vote_block_timestamp_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_vote_state_1_14_11_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_state_1_14_11_t);
  void const * start_data = ctx->data;
  int err = fd_vote_state_1_14_11_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_vote_state_1_14_11_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_state_1_14_11_t * self = (fd_vote_state_1_14_11_t *)struct_mem;
  fd_pubkey_decode_inner( &self->node_pubkey, alloc_mem, ctx );
  fd_pubkey_decode_inner( &self->authorized_withdrawer, alloc_mem, ctx );
  fd_bincode_uint8_decode_unsafe( &self->commission, ctx );
  ulong votes_len;
  fd_bincode_uint64_decode_unsafe( &votes_len, ctx );
  ulong votes_max = fd_ulong_max( votes_len, 32 );
  self->votes = deq_fd_vote_lockout_t_join_new( alloc_mem, votes_max );
  for( ulong i=0; i < votes_len; i++ ) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy( self->votes );
    fd_vote_lockout_new( elem );
    fd_vote_lockout_decode_inner( elem, alloc_mem, ctx );
  }
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_root_slot = !!o;
    if( o ) {
      fd_bincode_uint64_decode_unsafe( &self->root_slot, ctx );
    }
  }
  fd_vote_authorized_voters_decode_inner( &self->authorized_voters, alloc_mem, ctx );
  fd_vote_prior_voters_decode_inner( &self->prior_voters, alloc_mem, ctx );
  ulong epoch_credits_len;
  fd_bincode_uint64_decode_unsafe( &epoch_credits_len, ctx );
  ulong epoch_credits_max = fd_ulong_max( epoch_credits_len, 64 );
  self->epoch_credits = deq_fd_vote_epoch_credits_t_join_new( alloc_mem, epoch_credits_max );
  for( ulong i=0; i < epoch_credits_len; i++ ) {
    fd_vote_epoch_credits_t * elem = deq_fd_vote_epoch_credits_t_push_tail_nocopy( self->epoch_credits );
    fd_vote_epoch_credits_new( elem );
    fd_vote_epoch_credits_decode_inner( elem, alloc_mem, ctx );
  }
  fd_vote_block_timestamp_decode_inner( &self->last_timestamp, alloc_mem, ctx );
}
void * fd_vote_state_1_14_11_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_state_1_14_11_t * self = (fd_vote_state_1_14_11_t *)mem;
  fd_vote_state_1_14_11_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_state_1_14_11_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_state_1_14_11_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_state_1_14_11_new(fd_vote_state_1_14_11_t * self) {
  fd_memset( self, 0, sizeof(fd_vote_state_1_14_11_t) );
  fd_pubkey_new( &self->node_pubkey );
  fd_pubkey_new( &self->authorized_withdrawer );
  fd_vote_authorized_voters_new( &self->authorized_voters );
  fd_vote_prior_voters_new( &self->prior_voters );
  fd_vote_block_timestamp_new( &self->last_timestamp );
}
void fd_vote_state_1_14_11_walk( void * w, fd_vote_state_1_14_11_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_state_1_14_11", level++, 0 );
  fd_pubkey_walk( w, &self->node_pubkey, fun, "node_pubkey", level, 0 );
  fd_pubkey_walk( w, &self->authorized_withdrawer, fun, "authorized_withdrawer", level, 0 );
  fun( w, &self->commission, "commission", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );

  /* Walk deque */
  fun( w, self->votes, "votes", FD_FLAMENCO_TYPE_ARR, "votes", level++, 0 );
  if( self->votes ) {
    for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes );
         !deq_fd_vote_lockout_t_iter_done( self->votes, iter );
         iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->votes, iter );
      fd_vote_lockout_walk(w, ele, fun, "votes", level, 0 );
    }
  }
  fun( w, self->votes, "votes", FD_FLAMENCO_TYPE_ARR_END, "votes", level--, 0 );
  /* Done walking deque */

  if( !self->has_root_slot ) {
    fun( w, NULL, "root_slot", FD_FLAMENCO_TYPE_NULL, "ulong", level, 0 );
  } else {
    fun( w, &self->root_slot, "root_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0 );
  }
  fd_vote_authorized_voters_walk( w, &self->authorized_voters, fun, "authorized_voters", level, 0 );
  fd_vote_prior_voters_walk( w, &self->prior_voters, fun, "prior_voters", level, 0 );

  /* Walk deque */
  fun( w, self->epoch_credits, "epoch_credits", FD_FLAMENCO_TYPE_ARR, "epoch_credits", level++, 0 );
  if( self->epoch_credits ) {
    for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits );
         !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter );
         iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      fd_vote_epoch_credits_walk(w, ele, fun, "epoch_credits", level, 0 );
    }
  }
  fun( w, self->epoch_credits, "epoch_credits", FD_FLAMENCO_TYPE_ARR_END, "epoch_credits", level--, 0 );
  /* Done walking deque */

  fd_vote_block_timestamp_walk( w, &self->last_timestamp, fun, "last_timestamp", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_state_1_14_11", level--, 0 );
}
ulong fd_vote_state_1_14_11_size( fd_vote_state_1_14_11_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->node_pubkey );
  size += fd_pubkey_size( &self->authorized_withdrawer );
  size += sizeof(char);
  if( self->votes ) {
    size += sizeof(ulong);
    for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->votes ); !deq_fd_vote_lockout_t_iter_done( self->votes, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->votes, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->votes, iter );
      size += fd_vote_lockout_size( ele );
    }
  } else {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if( self->has_root_slot ) {
    size += sizeof(ulong);
  }
  size += fd_vote_authorized_voters_size( &self->authorized_voters );
  size += fd_vote_prior_voters_size( &self->prior_voters );
  if( self->epoch_credits ) {
    size += sizeof(ulong);
    for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      size += fd_vote_epoch_credits_size( ele );
    }
  } else {
    size += sizeof(ulong);
  }
  size += fd_vote_block_timestamp_size( &self->last_timestamp );
  return size;
}

int fd_vote_state_encode( fd_vote_state_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->node_pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->authorized_withdrawer, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->commission), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->votes ) {
    ulong votes_len = deq_fd_landed_vote_t_cnt( self->votes );
    err = fd_bincode_uint64_encode( votes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( self->votes ); !deq_fd_landed_vote_t_iter_done( self->votes, iter ); iter = deq_fd_landed_vote_t_iter_next( self->votes, iter ) ) {
      fd_landed_vote_t const * ele = deq_fd_landed_vote_t_iter_ele_const( self->votes, iter );
      err = fd_landed_vote_encode( ele, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  } else {
    ulong votes_len = 0;
    err = fd_bincode_uint64_encode( votes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_bool_encode( self->has_root_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_root_slot ) {
    err = fd_bincode_uint64_encode( self->root_slot, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_vote_authorized_voters_encode( &self->authorized_voters, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_vote_prior_voters_encode( &self->prior_voters, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->epoch_credits ) {
    ulong epoch_credits_len = deq_fd_vote_epoch_credits_t_cnt( self->epoch_credits );
    err = fd_bincode_uint64_encode( epoch_credits_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t const * ele = deq_fd_vote_epoch_credits_t_iter_ele_const( self->epoch_credits, iter );
      err = fd_vote_epoch_credits_encode( ele, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  } else {
    ulong epoch_credits_len = 0;
    err = fd_bincode_uint64_encode( epoch_credits_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_vote_block_timestamp_encode( &self->last_timestamp, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_vote_state_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong votes_len;
  err = fd_bincode_uint64_decode( &votes_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong votes_max = fd_ulong_max( votes_len, 32 );
  *total_sz += deq_fd_landed_vote_t_align() + deq_fd_landed_vote_t_footprint( votes_max );
  ulong votes_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( votes_len, 13, &votes_sz ) ) ) return FD_BINCODE_ERR_UNDERFLOW;
  err = fd_bincode_bytes_decode_footprint( votes_sz, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_vote_authorized_voters_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_vote_prior_voters_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ulong epoch_credits_len;
  err = fd_bincode_uint64_decode( &epoch_credits_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong epoch_credits_max = fd_ulong_max( epoch_credits_len, 64 );
  *total_sz += deq_fd_vote_epoch_credits_t_align() + deq_fd_vote_epoch_credits_t_footprint( epoch_credits_max );
  ulong epoch_credits_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( epoch_credits_len, 24, &epoch_credits_sz ) ) ) return FD_BINCODE_ERR_UNDERFLOW;
  err = fd_bincode_bytes_decode_footprint( epoch_credits_sz, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_vote_block_timestamp_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_vote_state_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_state_t);
  void const * start_data = ctx->data;
  int err = fd_vote_state_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_vote_state_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_state_t * self = (fd_vote_state_t *)struct_mem;
  fd_pubkey_decode_inner( &self->node_pubkey, alloc_mem, ctx );
  fd_pubkey_decode_inner( &self->authorized_withdrawer, alloc_mem, ctx );
  fd_bincode_uint8_decode_unsafe( &self->commission, ctx );
  ulong votes_len;
  fd_bincode_uint64_decode_unsafe( &votes_len, ctx );
  ulong votes_max = fd_ulong_max( votes_len, 32 );
  self->votes = deq_fd_landed_vote_t_join_new( alloc_mem, votes_max );
  for( ulong i=0; i < votes_len; i++ ) {
    fd_landed_vote_t * elem = deq_fd_landed_vote_t_push_tail_nocopy( self->votes );
    fd_landed_vote_new( elem );
    fd_landed_vote_decode_inner( elem, alloc_mem, ctx );
  }
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_root_slot = !!o;
    if( o ) {
      fd_bincode_uint64_decode_unsafe( &self->root_slot, ctx );
    }
  }
  fd_vote_authorized_voters_decode_inner( &self->authorized_voters, alloc_mem, ctx );
  fd_vote_prior_voters_decode_inner( &self->prior_voters, alloc_mem, ctx );
  ulong epoch_credits_len;
  fd_bincode_uint64_decode_unsafe( &epoch_credits_len, ctx );
  ulong epoch_credits_max = fd_ulong_max( epoch_credits_len, 64 );
  self->epoch_credits = deq_fd_vote_epoch_credits_t_join_new( alloc_mem, epoch_credits_max );
  for( ulong i=0; i < epoch_credits_len; i++ ) {
    fd_vote_epoch_credits_t * elem = deq_fd_vote_epoch_credits_t_push_tail_nocopy( self->epoch_credits );
    fd_vote_epoch_credits_new( elem );
    fd_vote_epoch_credits_decode_inner( elem, alloc_mem, ctx );
  }
  fd_vote_block_timestamp_decode_inner( &self->last_timestamp, alloc_mem, ctx );
}
void * fd_vote_state_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_state_t * self = (fd_vote_state_t *)mem;
  fd_vote_state_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_state_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_state_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_state_new(fd_vote_state_t * self) {
  fd_memset( self, 0, sizeof(fd_vote_state_t) );
  fd_pubkey_new( &self->node_pubkey );
  fd_pubkey_new( &self->authorized_withdrawer );
  fd_vote_authorized_voters_new( &self->authorized_voters );
  fd_vote_prior_voters_new( &self->prior_voters );
  fd_vote_block_timestamp_new( &self->last_timestamp );
}
void fd_vote_state_walk( void * w, fd_vote_state_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_state", level++, 0 );
  fd_pubkey_walk( w, &self->node_pubkey, fun, "node_pubkey", level, 0 );
  fd_pubkey_walk( w, &self->authorized_withdrawer, fun, "authorized_withdrawer", level, 0 );
  fun( w, &self->commission, "commission", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );

  /* Walk deque */
  fun( w, self->votes, "votes", FD_FLAMENCO_TYPE_ARR, "votes", level++, 0 );
  if( self->votes ) {
    for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( self->votes );
         !deq_fd_landed_vote_t_iter_done( self->votes, iter );
         iter = deq_fd_landed_vote_t_iter_next( self->votes, iter ) ) {
      fd_landed_vote_t * ele = deq_fd_landed_vote_t_iter_ele( self->votes, iter );
      fd_landed_vote_walk(w, ele, fun, "votes", level, 0 );
    }
  }
  fun( w, self->votes, "votes", FD_FLAMENCO_TYPE_ARR_END, "votes", level--, 0 );
  /* Done walking deque */

  if( !self->has_root_slot ) {
    fun( w, NULL, "root_slot", FD_FLAMENCO_TYPE_NULL, "ulong", level, 0 );
  } else {
    fun( w, &self->root_slot, "root_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0 );
  }
  fd_vote_authorized_voters_walk( w, &self->authorized_voters, fun, "authorized_voters", level, 0 );
  fd_vote_prior_voters_walk( w, &self->prior_voters, fun, "prior_voters", level, 0 );

  /* Walk deque */
  fun( w, self->epoch_credits, "epoch_credits", FD_FLAMENCO_TYPE_ARR, "epoch_credits", level++, 0 );
  if( self->epoch_credits ) {
    for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits );
         !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter );
         iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      fd_vote_epoch_credits_walk(w, ele, fun, "epoch_credits", level, 0 );
    }
  }
  fun( w, self->epoch_credits, "epoch_credits", FD_FLAMENCO_TYPE_ARR_END, "epoch_credits", level--, 0 );
  /* Done walking deque */

  fd_vote_block_timestamp_walk( w, &self->last_timestamp, fun, "last_timestamp", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_state", level--, 0 );
}
ulong fd_vote_state_size( fd_vote_state_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->node_pubkey );
  size += fd_pubkey_size( &self->authorized_withdrawer );
  size += sizeof(char);
  if( self->votes ) {
    size += sizeof(ulong);
    for( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( self->votes ); !deq_fd_landed_vote_t_iter_done( self->votes, iter ); iter = deq_fd_landed_vote_t_iter_next( self->votes, iter ) ) {
      fd_landed_vote_t * ele = deq_fd_landed_vote_t_iter_ele( self->votes, iter );
      size += fd_landed_vote_size( ele );
    }
  } else {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if( self->has_root_slot ) {
    size += sizeof(ulong);
  }
  size += fd_vote_authorized_voters_size( &self->authorized_voters );
  size += fd_vote_prior_voters_size( &self->prior_voters );
  if( self->epoch_credits ) {
    size += sizeof(ulong);
    for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( self->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( self->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( self->epoch_credits, iter ) ) {
      fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( self->epoch_credits, iter );
      size += fd_vote_epoch_credits_size( ele );
    }
  } else {
    size += sizeof(ulong);
  }
  size += fd_vote_block_timestamp_size( &self->last_timestamp );
  return size;
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
void fd_vote_state_versioned_inner_new( fd_vote_state_versioned_inner_t * self, uint discriminant );
int fd_vote_state_versioned_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_vote_state_0_23_5_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_vote_state_1_14_11_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_vote_state_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_vote_state_versioned_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_vote_state_versioned_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_vote_state_versioned_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_state_versioned_t);
  void const * start_data = ctx->data;
  int err =  fd_vote_state_versioned_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_vote_state_versioned_inner_decode_inner( fd_vote_state_versioned_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    fd_vote_state_0_23_5_decode_inner( &self->v0_23_5, alloc_mem, ctx );
    break;
  }
  case 1: {
    fd_vote_state_1_14_11_decode_inner( &self->v1_14_11, alloc_mem, ctx );
    break;
  }
  case 2: {
    fd_vote_state_decode_inner( &self->current, alloc_mem, ctx );
    break;
  }
  }
}
static void fd_vote_state_versioned_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_state_versioned_t * self = (fd_vote_state_versioned_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_vote_state_versioned_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_vote_state_versioned_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_state_versioned_t * self = (fd_vote_state_versioned_t *)mem;
  fd_vote_state_versioned_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_state_versioned_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_state_versioned_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_state_versioned_inner_new( fd_vote_state_versioned_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    fd_vote_state_0_23_5_new( &self->v0_23_5 );
    break;
  }
  case 1: {
    fd_vote_state_1_14_11_new( &self->v1_14_11 );
    break;
  }
  case 2: {
    fd_vote_state_new( &self->current );
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_vote_state_versioned_new_disc( fd_vote_state_versioned_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_vote_state_versioned_inner_new( &self->inner, self->discriminant );
}
void fd_vote_state_versioned_new( fd_vote_state_versioned_t * self ) {
  fd_memset( self, 0, sizeof(fd_vote_state_versioned_t) );
  fd_vote_state_versioned_new_disc( self, UINT_MAX );
}

void fd_vote_state_versioned_walk( void * w, fd_vote_state_versioned_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_vote_state_versioned", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "v0_23_5", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_vote_state_0_23_5_walk( w, &self->inner.v0_23_5, fun, "v0_23_5", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "v1_14_11", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_vote_state_1_14_11_walk( w, &self->inner.v1_14_11, fun, "v1_14_11", level, 0 );
    break;
  }
  case 2: {
    fun( w, self, "current", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_vote_state_walk( w, &self->inner.current, fun, "current", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_vote_state_versioned", level--, 0 );
}
ulong fd_vote_state_versioned_size( fd_vote_state_versioned_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_vote_state_0_23_5_size( &self->inner.v0_23_5 );
    break;
  }
  case 1: {
    size += fd_vote_state_1_14_11_size( &self->inner.v1_14_11 );
    break;
  }
  case 2: {
    size += fd_vote_state_size( &self->inner.current );
    break;
  }
  }
  return size;
}

int fd_vote_state_versioned_inner_encode( fd_vote_state_versioned_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_vote_state_0_23_5_encode( &self->v0_23_5, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 1: {
    err = fd_vote_state_1_14_11_encode( &self->v1_14_11, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 2: {
    err = fd_vote_state_encode( &self->current, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_vote_state_versioned_encode( fd_vote_state_versioned_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_vote_state_versioned_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_vote_state_update_encode( fd_vote_state_update_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  if( self->lockouts ) {
    ulong lockouts_len = deq_fd_vote_lockout_t_cnt( self->lockouts );
    err = fd_bincode_uint64_encode( lockouts_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->lockouts ); !deq_fd_vote_lockout_t_iter_done( self->lockouts, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->lockouts, iter ) ) {
      fd_vote_lockout_t const * ele = deq_fd_vote_lockout_t_iter_ele_const( self->lockouts, iter );
      err = fd_vote_lockout_encode( ele, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  } else {
    ulong lockouts_len = 0;
    err = fd_bincode_uint64_encode( lockouts_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_bool_encode( self->has_root, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_root ) {
    err = fd_bincode_uint64_encode( self->root, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_hash_encode( &self->hash, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_encode( self->has_timestamp, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_timestamp ) {
    err = fd_bincode_int64_encode( self->timestamp, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_vote_state_update_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ulong lockouts_len;
  err = fd_bincode_uint64_decode( &lockouts_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong lockouts_max = fd_ulong_max( lockouts_len, 32 );
  *total_sz += deq_fd_vote_lockout_t_align() + deq_fd_vote_lockout_t_footprint( lockouts_max );
  ulong lockouts_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( lockouts_len, 12, &lockouts_sz ) ) ) return FD_BINCODE_ERR_UNDERFLOW;
  err = fd_bincode_bytes_decode_footprint( lockouts_sz, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_hash_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_int64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_vote_state_update_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_state_update_t);
  void const * start_data = ctx->data;
  int err = fd_vote_state_update_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_vote_state_update_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_state_update_t * self = (fd_vote_state_update_t *)struct_mem;
  ulong lockouts_len;
  fd_bincode_uint64_decode_unsafe( &lockouts_len, ctx );
  ulong lockouts_max = fd_ulong_max( lockouts_len, 32 );
  self->lockouts = deq_fd_vote_lockout_t_join_new( alloc_mem, lockouts_max );
  for( ulong i=0; i < lockouts_len; i++ ) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy( self->lockouts );
    fd_vote_lockout_new( elem );
    fd_vote_lockout_decode_inner( elem, alloc_mem, ctx );
  }
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_root = !!o;
    if( o ) {
      fd_bincode_uint64_decode_unsafe( &self->root, ctx );
    }
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
}
void * fd_vote_state_update_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_state_update_t * self = (fd_vote_state_update_t *)mem;
  fd_vote_state_update_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_state_update_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_state_update_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_state_update_new(fd_vote_state_update_t * self) {
  fd_memset( self, 0, sizeof(fd_vote_state_update_t) );
  fd_hash_new( &self->hash );
}
void fd_vote_state_update_walk( void * w, fd_vote_state_update_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_state_update", level++, 0 );

  /* Walk deque */
  fun( w, self->lockouts, "lockouts", FD_FLAMENCO_TYPE_ARR, "lockouts", level++, 0 );
  if( self->lockouts ) {
    for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->lockouts );
         !deq_fd_vote_lockout_t_iter_done( self->lockouts, iter );
         iter = deq_fd_vote_lockout_t_iter_next( self->lockouts, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->lockouts, iter );
      fd_vote_lockout_walk(w, ele, fun, "lockouts", level, 0 );
    }
  }
  fun( w, self->lockouts, "lockouts", FD_FLAMENCO_TYPE_ARR_END, "lockouts", level--, 0 );
  /* Done walking deque */

  if( !self->has_root ) {
    fun( w, NULL, "root", FD_FLAMENCO_TYPE_NULL, "ulong", level, 0 );
  } else {
    fun( w, &self->root, "root", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0 );
  }
  fd_hash_walk( w, &self->hash, fun, "hash", level, 0 );
  if( !self->has_timestamp ) {
    fun( w, NULL, "timestamp", FD_FLAMENCO_TYPE_NULL, "long", level, 0 );
  } else {
    fun( w, &self->timestamp, "timestamp", FD_FLAMENCO_TYPE_SLONG, "long", level, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_state_update", level--, 0 );
}
ulong fd_vote_state_update_size( fd_vote_state_update_t const * self ) {
  ulong size = 0;
  if( self->lockouts ) {
    size += sizeof(ulong);
    for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->lockouts ); !deq_fd_vote_lockout_t_iter_done( self->lockouts, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->lockouts, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->lockouts, iter );
      size += fd_vote_lockout_size( ele );
    }
  } else {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if( self->has_root ) {
    size += sizeof(ulong);
  }
  size += fd_hash_size( &self->hash );
  size += sizeof(char);
  if( self->has_timestamp ) {
    size += sizeof(long);
  }
  return size;
}

int fd_compact_vote_state_update_encode( fd_compact_vote_state_update_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->root, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_compact_u16_encode( &self->lockouts_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->lockouts_len ) {
    for( ulong i=0; i < self->lockouts_len; i++ ) {
      err = fd_lockout_offset_encode( self->lockouts + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  err = fd_hash_encode( &self->hash, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_encode( self->has_timestamp, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_timestamp ) {
    err = fd_bincode_int64_encode( self->timestamp, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_compact_vote_state_update_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ushort lockouts_len;
  err = fd_bincode_compact_u16_decode( &lockouts_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( lockouts_len ) {
    *total_sz += FD_LOCKOUT_OFFSET_ALIGN + sizeof(fd_lockout_offset_t)*lockouts_len;
    for( ulong i=0; i < lockouts_len; i++ ) {
      err = fd_lockout_offset_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_hash_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_int64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_compact_vote_state_update_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_compact_vote_state_update_t);
  void const * start_data = ctx->data;
  int err = fd_compact_vote_state_update_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_compact_vote_state_update_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_compact_vote_state_update_t * self = (fd_compact_vote_state_update_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->root, ctx );
  fd_bincode_compact_u16_decode_unsafe( &self->lockouts_len, ctx );
  if( self->lockouts_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_LOCKOUT_OFFSET_ALIGN );
    self->lockouts = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_lockout_offset_t)*self->lockouts_len;
    for( ulong i=0; i < self->lockouts_len; i++ ) {
      fd_lockout_offset_new( self->lockouts + i );
      fd_lockout_offset_decode_inner( self->lockouts + i, alloc_mem, ctx );
    }
  } else
    self->lockouts = NULL;
  fd_hash_decode_inner( &self->hash, alloc_mem, ctx );
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_timestamp = !!o;
    if( o ) {
      fd_bincode_int64_decode_unsafe( &self->timestamp, ctx );
    }
  }
}
void * fd_compact_vote_state_update_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_compact_vote_state_update_t * self = (fd_compact_vote_state_update_t *)mem;
  fd_compact_vote_state_update_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_compact_vote_state_update_t);
  void * * alloc_mem = &alloc_region;
  fd_compact_vote_state_update_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_compact_vote_state_update_new(fd_compact_vote_state_update_t * self) {
  fd_memset( self, 0, sizeof(fd_compact_vote_state_update_t) );
  fd_hash_new( &self->hash );
}
void fd_compact_vote_state_update_walk( void * w, fd_compact_vote_state_update_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_compact_vote_state_update", level++, 0 );
  fun( w, &self->root, "root", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->lockouts_len, "lockouts_len", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 1 );
  if( self->lockouts_len ) {
    fun( w, NULL, "lockouts", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->lockouts_len; i++ )
      fd_lockout_offset_walk(w, self->lockouts + i, fun, "lockout_offset", level, 0 );
    fun( w, NULL, "lockouts", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fd_hash_walk( w, &self->hash, fun, "hash", level, 0 );
  if( !self->has_timestamp ) {
    fun( w, NULL, "timestamp", FD_FLAMENCO_TYPE_NULL, "long", level, 0 );
  } else {
    fun( w, &self->timestamp, "timestamp", FD_FLAMENCO_TYPE_SLONG, "long", level, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_compact_vote_state_update", level--, 0 );
}
ulong fd_compact_vote_state_update_size( fd_compact_vote_state_update_t const * self ) {
  ulong size = 0;
  size += sizeof(ulong);
  do {
    ushort tmp = (ushort)self->lockouts_len;
    size += fd_bincode_compact_u16_size( &tmp );
    for( ulong i=0; i < self->lockouts_len; i++ )
      size += fd_lockout_offset_size( self->lockouts + i );
  } while(0);
  size += fd_hash_size( &self->hash );
  size += sizeof(char);
  if( self->has_timestamp ) {
    size += sizeof(long);
  }
  return size;
}

int fd_compact_vote_state_update_switch_encode( fd_compact_vote_state_update_switch_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_compact_vote_state_update_encode( &self->compact_vote_state_update, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_hash_encode( &self->hash, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_compact_vote_state_update_switch_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_compact_vote_state_update_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_hash_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_compact_vote_state_update_switch_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_compact_vote_state_update_switch_t);
  void const * start_data = ctx->data;
  int err = fd_compact_vote_state_update_switch_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_compact_vote_state_update_switch_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_compact_vote_state_update_switch_t * self = (fd_compact_vote_state_update_switch_t *)struct_mem;
  fd_compact_vote_state_update_decode_inner( &self->compact_vote_state_update, alloc_mem, ctx );
  fd_hash_decode_inner( &self->hash, alloc_mem, ctx );
}
void * fd_compact_vote_state_update_switch_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_compact_vote_state_update_switch_t * self = (fd_compact_vote_state_update_switch_t *)mem;
  fd_compact_vote_state_update_switch_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_compact_vote_state_update_switch_t);
  void * * alloc_mem = &alloc_region;
  fd_compact_vote_state_update_switch_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_compact_vote_state_update_switch_new(fd_compact_vote_state_update_switch_t * self) {
  fd_memset( self, 0, sizeof(fd_compact_vote_state_update_switch_t) );
  fd_compact_vote_state_update_new( &self->compact_vote_state_update );
  fd_hash_new( &self->hash );
}
void fd_compact_vote_state_update_switch_walk( void * w, fd_compact_vote_state_update_switch_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_compact_vote_state_update_switch", level++, 0 );
  fd_compact_vote_state_update_walk( w, &self->compact_vote_state_update, fun, "compact_vote_state_update", level, 0 );
  fd_hash_walk( w, &self->hash, fun, "hash", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_compact_vote_state_update_switch", level--, 0 );
}
ulong fd_compact_vote_state_update_switch_size( fd_compact_vote_state_update_switch_t const * self ) {
  ulong size = 0;
  size += fd_compact_vote_state_update_size( &self->compact_vote_state_update );
  size += fd_hash_size( &self->hash );
  return size;
}

int fd_compact_tower_sync_encode( fd_compact_tower_sync_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->root, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->lockout_offsets ) {
    ushort lockout_offsets_len = (ushort)deq_fd_lockout_offset_t_cnt( self->lockout_offsets );
    err = fd_bincode_compact_u16_encode( &lockout_offsets_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( deq_fd_lockout_offset_t_iter_t iter = deq_fd_lockout_offset_t_iter_init( self->lockout_offsets ); !deq_fd_lockout_offset_t_iter_done( self->lockout_offsets, iter ); iter = deq_fd_lockout_offset_t_iter_next( self->lockout_offsets, iter ) ) {
      fd_lockout_offset_t const * ele = deq_fd_lockout_offset_t_iter_ele_const( self->lockout_offsets, iter );
      err = fd_lockout_offset_encode( ele, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  } else {
    ushort lockout_offsets_len = 0;
    err = fd_bincode_compact_u16_encode( &lockout_offsets_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_hash_encode( &self->hash, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_encode( self->has_timestamp, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_timestamp ) {
    err = fd_bincode_int64_encode( self->timestamp, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_hash_encode( &self->block_id, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_compact_tower_sync_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ushort lockout_offsets_len;
  err = fd_bincode_compact_u16_decode( &lockout_offsets_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong lockout_offsets_max = fd_ulong_max( lockout_offsets_len, 32 );
  *total_sz += deq_fd_lockout_offset_t_align() + deq_fd_lockout_offset_t_footprint( lockout_offsets_max );
  for( ulong i = 0; i < lockout_offsets_len; ++i ) {
    err = fd_lockout_offset_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_hash_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_int64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_hash_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_compact_tower_sync_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_compact_tower_sync_t);
  void const * start_data = ctx->data;
  int err = fd_compact_tower_sync_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_compact_tower_sync_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_compact_tower_sync_t * self = (fd_compact_tower_sync_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->root, ctx );
  ushort lockout_offsets_len;
  fd_bincode_compact_u16_decode_unsafe( &lockout_offsets_len, ctx );
  ulong lockout_offsets_max = fd_ulong_max( lockout_offsets_len, 32 );
  self->lockout_offsets = deq_fd_lockout_offset_t_join_new( alloc_mem, lockout_offsets_max );
  for( ulong i=0; i < lockout_offsets_len; i++ ) {
    fd_lockout_offset_t * elem = deq_fd_lockout_offset_t_push_tail_nocopy( self->lockout_offsets );
    fd_lockout_offset_new( elem );
    fd_lockout_offset_decode_inner( elem, alloc_mem, ctx );
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
void * fd_compact_tower_sync_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_compact_tower_sync_t * self = (fd_compact_tower_sync_t *)mem;
  fd_compact_tower_sync_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_compact_tower_sync_t);
  void * * alloc_mem = &alloc_region;
  fd_compact_tower_sync_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_compact_tower_sync_new(fd_compact_tower_sync_t * self) {
  fd_memset( self, 0, sizeof(fd_compact_tower_sync_t) );
  fd_hash_new( &self->hash );
  fd_hash_new( &self->block_id );
}
void fd_compact_tower_sync_walk( void * w, fd_compact_tower_sync_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_compact_tower_sync", level++, 0 );
  fun( w, &self->root, "root", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );

  /* Walk deque */
  fun( w, self->lockout_offsets, "lockout_offsets", FD_FLAMENCO_TYPE_ARR, "lockout_offsets", level++, 0 );
  if( self->lockout_offsets ) {
    for( deq_fd_lockout_offset_t_iter_t iter = deq_fd_lockout_offset_t_iter_init( self->lockout_offsets );
         !deq_fd_lockout_offset_t_iter_done( self->lockout_offsets, iter );
         iter = deq_fd_lockout_offset_t_iter_next( self->lockout_offsets, iter ) ) {
      fd_lockout_offset_t * ele = deq_fd_lockout_offset_t_iter_ele( self->lockout_offsets, iter );
      fd_lockout_offset_walk(w, ele, fun, "lockout_offsets", level, 0 );
    }
  }
  fun( w, self->lockout_offsets, "lockout_offsets", FD_FLAMENCO_TYPE_ARR_END, "lockout_offsets", level--, 0 );
  /* Done walking deque */

  fd_hash_walk( w, &self->hash, fun, "hash", level, 0 );
  if( !self->has_timestamp ) {
    fun( w, NULL, "timestamp", FD_FLAMENCO_TYPE_NULL, "long", level, 0 );
  } else {
    fun( w, &self->timestamp, "timestamp", FD_FLAMENCO_TYPE_SLONG, "long", level, 0 );
  }
  fd_hash_walk( w, &self->block_id, fun, "block_id", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_compact_tower_sync", level--, 0 );
}
ulong fd_compact_tower_sync_size( fd_compact_tower_sync_t const * self ) {
  ulong size = 0;
  size += sizeof(ulong);
  if( self->lockout_offsets ) {
    ushort lockout_offsets_len = (ushort)deq_fd_lockout_offset_t_cnt( self->lockout_offsets );
    size += fd_bincode_compact_u16_size( &lockout_offsets_len );
    for( deq_fd_lockout_offset_t_iter_t iter = deq_fd_lockout_offset_t_iter_init( self->lockout_offsets ); !deq_fd_lockout_offset_t_iter_done( self->lockout_offsets, iter ); iter = deq_fd_lockout_offset_t_iter_next( self->lockout_offsets, iter ) ) {
      fd_lockout_offset_t * ele = deq_fd_lockout_offset_t_iter_ele( self->lockout_offsets, iter );
      size += fd_lockout_offset_size( ele );
    }
  } else {
    size += 1;
  }
  size += fd_hash_size( &self->hash );
  size += sizeof(char);
  if( self->has_timestamp ) {
    size += sizeof(long);
  }
  size += fd_hash_size( &self->block_id );
  return size;
}

void fd_tower_sync_new(fd_tower_sync_t * self) {
  fd_memset( self, 0, sizeof(fd_tower_sync_t) );
  fd_hash_new( &self->hash );
  fd_hash_new( &self->block_id );
}
void fd_tower_sync_walk( void * w, fd_tower_sync_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_tower_sync", level++, 0 );

  /* Walk deque */
  fun( w, self->lockouts, "lockouts", FD_FLAMENCO_TYPE_ARR, "lockouts", level++, 0 );
  if( self->lockouts ) {
    for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->lockouts );
         !deq_fd_vote_lockout_t_iter_done( self->lockouts, iter );
         iter = deq_fd_vote_lockout_t_iter_next( self->lockouts, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->lockouts, iter );
      fd_vote_lockout_walk(w, ele, fun, "lockouts", level, 0 );
    }
  }
  fun( w, self->lockouts, "lockouts", FD_FLAMENCO_TYPE_ARR_END, "lockouts", level--, 0 );
  /* Done walking deque */

  fun( w, &self->lockouts_cnt, "lockouts_cnt", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  if( !self->has_root ) {
    fun( w, NULL, "root", FD_FLAMENCO_TYPE_NULL, "ulong", level, 0 );
  } else {
    fun( w, &self->root, "root", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0 );
  }
  fd_hash_walk( w, &self->hash, fun, "hash", level, 0 );
  if( !self->has_timestamp ) {
    fun( w, NULL, "timestamp", FD_FLAMENCO_TYPE_NULL, "long", level, 0 );
  } else {
    fun( w, &self->timestamp, "timestamp", FD_FLAMENCO_TYPE_SLONG, "long", level, 0 );
  }
  fd_hash_walk( w, &self->block_id, fun, "block_id", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_tower_sync", level--, 0 );
}
ulong fd_tower_sync_size( fd_tower_sync_t const * self ) {
  ulong size = 0;
  if( self->lockouts ) {
    size += sizeof(ulong);
    for( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( self->lockouts ); !deq_fd_vote_lockout_t_iter_done( self->lockouts, iter ); iter = deq_fd_vote_lockout_t_iter_next( self->lockouts, iter ) ) {
      fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( self->lockouts, iter );
      size += fd_vote_lockout_size( ele );
    }
  } else {
    size += sizeof(ulong);
  }
  size += sizeof(ulong);
  size += sizeof(char);
  if( self->has_root ) {
    size += sizeof(ulong);
  }
  size += fd_hash_size( &self->hash );
  size += sizeof(char);
  if( self->has_timestamp ) {
    size += sizeof(long);
  }
  size += fd_hash_size( &self->block_id );
  return size;
}

int fd_tower_sync_switch_encode( fd_tower_sync_switch_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_tower_sync_encode( &self->tower_sync, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_hash_encode( &self->hash, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_tower_sync_switch_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_tower_sync_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_hash_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_tower_sync_switch_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_tower_sync_switch_t);
  void const * start_data = ctx->data;
  int err = fd_tower_sync_switch_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_tower_sync_switch_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_tower_sync_switch_t * self = (fd_tower_sync_switch_t *)struct_mem;
  fd_tower_sync_decode_inner( &self->tower_sync, alloc_mem, ctx );
  fd_hash_decode_inner( &self->hash, alloc_mem, ctx );
}
void * fd_tower_sync_switch_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_tower_sync_switch_t * self = (fd_tower_sync_switch_t *)mem;
  fd_tower_sync_switch_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_tower_sync_switch_t);
  void * * alloc_mem = &alloc_region;
  fd_tower_sync_switch_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_tower_sync_switch_new(fd_tower_sync_switch_t * self) {
  fd_memset( self, 0, sizeof(fd_tower_sync_switch_t) );
  fd_tower_sync_new( &self->tower_sync );
  fd_hash_new( &self->hash );
}
void fd_tower_sync_switch_walk( void * w, fd_tower_sync_switch_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_tower_sync_switch", level++, 0 );
  fd_tower_sync_walk( w, &self->tower_sync, fun, "tower_sync", level, 0 );
  fd_hash_walk( w, &self->hash, fun, "hash", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_tower_sync_switch", level--, 0 );
}
ulong fd_tower_sync_switch_size( fd_tower_sync_switch_t const * self ) {
  ulong size = 0;
  size += fd_tower_sync_size( &self->tower_sync );
  size += fd_hash_size( &self->hash );
  return size;
}

int fd_slot_history_encode( fd_slot_history_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_bool_encode( self->has_bits, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_bits ) {
    err = fd_bincode_uint64_encode( self->bits_bitvec_len, ctx );
    if( FD_UNLIKELY(err) ) return err;
    if( self->bits_bitvec_len ) {
      for( ulong i=0; i < self->bits_bitvec_len; i++ ) {
        err = fd_bincode_uint64_encode( self->bits_bitvec[i], ctx );
      }
    }
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint64_encode( self->bits_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->next_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
int fd_slot_history_encode_global( fd_slot_history_global_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_bool_encode( self->has_bits, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_bits ) {
  if( FD_UNLIKELY( err ) ) return err;
    err = fd_bincode_uint64_encode( self->bits_bitvec_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    if( self->bits_bitvec_len ) {
      uchar * bits_bitvec_laddr = (uchar*)self + self->bits_bitvec_offset;
      ulong * bits_bitvec = (ulong *)bits_bitvec_laddr;
      for( ulong i=0; i < self->bits_bitvec_len; i++ ) {
        err = fd_bincode_uint64_encode( bits_bitvec[i], ctx );
        if( FD_UNLIKELY( err ) ) return err;
      }
    }
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint64_encode( self->bits_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->next_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_slot_history_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  {
    uchar o;
    ulong inner_len = 0UL;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      ulong bits_bitvec_len;
      err = fd_bincode_uint64_decode( &bits_bitvec_len, ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
      if( bits_bitvec_len ) {
        *total_sz += 8UL + sizeof(ulong)*bits_bitvec_len;
        for( ulong i=0; i < bits_bitvec_len; i++ ) {
          err = fd_bincode_uint64_decode_footprint( ctx );
          if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
        }
      }
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
      inner_len = bits_bitvec_len;
      if( inner_len==0 ) return FD_BINCODE_ERR_ENCODING;
    }
    ulong len;
    err = fd_bincode_uint64_decode( &len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( len > inner_len * sizeof(ulong) * 8UL ) return FD_BINCODE_ERR_ENCODING;
  }
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_slot_history_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_slot_history_t);
  void const * start_data = ctx->data;
  int err = fd_slot_history_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_slot_history_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_slot_history_t * self = (fd_slot_history_t *)struct_mem;
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_bits = !!o;
    if( o ) {
      fd_bincode_uint64_decode_unsafe( &self->bits_bitvec_len, ctx );
      if( self->bits_bitvec_len ) {
        *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), 8UL );
        self->bits_bitvec = *alloc_mem;
        *alloc_mem = (uchar *)(*alloc_mem) + sizeof(ulong)*self->bits_bitvec_len;
        for( ulong i=0; i < self->bits_bitvec_len; i++ ) {
          fd_bincode_uint64_decode_unsafe( self->bits_bitvec + i, ctx );
        }
      } else
        self->bits_bitvec = NULL;
    } else {
      self->bits_bitvec = NULL;
    }
    fd_bincode_uint64_decode_unsafe( &self->bits_len, ctx );
  }
  fd_bincode_uint64_decode_unsafe( &self->next_slot, ctx );
}
void * fd_slot_history_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_slot_history_t * self = (fd_slot_history_t *)mem;
  fd_slot_history_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_slot_history_t);
  void * * alloc_mem = &alloc_region;
  fd_slot_history_decode_inner( mem, alloc_mem, ctx );
  return self;
}
static void fd_slot_history_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_slot_history_global_t * self = (fd_slot_history_global_t *)struct_mem;
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_bits = !!o;
    if( o ) {
      fd_bincode_uint64_decode_unsafe( &self->bits_bitvec_len, ctx );
      if( self->bits_bitvec_len ) {
        *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), 8UL );
        self->bits_bitvec_offset = (ulong)*alloc_mem - (ulong)struct_mem;
        uchar * cur_mem = (uchar *)(*alloc_mem);
        *alloc_mem = (uchar *)(*alloc_mem) + sizeof(ulong)*self->bits_bitvec_len;
        for( ulong i=0; i < self->bits_bitvec_len; i++ ) {
          fd_bincode_uint64_decode_unsafe( (ulong*)(cur_mem + sizeof(ulong) * i), ctx );
        }
      } else {
        self->bits_bitvec_offset = 0UL;
      }
    }
    fd_bincode_uint64_decode_unsafe( &self->bits_len, ctx );
  }
  fd_bincode_uint64_decode_unsafe( &self->next_slot, ctx );
}
void * fd_slot_history_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_slot_history_global_t * self = (fd_slot_history_global_t *)mem;
  fd_slot_history_new( (fd_slot_history_t *)self );
  void * alloc_region = (uchar *)mem + sizeof(fd_slot_history_global_t);
  void * * alloc_mem = &alloc_region;
  fd_slot_history_decode_inner_global( mem, alloc_mem, ctx );
  return self;
}
void fd_slot_history_new(fd_slot_history_t * self) {
  fd_memset( self, 0, sizeof(fd_slot_history_t) );
}
void fd_slot_history_walk( void * w, fd_slot_history_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_slot_history", level++, 0 );
  if( !self->has_bits ) {
    fun( w, NULL, "bits", FD_FLAMENCO_TYPE_NULL, "ulong", level, 0 );
  } else {
    if( self->bits_bitvec_len ) {
      fun( w, NULL, "bits_bitvec", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
      for( ulong i=0; i < self->bits_bitvec_len; i++ )
      fun( w, self->bits_bitvec + i, "bits_bitvec", FD_FLAMENCO_TYPE_ULONG,   "ulong",   level, 0 );
      fun( w, NULL, "bits_bitvec", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
    }
  }
  fun( w, &self->bits_len, "bits_len", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0 );
  fun( w, &self->next_slot, "next_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_slot_history", level--, 0 );
}
ulong fd_slot_history_size( fd_slot_history_t const * self ) {
  ulong size = 0;
  size += sizeof(char);
  if( self->has_bits ) {
    do {
      size += sizeof(ulong);
      size += self->bits_bitvec_len * sizeof(ulong);
    } while(0);
  }
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

ulong fd_slot_history_size_global( fd_slot_history_global_t const * self ) {
  ulong size = 0;
  do {
    size += sizeof(char);
    if( self->has_bits ) {
    do {
      size += sizeof(ulong);
    ulong * bits_bitvec = self->bits_bitvec_offset ? (ulong *)fd_type_pun( (uchar *)self + self->bits_bitvec_offset ) : NULL;
      size += self->bits_bitvec_len * sizeof(ulong);
    } while(0);
    }
  } while(0);
  size += sizeof(ulong);
  return size;
}

int fd_slot_hash_encode( fd_slot_hash_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_hash_encode( &self->hash, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_slot_hash_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 40UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 40UL );
  return 0;
}
static void fd_slot_hash_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_slot_hash_t * self = (fd_slot_hash_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->slot, ctx );
  fd_hash_decode_inner( &self->hash, alloc_mem, ctx );
}
void * fd_slot_hash_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_slot_hash_t * self = (fd_slot_hash_t *)mem;
  fd_slot_hash_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_slot_hash_t);
  void * * alloc_mem = &alloc_region;
  fd_slot_hash_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_slot_hash_walk( void * w, fd_slot_hash_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_slot_hash", level++, 0 );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_hash_walk( w, &self->hash, fun, "hash", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_slot_hash", level--, 0 );
}
int fd_slot_hashes_encode( fd_slot_hashes_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  if( self->hashes ) {
    ulong hashes_len = deq_fd_slot_hash_t_cnt( self->hashes );
    err = fd_bincode_uint64_encode( hashes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( self->hashes ); !deq_fd_slot_hash_t_iter_done( self->hashes, iter ); iter = deq_fd_slot_hash_t_iter_next( self->hashes, iter ) ) {
      fd_slot_hash_t const * ele = deq_fd_slot_hash_t_iter_ele_const( self->hashes, iter );
      err = fd_slot_hash_encode( ele, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  } else {
    ulong hashes_len = 0;
    err = fd_bincode_uint64_encode( hashes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
int fd_slot_hashes_encode_global( fd_slot_hashes_global_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  if( self->hashes_offset ) {
  uchar * hashes_laddr = (uchar*)self + self->hashes_offset;
   fd_slot_hash_t * hashes = deq_fd_slot_hash_t_join( hashes_laddr );
    ulong hashes_len = deq_fd_slot_hash_t_cnt( hashes );
    err = fd_bincode_uint64_encode( hashes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( hashes ); !deq_fd_slot_hash_t_iter_done( hashes, iter ); iter = deq_fd_slot_hash_t_iter_next( hashes, iter ) ) {
      fd_slot_hash_t const * ele = deq_fd_slot_hash_t_iter_ele_const( hashes, iter );
      err = fd_slot_hash_encode( ele, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  } else {
    ulong hashes_len = 0;
    err = fd_bincode_uint64_encode( hashes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_slot_hashes_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ulong hashes_len;
  err = fd_bincode_uint64_decode( &hashes_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong hashes_max = fd_ulong_max( hashes_len, 512 );
  *total_sz += deq_fd_slot_hash_t_align() + deq_fd_slot_hash_t_footprint( hashes_max );
  ulong hashes_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( hashes_len, 40, &hashes_sz ) ) ) return FD_BINCODE_ERR_UNDERFLOW;
  err = fd_bincode_bytes_decode_footprint( hashes_sz, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_slot_hashes_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_slot_hashes_t);
  void const * start_data = ctx->data;
  int err = fd_slot_hashes_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_slot_hashes_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_slot_hashes_t * self = (fd_slot_hashes_t *)struct_mem;
  ulong hashes_len;
  fd_bincode_uint64_decode_unsafe( &hashes_len, ctx );
  ulong hashes_max = fd_ulong_max( hashes_len, 512 );
  self->hashes = deq_fd_slot_hash_t_join_new( alloc_mem, hashes_max );
  for( ulong i=0; i < hashes_len; i++ ) {
    fd_slot_hash_t * elem = deq_fd_slot_hash_t_push_tail_nocopy( self->hashes );
    fd_slot_hash_new( elem );
    fd_slot_hash_decode_inner( elem, alloc_mem, ctx );
  }
}
void * fd_slot_hashes_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_slot_hashes_t * self = (fd_slot_hashes_t *)mem;
  fd_slot_hashes_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_slot_hashes_t);
  void * * alloc_mem = &alloc_region;
  fd_slot_hashes_decode_inner( mem, alloc_mem, ctx );
  return self;
}
static void fd_slot_hashes_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_slot_hashes_global_t * self = (fd_slot_hashes_global_t *)struct_mem;
  ulong hashes_len;
  fd_bincode_uint64_decode_unsafe( &hashes_len, ctx );
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, deq_fd_slot_hash_t_align() );
  ulong hashes_max = fd_ulong_max( hashes_len, 512 );
  fd_slot_hash_t * hashes = deq_fd_slot_hash_t_join_new( alloc_mem, hashes_max );
  for( ulong i=0; i < hashes_len; i++ ) {
    fd_slot_hash_t * elem = deq_fd_slot_hash_t_push_tail_nocopy( hashes );
    fd_slot_hash_new( (fd_slot_hash_t*)fd_type_pun( elem ) );
    fd_slot_hash_decode_inner( elem, alloc_mem, ctx );
  }
  self->hashes_offset = (ulong)deq_fd_slot_hash_t_leave( hashes ) - (ulong)struct_mem;
}
void * fd_slot_hashes_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_slot_hashes_global_t * self = (fd_slot_hashes_global_t *)mem;
  fd_slot_hashes_new( (fd_slot_hashes_t *)self );
  void * alloc_region = (uchar *)mem + sizeof(fd_slot_hashes_global_t);
  void * * alloc_mem = &alloc_region;
  fd_slot_hashes_decode_inner_global( mem, alloc_mem, ctx );
  return self;
}
void fd_slot_hashes_new(fd_slot_hashes_t * self) {
  fd_memset( self, 0, sizeof(fd_slot_hashes_t) );
}
void fd_slot_hashes_walk( void * w, fd_slot_hashes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_slot_hashes", level++, 0 );

  /* Walk deque */
  fun( w, self->hashes, "hashes", FD_FLAMENCO_TYPE_ARR, "hashes", level++, 0 );
  if( self->hashes ) {
    for( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( self->hashes );
         !deq_fd_slot_hash_t_iter_done( self->hashes, iter );
         iter = deq_fd_slot_hash_t_iter_next( self->hashes, iter ) ) {
      fd_slot_hash_t * ele = deq_fd_slot_hash_t_iter_ele( self->hashes, iter );
      fd_slot_hash_walk(w, ele, fun, "hashes", level, 0 );
    }
  }
  fun( w, self->hashes, "hashes", FD_FLAMENCO_TYPE_ARR_END, "hashes", level--, 0 );
  /* Done walking deque */

  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_slot_hashes", level--, 0 );
}
ulong fd_slot_hashes_size( fd_slot_hashes_t const * self ) {
  ulong size = 0;
  if( self->hashes ) {
    size += sizeof(ulong);
    for( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( self->hashes ); !deq_fd_slot_hash_t_iter_done( self->hashes, iter ); iter = deq_fd_slot_hash_t_iter_next( self->hashes, iter ) ) {
      fd_slot_hash_t * ele = deq_fd_slot_hash_t_iter_ele( self->hashes, iter );
      size += fd_slot_hash_size( ele );
    }
  } else {
    size += sizeof(ulong);
  }
  return size;
}

ulong fd_slot_hashes_size_global( fd_slot_hashes_global_t const * self ) {
  ulong size = 0;
  if( self->hashes_offset!=0 ) {
    fd_slot_hash_t * hashes = (fd_slot_hash_t *)deq_fd_slot_hash_t_join( fd_type_pun( (uchar *)self + self->hashes_offset ) );
    size += sizeof(ulong);
    for( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( hashes ); !deq_fd_slot_hash_t_iter_done( hashes, iter ); iter = deq_fd_slot_hash_t_iter_next( hashes, iter ) ) {
      fd_slot_hash_t * ele = deq_fd_slot_hash_t_iter_ele( hashes, iter );
      size += fd_slot_hash_size( ele );
    }
  } else {
    size += sizeof(ulong);
  }
  return size;
}

int fd_block_block_hash_entry_encode( fd_block_block_hash_entry_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_hash_encode( &self->blockhash, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_fee_calculator_encode( &self->fee_calculator, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_block_block_hash_entry_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 40UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 40UL );
  return 0;
}
static void fd_block_block_hash_entry_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_block_block_hash_entry_t * self = (fd_block_block_hash_entry_t *)struct_mem;
  fd_hash_decode_inner( &self->blockhash, alloc_mem, ctx );
  fd_fee_calculator_decode_inner( &self->fee_calculator, alloc_mem, ctx );
}
void * fd_block_block_hash_entry_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_block_block_hash_entry_t * self = (fd_block_block_hash_entry_t *)mem;
  fd_block_block_hash_entry_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_block_block_hash_entry_t);
  void * * alloc_mem = &alloc_region;
  fd_block_block_hash_entry_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_block_block_hash_entry_walk( void * w, fd_block_block_hash_entry_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_block_block_hash_entry", level++, 0 );
  fd_hash_walk( w, &self->blockhash, fun, "blockhash", level, 0 );
  fd_fee_calculator_walk( w, &self->fee_calculator, fun, "fee_calculator", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_block_block_hash_entry", level--, 0 );
}
int fd_recent_block_hashes_encode( fd_recent_block_hashes_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  if( self->hashes ) {
    ulong hashes_len = deq_fd_block_block_hash_entry_t_cnt( self->hashes );
    err = fd_bincode_uint64_encode( hashes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( deq_fd_block_block_hash_entry_t_iter_t iter = deq_fd_block_block_hash_entry_t_iter_init( self->hashes ); !deq_fd_block_block_hash_entry_t_iter_done( self->hashes, iter ); iter = deq_fd_block_block_hash_entry_t_iter_next( self->hashes, iter ) ) {
      fd_block_block_hash_entry_t const * ele = deq_fd_block_block_hash_entry_t_iter_ele_const( self->hashes, iter );
      err = fd_block_block_hash_entry_encode( ele, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  } else {
    ulong hashes_len = 0;
    err = fd_bincode_uint64_encode( hashes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
int fd_recent_block_hashes_encode_global( fd_recent_block_hashes_global_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  if( self->hashes_offset ) {
  uchar * hashes_laddr = (uchar*)self + self->hashes_offset;
   fd_block_block_hash_entry_t * hashes = deq_fd_block_block_hash_entry_t_join( hashes_laddr );
    ulong hashes_len = deq_fd_block_block_hash_entry_t_cnt( hashes );
    err = fd_bincode_uint64_encode( hashes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( deq_fd_block_block_hash_entry_t_iter_t iter = deq_fd_block_block_hash_entry_t_iter_init( hashes ); !deq_fd_block_block_hash_entry_t_iter_done( hashes, iter ); iter = deq_fd_block_block_hash_entry_t_iter_next( hashes, iter ) ) {
      fd_block_block_hash_entry_t const * ele = deq_fd_block_block_hash_entry_t_iter_ele_const( hashes, iter );
      err = fd_block_block_hash_entry_encode( ele, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  } else {
    ulong hashes_len = 0;
    err = fd_bincode_uint64_encode( hashes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_recent_block_hashes_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ulong hashes_len;
  err = fd_bincode_uint64_decode( &hashes_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong hashes_max = fd_ulong_max( hashes_len, 151 );
  *total_sz += deq_fd_block_block_hash_entry_t_align() + deq_fd_block_block_hash_entry_t_footprint( hashes_max );
  ulong hashes_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( hashes_len, 40, &hashes_sz ) ) ) return FD_BINCODE_ERR_UNDERFLOW;
  err = fd_bincode_bytes_decode_footprint( hashes_sz, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_recent_block_hashes_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_recent_block_hashes_t);
  void const * start_data = ctx->data;
  int err = fd_recent_block_hashes_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_recent_block_hashes_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_recent_block_hashes_t * self = (fd_recent_block_hashes_t *)struct_mem;
  ulong hashes_len;
  fd_bincode_uint64_decode_unsafe( &hashes_len, ctx );
  ulong hashes_max = fd_ulong_max( hashes_len, 151 );
  self->hashes = deq_fd_block_block_hash_entry_t_join_new( alloc_mem, hashes_max );
  for( ulong i=0; i < hashes_len; i++ ) {
    fd_block_block_hash_entry_t * elem = deq_fd_block_block_hash_entry_t_push_tail_nocopy( self->hashes );
    fd_block_block_hash_entry_new( elem );
    fd_block_block_hash_entry_decode_inner( elem, alloc_mem, ctx );
  }
}
void * fd_recent_block_hashes_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_recent_block_hashes_t * self = (fd_recent_block_hashes_t *)mem;
  fd_recent_block_hashes_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_recent_block_hashes_t);
  void * * alloc_mem = &alloc_region;
  fd_recent_block_hashes_decode_inner( mem, alloc_mem, ctx );
  return self;
}
static void fd_recent_block_hashes_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_recent_block_hashes_global_t * self = (fd_recent_block_hashes_global_t *)struct_mem;
  ulong hashes_len;
  fd_bincode_uint64_decode_unsafe( &hashes_len, ctx );
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, deq_fd_block_block_hash_entry_t_align() );
  ulong hashes_max = fd_ulong_max( hashes_len, 151 );
  fd_block_block_hash_entry_t * hashes = deq_fd_block_block_hash_entry_t_join_new( alloc_mem, hashes_max );
  for( ulong i=0; i < hashes_len; i++ ) {
    fd_block_block_hash_entry_t * elem = deq_fd_block_block_hash_entry_t_push_tail_nocopy( hashes );
    fd_block_block_hash_entry_new( (fd_block_block_hash_entry_t*)fd_type_pun( elem ) );
    fd_block_block_hash_entry_decode_inner( elem, alloc_mem, ctx );
  }
  self->hashes_offset = (ulong)deq_fd_block_block_hash_entry_t_leave( hashes ) - (ulong)struct_mem;
}
void * fd_recent_block_hashes_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_recent_block_hashes_global_t * self = (fd_recent_block_hashes_global_t *)mem;
  fd_recent_block_hashes_new( (fd_recent_block_hashes_t *)self );
  void * alloc_region = (uchar *)mem + sizeof(fd_recent_block_hashes_global_t);
  void * * alloc_mem = &alloc_region;
  fd_recent_block_hashes_decode_inner_global( mem, alloc_mem, ctx );
  return self;
}
void fd_recent_block_hashes_new(fd_recent_block_hashes_t * self) {
  fd_memset( self, 0, sizeof(fd_recent_block_hashes_t) );
}
void fd_recent_block_hashes_walk( void * w, fd_recent_block_hashes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_recent_block_hashes", level++, 0 );

  /* Walk deque */
  fun( w, self->hashes, "hashes", FD_FLAMENCO_TYPE_ARR, "hashes", level++, 0 );
  if( self->hashes ) {
    for( deq_fd_block_block_hash_entry_t_iter_t iter = deq_fd_block_block_hash_entry_t_iter_init( self->hashes );
         !deq_fd_block_block_hash_entry_t_iter_done( self->hashes, iter );
         iter = deq_fd_block_block_hash_entry_t_iter_next( self->hashes, iter ) ) {
      fd_block_block_hash_entry_t * ele = deq_fd_block_block_hash_entry_t_iter_ele( self->hashes, iter );
      fd_block_block_hash_entry_walk(w, ele, fun, "hashes", level, 0 );
    }
  }
  fun( w, self->hashes, "hashes", FD_FLAMENCO_TYPE_ARR_END, "hashes", level--, 0 );
  /* Done walking deque */

  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_recent_block_hashes", level--, 0 );
}
ulong fd_recent_block_hashes_size( fd_recent_block_hashes_t const * self ) {
  ulong size = 0;
  if( self->hashes ) {
    size += sizeof(ulong);
    for( deq_fd_block_block_hash_entry_t_iter_t iter = deq_fd_block_block_hash_entry_t_iter_init( self->hashes ); !deq_fd_block_block_hash_entry_t_iter_done( self->hashes, iter ); iter = deq_fd_block_block_hash_entry_t_iter_next( self->hashes, iter ) ) {
      fd_block_block_hash_entry_t * ele = deq_fd_block_block_hash_entry_t_iter_ele( self->hashes, iter );
      size += fd_block_block_hash_entry_size( ele );
    }
  } else {
    size += sizeof(ulong);
  }
  return size;
}

ulong fd_recent_block_hashes_size_global( fd_recent_block_hashes_global_t const * self ) {
  ulong size = 0;
  if( self->hashes_offset!=0 ) {
    fd_block_block_hash_entry_t * hashes = (fd_block_block_hash_entry_t *)deq_fd_block_block_hash_entry_t_join( fd_type_pun( (uchar *)self + self->hashes_offset ) );
    size += sizeof(ulong);
    for( deq_fd_block_block_hash_entry_t_iter_t iter = deq_fd_block_block_hash_entry_t_iter_init( hashes ); !deq_fd_block_block_hash_entry_t_iter_done( hashes, iter ); iter = deq_fd_block_block_hash_entry_t_iter_next( hashes, iter ) ) {
      fd_block_block_hash_entry_t * ele = deq_fd_block_block_hash_entry_t_iter_ele( hashes, iter );
      size += fd_block_block_hash_entry_size( ele );
    }
  } else {
    size += sizeof(ulong);
  }
  return size;
}

int fd_slot_meta_encode( fd_slot_meta_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->consumed, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->received, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( (ulong)self->first_shred_timestamp, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->last_index, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->parent_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->next_slot_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->next_slot_len ) {
    for( ulong i=0; i < self->next_slot_len; i++ ) {
      err = fd_bincode_uint64_encode( self->next_slot[i], ctx );
    }
  }
  err = fd_bincode_uint8_encode( (uchar)(self->is_connected), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->entry_end_indexes_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->entry_end_indexes_len ) {
    for( ulong i=0; i < self->entry_end_indexes_len; i++ ) {
      err = fd_bincode_uint32_encode( self->entry_end_indexes[i], ctx );
    }
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_slot_meta_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ulong next_slot_len;
  err = fd_bincode_uint64_decode( &next_slot_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( next_slot_len ) {
    *total_sz += 8UL + sizeof(ulong)*next_slot_len;
    for( ulong i=0; i < next_slot_len; i++ ) {
      err = fd_bincode_uint64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong entry_end_indexes_len;
  err = fd_bincode_uint64_decode( &entry_end_indexes_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( entry_end_indexes_len ) {
    *total_sz += 8UL + sizeof(uint)*entry_end_indexes_len;
    for( ulong i=0; i < entry_end_indexes_len; i++ ) {
      err = fd_bincode_uint32_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_slot_meta_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_slot_meta_t);
  void const * start_data = ctx->data;
  int err = fd_slot_meta_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_slot_meta_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_slot_meta_t * self = (fd_slot_meta_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->slot, ctx );
  fd_bincode_uint64_decode_unsafe( &self->consumed, ctx );
  fd_bincode_uint64_decode_unsafe( &self->received, ctx );
  fd_bincode_uint64_decode_unsafe( (ulong *) &self->first_shred_timestamp, ctx );
  fd_bincode_uint64_decode_unsafe( &self->last_index, ctx );
  fd_bincode_uint64_decode_unsafe( &self->parent_slot, ctx );
  fd_bincode_uint64_decode_unsafe( &self->next_slot_len, ctx );
  if( self->next_slot_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), 8UL );
    self->next_slot = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(ulong)*self->next_slot_len;
    for( ulong i=0; i < self->next_slot_len; i++ ) {
      fd_bincode_uint64_decode_unsafe( self->next_slot + i, ctx );
    }
  } else
    self->next_slot = NULL;
  fd_bincode_uint8_decode_unsafe( &self->is_connected, ctx );
  fd_bincode_uint64_decode_unsafe( &self->entry_end_indexes_len, ctx );
  if( self->entry_end_indexes_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), 8UL );
    self->entry_end_indexes = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(uint)*self->entry_end_indexes_len;
    for( ulong i=0; i < self->entry_end_indexes_len; i++ ) {
      fd_bincode_uint32_decode_unsafe( self->entry_end_indexes + i, ctx );
    }
  } else
    self->entry_end_indexes = NULL;
}
void * fd_slot_meta_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_slot_meta_t * self = (fd_slot_meta_t *)mem;
  fd_slot_meta_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_slot_meta_t);
  void * * alloc_mem = &alloc_region;
  fd_slot_meta_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_slot_meta_new(fd_slot_meta_t * self) {
  fd_memset( self, 0, sizeof(fd_slot_meta_t) );
}
void fd_slot_meta_walk( void * w, fd_slot_meta_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_slot_meta", level++, 0 );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->consumed, "consumed", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->received, "received", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->first_shred_timestamp, "first_shred_timestamp", FD_FLAMENCO_TYPE_SLONG, "long", level, 0  );
  fun( w, &self->last_index, "last_index", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->parent_slot, "parent_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  if( self->next_slot_len ) {
    fun( w, NULL, "next_slot", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->next_slot_len; i++ )
      fun( w, self->next_slot + i, "next_slot", FD_FLAMENCO_TYPE_ULONG,   "ulong",   level, 0 );
    fun( w, NULL, "next_slot", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, &self->is_connected, "is_connected", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  if( self->entry_end_indexes_len ) {
    fun( w, NULL, "entry_end_indexes", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->entry_end_indexes_len; i++ )
      fun( w, self->entry_end_indexes + i, "entry_end_indexes", FD_FLAMENCO_TYPE_UINT,    "uint",    level, 0 );
    fun( w, NULL, "entry_end_indexes", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_slot_meta", level--, 0 );
}
ulong fd_slot_meta_size( fd_slot_meta_t const * self ) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(long);
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

int fd_clock_timestamp_vote_encode( fd_clock_timestamp_vote_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( (ulong)self->timestamp, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_clock_timestamp_vote_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 48UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 48UL );
  return 0;
}
static void fd_clock_timestamp_vote_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_clock_timestamp_vote_t * self = (fd_clock_timestamp_vote_t *)struct_mem;
  fd_pubkey_decode_inner( &self->pubkey, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( (ulong *) &self->timestamp, ctx );
  fd_bincode_uint64_decode_unsafe( &self->slot, ctx );
}
void * fd_clock_timestamp_vote_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_clock_timestamp_vote_t * self = (fd_clock_timestamp_vote_t *)mem;
  fd_clock_timestamp_vote_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_clock_timestamp_vote_t);
  void * * alloc_mem = &alloc_region;
  fd_clock_timestamp_vote_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_clock_timestamp_vote_walk( void * w, fd_clock_timestamp_vote_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_clock_timestamp_vote", level++, 0 );
  fd_pubkey_walk( w, &self->pubkey, fun, "pubkey", level, 0 );
  fun( w, &self->timestamp, "timestamp", FD_FLAMENCO_TYPE_SLONG, "long", level, 0  );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_clock_timestamp_vote", level--, 0 );
}
int fd_clock_timestamp_votes_encode( fd_clock_timestamp_votes_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  if( self->votes_root ) {
    ulong votes_len = fd_clock_timestamp_vote_t_map_size( self->votes_pool, self->votes_root );
    err = fd_bincode_uint64_encode( votes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( fd_clock_timestamp_vote_t_mapnode_t * n = fd_clock_timestamp_vote_t_map_minimum( self->votes_pool, self->votes_root ); n; n = fd_clock_timestamp_vote_t_map_successor( self->votes_pool, n ) ) {
      err = fd_clock_timestamp_vote_encode( &n->elem, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  } else {
    ulong votes_len = 0;
    err = fd_bincode_uint64_encode( votes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
int fd_clock_timestamp_votes_encode_global( fd_clock_timestamp_votes_global_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  fd_clock_timestamp_vote_t_mapnode_t * votes_root = fd_clock_timestamp_vote_t_map_join( (uchar *)self + self->votes_root_offset );
  fd_clock_timestamp_vote_t_mapnode_t * votes_pool = fd_clock_timestamp_vote_t_map_join( (uchar *)self + self->votes_pool_offset );
  if( votes_root ) {
    ulong votes_len = fd_clock_timestamp_vote_t_map_size( votes_pool, votes_root );
    err = fd_bincode_uint64_encode( votes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( fd_clock_timestamp_vote_t_mapnode_t * n = fd_clock_timestamp_vote_t_map_minimum( votes_pool, votes_root ); n; n = fd_clock_timestamp_vote_t_map_successor( votes_pool, n ) ) {
      err = fd_clock_timestamp_vote_encode( &n->elem, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  } else {
    ulong votes_len = 0;
    err = fd_bincode_uint64_encode( votes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_clock_timestamp_votes_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ulong votes_len = 0UL;
  err = fd_bincode_uint64_decode( &votes_len, ctx );
  ulong votes_cnt = fd_ulong_max( votes_len, 15000 );
  *total_sz += fd_clock_timestamp_vote_t_map_align() + fd_clock_timestamp_vote_t_map_footprint( votes_cnt );
  if( FD_UNLIKELY( err ) ) return err;
  for( ulong i=0; i < votes_len; i++ ) {
    err = fd_clock_timestamp_vote_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return 0;
}
int fd_clock_timestamp_votes_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_clock_timestamp_votes_t);
  void const * start_data = ctx->data;
  int err = fd_clock_timestamp_votes_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_clock_timestamp_votes_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_clock_timestamp_votes_t * self = (fd_clock_timestamp_votes_t *)struct_mem;
  ulong votes_len;
  fd_bincode_uint64_decode_unsafe( &votes_len, ctx );
  self->votes_pool = fd_clock_timestamp_vote_t_map_join_new( alloc_mem, fd_ulong_max( votes_len, 15000 ) );
  self->votes_root = NULL;
  for( ulong i=0; i < votes_len; i++ ) {
    fd_clock_timestamp_vote_t_mapnode_t * node = fd_clock_timestamp_vote_t_map_acquire( self->votes_pool );
    fd_clock_timestamp_vote_new( &node->elem );
    fd_clock_timestamp_vote_decode_inner( &node->elem, alloc_mem, ctx );
    fd_clock_timestamp_vote_t_mapnode_t * out = NULL;;
    fd_clock_timestamp_vote_t_map_insert_or_replace( self->votes_pool, &self->votes_root, node, &out );
    if( out != NULL ) {
      fd_clock_timestamp_vote_t_map_release( self->votes_pool, out );
    }
  }
}
void * fd_clock_timestamp_votes_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_clock_timestamp_votes_t * self = (fd_clock_timestamp_votes_t *)mem;
  fd_clock_timestamp_votes_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_clock_timestamp_votes_t);
  void * * alloc_mem = &alloc_region;
  fd_clock_timestamp_votes_decode_inner( mem, alloc_mem, ctx );
  return self;
}
static void fd_clock_timestamp_votes_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_clock_timestamp_votes_global_t * self = (fd_clock_timestamp_votes_global_t *)struct_mem;
  ulong votes_len;
  fd_bincode_uint64_decode_unsafe( &votes_len, ctx );
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_clock_timestamp_vote_t_map_align() );
  fd_clock_timestamp_vote_t_mapnode_t * votes_pool = fd_clock_timestamp_vote_t_map_join_new( alloc_mem, fd_ulong_max( votes_len, 15000 ) );
  fd_clock_timestamp_vote_t_mapnode_t * votes_root = NULL;
  for( ulong i=0; i < votes_len; i++ ) {
    fd_clock_timestamp_vote_t_mapnode_t * node = fd_clock_timestamp_vote_t_map_acquire( votes_pool );
    fd_clock_timestamp_vote_new( (fd_clock_timestamp_vote_t *)fd_type_pun(&node->elem) );
    fd_clock_timestamp_vote_decode_inner( &node->elem, alloc_mem, ctx );
    fd_clock_timestamp_vote_t_map_insert( votes_pool, &votes_root, node );
  }
  self->votes_pool_offset = (ulong)fd_clock_timestamp_vote_t_map_leave( votes_pool ) - (ulong)struct_mem;
  self->votes_root_offset = (ulong)votes_root - (ulong)struct_mem;
}
void * fd_clock_timestamp_votes_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_clock_timestamp_votes_global_t * self = (fd_clock_timestamp_votes_global_t *)mem;
  fd_clock_timestamp_votes_new( (fd_clock_timestamp_votes_t *)self );
  void * alloc_region = (uchar *)mem + sizeof(fd_clock_timestamp_votes_global_t);
  void * * alloc_mem = &alloc_region;
  fd_clock_timestamp_votes_decode_inner_global( mem, alloc_mem, ctx );
  return self;
}
void fd_clock_timestamp_votes_new(fd_clock_timestamp_votes_t * self) {
  fd_memset( self, 0, sizeof(fd_clock_timestamp_votes_t) );
}
void fd_clock_timestamp_votes_walk( void * w, fd_clock_timestamp_votes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_clock_timestamp_votes", level++, 0 );
  if( self->votes_root ) {
    for( fd_clock_timestamp_vote_t_mapnode_t * n = fd_clock_timestamp_vote_t_map_minimum(self->votes_pool, self->votes_root ); n; n = fd_clock_timestamp_vote_t_map_successor( self->votes_pool, n ) ) {
      fd_clock_timestamp_vote_walk(w, &n->elem, fun, "votes", level, 0 );
    }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_clock_timestamp_votes", level--, 0 );
}
ulong fd_clock_timestamp_votes_size( fd_clock_timestamp_votes_t const * self ) {
  ulong size = 0;
  if( self->votes_root ) {
    size += sizeof(ulong);
    ulong max = fd_clock_timestamp_vote_t_map_max( self->votes_pool );
    size += fd_clock_timestamp_vote_t_map_footprint( max );
    for( fd_clock_timestamp_vote_t_mapnode_t * n = fd_clock_timestamp_vote_t_map_minimum( self->votes_pool, self->votes_root ); n; n = fd_clock_timestamp_vote_t_map_successor( self->votes_pool, n ) ) {
      size += fd_clock_timestamp_vote_size( &n->elem ) - sizeof(fd_clock_timestamp_vote_t);
    }
  } else {
    size += sizeof(ulong);
  }
  return size;
}

ulong fd_clock_timestamp_votes_size_global( fd_clock_timestamp_votes_global_t const * self ) {
  ulong size = 0;
  fd_clock_timestamp_vote_t_mapnode_t * votes_pool = !!self->votes_pool_offset ? (fd_clock_timestamp_vote_t_mapnode_t *)fd_clock_timestamp_vote_t_map_join( fd_type_pun( (uchar *)self + self->votes_pool_offset ) ) : NULL;
  fd_clock_timestamp_vote_t_mapnode_t * votes_root = !!self->votes_root_offset ? (fd_clock_timestamp_vote_t_mapnode_t *)fd_type_pun( (uchar *)self + self->votes_root_offset ) : NULL;
  if( votes_root ) {
    size += sizeof(ulong);
    ulong max = fd_clock_timestamp_vote_t_map_max( votes_pool );
    size += fd_clock_timestamp_vote_t_map_footprint( max );
    for( fd_clock_timestamp_vote_t_mapnode_t * n = fd_clock_timestamp_vote_t_map_minimum( votes_pool, votes_root ); n; n = fd_clock_timestamp_vote_t_map_successor( votes_pool, n ) ) {
      size += fd_clock_timestamp_vote_size( &n->elem ) - sizeof(fd_clock_timestamp_vote_t);
    }
  } else {
    size += sizeof(ulong);
  }
  return size;
}

int fd_sysvar_fees_encode( fd_sysvar_fees_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_fee_calculator_encode( &self->fee_calculator, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_sysvar_fees_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 8UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 8UL );
  return 0;
}
static void fd_sysvar_fees_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_sysvar_fees_t * self = (fd_sysvar_fees_t *)struct_mem;
  fd_fee_calculator_decode_inner( &self->fee_calculator, alloc_mem, ctx );
}
void * fd_sysvar_fees_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_sysvar_fees_t * self = (fd_sysvar_fees_t *)mem;
  fd_sysvar_fees_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_sysvar_fees_t);
  void * * alloc_mem = &alloc_region;
  fd_sysvar_fees_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_sysvar_fees_walk( void * w, fd_sysvar_fees_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_sysvar_fees", level++, 0 );
  fd_fee_calculator_walk( w, &self->fee_calculator, fun, "fee_calculator", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_sysvar_fees", level--, 0 );
}
int fd_sysvar_epoch_rewards_encode( fd_sysvar_epoch_rewards_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->distribution_starting_block_height, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->num_partitions, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_hash_encode( &self->parent_blockhash, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint128_encode( self->total_points, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->total_rewards, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->distributed_rewards, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_encode( (uchar)(self->active), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_sysvar_epoch_rewards_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_hash_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint128_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_bool_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_sysvar_epoch_rewards_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_sysvar_epoch_rewards_t);
  void const * start_data = ctx->data;
  int err = fd_sysvar_epoch_rewards_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_sysvar_epoch_rewards_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_sysvar_epoch_rewards_t * self = (fd_sysvar_epoch_rewards_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->distribution_starting_block_height, ctx );
  fd_bincode_uint64_decode_unsafe( &self->num_partitions, ctx );
  fd_hash_decode_inner( &self->parent_blockhash, alloc_mem, ctx );
  fd_bincode_uint128_decode_unsafe( &self->total_points, ctx );
  fd_bincode_uint64_decode_unsafe( &self->total_rewards, ctx );
  fd_bincode_uint64_decode_unsafe( &self->distributed_rewards, ctx );
  fd_bincode_bool_decode_unsafe( &self->active, ctx );
}
void * fd_sysvar_epoch_rewards_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_sysvar_epoch_rewards_t * self = (fd_sysvar_epoch_rewards_t *)mem;
  fd_sysvar_epoch_rewards_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_sysvar_epoch_rewards_t);
  void * * alloc_mem = &alloc_region;
  fd_sysvar_epoch_rewards_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_sysvar_epoch_rewards_new(fd_sysvar_epoch_rewards_t * self) {
  fd_memset( self, 0, sizeof(fd_sysvar_epoch_rewards_t) );
  fd_hash_new( &self->parent_blockhash );
}
void fd_sysvar_epoch_rewards_walk( void * w, fd_sysvar_epoch_rewards_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_sysvar_epoch_rewards", level++, 0 );
  fun( w, &self->distribution_starting_block_height, "distribution_starting_block_height", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->num_partitions, "num_partitions", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_hash_walk( w, &self->parent_blockhash, fun, "parent_blockhash", level, 0 );
  fun( w, &self->total_points, "total_points", FD_FLAMENCO_TYPE_UINT128, "uint128", level, 0  );
  fun( w, &self->total_rewards, "total_rewards", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->distributed_rewards, "distributed_rewards", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->active, "active", FD_FLAMENCO_TYPE_BOOL, "bool", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_sysvar_epoch_rewards", level--, 0 );
}
int fd_config_keys_pair_encode( fd_config_keys_pair_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->key, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_encode( (uchar)(self->signer), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_config_keys_pair_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_config_keys_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_config_keys_pair_t);
  void const * start_data = ctx->data;
  int err = fd_config_keys_pair_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_config_keys_pair_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_config_keys_pair_t * self = (fd_config_keys_pair_t *)struct_mem;
  fd_pubkey_decode_inner( &self->key, alloc_mem, ctx );
  fd_bincode_bool_decode_unsafe( &self->signer, ctx );
}
void * fd_config_keys_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_config_keys_pair_t * self = (fd_config_keys_pair_t *)mem;
  fd_config_keys_pair_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_config_keys_pair_t);
  void * * alloc_mem = &alloc_region;
  fd_config_keys_pair_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_config_keys_pair_new(fd_config_keys_pair_t * self) {
  fd_memset( self, 0, sizeof(fd_config_keys_pair_t) );
  fd_pubkey_new( &self->key );
}
void fd_config_keys_pair_walk( void * w, fd_config_keys_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_config_keys_pair", level++, 0 );
  fd_pubkey_walk( w, &self->key, fun, "key", level, 0 );
  fun( w, &self->signer, "signer", FD_FLAMENCO_TYPE_BOOL, "bool", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_config_keys_pair", level--, 0 );
}
int fd_stake_config_encode( fd_stake_config_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_compact_u16_encode( &self->config_keys_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->config_keys_len ) {
    for( ulong i=0; i < self->config_keys_len; i++ ) {
      err = fd_config_keys_pair_encode( self->config_keys + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  err = fd_bincode_double_encode( self->warmup_cooldown_rate, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->slash_penalty), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_stake_config_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ushort config_keys_len;
  err = fd_bincode_compact_u16_decode( &config_keys_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( config_keys_len ) {
    *total_sz += FD_CONFIG_KEYS_PAIR_ALIGN + sizeof(fd_config_keys_pair_t)*config_keys_len;
    for( ulong i=0; i < config_keys_len; i++ ) {
      err = fd_config_keys_pair_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_double_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_stake_config_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_config_t);
  void const * start_data = ctx->data;
  int err = fd_stake_config_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_stake_config_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_config_t * self = (fd_stake_config_t *)struct_mem;
  fd_bincode_compact_u16_decode_unsafe( &self->config_keys_len, ctx );
  if( self->config_keys_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_CONFIG_KEYS_PAIR_ALIGN );
    self->config_keys = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_config_keys_pair_t)*self->config_keys_len;
    for( ulong i=0; i < self->config_keys_len; i++ ) {
      fd_config_keys_pair_new( self->config_keys + i );
      fd_config_keys_pair_decode_inner( self->config_keys + i, alloc_mem, ctx );
    }
  } else
    self->config_keys = NULL;
  fd_bincode_double_decode_unsafe( &self->warmup_cooldown_rate, ctx );
  fd_bincode_uint8_decode_unsafe( &self->slash_penalty, ctx );
}
void * fd_stake_config_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_config_t * self = (fd_stake_config_t *)mem;
  fd_stake_config_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_stake_config_t);
  void * * alloc_mem = &alloc_region;
  fd_stake_config_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_stake_config_new(fd_stake_config_t * self) {
  fd_memset( self, 0, sizeof(fd_stake_config_t) );
}
void fd_stake_config_walk( void * w, fd_stake_config_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_config", level++, 0 );
  fun( w, &self->config_keys_len, "config_keys_len", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 1 );
  if( self->config_keys_len ) {
    fun( w, NULL, "config_keys", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->config_keys_len; i++ )
      fd_config_keys_pair_walk(w, self->config_keys + i, fun, "config_keys_pair", level, 0 );
    fun( w, NULL, "config_keys", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, &self->warmup_cooldown_rate, "warmup_cooldown_rate", FD_FLAMENCO_TYPE_DOUBLE, "double", level, 0  );
  fun( w, &self->slash_penalty, "slash_penalty", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_config", level--, 0 );
}
ulong fd_stake_config_size( fd_stake_config_t const * self ) {
  ulong size = 0;
  do {
    ushort tmp = (ushort)self->config_keys_len;
    size += fd_bincode_compact_u16_size( &tmp );
    for( ulong i=0; i < self->config_keys_len; i++ )
      size += fd_config_keys_pair_size( self->config_keys + i );
  } while(0);
  size += sizeof(double);
  size += sizeof(char);
  return size;
}

int fd_feature_entry_encode( fd_feature_entry_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->description_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->description_len ) {
    err = fd_bincode_bytes_encode( self->description, self->description_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint64_encode( self->since_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_feature_entry_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ulong description_len;
  err = fd_bincode_uint64_decode( &description_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  *total_sz += description_len;
  if( description_len ) {
    err = fd_bincode_bytes_decode_footprint( description_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    err = !fd_utf8_verify( (char const *) ctx->data - description_len, description_len );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_feature_entry_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_feature_entry_t);
  void const * start_data = ctx->data;
  int err = fd_feature_entry_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_feature_entry_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_feature_entry_t * self = (fd_feature_entry_t *)struct_mem;
  fd_pubkey_decode_inner( &self->pubkey, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->description_len, ctx );
  if( self->description_len ) {
    self->description = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->description, self->description_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->description_len;
  } else
    self->description = NULL;
  fd_bincode_uint64_decode_unsafe( &self->since_slot, ctx );
}
void * fd_feature_entry_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_feature_entry_t * self = (fd_feature_entry_t *)mem;
  fd_feature_entry_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_feature_entry_t);
  void * * alloc_mem = &alloc_region;
  fd_feature_entry_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_feature_entry_new(fd_feature_entry_t * self) {
  fd_memset( self, 0, sizeof(fd_feature_entry_t) );
  fd_pubkey_new( &self->pubkey );
}
void fd_feature_entry_walk( void * w, fd_feature_entry_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_feature_entry", level++, 0 );
  fd_pubkey_walk( w, &self->pubkey, fun, "pubkey", level, 0 );
  if( self->description_len ) {
    fun( w, NULL, "description", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->description_len; i++ )
      fun( w, self->description + i, "description", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "description", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, &self->since_slot, "since_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_feature_entry", level--, 0 );
}
ulong fd_feature_entry_size( fd_feature_entry_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->pubkey );
  do {
    size += sizeof(ulong);
    size += self->description_len;
  } while(0);
  size += sizeof(ulong);
  return size;
}

FD_FN_PURE uchar fd_cluster_type_is_Testnet(fd_cluster_type_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_cluster_type_is_MainnetBeta(fd_cluster_type_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_cluster_type_is_Devnet(fd_cluster_type_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_cluster_type_is_Development(fd_cluster_type_t const * self) {
  return self->discriminant == 3;
}
int fd_cluster_type_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
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
static int fd_cluster_type_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_cluster_type_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_cluster_type_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_cluster_type_t);
  void const * start_data = ctx->data;
  int err =  fd_cluster_type_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_cluster_type_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_cluster_type_t * self = (fd_cluster_type_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
}
void * fd_cluster_type_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_cluster_type_t * self = (fd_cluster_type_t *)mem;
  fd_cluster_type_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_cluster_type_t);
  void * * alloc_mem = &alloc_region;
  fd_cluster_type_decode_inner( mem, alloc_mem, ctx );
  return self;
}

void fd_cluster_type_walk( void * w, fd_cluster_type_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_cluster_type", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "Testnet", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "MainnetBeta", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 2: {
    fun( w, self, "Devnet", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 3: {
    fun( w, self, "Development", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_cluster_type", level--, 0 );
}
ulong fd_cluster_type_size( fd_cluster_type_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  }
  return size;
}

int fd_cluster_type_encode( fd_cluster_type_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return err;
}

int fd_cluster_version_encode( fd_cluster_version_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint32_encode( self->major, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint32_encode( self->minor, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint32_encode( self->patch, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_cluster_version_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 12UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 12UL );
  return 0;
}
static void fd_cluster_version_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_cluster_version_t * self = (fd_cluster_version_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->major, ctx );
  fd_bincode_uint32_decode_unsafe( &self->minor, ctx );
  fd_bincode_uint32_decode_unsafe( &self->patch, ctx );
}
void * fd_cluster_version_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_cluster_version_t * self = (fd_cluster_version_t *)mem;
  fd_cluster_version_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_cluster_version_t);
  void * * alloc_mem = &alloc_region;
  fd_cluster_version_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_cluster_version_walk( void * w, fd_cluster_version_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_cluster_version", level++, 0 );
  fun( w, &self->major, "major", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, &self->minor, "minor", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, &self->patch, "patch", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_cluster_version", level--, 0 );
}
int fd_stake_reward_encode( fd_stake_reward_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->stake_pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->credits_observed, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->lamports, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->valid), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_stake_reward_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 49UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 49UL );
  return 0;
}
static void fd_stake_reward_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_reward_t * self = (fd_stake_reward_t *)struct_mem;
  fd_pubkey_decode_inner( &self->stake_pubkey, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->credits_observed, ctx );
  fd_bincode_uint64_decode_unsafe( &self->lamports, ctx );
  fd_bincode_uint8_decode_unsafe( &self->valid, ctx );
}
void * fd_stake_reward_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_reward_t * self = (fd_stake_reward_t *)mem;
  fd_stake_reward_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_stake_reward_t);
  void * * alloc_mem = &alloc_region;
  fd_stake_reward_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_stake_reward_walk( void * w, fd_stake_reward_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_reward", level++, 0 );
  fd_pubkey_walk( w, &self->stake_pubkey, fun, "stake_pubkey", level, 0 );
  fun( w, &self->credits_observed, "credits_observed", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->lamports, "lamports", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->valid, "valid", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_reward", level--, 0 );
}
int fd_vote_reward_encode( fd_vote_reward_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->vote_rewards, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->commission), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->needs_store), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_vote_reward_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 42UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 42UL );
  return 0;
}
static void fd_vote_reward_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_reward_t * self = (fd_vote_reward_t *)struct_mem;
  fd_pubkey_decode_inner( &self->pubkey, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->vote_rewards, ctx );
  fd_bincode_uint8_decode_unsafe( &self->commission, ctx );
  fd_bincode_uint8_decode_unsafe( &self->needs_store, ctx );
}
void * fd_vote_reward_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_reward_t * self = (fd_vote_reward_t *)mem;
  fd_vote_reward_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_reward_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_reward_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_reward_walk( void * w, fd_vote_reward_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_reward", level++, 0 );
  fd_pubkey_walk( w, &self->pubkey, fun, "pubkey", level, 0 );
  fun( w, &self->vote_rewards, "vote_rewards", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->commission, "commission", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fun( w, &self->needs_store, "needs_store", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_reward", level--, 0 );
}
int fd_point_value_encode( fd_point_value_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->rewards, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint128_encode( self->points, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_point_value_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 24UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 24UL );
  return 0;
}
static void fd_point_value_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_point_value_t * self = (fd_point_value_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->rewards, ctx );
  fd_bincode_uint128_decode_unsafe( &self->points, ctx );
}
void * fd_point_value_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_point_value_t * self = (fd_point_value_t *)mem;
  fd_point_value_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_point_value_t);
  void * * alloc_mem = &alloc_region;
  fd_point_value_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_point_value_walk( void * w, fd_point_value_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_point_value", level++, 0 );
  fun( w, &self->rewards, "rewards", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->points, "points", FD_FLAMENCO_TYPE_UINT128, "uint128", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_point_value", level--, 0 );
}
int fd_partitioned_stake_rewards_encode( fd_partitioned_stake_rewards_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  if( self->partitions ) {
    err = fd_bincode_uint64_encode( self->partitions_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( ulong i=0; i < 4096; i++ ) {
      err = fd_bincode_uint64_encode( self->partitions_lengths[ i ], ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
    for( ulong i=0; i < self->partitions_len; i++ ) {
      for( fd_partitioned_stake_rewards_dlist_iter_t iter = fd_partitioned_stake_rewards_dlist_iter_fwd_init( &self->partitions[ i ], self->pool );
           !fd_partitioned_stake_rewards_dlist_iter_done( iter, &self->partitions[ i ], self->pool );
           iter = fd_partitioned_stake_rewards_dlist_iter_fwd_next( iter, &self->partitions[ i ], self->pool ) ) {
        fd_stake_reward_t * ele = fd_partitioned_stake_rewards_dlist_iter_ele( iter, &self->partitions[ i ], self->pool );
        err = fd_stake_reward_encode( ele, ctx );
        if( FD_UNLIKELY( err ) ) return err;
      }
    }
  } else {
    err = fd_bincode_uint64_encode( self->partitions_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
int fd_partitioned_stake_rewards_encode_global( fd_partitioned_stake_rewards_global_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  return FD_BINCODE_SUCCESS;
}
static int fd_partitioned_stake_rewards_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ulong partitions_len;
  err = fd_bincode_uint64_decode( &partitions_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong total_count = 0UL;
  ulong partitions_lengths[4096];
  for( ulong i=0; i<4096; i++ ) {
    err = fd_bincode_uint64_decode( partitions_lengths + i, ctx );
    total_count+=partitions_lengths[ i ];
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  *total_sz += fd_partitioned_stake_rewards_pool_align() + fd_partitioned_stake_rewards_pool_footprint( total_count );
  *total_sz += fd_partitioned_stake_rewards_dlist_align() + fd_partitioned_stake_rewards_dlist_footprint()*partitions_len;
  for( ulong i=0; i < partitions_len; i++ ) {
    err = fd_stake_reward_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY ( err ) ) return err;
  }
  return 0;
}
int fd_partitioned_stake_rewards_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_partitioned_stake_rewards_t);
  void const * start_data = ctx->data;
  int err = fd_partitioned_stake_rewards_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_partitioned_stake_rewards_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_partitioned_stake_rewards_t * self = (fd_partitioned_stake_rewards_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->partitions_len, ctx );
  ulong total_count = 0UL;
  for( ulong i=0; i < 4096; i++ ) {
    fd_bincode_uint64_decode_unsafe( self->partitions_lengths + i, ctx );
    total_count += self->partitions_lengths[ i ];
  }
  self->pool = fd_partitioned_stake_rewards_pool_join_new( alloc_mem, total_count );
  self->partitions = fd_partitioned_stake_rewards_dlist_join_new( alloc_mem, self->partitions_len );
  for( ulong i=0; i < self->partitions_len; i++ ) {
    fd_partitioned_stake_rewards_dlist_new( &self->partitions[ i ] );
    for( ulong j=0; j < self->partitions_lengths[ i ]; j++ ) {
      fd_stake_reward_t * ele = fd_partitioned_stake_rewards_pool_ele_acquire( self->pool );
      fd_stake_reward_new( ele );
      fd_stake_reward_decode_inner( ele, alloc_mem, ctx );
      fd_partitioned_stake_rewards_dlist_ele_push_tail( &self->partitions[ i ], ele, self->pool );
    }
  }
}
void * fd_partitioned_stake_rewards_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_partitioned_stake_rewards_t * self = (fd_partitioned_stake_rewards_t *)mem;
  fd_partitioned_stake_rewards_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_partitioned_stake_rewards_t);
  void * * alloc_mem = &alloc_region;
  fd_partitioned_stake_rewards_decode_inner( mem, alloc_mem, ctx );
  return self;
}
static void fd_partitioned_stake_rewards_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_partitioned_stake_rewards_global_t * self = (fd_partitioned_stake_rewards_global_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->partitions_len, ctx );
  ulong total_count = 0UL;
  for( ulong i=0; i < 4096; i++ ) {
    fd_bincode_uint64_decode_unsafe( self->partitions_lengths + i, ctx );
    total_count += self->partitions_lengths[ i ];
  }
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_partitioned_stake_rewards_pool_align() );
  fd_stake_reward_t * pool = fd_partitioned_stake_rewards_pool_join_new( alloc_mem, total_count );
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, fd_partitioned_stake_rewards_dlist_align() );
  fd_partitioned_stake_rewards_dlist_t * partitions = fd_partitioned_stake_rewards_dlist_join_new( alloc_mem, self->partitions_len );
  for( ulong i=0; i < self->partitions_len; i++ ) {
    fd_partitioned_stake_rewards_dlist_new( &partitions[ i ] );
    for( ulong j=0; j < self->partitions_lengths[ i ]; j++ ) {
      fd_stake_reward_t * ele = fd_partitioned_stake_rewards_pool_ele_acquire( pool );
      fd_stake_reward_new( ele );
      fd_stake_reward_decode_inner( ele, alloc_mem, ctx );
      fd_partitioned_stake_rewards_dlist_ele_push_tail( &partitions[ i ], ele, pool );
    }
  }
  self->pool_offset  = (ulong)fd_partitioned_stake_rewards_pool_leave( pool ) - (ulong)struct_mem;
  self->partitions_offset = (ulong)fd_partitioned_stake_rewards_dlist_leave( partitions ) - (ulong)struct_mem;
}
void * fd_partitioned_stake_rewards_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_partitioned_stake_rewards_global_t * self = (fd_partitioned_stake_rewards_global_t *)mem;
  fd_partitioned_stake_rewards_new( (fd_partitioned_stake_rewards_t *)self );
  void * alloc_region = (uchar *)mem + sizeof(fd_partitioned_stake_rewards_global_t);
  void * * alloc_mem = &alloc_region;
  fd_partitioned_stake_rewards_decode_inner_global( mem, alloc_mem, ctx );
  return self;
}
void fd_partitioned_stake_rewards_new(fd_partitioned_stake_rewards_t * self) {
  fd_memset( self, 0, sizeof(fd_partitioned_stake_rewards_t) );
}
void fd_partitioned_stake_rewards_walk( void * w, fd_partitioned_stake_rewards_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_partitioned_stake_rewards", level++, 0 );
  if( self->partitions ) {
  for( ulong i=0; i < self->partitions_len; i++ ) {
      for( fd_partitioned_stake_rewards_dlist_iter_t iter = fd_partitioned_stake_rewards_dlist_iter_fwd_init( &self->partitions[ i ], self->pool );
             !fd_partitioned_stake_rewards_dlist_iter_done( iter, &self->partitions[ i ], self->pool );
             iter = fd_partitioned_stake_rewards_dlist_iter_fwd_next( iter, &self->partitions[ i ], self->pool ) ) {
          fd_stake_reward_t * ele = fd_partitioned_stake_rewards_dlist_iter_ele( iter, &self->partitions[ i ], self->pool );
        fd_stake_reward_walk( w, ele, fun, "fd_stake_reward_t", level, 0 );
      }
    }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_partitioned_stake_rewards", level--, 0 );
}
ulong fd_partitioned_stake_rewards_size( fd_partitioned_stake_rewards_t const * self ) {
  ulong size = 0;
  size += sizeof(ulong);
  size += 4096 * sizeof(ulong);
  if( self->partitions ) {
  for( ulong i=0; i < self->partitions_len; i++ ) {
      for( fd_partitioned_stake_rewards_dlist_iter_t iter = fd_partitioned_stake_rewards_dlist_iter_fwd_init( &self->partitions[ i ], self->pool );
           !fd_partitioned_stake_rewards_dlist_iter_done( iter, &self->partitions[ i ], self->pool );
           iter = fd_partitioned_stake_rewards_dlist_iter_fwd_next( iter, &self->partitions[ i ], self->pool ) ) {
        fd_stake_reward_t * ele = fd_partitioned_stake_rewards_dlist_iter_ele( iter, &self->partitions[ i ], self->pool );
        size += fd_stake_reward_size( ele );
      }
    }
  }
  return size;
}

ulong fd_partitioned_stake_rewards_size_global( fd_partitioned_stake_rewards_global_t const * self ) {
  ulong size = 0;
  FD_LOG_CRIT(( "FIXME: not implemented" ));
  return size;
}

int fd_stake_reward_calculation_partitioned_encode( fd_stake_reward_calculation_partitioned_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_partitioned_stake_rewards_encode( &self->partitioned_stake_rewards, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->total_stake_rewards_lamports, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_stake_reward_calculation_partitioned_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_partitioned_stake_rewards_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_stake_reward_calculation_partitioned_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_reward_calculation_partitioned_t);
  void const * start_data = ctx->data;
  int err = fd_stake_reward_calculation_partitioned_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_stake_reward_calculation_partitioned_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_reward_calculation_partitioned_t * self = (fd_stake_reward_calculation_partitioned_t *)struct_mem;
  fd_partitioned_stake_rewards_decode_inner( &self->partitioned_stake_rewards, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->total_stake_rewards_lamports, ctx );
}
void * fd_stake_reward_calculation_partitioned_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_reward_calculation_partitioned_t * self = (fd_stake_reward_calculation_partitioned_t *)mem;
  fd_stake_reward_calculation_partitioned_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_stake_reward_calculation_partitioned_t);
  void * * alloc_mem = &alloc_region;
  fd_stake_reward_calculation_partitioned_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_stake_reward_calculation_partitioned_new(fd_stake_reward_calculation_partitioned_t * self) {
  fd_memset( self, 0, sizeof(fd_stake_reward_calculation_partitioned_t) );
  fd_partitioned_stake_rewards_new( &self->partitioned_stake_rewards );
}
void fd_stake_reward_calculation_partitioned_walk( void * w, fd_stake_reward_calculation_partitioned_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_reward_calculation_partitioned", level++, 0 );
  fd_partitioned_stake_rewards_walk( w, &self->partitioned_stake_rewards, fun, "partitioned_stake_rewards", level, 0 );
  fun( w, &self->total_stake_rewards_lamports, "total_stake_rewards_lamports", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_reward_calculation_partitioned", level--, 0 );
}
ulong fd_stake_reward_calculation_partitioned_size( fd_stake_reward_calculation_partitioned_t const * self ) {
  ulong size = 0;
  size += fd_partitioned_stake_rewards_size( &self->partitioned_stake_rewards );
  size += sizeof(ulong);
  return size;
}

int fd_stake_reward_calculation_encode( fd_stake_reward_calculation_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  if( self->stake_rewards ) {
    err = fd_bincode_uint64_encode( self->stake_rewards_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( fd_stake_reward_calculation_dlist_iter_t iter = fd_stake_reward_calculation_dlist_iter_fwd_init( self->stake_rewards, self->pool );
         !fd_stake_reward_calculation_dlist_iter_done( iter, self->stake_rewards, self->pool );
         iter = fd_stake_reward_calculation_dlist_iter_fwd_next( iter, self->stake_rewards, self->pool ) ) {
      fd_stake_reward_t * ele = fd_stake_reward_calculation_dlist_iter_ele( iter, self->stake_rewards, self->pool );
      err = fd_stake_reward_encode( ele, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  } else {
    err = fd_bincode_uint64_encode( self->stake_rewards_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint64_encode( self->total_stake_rewards_lamports, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_stake_reward_calculation_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ulong stake_rewards_len;
  err = fd_bincode_uint64_decode( &stake_rewards_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  *total_sz += fd_stake_reward_calculation_pool_align() + fd_stake_reward_calculation_pool_footprint( stake_rewards_len );
  *total_sz += fd_stake_reward_calculation_dlist_align() + fd_stake_reward_calculation_dlist_footprint()*stake_rewards_len;
  for( ulong i=0; i < stake_rewards_len; i++ ) {
    err = fd_stake_reward_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY ( err ) ) return err;
  }
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_stake_reward_calculation_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_reward_calculation_t);
  void const * start_data = ctx->data;
  int err = fd_stake_reward_calculation_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_stake_reward_calculation_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_reward_calculation_t * self = (fd_stake_reward_calculation_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->stake_rewards_len, ctx );
  self->pool = fd_stake_reward_calculation_pool_join_new( alloc_mem, self->stake_rewards_len );
  self->stake_rewards = fd_stake_reward_calculation_dlist_join_new( alloc_mem, self->stake_rewards_len );
  fd_stake_reward_calculation_dlist_new( self->stake_rewards );
  for( ulong i=0; i < self->stake_rewards_len; i++ ) {
    fd_stake_reward_t * ele = fd_stake_reward_calculation_pool_ele_acquire( self->pool );
    fd_stake_reward_new( ele );
    fd_stake_reward_decode_inner( ele, alloc_mem, ctx );
    fd_stake_reward_calculation_dlist_ele_push_tail( self->stake_rewards, ele, self->pool );
  }
  fd_bincode_uint64_decode_unsafe( &self->total_stake_rewards_lamports, ctx );
}
void * fd_stake_reward_calculation_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_reward_calculation_t * self = (fd_stake_reward_calculation_t *)mem;
  fd_stake_reward_calculation_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_stake_reward_calculation_t);
  void * * alloc_mem = &alloc_region;
  fd_stake_reward_calculation_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_stake_reward_calculation_new(fd_stake_reward_calculation_t * self) {
  fd_memset( self, 0, sizeof(fd_stake_reward_calculation_t) );
}
void fd_stake_reward_calculation_walk( void * w, fd_stake_reward_calculation_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_reward_calculation", level++, 0 );
  if( self->stake_rewards ) {
    for( fd_stake_reward_calculation_dlist_iter_t iter = fd_stake_reward_calculation_dlist_iter_fwd_init( self->stake_rewards, self->pool );
           !fd_stake_reward_calculation_dlist_iter_done( iter, self->stake_rewards, self->pool );
           iter = fd_stake_reward_calculation_dlist_iter_fwd_next( iter, self->stake_rewards, self->pool ) ) {
        fd_stake_reward_t * ele = fd_stake_reward_calculation_dlist_iter_ele( iter, self->stake_rewards, self->pool );
      fd_stake_reward_walk( w, ele, fun, "fd_stake_reward_t", level, 0 );
    }
  }
  fun( w, &self->total_stake_rewards_lamports, "total_stake_rewards_lamports", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_reward_calculation", level--, 0 );
}
ulong fd_stake_reward_calculation_size( fd_stake_reward_calculation_t const * self ) {
  ulong size = 0;
  size += sizeof(ulong);
  if( self->stake_rewards ) {
    for( fd_stake_reward_calculation_dlist_iter_t iter = fd_stake_reward_calculation_dlist_iter_fwd_init( self->stake_rewards, self->pool );
         !fd_stake_reward_calculation_dlist_iter_done( iter, self->stake_rewards, self->pool );
         iter = fd_stake_reward_calculation_dlist_iter_fwd_next( iter, self->stake_rewards, self->pool ) ) {
      fd_stake_reward_t * ele = fd_stake_reward_calculation_dlist_iter_ele( iter, self->stake_rewards, self->pool );
      size += fd_stake_reward_size( ele );
    }
  }
  size += sizeof(ulong);
  return size;
}

int fd_calculate_stake_vote_rewards_result_encode( fd_calculate_stake_vote_rewards_result_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_stake_reward_calculation_encode( &self->stake_reward_calculation, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->vote_reward_map_root ) {
    ulong vote_reward_map_len = fd_vote_reward_t_map_size( self->vote_reward_map_pool, self->vote_reward_map_root );
    err = fd_bincode_uint64_encode( vote_reward_map_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( fd_vote_reward_t_mapnode_t * n = fd_vote_reward_t_map_minimum( self->vote_reward_map_pool, self->vote_reward_map_root ); n; n = fd_vote_reward_t_map_successor( self->vote_reward_map_pool, n ) ) {
      err = fd_vote_reward_encode( &n->elem, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  } else {
    ulong vote_reward_map_len = 0;
    err = fd_bincode_uint64_encode( vote_reward_map_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_calculate_stake_vote_rewards_result_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_stake_reward_calculation_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ulong vote_reward_map_len = 0UL;
  err = fd_bincode_uint64_decode( &vote_reward_map_len, ctx );
  ulong vote_reward_map_cnt = fd_ulong_max( vote_reward_map_len, 15000 );
  *total_sz += fd_vote_reward_t_map_align() + fd_vote_reward_t_map_footprint( vote_reward_map_cnt );
  if( FD_UNLIKELY( err ) ) return err;
  for( ulong i=0; i < vote_reward_map_len; i++ ) {
    err = fd_vote_reward_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return 0;
}
int fd_calculate_stake_vote_rewards_result_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_calculate_stake_vote_rewards_result_t);
  void const * start_data = ctx->data;
  int err = fd_calculate_stake_vote_rewards_result_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_calculate_stake_vote_rewards_result_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_calculate_stake_vote_rewards_result_t * self = (fd_calculate_stake_vote_rewards_result_t *)struct_mem;
  fd_stake_reward_calculation_decode_inner( &self->stake_reward_calculation, alloc_mem, ctx );
  ulong vote_reward_map_len;
  fd_bincode_uint64_decode_unsafe( &vote_reward_map_len, ctx );
  self->vote_reward_map_pool = fd_vote_reward_t_map_join_new( alloc_mem, fd_ulong_max( vote_reward_map_len, 15000 ) );
  self->vote_reward_map_root = NULL;
  for( ulong i=0; i < vote_reward_map_len; i++ ) {
    fd_vote_reward_t_mapnode_t * node = fd_vote_reward_t_map_acquire( self->vote_reward_map_pool );
    fd_vote_reward_new( &node->elem );
    fd_vote_reward_decode_inner( &node->elem, alloc_mem, ctx );
    fd_vote_reward_t_mapnode_t * out = NULL;;
    fd_vote_reward_t_map_insert_or_replace( self->vote_reward_map_pool, &self->vote_reward_map_root, node, &out );
    if( out != NULL ) {
      fd_vote_reward_t_map_release( self->vote_reward_map_pool, out );
    }
  }
}
void * fd_calculate_stake_vote_rewards_result_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_calculate_stake_vote_rewards_result_t * self = (fd_calculate_stake_vote_rewards_result_t *)mem;
  fd_calculate_stake_vote_rewards_result_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_calculate_stake_vote_rewards_result_t);
  void * * alloc_mem = &alloc_region;
  fd_calculate_stake_vote_rewards_result_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_calculate_stake_vote_rewards_result_new(fd_calculate_stake_vote_rewards_result_t * self) {
  fd_memset( self, 0, sizeof(fd_calculate_stake_vote_rewards_result_t) );
  fd_stake_reward_calculation_new( &self->stake_reward_calculation );
}
void fd_calculate_stake_vote_rewards_result_walk( void * w, fd_calculate_stake_vote_rewards_result_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_calculate_stake_vote_rewards_result", level++, 0 );
  fd_stake_reward_calculation_walk( w, &self->stake_reward_calculation, fun, "stake_reward_calculation", level, 0 );
  if( self->vote_reward_map_root ) {
    for( fd_vote_reward_t_mapnode_t * n = fd_vote_reward_t_map_minimum(self->vote_reward_map_pool, self->vote_reward_map_root ); n; n = fd_vote_reward_t_map_successor( self->vote_reward_map_pool, n ) ) {
      fd_vote_reward_walk(w, &n->elem, fun, "vote_reward_map", level, 0 );
    }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_calculate_stake_vote_rewards_result", level--, 0 );
}
ulong fd_calculate_stake_vote_rewards_result_size( fd_calculate_stake_vote_rewards_result_t const * self ) {
  ulong size = 0;
  size += fd_stake_reward_calculation_size( &self->stake_reward_calculation );
  if( self->vote_reward_map_root ) {
    size += sizeof(ulong);
    ulong max = fd_vote_reward_t_map_max( self->vote_reward_map_pool );
    size += fd_vote_reward_t_map_footprint( max );
    for( fd_vote_reward_t_mapnode_t * n = fd_vote_reward_t_map_minimum( self->vote_reward_map_pool, self->vote_reward_map_root ); n; n = fd_vote_reward_t_map_successor( self->vote_reward_map_pool, n ) ) {
      size += fd_vote_reward_size( &n->elem ) - sizeof(fd_vote_reward_t);
    }
  } else {
    size += sizeof(ulong);
  }
  return size;
}

int fd_calculate_validator_rewards_result_encode( fd_calculate_validator_rewards_result_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_calculate_stake_vote_rewards_result_encode( &self->calculate_stake_vote_rewards_result, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_point_value_encode( &self->point_value, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_calculate_validator_rewards_result_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_calculate_stake_vote_rewards_result_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_point_value_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_calculate_validator_rewards_result_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_calculate_validator_rewards_result_t);
  void const * start_data = ctx->data;
  int err = fd_calculate_validator_rewards_result_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_calculate_validator_rewards_result_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_calculate_validator_rewards_result_t * self = (fd_calculate_validator_rewards_result_t *)struct_mem;
  fd_calculate_stake_vote_rewards_result_decode_inner( &self->calculate_stake_vote_rewards_result, alloc_mem, ctx );
  fd_point_value_decode_inner( &self->point_value, alloc_mem, ctx );
}
void * fd_calculate_validator_rewards_result_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_calculate_validator_rewards_result_t * self = (fd_calculate_validator_rewards_result_t *)mem;
  fd_calculate_validator_rewards_result_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_calculate_validator_rewards_result_t);
  void * * alloc_mem = &alloc_region;
  fd_calculate_validator_rewards_result_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_calculate_validator_rewards_result_new(fd_calculate_validator_rewards_result_t * self) {
  fd_memset( self, 0, sizeof(fd_calculate_validator_rewards_result_t) );
  fd_calculate_stake_vote_rewards_result_new( &self->calculate_stake_vote_rewards_result );
  fd_point_value_new( &self->point_value );
}
void fd_calculate_validator_rewards_result_walk( void * w, fd_calculate_validator_rewards_result_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_calculate_validator_rewards_result", level++, 0 );
  fd_calculate_stake_vote_rewards_result_walk( w, &self->calculate_stake_vote_rewards_result, fun, "calculate_stake_vote_rewards_result", level, 0 );
  fd_point_value_walk( w, &self->point_value, fun, "point_value", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_calculate_validator_rewards_result", level--, 0 );
}
ulong fd_calculate_validator_rewards_result_size( fd_calculate_validator_rewards_result_t const * self ) {
  ulong size = 0;
  size += fd_calculate_stake_vote_rewards_result_size( &self->calculate_stake_vote_rewards_result );
  size += fd_point_value_size( &self->point_value );
  return size;
}

int fd_partitioned_rewards_calculation_encode( fd_partitioned_rewards_calculation_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  if( self->vote_reward_map_root ) {
    ulong vote_reward_map_len = fd_vote_reward_t_map_size( self->vote_reward_map_pool, self->vote_reward_map_root );
    err = fd_bincode_uint64_encode( vote_reward_map_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( fd_vote_reward_t_mapnode_t * n = fd_vote_reward_t_map_minimum( self->vote_reward_map_pool, self->vote_reward_map_root ); n; n = fd_vote_reward_t_map_successor( self->vote_reward_map_pool, n ) ) {
      err = fd_vote_reward_encode( &n->elem, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  } else {
    ulong vote_reward_map_len = 0;
    err = fd_bincode_uint64_encode( vote_reward_map_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_stake_reward_calculation_partitioned_encode( &self->stake_rewards_by_partition, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->old_vote_balance_and_staked, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->validator_rewards, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_double_encode( self->validator_rate, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_double_encode( self->foundation_rate, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_double_encode( self->prev_epoch_duration_in_years, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->capitalization, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_point_value_encode( &self->point_value, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_partitioned_rewards_calculation_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ulong vote_reward_map_len = 0UL;
  err = fd_bincode_uint64_decode( &vote_reward_map_len, ctx );
  ulong vote_reward_map_cnt = fd_ulong_max( vote_reward_map_len, 15000 );
  *total_sz += fd_vote_reward_t_map_align() + fd_vote_reward_t_map_footprint( vote_reward_map_cnt );
  if( FD_UNLIKELY( err ) ) return err;
  for( ulong i=0; i < vote_reward_map_len; i++ ) {
    err = fd_vote_reward_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_stake_reward_calculation_partitioned_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_double_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_double_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_double_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_point_value_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_partitioned_rewards_calculation_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_partitioned_rewards_calculation_t);
  void const * start_data = ctx->data;
  int err = fd_partitioned_rewards_calculation_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_partitioned_rewards_calculation_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_partitioned_rewards_calculation_t * self = (fd_partitioned_rewards_calculation_t *)struct_mem;
  ulong vote_reward_map_len;
  fd_bincode_uint64_decode_unsafe( &vote_reward_map_len, ctx );
  self->vote_reward_map_pool = fd_vote_reward_t_map_join_new( alloc_mem, fd_ulong_max( vote_reward_map_len, 15000 ) );
  self->vote_reward_map_root = NULL;
  for( ulong i=0; i < vote_reward_map_len; i++ ) {
    fd_vote_reward_t_mapnode_t * node = fd_vote_reward_t_map_acquire( self->vote_reward_map_pool );
    fd_vote_reward_new( &node->elem );
    fd_vote_reward_decode_inner( &node->elem, alloc_mem, ctx );
    fd_vote_reward_t_mapnode_t * out = NULL;;
    fd_vote_reward_t_map_insert_or_replace( self->vote_reward_map_pool, &self->vote_reward_map_root, node, &out );
    if( out != NULL ) {
      fd_vote_reward_t_map_release( self->vote_reward_map_pool, out );
    }
  }
  fd_stake_reward_calculation_partitioned_decode_inner( &self->stake_rewards_by_partition, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->old_vote_balance_and_staked, ctx );
  fd_bincode_uint64_decode_unsafe( &self->validator_rewards, ctx );
  fd_bincode_double_decode_unsafe( &self->validator_rate, ctx );
  fd_bincode_double_decode_unsafe( &self->foundation_rate, ctx );
  fd_bincode_double_decode_unsafe( &self->prev_epoch_duration_in_years, ctx );
  fd_bincode_uint64_decode_unsafe( &self->capitalization, ctx );
  fd_point_value_decode_inner( &self->point_value, alloc_mem, ctx );
}
void * fd_partitioned_rewards_calculation_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_partitioned_rewards_calculation_t * self = (fd_partitioned_rewards_calculation_t *)mem;
  fd_partitioned_rewards_calculation_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_partitioned_rewards_calculation_t);
  void * * alloc_mem = &alloc_region;
  fd_partitioned_rewards_calculation_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_partitioned_rewards_calculation_new(fd_partitioned_rewards_calculation_t * self) {
  fd_memset( self, 0, sizeof(fd_partitioned_rewards_calculation_t) );
  fd_stake_reward_calculation_partitioned_new( &self->stake_rewards_by_partition );
  fd_point_value_new( &self->point_value );
}
void fd_partitioned_rewards_calculation_walk( void * w, fd_partitioned_rewards_calculation_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_partitioned_rewards_calculation", level++, 0 );
  if( self->vote_reward_map_root ) {
    for( fd_vote_reward_t_mapnode_t * n = fd_vote_reward_t_map_minimum(self->vote_reward_map_pool, self->vote_reward_map_root ); n; n = fd_vote_reward_t_map_successor( self->vote_reward_map_pool, n ) ) {
      fd_vote_reward_walk(w, &n->elem, fun, "vote_reward_map", level, 0 );
    }
  }
  fd_stake_reward_calculation_partitioned_walk( w, &self->stake_rewards_by_partition, fun, "stake_rewards_by_partition", level, 0 );
  fun( w, &self->old_vote_balance_and_staked, "old_vote_balance_and_staked", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->validator_rewards, "validator_rewards", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->validator_rate, "validator_rate", FD_FLAMENCO_TYPE_DOUBLE, "double", level, 0  );
  fun( w, &self->foundation_rate, "foundation_rate", FD_FLAMENCO_TYPE_DOUBLE, "double", level, 0  );
  fun( w, &self->prev_epoch_duration_in_years, "prev_epoch_duration_in_years", FD_FLAMENCO_TYPE_DOUBLE, "double", level, 0  );
  fun( w, &self->capitalization, "capitalization", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_point_value_walk( w, &self->point_value, fun, "point_value", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_partitioned_rewards_calculation", level--, 0 );
}
ulong fd_partitioned_rewards_calculation_size( fd_partitioned_rewards_calculation_t const * self ) {
  ulong size = 0;
  if( self->vote_reward_map_root ) {
    size += sizeof(ulong);
    ulong max = fd_vote_reward_t_map_max( self->vote_reward_map_pool );
    size += fd_vote_reward_t_map_footprint( max );
    for( fd_vote_reward_t_mapnode_t * n = fd_vote_reward_t_map_minimum( self->vote_reward_map_pool, self->vote_reward_map_root ); n; n = fd_vote_reward_t_map_successor( self->vote_reward_map_pool, n ) ) {
      size += fd_vote_reward_size( &n->elem ) - sizeof(fd_vote_reward_t);
    }
  } else {
    size += sizeof(ulong);
  }
  size += fd_stake_reward_calculation_partitioned_size( &self->stake_rewards_by_partition );
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(double);
  size += sizeof(double);
  size += sizeof(double);
  size += sizeof(ulong);
  size += fd_point_value_size( &self->point_value );
  return size;
}

int fd_start_block_height_and_rewards_encode( fd_start_block_height_and_rewards_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->distribution_starting_block_height, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_partitioned_stake_rewards_encode( &self->partitioned_stake_rewards, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
int fd_start_block_height_and_rewards_encode_global( fd_start_block_height_and_rewards_global_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->distribution_starting_block_height, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_partitioned_stake_rewards_encode_global( &self->partitioned_stake_rewards, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_start_block_height_and_rewards_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_partitioned_stake_rewards_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_start_block_height_and_rewards_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_start_block_height_and_rewards_t);
  void const * start_data = ctx->data;
  int err = fd_start_block_height_and_rewards_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_start_block_height_and_rewards_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_start_block_height_and_rewards_t * self = (fd_start_block_height_and_rewards_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->distribution_starting_block_height, ctx );
  fd_partitioned_stake_rewards_decode_inner( &self->partitioned_stake_rewards, alloc_mem, ctx );
}
void * fd_start_block_height_and_rewards_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_start_block_height_and_rewards_t * self = (fd_start_block_height_and_rewards_t *)mem;
  fd_start_block_height_and_rewards_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_start_block_height_and_rewards_t);
  void * * alloc_mem = &alloc_region;
  fd_start_block_height_and_rewards_decode_inner( mem, alloc_mem, ctx );
  return self;
}
static void fd_start_block_height_and_rewards_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_start_block_height_and_rewards_global_t * self = (fd_start_block_height_and_rewards_global_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->distribution_starting_block_height, ctx );
  fd_partitioned_stake_rewards_decode_inner_global( &self->partitioned_stake_rewards, alloc_mem, ctx );
}
void * fd_start_block_height_and_rewards_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_start_block_height_and_rewards_global_t * self = (fd_start_block_height_and_rewards_global_t *)mem;
  fd_start_block_height_and_rewards_new( (fd_start_block_height_and_rewards_t *)self );
  void * alloc_region = (uchar *)mem + sizeof(fd_start_block_height_and_rewards_global_t);
  void * * alloc_mem = &alloc_region;
  fd_start_block_height_and_rewards_decode_inner_global( mem, alloc_mem, ctx );
  return self;
}
void fd_start_block_height_and_rewards_new(fd_start_block_height_and_rewards_t * self) {
  fd_memset( self, 0, sizeof(fd_start_block_height_and_rewards_t) );
  fd_partitioned_stake_rewards_new( &self->partitioned_stake_rewards );
}
void fd_start_block_height_and_rewards_walk( void * w, fd_start_block_height_and_rewards_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_start_block_height_and_rewards", level++, 0 );
  fun( w, &self->distribution_starting_block_height, "distribution_starting_block_height", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_partitioned_stake_rewards_walk( w, &self->partitioned_stake_rewards, fun, "partitioned_stake_rewards", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_start_block_height_and_rewards", level--, 0 );
}
ulong fd_start_block_height_and_rewards_size( fd_start_block_height_and_rewards_t const * self ) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_partitioned_stake_rewards_size( &self->partitioned_stake_rewards );
  return size;
}

ulong fd_start_block_height_and_rewards_size_global( fd_start_block_height_and_rewards_global_t const * self ) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_partitioned_stake_rewards_size_global( &self->partitioned_stake_rewards );
  return size;
}

int fd_fd_epoch_reward_status_inner_encode( fd_fd_epoch_reward_status_inner_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_start_block_height_and_rewards_encode( &self->Active, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_fd_epoch_reward_status_inner_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_start_block_height_and_rewards_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_fd_epoch_reward_status_inner_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_fd_epoch_reward_status_inner_t);
  void const * start_data = ctx->data;
  int err = fd_fd_epoch_reward_status_inner_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_fd_epoch_reward_status_inner_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_fd_epoch_reward_status_inner_t * self = (fd_fd_epoch_reward_status_inner_t *)struct_mem;
  fd_start_block_height_and_rewards_decode_inner( &self->Active, alloc_mem, ctx );
}
void * fd_fd_epoch_reward_status_inner_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_fd_epoch_reward_status_inner_t * self = (fd_fd_epoch_reward_status_inner_t *)mem;
  fd_fd_epoch_reward_status_inner_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_fd_epoch_reward_status_inner_t);
  void * * alloc_mem = &alloc_region;
  fd_fd_epoch_reward_status_inner_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_fd_epoch_reward_status_inner_new(fd_fd_epoch_reward_status_inner_t * self) {
  fd_memset( self, 0, sizeof(fd_fd_epoch_reward_status_inner_t) );
  fd_start_block_height_and_rewards_new( &self->Active );
}
void fd_fd_epoch_reward_status_inner_walk( void * w, fd_fd_epoch_reward_status_inner_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_fd_epoch_reward_status_inner", level++, 0 );
  fd_start_block_height_and_rewards_walk( w, &self->Active, fun, "Active", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_fd_epoch_reward_status_inner", level--, 0 );
}
ulong fd_fd_epoch_reward_status_inner_size( fd_fd_epoch_reward_status_inner_t const * self ) {
  ulong size = 0;
  size += fd_start_block_height_and_rewards_size( &self->Active );
  return size;
}

FD_FN_PURE uchar fd_epoch_reward_status_is_Active(fd_epoch_reward_status_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_epoch_reward_status_is_Inactive(fd_epoch_reward_status_t const * self) {
  return self->discriminant == 1;
}
void fd_epoch_reward_status_inner_new( fd_epoch_reward_status_inner_t * self, uint discriminant );
int fd_epoch_reward_status_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_start_block_height_and_rewards_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_epoch_reward_status_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_epoch_reward_status_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_epoch_reward_status_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_epoch_reward_status_t);
  void const * start_data = ctx->data;
  int err =  fd_epoch_reward_status_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_epoch_reward_status_inner_decode_inner( fd_epoch_reward_status_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    fd_start_block_height_and_rewards_decode_inner( &self->Active, alloc_mem, ctx );
    break;
  }
  case 1: {
    break;
  }
  }
}
static void fd_epoch_reward_status_inner_decode_inner_global( fd_epoch_reward_status_inner_global_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    fd_start_block_height_and_rewards_decode_inner_global( &self->Active, alloc_mem, ctx );
    break;
  }
  case 1: {
    break;
  }
  }
}
static void fd_epoch_reward_status_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_epoch_reward_status_t * self = (fd_epoch_reward_status_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_epoch_reward_status_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_epoch_reward_status_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_epoch_reward_status_t * self = (fd_epoch_reward_status_t *)mem;
  fd_epoch_reward_status_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_epoch_reward_status_t);
  void * * alloc_mem = &alloc_region;
  fd_epoch_reward_status_decode_inner( mem, alloc_mem, ctx );
  return self;
}
static int fd_epoch_reward_status_inner_encode_global( fd_epoch_reward_status_inner_global_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_start_block_height_and_rewards_encode_global( &self->Active, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_epoch_reward_status_encode_global( fd_epoch_reward_status_global_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_epoch_reward_status_inner_encode_global( &self->inner, self->discriminant, ctx );
}

static void fd_epoch_reward_status_decode_inner_global( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_epoch_reward_status_global_t * self = (fd_epoch_reward_status_global_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_epoch_reward_status_inner_decode_inner_global( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_epoch_reward_status_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_epoch_reward_status_t * self = (fd_epoch_reward_status_t *)mem;
  fd_epoch_reward_status_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_epoch_reward_status_t);
  void * * alloc_mem = &alloc_region;
  fd_epoch_reward_status_decode_inner_global( mem, alloc_mem, ctx );
  return self;
}
void fd_epoch_reward_status_inner_new( fd_epoch_reward_status_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    fd_start_block_height_and_rewards_new( &self->Active );
    break;
  }
  case 1: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_epoch_reward_status_new_disc( fd_epoch_reward_status_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_epoch_reward_status_inner_new( &self->inner, self->discriminant );
}
void fd_epoch_reward_status_new( fd_epoch_reward_status_t * self ) {
  fd_memset( self, 0, sizeof(fd_epoch_reward_status_t) );
  fd_epoch_reward_status_new_disc( self, UINT_MAX );
}

void fd_epoch_reward_status_walk( void * w, fd_epoch_reward_status_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_epoch_reward_status", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "Active", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_start_block_height_and_rewards_walk( w, &self->inner.Active, fun, "Active", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "Inactive", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_epoch_reward_status", level--, 0 );
}
ulong fd_epoch_reward_status_size( fd_epoch_reward_status_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_start_block_height_and_rewards_size( &self->inner.Active );
    break;
  }
  }
  return size;
}

ulong fd_epoch_reward_status_size_global( fd_epoch_reward_status_global_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_start_block_height_and_rewards_size_global( &self->inner.Active );
    break;
  }
  }
  return size;
}

int fd_epoch_reward_status_inner_encode( fd_epoch_reward_status_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_start_block_height_and_rewards_encode( &self->Active, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_epoch_reward_status_encode( fd_epoch_reward_status_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_epoch_reward_status_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_prev_epoch_inflation_rewards_encode( fd_prev_epoch_inflation_rewards_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->validator_rewards, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_double_encode( self->prev_epoch_duration_in_years, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_double_encode( self->validator_rate, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_double_encode( self->foundation_rate, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_prev_epoch_inflation_rewards_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 32UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 32UL );
  return 0;
}
static void fd_prev_epoch_inflation_rewards_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_prev_epoch_inflation_rewards_t * self = (fd_prev_epoch_inflation_rewards_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->validator_rewards, ctx );
  fd_bincode_double_decode_unsafe( &self->prev_epoch_duration_in_years, ctx );
  fd_bincode_double_decode_unsafe( &self->validator_rate, ctx );
  fd_bincode_double_decode_unsafe( &self->foundation_rate, ctx );
}
void * fd_prev_epoch_inflation_rewards_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_prev_epoch_inflation_rewards_t * self = (fd_prev_epoch_inflation_rewards_t *)mem;
  fd_prev_epoch_inflation_rewards_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_prev_epoch_inflation_rewards_t);
  void * * alloc_mem = &alloc_region;
  fd_prev_epoch_inflation_rewards_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_prev_epoch_inflation_rewards_walk( void * w, fd_prev_epoch_inflation_rewards_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_prev_epoch_inflation_rewards", level++, 0 );
  fun( w, &self->validator_rewards, "validator_rewards", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->prev_epoch_duration_in_years, "prev_epoch_duration_in_years", FD_FLAMENCO_TYPE_DOUBLE, "double", level, 0  );
  fun( w, &self->validator_rate, "validator_rate", FD_FLAMENCO_TYPE_DOUBLE, "double", level, 0  );
  fun( w, &self->foundation_rate, "foundation_rate", FD_FLAMENCO_TYPE_DOUBLE, "double", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_prev_epoch_inflation_rewards", level--, 0 );
}
int fd_vote_encode( fd_vote_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  if( self->slots ) {
    ulong slots_len = deq_ulong_cnt( self->slots );
    err = fd_bincode_uint64_encode( slots_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( deq_ulong_iter_t iter = deq_ulong_iter_init( self->slots ); !deq_ulong_iter_done( self->slots, iter ); iter = deq_ulong_iter_next( self->slots, iter ) ) {
      ulong const * ele = deq_ulong_iter_ele_const( self->slots, iter );
      err = fd_bincode_uint64_encode( ele[0], ctx );
    }
  } else {
    ulong slots_len = 0;
    err = fd_bincode_uint64_encode( slots_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_hash_encode( &self->hash, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_encode( self->has_timestamp, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_timestamp ) {
    err = fd_bincode_int64_encode( self->timestamp, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_vote_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ulong slots_len;
  err = fd_bincode_uint64_decode( &slots_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong slots_max = slots_len == 0 ? 1 : slots_len;
  *total_sz += deq_ulong_align() + deq_ulong_footprint( slots_max ) ;
  ulong slots_sz;
  if( FD_UNLIKELY( __builtin_umull_overflow( slots_len, 8, &slots_sz ) ) ) return FD_BINCODE_ERR_UNDERFLOW;
  err = fd_bincode_bytes_decode_footprint( slots_sz, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_hash_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_int64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_vote_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_t);
  void const * start_data = ctx->data;
  int err = fd_vote_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_vote_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_t * self = (fd_vote_t *)struct_mem;
  ulong slots_len;
  fd_bincode_uint64_decode_unsafe( &slots_len, ctx );
  self->slots = deq_ulong_join_new( alloc_mem, slots_len );
  for( ulong i=0; i < slots_len; i++ ) {
    ulong * elem = deq_ulong_push_tail_nocopy( self->slots );
    fd_bincode_uint64_decode_unsafe( elem, ctx );
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
}
void * fd_vote_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_t * self = (fd_vote_t *)mem;
  fd_vote_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_new(fd_vote_t * self) {
  fd_memset( self, 0, sizeof(fd_vote_t) );
  fd_hash_new( &self->hash );
}
void fd_vote_walk( void * w, fd_vote_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote", level++, 0 );

  /* Walk deque */
  fun( w, self->slots, "slots", FD_FLAMENCO_TYPE_ARR, "slots", level++, 0 );
  if( self->slots ) {
    for( deq_ulong_iter_t iter = deq_ulong_iter_init( self->slots );
         !deq_ulong_iter_done( self->slots, iter );
         iter = deq_ulong_iter_next( self->slots, iter ) ) {
      ulong * ele = deq_ulong_iter_ele( self->slots, iter );
      fun(w, ele, "ele", FD_FLAMENCO_TYPE_ULONG, "long",  level, 0 );
    }
  }
  fun( w, self->slots, "slots", FD_FLAMENCO_TYPE_ARR_END, "slots", level--, 0 );
  /* Done walking deque */

  fd_hash_walk( w, &self->hash, fun, "hash", level, 0 );
  if( !self->has_timestamp ) {
    fun( w, NULL, "timestamp", FD_FLAMENCO_TYPE_NULL, "long", level, 0 );
  } else {
    fun( w, &self->timestamp, "timestamp", FD_FLAMENCO_TYPE_SLONG, "long", level, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote", level--, 0 );
}
ulong fd_vote_size( fd_vote_t const * self ) {
  ulong size = 0;
  if( self->slots ) {
    size += sizeof(ulong);
    ulong slots_len = deq_ulong_cnt(self->slots);
    size += slots_len * sizeof(ulong);
  } else {
    size += sizeof(ulong);
  }
  size += fd_hash_size( &self->hash );
  size += sizeof(char);
  if( self->has_timestamp ) {
    size += sizeof(long);
  }
  return size;
}

int fd_vote_init_encode( fd_vote_init_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->node_pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->authorized_voter, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->authorized_withdrawer, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->commission), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_vote_init_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 97UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 97UL );
  return 0;
}
static void fd_vote_init_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_init_t * self = (fd_vote_init_t *)struct_mem;
  fd_pubkey_decode_inner( &self->node_pubkey, alloc_mem, ctx );
  fd_pubkey_decode_inner( &self->authorized_voter, alloc_mem, ctx );
  fd_pubkey_decode_inner( &self->authorized_withdrawer, alloc_mem, ctx );
  fd_bincode_uint8_decode_unsafe( &self->commission, ctx );
}
void * fd_vote_init_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_init_t * self = (fd_vote_init_t *)mem;
  fd_vote_init_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_init_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_init_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_init_walk( void * w, fd_vote_init_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_init", level++, 0 );
  fd_pubkey_walk( w, &self->node_pubkey, fun, "node_pubkey", level, 0 );
  fd_pubkey_walk( w, &self->authorized_voter, fun, "authorized_voter", level, 0 );
  fd_pubkey_walk( w, &self->authorized_withdrawer, fun, "authorized_withdrawer", level, 0 );
  fun( w, &self->commission, "commission", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_init", level--, 0 );
}
FD_FN_PURE uchar fd_vote_authorize_is_voter(fd_vote_authorize_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_vote_authorize_is_withdrawer(fd_vote_authorize_t const * self) {
  return self->discriminant == 1;
}
int fd_vote_authorize_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
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
static int fd_vote_authorize_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_vote_authorize_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_vote_authorize_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_authorize_t);
  void const * start_data = ctx->data;
  int err =  fd_vote_authorize_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_vote_authorize_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_authorize_t * self = (fd_vote_authorize_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
}
void * fd_vote_authorize_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_authorize_t * self = (fd_vote_authorize_t *)mem;
  fd_vote_authorize_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_authorize_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_authorize_decode_inner( mem, alloc_mem, ctx );
  return self;
}

void fd_vote_authorize_walk( void * w, fd_vote_authorize_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_vote_authorize", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "voter", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "withdrawer", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_vote_authorize", level--, 0 );
}
ulong fd_vote_authorize_size( fd_vote_authorize_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  }
  return size;
}

int fd_vote_authorize_encode( fd_vote_authorize_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return err;
}

int fd_vote_authorize_pubkey_encode( fd_vote_authorize_pubkey_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_vote_authorize_encode( &self->vote_authorize, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_vote_authorize_pubkey_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_vote_authorize_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_vote_authorize_pubkey_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_authorize_pubkey_t);
  void const * start_data = ctx->data;
  int err = fd_vote_authorize_pubkey_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_vote_authorize_pubkey_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_authorize_pubkey_t * self = (fd_vote_authorize_pubkey_t *)struct_mem;
  fd_pubkey_decode_inner( &self->pubkey, alloc_mem, ctx );
  fd_vote_authorize_decode_inner( &self->vote_authorize, alloc_mem, ctx );
}
void * fd_vote_authorize_pubkey_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_authorize_pubkey_t * self = (fd_vote_authorize_pubkey_t *)mem;
  fd_vote_authorize_pubkey_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_authorize_pubkey_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_authorize_pubkey_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_authorize_pubkey_new(fd_vote_authorize_pubkey_t * self) {
  fd_memset( self, 0, sizeof(fd_vote_authorize_pubkey_t) );
  fd_pubkey_new( &self->pubkey );
  fd_vote_authorize_new( &self->vote_authorize );
}
void fd_vote_authorize_pubkey_walk( void * w, fd_vote_authorize_pubkey_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_authorize_pubkey", level++, 0 );
  fd_pubkey_walk( w, &self->pubkey, fun, "pubkey", level, 0 );
  fd_vote_authorize_walk( w, &self->vote_authorize, fun, "vote_authorize", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_authorize_pubkey", level--, 0 );
}
int fd_vote_switch_encode( fd_vote_switch_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_vote_encode( &self->vote, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_hash_encode( &self->hash, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_vote_switch_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_vote_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_hash_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_vote_switch_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_switch_t);
  void const * start_data = ctx->data;
  int err = fd_vote_switch_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_vote_switch_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_switch_t * self = (fd_vote_switch_t *)struct_mem;
  fd_vote_decode_inner( &self->vote, alloc_mem, ctx );
  fd_hash_decode_inner( &self->hash, alloc_mem, ctx );
}
void * fd_vote_switch_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_switch_t * self = (fd_vote_switch_t *)mem;
  fd_vote_switch_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_switch_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_switch_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_switch_new(fd_vote_switch_t * self) {
  fd_memset( self, 0, sizeof(fd_vote_switch_t) );
  fd_vote_new( &self->vote );
  fd_hash_new( &self->hash );
}
void fd_vote_switch_walk( void * w, fd_vote_switch_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_switch", level++, 0 );
  fd_vote_walk( w, &self->vote, fun, "vote", level, 0 );
  fd_hash_walk( w, &self->hash, fun, "hash", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_switch", level--, 0 );
}
ulong fd_vote_switch_size( fd_vote_switch_t const * self ) {
  ulong size = 0;
  size += fd_vote_size( &self->vote );
  size += fd_hash_size( &self->hash );
  return size;
}

int fd_update_vote_state_switch_encode( fd_update_vote_state_switch_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_vote_state_update_encode( &self->vote_state_update, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_hash_encode( &self->hash, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_update_vote_state_switch_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_vote_state_update_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_hash_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_update_vote_state_switch_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_update_vote_state_switch_t);
  void const * start_data = ctx->data;
  int err = fd_update_vote_state_switch_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_update_vote_state_switch_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_update_vote_state_switch_t * self = (fd_update_vote_state_switch_t *)struct_mem;
  fd_vote_state_update_decode_inner( &self->vote_state_update, alloc_mem, ctx );
  fd_hash_decode_inner( &self->hash, alloc_mem, ctx );
}
void * fd_update_vote_state_switch_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_update_vote_state_switch_t * self = (fd_update_vote_state_switch_t *)mem;
  fd_update_vote_state_switch_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_update_vote_state_switch_t);
  void * * alloc_mem = &alloc_region;
  fd_update_vote_state_switch_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_update_vote_state_switch_new(fd_update_vote_state_switch_t * self) {
  fd_memset( self, 0, sizeof(fd_update_vote_state_switch_t) );
  fd_vote_state_update_new( &self->vote_state_update );
  fd_hash_new( &self->hash );
}
void fd_update_vote_state_switch_walk( void * w, fd_update_vote_state_switch_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_update_vote_state_switch", level++, 0 );
  fd_vote_state_update_walk( w, &self->vote_state_update, fun, "vote_state_update", level, 0 );
  fd_hash_walk( w, &self->hash, fun, "hash", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_update_vote_state_switch", level--, 0 );
}
ulong fd_update_vote_state_switch_size( fd_update_vote_state_switch_t const * self ) {
  ulong size = 0;
  size += fd_vote_state_update_size( &self->vote_state_update );
  size += fd_hash_size( &self->hash );
  return size;
}

int fd_vote_authorize_with_seed_args_encode( fd_vote_authorize_with_seed_args_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_vote_authorize_encode( &self->authorization_type, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->current_authority_derived_key_owner, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->current_authority_derived_key_seed_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->current_authority_derived_key_seed_len ) {
    err = fd_bincode_bytes_encode( self->current_authority_derived_key_seed, self->current_authority_derived_key_seed_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_pubkey_encode( &self->new_authority, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_vote_authorize_with_seed_args_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_vote_authorize_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ulong current_authority_derived_key_seed_len;
  err = fd_bincode_uint64_decode( &current_authority_derived_key_seed_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  *total_sz += current_authority_derived_key_seed_len;
  if( current_authority_derived_key_seed_len ) {
    err = fd_bincode_bytes_decode_footprint( current_authority_derived_key_seed_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    err = !fd_utf8_verify( (char const *) ctx->data - current_authority_derived_key_seed_len, current_authority_derived_key_seed_len );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_vote_authorize_with_seed_args_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_authorize_with_seed_args_t);
  void const * start_data = ctx->data;
  int err = fd_vote_authorize_with_seed_args_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_vote_authorize_with_seed_args_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_authorize_with_seed_args_t * self = (fd_vote_authorize_with_seed_args_t *)struct_mem;
  fd_vote_authorize_decode_inner( &self->authorization_type, alloc_mem, ctx );
  fd_pubkey_decode_inner( &self->current_authority_derived_key_owner, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->current_authority_derived_key_seed_len, ctx );
  if( self->current_authority_derived_key_seed_len ) {
    self->current_authority_derived_key_seed = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->current_authority_derived_key_seed, self->current_authority_derived_key_seed_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->current_authority_derived_key_seed_len;
  } else
    self->current_authority_derived_key_seed = NULL;
  fd_pubkey_decode_inner( &self->new_authority, alloc_mem, ctx );
}
void * fd_vote_authorize_with_seed_args_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_authorize_with_seed_args_t * self = (fd_vote_authorize_with_seed_args_t *)mem;
  fd_vote_authorize_with_seed_args_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_authorize_with_seed_args_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_authorize_with_seed_args_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_authorize_with_seed_args_new(fd_vote_authorize_with_seed_args_t * self) {
  fd_memset( self, 0, sizeof(fd_vote_authorize_with_seed_args_t) );
  fd_vote_authorize_new( &self->authorization_type );
  fd_pubkey_new( &self->current_authority_derived_key_owner );
  fd_pubkey_new( &self->new_authority );
}
void fd_vote_authorize_with_seed_args_walk( void * w, fd_vote_authorize_with_seed_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_authorize_with_seed_args", level++, 0 );
  fd_vote_authorize_walk( w, &self->authorization_type, fun, "authorization_type", level, 0 );
  fd_pubkey_walk( w, &self->current_authority_derived_key_owner, fun, "current_authority_derived_key_owner", level, 0 );
  if( self->current_authority_derived_key_seed_len ) {
    fun( w, NULL, "current_authority_derived_key_seed", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->current_authority_derived_key_seed_len; i++ )
      fun( w, self->current_authority_derived_key_seed + i, "current_authority_derived_key_seed", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "current_authority_derived_key_seed", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fd_pubkey_walk( w, &self->new_authority, fun, "new_authority", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_authorize_with_seed_args", level--, 0 );
}
ulong fd_vote_authorize_with_seed_args_size( fd_vote_authorize_with_seed_args_t const * self ) {
  ulong size = 0;
  size += fd_vote_authorize_size( &self->authorization_type );
  size += fd_pubkey_size( &self->current_authority_derived_key_owner );
  do {
    size += sizeof(ulong);
    size += self->current_authority_derived_key_seed_len;
  } while(0);
  size += fd_pubkey_size( &self->new_authority );
  return size;
}

int fd_vote_authorize_checked_with_seed_args_encode( fd_vote_authorize_checked_with_seed_args_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_vote_authorize_encode( &self->authorization_type, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->current_authority_derived_key_owner, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->current_authority_derived_key_seed_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->current_authority_derived_key_seed_len ) {
    err = fd_bincode_bytes_encode( self->current_authority_derived_key_seed, self->current_authority_derived_key_seed_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_vote_authorize_checked_with_seed_args_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_vote_authorize_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ulong current_authority_derived_key_seed_len;
  err = fd_bincode_uint64_decode( &current_authority_derived_key_seed_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  *total_sz += current_authority_derived_key_seed_len;
  if( current_authority_derived_key_seed_len ) {
    err = fd_bincode_bytes_decode_footprint( current_authority_derived_key_seed_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    err = !fd_utf8_verify( (char const *) ctx->data - current_authority_derived_key_seed_len, current_authority_derived_key_seed_len );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return 0;
}
int fd_vote_authorize_checked_with_seed_args_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_authorize_checked_with_seed_args_t);
  void const * start_data = ctx->data;
  int err = fd_vote_authorize_checked_with_seed_args_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_vote_authorize_checked_with_seed_args_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_authorize_checked_with_seed_args_t * self = (fd_vote_authorize_checked_with_seed_args_t *)struct_mem;
  fd_vote_authorize_decode_inner( &self->authorization_type, alloc_mem, ctx );
  fd_pubkey_decode_inner( &self->current_authority_derived_key_owner, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->current_authority_derived_key_seed_len, ctx );
  if( self->current_authority_derived_key_seed_len ) {
    self->current_authority_derived_key_seed = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->current_authority_derived_key_seed, self->current_authority_derived_key_seed_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->current_authority_derived_key_seed_len;
  } else
    self->current_authority_derived_key_seed = NULL;
}
void * fd_vote_authorize_checked_with_seed_args_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_authorize_checked_with_seed_args_t * self = (fd_vote_authorize_checked_with_seed_args_t *)mem;
  fd_vote_authorize_checked_with_seed_args_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_authorize_checked_with_seed_args_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_authorize_checked_with_seed_args_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_authorize_checked_with_seed_args_new(fd_vote_authorize_checked_with_seed_args_t * self) {
  fd_memset( self, 0, sizeof(fd_vote_authorize_checked_with_seed_args_t) );
  fd_vote_authorize_new( &self->authorization_type );
  fd_pubkey_new( &self->current_authority_derived_key_owner );
}
void fd_vote_authorize_checked_with_seed_args_walk( void * w, fd_vote_authorize_checked_with_seed_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_vote_authorize_checked_with_seed_args", level++, 0 );
  fd_vote_authorize_walk( w, &self->authorization_type, fun, "authorization_type", level, 0 );
  fd_pubkey_walk( w, &self->current_authority_derived_key_owner, fun, "current_authority_derived_key_owner", level, 0 );
  if( self->current_authority_derived_key_seed_len ) {
    fun( w, NULL, "current_authority_derived_key_seed", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->current_authority_derived_key_seed_len; i++ )
      fun( w, self->current_authority_derived_key_seed + i, "current_authority_derived_key_seed", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "current_authority_derived_key_seed", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_vote_authorize_checked_with_seed_args", level--, 0 );
}
ulong fd_vote_authorize_checked_with_seed_args_size( fd_vote_authorize_checked_with_seed_args_t const * self ) {
  ulong size = 0;
  size += fd_vote_authorize_size( &self->authorization_type );
  size += fd_pubkey_size( &self->current_authority_derived_key_owner );
  do {
    size += sizeof(ulong);
    size += self->current_authority_derived_key_seed_len;
  } while(0);
  return size;
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
FD_FN_PURE uchar fd_vote_instruction_is_tower_sync(fd_vote_instruction_t const * self) {
  return self->discriminant == 14;
}
FD_FN_PURE uchar fd_vote_instruction_is_tower_sync_switch(fd_vote_instruction_t const * self) {
  return self->discriminant == 15;
}
void fd_vote_instruction_inner_new( fd_vote_instruction_inner_t * self, uint discriminant );
int fd_vote_instruction_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_vote_init_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_vote_authorize_pubkey_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_vote_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    err = fd_bincode_uint64_decode_footprint( ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    return FD_BINCODE_SUCCESS;
  }
  case 5: {
    err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 6: {
    err = fd_vote_switch_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 7: {
    err = fd_vote_authorize_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 8: {
    err = fd_vote_state_update_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 9: {
    err = fd_update_vote_state_switch_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 10: {
    err = fd_vote_authorize_with_seed_args_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 11: {
    err = fd_vote_authorize_checked_with_seed_args_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 12: {
    err = fd_compact_vote_state_update_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 13: {
    err = fd_compact_vote_state_update_switch_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 14: {
    err = fd_tower_sync_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 15: {
    err = fd_tower_sync_switch_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_vote_instruction_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_vote_instruction_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_vote_instruction_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_vote_instruction_t);
  void const * start_data = ctx->data;
  int err =  fd_vote_instruction_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_vote_instruction_inner_decode_inner( fd_vote_instruction_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    fd_vote_init_decode_inner( &self->initialize_account, alloc_mem, ctx );
    break;
  }
  case 1: {
    fd_vote_authorize_pubkey_decode_inner( &self->authorize, alloc_mem, ctx );
    break;
  }
  case 2: {
    fd_vote_decode_inner( &self->vote, alloc_mem, ctx );
    break;
  }
  case 3: {
    fd_bincode_uint64_decode_unsafe( &self->withdraw, ctx );
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    fd_bincode_uint8_decode_unsafe( &self->update_commission, ctx );
    break;
  }
  case 6: {
    fd_vote_switch_decode_inner( &self->vote_switch, alloc_mem, ctx );
    break;
  }
  case 7: {
    fd_vote_authorize_decode_inner( &self->authorize_checked, alloc_mem, ctx );
    break;
  }
  case 8: {
    fd_vote_state_update_decode_inner( &self->update_vote_state, alloc_mem, ctx );
    break;
  }
  case 9: {
    fd_update_vote_state_switch_decode_inner( &self->update_vote_state_switch, alloc_mem, ctx );
    break;
  }
  case 10: {
    fd_vote_authorize_with_seed_args_decode_inner( &self->authorize_with_seed, alloc_mem, ctx );
    break;
  }
  case 11: {
    fd_vote_authorize_checked_with_seed_args_decode_inner( &self->authorize_checked_with_seed, alloc_mem, ctx );
    break;
  }
  case 12: {
    fd_compact_vote_state_update_decode_inner( &self->compact_update_vote_state, alloc_mem, ctx );
    break;
  }
  case 13: {
    fd_compact_vote_state_update_switch_decode_inner( &self->compact_update_vote_state_switch, alloc_mem, ctx );
    break;
  }
  case 14: {
    fd_tower_sync_decode_inner( &self->tower_sync, alloc_mem, ctx );
    break;
  }
  case 15: {
    fd_tower_sync_switch_decode_inner( &self->tower_sync_switch, alloc_mem, ctx );
    break;
  }
  }
}
static void fd_vote_instruction_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_instruction_t * self = (fd_vote_instruction_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_vote_instruction_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_vote_instruction_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_vote_instruction_t * self = (fd_vote_instruction_t *)mem;
  fd_vote_instruction_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_vote_instruction_t);
  void * * alloc_mem = &alloc_region;
  fd_vote_instruction_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_vote_instruction_inner_new( fd_vote_instruction_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    fd_vote_init_new( &self->initialize_account );
    break;
  }
  case 1: {
    fd_vote_authorize_pubkey_new( &self->authorize );
    break;
  }
  case 2: {
    fd_vote_new( &self->vote );
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
    fd_vote_switch_new( &self->vote_switch );
    break;
  }
  case 7: {
    fd_vote_authorize_new( &self->authorize_checked );
    break;
  }
  case 8: {
    fd_vote_state_update_new( &self->update_vote_state );
    break;
  }
  case 9: {
    fd_update_vote_state_switch_new( &self->update_vote_state_switch );
    break;
  }
  case 10: {
    fd_vote_authorize_with_seed_args_new( &self->authorize_with_seed );
    break;
  }
  case 11: {
    fd_vote_authorize_checked_with_seed_args_new( &self->authorize_checked_with_seed );
    break;
  }
  case 12: {
    fd_compact_vote_state_update_new( &self->compact_update_vote_state );
    break;
  }
  case 13: {
    fd_compact_vote_state_update_switch_new( &self->compact_update_vote_state_switch );
    break;
  }
  case 14: {
    fd_tower_sync_new( &self->tower_sync );
    break;
  }
  case 15: {
    fd_tower_sync_switch_new( &self->tower_sync_switch );
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_vote_instruction_new_disc( fd_vote_instruction_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_vote_instruction_inner_new( &self->inner, self->discriminant );
}
void fd_vote_instruction_new( fd_vote_instruction_t * self ) {
  fd_memset( self, 0, sizeof(fd_vote_instruction_t) );
  fd_vote_instruction_new_disc( self, UINT_MAX );
}

void fd_vote_instruction_walk( void * w, fd_vote_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_vote_instruction", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "initialize_account", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_vote_init_walk( w, &self->inner.initialize_account, fun, "initialize_account", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "authorize", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_vote_authorize_pubkey_walk( w, &self->inner.authorize, fun, "authorize", level, 0 );
    break;
  }
  case 2: {
    fun( w, self, "vote", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_vote_walk( w, &self->inner.vote, fun, "vote", level, 0 );
    break;
  }
  case 3: {
    fun( w, self, "withdraw", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
  fun( w, &self->inner.withdraw, "withdraw", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
    break;
  }
  case 4: {
    fun( w, self, "update_validator_identity", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 5: {
    fun( w, self, "update_commission", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
  fun( w, &self->inner.update_commission, "update_commission", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
    break;
  }
  case 6: {
    fun( w, self, "vote_switch", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_vote_switch_walk( w, &self->inner.vote_switch, fun, "vote_switch", level, 0 );
    break;
  }
  case 7: {
    fun( w, self, "authorize_checked", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_vote_authorize_walk( w, &self->inner.authorize_checked, fun, "authorize_checked", level, 0 );
    break;
  }
  case 8: {
    fun( w, self, "update_vote_state", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_vote_state_update_walk( w, &self->inner.update_vote_state, fun, "update_vote_state", level, 0 );
    break;
  }
  case 9: {
    fun( w, self, "update_vote_state_switch", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_update_vote_state_switch_walk( w, &self->inner.update_vote_state_switch, fun, "update_vote_state_switch", level, 0 );
    break;
  }
  case 10: {
    fun( w, self, "authorize_with_seed", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_vote_authorize_with_seed_args_walk( w, &self->inner.authorize_with_seed, fun, "authorize_with_seed", level, 0 );
    break;
  }
  case 11: {
    fun( w, self, "authorize_checked_with_seed", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_vote_authorize_checked_with_seed_args_walk( w, &self->inner.authorize_checked_with_seed, fun, "authorize_checked_with_seed", level, 0 );
    break;
  }
  case 12: {
    fun( w, self, "compact_update_vote_state", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_compact_vote_state_update_walk( w, &self->inner.compact_update_vote_state, fun, "compact_update_vote_state", level, 0 );
    break;
  }
  case 13: {
    fun( w, self, "compact_update_vote_state_switch", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_compact_vote_state_update_switch_walk( w, &self->inner.compact_update_vote_state_switch, fun, "compact_update_vote_state_switch", level, 0 );
    break;
  }
  case 14: {
    fun( w, self, "tower_sync", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_tower_sync_walk( w, &self->inner.tower_sync, fun, "tower_sync", level, 0 );
    break;
  }
  case 15: {
    fun( w, self, "tower_sync_switch", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_tower_sync_switch_walk( w, &self->inner.tower_sync_switch, fun, "tower_sync_switch", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_vote_instruction", level--, 0 );
}
ulong fd_vote_instruction_size( fd_vote_instruction_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_vote_init_size( &self->inner.initialize_account );
    break;
  }
  case 1: {
    size += fd_vote_authorize_pubkey_size( &self->inner.authorize );
    break;
  }
  case 2: {
    size += fd_vote_size( &self->inner.vote );
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
    size += fd_vote_switch_size( &self->inner.vote_switch );
    break;
  }
  case 7: {
    size += fd_vote_authorize_size( &self->inner.authorize_checked );
    break;
  }
  case 8: {
    size += fd_vote_state_update_size( &self->inner.update_vote_state );
    break;
  }
  case 9: {
    size += fd_update_vote_state_switch_size( &self->inner.update_vote_state_switch );
    break;
  }
  case 10: {
    size += fd_vote_authorize_with_seed_args_size( &self->inner.authorize_with_seed );
    break;
  }
  case 11: {
    size += fd_vote_authorize_checked_with_seed_args_size( &self->inner.authorize_checked_with_seed );
    break;
  }
  case 12: {
    size += fd_compact_vote_state_update_size( &self->inner.compact_update_vote_state );
    break;
  }
  case 13: {
    size += fd_compact_vote_state_update_switch_size( &self->inner.compact_update_vote_state_switch );
    break;
  }
  case 14: {
    size += fd_tower_sync_size( &self->inner.tower_sync );
    break;
  }
  case 15: {
    size += fd_tower_sync_switch_size( &self->inner.tower_sync_switch );
    break;
  }
  }
  return size;
}

int fd_vote_instruction_inner_encode( fd_vote_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_vote_init_encode( &self->initialize_account, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 1: {
    err = fd_vote_authorize_pubkey_encode( &self->authorize, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 2: {
    err = fd_vote_encode( &self->vote, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 3: {
    err = fd_bincode_uint64_encode( self->withdraw, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 5: {
    err = fd_bincode_uint8_encode( (uchar)(self->update_commission), ctx );
  if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 6: {
    err = fd_vote_switch_encode( &self->vote_switch, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 7: {
    err = fd_vote_authorize_encode( &self->authorize_checked, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 8: {
    err = fd_vote_state_update_encode( &self->update_vote_state, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 9: {
    err = fd_update_vote_state_switch_encode( &self->update_vote_state_switch, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 10: {
    err = fd_vote_authorize_with_seed_args_encode( &self->authorize_with_seed, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 11: {
    err = fd_vote_authorize_checked_with_seed_args_encode( &self->authorize_checked_with_seed, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 12: {
    err = fd_compact_vote_state_update_encode( &self->compact_update_vote_state, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 13: {
    err = fd_compact_vote_state_update_switch_encode( &self->compact_update_vote_state_switch, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 14: {
    err = fd_tower_sync_encode( &self->tower_sync, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 15: {
    err = fd_tower_sync_switch_encode( &self->tower_sync_switch, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_vote_instruction_encode( fd_vote_instruction_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_vote_instruction_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_system_program_instruction_create_account_encode( fd_system_program_instruction_create_account_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->lamports, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->space, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->owner, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_system_program_instruction_create_account_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 48UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 48UL );
  return 0;
}
static void fd_system_program_instruction_create_account_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_system_program_instruction_create_account_t * self = (fd_system_program_instruction_create_account_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->lamports, ctx );
  fd_bincode_uint64_decode_unsafe( &self->space, ctx );
  fd_pubkey_decode_inner( &self->owner, alloc_mem, ctx );
}
void * fd_system_program_instruction_create_account_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_system_program_instruction_create_account_t * self = (fd_system_program_instruction_create_account_t *)mem;
  fd_system_program_instruction_create_account_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_system_program_instruction_create_account_t);
  void * * alloc_mem = &alloc_region;
  fd_system_program_instruction_create_account_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_system_program_instruction_create_account_walk( void * w, fd_system_program_instruction_create_account_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_system_program_instruction_create_account", level++, 0 );
  fun( w, &self->lamports, "lamports", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->space, "space", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_pubkey_walk( w, &self->owner, fun, "owner", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_system_program_instruction_create_account", level--, 0 );
}
int fd_system_program_instruction_create_account_with_seed_encode( fd_system_program_instruction_create_account_with_seed_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->base, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->seed_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->seed_len ) {
    err = fd_bincode_bytes_encode( self->seed, self->seed_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint64_encode( self->lamports, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->space, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->owner, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_system_program_instruction_create_account_with_seed_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ulong seed_len;
  err = fd_bincode_uint64_decode( &seed_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  *total_sz += seed_len;
  if( seed_len ) {
    err = fd_bincode_bytes_decode_footprint( seed_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    err = !fd_utf8_verify( (char const *) ctx->data - seed_len, seed_len );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_system_program_instruction_create_account_with_seed_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_system_program_instruction_create_account_with_seed_t);
  void const * start_data = ctx->data;
  int err = fd_system_program_instruction_create_account_with_seed_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_system_program_instruction_create_account_with_seed_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_system_program_instruction_create_account_with_seed_t * self = (fd_system_program_instruction_create_account_with_seed_t *)struct_mem;
  fd_pubkey_decode_inner( &self->base, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->seed_len, ctx );
  if( self->seed_len ) {
    self->seed = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->seed, self->seed_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->seed_len;
  } else
    self->seed = NULL;
  fd_bincode_uint64_decode_unsafe( &self->lamports, ctx );
  fd_bincode_uint64_decode_unsafe( &self->space, ctx );
  fd_pubkey_decode_inner( &self->owner, alloc_mem, ctx );
}
void * fd_system_program_instruction_create_account_with_seed_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_system_program_instruction_create_account_with_seed_t * self = (fd_system_program_instruction_create_account_with_seed_t *)mem;
  fd_system_program_instruction_create_account_with_seed_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_system_program_instruction_create_account_with_seed_t);
  void * * alloc_mem = &alloc_region;
  fd_system_program_instruction_create_account_with_seed_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_system_program_instruction_create_account_with_seed_new(fd_system_program_instruction_create_account_with_seed_t * self) {
  fd_memset( self, 0, sizeof(fd_system_program_instruction_create_account_with_seed_t) );
  fd_pubkey_new( &self->base );
  fd_pubkey_new( &self->owner );
}
void fd_system_program_instruction_create_account_with_seed_walk( void * w, fd_system_program_instruction_create_account_with_seed_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_system_program_instruction_create_account_with_seed", level++, 0 );
  fd_pubkey_walk( w, &self->base, fun, "base", level, 0 );
  if( self->seed_len ) {
    fun( w, NULL, "seed", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->seed_len; i++ )
      fun( w, self->seed + i, "seed", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "seed", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, &self->lamports, "lamports", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->space, "space", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_pubkey_walk( w, &self->owner, fun, "owner", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_system_program_instruction_create_account_with_seed", level--, 0 );
}
ulong fd_system_program_instruction_create_account_with_seed_size( fd_system_program_instruction_create_account_with_seed_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->base );
  do {
    size += sizeof(ulong);
    size += self->seed_len;
  } while(0);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_pubkey_size( &self->owner );
  return size;
}

int fd_system_program_instruction_allocate_with_seed_encode( fd_system_program_instruction_allocate_with_seed_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->base, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->seed_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->seed_len ) {
    err = fd_bincode_bytes_encode( self->seed, self->seed_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint64_encode( self->space, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->owner, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_system_program_instruction_allocate_with_seed_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ulong seed_len;
  err = fd_bincode_uint64_decode( &seed_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  *total_sz += seed_len;
  if( seed_len ) {
    err = fd_bincode_bytes_decode_footprint( seed_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    err = !fd_utf8_verify( (char const *) ctx->data - seed_len, seed_len );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_system_program_instruction_allocate_with_seed_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_system_program_instruction_allocate_with_seed_t);
  void const * start_data = ctx->data;
  int err = fd_system_program_instruction_allocate_with_seed_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_system_program_instruction_allocate_with_seed_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_system_program_instruction_allocate_with_seed_t * self = (fd_system_program_instruction_allocate_with_seed_t *)struct_mem;
  fd_pubkey_decode_inner( &self->base, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->seed_len, ctx );
  if( self->seed_len ) {
    self->seed = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->seed, self->seed_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->seed_len;
  } else
    self->seed = NULL;
  fd_bincode_uint64_decode_unsafe( &self->space, ctx );
  fd_pubkey_decode_inner( &self->owner, alloc_mem, ctx );
}
void * fd_system_program_instruction_allocate_with_seed_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_system_program_instruction_allocate_with_seed_t * self = (fd_system_program_instruction_allocate_with_seed_t *)mem;
  fd_system_program_instruction_allocate_with_seed_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_system_program_instruction_allocate_with_seed_t);
  void * * alloc_mem = &alloc_region;
  fd_system_program_instruction_allocate_with_seed_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_system_program_instruction_allocate_with_seed_new(fd_system_program_instruction_allocate_with_seed_t * self) {
  fd_memset( self, 0, sizeof(fd_system_program_instruction_allocate_with_seed_t) );
  fd_pubkey_new( &self->base );
  fd_pubkey_new( &self->owner );
}
void fd_system_program_instruction_allocate_with_seed_walk( void * w, fd_system_program_instruction_allocate_with_seed_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_system_program_instruction_allocate_with_seed", level++, 0 );
  fd_pubkey_walk( w, &self->base, fun, "base", level, 0 );
  if( self->seed_len ) {
    fun( w, NULL, "seed", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->seed_len; i++ )
      fun( w, self->seed + i, "seed", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "seed", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, &self->space, "space", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_pubkey_walk( w, &self->owner, fun, "owner", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_system_program_instruction_allocate_with_seed", level--, 0 );
}
ulong fd_system_program_instruction_allocate_with_seed_size( fd_system_program_instruction_allocate_with_seed_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->base );
  do {
    size += sizeof(ulong);
    size += self->seed_len;
  } while(0);
  size += sizeof(ulong);
  size += fd_pubkey_size( &self->owner );
  return size;
}

int fd_system_program_instruction_assign_with_seed_encode( fd_system_program_instruction_assign_with_seed_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->base, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->seed_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->seed_len ) {
    err = fd_bincode_bytes_encode( self->seed, self->seed_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_pubkey_encode( &self->owner, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_system_program_instruction_assign_with_seed_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ulong seed_len;
  err = fd_bincode_uint64_decode( &seed_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  *total_sz += seed_len;
  if( seed_len ) {
    err = fd_bincode_bytes_decode_footprint( seed_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    err = !fd_utf8_verify( (char const *) ctx->data - seed_len, seed_len );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_system_program_instruction_assign_with_seed_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_system_program_instruction_assign_with_seed_t);
  void const * start_data = ctx->data;
  int err = fd_system_program_instruction_assign_with_seed_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_system_program_instruction_assign_with_seed_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_system_program_instruction_assign_with_seed_t * self = (fd_system_program_instruction_assign_with_seed_t *)struct_mem;
  fd_pubkey_decode_inner( &self->base, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->seed_len, ctx );
  if( self->seed_len ) {
    self->seed = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->seed, self->seed_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->seed_len;
  } else
    self->seed = NULL;
  fd_pubkey_decode_inner( &self->owner, alloc_mem, ctx );
}
void * fd_system_program_instruction_assign_with_seed_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_system_program_instruction_assign_with_seed_t * self = (fd_system_program_instruction_assign_with_seed_t *)mem;
  fd_system_program_instruction_assign_with_seed_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_system_program_instruction_assign_with_seed_t);
  void * * alloc_mem = &alloc_region;
  fd_system_program_instruction_assign_with_seed_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_system_program_instruction_assign_with_seed_new(fd_system_program_instruction_assign_with_seed_t * self) {
  fd_memset( self, 0, sizeof(fd_system_program_instruction_assign_with_seed_t) );
  fd_pubkey_new( &self->base );
  fd_pubkey_new( &self->owner );
}
void fd_system_program_instruction_assign_with_seed_walk( void * w, fd_system_program_instruction_assign_with_seed_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_system_program_instruction_assign_with_seed", level++, 0 );
  fd_pubkey_walk( w, &self->base, fun, "base", level, 0 );
  if( self->seed_len ) {
    fun( w, NULL, "seed", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->seed_len; i++ )
      fun( w, self->seed + i, "seed", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "seed", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fd_pubkey_walk( w, &self->owner, fun, "owner", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_system_program_instruction_assign_with_seed", level--, 0 );
}
ulong fd_system_program_instruction_assign_with_seed_size( fd_system_program_instruction_assign_with_seed_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->base );
  do {
    size += sizeof(ulong);
    size += self->seed_len;
  } while(0);
  size += fd_pubkey_size( &self->owner );
  return size;
}

int fd_system_program_instruction_transfer_with_seed_encode( fd_system_program_instruction_transfer_with_seed_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->lamports, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->from_seed_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->from_seed_len ) {
    err = fd_bincode_bytes_encode( self->from_seed, self->from_seed_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_pubkey_encode( &self->from_owner, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_system_program_instruction_transfer_with_seed_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ulong from_seed_len;
  err = fd_bincode_uint64_decode( &from_seed_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  *total_sz += from_seed_len;
  if( from_seed_len ) {
    err = fd_bincode_bytes_decode_footprint( from_seed_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    err = !fd_utf8_verify( (char const *) ctx->data - from_seed_len, from_seed_len );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_system_program_instruction_transfer_with_seed_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_system_program_instruction_transfer_with_seed_t);
  void const * start_data = ctx->data;
  int err = fd_system_program_instruction_transfer_with_seed_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_system_program_instruction_transfer_with_seed_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_system_program_instruction_transfer_with_seed_t * self = (fd_system_program_instruction_transfer_with_seed_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->lamports, ctx );
  fd_bincode_uint64_decode_unsafe( &self->from_seed_len, ctx );
  if( self->from_seed_len ) {
    self->from_seed = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->from_seed, self->from_seed_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->from_seed_len;
  } else
    self->from_seed = NULL;
  fd_pubkey_decode_inner( &self->from_owner, alloc_mem, ctx );
}
void * fd_system_program_instruction_transfer_with_seed_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_system_program_instruction_transfer_with_seed_t * self = (fd_system_program_instruction_transfer_with_seed_t *)mem;
  fd_system_program_instruction_transfer_with_seed_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_system_program_instruction_transfer_with_seed_t);
  void * * alloc_mem = &alloc_region;
  fd_system_program_instruction_transfer_with_seed_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_system_program_instruction_transfer_with_seed_new(fd_system_program_instruction_transfer_with_seed_t * self) {
  fd_memset( self, 0, sizeof(fd_system_program_instruction_transfer_with_seed_t) );
  fd_pubkey_new( &self->from_owner );
}
void fd_system_program_instruction_transfer_with_seed_walk( void * w, fd_system_program_instruction_transfer_with_seed_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_system_program_instruction_transfer_with_seed", level++, 0 );
  fun( w, &self->lamports, "lamports", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  if( self->from_seed_len ) {
    fun( w, NULL, "from_seed", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->from_seed_len; i++ )
      fun( w, self->from_seed + i, "from_seed", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "from_seed", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fd_pubkey_walk( w, &self->from_owner, fun, "from_owner", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_system_program_instruction_transfer_with_seed", level--, 0 );
}
ulong fd_system_program_instruction_transfer_with_seed_size( fd_system_program_instruction_transfer_with_seed_t const * self ) {
  ulong size = 0;
  size += sizeof(ulong);
  do {
    size += sizeof(ulong);
    size += self->from_seed_len;
  } while(0);
  size += fd_pubkey_size( &self->from_owner );
  return size;
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
void fd_system_program_instruction_inner_new( fd_system_program_instruction_inner_t * self, uint discriminant );
int fd_system_program_instruction_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_system_program_instruction_create_account_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_bincode_uint64_decode_footprint( ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    err = fd_system_program_instruction_create_account_with_seed_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    return FD_BINCODE_SUCCESS;
  }
  case 5: {
    err = fd_bincode_uint64_decode_footprint( ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 6: {
    err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 7: {
    err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 8: {
    err = fd_bincode_uint64_decode_footprint( ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 9: {
    err = fd_system_program_instruction_allocate_with_seed_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 10: {
    err = fd_system_program_instruction_assign_with_seed_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 11: {
    err = fd_system_program_instruction_transfer_with_seed_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 12: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_system_program_instruction_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_system_program_instruction_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_system_program_instruction_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_system_program_instruction_t);
  void const * start_data = ctx->data;
  int err =  fd_system_program_instruction_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_system_program_instruction_inner_decode_inner( fd_system_program_instruction_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    fd_system_program_instruction_create_account_decode_inner( &self->create_account, alloc_mem, ctx );
    break;
  }
  case 1: {
    fd_pubkey_decode_inner( &self->assign, alloc_mem, ctx );
    break;
  }
  case 2: {
    fd_bincode_uint64_decode_unsafe( &self->transfer, ctx );
    break;
  }
  case 3: {
    fd_system_program_instruction_create_account_with_seed_decode_inner( &self->create_account_with_seed, alloc_mem, ctx );
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    fd_bincode_uint64_decode_unsafe( &self->withdraw_nonce_account, ctx );
    break;
  }
  case 6: {
    fd_pubkey_decode_inner( &self->initialize_nonce_account, alloc_mem, ctx );
    break;
  }
  case 7: {
    fd_pubkey_decode_inner( &self->authorize_nonce_account, alloc_mem, ctx );
    break;
  }
  case 8: {
    fd_bincode_uint64_decode_unsafe( &self->allocate, ctx );
    break;
  }
  case 9: {
    fd_system_program_instruction_allocate_with_seed_decode_inner( &self->allocate_with_seed, alloc_mem, ctx );
    break;
  }
  case 10: {
    fd_system_program_instruction_assign_with_seed_decode_inner( &self->assign_with_seed, alloc_mem, ctx );
    break;
  }
  case 11: {
    fd_system_program_instruction_transfer_with_seed_decode_inner( &self->transfer_with_seed, alloc_mem, ctx );
    break;
  }
  case 12: {
    break;
  }
  }
}
static void fd_system_program_instruction_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_system_program_instruction_t * self = (fd_system_program_instruction_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_system_program_instruction_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_system_program_instruction_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_system_program_instruction_t * self = (fd_system_program_instruction_t *)mem;
  fd_system_program_instruction_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_system_program_instruction_t);
  void * * alloc_mem = &alloc_region;
  fd_system_program_instruction_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_system_program_instruction_inner_new( fd_system_program_instruction_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    fd_system_program_instruction_create_account_new( &self->create_account );
    break;
  }
  case 1: {
    fd_pubkey_new( &self->assign );
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    fd_system_program_instruction_create_account_with_seed_new( &self->create_account_with_seed );
    break;
  }
  case 4: {
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    fd_pubkey_new( &self->initialize_nonce_account );
    break;
  }
  case 7: {
    fd_pubkey_new( &self->authorize_nonce_account );
    break;
  }
  case 8: {
    break;
  }
  case 9: {
    fd_system_program_instruction_allocate_with_seed_new( &self->allocate_with_seed );
    break;
  }
  case 10: {
    fd_system_program_instruction_assign_with_seed_new( &self->assign_with_seed );
    break;
  }
  case 11: {
    fd_system_program_instruction_transfer_with_seed_new( &self->transfer_with_seed );
    break;
  }
  case 12: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_system_program_instruction_new_disc( fd_system_program_instruction_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_system_program_instruction_inner_new( &self->inner, self->discriminant );
}
void fd_system_program_instruction_new( fd_system_program_instruction_t * self ) {
  fd_memset( self, 0, sizeof(fd_system_program_instruction_t) );
  fd_system_program_instruction_new_disc( self, UINT_MAX );
}

void fd_system_program_instruction_walk( void * w, fd_system_program_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_system_program_instruction", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "create_account", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_system_program_instruction_create_account_walk( w, &self->inner.create_account, fun, "create_account", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "assign", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_pubkey_walk( w, &self->inner.assign, fun, "assign", level, 0 );
    break;
  }
  case 2: {
    fun( w, self, "transfer", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
  fun( w, &self->inner.transfer, "transfer", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
    break;
  }
  case 3: {
    fun( w, self, "create_account_with_seed", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_system_program_instruction_create_account_with_seed_walk( w, &self->inner.create_account_with_seed, fun, "create_account_with_seed", level, 0 );
    break;
  }
  case 4: {
    fun( w, self, "advance_nonce_account", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 5: {
    fun( w, self, "withdraw_nonce_account", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
  fun( w, &self->inner.withdraw_nonce_account, "withdraw_nonce_account", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
    break;
  }
  case 6: {
    fun( w, self, "initialize_nonce_account", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_pubkey_walk( w, &self->inner.initialize_nonce_account, fun, "initialize_nonce_account", level, 0 );
    break;
  }
  case 7: {
    fun( w, self, "authorize_nonce_account", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_pubkey_walk( w, &self->inner.authorize_nonce_account, fun, "authorize_nonce_account", level, 0 );
    break;
  }
  case 8: {
    fun( w, self, "allocate", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
  fun( w, &self->inner.allocate, "allocate", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
    break;
  }
  case 9: {
    fun( w, self, "allocate_with_seed", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_system_program_instruction_allocate_with_seed_walk( w, &self->inner.allocate_with_seed, fun, "allocate_with_seed", level, 0 );
    break;
  }
  case 10: {
    fun( w, self, "assign_with_seed", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_system_program_instruction_assign_with_seed_walk( w, &self->inner.assign_with_seed, fun, "assign_with_seed", level, 0 );
    break;
  }
  case 11: {
    fun( w, self, "transfer_with_seed", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_system_program_instruction_transfer_with_seed_walk( w, &self->inner.transfer_with_seed, fun, "transfer_with_seed", level, 0 );
    break;
  }
  case 12: {
    fun( w, self, "upgrade_nonce_account", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_system_program_instruction", level--, 0 );
}
ulong fd_system_program_instruction_size( fd_system_program_instruction_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_system_program_instruction_create_account_size( &self->inner.create_account );
    break;
  }
  case 1: {
    size += fd_pubkey_size( &self->inner.assign );
    break;
  }
  case 2: {
    size += sizeof(ulong);
    break;
  }
  case 3: {
    size += fd_system_program_instruction_create_account_with_seed_size( &self->inner.create_account_with_seed );
    break;
  }
  case 5: {
    size += sizeof(ulong);
    break;
  }
  case 6: {
    size += fd_pubkey_size( &self->inner.initialize_nonce_account );
    break;
  }
  case 7: {
    size += fd_pubkey_size( &self->inner.authorize_nonce_account );
    break;
  }
  case 8: {
    size += sizeof(ulong);
    break;
  }
  case 9: {
    size += fd_system_program_instruction_allocate_with_seed_size( &self->inner.allocate_with_seed );
    break;
  }
  case 10: {
    size += fd_system_program_instruction_assign_with_seed_size( &self->inner.assign_with_seed );
    break;
  }
  case 11: {
    size += fd_system_program_instruction_transfer_with_seed_size( &self->inner.transfer_with_seed );
    break;
  }
  }
  return size;
}

int fd_system_program_instruction_inner_encode( fd_system_program_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_system_program_instruction_create_account_encode( &self->create_account, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 1: {
    err = fd_pubkey_encode( &self->assign, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 2: {
    err = fd_bincode_uint64_encode( self->transfer, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 3: {
    err = fd_system_program_instruction_create_account_with_seed_encode( &self->create_account_with_seed, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 5: {
    err = fd_bincode_uint64_encode( self->withdraw_nonce_account, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 6: {
    err = fd_pubkey_encode( &self->initialize_nonce_account, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 7: {
    err = fd_pubkey_encode( &self->authorize_nonce_account, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 8: {
    err = fd_bincode_uint64_encode( self->allocate, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 9: {
    err = fd_system_program_instruction_allocate_with_seed_encode( &self->allocate_with_seed, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 10: {
    err = fd_system_program_instruction_assign_with_seed_encode( &self->assign_with_seed, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 11: {
    err = fd_system_program_instruction_transfer_with_seed_encode( &self->transfer_with_seed, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_system_program_instruction_encode( fd_system_program_instruction_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_system_program_instruction_inner_encode( &self->inner, self->discriminant, ctx );
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
int fd_system_error_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
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
static int fd_system_error_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_system_error_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_system_error_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_system_error_t);
  void const * start_data = ctx->data;
  int err =  fd_system_error_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_system_error_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_system_error_t * self = (fd_system_error_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
}
void * fd_system_error_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_system_error_t * self = (fd_system_error_t *)mem;
  fd_system_error_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_system_error_t);
  void * * alloc_mem = &alloc_region;
  fd_system_error_decode_inner( mem, alloc_mem, ctx );
  return self;
}

void fd_system_error_walk( void * w, fd_system_error_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_system_error", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "account_already_in_use", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "result_with_negative_lamports", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 2: {
    fun( w, self, "invalid_program_id", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 3: {
    fun( w, self, "invalid_account_data_length", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 4: {
    fun( w, self, "max_seed_length_exceeded", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 5: {
    fun( w, self, "address_with_seed_mismatch", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 6: {
    fun( w, self, "nonce_no_recent_blockhashes", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 7: {
    fun( w, self, "nonce_blockhash_not_expired", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 8: {
    fun( w, self, "nonce_unexpected_blockhash_value", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_system_error", level--, 0 );
}
ulong fd_system_error_size( fd_system_error_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  }
  return size;
}

int fd_system_error_encode( fd_system_error_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return err;
}

int fd_stake_authorized_encode( fd_stake_authorized_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->staker, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->withdrawer, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_stake_authorized_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 64UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 64UL );
  return 0;
}
static void fd_stake_authorized_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_authorized_t * self = (fd_stake_authorized_t *)struct_mem;
  fd_pubkey_decode_inner( &self->staker, alloc_mem, ctx );
  fd_pubkey_decode_inner( &self->withdrawer, alloc_mem, ctx );
}
void * fd_stake_authorized_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_authorized_t * self = (fd_stake_authorized_t *)mem;
  fd_stake_authorized_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_stake_authorized_t);
  void * * alloc_mem = &alloc_region;
  fd_stake_authorized_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_stake_authorized_walk( void * w, fd_stake_authorized_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_authorized", level++, 0 );
  fd_pubkey_walk( w, &self->staker, fun, "staker", level, 0 );
  fd_pubkey_walk( w, &self->withdrawer, fun, "withdrawer", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_authorized", level--, 0 );
}
int fd_stake_lockup_encode( fd_stake_lockup_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( (ulong)self->unix_timestamp, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->epoch, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->custodian, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_stake_lockup_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 48UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 48UL );
  return 0;
}
static void fd_stake_lockup_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_lockup_t * self = (fd_stake_lockup_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( (ulong *) &self->unix_timestamp, ctx );
  fd_bincode_uint64_decode_unsafe( &self->epoch, ctx );
  fd_pubkey_decode_inner( &self->custodian, alloc_mem, ctx );
}
void * fd_stake_lockup_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_lockup_t * self = (fd_stake_lockup_t *)mem;
  fd_stake_lockup_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_stake_lockup_t);
  void * * alloc_mem = &alloc_region;
  fd_stake_lockup_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_stake_lockup_walk( void * w, fd_stake_lockup_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_lockup", level++, 0 );
  fun( w, &self->unix_timestamp, "unix_timestamp", FD_FLAMENCO_TYPE_SLONG, "long", level, 0  );
  fun( w, &self->epoch, "epoch", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_pubkey_walk( w, &self->custodian, fun, "custodian", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_lockup", level--, 0 );
}
int fd_stake_instruction_initialize_encode( fd_stake_instruction_initialize_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_stake_authorized_encode( &self->authorized, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_stake_lockup_encode( &self->lockup, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_stake_instruction_initialize_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 112UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 112UL );
  return 0;
}
static void fd_stake_instruction_initialize_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_instruction_initialize_t * self = (fd_stake_instruction_initialize_t *)struct_mem;
  fd_stake_authorized_decode_inner( &self->authorized, alloc_mem, ctx );
  fd_stake_lockup_decode_inner( &self->lockup, alloc_mem, ctx );
}
void * fd_stake_instruction_initialize_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_instruction_initialize_t * self = (fd_stake_instruction_initialize_t *)mem;
  fd_stake_instruction_initialize_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_stake_instruction_initialize_t);
  void * * alloc_mem = &alloc_region;
  fd_stake_instruction_initialize_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_stake_instruction_initialize_walk( void * w, fd_stake_instruction_initialize_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_instruction_initialize", level++, 0 );
  fd_stake_authorized_walk( w, &self->authorized, fun, "authorized", level, 0 );
  fd_stake_lockup_walk( w, &self->lockup, fun, "lockup", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_instruction_initialize", level--, 0 );
}
int fd_stake_lockup_custodian_args_encode( fd_stake_lockup_custodian_args_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_stake_lockup_encode( &self->lockup, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_sol_sysvar_clock_encode( &self->clock, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->custodian != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_pubkey_encode( self->custodian, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_stake_lockup_custodian_args_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_stake_lockup_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_sol_sysvar_clock_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
    *total_sz += FD_PUBKEY_ALIGN + sizeof(fd_pubkey_t);
      err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_stake_lockup_custodian_args_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_lockup_custodian_args_t);
  void const * start_data = ctx->data;
  int err = fd_stake_lockup_custodian_args_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_stake_lockup_custodian_args_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_lockup_custodian_args_t * self = (fd_stake_lockup_custodian_args_t *)struct_mem;
  fd_stake_lockup_decode_inner( &self->lockup, alloc_mem, ctx );
  fd_sol_sysvar_clock_decode_inner( &self->clock, alloc_mem, ctx );
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, FD_PUBKEY_ALIGN );
      self->custodian = *alloc_mem;
      *alloc_mem = (uchar *)*alloc_mem + sizeof(fd_pubkey_t);
      fd_pubkey_new( self->custodian );
      fd_pubkey_decode_inner( self->custodian, alloc_mem, ctx );
    } else {
      self->custodian = NULL;
    }
  }
}
void * fd_stake_lockup_custodian_args_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_lockup_custodian_args_t * self = (fd_stake_lockup_custodian_args_t *)mem;
  fd_stake_lockup_custodian_args_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_stake_lockup_custodian_args_t);
  void * * alloc_mem = &alloc_region;
  fd_stake_lockup_custodian_args_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_stake_lockup_custodian_args_new(fd_stake_lockup_custodian_args_t * self) {
  fd_memset( self, 0, sizeof(fd_stake_lockup_custodian_args_t) );
  fd_stake_lockup_new( &self->lockup );
  fd_sol_sysvar_clock_new( &self->clock );
}
void fd_stake_lockup_custodian_args_walk( void * w, fd_stake_lockup_custodian_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_lockup_custodian_args", level++, 0 );
  fd_stake_lockup_walk( w, &self->lockup, fun, "lockup", level, 0 );
  fd_sol_sysvar_clock_walk( w, &self->clock, fun, "clock", level, 0 );
  if( !self->custodian ) {
    fun( w, NULL, "custodian", FD_FLAMENCO_TYPE_NULL, "pubkey", level, 0 );
  } else {
    fd_pubkey_walk( w, self->custodian, fun, "custodian", level, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_lockup_custodian_args", level--, 0 );
}
ulong fd_stake_lockup_custodian_args_size( fd_stake_lockup_custodian_args_t const * self ) {
  ulong size = 0;
  size += fd_stake_lockup_size( &self->lockup );
  size += fd_sol_sysvar_clock_size( &self->clock );
  size += sizeof(char);
  if( NULL != self->custodian ) {
    size += fd_pubkey_size( self->custodian );
  }
  return size;
}

FD_FN_PURE uchar fd_stake_authorize_is_staker(fd_stake_authorize_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_stake_authorize_is_withdrawer(fd_stake_authorize_t const * self) {
  return self->discriminant == 1;
}
int fd_stake_authorize_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
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
static int fd_stake_authorize_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_stake_authorize_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_stake_authorize_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_authorize_t);
  void const * start_data = ctx->data;
  int err =  fd_stake_authorize_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_stake_authorize_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_authorize_t * self = (fd_stake_authorize_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
}
void * fd_stake_authorize_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_authorize_t * self = (fd_stake_authorize_t *)mem;
  fd_stake_authorize_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_stake_authorize_t);
  void * * alloc_mem = &alloc_region;
  fd_stake_authorize_decode_inner( mem, alloc_mem, ctx );
  return self;
}

void fd_stake_authorize_walk( void * w, fd_stake_authorize_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_stake_authorize", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "staker", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "withdrawer", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_stake_authorize", level--, 0 );
}
ulong fd_stake_authorize_size( fd_stake_authorize_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  }
  return size;
}

int fd_stake_authorize_encode( fd_stake_authorize_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return err;
}

int fd_stake_instruction_authorize_encode( fd_stake_instruction_authorize_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_stake_authorize_encode( &self->stake_authorize, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_stake_instruction_authorize_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_stake_authorize_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_stake_instruction_authorize_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_instruction_authorize_t);
  void const * start_data = ctx->data;
  int err = fd_stake_instruction_authorize_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_stake_instruction_authorize_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_instruction_authorize_t * self = (fd_stake_instruction_authorize_t *)struct_mem;
  fd_pubkey_decode_inner( &self->pubkey, alloc_mem, ctx );
  fd_stake_authorize_decode_inner( &self->stake_authorize, alloc_mem, ctx );
}
void * fd_stake_instruction_authorize_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_instruction_authorize_t * self = (fd_stake_instruction_authorize_t *)mem;
  fd_stake_instruction_authorize_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_stake_instruction_authorize_t);
  void * * alloc_mem = &alloc_region;
  fd_stake_instruction_authorize_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_stake_instruction_authorize_new(fd_stake_instruction_authorize_t * self) {
  fd_memset( self, 0, sizeof(fd_stake_instruction_authorize_t) );
  fd_pubkey_new( &self->pubkey );
  fd_stake_authorize_new( &self->stake_authorize );
}
void fd_stake_instruction_authorize_walk( void * w, fd_stake_instruction_authorize_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_instruction_authorize", level++, 0 );
  fd_pubkey_walk( w, &self->pubkey, fun, "pubkey", level, 0 );
  fd_stake_authorize_walk( w, &self->stake_authorize, fun, "stake_authorize", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_instruction_authorize", level--, 0 );
}
int fd_authorize_with_seed_args_encode( fd_authorize_with_seed_args_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->new_authorized_pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_stake_authorize_encode( &self->stake_authorize, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->authority_seed_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->authority_seed_len ) {
    err = fd_bincode_bytes_encode( self->authority_seed, self->authority_seed_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_pubkey_encode( &self->authority_owner, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_authorize_with_seed_args_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_stake_authorize_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ulong authority_seed_len;
  err = fd_bincode_uint64_decode( &authority_seed_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  *total_sz += authority_seed_len;
  if( authority_seed_len ) {
    err = fd_bincode_bytes_decode_footprint( authority_seed_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    err = !fd_utf8_verify( (char const *) ctx->data - authority_seed_len, authority_seed_len );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_authorize_with_seed_args_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_authorize_with_seed_args_t);
  void const * start_data = ctx->data;
  int err = fd_authorize_with_seed_args_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_authorize_with_seed_args_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_authorize_with_seed_args_t * self = (fd_authorize_with_seed_args_t *)struct_mem;
  fd_pubkey_decode_inner( &self->new_authorized_pubkey, alloc_mem, ctx );
  fd_stake_authorize_decode_inner( &self->stake_authorize, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->authority_seed_len, ctx );
  if( self->authority_seed_len ) {
    self->authority_seed = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->authority_seed, self->authority_seed_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->authority_seed_len;
  } else
    self->authority_seed = NULL;
  fd_pubkey_decode_inner( &self->authority_owner, alloc_mem, ctx );
}
void * fd_authorize_with_seed_args_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_authorize_with_seed_args_t * self = (fd_authorize_with_seed_args_t *)mem;
  fd_authorize_with_seed_args_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_authorize_with_seed_args_t);
  void * * alloc_mem = &alloc_region;
  fd_authorize_with_seed_args_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_authorize_with_seed_args_new(fd_authorize_with_seed_args_t * self) {
  fd_memset( self, 0, sizeof(fd_authorize_with_seed_args_t) );
  fd_pubkey_new( &self->new_authorized_pubkey );
  fd_stake_authorize_new( &self->stake_authorize );
  fd_pubkey_new( &self->authority_owner );
}
void fd_authorize_with_seed_args_walk( void * w, fd_authorize_with_seed_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_authorize_with_seed_args", level++, 0 );
  fd_pubkey_walk( w, &self->new_authorized_pubkey, fun, "new_authorized_pubkey", level, 0 );
  fd_stake_authorize_walk( w, &self->stake_authorize, fun, "stake_authorize", level, 0 );
  if( self->authority_seed_len ) {
    fun( w, NULL, "authority_seed", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->authority_seed_len; i++ )
      fun( w, self->authority_seed + i, "authority_seed", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "authority_seed", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fd_pubkey_walk( w, &self->authority_owner, fun, "authority_owner", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_authorize_with_seed_args", level--, 0 );
}
ulong fd_authorize_with_seed_args_size( fd_authorize_with_seed_args_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->new_authorized_pubkey );
  size += fd_stake_authorize_size( &self->stake_authorize );
  do {
    size += sizeof(ulong);
    size += self->authority_seed_len;
  } while(0);
  size += fd_pubkey_size( &self->authority_owner );
  return size;
}

int fd_authorize_checked_with_seed_args_encode( fd_authorize_checked_with_seed_args_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_stake_authorize_encode( &self->stake_authorize, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->authority_seed_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->authority_seed_len ) {
    err = fd_bincode_bytes_encode( self->authority_seed, self->authority_seed_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_pubkey_encode( &self->authority_owner, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_authorize_checked_with_seed_args_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_stake_authorize_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ulong authority_seed_len;
  err = fd_bincode_uint64_decode( &authority_seed_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  *total_sz += authority_seed_len;
  if( authority_seed_len ) {
    err = fd_bincode_bytes_decode_footprint( authority_seed_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    err = !fd_utf8_verify( (char const *) ctx->data - authority_seed_len, authority_seed_len );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_authorize_checked_with_seed_args_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_authorize_checked_with_seed_args_t);
  void const * start_data = ctx->data;
  int err = fd_authorize_checked_with_seed_args_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_authorize_checked_with_seed_args_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_authorize_checked_with_seed_args_t * self = (fd_authorize_checked_with_seed_args_t *)struct_mem;
  fd_stake_authorize_decode_inner( &self->stake_authorize, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->authority_seed_len, ctx );
  if( self->authority_seed_len ) {
    self->authority_seed = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->authority_seed, self->authority_seed_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->authority_seed_len;
  } else
    self->authority_seed = NULL;
  fd_pubkey_decode_inner( &self->authority_owner, alloc_mem, ctx );
}
void * fd_authorize_checked_with_seed_args_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_authorize_checked_with_seed_args_t * self = (fd_authorize_checked_with_seed_args_t *)mem;
  fd_authorize_checked_with_seed_args_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_authorize_checked_with_seed_args_t);
  void * * alloc_mem = &alloc_region;
  fd_authorize_checked_with_seed_args_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_authorize_checked_with_seed_args_new(fd_authorize_checked_with_seed_args_t * self) {
  fd_memset( self, 0, sizeof(fd_authorize_checked_with_seed_args_t) );
  fd_stake_authorize_new( &self->stake_authorize );
  fd_pubkey_new( &self->authority_owner );
}
void fd_authorize_checked_with_seed_args_walk( void * w, fd_authorize_checked_with_seed_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_authorize_checked_with_seed_args", level++, 0 );
  fd_stake_authorize_walk( w, &self->stake_authorize, fun, "stake_authorize", level, 0 );
  if( self->authority_seed_len ) {
    fun( w, NULL, "authority_seed", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->authority_seed_len; i++ )
      fun( w, self->authority_seed + i, "authority_seed", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "authority_seed", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fd_pubkey_walk( w, &self->authority_owner, fun, "authority_owner", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_authorize_checked_with_seed_args", level--, 0 );
}
ulong fd_authorize_checked_with_seed_args_size( fd_authorize_checked_with_seed_args_t const * self ) {
  ulong size = 0;
  size += fd_stake_authorize_size( &self->stake_authorize );
  do {
    size += sizeof(ulong);
    size += self->authority_seed_len;
  } while(0);
  size += fd_pubkey_size( &self->authority_owner );
  return size;
}

int fd_lockup_checked_args_encode( fd_lockup_checked_args_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  if( self->unix_timestamp != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_bincode_int64_encode( self->unix_timestamp[0], ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  if( self->epoch != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_bincode_uint64_encode( self->epoch[0], ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_lockup_checked_args_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
    *total_sz += 8UL + sizeof(long);
      err = fd_bincode_int64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
    *total_sz += 8UL + sizeof(ulong);
      err = fd_bincode_uint64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_lockup_checked_args_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_lockup_checked_args_t);
  void const * start_data = ctx->data;
  int err = fd_lockup_checked_args_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_lockup_checked_args_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_lockup_checked_args_t * self = (fd_lockup_checked_args_t *)struct_mem;
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, 8UL );
      self->unix_timestamp = *alloc_mem;
      *alloc_mem = (uchar *)*alloc_mem + sizeof(long);
      fd_bincode_int64_decode_unsafe( self->unix_timestamp, ctx );
    } else {
      self->unix_timestamp = NULL;
    }
  }
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, 8UL );
      self->epoch = *alloc_mem;
      *alloc_mem = (uchar *)*alloc_mem + sizeof(ulong);
      fd_bincode_uint64_decode_unsafe( self->epoch, ctx );
    } else {
      self->epoch = NULL;
    }
  }
}
void * fd_lockup_checked_args_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_lockup_checked_args_t * self = (fd_lockup_checked_args_t *)mem;
  fd_lockup_checked_args_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_lockup_checked_args_t);
  void * * alloc_mem = &alloc_region;
  fd_lockup_checked_args_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_lockup_checked_args_new(fd_lockup_checked_args_t * self) {
  fd_memset( self, 0, sizeof(fd_lockup_checked_args_t) );
}
void fd_lockup_checked_args_walk( void * w, fd_lockup_checked_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_lockup_checked_args", level++, 0 );
  if( !self->unix_timestamp ) {
    fun( w, NULL, "unix_timestamp", FD_FLAMENCO_TYPE_NULL, "long", level, 0 );
  } else {
    fun( w, self->unix_timestamp, "unix_timestamp", FD_FLAMENCO_TYPE_SLONG, "long", level, 0 );
  }
  if( !self->epoch ) {
    fun( w, NULL, "epoch", FD_FLAMENCO_TYPE_NULL, "ulong", level, 0 );
  } else {
    fun( w, self->epoch, "epoch", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_lockup_checked_args", level--, 0 );
}
ulong fd_lockup_checked_args_size( fd_lockup_checked_args_t const * self ) {
  ulong size = 0;
  size += sizeof(char);
  if( NULL != self->unix_timestamp ) {
    size += sizeof(long);
  }
  size += sizeof(char);
  if( NULL != self->epoch ) {
    size += sizeof(ulong);
  }
  return size;
}

int fd_lockup_args_encode( fd_lockup_args_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  if( self->unix_timestamp != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_bincode_int64_encode( self->unix_timestamp[0], ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  if( self->epoch != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_bincode_uint64_encode( self->epoch[0], ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  if( self->custodian != NULL ) {
    err = fd_bincode_bool_encode( 1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_pubkey_encode( self->custodian, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  } else {
    err = fd_bincode_bool_encode( 0, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_lockup_args_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
    *total_sz += 8UL + sizeof(long);
      err = fd_bincode_int64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
    *total_sz += 8UL + sizeof(ulong);
      err = fd_bincode_uint64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
    *total_sz += FD_PUBKEY_ALIGN + sizeof(fd_pubkey_t);
      err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_lockup_args_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_lockup_args_t);
  void const * start_data = ctx->data;
  int err = fd_lockup_args_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_lockup_args_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_lockup_args_t * self = (fd_lockup_args_t *)struct_mem;
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, 8UL );
      self->unix_timestamp = *alloc_mem;
      *alloc_mem = (uchar *)*alloc_mem + sizeof(long);
      fd_bincode_int64_decode_unsafe( self->unix_timestamp, ctx );
    } else {
      self->unix_timestamp = NULL;
    }
  }
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, 8UL );
      self->epoch = *alloc_mem;
      *alloc_mem = (uchar *)*alloc_mem + sizeof(ulong);
      fd_bincode_uint64_decode_unsafe( self->epoch, ctx );
    } else {
      self->epoch = NULL;
    }
  }
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    if( o ) {
      *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, FD_PUBKEY_ALIGN );
      self->custodian = *alloc_mem;
      *alloc_mem = (uchar *)*alloc_mem + sizeof(fd_pubkey_t);
      fd_pubkey_new( self->custodian );
      fd_pubkey_decode_inner( self->custodian, alloc_mem, ctx );
    } else {
      self->custodian = NULL;
    }
  }
}
void * fd_lockup_args_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_lockup_args_t * self = (fd_lockup_args_t *)mem;
  fd_lockup_args_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_lockup_args_t);
  void * * alloc_mem = &alloc_region;
  fd_lockup_args_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_lockup_args_new(fd_lockup_args_t * self) {
  fd_memset( self, 0, sizeof(fd_lockup_args_t) );
}
void fd_lockup_args_walk( void * w, fd_lockup_args_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_lockup_args", level++, 0 );
  if( !self->unix_timestamp ) {
    fun( w, NULL, "unix_timestamp", FD_FLAMENCO_TYPE_NULL, "long", level, 0 );
  } else {
    fun( w, self->unix_timestamp, "unix_timestamp", FD_FLAMENCO_TYPE_SLONG, "long", level, 0 );
  }
  if( !self->epoch ) {
    fun( w, NULL, "epoch", FD_FLAMENCO_TYPE_NULL, "ulong", level, 0 );
  } else {
    fun( w, self->epoch, "epoch", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0 );
  }
  if( !self->custodian ) {
    fun( w, NULL, "custodian", FD_FLAMENCO_TYPE_NULL, "pubkey", level, 0 );
  } else {
    fd_pubkey_walk( w, self->custodian, fun, "custodian", level, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_lockup_args", level--, 0 );
}
ulong fd_lockup_args_size( fd_lockup_args_t const * self ) {
  ulong size = 0;
  size += sizeof(char);
  if( NULL != self->unix_timestamp ) {
    size += sizeof(long);
  }
  size += sizeof(char);
  if( NULL != self->epoch ) {
    size += sizeof(ulong);
  }
  size += sizeof(char);
  if( NULL != self->custodian ) {
    size += fd_pubkey_size( self->custodian );
  }
  return size;
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
FD_FN_PURE uchar fd_stake_instruction_is_move_stake(fd_stake_instruction_t const * self) {
  return self->discriminant == 16;
}
FD_FN_PURE uchar fd_stake_instruction_is_move_lamports(fd_stake_instruction_t const * self) {
  return self->discriminant == 17;
}
void fd_stake_instruction_inner_new( fd_stake_instruction_inner_t * self, uint discriminant );
int fd_stake_instruction_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_stake_instruction_initialize_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_stake_instruction_authorize_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    err = fd_bincode_uint64_decode_footprint( ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    err = fd_bincode_uint64_decode_footprint( ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 5: {
    return FD_BINCODE_SUCCESS;
  }
  case 6: {
    err = fd_lockup_args_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 7: {
    return FD_BINCODE_SUCCESS;
  }
  case 8: {
    err = fd_authorize_with_seed_args_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 9: {
    return FD_BINCODE_SUCCESS;
  }
  case 10: {
    err = fd_stake_authorize_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 11: {
    err = fd_authorize_checked_with_seed_args_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 12: {
    err = fd_lockup_checked_args_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
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
  case 16: {
    err = fd_bincode_uint64_decode_footprint( ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 17: {
    err = fd_bincode_uint64_decode_footprint( ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_stake_instruction_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_stake_instruction_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_stake_instruction_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_instruction_t);
  void const * start_data = ctx->data;
  int err =  fd_stake_instruction_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_stake_instruction_inner_decode_inner( fd_stake_instruction_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    fd_stake_instruction_initialize_decode_inner( &self->initialize, alloc_mem, ctx );
    break;
  }
  case 1: {
    fd_stake_instruction_authorize_decode_inner( &self->authorize, alloc_mem, ctx );
    break;
  }
  case 2: {
    break;
  }
  case 3: {
    fd_bincode_uint64_decode_unsafe( &self->split, ctx );
    break;
  }
  case 4: {
    fd_bincode_uint64_decode_unsafe( &self->withdraw, ctx );
    break;
  }
  case 5: {
    break;
  }
  case 6: {
    fd_lockup_args_decode_inner( &self->set_lockup, alloc_mem, ctx );
    break;
  }
  case 7: {
    break;
  }
  case 8: {
    fd_authorize_with_seed_args_decode_inner( &self->authorize_with_seed, alloc_mem, ctx );
    break;
  }
  case 9: {
    break;
  }
  case 10: {
    fd_stake_authorize_decode_inner( &self->authorize_checked, alloc_mem, ctx );
    break;
  }
  case 11: {
    fd_authorize_checked_with_seed_args_decode_inner( &self->authorize_checked_with_seed, alloc_mem, ctx );
    break;
  }
  case 12: {
    fd_lockup_checked_args_decode_inner( &self->set_lockup_checked, alloc_mem, ctx );
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
  case 16: {
    fd_bincode_uint64_decode_unsafe( &self->move_stake, ctx );
    break;
  }
  case 17: {
    fd_bincode_uint64_decode_unsafe( &self->move_lamports, ctx );
    break;
  }
  }
}
static void fd_stake_instruction_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_instruction_t * self = (fd_stake_instruction_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_stake_instruction_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_stake_instruction_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_instruction_t * self = (fd_stake_instruction_t *)mem;
  fd_stake_instruction_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_stake_instruction_t);
  void * * alloc_mem = &alloc_region;
  fd_stake_instruction_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_stake_instruction_inner_new( fd_stake_instruction_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    fd_stake_instruction_initialize_new( &self->initialize );
    break;
  }
  case 1: {
    fd_stake_instruction_authorize_new( &self->authorize );
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
    fd_lockup_args_new( &self->set_lockup );
    break;
  }
  case 7: {
    break;
  }
  case 8: {
    fd_authorize_with_seed_args_new( &self->authorize_with_seed );
    break;
  }
  case 9: {
    break;
  }
  case 10: {
    fd_stake_authorize_new( &self->authorize_checked );
    break;
  }
  case 11: {
    fd_authorize_checked_with_seed_args_new( &self->authorize_checked_with_seed );
    break;
  }
  case 12: {
    fd_lockup_checked_args_new( &self->set_lockup_checked );
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
  case 16: {
    break;
  }
  case 17: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_stake_instruction_new_disc( fd_stake_instruction_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_stake_instruction_inner_new( &self->inner, self->discriminant );
}
void fd_stake_instruction_new( fd_stake_instruction_t * self ) {
  fd_memset( self, 0, sizeof(fd_stake_instruction_t) );
  fd_stake_instruction_new_disc( self, UINT_MAX );
}

void fd_stake_instruction_walk( void * w, fd_stake_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_stake_instruction", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "initialize", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_stake_instruction_initialize_walk( w, &self->inner.initialize, fun, "initialize", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "authorize", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_stake_instruction_authorize_walk( w, &self->inner.authorize, fun, "authorize", level, 0 );
    break;
  }
  case 2: {
    fun( w, self, "delegate_stake", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 3: {
    fun( w, self, "split", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
  fun( w, &self->inner.split, "split", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
    break;
  }
  case 4: {
    fun( w, self, "withdraw", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
  fun( w, &self->inner.withdraw, "withdraw", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
    break;
  }
  case 5: {
    fun( w, self, "deactivate", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 6: {
    fun( w, self, "set_lockup", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_lockup_args_walk( w, &self->inner.set_lockup, fun, "set_lockup", level, 0 );
    break;
  }
  case 7: {
    fun( w, self, "merge", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 8: {
    fun( w, self, "authorize_with_seed", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_authorize_with_seed_args_walk( w, &self->inner.authorize_with_seed, fun, "authorize_with_seed", level, 0 );
    break;
  }
  case 9: {
    fun( w, self, "initialize_checked", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 10: {
    fun( w, self, "authorize_checked", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_stake_authorize_walk( w, &self->inner.authorize_checked, fun, "authorize_checked", level, 0 );
    break;
  }
  case 11: {
    fun( w, self, "authorize_checked_with_seed", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_authorize_checked_with_seed_args_walk( w, &self->inner.authorize_checked_with_seed, fun, "authorize_checked_with_seed", level, 0 );
    break;
  }
  case 12: {
    fun( w, self, "set_lockup_checked", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_lockup_checked_args_walk( w, &self->inner.set_lockup_checked, fun, "set_lockup_checked", level, 0 );
    break;
  }
  case 13: {
    fun( w, self, "get_minimum_delegation", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 14: {
    fun( w, self, "deactivate_delinquent", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 15: {
    fun( w, self, "redelegate", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 16: {
    fun( w, self, "move_stake", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
  fun( w, &self->inner.move_stake, "move_stake", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
    break;
  }
  case 17: {
    fun( w, self, "move_lamports", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
  fun( w, &self->inner.move_lamports, "move_lamports", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_stake_instruction", level--, 0 );
}
ulong fd_stake_instruction_size( fd_stake_instruction_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_stake_instruction_initialize_size( &self->inner.initialize );
    break;
  }
  case 1: {
    size += fd_stake_instruction_authorize_size( &self->inner.authorize );
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
    size += fd_lockup_args_size( &self->inner.set_lockup );
    break;
  }
  case 8: {
    size += fd_authorize_with_seed_args_size( &self->inner.authorize_with_seed );
    break;
  }
  case 10: {
    size += fd_stake_authorize_size( &self->inner.authorize_checked );
    break;
  }
  case 11: {
    size += fd_authorize_checked_with_seed_args_size( &self->inner.authorize_checked_with_seed );
    break;
  }
  case 12: {
    size += fd_lockup_checked_args_size( &self->inner.set_lockup_checked );
    break;
  }
  case 16: {
    size += sizeof(ulong);
    break;
  }
  case 17: {
    size += sizeof(ulong);
    break;
  }
  }
  return size;
}

int fd_stake_instruction_inner_encode( fd_stake_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_stake_instruction_initialize_encode( &self->initialize, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 1: {
    err = fd_stake_instruction_authorize_encode( &self->authorize, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 3: {
    err = fd_bincode_uint64_encode( self->split, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 4: {
    err = fd_bincode_uint64_encode( self->withdraw, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 6: {
    err = fd_lockup_args_encode( &self->set_lockup, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 8: {
    err = fd_authorize_with_seed_args_encode( &self->authorize_with_seed, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 10: {
    err = fd_stake_authorize_encode( &self->authorize_checked, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 11: {
    err = fd_authorize_checked_with_seed_args_encode( &self->authorize_checked_with_seed, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 12: {
    err = fd_lockup_checked_args_encode( &self->set_lockup_checked, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 16: {
    err = fd_bincode_uint64_encode( self->move_stake, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 17: {
    err = fd_bincode_uint64_encode( self->move_lamports, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_stake_instruction_encode( fd_stake_instruction_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_stake_instruction_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_stake_meta_encode( fd_stake_meta_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->rent_exempt_reserve, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_stake_authorized_encode( &self->authorized, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_stake_lockup_encode( &self->lockup, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_stake_meta_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 120UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 120UL );
  return 0;
}
static void fd_stake_meta_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_meta_t * self = (fd_stake_meta_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->rent_exempt_reserve, ctx );
  fd_stake_authorized_decode_inner( &self->authorized, alloc_mem, ctx );
  fd_stake_lockup_decode_inner( &self->lockup, alloc_mem, ctx );
}
void * fd_stake_meta_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_meta_t * self = (fd_stake_meta_t *)mem;
  fd_stake_meta_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_stake_meta_t);
  void * * alloc_mem = &alloc_region;
  fd_stake_meta_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_stake_meta_walk( void * w, fd_stake_meta_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_meta", level++, 0 );
  fun( w, &self->rent_exempt_reserve, "rent_exempt_reserve", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_stake_authorized_walk( w, &self->authorized, fun, "authorized", level, 0 );
  fd_stake_lockup_walk( w, &self->lockup, fun, "lockup", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_meta", level--, 0 );
}
int fd_stake_flags_encode( fd_stake_flags_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint8_encode( (uchar)(self->bits), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_stake_flags_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 1UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 1UL );
  return 0;
}
static void fd_stake_flags_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_flags_t * self = (fd_stake_flags_t *)struct_mem;
  fd_bincode_uint8_decode_unsafe( &self->bits, ctx );
}
void * fd_stake_flags_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_flags_t * self = (fd_stake_flags_t *)mem;
  fd_stake_flags_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_stake_flags_t);
  void * * alloc_mem = &alloc_region;
  fd_stake_flags_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_stake_flags_walk( void * w, fd_stake_flags_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_flags", level++, 0 );
  fun( w, &self->bits, "bits", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_flags", level--, 0 );
}
int fd_stake_state_v2_initialized_encode( fd_stake_state_v2_initialized_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_stake_meta_encode( &self->meta, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_stake_state_v2_initialized_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 120UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 120UL );
  return 0;
}
static void fd_stake_state_v2_initialized_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_state_v2_initialized_t * self = (fd_stake_state_v2_initialized_t *)struct_mem;
  fd_stake_meta_decode_inner( &self->meta, alloc_mem, ctx );
}
void * fd_stake_state_v2_initialized_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_state_v2_initialized_t * self = (fd_stake_state_v2_initialized_t *)mem;
  fd_stake_state_v2_initialized_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_stake_state_v2_initialized_t);
  void * * alloc_mem = &alloc_region;
  fd_stake_state_v2_initialized_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_stake_state_v2_initialized_walk( void * w, fd_stake_state_v2_initialized_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_state_v2_initialized", level++, 0 );
  fd_stake_meta_walk( w, &self->meta, fun, "meta", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_state_v2_initialized", level--, 0 );
}
int fd_stake_state_v2_stake_encode( fd_stake_state_v2_stake_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_stake_meta_encode( &self->meta, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_stake_encode( &self->stake, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_stake_flags_encode( &self->stake_flags, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_stake_state_v2_stake_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 193UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 193UL );
  return 0;
}
static void fd_stake_state_v2_stake_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_state_v2_stake_t * self = (fd_stake_state_v2_stake_t *)struct_mem;
  fd_stake_meta_decode_inner( &self->meta, alloc_mem, ctx );
  fd_stake_decode_inner( &self->stake, alloc_mem, ctx );
  fd_stake_flags_decode_inner( &self->stake_flags, alloc_mem, ctx );
}
void * fd_stake_state_v2_stake_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_state_v2_stake_t * self = (fd_stake_state_v2_stake_t *)mem;
  fd_stake_state_v2_stake_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_stake_state_v2_stake_t);
  void * * alloc_mem = &alloc_region;
  fd_stake_state_v2_stake_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_stake_state_v2_stake_walk( void * w, fd_stake_state_v2_stake_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_stake_state_v2_stake", level++, 0 );
  fd_stake_meta_walk( w, &self->meta, fun, "meta", level, 0 );
  fd_stake_walk( w, &self->stake, fun, "stake", level, 0 );
  fd_stake_flags_walk( w, &self->stake_flags, fun, "stake_flags", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_stake_state_v2_stake", level--, 0 );
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
void fd_stake_state_v2_inner_new( fd_stake_state_v2_inner_t * self, uint discriminant );
int fd_stake_state_v2_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_stake_state_v2_initialized_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_stake_state_v2_stake_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_stake_state_v2_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_stake_state_v2_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_stake_state_v2_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_state_v2_t);
  void const * start_data = ctx->data;
  int err =  fd_stake_state_v2_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_stake_state_v2_inner_decode_inner( fd_stake_state_v2_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_stake_state_v2_initialized_decode_inner( &self->initialized, alloc_mem, ctx );
    break;
  }
  case 2: {
    fd_stake_state_v2_stake_decode_inner( &self->stake, alloc_mem, ctx );
    break;
  }
  case 3: {
    break;
  }
  }
}
static void fd_stake_state_v2_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_state_v2_t * self = (fd_stake_state_v2_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_stake_state_v2_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_stake_state_v2_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_stake_state_v2_t * self = (fd_stake_state_v2_t *)mem;
  fd_stake_state_v2_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_stake_state_v2_t);
  void * * alloc_mem = &alloc_region;
  fd_stake_state_v2_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_stake_state_v2_inner_new( fd_stake_state_v2_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    break;
  }
  case 1: {
    fd_stake_state_v2_initialized_new( &self->initialized );
    break;
  }
  case 2: {
    fd_stake_state_v2_stake_new( &self->stake );
    break;
  }
  case 3: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_stake_state_v2_new_disc( fd_stake_state_v2_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_stake_state_v2_inner_new( &self->inner, self->discriminant );
}
void fd_stake_state_v2_new( fd_stake_state_v2_t * self ) {
  fd_memset( self, 0, sizeof(fd_stake_state_v2_t) );
  fd_stake_state_v2_new_disc( self, UINT_MAX );
}

void fd_stake_state_v2_walk( void * w, fd_stake_state_v2_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_stake_state_v2", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "uninitialized", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "initialized", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_stake_state_v2_initialized_walk( w, &self->inner.initialized, fun, "initialized", level, 0 );
    break;
  }
  case 2: {
    fun( w, self, "stake", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_stake_state_v2_stake_walk( w, &self->inner.stake, fun, "stake", level, 0 );
    break;
  }
  case 3: {
    fun( w, self, "rewards_pool", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_stake_state_v2", level--, 0 );
}
ulong fd_stake_state_v2_size( fd_stake_state_v2_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 1: {
    size += fd_stake_state_v2_initialized_size( &self->inner.initialized );
    break;
  }
  case 2: {
    size += fd_stake_state_v2_stake_size( &self->inner.stake );
    break;
  }
  }
  return size;
}

int fd_stake_state_v2_inner_encode( fd_stake_state_v2_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 1: {
    err = fd_stake_state_v2_initialized_encode( &self->initialized, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 2: {
    err = fd_stake_state_v2_stake_encode( &self->stake, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_stake_state_v2_encode( fd_stake_state_v2_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_stake_state_v2_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_nonce_data_encode( fd_nonce_data_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->authority, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_hash_encode( &self->durable_nonce, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_fee_calculator_encode( &self->fee_calculator, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_nonce_data_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 72UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 72UL );
  return 0;
}
static void fd_nonce_data_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_nonce_data_t * self = (fd_nonce_data_t *)struct_mem;
  fd_pubkey_decode_inner( &self->authority, alloc_mem, ctx );
  fd_hash_decode_inner( &self->durable_nonce, alloc_mem, ctx );
  fd_fee_calculator_decode_inner( &self->fee_calculator, alloc_mem, ctx );
}
void * fd_nonce_data_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_nonce_data_t * self = (fd_nonce_data_t *)mem;
  fd_nonce_data_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_nonce_data_t);
  void * * alloc_mem = &alloc_region;
  fd_nonce_data_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_nonce_data_walk( void * w, fd_nonce_data_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_nonce_data", level++, 0 );
  fd_pubkey_walk( w, &self->authority, fun, "authority", level, 0 );
  fd_hash_walk( w, &self->durable_nonce, fun, "durable_nonce", level, 0 );
  fd_fee_calculator_walk( w, &self->fee_calculator, fun, "fee_calculator", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_nonce_data", level--, 0 );
}
FD_FN_PURE uchar fd_nonce_state_is_uninitialized(fd_nonce_state_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_nonce_state_is_initialized(fd_nonce_state_t const * self) {
  return self->discriminant == 1;
}
void fd_nonce_state_inner_new( fd_nonce_state_inner_t * self, uint discriminant );
int fd_nonce_state_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_nonce_data_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_nonce_state_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_nonce_state_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_nonce_state_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_nonce_state_t);
  void const * start_data = ctx->data;
  int err =  fd_nonce_state_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_nonce_state_inner_decode_inner( fd_nonce_state_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_nonce_data_decode_inner( &self->initialized, alloc_mem, ctx );
    break;
  }
  }
}
static void fd_nonce_state_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_nonce_state_t * self = (fd_nonce_state_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_nonce_state_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_nonce_state_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_nonce_state_t * self = (fd_nonce_state_t *)mem;
  fd_nonce_state_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_nonce_state_t);
  void * * alloc_mem = &alloc_region;
  fd_nonce_state_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_nonce_state_inner_new( fd_nonce_state_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    break;
  }
  case 1: {
    fd_nonce_data_new( &self->initialized );
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_nonce_state_new_disc( fd_nonce_state_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_nonce_state_inner_new( &self->inner, self->discriminant );
}
void fd_nonce_state_new( fd_nonce_state_t * self ) {
  fd_memset( self, 0, sizeof(fd_nonce_state_t) );
  fd_nonce_state_new_disc( self, UINT_MAX );
}

void fd_nonce_state_walk( void * w, fd_nonce_state_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_nonce_state", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "uninitialized", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "initialized", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_nonce_data_walk( w, &self->inner.initialized, fun, "initialized", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_nonce_state", level--, 0 );
}
ulong fd_nonce_state_size( fd_nonce_state_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 1: {
    size += fd_nonce_data_size( &self->inner.initialized );
    break;
  }
  }
  return size;
}

int fd_nonce_state_inner_encode( fd_nonce_state_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 1: {
    err = fd_nonce_data_encode( &self->initialized, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_nonce_state_encode( fd_nonce_state_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_nonce_state_inner_encode( &self->inner, self->discriminant, ctx );
}

FD_FN_PURE uchar fd_nonce_state_versions_is_legacy(fd_nonce_state_versions_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_nonce_state_versions_is_current(fd_nonce_state_versions_t const * self) {
  return self->discriminant == 1;
}
void fd_nonce_state_versions_inner_new( fd_nonce_state_versions_inner_t * self, uint discriminant );
int fd_nonce_state_versions_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_nonce_state_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_nonce_state_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_nonce_state_versions_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_nonce_state_versions_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_nonce_state_versions_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_nonce_state_versions_t);
  void const * start_data = ctx->data;
  int err =  fd_nonce_state_versions_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_nonce_state_versions_inner_decode_inner( fd_nonce_state_versions_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    fd_nonce_state_decode_inner( &self->legacy, alloc_mem, ctx );
    break;
  }
  case 1: {
    fd_nonce_state_decode_inner( &self->current, alloc_mem, ctx );
    break;
  }
  }
}
static void fd_nonce_state_versions_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_nonce_state_versions_t * self = (fd_nonce_state_versions_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_nonce_state_versions_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_nonce_state_versions_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_nonce_state_versions_t * self = (fd_nonce_state_versions_t *)mem;
  fd_nonce_state_versions_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_nonce_state_versions_t);
  void * * alloc_mem = &alloc_region;
  fd_nonce_state_versions_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_nonce_state_versions_inner_new( fd_nonce_state_versions_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    fd_nonce_state_new( &self->legacy );
    break;
  }
  case 1: {
    fd_nonce_state_new( &self->current );
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_nonce_state_versions_new_disc( fd_nonce_state_versions_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_nonce_state_versions_inner_new( &self->inner, self->discriminant );
}
void fd_nonce_state_versions_new( fd_nonce_state_versions_t * self ) {
  fd_memset( self, 0, sizeof(fd_nonce_state_versions_t) );
  fd_nonce_state_versions_new_disc( self, UINT_MAX );
}

void fd_nonce_state_versions_walk( void * w, fd_nonce_state_versions_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_nonce_state_versions", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "legacy", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_nonce_state_walk( w, &self->inner.legacy, fun, "legacy", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "current", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_nonce_state_walk( w, &self->inner.current, fun, "current", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_nonce_state_versions", level--, 0 );
}
ulong fd_nonce_state_versions_size( fd_nonce_state_versions_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_nonce_state_size( &self->inner.legacy );
    break;
  }
  case 1: {
    size += fd_nonce_state_size( &self->inner.current );
    break;
  }
  }
  return size;
}

int fd_nonce_state_versions_inner_encode( fd_nonce_state_versions_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_nonce_state_encode( &self->legacy, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 1: {
    err = fd_nonce_state_encode( &self->current, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_nonce_state_versions_encode( fd_nonce_state_versions_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_nonce_state_versions_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_compute_budget_program_instruction_request_units_deprecated_encode( fd_compute_budget_program_instruction_request_units_deprecated_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint32_encode( self->units, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint32_encode( self->additional_fee, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_compute_budget_program_instruction_request_units_deprecated_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 8UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 8UL );
  return 0;
}
static void fd_compute_budget_program_instruction_request_units_deprecated_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_compute_budget_program_instruction_request_units_deprecated_t * self = (fd_compute_budget_program_instruction_request_units_deprecated_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->units, ctx );
  fd_bincode_uint32_decode_unsafe( &self->additional_fee, ctx );
}
void * fd_compute_budget_program_instruction_request_units_deprecated_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_compute_budget_program_instruction_request_units_deprecated_t * self = (fd_compute_budget_program_instruction_request_units_deprecated_t *)mem;
  fd_compute_budget_program_instruction_request_units_deprecated_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_compute_budget_program_instruction_request_units_deprecated_t);
  void * * alloc_mem = &alloc_region;
  fd_compute_budget_program_instruction_request_units_deprecated_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_compute_budget_program_instruction_request_units_deprecated_walk( void * w, fd_compute_budget_program_instruction_request_units_deprecated_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_compute_budget_program_instruction_request_units_deprecated", level++, 0 );
  fun( w, &self->units, "units", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, &self->additional_fee, "additional_fee", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_compute_budget_program_instruction_request_units_deprecated", level--, 0 );
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
void fd_compute_budget_program_instruction_inner_new( fd_compute_budget_program_instruction_inner_t * self, uint discriminant );
int fd_compute_budget_program_instruction_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_compute_budget_program_instruction_request_units_deprecated_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_bincode_uint32_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_bincode_uint32_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    err = fd_bincode_uint64_decode_footprint( ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    err = fd_bincode_uint32_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_compute_budget_program_instruction_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ushort discriminant = 0;
  int err = fd_bincode_compact_u16_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_compute_budget_program_instruction_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_compute_budget_program_instruction_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_compute_budget_program_instruction_t);
  void const * start_data = ctx->data;
  int err =  fd_compute_budget_program_instruction_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_compute_budget_program_instruction_inner_decode_inner( fd_compute_budget_program_instruction_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    fd_compute_budget_program_instruction_request_units_deprecated_decode_inner( &self->request_units_deprecated, alloc_mem, ctx );
    break;
  }
  case 1: {
    fd_bincode_uint32_decode_unsafe( &self->request_heap_frame, ctx );
    break;
  }
  case 2: {
    fd_bincode_uint32_decode_unsafe( &self->set_compute_unit_limit, ctx );
    break;
  }
  case 3: {
    fd_bincode_uint64_decode_unsafe( &self->set_compute_unit_price, ctx );
    break;
  }
  case 4: {
    fd_bincode_uint32_decode_unsafe( &self->set_loaded_accounts_data_size_limit, ctx );
    break;
  }
  }
}
static void fd_compute_budget_program_instruction_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_compute_budget_program_instruction_t * self = (fd_compute_budget_program_instruction_t *)struct_mem;
  ushort tmp = 0;
  fd_bincode_compact_u16_decode_unsafe( &tmp, ctx );
  self->discriminant = tmp;
  fd_compute_budget_program_instruction_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_compute_budget_program_instruction_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_compute_budget_program_instruction_t * self = (fd_compute_budget_program_instruction_t *)mem;
  fd_compute_budget_program_instruction_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_compute_budget_program_instruction_t);
  void * * alloc_mem = &alloc_region;
  fd_compute_budget_program_instruction_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_compute_budget_program_instruction_inner_new( fd_compute_budget_program_instruction_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    fd_compute_budget_program_instruction_request_units_deprecated_new( &self->request_units_deprecated );
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
void fd_compute_budget_program_instruction_new_disc( fd_compute_budget_program_instruction_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_compute_budget_program_instruction_inner_new( &self->inner, self->discriminant );
}
void fd_compute_budget_program_instruction_new( fd_compute_budget_program_instruction_t * self ) {
  fd_memset( self, 0, sizeof(fd_compute_budget_program_instruction_t) );
  fd_compute_budget_program_instruction_new_disc( self, UINT_MAX );
}

void fd_compute_budget_program_instruction_walk( void * w, fd_compute_budget_program_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_compute_budget_program_instruction", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "request_units_deprecated", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_compute_budget_program_instruction_request_units_deprecated_walk( w, &self->inner.request_units_deprecated, fun, "request_units_deprecated", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "request_heap_frame", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
  fun( w, &self->inner.request_heap_frame, "request_heap_frame", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
    break;
  }
  case 2: {
    fun( w, self, "set_compute_unit_limit", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
  fun( w, &self->inner.set_compute_unit_limit, "set_compute_unit_limit", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
    break;
  }
  case 3: {
    fun( w, self, "set_compute_unit_price", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
  fun( w, &self->inner.set_compute_unit_price, "set_compute_unit_price", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
    break;
  }
  case 4: {
    fun( w, self, "set_loaded_accounts_data_size_limit", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
  fun( w, &self->inner.set_loaded_accounts_data_size_limit, "set_loaded_accounts_data_size_limit", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_compute_budget_program_instruction", level--, 0 );
}
ulong fd_compute_budget_program_instruction_size( fd_compute_budget_program_instruction_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_compute_budget_program_instruction_request_units_deprecated_size( &self->inner.request_units_deprecated );
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

int fd_compute_budget_program_instruction_inner_encode( fd_compute_budget_program_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_compute_budget_program_instruction_request_units_deprecated_encode( &self->request_units_deprecated, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 1: {
    err = fd_bincode_uint32_encode( self->request_heap_frame, ctx );
  if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 2: {
    err = fd_bincode_uint32_encode( self->set_compute_unit_limit, ctx );
  if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 3: {
    err = fd_bincode_uint64_encode( self->set_compute_unit_price, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 4: {
    err = fd_bincode_uint32_encode( self->set_loaded_accounts_data_size_limit, ctx );
  if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_compute_budget_program_instruction_encode( fd_compute_budget_program_instruction_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  ushort discriminant = (ushort) self->discriminant;
  int err = fd_bincode_compact_u16_encode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_compute_budget_program_instruction_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_config_keys_encode( fd_config_keys_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_compact_u16_encode( &self->keys_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->keys_len ) {
    for( ulong i=0; i < self->keys_len; i++ ) {
      err = fd_config_keys_pair_encode( self->keys + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_config_keys_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ushort keys_len;
  err = fd_bincode_compact_u16_decode( &keys_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( keys_len ) {
    *total_sz += FD_CONFIG_KEYS_PAIR_ALIGN + sizeof(fd_config_keys_pair_t)*keys_len;
    for( ulong i=0; i < keys_len; i++ ) {
      err = fd_config_keys_pair_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_config_keys_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_config_keys_t);
  void const * start_data = ctx->data;
  int err = fd_config_keys_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_config_keys_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_config_keys_t * self = (fd_config_keys_t *)struct_mem;
  fd_bincode_compact_u16_decode_unsafe( &self->keys_len, ctx );
  if( self->keys_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_CONFIG_KEYS_PAIR_ALIGN );
    self->keys = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_config_keys_pair_t)*self->keys_len;
    for( ulong i=0; i < self->keys_len; i++ ) {
      fd_config_keys_pair_new( self->keys + i );
      fd_config_keys_pair_decode_inner( self->keys + i, alloc_mem, ctx );
    }
  } else
    self->keys = NULL;
}
void * fd_config_keys_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_config_keys_t * self = (fd_config_keys_t *)mem;
  fd_config_keys_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_config_keys_t);
  void * * alloc_mem = &alloc_region;
  fd_config_keys_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_config_keys_new(fd_config_keys_t * self) {
  fd_memset( self, 0, sizeof(fd_config_keys_t) );
}
void fd_config_keys_walk( void * w, fd_config_keys_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_config_keys", level++, 0 );
  fun( w, &self->keys_len, "keys_len", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 1 );
  if( self->keys_len ) {
    fun( w, NULL, "keys", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->keys_len; i++ )
      fd_config_keys_pair_walk(w, self->keys + i, fun, "config_keys_pair", level, 0 );
    fun( w, NULL, "keys", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_config_keys", level--, 0 );
}
ulong fd_config_keys_size( fd_config_keys_t const * self ) {
  ulong size = 0;
  do {
    ushort tmp = (ushort)self->keys_len;
    size += fd_bincode_compact_u16_size( &tmp );
    for( ulong i=0; i < self->keys_len; i++ )
      size += fd_config_keys_pair_size( self->keys + i );
  } while(0);
  return size;
}

int fd_bpf_loader_program_instruction_write_encode( fd_bpf_loader_program_instruction_write_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint32_encode( self->offset, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->bytes_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->bytes_len ) {
    err = fd_bincode_bytes_encode( self->bytes, self->bytes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_bpf_loader_program_instruction_write_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint32_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong bytes_len;
  err = fd_bincode_uint64_decode( &bytes_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( bytes_len ) {
    *total_sz += 8UL + bytes_len;
    err = fd_bincode_bytes_decode_footprint( bytes_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return 0;
}
int fd_bpf_loader_program_instruction_write_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_bpf_loader_program_instruction_write_t);
  void const * start_data = ctx->data;
  int err = fd_bpf_loader_program_instruction_write_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_bpf_loader_program_instruction_write_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_loader_program_instruction_write_t * self = (fd_bpf_loader_program_instruction_write_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->offset, ctx );
  fd_bincode_uint64_decode_unsafe( &self->bytes_len, ctx );
  if( self->bytes_len ) {
    self->bytes = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->bytes, self->bytes_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->bytes_len;
  } else
    self->bytes = NULL;
}
void * fd_bpf_loader_program_instruction_write_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_loader_program_instruction_write_t * self = (fd_bpf_loader_program_instruction_write_t *)mem;
  fd_bpf_loader_program_instruction_write_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_bpf_loader_program_instruction_write_t);
  void * * alloc_mem = &alloc_region;
  fd_bpf_loader_program_instruction_write_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_bpf_loader_program_instruction_write_new(fd_bpf_loader_program_instruction_write_t * self) {
  fd_memset( self, 0, sizeof(fd_bpf_loader_program_instruction_write_t) );
}
void fd_bpf_loader_program_instruction_write_walk( void * w, fd_bpf_loader_program_instruction_write_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_loader_program_instruction_write", level++, 0 );
  fun( w, &self->offset, "offset", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  if( self->bytes_len ) {
    fun( w, NULL, "bytes", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->bytes_len; i++ )
      fun( w, self->bytes + i, "bytes", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "bytes", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_loader_program_instruction_write", level--, 0 );
}
ulong fd_bpf_loader_program_instruction_write_size( fd_bpf_loader_program_instruction_write_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  do {
    size += sizeof(ulong);
    size += self->bytes_len;
  } while(0);
  return size;
}

FD_FN_PURE uchar fd_bpf_loader_program_instruction_is_write(fd_bpf_loader_program_instruction_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_bpf_loader_program_instruction_is_finalize(fd_bpf_loader_program_instruction_t const * self) {
  return self->discriminant == 1;
}
void fd_bpf_loader_program_instruction_inner_new( fd_bpf_loader_program_instruction_inner_t * self, uint discriminant );
int fd_bpf_loader_program_instruction_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_bpf_loader_program_instruction_write_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_bpf_loader_program_instruction_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_bpf_loader_program_instruction_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_bpf_loader_program_instruction_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_bpf_loader_program_instruction_t);
  void const * start_data = ctx->data;
  int err =  fd_bpf_loader_program_instruction_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_bpf_loader_program_instruction_inner_decode_inner( fd_bpf_loader_program_instruction_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    fd_bpf_loader_program_instruction_write_decode_inner( &self->write, alloc_mem, ctx );
    break;
  }
  case 1: {
    break;
  }
  }
}
static void fd_bpf_loader_program_instruction_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_loader_program_instruction_t * self = (fd_bpf_loader_program_instruction_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_bpf_loader_program_instruction_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_bpf_loader_program_instruction_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_loader_program_instruction_t * self = (fd_bpf_loader_program_instruction_t *)mem;
  fd_bpf_loader_program_instruction_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_bpf_loader_program_instruction_t);
  void * * alloc_mem = &alloc_region;
  fd_bpf_loader_program_instruction_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_bpf_loader_program_instruction_inner_new( fd_bpf_loader_program_instruction_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    fd_bpf_loader_program_instruction_write_new( &self->write );
    break;
  }
  case 1: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_bpf_loader_program_instruction_new_disc( fd_bpf_loader_program_instruction_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_bpf_loader_program_instruction_inner_new( &self->inner, self->discriminant );
}
void fd_bpf_loader_program_instruction_new( fd_bpf_loader_program_instruction_t * self ) {
  fd_memset( self, 0, sizeof(fd_bpf_loader_program_instruction_t) );
  fd_bpf_loader_program_instruction_new_disc( self, UINT_MAX );
}

void fd_bpf_loader_program_instruction_walk( void * w, fd_bpf_loader_program_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_bpf_loader_program_instruction", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "write", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_bpf_loader_program_instruction_write_walk( w, &self->inner.write, fun, "write", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "finalize", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_bpf_loader_program_instruction", level--, 0 );
}
ulong fd_bpf_loader_program_instruction_size( fd_bpf_loader_program_instruction_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_bpf_loader_program_instruction_write_size( &self->inner.write );
    break;
  }
  }
  return size;
}

int fd_bpf_loader_program_instruction_inner_encode( fd_bpf_loader_program_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_bpf_loader_program_instruction_write_encode( &self->write, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_bpf_loader_program_instruction_encode( fd_bpf_loader_program_instruction_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_bpf_loader_program_instruction_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_loader_v4_program_instruction_write_encode( fd_loader_v4_program_instruction_write_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint32_encode( self->offset, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->bytes_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->bytes_len ) {
    err = fd_bincode_bytes_encode( self->bytes, self->bytes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_loader_v4_program_instruction_write_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint32_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong bytes_len;
  err = fd_bincode_uint64_decode( &bytes_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( bytes_len ) {
    *total_sz += 8UL + bytes_len;
    err = fd_bincode_bytes_decode_footprint( bytes_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return 0;
}
int fd_loader_v4_program_instruction_write_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_loader_v4_program_instruction_write_t);
  void const * start_data = ctx->data;
  int err = fd_loader_v4_program_instruction_write_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_loader_v4_program_instruction_write_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_loader_v4_program_instruction_write_t * self = (fd_loader_v4_program_instruction_write_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->offset, ctx );
  fd_bincode_uint64_decode_unsafe( &self->bytes_len, ctx );
  if( self->bytes_len ) {
    self->bytes = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->bytes, self->bytes_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->bytes_len;
  } else
    self->bytes = NULL;
}
void * fd_loader_v4_program_instruction_write_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_loader_v4_program_instruction_write_t * self = (fd_loader_v4_program_instruction_write_t *)mem;
  fd_loader_v4_program_instruction_write_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_loader_v4_program_instruction_write_t);
  void * * alloc_mem = &alloc_region;
  fd_loader_v4_program_instruction_write_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_loader_v4_program_instruction_write_new(fd_loader_v4_program_instruction_write_t * self) {
  fd_memset( self, 0, sizeof(fd_loader_v4_program_instruction_write_t) );
}
void fd_loader_v4_program_instruction_write_walk( void * w, fd_loader_v4_program_instruction_write_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_loader_v4_program_instruction_write", level++, 0 );
  fun( w, &self->offset, "offset", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  if( self->bytes_len ) {
    fun( w, NULL, "bytes", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->bytes_len; i++ )
      fun( w, self->bytes + i, "bytes", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "bytes", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_loader_v4_program_instruction_write", level--, 0 );
}
ulong fd_loader_v4_program_instruction_write_size( fd_loader_v4_program_instruction_write_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  do {
    size += sizeof(ulong);
    size += self->bytes_len;
  } while(0);
  return size;
}

int fd_loader_v4_program_instruction_copy_encode( fd_loader_v4_program_instruction_copy_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint32_encode( self->destination_offset, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint32_encode( self->source_offset, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint32_encode( self->length, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_loader_v4_program_instruction_copy_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 12UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 12UL );
  return 0;
}
static void fd_loader_v4_program_instruction_copy_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_loader_v4_program_instruction_copy_t * self = (fd_loader_v4_program_instruction_copy_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->destination_offset, ctx );
  fd_bincode_uint32_decode_unsafe( &self->source_offset, ctx );
  fd_bincode_uint32_decode_unsafe( &self->length, ctx );
}
void * fd_loader_v4_program_instruction_copy_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_loader_v4_program_instruction_copy_t * self = (fd_loader_v4_program_instruction_copy_t *)mem;
  fd_loader_v4_program_instruction_copy_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_loader_v4_program_instruction_copy_t);
  void * * alloc_mem = &alloc_region;
  fd_loader_v4_program_instruction_copy_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_loader_v4_program_instruction_copy_walk( void * w, fd_loader_v4_program_instruction_copy_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_loader_v4_program_instruction_copy", level++, 0 );
  fun( w, &self->destination_offset, "destination_offset", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, &self->source_offset, "source_offset", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, &self->length, "length", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_loader_v4_program_instruction_copy", level--, 0 );
}
int fd_loader_v4_program_instruction_set_program_length_encode( fd_loader_v4_program_instruction_set_program_length_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint32_encode( self->new_size, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_loader_v4_program_instruction_set_program_length_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 4UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 4UL );
  return 0;
}
static void fd_loader_v4_program_instruction_set_program_length_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_loader_v4_program_instruction_set_program_length_t * self = (fd_loader_v4_program_instruction_set_program_length_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->new_size, ctx );
}
void * fd_loader_v4_program_instruction_set_program_length_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_loader_v4_program_instruction_set_program_length_t * self = (fd_loader_v4_program_instruction_set_program_length_t *)mem;
  fd_loader_v4_program_instruction_set_program_length_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_loader_v4_program_instruction_set_program_length_t);
  void * * alloc_mem = &alloc_region;
  fd_loader_v4_program_instruction_set_program_length_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_loader_v4_program_instruction_set_program_length_walk( void * w, fd_loader_v4_program_instruction_set_program_length_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_loader_v4_program_instruction_set_program_length", level++, 0 );
  fun( w, &self->new_size, "new_size", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_loader_v4_program_instruction_set_program_length", level--, 0 );
}
FD_FN_PURE uchar fd_loader_v4_program_instruction_is_write(fd_loader_v4_program_instruction_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_loader_v4_program_instruction_is_copy(fd_loader_v4_program_instruction_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_loader_v4_program_instruction_is_set_program_length(fd_loader_v4_program_instruction_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_loader_v4_program_instruction_is_deploy(fd_loader_v4_program_instruction_t const * self) {
  return self->discriminant == 3;
}
FD_FN_PURE uchar fd_loader_v4_program_instruction_is_retract(fd_loader_v4_program_instruction_t const * self) {
  return self->discriminant == 4;
}
FD_FN_PURE uchar fd_loader_v4_program_instruction_is_transfer_authority(fd_loader_v4_program_instruction_t const * self) {
  return self->discriminant == 5;
}
FD_FN_PURE uchar fd_loader_v4_program_instruction_is_finalize(fd_loader_v4_program_instruction_t const * self) {
  return self->discriminant == 6;
}
void fd_loader_v4_program_instruction_inner_new( fd_loader_v4_program_instruction_inner_t * self, uint discriminant );
int fd_loader_v4_program_instruction_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_loader_v4_program_instruction_write_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_loader_v4_program_instruction_copy_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_loader_v4_program_instruction_set_program_length_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
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
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_loader_v4_program_instruction_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_loader_v4_program_instruction_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_loader_v4_program_instruction_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_loader_v4_program_instruction_t);
  void const * start_data = ctx->data;
  int err =  fd_loader_v4_program_instruction_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_loader_v4_program_instruction_inner_decode_inner( fd_loader_v4_program_instruction_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    fd_loader_v4_program_instruction_write_decode_inner( &self->write, alloc_mem, ctx );
    break;
  }
  case 1: {
    fd_loader_v4_program_instruction_copy_decode_inner( &self->copy, alloc_mem, ctx );
    break;
  }
  case 2: {
    fd_loader_v4_program_instruction_set_program_length_decode_inner( &self->set_program_length, alloc_mem, ctx );
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
  }
}
static void fd_loader_v4_program_instruction_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_loader_v4_program_instruction_t * self = (fd_loader_v4_program_instruction_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_loader_v4_program_instruction_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_loader_v4_program_instruction_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_loader_v4_program_instruction_t * self = (fd_loader_v4_program_instruction_t *)mem;
  fd_loader_v4_program_instruction_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_loader_v4_program_instruction_t);
  void * * alloc_mem = &alloc_region;
  fd_loader_v4_program_instruction_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_loader_v4_program_instruction_inner_new( fd_loader_v4_program_instruction_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    fd_loader_v4_program_instruction_write_new( &self->write );
    break;
  }
  case 1: {
    fd_loader_v4_program_instruction_copy_new( &self->copy );
    break;
  }
  case 2: {
    fd_loader_v4_program_instruction_set_program_length_new( &self->set_program_length );
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
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_loader_v4_program_instruction_new_disc( fd_loader_v4_program_instruction_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_loader_v4_program_instruction_inner_new( &self->inner, self->discriminant );
}
void fd_loader_v4_program_instruction_new( fd_loader_v4_program_instruction_t * self ) {
  fd_memset( self, 0, sizeof(fd_loader_v4_program_instruction_t) );
  fd_loader_v4_program_instruction_new_disc( self, UINT_MAX );
}

void fd_loader_v4_program_instruction_walk( void * w, fd_loader_v4_program_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_loader_v4_program_instruction", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "write", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_loader_v4_program_instruction_write_walk( w, &self->inner.write, fun, "write", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "copy", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_loader_v4_program_instruction_copy_walk( w, &self->inner.copy, fun, "copy", level, 0 );
    break;
  }
  case 2: {
    fun( w, self, "set_program_length", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_loader_v4_program_instruction_set_program_length_walk( w, &self->inner.set_program_length, fun, "set_program_length", level, 0 );
    break;
  }
  case 3: {
    fun( w, self, "deploy", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 4: {
    fun( w, self, "retract", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 5: {
    fun( w, self, "transfer_authority", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 6: {
    fun( w, self, "finalize", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_loader_v4_program_instruction", level--, 0 );
}
ulong fd_loader_v4_program_instruction_size( fd_loader_v4_program_instruction_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_loader_v4_program_instruction_write_size( &self->inner.write );
    break;
  }
  case 1: {
    size += fd_loader_v4_program_instruction_copy_size( &self->inner.copy );
    break;
  }
  case 2: {
    size += fd_loader_v4_program_instruction_set_program_length_size( &self->inner.set_program_length );
    break;
  }
  }
  return size;
}

int fd_loader_v4_program_instruction_inner_encode( fd_loader_v4_program_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_loader_v4_program_instruction_write_encode( &self->write, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 1: {
    err = fd_loader_v4_program_instruction_copy_encode( &self->copy, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 2: {
    err = fd_loader_v4_program_instruction_set_program_length_encode( &self->set_program_length, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_loader_v4_program_instruction_encode( fd_loader_v4_program_instruction_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_loader_v4_program_instruction_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_bpf_upgradeable_loader_program_instruction_write_encode( fd_bpf_upgradeable_loader_program_instruction_write_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint32_encode( self->offset, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->bytes_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->bytes_len ) {
    err = fd_bincode_bytes_encode( self->bytes, self->bytes_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_bpf_upgradeable_loader_program_instruction_write_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint32_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong bytes_len;
  err = fd_bincode_uint64_decode( &bytes_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( bytes_len ) {
    *total_sz += 8UL + bytes_len;
    err = fd_bincode_bytes_decode_footprint( bytes_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return 0;
}
int fd_bpf_upgradeable_loader_program_instruction_write_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_bpf_upgradeable_loader_program_instruction_write_t);
  void const * start_data = ctx->data;
  int err = fd_bpf_upgradeable_loader_program_instruction_write_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_bpf_upgradeable_loader_program_instruction_write_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_upgradeable_loader_program_instruction_write_t * self = (fd_bpf_upgradeable_loader_program_instruction_write_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->offset, ctx );
  fd_bincode_uint64_decode_unsafe( &self->bytes_len, ctx );
  if( self->bytes_len ) {
    self->bytes = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->bytes, self->bytes_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->bytes_len;
  } else
    self->bytes = NULL;
}
void * fd_bpf_upgradeable_loader_program_instruction_write_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_upgradeable_loader_program_instruction_write_t * self = (fd_bpf_upgradeable_loader_program_instruction_write_t *)mem;
  fd_bpf_upgradeable_loader_program_instruction_write_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_bpf_upgradeable_loader_program_instruction_write_t);
  void * * alloc_mem = &alloc_region;
  fd_bpf_upgradeable_loader_program_instruction_write_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_bpf_upgradeable_loader_program_instruction_write_new(fd_bpf_upgradeable_loader_program_instruction_write_t * self) {
  fd_memset( self, 0, sizeof(fd_bpf_upgradeable_loader_program_instruction_write_t) );
}
void fd_bpf_upgradeable_loader_program_instruction_write_walk( void * w, fd_bpf_upgradeable_loader_program_instruction_write_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_upgradeable_loader_program_instruction_write", level++, 0 );
  fun( w, &self->offset, "offset", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  if( self->bytes_len ) {
    fun( w, NULL, "bytes", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->bytes_len; i++ )
      fun( w, self->bytes + i, "bytes", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "bytes", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_upgradeable_loader_program_instruction_write", level--, 0 );
}
ulong fd_bpf_upgradeable_loader_program_instruction_write_size( fd_bpf_upgradeable_loader_program_instruction_write_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  do {
    size += sizeof(ulong);
    size += self->bytes_len;
  } while(0);
  return size;
}

int fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_encode( fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->max_data_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 8UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 8UL );
  return 0;
}
static void fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t * self = (fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->max_data_len, ctx );
}
void * fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t * self = (fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t *)mem;
  fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t);
  void * * alloc_mem = &alloc_region;
  fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_walk( void * w, fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len", level++, 0 );
  fun( w, &self->max_data_len, "max_data_len", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len", level--, 0 );
}
int fd_bpf_upgradeable_loader_program_instruction_extend_program_encode( fd_bpf_upgradeable_loader_program_instruction_extend_program_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint32_encode( self->additional_bytes, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_bpf_upgradeable_loader_program_instruction_extend_program_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 4UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 4UL );
  return 0;
}
static void fd_bpf_upgradeable_loader_program_instruction_extend_program_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_upgradeable_loader_program_instruction_extend_program_t * self = (fd_bpf_upgradeable_loader_program_instruction_extend_program_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->additional_bytes, ctx );
}
void * fd_bpf_upgradeable_loader_program_instruction_extend_program_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_upgradeable_loader_program_instruction_extend_program_t * self = (fd_bpf_upgradeable_loader_program_instruction_extend_program_t *)mem;
  fd_bpf_upgradeable_loader_program_instruction_extend_program_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_bpf_upgradeable_loader_program_instruction_extend_program_t);
  void * * alloc_mem = &alloc_region;
  fd_bpf_upgradeable_loader_program_instruction_extend_program_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_bpf_upgradeable_loader_program_instruction_extend_program_walk( void * w, fd_bpf_upgradeable_loader_program_instruction_extend_program_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_upgradeable_loader_program_instruction_extend_program", level++, 0 );
  fun( w, &self->additional_bytes, "additional_bytes", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_upgradeable_loader_program_instruction_extend_program", level--, 0 );
}
int fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_encode( fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint32_encode( self->additional_bytes, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 4UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 4UL );
  return 0;
}
static void fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_t * self = (fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->additional_bytes, ctx );
}
void * fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_t * self = (fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_t *)mem;
  fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_t);
  void * * alloc_mem = &alloc_region;
  fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_walk( void * w, fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_upgradeable_loader_program_instruction_extend_program_checked", level++, 0 );
  fun( w, &self->additional_bytes, "additional_bytes", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_upgradeable_loader_program_instruction_extend_program_checked", level--, 0 );
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
FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_migrate(fd_bpf_upgradeable_loader_program_instruction_t const * self) {
  return self->discriminant == 8;
}
FD_FN_PURE uchar fd_bpf_upgradeable_loader_program_instruction_is_extend_program_checked(fd_bpf_upgradeable_loader_program_instruction_t const * self) {
  return self->discriminant == 9;
}
void fd_bpf_upgradeable_loader_program_instruction_inner_new( fd_bpf_upgradeable_loader_program_instruction_inner_t * self, uint discriminant );
int fd_bpf_upgradeable_loader_program_instruction_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_bpf_upgradeable_loader_program_instruction_write_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
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
    err = fd_bpf_upgradeable_loader_program_instruction_extend_program_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 7: {
    return FD_BINCODE_SUCCESS;
  }
  case 8: {
    return FD_BINCODE_SUCCESS;
  }
  case 9: {
    err = fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_bpf_upgradeable_loader_program_instruction_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_bpf_upgradeable_loader_program_instruction_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_bpf_upgradeable_loader_program_instruction_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_bpf_upgradeable_loader_program_instruction_t);
  void const * start_data = ctx->data;
  int err =  fd_bpf_upgradeable_loader_program_instruction_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_bpf_upgradeable_loader_program_instruction_inner_decode_inner( fd_bpf_upgradeable_loader_program_instruction_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_bpf_upgradeable_loader_program_instruction_write_decode_inner( &self->write, alloc_mem, ctx );
    break;
  }
  case 2: {
    fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_decode_inner( &self->deploy_with_max_data_len, alloc_mem, ctx );
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
    fd_bpf_upgradeable_loader_program_instruction_extend_program_decode_inner( &self->extend_program, alloc_mem, ctx );
    break;
  }
  case 7: {
    break;
  }
  case 8: {
    break;
  }
  case 9: {
    fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_decode_inner( &self->extend_program_checked, alloc_mem, ctx );
    break;
  }
  }
}
static void fd_bpf_upgradeable_loader_program_instruction_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_upgradeable_loader_program_instruction_t * self = (fd_bpf_upgradeable_loader_program_instruction_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_bpf_upgradeable_loader_program_instruction_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_bpf_upgradeable_loader_program_instruction_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_upgradeable_loader_program_instruction_t * self = (fd_bpf_upgradeable_loader_program_instruction_t *)mem;
  fd_bpf_upgradeable_loader_program_instruction_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_bpf_upgradeable_loader_program_instruction_t);
  void * * alloc_mem = &alloc_region;
  fd_bpf_upgradeable_loader_program_instruction_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_bpf_upgradeable_loader_program_instruction_inner_new( fd_bpf_upgradeable_loader_program_instruction_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    break;
  }
  case 1: {
    fd_bpf_upgradeable_loader_program_instruction_write_new( &self->write );
    break;
  }
  case 2: {
    fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_new( &self->deploy_with_max_data_len );
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
    fd_bpf_upgradeable_loader_program_instruction_extend_program_new( &self->extend_program );
    break;
  }
  case 7: {
    break;
  }
  case 8: {
    break;
  }
  case 9: {
    fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_new( &self->extend_program_checked );
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_bpf_upgradeable_loader_program_instruction_new_disc( fd_bpf_upgradeable_loader_program_instruction_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_bpf_upgradeable_loader_program_instruction_inner_new( &self->inner, self->discriminant );
}
void fd_bpf_upgradeable_loader_program_instruction_new( fd_bpf_upgradeable_loader_program_instruction_t * self ) {
  fd_memset( self, 0, sizeof(fd_bpf_upgradeable_loader_program_instruction_t) );
  fd_bpf_upgradeable_loader_program_instruction_new_disc( self, UINT_MAX );
}

void fd_bpf_upgradeable_loader_program_instruction_walk( void * w, fd_bpf_upgradeable_loader_program_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_bpf_upgradeable_loader_program_instruction", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "initialize_buffer", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "write", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_bpf_upgradeable_loader_program_instruction_write_walk( w, &self->inner.write, fun, "write", level, 0 );
    break;
  }
  case 2: {
    fun( w, self, "deploy_with_max_data_len", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_walk( w, &self->inner.deploy_with_max_data_len, fun, "deploy_with_max_data_len", level, 0 );
    break;
  }
  case 3: {
    fun( w, self, "upgrade", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 4: {
    fun( w, self, "set_authority", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 5: {
    fun( w, self, "close", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 6: {
    fun( w, self, "extend_program", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_bpf_upgradeable_loader_program_instruction_extend_program_walk( w, &self->inner.extend_program, fun, "extend_program", level, 0 );
    break;
  }
  case 7: {
    fun( w, self, "set_authority_checked", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 8: {
    fun( w, self, "migrate", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 9: {
    fun( w, self, "extend_program_checked", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_walk( w, &self->inner.extend_program_checked, fun, "extend_program_checked", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_bpf_upgradeable_loader_program_instruction", level--, 0 );
}
ulong fd_bpf_upgradeable_loader_program_instruction_size( fd_bpf_upgradeable_loader_program_instruction_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 1: {
    size += fd_bpf_upgradeable_loader_program_instruction_write_size( &self->inner.write );
    break;
  }
  case 2: {
    size += fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_size( &self->inner.deploy_with_max_data_len );
    break;
  }
  case 6: {
    size += fd_bpf_upgradeable_loader_program_instruction_extend_program_size( &self->inner.extend_program );
    break;
  }
  case 9: {
    size += fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_size( &self->inner.extend_program_checked );
    break;
  }
  }
  return size;
}

int fd_bpf_upgradeable_loader_program_instruction_inner_encode( fd_bpf_upgradeable_loader_program_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 1: {
    err = fd_bpf_upgradeable_loader_program_instruction_write_encode( &self->write, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 2: {
    err = fd_bpf_upgradeable_loader_program_instruction_deploy_with_max_data_len_encode( &self->deploy_with_max_data_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 6: {
    err = fd_bpf_upgradeable_loader_program_instruction_extend_program_encode( &self->extend_program, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 9: {
    err = fd_bpf_upgradeable_loader_program_instruction_extend_program_checked_encode( &self->extend_program_checked, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_bpf_upgradeable_loader_program_instruction_encode( fd_bpf_upgradeable_loader_program_instruction_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_bpf_upgradeable_loader_program_instruction_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_bpf_upgradeable_loader_state_buffer_encode( fd_bpf_upgradeable_loader_state_buffer_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_bool_encode( self->has_authority_address, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_authority_address ) {
    err = fd_pubkey_encode( &self->authority_address, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_bpf_upgradeable_loader_state_buffer_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_bpf_upgradeable_loader_state_buffer_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_bpf_upgradeable_loader_state_buffer_t);
  void const * start_data = ctx->data;
  int err = fd_bpf_upgradeable_loader_state_buffer_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_bpf_upgradeable_loader_state_buffer_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_upgradeable_loader_state_buffer_t * self = (fd_bpf_upgradeable_loader_state_buffer_t *)struct_mem;
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_authority_address = !!o;
    if( o ) {
      fd_pubkey_new( &self->authority_address );
      fd_pubkey_decode_inner( &self->authority_address, alloc_mem, ctx );
    }
  }
}
void * fd_bpf_upgradeable_loader_state_buffer_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_upgradeable_loader_state_buffer_t * self = (fd_bpf_upgradeable_loader_state_buffer_t *)mem;
  fd_bpf_upgradeable_loader_state_buffer_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_bpf_upgradeable_loader_state_buffer_t);
  void * * alloc_mem = &alloc_region;
  fd_bpf_upgradeable_loader_state_buffer_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_bpf_upgradeable_loader_state_buffer_new(fd_bpf_upgradeable_loader_state_buffer_t * self) {
  fd_memset( self, 0, sizeof(fd_bpf_upgradeable_loader_state_buffer_t) );
}
void fd_bpf_upgradeable_loader_state_buffer_walk( void * w, fd_bpf_upgradeable_loader_state_buffer_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_upgradeable_loader_state_buffer", level++, 0 );
  if( !self->has_authority_address ) {
    fun( w, NULL, "authority_address", FD_FLAMENCO_TYPE_NULL, "pubkey", level, 0 );
  } else {
    fd_pubkey_walk( w, &self->authority_address, fun, "authority_address", level, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_upgradeable_loader_state_buffer", level--, 0 );
}
ulong fd_bpf_upgradeable_loader_state_buffer_size( fd_bpf_upgradeable_loader_state_buffer_t const * self ) {
  ulong size = 0;
  size += sizeof(char);
  if( self->has_authority_address ) {
    size += fd_pubkey_size( &self->authority_address );
  }
  return size;
}

int fd_bpf_upgradeable_loader_state_program_encode( fd_bpf_upgradeable_loader_state_program_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->programdata_address, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_bpf_upgradeable_loader_state_program_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 32UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 32UL );
  return 0;
}
static void fd_bpf_upgradeable_loader_state_program_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_upgradeable_loader_state_program_t * self = (fd_bpf_upgradeable_loader_state_program_t *)struct_mem;
  fd_pubkey_decode_inner( &self->programdata_address, alloc_mem, ctx );
}
void * fd_bpf_upgradeable_loader_state_program_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_upgradeable_loader_state_program_t * self = (fd_bpf_upgradeable_loader_state_program_t *)mem;
  fd_bpf_upgradeable_loader_state_program_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_bpf_upgradeable_loader_state_program_t);
  void * * alloc_mem = &alloc_region;
  fd_bpf_upgradeable_loader_state_program_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_bpf_upgradeable_loader_state_program_walk( void * w, fd_bpf_upgradeable_loader_state_program_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_upgradeable_loader_state_program", level++, 0 );
  fd_pubkey_walk( w, &self->programdata_address, fun, "programdata_address", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_upgradeable_loader_state_program", level--, 0 );
}
int fd_bpf_upgradeable_loader_state_program_data_encode( fd_bpf_upgradeable_loader_state_program_data_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_encode( self->has_upgrade_authority_address, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_upgrade_authority_address ) {
    err = fd_pubkey_encode( &self->upgrade_authority_address, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_bpf_upgradeable_loader_state_program_data_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_bpf_upgradeable_loader_state_program_data_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_bpf_upgradeable_loader_state_program_data_t);
  void const * start_data = ctx->data;
  int err = fd_bpf_upgradeable_loader_state_program_data_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_bpf_upgradeable_loader_state_program_data_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_upgradeable_loader_state_program_data_t * self = (fd_bpf_upgradeable_loader_state_program_data_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->slot, ctx );
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_upgrade_authority_address = !!o;
    if( o ) {
      fd_pubkey_new( &self->upgrade_authority_address );
      fd_pubkey_decode_inner( &self->upgrade_authority_address, alloc_mem, ctx );
    }
  }
}
void * fd_bpf_upgradeable_loader_state_program_data_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_upgradeable_loader_state_program_data_t * self = (fd_bpf_upgradeable_loader_state_program_data_t *)mem;
  fd_bpf_upgradeable_loader_state_program_data_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_bpf_upgradeable_loader_state_program_data_t);
  void * * alloc_mem = &alloc_region;
  fd_bpf_upgradeable_loader_state_program_data_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_bpf_upgradeable_loader_state_program_data_new(fd_bpf_upgradeable_loader_state_program_data_t * self) {
  fd_memset( self, 0, sizeof(fd_bpf_upgradeable_loader_state_program_data_t) );
}
void fd_bpf_upgradeable_loader_state_program_data_walk( void * w, fd_bpf_upgradeable_loader_state_program_data_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bpf_upgradeable_loader_state_program_data", level++, 0 );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  if( !self->has_upgrade_authority_address ) {
    fun( w, NULL, "upgrade_authority_address", FD_FLAMENCO_TYPE_NULL, "pubkey", level, 0 );
  } else {
    fd_pubkey_walk( w, &self->upgrade_authority_address, fun, "upgrade_authority_address", level, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bpf_upgradeable_loader_state_program_data", level--, 0 );
}
ulong fd_bpf_upgradeable_loader_state_program_data_size( fd_bpf_upgradeable_loader_state_program_data_t const * self ) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(char);
  if( self->has_upgrade_authority_address ) {
    size += fd_pubkey_size( &self->upgrade_authority_address );
  }
  return size;
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
void fd_bpf_upgradeable_loader_state_inner_new( fd_bpf_upgradeable_loader_state_inner_t * self, uint discriminant );
int fd_bpf_upgradeable_loader_state_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_bpf_upgradeable_loader_state_buffer_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_bpf_upgradeable_loader_state_program_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    err = fd_bpf_upgradeable_loader_state_program_data_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_bpf_upgradeable_loader_state_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_bpf_upgradeable_loader_state_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_bpf_upgradeable_loader_state_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_bpf_upgradeable_loader_state_t);
  void const * start_data = ctx->data;
  int err =  fd_bpf_upgradeable_loader_state_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_bpf_upgradeable_loader_state_inner_decode_inner( fd_bpf_upgradeable_loader_state_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_bpf_upgradeable_loader_state_buffer_decode_inner( &self->buffer, alloc_mem, ctx );
    break;
  }
  case 2: {
    fd_bpf_upgradeable_loader_state_program_decode_inner( &self->program, alloc_mem, ctx );
    break;
  }
  case 3: {
    fd_bpf_upgradeable_loader_state_program_data_decode_inner( &self->program_data, alloc_mem, ctx );
    break;
  }
  }
}
static void fd_bpf_upgradeable_loader_state_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_upgradeable_loader_state_t * self = (fd_bpf_upgradeable_loader_state_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_bpf_upgradeable_loader_state_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_bpf_upgradeable_loader_state_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bpf_upgradeable_loader_state_t * self = (fd_bpf_upgradeable_loader_state_t *)mem;
  fd_bpf_upgradeable_loader_state_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_bpf_upgradeable_loader_state_t);
  void * * alloc_mem = &alloc_region;
  fd_bpf_upgradeable_loader_state_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_bpf_upgradeable_loader_state_inner_new( fd_bpf_upgradeable_loader_state_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    break;
  }
  case 1: {
    fd_bpf_upgradeable_loader_state_buffer_new( &self->buffer );
    break;
  }
  case 2: {
    fd_bpf_upgradeable_loader_state_program_new( &self->program );
    break;
  }
  case 3: {
    fd_bpf_upgradeable_loader_state_program_data_new( &self->program_data );
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_bpf_upgradeable_loader_state_new_disc( fd_bpf_upgradeable_loader_state_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_bpf_upgradeable_loader_state_inner_new( &self->inner, self->discriminant );
}
void fd_bpf_upgradeable_loader_state_new( fd_bpf_upgradeable_loader_state_t * self ) {
  fd_memset( self, 0, sizeof(fd_bpf_upgradeable_loader_state_t) );
  fd_bpf_upgradeable_loader_state_new_disc( self, UINT_MAX );
}

void fd_bpf_upgradeable_loader_state_walk( void * w, fd_bpf_upgradeable_loader_state_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_bpf_upgradeable_loader_state", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "uninitialized", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "buffer", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_bpf_upgradeable_loader_state_buffer_walk( w, &self->inner.buffer, fun, "buffer", level, 0 );
    break;
  }
  case 2: {
    fun( w, self, "program", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_bpf_upgradeable_loader_state_program_walk( w, &self->inner.program, fun, "program", level, 0 );
    break;
  }
  case 3: {
    fun( w, self, "program_data", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_bpf_upgradeable_loader_state_program_data_walk( w, &self->inner.program_data, fun, "program_data", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_bpf_upgradeable_loader_state", level--, 0 );
}
ulong fd_bpf_upgradeable_loader_state_size( fd_bpf_upgradeable_loader_state_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 1: {
    size += fd_bpf_upgradeable_loader_state_buffer_size( &self->inner.buffer );
    break;
  }
  case 2: {
    size += fd_bpf_upgradeable_loader_state_program_size( &self->inner.program );
    break;
  }
  case 3: {
    size += fd_bpf_upgradeable_loader_state_program_data_size( &self->inner.program_data );
    break;
  }
  }
  return size;
}

int fd_bpf_upgradeable_loader_state_inner_encode( fd_bpf_upgradeable_loader_state_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 1: {
    err = fd_bpf_upgradeable_loader_state_buffer_encode( &self->buffer, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 2: {
    err = fd_bpf_upgradeable_loader_state_program_encode( &self->program, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 3: {
    err = fd_bpf_upgradeable_loader_state_program_data_encode( &self->program_data, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_bpf_upgradeable_loader_state_encode( fd_bpf_upgradeable_loader_state_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_bpf_upgradeable_loader_state_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_loader_v4_state_encode( fd_loader_v4_state_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->authority_address_or_next_version, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->status, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_loader_v4_state_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 48UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 48UL );
  return 0;
}
static void fd_loader_v4_state_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_loader_v4_state_t * self = (fd_loader_v4_state_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->slot, ctx );
  fd_pubkey_decode_inner( &self->authority_address_or_next_version, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->status, ctx );
}
void * fd_loader_v4_state_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_loader_v4_state_t * self = (fd_loader_v4_state_t *)mem;
  fd_loader_v4_state_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_loader_v4_state_t);
  void * * alloc_mem = &alloc_region;
  fd_loader_v4_state_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_loader_v4_state_walk( void * w, fd_loader_v4_state_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_loader_v4_state", level++, 0 );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_pubkey_walk( w, &self->authority_address_or_next_version, fun, "authority_address_or_next_version", level, 0 );
  fun( w, &self->status, "status", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_loader_v4_state", level--, 0 );
}
int fd_frozen_hash_status_encode( fd_frozen_hash_status_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_hash_encode( &self->frozen_hash, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_encode( (uchar)(self->is_duplicate_confirmed), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_frozen_hash_status_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_hash_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_frozen_hash_status_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_frozen_hash_status_t);
  void const * start_data = ctx->data;
  int err = fd_frozen_hash_status_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_frozen_hash_status_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_frozen_hash_status_t * self = (fd_frozen_hash_status_t *)struct_mem;
  fd_hash_decode_inner( &self->frozen_hash, alloc_mem, ctx );
  fd_bincode_bool_decode_unsafe( &self->is_duplicate_confirmed, ctx );
}
void * fd_frozen_hash_status_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_frozen_hash_status_t * self = (fd_frozen_hash_status_t *)mem;
  fd_frozen_hash_status_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_frozen_hash_status_t);
  void * * alloc_mem = &alloc_region;
  fd_frozen_hash_status_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_frozen_hash_status_new(fd_frozen_hash_status_t * self) {
  fd_memset( self, 0, sizeof(fd_frozen_hash_status_t) );
  fd_hash_new( &self->frozen_hash );
}
void fd_frozen_hash_status_walk( void * w, fd_frozen_hash_status_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_frozen_hash_status", level++, 0 );
  fd_hash_walk( w, &self->frozen_hash, fun, "frozen_hash", level, 0 );
  fun( w, &self->is_duplicate_confirmed, "is_duplicate_confirmed", FD_FLAMENCO_TYPE_BOOL, "bool", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_frozen_hash_status", level--, 0 );
}
FD_FN_PURE uchar fd_frozen_hash_versioned_is_current(fd_frozen_hash_versioned_t const * self) {
  return self->discriminant == 0;
}
void fd_frozen_hash_versioned_inner_new( fd_frozen_hash_versioned_inner_t * self, uint discriminant );
int fd_frozen_hash_versioned_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_frozen_hash_status_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_frozen_hash_versioned_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_frozen_hash_versioned_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_frozen_hash_versioned_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_frozen_hash_versioned_t);
  void const * start_data = ctx->data;
  int err =  fd_frozen_hash_versioned_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_frozen_hash_versioned_inner_decode_inner( fd_frozen_hash_versioned_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    fd_frozen_hash_status_decode_inner( &self->current, alloc_mem, ctx );
    break;
  }
  }
}
static void fd_frozen_hash_versioned_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_frozen_hash_versioned_t * self = (fd_frozen_hash_versioned_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_frozen_hash_versioned_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_frozen_hash_versioned_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_frozen_hash_versioned_t * self = (fd_frozen_hash_versioned_t *)mem;
  fd_frozen_hash_versioned_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_frozen_hash_versioned_t);
  void * * alloc_mem = &alloc_region;
  fd_frozen_hash_versioned_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_frozen_hash_versioned_inner_new( fd_frozen_hash_versioned_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    fd_frozen_hash_status_new( &self->current );
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_frozen_hash_versioned_new_disc( fd_frozen_hash_versioned_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_frozen_hash_versioned_inner_new( &self->inner, self->discriminant );
}
void fd_frozen_hash_versioned_new( fd_frozen_hash_versioned_t * self ) {
  fd_memset( self, 0, sizeof(fd_frozen_hash_versioned_t) );
  fd_frozen_hash_versioned_new_disc( self, UINT_MAX );
}

void fd_frozen_hash_versioned_walk( void * w, fd_frozen_hash_versioned_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_frozen_hash_versioned", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "current", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_frozen_hash_status_walk( w, &self->inner.current, fun, "current", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_frozen_hash_versioned", level--, 0 );
}
ulong fd_frozen_hash_versioned_size( fd_frozen_hash_versioned_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_frozen_hash_status_size( &self->inner.current );
    break;
  }
  }
  return size;
}

int fd_frozen_hash_versioned_inner_encode( fd_frozen_hash_versioned_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_frozen_hash_status_encode( &self->current, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_frozen_hash_versioned_encode( fd_frozen_hash_versioned_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_frozen_hash_versioned_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_lookup_table_meta_encode( fd_lookup_table_meta_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->deactivation_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->last_extended_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->last_extended_slot_start_index), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_encode( self->has_authority, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_authority ) {
    err = fd_pubkey_encode( &self->authority, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint16_encode( self->_padding, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_lookup_table_meta_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint16_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_lookup_table_meta_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_lookup_table_meta_t);
  void const * start_data = ctx->data;
  int err = fd_lookup_table_meta_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_lookup_table_meta_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_lookup_table_meta_t * self = (fd_lookup_table_meta_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->deactivation_slot, ctx );
  fd_bincode_uint64_decode_unsafe( &self->last_extended_slot, ctx );
  fd_bincode_uint8_decode_unsafe( &self->last_extended_slot_start_index, ctx );
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_authority = !!o;
    if( o ) {
      fd_pubkey_new( &self->authority );
      fd_pubkey_decode_inner( &self->authority, alloc_mem, ctx );
    }
  }
  fd_bincode_uint16_decode_unsafe( &self->_padding, ctx );
}
void * fd_lookup_table_meta_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_lookup_table_meta_t * self = (fd_lookup_table_meta_t *)mem;
  fd_lookup_table_meta_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_lookup_table_meta_t);
  void * * alloc_mem = &alloc_region;
  fd_lookup_table_meta_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_lookup_table_meta_new(fd_lookup_table_meta_t * self) {
  fd_memset( self, 0, sizeof(fd_lookup_table_meta_t) );
}
void fd_lookup_table_meta_walk( void * w, fd_lookup_table_meta_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_lookup_table_meta", level++, 0 );
  fun( w, &self->deactivation_slot, "deactivation_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->last_extended_slot, "last_extended_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->last_extended_slot_start_index, "last_extended_slot_start_index", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  if( !self->has_authority ) {
    fun( w, NULL, "authority", FD_FLAMENCO_TYPE_NULL, "pubkey", level, 0 );
  } else {
    fd_pubkey_walk( w, &self->authority, fun, "authority", level, 0 );
  }
  fun( w, &self->_padding, "_padding", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_lookup_table_meta", level--, 0 );
}
ulong fd_lookup_table_meta_size( fd_lookup_table_meta_t const * self ) {
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

int fd_address_lookup_table_encode( fd_address_lookup_table_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_lookup_table_meta_encode( &self->meta, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_address_lookup_table_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_lookup_table_meta_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_address_lookup_table_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_address_lookup_table_t);
  void const * start_data = ctx->data;
  int err = fd_address_lookup_table_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_address_lookup_table_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_address_lookup_table_t * self = (fd_address_lookup_table_t *)struct_mem;
  fd_lookup_table_meta_decode_inner( &self->meta, alloc_mem, ctx );
}
void * fd_address_lookup_table_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_address_lookup_table_t * self = (fd_address_lookup_table_t *)mem;
  fd_address_lookup_table_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_address_lookup_table_t);
  void * * alloc_mem = &alloc_region;
  fd_address_lookup_table_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_address_lookup_table_new(fd_address_lookup_table_t * self) {
  fd_memset( self, 0, sizeof(fd_address_lookup_table_t) );
  fd_lookup_table_meta_new( &self->meta );
}
void fd_address_lookup_table_walk( void * w, fd_address_lookup_table_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_address_lookup_table", level++, 0 );
  fd_lookup_table_meta_walk( w, &self->meta, fun, "meta", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_address_lookup_table", level--, 0 );
}
ulong fd_address_lookup_table_size( fd_address_lookup_table_t const * self ) {
  ulong size = 0;
  size += fd_lookup_table_meta_size( &self->meta );
  return size;
}

FD_FN_PURE uchar fd_address_lookup_table_state_is_uninitialized(fd_address_lookup_table_state_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_address_lookup_table_state_is_lookup_table(fd_address_lookup_table_state_t const * self) {
  return self->discriminant == 1;
}
void fd_address_lookup_table_state_inner_new( fd_address_lookup_table_state_inner_t * self, uint discriminant );
int fd_address_lookup_table_state_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_address_lookup_table_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_address_lookup_table_state_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_address_lookup_table_state_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_address_lookup_table_state_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_address_lookup_table_state_t);
  void const * start_data = ctx->data;
  int err =  fd_address_lookup_table_state_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_address_lookup_table_state_inner_decode_inner( fd_address_lookup_table_state_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_address_lookup_table_decode_inner( &self->lookup_table, alloc_mem, ctx );
    break;
  }
  }
}
static void fd_address_lookup_table_state_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_address_lookup_table_state_t * self = (fd_address_lookup_table_state_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_address_lookup_table_state_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_address_lookup_table_state_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_address_lookup_table_state_t * self = (fd_address_lookup_table_state_t *)mem;
  fd_address_lookup_table_state_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_address_lookup_table_state_t);
  void * * alloc_mem = &alloc_region;
  fd_address_lookup_table_state_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_address_lookup_table_state_inner_new( fd_address_lookup_table_state_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    break;
  }
  case 1: {
    fd_address_lookup_table_new( &self->lookup_table );
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_address_lookup_table_state_new_disc( fd_address_lookup_table_state_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_address_lookup_table_state_inner_new( &self->inner, self->discriminant );
}
void fd_address_lookup_table_state_new( fd_address_lookup_table_state_t * self ) {
  fd_memset( self, 0, sizeof(fd_address_lookup_table_state_t) );
  fd_address_lookup_table_state_new_disc( self, UINT_MAX );
}

void fd_address_lookup_table_state_walk( void * w, fd_address_lookup_table_state_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_address_lookup_table_state", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "uninitialized", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "lookup_table", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_address_lookup_table_walk( w, &self->inner.lookup_table, fun, "lookup_table", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_address_lookup_table_state", level--, 0 );
}
ulong fd_address_lookup_table_state_size( fd_address_lookup_table_state_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 1: {
    size += fd_address_lookup_table_size( &self->inner.lookup_table );
    break;
  }
  }
  return size;
}

int fd_address_lookup_table_state_inner_encode( fd_address_lookup_table_state_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 1: {
    err = fd_address_lookup_table_encode( &self->lookup_table, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_address_lookup_table_state_encode( fd_address_lookup_table_state_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_address_lookup_table_state_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_gossip_ping_encode( fd_gossip_ping_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->from, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_hash_encode( &self->token, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_signature_encode( &self->signature, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_gossip_ping_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 128UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 128UL );
  return 0;
}
static void fd_gossip_ping_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_ping_t * self = (fd_gossip_ping_t *)struct_mem;
  fd_pubkey_decode_inner( &self->from, alloc_mem, ctx );
  fd_hash_decode_inner( &self->token, alloc_mem, ctx );
  fd_signature_decode_inner( &self->signature, alloc_mem, ctx );
}
void * fd_gossip_ping_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_ping_t * self = (fd_gossip_ping_t *)mem;
  fd_gossip_ping_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_ping_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_ping_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_ping_walk( void * w, fd_gossip_ping_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_ping", level++, 0 );
  fd_pubkey_walk( w, &self->from, fun, "from", level, 0 );
  fd_hash_walk( w, &self->token, fun, "token", level, 0 );
  fd_signature_walk( w, &self->signature, fun, "signature", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_ping", level--, 0 );
}
FD_FN_PURE uchar fd_gossip_ip_addr_is_ip4(fd_gossip_ip_addr_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_gossip_ip_addr_is_ip6(fd_gossip_ip_addr_t const * self) {
  return self->discriminant == 1;
}
void fd_gossip_ip_addr_inner_new( fd_gossip_ip_addr_inner_t * self, uint discriminant );
int fd_gossip_ip_addr_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_ip4_addr_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_gossip_ip6_addr_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_gossip_ip_addr_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_gossip_ip_addr_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_gossip_ip_addr_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_ip_addr_t);
  void const * start_data = ctx->data;
  int err =  fd_gossip_ip_addr_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_ip_addr_inner_decode_inner( fd_gossip_ip_addr_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    fd_gossip_ip4_addr_decode_inner( &self->ip4, alloc_mem, ctx );
    break;
  }
  case 1: {
    fd_gossip_ip6_addr_decode_inner( &self->ip6, alloc_mem, ctx );
    break;
  }
  }
}
static void fd_gossip_ip_addr_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_ip_addr_t * self = (fd_gossip_ip_addr_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_gossip_ip_addr_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_gossip_ip_addr_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_ip_addr_t * self = (fd_gossip_ip_addr_t *)mem;
  fd_gossip_ip_addr_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_ip_addr_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_ip_addr_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_ip_addr_inner_new( fd_gossip_ip_addr_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    fd_gossip_ip4_addr_new( &self->ip4 );
    break;
  }
  case 1: {
    fd_gossip_ip6_addr_new( &self->ip6 );
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_gossip_ip_addr_new_disc( fd_gossip_ip_addr_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_gossip_ip_addr_inner_new( &self->inner, self->discriminant );
}
void fd_gossip_ip_addr_new( fd_gossip_ip_addr_t * self ) {
  fd_memset( self, 0, sizeof(fd_gossip_ip_addr_t) );
  fd_gossip_ip_addr_new_disc( self, UINT_MAX );
}

void fd_gossip_ip_addr_walk( void * w, fd_gossip_ip_addr_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_gossip_ip_addr", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "ip4", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_ip4_addr_walk( w, &self->inner.ip4, fun, "ip4", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "ip6", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_ip6_addr_walk( w, &self->inner.ip6, fun, "ip6", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_gossip_ip_addr", level--, 0 );
}
ulong fd_gossip_ip_addr_size( fd_gossip_ip_addr_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_gossip_ip4_addr_size( &self->inner.ip4 );
    break;
  }
  case 1: {
    size += fd_gossip_ip6_addr_size( &self->inner.ip6 );
    break;
  }
  }
  return size;
}

int fd_gossip_ip_addr_inner_encode( fd_gossip_ip_addr_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_ip4_addr_encode( &self->ip4, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 1: {
    err = fd_gossip_ip6_addr_encode( &self->ip6, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_ip_addr_encode( fd_gossip_ip_addr_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_gossip_ip_addr_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_gossip_prune_data_encode( fd_gossip_prune_data_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->prunes_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->prunes_len ) {
    for( ulong i=0; i < self->prunes_len; i++ ) {
      err = fd_pubkey_encode( self->prunes + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  err = fd_signature_encode( &self->signature, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->destination, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->wallclock, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_prune_data_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ulong prunes_len;
  err = fd_bincode_uint64_decode( &prunes_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( prunes_len ) {
    *total_sz += FD_PUBKEY_ALIGN + sizeof(fd_pubkey_t)*prunes_len;
    for( ulong i=0; i < prunes_len; i++ ) {
      err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_signature_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_gossip_prune_data_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_prune_data_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_prune_data_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_prune_data_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_prune_data_t * self = (fd_gossip_prune_data_t *)struct_mem;
  fd_pubkey_decode_inner( &self->pubkey, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->prunes_len, ctx );
  if( self->prunes_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_PUBKEY_ALIGN );
    self->prunes = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_pubkey_t)*self->prunes_len;
    for( ulong i=0; i < self->prunes_len; i++ ) {
      fd_pubkey_new( self->prunes + i );
      fd_pubkey_decode_inner( self->prunes + i, alloc_mem, ctx );
    }
  } else
    self->prunes = NULL;
  fd_signature_decode_inner( &self->signature, alloc_mem, ctx );
  fd_pubkey_decode_inner( &self->destination, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->wallclock, ctx );
}
void * fd_gossip_prune_data_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_prune_data_t * self = (fd_gossip_prune_data_t *)mem;
  fd_gossip_prune_data_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_prune_data_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_prune_data_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_prune_data_new(fd_gossip_prune_data_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_prune_data_t) );
  fd_pubkey_new( &self->pubkey );
  fd_signature_new( &self->signature );
  fd_pubkey_new( &self->destination );
}
void fd_gossip_prune_data_walk( void * w, fd_gossip_prune_data_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_prune_data", level++, 0 );
  fd_pubkey_walk( w, &self->pubkey, fun, "pubkey", level, 0 );
  if( self->prunes_len ) {
    fun( w, NULL, "prunes", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->prunes_len; i++ )
      fd_pubkey_walk(w, self->prunes + i, fun, "pubkey", level, 0 );
    fun( w, NULL, "prunes", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fd_signature_walk( w, &self->signature, fun, "signature", level, 0 );
  fd_pubkey_walk( w, &self->destination, fun, "destination", level, 0 );
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_prune_data", level--, 0 );
}
ulong fd_gossip_prune_data_size( fd_gossip_prune_data_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->pubkey );
  do {
    size += sizeof(ulong);
    for( ulong i=0; i < self->prunes_len; i++ )
      size += fd_pubkey_size( self->prunes + i );
  } while(0);
  size += fd_signature_size( &self->signature );
  size += fd_pubkey_size( &self->destination );
  size += sizeof(ulong);
  return size;
}

int fd_gossip_prune_sign_data_encode( fd_gossip_prune_sign_data_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->prunes_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->prunes_len ) {
    for( ulong i=0; i < self->prunes_len; i++ ) {
      err = fd_pubkey_encode( self->prunes + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  err = fd_pubkey_encode( &self->destination, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->wallclock, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_prune_sign_data_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ulong prunes_len;
  err = fd_bincode_uint64_decode( &prunes_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( prunes_len ) {
    *total_sz += FD_PUBKEY_ALIGN + sizeof(fd_pubkey_t)*prunes_len;
    for( ulong i=0; i < prunes_len; i++ ) {
      err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_gossip_prune_sign_data_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_prune_sign_data_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_prune_sign_data_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_prune_sign_data_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_prune_sign_data_t * self = (fd_gossip_prune_sign_data_t *)struct_mem;
  fd_pubkey_decode_inner( &self->pubkey, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->prunes_len, ctx );
  if( self->prunes_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_PUBKEY_ALIGN );
    self->prunes = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_pubkey_t)*self->prunes_len;
    for( ulong i=0; i < self->prunes_len; i++ ) {
      fd_pubkey_new( self->prunes + i );
      fd_pubkey_decode_inner( self->prunes + i, alloc_mem, ctx );
    }
  } else
    self->prunes = NULL;
  fd_pubkey_decode_inner( &self->destination, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->wallclock, ctx );
}
void * fd_gossip_prune_sign_data_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_prune_sign_data_t * self = (fd_gossip_prune_sign_data_t *)mem;
  fd_gossip_prune_sign_data_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_prune_sign_data_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_prune_sign_data_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_prune_sign_data_new(fd_gossip_prune_sign_data_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_prune_sign_data_t) );
  fd_pubkey_new( &self->pubkey );
  fd_pubkey_new( &self->destination );
}
void fd_gossip_prune_sign_data_walk( void * w, fd_gossip_prune_sign_data_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_prune_sign_data", level++, 0 );
  fd_pubkey_walk( w, &self->pubkey, fun, "pubkey", level, 0 );
  if( self->prunes_len ) {
    fun( w, NULL, "prunes", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->prunes_len; i++ )
      fd_pubkey_walk(w, self->prunes + i, fun, "pubkey", level, 0 );
    fun( w, NULL, "prunes", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fd_pubkey_walk( w, &self->destination, fun, "destination", level, 0 );
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_prune_sign_data", level--, 0 );
}
ulong fd_gossip_prune_sign_data_size( fd_gossip_prune_sign_data_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->pubkey );
  do {
    size += sizeof(ulong);
    for( ulong i=0; i < self->prunes_len; i++ )
      size += fd_pubkey_size( self->prunes + i );
  } while(0);
  size += fd_pubkey_size( &self->destination );
  size += sizeof(ulong);
  return size;
}

int fd_gossip_prune_sign_data_with_prefix_encode( fd_gossip_prune_sign_data_with_prefix_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->prefix_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->prefix_len ) {
    err = fd_bincode_bytes_encode( self->prefix, self->prefix_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_gossip_prune_sign_data_encode( &self->data, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_prune_sign_data_with_prefix_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ulong prefix_len;
  err = fd_bincode_uint64_decode( &prefix_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  *total_sz += prefix_len;
  if( prefix_len ) {
    err = fd_bincode_bytes_decode_footprint( prefix_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    err = !fd_utf8_verify( (char const *) ctx->data - prefix_len, prefix_len );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  err = fd_gossip_prune_sign_data_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_gossip_prune_sign_data_with_prefix_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_prune_sign_data_with_prefix_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_prune_sign_data_with_prefix_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_prune_sign_data_with_prefix_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_prune_sign_data_with_prefix_t * self = (fd_gossip_prune_sign_data_with_prefix_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->prefix_len, ctx );
  if( self->prefix_len ) {
    self->prefix = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->prefix, self->prefix_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->prefix_len;
  } else
    self->prefix = NULL;
  fd_gossip_prune_sign_data_decode_inner( &self->data, alloc_mem, ctx );
}
void * fd_gossip_prune_sign_data_with_prefix_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_prune_sign_data_with_prefix_t * self = (fd_gossip_prune_sign_data_with_prefix_t *)mem;
  fd_gossip_prune_sign_data_with_prefix_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_prune_sign_data_with_prefix_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_prune_sign_data_with_prefix_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_prune_sign_data_with_prefix_new(fd_gossip_prune_sign_data_with_prefix_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_prune_sign_data_with_prefix_t) );
  fd_gossip_prune_sign_data_new( &self->data );
}
void fd_gossip_prune_sign_data_with_prefix_walk( void * w, fd_gossip_prune_sign_data_with_prefix_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_prune_sign_data_with_prefix", level++, 0 );
  if( self->prefix_len ) {
    fun( w, NULL, "prefix", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->prefix_len; i++ )
      fun( w, self->prefix + i, "prefix", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "prefix", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fd_gossip_prune_sign_data_walk( w, &self->data, fun, "data", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_prune_sign_data_with_prefix", level--, 0 );
}
ulong fd_gossip_prune_sign_data_with_prefix_size( fd_gossip_prune_sign_data_with_prefix_t const * self ) {
  ulong size = 0;
  do {
    size += sizeof(ulong);
    size += self->prefix_len;
  } while(0);
  size += fd_gossip_prune_sign_data_size( &self->data );
  return size;
}

int fd_gossip_socket_addr_old_encode( fd_gossip_socket_addr_old_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_gossip_ip_addr_encode( &self->addr, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint16_encode( self->port, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_socket_addr_old_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_gossip_ip_addr_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint16_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_gossip_socket_addr_old_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_socket_addr_old_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_socket_addr_old_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_socket_addr_old_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_socket_addr_old_t * self = (fd_gossip_socket_addr_old_t *)struct_mem;
  fd_gossip_ip_addr_decode_inner( &self->addr, alloc_mem, ctx );
  fd_bincode_uint16_decode_unsafe( &self->port, ctx );
}
void * fd_gossip_socket_addr_old_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_socket_addr_old_t * self = (fd_gossip_socket_addr_old_t *)mem;
  fd_gossip_socket_addr_old_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_socket_addr_old_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_socket_addr_old_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_socket_addr_old_new(fd_gossip_socket_addr_old_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_socket_addr_old_t) );
  fd_gossip_ip_addr_new( &self->addr );
}
void fd_gossip_socket_addr_old_walk( void * w, fd_gossip_socket_addr_old_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_socket_addr_old", level++, 0 );
  fd_gossip_ip_addr_walk( w, &self->addr, fun, "addr", level, 0 );
  fun( w, &self->port, "port", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_socket_addr_old", level--, 0 );
}
ulong fd_gossip_socket_addr_old_size( fd_gossip_socket_addr_old_t const * self ) {
  ulong size = 0;
  size += fd_gossip_ip_addr_size( &self->addr );
  size += sizeof(ushort);
  return size;
}

int fd_gossip_socket_addr_ip4_encode( fd_gossip_socket_addr_ip4_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_gossip_ip4_addr_encode( &self->addr, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint16_encode( self->port, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_socket_addr_ip4_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_gossip_ip4_addr_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint16_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_gossip_socket_addr_ip4_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_socket_addr_ip4_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_socket_addr_ip4_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_socket_addr_ip4_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_socket_addr_ip4_t * self = (fd_gossip_socket_addr_ip4_t *)struct_mem;
  fd_gossip_ip4_addr_decode_inner( &self->addr, alloc_mem, ctx );
  fd_bincode_uint16_decode_unsafe( &self->port, ctx );
}
void * fd_gossip_socket_addr_ip4_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_socket_addr_ip4_t * self = (fd_gossip_socket_addr_ip4_t *)mem;
  fd_gossip_socket_addr_ip4_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_socket_addr_ip4_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_socket_addr_ip4_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_socket_addr_ip4_new(fd_gossip_socket_addr_ip4_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_socket_addr_ip4_t) );
  fd_gossip_ip4_addr_new( &self->addr );
}
void fd_gossip_socket_addr_ip4_walk( void * w, fd_gossip_socket_addr_ip4_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_socket_addr_ip4", level++, 0 );
  fd_gossip_ip4_addr_walk( w, &self->addr, fun, "addr", level, 0 );
  fun( w, &self->port, "port", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_socket_addr_ip4", level--, 0 );
}
ulong fd_gossip_socket_addr_ip4_size( fd_gossip_socket_addr_ip4_t const * self ) {
  ulong size = 0;
  size += fd_gossip_ip4_addr_size( &self->addr );
  size += sizeof(ushort);
  return size;
}

int fd_gossip_socket_addr_ip6_encode( fd_gossip_socket_addr_ip6_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_gossip_ip6_addr_encode( &self->addr, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint16_encode( self->port, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_socket_addr_ip6_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_gossip_ip6_addr_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint16_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_gossip_socket_addr_ip6_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_socket_addr_ip6_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_socket_addr_ip6_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_socket_addr_ip6_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_socket_addr_ip6_t * self = (fd_gossip_socket_addr_ip6_t *)struct_mem;
  fd_gossip_ip6_addr_decode_inner( &self->addr, alloc_mem, ctx );
  fd_bincode_uint16_decode_unsafe( &self->port, ctx );
}
void * fd_gossip_socket_addr_ip6_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_socket_addr_ip6_t * self = (fd_gossip_socket_addr_ip6_t *)mem;
  fd_gossip_socket_addr_ip6_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_socket_addr_ip6_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_socket_addr_ip6_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_socket_addr_ip6_new(fd_gossip_socket_addr_ip6_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_socket_addr_ip6_t) );
  fd_gossip_ip6_addr_new( &self->addr );
}
void fd_gossip_socket_addr_ip6_walk( void * w, fd_gossip_socket_addr_ip6_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_socket_addr_ip6", level++, 0 );
  fd_gossip_ip6_addr_walk( w, &self->addr, fun, "addr", level, 0 );
  fun( w, &self->port, "port", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_socket_addr_ip6", level--, 0 );
}
FD_FN_PURE uchar fd_gossip_socket_addr_is_ip4(fd_gossip_socket_addr_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_gossip_socket_addr_is_ip6(fd_gossip_socket_addr_t const * self) {
  return self->discriminant == 1;
}
void fd_gossip_socket_addr_inner_new( fd_gossip_socket_addr_inner_t * self, uint discriminant );
int fd_gossip_socket_addr_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_socket_addr_ip4_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_gossip_socket_addr_ip6_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_gossip_socket_addr_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_gossip_socket_addr_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_gossip_socket_addr_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_socket_addr_t);
  void const * start_data = ctx->data;
  int err =  fd_gossip_socket_addr_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_socket_addr_inner_decode_inner( fd_gossip_socket_addr_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    fd_gossip_socket_addr_ip4_decode_inner( &self->ip4, alloc_mem, ctx );
    break;
  }
  case 1: {
    fd_gossip_socket_addr_ip6_decode_inner( &self->ip6, alloc_mem, ctx );
    break;
  }
  }
}
static void fd_gossip_socket_addr_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_socket_addr_t * self = (fd_gossip_socket_addr_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_gossip_socket_addr_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_gossip_socket_addr_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_socket_addr_t * self = (fd_gossip_socket_addr_t *)mem;
  fd_gossip_socket_addr_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_socket_addr_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_socket_addr_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_socket_addr_inner_new( fd_gossip_socket_addr_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    fd_gossip_socket_addr_ip4_new( &self->ip4 );
    break;
  }
  case 1: {
    fd_gossip_socket_addr_ip6_new( &self->ip6 );
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_gossip_socket_addr_new_disc( fd_gossip_socket_addr_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_gossip_socket_addr_inner_new( &self->inner, self->discriminant );
}
void fd_gossip_socket_addr_new( fd_gossip_socket_addr_t * self ) {
  fd_memset( self, 0, sizeof(fd_gossip_socket_addr_t) );
  fd_gossip_socket_addr_new_disc( self, UINT_MAX );
}

void fd_gossip_socket_addr_walk( void * w, fd_gossip_socket_addr_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_gossip_socket_addr", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "ip4", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_socket_addr_ip4_walk( w, &self->inner.ip4, fun, "ip4", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "ip6", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_socket_addr_ip6_walk( w, &self->inner.ip6, fun, "ip6", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_gossip_socket_addr", level--, 0 );
}
ulong fd_gossip_socket_addr_size( fd_gossip_socket_addr_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_gossip_socket_addr_ip4_size( &self->inner.ip4 );
    break;
  }
  case 1: {
    size += fd_gossip_socket_addr_ip6_size( &self->inner.ip6 );
    break;
  }
  }
  return size;
}

int fd_gossip_socket_addr_inner_encode( fd_gossip_socket_addr_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_socket_addr_ip4_encode( &self->ip4, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 1: {
    err = fd_gossip_socket_addr_ip6_encode( &self->ip6, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_socket_addr_encode( fd_gossip_socket_addr_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_gossip_socket_addr_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_gossip_contact_info_v1_encode( fd_gossip_contact_info_v1_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->id, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_encode( &self->gossip, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_encode( &self->tvu, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_encode( &self->tvu_fwd, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_encode( &self->repair, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_encode( &self->tpu, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_encode( &self->tpu_fwd, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_encode( &self->tpu_vote, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_encode( &self->rpc, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_encode( &self->rpc_pubsub, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_encode( &self->serve_repair, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->wallclock, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint16_encode( self->shred_version, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_contact_info_v1_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_socket_addr_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint16_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_gossip_contact_info_v1_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_contact_info_v1_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_contact_info_v1_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_contact_info_v1_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_contact_info_v1_t * self = (fd_gossip_contact_info_v1_t *)struct_mem;
  fd_pubkey_decode_inner( &self->id, alloc_mem, ctx );
  fd_gossip_socket_addr_decode_inner( &self->gossip, alloc_mem, ctx );
  fd_gossip_socket_addr_decode_inner( &self->tvu, alloc_mem, ctx );
  fd_gossip_socket_addr_decode_inner( &self->tvu_fwd, alloc_mem, ctx );
  fd_gossip_socket_addr_decode_inner( &self->repair, alloc_mem, ctx );
  fd_gossip_socket_addr_decode_inner( &self->tpu, alloc_mem, ctx );
  fd_gossip_socket_addr_decode_inner( &self->tpu_fwd, alloc_mem, ctx );
  fd_gossip_socket_addr_decode_inner( &self->tpu_vote, alloc_mem, ctx );
  fd_gossip_socket_addr_decode_inner( &self->rpc, alloc_mem, ctx );
  fd_gossip_socket_addr_decode_inner( &self->rpc_pubsub, alloc_mem, ctx );
  fd_gossip_socket_addr_decode_inner( &self->serve_repair, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->wallclock, ctx );
  fd_bincode_uint16_decode_unsafe( &self->shred_version, ctx );
}
void * fd_gossip_contact_info_v1_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_contact_info_v1_t * self = (fd_gossip_contact_info_v1_t *)mem;
  fd_gossip_contact_info_v1_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_contact_info_v1_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_contact_info_v1_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_contact_info_v1_new(fd_gossip_contact_info_v1_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_contact_info_v1_t) );
  fd_pubkey_new( &self->id );
  fd_gossip_socket_addr_new( &self->gossip );
  fd_gossip_socket_addr_new( &self->tvu );
  fd_gossip_socket_addr_new( &self->tvu_fwd );
  fd_gossip_socket_addr_new( &self->repair );
  fd_gossip_socket_addr_new( &self->tpu );
  fd_gossip_socket_addr_new( &self->tpu_fwd );
  fd_gossip_socket_addr_new( &self->tpu_vote );
  fd_gossip_socket_addr_new( &self->rpc );
  fd_gossip_socket_addr_new( &self->rpc_pubsub );
  fd_gossip_socket_addr_new( &self->serve_repair );
}
void fd_gossip_contact_info_v1_walk( void * w, fd_gossip_contact_info_v1_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_contact_info_v1", level++, 0 );
  fd_pubkey_walk( w, &self->id, fun, "id", level, 0 );
  fd_gossip_socket_addr_walk( w, &self->gossip, fun, "gossip", level, 0 );
  fd_gossip_socket_addr_walk( w, &self->tvu, fun, "tvu", level, 0 );
  fd_gossip_socket_addr_walk( w, &self->tvu_fwd, fun, "tvu_fwd", level, 0 );
  fd_gossip_socket_addr_walk( w, &self->repair, fun, "repair", level, 0 );
  fd_gossip_socket_addr_walk( w, &self->tpu, fun, "tpu", level, 0 );
  fd_gossip_socket_addr_walk( w, &self->tpu_fwd, fun, "tpu_fwd", level, 0 );
  fd_gossip_socket_addr_walk( w, &self->tpu_vote, fun, "tpu_vote", level, 0 );
  fd_gossip_socket_addr_walk( w, &self->rpc, fun, "rpc", level, 0 );
  fd_gossip_socket_addr_walk( w, &self->rpc_pubsub, fun, "rpc_pubsub", level, 0 );
  fd_gossip_socket_addr_walk( w, &self->serve_repair, fun, "serve_repair", level, 0 );
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->shred_version, "shred_version", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_contact_info_v1", level--, 0 );
}
ulong fd_gossip_contact_info_v1_size( fd_gossip_contact_info_v1_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->id );
  size += fd_gossip_socket_addr_size( &self->gossip );
  size += fd_gossip_socket_addr_size( &self->tvu );
  size += fd_gossip_socket_addr_size( &self->tvu_fwd );
  size += fd_gossip_socket_addr_size( &self->repair );
  size += fd_gossip_socket_addr_size( &self->tpu );
  size += fd_gossip_socket_addr_size( &self->tpu_fwd );
  size += fd_gossip_socket_addr_size( &self->tpu_vote );
  size += fd_gossip_socket_addr_size( &self->rpc );
  size += fd_gossip_socket_addr_size( &self->rpc_pubsub );
  size += fd_gossip_socket_addr_size( &self->serve_repair );
  size += sizeof(ulong);
  size += sizeof(ushort);
  return size;
}

int fd_gossip_vote_old_encode( fd_gossip_vote_old_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint8_encode( (uchar)(self->index), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->from, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_flamenco_txn_encode( &self->txn, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->wallclock, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_vote_old_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_flamenco_txn_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_gossip_vote_old_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_vote_old_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_vote_old_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_vote_old_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_vote_old_t * self = (fd_gossip_vote_old_t *)struct_mem;
  fd_bincode_uint8_decode_unsafe( &self->index, ctx );
  fd_pubkey_decode_inner( &self->from, alloc_mem, ctx );
  fd_flamenco_txn_decode_inner( &self->txn, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->wallclock, ctx );
}
void * fd_gossip_vote_old_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_vote_old_t * self = (fd_gossip_vote_old_t *)mem;
  fd_gossip_vote_old_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_vote_old_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_vote_old_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_vote_old_new(fd_gossip_vote_old_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_vote_old_t) );
  fd_pubkey_new( &self->from );
  fd_flamenco_txn_new( &self->txn );
}
void fd_gossip_vote_old_walk( void * w, fd_gossip_vote_old_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_vote_old", level++, 0 );
  fun( w, &self->index, "index", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fd_pubkey_walk( w, &self->from, fun, "from", level, 0 );
  fd_flamenco_txn_walk( w, &self->txn, fun, "txn", level, 0 );
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_vote_old", level--, 0 );
}
ulong fd_gossip_vote_old_size( fd_gossip_vote_old_t const * self ) {
  ulong size = 0;
  size += sizeof(char);
  size += fd_pubkey_size( &self->from );
  size += fd_flamenco_txn_size( &self->txn );
  size += sizeof(ulong);
  return size;
}

FD_FN_PURE uchar fd_gossip_deprecated_compression_type_is_Uncompressed(fd_gossip_deprecated_compression_type_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_gossip_deprecated_compression_type_is_GZip(fd_gossip_deprecated_compression_type_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_gossip_deprecated_compression_type_is_BZip2(fd_gossip_deprecated_compression_type_t const * self) {
  return self->discriminant == 2;
}
int fd_gossip_deprecated_compression_type_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
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
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_gossip_deprecated_compression_type_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_gossip_deprecated_compression_type_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_gossip_deprecated_compression_type_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_deprecated_compression_type_t);
  void const * start_data = ctx->data;
  int err =  fd_gossip_deprecated_compression_type_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_deprecated_compression_type_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_deprecated_compression_type_t * self = (fd_gossip_deprecated_compression_type_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
}
void * fd_gossip_deprecated_compression_type_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_deprecated_compression_type_t * self = (fd_gossip_deprecated_compression_type_t *)mem;
  fd_gossip_deprecated_compression_type_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_deprecated_compression_type_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_deprecated_compression_type_decode_inner( mem, alloc_mem, ctx );
  return self;
}

void fd_gossip_deprecated_compression_type_walk( void * w, fd_gossip_deprecated_compression_type_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_gossip_deprecated_compression_type", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "Uncompressed", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "GZip", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 2: {
    fun( w, self, "BZip2", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_gossip_deprecated_compression_type", level--, 0 );
}
ulong fd_gossip_deprecated_compression_type_size( fd_gossip_deprecated_compression_type_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  }
  return size;
}

int fd_gossip_deprecated_compression_type_encode( fd_gossip_deprecated_compression_type_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return err;
}

int fd_gossip_deprecated_epoch_incomplete_slots_encode( fd_gossip_deprecated_epoch_incomplete_slots_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->first, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_deprecated_compression_type_encode( &self->compression, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->compressed_list_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->compressed_list_len ) {
    err = fd_bincode_bytes_encode( self->compressed_list, self->compressed_list_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_deprecated_epoch_incomplete_slots_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_gossip_deprecated_compression_type_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ulong compressed_list_len;
  err = fd_bincode_uint64_decode( &compressed_list_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( compressed_list_len ) {
    *total_sz += 8UL + compressed_list_len;
    err = fd_bincode_bytes_decode_footprint( compressed_list_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return 0;
}
int fd_gossip_deprecated_epoch_incomplete_slots_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_deprecated_epoch_incomplete_slots_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_deprecated_epoch_incomplete_slots_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_deprecated_epoch_incomplete_slots_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_deprecated_epoch_incomplete_slots_t * self = (fd_gossip_deprecated_epoch_incomplete_slots_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->first, ctx );
  fd_gossip_deprecated_compression_type_decode_inner( &self->compression, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->compressed_list_len, ctx );
  if( self->compressed_list_len ) {
    self->compressed_list = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->compressed_list, self->compressed_list_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->compressed_list_len;
  } else
    self->compressed_list = NULL;
}
void * fd_gossip_deprecated_epoch_incomplete_slots_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_deprecated_epoch_incomplete_slots_t * self = (fd_gossip_deprecated_epoch_incomplete_slots_t *)mem;
  fd_gossip_deprecated_epoch_incomplete_slots_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_deprecated_epoch_incomplete_slots_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_deprecated_epoch_incomplete_slots_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_deprecated_epoch_incomplete_slots_new(fd_gossip_deprecated_epoch_incomplete_slots_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_deprecated_epoch_incomplete_slots_t) );
  fd_gossip_deprecated_compression_type_new( &self->compression );
}
void fd_gossip_deprecated_epoch_incomplete_slots_walk( void * w, fd_gossip_deprecated_epoch_incomplete_slots_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_deprecated_epoch_incomplete_slots", level++, 0 );
  fun( w, &self->first, "first", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_gossip_deprecated_compression_type_walk( w, &self->compression, fun, "compression", level, 0 );
  if( self->compressed_list_len ) {
    fun( w, NULL, "compressed_list", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->compressed_list_len; i++ )
      fun( w, self->compressed_list + i, "compressed_list", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "compressed_list", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_deprecated_epoch_incomplete_slots", level--, 0 );
}
ulong fd_gossip_deprecated_epoch_incomplete_slots_size( fd_gossip_deprecated_epoch_incomplete_slots_t const * self ) {
  ulong size = 0;
  size += sizeof(ulong);
  size += fd_gossip_deprecated_compression_type_size( &self->compression );
  do {
    size += sizeof(ulong);
    size += self->compressed_list_len;
  } while(0);
  return size;
}

int fd_gossip_lowest_slot_encode( fd_gossip_lowest_slot_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint8_encode( (uchar)(self->u8), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->from, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->root, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->lowest, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->slots_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->slots_len ) {
    for( ulong i=0; i < self->slots_len; i++ ) {
      err = fd_bincode_uint64_encode( self->slots[i], ctx );
    }
  }
  err = fd_bincode_uint64_encode( self->stash_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->stash_len ) {
    for( ulong i=0; i < self->stash_len; i++ ) {
      err = fd_gossip_deprecated_epoch_incomplete_slots_encode( self->stash + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  err = fd_bincode_uint64_encode( self->wallclock, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_lowest_slot_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ulong slots_len;
  err = fd_bincode_uint64_decode( &slots_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( slots_len ) {
    *total_sz += 8UL + sizeof(ulong)*slots_len;
    for( ulong i=0; i < slots_len; i++ ) {
      err = fd_bincode_uint64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  ulong stash_len;
  err = fd_bincode_uint64_decode( &stash_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( stash_len ) {
    *total_sz += FD_GOSSIP_DEPRECATED_EPOCH_INCOMPLETE_SLOTS_ALIGN + sizeof(fd_gossip_deprecated_epoch_incomplete_slots_t)*stash_len;
    for( ulong i=0; i < stash_len; i++ ) {
      err = fd_gossip_deprecated_epoch_incomplete_slots_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_gossip_lowest_slot_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_lowest_slot_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_lowest_slot_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_lowest_slot_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_lowest_slot_t * self = (fd_gossip_lowest_slot_t *)struct_mem;
  fd_bincode_uint8_decode_unsafe( &self->u8, ctx );
  fd_pubkey_decode_inner( &self->from, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->root, ctx );
  fd_bincode_uint64_decode_unsafe( &self->lowest, ctx );
  fd_bincode_uint64_decode_unsafe( &self->slots_len, ctx );
  if( self->slots_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), 8UL );
    self->slots = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(ulong)*self->slots_len;
    for( ulong i=0; i < self->slots_len; i++ ) {
      fd_bincode_uint64_decode_unsafe( self->slots + i, ctx );
    }
  } else
    self->slots = NULL;
  fd_bincode_uint64_decode_unsafe( &self->stash_len, ctx );
  if( self->stash_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_GOSSIP_DEPRECATED_EPOCH_INCOMPLETE_SLOTS_ALIGN );
    self->stash = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_gossip_deprecated_epoch_incomplete_slots_t)*self->stash_len;
    for( ulong i=0; i < self->stash_len; i++ ) {
      fd_gossip_deprecated_epoch_incomplete_slots_new( self->stash + i );
      fd_gossip_deprecated_epoch_incomplete_slots_decode_inner( self->stash + i, alloc_mem, ctx );
    }
  } else
    self->stash = NULL;
  fd_bincode_uint64_decode_unsafe( &self->wallclock, ctx );
}
void * fd_gossip_lowest_slot_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_lowest_slot_t * self = (fd_gossip_lowest_slot_t *)mem;
  fd_gossip_lowest_slot_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_lowest_slot_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_lowest_slot_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_lowest_slot_new(fd_gossip_lowest_slot_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_lowest_slot_t) );
  fd_pubkey_new( &self->from );
}
void fd_gossip_lowest_slot_walk( void * w, fd_gossip_lowest_slot_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_lowest_slot", level++, 0 );
  fun( w, &self->u8, "u8", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fd_pubkey_walk( w, &self->from, fun, "from", level, 0 );
  fun( w, &self->root, "root", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->lowest, "lowest", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  if( self->slots_len ) {
    fun( w, NULL, "slots", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->slots_len; i++ )
      fun( w, self->slots + i, "slots", FD_FLAMENCO_TYPE_ULONG,   "ulong",   level, 0 );
    fun( w, NULL, "slots", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  if( self->stash_len ) {
    fun( w, NULL, "stash", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->stash_len; i++ )
      fd_gossip_deprecated_epoch_incomplete_slots_walk(w, self->stash + i, fun, "gossip_deprecated_epoch_incomplete_slots", level, 0 );
    fun( w, NULL, "stash", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_lowest_slot", level--, 0 );
}
ulong fd_gossip_lowest_slot_size( fd_gossip_lowest_slot_t const * self ) {
  ulong size = 0;
  size += sizeof(char);
  size += fd_pubkey_size( &self->from );
  size += sizeof(ulong);
  size += sizeof(ulong);
  do {
    size += sizeof(ulong);
    size += self->slots_len * sizeof(ulong);
  } while(0);
  do {
    size += sizeof(ulong);
    for( ulong i=0; i < self->stash_len; i++ )
      size += fd_gossip_deprecated_epoch_incomplete_slots_size( self->stash + i );
  } while(0);
  size += sizeof(ulong);
  return size;
}

int fd_gossip_slot_hashes_encode( fd_gossip_slot_hashes_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->from, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->hashes_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->hashes_len ) {
    for( ulong i=0; i < self->hashes_len; i++ ) {
      err = fd_slot_hash_encode( self->hashes + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  err = fd_bincode_uint64_encode( self->wallclock, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_slot_hashes_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ulong hashes_len;
  err = fd_bincode_uint64_decode( &hashes_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( hashes_len ) {
    *total_sz += FD_SLOT_HASH_ALIGN + sizeof(fd_slot_hash_t)*hashes_len;
    for( ulong i=0; i < hashes_len; i++ ) {
      err = fd_slot_hash_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_gossip_slot_hashes_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_slot_hashes_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_slot_hashes_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_slot_hashes_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_slot_hashes_t * self = (fd_gossip_slot_hashes_t *)struct_mem;
  fd_pubkey_decode_inner( &self->from, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->hashes_len, ctx );
  if( self->hashes_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_SLOT_HASH_ALIGN );
    self->hashes = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_slot_hash_t)*self->hashes_len;
    for( ulong i=0; i < self->hashes_len; i++ ) {
      fd_slot_hash_new( self->hashes + i );
      fd_slot_hash_decode_inner( self->hashes + i, alloc_mem, ctx );
    }
  } else
    self->hashes = NULL;
  fd_bincode_uint64_decode_unsafe( &self->wallclock, ctx );
}
void * fd_gossip_slot_hashes_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_slot_hashes_t * self = (fd_gossip_slot_hashes_t *)mem;
  fd_gossip_slot_hashes_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_slot_hashes_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_slot_hashes_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_slot_hashes_new(fd_gossip_slot_hashes_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_slot_hashes_t) );
  fd_pubkey_new( &self->from );
}
void fd_gossip_slot_hashes_walk( void * w, fd_gossip_slot_hashes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_slot_hashes", level++, 0 );
  fd_pubkey_walk( w, &self->from, fun, "from", level, 0 );
  if( self->hashes_len ) {
    fun( w, NULL, "hashes", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->hashes_len; i++ )
      fd_slot_hash_walk(w, self->hashes + i, fun, "slot_hash", level, 0 );
    fun( w, NULL, "hashes", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_slot_hashes", level--, 0 );
}
ulong fd_gossip_slot_hashes_size( fd_gossip_slot_hashes_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->from );
  do {
    size += sizeof(ulong);
    for( ulong i=0; i < self->hashes_len; i++ )
      size += fd_slot_hash_size( self->hashes + i );
  } while(0);
  size += sizeof(ulong);
  return size;
}

int fd_gossip_slots_encode( fd_gossip_slots_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->first_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->num, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_encode( self->has_slots, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_slots ) {
    err = fd_bincode_uint64_encode( self->slots_bitvec_len, ctx );
    if( FD_UNLIKELY(err) ) return err;
    if( self->slots_bitvec_len ) {
      err = fd_bincode_bytes_encode( self->slots_bitvec, self->slots_bitvec_len, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint64_encode( self->slots_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_slots_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  {
    uchar o;
    ulong inner_len = 0UL;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      ulong slots_bitvec_len;
      err = fd_bincode_uint64_decode( &slots_bitvec_len, ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
      if( slots_bitvec_len ) {
        *total_sz += 8UL + slots_bitvec_len;
        err = fd_bincode_bytes_decode_footprint( slots_bitvec_len, ctx );
        if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
      }
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
      inner_len = slots_bitvec_len;
      if( inner_len==0 ) return FD_BINCODE_ERR_ENCODING;
    }
    ulong len;
    err = fd_bincode_uint64_decode( &len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( len > inner_len * sizeof(uchar) * 8UL ) return FD_BINCODE_ERR_ENCODING;
  }
  return 0;
}
int fd_gossip_slots_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_slots_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_slots_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_slots_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_slots_t * self = (fd_gossip_slots_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->first_slot, ctx );
  fd_bincode_uint64_decode_unsafe( &self->num, ctx );
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_slots = !!o;
    if( o ) {
      fd_bincode_uint64_decode_unsafe( &self->slots_bitvec_len, ctx );
      if( self->slots_bitvec_len ) {
        self->slots_bitvec = *alloc_mem;
        fd_bincode_bytes_decode_unsafe( self->slots_bitvec, self->slots_bitvec_len, ctx );
        *alloc_mem = (uchar *)(*alloc_mem) + self->slots_bitvec_len;
      } else
        self->slots_bitvec = NULL;
    } else {
      self->slots_bitvec = NULL;
    }
    fd_bincode_uint64_decode_unsafe( &self->slots_len, ctx );
  }
}
void * fd_gossip_slots_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_slots_t * self = (fd_gossip_slots_t *)mem;
  fd_gossip_slots_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_slots_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_slots_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_slots_new(fd_gossip_slots_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_slots_t) );
}
void fd_gossip_slots_walk( void * w, fd_gossip_slots_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_slots", level++, 0 );
  fun( w, &self->first_slot, "first_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->num, "num", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  if( !self->has_slots ) {
    fun( w, NULL, "slots", FD_FLAMENCO_TYPE_NULL, "uchar", level, 0 );
  } else {
    if( self->slots_bitvec_len ) {
      fun( w, NULL, "slots_bitvec", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
      for( ulong i=0; i < self->slots_bitvec_len; i++ )
      fun( w, self->slots_bitvec + i, "slots_bitvec", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
      fun( w, NULL, "slots_bitvec", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
    }
  }
  fun( w, &self->slots_len, "slots_len", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_slots", level--, 0 );
}
ulong fd_gossip_slots_size( fd_gossip_slots_t const * self ) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(char);
  if( self->has_slots ) {
    do {
      size += sizeof(ulong);
      size += self->slots_bitvec_len;
    } while(0);
  }
  size += sizeof(ulong);
  return size;
}

int fd_gossip_flate2_slots_encode( fd_gossip_flate2_slots_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->first_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->num, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->compressed_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->compressed_len ) {
    err = fd_bincode_bytes_encode( self->compressed, self->compressed_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_flate2_slots_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ulong compressed_len;
  err = fd_bincode_uint64_decode( &compressed_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( compressed_len ) {
    *total_sz += 8UL + compressed_len;
    err = fd_bincode_bytes_decode_footprint( compressed_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return 0;
}
int fd_gossip_flate2_slots_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_flate2_slots_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_flate2_slots_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_flate2_slots_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_flate2_slots_t * self = (fd_gossip_flate2_slots_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->first_slot, ctx );
  fd_bincode_uint64_decode_unsafe( &self->num, ctx );
  fd_bincode_uint64_decode_unsafe( &self->compressed_len, ctx );
  if( self->compressed_len ) {
    self->compressed = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->compressed, self->compressed_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->compressed_len;
  } else
    self->compressed = NULL;
}
void * fd_gossip_flate2_slots_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_flate2_slots_t * self = (fd_gossip_flate2_slots_t *)mem;
  fd_gossip_flate2_slots_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_flate2_slots_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_flate2_slots_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_flate2_slots_new(fd_gossip_flate2_slots_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_flate2_slots_t) );
}
void fd_gossip_flate2_slots_walk( void * w, fd_gossip_flate2_slots_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_flate2_slots", level++, 0 );
  fun( w, &self->first_slot, "first_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->num, "num", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  if( self->compressed_len ) {
    fun( w, NULL, "compressed", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->compressed_len; i++ )
      fun( w, self->compressed + i, "compressed", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "compressed", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_flate2_slots", level--, 0 );
}
ulong fd_gossip_flate2_slots_size( fd_gossip_flate2_slots_t const * self ) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  do {
    size += sizeof(ulong);
    size += self->compressed_len;
  } while(0);
  return size;
}

FD_FN_PURE uchar fd_gossip_slots_enum_is_flate2(fd_gossip_slots_enum_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_gossip_slots_enum_is_uncompressed(fd_gossip_slots_enum_t const * self) {
  return self->discriminant == 1;
}
void fd_gossip_slots_enum_inner_new( fd_gossip_slots_enum_inner_t * self, uint discriminant );
int fd_gossip_slots_enum_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_flate2_slots_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_gossip_slots_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_gossip_slots_enum_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_gossip_slots_enum_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_gossip_slots_enum_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_slots_enum_t);
  void const * start_data = ctx->data;
  int err =  fd_gossip_slots_enum_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_slots_enum_inner_decode_inner( fd_gossip_slots_enum_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    fd_gossip_flate2_slots_decode_inner( &self->flate2, alloc_mem, ctx );
    break;
  }
  case 1: {
    fd_gossip_slots_decode_inner( &self->uncompressed, alloc_mem, ctx );
    break;
  }
  }
}
static void fd_gossip_slots_enum_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_slots_enum_t * self = (fd_gossip_slots_enum_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_gossip_slots_enum_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_gossip_slots_enum_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_slots_enum_t * self = (fd_gossip_slots_enum_t *)mem;
  fd_gossip_slots_enum_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_slots_enum_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_slots_enum_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_slots_enum_inner_new( fd_gossip_slots_enum_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    fd_gossip_flate2_slots_new( &self->flate2 );
    break;
  }
  case 1: {
    fd_gossip_slots_new( &self->uncompressed );
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_gossip_slots_enum_new_disc( fd_gossip_slots_enum_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_gossip_slots_enum_inner_new( &self->inner, self->discriminant );
}
void fd_gossip_slots_enum_new( fd_gossip_slots_enum_t * self ) {
  fd_memset( self, 0, sizeof(fd_gossip_slots_enum_t) );
  fd_gossip_slots_enum_new_disc( self, UINT_MAX );
}

void fd_gossip_slots_enum_walk( void * w, fd_gossip_slots_enum_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_gossip_slots_enum", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "flate2", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_flate2_slots_walk( w, &self->inner.flate2, fun, "flate2", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "uncompressed", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_slots_walk( w, &self->inner.uncompressed, fun, "uncompressed", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_gossip_slots_enum", level--, 0 );
}
ulong fd_gossip_slots_enum_size( fd_gossip_slots_enum_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_gossip_flate2_slots_size( &self->inner.flate2 );
    break;
  }
  case 1: {
    size += fd_gossip_slots_size( &self->inner.uncompressed );
    break;
  }
  }
  return size;
}

int fd_gossip_slots_enum_inner_encode( fd_gossip_slots_enum_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_flate2_slots_encode( &self->flate2, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 1: {
    err = fd_gossip_slots_encode( &self->uncompressed, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_slots_enum_encode( fd_gossip_slots_enum_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_gossip_slots_enum_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_gossip_epoch_slots_encode( fd_gossip_epoch_slots_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint8_encode( (uchar)(self->u8), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->from, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->slots_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->slots_len ) {
    for( ulong i=0; i < self->slots_len; i++ ) {
      err = fd_gossip_slots_enum_encode( self->slots + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  err = fd_bincode_uint64_encode( self->wallclock, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_epoch_slots_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ulong slots_len;
  err = fd_bincode_uint64_decode( &slots_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( slots_len ) {
    *total_sz += FD_GOSSIP_SLOTS_ENUM_ALIGN + sizeof(fd_gossip_slots_enum_t)*slots_len;
    for( ulong i=0; i < slots_len; i++ ) {
      err = fd_gossip_slots_enum_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_gossip_epoch_slots_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_epoch_slots_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_epoch_slots_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_epoch_slots_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_epoch_slots_t * self = (fd_gossip_epoch_slots_t *)struct_mem;
  fd_bincode_uint8_decode_unsafe( &self->u8, ctx );
  fd_pubkey_decode_inner( &self->from, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->slots_len, ctx );
  if( self->slots_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_GOSSIP_SLOTS_ENUM_ALIGN );
    self->slots = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_gossip_slots_enum_t)*self->slots_len;
    for( ulong i=0; i < self->slots_len; i++ ) {
      fd_gossip_slots_enum_new( self->slots + i );
      fd_gossip_slots_enum_decode_inner( self->slots + i, alloc_mem, ctx );
    }
  } else
    self->slots = NULL;
  fd_bincode_uint64_decode_unsafe( &self->wallclock, ctx );
}
void * fd_gossip_epoch_slots_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_epoch_slots_t * self = (fd_gossip_epoch_slots_t *)mem;
  fd_gossip_epoch_slots_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_epoch_slots_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_epoch_slots_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_epoch_slots_new(fd_gossip_epoch_slots_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_epoch_slots_t) );
  fd_pubkey_new( &self->from );
}
void fd_gossip_epoch_slots_walk( void * w, fd_gossip_epoch_slots_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_epoch_slots", level++, 0 );
  fun( w, &self->u8, "u8", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fd_pubkey_walk( w, &self->from, fun, "from", level, 0 );
  if( self->slots_len ) {
    fun( w, NULL, "slots", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->slots_len; i++ )
      fd_gossip_slots_enum_walk(w, self->slots + i, fun, "gossip_slots_enum", level, 0 );
    fun( w, NULL, "slots", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_epoch_slots", level--, 0 );
}
ulong fd_gossip_epoch_slots_size( fd_gossip_epoch_slots_t const * self ) {
  ulong size = 0;
  size += sizeof(char);
  size += fd_pubkey_size( &self->from );
  do {
    size += sizeof(ulong);
    for( ulong i=0; i < self->slots_len; i++ )
      size += fd_gossip_slots_enum_size( self->slots + i );
  } while(0);
  size += sizeof(ulong);
  return size;
}

int fd_gossip_version_v1_encode( fd_gossip_version_v1_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->from, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->wallclock, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint16_encode( self->major, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint16_encode( self->minor, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint16_encode( self->patch, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_encode( self->has_commit, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_commit ) {
    err = fd_bincode_uint32_encode( self->commit, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_version_v1_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint16_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint16_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint16_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint32_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_gossip_version_v1_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_version_v1_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_version_v1_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_version_v1_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_version_v1_t * self = (fd_gossip_version_v1_t *)struct_mem;
  fd_pubkey_decode_inner( &self->from, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->wallclock, ctx );
  fd_bincode_uint16_decode_unsafe( &self->major, ctx );
  fd_bincode_uint16_decode_unsafe( &self->minor, ctx );
  fd_bincode_uint16_decode_unsafe( &self->patch, ctx );
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_commit = !!o;
    if( o ) {
      fd_bincode_uint32_decode_unsafe( &self->commit, ctx );
    }
  }
}
void * fd_gossip_version_v1_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_version_v1_t * self = (fd_gossip_version_v1_t *)mem;
  fd_gossip_version_v1_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_version_v1_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_version_v1_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_version_v1_new(fd_gossip_version_v1_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_version_v1_t) );
  fd_pubkey_new( &self->from );
}
void fd_gossip_version_v1_walk( void * w, fd_gossip_version_v1_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_version_v1", level++, 0 );
  fd_pubkey_walk( w, &self->from, fun, "from", level, 0 );
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->major, "major", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 0  );
  fun( w, &self->minor, "minor", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 0  );
  fun( w, &self->patch, "patch", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 0  );
  if( !self->has_commit ) {
    fun( w, NULL, "commit", FD_FLAMENCO_TYPE_NULL, "uint", level, 0 );
  } else {
    fun( w, &self->commit, "commit", FD_FLAMENCO_TYPE_UINT, "uint", level, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_version_v1", level--, 0 );
}
ulong fd_gossip_version_v1_size( fd_gossip_version_v1_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->from );
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

int fd_gossip_version_v2_encode( fd_gossip_version_v2_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->from, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->wallclock, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint16_encode( self->major, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint16_encode( self->minor, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint16_encode( self->patch, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_encode( self->has_commit, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_commit ) {
    err = fd_bincode_uint32_encode( self->commit, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint32_encode( self->feature_set, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_version_v2_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint16_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint16_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint16_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  {
    uchar o;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      err = fd_bincode_uint32_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint32_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_gossip_version_v2_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_version_v2_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_version_v2_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_version_v2_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_version_v2_t * self = (fd_gossip_version_v2_t *)struct_mem;
  fd_pubkey_decode_inner( &self->from, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->wallclock, ctx );
  fd_bincode_uint16_decode_unsafe( &self->major, ctx );
  fd_bincode_uint16_decode_unsafe( &self->minor, ctx );
  fd_bincode_uint16_decode_unsafe( &self->patch, ctx );
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_commit = !!o;
    if( o ) {
      fd_bincode_uint32_decode_unsafe( &self->commit, ctx );
    }
  }
  fd_bincode_uint32_decode_unsafe( &self->feature_set, ctx );
}
void * fd_gossip_version_v2_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_version_v2_t * self = (fd_gossip_version_v2_t *)mem;
  fd_gossip_version_v2_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_version_v2_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_version_v2_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_version_v2_new(fd_gossip_version_v2_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_version_v2_t) );
  fd_pubkey_new( &self->from );
}
void fd_gossip_version_v2_walk( void * w, fd_gossip_version_v2_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_version_v2", level++, 0 );
  fd_pubkey_walk( w, &self->from, fun, "from", level, 0 );
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->major, "major", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 0  );
  fun( w, &self->minor, "minor", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 0  );
  fun( w, &self->patch, "patch", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 0  );
  if( !self->has_commit ) {
    fun( w, NULL, "commit", FD_FLAMENCO_TYPE_NULL, "uint", level, 0 );
  } else {
    fun( w, &self->commit, "commit", FD_FLAMENCO_TYPE_UINT, "uint", level, 0 );
  }
  fun( w, &self->feature_set, "feature_set", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_version_v2", level--, 0 );
}
ulong fd_gossip_version_v2_size( fd_gossip_version_v2_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->from );
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

int fd_gossip_version_v3_encode( fd_gossip_version_v3_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_compact_u16_encode( &self->major, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_compact_u16_encode( &self->minor, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_compact_u16_encode( &self->patch, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint32_encode( self->commit, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint32_encode( self->feature_set, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_compact_u16_encode( &self->client, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_version_v3_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  do { ushort _tmp; err = fd_bincode_compact_u16_decode( &_tmp, ctx ); } while(0);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  do { ushort _tmp; err = fd_bincode_compact_u16_decode( &_tmp, ctx ); } while(0);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  do { ushort _tmp; err = fd_bincode_compact_u16_decode( &_tmp, ctx ); } while(0);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint32_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint32_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  do { ushort _tmp; err = fd_bincode_compact_u16_decode( &_tmp, ctx ); } while(0);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_gossip_version_v3_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_version_v3_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_version_v3_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_version_v3_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_version_v3_t * self = (fd_gossip_version_v3_t *)struct_mem;
  fd_bincode_compact_u16_decode_unsafe( &self->major, ctx );
  fd_bincode_compact_u16_decode_unsafe( &self->minor, ctx );
  fd_bincode_compact_u16_decode_unsafe( &self->patch, ctx );
  fd_bincode_uint32_decode_unsafe( &self->commit, ctx );
  fd_bincode_uint32_decode_unsafe( &self->feature_set, ctx );
  fd_bincode_compact_u16_decode_unsafe( &self->client, ctx );
}
void * fd_gossip_version_v3_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_version_v3_t * self = (fd_gossip_version_v3_t *)mem;
  fd_gossip_version_v3_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_version_v3_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_version_v3_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_version_v3_new(fd_gossip_version_v3_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_version_v3_t) );
}
void fd_gossip_version_v3_walk( void * w, fd_gossip_version_v3_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_version_v3", level++, 0 );
  fun( w, &self->major, "major", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 1  );
  fun( w, &self->minor, "minor", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 1  );
  fun( w, &self->patch, "patch", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 1  );
  fun( w, &self->commit, "commit", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, &self->feature_set, "feature_set", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, &self->client, "client", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 1  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_version_v3", level--, 0 );
}
ulong fd_gossip_version_v3_size( fd_gossip_version_v3_t const * self ) {
  ulong size = 0;
  size += fd_bincode_compact_u16_size( &self->major );
  size += fd_bincode_compact_u16_size( &self->minor );
  size += fd_bincode_compact_u16_size( &self->patch );
  size += sizeof(uint);
  size += sizeof(uint);
  size += fd_bincode_compact_u16_size( &self->client );
  return size;
}

int fd_gossip_node_instance_encode( fd_gossip_node_instance_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->from, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->wallclock, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->timestamp, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->token, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_gossip_node_instance_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 56UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 56UL );
  return 0;
}
static void fd_gossip_node_instance_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_node_instance_t * self = (fd_gossip_node_instance_t *)struct_mem;
  fd_pubkey_decode_inner( &self->from, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->wallclock, ctx );
  fd_bincode_uint64_decode_unsafe( &self->timestamp, ctx );
  fd_bincode_uint64_decode_unsafe( &self->token, ctx );
}
void * fd_gossip_node_instance_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_node_instance_t * self = (fd_gossip_node_instance_t *)mem;
  fd_gossip_node_instance_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_node_instance_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_node_instance_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_node_instance_walk( void * w, fd_gossip_node_instance_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_node_instance", level++, 0 );
  fd_pubkey_walk( w, &self->from, fun, "from", level, 0 );
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->timestamp, "timestamp", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->token, "token", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_node_instance", level--, 0 );
}
int fd_gossip_duplicate_shred_old_encode( fd_gossip_duplicate_shred_old_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint16_encode( self->duplicate_shred_index, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->from, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->wallclock, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint32_encode( self->_unused, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->_unused_shred_type), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->num_chunks), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->chunk_index), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->chunk_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->chunk_len ) {
    err = fd_bincode_bytes_encode( self->chunk, self->chunk_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_duplicate_shred_old_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint16_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint32_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong chunk_len;
  err = fd_bincode_uint64_decode( &chunk_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( chunk_len ) {
    *total_sz += 8UL + chunk_len;
    err = fd_bincode_bytes_decode_footprint( chunk_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return 0;
}
int fd_gossip_duplicate_shred_old_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_duplicate_shred_old_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_duplicate_shred_old_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_duplicate_shred_old_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_duplicate_shred_old_t * self = (fd_gossip_duplicate_shred_old_t *)struct_mem;
  fd_bincode_uint16_decode_unsafe( &self->duplicate_shred_index, ctx );
  fd_pubkey_decode_inner( &self->from, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->wallclock, ctx );
  fd_bincode_uint64_decode_unsafe( &self->slot, ctx );
  fd_bincode_uint32_decode_unsafe( &self->_unused, ctx );
  fd_bincode_uint8_decode_unsafe( &self->_unused_shred_type, ctx );
  fd_bincode_uint8_decode_unsafe( &self->num_chunks, ctx );
  fd_bincode_uint8_decode_unsafe( &self->chunk_index, ctx );
  fd_bincode_uint64_decode_unsafe( &self->chunk_len, ctx );
  if( self->chunk_len ) {
    self->chunk = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->chunk, self->chunk_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->chunk_len;
  } else
    self->chunk = NULL;
}
void * fd_gossip_duplicate_shred_old_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_duplicate_shred_old_t * self = (fd_gossip_duplicate_shred_old_t *)mem;
  fd_gossip_duplicate_shred_old_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_duplicate_shred_old_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_duplicate_shred_old_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_duplicate_shred_old_new(fd_gossip_duplicate_shred_old_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_duplicate_shred_old_t) );
  fd_pubkey_new( &self->from );
}
void fd_gossip_duplicate_shred_old_walk( void * w, fd_gossip_duplicate_shred_old_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_duplicate_shred_old", level++, 0 );
  fun( w, &self->duplicate_shred_index, "duplicate_shred_index", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 0  );
  fd_pubkey_walk( w, &self->from, fun, "from", level, 0 );
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->_unused, "_unused", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, &self->_unused_shred_type, "_unused_shred_type", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fun( w, &self->num_chunks, "num_chunks", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fun( w, &self->chunk_index, "chunk_index", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  if( self->chunk_len ) {
    fun( w, NULL, "chunk", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->chunk_len; i++ )
      fun( w, self->chunk + i, "chunk", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "chunk", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_duplicate_shred_old", level--, 0 );
}
ulong fd_gossip_duplicate_shred_old_size( fd_gossip_duplicate_shred_old_t const * self ) {
  ulong size = 0;
  size += sizeof(ushort);
  size += fd_pubkey_size( &self->from );
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

int fd_gossip_incremental_snapshot_hashes_encode( fd_gossip_incremental_snapshot_hashes_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->from, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_slot_hash_encode( &self->base_hash, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->hashes_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->hashes_len ) {
    for( ulong i=0; i < self->hashes_len; i++ ) {
      err = fd_slot_hash_encode( self->hashes + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  err = fd_bincode_uint64_encode( self->wallclock, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_incremental_snapshot_hashes_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_slot_hash_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ulong hashes_len;
  err = fd_bincode_uint64_decode( &hashes_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( hashes_len ) {
    *total_sz += FD_SLOT_HASH_ALIGN + sizeof(fd_slot_hash_t)*hashes_len;
    for( ulong i=0; i < hashes_len; i++ ) {
      err = fd_slot_hash_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_gossip_incremental_snapshot_hashes_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_incremental_snapshot_hashes_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_incremental_snapshot_hashes_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_incremental_snapshot_hashes_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_incremental_snapshot_hashes_t * self = (fd_gossip_incremental_snapshot_hashes_t *)struct_mem;
  fd_pubkey_decode_inner( &self->from, alloc_mem, ctx );
  fd_slot_hash_decode_inner( &self->base_hash, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->hashes_len, ctx );
  if( self->hashes_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_SLOT_HASH_ALIGN );
    self->hashes = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_slot_hash_t)*self->hashes_len;
    for( ulong i=0; i < self->hashes_len; i++ ) {
      fd_slot_hash_new( self->hashes + i );
      fd_slot_hash_decode_inner( self->hashes + i, alloc_mem, ctx );
    }
  } else
    self->hashes = NULL;
  fd_bincode_uint64_decode_unsafe( &self->wallclock, ctx );
}
void * fd_gossip_incremental_snapshot_hashes_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_incremental_snapshot_hashes_t * self = (fd_gossip_incremental_snapshot_hashes_t *)mem;
  fd_gossip_incremental_snapshot_hashes_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_incremental_snapshot_hashes_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_incremental_snapshot_hashes_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_incremental_snapshot_hashes_new(fd_gossip_incremental_snapshot_hashes_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_incremental_snapshot_hashes_t) );
  fd_pubkey_new( &self->from );
  fd_slot_hash_new( &self->base_hash );
}
void fd_gossip_incremental_snapshot_hashes_walk( void * w, fd_gossip_incremental_snapshot_hashes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_incremental_snapshot_hashes", level++, 0 );
  fd_pubkey_walk( w, &self->from, fun, "from", level, 0 );
  fd_slot_hash_walk( w, &self->base_hash, fun, "base_hash", level, 0 );
  if( self->hashes_len ) {
    fun( w, NULL, "hashes", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->hashes_len; i++ )
      fd_slot_hash_walk(w, self->hashes + i, fun, "slot_hash", level, 0 );
    fun( w, NULL, "hashes", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_incremental_snapshot_hashes", level--, 0 );
}
ulong fd_gossip_incremental_snapshot_hashes_size( fd_gossip_incremental_snapshot_hashes_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->from );
  size += fd_slot_hash_size( &self->base_hash );
  do {
    size += sizeof(ulong);
    for( ulong i=0; i < self->hashes_len; i++ )
      size += fd_slot_hash_size( self->hashes + i );
  } while(0);
  size += sizeof(ulong);
  return size;
}

int fd_gossip_socket_entry_encode( fd_gossip_socket_entry_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint8_encode( (uchar)(self->key), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->index), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_compact_u16_encode( &self->offset, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_socket_entry_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  do { ushort _tmp; err = fd_bincode_compact_u16_decode( &_tmp, ctx ); } while(0);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_gossip_socket_entry_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_socket_entry_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_socket_entry_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_socket_entry_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_socket_entry_t * self = (fd_gossip_socket_entry_t *)struct_mem;
  fd_bincode_uint8_decode_unsafe( &self->key, ctx );
  fd_bincode_uint8_decode_unsafe( &self->index, ctx );
  fd_bincode_compact_u16_decode_unsafe( &self->offset, ctx );
}
void * fd_gossip_socket_entry_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_socket_entry_t * self = (fd_gossip_socket_entry_t *)mem;
  fd_gossip_socket_entry_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_socket_entry_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_socket_entry_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_socket_entry_new(fd_gossip_socket_entry_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_socket_entry_t) );
}
void fd_gossip_socket_entry_walk( void * w, fd_gossip_socket_entry_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_socket_entry", level++, 0 );
  fun( w, &self->key, "key", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fun( w, &self->index, "index", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fun( w, &self->offset, "offset", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 1  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_socket_entry", level--, 0 );
}
ulong fd_gossip_socket_entry_size( fd_gossip_socket_entry_t const * self ) {
  ulong size = 0;
  size += sizeof(char);
  size += sizeof(char);
  size += fd_bincode_compact_u16_size( &self->offset );
  return size;
}

int fd_gossip_contact_info_v2_encode( fd_gossip_contact_info_v2_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->from, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_varint_encode( self->wallclock, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->outset, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint16_encode( self->shred_version, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_version_v3_encode( &self->version, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_compact_u16_encode( &self->addrs_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->addrs_len ) {
    for( ulong i=0; i < self->addrs_len; i++ ) {
      err = fd_gossip_ip_addr_encode( self->addrs + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  err = fd_bincode_compact_u16_encode( &self->sockets_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->sockets_len ) {
    for( ulong i=0; i < self->sockets_len; i++ ) {
      err = fd_gossip_socket_entry_encode( self->sockets + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  err = fd_bincode_compact_u16_encode( &self->extensions_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->extensions_len ) {
    for( ulong i=0; i < self->extensions_len; i++ ) {
      err = fd_bincode_uint32_encode( self->extensions[i], ctx );
    }
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_contact_info_v2_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_varint_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint16_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_gossip_version_v3_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ushort addrs_len;
  err = fd_bincode_compact_u16_decode( &addrs_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( addrs_len ) {
    *total_sz += FD_GOSSIP_IP_ADDR_ALIGN + sizeof(fd_gossip_ip_addr_t)*addrs_len;
    for( ulong i=0; i < addrs_len; i++ ) {
      err = fd_gossip_ip_addr_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  ushort sockets_len;
  err = fd_bincode_compact_u16_decode( &sockets_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( sockets_len ) {
    *total_sz += FD_GOSSIP_SOCKET_ENTRY_ALIGN + sizeof(fd_gossip_socket_entry_t)*sockets_len;
    for( ulong i=0; i < sockets_len; i++ ) {
      err = fd_gossip_socket_entry_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  ushort extensions_len;
  err = fd_bincode_compact_u16_decode( &extensions_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( extensions_len ) {
    *total_sz += 8UL + sizeof(uint)*extensions_len;
    for( ulong i=0; i < extensions_len; i++ ) {
      err = fd_bincode_uint32_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_gossip_contact_info_v2_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_contact_info_v2_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_contact_info_v2_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_contact_info_v2_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_contact_info_v2_t * self = (fd_gossip_contact_info_v2_t *)struct_mem;
  fd_pubkey_decode_inner( &self->from, alloc_mem, ctx );
  fd_bincode_varint_decode_unsafe( &self->wallclock, ctx );
  fd_bincode_uint64_decode_unsafe( &self->outset, ctx );
  fd_bincode_uint16_decode_unsafe( &self->shred_version, ctx );
  fd_gossip_version_v3_decode_inner( &self->version, alloc_mem, ctx );
  fd_bincode_compact_u16_decode_unsafe( &self->addrs_len, ctx );
  if( self->addrs_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_GOSSIP_IP_ADDR_ALIGN );
    self->addrs = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_gossip_ip_addr_t)*self->addrs_len;
    for( ulong i=0; i < self->addrs_len; i++ ) {
      fd_gossip_ip_addr_new( self->addrs + i );
      fd_gossip_ip_addr_decode_inner( self->addrs + i, alloc_mem, ctx );
    }
  } else
    self->addrs = NULL;
  fd_bincode_compact_u16_decode_unsafe( &self->sockets_len, ctx );
  if( self->sockets_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_GOSSIP_SOCKET_ENTRY_ALIGN );
    self->sockets = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_gossip_socket_entry_t)*self->sockets_len;
    for( ulong i=0; i < self->sockets_len; i++ ) {
      fd_gossip_socket_entry_new( self->sockets + i );
      fd_gossip_socket_entry_decode_inner( self->sockets + i, alloc_mem, ctx );
    }
  } else
    self->sockets = NULL;
  fd_bincode_compact_u16_decode_unsafe( &self->extensions_len, ctx );
  if( self->extensions_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), 8UL );
    self->extensions = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(uint)*self->extensions_len;
    for( ulong i=0; i < self->extensions_len; i++ ) {
      fd_bincode_uint32_decode_unsafe( self->extensions + i, ctx );
    }
  } else
    self->extensions = NULL;
}
void * fd_gossip_contact_info_v2_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_contact_info_v2_t * self = (fd_gossip_contact_info_v2_t *)mem;
  fd_gossip_contact_info_v2_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_contact_info_v2_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_contact_info_v2_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_contact_info_v2_new(fd_gossip_contact_info_v2_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_contact_info_v2_t) );
  fd_pubkey_new( &self->from );
  fd_gossip_version_v3_new( &self->version );
}
void fd_gossip_contact_info_v2_walk( void * w, fd_gossip_contact_info_v2_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_contact_info_v2", level++, 0 );
  fd_pubkey_walk( w, &self->from, fun, "from", level, 0 );
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 1  );
  fun( w, &self->outset, "outset", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->shred_version, "shred_version", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 0  );
  fd_gossip_version_v3_walk( w, &self->version, fun, "version", level, 0 );
  fun( w, &self->addrs_len, "addrs_len", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 1 );
  if( self->addrs_len ) {
    fun( w, NULL, "addrs", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->addrs_len; i++ )
      fd_gossip_ip_addr_walk(w, self->addrs + i, fun, "gossip_ip_addr", level, 0 );
    fun( w, NULL, "addrs", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, &self->sockets_len, "sockets_len", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 1 );
  if( self->sockets_len ) {
    fun( w, NULL, "sockets", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->sockets_len; i++ )
      fd_gossip_socket_entry_walk(w, self->sockets + i, fun, "gossip_socket_entry", level, 0 );
    fun( w, NULL, "sockets", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, &self->extensions_len, "extensions_len", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 1 );
  if( self->extensions_len ) {
    fun( w, NULL, "extensions", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->extensions_len; i++ )
      fun( w, self->extensions + i, "extensions", FD_FLAMENCO_TYPE_UINT,    "uint",    level, 0 );
    fun( w, NULL, "extensions", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_contact_info_v2", level--, 0 );
}
ulong fd_gossip_contact_info_v2_size( fd_gossip_contact_info_v2_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->from );
  size += fd_bincode_varint_size( self->wallclock );
  size += sizeof(ulong);
  size += sizeof(ushort);
  size += fd_gossip_version_v3_size( &self->version );
  do {
    ushort tmp = (ushort)self->addrs_len;
    size += fd_bincode_compact_u16_size( &tmp );
    for( ulong i=0; i < self->addrs_len; i++ )
      size += fd_gossip_ip_addr_size( self->addrs + i );
  } while(0);
  do {
    ushort tmp = (ushort)self->sockets_len;
    size += fd_bincode_compact_u16_size( &tmp );
    for( ulong i=0; i < self->sockets_len; i++ )
      size += fd_gossip_socket_entry_size( self->sockets + i );
  } while(0);
  do {
    ushort tmp = (ushort)self->extensions_len;
    size += fd_bincode_compact_u16_size( &tmp );
    size += self->extensions_len * sizeof(uint);
  } while(0);
  return size;
}

int fd_restart_run_length_encoding_inner_encode( fd_restart_run_length_encoding_inner_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_compact_u16_encode( &self->bits, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_restart_run_length_encoding_inner_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  do { ushort _tmp; err = fd_bincode_compact_u16_decode( &_tmp, ctx ); } while(0);
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_restart_run_length_encoding_inner_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_restart_run_length_encoding_inner_t);
  void const * start_data = ctx->data;
  int err = fd_restart_run_length_encoding_inner_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_restart_run_length_encoding_inner_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_restart_run_length_encoding_inner_t * self = (fd_restart_run_length_encoding_inner_t *)struct_mem;
  fd_bincode_compact_u16_decode_unsafe( &self->bits, ctx );
}
void * fd_restart_run_length_encoding_inner_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_restart_run_length_encoding_inner_t * self = (fd_restart_run_length_encoding_inner_t *)mem;
  fd_restart_run_length_encoding_inner_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_restart_run_length_encoding_inner_t);
  void * * alloc_mem = &alloc_region;
  fd_restart_run_length_encoding_inner_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_restart_run_length_encoding_inner_new(fd_restart_run_length_encoding_inner_t * self) {
  fd_memset( self, 0, sizeof(fd_restart_run_length_encoding_inner_t) );
}
void fd_restart_run_length_encoding_inner_walk( void * w, fd_restart_run_length_encoding_inner_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_restart_run_length_encoding_inner", level++, 0 );
  fun( w, &self->bits, "bits", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 1  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_restart_run_length_encoding_inner", level--, 0 );
}
ulong fd_restart_run_length_encoding_inner_size( fd_restart_run_length_encoding_inner_t const * self ) {
  ulong size = 0;
  size += fd_bincode_compact_u16_size( &self->bits );
  return size;
}

int fd_restart_run_length_encoding_encode( fd_restart_run_length_encoding_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->offsets_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->offsets_len ) {
    for( ulong i=0; i < self->offsets_len; i++ ) {
      err = fd_restart_run_length_encoding_inner_encode( self->offsets + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_restart_run_length_encoding_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ulong offsets_len;
  err = fd_bincode_uint64_decode( &offsets_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( offsets_len ) {
    *total_sz += FD_RESTART_RUN_LENGTH_ENCODING_INNER_ALIGN + sizeof(fd_restart_run_length_encoding_inner_t)*offsets_len;
    for( ulong i=0; i < offsets_len; i++ ) {
      err = fd_restart_run_length_encoding_inner_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_restart_run_length_encoding_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_restart_run_length_encoding_t);
  void const * start_data = ctx->data;
  int err = fd_restart_run_length_encoding_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_restart_run_length_encoding_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_restart_run_length_encoding_t * self = (fd_restart_run_length_encoding_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->offsets_len, ctx );
  if( self->offsets_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_RESTART_RUN_LENGTH_ENCODING_INNER_ALIGN );
    self->offsets = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_restart_run_length_encoding_inner_t)*self->offsets_len;
    for( ulong i=0; i < self->offsets_len; i++ ) {
      fd_restart_run_length_encoding_inner_new( self->offsets + i );
      fd_restart_run_length_encoding_inner_decode_inner( self->offsets + i, alloc_mem, ctx );
    }
  } else
    self->offsets = NULL;
}
void * fd_restart_run_length_encoding_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_restart_run_length_encoding_t * self = (fd_restart_run_length_encoding_t *)mem;
  fd_restart_run_length_encoding_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_restart_run_length_encoding_t);
  void * * alloc_mem = &alloc_region;
  fd_restart_run_length_encoding_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_restart_run_length_encoding_new(fd_restart_run_length_encoding_t * self) {
  fd_memset( self, 0, sizeof(fd_restart_run_length_encoding_t) );
}
void fd_restart_run_length_encoding_walk( void * w, fd_restart_run_length_encoding_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_restart_run_length_encoding", level++, 0 );
  if( self->offsets_len ) {
    fun( w, NULL, "offsets", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->offsets_len; i++ )
      fd_restart_run_length_encoding_inner_walk(w, self->offsets + i, fun, "restart_run_length_encoding_inner", level, 0 );
    fun( w, NULL, "offsets", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_restart_run_length_encoding", level--, 0 );
}
ulong fd_restart_run_length_encoding_size( fd_restart_run_length_encoding_t const * self ) {
  ulong size = 0;
  do {
    size += sizeof(ulong);
    for( ulong i=0; i < self->offsets_len; i++ )
      size += fd_restart_run_length_encoding_inner_size( self->offsets + i );
  } while(0);
  return size;
}

int fd_restart_raw_offsets_encode( fd_restart_raw_offsets_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_bool_encode( self->has_offsets, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_offsets ) {
    err = fd_bincode_uint64_encode( self->offsets_bitvec_len, ctx );
    if( FD_UNLIKELY(err) ) return err;
    if( self->offsets_bitvec_len ) {
      err = fd_bincode_bytes_encode( self->offsets_bitvec, self->offsets_bitvec_len, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint64_encode( self->offsets_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_restart_raw_offsets_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  {
    uchar o;
    ulong inner_len = 0UL;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      ulong offsets_bitvec_len;
      err = fd_bincode_uint64_decode( &offsets_bitvec_len, ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
      if( offsets_bitvec_len ) {
        *total_sz += 8UL + offsets_bitvec_len;
        err = fd_bincode_bytes_decode_footprint( offsets_bitvec_len, ctx );
        if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
      }
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
      inner_len = offsets_bitvec_len;
      if( inner_len==0 ) return FD_BINCODE_ERR_ENCODING;
    }
    ulong len;
    err = fd_bincode_uint64_decode( &len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( len > inner_len * sizeof(uchar) * 8UL ) return FD_BINCODE_ERR_ENCODING;
  }
  return 0;
}
int fd_restart_raw_offsets_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_restart_raw_offsets_t);
  void const * start_data = ctx->data;
  int err = fd_restart_raw_offsets_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_restart_raw_offsets_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_restart_raw_offsets_t * self = (fd_restart_raw_offsets_t *)struct_mem;
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_offsets = !!o;
    if( o ) {
      fd_bincode_uint64_decode_unsafe( &self->offsets_bitvec_len, ctx );
      if( self->offsets_bitvec_len ) {
        self->offsets_bitvec = *alloc_mem;
        fd_bincode_bytes_decode_unsafe( self->offsets_bitvec, self->offsets_bitvec_len, ctx );
        *alloc_mem = (uchar *)(*alloc_mem) + self->offsets_bitvec_len;
      } else
        self->offsets_bitvec = NULL;
    } else {
      self->offsets_bitvec = NULL;
    }
    fd_bincode_uint64_decode_unsafe( &self->offsets_len, ctx );
  }
}
void * fd_restart_raw_offsets_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_restart_raw_offsets_t * self = (fd_restart_raw_offsets_t *)mem;
  fd_restart_raw_offsets_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_restart_raw_offsets_t);
  void * * alloc_mem = &alloc_region;
  fd_restart_raw_offsets_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_restart_raw_offsets_new(fd_restart_raw_offsets_t * self) {
  fd_memset( self, 0, sizeof(fd_restart_raw_offsets_t) );
}
void fd_restart_raw_offsets_walk( void * w, fd_restart_raw_offsets_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_restart_raw_offsets", level++, 0 );
  if( !self->has_offsets ) {
    fun( w, NULL, "offsets", FD_FLAMENCO_TYPE_NULL, "uchar", level, 0 );
  } else {
    if( self->offsets_bitvec_len ) {
      fun( w, NULL, "offsets_bitvec", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
      for( ulong i=0; i < self->offsets_bitvec_len; i++ )
      fun( w, self->offsets_bitvec + i, "offsets_bitvec", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
      fun( w, NULL, "offsets_bitvec", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
    }
  }
  fun( w, &self->offsets_len, "offsets_len", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_restart_raw_offsets", level--, 0 );
}
ulong fd_restart_raw_offsets_size( fd_restart_raw_offsets_t const * self ) {
  ulong size = 0;
  size += sizeof(char);
  if( self->has_offsets ) {
    do {
      size += sizeof(ulong);
      size += self->offsets_bitvec_len;
    } while(0);
  }
  size += sizeof(ulong);
  return size;
}

FD_FN_PURE uchar fd_restart_slots_offsets_is_run_length_encoding(fd_restart_slots_offsets_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_restart_slots_offsets_is_raw_offsets(fd_restart_slots_offsets_t const * self) {
  return self->discriminant == 1;
}
void fd_restart_slots_offsets_inner_new( fd_restart_slots_offsets_inner_t * self, uint discriminant );
int fd_restart_slots_offsets_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_restart_run_length_encoding_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_restart_raw_offsets_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_restart_slots_offsets_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_restart_slots_offsets_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_restart_slots_offsets_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_restart_slots_offsets_t);
  void const * start_data = ctx->data;
  int err =  fd_restart_slots_offsets_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_restart_slots_offsets_inner_decode_inner( fd_restart_slots_offsets_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    fd_restart_run_length_encoding_decode_inner( &self->run_length_encoding, alloc_mem, ctx );
    break;
  }
  case 1: {
    fd_restart_raw_offsets_decode_inner( &self->raw_offsets, alloc_mem, ctx );
    break;
  }
  }
}
static void fd_restart_slots_offsets_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_restart_slots_offsets_t * self = (fd_restart_slots_offsets_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_restart_slots_offsets_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_restart_slots_offsets_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_restart_slots_offsets_t * self = (fd_restart_slots_offsets_t *)mem;
  fd_restart_slots_offsets_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_restart_slots_offsets_t);
  void * * alloc_mem = &alloc_region;
  fd_restart_slots_offsets_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_restart_slots_offsets_inner_new( fd_restart_slots_offsets_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    fd_restart_run_length_encoding_new( &self->run_length_encoding );
    break;
  }
  case 1: {
    fd_restart_raw_offsets_new( &self->raw_offsets );
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_restart_slots_offsets_new_disc( fd_restart_slots_offsets_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_restart_slots_offsets_inner_new( &self->inner, self->discriminant );
}
void fd_restart_slots_offsets_new( fd_restart_slots_offsets_t * self ) {
  fd_memset( self, 0, sizeof(fd_restart_slots_offsets_t) );
  fd_restart_slots_offsets_new_disc( self, UINT_MAX );
}

void fd_restart_slots_offsets_walk( void * w, fd_restart_slots_offsets_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_restart_slots_offsets", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "run_length_encoding", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_restart_run_length_encoding_walk( w, &self->inner.run_length_encoding, fun, "run_length_encoding", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "raw_offsets", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_restart_raw_offsets_walk( w, &self->inner.raw_offsets, fun, "raw_offsets", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_restart_slots_offsets", level--, 0 );
}
ulong fd_restart_slots_offsets_size( fd_restart_slots_offsets_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_restart_run_length_encoding_size( &self->inner.run_length_encoding );
    break;
  }
  case 1: {
    size += fd_restart_raw_offsets_size( &self->inner.raw_offsets );
    break;
  }
  }
  return size;
}

int fd_restart_slots_offsets_inner_encode( fd_restart_slots_offsets_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_restart_run_length_encoding_encode( &self->run_length_encoding, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 1: {
    err = fd_restart_raw_offsets_encode( &self->raw_offsets, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_restart_slots_offsets_encode( fd_restart_slots_offsets_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_restart_slots_offsets_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_gossip_restart_last_voted_fork_slots_encode( fd_gossip_restart_last_voted_fork_slots_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->from, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->wallclock, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_restart_slots_offsets_encode( &self->offsets, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->last_voted_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_hash_encode( &self->last_voted_hash, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint16_encode( self->shred_version, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_restart_last_voted_fork_slots_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_restart_slots_offsets_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_hash_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint16_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_gossip_restart_last_voted_fork_slots_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_restart_last_voted_fork_slots_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_restart_last_voted_fork_slots_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_restart_last_voted_fork_slots_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_restart_last_voted_fork_slots_t * self = (fd_gossip_restart_last_voted_fork_slots_t *)struct_mem;
  fd_pubkey_decode_inner( &self->from, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->wallclock, ctx );
  fd_restart_slots_offsets_decode_inner( &self->offsets, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->last_voted_slot, ctx );
  fd_hash_decode_inner( &self->last_voted_hash, alloc_mem, ctx );
  fd_bincode_uint16_decode_unsafe( &self->shred_version, ctx );
}
void * fd_gossip_restart_last_voted_fork_slots_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_restart_last_voted_fork_slots_t * self = (fd_gossip_restart_last_voted_fork_slots_t *)mem;
  fd_gossip_restart_last_voted_fork_slots_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_restart_last_voted_fork_slots_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_restart_last_voted_fork_slots_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_restart_last_voted_fork_slots_new(fd_gossip_restart_last_voted_fork_slots_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_restart_last_voted_fork_slots_t) );
  fd_pubkey_new( &self->from );
  fd_restart_slots_offsets_new( &self->offsets );
  fd_hash_new( &self->last_voted_hash );
}
void fd_gossip_restart_last_voted_fork_slots_walk( void * w, fd_gossip_restart_last_voted_fork_slots_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_restart_last_voted_fork_slots", level++, 0 );
  fd_pubkey_walk( w, &self->from, fun, "from", level, 0 );
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_restart_slots_offsets_walk( w, &self->offsets, fun, "offsets", level, 0 );
  fun( w, &self->last_voted_slot, "last_voted_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_hash_walk( w, &self->last_voted_hash, fun, "last_voted_hash", level, 0 );
  fun( w, &self->shred_version, "shred_version", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_restart_last_voted_fork_slots", level--, 0 );
}
ulong fd_gossip_restart_last_voted_fork_slots_size( fd_gossip_restart_last_voted_fork_slots_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->from );
  size += sizeof(ulong);
  size += fd_restart_slots_offsets_size( &self->offsets );
  size += sizeof(ulong);
  size += fd_hash_size( &self->last_voted_hash );
  size += sizeof(ushort);
  return size;
}

int fd_gossip_restart_heaviest_fork_encode( fd_gossip_restart_heaviest_fork_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->from, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->wallclock, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->last_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_hash_encode( &self->last_slot_hash, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->observed_stake, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint16_encode( self->shred_version, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_gossip_restart_heaviest_fork_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 90UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 90UL );
  return 0;
}
static void fd_gossip_restart_heaviest_fork_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_restart_heaviest_fork_t * self = (fd_gossip_restart_heaviest_fork_t *)struct_mem;
  fd_pubkey_decode_inner( &self->from, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->wallclock, ctx );
  fd_bincode_uint64_decode_unsafe( &self->last_slot, ctx );
  fd_hash_decode_inner( &self->last_slot_hash, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->observed_stake, ctx );
  fd_bincode_uint16_decode_unsafe( &self->shred_version, ctx );
}
void * fd_gossip_restart_heaviest_fork_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_restart_heaviest_fork_t * self = (fd_gossip_restart_heaviest_fork_t *)mem;
  fd_gossip_restart_heaviest_fork_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_restart_heaviest_fork_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_restart_heaviest_fork_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_restart_heaviest_fork_walk( void * w, fd_gossip_restart_heaviest_fork_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_restart_heaviest_fork", level++, 0 );
  fd_pubkey_walk( w, &self->from, fun, "from", level, 0 );
  fun( w, &self->wallclock, "wallclock", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->last_slot, "last_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_hash_walk( w, &self->last_slot_hash, fun, "last_slot_hash", level, 0 );
  fun( w, &self->observed_stake, "observed_stake", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->shred_version, "shred_version", FD_FLAMENCO_TYPE_USHORT, "ushort", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_restart_heaviest_fork", level--, 0 );
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
FD_FN_PURE uchar fd_crds_data_is_restart_last_voted_fork_slots(fd_crds_data_t const * self) {
  return self->discriminant == 12;
}
FD_FN_PURE uchar fd_crds_data_is_restart_heaviest_fork(fd_crds_data_t const * self) {
  return self->discriminant == 13;
}
void fd_crds_data_inner_new( fd_crds_data_inner_t * self, uint discriminant );
int fd_crds_data_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_contact_info_v1_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_gossip_vote_old_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_gossip_lowest_slot_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    err = fd_gossip_slot_hashes_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    err = fd_gossip_slot_hashes_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 5: {
    err = fd_gossip_epoch_slots_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 6: {
    err = fd_gossip_version_v1_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 7: {
    err = fd_gossip_version_v2_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 8: {
    err = fd_gossip_node_instance_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 9: {
    err = fd_gossip_duplicate_shred_old_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 10: {
    err = fd_gossip_incremental_snapshot_hashes_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 11: {
    err = fd_gossip_contact_info_v2_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 12: {
    err = fd_gossip_restart_last_voted_fork_slots_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 13: {
    err = fd_gossip_restart_heaviest_fork_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_crds_data_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_crds_data_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_crds_data_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_crds_data_t);
  void const * start_data = ctx->data;
  int err =  fd_crds_data_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_crds_data_inner_decode_inner( fd_crds_data_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    fd_gossip_contact_info_v1_decode_inner( &self->contact_info_v1, alloc_mem, ctx );
    break;
  }
  case 1: {
    fd_gossip_vote_old_decode_inner( &self->vote, alloc_mem, ctx );
    break;
  }
  case 2: {
    fd_gossip_lowest_slot_decode_inner( &self->lowest_slot, alloc_mem, ctx );
    break;
  }
  case 3: {
    fd_gossip_slot_hashes_decode_inner( &self->snapshot_hashes, alloc_mem, ctx );
    break;
  }
  case 4: {
    fd_gossip_slot_hashes_decode_inner( &self->accounts_hashes, alloc_mem, ctx );
    break;
  }
  case 5: {
    fd_gossip_epoch_slots_decode_inner( &self->epoch_slots, alloc_mem, ctx );
    break;
  }
  case 6: {
    fd_gossip_version_v1_decode_inner( &self->version_v1, alloc_mem, ctx );
    break;
  }
  case 7: {
    fd_gossip_version_v2_decode_inner( &self->version_v2, alloc_mem, ctx );
    break;
  }
  case 8: {
    fd_gossip_node_instance_decode_inner( &self->node_instance, alloc_mem, ctx );
    break;
  }
  case 9: {
    fd_gossip_duplicate_shred_old_decode_inner( &self->duplicate_shred, alloc_mem, ctx );
    break;
  }
  case 10: {
    fd_gossip_incremental_snapshot_hashes_decode_inner( &self->incremental_snapshot_hashes, alloc_mem, ctx );
    break;
  }
  case 11: {
    fd_gossip_contact_info_v2_decode_inner( &self->contact_info_v2, alloc_mem, ctx );
    break;
  }
  case 12: {
    fd_gossip_restart_last_voted_fork_slots_decode_inner( &self->restart_last_voted_fork_slots, alloc_mem, ctx );
    break;
  }
  case 13: {
    fd_gossip_restart_heaviest_fork_decode_inner( &self->restart_heaviest_fork, alloc_mem, ctx );
    break;
  }
  }
}
static void fd_crds_data_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_crds_data_t * self = (fd_crds_data_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_crds_data_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_crds_data_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_crds_data_t * self = (fd_crds_data_t *)mem;
  fd_crds_data_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_crds_data_t);
  void * * alloc_mem = &alloc_region;
  fd_crds_data_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_crds_data_inner_new( fd_crds_data_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    fd_gossip_contact_info_v1_new( &self->contact_info_v1 );
    break;
  }
  case 1: {
    fd_gossip_vote_old_new( &self->vote );
    break;
  }
  case 2: {
    fd_gossip_lowest_slot_new( &self->lowest_slot );
    break;
  }
  case 3: {
    fd_gossip_slot_hashes_new( &self->snapshot_hashes );
    break;
  }
  case 4: {
    fd_gossip_slot_hashes_new( &self->accounts_hashes );
    break;
  }
  case 5: {
    fd_gossip_epoch_slots_new( &self->epoch_slots );
    break;
  }
  case 6: {
    fd_gossip_version_v1_new( &self->version_v1 );
    break;
  }
  case 7: {
    fd_gossip_version_v2_new( &self->version_v2 );
    break;
  }
  case 8: {
    fd_gossip_node_instance_new( &self->node_instance );
    break;
  }
  case 9: {
    fd_gossip_duplicate_shred_old_new( &self->duplicate_shred );
    break;
  }
  case 10: {
    fd_gossip_incremental_snapshot_hashes_new( &self->incremental_snapshot_hashes );
    break;
  }
  case 11: {
    fd_gossip_contact_info_v2_new( &self->contact_info_v2 );
    break;
  }
  case 12: {
    fd_gossip_restart_last_voted_fork_slots_new( &self->restart_last_voted_fork_slots );
    break;
  }
  case 13: {
    fd_gossip_restart_heaviest_fork_new( &self->restart_heaviest_fork );
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_crds_data_new_disc( fd_crds_data_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_crds_data_inner_new( &self->inner, self->discriminant );
}
void fd_crds_data_new( fd_crds_data_t * self ) {
  fd_memset( self, 0, sizeof(fd_crds_data_t) );
  fd_crds_data_new_disc( self, UINT_MAX );
}

void fd_crds_data_walk( void * w, fd_crds_data_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_crds_data", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "contact_info_v1", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_contact_info_v1_walk( w, &self->inner.contact_info_v1, fun, "contact_info_v1", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "vote", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_vote_old_walk( w, &self->inner.vote, fun, "vote", level, 0 );
    break;
  }
  case 2: {
    fun( w, self, "lowest_slot", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_lowest_slot_walk( w, &self->inner.lowest_slot, fun, "lowest_slot", level, 0 );
    break;
  }
  case 3: {
    fun( w, self, "snapshot_hashes", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_slot_hashes_walk( w, &self->inner.snapshot_hashes, fun, "snapshot_hashes", level, 0 );
    break;
  }
  case 4: {
    fun( w, self, "accounts_hashes", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_slot_hashes_walk( w, &self->inner.accounts_hashes, fun, "accounts_hashes", level, 0 );
    break;
  }
  case 5: {
    fun( w, self, "epoch_slots", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_epoch_slots_walk( w, &self->inner.epoch_slots, fun, "epoch_slots", level, 0 );
    break;
  }
  case 6: {
    fun( w, self, "version_v1", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_version_v1_walk( w, &self->inner.version_v1, fun, "version_v1", level, 0 );
    break;
  }
  case 7: {
    fun( w, self, "version_v2", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_version_v2_walk( w, &self->inner.version_v2, fun, "version_v2", level, 0 );
    break;
  }
  case 8: {
    fun( w, self, "node_instance", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_node_instance_walk( w, &self->inner.node_instance, fun, "node_instance", level, 0 );
    break;
  }
  case 9: {
    fun( w, self, "duplicate_shred", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_duplicate_shred_old_walk( w, &self->inner.duplicate_shred, fun, "duplicate_shred", level, 0 );
    break;
  }
  case 10: {
    fun( w, self, "incremental_snapshot_hashes", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_incremental_snapshot_hashes_walk( w, &self->inner.incremental_snapshot_hashes, fun, "incremental_snapshot_hashes", level, 0 );
    break;
  }
  case 11: {
    fun( w, self, "contact_info_v2", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_contact_info_v2_walk( w, &self->inner.contact_info_v2, fun, "contact_info_v2", level, 0 );
    break;
  }
  case 12: {
    fun( w, self, "restart_last_voted_fork_slots", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_restart_last_voted_fork_slots_walk( w, &self->inner.restart_last_voted_fork_slots, fun, "restart_last_voted_fork_slots", level, 0 );
    break;
  }
  case 13: {
    fun( w, self, "restart_heaviest_fork", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_restart_heaviest_fork_walk( w, &self->inner.restart_heaviest_fork, fun, "restart_heaviest_fork", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_crds_data", level--, 0 );
}
ulong fd_crds_data_size( fd_crds_data_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_gossip_contact_info_v1_size( &self->inner.contact_info_v1 );
    break;
  }
  case 1: {
    size += fd_gossip_vote_old_size( &self->inner.vote );
    break;
  }
  case 2: {
    size += fd_gossip_lowest_slot_size( &self->inner.lowest_slot );
    break;
  }
  case 3: {
    size += fd_gossip_slot_hashes_size( &self->inner.snapshot_hashes );
    break;
  }
  case 4: {
    size += fd_gossip_slot_hashes_size( &self->inner.accounts_hashes );
    break;
  }
  case 5: {
    size += fd_gossip_epoch_slots_size( &self->inner.epoch_slots );
    break;
  }
  case 6: {
    size += fd_gossip_version_v1_size( &self->inner.version_v1 );
    break;
  }
  case 7: {
    size += fd_gossip_version_v2_size( &self->inner.version_v2 );
    break;
  }
  case 8: {
    size += fd_gossip_node_instance_size( &self->inner.node_instance );
    break;
  }
  case 9: {
    size += fd_gossip_duplicate_shred_old_size( &self->inner.duplicate_shred );
    break;
  }
  case 10: {
    size += fd_gossip_incremental_snapshot_hashes_size( &self->inner.incremental_snapshot_hashes );
    break;
  }
  case 11: {
    size += fd_gossip_contact_info_v2_size( &self->inner.contact_info_v2 );
    break;
  }
  case 12: {
    size += fd_gossip_restart_last_voted_fork_slots_size( &self->inner.restart_last_voted_fork_slots );
    break;
  }
  case 13: {
    size += fd_gossip_restart_heaviest_fork_size( &self->inner.restart_heaviest_fork );
    break;
  }
  }
  return size;
}

int fd_crds_data_inner_encode( fd_crds_data_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_contact_info_v1_encode( &self->contact_info_v1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 1: {
    err = fd_gossip_vote_old_encode( &self->vote, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 2: {
    err = fd_gossip_lowest_slot_encode( &self->lowest_slot, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 3: {
    err = fd_gossip_slot_hashes_encode( &self->snapshot_hashes, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 4: {
    err = fd_gossip_slot_hashes_encode( &self->accounts_hashes, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 5: {
    err = fd_gossip_epoch_slots_encode( &self->epoch_slots, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 6: {
    err = fd_gossip_version_v1_encode( &self->version_v1, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 7: {
    err = fd_gossip_version_v2_encode( &self->version_v2, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 8: {
    err = fd_gossip_node_instance_encode( &self->node_instance, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 9: {
    err = fd_gossip_duplicate_shred_old_encode( &self->duplicate_shred, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 10: {
    err = fd_gossip_incremental_snapshot_hashes_encode( &self->incremental_snapshot_hashes, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 11: {
    err = fd_gossip_contact_info_v2_encode( &self->contact_info_v2, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 12: {
    err = fd_gossip_restart_last_voted_fork_slots_encode( &self->restart_last_voted_fork_slots, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 13: {
    err = fd_gossip_restart_heaviest_fork_encode( &self->restart_heaviest_fork, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_crds_data_encode( fd_crds_data_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_crds_data_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_crds_bloom_encode( fd_crds_bloom_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->keys_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->keys_len ) {
    for( ulong i=0; i < self->keys_len; i++ ) {
      err = fd_bincode_uint64_encode( self->keys[i], ctx );
    }
  }
  err = fd_bincode_bool_encode( self->has_bits, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  if( self->has_bits ) {
    err = fd_bincode_uint64_encode( self->bits_bitvec_len, ctx );
    if( FD_UNLIKELY(err) ) return err;
    if( self->bits_bitvec_len ) {
      for( ulong i=0; i < self->bits_bitvec_len; i++ ) {
        err = fd_bincode_uint64_encode( self->bits_bitvec[i], ctx );
      }
    }
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint64_encode( self->bits_len, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->num_bits_set, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_crds_bloom_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ulong keys_len;
  err = fd_bincode_uint64_decode( &keys_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( keys_len ) {
    *total_sz += 8UL + sizeof(ulong)*keys_len;
    for( ulong i=0; i < keys_len; i++ ) {
      err = fd_bincode_uint64_decode_footprint( ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  {
    uchar o;
    ulong inner_len = 0UL;
    err = fd_bincode_bool_decode( &o, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( o ) {
      ulong bits_bitvec_len;
      err = fd_bincode_uint64_decode( &bits_bitvec_len, ctx );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
      if( bits_bitvec_len ) {
        *total_sz += 8UL + sizeof(ulong)*bits_bitvec_len;
        for( ulong i=0; i < bits_bitvec_len; i++ ) {
          err = fd_bincode_uint64_decode_footprint( ctx );
          if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
        }
      }
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
      inner_len = bits_bitvec_len;
      if( inner_len==0 ) return FD_BINCODE_ERR_ENCODING;
    }
    ulong len;
    err = fd_bincode_uint64_decode( &len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    if( len > inner_len * sizeof(ulong) * 8UL ) return FD_BINCODE_ERR_ENCODING;
  }
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_crds_bloom_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_crds_bloom_t);
  void const * start_data = ctx->data;
  int err = fd_crds_bloom_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_crds_bloom_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_crds_bloom_t * self = (fd_crds_bloom_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->keys_len, ctx );
  if( self->keys_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), 8UL );
    self->keys = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(ulong)*self->keys_len;
    for( ulong i=0; i < self->keys_len; i++ ) {
      fd_bincode_uint64_decode_unsafe( self->keys + i, ctx );
    }
  } else
    self->keys = NULL;
  {
    uchar o;
    fd_bincode_bool_decode_unsafe( &o, ctx );
    self->has_bits = !!o;
    if( o ) {
      fd_bincode_uint64_decode_unsafe( &self->bits_bitvec_len, ctx );
      if( self->bits_bitvec_len ) {
        *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), 8UL );
        self->bits_bitvec = *alloc_mem;
        *alloc_mem = (uchar *)(*alloc_mem) + sizeof(ulong)*self->bits_bitvec_len;
        for( ulong i=0; i < self->bits_bitvec_len; i++ ) {
          fd_bincode_uint64_decode_unsafe( self->bits_bitvec + i, ctx );
        }
      } else
        self->bits_bitvec = NULL;
    } else {
      self->bits_bitvec = NULL;
    }
    fd_bincode_uint64_decode_unsafe( &self->bits_len, ctx );
  }
  fd_bincode_uint64_decode_unsafe( &self->num_bits_set, ctx );
}
void * fd_crds_bloom_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_crds_bloom_t * self = (fd_crds_bloom_t *)mem;
  fd_crds_bloom_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_crds_bloom_t);
  void * * alloc_mem = &alloc_region;
  fd_crds_bloom_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_crds_bloom_new(fd_crds_bloom_t * self) {
  fd_memset( self, 0, sizeof(fd_crds_bloom_t) );
}
void fd_crds_bloom_walk( void * w, fd_crds_bloom_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_crds_bloom", level++, 0 );
  if( self->keys_len ) {
    fun( w, NULL, "keys", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->keys_len; i++ )
      fun( w, self->keys + i, "keys", FD_FLAMENCO_TYPE_ULONG,   "ulong",   level, 0 );
    fun( w, NULL, "keys", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  if( !self->has_bits ) {
    fun( w, NULL, "bits", FD_FLAMENCO_TYPE_NULL, "ulong", level, 0 );
  } else {
    if( self->bits_bitvec_len ) {
      fun( w, NULL, "bits_bitvec", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
      for( ulong i=0; i < self->bits_bitvec_len; i++ )
      fun( w, self->bits_bitvec + i, "bits_bitvec", FD_FLAMENCO_TYPE_ULONG,   "ulong",   level, 0 );
      fun( w, NULL, "bits_bitvec", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
    }
  }
  fun( w, &self->bits_len, "bits_len", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0 );
  fun( w, &self->num_bits_set, "num_bits_set", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_crds_bloom", level--, 0 );
}
ulong fd_crds_bloom_size( fd_crds_bloom_t const * self ) {
  ulong size = 0;
  do {
    size += sizeof(ulong);
    size += self->keys_len * sizeof(ulong);
  } while(0);
  size += sizeof(char);
  if( self->has_bits ) {
    do {
      size += sizeof(ulong);
      size += self->bits_bitvec_len * sizeof(ulong);
    } while(0);
  }
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_crds_filter_encode( fd_crds_filter_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_crds_bloom_encode( &self->filter, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->mask, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint32_encode( self->mask_bits, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_crds_filter_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_crds_bloom_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint32_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_crds_filter_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_crds_filter_t);
  void const * start_data = ctx->data;
  int err = fd_crds_filter_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_crds_filter_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_crds_filter_t * self = (fd_crds_filter_t *)struct_mem;
  fd_crds_bloom_decode_inner( &self->filter, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->mask, ctx );
  fd_bincode_uint32_decode_unsafe( &self->mask_bits, ctx );
}
void * fd_crds_filter_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_crds_filter_t * self = (fd_crds_filter_t *)mem;
  fd_crds_filter_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_crds_filter_t);
  void * * alloc_mem = &alloc_region;
  fd_crds_filter_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_crds_filter_new(fd_crds_filter_t * self) {
  fd_memset( self, 0, sizeof(fd_crds_filter_t) );
  fd_crds_bloom_new( &self->filter );
}
void fd_crds_filter_walk( void * w, fd_crds_filter_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_crds_filter", level++, 0 );
  fd_crds_bloom_walk( w, &self->filter, fun, "filter", level, 0 );
  fun( w, &self->mask, "mask", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->mask_bits, "mask_bits", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_crds_filter", level--, 0 );
}
ulong fd_crds_filter_size( fd_crds_filter_t const * self ) {
  ulong size = 0;
  size += fd_crds_bloom_size( &self->filter );
  size += sizeof(ulong);
  size += sizeof(uint);
  return size;
}

int fd_crds_value_encode( fd_crds_value_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_signature_encode( &self->signature, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_crds_data_encode( &self->data, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_crds_value_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_signature_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_crds_data_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_crds_value_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_crds_value_t);
  void const * start_data = ctx->data;
  int err = fd_crds_value_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_crds_value_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_crds_value_t * self = (fd_crds_value_t *)struct_mem;
  fd_signature_decode_inner( &self->signature, alloc_mem, ctx );
  fd_crds_data_decode_inner( &self->data, alloc_mem, ctx );
}
void * fd_crds_value_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_crds_value_t * self = (fd_crds_value_t *)mem;
  fd_crds_value_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_crds_value_t);
  void * * alloc_mem = &alloc_region;
  fd_crds_value_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_crds_value_new(fd_crds_value_t * self) {
  fd_memset( self, 0, sizeof(fd_crds_value_t) );
  fd_signature_new( &self->signature );
  fd_crds_data_new( &self->data );
}
void fd_crds_value_walk( void * w, fd_crds_value_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_crds_value", level++, 0 );
  fd_signature_walk( w, &self->signature, fun, "signature", level, 0 );
  fd_crds_data_walk( w, &self->data, fun, "data", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_crds_value", level--, 0 );
}
ulong fd_crds_value_size( fd_crds_value_t const * self ) {
  ulong size = 0;
  size += fd_signature_size( &self->signature );
  size += fd_crds_data_size( &self->data );
  return size;
}

int fd_gossip_pull_req_encode( fd_gossip_pull_req_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_crds_filter_encode( &self->filter, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_crds_value_encode( &self->value, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_pull_req_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_crds_filter_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_crds_value_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_gossip_pull_req_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_pull_req_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_pull_req_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_pull_req_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_pull_req_t * self = (fd_gossip_pull_req_t *)struct_mem;
  fd_crds_filter_decode_inner( &self->filter, alloc_mem, ctx );
  fd_crds_value_decode_inner( &self->value, alloc_mem, ctx );
}
void * fd_gossip_pull_req_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_pull_req_t * self = (fd_gossip_pull_req_t *)mem;
  fd_gossip_pull_req_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_pull_req_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_pull_req_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_pull_req_new(fd_gossip_pull_req_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_pull_req_t) );
  fd_crds_filter_new( &self->filter );
  fd_crds_value_new( &self->value );
}
void fd_gossip_pull_req_walk( void * w, fd_gossip_pull_req_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_pull_req", level++, 0 );
  fd_crds_filter_walk( w, &self->filter, fun, "filter", level, 0 );
  fd_crds_value_walk( w, &self->value, fun, "value", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_pull_req", level--, 0 );
}
ulong fd_gossip_pull_req_size( fd_gossip_pull_req_t const * self ) {
  ulong size = 0;
  size += fd_crds_filter_size( &self->filter );
  size += fd_crds_value_size( &self->value );
  return size;
}

int fd_gossip_pull_resp_encode( fd_gossip_pull_resp_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->crds_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->crds_len ) {
    for( ulong i=0; i < self->crds_len; i++ ) {
      err = fd_crds_value_encode( self->crds + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_pull_resp_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ulong crds_len;
  err = fd_bincode_uint64_decode( &crds_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( crds_len ) {
    *total_sz += FD_CRDS_VALUE_ALIGN + sizeof(fd_crds_value_t)*crds_len;
    for( ulong i=0; i < crds_len; i++ ) {
      err = fd_crds_value_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_gossip_pull_resp_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_pull_resp_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_pull_resp_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_pull_resp_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_pull_resp_t * self = (fd_gossip_pull_resp_t *)struct_mem;
  fd_pubkey_decode_inner( &self->pubkey, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->crds_len, ctx );
  if( self->crds_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_CRDS_VALUE_ALIGN );
    self->crds = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_crds_value_t)*self->crds_len;
    for( ulong i=0; i < self->crds_len; i++ ) {
      fd_crds_value_new( self->crds + i );
      fd_crds_value_decode_inner( self->crds + i, alloc_mem, ctx );
    }
  } else
    self->crds = NULL;
}
void * fd_gossip_pull_resp_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_pull_resp_t * self = (fd_gossip_pull_resp_t *)mem;
  fd_gossip_pull_resp_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_pull_resp_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_pull_resp_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_pull_resp_new(fd_gossip_pull_resp_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_pull_resp_t) );
  fd_pubkey_new( &self->pubkey );
}
void fd_gossip_pull_resp_walk( void * w, fd_gossip_pull_resp_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_pull_resp", level++, 0 );
  fd_pubkey_walk( w, &self->pubkey, fun, "pubkey", level, 0 );
  if( self->crds_len ) {
    fun( w, NULL, "crds", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->crds_len; i++ )
      fd_crds_value_walk(w, self->crds + i, fun, "crds_value", level, 0 );
    fun( w, NULL, "crds", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_pull_resp", level--, 0 );
}
ulong fd_gossip_pull_resp_size( fd_gossip_pull_resp_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->pubkey );
  do {
    size += sizeof(ulong);
    for( ulong i=0; i < self->crds_len; i++ )
      size += fd_crds_value_size( self->crds + i );
  } while(0);
  return size;
}

int fd_gossip_push_msg_encode( fd_gossip_push_msg_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->crds_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->crds_len ) {
    for( ulong i=0; i < self->crds_len; i++ ) {
      err = fd_crds_value_encode( self->crds + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_push_msg_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  ulong crds_len;
  err = fd_bincode_uint64_decode( &crds_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( crds_len ) {
    *total_sz += FD_CRDS_VALUE_ALIGN + sizeof(fd_crds_value_t)*crds_len;
    for( ulong i=0; i < crds_len; i++ ) {
      err = fd_crds_value_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_gossip_push_msg_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_push_msg_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_push_msg_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_push_msg_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_push_msg_t * self = (fd_gossip_push_msg_t *)struct_mem;
  fd_pubkey_decode_inner( &self->pubkey, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->crds_len, ctx );
  if( self->crds_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_CRDS_VALUE_ALIGN );
    self->crds = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_crds_value_t)*self->crds_len;
    for( ulong i=0; i < self->crds_len; i++ ) {
      fd_crds_value_new( self->crds + i );
      fd_crds_value_decode_inner( self->crds + i, alloc_mem, ctx );
    }
  } else
    self->crds = NULL;
}
void * fd_gossip_push_msg_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_push_msg_t * self = (fd_gossip_push_msg_t *)mem;
  fd_gossip_push_msg_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_push_msg_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_push_msg_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_push_msg_new(fd_gossip_push_msg_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_push_msg_t) );
  fd_pubkey_new( &self->pubkey );
}
void fd_gossip_push_msg_walk( void * w, fd_gossip_push_msg_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_push_msg", level++, 0 );
  fd_pubkey_walk( w, &self->pubkey, fun, "pubkey", level, 0 );
  if( self->crds_len ) {
    fun( w, NULL, "crds", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->crds_len; i++ )
      fd_crds_value_walk(w, self->crds + i, fun, "crds_value", level, 0 );
    fun( w, NULL, "crds", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_push_msg", level--, 0 );
}
ulong fd_gossip_push_msg_size( fd_gossip_push_msg_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->pubkey );
  do {
    size += sizeof(ulong);
    for( ulong i=0; i < self->crds_len; i++ )
      size += fd_crds_value_size( self->crds + i );
  } while(0);
  return size;
}

int fd_gossip_prune_msg_encode( fd_gossip_prune_msg_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_prune_data_encode( &self->data, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_gossip_prune_msg_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_gossip_prune_data_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_gossip_prune_msg_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_prune_msg_t);
  void const * start_data = ctx->data;
  int err = fd_gossip_prune_msg_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_prune_msg_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_prune_msg_t * self = (fd_gossip_prune_msg_t *)struct_mem;
  fd_pubkey_decode_inner( &self->pubkey, alloc_mem, ctx );
  fd_gossip_prune_data_decode_inner( &self->data, alloc_mem, ctx );
}
void * fd_gossip_prune_msg_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_prune_msg_t * self = (fd_gossip_prune_msg_t *)mem;
  fd_gossip_prune_msg_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_prune_msg_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_prune_msg_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_prune_msg_new(fd_gossip_prune_msg_t * self) {
  fd_memset( self, 0, sizeof(fd_gossip_prune_msg_t) );
  fd_pubkey_new( &self->pubkey );
  fd_gossip_prune_data_new( &self->data );
}
void fd_gossip_prune_msg_walk( void * w, fd_gossip_prune_msg_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_gossip_prune_msg", level++, 0 );
  fd_pubkey_walk( w, &self->pubkey, fun, "pubkey", level, 0 );
  fd_gossip_prune_data_walk( w, &self->data, fun, "data", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_gossip_prune_msg", level--, 0 );
}
ulong fd_gossip_prune_msg_size( fd_gossip_prune_msg_t const * self ) {
  ulong size = 0;
  size += fd_pubkey_size( &self->pubkey );
  size += fd_gossip_prune_data_size( &self->data );
  return size;
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
void fd_gossip_msg_inner_new( fd_gossip_msg_inner_t * self, uint discriminant );
int fd_gossip_msg_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_pull_req_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_gossip_pull_resp_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_gossip_push_msg_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 3: {
    err = fd_gossip_prune_msg_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 4: {
    err = fd_gossip_ping_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 5: {
    err = fd_gossip_ping_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_gossip_msg_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_gossip_msg_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_gossip_msg_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_gossip_msg_t);
  void const * start_data = ctx->data;
  int err =  fd_gossip_msg_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_gossip_msg_inner_decode_inner( fd_gossip_msg_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    fd_gossip_pull_req_decode_inner( &self->pull_req, alloc_mem, ctx );
    break;
  }
  case 1: {
    fd_gossip_pull_resp_decode_inner( &self->pull_resp, alloc_mem, ctx );
    break;
  }
  case 2: {
    fd_gossip_push_msg_decode_inner( &self->push_msg, alloc_mem, ctx );
    break;
  }
  case 3: {
    fd_gossip_prune_msg_decode_inner( &self->prune_msg, alloc_mem, ctx );
    break;
  }
  case 4: {
    fd_gossip_ping_decode_inner( &self->ping, alloc_mem, ctx );
    break;
  }
  case 5: {
    fd_gossip_ping_decode_inner( &self->pong, alloc_mem, ctx );
    break;
  }
  }
}
static void fd_gossip_msg_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_msg_t * self = (fd_gossip_msg_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_gossip_msg_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_gossip_msg_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_gossip_msg_t * self = (fd_gossip_msg_t *)mem;
  fd_gossip_msg_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_gossip_msg_t);
  void * * alloc_mem = &alloc_region;
  fd_gossip_msg_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_gossip_msg_inner_new( fd_gossip_msg_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    fd_gossip_pull_req_new( &self->pull_req );
    break;
  }
  case 1: {
    fd_gossip_pull_resp_new( &self->pull_resp );
    break;
  }
  case 2: {
    fd_gossip_push_msg_new( &self->push_msg );
    break;
  }
  case 3: {
    fd_gossip_prune_msg_new( &self->prune_msg );
    break;
  }
  case 4: {
    fd_gossip_ping_new( &self->ping );
    break;
  }
  case 5: {
    fd_gossip_ping_new( &self->pong );
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_gossip_msg_new_disc( fd_gossip_msg_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_gossip_msg_inner_new( &self->inner, self->discriminant );
}
void fd_gossip_msg_new( fd_gossip_msg_t * self ) {
  fd_memset( self, 0, sizeof(fd_gossip_msg_t) );
  fd_gossip_msg_new_disc( self, UINT_MAX );
}

void fd_gossip_msg_walk( void * w, fd_gossip_msg_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_gossip_msg", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "pull_req", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_pull_req_walk( w, &self->inner.pull_req, fun, "pull_req", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "pull_resp", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_pull_resp_walk( w, &self->inner.pull_resp, fun, "pull_resp", level, 0 );
    break;
  }
  case 2: {
    fun( w, self, "push_msg", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_push_msg_walk( w, &self->inner.push_msg, fun, "push_msg", level, 0 );
    break;
  }
  case 3: {
    fun( w, self, "prune_msg", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_prune_msg_walk( w, &self->inner.prune_msg, fun, "prune_msg", level, 0 );
    break;
  }
  case 4: {
    fun( w, self, "ping", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_ping_walk( w, &self->inner.ping, fun, "ping", level, 0 );
    break;
  }
  case 5: {
    fun( w, self, "pong", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_ping_walk( w, &self->inner.pong, fun, "pong", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_gossip_msg", level--, 0 );
}
ulong fd_gossip_msg_size( fd_gossip_msg_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_gossip_pull_req_size( &self->inner.pull_req );
    break;
  }
  case 1: {
    size += fd_gossip_pull_resp_size( &self->inner.pull_resp );
    break;
  }
  case 2: {
    size += fd_gossip_push_msg_size( &self->inner.push_msg );
    break;
  }
  case 3: {
    size += fd_gossip_prune_msg_size( &self->inner.prune_msg );
    break;
  }
  case 4: {
    size += fd_gossip_ping_size( &self->inner.ping );
    break;
  }
  case 5: {
    size += fd_gossip_ping_size( &self->inner.pong );
    break;
  }
  }
  return size;
}

int fd_gossip_msg_inner_encode( fd_gossip_msg_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_pull_req_encode( &self->pull_req, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 1: {
    err = fd_gossip_pull_resp_encode( &self->pull_resp, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 2: {
    err = fd_gossip_push_msg_encode( &self->push_msg, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 3: {
    err = fd_gossip_prune_msg_encode( &self->prune_msg, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 4: {
    err = fd_gossip_ping_encode( &self->ping, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 5: {
    err = fd_gossip_ping_encode( &self->pong, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_gossip_msg_encode( fd_gossip_msg_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_gossip_msg_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_addrlut_create_encode( fd_addrlut_create_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->recent_slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->bump_seed), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_addrlut_create_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 9UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 9UL );
  return 0;
}
static void fd_addrlut_create_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_addrlut_create_t * self = (fd_addrlut_create_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->recent_slot, ctx );
  fd_bincode_uint8_decode_unsafe( &self->bump_seed, ctx );
}
void * fd_addrlut_create_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_addrlut_create_t * self = (fd_addrlut_create_t *)mem;
  fd_addrlut_create_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_addrlut_create_t);
  void * * alloc_mem = &alloc_region;
  fd_addrlut_create_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_addrlut_create_walk( void * w, fd_addrlut_create_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_addrlut_create", level++, 0 );
  fun( w, &self->recent_slot, "recent_slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->bump_seed, "bump_seed", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_addrlut_create", level--, 0 );
}
int fd_addrlut_extend_encode( fd_addrlut_extend_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->new_addrs_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->new_addrs_len ) {
    for( ulong i=0; i < self->new_addrs_len; i++ ) {
      err = fd_pubkey_encode( self->new_addrs + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_addrlut_extend_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ulong new_addrs_len;
  err = fd_bincode_uint64_decode( &new_addrs_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( new_addrs_len ) {
    *total_sz += FD_PUBKEY_ALIGN + sizeof(fd_pubkey_t)*new_addrs_len;
    for( ulong i=0; i < new_addrs_len; i++ ) {
      err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_addrlut_extend_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_addrlut_extend_t);
  void const * start_data = ctx->data;
  int err = fd_addrlut_extend_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_addrlut_extend_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_addrlut_extend_t * self = (fd_addrlut_extend_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->new_addrs_len, ctx );
  if( self->new_addrs_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_PUBKEY_ALIGN );
    self->new_addrs = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_pubkey_t)*self->new_addrs_len;
    for( ulong i=0; i < self->new_addrs_len; i++ ) {
      fd_pubkey_new( self->new_addrs + i );
      fd_pubkey_decode_inner( self->new_addrs + i, alloc_mem, ctx );
    }
  } else
    self->new_addrs = NULL;
}
void * fd_addrlut_extend_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_addrlut_extend_t * self = (fd_addrlut_extend_t *)mem;
  fd_addrlut_extend_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_addrlut_extend_t);
  void * * alloc_mem = &alloc_region;
  fd_addrlut_extend_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_addrlut_extend_new(fd_addrlut_extend_t * self) {
  fd_memset( self, 0, sizeof(fd_addrlut_extend_t) );
}
void fd_addrlut_extend_walk( void * w, fd_addrlut_extend_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_addrlut_extend", level++, 0 );
  if( self->new_addrs_len ) {
    fun( w, NULL, "new_addrs", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->new_addrs_len; i++ )
      fd_pubkey_walk(w, self->new_addrs + i, fun, "pubkey", level, 0 );
    fun( w, NULL, "new_addrs", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_addrlut_extend", level--, 0 );
}
ulong fd_addrlut_extend_size( fd_addrlut_extend_t const * self ) {
  ulong size = 0;
  do {
    size += sizeof(ulong);
    for( ulong i=0; i < self->new_addrs_len; i++ )
      size += fd_pubkey_size( self->new_addrs + i );
  } while(0);
  return size;
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
void fd_addrlut_instruction_inner_new( fd_addrlut_instruction_inner_t * self, uint discriminant );
int fd_addrlut_instruction_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_addrlut_create_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    err = fd_addrlut_extend_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
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
static int fd_addrlut_instruction_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_addrlut_instruction_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_addrlut_instruction_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_addrlut_instruction_t);
  void const * start_data = ctx->data;
  int err =  fd_addrlut_instruction_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_addrlut_instruction_inner_decode_inner( fd_addrlut_instruction_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    fd_addrlut_create_decode_inner( &self->create_lut, alloc_mem, ctx );
    break;
  }
  case 1: {
    break;
  }
  case 2: {
    fd_addrlut_extend_decode_inner( &self->extend_lut, alloc_mem, ctx );
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
static void fd_addrlut_instruction_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_addrlut_instruction_t * self = (fd_addrlut_instruction_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_addrlut_instruction_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_addrlut_instruction_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_addrlut_instruction_t * self = (fd_addrlut_instruction_t *)mem;
  fd_addrlut_instruction_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_addrlut_instruction_t);
  void * * alloc_mem = &alloc_region;
  fd_addrlut_instruction_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_addrlut_instruction_inner_new( fd_addrlut_instruction_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    fd_addrlut_create_new( &self->create_lut );
    break;
  }
  case 1: {
    break;
  }
  case 2: {
    fd_addrlut_extend_new( &self->extend_lut );
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
void fd_addrlut_instruction_new_disc( fd_addrlut_instruction_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_addrlut_instruction_inner_new( &self->inner, self->discriminant );
}
void fd_addrlut_instruction_new( fd_addrlut_instruction_t * self ) {
  fd_memset( self, 0, sizeof(fd_addrlut_instruction_t) );
  fd_addrlut_instruction_new_disc( self, UINT_MAX );
}

void fd_addrlut_instruction_walk( void * w, fd_addrlut_instruction_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_addrlut_instruction", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "create_lut", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_addrlut_create_walk( w, &self->inner.create_lut, fun, "create_lut", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "freeze_lut", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 2: {
    fun( w, self, "extend_lut", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_addrlut_extend_walk( w, &self->inner.extend_lut, fun, "extend_lut", level, 0 );
    break;
  }
  case 3: {
    fun( w, self, "deactivate_lut", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 4: {
    fun( w, self, "close_lut", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_addrlut_instruction", level--, 0 );
}
ulong fd_addrlut_instruction_size( fd_addrlut_instruction_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_addrlut_create_size( &self->inner.create_lut );
    break;
  }
  case 2: {
    size += fd_addrlut_extend_size( &self->inner.extend_lut );
    break;
  }
  }
  return size;
}

int fd_addrlut_instruction_inner_encode( fd_addrlut_instruction_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_addrlut_create_encode( &self->create_lut, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 2: {
    err = fd_addrlut_extend_encode( &self->extend_lut, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_addrlut_instruction_encode( fd_addrlut_instruction_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_addrlut_instruction_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_repair_request_header_encode( fd_repair_request_header_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_signature_encode( &self->signature, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->sender, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_pubkey_encode( &self->recipient, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->timestamp, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint32_encode( self->nonce, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_repair_request_header_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 140UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 140UL );
  return 0;
}
static void fd_repair_request_header_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_repair_request_header_t * self = (fd_repair_request_header_t *)struct_mem;
  fd_signature_decode_inner( &self->signature, alloc_mem, ctx );
  fd_pubkey_decode_inner( &self->sender, alloc_mem, ctx );
  fd_pubkey_decode_inner( &self->recipient, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->timestamp, ctx );
  fd_bincode_uint32_decode_unsafe( &self->nonce, ctx );
}
void * fd_repair_request_header_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_repair_request_header_t * self = (fd_repair_request_header_t *)mem;
  fd_repair_request_header_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_repair_request_header_t);
  void * * alloc_mem = &alloc_region;
  fd_repair_request_header_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_repair_request_header_walk( void * w, fd_repair_request_header_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_repair_request_header", level++, 0 );
  fd_signature_walk( w, &self->signature, fun, "signature", level, 0 );
  fd_pubkey_walk( w, &self->sender, fun, "sender", level, 0 );
  fd_pubkey_walk( w, &self->recipient, fun, "recipient", level, 0 );
  fun( w, &self->timestamp, "timestamp", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->nonce, "nonce", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_repair_request_header", level--, 0 );
}
int fd_repair_window_index_encode( fd_repair_window_index_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_repair_request_header_encode( &self->header, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->shred_index, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_repair_window_index_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 156UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 156UL );
  return 0;
}
static void fd_repair_window_index_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_repair_window_index_t * self = (fd_repair_window_index_t *)struct_mem;
  fd_repair_request_header_decode_inner( &self->header, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->slot, ctx );
  fd_bincode_uint64_decode_unsafe( &self->shred_index, ctx );
}
void * fd_repair_window_index_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_repair_window_index_t * self = (fd_repair_window_index_t *)mem;
  fd_repair_window_index_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_repair_window_index_t);
  void * * alloc_mem = &alloc_region;
  fd_repair_window_index_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_repair_window_index_walk( void * w, fd_repair_window_index_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_repair_window_index", level++, 0 );
  fd_repair_request_header_walk( w, &self->header, fun, "header", level, 0 );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->shred_index, "shred_index", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_repair_window_index", level--, 0 );
}
int fd_repair_highest_window_index_encode( fd_repair_highest_window_index_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_repair_request_header_encode( &self->header, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->shred_index, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_repair_highest_window_index_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 156UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 156UL );
  return 0;
}
static void fd_repair_highest_window_index_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_repair_highest_window_index_t * self = (fd_repair_highest_window_index_t *)struct_mem;
  fd_repair_request_header_decode_inner( &self->header, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->slot, ctx );
  fd_bincode_uint64_decode_unsafe( &self->shred_index, ctx );
}
void * fd_repair_highest_window_index_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_repair_highest_window_index_t * self = (fd_repair_highest_window_index_t *)mem;
  fd_repair_highest_window_index_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_repair_highest_window_index_t);
  void * * alloc_mem = &alloc_region;
  fd_repair_highest_window_index_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_repair_highest_window_index_walk( void * w, fd_repair_highest_window_index_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_repair_highest_window_index", level++, 0 );
  fd_repair_request_header_walk( w, &self->header, fun, "header", level, 0 );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->shred_index, "shred_index", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_repair_highest_window_index", level--, 0 );
}
int fd_repair_orphan_encode( fd_repair_orphan_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_repair_request_header_encode( &self->header, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_repair_orphan_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 148UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 148UL );
  return 0;
}
static void fd_repair_orphan_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_repair_orphan_t * self = (fd_repair_orphan_t *)struct_mem;
  fd_repair_request_header_decode_inner( &self->header, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->slot, ctx );
}
void * fd_repair_orphan_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_repair_orphan_t * self = (fd_repair_orphan_t *)mem;
  fd_repair_orphan_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_repair_orphan_t);
  void * * alloc_mem = &alloc_region;
  fd_repair_orphan_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_repair_orphan_walk( void * w, fd_repair_orphan_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_repair_orphan", level++, 0 );
  fd_repair_request_header_walk( w, &self->header, fun, "header", level, 0 );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_repair_orphan", level--, 0 );
}
int fd_repair_ancestor_hashes_encode( fd_repair_ancestor_hashes_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_repair_request_header_encode( &self->header, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_repair_ancestor_hashes_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 148UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 148UL );
  return 0;
}
static void fd_repair_ancestor_hashes_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_repair_ancestor_hashes_t * self = (fd_repair_ancestor_hashes_t *)struct_mem;
  fd_repair_request_header_decode_inner( &self->header, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->slot, ctx );
}
void * fd_repair_ancestor_hashes_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_repair_ancestor_hashes_t * self = (fd_repair_ancestor_hashes_t *)mem;
  fd_repair_ancestor_hashes_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_repair_ancestor_hashes_t);
  void * * alloc_mem = &alloc_region;
  fd_repair_ancestor_hashes_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_repair_ancestor_hashes_walk( void * w, fd_repair_ancestor_hashes_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_repair_ancestor_hashes", level++, 0 );
  fd_repair_request_header_walk( w, &self->header, fun, "header", level, 0 );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_repair_ancestor_hashes", level--, 0 );
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
void fd_repair_protocol_inner_new( fd_repair_protocol_inner_t * self, uint discriminant );
int fd_repair_protocol_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
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
    err = fd_gossip_ping_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 8: {
    err = fd_repair_window_index_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 9: {
    err = fd_repair_highest_window_index_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 10: {
    err = fd_repair_orphan_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 11: {
    err = fd_repair_ancestor_hashes_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_repair_protocol_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_repair_protocol_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_repair_protocol_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_repair_protocol_t);
  void const * start_data = ctx->data;
  int err =  fd_repair_protocol_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_repair_protocol_inner_decode_inner( fd_repair_protocol_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
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
    fd_gossip_ping_decode_inner( &self->pong, alloc_mem, ctx );
    break;
  }
  case 8: {
    fd_repair_window_index_decode_inner( &self->window_index, alloc_mem, ctx );
    break;
  }
  case 9: {
    fd_repair_highest_window_index_decode_inner( &self->highest_window_index, alloc_mem, ctx );
    break;
  }
  case 10: {
    fd_repair_orphan_decode_inner( &self->orphan, alloc_mem, ctx );
    break;
  }
  case 11: {
    fd_repair_ancestor_hashes_decode_inner( &self->ancestor_hashes, alloc_mem, ctx );
    break;
  }
  }
}
static void fd_repair_protocol_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_repair_protocol_t * self = (fd_repair_protocol_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_repair_protocol_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_repair_protocol_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_repair_protocol_t * self = (fd_repair_protocol_t *)mem;
  fd_repair_protocol_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_repair_protocol_t);
  void * * alloc_mem = &alloc_region;
  fd_repair_protocol_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_repair_protocol_inner_new( fd_repair_protocol_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
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
    fd_gossip_ping_new( &self->pong );
    break;
  }
  case 8: {
    fd_repair_window_index_new( &self->window_index );
    break;
  }
  case 9: {
    fd_repair_highest_window_index_new( &self->highest_window_index );
    break;
  }
  case 10: {
    fd_repair_orphan_new( &self->orphan );
    break;
  }
  case 11: {
    fd_repair_ancestor_hashes_new( &self->ancestor_hashes );
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_repair_protocol_new_disc( fd_repair_protocol_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_repair_protocol_inner_new( &self->inner, self->discriminant );
}
void fd_repair_protocol_new( fd_repair_protocol_t * self ) {
  fd_memset( self, 0, sizeof(fd_repair_protocol_t) );
  fd_repair_protocol_new_disc( self, UINT_MAX );
}

void fd_repair_protocol_walk( void * w, fd_repair_protocol_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_repair_protocol", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "LegacyWindowIndex", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "LegacyHighestWindowIndex", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 2: {
    fun( w, self, "LegacyOrphan", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 3: {
    fun( w, self, "LegacyWindowIndexWithNonce", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 4: {
    fun( w, self, "LegacyHighestWindowIndexWithNonce", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 5: {
    fun( w, self, "LegacyOrphanWithNonce", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 6: {
    fun( w, self, "LegacyAncestorHashes", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 7: {
    fun( w, self, "pong", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_ping_walk( w, &self->inner.pong, fun, "pong", level, 0 );
    break;
  }
  case 8: {
    fun( w, self, "window_index", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_repair_window_index_walk( w, &self->inner.window_index, fun, "window_index", level, 0 );
    break;
  }
  case 9: {
    fun( w, self, "highest_window_index", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_repair_highest_window_index_walk( w, &self->inner.highest_window_index, fun, "highest_window_index", level, 0 );
    break;
  }
  case 10: {
    fun( w, self, "orphan", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_repair_orphan_walk( w, &self->inner.orphan, fun, "orphan", level, 0 );
    break;
  }
  case 11: {
    fun( w, self, "ancestor_hashes", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_repair_ancestor_hashes_walk( w, &self->inner.ancestor_hashes, fun, "ancestor_hashes", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_repair_protocol", level--, 0 );
}
ulong fd_repair_protocol_size( fd_repair_protocol_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 7: {
    size += fd_gossip_ping_size( &self->inner.pong );
    break;
  }
  case 8: {
    size += fd_repair_window_index_size( &self->inner.window_index );
    break;
  }
  case 9: {
    size += fd_repair_highest_window_index_size( &self->inner.highest_window_index );
    break;
  }
  case 10: {
    size += fd_repair_orphan_size( &self->inner.orphan );
    break;
  }
  case 11: {
    size += fd_repair_ancestor_hashes_size( &self->inner.ancestor_hashes );
    break;
  }
  }
  return size;
}

int fd_repair_protocol_inner_encode( fd_repair_protocol_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 7: {
    err = fd_gossip_ping_encode( &self->pong, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 8: {
    err = fd_repair_window_index_encode( &self->window_index, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 9: {
    err = fd_repair_highest_window_index_encode( &self->highest_window_index, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 10: {
    err = fd_repair_orphan_encode( &self->orphan, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 11: {
    err = fd_repair_ancestor_hashes_encode( &self->ancestor_hashes, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_repair_protocol_encode( fd_repair_protocol_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_repair_protocol_inner_encode( &self->inner, self->discriminant, ctx );
}

FD_FN_PURE uchar fd_repair_response_is_ping(fd_repair_response_t const * self) {
  return self->discriminant == 0;
}
void fd_repair_response_inner_new( fd_repair_response_inner_t * self, uint discriminant );
int fd_repair_response_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_ping_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_repair_response_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_repair_response_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_repair_response_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_repair_response_t);
  void const * start_data = ctx->data;
  int err =  fd_repair_response_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_repair_response_inner_decode_inner( fd_repair_response_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    fd_gossip_ping_decode_inner( &self->ping, alloc_mem, ctx );
    break;
  }
  }
}
static void fd_repair_response_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_repair_response_t * self = (fd_repair_response_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_repair_response_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_repair_response_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_repair_response_t * self = (fd_repair_response_t *)mem;
  fd_repair_response_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_repair_response_t);
  void * * alloc_mem = &alloc_region;
  fd_repair_response_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_repair_response_inner_new( fd_repair_response_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    fd_gossip_ping_new( &self->ping );
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_repair_response_new_disc( fd_repair_response_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_repair_response_inner_new( &self->inner, self->discriminant );
}
void fd_repair_response_new( fd_repair_response_t * self ) {
  fd_memset( self, 0, sizeof(fd_repair_response_t) );
  fd_repair_response_new_disc( self, UINT_MAX );
}

void fd_repair_response_walk( void * w, fd_repair_response_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_repair_response", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "ping", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_gossip_ping_walk( w, &self->inner.ping, fun, "ping", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_repair_response", level--, 0 );
}
ulong fd_repair_response_size( fd_repair_response_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 0: {
    size += fd_gossip_ping_size( &self->inner.ping );
    break;
  }
  }
  return size;
}

int fd_repair_response_inner_encode( fd_repair_response_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 0: {
    err = fd_gossip_ping_encode( &self->ping, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_repair_response_encode( fd_repair_response_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_repair_response_inner_encode( &self->inner, self->discriminant, ctx );
}

FD_FN_PURE uchar fd_instr_error_enum_is_generic_error(fd_instr_error_enum_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_instr_error_enum_is_invalid_argument(fd_instr_error_enum_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_instr_error_enum_is_invalid_instruction_data(fd_instr_error_enum_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_instr_error_enum_is_invalid_account_data(fd_instr_error_enum_t const * self) {
  return self->discriminant == 3;
}
FD_FN_PURE uchar fd_instr_error_enum_is_account_data_too_small(fd_instr_error_enum_t const * self) {
  return self->discriminant == 4;
}
FD_FN_PURE uchar fd_instr_error_enum_is_insufficient_funds(fd_instr_error_enum_t const * self) {
  return self->discriminant == 5;
}
FD_FN_PURE uchar fd_instr_error_enum_is_incorrect_program_id(fd_instr_error_enum_t const * self) {
  return self->discriminant == 6;
}
FD_FN_PURE uchar fd_instr_error_enum_is_missing_required_signature(fd_instr_error_enum_t const * self) {
  return self->discriminant == 7;
}
FD_FN_PURE uchar fd_instr_error_enum_is_account_already_initialized(fd_instr_error_enum_t const * self) {
  return self->discriminant == 8;
}
FD_FN_PURE uchar fd_instr_error_enum_is_uninitialized_account(fd_instr_error_enum_t const * self) {
  return self->discriminant == 9;
}
FD_FN_PURE uchar fd_instr_error_enum_is_unbalanced_instruction(fd_instr_error_enum_t const * self) {
  return self->discriminant == 10;
}
FD_FN_PURE uchar fd_instr_error_enum_is_modified_program_id(fd_instr_error_enum_t const * self) {
  return self->discriminant == 11;
}
FD_FN_PURE uchar fd_instr_error_enum_is_external_account_lamport_spend(fd_instr_error_enum_t const * self) {
  return self->discriminant == 12;
}
FD_FN_PURE uchar fd_instr_error_enum_is_external_account_data_modified(fd_instr_error_enum_t const * self) {
  return self->discriminant == 13;
}
FD_FN_PURE uchar fd_instr_error_enum_is_readonly_lamport_change(fd_instr_error_enum_t const * self) {
  return self->discriminant == 14;
}
FD_FN_PURE uchar fd_instr_error_enum_is_readonly_data_modified(fd_instr_error_enum_t const * self) {
  return self->discriminant == 15;
}
FD_FN_PURE uchar fd_instr_error_enum_is_duplicate_account_index(fd_instr_error_enum_t const * self) {
  return self->discriminant == 16;
}
FD_FN_PURE uchar fd_instr_error_enum_is_executable_modified(fd_instr_error_enum_t const * self) {
  return self->discriminant == 17;
}
FD_FN_PURE uchar fd_instr_error_enum_is_rent_epoch_modified(fd_instr_error_enum_t const * self) {
  return self->discriminant == 18;
}
FD_FN_PURE uchar fd_instr_error_enum_is_not_enough_account_keys(fd_instr_error_enum_t const * self) {
  return self->discriminant == 19;
}
FD_FN_PURE uchar fd_instr_error_enum_is_account_data_size_changed(fd_instr_error_enum_t const * self) {
  return self->discriminant == 20;
}
FD_FN_PURE uchar fd_instr_error_enum_is_account_not_executable(fd_instr_error_enum_t const * self) {
  return self->discriminant == 21;
}
FD_FN_PURE uchar fd_instr_error_enum_is_account_borrow_failed(fd_instr_error_enum_t const * self) {
  return self->discriminant == 22;
}
FD_FN_PURE uchar fd_instr_error_enum_is_account_borrow_outstanding(fd_instr_error_enum_t const * self) {
  return self->discriminant == 23;
}
FD_FN_PURE uchar fd_instr_error_enum_is_duplicate_account_out_of_sync(fd_instr_error_enum_t const * self) {
  return self->discriminant == 24;
}
FD_FN_PURE uchar fd_instr_error_enum_is_custom(fd_instr_error_enum_t const * self) {
  return self->discriminant == 25;
}
FD_FN_PURE uchar fd_instr_error_enum_is_invalid_error(fd_instr_error_enum_t const * self) {
  return self->discriminant == 26;
}
FD_FN_PURE uchar fd_instr_error_enum_is_executable_data_modified(fd_instr_error_enum_t const * self) {
  return self->discriminant == 27;
}
FD_FN_PURE uchar fd_instr_error_enum_is_executable_lamport_change(fd_instr_error_enum_t const * self) {
  return self->discriminant == 28;
}
FD_FN_PURE uchar fd_instr_error_enum_is_executable_account_not_rent_exempt(fd_instr_error_enum_t const * self) {
  return self->discriminant == 29;
}
FD_FN_PURE uchar fd_instr_error_enum_is_unsupported_program_id(fd_instr_error_enum_t const * self) {
  return self->discriminant == 30;
}
FD_FN_PURE uchar fd_instr_error_enum_is_call_depth(fd_instr_error_enum_t const * self) {
  return self->discriminant == 31;
}
FD_FN_PURE uchar fd_instr_error_enum_is_missing_account(fd_instr_error_enum_t const * self) {
  return self->discriminant == 32;
}
FD_FN_PURE uchar fd_instr_error_enum_is_reentrancy_not_allowed(fd_instr_error_enum_t const * self) {
  return self->discriminant == 33;
}
FD_FN_PURE uchar fd_instr_error_enum_is_max_seed_length_exceeded(fd_instr_error_enum_t const * self) {
  return self->discriminant == 34;
}
FD_FN_PURE uchar fd_instr_error_enum_is_invalid_seeds(fd_instr_error_enum_t const * self) {
  return self->discriminant == 35;
}
FD_FN_PURE uchar fd_instr_error_enum_is_invalid_realloc(fd_instr_error_enum_t const * self) {
  return self->discriminant == 36;
}
FD_FN_PURE uchar fd_instr_error_enum_is_computational_budget_exceeded(fd_instr_error_enum_t const * self) {
  return self->discriminant == 37;
}
FD_FN_PURE uchar fd_instr_error_enum_is_privilege_escalation(fd_instr_error_enum_t const * self) {
  return self->discriminant == 38;
}
FD_FN_PURE uchar fd_instr_error_enum_is_program_environment_setup_failure(fd_instr_error_enum_t const * self) {
  return self->discriminant == 39;
}
FD_FN_PURE uchar fd_instr_error_enum_is_program_failed_to_complete(fd_instr_error_enum_t const * self) {
  return self->discriminant == 40;
}
FD_FN_PURE uchar fd_instr_error_enum_is_program_failed_to_compile(fd_instr_error_enum_t const * self) {
  return self->discriminant == 41;
}
FD_FN_PURE uchar fd_instr_error_enum_is_immutable(fd_instr_error_enum_t const * self) {
  return self->discriminant == 42;
}
FD_FN_PURE uchar fd_instr_error_enum_is_incorrect_authority(fd_instr_error_enum_t const * self) {
  return self->discriminant == 43;
}
FD_FN_PURE uchar fd_instr_error_enum_is_borsh_io_error(fd_instr_error_enum_t const * self) {
  return self->discriminant == 44;
}
FD_FN_PURE uchar fd_instr_error_enum_is_account_not_rent_exempt(fd_instr_error_enum_t const * self) {
  return self->discriminant == 45;
}
FD_FN_PURE uchar fd_instr_error_enum_is_invalid_account_owner(fd_instr_error_enum_t const * self) {
  return self->discriminant == 46;
}
FD_FN_PURE uchar fd_instr_error_enum_is_arithmetic_overflow(fd_instr_error_enum_t const * self) {
  return self->discriminant == 47;
}
FD_FN_PURE uchar fd_instr_error_enum_is_unsupported_sysvar(fd_instr_error_enum_t const * self) {
  return self->discriminant == 48;
}
FD_FN_PURE uchar fd_instr_error_enum_is_illegal_owner(fd_instr_error_enum_t const * self) {
  return self->discriminant == 49;
}
FD_FN_PURE uchar fd_instr_error_enum_is_max_accounts_data_allocations_exceeded(fd_instr_error_enum_t const * self) {
  return self->discriminant == 50;
}
FD_FN_PURE uchar fd_instr_error_enum_is_max_accounts_exceeded(fd_instr_error_enum_t const * self) {
  return self->discriminant == 51;
}
FD_FN_PURE uchar fd_instr_error_enum_is_max_instruction_trace_length_exceeded(fd_instr_error_enum_t const * self) {
  return self->discriminant == 52;
}
FD_FN_PURE uchar fd_instr_error_enum_is_builtin_programs_must_consume_compute_units(fd_instr_error_enum_t const * self) {
  return self->discriminant == 53;
}
void fd_instr_error_enum_inner_new( fd_instr_error_enum_inner_t * self, uint discriminant );
int fd_instr_error_enum_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
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
  case 9: {
    return FD_BINCODE_SUCCESS;
  }
  case 10: {
    return FD_BINCODE_SUCCESS;
  }
  case 11: {
    return FD_BINCODE_SUCCESS;
  }
  case 12: {
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
  case 16: {
    return FD_BINCODE_SUCCESS;
  }
  case 17: {
    return FD_BINCODE_SUCCESS;
  }
  case 18: {
    return FD_BINCODE_SUCCESS;
  }
  case 19: {
    return FD_BINCODE_SUCCESS;
  }
  case 20: {
    return FD_BINCODE_SUCCESS;
  }
  case 21: {
    return FD_BINCODE_SUCCESS;
  }
  case 22: {
    return FD_BINCODE_SUCCESS;
  }
  case 23: {
    return FD_BINCODE_SUCCESS;
  }
  case 24: {
    return FD_BINCODE_SUCCESS;
  }
  case 25: {
    err = fd_bincode_uint32_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 26: {
    return FD_BINCODE_SUCCESS;
  }
  case 27: {
    return FD_BINCODE_SUCCESS;
  }
  case 28: {
    return FD_BINCODE_SUCCESS;
  }
  case 29: {
    return FD_BINCODE_SUCCESS;
  }
  case 30: {
    return FD_BINCODE_SUCCESS;
  }
  case 31: {
    return FD_BINCODE_SUCCESS;
  }
  case 32: {
    return FD_BINCODE_SUCCESS;
  }
  case 33: {
    return FD_BINCODE_SUCCESS;
  }
  case 34: {
    return FD_BINCODE_SUCCESS;
  }
  case 35: {
    return FD_BINCODE_SUCCESS;
  }
  case 36: {
    return FD_BINCODE_SUCCESS;
  }
  case 37: {
    return FD_BINCODE_SUCCESS;
  }
  case 38: {
    return FD_BINCODE_SUCCESS;
  }
  case 39: {
    return FD_BINCODE_SUCCESS;
  }
  case 40: {
    return FD_BINCODE_SUCCESS;
  }
  case 41: {
    return FD_BINCODE_SUCCESS;
  }
  case 42: {
    return FD_BINCODE_SUCCESS;
  }
  case 43: {
    return FD_BINCODE_SUCCESS;
  }
  case 44: {
    ulong slen;
    err = fd_bincode_uint64_decode( &slen, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    err = fd_bincode_bytes_decode_footprint( slen, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    *total_sz += slen + 1; // Need an extra byte for null termination
    return FD_BINCODE_SUCCESS;
  }
  case 45: {
    return FD_BINCODE_SUCCESS;
  }
  case 46: {
    return FD_BINCODE_SUCCESS;
  }
  case 47: {
    return FD_BINCODE_SUCCESS;
  }
  case 48: {
    return FD_BINCODE_SUCCESS;
  }
  case 49: {
    return FD_BINCODE_SUCCESS;
  }
  case 50: {
    return FD_BINCODE_SUCCESS;
  }
  case 51: {
    return FD_BINCODE_SUCCESS;
  }
  case 52: {
    return FD_BINCODE_SUCCESS;
  }
  case 53: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_instr_error_enum_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_instr_error_enum_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_instr_error_enum_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_instr_error_enum_t);
  void const * start_data = ctx->data;
  int err =  fd_instr_error_enum_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_instr_error_enum_inner_decode_inner( fd_instr_error_enum_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
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
  case 9: {
    break;
  }
  case 10: {
    break;
  }
  case 11: {
    break;
  }
  case 12: {
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
  case 16: {
    break;
  }
  case 17: {
    break;
  }
  case 18: {
    break;
  }
  case 19: {
    break;
  }
  case 20: {
    break;
  }
  case 21: {
    break;
  }
  case 22: {
    break;
  }
  case 23: {
    break;
  }
  case 24: {
    break;
  }
  case 25: {
    fd_bincode_uint32_decode_unsafe( &self->custom, ctx );
    break;
  }
  case 26: {
    break;
  }
  case 27: {
    break;
  }
  case 28: {
    break;
  }
  case 29: {
    break;
  }
  case 30: {
    break;
  }
  case 31: {
    break;
  }
  case 32: {
    break;
  }
  case 33: {
    break;
  }
  case 34: {
    break;
  }
  case 35: {
    break;
  }
  case 36: {
    break;
  }
  case 37: {
    break;
  }
  case 38: {
    break;
  }
  case 39: {
    break;
  }
  case 40: {
    break;
  }
  case 41: {
    break;
  }
  case 42: {
    break;
  }
  case 43: {
    break;
  }
  case 44: {
    ulong slen;
    fd_bincode_uint64_decode_unsafe( &slen, ctx );
    self->borsh_io_error = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( (uchar *)self->borsh_io_error, slen, ctx );
    self->borsh_io_error[slen] = '\0';
    *alloc_mem = (uchar *)(*alloc_mem) + (slen + 1); // extra byte for null termination
    break;
  }
  case 45: {
    break;
  }
  case 46: {
    break;
  }
  case 47: {
    break;
  }
  case 48: {
    break;
  }
  case 49: {
    break;
  }
  case 50: {
    break;
  }
  case 51: {
    break;
  }
  case 52: {
    break;
  }
  case 53: {
    break;
  }
  }
}
static void fd_instr_error_enum_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_instr_error_enum_t * self = (fd_instr_error_enum_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_instr_error_enum_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_instr_error_enum_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_instr_error_enum_t * self = (fd_instr_error_enum_t *)mem;
  fd_instr_error_enum_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_instr_error_enum_t);
  void * * alloc_mem = &alloc_region;
  fd_instr_error_enum_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_instr_error_enum_inner_new( fd_instr_error_enum_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
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
  case 9: {
    break;
  }
  case 10: {
    break;
  }
  case 11: {
    break;
  }
  case 12: {
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
  case 16: {
    break;
  }
  case 17: {
    break;
  }
  case 18: {
    break;
  }
  case 19: {
    break;
  }
  case 20: {
    break;
  }
  case 21: {
    break;
  }
  case 22: {
    break;
  }
  case 23: {
    break;
  }
  case 24: {
    break;
  }
  case 25: {
    break;
  }
  case 26: {
    break;
  }
  case 27: {
    break;
  }
  case 28: {
    break;
  }
  case 29: {
    break;
  }
  case 30: {
    break;
  }
  case 31: {
    break;
  }
  case 32: {
    break;
  }
  case 33: {
    break;
  }
  case 34: {
    break;
  }
  case 35: {
    break;
  }
  case 36: {
    break;
  }
  case 37: {
    break;
  }
  case 38: {
    break;
  }
  case 39: {
    break;
  }
  case 40: {
    break;
  }
  case 41: {
    break;
  }
  case 42: {
    break;
  }
  case 43: {
    break;
  }
  case 44: {
    break;
  }
  case 45: {
    break;
  }
  case 46: {
    break;
  }
  case 47: {
    break;
  }
  case 48: {
    break;
  }
  case 49: {
    break;
  }
  case 50: {
    break;
  }
  case 51: {
    break;
  }
  case 52: {
    break;
  }
  case 53: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_instr_error_enum_new_disc( fd_instr_error_enum_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_instr_error_enum_inner_new( &self->inner, self->discriminant );
}
void fd_instr_error_enum_new( fd_instr_error_enum_t * self ) {
  fd_memset( self, 0, sizeof(fd_instr_error_enum_t) );
  fd_instr_error_enum_new_disc( self, UINT_MAX );
}

void fd_instr_error_enum_walk( void * w, fd_instr_error_enum_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_instr_error_enum", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "generic_error", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "invalid_argument", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 2: {
    fun( w, self, "invalid_instruction_data", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 3: {
    fun( w, self, "invalid_account_data", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 4: {
    fun( w, self, "account_data_too_small", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 5: {
    fun( w, self, "insufficient_funds", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 6: {
    fun( w, self, "incorrect_program_id", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 7: {
    fun( w, self, "missing_required_signature", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 8: {
    fun( w, self, "account_already_initialized", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 9: {
    fun( w, self, "uninitialized_account", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 10: {
    fun( w, self, "unbalanced_instruction", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 11: {
    fun( w, self, "modified_program_id", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 12: {
    fun( w, self, "external_account_lamport_spend", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 13: {
    fun( w, self, "external_account_data_modified", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 14: {
    fun( w, self, "readonly_lamport_change", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 15: {
    fun( w, self, "readonly_data_modified", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 16: {
    fun( w, self, "duplicate_account_index", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 17: {
    fun( w, self, "executable_modified", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 18: {
    fun( w, self, "rent_epoch_modified", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 19: {
    fun( w, self, "not_enough_account_keys", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 20: {
    fun( w, self, "account_data_size_changed", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 21: {
    fun( w, self, "account_not_executable", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 22: {
    fun( w, self, "account_borrow_failed", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 23: {
    fun( w, self, "account_borrow_outstanding", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 24: {
    fun( w, self, "duplicate_account_out_of_sync", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 25: {
    fun( w, self, "custom", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
  fun( w, &self->inner.custom, "custom", FD_FLAMENCO_TYPE_UINT, "uint", level, 0  );
    break;
  }
  case 26: {
    fun( w, self, "invalid_error", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 27: {
    fun( w, self, "executable_data_modified", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 28: {
    fun( w, self, "executable_lamport_change", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 29: {
    fun( w, self, "executable_account_not_rent_exempt", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 30: {
    fun( w, self, "unsupported_program_id", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 31: {
    fun( w, self, "call_depth", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 32: {
    fun( w, self, "missing_account", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 33: {
    fun( w, self, "reentrancy_not_allowed", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 34: {
    fun( w, self, "max_seed_length_exceeded", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 35: {
    fun( w, self, "invalid_seeds", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 36: {
    fun( w, self, "invalid_realloc", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 37: {
    fun( w, self, "computational_budget_exceeded", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 38: {
    fun( w, self, "privilege_escalation", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 39: {
    fun( w, self, "program_environment_setup_failure", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 40: {
    fun( w, self, "program_failed_to_complete", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 41: {
    fun( w, self, "program_failed_to_compile", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 42: {
    fun( w, self, "immutable", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 43: {
    fun( w, self, "incorrect_authority", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 44: {
    fun( w, self, "borsh_io_error", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
  fun( w, self->inner.borsh_io_error, "borsh_io_error", FD_FLAMENCO_TYPE_CSTR, "char*", level, 0  );
    break;
  }
  case 45: {
    fun( w, self, "account_not_rent_exempt", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 46: {
    fun( w, self, "invalid_account_owner", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 47: {
    fun( w, self, "arithmetic_overflow", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 48: {
    fun( w, self, "unsupported_sysvar", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 49: {
    fun( w, self, "illegal_owner", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 50: {
    fun( w, self, "max_accounts_data_allocations_exceeded", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 51: {
    fun( w, self, "max_accounts_exceeded", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 52: {
    fun( w, self, "max_instruction_trace_length_exceeded", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 53: {
    fun( w, self, "builtin_programs_must_consume_compute_units", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_instr_error_enum", level--, 0 );
}
ulong fd_instr_error_enum_size( fd_instr_error_enum_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 25: {
    size += sizeof(uint);
    break;
  }
  case 44: {
    size += sizeof(ulong) + strlen(self->inner.borsh_io_error);
    break;
  }
  }
  return size;
}

int fd_instr_error_enum_inner_encode( fd_instr_error_enum_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 25: {
    err = fd_bincode_uint32_encode( self->custom, ctx );
  if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 44: {
    ulong slen = strlen( (char *) self->borsh_io_error );
    err = fd_bincode_uint64_encode( slen, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    err = fd_bincode_bytes_encode( (uchar *) self->borsh_io_error, slen, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_instr_error_enum_encode( fd_instr_error_enum_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_instr_error_enum_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_txn_instr_error_encode( fd_txn_instr_error_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint8_encode( (uchar)(self->instr_idx), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_instr_error_enum_encode( &self->error, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_txn_instr_error_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_instr_error_enum_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_txn_instr_error_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_txn_instr_error_t);
  void const * start_data = ctx->data;
  int err = fd_txn_instr_error_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_txn_instr_error_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_txn_instr_error_t * self = (fd_txn_instr_error_t *)struct_mem;
  fd_bincode_uint8_decode_unsafe( &self->instr_idx, ctx );
  fd_instr_error_enum_decode_inner( &self->error, alloc_mem, ctx );
}
void * fd_txn_instr_error_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_txn_instr_error_t * self = (fd_txn_instr_error_t *)mem;
  fd_txn_instr_error_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_txn_instr_error_t);
  void * * alloc_mem = &alloc_region;
  fd_txn_instr_error_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_txn_instr_error_new(fd_txn_instr_error_t * self) {
  fd_memset( self, 0, sizeof(fd_txn_instr_error_t) );
  fd_instr_error_enum_new( &self->error );
}
void fd_txn_instr_error_walk( void * w, fd_txn_instr_error_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_txn_instr_error", level++, 0 );
  fun( w, &self->instr_idx, "instr_idx", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fd_instr_error_enum_walk( w, &self->error, fun, "error", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_txn_instr_error", level--, 0 );
}
ulong fd_txn_instr_error_size( fd_txn_instr_error_t const * self ) {
  ulong size = 0;
  size += sizeof(char);
  size += fd_instr_error_enum_size( &self->error );
  return size;
}

FD_FN_PURE uchar fd_txn_error_enum_is_account_in_use(fd_txn_error_enum_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_txn_error_enum_is_account_loaded_twice(fd_txn_error_enum_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_txn_error_enum_is_account_not_found(fd_txn_error_enum_t const * self) {
  return self->discriminant == 2;
}
FD_FN_PURE uchar fd_txn_error_enum_is_program_account_not_found(fd_txn_error_enum_t const * self) {
  return self->discriminant == 3;
}
FD_FN_PURE uchar fd_txn_error_enum_is_insufficient_funds_for_fee(fd_txn_error_enum_t const * self) {
  return self->discriminant == 4;
}
FD_FN_PURE uchar fd_txn_error_enum_is_invalid_account_for_fee(fd_txn_error_enum_t const * self) {
  return self->discriminant == 5;
}
FD_FN_PURE uchar fd_txn_error_enum_is_already_processed(fd_txn_error_enum_t const * self) {
  return self->discriminant == 6;
}
FD_FN_PURE uchar fd_txn_error_enum_is_blockhash_not_found(fd_txn_error_enum_t const * self) {
  return self->discriminant == 7;
}
FD_FN_PURE uchar fd_txn_error_enum_is_instruction_error(fd_txn_error_enum_t const * self) {
  return self->discriminant == 8;
}
FD_FN_PURE uchar fd_txn_error_enum_is_call_chain_too_deep(fd_txn_error_enum_t const * self) {
  return self->discriminant == 9;
}
FD_FN_PURE uchar fd_txn_error_enum_is_missing_signature_for_fee(fd_txn_error_enum_t const * self) {
  return self->discriminant == 10;
}
FD_FN_PURE uchar fd_txn_error_enum_is_invalid_account_index(fd_txn_error_enum_t const * self) {
  return self->discriminant == 11;
}
FD_FN_PURE uchar fd_txn_error_enum_is_signature_failure(fd_txn_error_enum_t const * self) {
  return self->discriminant == 12;
}
FD_FN_PURE uchar fd_txn_error_enum_is_invalid_program_for_execution(fd_txn_error_enum_t const * self) {
  return self->discriminant == 13;
}
FD_FN_PURE uchar fd_txn_error_enum_is_sanitize_failure(fd_txn_error_enum_t const * self) {
  return self->discriminant == 14;
}
FD_FN_PURE uchar fd_txn_error_enum_is_cluster_maintenance(fd_txn_error_enum_t const * self) {
  return self->discriminant == 15;
}
FD_FN_PURE uchar fd_txn_error_enum_is_account_borrow_outstanding(fd_txn_error_enum_t const * self) {
  return self->discriminant == 16;
}
FD_FN_PURE uchar fd_txn_error_enum_is_would_exceed_max_block_cost_limit(fd_txn_error_enum_t const * self) {
  return self->discriminant == 17;
}
FD_FN_PURE uchar fd_txn_error_enum_is_unsupported_version(fd_txn_error_enum_t const * self) {
  return self->discriminant == 18;
}
FD_FN_PURE uchar fd_txn_error_enum_is_invalid_writable_account(fd_txn_error_enum_t const * self) {
  return self->discriminant == 19;
}
FD_FN_PURE uchar fd_txn_error_enum_is_would_exceed_max_account_cost_limit(fd_txn_error_enum_t const * self) {
  return self->discriminant == 20;
}
FD_FN_PURE uchar fd_txn_error_enum_is_would_exceed_account_data_block_limit(fd_txn_error_enum_t const * self) {
  return self->discriminant == 21;
}
FD_FN_PURE uchar fd_txn_error_enum_is_too_many_account_locks(fd_txn_error_enum_t const * self) {
  return self->discriminant == 22;
}
FD_FN_PURE uchar fd_txn_error_enum_is_address_lookup_table_not_found(fd_txn_error_enum_t const * self) {
  return self->discriminant == 23;
}
FD_FN_PURE uchar fd_txn_error_enum_is_invalid_address_lookup_table_owner(fd_txn_error_enum_t const * self) {
  return self->discriminant == 24;
}
FD_FN_PURE uchar fd_txn_error_enum_is_invalid_address_lookup_table_data(fd_txn_error_enum_t const * self) {
  return self->discriminant == 25;
}
FD_FN_PURE uchar fd_txn_error_enum_is_invalid_address_lookup_table_index(fd_txn_error_enum_t const * self) {
  return self->discriminant == 26;
}
FD_FN_PURE uchar fd_txn_error_enum_is_invalid_rent_paying_account(fd_txn_error_enum_t const * self) {
  return self->discriminant == 27;
}
FD_FN_PURE uchar fd_txn_error_enum_is_would_exceed_max_vote_cost_limit(fd_txn_error_enum_t const * self) {
  return self->discriminant == 28;
}
FD_FN_PURE uchar fd_txn_error_enum_is_would_exceed_account_data_total_limit(fd_txn_error_enum_t const * self) {
  return self->discriminant == 29;
}
FD_FN_PURE uchar fd_txn_error_enum_is_duplicate_instruction(fd_txn_error_enum_t const * self) {
  return self->discriminant == 30;
}
FD_FN_PURE uchar fd_txn_error_enum_is_insufficient_funds_for_rent(fd_txn_error_enum_t const * self) {
  return self->discriminant == 31;
}
FD_FN_PURE uchar fd_txn_error_enum_is_max_loaded_accounts_data_size_exceeded(fd_txn_error_enum_t const * self) {
  return self->discriminant == 32;
}
FD_FN_PURE uchar fd_txn_error_enum_is_invalid_loaded_accounts_data_size_limit(fd_txn_error_enum_t const * self) {
  return self->discriminant == 33;
}
FD_FN_PURE uchar fd_txn_error_enum_is_resanitization_needed(fd_txn_error_enum_t const * self) {
  return self->discriminant == 34;
}
FD_FN_PURE uchar fd_txn_error_enum_is_program_execution_temporarily_restricted(fd_txn_error_enum_t const * self) {
  return self->discriminant == 35;
}
FD_FN_PURE uchar fd_txn_error_enum_is_unbalanced_transaction(fd_txn_error_enum_t const * self) {
  return self->discriminant == 36;
}
void fd_txn_error_enum_inner_new( fd_txn_error_enum_inner_t * self, uint discriminant );
int fd_txn_error_enum_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
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
    err = fd_txn_instr_error_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 9: {
    return FD_BINCODE_SUCCESS;
  }
  case 10: {
    return FD_BINCODE_SUCCESS;
  }
  case 11: {
    return FD_BINCODE_SUCCESS;
  }
  case 12: {
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
  case 16: {
    return FD_BINCODE_SUCCESS;
  }
  case 17: {
    return FD_BINCODE_SUCCESS;
  }
  case 18: {
    return FD_BINCODE_SUCCESS;
  }
  case 19: {
    return FD_BINCODE_SUCCESS;
  }
  case 20: {
    return FD_BINCODE_SUCCESS;
  }
  case 21: {
    return FD_BINCODE_SUCCESS;
  }
  case 22: {
    return FD_BINCODE_SUCCESS;
  }
  case 23: {
    return FD_BINCODE_SUCCESS;
  }
  case 24: {
    return FD_BINCODE_SUCCESS;
  }
  case 25: {
    return FD_BINCODE_SUCCESS;
  }
  case 26: {
    return FD_BINCODE_SUCCESS;
  }
  case 27: {
    return FD_BINCODE_SUCCESS;
  }
  case 28: {
    return FD_BINCODE_SUCCESS;
  }
  case 29: {
    return FD_BINCODE_SUCCESS;
  }
  case 30: {
    err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 31: {
    err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 32: {
    return FD_BINCODE_SUCCESS;
  }
  case 33: {
    return FD_BINCODE_SUCCESS;
  }
  case 34: {
    return FD_BINCODE_SUCCESS;
  }
  case 35: {
    err = fd_bincode_uint8_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 36: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_txn_error_enum_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_txn_error_enum_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_txn_error_enum_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_txn_error_enum_t);
  void const * start_data = ctx->data;
  int err =  fd_txn_error_enum_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_txn_error_enum_inner_decode_inner( fd_txn_error_enum_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
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
    fd_txn_instr_error_decode_inner( &self->instruction_error, alloc_mem, ctx );
    break;
  }
  case 9: {
    break;
  }
  case 10: {
    break;
  }
  case 11: {
    break;
  }
  case 12: {
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
  case 16: {
    break;
  }
  case 17: {
    break;
  }
  case 18: {
    break;
  }
  case 19: {
    break;
  }
  case 20: {
    break;
  }
  case 21: {
    break;
  }
  case 22: {
    break;
  }
  case 23: {
    break;
  }
  case 24: {
    break;
  }
  case 25: {
    break;
  }
  case 26: {
    break;
  }
  case 27: {
    break;
  }
  case 28: {
    break;
  }
  case 29: {
    break;
  }
  case 30: {
    fd_bincode_uint8_decode_unsafe( &self->duplicate_instruction, ctx );
    break;
  }
  case 31: {
    fd_bincode_uint8_decode_unsafe( &self->insufficient_funds_for_rent, ctx );
    break;
  }
  case 32: {
    break;
  }
  case 33: {
    break;
  }
  case 34: {
    break;
  }
  case 35: {
    fd_bincode_uint8_decode_unsafe( &self->program_execution_temporarily_restricted, ctx );
    break;
  }
  case 36: {
    break;
  }
  }
}
static void fd_txn_error_enum_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_txn_error_enum_t * self = (fd_txn_error_enum_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_txn_error_enum_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_txn_error_enum_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_txn_error_enum_t * self = (fd_txn_error_enum_t *)mem;
  fd_txn_error_enum_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_txn_error_enum_t);
  void * * alloc_mem = &alloc_region;
  fd_txn_error_enum_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_txn_error_enum_inner_new( fd_txn_error_enum_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
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
    fd_txn_instr_error_new( &self->instruction_error );
    break;
  }
  case 9: {
    break;
  }
  case 10: {
    break;
  }
  case 11: {
    break;
  }
  case 12: {
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
  case 16: {
    break;
  }
  case 17: {
    break;
  }
  case 18: {
    break;
  }
  case 19: {
    break;
  }
  case 20: {
    break;
  }
  case 21: {
    break;
  }
  case 22: {
    break;
  }
  case 23: {
    break;
  }
  case 24: {
    break;
  }
  case 25: {
    break;
  }
  case 26: {
    break;
  }
  case 27: {
    break;
  }
  case 28: {
    break;
  }
  case 29: {
    break;
  }
  case 30: {
    break;
  }
  case 31: {
    break;
  }
  case 32: {
    break;
  }
  case 33: {
    break;
  }
  case 34: {
    break;
  }
  case 35: {
    break;
  }
  case 36: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_txn_error_enum_new_disc( fd_txn_error_enum_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_txn_error_enum_inner_new( &self->inner, self->discriminant );
}
void fd_txn_error_enum_new( fd_txn_error_enum_t * self ) {
  fd_memset( self, 0, sizeof(fd_txn_error_enum_t) );
  fd_txn_error_enum_new_disc( self, UINT_MAX );
}

void fd_txn_error_enum_walk( void * w, fd_txn_error_enum_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_txn_error_enum", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "account_in_use", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "account_loaded_twice", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 2: {
    fun( w, self, "account_not_found", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 3: {
    fun( w, self, "program_account_not_found", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 4: {
    fun( w, self, "insufficient_funds_for_fee", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 5: {
    fun( w, self, "invalid_account_for_fee", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 6: {
    fun( w, self, "already_processed", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 7: {
    fun( w, self, "blockhash_not_found", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 8: {
    fun( w, self, "instruction_error", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_txn_instr_error_walk( w, &self->inner.instruction_error, fun, "instruction_error", level, 0 );
    break;
  }
  case 9: {
    fun( w, self, "call_chain_too_deep", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 10: {
    fun( w, self, "missing_signature_for_fee", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 11: {
    fun( w, self, "invalid_account_index", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 12: {
    fun( w, self, "signature_failure", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 13: {
    fun( w, self, "invalid_program_for_execution", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 14: {
    fun( w, self, "sanitize_failure", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 15: {
    fun( w, self, "cluster_maintenance", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 16: {
    fun( w, self, "account_borrow_outstanding", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 17: {
    fun( w, self, "would_exceed_max_block_cost_limit", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 18: {
    fun( w, self, "unsupported_version", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 19: {
    fun( w, self, "invalid_writable_account", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 20: {
    fun( w, self, "would_exceed_max_account_cost_limit", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 21: {
    fun( w, self, "would_exceed_account_data_block_limit", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 22: {
    fun( w, self, "too_many_account_locks", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 23: {
    fun( w, self, "address_lookup_table_not_found", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 24: {
    fun( w, self, "invalid_address_lookup_table_owner", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 25: {
    fun( w, self, "invalid_address_lookup_table_data", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 26: {
    fun( w, self, "invalid_address_lookup_table_index", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 27: {
    fun( w, self, "invalid_rent_paying_account", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 28: {
    fun( w, self, "would_exceed_max_vote_cost_limit", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 29: {
    fun( w, self, "would_exceed_account_data_total_limit", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 30: {
    fun( w, self, "duplicate_instruction", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
  fun( w, &self->inner.duplicate_instruction, "duplicate_instruction", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
    break;
  }
  case 31: {
    fun( w, self, "insufficient_funds_for_rent", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
  fun( w, &self->inner.insufficient_funds_for_rent, "insufficient_funds_for_rent", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
    break;
  }
  case 32: {
    fun( w, self, "max_loaded_accounts_data_size_exceeded", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 33: {
    fun( w, self, "invalid_loaded_accounts_data_size_limit", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 34: {
    fun( w, self, "resanitization_needed", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 35: {
    fun( w, self, "program_execution_temporarily_restricted", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
  fun( w, &self->inner.program_execution_temporarily_restricted, "program_execution_temporarily_restricted", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
    break;
  }
  case 36: {
    fun( w, self, "unbalanced_transaction", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_txn_error_enum", level--, 0 );
}
ulong fd_txn_error_enum_size( fd_txn_error_enum_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 8: {
    size += fd_txn_instr_error_size( &self->inner.instruction_error );
    break;
  }
  case 30: {
    size += sizeof(char);
    break;
  }
  case 31: {
    size += sizeof(char);
    break;
  }
  case 35: {
    size += sizeof(char);
    break;
  }
  }
  return size;
}

int fd_txn_error_enum_inner_encode( fd_txn_error_enum_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 8: {
    err = fd_txn_instr_error_encode( &self->instruction_error, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 30: {
    err = fd_bincode_uint8_encode( (uchar)(self->duplicate_instruction), ctx );
  if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 31: {
    err = fd_bincode_uint8_encode( (uchar)(self->insufficient_funds_for_rent), ctx );
  if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  case 35: {
    err = fd_bincode_uint8_encode( (uchar)(self->program_execution_temporarily_restricted), ctx );
  if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_txn_error_enum_encode( fd_txn_error_enum_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_txn_error_enum_inner_encode( &self->inner, self->discriminant, ctx );
}

FD_FN_PURE uchar fd_txn_result_is_ok(fd_txn_result_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_txn_result_is_error(fd_txn_result_t const * self) {
  return self->discriminant == 1;
}
void fd_txn_result_inner_new( fd_txn_result_inner_t * self, uint discriminant );
int fd_txn_result_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_txn_error_enum_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_txn_result_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_txn_result_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_txn_result_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_txn_result_t);
  void const * start_data = ctx->data;
  int err =  fd_txn_result_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_txn_result_inner_decode_inner( fd_txn_result_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_txn_error_enum_decode_inner( &self->error, alloc_mem, ctx );
    break;
  }
  }
}
static void fd_txn_result_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_txn_result_t * self = (fd_txn_result_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_txn_result_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_txn_result_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_txn_result_t * self = (fd_txn_result_t *)mem;
  fd_txn_result_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_txn_result_t);
  void * * alloc_mem = &alloc_region;
  fd_txn_result_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_txn_result_inner_new( fd_txn_result_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    break;
  }
  case 1: {
    fd_txn_error_enum_new( &self->error );
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_txn_result_new_disc( fd_txn_result_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_txn_result_inner_new( &self->inner, self->discriminant );
}
void fd_txn_result_new( fd_txn_result_t * self ) {
  fd_memset( self, 0, sizeof(fd_txn_result_t) );
  fd_txn_result_new_disc( self, UINT_MAX );
}

void fd_txn_result_walk( void * w, fd_txn_result_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_txn_result", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "ok", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "error", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_txn_error_enum_walk( w, &self->inner.error, fun, "error", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_txn_result", level--, 0 );
}
ulong fd_txn_result_size( fd_txn_result_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 1: {
    size += fd_txn_error_enum_size( &self->inner.error );
    break;
  }
  }
  return size;
}

int fd_txn_result_inner_encode( fd_txn_result_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 1: {
    err = fd_txn_error_enum_encode( &self->error, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_txn_result_encode( fd_txn_result_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_txn_result_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_cache_status_encode( fd_cache_status_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_bytes_encode( self->key_slice, 20, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_txn_result_encode( &self->result, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_cache_status_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_bytes_decode_footprint( 20, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_txn_result_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_cache_status_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_cache_status_t);
  void const * start_data = ctx->data;
  int err = fd_cache_status_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_cache_status_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_cache_status_t * self = (fd_cache_status_t *)struct_mem;
  fd_bincode_bytes_decode_unsafe( self->key_slice, 20, ctx );
  fd_txn_result_decode_inner( &self->result, alloc_mem, ctx );
}
void * fd_cache_status_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_cache_status_t * self = (fd_cache_status_t *)mem;
  fd_cache_status_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_cache_status_t);
  void * * alloc_mem = &alloc_region;
  fd_cache_status_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_cache_status_new(fd_cache_status_t * self) {
  fd_memset( self, 0, sizeof(fd_cache_status_t) );
  fd_txn_result_new( &self->result );
}
void fd_cache_status_walk( void * w, fd_cache_status_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_cache_status", level++, 0 );
  fun(w, self->key_slice, "key_slice", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0 );
  fd_txn_result_walk( w, &self->result, fun, "result", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_cache_status", level--, 0 );
}
ulong fd_cache_status_size( fd_cache_status_t const * self ) {
  ulong size = 0;
  size += 20;
  size += fd_txn_result_size( &self->result );
  return size;
}

int fd_status_value_encode( fd_status_value_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->txn_idx, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->statuses_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->statuses_len ) {
    for( ulong i=0; i < self->statuses_len; i++ ) {
      err = fd_cache_status_encode( self->statuses + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_status_value_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  ulong statuses_len;
  err = fd_bincode_uint64_decode( &statuses_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( statuses_len ) {
    *total_sz += FD_CACHE_STATUS_ALIGN + sizeof(fd_cache_status_t)*statuses_len;
    for( ulong i=0; i < statuses_len; i++ ) {
      err = fd_cache_status_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_status_value_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_status_value_t);
  void const * start_data = ctx->data;
  int err = fd_status_value_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_status_value_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_status_value_t * self = (fd_status_value_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->txn_idx, ctx );
  fd_bincode_uint64_decode_unsafe( &self->statuses_len, ctx );
  if( self->statuses_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_CACHE_STATUS_ALIGN );
    self->statuses = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_cache_status_t)*self->statuses_len;
    for( ulong i=0; i < self->statuses_len; i++ ) {
      fd_cache_status_new( self->statuses + i );
      fd_cache_status_decode_inner( self->statuses + i, alloc_mem, ctx );
    }
  } else
    self->statuses = NULL;
}
void * fd_status_value_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_status_value_t * self = (fd_status_value_t *)mem;
  fd_status_value_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_status_value_t);
  void * * alloc_mem = &alloc_region;
  fd_status_value_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_status_value_new(fd_status_value_t * self) {
  fd_memset( self, 0, sizeof(fd_status_value_t) );
}
void fd_status_value_walk( void * w, fd_status_value_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_status_value", level++, 0 );
  fun( w, &self->txn_idx, "txn_idx", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  if( self->statuses_len ) {
    fun( w, NULL, "statuses", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->statuses_len; i++ )
      fd_cache_status_walk(w, self->statuses + i, fun, "cache_status", level, 0 );
    fun( w, NULL, "statuses", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_status_value", level--, 0 );
}
ulong fd_status_value_size( fd_status_value_t const * self ) {
  ulong size = 0;
  size += sizeof(ulong);
  do {
    size += sizeof(ulong);
    for( ulong i=0; i < self->statuses_len; i++ )
      size += fd_cache_status_size( self->statuses + i );
  } while(0);
  return size;
}

int fd_status_pair_encode( fd_status_pair_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_hash_encode( &self->hash, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_status_value_encode( &self->value, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_status_pair_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_hash_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_status_value_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_status_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_status_pair_t);
  void const * start_data = ctx->data;
  int err = fd_status_pair_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_status_pair_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_status_pair_t * self = (fd_status_pair_t *)struct_mem;
  fd_hash_decode_inner( &self->hash, alloc_mem, ctx );
  fd_status_value_decode_inner( &self->value, alloc_mem, ctx );
}
void * fd_status_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_status_pair_t * self = (fd_status_pair_t *)mem;
  fd_status_pair_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_status_pair_t);
  void * * alloc_mem = &alloc_region;
  fd_status_pair_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_status_pair_new(fd_status_pair_t * self) {
  fd_memset( self, 0, sizeof(fd_status_pair_t) );
  fd_hash_new( &self->hash );
  fd_status_value_new( &self->value );
}
void fd_status_pair_walk( void * w, fd_status_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_status_pair", level++, 0 );
  fd_hash_walk( w, &self->hash, fun, "hash", level, 0 );
  fd_status_value_walk( w, &self->value, fun, "value", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_status_pair", level--, 0 );
}
ulong fd_status_pair_size( fd_status_pair_t const * self ) {
  ulong size = 0;
  size += fd_hash_size( &self->hash );
  size += fd_status_value_size( &self->value );
  return size;
}

int fd_slot_delta_encode( fd_slot_delta_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->slot, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_bool_encode( (uchar)(self->is_root), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->slot_delta_vec_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->slot_delta_vec_len ) {
    for( ulong i=0; i < self->slot_delta_vec_len; i++ ) {
      err = fd_status_pair_encode( self->slot_delta_vec + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_slot_delta_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_bool_decode_footprint( ctx );
  if( FD_UNLIKELY( err ) ) return err;
  ulong slot_delta_vec_len;
  err = fd_bincode_uint64_decode( &slot_delta_vec_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( slot_delta_vec_len ) {
    *total_sz += FD_STATUS_PAIR_ALIGN + sizeof(fd_status_pair_t)*slot_delta_vec_len;
    for( ulong i=0; i < slot_delta_vec_len; i++ ) {
      err = fd_status_pair_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_slot_delta_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_slot_delta_t);
  void const * start_data = ctx->data;
  int err = fd_slot_delta_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_slot_delta_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_slot_delta_t * self = (fd_slot_delta_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->slot, ctx );
  fd_bincode_bool_decode_unsafe( &self->is_root, ctx );
  fd_bincode_uint64_decode_unsafe( &self->slot_delta_vec_len, ctx );
  if( self->slot_delta_vec_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_STATUS_PAIR_ALIGN );
    self->slot_delta_vec = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_status_pair_t)*self->slot_delta_vec_len;
    for( ulong i=0; i < self->slot_delta_vec_len; i++ ) {
      fd_status_pair_new( self->slot_delta_vec + i );
      fd_status_pair_decode_inner( self->slot_delta_vec + i, alloc_mem, ctx );
    }
  } else
    self->slot_delta_vec = NULL;
}
void * fd_slot_delta_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_slot_delta_t * self = (fd_slot_delta_t *)mem;
  fd_slot_delta_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_slot_delta_t);
  void * * alloc_mem = &alloc_region;
  fd_slot_delta_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_slot_delta_new(fd_slot_delta_t * self) {
  fd_memset( self, 0, sizeof(fd_slot_delta_t) );
}
void fd_slot_delta_walk( void * w, fd_slot_delta_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_slot_delta", level++, 0 );
  fun( w, &self->slot, "slot", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->is_root, "is_root", FD_FLAMENCO_TYPE_BOOL, "bool", level, 0  );
  if( self->slot_delta_vec_len ) {
    fun( w, NULL, "slot_delta_vec", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->slot_delta_vec_len; i++ )
      fd_status_pair_walk(w, self->slot_delta_vec + i, fun, "status_pair", level, 0 );
    fun( w, NULL, "slot_delta_vec", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_slot_delta", level--, 0 );
}
ulong fd_slot_delta_size( fd_slot_delta_t const * self ) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(char);
  do {
    size += sizeof(ulong);
    for( ulong i=0; i < self->slot_delta_vec_len; i++ )
      size += fd_status_pair_size( self->slot_delta_vec + i );
  } while(0);
  return size;
}

int fd_bank_slot_deltas_encode( fd_bank_slot_deltas_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->slot_deltas_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->slot_deltas_len ) {
    for( ulong i=0; i < self->slot_deltas_len; i++ ) {
      err = fd_slot_delta_encode( self->slot_deltas + i, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_bank_slot_deltas_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ulong slot_deltas_len;
  err = fd_bincode_uint64_decode( &slot_deltas_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( slot_deltas_len ) {
    *total_sz += FD_SLOT_DELTA_ALIGN + sizeof(fd_slot_delta_t)*slot_deltas_len;
    for( ulong i=0; i < slot_deltas_len; i++ ) {
      err = fd_slot_delta_decode_footprint_inner( ctx, total_sz );
      if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
    }
  }
  return 0;
}
int fd_bank_slot_deltas_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_bank_slot_deltas_t);
  void const * start_data = ctx->data;
  int err = fd_bank_slot_deltas_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_bank_slot_deltas_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bank_slot_deltas_t * self = (fd_bank_slot_deltas_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->slot_deltas_len, ctx );
  if( self->slot_deltas_len ) {
    *alloc_mem = (void*)fd_ulong_align_up( (ulong)(*alloc_mem), FD_SLOT_DELTA_ALIGN );
    self->slot_deltas = *alloc_mem;
    *alloc_mem = (uchar *)(*alloc_mem) + sizeof(fd_slot_delta_t)*self->slot_deltas_len;
    for( ulong i=0; i < self->slot_deltas_len; i++ ) {
      fd_slot_delta_new( self->slot_deltas + i );
      fd_slot_delta_decode_inner( self->slot_deltas + i, alloc_mem, ctx );
    }
  } else
    self->slot_deltas = NULL;
}
void * fd_bank_slot_deltas_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_bank_slot_deltas_t * self = (fd_bank_slot_deltas_t *)mem;
  fd_bank_slot_deltas_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_bank_slot_deltas_t);
  void * * alloc_mem = &alloc_region;
  fd_bank_slot_deltas_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_bank_slot_deltas_new(fd_bank_slot_deltas_t * self) {
  fd_memset( self, 0, sizeof(fd_bank_slot_deltas_t) );
}
void fd_bank_slot_deltas_walk( void * w, fd_bank_slot_deltas_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_bank_slot_deltas", level++, 0 );
  if( self->slot_deltas_len ) {
    fun( w, NULL, "slot_deltas", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->slot_deltas_len; i++ )
      fd_slot_delta_walk(w, self->slot_deltas + i, fun, "slot_delta", level, 0 );
    fun( w, NULL, "slot_deltas", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_bank_slot_deltas", level--, 0 );
}
ulong fd_bank_slot_deltas_size( fd_bank_slot_deltas_t const * self ) {
  ulong size = 0;
  do {
    size += sizeof(ulong);
    for( ulong i=0; i < self->slot_deltas_len; i++ )
      size += fd_slot_delta_size( self->slot_deltas + i );
  } while(0);
  return size;
}

int fd_pubkey_rewardinfo_pair_encode( fd_pubkey_rewardinfo_pair_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->pubkey, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_reward_info_encode( &self->reward_info, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_pubkey_rewardinfo_pair_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_pubkey_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_reward_info_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  return 0;
}
int fd_pubkey_rewardinfo_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_pubkey_rewardinfo_pair_t);
  void const * start_data = ctx->data;
  int err = fd_pubkey_rewardinfo_pair_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_pubkey_rewardinfo_pair_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_pubkey_rewardinfo_pair_t * self = (fd_pubkey_rewardinfo_pair_t *)struct_mem;
  fd_pubkey_decode_inner( &self->pubkey, alloc_mem, ctx );
  fd_reward_info_decode_inner( &self->reward_info, alloc_mem, ctx );
}
void * fd_pubkey_rewardinfo_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_pubkey_rewardinfo_pair_t * self = (fd_pubkey_rewardinfo_pair_t *)mem;
  fd_pubkey_rewardinfo_pair_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_pubkey_rewardinfo_pair_t);
  void * * alloc_mem = &alloc_region;
  fd_pubkey_rewardinfo_pair_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_pubkey_rewardinfo_pair_new(fd_pubkey_rewardinfo_pair_t * self) {
  fd_memset( self, 0, sizeof(fd_pubkey_rewardinfo_pair_t) );
  fd_pubkey_new( &self->pubkey );
  fd_reward_info_new( &self->reward_info );
}
void fd_pubkey_rewardinfo_pair_walk( void * w, fd_pubkey_rewardinfo_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_pubkey_rewardinfo_pair", level++, 0 );
  fd_pubkey_walk( w, &self->pubkey, fun, "pubkey", level, 0 );
  fd_reward_info_walk( w, &self->reward_info, fun, "reward_info", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_pubkey_rewardinfo_pair", level--, 0 );
}
int fd_calculated_stake_points_encode( fd_calculated_stake_points_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint128_encode( self->points, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->new_credits_observed, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint8_encode( (uchar)(self->force_credits_update_with_skipped_reward), ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_calculated_stake_points_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 25UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 25UL );
  return 0;
}
static void fd_calculated_stake_points_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_calculated_stake_points_t * self = (fd_calculated_stake_points_t *)struct_mem;
  fd_bincode_uint128_decode_unsafe( &self->points, ctx );
  fd_bincode_uint64_decode_unsafe( &self->new_credits_observed, ctx );
  fd_bincode_uint8_decode_unsafe( &self->force_credits_update_with_skipped_reward, ctx );
}
void * fd_calculated_stake_points_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_calculated_stake_points_t * self = (fd_calculated_stake_points_t *)mem;
  fd_calculated_stake_points_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_calculated_stake_points_t);
  void * * alloc_mem = &alloc_region;
  fd_calculated_stake_points_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_calculated_stake_points_walk( void * w, fd_calculated_stake_points_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_calculated_stake_points", level++, 0 );
  fun( w, &self->points, "points", FD_FLAMENCO_TYPE_UINT128, "uint128", level, 0  );
  fun( w, &self->new_credits_observed, "new_credits_observed", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->force_credits_update_with_skipped_reward, "force_credits_update_with_skipped_reward", FD_FLAMENCO_TYPE_UCHAR, "uchar", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_calculated_stake_points", level--, 0 );
}
int fd_calculated_stake_rewards_encode( fd_calculated_stake_rewards_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->staker_rewards, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->voter_rewards, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->new_credits_observed, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_calculated_stake_rewards_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 24UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 24UL );
  return 0;
}
static void fd_calculated_stake_rewards_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_calculated_stake_rewards_t * self = (fd_calculated_stake_rewards_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->staker_rewards, ctx );
  fd_bincode_uint64_decode_unsafe( &self->voter_rewards, ctx );
  fd_bincode_uint64_decode_unsafe( &self->new_credits_observed, ctx );
}
void * fd_calculated_stake_rewards_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_calculated_stake_rewards_t * self = (fd_calculated_stake_rewards_t *)mem;
  fd_calculated_stake_rewards_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_calculated_stake_rewards_t);
  void * * alloc_mem = &alloc_region;
  fd_calculated_stake_rewards_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_calculated_stake_rewards_walk( void * w, fd_calculated_stake_rewards_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_calculated_stake_rewards", level++, 0 );
  fun( w, &self->staker_rewards, "staker_rewards", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->voter_rewards, "voter_rewards", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->new_credits_observed, "new_credits_observed", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_calculated_stake_rewards", level--, 0 );
}
int fd_duplicate_slot_proof_encode( fd_duplicate_slot_proof_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->shred1_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->shred1_len ) {
    err = fd_bincode_bytes_encode( self->shred1, self->shred1_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  err = fd_bincode_uint64_encode( self->shred2_len, ctx );
  if( FD_UNLIKELY(err) ) return err;
  if( self->shred2_len ) {
    err = fd_bincode_bytes_encode( self->shred2, self->shred2_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_duplicate_slot_proof_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ulong shred1_len;
  err = fd_bincode_uint64_decode( &shred1_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( shred1_len ) {
    *total_sz += 8UL + shred1_len;
    err = fd_bincode_bytes_decode_footprint( shred1_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  ulong shred2_len;
  err = fd_bincode_uint64_decode( &shred2_len, ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  if( shred2_len ) {
    *total_sz += 8UL + shred2_len;
    err = fd_bincode_bytes_decode_footprint( shred2_len, ctx );
    if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  }
  return 0;
}
int fd_duplicate_slot_proof_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_duplicate_slot_proof_t);
  void const * start_data = ctx->data;
  int err = fd_duplicate_slot_proof_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_duplicate_slot_proof_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_duplicate_slot_proof_t * self = (fd_duplicate_slot_proof_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->shred1_len, ctx );
  if( self->shred1_len ) {
    self->shred1 = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->shred1, self->shred1_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->shred1_len;
  } else
    self->shred1 = NULL;
  fd_bincode_uint64_decode_unsafe( &self->shred2_len, ctx );
  if( self->shred2_len ) {
    self->shred2 = *alloc_mem;
    fd_bincode_bytes_decode_unsafe( self->shred2, self->shred2_len, ctx );
    *alloc_mem = (uchar *)(*alloc_mem) + self->shred2_len;
  } else
    self->shred2 = NULL;
}
void * fd_duplicate_slot_proof_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_duplicate_slot_proof_t * self = (fd_duplicate_slot_proof_t *)mem;
  fd_duplicate_slot_proof_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_duplicate_slot_proof_t);
  void * * alloc_mem = &alloc_region;
  fd_duplicate_slot_proof_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_duplicate_slot_proof_new(fd_duplicate_slot_proof_t * self) {
  fd_memset( self, 0, sizeof(fd_duplicate_slot_proof_t) );
}
void fd_duplicate_slot_proof_walk( void * w, fd_duplicate_slot_proof_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_duplicate_slot_proof", level++, 0 );
  if( self->shred1_len ) {
    fun( w, NULL, "shred1", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->shred1_len; i++ )
      fun( w, self->shred1 + i, "shred1", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "shred1", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  if( self->shred2_len ) {
    fun( w, NULL, "shred2", FD_FLAMENCO_TYPE_ARR, "array", level++, 0 );
    for( ulong i=0; i < self->shred2_len; i++ )
      fun( w, self->shred2 + i, "shred2", FD_FLAMENCO_TYPE_UCHAR,   "uchar",   level, 0 );
    fun( w, NULL, "shred2", FD_FLAMENCO_TYPE_ARR_END, "array", level--, 0 );
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_duplicate_slot_proof", level--, 0 );
}
ulong fd_duplicate_slot_proof_size( fd_duplicate_slot_proof_t const * self ) {
  ulong size = 0;
  do {
    size += sizeof(ulong);
    size += self->shred1_len;
  } while(0);
  do {
    size += sizeof(ulong);
    size += self->shred2_len;
  } while(0);
  return size;
}

int fd_epoch_info_pair_encode( fd_epoch_info_pair_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->account, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_stake_encode( &self->stake, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_epoch_info_pair_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 104UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 104UL );
  return 0;
}
static void fd_epoch_info_pair_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_epoch_info_pair_t * self = (fd_epoch_info_pair_t *)struct_mem;
  fd_pubkey_decode_inner( &self->account, alloc_mem, ctx );
  fd_stake_decode_inner( &self->stake, alloc_mem, ctx );
}
void * fd_epoch_info_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_epoch_info_pair_t * self = (fd_epoch_info_pair_t *)mem;
  fd_epoch_info_pair_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_epoch_info_pair_t);
  void * * alloc_mem = &alloc_region;
  fd_epoch_info_pair_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_epoch_info_pair_walk( void * w, fd_epoch_info_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_epoch_info_pair", level++, 0 );
  fd_pubkey_walk( w, &self->account, fun, "account", level, 0 );
  fd_stake_walk( w, &self->stake, fun, "stake", level, 0 );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_epoch_info_pair", level--, 0 );
}
int fd_usage_cost_details_encode( fd_usage_cost_details_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->signature_cost, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->write_lock_cost, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->data_bytes_cost, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->programs_execution_cost, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->loaded_accounts_data_size_cost, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->allocated_accounts_data_size, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_usage_cost_details_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 48UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 48UL );
  return 0;
}
static void fd_usage_cost_details_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_usage_cost_details_t * self = (fd_usage_cost_details_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->signature_cost, ctx );
  fd_bincode_uint64_decode_unsafe( &self->write_lock_cost, ctx );
  fd_bincode_uint64_decode_unsafe( &self->data_bytes_cost, ctx );
  fd_bincode_uint64_decode_unsafe( &self->programs_execution_cost, ctx );
  fd_bincode_uint64_decode_unsafe( &self->loaded_accounts_data_size_cost, ctx );
  fd_bincode_uint64_decode_unsafe( &self->allocated_accounts_data_size, ctx );
}
void * fd_usage_cost_details_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_usage_cost_details_t * self = (fd_usage_cost_details_t *)mem;
  fd_usage_cost_details_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_usage_cost_details_t);
  void * * alloc_mem = &alloc_region;
  fd_usage_cost_details_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_usage_cost_details_walk( void * w, fd_usage_cost_details_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_usage_cost_details", level++, 0 );
  fun( w, &self->signature_cost, "signature_cost", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->write_lock_cost, "write_lock_cost", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->data_bytes_cost, "data_bytes_cost", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->programs_execution_cost, "programs_execution_cost", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->loaded_accounts_data_size_cost, "loaded_accounts_data_size_cost", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->allocated_accounts_data_size, "allocated_accounts_data_size", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_usage_cost_details", level--, 0 );
}
FD_FN_PURE uchar fd_transaction_cost_is_simple_vote(fd_transaction_cost_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_transaction_cost_is_transaction(fd_transaction_cost_t const * self) {
  return self->discriminant == 1;
}
void fd_transaction_cost_inner_new( fd_transaction_cost_inner_t * self, uint discriminant );
int fd_transaction_cost_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_usage_cost_details_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_transaction_cost_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_transaction_cost_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_transaction_cost_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_transaction_cost_t);
  void const * start_data = ctx->data;
  int err =  fd_transaction_cost_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_transaction_cost_inner_decode_inner( fd_transaction_cost_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_usage_cost_details_decode_inner( &self->transaction, alloc_mem, ctx );
    break;
  }
  }
}
static void fd_transaction_cost_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_transaction_cost_t * self = (fd_transaction_cost_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_transaction_cost_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_transaction_cost_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_transaction_cost_t * self = (fd_transaction_cost_t *)mem;
  fd_transaction_cost_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_transaction_cost_t);
  void * * alloc_mem = &alloc_region;
  fd_transaction_cost_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_transaction_cost_inner_new( fd_transaction_cost_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    break;
  }
  case 1: {
    fd_usage_cost_details_new( &self->transaction );
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_transaction_cost_new_disc( fd_transaction_cost_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_transaction_cost_inner_new( &self->inner, self->discriminant );
}
void fd_transaction_cost_new( fd_transaction_cost_t * self ) {
  fd_memset( self, 0, sizeof(fd_transaction_cost_t) );
  fd_transaction_cost_new_disc( self, UINT_MAX );
}

void fd_transaction_cost_walk( void * w, fd_transaction_cost_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_transaction_cost", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "simple_vote", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "transaction", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_usage_cost_details_walk( w, &self->inner.transaction, fun, "transaction", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_transaction_cost", level--, 0 );
}
ulong fd_transaction_cost_size( fd_transaction_cost_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 1: {
    size += fd_usage_cost_details_size( &self->inner.transaction );
    break;
  }
  }
  return size;
}

int fd_transaction_cost_inner_encode( fd_transaction_cost_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 1: {
    err = fd_usage_cost_details_encode( &self->transaction, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_transaction_cost_encode( fd_transaction_cost_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_transaction_cost_inner_encode( &self->inner, self->discriminant, ctx );
}

int fd_account_costs_pair_encode( fd_account_costs_pair_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_pubkey_encode( &self->key, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->cost, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_account_costs_pair_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 40UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 40UL );
  return 0;
}
static void fd_account_costs_pair_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_account_costs_pair_t * self = (fd_account_costs_pair_t *)struct_mem;
  fd_pubkey_decode_inner( &self->key, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->cost, ctx );
}
void * fd_account_costs_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_account_costs_pair_t * self = (fd_account_costs_pair_t *)mem;
  fd_account_costs_pair_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_account_costs_pair_t);
  void * * alloc_mem = &alloc_region;
  fd_account_costs_pair_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_account_costs_pair_walk( void * w, fd_account_costs_pair_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_account_costs_pair", level++, 0 );
  fd_pubkey_walk( w, &self->key, fun, "key", level, 0 );
  fun( w, &self->cost, "cost", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_account_costs_pair", level--, 0 );
}
int fd_account_costs_encode( fd_account_costs_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  if( self->account_costs_root ) {
    ulong account_costs_len = fd_account_costs_pair_t_map_size( self->account_costs_pool, self->account_costs_root );
    err = fd_bincode_uint64_encode( account_costs_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    for( fd_account_costs_pair_t_mapnode_t * n = fd_account_costs_pair_t_map_minimum( self->account_costs_pool, self->account_costs_root ); n; n = fd_account_costs_pair_t_map_successor( self->account_costs_pool, n ) ) {
      err = fd_account_costs_pair_encode( &n->elem, ctx );
      if( FD_UNLIKELY( err ) ) return err;
    }
  } else {
    ulong account_costs_len = 0;
    err = fd_bincode_uint64_encode( account_costs_len, ctx );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return FD_BINCODE_SUCCESS;
}
static int fd_account_costs_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  ulong account_costs_len = 0UL;
  err = fd_bincode_uint64_decode( &account_costs_len, ctx );
  ulong account_costs_cnt = fd_ulong_max( account_costs_len, 4096 );
  *total_sz += fd_account_costs_pair_t_map_align() + fd_account_costs_pair_t_map_footprint( account_costs_cnt );
  if( FD_UNLIKELY( err ) ) return err;
  for( ulong i=0; i < account_costs_len; i++ ) {
    err = fd_account_costs_pair_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
  }
  return 0;
}
int fd_account_costs_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_account_costs_t);
  void const * start_data = ctx->data;
  int err = fd_account_costs_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_account_costs_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_account_costs_t * self = (fd_account_costs_t *)struct_mem;
  ulong account_costs_len;
  fd_bincode_uint64_decode_unsafe( &account_costs_len, ctx );
  self->account_costs_pool = fd_account_costs_pair_t_map_join_new( alloc_mem, fd_ulong_max( account_costs_len, 4096 ) );
  self->account_costs_root = NULL;
  for( ulong i=0; i < account_costs_len; i++ ) {
    fd_account_costs_pair_t_mapnode_t * node = fd_account_costs_pair_t_map_acquire( self->account_costs_pool );
    fd_account_costs_pair_new( &node->elem );
    fd_account_costs_pair_decode_inner( &node->elem, alloc_mem, ctx );
    fd_account_costs_pair_t_mapnode_t * out = NULL;;
    fd_account_costs_pair_t_map_insert_or_replace( self->account_costs_pool, &self->account_costs_root, node, &out );
    if( out != NULL ) {
      fd_account_costs_pair_t_map_release( self->account_costs_pool, out );
    }
  }
}
void * fd_account_costs_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_account_costs_t * self = (fd_account_costs_t *)mem;
  fd_account_costs_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_account_costs_t);
  void * * alloc_mem = &alloc_region;
  fd_account_costs_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_account_costs_new(fd_account_costs_t * self) {
  fd_memset( self, 0, sizeof(fd_account_costs_t) );
}
void fd_account_costs_walk( void * w, fd_account_costs_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_account_costs", level++, 0 );
  if( self->account_costs_root ) {
    for( fd_account_costs_pair_t_mapnode_t * n = fd_account_costs_pair_t_map_minimum(self->account_costs_pool, self->account_costs_root ); n; n = fd_account_costs_pair_t_map_successor( self->account_costs_pool, n ) ) {
      fd_account_costs_pair_walk(w, &n->elem, fun, "account_costs", level, 0 );
    }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_account_costs", level--, 0 );
}
ulong fd_account_costs_size( fd_account_costs_t const * self ) {
  ulong size = 0;
  if( self->account_costs_root ) {
    size += sizeof(ulong);
    ulong max = fd_account_costs_pair_t_map_max( self->account_costs_pool );
    size += fd_account_costs_pair_t_map_footprint( max );
    for( fd_account_costs_pair_t_mapnode_t * n = fd_account_costs_pair_t_map_minimum( self->account_costs_pool, self->account_costs_root ); n; n = fd_account_costs_pair_t_map_successor( self->account_costs_pool, n ) ) {
      size += fd_account_costs_pair_size( &n->elem ) - sizeof(fd_account_costs_pair_t);
    }
  } else {
    size += sizeof(ulong);
  }
  return size;
}

int fd_cost_tracker_encode( fd_cost_tracker_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->account_cost_limit, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->block_cost_limit, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->vote_cost_limit, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_account_costs_encode( &self->cost_by_writable_accounts, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->block_cost, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->vote_cost, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->transaction_count, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->allocated_accounts_data_size, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->transaction_signature_count, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->secp256k1_instruction_signature_count, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->ed25519_instruction_signature_count, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->secp256r1_instruction_signature_count, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static int fd_cost_tracker_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  int err = 0;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_account_costs_decode_footprint_inner( ctx, total_sz );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  err = fd_bincode_uint64_decode_footprint( ctx );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return err;
  return 0;
}
int fd_cost_tracker_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_cost_tracker_t);
  void const * start_data = ctx->data;
  int err = fd_cost_tracker_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_cost_tracker_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_cost_tracker_t * self = (fd_cost_tracker_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->account_cost_limit, ctx );
  fd_bincode_uint64_decode_unsafe( &self->block_cost_limit, ctx );
  fd_bincode_uint64_decode_unsafe( &self->vote_cost_limit, ctx );
  fd_account_costs_decode_inner( &self->cost_by_writable_accounts, alloc_mem, ctx );
  fd_bincode_uint64_decode_unsafe( &self->block_cost, ctx );
  fd_bincode_uint64_decode_unsafe( &self->vote_cost, ctx );
  fd_bincode_uint64_decode_unsafe( &self->transaction_count, ctx );
  fd_bincode_uint64_decode_unsafe( &self->allocated_accounts_data_size, ctx );
  fd_bincode_uint64_decode_unsafe( &self->transaction_signature_count, ctx );
  fd_bincode_uint64_decode_unsafe( &self->secp256k1_instruction_signature_count, ctx );
  fd_bincode_uint64_decode_unsafe( &self->ed25519_instruction_signature_count, ctx );
  fd_bincode_uint64_decode_unsafe( &self->secp256r1_instruction_signature_count, ctx );
}
void * fd_cost_tracker_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_cost_tracker_t * self = (fd_cost_tracker_t *)mem;
  fd_cost_tracker_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_cost_tracker_t);
  void * * alloc_mem = &alloc_region;
  fd_cost_tracker_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_cost_tracker_new(fd_cost_tracker_t * self) {
  fd_memset( self, 0, sizeof(fd_cost_tracker_t) );
  fd_account_costs_new( &self->cost_by_writable_accounts );
}
void fd_cost_tracker_walk( void * w, fd_cost_tracker_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_cost_tracker", level++, 0 );
  fun( w, &self->account_cost_limit, "account_cost_limit", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->block_cost_limit, "block_cost_limit", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->vote_cost_limit, "vote_cost_limit", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fd_account_costs_walk( w, &self->cost_by_writable_accounts, fun, "cost_by_writable_accounts", level, 0 );
  fun( w, &self->block_cost, "block_cost", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->vote_cost, "vote_cost", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->transaction_count, "transaction_count", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->allocated_accounts_data_size, "allocated_accounts_data_size", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->transaction_signature_count, "transaction_signature_count", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->secp256k1_instruction_signature_count, "secp256k1_instruction_signature_count", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->ed25519_instruction_signature_count, "ed25519_instruction_signature_count", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->secp256r1_instruction_signature_count, "secp256r1_instruction_signature_count", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_cost_tracker", level--, 0 );
}
ulong fd_cost_tracker_size( fd_cost_tracker_t const * self ) {
  ulong size = 0;
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += fd_account_costs_size( &self->cost_by_writable_accounts );
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  size += sizeof(ulong);
  return size;
}

int fd_rent_paying_encode( fd_rent_paying_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  err = fd_bincode_uint64_encode( self->lamports, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_bincode_uint64_encode( self->data_size, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return FD_BINCODE_SUCCESS;
}
static inline int fd_rent_paying_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( (ulong)ctx->data + 16UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = (void *)( (ulong)ctx->data + 16UL );
  return 0;
}
static void fd_rent_paying_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_rent_paying_t * self = (fd_rent_paying_t *)struct_mem;
  fd_bincode_uint64_decode_unsafe( &self->lamports, ctx );
  fd_bincode_uint64_decode_unsafe( &self->data_size, ctx );
}
void * fd_rent_paying_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_rent_paying_t * self = (fd_rent_paying_t *)mem;
  fd_rent_paying_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_rent_paying_t);
  void * * alloc_mem = &alloc_region;
  fd_rent_paying_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_rent_paying_walk( void * w, fd_rent_paying_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP, "fd_rent_paying", level++, 0 );
  fun( w, &self->lamports, "lamports", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, &self->data_size, "data_size", FD_FLAMENCO_TYPE_ULONG, "ulong", level, 0  );
  fun( w, self, name, FD_FLAMENCO_TYPE_MAP_END, "fd_rent_paying", level--, 0 );
}
FD_FN_PURE uchar fd_rent_state_is_uninitialized(fd_rent_state_t const * self) {
  return self->discriminant == 0;
}
FD_FN_PURE uchar fd_rent_state_is_rent_paying(fd_rent_state_t const * self) {
  return self->discriminant == 1;
}
FD_FN_PURE uchar fd_rent_state_is_rent_exempt(fd_rent_state_t const * self) {
  return self->discriminant == 2;
}
void fd_rent_state_inner_new( fd_rent_state_inner_t * self, uint discriminant );
int fd_rent_state_inner_decode_footprint( uint discriminant, fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  int err;
  switch (discriminant) {
  case 0: {
    return FD_BINCODE_SUCCESS;
  }
  case 1: {
    err = fd_rent_paying_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
    return FD_BINCODE_SUCCESS;
  }
  case 2: {
    return FD_BINCODE_SUCCESS;
  }
  default: return FD_BINCODE_ERR_ENCODING;
  }
}
static int fd_rent_state_decode_footprint_inner( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  if( ctx->data>=ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  uint discriminant = 0;
  int err = fd_bincode_uint32_decode( &discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_rent_state_inner_decode_footprint( discriminant, ctx, total_sz );
}
int fd_rent_state_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_rent_state_t);
  void const * start_data = ctx->data;
  int err =  fd_rent_state_decode_footprint_inner( ctx, total_sz );
  if( ctx->data>ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  ctx->data = start_data;
  return err;
}
static void fd_rent_state_inner_decode_inner( fd_rent_state_inner_t * self, void * * alloc_mem, uint discriminant, fd_bincode_decode_ctx_t * ctx ) {
  switch (discriminant) {
  case 0: {
    break;
  }
  case 1: {
    fd_rent_paying_decode_inner( &self->rent_paying, alloc_mem, ctx );
    break;
  }
  case 2: {
    break;
  }
  }
}
static void fd_rent_state_decode_inner( void * struct_mem, void * * alloc_mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_rent_state_t * self = (fd_rent_state_t *)struct_mem;
  fd_bincode_uint32_decode_unsafe( &self->discriminant, ctx );
  fd_rent_state_inner_decode_inner( &self->inner, alloc_mem, self->discriminant, ctx );
}
void * fd_rent_state_decode( void * mem, fd_bincode_decode_ctx_t * ctx ) {
  fd_rent_state_t * self = (fd_rent_state_t *)mem;
  fd_rent_state_new( self );
  void * alloc_region = (uchar *)mem + sizeof(fd_rent_state_t);
  void * * alloc_mem = &alloc_region;
  fd_rent_state_decode_inner( mem, alloc_mem, ctx );
  return self;
}
void fd_rent_state_inner_new( fd_rent_state_inner_t * self, uint discriminant ) {
  switch( discriminant ) {
  case 0: {
    break;
  }
  case 1: {
    fd_rent_paying_new( &self->rent_paying );
    break;
  }
  case 2: {
    break;
  }
  default: break; // FD_LOG_ERR(( "unhandled type"));
  }
}
void fd_rent_state_new_disc( fd_rent_state_t * self, uint discriminant ) {
  self->discriminant = discriminant;
  fd_rent_state_inner_new( &self->inner, self->discriminant );
}
void fd_rent_state_new( fd_rent_state_t * self ) {
  fd_memset( self, 0, sizeof(fd_rent_state_t) );
  fd_rent_state_new_disc( self, UINT_MAX );
}

void fd_rent_state_walk( void * w, fd_rent_state_t const * self, fd_types_walk_fn_t fun, const char *name, uint level, uint varint ) {
  (void) varint;
  fun(w, self, name, FD_FLAMENCO_TYPE_ENUM, "fd_rent_state", level++, 0);
  switch( self->discriminant ) {
  case 0: {
    fun( w, self, "uninitialized", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  case 1: {
    fun( w, self, "rent_paying", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    fd_rent_paying_walk( w, &self->inner.rent_paying, fun, "rent_paying", level, 0 );
    break;
  }
  case 2: {
    fun( w, self, "rent_exempt", FD_FLAMENCO_TYPE_ENUM_DISC, "discriminant", level, 0 );
    break;
  }
  }
  fun( w, self, name, FD_FLAMENCO_TYPE_ENUM_END, "fd_rent_state", level--, 0 );
}
ulong fd_rent_state_size( fd_rent_state_t const * self ) {
  ulong size = 0;
  size += sizeof(uint);
  switch (self->discriminant) {
  case 1: {
    size += fd_rent_paying_size( &self->inner.rent_paying );
    break;
  }
  }
  return size;
}

int fd_rent_state_inner_encode( fd_rent_state_inner_t const * self, uint discriminant, fd_bincode_encode_ctx_t * ctx ) {
  int err;
  switch (discriminant) {
  case 1: {
    err = fd_rent_paying_encode( &self->rent_paying, ctx );
    if( FD_UNLIKELY( err ) ) return err;
    break;
  }
  }
  return FD_BINCODE_SUCCESS;
}
int fd_rent_state_encode( fd_rent_state_t const * self, fd_bincode_encode_ctx_t * ctx ) {
  int err = fd_bincode_uint32_encode( self->discriminant, ctx );
  if( FD_UNLIKELY( err ) ) return err;
  return fd_rent_state_inner_encode( &self->inner, self->discriminant, ctx );
}

#define REDBLK_T fd_clock_timestamp_vote_t_mapnode_t
#define REDBLK_NAME fd_clock_timestamp_vote_t_map
#define REDBLK_IMPL_STYLE 2
#include "../../util/tmpl/fd_redblack.c"
long fd_clock_timestamp_vote_t_map_compare( fd_clock_timestamp_vote_t_mapnode_t * left, fd_clock_timestamp_vote_t_mapnode_t * right ) {
  return memcmp( left->elem.pubkey.uc, right->elem.pubkey.uc, sizeof(right->elem.pubkey) );
}
#define REDBLK_T fd_vote_reward_t_mapnode_t
#define REDBLK_NAME fd_vote_reward_t_map
#define REDBLK_IMPL_STYLE 2
#include "../../util/tmpl/fd_redblack.c"
long fd_vote_reward_t_map_compare( fd_vote_reward_t_mapnode_t * left, fd_vote_reward_t_mapnode_t * right ) {
  return memcmp( left->elem.pubkey.uc, right->elem.pubkey.uc, sizeof(right->elem.pubkey) );
}
#define REDBLK_T fd_account_costs_pair_t_mapnode_t
#define REDBLK_NAME fd_account_costs_pair_t_map
#define REDBLK_IMPL_STYLE 2
#include "../../util/tmpl/fd_redblack.c"
long fd_account_costs_pair_t_map_compare( fd_account_costs_pair_t_mapnode_t * left, fd_account_costs_pair_t_mapnode_t * right ) {
  return memcmp( left->elem.key.uc, right->elem.key.uc, sizeof(right->elem.key) );
}
#include "fd_types_custom.c"
