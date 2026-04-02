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
FD_FN_PURE uchar fd_system_program_instruction_is_create_account_allow_prefund(fd_system_program_instruction_t const * self) {
  return self->discriminant == 13;
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
  case 13: {
    err = fd_system_program_instruction_create_account_decode_footprint_inner( ctx, total_sz );
    if( FD_UNLIKELY( err ) ) return err;
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
  case 13: {
    fd_system_program_instruction_create_account_decode_inner( &self->create_account_allow_prefund, alloc_mem, ctx );
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
  case 13: {
    fd_system_program_instruction_create_account_new( &self->create_account_allow_prefund );
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
  case 13: {
    size += fd_system_program_instruction_create_account_size( &self->inner.create_account_allow_prefund );
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
  case 13: {
    err = fd_system_program_instruction_create_account_encode( &self->create_account_allow_prefund, ctx );
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

#include "fd_types_custom.c"
