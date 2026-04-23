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
#include "fd_types_custom.c"
