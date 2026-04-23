// This is an auto-generated file. To add entries, edit fd_types.json
#ifndef HEADER_FD_RUNTIME_TYPES
#define HEADER_FD_RUNTIME_TYPES

#include "fd_bincode.h"
#include "fd_types_custom.h"

/* https://github.com/solana-program/stake/blob/330d89c6246ab3fd35d02803386fa700be0455d6/interface/src/stake_history.rs#L17 */
/* Encoded Size: Fixed (24 bytes) */
struct fd_stake_history_entry {
  ulong effective;
  ulong activating;
  ulong deactivating;
};
typedef struct fd_stake_history_entry fd_stake_history_entry_t;
#define FD_STAKE_HISTORY_ENTRY_ALIGN alignof(fd_stake_history_entry_t)

/* https://github.com/solana-program/stake/blob/330d89c6246ab3fd35d02803386fa700be0455d6/interface/src/stake_history.rs#L66 */
/* Encoded Size: Fixed (32 bytes) */
struct fd_epoch_stake_history_entry_pair {
  ulong epoch;
  fd_stake_history_entry_t entry;
};
typedef struct fd_epoch_stake_history_entry_pair fd_epoch_stake_history_entry_pair_t;
#define FD_EPOCH_STAKE_HISTORY_ENTRY_PAIR_ALIGN alignof(fd_epoch_stake_history_entry_pair_t)

/* https://github.com/solana-program/stake/blob/330d89c6246ab3fd35d02803386fa700be0455d6/interface/src/stake_history.rs#L66 */
/* Encoded Size: Fixed (16392 bytes) */
struct fd_stake_history {
  ulong fd_stake_history_len;
  ulong fd_stake_history_size;
  ulong fd_stake_history_offset;
  fd_epoch_stake_history_entry_pair_t fd_stake_history[512];
};
typedef struct fd_stake_history fd_stake_history_t;
#define FD_STAKE_HISTORY_ALIGN alignof(fd_stake_history_t)

/* Encoded Size: Fixed (40 bytes) */
struct fd_slot_hash {
  ulong slot;
  fd_hash_t hash;
};
typedef struct fd_slot_hash fd_slot_hash_t;
#define FD_SLOT_HASH_ALIGN alignof(fd_slot_hash_t)

#define DEQUE_NAME deq_fd_slot_hash_t
#define DEQUE_T fd_slot_hash_t
#include "../../util/tmpl/fd_deque_dynamic.c"
#undef DEQUE_NAME
#undef DEQUE_T
#undef DEQUE_MAX
static inline fd_slot_hash_t *
deq_fd_slot_hash_t_join_new( void * * alloc_mem, ulong max ) {
  if( FD_UNLIKELY( 0 == max ) ) max = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, deq_fd_slot_hash_t_align() );
  void * deque_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + deq_fd_slot_hash_t_footprint( max );
  return deq_fd_slot_hash_t_join( deq_fd_slot_hash_t_new( deque_mem, max ) );
}

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_hashes.rs#L31 */
/* Encoded Size: Dynamic */
struct fd_slot_hashes {
  fd_slot_hash_t * hashes; /* fd_deque_dynamic (min cnt 512) */
};
typedef struct fd_slot_hashes fd_slot_hashes_t;
#define FD_SLOT_HASHES_ALIGN alignof(fd_slot_hashes_t)

struct fd_slot_hashes_global {
  ulong hashes_offset; /* fd_deque_dynamic (min cnt 512) */
};
typedef struct fd_slot_hashes_global fd_slot_hashes_global_t;
#define FD_SLOT_HASHES_GLOBAL_ALIGN alignof(fd_slot_hashes_global_t)

static FD_FN_UNUSED fd_slot_hash_t * fd_slot_hashes_hashes_join( fd_slot_hashes_global_t * type ) { // deque
  return type->hashes_offset ? (fd_slot_hash_t *)deq_fd_slot_hash_t_join( fd_type_pun( (uchar *)type + type->hashes_offset ) ) : NULL;
}

FD_PROTOTYPES_BEGIN

static inline void fd_stake_history_entry_new( fd_stake_history_entry_t * self ) { fd_memset( self, 0, sizeof(fd_stake_history_entry_t) ); }
int fd_stake_history_entry_encode( fd_stake_history_entry_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_stake_history_entry_size( fd_stake_history_entry_t const * self ) { (void)self; return 24UL; }
static inline ulong fd_stake_history_entry_align( void ) { return FD_STAKE_HISTORY_ENTRY_ALIGN; }
static inline int fd_stake_history_entry_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_stake_history_entry_t);
  if( (ulong)ctx->data + 24UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_stake_history_entry_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_epoch_stake_history_entry_pair_new( fd_epoch_stake_history_entry_pair_t * self ) { fd_memset( self, 0, sizeof(fd_epoch_stake_history_entry_pair_t) ); }
int fd_epoch_stake_history_entry_pair_encode( fd_epoch_stake_history_entry_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_epoch_stake_history_entry_pair_size( fd_epoch_stake_history_entry_pair_t const * self ) { (void)self; return 32UL; }
static inline ulong fd_epoch_stake_history_entry_pair_align( void ) { return FD_EPOCH_STAKE_HISTORY_ENTRY_PAIR_ALIGN; }
static inline int fd_epoch_stake_history_entry_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_epoch_stake_history_entry_pair_t);
  if( (ulong)ctx->data + 32UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_epoch_stake_history_entry_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_stake_history_new( fd_stake_history_t * self );
int fd_stake_history_encode( fd_stake_history_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_stake_history_size( fd_stake_history_t const * self ) { (void)self; return 16392UL; }
static inline ulong fd_stake_history_align( void ) { return FD_STAKE_HISTORY_ALIGN; }
int fd_stake_history_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_stake_history_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_slot_hash_new( fd_slot_hash_t * self ) { fd_memset( self, 0, sizeof(fd_slot_hash_t) ); }
int fd_slot_hash_encode( fd_slot_hash_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_slot_hash_size( fd_slot_hash_t const * self ) { (void)self; return 40UL; }
static inline ulong fd_slot_hash_align( void ) { return FD_SLOT_HASH_ALIGN; }
static inline int fd_slot_hash_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_slot_hash_t);
  if( (ulong)ctx->data + 40UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_slot_hash_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_slot_hashes_new( fd_slot_hashes_t * self );
int fd_slot_hashes_encode( fd_slot_hashes_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_slot_hashes_size( fd_slot_hashes_t const * self );
static inline ulong fd_slot_hashes_align( void ) { return FD_SLOT_HASHES_ALIGN; }
int fd_slot_hashes_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_slot_hashes_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_slot_hashes_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_slot_hashes_encode_global( fd_slot_hashes_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_slot_hashes_size_global( fd_slot_hashes_global_t const * self );

FD_PROTOTYPES_END

#endif // HEADER_FD_RUNTIME_TYPES
