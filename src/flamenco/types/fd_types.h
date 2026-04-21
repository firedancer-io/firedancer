// This is an auto-generated file. To add entries, edit fd_types.json
#ifndef HEADER_FD_RUNTIME_TYPES
#define HEADER_FD_RUNTIME_TYPES

#include "fd_bincode.h"
#include "../../ballet/utf8/fd_utf8.h"
#include "fd_types_custom.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/fee_calculator.rs#L9 */
/* Encoded Size: Fixed (8 bytes) */
struct fd_fee_calculator {
  ulong lamports_per_signature;
};
typedef struct fd_fee_calculator fd_fee_calculator_t;
#define FD_FEE_CALCULATOR_ALIGN alignof(fd_fee_calculator_t)

/* Encoded Size: Fixed (16 bytes) */
struct fd_slot_pair {
  ulong slot;
  ulong val;
};
typedef struct fd_slot_pair fd_slot_pair_t;
#define FD_SLOT_PAIR_ALIGN alignof(fd_slot_pair_t)

/* Encoded Size: Dynamic */
struct fd_hard_forks {
  ulong hard_forks_len;
  fd_slot_pair_t * hard_forks;
};
typedef struct fd_hard_forks fd_hard_forks_t;
#define FD_HARD_FORKS_ALIGN alignof(fd_hard_forks_t)

struct fd_hard_forks_global {
  ulong hard_forks_len;
  ulong hard_forks_offset;
};
typedef struct fd_hard_forks_global fd_hard_forks_global_t;
#define FD_HARD_FORKS_GLOBAL_ALIGN alignof(fd_hard_forks_global_t)

FD_FN_UNUSED static fd_slot_pair_t * fd_hard_forks_hard_forks_join( fd_hard_forks_global_t const * struct_mem ) { // vector
  return struct_mem->hard_forks_offset ? (fd_slot_pair_t *)fd_type_pun( (uchar *)struct_mem + struct_mem->hard_forks_offset ) : NULL;
}
FD_FN_UNUSED static void fd_hard_forks_hard_forks_update( fd_hard_forks_global_t * struct_mem, fd_slot_pair_t * vec ) {
  struct_mem->hard_forks_offset = !!vec ? (ulong)vec - (ulong)struct_mem : 0UL;
}
/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/rent.rs#L11 */
/* Encoded Size: Fixed (17 bytes) */
struct fd_rent {
  ulong lamports_per_uint8_year;
  double exemption_threshold;
  uchar burn_percent;
};
typedef struct fd_rent fd_rent_t;
#define FD_RENT_ALIGN alignof(fd_rent_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/epoch_schedule.rs#L26 */
/* Encoded Size: Fixed (33 bytes) */
struct fd_epoch_schedule {
  ulong slots_per_epoch;
  ulong leader_schedule_slot_offset;
  uchar warmup;
  ulong first_normal_epoch;
  ulong first_normal_slot;
};
typedef struct fd_epoch_schedule fd_epoch_schedule_t;
#define FD_EPOCH_SCHEDULE_ALIGN alignof(fd_epoch_schedule_t)

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

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/slot_history.rs#L11 */
/* Encoded Size: Dynamic */
struct fd_slot_history {
  uchar has_bits;
  ulong bits_bitvec_len;
  ulong* bits_bitvec;
  ulong bits_len;
  ulong next_slot;
};
typedef struct fd_slot_history fd_slot_history_t;
#define FD_SLOT_HISTORY_ALIGN alignof(fd_slot_history_t)

struct fd_slot_history_global {
  uchar has_bits;
  ulong bits_bitvec_len;
  ulong bits_bitvec_offset;
  ulong bits_len;
  ulong next_slot;
};
typedef struct fd_slot_history_global fd_slot_history_global_t;
#define FD_SLOT_HISTORY_GLOBAL_ALIGN alignof(fd_slot_history_global_t)

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
/* Encoded Size: Fixed (40 bytes) */
struct fd_block_block_hash_entry {
  fd_hash_t blockhash;
  fd_fee_calculator_t fee_calculator;
};
typedef struct fd_block_block_hash_entry fd_block_block_hash_entry_t;
#define FD_BLOCK_BLOCK_HASH_ENTRY_ALIGN alignof(fd_block_block_hash_entry_t)

#define DEQUE_NAME deq_fd_block_block_hash_entry_t
#define DEQUE_T fd_block_block_hash_entry_t
#include "../../util/tmpl/fd_deque_dynamic.c"
#undef DEQUE_NAME
#undef DEQUE_T
#undef DEQUE_MAX
static inline fd_block_block_hash_entry_t *
deq_fd_block_block_hash_entry_t_join_new( void * * alloc_mem, ulong max ) {
  if( FD_UNLIKELY( 0 == max ) ) max = 1; // prevent underflow
  *alloc_mem = (void*)fd_ulong_align_up( (ulong)*alloc_mem, deq_fd_block_block_hash_entry_t_align() );
  void * deque_mem = *alloc_mem;
  *alloc_mem = (uchar *)*alloc_mem + deq_fd_block_block_hash_entry_t_footprint( max );
  return deq_fd_block_block_hash_entry_t_join( deq_fd_block_block_hash_entry_t_new( deque_mem, max ) );
}

/* Encoded Size: Dynamic */
struct fd_recent_block_hashes {
  fd_block_block_hash_entry_t * hashes; /* fd_deque_dynamic (min cnt 151) */
};
typedef struct fd_recent_block_hashes fd_recent_block_hashes_t;
#define FD_RECENT_BLOCK_HASHES_ALIGN alignof(fd_recent_block_hashes_t)

struct fd_recent_block_hashes_global {
  ulong hashes_offset; /* fd_deque_dynamic (min cnt 151) */
};
typedef struct fd_recent_block_hashes_global fd_recent_block_hashes_global_t;
#define FD_RECENT_BLOCK_HASHES_GLOBAL_ALIGN alignof(fd_recent_block_hashes_global_t)

static FD_FN_UNUSED fd_block_block_hash_entry_t * fd_recent_block_hashes_hashes_join( fd_recent_block_hashes_global_t * type ) { // deque
  return type->hashes_offset ? (fd_block_block_hash_entry_t *)deq_fd_block_block_hash_entry_t_join( fd_type_pun( (uchar *)type + type->hashes_offset ) ) : NULL;
}
/* Encoded Size: Dynamic */
struct fd_slot_meta {
  ulong slot;
  ulong consumed;
  ulong received;
  long first_shred_timestamp;
  ulong last_index;
  ulong parent_slot;
  ulong next_slot_len;
  ulong* next_slot;
  uchar is_connected;
};
typedef struct fd_slot_meta fd_slot_meta_t;
#define FD_SLOT_META_ALIGN alignof(fd_slot_meta_t)

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/sysvar/fees.rs#L21 */
/* Encoded Size: Fixed (8 bytes) */
struct fd_sysvar_fees {
  fd_fee_calculator_t fee_calculator;
};
typedef struct fd_sysvar_fees fd_sysvar_fees_t;
#define FD_SYSVAR_FEES_ALIGN alignof(fd_sysvar_fees_t)

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/sdk/program/src/epoch_rewards.rs#L14 */
/* Encoded Size: Fixed (81 bytes) */
struct fd_sysvar_epoch_rewards {
  ulong distribution_starting_block_height;
  ulong num_partitions;
  fd_hash_t parent_blockhash;
  fd_w_u128_t total_points;
  ulong total_rewards;
  ulong distributed_rewards;
  uchar active;
};
typedef struct fd_sysvar_epoch_rewards fd_sysvar_epoch_rewards_t;
#define FD_SYSVAR_EPOCH_REWARDS_ALIGN alignof(fd_sysvar_epoch_rewards_t)


FD_PROTOTYPES_BEGIN

static inline void fd_fee_calculator_new( fd_fee_calculator_t * self ) { fd_memset( self, 0, sizeof(fd_fee_calculator_t) ); }
int fd_fee_calculator_encode( fd_fee_calculator_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_fee_calculator_size( fd_fee_calculator_t const * self ) { (void)self; return 8UL; }
static inline ulong fd_fee_calculator_align( void ) { return FD_FEE_CALCULATOR_ALIGN; }
static inline int fd_fee_calculator_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_fee_calculator_t);
  if( (ulong)ctx->data + 8UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_fee_calculator_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_slot_pair_new( fd_slot_pair_t * self ) { fd_memset( self, 0, sizeof(fd_slot_pair_t) ); }
int fd_slot_pair_encode( fd_slot_pair_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_slot_pair_size( fd_slot_pair_t const * self ) { (void)self; return 16UL; }
static inline ulong fd_slot_pair_align( void ) { return FD_SLOT_PAIR_ALIGN; }
static inline int fd_slot_pair_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_slot_pair_t);
  if( (ulong)ctx->data + 16UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_slot_pair_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_hard_forks_new( fd_hard_forks_t * self );
int fd_hard_forks_encode( fd_hard_forks_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_hard_forks_size( fd_hard_forks_t const * self );
static inline ulong fd_hard_forks_align( void ) { return FD_HARD_FORKS_ALIGN; }
int fd_hard_forks_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_hard_forks_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_hard_forks_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_hard_forks_encode_global( fd_hard_forks_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_hard_forks_size_global( fd_hard_forks_global_t const * self );

static inline void fd_rent_new( fd_rent_t * self ) { fd_memset( self, 0, sizeof(fd_rent_t) ); }
int fd_rent_encode( fd_rent_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_rent_size( fd_rent_t const * self ) { (void)self; return 17UL; }
static inline ulong fd_rent_align( void ) { return FD_RENT_ALIGN; }
static inline int fd_rent_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_rent_t);
  if( (ulong)ctx->data + 17UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_rent_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_epoch_schedule_new( fd_epoch_schedule_t * self );
int fd_epoch_schedule_encode( fd_epoch_schedule_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_epoch_schedule_size( fd_epoch_schedule_t const * self ) { (void)self; return 33UL; }
static inline ulong fd_epoch_schedule_align( void ) { return FD_EPOCH_SCHEDULE_ALIGN; }
int fd_epoch_schedule_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_epoch_schedule_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

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

void fd_slot_history_new( fd_slot_history_t * self );
int fd_slot_history_encode( fd_slot_history_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_slot_history_size( fd_slot_history_t const * self );
static inline ulong fd_slot_history_align( void ) { return FD_SLOT_HISTORY_ALIGN; }
int fd_slot_history_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_slot_history_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_slot_history_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_slot_history_encode_global( fd_slot_history_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_slot_history_size_global( fd_slot_history_global_t const * self );

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

static inline void fd_block_block_hash_entry_new( fd_block_block_hash_entry_t * self ) { fd_memset( self, 0, sizeof(fd_block_block_hash_entry_t) ); }
int fd_block_block_hash_entry_encode( fd_block_block_hash_entry_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_block_block_hash_entry_size( fd_block_block_hash_entry_t const * self ) { (void)self; return 40UL; }
static inline ulong fd_block_block_hash_entry_align( void ) { return FD_BLOCK_BLOCK_HASH_ENTRY_ALIGN; }
static inline int fd_block_block_hash_entry_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_block_block_hash_entry_t);
  if( (ulong)ctx->data + 40UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_block_block_hash_entry_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_recent_block_hashes_new( fd_recent_block_hashes_t * self );
int fd_recent_block_hashes_encode( fd_recent_block_hashes_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_recent_block_hashes_size( fd_recent_block_hashes_t const * self );
static inline ulong fd_recent_block_hashes_align( void ) { return FD_RECENT_BLOCK_HASHES_ALIGN; }
int fd_recent_block_hashes_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_recent_block_hashes_decode( void * mem, fd_bincode_decode_ctx_t * ctx );
void * fd_recent_block_hashes_decode_global( void * mem, fd_bincode_decode_ctx_t * ctx );
int fd_recent_block_hashes_encode_global( fd_recent_block_hashes_global_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_recent_block_hashes_size_global( fd_recent_block_hashes_global_t const * self );

void fd_slot_meta_new( fd_slot_meta_t * self );
int fd_slot_meta_encode( fd_slot_meta_t const * self, fd_bincode_encode_ctx_t * ctx );
ulong fd_slot_meta_size( fd_slot_meta_t const * self );
static inline ulong fd_slot_meta_align( void ) { return FD_SLOT_META_ALIGN; }
int fd_slot_meta_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_slot_meta_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

static inline void fd_sysvar_fees_new( fd_sysvar_fees_t * self ) { fd_memset( self, 0, sizeof(fd_sysvar_fees_t) ); }
int fd_sysvar_fees_encode( fd_sysvar_fees_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_sysvar_fees_size( fd_sysvar_fees_t const * self ) { (void)self; return 8UL; }
static inline ulong fd_sysvar_fees_align( void ) { return FD_SYSVAR_FEES_ALIGN; }
static inline int fd_sysvar_fees_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz ) {
  *total_sz += sizeof(fd_sysvar_fees_t);
  if( (ulong)ctx->data + 8UL > (ulong)ctx->dataend ) { return FD_BINCODE_ERR_OVERFLOW; };
  return 0;
}
void * fd_sysvar_fees_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

void fd_sysvar_epoch_rewards_new( fd_sysvar_epoch_rewards_t * self );
int fd_sysvar_epoch_rewards_encode( fd_sysvar_epoch_rewards_t const * self, fd_bincode_encode_ctx_t * ctx );
static inline ulong fd_sysvar_epoch_rewards_size( fd_sysvar_epoch_rewards_t const * self ) { (void)self; return 81UL; }
static inline ulong fd_sysvar_epoch_rewards_align( void ) { return FD_SYSVAR_EPOCH_REWARDS_ALIGN; }
int fd_sysvar_epoch_rewards_decode_footprint( fd_bincode_decode_ctx_t * ctx, ulong * total_sz );
void * fd_sysvar_epoch_rewards_decode( void * mem, fd_bincode_decode_ctx_t * ctx );

FD_PROTOTYPES_END

#endif // HEADER_FD_RUNTIME_TYPES
