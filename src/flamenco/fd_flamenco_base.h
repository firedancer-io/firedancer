#ifndef HEADER_fd_src_flamenco_fd_flamenco_base_h
#define HEADER_fd_src_flamenco_fd_flamenco_base_h

#include "../ballet/base58/fd_base58.h"

/* fd_w_u128 is a wrapped "uint128" type providing basic 128-bit
   unsigned int functionality even if the compile target does not
   natively support uint128. */

union __attribute__((packed)) fd_w_u128 {
  uchar uc[16];
  ulong ul[2];
# ifdef __SIZEOF_INT128__
  uint128 ud;
# endif
};

typedef union fd_w_u128 fd_w_u128_t;

/* 32-byte container */

#define FD_HASH_FOOTPRINT   (32UL)
#define FD_PUBKEY_FOOTPRINT FD_HASH_FOOTPRINT
union __attribute__((packed)) fd_hash {
  uchar hash[ FD_HASH_FOOTPRINT ];
  uchar key [ FD_HASH_FOOTPRINT ]; // Making fd_hash and fd_pubkey interchangeable

  // Generic type specific accessors
  ulong  ul  [ FD_HASH_FOOTPRINT / sizeof(ulong)  ];
  uint   ui  [ FD_HASH_FOOTPRINT / sizeof(uint)   ];
  ushort us  [ FD_HASH_FOOTPRINT / sizeof(ushort) ];
  uchar  uc  [ FD_HASH_FOOTPRINT                  ];
};
typedef union fd_hash fd_hash_t;
typedef union fd_hash fd_pubkey_t;

FD_FN_PURE static inline int
fd_hash_eq( fd_hash_t const * a,
            fd_hash_t const * b ) {
  return 0==memcmp( a, b, sizeof(fd_hash_t) );
}

FD_FN_PURE static inline int
fd_hash_eq1( fd_hash_t a,
             fd_hash_t b ) {
  return
    ( a.ul[0]==b.ul[0] ) & ( a.ul[1]==b.ul[1] ) &
    ( a.ul[2]==b.ul[2] ) & ( a.ul[3]==b.ul[3] );
}

FD_FN_PURE static inline int
fd_hash_check_zero( fd_hash_t const * _x ) {
  return !( (_x)->ul[0] | (_x)->ul[1] | (_x)->ul[2] | (_x)->ul[3] );
}

#define fd_pubkey_check_zero fd_hash_check_zero
#define fd_pubkey_eq         fd_hash_eq

/* 64-byte container */

union fd_signature {
  uchar uc[ 64 ];
  ulong ul[  8 ];
};
typedef union fd_signature fd_signature_t;

FD_FN_PURE static inline int
fd_signature_eq( fd_signature_t const * a,
                 fd_signature_t const * b ) {
  return 0==memcmp( a, b, sizeof(fd_signature_t) );
}

/* Forward declarations */

struct fd_bank;
typedef struct fd_bank fd_bank_t;

struct fd_banks;
typedef struct fd_banks fd_banks_t;

struct fd_exec_instr_ctx;
typedef struct fd_exec_instr_ctx fd_exec_instr_ctx_t;

struct fd_acc_mgr;
typedef struct fd_acc_mgr fd_acc_mgr_t;

struct fd_capture_ctx;
typedef struct fd_capture_ctx fd_capture_ctx_t;

struct fd_dump_proto_ctx;
typedef struct fd_dump_proto_ctx fd_dump_proto_ctx_t;

struct fd_txn_dump_ctx;
typedef struct fd_txn_dump_ctx fd_txn_dump_ctx_t;

struct fd_borrowed_account;
typedef struct fd_borrowed_account fd_borrowed_account_t;

union fd_features;
typedef union fd_features fd_features_t;

struct fd_epoch_schedule;
typedef struct fd_epoch_schedule fd_epoch_schedule_t;

struct fd_slot_params;
typedef struct fd_slot_params fd_slot_params_t;

struct fd_progcache;
typedef struct fd_progcache fd_progcache_t;

struct fd_runtime_stack;
typedef struct fd_runtime_stack fd_runtime_stack_t;

struct fd_runtime;
typedef struct fd_runtime fd_runtime_t;

struct fd_txn_in;
typedef struct fd_txn_in fd_txn_in_t;

struct fd_txn_out;
typedef struct fd_txn_out fd_txn_out_t;

struct fd_log_collector;
typedef struct fd_log_collector fd_log_collector_t;

struct fd_genesis;
typedef struct fd_genesis fd_genesis_t;

struct fd_stake_rewards;
typedef struct fd_stake_rewards fd_stake_rewards_t;

/* Misc types */

#define FD_EPOCH_CREDITS_MAX (64UL)

FD_FN_CONST static inline int
fd_epoch_credits_is_alpenglow_marker_raw( ulong epoch,
                                          ulong credits,
                                          ulong prev_credits ) {
  return epoch==ULONG_MAX && credits==ULONG_MAX && prev_credits==ULONG_MAX;
}

/* credits_delta/prev_credits_delta are stored as deltas from
   base_credits.  These are u64 (no longer u32). */

struct fd_epoch_credits {
  uchar  pubkey[32];
  ulong  base_credits;
  ushort epoch             [ FD_EPOCH_CREDITS_MAX ];
  ulong  credits_delta     [ FD_EPOCH_CREDITS_MAX ];
  ulong  prev_credits_delta[ FD_EPOCH_CREDITS_MAX ];
  ushort commission;
  uchar  cnt;
  uchar  marker_idx; /* UCHAR_MAX for an account that has not migrated.  Otherwise the
                        marker itself is not stored, and entries [0,marker_idx) are
                        tower-era credits while [marker_idx,cnt) are Alpenglow-era reward
                        lamports.  marker_idx==cnt means the marker was the newest entry,
                        i.e. the account migrated but has not recorded an Alpenglow entry
                        yet.  Every writer must set this. */
  uchar  fast_path_ok; /* True if the entries satisfy the boundary fast path prerequisites:
                          (1) initial[n]<=final[n], (2) initial[n]==final[n-1], and (3)
                          epoch[n]>=epoch[n-1].  Always true for production accounts written
                          by vote programs.  Points calculation takes the fast paths only
                          when true and the slow reference implementation otherwise.  So
                          synthetic fuzzer inputs fall back gracefully. */
};
typedef struct fd_epoch_credits fd_epoch_credits_t;

FD_STATIC_ASSERT( (ulong)UCHAR_MAX>=FD_EPOCH_CREDITS_MAX, cnt_width );
FD_STATIC_ASSERT( sizeof(fd_epoch_credits_t)==1200UL, fd_epoch_credits );
FD_STATIC_ASSERT( (ulong)UCHAR_MAX>FD_EPOCH_CREDITS_MAX, marker_idx_sentinel );

FD_FN_PURE static inline ulong
fd_epoch_credits_tower_cnt( fd_epoch_credits_t const * epoch_credits ) {
  return epoch_credits->marker_idx==UCHAR_MAX ? (ulong)epoch_credits->cnt : (ulong)epoch_credits->marker_idx;
}

static inline uchar
fd_epoch_credits_fast_path_ok( fd_epoch_credits_t const * epoch_credits ) {
  for( ulong i=0UL; i<epoch_credits->cnt; i++ ) {
    if( FD_UNLIKELY( epoch_credits->base_credits>ULONG_MAX-(ulong)epoch_credits->credits_delta[ i ] ) ) return 0;     /* no overflow/wrapping on any credits */
    if( FD_UNLIKELY( epoch_credits->prev_credits_delta[ i ]>epoch_credits->credits_delta[ i ] ) ) return 0;           /* (1) */
    if( FD_UNLIKELY( i && epoch_credits->prev_credits_delta[ i ]!=epoch_credits->credits_delta[ i-1UL ] ) ) return 0; /* (2) */
    if( FD_UNLIKELY( i && epoch_credits->epoch[ i ]<epoch_credits->epoch[ i-1UL ] ) ) return 0;                       /* (3) */
  }
  return 1;
}

struct fd_stashed_commission {
  uchar  pubkey[32];
  ushort commission;
};
typedef struct fd_stashed_commission fd_stashed_commission_t;

struct fd_hard_fork {
  ulong slot;
  ulong cnt; /* number of hard forks in that slot */
};
typedef struct fd_hard_fork fd_hard_fork_t;

FD_PROTOTYPES_BEGIN

struct fd_fee_rate_governor {
  ulong target_lamports_per_signature;
  ulong target_signatures_per_slot;
  ulong min_lamports_per_signature;
  ulong max_lamports_per_signature;
  uchar burn_percent;
};
typedef struct fd_fee_rate_governor fd_fee_rate_governor_t;

struct fd_inflation {
  double initial;
  double terminal;
  double taper;
  double foundation;
  double foundation_term;
  double unused;
};
typedef struct fd_inflation fd_inflation_t;

#endif /* HEADER_fd_src_flamenco_fd_flamenco_base_h */
