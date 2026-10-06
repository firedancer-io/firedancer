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

struct fd_txn_in;
typedef struct fd_txn_in fd_txn_in_t;

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

/* credits_delta/prev_credits_delta are stored as deltas from
   base_credits.  These are u64 (no longer u32). */

struct fd_epoch_credits {
  uchar  pubkey[32];
  ulong  base_credits;
  ushort epoch             [ FD_EPOCH_CREDITS_MAX ];
  ulong  credits_delta     [ FD_EPOCH_CREDITS_MAX ];
  ulong  prev_credits_delta[ FD_EPOCH_CREDITS_MAX ];
  ushort commission;
  /* cnt does not include the Alpenglow marker entry */
  uchar  cnt;
  uchar  fast_path_ok; /* True if the entries satisfy the boundary fast path prerequisites:
                          (1) initial[n]<=final[n], (2) initial[n]==final[n-1], and (3)
                          epoch[n]>=epoch[n-1].  Always true for production accounts written
                          by vote programs.  Points calculation takes the fast paths only
                          when true and the slow reference implementation otherwise.  So
                          synthetic fuzzer inputs fall back gracefully. */
  /* has_ag_migration_marker is 1 if the Alpenglow migration marker
     is present in the vote account's epoch credits, and 0 otherwise.
     This is only needed to correctly pay out rewards earnt during the
     Alpenglow migration epoch.

     The Alpenglow migration changes what epoch credit entries
     represent. Entries from before the migration are Tower credits,
     and entries from after are Alpenglow credits.

     During the migration epoch, vote accounts can earn both Tower
     credits before the migration slot and Alpenglow credits after.
     This means there can be two entries for the migration epoch, and
     if there is only one entry we don't know if it represents Tower
     credits or Alpenglow credits. The marker is used to disambiguate:
     entries from epochs before the marker are Tower credits, and
     entries at/after the marker are Alpenglow credits.

     It is also true that:
     - At most one entry per epoch is written in non-migration epochs.
     - At most one entry per epoch is written for Tower credits during
       the migration epoch.
     - At most one entry per epoch is written for Alpenglow credits
       during the migration epoch.
     - The marker is only written during the migration epoch, whilst
       crediting any Alpenglow credits earnt. If the vote account did
       not earn any Alpenglow credits during the migration epoch,
       there will never be a marker in its epoch credits.

     Therefore, we know that:
     - If the marker is not present and there is only 1 entry for the
       migration epoch, that entry must represent Tower credits
     - If the marker is present and there is only 1 entry for the
       migration epoch, that entry must represent Alpenglow credits
     - If the marker is present and there are 2 entries for the
       migration epoch, the first represents Tower credits and the
       second represents Alpenglow credits

    https://github.com/anza-xyz/agave/blob/v4.3.0/runtime/src/block_component_processor/vote_reward.rs#L532-L596 */
  uchar  has_ag_migration_marker;
};
typedef struct fd_epoch_credits fd_epoch_credits_t;

FD_STATIC_ASSERT( (ulong)UCHAR_MAX>=FD_EPOCH_CREDITS_MAX, cnt_width );
FD_STATIC_ASSERT( sizeof(fd_epoch_credits_t)==1200UL, fd_epoch_credits );

/* fd_epoch_credits_ag_marker_idx returns the index of the Alpenglow
   migration marker in the on-chain epoch credits state, given the
   epoch_credits and the migration epoch. This is so that our
   serialized epoch credits are Agave-compatible. */

static inline ulong
fd_epoch_credits_ag_marker_idx( fd_epoch_credits_t const * epoch_credits,
                                ulong                      ag_migration_epoch ) {
  if( FD_LIKELY( !epoch_credits->has_ag_migration_marker ) ) return ULONG_MAX;

  /* Find the last entry for the migration epoch - the marker goes
     immediately before this entry. */
  for( ulong i=epoch_credits->cnt; i; i-- ) {
    if( FD_UNLIKELY ((ulong)epoch_credits->epoch[ i-1UL ]==ag_migration_epoch )) {
      return i-1UL;
    }
  }

  /* If there is no entry for the migration epoch, the marker is the
     last entry. */
  return epoch_credits->cnt;
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
