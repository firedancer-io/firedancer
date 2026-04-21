#ifndef HEADER_fd_src_flamenco_fd_flamenco_base_h
#define HEADER_fd_src_flamenco_fd_flamenco_base_h

#include "../ballet/base58/fd_base58.h"

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

struct fd_progcache;
typedef struct fd_progcache fd_progcache_t;

struct fd_runtime_stack;
typedef struct fd_runtime_stack fd_runtime_stack_t;

struct fd_vote_stakes;
typedef struct fd_vote_stakes fd_vote_stakes_t;

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

struct fd_top_votes;
typedef struct fd_top_votes fd_top_votes_t;

#define FD_EPOCH_CREDITS_MAX (64UL)
struct fd_epoch_credits {
  uchar  pubkey[32];
  ulong  cnt;
  ulong  base_credits;
  ushort epoch             [ FD_EPOCH_CREDITS_MAX ];
  uint   credits_delta     [ FD_EPOCH_CREDITS_MAX ];
  uint   prev_credits_delta[ FD_EPOCH_CREDITS_MAX ];
};
typedef struct fd_epoch_credits fd_epoch_credits_t;

struct fd_stashed_commission {
  uchar pubkey[32];
  uchar commission;
};
typedef struct fd_stashed_commission fd_stashed_commission_t;

FD_PROTOTYPES_BEGIN

/* fd_acct_addr_cstr converts the given Solana address into a base58-
   encoded cstr.  Returns cstr.  On return cstr contains a string with
   length in [32,44] (excluding NULL terminator). */

static inline char *
fd_acct_addr_cstr( char        cstr[ FD_BASE58_ENCODED_32_SZ ],
                   uchar const addr[ 32 ] ) {
  return fd_base58_encode_32( addr, NULL, cstr );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_fd_flamenco_base_h */
