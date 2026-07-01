#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_const_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_const_h

#include "../leaders/fd_leaders.h"
#include "../../ballet/txn/fd_txn.h" /* for fd_acct_addr_t */
#include "../vm/fd_vm_base.h" /* fd_vm_trace_t */

FD_PROTOTYPES_BEGIN

#define FD_RUNTIME_MAX_FORK_CNT (4096UL)

/* FD_RUNTIME_MAX_{STAKE,VOTE}_ACCOUNTS are the maximum number of stake
   and vote accounts that the system supports: anything larger will
   result in a crash. The bounds were set with the intention of making a
   dos vector to mint stake/vote accounts financially infeasible.  A
   reasonable value to guard against this attack is roughly 550,000 SOL.

   For vote accounts, the limit is set to 19,000,000 because the rent
   exempt reserve of creating a valid vote account is ~0.03 SOL.  For
   each vote account, it also must be staked.  Each stake account has a
   rent exempt value of ~0.022 SOL.  This means the cost of minting 20M
   vote accounts is:
   19,000,000 accounts * 0.02685 SOL = 510,150 SOL.
   19,000,000 accounts * 0.00228 SOL = 43,320 SOL.
   Total cost: 553,470 SOL.
   In reality, the cost is slightly higher because of transaction fees
   and various CU costs to create the vote and stake accounts.

   For stake accounts, the rent exempt reserve is 0.00228 SOL.  However,
   new stake accounts must have a minimum balance of 1 SOL as of the
   feature upgrade_bpf_stake_program_to_v5.  Stake accounts created
   after the feature must have a balance of 1.00228 SOL.  To guard
   against a potential attack, we need to guard against the creation of
   550,000 SOL worth of stake accounts: 550,000 SOL / 1.00228 SOL =
   roughly 550,000 stake accounts.  In addition to the 1.6 million stake
   accounts which exist on mainnet today, we must support roughly 2.15
   million stake accounts. */

#define FD_RUNTIME_MAX_VOTE_ACCOUNTS  (19000000UL)
#define FD_RUNTIME_MAX_STAKE_ACCOUNTS (2150000UL)

/* The expected stake and vote account values are based on observed
   values on mainnet and testnet allowing for some growth.  These are
   chosen to size various caches and maps: they are not intended to be
   exact as they are not consensus critical values. */

#define FD_RUNTIME_EXPECTED_STAKE_ACCOUNTS (2150000UL)
#define FD_RUNTIME_EXPECTED_VOTE_ACCOUNTS  (16384UL)

#define FD_RUNTIME_SLOTS_PER_EPOCH    (432000UL)  /* 432k slots per epoch */

#define FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT (2000UL)

/* Maximum amount of writable accounts per transaction
   https://github.com/anza-xyz/agave/blob/v3.0.8/runtime/src/bank.rs#L2946 */
#define FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_TRANSACTION (64UL)

/* FD_RUNTIME_ACC_SZ_MAX is the protocol level hardcoded size limit of a
   Solana account. */

#define FD_RUNTIME_ACC_SZ_MAX (10UL<<20) /* 10MiB */

/* FD_RUNTIME_ACC_DATA_GROWTH_MAX_PER_TXN is the protocol level hardcoded
   limit on the total account data growth (sum of resize deltas) across a
   single transaction.  Defined here (alongside FD_RUNTIME_ACC_SZ_MAX) so
   low-level size bounds can reference it; fd_borrowed_account.h's
   MAX_PERMITTED_ACCOUNT_DATA_ALLOCS_PER_TXN and fd_vm_private.h's
   FD_MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION are kept equal to this via
   static asserts in those headers. */

#define FD_RUNTIME_ACC_DATA_GROWTH_MAX_PER_TXN (2UL*FD_RUNTIME_ACC_SZ_MAX) /* 20MiB */

/* FD_RUNTIME_WRITABLE_ACCOUNTS_MAX is the protocol level hardcoded
   limit of writable accounts per transaction. */

#define FD_RUNTIME_WRITABLE_ACCOUNTS_MAX (64UL)

/* Genesis creation times for major Solana clusters */

#define FD_RUNTIME_GENESIS_CREATION_TIME_MAINNET (1584368940UL)
#define FD_RUNTIME_GENESIS_CREATION_TIME_TESTNET (1580834132UL)
#define FD_RUNTIME_GENESIS_CREATION_TIME_DEVNET  (1597081016UL)

/* FeeStructure constants. Bank is always initialized with
   `FeeStructure::default()`
   https://github.com/anza-xyz/agave/blob/v3.1.0-beta.0/runtime/src/bank.rs#L1859
   https://github.com/anza-xyz/solana-sdk/blob/badc2c40071e6e7f7a8e8452b792b66613c5164c/fee-structure/src/lib.rs#L100 */
#define FD_RUNTIME_FEE_STRUCTURE_LAMPORTS_PER_SIGNATURE (5000UL)

/* Various constant values used by the runtime. */

#define MICRO_LAMPORTS_PER_LAMPORT (1000000UL)

#define DEFAULT_HASHES_PER_TICK  (12500)
#define UPDATED_HASHES_PER_TICK2 (17500)
#define UPDATED_HASHES_PER_TICK3 (27500)
#define UPDATED_HASHES_PER_TICK4 (47500)
#define UPDATED_HASHES_PER_TICK5 (57500)
#define UPDATED_HASHES_PER_TICK6 (62500)
#define FD_RUNTIME_MAX_HASHES_PER_TICK ((ulong)UPDATED_HASHES_PER_TICK6)

#define SECONDS_PER_YEAR ((double)(365.242199 * 24.0 * 60.0 * 60.0))

/* https://github.com/anza-xyz/agave/blob/0d34a1a160129c4293dac248e14231e9e773b4ce/program-runtime/src/compute_budget.rs#L139 */
#define FD_MAX_INSTRUCTION_TRACE_LENGTH (64UL)
/* https://github.com/anza-xyz/agave/blob/f70ab5598ccd86b216c3928e4397bf4a5b58d723/compute-budget/src/compute_budget.rs#L13 */
#define FD_MAX_INSTRUCTION_STACK_DEPTH  (5UL)


#define FD_RUNTIME_VM_TRACE_EVENT_MAX      (128UL<<20)
#define FD_RUNTIME_VM_TRACE_EVENT_DATA_MAX (2048UL)

#define FD_RUNTIME_VM_TRACE_STATIC_FOOTPRINT (FD_RUNTIME_VM_TRACE_EVENT_MAX + sizeof(fd_vm_trace_t))
#define FD_RUNTIME_VM_TRACE_STATIC_ALIGN     (8UL)

/* Maximum CPI instruction data size. 10 KiB was chosen to ensure that
   CPI instructions are not more limited than transaction instructions
   if the size of transactions is doubled in the future.
   https://github.com/anza-xyz/agave/blob/v3.1.1/transaction-context/src/lib.rs#L33 */
#define FD_RUNTIME_CPI_MAX_INSTR_DATA_LEN (10240UL)

/* The bpf loader's serialization footprint (the size of the per-stack-
   frame input region buffer) is bounded by FD_BPF_LOADER_INPUT_REGION_
   FOOTPRINT / BPF_LOADER_SERIALIZATION_FOOTPRINT below; see the comment
   there for the derivation.  Briefly: per-account fixed overhead
   (metadata + per-account resize headroom + alignment) for up to 64
   unique accounts, plus the total account-data body bounded once by the
   per-transaction loaded-data cap (64 MiB) plus the per-transaction data
   growth cap (20 MiB), plus instruction/program-id/pointer-array
   trailers.  This is far tighter than the previous 64 * 10MiB worst
   case, which assumed all 64 accounts could simultaneously be at the
   per-account max size (the loaded-data + growth caps make that
   impossible). */
#define MAX_PERMITTED_DATA_INCREASE (10240UL) // 10KB
#define FD_BPF_ALIGN_OF_U128        (8UL)
#define FD_ACCOUNT_REC_ALIGN        (8UL)
/* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/ebpf.rs#L37-L38 */
#define FD_RUNTIME_EBPF_HOST_ALIGN  (16UL)

/* FD_INSTR_ACCT_MAX is the maximum number of accounts that can
   be referenced by a single instruction.

   This is different from FD_BPF_INSTR_ACCT_MAX, which is enforced by the
   BPF serializer. It is possible to pass in more than FD_BPF_INSTR_ACCT_MAX
   instruction accounts in a transaction (for example mainnet transaction)
   3eDdfZE6HswPxFKrtnQPsEmTkyL1iP57gRPEXwaqNGAqF1paGXCYYMwh7z4uQDUMgFor742sikVSQZW1gFRDhPNh).

   A transaction like this will be loaded and sanitized, but will fail in the
   bpf serialization stage. It is also possible to invoke a native program with
   more than FD_BPF_INSTR_ACCT_MAX instruction accounts that will execute successfully.

   Therefore we need to derive a bound from a worst-case transaction: one that
   has the maximum possible number of instruction accounts at the expense of
   everything else. This is a legacy transaction with a single account address,
   a single signature, a single instruction with empty data and as many
   instruction accounts as possible.

   Therefore, the maximum number of instruction accounts is:
     (MTU - fixed overhead) / (size of instruction account)
   = (MTU
       - signature count (1 byte, value=1)
       - signature (64 bytes)
       - signature count in header (1 byte)
       - readonly signed count (1 byte)
       - readonly unsigned count (1 byte)
       - account count (1 byte, compact-u16 value=1)
       - 1 account address (32 bytes)
       - recent blockhash (32 bytes)
       - instruction count (1 byte, compact-u16 value=1)
       - program id index (1 byte)
       - instruction account count (2 bytes)
       - data len (1 byte, value=0)
   = 1232 - 1 - 64 - 1 - 1 - 1 - 1 - 32 - 32 - 1 - 1 - 2 - 1
   = 1094

   TODO: SIMD-406 (https://github.com/solana-foundation/solana-improvement-documents/pull/406)
   limits the number of instruction accounts to 255 in transaction sanitization.

   Once the corresponding feature gate has been activated, we can reduce
   FD_INSTR_ACCT_MAX to 255. We cannot reduce this before as this would cause
   the result of the get_processed_sibling_instruction syscall to diverge from
   Agave. */
#define FD_INSTR_ACCT_MAX           (1094UL)

/* FD_BPF_INSTR_ACCT_MAX is the maximum number of accounts that
   an instruction that goes through the bpf loader serializer can reference.

   The BPF loader has a lower limit for the number of instruction accounts
   than is enforced in transaction sanitization.

   TODO: remove this limit once SIMD-406 is activated, as we can then use the
   same limit everywhere.

   https://github.com/anza-xyz/agave/blob/v3.1.4/transaction-context/src/lib.rs#L30-L32 */
#define FD_BPF_INSTR_ACCT_MAX       (255UL)

/* FD_BPF_LOADER_UNIQUE_ACCOUNT_FIXED_FOOTPRINT is the per-unique-account
   serialization overhead EXCLUDING the account's data body: the fixed
   metadata fields, plus the realloc headroom (MAX_PERMITTED_DATA_INCREASE)
   and the worst-case per-account alignment padding (FD_BPF_ALIGN_OF_U128).
   The account data body itself is bounded separately, at the region level,
   by the per-transaction loaded-accounts-data cap (see below). */
#define FD_BPF_LOADER_UNIQUE_ACCOUNT_FIXED_FOOTPRINT                                                                                                        \
                                              (1UL                         /* dup byte          */                                                        + \
                                               sizeof(uchar)               /* is_signer         */                                                        + \
                                               sizeof(uchar)               /* is_writable       */                                                        + \
                                               sizeof(uchar)               /* executable        */                                                        + \
                                               sizeof(uint)                /* original_data_len */                                                        + \
                                               sizeof(fd_pubkey_t)         /* key               */                                                        + \
                                               sizeof(fd_pubkey_t)         /* owner             */                                                        + \
                                               sizeof(ulong)               /* lamports          */                                                        + \
                                               sizeof(ulong)               /* data len          */                                                        + \
                                               FD_BPF_ALIGN_OF_U128        /* per-account data alignment padding */                                       + \
                                               MAX_PERMITTED_DATA_INCREASE /* realloc headroom (additive to loaded size) */                               + \
                                               sizeof(ulong))              /* rent_epoch        */
#define FD_BPF_LOADER_DUPLICATE_ACCOUNT_FOOTPRINT (8UL) /* 1 dup byte + 7 bytes for padding */

/* FD_BPF_LOADER_INPUT_REGION_FOOTPRINT bounds the bytes a single
   instruction can serialize into one input region.

   The account data bodies are NOT bounded by account_lock_limit *
   FD_RUNTIME_ACC_SZ_MAX (64 * 10 MiB = 640 MiB): a transaction is
   rejected before execution (and therefore before serialization) if the
   sum of its loaded account data exceeds
   FD_VM_LOADED_ACCOUNTS_DATA_SIZE_LIMIT (see
   fd_executor_load_transaction_accounts ->
   fd_increase_calculated_data_size, called from
   fd_runtime_pre_execute_check before fd_execute_txn).  An instruction
   serializes a subset of the transaction's (<= account_lock_limit
   unique) accounts, each unique account's data copied at most once (dups
   cost 8 bytes).

   However, a program may GROW account data during execution before a
   later instruction (or CPI) re-serializes it.  Total account-data
   growth across a transaction is itself capped, at
   FD_RUNTIME_ACC_DATA_GROWTH_MAX_PER_TXN (== fd_borrowed_account.h's
   MAX_PERMITTED_ACCOUNT_DATA_ALLOCS_PER_TXN, which fd_borrowed_account.c
   enforces by rejecting any resize that pushes accounts_resize_delta
   over the cap).  So the worst-case account-data body serialized by any
   one instruction is bounded by

     FD_VM_LOADED_ACCOUNTS_DATA_SIZE_LIMIT          (initial loaded data)
   + FD_RUNTIME_ACC_DATA_GROWTH_MAX_PER_TXN         (max growth this txn)

   i.e. 64 MiB + 20 MiB = 84 MiB.  We charge the data bodies once at the
   region level with that combined bound, plus the fixed per-account
   overhead (metadata + per-account realloc headroom + alignment).

   When direct_mapping is enabled the data body is mapped rather than
   copied, so it costs nothing in this buffer at all. */
#define FD_BPF_LOADER_INPUT_REGION_FOOTPRINT(account_lock_limit, direct_mapping)                                                                          \
                                              (FD_ULONG_ALIGN_UP( (sizeof(ulong)                      /* acct_cnt       */                          +     \
                                                                   account_lock_limit*FD_BPF_LOADER_UNIQUE_ACCOUNT_FIXED_FOOTPRINT                  +     \
                                                                   ((direct_mapping) ? 0UL : ((ulong)FD_VM_LOADED_ACCOUNTS_DATA_SIZE_LIMIT +              \
                                                                                              (ulong)FD_RUNTIME_ACC_DATA_GROWTH_MAX_PER_TXN))       +     \
                                                                   (FD_BPF_INSTR_ACCT_MAX-account_lock_limit)*FD_BPF_LOADER_DUPLICATE_ACCOUNT_FOOTPRINT + \
                                                                   sizeof(ulong)                      /* instr data len */                          +     \
                                                                   FD_RUNTIME_CPI_MAX_INSTR_DATA_LEN  /* instr data  */                             +     \
                                                                   sizeof(fd_pubkey_t)                /* program id     */                          +     \
                                                                   (FD_BPF_ALIGN_OF_U128-1UL) +                                                           \
                                                                   FD_BPF_INSTR_ACCT_MAX*sizeof(ulong) /* direct_account_pointers_in_program_input */),   \
                                                                   FD_RUNTIME_EBPF_HOST_ALIGN ))



#define BPF_LOADER_SERIALIZATION_FOOTPRINT (FD_BPF_LOADER_INPUT_REGION_FOOTPRINT(64UL, 0))

/* FD_SYSVAR_INSTRUCTIONS_FOOTPRINT bounds the worst-case serialized
   size of the sysvar instructions account.  See
   fd_sysvar_instructions.c for the format.  Worst case:
     - 2 bytes header (num_instructions)
     - FD_TXN_INSTR_MAX * 2 = 128 bytes (instruction offsets)
     - per-instr fixed: 2 (num_accounts) + 32 (program_id) + 2 (data_len)
       = 36 bytes * FD_TXN_INSTR_MAX (64) = 2304 bytes
     - per-acct ref: 33 bytes * FD_INSTR_ACCT_MAX (1094) = 36102 bytes
     - instr data total: bounded by FD_TXN_MTU (1232 bytes)
     - 2 bytes tail (current_instr_idx)
   Total: 39770 bytes, rounded up to 40960. */
#define FD_SYSVAR_INSTRUCTIONS_FOOTPRINT (40960UL)

#define FD_HARD_FORKS_MAX (64UL)

/* Snapshot manifest array bounds.  They are used to size arrays and
   validate parsed lengths throughout the entire architecture. */

#define FD_VOTE_ACCOUNTS_MAX     (40200UL)
#define FD_STAKE_DELEGATIONS_MAX FD_RUNTIME_MAX_STAKE_ACCOUNTS
#define FD_EPOCH_STAKES_LEN      (3UL)


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_const_h */
