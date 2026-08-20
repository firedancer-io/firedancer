#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_const_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_const_h

#include "../../ballet/txn/fd_txn.h" /* for FD_TXN_ACCT_ADDR_MAX */
#include "../vm/fd_vm_base.h" /* fd_vm_trace_t */

FD_PROTOTYPES_BEGIN

#define FD_RUNTIME_MAX_FORK_CNT (4096UL)

/* FD_INSTR_SIGNERS_MAX: The (inclusive) maximum number of distinct
   signers a single instruction can have.

   This is the runtime bound, which is larger than the transaction
   parser bound because during CPI calls PDAs can be promoted to
   signers. Therefore in the runtime, the effective limit is the
   amount of distinct accounts the transaction can access. */
#define FD_INSTR_SIGNERS_MAX FD_TXN_ACCT_ADDR_MAX

/* FD_RUNTIME_MAX_STAKE_ACCOUNTS is the maximum number of stake accounts
   that the system supports: anything larger will result in a crash.
   The bounds were set with the intention of making a dos vector to mint
   stake accounts financially infeasible.  Similarly, the number of
   stake accounts that the system supports is also the maximum number of
   staked vote accounts that the system supports since in the worst case
   we have one stake account per vote account.

   Prior to the feature upgrade_bpf_stake_program_to_v5, which
   introduced the minimum 1 SOL delegation amount, there were 1.6
   million stake accounts on mainnet.  With a bound of 2.15 million
   stake accounts, this means an attacker would need roughly 0.75
   million SOL to attack the system which is a reasonable bound. */

#define FD_RUNTIME_MAX_STAKE_ACCOUNTS (2150000UL)

/* FD_RUNTIME_MAX_STAKE_ACCOUNTS_FALLBACK is the number of stake
   accounts that the system can support.  FD_RUNTIME_STAKE_ACCOUNTS is
   the measure of active stake accounts while _FALLBACK is the measure
   of total stake accounts that the network can support.  This is a
   measured and chosen threshold based on what the wider network on
   mainnet can reasonably support across clients and valdiator
   hardware. */

#define FD_RUNTIME_MAX_STAKE_ACCOUNTS_FALLBACK (100000000UL)

/* The runtime only supports post-validator_admission_ticket banks.  The
   accumulator can still see one distinct voter per stake account before
   the final eligible set is reduced to the VAT limit below. */

#define FD_RUNTIME_MAX_STAKED_VOTE_ACCOUNTS (FD_RUNTIME_MAX_STAKE_ACCOUNTS)

/* Maximum number of vote accounts eligible to receive rewards or
   meaningfully contribute to consensus after
   validator_admission_ticket activation. */

#define FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS (2000UL)

/* Bound on the snapshot manifest's vote account map, which holds
   every staked voter rather than only the VAT-admitted set.  Wait
   for supermajority is the sole consumer. */

#define FD_RUNTIME_MAX_SNAPSHOT_VOTE_ACCOUNTS (40200UL)

/* The maximum number of epoch stakes that are needed to be parsed out
   from the manifest.  Agave produced snapshots include 5 epoch stakes,
   but only 3 are required for consensus. */

#define FD_RUNTIME_MANIFEST_EPOCH_STAKES_LEN (3UL)

#define FD_RUNTIME_SLOTS_PER_EPOCH (432000UL)

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
/* https://github.com/anza-xyz/agave/blob/v4.2.0-beta.1/program-runtime/src/execution_budget.rs#L10 */
#define FD_MAX_INSTRUCTION_STACK_DEPTH_SIMD_0268 (9UL)


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

/* FD_SYSVAR_INSTRUCTIONS_FOOTPRINT bounds the worst-case serialized
   size of the sysvar instructions account.  See
   fd_sysvar_instructions.c for the format.

   Worst case size for V0/legacy transactions.  Each bullet is bounded by
   its own maximum; those maxima compete for the same 1232-byte tx and
   can't all be reached at once, so the sum is a deliberately loose
   over-estimate:
     - 2 bytes header (num_instructions)
     - instruction offsets: 2 bytes * FD_TXN_INSTR_MAX (64) = 128 bytes
     - per-instr fixed: 2 (num_accounts) + 32 (program_id) + 2 (data_len)
       = 36 bytes * FD_TXN_INSTR_MAX (64) = 2304 bytes
     - account refs: each takes 1 byte (an index) in the tx but serializes
       to 33 bytes (1 flag + 32-byte pubkey); a 1232-byte tx holds at most
       ~1094 indices across all its instructions, so 33 * 1094 = 36102 bytes
     - instr data: bounded by the legacy MTU FD_TXN_MTU_V0 (1232 bytes)
     - 2 bytes tail (current_instr_idx)
   Total: 39770 bytes

   Worst case size for V1 transactions:
   Instruction start offsets are u16, so an accepted sysvar has every
   offset <= 65535; a larger offset overflows and is rejected (matching
   agave).  The worst case is the last instruction starting at 65535:

     - 65535 bytes (offset of the last instruction)
     - per-acct ref: 33 bytes * 255 = 8415 bytes
     - per-instr fixed: 2 (num_accounts) + 32 (program_id) + 2 (data_len)
       = 36 bytes
     - instr data: bounded by FD_TXN_MTU (4096 bytes)
     - 2 bytes tail (current_instr_idx)
   Total: 78084 bytes, rounded up to 81920. */
#define FD_SYSVAR_INSTRUCTIONS_FOOTPRINT (81920UL)

/* FD_BPF_LOADER_INPUT_REGION_FOOTPRINT bounds the bytes a single
   instruction can serialize into one input region.

   The account data bodies are NOT bounded by account_lock_limit *
   FD_RUNTIME_ACC_SZ_MAX (64 * 10 MiB = 640 MiB): a transaction is
   rejected before execution (and therefore before serialization) if the
   sum of its loaded account data exceeds
   FD_VM_LOADED_ACCOUNTS_DATA_SIZE_LIMIT (see
   fd_executor_load_transaction_accounts ->
   fd_increase_calculated_data_size, called from
   fd_runtime_pre_execute_check before fd_execute_txn).  Note that this
   does not include the instructions sysvar, as this is not counted
   towards the loaded accounts data size limit.  An instruction
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
                                                                   FD_SYSVAR_INSTRUCTIONS_FOOTPRINT                                                 +     \
                                                                   (FD_TXN_INSTR_ACCT_MAX-account_lock_limit)*FD_BPF_LOADER_DUPLICATE_ACCOUNT_FOOTPRINT + \
                                                                   sizeof(ulong)                      /* instr data len */                          +     \
                                                                   FD_RUNTIME_CPI_MAX_INSTR_DATA_LEN  /* instr data  */                             +     \
                                                                   sizeof(fd_pubkey_t)                /* program id     */                          +     \
                                                                   (FD_BPF_ALIGN_OF_U128-1UL) +                                                           \
                                                                   FD_TXN_INSTR_ACCT_MAX*sizeof(ulong) /* direct_account_pointers_in_program_input */),   \
                                                                   FD_RUNTIME_EBPF_HOST_ALIGN ))



#define BPF_LOADER_SERIALIZATION_FOOTPRINT (FD_BPF_LOADER_INPUT_REGION_FOOTPRINT(64UL, 0))

#define FD_HARD_FORKS_MAX (64UL)

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_const_h */
