#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_const_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_const_h

#include "../leaders/fd_leaders.h"
#include "../types/fd_types.h"
#include "../../ballet/txn/fd_txn.h" /* for fd_acct_addr_t */
#include "../vm/fd_vm_base.h" /* fd_vm_trace_t */

FD_PROTOTYPES_BEGIN

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

   For stake accounts, the limit is set to 241M because the rent exempt
   reserve of creating a valid stake account is
   241,000,000 accounts * 0.00228 SOL = 549,480 SOL.
   If you just consider the transaction fee of 0.000005 per account
   241,000,000 * 0.000005 = 1,205 SOL.
   This brings our total cost to 550,685 SOL. */

#define FD_RUNTIME_MAX_VOTE_ACCOUNTS  (19000000UL)
#define FD_RUNTIME_MAX_STAKE_ACCOUNTS (241000000UL)

/* The expected stake and vote account values are based on observed
   values on mainnet and testnet allowing for some growth.  These are
   chosen to size various caches and maps: they are not intended to be
   exact as they are not consensus critical values. */

#define FD_RUNTIME_EXPECTED_STAKE_ACCOUNTS (2000000UL)
#define FD_RUNTIME_EXPECTED_VOTE_ACCOUNTS  (16384UL)

#define FD_RUNTIME_SLOTS_PER_EPOCH    (432000UL)  /* 432k slots per epoch */

#define FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT (2000UL)

/* Maximum amount of writable accounts per transaction
   https://github.com/anza-xyz/agave/blob/v3.0.8/runtime/src/bank.rs#L2946 */
#define FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_TRANSACTION (64UL)

/* FD_RUNTIME_ACC_SZ_MAX is the protocol level hardcoded size limit of a
   Solana account. */

#define FD_RUNTIME_ACC_SZ_MAX (10UL<<20) /* 10MiB */

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

/* The bpf loader's serialization footprint is bounded in the worst case
   by 64 unique writable accounts which are each 10MiB in size (bounded
   by the amount of transaction accounts).  We can also have up to
   FD_BPF_INSTR_ACCT_MAX (255) referenced accounts in an instruction.

   - 8 bytes for the account count
   For each account:
     If duplicated:
       - 8 bytes for each duplicated account
    If not duplicated:
     - header for each unique account (96 bytes)
       - 1 account idx byte
       - 1 is_signer byte
       - 1 is_writable byte
       - 1 executable byte
       - 4 bytes for the original data length
       - 32 bytes for the key
       - 32 bytes for the owner
       - 8 bytes for the lamports
       - 8 bytes for the data length
       - 8 bytes for the rent epoch
     - 10MiB for the data (10485760 bytes)
     - 10240 bytes for resizing the data
     - 0 padding bytes because this is already 8 byte aligned
   - 8 bytes for instruction data length
   - 10240 bytes for the instruction data (CPI_MAX_INSTR_DATA_LEN)
   - 32 bytes for the program id

  So the total footprint is:
  8 header bytes +
  191 duplicate accounts (255 instr accounts - 64 unique accounts) * 8 bytes     = 1528      duplicate account bytes +
  64 unique accounts * (96 header bytes + 10485760 bytes + 10240 resizing bytes) = 671750144 unique account bytes +
  8 + 10240 + 32                                                                 = 10280     trailer bytes
  Subtotal: 671761960 bytes, aligned up to 16 = 671761968 bytes

  This is a reasonably tight-ish upper bound on the input region
  footprint for a single instruction at a single stack depth. */
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

#define FD_BPF_LOADER_UNIQUE_ACCOUNT_FOOTPRINT(direct_mapping)                                                                                              \
                                              (1UL                         /* dup byte          */                                                        + \
                                               sizeof(uchar)               /* is_signer         */                                                        + \
                                               sizeof(uchar)               /* is_writable       */                                                        + \
                                               sizeof(uchar)               /* executable        */                                                        + \
                                               sizeof(uint)                /* original_data_len */                                                        + \
                                               sizeof(fd_pubkey_t)         /* key               */                                                        + \
                                               sizeof(fd_pubkey_t)         /* owner             */                                                        + \
                                               sizeof(ulong)               /* lamports          */                                                        + \
                                               sizeof(ulong)               /* data len          */                                                        + \
                                               (direct_mapping ? FD_BPF_ALIGN_OF_U128 : FD_ULONG_ALIGN_UP( FD_RUNTIME_ACC_SZ_MAX, FD_BPF_ALIGN_OF_U128 )) + \
                                               MAX_PERMITTED_DATA_INCREASE                                                                                + \
                                               sizeof(ulong))              /* rent_epoch        */
#define FD_BPF_LOADER_DUPLICATE_ACCOUNT_FOOTPRINT (8UL) /* 1 dup byte + 7 bytes for padding */

#define FD_BPF_LOADER_INPUT_REGION_FOOTPRINT(account_lock_limit, direct_mapping)                                                                      \
                                              (FD_ULONG_ALIGN_UP( (sizeof(ulong)                      /* acct_cnt       */                          + \
                                                                   account_lock_limit*FD_BPF_LOADER_UNIQUE_ACCOUNT_FOOTPRINT(direct_mapping)        + \
                                                                   (FD_BPF_INSTR_ACCT_MAX-account_lock_limit)*FD_BPF_LOADER_DUPLICATE_ACCOUNT_FOOTPRINT + \
                                                                   sizeof(ulong)                      /* instr data len */                          + \
                                                                   FD_RUNTIME_CPI_MAX_INSTR_DATA_LEN  /* instr data  */                             + \
                                                                   sizeof(fd_pubkey_t)),              /* program id     */                            \
                                                                   FD_RUNTIME_EBPF_HOST_ALIGN ))



#define BPF_LOADER_SERIALIZATION_FOOTPRINT (671761968UL)
FD_STATIC_ASSERT( BPF_LOADER_SERIALIZATION_FOOTPRINT==FD_BPF_LOADER_INPUT_REGION_FOOTPRINT(64UL, 0), bpf_loader_serialization_footprint );

#define FD_EPOCH_CREDITS_MAX (64UL)

static const FD_FN_UNUSED fd_account_meta_t FD_ACCOUNT_META_DEFAULT = {0};

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_const_h */
