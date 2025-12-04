#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_const_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_const_h

#include "../leaders/fd_leaders.h"
#include "../types/fd_types.h"
#include "../../ballet/txn/fd_txn.h" /* for fd_acct_addr_t */
#include "../vm/fd_vm_base.h" /* fd_vm_trace_t */

FD_PROTOTYPES_BEGIN

/* All of the variable bounds in the bank should be deteremined by the
   max number of vote accounts and stake accounts that the system
   supports. These are not protocol-level bounds, but rather bounds
   that are used to determine the max amount of memory that various
   data structures require. */

#define FD_RUNTIME_MAX_VOTE_ACCOUNTS  (40200UL)   /* ~40k vote accounts */

#define FD_RUNTIME_MAX_STAKE_ACCOUNTS (3000000UL) /* 3M stake accounts */

#define FD_RUNTIME_SLOTS_PER_EPOCH    (432000UL)  /* 432k slots per epoch */

/* Maximum amount of writable accounts per transaction
   https://github.com/anza-xyz/agave/blob/v3.0.8/runtime/src/bank.rs#L2946 */
#define FD_RUNTIME_MAX_WRITABLE_ACCOUNTS_PER_TRANSACTION (64UL)

/* The initial block id hash is a dummy value for the initial block id
   as one is not provided in snapshots.  This does not have an
   equivalent in Agave.

   TODO: This should be removed in favor of repairing the last shred of
   the snapshot slot to get the actual block id of the snapshot slot. */

#define FD_RUNTIME_INITIAL_BLOCK_ID (0xF17EDA2CE7B1DUL)

/* The stake program is now a BPF program which means that there is a
   variable cost in CUs to execute the stake program.  This is the
   absolute minimum cost of executing the stake program.

   FIXME: This is a reasonable estimate based off of BPF withdraw
   instructions.  The hard bound still needs to be determined. */

#define FD_RUNTIME_MIN_STAKE_INSN_CUS (6000UL)

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

static const fd_cluster_version_t FD_RUNTIME_CLUSTER_VERSION = {
  .major = 3UL,
  .minor = 0UL,
  .patch = 3UL
};

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
   FD_INSTR_ACCT_MAX (256) referenced accounts in an instruction.

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
   - 1232 bytes for the instruction data (TXN_MTU)
   - 32 bytes for the program id

  So the total footprint is:
  8 header bytes +
  192 duplicate accounts (256 instr accounts - 64 unique accounts) * 8 bytes     = 1536      duplicate account bytes +
  64 unique accounts * (96 header bytes + 10485760 bytes + 10240 resizing bytes) = 671750144 unique account bytes +
  8 + 1232 + 32                                                                  = 1272 bytes trailer bytes + program id = 671751416 bytes
  Total footprint: 671752960 bytes

  This is a reasonably tight-ish upper bound on the input region
  footprint for a single instruction at a single stack depth.  In
  reality the footprint would be slightly smaller because the
  instruction data can't be equal to the transaction MTU.
 */
#define MAX_PERMITTED_DATA_INCREASE (10240UL) // 10KB
#define FD_BPF_ALIGN_OF_U128        (8UL)
#define FD_ACCOUNT_REC_ALIGN        (8UL)
/* https://github.com/anza-xyz/sbpf/blob/v0.12.2/src/ebpf.rs#L37-L38 */
#define FD_RUNTIME_EBPF_HOST_ALIGN  (16UL)
#define FD_INSTR_ACCT_MAX            (256)


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
                                              (FD_ULONG_ALIGN_UP( (sizeof(ulong)         /* acct_cnt       */                                       + \
                                                                   account_lock_limit*FD_BPF_LOADER_UNIQUE_ACCOUNT_FOOTPRINT(direct_mapping)        + \
                                                                   (FD_INSTR_ACCT_MAX-account_lock_limit)*FD_BPF_LOADER_DUPLICATE_ACCOUNT_FOOTPRINT + \
                                                                   sizeof(ulong)         /* instr data len */                                       + \
                                                                   FD_TXN_MTU            /* No instr data  */                                       + \
                                                                   sizeof(fd_pubkey_t)), /* program id     */                                          \
                                                                   FD_RUNTIME_EBPF_HOST_ALIGN ))



#define BPF_LOADER_SERIALIZATION_FOOTPRINT (671752960UL)
FD_STATIC_ASSERT( BPF_LOADER_SERIALIZATION_FOOTPRINT==FD_BPF_LOADER_INPUT_REGION_FOOTPRINT(64UL, 0), bpf_loader_serialization_footprint );


/* Some vote instruction types are dynamically sized:
    - tower_sync_switch                (contains deque of fd_vote_lockout_t)
    - tower_sync                       (contains deque of fd_vote_lockout_t)
    - compact_vote_state_update_switch (vector of fd_lockout_offset_t)
    - compact_vote_state_update        (vector of fd_lockout_offset_t)
    - authorize_checked_with_seed      (char vector of current_authority_derived_key_seed)
    - authorize_with_seed              (char vector of current_authority_derived_key_seed)
    - update_vote_state_switch         (contains deque of fd_vote_lockout_t)
    - update_vote_state                (contains deque of fd_vote_lockout_t)
    - vote_switch                      (deque of slot numbers)
    - vote                             (deque of slot numbers)
   All other vote instruction types are statically sized.

   A loose bound on the max amount of encoded fd_vote_lockout_t
   possible is 1232 bytes/(12 bytes/per lockout) = 102 lockouts.  So
   the worst case bound for the deque of fd_vote_lockout is
   32 + (102 * sizeof(fd_vote_lockout_t)) = 1644 bytes.

   The worst case vector of fd_lockout_offset_t is one where each
   encoded element is 2 bytes.  This means that we can have 1232/2 =
   616 elements.  They are represented as being 16 bytes each, so the
   total footprint would be 9856 bytes.

   The deque of slot numbers is a vector of ulong, which is 8 bytes.
   So the worst case is 1232 bytes/8 bytes = 154 elements.  So, the
   total footprint is 32 + (154 * 8 bytes) = 1264 bytes.

   The worst case char vector is 1232 bytes as each element is 1 byte
   up to the txn MTU.

   With this, that means that the compact_vote_state_update_switch
   can have the largest worst case footprint where the struct is
   104 bytes (sizeof(fd_compact_vote_state_update_switch_t) + the
   worst case lockout vector of 616 elements. */
#define FD_LOCKOUT_OFFSET_FOOTPRINT   (9856UL)
#define FD_VOTE_INSTRUCTION_FOOTPRINT (sizeof(fd_vote_instruction_t) + FD_LOCKOUT_OFFSET_FOOTPRINT)

/* TODO: This is the value as generated by fd_types bincode decoding of
   fd_vote_state_versioned_t.  This should eventually be replaced. */
#define FD_VOTE_STATE_VERSIONED_FOOTPRINT (9248UL)

/* The footprint of a fd_vote_authorized_voters_t struct is defined as a
   fd_vote_authorized_voters_t followed by a pool and then a treap. */
#define FD_AUTHORIZED_VOTERS_ALIGN     (128UL)
#define FD_AUTHORIZED_VOTERS_FOOTPRINT (4888UL)

/* TODO: These footprints are currently overprovisioned due to test
   fixtures which currently violate protocol invariants. */

/* The footprint of the landed votes is determined by a deque with max
   cnt of 31.  The footprint is as follows:
   alignof(DEQUE_T) == alignof(fd_landed_vote_t) == 8
   sizeof(DEQUE_T)  == sizeof(fd_landed_vote_t)  == 24
   return fd_ulong_align_up( fd_ulong_align_up( 32UL, alignof(DEQUE_T) ) + sizeof(DEQUE_T)*max, alignof(DEQUE_(private_t)) );
   return fd_ulong_align_up( fd_ulong_align_up( 32UL, 8UL ) )            + 24UL*31UL, 8UL );
   return fd_ulong_align_up( 32UL + 744, 8UL ) == 776 */
#define FD_LANDED_VOTES_ALIGN     (32UL)
#define FD_LANDED_VOTES_FOOTPRINT (FD_VOTE_STATE_VERSIONED_FOOTPRINT)

/* The calculation for the landed votes footprint is the same as the
   calculation for the landed votes but the sizeof(fd_vote_lockout_t)
   is 16 bytes:
   return fd_ulong_align_up( 32UL + 16UL * 31UL, 8UL ) == 528UL */
#define FD_VOTE_LOCKOUTS_ALIGN     (32UL)
#define FD_VOTE_LOCKOUTS_FOOTPRINT (FD_VOTE_STATE_VERSIONED_FOOTPRINT)

static FD_FN_UNUSED fd_account_meta_t FD_ACCOUNT_META_DEFAULT = {0};

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_const_h */
