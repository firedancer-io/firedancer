#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_const_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_const_h

#include "sysvar/fd_sysvar_slot_hashes.h"
#include "sysvar/fd_sysvar_stake_history.h"
#include "../types/fd_types.h"
#include "../leaders/fd_leaders.h"
#include "../../ballet/sbpf/fd_sbpf_loader.h"

FD_PROTOTYPES_BEGIN

/* All of the variable bounds in the bank should be deteremined by the
   max number of vote accounts and stake accounts that the system
   supports. These are not protocol-level bounds, but rather bounds
   that are used to determine the max amount of memory that various
   data structures require. */

#define FD_RUNTIME_MAX_VOTE_ACCOUNTS  (40200UL)   /* ~40k vote accounts */

#define FD_RUNTIME_MAX_STAKE_ACCOUNTS (3000000UL) /* 3M stake accounts */

#define FD_RUNTIME_SLOTS_PER_EPOCH    (432000UL)  /* 432k slots per epoch */

/* Maximum amount of writable accounts per transaction */

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

struct fd_runtime_mem {
  uchar __attribute__((aligned(alignof(fd_vote_stake_weight_t)))) epoch_weights_mem[ FD_RUNTIME_MAX_VOTE_ACCOUNTS * sizeof(fd_vote_stake_weight_t) ];
  uchar __attribute__((aligned(FD_SBPF_SYSCALLS_ALIGN)))          syscalls_mem     [ FD_SBPF_SYSCALLS_FOOTPRINT ];
  uchar __attribute__((aligned(alignof(fd_sbpf_program_t))))      sbpf_program_mem [ FD_RUNTIME_ACC_SZ_MAX ]; /* FIXME: wait for sbpf rewrite constant */
  uchar __attribute__((aligned(128UL)))                           slot_hashes_mem  [ FD_SYSVAR_SLOT_HASHES_DECODE_FOOTPRINT ];
  uchar __attribute__((aligned(128UL)))                           clock_ts_pool_mem[ FD_RUNTIME_MAX_VOTE_ACCOUNTS * 64UL + 10000 ]; /* FIXME: calculate this properly */
  uchar __attribute__((aligned(alignof(fd_stake_history_t))))     stake_history_mem[ sizeof(fd_stake_history_t) ];
};
typedef struct fd_runtime_mem fd_runtime_mem_t;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_const_h */
