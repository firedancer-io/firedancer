#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_block_harness_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_block_harness_h

#include "../../fd_executor.h"
#include "../../program/fd_vote_program.h"
#include "../../program/fd_stake_program.h"
#include "../../sysvar/fd_sysvar_epoch_schedule.h"
#include "../../sysvar/fd_sysvar_recent_hashes.h"
#include "../../../rewards/fd_rewards.h"

#include "fd_harness_common.h"
#include "fd_txn_harness.h"
#include "generated/block.pb.h"

/* TODO: We should decide how many workers to use for the execution tpool. We might have a bunch of
   transactions within a single block, but increasing the worker cnt increases the memory requirements by
   1 GB per additional worker (for spad memory allocation). We also fuzz block execution using
   multiple cores, so it may be possible to get away with only 1 worker. Additionally, Agave will more than
   likely always be the execution speed bottleneck, so we can play around with numbers and see what yields
   the best results. */
#define FD_BLOCK_HARNESS_TPOOL_WORKER_CNT (2UL)
#define FD_BLOCK_HARNESS_MEM_PER_SPAD     (1UL << 30)

FD_PROTOTYPES_BEGIN

/*
   Executes a block containing zero or more transactions.
   - All sysvars must be provided
   - This does not test sigverify or POH
   - Epoch boundaries are tested
   - Tested Firedancer code is `fd_runtime_block_execute_tpool()` and `fd_runtime_process_new_epoch()`
   - Associated entrypoint tested in Agave is `confirm_slot_entries` (except sigverify and verify_ticks are removed)
   - (idk about this yet) Recent blockhashes sysvar account must NOT be provided in the input account states.
     Instead, the sysvar is populated through the input blockhash queue.
*/
ulong
fd_runtime_fuzz_block_run( fd_runtime_fuzz_runner_t * runner,
                           void const *               input_,
                           void **                    output_,
                           void *                     output_buf,
                           ulong                      output_bufsz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_block_harness_h */
