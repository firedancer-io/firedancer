#ifndef HEADER_fd_src_flamenco_runtime_tests_harness_fd_harness_common_h
#define HEADER_fd_src_flamenco_runtime_tests_harness_fd_harness_common_h

#include <assert.h>

#include "../../fd_runtime.h"
#include "generated/context.pb.h"

/* fd_runtime_fuzz_runner_t provides a funk instance and spad, generic
   for all harnesses. */

struct fd_runtime_fuzz_runner {
  fd_funk_t   funk[1];
  fd_wksp_t * wksp;
  fd_spad_t * spad;
  fd_bank_t * bank;
};
typedef struct fd_runtime_fuzz_runner fd_runtime_fuzz_runner_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

ulong
fd_runtime_fuzz_runner_align( void );

ulong
fd_runtime_fuzz_runner_footprint( void );

/* fd_runtime_fuzz_runner_new formats two memory regions, one for use as
   a fuzzing context object and another for an spad. `mem` must be part
   of an fd_wksp and hold memory for both the runner and a funk
   instance. Does additional wksp allocs. wksp_tag is the tag used for
   wksp allocs managed by the runner. The runner also takes in a
   initialized bank object. This bnak reused for each iteration of the
   fuzzer. Returns newly created runner on success. On failure, returns
   NULL and logs reason for error. */

fd_runtime_fuzz_runner_t *
fd_runtime_fuzz_runner_new( void *      mem,
                            void *      spad_mem,
                            fd_bank_t * bank,
                            ulong       wksp_tag );

/* fd_runtime_fuzz_runner_delete frees wksp allocations managed by
   runner and returns the memory region backing runner itself back to
   the caller. */

void *
fd_runtime_fuzz_runner_delete( fd_runtime_fuzz_runner_t * runner );

/* Context setup helpers */

/* Creates / overwrites an account in funk given an input account state.
   On success, loads the account into `acc`. Optionally, reject any zero-lamport
   accounts from being loaded in. */
int
fd_runtime_fuzz_load_account( fd_txn_account_t *                acc,
                              fd_funk_t *                       funk,
                              fd_funk_txn_t *                   funk_txn,
                              fd_exec_test_acct_state_t const * state,
                              uchar                             reject_zero_lamports );

/* Activates features in the runtime given an input feature set. Fails if a passed-in feature
   is unknown / not supported. */
int
fd_runtime_fuzz_restore_features( fd_features_t *                    features,
                                  fd_exec_test_feature_set_t const * feature_set );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_harness_fd_harness_common_h */
