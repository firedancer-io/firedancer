#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_harness_common_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_harness_common_h

/* fd_harness_common.h provides common utilities for all harnesses. */

#include "fd_solfuzz.h"
#include "../../features/fd_features.h"
#include "generated/context.pb.h"

FD_PROTOTYPES_BEGIN

/* Creates / overwrites an account in funk given an input account state.
   On success, loads the account into `acc`.  Optionally, reject any
   zero-lamport accounts from being loaded in. */
int
fd_runtime_fuzz_load_account( fd_txn_account_t *                acc,
                              fd_funk_t *                       funk,
                              fd_funk_txn_xid_t const *         xid,
                              fd_exec_test_acct_state_t const * state,
                              uchar                             reject_zero_lamports );

/* Activates features in the runtime given an input feature set.  Fails
   if a passed-in feature is unknown / not supported. */
int
fd_runtime_fuzz_restore_features( fd_features_t *                    features,
                                  fd_exec_test_feature_set_t const * feature_set );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_harness_common_h */
