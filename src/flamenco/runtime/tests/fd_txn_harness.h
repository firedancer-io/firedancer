#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_txn_harness_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_txn_harness_h

#include "fd_solfuzz.h"
#include "../../../disco/pack/fd_microblock.h"
#include "generated/txn.pb.h"

FD_PROTOTYPES_BEGIN

/* Serializes a Protobuf SanitizedTransaction that can be parsed into a
   txn descriptor and returns the number of bytes consumed. Returns
   ULONG_MAX if the number of bytes read exceeds 1232 (FD_TXN_MTU).
   _txn_raw_begin is assumed to be a pre-allocated buffer of at least
   1232 bytes. */
ulong
fd_solfuzz_pb_txn_serialize( uchar *                                      txn_raw_begin,
                             fd_exec_test_sanitized_transaction_t const * tx );

/* Takes in a parsed txn descriptor to be executed against the runtime.
   Returns the spad-allocated transaction context. Writes the execution
   result to the exec_res pointer (assumed to be pre-allocated). */
fd_exec_txn_ctx_t *
fd_solfuzz_txn_ctx_exec( fd_solfuzz_runner_t *     runner,
                         fd_funk_txn_xid_t const * xid,
                         fd_txn_p_t *              txn,
                         int *                     exec_res );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_txn_harness_h */
