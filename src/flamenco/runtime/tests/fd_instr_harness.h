#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_instr_harness_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_instr_harness_h

/* fd_instr_harness.h provides APIs for running instruction processor
   tests. */

#include "fd_solfuzz.h"
#include "generated/invoke.pb.h"

FD_PROTOTYPES_BEGIN

/* fd_solfuzz_pb_instr_ctx_create takes in a test runner and InstrCtx
   protobuf and creates an fd_exec_instr_ctx_t that can be used in
   runtime.

   Setting is_syscall avoids some operations/checks only relevant for
   program instructions.

   This function is infallible, it will abort with FD_LOG_ERR on
   invariant violations (malformed test inputs).

   Should be coupled with fd_solfuzz_pb_instr_ctx_destroy when the
   instr_ctx is no longer needed. */
void
fd_solfuzz_pb_instr_ctx_create( fd_solfuzz_runner_t *                runner,
                                fd_exec_instr_ctx_t *                ctx,
                                fd_exec_test_instr_context_t const * test_ctx,
                                bool                                 is_syscall );

/* Frees an instr_ctx created by fd_solfuzz_pb_instr_ctx_create */
void
fd_solfuzz_pb_instr_ctx_destroy( fd_solfuzz_runner_t * runner,
                                 fd_exec_instr_ctx_t * ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_instr_harness_h */
