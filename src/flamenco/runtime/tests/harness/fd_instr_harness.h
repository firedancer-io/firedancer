#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_instr_harness_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_instr_harness_h

/* fd_instr_harness.h provides APIs for running instruction processor
   tests. */

#include "fd_harness_common.h"

#include "../../fd_executor.h"
#include "../../program/fd_program_cache.h"
#include "../../context/fd_exec_slot_ctx.h"
#include "../../context/fd_exec_txn_ctx.h"
#include "../../program/fd_bpf_loader_program.h"
#include "../../../fd_flamenco.h"
#include "../../../fd_flamenco_base.h"
#include "../../../vm/fd_vm.h"
#include "../../../../funk/fd_funk.h"
#include "../../../../ballet/murmur3/fd_murmur3.h"
#include "../../../../ballet/sbpf/fd_sbpf_loader.h"

#include <assert.h>

#include "generated/invoke.pb.h"
#include "generated/txn.pb.h"
#include "generated/vm.pb.h"
#include "generated/block.pb.h"

FD_PROTOTYPES_BEGIN

/* fd_runtime_fuzz_instr_ctx_create takes in a test runner and InstrCtx protobuf
   and creates an fd_exec_instr_ctx_t that can be used in runtime.

   Setting is_syscall avoids some operations/checks only relevant for
   program instructions.

   Should be coupled with fd_exec_test_instr_context_destroy when the instr_ctx
   is no longer needed. */
int
fd_runtime_fuzz_instr_ctx_create( fd_runtime_fuzz_runner_t *           runner,
                                  fd_exec_instr_ctx_t *                ctx,
                                  fd_exec_test_instr_context_t const * test_ctx,
                                  bool                                 is_syscall );

/* Frees an instr_ctx created by fd_runtime_fuzz_instr_ctx_create */
void
fd_runtime_fuzz_instr_ctx_destroy( fd_runtime_fuzz_runner_t * runner,
                                   fd_exec_instr_ctx_t *      ctx );


/* User API */

/* fd_runtime_fuzz_instr_run executes a given instruction context (input)
   and returns the effects of executing that instruction to the caller.
   output_buf points to a memory region of output_bufsz bytes where the
   result is allocated into.  On successful execution, *output points
   to a newly created instruction effects object, and returns the number
   of bytes allocated at output_buf.  (The caller can use this to shrink
   the output buffer)  Note that an instruction that errored (in the
   runtime) is also considered a successful execution.  On failure to
   execute, returns 0UL and leaves *object undefined and logs reason
   for failure.  Reasons for failure include insufficient output_bufsz. */

ulong
fd_runtime_fuzz_instr_run( fd_runtime_fuzz_runner_t * runner,
                           void const *               input_,
                           void **                    output_,
                           void *                     output_buf,
                           ulong                      output_bufsz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_instr_harness_h */
