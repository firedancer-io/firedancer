#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_exec_instr_test_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_exec_instr_test_h

/* fd_exec_instr_test.h provides APIs for running instruction processor
   tests. */

#include "fd_exec_test.pb.h"
#include "../../../funk/fd_funk.h"

/* fd_exec_instr_test_runner_t provides fake fd_exec_instr_ctx_t to
   test processing of individual instructions. */

struct fd_exec_instr_test_runner_private;
typedef struct fd_exec_instr_test_runner_private fd_exec_instr_test_runner_t;

FD_PROTOTYPES_BEGIN

/* Constructors */

ulong
fd_exec_instr_test_runner_align( void );

ulong
fd_exec_instr_test_runner_footprint( void );

/* fd_exec_instr_test_runner_new formats a memory region for use as an
   instruction test runner.  mem must be part of an fd_wksp.  Does
   additional wksp allocs.  wksp_tag is the tag used for wksp allocs
   managed by the runner.  Returns newly created runner on success.  On
   failure, returns NULL and logs reason for error. */

fd_exec_instr_test_runner_t *
fd_exec_instr_test_runner_new( void * mem,
                               ulong  wksp_tag );

/* fd_exec_instr_test_runner_delete frees wksp allocations managed by
   runner and returns the memory region backing runner itself back to
   the caller. */

void *
fd_exec_instr_test_runner_delete( fd_exec_instr_test_runner_t * runner );

/* User API */

/* fd_exec_instr_fixture_run executes the given instruction processing
   fixture and validates that the actual result matches the expected.
   Returns 1 on success.  On failure, returns 0 and logs reason for
   error to warning log.  Uses fd_scratch. */

int
fd_exec_instr_fixture_run( fd_exec_instr_test_runner_t *        runner,
                           fd_exec_test_instr_fixture_t const * test );

/* fd_exec_instr_test_run executes a given instruction context (input)
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
fd_exec_instr_test_run( fd_exec_instr_test_runner_t *        runner,
                        fd_exec_test_instr_context_t const * input,
                        fd_exec_test_instr_effects_t **      output,
                        void *                               output_buf,
                        ulong                                output_bufsz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_exec_instr_test_h */
