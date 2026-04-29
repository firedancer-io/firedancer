#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_cost_harness_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_cost_harness_h

#include "fd_solfuzz.h"
#include "generated/cost.pb.h"

FD_PROTOTYPES_BEGIN

int
fd_solfuzz_pb_cost_run( fd_solfuzz_runner_t *               runner,
                        fd_exec_test_cost_context_t const * input,
                        fd_exec_test_cost_result_t *        output );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_cost_harness_h */
