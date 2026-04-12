#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_cost_tracker_harness_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_cost_tracker_harness_h

#include "fd_solfuzz.h"

FD_PROTOTYPES_BEGIN

ulong
fd_solfuzz_pb_calc_allocated_accounts_data_size_run(
    fd_solfuzz_runner_t * runner,
    void const *          input_,
    void **               output_,
    void *                output_buf,
    ulong                 output_bufsz
);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_cost_tracker_harness_h */
