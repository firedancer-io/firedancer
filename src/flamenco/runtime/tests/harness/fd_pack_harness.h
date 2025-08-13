#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_pack_harness_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_pack_harness_h

#include "fd_instr_harness.h"
#include "generated/pack.pb.h"

FD_PROTOTYPES_BEGIN

ulong
fd_runtime_fuzz_pack_cpb_run( fd_runtime_fuzz_runner_t * _unused , /* fd_runtime_fuzz_runner_t */
                              void const *               input_,
                              void **                    output_,
                              void *                     output_buf,
                              ulong                      output_bufsz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_pack_harness_h */
