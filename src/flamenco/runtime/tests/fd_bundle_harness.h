#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_bundle_harness_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_bundle_harness_h

#include "fd_solfuzz.h"

FD_PROTOTYPES_BEGIN

/* fd_solfuzz_pb_bundle_run executes a BundleContext twice: once as
   serial transactions and once as a bundle.  It hard-fails if only one
   mode succeeds or if successful transaction effects differ. */

ulong
fd_solfuzz_pb_bundle_run( fd_solfuzz_runner_t * runner,
                          void const *          input_,
                          void **               output_,
                          void *                output_buf,
                          ulong                 output_bufsz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_bundle_harness_h */
