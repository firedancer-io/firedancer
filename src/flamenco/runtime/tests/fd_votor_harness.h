#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_votor_harness_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_votor_harness_h

#include "fd_solfuzz.h"

FD_PROTOTYPES_BEGIN

/* fd_solfuzz_pb_votor_receive_run runs a VotorReceiveContext's
   datagrams, in order, through the votor tile's receive path and
   writes VotorReceiveEffects for differential comparison with Agave. */

ulong
fd_solfuzz_pb_votor_receive_run( fd_solfuzz_runner_t * runner,
                                 void const *          input,
                                 void **               output,
                                 void *                output_buf,
                                 ulong                 output_bufsz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_votor_harness_h */
