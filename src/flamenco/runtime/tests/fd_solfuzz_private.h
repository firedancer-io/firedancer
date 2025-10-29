#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_solfuzz_private_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_solfuzz_private_h

/* fd_solfuzz_private.h contains internal components for the solfuzz
   Protobuf shim. */

#include "fd_solfuzz.h"

FD_PROTOTYPES_BEGIN

typedef ulong( exec_test_run_fn_t )( fd_solfuzz_runner_t *,
                                     void const *,
                                     void **,
                                     void *,
                                     ulong );

static inline void
fd_solfuzz_execute_wrapper( fd_solfuzz_runner_t * runner,
                            void * input,
                            void ** output,
                            exec_test_run_fn_t * exec_test_run_fn ) {

  ulong out_bufsz = 100000000;  /* 100 MB */
  void * out0 = fd_spad_alloc( runner->spad, 1UL, out_bufsz );
  FD_TEST( out_bufsz <= fd_spad_alloc_max( runner->spad, 1UL ) );

  ulong out_used = exec_test_run_fn( runner, input, output, out0, out_bufsz );
  if( FD_UNLIKELY( !out_used ) ) {
    *output = NULL;
  }

}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_solfuzz_private_h */
