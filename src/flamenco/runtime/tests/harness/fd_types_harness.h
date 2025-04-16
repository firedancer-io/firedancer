#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_types_harness_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_types_harness_h

#define _GNU_SOURCE

#include "../../../types/fd_types_yaml.h"
#include <stdio.h>
#include <dlfcn.h>
#include <ctype.h>

int
fd_runtime_fuzz_decode_type_run( fd_spad_t *   spad,
                                 uchar const * input,
                                 ulong         input_sz,
                                 uchar *       output,
                                 ulong *       output_sz );

#endif
