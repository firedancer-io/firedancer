#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_exec_sol_compat_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_exec_sol_compat_h

#include "fd_exec_instr_test.h"
#include "../../nanopb/pb_decode.h"
#include "../../nanopb/pb_encode.h"
#include <assert.h>
#include <stdlib.h>
#include "../../../funk/fd_funk.h"

typedef struct {
  ulong struct_size;
  ulong *hardcoded_features;
  ulong hardcoded_feature_cnt;
  ulong *supported_features;
  ulong supported_feature_cnt;
} sol_compat_features_t;

FD_PROTOTYPES_BEGIN

void
sol_compat_init( void );

void
sol_compat_fini( void );

int
sol_compat_instr_execute_v1( uchar *       out,
                             ulong *       out_sz,
                             uchar const * in,
                             ulong         in_sz );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_exec_sol_compat_h */
