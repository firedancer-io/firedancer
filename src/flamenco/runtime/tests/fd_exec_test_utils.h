#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_exec_test_utils_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_exec_test_utils_h

#include "generated/invoke.pb.h"
#include "../context/fd_exec_epoch_ctx.h"



int
fd_exec_test_restore_feature_flags( fd_features_t * features,
                                    fd_exec_test_feature_set_t const * feature_set );

#endif
