#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_exec_sol_compat_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_exec_sol_compat_h

/* fd_exec_sol_compat.h provides APIs for running differential
   tests between Agave and Firedancer. */

#include "./fd_exec_instr_test.h"

FD_PROTOTYPES_BEGIN

void
sol_compat_wksp_init( void );

void
sol_compat_fini( void );

fd_exec_instr_test_runner_t *
sol_compat_setup_scratch_and_runner( void * fmem );

void
sol_compat_cleanup_scratch_and_runner( fd_exec_instr_test_runner_t * runner );

int
sol_compat_instr_fixture( fd_exec_instr_test_runner_t * runner,
                          uchar const *                 in,
                          ulong                         in_sz );

int
sol_compat_syscall_fixture( fd_exec_instr_test_runner_t * runner,
                            uchar const *                 in,
                            ulong                         in_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_exec_sol_compat_h */
