#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_exec_sol_compat_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_exec_sol_compat_h

/* fd_exec_sol_compat.h provides APIs for running differential
   tests between Agave and Firedancer. */

#include "fd_harness_common.h"

FD_PROTOTYPES_BEGIN

fd_wksp_t *
sol_compat_wksp_init( ulong wksp_page_sz );

void
sol_compat_fini( void );

void
sol_compat_check_wksp_usage( void );

fd_runtime_fuzz_runner_t *
sol_compat_setup_runner( void );

void
sol_compat_cleanup_runner( fd_runtime_fuzz_runner_t * runner );

int
sol_compat_instr_fixture( fd_runtime_fuzz_runner_t * runner,
                          uchar const *              in,
                          ulong                      in_sz );

int
sol_compat_txn_fixture( fd_runtime_fuzz_runner_t * runner,
                        uchar const *              in,
                        ulong                      in_sz );

int
sol_compat_block_fixture( fd_runtime_fuzz_runner_t * runner,
                          uchar const *              in,
                          ulong                      in_sz );

int
sol_compat_elf_loader_fixture( fd_runtime_fuzz_runner_t * runner,
                               uchar const *              in,
                               ulong                      in_sz );

int
sol_compat_syscall_fixture( fd_runtime_fuzz_runner_t * runner,
                            uchar const *              in,
                            ulong                      in_sz );

int
sol_compat_vm_interp_fixture( fd_runtime_fuzz_runner_t * runner,
                              uchar const *              in,
                              ulong                      in_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_exec_sol_compat_h */
