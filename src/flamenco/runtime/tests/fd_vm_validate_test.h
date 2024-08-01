#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_exec_vm_test_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_exec_vm_test_h

#include "fd_exec_instr_test.h" /* FIXME: extract common exec test API */
#include "generated/vm.pb.h"
#include "../../vm/fd_vm.h"

/* fd_exec_vm_test.h provides APIs for running VM specific tests */

/* FIXME: Migrate from fd_exec_instr_test, but need to expose _context_{create,destroy} */
// FD_PROTOTYPES_BEGIN
// ulong
// fd_exec_vm_syscall_test_run( fd_exec_instr_test_runner_t *          runner,
//                              fd_exec_test_syscall_context_t const * input,
//                              fd_exec_test_syscall_effects_t **      output,
//                              void *                                 output_buf,
//                              ulong                                  output_bufsz );


ulong
fd_exec_vm_validate_test_run( fd_exec_instr_test_runner_t * runner,
                              void const *                  input_,
                              void **                       output_,
                              void *                        output_buf,
                              ulong                         output_bufsz );

ulong
fd_exec_vm_interp_test_run( fd_exec_instr_test_runner_t *         runner,
                            fd_exec_test_syscall_context_t const *input,
                            fd_exec_test_syscall_effects_t   **   output,
                            void *                                output_buf,
                            ulong                                 output_bufsz );

FD_PROTOTYPES_END

#endif
