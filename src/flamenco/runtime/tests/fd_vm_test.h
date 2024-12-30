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
fd_exec_vm_interp_test_run( fd_exec_instr_test_runner_t *         runner,
                            void const *                          input,
                            void **                               output,
                            void *                                output_buf,
                            ulong                                 output_bufsz );

/* Populates fd_vm_acc_region_meta_t array to reflect contents of the accounts
   in the instruction and the input mem regions */

void
fd_setup_vm_acc_region_metas( fd_vm_acc_region_meta_t * acc_regions_meta,
                              fd_vm_t *                 vm,
                              fd_exec_instr_ctx_t *     instr_ctx );

/* Populates a (caller-initialized) `fd_vm_input_region_t` array from an array of
   `fd_exec_test_input_data_region`s. Caller must guarantee lifetime of the actual
   region(s).

   Empty regions are skipped, so we return the true size of the populated array. */
uint
fd_setup_vm_input_regions( fd_vm_input_region_t *                   input,
                           fd_exec_test_input_data_region_t const * test_input,
                           ulong                                    test_input_count,
                           fd_spad_t *                              spad );

ulong
load_from_vm_input_regions( fd_vm_input_region_t const *        input,
                            uint                                input_count,
                            fd_exec_test_input_data_region_t ** output,
                            pb_size_t *                         output_count,
                            void *                              output_buf,
                            ulong                               output_bufsz );

FD_PROTOTYPES_END

#endif
