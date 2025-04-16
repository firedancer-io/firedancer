#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_vm_harness_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_vm_harness_h

#include "fd_harness_common.h"
#include "fd_instr_harness.h"

#include "../../fd_system_ids.h"
#include "../../program/fd_bpf_loader_serialization.h"
#include "../../fd_executor.h"
#include "../../../vm/fd_vm.h"
#include "../../../vm/test_vm_util.h"

#include "generated/vm.pb.h"

/* fd_exec_vm_test.h provides APIs for running VM specific tests */
FD_PROTOTYPES_BEGIN

/* Executes a single test case against the interpreter. */
ulong
fd_runtime_fuzz_vm_interp_run( fd_runtime_fuzz_runner_t * runner,
                               void const *               input,
                               void **                    output,
                               void *                     output_buf,
                               ulong                      output_bufsz );

/* Executes a single test case against a target syscall within the VM. */
ulong
fd_runtime_fuzz_vm_syscall_run( fd_runtime_fuzz_runner_t * runner,
                                void const *               input_,
                                void **                    output_,
                                void *                     output_buf,
                                ulong                      output_bufsz );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_vm_harness_h */
