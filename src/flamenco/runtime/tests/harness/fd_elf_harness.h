#ifndef HEADER_fd_src_flamenco_runtime_tests_harness_fd_elf_harness_h
#define HEADER_fd_src_flamenco_runtime_tests_harness_fd_elf_harness_h

#include "fd_harness_common.h"

#include "../../../vm/fd_vm_base.h"

#include "generated/elf.pb.h"

FD_PROTOTYPES_BEGIN

/* Loads an ELF binary (in input->elf.data()).
   output_buf points to a memory region of output_bufsz bytes where the
   result is allocated into. During execution, the contents of
   fd_sbpf_program_t are wrapped in *output (backed by output_buf).

   Returns number of bytes allocated at output_buf OR 0UL on any
   harness-specific failures. Execution failures still return number of allocated bytes,
   but output is incomplete/undefined.
   */
ulong
fd_runtime_fuzz_sbpf_load_run( fd_runtime_fuzz_runner_t * runner,
                               void const *               input_,
                               void **                    output_,
                               void *                     output_buf,
                               ulong                      output_bufsz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_tests_harness_fd_elf_harness_h */
