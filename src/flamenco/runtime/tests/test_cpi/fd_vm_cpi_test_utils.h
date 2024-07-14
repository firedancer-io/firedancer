#ifndef HEADER_fd_src_flamenco_runtime_tests_fd_vm_cpi_test_utils_h
#define HEADER_fd_src_flamenco_runtime_tests_fd_vm_cpi_test_utils_h
#include "../../../vm/syscall/fd_vm_syscall.h"
#include "../../../../util/fd_util.h"
#include "../generated/vm_cpi.pb.h"


typedef struct fd_cpi_test_funcs{
    int (*syscall)(void *_vm, ulong r1, ulong r2, ulong r3, ulong r4, ulong r5, ulong *_ret);
    int (*setup_cpi_instr)(fd_vm_t *_vm, fd_exec_test_cpi_instr_t const *cpi_instr);
} fd_cpi_test_funcs_t;

fd_cpi_test_funcs_t c_cpi_test_funcs;
fd_cpi_test_funcs_t rust_cpi_test_funcs;

#endif /* HEADER_fd_src_flamenco_runtime_tests_fd_vm_cpi_test_utils_h */