#include "sol_compat_harness_ctx.h"
#include "generated/vm.pb.h"
#include "generated/invoke.pb.h"
#include "generated/txn.pb.h"
#include "generated/elf.pb.h"

GEN_HARNESS_CTX( instr_harness_ctx, fd_exec_test_instr_fixture_t, FD_EXEC_TEST_INSTR_EFFECTS )
GEN_HARNESS_CTX( txn_harness_ctx, fd_exec_test_txn_fixture_t, FD_EXEC_TEST_TXN_RESULT )
GEN_HARNESS_CTX( syscall_harness_ctx, fd_exec_test_syscall_fixture_t, FD_EXEC_TEST_SYSCALL_EFFECTS )
GEN_HARNESS_CTX( vm_validate_harness_ctx, fd_exec_test_validate_vm_fixture_t, FD_EXEC_TEST_VALIDATE_VM_EFFECTS )
GEN_HARNESS_CTX( elf_loader_harness_ctx, fd_exec_test_elf_loader_fixture_t, FD_EXEC_TEST_ELF_LOADER_EFFECTS )
