#ifndef HEADER_fd_src_flamenco_vm_test_vm_util_h
#define HEADER_fd_src_flamenco_vm_test_vm_util_h

#include "../fd_flamenco_base.h"

#define TEST_VM_REJECT_CALLX_R10_FEATURE_PREFIX (0x7e787d5c6d662d23)

#define TEST_VM_DEFAULT_SBPF_VERSION FD_SBPF_V0

FD_PROTOTYPES_BEGIN

void
test_vm_minimal_exec_instr_ctx( fd_exec_instr_ctx_t * instr_ctx,
                                fd_exec_txn_ctx_t *   txn_ctx,
                                fd_bank_t *           bank );

void
test_vm_clear_txn_ctx_err( fd_exec_txn_ctx_t * txn_ctx );

FD_PROTOTYPES_END

#endif
