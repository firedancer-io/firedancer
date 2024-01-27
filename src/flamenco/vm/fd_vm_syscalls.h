#ifndef HEADER_fd_src_flamenco_vm_fd_vm_syscalls_h
#define HEADER_fd_src_flamenco_vm_fd_vm_syscalls_h

#include "../fd_flamenco_base.h"
#include "fd_vm_context.h"

#define FD_VM_SYSCALL_SUCCESS           (0UL)
#define FD_VM_SYSCALL_ERR_ABORT         (1UL)
#define FD_VM_SYSCALL_ERR_PANIC         (2UL)
#define FD_VM_SYSCALL_ERR_MEM_OVERLAP   (3UL)
#define FD_VM_SYSCALL_ERR_INVAL         (4UL)
#define FD_VM_SYSCALL_ERR_INSTR_ERR     (5UL)
#define FD_VM_SYSCALL_ERR_INVOKE_CONTEXT_BORROW_FAILED (6UL)
#define FD_VM_SYSCALL_ERR_RETURN_DATA_TOO_LARGE        (7UL)
#define FD_VM_SYSCALL_ERR_UNIMPLEMENTED (0xFFFFUL) /* TODO: remove when unused */

#define MAX_RETURN_DATA                 (1024UL)

#define FD_VM_SYSCALL_DECL(name) ulong fd_vm_syscall_##name ( \
    void * _ctx, \
    ulong arg0, ulong arg1, ulong arg2, ulong arg3, ulong arg4, \
    ulong * ret_val )

struct fd_vm_syscall_bytes_slice {
  ulong addr;
  ulong len;
};
typedef struct fd_vm_syscall_bytes_slice fd_vm_syscall_bytes_slice_t;

FD_PROTOTYPES_BEGIN

/* Registers a syscall by name to an execution context. */
void fd_vm_register_syscall( fd_sbpf_syscalls_t * syscalls, char const * name, fd_sbpf_syscall_fn_ptr_t fn_ptr );

/* Registers all standard syscalls with the VM */
void fd_vm_syscall_register_all( fd_sbpf_syscalls_t * syscalls );

/* Syscall function declarations */

/* Exceptional syscalls */
FD_VM_SYSCALL_DECL(abort);
FD_VM_SYSCALL_DECL(sol_panic);

/* Logging syscalls */
FD_VM_SYSCALL_DECL(sol_log);
FD_VM_SYSCALL_DECL(sol_log_64);
FD_VM_SYSCALL_DECL(sol_log_compute_units);
FD_VM_SYSCALL_DECL(sol_log_pubkey);
FD_VM_SYSCALL_DECL(sol_log_data);

/* Program syscalls */
FD_VM_SYSCALL_DECL(sol_create_program_address);
FD_VM_SYSCALL_DECL(sol_try_find_program_address);
FD_VM_SYSCALL_DECL(sol_get_processed_sibling_instruction);

/* Crypto syscalls */
FD_VM_SYSCALL_DECL(sol_sha256);
FD_VM_SYSCALL_DECL(sol_keccak256);
FD_VM_SYSCALL_DECL(sol_blake3);
FD_VM_SYSCALL_DECL(sol_secp256k1_recover);
FD_VM_SYSCALL_DECL(sol_curve_validate_point);
FD_VM_SYSCALL_DECL(sol_curve_group_op);
FD_VM_SYSCALL_DECL(sol_curve_multiscalar_mul);
FD_VM_SYSCALL_DECL(sol_curve_pairing_map);
FD_VM_SYSCALL_DECL(sol_alt_bn128_group_op);

/* Memory syscalls */
FD_VM_SYSCALL_DECL(sol_memcpy);
FD_VM_SYSCALL_DECL(sol_memcmp);
FD_VM_SYSCALL_DECL(sol_memset);
FD_VM_SYSCALL_DECL(sol_memmove);

/* CPI syscalls */
FD_VM_SYSCALL_DECL(sol_invoke_signed_c);
FD_VM_SYSCALL_DECL(sol_invoke_signed_rust);
FD_VM_SYSCALL_DECL(sol_alloc_free);
FD_VM_SYSCALL_DECL(sol_set_return_data);
FD_VM_SYSCALL_DECL(sol_get_return_data);
FD_VM_SYSCALL_DECL(sol_get_stack_height);

/* Sysvar syscalls */
FD_VM_SYSCALL_DECL(sol_get_clock_sysvar);
FD_VM_SYSCALL_DECL(sol_get_epoch_schedule_sysvar);
FD_VM_SYSCALL_DECL(sol_get_fees_sysvar);
FD_VM_SYSCALL_DECL(sol_get_rent_sysvar);

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_syscalls_h */
