#ifndef HEADER_fd_src_ballet_runtime_fd_syscalls_h
#define HEADER_fd_src_ballet_runtime_fd_syscalls_h

#include "../ballet/fd_ballet_base.h"
#include "fd_sbpf_interp.h"

#define FD_VM_SYSCALL_SUCCESS           (0UL)
#define FD_VM_SYSCALL_ERR_ABORT         (1UL)
#define FD_VM_SYSCALL_ERR_PANIC         (2UL)
#define FD_VM_SYSCALL_ERR_MEM_OVERLAP   (3UL)

#define FD_VM_SYSCALL_DECL(name) ulong fd_vm_syscall_##name##( \
    fd_vm_exec_context_t *  ctx, \
    fd_vm_mem_map_t *       mem_map, \
    ulong arg0, ulong arg1, ulong arg2, ulong arg3, ulong arg4, \
    ulong ret_val )

FD_PROTOTYPES_BEGIN

/*
void fd_syscall_sol_log( uchar const * message, ulong len );
void fd_syscall_sol_log_64( ulong arg1, ulong arg2, ulong arg3, ulong arg4, ulong arg5 );
void fd_syscall_sol_log_compute_units();
void fd_syscall_sol_log_pubkey( uchar const * pubkey_addr );

void fd_syscall_sol_create_program_address( uchar const );
void fd_syscall_sol_try_find_program_address();

void fd_syscall_sol_sha256();
void fd_syscall_sol_keccak256();
void fd_syscall_sol_secp256k1_recover();
void fd_syscall_sol_blake3();
void fd_syscall_sol_curve_validate_point();
void fd_syscall_sol_curve_group_op();

void fd_syscall_sol_get_clock_sysvar();
void fd_syscall_sol_get_epoch_schedule_sysvar();
void fd_syscall_sol_get_fees_sysvar();
void fd_syscall_sol_get_rent_sysvar();

void fd_syscall_sol_memcpy( uchar * dst, uchar const * src, ulong n );
void fd_syscall_sol_memmove( uchar * dst, uchar const * src, ulong n );
void fd_syscall_sol_memcmp( uchar const * s1, uchar const * s2, ulong n );
void fd_syscall_sol_memset( uchar * s, uchar c, ulong n );
void fd_syscall_sol_invoke_signed_c();
void fd_syscall_sol_invoke_signed_rust();
void fd_syscall_sol_alloc_free();
void fd_syscall_sol_set_return_data();
void fd_syscall_sol_get_return_data();
void fd_syscall_sol_log_data();

void fd_syscall_sol_get_processed_sibling_instruction();
void fd_syscall_sol_get_stack_height();
void fd_syscall_sol_curve_multiscalar_mul();
void fd_syscall_sol_curve_pairing_map();
void fd_syscall_sol_alt_bn128_group_op();
*/
FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_runtime_fd_syscalls_h */
