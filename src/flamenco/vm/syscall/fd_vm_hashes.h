#ifndef HEADER_src_flamenco_vm_syscall_fd_vm_hashes_h
#define HEADER_src_flamenco_vm_syscall_fd_vm_hashes_h

/* fd_vm_hashes defines syscalls for the sha256, keccak256, blake3. */

#include "../fd_vm_syscalls.h"

FD_PROTOTYPES_BEGIN

FD_VM_SYSCALL_DECL( sol_sha256 );
FD_VM_SYSCALL_DECL( sol_keccak256 );
FD_VM_SYSCALL_DECL( sol_blake3 );

FD_PROTOTYPES_END

#endif /*HEADER_src_flamenco_vm_syscall_fd_vm_hashes_h */
