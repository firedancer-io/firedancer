#ifndef HEADER_src_flamenco_vm_syscall_fd_vm_curve25519_h
#define HEADER_src_flamenco_vm_syscall_fd_vm_curve25519_h

/* fd_vm_curve25519 defines Curve25519-related VM syscalls. */

#include "../fd_vm_syscalls.h"

/* FD_FLAMENCO_CURVE_{...} declares curve IDs specified via syscall. */

#define FD_FLAMENCO_CURVE_25519_EDWARDS   (0UL)
#define FD_FLAMENCO_CURVE_25519_RISTRETTO (1UL)

FD_PROTOTYPES_BEGIN

FD_VM_SYSCALL_DECL( sol_curve_validate_point );

FD_PROTOTYPES_END

#endif /*HEADER_src_flamenco_vm_syscall_fd_vm_curve25519_h */
