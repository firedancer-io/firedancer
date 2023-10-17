#ifndef HEADER_src_flamenco_vm_syscall_fd_vm_curve25519_h
#define HEADER_src_flamenco_vm_syscall_fd_vm_curve25519_h

/* fd_vm_curve25519 defines Curve25519-related VM syscalls. */

#include "../fd_vm_syscalls.h"

/* FD_FLAMENCO_ECC_{...} declares curve IDs specified via syscall. */

#define FD_FLAMENCO_ECC_ED25519      (0UL)
#define FD_FLAMENCO_ECC_RISTRETTO255 (1UL)

/* FD_FLAMENCO_ECC_G_{...} declares IDs of operations on elliptic curve
   groups. */

#define FD_FLAMENCO_ECC_G_ADD (0UL)  /* add */
#define FD_FLAMENCO_ECC_G_SUB (1UL)  /* add inverse */
#define FD_FLAMENCO_ECC_G_MUL (2UL)  /* scalar mult */

FD_PROTOTYPES_BEGIN

FD_VM_SYSCALL_DECL( sol_curve_validate_point );
FD_VM_SYSCALL_DECL( sol_curve_group_op       );

FD_PROTOTYPES_END

#endif /*HEADER_src_flamenco_vm_syscall_fd_vm_curve25519_h */
