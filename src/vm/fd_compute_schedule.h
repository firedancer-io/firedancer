#ifndef HEADER_fd_src_vm_fd_compute_schedule_h
#define HEADER_fd_src_vm_fd_compute_schedule_h

#include "../util/fd_util.h"

/* Syscall base fees */
#define FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL                   (100)
#define FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL_LOG_64            (100)
#define FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL_LOG_PUBKEY        (100)
#define FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL_SHA               (85)
#define FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL_SECP256K1_RECOVER (25000)
#define FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL_SYSVAR            (100)
#define FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL_MEM_OP  (8)


/* Syscall per-usage fees */
#define FD_VM_COMPUTE_SCHEDULE_SYSCALL_SHA_PER_BYTE (1)


/* Syscall limits */
#define FD_VM_COMPUTE_SCHEDULE_LIMITS_SYSCALL_SHA_SLICES  (20000)

/* Execution base fees */
#define FD_VM_COM

/* Execution per-usage fees */
#define FD_VM_COMPUTE_SCHEDULE_LIMITS_MAX_CPI_INSTR_SZ  (1280)


/* Execution limits */
#define FD_VM_COMPUTE_SCHEDULE_MAX_CALL_DEPTH   (64)
#define FD_VM_COMPUTE_SCHEDULE_HEAP_REGION_SZ   (65536)

FD_PROTOTYPES_BEGIN
FD_PROTOTYPES_END

#endif /* HEADER_fd_src_vm_fd_compute_schedule_h */
