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
#define FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL_PROG_ADDR         (1500)
#define FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL_MEM_OP  (10)


/* Syscall per-usage fees */
#define FD_VM_COMPUTE_SCHEDULE_SYSCALL_SHA_PER_BYTE (1)
#define FD_VM_COMPUTE_SCHEDULE_SYSCALL_MEM_OP_BYTES_PER (250)


/* Syscall limits */
#define FD_VM_COMPUTE_SCHEDULE_LIMITS_SYSCALL_SHA_SLICES  (20000)

/* Execution base fees */
#define FD_VM_COMPUTE_

/* Execution per-usage fees */
#define FD_VM_COMPUTE_SCHEDULE_LIMITS_MAX_CPI_INSTR_SZ  (1280)


/* Execution limits */
#define FD_VM_COMPUTE_SCHEDULE_MAX_CALL_DEPTH   (64)
#define FD_VM_COMPUTE_SCHEDULE_HEAP_REGION_SZ   (65536)

FD_PROTOTYPES_BEGIN

// FIXME: all math in here needs to be saturating.

ulong fd_vm_compute_schedule_charge_mem_op(ulong n) {
  ulong cost_per_byte = (n / FD_VM_COMPUTE_SCHEDULE_SYSCALL_SHA_BYTES_PER);
  ulong cost = cost_per_byte > FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL_MEM_OP
    ? cost_per_byte
    : FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL_MEM_OP;
  
  return cost;
}

ulong fd_vm_compute_schedule_charge_sha256(fd_vm_syscall_bytes_slice_t * slices, ulong num_slices) {
  ulong cost = FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL_SHA;

  for (ulong i = 0; i < num_slices; i++) {
    ulong slice_cost_per_byte = (FD_VM_COMPUTE_SCHEDULE_SYSCALL_SHA_PER_BYTE * slices[i].len)/2;
    ulong slice_cost = slice_cost_per_byte > FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL_MEM_OP
      ? slice_cost_per_byte
      : FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL_MEM_OP;

    cost += slice_cost;
  }

  return cost;
}

ulong fd_vm_compute_schedule_charge_log_data(fd_vm_syscall_bytes_slice_t * slices, ulong num_slices) {
  ulong cost = FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL;

  cost += num_slices * FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL;
  
  for (ulong i = 0; i < num_slices; i++) {
    cost += slices[i].len;
  }

  return cost;
}

ulong fd_vm_compute_schedule_charge_log(ulong len) {
  ulong cost = len > FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL 
    ? len
    : FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL;

  return cost;
}

ulong fd_vm_compute_schedule_charge_log_64() {
  return FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL_LOG_64;
}

ulong fd_vm_compute_schedule_charge_log_pubkey() {
  return FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL_LOG_PUBKEY;
}

ulong fd_vm_compute_schedule_charge_set_return_data(ulong n) {
  ulong cost = (n / FD_VM_COMPUTE_SCHEDULE_SYSCALL_MEM_OP_BYTES_PER) 
    + FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL;
  return cost;
}

ulong fd_vm_compute_schedule_charge_simple_syscall() {
  return FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL;
}

ulong fd_vm_compute_schedule_charge_create_program_address() {
  return FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL_PROG_ADDR;
}

ulong fd_vm_compute_schedule_charge_find_program_address() {
  return FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL_PROG_ADDR;
}

ulong fd_vm_compute_schedule_charge_sysvar(ulong sz) {
  return sz + FD_VM_COMPUTE_SCHEDULE_BASE_FEE_SYSCALL_SYSVAR;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_vm_fd_compute_schedule_h */
