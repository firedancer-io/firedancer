#ifndef HEADER_fd_src_flamenco_vm_fd_vm_cpi_h
#define HEADER_fd_src_flamenco_vm_fd_vm_cpi_h

#include "../fd_flamenco_base.h"

#define FD_VM_VEC_ALIGN (8UL)

struct __attribute__((packed)) fd_vm_vec {
  ulong addr;
  ulong len;
};

typedef struct fd_vm_vec fd_vm_vec_t;

#endif /* HEADER_fd_src_flamenco_vm_fd_vm_cpi_h */
