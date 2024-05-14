#include "fd_vm_syscall.h"

#include "../../../ballet/keccak256/fd_keccak256.h"

/* Syscalls for sha256, keccak256, blake3. */

/* Agave has a single generic hash syscall:
   https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1895-L1959
   With trait impl for sha256, keccak256 and blake3:
   https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L130-L225

   Notes:
   1. Max slices, base cost and byte cost are the same for all 3 hash functions:
      - https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L189-L197
      - https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L216-L224
   2. Poseidon doesn't follow this generic hash implementation (so we left it in fd_vm_syscall_crypto.c):
      - https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1678

   Implementation notes.
   Because of the notes above, we implemented fd_vm_syscall_sol_sha256() following the generic hash
   syscall step by step.
   The other implementations are just a copy & paste, replacing the hash function.
   Resisted the temptation to do a macro, because it would complicate future changes, for example if
   we were to modify CU costs. */

int
fd_vm_syscall_sol_sha256( /**/            void *  _vm,
                          /**/            ulong   vals_addr,
                          /**/            ulong   vals_len,
                          /**/            ulong   result_addr,
                          FD_PARAM_UNUSED ulong   r3,
                          FD_PARAM_UNUSED ulong   r4,
                          /**/            ulong * _ret ) {
  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1897 */
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1911-L1920 */
  if( FD_UNLIKELY( FD_VM_SHA256_MAX_SLICES < vals_len ) ) {
    fd_vm_log_append_printf( vm, "%s Hashing %lu sequences in one syscall is over the limit %lu", "Sha256", vals_len, FD_VM_SHA256_MAX_SLICES );
    return FD_VM_ERR_INVAL; /* SyscallError::TooManySlices */
  }

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1922 */
  FD_VM_CU_UPDATE( vm, FD_VM_SHA256_BASE_COST );

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1924-L1929 */
  void * hash_result = FD_VM_MEM_HADDR_ST( vm, result_addr, FD_VM_ALIGN_RUST_U8, 32UL );

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1930 */
  fd_sha256_t sha[1];
  fd_sha256_init( sha );

  if( vals_len > 0 ) {
    /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1932-L1937 */
    fd_vm_vec_t const * input_vec_haddr = (fd_vm_vec_t const *)FD_VM_MEM_HADDR_LD( vm, vals_addr, FD_VM_VEC_ALIGN, vals_len*sizeof(fd_vm_vec_t) );
    for( ulong i=0UL; i<vals_len; i++ ) {
      /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1939-L1944 */
      ulong val_len = input_vec_haddr[i].len;
      void const * bytes = FD_VM_MEM_HADDR_LD( vm, input_vec_haddr[i].addr, FD_VM_ALIGN_RUST_U8, val_len );

      /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1945-L1951 */
      ulong cost = fd_ulong_max( FD_VM_MEM_OP_BASE_COST,
                                 fd_ulong_sat_mul( FD_VM_SHA256_BYTE_COST, (val_len / 2) ) );

      /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1952 */
      FD_VM_CU_UPDATE( vm, cost );

      /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1953 */
      fd_sha256_append( sha, bytes, val_len );
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1956-L1957 */
  fd_sha256_fini( sha, hash_result );
  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_blake3( /**/            void *  _vm,
                          /**/            ulong   vals_addr,
                          /**/            ulong   vals_len,
                          /**/            ulong   result_addr,
                          FD_PARAM_UNUSED ulong   r3,
                          FD_PARAM_UNUSED ulong   r4,
                          /**/            ulong * _ret ) {
  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1897 */
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1911-L1920 */
  if( FD_UNLIKELY( FD_VM_SHA256_MAX_SLICES < vals_len ) ) {
    fd_vm_log_append_printf( vm, "%s Hashing %lu sequences in one syscall is over the limit %lu", "Blake3", vals_len, FD_VM_SHA256_MAX_SLICES );
    return FD_VM_ERR_INVAL; /* SyscallError::TooManySlices */
  }

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1922 */
  FD_VM_CU_UPDATE( vm, FD_VM_SHA256_BASE_COST );

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1924-L1929 */
  void * hash_result = FD_VM_MEM_HADDR_ST( vm, result_addr, FD_VM_ALIGN_RUST_U8, 32UL );

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1930 */
  fd_blake3_t sha[1];
  fd_blake3_init( sha );

  if( vals_len > 0 ) {
    /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1932-L1937 */
    fd_vm_vec_t const * input_vec_haddr = (fd_vm_vec_t const *)FD_VM_MEM_HADDR_LD( vm, vals_addr, FD_VM_VEC_ALIGN, vals_len*sizeof(fd_vm_vec_t) );
    for( ulong i=0UL; i<vals_len; i++ ) {
      /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1939-L1944 */
      ulong val_len = input_vec_haddr[i].len;
      void const * bytes = FD_VM_MEM_HADDR_LD( vm, input_vec_haddr[i].addr, FD_VM_ALIGN_RUST_U8, val_len );

      /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1945-L1951 */
      ulong cost = fd_ulong_max( FD_VM_MEM_OP_BASE_COST,
                                 fd_ulong_sat_mul( FD_VM_SHA256_BYTE_COST, (val_len / 2) ) );

      /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1952 */
      FD_VM_CU_UPDATE( vm, cost );

      /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1953 */
      fd_blake3_append( sha, bytes, val_len );
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1956-L1957 */
  fd_blake3_fini( sha, hash_result );
  *_ret = 0UL;
  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_sol_keccak256( /**/            void *  _vm,
                             /**/            ulong   vals_addr,
                             /**/            ulong   vals_len,
                             /**/            ulong   result_addr,
                             FD_PARAM_UNUSED ulong   r3,
                             FD_PARAM_UNUSED ulong   r4,
                             /**/            ulong * _ret ) {
  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1897 */
  fd_vm_t * vm = (fd_vm_t *)_vm;

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1911-L1920 */
  if( FD_UNLIKELY( FD_VM_SHA256_MAX_SLICES < vals_len ) ) {
    fd_vm_log_append_printf( vm, "%s Hashing %lu sequences in one syscall is over the limit %lu", "Keccak256", vals_len, FD_VM_SHA256_MAX_SLICES );
    return FD_VM_ERR_INVAL; /* SyscallError::TooManySlices */
  }

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1922 */
  FD_VM_CU_UPDATE( vm, FD_VM_SHA256_BASE_COST );

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1924-L1929 */
  void * hash_result = FD_VM_MEM_HADDR_ST( vm, result_addr, FD_VM_ALIGN_RUST_U8, 32UL );

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1930 */
  fd_keccak256_t sha[1];
  fd_keccak256_init( sha );

  if( vals_len > 0 ) {
    /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1932-L1937 */
    fd_vm_vec_t const * input_vec_haddr = (fd_vm_vec_t const *)FD_VM_MEM_HADDR_LD( vm, vals_addr, FD_VM_VEC_ALIGN, vals_len*sizeof(fd_vm_vec_t) );
    for( ulong i=0UL; i<vals_len; i++ ) {
      /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1939-L1944 */
      ulong val_len = input_vec_haddr[i].len;
      void const * bytes = FD_VM_MEM_HADDR_LD( vm, input_vec_haddr[i].addr, FD_VM_ALIGN_RUST_U8, val_len );

      /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1945-L1951 */
      ulong cost = fd_ulong_max( FD_VM_MEM_OP_BASE_COST,
                                  fd_ulong_sat_mul( FD_VM_SHA256_BYTE_COST, (val_len / 2) ) );

      /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1952 */
      FD_VM_CU_UPDATE( vm, cost );

      /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1953 */
      fd_keccak256_append( sha, bytes, val_len );
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v1.18.12/programs/bpf_loader/src/syscalls/mod.rs#L1956-L1957 */
  fd_keccak256_fini( sha, hash_result );
  *_ret = 0UL;
  return FD_VM_SUCCESS;
}
