#include "fd_syscalls.h"

#include "../ballet/sha256/fd_sha256.h"

#define FD_VM_SYSCALL_DEFN(name, ctx_attr, mem_map_attr, arg0, arg1, arg2, arg3, arg4) \
ulong \
fd_vm_syscall_##name##( \
    ctx_attr fd_vm_exec_context_t * ctx, \
    mem_map_attr fd_vm_mem_map_t *  mem_map, \
    arg0, arg1, arg2, arg3, arg4, \
    ulong * ret_val )

#define FD_VM_SYSCALL_DEFN0_NO_CTX_NO_MEM(name) FD_VM_SYSCALL_DEFN( \
    name, FD_FN_UNUSED, FD_FN_UNUSED, \
    FD_FN_UNUSED ulong _arg0, \
    FD_FN_UNUSED ulong _arg1, \
    FD_FN_UNUSED ulong _arg2, \
    FD_FN_UNUSED ulong _arg3, \
    FD_FN_UNUSED ulong _arg4 )

#define FD_VM_SYSCALL_DEFN4(name, arg0, arg1, arg2, arg3) FD_VM_SYSCALL_DEFN( \
    name, , , \
    ulong arg0, \
    ulong arg1, \
    ulong arg2, \
    ulong arg3, \
    FD_FN_UNUSED ulong _arg4 )

#define FD_VM_SYSCALL_DEFN4_NO_MEM(name, arg0, arg1, arg2, arg3, arg4) FD_VM_SYSCALL_DEFN( \
    name, , FD_UNUSED, \
    ulong arg0, \
    ulong arg1, \
    ulong arg2, \
    ulong arg3, \
    ulong arg4 )


ulong
fd_vm_syscall_abort(
    FD_FN_UNUSED fd_vm_sbpf_exec_context_t * ctx,
    FD_FN_UNUSED ulong arg0, 
    FD_FN_UNUSED ulong arg1, 
    FD_FN_UNUSED ulong arg2, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  return FD_VM_SYSCALL_ERR_ABORT;
}

// TODO: unimplemented
ulong
fd_vm_syscall_sol_panic(
    FD_FN_UNUSED fd_vm_sbpf_exec_context_t * ctx,
    FD_FN_UNUSED ulong arg0, 
    FD_FN_UNUSED ulong arg1, 
    FD_FN_UNUSED ulong arg2, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  return 0;
}

struct fd_vm_syscall_bytes_slice {
  ulong addr;
  ulong len;
};
typedef struct fd_vm_syscall_bytes_slice fd_vm_syscall_bytes_slice_t;

ulong
fd_vm_syscall_sol_sha256(
    fd_vm_sbpf_exec_context_t * ctx,
    ulong slices_addr,
    ulong slices_len,
    ulong res_addr,
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  void * slices_raw;
  ulong translation_res = fd_vm_sbpf_interp_translate_vm_to_host(ctx, 0, slices_addr, slices_len * sizeof(fd_vm_syscall_bytes_slice_t), &slices_raw);
  if (translation_res != FD_VM_MEM_MAP_SUCCESS) {
    return translation_res;
  }
  
  void * hash;
  translation_res = fd_vm_sbpf_interp_translate_vm_to_host(ctx, 1, res_addr, 32, &hash);
  if (translation_res != FD_VM_MEM_MAP_SUCCESS) {
    return translation_res;
  }

  fd_vm_syscall_bytes_slice_t * slices = (fd_vm_syscall_bytes_slice_t *) slices_raw;

  fd_sha256_t sha;
  fd_sha256_init(&sha);

  for (ulong i = 0; i < slices_len; i++) {
    void * slice;
    translation_res = fd_vm_sbpf_interp_translate_vm_to_host(ctx, 0, slices[i].addr, slices[i].len, &slice);
    if (translation_res != FD_VM_MEM_MAP_SUCCESS) {
      return translation_res;
    }

    fd_sha256_append(&sha, slice, slices[i].len);
  }

  fd_sha256_fini(&sha, hash);

  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_keccak256(
    fd_vm_sbpf_exec_context_t * ctx,
    ulong slices_addr,
    ulong slices_len,
    ulong res_addr,
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  void * slices_raw;
  ulong translation_res = fd_vm_sbpf_interp_translate_vm_to_host(ctx, 0, slices_addr, slices_len * sizeof(fd_vm_syscall_bytes_slice_t), &slices_raw);
  if (translation_res != FD_VM_MEM_MAP_SUCCESS) {
    return translation_res;
  }
  
  void * hash;
  translation_res = fd_vm_sbpf_interp_translate_vm_to_host(ctx, 1, res_addr, 32, &hash);
  if (translation_res != FD_VM_MEM_MAP_SUCCESS) {
    return translation_res;
  }

  fd_vm_syscall_bytes_slice_t * slices = (fd_vm_syscall_bytes_slice_t *) slices_raw;

  fd_keccak256_t sha;
  fd_keccak256_init(&sha);

  for (ulong i = 0; i < slices_len; i++) {
    void * slice;
    translation_res = fd_vm_sbpf_interp_translate_vm_to_host(ctx, 0, slices[i].addr, slices[i].len, &slice);
    if (translation_res != FD_VM_MEM_MAP_SUCCESS) {
      return translation_res;
    }

    fd_keccak256_append(&sha, slice, slices[i].len);
  }

  fd_keccak256_fini(&sha, hash);

  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_blake3(
    fd_vm_sbpf_exec_context_t * ctx,
    ulong slices_addr,
    ulong slices_len,
    ulong res_addr,
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  void * slices_raw;
  ulong translation_res = fd_vm_sbpf_interp_translate_vm_to_host(ctx, 0, slices_addr, slices_len * sizeof(fd_vm_syscall_bytes_slice_t), &slices_raw);
  if (translation_res != FD_VM_MEM_MAP_SUCCESS) {
    return translation_res;
  }
  
  void * hash;
  translation_res = fd_vm_sbpf_interp_translate_vm_to_host(ctx, 1, res_addr, 32, &hash);
  if (translation_res != FD_VM_MEM_MAP_SUCCESS) {
    return translation_res;
  }

  fd_vm_syscall_bytes_slice_t * slices = (fd_vm_syscall_bytes_slice_t *) slices_raw;

  fd_blake3_t sha;
  fd_blake3_init(&sha);

  for (ulong i = 0; i < slices_len; i++) {
    void * slice;
    translation_res = fd_vm_sbpf_interp_translate_vm_to_host(ctx, 0, slices[i].addr, slices[i].len, &slice);
    if (translation_res != FD_VM_MEM_MAP_SUCCESS) {
      return translation_res;
    }

    fd_blake3_append(&sha, slice, slices[i].len);
  }

  fd_blake3_fini(&sha, hash);

  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_memcpy(
    fd_vm_sbpf_exec_context_t * ctx,
    ulong dst_vm_addr, 
    ulong src_vm_addr, 
    ulong n, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    ulong * ret
) {
  /* Check for overlap */
  if (src_vm_addr <= (dst_vm_addr + n) && dst_vm_addr <= (src_vm_addr + n)) {
    return FD_VM_SYSCALL_ERR_MEM_OVERLAP;
  }

  void * dst_host_addr;
  void * src_host_addr;
  
  ulong translation_res = fd_vm_sbpf_interp_translate_vm_to_host(ctx, 1, dst_vm_addr, n, &dst_host_addr);
  if (translation_res != FD_VM_MEM_MAP_SUCCESS) {
    return translation_res;
  }

  translation_res = fd_vm_sbpf_interp_translate_vm_to_host(ctx, 0, src_vm_addr, n, &src_host_addr);
  if (translation_res != FD_VM_MEM_MAP_SUCCESS) {
    return translation_res;
  }

  fd_memcpy(dst_host_addr, src_host_addr, n);

  *ret = dst_vm_addr;

  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_memcmp(
    fd_vm_sbpf_exec_context_t * ctx,
    ulong vm_addr1,
    ulong vm_addr2, 
    ulong n, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    ulong * ret
) {
  void * host_addr1;
  void * host_addr2;
  
  ulong translation_res = fd_vm_sbpf_interp_translate_vm_to_host(ctx, 0, vm_addr1, n, &host_addr1);
  if (translation_res != FD_VM_MEM_MAP_SUCCESS) {
    return translation_res;
  }

  translation_res = fd_vm_sbpf_interp_translate_vm_to_host(ctx, 0, vm_addr2, n, &host_addr2);
  if (translation_res != FD_VM_MEM_MAP_SUCCESS) {
    return translation_res;
  }

  *ret = (ulong)memcmp(host_addr1, host_addr2, n);

  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_memset(
    fd_vm_sbpf_exec_context_t * ctx,
    ulong dst_vm_addr,
    ulong c, 
    ulong n, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    ulong * ret
) {
  void * dst_host_addr;
  
  ulong translation_res = fd_vm_sbpf_interp_translate_vm_to_host(ctx, 1, dst_vm_addr, n, &dst_host_addr);
  if (translation_res != FD_VM_MEM_MAP_SUCCESS) {
    return translation_res;
  }

  fd_memset(dst_host_addr, c, n);

  *ret = dst_vm_addr;

  return FD_VM_SYSCALL_SUCCESS;
}

// TODO: move back to top of file.
void fd_vm_syscall_register_all( fd_vm_sbpf_exec_context_t * ctx ) {
  fd_vm_sbpf_interp_register_syscall( ctx, "abort", fd_vm_syscall_abort );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_sha256", fd_vm_syscall_sol_sha256 );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_keccak256", fd_vm_syscall_sol_keccak256 );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_blake3", fd_vm_syscall_sol_blake3 );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_memcpy_", fd_vm_syscall_sol_memcpy );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_memcmp_", fd_vm_syscall_sol_memcmp );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_memset_", fd_vm_syscall_sol_memset );
}
