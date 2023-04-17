#include "fd_syscalls.h"

#include <stdio.h>

#include "../ballet/sha256/fd_sha256.h"
#include "../ballet/keccak256/fd_keccak256.h"
#include "../ballet/blake3/fd_blake3.h"
#include "../ballet/base58/fd_base58.h"


void fd_vm_syscall_register_all( fd_vm_sbpf_exec_context_t * ctx ) {
  fd_vm_sbpf_interp_register_syscall( ctx, "abort", fd_vm_syscall_abort );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_panic_", fd_vm_syscall_sol_panic );
  
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_log_", fd_vm_syscall_sol_log );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_log_64_", fd_vm_syscall_sol_log_64 );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_log_compute_units_", fd_vm_syscall_sol_log );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_log_pubkey_", fd_vm_syscall_sol_log_pubkey );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_log_data_", fd_vm_syscall_sol_log_data );
  
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_sha256", fd_vm_syscall_sol_sha256 );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_keccak256", fd_vm_syscall_sol_keccak256 );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_blake3", fd_vm_syscall_sol_blake3 );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_secp256k1_recover", fd_vm_syscall_sol_secp256k1_recover );
  
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_memcpy_", fd_vm_syscall_sol_memcpy );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_memcmp_", fd_vm_syscall_sol_memcmp );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_memset_", fd_vm_syscall_sol_memset );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_memmove_", fd_vm_syscall_sol_memmove );
  
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_invoke_signed_c", fd_vm_syscall_sol_invoke_signed_c );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_invoke_signed_rust", fd_vm_syscall_sol_invoke_signed_rust );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_alloc_free_", fd_vm_syscall_sol_alloc_free );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_set_return_data", fd_vm_syscall_sol_set_return_data );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_get_return_data", fd_vm_syscall_sol_get_return_data );
  fd_vm_sbpf_interp_register_syscall( ctx, "sol_get_stack_height", fd_vm_syscall_sol_get_stack_height );
}

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
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
}


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
fd_vm_syscall_sol_secp256k1_recover(
    FD_FN_UNUSED fd_vm_sbpf_exec_context_t * ctx,
    FD_FN_UNUSED ulong arg0, 
    FD_FN_UNUSED ulong arg1, 
    FD_FN_UNUSED ulong arg2, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
}


ulong
fd_vm_syscall_sol_log(
    fd_vm_sbpf_exec_context_t * ctx,
    ulong msg_vm_addr,
    ulong msg_len, 
    FD_FN_UNUSED ulong arg2, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  void * msg_host_addr;
  
  ulong translation_res = fd_vm_sbpf_interp_translate_vm_to_host(ctx, 1, msg_vm_addr, msg_len, &msg_host_addr);
  if (translation_res != FD_VM_MEM_MAP_SUCCESS) {
    return translation_res;
  }

  fd_vm_log_collector_log( &ctx->log_collector, msg_host_addr, msg_len );

  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_log_64(
    fd_vm_sbpf_exec_context_t * ctx,
    ulong arg0,
    ulong arg1, 
    ulong arg2, 
    ulong arg3, 
    ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  char msg[1024];

  int msg_len = sprintf(msg, "Program log: %lx %lx %lx %lx %lx", arg0, arg1, arg2, arg3, arg4);

  fd_vm_log_collector_log( &ctx->log_collector, msg, msg_len );

  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_log_pubkey(
    fd_vm_sbpf_exec_context_t * ctx,
    ulong pubkey_vm_addr,
    FD_FN_UNUSED ulong arg1, 
    FD_FN_UNUSED ulong arg2, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  void * pubkey_host_addr;

  char msg[128];
  char pubkey_str[FD_BASE58_ENCODED_32_SZ];

  ulong translation_res = fd_vm_sbpf_interp_translate_vm_to_host(ctx, 1, pubkey_vm_addr, 32, &pubkey_host_addr);
  if (translation_res != FD_VM_MEM_MAP_SUCCESS) {
    return translation_res;
  }
  
  fd_base58_encode_32( pubkey_host_addr, NULL, pubkey_str );
  
  int msg_len = sprintf( msg, "Program log: %s", pubkey_str );

  fd_vm_log_collector_log( &ctx->log_collector, msg, msg_len );

  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_log_compute_units(
    FD_FN_UNUSED fd_vm_sbpf_exec_context_t * ctx,
    FD_FN_UNUSED ulong arg0, 
    FD_FN_UNUSED ulong arg1, 
    FD_FN_UNUSED ulong arg2, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
}

ulong
fd_vm_syscall_sol_log_data(
    FD_FN_UNUSED fd_vm_sbpf_exec_context_t * ctx,
    FD_FN_UNUSED ulong arg0, 
    FD_FN_UNUSED ulong arg1, 
    FD_FN_UNUSED ulong arg2, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
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

ulong
fd_vm_syscall_sol_memmove(
    fd_vm_sbpf_exec_context_t * ctx,
    ulong dst_vm_addr, 
    ulong src_vm_addr, 
    ulong n, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    ulong * ret
) {
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

  memmove(dst_host_addr, src_host_addr, n);

  *ret = dst_vm_addr;

  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_invoke_signed_c(
    FD_FN_UNUSED fd_vm_sbpf_exec_context_t * ctx,
    FD_FN_UNUSED ulong arg0, 
    FD_FN_UNUSED ulong arg1, 
    FD_FN_UNUSED ulong arg2, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
}

ulong
fd_vm_syscall_sol_invoke_signed_rust(
    FD_FN_UNUSED fd_vm_sbpf_exec_context_t * ctx,
    FD_FN_UNUSED ulong arg0, 
    FD_FN_UNUSED ulong arg1, 
    FD_FN_UNUSED ulong arg2, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
}

ulong
fd_vm_syscall_sol_alloc_free(
    FD_FN_UNUSED fd_vm_sbpf_exec_context_t * ctx,
    FD_FN_UNUSED ulong arg0, 
    FD_FN_UNUSED ulong arg1, 
    FD_FN_UNUSED ulong arg2, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
}

ulong
fd_vm_syscall_sol_get_return_data(
    FD_FN_UNUSED fd_vm_sbpf_exec_context_t * ctx,
    FD_FN_UNUSED ulong arg0, 
    FD_FN_UNUSED ulong arg1, 
    FD_FN_UNUSED ulong arg2, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
}

ulong
fd_vm_syscall_sol_set_return_data(
    FD_FN_UNUSED fd_vm_sbpf_exec_context_t * ctx,
    FD_FN_UNUSED ulong arg0, 
    FD_FN_UNUSED ulong arg1, 
    FD_FN_UNUSED ulong arg2, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
}

ulong
fd_vm_syscall_sol_get_stack_height(
    fd_vm_sbpf_exec_context_t * ctx,
    FD_FN_UNUSED ulong arg0, 
    FD_FN_UNUSED ulong arg1, 
    FD_FN_UNUSED ulong arg2, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    ulong * ret
) {
  *ret = ctx->stack.frames_used;

  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_get_clock_sysvar(
    FD_FN_UNUSED fd_vm_sbpf_exec_context_t * ctx,
    FD_FN_UNUSED ulong arg0, 
    FD_FN_UNUSED ulong arg1, 
    FD_FN_UNUSED ulong arg2, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
}

ulong
fd_vm_syscall_sol_get_epoch_schedule_sysvar(
    FD_FN_UNUSED fd_vm_sbpf_exec_context_t * ctx,
    FD_FN_UNUSED ulong arg0, 
    FD_FN_UNUSED ulong arg1, 
    FD_FN_UNUSED ulong arg2, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
}

ulong
fd_vm_syscall_sol_get_fees_sysvar(
    FD_FN_UNUSED fd_vm_sbpf_exec_context_t * ctx,
    FD_FN_UNUSED ulong arg0, 
    FD_FN_UNUSED ulong arg1, 
    FD_FN_UNUSED ulong arg2, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
}

ulong
fd_vm_syscall_sol_get_rent_sysvar(
    FD_FN_UNUSED fd_vm_sbpf_exec_context_t * ctx,
    FD_FN_UNUSED ulong arg0, 
    FD_FN_UNUSED ulong arg1, 
    FD_FN_UNUSED ulong arg2, 
    FD_FN_UNUSED ulong arg3, 
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
}
