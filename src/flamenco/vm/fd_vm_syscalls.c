#include "fd_vm_syscalls.h"

#include "../../ballet/base64/fd_base64.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/keccak256/fd_keccak256.h"
#include "../../ballet/blake3/fd_blake3.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/murmur3/fd_murmur3.h"

#include <stdio.h>

/* Consume compute units for mem ops*/
static ulong
fd_vm_mem_op_consume( fd_vm_exec_context_t * ctx,
                      ulong                  n ) {
  ulong cost = fd_ulong_max( vm_compute_budget.mem_op_base_cost,
                             n / vm_compute_budget.cpi_bytes_per_unit );
  return fd_vm_consume_compute_meter( ctx, cost );
}

void
fd_vm_register_syscall( fd_sbpf_syscalls_t * syscalls,
                        char const *         name,
                        fd_sbpf_syscall_fn_t fn_ptr) {

  ulong name_len     = strlen(name);
  uint  syscall_hash = fd_murmur3_32( name, name_len, 0U );

  fd_sbpf_syscalls_t * syscall_entry = fd_sbpf_syscalls_insert( syscalls, syscall_hash );
  syscall_entry->func_ptr            = fn_ptr;
  syscall_entry->name = name;
}

static void
fd_vm_syscall_register_base( fd_sbpf_syscalls_t * syscalls ) {
  fd_vm_register_syscall( syscalls, "abort",                  fd_vm_syscall_abort     );
  fd_vm_register_syscall( syscalls, "sol_panic_",             fd_vm_syscall_sol_panic );

  fd_vm_register_syscall( syscalls, "sol_log_",               fd_vm_syscall_sol_log                 );
  fd_vm_register_syscall( syscalls, "sol_log_64_",            fd_vm_syscall_sol_log_64              );
  fd_vm_register_syscall( syscalls, "sol_log_pubkey",         fd_vm_syscall_sol_log_pubkey          );
  fd_vm_register_syscall( syscalls, "sol_log_data",           fd_vm_syscall_sol_log_data            );
  fd_vm_register_syscall( syscalls, "sol_log_compute_units_", fd_vm_syscall_sol_log_compute_units   );

  fd_vm_register_syscall( syscalls, "sol_sha256",             fd_vm_syscall_sol_sha256            );
  fd_vm_register_syscall( syscalls, "sol_keccak256",          fd_vm_syscall_sol_keccak256         );

  fd_vm_register_syscall( syscalls, "sol_memcpy_",            fd_vm_syscall_sol_memcpy  );
  fd_vm_register_syscall( syscalls, "sol_memcmp_",            fd_vm_syscall_sol_memcmp  );
  fd_vm_register_syscall( syscalls, "sol_memset_",            fd_vm_syscall_sol_memset  );
  fd_vm_register_syscall( syscalls, "sol_memmove_",           fd_vm_syscall_sol_memmove );

  fd_vm_register_syscall( syscalls, "sol_alloc_free_",               fd_vm_syscall_sol_alloc_free       );
  fd_vm_register_syscall( syscalls, "sol_set_return_data",           fd_vm_syscall_sol_set_return_data  );
  fd_vm_register_syscall( syscalls, "sol_get_return_data",           fd_vm_syscall_sol_get_return_data  );
  fd_vm_register_syscall( syscalls, "sol_get_stack_height",          fd_vm_syscall_sol_get_stack_height );

  fd_vm_register_syscall( syscalls, "sol_get_clock_sysvar",          fd_vm_syscall_sol_get_clock_sysvar          );
  fd_vm_register_syscall( syscalls, "sol_get_epoch_schedule_sysvar", fd_vm_syscall_sol_get_epoch_schedule_sysvar );
  fd_vm_register_syscall( syscalls, "sol_get_rent_sysvar",           fd_vm_syscall_sol_get_rent_sysvar           );

  fd_vm_register_syscall( syscalls, "sol_create_program_address",            fd_vm_syscall_sol_create_program_address            );
  fd_vm_register_syscall( syscalls, "sol_try_find_program_address",          fd_vm_syscall_sol_try_find_program_address          );
  fd_vm_register_syscall( syscalls, "sol_get_processed_sibling_instruction", fd_vm_syscall_sol_get_processed_sibling_instruction );
}

void
fd_vm_syscall_register_all( fd_sbpf_syscalls_t * syscalls ) {
  fd_vm_syscall_register_base( syscalls );
}

ulong
fd_vm_syscall_abort(
    FD_FN_UNUSED void * _ctx,
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
    void *  _ctx,
    ulong   msg_vaddr,
    ulong   msg_len,
    ulong   r3  __attribute__((unused)),
    ulong   r4  __attribute__((unused)),
    ulong   r5  __attribute__((unused)),
    ulong * pr0 __attribute__((unused))) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  ulong err = fd_vm_consume_compute_meter(ctx, msg_len);
  if ( FD_UNLIKELY( err ) ) return err;
  /* Here, Solana Labs charges compute units, does UTF-8 validation,
     and checks for a cstr terminating NUL.  We skip all of this since
     this syscall always aborts the transaction.  The type of error
     does not matter. */

  char const * str = fd_vm_translate_vm_to_host_const( ctx, msg_vaddr, msg_len, alignof(uchar) );

  /* TODO write to log collector instead of writing to fd_log */

  if( FD_UNLIKELY( !str ) ) {
    FD_LOG_WARNING(( "sol_panic_ called with invalid string (addr=%#lx, len=%#lx)",
                     msg_vaddr, msg_len ));
    return FD_VM_SYSCALL_ERR_MEM_OVERLAP;
  }

  if( FD_UNLIKELY( msg_len > 1024UL ) )
    FD_LOG_WARNING(( "Truncating sol_panic_ message (orig %#lx bytes)", msg_len ));
  FD_LOG_HEXDUMP_DEBUG(( "sol_panic", str, msg_len ));

  return FD_VM_SYSCALL_ERR_PANIC;
}


ulong
fd_vm_syscall_sol_sha256(
    void *  _ctx,
    ulong   slices_vaddr,
    ulong   slices_cnt,
    ulong   res_vaddr,
    ulong   r4 __attribute__((unused)),
    ulong   r5 __attribute__((unused)),
    ulong * pr0
) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  if( FD_UNLIKELY( slices_cnt > vm_compute_budget.sha256_max_slices ) )
    return FD_VM_SYSCALL_ERR_INVAL;

  ulong err = fd_vm_consume_compute_meter(ctx, vm_compute_budget.sha256_base_cost);
  if ( FD_UNLIKELY( err ) ) return err;
  ulong slices_sz = slices_cnt * sizeof(fd_vm_vec_t);

  fd_vm_vec_t const * slices =
      fd_vm_translate_vm_to_host_const( ctx, slices_vaddr, slices_sz, FD_VM_VEC_ALIGN );
  void * hash =
      fd_vm_translate_vm_to_host      ( ctx, res_vaddr,    32UL,      alignof(uchar)  );

  if( FD_UNLIKELY( (!slices) | (!hash) ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_sha256_t sha;
  fd_sha256_init( &sha );

  for( ulong i = 0; i < slices_cnt; i++ ) {
    uchar const * slice = fd_vm_translate_vm_to_host_const( ctx, slices[i].addr, slices[i].len, alignof(uchar) );
    if( FD_UNLIKELY( !slice ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

    ulong cost = fd_ulong_max(vm_compute_budget.mem_op_base_cost, fd_ulong_sat_mul(vm_compute_budget.sha256_byte_cost, slices[i].len) / 2);
    ulong err = fd_vm_consume_compute_meter(ctx, cost);
    if ( FD_UNLIKELY( err ) ) return err;

    fd_sha256_append( &sha, slice, slices[i].len );
  }

  fd_sha256_fini( &sha, hash );
  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_keccak256(
    void *  _ctx,
    ulong   slices_vaddr,
    ulong   slices_cnt,
    ulong   res_vaddr,
    ulong   r4 __attribute__((unused)),
    ulong   r5 __attribute__((unused)),
    ulong * pr0
) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  if( FD_UNLIKELY( slices_cnt > vm_compute_budget.sha256_max_slices ) )
    return FD_VM_SYSCALL_ERR_INVAL;

  ulong err = fd_vm_consume_compute_meter(ctx, vm_compute_budget.sha256_base_cost);
  if ( FD_UNLIKELY( err ) ) {
    return err;
  }

  void * hash =
      fd_vm_translate_vm_to_host      ( ctx, res_vaddr,    32UL,      alignof(uchar)  );

  if( FD_UNLIKELY( (!hash) ) ) {
    return FD_VM_MEM_MAP_ERR_ACC_VIO;
  }

  fd_keccak256_t sha;
  fd_keccak256_init(&sha);

  if ( FD_LIKELY( slices_cnt > 0 ) ) {
    ulong slices_sz = slices_cnt * sizeof(fd_vm_vec_t);

    fd_vm_vec_t const * slices =
        fd_vm_translate_vm_to_host_const( ctx, slices_vaddr, slices_sz, FD_VM_VEC_ALIGN );

    if( FD_UNLIKELY( (!slices) ) ) {
      return FD_VM_MEM_MAP_ERR_ACC_VIO;
    }

    for (ulong i = 0; i < slices_cnt; i++) {
      void const * slice = fd_vm_translate_vm_to_host_const( ctx, slices[i].addr, slices[i].len, alignof(uchar) );
      if( FD_UNLIKELY( !slice ) ) {
        FD_LOG_DEBUG(("Translate slice failed %lu %lu %lu", i, slices[i].addr, slices[i].len));
        return FD_VM_MEM_MAP_ERR_ACC_VIO;
      }

      ulong cost = fd_ulong_max(vm_compute_budget.mem_op_base_cost, fd_ulong_sat_mul(vm_compute_budget.sha256_byte_cost, slices[i].len / 2));
      ulong err = fd_vm_consume_compute_meter(ctx, cost);
      if ( FD_UNLIKELY( err ) ) return err;

      fd_keccak256_append( &sha, slice, slices[i].len );
    }
  }

  fd_keccak256_fini(&sha, hash);
  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_blake3(
    void *  _ctx,
    ulong   slices_vaddr,
    ulong   slices_cnt,
    ulong   res_vaddr,
    ulong   r4 __attribute__((unused)),
    ulong   r5 __attribute__((unused)),
    ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  /* TODO don't hardcode limit */
  if( FD_UNLIKELY( slices_cnt > vm_compute_budget.sha256_max_slices ) )
    return FD_VM_SYSCALL_ERR_INVAL;

  ulong err = fd_vm_consume_compute_meter(ctx, vm_compute_budget.sha256_base_cost);
  if ( FD_UNLIKELY( err ) ) return err;
  ulong slices_sz = slices_cnt * sizeof(fd_vm_vec_t);

  fd_vm_vec_t const * slices =
      fd_vm_translate_vm_to_host_const( ctx, slices_vaddr, slices_sz, FD_VM_VEC_ALIGN );
  void * hash =
      fd_vm_translate_vm_to_host      ( ctx, res_vaddr,    32UL,      alignof(uchar)  );

  if( FD_UNLIKELY( (!slices) | (!hash) ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_blake3_t b3;
  fd_blake3_init(&b3);

  for (ulong i = 0; i < slices_cnt; i++) {
    void const * slice = fd_vm_translate_vm_to_host( ctx, slices[i].addr, slices[i].len, alignof(uchar) );
    if( FD_UNLIKELY( !slice ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

    ulong cost = fd_ulong_max(vm_compute_budget.mem_op_base_cost, fd_ulong_sat_mul(vm_compute_budget.sha256_byte_cost, slices[i].len) / 2);
    ulong err = fd_vm_consume_compute_meter(ctx, cost);
    if ( FD_UNLIKELY( err ) ) return err;

    fd_blake3_append( &b3, slice, slices[i].len );
  }

  fd_blake3_fini( &b3, hash );
  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_secp256k1_recover(
    FD_FN_UNUSED void * _ctx,
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
    void *  _ctx,
    ulong   msg_vm_addr,
    ulong   msg_len,
    ulong   r3 __attribute__((unused)),
    ulong   r4 __attribute__((unused)),
    ulong   r5 __attribute__((unused)),
    ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  ulong err = fd_vm_consume_compute_meter( ctx, fd_ulong_max(msg_len, vm_compute_budget.syscall_base_cost) );
  if ( FD_UNLIKELY( err ) ) return err;

  void const * msg_host_addr =
      fd_vm_translate_vm_to_host_const( ctx, msg_vm_addr, msg_len, alignof(uchar) );
  if( FD_UNLIKELY( !msg_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_vm_log_collector_log( &ctx->log_collector, msg_host_addr, msg_len );

  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_log_64(
    void *  _ctx,
    ulong   r1,
    ulong   r2,
    ulong   r3,
    ulong   r4,
    ulong   r5,
    ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  ulong err = fd_vm_consume_compute_meter( ctx, vm_compute_budget.log_64_units );
  if ( FD_UNLIKELY( err ) ) return err;

  char msg[1024];
  int msg_len = sprintf( msg, "Program log: %lx %lx %lx %lx %lx", r1, r2, r3, r4, r5 );

  fd_vm_log_collector_log( &ctx->log_collector, msg, (ulong)msg_len );

  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_log_pubkey(
    void *  _ctx,
    ulong   pubkey_vm_addr,
    ulong   r2 __attribute__((unused)),
    ulong   r3 __attribute__((unused)),
    ulong   r4 __attribute__((unused)),
    ulong   r5 __attribute__((unused)),
    ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  ulong err = fd_vm_consume_compute_meter( ctx, vm_compute_budget.log_pubkey_units );
  if ( FD_UNLIKELY( err ) ) return err;

  char msg[128];
  char pubkey_str[FD_BASE58_ENCODED_32_SZ];

  void * pubkey_host_addr =
      fd_vm_translate_vm_to_host( ctx, pubkey_vm_addr, sizeof(fd_pubkey_t), alignof(uchar) );
  if( FD_UNLIKELY( !pubkey_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_base58_encode_32( pubkey_host_addr, NULL, pubkey_str );

  int msg_len = sprintf( msg, "Program log: %s", pubkey_str );

  fd_vm_log_collector_log( &ctx->log_collector, msg, (ulong)msg_len );

  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_log_compute_units(
    void * _ctx,
    ulong arg0 __attribute__((unused)),
    ulong arg1 __attribute__((unused)),
    ulong arg2 __attribute__((unused)),
    ulong arg3 __attribute__((unused)),
    ulong arg4 __attribute__((unused)),
    FD_FN_UNUSED ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  if ( FD_UNLIKELY( !ctx)) {
    return FD_VM_SYSCALL_ERR_INVOKE_CONTEXT_BORROW_FAILED;
  }

  ulong result = fd_vm_consume_compute_meter( ctx, vm_compute_budget.syscall_base_cost );
  if (result != FD_VM_SYSCALL_SUCCESS) {
    return result;
  }

  char msg[1024];
  int msg_len = sprintf( msg, "Program consumption: %lu units remaining\n", ctx->compute_meter);

  fd_vm_log_collector_log( &ctx->log_collector, msg, (ulong)msg_len );

  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_log_data(
    void * _ctx,
    ulong vm_addr,
    ulong len,
    ulong r3 __attribute__((unused)),
    ulong r4 __attribute__((unused)),
    ulong r5 __attribute__((unused)),
    ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  ulong err = fd_vm_consume_compute_meter( ctx, vm_compute_budget.syscall_base_cost );
  if ( FD_UNLIKELY( err ) ) return err;

  ulong sz = len * sizeof (fd_vm_vec_t);

  fd_vm_vec_t const * untranslated_fields = fd_vm_translate_slice_vm_to_host_const(
    ctx,
    vm_addr,
    sz,
    FD_VM_VEC_ALIGN );

  err = fd_vm_consume_compute_meter( ctx, fd_ulong_sat_mul(vm_compute_budget.syscall_base_cost, len) );
  if ( FD_UNLIKELY( err ) ) return err;

  char msg[102400];
  ulong msg_len = (ulong) sprintf( msg, "Program data: " );

  ulong total = 0UL;
  for (ulong i = 0; i < len; ++i) {
    total += untranslated_fields[i].len;
    void const * translated_addr = fd_vm_translate_vm_to_host_const( ctx, untranslated_fields[i].addr, untranslated_fields[i].len, alignof(uchar) );
    /* TODO bounds check */
    char encoded[1500];
    ulong encoded_len = fd_base64_encode( encoded, translated_addr, untranslated_fields[i].len );
    if ( i != len-1 ) {
      sprintf( msg + msg_len, " ");
      msg_len++;
    }
    memcpy( msg + msg_len, encoded, encoded_len);
    msg_len += encoded_len;
  }
  err = fd_vm_consume_compute_meter( ctx, total );
  if ( FD_UNLIKELY( err ) ) return err;

  *pr0 = 0;
  fd_vm_log_collector_log( &ctx->log_collector, msg, msg_len );
  return FD_VM_SYSCALL_SUCCESS;

}

ulong
fd_vm_syscall_sol_memcpy(
    void *  _ctx,
    ulong   dst_vm_addr,
    ulong   src_vm_addr,
    ulong   n,
    ulong   r4 __attribute__((unused)),
    ulong   r5 __attribute__((unused)),
    ulong * pr0
) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  ulong err = fd_vm_mem_op_consume(ctx, n);
  if ( FD_UNLIKELY( err ) ) return err;

  /* Check for overlap */
  if ((dst_vm_addr <= src_vm_addr && src_vm_addr < dst_vm_addr + n)
  || (src_vm_addr <= dst_vm_addr && dst_vm_addr < src_vm_addr + n))
    return FD_VM_SYSCALL_ERR_MEM_OVERLAP;

  if ( n == 0 ) {
    *pr0 = 0;
    return FD_VM_SYSCALL_SUCCESS;
  }

  void *       dst_host_addr =
      fd_vm_translate_vm_to_host      ( ctx, dst_vm_addr, n, alignof(uchar) );
  if( FD_UNLIKELY( !dst_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  void const * src_host_addr =
      fd_vm_translate_vm_to_host_const( ctx, src_vm_addr, n, alignof(uchar) );
  if( FD_UNLIKELY( !src_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_memcpy(dst_host_addr, src_host_addr, n);

  *pr0 = 0;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_memcmp(
    void *  _ctx,
    ulong   vm_addr1,
    ulong   vm_addr2,
    ulong   n,
    ulong   cmp_result_vm_addr,
    ulong   r5 __attribute__((unused)),
    ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  ulong err = fd_vm_mem_op_consume(ctx, n);
  if ( FD_UNLIKELY( err ) ) return err;

  uchar const * host_addr1 =
      fd_vm_translate_vm_to_host_const( ctx, vm_addr1, n, alignof(uchar) );
  if( FD_UNLIKELY( !host_addr1 ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  uchar const * host_addr2 =
      fd_vm_translate_vm_to_host_const( ctx, vm_addr2, n, alignof(uchar) );
  if( FD_UNLIKELY( !host_addr2 ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  int * cmp_result_host_addr =
      fd_vm_translate_vm_to_host( ctx, cmp_result_vm_addr, sizeof(int), alignof(int) );
  if ( FD_UNLIKELY( !cmp_result_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  if( FD_UNLIKELY( (!host_addr1) | (!host_addr2) ) )
    return FD_VM_MEM_MAP_ERR_ACC_VIO;

  *pr0 = 0;

  for( ulong i = 0; i < n; i++ ) {
    uchar byte1 = host_addr1[i];
    uchar byte2 = host_addr2[i];

    if( byte1 != byte2 ) {
      *cmp_result_host_addr = (int)byte1 - (int)byte2;
      break;
    }
  }
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_memset(
    void *  _ctx,
    ulong   dst_vm_addr,
    ulong   c,
    ulong   n,
    ulong   r4 __attribute__((unused)),
    ulong   r5 __attribute__((unused)),
    ulong * ret
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  ulong err = fd_vm_mem_op_consume(ctx, n);
  if ( FD_UNLIKELY( err ) ) return err;

  void * dst_host_addr = fd_vm_translate_vm_to_host( ctx, dst_vm_addr, n, alignof(uchar) );
  if( FD_UNLIKELY( !dst_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_memset( dst_host_addr, (int)c, n );

  *ret = 0;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_memmove(
    void *  _ctx,
    ulong   dst_vm_addr,
    ulong   src_vm_addr,
    ulong   n,
    ulong   r4 __attribute__((unused)),
    ulong   r5 __attribute__((unused)),
    ulong * ret
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  ulong err = fd_vm_mem_op_consume(ctx, n);
  if ( FD_UNLIKELY( err ) ) return err;

  void *       dst_host_addr = fd_vm_translate_vm_to_host      ( ctx, dst_vm_addr, n, alignof(uchar) );
  if( FD_UNLIKELY( !dst_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  void const * src_host_addr = fd_vm_translate_vm_to_host_const( ctx, src_vm_addr, n, alignof(uchar) );
  if( FD_UNLIKELY( !src_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  /* FIXME: use fd_memcpy here? */
  memmove( dst_host_addr, src_host_addr, n );

  *ret = 0;

  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_invoke_signed_c(
    FD_FN_UNUSED void * _ctx,
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
    FD_FN_UNUSED void * _ctx,
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
    FD_FN_UNUSED void * _ctx,
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
    FD_FN_UNUSED void * _ctx,
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
    FD_FN_UNUSED void * _ctx,
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
    void * _ctx,
    FD_FN_UNUSED ulong arg0,
    FD_FN_UNUSED ulong arg1,
    FD_FN_UNUSED ulong arg2,
    FD_FN_UNUSED ulong arg3,
    FD_FN_UNUSED ulong arg4,
    ulong * ret
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  *ret = ctx->stack.frames_used;

  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_get_clock_sysvar(
    FD_FN_UNUSED void * _ctx,
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
    FD_FN_UNUSED void * _ctx,
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
    FD_FN_UNUSED void * _ctx,
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
    FD_FN_UNUSED void * _ctx,
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
fd_vm_syscall_sol_create_program_address(
    FD_FN_UNUSED void * _ctx,
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
fd_vm_syscall_sol_try_find_program_address(
    FD_FN_UNUSED void * _ctx,
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
fd_vm_syscall_sol_get_processed_sibling_instruction(
    FD_FN_UNUSED void * _ctx,
    FD_FN_UNUSED ulong arg0,
    FD_FN_UNUSED ulong arg1,
    FD_FN_UNUSED ulong arg2,
    FD_FN_UNUSED ulong arg3,
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
}
