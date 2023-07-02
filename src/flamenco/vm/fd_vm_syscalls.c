#include "fd_vm_syscalls.h"

#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/keccak256/fd_keccak256.h"
#include "../../ballet/blake3/fd_blake3.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/murmur3/fd_murmur3.h"
#include "../../ballet/sbpf/fd_sbpf_maps.c"
#include "fd_vm_cpi.h"

#include <stdio.h>


void
fd_vm_register_syscall( fd_sbpf_syscalls_t *    syscalls,
                        char const *            name,
                        fd_sbpf_syscall_fn_ptr_t  fn_ptr) {

  ulong name_len     = strlen(name);
  uint  syscall_hash = fd_murmur3_32( name, name_len, 0U );

  fd_sbpf_syscalls_t * syscall_entry = fd_sbpf_syscalls_insert( syscalls, syscall_hash );
  syscall_entry->func_ptr            = fn_ptr;
  syscall_entry->name = name;
}

void fd_vm_syscall_register_all( fd_sbpf_syscalls_t * syscalls ) {
  fd_vm_register_syscall( syscalls, "abort", fd_vm_syscall_abort );
  fd_vm_register_syscall( syscalls, "sol_panic_", fd_vm_syscall_sol_panic );

  fd_vm_register_syscall( syscalls, "sol_log_", fd_vm_syscall_sol_log );
  fd_vm_register_syscall( syscalls, "sol_log_64_", fd_vm_syscall_sol_log_64 );
  fd_vm_register_syscall( syscalls, "sol_log_compute_units_", fd_vm_syscall_sol_log );
  fd_vm_register_syscall( syscalls, "sol_log_pubkey", fd_vm_syscall_sol_log_pubkey );
  fd_vm_register_syscall( syscalls, "sol_log_data", fd_vm_syscall_sol_log_data );

  fd_vm_register_syscall( syscalls, "sol_sha256", fd_vm_syscall_sol_sha256 );
  fd_vm_register_syscall( syscalls, "sol_keccak256", fd_vm_syscall_sol_keccak256 );
  fd_vm_register_syscall( syscalls, "sol_blake3", fd_vm_syscall_sol_blake3 );
  fd_vm_register_syscall( syscalls, "sol_secp256k1_recover", fd_vm_syscall_sol_secp256k1_recover );

  fd_vm_register_syscall( syscalls, "sol_memcpy_", fd_vm_syscall_sol_memcpy );
  fd_vm_register_syscall( syscalls, "sol_memcmp_", fd_vm_syscall_sol_memcmp );
  fd_vm_register_syscall( syscalls, "sol_memset_", fd_vm_syscall_sol_memset );
  fd_vm_register_syscall( syscalls, "sol_memmove_", fd_vm_syscall_sol_memmove );

  fd_vm_register_syscall( syscalls, "sol_invoke_signed_c", fd_vm_syscall_sol_invoke_signed_c );
  fd_vm_register_syscall( syscalls, "sol_invoke_signed_rust", fd_vm_syscall_sol_invoke_signed_rust );
  fd_vm_register_syscall( syscalls, "sol_alloc_free_", fd_vm_syscall_sol_alloc_free );
  fd_vm_register_syscall( syscalls, "sol_set_return_data", fd_vm_syscall_sol_set_return_data );
  fd_vm_register_syscall( syscalls, "sol_get_return_data", fd_vm_syscall_sol_get_return_data );
  fd_vm_register_syscall( syscalls, "sol_get_stack_height", fd_vm_syscall_sol_get_stack_height );

  fd_vm_register_syscall( syscalls, "sol_get_clock_sysvar", fd_vm_syscall_sol_get_clock_sysvar );
  fd_vm_register_syscall( syscalls, "sol_get_epoch_schedule_sysvar", fd_vm_syscall_sol_get_epoch_schedule_sysvar );
  fd_vm_register_syscall( syscalls, "sol_get_fees_sysvar", fd_vm_syscall_sol_get_fees_sysvar );
  fd_vm_register_syscall( syscalls, "sol_get_rent_sysvar", fd_vm_syscall_sol_get_rent_sysvar );

  fd_vm_register_syscall( syscalls, "sol_create_program_address", fd_vm_syscall_sol_create_program_address );
  fd_vm_register_syscall( syscalls, "sol_try_find_program_address", fd_vm_syscall_sol_try_find_program_address );
  fd_vm_register_syscall( syscalls, "sol_get_processed_sibling_instruction", fd_vm_syscall_sol_get_processed_sibling_instruction );
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
fd_vm_syscall_sol_sha256(
    void * _ctx,
    ulong slices_addr,
    ulong slices_len,
    ulong res_addr,
    FD_FN_UNUSED ulong arg3,
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  void const * slices_raw = fd_vm_translate_vm_to_host( ctx, 0, slices_addr, slices_len * sizeof(fd_vm_syscall_bytes_slice_t) );
  if( FD_UNLIKELY( !slices_raw ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  void * hash = fd_vm_translate_vm_to_host( ctx, 1, res_addr, 32 );
  if( FD_UNLIKELY( !slices_raw ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_vm_syscall_bytes_slice_t * slices = (fd_vm_syscall_bytes_slice_t *)slices_raw;

  fd_sha256_t sha;
  fd_sha256_init( &sha );

  for( ulong i = 0; i < slices_len; i++ ) {
    void const * slice = fd_vm_translate_vm_to_host( ctx, 0, slices[i].addr, slices[i].len );
    if( FD_UNLIKELY( !slices_raw ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

    fd_sha256_append( &sha, slice, slices[i].len );
  }

  fd_sha256_fini( &sha, hash );
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_keccak256(
    void * _ctx,
    ulong slices_addr,
    ulong slices_len,
    ulong res_addr,
    FD_FN_UNUSED ulong arg3,
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  void const * slices_raw = fd_vm_translate_vm_to_host( ctx, 0, slices_addr, slices_len * sizeof(fd_vm_syscall_bytes_slice_t) );
  if( FD_UNLIKELY( !slices_raw ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  void * hash = fd_vm_translate_vm_to_host( ctx, 1, res_addr, 32 );
  if( FD_UNLIKELY( !slices_raw ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_vm_syscall_bytes_slice_t * slices = (fd_vm_syscall_bytes_slice_t *) slices_raw;

  fd_keccak256_t sha;
  fd_keccak256_init(&sha);

  for (ulong i = 0; i < slices_len; i++) {
    void const * slice = fd_vm_translate_vm_to_host(ctx, 0, slices[i].addr, slices[i].len );
    if( FD_UNLIKELY( !slices_raw ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

    fd_keccak256_append( &sha, slice, slices[i].len );
  }

  fd_keccak256_fini(&sha, hash);
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_blake3(
    FD_FN_UNUSED void * _ctx,
    ulong slices_addr,
    ulong slices_len,
    ulong res_addr,
    FD_FN_UNUSED ulong arg3,
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  void const * slices_raw = fd_vm_translate_vm_to_host( ctx, 0, slices_addr, slices_len * sizeof(fd_vm_syscall_bytes_slice_t) );
  if( FD_UNLIKELY( !slices_raw ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  void * hash = fd_vm_translate_vm_to_host( ctx, 1, res_addr, 32 );
  if( FD_UNLIKELY( !slices_raw ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_vm_syscall_bytes_slice_t * slices = (fd_vm_syscall_bytes_slice_t *) slices_raw;

  fd_blake3_t sha;
  fd_blake3_init(&sha);

  for (ulong i = 0; i < slices_len; i++) {
    void const * slice = fd_vm_translate_vm_to_host( ctx, 0, slices[i].addr, slices[i].len );
    if( FD_UNLIKELY( !slices_raw ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

    fd_blake3_append( &sha, slice, slices[i].len );
  }

  fd_blake3_fini( &sha, hash );
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
    void  * _ctx,
    ulong msg_vm_addr,
    ulong msg_len,
    FD_FN_UNUSED ulong arg2,
    FD_FN_UNUSED ulong arg3,
    FD_FN_UNUSED ulong arg4,
    ulong * ret
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  void const * msg_host_addr = fd_vm_translate_vm_to_host( ctx, 0, msg_vm_addr, msg_len );
  if( FD_UNLIKELY( !msg_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_vm_log_collector_log( &ctx->log_collector, msg_host_addr, msg_len );

  *ret = 0;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_log_64(
    void * _ctx,
    ulong arg0,
    ulong arg1,
    ulong arg2,
    ulong arg3,
    ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  char msg[1024];

  int msg_len = sprintf(msg, "Program log: %lx %lx %lx %lx %lx", arg0, arg1, arg2, arg3, arg4);

  fd_vm_log_collector_log( &ctx->log_collector, msg, (ulong)msg_len );

  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_log_pubkey(
    void * _ctx,
    ulong pubkey_vm_addr,
    FD_FN_UNUSED ulong arg1,
    FD_FN_UNUSED ulong arg2,
    FD_FN_UNUSED ulong arg3,
    FD_FN_UNUSED ulong arg4,
    FD_FN_UNUSED ulong * ret
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  char msg[128];
  char pubkey_str[FD_BASE58_ENCODED_32_SZ];

  /* FIXME Really need write here? */
  void * pubkey_host_addr = fd_vm_translate_vm_to_host( ctx, 1, pubkey_vm_addr, 32 );
  if( FD_UNLIKELY( !pubkey_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_base58_encode_32( pubkey_host_addr, NULL, pubkey_str );

  int msg_len = sprintf( msg, "Program log: %s", pubkey_str );

  fd_vm_log_collector_log( &ctx->log_collector, msg, (ulong)msg_len );

  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_log_compute_units(
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
fd_vm_syscall_sol_log_data(
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
fd_vm_syscall_sol_memcpy(
    void * _ctx,
    ulong dst_vm_addr,
    ulong src_vm_addr,
    ulong n,
    FD_FN_UNUSED ulong arg3,
    FD_FN_UNUSED ulong arg4,
    ulong * ret
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  /* Check for overlap */
  /*
  if (src_vm_addr <= (dst_vm_addr + n) && dst_vm_addr <= (src_vm_addr + n)) {
    return FD_VM_SYSCALL_ERR_MEM_OVERLAP;
  }
  */

  void *       dst_host_addr = fd_vm_translate_vm_to_host( ctx, 1, dst_vm_addr, n );
  void const * src_host_addr = fd_vm_translate_vm_to_host( ctx, 0, src_vm_addr, n );

  if( FD_UNLIKELY( (!dst_host_addr) | (!src_host_addr) ) )
    return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_memcpy(dst_host_addr, src_host_addr, n);

  *ret = 0;

  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_memcmp(
    void * _ctx,
    ulong vm_addr1,
    ulong vm_addr2,
    ulong n,
    FD_FN_UNUSED ulong arg3,
    FD_FN_UNUSED ulong arg4,
    ulong * ret
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  void const * host_addr1 = fd_vm_translate_vm_to_host( ctx, 0, vm_addr1, n );
  void const * host_addr2 = fd_vm_translate_vm_to_host( ctx, 0, vm_addr2, n );

  if( FD_UNLIKELY( (!host_addr1) | (!host_addr2) ) )
    return FD_VM_MEM_MAP_ERR_ACC_VIO;

  *ret = (ulong)memcmp(host_addr1, host_addr2, n);

  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_memset(
    void * _ctx,
    ulong dst_vm_addr,
    ulong c,
    ulong n,
    FD_FN_UNUSED ulong arg3,
    FD_FN_UNUSED ulong arg4,
    ulong * ret
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  void * dst_host_addr = fd_vm_translate_vm_to_host( ctx, 1, dst_vm_addr, n );
  if( FD_UNLIKELY( !dst_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_memset( dst_host_addr, (int)c, n );

  *ret = dst_vm_addr;

  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_memmove(
    void * _ctx,
    ulong dst_vm_addr,
    ulong src_vm_addr,
    ulong n,
    FD_FN_UNUSED ulong arg3,
    FD_FN_UNUSED ulong arg4,
    ulong * ret
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  void *       dst_host_addr = fd_vm_translate_vm_to_host( ctx, 1, dst_vm_addr, n );
  void const * src_host_addr = fd_vm_translate_vm_to_host( ctx, 0, src_vm_addr, n );

  if( FD_UNLIKELY( (!dst_host_addr) | (!src_host_addr) ) )
    return FD_VM_MEM_MAP_ERR_ACC_VIO;

  /* FIXME use fd_memcpy here? */
  memmove( dst_host_addr, src_host_addr, n );

  *ret = dst_vm_addr;

  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_invoke_signed_c(
    FD_FN_UNUSED void * _ctx,
    FD_FN_UNUSED ulong instruction_va,
    FD_FN_UNUSED ulong acct_infos_va,
    FD_FN_UNUSED ulong acct_info_cnt,
    FD_FN_UNUSED ulong signers_seeds_va,
    FD_FN_UNUSED ulong signers_seeds_cnt,
    FD_FN_UNUSED ulong * ret
) {
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
}

ulong
fd_vm_syscall_sol_invoke_signed_rust(
    void * _ctx,
    ulong instruction_va,
    ulong acct_infos_va,
    ulong acct_info_cnt,
    ulong signers_seeds_va,
    ulong signers_seeds_cnt,
    FD_FN_UNUSED ulong * ret
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  /* TODO Consume syscall invoke fee compute units */

  /* Pre-flight checks ************************************************/

  /* Solana Labs does these checks after address translation.
     We do them before to avoid length overflow.
     This can change the error code, but consensus does not care -
     Protocol error conditions are only qualitative, not quantitative. */

  /* Check signer count */

  if( FD_UNLIKELY( signers_seeds_cnt > 11UL ) )
    /* TODO use MAX_SIGNERS constant */
    FD_LOG_ERR(("TODO: return too many signers" ));

  /* Check account info count */

  if( FD_UNLIKELY( acct_info_cnt > 64UL ) )
    FD_LOG_ERR(( "TODO: return max instruction account infos exceeded" ));

  /* Translate instruction ********************************************/

  /* TODO check alignment */
  fd_vm_rust_instruction_t const * instruction =
    fd_vm_translate_vm_to_host(
      _ctx,
      0 /* write */,
      instruction_va,
      sizeof(fd_vm_rust_instruction_t) );
  if( FD_UNLIKELY( !instruction ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  /* TODO Check instruction size */

  fd_vm_rust_account_meta_t const * accounts =
    fd_vm_translate_vm_to_host(
      ctx,
      0 /* write */,
      acct_infos_va,
      acct_info_cnt * sizeof(fd_vm_rust_account_meta_t) );
  if( FD_UNLIKELY( !accounts ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  /* TODO consume compute meter proportionally to data sz */

  uchar const * data = fd_vm_translate_vm_to_host(
      ctx,
      0 /* write */,
      instruction->data.addr,
      instruction->data.len );
  if( FD_UNLIKELY( !data ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  /* Translate signers ************************************************/

  /* Order of operations is liberally rearranged.
     For inputs that cause multiple errors, this means that Solana Labs
     and Firedancer may return different error codes (as we abort at the
     first error).  Again, we don't mind as consensus is not aware of
     error codes, but only of the existence of an arbitrary error or
     success. */

  fd_pubkey_t signers[11];
  if( signers_seeds_cnt>0UL ) {
    /* Translate &[&[&[u8]]].
       Outer slice addr and cnt provided as r4, r5.
       Inner slice params stored in memory */
    fd_vm_rust_slice_t const * seeds = fd_vm_translate_vm_to_host(
        ctx,
        0 /* write */,
        signers_seeds_va,
        signers_seeds_cnt * sizeof(fd_vm_rust_slice_t) );
    if( FD_UNLIKELY( !seeds ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

    /* Create program addresses.
       TODO use MAX_SIGNERS constant */

    for( ulong i=0UL; i<signers_seeds_cnt; i++ ) {

      /* Check seed count (avoid overflow) */
      /* TODO use constant */
      if( FD_UNLIKELY( seeds[i].len > 16UL ) )
        FD_LOG_ERR(("TODO: return MaxSeedLengthExceeded" ));

      /* Translate inner seed slice (type &[&[u8]]) */
      fd_vm_rust_slice_t const * seed = fd_vm_translate_vm_to_host(
          ctx,
          0 /* write */,
          seeds[i].addr,
          seeds[i].len );
      if( FD_UNLIKELY( !seed ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

      /* Derive program address.
         Matches Pubkey::create_program_address */

      fd_sha256_t _sha[1];
      fd_sha256_t * sha = fd_sha256_init( fd_sha256_join( fd_sha256_new( _sha ) ) );

      for( ulong i=0UL; i < seed->len; i++ ) {
        /* Check seed limb length */
        /* TODO use constant */
        if( FD_UNLIKELY( seed[i].len > 32 ) )
          FD_LOG_ERR(("TODO: return MaxSeedLengthExceeded" ));

        /* Translate inner seed limb (type &[u8]) */
        uchar const * seed_limb = fd_vm_translate_vm_to_host(
            ctx,
            0 /* write */,
            seed[i].addr,
            seed[i].len );
        if( FD_UNLIKELY( !seed_limb ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

        fd_sha256_append( sha, seed_limb, seed[i].len );
      }

      /* TODO hash program ID */
      /* TODO use char const[] symbol for PDA marker */
      fd_sha256_append( sha, "ProgramDerivedAddress", 21UL );
      fd_sha256_fini  ( sha, &signers[i].uc );
      /* TODO check if off curve point */
    }
  }

  /* TODO prepare accounts */

  /* Translate account infos ******************************************/

  fd_vm_rust_account_info_t const * acc_infos =
    fd_vm_translate_vm_to_host(
      ctx,
      0 /* write */,
      acct_infos_va,
      acct_info_cnt * sizeof(fd_vm_rust_account_info_t) );
  if( FD_UNLIKELY( !acc_infos ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  /* Collect pubkeys */

  fd_pubkey_t * acct_keys =
    fd_alloca_check( /* align */ 1UL, /* sz */ acct_info_cnt * sizeof(fd_pubkey_t) );

  for( ulong i=0UL; i<acct_info_cnt; i++ ) {
    /* Extract address of account info */

    fd_pubkey_t const * acct_addr = fd_vm_translate_vm_to_host(
        ctx,
        0 /* write */,
        acc_infos[i].pubkey_addr,
        sizeof(fd_pubkey_t) );
    if( FD_UNLIKELY( !acct_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

    /* Copy address */

    memcpy( acct_keys[i].uc, acct_addr->uc, sizeof(fd_pubkey_t) );
  }

  /* TODO: Dispatch CPI to executor.
           For now, we'll just log parameters. */

  FD_LOG_WARNING(( "TODO implement CPIs" ));
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
}

ulong
fd_vm_syscall_sol_alloc_free( void * _ctx,
                              ulong sz,
                              ulong free_addr,
                              FD_FN_UNUSED ulong r3,
                              FD_FN_UNUSED ulong r4,
                              FD_FN_UNUSED ulong r5,
                              ulong * ret ) {

  /* Value to return */
  ulong r0 = 0UL;

  /* TODO Get suitable alignment size based on invoke context */
  ulong align = 1UL;

  fd_vm_exec_context_t * ctx     = (fd_vm_exec_context_t *) _ctx;
  fd_vm_heap_allocator_t * alloc = &ctx->alloc;

  /* Non-zero free address implies that this is a free() call.
     However, we provide a bump allocator, so free is a no-op. */

  if( free_addr ) goto fini;

  /* Rest of function provides malloc() ... */

  ulong pos   = fd_ulong_align_up( alloc->offset, align );
  ulong vaddr = fd_ulong_sat_add ( pos,           FD_VM_MEM_MAP_HEAP_REGION_START );
        pos   = fd_ulong_sat_add ( pos,           sz    );

  /* Bail if allocation overruns heap size */

  if( FD_UNLIKELY( pos > alloc->heap_sz ) ) goto fini;

  /* Success. Return virtual address of allocation and update allocator */

  r0            = vaddr;
  alloc->offset = pos;

fini:
  *ret = r0;
  return FD_VM_SYSCALL_SUCCESS;
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

/* fd_vm_partial_derive_address begins the SHA calculation for a program
   derived account address.  sha is an uninitialized, joined SHA state
   object. program_id_vaddr points to the program address in VM address
   space. seeds_vaddr points to the first element of an iovec-like
   scatter of a seed byte array (&[&[u8]]) in VM address space.
   seed_cnt is the number of scatter elems.  Returns in-flight sha
   calculation on success.  On failure, returns NULL.  Reasons for
   failure include out-of-bounds memory access or invalid seed list. */

static fd_sha256_t *
fd_vm_partial_derive_address( fd_vm_exec_context_t * ctx,
                              fd_sha256_t *          sha,
                              ulong                  program_id_vaddr,
                              ulong                  seeds_vaddr,
                              ulong                  seeds_cnt ) {

  /* TODO use constant macro */
  if( FD_UNLIKELY( seeds_cnt > 16UL ) ) return NULL;

  /* Translate program ID address */

  fd_pubkey_t const * program_id = fd_vm_translate_vm_to_host(
      ctx,
      0 /* write */,
      program_id_vaddr,
      sizeof(fd_pubkey_t) );

  /* Translate seed scatter array address */

  fd_vm_rust_slice_t const * seeds = fd_vm_translate_vm_to_host(
      ctx,
      0 /* write */,
      seeds_vaddr,
      /* no overflow, as seeds_cnt<=16UL */
      seeds_cnt * sizeof(fd_vm_rust_vec_t) );

  /* Bail if translation fails */

  if( FD_UNLIKELY( ( !program_id )
                 | ( !seeds      ) ) ) return NULL;

  /* Start hashing */

  fd_sha256_init( sha );
  fd_sha256_append( sha, program_id, sizeof(fd_pubkey_t) );

  for( ulong i=0UL; i<seeds_cnt; i++ ) {

    /* Refuse to hash overlong parts */

    if( FD_UNLIKELY( seeds[ i ].len > 32UL ) ) return NULL;

    /* Translate seed */

    void const * seed_part = fd_vm_translate_vm_to_host(
        ctx,
        0 /* write */,
        seeds[ i ].addr,
        seeds[ i ].len );
    if( FD_UNLIKELY( !seed_part ) ) return NULL;

    /* Append to hash (gather) */

    fd_sha256_append( sha, seed_part, seeds[ i ].len );

  }

  return sha;
}

ulong
fd_vm_syscall_sol_create_program_address(
    void *  _ctx,
    ulong   seeds_vaddr,
    ulong   seeds_cnt,
    ulong   program_id_vaddr,
    ulong   out_vaddr,
    ulong   r5,
    ulong * ret )  {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *)_ctx;
  (void)r5;
  ulong r0 = 1UL;  /* 1 implies fail */

  /* TODO charge CUs */

  /* Calculate PDA */

  fd_sha256_t _sha[1];
  fd_sha256_t * sha = fd_sha256_join( fd_sha256_new( _sha ) );
  if( FD_UNLIKELY( !fd_vm_partial_derive_address( ctx, sha, program_id_vaddr, seeds_vaddr, seeds_cnt ) ) )
    return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_pubkey_t result;
  fd_sha256_fini( sha, &result );

  /* Return failure if PDA overlaps with a valid curve point */

  if( FD_UNLIKELY( fd_ed25519_validate_public_key( &result ) ) )
    goto fini;

  /* Translate output address
     Cannot reorder - Out may be an invalid pointer if PDA is invalid */

  fd_pubkey_t * out = fd_vm_translate_vm_to_host(
      ctx,
      1 /* write */,
      out_vaddr,
      sizeof(fd_pubkey_t) );
  if( FD_UNLIKELY( !out ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  /* Write result into out */

  memcpy( out, result.uc, sizeof(fd_pubkey_t) );
  r0 = 0UL; /* success */

fini:
  fd_sha256_delete( fd_sha256_leave( sha ) );
  *ret = r0;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_try_find_program_address(
    void *  _ctx,
    ulong   seeds_vaddr,
    ulong   seeds_cnt,
    ulong   program_id_vaddr,
    ulong   out_vaddr,
    ulong   bump_seed_vaddr,
    ulong * ret ) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *)_ctx;
  ulong r0 = 1UL;  /* 1 implies fail */

  /* TODO charge CUs */

  /* Similar to create_program_address, but suffixes a 1 byte nonce
     that it decrements from 255 down to 1, until a valid PDA is found.

     Solana Labs recomputes the SHA hash for each iteration here. We
     leverage SHA's streaming properties to precompute all but the last
     two blocks (1 data, 0 or 1 padding). */

  fd_sha256_t _sha[2];
  fd_sha256_t * sha0 = fd_sha256_join( fd_sha256_new( _sha     ) );
  fd_sha256_t * sha1 = fd_sha256_join( fd_sha256_new( _sha + 1 ) );

  /* Translate outputs but delay validation.

     In the unlikely case that none of the 255 iterations yield a valid
     PDA, Solana Labs never validates whether out_vaddr is a valid
     pointer */

  fd_pubkey_t * address_out = fd_vm_translate_vm_to_host(
      ctx,
      1 /* write */,
      out_vaddr,
      sizeof(fd_pubkey_t) );

  uchar * bump_seed_out = fd_vm_translate_vm_to_host(
      ctx,
      1 /* write */,
      bump_seed_vaddr,
      1UL );

  /* Calculate PDA prefix */

  if( FD_UNLIKELY( !fd_vm_partial_derive_address( ctx, sha0, program_id_vaddr, seeds_vaddr, seeds_cnt ) ) )
    return FD_VM_MEM_MAP_ERR_ACC_VIO;

  /* Iterate through bump prefix and hash */

  fd_pubkey_t result;
  for( ulong i=255UL; i>0UL; i-- ) {

    /* Compute PDA on copy of SHA state */

    memcpy( sha1, sha0, FD_SHA256_FOOTPRINT );

    uchar suffix[1] = {(uchar)i};
    fd_sha256_append( sha1, suffix, 1UL );
    fd_sha256_fini  ( sha1, &result );

    /* PDA is valid if it's not a curve point */

    if( FD_LIKELY( !fd_ed25519_validate_public_key( &result ) ) ) {

      /* Delayed translation and overlap check */

      if( FD_UNLIKELY( ( !address_out   )
                     | ( !bump_seed_out )
                     | ( (ulong)address_out+32UL  >= (ulong)bump_seed_out )
                     | ( (ulong)bump_seed_out+1UL >= (ulong)address_out   ) ) )
        return FD_VM_MEM_MAP_ERR_ACC_VIO;

      /* Write results */

      *bump_seed_out = (uchar)i;
      memcpy( address_out, result.uc, sizeof(fd_pubkey_t) );
      r0 = 0UL; /* success */
      goto fini;

    }

  }

  /* Exhausted all 255 iterations and failed to find a valid PDA.
     Return failure. */

fini:
  fd_sha256_delete( fd_sha256_leave( sha0 ) );
  fd_sha256_delete( fd_sha256_leave( sha1 ) );
  *ret = r0;
  return FD_VM_SYSCALL_SUCCESS;
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
