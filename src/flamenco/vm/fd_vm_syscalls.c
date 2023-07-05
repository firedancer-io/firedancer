#include "fd_vm_syscalls.h"

#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/keccak256/fd_keccak256.h"
#include "../../ballet/blake3/fd_blake3.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/murmur3/fd_murmur3.h"
#include "../../ballet/sbpf/fd_sbpf_maps.c"
#include "fd_vm_context.h"
#include "fd_vm_cpi.h"
#include "../runtime/sysvar/fd_sysvar.h"

#include <stdio.h>


void
fd_vm_register_syscall( fd_sbpf_syscalls_t *     syscalls,
                        char const *             name,
                        fd_sbpf_syscall_fn_ptr_t fn_ptr) {

  ulong name_len     = strlen(name);
  uint  syscall_hash = fd_murmur3_32( name, name_len, 0U );

  fd_sbpf_syscalls_t * syscall_entry = fd_sbpf_syscalls_insert( syscalls, syscall_hash );
  syscall_entry->func_ptr            = fn_ptr;
  syscall_entry->name = name;
}

void
fd_vm_syscall_register_all( fd_sbpf_syscalls_t * syscalls ) {
  fd_vm_register_syscall( syscalls, "abort",                  fd_vm_syscall_abort     );
  fd_vm_register_syscall( syscalls, "sol_panic_",             fd_vm_syscall_sol_panic );

  fd_vm_register_syscall( syscalls, "sol_log_",               fd_vm_syscall_sol_log        );
  fd_vm_register_syscall( syscalls, "sol_log_64_",            fd_vm_syscall_sol_log_64     );
  fd_vm_register_syscall( syscalls, "sol_log_compute_units_", fd_vm_syscall_sol_log        );
  fd_vm_register_syscall( syscalls, "sol_log_pubkey",         fd_vm_syscall_sol_log_pubkey );
  fd_vm_register_syscall( syscalls, "sol_log_data",           fd_vm_syscall_sol_log_data   );

  fd_vm_register_syscall( syscalls, "sol_sha256",             fd_vm_syscall_sol_sha256            );
  fd_vm_register_syscall( syscalls, "sol_keccak256",          fd_vm_syscall_sol_keccak256         );
  fd_vm_register_syscall( syscalls, "sol_blake3",             fd_vm_syscall_sol_blake3            );
  fd_vm_register_syscall( syscalls, "sol_secp256k1_recover",  fd_vm_syscall_sol_secp256k1_recover );

  fd_vm_register_syscall( syscalls, "sol_memcpy_",            fd_vm_syscall_sol_memcpy  );
  fd_vm_register_syscall( syscalls, "sol_memcmp_",            fd_vm_syscall_sol_memcmp  );
  fd_vm_register_syscall( syscalls, "sol_memset_",            fd_vm_syscall_sol_memset  );
  fd_vm_register_syscall( syscalls, "sol_memmove_",           fd_vm_syscall_sol_memmove );

  fd_vm_register_syscall( syscalls, "sol_invoke_signed_c",           fd_vm_syscall_cpi_c                );
  fd_vm_register_syscall( syscalls, "sol_invoke_signed_rust",        fd_vm_syscall_cpi_rust             );
  fd_vm_register_syscall( syscalls, "sol_alloc_free_",               fd_vm_syscall_sol_alloc_free       );
  fd_vm_register_syscall( syscalls, "sol_set_return_data",           fd_vm_syscall_sol_set_return_data  );
  fd_vm_register_syscall( syscalls, "sol_get_return_data",           fd_vm_syscall_sol_get_return_data  );
  fd_vm_register_syscall( syscalls, "sol_get_stack_height",          fd_vm_syscall_sol_get_stack_height );

  fd_vm_register_syscall( syscalls, "sol_get_clock_sysvar",          fd_vm_syscall_sol_get_clock_sysvar          );
  fd_vm_register_syscall( syscalls, "sol_get_epoch_schedule_sysvar", fd_vm_syscall_sol_get_epoch_schedule_sysvar );
  fd_vm_register_syscall( syscalls, "sol_get_fees_sysvar",           fd_vm_syscall_sol_get_fees_sysvar           );
  fd_vm_register_syscall( syscalls, "sol_get_rent_sysvar",           fd_vm_syscall_sol_get_rent_sysvar           );

  fd_vm_register_syscall( syscalls, "sol_create_program_address",            fd_vm_syscall_sol_create_program_address            );
  fd_vm_register_syscall( syscalls, "sol_try_find_program_address",          fd_vm_syscall_sol_try_find_program_address          );
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
    void *  _ctx,
    ulong   msg_vaddr,
    ulong   msg_len,
    ulong   r3,
    ulong   r4,
    ulong   r5,
    ulong * pr0 ) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  (void)r3; (void)r4; (void)r5; (void)pr0;

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

  /* TODO don't hardcode limit */
  if( FD_UNLIKELY( slices_cnt > 20000UL ) )
    return FD_VM_SYSCALL_ERR_INVAL;
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

  /* TODO don't hardcode limit */
  if( FD_UNLIKELY( slices_cnt > 20000UL ) )
    return FD_VM_SYSCALL_ERR_INVAL;
  ulong slices_sz = slices_cnt * sizeof(fd_vm_vec_t);

  fd_vm_vec_t const * slices =
      fd_vm_translate_vm_to_host_const( ctx, slices_vaddr, slices_sz, FD_VM_VEC_ALIGN );
  void * hash =
      fd_vm_translate_vm_to_host      ( ctx, res_vaddr,    32UL,      alignof(uchar)  );

  if( FD_UNLIKELY( (!slices) | (!hash) ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_keccak256_t sha;
  fd_keccak256_init(&sha);

  for (ulong i = 0; i < slices_cnt; i++) {
    void const * slice = fd_vm_translate_vm_to_host( ctx, slices[i].addr, slices[i].len, alignof(uchar) );
    if( FD_UNLIKELY( !slice ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

    fd_keccak256_append( &sha, slice, slices[i].len );
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
  if( FD_UNLIKELY( slices_cnt > 20000UL ) )
    return FD_VM_SYSCALL_ERR_INVAL;
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
    void *  _ctx,
    ulong   dst_vm_addr,
    ulong   src_vm_addr,
    ulong   n,
    ulong   r4 __attribute__((unused)),
    ulong   r5 __attribute__((unused)),
    ulong * pr0
) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  /* Check for overlap */
  /*
  if (src_vm_addr <= (dst_vm_addr + n) && dst_vm_addr <= (src_vm_addr + n)) {
    return FD_VM_SYSCALL_ERR_MEM_OVERLAP;
  }
  */

  void *       dst_host_addr =
      fd_vm_translate_vm_to_host      ( ctx, dst_vm_addr, n, alignof(uchar) );
  void const * src_host_addr =
      fd_vm_translate_vm_to_host_const( ctx, src_vm_addr, n, alignof(uchar) );

  if( FD_UNLIKELY( (!dst_host_addr) | (!src_host_addr) ) )
    return FD_VM_MEM_MAP_ERR_ACC_VIO;

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
    ulong   r4 __attribute__((unused)),
    ulong   r5 __attribute__((unused)),
    ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  void const * host_addr1 =
      fd_vm_translate_vm_to_host_const( ctx, vm_addr1, n, alignof(uchar) );
  void const * host_addr2 =
      fd_vm_translate_vm_to_host_const( ctx, vm_addr2, n, alignof(uchar) );

  if( FD_UNLIKELY( (!host_addr1) | (!host_addr2) ) )
    return FD_VM_MEM_MAP_ERR_ACC_VIO;

  *pr0 = (ulong)memcmp(host_addr1, host_addr2, n);
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

  void * dst_host_addr = fd_vm_translate_vm_to_host( ctx, dst_vm_addr, n, alignof(uchar) );
  if( FD_UNLIKELY( !dst_host_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_memset( dst_host_addr, (int)c, n );

  *ret = dst_vm_addr;
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

  void *       dst_host_addr = fd_vm_translate_vm_to_host      ( ctx, dst_vm_addr, n, alignof(uchar) );
  void const * src_host_addr = fd_vm_translate_vm_to_host_const( ctx, src_vm_addr, n, alignof(uchar) );

  if( FD_UNLIKELY( (!dst_host_addr) | (!src_host_addr) ) )
    return FD_VM_MEM_MAP_ERR_ACC_VIO;

  /* FIXME use fd_memcpy here? */
  memmove( dst_host_addr, src_host_addr, n );

  *ret = dst_vm_addr;

  return FD_VM_SYSCALL_SUCCESS;
}

/**********************************************************************
   CROSS PROGRAM INVOCATION (Generic logic)
 **********************************************************************/

/* FD_CPI_MAX_SIGNER_CNT is the max amount of PDA signer addresses that
   a cross-program invocation can include in an instruction. */

#define FD_CPI_MAX_SIGNER_CNT (16UL)

/* fd_vm_syscall_cpi_preflight_check contains common argument checks
   for cross-program invocations.

   Solana Labs does these checks after address translation.
   We do them before to avoid length overflow.  Reordering checks can
   change the error code, but this is fine as consensus only cares about
   whether an error occurred at all or not. */

static ulong
fd_vm_syscall_cpi_preflight_check( ulong signers_seeds_cnt,
                                   ulong acct_info_cnt ) {

  /* TODO use MAX_SIGNERS constant */

  if( FD_UNLIKELY( signers_seeds_cnt > FD_CPI_MAX_SIGNER_CNT ) ) {
    FD_LOG_WARNING(("TODO: return too many signers" ));
    return FD_VM_SYSCALL_ERR_INVAL;
  }

  if( FD_UNLIKELY( acct_info_cnt > 64UL ) ) {
    FD_LOG_ERR(( "TODO: return max instruction account infos exceeded" ));
    return FD_VM_SYSCALL_ERR_INVAL;
  }

  return FD_VM_SYSCALL_SUCCESS;
}

/* fd_vm_syscall_cpi_check_instruction contains common instruction acct
   count and data sz checks.  Also consumes compute units proportional
   to instruction data size. */

static ulong
fd_vm_syscall_cpi_check_instruction( fd_vm_exec_context_t const * ctx,
                                     ulong                        acct_cnt,
                                     ulong                        data_sz ) {

  if( ctx->instr_ctx.global->features.loosen_cpi_size_restriction ) {
    if( FD_UNLIKELY( data_sz > 0x2800UL ) ) {
      FD_LOG_WARNING(( "cpi: data too long (%#lx)", data_sz ));
      return FD_VM_SYSCALL_ERR_INVAL;
    }
    if( FD_UNLIKELY( acct_cnt > 0xFFUL ) ) {
      FD_LOG_WARNING(( "cpi: too many accounts (%#lx)", acct_cnt ));
      return FD_VM_SYSCALL_ERR_INVAL;
    }
  } else {
    ulong tot_sz;
    int too_long  = __builtin_umull_overflow( acct_cnt, sizeof(fd_vm_c_account_meta_t), &tot_sz );
        too_long |= __builtin_uaddl_overflow( tot_sz, data_sz, &tot_sz );
    if( FD_UNLIKELY( too_long ) ) {
      FD_LOG_WARNING(( "cpi: instruction too long (%#lx)", tot_sz ));
      return FD_VM_SYSCALL_ERR_INVAL;
    }
  }

  return FD_VM_SYSCALL_SUCCESS;
}

/* fd_vm_syscall_pdas_t is buffer holding program derived accounts. */

struct fd_vm_syscall_pdas_t {
  ulong         idx;  /* <=FD_CPI_MAX_SIGNER_CNT */
  fd_pubkey_t * keys; /* cnt==FD_CPI_MAX_SIGNER_CNT */
  fd_sha256_t   sha[1];
};

typedef struct fd_vm_syscall_pdas_t fd_vm_syscall_pdas_t;

/* fd_vm_syscall_pdas_{new,join,leave,delete} follows the Firedancer
   object lifecycle pattern. */

static inline void *
fd_vm_syscall_pdas_new( void *        mem,
                        fd_pubkey_t * keys ) {

  fd_vm_syscall_pdas_t * pdas = (fd_vm_syscall_pdas_t *)mem;
  *pdas = (fd_vm_syscall_pdas_t) {
    .idx  = 0UL,
    .keys = keys
  };

  fd_sha256_new( &pdas->sha );

  return mem;
}

static inline fd_vm_syscall_pdas_t * fd_vm_syscall_pdas_join( void * mem ) { return (fd_vm_syscall_pdas_t *)mem; }
static inline void * fd_vm_syscall_pdas_leave( fd_vm_syscall_pdas_t * pdas ) { return (void *)pdas; }
static inline void * fd_vm_syscall_pdas_delete( fd_vm_syscall_pdas_t * pdas ) { return (void *)pdas; }

/* fd_vm_syscall_pda_next starts the calculation of a program derived
   address.  Panics if called more than FD_CPI_MAX_SIGNER_CNT times. */

static void
fd_vm_syscall_pda_next( fd_vm_exec_context_t const * ctx,
                        fd_vm_syscall_pdas_t *       pdas ) {
  FD_TEST( pdas->idx < FD_CPI_MAX_SIGNER_CNT );

  fd_sha256_t * sha = fd_sha256_join( pdas->sha );
  fd_sha256_init  ( sha );
  fd_sha256_append( sha, &ctx->instr_ctx.txn_ctx->txn_raw[ ctx->instr_ctx.instr->program_id ], sizeof(fd_pubkey_t) );
  fd_sha256_leave ( sha );
}

/* fd_vm_syscall_pda_seed_append adds a seed to the hash state that will
   eventually produce the program derived address. */

static void
fd_vm_syscall_pda_seed_append( fd_vm_syscall_pdas_t * pdas,
                               uchar const *          piece,
                               ulong                  piece_sz ) {
  fd_sha256_leave( fd_sha256_append( fd_sha256_join( pdas->sha ), piece, piece_sz ) );
}

/* fd_vm_syscall_pda_fini finalizes the current PDA calculation.
   Returns pointer to resulting pubkey on success.  Pointer is valid for
   duration of join.  On failure, returns NULL.  Reasons for failure
   include address is not a valid PDA. */

static fd_pubkey_t const *
fd_vm_syscall_pda_fini( fd_vm_syscall_pdas_t * pdas ) {
  fd_pubkey_t * pda = &pdas->keys[ pdas->idx ];

  fd_sha256_t * sha = fd_sha256_join( pdas->sha );
  /* TODO use char const[] symbol for PDA marker */
  fd_sha256_append( sha, "ProgramDerivedAddress", 21UL );
  fd_sha256_fini  ( sha, pda->uc );
  fd_sha256_leave ( sha );

  /* A PDA is valid if is not an Ed25519 curve point */
  if( FD_UNLIKELY(fd_ed25519_validate_public_key( pda->key ) != 0) ) return NULL;

  pdas->idx++;
  return (fd_pubkey_t const *)pda;
}

/* fd_vm_syscall_cpi_derive_signers loads a vector of PDA derive
   paths provided by the user.  Part of fd_vm_syscall_cpi_{c,rust}.
   This code was implemented twice in Solana Labs (for C and Rust ABIs
   respectively), but the logic is identical. */

static ulong
fd_vm_syscall_cpi_derive_signers_( fd_vm_exec_context_t * ctx,
                                   fd_vm_syscall_pdas_t * pdas,
                                   ulong signers_seeds_va,
                                   ulong signers_seeds_cnt ) {

  /* Translate array of seeds.  Each seed is an array of byte arrays. */
  fd_vm_vec_t const * seeds = fd_vm_translate_vm_to_host_const(
      ctx,
      signers_seeds_va,
      signers_seeds_cnt * sizeof(fd_vm_vec_t),
      FD_VM_VEC_ALIGN );
  if( FD_UNLIKELY( !seeds ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  /* Create program addresses.
      TODO use MAX_SIGNERS constant */

  for( ulong i=0UL; i<signers_seeds_cnt; i++ ) {

    /* Check seed count (avoid overflow) */
    /* TODO use constant */
    if( FD_UNLIKELY( seeds[i].len > 16UL ) ) return FD_VM_SYSCALL_ERR_INVAL;

    /* Translate inner seed slice.  Each element points to a byte array. */
    fd_vm_vec_t const * seed = fd_vm_translate_vm_to_host_const(
        ctx,
        seeds[i].addr,
        seeds[i].len * sizeof(fd_vm_vec_t),
        FD_VM_VEC_ALIGN );
    if( FD_UNLIKELY( !seed ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

    /* Derive PDA */

    fd_vm_syscall_pda_next( ctx, pdas );

    for( ulong i=0UL; i < seeds->len; i++ ) {
      /* Check seed limb length */
      /* TODO use constant */
      if( FD_UNLIKELY( seed[i].len > 32 ) ) return FD_VM_SYSCALL_ERR_INVAL;

      /* Translate inner seed limb (type &[u8]) */
      uchar const * seed_limb = fd_vm_translate_vm_to_host_const(
          ctx,
          seed[i].addr,
          seed[i].len,
          alignof(uchar) );
      if( FD_UNLIKELY( !seed_limb ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

      fd_vm_syscall_pda_seed_append( pdas, seed_limb, seed[i].len );
    }

    if( FD_UNLIKELY( !fd_vm_syscall_pda_fini( pdas ) ) )
      return FD_VM_SYSCALL_ERR_INVAL;
  }

  return FD_VM_SYSCALL_SUCCESS;
}

static ulong
fd_vm_syscall_cpi_derive_signers( fd_vm_exec_context_t * ctx,
                                  fd_pubkey_t *          out,
                                  ulong                  signers_seeds_va,
                                    ulong                  signers_seeds_cnt ) {

  fd_vm_syscall_pdas_t _pdas[1];
  fd_vm_syscall_pdas_t * pdas = fd_vm_syscall_pdas_join( fd_vm_syscall_pdas_new( _pdas, out ) );

  if( signers_seeds_cnt>0UL ) {
    ulong res = fd_vm_syscall_cpi_derive_signers_( ctx, pdas, signers_seeds_va, signers_seeds_cnt );
    if( FD_UNLIKELY( res != FD_VM_SYSCALL_SUCCESS ) ) return res;
  }

  fd_vm_syscall_pdas_delete( fd_vm_syscall_pdas_leave( pdas ) );
  return FD_VM_SYSCALL_SUCCESS;
}

/**********************************************************************
   CROSS PROGRAM INVOCATION (C ABI)
 **********************************************************************/

/* fd_vm_syscall_cpi_c implements Solana VM syscall sol_invoked_signed_c. */

ulong
fd_vm_syscall_cpi_c(
    void *  _ctx,
    ulong   instruction_va,
    ulong   acct_infos_va,
    ulong   acct_info_cnt,
    ulong   signers_seeds_va,
    ulong   signers_seeds_cnt,
    ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  /* Pre-flight checks ************************************************/

  ulong res = fd_vm_syscall_cpi_preflight_check( signers_seeds_cnt, acct_info_cnt);
  if( FD_UNLIKELY( res != FD_VM_SYSCALL_SUCCESS ) ) return res;

  /* Translate instruction ********************************************/

  fd_vm_c_instruction_t const * instruction =
    fd_vm_translate_vm_to_host_const(
      ctx,
      instruction_va,
      sizeof(fd_vm_c_instruction_t),
      FD_VM_C_INSTRUCTION_ALIGN );
  if( FD_UNLIKELY( !instruction ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_vm_c_account_meta_t const * accounts =
    fd_vm_translate_vm_to_host_const(
      ctx,
      acct_infos_va,
      acct_info_cnt * sizeof(fd_vm_c_account_meta_t),
      FD_VM_C_ACCOUNT_META_ALIGN );
  if( FD_UNLIKELY( !accounts ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  uchar const * data = fd_vm_translate_vm_to_host_const(
      ctx,
      instruction->data.addr,
      instruction->data.len,
      alignof(uchar) );
  if( FD_UNLIKELY( !data ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  /* Instruction checks ***********************************************/

  res = fd_vm_syscall_cpi_check_instruction( ctx, instruction->accounts.len, instruction->data.len );
  if( FD_UNLIKELY( res != FD_VM_SYSCALL_SUCCESS ) ) return res;

  /* Translate signers ************************************************/

  /* Order of operations is liberally rearranged.
     For inputs that cause multiple errors, this means that Solana Labs
     and Firedancer may return different error codes (as we abort at the
     first error).  (See above) */

  fd_pubkey_t signers[ FD_CPI_MAX_SIGNER_CNT ];
  res = fd_vm_syscall_cpi_derive_signers( ctx, signers, signers_seeds_va, signers_seeds_cnt );
  if( FD_UNLIKELY( res != FD_VM_SYSCALL_SUCCESS ) ) return res;

  /* TODO: Dispatch CPI to executor.
           For now, we'll just log parameters. */

  FD_LOG_WARNING(( "TODO implement CPIs" ));
  *pr0 = 0UL;
  return FD_VM_SYSCALL_ERR_UNIMPLEMENTED;
}

/**********************************************************************
   CROSS PROGRAM INVOCATION (Rust ABI)
 **********************************************************************/

ulong
fd_vm_syscall_cpi_rust(
    void *  _ctx,
    ulong   instruction_va,
    ulong   acct_infos_va,
    ulong   acct_info_cnt,
    ulong   signers_seeds_va,
    ulong   signers_seeds_cnt,
    ulong * pr0
) {
  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;

  /* TODO Consume syscall invoke fee compute units */

  /* Pre-flight checks ************************************************/

  ulong res = fd_vm_syscall_cpi_preflight_check( signers_seeds_cnt, acct_info_cnt);
  if( FD_UNLIKELY( res != FD_VM_SYSCALL_SUCCESS ) ) return res;

  /* Translate instruction ********************************************/

  fd_vm_rust_instruction_t const * instruction =
    fd_vm_translate_vm_to_host_const(
      ctx,
      instruction_va,
      sizeof(fd_vm_rust_instruction_t),
      FD_VM_RUST_INSTRUCTION_ALIGN );
  if( FD_UNLIKELY( !instruction ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  fd_vm_rust_account_meta_t const * accounts =
    fd_vm_translate_vm_to_host_const(
      ctx,
      acct_infos_va,
      acct_info_cnt * sizeof(fd_vm_rust_account_meta_t),
      FD_VM_RUST_ACCOUNT_META_ALIGN );
  if( FD_UNLIKELY( !accounts ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  uchar const * data = fd_vm_translate_vm_to_host_const(
      ctx,
      instruction->data.addr,
      instruction->data.len,
      alignof(uchar) );
  if( FD_UNLIKELY( !data ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  /* Instruction checks ***********************************************/

  res = fd_vm_syscall_cpi_check_instruction( ctx, instruction->accounts.len, instruction->data.len );
  if( FD_UNLIKELY( res != FD_VM_SYSCALL_SUCCESS ) ) return res;

  /* Translate signers ************************************************/

  fd_pubkey_t signers[ FD_CPI_MAX_SIGNER_CNT ];
  res = fd_vm_syscall_cpi_derive_signers( ctx, signers, signers_seeds_va, signers_seeds_cnt );
  if( FD_UNLIKELY( res != FD_VM_SYSCALL_SUCCESS ) ) return res;

  /* TODO prepare accounts */

  /* Translate account infos ******************************************/

  fd_vm_rust_account_info_t const * acc_infos =
    fd_vm_translate_vm_to_host_const(
      ctx,
      acct_infos_va,
      acct_info_cnt * sizeof(fd_vm_rust_account_info_t),
      FD_VM_RUST_ACCOUNT_INFO_ALIGN );
  if( FD_UNLIKELY( !acc_infos ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

  /* Collect pubkeys */

  fd_pubkey_t acct_keys[ acct_info_cnt ];  /* FIXME get rid of VLA */
  for( ulong i=0UL; i<acct_info_cnt; i++ ) {
    fd_pubkey_t const * acct_addr = fd_vm_translate_vm_to_host_const(
        ctx,
        acc_infos[i].pubkey_addr,
        sizeof(fd_pubkey_t),
        alignof(uchar) );
    if( FD_UNLIKELY( !acct_addr ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;

    memcpy( acct_keys[i].uc, acct_addr->uc, sizeof(fd_pubkey_t) );
  }

  /* TODO: Dispatch CPI to executor.
           For now, we'll just log parameters. */

  FD_LOG_WARNING(( "TODO implement CPIs" ));
  *pr0 = 0UL;
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

/**********************************************************************
   SYSVAR GETTERS
 **********************************************************************/

ulong
fd_vm_syscall_sol_get_clock_sysvar(
    void *  _ctx,
    ulong   out_addr,
    ulong   r2 __attribute__((unused)),
    ulong   r3 __attribute__((unused)),
    ulong   r4 __attribute__((unused)),
    ulong   r5 __attribute__((unused)),
    ulong * pr0 ) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  FD_TEST( ctx->instr_ctx.instr );  /* TODO */

  fd_sol_sysvar_clock_t clock;
  fd_sysvar_clock_read( ctx->instr_ctx.global, &clock );

  void * out = fd_vm_translate_vm_to_host(
      ctx,
      out_addr,
      sizeof(fd_sol_sysvar_clock_t),
      FD_SOL_SYSVAR_CLOCK_ALIGN );
  if( FD_UNLIKELY( !out ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;
  memcpy( out, &clock, sizeof(fd_sol_sysvar_clock_t ) );

  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_get_epoch_schedule_sysvar(
    void *  _ctx,
    ulong   out_addr,
    ulong   r2 __attribute__((unused)),
    ulong   r3 __attribute__((unused)),
    ulong   r4 __attribute__((unused)),
    ulong   r5 __attribute__((unused)),
    ulong * pr0 ) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  FD_TEST( ctx->instr_ctx.instr );  /* TODO */

  fd_epoch_schedule_t schedule;
  fd_sysvar_epoch_schedule_read( ctx->instr_ctx.global, &schedule );

  void * out = fd_vm_translate_vm_to_host(
      ctx,
      out_addr,
      sizeof(fd_epoch_schedule_t),
      FD_EPOCH_SCHEDULE_ALIGN );
  if( FD_UNLIKELY( !out ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;
  memcpy( out, &schedule, sizeof(fd_epoch_schedule_t) );

  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_get_fees_sysvar(
    void *  _ctx,
    ulong   out_addr,
    ulong   r2 __attribute__((unused)),
    ulong   r3 __attribute__((unused)),
    ulong   r4 __attribute__((unused)),
    ulong   r5 __attribute__((unused)),
    ulong * pr0 ) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  FD_TEST( ctx->instr_ctx.instr );  /* TODO */

  fd_sysvar_fees_t fees;
  fd_sysvar_fees_read( ctx->instr_ctx.global, &fees );

  void * out = fd_vm_translate_vm_to_host(
      ctx,
      out_addr,
      sizeof(fd_sysvar_fees_t),
      FD_SYSVAR_FEES_ALIGN );
  if( FD_UNLIKELY( !out ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;
  memcpy( out, &fees, sizeof(fd_sysvar_fees_t) );

  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

ulong
fd_vm_syscall_sol_get_rent_sysvar(
    void *  _ctx,
    ulong   out_addr,
    ulong   r2 __attribute__((unused)),
    ulong   r3 __attribute__((unused)),
    ulong   r4 __attribute__((unused)),
    ulong   r5 __attribute__((unused)),
    ulong * pr0 ) {

  fd_vm_exec_context_t * ctx = (fd_vm_exec_context_t *) _ctx;
  FD_TEST( ctx->instr_ctx.instr );  /* TODO */

  fd_rent_t rent;
  fd_sysvar_rent_read( ctx->instr_ctx.global, &rent );

  void * out = fd_vm_translate_vm_to_host(
      ctx,
      out_addr,
      sizeof(fd_rent_t),
      FD_RENT_ALIGN );
  if( FD_UNLIKELY( !out ) ) return FD_VM_MEM_MAP_ERR_ACC_VIO;
  memcpy( out, &rent, sizeof(fd_rent_t) );

  *pr0 = 0UL;
  return FD_VM_SYSCALL_SUCCESS;
}

/**********************************************************************
   PROGRAM DERIVED ADDRESSES
 **********************************************************************/

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

  fd_pubkey_t const * program_id = fd_vm_translate_vm_to_host_const(
      ctx,
      program_id_vaddr,
      sizeof(fd_pubkey_t),
      alignof(uchar) );

  /* Translate seed scatter array address */

  fd_vm_vec_t const * seeds = fd_vm_translate_vm_to_host_const(
      ctx,
      seeds_vaddr,
      /* no overflow, as fd_vm_vec_t<=16UL */
      seeds_cnt * sizeof(fd_vm_rust_vec_t),
      FD_VM_VEC_ALIGN );

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

    void const * seed_part = fd_vm_translate_vm_to_host_const(
        ctx,
        seeds[ i ].addr,
        seeds[ i ].len,
        alignof(uchar) );
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
      out_vaddr,
      sizeof(fd_pubkey_t),
      alignof(uchar) );
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
      out_vaddr,
      sizeof(fd_pubkey_t),
      alignof(uchar) );

  uchar * bump_seed_out = fd_vm_translate_vm_to_host(
      ctx,
      bump_seed_vaddr,
      1UL,
      alignof(uchar) );

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
