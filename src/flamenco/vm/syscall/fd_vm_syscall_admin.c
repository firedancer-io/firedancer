#include "fd_vm_syscall.h"

void
fd_vm_syscall_register( fd_sbpf_syscalls_t *   syscalls,
                        char const *           name,
                        fd_sbpf_syscall_func_t func ) {
  ulong name_len     = strlen( name );
  uint  syscall_hash = fd_murmur3_32( name, name_len, 0U );
  fd_sbpf_syscalls_t * syscall_entry = fd_sbpf_syscalls_insert( syscalls, syscall_hash );
  /* FIXME: HANDLE TABLE OVERFLOW? */
  syscall_entry->func = func;
  syscall_entry->name = name;
}

void
fd_vm_syscall_register_slot( fd_sbpf_syscalls_t *       syscalls,
                             fd_exec_slot_ctx_t const * slot_ctx ) {

  int secp256k1_recover_syscall_enabled    = 0;
  int blake3_syscall_enabled               = 0;
  int curve25519_syscall_enabled           = 0;
  int enable_poseidon_syscall              = 0;
  int enable_alt_bn128_compression_syscall = 0;
  /* disable */
  int disable_fees_sysvar                  = 0;

  if( slot_ctx ) {

    secp256k1_recover_syscall_enabled    = FD_FEATURE_ACTIVE( slot_ctx, secp256k1_recover_syscall_enabled );
    blake3_syscall_enabled               = FD_FEATURE_ACTIVE( slot_ctx, blake3_syscall_enabled );
    curve25519_syscall_enabled           = FD_FEATURE_ACTIVE( slot_ctx, curve25519_syscall_enabled );
    enable_poseidon_syscall              = FD_FEATURE_ACTIVE( slot_ctx, enable_poseidon_syscall );
    enable_alt_bn128_compression_syscall = FD_FEATURE_ACTIVE( slot_ctx, enable_alt_bn128_compression_syscall );
    /* disable */
    disable_fees_sysvar                  = !FD_FEATURE_ACTIVE( slot_ctx, disable_fees_sysvar );

  } else {

    /* enable ALL */
    secp256k1_recover_syscall_enabled    = 1;
    blake3_syscall_enabled               = 1;
    curve25519_syscall_enabled           = 1;
    enable_poseidon_syscall              = 1;
    enable_alt_bn128_compression_syscall = 1;

  }

  /* Firedancer only (FIXME: HMMMM) */

  fd_vm_syscall_register( syscalls, "abort",                                 fd_vm_syscall_abort );
  fd_vm_syscall_register( syscalls, "sol_panic_",                            fd_vm_syscall_sol_panic );
  fd_vm_syscall_register( syscalls, "custom_panic",                          fd_vm_syscall_sol_panic ); /* TODO: unsure if this is entirely correct */
  fd_vm_syscall_register( syscalls, "sol_alloc_free_",                       fd_vm_syscall_sol_alloc_free );

  /* https://github.com/solana-labs/solana/blob/v1.18.1/sdk/program/src/syscalls/definitions.rs#L39 */

  fd_vm_syscall_register( syscalls, "sol_log_",                              fd_vm_syscall_sol_log );
  fd_vm_syscall_register( syscalls, "sol_log_64_",                           fd_vm_syscall_sol_log_64 );
  fd_vm_syscall_register( syscalls, "sol_log_compute_units_",                fd_vm_syscall_sol_log_compute_units );
  fd_vm_syscall_register( syscalls, "sol_log_pubkey",                        fd_vm_syscall_sol_log_pubkey );
  fd_vm_syscall_register( syscalls, "sol_create_program_address",            fd_vm_syscall_sol_create_program_address );
  fd_vm_syscall_register( syscalls, "sol_try_find_program_address",          fd_vm_syscall_sol_try_find_program_address );
  fd_vm_syscall_register( syscalls, "sol_sha256",                            fd_vm_syscall_sol_sha256 );
  fd_vm_syscall_register( syscalls, "sol_keccak256",                         fd_vm_syscall_sol_keccak256 );

  if( secp256k1_recover_syscall_enabled )
    fd_vm_syscall_register( syscalls, "sol_secp256k1_recover",               fd_vm_syscall_sol_secp256k1_recover );

  if( blake3_syscall_enabled )
    fd_vm_syscall_register( syscalls, "sol_blake3",                          fd_vm_syscall_sol_blake3 );

  fd_vm_syscall_register( syscalls, "sol_get_clock_sysvar",                  fd_vm_syscall_sol_get_clock_sysvar );
  fd_vm_syscall_register( syscalls, "sol_get_epoch_schedule_sysvar",         fd_vm_syscall_sol_get_epoch_schedule_sysvar );

  if( !disable_fees_sysvar )
    fd_vm_syscall_register( syscalls, "sol_get_fees_sysvar",                 fd_vm_syscall_sol_get_fees_sysvar );

  fd_vm_syscall_register( syscalls, "sol_get_rent_sysvar",                   fd_vm_syscall_sol_get_rent_sysvar );
//fd_vm_syscall_register( syscalls, "sol_get_last_restart_slot",             fd_vm_syscall_sol_get_last_restart_slot );
  fd_vm_syscall_register( syscalls, "sol_memcpy_",                           fd_vm_syscall_sol_memcpy );
  fd_vm_syscall_register( syscalls, "sol_memmove_",                          fd_vm_syscall_sol_memmove );
  fd_vm_syscall_register( syscalls, "sol_memcmp_",                           fd_vm_syscall_sol_memcmp );
  fd_vm_syscall_register( syscalls, "sol_memset_",                           fd_vm_syscall_sol_memset );
  fd_vm_syscall_register( syscalls, "sol_invoke_signed_c",                   fd_vm_syscall_cpi_c );
  fd_vm_syscall_register( syscalls, "sol_invoke_signed_rust",                fd_vm_syscall_cpi_rust );
  fd_vm_syscall_register( syscalls, "sol_set_return_data",                   fd_vm_syscall_sol_set_return_data );
  fd_vm_syscall_register( syscalls, "sol_get_return_data",                   fd_vm_syscall_sol_get_return_data );
  fd_vm_syscall_register( syscalls, "sol_log_data",                          fd_vm_syscall_sol_log_data );
  fd_vm_syscall_register( syscalls, "sol_get_processed_sibling_instruction", fd_vm_syscall_sol_get_processed_sibling_instruction );
  fd_vm_syscall_register( syscalls, "sol_get_stack_height",                  fd_vm_syscall_sol_get_stack_height );

  if( curve25519_syscall_enabled ) {
    fd_vm_syscall_register( syscalls, "sol_curve_validate_point",            fd_vm_syscall_sol_curve_validate_point );
    fd_vm_syscall_register( syscalls, "sol_curve_group_op",                  fd_vm_syscall_sol_curve_group_op );
    fd_vm_syscall_register( syscalls, "sol_curve_multiscalar_mul",           fd_vm_syscall_sol_curve_multiscalar_mul );
  }

  // NOTE: sol_curve_pairing_map is defined but never implemented /
  // used, we can ignore it for now
//fd_vm_syscall_register( syscalls, "sol_curve_pairing_map",                 fd_vm_syscall_sol_curve_pairing_map );

  fd_vm_syscall_register( syscalls, "sol_alt_bn128_group_op",                fd_vm_syscall_sol_alt_bn128_group_op );
//fd_vm_syscall_register( syscalls, "sol_big_mod_exp",                       fd_vm_syscall_sol_big_mod_exp );
//fd_vm_syscall_register( syscalls, "sol_get_epoch_rewards_sysvar",          fd_vm_syscall_sol_get_epoch_rewards_sysvar );

  if( enable_poseidon_syscall )
    fd_vm_syscall_register( syscalls, "sol_poseidon",                        fd_vm_syscall_sol_poseidon );

//fd_vm_syscall_register( syscalls, "sol_remaining_compute_units",           fd_vm_syscall_sol_remaining_compute_units );

  if( enable_alt_bn128_compression_syscall )
    fd_vm_syscall_register( syscalls, "sol_alt_bn128_compression",           fd_vm_syscall_sol_alt_bn128_compression );
}

void
fd_vm_syscall_register_all( fd_sbpf_syscalls_t * syscalls ) {
  fd_vm_syscall_register_slot( syscalls, NULL );
}
