#include "fd_vm_syscall.h"
#include "../../../ballet/murmur3/fd_murmur3.h"

int
fd_vm_syscall_register( fd_sbpf_syscalls_t *   syscalls,
                        char const *           name,
                        fd_sbpf_syscall_func_t func ) {
  if( FD_UNLIKELY( (!syscalls) | (!name) ) ) return FD_VM_ERR_INVAL;

  fd_sbpf_syscalls_t * syscall = fd_sbpf_syscalls_insert( syscalls, (ulong)fd_murmur3_32( name, strlen( name ), 0U ) );
  if( FD_UNLIKELY( !syscall ) ) return FD_VM_ERR_INVAL; /* name (or hash of name) already in map */

  syscall->func = func;
  syscall->name = name;

  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_register_slot( fd_sbpf_syscalls_t *      syscalls,
                             ulong                     slot,
                             fd_features_t const *     features,
                             uchar                     is_deploy ) {
  if( FD_UNLIKELY( (!syscalls) || (slot==FD_FEATURE_DISABLED) ) ) return FD_VM_ERR_INVAL;

  int enable_blake3_syscall            = 0;
  int enable_get_sysvar_syscall        = 0;
  int enable_get_epoch_stake_syscall   = 0;
  int enable_bls12_381_syscall         = 0;
  int enable_sha512_syscall            = 0;

  if( features ) {
    enable_blake3_syscall            = FD_FEATURE_ACTIVE( slot, features, blake3_syscall_enabled );
    enable_get_sysvar_syscall        = FD_FEATURE_ACTIVE( slot, features, get_sysvar_syscall_enabled );
    enable_get_epoch_stake_syscall   = FD_FEATURE_ACTIVE( slot, features, enable_get_epoch_stake_syscall );
    enable_bls12_381_syscall         = FD_FEATURE_ACTIVE( slot, features, enable_bls12_381_syscall );
    enable_sha512_syscall            = FD_FEATURE_ACTIVE( slot, features, enable_sha512_syscall );

  } else { /* enable ALL */

    enable_blake3_syscall            = 1;
    enable_get_sysvar_syscall        = 1;
    enable_get_epoch_stake_syscall   = 1;
    enable_bls12_381_syscall         = 1;
    enable_sha512_syscall            = 1;

  }

  fd_sbpf_syscalls_clear( syscalls );

  ulong syscall_cnt = 0UL;

# define REGISTER(name,func) do {                                                       \
    if( FD_UNLIKELY( syscall_cnt>=fd_sbpf_syscalls_key_max() ) ) return FD_VM_ERR_FULL; \
    int _err = fd_vm_syscall_register( syscalls, (name), (func) );                      \
    if( FD_UNLIKELY( _err ) ) return _err;                                              \
    syscall_cnt++;                                                                      \
  } while(0)

  /* https://github.com/anza-xyz/agave/blob/v2.2.20/programs/bpf_loader/src/syscalls/mod.rs#L392-L396 */

  REGISTER( "abort",                                 fd_vm_syscall_abort );
  REGISTER( "sol_panic_",                            fd_vm_syscall_sol_panic );

  /* As of the activation of disable_deploy_of_alloc_free_syscall, which is activated on all networks,
     programs can no longer be deployed which use the sol_alloc_free_ syscall.

    https://github.com/anza-xyz/agave/blob/d6041c002bbcf1526de4e38bc18fa6e781c380e7/programs/bpf_loader/src/syscalls/mod.rs#L429 */
  if ( FD_LIKELY( !is_deploy ) ) {
    REGISTER( "sol_alloc_free_",                       fd_vm_syscall_sol_alloc_free );
  }

  /* https://github.com/solana-labs/solana/blob/v1.18.1/sdk/program/src/syscalls/definitions.rs#L39 */

  REGISTER( "sol_log_",                              fd_vm_syscall_sol_log );
  REGISTER( "sol_log_64_",                           fd_vm_syscall_sol_log_64 );
  REGISTER( "sol_log_compute_units_",                fd_vm_syscall_sol_log_compute_units );
  REGISTER( "sol_log_pubkey",                        fd_vm_syscall_sol_log_pubkey );
  REGISTER( "sol_create_program_address",            fd_vm_syscall_sol_create_program_address );
  REGISTER( "sol_try_find_program_address",          fd_vm_syscall_sol_try_find_program_address );
  REGISTER( "sol_sha256",                            fd_vm_syscall_sol_sha256 );
  REGISTER( "sol_keccak256",                         fd_vm_syscall_sol_keccak256 );
# if FD_HAS_S2NBIGNUM
  REGISTER( "sol_secp256k1_recover",                 fd_vm_syscall_sol_secp256k1_recover );
# else
  FD_LOG_ERR(( "This build does not include s2n-bignum, which is required to run a validator.\n"
               "To install s2n-bignum, re-run ./deps.sh, make distclean, and make -j" ));
# endif

  if( enable_blake3_syscall )
    REGISTER( "sol_blake3",                          fd_vm_syscall_sol_blake3 );

  if( enable_sha512_syscall )
    REGISTER( "sol_sha512",                          fd_vm_syscall_sol_sha512 );

  REGISTER( "sol_get_clock_sysvar",                  fd_vm_syscall_sol_get_clock_sysvar );
  REGISTER( "sol_get_epoch_schedule_sysvar",         fd_vm_syscall_sol_get_epoch_schedule_sysvar );

  REGISTER( "sol_get_rent_sysvar",                   fd_vm_syscall_sol_get_rent_sysvar );

  REGISTER( "sol_get_last_restart_slot",             fd_vm_syscall_sol_get_last_restart_slot_sysvar );

  if( enable_get_sysvar_syscall ) {
    REGISTER( "sol_get_sysvar",                      fd_vm_syscall_sol_get_sysvar );
  }

  if( enable_get_epoch_stake_syscall ) {
    REGISTER( "sol_get_epoch_stake",                 fd_vm_syscall_sol_get_epoch_stake );
  }

  REGISTER( "sol_memcpy_",                           fd_vm_syscall_sol_memcpy );
  REGISTER( "sol_memmove_",                          fd_vm_syscall_sol_memmove );
  REGISTER( "sol_memcmp_",                           fd_vm_syscall_sol_memcmp );
  REGISTER( "sol_memset_",                           fd_vm_syscall_sol_memset );
  REGISTER( "sol_invoke_signed_c",                   fd_vm_syscall_cpi_c );
  REGISTER( "sol_invoke_signed_rust",                fd_vm_syscall_cpi_rust );
  REGISTER( "sol_set_return_data",                   fd_vm_syscall_sol_set_return_data );
  REGISTER( "sol_get_return_data",                   fd_vm_syscall_sol_get_return_data );
  REGISTER( "sol_log_data",                          fd_vm_syscall_sol_log_data );
  REGISTER( "sol_get_processed_sibling_instruction", fd_vm_syscall_sol_get_processed_sibling_instruction );
  REGISTER( "sol_get_stack_height",                  fd_vm_syscall_sol_get_stack_height );
  REGISTER( "sol_get_epoch_rewards_sysvar",          fd_vm_syscall_sol_get_epoch_rewards_sysvar );

  REGISTER( "sol_curve_validate_point",              fd_vm_syscall_sol_curve_validate_point );
  REGISTER( "sol_curve_group_op",                    fd_vm_syscall_sol_curve_group_op );
  REGISTER( "sol_curve_multiscalar_mul",             fd_vm_syscall_sol_curve_multiscalar_mul );

  // NOTE: sol_curve_pairing_map is defined but never implemented /
  // used, we can ignore it for now
//REGISTER( "sol_curve_pairing_map",                 fd_vm_syscall_sol_curve_pairing_map );

  REGISTER( "sol_alt_bn128_group_op",                  fd_vm_syscall_sol_alt_bn128_group_op );
  REGISTER( "sol_alt_bn128_compression",               fd_vm_syscall_sol_alt_bn128_compression );

//REGISTER( "sol_big_mod_exp",                       fd_vm_syscall_sol_big_mod_exp );

  REGISTER( "sol_poseidon",                          fd_vm_syscall_sol_poseidon );

//REGISTER( "sol_remaining_compute_units",           fd_vm_syscall_sol_remaining_compute_units );

#if FD_HAS_BLST
  if( enable_bls12_381_syscall ) {
    REGISTER( "sol_curve_decompress",                fd_vm_syscall_sol_curve_decompress );
    REGISTER( "sol_curve_pairing_map",               fd_vm_syscall_sol_curve_pairing_map );
  }
#else
  (void)enable_bls12_381_syscall;
#endif /* FD_HAS_BLST */

# undef REGISTER

  return FD_VM_SUCCESS;
}

fd_vm_syscall_cache_t *
fd_vm_syscall_cache_init( fd_vm_syscall_cache_t * cache ) {
  if( FD_UNLIKELY( !cache ) ) return NULL;

  fd_memset( cache, 0, sizeof(fd_vm_syscall_cache_t) );
  fd_sbpf_syscalls_new( cache->exec_mem   );
  fd_sbpf_syscalls_new( cache->deploy_mem );
  return cache;
}

static void
fd_vm_syscall_cache_slot_interval( fd_features_t const * features,
                                   ulong                 slot,
                                   ulong *               slot_lo,
                                   ulong *               slot_hi ) {
  ulong lo = 0UL;
  ulong hi = ULONG_MAX;

  for( ulong feature_idx=0UL; feature_idx<FD_FEATURE_ID_CNT; feature_idx++ ) {
    ulong activation_slot = features->f[ feature_idx ];
    if( activation_slot<=slot ) lo = fd_ulong_max( lo, activation_slot );
    else                        hi = fd_ulong_min( hi, activation_slot-1UL );
  }

  *slot_lo = lo;
  *slot_hi = hi;
}

int
fd_vm_syscall_cache_prepare( fd_vm_syscall_cache_t * cache,
                             ulong                   slot,
                             fd_features_t const *   features ) {
  if( FD_UNLIKELY( (!cache) | (!features) | (slot>=ULONG_MAX-1UL) ) ) return FD_VM_ERR_INVAL;

  ulong deploy_slot = slot+1UL;
  if( FD_LIKELY( cache->prepared &&
                 fd_memeq( &cache->features, features, sizeof(fd_features_t) ) &&
                 slot       >=cache->exec_slot_lo   && slot       <=cache->exec_slot_hi &&
                 deploy_slot>=cache->deploy_slot_lo && deploy_slot<=cache->deploy_slot_hi ) ) {
    return FD_VM_SUCCESS;
  }

  uchar exec_mem  [ FD_SBPF_SYSCALLS_FOOTPRINT ] __attribute__((aligned(FD_SBPF_SYSCALLS_ALIGN))) = {0};
  uchar deploy_mem[ FD_SBPF_SYSCALLS_FOOTPRINT ] __attribute__((aligned(FD_SBPF_SYSCALLS_ALIGN))) = {0};
  fd_sbpf_syscalls_t * exec   = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( exec_mem   ) );
  fd_sbpf_syscalls_t * deploy = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( deploy_mem ) );

  int err = fd_vm_syscall_register_slot( exec, slot, features, 0 );
  if( FD_UNLIKELY( err ) ) return err;
  err = fd_vm_syscall_register_slot( deploy, deploy_slot, features, 1 );
  if( FD_UNLIKELY( err ) ) return err;

  ulong exec_slot_lo;
  ulong exec_slot_hi;
  ulong deploy_slot_lo;
  ulong deploy_slot_hi;
  fd_vm_syscall_cache_slot_interval( features, slot,        &exec_slot_lo,   &exec_slot_hi   );
  fd_vm_syscall_cache_slot_interval( features, deploy_slot, &deploy_slot_lo, &deploy_slot_hi );

  fd_memcpy( cache->exec_mem,   exec_mem,   sizeof(exec_mem)   );
  fd_memcpy( cache->deploy_mem, deploy_mem, sizeof(deploy_mem) );
  fd_memcpy( &cache->features, features, sizeof(fd_features_t) );
  cache->exec_slot_lo   = exec_slot_lo;
  cache->exec_slot_hi   = exec_slot_hi;
  cache->deploy_slot_lo = deploy_slot_lo;
  cache->deploy_slot_hi = deploy_slot_hi;
  cache->prepared       = 1;
  return FD_VM_SUCCESS;
}

fd_sbpf_syscalls_t const *
fd_vm_syscall_cache_exec( fd_vm_syscall_cache_t const * cache ) {
  if( FD_UNLIKELY( (!cache) || (!cache->prepared) ) ) return NULL;
  return (fd_sbpf_syscalls_t const *)(void const *)cache->exec_mem;
}

fd_sbpf_syscalls_t const *
fd_vm_syscall_cache_deploy( fd_vm_syscall_cache_t const * cache ) {
  if( FD_UNLIKELY( (!cache) || (!cache->prepared) ) ) return NULL;
  return (fd_sbpf_syscalls_t const *)(void const *)cache->deploy_mem;
}
