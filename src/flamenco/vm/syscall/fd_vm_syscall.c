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

ulong
fd_vm_syscall_env( ulong                 slot,
                   fd_features_t const * features,
                   uchar                 is_deploy ) {
  ulong env = FD_VM_SYSCALL_ENV_VALID | ( is_deploy ? FD_VM_SYSCALL_ENV_DEPLOY : 0UL );
  if( features ) {
    env |= FD_FEATURE_ACTIVE( slot, features, get_sysvar_syscall_enabled     ) ? FD_VM_SYSCALL_ENV_GET_SYSVAR      : 0UL;
    env |= FD_FEATURE_ACTIVE( slot, features, enable_get_epoch_stake_syscall ) ? FD_VM_SYSCALL_ENV_GET_EPOCH_STAKE : 0UL;
    env |= FD_FEATURE_ACTIVE( slot, features, enable_sha512_syscall          ) ? FD_VM_SYSCALL_ENV_SHA512          : 0UL;
    env |= FD_FEATURE_ACTIVE( slot, features, enable_big_mod_exp_syscall     ) ? FD_VM_SYSCALL_ENV_BIG_MOD_EXP     : 0UL;
  } else { /* enable ALL */
    env |= FD_VM_SYSCALL_ENV_GET_SYSVAR | FD_VM_SYSCALL_ENV_GET_EPOCH_STAKE | FD_VM_SYSCALL_ENV_SHA512 | FD_VM_SYSCALL_ENV_BIG_MOD_EXP;
  }
  return env;
}

int
fd_vm_syscall_register_env( fd_sbpf_syscalls_t * syscalls,
                            ulong                env ) {
  if( FD_UNLIKELY( !syscalls || !(env & FD_VM_SYSCALL_ENV_VALID) ) ) return FD_VM_ERR_INVAL;

  int is_deploy                      = !!( env & FD_VM_SYSCALL_ENV_DEPLOY          );
  int enable_get_sysvar_syscall      = !!( env & FD_VM_SYSCALL_ENV_GET_SYSVAR      );
  int enable_get_epoch_stake_syscall = !!( env & FD_VM_SYSCALL_ENV_GET_EPOCH_STAKE );
  int enable_sha512_syscall          = !!( env & FD_VM_SYSCALL_ENV_SHA512          );
  int enable_big_mod_exp_syscall     = !!( env & FD_VM_SYSCALL_ENV_BIG_MOD_EXP     );

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
  REGISTER( "sol_secp256k1_recover",                 fd_vm_syscall_sol_secp256k1_recover );

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
  REGISTER( "sol_curve_decompress",                  fd_vm_syscall_sol_curve_decompress );
  REGISTER( "sol_curve_pairing_map",                 fd_vm_syscall_sol_curve_pairing_map );

  REGISTER( "sol_alt_bn128_group_op",                  fd_vm_syscall_sol_alt_bn128_group_op );
  REGISTER( "sol_alt_bn128_compression",               fd_vm_syscall_sol_alt_bn128_compression );

# if FD_HAS_S2NBIGNUM
  if( enable_big_mod_exp_syscall )
    REGISTER( "sol_big_mod_exp",                     fd_vm_syscall_sol_big_mod_exp );
# else
  (void)enable_big_mod_exp_syscall;
# endif

  REGISTER( "sol_poseidon",                          fd_vm_syscall_sol_poseidon );

//REGISTER( "sol_remaining_compute_units",           fd_vm_syscall_sol_remaining_compute_units );

# undef REGISTER

  return FD_VM_SUCCESS;
}

int
fd_vm_syscall_register_slot( fd_sbpf_syscalls_t *  syscalls,
                             ulong                 slot,
                             fd_features_t const * features,
                             uchar                 is_deploy ) {
  return fd_vm_syscall_register_env( syscalls, fd_vm_syscall_env( slot, features, is_deploy ) );
}

ulong
fd_vm_syscalls_hash( fd_sbpf_syscalls_t const * syscalls ) {
  ulong h = 0x9e3779b97f4a7c15UL;
  for( ulong i=0UL; i<FD_SBPF_SYSCALLS_SLOT_CNT; i++ ) {
    h = fd_ulong_hash( h ^ syscalls[ i ].key );
    if( fd_sbpf_syscalls_key_inval( syscalls[ i ].key ) ) continue; /* empty slot, func is garbage */
    h = fd_ulong_hash( h ^ (ulong)syscalls[ i ].func );
  }
  return h;
}

fd_sbpf_syscalls_t *
fd_vm_syscall_cache_get( fd_vm_syscall_cache_t * cache,
                         ulong                   env ) {
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_join( cache->syscalls );
  if( FD_UNLIKELY( cache->env!=env ) ) {
    fd_sbpf_syscalls_new( cache->syscalls );
    if( FD_UNLIKELY( fd_vm_syscall_register_env( syscalls, env )!=FD_VM_SUCCESS ) ) FD_LOG_CRIT(( "fd_vm_syscall_register_env failed" ));
    cache->hash = fd_vm_syscalls_hash( syscalls );
    cache->env  = env;
  }
  return syscalls;
}
