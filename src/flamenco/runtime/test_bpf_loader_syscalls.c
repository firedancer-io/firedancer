#include "fd_runtime.h"
#include "fd_bank.h"
#include "../features/fd_features.h"

static int
has_syscall( fd_sbpf_syscalls_t const * syscalls,
             char const *              name ) {
  for( ulong i=0UL; i<FD_SBPF_SYSCALLS_SLOT_CNT; i++ ) {
    if( fd_sbpf_syscalls_key_inval( syscalls[i].key ) ) continue;
    if( syscalls[i].name && !strcmp( syscalls[i].name, name ) ) return 1;
  }
  return 0;
}

static fd_sbpf_syscalls_t *
syscalls_at( fd_runtime_bpf_loader_syscalls_t * syscalls,
             fd_bank_t *                        bank,
             ulong                              slot ) {
  bank->f.slot = slot;
  fd_sbpf_syscalls_t * map = fd_runtime_bpf_loader_syscalls_get( syscalls, bank );
  FD_TEST( map );
  return map;
}

static void
test_feature_transitions( void ) {
  static fd_runtime_bpf_loader_syscalls_t syscalls[1];
  static fd_bank_t                        bank[1];

  fd_memset( bank, 0, sizeof(bank) );
  fd_runtime_bpf_loader_syscalls_init( syscalls );
  fd_features_disable_all( &bank->f.features );

  FD_FEATURE_SET_ACTIVE( &bank->f.features, get_sysvar_syscall_enabled,      101UL );
  FD_FEATURE_SET_ACTIVE( &bank->f.features, enable_get_epoch_stake_syscall,  102UL );
  FD_FEATURE_SET_ACTIVE( &bank->f.features, enable_bls12_381_syscall,        103UL );
  FD_FEATURE_SET_ACTIVE( &bank->f.features, enable_sha512_syscall,           104UL );

  fd_sbpf_syscalls_t * map = syscalls_at( syscalls, bank, 100UL );
  FD_TEST( map==syscalls->map );
  FD_TEST( syscalls->rebuild_cnt==1UL );
  FD_TEST(  has_syscall( map, "sol_log_"            ) );
  FD_TEST(  has_syscall( map, "sol_alloc_free_"     ) );
  FD_TEST( !has_syscall( map, "sol_get_sysvar"      ) );
  FD_TEST( !has_syscall( map, "sol_get_epoch_stake" ) );
  FD_TEST( !has_syscall( map, "sol_sha512"          ) );
#if FD_HAS_BLST
  FD_TEST( !has_syscall( map, "sol_curve_decompress" ) );
  FD_TEST( !has_syscall( map, "sol_curve_pairing_map" ) );
#endif

  FD_TEST( syscalls_at( syscalls, bank, 100UL )==map );
  FD_TEST( syscalls->rebuild_cnt==1UL );

  map = syscalls_at( syscalls, bank, 0UL );
  FD_TEST( syscalls->rebuild_cnt==2UL );
  FD_TEST( has_syscall( map, "sol_get_sysvar"      ) );
  FD_TEST( has_syscall( map, "sol_get_epoch_stake" ) );
  FD_TEST( has_syscall( map, "sol_sha512"          ) );
#if FD_HAS_BLST
  FD_TEST( has_syscall( map, "sol_curve_decompress" ) );
  FD_TEST( has_syscall( map, "sol_curve_pairing_map" ) );
#endif

  map = syscalls_at( syscalls, bank, 101UL );
  FD_TEST( syscalls->rebuild_cnt==3UL );
  FD_TEST(  has_syscall( map, "sol_get_sysvar"      ) );
  FD_TEST( !has_syscall( map, "sol_get_epoch_stake" ) );
  FD_TEST( !has_syscall( map, "sol_sha512"          ) );

  map = syscalls_at( syscalls, bank, 102UL );
  FD_TEST( syscalls->rebuild_cnt==4UL );
  FD_TEST( has_syscall( map, "sol_get_sysvar"      ) );
  FD_TEST( has_syscall( map, "sol_get_epoch_stake" ) );
  FD_TEST( !has_syscall( map, "sol_sha512"         ) );

  map = syscalls_at( syscalls, bank, 103UL );
#if FD_HAS_BLST
  FD_TEST( syscalls->rebuild_cnt==5UL );
  FD_TEST( has_syscall( map, "sol_curve_decompress" ) );
  FD_TEST( has_syscall( map, "sol_curve_pairing_map" ) );
#else
  FD_TEST( syscalls->rebuild_cnt==4UL );
#endif
  FD_TEST( !has_syscall( map, "sol_sha512" ) );

  map = syscalls_at( syscalls, bank, 104UL );
#if FD_HAS_BLST
  FD_TEST( syscalls->rebuild_cnt==6UL );
#else
  FD_TEST( syscalls->rebuild_cnt==5UL );
#endif
  FD_TEST( has_syscall( map, "sol_sha512" ) );

  FD_TEST( syscalls_at( syscalls, bank, 105UL )==map );
#if FD_HAS_BLST
  FD_TEST( syscalls->rebuild_cnt==6UL );
#else
  FD_TEST( syscalls->rebuild_cnt==5UL );
#endif

  map = syscalls_at( syscalls, bank, 100UL );
#if FD_HAS_BLST
  FD_TEST( syscalls->rebuild_cnt==7UL );
#else
  FD_TEST( syscalls->rebuild_cnt==6UL );
#endif
  FD_TEST( !has_syscall( map, "sol_get_sysvar"      ) );
  FD_TEST( !has_syscall( map, "sol_get_epoch_stake" ) );
  FD_TEST( !has_syscall( map, "sol_sha512"          ) );

  fd_sbpf_syscalls_t deploy_mem[ FD_SBPF_SYSCALLS_SLOT_CNT ];
  fd_sbpf_syscalls_t * deploy = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( deploy_mem ) );
  FD_TEST( !fd_vm_syscall_register_slot( deploy, bank->f.slot, &bank->f.features, 1 ) );
  FD_TEST( !has_syscall( deploy, "sol_alloc_free_" ) );
  FD_TEST(  has_syscall( map,    "sol_alloc_free_" ) );

  FD_TEST( !fd_runtime_bpf_loader_syscalls_get( NULL, bank ) );
  FD_TEST( !fd_runtime_bpf_loader_syscalls_get( syscalls, NULL ) );

  fd_memset( syscalls, 0, sizeof(syscalls) );
  map = syscalls_at( syscalls, bank, 100UL );
  FD_TEST( syscalls->rebuild_cnt==1UL );
  FD_TEST( !has_syscall( map, "sol_get_sysvar" ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_feature_transitions();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
