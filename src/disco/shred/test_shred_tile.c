#define TEST_IS_FIREDANCER (0)

/* Auxiliary tile unit test skeleton and api. */
#include "../../app/shared/fd_tile_unit_test.h"

/* Base topology. */
#if TEST_IS_FIREDANCER==0
#include "../../app/fdctl/topology.c"
#define TEST_DEFAULT_TOPO_CONFIG_PATH ("src/app/fdctl/config/default.toml")
#else
#include "../../app/firedancer/topology.c"
#define TEST_DEFAULT_TOPO_CONFIG_PATH ("src/app/firedancer/config/default.toml")
#endif

/* Tile under test. */
#include "fd_shred_tile.c"

/* Global config. */
config_t config[1];

/* Main test. */
int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  uint rng_seed = fd_env_strip_cmdline_uint( &argc, &argv, "--rng-seed", NULL, 0U );
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, rng_seed, 0UL ) );

  /* Initialize tile unit test */
  char const * default_topo_config_path  = TEST_DEFAULT_TOPO_CONFIG_PATH;
  char const * override_topo_config_path = NULL;
  char const * user_topo_config_path     = NULL;
  int          netns                     = 0;
  int          is_firedancer             = TEST_IS_FIREDANCER;
  int          is_local_cluster          = 0;
  fd_topo_tile_t * shred_tile = fd_tile_unit_test_init( default_topo_config_path, override_topo_config_path, user_topo_config_path,
                                                       netns, is_firedancer, is_local_cluster,
                                                       fd_topo_initialize, &fd_tile_shred, config );
  FD_TEST( shred_tile );

  FD_LOG_NOTICE(( "is_firedancer %d", is_firedancer ));

  /* [tile-unit-test] unprivileged_init. */
  /* this happens externally to shred tile ... */
  ulong poh_shed_obj_id = fd_pod_query_ulong( config->topo.props, "poh_shred", ULONG_MAX );
  FD_TEST( poh_shed_obj_id!=ULONG_MAX );
  ulong * gossip_shred_version = fd_fseq_join( fd_topo_obj_laddr( &config->topo, poh_shed_obj_id ) );
  *gossip_shred_version = 0xcafeUL;
  /* ... before invoking unprivileged_init */
  unprivileged_init( &config->topo, shred_tile );

  fd_shred_ctx_t * shred_ctx = fd_topo_obj_laddr( &config->topo, shred_tile->tile_obj_id );
  FD_TEST( shred_ctx );

  /* TODO expand the test here */
  FD_LOG_WARNING(( "UNDER CONSTRUCTION!!" ));

  /* Tear down tile unit test. */
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#undef TEST_IS_FIREDANCER
#undef TEST_DEFAULT_TOPO_CONFIG_PATH
