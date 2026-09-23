#include "commands/configure/fd_cpu_isolation.h"

static fd_topo_t topo;

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  FD_TEST( fd_shmem_cpu_cnt()>=1UL );
  FD_CPUSET_DECL( cpus );

  /* A shared tile still has a CPU index for memory placement, but that
     CPU must remain available for interrupts and kernel workers. */
  topo.tile_cnt = 3UL;
  topo.tiles[0].cpu_idx = 0UL;
  topo.tiles[0].floats  = 1;
  topo.tiles[1].cpu_idx = ULONG_MAX;
  topo.tiles[2].cpu_idx = FD_TILE_MAX;
  FD_TEST( fd_cpu_isolation_tile_cpus( cpus, &topo )==cpus );
  FD_TEST( fd_cpuset_is_null( cpus ) );

  /* A dedicated reservation wins even if another tile is shared. */
  topo.tile_cnt = 4UL;
  topo.tiles[3].cpu_idx = 0UL;
  topo.tiles[3].floats  = 0;
  fd_cpu_isolation_tile_cpus( cpus, &topo );
  FD_TEST( fd_cpuset_cnt( cpus )==1UL );
  FD_TEST( fd_cpuset_test( cpus, 0UL ) );

  topo.tiles[3].floats = 1;
  fd_cpu_isolation_tile_cpus( cpus, &topo );
  FD_TEST( fd_cpuset_is_null( cpus ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
