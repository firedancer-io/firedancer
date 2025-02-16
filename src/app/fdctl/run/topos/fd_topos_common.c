#include "topos.h"
#include "../../fdctl.h"
#include "../../../../disco/topo/fd_topob.h"
#include "../../../../util/tile/fd_tile_private.h" /* fd_tile_private_cpus_parse */
#include "../../../../util/shmem/fd_shmem_private.h" /* fd_numa_cpu_cnt() */

void
fd_topos_affinity( fd_topos_affinity_t * affinity,
                   char const *          affinity_str,
                   char const *          config_option ) {
  memset( affinity, 0, sizeof(fd_topos_affinity_t) );

  ushort parsed_tile_to_cpu[ FD_TILE_MAX ];
  /* Unassigned tiles will be floating, unless auto topology is enabled. */
  for( ulong i=0UL; i<FD_TILE_MAX; i++ ) parsed_tile_to_cpu[ i ] = USHORT_MAX;

  affinity->is_auto = !strcmp( affinity_str, "auto" );

  affinity->tile_cnt = 0UL;
  if( FD_LIKELY( !affinity->is_auto ) ) affinity->tile_cnt = fd_tile_private_cpus_parse( affinity_str, parsed_tile_to_cpu );

  for( ulong i=0UL; i<affinity->tile_cnt; i++ ) {
    if( FD_UNLIKELY( parsed_tile_to_cpu[ i ]!=USHORT_MAX && parsed_tile_to_cpu[ i ]>=fd_numa_cpu_cnt() ) )
      FD_LOG_ERR(( "The CPU affinity string in the configuration file under [%s] specifies a CPU index of %hu, but the system "
                   "only has %lu CPUs. You should either change the CPU allocations in the affinity string, or increase the number of CPUs "
                   "in the system.",
                   config_option, parsed_tile_to_cpu[ i ], fd_numa_cpu_cnt() ));
    affinity->tile_to_cpu[ i ] = fd_ulong_if( parsed_tile_to_cpu[ i ]==USHORT_MAX, ULONG_MAX, (ulong)parsed_tile_to_cpu[ i ] );
  }
}

void
fd_topos_seal( fd_topo_t * topo ) {
  fd_topob_finish( topo, fdctl_obj_align, fdctl_obj_footprint, fdctl_obj_loose );
}
