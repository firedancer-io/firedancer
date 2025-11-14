#include "configure.h"

#define NAME "hyperthreads"

#include "../../../../disco/topo/fd_cpu_topo.h"

static ulong
determine_ht_pair( config_t const *       config,
                   fd_topo_cpus_t const * cpus,
                   char const *           kind,
                   ulong                  kind_id ) {
  ulong tile_idx = fd_topo_find_tile( &config->topo, kind, kind_id );
  if( FD_LIKELY( tile_idx!=ULONG_MAX ) ) {
    fd_topo_tile_t const * tile = &config->topo.tiles[ tile_idx ];
    if( FD_LIKELY( tile->cpu_idx!=ULONG_MAX ) ) return cpus->cpu[ tile->cpu_idx ].sibling;
  }
  return ULONG_MAX;
}

static int
determine_cpu_used( config_t const * config,
                    ulong            cpu_idx ) {
  if( FD_UNLIKELY( cpu_idx==ULONG_MAX ) ) return 0;

  ulong tile_cnt = config->topo.tile_cnt;
  for( ulong i=0UL; i<tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &config->topo.tiles[ i ];
    if( tile->cpu_idx==cpu_idx ) return 1;
  }
  return 0;
}

static configure_result_t
check( config_t const * config,
       int              check_type ) {
  if( !( check_type==FD_CONFIGURE_CHECK_TYPE_PRE_INIT ||
         check_type==FD_CONFIGURE_CHECK_TYPE_CHECK ||
         check_type==FD_CONFIGURE_CHECK_TYPE_RUN ) ) CONFIGURE_OK();

  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  ulong pack_tile_idx = fd_topo_find_tile( &config->topo, "pack", 0UL );
  ulong poh_tile_idx  = fd_topo_find_tile( &config->topo, "poh", 0UL );

  ulong pack_pair = determine_ht_pair( config, cpus, "pack", 0UL );
  ulong poh_pair  = determine_ht_pair( config, cpus, "poh",  0UL );

  int pack_pair_used = determine_cpu_used( config, pack_pair );
  int poh_pair_used  = determine_cpu_used( config, poh_pair );

  int pack_pair_online      = 0;
  int poh_pair_online       = 0;
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    if( i==pack_pair && !pack_pair_used ) {
      if( FD_UNLIKELY( cpus->cpu[ i ].online ) ) pack_pair_online = 1;
    } else if( i==poh_pair && !poh_pair_used ) {
      if( FD_UNLIKELY( cpus->cpu[ i ].online ) ) poh_pair_online = 1;
    }
  }

  if( FD_UNLIKELY( pack_pair_used ) )        FD_LOG_WARNING(( "pack cpu %lu has hyperthread pair cpu %lu which is used by another tile. Proceeding but performance may be reduced.", config->topo.tiles[ pack_tile_idx ].cpu_idx, pack_pair ));
  else if( FD_UNLIKELY( pack_pair_online ) ) FD_LOG_WARNING(( "pack cpu %lu has hyperthread pair cpu %lu which should be offline. Proceeding but performance may be reduced.", config->topo.tiles[ pack_tile_idx ].cpu_idx, pack_pair ));
  if( FD_UNLIKELY( poh_pair_used  ) )        FD_LOG_WARNING(( "poh cpu %lu has hyperthread pair cpu %lu which is used by another tile. Proceeding but performance may be reduced.", config->topo.tiles[ poh_tile_idx ].cpu_idx, poh_pair ));
  else if( FD_UNLIKELY( poh_pair_online ) )  FD_LOG_WARNING(( "poh cpu %lu has hyperthread pair cpu %lu which should be offline. Proceeding but performance may be reduced.", config->topo.tiles[ poh_tile_idx ].cpu_idx, poh_pair ));

  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_hyperthreads = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = NULL,
  .init_perm       = NULL,
  .fini_perm       = NULL,
  .init            = NULL,
  .fini            = NULL,
  .check           = check,
};

#undef NAME
