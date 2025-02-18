#include "configure.h"

#define NAME "hyperthreads"

#include "../../../disco/topo/fd_topob.h"
#include "../../../disco/topo/fd_cpu_topo.h"

static void
init_perm( fd_caps_ctx_t *  caps,
           config_t * const config ) {
  (void)config;
  fd_caps_check_root( caps, NAME, "enable and disable cpu cores in `/sys/devices/system/cpu`" );
}

static void
fini_perm( fd_caps_ctx_t *  caps,
           config_t * const config ) {
  (void)config;
  fd_caps_check_root( caps, NAME, "enable and disable cpu cores in `/sys/devices/system/cpu`" );
}

ulong
determine_ht_pair( config_t * const       config,
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
determine_cpu_used( config_t * const config,
                    ulong            cpu_idx ) {
  if( FD_UNLIKELY( cpu_idx==ULONG_MAX ) ) return 0;

  ulong tile_cnt = config->topo.tile_cnt;
  for( ulong i=0UL; i<tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &config->topo.tiles[ i ];
    if( tile->cpu_idx==cpu_idx ) return 1;
  }
  return 0;
}


static void
init( config_t * const config ) {
  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  ulong pack_pair = determine_ht_pair( config, cpus, "pack", 0UL );
  ulong poh_pair  = determine_ht_pair( config, cpus, "poh",  0UL );

  int pack_pair_used = determine_cpu_used( config, pack_pair );
  int poh_pair_used  = determine_cpu_used( config, poh_pair );

  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    char path[ PATH_MAX ];
    fd_cstr_printf_check( path, sizeof( path ), NULL, "/sys/devices/system/cpu/cpu%lu/online", i );

    if( (i==pack_pair && !pack_pair_used) || (i==poh_pair && !poh_pair_used) ) {
      if( FD_UNLIKELY( cpus->cpu[ i ].online ) ) {
        if( FD_UNLIKELY( !i ) ) FD_LOG_ERR(( "cpu0 is a hyperthread pair of poh or pack but it cannot be switched offline" ));
        FD_LOG_NOTICE(( "RUN: `echo \"0\" > %s`", path ));
        write_uint_file( path, 0U );
      }
    } else if( FD_UNLIKELY( !cpus->cpu[ i ].online ) ) {
      FD_LOG_NOTICE(( "RUN: `echo \"1\" > %s`", path ));
      write_uint_file( path, 1U );
    }
  }
}

static configure_result_t
check( config_t * const config ) {
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
  ulong other_thread_offline = ULONG_MAX;
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    if( i==pack_pair && !pack_pair_used ) {
      if( FD_UNLIKELY( cpus->cpu[ i ].online ) ) pack_pair_online = 1;
    } else if( i==poh_pair && !poh_pair_used ) {
      if( FD_UNLIKELY( cpus->cpu[ i ].online ) ) poh_pair_online = 1;
    } else if( FD_UNLIKELY( !cpus->cpu[ i ].online ) ) {
      other_thread_offline = i;
    }
  }

  int all_online = 1;
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    if( FD_UNLIKELY( !cpus->cpu[ i ].online ) ) {
      all_online = 0;
      break;
    }
  }

  if( FD_LIKELY( all_online ) ) {
    if( FD_UNLIKELY( pack_pair_online ) ) NOT_CONFIGURED( "pack cpu %lu has hyperthread pair %lu which should be offline", config->topo.tiles[ pack_tile_idx ].cpu_idx, pack_pair );
    else if( FD_UNLIKELY( poh_pair_online ) ) NOT_CONFIGURED( "poh cpu %lu has hyperthread pair %lu which should be offline", config->topo.tiles[ poh_tile_idx ].cpu_idx, poh_pair );
    else if( FD_UNLIKELY( other_thread_offline!=ULONG_MAX ) ) NOT_CONFIGURED( "cpu %lu is not a hyperthread pair of poh or pack but is offline", other_thread_offline );
  } else {
    if( FD_UNLIKELY( pack_pair_online ) ) PARTIALLY_CONFIGURED( "pack cpu %lu has hyperthread pair %lu which should be offline", config->topo.tiles[ pack_tile_idx ].cpu_idx, pack_pair );
    else if( FD_UNLIKELY( poh_pair_online ) ) PARTIALLY_CONFIGURED( "poh cpu %lu has hyperthread pair %lu which should be offline", config->topo.tiles[ poh_tile_idx ].cpu_idx, poh_pair );
    else if( FD_UNLIKELY( other_thread_offline!=ULONG_MAX ) ) PARTIALLY_CONFIGURED( "cpu %lu is not a hyperthread pair of poh or pack but is offline", other_thread_offline );
  }

  CONFIGURE_OK();
}

static void
fini( config_t * const config,
      int              pre_init ) {
  (void)config;
  (void)pre_init;

  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    char path[ PATH_MAX ];
    fd_cstr_printf_check( path, sizeof( path ), NULL, "/sys/devices/system/cpu/cpu%lu/online", i );

    if( FD_UNLIKELY( !cpus->cpu[ i ].online ) ) {
      FD_LOG_NOTICE(( "RUN: `echo \"1\" > %s`", path ));
      write_uint_file( path, 1U );
    }
  }
}

configure_stage_t fd_cfg_stage_hyperthreads = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = NULL,
  .init_perm       = init_perm,
  .fini_perm       = fini_perm,
  .init            = init,
  .fini            = fini,
  .check           = check,
};

#undef NAME
