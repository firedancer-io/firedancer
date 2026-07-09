#include "configure.h"

#define NAME "hyperthreads"

#include "fd_cpu_isolation.h"
#include "../../../../disco/topo/fd_cpu_topo.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static int
sibling_isolated_idle( config_t const * config,
                       ulong            cpu_idx ) {
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof(path), NULL, "/sys/fs/cgroup/%s/cpuset.cpus", config->name ) );

  int fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( fd<0 ) ) {
    if( FD_LIKELY( errno==ENOENT ) ) return 0; /* cpuset stage not configured */
    FD_LOG_ERR(( "open(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }

  char list[ FD_CPU_ISOLATION_LIST_MAX ];
  long list_len = read( fd, list, sizeof(list)-1UL );
  if( FD_UNLIKELY( list_len<0L ) ) FD_LOG_ERR(( "read(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  list[ list_len ] = '\0';

  FD_CPUSET_DECL( partition );
  if( FD_UNLIKELY( !fd_cpu_isolation_parse_list( partition, list ) ) )
    FD_LOG_ERR(( "failed to parse `%s` (\"%s\")", path, list ));

  if( FD_LIKELY( cpu_idx>=FD_TILE_MAX || !fd_cpuset_test( partition, cpu_idx ) ) ) return 0;

  return 1;
}

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
  ulong pohh_tile_idx  = fd_topo_find_tile( &config->topo, "pohh", 0UL );
  ulong poh_tile_idx  = fd_topo_find_tile( &config->topo, "poh", 0UL );

  ulong pack_pair = determine_ht_pair( config, cpus, "pack", 0UL );
  ulong pohh_pair  = determine_ht_pair( config, cpus, "pohh",  0UL );
  ulong poh_pair = determine_ht_pair( config, cpus, "poh",  0UL );

  int pack_pair_used = determine_cpu_used( config, pack_pair );
  int pohh_pair_used  = determine_cpu_used( config, pohh_pair );
  int poh_pair_used = determine_cpu_used( config, poh_pair );

  int pack_pair_online = 0;
  int pohh_pair_online = 0;
  int poh_pair_online  = 0;
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    if( i==pack_pair && !pack_pair_used ) {
      if( FD_UNLIKELY( cpus->cpu[ i ].online ) ) pack_pair_online = 1;
    } else if( i==pohh_pair && !pohh_pair_used ) {
      if( FD_UNLIKELY( cpus->cpu[ i ].online ) ) pohh_pair_online = 1;
    } else if( i==poh_pair && !poh_pair_used ) {
      if( FD_UNLIKELY( cpus->cpu[ i ].online ) ) poh_pair_online = 1;
    }
  }

  /* An online-but-unused sibling inside this instance's isolated
     cpuset partition is permanently idle, which is about as good as
     offline for SMT purposes: no warning needed. */
  if( FD_UNLIKELY( pack_pair_online && sibling_isolated_idle( config, pack_pair ) ) ) pack_pair_online = 0;
  if( FD_UNLIKELY( pohh_pair_online && sibling_isolated_idle( config, pohh_pair ) ) ) pohh_pair_online = 0;
  if( FD_UNLIKELY( poh_pair_online  && sibling_isolated_idle( config, poh_pair  ) ) ) poh_pair_online  = 0;

  if( FD_UNLIKELY( pack_pair_used ) )        FD_LOG_WARNING(( "pack cpu %lu has hyperthread pair cpu %lu which is used by another tile. Proceeding but performance may be reduced.", config->topo.tiles[ pack_tile_idx ].cpu_idx, pack_pair ));
  else if( FD_UNLIKELY( pack_pair_online ) ) FD_LOG_WARNING(( "pack cpu %lu has hyperthread pair cpu %lu which should be offline or in the isolated cpuset partition (`configure init cpuset`). Proceeding but performance may be reduced.", config->topo.tiles[ pack_tile_idx ].cpu_idx, pack_pair ));
  if( FD_UNLIKELY( pohh_pair_used  ) )       FD_LOG_WARNING(( "pohh cpu %lu has hyperthread pair cpu %lu which is used by another tile. Proceeding but performance may be reduced.", config->topo.tiles[ pohh_tile_idx ].cpu_idx, pohh_pair ));
  else if( FD_UNLIKELY( pohh_pair_online ) ) FD_LOG_WARNING(( "pohh cpu %lu has hyperthread pair cpu %lu which should be offline or in the isolated cpuset partition (`configure init cpuset`). Proceeding but performance may be reduced.", config->topo.tiles[ pohh_tile_idx ].cpu_idx, pohh_pair ));
  if( FD_UNLIKELY( poh_pair_used  ) )        FD_LOG_WARNING(( "poh cpu %lu has hyperthread pair cpu %lu which is used by another tile. Proceeding but performance may be reduced.", config->topo.tiles[ poh_tile_idx ].cpu_idx, poh_pair ));
  else if( FD_UNLIKELY( poh_pair_online ) )  FD_LOG_WARNING(( "poh cpu %lu has hyperthread pair cpu %lu which should be offline or in the isolated cpuset partition (`configure init cpuset`). Proceeding but performance may be reduced.", config->topo.tiles[ poh_tile_idx ].cpu_idx, poh_pair ));

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
