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

static configure_result_t
check( config_t const * config,
       int              check_type ) {
  if( !( check_type==FD_CONFIGURE_CHECK_TYPE_CHECK ||
         check_type==FD_CONFIGURE_CHECK_TYPE_RUN ) ) CONFIGURE_OK();

  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );

  fd_topo_t const * topo = &config->topo;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    if( FD_LIKELY( tile->kind_id || !( !strcmp( tile->name, "pack" ) || !strcmp( tile->name, "poh" ) || !strcmp( tile->name, "pohh" ) ) ) ) continue;

    /* A floating tile (efficient layout mode) shares its cores with
       the other floaters, so an idle sibling buys it nothing */
    if( FD_UNLIKELY( tile->cpu_idx>=cpus->cpu_cnt || tile->floats ) ) continue;
    ulong pair = cpus->cpu[ tile->cpu_idx ].sibling;
    if( FD_UNLIKELY( pair>=cpus->cpu_cnt ) ) continue;

    int pair_used = 0;
    for( ulong j=0UL; j<topo->tile_cnt; j++ ) pair_used |= topo->tiles[ j ].cpu_idx==pair;

    /* An online-but-unused sibling inside this instance's isolated
       cpuset partition is permanently idle, which is about as good as
       offline for SMT purposes: no warning needed. */
    int pair_online = !pair_used && cpus->cpu[ pair ].online && !sibling_isolated_idle( config, pair );

    if( FD_UNLIKELY( pair_used ) )        FD_LOG_WARNING(( "%s cpu %lu has hyperthread pair cpu %lu which is used by another tile. Proceeding but performance may be reduced.", tile->name, tile->cpu_idx, pair ));
    else if( FD_UNLIKELY( pair_online ) ) FD_LOG_WARNING(( "%s cpu %lu has hyperthread pair cpu %lu which should be offline or in the isolated cpuset partition (`configure init cpuset`). Proceeding but performance may be reduced.", tile->name, tile->cpu_idx, pair ));
  }

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
