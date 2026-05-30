#define _DEFAULT_SOURCE
#include "configure.h"
#include "../../../../disco/topo/fd_cpu_topo.h"
#include "../../../../util/tile/fd_tile_private.h"
#include "fd_irqbalance_client.h"
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>

#define NAME "irq-affinity"

/* smp_affinity file format is 4a4a4a4a,fcfcfcfc,...
   So, 9 bytes per 32 bits ~ 3.56 bits per byte. */
#define SMP_AFFINITY_STR_LEN (FD_TILE_MAX/3)

/* topo_allowed_cpus returns the set of CPUs that should be allowed to
   handle interrupts in *cpuset. */

static fd_cpuset_t *
topo_allowed_cpus( fd_cpuset_t cpuset[ static fd_cpuset_word_cnt ],
                   fd_topo_t const * topo ) {
  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );
  fd_cpuset_new( cpuset );
  fd_cpuset_insert_range( cpuset, 0, fd_shmem_cpu_cnt() );
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * tile = &topo->tiles[ i ];
    if( tile->cpu_idx < FD_TILE_MAX ) {
      fd_cpuset_remove( cpuset, tile->cpu_idx );
    }
  }
  return cpuset;
}

static int
enabled( config_t const * config ) {
  /* If irqbalance is running, tell it to isolate CPUs which have pinned
     tiles */
  (void)config;
  char path[ PATH_MAX ];
  return !!fd_irqbalance_socket_path( path, sizeof(path) );
}

static void
init( config_t const * config ) {
  char path[ PATH_MAX ];
  if( FD_UNLIKELY( !fd_irqbalance_socket_path( path, sizeof(path) ) ) ) {
    FD_LOG_ERR(( "error configuring IRQ affinity: cannot connect to irqbalance" ));
  }

  FD_CPUSET_DECL( banned );
  topo_allowed_cpus( banned, &config->topo );
  fd_cpuset_complement( banned, banned );
  fd_cpuset_select_range( banned, 0, fd_shmem_cpu_cnt() );

  fd_irqbalance_ban_cpus( banned, path );
}

static int
fini( config_t const * config,
      int              pre_init ) {
  (void)config; (void)pre_init;
  char path[ PATH_MAX ];
  if( FD_UNLIKELY( !fd_irqbalance_socket_path( path, sizeof(path) ) ) ) {
    FD_LOG_ERR(( "error configuring IRQ affinity: cannot connect to irqbalance" ));
  }

  FD_CPUSET_DECL( none );
  fd_cpuset_new( none );
  fd_irqbalance_ban_cpus( none, path );
  return 1;
}

static configure_result_t
check( config_t const * config FD_PARAM_UNUSED,
       int              check_type FD_PARAM_UNUSED ) {
  /* Note: There is no practical way to check whether the IRQ affinity
     init stage is completely "done".  In general this is a best-effort
     configuration and it is expected that many of the IRQ affinities
     will fail to be set.  We also can not check whether the irqbalance
     cpu ban setting is correct as this requires root privlidges.  Thus
     we set the always_recreate flag so we just re-run init every time. */
  configure_result_t result;
  result.result = CONFIGURE_PARTIALLY_CONFIGURED;
  result.message[ 0 ] = '\0';
  return result;
}

configure_stage_t fd_cfg_stage_irq_affinity = {
  .name            = NAME,
  .always_recreate = 1,
  .enabled         = enabled,
  .init            = init,
  .fini            = fini,
  .check           = check
};

#undef NAME
