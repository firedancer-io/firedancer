/* Keep unbound kernel workqueues off Firedancer tile CPUs without
   migrating ordered workqueues on kernels affected by Linux
   703ccb63ae9f.  Only accept an already compatible effective mask;
   the cpuset stage preserves it before partition removal.  fini
   intentionally leaves background workers restricted.  Per-CPU
   (bound) workers are unaffected. */

#include "configure.h"
#include "fd_cpu_isolation.h"

#include <unistd.h>

#define NAME "kworkers"

static int
wq_enabled( config_t const * config ) {
  (void)config;
  /* Not all kernels expose the unbound workqueue mask (CONFIG_SYSFS,
     ancient kernels).  If absent there is nothing to configure. */
  return 0==access( FD_CPU_ISOLATION_WQ_MASK_PATH, F_OK );
}

static void
wq_init_perm( fd_cap_chk_t *   chk,
              config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "modify `" FD_CPU_ISOLATION_WQ_MASK_PATH "`" );
}

static void
wq_init( config_t const * config ) {
  FD_CPUSET_DECL( tile_cpus );
  fd_cpu_isolation_tile_cpus( tile_cpus, &config->topo );
  fd_cpu_isolation_check_wq_mask( tile_cpus );
}

static int
wq_fini( config_t const * config,
         int              pre_init ) {
  (void)config; (void)pre_init;
  /* No undo: a restricted effective mask is still configured. */
  return 0;
}

static configure_result_t
wq_check( config_t const * config,
          int              check_type ) {
  (void)check_type;

  FD_CPUSET_DECL( current );
  fd_cpu_isolation_read_wq_mask( current );

  FD_CPUSET_DECL( tile_cpus );
  fd_cpu_isolation_tile_cpus( tile_cpus, &config->topo );

  FD_CPUSET_DECL( overlap );
  fd_cpuset_intersect( overlap, current, tile_cpus );
  if( FD_UNLIKELY( !fd_cpuset_is_null( overlap ) ) ) {
    char list[ FD_CPU_ISOLATION_LIST_MAX ];
    fd_cpu_isolation_format_list( list, sizeof(list), overlap );
    NOT_CONFIGURED( "kernel workqueue cpumask includes Firedancer tile CPUs %s", list );
  }

  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_kworkers = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = wq_enabled,
  .init_perm       = wq_init_perm,
  .fini_perm       = wq_init_perm,
  .init            = wq_init,
  .fini            = wq_fini,
  .check           = wq_check,
};

#undef NAME
