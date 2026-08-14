/* The nohz-full stage checks that Firedancer tile CPUs run in full
   dynticks ("nohz_full") mode.

   On a nohz_full CPU running exactly one runnable task, the kernel
   stops the periodic scheduler tick, and (since kernel 4.17) offloads
   even the residual 1Hz tick to a housekeeping CPU via the global
   workqueue (see the kworkers stage, which keeps that workqueue off
   tile CPUs).  This removes ~CONFIG_HZ (typically 250/s) timer
   interrupts per second per tile CPU, each costing ~2-5us plus cache
   and branch predictor pollution.  See also the rcu-nocbs stage:
   nohz_full CPUs need rcu_nocbs to reach full silence.

   nohz_full is a boot-time kernel parameter: it cannot be configured
   at runtime, so this stage cannot have an init step.  It is a
   check-only stage (like hyperthreads) that WARNS with the exact
   suggested parameter rather than failing, since Firedancer runs
   correctly (with slightly degraded jitter) without it.

   The kernel exposes the active set in
   /sys/devices/system/cpu/nohz_full (cpulist; may contain "(null)" or
   be absent when CONFIG_NO_HZ_FULL is off).

   A CPU listed in nohz_full but running multiple tasks just keeps its
   tick, so listing extra CPUs is harmless.  Hence the suggested
   parameter covers ALL fixed tile CPUs.  One CPU must remain outside
   the set for timekeeping; since the topology never covers every host
   CPU (other stages enforce housekeeping CPUs exist), the tile set is
   always safe to suggest. */

#include "configure.h"
#include "fd_cpu_isolation.h"

#define NAME "nohz-full"

#define NOHZ_FULL_PATH "/sys/devices/system/cpu/nohz_full"

static configure_result_t
check( config_t const * config,
       int              check_type ) {
  if( !( check_type==FD_CONFIGURE_CHECK_TYPE_CHECK ||
         check_type==FD_CONFIGURE_CHECK_TYPE_RUN ) ) CONFIGURE_OK();

  /* Jitter tuning only matters for production validators against a
     live cluster, don't nag in development. */
  if( FD_LIKELY( !config->is_live_cluster || config->is_dev ) ) CONFIGURE_OK();

  FD_CPUSET_DECL( tile_cpus );
  fd_cpu_isolation_tile_cpus( tile_cpus, &config->topo );
  if( FD_UNLIKELY( !fd_cpuset_cnt( tile_cpus ) ) ) CONFIGURE_OK();

  char suggested[ FD_CPU_ISOLATION_LIST_MAX ];
  fd_cpu_isolation_format_list( suggested, sizeof(suggested), tile_cpus );

  FD_CPUSET_DECL( nohz );
  if( FD_UNLIKELY( !fd_cpu_isolation_read_list( NOHZ_FULL_PATH, nohz ) ) ) {
    FD_LOG_WARNING(( "kernel has no nohz_full support %s(missing " NOHZ_FULL_PATH ")%s. Firedancer tiles will be "
                     "interrupted by periodic timer ticks. For lower jitter, use a kernel with CONFIG_NO_HZ_FULL "
                     "and boot with %snohz_full=%s%s.",
                     fd_log_style_dim(), fd_log_style_normal(),
                     fd_log_style_bold(), suggested, fd_log_style_normal() ));
    CONFIGURE_OK();
  }

  FD_CPUSET_DECL( missing );
  fd_cpuset_subtract( missing, tile_cpus, nohz );
  if( FD_UNLIKELY( !fd_cpuset_is_null( missing ) ) ) {
    char missing_str[ FD_CPU_ISOLATION_LIST_MAX ];
    fd_cpu_isolation_format_list( missing_str, sizeof(missing_str), missing );
    FD_LOG_WARNING(( "tile cpus %s are not in the kernel nohz_full= set and will be interrupted by "
                     "periodic timer ticks. For lower jitter, boot with %snohz_full=%s%s.",
                     missing_str, fd_log_style_bold(), suggested, fd_log_style_normal() ));
  }

  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_nohz_full = {
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
#undef NOHZ_FULL_PATH
