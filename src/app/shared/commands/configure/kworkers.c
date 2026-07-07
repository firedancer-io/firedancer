/* The kworkers stage removes Firedancer tile CPUs from the cpumask of
   unbound kernel workqueues, so that deferred kernel work (writeback,
   vmstat refresh, various driver bottom halves, and notably the
   nohz_full remote tick offload) runs on housekeeping CPUs instead of
   stealing time from spinning tiles.

   The kernel exposes this as a global hex mask at
   /sys/devices/virtual/workqueue/cpumask.  Per-CPU (bound) kworkers
   are unaffected: they are idle unless work is queued on their CPU,
   which the irq-affinity and cpuset stages minimize.

   The kernel rejects a mask with no online CPU, so like irq-affinity
   this stage refuses to run if tiles cover every host CPU.

   fini restores the mask to all host CPUs (the kernel default),
   which may over-restore if the operator had their own narrower mask
   before init; the previous mask is not persisted anywhere. */

#include "configure.h"
#include "fd_cpu_isolation.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define NAME "kworkers"

#define WQ_CPUMASK_PATH "/sys/devices/virtual/workqueue/cpumask"

/* read_wq_cpumask reads and parses the workqueue cpumask.  Fails fast
   on any error except the file being absent (which enabled() already
   gates on, but guard against removal races anyway): this is a
   kernel-provided file with a fixed format, so parse or IO failures
   mean something is wrong that we should not paper over. */

static void
read_wq_cpumask( fd_cpuset_t cpuset[ static fd_cpuset_word_cnt ] ) {
  int fd = open( WQ_CPUMASK_PATH, O_RDONLY );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "open(" WQ_CPUMASK_PATH ") failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  char mask[ FD_CPU_ISOLATION_MASK_MAX+64UL ];
  long mask_len = read( fd, mask, sizeof(mask)-1UL );
  if( FD_UNLIKELY( mask_len<=0L ) ) FD_LOG_ERR(( "read(" WQ_CPUMASK_PATH ") failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close(" WQ_CPUMASK_PATH ") failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  mask[ mask_len ] = '\0';

  if( FD_UNLIKELY( !fd_cpu_isolation_parse_mask( cpuset, mask ) ) )
    FD_LOG_ERR(( "failed to parse `" WQ_CPUMASK_PATH "` (\"%s\")", mask ));
}

static void
write_wq_cpumask( fd_cpuset_t const * cpuset ) {
  char mask[ FD_CPU_ISOLATION_MASK_MAX ];
  fd_cpu_isolation_format_mask( mask, sizeof(mask), cpuset );
  ulong mask_len = strlen( mask );

  FD_LOG_NOTICE(( "RUN: `echo \"%s\" > " WQ_CPUMASK_PATH "`", mask ));

  int fd = open( WQ_CPUMASK_PATH, O_WRONLY );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "open(" WQ_CPUMASK_PATH ") failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( write( fd, mask, mask_len )!=(long)mask_len ) )
    FD_LOG_ERR(( "write(" WQ_CPUMASK_PATH ") failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close(" WQ_CPUMASK_PATH ") failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static int
enabled( config_t const * config ) {
  (void)config;
  /* Not all kernels expose the unbound workqueue mask (CONFIG_SYSFS,
     ancient kernels).  If absent there is nothing to configure. */
  return 0==access( WQ_CPUMASK_PATH, F_OK );
}

static void
init_perm( fd_cap_chk_t *   chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "modify `" WQ_CPUMASK_PATH "`" );
}

static void
fini_perm( fd_cap_chk_t *   chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "modify `" WQ_CPUMASK_PATH "`" );
}

static void
init( config_t const * config ) {
  FD_CPUSET_DECL( tile_cpus );
  fd_cpu_isolation_tile_cpus( tile_cpus, &config->topo );

  FD_CPUSET_DECL( allowed );
  fd_cpu_isolation_host_cpus( allowed );
  fd_cpuset_subtract( allowed, allowed, tile_cpus );

  if( FD_UNLIKELY( !fd_cpuset_cnt( allowed ) ) )
    FD_LOG_ERR(( "all host CPUs are assigned to Firedancer tiles; cannot reserve any CPU for kernel workqueues" ));

  write_wq_cpumask( allowed );
}

static int
fini( config_t const * config,
      int              pre_init ) {
  (void)config; (void)pre_init;

  FD_CPUSET_DECL( all );
  fd_cpu_isolation_host_cpus( all );
  write_wq_cpumask( all );
  return 1;
}

static configure_result_t
check( config_t const * config,
       int              check_type ) {
  (void)check_type;

  FD_CPUSET_DECL( current );
  read_wq_cpumask( current );

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
  .enabled         = enabled,
  .init_perm       = init_perm,
  .fini_perm       = fini_perm,
  .init            = init,
  .fini            = fini,
  .check           = check,
};

#undef NAME
#undef WQ_CPUMASK_PATH
