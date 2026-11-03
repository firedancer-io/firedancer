/* The kworkers stage removes Firedancer tile CPUs from the cpumask of
   unbound kernel workqueues, so that deferred kernel work (writeback,
   vmstat refresh, various driver bottom halves, and notably the
   nohz_full remote tick offload) runs on housekeeping CPUs instead of
   stealing time from spinning tiles.

   In rare cases, rewriting the mask can cause unrecoverable stalls
   (Linux commit 703ccb63ae9f). To mitigate this, the auto layout keeps
   unbound kernel workqueues and firedancer tiles assigned to cpus on
   disjoint dies (best effort). This prevents the kworker mask from
   being changed unless a significant layout change requires it.

   fini is a nop, since restoring the cpumask might trigger the kernel bug mentioned above.

   The kernel exposes this as a global hex mask at
   /sys/devices/virtual/workqueue/cpumask.  Per-CPU (bound) kworkers
   are unaffected: they are idle unless work is queued on their CPU,
   which the irq-affinity and cpuset stages minimize.

   The kernel rejects a mask with no online CPU, so like irq-affinity
   this stage refuses to run if tiles cover every host CPU. */

#include "configure.h"
#include "fd_cpu_isolation.h"
#include "../../../../disco/topo/fd_cpu_topo.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define NAME "kworkers"

#define WQ_CPUMASK_PATH           "/sys/devices/virtual/workqueue/cpumask"
#define WQ_CPUMASK_REQUESTED_PATH "/sys/devices/virtual/workqueue/cpumask_requested"

/* read_wq_cpumask returns the online CPUs in the workqueue cpumask.
   If requested, that is the mask written by userspace
   (cpumask_requested, where it exists), else the effective mask
   (cpumask, which also drops isolated CPUs).  Fails fast on IO or parse
   errors: this is a kernel-provided file with a fixed format, so
   failures mean something is wrong that we should not paper over. */

static fd_cpuset_t *
read_wq_cpumask( fd_cpuset_t cpuset[ static fd_cpuset_word_cnt ],
                 int         requested ) {
  char const * path = requested && 0==access( WQ_CPUMASK_REQUESTED_PATH, F_OK ) ? WQ_CPUMASK_REQUESTED_PATH : WQ_CPUMASK_PATH;
  int fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "open(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  char mask[ FD_CPU_ISOLATION_MASK_MAX+64UL ];
  long mask_len = read( fd, mask, sizeof(mask)-1UL );
  if( FD_UNLIKELY( mask_len<=0L ) ) FD_LOG_ERR(( "read(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  mask[ mask_len ] = '\0';

  if( FD_UNLIKELY( !fd_cpu_isolation_parse_mask( cpuset, mask ) ) )
    FD_LOG_ERR(( "failed to parse `%s` (\"%s\")", path, mask ));
  FD_CPUSET_DECL( online );
  return fd_cpuset_intersect( cpuset, cpuset, fd_cpu_isolation_online_cpus( online ) );
}

static void
write_wq_cpumask( fd_cpuset_t const * cpuset ) {
  char mask[ FD_CPU_ISOLATION_MASK_MAX ];
  fd_cpu_isolation_format_mask( mask, sizeof(mask), cpuset );
  ulong mask_len = strlen( mask );

  FD_LOG_NOTICE(( "%sRUN: `echo \"%s\" > " WQ_CPUMASK_PATH "`%s", fd_log_style_dim(), mask, fd_log_style_normal() ));

  int fd = open( WQ_CPUMASK_PATH, O_WRONLY );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "open(" WQ_CPUMASK_PATH ") failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  FD_CPUSET_DECL( before );
  int have_before = fd_cpu_isolation_read_wq_mask( before );
  if( FD_UNLIKELY( write( fd, mask, mask_len )!=(long)mask_len ) )
    FD_LOG_ERR(( "write(" WQ_CPUMASK_PATH ") failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close(" WQ_CPUMASK_PATH ") failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( have_before ) fd_cpu_isolation_warn_wq_change( WQ_CPUMASK_PATH, before );
}

static fd_cpuset_t *
target_wq_cpumask( fd_cpuset_t       target[ static fd_cpuset_word_cnt ],
                   fd_cpuset_t       banned[ static fd_cpuset_word_cnt ],
                   fd_topo_t const * topo ) {
  fd_cpu_isolation_banned_cpus( banned, topo );
  fd_topo_cpus_t cpus[1];
  fd_topo_cpus_init( cpus );
  if( fd_cpuset_is_null( fd_topo_cpus_free_dies( cpus, banned, target ) ) )
    fd_cpuset_subtract( target, fd_cpu_isolation_online_cpus( target ), banned );
  return target;
}

static int
enabled( config_t const * config ) {
  (void)config;
  return 0==access( WQ_CPUMASK_PATH, F_OK );
}

static void
init_perm( fd_cap_chk_t *   chk,
           config_t const * config FD_PARAM_UNUSED ) {
  fd_cap_chk_root( chk, NAME, "modify `" WQ_CPUMASK_PATH "`" );
}

static void
init( config_t const * config ) {
  FD_CPUSET_DECL( target );
  FD_CPUSET_DECL( banned );
  target_wq_cpumask( target, banned, &config->topo );
  if( FD_UNLIKELY( fd_cpuset_is_null( target ) ) )
    FD_LOG_ERR(( "all host CPUs are assigned to Firedancer tiles; cannot reserve any CPU for kernel workqueues" ));
  write_wq_cpumask( target );
}

static configure_result_t
check( config_t const * config,
       int              check_type ) {
  FD_CPUSET_DECL( target );
  FD_CPUSET_DECL( banned );
  target_wq_cpumask( target, banned, &config->topo );
  /* run only cares that workqueues cannot use Firedancer CPUs now, not
     that init is current */
  int run = check_type==FD_CONFIGURE_CHECK_TYPE_RUN;
  FD_CPUSET_DECL( current );
  read_wq_cpumask( current, !run );

  if( run ) {
    FD_CPUSET_DECL( overlap );
    fd_cpuset_intersect( overlap, current, banned );
    if( FD_UNLIKELY( !fd_cpuset_is_null( overlap ) ) ) {
      char list[ FD_CPU_ISOLATION_LIST_MAX ];
      fd_cpu_isolation_format_list( list, sizeof(list), overlap );
      NOT_CONFIGURED( "kernel workqueue cpumask includes Firedancer CPUs %s", list );
    }
  } else if( FD_UNLIKELY( !fd_cpuset_eq( current, target ) ) ) {
    char list[ FD_CPU_ISOLATION_LIST_MAX ];
    fd_cpu_isolation_format_list( list, sizeof(list), target );
    NOT_CONFIGURED( "kernel workqueue cpumask is not CPUs %s", list );
  }
  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_kworkers = {
  .name            = NAME,
  .always_recreate = 0,
  .enabled         = enabled,
  .init_perm       = init_perm,
  .fini_perm       = NULL,
  .init            = init,
  .fini            = NULL,
  .check           = check,
};

#undef NAME
#undef WQ_CPUMASK_PATH
#undef WQ_CPUMASK_REQUESTED_PATH
