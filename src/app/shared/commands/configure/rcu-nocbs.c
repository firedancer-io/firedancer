/* The rcu-nocbs stage checks that RCU callback processing is offloaded
   from Firedancer tile CPUs to housekeeping kthreads.

   Any CPU executing kernel code (syscalls, IRQs) generates RCU
   callbacks which are normally invoked from softirq context on the CPU
   that queued them.  The `rcu_nocbs=` boot parameter moves callback
   invocation to rcuo* kthreads which the scheduler places like any
   other thread, i.e. on housekeeping CPUs once tile CPUs are excluded
   from their affinity (the cpuset stage) or simply because tile CPUs
   are always busy.  nohz_full tile CPUs additionally require this to
   reach full tick silence; recent kernels imply rcu_nocbs for the
   nohz_full set, but being explicit is recommended and required on
   older kernels.

   Like nohz_full this is a boot-time parameter, so this is a
   check-only stage that WARNS with the exact suggested parameter
   rather than failing: Firedancer runs correctly (with slightly
   degraded jitter) without it.

   Unlike nohz_full, the kernel does NOT expose the offloaded set in
   sysfs, so the stage parses `rcu_nocbs=` out of /proc/cmdline.  CPUs
   in `nohz_full=` are implicitly offloaded as well (the kernel adds
   the nohz_full mask to the nocb mask), so the nohz_full sysfs set is
   unioned in.  A `rcu_nocbs=` parameter on a kernel without
   CONFIG_RCU_NOCB_CPU is silently ignored by the kernel; that
   misconfiguration is not detectable from userspace and not checked
   here. */

#include "configure.h"
#include "fd_cpu_isolation.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define NAME "rcu-nocbs"

#define NOHZ_FULL_PATH "/sys/devices/system/cpu/nohz_full"
#define CMDLINE_PATH   "/proc/cmdline"

/* read_cmdline_rcu_nocbs parses the `rcu_nocbs=` parameter out of
   /proc/cmdline into cpuset (empty set if the parameter is absent).
   The parameter value is a cpulist; the kernel also accepts the
   literal "all" (5.15+).  All word-boundary occurrences are parsed
   and unioned: the kernel invokes the parameter handler once per
   occurrence, each ORing into the nocb mask, and searching past
   embedded matches (a `rcu_nocbs=` suffix of some other parameter)
   also avoids missing a valid standalone occurrence later in the
   string. */

static void
read_cmdline_rcu_nocbs( fd_cpuset_t cpuset[ static fd_cpuset_word_cnt ] ) {
  fd_cpuset_new( cpuset );

  int fd = open( CMDLINE_PATH, O_RDONLY );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "open(" CMDLINE_PATH ") failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  char cmdline[ 4096 ];
  long cmdline_len = read( fd, cmdline, sizeof(cmdline)-1UL );
  if( FD_UNLIKELY( cmdline_len<0L ) ) FD_LOG_ERR(( "read(" CMDLINE_PATH ") failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close(" CMDLINE_PATH ") failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  cmdline[ cmdline_len ] = '\0';

  for( char * search=cmdline; (search=strstr( search, "rcu_nocbs=" )); ) {
    char * param = search;
    search += sizeof("rcu_nocbs=")-1UL;
    if( FD_UNLIKELY( param!=cmdline && !isspace( (uchar)param[-1] ) ) ) continue; /* substring of another param */
    param = search;

    char * end = param;
    while( *end && !isspace( (uchar)*end ) ) end++;
    int last = !*end;
    *end = '\0';

    if( FD_UNLIKELY( !strcmp( param, "all" ) ) ) {
      fd_cpu_isolation_host_cpus( cpuset );
    } else {
      FD_CPUSET_DECL( occurrence );
      if( FD_UNLIKELY( !fd_cpu_isolation_parse_list( occurrence, param ) ) )
        FD_LOG_ERR(( "failed to parse `rcu_nocbs=%s` from " CMDLINE_PATH, param ));
      fd_cpuset_union( cpuset, cpuset, occurrence );
    }

    if( FD_UNLIKELY( last ) ) break;
    *end = ' '; /* restore the terminator we overwrote so the scan can continue */
    search = end;
  }
}

static configure_result_t
check( config_t const * config,
       int              check_type ) {
  if( !( check_type==FD_CONFIGURE_CHECK_TYPE_PRE_INIT ||
         check_type==FD_CONFIGURE_CHECK_TYPE_CHECK ||
         check_type==FD_CONFIGURE_CHECK_TYPE_RUN ) ) CONFIGURE_OK();

  FD_CPUSET_DECL( tile_cpus );
  fd_cpu_isolation_tile_cpus( tile_cpus, &config->topo );
  if( FD_UNLIKELY( !fd_cpuset_cnt( tile_cpus ) ) ) CONFIGURE_OK();

  char suggested[ FD_CPU_ISOLATION_LIST_MAX ];
  fd_cpu_isolation_format_list( suggested, sizeof(suggested), tile_cpus );

  /* Offloaded set = explicit rcu_nocbs= cmdline parameter, plus the
     nohz_full set which the kernel implicitly offloads.

     Tile CPUs missing from BOTH sets are already covered by the
     nohz-full stage, whose warning suggests setting nohz_full= and
     rcu_nocbs= together (one grub edit); repeating the advice here
     would be noise, so this stage only speaks when rcu_nocbs is the
     MARGINAL gap: tile CPUs deliberately excluded from nohz_full=
     (e.g. consolidation/housekeeping-adjacent cores where full
     dynticks accounting overhead is unwanted) that still want their
     RCU callbacks offloaded.  In that configuration the nohz-full
     stage warning is expected and ignored by the operator, and this
     is the only reminder that rcu_nocbs= should still cover the
     remaining tile CPUs. */
  FD_CPUSET_DECL( nocbs );
  read_cmdline_rcu_nocbs( nocbs );
  FD_CPUSET_DECL( nohz );
  fd_cpu_isolation_read_list( NOHZ_FULL_PATH, nohz );

  /* Nothing offloaded anywhere: the nohz-full stage warning (which
     suggests both parameters) covers it. */
  if( FD_LIKELY( !fd_cpuset_cnt( nocbs ) && !fd_cpuset_cnt( nohz ) ) ) CONFIGURE_OK();

  FD_CPUSET_DECL( offloaded );
  fd_cpuset_union( offloaded, nocbs, nohz );

  FD_CPUSET_DECL( missing );
  fd_cpuset_subtract( missing, tile_cpus, offloaded );
  if( FD_UNLIKELY( !fd_cpuset_is_null( missing ) ) ) {
    char missing_str[ FD_CPU_ISOLATION_LIST_MAX ];
    fd_cpu_isolation_format_list( missing_str, sizeof(missing_str), missing );
    FD_LOG_WARNING(( "tile cpus %s are in neither the `rcu_nocbs=` nor the `nohz_full=` boot parameter; RCU "
                     "callbacks may run on them. For lower jitter, extend `rcu_nocbs=` to cover them (a full "
                     "setting for all tile cpus is `rcu_nocbs=%s`).", missing_str, suggested ));
  }

  CONFIGURE_OK();
}

configure_stage_t fd_cfg_stage_rcu_nocbs = {
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
#undef CMDLINE_PATH
