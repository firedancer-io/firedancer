#ifndef HEADER_fd_src_util_fd_util_h
#define HEADER_fd_src_util_fd_util_h

//#include "fd_util_base.h"         /* includes stdalign.h, string.h, limits.h, float.h */
//#include "bits/fd_bits.h"         /* includes fd_util_base.h */
//#include "sanitize/fd_asan.h"     /* includes fd_util_base.h" */
//#include "sanitize/fd_sanitize.h" /* includes sanitize/fd_asan.h */
//#include "cstr/fd_cstr.h"         /* includes bits/fd_bits.h */
//#include "io/fd_io.h"             /* includes bits/fd_bits.h */
//#include "pod/fd_pod.h"           /* includes cstr/fd_cstr.h */
//#include "env/fd_env.h"           /* includes cstr/fd_cstr.h */
//#include "log/fd_log.h"           /* includes env/fd_env.h io/fd_io.h */
//#include "shmem/fd_shmem.h"       /* includes log/fd_log.h */
//#include "tile/fd_tile.h"         /* includes shmem/fd_shmem.h */
//#include "wksp/fd_wksp.h"         /* includes shmem/fd_shmem.h pod/fd_pod.h */
//#include "valloc/fd_valloc.h"     /* includes fd_util_base.h */
//#include "scratch/fd_scratch.h"   /* includes tile/fd_tile.h sanitize/fd_sanitize.h valloc/fd_valloc.h */
#include "math/fd_stat.h"           /* includes bits/fd_bits.h */
#include "bits/fd_sat.h"
#include "hist/fd_histf.h"
#include "rng/fd_rng.h"             /* includes bits/fd_bits.h */
#include "tpool/fd_tpool.h"         /* includes tile/fd_tile.h and scratch/fd_scratch.h */
#include "alloc/fd_alloc.h"         /* includes wksp/fd_wksp.h valloc/fd_valloc.h */
#include "sandbox/fd_sandbox.h"

/* Additional fd_util APIs that are not included by default */

//#include "archive/fd_ar.h"  /* includes fd_util_base.h */
//#include "net/fd_eth.h"     /* includes bits/fd_bits.h */
//#include "net/fd_ip4.h"     /* includes bits/fd_bits.h */
//#include "net/fd_pcap.h"    /* includes net/fd_eth.h */
//#include "net/fd_igmp.h"    /* includes net/fd_ip4.h */
//#include "net/fd_udp.h"     /* includes net/fd_ip4.h */
//#include "bits/fd_float.h"  /* includes bits/fd_bits.h */
//#include "bits/fd_uwide.h"  /* includes bits/fd_bits.h */
//#include "math/fd_sqrt.h"   /* includes bits/fd_bits.h */
//#include "math/fd_fxp.h"    /* includes math/fd_sqrt.h, (!FD_HAS_INT128) bits/fd_uwide.h */
//#include "simd/fd_sse.h"    /* includes bits/fd_bits.h, requires FD_HAS_SSE */
//#include "simd/fd_avx.h"    /* includes bits/fd_bits.h, requires FD_HAS_AVX */
//#include "simd/fd_avx512.h" /* includes bits/fd_bits.h, requires FD_HAS_AVX512 */

FD_PROTOTYPES_BEGIN

/* Boot/halt all fd_util services.  fd_boot is intended to be called
   explicitly once immediately after the main thread in a thread group
   starts.  fd_halt is intended to be called explicitly once immediately
   before normal thread group shutdown.

   Command line / environment options (last option on command line takes
   precedence, command line will be stripped of these options):

     --log-path [cstr] / FD_LOG_PATH=[cstr]

       Provides the location where the permanent log for this process
       should be appended (created if not already existing).  If not
       specified, will autogenerate a descriptive log path that will
       almost certainly be globally unique.  If specified as an empty
       string, will disable the permanent log for this process.  If
       specified as "-", the permanent log will be written to stdout.
       The shortened ephemeral log will always be written to stderr.
       This option might be ignored by some targets (e.g. unhosted
       machine targets).

     --log-dedup [int] / FD_LOG_DEDUP=[int]

       Zero indicates the logger should not try to do any log message
       deduplication.  Non-zero indicates it should.  Defaults to 1.
       This option might be ignored by some targets (e.g. unhosted
       machine targets where deduplication would be handled by the
       pretty printer at the other side of the tether).

     --log-backtrace [int] / FD_LOG_BACKTRACE=[int]

       Zero indicates the logging should not try to any backtracing in
       response to signals that (by default) terminate the thread group.
       Non-zero indicates it should.  Defaults to 1.  This option might
       be ignored by some targets (e.g. unhosted machine targets where
       backtracing would be handled by the pretty printer at the other
       side of the tether).

     --log-app-id [ulong] / FD_LOG_APP_ID=[ulong]

       Provides the application id of the application running the
       caller.  If not provided, defaults to 0.  An application id is
       intended to be, at a minimum, enterprise unique over all
       currently running applications.  It is the thread group
       launcher's responsibility for determining this.

     --log-app [cstr] / FD_LOG_APP=[cstr]

       Provides an application description.  If that is not available,
       falls back to "[app]".  This string might be truncated and
       sanitized as needed for logging.

     --log-thread-id [ulong] / FD_LOG_THREAD_ID=[ulong]

       Provides the first application thread id to use in the
       application thread group to which the caller belongs.  If not
       provided defaults to 0.  A thread id is intended to be, at a
       minimum, application wide unique over all currently running
       threads in the application (this is neither a tid nor
       contiguous).  The caller will be assigned this first id.  If
       there can be more than one thread in the thread group to which
       the caller belongs, subsequently created threads will be assigned
       thread ids sequentially from this.  The thread group launcher is
       responsible for setting the initial thread id for each
       application thread group such that ids will not collide with
       application ids from other thread groups (e.g. assign
       non-overlapping blocks of thread ids to each application thread
       group and pass the first thread each block for the fd_boot to the
       corresponding thread group here ... note that as a result, it is
       possible for a launcher to assign thread ids to all application
       threads sequentially from zero in the common case of applications
       that have a fixed number of threads for the application's
       lifetime).

     --log-thread [cstr] / FD_LOG_THREAD=[cstr]

       Provides the caller's threads description.  If not provided,
       falls back to a target specific default (e.g. "[tid]@[cpu]").
       This string might be truncated and sanitized as needed for
       logging.

     --log-host-id [ulong] / FD_LOG_HOST_ID=[ulong]

       Provides the host id of the host running the caller.  If not
       provided, defaults to 0.  It is intended that this be, at a
       minimum, application wide unique over all hosts currently running
       application threads.  It is the thread group launcher's
       responsibility for guaranteeing this.

     --log-host [cstr] / FD_LOG_HOST=[cstr]

       Provides the host description for the thread group to which the
       caller belongs.  If not provided, falls back to gethostname().
       If that is not available, falls back to a target specific default
       (e.g. host's name).  This string might be truncated and sanitized
       as needed for logging.

     --log-cpu-id [ulong] / FD_LOG_CPU_ID=[ulong]

       Provides the cpu id of the cpu running the caller.  If not
       provided, defaults to 0.  It is intended that a cpu id be unique
       over all cpus currently available on a host.  This is stripped
       but otherwise ignored on targets where an underlying OS assigns
       this (e.g. the lowest indexed core in a /proc/cpuinfo sense the
       caller is allowed to run on).

     --log-cpu [cstr] / FD_LOG_CPU=[cstr]

       Provides the description for the cpu running the caller the
       thread group to which the caller belongs.  If not provided, falls
       back to a target specific default (e.g. the cpu-id pretty
       printed).  This string might be truncated and sanitized as needed
       for logging.

     --log-group-id [ulong] / FD_LOG_GROUP_ID=[ulong]

       Provides the group id of the thread group to which the caller
       belongs.  If not provided, defaults to 0.  This is stripped but
       otherwise ignored on targets where an underlying OS assigns this
       (e.g. the pid of the process containing the caller).

     --log-group [cstr] / FD_LOG_GROUP=[cstr]

       Provides the description of the cpu running the caller.  If not
       provided, falls back to program_invocation_short_name (if
       applicable).  If that is not available, falls back to argv[0] (if
       applicable).  This string might be truncated and sanitized as
       needed for logging.

     --log-tid [ulong] / FD_LOG_TID=[ulong]

       Provides the tid of the caller in the caller's thread group.  If
       not provided, defaults to 0.  This is stripped but otherwise
       ignored on targets where the underlying OS assigns this (e.g. the
       tid of the process containing the caller).

     --log-user-id [ulong] / FD_LOG_USER_ID=[ulong]

       Provides the user id of the user responsible for the caller.  If
       not provided, defaults to 0.  This is stripped but otherwise
       ignored on targets where an underlying OS assigns this (e.g. the
       user ID of the person who started the caller's process).

     --log-user [cstr] / FD_LOG_USER=[cstr]

       Provides the user of the caller's thread group.  If not provided,
       falls back to the environment LOGNAME value (if applicable).  If
       that is not available, falls back on getlogin() (if applicable).
       If that is not available, falls back to "[user]".  This string
       might be truncated and sanitized as needed for logging.

     --log-colorize      [int] / FD_LOG_COLORIZE=[int]      / default system
     --log-level-logfile [int] / FD_LOG_LEVEL_LOGFILE=[int] / default 1 ... >=INFO
     --log-level-stderr  [int] / FD_LOG_LEVEL_STDERR=[int]  / default 2 ... >=NOTICE
     --log-level-flush   [int] / FD_LOG_LEVEL_FLUSH=[int]   / default 3 ... >=WARNING
     --log-level-core    [int] / FD_LOG_LEVEL_CORE=[int]    / default 5 ... >=CRIT

       These configure the behaviors of the logger.

       A non-zero colorize indicates stderr log messages should be
       colorized.  default is disabled unless either
       COLORTERM==truecolor or TERM==xterm-256color in the environment.
       (This can also be enabled / disabled on the fly by the program
       itself.) Note that the permanent log is _never_ colorized to aid
       in robust log file message archiving.

       logfile is the minimal level for which the logger should write
       detailed messages to the permanent log file (if there is one).
       stderr is the minimal level for which the logger should write
       summarized messages to the ephemeral log stream.  flush is the
       minimal level at which the logger should try to immediately flush
       out messages.  core is the level at which an abortive log message
       should attempt to write out a core and do a backtrace.

         0 - DEBUG
         1 - INFO
         2 - NOTICE
         3 - WARNING
         4 - ERR
         5 - CRIT
         6 - ALERT
         7 - EMERG

       If these are set weirdly (i.e. decreasing or core is not at least
       4), they will be overridden to values that are sensible.

       Setting logfile, stderr, flush <=0 and core==4 makes the log
       maximally chatty.  Setting logfile, stderr, flush, core >7 makes
       the log minimally chatty.

     --shmem-path [path] / FD_SHMEM_PATH=[path]

       Give the location of the hugetlbs mounts for the shared memory
       domain this thread group will use.  Defaults to "/mnt/.fd" if not
       specified.  Ignored if not a hosted x86 implementation.

     --tile-cpus [cpu-list] / FD_TILE_CPUS=[cpu-list]

       For a thread group of an application on a hosted target, this
       specifies the cpus to use.  E.g.

         --tile-cpus f,1-3,f2,9,7,11-17/2

       specifies this application thread group has 12 tiles that should
       be mapped to cpus on this host as:

         tile  0 on floating
         tile  1 on cpu 1
         tile  2 on cpu 2
         tile  3 on cpu 3
         tile  4 on floating
         tile  5 on floating
         tile  6 on cpu 9
         tile  7 on cpu 7
         tile  8 on cpu 11
         tile  9 on cpu 13
         tile 10 on cpu 15
         tile 11 on cpu 17

       Floating tiles run on the cores the job launcher initially the
       thread group with whatever priority was initially assigned the
       thread group.  Fixed tiles run on the specified tile with high
       scheduler priority.  Tile 0's stack is the default stack used by
       the job launcher.  Floating tiles use the default stack provided
       by pthread_create.  All other tiles (i.e. high performance fixed
       tiles) use an 8 MiB huge page backed numa optimized stack (if
       possible).

       The booter will become tile 0.  The non-floating cpus in the list
       must be unique (e.g. multiple non-floating tiles cannot be
       assigned to the same cpu) and ranges in the list ("x-y") must be
       non-empty (i.e. x<=y).  If --tile-cpus is not provided, this
       thread group will be assumed to be single threaded and the cpu
       will be whatever the OS assigned to the booter (equivalent to
       "--tile-cpus f").

       Strides for a range of cores can be specified with a '/' or
       (taskset style) with a ':'.

       If tile 0 is not a floating tile, recommend using
       "taskset -c [cpu for tile 0]" or equivalent at thread group launch
       to have the OS place the booter on the correct cpu from the start. */

void
fd_boot( int *    pargc,
         char *** pargv );
void
fd_halt( void );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_fd_util_h */
