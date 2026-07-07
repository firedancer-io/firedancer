#ifndef HEADER_fd_src_app_shared_commands_configure_fd_cpu_isolation_h
#define HEADER_fd_src_app_shared_commands_configure_fd_cpu_isolation_h

/* Shared helpers for the CPU isolation configure stages (kworkers,
   cpuset, nohz-full, rcu-nocbs).  These stages all reason about the
   same thing: the set of CPUs hosting fixed (pinned) Firedancer tiles,
   and kernel interfaces that take CPU sets either as range lists
   ("0-3,7,9-11") or as comma-grouped hex masks ("0000000f,ffffff00"). */

#include "../../fd_config.h"
#include "../../../../util/tile/fd_tile_private.h"

FD_PROTOTYPES_BEGIN

/* fd_cpu_isolation_tile_cpus fills cpuset with the CPUs hosting fixed
   Firedancer tiles per the topology.  Floating tiles are ignored.
   Returns cpuset. */

fd_cpuset_t *
fd_cpu_isolation_tile_cpus( fd_cpuset_t       cpuset[ static fd_cpuset_word_cnt ],
                            fd_topo_t const * topo );

/* fd_cpu_isolation_host_cpus fills cpuset with all host CPUs
   [0,fd_shmem_cpu_cnt()).  Returns cpuset. */

fd_cpuset_t *
fd_cpu_isolation_host_cpus( fd_cpuset_t cpuset[ static fd_cpuset_word_cnt ] );

/* fd_cpu_isolation_parse_list parses a kernel CPU range list like
   "0-3,7,9-11\n" (e.g. contents of /sys/devices/system/cpu/nohz_full
   or a cpuset.cpus file) into cpuset.  An empty string or lone "\n"
   parses to the empty set.  Returns 1 on success, 0 on parse failure. */

int
fd_cpu_isolation_parse_list( fd_cpuset_t  cpuset[ static fd_cpuset_word_cnt ],
                             char const * list );

/* fd_cpu_isolation_read_list reads and parses the sysfs cpulist file
   at path into cpuset.  Returns 1 on success (including an empty or
   "(null)" list), 0 if the file does not exist (e.g. the kernel was
   compiled without support for the feature).  Any other IO or parse
   failure is fatal: these are kernel-provided files with a fixed
   format, and an unexpected failure reading them means something is
   wrong that should not be papered over. */

int
fd_cpu_isolation_read_list( char const * path,
                            fd_cpuset_t  cpuset[ static fd_cpuset_word_cnt ] );

/* fd_cpu_isolation_format_list formats cpuset as a kernel CPU range
   list ("0-3,7") into buf of size buf_sz (recommended at least
   FD_CPU_ISOLATION_LIST_MAX).  The empty set formats to an empty
   string.  Returns buf. */

#define FD_CPU_ISOLATION_LIST_MAX (4096UL)

char *
fd_cpu_isolation_format_list( char *              buf,
                              ulong               buf_sz,
                              fd_cpuset_t const * cpuset );

/* fd_cpu_isolation_partition_cpus fills cpuset with the CPUs that the
   cpuset stage places in the isolated partition: all fixed tile CPUs,
   plus the otherwise-unused hyperthread siblings of the tiles that are
   sensitive to SMT resource sharing (pack, poh, pohh; the same set the
   hyperthreads stage checks).  Isolating an unused sibling leaves it
   permanently idle in a deep sleep state, which relinquishes the
   physical core's shared execution resources about as well as taking
   the CPU offline, while keeping it available for future use.
   Siblings used by another tile, offline, or nonexistent are not
   added.  Returns cpuset. */

fd_cpuset_t *
fd_cpu_isolation_partition_cpus( fd_cpuset_t       cpuset[ static fd_cpuset_word_cnt ],
                                 fd_topo_t const * topo );

/* fd_cpu_isolation_parse_mask parses a comma-grouped hex CPU mask like
   "0000000f,ffffff00\n" (e.g. contents of
   /sys/devices/virtual/workqueue/cpumask) into cpuset.  Returns 1 on
   success, 0 on parse failure. */

int
fd_cpu_isolation_parse_mask( fd_cpuset_t  cpuset[ static fd_cpuset_word_cnt ],
                             char const * mask );

/* fd_cpu_isolation_format_mask formats cpuset as a comma-grouped hex
   CPU mask sized to the host CPU count, into buf of size buf_sz
   (recommended at least FD_CPU_ISOLATION_MASK_MAX).  Returns buf. */

#define FD_CPU_ISOLATION_MASK_MAX (FD_TILE_MAX/4UL+FD_TILE_MAX/32UL+2UL)

char *
fd_cpu_isolation_format_mask( char *              buf,
                              ulong               buf_sz,
                              fd_cpuset_t const * cpuset );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_commands_configure_fd_cpu_isolation_h */
