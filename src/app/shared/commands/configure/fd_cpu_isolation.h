#ifndef HEADER_fd_src_app_shared_commands_configure_fd_cpu_isolation_h
#define HEADER_fd_src_app_shared_commands_configure_fd_cpu_isolation_h

/* Shared helpers for the CPU isolation configure stages (kworkers,
   cpuset, nohz-full, rcu-nocbs).  These stages all reason about the
   same thing: the set of CPUs hosting fixed (pinned) Firedancer tiles,
   and kernel interfaces that take CPU sets either as range lists
   ("0-3,7,9-11") or as comma-grouped hex masks ("0000000f,ffffff00"). */

#include "../../fd_config.h"
#include "../../../../util/tile/fd_tile_private.h"

FD_STATIC_ASSERT( FD_SHMEM_CPU_MAX<=FD_TILE_MAX, cpuset_holds_all_cpus );

FD_PROTOTYPES_BEGIN

/* fd_cpu_isolation_tile_cpus fills cpuset with the CPUs hosting fixed
   Firedancer tiles per the topology.  Floating tiles are ignored.
   Returns cpuset. */

fd_cpuset_t *
fd_cpu_isolation_tile_cpus( fd_cpuset_t       cpuset[ static fd_cpuset_word_cnt ],
                            fd_topo_t const * topo );

/* fd_cpu_isolation_online_cpus fills cpuset with the currently online
   host CPUs.  Offline CPUs cannot serve as housekeeping or IRQ targets.
   Returns cpuset. */

fd_cpuset_t *
fd_cpu_isolation_online_cpus( fd_cpuset_t cpuset[ static fd_cpuset_word_cnt ] );

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

/* fd_cpu_isolation_partition_type returns the cpuset.cpus.partition
   value for the topology: "isolated" (no scheduler domain, tiles are
   pinned 1:1) unless some tile floats within the tile CPU set, when
   the partition must keep a domain to balance them: "root". */

char const *
fd_cpu_isolation_partition_type( fd_topo_t const * topo );

/* fd_cpu_isolation_partition_cpus fills cpuset with the CPUs that the
   cpuset stage places in the isolated partition: all fixed tile CPUs,
   plus the otherwise-unused hyperthread siblings of the
   FD_TOPOB_TILE_SMT_CRITICAL tiles (the set the hyperthreads stage
   checks) and of FD_TOPOB_TILE_DEDICATED tiles placed on a whole core,
   the latter skipping blocklisted siblings and never taking the last
   housekeeping CPU.  Isolating an unused sibling leaves it permanently
   idle in a deep sleep state, which relinquishes the physical core's
   shared execution resources about as well as taking the CPU offline,
   while keeping it available for future use.  Siblings used by another
   tile, offline, or nonexistent are not added.  Returns cpuset. */

fd_cpuset_t *
fd_cpu_isolation_partition_cpus( fd_cpuset_t       cpuset[ static fd_cpuset_word_cnt ],
                                 fd_topo_t const * topo );

/* fd_cpu_isolation_banned_cpus fills cpuset with the CPUs that must not
   take device interrupts or unbound kernel work: the partition CPUs, or
   only the tile CPUs (with a warning) if the partition covers every
   online host CPU.  Returns cpuset. */

fd_cpuset_t *
fd_cpu_isolation_banned_cpus( fd_cpuset_t       cpuset[ static fd_cpuset_word_cnt ],
                              fd_topo_t const * topo );

/* fd_cpu_isolation_check_cgroup fails if a pinned tile is outside the
   process's cgroup cpuset.  Auto layout picks CPUs from sysfs and
   ignores the launcher's cgroup cpuset (systemd AllowedCPUs=, a
   container).  Following it would make configure, run and monitor,
   each launched differently, compute different layouts.  So a tile can
   land outside the cpuset, which otherwise fails late at spawn with a
   misleading EINVAL.

   Fail here instead, naming the tile and suggesting a blocklist.  Tiles
   join the instance partition before pinning, so its CPUs count as
   allowed.  A floating tile fails only if none of the CPUs it would run
   on is allowed.  Skipped when the cgroup v2 cpuset cannot be read. */

void
fd_cpu_isolation_check_cgroup( config_t const * config );

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

/* Best-effort workqueue mask diagnostics.  read_wq_mask returns 0 if
   unavailable; warn_wq_change compares a successful snapshot with the
   current mask after a write to path. */

int
fd_cpu_isolation_read_wq_mask( fd_cpuset_t cpuset[ static fd_cpuset_word_cnt ] );

void
fd_cpu_isolation_warn_wq_change( char const *        path,
                                 fd_cpuset_t const * before );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_app_shared_commands_configure_fd_cpu_isolation_h */
