#ifndef HEADER_fd_src_disco_topo_fd_cpu_topo_h
#define HEADER_fd_src_disco_topo_fd_cpu_topo_h

#include "fd_topo.h"
#include "../../util/tile/fd_tile_private.h"

struct fd_topo_cpu {
  ulong idx;
  int   online;
  ulong numa_node;
  ulong sibling;
  ulong package_idx;
  ulong die_idx;
  ulong l3_idx;
  int   isolated;
  int   nohz_full;
};

typedef struct fd_topo_cpu fd_topo_cpu_t;

struct fd_topo_cpus {
  ulong         numa_node_cnt;
  ulong         l3_cnt;

  ulong         cpu_cnt;
  fd_topo_cpu_t cpu[ FD_TILE_MAX ];
};

typedef struct fd_topo_cpus fd_topo_cpus_t;

FD_PROTOTYPES_BEGIN

/* Initialize the CPU topology structure by reading information from the
   operating system.  If the CPU topology cannot be determined, logs an
   error and exits the process. */

void
fd_topo_cpus_init( fd_topo_cpus_t * cpus );

void
fd_topo_cpus_printf( fd_topo_cpus_t * cpus );

/* fd_topo_cpus_l3_complete returns 1 if the host has more than one L3
   domain and every online CPU has a known one, the precondition for a
   layout that places tiles by L3. */

int
fd_topo_cpus_l3_complete( fd_topo_cpus_t const * cpus );

/* fd_topo_cpus_floating computes where the launcher runs unpinned
   tiles, given launch, the launcher's affinity.  float_cpu_set gets the
   CPUs of the floats tiles minus pinned CPUs and their siblings.
   cpuless_cpu_set, for tiles with no cpu_idx, gets the first non-empty
   of float_cpu_set & launch, launch minus pinned CPUs and siblings of
   non-floating pinned tiles, both minus isolated CPUs, and launch. */

void
fd_topo_cpus_floating( fd_topo_cpus_t const * cpus,
                       fd_topo_t const *      topo,
                       fd_cpuset_t const *    launch,
                       fd_cpuset_t *          float_cpu_set,
                       fd_cpuset_t *          cpuless_cpu_set );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_topo_fd_cpu_topo_h */
