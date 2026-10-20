#ifndef HEADER_fd_src_disco_topo_fd_topob_layout_h
#define HEADER_fd_src_disco_topo_fd_topob_layout_h

/* fd_topob_layout assigns topology tiles to CPUs.  Configs with an
   explicit [layout.affinity] are parsed by fd_topob_parse_affinity_cstr
   instead; "auto" runs fd_topob_auto_layout.

   Auto layout walks CPUs in NUMA node order with each CPU's HT sibling
   right after it, skipping blocklisted and offline CPUs.  Each tile's
   class (FD_TOPOB_TILE_*, keyed by name) decides its placement:

     - ALWAYS tiles are placed first.  STARTUP and POSTSTART tiles are
       then placed over the same remaining CPUs, since startup tiles
       exit before post-start tiles wake.
     - FLOATING tiles get no CPU and run wherever the kernel puts them,
       kept off pinned cores and their siblings by the launcher.
     - With a physical core per tile, every tile gets a whole core.
       Otherwise SMT_CRITICAL tiles still get one, DEDICATED tiles get
       one while spare logical CPUs last, and the rest share cores.
       Firedancer ranks the steady tiles instead and shares only as
       many cores as needed, lowest ranked first.

   In efficient mode (tiles park when idle), only SMT_CRITICAL,
   THROUGHPUT and PIN_EFFICIENT tiles are pinned; the rest float over
   a pool and cpu_idx only picks its NUMA node.  Pinned tiles prefer
   CPUs isolated by isolcpus= and floaters never use them.  Every
   choice is checked to leave room for the tiles still to place, and
   preferences relax rather than fail.  On hosts with a complete cache
   topology and room to spare, the tiles that wake each other the most
   are first packed onto whole cores in as few L3 domains as possible.

   Frankendancer reserves the CPUs left over for Agave threads. */

#include "fd_topo.h"
#include "fd_cpu_topo.h"

/* Affinity entries prefixed with 's' ("s2", "s2-3") are shared, the
   tile is homed at that CPU but floats over the shared CPUs on the
   same NUMA node.  The bit is set in the parsed CPU index, and only
   callers passing allow_shared accept it. */
#define FD_TOPOB_CPU_SHARED (0x8000UL)

/* Tile priority types used by fd_topob_auto_layout to classify tiles
   into scheduling categories. */
#define FD_TOPOB_PRIORITY_FLOATING (1)
#define FD_TOPOB_PRIORITY_STARTUP  (2)
#define FD_TOPOB_PRIORITY_NORMAL   (3)
#define FD_TOPOB_PRIORITY_CRITICAL (4)

/* Tile classes for the auto layout and the CPU isolation stages.

   Phases, exactly one per known tile:
     - ALWAYS:    runs for the whole process lifetime
     - STARTUP:   shuts down after snapshot load
     - POSTSTART: sleeps until snapshot load finishes
     - FLOATING:  yields to the kernel scheduler

   Placement flags, any combination:
     - SMT_CRITICAL:  hyperthread sibling kept idle
     - DEDICATED:     whole core while spare logical CPUs last
     - THROUGHPUT:    pinned in efficient mode, with an idle sibling
     - PIN_EFFICIENT: pinned in efficient mode */

#define FD_TOPOB_TILE_ALWAYS        (1U<<0)
#define FD_TOPOB_TILE_STARTUP       (1U<<1)
#define FD_TOPOB_TILE_POSTSTART     (1U<<2)
#define FD_TOPOB_TILE_FLOATING      (1U<<3)
#define FD_TOPOB_TILE_SMT_CRITICAL  (1U<<4)
#define FD_TOPOB_TILE_DEDICATED     (1U<<5)
#define FD_TOPOB_TILE_THROUGHPUT    (1U<<6)
#define FD_TOPOB_TILE_PIN_EFFICIENT (1U<<7)

#define FD_TOPOB_TILE_PHASE (FD_TOPOB_TILE_ALWAYS|FD_TOPOB_TILE_STARTUP|FD_TOPOB_TILE_POSTSTART|FD_TOPOB_TILE_FLOATING)
#define FD_TOPOB_TILE_EFFICIENT_PINNED (FD_TOPOB_TILE_SMT_CRITICAL|FD_TOPOB_TILE_THROUGHPUT|FD_TOPOB_TILE_PIN_EFFICIENT)

FD_PROTOTYPES_BEGIN

/* fd_topob_tile_class returns the FD_TOPOB_TILE_* flags of the tile
   named name, 0 if the tile is unknown. */

FD_FN_PURE uint
fd_topob_tile_class( char const * name );

/* Automatically layout the tiles onto CPUs in the topology for a
   best effort.  fd_topob_auto_layout reads CPU topology from the OS.
   fd_topob_auto_layout_cpus takes a pre-built CPU topology, useful
   for testing. */

void
fd_topob_auto_layout( fd_topo_t * topo,
                      int         reserve_agave_cores );

void
fd_topob_auto_layout_cpus( fd_topo_t *      topo,
                           fd_topo_cpus_t * cpus,
                           int              reserve_agave_cores );

/* Classify a tile into one of the FD_TOPOB_PRIORITY_* categories. */
int
fd_topob_tile_priority_type( fd_topo_tile_t const * tile );

int
fd_topob_cpu_overlap_allowed( fd_topo_tile_t const * a,
                              fd_topo_tile_t const * b,
                              int                    floats_share );

void
fd_topob_validate_cpu_overlaps( fd_topo_t const * topo );

ulong
fd_topob_parse_affinity_cstr( char const * cstr,
                              ushort *     tile_to_cpu,
                              int          allow_repeats,
                              int          allow_shared );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_topo_fd_topob_layout_h */
