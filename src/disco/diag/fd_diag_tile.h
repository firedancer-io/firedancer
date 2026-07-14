#ifndef HEADER_fd_src_disco_diag_fd_diag_tile_h
#define HEADER_fd_src_disco_diag_fd_diag_tile_h

#include "../fd_disco_base.h"

#define FD_DIAG_BUNDLE_STATUS_DISABLED     (0UL) /* No bundle tiles configured */
#define FD_DIAG_BUNDLE_STATUS_DISCONNECTED (1UL) /* All bundle tiles disconnected */
#define FD_DIAG_BUNDLE_STATUS_CONNECTING   (2UL) /* At least one bundle tile connecting, none connected or sleeping */
#define FD_DIAG_BUNDLE_STATUS_CONNECTED    (3UL) /* At least one bundle tile connected */
#define FD_DIAG_BUNDLE_STATUS_SLEEPING     (4UL) /* At least one bundle tile sleeping, none connected */

#define FD_DIAG_VOTE_STATUS_DISABLED    (0UL) /* Non-voting or no tower tile */
#define FD_DIAG_VOTE_STATUS_NOT_STARTED (1UL) /* Tower tile not running or no votes cast yet */
#define FD_DIAG_VOTE_STATUS_DELINQUENT  (2UL) /* Vote distance exceeds threshold or vote stalled */
#define FD_DIAG_VOTE_STATUS_VOTING      (3UL) /* Voting normally */

#define FD_DIAG_REPLAY_STATUS_DISABLED    (0UL) /* No replay tile */
#define FD_DIAG_REPLAY_STATUS_NOT_STARTED (1UL) /* Replay tile not running or slots are zero */
#define FD_DIAG_REPLAY_STATUS_BEHIND      (2UL) /* Replay lagging behind turbine or reset slot stalled */
#define FD_DIAG_REPLAY_STATUS_RUNNING     (3UL) /* Replay keeping up */

#define FD_DIAG_TURBINE_STATUS_DISABLED         (0UL) /* No shred or replay tiles */
#define FD_DIAG_TURBINE_STATUS_NOT_STARTED      (1UL) /* Tiles not all running or turbine slot is zero */
#define FD_DIAG_TURBINE_STATUS_STALLED          (2UL) /* Turbine slot not advancing */
#define FD_DIAG_TURBINE_STATUS_REPAIR_OUTPACING (3UL) /* Repair byte throughput exceeds turbine */
#define FD_DIAG_TURBINE_STATUS_RUNNING          (4UL) /* Turbine receiving normally */

#define FD_DIAG_SYSTEM_CPU_MAX      (1024UL)
#define FD_DIAG_SYSTEM_NUMA_MAX     (64UL)
#define FD_DIAG_SYSTEM_TILE_MAX     (256UL)
#define FD_DIAG_SYSTEM_TILE_MEM_MAX (FD_DIAG_SYSTEM_TILE_MAX*FD_DIAG_SYSTEM_NUMA_MAX)

#define FD_DIAG_SYSTEM_FILE_CATEGORY_ACCOUNTS  (0U)
#define FD_DIAG_SYSTEM_FILE_CATEGORY_SHREDS    (1U)
#define FD_DIAG_SYSTEM_FILE_CATEGORY_SNAPSHOTS (2U)
#define FD_DIAG_SYSTEM_FILE_CATEGORY_GUI       (3U)
#define FD_DIAG_SYSTEM_FILE_CATEGORY_LOGS      (4U)
#define FD_DIAG_SYSTEM_FILE_MAX                 (5UL)

struct fd_diag_system_cpu {
  ushort cpu_idx;
  ushort numa_idx;
  ushort sibling_idx; /* USHORT_MAX when unavailable/offline */
  uchar  online;
};
typedef struct fd_diag_system_cpu fd_diag_system_cpu_t;

struct fd_diag_system_numa_mem {
  ushort numa_idx;
  ulong  total_bytes;
  ulong  free_bytes;
  ulong  shared_bytes; /* Configured workspace bytes without a unique tile owner */
};
typedef struct fd_diag_system_numa_mem fd_diag_system_numa_mem_t;

struct fd_diag_system_tile_mem {
  ushort tile_idx;
  ushort numa_idx;
  ulong  allocated_bytes; /* Configured workspace and stack bytes */
};
typedef struct fd_diag_system_tile_mem fd_diag_system_tile_mem_t;

struct fd_diag_system_mount {
  char  path[ PATH_MAX ];
  ulong total_bytes;
  ulong free_bytes;
  ulong available_bytes;
};
typedef struct fd_diag_system_mount fd_diag_system_mount_t;

struct fd_diag_system_file {
  char  path[ PATH_MAX ];
  uint  category;
  uint  mount_idx;
  ulong bytes;
};
typedef struct fd_diag_system_file fd_diag_system_file_t;

struct fd_diag_system_resources {
  ulong                     sample_time_nanos;
  uint                      cpu_cnt;
  ulong                     mem_available_bytes;
  ulong                     mem_free_bytes;
  uint                      numa_mem_cnt;
  uint                      tile_mem_cnt;
  uint                      mount_cnt;
  uint                      file_cnt;
  fd_diag_system_cpu_t      cpu     [ FD_DIAG_SYSTEM_CPU_MAX      ];
  fd_diag_system_numa_mem_t numa_mem[ FD_DIAG_SYSTEM_NUMA_MAX     ];
  fd_diag_system_tile_mem_t tile_mem[ FD_DIAG_SYSTEM_TILE_MEM_MAX ];
  fd_diag_system_mount_t    mount   [ FD_DIAG_SYSTEM_FILE_MAX     ];
  fd_diag_system_file_t     file    [ FD_DIAG_SYSTEM_FILE_MAX     ];
};
typedef struct fd_diag_system_resources fd_diag_system_resources_t;

#endif /* HEADER_fd_src_disco_diag_fd_diag_tile_h */
