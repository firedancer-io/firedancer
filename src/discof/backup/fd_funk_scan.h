#ifndef HEADER_fd_src_discof_backup_fd_funk_scan_h
#define HEADER_fd_src_discof_backup_fd_funk_scan_h

/* fd_funk_scan.h is a fast funk index scanner.

   Why? map_chain_para has horrible pointer-chasing characteristics.
   Naively iterating through a giant map_chain_para map on a Zen 5
   DDR5-4800 box results in about 6.5 million element/second throughput.

   funk_scan uses read-ahead & memory gather optimizations to amortize
   DRAM latency by keeping the CPU's load queue busy.

   funk_scan is able to achieve up to 100 million element/second for a
   rec_map with low load factor. */

#include "../../funk/fd_funk.h"
#include "../../flamenco/fd_flamenco_base.h"

#define FUNK_SCAN_PARA   64
#define SLOW_WALK_MAX     8
struct __attribute__((aligned(64))) fd_funk_scan_batch {
  ulong val_gaddr[ FUNK_SCAN_PARA ];  /* ULONG_MAX implies sentinel */
  uint  rec_idx  [ FUNK_SCAN_PARA ];
};
typedef struct fd_funk_scan_batch fd_funk_scan_batch_t;

typedef fd_funk_rec_map_shmem_private_chain_t fd_funk_rec_chain_t;
struct fd_funk_scan {
  fd_funk_rec_map_t *         rec_map;
  fd_funk_rec_chain_t const * chain_tbl;
  fd_funk_rec_t const *       rec_tbl;

  ulong chain_idx;
  ulong chain_max;

  /* Slow path for chains with more than one element */
  ulong slow_cnt;
  ulong walk_cnt;
  ulong walk_ele_idx  [ SLOW_WALK_MAX ];
  ulong walk_chain_idx[ SLOW_WALK_MAX ];
  ulong slow_chain[ 3*FUNK_SCAN_PARA ]; /* actually only 2*FUNK_SCAN_PARA, but with tail region for spilled writes */
};
typedef struct fd_funk_scan fd_funk_scan_t;

fd_funk_scan_t *
fd_funk_scan_init( fd_funk_scan_t * scan,
                   fd_funk_t *      funk );

fd_funk_scan_batch_t *
fd_funk_scan_poll( fd_funk_scan_t *       scan,
                   fd_funk_scan_batch_t * batch );

#endif /* HEADER_fd_src_discof_backup_fd_funk_scan_h */
