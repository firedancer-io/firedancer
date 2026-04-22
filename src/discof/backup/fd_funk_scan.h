#ifndef HEADER_fd_src_discof_backup_fd_funk_scan_h
#define HEADER_fd_src_discof_backup_fd_funk_scan_h

/* Instruction-level parallel funk index scanner.

   ### Why does this exist?

   map_chain_para has horrible pointer-chasing characteristics.
   Naively iterating through a giant map_chain_para map on a Zen 5
   DDR5-4800 box results in about 6.5 million element/second throughput.
   That is about 150 ns or 450 cycles per element.

   ### What do we do about it?

   Read-ahead & memory gather optimizations to amortize DRAM latency by
   keeping the CPU's load queue busy. */

#include "../../funk/fd_funk.h"
#include "../../flamenco/fd_flamenco_base.h"

typedef fd_funk_rec_map_shmem_private_chain_t fd_funk_rec_chain_t;

#define FUNK_SCAN_PARA 64

static fd_funk_rec_chain_t const rec_chain_sentinel = {
  .ver_cnt   = 0UL,
  .head_cidx = UINT_MAX
};

static fd_funk_rec_t const rec_sentinel = {
  .val_gaddr = ULONG_MAX
};

struct fd_funk_scan {
  /* Source */
  fd_funk_rec_chain_t const * chain_tbl;
  fd_funk_rec_t const *       rec_tbl;

  /* Cache */
  uint  rec_idx  [ FUNK_SCAN_PARA ];
  ulong val_gaddr[ FUNK_SCAN_PARA ];
  uint  data_sz  [ FUNK_SCAN_PARA ];
};
typedef struct fd_funk_scan fd_funk_scan_t;

fd_funk_scan_t *
fd_funk_scan_init( fd_funk_scan_t *  scan,
                   fd_funk_t const * funk );

void
fd_funk_scan_refill( fd_funk_scan_t * scan,
                     ulong            chain );

#endif /* HEADER_fd_src_discof_backup_fd_funk_scan_h */
