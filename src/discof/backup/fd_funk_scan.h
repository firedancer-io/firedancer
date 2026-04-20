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

#define FUNK_SCAN_PARA 64 /* Zen 5 load queue depth */

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
  fd_wksp_t *                 val_base;
  ulong                       chain0;
  ulong                       chain1;
  ulong                       chain;
  ulong                       rec_tot;

  /* Cache */
  fd_funk_rec_chain_t       heads[ FUNK_SCAN_PARA ];
  fd_funk_rec_t const *     rec  [ FUNK_SCAN_PARA ];
  fd_account_meta_t const * val  [ FUNK_SCAN_PARA ];
  ulong rec_idx;
  ulong rec_cnt;
};
typedef struct fd_funk_scan fd_funk_scan_t;

fd_funk_scan_t *
fd_funk_scan_init( fd_funk_scan_t *  scan,
                   fd_funk_t const * funk,
                   ulong             chain0,
                   ulong             chain1 );

void
fd_funk_scan_refill( fd_funk_scan_t * scan );

static inline ulong
fd_funk_scan_next( fd_funk_scan_t * scan ) {
  if( FD_UNLIKELY( scan->rec_idx>=scan->rec_cnt ) ) {
    fd_funk_scan_refill( scan );
    if( FD_UNLIKELY( scan->rec_idx>=scan->rec_cnt ) ) return ULONG_MAX;
  }
  return scan->rec_idx++;
}

static inline ulong
fd_funk_scan_next_rooted( fd_funk_scan_t * scan ) {
  for(;;) {
    ulong rec_idx = fd_funk_scan_next( scan );
    if( FD_UNLIKELY( rec_idx==ULONG_MAX ) ) return ULONG_MAX;
    fd_funk_rec_t const * rec = scan->rec[ rec_idx ];
    fd_xid_t xid; fd_funk_txn_xid_ld_atomic( &xid, rec->pair.xid );
    if( FD_LIKELY( fd_funk_txn_xid_eq_root( &xid ) ) ) return rec_idx;
  }
}

#endif /* HEADER_fd_src_discof_backup_fd_funk_scan_h */
