#include "fd_funk_scan.h"
#include <x86intrin.h>

fd_funk_scan_t *
fd_funk_scan_init( fd_funk_scan_t *  scan,
                   fd_funk_t const * funk,
                   ulong             chain0,
                   ulong             chain1 ) {
  ulong chain_cnt = funk->rec_map->map->chain_cnt;
  if( chain1 >= chain_cnt ) chain1 = chain_cnt;
  *scan = (fd_funk_scan_t) {
    .rec_tbl   = funk->rec_pool->ele,
    .chain_tbl = fd_funk_rec_map_shmem_private_chain( funk->rec_map->map, 0UL ),
    .val_base  = funk->wksp,
    .chain0    = chain0,
    .chain1    = chain1,
    .chain     = chain0
  };
  FD_TEST( chain0 <= chain1 );
  return scan;
}

void
fd_funk_scan_refill( fd_funk_scan_t * scan ) {
restart:
  if( FD_UNLIKELY( scan->chain >= scan->chain1 ) ) return;
  if( FD_UNLIKELY( scan->chain + FUNK_SCAN_PARA > scan->chain1 ) ) {
    /* FIXME tail end */
    scan->chain = scan->chain1;
    return;
  }

  fd_funk_rec_chain_t const * chain_tbl = scan->chain_tbl;
  fd_funk_rec_t const *       rec_tbl   = scan->rec_tbl;

  /* Scan map chain descriptors */
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ) {
    scan->heads[ i ] = chain_tbl[ scan->chain+i ];
  }

  /* Locate map heads */
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ) {
    uint rec_idx;
    ulong chain_cnt = fd_funk_rec_map_private_vcnt_cnt( scan->heads[ i ].ver_cnt );
    scan->rec_tot += chain_cnt;
    if( chain_cnt ) rec_idx = scan->heads[ i ].head_cidx;
    else            rec_idx = UINT_MAX;
    scan->rec_idx[ i ] = rec_idx;
  }
  scan->chain += FUNK_SCAN_PARA;

  /* Gather map recs */
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ) {
    _mm_prefetch( (char const *)&rec_tbl[ scan->rec_idx[ i ] ].pair.xid,  _MM_HINT_T1 );
    _mm_prefetch( (char const *)&rec_tbl[ scan->rec_idx[ i ] ].val_gaddr, _MM_HINT_T1 );
  }

  /* Locate rec vals */
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ) {
    uint rec_idx = scan->rec_idx[ i ];
    fd_funk_rec_t const * rec = rec_idx!=UINT_MAX ? &scan->rec_tbl[ rec_idx ] : &rec_sentinel;
    scan->val_gaddr[ i ] = rec->val_gaddr;
  }

  /* Filter */
  ulong rec_cnt = 0UL;
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ) {
    if( scan->val_gaddr[ i ]==ULONG_MAX ) continue;
    scan->rec_idx  [ rec_cnt ] = scan->rec_idx[ i ];
    scan->val_gaddr[ rec_cnt ] = scan->val_gaddr[ i ];
    rec_cnt++;
  }
  scan->batch_idx = 0UL;
  scan->batch_cnt = rec_cnt;
  if( !rec_cnt ) goto restart;
}
