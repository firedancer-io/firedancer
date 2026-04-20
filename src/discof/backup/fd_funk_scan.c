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
  fd_wksp_t const *           val_base  = scan->val_base;

  /* Scan map chain descriptors */
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ) {
    scan->heads[ i ] = chain_tbl[ scan->chain+i ];
  }

  /* Locate map heads */
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ) {
    fd_funk_rec_t const * rec;
    ulong chain_cnt = fd_funk_rec_map_private_vcnt_cnt( scan->heads[ i ].ver_cnt );
    scan->rec_tot += chain_cnt;
    if( chain_cnt ) rec = &rec_tbl[ scan->heads[ i ].head_cidx ];
    else            rec = &rec_sentinel;
    scan->rec[ i ] = rec;
  }
  scan->chain += FUNK_SCAN_PARA;

  /* Gather map recs */
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ) {
    _mm_prefetch( (char const *)&scan->rec[ i ]->pair.xid,  _MM_HINT_T1 );
    _mm_prefetch( (char const *)&scan->rec[ i ]->val_gaddr, _MM_HINT_T1 );
  }

  /* Locate rec vals */
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ) {
    fd_funk_rec_t const * rec       = scan->rec[ i ];
    ulong                 val_gaddr = rec->val_gaddr;
    if( val_gaddr==ULONG_MAX ) scan->val[ i ] = NULL;
    else                       scan->val[ i ] = fd_wksp_laddr( val_base, val_gaddr );
    _mm_prefetch( (char const *)scan->val[ i ], _MM_HINT_T1 );
  }

  /* Filter */
  ulong rec_cnt = 0UL;
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ) {
    fd_funk_rec_t const * rec = scan->rec[ i ];
    if( rec->val_gaddr==ULONG_MAX ) continue;
    scan->rec[ rec_cnt ] = rec;
    scan->val[ rec_cnt ] = fd_wksp_laddr( val_base, rec->val_gaddr );
    rec_cnt++;
  }
  scan->rec_idx = 0UL;
  scan->rec_cnt = rec_cnt;
  if( !rec_cnt ) goto restart;
}
