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
  fd_funk_rec_chain_t heads[ FUNK_SCAN_PARA ];
  fd_funk_rec_t const * reca[ FUNK_SCAN_PARA ];

  if( FD_UNLIKELY( scan->chain >= scan->chain1 ) ) return;
  if( FD_UNLIKELY( scan->chain + FUNK_SCAN_PARA > scan->chain1 ) ) {
    /* FIXME tail end */
    scan->chain = scan->chain1;
    return;
  }

  fd_funk_rec_chain_t const * chain_tbl = scan->chain_tbl;
  fd_funk_rec_t const *       rec_tbl   = scan->rec_tbl;

  /* Scan map chain descriptors */
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i+=4 ) {
    __m512i chain_sse = _mm512_load_si512( (void const *)( &chain_tbl[ scan->chain+i ] ) );
    memcpy( &heads[ i ], &chain_sse, sizeof(__m512i) );
  }

  /* Locate map heads */
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ) {
    ulong chain_cnt = fd_funk_rec_map_private_vcnt_cnt( heads[ i ].ver_cnt );
    scan->rec_tot += chain_cnt;
    uint rec_idx = heads[ i ].head_cidx;
    reca[ i ] = chain_cnt ? &rec_tbl[ rec_idx ] : &rec_sentinel;
    scan->rec_idx[ i ] = rec_idx;
  }
  scan->chain += FUNK_SCAN_PARA;

  /* Gather map recs */
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ) {
    fd_funk_rec_t const * rec = reca[ i ];
    scan->val_gaddr[ i ] = rec->val_gaddr;
    scan->data_sz  [ i ] = (uint)( rec->val_sz - sizeof(fd_account_meta_t) );
  }

  scan->batch_idx = 0UL;
  scan->batch_cnt = FUNK_SCAN_PARA;
}
