#include "fd_snapmk.h"
#include <x86intrin.h>

fd_funk_scan_t *
fd_funk_scan_init( fd_funk_scan_t *  scan,
                   fd_funk_t const * funk ) {
  *scan = (fd_funk_scan_t) {
    .rec_tbl   = funk->rec_pool->ele,
    .chain_tbl = fd_funk_rec_map_shmem_private_chain( funk->rec_map->map, 0UL ),
  };
  return scan;
}

void
fd_funk_scan_refill( fd_funk_scan_t * scan,
                     ulong            chain ) {
  fd_funk_rec_chain_t heads[ FUNK_SCAN_PARA ];
  fd_funk_rec_t const * reca[ FUNK_SCAN_PARA ];
  fd_snapmk_batch_t * batch = scan->batch;

  fd_funk_rec_chain_t const * chain_tbl = scan->chain_tbl;
  fd_funk_rec_t const *       rec_tbl   = scan->rec_tbl;

  /* Scan map chain descriptors */
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i+=4 ) {
    __m512i chain_sse = *((__m512i volatile *)( &chain_tbl[ chain+i ] ));
    memcpy( &heads[ i ], &chain_sse, sizeof(__m512i) );
  }

  /* Locate map heads */
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ) {
    ulong chain_cnt = fd_funk_rec_map_private_vcnt_cnt( heads[ i ].ver_cnt );
    uint rec_idx = heads[ i ].head_cidx;
    reca[ i ] = !!chain_cnt ? &rec_tbl[ rec_idx ] : &rec_sentinel;
    batch->rec_idx[ i ] = rec_idx;
  }

  /* Gather map recs */
  //   for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ) {
  //   fd_funk_rec_t const * rec = reca[ i ];
  //   scan->val_gaddr[ i ] = rec->val_gaddr;
  //   scan->data_sz  [ i ] = (uint)( rec->val_sz - sizeof(fd_account_meta_t) );
  // }
  __m512i off_gaddr = _mm512_set1_epi64( (long)offsetof(fd_funk_rec_t, val_gaddr)      );
  __m512i off_valsz = _mm512_set1_epi64( (long)offsetof(fd_funk_rec_t, val_gaddr) - 8L );
  __m512i mask28    = _mm512_set1_epi64( (1L<<28)-1L );
  __m512i meta_sz   = _mm512_set1_epi64( (long)sizeof(fd_account_meta_t) );
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i+=8UL ) {
    __m512i ptrs   = _mm512_loadu_si512( &reca[ i ] );
    __m512i gaddr  = _mm512_i64gather_epi64( _mm512_add_epi64( ptrs, off_gaddr ), (void const *)0, 1 );
    _mm512_storeu_si512( &batch->val_gaddr[ i ], gaddr );
    __m512i bf     = _mm512_i64gather_epi64( _mm512_add_epi64( ptrs, off_valsz ), (void const *)0, 1 );
    __m512i valsz  = _mm512_and_epi64( bf, mask28 );
    __m512i dsz    = _mm512_sub_epi64( valsz, meta_sz );
    __m256i dsz32  = _mm512_cvtepi64_epi32( dsz );
    _mm256_storeu_si256( (__m256i *)&batch->data_sz[ i ], dsz32 );
  }
}
