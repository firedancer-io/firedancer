#include "fd_funk_scan.h"
#include <x86intrin.h>

#if FD_USING_CLANG
#define FD_UNPREDICTABLE(x) __builtin_unpredictable( x )
#else
#define FD_UNPREDICTABLE(x) __builtin_expect_with_probability( !!(x), 0, 0.5 )
#endif

/* FIXME tail end */

fd_funk_scan_t *
fd_funk_scan_init( fd_funk_scan_t * scan,
                   fd_funk_t *      funk ) {

  *scan = (fd_funk_scan_t) {
    .rec_map   = funk->rec_map,
    .rec_tbl   = funk->rec_pool->ele,
    .chain_tbl = fd_funk_rec_map_shmem_private_chain( funk->rec_map->map, 0UL ),
    .chain_idx = 0UL,
    .chain_max = fd_funk_rec_map_chain_cnt( funk->rec_map ),

    .slow_cnt  = 0UL,
    .slow_last_chain_idx = ULONG_MAX,
    .slow_last_rec_idx   = ULONG_MAX
  };

  /* Handle tail end via slow path */
  ulong chain_tail1 = scan->chain_max;
  ulong chain_tail0 = fd_ulong_align_dn( chain_tail1, FUNK_SCAN_PARA );
  for( ulong i=chain_tail0; i<chain_tail1; i++ ) {
    scan->slow_chain[ scan->slow_cnt++ ] = i;
  }
  scan->chain_max = chain_tail0;

  return scan;
}

static fd_funk_rec_t const rec_sentinel = {
  .val_gaddr = ULONG_MAX
};

/* fd_funk_scan_fast runs the fast path, advancing by FUNK_SCAN_PARA
   hash chains.

   To allow for compiler vectorization and speculative execution, there
   are no dependencies between iterations of the same loop. */

static fd_funk_scan_batch_t *
fd_funk_scan_fast( fd_funk_scan_t *       scan,
                   fd_funk_scan_batch_t * batch ) {
  /* invariant: chain_idx+FUNK_SCAN_PARA <= chain_max */
  /* invariant: slow_cnt <= FUNK_SCAN_PARA */

  fd_funk_rec_chain_t    heads[ FUNK_SCAN_PARA ];
  fd_funk_rec_t const *  reca [ FUNK_SCAN_PARA ];

  fd_funk_rec_chain_t const * chain_tbl = scan->chain_tbl;
  fd_funk_rec_t const *       rec_tbl   = scan->rec_tbl;

  ulong   chain = scan->chain_idx;
  // ulong * slow  = scan->slow_chain + scan->slow_cnt;

  /* Load map chain descriptors */
  FD_STATIC_ASSERT( sizeof(fd_funk_rec_chain_t)==16UL, layout ); /* prevent silent breakage */
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i+=4 ) {
    /* Dereferencing __m512i volatile forces an aligned AVX512 load,
       which is atomic for each fd_funk_rec_chain_t (16 bytes). */
    __m512i chain_sse = *((__m512i volatile *)( &chain_tbl[ chain+i ] ));
    memcpy( &heads[ i ], &chain_sse, sizeof(__m512i) );
  }

  /* Locate map heads */
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ) {
    ulong ver_cnt   = heads[ i ].ver_cnt;
    _Bool locked    = fd_funk_rec_map_private_vcnt_ver( ver_cnt ) &  1;
    _Bool is_empty  = fd_funk_rec_map_private_vcnt_cnt( ver_cnt ) == 0;
    _Bool is_long   = fd_funk_rec_map_private_vcnt_cnt( ver_cnt ) >  1;
    _Bool fast_path = FD_UNPREDICTABLE( !locked   && !is_long  );
    _Bool visible   = FD_UNPREDICTABLE( fast_path && !is_empty );

    uint rec_idx = heads[ i ].head_cidx;
    reca[ i ] = visible ? &rec_tbl[ rec_idx ] : &rec_sentinel;
    batch->rec_idx[ i ] = rec_idx;

    // slow[ i ] = fast_path ? ULONG_MAX : i;
  }

  /* Gather map recs */
  __m512i off_gaddr = _mm512_set1_epi64( (long)offsetof(fd_funk_rec_t, val_gaddr)      );
  __m512i off_valsz = _mm512_set1_epi64( (long)offsetof(fd_funk_rec_t, val_gaddr) - 8L );
  __m512i mask28    = _mm512_set1_epi64( (1L<<28)-1L );
  __m512i meta_sz   = _mm512_set1_epi64( (long)sizeof(fd_account_meta_t) );
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i+=8UL ) {
    __m512i ptrs   = _mm512_loadu_si512( &reca[ i ] );
    __m512i gaddr  = _mm512_i64gather_epi64( _mm512_add_epi64( ptrs, off_gaddr ), NULL, 1 );
    _mm512_storeu_si512( &batch->val_gaddr[ i ], gaddr );
    __m512i bf     = _mm512_i64gather_epi64( _mm512_add_epi64( ptrs, off_valsz ), NULL, 1 );
    __m512i valsz  = _mm512_and_epi64( bf, mask28 );
    __m512i dsz    = _mm512_sub_epi64( valsz, meta_sz );
    __m256i dsz32  = _mm512_cvtepi64_epi32( dsz );
    _mm256_storeu_si256( (__m256i *)&batch->data_sz[ i ], dsz32 );
  }

  /* Compact slow array */
  // ulong j = 0UL;
  // for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ) {
  //   if( slow[ i ]!=ULONG_MAX ) slow[ j++ ] = slow[ i ];
  // }
  // scan->slow_cnt += j;

  scan->chain_idx += FUNK_SCAN_PARA;

  return batch;
}

// static void
// slow_walk_chain( fd_funk_scan_t * scan ) {
//   fd_funk_rec_map_iter_t iter = { .ele=scan->rec_tbl };
//   ulong saved_idx = scan->slow_last_rec_idx;
//   if( saved_idx==ULONG_MAX ) {
//     iter.ele_idx = scan->chain_tbl[ scan->slow_last_chain_idx ].head_cidx;
//   } else {
//     iter.ele_idx = saved_idx;
//   }

//   ulong i = scan->cnt;
//   while( i<FUNK_SCAN_PARA ) {
//     if( fd_funk_rec_map_iter_done( iter ) ) break;
//     fd_funk_rec_t const * rec = fd_funk_rec_map_iter_ele_const( iter );
//     if( fd_funk_txn_xid_eq_root( rec->pair.xid ) ) {
//       scan->batch->val_gaddr[ i ] = rec->val_gaddr;
//       scan->batch->rec_idx  [ i ] = (uint)iter.ele_idx;
//       scan->batch->data_sz  [ i ] = rec->val_sz - sizeof(fd_account_meta_t);
//       i++;
//     }
//     iter = fd_funk_rec_map_iter_next( iter );
//   }
//   scan->cnt = i;
//   scan->slow_last_rec_idx = iter.ele_idx;
// }

/* fd_funk_scan_slow runs the slow path.
   FIXME add memory-level parallelism */

static fd_funk_scan_batch_t *
fd_funk_scan_slow( fd_funk_scan_t *       scan,
                   fd_funk_scan_batch_t * batch ) {
  for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ) {
    batch->val_gaddr[ i ] = ULONG_MAX;
  }
  if( scan->slow_cnt==0UL ) return NULL;
  scan->slow_cnt = 0UL;
  return batch;

  // /* invariant: slow_cnt > 1 */

  // ulong cnt = scan->slow_cnt;
  // fd_funk_rec_map_iter_lock( scan->rec_map, scan->slow_chain, cnt, FD_MAP_FLAG_BLOCKING );

  // fd_funk_rec_map_iter_unlock( scan->rec_map, scan->slow_chain, cnt );
  // scan->slow_cnt = 0UL;

  // return scan->batch;
}

fd_funk_scan_batch_t *
fd_funk_scan_poll( fd_funk_scan_t *       scan,
                   fd_funk_scan_batch_t * batch ) {

  if( FD_UNLIKELY( scan->slow_cnt  >  FUNK_SCAN_PARA ||
                   scan->chain_idx >= scan->chain_max ) ) {
    return fd_funk_scan_slow( scan, batch );
  }

  return fd_funk_scan_fast( scan, batch );
}
