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

/* fd_funk_scan_fast runs the fast path, advancing by FUNK_SCAN_PARA
   hash chains.

   Fused loop: for each group of 8 chain descriptors, compute the
   visibility mask and do masked gathers in a single pass.  This avoids
   an intermediate bitmask and the scalar epilogue GCC emits for it. */

static fd_funk_scan_batch_t *
fd_funk_scan_fast( fd_funk_scan_t *       scan,
                   fd_funk_scan_batch_t * batch ) {
  /* invariant: chain_idx+FUNK_SCAN_PARA <= chain_max */
  /* invariant: slow_cnt <= FUNK_SCAN_PARA */

  fd_funk_rec_chain_t const * chain_tbl = scan->chain_tbl;
  fd_funk_rec_t const *       rec_tbl   = scan->rec_tbl;

  ulong chain = scan->chain_idx;

  FD_STATIC_ASSERT( sizeof(fd_funk_rec_chain_t)==16UL, layout );

  __m512i sentinel  = _mm512_set1_epi64( (long)ULONG_MAX );
  __m512i rec_base  = _mm512_set1_epi64( (long)(ulong)rec_tbl );
  __m512i rec_sz    = _mm512_set1_epi64( (long)sizeof(fd_funk_rec_t) );
  __m512i off_gaddr = _mm512_set1_epi64( (long)offsetof(fd_funk_rec_t, val_gaddr)      );
  __m512i off_valsz = _mm512_set1_epi64( (long)offsetof(fd_funk_rec_t, val_gaddr) - 8L );
  __m512i mask28    = _mm512_set1_epi64( (1L<<28)-1L );
  __m512i meta_sz   = _mm512_set1_epi64( (long)sizeof(fd_account_meta_t) );

  /* visible = !locked && cnt==1  ⟺  (ver_cnt & ((1<<44)-1)) == 1
     (low 43 bits are cnt, bit 43 is the lock bit) */
  __m512i mask44    = _mm512_set1_epi64( (1L<<44)-1L );
  __m512i mask43    = _mm512_set1_epi64( (1L<<43)-1L );
  __m512i one       = _mm512_set1_epi64( 1L );
  __m512i zero      = _mm512_setzero_si512();
  __m512i lane_off  = _mm512_set_epi64( 7, 6, 5, 4, 3, 2, 1, 0 );

  /* Permute indices for deinterleaving 8 chain descriptors.
     Each descriptor is {ver_cnt:u64, head_cidx:u32, pad:u32} = 2 qwords.
     Two zmm registers hold 8 descriptors as 16 qwords.
     ver_cnt  sits at even qword positions (0,2,4,6 in each zmm).
     head_cidx sits at dword positions (2,6,10,14 in each zmm). */
  __m512i perm_vcnt = _mm512_set_epi64( 14, 12, 10, 8, 6, 4, 2, 0 );
  __m512i perm_cidx = _mm512_set_epi32( 0,0,0,0,0,0,0,0,
                                        30,26,22,18, 14,10,6,2 );

  ulong slow_cnt = scan->slow_cnt;

  for( ulong i=0UL; i<FUNK_SCAN_PARA; i+=8UL ) {
    /* Load 8 chain descriptors (2 zmm, 4 descriptors each).
       Volatile deref forces an aligned AVX-512 load, which is atomic
       for each fd_funk_rec_chain_t (16 bytes). */
    __m512i cd0 = *((__m512i volatile *)( &chain_tbl[ chain+i   ] ));
    __m512i cd1 = *((__m512i volatile *)( &chain_tbl[ chain+i+4 ] ));

    /* Extract ver_cnt for 8 chains and compute visibility mask */
    __m512i vcnt = _mm512_permutex2var_epi64( cd0, perm_vcnt, cd1 );
    __mmask8 vis  = _mm512_cmpeq_epi64_mask( _mm512_and_epi64( vcnt, mask44 ), one );

    /* Append locked or multi-element chains to slow array */
    __mmask8 not_empty = _mm512_cmpneq_epi64_mask( _mm512_and_epi64( vcnt, mask43 ), zero );
    __mmask8 slow_mask = not_empty & (__mmask8)~vis;
    if( FD_UNLIKELY( slow_mask ) ) {
      __m512i chain_ids = _mm512_add_epi64( _mm512_set1_epi64( (long)(chain+i) ), lane_off );
#     if defined(__znver4__)
      __m512i compressed = _mm512_maskz_compress_epi64( slow_mask, chain_ids );
      _mm512_storeu_si512( scan->slow_chain + slow_cnt, compressed );
#     else
      _mm512_mask_compressstoreu_epi64( scan->slow_chain + slow_cnt, slow_mask, chain_ids );
#     endif
      slow_cnt += (ulong)_mm_popcnt_u32( (uint)slow_mask );
    }

    /* Extract and store head_cidx for 8 chains */
    __m256i cidx = _mm512_castsi512_si256(
                     _mm512_permutex2var_epi32( cd0, perm_cidx, cd1 ) );
    _mm256_storeu_si256( (__m256i *)&batch->rec_idx[ i ], cidx );

    /* Compute record addresses: rec_tbl + head_cidx * sizeof(fd_funk_rec_t) */
    __m512i idx64 = _mm512_cvtepu32_epi64( cidx );
    __m512i addrs = _mm512_add_epi64( rec_base, _mm512_mullo_epi64( idx64, rec_sz ) );

    /* Masked gather val_gaddr (inactive lanes get sentinel) */
    __m512i gaddr = _mm512_mask_i64gather_epi64( sentinel, vis,
                      _mm512_add_epi64( addrs, off_gaddr ), NULL, 1 );
    _mm512_storeu_si512( &batch->val_gaddr[ i ], gaddr );

    /* Masked gather val_sz bitfield, extract data size */
    __m512i bf    = _mm512_mask_i64gather_epi64( sentinel, vis,
                      _mm512_add_epi64( addrs, off_valsz ), NULL, 1 );
    __m512i valsz = _mm512_and_epi64( bf, mask28 );
    __m512i dsz   = _mm512_sub_epi64( valsz, meta_sz );
    __m256i dsz32 = _mm512_cvtepi64_epi32( dsz );
    _mm256_storeu_si256( (__m256i *)&batch->data_sz[ i ], dsz32 );
  }

  scan->slow_cnt = slow_cnt;

  scan->chain_idx += FUNK_SCAN_PARA;

  return batch;
}

/* Walk a locked chain starting from iter, appending root records to
   batch starting at position *cnt.  Returns the iterator position
   (done or not) after filling up to FUNK_SCAN_PARA entries. */

static fd_funk_rec_map_iter_t
fd_funk_scan_walk_chain( fd_funk_scan_batch_t * batch,
                         fd_funk_rec_map_iter_t iter,
                         ulong *                cnt ) {
  while( *cnt<FUNK_SCAN_PARA && !fd_funk_rec_map_iter_done( iter ) ) {
    fd_funk_rec_t const * rec = fd_funk_rec_map_iter_ele_const( iter );
    if( fd_funk_txn_xid_eq_root( rec->pair.xid ) ) {
      ulong i = (*cnt)++;
      batch->val_gaddr[ i ] = rec->val_gaddr;
      batch->rec_idx  [ i ] = (uint)iter.ele_idx;
      batch->data_sz  [ i ] = (uint)( rec->val_sz - sizeof(fd_account_meta_t) );
    }
    iter = fd_funk_rec_map_iter_next( iter );
  }
  return iter;
}

/* fd_funk_scan_slow runs the slow path */

__attribute__((noinline)) static fd_funk_scan_batch_t *
fd_funk_scan_slow( fd_funk_scan_t *       scan,
                   fd_funk_scan_batch_t * batch ) {

  for( ulong i=0UL; i<FUNK_SCAN_PARA; i++ ) {
    batch->val_gaddr[ i ] = ULONG_MAX;
  }

  fd_funk_rec_map_t *   rec_map = scan->rec_map;
  fd_funk_rec_t const * rec_tbl = scan->rec_tbl;

  ulong cnt      = 0UL;
  ulong slow_idx = 0UL;
  ulong slow_cnt = scan->slow_cnt;

  /* Resume a partially consumed chain from last call (already locked) */
  if( FD_UNLIKELY( scan->slow_last_chain_idx!=ULONG_MAX ) ) {
    ulong chain_idx = scan->slow_last_chain_idx;

    fd_funk_rec_map_iter_t iter = { .ele=rec_tbl, .ele_idx=scan->slow_last_rec_idx };
    iter = fd_funk_scan_walk_chain( batch, iter, &cnt );

    if( FD_UNLIKELY( !fd_funk_rec_map_iter_done( iter ) ) ) {
      scan->slow_last_rec_idx = iter.ele_idx;
      goto compact;
    }

    scan->slow_last_chain_idx = ULONG_MAX;
    scan->slow_last_rec_idx   = ULONG_MAX;
    fd_funk_rec_map_iter_unlock( rec_map, &chain_idx, 1UL );
  }

  /* Process queued chains */
  while( slow_idx<slow_cnt && cnt<FUNK_SCAN_PARA ) {
    ulong chain_idx = scan->slow_chain[ slow_idx ];
    slow_idx++;

    int err = fd_funk_rec_map_iter_lock( rec_map, &chain_idx, 1UL, FD_MAP_FLAG_BLOCKING );
    if( FD_UNLIKELY( err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "iter_lock failed (%i-%s)", err, fd_map_strerror( err ) ));

    fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter( rec_map, chain_idx );
    iter = fd_funk_scan_walk_chain( batch, iter, &cnt );

    if( FD_UNLIKELY( !fd_funk_rec_map_iter_done( iter ) ) ) {
      scan->slow_last_chain_idx = chain_idx;
      scan->slow_last_rec_idx   = iter.ele_idx;
      goto compact;
    }

    fd_funk_rec_map_iter_unlock( rec_map, &chain_idx, 1UL );
  }

compact:;
  /* Shift unprocessed chains to front */
  ulong remaining = slow_cnt - slow_idx;
  for( ulong j=0UL; j<remaining; j++ ) {
    scan->slow_chain[ j ] = scan->slow_chain[ slow_idx + j ];
  }
  scan->slow_cnt = remaining;

  if( FD_UNLIKELY( !cnt && !scan->slow_cnt && scan->chain_idx>=scan->chain_max ) ) return NULL;

  return batch;
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
