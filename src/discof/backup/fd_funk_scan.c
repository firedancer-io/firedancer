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
    .walk_cnt  = 0UL
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
  __m512i off_gaddr = _mm512_set1_epi64( (long)offsetof(fd_funk_rec_t, val_gaddr) );

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
  }

  scan->slow_cnt = slow_cnt;

  scan->chain_idx += FUNK_SCAN_PARA;

  return batch;
}

/* fd_funk_scan_slow runs the slow path.  Walks up to SLOW_WALK_MAX
   chains simultaneously so that cache-miss loads from independent
   chains overlap (memory-level parallelism). */

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

  ulong walk_cnt = scan->walk_cnt;
  ulong walk_ele_idx  [ SLOW_WALK_MAX ];
  ulong walk_chain_idx[ SLOW_WALK_MAX ];
  for( ulong w=0UL; w<walk_cnt; w++ ) {
    walk_ele_idx  [ w ] = scan->walk_ele_idx  [ w ];
    walk_chain_idx[ w ] = scan->walk_chain_idx[ w ];
  }

  /* Fill walk slots from the slow queue */
# define FILL_WALKS                                                                                             \
  while( walk_cnt<SLOW_WALK_MAX && slow_idx<slow_cnt ) {                                                        \
    ulong ci_ = scan->slow_chain[ slow_idx++ ];                                                                 \
    int err_ = fd_funk_rec_map_iter_lock( rec_map, &ci_, 1UL, FD_MAP_FLAG_BLOCKING );                           \
    if( FD_UNLIKELY( err_!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "iter_lock failed (%i-%s)", err_, fd_map_strerror( err_ ) )); \
    fd_funk_rec_map_iter_t it_ = fd_funk_rec_map_iter( rec_map, ci_ );                                          \
    if( FD_UNLIKELY( fd_funk_rec_map_iter_done( it_ ) ) ) {                                                     \
      fd_funk_rec_map_iter_unlock( rec_map, &ci_, 1UL );                                                        \
      continue;                                                                                                 \
    }                                                                                                           \
    walk_chain_idx[ walk_cnt ] = ci_;                                                                           \
    walk_ele_idx  [ walk_cnt ] = it_.ele_idx;                                                                   \
    walk_cnt++;                                                                                                 \
  }

  FILL_WALKS

  /* Prefetch first elements of all active walks */
  for( ulong w=0UL; w<walk_cnt; w++ )
    __builtin_prefetch( &rec_tbl[ walk_ele_idx[ w ] ], 0, 0 );

  /* Round-robin walk across active chains */
  while( FD_LIKELY( walk_cnt>0UL ) ) {
    ulong w = 0UL;
    while( w<walk_cnt ) {
      if( FD_UNLIKELY( cnt>=FUNK_SCAN_PARA ) ) goto suspend;

      fd_funk_rec_t const * rec = &rec_tbl[ walk_ele_idx[ w ] ];

      if( fd_funk_txn_xid_eq_root( rec->pair.xid ) ) {
        batch->val_gaddr[ cnt ] = rec->val_gaddr;
        batch->rec_idx  [ cnt ] = (uint)walk_ele_idx[ w ];
        cnt++;
      }

      ulong next = (ulong)rec->map_next;
      if( FD_UNPREDICTABLE( next==(ulong)(uint)(~0UL) ) ) {
        fd_funk_rec_map_iter_unlock( rec_map, &walk_chain_idx[ w ], 1UL );
        walk_cnt--;
        walk_ele_idx  [ w ] = walk_ele_idx  [ walk_cnt ];
        walk_chain_idx[ w ] = walk_chain_idx[ walk_cnt ];
        continue;
      }

      walk_ele_idx[ w ] = next;
      __builtin_prefetch( &rec_tbl[ next ], 0, 0 );
      w++;
    }

    FILL_WALKS

    for( ulong w2=0UL; w2<walk_cnt; w2++ )
      __builtin_prefetch( &rec_tbl[ walk_ele_idx[ w2 ] ], 0, 0 );
  }

# undef FILL_WALKS

  /* Shift unprocessed chains to front */
  ulong remaining = slow_cnt - slow_idx;
  for( ulong j=0UL; j<remaining; j++ ) {
    scan->slow_chain[ j ] = scan->slow_chain[ slow_idx + j ];
  }
  scan->slow_cnt  = remaining;
  scan->walk_cnt  = 0UL;

  if( FD_UNLIKELY( !cnt && !remaining && scan->chain_idx>=scan->chain_max ) ) return NULL;
  return batch;

suspend:
  /* Save all active walk states (chains remain locked) */
  scan->walk_cnt = walk_cnt;
  for( ulong w=0UL; w<walk_cnt; w++ ) {
    scan->walk_ele_idx  [ w ] = walk_ele_idx  [ w ];
    scan->walk_chain_idx[ w ] = walk_chain_idx[ w ];
  }

  ulong remaining2 = slow_cnt - slow_idx;
  for( ulong j=0UL; j<remaining2; j++ ) {
    scan->slow_chain[ j ] = scan->slow_chain[ slow_idx + j ];
  }
  scan->slow_cnt = remaining2;

  return batch;
}

fd_funk_scan_batch_t *
fd_funk_scan_poll( fd_funk_scan_t *       scan,
                   fd_funk_scan_batch_t * batch ) {

  if( FD_UNLIKELY( scan->slow_cnt  >  FUNK_SCAN_PARA ||
                   scan->walk_cnt  >  0UL             ||
                   scan->chain_idx >= scan->chain_max ) ) {
    return fd_funk_scan_slow( scan, batch );
  }

  return fd_funk_scan_fast( scan, batch );
}
