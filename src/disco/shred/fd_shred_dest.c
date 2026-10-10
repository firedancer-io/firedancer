#include "fd_shred_dest.h"
#include "../../util/fd_hash32.h"
#if FD_HAS_AVX512
#include "../../util/simd/fd_avx512.h"
#elif FD_HAS_AVX
#include "../../util/simd/fd_avx.h"
#endif

static const fd_pubkey_t null_pubkey = {{ 0 }};

/* pubkey_map_query returns the index of the first destination with
   pubkey key, or FD_SHRED_DEST_NO_DEST.  The map is open addressed
   with linear probing; slots hold destination indices, UINT_MAX if
   empty. */
static inline fd_shred_dest_idx_t
pubkey_map_query( fd_shred_dest_t const * sdest,
                  fd_pubkey_t const *     key ) {
  uint const * map  = sdest->pubkey_map;
  ulong        mask = sdest->pubkey_map_mask;
  ulong        slot = fd_hash32( key->uc, sdest->pubkey_map_seed ) & mask;
  for(;;) {
    uint idx = map[ slot ];
    if( FD_UNLIKELY( idx==UINT_MAX ) ) return FD_SHRED_DEST_NO_DEST;
    if( FD_LIKELY( !memcmp( sdest->all_destinations[ idx ].pubkey.uc, key->uc, 32UL ) ) ) return idx;
    slot = (slot+1UL) & mask;
  }
}

/* This 45 byte struct gets hashed to compute the seed for ChaCha to
   compute the shred destinations. */
struct __attribute__((packed)) shred_dest_input {
  ulong slot;
  uchar type; /*     Data = 0b1010_0101, Code = 0b0101_1010 */
  uint  idx;
  uchar leader_pubkey[32];
};
typedef struct shred_dest_input shred_dest_input_t;

/* Flat staked sampler (AVX-512 or AVX2, staked_cnt<=FLAT_MAX): group
   prefixes in registers over rows of 16 or 32 leaf prefixes, with 16
   subgroup prefixes in between for class 3.  Prefixes are < 2^63 so
   the signed AVX2 compares work. */
#define FLAT_MAX  (4096UL)
#define FLAT_CLS3 (3UL)

#if FD_HAS_AVX512
#define FLAT_VL                  (8UL)
#define flat_v_t                 wwv_t
#define flat_v_ld( p )           wwv_ld( (p) )
#define flat_v_st( p, v )        wwv_st( (p), (v) )
#define flat_v_bcast( x )        wwv_bcast( (x) )
#define flat_v_cnt_le( a, x )    ((ulong)fd_uint_popcnt( (uint)wwv_le( (a), (x) ) ))
#define flat_v_sub_gt( a, x, w ) wwv_sub_if( wwv_gt( (a), (x) ), (a), (w), (a) )
#elif FD_HAS_AVX
#define FLAT_VL                  (4UL)
#define flat_v_t                 wl_t
#define flat_v_ld( p )           wl_ld( (long const *)(p) )
#define flat_v_st( p, v )        wl_st( (long *)(p), (v) )
#define flat_v_bcast( x )        wl_bcast( (long)(x) )
#define flat_v_cnt_le( a, x )    (4UL-((ulong)fd_uint_popcnt( (uint)wc_pack( wl_gt( (a), (x) ) ) )>>1)) /* 2 pack bits per lane */
#define flat_v_sub_gt( a, x, w ) wl_sub( (a), wl_and( wl_gt( (a), (x) ), (w) ) )
#endif

static inline ulong
flat_cls( ulong staked_cnt ) {
# if FD_HAS_AVX
  if( FD_UNLIKELY( (staked_cnt==0UL) | (staked_cnt>FLAT_MAX) ) ) return 0UL;
  return 1UL + (ulong)(staked_cnt>512UL) + (ulong)(staked_cnt>1024UL);
# else
  (void)staked_cnt;
  return 0UL;
# endif
}

/* flat_gsz returns the number of leaves per row. */
static inline ulong flat_gsz( ulong cls ) { return fd_ulong_if( cls==2UL, 32UL, 16UL ); }

/* flat_row_cnt returns the number of ulongs in each of flat_rowb and
   flat_row. */
static inline ulong
flat_row_cnt( ulong staked_cnt ) {
  ulong cls = flat_cls( staked_cnt );
  return fd_ulong_if( !!cls, fd_ulong_align_up( staked_cnt, flat_gsz( cls ) ), 0UL );
}

static inline ulong
flat_footprint( ulong staked_cnt ) {
  ulong mid_cnt = fd_ulong_if( flat_cls( staked_cnt )==FLAT_CLS3, 256UL, 0UL );
  return sizeof(ulong)*2UL*( flat_row_cnt( staked_cnt ) + mid_cnt );
}

ulong
fd_shred_dest_footprint( ulong staked_cnt, ulong unstaked_cnt ) {
  ulong cnt = staked_cnt+unstaked_cnt;
  ulong map_cnt = fd_ulong_pow2_up( 2UL*fd_ulong_max( cnt, 1UL ) );
  return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND(
                FD_LAYOUT_INIT,
                fd_shred_dest_align(),             sizeof(fd_shred_dest_t)              ),
                64UL,                              sizeof(uint)*map_cnt                 ),
                alignof(fd_shred_dest_weighted_t), sizeof(fd_shred_dest_weighted_t)*cnt ),
                fd_wsample_align(),                fd_wsample_footprint( staked_cnt, 1 )),
                alignof(ulong),                    sizeof(ulong)*unstaked_cnt           ),
                64UL,                              flat_footprint( staked_cnt )         ),
      FD_SHRED_DEST_ALIGN );
}


void *
fd_shred_dest_new( void                           * mem,
                   fd_shred_dest_weighted_t const * info,
                   ulong                            cnt,
                   fd_epoch_leaders_t const       * lsched,
                   fd_pubkey_t const              * source,
                   ulong                            seed ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_shred_dest_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong map_cnt = fd_ulong_pow2_up( 2UL*fd_ulong_max( cnt, 1UL ) );
  FD_SCRATCH_ALLOC_INIT( footprint, mem );
  fd_shred_dest_t * sdest;
  /* */  sdest     = FD_SCRATCH_ALLOC_APPEND( footprint, fd_shred_dest_align(),             sizeof(fd_shred_dest_t)              );
  uint * map       = FD_SCRATCH_ALLOC_APPEND( footprint, 64UL,                              sizeof(uint)*map_cnt                 );
  void * _info     = FD_SCRATCH_ALLOC_APPEND( footprint, alignof(fd_shred_dest_weighted_t), sizeof(fd_shred_dest_weighted_t)*cnt );

  ulong cnts[2] = { 0UL, 0UL }; /* cnts[0] = staked, cnts[1] = unstaked */

  /* Null pubkeys are never found.  On duplicates, the first wins. */
  ulong mask = map_cnt-1UL;
  fd_memset( map, 0xFF, sizeof(uint)*map_cnt );

  fd_shred_dest_weighted_t * copy = (fd_shred_dest_weighted_t *)_info;
  for( ulong i=0UL; i<cnt; i++ ) {
    copy[i] = info[i];
    ulong stake = info[i].stake_lamports;
    /* Check to make we never have a staked node following an unstaked
       node, which would mean info is not sorted properly. */
    if( FD_UNLIKELY( (stake>0UL) & (cnts[1]>0UL) ) ) {
      FD_LOG_WARNING(( "info was not sorted properly. info[%lu] has non-zero stake %lu but follows an unstaked node", i, stake ));
      return NULL;
    }
    cnts[ stake==0UL ]++;

    fd_pubkey_t const * key = &info[ i ].pubkey;
    if( FD_UNLIKELY( !memcmp( key->uc, null_pubkey.uc, 32UL ) ) ) continue;
    ulong slot = fd_hash32( key->uc, seed ) & mask;
    for(;;) {
      uint idx = map[ slot ];
      if( FD_LIKELY  ( idx==UINT_MAX                                     ) ) { map[ slot ] = (uint)i; break; }
      if( FD_UNLIKELY( !memcmp( copy[ idx ].pubkey.uc, key->uc, 32UL ) ) ) break;
      slot = (slot+1UL) & mask;
    }
  }

  ulong staked_cnt   = cnts[0];
  ulong unstaked_cnt = cnts[1];

  void * _wsample  = FD_SCRATCH_ALLOC_APPEND( footprint, fd_wsample_align(), fd_wsample_footprint( staked_cnt, 1 ));
  void * _unstaked = FD_SCRATCH_ALLOC_APPEND( footprint, alignof(ulong),     sizeof(ulong)*unstaked_cnt           );
  ulong   flat_cnt  = flat_row_cnt( staked_cnt );
  ulong * _flat     = FD_SCRATCH_ALLOC_APPEND( footprint, 64UL,               flat_footprint( staked_cnt )         );


  fd_chacha_rng_t * rng = fd_chacha_rng_join( fd_chacha_rng_new( sdest->rng, FD_CHACHA_RNG_MODE_SHIFT ) );

  /* Pad lanes hold the row (mid row) total, pad groups LONG_MAX: never
     selected. */
  ulong   cls   = flat_cls( staked_cnt );
  ulong   lg    = (ulong)fd_ulong_find_msb( flat_gsz( cls ) );
  ulong   gmask = (1UL<<lg)-1UL;
  ulong   rmask = fd_ulong_if( cls==FLAT_CLS3, 15UL, 0UL ); /* rows per group - 1 */
  ulong   lgr   = fd_ulong_if( cls==FLAT_CLS3, 4UL,  0UL );
  ulong * frowb = _flat;
  ulong * fmidb = _flat + 2UL*flat_cnt;
  ulong   acc   = 0UL;
  ulong   grp   = 0UL;
  ulong   row   = 0UL;
  ulong   tot   = 0UL;
  int     ovf   = 0;
  for( ulong g=0UL; g<32UL; g++ ) sdest->flat_p0b[ g ] = (ulong)LONG_MAX;
  memset( sdest->flat_p0m,   0, sizeof(sdest->flat_p0m)   );
  memset( sdest->flat_dirty, 0, sizeof(sdest->flat_dirty) );
  if( cls ) {
    for( ulong i=0UL; i<flat_cnt; i++ ) {
      ulong wt = 0UL;
      if( FD_LIKELY( i<staked_cnt ) ) { wt = info[i].stake_lamports; ovf |= __builtin_uaddl_overflow( tot, wt, &tot ); }
      row       += wt;
      frowb[ i ] = row;
      if( (i&gmask)==gmask ) {
        ulong j = i>>lg;
        grp += row;
        row  = 0UL;
        if( cls==FLAT_CLS3 ) fmidb[ j ] = grp;
        if( (j&rmask)==rmask ) { acc += grp; sdest->flat_p0b[ j>>lgr ] = acc; grp = 0UL; }
      }
    }
    ulong j = flat_cnt>>lg;
    if( j&rmask ) {
      for( ulong t=j; t&rmask; t++ ) fmidb[ t ] = grp;
      acc += grp;
      sdest->flat_p0b[ j>>lgr ] = acc;
    }
    fd_memcpy( _flat+flat_cnt, frowb, sizeof(ulong)*flat_cnt );
    if( cls==FLAT_CLS3 ) fd_memcpy( fmidb+256UL, fmidb, sizeof(ulong)*256UL );
    if( FD_UNLIKELY( ovf | (tot>=(1UL<<63)) ) ) cls = 0UL; /* fd_wsample fallback */
    else fd_memcpy( sdest->flat_p0m+8UL, sdest->flat_p0b, sizeof(sdest->flat_p0b) );
  }
  /* If flat, the empty fd_wsample only holds the shared rng */
  void * _staked = fd_wsample_new_init( _wsample, rng, fd_ulong_if( !!cls, 0UL, staked_cnt ), 1, FD_WSAMPLE_HINT_POWERLAW_REMOVE );
  if( !cls ) for( ulong i=0UL; i<staked_cnt; i++ ) _staked = fd_wsample_new_add( _staked, info[i].stake_lamports );
  _staked = fd_wsample_new_fini( _staked, 0UL );

  memset( sdest->null_dest, 0, sizeof(fd_shred_dest_weighted_t) );
  sdest->lsched                     = lsched;
  sdest->cnt                        = cnt;
  sdest->all_destinations           = copy;
  sdest->staked                     = fd_wsample_join( _staked );
  sdest->unstaked                   = _unstaked;
  sdest->unstaked_unremoved_cnt     = 0UL; /* unstaked doesn't get initialized until it's needed */
  sdest->staked_cnt                 = staked_cnt;
  sdest->unstaked_cnt               = unstaked_cnt;
  sdest->pubkey_map                 = map;
  sdest->pubkey_map_mask            = mask;
  sdest->pubkey_map_seed            = seed;

  fd_shred_dest_idx_t source_idx = pubkey_map_query( sdest, source );
  if( FD_UNLIKELY( source_idx==FD_SHRED_DEST_NO_DEST ) ) {
    FD_LOG_WARNING(( "source pubkey not found" ));
    return NULL;
  }
  sdest->source_validator_orig_idx  = source_idx;

  sdest->flat_cls       = cls;
  sdest->flat_total     = acc;
  sdest->flat_W         = acc;
  sdest->flat_dirty_mid = 0UL;
  sdest->flat_rowb      = _flat;
  sdest->flat_row       = _flat + flat_cnt;
  sdest->flat_midb      = fmidb;
  sdest->flat_mid       = fmidb + 256UL;

  return (void *)sdest;
}

fd_shred_dest_t * fd_shred_dest_join( void * mem  ) { return (fd_shred_dest_t *)mem; }
void * fd_shred_dest_leave( fd_shred_dest_t * sdest ) { return (void *)sdest;          }

void * fd_shred_dest_delete( void * mem ) {
  fd_shred_dest_t * sdest = (fd_shred_dest_t *)mem;

  fd_chacha_rng_delete( fd_chacha_rng_leave( sdest->rng               ) );
  fd_wsample_delete   ( fd_wsample_leave   ( sdest->staked            ) );
  return mem;
}

/* sample_unstaked, sample_unstaked_noprepare, and
   prepare_unstaked_sampling are used to perform the specific form of
   unweighted random sampling that Solana uses for unstaked validators.
   In essence, you:
    1. construct a list of all the unstaked validators,
    2. delete the leader (if present)
    then repeatedly:
    3. choose the chacha_rng_roll( |unstaked| )th element.
    4. swap the last element in unstaked with the chosen element
    5. return and remove the chosen element (which is now in the last
    position, so remove is O(1)).
   Steps 1 and 2 are both O(|unstaked|), but they can be combined
   relatively easily if we wait to construct the list until we know
   which element we need to delete.  prepare_unstaked_sampling performs
   steps 1 and 2. sample_unstaked performs steps 3-5.  Thus, you must
   call prepare_unstaked_sampling prior to calling sample_unstaked.

   When only sampling a single element from the list, forming the whole
   array is wasteful; we just need to know whether the element we choose
   comes before or after the element we deleted.
   sample_unstaked_noprepare returns the same result as
   prepare_unstaked_sampling followed by one call to sample_unstaked.
   sample_unstaked_noprepare does not read or modify the unstaked array,
   so it can be called without calling prepare_unstaked_sampling.

   remove_idx is the index of the element to remove in step 2.  If it is
   not in [sdest->staked_cnt, sdest->staked_cnt+sdest->unstaked_cnt),
   then it will be ignored.  sample_unstaked and
   sample_unstaked_noprepare return the index into
   sdest->all_destinations of the selected sample.  The returned value
   will be in [sdest->staked_cnt, sdest->staked_cnt+sdest->unstaked_cnt)
   or FD_WSAMPLE_EMPTY. */
static inline ulong
sample_unstaked_noprepare( fd_shred_dest_t  * sdest,
                           ulong              remove_idx ) {
  /* is remove_idx in
     [sdest->staked_cnt, sdest->staked_cnt+sdest->unstaked_cnt) ? */
  int remove_in_interval = (sdest->staked_cnt <= remove_idx) & (remove_idx < (sdest->staked_cnt+sdest->unstaked_cnt) );
  ulong unstaked_cnt = sdest->unstaked_cnt - (ulong)remove_in_interval;
  if( FD_UNLIKELY( unstaked_cnt==0UL ) ) return FD_WSAMPLE_EMPTY;

  ulong sample = sdest->staked_cnt + fd_chacha_rng_ulong_roll( sdest->rng, unstaked_cnt );
  return fd_ulong_if( (!remove_in_interval) | (sample<remove_idx), sample, sample+1UL );
}

/* It's cheaper to initialize unstaked without the element we want to
   delete than to delete it after initializing, so we defer the
   initialization until we know who the leader is. */
static inline void
prepare_unstaked_sampling( fd_shred_dest_t  * sdest,
                           ulong              remove_idx ) {
  int remove_in_interval = (sdest->staked_cnt <= remove_idx) & (remove_idx < (sdest->staked_cnt+sdest->unstaked_cnt) );
  ulong unstaked_cnt = sdest->unstaked_cnt - (ulong)remove_in_interval;
  sdest->unstaked_unremoved_cnt = unstaked_cnt;
  if( FD_UNLIKELY( unstaked_cnt==0UL ) ) return;

  /* If we had to remove something in the interval, we want to make sure
     it doesn't occur in the list of indices.  Otherwise just take them
     all. */
  ulong direct_index_up_to = fd_ulong_if( remove_in_interval, remove_idx - sdest->staked_cnt, unstaked_cnt );
  ulong i=0UL;
  for( ; i<direct_index_up_to; i++ ) sdest->unstaked[i] = i+sdest->staked_cnt;
  for( ; i<unstaked_cnt;       i++ ) sdest->unstaked[i] = i+sdest->staked_cnt + 1UL;
}

static inline ulong
sample_unstaked( fd_shred_dest_t * sdest ) {
  if( FD_UNLIKELY( sdest->unstaked_unremoved_cnt==0UL ) ) return FD_WSAMPLE_EMPTY;

  ulong sample = fd_chacha_rng_ulong_roll( sdest->rng, sdest->unstaked_unremoved_cnt );
  ulong to_return = sdest->unstaked[sample];
  sdest->unstaked[sample] = sdest->unstaked[--sdest->unstaked_unremoved_cnt];
  return to_return;
}


#if FD_HAS_AVX

/* flat_roll is fd_chacha_rng_ulong_roll( rng, W ) (MODE_SHIFT) with
   the buffer cursor in registers.  The first two words are tried
   branchlessly, the first accepted one wins. */
static inline __attribute__((always_inline)) ulong
flat_roll( fd_chacha_rng_t * rng,
           ulong             W,
           ulong           * _off,
           ulong           * _fill ) {
  ulong off  = *_off;
  ulong fill = *_fill;
  ulong zone = (W << (63 - fd_ulong_find_msb( W ))) - 1UL;
  ulong r;
  int   done = 0;
  if( FD_LIKELY( fill-off>=16UL ) ) {
    ulong v0 = FD_LOAD( ulong, rng->buf + ( off     % FD_CHACHA_RNG_BUFSZ) );
    ulong v1 = FD_LOAD( ulong, rng->buf + ((off+8UL) % FD_CHACHA_RNG_BUFSZ) );
    ulong h0, l0, h1, l1;
    fd_uwide_mul( &h0, &l0, v0, W );
    fd_uwide_mul( &h1, &l1, v1, W );
    /* r = l0<=zone ? h0 : h1, step = l0<=zone ? 8 : 16 (asm: a C select spills) */
    ulong step = 8UL;
    r = h0;
    __asm__( "cmpq %3, %2; cmova %4, %0; cmova %5, %1" : "+&r"(r), "+&r"(step) : "r"(l0), "r"(zone), "r"(h1), "r"(16UL) : "cc" );
    off += step;
    done = (l0<=zone) | (l1<=zone);
  }
  if( FD_UNLIKELY( !done ) ) {
    for(;;) {
      if( FD_UNLIKELY( off==fill ) ) { rng->buf_off = off; fd_chacha8_rng_private_refill( rng ); fill = rng->buf_fill; }
      ulong v = FD_LOAD( ulong, rng->buf + (off % FD_CHACHA_RNG_BUFSZ) );
      off += 8UL;
      ulong lo;
      fd_uwide_mul( &r, &lo, v, W );
      if( FD_LIKELY( lo<=zone ) ) break;
    }
  }
  *_off  = off;
  *_fill = fill;
  return r;
}

/* flat_remove_idx removes staked leaf idx. */
static inline __attribute__((always_inline)) void
flat_remove_idx( fd_shred_dest_t * sdest,
                 ulong             idx ) {
  ulong gsz = flat_gsz( sdest->flat_cls );
  ulong j   = idx / gsz; /* row */
  ulong g   = j;         /* group */
  ulong k0  = idx % gsz;
  ulong wt  = sdest->flat_row[ idx ] - fd_ulong_if( !!k0, sdest->flat_row[ idx-1UL ], 0UL );
  for( ulong k=k0; k<gsz; k++ ) sdest->flat_row[ j*gsz+k ] -= wt;
  if( sdest->flat_cls==FLAT_CLS3 ) {
    g = j/16UL;
    for( ulong s=j%16UL; s<16UL; s++ ) sdest->flat_mid[ g*16UL+s ] -= wt;
    sdest->flat_dirty_mid |= 1UL<<g;
  }
  for( ulong t=g; t<32UL; t++ ) sdest->flat_p0m[ 8UL+t ] -= wt;
  sdest->flat_dirty[ j/64UL ] |= 1UL<<(j%64UL);
  sdest->flat_W               -= wt;
}

/* flat_sample2 is fd_wsample_sample_and_remove_many for the two level
   classes, rows of gsz leaves. */
static inline __attribute__((always_inline)) void
flat_sample2( fd_shred_dest_t * sdest,
              ulong           * out,
              ulong             cnt,
              ulong const       gsz ) {
  fd_chacha_rng_t * rng = sdest->rng;
  ulong *           p0m = sdest->flat_p0m+8UL;
  ulong *           row = sdest->flat_row;

  flat_v_t p0[ 32UL/FLAT_VL ];
# pragma GCC unroll 32
  for( ulong j=0UL; j<32UL/FLAT_VL; j++ ) p0[ j ] = flat_v_ld( p0m+FLAT_VL*j );

  ulong W     = sdest->flat_W;
  ulong dirty = sdest->flat_dirty[ 0 ];
  ulong off   = rng->buf_off;
  ulong fill  = rng->buf_fill;

  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( !W ) ) { out[ i ] = FD_WSAMPLE_EMPTY; continue; }

    ulong    r  = flat_roll( rng, W, &off, &fill );
    flat_v_t vr = flat_v_bcast( r );
    ulong    g  = 0UL;
#   pragma GCC unroll 32
    for( ulong j=0UL; j<32UL/FLAT_VL; j++ ) g += flat_v_cnt_le( p0[ j ], vr );

    flat_v_t vrr = flat_v_bcast( r - p0m[ (long)g-1L ] );
    ulong *  q   = row + g*gsz;
    flat_v_t rr[ 32UL/FLAT_VL ];
    ulong    k   = 0UL;
#   pragma GCC unroll 32
    for( ulong j=0UL; j<gsz/FLAT_VL; j++ ) { rr[ j ] = flat_v_ld( q+FLAT_VL*j ); k += flat_v_cnt_le( rr[ j ], vrr ); }

    ulong    idx = g*gsz + k;
    ulong    wt  = q[ k ] - (q[ (k-1UL)&(gsz-1UL) ] & (-(ulong)(k!=0UL)));
    flat_v_t vw  = flat_v_bcast( wt );
#   pragma GCC unroll 32
    for( ulong j=0UL; j<32UL/FLAT_VL; j++ ) { p0[ j ] = flat_v_sub_gt( p0[ j ], vr, vw ); flat_v_st( p0m+FLAT_VL*j, p0[ j ] ); }
#   pragma GCC unroll 32
    for( ulong j=0UL; j<gsz/FLAT_VL; j++ ) flat_v_st( q+FLAT_VL*j, flat_v_sub_gt( rr[ j ], vrr, vw ) );

    dirty   |= 1UL<<g;
    W       -= wt;
    out[ i ] = idx;
  }

  rng->buf_off           = off;
  sdest->flat_W          = W;
  sdest->flat_dirty[ 0 ] = dirty;
}

/* flat_sample3 is flat_sample2 for the three level class. */
static void
flat_sample3( fd_shred_dest_t * sdest,
              ulong           * out,
              ulong             cnt ) {
  fd_chacha_rng_t * rng = sdest->rng;
  ulong *           p0m = sdest->flat_p0m+8UL;
  ulong *           mid = sdest->flat_mid;
  ulong *           row = sdest->flat_row;

  flat_v_t p0[ 16UL/FLAT_VL ];
# pragma GCC unroll 16
  for( ulong j=0UL; j<16UL/FLAT_VL; j++ ) p0[ j ] = flat_v_ld( p0m+FLAT_VL*j );

  ulong W    = sdest->flat_W;
  ulong dmid = sdest->flat_dirty_mid;
  ulong off  = rng->buf_off;
  ulong fill = rng->buf_fill;

  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( !W ) ) { out[ i ] = FD_WSAMPLE_EMPTY; continue; }

    ulong    r  = flat_roll( rng, W, &off, &fill );
    flat_v_t vr = flat_v_bcast( r );
    ulong    g  = 0UL;
#   pragma GCC unroll 16
    for( ulong k=0UL; k<16UL/FLAT_VL; k++ ) g += flat_v_cnt_le( p0[ k ], vr );

    ulong    r1 = r - p0m[ (long)g-1L ];
    flat_v_t v1 = flat_v_bcast( r1 );
    ulong *  m  = mid + g*16UL;
    flat_v_t mm[ 16UL/FLAT_VL ];
    ulong    s  = 0UL;
#   pragma GCC unroll 16
    for( ulong k=0UL; k<16UL/FLAT_VL; k++ ) { mm[ k ] = flat_v_ld( m+FLAT_VL*k ); s += flat_v_cnt_le( mm[ k ], v1 ); }

    ulong    j  = g*16UL + s;
    flat_v_t v2 = flat_v_bcast( r1 - (m[ (s-1UL)&15UL ] & (-(ulong)(s!=0UL))) );
    ulong *  q  = row + j*16UL;
    flat_v_t qq[ 16UL/FLAT_VL ];
    ulong    t  = 0UL;
#   pragma GCC unroll 16
    for( ulong k=0UL; k<16UL/FLAT_VL; k++ ) { qq[ k ] = flat_v_ld( q+FLAT_VL*k ); t += flat_v_cnt_le( qq[ k ], v2 ); }

    ulong    wt = q[ t ] - (q[ (t-1UL)&15UL ] & (-(ulong)(t!=0UL)));
    flat_v_t vw = flat_v_bcast( wt );
#   pragma GCC unroll 16
    for( ulong k=0UL; k<16UL/FLAT_VL; k++ ) {
      p0[ k ] = flat_v_sub_gt( p0[ k ], vr, vw ); flat_v_st( p0m+FLAT_VL*k, p0[ k ] );
      flat_v_st( m+FLAT_VL*k, flat_v_sub_gt( mm[ k ], v1, vw ) );
      flat_v_st( q+FLAT_VL*k, flat_v_sub_gt( qq[ k ], v2, vw ) );
    }

    dmid                      |= 1UL<<g;
    sdest->flat_dirty[ j>>6 ] |= 1UL<<(j&63UL);
    W                         -= wt;
    out[ i ] = j*16UL + t;
  }

  rng->buf_off          = off;
  sdest->flat_W         = W;
  sdest->flat_dirty_mid = dmid;
}

static void
flat_sample_and_remove_many( fd_shred_dest_t * sdest,
                             ulong           * out,
                             ulong             cnt ) {
  switch( sdest->flat_cls ) {
  case 1UL: flat_sample2( sdest, out, cnt, 16UL ); break;
  case 2UL: flat_sample2( sdest, out, cnt, 32UL ); break;
  default:  flat_sample3( sdest, out, cnt      ); break;
  }
}

/* flat_sample1 is fd_wsample_sample (no removal). */
static ulong
flat_sample1( fd_shred_dest_t * sdest ) {
  fd_chacha_rng_t * rng = sdest->rng;
  ulong const *     p0m = sdest->flat_p0m+8UL;
  ulong             W   = sdest->flat_W;
  if( FD_UNLIKELY( !W ) ) return FD_WSAMPLE_EMPTY;

  ulong off  = rng->buf_off;
  ulong fill = rng->buf_fill;
  ulong r    = flat_roll( rng, W, &off, &fill );
  rng->buf_off = off;

  flat_v_t vr = flat_v_bcast( r );
  ulong    g  = 0UL;
  for( ulong j=0UL; j<32UL/FLAT_VL; j++ ) g += flat_v_cnt_le( flat_v_ld( p0m+FLAT_VL*j ), vr );
  ulong r1 = r - p0m[ (long)g-1L ];

  ulong j = g;
  if( sdest->flat_cls==FLAT_CLS3 ) {
    ulong const * m  = sdest->flat_mid + g*16UL;
    flat_v_t      v1 = flat_v_bcast( r1 );
    ulong         s  = 0UL;
    for( ulong k=0UL; k<16UL/FLAT_VL; k++ ) s += flat_v_cnt_le( flat_v_ld( m+FLAT_VL*k ), v1 );
    j   = g*16UL + s;
    r1 -= m[ (s-1UL)&15UL ] & (-(ulong)(s!=0UL));
  }
  ulong         gsz = flat_gsz( sdest->flat_cls );
  ulong const * q   = sdest->flat_row + j*gsz;
  flat_v_t      v2  = flat_v_bcast( r1 );
  ulong         t   = 0UL;
  for( ulong k=0UL; k<gsz/FLAT_VL; k++ ) t += flat_v_cnt_le( flat_v_ld( q+FLAT_VL*k ), v2 );
  return j*gsz + t;
}

/* flat_restore_all undoes all removals by copying back dirty rows. */
static inline void
flat_restore_all( fd_shred_dest_t * sdest ) {
  ulong gsz = flat_gsz( sdest->flat_cls );
  for( ulong h=0UL; h<4UL; h++ ) {
    for( ulong d=sdest->flat_dirty[ h ]; d; d=fd_ulong_pop_lsb( d ) ) {
      ulong j = h*64UL + (ulong)fd_ulong_find_lsb( d );
      fd_memcpy( sdest->flat_row+j*gsz, sdest->flat_rowb+j*gsz, gsz*sizeof(ulong) );
    }
    sdest->flat_dirty[ h ] = 0UL;
  }
  for( ulong d=sdest->flat_dirty_mid; d; d=fd_ulong_pop_lsb( d ) ) {
    ulong g = (ulong)fd_ulong_find_lsb( d );
    fd_memcpy( sdest->flat_mid+g*16UL, sdest->flat_midb+g*16UL, 16UL*sizeof(ulong) );
  }
  sdest->flat_dirty_mid = 0UL;
  sdest->flat_W         = sdest->flat_total;
  fd_memcpy( sdest->flat_p0m+8UL, sdest->flat_p0b, sizeof(sdest->flat_p0b) );
}

#else /* the flat sampler is never enabled */

static inline void flat_remove_idx            ( fd_shred_dest_t * sdest, ulong idx                ) { (void)sdest; (void)idx;            }
static inline void flat_sample_and_remove_many( fd_shred_dest_t * sdest, ulong * out, ulong cnt ) { (void)sdest; (void)out; (void)cnt; }
static inline void flat_restore_all           ( fd_shred_dest_t * sdest                           ) { (void)sdest;                       }
static inline ulong flat_sample1              ( fd_shred_dest_t * sdest                           ) { (void)sdest; return FD_WSAMPLE_EMPTY; }

#endif

/* Returns 0 on success
   https://github.com/anza-xyz/agave/blob/v2.2.1/ledger/src/shred.rs#L293 */
static inline int
compute_seeds( fd_shred_dest_t           * sdest,
               fd_shred_t  const * const * input_shreds,
               ulong                       shred_cnt,
               fd_pubkey_t       const   * leader,
               ulong                       slot,
               uchar                       dest_hash_output[ FD_SHRED_DEST_MAX_SHRED_CNT ][ 32 ] ) {

  shred_dest_input_t dest_hash_inputs [ FD_SHRED_DEST_MAX_SHRED_CNT ];
  fd_sha256_batch_t * sha256 = fd_sha256_batch_init( sdest->_sha256_batch );

  for( ulong i=0UL; i<shred_cnt; i++ ) {
    shred_dest_input_t * h_in  = dest_hash_inputs+i;
    fd_shred_t const   * shred = input_shreds[i];
    if( FD_UNLIKELY( shred->slot != slot ) ) return -1;

    uchar shred_type = fd_shred_type( shred->variant );
    h_in->slot = slot;
    h_in->type = fd_uchar_if( fd_shred_is_data( shred_type ), 0xA5, 0x5A );
    h_in->idx  = shred->idx;
    memcpy( h_in->leader_pubkey, leader, 32UL );

    fd_sha256_batch_add( sha256, dest_hash_inputs+i,   sizeof(shred_dest_input_t), dest_hash_output[ i ] );
  }
  fd_sha256_batch_fini( sha256 );
  return 0;
}


fd_shred_dest_idx_t *
fd_shred_dest_compute_first( fd_shred_dest_t          * sdest,
                             fd_shred_t const * const * input_shreds,
                             ulong                      shred_cnt,
                             fd_shred_dest_idx_t      * out ) {

  if( FD_UNLIKELY( shred_cnt==0UL ) ) return out;

  if( FD_UNLIKELY( sdest->cnt<=1UL ) ) {
    /* We are the only validator that we know about, and we can't send
       it to ourself, so there's nobody we can send the shred to. */
    for( ulong i=0UL; i<shred_cnt; i++ ) out[ i ] = FD_SHRED_DEST_NO_DEST;
    return out;
  }

  uchar dest_hash_outputs[ FD_SHRED_DEST_MAX_SHRED_CNT ][ 32 ];

  ulong slot = input_shreds[0]->slot;
  fd_pubkey_t const * leader = fd_epoch_leaders_get( sdest->lsched, slot );
  if( FD_UNLIKELY( !leader ) ) return NULL;

  if( FD_UNLIKELY( compute_seeds( sdest, input_shreds, shred_cnt, leader, slot, dest_hash_outputs ) ) ) return NULL;

  /* If we're calling this, we must be the leader.  That means we had
     some stake when the leader schedule was created, but maybe not
     anymore?  This version of the code is safe either way, but I should
     probably confirm this can happen. */
  int source_validator_is_staked = sdest->source_validator_orig_idx<sdest->staked_cnt;
  int flat                       = !!sdest->flat_cls;
  if( FD_LIKELY( source_validator_is_staked ) ) {
    if( flat ) flat_remove_idx( sdest, sdest->source_validator_orig_idx );
    else       fd_wsample_remove_idx( sdest->staked, sdest->source_validator_orig_idx );
  }

  int any_staked_candidates = sdest->staked_cnt > (ulong)source_validator_is_staked;
  for( ulong i=0UL; i<shred_cnt; i++ ) {
    fd_wsample_seed_rng( sdest->staked, dest_hash_outputs[ i ] );
    /* Map FD_WSAMPLE_EMPTY (UINT_MAX) to FD_SHRED_DEST_NO_DEST.
       Otherwise, since wsample guarantees the returned index is in
       [0, INT_MAX], it will remain non-negative when cast to an int. */
    FD_STATIC_ASSERT( (int)FD_WSAMPLE_EMPTY                     <=-1, wsample_val );
    FD_STATIC_ASSERT( FD_SHRED_DEST_NO_DEST==(fd_shred_dest_idx_t)-1, wsample_val );
    if( FD_LIKELY( any_staked_candidates ) ) {
      ulong sample = flat ? flat_sample1( sdest ) : fd_wsample_sample( sdest->staked );
      out[i] = (fd_shred_dest_idx_t)fd_int_max( (int)sample, -1 );
    } else {
      out[i] = (fd_shred_dest_idx_t)sample_unstaked_noprepare( sdest, sdest->source_validator_orig_idx );
    }
  }
  if( flat ) flat_restore_all( sdest );
  else       fd_wsample_restore_all( sdest->staked );

  return out;
}

fd_shred_dest_idx_t *
fd_shred_dest_compute_children( fd_shred_dest_t          * sdest,
                                fd_shred_t const * const * input_shreds,
                                ulong                      shred_cnt,
                                fd_shred_dest_idx_t      * out,
                                ulong                      out_stride,
                                ulong                      fanout,
                                ulong                      dest_cnt,
                                ulong                    * opt_max_dest_cnt ) {

  /* The logic here is a little tricky since we are keeping track of
     staked and unstaked separately and only logically concatenating
     them [staked, unstaked] , but that does allow us to skip some
     samples sometimes.  We're operating from the source validator's
     perspective here, so everything in the first person singular refers
     to the source validator. */

  ulong my_orig_idx = sdest->source_validator_orig_idx;
  int   i_am_staked = my_orig_idx<sdest->staked_cnt;

  fd_ulong_store_if( !!opt_max_dest_cnt, opt_max_dest_cnt, 0UL );

  if( FD_UNLIKELY( (shred_cnt==0UL) | (dest_cnt==0UL) ) ) return out; /* Nothing to do */

  ulong               slot   = input_shreds[0]->slot;
  fd_pubkey_t const * leader = fd_epoch_leaders_get   ( sdest->lsched, slot );
  if( FD_UNLIKELY( !leader                 ) ) return NULL; /* Unknown slot */

  fd_shred_dest_idx_t query  = pubkey_map_query( sdest, leader );
  int                 leader_is_staked = query<sdest->staked_cnt; /* NO_DEST is never <staked_cnt */
  ulong               leader_idx       = fd_ulong_if( query!=FD_SHRED_DEST_NO_DEST, (ulong)query, ULONG_MAX );
  if( FD_UNLIKELY( leader_idx==my_orig_idx ) ) return NULL; /* I am the leader. Use compute_first */

  if( FD_UNLIKELY( (sdest->cnt<=1UL) |                    /* We don't know about a single destination, so we can't send
                                                             anything. */
        ( (!i_am_staked) & (sdest->staked_cnt-(ulong)leader_is_staked>fanout) ) ) ) {
    /* My position is somewhere after all the staked nodes, which means
       my shuffled index is always greater than fanout.  That means I'm
       always at the bottom of the Turbine tree so I don't have to send
       any shreds to anyone.  Contiguous rows take one memset, NO_DEST
       is all bytes 0xFF. */
    if( FD_LIKELY( out_stride==shred_cnt ) ) fd_memset( out, 0xFF, dest_cnt*shred_cnt*sizeof(fd_shred_dest_idx_t) );
    else for( ulong j=0UL; j<dest_cnt; j++ ) for( ulong i=0UL; i<shred_cnt; i++ ) out[ j*out_stride + i ] = FD_SHRED_DEST_NO_DEST;
    return out;
  }

  uchar dest_hash_outputs[ FD_SHRED_DEST_MAX_SHRED_CNT ][ 32 ];


  if( FD_UNLIKELY( compute_seeds( sdest, input_shreds, shred_cnt, leader, slot, dest_hash_outputs ) ) ) return NULL;

  ulong max_dest_cnt = 0UL;

  ulong staked_shuffle[ sdest->staked_cnt+1UL ];
  ulong staked_shuffle_populated_cnt = 0UL;
  int   flat = !!sdest->flat_cls;

  for( ulong i=0UL; i<shred_cnt; i++ ) {
    /* Remove the leader. */
    if( FD_LIKELY( leader_is_staked ) ) {
      if( flat ) flat_remove_idx( sdest, leader_idx );
      else       fd_wsample_remove_idx( sdest->staked, leader_idx );
    }

    ulong my_idx         = 0UL;
    fd_wsample_seed_rng( sdest->staked, dest_hash_outputs[ i ] ); /* Seeds both samplers since the rng is shared */

    if( FD_UNLIKELY( !i_am_staked ) ) {
      /* Quickly burn through all the staked nodes since I'll be in the
         unstaked portion.  We don't care about the values, but we need
         to advance the RNG the right number of times, and sadly there's
         no other way to do it than this. There can't be too many of
         them since otherwise we would have taken the quick exit at the
         start of the function. */
      staked_shuffle_populated_cnt = sdest->staked_cnt + 1UL;
      if( flat ) flat_sample_and_remove_many( sdest, staked_shuffle, staked_shuffle_populated_cnt );
      else       fd_wsample_sample_and_remove_many( sdest->staked, staked_shuffle, staked_shuffle_populated_cnt );
      my_idx += sdest->staked_cnt - (ulong)leader_is_staked;

      prepare_unstaked_sampling( sdest, leader_idx );
      while( my_idx <= fanout ) {
        ulong sample = sample_unstaked( sdest );
        if( FD_UNLIKELY( sample==my_orig_idx      ) ) break; /* Found me! */
        if( FD_UNLIKELY( sample==FD_WSAMPLE_EMPTY ) ) return NULL; /* I couldn't find myself.  This should be impossible. */
        my_idx++;
      }
    } else {
      staked_shuffle_populated_cnt = fd_ulong_min( fanout+1UL, sdest->staked_cnt+1UL );
      if( flat ) flat_sample_and_remove_many( sdest, staked_shuffle, staked_shuffle_populated_cnt );
      else       fd_wsample_sample_and_remove_many( sdest->staked, staked_shuffle, staked_shuffle_populated_cnt );
      while( my_idx <= fanout ) {
        /* my_idx < fanout+1UL because of the while loop condition.
           my_idx < staked_cnt+1UL because my_idx==staked_cnt will
           trigger sample==FD_WSAMPLE_EMPTY below.  Thus, this access is
           safe. */
        ulong sample = staked_shuffle[ my_idx ];
        if( FD_UNLIKELY( sample==my_orig_idx              ) ) break; /* Found me! */
        if( FD_UNLIKELY( sample==FD_WSAMPLE_EMPTY         ) ) return NULL; /* I couldn't find myself.  This should be impossible. */
        my_idx++;
      }
    }

    if( FD_LIKELY( my_idx > fanout ) ) {
      /* I'm at the bottom of Turbine tree for this shred.  Fill in all
         the destinations with NO_DEST. */
      for( ulong j=0UL; j<dest_cnt; j++ ) out[ j*out_stride + i ] = FD_SHRED_DEST_NO_DEST;

      if( flat ) flat_restore_all( sdest );
      else       fd_wsample_restore_all( sdest->staked );
      continue; /* Next shred */
    }
    /* If my index is    |  Send to indices
       ------------------------------------
        Leader (no idx)  |  0             (just for reference)
        0                |  1, 2, ..., F
        j in [1, F]      |  j + l*F for l in [1,F]
        [F+1, F^2+F]     |  Nobody
        [F^2+F+1, inf)   |  Not yet implemented in Agave code
     */
    ulong last_dest_idx = fd_ulong_if( my_idx==0UL, fanout, my_idx+fanout*fanout ); /* inclusive */
    ulong stride        = fd_ulong_if( my_idx==0UL, 1UL,    fanout               );

    last_dest_idx = fd_ulong_min( last_dest_idx, my_idx + stride*dest_cnt );

    ulong cursor     = my_idx+1UL;
    ulong stored_cnt = 0UL;

    if( FD_LIKELY( (last_dest_idx>=staked_shuffle_populated_cnt) & (staked_shuffle_populated_cnt<sdest->staked_cnt+1UL ) ) ) {
      ulong adtl = fd_ulong_min( last_dest_idx+1UL, sdest->staked_cnt+1UL ) - staked_shuffle_populated_cnt;

      if( flat ) flat_sample_and_remove_many( sdest, staked_shuffle+staked_shuffle_populated_cnt, adtl );
      else       fd_wsample_sample_and_remove_many( sdest->staked, staked_shuffle+staked_shuffle_populated_cnt, adtl );
      staked_shuffle_populated_cnt += adtl;
    }

    while( cursor<=fd_ulong_min( last_dest_idx, sdest->staked_cnt ) ) {
      ulong sample = staked_shuffle[ cursor ];
      if( FD_UNLIKELY( sample==FD_WSAMPLE_EMPTY         ) ) break;

      if( FD_UNLIKELY( cursor == my_idx + stride*(stored_cnt+1UL) ) ) {
        out[ stored_cnt*out_stride + i ] = (fd_shred_dest_idx_t)sample;
        stored_cnt++;
      }
      cursor++;
    }

    /* Next set of samples (if any) come from the unstaked portion. If I
       am not staked, then prepare_unstaked_sampling was already called
       earlier. */
    if( FD_LIKELY( (cursor<=last_dest_idx) & !!i_am_staked ) ) prepare_unstaked_sampling( sdest, leader_idx );

    /* sample_unstaked over buffered rng runs: resolve accepts (bounds
       n,n-1,...) first, then swap */
    fd_chacha_rng_t * rng  = sdest->rng;
    ulong *           u    = sdest->unstaked;
    ulong             n    = sdest->unstaked_unremoved_cnt;
    ulong             emit = my_idx + stride*(stored_cnt+1UL);
    ulong             end  = fd_ulong_min( last_dest_idx+1UL, cursor+n );
    while( cursor<end ) {
      if( FD_UNLIKELY( rng->buf_off==rng->buf_fill ) ) {
        if( rng->algo==FD_CHACHA_RNG_ALGO_CHACHA8 ) fd_chacha8_rng_private_refill ( rng );
        else                                        fd_chacha20_rng_private_refill( rng );
      }
      ulong         off  = rng->buf_off;
      ulong         boff = off%FD_CHACHA_RNG_BUFSZ;
      uchar const * wbuf = rng->buf + boff;
      ulong         wcnt = fd_ulong_min( rng->buf_fill-off, FD_CHACHA_RNG_BUFSZ-boff )/8UL;
      ulong         need = end-cursor;
      uint          h[ FD_CHACHA_RNG_BUFSZ/8UL ];
      ulong         j    = 0UL;
      ulong         k    = 0UL;
      while( k<wcnt ) {
        ulong nj = n-j;
        ulong hi, lo;
        fd_uwide_mul( &hi, &lo, FD_LOAD( ulong, wbuf+8UL*k ), nj );
        h[ j ] = (uint)hi;
        j += (ulong)( lo < (nj << (63-fd_ulong_find_msb( nj ))) ); /* MODE_SHIFT zone */
        k++;
        if( FD_UNLIKELY( j==need ) ) break;
      }
      rng->buf_off = off + 8UL*k;

      for( ulong q=0UL; q<j; q++ ) {
        ulong sample = u[ h[ q ] ];
        u[ h[ q ] ] = u[ n-1UL-q ];
        if( FD_UNLIKELY( cursor+q==emit ) ) {
          out[ stored_cnt*out_stride + i ] = (fd_shred_dest_idx_t)sample;
          stored_cnt++;
          emit += stride;
        }
      }
      n      -= j;
      cursor += j;
    }
    sdest->unstaked_unremoved_cnt = n;
    max_dest_cnt = fd_ulong_max( max_dest_cnt, stored_cnt );

    /* The rest of my destinations are past the end of the tree */
    for( ulong j=stored_cnt; j<dest_cnt; j++ ) out[ j*out_stride + i ] = FD_SHRED_DEST_NO_DEST;

    if( flat ) flat_restore_all( sdest );
    else       fd_wsample_restore_all( sdest->staked );

  }
  fd_ulong_store_if( !!opt_max_dest_cnt, opt_max_dest_cnt, max_dest_cnt );
  return out;
}

fd_shred_dest_idx_t
fd_shred_dest_pubkey_to_idx( fd_shred_dest_t   * sdest,
                             fd_pubkey_t const * pubkey     ) {
  if( FD_UNLIKELY( !memcmp( pubkey, null_pubkey.uc, 32UL ) ) ) return FD_SHRED_DEST_NO_DEST;

  return pubkey_map_query( sdest, pubkey );
}

fd_shred_dest_idx_t
fd_shred_dest_leader_for_slot( fd_shred_dest_t const * sdest,
                               ulong slot ) {
  fd_pubkey_t const * leader = fd_epoch_leaders_get( sdest->lsched, slot );
  if( FD_UNLIKELY( !leader ) ) return FD_SHRED_DEST_NO_DEST;

  fd_shred_dest_idx_t idx = pubkey_map_query( sdest, leader );
  if( FD_UNLIKELY( idx==sdest->source_validator_orig_idx ) ) return FD_SHRED_DEST_NO_DEST;

  return idx;
}

