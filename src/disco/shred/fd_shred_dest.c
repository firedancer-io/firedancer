#include "fd_shred_dest.h"
#include "../../util/fd_hash32.h"
#if FD_HAS_AVX512
#include "../../util/simd/fd_avx512.h"
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

/* Flat staked sampler (AVX-512, staked_cnt<=FLAT_MAX): group prefixes
   in registers over rows of 16, 32 or 64 leaf prefixes. */
#define FLAT_MAX  (4096UL)

static inline ulong
flat_cls( ulong staked_cnt ) {
# if FD_HAS_AVX512
  if( FD_UNLIKELY( (staked_cnt==0UL) | (staked_cnt>FLAT_MAX) ) ) return 0UL;
  return 1UL + (ulong)(staked_cnt>512UL) + (ulong)(staked_cnt>1024UL) + (ulong)(staked_cnt>2048UL);
# else
  (void)staked_cnt;
  return 0UL;
# endif
}

/* flat_gsz returns the number of leaves per row. */
static inline ulong flat_gsz( ulong cls ) { return fd_ulong_if( cls==1UL, 16UL, fd_ulong_if( cls==4UL, 64UL, 32UL ) ); }

/* flat_row_cnt returns the number of ulongs in each of flat_rowb and
   flat_row. */
static inline ulong
flat_row_cnt( ulong staked_cnt ) {
  ulong cls = flat_cls( staked_cnt );
  return fd_ulong_if( !!cls, fd_ulong_align_up( staked_cnt, flat_gsz( cls ) ), 0UL );
}

static inline ulong flat_footprint( ulong staked_cnt ) { return sizeof(ulong)*2UL*flat_row_cnt( staked_cnt ); }

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

  void  *  _staked   = fd_wsample_new_init( _wsample,  rng, staked_cnt,   1, FD_WSAMPLE_HINT_POWERLAW_REMOVE );

  /* Pad lanes hold the row total, pad groups ULONG_MAX: never selected. */
  ulong   cls   = flat_cls( staked_cnt );
  ulong   gmask = flat_gsz( cls )-1UL;
  ulong * frowb = _flat;
  ulong   acc   = 0UL;
  ulong   row   = 0UL;
  for( ulong g=0UL; g<64UL; g++ ) sdest->flat_p0b[ g ] = ULONG_MAX;
  memset( sdest->flat_p0m, 0, sizeof(sdest->flat_p0m) );
  if( cls ) {
    for( ulong i=0UL; i<staked_cnt; i++ ) {
      ulong wt = info[i].stake_lamports;
      _staked    = fd_wsample_new_add( _staked, wt );
      row       += wt;
      frowb[ i ] = row;
      if( (i&gmask)==gmask ) { acc += row; sdest->flat_p0b[ i>>fd_ulong_find_msb( gmask+1UL ) ] = acc; row = 0UL; }
    }
    for( ulong i=staked_cnt; i<flat_cnt; i++ ) frowb[ i ] = row;
    if( staked_cnt&gmask ) { acc += row; sdest->flat_p0b[ staked_cnt>>fd_ulong_find_msb( gmask+1UL ) ] = acc; }
    fd_memcpy( _flat+flat_cnt, frowb, sizeof(ulong)*flat_cnt );
    if( FD_UNLIKELY( (acc>=(1UL<<63)) | !_staked ) ) cls = 0UL; /* fd_wsample fallback */
    else fd_memcpy( sdest->flat_p0m+8UL, sdest->flat_p0b, sizeof(sdest->flat_p0b) );
  } else {
    for( ulong i=0UL; i<staked_cnt; i++ ) _staked = fd_wsample_new_add( _staked, info[i].stake_lamports );
  }
  _staked   = fd_wsample_new_fini( _staked, 0UL );

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

  sdest->flat_cls   = cls;
  sdest->flat_total = acc;
  sdest->flat_W     = acc;
  sdest->flat_dirty = 0UL;
  sdest->flat_rowb  = _flat;
  sdest->flat_row   = _flat + flat_cnt;

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


#if FD_HAS_AVX512

/* flat_roll is fd_chacha_rng_ulong_roll( rng, W ) (MODE_SHIFT) with
   the buffer cursor in registers. */
static inline __attribute__((always_inline)) ulong
flat_roll( fd_chacha_rng_t * rng,
           ulong             W,
           ulong           * _off,
           ulong           * _fill ) {
  ulong off  = *_off;
  ulong fill = *_fill;
  ulong zone = (W << (63 - fd_ulong_find_msb( W ))) - 1UL;
  ulong r;
  for(;;) {
    if( FD_UNLIKELY( off==fill ) ) { rng->buf_off = off; fd_chacha8_rng_private_refill( rng ); fill = rng->buf_fill; }
    ulong v = FD_LOAD( ulong, rng->buf + (off % FD_CHACHA_RNG_BUFSZ) );
    off += 8UL;
    ulong lo;
    fd_uwide_mul( &r, &lo, v, W );
    if( FD_LIKELY( lo<=zone ) ) break;
  }
  *_off  = off;
  *_fill = fill;
  return r;
}

/* flat_remove_idx removes staked leaf idx. */
static void
flat_remove_idx( fd_shred_dest_t * sdest,
                 ulong             idx ) {
  ulong gsz = flat_gsz( sdest->flat_cls );
  ulong g   = idx / gsz;
  ulong k0  = idx % gsz;
  ulong wt  = sdest->flat_row[ idx ] - fd_ulong_if( !!k0, sdest->flat_row[ idx-1UL ], 0UL );
  for( ulong k=k0;      k<gsz;  k++ ) sdest->flat_row[ g*gsz+k ] -= wt;
  for( ulong t=g;       t<64UL; t++ ) sdest->flat_p0m[ 8UL+t ]   -= wt;
  sdest->flat_dirty |= 1UL<<g;
  sdest->flat_W     -= wt;
}

/* flat_sample is fd_wsample_sample_and_remove_many over nr0 group
   prefix registers and rows of rv vectors. */
static inline __attribute__((always_inline)) void
flat_sample( fd_shred_dest_t * sdest,
             ulong           * out,
             ulong             cnt,
             ulong const       nr0,
             ulong const       rv ) {
  fd_chacha_rng_t * rng = sdest->rng;
  ulong const       gsz = 8UL*rv;
  ulong *           p0m = sdest->flat_p0m+8UL;
  ulong *           row = sdest->flat_row;

  wwv_t p0[ 8 ];
# pragma GCC unroll 8
  for( ulong j=0UL; j<nr0; j++ ) p0[ j ] = wwv_ld( p0m+8UL*j );

  ulong W     = sdest->flat_W;
  ulong dirty = sdest->flat_dirty;
  ulong off   = rng->buf_off;
  ulong fill  = rng->buf_fill;

  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( !W ) ) { out[ i ] = FD_WSAMPLE_EMPTY; continue; }

    ulong r  = flat_roll( rng, W, &off, &fill );
    wwv_t vr = wwv_bcast( r );
    ulong g  = 0UL;
#   pragma GCC unroll 8
    for( ulong j=0UL; j<nr0; j++ ) g += (ulong)fd_ulong_popcnt( (ulong)(uint)wwv_le( p0[ j ], vr ) );

    wwv_t   vrr = wwv_bcast( r - p0m[ (long)g-1L ] );
    ulong * q   = row + g*gsz;
    wwv_t   rr[ 8 ];
    ulong   k   = 0UL;
#   pragma GCC unroll 8
    for( ulong j=0UL; j<rv; j++ ) { rr[ j ] = wwv_ld( q+8UL*j ); k += (ulong)fd_ulong_popcnt( (ulong)(uint)wwv_le( rr[ j ], vrr ) ); }

    ulong idx = g*gsz + k;
    ulong wt  = q[ k ] - (q[ (k-1UL)&(gsz-1UL) ] & (-(ulong)(k!=0UL)));
    wwv_t vw  = wwv_bcast( wt );
#   pragma GCC unroll 8
    for( ulong j=0UL; j<nr0; j++ ) { p0[ j ] = wwv_sub_if( wwv_gt( p0[ j ], vr ), p0[ j ], vw, p0[ j ] ); wwv_st( p0m+8UL*j, p0[ j ] ); }
#   pragma GCC unroll 8
    for( ulong j=0UL; j<rv;  j++ ) wwv_st( q+8UL*j, wwv_sub_if( wwv_gt( rr[ j ], vrr ), rr[ j ], vw, rr[ j ] ) );

    dirty   |= 1UL<<g;
    W       -= wt;
    out[ i ] = idx;
  }

  rng->buf_off      = off;
  sdest->flat_W     = W;
  sdest->flat_dirty = dirty;
}

static void
flat_sample_and_remove_many( fd_shred_dest_t * sdest,
                             ulong           * out,
                             ulong             cnt ) {
  switch( sdest->flat_cls ) {
  case 1UL: flat_sample( sdest, out, cnt, 4UL, 2UL ); break;
  case 2UL: flat_sample( sdest, out, cnt, 4UL, 4UL ); break;
  case 3UL: flat_sample( sdest, out, cnt, 8UL, 4UL ); break;
  default:  flat_sample( sdest, out, cnt, 8UL, 8UL ); break;
  }
}

/* flat_restore_all undoes all removals by copying back dirty rows. */
static inline void
flat_restore_all( fd_shred_dest_t * sdest ) {
  ulong gsz = flat_gsz( sdest->flat_cls );
  for( ulong d=sdest->flat_dirty; d; d=fd_ulong_pop_lsb( d ) ) {
    ulong g = (ulong)fd_ulong_find_lsb( d );
    fd_memcpy( sdest->flat_row+g*gsz, sdest->flat_rowb+g*gsz, gsz*sizeof(ulong) );
  }
  sdest->flat_dirty = 0UL;
  sdest->flat_W     = sdest->flat_total;
  fd_memcpy( sdest->flat_p0m+8UL, sdest->flat_p0b, sizeof(sdest->flat_p0b) );
}

#else /* the flat sampler is never enabled */

static inline void flat_remove_idx            ( fd_shred_dest_t * sdest, ulong idx                ) { (void)sdest; (void)idx;            }
static inline void flat_sample_and_remove_many( fd_shred_dest_t * sdest, ulong * out, ulong cnt ) { (void)sdest; (void)out; (void)cnt; }
static inline void flat_restore_all           ( fd_shred_dest_t * sdest                           ) { (void)sdest;                       }

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
  if( FD_LIKELY( source_validator_is_staked ) )
    fd_wsample_remove_idx( sdest->staked, sdest->source_validator_orig_idx );

  int any_staked_candidates = sdest->staked_cnt > (ulong)source_validator_is_staked;
  for( ulong i=0UL; i<shred_cnt; i++ ) {
    fd_wsample_seed_rng( sdest->staked, dest_hash_outputs[ i ] );
    /* Map FD_WSAMPLE_EMPTY (UINT_MAX) to FD_SHRED_DEST_NO_DEST.
       Otherwise, since wsample guarantees the returned index is in
       [0, INT_MAX], it will remain non-negative when cast to an int. */
    FD_STATIC_ASSERT( (int)FD_WSAMPLE_EMPTY                     <=-1, wsample_val );
    FD_STATIC_ASSERT( FD_SHRED_DEST_NO_DEST==(fd_shred_dest_idx_t)-1, wsample_val );
    if( FD_LIKELY( any_staked_candidates ) ) out[i] = (fd_shred_dest_idx_t)fd_int_max( (int)fd_wsample_sample( sdest->staked ), -1 );
    else                                     out[i] = (fd_shred_dest_idx_t)sample_unstaked_noprepare( sdest, sdest->source_validator_orig_idx );
  }
  fd_wsample_restore_all( sdest->staked );

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
    while( cursor<=last_dest_idx ) {
      ulong sample = sample_unstaked( sdest );
      if( FD_UNLIKELY( sample==FD_WSAMPLE_EMPTY ) ) break;

      if( FD_UNLIKELY( cursor == my_idx + stride*(stored_cnt+1UL) ) ) {
        out[ stored_cnt*out_stride + i ] = (fd_shred_dest_idx_t)sample;
        stored_cnt++;
      }
      cursor++;
    }
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

