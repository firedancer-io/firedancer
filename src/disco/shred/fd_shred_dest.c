#include "fd_shred_dest.h"

struct pubkey_to_idx {
  fd_pubkey_t key;
  ulong       idx;
};
typedef struct pubkey_to_idx pubkey_to_idx_t;

const fd_pubkey_t null_pubkey = {{ 0 }};

#define MAP_NAME              pubkey_to_idx
#define MAP_T                 pubkey_to_idx_t
#define MAP_KEY_T             fd_pubkey_t
#define MAP_KEY_NULL          null_pubkey
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_MEMOIZE           0
#define MAP_KEY_INVAL(k)      MAP_KEY_EQUAL((k),MAP_KEY_NULL)
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp( (k0).key, (k1).key, 32UL ))
#define MAP_KEY_HASH(key)     ((MAP_HASH_T)( (key).ul[1] ))

#include "../../util/tmpl/fd_map_dynamic.c"


/* This 45 byte struct gets hashed to compute the seed for Chacha20 to
   compute the shred destinations. */
struct __attribute__((packed)) shred_dest_input {
  ulong slot;
  uchar type; /*     Data = 0b1010_0101, Code = 0b0101_1010 */
  uint  idx;
  uchar leader_pubkey[32];
};
typedef struct shred_dest_input shred_dest_input_t;

ulong
fd_shred_dest_footprint( ulong staked_cnt, ulong unstaked_cnt ) {
  ulong cnt = staked_cnt+unstaked_cnt;
  int lg_cnt = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*fd_ulong_max( cnt, 1UL ) ) );
  return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND(
                FD_LAYOUT_INIT,
                fd_shred_dest_align(),             sizeof(fd_shred_dest_t)              ),
                pubkey_to_idx_align(),             pubkey_to_idx_footprint( lg_cnt )    ),
                alignof(fd_shred_dest_weighted_t), sizeof(fd_shred_dest_weighted_t)*cnt ),
                fd_wsample_align(),                fd_wsample_footprint( staked_cnt, 1 )),
                alignof(ulong),                    sizeof(ulong)*unstaked_cnt           ),
      FD_SHRED_DEST_ALIGN );
}


void *
fd_shred_dest_new( void                           * mem,
                   fd_shred_dest_weighted_t const * info,
                   ulong                            cnt,
                   fd_epoch_leaders_t const       * lsched,
                   fd_pubkey_t const              * source ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_shred_dest_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  int lg_cnt = fd_ulong_find_msb( fd_ulong_pow2_up( 2UL*fd_ulong_max( cnt, 1UL ) ) );
  FD_SCRATCH_ALLOC_INIT( footprint, mem );
  fd_shred_dest_t * sdest;
  /* */  sdest     = FD_SCRATCH_ALLOC_APPEND( footprint, fd_shred_dest_align(),             sizeof(fd_shred_dest_t)              );
  void * _map      = FD_SCRATCH_ALLOC_APPEND( footprint, pubkey_to_idx_align(),             pubkey_to_idx_footprint( lg_cnt )    );
  void * _info     = FD_SCRATCH_ALLOC_APPEND( footprint, alignof(fd_shred_dest_weighted_t), sizeof(fd_shred_dest_weighted_t)*cnt );

  ulong cnts[2] = { 0UL, 0UL }; /* cnts[0] = staked, cnts[1] = unstaked */

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
  }

  ulong staked_cnt   = cnts[0];
  ulong unstaked_cnt = cnts[1];

  void * _wsample  = FD_SCRATCH_ALLOC_APPEND( footprint, fd_wsample_align(),                fd_wsample_footprint( staked_cnt, 1 ));
  void * _unstaked = FD_SCRATCH_ALLOC_APPEND( footprint, alignof(ulong),                    sizeof(ulong)*unstaked_cnt           );


  fd_chacha20rng_t * rng = fd_chacha20rng_join( fd_chacha20rng_new( sdest->rng, FD_CHACHA20RNG_MODE_SHIFT ) );

  void  *  _staked   = fd_wsample_new_init( _wsample,  rng, staked_cnt,   1, FD_WSAMPLE_HINT_POWERLAW_REMOVE );

  for( ulong i=0UL; i<staked_cnt;   i++ ) _staked   = fd_wsample_new_add( _staked,   info[i].stake_lamports );
  _staked   = fd_wsample_new_fini( _staked   );

  pubkey_to_idx_t * pubkey_to_idx_map = pubkey_to_idx_join( pubkey_to_idx_new( _map, lg_cnt ) );
  for( ulong i=0UL; i<cnt; i++ ) {
    pubkey_to_idx_insert( pubkey_to_idx_map, info[i].pubkey )->idx = i;
  }
  pubkey_to_idx_t * query = pubkey_to_idx_query( pubkey_to_idx_map, *source, NULL );
  if( FD_UNLIKELY( !query ) ) {
    FD_LOG_WARNING(( "source pubkey not found" ));
    return NULL;
  }

  memset( sdest->null_dest, 0, sizeof(fd_shred_dest_weighted_t) );
  sdest->lsched                     = lsched;
  sdest->cnt                        = cnt;
  sdest->all_destinations           = copy;
  sdest->staked                     = fd_wsample_join( _staked );
  sdest->unstaked                   = _unstaked;
  sdest->unstaked_unremoved_cnt     = 0UL; /* unstaked doesn't get initialized until it's needed */
  sdest->staked_cnt                 = staked_cnt;
  sdest->unstaked_cnt               = unstaked_cnt;
  sdest->pubkey_to_idx_map          = pubkey_to_idx_map;
  sdest->source_validator_orig_idx  = query->idx;

  return (void *)sdest;
}

fd_shred_dest_t * fd_shred_dest_join( void * mem  ) { return (fd_shred_dest_t *)mem; }
void * fd_shred_dest_leave( fd_shred_dest_t * sdest ) { return (void *)sdest;          }

void * fd_shred_dest_delete( void * mem ) {
  fd_shred_dest_t * sdest = (fd_shred_dest_t *)mem;

  fd_chacha20rng_delete( fd_chacha20rng_leave( sdest->rng               ) );
  fd_wsample_delete    ( fd_wsample_leave    ( sdest->staked            ) );
  pubkey_to_idx_delete ( pubkey_to_idx_leave ( sdest->pubkey_to_idx_map ) );
  return mem;
}

/* sample_unstaked, sample_unstaked_noprepare, and
   prepare_unstaked_sampling are used to perform the specific form of
   unweighted random sampling that Solana uses for unstaked validators.
   In essence, you:
    1. construct a list of all the unstaked validators,
    2. delete the leader (if present)
    then repeatedly:
    3. choose the chacha20rng_roll( |unstaked| )th element.
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

  ulong sample = sdest->staked_cnt + fd_chacha20rng_ulong_roll( sdest->rng, unstaked_cnt );
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

  ulong sample = fd_chacha20rng_ulong_roll( sdest->rng, sdest->unstaked_unremoved_cnt );
  ulong to_return = sdest->unstaked[sample];
  sdest->unstaked[sample] = sdest->unstaked[--sdest->unstaked_unremoved_cnt];
  return to_return;
}


/* Returns 0 on success */
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
    h_in->type = fd_uchar_if( (shred_type==FD_SHRED_TYPE_LEGACY_DATA) | (shred_type==FD_SHRED_TYPE_MERKLE_DATA), 0xA5, 0x5A );
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
    fd_wsample_seed_rng( fd_wsample_get_rng( sdest->staked ), dest_hash_outputs[ i ] );
    if( FD_LIKELY( any_staked_candidates ) ) out[i] = (ushort)fd_wsample_sample( sdest->staked );
    else                                     out[i] = (ushort)sample_unstaked_noprepare( sdest, sdest->source_validator_orig_idx );
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
  pubkey_to_idx_t *   query  = pubkey_to_idx_query( sdest->pubkey_to_idx_map, *leader, NULL );
  int                 leader_is_staked = query ? (query->idx<sdest->staked_cnt): 0;
  ulong               leader_idx       = query ?  query->idx                   : ULONG_MAX;
  if( FD_UNLIKELY( !leader                 ) ) return NULL; /* Unknown slot */
  if( FD_UNLIKELY( leader_idx==my_orig_idx ) ) return NULL; /* I am the leader. Use compute_first */

  if( FD_UNLIKELY( (sdest->cnt<=1UL) |                    /* We don't know about a single destination, so we can't send
                                                             anything. */
        ( (!i_am_staked) & (sdest->staked_cnt-(ulong)leader_is_staked>fanout) ) ) ) {
    /* My position is somewhere after all the staked nodes, which means
       my shuffled index is always greater than fanout.  That means I'm
       always at the bottom of the Turbine tree so I don't have to send
       any shreds to anyone. */
    for( ulong j=0UL; j<dest_cnt; j++ ) for( ulong i=0UL; i<shred_cnt; i++ ) out[ j*out_stride + i ] = FD_SHRED_DEST_NO_DEST;
    return out;
  }

  uchar dest_hash_outputs[ FD_SHRED_DEST_MAX_SHRED_CNT ][ 32 ];


  if( FD_UNLIKELY( compute_seeds( sdest, input_shreds, shred_cnt, leader, slot, dest_hash_outputs ) ) ) return NULL;

  ulong max_dest_cnt = 0UL;

  ulong staked_shuffle[ sdest->staked_cnt+1UL ];
  ulong staked_shuffle_populated_cnt = 0UL;

  for( ulong i=0UL; i<shred_cnt; i++ ) {
    /* Remove the leader. */
    if( FD_LIKELY( query && leader_is_staked ) ) fd_wsample_remove_idx( sdest->staked, leader_idx );

    ulong my_idx         = 0UL;
    fd_wsample_seed_rng( fd_wsample_get_rng( sdest->staked ), dest_hash_outputs[ i ] ); /* Seeds both samplers since the rng is shared */

    if( FD_UNLIKELY( !i_am_staked ) ) {
      /* Quickly burn through all the staked nodes since I'll be in the
         unstaked portion.  We don't care about the values, but we need
         to advance the RNG the right number of times, and sadly there's
         no other way to do it than this. There can't be too many of
         them since otherwise we would have taken the quick exit at the
         start of the function. */
      staked_shuffle_populated_cnt = sdest->staked_cnt + 1UL;
      fd_wsample_sample_and_remove_many( sdest->staked, staked_shuffle, staked_shuffle_populated_cnt );
      my_idx += sdest->staked_cnt - (ulong)(query && leader_is_staked);

      prepare_unstaked_sampling( sdest, leader_idx );
      while( my_idx <= fanout ) {
        ulong sample = sample_unstaked( sdest );
        if( FD_UNLIKELY( sample==my_orig_idx      ) ) break; /* Found me! */
        if( FD_UNLIKELY( sample==FD_WSAMPLE_EMPTY ) ) return NULL; /* I couldn't find myself.  This should be impossible. */
        my_idx++;
      }
    } else {
      staked_shuffle_populated_cnt = fd_ulong_min( fanout+1UL, sdest->staked_cnt+1UL );
      fd_wsample_sample_and_remove_many( sdest->staked, staked_shuffle, staked_shuffle_populated_cnt );
      while( my_idx <= fanout ) {
        /* my_idx < fanout+1UL because of the while loop condition.
           my_idx < staked_cnt+1UL because my_idx==staked_cnt will
           trigger sample==FD_WSAMPLE_EMPTY below.  Thus, this access is
           safe. */
        ulong sample = staked_shuffle[ my_idx ];
        if( FD_UNLIKELY( sample==my_orig_idx      ) ) break; /* Found me! */
        if( FD_UNLIKELY( sample==FD_WSAMPLE_EMPTY ) ) return NULL; /* I couldn't find myself.  This should be impossible. */
        my_idx++;
      }
    }

    if( FD_LIKELY( my_idx > fanout ) ) {
      /* I'm at the bottom of Turbine tree for this shred.  Fill in all
         the destinations with NO_DEST. */
      for( ulong j=0UL; j<dest_cnt; j++ ) out[ j*out_stride + i ] = FD_SHRED_DEST_NO_DEST;

      fd_wsample_restore_all( sdest->staked   );
      continue; /* Next shred */
    }
    /* If my index is    |  Send to indices
       ------------------------------------
        Leader (no idx)  |  0             (just for reference)
        0                |  1, 2, ..., F
        j in [1, F]      |  j + l*F for l in [1,F]
        [F+1, F^2+F]     |  Nobody
        [F^2+F+1, inf)   |  Not yet implemented in Labs code
     */
    ulong last_dest_idx = fd_ulong_if( my_idx==0UL, fanout, my_idx+fanout*fanout ); /* inclusive */
    ulong stride        = fd_ulong_if( my_idx==0UL, 1UL,    fanout               );

    last_dest_idx = fd_ulong_min( last_dest_idx, my_idx + stride*dest_cnt );

    ulong cursor     = my_idx+1UL;
    ulong stored_cnt = 0UL;

    if( FD_LIKELY( (last_dest_idx>=staked_shuffle_populated_cnt) & (staked_shuffle_populated_cnt<sdest->staked_cnt+1UL ) ) ) {
      ulong adtl = fd_ulong_min( last_dest_idx+1UL, sdest->staked_cnt+1UL ) - staked_shuffle_populated_cnt;

      fd_wsample_sample_and_remove_many( sdest->staked, staked_shuffle+staked_shuffle_populated_cnt, adtl );
      staked_shuffle_populated_cnt += adtl;
    }

    while( cursor<=fd_ulong_min( last_dest_idx, sdest->staked_cnt ) ) {
      ulong sample = staked_shuffle[ cursor ];
      if( FD_UNLIKELY( sample==FD_WSAMPLE_EMPTY ) ) break;

      if( FD_UNLIKELY( cursor == my_idx + stride*(stored_cnt+1UL) ) ) {
        out[ stored_cnt*out_stride + i ] = (ushort)sample;
        stored_cnt++;
      }
      cursor++;
    }

    /* Next set of samples (if any) come from the unstaked portion */
    if( FD_LIKELY( (cursor<=last_dest_idx) & !!i_am_staked ) ) prepare_unstaked_sampling( sdest, leader_idx );
    while( cursor<=last_dest_idx ) {
      ulong sample = sample_unstaked( sdest );
      if( FD_UNLIKELY( sample==FD_WSAMPLE_EMPTY ) ) break;

      if( FD_UNLIKELY( cursor == my_idx + stride*(stored_cnt+1UL) ) ) {
        out[ stored_cnt*out_stride + i ] = (ushort)sample;
        stored_cnt++;
      }
      cursor++;
    }
    max_dest_cnt = fd_ulong_max( max_dest_cnt, stored_cnt );

    /* The rest of my destinations are past the end of the tree */
    for( ulong j=stored_cnt; j<dest_cnt; j++ ) out[ j*out_stride + i ] = FD_SHRED_DEST_NO_DEST;

    fd_wsample_restore_all( sdest->staked );

  }
  fd_ulong_store_if( !!opt_max_dest_cnt, opt_max_dest_cnt, max_dest_cnt );
  return out;
}

fd_shred_dest_idx_t
fd_shred_dest_pubkey_to_idx( fd_shred_dest_t   * sdest,
                             fd_pubkey_t const * pubkey     ) {
  if( FD_UNLIKELY( !memcmp( pubkey, null_pubkey.uc, 32UL ) ) ) return FD_SHRED_DEST_NO_DEST;

  pubkey_to_idx_t default_res[ 1 ] = {{ .idx = FD_SHRED_DEST_NO_DEST }};
  pubkey_to_idx_t * query = pubkey_to_idx_query( sdest->pubkey_to_idx_map, *pubkey, default_res );

  return (fd_shred_dest_idx_t)query->idx;
}

