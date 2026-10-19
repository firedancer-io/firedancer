#include "fd_leaders.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/chacha/fd_chacha_rng.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/wsample/fd_wsample.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"

#define SORT_NAME sort_vote_weights_by_stake_id
#define SORT_KEY_T fd_vote_stake_weight_t
#define SORT_BEFORE(a,b) ((a).stake > (b).stake ? 1 : ((a).stake < (b).stake ? 0 : memcmp( (a).id_key.uc, (b).id_key.uc, 32UL )>0))
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME sort_vote_weights_by_id
#define SORT_KEY_T fd_vote_stake_weight_t
#define SORT_BEFORE(a,b) (memcmp( (a).id_key.uc, (b).id_key.uc, 32UL )>0)
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME sort_weights_by_stake_id
#define SORT_KEY_T fd_stake_weight_t
#define SORT_BEFORE(a,b) ((a).stake > (b).stake ? 1 : ((a).stake < (b).stake ? 0 : memcmp( (a).key.uc, (b).key.uc, 32UL )>0))
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME sort_weights_by_id
#define SORT_KEY_T fd_stake_weight_t
#define SORT_BEFORE(a,b) (memcmp( (a).key.uc, (b).key.uc, 32UL )>0)
#include "../../util/tmpl/fd_sort.c"

/* FD_EPOCH_LEADERS_GEO_RUN_LENGTH is the maximum number of leaders in
   a single cluster. Defined by SIMD-0675. */
#define FD_EPOCH_LEADERS_GEO_RUN_LENGTH  (3UL)

/* FD_EPOCH_LEADERS_GEO_STAKE_FLOOR is the minimum % of the total stake
   that each leaders radius must contain. Defined by SIMD-0675. */
#define FD_EPOCH_LEADERS_GEO_STAKE_FLOOR (10UL)

ulong
compute_id_weights_from_vote_weights( fd_stake_weight_t *            stake_weight,
                                      fd_vote_stake_weight_t const * vote_stake_weight,
                                      ulong                          staked_cnt ) {

  /* Copy from input message [(vote, id, stake)] into old format [(id, stake)]. */
  ulong idx = 0UL;
  for( ulong i=0UL; i<staked_cnt; i++ ) {
    memcpy( stake_weight[ idx ].key.uc, vote_stake_weight[ i ].id_key.uc, sizeof(fd_pubkey_t) );
    stake_weight[ idx ].stake = vote_stake_weight[ i ].stake;
    idx++;
  }

  /* Sort [(id, stake)] by id, so we can dedup */
  sort_weights_by_id_inplace( stake_weight, idx );

  /* Dedup entries, aggregating stake */
  ulong j=0UL;
  for( ulong i=1UL; i<idx; i++ ) {
    fd_pubkey_t * pre = &stake_weight[ j ].key;
    fd_pubkey_t * cur = &stake_weight[ i ].key;
    if( 0==memcmp( pre, cur, sizeof(fd_pubkey_t) ) ) {
      stake_weight[ j ].stake += stake_weight[ i ].stake;
    } else {
      ++j;
      stake_weight[ j ].stake = stake_weight[ i ].stake;
      memcpy( stake_weight[ j ].key.uc, stake_weight[ i ].key.uc, sizeof(fd_pubkey_t) );
    }
  }
  ulong staked_cnt_by_id = fd_ulong_min( idx, j+1 );

  /* Sort [(id, stake)] by stake then id, as expected */
  sort_weights_by_stake_id_inplace( stake_weight, staked_cnt_by_id );

  return staked_cnt_by_id;
}

ulong
fd_epoch_leaders_align( void ) {
  return FD_EPOCH_LEADERS_ALIGN;
}

FD_FN_CONST ulong
fd_epoch_leaders_footprint( ulong pub_cnt,
                            ulong slot_cnt ) {
  if( FD_UNLIKELY( ( pub_cnt  ==     0UL     )
                 | ( pub_cnt   >UINT_MAX-3UL )
                 | ( slot_cnt==     0UL  ) ) )
    return 0UL;
  return FD_EPOCH_LEADERS_FOOTPRINT( pub_cnt, slot_cnt );
}

struct fd_geo_neighbor {
  ulong dist2;
  ulong stake;
};
typedef struct fd_geo_neighbor fd_geo_neighbor_t;

struct fd_geo_cluster {
  uint members_cnt;
  uint members[ FD_EPOCH_LEADERS_GEO_RUN_LENGTH ];
};
typedef struct fd_geo_cluster fd_geo_cluster_t;

#define SORT_NAME        sort_geo_neighbor
#define SORT_KEY_T       fd_geo_neighbor_t
#define SORT_BEFORE(a,b) ((a).dist2<(b).dist2)
#include "../../util/tmpl/fd_sort.c"

static void
fisher_yates_shuffle( fd_chacha_rng_t * rng,
                      uint *            array,
                      ulong             n ) {
  for( ulong i=n; i>1UL; i-- ) {
    ulong j        = fd_chacha_rng_ulong_roll( rng, i );
    uint  t        = array[ i-1UL ];
    array[ i-1UL ] = array[ j ];
    array[ j ]     = t;
  }
}

/* compute_smallest_radius returns the smallest squared distance r
   from the validator v, such that the validators at most r away from
   v make up at least FD_EPOCH_LEADERS_GEO_STAKE_FLOOR % of the total
   stake.

   neighbor is an array of the pre-computed distances and stakes of
   each validator from v.

   The algorithm is as such:
   - Sort the neighbours by distance
   - Sum the stake until we get to the stake floor */
static ulong
compute_smallest_radius( fd_geo_neighbor_t * neighbor,
                         ulong               cnt,
                         ulong               total ) {
  sort_geo_neighbor_inplace( neighbor, cnt );
  uint128 thresh = (uint128)total*FD_EPOCH_LEADERS_GEO_STAKE_FLOOR;
  ulong   acc    = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    acc += neighbor[ i ].stake;
    if( (uint128)acc*100UL>=thresh ) return neighbor[ i ].dist2;
  }
  FD_LOG_CRIT(( "unreachable" ));
}

/* can_join_cluster returns 1 if the given validator leader can join
   the given cluster. The leader can join if it is "close enough":
   the squared distance between the leader and the cluster isn't
   greater than the larger of the radii. I.e. the leader is within the
   cluster's radius or the cluster is within the leader's radius. */
static inline int
can_join_cluster( fd_vote_stake_weight_t const * stakes,
                  ulong const *                  radius,
                  ulong                          cluster,
                  ulong                          leader ) {
  return fd_validator_location_dist2(
    &stakes[ cluster ].location, &stakes[ leader ].location )<=
      fd_ulong_max( radius[ cluster ], radius[ leader ] );
}

static void
assign_to_clusters( uint *                         sched,
                    ulong                          sched_cnt,
                    fd_vote_stake_weight_t const * stakes,
                    ulong const *                  radius,
                    fd_geo_cluster_t *             clusters,
                    uint *                         open_clusters,
                    uint *                         eligible_clusters,
                    fd_chacha_rng_t *              rng ) {
  ulong open_clusters_cnt     = 0UL;
  ulong finalized_leaders_cnt = 0UL;

  /* Assign each leader in the schedule to a cluster, overwriting the
     final leader schedule as we go. */
  for( ulong i=0UL; i<sched_cnt; i++ ) {
    uint leader = sched[ i ];

    /* Find all the clusters that the leader can join. */
    ulong eligible_cnt = 0UL;
    for( ulong j=0UL; j<open_clusters_cnt; j++ ) {
      if( can_join_cluster( stakes, radius, open_clusters[ j ], leader ) ) {
        eligible_clusters[ eligible_cnt++ ] = (uint)j;
      }
    }

    /* Choose one of the eligible clusters for the leader to join.
       If there are none, start a new one. */
    ulong cluster_idx;
    if( eligible_cnt==0UL ) {
      clusters[ leader ].members_cnt       = 0U;
      cluster_idx                          = open_clusters_cnt;
      open_clusters[ open_clusters_cnt++ ] = leader;
    } else {
      cluster_idx = eligible_clusters[ fd_chacha_rng_ulong_roll( rng, eligible_cnt ) ];
    }
    fd_geo_cluster_t * cluster                 = clusters + open_clusters[ cluster_idx ];
    cluster->members[ cluster->members_cnt++ ] = leader;

    /* If the cluster is now full, shuffle its members and add it to
       the finalized leader schedule. */
    if( cluster->members_cnt==FD_EPOCH_LEADERS_GEO_RUN_LENGTH ) {
      fisher_yates_shuffle( rng, cluster->members, cluster->members_cnt );
      memcpy( sched+finalized_leaders_cnt, cluster->members, cluster->members_cnt*sizeof(uint) );
      finalized_leaders_cnt += cluster->members_cnt;
      open_clusters_cnt--;
      memmove( open_clusters+cluster_idx, open_clusters+cluster_idx+1UL, (open_clusters_cnt-cluster_idx)*sizeof(uint) );
    }
  }

  /* Add any leftover open clusters to the final leader schedule,
     shuffling them first. */
  fisher_yates_shuffle( rng, open_clusters, open_clusters_cnt );
  for( ulong j=0UL; j<open_clusters_cnt; j++ ) {
    fd_geo_cluster_t * cluster = clusters + open_clusters[ j ];
    fisher_yates_shuffle( rng, cluster->members, cluster->members_cnt );
    memcpy( sched+finalized_leaders_cnt, cluster->members, cluster->members_cnt*sizeof(uint) );
    finalized_leaders_cnt += cluster->members_cnt;
  }
}

/* geo_aware_reorder re-orders the given sched in-place, according to
   SIMD-0675 Geo-Aware Leader Schedule.
   - sched: the input leader schedule
   - sched_cnt: the number of validators in the leader schedule
   - stakes: metadata about each vote account, including their stake
             weight and validator location
   - stakes_cnt: the number of entries in the stakes
   - epoch: the epoch this leader schedule is computed for
   - scratch: scratch memory region used for intermediate computations */
static void
geo_aware_reorder( uint *                         sched,
                   ulong                          sched_cnt,
                   fd_vote_stake_weight_t const * stakes,
                   ulong                          stakes_cnt,
                   ulong                          epoch,
                   void *                         scratch ) {
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  /* radius[v] will hold the smallest radius for each validator v which
     contains FD_EPOCH_LEADERS_GEO_STAKE_FLOOR % of the total stake. */
  ulong *             radius            = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),             stakes_cnt*sizeof(ulong) );
  /* neighbor[ u ] will hold the squared distance from the validator
     whose smallest radius is being computed to validator u, and u's
     stake. The same memory is then reused in assign_to_clusters,
     so we size it for the larger of the two uses. */
  fd_geo_neighbor_t * neighbor          = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_geo_neighbor_t),
    stakes_cnt*fd_ulong_max( sizeof(fd_geo_neighbor_t), sizeof(fd_geo_cluster_t) ) );
  /* open_clusters and eligible_clusters are used in assign_to_clusters,
     we just reserve the memory here. */
  uint *              open_clusters     = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),              stakes_cnt*sizeof(uint)  );
  uint *              eligible_clusters = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),              stakes_cnt*sizeof(uint)  );
  FD_SCRATCH_ALLOC_FINI( l, 1UL );

  /* Sum up the total stake and sanity-check that all the validators
     have a valid location set. As geo_aware_leader_schedule can only
     be activated after enforce_validator_location_registration, all
     validators should have a valid location set. */
  ulong total = 0UL;
  for( ulong i=0UL; i<stakes_cnt; i++ ) {
    if( FD_UNLIKELY( !fd_validator_location_is_valid( &stakes[ i ].location ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( stakes[ i ].vote_key.uc, vote_b58 );
      FD_LOG_ERR(( "vote account %s has no valid validator location for epoch %lu", vote_b58, epoch ));
    }
    total += stakes[ i ].stake;
  }

  /* Compute the smallest radius around each validator that contains at
     least FD_EPOCH_LEADERS_GEO_STAKE_FLOOR % of the total stake,
     including the validator at the center. */
  for( ulong v=0UL; v<stakes_cnt; v++ ) {
    for( ulong u=0UL; u<stakes_cnt; u++ ) {
      neighbor[ u ].dist2 = fd_validator_location_dist2( &stakes[ v ].location, &stakes[ u ].location );
      neighbor[ u ].stake = stakes[ u ].stake;
    }
    radius[ v ] = compute_smallest_radius( neighbor, stakes_cnt, total );
  }

  /* Use a different rng stream for the geo-aware re-ordering so that
     it is independent of the order of the original schedule's PRNG
     scheme, as per SIMD-0675.

     TODO: is this really necessary? */
  static char const tag[] = "geo-aware-leader-schedule";
  uchar             key[ 32 ];
  fd_sha256_t       sha[1];
  fd_sha256_init  ( sha );
  fd_sha256_append( sha, tag,    sizeof(tag)-1UL );
  fd_sha256_append( sha, &epoch, sizeof(ulong)   );
  fd_sha256_fini  ( sha, key );

  fd_chacha_rng_t _rng[1];
  fd_chacha_rng_t * rng = fd_chacha_rng_join( fd_chacha_rng_new( _rng, FD_CHACHA_RNG_MODE_MOD ) );
  fd_chacha_rng_init( rng, key, FD_CHACHA_RNG_ALGO_CHACHA20 );

  /* Group the validators into clusters */
  /* We re-purpose the neighbor memory region used for the radius
     calculation, because it is not used anymore after the radius
     calculations. */
  fd_geo_cluster_t * clusters = (fd_geo_cluster_t *)fd_type_pun( neighbor );
  assign_to_clusters( sched, sched_cnt, stakes, radius, clusters, open_clusters, eligible_clusters, rng );

  fd_chacha_rng_delete( fd_chacha_rng_leave( rng ) );
}

int
fd_epoch_leaders_use_geo_aware( fd_features_t const *       features,
                                fd_epoch_schedule_t const * epoch_schedule,
                                ulong                       schedule_epoch ) {
  ulong activation_slot = features->geo_aware_leader_schedule;
  if( activation_slot==FD_FEATURE_DISABLED ) return 0;
  return schedule_epoch>fd_slot_to_epoch( epoch_schedule, activation_slot, NULL );
}

void *
fd_epoch_leaders_new( void  *                  shmem,
                      ulong                    epoch,
                      ulong                    slot0,
                      ulong                    slot_cnt,
                      ulong                    pub_cnt,
                      fd_vote_stake_weight_t * stakes,
                      int                      geo_aware ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  ulong laddr = (ulong)shmem;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( laddr, FD_EPOCH_LEADERS_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !pub_cnt ) ) {
    FD_LOG_WARNING(( "pub_cnt is 0" ));
    return NULL;
  }

  if( FD_UNLIKELY( slot_cnt>MAX_SLOTS_PER_EPOCH ) ) {
    FD_LOG_ERR(( "epoch %lu has %lu slots, but the maximum supported is %lu", epoch, slot_cnt, MAX_SLOTS_PER_EPOCH ));
  }

  /* The eventual layout that we want is:
     struct                   (align=8, footprint=64)
     list of indices          (align=4, footprint=4*ceil(slot_cnt/4))
     (up to 28 bytes of padding to align to 32)
     vote addr per rotation   (align=32, footprint=32*ceil(slot_cnt/4))
     (up to 32 bytes of padding to align to 64)
     list of pubkeys          (align=32, footprint=32*pub_cnt)
     (possibly 32 bytes of padding to align to 64)

     The memory for the list of pubkeys is used three times, in this
     order:
     1. by wsample, to generate the list of indices.  The region is
        sized for the larger of 32*pub_cnt and wsample's footprint.
     2. by the geo-aware re-ordering, as scratch space: at most 32
        bytes per pubkey.
     3. for the pubkeys themselves, which we only copy in once both
        are done.

     There's a lot of type punning going on here, so watch out. */

  ulong sched_cnt = (slot_cnt+FD_EPOCH_SLOTS_PER_ROTATION-1UL)/FD_EPOCH_SLOTS_PER_ROTATION;

  fd_epoch_leaders_t * leaders = (fd_epoch_leaders_t *)fd_type_pun( (void *)laddr );
  laddr += sizeof(fd_epoch_leaders_t);

  laddr  = fd_ulong_align_up( laddr, alignof(uint) );
  uint * sched     = (uint *)fd_type_pun( (void *)laddr );
  laddr += sizeof(uint)*sched_cnt;

  laddr  = fd_ulong_align_up( laddr, 32UL );
  fd_pubkey_t * vote_addr = (fd_pubkey_t *)fd_type_pun( (void *)laddr );
  laddr += 32UL*sched_cnt;

  laddr  = fd_ulong_align_up( laddr, fd_ulong_max( sizeof(fd_pubkey_t), FD_WSAMPLE_ALIGN ) );
  /* These two alias, like a union.  We don't need pubkeys until we're
     done with wsample. */
  void        * wsample_mem = (void        *)fd_type_pun( (void *)laddr );
  fd_pubkey_t * pubkeys     = (fd_pubkey_t *)fd_type_pun( (void *)laddr );

  FD_STATIC_ASSERT( sizeof(fd_geo_neighbor_t)<=sizeof(fd_geo_cluster_t),                          geo_scratch );
  FD_STATIC_ASSERT( sizeof(ulong)+sizeof(fd_geo_cluster_t)+2UL*sizeof(uint)<=sizeof(fd_pubkey_t), geo_scratch );

  FD_TEST( laddr+fd_wsample_footprint( pub_cnt, 0 )<=(ulong)wsample_mem + fd_epoch_leaders_footprint( pub_cnt, slot_cnt ) );

  /* Create and seed ChaCha20Rng */
  fd_chacha_rng_t _rng[1];
  fd_chacha_rng_t * rng = fd_chacha_rng_join( fd_chacha_rng_new( _rng, FD_CHACHA_RNG_MODE_MOD ) );
  uchar key[ 32 ] = {0};
  memcpy( key, &epoch, sizeof(ulong) );
  fd_chacha_rng_init( rng, key, FD_CHACHA_RNG_ALGO_CHACHA20 );

  void * _wsample = fd_wsample_new_init( wsample_mem, rng, pub_cnt, 0, FD_WSAMPLE_HINT_POWERLAW_NOREMOVE );
  for( ulong i=0UL; i<pub_cnt; i++ ) _wsample = fd_wsample_new_add( _wsample, stakes[i].stake );
  fd_wsample_t * wsample = fd_wsample_join( fd_wsample_new_fini( _wsample, 0UL ) );
  FD_TEST( wsample );

  /* Generate samples.  We need uints, so we can't use sample_many. */
  for( ulong i=0UL; i<sched_cnt; i++ ) sched[ i ] = (uint)fd_wsample_sample( wsample );

  /* Clean up the wsample object */
  fd_wsample_delete( fd_wsample_leave( wsample ) );
  fd_chacha_rng_delete( fd_chacha_rng_leave( rng ) );

  /* Apply the geo-aware re-ordering */
  if( geo_aware ) {
    geo_aware_reorder( sched, sched_cnt, stakes, pub_cnt, epoch, wsample_mem );
  }

  /* Now we can use the space for the pubkeys */
  for( ulong i=0UL; i<pub_cnt; i++ ) memcpy( pubkeys+i, &stakes[ i ].id_key, 32UL );

  /* record the leader vote address per rotation */
  for( ulong i=0UL; i<sched_cnt; i++ ) memcpy( vote_addr+i, &stakes[ sched[ i ] ].vote_key, 32UL );

  /* Construct the final struct */
  leaders->epoch     = epoch;
  leaders->slot0     = slot0;
  leaders->slot_cnt  = slot_cnt;
  leaders->pub       = pubkeys;
  leaders->pub_cnt   = pub_cnt;
  leaders->sched     = sched;
  leaders->sched_cnt = sched_cnt;
  leaders->vote_addr = vote_addr;

  return (void *)shmem;
}

fd_epoch_leaders_t *
fd_epoch_leaders_join( void * shleaders ) {
  return (fd_epoch_leaders_t *)shleaders;
}

void *
fd_epoch_leaders_leave( fd_epoch_leaders_t * leaders ) {
  return (void *)leaders;
}

void *
fd_epoch_leaders_delete( void * shleaders ) {
  return shleaders;
}
