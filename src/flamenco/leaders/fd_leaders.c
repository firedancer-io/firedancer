#include "fd_leaders.h"
#include "../../ballet/chacha20/fd_chacha20rng.h"
#include "../../ballet/wsample/fd_wsample.h"

ulong
fd_epoch_leaders_align( void ) {
  return FD_EPOCH_LEADERS_ALIGN;
}

FD_FN_CONST ulong
fd_epoch_leaders_footprint( ulong pub_cnt,
                            ulong slot_cnt ) {
  if( FD_UNLIKELY( ( pub_cnt  ==     0UL )
                 | ( pub_cnt   >UINT_MAX )
                 | ( slot_cnt==     0UL ) ) )
    return 0UL;
  return FD_EPOCH_LEADERS_FOOTPRINT( pub_cnt, slot_cnt );
}

void *
fd_epoch_leaders_new( void                    * shmem,
                      ulong                     epoch,
                      ulong                     slot0,
                      ulong                     slot_cnt,
                      ulong                     pub_cnt,
                      fd_stake_weight_t const * stakes ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  ulong laddr = (ulong)shmem;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( laddr, FD_EPOCH_LEADERS_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  /* The eventual layout that we want is:
     struct           (align=8, footprint=56)
     list of indices  (align=4, footprint=4*ceil(slot_cnt/4))
     (up to 56 bytes of padding to align to 64)
     list of pubkeys  (align=32, footprint=32*pub_cnt)
     (possibly 32 bytes of padding to align to 64)

     but in order to generate the list of indices, we want to use
     wsample, which needs some memory to work.  Turns out that we
     probably have all the memory we need right here in shmem, we just
     need to be careful about how we use it; for most of the values of
     pub_cnt we care about, wsample's footprint is less than 32*pub_cnt.

     This works out because we can delay copying the pubkeys until we're
     done with the wsample object.  There's a lot of type punning going
     on here, so watch out. */
  ulong sched_cnt = (slot_cnt+FD_EPOCH_SLOTS_PER_ROTATION-1UL)/FD_EPOCH_SLOTS_PER_ROTATION;

  fd_epoch_leaders_t * leaders = (fd_epoch_leaders_t *)fd_type_pun( (void *)laddr );
  laddr += sizeof(fd_epoch_leaders_t);

  laddr  = fd_ulong_align_up( laddr, alignof(uint) );
  uint * sched     = (uint *)fd_type_pun( (void *)laddr );
  laddr += sizeof(uint)*sched_cnt;

  laddr  = fd_ulong_align_up( laddr, fd_ulong_max( sizeof(fd_pubkey_t), FD_WSAMPLE_ALIGN ) );
  /* These two alias, like a union.  We don't need pubkeys until we're
     done with wsample. */
  void        * wsample_mem = (void        *)fd_type_pun( (void *)laddr );
  fd_pubkey_t * pubkeys     = (fd_pubkey_t *)fd_type_pun( (void *)laddr );

  FD_TEST( laddr+fd_wsample_footprint( pub_cnt, 0 )<=(ulong)wsample_mem + fd_epoch_leaders_footprint( pub_cnt, slot_cnt ) );

  /* Create and seed ChaCha20Rng */
  fd_chacha20rng_t _rng[1];
  fd_chacha20rng_t * rng = fd_chacha20rng_join( fd_chacha20rng_new( _rng, FD_CHACHA20RNG_MODE_MOD ) );
  uchar key[ 32 ] = {0};
  memcpy( key, &epoch, sizeof(ulong) );
  fd_chacha20rng_init( rng, key );

  void * _wsample = fd_wsample_new_init( wsample_mem, rng, pub_cnt, 0, FD_WSAMPLE_HINT_POWERLAW_NOREMOVE );
  for( ulong i=0UL; i<pub_cnt; i++ ) _wsample = fd_wsample_new_add( _wsample, stakes[i].stake );
  fd_wsample_t * wsample = fd_wsample_join( fd_wsample_new_fini( _wsample ) );

  /* Generate samples.  We need uints, so we can't use sample_many. */
  for( ulong i=0UL; i<sched_cnt; i++ ) sched[ i ] = (uint)fd_wsample_sample( wsample );

  /* Clean up the wsample object */
  fd_wsample_delete( fd_wsample_leave( wsample ) );
  fd_chacha20rng_delete( fd_chacha20rng_leave( rng ) );

  /* Now we can use the space for the pubkeys */
  for( ulong i=0UL; i<pub_cnt; i++ ) memcpy( pubkeys+i, &stakes[ i ].key, 32UL );

  /* Construct the final struct */
  leaders->epoch     = epoch;
  leaders->slot0     = slot0;
  leaders->slot_cnt  = slot_cnt;
  leaders->pub       = pubkeys;
  leaders->pub_cnt   = pub_cnt;
  leaders->sched     = sched;
  leaders->sched_cnt = sched_cnt;

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

/* fd_epoch_leaders_weighted_index performs binary search to resolve a
   sample uniformly distributed in [0,accum_stake) to a public key
   while preserving stake weight probability distribution. */

static ulong
fd_epoch_leaders_weighted_index( ulong const * scratch,
                                 ulong         stakes_cnt,
                                 ulong         roll ) {
  ulong lo = 0UL;
  ulong hi = stakes_cnt;
  while( lo<=hi ) {
    ulong idx = lo+(hi-lo)/2UL;
    if( scratch[idx]<=roll && roll<scratch[idx+1] )
      return idx;
    if( roll<scratch[idx] )
      hi = idx-1UL;
    else
      lo = idx+1UL;
  }
  __builtin_unreachable();
}

void
fd_epoch_leaders_derive( fd_epoch_leaders_t *      leaders,
                         fd_stake_weight_t const * stakes,
                         ulong                     epoch ) {

  fd_scratch_push();

  ulong pub_cnt   = leaders->pub_cnt;
  ulong sched_cnt = leaders->sched_cnt;

  /* Copy public keys */
  for( ulong i=0UL; i<pub_cnt; i++ )
    memcpy( &leaders->pub[ i ], &stakes[ i ].key, 32UL );

  /* Create map of cumulative stake index */
  ulong * scratch = fd_scratch_alloc( alignof(ulong), (pub_cnt+1UL)*sizeof(ulong) );
  ulong accum_stake = 0UL;
  for( ulong i=0UL; i<pub_cnt; i++ ) {
    scratch[ i ] = accum_stake;
    accum_stake += stakes[ i ].stake;
  }
  scratch[ pub_cnt ] = accum_stake;

  FD_LOG_DEBUG(( "accum_stake=%016lx", accum_stake ));

  /* Create and seed ChaCha20Rng */
  fd_chacha20rng_t _rng[1];
  fd_chacha20rng_t * rng = fd_chacha20rng_join( fd_chacha20rng_new( _rng, FD_CHACHA20RNG_MODE_MOD ) );
  uchar key[ 32 ] = {0};
  memcpy( key, &epoch, sizeof(ulong) );
  fd_chacha20rng_init( rng, key );

  /* Sample leader schedule */
  for( ulong i=0UL; i<sched_cnt; i++ ) {
    ulong roll = fd_chacha20rng_ulong_roll( rng, accum_stake );
    ulong idx  = fd_epoch_leaders_weighted_index( scratch, pub_cnt, roll );
    leaders->sched[ i ] = (uint)idx;
  }

  /* Clean up */
  fd_chacha20rng_delete( fd_chacha20rng_leave( rng ) );

  fd_scratch_pop();
}
