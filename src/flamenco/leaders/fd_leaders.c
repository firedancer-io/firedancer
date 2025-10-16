#include "fd_leaders.h"
#include "../../ballet/chacha/fd_chacha_rng.h"
#include "../../ballet/wsample/fd_wsample.h"

#define SORT_NAME sort_vote_weights_by_stake_id
#define SORT_KEY_T fd_vote_stake_weight_t
#define SORT_BEFORE(a,b) ((a).stake > (b).stake ? 1 : ((a).stake < (b).stake ? 0 : memcmp( (a).id_key.uc, (b).id_key.uc, 32UL )>0))
#include "../../util/tmpl/fd_sort.c"

#define SORT_NAME sort_vote_weights_by_id
#define SORT_KEY_T fd_vote_stake_weight_t
#define SORT_BEFORE(a,b) (memcmp( (a).id_key.uc, (b).id_key.uc, 32UL )>0)
#include "../../util/tmpl/fd_sort.c"

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

void *
fd_epoch_leaders_new( void  *                  shmem,
                      ulong                    epoch,
                      ulong                    slot0,
                      ulong                    slot_cnt,
                      ulong                    pub_cnt,
                      fd_vote_stake_weight_t * stakes,
                      ulong                    excluded_stake,
                      ulong                    vote_keyed_lsched ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  ulong laddr = (ulong)shmem;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( laddr, FD_EPOCH_LEADERS_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  /* This code can be be removed when enable_vote_address_leader_schedule is
     enabled and cleared.
     And, as a consequence, stakes can be made const. */
  if( FD_LIKELY( vote_keyed_lsched==0 ) ) {
    /* Sort [(vote, id, stake)] by id, so we can dedup */
    sort_vote_weights_by_id_inplace( stakes, pub_cnt );

    /* Dedup entries, aggregating stake */
    ulong j=0UL;
    for( ulong i=1UL; i<pub_cnt; i++ ) {
      fd_pubkey_t * pre = &stakes[ j ].id_key;
      fd_pubkey_t * cur = &stakes[ i ].id_key;
      if( 0==memcmp( pre, cur, sizeof(fd_pubkey_t) ) ) {
        stakes[ j ].stake += stakes[ i ].stake;
      } else {
        ++j;
        stakes[ j ].stake = stakes[ i ].stake;
        memcpy( stakes[ j ].id_key.uc, stakes[ i ].id_key.uc, sizeof(fd_pubkey_t) );
        /* vote doesn't matter */
      }
    }
    pub_cnt = fd_ulong_min( pub_cnt, j+1 );

    /* Sort [(vote, id, stake)] by stake then id, as expected */
    sort_vote_weights_by_stake_id_inplace( stakes, pub_cnt );
  }

  /* The eventual layout that we want is:
     struct                   (align=8, footprint=48)
     list of indices          (align=4, footprint=4*ceil(slot_cnt/4))
     (up to 60 bytes of padding to align to 64)
     list of pubkeys          (align=32, footprint=32*pub_cnt)
     the indeterminate pubkey (align=32, footprint=32)
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
  fd_chacha_rng_t _rng[1];
  fd_chacha_rng_t * rng = fd_chacha_rng_join( fd_chacha_rng_new( _rng, FD_CHACHA_RNG_MODE_MOD ) );
  uchar key[ 32 ] = {0};
  memcpy( key, &epoch, sizeof(ulong) );
  fd_chacha20_rng_init( rng, key );

  void * _wsample = fd_wsample_new_init( wsample_mem, rng, pub_cnt, 0, FD_WSAMPLE_HINT_POWERLAW_NOREMOVE );
  for( ulong i=0UL; i<pub_cnt; i++ ) _wsample = fd_wsample_new_add( _wsample, stakes[i].stake );
  fd_wsample_t * wsample = fd_wsample_join( fd_wsample_new_fini( _wsample, excluded_stake ) );

  /* Generate samples.  We need uints, so we can't use sample_many.  Map
     any FD_WSAMPLE_INDETERMINATE values to pub_cnt. */
  for( ulong i=0UL; i<sched_cnt; i++ ) sched[ i ] = (uint)fd_ulong_min( fd_wsample_sample( wsample ), pub_cnt );

  /* Clean up the wsample object */
  fd_wsample_delete( fd_wsample_leave( wsample ) );
  fd_chacha_rng_delete( fd_chacha_rng_leave( rng ) );

  /* Now we can use the space for the pubkeys */
  for( ulong i=0UL; i<pub_cnt; i++ ) memcpy( pubkeys+i, &stakes[ i ].id_key, 32UL );

  /* copy indeterminate leader to the last spot */
  static const uchar fd_indeterminate_leader[32] = { FD_INDETERMINATE_LEADER };
  memcpy( pubkeys+pub_cnt, fd_indeterminate_leader, 32UL );

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
