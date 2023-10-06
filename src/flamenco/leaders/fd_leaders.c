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
  laddr += FD_LAYOUT_INIT;

  /* The eventual layout that we want is:
      [0,            64)                               struct
      [64,           64+32*pub_cnt)                    list of pubkeys
      [64+32*pubcnt, 64+32*pubcnt+4*ceil(slot_cnt/4) ) list of indices

     but in order to generate the list of indices, we want to use
     wsample, which needs some memory to work.  Turns out that we have
     all the memory we need right here in shmem, we just need to be
     careful about how we use it.
     In order to construct a wsample object, we need a footprint of
     64+32*pub_cnt bytes.  The footprint fits nicely in the space we'll use
     for the struct and the list of pubkeys.

     This works out because we can delay copying the pubkeys until we're
     done with the wsample object.  There's a lot of type punning going
     on here, so watch out. */

  laddr = (ulong)shmem;
  laddr  = fd_ulong_align_up( laddr, fd_wsample_align() );
  void * wsample_mem = (void *)fd_type_pun( (void *)laddr );
  laddr += fd_wsample_footprint( pub_cnt, 0 );

  FD_TEST( laddr-(ulong)shmem <= fd_epoch_leaders_footprint( pub_cnt, slot_cnt ) );

  /* Create and seed ChaCha20Rng */
  fd_chacha20rng_t _rng[1];
  fd_chacha20rng_t * rng = fd_chacha20rng_join( fd_chacha20rng_new( _rng, FD_CHACHA20RNG_MODE_MOD ) );
  uchar key[ 32 ] = {0};
  memcpy( key, &epoch, sizeof(ulong) );
  fd_chacha20rng_init( rng, key );

  void * _wsample = fd_wsample_new_init( wsample_mem, rng, pub_cnt, 0, FD_WSAMPLE_HINT_POWERLAW_NOREMOVE );
  for( ulong i=0UL; i<pub_cnt; i++ ) _wsample = fd_wsample_new_add( _wsample, stakes[i].stake );
  fd_wsample_t * wsample = fd_wsample_join( fd_wsample_new_fini( _wsample ) );

  /* Compute the eventual addresses */
  laddr = (ulong)shmem;
  laddr  = fd_ulong_align_up( laddr, alignof(fd_epoch_leaders_t) );
  fd_epoch_leaders_t * leaders = (fd_epoch_leaders_t *)fd_type_pun( (void *)laddr );
  laddr += sizeof(fd_epoch_leaders_t);

  laddr  = fd_ulong_align_up( laddr, sizeof(fd_pubkey_t) );
  fd_pubkey_t * pubkeys     = (fd_pubkey_t *)fd_type_pun( (void *)laddr );
  laddr += pub_cnt*sizeof(fd_pubkey_t);

  laddr  = fd_ulong_align_up( laddr, alignof(uint) );
  uint * sched     = (uint *)fd_type_pun( (void *)laddr );
  ulong sched_cnt = (slot_cnt+FD_EPOCH_SLOTS_PER_ROTATION-1UL)/FD_EPOCH_SLOTS_PER_ROTATION;

  /* Generate samples.  We need uints, so we can't use sample_many. */
  for( ulong i=0UL; i<sched_cnt; i++ ) sched[ i ] = (uint)fd_wsample_sample( wsample );

  /* Clean up the wsample object */
  fd_wsample_delete( fd_wsample_leave( wsample ) );
  fd_chacha20rng_delete( fd_chacha20rng_leave( rng ) );

  /* Now we can use the space for the struct and pubkeys */
  /* Copy all the pubkeys */
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
