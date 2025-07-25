#include "fd_multi_epoch_leaders.h"

void *
fd_multi_epoch_leaders_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_multi_epoch_leaders_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_multi_epoch_leaders_t * leaders = (fd_multi_epoch_leaders_t *)shmem;
  leaders->scratch->vote_keyed_lsched = 0;

  /* Initialize all epochs to satisfy invariants */
  fd_vote_stake_weight_t dummy_stakes[ 1 ] = {{ .vote_key = {{0}}, .id_key = {{0}}, .stake = 1UL }};
  for( ulong i=0UL; i<MULTI_EPOCH_LEADERS_EPOCH_CNT; i++ ) {
    leaders->lsched[i] = fd_epoch_leaders_join( fd_epoch_leaders_new( leaders->_lsched[i], i, 0UL, 1UL, 1UL, dummy_stakes, 0UL, leaders->scratch->vote_keyed_lsched ) );
    FD_TEST( leaders->lsched[i] );
    leaders->init_done[i] = 0;
  }

  return shmem;
}

fd_multi_epoch_leaders_t *
fd_multi_epoch_leaders_join( void * shleaders ) { return shleaders; }

void *
fd_multi_epoch_leaders_leave( fd_multi_epoch_leaders_t * mleaders ) { return mleaders; }

void *
fd_multi_epoch_leaders_delete( void * shleaders ) { return shleaders; }

fd_epoch_leaders_t const *
fd_multi_epoch_leaders_get_lsched_for_epoch( fd_multi_epoch_leaders_t const * mleaders,
                                             ulong                            epoch ) {
  fd_epoch_leaders_t const * even_lsched = fd_ptr_if( mleaders->init_done[0] & !!(mleaders->lsched[0]->epoch==epoch), mleaders->lsched[0], NULL );
  fd_epoch_leaders_t const * odd_lsched  = fd_ptr_if( mleaders->init_done[1] & !!(mleaders->lsched[1]->epoch==epoch), mleaders->lsched[1], NULL );
  return fd_ptr_if( !!even_lsched, even_lsched, odd_lsched );
}

static inline ulong
fd_multi_epoch_leaders_get_epoch_idx( fd_multi_epoch_leaders_t const * mleaders,
                                      ulong                            slot ) {
  fd_epoch_leaders_t const * even_lsched = mleaders->lsched[0];
  fd_epoch_leaders_t const * odd_lsched  = mleaders->lsched[1];

  ulong even_match = fd_ulong_if( mleaders->init_done[0] & !!(even_lsched->slot0<=slot) & !!(slot<even_lsched->slot0+even_lsched->slot_cnt), 0UL, ULONG_MAX );
  ulong odd_match  = fd_ulong_if( mleaders->init_done[1] & !!(odd_lsched->slot0<=slot) & !!(slot<odd_lsched->slot0+odd_lsched->slot_cnt), 1UL, ULONG_MAX );

  return fd_ulong_if( even_match!=ULONG_MAX, even_match, odd_match );
}

fd_epoch_leaders_t const *
fd_multi_epoch_leaders_get_lsched_for_slot( fd_multi_epoch_leaders_t const *  mleaders,
                                             ulong                            slot ) {
  const ulong epoch_idx = fd_multi_epoch_leaders_get_epoch_idx( mleaders, slot );
  if( FD_UNLIKELY( epoch_idx==ULONG_MAX ) ) return NULL;
  return mleaders->lsched[epoch_idx];
}

ulong
fd_multi_epoch_leaders_get_next_slot( fd_multi_epoch_leaders_t const * mleaders,
                                      ulong                            start_slot,
                                      fd_pubkey_t              const * leader_q ) {

  /* Find epoch containing start_slot */
  ulong epoch_idx = fd_multi_epoch_leaders_get_epoch_idx( mleaders, start_slot );
  if( FD_UNLIKELY( epoch_idx==ULONG_MAX ) ) return ULONG_MAX;

  /* Start at epoch_idx and seek next slot (across epochs)  */
  for( ulong i=0; i<MULTI_EPOCH_LEADERS_EPOCH_CNT; i++ ) {
    ulong epoch_i = (epoch_idx + i) % MULTI_EPOCH_LEADERS_EPOCH_CNT;

    fd_epoch_leaders_t const * epoch_lsched  = mleaders->lsched[ epoch_i ];
    ulong                      slot0         = epoch_lsched->slot0;
    ulong                      slot_end      = slot0 + epoch_lsched->slot_cnt;

    /* skip older epochs */
    if( FD_UNLIKELY( !mleaders->init_done[epoch_i] ) ) continue;

    ulong start_slot_it = fd_ulong_max( start_slot, slot0 );
    for( ulong slot=start_slot_it; slot<slot_end; slot++ ) {
      fd_pubkey_t const * leader = fd_epoch_leaders_get( epoch_lsched, slot );
      if( FD_UNLIKELY( !memcmp( leader->key, leader_q->key, 32UL ) ) ) return slot;
    }
  }

  return ULONG_MAX;
}

void
fd_multi_epoch_leaders_stake_msg_init( fd_multi_epoch_leaders_t    * mleaders,
                                       fd_stake_weight_msg_t const * msg ) {
  if( FD_UNLIKELY( msg->staked_cnt > MAX_STAKED_LEADERS ) )
    FD_LOG_ERR(( "Multi-epoch leaders received a malformed update with %lu stakes in it,"
                 " but the maximum allowed is %lu", msg->staked_cnt, MAX_STAKED_LEADERS ));

  mleaders->scratch->epoch          = msg->epoch;
  mleaders->scratch->start_slot     = msg->start_slot;
  mleaders->scratch->slot_cnt       = msg->slot_cnt;
  mleaders->scratch->staked_cnt     = msg->staked_cnt;
  mleaders->scratch->excluded_stake = msg->excluded_stake;
  mleaders->scratch->vote_keyed_lsched = msg->vote_keyed_lsched;

  fd_memcpy( mleaders->vote_stake_weight, msg->weights, msg->staked_cnt*sizeof(fd_vote_stake_weight_t) );
}

void
fd_multi_epoch_leaders_stake_msg_fini( fd_multi_epoch_leaders_t * mleaders ) {
  const ulong epoch          = mleaders->scratch->epoch;
  const ulong slot0          = mleaders->scratch->start_slot;
  const ulong slot_cnt       = mleaders->scratch->slot_cnt;
  const ulong pub_cnt        = mleaders->scratch->staked_cnt;
  const ulong excluded_stake = mleaders->scratch->excluded_stake;
  const ulong vote_keyed_lsched = mleaders->scratch->vote_keyed_lsched;
  const ulong epoch_idx      = epoch % MULTI_EPOCH_LEADERS_EPOCH_CNT;

  fd_vote_stake_weight_t * stakes = mleaders->vote_stake_weight;

  /* Clear old data */
  fd_epoch_leaders_delete( fd_epoch_leaders_leave( mleaders->lsched[epoch_idx] ) );

  /* Populate new lsched */
  uchar *  lsched_mem        = mleaders->_lsched[epoch_idx];
  mleaders->lsched[epoch_idx] = fd_epoch_leaders_join( fd_epoch_leaders_new(
                                    lsched_mem, epoch, slot0, slot_cnt,
                                    pub_cnt, stakes, excluded_stake, vote_keyed_lsched ) );
  mleaders->init_done[epoch_idx] = 1;
}

fd_pubkey_t const *
fd_multi_epoch_leaders_get_leader_for_slot( fd_multi_epoch_leaders_t const * mleaders,
                                            ulong                            slot ) {
  const ulong epoch_idx = fd_multi_epoch_leaders_get_epoch_idx( mleaders, slot );
  if( FD_UNLIKELY( epoch_idx==ULONG_MAX ) ) return NULL;
  return fd_epoch_leaders_get( mleaders->lsched[epoch_idx], slot );
}

fd_multi_epoch_leaders_lsched_sorted_t
fd_multi_epoch_leaders_get_sorted_lscheds( fd_multi_epoch_leaders_t const * mleaders ) {
  fd_multi_epoch_leaders_lsched_sorted_t ret = { .lscheds = { NULL, NULL } };
  fd_epoch_leaders_t * even_option = fd_ptr_if( mleaders->init_done[0], mleaders->lsched[0], NULL );
  fd_epoch_leaders_t * odd_option  = fd_ptr_if( mleaders->init_done[1], mleaders->lsched[1], NULL );

  /* Sort by epoch if both non-null, null comes first */
  if( even_option && odd_option ) {
    ret.lscheds[0] = fd_ptr_if( even_option->epoch < odd_option->epoch, even_option, odd_option );
    ret.lscheds[1] = fd_ptr_if( even_option->epoch < odd_option->epoch, odd_option, even_option );
  } else {
    /* if one non-null, this will pick it up. Else, both null and this no-ops */
    ret.lscheds[0] = fd_ptr_if( !!even_option, even_option, odd_option );
  }

  return ret;
}
