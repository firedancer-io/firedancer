#include "fd_multi_epoch_leaders.h"
#include "../../discof/replay/fd_exec.h"

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

  /* Initialize all epochs to satisfy invariants */
  fd_stake_weight_t dummy_stakes[ 1 ] = {{ .key = {{0}}, .stake = 1UL }};
  for( ulong i = 0; i < MULTI_EPOCH_LEADERS_EPOCH_CNT; i++ ) {
    leaders->lsched[i] = fd_epoch_leaders_join( fd_epoch_leaders_new( leaders->_lsched[i], i, 0UL, 1UL, 1UL, dummy_stakes, 0UL ) );
    FD_TEST( leaders->lsched[i] );
    leaders->init_done[i] = 0;
  }

  return shmem;
}

fd_multi_epoch_leaders_t *
fd_multi_epoch_leaders_join( void * shleaders ) { return shleaders; }

void *
fd_multi_epoch_leaders_leave( fd_multi_epoch_leaders_t * leaders ) { return leaders; }

void *
fd_multi_epoch_leaders_delete( void * shleaders ) { return shleaders; }

fd_epoch_leaders_t const *
fd_multi_epoch_leaders_get_lsched_for_epoch( fd_multi_epoch_leaders_t const * mleaders,
                                             ulong                            epoch ) {
  fd_epoch_leaders_t const * even_lsched = fd_ptr_if( mleaders->init_done[0] && mleaders->lsched[0]->epoch==epoch, mleaders->lsched[0], NULL );
  fd_epoch_leaders_t const * odd_lsched  = fd_ptr_if( mleaders->init_done[1] && mleaders->lsched[1]->epoch==epoch, mleaders->lsched[1], NULL );
  return fd_ptr_if( !!even_lsched, even_lsched, odd_lsched );
}

static inline ulong
fd_multi_epoch_leaders_get_epoch_idx( fd_multi_epoch_leaders_t const * leaders,
                                      ulong                            slot ) {
  fd_epoch_leaders_t const * even_lsched = leaders->lsched[0];
  fd_epoch_leaders_t const * odd_lsched  = leaders->lsched[1];

  ulong even_match = fd_ulong_if( even_lsched->slot0<=slot && slot<even_lsched->slot0+even_lsched->slot_cnt, 0UL, ULONG_MAX );
  ulong odd_match  = fd_ulong_if( odd_lsched->slot0<=slot && slot<odd_lsched->slot0+odd_lsched->slot_cnt, 1UL, ULONG_MAX );

  return fd_ulong_if( even_match!=ULONG_MAX, even_match, odd_match );
}

fd_epoch_leaders_t const *
fd_multi_epoch_leaders_get_lsched_for_slot( fd_multi_epoch_leaders_t const * mleaders,
                                             ulong                            slot ) {
  const ulong epoch_idx = fd_multi_epoch_leaders_get_epoch_idx( mleaders, slot );
  if( FD_UNLIKELY( epoch_idx == ULONG_MAX ) ) return NULL;
  return mleaders->lsched[epoch_idx];
}

ulong
fd_multi_epoch_leaders_get_next_slot( fd_multi_epoch_leaders_t const * leaders,
                                        ulong                          start_slot,
                                        fd_pubkey_t const *            leader_q ) {

  /* Find epoch containing start_slot */
  ulong epoch_idx = fd_multi_epoch_leaders_get_epoch_idx( leaders, start_slot );
  if( FD_UNLIKELY( epoch_idx == ULONG_MAX ) ) return ULONG_MAX;

  /* Find the leader in the epoch */
  fd_epoch_leaders_t const * epoch_lsched = leaders->lsched[ epoch_idx ];
  ulong                      slot0        = epoch_lsched->slot0;
  ulong                      slot_end     = slot0 + epoch_lsched->slot_cnt;

  for( ulong slot = start_slot; slot < slot_end; slot++ ) {
    fd_pubkey_t const * leader = fd_epoch_leaders_get( epoch_lsched, slot );
    if( FD_UNLIKELY( !memcmp( leader->key, leader_q->key, 32UL ) ) ) return slot;
  }

  return ULONG_MAX;
}

void
fd_multi_epoch_leaders_stake_msg_init( fd_multi_epoch_leaders_t * leaders,
                                       uchar const *              new_message ) {
  fd_stake_weight_msg_t const * hdr = fd_type_pun_const( new_message );

  if( FD_UNLIKELY( hdr->staked_cnt > MAX_STAKED_LEADERS ) )
    FD_LOG_ERR(( "Multi-epoch leaders received a malformed update with %lu stakes in it,"
                 " but the maximum allowed is %lu", hdr->staked_cnt, MAX_STAKED_LEADERS ));

  leaders->scratch->epoch          = hdr->epoch;
  leaders->scratch->start_slot     = hdr->start_slot;
  leaders->scratch->slot_cnt       = hdr->slot_cnt;
  leaders->scratch->staked_cnt     = hdr->staked_cnt;
  leaders->scratch->excluded_stake = hdr->excluded_stake;

  fd_memcpy( leaders->stake_weight, hdr+1UL, sizeof(fd_stake_weight_t)*hdr->staked_cnt );
}

void
fd_multi_epoch_leaders_stake_msg_fini( fd_multi_epoch_leaders_t * leaders ) {
  const ulong epoch          = leaders->scratch->epoch;
  const ulong slot0          = leaders->scratch->start_slot;
  const ulong slot_cnt       = leaders->scratch->slot_cnt;
  const ulong pub_cnt        = leaders->scratch->staked_cnt;
  const ulong excluded_stake = leaders->scratch->excluded_stake;
  const ulong epoch_idx      = epoch % MULTI_EPOCH_LEADERS_EPOCH_CNT;

  fd_stake_weight_t const * stakes = leaders->stake_weight;

  /* Clear old data */
  fd_epoch_leaders_delete( fd_epoch_leaders_leave( leaders->lsched[epoch_idx] ) );

  /* Populate new lsched */
  uchar *  lsched_mem        = leaders->_lsched[epoch_idx];
  leaders->lsched[epoch_idx] = fd_epoch_leaders_join( fd_epoch_leaders_new(
                                    lsched_mem, epoch, slot0, slot_cnt,
                                    pub_cnt, stakes, excluded_stake ) );
  leaders->init_done[epoch_idx] = 1;
}
