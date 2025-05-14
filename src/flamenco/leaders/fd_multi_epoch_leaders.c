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

  /* Initialize all epochs to satisfy invariants */
  fd_stake_weight_t dummy_stakes[ 1 ] = {{ .key = {{0}}, .stake = 1UL }};
  for( ulong i = 0; i < MULTI_EPOCH_LEADERS_EPOCH_CNT; i++ ) {
    leaders->lsched[i] = fd_epoch_leaders_join( fd_epoch_leaders_new( leaders->_lsched[i], 0UL, 0UL, 1UL, 1UL, dummy_stakes, 0UL ) );
  }

  return shmem;
}

fd_multi_epoch_leaders_t *
fd_multi_epoch_leaders_join( void * shleaders ) { return shleaders; }

void *
fd_multi_epoch_leaders_leave( fd_multi_epoch_leaders_t * leaders ) { return leaders; }

void *
fd_multi_epoch_leaders_delete( void * shleaders ) { return shleaders; }

static ulong
fd_multi_epoch_leaders_get_epoch_idx( fd_multi_epoch_leaders_t const * leaders,
                                      ulong                            slot ) {
  for( ulong i = 0; i < MULTI_EPOCH_LEADERS_EPOCH_CNT; i++ ) {
    fd_epoch_leaders_t const * epoch_leaders = leaders->lsched[i];
    ulong slot0    = epoch_leaders->slot0;
    ulong slot_end = slot0 + epoch_leaders->slot_cnt;
    if( FD_UNLIKELY( slot0 > slot ) ) break;
    if( FD_LIKELY( slot < slot_end ) ) return i;
  }
  return ULONG_MAX;
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
  ulong const * hdr = fd_type_pun_const( new_message );

  ulong epoch               = hdr[ 0 ];
  ulong staked_cnt          = hdr[ 1 ];
  ulong start_slot          = hdr[ 2 ];
  ulong slot_cnt            = hdr[ 3 ];
  ulong excluded_stake      = hdr[ 4 ];

  if( FD_UNLIKELY( staked_cnt > MAX_STAKED_LEADERS ) )
    FD_LOG_ERR(( "Multi-epoch leaders received a malformed update with %lu stakes in it,"
                 " but the maximum allowed is %lu", staked_cnt, MAX_STAKED_LEADERS ));

  leaders->scratch->epoch          = epoch;
  leaders->scratch->start_slot     = start_slot;
  leaders->scratch->slot_cnt       = slot_cnt;
  leaders->scratch->staked_cnt     = staked_cnt;
  leaders->scratch->excluded_stake = excluded_stake;

  fd_memcpy( leaders->stake_weight, hdr+5UL, sizeof(fd_stake_weight_t)*staked_cnt );
}

void
fd_multi_epoch_leaders_stake_msg_fini( fd_multi_epoch_leaders_t * leaders ) {
  fd_multi_epoch_leaders_set_epoch_leaders( leaders, leaders->scratch->epoch,
                                            leaders->scratch->start_slot,
                                            leaders->scratch->slot_cnt,
                                            leaders->scratch->staked_cnt,
                                            leaders->stake_weight,
                                            leaders->scratch->excluded_stake );
}

void
fd_multi_epoch_leaders_set_epoch_leaders( fd_multi_epoch_leaders_t * leaders,
                                          ulong                      epoch,
                                          ulong                      slot0,
                                          ulong                      slot_cnt,
                                          ulong                      pub_cnt,
                                          fd_stake_weight_t const *  stakes,
                                          ulong                      excluded_stake ) {

  const ulong epoch_idx  = epoch % MULTI_EPOCH_LEADERS_EPOCH_CNT;

  /* Clear old data */
  fd_epoch_leaders_delete( fd_epoch_leaders_leave( leaders->lsched[epoch_idx] ) );

  /* Populate new lsched */
  uchar *  lsched_mem        = (uchar *)&(leaders->_lsched[epoch_idx]);
  leaders->lsched[epoch_idx] = fd_epoch_leaders_join( fd_epoch_leaders_new(
                                    lsched_mem, epoch, slot0, slot_cnt,
                                    pub_cnt, stakes, excluded_stake ) );
}
