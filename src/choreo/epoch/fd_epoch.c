#include "fd_epoch.h"

void *
fd_epoch_new( void * shmem, ulong voter_max ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_epoch_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_epoch_footprint( voter_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad mem" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( shmem );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "shmem must be part of a workspace" ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );
  int lg_slot_cnt = fd_ulong_find_msb( fd_ulong_pow2_up( voter_max ) ) + 2; /* fill ratio <= 0.25 */

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_epoch_t * epoch  = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_align(), sizeof(fd_epoch_t) );
  void * epoch_voters = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_voters_align(),  fd_epoch_voters_footprint( lg_slot_cnt ) );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_epoch_align() ) == (ulong)shmem + footprint );

  epoch->voters_gaddr = fd_wksp_gaddr_fast( wksp, fd_epoch_voters_join( fd_epoch_voters_new( epoch_voters, lg_slot_cnt ) ) );

  epoch->epoch_gaddr = fd_wksp_gaddr_fast( wksp, epoch );
  epoch->total_stake = 0UL;
  epoch->first_slot  = FD_SLOT_NULL;
  epoch->last_slot   = FD_SLOT_NULL;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( epoch->magic ) = FD_EPOCH_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_epoch_t *
fd_epoch_join( void * shepoch ) {
  fd_epoch_t * epoch = (fd_epoch_t *)shepoch;

  if( FD_UNLIKELY( !epoch ) ) {
    FD_LOG_WARNING(( "NULL epoch" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)epoch, fd_epoch_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned epoch" ));
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_containing( epoch );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_WARNING(( "epoch must be part of a workspace" ));
    return NULL;
  }

  if( FD_UNLIKELY( epoch->magic!=FD_EPOCH_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return epoch;
}

void *
fd_epoch_leave( fd_epoch_t const * epoch ) {

  if( FD_UNLIKELY( !epoch ) ) {
    FD_LOG_WARNING(( "NULL epoch" ));
    return NULL;
  }

  return (void *)epoch;
}

void *
fd_epoch_delete( void * epoch ) {

  if( FD_UNLIKELY( !epoch ) ) {
    FD_LOG_WARNING(( "NULL epoch" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)epoch, fd_epoch_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned epoch" ));
    return NULL;
  }

  return epoch;
}

void
fd_epoch_init( fd_epoch_t *                      epoch,
               ulong                             eah_start_slot,
               ulong                             eah_stop_slot,
               fd_vote_accounts_global_t const * vote_accounts ) {

  epoch->first_slot = eah_start_slot;
  epoch->last_slot  = eah_stop_slot;

  fd_voter_t * epoch_voters = fd_epoch_voters( epoch );

  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_pool = fd_vote_accounts_vote_accounts_pool_join( vote_accounts );
  fd_vote_accounts_pair_global_t_mapnode_t * vote_accounts_root = fd_vote_accounts_vote_accounts_root_join( vote_accounts );

  for( fd_vote_accounts_pair_global_t_mapnode_t * curr = fd_vote_accounts_pair_global_t_map_minimum(
           vote_accounts_pool,
           vote_accounts_root );
       curr;
       curr = fd_vote_accounts_pair_global_t_map_successor( vote_accounts_pool, curr ) ) {

    if( FD_UNLIKELY( curr->elem.stake > 0UL ) ) {

      #if FD_EPOCH_USE_HANDHOLDING
      FD_TEST( !fd_epoch_voters_query( epoch_voters, curr->elem.key, NULL ) );
      FD_TEST( fd_epoch_voters_key_cnt( epoch_voters ) < fd_epoch_voters_key_max( epoch_voters ) );
      #endif

      fd_voter_t * voter = fd_epoch_voters_insert( epoch_voters, curr->elem.key );
      voter->rec.uc[FD_FUNK_REC_KEY_FOOTPRINT - 1] = FD_FUNK_KEY_TYPE_ACC;

      #if FD_EPOCH_USE_HANDHOLDING
      FD_TEST( 0 == memcmp( &voter->key, &curr->elem.key, sizeof(fd_pubkey_t) ) );
      FD_TEST( fd_epoch_voters_query( epoch_voters, voter->key, NULL ) );
      #endif

      voter->stake = curr->elem.stake;

      voter->replay_vote.slot = FD_SLOT_NULL;
      voter->gossip_vote.slot = FD_SLOT_NULL;
      voter->rooted_vote.slot = FD_SLOT_NULL;
    }
    epoch->total_stake += curr->elem.stake;
  }
}

void
fd_epoch_fini( fd_epoch_t * epoch ) {
  fd_epoch_voters_clear( fd_epoch_voters( epoch ) );
  epoch->total_stake = 0UL;
}
