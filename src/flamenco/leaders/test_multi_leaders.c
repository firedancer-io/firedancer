#include "fd_multi_epoch_leaders.h"

FD_STATIC_ASSERT( alignof(fd_multi_epoch_leaders_t)<=FD_MULTI_EPOCH_LEADERS_ALIGN, alignment );

static uchar mleaders_mem[ FD_MULTI_EPOCH_LEADERS_FOOTPRINT ]
  __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN)));

#define SLOTS_PER_EPOCH 1000 /* Just for testing */
#define STAKE_MSG_SZ ( FD_STAKE_CI_STAKE_MSG_HEADER_SZ + MAX_STAKED_LEADERS * FD_STAKE_CI_STAKE_MSG_RECORD_SZ ) /* for testing, at most 16 nodes */
uchar stake_msg[ STAKE_MSG_SZ ];

static fd_stake_weight_msg_t *
generate_stake_msg( uchar *      _buf,
                    ulong        epoch,
                    char const * stakers ) {
  fd_stake_weight_msg_t *buf = fd_type_pun( _buf );

  buf->epoch          = epoch;
  buf->start_slot     = epoch * SLOTS_PER_EPOCH;
  buf->slot_cnt       = SLOTS_PER_EPOCH;
  buf->staked_cnt     = strlen(stakers);
  buf->excluded_stake = 0UL;

  ulong i = 0UL;
  for(; *stakers; stakers++, i++ ) {
    memset( buf->weights[i].vote_key.uc, *stakers, sizeof(fd_pubkey_t) );
    memset( buf->weights[i].id_key.uc, *stakers, sizeof(fd_pubkey_t) );
    buf->weights[i].stake = 1000UL/(i+1UL);
  }
  return fd_type_pun( _buf );
}

static void
check_leaders( fd_multi_epoch_leaders_t const * mleaders,
               ulong                            epoch,
               char const                     * staked_leaders ) {
  ulong min_slot =  epoch        * SLOTS_PER_EPOCH;
  ulong max_slot = (epoch + 1UL) * SLOTS_PER_EPOCH - 1UL;

  fd_epoch_leaders_t const * lsched = fd_multi_epoch_leaders_get_lsched_for_slot( mleaders, min_slot );

  if( !staked_leaders ) {
    FD_TEST( !lsched );
    return;
  }

  FD_TEST( lsched );
  FD_TEST( lsched == fd_multi_epoch_leaders_get_lsched_for_slot( mleaders, max_slot ) );
  FD_TEST( !fd_epoch_leaders_get( lsched, min_slot-1UL ) );
  FD_TEST( !fd_epoch_leaders_get( lsched, max_slot+1UL ) );

  ulong leader_cnt[ 26 ]={ 0UL };
  for( ulong s=min_slot; s<=max_slot; s++ ) {
    fd_pubkey_t const * leader = fd_multi_epoch_leaders_get_leader_for_slot( mleaders, s );
    FD_TEST( leader );
    ulong c = (ulong)leader->uc[ 0 ] - (ulong)'A';
    leader_cnt[ c ]++;
  }

  ulong unaccounted = max_slot-min_slot+1UL;
  for( char const * c=staked_leaders; *c; c++ ) {
    /* The stake distribution this test uses is such that given the
       large number of slots per epoch and small number of validators,
       with high probability every staked validator will get at least
       one leader slot.  */
    FD_TEST( leader_cnt[ *c-'A' ] );
    unaccounted -= leader_cnt[ *c-'A' ];
  }
  FD_TEST( unaccounted==0UL );
}

static void
test_staked_only( void ) {
  fd_multi_epoch_leaders_t * mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders_mem ) );

  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 0UL, "ABC"   ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );
  check_leaders( mleaders, 0UL, "ABC" );

  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 1UL, "ABCDE" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );
  check_leaders( mleaders, 0UL, "ABC" );
  check_leaders( mleaders, 1UL, "ABCDE" );

  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 2UL, "ABCF" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );
  check_leaders( mleaders, 2UL, "ABCF" );
  check_leaders( mleaders, 1UL, "ABCDE" );

  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 3UL, "I"    ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );
  check_leaders( mleaders, 2UL, "ABCF" );
  check_leaders( mleaders, 3UL, "I" );

  fd_multi_epoch_leaders_delete( fd_multi_epoch_leaders_leave( mleaders ) );
}

static void
test_transitions( void ) {
  fd_multi_epoch_leaders_t * mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders_mem ) );

  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 0UL, "ABCD" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );
  check_leaders( mleaders, 0UL, "ABCD" );

  /* Transition to different set */
  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 1UL, "ABCDEF" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );
  check_leaders( mleaders, 0UL, "ABCD" );
  check_leaders( mleaders, 1UL, "ABCDEF" );

  /* Transition them back */
  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 2UL, "AB" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );
  check_leaders( mleaders, 1UL, "ABCDEF" );
  check_leaders( mleaders, 2UL, "AB" );

  /* Completely swap */
  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 3UL, "GI" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );
  check_leaders( mleaders, 2UL, "AB" );
  check_leaders( mleaders, 3UL, "GI" );

  fd_multi_epoch_leaders_delete( fd_multi_epoch_leaders_leave( mleaders ) );
}

static void
test_skip_ahead( void ) {
  fd_multi_epoch_leaders_t * mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders_mem ) );

  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 0UL, "ABC" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );
  check_leaders( mleaders, 0UL, "ABC" );

  /* Skip ahead several epochs */
  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 5UL, "DEF" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );
  check_leaders( mleaders, 0UL, "ABC" ); /* Should remain because diff parity */
  check_leaders( mleaders, 1UL, NULL );
  check_leaders( mleaders, 4UL, NULL );
  check_leaders( mleaders, 5UL, "DEF" );

  fd_multi_epoch_leaders_delete( fd_multi_epoch_leaders_leave( mleaders ) );
}

static void
test_cancel( void ) {
  fd_multi_epoch_leaders_t * mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders_mem ) );

  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 0UL, "ABC" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );
  check_leaders( mleaders, 0UL, "ABC" );

  /* Start init but don't finish */
  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 1UL, "DEF" ) );
  /* Don't call fini */

  /* Start another init - should cancel the previous one */
  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 1UL, "GHI" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );

  check_leaders( mleaders, 0UL, "ABC" );
  check_leaders( mleaders, 1UL, "GHI" ); /* Should be GHI, not DEF */

  fd_multi_epoch_leaders_delete( fd_multi_epoch_leaders_leave( mleaders ) );
}

static void
test_ordering( void ) {
  fd_multi_epoch_leaders_t * mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders_mem ) );

  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 0UL, "ABC" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );
  check_leaders( mleaders, 0UL, "ABC" );

  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 1UL, "BCA" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );
  check_leaders( mleaders, 0UL, "ABC" );
  check_leaders( mleaders, 1UL, "BCA" );

  fd_multi_epoch_leaders_delete( fd_multi_epoch_leaders_leave( mleaders ) );
}

static void
test_next_slot( void ) {
  fd_multi_epoch_leaders_t * mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders_mem ) );

  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 0UL, "ABC" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );

  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 1UL, "D" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );

  fd_epoch_leaders_t const * lsched = fd_multi_epoch_leaders_get_lsched_for_epoch( mleaders, 0UL );
  FD_TEST( lsched );
  FD_TEST( lsched->slot0 == 0UL );
  FD_TEST( lsched->slot_cnt == SLOTS_PER_EPOCH );

  /* Test finding next slot for each leader */
  fd_pubkey_t test_key;
  for( char leader='A'; leader<='C'; leader++ ) {
    fd_memset( test_key.uc, leader, sizeof(fd_pubkey_t) );
    ulong next_slot = fd_multi_epoch_leaders_get_next_slot( mleaders, 0UL, &test_key );
    FD_TEST( next_slot >= lsched->slot0 );
    FD_TEST( next_slot < lsched->slot0 + lsched->slot_cnt );
    FD_TEST( fd_multi_epoch_leaders_get_leader_for_slot( mleaders, next_slot )->uc[0] == leader );
  }

  /* test crossing epoch boundary */
  {
    fd_memset( test_key.uc, 'D', sizeof(fd_pubkey_t) );
    fd_epoch_leaders_t const * lsched = fd_multi_epoch_leaders_get_lsched_for_epoch( mleaders, 1UL );
    ulong next_slot = fd_multi_epoch_leaders_get_next_slot( mleaders, 0UL, &test_key );
    FD_TEST( next_slot >= lsched->slot0 );
    FD_TEST( next_slot < lsched->slot0 + lsched->slot_cnt );
    FD_TEST( fd_multi_epoch_leaders_get_leader_for_slot( mleaders, next_slot )->uc[0] == 'D' );
  }

  /* Test with non-existent leader */
  memset( test_key.uc, 'Z', sizeof(fd_pubkey_t) );
  ulong next_slot = fd_multi_epoch_leaders_get_next_slot( mleaders, 0UL, &test_key );
  FD_TEST( next_slot == ULONG_MAX );

  fd_multi_epoch_leaders_delete( fd_multi_epoch_leaders_leave( mleaders ) );
}

static void
test_limits( void ) {
  /* Test with maximum number of staked leaders */
  fd_multi_epoch_leaders_t * mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders_mem ) );

  for( ulong stake_weight_cnt=MAX_STAKED_LEADERS-2; stake_weight_cnt<=MAX_STAKED_LEADERS+2; stake_weight_cnt++ ) {
    fd_stake_weight_msg_t * buf = fd_type_pun( stake_msg );
    buf->epoch          = stake_weight_cnt;
    buf->start_slot     = stake_weight_cnt * SLOTS_PER_EPOCH;
    buf->slot_cnt       = SLOTS_PER_EPOCH;
    buf->staked_cnt     = 0UL;
    buf->excluded_stake = 0UL;

    for( ulong i=0UL; i<stake_weight_cnt; i++ ) {
      ulong stake = 2000000000UL/(i+1UL);
      if( FD_LIKELY( i<MAX_STAKED_LEADERS ) ) {
        memset( buf->weights[i].vote_key.uc, 127-((int)i%96), sizeof(fd_pubkey_t) );
        memset( buf->weights[i].id_key.uc, 127-((int)i%96), sizeof(fd_pubkey_t) );
        FD_STORE( ulong, buf->weights[i].vote_key.uc, fd_ulong_bswap( i ) );
        FD_STORE( ulong, buf->weights[i].id_key.uc, fd_ulong_bswap( i ) );
        buf->weights[i].stake = stake;
        buf->staked_cnt++;
      } else {
        buf->excluded_stake += stake;
      }
    }
    fd_multi_epoch_leaders_stake_msg_init( mleaders, buf );
    fd_multi_epoch_leaders_stake_msg_fini( mleaders );

    FD_TEST( fd_multi_epoch_leaders_get_lsched_for_slot( mleaders, stake_weight_cnt*SLOTS_PER_EPOCH ) );
  }

  fd_multi_epoch_leaders_delete( fd_multi_epoch_leaders_leave( mleaders ) );
}

static void
test_get_sorted_lscheds( void ) {
  fd_multi_epoch_leaders_t * mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders_mem ) );

  /* No epochs initialized - both should be NULL */
  fd_multi_epoch_leaders_lsched_sorted_t result = fd_multi_epoch_leaders_get_sorted_lscheds( mleaders );
  FD_TEST( result.lscheds[0] == NULL );
  FD_TEST( result.lscheds[1] == NULL );

  /* Initialize one epoch (epoch 0) */
  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 0UL, "ABC" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );

  result = fd_multi_epoch_leaders_get_sorted_lscheds( mleaders );
  FD_TEST( result.lscheds[0] != NULL );
  FD_TEST( result.lscheds[0]->epoch == 0UL );
  FD_TEST( result.lscheds[1] == NULL );

  /* Initialize second epoch (epoch 1) - should be sorted by epoch */
  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 1UL, "DEF" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );

  result = fd_multi_epoch_leaders_get_sorted_lscheds( mleaders );
  FD_TEST( result.lscheds[0] != NULL );
  FD_TEST( result.lscheds[1] != NULL );
  FD_TEST( result.lscheds[0]->epoch == 0UL );
  FD_TEST( result.lscheds[1]->epoch == 1UL );

  /* Initialize epoch 3 (overwrites epoch 1) - should maintain sorting */
  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 3UL, "GHI" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );

  result = fd_multi_epoch_leaders_get_sorted_lscheds( mleaders );
  FD_TEST( result.lscheds[0] != NULL );
  FD_TEST( result.lscheds[1] != NULL );
  FD_TEST( result.lscheds[0]->epoch == 0UL );
  FD_TEST( result.lscheds[1]->epoch == 3UL );

  /* Initialize a much higher epoch (epoch 10) to test large gap */
  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 10UL, "MNO" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );

  result = fd_multi_epoch_leaders_get_sorted_lscheds( mleaders );
  FD_TEST( result.lscheds[0] != NULL );
  FD_TEST( result.lscheds[1] != NULL );
  /* Now we have epoch 3 (odd parity) and epoch 10 (even parity) */
  FD_TEST( result.lscheds[0]->epoch == 3UL );   /* epoch 3 is smaller */
  FD_TEST( result.lscheds[1]->epoch == 10UL );  /* epoch 10 is larger */

  fd_multi_epoch_leaders_delete( fd_multi_epoch_leaders_leave( mleaders ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_staked_only();
  test_transitions();
  test_skip_ahead();
  test_cancel();
  test_ordering();
  test_next_slot();
  test_limits();
  test_get_sorted_lscheds();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
