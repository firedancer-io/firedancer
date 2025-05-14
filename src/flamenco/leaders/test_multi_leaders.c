#include "fd_multi_epoch_leaders.h"

FD_STATIC_ASSERT( alignof(fd_multi_epoch_leaders_t)<=FD_MULTI_EPOCH_LEADERS_ALIGN, alignment );

static uchar mleaders_mem[ FD_MULTI_EPOCH_LEADERS_FOOTPRINT ]
  __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN)));

#define SLOTS_PER_EPOCH 1000 /* Just for testing */
#define STAKE_MSG_SZ ( 40UL + MAX_STAKED_LEADERS * 40UL ) /* for testing, at most 16 nodes */
uchar stake_msg[ STAKE_MSG_SZ ];

#include "../../discof/replay/fd_exec.h"
typedef struct {
    fd_stake_weight_msg_t hdr;
    fd_stake_weight_t     weights[];
  } stake_msg_t;

static uchar *
generate_stake_msg( uchar *      _buf,
                    ulong        epoch,
                    char const * stakers ) {
  stake_msg_t *buf = (stake_msg_t *)_buf;

  buf->hdr.epoch          = epoch;
  buf->hdr.start_slot     = epoch * SLOTS_PER_EPOCH;
  buf->hdr.slot_cnt       = SLOTS_PER_EPOCH;
  buf->hdr.staked_cnt     = strlen(stakers);
  buf->hdr.excluded_stake = 0UL;

  ulong i = 0UL;
  for(; *stakers; stakers++, i++ ) {
    memset( buf->weights[i].key.uc, *stakers, sizeof(fd_pubkey_t) );
    buf->weights[i].stake = 1000UL/(i+1UL);
  }
  return _buf;
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

  /* Test finding next slot for each leader */
  fd_pubkey_t test_key;
  memset( test_key.uc, 'A', sizeof(fd_pubkey_t) );
  ulong next_slot = fd_multi_epoch_leaders_get_next_slot( mleaders, 0UL, &test_key );
  FD_TEST( next_slot != ULONG_MAX );
  FD_TEST( next_slot < SLOTS_PER_EPOCH );

  memset( test_key.uc, 'B', sizeof(fd_pubkey_t) );
  next_slot = fd_multi_epoch_leaders_get_next_slot( mleaders, 0UL, &test_key );
  FD_TEST( next_slot != ULONG_MAX );
  FD_TEST( next_slot < SLOTS_PER_EPOCH );

  /* Test with non-existent leader */
  memset( test_key.uc, 'Z', sizeof(fd_pubkey_t) );
  next_slot = fd_multi_epoch_leaders_get_next_slot( mleaders, 0UL, &test_key );
  FD_TEST( next_slot == ULONG_MAX );

  fd_multi_epoch_leaders_delete( fd_multi_epoch_leaders_leave( mleaders ) );
}

static void
test_limits( void ) {
  /* Test with maximum number of staked leaders */
  fd_multi_epoch_leaders_t * mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders_mem ) );

  for( ulong stake_weight_cnt=MAX_STAKED_LEADERS-2; stake_weight_cnt<=MAX_STAKED_LEADERS+2; stake_weight_cnt++ ) {
    stake_msg_t * buf = (stake_msg_t *)stake_msg;
    buf->hdr.epoch          = stake_weight_cnt;
    buf->hdr.start_slot     = stake_weight_cnt * SLOTS_PER_EPOCH;
    buf->hdr.slot_cnt       = SLOTS_PER_EPOCH;
    buf->hdr.staked_cnt     = 0UL;
    buf->hdr.excluded_stake = 0UL;

    for( ulong i=0UL; i<stake_weight_cnt; i++ ) {
      ulong stake = 2000000000UL/(i+1UL);
      if( FD_LIKELY( i<MAX_STAKED_LEADERS ) ) {
        memset( buf->weights[i].key.uc, 127-((int)i%96), sizeof(fd_pubkey_t) );
        FD_STORE( ulong, buf->weights[i].key.uc, fd_ulong_bswap( i ) );
        buf->weights[i].stake = stake;
        buf->hdr.staked_cnt++;
      } else {
        buf->hdr.excluded_stake += stake;
      }
    }
    fd_multi_epoch_leaders_stake_msg_init( mleaders, stake_msg );
    fd_multi_epoch_leaders_stake_msg_fini( mleaders );

    FD_TEST( fd_multi_epoch_leaders_get_lsched_for_slot( mleaders, stake_weight_cnt*SLOTS_PER_EPOCH ) );
  }

  fd_multi_epoch_leaders_delete( fd_multi_epoch_leaders_leave( mleaders ) );
}

static void
test_metadata( void ) {
  fd_multi_epoch_leaders_t * mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( mleaders_mem ) );

  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 5UL, "ABC" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );

  FD_TEST( fd_multi_epoch_leaders_get_start_epoch( mleaders ) == 5UL );
  FD_TEST( fd_multi_epoch_leaders_get_start_slot( mleaders ) == 5UL * SLOTS_PER_EPOCH );

  fd_multi_epoch_leaders_stake_msg_init( mleaders, generate_stake_msg( stake_msg, 6UL, "DEF" ) );
  fd_multi_epoch_leaders_stake_msg_fini( mleaders );

  FD_TEST( fd_multi_epoch_leaders_get_start_epoch( mleaders ) == 5UL );
  FD_TEST( fd_multi_epoch_leaders_get_start_slot( mleaders ) == 5UL * SLOTS_PER_EPOCH );

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
  test_metadata();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
