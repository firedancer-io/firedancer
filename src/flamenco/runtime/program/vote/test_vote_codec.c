#include "fd_vote_codec.h"

#define OFF_BLOCK_REVENUE_COMMISSION_BPS (134UL)
#define OFF_PENDING_DELEGATOR_REWARDS    (136UL)

static void
v4_state( uchar * data,
          ushort  block_revenue_commission_bps,
          ulong   pending_delegator_rewards ) {
  fd_memset( data, 0, FD_VOTE_STATE_V4_SZ );
  FD_STORE( uint,   data,                                  fd_vote_state_versioned_enum_v4 );
  FD_STORE( ushort, data+OFF_BLOCK_REVENUE_COMMISSION_BPS, block_revenue_commission_bps );
  FD_STORE( ulong,  data+OFF_PENDING_DELEGATOR_REWARDS,    pending_delegator_rewards );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  uchar  data[ FD_VOTE_STATE_V4_SZ ];
  ushort bps;
  ulong  pending;

  /* v4: the stored values */
  v4_state( data, 2500U, 777UL );
  FD_TEST( !fd_vote_account_block_revenue_commission_bps( data, sizeof(data), &bps ) && bps==2500U );
  FD_TEST( !fd_vote_account_pending_delegator_rewards( data, sizeof(data), &pending ) && pending==777UL );

  /* pre-v4: the defaults, whatever the bytes at the v4 offsets hold */
  FD_STORE( uint, data, fd_vote_state_versioned_enum_v3 );
  FD_TEST( !fd_vote_account_block_revenue_commission_bps( data, FD_VOTE_STATE_V3_SZ, &bps ) && bps==FD_VOTE_DEFAULT_BLOCK_REVENUE_COMMISSION_BPS );
  FD_TEST( !fd_vote_account_pending_delegator_rewards( data, FD_VOTE_STATE_V3_SZ, &pending ) && pending==0UL );
  FD_STORE( uint, data, fd_vote_state_versioned_enum_v1_14_11 );
  FD_TEST( !fd_vote_account_block_revenue_commission_bps( data, FD_VOTE_STATE_V2_SZ, &bps ) && bps==FD_VOTE_DEFAULT_BLOCK_REVENUE_COMMISSION_BPS );
  FD_TEST( !fd_vote_account_pending_delegator_rewards( data, FD_VOTE_STATE_V2_SZ, &pending ) && pending==0UL );

  /* unknown discriminant and truncated v4 are errors */
  FD_STORE( uint, data, 7U );
  FD_TEST( fd_vote_account_block_revenue_commission_bps( data, sizeof(data), &bps )==1 );
  FD_TEST( fd_vote_account_pending_delegator_rewards( data, sizeof(data), &pending )==1 );
  v4_state( data, 2500U, 777UL );
  FD_TEST( fd_vote_account_block_revenue_commission_bps( data, OFF_BLOCK_REVENUE_COMMISSION_BPS+1UL, &bps )==1 );
  FD_TEST( fd_vote_account_pending_delegator_rewards( data, OFF_PENDING_DELEGATOR_REWARDS+7UL, &pending )==1 );
  FD_TEST( fd_vote_account_pending_delegator_rewards( data, 2UL, &pending )==1 );
  FD_TEST( fd_vote_account_pending_delegator_rewards( data, sizeof(data)-1UL, &pending )==1 );
  FD_TEST( fd_vote_account_pending_delegator_rewards( data, sizeof(data)+1UL, &pending )==1 );

  /* mutators: exact v4 size only, overflow leaves the field alone */
  v4_state( data, 0U, 10UL );
  FD_TEST( fd_vote_account_add_pending_delegator_rewards( data, sizeof(data)-1UL, 5UL )==1 );
  FD_TEST( fd_vote_account_add_pending_delegator_rewards( data, sizeof(data)+1UL, 5UL )==1 );
  FD_TEST( fd_vote_account_add_pending_delegator_rewards( data, sizeof(data),     5UL )==0 );
  FD_TEST( !fd_vote_account_pending_delegator_rewards( data, sizeof(data), &pending ) && pending==15UL );
  FD_TEST( fd_vote_account_add_pending_delegator_rewards( data, sizeof(data), ULONG_MAX )==2 );
  FD_TEST( !fd_vote_account_pending_delegator_rewards( data, sizeof(data), &pending ) && pending==15UL );

  ulong old = 0UL;
  FD_TEST( fd_vote_account_reset_pending_delegator_rewards( data, sizeof(data)-1UL, &old )==1 && old==0UL );
  FD_TEST( fd_vote_account_reset_pending_delegator_rewards( data, sizeof(data), &old )==0 && old==15UL );
  FD_TEST( !fd_vote_account_pending_delegator_rewards( data, sizeof(data), &pending ) && pending==0UL );

  FD_STORE( uint, data, fd_vote_state_versioned_enum_v3 );
  FD_TEST( fd_vote_account_add_pending_delegator_rewards( data, sizeof(data), 1UL )==1 );
  FD_TEST( fd_vote_account_reset_pending_delegator_rewards( data, sizeof(data), &old )==1 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
