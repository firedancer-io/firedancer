#include "fd_ssmanifest_parser.h"
#include "fd_ssmsg.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static fd_vote_state_v5_t v5[1];
  fd_memset( v5->node_pubkey.uc,                 0x11, 32UL );
  fd_memset( v5->inflation_rewards_collector.uc, 0x33, 32UL );
  fd_memset( v5->block_revenue_collector.uc,     0x44, 32UL );
  fd_memset( v5->bls_pubkey_compressed,          0x55, FD_BLS_PUBKEY_COMPRESSED_SZ );
  v5->inflation_rewards_commission_bps_len        = 2;
  v5->inflation_rewards_commission_bps_epochs[ 0 ] = 5UL;
  v5->inflation_rewards_commission_bps[ 0 ]        = 1234;
  v5->inflation_rewards_commission_bps_epochs[ 1 ] = 12UL;
  v5->inflation_rewards_commission_bps[ 1 ]        = 4321;
  v5->block_revenue_commission_bps_len            = 1;
  v5->block_revenue_commission_bps_epochs[ 0 ]     = 5UL;
  v5->block_revenue_commission_bps[ 0 ]            = 5678;
  v5->pending_delegator_rewards                   = 999UL;
  v5->accumulated_lamports_len                    = 2U;
  v5->accumulated_lamports[ 0 ]                   = (fd_vote_epoch_credits_t){ .epoch=ULONG_MAX, .credits=ULONG_MAX, .prev_credits=ULONG_MAX };
  v5->accumulated_lamports[ 1 ]                   = (fd_vote_epoch_credits_t){ .epoch=8UL, .credits=50UL, .prev_credits=0UL };
  v5->last_timestamp                              = (fd_vote_block_timestamp_t){ .slot=4242UL, .timestamp=1700000000L };

  static fd_snapshot_manifest_vote_stakes_t out[1];
  fd_memset( out, 0xA5, sizeof(out) );
  FD_TEST( !fd_ssmanifest_vote_stakes_from_v5( out, v5 ) );
  FD_TEST( out->identity[ 0 ]==0x11 && out->commission_inflation[ 0 ]==0x33 && out->commission_block[ 0 ]==0x44 );
  FD_TEST( out->commission==4321 && out->commission_block_bps==5678 && out->pending_delegator_rewards==999UL );
  FD_TEST( out->has_identity_bls==1 && out->identity_bls[ FD_BLS_PUBKEY_COMPRESSED_SZ-1UL ]==0x55 );
  FD_TEST( out->epoch_credits_history_len==2UL );
  FD_TEST( fd_vote_epoch_credits_is_alpenglow_marker( (fd_vote_epoch_credits_t const *)&out->epoch_credits[ 0 ] ) );
  FD_TEST( out->epoch_credits[ 1 ].epoch==8UL && out->epoch_credits[ 1 ].credits==50UL );
  FD_TEST( out->slot==4242UL && out->timestamp==1700000000L );


  v5->block_revenue_commission_bps_len = 0;
  FD_TEST( fd_ssmanifest_vote_stakes_from_v5( out, v5 )==-1 );
  v5->block_revenue_commission_bps_len = 1;
  v5->inflation_rewards_commission_bps_len = (ushort)( FD_VOTE_STATE_V5_COMMISSION_MAX+1UL );
  FD_TEST( fd_ssmanifest_vote_stakes_from_v5( out, v5 )==-1 );
  v5->inflation_rewards_commission_bps_len = 2;

  v5->accumulated_lamports_len = (uint)MAX_EPOCH_CREDITS_HISTORY+1U;
  FD_TEST( fd_ssmanifest_vote_stakes_from_v5( out, v5 )==-1 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
