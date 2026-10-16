#include "fd_vote_state_versioned.h"
#include "fd_vote_state_v5.h"
#include "fd_vote_codec_tmpl.h"
#include "fd_authorized_voters.h"
#include "../fd_vote_program.h"
#include "../../fd_executor_err.h"
#include "../../fd_runtime.h"

static void
make_v4( fd_vote_state_versioned_t * vsv,
         int                         has_bls ) {
  FD_TEST( fd_vote_state_versioned_new( vsv, fd_vote_state_versioned_enum_v4 ) );
  fd_vote_state_v4_t * s = &vsv->v4;
  fd_memset( s->node_pubkey.uc,                 0x11, 32UL );
  fd_memset( s->authorized_withdrawer.uc,       0x22, 32UL );
  fd_memset( s->inflation_rewards_collector.uc, 0x33, 32UL );
  fd_memset( s->block_revenue_collector.uc,     0x44, 32UL );
  fd_memset( s->bls_pubkey_compressed,          0x55, FD_BLS_PUBKEY_COMPRESSED_SZ );
  s->inflation_rewards_commission_bps = 1234;
  s->block_revenue_commission_bps     = 5678;
  s->pending_delegator_rewards        = 999UL;
  s->has_bls_pubkey_compressed        = (uchar)has_bls;
  s->has_root_slot                    = 1;
  s->root_slot                        = 80UL;
  s->last_timestamp                   = (fd_vote_block_timestamp_t){ .slot=91UL, .timestamp=1700000000L };
  deq_fd_landed_vote_t_push_tail( s->votes, (fd_landed_vote_t){ .lockout={ .slot=90UL, .confirmation_count=2U } } );
  deq_fd_landed_vote_t_push_tail( s->votes, (fd_landed_vote_t){ .lockout={ .slot=91UL, .confirmation_count=1U } } );
  deq_fd_vote_epoch_credits_t_push_tail( s->epoch_credits, (fd_vote_epoch_credits_t){ .epoch=2UL, .credits=50UL, .prev_credits=0UL  } );
  deq_fd_vote_epoch_credits_t_push_tail( s->epoch_credits, (fd_vote_epoch_credits_t){ .epoch=3UL, .credits=80UL, .prev_credits=50UL } );
  fd_vote_authorized_voter_t * v = fd_vote_authorized_voters_pool_ele_acquire( s->authorized_voters.pool );
  v->epoch = 3UL;
  v->prio  = 0x66;
  fd_memset( v->pubkey.uc, 0x66, 32UL );
  fd_vote_authorized_voters_treap_ele_insert( s->authorized_voters.treap, v, s->authorized_voters.pool );
}

static void
test_convert( void ) {
  static fd_vote_state_versioned_t vsv[1], out[1];

  make_v4( vsv, 1 );
  FD_TEST( fd_vsv_has_tower_votes( vsv ) );
  FD_TEST( fd_vsv_try_convert_to_v5( vsv, 10UL )==FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( vsv->kind==fd_vote_state_versioned_enum_v5 );
  FD_TEST( !fd_vsv_has_tower_votes( vsv ) );
  fd_vote_state_v5_t const * s = &vsv->v5;
  FD_TEST( s->node_pubkey.uc[ 0 ]==0x11 && s->authorized_withdrawer.uc[ 0 ]==0x22 );
  FD_TEST( s->inflation_rewards_collector.uc[ 0 ]==0x33 && s->block_revenue_collector.uc[ 0 ]==0x44 );
  FD_TEST( s->inflation_rewards_commission_bps_len==1 && s->inflation_rewards_commission_bps_epochs[ 0 ]==12UL && s->inflation_rewards_commission_bps[ 0 ]==1234 );
  FD_TEST( s->block_revenue_commission_bps_len==1 && s->block_revenue_commission_bps_epochs[ 0 ]==12UL && s->block_revenue_commission_bps[ 0 ]==5678 );
  for( ulong i=1UL; i<FD_VOTE_STATE_V5_COMMISSION_MAX; i++ ) {
    FD_TEST( !s->inflation_rewards_commission_bps_epochs[ i ] && !s->inflation_rewards_commission_bps[ i ] );
    FD_TEST( !s->block_revenue_commission_bps_epochs[ i ] && !s->block_revenue_commission_bps[ i ] );
  }
  FD_TEST( s->pending_delegator_rewards==999UL && s->bls_pubkey_compressed[ FD_BLS_PUBKEY_COMPRESSED_SZ-1UL ]==0x55 );
  FD_TEST( !s->location.x && !s->location.y && !s->location.z );
  FD_TEST( s->latest_vote==91UL && s->root_slot==80UL );
  FD_TEST( s->authorized_voters_len==1U && s->authorized_voters[ 0 ].epoch==3UL && s->authorized_voters[ 0 ].pubkey.uc[ 0 ]==0x66 );
  FD_TEST( s->accumulated_lamports_len==2U && s->accumulated_lamports[ 1 ].epoch==3UL && s->accumulated_lamports[ 1 ].credits==80UL );
  FD_TEST( s->last_timestamp.slot==91UL && s->last_timestamp.timestamp==1700000000L );
  FD_TEST( fd_mem_iszero( (uchar const *)( s->authorized_voters+1 ), (MAX_AUTHORIZED_VOTERS-1UL)*sizeof(fd_vote_state_v5_authorized_voter_t) ) );
  FD_TEST( fd_mem_iszero( (uchar const *)( s->accumulated_lamports+2 ), (MAX_EPOCH_CREDITS_HISTORY-2UL)*sizeof(fd_vote_epoch_credits_t) ) );

  uchar data[ FD_VOTE_STATE_V5_SZ ];
  FD_TEST( !fd_vote_state_versioned_serialize( vsv, data, sizeof(data) ) );
  FD_TEST( fd_vote_state_versioned_deserialize( out, data, sizeof(data) ) && out->kind==fd_vote_state_versioned_enum_v5 );
  FD_TEST( fd_memeq( &out->v5, &vsv->v5, sizeof(fd_vote_state_v5_t) ) );
  FD_TEST( fd_vsv_try_convert_to_v5( vsv, 10UL )==FD_EXECUTOR_INSTR_SUCCESS && fd_memeq( &out->v5, &vsv->v5, sizeof(fd_vote_state_v5_t) ) );

  make_v4( vsv, 0 );
  FD_TEST( fd_vsv_try_convert_to_v5( vsv, 10UL )==FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA );
  FD_TEST( vsv->kind==fd_vote_state_versioned_enum_v4 && deq_fd_landed_vote_t_cnt( vsv->v4.votes )==2UL );

  make_v4( vsv, 1 );
  deq_fd_landed_vote_t_remove_all( vsv->v4.votes );
  vsv->v4.has_root_slot = 0;
  FD_TEST( !fd_vsv_try_convert_to_v5( vsv, 10UL ) );
  FD_TEST( vsv->v5.latest_vote==ULONG_MAX && vsv->v5.root_slot==ULONG_MAX );

  make_v4( vsv, 1 );
  vsv->v4.root_slot = ULONG_MAX;
  FD_TEST( !fd_vsv_try_convert_to_v5( vsv, 10UL ) && vsv->v5.root_slot==ULONG_MAX );
  FD_TEST( !fd_vote_state_versioned_serialize( vsv, data, sizeof(data) ) );

  make_v4( vsv, 1 );
  while( deq_fd_vote_epoch_credits_t_cnt( vsv->v4.epoch_credits )<=MAX_EPOCH_CREDITS_HISTORY ) {
    deq_fd_vote_epoch_credits_t_push_tail( vsv->v4.epoch_credits, (fd_vote_epoch_credits_t){ .epoch=9UL } );
  }
  FD_TEST( fd_vsv_try_convert_to_v5( vsv, 10UL )==FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA && vsv->kind==fd_vote_state_versioned_enum_v4 );

  make_v4( vsv, 1 ); deq_fd_landed_vote_t_remove_all( vsv->v4.votes ); FD_TEST( !fd_vsv_try_convert_to_v5( vsv, 10UL ) );
  FD_TEST( fd_vsv_try_convert_to_v4( vsv, &vsv->v5.node_pubkey )==FD_EXECUTOR_INSTR_ERR_INVALID_ARG );
  FD_TEST( fd_vsv_try_convert_to_v3( vsv )==FD_EXECUTOR_INSTR_ERR_INVALID_ARG );
  FD_TEST( !fd_vsv_is_uninitialized( vsv ) );
}

static void
test_accessors( void ) {
  static fd_vote_state_versioned_t vsv[1];
  make_v4( vsv, 1 );
  FD_TEST( !fd_vsv_try_convert_to_v5( vsv, 10UL ) );

  FD_TEST( fd_vsv_get_authorized_withdrawer( vsv )->uc[ 0 ]==0x22 );
  FD_TEST( fd_vsv_get_commission( vsv )==12 );
  FD_TEST( fd_vsv_get_pending_delegator_rewards( vsv )==999UL );
  FD_TEST( fd_vsv_has_bls_pubkey( vsv ) );
  FD_TEST( fd_vsv_get_last_epoch_credits( vsv )->credits==80UL );

  fd_pubkey_t key = { .ul = { 7UL } };
  fd_vsv_set_node_pubkey( vsv, &key );
  fd_vsv_set_authorized_withdrawer( vsv, &key );
  fd_vsv_set_inflation_rewards_collector( vsv, &key );
  fd_vsv_set_block_revenue_collector( vsv, &key );
  fd_vsv_set_inflation_rewards_commission_bps( vsv, 777, 10UL );
  fd_vsv_set_block_revenue_commission_bps( vsv, 888, 10UL );
  FD_TEST( vsv->v5.node_pubkey.ul[ 0 ]==7UL && vsv->v5.authorized_withdrawer.ul[ 0 ]==7UL );
  FD_TEST( vsv->v5.inflation_rewards_collector.ul[ 0 ]==7UL && vsv->v5.block_revenue_collector.ul[ 0 ]==7UL );
  FD_TEST( vsv->v5.inflation_rewards_commission_bps_len==1 && vsv->v5.inflation_rewards_commission_bps[ 0 ]==777 );
  FD_TEST( vsv->v5.block_revenue_commission_bps_len==1 && vsv->v5.block_revenue_commission_bps[ 0 ]==888 );
  FD_TEST( fd_vsv_get_commission( vsv )==7 );

  fd_vsv_set_commission( vsv, 5, 11UL );
  FD_TEST( vsv->v5.inflation_rewards_commission_bps_len==2 );
  FD_TEST( vsv->v5.inflation_rewards_commission_bps_epochs[ 1 ]==13UL && vsv->v5.inflation_rewards_commission_bps[ 1 ]==500 );
  FD_TEST( vsv->v5.block_revenue_commission_bps_len==1 );
  FD_TEST( fd_vsv_get_commission( vsv )==5 );

  fd_vsv_set_inflation_rewards_commission_bps( vsv, 600, 11UL );
  FD_TEST( vsv->v5.inflation_rewards_commission_bps_len==2 && vsv->v5.inflation_rewards_commission_bps[ 1 ]==600 );

  fd_vsv_set_inflation_rewards_commission_bps( vsv, 700, 12UL );
  fd_vsv_set_inflation_rewards_commission_bps( vsv, 800, 13UL );
  FD_TEST( vsv->v5.inflation_rewards_commission_bps_len==4 );
  fd_vsv_set_inflation_rewards_commission_bps( vsv, 900, 14UL );
  FD_TEST( vsv->v5.inflation_rewards_commission_bps_len==4 );
  ulong  const want_epoch[ 4 ] = { 13UL, 14UL, 15UL, 16UL };
  ushort const want_bps  [ 4 ] = { 600, 700, 800, 900 };
  for( ulong i=0UL; i<4UL; i++ ) {
    FD_TEST( vsv->v5.inflation_rewards_commission_bps_epochs[ i ]==want_epoch[ i ] );
    FD_TEST( vsv->v5.inflation_rewards_commission_bps[ i ]==want_bps[ i ] );
  }
  uchar data[ FD_VOTE_STATE_V5_SZ ];
  FD_TEST( !fd_vote_state_versioned_serialize( vsv, data, sizeof(data) ) );
  ushort bps;
  FD_TEST( !fd_vote_account_commission_bps( data, sizeof(data), 1, &bps ) && bps==900 );
  FD_TEST( !fd_vote_account_block_revenue_commission_bps( data, sizeof(data), &bps ) && bps==888 );

  vsv->v5.accumulated_lamports_len = 0U;
  fd_memset( vsv->v5.accumulated_lamports, 0, sizeof(vsv->v5.accumulated_lamports) );
  FD_TEST( !fd_vsv_get_last_epoch_credits( vsv ) );
}

static void
set_voters( fd_vote_state_v5_t * s,
            ulong const *        epochs,
            ulong                cnt ) {
  fd_memset( s->authorized_voters, 0, sizeof(s->authorized_voters) );
  for( ulong i=0UL; i<cnt; i++ ) {
    s->authorized_voters[ i ].epoch = epochs[ i ];
    fd_memset( s->authorized_voters[ i ].pubkey.uc, (int)( 0x70+i ), 32UL );
  }
  s->authorized_voters_len = (uint)cnt;
}

static void
test_authorized_voters( void ) {
  static fd_vote_state_versioned_t vsv[1];
  make_v4( vsv, 1 );
  FD_TEST( !fd_vsv_try_convert_to_v5( vsv, 10UL ) );
  fd_vote_state_v5_t * s = &vsv->v5;

  fd_pubkey_t * voter = NULL;
  FD_TEST( !fd_authorized_voters_get_and_update_authorized_voter( vsv, 5UL, &voter ) && voter->uc[ 0 ]==0x66 );
  FD_TEST( s->authorized_voters_len==1U && s->authorized_voters[ 0 ].epoch==5UL );
  FD_TEST( fd_mem_iszero( (uchar const *)( s->authorized_voters+1 ), (MAX_AUTHORIZED_VOTERS-1UL)*sizeof(fd_vote_state_v5_authorized_voter_t) ) );

  set_voters( s, (ulong[]){ 4UL, 6UL, 7UL }, 3UL );
  FD_TEST( !fd_vote_state_v5_get_and_update_authorized_voter( s, 6UL, &voter ) && voter->uc[ 0 ]==0x71 );
  FD_TEST( s->authorized_voters_len==2U && s->authorized_voters[ 0 ].epoch==6UL );
  FD_TEST( !fd_vote_state_v5_get_and_update_authorized_voter( s, 9UL, &voter ) && voter->uc[ 0 ]==0x72 );
  FD_TEST( s->authorized_voters_len==1U && s->authorized_voters[ 0 ].epoch==9UL );

  set_voters( s, (ulong[]){ 4UL, 5UL, 6UL, 7UL }, 4UL );
  FD_TEST( !fd_vote_state_v5_get_and_update_authorized_voter( s, 8UL, &voter ) && voter->uc[ 0 ]==0x73 );
  FD_TEST( s->authorized_voters_len==2U && s->authorized_voters[ 0 ].epoch==7UL && s->authorized_voters[ 1 ].epoch==8UL );
  FD_TEST( s->authorized_voters[ 1 ].pubkey.uc[ 0 ]==0x73 );

  set_voters( s, (ulong[]){ 5UL }, 1UL );
  FD_TEST( fd_vote_state_v5_get_and_update_authorized_voter( s, 4UL, &voter )==FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA );

  set_voters( s, (ulong[]){ 4UL, 6UL, 7UL, 8UL }, 4UL );
  FD_TEST( fd_vote_state_v5_get_and_update_authorized_voter( s, 5UL, &voter )==FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL );

  static fd_txn_out_t        txn_out[1];
  static fd_exec_instr_ctx_t ctx[1];
  ctx->txn_out = txn_out;
  fd_pubkey_t new_voter = { .ul = { 9UL } };
  uchar       bls[ FD_BLS_PUBKEY_COMPRESSED_SZ ];
  fd_memset( bls, 0x99, FD_BLS_PUBKEY_COMPRESSED_SZ );

  set_voters( s, (ulong[]){ 5UL }, 1UL );
  FD_TEST( !fd_vsv_set_new_authorized_voter( ctx, vsv, &new_voter, 5UL, 7UL, bls, 1, NULL, 0UL ) );
  FD_TEST( s->authorized_voters_len==2U && s->authorized_voters[ 1 ].epoch==7UL && s->authorized_voters[ 1 ].pubkey.ul[ 0 ]==9UL );
  FD_TEST( s->bls_pubkey_compressed[ 0 ]==0x99 );
  FD_TEST( fd_vsv_set_new_authorized_voter( ctx, vsv, &new_voter, 5UL, 7UL, NULL, 1, NULL, 0UL )==FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR );
  FD_TEST( txn_out->err.custom_err==FD_VOTE_ERR_TOO_SOON_TO_REAUTHORIZE );

  set_voters( s, (ulong[]){ 5UL, 8UL, 9UL, 10UL }, 4UL );
  FD_TEST( fd_vsv_set_new_authorized_voter( ctx, vsv, &new_voter, 5UL, 7UL, NULL, 1, NULL, 0UL )==FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_convert();
  test_accessors();
  test_authorized_voters();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
