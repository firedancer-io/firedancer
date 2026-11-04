#include "fd_vote_codec.h"
#include "fd_vote_state_versioned.h"

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

static fd_validator_location_t const LOC = { 4051542, 618526, 4870645 };

static void
make_v5( fd_vote_state_versioned_t * vsv ) {
  FD_TEST( fd_vote_state_versioned_new( vsv, fd_vote_state_versioned_enum_v5 ) );
  fd_vote_state_v5_t * s = &vsv->v5;
  fd_memset( s->node_pubkey.uc,                 0x11, 32UL );
  fd_memset( s->authorized_withdrawer.uc,       0x22, 32UL );
  fd_memset( s->inflation_rewards_collector.uc, 0x33, 32UL );
  fd_memset( s->block_revenue_collector.uc,     0x44, 32UL );
  fd_memset( s->bls_pubkey_compressed,          0x55, FD_BLS_PUBKEY_COMPRESSED_SZ );
  s->inflation_rewards_commission_bps_len        = 2;
  s->block_revenue_commission_bps_len            = 1;
  s->inflation_rewards_commission_bps_epochs[ 0 ] = 5UL;
  s->inflation_rewards_commission_bps[ 0 ]        = 1234;
  s->inflation_rewards_commission_bps_epochs[ 1 ] = 12UL;
  s->inflation_rewards_commission_bps[ 1 ]        = 4321;
  s->block_revenue_commission_bps_epochs[ 0 ]     = 5UL;
  s->block_revenue_commission_bps[ 0 ]            = 5678;
  s->pending_delegator_rewards                   = 999UL;
  s->location                                    = LOC;
  s->latest_vote                                 = 4242UL;
  s->root_slot                                   = 4200UL;
  s->authorized_voters_len                       = 2U;
  s->accumulated_lamports_len                    = 2U;
  s->last_timestamp                              = (fd_vote_block_timestamp_t){ .slot=4242UL, .timestamp=1700000000L };
  for( ulong i=0UL; i<2UL; i++ ) {
    s->authorized_voters[ i ].epoch = 10UL+i;
    fd_memset( s->authorized_voters[ i ].pubkey.uc, (int)( 0x60+i ), 32UL );
  }
  for( ulong i=0UL; i<2UL; i++ ) {
    s->accumulated_lamports[ i ] = (fd_vote_epoch_credits_t){ .epoch=7UL+i, .credits=100UL*(i+1UL), .prev_credits=100UL*i };
  }
}

static void
test_v5_codec( void ) {
  static fd_vote_state_versioned_t vsv[1], out[1];
  uchar data[ FD_VOTE_STATE_V5_SZ ];

  make_v5( vsv );
  FD_TEST( fd_vote_state_versioned_serialized_size( vsv )==FD_VOTE_STATE_V5_SZ );
  fd_memset( data, 0xEE, sizeof(data) );
  FD_TEST( !fd_vote_state_versioned_serialize( vsv, data, sizeof(data) ) );
  FD_TEST( FD_LOAD( uint,   data+  0 )==4U );
  FD_TEST( data[ 4 ]==0x11 && data[ 36 ]==0x22 && data[ 68 ]==0x33 && data[ 100 ]==0x44 );
  FD_TEST( FD_LOAD( int,    data+132 )==LOC.x && FD_LOAD( int, data+136 )==LOC.y && FD_LOAD( int, data+140 )==LOC.z );
  FD_TEST( FD_LOAD( ulong,  data+144 )==999UL );
  FD_TEST( FD_LOAD( uint,   data+152 )==2U );
  FD_TEST( FD_LOAD( uint,   data+156 )==1U );
  FD_TEST( FD_LOAD( ulong,  data+160 )==5UL && FD_LOAD( ulong, data+168 )==12UL && fd_mem_iszero( data+176, 16UL ) );
  FD_TEST( FD_LOAD( ushort, data+192 )==1234 && FD_LOAD( ushort, data+194 )==4321 && fd_mem_iszero( data+196, 4UL ) );
  FD_TEST( FD_LOAD( ulong,  data+200 )==5UL && fd_mem_iszero( data+208, 24UL ) );
  FD_TEST( FD_LOAD( ushort, data+232 )==5678 && fd_mem_iszero( data+234, 6UL ) );
  FD_TEST( data[ 240 ]==0x55 && data[ 287 ]==0x55 );
  FD_TEST( FD_LOAD( ulong, data+288 )==4242UL && FD_LOAD( ulong, data+296 )==4200UL );
  FD_TEST( FD_LOAD( uint, data+304 )==2U && FD_LOAD( uint, data+308 )==2U );
  FD_TEST( FD_LOAD( ulong, data+312 )==10UL && data[ 320 ]==0x60 && FD_LOAD( ulong, data+352 )==11UL );
  FD_TEST( fd_mem_iszero( data+312+2*40, 2*40 ) );
  FD_TEST( FD_LOAD( ulong, data+472 )==7UL && FD_LOAD( ulong, data+480 )==100UL && FD_LOAD( ulong, data+496 )==8UL && FD_LOAD( ulong, data+504 )==200UL );
  FD_TEST( fd_mem_iszero( data+472+2*24, 3*24 ) );
  FD_TEST( FD_LOAD( ulong, data+592 )==4242UL && FD_LOAD( long, data+600 )==1700000000L );
  FD_TEST( fd_mem_iszero( data+608, FD_VOTE_STATE_V5_SZ-608UL ) );

  FD_TEST( fd_vote_state_versioned_deserialize( out, data, sizeof(data) ) );
  FD_TEST( out->kind==fd_vote_state_versioned_enum_v5 );
  FD_TEST( fd_memeq( &out->v5, &vsv->v5, sizeof(fd_vote_state_v5_t) ) );
  uchar again[ FD_VOTE_STATE_V5_SZ ];
  FD_TEST( !fd_vote_state_versioned_serialize( out, again, sizeof(again) ) && fd_memeq( data, again, sizeof(data) ) );

  make_v5( vsv ); vsv->v5.root_slot = ULONG_MAX; vsv->v5.latest_vote = ULONG_MAX;
  FD_TEST( !fd_vote_state_versioned_serialize( vsv, data, sizeof(data) ) && FD_LOAD( ulong, data+296 )==ULONG_MAX && FD_LOAD( ulong, data+288 )==ULONG_MAX );
  FD_TEST( fd_vote_state_versioned_deserialize( out, data, sizeof(data) ) && out->v5.root_slot==ULONG_MAX && out->v5.latest_vote==ULONG_MAX );

  make_v5( vsv ); FD_TEST( !fd_vote_state_versioned_serialize( vsv, data, sizeof(data) ) );
  FD_TEST( !fd_vote_state_versioned_deserialize( out, data, sizeof(data)-1UL ) );
  FD_TEST(  fd_vote_state_versioned_deserialize( out, data, sizeof(data)     ) );
# define BAD( mutate ) do { make_v5( vsv ); FD_TEST( !fd_vote_state_versioned_serialize( vsv, data, sizeof(data) ) ); \
                             (void)( mutate ); FD_TEST( !fd_vote_state_versioned_deserialize( out, data, sizeof(data) ) ); } while(0)
  BAD( FD_STORE( uint, data+304, 5U ) );
  BAD( FD_STORE( ulong, data+352, 10UL ) );
  BAD( data[ 312+3*40 ]=1 );
  BAD( FD_STORE( uint, data+308, 6U ) );
  BAD( FD_STORE( uint, data+308, 1U ) );
  BAD( data[ 472+4*24 ]=1 );
  BAD( data[ 608 ]=1 );
  BAD( FD_STORE( uint, data+152, 0U ) );
  BAD( FD_STORE( uint, data+152, 5U ) );
  BAD( FD_STORE( uint, data+152, 0x10002U ) );
  BAD( FD_STORE( uint, data+156, 0U ) );
  BAD( FD_STORE( uint, data+156, 5U ) );
  make_v5( vsv ); FD_TEST( !fd_vote_state_versioned_serialize( vsv, data, sizeof(data) ) );
  FD_STORE( ulong, data+168, 4UL );
  FD_TEST( fd_vote_state_versioned_deserialize( out, data, sizeof(data) ) && out->v5.inflation_rewards_commission_bps_epochs[ 1 ]==4UL );
  BAD( FD_STORE( ulong, data+176, 13UL ) );
  BAD( FD_STORE( ushort, data+196, 1 ) );
  BAD( FD_STORE( ulong, data+208, 6UL ) );
  BAD( FD_STORE( ushort, data+234, 1 ) );
  BAD( data[ 3761 ]=1 );
  BAD( FD_STORE( int, data+132, FD_VALIDATOR_LOCATION_COORD_MAX+1 ) );
  BAD( FD_STORE( int, data+136, -FD_VALIDATOR_LOCATION_COORD_MAX-1 ) );
  BAD( FD_STORE( int, data+140, INT_MIN ) );
  BAD( FD_STORE( int, data+140, INT_MAX ) );
  BAD( FD_STORE( int, data+140, 0 ) );
# undef BAD

  make_v5( vsv ); vsv->v5.location = (fd_validator_location_t){ 0, -FD_VALIDATOR_LOCATION_COORD_MAX, 0 };
  FD_TEST( !fd_vote_state_versioned_serialize( vsv, data, sizeof(data) ) );
  FD_TEST( fd_vote_state_versioned_deserialize( out, data, sizeof(data) ) && out->v5.location.y==-FD_VALIDATOR_LOCATION_COORD_MAX );
  make_v5( vsv ); vsv->v5.location.z = FD_VALIDATOR_LOCATION_COORD_MAX+1;
  FD_TEST( fd_vote_state_versioned_serialize( vsv, data, sizeof(data) )==1 );

  make_v5( vsv ); vsv->v5.authorized_voters_len = (uint)MAX_AUTHORIZED_VOTERS+1U;
  FD_TEST( fd_vote_state_versioned_serialize( vsv, data, sizeof(data) )==1 );
  make_v5( vsv ); vsv->v5.accumulated_lamports_len = (uint)FD_VOTE_STATE_V5_ACCUMULATED_LAMPORTS_MAX+1U;
  FD_TEST( fd_vote_state_versioned_serialize( vsv, data, sizeof(data) )==1 );
  make_v5( vsv ); vsv->v5.inflation_rewards_commission_bps_len = 0;
  FD_TEST( fd_vote_state_versioned_serialize( vsv, data, sizeof(data) )==1 );
  make_v5( vsv ); vsv->v5.block_revenue_commission_bps_len = (uint)( FD_VOTE_STATE_V5_COMMISSION_MAX+1UL );
  FD_TEST( fd_vote_state_versioned_serialize( vsv, data, sizeof(data) )==1 );
  make_v5( vsv ); vsv->v5.inflation_rewards_commission_bps_epochs[ 1 ] = 5UL;
  FD_TEST( !fd_vote_state_versioned_serialize( vsv, data, sizeof(data) ) && fd_vote_account_is_valid_v5( data, sizeof(data) ) );
  make_v5( vsv );
  FD_TEST( fd_vote_state_versioned_serialize( vsv, data, sizeof(data)-1UL )==1 );
  uchar big[ FD_VOTE_STATE_V5_SZ+334UL ];
  fd_memset( big, 0xAB, sizeof(big) );
  FD_TEST( !fd_vote_state_versioned_serialize( vsv, data, sizeof(data) ) );
  FD_TEST( !fd_vote_state_versioned_serialize( vsv, big,  sizeof(big)  ) );
  FD_TEST( fd_memeq( big, data, FD_VOTE_STATE_V5_SZ ) );
  for( ulong i=FD_VOTE_STATE_V5_SZ; i<sizeof(big); i++ ) FD_TEST( big[ i ]==0xAB );

  FD_TEST( fd_vote_state_versioned_new( vsv, fd_vote_state_versioned_enum_v5 ) );
  FD_TEST( fd_vote_state_versioned_serialize( vsv, data, sizeof(data) )==1 );
  vsv->v5.location = LOC;
  FD_TEST( !fd_vote_state_versioned_serialize( vsv, data, sizeof(data) ) && fd_vote_account_is_valid_v5( data, sizeof(data) ) );
  FD_TEST( vsv->v5.latest_vote==ULONG_MAX && vsv->v5.root_slot==ULONG_MAX );
}

static void
test_v5_accessors( void ) {
  static fd_vote_state_versioned_t vsv[1];
  uchar storage[ FD_VOTE_STATE_V5_SZ+4UL ] __attribute__((aligned(8)));
  for( ulong off=0UL; off<4UL; off++ ) {
    uchar * data = storage+off;
    make_v5( vsv );
    FD_TEST( !fd_vote_state_versioned_serialize( vsv, data, FD_VOTE_STATE_V5_SZ ) );
    ulong sz = FD_VOTE_STATE_V5_SZ;

    fd_pubkey_t               pk, a, b;
    ushort                    bps;
    ulong                     pending;
    fd_vote_block_timestamp_t ts;
    fd_validator_location_t   loc;
    uchar                     bls[ FD_BLS_PUBKEY_COMPRESSED_SZ ];
    FD_TEST( fd_vote_account_is_valid_v5( data, sz ) );
    FD_TEST( !fd_vote_account_node_pubkey( data, sz, &pk ) && pk.uc[ 0 ]==0x11 );
    FD_TEST( !fd_vote_account_commission_bps( data, sz, 1, &bps ) && bps==4321 );
    FD_TEST( !fd_vote_account_commission_bps( data, sz, 0, &bps ) && bps==4300 );
    FD_TEST( !fd_vote_account_block_revenue_commission_bps( data, sz, &bps ) && bps==5678 );
    FD_TEST( !fd_vote_account_pending_delegator_rewards( data, sz, &pending ) && pending==999UL );
    FD_TEST( !fd_vote_account_collectors( data, sz, &pk, &pk, &a, &b ) && a.uc[ 0 ]==0x33 && b.uc[ 0 ]==0x44 );
    FD_TEST( !fd_vote_account_authorized_voter( data, sz, 10UL, &a ) && a.uc[ 0 ]==0x60 );
    FD_TEST( !fd_vote_account_authorized_voter( data, sz, 99UL, &a ) && a.uc[ 0 ]==0x61 );
    FD_TEST(  fd_vote_account_authorized_voter( data, sz,  9UL, &a ) );
    FD_TEST( !fd_vote_account_last_timestamp( data, sz, &ts ) && ts.slot==4242UL && ts.timestamp==1700000000L );
    FD_TEST(  fd_vote_account_has_bls_pubkey( data, sz ) );
    FD_TEST( !fd_vote_account_bls_pubkey( data, sz, bls ) && bls[ 0 ]==0x55 );
    loc = fd_vote_account_location( data, sz );
    FD_TEST( loc.x==LOC.x && loc.y==LOC.y && loc.z==LOC.z );
    ulong ec_cnt; fd_vote_epoch_credits_t const * ec = fd_vote_account_epoch_credits( data, sz, &ec_cnt );
    FD_TEST( ec && ec_cnt==2UL && ec[ 1 ].epoch==8UL && ec[ 1 ].credits==200UL );
    FD_TEST( fd_vsv_is_correct_size_and_initialized( data, sz ) );
    FD_TEST( !fd_vsv_is_correct_size_and_initialized( data, sz-1UL ) );

    FD_TEST( !fd_vote_account_add_pending_delegator_rewards( data, sz, 1UL ) );
    FD_TEST( !fd_vote_account_pending_delegator_rewards( data, sz, &pending ) && pending==1000UL );
    ulong old; FD_TEST( !fd_vote_account_reset_pending_delegator_rewards( data, sz, &old ) && old==1000UL );

    for( ulong bad_sz=sz-1UL; bad_sz<=sz+1UL; bad_sz+=2UL ) {
      FD_TEST( !fd_vote_account_is_valid_v5( data, bad_sz ) );
      FD_TEST(  fd_vote_account_commission_bps( data, bad_sz, 1, &bps ) );
      FD_TEST(  fd_vote_account_block_revenue_commission_bps( data, bad_sz, &bps ) );
      FD_TEST(  fd_vote_account_pending_delegator_rewards( data, bad_sz, &pending ) );
      FD_TEST(  fd_vote_account_add_pending_delegator_rewards( data, bad_sz, 1UL )==1 );
      FD_TEST(  fd_vote_account_reset_pending_delegator_rewards( data, bad_sz, &old )==1 );
      FD_TEST(  fd_vote_account_collectors( data, bad_sz, &pk, &pk, &a, &b ) );
      FD_TEST(  fd_vote_account_authorized_voter( data, bad_sz, 10UL, &a ) );
      FD_TEST(  fd_vote_account_last_timestamp( data, bad_sz, &ts ) );
      FD_TEST( !fd_vote_account_has_bls_pubkey( data, bad_sz ) );
      FD_TEST( !fd_vote_account_epoch_credits( data, bad_sz, &ec_cnt ) );
      loc = fd_vote_account_location( data, bad_sz );
      FD_TEST( !loc.x && !loc.y && !loc.z );
    }

    FD_STORE( uint, data+304, 9U );
    FD_TEST( !fd_vote_account_is_valid_v5( data, sz ) );
    loc = fd_vote_account_location( data, sz );
    FD_TEST( !loc.x && !loc.y && !loc.z );
    FD_TEST( fd_vote_account_authorized_voter( data, sz, 10UL, &a ) );
    FD_STORE( uint, data+308, 6U );
    FD_TEST( !fd_vote_account_epoch_credits( data, sz, &ec_cnt ) );
    FD_STORE( uint, data+152, 0x10002U );
    FD_TEST( fd_vote_account_commission_bps( data, sz, 1, &bps ) );
    FD_STORE( uint, data+152, 0U );
    FD_TEST( fd_vote_account_commission_bps( data, sz, 1, &bps ) );
    FD_STORE( uint, data+156, 5U );
    FD_TEST( fd_vote_account_block_revenue_commission_bps( data, sz, &bps ) );
  }

  make_v5( vsv );
  fd_memset( vsv->v5.node_pubkey.uc,                 0, 32UL );
  fd_memset( vsv->v5.authorized_withdrawer.uc,       0, 32UL );
  fd_memset( vsv->v5.inflation_rewards_collector.uc, 0, 32UL );
  fd_memset( vsv->v5.block_revenue_collector.uc,     0, 32UL );
  FD_TEST( !fd_vote_state_versioned_serialize( vsv, storage, FD_VOTE_STATE_V5_SZ ) );
  FD_TEST( fd_vsv_is_correct_size_and_initialized( storage, FD_VOTE_STATE_V5_SZ ) );

  uchar v4[ FD_VOTE_STATE_V4_SZ ] = {0};
  FD_STORE( uint, v4, fd_vote_state_versioned_enum_v4 );
  FD_TEST( !fd_vote_account_has_bls_pubkey( v4, sizeof(v4) ) );
}

static void
test_update_location_decode( void ) {
  static fd_vote_instruction_t ix[1];
  uchar data[ 17 ];
  FD_STORE( uint, data,      20U     );
  FD_STORE( int,  data+4UL,  4051542 );
  FD_STORE( int,  data+8UL,  -618526 );
  FD_STORE( int,  data+12UL, INT_MIN );
  data[ 16 ] = 0xFF;
  FD_TEST( fd_vote_instruction_deserialize( ix, data, 16UL ) );
  FD_TEST( ix->discriminant==fd_vote_instruction_enum_update_location );
  FD_TEST( ix->update_location.x==4051542 && ix->update_location.y==-618526 && ix->update_location.z==INT_MIN );
  FD_TEST( fd_vote_instruction_deserialize( ix, data, 17UL ) );
  FD_TEST( !fd_vote_instruction_deserialize( ix, data, 15UL ) );
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

  test_v5_codec();
  test_v5_accessors();
  test_update_location_decode();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
