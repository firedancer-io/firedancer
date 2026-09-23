#include "fd_admin_tile.c"

#include <stdio.h>
#include <unistd.h>

static fd_admin_tile_ctx_t ctx;
static uchar ctl_mem[ 2048 ] __attribute__((aligned(FD_ADMINCTL_ALIGN)));
static uchar bus_mem[ 4096 ] __attribute__((aligned(128)));

/* A fake stem, publishing records the frag instead of writing an
   mcache, so the forwarding path runs without a topology. */
static fd_frag_meta_t   pub_mcache[ 8 ];
static ulong            pub_seq;
static ulong            pub_depth = 8UL;
static ulong            pub_cr_avail;
static ulong            pub_min_cr_avail;
static int              pub_reliable;
static fd_stem_context_t stem[1];

static void
stem_init( void ) {
  static fd_frag_meta_t * mcaches[ 1 ];
  static ulong            seqs[ 1 ];
  static ulong            depths[ 1 ];
  mcaches[ 0 ] = pub_mcache;
  seqs[ 0 ]    = 0UL;
  depths[ 0 ]  = pub_depth;
  pub_seq          = 0UL;
  pub_cr_avail     = 64UL;
  pub_min_cr_avail = 64UL;
  pub_reliable     = 0;
  *stem = (fd_stem_context_t){
    .mcaches = mcaches, .seqs = seqs, .depths = depths,
    .cr_avail = &pub_cr_avail, .min_cr_avail = &pub_min_cr_avail,
    .cr_decrement_amount = 1UL, .out_reliable = &pub_reliable,
  };
}

static ulong
request( ulong cmd, void const * data, ulong sz, void ** payload ) {
  ulong max;
  ulong idx = fd_adminctl_reserve( ctx.adminctl, payload, &max );
  FD_TEST( idx!=ULONG_MAX && sz<=max );
  fd_memcpy( *payload, data, sz );
  fd_adminctl_publish( ctx.adminctl, idx, cmd, sz );
  for( ulong i=0UL; i<FD_ADMINCTL_SLOT_CNT; i++ ) {
    ulong got_idx;
    ulong got_sz;
    ulong got_cmd = fd_adminctl_poll( ctx.adminctl, &got_idx, payload, &got_sz );
    if( got_cmd==FD_ADMINCTL_CMD_IDLE ) continue;
    FD_TEST( got_cmd==cmd && got_idx==idx && got_sz==sz );
    return idx;
  }
  FD_LOG_ERR(( "command was not polled" ));
}

static void
test_status_abi( void ) {
  /* The admin tile validates the ABI before anything reaches the bus, so
     a malformed request never occupies the parked slot. */
  ctx.failover_enabled = 0;
  ulong versions[] = { 2UL, FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION, ULONG_MAX };
  ulong sizes[] = { 0UL, 7UL, 8UL, 15UL, 16UL, 17UL, FD_ADMINCTL_PAYLOAD_MAX };
  for( ulong v=0UL; v<sizeof(versions)/sizeof(versions[0]); v++ ) {
    for( ulong s=0UL; s<sizeof(sizes)/sizeof(sizes[0]); s++ ) {
      uchar data[ FD_ADMINCTL_PAYLOAD_MAX ] = {0};
      FD_STORE( ulong, data, versions[v] );
      void * payload;
      ulong idx = request( FD_ADMINCTL_CMD_FAILOVER_STATUS, data, sizes[s], &payload );
      failover_status( &ctx, stem, idx, payload, sizes[s] );
      fd_adminctl_failover_status_resp_t resp;
      fd_memset( &resp, 0xA5, sizeof(resp) );
      ulong out_sz;
      ulong result = fd_adminctl_wait_response( ctx.adminctl, idx, &resp, sizeof(resp), &out_sz );
      ulong expected = sizes[s]<8UL ? FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH
                     : versions[v]!=FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION ? FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH
                     : sizes[s]!=16UL ? FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH
                     : FD_ADMINCTL_RESULT_SUCCESS;
      FD_TEST( result==expected );
      FD_TEST( ctx.failover_status_slot_idx==ULONG_MAX );
      if( expected ) { FD_TEST( !out_sz ); continue; }
      /* Failover disabled is answered locally, without the bus. */
      FD_TEST( out_sz==sizeof(resp) && resp.version==FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION );
      FD_TEST( !resp.enabled && !resp.member_cnt && !resp.self_idx && !resp.peer_idx && !resp.peers_paired );
      FD_TEST( resp.peer_status_age_nanos==ULONG_MAX && resp.replication_lag_slots==ULONG_MAX );
      for( ulong i=0UL; i<sizeof(resp.reserved); i++ ) FD_TEST( !resp.reserved[i] );
    }
  }
  FD_LOG_NOTICE(( "pass: failover status ABI rejects old versions and malformed sizes" ));
}

static void
test_installed_identity_query( void ) {
  stem_init();
  ctx.failover_enabled = 1;
  ctx.failov_out_idx   = 0UL;
  ctx.failov_out_mem   = (fd_wksp_t *)bus_mem;
  ctx.failov_out_chunk = ctx.failov_out_chunk0 = ctx.failov_out_wmark = 0UL;
  fd_memset( &ctx.failov_resp, 0, sizeof(ctx.failov_resp) );
  ctx.failov_resp.nonce = 77UL;
  fd_memset( ctx.failover_junk_pubkey, 0x11, 32UL );
  fd_memset( ctx.failover_staked_pubkey, 0x22, 32UL );
  ulong expected[] = { FD_FAILOVER_SWITCH_STATE_JUNK, FD_FAILOVER_SWITCH_STATE_STAKED, FD_FAILOVER_SWITCH_STATE_FOREIGN };
  for( ulong i=0UL; i<3UL; i++ ) {
    fd_memset( ctx.identity_pubkey, (int)(0x11UL*(i+1UL)), 32UL );
    failover_switch_query( &ctx, stem );
    fd_failover_bus_msg_t const * msg = (fd_failover_bus_msg_t const *)bus_mem;
    fd_failover_switch_resp_t answer;
    fd_memcpy( &answer, msg->payload, sizeof(answer) );
    FD_TEST( pub_mcache[ i ].sig==FD_FAILOVER_BUS_SWITCH_STATE );
    FD_TEST( msg->nonce==77UL && answer.result==expected[ i ] );
    FD_TEST( answer.tower_watermark==ULONG_MAX && fd_memeq( answer.identity, ctx.identity_pubkey, 32UL ) );
  }
  ctx.failover_enabled = 0;
  fd_memcpy( ctx.identity_pubkey, ctx.failover_junk_pubkey, 32UL );
  failover_switch_query( &ctx, stem );
  FD_TEST( ((fd_failover_bus_msg_t *)bus_mem)->result==FD_FAILOVER_SWITCH_STATE_FOREIGN );
  stem_init();
  FD_LOG_NOTICE(( "pass: installed identity queries report junk, staked, foreign and disabled without switching" ));
}

static fd_failover_bus_msg_t *
published_request( void ) {
  FD_TEST( pub_mcache[ 0 ].sig==FD_FAILOVER_BUS_STATUS_REQ );
  FD_TEST( pub_mcache[ 0 ].sz==sizeof(fd_failover_bus_msg_t) );
  return (fd_failover_bus_msg_t *)bus_mem;
}

static void
test_bus_forwarding( void ) {
  /* With failover enabled the command is forwarded to the failover tile and
     the slot stays parked until the response comes back. */
  FD_TEST( sizeof(fd_failover_bus_msg_t)<=sizeof(bus_mem) );
  ctx.failover_enabled         = 1;
  ctx.failov_out_idx           = 0UL;
  ctx.failov_out_mem           = NULL;
  ctx.failov_in_idx            = 0UL;
  ctx.failover_status_slot_idx = ULONG_MAX;

  /* The bus buffer stands in for the dcache chunk. */
  ctx.failov_out_chunk0 = 0UL;
  ctx.failov_out_wmark  = 0UL;
  ctx.failov_out_chunk  = 0UL;
  ctx.failov_out_mem    = (fd_wksp_t *)bus_mem; /* chunk 0 maps to bus_mem */

  fd_adminctl_failover_status_req_t req = { .version=FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION, .peer_idx=0UL };
  void * payload;
  ulong idx = request( FD_ADMINCTL_CMD_FAILOVER_STATUS, &req, sizeof(req), &payload );
  failover_status( &ctx, stem, idx, payload, sizeof(req) );
  FD_TEST( ctx.failover_status_slot_idx==idx && ctx.failover_status_nonce==1UL );
  fd_failover_bus_msg_t * sent = published_request();
  FD_TEST( sent->nonce==1UL );
  FD_TEST( ((fd_adminctl_failover_status_req_t *)sent->payload)->version==FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION );

  /* A second request while one is parked is answered busy. */
  void * payload2;
  ulong idx2 = request( FD_ADMINCTL_CMD_FAILOVER_STATUS, &req, sizeof(req), &payload2 );
  failover_status( &ctx, stem, idx2, payload2, sizeof(req) );
  FD_TEST( fd_adminctl_wait( ctx.adminctl, idx2 )==FD_FAILOVER_STATUS_RESULT_BUSY );
  FD_TEST( ctx.failover_status_slot_idx==idx );

  /* A response with a stale nonce is dropped, the slot stays parked. */
  fd_memset( &ctx.failov_resp, 0, sizeof(ctx.failov_resp) );
  ctx.failov_resp.nonce  = 99UL;
  ctx.failov_resp.result = FD_ADMINCTL_RESULT_SUCCESS;
  failover_status_response( &ctx, FD_FAILOVER_BUS_STATUS_RESP );
  FD_TEST( ctx.failover_status_slot_idx==idx );

  /* The matching response completes the command with the tile's payload. */
  fd_adminctl_failover_status_resp_t answer;
  fd_memset( &answer, 0, sizeof(answer) );
  answer.version    = FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION;
  answer.enabled    = 1U;
  answer.member_cnt = 2U;
  answer.self_idx   = 1U;
  ctx.failov_resp.nonce  = 1UL;
  ctx.failov_resp.result = FD_ADMINCTL_RESULT_SUCCESS;
  fd_memcpy( ctx.failov_resp.payload, &answer, sizeof(answer) );
  failover_status_response( &ctx, FD_FAILOVER_BUS_STATUS_RESP );
  fd_adminctl_failover_status_resp_t got;
  ulong got_sz;
  FD_TEST( !fd_adminctl_wait_response( ctx.adminctl, idx, &got, sizeof(got), &got_sz ) );
  FD_TEST( got_sz==sizeof(got) && got.enabled && got.member_cnt==2U && got.self_idx==1U );
  FD_TEST( ctx.failover_status_slot_idx==ULONG_MAX );
  FD_LOG_NOTICE(( "pass: failover status forwards over the bus, busy while parked, stale nonce dropped" ));
}

static void
test_bus_unresponsive( void ) {
  /* A failover tile that never answers must not wedge the CLI. */
  fd_adminctl_failover_status_req_t req = { .version=FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION };
  void * payload;
  ulong idx = request( FD_ADMINCTL_CMD_FAILOVER_STATUS, &req, sizeof(req), &payload );
  failover_status( &ctx, stem, idx, payload, sizeof(req) );
  FD_TEST( ctx.failover_status_slot_idx==idx );
  ctx.failover_status_deadline = fd_log_wallclock()-1L;
  failover_status_complete( &ctx, FD_FAILOVER_STATUS_RESULT_UNRESPONSIVE, NULL, 0UL );
  ulong sz;
  FD_TEST( fd_adminctl_wait_response( ctx.adminctl, idx, NULL, 0UL, &sz )==FD_FAILOVER_STATUS_RESULT_UNRESPONSIVE );
  FD_TEST( !sz && ctx.failover_status_slot_idx==ULONG_MAX );
  FD_LOG_NOTICE(( "pass: a silent failover tile completes the command as unresponsive" ));
}

static void
test_identity_guard( void ) {
  static fd_admin_tile_ctx_t saved;
  fd_adminctl_set_identity_t req = { .version=FD_ADMINCTL_SET_IDENTITY_PAYLOAD_VERSION, .keypair={1} };
  fd_ed25519_public_from_private( req.keypair+32UL, req.keypair, ctx.sha512 );
  for( uint flags=1U; flags<4U; flags++ ) {
    ctx.failover_enabled   = !!(flags & 1U);
    ctx.tower_file_enabled = !!(flags & 2U);
    void * payload;
    ulong idx = request( FD_ADMINCTL_CMD_SET_IDENTITY, &req, sizeof(req), &payload );
    saved = ctx;
    /* A valid key must be refused before any topology or keyswitch
       access.  The context intentionally has no topology attached. */
    set_identity( &ctx, idx, payload, sizeof(req) );
    FD_TEST( fd_adminctl_wait( ctx.adminctl, idx )==FD_ADMINCTL_RESULT_UNSUPPORTED );
    FD_TEST( fd_memeq( &ctx, &saved, sizeof(ctx) ) );
    for( ulong i=0UL; i<sizeof(req); i++ ) FD_TEST( !((uchar *)payload)[i] );
  }
  ctx.failover_enabled = ctx.tower_file_enabled = 0;
  FD_LOG_NOTICE(( "pass: failover and tower-file identity guards" ));
}

/* Exercise both request formats through the halt/drain/switch sequence.
   Two sign tiles must both complete before any producer is unhalted. */
static void
test_identity_switch_ordering( void ) {
  enum { REPLAY, TOWER, TXSEND, REPAIR, GOSSIP, BUNDLE, RSERVE, SHRED,
         SIGN0, SIGN1, GOSSVF, GUI, EVENT, TILE_CNT };
  static char const * names[ TILE_CNT ] = {
    "replay", "tower", "txsend", "repair", "gossip", "bundle", "rserve",
    "shred", "sign", "sign", "gossvf", "gui", "event"
  };
  static fd_topo_t topo;
  static fd_keyswitch_t ks[ TILE_CNT+1 ];
  fd_memset( &topo, 0, sizeof(topo) );
  topo.tile_cnt = TILE_CNT;
  topo.workspaces[ 0 ].wksp = fd_type_pun( ks );
  for( ulong i=0UL; i<TILE_CNT; i++ ) {
    fd_cstr_ncpy( topo.tiles[ i ].name, names[ i ], sizeof(topo.tiles[ i ].name) );
    topo.tiles[ i ].kind_id = (ulong)( i==SIGN1 );
    topo.tiles[ i ].id_keyswitch_obj_id = i;
    topo.objs[ i ].id     = i;
    topo.objs[ i ].offset = (i+1UL)*sizeof(fd_keyswitch_t);
  }
  ctx.topo = &topo;
  fd_keyswitch_t * k = ks+1;
  for( int resident=0; resident<2; resident++ ) {
    for( ulong i=0UL; i<TILE_CNT; i++ ) {
      FD_TEST( fd_keyswitch_new( &k[ i ], FD_KEYSWITCH_STATE_UNLOCKED ) );
      fd_memset( k[ i ].bytes, 0xA5, 64UL );
    }
    uchar keypair[ 64 ];
    fd_memset( keypair,      0x33, 32UL );
    fd_memset( keypair+32UL, 0x55, 32UL );
    uchar const * public_key = keypair+32UL;
    uchar * private_key = resident ? NULL : keypair;
    ulong state = FD_SET_IDENTITY_STATE_UNLOCKED;
    ulong halted_seq = 0UL;
    ulong outset = 1234UL;
#define POLL() FD_TEST( !poll_set_identity( &ctx, &state, &halted_seq, outset, public_key, private_key ) )
    POLL();
    POLL();
    FD_TEST( k[ REPLAY ].state==FD_KEYSWITCH_STATE_SWITCH_PENDING );
    FD_TEST( fd_memeq( k[ REPLAY ].bytes, public_key, 32UL ) );
    POLL();
    FD_TEST( k[ TOWER ].state==FD_KEYSWITCH_STATE_UNLOCKED );
    k[ REPLAY ].result = 17UL;
    k[ REPLAY ].state = FD_KEYSWITCH_STATE_COMPLETED;
    POLL();
    FD_TEST( halted_seq==17UL );
    POLL();
    POLL();
    FD_TEST( k[ TXSEND ].state==FD_KEYSWITCH_STATE_UNLOCKED );
    FD_TEST( k[ SIGN0 ].state==FD_KEYSWITCH_STATE_UNLOCKED );
    for( ulong i=TOWER; i<=SHRED; i++ ) {
      if( i==TXSEND ) continue;
      FD_TEST( k[ i ].state==FD_KEYSWITCH_STATE_SWITCH_PENDING );
      FD_TEST( fd_memeq( k[ i ].bytes, public_key, 32UL ) );
      k[ i ].state = FD_KEYSWITCH_STATE_COMPLETED;
    }
    k[ TOWER ].result = 37UL;
    POLL();
    POLL();
    FD_TEST( k[ TXSEND ].state==FD_KEYSWITCH_STATE_SWITCH_PENDING );
    FD_TEST( k[ TXSEND ].param==37UL );
    FD_TEST( fd_memeq( k[ TXSEND ].bytes, public_key, 32UL ) );
    POLL();
    FD_TEST( state==FD_SET_IDENTITY_STATE_TXSEND_FLUSH_REQUESTED );
    FD_TEST( k[ SIGN0 ].state==FD_KEYSWITCH_STATE_UNLOCKED );
    FD_TEST( k[ SIGN1 ].state==FD_KEYSWITCH_STATE_UNLOCKED );
    k[ TXSEND ].state = FD_KEYSWITCH_STATE_COMPLETED;
    POLL();
    POLL();
    for( ulong i=SIGN0; i<=SIGN1; i++ ) {
      FD_TEST( k[ i ].state==FD_KEYSWITCH_STATE_SWITCH_PENDING );
      if( resident ) {
        FD_TEST( k[ i ].param==FD_KEYSWITCH_PARAM_IDENTITY_PUBKEY );
        FD_TEST( fd_memeq( k[ i ].bytes, public_key, 32UL ) );
        for( ulong j=32UL; j<64UL; j++ ) FD_TEST( !k[ i ].bytes[ j ] );
      } else {
        FD_TEST( k[ i ].param==FD_KEYSWITCH_PARAM_IDENTITY_KEYPAIR );
        for( ulong j=0UL; j<32UL; j++ ) FD_TEST( k[ i ].bytes[ j ]==0x33 );
        FD_TEST( fd_memeq( k[ i ].bytes+32UL, public_key, 32UL ) );
      }
    }
    if( !resident ) for( ulong i=0UL; i<32UL; i++ ) FD_TEST( !keypair[ i ] );
    FD_TEST( k[ GOSSVF ].param==outset );
    for( ulong i=GOSSVF; i<TILE_CNT; i++ ) {
      FD_TEST( fd_memeq( k[ i ].bytes, public_key, 32UL ) );
      k[ i ].state = FD_KEYSWITCH_STATE_COMPLETED;
    }
    POLL();
    k[ SIGN0 ].state = FD_KEYSWITCH_STATE_COMPLETED;
    POLL();
    FD_TEST( state==FD_SET_IDENTITY_STATE_ALL_SWITCH_REQUESTED );
    FD_TEST( k[ TOWER ].state==FD_KEYSWITCH_STATE_COMPLETED );
    FD_TEST( k[ TXSEND ].state==FD_KEYSWITCH_STATE_COMPLETED );
    k[ SIGN1 ].state = FD_KEYSWITCH_STATE_COMPLETED;
    POLL();
    for( ulong i=SIGN0; i<=SIGN1; i++ )
      for( ulong j=0UL; j<64UL; j++ ) FD_TEST( !k[ i ].bytes[ j ] );
    POLL();
    POLL();
    FD_TEST( k[ REPLAY ].state==FD_KEYSWITCH_STATE_COMPLETED );
    for( ulong i=TOWER; i<SHRED; i++ ) {
      FD_TEST( k[ i ].state==FD_KEYSWITCH_STATE_UNHALT_PENDING );
      k[ i ].state = FD_KEYSWITCH_STATE_COMPLETED;
    }
    POLL();
    POLL();
    FD_TEST( k[ REPLAY ].state==FD_KEYSWITCH_STATE_UNHALT_PENDING );
    POLL();
    k[ REPLAY ].state = FD_KEYSWITCH_STATE_COMPLETED;
    FD_TEST( poll_set_identity( &ctx, &state, &halted_seq, outset, public_key, private_key ) );
    FD_TEST( state==FD_SET_IDENTITY_STATE_UNLOCKED );
    FD_TEST( k[ REPLAY ].state==FD_KEYSWITCH_STATE_UNLOCKED );
#undef POLL
  }
  ctx.topo = NULL;
  FD_LOG_NOTICE(( "pass: public-key selection and manual keypair switches preserve drain and completion ordering" ));
}

static void
test_authorized_voter_refusal( void ) {
  fd_keyswitch_t tower;
  fd_keyswitch_t signs[ 2 ];
  FD_TEST( fd_keyswitch_new( &tower, FD_KEYSWITCH_STATE_UNLOCKED ) );
  ctx.tower_av_keyswitch = &tower;
  ctx.sign_av_keyswitch_cnt = 2UL;
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_TEST( fd_keyswitch_new( &signs[ i ], FD_KEYSWITCH_STATE_UNLOCKED ) );
    ctx.sign_av_keyswitch[ i ] = &signs[ i ];
  }
  uchar keypair[ 64 ];
  fd_memset( keypair, 0x33, sizeof(keypair) );
  ulong state = FD_ADD_AUTH_VOTER_STATE_UNLOCKED;
  ulong result = FD_ADMINCTL_RESULT_SUCCESS;
  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  FD_TEST( tower.state==FD_KEYSWITCH_STATE_LOCKED );
  for( ulong i=0UL; i<32UL; i++ ) FD_TEST( !keypair[ i ] );
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_TEST( signs[ i ].state==FD_KEYSWITCH_STATE_SWITCH_PENDING );
    signs[ i ].result = FD_ADMINCTL_RESULT_UNSUPPORTED;
    signs[ i ].state = FD_KEYSWITCH_STATE_FAILED;
    poll_add_authorized_voter( &ctx, &state, keypair, &result );
    FD_TEST( result==FD_ADMINCTL_RESULT_UNSUPPORTED );
    if( !i ) FD_TEST( state==FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_REQUESTED );
  }
  /* A rejected staked key must not reach the tower's authorized set. */
  FD_TEST( state==FD_ADD_AUTH_VOTER_STATE_TOWER_TILE_UPDATED );
  for( ulong i=0UL; i<64UL; i++ ) FD_TEST( !tower.bytes[ i ] );
  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  FD_TEST( tower.state==FD_KEYSWITCH_STATE_UNHALT_PENDING );
  tower.state = FD_KEYSWITCH_STATE_UNLOCKED;
  poll_add_authorized_voter( &ctx, &state, keypair, &result );
  FD_TEST( state==FD_ADD_AUTH_VOTER_STATE_UNLOCKED );
  ctx.tower_av_keyswitch = NULL;
  ctx.sign_av_keyswitch_cnt = 0UL;
  ctx.sign_av_keyswitch[ 0 ] = ctx.sign_av_keyswitch[ 1 ] = NULL;
  FD_LOG_NOTICE(( "pass: a refused authorized voter is reported after both signers answer without changing tower" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  FD_TEST( fd_adminctl_footprint()<=sizeof(ctl_mem) );
  ctx.adminctl = fd_adminctl_join( fd_adminctl_new( ctl_mem ) );
  FD_TEST( ctx.adminctl );
  fd_sha512_join( fd_sha512_new( ctx.sha512 ) );
  ctx.failover_status_slot_idx = ULONG_MAX;
  ctx.snap_create_slot_idx     = ULONG_MAX;
  stem_init();
  test_identity_guard();
  test_status_abi();
  test_installed_identity_query();
  test_bus_forwarding();
  test_bus_unresponsive();
  test_identity_switch_ordering();
  test_authorized_voter_refusal();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
