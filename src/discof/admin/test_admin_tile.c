#include "fd_admin_tile.c"
#include "../failover/fd_failover_proto.h"
#include "../../util/net/fd_ip4.h"

static fd_admin_tile_ctx_t ctx;
static uchar ctl_mem[ 2048 ] __attribute__((aligned(FD_ADMINCTL_ALIGN)));
static uchar out_mem[ 4096 ] __attribute__((aligned(128)));
static uchar in_mem [ 4096 ] __attribute__((aligned(128)));

static fd_frag_meta_t    pub_mcache[ 8 ];
static ulong             pub_seq;
static ulong             pub_cr_avail;
static ulong             pub_min_cr_avail;
static int               pub_reliable;
static fd_stem_context_t stem[1];

static void
stem_init( void ) {
  static fd_frag_meta_t * mcaches[ 1 ];
  static ulong            depths[ 1 ];
  mcaches[ 0 ]     = pub_mcache;
  depths[ 0 ]      = 8UL;
  pub_seq          = 0UL;
  pub_cr_avail     = 64UL;
  pub_min_cr_avail = 64UL;
  pub_reliable     = 0;
  fd_memset( pub_mcache, 0, sizeof(pub_mcache) );
  *stem = (fd_stem_context_t){
    .mcaches = mcaches, .seqs = &pub_seq, .depths = depths,
    .cr_avail = &pub_cr_avail, .min_cr_avail = &pub_min_cr_avail,
    .cr_decrement_amount = 1UL, .out_reliable = &pub_reliable,
  };
}

static void
bus_init( void ) {
  stem_init();
  ctx.failover_enabled  = 1;
  ctx.failover_slot_idx = ULONG_MAX;
  ctx.failov_out_idx    = 0UL;
  ctx.failov_out_mem    = (fd_wksp_t *)out_mem;
  ctx.failov_out_chunk0 = ctx.failov_out_wmark = ctx.failov_out_chunk = 0UL;
  ctx.failov_in_idx     = 0UL;
  ctx.failov_in_mem     = (fd_wksp_t *)in_mem;
  ctx.failov_in_chunk0  = ctx.failov_in_wmark = 0UL;
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
failov_send( ulong sig, ulong nonce, ulong result, void const * payload, ulong payload_sz, int overrun ) {
  fd_failover_bus_msg_t * msg = (fd_failover_bus_msg_t *)in_mem;
  fd_memset( msg, 0, sizeof(*msg) );
  msg->nonce  = nonce;
  msg->result = result;
  fd_memcpy( msg->payload, payload, payload_sz );
  during_frag( &ctx, 0UL, 0UL, sig, 0UL, sizeof(*msg), 0UL );
  if( !overrun ) after_frag( &ctx, 0UL, 0UL, sig, sizeof(*msg), 0UL, 0UL, stem );
}

static uchar                            ev_mcache_mem[ 4096 ] __attribute__((aligned(FD_MCACHE_ALIGN)));
static uchar                            ev_mem[ 1024 ] __attribute__((aligned(FD_CHUNK_ALIGN)));
static fd_event_reporter_t              ev_reporter;
static fd_event_admin_command_t const * ev = (fd_event_admin_command_t const *)ev_mem;

static void
ev_init( void ) {
  FD_TEST( fd_mcache_footprint( 8UL, 0UL )<=sizeof(ev_mcache_mem) );
  fd_frag_meta_t * mcache = fd_mcache_join( fd_mcache_new( ev_mcache_mem, 8UL, 0UL, 0UL ) );
  FD_TEST( mcache );
  fd_memset( ev_mem, 0, sizeof(ev_mem) );
  ev_reporter = (fd_event_reporter_t){ .mcache=mcache, .depth=8UL, .seq_store=fd_mcache_seq_laddr( mcache ),
                                       .mem=(fd_wksp_t *)ev_mem, .mtu=sizeof(ev_mem) };
  fd_event_tl = &ev_reporter;
}

static int
ev_was( int type, int result ) {
  int ok = ev->type==type && ev->result==result;
  fd_memset( ev_mem, 0, sizeof(ev_mem) );
  return ok;
}

static ulong
control( ulong cmd, ulong flags ) {
  fd_adminctl_failover_control_t req = { .version=FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION, .cmd=cmd, .flags=flags };
  void * payload;
  ulong idx = request( FD_ADMINCTL_CMD_FAILOVER_CONTROL, &req, sizeof(req), &payload );
  failover_control( &ctx, stem, idx, payload, sizeof(req) );
  return idx;
}

static void
test_identity_guard( void ) {
  static fd_admin_tile_ctx_t saved;
  fd_adminctl_set_identity_t req = { .version=FD_ADMINCTL_SET_IDENTITY_PAYLOAD_VERSION, .keypair={1} };
  fd_ed25519_public_from_private( req.keypair+32UL, req.keypair, ctx.sha512 );
  ctx.failover_enabled = 1;
  ev_init();
  void * payload;
  ulong idx = request( FD_ADMINCTL_CMD_SET_IDENTITY, &req, sizeof(req), &payload );
  saved = ctx;
  set_identity( &ctx, idx, payload, sizeof(req) );
  FD_TEST( fd_adminctl_wait( ctx.adminctl, idx )==FD_ADMINCTL_RESULT_UNSUPPORTED );
  FD_TEST( ev_was( FD_EVENT_ADMIN_COMMAND_TYPE_SET_IDENTITY, FD_EVENT_ADMIN_COMMAND_RESULT_UNSUPPORTED ) );
  fd_event_tl = NULL;
  FD_TEST( fd_memeq( &ctx, &saved, sizeof(ctx) ) );
  for( ulong i=0UL; i<sizeof(req); i++ ) FD_TEST( !((uchar *)payload)[ i ] );
  ctx.failover_enabled = 0;
  FD_LOG_NOTICE(( "pass: set-identity refused under failover" ));
}

static void
test_bus_forwarding( void ) {
  bus_init();
  ulong idx = control( FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_YES|FD_ADMINCTL_FAILOVER_FLAG_FORCE );
  FD_TEST( ctx.failover_slot_idx==idx && pub_seq==1UL );
  FD_TEST( pub_mcache[ 0 ].sig==FD_FAILOVER_BUS_CONTROL_REQ && pub_mcache[ 0 ].sz==sizeof(fd_failover_bus_msg_t) );
  fd_failover_bus_msg_t const * sent = (fd_failover_bus_msg_t const *)out_mem;
  fd_adminctl_failover_control_t fwd;
  fd_memcpy( &fwd, sent->payload, sizeof(fwd) );
  ulong nonce = sent->nonce;
  FD_TEST( nonce==ctx.failover_nonce );
  FD_TEST( fwd.version==FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION );
  FD_TEST( fwd.cmd==FD_ADMINCTL_FAILOVER_CMD_PROMOTE && fwd.flags==(FD_ADMINCTL_FAILOVER_FLAG_YES|FD_ADMINCTL_FAILOVER_FLAG_FORCE) );

  fd_adminctl_failover_control_resp_t answer = { .version=FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION, .role=(uchar)FD_FAILOVER_ROLE_ACTIVE, .action=3 };
  failov_send( FD_FAILOVER_BUS_CONTROL_RESP, nonce, FD_ADMINCTL_RESULT_SUCCESS, &answer, sizeof(answer), 0 );
  FD_TEST( ctx.failover_slot_idx==ULONG_MAX );

  fd_adminctl_failover_control_resp_t got;
  ulong got_sz;
  FD_TEST( fd_adminctl_wait_response( ctx.adminctl, idx, &got, sizeof(got), &got_sz )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( got_sz==sizeof(got) && got.version==FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION );
  FD_TEST( got.role==FD_FAILOVER_ROLE_ACTIVE && got.action==3 );

  FD_LOG_NOTICE(( "pass: a failover command and its response pass over the admin bus" ));
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  FD_TEST( fd_adminctl_footprint()<=sizeof(ctl_mem) );
  ctx.adminctl = fd_adminctl_join( fd_adminctl_new( ctl_mem ) );
  FD_TEST( ctx.adminctl );
  FD_TEST( fd_sha512_join( fd_sha512_new( ctx.sha512 ) ) );
  ctx.replay_out_idx       = ULONG_MAX;
  ctx.snap_create_slot_idx = ULONG_MAX;
  ctx.failover_slot_idx    = ULONG_MAX;
  ctx.failov_out_idx       = ULONG_MAX;
  ctx.failov_in_idx        = ULONG_MAX;
  test_bus_forwarding();
  test_identity_guard();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
