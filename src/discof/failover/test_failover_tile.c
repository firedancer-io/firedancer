/* The tests reach into the channel, to read its dial address and to
   mark a session paired without a socket. */
#include "fd_failover_channel.c"
#include "fd_failover_tile.c"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../choreo/tower/fd_tower.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#define OWN_GOSSIP_ADDR FD_IP4_ADDR(10,0,0,1)
#define OWN_GOSSIP_PORT ((ushort)8001)

static fd_topo_t      topo;
static fd_topo_tile_t tiles[ 2 ];
static uchar          keys[ 3 ][ 64 ]; /* two junk keypairs, then the staked one */
static char           key_paths[ 3 ][ PATH_MAX ];
static char           vote_account[ FD_BASE58_ENCODED_32_SZ ];
static fd_wksp_t *    wksp;
static char           boot_peer_address[ FD_FQDN_BUF_MAX ]; /* [failover.peer_address] for the next boot */
static fd_sha512_t    sha[ 1 ];

static void
write_key( char const *  path,
           uchar const * key ) {
  FILE * file = fopen( path, "w" );
  FD_TEST( file );
  FD_TEST( fputc( '[', file )!=EOF );
  for( ulong i=0UL; i<64UL; i++ ) FD_TEST( fprintf( file, "%s%u", i ? "," : "", (uint)key[ i ] )>0 );
  FD_TEST( fputc( ']', file )!=EOF );
  FD_TEST( !fclose( file ) );
}

/* A link with a real mcache and dcache in the test workspace. */
static void
link_init( ulong        idx,
           char const * name,
           ulong        mtu ) {
  ulong            depth   = 128UL;
  ulong            data_sz = fd_dcache_req_data_sz( mtu, depth, 1UL, 1 );
  fd_topo_link_t * link    = &topo.links[ idx ];
  fd_cstr_ncpy( link->name, name, sizeof(link->name) );
  link->id            = idx;
  link->mtu           = mtu;
  link->dcache_obj_id = 2UL;
  link->mcache        = fd_mcache_join( fd_mcache_new( fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( depth, 0UL ), 1UL ), depth, 0UL, 0UL ) );
  link->dcache        = fd_dcache_join( fd_dcache_new( fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( data_sz, 0UL ), 1UL ), data_sz, 0UL ) );
  FD_TEST( link->mcache && link->dcache );
}

/* gossip_out and the two keyguard links to the sign tile, which the
   tests never use since they sign the member certificate themselves. */
static void
links_init( void ) {
  wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 4096UL, 0UL, "failov_test", 0UL );
  FD_TEST( wksp );
  topo.workspaces[ 1 ].wksp = wksp;
  topo.objs[ 2 ].id         = 2UL;
  topo.objs[ 2 ].wksp_id    = 1UL;
  topo.sleep_obj_id         = ULONG_MAX;
  topo.link_cnt             = 3UL;
  link_init( 0UL, "gossip_out",  sizeof(fd_gossip_update_message_t) );
  link_init( 1UL, "sign_failov", 64UL                               );
  link_init( 2UL, "failov_sign", FD_KEYGUARD_MEMBER_CERT_MSG_SZ     );
}

/* Boots tile idx through the real init path with junk key idx and
   gives it the member certificate the sign tile would.  Port zero binds
   an ephemeral listener. */
static fd_failover_tile_ctx_t *
boot( ulong idx ) {
  fd_topo_tile_t * tile = &tiles[ idx ];
  fd_memset( tile, 0, sizeof(fd_topo_tile_t) );
  tile->tile_obj_id      = idx;
  tile->in_cnt           = 2UL;
  tile->in_link_id[ 0 ]  = 0UL;
  tile->in_link_id[ 1 ]  = 1UL;
  tile->out_cnt          = 1UL;
  tile->out_link_id[ 0 ] = 2UL;
  fd_cstr_ncpy( tile->failov.identity_key_path, key_paths[ idx ], sizeof(tile->failov.identity_key_path) );
  fd_cstr_ncpy( tile->failov.staked_key_path,   key_paths[ 2 ],   sizeof(tile->failov.staked_key_path)   );
  fd_cstr_ncpy( tile->failov.vote_account_path, vote_account,     sizeof(tile->failov.vote_account_path) );
  tile->failov.port             = 0;
  fd_cstr_ncpy( tile->failov.peer_address, boot_peer_address, sizeof(tile->failov.peer_address) );
  tile->failov.gossip_addr.addr = OWN_GOSSIP_ADDR;
  tile->failov.gossip_addr.port = fd_ushort_bswap( OWN_GOSSIP_PORT );
  privileged_init  ( &topo, tile );
  unprivileged_init( &topo, tile );
  fd_failover_tile_ctx_t * ctx = fd_topo_obj_laddr( &topo, idx );
  FD_TEST( ctx->gossip_in_idx==0UL );

  uchar msg [ FD_KEYGUARD_MEMBER_CERT_MSG_SZ ];
  uchar cert[ 64 ];
  fd_failover_member_cert_msg( msg, keys[ idx ]+32UL );
  fd_ed25519_sign( cert, msg, sizeof(msg), keys[ 2 ]+32UL, keys[ 2 ], sha );
  FD_TEST( !fd_failover_channel_set_member_cert( ctx->channel, cert ) );
  ctx->member_cert_set = 1;
  return ctx;
}

/* Publishes one frag on the gossip link and runs it through the stem
   callbacks.  An overrun skips after_frag like the stem does. */
static void
gossip_frag( fd_failover_tile_ctx_t * ctx,
             ulong                    sig,
             uchar const *            origin,
             uint                     addr,
             ushort                   port,
             int                      is_ipv6,
             int                      overrun ) {
  ulong chunk = fd_dcache_compact_chunk0( wksp, topo.links[ 0 ].dcache );
  fd_gossip_update_message_t * msg = fd_chunk_to_laddr( wksp, chunk );
  fd_memset( msg, 0, sizeof(fd_gossip_update_message_t) );
  msg->tag = (int)sig;
  fd_memcpy( msg->origin, origin, 32UL );
  ulong sz = FD_GOSSIP_UPDATE_SZ_CONTACT_INFO_REMOVE;
  if( sig==FD_GOSSIP_UPDATE_TAG_CONTACT_INFO ) {
    fd_gossip_socket_t * socket = &msg->contact_info->value->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP ];
    socket->is_ipv6 = (uint)is_ipv6;
    socket->ip4     = addr;
    socket->port    = fd_ushort_bswap( port );
    sz = FD_GOSSIP_UPDATE_SZ_CONTACT_INFO;
  }
  if( before_frag( ctx, ctx->gossip_in_idx, 0UL, sig ) ) return;
  during_frag( ctx, ctx->gossip_in_idx, 0UL, sig, chunk, sz, 0UL );
  if( !overrun ) after_frag( ctx, ctx->gossip_in_idx, 0UL, sig, sz, 0UL, 0UL, NULL );
}

static void
contact_info( fd_failover_tile_ctx_t * ctx,
              uchar const *            origin,
              uint                     addr,
              ushort                   port ) {
  gossip_frag( ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO, origin, addr, port, 0, 0 );
}

static void
shutdown_pair( fd_failover_tile_ctx_t * a,
               fd_failover_tile_ctx_t * b ) {
  fd_failover_channel_fini( a->channel );
  fd_failover_channel_fini( b->channel );
}

/* A fake stem for the bus and adopt publishes, every out index lands in
   one mcache and every chunk maps into bus_mem. */
static fd_frag_meta_t    pub_mcache[ 8 ];
static ulong             pub_cr_avail;
static ulong             pub_min_cr_avail;
static int               pub_reliable;
static fd_stem_context_t stem[1];
static uchar             bus_mem[ 4096 ] __attribute__((aligned(128)));

static void
stem_init( void ) {
  static fd_frag_meta_t * mcaches[ 1 ];
  static ulong            seqs[ 1 ];
  static ulong            depths[ 1 ];
  mcaches[ 0 ]     = pub_mcache;
  seqs[ 0 ]        = 0UL;
  depths[ 0 ]      = 8UL;
  pub_cr_avail     = 64UL;
  pub_min_cr_avail = 64UL;
  pub_reliable     = 0;
  *stem = (fd_stem_context_t){
    .mcaches = mcaches, .seqs = seqs, .depths = depths,
    .cr_avail = &pub_cr_avail, .min_cr_avail = &pub_min_cr_avail,
    .cr_decrement_amount = 1UL, .out_reliable = &pub_reliable,
  };
}

/* The controller tests drive one context without sockets. */
static uchar                  ch_mem[ 8UL<<20 ] __attribute__((aligned(128)));
static fd_failover_tile_ctx_t ctl[ 1 ];

#define OUR_BOOT_ID (1000UL)

static fd_failover_tile_ctx_t *
controller_init( ulong role ) {
  stem_init();
  fd_failover_tile_ctx_t * ctx = ctl;
  fd_memset( ctx, 0, sizeof(fd_failover_tile_ctx_t) );
  ctx->role               = role;
  ctx->hello.role         = (uchar)role;
  ctx->hello.boot_id      = OUR_BOOT_ID;
  fd_memset( ctx->hello.junk_pubkey,   0x11, 32UL );
  fd_memset( ctx->hello.staked_pubkey, 0x5A, 32UL );
  ctx->replay_slot        = 100UL;
  ctx->root_slot          = 90UL;
  ctx->last_vote_slot     = 99UL;
  ctx->switch_pending_key = FD_FAILOVER_SWITCH_KEY_CNT;
  ctx->deadline_slot      = FD_FAILOVER_SLOT_NULL;
  ctx->peer_floor         = FD_FAILOVER_SLOT_NULL;
  ctx->own_floor          = FD_FAILOVER_SLOT_NULL;
  ctx->tower_seen_seq     = ULONG_MAX;
  ctx->handoff_base       = 5000UL;
  ctx->gossip_in_idx      = ULONG_MAX;
  ctx->tower_in_idx       = ULONG_MAX;
  ctx->admin_in_idx       = ULONG_MAX;
  ctx->adopt_in_idx       = ULONG_MAX;
  ctx->admin_out_idx      = 0UL;
  ctx->admin_out_mem      = (fd_wksp_t *)bus_mem;
  ctx->adopt_out_idx      = 0UL;
  ctx->adopt_out_mem      = (fd_wksp_t *)bus_mem;
  ctx->own_gossip.addr    = OWN_GOSSIP_ADDR;
  ctx->own_gossip.port    = fd_ushort_bswap( OWN_GOSSIP_PORT );
  ctx->channel            = fd_failover_channel_join( fd_failover_channel_new( ch_mem ) );
  FD_TEST( ctx->channel );
  ctx->channel->self_hello = ctx->hello;
  ctx->channel_state       = fd_failover_channel_state( ctx->channel );
  return ctx;
}

static void
controller_fini( fd_failover_tile_ctx_t * ctx ) {
  fd_failover_channel_fini( ctx->channel );
}

/* Marks the session paired with a peer boot and gives us a fresh STATUS
   from it with peer_role, as if our own first STATUS went out too. */
static void
pair( fd_failover_tile_ctx_t * ctx,
      ulong                    boot_id,
      ulong                    peer_role,
      long                     now ) {
  ctx->channel->state              = FD_FAILOVER_SESSION_PAIRED;
  ctx->channel->peer_hello.boot_id = boot_id;
  ctx->channel->peer_hello.role    = (uchar)peer_role;
  sync_session( ctx );
  fd_failover_status_t status = { .role           = (uchar)peer_role,
                                  .replay_slot    = FD_FAILOVER_SLOT_NULL,
                                  .root_slot      = FD_FAILOVER_SLOT_NULL,
                                  .last_vote_slot = FD_FAILOVER_SLOT_NULL };
  handle_status( ctx, &status, now );
  ctx->status_sent = 1;
}

static void
unpair( fd_failover_tile_ctx_t * ctx ) {
  ctx->channel->state = FD_FAILOVER_SESSION_LISTENING;
  fd_memset( &ctx->channel->peer_hello, 0, sizeof(fd_failover_hello_t) );
  sync_session( ctx );
}

static void
peer_says( fd_failover_tile_ctx_t * ctx,
           ulong                    role,
           ulong                    last_vote_slot,
           long                     now ) {
  fd_failover_status_t status = { .role           = (uchar)role,
                                  .replay_slot    = FD_FAILOVER_SLOT_NULL,
                                  .root_slot      = FD_FAILOVER_SLOT_NULL,
                                  .last_vote_slot = last_vote_slot };
  handle_status( ctx, &status, now );
}

/* Pairs with a peer boot that said ACTIVE on an earlier session, the
   member whose DEMOTED we take. */
static void
pair_demoter( fd_failover_tile_ctx_t * ctx,
              ulong                    boot_id,
              long                     now ) {
  pair( ctx, boot_id, FD_FAILOVER_ROLE_STANDBY, now );
  fd_memcpy( ctx->active_junk, ctx->channel->peer_hello.junk_pubkey, 32UL );
  ctx->active_boot_id = boot_id;
}

/* A real one vote compact tower ending at tip. */
static void
make_tower( fd_failover_tower_t * tower,
            ulong                 tip ) {
  fd_compact_tower_sync_serde_t serde;
  fd_memset( &serde, 0, sizeof(serde) );
  serde.root                             = tip-2UL;
  serde.lockouts_cnt                     = 1;
  serde.lockouts[ 0 ].offset             = 2UL;
  serde.lockouts[ 0 ].confirmation_count = 1;
  FD_TEST( !fd_compact_tower_sync_ser( &serde, tower->state, FD_FAILOVER_TOWER_STATE_MAX, &tower->sz ) );
  tower->valid = 1;
  tower->tip   = tip;
}

static ulong
demoted_payload( uchar * payload,
                 ulong   handoff_id,
                 ulong   target_boot_id,
                 ulong   tip ) {
  fd_failover_tower_t tower;
  make_tower( &tower, tip );
  ulong payload_sz = fd_failover_demoted_encode( payload, handoff_id, target_boot_id, tip, tower.state, tower.sz );
  FD_TEST( payload_sz );
  return payload_sz;
}

static void
deliver( fd_failover_tile_ctx_t * ctx,
         ushort                   type,
         void const *             payload,
         ulong                    payload_sz ) {
  fd_memcpy( ctx->rx, payload, payload_sz );
  handle_control( ctx, type, payload_sz, 1000L );
}

static void
deliver_ack( fd_failover_tile_ctx_t * ctx,
             ulong                    handoff_id ) {
  uchar payload[ sizeof(fd_failover_promote_ack_t) ];
  deliver( ctx, (ushort)FD_FAILOVER_MSG_PROMOTE_ACK, payload, fd_failover_promote_ack_encode( payload, handoff_id ) );
}

static void
deliver_rejected( fd_failover_tile_ctx_t * ctx,
                  ulong                    handoff_id,
                  uchar                    reason ) {
  uchar payload[ sizeof(fd_failover_promote_rejected_t) ];
  deliver( ctx, (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED, payload, fd_failover_promote_rejected_encode( payload, handoff_id, reason ) );
}

static void
switch_ok( fd_failover_tile_ctx_t * ctx,
           ulong                    watermark ) {
  ctx->switch_result.result          = FD_FAILOVER_SWITCH_OK;
  ctx->switch_result.tower_watermark = watermark;
  FD_TEST( switch_answer( ctx, ctx->switch_request_id ) );
}

static void
adopt_answer( fd_failover_tile_ctx_t * ctx,
              ulong                    result,
              ulong                    vote_slot ) {
  ctx->adopt_result       = (fd_tower_adopt_result_t){ .result=result, .root=0UL, .vote_slot=vote_slot };
  ctx->adopt_result_id    = ctx->adopt_expected_id;
  ctx->adopt_result_fresh = 1;
}

/* The tower tile's answer to an empty request, vote_slot is what is left
   above our root and acct_vote_slot the account's own last vote. */
static void
acct_answer( fd_failover_tile_ctx_t * ctx,
             ulong                    vote_slot,
             ulong                    acct_vote_slot ) {
  ctx->adopt_result       = (fd_tower_adopt_result_t){ .result=FD_TOWER_ADOPT_SUCCESS, .root=0UL, .vote_slot=vote_slot, .acct_vote_slot=acct_vote_slot };
  ctx->adopt_result_id    = ctx->adopt_expected_id;
  ctx->adopt_result_fresh = 1;
}

static fd_failover_demoted_t
pending_demoted( fd_failover_tile_ctx_t const * ctx ) {
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_DEMOTED );
  fd_failover_demoted_t demoted;
  FD_TEST( fd_failover_demoted_decode( &demoted, ctx->pending, ctx->pending_sz ) );
  return demoted;
}

static fd_failover_promote_rejected_t
pending_rejected( fd_failover_tile_ctx_t const * ctx ) {
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED );
  fd_failover_promote_rejected_t rej;
  FD_TEST( fd_failover_promote_rejected_decode( &rej, ctx->pending, ctx->pending_sz ) );
  return rej;
}

static ulong
pending_ack( fd_failover_tile_ctx_t const * ctx ) {
  FD_TEST( ctx->pending_valid && ctx->pending_type==(ushort)FD_FAILOVER_MSG_PROMOTE_ACK );
  fd_failover_promote_ack_t ack;
  FD_TEST( fd_failover_promote_ack_decode( &ack, ctx->pending, ctx->pending_sz ) );
  return ack.handoff_id;
}

/* Runs a demotion on an active through the junk switch and the drain,
   a handoff when handoff is set, else a demote. */
static void
demote_through( fd_failover_tile_ctx_t * ctx,
                int                      handoff ) {
  start_demotion( ctx, handoff );
  step_controller( ctx, stem );
  FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_JUNK );
  ctx->tower_seen_seq = 19UL;
  switch_ok( ctx, 20UL );
  step_controller( ctx, stem );
}

static ulong
control( fd_failover_tile_ctx_t * ctx,
         ulong                    cmd,
         ulong                    flags,
         long                     now ) {
  fd_adminctl_failover_control_t req = { .version=FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION, .cmd=cmd, .flags=flags };
  return apply_control( ctx, &req, now );
}

/* test_gossip_filter: only contact infos and their removal get past
   before_frag. */
static void
test_gossip_filter( fd_failover_tile_ctx_t * ctx ) {
  FD_TEST( !before_frag( ctx, ctx->gossip_in_idx, 0UL, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO        ) );
  FD_TEST( !before_frag( ctx, ctx->gossip_in_idx, 0UL, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE ) );
  FD_TEST(  before_frag( ctx, ctx->gossip_in_idx, 0UL, FD_GOSSIP_UPDATE_TAG_VOTE                ) );
  FD_TEST(  before_frag( ctx, ctx->gossip_in_idx, 0UL, FD_GOSSIP_UPDATE_TAG_DUPLICATE_SHRED     ) );
  FD_TEST(  before_frag( ctx, ctx->gossip_in_idx, 0UL, FD_GOSSIP_UPDATE_TAG_SNAPSHOT_HASHES     ) );
  FD_TEST(  before_frag( ctx, ctx->gossip_in_idx, 0UL, FD_GOSSIP_UPDATE_TAG_WFS_DONE            ) );
  FD_TEST(  before_frag( ctx, ctx->gossip_in_idx, 0UL, FD_GOSSIP_UPDATE_TAG_PEER_SATURATED      ) );
  FD_LOG_NOTICE(( "pass: gossip filter" ));
}

/* test_gossip_dialer: a standby dials the newest staked contact info
   that is not ours.  Other origins, removes, IPv6, zero addresses and
   overruns change nothing. */
static void
test_gossip_dialer( fd_failover_tile_ctx_t * ctx ) {
  uchar const * junk   = keys[ 1 ]+32UL;
  uchar const * staked = keys[ 2 ]+32UL;
  uchar         other[ 32 ];
  fd_memset( other, 0x77, 32UL );
  fd_failover_channel_t const * ch = ctx->channel;
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( !ch->peer_addr && !ch->dial_peer && ch->state==FD_FAILOVER_SESSION_LISTENING );

  contact_info( ctx, other, FD_IP4_ADDR(10,0,0,7), 8001 );
  contact_info( ctx, junk,  FD_IP4_ADDR(10,0,0,2), 8001 );
  gossip_frag( ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO, staked, FD_IP4_ADDR(10,0,0,9), 8001, 1, 0 );
  contact_info( ctx, staked, 0U, 8001 );
  gossip_frag( ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO, staked, FD_IP4_ADDR(10,0,0,9), 8001, 0, 1 );
  contact_info( ctx, staked, OWN_GOSSIP_ADDR, OWN_GOSSIP_PORT );
  FD_TEST( !ctx->staked_addr && !ch->peer_addr && !ctx->staked_seen_at );
  FD_TEST( ch->state==FD_FAILOVER_SESSION_LISTENING );

  contact_info( ctx, staked, FD_IP4_ADDR(10,0,0,9), 8001 );
  FD_TEST( ch->peer_addr==FD_IP4_ADDR(10,0,0,9) && ch->peer_port==ctx->port && ch->dial_peer );
  FD_TEST( ch->state==FD_FAILOVER_SESSION_BACKOFF && !ch->retry_at );
  long seen = ctx->staked_seen_at;
  FD_TEST( seen>0L );

  gossip_frag( ctx, FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE, staked, 0U, 0, 0, 0 );
  FD_TEST( ch->peer_addr==FD_IP4_ADDR(10,0,0,9) && ctx->staked_seen_at==seen );
  contact_info( ctx, staked, FD_IP4_ADDR(10,0,0,9), 8001 );
  FD_TEST( ch->peer_addr==FD_IP4_ADDR(10,0,0,9) && ctx->staked_seen_at>=seen );

  /* Our address from another gossip port is somebody else. */
  seen = ctx->staked_seen_at;
  contact_info( ctx, staked, OWN_GOSSIP_ADDR, (ushort)(OWN_GOSSIP_PORT+1) );
  FD_TEST( ctx->staked_seen_at>=seen && ctx->staked_addr==OWN_GOSSIP_ADDR );
  FD_TEST( ch->peer_addr==OWN_GOSSIP_ADDR );

  contact_info( ctx, staked, FD_IP4_ADDR(10,0,0,3), 8001 );
  FD_TEST( ch->peer_addr==FD_IP4_ADDR(10,0,0,3) && ctx->staked_addr==FD_IP4_ADDR(10,0,0,3) );
  FD_TEST( ch->dial_peer && ch->state==FD_FAILOVER_SESSION_BACKOFF );
  FD_LOG_NOTICE(( "pass: a standby follows the staked contact info" ));
}

/* test_gossip_listener: an active keeps listening and dials nobody.
   The address it learned becomes the dial target once it stands by. */
static void
test_gossip_listener( fd_failover_tile_ctx_t * ctx ) {
  fd_failover_channel_t const * ch = ctx->channel;
  int listen_fd = ch->listen_fd;
  FD_TEST( listen_fd!=-1 && !ch->peer_addr );
  set_role( ctx, FD_FAILOVER_ROLE_ACTIVE );
  contact_info( ctx, keys[ 2 ]+32UL, FD_IP4_ADDR(10,0,0,4), 8001 );
  FD_TEST( ch->peer_addr==FD_IP4_ADDR(10,0,0,4) && ch->listen_fd==listen_fd && !ch->dial_peer );
  FD_TEST( ch->state==FD_FAILOVER_SESSION_LISTENING && ctx->staked_seen_at>0L );
  set_role( ctx, FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( ch->dial_peer && ch->listen_fd==listen_fd && ch->state==FD_FAILOVER_SESSION_BACKOFF );
  FD_LOG_NOTICE(( "pass: an active only listens" ));
}

/* test_peer_address_self: a [failover.peer_address] that is our own
   address stops the boot. */
static void
test_peer_address_self( void ) {
  fd_cstr_ncpy( boot_peer_address, "10.0.0.1", sizeof(boot_peer_address) );
  pid_t pid = fork();
  FD_TEST( pid>=0 );
  if( !pid ) {
    boot( 0UL );
    _exit( 0 );
  }
  int status;
  FD_TEST( waitpid( pid, &status, 0 )==pid );
  FD_TEST( WIFEXITED( status ) && WEXITSTATUS( status )==1 );
  boot_peer_address[ 0 ] = '\0';
  FD_LOG_NOTICE(( "pass: a peer address that is our own address is refused" ));
}

/* test_status_interval: a paired member sends STATUS once per interval
   and not in between. */
static void
test_status_interval( fd_failover_tile_ctx_t * ctx ) {
  fd_failover_channel_metrics_t const * m = fd_failover_channel_metrics( ctx->channel );
  FD_TEST( fd_failover_channel_state( ctx->channel )==FD_FAILOVER_SESSION_PAIRED && ctx->status_sent );
  int   busy = 0;
  long  t    = ctx->status_at+FD_FAILOVER_STATUS_INTERVAL_NANOS;
  ulong sent = m->frames_sent;
  peer_poll( ctx, t, &busy );
  FD_TEST( m->frames_sent==sent+1UL && ctx->status_at==t );
  peer_poll( ctx, t+FD_FAILOVER_STATUS_INTERVAL_NANOS-1L, &busy );
  FD_TEST( m->frames_sent==sent+1UL && ctx->status_at==t );
  peer_poll( ctx, t+FD_FAILOVER_STATUS_INTERVAL_NANOS, &busy );
  FD_TEST( m->frames_sent==sent+2UL && ctx->status_at==t+FD_FAILOVER_STATUS_INTERVAL_NANOS );
  FD_LOG_NOTICE(( "pass: STATUS goes out once per interval" ));
}

/* test_status_session_edge: the standby hangs up and dials again.  The
   new session gets our STATUS at once, before the interval is up. */
static void
test_status_session_edge( fd_failover_tile_ctx_t * active,
                          fd_failover_tile_ctx_t * standby ) {
  FD_TEST( fd_failover_channel_state( active->channel )==FD_FAILOVER_SESSION_PAIRED && active->status_sent );
  int  busy     = 0;
  long ta       = active->status_at+1L;
  long tb       = fd_failover_clock();
  long deadline = tb+10000000000L;
  fd_failover_channel_hangup( standby->channel, tb );
  while( fd_failover_channel_state( active->channel )==FD_FAILOVER_SESSION_PAIRED ) {
    FD_TEST( fd_failover_clock()<deadline );
    peer_poll( active, ta, &busy );
  }
  FD_TEST( !active->status_sent );
  while( fd_failover_channel_state( active->channel )!=FD_FAILOVER_SESSION_PAIRED ) {
    FD_TEST( fd_failover_clock()<deadline );
    tb = fd_long_max( tb+1000L, standby->channel->retry_at );
    peer_poll( standby, tb, &busy );
    peer_poll( active,  ta, &busy );
  }
  FD_TEST( active->status_sent && active->status_at==ta );
  FD_TEST( fd_failover_channel_peer_hello( active->channel )->boot_id==standby->hello.boot_id );
  FD_LOG_NOTICE(( "pass: a new session gets our STATUS at once" ));
}

/* test_configured_peer: a configured peer address is dialed and keeps
   its room on the listener.  Gossip then only refreshes staked_seen_at. */
static void
test_configured_peer( fd_failover_tile_ctx_t * ctx ) {
  fd_failover_channel_t const * ch = ctx->channel;
  FD_TEST( ctx->config_addr==FD_IP4_ADDR(10,0,0,5) );
  FD_TEST( ch->expect_addr==FD_IP4_ADDR(10,0,0,5) && ch->peer_addr==FD_IP4_ADDR(10,0,0,5) );
  FD_TEST( ch->dial_peer && ch->state==FD_FAILOVER_SESSION_BACKOFF );
  contact_info( ctx, keys[ 2 ]+32UL, FD_IP4_ADDR(10,0,0,9), 8001 );
  FD_TEST( ctx->staked_seen_at>0L && !ctx->staked_addr );
  FD_TEST( ch->peer_addr==FD_IP4_ADDR(10,0,0,5) && ch->state==FD_FAILOVER_SESSION_BACKOFF );
  FD_LOG_NOTICE(( "pass: a configured peer address is dialed, gossip only feeds the guard" ));
}

/* Runs both tiles' after_credit until done says stop. */
#define PUMP( a, b, done ) do {                                        \
    long _deadline = fd_failover_clock()+10000000000L;                 \
    while( !(done) ) {                                                 \
      FD_TEST( fd_failover_clock()<_deadline );                        \
      int _busy = 0;                                                   \
      after_credit( (a), stem, NULL, &_busy );                         \
      after_credit( (b), stem, NULL, &_busy );                         \
    }                                                                  \
  } while(0)

/* Pairs the standby with the active through gossip.  Both members run
   on this host, so the standby dials the active's ephemeral port
   instead of a shared one. */
static void
pair_loopback( fd_failover_tile_ctx_t * active,
               fd_failover_tile_ctx_t * standby ) {
  standby->port = fd_failover_channel_listen_port( active->channel );
  contact_info( active,  keys[ 2 ]+32UL, OWN_GOSSIP_ADDR,         OWN_GOSSIP_PORT );
  contact_info( standby, keys[ 2 ]+32UL, FD_IP4_ADDR(127,0,0,1), 8002            );
  PUMP( standby, active, standby->peer_status_valid && active->peer_status_valid );
}

/* test_gossip_pairs: without a contact info nothing is dialed, with one
   the standby dials the active and the pair trades STATUS. */
static void
test_gossip_pairs( fd_failover_tile_ctx_t * active,
                   fd_failover_tile_ctx_t * standby ) {
  set_role( active, FD_FAILOVER_ROLE_ACTIVE );
  int busy = 0;
  for( ulong i=0UL; i<50UL; i++ ) {
    peer_poll( standby, fd_failover_clock(), &busy );
    peer_poll( active,  fd_failover_clock(), &busy );
  }
  FD_TEST( !fd_failover_channel_metrics( standby->channel )->connection_attempt_cnt );
  FD_TEST( fd_failover_channel_state( standby->channel )==FD_FAILOVER_SESSION_LISTENING );
  FD_TEST( fd_failover_channel_state( active->channel  )==FD_FAILOVER_SESSION_LISTENING );

  pair_loopback( active, standby );
  FD_TEST( fd_failover_channel_state( standby->channel )==FD_FAILOVER_SESSION_PAIRED );
  FD_TEST( fd_failover_channel_state( active->channel  )==FD_FAILOVER_SESSION_PAIRED );
  FD_TEST( fd_failover_channel_metrics( standby->channel )->paired_cnt==1UL );
  FD_TEST( !active->channel->dial_peer && !active->channel->candidates[ active->channel->active ].dialed );
  FD_TEST( active->peer_status.role==FD_FAILOVER_ROLE_STANDBY && standby->peer_status.role==FD_FAILOVER_ROLE_ACTIVE );
  FD_TEST( active->peer_boot_id==standby->hello.boot_id && standby->peer_boot_id==active->hello.boot_id );
  FD_LOG_NOTICE(( "pass: the standby pairs once gossip has the active's address" ));
}

/* test_bad_status_session: a STATUS that does not decode drops the
   session. */
static void
test_bad_status_session( fd_failover_tile_ctx_t * active,
                         fd_failover_tile_ctx_t * standby ) {
  set_role( active, FD_FAILOVER_ROLE_ACTIVE );
  pair_loopback( active, standby );
  PUMP( active, active, !fd_failover_channel_tx_pending( active->channel ) );
  fd_failover_status_t status = local_status( active, fd_failover_clock() );
  status.role = (uchar)( FD_FAILOVER_ROLE_ACTIVE+1UL );
  FD_TEST( !fd_failover_channel_send( active->channel, fd_failover_clock(), (ushort)FD_FAILOVER_MSG_STATUS,
                                      (uchar const *)&status, sizeof(status) ) );
  PUMP( active, standby, fd_failover_channel_metrics( standby->channel )->wire_fatal_cnt );
  FD_TEST( fd_failover_channel_metrics( standby->channel )->wire_fatal_cnt==1UL );
  FD_TEST( fd_failover_channel_state( standby->channel )!=FD_FAILOVER_SESSION_PAIRED && !standby->peer_status_valid );
  FD_LOG_NOTICE(( "pass: a STATUS that does not decode drops the session" ));
}

/* test_handoff_session: a handoff over a real session.  The session
   stays up through both role changes and the standby ends up active. */
static void
test_handoff_session( fd_failover_tile_ctx_t * a,
                      fd_failover_tile_ctx_t * b ) {
  stem_init();
  fd_failover_tile_ctx_t * both[ 2 ] = { a, b };
  for( ulong i=0UL; i<2UL; i++ ) {
    both[ i ]->admin_out_idx = 0UL;
    both[ i ]->admin_out_mem = (fd_wksp_t *)bus_mem;
    both[ i ]->adopt_out_idx = 0UL;
    both[ i ]->adopt_out_mem = (fd_wksp_t *)bus_mem;
    both[ i ]->replay_slot   = 120UL;
    both[ i ]->root_slot     = 100UL;
  }
  set_role( a, FD_FAILOVER_ROLE_ACTIVE );
  a->last_vote_slot = 110UL;
  make_tower( &a->cs, 110UL );
  pair_loopback( a, b );
  PUMP( a, b, b->peer_floor==110UL );
  FD_TEST( b->active_boot_id==a->hello.boot_id && fd_memeq( b->active_junk, a->hello.junk_pubkey, 32UL ) );

  FD_TEST( control( a, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, fd_failover_clock() )==FD_ADMINCTL_RESULT_SUCCESS );
  PUMP( a, b, a->switch_pending_key==FD_FAILOVER_SWITCH_KEY_JUNK );
  switch_ok( a, 0UL );
  /* DEMOTED goes out once on this session while we wait for the answer. */
  PUMP( a, a, a->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK && !a->pending_valid && !fd_failover_channel_tx_pending( a->channel ) );
  ulong sent = fd_failover_channel_metrics( a->channel )->frames_sent;
  for( ulong i=0UL; i<100UL; i++ ) {
    int busy = 0;
    after_credit( a, stem, NULL, &busy );
  }
  FD_TEST( fd_failover_channel_metrics( a->channel )->frames_sent==sent && !a->pending_valid );
  PUMP( a, b, b->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT );
  FD_TEST( a->role==FD_FAILOVER_ROLE_STANDBY && b->peer_tower.valid && b->peer_tower.tip==110UL );
  adopt_answer( b, FD_TOWER_ADOPT_SUCCESS, 110UL );
  PUMP( a, b, b->switch_pending_key==FD_FAILOVER_SWITCH_KEY_STAKED );
  switch_ok( b, 0UL );
  PUMP( a, b, a->handoff_result==FD_FAILOVER_HANDOFF_TAKEN );
  PUMP( a, b, a->peer_status.role==FD_FAILOVER_ROLE_ACTIVE && b->peer_status.role==FD_FAILOVER_ROLE_STANDBY );

  FD_TEST( a->role==FD_FAILOVER_ROLE_STANDBY && b->role==FD_FAILOVER_ROLE_ACTIVE && a->taken );
  FD_TEST( a->action==FD_FAILOVER_ACTION_IDLE && b->action==FD_FAILOVER_ACTION_IDLE && !a->stuck && !b->stuck );
  /* The ACK went out and freed the control slot for a later handoff. */
  FD_TEST( !b->pending_valid );
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_failover_channel_metrics_t const * m = fd_failover_channel_metrics( both[ i ]->channel );
    FD_TEST( fd_failover_channel_state( both[ i ]->channel )==FD_FAILOVER_SESSION_PAIRED );
    FD_TEST( m->paired_cnt==1UL && !m->wire_fatal_cnt );
  }
  FD_LOG_NOTICE(( "pass: a handoff keeps the session through both role changes" ));
}

/* test_demoted_from_standby_session: over a real session between two
   certified members, a DEMOTED from a member that never said ACTIVE is
   refused with HOLDS_IDENTITY. */
static void
test_demoted_from_standby_session( fd_failover_tile_ctx_t * a,
                                   fd_failover_tile_ctx_t * b ) {
  stem_init();
  b->replay_slot = 120UL;
  b->root_slot   = 100UL;
  pair_loopback( a, b );
  FD_TEST( a->role==FD_FAILOVER_ROLE_STANDBY && b->peer_status.role==FD_FAILOVER_ROLE_STANDBY && !b->active_boot_id );

  /* a sends b a DEMOTED as if it were handing off. */
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  a->handoff_id     = 42UL;
  a->handoff_target = b->hello.boot_id;
  a->send_demoted   = 1;
  FD_TEST( !queue_control( a, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, demoted_payload( payload, 42UL, b->hello.boot_id, 110UL ) ) );
  PUMP( a, b, a->handoff_result==FD_FAILOVER_HANDOFF_DECLINED );
  FD_TEST( b->reply_valid && b->reply_reason==(uchar)FD_FAILOVER_REJECT_HOLDS_IDENTITY );
  FD_TEST( b->role==FD_FAILOVER_ROLE_STANDBY && b->action==FD_FAILOVER_ACTION_IDLE && !b->peer_tower.valid );
  FD_TEST( fd_failover_channel_state( b->channel )==FD_FAILOVER_SESSION_PAIRED );
  FD_LOG_NOTICE(( "pass: a certified member that never said ACTIVE cannot hand over the identity" ));
}

/* test_boot_binding_session: the standby restarts after our handoff
   began and before its DEMOTED went out.  The new boot never gets that
   DEMOTED and the handoff ends RESTARTED.  Returns the new boot. */
static fd_failover_tile_ctx_t *
test_boot_binding_session( fd_failover_tile_ctx_t * a,
                           fd_failover_tile_ctx_t * b ) {
  stem_init();
  a->admin_out_idx = 0UL;
  a->admin_out_mem = (fd_wksp_t *)bus_mem;
  a->replay_slot   = 120UL;
  a->root_slot     = 100UL;
  set_role( a, FD_FAILOVER_ROLE_ACTIVE );
  a->last_vote_slot = 110UL;
  make_tower( &a->cs, 110UL );
  pair_loopback( a, b );
  PUMP( a, b, b->peer_floor==110UL );
  FD_TEST( control( a, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, fd_failover_clock() )==FD_ADMINCTL_RESULT_SUCCESS );
  PUMP( a, b, a->switch_pending_key==FD_FAILOVER_SWITCH_KEY_JUNK );

  /* The standby goes away before our switch answers, so the DEMOTED
     waits for a session. */
  ulong old_boot = b->hello.boot_id;
  fd_failover_channel_fini( b->channel );
  PUMP( a, a, fd_failover_channel_state( a->channel )!=FD_FAILOVER_SESSION_PAIRED );
  switch_ok( a, 0UL );
  PUMP( a, a, a->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK );
  FD_TEST( a->pending_valid && a->handoff_target==old_boot );

  /* It boots again under a new boot_id and dials us. */
  b = boot( 1UL );
  FD_TEST( b->hello.boot_id!=old_boot );
  b->replay_slot = 120UL;
  b->root_slot   = 100UL;
  b->port        = fd_failover_channel_listen_port( a->channel );
  contact_info( b, keys[ 2 ]+32UL, FD_IP4_ADDR(127,0,0,1), 8002 );
  PUMP( a, b, a->handoff_result==FD_FAILOVER_HANDOFF_RESTARTED );
  PUMP( a, b, a->peer_status_valid && b->peer_status_valid );
  for( ulong i=0UL; i<1000UL; i++ ) {
    int busy = 0;
    after_credit( a, stem, NULL, &busy );
    after_credit( b, stem, NULL, &busy );
  }
  FD_TEST( a->action==FD_FAILOVER_ACTION_IDLE && !a->pending_valid && !a->send_demoted );
  FD_TEST( b->action==FD_FAILOVER_ACTION_IDLE && !b->reply_valid && !b->peer_tower.valid );
  FD_TEST( fd_failover_channel_state( b->channel )==FD_FAILOVER_SESSION_PAIRED );
  FD_LOG_NOTICE(( "pass: a DEMOTED never reaches a peer that restarted" ));
  return b;
}

/* test_slot_done_bookkeeping: the slot view follows the tower and the
   STATUS we send always passes the peer's decoder. */
static void
test_slot_done_bookkeeping( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->replay_slot    = FD_FAILOVER_SLOT_NULL;
  ctx->root_slot      = FD_FAILOVER_SLOT_NULL;
  ctx->last_vote_slot = FD_FAILOVER_SLOT_NULL;

  static fd_tower_slot_done_t done;
  fd_memset( &done, 0, sizeof(done) );
  done.replay_slot = 100UL;
  done.root_slot   = FD_FAILOVER_SLOT_NULL;
  done.vote_slot   = FD_FAILOVER_SLOT_NULL;
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->replay_slot==100UL && ctx->root_slot==FD_FAILOVER_SLOT_NULL && ctx->last_vote_slot==FD_FAILOVER_SLOT_NULL );

  /* The replay slot does not go backwards when a fork reports an older slot. */
  done.replay_slot = 90UL;
  done.root_slot   = 60UL;
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->replay_slot==100UL && ctx->root_slot==60UL );

  /* A slot done without a new root keeps the one we know. */
  done.root_slot = FD_FAILOVER_SLOT_NULL;
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->root_slot==60UL );

  /* The vote slot is ignored without a vote transaction, and a standby
     keeps no tower. */
  done.replay_slot  = 101UL;
  done.vote_slot    = 101UL;
  done.has_vote_txn = 0;
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->last_vote_slot==FD_FAILOVER_SLOT_NULL && !ctx->cs.valid );
  done.has_vote_txn = 1;
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->last_vote_slot==101UL && !ctx->cs.valid );

  /* Our last vote ahead of replay, as while a promotion waits for it,
     raises the replay slot we report. */
  fd_failover_status_t decoded;
  ctx->replay_slot    = 1000UL;
  ctx->last_vote_slot = 1200UL;
  ctx->root_slot      = 900UL;
  fd_failover_status_t status = local_status( ctx, 1L );
  FD_TEST( status.replay_slot==1200UL && status.last_vote_slot==1200UL && status.root_slot==900UL );
  FD_TEST( fd_failover_status_decode( &decoded, (uchar const *)&status, sizeof(status) ) );

  /* A root past the last vote, as on a machine that stopped voting, is
     left out. */
  ctx->replay_slot    = 1400UL;
  ctx->last_vote_slot = 1000UL;
  ctx->root_slot      = 1300UL;
  status = local_status( ctx, 1L );
  FD_TEST( status.last_vote_slot==1000UL && status.root_slot==FD_FAILOVER_SLOT_NULL );
  FD_TEST( fd_failover_status_decode( &decoded, (uchar const *)&status, sizeof(status) ) );

  /* A consistent view goes out unchanged, busy and stuck with it. */
  ctx->last_vote_slot = 1300UL;
  ctx->root_slot      = 1200UL;
  ctx->action         = FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY;
  ctx->stuck          = 1;
  status = local_status( ctx, 1L );
  FD_TEST( status.replay_slot==1400UL && status.last_vote_slot==1300UL && status.root_slot==1200UL );
  FD_TEST( status.flags==(uchar)( FD_FAILOVER_STATUS_BUSY|FD_FAILOVER_STATUS_STUCK ) );
  FD_TEST( fd_failover_status_decode( &decoded, (uchar const *)&status, sizeof(status) ) );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: slot bookkeeping and the local status view" ));
}

/* test_final_tower: the active keeps the tower of its vote transaction
   and a demotion hands it over in a DEMOTED the peer decodes. */
static void
test_final_tower( void ) {
  ulong  tower_sz  = fd_ulong_align_up( fd_tower_footprint( 2UL, 2UL ), fd_tower_align() );
  void * tower_mem = aligned_alloc( fd_tower_align(), tower_sz );
  FD_TEST( tower_mem );
  fd_tower_t * tower = fd_tower_join( fd_tower_new( tower_mem, 2UL, 2UL, 0UL ) );
  FD_TEST( tower );
  /* Confirmation counts decrease toward the tip, as in a real tower. */
  for( ulong i=1UL; i<=31UL; i++ ) {
    fd_tower_vote_t vote = { .slot=i, .conf=32UL-i };
    fd_tower_vote_push_tail( tower->votes, vote );
  }
  tower->root = 0UL;

  fd_hash_t   bank_hash        = { .ul = { 1 } };
  fd_hash_t   block_id         = { .ul = { 2 } };
  fd_hash_t   recent_blockhash = { .ul = { 3 } };
  fd_pubkey_t identity         = { .ul = { 4 } };
  fd_pubkey_t vote_acct        = { .ul = { 5 } };
  static fd_txn_p_t txnp[1];
  fd_tower_to_vote_txn( tower, &bank_hash, &block_id, &recent_blockhash, &identity, &identity, &vote_acct, txnp );
  FD_TEST( txnp->payload_sz && txnp->payload_sz<=FD_TPU_MTU );

  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  ctx->replay_slot    = FD_FAILOVER_SLOT_NULL;
  ctx->last_vote_slot = FD_FAILOVER_SLOT_NULL;

  static fd_tower_slot_done_t done;
  fd_memset( &done, 0, sizeof(done) );
  done.replay_slot  = 31UL;
  done.root_slot    = 1UL;
  done.vote_slot    = 31UL;
  done.has_vote_txn = 1;
  done.vote_txn_sz  = txnp->payload_sz;
  fd_memcpy( done.vote_txn, txnp->payload, txnp->payload_sz );
  /* A frag skipped before this vote is superseded by it. */
  ctx->tower_gap = 1;
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->cs.valid && ctx->cs.tip==31UL && ctx->last_vote_slot==31UL );
  FD_TEST( !ctx->tower_gap );

  /* A malformed vote transaction leaves the previous tower in place. */
  ulong good_sz = ctx->cs.sz;
  done.vote_txn_sz = 3UL;
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->cs.valid && ctx->cs.sz==good_sz );
  done.vote_txn_sz = txnp->payload_sz;

  demote_through( ctx, 1 );
  fd_failover_demoted_t demoted = pending_demoted( ctx );
  FD_TEST( demoted.last_vote_slot==31UL && demoted.state_len==good_sz );
  FD_TEST( fd_memeq( ctx->pending+sizeof(fd_failover_demoted_t), ctx->cs.state, good_sz ) );
  controller_fini( ctx );

  /* A standby keeps no tower, and the first vote under the new key
     already counts while its switch answer is on the way. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  consume_slot_done( ctx, &done );
  FD_TEST( !ctx->cs.valid );
  ctx->action = FD_FAILOVER_ACTION_PROMOTE_SWITCH;
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->cs.valid && ctx->cs.tip==31UL );
  controller_fini( ctx );

  /* after_credit folds in the slot done that reaches the halt watermark
     before it steps, so its vote is the one DEMOTED hands over. */
  static uchar msg_mem[ sizeof(fd_tower_msg_t) ] __attribute__((aligned(128)));
  fd_memcpy( msg_mem, &done, sizeof(done) );
  ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_tower( &ctx->cs, 30UL );
  ctx->last_vote_slot  = 30UL;
  ctx->member_cert_set = 1;
  ctx->tower_in_idx    = 3UL;
  ctx->tower_in_mem    = (fd_wksp_t *)msg_mem;
  start_demotion( ctx, 1 );
  step_controller( ctx, stem );
  ctx->tower_seen_seq = 18UL;
  switch_ok( ctx, 20UL );
  FD_TEST( !before_frag( ctx, 3UL, 19UL, FD_TOWER_SIG_SLOT_DONE ) );
  during_frag( ctx, 3UL, 19UL, FD_TOWER_SIG_SLOT_DONE, 0UL, sizeof(fd_tower_msg_t), 0UL );
  after_frag ( ctx, 3UL, 19UL, FD_TOWER_SIG_SLOT_DONE, sizeof(fd_tower_msg_t), 0UL, 0UL, stem );
  int busy = 0;
  after_credit( ctx, stem, NULL, &busy );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK );
  FD_TEST( pending_demoted( ctx ).last_vote_slot==31UL );
  controller_fini( ctx );
  free( tower_mem );
  FD_LOG_NOTICE(( "pass: the final tower comes from the vote transaction" ));
}

/* test_before_frag_admits: switch answers and commands get through.  A
   dropped switch answer would leave the switch hanging forever. */
static void
test_before_frag_admits( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->tower_in_idx = 0UL;
  ctx->admin_in_idx = 1UL;
  FD_TEST( !before_frag( ctx, 0UL, 0UL, FD_TOWER_SIG_SLOT_DONE     ) );
  FD_TEST(  before_frag( ctx, 0UL, 1UL, FD_TOWER_SIG_SLOT_DONE+1UL ) );
  FD_TEST( !before_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_CONTROL_REQ  ) );
  FD_TEST( !before_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_SWITCH_RESP  ) );
  /* This tile publishes these two, it never receives them. */
  FD_TEST(  before_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_CONTROL_RESP ) );
  FD_TEST(  before_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_SWITCH_REQ   ) );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: before_frag admits every frame the tile acts on" ));
}

/* test_demotion_order: we only tell the peer to promote after we have
   actually given up the identity. */
static void
test_demotion_order( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_tower( &ctx->cs, 99UL );

  start_demotion( ctx, 1 );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && ctx->role==FD_FAILOVER_ROLE_ACTIVE );
  FD_TEST( ctx->handoff_target==77UL && ctx->send_demoted && ctx->handoff_id==5001UL );
  /* The switch is asked for from the step, after a command's answer went
     out, and it names the junk key by its public key. */
  FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  step_controller( ctx, stem );
  FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_JUNK && pub_mcache[ 0 ].sig==FD_FAILOVER_BUS_SWITCH_REQ );
  fd_failover_switch_req_t req;
  fd_memcpy( &req, ((fd_failover_bus_msg_t const *)bus_mem)->payload, sizeof(req) );
  FD_TEST( fd_memeq( req.identity, ctx->hello.junk_pubkey, 32UL ) );
  FD_TEST( !ctx->pending_valid );

  /* If the switch fails we still hold the identity, so nothing goes to
     the peer and we flag stuck. */
  ctx->switch_result.result = FD_FAILOVER_SWITCH_ERR_DISABLED;
  switch_answer( ctx, ctx->switch_request_id );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck );
  FD_TEST( !ctx->pending_valid && !ctx->send_demoted && ctx->handoff_result==FD_FAILOVER_HANDOFF_NONE );

  /* Once the switch succeeds we stand by, keep our final tower and queue
     DEMOTED for the peer boot behind a STATUS that says so. */
  demote_through( ctx, 1 );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK );
  FD_TEST( ctx->channel->self_hello.role==FD_FAILOVER_ROLE_STANDBY && !ctx->status_sent && !ctx->stuck );
  FD_TEST( ctx->handoff_result==FD_FAILOVER_HANDOFF_PENDING );
  FD_TEST( ctx->own_tower.valid && ctx->own_tower.tip==99UL );
  fd_failover_demoted_t demoted = pending_demoted( ctx );
  FD_TEST( demoted.handoff_id==5002UL && demoted.target_boot_id==77UL );
  FD_TEST( demoted.last_vote_slot==99UL );
  controller_fini( ctx );

  /* A cached tower that is not the one of our last vote hands over
     nothing. */
  ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_tower( &ctx->cs, 98UL );
  demote_through( ctx, 1 );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck );
  FD_TEST( !ctx->pending_valid && !ctx->send_demoted && !ctx->own_tower.valid );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a demotion hands over only after the identity is gone" ));
}

/* test_active_handoff_checks: a handoff reads the standby's last STATUS
   before giving the identity up. */
static void
test_active_handoff_checks( void ) {
  /* A fresh, idle standby, the demotion starts.  Our own stuck bit, left
     by a failed switch, does not stop the operator handing off. */
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_tower( &ctx->cs, 99UL );
  ctx->stuck = 1;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && !ctx->stuck );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, 1000L )==FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS );
  controller_fini( ctx );

  /* A standby that is stuck, busy, not standing by, or stale is refused
     and the identity stays put. */
  uchar flags[] = { FD_FAILOVER_STATUS_STUCK, FD_FAILOVER_STATUS_BUSY, 0, 0 };
  ulong roles[] = { FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_ROLE_ACTIVE, FD_FAILOVER_ROLE_STANDBY };
  for( ulong i=0UL; i<4UL; i++ ) {
    ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
    pair( ctx, 77UL, roles[ i ], 1000L );
    ctx->peer_status.flags = flags[ i ];
    long now = i==3UL ? 1000L+3L*FD_FAILOVER_STATUS_INTERVAL_NANOS : 1000L;
    FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, now )==FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
    FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_IDLE );
    controller_fini( ctx );
  }

  /* No tower for our last vote yet, a tower frag skipped since it was
     built, or a tower older than our last vote.  We keep the identity. */
  for( ulong i=0UL; i<3UL; i++ ) {
    ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
    pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
    if( i ) make_tower( &ctx->cs, 99UL );
    if( i==1UL ) ctx->tower_gap = 1;
    if( i==2UL ) ctx->last_vote_slot = 100UL;
    FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, 1000L )==FD_FAILOVER_CONTROL_RESULT_NO_FINAL_TOWER );
    FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->handoff_id );
    controller_fini( ctx );
  }

  /* Unpaired there is nobody to hand to, and a standby has nothing to
     hand.  A demote needs nothing from the peer. */
  ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, 1000L )==FD_FAILOVER_CONTROL_RESULT_NOT_PAIRED );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_DEMOTE,  0UL, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && !ctx->send_demoted && !ctx->handoff_target );
  controller_fini( ctx );
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, 1000L )==FD_FAILOVER_CONTROL_RESULT_BAD_ROLE );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_DEMOTE,  0UL, 1000L )==FD_FAILOVER_CONTROL_RESULT_BAD_ROLE );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: the active asks the standby's status before handing off" ));
}

/* test_demotion_drain: the final tower is taken only once the tower
   stream reached the halt watermark, and nothing is sent when it never
   gets there or a frag was skipped. */
static void
test_demotion_drain( void ) {
  /* The junk key is in, the stream is three frags short of the halt. */
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_tower( &ctx->cs, 99UL );
  start_demotion( ctx, 1 );
  step_controller( ctx, stem );
  ctx->tower_seen_seq = 796UL;
  switch_ok( ctx, 800UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH );
  FD_TEST( !ctx->pending_valid && !ctx->stuck );

  /* One frag short is still short. */
  ctx->tower_seen_seq = 798UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && !ctx->pending_valid );

  /* The last frag before the halt arrives, DEMOTED goes out. */
  ctx->tower_seen_seq = 799UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK );
  (void)pending_demoted( ctx );
  controller_fini( ctx );

  /* A stream that never reaches the halt sends nothing at the deadline. */
  ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_tower( &ctx->cs, 99UL );
  start_demotion( ctx, 1 );
  step_controller( ctx, stem );
  ctx->tower_seen_seq = 700UL;
  switch_ok( ctx, 800UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE );
  ctx->replay_slot = 1000UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck );
  FD_TEST( !ctx->pending_valid && !ctx->send_demoted );
  controller_fini( ctx );

  /* A tower frag skipped since the cached tower sends nothing either. */
  ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_tower( &ctx->cs, 99UL );
  ctx->tower_gap = 1;
  start_demotion( ctx, 1 );
  step_controller( ctx, stem );
  ctx->tower_seen_seq = 799UL;
  switch_ok( ctx, 800UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->stuck && !ctx->pending_valid && !ctx->own_tower.valid );

  /* A slot done counts once after_frag has it, one the stem abandons to
     an overrun never does.  Other frags count at once, and a skipped one
     is noticed either way. */
  ctx->tower_seen_seq = ULONG_MAX;
  ctx->tower_gap      = 0;
  ctx->tower_in_idx   = 3UL;
  FD_TEST(  before_frag( ctx, 3UL, 10UL, FD_TOWER_SIG_SLOT_DONE+1UL ) && ctx->tower_seen_seq==10UL && !ctx->tower_gap );
  FD_TEST( !before_frag( ctx, 3UL, 11UL, FD_TOWER_SIG_SLOT_DONE ) && ctx->tower_seen_seq==10UL && !ctx->tower_gap );
  after_frag( ctx, 3UL, 11UL, FD_TOWER_SIG_SLOT_DONE, sizeof(fd_tower_msg_t), 0UL, 0UL, stem );
  FD_TEST( ctx->tower_seen_seq==11UL && ctx->slot_done_fresh && !ctx->tower_gap );
  ctx->slot_done_fresh = 0;
  FD_TEST( !before_frag( ctx, 3UL, 12UL, FD_TOWER_SIG_SLOT_DONE ) && ctx->tower_seen_seq==11UL && !ctx->tower_gap );
  FD_TEST(  before_frag( ctx, 3UL, 14UL, FD_TOWER_SIG_SLOT_DONE+1UL ) && ctx->tower_seen_seq==14UL && ctx->tower_gap );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: the final tower waits for the halt watermark" ));
}

/* test_switch_overdue: a switch whose answer is overdue is waited for,
   on both sides.  Standing down would tell the peer nobody promoted
   while the staked key may be installed. */
static void
test_switch_overdue( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  make_tower( &ctx->peer_tower, 99UL );
  start_promotion( ctx, FD_FAILOVER_SOURCE_PEER, 0 );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT );
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 99UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_STAKED );
  fd_failover_switch_req_t req;
  fd_memcpy( &req, ((fd_failover_bus_msg_t const *)bus_mem)->payload, sizeof(req) );
  FD_TEST( fd_memeq( req.identity, ctx->hello.staked_pubkey, 32UL ) );

  /* Replay runs past the deadline with no answer.  We stay a standby,
     keep the request open and raise stuck. */
  ctx->replay_slot = 1000UL;
  step_controller( ctx, stem );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH );
  FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_STAKED && ctx->stuck && ctx->switch_overdue );

  /* The late answer is consumed, not dropped, and finishes the promotion. */
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->stuck );
  FD_TEST( !ctx->peer_tower.valid && !ctx->pending_valid );

  /* Same on the demotion side, an overdue switch to the junk key is
     waited for and the late answer completes the demotion. */
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  start_demotion( ctx, 1 );
  step_controller( ctx, stem );
  ctx->replay_slot = 2000UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH );
  FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_JUNK && ctx->stuck && !ctx->pending_valid );
  ctx->tower_seen_seq = 8UL;
  switch_ok( ctx, 9UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK );
  FD_TEST( pending_demoted( ctx ).last_vote_slot==99UL );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: an overdue switch is waited for, not abandoned" ));
}

/* test_promotion_reject: a tower the tower tile will not adopt ends the
   promotion, the peer is told why and the tower is not kept. */
static void
test_promotion_reject( void ) {
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, 1000L );
  ulong payload_sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && ctx->peer_tower.valid && ctx->promote_peer );
  FD_TEST( ctx->last_vote_slot==99UL && ctx->cs.tip==99UL );

  /* Replay is past the tip, so we hand the tower to the tower tile. */
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->adopt_expected_id );
  FD_TEST( pub_mcache[ 0 ].sig==ctx->adopt_expected_id && pub_mcache[ 0 ].sz==ctx->peer_tower.sz );

  adopt_answer( ctx, FD_TOWER_ADOPT_ERR_BLOCK_MISMATCH, 90UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck );
  FD_TEST( !ctx->peer_tower.valid && !ctx->promote_peer && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  fd_failover_promote_rejected_t rej = pending_rejected( ctx );
  FD_TEST( rej.handoff_id==42UL && rej.reason==FD_FAILOVER_REJECT_ADOPTION_MISMATCH );
  controller_fini( ctx );

  /* The tower tile kept only a prefix of the tower, which would leave
     lockouts behind.  That is a mismatch too. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, 1000L );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  step_controller( ctx, stem );
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 98UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT && !ctx->peer_tower.valid );
  FD_TEST( pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_ADOPTION_MISMATCH );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a promotion that cannot adopt stands down and says why" ));
}

/* test_promotion_switch_failed: a staked switch that fails ends the
   promotion, the peer gets SWITCH_FAILED and we stay a stuck standby. */
static void
test_promotion_switch_failed( void ) {
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, 1000L );
  ulong payload_sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  step_controller( ctx, stem );
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 99UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_STAKED );

  ctx->switch_result.result = FD_FAILOVER_SWITCH_ERR_DISABLED;
  FD_TEST( switch_answer( ctx, ctx->switch_request_id ) );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck );
  FD_TEST( ctx->channel->self_hello.role==(uchar)FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( !ctx->promote_peer && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  fd_failover_promote_rejected_t rej = pending_rejected( ctx );
  FD_TEST( rej.handoff_id==42UL && rej.reason==FD_FAILOVER_REJECT_SWITCH_FAILED );
  FD_TEST( local_status( ctx, 2000L ).flags & FD_FAILOVER_STATUS_STUCK );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a failed staked switch stands down and tells the peer" ));
}

/* test_promotion_wait_replay: the adopt request waits until replay
   reaches the tower's tip.  Replay passing the slot deadline first ends
   the promotion with REPLAY_BEHIND. */
static void
test_promotion_wait_replay( void ) {
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, 1000L );
  ulong payload_sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 120UL );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY );
  step_controller( ctx, stem );
  ctx->replay_slot = 119UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && !stem->seqs[ 0 ] );
  ctx->replay_slot = 120UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && stem->seqs[ 0 ]==1UL );
  FD_TEST( pub_mcache[ 0 ].sig==ctx->adopt_expected_id );
  controller_fini( ctx );

  /* Replay moves on but passes the slot deadline, 64 slots from where it
     started, before it reaches the tip. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, 1000L );
  payload_sz = demoted_payload( payload, 43UL, OUR_BOOT_ID, 200UL );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  FD_TEST( ctx->deadline_slot==100UL+FD_FAILOVER_DEADLINE_SLOTS );
  ctx->replay_slot = 100UL+FD_FAILOVER_DEADLINE_SLOTS;
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && !ctx->pending_valid );
  ctx->replay_slot++;
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->stuck );
  FD_TEST( !stem->seqs[ 0 ] );
  fd_failover_promote_rejected_t rej = pending_rejected( ctx );
  FD_TEST( rej.handoff_id==43UL && rej.reason==FD_FAILOVER_REJECT_REPLAY_BEHIND );
  controller_fini( ctx );

  /* Right after boot replay has reported no slot yet, the promotion waits
     for the first one. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->replay_slot = FD_FAILOVER_SLOT_NULL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_YES, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && !stem->seqs[ 0 ] );
  ctx->replay_slot = 100UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && stem->seqs[ 0 ]==1UL );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a promotion waits for replay and gives up past the slot deadline" ));
}

/* test_command_clears_stuck: a new operator command clears stuck, so a
   standby whose promotion failed does not refuse every later handoff.
   A switch still in flight keeps it. */
static void
test_command_clears_stuck( void ) {
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, 1000L );
  ulong payload_sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  step_controller( ctx, stem );
  adopt_answer( ctx, FD_TOWER_ADOPT_ERR_BLOCK_MISMATCH, 90UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck );
  FD_TEST( local_status( ctx, 2000L ).flags & FD_FAILOVER_STATUS_STUCK );

  /* The command is refused on a standby, stuck clears anyway. */
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_HANDOFF, 0UL, 2000L )==FD_FAILOVER_CONTROL_RESULT_BAD_ROLE );
  FD_TEST( !ctx->stuck && !( local_status( ctx, 2000L ).flags & FD_FAILOVER_STATUS_STUCK ) );
  controller_fini( ctx );

  /* An overdue switch keeps stuck until its answer comes. */
  ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  start_demotion( ctx, 0 );
  step_controller( ctx, stem );
  FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_JUNK );
  ctx->replay_slot = ctx->deadline_slot+1UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->stuck && ctx->switch_overdue );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_DEMOTE, 0UL, 2000L )==FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS );
  FD_TEST( ctx->stuck );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a new command clears stuck unless a switch is still in flight" ));
}

/* test_promotion_outcome_resent: a finished handoff's DEMOTED again gets
   the same answer, so a peer that missed it is not left waiting. */
static void
test_promotion_outcome_resent( void ) {
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];

  /* We promoted and acked.  The DEMOTED comes again while we are the
     active and gets the ACK again, the session stays. */
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, 1000L );
  ulong payload_sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  step_controller( ctx, stem );
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 99UL );
  step_controller( ctx, stem );
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && pending_ack( ctx )==42UL );
  ctx->pending_valid = 0;
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && pending_ack( ctx )==42UL );
  FD_TEST( !ctx->channel->metrics.wire_fatal_cnt );

  /* The slot is busy, the answer is owed and goes out once it drains. */
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  FD_TEST( ctx->reply_owed );
  ctx->pending_valid = 0;
  step_controller( ctx, stem );
  FD_TEST( !ctx->reply_owed && pending_ack( ctx )==42UL );
  controller_fini( ctx );

  /* We refused, the DEMOTED comes again and gets the same refusal. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, 1000L );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  step_controller( ctx, stem );
  adopt_answer( ctx, FD_TOWER_ADOPT_ERR_INVALID, FD_FAILOVER_SLOT_NULL );
  step_controller( ctx, stem );
  FD_TEST( pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_ADOPTION_FAILED && !ctx->peer_tower.valid );
  ctx->pending_valid = 0;
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->peer_tower.valid );
  fd_failover_promote_rejected_t rej = pending_rejected( ctx );
  FD_TEST( rej.handoff_id==42UL && rej.reason==FD_FAILOVER_REJECT_ADOPTION_FAILED );
  FD_TEST( !ctx->channel->metrics.wire_fatal_cnt );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a promotion outcome is resent when the peer misses the reply" ));
}

/* test_dedup: the same DEMOTED while we still work on it gets nothing,
   the same handoff id from another peer boot is another handoff. */
static void
test_dedup( void ) {
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, 1000L );
  ulong payload_sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && ctx->promote_handoff_id==42UL );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && !ctx->pending_valid );
  step_controller( ctx, stem );
  ulong expected_id = ctx->adopt_expected_id;
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && !ctx->pending_valid && ctx->adopt_expected_id==expected_id );

  /* Another peer boot with the same id, we are busy with the first. */
  unpair( ctx );
  pair( ctx, 78UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  fd_failover_promote_rejected_t rej = pending_rejected( ctx );
  FD_TEST( rej.handoff_id==42UL && rej.reason==FD_FAILOVER_REJECT_BUSY );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->promote_boot_id==77UL );
  ctx->pending_valid = 0;

  /* The first one still finishes with its ACK. */
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 99UL );
  step_controller( ctx, stem );
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && pending_ack( ctx )==42UL );
  FD_TEST( !ctx->channel->metrics.wire_fatal_cnt );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a DEMOTED in progress is not answered twice" ));
}

/* test_demote_sends_nothing: a demote drops the identity and tells the
   peer nothing, paired or not.  Our final tower stays for a later
   promote. */
static void
test_demote_sends_nothing( void ) {
  for( int paired=0; paired<2; paired++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
    if( paired ) pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
    make_tower( &ctx->cs, 99UL );
    FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_DEMOTE, 0UL, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && !ctx->send_demoted && !ctx->handoff_target );
    step_controller( ctx, stem );
    FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_JUNK );
    ctx->tower_seen_seq = 19UL;
    switch_ok( ctx, 20UL );
    step_controller( ctx, stem );
    step_controller( ctx, stem );
    FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->stuck );
    FD_TEST( !ctx->pending_valid && !ctx->send_demoted && ctx->handoff_result==FD_FAILOVER_HANDOFF_NONE );
    FD_TEST( ctx->own_tower.valid && ctx->own_tower.tip==99UL );

    /* A plain promote adopts our own final tower, and a promotion that
       succeeds drops it. */
    FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
    FD_TEST( ctx->promote_source==FD_FAILOVER_SOURCE_OWN && ctx->adopt.tip==99UL );
    step_controller( ctx, stem );
    adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 99UL );
    step_controller( ctx, stem );
    switch_ok( ctx, 0UL );
    step_controller( ctx, stem );
    FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && !ctx->own_tower.valid && !ctx->pending_valid );
    controller_fini( ctx );
  }

  /* A demote after a skipped tower frag has no final tower to keep, it
     stands down stuck. */
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  make_tower( &ctx->cs, 99UL );
  ctx->tower_gap = 1;
  demote_through( ctx, 0 );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck );
  FD_TEST( !ctx->own_tower.valid && !ctx->pending_valid && !ctx->send_demoted );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, 1000L )==FD_FAILOVER_CONTROL_RESULT_NO_TOWER );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a demote sends nothing and keeps our final tower" ));
}

/* stored_tower_ctx: a standby whose promotion on the peer's DEMOTED
   ended at the deadline, so it keeps the peer's tower ending at 110. */
static fd_failover_tile_ctx_t *
stored_tower_ctx( void ) {
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, 1000L );
  ctx->replay_slot = 120UL;
  ulong payload_sz = demoted_payload( payload, 43UL, OUR_BOOT_ID, 110UL );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  step_controller( ctx, stem );
  adopt_answer( ctx, FD_TOWER_ADOPT_ERR_UNREPLAYED, 90UL );
  step_controller( ctx, stem );
  ctx->replay_slot = 1000UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->peer_tower.valid && ctx->peer_tower.tip==110UL );
  FD_TEST( pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_ADOPTION_FAILED );
  ctx->pending_valid = 0;
  return ctx;
}

/* test_stored_tower: the peer's tower from a promotion that did not
   finish is adopted by a later promote.  It survives a peer reboot, the
   peer seen ACTIVE drops it, and once our root reaches its tip promote
   skips it for the vote account. */
static void
test_stored_tower( void ) {
  fd_failover_tile_ctx_t * ctx = stored_tower_ctx();
  unpair( ctx );
  pair( ctx, 78UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  FD_TEST( ctx->peer_tower.valid );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->promote_source==FD_FAILOVER_SOURCE_PEER && !ctx->promote_peer && ctx->adopt.tip==110UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && pub_mcache[ 0 ].sz==ctx->peer_tower.sz );
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 110UL );
  step_controller( ctx, stem );
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && !ctx->peer_tower.valid && !ctx->pending_valid );
  controller_fini( ctx );

  ctx = stored_tower_ctx();
  peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE, 130UL, 1000L );
  FD_TEST( !ctx->peer_tower.valid );
  controller_fini( ctx );

  ctx = stored_tower_ctx();
  ctx->root_slot = 110UL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, 1000L )==FD_FAILOVER_CONTROL_RESULT_NO_TOWER );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_YES, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->promote_source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT );
  controller_fini( ctx );

  /* The same for our own final tower. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  make_tower( &ctx->own_tower, 99UL );
  ctx->root_slot = 99UL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, 1000L )==FD_FAILOVER_CONTROL_RESULT_NO_TOWER );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a tower from an unfinished promotion is kept for the next promote" ));
}

/* test_promote_refusals: a DEMOTED is refused while we hold the
   identity, and without a STATUS from this session saying the peer
   stands by. */
static void
test_promote_refusals( void ) {
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  ulong payload_sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL );
  for( ulong variant=0UL; variant<3UL; variant++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( variant==0UL ? FD_FAILOVER_ROLE_ACTIVE : FD_FAILOVER_ROLE_STANDBY );
    pair_demoter( ctx, 77UL, 1000L );
    if( variant==1UL ) ctx->peer_status_valid = 0;
    if( variant==2UL ) peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE, FD_FAILOVER_SLOT_NULL, 1000L );
    deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
    fd_failover_promote_rejected_t rej = pending_rejected( ctx );
    FD_TEST( rej.handoff_id==42UL && rej.reason==FD_FAILOVER_REJECT_HOLDS_IDENTITY );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->peer_tower.valid && !ctx->promote_peer );
    controller_fini( ctx );
  }
  FD_LOG_NOTICE(( "pass: a DEMOTED is refused while either side may hold the identity" ));
}

/* test_demoted_from_active: a DEMOTED is taken only from the junk key
   and boot that last said ACTIVE, across sessions.  A certified member
   that never said ACTIVE is refused. */
static void
test_demoted_from_active( void ) {
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  fd_memset( ctx->channel->peer_hello.junk_pubkey, 0x22, 32UL );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL ) );
  fd_failover_promote_rejected_t rej = pending_rejected( ctx );
  FD_TEST( rej.handoff_id==42UL && rej.reason==FD_FAILOVER_REJECT_HOLDS_IDENTITY );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->peer_tower.valid && !ctx->promote_peer );
  ctx->pending_valid = 0;

  /* Junk key 0x33 at boot 78 says ACTIVE, stands by and goes away. */
  unpair( ctx );
  fd_memset( ctx->channel->peer_hello.junk_pubkey, 0x33, 32UL );
  pair( ctx, 78UL, FD_FAILOVER_ROLE_ACTIVE, 1000L );
  peer_says( ctx, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_SLOT_NULL, 1000L );
  FD_TEST( ctx->active_boot_id==78UL );

  /* 0x22 is still refused, and so is 0x33 under a new boot. */
  for( ulong i=0UL; i<2UL; i++ ) {
    unpair( ctx );
    fd_memset( ctx->channel->peer_hello.junk_pubkey, i ? 0x33 : 0x22, 32UL );
    pair( ctx, 79UL+i, FD_FAILOVER_ROLE_STANDBY, 1000L );
    deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, demoted_payload( payload, 43UL+i, OUR_BOOT_ID, 99UL ) );
    rej = pending_rejected( ctx );
    FD_TEST( rej.handoff_id==43UL+i && rej.reason==FD_FAILOVER_REJECT_HOLDS_IDENTITY );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->peer_tower.valid );
    ctx->pending_valid = 0;
  }

  /* 0x33 at boot 78 pairs again and its DEMOTED is taken. */
  unpair( ctx );
  fd_memset( ctx->channel->peer_hello.junk_pubkey, 0x33, 32UL );
  pair( ctx, 78UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, demoted_payload( payload, 45UL, OUR_BOOT_ID, 99UL ) );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && ctx->promote_peer && ctx->promote_handoff_id==45UL );
  FD_TEST( !ctx->pending_valid );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a DEMOTED is taken only from the member we last saw active" ));
}

/* test_wrong_target: a DEMOTED meant for another boot of ours is
   refused and nothing is kept. */
static void
test_wrong_target( void ) {
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  for( ulong i=0UL; i<2UL; i++ ) {
    ulong payload_sz = demoted_payload( payload, 44UL+i, OUR_BOOT_ID+1UL, 99UL );
    deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
    fd_failover_promote_rejected_t rej = pending_rejected( ctx );
    FD_TEST( rej.handoff_id==44UL+i && rej.reason==FD_FAILOVER_REJECT_WRONG_TARGET );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->peer_tower.valid );
    ctx->pending_valid = 0;
  }
  FD_TEST( !ctx->channel->metrics.wire_fatal_cnt );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a DEMOTED for another boot is refused" ));
}

/* test_malformed_control: a control frame that does not decode, or one
   of a type we do not know, drops the session. */
static void
test_malformed_control( void ) {
  uchar  payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  ulong  demoted_sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL );
  ushort types[ 4 ] = { (ushort)FD_FAILOVER_MSG_DEMOTED, (ushort)FD_FAILOVER_MSG_PROMOTE_ACK,
                        (ushort)FD_FAILOVER_MSG_PROMOTE_REJECTED, (ushort)FD_FAILOVER_MSG_RESERVED };
  ulong  sizes[ 4 ] = { demoted_sz-1UL, sizeof(fd_failover_promote_ack_t)+1UL,
                        sizeof(fd_failover_promote_rejected_t)+1UL, 1UL };
  for( ulong i=0UL; i<4UL; i++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
    pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
    ctx->channel->active = 0; /* a live session, so a hangup drops it */
    deliver( ctx, types[ i ], payload, sizes[ i ] );
    FD_TEST( ctx->channel->metrics.wire_fatal_cnt==1UL );
    FD_TEST( fd_failover_channel_state( ctx->channel )!=FD_FAILOVER_SESSION_PAIRED && !ctx->peer_status_valid );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && !ctx->pending_valid && !ctx->peer_tower.valid );
    controller_fini( ctx );
  }
  FD_LOG_NOTICE(( "pass: a control frame that does not decode drops the session" ));
}

/* test_boot_binding: DEMOTED is resent on each new session with the
   same peer boot and stops once the peer restarted. */
static void
test_boot_binding( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_tower( &ctx->cs, 99UL );
  demote_through( ctx, 1 );
  ulong handoff_id = pending_demoted( ctx ).handoff_id;

  /* It went out, then the session drops and comes back with the same
     boot, so it goes out again. */
  ctx->pending_valid = 0;
  ctx->demoted_sent  = 1;
  step_controller( ctx, stem );
  FD_TEST( !ctx->pending_valid );
  unpair( ctx );
  step_controller( ctx, stem );
  FD_TEST( !ctx->pending_valid );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  FD_TEST( !ctx->demoted_sent );
  step_controller( ctx, stem );
  FD_TEST( pending_demoted( ctx ).handoff_id==handoff_id );

  /* A new peer boot, it restarted on its junk key.  The DEMOTED is
     dropped and the handoff is over. */
  unpair( ctx );
  pair( ctx, 78UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  step_controller( ctx, stem );
  FD_TEST( !ctx->pending_valid && !ctx->send_demoted && ctx->action==FD_FAILOVER_ACTION_IDLE );
  FD_TEST( ctx->handoff_result==FD_FAILOVER_HANDOFF_RESTARTED && !ctx->taken );
  deliver_ack( ctx, handoff_id );
  FD_TEST( ctx->handoff_result==FD_FAILOVER_HANDOFF_RESTARTED && !ctx->taken );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: DEMOTED is bound to the peer boot it was made for" ));
}

/* test_repeated_handoff_tower: a handoff right after a promotion hands
   over the adopted tower, not an older cached one. */
static void
test_repeated_handoff_tower( void ) {
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, 1000L );
  make_tower( &ctx->cs, 50UL );
  ctx->tower_gap   = 1; /* a frag skipped earlier, the promotion clears it */
  ctx->replay_slot = 120UL;
  ulong payload_sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 120UL );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  step_controller( ctx, stem );
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 120UL );
  step_controller( ctx, stem );
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && ctx->last_vote_slot==120UL );
  ctx->pending_valid = 0;

  demote_through( ctx, 1 );
  fd_failover_demoted_t demoted = pending_demoted( ctx );
  FD_TEST( demoted.last_vote_slot==120UL && demoted.state_len==payload_sz-sizeof(fd_failover_demoted_t) );
  FD_TEST( fd_memeq( ctx->pending+sizeof(fd_failover_demoted_t), payload+sizeof(fd_failover_demoted_t), demoted.state_len ) );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: an immediate handoff back hands over the adopted tower" ));
}

/* test_ack_during_switch: an answer while the junk switch is in flight
   answers nothing, since no DEMOTED went out yet. */
static void
test_ack_during_switch( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  make_tower( &ctx->cs, 99UL );
  start_demotion( ctx, 1 );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && ctx->send_demoted );
  deliver_ack( ctx, ctx->handoff_id );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && ctx->send_demoted && !ctx->taken );
  deliver_rejected( ctx, ctx->handoff_id, (uchar)FD_FAILOVER_REJECT_BUSY );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && ctx->send_demoted );
  FD_TEST( !ctx->channel->metrics.wire_fatal_cnt );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a promotion outcome is ignored while the junk switch is in flight" ));
}

/* test_adopt_unreplayed_retry: a tower on a block replay has not
   produced yet is asked for again once replay moves, up to the
   deadline. */
static void
test_adopt_unreplayed_retry( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  make_tower( &ctx->peer_tower, 99UL );
  start_promotion( ctx, FD_FAILOVER_SOURCE_PEER, 0 );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT );
  ulong first = ctx->adopt_expected_id;
  adopt_answer( ctx, FD_TOWER_ADOPT_ERR_UNREPLAYED, 90UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->adopt_retry );
  /* Nothing is asked until replay moves. */
  step_controller( ctx, stem );
  FD_TEST( ctx->adopt_retry && ctx->adopt_expected_id==first );
  ctx->replay_slot++;
  step_controller( ctx, stem );
  FD_TEST( !ctx->adopt_retry && ctx->adopt_expected_id!=first );
  /* An answer to the first request is stale. */
  ctx->adopt_result       = (fd_tower_adopt_result_t){ .result=FD_TOWER_ADOPT_SUCCESS, .vote_slot=99UL };
  ctx->adopt_result_id    = first;
  ctx->adopt_result_fresh = 1;
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT );
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 99UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH );
  controller_fini( ctx );

  /* The deadline still bounds the retries, and the peer hears why. */
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, 1000L );
  ulong payload_sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  step_controller( ctx, stem );
  adopt_answer( ctx, FD_TOWER_ADOPT_ERR_UNREPLAYED, 90UL );
  step_controller( ctx, stem );
  ctx->replay_slot = 1000UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->stuck );
  FD_TEST( pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_ADOPTION_FAILED && ctx->peer_tower.valid );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a tower short of replay is retried until the deadline" ));
}

/* Runs one tower_failov frag with the tower tile's answer through the
   stem callbacks. */
static void
adopt_frag( fd_failover_tile_ctx_t * ctx,
            ulong                    sig,
            ulong                    result,
            ulong                    vote_slot ) {
  fd_tower_adopt_result_t answer = { .result=result, .root=0UL, .vote_slot=vote_slot };
  fd_memcpy( fd_chunk_to_laddr( ctx->adopt_in_mem, 0UL ), &answer, sizeof(answer) );
  FD_TEST( !before_frag( ctx, ctx->adopt_in_idx, 0UL, sig ) );
  during_frag( ctx, ctx->adopt_in_idx, 0UL, sig, 0UL, sizeof(answer), 0UL );
  after_frag ( ctx, ctx->adopt_in_idx, 0UL, sig, sizeof(answer), 0UL, 0UL, stem );
}

/* test_adopt_answer_id: the tower tile's answer is matched to our
   request by the frag sig, a late answer to an earlier request is not
   taken for the current one. */
static void
test_adopt_answer_id( void ) {
  static uchar res_mem[ sizeof(fd_tower_adopt_result_t) ] __attribute__((aligned(128)));
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->adopt_in_idx = 2UL;
  ctx->adopt_in_mem = (fd_wksp_t *)res_mem;
  make_tower( &ctx->peer_tower, 99UL );
  start_promotion( ctx, FD_FAILOVER_SOURCE_PEER, 0 );
  step_controller( ctx, stem );
  ulong first = ctx->adopt_expected_id;
  adopt_frag( ctx, first, FD_TOWER_ADOPT_ERR_UNREPLAYED, 90UL );
  step_controller( ctx, stem );
  ctx->replay_slot++;
  step_controller( ctx, stem );
  ulong second = ctx->adopt_expected_id;
  FD_TEST( second!=first );

  /* A late answer to the first request says nothing about the second. */
  adopt_frag( ctx, first, FD_TOWER_ADOPT_SUCCESS, 99UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  adopt_frag( ctx, second, FD_TOWER_ADOPT_SUCCESS, 99UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_STAKED );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: an adopt answer counts only for the request it answers" ));
}

/* test_hello_refresh: a role change reaches the HELLO we advertise and
   the session stays up. */
static void
test_hello_refresh( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  fd_failover_channel_t * ch = ctx->channel;
  FD_TEST( ch->self_hello.role==FD_FAILOVER_ROLE_ACTIVE );
  set_role( ctx, FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( ch->self_hello.role==FD_FAILOVER_ROLE_STANDBY && ctx->hello.role==FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( ch->state==FD_FAILOVER_SESSION_PAIRED && !ctx->status_sent );

  /* A STATUS built now decodes fine. */
  fd_failover_status_t status = local_status( ctx, 1L );
  fd_failover_status_t out;
  FD_TEST( status.role==FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( fd_failover_status_decode( &out, (uchar const *)&status, sizeof(status) ) );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a role change reaches the advertised HELLO" ));
}

/* test_deadline_arms_late: a wait started before the first replay slot
   still reaches its deadline. */
static void
test_deadline_arms_late( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->replay_slot = FD_FAILOVER_SLOT_NULL;
  ctx->action      = FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK;
  step_controller( ctx, stem );
  FD_TEST( ctx->deadline_slot==FD_FAILOVER_SLOT_NULL && ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK );

  ctx->replay_slot = 500UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->deadline_slot==500UL+FD_FAILOVER_DEADLINE_SLOTS );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK && !ctx->stuck );

  /* DEMOTED is still owed, so we stay in the wait and keep retrying
     while flagging stuck, rather than give up. */
  ctx->replay_slot = 500UL+FD_FAILOVER_DEADLINE_SLOTS+1UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK && ctx->stuck );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a wait started before replay reported still reaches its deadline" ));
}

/* test_late_promote_ack: an ACK after the deadline is still acted on,
   one we do not wait for or with another id is ignored. */
static void
test_late_promote_ack( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
  ctx->send_demoted   = 1;
  ctx->handoff_id     = 5001UL;
  ctx->handoff_target = 77UL;
  ctx->handoff_result = FD_FAILOVER_HANDOFF_PENDING;
  ctx->action         = FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK;
  ctx->stuck          = 1; /* the deadline fired */

  deliver_ack( ctx, 9UL );
  FD_TEST( ctx->send_demoted && ctx->handoff_result==FD_FAILOVER_HANDOFF_PENDING );
  deliver_ack( ctx, 5001UL );
  FD_TEST( !ctx->send_demoted && !ctx->stuck && ctx->action==FD_FAILOVER_ACTION_IDLE );
  FD_TEST( ctx->handoff_result==FD_FAILOVER_HANDOFF_TAKEN && ctx->taken && ctx->taken_boot_id==77UL );
  deliver_ack( ctx, 5001UL );
  FD_TEST( ctx->handoff_result==FD_FAILOVER_HANDOFF_TAKEN );

  /* A refusal with another id, or for a DEMOTED we no longer owe, is
     ignored too. */
  ctx->send_demoted = 1;
  ctx->handoff_id   = 5002UL;
  deliver_rejected( ctx, 5001UL, (uchar)FD_FAILOVER_REJECT_BUSY );
  FD_TEST( ctx->send_demoted && !ctx->stuck && ctx->handoff_result==FD_FAILOVER_HANDOFF_TAKEN );
  ctx->send_demoted = 0;
  deliver_rejected( ctx, 5002UL, (uchar)FD_FAILOVER_REJECT_BUSY );
  FD_TEST( !ctx->stuck && ctx->handoff_result==FD_FAILOVER_HANDOFF_TAKEN );

  /* A refusal is DECLINED and stuck. */
  ctx->send_demoted = 1;
  ctx->handoff_id   = 5002UL;
  deliver_rejected( ctx, 5002UL, (uchar)FD_FAILOVER_REJECT_BUSY );
  FD_TEST( !ctx->send_demoted && ctx->stuck && ctx->handoff_result==FD_FAILOVER_HANDOFF_DECLINED );
  FD_TEST( !ctx->channel->metrics.wire_fatal_cnt );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a late acknowledgement is acted on and an unowed one is ignored" ));
}

/* test_bus_control_ordering: a command's answer goes out before the
   switch request it leads to. */
static void
test_bus_control_ordering( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  ctx->admin_out_wmark = 16UL;

  fd_memset( &ctx->bus_req, 0, sizeof(ctx->bus_req) );
  ctx->bus_req.nonce = 77UL;
  fd_adminctl_failover_control_t req = { .version=FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION, .cmd=FD_ADMINCTL_FAILOVER_CMD_DEMOTE };
  fd_memcpy( ctx->bus_req.payload, &req, sizeof(req) );
  serve_bus_request( ctx, stem, 1000L );

  FD_TEST( pub_mcache[ 0 ].sig==FD_FAILOVER_BUS_CONTROL_RESP );
  fd_failover_bus_msg_t const * ans = fd_chunk_to_laddr_const( ctx->admin_out_mem, pub_mcache[ 0 ].chunk );
  FD_TEST( ans->nonce==77UL && ans->result==FD_ADMINCTL_RESULT_SUCCESS );
  fd_adminctl_failover_control_resp_t answer;
  fd_memcpy( &answer, ans->payload, sizeof(answer) );
  FD_TEST( answer.version==FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION );
  FD_TEST( answer.role==(uchar)FD_FAILOVER_ROLE_ACTIVE && answer.action==(uchar)FD_FAILOVER_ACTION_DEMOTE_SWITCH );
  FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );

  step_controller( ctx, stem );
  FD_TEST( pub_mcache[ 1 ].sig==FD_FAILOVER_BUS_SWITCH_REQ && pub_mcache[ 0 ].chunk!=pub_mcache[ 1 ].chunk );
  fd_failover_bus_msg_t const * sw = fd_chunk_to_laddr_const( ctx->admin_out_mem, pub_mcache[ 1 ].chunk );
  fd_failover_switch_req_t sreq;
  fd_memcpy( &sreq, sw->payload, sizeof(sreq) );
  FD_TEST( fd_memeq( sreq.identity, ctx->hello.junk_pubkey, 32UL ) && sw->nonce==ctx->switch_request_id );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a command's answer goes out before its switch request" ));
}

/* test_bus_refusal_once: a refused command is answered once, with the
   refusal and the request's nonce. */
static void
test_bus_refusal_once( void ) {
  static uchar req_mem[ sizeof(fd_failover_bus_msg_t) ] __attribute__((aligned(128)));
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->member_cert_set = 1;
  ctx->admin_out_wmark = 16UL;
  ctx->admin_in_idx    = 1UL;
  ctx->admin_in_mem    = (fd_wksp_t *)req_mem;

  fd_failover_bus_msg_t * msg = (fd_failover_bus_msg_t *)req_mem;
  fd_memset( msg, 0, sizeof(*msg) );
  msg->nonce = 77UL;
  fd_adminctl_failover_control_t req = { .version=FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION, .cmd=FD_ADMINCTL_FAILOVER_CMD_DEMOTE };
  fd_memcpy( msg->payload, &req, sizeof(req) );
  FD_TEST( !before_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_CONTROL_REQ ) );
  during_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_CONTROL_REQ, 0UL, sizeof(*msg), 0UL );
  after_frag ( ctx, 1UL, 0UL, FD_FAILOVER_BUS_CONTROL_REQ, sizeof(*msg), 0UL, 0UL, stem );
  for( ulong i=0UL; i<2UL; i++ ) {
    int busy = 0;
    after_credit( ctx, stem, NULL, &busy );
  }

  FD_TEST( stem->seqs[ 0 ]==1UL && pub_mcache[ 0 ].sig==FD_FAILOVER_BUS_CONTROL_RESP );
  fd_failover_bus_msg_t const * ans = fd_chunk_to_laddr_const( ctx->admin_out_mem, pub_mcache[ 0 ].chunk );
  FD_TEST( ans->nonce==77UL && ans->result==FD_FAILOVER_CONTROL_RESULT_BAD_ROLE );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_IDLE );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a refused command is answered once with its refusal" ));
}

/* test_promote_guard: promote is refused while the peer holds or may
   hold the identity, and on the operator's word otherwise. */
static void
test_promote_guard( void ) {
  long now = 100L*FD_FAILOVER_GOSSIP_FRESH_NANOS;
  ulong yes = FD_ADMINCTL_FAILOVER_FLAG_YES;

  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now )==FD_FAILOVER_CONTROL_RESULT_BAD_ROLE );
  controller_fini( ctx );

  /* Our own handoff unanswered, or anything else in flight. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->action = FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now )==FD_FAILOVER_CONTROL_RESULT_HANDOFF_PENDING );
  ctx->action = FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now )==FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS );
  ctx->action             = FD_FAILOVER_ACTION_IDLE;
  ctx->switch_pending_key = FD_FAILOVER_SWITCH_KEY_JUNK;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now )==FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS );
  controller_fini( ctx );

  /* The paired peer's latest STATUS, or its HELLO before one, says it
     holds the identity, or it is busy.  A HELLO has no busy bit, so a
     standby HELLO waits for the first STATUS. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_ACTIVE, now );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now )==FD_FAILOVER_CONTROL_RESULT_PEER_ACTIVE );
  ctx->peer_status_valid = 0;
  ctx->active_seen_at    = 0L;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now )==FD_FAILOVER_CONTROL_RESULT_PEER_ACTIVE );
  unpair( ctx );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, now );
  ctx->peer_status.flags = FD_FAILOVER_STATUS_BUSY;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now )==FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
  ctx->peer_status.flags = 0;
  ctx->peer_status_valid = 0;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now )==FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
  controller_fini( ctx );

  /* Unpaired, a peer that said ACTIVE within the silence window still
     counts, also when that was on a session that has since dropped. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE, FD_FAILOVER_SLOT_NULL, now );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now+FD_FAILOVER_CHANNEL_SILENCE_NANOS-1L )==FD_FAILOVER_CONTROL_RESULT_PEER_ACTIVE );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now+FD_FAILOVER_CHANNEL_SILENCE_NANOS    )==FD_ADMINCTL_RESULT_SUCCESS );
  controller_fini( ctx );
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, now );
  peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE, FD_FAILOVER_SLOT_NULL, now );
  unpair( ctx );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now+1L                               )==FD_FAILOVER_CONTROL_RESULT_PEER_ACTIVE );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now+FD_FAILOVER_CHANNEL_SILENCE_NANOS )==FD_ADMINCTL_RESULT_SUCCESS );
  controller_fini( ctx );

  /* The peer took our handoff.  Until it stands by or restarts it may
     still be voting. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, now );
  ctx->taken         = 1;
  ctx->taken_boot_id = 77UL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now )==FD_FAILOVER_CONTROL_RESULT_TAKEN );
  unpair( ctx );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, now );
  FD_TEST( !ctx->taken ); /* its STANDBY status */
  ctx->taken = 1;
  unpair( ctx );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now )==FD_FAILOVER_CONTROL_RESULT_TAKEN );
  ctx->channel->state              = FD_FAILOVER_SESSION_PAIRED;
  ctx->channel->peer_hello.boot_id = 77UL;
  sync_session( ctx );
  FD_TEST( ctx->taken ); /* the same boot came back */
  unpair( ctx );
  ctx->channel->state              = FD_FAILOVER_SESSION_PAIRED;
  ctx->channel->peer_hello.boot_id = 78UL;
  sync_session( ctx );
  FD_TEST( !ctx->taken ); /* it restarted */
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now )==FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
  peer_says( ctx, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_SLOT_NULL, now );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now )==FD_ADMINCTL_RESULT_SUCCESS );
  controller_fini( ctx );

  /* Gossip has the staked identity from another host within the
     freshness window.  Our own address does not count. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  fd_memcpy( ctx->gossip_origin, ctx->hello.staked_pubkey, 32UL );
  ctx->gossip_socket = ctx->own_gossip;
  gossip_commit( ctx, now );
  FD_TEST( !ctx->staked_seen_at );
  ctx->gossip_socket.addr = FD_IP4_ADDR(10,0,0,9);
  gossip_commit( ctx, now );
  FD_TEST( ctx->staked_seen_at==now );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now+FD_FAILOVER_GOSSIP_FRESH_NANOS-1L )==FD_FAILOVER_CONTROL_RESULT_STAKED_SEEN );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now+FD_FAILOVER_GOSSIP_FRESH_NANOS    )==FD_ADMINCTL_RESULT_SUCCESS );
  /* A contact info from before the promote does not stop it at the switch. */
  step_controller( ctx, stem );
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, FD_FAILOVER_SLOT_NULL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_STAKED );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: promote is refused while the peer may hold the identity" ));
}

/* test_vote_account_yes: with no tower to adopt, promote needs --yes and
   sends the tower tile an empty request for the vote account tower. */
static void
test_vote_account_yes( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, 1000L )==FD_FAILOVER_CONTROL_RESULT_NO_TOWER );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_YES, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->promote_source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT && !ctx->cs.valid );
  FD_TEST( ctx->last_vote_slot==FD_FAILOVER_SLOT_NULL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT );
  FD_TEST( pub_mcache[ 0 ].sig==ctx->adopt_expected_id && !pub_mcache[ 0 ].sz );
  acct_answer( ctx, 95UL, 95UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && ctx->last_vote_slot==95UL );
  switch_ok( ctx, 0UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_ACTIVE && !ctx->pending_valid );
  controller_fini( ctx );

  /* A tower of our own is taken first, --yes or not. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  make_tower( &ctx->own_tower, 99UL );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->promote_source==FD_FAILOVER_SOURCE_OWN && ctx->adopt.tip==99UL );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: promote from the vote account needs --yes" ));
}

/* test_coverage_floor: the adopted tower has to reach the highest last
   vote the peer reported.  The vote account may also go ahead once
   replay passes that floor by the slack. */
static void
test_coverage_floor( void ) {
  long  now = 1000L;
  long  later = now+FD_FAILOVER_CHANNEL_SILENCE_NANOS;
  ulong yes = FD_ADMINCTL_FAILOVER_FLAG_YES;

  /* The floor only rises, counts a standby's last vote too, and outlives
     the session. */
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, now );
  peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE,  150UL, now );
  peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE,  140UL, now );
  FD_TEST( ctx->peer_floor==150UL );
  peer_says( ctx, FD_FAILOVER_ROLE_STANDBY, 160UL, now );
  peer_says( ctx, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_SLOT_NULL, now );
  unpair( ctx );
  FD_TEST( ctx->peer_floor==160UL );

  /* Our own final tower ends short of the floor and can never cover it,
     so promote skips it for the vote account, which needs --yes. */
  ctx->replay_slot = 200UL;
  make_tower( &ctx->own_tower, 120UL );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, later )==FD_FAILOVER_CONTROL_RESULT_NO_TOWER );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE );

  /* The vote account with --yes waits for the account's own last vote
     to cover the floor, also when our root already passed it and no
     vote is left to adopt. */
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, later )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->promote_source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT && ctx->promote_floor==160UL );
  step_controller( ctx, stem );
  FD_TEST( pub_mcache[ 0 ].sig==ctx->adopt_expected_id && !pub_mcache[ 0 ].sz );
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 140UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->adopt_retry );
  ctx->replay_slot++;
  step_controller( ctx, stem );
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 160UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && ctx->last_vote_slot==FD_FAILOVER_SLOT_NULL );
  controller_fini( ctx );

  /* A stored peer tower short of the floor is skipped too, and a peer's
     DEMOTED short of it never gets to the switch. */
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, now );
  peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE,  150UL, now );
  peer_says( ctx, FD_FAILOVER_ROLE_STANDBY, 150UL, now );
  make_tower( &ctx->peer_tower, 140UL );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, later )==FD_FAILOVER_CONTROL_RESULT_NO_TOWER );
  ulong payload_sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 140UL );
  ctx->replay_slot = 200UL;
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && ctx->promote_floor==150UL );
  step_controller( ctx, stem );
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 140UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->adopt_retry );
  FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  controller_fini( ctx );

  /* A tower of our own that reaches the floor is still taken first. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE, 150UL, now );
  make_tower( &ctx->own_tower, 150UL );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, later )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->promote_source==FD_FAILOVER_SOURCE_OWN && ctx->adopt.tip==150UL );
  controller_fini( ctx );

  /* Or until replay passes the floor by the slack, past the normal
     deadline. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE, 150UL, now );
  ctx->replay_slot = 200UL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, later )==FD_ADMINCTL_RESULT_SUCCESS );
  step_controller( ctx, stem );
  FD_TEST( ctx->deadline_slot==150UL+FD_FAILOVER_FLOOR_SLACK_SLOTS+FD_FAILOVER_DEADLINE_SLOTS );
  acct_answer( ctx, 140UL, 140UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->adopt_retry );
  ctx->replay_slot = 150UL+FD_FAILOVER_FLOOR_SLACK_SLOTS;
  step_controller( ctx, stem );
  acct_answer( ctx, 140UL, 140UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->adopt_retry && ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT );
  ctx->replay_slot++;
  step_controller( ctx, stem );
  acct_answer( ctx, 140UL, 140UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && ctx->last_vote_slot==140UL );
  controller_fini( ctx );

  /* With no floor known we go ahead, like an upstream restart. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, later )==FD_ADMINCTL_RESULT_SUCCESS );
  step_controller( ctx, stem );
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, FD_FAILOVER_SLOT_NULL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && ctx->last_vote_slot==FD_FAILOVER_SLOT_NULL );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a promotion covers the peer's reported votes" ));
}

/* test_own_floor: the votes we signed while active this boot raise the
   floor too, and a later promote has to cover them. */
static void
test_own_floor( void ) {
  long  later = 1000L+FD_FAILOVER_CHANNEL_SILENCE_NANOS;
  ulong yes   = FD_ADMINCTL_FAILOVER_FLAG_YES;

  /* A standby's slot done is not ours to cover.  The vote transaction
     here does not parse, so no final tower is kept, but the vote counts
     anyway. */
  static fd_tower_slot_done_t done;
  fd_memset( &done, 0, sizeof(done) );
  done.replay_slot  = 150UL;
  done.root_slot    = FD_FAILOVER_SLOT_NULL;
  done.vote_slot    = 150UL;
  done.has_vote_txn = 1;
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->own_floor==FD_FAILOVER_SLOT_NULL );
  controller_fini( ctx );

  ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->own_floor==150UL && !ctx->cs.valid );
  done.vote_slot = 140UL;
  consume_slot_done( ctx, &done );
  FD_TEST( ctx->own_floor==150UL );

  /* A demote with no final tower leaves the vote account, which has to
     reach our last vote, and a peer tower short of it is skipped. */
  demote_through( ctx, 0 );
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && !ctx->own_tower.valid );
  make_tower( &ctx->peer_tower, 145UL );
  ctx->replay_slot = 200UL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL, later )==FD_FAILOVER_CONTROL_RESULT_NO_TOWER );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, later )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->promote_source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT && ctx->promote_floor==150UL );
  step_controller( ctx, stem );
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 145UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->adopt_retry );
  ctx->replay_slot++;
  step_controller( ctx, stem );
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 150UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a promotion covers the votes we signed" ));
}

/* test_floor_wait_retry: the floor wait asks the tower tile again only
   when the account's last vote moved, else once replay passes the floor
   by the slack.  A peer tower short of the floor is not asked for again. */
static void
test_floor_wait_retry( void ) {
  long  now   = 1000L;
  long  later = now+FD_FAILOVER_CHANNEL_SILENCE_NANOS;
  ulong yes   = FD_ADMINCTL_FAILOVER_FLAG_YES;

  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE, 150UL, now );
  ctx->replay_slot = 200UL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, later )==FD_ADMINCTL_RESULT_SUCCESS );
  step_controller( ctx, stem );
  ulong asked = ctx->adopt_expected_id;
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 140UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->adopt_retry && ctx->floor_logged );

  /* The first answer is news, so we ask again once replay moves. */
  step_controller( ctx, stem );
  FD_TEST( ctx->adopt_expected_id==asked );
  ctx->replay_slot++;
  step_controller( ctx, stem );
  FD_TEST( ctx->adopt_expected_id!=asked );
  asked = ctx->adopt_expected_id;

  /* It moved and is still short, so again. */
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 145UL );
  step_controller( ctx, stem );
  ctx->replay_slot++;
  step_controller( ctx, stem );
  FD_TEST( ctx->adopt_expected_id!=asked );
  asked = ctx->adopt_expected_id;

  /* It stood still, replay moving asks nothing. */
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 145UL );
  step_controller( ctx, stem );
  for( ulong i=0UL; i<8UL; i++ ) {
    ctx->replay_slot++;
    step_controller( ctx, stem );
  }
  FD_TEST( ctx->adopt_expected_id==asked && ctx->adopt_retry );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT );

  /* Replay passing the floor by the slack asks once more and goes ahead. */
  ctx->replay_slot = 150UL+FD_FAILOVER_FLOOR_SLACK_SLOTS;
  step_controller( ctx, stem );
  FD_TEST( ctx->adopt_expected_id==asked );
  ctx->replay_slot++;
  step_controller( ctx, stem );
  FD_TEST( ctx->adopt_expected_id!=asked );
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 145UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH );
  controller_fini( ctx );

  /* A peer's DEMOTED short of the floor ends at the deadline without
     another ask. */
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, now );
  peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE,  150UL, now );
  peer_says( ctx, FD_FAILOVER_ROLE_STANDBY, 150UL, now );
  ctx->replay_slot = 200UL;
  ulong payload_sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 140UL );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  step_controller( ctx, stem );
  asked = ctx->adopt_expected_id;
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 140UL );
  step_controller( ctx, stem );
  ctx->replay_slot++;
  step_controller( ctx, stem );
  FD_TEST( ctx->adopt_retry && ctx->adopt_expected_id==asked );
  ctx->replay_slot = 200UL+FD_FAILOVER_DEADLINE_SLOTS+1UL;
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->adopt_expected_id==asked );
  FD_TEST( pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_ADOPTION_FAILED );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: the floor wait asks again only when the account moved" ));
}

/* test_floor_mid_promotion: a vote the peer reports while a promotion
   waits for replay or the adoption raises the floor it has to cover. */
static void
test_floor_mid_promotion( void ) {
  long  now   = 1000L;
  long  later = now+FD_FAILOVER_CHANNEL_SILENCE_NANOS;
  ulong yes   = FD_ADMINCTL_FAILOVER_FLAG_YES;

  /* Unpaired promote --yes starts with the floor at 150. */
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE, 150UL, now );
  ctx->replay_slot = 200UL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, later )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && ctx->promote_floor==150UL );

  /* The peer pairs before the adopt request and reports a vote at 170. */
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, later );
  peer_says( ctx, FD_FAILOVER_ROLE_STANDBY, 170UL, later );
  FD_TEST( ctx->promote_floor==170UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT );

  /* The account's last vote at 160 covers the old floor but not the new
     one, so there is no staked switch. */
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 160UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->adopt_retry );
  FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );

  /* A vote reported during the adopt wait counts too. */
  peer_says( ctx, FD_FAILOVER_ROLE_STANDBY, 175UL, later );
  FD_TEST( ctx->promote_floor==175UL );
  ctx->replay_slot++;
  step_controller( ctx, stem );
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 170UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  ctx->replay_slot++;
  step_controller( ctx, stem );
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 175UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_STAKED );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a vote the peer reports during a promotion raises its floor" ));
}

/* test_promote_clock: the replay and adopt waits of a promotion also end
   on our clock, so a standby whose replay froze stops and says why. */
static void
test_promote_clock( void ) {
  long  step  = FD_FAILOVER_DEADLINE_SLOT_NANOS;
  ulong yes   = FD_ADMINCTL_FAILOVER_FLAG_YES;
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];

  /* Replay stays short of the tower's tip and never reaches the slot
     deadline. */
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, 1000L );
  ulong payload_sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 120UL );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  long before = fd_failover_clock();
  step_controller( ctx, stem );
  long after = fd_failover_clock();
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY );
  FD_TEST( ctx->promote_until>=before+(long)FD_FAILOVER_DEADLINE_SLOTS*step );
  FD_TEST( ctx->promote_until<=after +(long)FD_FAILOVER_DEADLINE_SLOTS*step );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY );
  ctx->promote_until = fd_failover_clock();
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->stuck );
  FD_TEST( pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_REPLAY_BEHIND );
  controller_fini( ctx );

  /* The adopt wait too.  The vote account's floor wait gets the slack
     on the clock as well. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE, 150UL, 1000L );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, 1000L+FD_FAILOVER_CHANNEL_SILENCE_NANOS )==FD_ADMINCTL_RESULT_SUCCESS );
  before = fd_failover_clock();
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT );
  FD_TEST( ctx->promote_until>=before+(long)(FD_FAILOVER_FLOOR_SLACK_SLOTS+FD_FAILOVER_DEADLINE_SLOTS)*step );
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 140UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->adopt_retry );
  ctx->promote_until = fd_failover_clock();
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck );
  FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a promotion stops on our clock when replay freezes" ));
}

/* test_promote_force: promote --force skips every check on the peer and
   gives up on our own handoff, but not a promotion or switch in flight.
   The vote account still needs --yes and the floor still applies. */
static void
test_promote_force( void ) {
  long  now   = 100L*FD_FAILOVER_GOSSIP_FRESH_NANOS;
  ulong yes   = FD_ADMINCTL_FAILOVER_FLAG_YES;
  ulong force = FD_ADMINCTL_FAILOVER_FLAG_FORCE;

  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes|force, now )==FD_FAILOVER_CONTROL_RESULT_BAD_ROLE );
  controller_fini( ctx );
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->action = FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes|force, now )==FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS );
  ctx->action             = FD_FAILOVER_ACTION_IDLE;
  ctx->switch_pending_key = FD_FAILOVER_SWITCH_KEY_JUNK;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes|force, now )==FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS );
  controller_fini( ctx );

  /* An ACTIVE peer that took our handoff while gossip shows the staked
     identity elsewhere.  Only --force goes ahead, and it does not stop
     when the peer says ACTIVE again. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_ACTIVE, now );
  ctx->taken          = 1;
  ctx->taken_boot_id  = 77UL;
  ctx->staked_seen_at = now;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes,       now )==FD_FAILOVER_CONTROL_RESULT_TAKEN );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, force,     now )==FD_FAILOVER_CONTROL_RESULT_NO_TOWER );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes|force, now )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->promote_force && ctx->promote_source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT );
  step_controller( ctx, stem );
  peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE, FD_FAILOVER_SLOT_NULL, now+1L );
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, FD_FAILOVER_SLOT_NULL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_STAKED );
  controller_fini( ctx );

  /* A paired standby with no STATUS yet, or a busy one. */
  for( int busy=0; busy<2; busy++ ) {
    ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
    pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, now );
    if( busy ) ctx->peer_status.flags = FD_FAILOVER_STATUS_BUSY;
    else       ctx->peer_status_valid = 0;
    FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes,       now )==FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY );
    FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes|force, now )==FD_ADMINCTL_RESULT_SUCCESS );
    controller_fini( ctx );
  }

  /* Our own handoff has no answer.  --force stops waiting for it and
     drops the DEMOTED we would resend, a late answer changes nothing. */
  ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, now );
  make_tower( &ctx->cs, 99UL );
  demote_through( ctx, 1 );
  ulong handoff_id = pending_demoted( ctx ).handoff_id;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, 0UL,   now )==FD_FAILOVER_CONTROL_RESULT_HANDOFF_PENDING );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, force, now )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( !ctx->pending_valid && !ctx->send_demoted && ctx->handoff_result==FD_FAILOVER_HANDOFF_CANCELLED );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && ctx->promote_source==FD_FAILOVER_SOURCE_OWN );
  deliver_ack( ctx, handoff_id );
  FD_TEST( ctx->handoff_result==FD_FAILOVER_HANDOFF_CANCELLED && !ctx->taken );
  controller_fini( ctx );

  /* The floor still holds a forced promote back. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair( ctx, 77UL, FD_FAILOVER_ROLE_ACTIVE, now );
  peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE, 150UL, now );
  ctx->replay_slot = 200UL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes|force, now )==FD_ADMINCTL_RESULT_SUCCESS );
  step_controller( ctx, stem );
  acct_answer( ctx, FD_FAILOVER_SLOT_NULL, 140UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT && ctx->adopt_retry );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: promote --force skips the checks on the peer and nothing else" ));
}

/* test_force_cleared: a DEMOTED after a forced promote that failed runs
   without --force, so the peer saying ACTIVE still stops it. */
static void
test_force_cleared( void ) {
  long  now = 100L*FD_FAILOVER_GOSSIP_FRESH_NANOS;
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_YES|FD_ADMINCTL_FAILOVER_FLAG_FORCE, now )==FD_ADMINCTL_RESULT_SUCCESS );
  step_controller( ctx, stem );
  adopt_answer( ctx, FD_TOWER_ADOPT_ERR_INVALID, FD_FAILOVER_SLOT_NULL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->promote_force );

  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, now );
  peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE,  FD_FAILOVER_SLOT_NULL, now );
  peer_says( ctx, FD_FAILOVER_ROLE_STANDBY, FD_FAILOVER_SLOT_NULL, now );
  ulong payload_sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && ctx->promote_peer && !ctx->promote_force );
  step_controller( ctx, stem );
  peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE, FD_FAILOVER_SLOT_NULL, now );
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 99UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  FD_TEST( pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_HOLDS_IDENTITY );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a promotion on the peer's DEMOTED never inherits --force" ));
}

/* test_holder_recheck: right before the staked switch we look again.  An
   operator promote stops when the peer said ACTIVE since it started or a
   new staked contact info arrived, a handoff only when the paired peer
   says ACTIVE. */
static void
test_holder_recheck( void ) {
  long  now = 100L*FD_FAILOVER_GOSSIP_FRESH_NANOS;
  ulong yes = FD_ADMINCTL_FAILOVER_FLAG_YES;
  for( ulong variant=0UL; variant<3UL; variant++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
    pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, now );
    FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now )==FD_ADMINCTL_RESULT_SUCCESS );
    step_controller( ctx, stem );
    if( variant==0UL ) {
      /* It said ACTIVE on a session that dropped since. */
      peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE, FD_FAILOVER_SLOT_NULL, now+1L );
      unpair( ctx );
    } else if( variant==1UL ) {
      fd_memcpy( ctx->gossip_origin, ctx->hello.staked_pubkey, 32UL );
      ctx->gossip_socket.addr = FD_IP4_ADDR(10,0,0,9);
      ctx->gossip_socket.port = ctx->own_gossip.port;
      gossip_commit( ctx, now+1L );
    } else {
      unpair( ctx );
      pair( ctx, 78UL, FD_FAILOVER_ROLE_ACTIVE, now+1L );
    }
    acct_answer( ctx, FD_FAILOVER_SLOT_NULL, FD_FAILOVER_SLOT_NULL );
    step_controller( ctx, stem );
    FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck );
    FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT && !ctx->pending_valid );
    controller_fini( ctx );
  }

  /* A handoff goes ahead past the demoter's own contact info. */
  uchar payload[ FD_FAILOVER_DEMOTED_PAYLOAD_MAX ];
  ulong payload_sz = demoted_payload( payload, 42UL, OUR_BOOT_ID, 99UL );
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, now );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  step_controller( ctx, stem );
  fd_memcpy( ctx->gossip_origin, ctx->hello.staked_pubkey, 32UL );
  ctx->gossip_socket.addr = FD_IP4_ADDR(10,0,0,9);
  ctx->gossip_socket.port = ctx->own_gossip.port;
  gossip_commit( ctx, now );
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 99UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_SWITCH );
  controller_fini( ctx );

  /* And stops with HOLDS_IDENTITY once the paired peer says ACTIVE. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  pair_demoter( ctx, 77UL, now );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  step_controller( ctx, stem );
  peer_says( ctx, FD_FAILOVER_ROLE_ACTIVE, FD_FAILOVER_SLOT_NULL, now );
  adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, 99UL );
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  FD_TEST( pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_HOLDS_IDENTITY );
  controller_fini( ctx );

  /* Before the first STATUS of a session the peer's HELLO is its word, an
     ACTIVE one stops an operator promote and a handoff alike. */
  for( int from_peer=0; from_peer<2; from_peer++ ) {
    ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
    if( from_peer ) {
      pair_demoter( ctx, 77UL, now );
      deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
      unpair( ctx );
    } else {
      FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, yes, now )==FD_ADMINCTL_RESULT_SUCCESS );
    }
    step_controller( ctx, stem );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_ADOPT );
    ctx->channel->state              = FD_FAILOVER_SESSION_PAIRED;
    ctx->channel->peer_hello.boot_id = 77UL;
    ctx->channel->peer_hello.role    = (uchar)FD_FAILOVER_ROLE_ACTIVE;
    sync_session( ctx );
    FD_TEST( !ctx->peer_status_valid );
    adopt_answer( ctx, FD_TOWER_ADOPT_SUCCESS, from_peer ? 99UL : FD_FAILOVER_SLOT_NULL );
    step_controller( ctx, stem );
    FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->stuck );
    FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
    if( from_peer ) FD_TEST( pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_HOLDS_IDENTITY );
    controller_fini( ctx );
  }
  FD_LOG_NOTICE(( "pass: a promotion checks for another holder again before its switch" ));
}

/* test_switch_request: request_switch publishes one request at a time
   and switch_answer takes only the matching nonce. */
static void
test_switch_request( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ulong id = request_switch( ctx, stem, FD_FAILOVER_SWITCH_KEY_STAKED );
  FD_TEST( id!=ULONG_MAX && id==ctx->switch_request_id && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_STAKED );
  fd_failover_bus_msg_t const * out = (fd_failover_bus_msg_t const *)bus_mem;
  FD_TEST( pub_mcache[ 0 ].sig==FD_FAILOVER_BUS_SWITCH_REQ && out->nonce==id );
  fd_failover_switch_req_t req;
  fd_memcpy( &req, out->payload, sizeof(req) );
  FD_TEST( fd_memeq( req.identity, ctx->hello.staked_pubkey, 32UL ) );

  /* One request at a time. */
  FD_TEST( request_switch( ctx, stem, FD_FAILOVER_SWITCH_KEY_JUNK )==ULONG_MAX );

  /* A stale answer is dropped and the request stays out. */
  FD_TEST( !switch_answer( ctx, id-1UL ) );
  FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_STAKED && !ctx->switch_result_fresh );

  /* The matching answer completes it. */
  FD_TEST( switch_answer( ctx, id ) );
  FD_TEST( ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT && ctx->switch_result_fresh && ctx->switch_result_id==id );

  /* An answer with nothing out is dropped. */
  ctx->switch_result_fresh = 0;
  FD_TEST( !switch_answer( ctx, id ) && !ctx->switch_result_fresh );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: one identity switch at a time and only its own answer counts" ));
}

/* test_switch_response_integrity: the accepted switch answer stays live
   while the tower drains.  A stale, repeated or abandoned frame never
   overwrites the watermark we drain toward. */
static void
test_switch_response_integrity( void ) {
  static uchar ans_mem[ sizeof(fd_failover_bus_msg_t) ] __attribute__((aligned(128)));
  for( ulong fault=0UL; fault<3UL; fault++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
    pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );
    make_tower( &ctx->cs, 99UL );
    ctx->admin_in_idx = 1UL;
    ctx->admin_in_mem = (fd_wksp_t *)ans_mem;
    start_demotion( ctx, 1 );
    step_controller( ctx, stem );
    ctx->tower_seen_seq = 796UL;
    fd_failover_bus_msg_t *   answer = (fd_failover_bus_msg_t *)ans_mem;
    fd_failover_switch_resp_t result = { .result=FD_FAILOVER_SWITCH_OK, .tower_watermark=800UL };
    answer->nonce = ctx->switch_request_id;
    fd_memcpy( answer->payload, &result, sizeof(result) );
    during_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_SWITCH_RESP, 0UL, sizeof(*answer), 0UL );
    after_frag ( ctx, 1UL, 0UL, FD_FAILOVER_BUS_SWITCH_RESP, sizeof(*answer), 0UL, 0UL, stem );
    step_controller( ctx, stem );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && ctx->switch_result_fresh && !ctx->pending_valid );

    /* An old nonce, the same answer again, or a copy the stem abandons
       before after_frag, each with a lower watermark. */
    if( fault==0UL ) answer->nonce--;
    result.tower_watermark = 100UL;
    fd_memcpy( answer->payload, &result, sizeof(result) );
    during_frag( ctx, 1UL, 1UL, FD_FAILOVER_BUS_SWITCH_RESP, 0UL, sizeof(*answer), 0UL );
    if( fault!=2UL ) after_frag( ctx, 1UL, 1UL, FD_FAILOVER_BUS_SWITCH_RESP, sizeof(*answer), 0UL, 0UL, stem );
    step_controller( ctx, stem );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_SWITCH && ctx->switch_result_fresh );
    FD_TEST( ctx->switch_result.tower_watermark==800UL && !ctx->pending_valid );

    ctx->tower_seen_seq = 799UL;
    step_controller( ctx, stem );
    FD_TEST( ctx->action==FD_FAILOVER_ACTION_DEMOTE_WAIT_ACK );
    (void)pending_demoted( ctx );
    controller_fini( ctx );
  }
  FD_LOG_NOTICE(( "pass: stale, repeated and abandoned switch answers keep the accepted watermark" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char dir[] = "/tmp/fd_failover_tile.XXXXXX";
  FD_TEST( mkdtemp( dir ) );
  FD_TEST( fd_sha512_join( fd_sha512_new( sha ) ) );
  for( ulong i=0UL; i<3UL; i++ ) {
    fd_memset( keys[ i ], (int)(i+1UL), 32UL );
    fd_ed25519_public_from_private( keys[ i ]+32UL, keys[ i ], sha );
    FD_TEST( fd_cstr_printf_check( key_paths[ i ], PATH_MAX, NULL, "%s/key%lu.json", dir, i ) );
    write_key( key_paths[ i ], keys[ i ] );
  }
  uchar vote_pubkey[ 32 ];
  fd_memset( vote_pubkey, 0xBB, 32UL );
  fd_base58_encode_32( vote_pubkey, NULL, vote_account );

  FD_TEST( fd_failover_channel_footprint()<=sizeof(ch_mem) );
  test_slot_done_bookkeeping();
  test_final_tower();
  test_before_frag_admits();
  test_demotion_order();
  test_active_handoff_checks();
  test_demotion_drain();
  test_switch_overdue();
  test_promotion_reject();
  test_promotion_switch_failed();
  test_promotion_wait_replay();
  test_command_clears_stuck();
  test_promotion_outcome_resent();
  test_dedup();
  test_demote_sends_nothing();
  test_stored_tower();
  test_promote_refusals();
  test_demoted_from_active();
  test_wrong_target();
  test_malformed_control();
  test_boot_binding();
  test_repeated_handoff_tower();
  test_ack_during_switch();
  test_adopt_unreplayed_retry();
  test_adopt_answer_id();
  test_hello_refresh();
  test_deadline_arms_late();
  test_late_promote_ack();
  test_bus_control_ordering();
  test_bus_refusal_once();
  test_promote_guard();
  test_vote_account_yes();
  test_coverage_floor();
  test_own_floor();
  test_floor_wait_retry();
  test_floor_mid_promotion();
  test_promote_clock();
  test_promote_force();
  test_force_cleared();
  test_holder_recheck();
  test_switch_request();
  test_switch_response_integrity();

  ulong footprint = scratch_footprint( &tiles[ 0 ] );
  FD_TEST( footprint%scratch_align()==0UL );
  void * mem = aligned_alloc( scratch_align(), 3UL*footprint );
  FD_TEST( mem );
  topo.workspaces[ 0 ].wksp = mem;
  for( ulong i=0UL; i<2UL; i++ ) {
    topo.objs[ i ].id     = i;
    topo.objs[ i ].offset = (i+1UL)*footprint;
  }
  links_init();

  fd_failover_tile_ctx_t * a = boot( 0UL );
  fd_failover_tile_ctx_t * b = boot( 1UL );
  test_gossip_filter( a );
  test_gossip_dialer( a );
  test_gossip_listener( b );
  shutdown_pair( a, b );

  a = boot( 0UL );
  b = boot( 1UL );
  test_gossip_pairs( a, b );
  test_status_interval( a );
  test_status_session_edge( a, b );
  shutdown_pair( a, b );

  a = boot( 0UL );
  b = boot( 1UL );
  test_bad_status_session( a, b );
  shutdown_pair( a, b );

  test_peer_address_self();
  fd_cstr_ncpy( boot_peer_address, "10.0.0.5", sizeof(boot_peer_address) );
  a = boot( 0UL );
  boot_peer_address[ 0 ] = '\0';
  test_configured_peer( a );
  fd_failover_channel_fini( a->channel );

  a = boot( 0UL );
  b = boot( 1UL );
  test_demoted_from_standby_session( a, b );
  shutdown_pair( a, b );

  a = boot( 0UL );
  b = boot( 1UL );
  test_handoff_session( a, b );
  shutdown_pair( a, b );

  a = boot( 0UL );
  b = boot( 1UL );
  b = test_boot_binding_session( a, b );
  shutdown_pair( a, b );

  for( ulong i=0UL; i<3UL; i++ ) FD_TEST( !unlink( key_paths[ i ] ) );
  FD_TEST( !rmdir( dir ) );
  fd_wksp_delete_anonymous( wksp );
  free( mem );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
