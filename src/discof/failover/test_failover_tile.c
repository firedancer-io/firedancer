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
  (void)now;
  fd_memset( ctx->channel->peer_hello.junk_pubkey, 0x22, 32UL );
}

static void
unpair( fd_failover_tile_ctx_t * ctx ) {
  ctx->channel->state = FD_FAILOVER_SESSION_LISTENING;
  fd_memset( &ctx->channel->peer_hello, 0, sizeof(fd_failover_hello_t) );
  sync_session( ctx );
}


/* Pairs with a peer boot that said ACTIVE on an earlier session, the
   member whose DEMOTED we take. */
static void
pair_demoter( fd_failover_tile_ctx_t * ctx,
              ulong                    boot_id,
              long                     now ) {
  pair( ctx, boot_id, FD_FAILOVER_ROLE_ACTIVE, now );
  ctx->action          = FD_FAILOVER_ACTION_HANDOFF_WAIT_PEER;
  ctx->request_id      = 42UL;
  ctx->request_boot_id = boot_id;
  ctx->request_until   = now+FD_FAILOVER_CHANNEL_IDLE_NANOS;
  fd_memcpy( ctx->request_junk, ctx->channel->peer_hello.junk_pubkey, 32UL );
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

/* test_gossip_listener: an active keeps listening and dials nobody.
   The address it learned becomes the dial target once it stands by. */

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

/* test_status_session_edge: the standby hangs up and dials again.  The
   new session gets our STATUS at once, before the interval is up. */

/* test_configured_peer: a configured peer address is dialed and keeps
   its room on the listener.  Gossip then only refreshes staked_seen_at. */

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

/* test_gossip_pairs: without a contact info nothing is dialed, with one
   the standby dials the active and the pair trades STATUS. */

/* test_bad_status_session: a STATUS that does not decode drops the
   session. */

/* test_handoff_session: a handoff over a real session.  The session
   stays up through both role changes and the standby ends up active. */

/* test_demoted_from_standby_session: over a real session between two
   certified members, a DEMOTED from a member that never said ACTIVE is
   refused with HOLDS_IDENTITY. */

/* test_boot_binding_session: the standby restarts after our handoff
   began and before its DEMOTED went out.  The new boot never gets that
   DEMOTED and the handoff ends RESTARTED.  Returns the new boot. */

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
  FD_TEST( !before_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_STATUS_REQ   ) );
  FD_TEST( !before_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_SWITCH_RESP  ) );
  /* This tile publishes these, it never receives them. */
  FD_TEST(  before_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_CONTROL_RESP ) );
  FD_TEST(  before_frag( ctx, 1UL, 0UL, FD_FAILOVER_BUS_STATUS_RESP  ) );
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
  FD_TEST( ctx->channel->self_hello.role==FD_FAILOVER_ROLE_STANDBY && !ctx->stuck );
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
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && ctx->stuck );
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
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT && !ctx->peer_tower.valid );
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
  FD_TEST( ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && ctx->stuck );
  FD_TEST( ctx->channel->self_hello.role==(uchar)FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( !ctx->promote_peer && ctx->switch_pending_key==FD_FAILOVER_SWITCH_KEY_CNT );
  fd_failover_promote_rejected_t rej = pending_rejected( ctx );
  FD_TEST( rej.handoff_id==42UL && rej.reason==FD_FAILOVER_REJECT_SWITCH_FAILED );
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
  ctx->request_id = 43UL;
  payload_sz = demoted_payload( payload, 43UL, OUR_BOOT_ID, 200UL );
  deliver( ctx, (ushort)FD_FAILOVER_MSG_DEMOTED, payload, payload_sz );
  FD_TEST( ctx->deadline_slot==100UL+FD_FAILOVER_DEADLINE_SLOTS );
  ctx->replay_slot = 100UL+FD_FAILOVER_DEADLINE_SLOTS;
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_PROMOTE_WAIT_REPLAY && !ctx->pending_valid );
  ctx->replay_slot++;
  step_controller( ctx, stem );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->stuck );
  FD_TEST( !stem->seqs[ 0 ] );
  fd_failover_promote_rejected_t rej = pending_rejected( ctx );
  FD_TEST( rej.handoff_id==43UL && rej.reason==FD_FAILOVER_REJECT_REPLAY_BEHIND );
  controller_fini( ctx );

  /* Right after boot replay has reported no slot yet, the promotion waits
     for the first one. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->replay_slot = FD_FAILOVER_SLOT_NULL;
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_RECOVER|FD_ADMINCTL_FAILOVER_FLAG_FORCE, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
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
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && !ctx->peer_tower.valid );
  fd_failover_promote_rejected_t rej = pending_rejected( ctx );
  FD_TEST( rej.handoff_id==42UL && rej.reason==FD_FAILOVER_REJECT_ADOPTION_FAILED );
  FD_TEST( !ctx->channel->metrics.wire_fatal_cnt );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a promotion outcome is resent when the peer misses the reply" ));
}

/* test_dedup: the same DEMOTED while we still work on it gets nothing,
   the same handoff id from another peer boot is another handoff. */

/* test_demote_sends_nothing: a demote drops the identity and tells the
   peer nothing, paired or not. Either member may then recover, so a
   later promotion consults the vote account with explicit consent. */
static void
test_demote_sends_nothing( void ) {
  for( int paired=0; paired<2; paired++ ) {
    fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
    ctx->own_floor  = 99UL;
    ctx->peer_floor = 98UL;
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
    FD_TEST( !ctx->own_tower.valid && !ctx->peer_tower.valid );
    FD_TEST( ctx->own_floor==99UL && ctx->peer_floor==98UL );

    FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_FORCE, 1000L )==FD_FAILOVER_CONTROL_RESULT_NO_TOWER );
    FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_RECOVER|FD_ADMINCTL_FAILOVER_FLAG_FORCE, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
    FD_TEST( ctx->promote_source==FD_FAILOVER_SOURCE_VOTE_ACCOUNT && !ctx->adopt.valid && !ctx->adopt.sz );
    step_controller( ctx, stem );
    acct_answer( ctx, 99UL, 99UL );
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
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_FORCE, 1000L )==FD_FAILOVER_CONTROL_RESULT_NO_TOWER );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a demote sends nothing and requires explicit vote-account recovery" ));
}

/* stored_tower_ctx: a standby whose promotion on the peer's DEMOTED
   ended at the deadline. Its recovery cache is retired, its floor stays. */

/* test_stored_tower: after a declined handoff either member may recover
   without reporting another tenure. Plain and forced promotion require
   account consent even if replay has not rooted past the old final. */

/* test_promote_refusals: a DEMOTED is refused while we hold the
   identity, and without a STATUS from this session saying the peer
   stands by. */

/* test_demoted_from_active: a DEMOTED is taken only from the junk key
   and boot that last said ACTIVE, across sessions.  A certified member
   that never said ACTIVE is refused. */

/* test_wrong_target: a DEMOTED meant for another boot of ours is
   refused and nothing is kept. */

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
    FD_TEST( fd_failover_channel_state( ctx->channel )!=FD_FAILOVER_SESSION_PAIRED );
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
  FD_TEST( !ctx->own_tower.valid && !ctx->peer_tower.valid );
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
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->stuck );
  FD_TEST( pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_ADOPTION_FAILED && !ctx->peer_tower.valid );
  FD_TEST( ctx->adopt.valid && ctx->adopt.tip==99UL && ctx->peer_floor==99UL );
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
  FD_TEST( ch->state==FD_FAILOVER_SESSION_PAIRED );

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
  fd_memcpy( ctx->handoff_junk, ctx->channel->peer_hello.junk_pubkey, 32UL );
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
  make_tower( &ctx->peer_tower, 99UL );
  make_tower( &ctx->own_tower, 99UL );
  ctx->own_floor  = 99UL;
  ctx->peer_floor = 98UL;
  deliver_rejected( ctx, 5002UL, (uchar)FD_FAILOVER_REJECT_BUSY );
  FD_TEST( !ctx->send_demoted && ctx->stuck && ctx->handoff_result==FD_FAILOVER_HANDOFF_DECLINED );
  FD_TEST( !ctx->peer_tower.valid && !ctx->own_tower.valid && ctx->own_floor==99UL && ctx->peer_floor==98UL );
  FD_TEST( promote_source( ctx )==FD_FAILOVER_SOURCE_VOTE_ACCOUNT );
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

/* test_vote_account_recover: with no tower to adopt, promote needs --recover and
   sends the tower tile an empty request for the vote account tower. */
static void
test_vote_account_recover( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_FORCE, 1000L )==FD_FAILOVER_CONTROL_RESULT_NO_TOWER );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_RECOVER|FD_ADMINCTL_FAILOVER_FLAG_FORCE, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
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

  /* A tower of our own is taken first, --recover or not. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  make_tower( &ctx->own_tower, 99UL );
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_FORCE, 1000L )==FD_ADMINCTL_RESULT_SUCCESS );
  FD_TEST( ctx->promote_source==FD_FAILOVER_SOURCE_OWN && ctx->adopt.tip==99UL );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: promote from the vote account needs --recover" ));
}

/* test_coverage_floor: the adopted tower has to reach the highest last
   vote the peer reported.  The vote account may also go ahead once
   replay passes that floor by the slack. */

/* test_own_floor: the votes we signed while active this boot raise the
   floor too, and a later promote has to cover them. */
static void
test_own_floor( void ) {
  long  later = 1000L+FD_FAILOVER_CHANNEL_SILENCE_NANOS;
  ulong yes   = FD_ADMINCTL_FAILOVER_FLAG_RECOVER|FD_ADMINCTL_FAILOVER_FLAG_FORCE;

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
  FD_TEST( control( ctx, FD_ADMINCTL_FAILOVER_CMD_PROMOTE, FD_ADMINCTL_FAILOVER_FLAG_FORCE, later )==FD_FAILOVER_CONTROL_RESULT_NO_TOWER );
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

/* test_floor_mid_promotion: a vote the peer reports while a promotion
   waits for replay or the adoption raises the floor it has to cover. */

/* test_promote_clock: the replay and adopt waits of a promotion also end
   on our clock, so a standby whose replay froze stops and says why. */
static void
test_promote_clock( void ) {
  long  step  = FD_FAILOVER_DEADLINE_SLOT_NANOS;
  ulong yes   = FD_ADMINCTL_FAILOVER_FLAG_RECOVER|FD_ADMINCTL_FAILOVER_FLAG_FORCE;
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
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_HANDOFF_WAIT_RESULT && ctx->role==FD_FAILOVER_ROLE_STANDBY && ctx->stuck );
  FD_TEST( pending_rejected( ctx ).reason==FD_FAILOVER_REJECT_REPLAY_BEHIND );
  controller_fini( ctx );

  /* The adopt wait too.  The vote account's floor wait gets the slack
     on the clock as well. */
  ctx = controller_init( FD_FAILOVER_ROLE_STANDBY );
  ctx->peer_floor = 150UL;
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
   The vote account still needs --recover and the floor still applies. */

/* test_force_cleared: a DEMOTED after a forced promote that failed runs
   without --force, so the peer saying ACTIVE still stops it. */

/* test_holder_recheck: right before the staked switch we look again.  An
   operator promote stops when the peer said ACTIVE since it started or a
   new staked contact info arrived, a handoff only when the paired peer
   says ACTIVE. */

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

/* test_status_snapshot: failover status reports the controller, the
   peer and what promote would do, the same answer promote gives. */

/* test_bus_status: a status request is answered with the snapshot and
   its nonce, and changes nothing. */
static void
test_bus_status( void ) {
  fd_failover_tile_ctx_t * ctx = controller_init( FD_FAILOVER_ROLE_ACTIVE );
  ctx->admin_out_wmark = 16UL;
  pair( ctx, 77UL, FD_FAILOVER_ROLE_STANDBY, 1000L );

  fd_memset( &ctx->bus_req, 0, sizeof(ctx->bus_req) );
  ctx->bus_req.nonce = 78UL;
  ctx->bus_req_sig   = FD_FAILOVER_BUS_STATUS_REQ;
  fd_adminctl_failover_status_req_t req = { .version=FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION };
  fd_memcpy( ctx->bus_req.payload, &req, sizeof(req) );
  serve_bus_request( ctx, stem, 1000L );

  FD_TEST( pub_mcache[ 0 ].sig==FD_FAILOVER_BUS_STATUS_RESP && pub_mcache[ 0 ].sz==sizeof(fd_failover_bus_msg_t) );
  fd_failover_bus_msg_t const * ans = fd_chunk_to_laddr_const( ctx->admin_out_mem, pub_mcache[ 0 ].chunk );
  FD_TEST( ans->nonce==78UL && ans->result==FD_ADMINCTL_RESULT_SUCCESS );
  fd_adminctl_failover_status_resp_t got;
  fd_adminctl_failover_status_resp_t want;
  fd_memcpy( &got, ans->payload, sizeof(got) );
  status_snapshot( ctx, 1000L, &want );
  FD_TEST( fd_memeq( &got, &want, sizeof(got) ) );
  FD_TEST( got.role==FD_FAILOVER_ROLE_ACTIVE && got.peer_boot_id==77UL );
  FD_TEST( ctx->action==FD_FAILOVER_ACTION_IDLE && ctx->role==FD_FAILOVER_ROLE_ACTIVE && !ctx->pending_valid );
  controller_fini( ctx );
  FD_LOG_NOTICE(( "pass: a status request is answered with the snapshot" ));
}

#include "test_failover_ondemand.inc"
#include "test_failover_recovery.inc"
#include "test_failover_preserved.inc"
#include "test_failover_unilateral.inc"

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  FD_TEST( fd_sha512_join( fd_sha512_new( sha ) ) );
  FD_TEST( fd_failover_channel_footprint()<=sizeof(ch_mem) );
  test_slot_done_bookkeeping();
  test_final_tower();
  test_before_frag_admits();
  test_demotion_order();
  test_demotion_drain();
  test_switch_overdue();
  test_promotion_reject();
  test_promotion_switch_failed();
  test_promotion_wait_replay();
  test_promotion_outcome_resent();
  test_demote_sends_nothing();
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
  test_vote_account_recover();
  test_own_floor();
  test_promote_clock();
  test_switch_request();
  test_switch_response_integrity();
  test_bus_status();
  test_ondemand();
  test_recovery();
  test_preserved();
  test_unilateral_permissions();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
