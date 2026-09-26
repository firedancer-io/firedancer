/* The tests read the channel's dial address, so they build it in. */
#include "fd_failover_channel.c"
#include "fd_failover_tile.c"
#include "../../ballet/ed25519/fd_ed25519.h"
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

static void
set_role( fd_failover_tile_ctx_t * ctx,
          ulong                    role ) {
  ctx->role = role;
  fd_failover_channel_set_role( ctx->channel, role );
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

  /* Both members run on this host, so the standby dials the active's
     ephemeral port instead of a shared one. */
  standby->port = fd_failover_channel_listen_port( active->channel );
  contact_info( active,  keys[ 2 ]+32UL, OWN_GOSSIP_ADDR,         OWN_GOSSIP_PORT );
  contact_info( standby, keys[ 2 ]+32UL, FD_IP4_ADDR(127,0,0,1), 8002            );
  long deadline = fd_failover_clock()+10000000000L;
  while( !standby->peer_status_valid || !active->peer_status_valid ) {
    FD_TEST( fd_failover_clock()<deadline );
    peer_poll( standby, fd_failover_clock(), &busy );
    peer_poll( active,  fd_failover_clock(), &busy );
  }
  FD_TEST( fd_failover_channel_state( standby->channel )==FD_FAILOVER_SESSION_PAIRED );
  FD_TEST( fd_failover_channel_state( active->channel  )==FD_FAILOVER_SESSION_PAIRED );
  FD_TEST( fd_failover_channel_metrics( standby->channel )->paired_cnt==1UL );
  FD_TEST( !active->channel->dial_peer && !active->channel->candidates[ active->channel->active ].dialed );
  FD_TEST( active->peer_status.role==FD_FAILOVER_ROLE_STANDBY && standby->peer_status.role==FD_FAILOVER_ROLE_ACTIVE );
  FD_LOG_NOTICE(( "pass: the standby pairs once gossip has the active's address" ));
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

  test_peer_address_self();
  fd_cstr_ncpy( boot_peer_address, "10.0.0.5", sizeof(boot_peer_address) );
  a = boot( 0UL );
  boot_peer_address[ 0 ] = '\0';
  test_configured_peer( a );
  fd_failover_channel_fini( a->channel );

  for( ulong i=0UL; i<3UL; i++ ) FD_TEST( !unlink( key_paths[ i ] ) );
  FD_TEST( !rmdir( dir ) );
  fd_wksp_delete_anonymous( wksp );
  free( mem );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
