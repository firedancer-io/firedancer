#include "fd_gossip_tile.c"

#include <stdlib.h>

static fd_gossip_tile_ctx_t ctx;
static ulong                sign_cnt;

static void
test_sign_fn( void *        sign_ctx  FD_PARAM_UNUSED,
              uchar const * data      FD_PARAM_UNUSED,
              ulong         sz        FD_PARAM_UNUSED,
              int           sign_type FD_PARAM_UNUSED ) {
  sign_cnt++;
}

static uchar * manifest_mem;

/* Drives snapin_manif: the manifest carries the boot slot, the
   FD_SSMSG_DONE that follows classifies it (see fd_wfs.h). */

static void
wfs_manifest( ulong slot ) {
  fd_snapshot_manifest_t * manifest = (fd_snapshot_manifest_t *)manifest_mem;
  manifest->slot = slot;
  FD_TEST( !returnable_frag( &ctx, 1UL, 0UL, fd_ssmsg_sig( FD_SSMSG_MANIFEST_FULL ), 0UL,
                             sizeof(fd_snapshot_manifest_t), 0UL, 0UL, 0UL, NULL ) );
}

static void
wfs_done( void ) {
  FD_TEST( !returnable_frag( &ctx, 1UL, 0UL, fd_ssmsg_sig( FD_SSMSG_DONE ), 0UL, 0UL, 0UL, 0UL, 0UL, NULL ) );
}

/* Boots with the given WFS config, feeds a manifest at boot_slot and
   the DONE after it, and returns the state gossip settles in. */

static void
wfs_boot( ulong  wfs_slot,
          int    hash_is_zero,
          ushort shred_version ) {
  ctx.wfs_slot          = wfs_slot;
  ctx.wfs_hash_is_zero  = hash_is_zero;
  ctx.wfs_shred_version = shred_version;
  ctx.wfs_boot_slot     = ULONG_MAX;
  ctx.wfs_state         = fd_int_if( fd_wfs_configured( wfs_slot, hash_is_zero, (ulong)shred_version ),
                                     FD_GOSSIP_WFS_STATE_INIT, FD_GOSSIP_WFS_STATE_DONE );
  ctx.wfs_stakes_cnt    = 0UL;
  ctx.wfs_stake.online  = 0UL;
  ctx.wfs_stake.total   = 0UL;
  ctx.wfs_peers.online  = 0UL;
  ctx.wfs_peers.total   = 0UL;
  memset( ctx.wfs_active, 0, sizeof(ctx.wfs_active) );
  ctx.in[ 1 ] = (fd_gossip_in_ctx_t){ .kind  = IN_KIND_SNAPIN_MANIF,
                                      .mem   = (fd_wksp_t *)manifest_mem,
                                      .mtu   = sizeof(fd_snapshot_manifest_t) };
}

static int
wfs_state_for( ulong  wfs_slot,
               int    hash_is_zero,
               ushort shred_version,
               ulong  boot_slot ) {
  wfs_boot( wfs_slot, hash_is_zero, shred_version );
  wfs_manifest( boot_slot );
  wfs_done();
  return ctx.wfs_state;
}

/* Gossip is the only tile that signals the wait is over, so a
   misclassification here leaves replay waiting forever. */

static void
test_wfs_state_transitions( void ) {
  static ulong metrics[ FD_METRICS_TOTAL_SZ/sizeof(ulong) ];
  fd_metrics_tl = metrics;

  /* aligned_alloc requires a size that is a multiple of the alignment. */
  manifest_mem = aligned_alloc( FD_CHUNK_ALIGN, fd_ulong_align_up( sizeof(fd_snapshot_manifest_t), FD_CHUNK_ALIGN ) );
  FD_TEST( manifest_mem );

  /* MATCH waits for the supermajority. */
  FD_TEST( wfs_state_for( 100UL, 0, 1234, 100UL )==FD_GOSSIP_WFS_STATE_WAIT );

  /* NOOP and DISABLED are finished at boot and never signal. */
  FD_TEST( wfs_state_for( 100UL, 0, 1234, 101UL )==FD_GOSSIP_WFS_STATE_DONE );
  FD_TEST( wfs_state_for(   0UL, 1,    0, 100UL )==FD_GOSSIP_WFS_STATE_DONE );

  /* ERROR holds at INIT.  Only WAIT can become PUBLISH, so completion
     is unreachable without ever testing after_credit. */
  FD_TEST( wfs_state_for( 100UL, 0, 1234, 99UL )==FD_GOSSIP_WFS_STATE_INIT );

  free( manifest_mem );
}

/* Drives replay_epoch with identity weights.  Identities are pubkeys
   filled with one byte so the sorted order is easy to check. */

static uchar epoch_mem[ FD_EPOCH_OUT_MTU ] __attribute__((aligned(FD_CHUNK_ALIGN)));

static void
wfs_epoch( ulong         epoch,
           uchar const * ids,
           ulong const * stakes,
           ulong         cnt ) {
  fd_epoch_info_msg_t * msg = (fd_epoch_info_msg_t *)epoch_mem;
  memset( msg, 0, sizeof(fd_epoch_info_msg_t) );
  msg->epoch         = epoch;
  msg->staked_id_cnt = cnt;
  fd_stake_weight_t * weights = fd_epoch_info_msg_id_weights( msg );
  for( ulong i=0UL; i<cnt; i++ ) {
    memset( weights[ i ].key.uc, ids[ i ], sizeof(fd_pubkey_t) );
    weights[ i ].stake = stakes[ i ];
  }
  FD_TEST( !returnable_frag( &ctx, 2UL, 0UL, 4UL, 0UL,
                             fd_epoch_info_msg_sz( 0UL, cnt ), 0UL, 0UL, 0UL, NULL ) );
}

/* Reports a contact info change for the identity with our shred
   version and a TVU socket, as gossvf would deliver it. */

static void
wfs_activity( uchar id,
              int   change_type ) {
  fd_pubkey_t identity;
  memset( identity.uc, id, sizeof(fd_pubkey_t) );
  fd_gossip_contact_info_t ci;
  memset( &ci, 0, sizeof(ci) );
  ci.shred_version = ctx.my_contact_info->shred_version;
  ci.sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_TVU ].ip4  = 1U;
  ci.sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_TVU ].port = 1;
  gossip_activity_update_fn( &ctx, &identity, &ci, change_type );
}

/* The first epoch message fixes the stake list the wait for
   supermajority is measured against; completion is 80% of it. */

static void
test_wfs_stake_list( void ) {
  static ulong metrics[ FD_METRICS_TOTAL_SZ/sizeof(ulong) ];
  fd_metrics_tl = metrics;

  manifest_mem = aligned_alloc( FD_CHUNK_ALIGN, fd_ulong_align_up( sizeof(fd_snapshot_manifest_t), FD_CHUNK_ALIGN ) );
  FD_TEST( manifest_mem );

  ulong  max_values = 256UL;
  void * mem        = aligned_alloc( fd_gossip_align(), fd_gossip_footprint( max_values, 1UL ) );
  FD_TEST( mem );

  uchar         ping_seed[ 32 ] = {0};
  fd_ip4_port_t entrypoint[1]   = {0};
  ctx.gossip = fd_gossip_join( fd_gossip_new( mem, fd_rng_join( fd_rng_new( ctx.rng, 0U, 0UL ) ), ping_seed, max_values, 1UL, entrypoint,
                                              ctx.identity_key->uc, ctx.my_contact_info, fd_clock_tile_now( ctx.clock ),
                                              gossip_send_fn,                &ctx,
                                              test_sign_fn,                  NULL,
                                              gossip_ping_tracker_change_fn, &ctx,
                                              gossip_activity_update_fn,     &ctx,
                                              ctx.update_out, ctx.net_out ) );
  FD_TEST( ctx.gossip );

  ctx.in[ 2 ] = (fd_gossip_in_ctx_t){ .kind = IN_KIND_EPOCH, .mem = (fd_wksp_t *)epoch_mem, .mtu = FD_EPOCH_OUT_MTU };
  ctx.my_contact_info->shred_version = 1234;

  /* Stakes sum to 100, and 40+39 is one short of the threshold while
     40+39+1 is exactly on it, so the comparison cannot be off by one.
     Identity order and stake order disagree, so the key sort the
     lookup depends on is not a no-op. */
  uchar ids_cur    [ 4 ] = { 0xC3, 0xA1, 0xE5, 0xB2 };
  ulong stakes_cur [ 4 ] = {  40UL, 39UL,  1UL, 20UL };
  uchar ids_next   [ 2 ] = { 0xD4, 0xF6 };
  ulong stakes_next[ 2 ] = { 90UL, 11UL };

  /* MATCH, epoch messages after DONE: the first list is kept, sorted
     by identity, and the next epoch's list is ignored. */
  wfs_boot( 100UL, 0, 1234 );
  wfs_manifest( 100UL );
  wfs_done();
  FD_TEST( ctx.wfs_state==FD_GOSSIP_WFS_STATE_WAIT );
  FD_TEST( !ctx.wfs_stakes_cnt );
  wfs_epoch( 7UL, ids_cur, stakes_cur, 4UL );
  FD_TEST( ctx.wfs_stakes_cnt==4UL );
  FD_TEST( ctx.wfs_stake.total==100UL );
  FD_TEST( ctx.wfs_peers.total==4UL );
  FD_TEST( ctx.wfs_stakes[ 0 ].key.uc[ 0 ]==0xA1 && ctx.wfs_stakes[ 0 ].stake==39UL );
  FD_TEST( ctx.wfs_stakes[ 1 ].key.uc[ 0 ]==0xB2 && ctx.wfs_stakes[ 1 ].stake==20UL );
  FD_TEST( ctx.wfs_stakes[ 2 ].key.uc[ 0 ]==0xC3 && ctx.wfs_stakes[ 2 ].stake==40UL );
  FD_TEST( ctx.wfs_stakes[ 3 ].key.uc[ 0 ]==0xE5 && ctx.wfs_stakes[ 3 ].stake== 1UL );
  wfs_epoch( 8UL, ids_next, stakes_next, 2UL );
  FD_TEST( ctx.wfs_stakes_cnt==4UL );
  FD_TEST( ctx.wfs_stake.total==100UL );

  /* Only listed identities count, once each, and leaving gives the
     stake back. */
  wfs_activity( 0xC3, FD_GOSSIP_ACTIVITY_CHANGE_TYPE_ACTIVE );
  FD_TEST( ctx.wfs_stake.online==40UL && ctx.wfs_peers.online==1UL );
  wfs_activity( 0xC3, FD_GOSSIP_ACTIVITY_CHANGE_TYPE_ACTIVE );
  FD_TEST( ctx.wfs_stake.online==40UL && ctx.wfs_peers.online==1UL );
  wfs_activity( 0xFF, FD_GOSSIP_ACTIVITY_CHANGE_TYPE_ACTIVE );
  FD_TEST( ctx.wfs_stake.online==40UL && ctx.wfs_peers.online==1UL );
  wfs_activity( 0xB2, FD_GOSSIP_ACTIVITY_CHANGE_TYPE_ACTIVE );
  FD_TEST( ctx.wfs_stake.online==60UL && ctx.wfs_peers.online==2UL );
  wfs_activity( 0xB2, FD_GOSSIP_ACTIVITY_CHANGE_TYPE_INACTIVE );
  FD_TEST( ctx.wfs_stake.online==40UL && ctx.wfs_peers.online==1UL );

  /* One short of the threshold still waits. */
  wfs_activity( 0xA1, FD_GOSSIP_ACTIVITY_CHANGE_TYPE_ACTIVE );
  FD_TEST( ctx.wfs_stake.online==79UL && ctx.wfs_peers.online==2UL );
  FD_TEST( ctx.wfs_state==FD_GOSSIP_WFS_STATE_WAIT );

  /* Exactly the threshold publishes. */
  wfs_activity( 0xE5, FD_GOSSIP_ACTIVITY_CHANGE_TYPE_ACTIVE );
  FD_TEST( ctx.wfs_stake.online==80UL && ctx.wfs_peers.online==3UL );
  FD_TEST( ctx.wfs_state==FD_GOSSIP_WFS_STATE_PUBLISH );

  /* MATCH, epoch message before DONE: the list is filled in INIT and
     DONE still decides the state. */
  wfs_boot( 100UL, 0, 1234 );
  wfs_epoch( 7UL, ids_cur, stakes_cur, 4UL );
  FD_TEST( ctx.wfs_state==FD_GOSSIP_WFS_STATE_INIT );
  FD_TEST( ctx.wfs_stakes_cnt==4UL );
  wfs_manifest( 100UL );
  wfs_done();
  FD_TEST( ctx.wfs_state==FD_GOSSIP_WFS_STATE_WAIT );
  FD_TEST( ctx.wfs_stakes_cnt==4UL && ctx.wfs_stake.total==100UL );

  /* NOOP: nothing is tracked. */
  wfs_boot( 100UL, 0, 1234 );
  wfs_manifest( 101UL );
  wfs_done();
  FD_TEST( ctx.wfs_state==FD_GOSSIP_WFS_STATE_DONE );
  wfs_epoch( 7UL, ids_cur, stakes_cur, 4UL );
  FD_TEST( !ctx.wfs_stakes_cnt );

  free( mem );
  free( manifest_mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_tempo_set_tick_per_ns( 1.0, 0.0 );
  fd_clock_tile_init( ctx.clock );

  test_wfs_state_transitions();
  test_wfs_stake_list();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
