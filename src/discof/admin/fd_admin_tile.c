#include "../../disco/topo/fd_topo.h"
#include "../../disco/events/generated/fd_event_gen.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../util/fd_version.h"

#include "fd_adminctl.h"
#include "../failover/fd_failover_channel.h"
#include "../failover/fd_failover_stream.h"
#include "../tower/fd_tower_tile.h"
#include "../../choreo/tower/fd_tower_serdes.h"
#include "../../ballet/txn/fd_txn.h"

#include <sys/socket.h>

#include "generated/fd_admin_tile_seccomp.h"
#include "generated/fd_admin_tile_failover_seccomp.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

struct fd_admin_tile_ctx {
  fd_topo_t const * topo;
  fd_adminctl_t *   adminctl;
  uchar             identity_pubkey[ 32UL ];
  fd_keyswitch_t *  tower_av_keyswitch;
  fd_keyswitch_t *  txsend_av_keyswitch;
  fd_keyswitch_t *  sign_av_keyswitch[ FD_TOPO_MAX_TILES ];
  ulong             sign_av_keyswitch_cnt;
  fd_sha512_t       sha512[ 1 ];

  int                     failover_enabled;
  ulong                   failover_role;
  int                     failover_dials;
  fd_failover_channel_t * failover;
  uchar                   failover_secret[ 32 ];
  fd_failover_hello_t     failover_hello;
  fd_failover_status_t    failover_peer_status;
  int                     failover_peer_status_valid;
  long                    failover_peer_status_time;
  ulong                   failover_channel_state;
  long                    failover_status_interval;
  ulong                   failover_replication_lag_limit;
  long                    failover_last_status;
  int                     failover_status_sent; /* sent in this session */
  long                    failover_rtt_nanos;
  long                    failover_rtt_probe_time;
  ulong                   failover_rtt_probe_seq;
  uchar                   failover_rx[ FD_FAILOVER_PAYLOAD_MAX ];

  ulong       tower_in_idx;
  fd_wksp_t * tower_in_mem;
  ulong       tower_in_chunk0;
  ulong       tower_in_wmark;

  fd_tower_slot_done_t failover_slot_done;
  ulong                failover_slot_done_seq;
  int                  failover_slot_done_fresh;

  ulong failover_replay_slot;
  ulong failover_root_slot;
  ulong failover_last_vote_slot;

  fd_failover_consensus_cache_t failover_consensus;
  ulong                         failover_lag_slots;

  /* Latest locally produced tower and its delivery state. */
  uchar failover_cs_buf[ sizeof(fd_failover_consensus_state_t)+FD_FAILOVER_TOWER_STATE_MAX ];
  ulong failover_cs_sz;
  int   failover_cs_valid;
  int   failover_cs_sent;

  ulong replay_out_idx;           /* admin_replay stem out index */
  ulong snap_create_slot_idx;     /* adminctl slot of snapshot-create command */
  ulong snap_create_target_slot;  /* requested slot retained until Replay responds */
  ulong snap_create_start_time;   /* command start retained until Replay responds */
};

typedef struct fd_admin_tile_ctx fd_admin_tile_ctx_t;

static inline fd_event_admin_command_t
prepare_admin_command( int          type,
                       void const * payload,
                       ulong        payload_sz ) {
  fd_event_admin_command_t event = {
    .type                = type,
    .args_json           = { '{', '}' },
    .args_json_len       = 2UL,
    .start_time          = (ulong)fd_log_wallclock(),
    .payload_size        = payload_sz,
    .has_payload_version = 0,
  };
  if( FD_LIKELY( payload_sz>=sizeof(ulong) ) ) {
    event.payload_version     = FD_LOAD( ulong, payload );
    event.has_payload_version = 1;
  }
  return event;
}

static inline void
report_admin_command( fd_event_admin_command_t * event,
                      int                        result ) {
  FD_TEST( result>=0 && result<=FD_EVENT_ADMIN_COMMAND_RESULT_CUSTOM );
  event->result   = result;
  event->end_time = (ulong)fd_log_wallclock();
  fd_event_report_admin_command( event );
}

static inline void
report_admin_command_custom_result( fd_event_admin_command_t * event,
                                    char const *               custom_result ) {
  FD_TEST( fd_cstr_printf_check( (char *)event->custom_result,
                                 sizeof(event->custom_result),
                                 &event->custom_result_len,
                                 "%s",
                                 custom_result ) );
  report_admin_command( event, FD_EVENT_ADMIN_COMMAND_RESULT_CUSTOM );
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_admin_tile_ctx_t), fd_failover_channel_align() );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_admin_tile_ctx_t), sizeof(fd_admin_tile_ctx_t) );
  if( FD_UNLIKELY( tile->admin.failover_enabled ) ) {
    l = FD_LAYOUT_APPEND( l, fd_failover_channel_align(), fd_failover_channel_footprint() );
  }
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
load_pair_secret( char const * path,
                  uint         owner_uid,
                  uchar        secret[ 32 ] ) {
  int fd = open( path, O_RDONLY|O_CLOEXEC|O_NOFOLLOW );
  if( FD_UNLIKELY( -1==fd ) ) FD_LOG_ERR(( "open(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  struct stat st;
  if( FD_UNLIKELY( -1==fstat( fd, &st ) ) )           FD_LOG_ERR(( "fstat(%s) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( !S_ISREG( st.st_mode ) ) )         FD_LOG_ERR(( "`%s` must be a regular file", path ));
  if( FD_UNLIKELY( st.st_uid!=(uid_t)owner_uid ) )    FD_LOG_ERR(( "`%s` must be owned by the validator user", path ));
  if( FD_UNLIKELY( !(st.st_mode&S_IRUSR) ) )          FD_LOG_ERR(( "`%s` must be owner-readable", path ));
  if( FD_UNLIKELY( st.st_mode & (S_IRWXG|S_IRWXO) ) ) FD_LOG_ERR(( "`%s` must be readable by its owner alone", path ));
  if( FD_UNLIKELY( st.st_size!=32L ) )                FD_LOG_ERR(( "`%s` must be exactly 32 bytes", path ));

  ulong secret_sz = 0UL;
  int err = fd_io_read( fd, secret, 32UL, 32UL, &secret_sz );
  if( FD_UNLIKELY( err || secret_sz!=32UL ) ) {
    if( FD_LIKELY( !err ) ) err = EIO;
    FD_LOG_ERR(( "read(%s) failed (%i-%s)", path, err, fd_io_strerror( err ) ));
  }
  if( FD_UNLIKELY( -1==close( fd ) ) ) FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
}

static long
failover_duration_nanos( ulong count,
                         ulong nanos_per_unit ) {
  return (long)fd_ulong_min( fd_ulong_sat_mul( count, nanos_per_unit ),
                             (ulong)LONG_MAX );
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_admin_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_admin_tile_ctx_t), sizeof(fd_admin_tile_ctx_t) );
  fd_memset( ctx, 0, sizeof(fd_admin_tile_ctx_t) );

  if( FD_UNLIKELY( !strcmp( tile->admin.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  fd_memcpy( ctx->identity_pubkey, fd_keyload_load( tile->admin.identity_key_path, /* pubkey only: */ 1 ), 32UL );

  ctx->failover_replay_slot    = FD_FAILOVER_SLOT_NULL;
  ctx->failover_root_slot      = FD_FAILOVER_SLOT_NULL;
  ctx->failover_last_vote_slot = FD_FAILOVER_SLOT_NULL;
  ctx->failover_lag_slots      = FD_FAILOVER_SLOT_NULL;
  ctx->failover_peer_status.replay_slot      = FD_FAILOVER_SLOT_NULL;
  ctx->failover_peer_status.turbine_slot     = FD_FAILOVER_SLOT_NULL;
  ctx->failover_peer_status.last_vote_slot   = FD_FAILOVER_SLOT_NULL;
  ctx->failover_peer_status.root_slot        = FD_FAILOVER_SLOT_NULL;
  ctx->failover_peer_status.next_leader_slot = FD_FAILOVER_SLOT_NULL;

  ctx->failover_enabled = tile->admin.failover_enabled;
  if( FD_UNLIKELY( ctx->failover_enabled ) ) {
    void * ch_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_failover_channel_align(), fd_failover_channel_footprint() );
    ctx->failover = fd_failover_channel_join( fd_failover_channel_new( ch_mem ) );
    FD_TEST( ctx->failover );
    ctx->failover_dials = tile->admin.failover_dial_peer;

    load_pair_secret( tile->admin.failover_pair_secret_path, tile->admin.target_uid, ctx->failover_secret );

    ctx->failover_hello.version = (ushort)FD_FAILOVER_VERSION;
    uchar const * junk_pubkey = fd_keyload_load( tile->admin.failover_junk_identity_path, 1 );
    fd_memcpy( ctx->failover_hello.junk_pubkey, junk_pubkey, 32UL );
    fd_keyload_unload( junk_pubkey, 1 );
    uchar const * staked_pubkey = fd_keyload_load( tile->admin.failover_staked_identity_path, 1 );
    fd_memcpy( ctx->failover_hello.staked_pubkey, staked_pubkey, 32UL );
    fd_keyload_unload( staked_pubkey, 1 );
    int is_junk   = !memcmp( ctx->identity_pubkey, ctx->failover_hello.junk_pubkey,   32UL );
    int is_staked = !memcmp( ctx->identity_pubkey, ctx->failover_hello.staked_pubkey, 32UL );
    if( FD_UNLIKELY( is_junk==is_staked ) ) {
      FD_LOG_ERR(( "`paths.identity_key` must match exactly one failover identity" ));
    }
    ctx->failover_role       = is_staked ? FD_FAILOVER_ROLE_ACTIVE : FD_FAILOVER_ROLE_STANDBY;
    ctx->failover_hello.role = (uchar)ctx->failover_role;
    uchar const * vote_account = fd_keyload_load( tile->admin.failover_vote_account_path, 1 );
    fd_memcpy( ctx->failover_hello.vote_account, vote_account, 32UL );
    fd_keyload_unload( vote_account, 1 );
    fd_memcpy( ctx->failover_hello.commit, fd_commit_ref_cstr,
               fd_ulong_min( sizeof(ctx->failover_hello.commit), strlen( fd_commit_ref_cstr ) ) );
    ctx->failover_hello.cfg_hash = tile->admin.failover_cfg_hash;
    FD_TEST( fd_rng_secure( &ctx->failover_hello.boot_id, 8UL ) );

    if( FD_LIKELY( !ctx->failover_dials ) ) {
      fd_failover_channel_init_listener( ctx->failover, tile->admin.failover_bind_addr, tile->admin.failover_bind_port );
    }
  }
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void *                scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_admin_tile_ctx_t * ctx     = (fd_admin_tile_ctx_t *)scratch;
  ctx->replay_out_idx       = ULONG_MAX;
  ctx->snap_create_slot_idx = ULONG_MAX;
  ctx->topo = topo;

  fd_topo_obj_t const * adminctl_obj = fd_topo_find_tile_obj( topo, tile, "adminctl" );
  FD_TEST( adminctl_obj );

  ctx->adminctl = fd_adminctl_join( fd_topo_obj_laddr( topo, adminctl_obj->id ) );
  FD_TEST( ctx->adminctl );

  ctx->replay_out_idx = fd_topo_find_tile_out_link( topo, tile, "admin_replay", 0UL );

  ctx->tower_in_idx = ULONG_MAX;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( FD_LIKELY( !strcmp( link->name, "replay_admin" ) ) ) continue;
    if( FD_LIKELY( !strcmp( link->name, "tower_out" ) ) ) {
      ctx->tower_in_idx    = i;
      ctx->tower_in_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->tower_in_chunk0 = fd_dcache_compact_chunk0( ctx->tower_in_mem, link->dcache );
      ctx->tower_in_wmark  = fd_dcache_compact_wmark( ctx->tower_in_mem, link->dcache, link->mtu );
      continue;
    }
    FD_LOG_ERR(( "unexpected input link name %s", link->name ));
  }

  ulong tower_idx = fd_topo_find_tile( topo, "tower", 0UL );
  if( FD_LIKELY( tower_idx!=ULONG_MAX ) ) {
    FD_TEST( topo->tiles[ tower_idx ].av_keyswitch_obj_id!=ULONG_MAX );
    ctx->tower_av_keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, topo->tiles[ tower_idx ].av_keyswitch_obj_id ) );
    FD_TEST( ctx->tower_av_keyswitch );
  } else {
    ctx->tower_av_keyswitch = NULL;
  }

  ulong txsend_idx = fd_topo_find_tile( topo, "txsend", 0UL );
  FD_TEST( txsend_idx!=ULONG_MAX );
  FD_TEST( topo->tiles[ txsend_idx ].av_keyswitch_obj_id!=ULONG_MAX );
  ctx->txsend_av_keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, topo->tiles[ txsend_idx ].av_keyswitch_obj_id ) );
  FD_TEST( ctx->txsend_av_keyswitch );

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t const * sign_tile = &topo->tiles[ i ];
    if( FD_LIKELY( strcmp( sign_tile->name, "sign" ) ) ) continue;
    FD_TEST( sign_tile->av_keyswitch_obj_id!=ULONG_MAX );
    ctx->sign_av_keyswitch[ ctx->sign_av_keyswitch_cnt ] = fd_keyswitch_join( fd_topo_obj_laddr( topo, sign_tile->av_keyswitch_obj_id ) );
    FD_TEST( ctx->sign_av_keyswitch[ ctx->sign_av_keyswitch_cnt ] );
    ctx->sign_av_keyswitch_cnt++;
  }
  FD_TEST( ctx->sign_av_keyswitch_cnt );

  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha512 ) ) );

  if( FD_UNLIKELY( ctx->failover_enabled ) ) {
    fd_failover_channel_set_identity( ctx->failover, ctx->failover_secret, &ctx->failover_hello );
    fd_memzero_explicit( ctx->failover_secret, sizeof(ctx->failover_secret) );
    fd_failover_channel_set_timing( ctx->failover,
                                    FD_FAILOVER_CHANNEL_HELLO_TIMEOUT_NANOS,
                                    failover_duration_nanos( fd_ulong_sat_mul( tile->admin.failover_status_interval_millis,
                                                                               tile->admin.failover_peer_silence_intervals ), 1000000UL ),
                                    failover_duration_nanos( tile->admin.failover_retry_backoff_min_millis, 1000000UL ),
                                    failover_duration_nanos( tile->admin.failover_retry_backoff_max_millis, 1000000UL ) );
    if( FD_LIKELY( ctx->failover_dials ) ) {
      fd_failover_channel_init_dialer( ctx->failover, tile->admin.failover_peer_addr, tile->admin.failover_peer_port );
    }
    ctx->failover_status_interval = failover_duration_nanos( tile->admin.failover_status_interval_millis, 1000000UL );
    ctx->failover_replication_lag_limit = tile->admin.failover_replication_lag_slots;
    ctx->failover_channel_state = fd_failover_channel_state( ctx->failover );
  }
}

/* The process of switching identity of the validator is somewhat
   involved, to prevent it from producing torn data (for example,
   a block where half the shreds are signed by one private key, and half
   are signed by another).

   The process of switching is a state machine that progresses linearly
   through each of the states.  Generally, no transitions are allowed
   except direct forward steps, except in emergency recovery cases an
   operator can force the state past the initial lock.

   The states follow, in order. */

/* State 0: UNLOCKED.
     The validator is not currently in the process of switching keys. */
#define FD_SET_IDENTITY_STATE_UNLOCKED                 (0UL)

/* State 1: LOCKED
     Some client to the validator has requested a key switch.  To do so,
     it acquired an exclusive lock on the validator to prevent the
     switch potentially being interleaved with another client. */
#define FD_SET_IDENTITY_STATE_LOCKED                   (1UL)

/* State 2: LEADER_HALT_REQUESTED
     The first step in the key switch process is to pause the leader
     pipeline of the validator, preventing us from becoming leader, but
     finishing any currently in progress leader slot if there is one.
     While in this state, the validator is waiting for the leader
     pipeline to confirm that it has paused production, and is no longer
     leader.

     In Firedancer, this halt request goes to the Replay tile, which
     causes the tile to switch the identity key it uses to determine the
     identity's balance as well as when the validator is the leader.
     After the leader pipeline has been halted, the validator will no
     longer become a leader until the switch has been completed. */
#define FD_SET_IDENTITY_STATE_LEADER_HALT_REQUESTED    (2UL)

/* State 3: LEADER_HALTED
     The Replay tile has confirmed that it has halted the leader
     pipeline, and the validator is no longer leader.  No more blocks
     will be produced until it is unhalted.  In addition, the Replay
     tile has switched its own identity key.

     At this point, we also have the guarantee that there are no more
     outstanding shreds that have to be signed with the old key.  Any
     tiles related to the leader pipeline that rely on the identity key
     will not be used. */
#define FD_SET_IDENTITY_STATE_LEADER_HALTED            (3UL)

/* State 4: SIGNERS_HALT_REQUESTED
     Repair, Gossip, Tower, and Bundle tiles will stop sending requests
     downstream to the sign tile.  This is done to avoid any mismatches
     with the identity key.  Their identity keys will be switched during
     this step, except for Gossip, which switches during
     SIGNERS_UNHALT_REQUESTED.  These tiles all use the identity key to
     make forward progress on non-leader pipeline replay except for the
     Bundle tile.

     These tiles use the identity key to populate messages which are
     signed by the sign tile:
       (a) Repair.  The repair tile uses the identity key as part of the
           repair protocol.  The identity key is included in and used
           for signing requests.  Because Repair uses an asynchronous
           signing mechanism, Repair will first wait until all
           outstanding sign requests have been received back from the
           sign tile before halting any new signing requests.
       (b) Gossip.  The gossip tile sends out ContactInfo messages with
           our identity key, and also uses the identity key to sign
           outgoing gossip messages.
       (c) Tower.  The tower tile uses the identity key to generate
           vote transactions which are sent to the send tile.  These
           vote transactions are then signed downstream by the TxSend
           tile instead of having its own keyguard client.
       (d) Bundle.  The bundle tile uses the identity key to sign an
           authentication challenge from the bundle server.
       (e) Rserve.  The rserve tile uses the identity key to sign
           outgoing pings.
        */
#define FD_SET_IDENTITY_STATE_SIGNERS_HALT_REQUESTED   (4UL)

/* State 5: SIGNERS_HALTED
     Repair, Gossip, Tower, and Bundle are no longer sending requests to
     the sign tile.  Replay can keep progressing at this point.
     However, the Tower tile may have an in-flight vote transaction to
     the TxSend tile that corresponds to the old identity key. */
#define FD_SET_IDENTITY_STATE_SIGNERS_HALTED           (5UL)

/* State 6: TXSEND_FLUSH_REQUESTED
     Once the Tower tile has updated its identity key and stopped
     sending vote transactions to the TxSend tile, any in-flight vote
     transactions for the old identity key must be flushed to avoid
     being badly signed.  We also know that Tower will send no more
     vote transactions to the TxSend tile.

     The TxSend tile is flushed by telling it the last sequence number
     the Tower tile has produced for an outgoing vote transaction at the
     time it was halted.  Once the TxSend tile has processed all vote
     transactions up to and including that sequence number, it will
     switch its own identity key.  There is a guarantee that the TxSend
     tile will not request to sign any vote transactions until it is
     unhalted.  At this point, the TxSend tile will stop receiving any
     new frags from the Net tile.  The reason for this is to avoid any
     QUIC callbacks that invoke key signing. */
#define FD_SET_IDENTITY_STATE_TXSEND_FLUSH_REQUESTED   (6UL)

/* State 7: TXSEND_FLUSHED
     The TxSend tile confirms that it has seen and processed all votes
     up to and including the last sequence number produced by the Tower
     tile at the time it was halted.  The TxSend tile also switches its
     own identity key which is used for signing votes and establishing
     a QUIC connection.  The TxSend tile is now no longer receiving any
     new frags from the Net tile. */
#define FD_SET_IDENTITY_STATE_TXSEND_FLUSHED           (7UL)

/* State 8: ALL_SWITCH_REQUESTED
     The client now requests that all other tiles which consume the
     identity key in some way switch to the new key.  The leader
     pipeline is still halted, although it doesn't strictly need to be,
     since outgoing shreds have been flushed.  This is done to keep the
     control flow simpler.  The sign tile's switch is requested first to
     avoid any potential mismatches with the identity key.

     The other tiles using the identity key are:
       (a) Sign.  The sign tile is responsible for holding the private
           key and servicing signing requests from other tiles.
       (b) GUI.  The GUI shows the validator identity key to the user,
           and uses the key to determine which blocks are ours for
           highlighting on the frontend.
       (c) Gossvf.  The gossvf tile uses the identity key to detect
           duplicate running instances of the same validator node as
           well as other message handling.
       (d) Shred.  The shred tile uses the identity key to determine the
           position of the validator in the Turbine tree and to sign
           outgoing shreds.
       (e) Event.  Outgoing events to the event server are signed with
           the identity key to authenticate the sender. */
#define FD_SET_IDENTITY_STATE_ALL_SWITCH_REQUESTED     (8UL)

/* State 9: ALL_SWITCHED
     All remaining tiles that use the identity key have confirmed that
     they have switched to the new key.  Gossip has not yet updated its
     identity key.  Repair, Gossip, Tower, TxSend, and Bundle remain
     halted. */
#define FD_SET_IDENTITY_STATE_ALL_SWITCHED             (9UL)

/* State 10: SIGNERS_UNHALT_REQUESTED
     During this state, the tiles that rely on the sign tile can be
     safely unhalted and have their keys switched.  After this state,
     all tiles will be using the switched identity key. */
#define FD_SET_IDENTITY_STATE_SIGNERS_UNHALT_REQUESTED (10UL)

/* State 11: SIGNERS_UNHALTED
     All tiles that rely on the sign tile have been unhalted, and the
     validator can now resume making progress on replay. */
#define FD_SET_IDENTITY_STATE_SIGNERS_UNHALTED         (11UL)

/* State 12: LEADER_UNHALT_REQUESTED
     The final state, now that all tiles have switched, the leader
     pipeline can be unblocked and the validator can resume producing
     blocks.  The next state once the Replay tile confirms the leader
     pipeline is unlocked, is UNLOCKED. */
#define FD_SET_IDENTITY_STATE_LEADER_UNHALT_REQUESTED  (12UL)

static fd_keyswitch_t *
find_identity_keyswitch( fd_admin_tile_ctx_t * ctx,
                         char const *          tile_name ) {
  fd_topo_t const * topo = ctx->topo;
  ulong tile_idx = fd_topo_find_tile( topo, tile_name, 0UL );
  FD_TEST( tile_idx!=ULONG_MAX );
  FD_TEST( topo->tiles[ tile_idx ].id_keyswitch_obj_id!=ULONG_MAX );

  fd_keyswitch_t * keyswitch = fd_topo_obj_laddr( topo, topo->tiles[ tile_idx ].id_keyswitch_obj_id );
  FD_TEST( keyswitch );
  return keyswitch;
}

static int FD_FN_SENSITIVE
poll_set_identity( fd_admin_tile_ctx_t * ctx,
                   ulong *               state,
                   ulong *               halted_seq,
                   ulong                 identity_outset,
                   uchar *               keypair ) {
  fd_topo_t const * topo = ctx->topo;

  switch( *state ) {
    case FD_SET_IDENTITY_STATE_UNLOCKED: {
      fd_keyswitch_t * replay = find_identity_keyswitch( ctx, "replay" );
      if( FD_LIKELY( FD_KEYSWITCH_STATE_UNLOCKED==FD_ATOMIC_CAS( &replay->state, FD_KEYSWITCH_STATE_UNLOCKED, FD_KEYSWITCH_STATE_LOCKED ) ) ) {
        *state = FD_SET_IDENTITY_STATE_LOCKED;
        FD_LOG_INFO(( "Locking validator identity for key switch..." ));
      } else {
        FD_LOG_CRIT(( "identity keyswitch is in a locked state but should be unlocked" ));
      }
      break;
    }
    case FD_SET_IDENTITY_STATE_LOCKED: {
      fd_keyswitch_t * replay = find_identity_keyswitch( ctx, "replay" );
      memcpy( replay->bytes, keypair+32UL, 32UL );

      FD_COMPILER_MFENCE();
      replay->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
      FD_COMPILER_MFENCE();
      *state = FD_SET_IDENTITY_STATE_LEADER_HALT_REQUESTED;
      FD_LOG_INFO(( "Pausing leader pipeline for key switch..." ));
      break;
    }
    case FD_SET_IDENTITY_STATE_LEADER_HALT_REQUESTED: {
      fd_keyswitch_t * replay = find_identity_keyswitch( ctx, "replay" );
      if( FD_LIKELY( replay->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
        fd_memzero_explicit( replay->bytes, 64UL );
        FD_COMPILER_MFENCE();
        *halted_seq = replay->result;
        *state = FD_SET_IDENTITY_STATE_LEADER_HALTED;
        FD_LOG_INFO(( "Leader pipeline successfully paused..." ));
      } else if( FD_UNLIKELY( replay->state==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
        FD_SPIN_PAUSE();
      } else {
        FD_LOG_ERR(( "Unexpected replay keyswitch state %lu", replay->state ));
      }
      break;
    }
    case FD_SET_IDENTITY_STATE_LEADER_HALTED: {
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &topo->tiles[ i ];
        if( FD_LIKELY( tile->id_keyswitch_obj_id==ULONG_MAX ) ) continue;
        if( strcmp( tile->name, "repair" ) &&
            strcmp( tile->name, "gossip" ) &&
            strcmp( tile->name, "tower" ) &&
            strcmp( tile->name, "bundle" ) &&
            strcmp( tile->name, "rserve" ) ) {
          continue;
        }

        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id );
        if( !strcmp( tile->name, "gossip" ) ) tile_ks->param = identity_outset;
        memcpy( tile_ks->bytes, keypair+32UL, 32UL );
        FD_COMPILER_MFENCE();
        tile_ks->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
        FD_COMPILER_MFENCE();
      }
      *state = FD_SET_IDENTITY_STATE_SIGNERS_HALT_REQUESTED;
      FD_LOG_INFO(( "Requesting to halt all signers..." ));
      break;
    }
    case FD_SET_IDENTITY_STATE_SIGNERS_HALT_REQUESTED: {
      int all_switched = 1;
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &topo->tiles[ i ];
        if( FD_LIKELY( tile->id_keyswitch_obj_id==ULONG_MAX ) ) continue;
        if( strcmp( tile->name, "repair" ) &&
            strcmp( tile->name, "gossip" ) &&
            strcmp( tile->name, "tower" ) &&
            strcmp( tile->name, "bundle" ) &&
            strcmp( tile->name, "rserve" ) ) {
          continue;
        }

        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id );
        if( FD_LIKELY( tile_ks->state==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
          all_switched = 0;
          break;
        }
      }
      if( FD_LIKELY( all_switched ) ) {
        FD_LOG_INFO(( "All signers successfully halted..." ));
        *state = FD_SET_IDENTITY_STATE_SIGNERS_HALTED;
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    case FD_SET_IDENTITY_STATE_SIGNERS_HALTED: {
      ulong tower_halted_seq = find_identity_keyswitch( ctx, "tower" )->result;
      fd_keyswitch_t * txsend = find_identity_keyswitch( ctx, "txsend" );
      txsend->param = tower_halted_seq;
      memcpy( txsend->bytes, keypair+32UL, 32UL );
      FD_COMPILER_MFENCE();
      txsend->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
      FD_COMPILER_MFENCE();

      *state = FD_SET_IDENTITY_STATE_TXSEND_FLUSH_REQUESTED;
      break;
    }
    case FD_SET_IDENTITY_STATE_TXSEND_FLUSH_REQUESTED: {
      fd_keyswitch_t * txsend = find_identity_keyswitch( ctx, "txsend" );
      if( FD_LIKELY( txsend->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
        fd_memzero_explicit( txsend->bytes, 64UL );
        FD_COMPILER_MFENCE();
        *state = FD_SET_IDENTITY_STATE_TXSEND_FLUSHED;
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    case FD_SET_IDENTITY_STATE_TXSEND_FLUSHED: {
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &topo->tiles[ i ];
        if( strcmp( tile->name, "sign" ) ) continue;
        fd_keyswitch_t * sign = fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id );
        memcpy( sign->bytes, keypair, 64UL );
        FD_COMPILER_MFENCE();
        sign->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
        FD_COMPILER_MFENCE();
      }

      fd_memzero_explicit( keypair, 32UL ); /* Private key no longer needed by the admin tile. */

      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &topo->tiles[ i ];
        if( FD_LIKELY( tile->id_keyswitch_obj_id==ULONG_MAX ) ) continue;
        if( FD_LIKELY( !strcmp( tile->name, "sign" ) ||
                       !strcmp( tile->name, "replay" ) ||
                       !strcmp( tile->name, "repair" ) ||
                       !strcmp( tile->name, "gossip" ) ||
                       !strcmp( tile->name, "txsend" ) ||
                       !strcmp( tile->name, "tower" ) ||
                       !strcmp( tile->name, "bundle" ) ||
                       !strcmp( tile->name, "rserve" ) ) ) continue;

        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id );
        if( !strcmp( tile->name, "gossvf" ) ) tile_ks->param = identity_outset;
        memcpy( tile_ks->bytes, keypair+32UL, 32UL );
        FD_COMPILER_MFENCE();
        tile_ks->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
        FD_COMPILER_MFENCE();
      }

      FD_LOG_INFO(( "Requesting all remaining tiles switch identity key..." ));
      *state = FD_SET_IDENTITY_STATE_ALL_SWITCH_REQUESTED;
      break;
    }
    case FD_SET_IDENTITY_STATE_ALL_SWITCH_REQUESTED: {
      ulong all_switched = 1UL;
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &topo->tiles[ i ];
        if( FD_LIKELY( tile->id_keyswitch_obj_id==ULONG_MAX ) ) continue;
        if( FD_LIKELY( !strcmp( tile->name, "replay" ) ||
                       !strcmp( tile->name, "repair" ) ||
                       !strcmp( tile->name, "gossip" ) ||
                       !strcmp( tile->name, "txsend" ) ||
                       !strcmp( tile->name, "tower" ) ||
                       !strcmp( tile->name, "bundle" ) ||
                       !strcmp( tile->name, "rserve" ) ) ) continue;

        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id );
        if( FD_LIKELY( tile_ks->state==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
          all_switched = 0UL;
          break;
        } else if( FD_UNLIKELY( tile_ks->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
          if( FD_LIKELY( !strcmp( tile->name, "sign" ) ) ) {
            FD_COMPILER_MFENCE();
            fd_memzero_explicit( tile_ks->bytes, 64UL );
            FD_COMPILER_MFENCE();
          }
          continue;
        } else {
          FD_LOG_ERR(( "Unexpected %s keyswitch state %lu", tile->name, tile_ks->state ));
        }
      }

      if( FD_LIKELY( all_switched ) ) {
        FD_LOG_INFO(( "All tiles successfully switched identity key..." ));
        *state = FD_SET_IDENTITY_STATE_ALL_SWITCHED;
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    case FD_SET_IDENTITY_STATE_ALL_SWITCHED: {
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &topo->tiles[ i ];
        if( FD_LIKELY( tile->id_keyswitch_obj_id==ULONG_MAX ) ) continue;
        if( strcmp( tile->name, "repair" ) &&
            strcmp( tile->name, "gossip" ) &&
            strcmp( tile->name, "tower" ) &&
            strcmp( tile->name, "txsend" ) &&
            strcmp( tile->name, "bundle" ) &&
            strcmp( tile->name, "rserve" ) ) {
          continue;
        }

        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id );
        FD_COMPILER_MFENCE();
        tile_ks->state = FD_KEYSWITCH_STATE_UNHALT_PENDING;
        FD_COMPILER_MFENCE();
      }

      FD_LOG_INFO(( "Requesting to unpause signers..." ));
      *state = FD_SET_IDENTITY_STATE_SIGNERS_UNHALT_REQUESTED;
      break;
    }
    case FD_SET_IDENTITY_STATE_SIGNERS_UNHALT_REQUESTED: {
      int all_switched = 1;
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &topo->tiles[ i ];
        if( FD_LIKELY( tile->id_keyswitch_obj_id==ULONG_MAX ) ) continue;
        if( strcmp( tile->name, "repair" ) &&
            strcmp( tile->name, "gossip" ) &&
            strcmp( tile->name, "tower" ) &&
            strcmp( tile->name, "txsend" ) &&
            strcmp( tile->name, "bundle" ) &&
            strcmp( tile->name, "rserve" ) ) {
          continue;
        }

        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id );
        if( FD_LIKELY( tile_ks->state==FD_KEYSWITCH_STATE_UNHALT_PENDING ) ) {
          all_switched = 0;
          break;
        }
      }
      if( FD_LIKELY( all_switched ) ) {
        FD_LOG_INFO(( "Successfully unpaused all non-leader signers..." ));
        *state = FD_SET_IDENTITY_STATE_SIGNERS_UNHALTED;
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    case FD_SET_IDENTITY_STATE_SIGNERS_UNHALTED: {
      fd_keyswitch_t * replay = find_identity_keyswitch( ctx, "replay" );
      replay->state = FD_KEYSWITCH_STATE_UNHALT_PENDING;
      FD_LOG_INFO(( "Requesting to unpause leader pipeline..." ));
      *state = FD_SET_IDENTITY_STATE_LEADER_UNHALT_REQUESTED;
      break;
    }
    case FD_SET_IDENTITY_STATE_LEADER_UNHALT_REQUESTED: {
      fd_keyswitch_t * replay = find_identity_keyswitch( ctx, "replay" );
      if( FD_LIKELY( replay->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
        FD_LOG_INFO(( "Leader pipeline unpaused..." ));
        replay->state = FD_KEYSWITCH_STATE_UNLOCKED;
        *state = FD_SET_IDENTITY_STATE_UNLOCKED;
      } else if( FD_UNLIKELY( replay->state==FD_KEYSWITCH_STATE_UNHALT_PENDING ) ) {
        FD_SPIN_PAUSE();
      } else {
        FD_LOG_ERR(( "Unexpected replay keyswitch state %lu", replay->state ));
      }
      break;
    }
    default:
      FD_LOG_ERR(( "Unexpected set-identity state %lu", *state ));
  }

  return *state==FD_SET_IDENTITY_STATE_UNLOCKED;
}

static void FD_FN_SENSITIVE
set_identity( fd_admin_tile_ctx_t * ctx,
              ulong                 slot_idx,
              void *                data,
              ulong                 data_sz ) {

  fd_adminctl_t * adminctl = ctx->adminctl;
  fd_event_admin_command_t event = prepare_admin_command( FD_EVENT_ADMIN_COMMAND_TYPE_SET_IDENTITY, data, data_sz );
  FD_BASE58_ENCODE_32_BYTES( ctx->identity_pubkey, old_identity );
  FD_TEST( fd_cstr_printf_check( (char *)event.args_json, sizeof(event.args_json), &event.args_json_len, "{\"old_identity\":\"%s\"}", old_identity ) );

  if( FD_UNLIKELY( data_sz<sizeof(ulong) ) ) {
    FD_LOG_WARNING(( "adminctl set-identity payload too small: %lu", data_sz ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
    return;
  }

  ulong version = FD_LOAD( ulong, data );
  if( FD_UNLIKELY( version!=FD_ADMINCTL_SET_IDENTITY_PAYLOAD_VERSION ) ) {
    FD_LOG_WARNING(( "unsupported adminctl set-identity payload version %lu", version ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_VERSION_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH );
    return;
  }

  if( FD_UNLIKELY( data_sz!=sizeof(fd_adminctl_set_identity_t) ) ) {
    FD_LOG_WARNING(( "unexpected adminctl set-identity payload_sz %lu", data_sz ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
    return;
  }

  fd_adminctl_set_identity_t * req = fd_type_pun( data );

  uchar public_key[ 32UL ];
  fd_ed25519_public_from_private( public_key, req->keypair, ctx->sha512 );
  if( FD_UNLIKELY( memcmp( public_key, req->keypair+32UL, 32UL ) ) ) {
    FD_LOG_WARNING(( "set-identity failed: public key in key file does not match private key" ));
    report_admin_command_custom_result( &event, "keypair_mismatch" );
    fd_adminctl_complete( adminctl, slot_idx, FD_SET_IDENTITY_RESULT_KEYPAIR_MISMATCH );
    return;
  }

  ulong state           = FD_SET_IDENTITY_STATE_UNLOCKED;
  ulong halted_seq      = 0UL;
  ulong identity_outset = (ulong)fd_log_wallclock();
  for(;;) {
    if( FD_UNLIKELY( poll_set_identity( ctx, &state, &halted_seq, identity_outset, req->keypair ) ) ) break;
  }

  memcpy( ctx->identity_pubkey, req->keypair+32UL, 32UL );

  report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_SUCCESS );
  fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_SUCCESS );
}

static void
get_identity( fd_admin_tile_ctx_t * ctx,
              ulong                 slot_idx,
              void *                data,
              ulong                 data_sz ) {

  fd_adminctl_t * adminctl = ctx->adminctl;
  fd_event_admin_command_t event = prepare_admin_command( FD_EVENT_ADMIN_COMMAND_TYPE_GET_IDENTITY, data, data_sz );
  FD_BASE58_ENCODE_32_BYTES( ctx->identity_pubkey, identity );
  FD_TEST( fd_cstr_printf_check( (char *)event.args_json, sizeof(event.args_json), &event.args_json_len, "{\"identity\":\"%s\"}", identity ) );

  if( FD_UNLIKELY( data_sz<sizeof(ulong) ) ) {
    FD_LOG_WARNING(( "adminctl get-identity payload too small: %lu", data_sz ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
    return;
  }

  ulong version = FD_LOAD( ulong, data );
  if( FD_UNLIKELY( version!=FD_ADMINCTL_GET_IDENTITY_PAYLOAD_VERSION ) ) {
    FD_LOG_WARNING(( "unsupported adminctl get-identity payload version %lu", version ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_VERSION_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH );
    return;
  }

  if( FD_UNLIKELY( data_sz!=sizeof(fd_adminctl_get_identity_req_t) ) ) {
    FD_LOG_WARNING(( "unexpected adminctl get-identity payload_sz %lu", data_sz ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
    return;
  }

  /* Adminctl commands are serviced one at a time by this tile, which is
     the only driver of identity switches, so the tracked identity
     cannot be mid-switch here. */
  fd_adminctl_get_identity_resp_t resp;
  resp.version = FD_ADMINCTL_GET_IDENTITY_PAYLOAD_VERSION;
  memcpy( resp.identity_pubkey, ctx->identity_pubkey, 32UL );

  report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_SUCCESS );
  fd_adminctl_complete_response( adminctl, slot_idx, FD_ADMINCTL_RESULT_SUCCESS, &resp, sizeof(resp) );
}

/* The process of adding an authorized voter to the validator must be
   done carefully in order to prevent vote transactions being generated
   with an authorized voter that the sign tile is not yet aware of.
   The authorized voter must be added to the sign tile before it is
   added to the tower tile.  All transitions must be linear and in
   forward order. */

/* State 0: UNLOCKED
   The validator is not currently in the process of switching keys. */
#define FD_ADD_AUTH_VOTER_STATE_UNLOCKED             (0UL)

/* State 1: LOCKED
   Some client to the validator has requested to add an authorized
   voter.  To do so, it acquired an exclusive lock on the validator to
   prevent the switch potentially being interleaved with another
   client. */
#define FD_ADD_AUTH_VOTER_STATE_LOCKED               (1UL)

/* State 2: SIGN_TILE_REQUESTED
   The first step to add an authorized voter is to notify the sign
   tile that an authorized voter is being added. */
#define FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_REQUESTED  (2UL)

/* State 3: SIGN_TILE_UPDATED
   The Sign tile has confirmed that it has updated its internal
   mapping for the set of supported authorized voters.  At this point
   the sign tile is aware of the new authorized voter but the Tower
   tile will not prepare vote transactions with the new authorized
   voter yet. */
#define FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_UPDATED    (3UL)

/* State 4: TOWER_TILE_REQUESTED
   Once the Sign tile is updated, now the Tower tile must be notified
   that an authorized voter is being added so it can start preparing
   vote transactions with the new authorized voter. */
#define FD_ADD_AUTH_VOTER_STATE_TOWER_TILE_REQUESTED (4UL)

/* State 5: TOWER_TILE_UPDATED
   The Tower tile has confirmed that it has updated its internal
   mapping for the set of supported authorized voters. */
#define FD_ADD_AUTH_VOTER_STATE_TOWER_TILE_UPDATED   (5UL)

/* State 6: UNLOCK_REQUESTED
   The client now requests that the Tower tile unpause the pipeline
   so the validator can start producing votes with the new authorized
   voter. */
#define FD_ADD_AUTH_VOTER_STATE_UNLOCK_REQUESTED     (6UL)

static void FD_FN_SENSITIVE
poll_add_authorized_voter( fd_admin_tile_ctx_t * ctx,
                           ulong *               state,
                           uchar *               keypair,
                           ulong *               result ) {
  fd_keyswitch_t * tower = ctx->tower_av_keyswitch;

  switch( *state ) {
    case FD_ADD_AUTH_VOTER_STATE_UNLOCKED: {
      if( FD_LIKELY( FD_KEYSWITCH_STATE_UNLOCKED==FD_ATOMIC_CAS( &tower->state, FD_KEYSWITCH_STATE_UNLOCKED, FD_KEYSWITCH_STATE_LOCKED ) ) ) {
        *state = FD_ADD_AUTH_VOTER_STATE_LOCKED;
        FD_LOG_INFO(( "Locking authorized voter set for authorized voter update..." ));
      } else {
        /* keyswitch changes should be guarded and ordered by adminctl.
           If the keyswitch is in a locked state means there is
           unexpected process state and the validator should crash. */
        FD_LOG_CRIT(( "keyswitch is in a locked state but should be unlocked" ));
      }
      break;
    }
    case FD_ADD_AUTH_VOTER_STATE_LOCKED: {
      for( ulong i=0UL; i<ctx->sign_av_keyswitch_cnt; i++ ) {
        fd_keyswitch_t * sign = ctx->sign_av_keyswitch[ i ];
        memcpy( sign->bytes, keypair, 64UL );
        sign->param = FD_KEYSWITCH_PARAM_AV_ADD;
        FD_COMPILER_MFENCE();
        sign->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
        FD_COMPILER_MFENCE();
      }
      fd_memzero_explicit( keypair, 32UL );
      *state = FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_REQUESTED;
      FD_LOG_INFO(( "Requesting all sign tiles to update authorized voter key set..." ));
      break;
    }
    case FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_REQUESTED: {
      int all_updated = 1;
      for( ulong i=0UL; i<ctx->sign_av_keyswitch_cnt; i++ ) {
        fd_keyswitch_t * sign = ctx->sign_av_keyswitch[ i ];
        if( FD_UNLIKELY( sign->state==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
          all_updated = 0;
        } else if( FD_UNLIKELY( sign->state==FD_KEYSWITCH_STATE_FAILED ) ) {
          /* Recoverable error: the sign tile failed to update the set
             of authorized voters is a result of bad caller input.  All
             the sign tiles should be in sync, which means that if one
             sign tile failed, we expect all of them to. */
          fd_memzero_explicit( sign->bytes, 64UL );
          if( FD_LIKELY( !*result ) ) *result = sign->result;
        } else { /* sign->state==FD_KEYSWITCH_STATE_COMPLETED */
          fd_memzero_explicit( sign->bytes, 64UL );
        }
      }

      if( FD_LIKELY( all_updated ) ) {
        if( FD_UNLIKELY( *result ) ) *state = FD_ADD_AUTH_VOTER_STATE_TOWER_TILE_UPDATED;
        else                         *state = FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_UPDATED;
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    case FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_UPDATED: {
      memcpy( tower->bytes, keypair+32UL, 32UL );
      tower->param = FD_KEYSWITCH_PARAM_AV_ADD;
      FD_COMPILER_MFENCE();
      tower->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
      FD_COMPILER_MFENCE();
      *state = FD_ADD_AUTH_VOTER_STATE_TOWER_TILE_REQUESTED;
      FD_LOG_INFO(( "Requesting tower tile to update authorized voter key set..." ));
      break;
    }
    case FD_ADD_AUTH_VOTER_STATE_TOWER_TILE_REQUESTED: {
      /* There is a guarantee that the tower tile will be in sync with
         the set of authorized voters in the sign tile.  At this point
         that means that the command should succeed because invariants
         such as not having duplicate authorized voter keys and too many
         authorized voters are upheld.  If this doesn't hold true, the
         Tower tile will detect any corruption and gracefully crash the
         validator. */
      if( FD_LIKELY( tower->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
        *state = FD_ADD_AUTH_VOTER_STATE_TOWER_TILE_UPDATED;
        FD_LOG_INFO(( "Tower tile key set successfully updated..." ));
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    case FD_ADD_AUTH_VOTER_STATE_TOWER_TILE_UPDATED: {
      tower->state = FD_KEYSWITCH_STATE_UNHALT_PENDING;
      *state       = FD_ADD_AUTH_VOTER_STATE_UNLOCK_REQUESTED;
      FD_LOG_INFO(( "Requesting an unlock of the authorized voter key set..." ));
      break;
    }
    case FD_ADD_AUTH_VOTER_STATE_UNLOCK_REQUESTED: {
      if( FD_LIKELY( tower->state==FD_KEYSWITCH_STATE_UNLOCKED ) ) {
        *state = FD_ADD_AUTH_VOTER_STATE_UNLOCKED;
        FD_LOG_INFO(( "Authorized voter key set unlocked..." ));
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    default: {
      FD_LOG_CRIT(( "Unexpected add-authorized-voter state %lu", *state ));
    }
  }
}

static void FD_FN_SENSITIVE
add_authorized_voter( fd_admin_tile_ctx_t *     ctx,
                      ulong                     slot_idx,
                      void *                    data,
                      ulong                     data_sz ) {

  fd_adminctl_t * adminctl = ctx->adminctl;
  fd_event_admin_command_t event = prepare_admin_command( FD_EVENT_ADMIN_COMMAND_TYPE_ADD_AUTHORIZED_VOTER, data, data_sz );

  if( FD_UNLIKELY( data_sz<sizeof(ulong) ) ) {
    FD_LOG_WARNING(( "adminctl add-authorized-voter payload too small: %lu", data_sz ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
    return;
  }

  ulong version = FD_LOAD( ulong, data );
  if( FD_UNLIKELY( version!=FD_ADMINCTL_ADD_AUTH_VOTER_PAYLOAD_VERSION ) ) {
    FD_LOG_WARNING(( "unsupported adminctl add-authorized-voter payload version %lu", version ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_VERSION_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH );
    return;
  }

  if( FD_UNLIKELY( data_sz!=sizeof(fd_adminctl_add_auth_voter_t) ) ) {
    FD_LOG_WARNING(( "unexpected adminctl add-authorized-voter payload_sz %lu", data_sz ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
    return;
  }

  fd_adminctl_add_auth_voter_t * req = fd_type_pun( data );
  FD_BASE58_ENCODE_32_BYTES( req->keypair+32UL, authorized_voter );
  FD_TEST( fd_cstr_printf_check( (char *)event.args_json, sizeof(event.args_json), &event.args_json_len, "{\"authorized_voter\":\"%s\"}", authorized_voter ) );

  if( FD_UNLIKELY( !ctx->tower_av_keyswitch ) ) {
    FD_LOG_WARNING(( "add-authorized-voter is not supported under Alpenglow." ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_UNSUPPORTED );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_UNSUPPORTED );
    return;
  }

  uchar public_key[ 32UL ];
  fd_ed25519_public_from_private( public_key, req->keypair, ctx->sha512 );
  if( FD_UNLIKELY( memcmp( public_key, req->keypair+32UL, 32UL ) ) ) {
    FD_LOG_WARNING(( "add-authorized-voter failed: public key in key file does not match private key" ));
    report_admin_command_custom_result( &event, "keypair_mismatch" );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADD_AUTHORIZED_VOTER_RESULT_KEYPAIR_MISMATCH );
    return;
  }

  ulong result = FD_ADMINCTL_RESULT_SUCCESS;
  ulong state  = FD_ADD_AUTH_VOTER_STATE_UNLOCKED;
  for(;;) {
    poll_add_authorized_voter( ctx, &state, req->keypair, &result );
    if( FD_UNLIKELY( state==FD_ADD_AUTH_VOTER_STATE_UNLOCKED ) ) break;
  }

  switch( result ) {
    case FD_ADMINCTL_RESULT_SUCCESS:
      report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_SUCCESS );
      break;
    case FD_ADD_AUTHORIZED_VOTER_RESULT_MAX_AUTH_VOTERS:
      report_admin_command_custom_result( &event, "max_authorized_voters" );
      break;
    case FD_ADD_AUTHORIZED_VOTER_RESULT_DUPLICATE_AUTH_VOTER:
      report_admin_command_custom_result( &event, "duplicate_authorized_voter" );
      break;
    default:
      FD_LOG_ERR(( "unexpected add-authorized-voter result %lu", result ));
  }
  fd_adminctl_complete( adminctl, slot_idx, result );
}

static void
snapshot_create( fd_admin_tile_ctx_t * ctx,
                 fd_stem_context_t *   stem,
                 ulong                 slot_idx,
                 void const *          payload,
                 ulong                 payload_sz ) {

  fd_adminctl_t * adminctl = ctx->adminctl;
  fd_event_admin_command_t event = prepare_admin_command( FD_EVENT_ADMIN_COMMAND_TYPE_SNAPSHOT_CREATE, payload, payload_sz );

  if( FD_UNLIKELY( payload_sz!=sizeof(fd_adminctl_snap_create_t) ) ) {
    FD_LOG_WARNING(( "unexpected adminctl snapshot-create payload_sz %lu", payload_sz ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
    return;
  }
  fd_adminctl_snap_create_t const * req = fd_type_pun_const( payload );
  if( FD_UNLIKELY( req->version!=FD_ADMINCTL_SNAP_CREATE_PAYLOAD_VERSION ) ) {
    FD_LOG_WARNING(( "unsupported adminctl snapshot-create payload version %lu", req->version ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_VERSION_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH );
    return;
  }
  ulong target_slot = req->slot;
  FD_TEST( fd_cstr_printf_check( (char *)event.args_json, sizeof(event.args_json), &event.args_json_len, "{\"target_slot\":%lu}", target_slot ) );

  if( FD_UNLIKELY( ctx->replay_out_idx==ULONG_MAX ) ) {
    FD_LOG_WARNING(( "admin requested snapshot creation, but admin tile has no replay command link" ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_UNSUPPORTED );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_UNSUPPORTED );
    return;
  }

  if( FD_UNLIKELY( ctx->snap_create_slot_idx!=ULONG_MAX ) ) {
    FD_LOG_WARNING(( "admin requested snapshot creation, but another snapshot-create command is pending replay response" ));
    report_admin_command_custom_result( &event, "busy" );
    fd_adminctl_complete( adminctl, slot_idx, FD_SNAPSHOT_CREATE_RESULT_BUSY );
    return;
  }

  ulong ctl   = fd_frag_meta_ctl( FD_ADMINCTL_CMD_SNAP_CREATE, 0, 0, 0 );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->replay_out_idx, target_slot, 0UL, 0UL, ctl, 0UL, tspub );
  ctx->snap_create_slot_idx    = slot_idx;
  ctx->snap_create_target_slot = target_slot;
  ctx->snap_create_start_time  = event.start_time;
}

static void
snapshot_create_response( fd_admin_tile_ctx_t * ctx,
                          ulong                 sig,
                          ulong                 ctl ) {

  if( FD_UNLIKELY( fd_frag_meta_ctl_orig( ctl )!=FD_ADMINCTL_CMD_SNAP_CREATE ) ) {
    FD_LOG_ERR(( "unexpected replay admin response orig %lu", fd_frag_meta_ctl_orig( ctl ) ));
  }

  fd_event_admin_command_t event = {
    .type                = FD_EVENT_ADMIN_COMMAND_TYPE_SNAPSHOT_CREATE,
    .start_time          = ctx->snap_create_start_time,
    .payload_version     = FD_ADMINCTL_SNAP_CREATE_PAYLOAD_VERSION,
    .has_payload_version = 1,
    .payload_size        = sizeof(fd_adminctl_snap_create_t),
  };
  FD_TEST( fd_cstr_printf_check( (char *)event.args_json, sizeof(event.args_json), &event.args_json_len, "{\"target_slot\":%lu}", ctx->snap_create_target_slot ) );
  switch( sig ) {
    case FD_ADMINCTL_RESULT_SUCCESS:
      report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_SUCCESS );
      break;
    case FD_SNAPSHOT_CREATE_RESULT_BUSY:
      report_admin_command_custom_result( &event, "busy" );
      break;
    case FD_ADMINCTL_RESULT_UNSUPPORTED:
      report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_UNSUPPORTED );
      break;
    case FD_SNAPSHOT_CREATE_RESULT_NOT_READY:
      report_admin_command_custom_result( &event, "not_ready" );
      break;
    case FD_SNAPSHOT_CREATE_RESULT_SLOT_IN_PAST:
      report_admin_command_custom_result( &event, "slot_in_past" );
      break;
    default:
      FD_LOG_ERR(( "unexpected snapshot-create result %lu", sig ));
  }
  fd_adminctl_complete( ctx->adminctl, ctx->snap_create_slot_idx, sig );
  ctx->snap_create_slot_idx    = ULONG_MAX;
  ctx->snap_create_target_slot = 0UL;
  ctx->snap_create_start_time  = 0UL;
}

/* Removing all authorized voters from the validator is the inverse of
   add-authorized-voter, and must be done in the opposite order.  When
   adding, the sign tile is updated before the tower tile so that the
   tower never asks the sign tile to sign a vote with an authority index
   the sign tile does not yet know about.  When removing, the tower tile
   must be cleared before the sign tiles, so that the tower stops
   referencing an authorized voter index before the sign tile drops the
   corresponding key.

   Clearing the tower map prevents new vote transactions from
   referencing a removed voter, but transactions already published to
   TxSend may still do so.  The tower therefore reports its final output
   sequence after draining its local publish queue.  TxSend processes
   every tower message through that sequence and synchronously waits for
   each signing response before acknowledging the drain.  Only then is
   it safe to clear the sign tiles.  All transitions are linear and in
   forward order.

   Unlike add-authorized-voter, removal cannot fail on the tile side: it
   is unconditional and idempotent (clearing an empty set succeeds). */

/* State 0: UNLOCKED
   The validator is not currently in the process of switching keys. */
#define FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCKED               (0UL)

/* State 1: LOCKED
   Some client to the validator has requested to remove all authorized
   voters.  To do so, it acquired an exclusive lock on the validator to
   prevent the removal potentially being interleaved with another
   client. */
#define FD_REMOVE_ALL_AUTH_VOTERS_STATE_LOCKED                 (1UL)

/* State 2: TOWER_TILE_REQUESTED
   The tower tile has been notified to clear its authorized voter set.
   It is cleared first so it stops preparing vote transactions with any
   authorized voter before the sign tiles drop the keys. */
#define FD_REMOVE_ALL_AUTH_VOTERS_STATE_TOWER_TILE_REQUESTED   (2UL)

/* State 3: TOWER_TILE_CLEARED
   The tower tile confirmed it cleared its authorized voter map.  At
   this point the validator will only prepare vote transactions signed
   by the identity key. */
#define FD_REMOVE_ALL_AUTH_VOTERS_STATE_TOWER_TILE_CLEARED     (3UL)

/* State 4: TXSEND_FLUSH_REQUESTED
   TxSend has been notified to process every tower message through the
   sequence at which the tower stopped producing votes. */
#define FD_REMOVE_ALL_AUTH_VOTERS_STATE_TXSEND_FLUSH_REQUESTED (4UL)

/* State 5: TXSEND_FLUSHED
   TxSend confirmed that all vote transactions which could reference an
   authorized voter have finished signing. */
#define FD_REMOVE_ALL_AUTH_VOTERS_STATE_TXSEND_FLUSHED         (5UL)

/* State 6: SIGN_TILE_REQUESTED
   All sign tiles have been notified to clear their authorized voter
   keys. */
#define FD_REMOVE_ALL_AUTH_VOTERS_STATE_SIGN_TILE_REQUESTED    (6UL)

/* State 7: SIGN_TILE_CLEARED
   All sign tiles confirmed they cleared (and securely zeroed) their
   authorized voter keys. */
#define FD_REMOVE_ALL_AUTH_VOTERS_STATE_SIGN_TILE_CLEARED      (7UL)

/* State 8: UNLOCK_REQUESTED
   The client requests that the tower tile release the lock. */
#define FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCK_REQUESTED       (8UL)

static void
poll_remove_all_authorized_voters( fd_admin_tile_ctx_t * ctx,
                                   ulong *               state ) {
  fd_keyswitch_t * tower = ctx->tower_av_keyswitch;

  switch( *state ) {
    case FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCKED: {
      if( FD_LIKELY( FD_KEYSWITCH_STATE_UNLOCKED==FD_ATOMIC_CAS( &tower->state, FD_KEYSWITCH_STATE_UNLOCKED, FD_KEYSWITCH_STATE_LOCKED ) ) ) {
        *state = FD_REMOVE_ALL_AUTH_VOTERS_STATE_LOCKED;
        FD_LOG_INFO(( "Locking authorized voter set for authorized voter update..." ));
      } else {
        /* keyswitch changes should be guarded and ordered by adminctl.
           If the keyswitch is in a locked state means there is
           unexpected process state and the validator should crash. */
        FD_LOG_CRIT(( "keyswitch is in a locked state but should be unlocked" ));
      }
      break;
    }
    case FD_REMOVE_ALL_AUTH_VOTERS_STATE_LOCKED: {
      tower->param = FD_KEYSWITCH_PARAM_AV_CLEAR;
      FD_COMPILER_MFENCE();
      tower->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
      FD_COMPILER_MFENCE();
      *state = FD_REMOVE_ALL_AUTH_VOTERS_STATE_TOWER_TILE_REQUESTED;
      FD_LOG_INFO(( "Requesting tower tile to clear authorized voter key set..." ));
      break;
    }
    case FD_REMOVE_ALL_AUTH_VOTERS_STATE_TOWER_TILE_REQUESTED: {
      if( FD_LIKELY( tower->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
        *state = FD_REMOVE_ALL_AUTH_VOTERS_STATE_TOWER_TILE_CLEARED;
        FD_LOG_INFO(( "Tower tile authorized voter key set cleared..." ));
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    case FD_REMOVE_ALL_AUTH_VOTERS_STATE_TOWER_TILE_CLEARED: {
      fd_keyswitch_t * txsend = ctx->txsend_av_keyswitch;
      FD_COMPILER_MFENCE();
      txsend->param = tower->result;
      FD_COMPILER_MFENCE();
      txsend->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
      FD_COMPILER_MFENCE();
      *state = FD_REMOVE_ALL_AUTH_VOTERS_STATE_TXSEND_FLUSH_REQUESTED;
      FD_LOG_INFO(( "Requesting TxSend drain in-flight authorized voter signing requests..." ));
      break;
    }
    case FD_REMOVE_ALL_AUTH_VOTERS_STATE_TXSEND_FLUSH_REQUESTED: {
      if( FD_LIKELY( ctx->txsend_av_keyswitch->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
        *state = FD_REMOVE_ALL_AUTH_VOTERS_STATE_TXSEND_FLUSHED;
        FD_LOG_INFO(( "TxSend authorized voter signing requests drained..." ));
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    case FD_REMOVE_ALL_AUTH_VOTERS_STATE_TXSEND_FLUSHED: {
      for( ulong i=0UL; i<ctx->sign_av_keyswitch_cnt; i++ ) {
        fd_keyswitch_t * sign = ctx->sign_av_keyswitch[ i ];
        sign->param = FD_KEYSWITCH_PARAM_AV_CLEAR;
        FD_COMPILER_MFENCE();
        sign->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
        FD_COMPILER_MFENCE();
      }
      *state = FD_REMOVE_ALL_AUTH_VOTERS_STATE_SIGN_TILE_REQUESTED;
      FD_LOG_INFO(( "Requesting all sign tiles to clear authorized voter key set..." ));
      break;
    }
    case FD_REMOVE_ALL_AUTH_VOTERS_STATE_SIGN_TILE_REQUESTED: {
      int all_cleared = 1;
      for( ulong i=0UL; i<ctx->sign_av_keyswitch_cnt; i++ ) {
        fd_keyswitch_t * sign = ctx->sign_av_keyswitch[ i ];
        if( FD_UNLIKELY( sign->state!=FD_KEYSWITCH_STATE_COMPLETED ) ) {
          all_cleared = 0;
          break;
        }
      }

      if( FD_LIKELY( all_cleared ) ) *state = FD_REMOVE_ALL_AUTH_VOTERS_STATE_SIGN_TILE_CLEARED;
      else                           FD_SPIN_PAUSE();
      break;
    }
    case FD_REMOVE_ALL_AUTH_VOTERS_STATE_SIGN_TILE_CLEARED: {
      tower->state = FD_KEYSWITCH_STATE_UNHALT_PENDING;
      *state       = FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCK_REQUESTED;
      FD_LOG_INFO(( "Requesting an unlock of the authorized voter key set..." ));
      break;
    }
    case FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCK_REQUESTED: {
      if( FD_LIKELY( tower->state==FD_KEYSWITCH_STATE_UNLOCKED ) ) {
        *state = FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCKED;
        FD_LOG_INFO(( "Authorized voter key set unlocked..." ));
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    default: {
      FD_LOG_CRIT(( "Unexpected remove-all-authorized-voters state %lu", *state ));
    }
  }
}

static void
remove_all_authorized_voters( fd_admin_tile_ctx_t * ctx,
                              ulong                 slot_idx,
                              void *                data,
                              ulong                 data_sz ) {

  fd_adminctl_t * adminctl = ctx->adminctl;
  fd_event_admin_command_t event = prepare_admin_command( FD_EVENT_ADMIN_COMMAND_TYPE_REMOVE_ALL_AUTHORIZED_VOTERS, data, data_sz );

  if( FD_UNLIKELY( data_sz<sizeof(ulong) ) ) {
    FD_LOG_WARNING(( "adminctl remove-all-authorized-voters payload too small: %lu", data_sz ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
    return;
  }

  ulong version = FD_LOAD( ulong, data );
  if( FD_UNLIKELY( version!=FD_ADMINCTL_REMOVE_ALL_AUTH_VOTERS_PAYLOAD_VERSION ) ) {
    FD_LOG_WARNING(( "unsupported adminctl remove-all-authorized-voters payload version %lu", version ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_VERSION_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH );
    return;
  }

  if( FD_UNLIKELY( data_sz!=sizeof(fd_adminctl_remove_all_auth_voters_t) ) ) {
    FD_LOG_WARNING(( "unexpected adminctl remove-all-authorized-voters payload_sz %lu", data_sz ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
    return;
  }

  if( FD_UNLIKELY( !ctx->tower_av_keyswitch ) ) {
    FD_LOG_WARNING(( "remove-all-authorized-voters is not supported under Alpenglow." ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_UNSUPPORTED );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_UNSUPPORTED );
    return;
  }

  ulong state = FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCKED;
  for(;;) {
    poll_remove_all_authorized_voters( ctx, &state );
    if( FD_UNLIKELY( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCKED ) ) break;
  }

  report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_SUCCESS );
  fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_SUCCESS );
}

static void
failover_update_lag( fd_admin_tile_ctx_t * ctx ) {
  ctx->failover_lag_slots = fd_failover_replication_lag( ctx->failover_peer_status_valid,
                                                         &ctx->failover_peer_status,
                                                         fd_failover_channel_peer_hello( ctx->failover )->boot_id,
                                                         &ctx->failover_consensus );
}

static void
failover_sync_channel_state( fd_admin_tile_ctx_t * ctx ) {
  ulong state = fd_failover_channel_state( ctx->failover );
  if( FD_LIKELY( state==ctx->failover_channel_state ) ) return;

  ctx->failover_channel_state      = state;
  ctx->failover_peer_status_valid  = 0;
  ctx->failover_peer_status_time   = 0L;
  ctx->failover_rtt_probe_time     = 0L;
  if( FD_UNLIKELY( state==FD_FAILOVER_SESSION_PAIRED ) ) {
    ctx->failover_status_sent = 0;
    ctx->failover_cs_sent     = 0;
  }
  failover_update_lag( ctx );
}

static void
failover_prepare_consensus( fd_admin_tile_ctx_t *       ctx,
                            fd_tower_slot_done_t const * done ) {
  if( FD_UNLIKELY( !done->vote_txn_sz || done->vote_txn_sz>sizeof(done->vote_txn) ) ) {
    FD_LOG_WARNING(( "tower produced an invalid vote transaction size" ));
    return;
  }

  uchar txn_mem[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  fd_compact_tower_sync_serde_t serde;
  if( FD_UNLIKELY( !fd_txn_parse( done->vote_txn, done->vote_txn_sz, txn_mem, NULL ) ||
                   !fd_txn_parse_simple_vote( (fd_txn_t const *)txn_mem, done->vote_txn, &serde ) ) ) {
    FD_LOG_WARNING(( "tower produced an invalid vote transaction" ));
    return;
  }

  fd_tower_vote_t votes[ FD_TOWER_VOTE_MAX ];
  ulong vote_cnt;
  ulong root;
  if( FD_UNLIKELY( fd_compact_tower_sync_to_votes( &serde, votes, &vote_cnt, &root ) ||
                   !vote_cnt || votes[ vote_cnt-1UL ].slot!=done->vote_slot ) ) {
    FD_LOG_WARNING(( "tower vote transaction does not match its slot metadata" ));
    return;
  }

  ulong state_sz = 0UL;
  if( FD_UNLIKELY( fd_compact_tower_sync_ser( &serde,
                                              ctx->failover_cs_buf+sizeof(fd_failover_consensus_state_t),
                                              FD_FAILOVER_TOWER_STATE_MAX,
                                              &state_sz ) ) ) {
    FD_LOG_WARNING(( "tower vote transaction exceeds the failover state limit" ));
    return;
  }

  fd_failover_consensus_state_t msg = {
    .term      = ctx->failover_hello.term,
    .link_seq  = ctx->failover_slot_done_seq,
    .vote_slot = done->vote_slot,
    .mode      = (uchar)FD_FAILOVER_MODE_TOWER,
    .state_len = (ushort)state_sz,
  };
  fd_memcpy( ctx->failover_cs_buf, &msg, sizeof(msg) );
  ctx->failover_cs_sz    = sizeof(msg)+state_sz;
  ctx->failover_cs_valid = 1;
  ctx->failover_cs_sent  = 0;
}

/* Drive the pair channel from the run loop. */
static void
failover_poll( fd_admin_tile_ctx_t * ctx,
               int *                 charge_busy ) {
  long now = fd_log_wallclock();

  failover_sync_channel_state( ctx );

  ushort type;
  ulong  payload_sz;
  if( FD_UNLIKELY( fd_failover_channel_poll( ctx->failover, now, charge_busy, &type, ctx->failover_rx, &payload_sz ) ) ) {
    if( FD_LIKELY( type==(ushort)FD_FAILOVER_MSG_STATUS ) ) {
      fd_failover_status_t status;
      if( FD_UNLIKELY( !fd_failover_status_decode( &status,
                                                   fd_failover_channel_peer_hello( ctx->failover ),
                                                   fd_failover_channel_tx_seq( ctx->failover ),
                                                   ctx->failover_rx,
                                                   payload_sz ) ) ) {
        fd_failover_channel_protocol_error( ctx->failover, now );
        failover_sync_channel_state( ctx );
        return;
      }
      ctx->failover_peer_status       = status;
      ctx->failover_peer_status_valid = 1;
      ctx->failover_peer_status_time  = now;
      failover_update_lag( ctx );
      if( FD_LIKELY( ctx->failover_rtt_probe_time && status.ack_seq!=ULONG_MAX &&
                     fd_seq_ge( status.ack_seq, ctx->failover_rtt_probe_seq ) ) ) {
        if( FD_LIKELY( now>=ctx->failover_rtt_probe_time ) ) {
          long sample = fd_long_sat_sub( now, ctx->failover_rtt_probe_time );
          ctx->failover_rtt_nanos = ctx->failover_rtt_nanos
            ? ctx->failover_rtt_nanos+(sample-ctx->failover_rtt_nanos)/8L
            : sample;
        }
        ctx->failover_rtt_probe_time = 0L;
      }
    } else if( FD_LIKELY( type==(ushort)FD_FAILOVER_MSG_CONSENSUS_STATE ) ) {
      if( FD_UNLIKELY( !fd_failover_consensus_decode( &ctx->failover_consensus,
                                                      ctx->failover_role,
                                                      fd_failover_channel_peer_hello( ctx->failover ),
                                                      ctx->failover_rx,
                                                      payload_sz ) ) ) {
        fd_failover_channel_protocol_error( ctx->failover, now );
        failover_sync_channel_state( ctx );
        return;
      }
      failover_update_lag( ctx );
    }
  }

  failover_sync_channel_state( ctx );

  if( FD_UNLIKELY( ctx->failover_slot_done_fresh ) ) {
    ctx->failover_slot_done_fresh = 0;
    fd_tower_slot_done_t const * done = &ctx->failover_slot_done;

    ctx->failover_replay_slot = done->replay_slot;
    if( FD_LIKELY( done->root_slot!=FD_FAILOVER_SLOT_NULL ) ) ctx->failover_root_slot = done->root_slot;
    if( FD_LIKELY( done->has_vote_txn && done->vote_slot!=FD_FAILOVER_SLOT_NULL ) ) {
      ctx->failover_last_vote_slot = done->vote_slot;
      if( FD_LIKELY( ctx->failover_role==FD_FAILOVER_ROLE_ACTIVE ) ) failover_prepare_consensus( ctx, done );
    }
  }

  if( FD_LIKELY( fd_failover_channel_state( ctx->failover )!=FD_FAILOVER_SESSION_PAIRED ) ) return;

  int status_due = !ctx->failover_status_sent ||
                   now<ctx->failover_last_status ||
                   fd_long_sat_sub( now, ctx->failover_last_status )>=ctx->failover_status_interval;
  if( FD_UNLIKELY( status_due && !fd_failover_channel_tx_pending( ctx->failover ) ) ) {
    fd_failover_status_t status;
    fd_memset( &status, 0, sizeof(status) );
    status.term             = ctx->failover_hello.term;
    status.role             = (uchar)ctx->failover_role;
    status.replay_slot      = ctx->failover_replay_slot;
    status.turbine_slot     = FD_FAILOVER_SLOT_NULL;
    status.last_vote_slot   = ctx->failover_last_vote_slot;
    status.root_slot        = ctx->failover_root_slot;
    status.next_leader_slot = FD_FAILOVER_SLOT_NULL;
    if( FD_UNLIKELY( ctx->failover_lag_slots!=FD_FAILOVER_SLOT_NULL &&
                     ctx->failover_lag_slots>ctx->failover_replication_lag_limit ) ) {
      status.status |= FD_FAILOVER_STATUS_REPLAG;
    }
    status.ack_seq = fd_failover_channel_ack_seq( ctx->failover );

    ulong seq_before = fd_failover_channel_tx_seq( ctx->failover );
    if( FD_LIKELY( !fd_failover_channel_send( ctx->failover, now, (ushort)FD_FAILOVER_MSG_STATUS,
                                              (uchar const *)&status, sizeof(status) ) ) ) {
      ctx->failover_last_status = now;
      ctx->failover_status_sent = 1;
      if( FD_LIKELY( !ctx->failover_rtt_probe_time ) ) {
        ctx->failover_rtt_probe_seq  = seq_before;
        ctx->failover_rtt_probe_time = now;
      }
      *charge_busy = 1;
    }
  }

  if( FD_UNLIKELY( ctx->failover_role==FD_FAILOVER_ROLE_ACTIVE &&
                   ctx->failover_cs_valid &&
                   !ctx->failover_cs_sent &&
                   !fd_failover_channel_tx_pending( ctx->failover ) &&
                   fd_failover_channel_state( ctx->failover )==FD_FAILOVER_SESSION_PAIRED &&
                   !fd_failover_channel_send( ctx->failover, now, (ushort)FD_FAILOVER_MSG_CONSENSUS_STATE,
                                              ctx->failover_cs_buf, ctx->failover_cs_sz ) ) ) {
    ctx->failover_cs_sent = 1;
    *charge_busy = 1;
  }

  failover_sync_channel_state( ctx );
}

static inline void FD_FN_SENSITIVE
after_credit( fd_admin_tile_ctx_t * ctx,
              fd_stem_context_t *   stem,
              int *                 opt_poll_in,
              int *                 charge_busy ) {

  if( FD_UNLIKELY( ctx->failover_enabled ) ) failover_poll( ctx, charge_busy );

  fd_adminctl_t * adminctl   = ctx->adminctl;
  ulong           slot_idx   = ULONG_MAX;
  void *          payload    = NULL;
  ulong           payload_sz = 0UL;

  ulong cmd_id = fd_adminctl_poll( adminctl, &slot_idx, &payload, &payload_sz );
  switch( cmd_id ) {
    case FD_ADMINCTL_CMD_IDLE:
      break;
    case FD_ADMINCTL_CMD_ADD_AUTH_VOTER:
      add_authorized_voter( ctx, slot_idx, payload, payload_sz );
      *charge_busy = 1;
      break;
    case FD_ADMINCTL_CMD_SET_IDENTITY:
      set_identity( ctx, slot_idx, payload, payload_sz );
      *charge_busy = 1;
      break;
    case FD_ADMINCTL_CMD_REMOVE_ALL_AUTH_VOTERS:
      remove_all_authorized_voters( ctx, slot_idx, payload, payload_sz );
      *charge_busy = 1;
      break;
    case FD_ADMINCTL_CMD_GET_IDENTITY:
      get_identity( ctx, slot_idx, payload, payload_sz );
      *charge_busy = 1;
      break;
    case FD_ADMINCTL_CMD_SNAP_CREATE:
      snapshot_create( ctx, stem, slot_idx, payload, payload_sz );
      *charge_busy = 1;
      *opt_poll_in = 0;
      break;
    default:
      FD_LOG_WARNING(( "unexpected adminctl cmd %lu", cmd_id ));
      fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_UNKNOWN_COMMAND );
  }
}

static inline int
before_frag( fd_admin_tile_ctx_t * ctx,
             ulong                 in_idx,
             ulong                 seq FD_PARAM_UNUSED,
             ulong                 sig ) {
  if( FD_LIKELY( in_idx==ctx->tower_in_idx ) ) return sig!=FD_TOWER_SIG_SLOT_DONE;
  return 0;
}

static void
during_frag( fd_admin_tile_ctx_t * ctx,
             ulong                 in_idx,
             ulong                 seq FD_PARAM_UNUSED,
             ulong                 sig,
             ulong                 chunk,
             ulong                 sz,
             ulong                 ctl ) {
  if( FD_UNLIKELY( in_idx==ctx->tower_in_idx ) ) {
    if( FD_UNLIKELY( chunk<ctx->tower_in_chunk0 || chunk>ctx->tower_in_wmark || sz!=sizeof(fd_tower_msg_t) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->tower_in_chunk0, ctx->tower_in_wmark ));
    }
    fd_memcpy( &ctx->failover_slot_done, fd_chunk_to_laddr_const( ctx->tower_in_mem, chunk ), sizeof(fd_tower_slot_done_t) );
    return;
  }

  if( FD_UNLIKELY( ctx->snap_create_slot_idx==ULONG_MAX ) ) {
    FD_LOG_ERR(( "unexpected replay snapshot-create response with no pending adminctl command" ));
    return;
  }
  snapshot_create_response( ctx, sig, ctl );
}

static void
after_frag( fd_admin_tile_ctx_t * ctx,
            ulong                 in_idx,
            ulong                 seq,
            ulong                 sig FD_PARAM_UNUSED,
            ulong                 sz FD_PARAM_UNUSED,
            ulong                 tsorig FD_PARAM_UNUSED,
            ulong                 tspub FD_PARAM_UNUSED,
            fd_stem_context_t *   stem FD_PARAM_UNUSED ) {
  if( FD_LIKELY( in_idx!=ctx->tower_in_idx ) ) return;
  ctx->failover_slot_done_seq   = seq;
  ctx->failover_slot_done_fresh = 1;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  if( FD_UNLIKELY( tile->admin.failover_enabled ) ) {
    populate_sock_filter_policy_fd_admin_tile_failover( out_cnt, out, (uint)fd_log_private_logfile_fd() );
    return sock_filter_policy_fd_admin_tile_failover_instr_cnt;
  }
  populate_sock_filter_policy_fd_admin_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_admin_tile_instr_cnt;
}

static int
failover_enabled( fd_topo_t const * topo FD_PARAM_UNUSED,
                  fd_topo_tile_t const * tile ) {
  return tile->admin.failover_enabled;
}

static ulong
rlimit_file_cnt( fd_topo_t const * topo FD_PARAM_UNUSED,
                 fd_topo_tile_t const * tile ) {
  return tile->admin.failover_enabled ? 16UL : 0UL;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_admin_tile_ctx_t const * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  int logfile_fd = fd_log_private_logfile_fd();
  int listen_fd  = ctx->failover_enabled ? fd_failover_channel_listen_fd( ctx->failover ) : -1;

  ulong required_fds = 1UL + (ulong)(-1!=logfile_fd) + (ulong)(-1!=listen_fd);
  if( FD_UNLIKELY( out_fds_cnt<required_fds ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY(   -1!=logfile_fd ) ) out_fds[ out_cnt++ ] = logfile_fd; /* logfile */
  if( FD_UNLIKELY( -1!=listen_fd  ) ) out_fds[ out_cnt++ ] = listen_fd;  /* pair listener */
  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  ((long)1e6) /* 1ms */

#define STEM_CALLBACK_CONTEXT_TYPE  fd_admin_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_admin_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT after_credit
#define STEM_CALLBACK_BEFORE_FRAG  before_frag
#define STEM_CALLBACK_DURING_FRAG  during_frag
#define STEM_CALLBACK_AFTER_FRAG   after_frag

#include "../../disco/stem/fd_stem.c"

static ulong
max_event_sz( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return sizeof(fd_event_admin_command_t);
}

fd_topo_run_tile_t fd_tile_admin = {
  .name                     = "admin",
  .max_event_sz             = max_event_sz,
  .keep_host_networking_fn  = failover_enabled,
  .allow_connect_fn         = failover_enabled,
  .rlimit_file_cnt_fn       = rlimit_file_cnt,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
