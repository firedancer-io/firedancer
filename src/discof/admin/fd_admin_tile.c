#include "../../disco/topo/fd_topo.h"
#include "../../disco/events/generated/fd_event_gen.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/keyguard/fd_keyload.h"

#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>

#include "fd_adminctl.h"
#include "../failover/fd_failover_bus.h"
#include "generated/fd_admin_tile_seccomp.h"
#include "generated/fd_admin_tile_failover_seccomp.h"

struct fd_admin_tile_ctx {
  fd_topo_t const * topo;
  fd_adminctl_t *   adminctl;
  uchar             identity_pubkey[ 32UL ];
  /* Neither private key is held resident.  Each is read from disk only for
     the duration of a switch, into failover_key_copy, then zeroed, so a
     spare never carries the staked key and the tile never carries either. */
  int               failover_junk_key_fd;      /* the key files, opened before the sandbox */
  int               failover_staked_key_fd;    /* a switch preads them, it never opens a path at runtime */
  uchar             failover_junk_pubkey[ 32 ];   /* the boot identity, checked against the file at a switch */
  uchar             failover_staked_pubkey[ 32 ]; /* checked against the file at a switch */
  uchar *           failover_key_copy;            /* a switch reads a key into this page, kept out of core dumps */
  fd_keyswitch_t *  tower_av_keyswitch;
  fd_keyswitch_t *  txsend_av_keyswitch;
  fd_keyswitch_t *  sign_av_keyswitch[ FD_TOPO_MAX_TILES ];
  ulong             sign_av_keyswitch_cnt;
  fd_sha512_t       sha512[ 1 ];

  ulong replay_out_idx;           /* admin_replay stem out index */
  ulong snap_create_slot_idx;     /* adminctl slot of snapshot-create command */
  ulong snap_create_target_slot;  /* requested slot retained until Replay responds */
  ulong snap_create_start_time;   /* command start retained until Replay responds */

  /* Failover commands get forwarded to the failover tile over the bus.
     Only one can be in flight at a time, same as snapshot creation. */
  int                   failover_enabled;
  int                   tower_file_enabled;
  ulong                 failov_out_idx;             /* admin_failov stem out index */
  fd_wksp_t *           failov_out_mem;
  ulong                 failov_out_chunk0;
  ulong                 failov_out_wmark;
  ulong                 failov_out_chunk;
  ulong                 failov_in_idx;
  fd_wksp_t *           failov_in_mem;
  ulong                 failov_in_chunk0;
  ulong                 failov_in_wmark;
  fd_failover_bus_msg_t failov_resp;                /* response frame being consumed */
  ulong                 failover_slot_cmd;          /* which failover command is parked, or IDLE */
  ulong                 failover_status_slot_idx;   /* adminctl slot parked on the bus */
  ulong                 failover_status_nonce;      /* nonce of the parked request */
  ulong                 failover_status_start_time; /* command start retained until the tile responds */
  long                  failover_status_deadline;   /* wallclock past which the admin tile answers unresponsive */
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
  return alignof(fd_admin_tile_ctx_t);
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return sizeof(fd_admin_tile_ctx_t);
}

/* Read a key file into the switch copy and check it is the identity
   recorded at boot.  Returns 0 with the private key in
   ctx->failover_key_copy, or nonzero with the copy zeroed. */
/* Read a key from an already-open file into the switch copy, parse it, and
   check it is the identity recorded at boot.  The file is preadd, never
   reopened, so the sandbox does not have to allow a runtime open, and a
   malformed file returns an error rather than terminating the tile.
   Returns 0 with the private key in ctx->failover_key_copy, or nonzero
   with the copy scrubbed.  The page holds the 64 byte key, then a scratch
   region for the json text and its tokens (as fd_keyload_read lays out). */
#define FD_ADMIN_KEY_MIN_SZ  (129UL)  /* 64 bytes, 63 commas, two brackets */
#define FD_ADMIN_KEY_JSON_SZ (1023UL)
static int FD_FN_SENSITIVE
read_switch_key( fd_admin_tile_ctx_t * ctx,
                 int                   key_fd,
                 uchar const *         want_pub ) {
  uchar * kp   = ctx->failover_key_copy;
  char *  json = (char *)kp + 64UL;
  long    n    = pread( key_fd, json, FD_ADMIN_KEY_JSON_SZ, 0L );
  if( FD_UNLIKELY( n<(long)FD_ADMIN_KEY_MIN_SZ ) ) {
    /* pread may have left a partial key in the scratch, scrub the whole
       page, not just the 64 byte slot. */
    fd_memzero_explicit( kp, 64UL+FD_ADMIN_KEY_JSON_SZ );
    FD_LOG_WARNING(( "could not read the key file for a switch (%li, %i-%s)", n, errno, fd_io_strerror( errno ) ));
    return errno ? errno : EPROTO;
  }
  json[ n ] = '\0';
  char ** tok = (char **)( kp + 64UL + 1024UL );
  int ok = fd_cstr_tokenize( tok, 64UL, json, ',' )==64UL;
  ok = ok && 1==sscanf( tok[ 0 ], "[ %hhu", &kp[ 0 ] );
  for( ulong i=1UL; ok && i<63UL; i++ ) ok = 1==sscanf( tok[ i ], "%hhu", &kp[ i ] );
  ok = ok && 1==sscanf( tok[ 63 ], "%hhu ]", &kp[ 63 ] );
  fd_memzero_explicit( json, FD_ADMIN_KEY_JSON_SZ+1UL );
  fd_memzero_explicit( tok,  64UL*sizeof(char *) );
  if( FD_UNLIKELY( !ok ) ) {
    fd_memzero_explicit( kp, 64UL );
    FD_LOG_WARNING(( "the key file is malformed, not switching" ));
    return EPROTO;
  }
  /* Check the file still holds the identity recorded at boot.  We do not
     derive the pubkey from the seed here, an inconsistent keypair is
     caught fatally by the sign tile, which is where the secret already
     lives. */
  if( FD_UNLIKELY( !fd_memeq( kp+32UL, want_pub, 32UL ) ) ) {
    fd_memzero_explicit( kp, 64UL );
    FD_LOG_WARNING(( "the key file no longer holds the configured identity, not switching" ));
    return EPERM;
  }
  return 0;
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void *                scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_admin_tile_ctx_t * ctx     = (fd_admin_tile_ctx_t *)scratch;
  fd_memset( ctx, 0, sizeof(fd_admin_tile_ctx_t) );

  if( FD_UNLIKELY( !strcmp( tile->admin.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  uchar const * identity = fd_keyload_load( tile->admin.identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->identity_pubkey, identity, 32UL );
  fd_keyload_unload( identity, 1 );

  if( FD_UNLIKELY( tile->admin.failover_enabled ) ) {
    /* A switch reads a key into this page, uses it, and zeroes it.  Like
       the loaded keys it is locked and kept out of core dumps. */
    ctx->failover_key_copy   = fd_keyload_alloc_protected_pages( 1UL, 1UL );

    /* Open the two key files before the sandbox.  A switch preads them, so
       it never opens a path once landlock is up, and RLIMIT_NOFILE=0 does
       not stop it because these descriptors already exist.  The boot
       identity is the junk key. */
    fd_memcpy( ctx->failover_junk_pubkey, ctx->identity_pubkey, 32UL );
    ctx->failover_junk_key_fd   = open( tile->admin.identity_key_path,             O_RDONLY|O_CLOEXEC );
    if( FD_UNLIKELY( ctx->failover_junk_key_fd<0 ) )
      FD_LOG_ERR(( "open(%s) failed (%i-%s)", tile->admin.identity_key_path, errno, fd_io_strerror( errno ) ));
    ctx->failover_staked_key_fd = open( tile->admin.failover_staked_identity_path, O_RDONLY|O_CLOEXEC );
    if( FD_UNLIKELY( ctx->failover_staked_key_fd<0 ) )
      FD_LOG_ERR(( "open(%s) failed (%i-%s)", tile->admin.failover_staked_identity_path, errno, fd_io_strerror( errno ) ));

    /* Record the staked public key for the boot checks and to verify the
       file at each switch.  The private half is not kept. */
    uchar const * staked_pk = fd_keyload_load( tile->admin.failover_staked_identity_path, 1 );
    fd_memcpy( ctx->failover_staked_pubkey, staked_pk, 32UL );
    int same_as_junk = fd_memeq( staked_pk, ctx->identity_pubkey, 32UL );
    fd_keyload_unload( staked_pk, 1 );
    if( FD_UNLIKELY( same_as_junk ) ) {
      FD_LOG_ERR(( "[failover.staked_identity_path] and [failover.junk_identity_path] hold the same key, a spare must not boot under the staked identity" ));
    }

    /* With the staked key as an authorized voter a spare could sign
       votes without being promoted. */
    ulong sign_idx = fd_topo_find_tile( topo, "sign", 0UL );
    FD_TEST( sign_idx!=ULONG_MAX );
    fd_topo_tile_t const * sign_tile = &topo->tiles[ sign_idx ];
    for( ulong i=0UL; i<sign_tile->sign.authorized_voter_paths_cnt; i++ ) {
      uchar const * voter = fd_keyload_load( sign_tile->sign.authorized_voter_paths[ i ], 1 );
      int matches = fd_memeq( voter, ctx->failover_staked_pubkey, 32UL );
      fd_keyload_unload( voter, 1 );
      if( FD_UNLIKELY( matches ) ) {
        FD_LOG_ERR(( "authorized voter `%s` must differ from [failover.staked_identity_path]", sign_tile->sign.authorized_voter_paths[ i ] ));
      }
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
  ctx->failov_out_idx           = ULONG_MAX;
  ctx->failov_in_idx            = ULONG_MAX;
  ctx->failover_status_slot_idx = ULONG_MAX;
  ctx->failover_slot_cmd        = FD_ADMINCTL_CMD_IDLE;
  ctx->failover_enabled         = tile->admin.failover_enabled;
  ctx->tower_file_enabled       = tile->admin.tower_file_enabled;
  ctx->topo = topo;

  fd_topo_obj_t const * adminctl_obj = fd_topo_find_tile_obj( topo, tile, "adminctl" );
  FD_TEST( adminctl_obj );

  ctx->adminctl = fd_adminctl_join( fd_topo_obj_laddr( topo, adminctl_obj->id ) );
  FD_TEST( ctx->adminctl );

  ctx->replay_out_idx = fd_topo_find_tile_out_link( topo, tile, "admin_replay", 0UL );

  ctx->failov_out_idx = fd_topo_find_tile_out_link( topo, tile, "admin_failov", 0UL );
  if( FD_LIKELY( ctx->failov_out_idx!=ULONG_MAX ) ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ ctx->failov_out_idx ] ];
    ctx->failov_out_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->failov_out_chunk0 = fd_dcache_compact_chunk0( ctx->failov_out_mem, link->dcache );
    ctx->failov_out_wmark  = fd_dcache_compact_wmark ( ctx->failov_out_mem, link->dcache, link->mtu );
    ctx->failov_out_chunk  = ctx->failov_out_chunk0;
  }

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( FD_LIKELY( !strcmp( link->name, "replay_admin" ) ) ) continue;
    if( FD_LIKELY( !strcmp( link->name, "failov_admin" ) ) ) {
      ctx->failov_in_idx    = i;
      ctx->failov_in_mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
      ctx->failov_in_chunk0 = fd_dcache_compact_chunk0( ctx->failov_in_mem, link->dcache );
      ctx->failov_in_wmark  = fd_dcache_compact_wmark ( ctx->failov_in_mem, link->dcache, link->mtu );
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
       (f) Shred.  The shred tile has the sign tile sign FEC sets
           asynchronously; it waits for its outstanding requests to be
           answered under the old key before switching.
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
            strcmp( tile->name, "rserve" ) &&
            strcmp( tile->name, "shred"  ) ) {
          continue;
        }

        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id );
        if( !strcmp( tile->name, "gossip" ) ) tile_ks->param = identity_outset;
        if( !strcmp( tile->name, "shred"  ) ) tile_ks->param = 0UL; /* the leader pipeline is halted, nothing more to reach */
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
            strcmp( tile->name, "rserve" ) &&
            strcmp( tile->name, "shred"  ) ) {
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
                       !strcmp( tile->name, "rserve" ) ||
                       !strcmp( tile->name, "shred"  ) ) ) continue;

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
                       !strcmp( tile->name, "tower"  ) ||
                       !strcmp( tile->name, "bundle" ) ||
                       !strcmp( tile->name, "rserve" ) ||
                       !strcmp( tile->name, "shred"  ) ) ) continue;

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

static void FD_FN_SENSITIVE run_identity_switch( fd_admin_tile_ctx_t * ctx,
                                                 uchar *               keypair,
                                                 ulong *               opt_tower_watermark );

static void FD_FN_SENSITIVE
set_identity( fd_admin_tile_ctx_t * ctx,
              ulong                 slot_idx,
              void *                data,
              ulong                 data_sz ) {

  fd_adminctl_t * adminctl = ctx->adminctl;
  fd_event_admin_command_t event = prepare_admin_command( FD_EVENT_ADMIN_COMMAND_TYPE_SET_IDENTITY, data, data_sz );
  FD_BASE58_ENCODE_32_BYTES( ctx->identity_pubkey, old_identity );
  FD_TEST( fd_cstr_printf_check( (char *)event.args_json, sizeof(event.args_json), &event.args_json_len, "{\"old_identity\":\"%s\"}", old_identity ) );

  /* With failover or tower persistence on, the failover controller owns
     the identity.  Refuse before touching any keyswitch so a CLI switch
     cannot race the pool. */
  if( FD_UNLIKELY( ctx->failover_enabled || ctx->tower_file_enabled ) ) {
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_UNSUPPORTED );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_UNSUPPORTED );
    return;
  }

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

  run_identity_switch( ctx, req->keypair, NULL );

  report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_SUCCESS );
  fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_SUCCESS );
}

/* Switches the whole validator to the given keypair.  This blocks until
   every tile has picked up the new key.  The private key is zeroed as
   part of the switch, so pass a copy.  If opt_tower_watermark is set, it
   receives the tower tile's sequence number at the point it stopped. */
static void FD_FN_SENSITIVE
run_identity_switch( fd_admin_tile_ctx_t * ctx,
                     uchar *               keypair,
                     ulong *               opt_tower_watermark ) {
  ulong state           = FD_SET_IDENTITY_STATE_UNLOCKED;
  ulong halted_seq      = 0UL;
  ulong identity_outset = (ulong)fd_log_wallclock();
  for(;;) {
    if( FD_UNLIKELY( poll_set_identity( ctx, &state, &halted_seq, identity_outset, keypair ) ) ) break;
  }

  fd_memcpy( ctx->identity_pubkey, keypair+32UL, 32UL );
  /* The watermark a demotion needs is the tower tile's output sequence,
     the one it records when it halts and the failover tile consumes on
     tower_out.  halted_seq above is the replay tile's field, which nothing
     writes. */
  if( FD_UNLIKELY( opt_tower_watermark ) ) *opt_tower_watermark = find_identity_keyswitch( ctx, "tower" )->result;
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

/* Failover status is answered by the failover tile, which owns the pool
   link.  We validate the request, forward it over the bus and park the
   adminctl slot until the response arrives or the deadline passes, like
   snapshot creation waits on replay. */

static void
failover_status_complete( fd_admin_tile_ctx_t * ctx,
                          ulong                 result,
                          void const *          resp,
                          ulong                 resp_sz ) {
  int is_control = ctx->failover_slot_cmd==FD_ADMINCTL_CMD_FAILOVER_CONTROL;
  fd_event_admin_command_t event = {
    .type                = is_control ? FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER_CONTROL
                                      : FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER_STATUS,
    .args_json           = { '{', '}' },
    .args_json_len       = 2UL,
    .start_time          = ctx->failover_status_start_time,
    .payload_version     = is_control ? FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION
                                      : FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION,
    .has_payload_version = 1,
    .payload_size        = is_control ? sizeof(fd_adminctl_failover_control_t)
                                      : sizeof(fd_adminctl_failover_status_req_t),
  };
  switch( result ) {
    case FD_ADMINCTL_RESULT_SUCCESS:
      report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_SUCCESS );
      break;
    case FD_FAILOVER_STATUS_RESULT_UNRESPONSIVE:
      report_admin_command_custom_result( &event, "unresponsive" );
      break;
    case FD_FAILOVER_STATUS_RESULT_NO_SUCH_PEER:
      report_admin_command_custom_result( &event, "no_such_peer" );
      break;
    case FD_FAILOVER_CONTROL_RESULT_DISABLED:
      report_admin_command_custom_result( &event, "disabled" );
      break;
    case FD_FAILOVER_CONTROL_RESULT_BAD_ROLE:
      report_admin_command_custom_result( &event, "bad_role" );
      break;
    case FD_FAILOVER_CONTROL_RESULT_NOT_PAIRED:
      report_admin_command_custom_result( &event, "not_paired" );
      break;
    case FD_FAILOVER_CONTROL_RESULT_BUSY:
      report_admin_command_custom_result( &event, "busy" );
      break;
    case FD_FAILOVER_CONTROL_RESULT_PAUSED:
      report_admin_command_custom_result( &event, "paused" );
      break;
    case FD_FAILOVER_CONTROL_RESULT_NO_EVIDENCE:
      report_admin_command_custom_result( &event, "no_evidence" );
      break;
    case FD_FAILOVER_CONTROL_RESULT_BAD_IDENTITY:
      report_admin_command_custom_result( &event, "bad_identity" );
      break;
    case FD_FAILOVER_CONTROL_RESULT_UNSUPPORTED:
      report_admin_command_custom_result( &event, "unsupported" );
      break;
    case FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY:
      report_admin_command_custom_result( &event, "peer_unready" );
      break;
    default:
      FD_LOG_WARNING(( "unexpected failover-status result %lu", result ));
      report_admin_command_custom_result( &event, "unexpected" );
      break;
  }
  fd_adminctl_complete_response( ctx->adminctl, ctx->failover_status_slot_idx, result, resp, resp_sz );
  ctx->failover_status_slot_idx   = ULONG_MAX;
  ctx->failover_slot_cmd          = FD_ADMINCTL_CMD_IDLE;
  ctx->failover_status_start_time = 0UL;
  ctx->failover_status_deadline   = 0L;
}

static void
failover_status( fd_admin_tile_ctx_t * ctx,
                 fd_stem_context_t *   stem,
                 ulong                 slot_idx,
                 void *                data,
                 ulong                 data_sz ) {

  fd_adminctl_t * adminctl = ctx->adminctl;
  fd_event_admin_command_t event = prepare_admin_command( FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER_STATUS,
                                                          data, data_sz );

  if( FD_UNLIKELY( data_sz<sizeof(ulong) ) ) {
    FD_LOG_WARNING(( "unexpected adminctl failover-status payload_sz %lu", data_sz ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
    return;
  }

  ulong version = FD_LOAD( ulong, data );
  if( FD_UNLIKELY( version!=FD_ADMINCTL_FAILOVER_STATUS_PAYLOAD_VERSION ) ) {
    FD_LOG_WARNING(( "unsupported adminctl failover-status payload version %lu", version ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_VERSION_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH );
    return;
  }

  if( FD_UNLIKELY( data_sz!=sizeof(fd_adminctl_failover_status_req_t) ) ) {
    FD_LOG_WARNING(( "unexpected adminctl failover-status payload_sz %lu", data_sz ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
    return;
  }

  if( FD_UNLIKELY( !ctx->failover_enabled ) ) {
    fd_adminctl_failover_status_resp_t resp;
    fd_adminctl_failover_status_resp_init( &resp );
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_SUCCESS );
    fd_adminctl_complete_response( adminctl, slot_idx, FD_ADMINCTL_RESULT_SUCCESS, &resp, sizeof(resp) );
    return;
  }

  if( FD_UNLIKELY( ctx->failov_out_idx==ULONG_MAX ) ) {
    FD_LOG_WARNING(( "failover status requested, but the admin tile has no failover bus link" ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_UNSUPPORTED );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_UNSUPPORTED );
    return;
  }

  if( FD_UNLIKELY( ctx->failover_status_slot_idx!=ULONG_MAX ) ) {
    report_admin_command_custom_result( &event, "busy" );
    fd_adminctl_complete( adminctl, slot_idx, FD_FAILOVER_STATUS_RESULT_BUSY );
    return;
  }

  fd_failover_bus_msg_t * msg = fd_chunk_to_laddr( ctx->failov_out_mem, ctx->failov_out_chunk );
  fd_memset( msg, 0, sizeof(*msg) );
  msg->nonce = ++ctx->failover_status_nonce;
  fd_memcpy( msg->payload, data, data_sz );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->failov_out_idx, FD_FAILOVER_BUS_STATUS_REQ, ctx->failov_out_chunk, sizeof(*msg), 0UL, tspub, tspub );
  ctx->failov_out_chunk = fd_dcache_compact_next( ctx->failov_out_chunk, sizeof(*msg), ctx->failov_out_chunk0, ctx->failov_out_wmark );

  ctx->failover_status_slot_idx   = slot_idx;
  ctx->failover_slot_cmd          = FD_ADMINCTL_CMD_FAILOVER_STATUS;
  ctx->failover_status_start_time = event.start_time;
  ctx->failover_status_deadline   = fd_failover_clock()+FD_FAILOVER_BUS_DEADLINE_NANOS;
}

/* The failover tile asked us to switch identity.  Do the switch and
   send back the result. */
static void FD_FN_SENSITIVE
failover_switch_request( fd_admin_tile_ctx_t * ctx,
                         fd_stem_context_t *   stem ) {
  fd_failover_bus_msg_t const * req = &ctx->failov_resp;
  fd_failover_switch_req_t sw;
  fd_memcpy( &sw, req->payload, sizeof(sw) );

  fd_failover_switch_resp_t answer;
  fd_memset( &answer, 0, sizeof(answer) );
  fd_memcpy( answer.identity, ctx->identity_pubkey, 32UL );

  int           key_fd   = -1;
  uchar const * want_pub = NULL;
  if( FD_UNLIKELY( !ctx->failover_enabled ) )                   answer.result = FD_FAILOVER_SWITCH_ERR_DISABLED;
  else if( FD_LIKELY( sw.key==FD_FAILOVER_SWITCH_KEY_JUNK   ) ) { key_fd = ctx->failover_junk_key_fd;   want_pub = ctx->failover_junk_pubkey;   }
  else if( FD_LIKELY( sw.key==FD_FAILOVER_SWITCH_KEY_STAKED ) ) { key_fd = ctx->failover_staked_key_fd; want_pub = ctx->failover_staked_pubkey; }
  else                                                         answer.result = FD_FAILOVER_SWITCH_ERR_KEY;

  if( FD_LIKELY( key_fd>=0 ) ) {
    /* Read the key from disk into the protected page only now, for this
       switch, so the tile never holds a private key resident. */
    if( FD_UNLIKELY( read_switch_key( ctx, key_fd, want_pub ) ) ) {
      answer.result = FD_FAILOVER_SWITCH_ERR_KEY;
    } else {
      ulong watermark = 0UL;
      run_identity_switch( ctx, ctx->failover_key_copy, &watermark );
      fd_memzero_explicit( ctx->failover_key_copy, 64UL );
      answer.result          = FD_FAILOVER_SWITCH_OK;
      answer.tower_watermark = watermark;
      fd_memcpy( answer.identity, ctx->identity_pubkey, 32UL );
    }
  }

  if( FD_UNLIKELY( ctx->failov_out_idx==ULONG_MAX ) ) {
    FD_LOG_WARNING(( "an identity switch was requested with no failover bus link" ));
    return;
  }
  fd_failover_bus_msg_t * out = fd_chunk_to_laddr( ctx->failov_out_mem, ctx->failov_out_chunk );
  fd_memset( out, 0, sizeof(*out) );
  out->nonce  = req->nonce;
  out->result = answer.result;
  fd_memcpy( out->payload, &answer, sizeof(answer) );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->failov_out_idx, FD_FAILOVER_BUS_SWITCH_RESP, ctx->failov_out_chunk, sizeof(*out), 0UL, tspub, tspub );
  ctx->failov_out_chunk = fd_dcache_compact_next( ctx->failov_out_chunk, sizeof(*out), ctx->failov_out_chunk0, ctx->failov_out_wmark );
}

/* This tile is the sole writer of identities.  A query reports its
   installed key without initiating a switch or exposing private keys.
   Switches run synchronously here, so a query cannot interleave one. */
static void
failover_switch_query( fd_admin_tile_ctx_t * ctx,
                       fd_stem_context_t *   stem ) {
  fd_failover_bus_msg_t const * req = &ctx->failov_resp;
  fd_failover_switch_query_t query;
  fd_memcpy( &query, req->payload, sizeof(query) );
  fd_failover_switch_resp_t answer;
  fd_memset( &answer, 0, sizeof(answer) );
  answer.tower_watermark = ULONG_MAX;
  answer.result = FD_FAILOVER_SWITCH_STATE_FOREIGN;
  fd_memcpy( answer.identity, ctx->identity_pubkey, 32UL );
  if( FD_LIKELY( ctx->failover_enabled && !query.reserved ) ) {
    if( FD_LIKELY( fd_memeq( ctx->identity_pubkey, ctx->failover_junk_pubkey, 32UL ) ) )
      answer.result = FD_FAILOVER_SWITCH_STATE_JUNK;
    else if( FD_LIKELY( fd_memeq( ctx->identity_pubkey, ctx->failover_staked_pubkey, 32UL ) ) )
      answer.result = FD_FAILOVER_SWITCH_STATE_STAKED;
  }
  if( FD_UNLIKELY( ctx->failov_out_idx==ULONG_MAX ) ) return;
  fd_failover_bus_msg_t * out = fd_chunk_to_laddr( ctx->failov_out_mem, ctx->failov_out_chunk );
  fd_memset( out, 0, sizeof(*out) );
  out->nonce  = req->nonce;
  out->result = answer.result;
  fd_memcpy( out->payload, &answer, sizeof(answer) );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->failov_out_idx, FD_FAILOVER_BUS_SWITCH_STATE, ctx->failov_out_chunk, sizeof(*out), 0UL, tspub, tspub );
  ctx->failov_out_chunk = fd_dcache_compact_next( ctx->failov_out_chunk, sizeof(*out), ctx->failov_out_chunk0, ctx->failov_out_wmark );
}

/* Forward a failover command to the failover tile.  We only check the ABI
   here, the failover tile decides whether the command is allowed. */
static void
failover_control( fd_admin_tile_ctx_t * ctx,
                  fd_stem_context_t *   stem,
                  ulong                 slot_idx,
                  void *                data,
                  ulong                 data_sz ) {

  fd_adminctl_t * adminctl = ctx->adminctl;
  fd_event_admin_command_t event = prepare_admin_command( FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER_CONTROL,
                                                          data, data_sz );

  if( FD_UNLIKELY( data_sz<sizeof(ulong) ) ) {
    FD_LOG_WARNING(( "unexpected adminctl failover-control payload_sz %lu", data_sz ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
    return;
  }

  ulong version = FD_LOAD( ulong, data );
  if( FD_UNLIKELY( version!=FD_ADMINCTL_FAILOVER_CONTROL_PAYLOAD_VERSION ) ) {
    FD_LOG_WARNING(( "unsupported adminctl failover-control payload version %lu", version ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_VERSION_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH );
    return;
  }

  if( FD_UNLIKELY( data_sz!=sizeof(fd_adminctl_failover_control_t) ) ) {
    FD_LOG_WARNING(( "unexpected adminctl failover-control payload_sz %lu", data_sz ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
    return;
  }

  fd_adminctl_failover_control_t const * req = fd_type_pun_const( data );
  if( FD_UNLIKELY( req->cmd>=FD_ADMINCTL_FAILOVER_CMD_CNT ) ) {
    FD_LOG_WARNING(( "unknown failover command %lu", req->cmd ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
    return;
  }

  if( FD_UNLIKELY( !ctx->failover_enabled || ctx->failov_out_idx==ULONG_MAX ) ) {
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_UNSUPPORTED );
    fd_adminctl_complete( adminctl, slot_idx, FD_FAILOVER_CONTROL_RESULT_DISABLED );
    return;
  }

  if( FD_UNLIKELY( ctx->failover_status_slot_idx!=ULONG_MAX ) ) {
    report_admin_command_custom_result( &event, "busy" );
    fd_adminctl_complete( adminctl, slot_idx, FD_FAILOVER_STATUS_RESULT_BUSY );
    return;
  }

  fd_failover_bus_msg_t * msg = fd_chunk_to_laddr( ctx->failov_out_mem, ctx->failov_out_chunk );
  fd_memset( msg, 0, sizeof(*msg) );
  msg->nonce = ++ctx->failover_status_nonce;
  fd_memcpy( msg->payload, data, data_sz );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->failov_out_idx, FD_FAILOVER_BUS_CONTROL_REQ, ctx->failov_out_chunk, sizeof(*msg), 0UL, tspub, tspub );
  ctx->failov_out_chunk = fd_dcache_compact_next( ctx->failov_out_chunk, sizeof(*msg), ctx->failov_out_chunk0, ctx->failov_out_wmark );

  ctx->failover_status_slot_idx   = slot_idx;
  ctx->failover_slot_cmd          = FD_ADMINCTL_CMD_FAILOVER_CONTROL;
  ctx->failover_status_start_time = event.start_time;
  ctx->failover_status_deadline   = fd_failover_clock()+FD_FAILOVER_BUS_DEADLINE_NANOS;
}

static void
failover_status_response( fd_admin_tile_ctx_t * ctx,
                          ulong                 sig ) {
  fd_failover_bus_msg_t const * msg = &ctx->failov_resp;
  if( FD_UNLIKELY( sig!=FD_FAILOVER_BUS_STATUS_RESP && sig!=FD_FAILOVER_BUS_CONTROL_RESP ) ) {
    FD_LOG_WARNING(( "unexpected failover bus response %lu", sig ));
    return;
  }
  /* A slot recycles after a few commands, so a late response is matched
     by nonce and dropped rather than applied to a newer request. */
  if( FD_UNLIKELY( ctx->failover_status_slot_idx==ULONG_MAX || msg->nonce!=ctx->failover_status_nonce ) ) {
    FD_LOG_WARNING(( "dropping a stale failover status response" ));
    return;
  }
  /* Control responses have their own payload.  Both kinds can also come
     back with just a result code. */
  ulong resp_sz = sig==FD_FAILOVER_BUS_CONTROL_RESP ? sizeof(fd_adminctl_failover_control_resp_t)
                                                    : sizeof(fd_adminctl_failover_status_resp_t);
  if( FD_LIKELY( msg->result==FD_ADMINCTL_RESULT_SUCCESS ) ) {
    failover_status_complete( ctx, FD_ADMINCTL_RESULT_SUCCESS, msg->payload, resp_sz );
  } else {
    failover_status_complete( ctx, msg->result, NULL, 0UL );
  }
}

static inline void FD_FN_SENSITIVE
after_credit( fd_admin_tile_ctx_t * ctx,
              fd_stem_context_t *   stem,
              int *                 opt_poll_in,
              int *                 charge_busy ) {

  fd_adminctl_t * adminctl   = ctx->adminctl;
  ulong           slot_idx   = ULONG_MAX;
  void *          payload    = NULL;
  ulong           payload_sz = 0UL;

  if( FD_UNLIKELY( ctx->failover_status_slot_idx!=ULONG_MAX && fd_failover_clock()>ctx->failover_status_deadline ) ) {
    FD_LOG_WARNING(( "the failover tile did not answer a status request in time" ));
    failover_status_complete( ctx, FD_FAILOVER_STATUS_RESULT_UNRESPONSIVE, NULL, 0UL );
  }

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
    case FD_ADMINCTL_CMD_FAILOVER_STATUS:
      failover_status( ctx, stem, slot_idx, payload, payload_sz );
      *charge_busy = 1;
      *opt_poll_in = 0;
      break;
    case FD_ADMINCTL_CMD_FAILOVER_CONTROL:
      failover_control( ctx, stem, slot_idx, payload, payload_sz );
      *charge_busy = 1;
      *opt_poll_in = 0;
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

static void
during_frag( fd_admin_tile_ctx_t * ctx,
             ulong                 in_idx,
             ulong                 seq FD_PARAM_UNUSED,
             ulong                 sig,
             ulong                 chunk,
             ulong                 sz,
             ulong                 ctl ) {
  if( FD_UNLIKELY( in_idx==ctx->failov_in_idx ) ) {
    if( FD_UNLIKELY( chunk<ctx->failov_in_chunk0 || chunk>ctx->failov_in_wmark || sz!=sizeof(fd_failover_bus_msg_t) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->failov_in_chunk0, ctx->failov_in_wmark ));
    }
    fd_memcpy( &ctx->failov_resp, fd_chunk_to_laddr_const( ctx->failov_in_mem, chunk ), sizeof(fd_failover_bus_msg_t) );
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
            ulong                 seq FD_PARAM_UNUSED,
            ulong                 sig,
            ulong                 sz FD_PARAM_UNUSED,
            ulong                 tsorig FD_PARAM_UNUSED,
            ulong                 tspub FD_PARAM_UNUSED,
            fd_stem_context_t *   stem ) {
  /* This link is unreliable, so only use the frame here in after_frag,
     once stem has confirmed it was not overrun. */
  if( FD_LIKELY( in_idx!=ctx->failov_in_idx ) ) return;
  if( FD_UNLIKELY( sig==FD_FAILOVER_BUS_SWITCH_REQ ) ) {
    failover_switch_request( ctx, stem );
    return;
  }
  if( FD_UNLIKELY( sig==FD_FAILOVER_BUS_SWITCH_QUERY ) ) {
    failover_switch_query( ctx, stem );
    return;
  }
  failover_status_response( ctx, sig );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  if( FD_UNLIKELY( tile->admin.failover_enabled ) ) {
    fd_admin_tile_ctx_t const * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
    populate_sock_filter_policy_fd_admin_tile_failover( out_cnt, out, (uint)fd_log_private_logfile_fd(),
                                                        (uint)ctx->failover_junk_key_fd, (uint)ctx->failover_staked_key_fd );
    return sock_filter_policy_fd_admin_tile_failover_instr_cnt;
  }
  populate_sock_filter_policy_fd_admin_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_admin_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  fd_admin_tile_ctx_t const * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  ulong need = 2UL + (ulong)(fd_log_private_logfile_fd()!=-1) + 2UL*(ulong)!!tile->admin.failover_enabled;
  if( FD_UNLIKELY( out_fds_cnt<need ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  if( FD_UNLIKELY( tile->admin.failover_enabled ) ) {
    out_fds[ out_cnt++ ] = ctx->failover_junk_key_fd;   /* preadd for a switch */
    out_fds[ out_cnt++ ] = ctx->failover_staked_key_fd;
  }
  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  ((long)1e6) /* 1ms */

#define STEM_CALLBACK_CONTEXT_TYPE  fd_admin_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_admin_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT after_credit
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
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
