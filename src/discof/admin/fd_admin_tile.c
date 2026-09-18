#include "../../disco/topo/fd_topo.h"
#include "../../disco/events/generated/fd_event_gen.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/keyguard/fd_keyload.h"

#include "fd_adminctl.h"
#include "../failover/fd_failover_bus.h"
#include <linux/futex.h>
#include "generated/fd_admin_tile_seccomp.h"

struct fd_admin_tile_ctx {
  fd_topo_t const * topo;
  fd_adminctl_t *   adminctl;
  uchar             identity_pubkey[ 32UL ];
  int               alpenglow;
  char const *      voter_name;         /* tile that produces votes: tower, or votor under Alpenglow */
  fd_keyswitch_t *  voter_av_keyswitch;
  fd_keyswitch_t *  txsend_av_keyswitch;
  fd_keyswitch_t *  sign_av_keyswitch[ FD_TOPO_MAX_TILES ];
  ulong             sign_av_keyswitch_cnt;
  fd_sha512_t       sha512[ 1 ];

  ulong replay_out_idx;           /* admin_replay stem out index */
  ulong snap_create_slot_idx;     /* adminctl slot of snapshot-create command */
  ulong snap_create_target_slot;  /* requested slot retained until Replay responds */
  ulong snap_create_start_time;   /* command start retained until Replay responds */

  int failover_enabled; /* failover moves the identity, set-identity is refused */

  /* Failover commands go to the failover tile over the bus, one at a
     time like snapshot creation. */
  ulong                 failov_out_idx;           /* admin_failov stem out index */
  fd_wksp_t *           failov_out_mem;
  ulong                 failov_out_chunk0;
  ulong                 failov_out_wmark;
  ulong                 failov_out_chunk;
  ulong                 failov_in_idx;            /* failov_admin stem in index */
  ulong                 in_cnt;                   /* stem ins, failov_admin is found among them */
  fd_wksp_t *           failov_in_mem;
  ulong                 failov_in_chunk0;
  ulong                 failov_in_wmark;
  fd_failover_bus_msg_t failov_in;                /* frame copied in during_frag */
  ulong                 failover_slot_idx;        /* adminctl slot parked on the bus, or ULONG_MAX */
  ulong                 failover_slot_cmd;        /* FD_ADMINCTL_FAILOVER_CMD_* */
  ulong                 failover_nonce;           /* nonce of the last command forwarded to the failover tile */
  ulong                 failover_answered;        /* nonce of the last command the failover tile responded to */
  ulong                 failover_start_time;      /* command start retained until the failover tile responds */
  long                  failover_deadline;        /* tickcount after which we report unresponsive */
  char                  failover_args_json[ 96 ]; /* the parked command and its flags for the event */
  ulong                 failover_args_json_len;
  char                  failover_cmd_cstr[ 48 ];  /* the parked command and its flags for the log, empty for status */
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

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void *                scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_admin_tile_ctx_t * ctx     = (fd_admin_tile_ctx_t *)scratch;
  fd_memset( ctx, 0, sizeof(fd_admin_tile_ctx_t) );

  if( FD_UNLIKELY( !strcmp( tile->admin.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  fd_memcpy( ctx->identity_pubkey, fd_keyload_load( tile->admin.identity_key_path, /* pubkey only: */ 1 ), 32UL );
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void *                scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  fd_admin_tile_ctx_t * ctx     = (fd_admin_tile_ctx_t *)scratch;
  ctx->replay_out_idx       = ULONG_MAX;
  ctx->snap_create_slot_idx = ULONG_MAX;
  ctx->failover_enabled     = fd_topo_find_tile( topo, "failov", 0UL )!=ULONG_MAX;
  ctx->failover_slot_idx    = ULONG_MAX;
  ctx->topo = topo;

  fd_topo_obj_t const * adminctl_obj = fd_topo_find_tile_obj( topo, tile, "adminctl" );
  FD_TEST( adminctl_obj );

  ctx->adminctl = fd_adminctl_join( fd_topo_obj_laddr( topo, adminctl_obj->id ) );
  FD_TEST( ctx->adminctl );

  ctx->replay_out_idx = fd_topo_find_tile_out_link( topo, tile, "admin_replay", 0UL );

  /* The failover bus links exist only when the failover tile does. */
  ctx->failov_out_idx = fd_topo_find_tile_out_link( topo, tile, "admin_failov", 0UL );
  ctx->failov_in_idx  = fd_topo_find_tile_in_link ( topo, tile, "failov_admin", 0UL );
  ctx->in_cnt         = tile->in_cnt;
  if( FD_UNLIKELY( (ctx->failov_out_idx==ULONG_MAX)!=(ctx->failov_in_idx==ULONG_MAX) ) ) {
    FD_LOG_ERR(( "admin tile needs both the admin_failov and failov_admin links or neither" ));
  }
  if( FD_UNLIKELY( ctx->failov_out_idx!=ULONG_MAX ) ) {
    fd_topo_link_t const * out_link = &topo->links[ tile->out_link_id[ ctx->failov_out_idx ] ];
    ctx->failov_out_mem    = topo->workspaces[ topo->objs[ out_link->dcache_obj_id ].wksp_id ].wksp;
    ctx->failov_out_chunk0 = fd_dcache_compact_chunk0( ctx->failov_out_mem, out_link->dcache );
    ctx->failov_out_wmark  = fd_dcache_compact_wmark ( ctx->failov_out_mem, out_link->dcache, out_link->mtu );
    ctx->failov_out_chunk  = ctx->failov_out_chunk0;

    fd_topo_link_t const * in_link = &topo->links[ tile->in_link_id[ ctx->failov_in_idx ] ];
    ctx->failov_in_mem    = topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ].wksp;
    ctx->failov_in_chunk0 = fd_dcache_compact_chunk0( ctx->failov_in_mem, in_link->dcache );
    ctx->failov_in_wmark  = fd_dcache_compact_wmark ( ctx->failov_in_mem, in_link->dcache, in_link->mtu );
  }

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    /* The stem numbers only the in links it polls, and we compare its
       numbers with topology in link indexes, so under failover every in
       link is polled. */
    if( FD_UNLIKELY( ctx->failov_in_idx!=ULONG_MAX ) ) FD_TEST( tile->in_link_poll[ i ] );
    if( FD_UNLIKELY( i==ctx->failov_in_idx ) ) continue;
    if( FD_UNLIKELY( strcmp( link->name, "replay_admin" ) ) ) {
      FD_LOG_ERR(( "unexpected input link name %s", link->name ));
    }
  }

  ulong voter_idx = fd_topo_find_tile( topo, "tower", 0UL );
  ctx->alpenglow  = voter_idx==ULONG_MAX;
  if( FD_UNLIKELY( ctx->alpenglow ) ) voter_idx = fd_topo_find_tile( topo, "votor", 0UL );
  FD_TEST( voter_idx!=ULONG_MAX );
  FD_TEST( topo->tiles[ voter_idx ].av_keyswitch_obj_id!=ULONG_MAX );
  ctx->voter_name         = topo->tiles[ voter_idx ].name;
  ctx->voter_av_keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, topo->tiles[ voter_idx ].av_keyswitch_obj_id ) );
  FD_TEST( ctx->voter_av_keyswitch );

  ulong txsend_idx = fd_topo_find_tile( topo, "txsend", 0UL );
  if( FD_LIKELY( txsend_idx!=ULONG_MAX ) ) {
    FD_TEST( topo->tiles[ txsend_idx ].av_keyswitch_obj_id!=ULONG_MAX );
    ctx->txsend_av_keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, topo->tiles[ txsend_idx ].av_keyswitch_obj_id ) );
    FD_TEST( ctx->txsend_av_keyswitch );
  } else {
    ctx->txsend_av_keyswitch = NULL;
  }

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

   If Alpenglow is active, Votor takes the place of Tower and Rotor
   takes the place of repair.  Votor/Tower will be referred to as the
   Voter tile for the purposes of the identity switch.

   The states follow, in order. */

/* State 0: UNLOCKED.
     The validator is not currently in the process of switching keys. */
#define FD_SET_IDENTITY_STATE_UNLOCKED                 (0UL)

/* State 1: LOCKED
     Some client to the validator has requested a key switch.  To do so,
     it acquired an exclusive lock on the validator to prevent the
     switch potentially being interleaved with another client. */
#define FD_SET_IDENTITY_STATE_LOCKED                   (1UL)

/* State 2: REPLAY_HALT_REQUESTED
     The first step in the key switch process is to pause Replay,
     preventing us from becoming leader or completing additional slots,
     but finishing any currently in progress leader slot if there is
     one.  Replay continues polling incoming links while paused so
     downstream tiles can drain without a reliable-link cycle.

     In Firedancer, this halt request goes to the Replay tile, which
     causes the tile to switch the identity key it uses to determine the
     identity's balance as well as when the validator is the leader.
     Replay reports the producer sequence of the link the voter reads
     (replay_out for tower, replay_slot for votor) as it switches. */
#define FD_SET_IDENTITY_STATE_REPLAY_HALT_REQUESTED    (2UL)

/* State 3: REPLAY_HALTED
     Replay has paused and the validator is no longer leader.  No more
     slots will complete until Replay is unhalted.  Replay has switched
     its own identity key and reported the voter's replay link sequence.

     At this point, we also have the guarantee that there are no more
     outstanding shreds that have to be signed with the old key.  Any
     tiles related to the leader pipeline that rely on the identity key
     will not be used. */
#define FD_SET_IDENTITY_STATE_REPLAY_HALTED            (3UL)

/* State 4: VOTER_HALT_REQUESTED
     Voter has been requested to consume its replay link through the
     sequence Replay reported, stop producing new vote transactions by
     backpressuring SLOT_COMPLETED, drain its local publish queue, and
     switch identity.  */
#define FD_SET_IDENTITY_STATE_VOTER_HALT_REQUESTED     (4UL)

/* State 5: VOTER_HALTED
     Voter has drained its pre-switch publish queue, switched identity,
     and reported the sequence after the final drained message.  If
     Alpenglow is active, there is no TxSend tile, so VOTER_HALTED will
     move straight to TXSEND_FLUSHED. */
#define FD_SET_IDENTITY_STATE_VOTER_HALTED             (5UL)

/* State 6: TXSEND_FLUSH_REQUESTED
     TxSend has been told the Tower sequence through which it must
     process messages before switching identity.  Gossip remains active
     in this state so it continues returning credits on tower_out and
     txsend_out. */
#define FD_SET_IDENTITY_STATE_TXSEND_FLUSH_REQUESTED   (6UL)

/* State 7: TXSEND_FLUSHED
     TxSend has processed all Tower messages through the halt sequence,
     switched its identity key, and stopped receiving Net fragments that
     could invoke QUIC signing callbacks.  TxSend also reported the
     sequence after its final txsend_out vote, which carries the old
     identity.  This state can also be reached right after VOTER_HALTED
     only if Alpenglow is active. */
#define FD_SET_IDENTITY_STATE_TXSEND_FLUSHED           (7UL)

/* State 8: SIGNERS_HALT_REQUESTED
     Repair, Gossip, Bundle, and Rserve will stop sending requests
     downstream to the sign tile.  This is done to avoid any mismatches
     with the identity key.  Their identity keys will be switched during
     this step, except for Gossip, which switches during
     SIGNERS_UNHALT_REQUESTED.

     These tiles use the identity key to populate messages signed by the
     sign tile:
       (a) Repair.  The repair tile uses the identity key as part of the
           repair protocol.  The identity key is included in and used
           for signing requests.  Because Repair uses an asynchronous
           signing mechanism, Repair will first wait until all
           outstanding sign requests have been received back from the
           sign tile before halting any new signing requests.
       (b) Gossip.  The gossip tile sends out ContactInfo messages with
           our identity key, and also uses the identity key to sign
           outgoing gossip messages.  Gossip first pushes the TxSend
           votes through the sequence TxSend reported, since the sign
           tile only signs them under the old key.
       (c) Bundle.  The bundle tile uses the identity key to sign an
           authentication challenge from the bundle server.
       (d) Rserve.  The rserve tile uses the identity key to sign
           outgoing pings.
       (e) Shred.  The shred tile has the sign tile sign FEC sets
           asynchronously; it waits for its outstanding requests to be
           answered under the old key before switching. */
#define FD_SET_IDENTITY_STATE_SIGNERS_HALT_REQUESTED   (8UL)

/* State 9: SIGNERS_HALTED
     Repair, Gossip, Bundle, and Rserve are no longer sending requests
     to the sign tile.  Tower and TxSend remain halted. */
#define FD_SET_IDENTITY_STATE_SIGNERS_HALTED           (9UL)

/* State 10: ALL_SWITCH_REQUESTED
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
#define FD_SET_IDENTITY_STATE_ALL_SWITCH_REQUESTED     (10UL)

/* State 11: ALL_SWITCHED
     All remaining tiles that use the identity key have confirmed that
     they have switched to the new key.  Gossip has not yet updated its
     identity key.  Repair, Gossip, Tower, TxSend, Bundle, and Rserve
     remain halted. */
#define FD_SET_IDENTITY_STATE_ALL_SWITCHED             (11UL)

/* State 12: SIGNERS_UNHALT_REQUESTED
     Now that the sign tile is using the switched identity key, the
     halted signers can be unhalted.  Gossip switches its identity key
     during this step.  These are the same tiles from
     SIGNERS_HALT_REQUESTED, along with Tower and TxSend. */
#define FD_SET_IDENTITY_STATE_SIGNERS_UNHALT_REQUESTED (12UL)

/* State 13: SIGNERS_UNHALTED
     All tiles that rely on the sign tile have been unhalted.  Replay
     remains paused. */
#define FD_SET_IDENTITY_STATE_SIGNERS_UNHALTED         (13UL)

/* State 14: REPLAY_UNHALT_REQUESTED
     The final state, now that all tiles have switched, Replay can be
     unpaused and the validator can resume processing and producing
     blocks.  The next state once Replay confirms it is unpaused is
     UNLOCKED. */
#define FD_SET_IDENTITY_STATE_REPLAY_UNHALT_REQUESTED  (14UL)

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
                   ulong                 identity_outset,
                   uchar *               keypair,
                   uchar const *         vote_history,
                   ulong                 vote_history_sz ) {
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
      *state = FD_SET_IDENTITY_STATE_REPLAY_HALT_REQUESTED;
      FD_LOG_INFO(( "Pausing Replay for key switch..." ));
      break;
    }
    case FD_SET_IDENTITY_STATE_REPLAY_HALT_REQUESTED: {
      fd_keyswitch_t * replay = find_identity_keyswitch( ctx, "replay" );
      if( FD_LIKELY( replay->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
        fd_memzero_explicit( replay->bytes, 64UL );
        FD_COMPILER_MFENCE();
        *state = FD_SET_IDENTITY_STATE_REPLAY_HALTED;
        FD_LOG_INFO(( "Replay successfully paused..." ));
      } else if( FD_UNLIKELY( replay->state==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
        FD_SPIN_PAUSE();
      } else {
        FD_LOG_ERR(( "Unexpected replay keyswitch state %lu", replay->state ));
      }
      break;
    }
    case FD_SET_IDENTITY_STATE_REPLAY_HALTED: {
      fd_keyswitch_t * replay = find_identity_keyswitch( ctx, "replay" );
      fd_keyswitch_t * voter  = find_identity_keyswitch( ctx, ctx->voter_name );
      voter->param = replay->result;
      memcpy( voter->bytes, keypair+32UL, 32UL );
      /* Copy in the vote history if one exists. */
      FD_TEST( 40UL+vote_history_sz<=sizeof(voter->bytes) );
      FD_STORE( ulong, voter->bytes+32UL, vote_history_sz );
      if( vote_history_sz ) memcpy( voter->bytes+40UL, vote_history, vote_history_sz );
      FD_COMPILER_MFENCE();
      voter->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
      FD_COMPILER_MFENCE();

      *state = FD_SET_IDENTITY_STATE_VOTER_HALT_REQUESTED;
      FD_LOG_INFO(( "Pausing %s and draining queued messages...", ctx->voter_name ));
      break;
    }
    case FD_SET_IDENTITY_STATE_VOTER_HALT_REQUESTED: {
      fd_keyswitch_t * voter = find_identity_keyswitch( ctx, ctx->voter_name );
      if( FD_LIKELY( voter->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
        fd_memzero_explicit( voter->bytes, 64UL );
        FD_COMPILER_MFENCE();
        *state = FD_SET_IDENTITY_STATE_VOTER_HALTED;
        FD_LOG_INFO(( "%s successfully paused...", ctx->voter_name ));
      } else if( FD_UNLIKELY( voter->state==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
        FD_SPIN_PAUSE();
      } else {
        FD_LOG_ERR(( "Unexpected %s keyswitch state %lu", ctx->voter_name, voter->state ));
      }
      break;
    }
    case FD_SET_IDENTITY_STATE_VOTER_HALTED: {
      if( FD_UNLIKELY( ctx->alpenglow ) ) {
        *state = FD_SET_IDENTITY_STATE_TXSEND_FLUSHED;
        break;
      }
      ulong tower_halted_seq = find_identity_keyswitch( ctx, "tower" )->result;
      fd_keyswitch_t * txsend = find_identity_keyswitch( ctx, "txsend" );
      txsend->param = tower_halted_seq;
      memcpy( txsend->bytes, keypair+32UL, 32UL );
      FD_COMPILER_MFENCE();
      txsend->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
      FD_COMPILER_MFENCE();

      *state = FD_SET_IDENTITY_STATE_TXSEND_FLUSH_REQUESTED;
      FD_LOG_INFO(( "Flushing old identity vote transactions from TxSend..." ));
      break;
    }
    case FD_SET_IDENTITY_STATE_TXSEND_FLUSH_REQUESTED: {
      fd_keyswitch_t * txsend = find_identity_keyswitch( ctx, "txsend" );
      if( FD_LIKELY( txsend->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
        fd_memzero_explicit( txsend->bytes, 64UL );
        FD_COMPILER_MFENCE();
        *state = FD_SET_IDENTITY_STATE_TXSEND_FLUSHED;
        FD_LOG_INFO(( "TxSend successfully flushed..." ));
      } else if( FD_UNLIKELY( txsend->state==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
        FD_SPIN_PAUSE();
      } else {
        FD_LOG_ERR(( "Unexpected txsend keyswitch state %lu", txsend->state ));
      }
      break;
    }
    case FD_SET_IDENTITY_STATE_TXSEND_FLUSHED: {
      ulong txsend_flushed_seq = ctx->alpenglow ? 0UL : find_identity_keyswitch( ctx, "txsend" )->result;
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &topo->tiles[ i ];
        if( FD_LIKELY( tile->id_keyswitch_obj_id==ULONG_MAX ) ) continue;
        if( strcmp( tile->name, "repair" ) &&
            strcmp( tile->name, "rotor" ) &&
            strcmp( tile->name, "gossip" ) &&
            strcmp( tile->name, "bundle" ) &&
            strcmp( tile->name, "rserve" ) &&
            strcmp( tile->name, "shred"  ) ) {
          continue;
        }

        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id );
        if( !strcmp( tile->name, "gossip" ) ) tile_ks->param = txsend_flushed_seq;
        if( !strcmp( tile->name, "shred"  ) ) tile_ks->param = 0UL; /* the leader pipeline is halted, nothing more to reach */
        memcpy( tile_ks->bytes, keypair+32UL, 32UL );
        FD_COMPILER_MFENCE();
        tile_ks->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
        FD_COMPILER_MFENCE();
      }
      *state = FD_SET_IDENTITY_STATE_SIGNERS_HALT_REQUESTED;
      FD_LOG_INFO(( "Requesting to halt remaining signers..." ));
      break;
    }
    case FD_SET_IDENTITY_STATE_SIGNERS_HALT_REQUESTED: {
      int all_switched = 1;
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &topo->tiles[ i ];
        if( FD_LIKELY( tile->id_keyswitch_obj_id==ULONG_MAX ) ) continue;
        if( strcmp( tile->name, "repair" ) &&
            strcmp( tile->name, "rotor" ) &&
            strcmp( tile->name, "gossip" ) &&
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
        FD_LOG_INFO(( "All remaining signers successfully halted..." ));
        *state = FD_SET_IDENTITY_STATE_SIGNERS_HALTED;
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    case FD_SET_IDENTITY_STATE_SIGNERS_HALTED: {
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &topo->tiles[ i ];
        if( strcmp( tile->name, "sign" ) ) continue;
        fd_keyswitch_t * sign = fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id );
        memcpy( sign->bytes, keypair, 64UL );
        if( FD_UNLIKELY( ctx->failover_enabled ) ) {
          /* Under failover the sign tile selects a keypair it loaded at
             boot by its public key. */
          sign->param = FD_KEYSWITCH_PARAM_IDENTITY_PUBKEY;
          fd_memcpy( sign->bytes,      keypair+32UL, 32UL );
          fd_memset( sign->bytes+32UL, 0,            32UL );
        }
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
                       !strcmp( tile->name, "rotor" ) ||
                       !strcmp( tile->name, "gossip" ) ||
                       !strcmp( tile->name, "txsend" ) ||
                       !strcmp( tile->name, "tower" ) ||
                       !strcmp( tile->name, "votor" ) ||
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
                       !strcmp( tile->name, "rotor"  ) ||
                       !strcmp( tile->name, "gossip" ) ||
                       !strcmp( tile->name, "txsend" ) ||
                       !strcmp( tile->name, "tower"  ) ||
                       !strcmp( tile->name, "votor"  ) ||
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
            strcmp( tile->name, "rotor" ) &&
            strcmp( tile->name, "gossip" ) &&
            strcmp( tile->name, "tower" ) &&
            strcmp( tile->name, "votor" ) &&
            strcmp( tile->name, "txsend" ) &&
            strcmp( tile->name, "bundle" ) &&
            strcmp( tile->name, "rserve" ) ) {
          continue;
        }

        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, tile->id_keyswitch_obj_id );
        if( !strcmp( tile->name, "gossip" ) ) tile_ks->param = identity_outset;
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
            strcmp( tile->name, "rotor" ) &&
            strcmp( tile->name, "gossip" ) &&
            strcmp( tile->name, "tower" ) &&
            strcmp( tile->name, "votor" ) &&
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
      FD_LOG_INFO(( "Requesting to unpause Replay..." ));
      *state = FD_SET_IDENTITY_STATE_REPLAY_UNHALT_REQUESTED;
      break;
    }
    case FD_SET_IDENTITY_STATE_REPLAY_UNHALT_REQUESTED: {
      fd_keyswitch_t * replay = find_identity_keyswitch( ctx, "replay" );
      if( FD_LIKELY( replay->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
        FD_LOG_INFO(( "Replay unpaused..." ));
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

  /* Under failover the failover tile moves the identity. */
  if( FD_UNLIKELY( ctx->failover_enabled ) ) {
    FD_LOG_WARNING(( "set-identity is not supported while [failover.enabled] is true" ));
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
  if( FD_UNLIKELY( req->vote_history_sz>sizeof(req->vote_history) ) ) {
    FD_LOG_WARNING(( "unexpected adminctl set-identity vote_history_sz %lu", req->vote_history_sz ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
    return;
  }

  fd_pubkey_t public_key;
  fd_ed25519_public_from_private( public_key.uc, req->keypair, ctx->sha512 );
  if( FD_UNLIKELY( memcmp( public_key.uc, req->keypair+32UL, 32UL ) ) ) {
    FD_LOG_WARNING(( "set-identity failed: public key in key file does not match private key" ));
    report_admin_command_custom_result( &event, "keypair_mismatch" );
    fd_adminctl_complete( adminctl, slot_idx, FD_SET_IDENTITY_RESULT_KEYPAIR_MISMATCH );
    return;
  }

  fd_tower_file_t tower_file;
  ulong           wait_to_vote_slot;
  uchar const *   vote_history    = NULL;
  ulong           vote_history_sz = 0UL;
  if( req->vote_history_sz ) {
    int err;
    if( ctx->alpenglow ) {
      err             = ag_vote_history_file_scan( req->vote_history, req->vote_history_sz, public_key.uc, &wait_to_vote_slot );
      vote_history    = (uchar const *)&wait_to_vote_slot;
      vote_history_sz = sizeof(ulong);
    } else {
      err             = fd_tower_file_de( req->vote_history, req->vote_history_sz, &public_key, &tower_file );
      vote_history    = (uchar const *)&tower_file;
      vote_history_sz = sizeof(fd_tower_file_t);
    }
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "set-identity failed: invalid vote history file (%i)", err ));
      report_admin_command_custom_result( &event, "invalid_vote_history" );
      fd_adminctl_complete( adminctl, slot_idx, FD_SET_IDENTITY_RESULT_INVALID_VOTE_HISTORY );
      return;
    }
  }

  ulong state           = FD_SET_IDENTITY_STATE_UNLOCKED;
  ulong identity_outset = (ulong)fd_log_wallclock();
  for(;;) {
    if( FD_UNLIKELY( poll_set_identity( ctx, &state, identity_outset, req->keypair, vote_history, vote_history_sz ) ) ) break;
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
   done carefully in order to prevent votes being generated with an
   authorized voter that the sign tile is not yet aware of.  The
   authorized voter must be added to the sign tile before it is added
   to the voter tile (the tower/votor tile).  All transitions must be
   linear and in forward order. */

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
   the sign tile is aware of the new authorized voter but the voter
   tile will not vote with the new authorized voter yet. */
#define FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_UPDATED    (3UL)

/* State 4: VOTER_TILE_REQUESTED
   Once the Sign tile is updated, now the voter tile must be notified
   that an authorized voter is being added so it can start voting with
   the new authorized voter. */
#define FD_ADD_AUTH_VOTER_STATE_VOTER_TILE_REQUESTED (4UL)

/* State 5: VOTER_TILE_UPDATED
   The voter tile has confirmed that it has updated its internal
   mapping for the set of supported authorized voters. */
#define FD_ADD_AUTH_VOTER_STATE_VOTER_TILE_UPDATED   (5UL)

/* State 6: UNLOCK_REQUESTED
   The client now requests that the voter tile unpause the pipeline
   so the validator can start producing votes with the new authorized
   voter. */
#define FD_ADD_AUTH_VOTER_STATE_UNLOCK_REQUESTED     (6UL)

static void FD_FN_SENSITIVE
poll_add_authorized_voter( fd_admin_tile_ctx_t * ctx,
                           ulong *               state,
                           uchar *               keypair,
                           ulong *               result ) {
  fd_keyswitch_t * voter = ctx->voter_av_keyswitch;

  switch( *state ) {
    case FD_ADD_AUTH_VOTER_STATE_UNLOCKED: {
      if( FD_LIKELY( FD_KEYSWITCH_STATE_UNLOCKED==FD_ATOMIC_CAS( &voter->state, FD_KEYSWITCH_STATE_UNLOCKED, FD_KEYSWITCH_STATE_LOCKED ) ) ) {
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
        if( FD_UNLIKELY( *result ) ) *state = FD_ADD_AUTH_VOTER_STATE_VOTER_TILE_UPDATED;
        else                         *state = FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_UPDATED;
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    case FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_UPDATED: {
      memcpy( voter->bytes, keypair+32UL, 32UL );
      voter->param = FD_KEYSWITCH_PARAM_AV_ADD;
      FD_COMPILER_MFENCE();
      voter->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
      FD_COMPILER_MFENCE();
      *state = FD_ADD_AUTH_VOTER_STATE_VOTER_TILE_REQUESTED;
      FD_LOG_INFO(( "Requesting %s tile to update authorized voter key set...", ctx->voter_name ));
      break;
    }
    case FD_ADD_AUTH_VOTER_STATE_VOTER_TILE_REQUESTED: {
      /* There is a guarantee that the voter tile will be in sync with
         the set of authorized voters in the sign tile.  At this point
         that means that the command should succeed because invariants
         such as not having duplicate authorized voter keys and too many
         authorized voters are upheld.  If this doesn't hold true, the
         voter tile will detect any corruption and gracefully crash the
         validator. */
      if( FD_LIKELY( voter->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
        *state = FD_ADD_AUTH_VOTER_STATE_VOTER_TILE_UPDATED;
        FD_LOG_INFO(( "%s tile key set successfully updated...", ctx->voter_name ));
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    case FD_ADD_AUTH_VOTER_STATE_VOTER_TILE_UPDATED: {
      voter->state = FD_KEYSWITCH_STATE_UNHALT_PENDING;
      *state       = FD_ADD_AUTH_VOTER_STATE_UNLOCK_REQUESTED;
      FD_LOG_INFO(( "Requesting an unlock of the authorized voter key set..." ));
      break;
    }
    case FD_ADD_AUTH_VOTER_STATE_UNLOCK_REQUESTED: {
      if( FD_LIKELY( voter->state==FD_KEYSWITCH_STATE_UNLOCKED ) ) {
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
    case FD_ADMINCTL_RESULT_UNSUPPORTED:
      report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_UNSUPPORTED );
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
   adding, the sign tile is updated before the voter tile (the tower
   tile, or the votor tile under Alpenglow) so that the voter never asks
   the sign tile to sign a vote with an authority index the sign tile
   does not yet know about.  When removing, the voter tile must be
   cleared before the sign tiles, so that the voter stops referencing an
   authorized voter index before the sign tile drops the corresponding
   key.

   Clearing the tower map prevents new vote transactions from
   referencing a removed voter, but transactions already published to
   TxSend may still do so.  The tower therefore reports its final output
   sequence after draining its local publish queue.  TxSend processes
   every tower message through that sequence and synchronously waits for
   each signing response before acknowledging the drain.  Only then is
   it safe to clear the sign tiles.  All transitions are linear and in
   forward order.

   Unlike add-authorized-voter, removal cannot fail on the tile side: it
   is unconditional and idempotent (clearing an empty set succeeds).

   Under Alpenglow the votor's votes are not sent through TxSend, and it
   signs synchronously, so it has no signing requests in flight once it
   confirms the clear.  The TxSend drain is skipped. */

/* State 0: UNLOCKED
   The validator is not currently in the process of switching keys. */
#define FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCKED               (0UL)

/* State 1: LOCKED
   Some client to the validator has requested to remove all authorized
   voters.  To do so, it acquired an exclusive lock on the validator to
   prevent the removal potentially being interleaved with another
   client. */
#define FD_REMOVE_ALL_AUTH_VOTERS_STATE_LOCKED                 (1UL)

/* State 2: VOTER_TILE_REQUESTED
   The voter tile has been notified to clear its authorized voter set.
   It is cleared first so it stops voting with any authorized voter
   before the sign tiles drop the keys. */
#define FD_REMOVE_ALL_AUTH_VOTERS_STATE_VOTER_TILE_REQUESTED   (2UL)

/* State 3: VOTER_TILE_CLEARED
   The voter tile confirmed it cleared its authorized voter map.  At
   this point the validator will only prepare votes signed by the
   identity key. */
#define FD_REMOVE_ALL_AUTH_VOTERS_STATE_VOTER_TILE_CLEARED     (3UL)

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
   The client requests that the voter tile release the lock. */
#define FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCK_REQUESTED       (8UL)

static void
poll_remove_all_authorized_voters( fd_admin_tile_ctx_t * ctx,
                                   ulong *               state ) {
  fd_keyswitch_t * voter = ctx->voter_av_keyswitch;

  switch( *state ) {
    case FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCKED: {
      if( FD_LIKELY( FD_KEYSWITCH_STATE_UNLOCKED==FD_ATOMIC_CAS( &voter->state, FD_KEYSWITCH_STATE_UNLOCKED, FD_KEYSWITCH_STATE_LOCKED ) ) ) {
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
      voter->param = FD_KEYSWITCH_PARAM_AV_CLEAR;
      FD_COMPILER_MFENCE();
      voter->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
      FD_COMPILER_MFENCE();
      *state = FD_REMOVE_ALL_AUTH_VOTERS_STATE_VOTER_TILE_REQUESTED;
      FD_LOG_INFO(( "Requesting %s tile to clear authorized voter key set...", ctx->voter_name ));
      break;
    }
    case FD_REMOVE_ALL_AUTH_VOTERS_STATE_VOTER_TILE_REQUESTED: {
      if( FD_LIKELY( voter->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
        *state = FD_REMOVE_ALL_AUTH_VOTERS_STATE_VOTER_TILE_CLEARED;
        FD_LOG_INFO(( "%s tile authorized voter key set cleared...", ctx->voter_name ));
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    case FD_REMOVE_ALL_AUTH_VOTERS_STATE_VOTER_TILE_CLEARED: {
      if( FD_UNLIKELY( ctx->alpenglow ) ) {
        *state = FD_REMOVE_ALL_AUTH_VOTERS_STATE_TXSEND_FLUSHED;
        break;
      }
      fd_keyswitch_t * txsend = ctx->txsend_av_keyswitch;
      FD_COMPILER_MFENCE();
      txsend->param = voter->result;
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
      voter->state = FD_KEYSWITCH_STATE_UNHALT_PENDING;
      *state       = FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCK_REQUESTED;
      FD_LOG_INFO(( "Requesting an unlock of the authorized voter key set..." ));
      break;
    }
    case FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCK_REQUESTED: {
      if( FD_LIKELY( voter->state==FD_KEYSWITCH_STATE_UNLOCKED ) ) {
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

  ulong state = FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCKED;
  for(;;) {
    poll_remove_all_authorized_voters( ctx, &state );
    if( FD_UNLIKELY( state==FD_REMOVE_ALL_AUTH_VOTERS_STATE_UNLOCKED ) ) break;
  }

  report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_SUCCESS );
  fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_SUCCESS );
}

/* The failover tile responds to commands.  We check the
   ABI, forward the command over the bus and park the adminctl slot
   until the response comes back or the deadline passes, like snapshot
   creation waits on replay. */

static fd_event_admin_command_t *
failover_event_args( fd_admin_tile_ctx_t const * ctx,
                     fd_event_admin_command_t *  event ) {
  if( FD_LIKELY( ctx->failover_args_json_len ) ) {
    fd_memcpy( event->args_json, ctx->failover_args_json, ctx->failover_args_json_len );
    event->args_json_len = ctx->failover_args_json_len;
  }
  return event;
}

/* failover_result_name is the event's custom result for a failover
   command that did not succeed. */
static char const *
failover_result_name( ulong result ) {
  switch( result ) {
    case FD_FAILOVER_CONTROL_RESULT_BUSY:              return "busy";
    case FD_FAILOVER_CONTROL_RESULT_UNRESPONSIVE:      return "unresponsive";
    case FD_FAILOVER_CONTROL_RESULT_BAD_ROLE:          return "bad_role";
    case FD_FAILOVER_CONTROL_RESULT_IN_PROGRESS:       return "in_progress";
    case FD_FAILOVER_CONTROL_RESULT_PEER_UNREADY:      return "peer_unready";
    case FD_FAILOVER_CONTROL_RESULT_PEER_UNVERIFIED:   return "peer_unverified";
    case FD_FAILOVER_CONTROL_RESULT_PEER_ACTIVE:       return "peer_active";
    case FD_FAILOVER_CONTROL_RESULT_HANDOFF_PENDING:   return "handoff_pending";
    case FD_FAILOVER_CONTROL_RESULT_TAKEN:             return "taken";
    case FD_FAILOVER_CONTROL_RESULT_STAKED_SEEN:       return "staked_seen";
    case FD_FAILOVER_CONTROL_RESULT_NO_FINAL_TOWER:    return "no_final_tower";
    case FD_FAILOVER_CONTROL_RESULT_REPLAY_BEHIND:     return "replay_behind";
    case FD_FAILOVER_CONTROL_RESULT_NO_ACTIVE_ADDRESS: return "no_active_address";
    default:                                           return "refused";
  }
}

static void
failover_complete( fd_admin_tile_ctx_t * ctx,
                   ulong                 result,
                   void const *          resp,
                   ulong                 resp_sz ) {
  fd_event_admin_command_t event = {
    .type                = FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER,
    .args_json           = { '{', '}' },
    .args_json_len       = 2UL,
    .start_time          = ctx->failover_start_time,
    .payload_version     = FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION,
    .has_payload_version = 1,
    .payload_size        = sizeof(fd_adminctl_failover_req_t),
  };
  switch( result ) {
    case FD_ADMINCTL_RESULT_SUCCESS:
      report_admin_command( failover_event_args( ctx, &event ), FD_EVENT_ADMIN_COMMAND_RESULT_SUCCESS );
      break;
    case FD_FAILOVER_CONTROL_RESULT_UNRESPONSIVE:
      report_admin_command_custom_result( failover_event_args( ctx, &event ), "unresponsive" );
      break;
    default:
      report_admin_command_custom_result( failover_event_args( ctx, &event ), failover_result_name( result ) );
      break;
  }
  fd_adminctl_complete_response( ctx->adminctl, ctx->failover_slot_idx, result, resp, resp_sz );
  if( FD_LIKELY( ctx->failover_cmd_cstr[ 0 ] ) ) {
    if( FD_LIKELY( result==FD_ADMINCTL_RESULT_SUCCESS ) ) {
      FD_LOG_NOTICE(( "`failover %s` accepted by the failover tile, follow it with `failover status`", ctx->failover_cmd_cstr ));
    } else if( FD_UNLIKELY( result!=FD_FAILOVER_CONTROL_RESULT_UNRESPONSIVE ) ) {
      FD_LOG_WARNING(( "`failover %s` refused by the failover tile (%s), nothing was done, the command prints the reason", ctx->failover_cmd_cstr, failover_result_name( result ) ));
    }
  }
  ctx->failover_slot_idx      = ULONG_MAX;
  ctx->failover_start_time    = 0UL;
  ctx->failover_deadline      = 0L;
  ctx->failover_args_json_len = 0UL;
  ctx->failover_cmd_cstr[ 0 ] = '\0';
}

static void
failover_request( fd_admin_tile_ctx_t * ctx,
                  fd_stem_context_t *   stem,
                  ulong                 slot_idx,
                  void const *          data,
                  ulong                 data_sz ) {

  fd_adminctl_t *          adminctl = ctx->adminctl;
  fd_event_admin_command_t event    = prepare_admin_command( FD_EVENT_ADMIN_COMMAND_TYPE_FAILOVER, data, data_sz );

  if( FD_UNLIKELY( data_sz<sizeof(ulong) ) ) {
    FD_LOG_WARNING(( "adminctl failover payload too small: %lu", data_sz ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
    return;
  }

  ulong version = FD_LOAD( ulong, data );
  if( FD_UNLIKELY( version!=FD_ADMINCTL_FAILOVER_PAYLOAD_VERSION ) ) {
    FD_LOG_WARNING(( "unsupported adminctl failover payload version %lu", version ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_VERSION_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_VERSION_MISMATCH );
    return;
  }

  if( FD_UNLIKELY( data_sz!=sizeof(fd_adminctl_failover_req_t) ) ) {
    FD_LOG_WARNING(( "unexpected adminctl failover payload_sz %lu", data_sz ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_ABI_SIZE_MISMATCH );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_ABI_SIZE_MISMATCH );
    return;
  }

  fd_adminctl_failover_req_t req;
  fd_memcpy( &req, data, sizeof(req) );
  int force = !!(req.flags & FD_ADMINCTL_FAILOVER_FLAG_FORCE);
  char const * invalid = NULL;
  if(      req.cmd>=FD_ADMINCTL_FAILOVER_CMD_CNT )                                      invalid = "unknown command";
  else if( req.flags & ~(FD_ADMINCTL_FAILOVER_FLAG_YES|FD_ADMINCTL_FAILOVER_FLAG_FORCE) ) invalid = "unknown flags";
  else if( (req.cmd==FD_ADMINCTL_FAILOVER_CMD_PROMOTE)!=force )                         invalid = "--force goes with promote, and a promote without it is sent as a handoff";
  else if( req.cmd==FD_ADMINCTL_FAILOVER_CMD_STATUS && req.flags )                      invalid = "status takes no flags";
  else if( req.cmd!=FD_ADMINCTL_FAILOVER_CMD_HANDOFF && (req.addr || req.port) )        invalid = "an address or port goes only with a handoff";
  else if( req.reserved[ 0 ] || req.reserved[ 1 ] )                                     invalid = "reserved bytes are set";
  if( FD_UNLIKELY( invalid ) ) {
    FD_LOG_WARNING(( "refusing adminctl failover cmd %lu flags %lu, %s", req.cmd, req.flags, invalid ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_UNKNOWN_COMMAND );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_UNKNOWN_COMMAND );
    return;
  }
  int status = req.cmd==FD_ADMINCTL_FAILOVER_CMD_STATUS;
  if( status ) {
    FD_TEST( fd_cstr_printf_check( (char *)event.args_json, sizeof(event.args_json), &event.args_json_len,
                                   "{\"command\":\"status\"}" ) );
  } else {
    FD_TEST( fd_cstr_printf_check( (char *)event.args_json, sizeof(event.args_json), &event.args_json_len,
                                   "{\"command\":\"%s\",\"yes\":%s,\"force\":%s}", fd_adminctl_failover_cmd_name( req.cmd ),
                                   (req.flags & FD_ADMINCTL_FAILOVER_FLAG_YES) ? "true" : "false",
                                   force                                       ? "true" : "false" ) );
  }
  char cmd_cstr[ 48 ];
  FD_TEST( fd_cstr_printf_check( cmd_cstr, sizeof(cmd_cstr), NULL, "%s%s%s", fd_adminctl_failover_cmd_typed( req.cmd ),
                                 (req.flags & FD_ADMINCTL_FAILOVER_FLAG_YES) ? " --yes"   : "",
                                 force                                       ? " --force" : "" ) );

  if( FD_UNLIKELY( ctx->failov_out_idx==ULONG_MAX ) ) {
    FD_LOG_WARNING(( "`failover %s` refused, the admin tile has no failover bus link", cmd_cstr ));
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_UNSUPPORTED );
    fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_UNSUPPORTED );
    return;
  }

  /* One command at a time.  A command stays outstanding until the
     failover tile responds, even after its deadline, so commands cannot
     pile up behind a stalled failover tile.  Status then reports the
     failover tile unresponsive rather than busy. */
  if( FD_UNLIKELY( ctx->failover_answered!=ctx->failover_nonce ) ) {
    if( FD_UNLIKELY( status && ctx->failover_slot_idx==ULONG_MAX ) ) {
      FD_LOG_WARNING(( "`failover status` refused, the failover tile has not responded to an earlier command, check the log" ));
      report_admin_command_custom_result( &event, "unresponsive" );
      fd_adminctl_complete( adminctl, slot_idx, FD_FAILOVER_CONTROL_RESULT_UNRESPONSIVE );
      return;
    }
    FD_LOG_WARNING(( "`failover %s` refused, another failover command is still waiting on the failover tile, try again", cmd_cstr ));
    report_admin_command_custom_result( &event, "busy" );
    fd_adminctl_complete( adminctl, slot_idx, FD_FAILOVER_CONTROL_RESULT_BUSY );
    return;
  }

  /* Kept for the event and the log of the response. */
  FD_TEST( event.args_json_len<=sizeof(ctx->failover_args_json) );
  fd_memcpy( ctx->failover_args_json, event.args_json, event.args_json_len );
  ctx->failover_args_json_len = event.args_json_len;
  if( status ) ctx->failover_cmd_cstr[ 0 ] = '\0';
  else {
    fd_cstr_ncpy( ctx->failover_cmd_cstr, cmd_cstr, sizeof(ctx->failover_cmd_cstr) );
    FD_LOG_NOTICE(( "forwarding `failover %s` to the failover tile", cmd_cstr ));
  }

  fd_failover_bus_msg_t * msg = fd_chunk_to_laddr( ctx->failov_out_mem, ctx->failov_out_chunk );
  fd_memset( msg, 0, sizeof(*msg) );
  msg->nonce = ++ctx->failover_nonce;
  fd_memcpy( msg->payload, &req, sizeof(req) );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->failov_out_idx, FD_FAILOVER_BUS_REQUEST, ctx->failov_out_chunk, sizeof(*msg), 0UL, tspub, tspub );
  ctx->failov_out_chunk = fd_dcache_compact_next( ctx->failov_out_chunk, sizeof(*msg), ctx->failov_out_chunk0, ctx->failov_out_wmark );

  ctx->failover_slot_idx   = slot_idx;
  ctx->failover_slot_cmd   = req.cmd;
  ctx->failover_start_time = event.start_time;
  ctx->failover_deadline   = fd_tickcount() + (long)( (double)FD_FAILOVER_BUS_DEADLINE_NANOS*fd_tempo_tick_per_ns( NULL ) );
}

static void
failover_response( fd_admin_tile_ctx_t * ctx ) {
  fd_failover_bus_msg_t const * msg = &ctx->failov_in;
  /* Even a late response means the last command is no longer outstanding. */
  if( FD_LIKELY( msg->nonce==ctx->failover_nonce ) ) ctx->failover_answered = msg->nonce;
  /* A response for an older command, or one after the deadline already
     answered the operator, is dropped. */
  if( FD_UNLIKELY( ctx->failover_slot_idx==ULONG_MAX || msg->nonce!=ctx->failover_nonce ) ) {
    FD_LOG_WARNING(( "dropping a stale failover command response" ));
    return;
  }
  /* Status and command responses each have their own payload. */
  ulong resp_sz = ctx->failover_slot_cmd==FD_ADMINCTL_FAILOVER_CMD_STATUS ? sizeof(fd_adminctl_failover_status_resp_t)
                                                                       : sizeof(fd_adminctl_failover_control_resp_t);
  failover_complete( ctx, msg->result, msg->payload, resp_sz );
}

/* The failover tile asked for an identity switch.  We only pass the
   public key on, the sign tile selects the keypair it loaded at boot.
   Like set-identity this blocks until every tile has switched.  We poll
   no adminctl command meanwhile, so `failover status` and every failover
   command wait for it, and hang behind a switch that never finishes. */

static void
failover_switch_request( fd_admin_tile_ctx_t * ctx,
                         fd_stem_context_t *   stem ) {
  ulong                    nonce = ctx->failov_in.nonce;
  fd_failover_switch_req_t req;
  fd_memcpy( &req, ctx->failov_in.payload, sizeof(req) );

  fd_failover_switch_resp_t response;
  fd_memset( &response, 0, sizeof(response) );
  response.result = FD_FAILOVER_SWITCH_ERR_DISABLED;
  if( FD_LIKELY( ctx->failover_enabled ) ) {
    /* Reported like set-identity, with the identity we move to and a
       source that tells it from an operator's set-identity. */
    fd_event_admin_command_t event = prepare_admin_command( FD_EVENT_ADMIN_COMMAND_TYPE_SET_IDENTITY, NULL, 0UL );
    FD_BASE58_ENCODE_32_BYTES( ctx->identity_pubkey, old_identity );
    FD_BASE58_ENCODE_32_BYTES( req.identity,         new_identity );
    FD_TEST( fd_cstr_printf_check( (char *)event.args_json, sizeof(event.args_json), &event.args_json_len,
                                   "{\"old_identity\":\"%s\",\"identity\":\"%s\",\"source\":\"failover\"}", old_identity, new_identity ) );
    FD_LOG_NOTICE(( "failover: switching the identity from `%s` to `%s`, failover commands wait until every tile has switched", old_identity, new_identity ));

    /* No private half, only the public key reaches the keyswitches. */
    uchar keypair[ 64 ];
    fd_memset( keypair,      0,            32UL );
    fd_memcpy( keypair+32UL, req.identity, 32UL );

    ulong state           = FD_SET_IDENTITY_STATE_UNLOCKED;
    ulong identity_outset = (ulong)fd_log_wallclock();
    for(;;) {
      if( FD_UNLIKELY( poll_set_identity( ctx, &state, identity_outset, keypair, NULL, 0UL ) ) ) break;
    }
    fd_memcpy( ctx->identity_pubkey, req.identity, 32UL );

    /* The watermark is the tower's output sequence at its halt, which
       the tower tile leaves in its keyswitch result. */
    response.result          = FD_FAILOVER_SWITCH_OK;
    response.tower_watermark = find_identity_keyswitch( ctx, "tower" )->result;
    report_admin_command( &event, FD_EVENT_ADMIN_COMMAND_RESULT_SUCCESS );
    FD_LOG_NOTICE(( "failover: every tile switched to `%s`, the tower halted signing at sequence %lu", new_identity, response.tower_watermark ));
  } else {
    FD_LOG_WARNING(( "the failover tile asked for an identity switch but failover is off, refusing" ));
  }

  fd_failover_bus_msg_t * out = fd_chunk_to_laddr( ctx->failov_out_mem, ctx->failov_out_chunk );
  fd_memset( out, 0, sizeof(*out) );
  out->nonce  = nonce;
  fd_memcpy( out->payload, &response, sizeof(response) );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->failov_out_idx, FD_FAILOVER_BUS_SWITCH_RESP, ctx->failov_out_chunk, sizeof(*out), 0UL, tspub, tspub );
  ctx->failov_out_chunk = fd_dcache_compact_next( ctx->failov_out_chunk, sizeof(*out), ctx->failov_out_chunk0, ctx->failov_out_wmark );
}

/* Whether a frag waits on failov_admin, the check the stem makes before
   it parks.  The stem reads it only after after_credit, and while we
   were blocked in an identity switch the response to a parked command may
   have arrived there. */

static int
failov_frag_waiting( fd_admin_tile_ctx_t const * ctx,
                     fd_stem_context_t const *   stem ) {
  for( ulong i=0UL; i<ctx->in_cnt; i++ ) {
    fd_stem_tile_in_t const * in = &stem->in[ i ];
    if( FD_LIKELY( (ulong)in->idx==ctx->failov_in_idx ) ) return fd_seq_diff( in->seq, fd_frag_meta_seq_query( in->mline ) )<=0L;
  }
  return 0;
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

  /* A response already waiting is read before the deadline counts. */
  if( FD_UNLIKELY( ctx->failover_slot_idx!=ULONG_MAX && fd_tickcount()>ctx->failover_deadline &&
                   !failov_frag_waiting( ctx, stem ) ) ) {
    if( FD_LIKELY( ctx->failover_cmd_cstr[ 0 ] ) ) FD_LOG_WARNING(( "the failover tile did not answer `failover %s` in time, it may still run, check `failover status` and the log", ctx->failover_cmd_cstr ));
    else                                           FD_LOG_WARNING(( "the failover tile did not answer `failover status` in time, check the log" ));
    failover_complete( ctx, FD_FAILOVER_CONTROL_RESULT_UNRESPONSIVE, NULL, 0UL );
    *charge_busy = 1;
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
    case FD_ADMINCTL_CMD_SNAP_CREATE:
      snapshot_create( ctx, stem, slot_idx, payload, payload_sz );
      *charge_busy = 1;
      *opt_poll_in = 0;
      break;
    case FD_ADMINCTL_CMD_FAILOVER:
      if( FD_UNLIKELY( ctx->failover_enabled ) ) {
        failover_request( ctx, stem, slot_idx, payload, payload_sz );
        *charge_busy = 1;
        *opt_poll_in = 0;
        break;
      }
      __attribute__((fallthrough)); /* without failover, upstream's unknown command answer */
    default:
      FD_LOG_WARNING(( "unexpected adminctl cmd %lu", cmd_id ));
      fd_adminctl_complete( adminctl, slot_idx, FD_ADMINCTL_RESULT_UNKNOWN_COMMAND );
  }
}

static void
during_frag( fd_admin_tile_ctx_t * ctx,
             ulong                 in_idx FD_PARAM_UNUSED,
             ulong                 seq FD_PARAM_UNUSED,
             ulong                 sig,
             ulong                 chunk FD_PARAM_UNUSED,
             ulong                 sz FD_PARAM_UNUSED,
             ulong                 ctl ) {
  if( FD_UNLIKELY( in_idx==ctx->failov_in_idx ) ) {
    if( FD_UNLIKELY( chunk<ctx->failov_in_chunk0 || chunk>ctx->failov_in_wmark || sz!=sizeof(fd_failover_bus_msg_t) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->failov_in_chunk0, ctx->failov_in_wmark ));
    }
    fd_memcpy( &ctx->failov_in, fd_chunk_to_laddr_const( ctx->failov_in_mem, chunk ), sizeof(fd_failover_bus_msg_t) );
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
  if( FD_LIKELY( in_idx!=ctx->failov_in_idx ) ) return;
  switch( sig ) {
    case FD_FAILOVER_BUS_SWITCH_REQ:
      failover_switch_request( ctx, stem );
      break;
    case FD_FAILOVER_BUS_RESPONSE:
      failover_response( ctx );
      break;
    default:
      FD_LOG_WARNING(( "unexpected failover bus frame %lu", sig ));
      break;
  }
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {

  populate_sock_filter_policy_fd_admin_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_admin_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
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
