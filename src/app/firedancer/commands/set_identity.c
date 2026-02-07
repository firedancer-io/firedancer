#define _GNU_SOURCE
#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"

#include <stdlib.h>
#include <unistd.h>
#include "../../platform/fd_cap_chk.h"
#include "../../../disco/keyguard/fd_keyswitch.h"
#include "../../../disco/keyguard/fd_keyload.h"
#include "../../../disco/topo/fd_topo.h"

#include <strings.h>
#include <unistd.h>
#include <sys/resource.h>

/* The process of switching identity of the validator is somewhat
   involved, to prevent it from producing torn data (for example,
   a block where half the shreds are signed by one private key, and half
   are signed by another).

   The process of switching is a state machine that progresses linearly
   through each of the states.  Generally, no transitions are allowed
   except direct forward steps, except in emergency recovery cases an
   operator can force the state back to unlocked.

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

/* State 4: REPLAY_HALT_REQUESTED
     Repair, Gossip, and Tower tiles will stop sending requests
     downstream to the sign tile.  This is done to avoid any mismatches
     with the identity key.  Their identity keys will be switched after
     this step.  These tiles all use the identity key to make forward
     progress on non-leader pipeline replay.

     These tiles use the identity key to populate messages which are
     signed by the sign tile:
       (a) Repair.  The repair tile uses the identity key as part of the
           repair protocol.  The identity key is included in and used
           for signing requests.  Because Repair uses an asnychronous
           signing mechanism, Repair will first wait until all
           outstanding sign requests have been received back from the
           sign tile before halting any new signing requests.
       (b) Gossip.  The gossip tile sends out ContactInfo messages with
           our identity key, and also uses the identity key to sign
           outgoing gossip messages.
           FIXME: Gossip keyswitch transition is buggy and may need to
           be coordinated with gossvf.
       (c) Tower.  The tower tiles uses the identity key to generate
           vote transactions which are sent to the send tile.  These
           vote transactions are then signed downstream by the Send tile
           instead of having its own keyguard client. */
#define FD_SET_IDENTITY_STATE_REPLAY_HALT_REQUESTED    (4UL)

/* State 5: REPLAY_HALTED
     Repair, Gossip, and Tower are no longer sending requests to the
     sign tile.  Replay can keep progressing at this point. However,
     the tower tile may have an in-flight vote transaction to the Send
     tile that corresponds to the old identity key. */
#define FD_SET_IDENTITY_STATE_REPLAY_HALTED            (5UL)

/* State 6: SEND_FLUSH_REQUESTED
     Once the Tower tile has updated its identity key and stopped
     sending vote transactions to the Send tile, any in-flight vote
     transactions for the old identity key must be flushed to avoid
     being badly signed.  We also know that Tower will send no more
     vote transactions to the Send tile.

     The Send tile is flushed by telling it the last sequence number the
     Tower tile has produced for an outgoing vote tansaction at the time
     it was halted.  Once the Send tile has processed all vote
     transactions up to and including that sequence number, it will
     switch it's own identity key.  There is a guarantee that the Send
     tile will not request to sign any vote transactions until it is
     unhalted. */
#define FD_SET_IDENTITY_STATE_SEND_FLUSH_REQUESTED     (6UL)

/* State 7: SEND_FLUSHED
     The Send tile confirms that it has seen and processed all votes
     up to and including the last sequence number produced by the Tower
     tile at the time it was halted.  The Send tile also switches its
     own identity key which is used for signing votes and establishing
     a QUIC connection. */
#define FD_SET_IDENTITY_STATE_SEND_FLUSHED             (7UL)

/* State 8: ALL_SWITCH_REQUESTED
     The client now requests that all other tiles which consume the
     identity key in some way switch to the new key.  The leader
     pipeline is still halted, although it doesn't strictly need to be,
     since outgoing shreds have been flushed.  This is done to keep the
     control flow simpler.  The sign tile is switched first to avoid any
     potential mismatches with the identity key.

     The other tiles using the identity key are:
       (a) Sign.  The sign tile is responsible for holding the private
           key and servicing signing requests from other tiles.
       (b) GUI.  The GUI shows the validator identity key to the user,
           and uses the key to determine which blocks are ours for
           highlighting on the frontend.
       (c) Bundle.  The validator must authenticate to any connected
           bundle server with the identity key to prove it is on the
           leader schedule.
       (d) Gossvf.  The gossvf tile uses the identity key to detect
           duplicate running instances of the same validator node as
           well as other message handling.
       (e) Shred.  The shred tile uses the identity key to determine the
           position of the validator in the Turbine tree and to sign
           outgoing shreds.
       (f) Event.  Outgoing events to the event server are signed with
           the identity key to authenticate the sender. */

#define FD_SET_IDENTITY_STATE_ALL_SWITCH_REQUESTED     (8UL)

/* State 9: ALL_SWITCHED
     All remaining tiles that use the identity key have confirmed that
     they have switched to the new key.  The validator is now fully
     switched over. */
#define FD_SET_IDENTITY_STATE_ALL_SWITCHED             (9UL)

/* State 10: REPLAY_UNHALT_REQUESTED
     Now that all of the tiles are using the switched identity key, the
     tiles that rely on the sign tile can be unhalted.  These are the
     same tiles from REPLAY_HALT_REQUESTED. */
#define FD_SET_IDENTITY_STATE_REPLAY_UNHALT_REQUESTED (10UL)

/* State 11: REPLAY_UNHALTED
     All tiles that rely on the sign tile have been unhalted and now the
     validator can resume making progress on replay. */
#define FD_SET_IDENTITY_STATE_REPLAY_UNHALTED          (11UL)

/* State 12: LEADER_UNHALT_REQUESTED
     The final state, now that all tiles have switched, the leader
     pipeline can be unblocked and the validator can resume producing
     blocks.  The next state once the Replay tile confirms the leader
     pipeline is unlocked, is UNLOCKED. */
#define FD_SET_IDENTITY_STATE_LEADER_UNHALT_REQUESTED  (12UL)

void
set_identity_cmd_perm( args_t *         args   FD_PARAM_UNUSED,
                       fd_cap_chk_t *   chk,
                       config_t const * config FD_PARAM_UNUSED ) {
  /* 5 huge pages for the key storage area */
  ulong mlock_limit = 5UL * FD_SHMEM_NORMAL_PAGE_SZ;
  fd_cap_chk_raise_rlimit( chk, "set-identity", RLIMIT_MEMLOCK, mlock_limit, "call `rlimit(2)` to increase `RLIMIT_MEMLOCK` so all memory can be locked with `mlock(2)`" );
}

static fd_keyswitch_t *
find_keyswitch( fd_topo_t const * topo,
                char const *      tile_name ) {
  ulong tile_idx = fd_topo_find_tile( topo, tile_name, 0UL );
  FD_TEST( tile_idx!=ULONG_MAX );
  FD_TEST( topo->tiles[ tile_idx ].keyswitch_obj_id!=ULONG_MAX );

  fd_keyswitch_t * keyswitch = fd_topo_obj_laddr( topo, topo->tiles[ tile_idx ].keyswitch_obj_id );
  FD_TEST( keyswitch );
  return keyswitch;
}

static void FD_FN_SENSITIVE
poll_keyswitch( fd_topo_t * topo,
                ulong *     state,
                ulong *     halted_seq,
                uchar *     keypair,
                int         require_tower,
                int         force_lock ) {
  switch( *state ) {
    case FD_SET_IDENTITY_STATE_UNLOCKED: {
      /* First update replay's keyswitch from unlocked to locked. */
      fd_keyswitch_t * replay = find_keyswitch( topo, "replay" );
      if( FD_LIKELY( FD_KEYSWITCH_STATE_UNLOCKED==FD_ATOMIC_CAS( &replay->state, FD_KEYSWITCH_STATE_UNLOCKED, FD_KEYSWITCH_STATE_LOCKED ) ) ) {
        *state = FD_SET_IDENTITY_STATE_LOCKED;
        FD_LOG_INFO(( "Locking validator identity for key switch..." ));
      } else {
        if( FD_UNLIKELY( force_lock ) ) {
          *state = FD_SET_IDENTITY_STATE_LOCKED;
          FD_LOG_WARNING(( "Another process was changing keys, but `--force` supplied. Forcing lock on validator identity for key switch..." ));
        } else {
          FD_LOG_ERR(( "Cannot set-identity because Firedancer is already in the process of switching keys. If you are not currently "
                       "changing the identity, it might be because an identity change was abandoned. To recover, run the `set-identity` "
                       "command again with the `--force` argument." ));
        }
      }
      break;
    }
    case FD_SET_IDENTITY_STATE_LOCKED: {
      fd_keyswitch_t * replay = find_keyswitch( topo, "replay" );
      memcpy( replay->bytes, keypair+32UL, 32UL );

      FD_COMPILER_MFENCE();
      replay->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
      FD_COMPILER_MFENCE();
      *state = FD_SET_IDENTITY_STATE_LEADER_HALT_REQUESTED;
      FD_LOG_INFO(( "Pausing leader pipeline for key switch..." ));
      break;
    }
    case FD_SET_IDENTITY_STATE_LEADER_HALT_REQUESTED: {
      fd_keyswitch_t * replay = find_keyswitch( topo, "replay" );
      if( FD_LIKELY( replay->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
        explicit_bzero( replay->bytes, 64UL );
        FD_COMPILER_MFENCE();
        *halted_seq = replay->result;
        *state = FD_SET_IDENTITY_STATE_LEADER_HALTED;
        FD_LOG_INFO(( "Leader pipeline successfully paused..." ));
      } else if( FD_UNLIKELY( replay->state==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
        FD_SPIN_PAUSE();
      } else {
        FD_LOG_ERR(( "Unexpected keyswitch state %lu", replay->state ));
      }
      break;
    }
    case FD_SET_IDENTITY_STATE_LEADER_HALTED: {
      /* Now we have to flush any in-flight and block requests from the
         repair, gossip, send, and tower tiles that need to be signed.

         TODO: Tower currently doesn't support running off of a tower
         file.  When support for a tower file is added, the tower file
         will need to be swapped and synced with the local state of the
         tower.  The security sandbox implications of adding another
         file descriptor need to be considered. */
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &topo->tiles[ i ];
        if( FD_LIKELY( topo->tiles[ i ].keyswitch_obj_id==ULONG_MAX ) ) continue;
        if( strcmp( tile->name, "repair" ) &&
            strcmp( tile->name, "gossip" ) &&
            strcmp( tile->name, "tower" ) ) {
          continue;
        }
        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, topo->tiles[ i ].keyswitch_obj_id );

        if( !strcmp( tile->name, "tower" ) ) tile_ks->param = !!require_tower;

        memcpy( tile_ks->bytes, keypair+32UL, 32UL );
        FD_COMPILER_MFENCE();
        tile_ks->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
        FD_COMPILER_MFENCE();
      }
      *state = FD_SET_IDENTITY_STATE_REPLAY_HALT_REQUESTED;
      FD_LOG_INFO(( "Requesting to halt all signers..." ));
      break;
    }
    case FD_SET_IDENTITY_STATE_REPLAY_HALT_REQUESTED: {
      int all_switched = 1;
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &topo->tiles[ i ];
        if( FD_LIKELY( topo->tiles[ i ].keyswitch_obj_id==ULONG_MAX ) ) continue;
        if( strcmp( tile->name, "repair" )!=0 &&
            strcmp( tile->name, "gossip" )!=0 &&
            strcmp( tile->name, "tower" )!=0 ) {
          continue;
        }

        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, topo->tiles[ i ].keyswitch_obj_id );
        if( FD_LIKELY( tile_ks->state==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
          all_switched = 0UL;
          break;
        }
      }
      if( FD_LIKELY( all_switched ) ) {
        FD_LOG_INFO(( "All successfully switched identity key..." ));
        *state = FD_SET_IDENTITY_STATE_REPLAY_HALTED;
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    case FD_SET_IDENTITY_STATE_REPLAY_HALTED: {
      ulong tower_halted_seq = find_keyswitch( topo, "tower" )->result;
      fd_keyswitch_t * txsend = find_keyswitch( topo, "txsend" );
      txsend->param = tower_halted_seq;
      memcpy( txsend->bytes, keypair+32UL, 32UL );
      FD_COMPILER_MFENCE();
      txsend->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
      FD_COMPILER_MFENCE();

      *state = FD_SET_IDENTITY_STATE_SEND_FLUSH_REQUESTED;
      break;
    }
    case FD_SET_IDENTITY_STATE_SEND_FLUSH_REQUESTED: {
      fd_keyswitch_t * txsend = find_keyswitch( topo, "txsend" );
      if( FD_LIKELY( txsend->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
        explicit_bzero( txsend->bytes, 64UL );
        FD_COMPILER_MFENCE();
        *state = FD_SET_IDENTITY_STATE_SEND_FLUSHED;
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    case FD_SET_IDENTITY_STATE_SEND_FLUSHED: {
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        fd_topo_tile_t * tile = &topo->tiles[ i ];
        if( strcmp( tile->name, "sign" ) ) continue;
        fd_keyswitch_t * sign = fd_topo_obj_laddr( topo, tile->keyswitch_obj_id );
        memcpy( sign->bytes, keypair, 64UL );
        FD_COMPILER_MFENCE();
        sign->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
        FD_COMPILER_MFENCE();
      }

      FD_COMPILER_MFENCE();
      explicit_bzero( keypair, 32UL ); /* Private key no longer needed in this process */
      FD_COMPILER_MFENCE();

      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        if( FD_LIKELY( topo->tiles[ i ].keyswitch_obj_id==ULONG_MAX ) ) continue;
        if( FD_LIKELY( !strcmp( topo->tiles[ i ].name, "sign" ) ||
                       !strcmp( topo->tiles[ i ].name, "replay" ) ||
                       !strcmp( topo->tiles[ i ].name, "shred" ) ||
                       !strcmp( topo->tiles[ i ].name, "repair" ) ||
                       !strcmp( topo->tiles[ i ].name, "gossip" ) ||
                       !strcmp( topo->tiles[ i ].name, "txsend" ) ||
                       !strcmp( topo->tiles[ i ].name, "tower" ) ) ) continue;

        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, topo->tiles[ i ].keyswitch_obj_id );
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
        if( FD_LIKELY( topo->tiles[ i ].keyswitch_obj_id==ULONG_MAX ) ) continue;
        if( FD_LIKELY( !strcmp( topo->tiles[ i ].name, "replay" ) ||
                       !strcmp( topo->tiles[ i ].name, "shred" ) ||
                       !strcmp( topo->tiles[ i ].name, "repair" ) ||
                       !strcmp( topo->tiles[ i ].name, "gossip" ) ||
                       !strcmp( topo->tiles[ i ].name, "txsend" ) ||
                       !strcmp( topo->tiles[ i ].name, "tower" ) ) ) continue;

        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, topo->tiles[ i ].keyswitch_obj_id );
        if( FD_LIKELY( tile_ks->state==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
          all_switched = 0UL;
          break;
        } else if( FD_UNLIKELY( tile_ks->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
          if( FD_LIKELY( !strcmp( topo->tiles[ i ].name, "sign" ) ) ) {
            FD_COMPILER_MFENCE();
            explicit_bzero( tile_ks->bytes, 64UL );
            FD_COMPILER_MFENCE();
          }
          continue;
        } else {
          FD_LOG_ERR(( "Unexpected %s keyswitch state %lu", topo->tiles[ i ].name, tile_ks->state ));
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
        if( FD_LIKELY( topo->tiles[ i ].keyswitch_obj_id==ULONG_MAX ) ) continue;
        if( strcmp( tile->name, "repair" ) &&
            strcmp( tile->name, "gossip" ) &&
            strcmp( tile->name, "tower" ) ) {
          continue;
        }

        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, topo->tiles[ i ].keyswitch_obj_id );
        FD_COMPILER_MFENCE();
        tile_ks->state = FD_KEYSWITCH_STATE_UNHALT_PENDING;
        FD_COMPILER_MFENCE();
      }

      FD_LOG_INFO(( "Requesting to unpause signers..." ));
      *state = FD_SET_IDENTITY_STATE_REPLAY_UNHALT_REQUESTED;
      break;
    }
    case FD_SET_IDENTITY_STATE_REPLAY_UNHALT_REQUESTED: {
      int all_switched = 1;
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &topo->tiles[ i ];
        if( FD_LIKELY( topo->tiles[ i ].keyswitch_obj_id==ULONG_MAX ) ) continue;
        if( strcmp( tile->name, "repair" ) &&
            strcmp( tile->name, "gossip" ) &&
            strcmp( tile->name, "tower" ) ) {
          continue;
        }

        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, topo->tiles[ i ].keyswitch_obj_id );
        if( FD_LIKELY( tile_ks->state==FD_KEYSWITCH_STATE_UNHALT_PENDING ) ) {
          all_switched = 0UL;
          break;
        }
      }
      if( FD_LIKELY( all_switched ) ) {
        FD_LOG_INFO(( "Successfully unpaused all non-leader signers..." ));
        *state = FD_SET_IDENTITY_STATE_REPLAY_UNHALTED;
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    case FD_SET_IDENTITY_STATE_REPLAY_UNHALTED: {
      fd_keyswitch_t * replay = find_keyswitch( topo, "replay" );
      replay->state = FD_KEYSWITCH_STATE_UNHALT_PENDING;
      FD_LOG_INFO(( "Requesting to unpause leader pipeline..." ));
      *state = FD_SET_IDENTITY_STATE_LEADER_UNHALT_REQUESTED;
      break;
    }
    case FD_SET_IDENTITY_STATE_LEADER_UNHALT_REQUESTED: {
      fd_keyswitch_t * replay = find_keyswitch( topo, "replay" );
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
  }
}

void
set_identity_cmd_args( int *    pargc,
                       char *** pargv,
                       args_t * args) {
  args->set_identity.require_tower = fd_env_strip_cmdline_contains( pargc, pargv, "--require-tower" );
  args->set_identity.force         = fd_env_strip_cmdline_contains( pargc, pargv, "--force" );

  if( FD_UNLIKELY( *pargc<1 ) ) goto err;

  char const * path = *pargv[0];
  (*pargc)--;
  (*pargv)++;

  if( FD_UNLIKELY( !strcmp( path, "-" ) ) ) {
    args->set_identity.keypair = fd_keyload_alloc_protected_pages( 1UL, 2UL );
    FD_LOG_STDOUT(( "Reading identity keypair from stdin.  Press Ctrl-D when done.\n" ));
    fd_keyload_read( STDIN_FILENO, "stdin", args->set_identity.keypair );
  } else {
    args->set_identity.keypair = fd_keyload_load( path, 0 );
  }

  return;

err:
  FD_LOG_ERR(( "Usage: firedancer set-identity <keypair> [--require-tower] [--force]" ));
}

static void FD_FN_SENSITIVE
set_identity( args_t *   args,
              config_t * config ) {
  uchar check_public_key[ 32 ];
  fd_sha512_t sha512[1];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha512 ) ) );
  fd_ed25519_public_from_private( check_public_key, args->set_identity.keypair, sha512 );
  if( FD_UNLIKELY( memcmp( check_public_key, args->set_identity.keypair+32UL, 32UL ) ) )
    FD_LOG_ERR(( "The public key in the identity key file does not match the public key derived from the private key. "
                 "Firedancer will not use the key pair to sign as it might leak the private key." ));

  for( ulong i=0UL; i<config->topo.obj_cnt; i++ ) {
    fd_topo_obj_t * obj = &config->topo.objs[ i ];
    if( FD_LIKELY( strcmp( obj->name, "keyswitch" ) ) ) continue;

    fd_topo_join_workspace( &config->topo, &config->topo.workspaces[ obj->wksp_id ], FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  }

  ulong state = FD_SET_IDENTITY_STATE_UNLOCKED;
  ulong halted_seq = 0UL;
  for(;;) {
    poll_keyswitch( &config->topo, &state, &halted_seq, args->set_identity.keypair, args->set_identity.require_tower, args->set_identity.force );
    if( FD_UNLIKELY( FD_SET_IDENTITY_STATE_UNLOCKED==state ) ) break;
  }

  char identity_key_base58[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( args->set_identity.keypair+32UL, NULL, identity_key_base58 );
  identity_key_base58[ FD_BASE58_ENCODED_32_SZ-1UL ] = '\0';

  FD_LOG_NOTICE(( "Validator identity key switched to `%s`", identity_key_base58 ));
}

void
set_identity_cmd_fn( args_t *   args,
                     config_t * config ) {
  set_identity( args, config );
}

action_t fd_action_set_identity = {
  .name           = "set-identity",
  .args           = set_identity_cmd_args,
  .fn             = set_identity_cmd_fn,
  .require_config = 1,
  .perm           = NULL,
  .description    = "Change the identity of a running validator",
};
