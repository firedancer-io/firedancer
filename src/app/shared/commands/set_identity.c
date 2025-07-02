#define _GNU_SOURCE
#include "run/run.h"

#include "../../platform/fd_cap_chk.h"
#include "../../../disco/keyguard/fd_keyswitch.h"
#include "../../../disco/keyguard/fd_keyload.h"
#include "../../../tango/fd_tango.h"
#include "../../../util/fd_util.h"

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
#define FD_SET_IDENTITY_STATE_UNLOCKED              (0UL)

/* State 1: LOCKED
     Some client to the validator has requested a key switch.  To do so,
     it acquired an exclusive lock on the validator to prevent the
     switch potentially being interleaved with another client. */
#define FD_SET_IDENTITY_STATE_LOCKED                (1UL)

/* State 2: POH_HALT_REQUESTED
     The first step in the key switch process is to pause the leader
     pipeline of the validator, preventing us from becoming leader, but
     finishing any currently in progress leader slot if there is one.
     While in this state, the validator is waiting for the leader
     pipeline to confirm that it has paused production, and is no longer
     leader.

     This halt request also causes the PoH tile to switch both:

       (a) The identity key used by the PoH tile itself, used to
           determine when this validator is leader in the schedule.

       (b) The key used by the Agave sub-process, if running
           Frankendancer.  The Agave key is inside a Mutex<> so it is
           swapped atomically across all consumers. */
#define FD_SET_IDENTITY_STATE_POH_HALT_REQUESTED    (2UL)

/* State 3: POH_HALTED
     The PoH tile has confirmed that it has halted the leader pipeline,
     and the validator is no longer leader.  No more blocks will be
     produced until it is unhalted.  In addition, the PoH tile has
     switched both its own identity key and the Agave key. */
#define FD_SET_IDENTITY_STATE_POH_HALTED            (3UL)

/* State 4: SHRED_FLUSH_REQUESTED
     Once the leader pipeline is halted, it must be flushed, meaning any
     in-flight shreds that could potentially need to be signed with the
     old key are signed and sent to the network.  This doesn't strictly
     need to happen before other tiles have their key flushed, but it
     makes the control flow easier to understand if we do this as an
     explicit step.

     The shred tile is flushed by telling it the last sequence number
     the PoH tile has produced for an outgoing shred, at the time it was
     halted, and then waiting for the shred tile to confirm that it has
     seen and processed all shreds up to and including that sequence
     number.

     In addition to flushing out any in-flight shreds, this also causes
     the shred tile to switch the identity key it uses internally, for
     determining where this validator is positioned in the Turbine tree. */
#define FD_SET_IDENTITY_STATE_SHRED_FLUSH_REQUESTED (4UL)

/* State 5: SHRED_FLUSHED
     The shred tile confirms that it has seen and processed all shreds
     up to and including the last sequence number produced by the PoH
     tile at the time it was halted.  The shred tile has also switched
     its own identity key when it indicates the flush is complete. */
#define FD_SET_IDENTITY_STATE_SHRED_FLUSHED         (5UL)

/* State 6: ALL_SWITCH_REQUESTED
     The client now requests that all other tiles which consume the
     identity key in some way switch to the new key.  The leader
     pipeline is still halted, although it doesn't strictly need to be,
     since outgoing shreds have been flushed.  This is done to keep the
     control flow simpler.

     The other tiles using the identity key are:

       (a) Sign.  The sign tile is responsible for holding the private
           key.
       (b) GUI.  The GUI shows the validator identity key to the user,
           and uses the key to determine which blocks are ours for
           highlighting on the frontend.
       (c) Event.  Outgoing events to the event server are signed with
           the identity key to authenticate the sender.
       (d) Bundle.  The validator must authenticate to any connected
           bundle server with the identity key to prove it is on the
           leader schedule. */
#define FD_SET_IDENTITY_STATE_ALL_SWITCH_REQUESTED  (6UL)

/* State 7: ALL_SWITCHED
     All remaining tiles that use the identity key have confirmed that
     they have switched to the new key.  The validator is now fully
     switched over. */
#define FD_SET_IDENTITY_STATE_ALL_SWITCHED          (7UL)

/* State 8: POH_UNHALT_REQUESTED
     The final state, now that all tiles have switched, the leader
     pipeline can be unblocked and the validator can resume producing
     blocks.  The next state once the PoH tile confirms the leader
     pipeline is unlocked, is UNLOCKED. */
#define FD_SET_IDENTITY_STATE_POH_UNHALT_REQUESTED  (8UL)

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
                int *       has_error,
                int         require_tower,
                int         force_lock ) {
  switch( *state ) {
    case FD_SET_IDENTITY_STATE_UNLOCKED: {
      fd_keyswitch_t * poh = find_keyswitch( topo, "poh" );
      if( FD_LIKELY( FD_KEYSWITCH_STATE_UNLOCKED==FD_ATOMIC_CAS( &poh->state, FD_KEYSWITCH_STATE_UNLOCKED, FD_KEYSWITCH_STATE_LOCKED ) ) ) {
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
      fd_keyswitch_t * poh = find_keyswitch( topo, "poh" );
      memcpy( poh->bytes, keypair, 64UL );
      poh->param = !!require_tower;
      FD_COMPILER_MFENCE();
      poh->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
      FD_COMPILER_MFENCE();
      *state = FD_SET_IDENTITY_STATE_POH_HALT_REQUESTED;
      FD_LOG_INFO(( "Pausing leader pipeline for key switch..." ));
      break;
    }
    case FD_SET_IDENTITY_STATE_POH_HALT_REQUESTED: {
      fd_keyswitch_t * poh = find_keyswitch( topo, "poh" );
      if( FD_LIKELY( poh->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
        explicit_bzero( poh->bytes, 64UL );
        FD_COMPILER_MFENCE();
        *halted_seq = poh->result;
        *state = FD_SET_IDENTITY_STATE_POH_HALTED;
        FD_LOG_INFO(( "Leader pipeline successfully paused..." ));
      } else if( FD_UNLIKELY( poh->state==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
        FD_SPIN_PAUSE();
      } else if( FD_LIKELY( poh->state==FD_KEYSWITCH_STATE_FAILED ) ) {
        /* Failed to switch identity in Agave, so abort the entire process. */
        *state = FD_SET_IDENTITY_STATE_ALL_SWITCHED;
        *has_error = 1;
      } else {
        FD_LOG_ERR(( "Unexpected poh keyswitch state %lu", poh->state ));
      }
      break;
    }
    case FD_SET_IDENTITY_STATE_POH_HALTED: {
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &topo->tiles[ i ];
        if( FD_LIKELY( strcmp( tile->name, "shred" ) ) ) continue;

        fd_keyswitch_t * shred = fd_topo_obj_laddr( topo, tile->keyswitch_obj_id );
        FD_TEST( shred );

        shred->param = *halted_seq;
        memcpy( shred->bytes, keypair+32UL, 32UL );
        FD_COMPILER_MFENCE();
        shred->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
        FD_COMPILER_MFENCE();
        FD_LOG_INFO(( "Flushing in-flight unpublished shreds, must reach seq %lu...", *halted_seq ));
      }

      *state = FD_SET_IDENTITY_STATE_SHRED_FLUSH_REQUESTED;
      break;
    }
    case FD_SET_IDENTITY_STATE_SHRED_FLUSH_REQUESTED: {
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        fd_topo_tile_t const * tile = &topo->tiles[ i ];
        if( FD_LIKELY( strcmp( tile->name, "shred" ) ) ) continue;

        fd_keyswitch_t * shred = fd_topo_obj_laddr( topo, tile->keyswitch_obj_id );
        FD_TEST( shred );

        if( FD_LIKELY( shred->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
          continue;
        } else if( FD_UNLIKELY( shred->state==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
          /* If any of the shred tiles is still pending, we need to wait. */
          FD_SPIN_PAUSE();
          return;
        } else {
          FD_LOG_ERR(( "Unexpected shred:%lu keyswitch state %lu", tile->kind_id, shred->state ));
        }
      }

      *state = FD_SET_IDENTITY_STATE_SHRED_FLUSHED;
      FD_LOG_INFO(( "All in-flight shreds published..." ));
      break;
    }
    case FD_SET_IDENTITY_STATE_SHRED_FLUSHED: {
      fd_keyswitch_t * sign = find_keyswitch( topo, "sign" );
      memcpy( sign->bytes, keypair, 64UL );
      FD_COMPILER_MFENCE();
      explicit_bzero( keypair, 32UL ); /* Private key no longer needed in this process */
      FD_COMPILER_MFENCE();
      sign->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
      FD_COMPILER_MFENCE();

      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        if( FD_LIKELY( topo->tiles[ i ].keyswitch_obj_id==ULONG_MAX ) ) continue;
        if( FD_LIKELY( !strcmp( topo->tiles[ i ].name, "sign" ) ||
                       !strcmp( topo->tiles[ i ].name, "poh" ) ||
                       !strcmp( topo->tiles[ i ].name, "shred" ) ) ) continue;

        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, topo->tiles[ i ].keyswitch_obj_id );
        memcpy( tile_ks->bytes, keypair+32UL, 32UL );
        FD_COMPILER_MFENCE();
        tile_ks->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
        FD_COMPILER_MFENCE();
      }

      FD_LOG_INFO(( "Requesting all tiles switch identity key..." ));
      *state = FD_SET_IDENTITY_STATE_ALL_SWITCH_REQUESTED;
      break;
    }
    case FD_SET_IDENTITY_STATE_ALL_SWITCH_REQUESTED: {
      ulong all_switched = 1UL;
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        if( FD_LIKELY( topo->tiles[ i ].keyswitch_obj_id==ULONG_MAX ) ) continue;
        if( FD_LIKELY( !strcmp( topo->tiles[ i ].name, "poh" ) ||
                       !strcmp( topo->tiles[ i ].name, "shred" ) ) ) continue;

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
      fd_keyswitch_t * poh = find_keyswitch( topo, "poh" );
      poh->state = FD_KEYSWITCH_STATE_UNHALT_PENDING;
      FD_LOG_INFO(( "Requesting to unpause leader pipeline..." ));
      *state = FD_SET_IDENTITY_STATE_POH_UNHALT_REQUESTED;
      break;
    }
    case FD_SET_IDENTITY_STATE_POH_UNHALT_REQUESTED: {
      fd_keyswitch_t * poh = find_keyswitch( topo, "poh" );
      if( FD_LIKELY( poh->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
        FD_LOG_INFO(( "Leader pipeline unpaused..." ));
        poh->state = FD_KEYSWITCH_STATE_UNLOCKED;
        *state = FD_SET_IDENTITY_STATE_UNLOCKED;
      } else if( FD_UNLIKELY( poh->state==FD_KEYSWITCH_STATE_UNHALT_PENDING ) ) {
        FD_SPIN_PAUSE();
      } else {
        FD_LOG_ERR(( "Unexpected poh keyswitch state %lu", poh->state ));
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
  FD_LOG_ERR(( "Usage: fdctl set-identity <keypair> [--require-tower]" ));
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

    fd_topo_join_workspace( &config->topo, &config->topo.workspaces[ obj->wksp_id ], FD_SHMEM_JOIN_MODE_READ_WRITE );
  }

  int has_error = 0;
  ulong state = FD_SET_IDENTITY_STATE_UNLOCKED;
  ulong halted_seq = 0UL;
  for(;;) {
    poll_keyswitch( &config->topo, &state, &halted_seq, args->set_identity.keypair, &has_error, args->set_identity.require_tower, args->set_identity.force );
    if( FD_UNLIKELY( FD_SET_IDENTITY_STATE_UNLOCKED==state ) ) break;
  }

  char identity_key_base58[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( args->set_identity.keypair+32UL, NULL, identity_key_base58 );
  identity_key_base58[ FD_BASE58_ENCODED_32_SZ-1UL ] = '\0';

  if( FD_UNLIKELY( has_error ) ) FD_LOG_ERR(( "Failed to switch identity key to `%s`, check validator logs for details", identity_key_base58 ));
  else                           FD_LOG_NOTICE(( "Validator identity key switched to `%s`", identity_key_base58 ));
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
