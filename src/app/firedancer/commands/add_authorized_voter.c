#define _GNU_SOURCE
#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"

#include "../../../disco/topo/fd_topo.h"
#include "../../../disco/keyguard/fd_keyswitch.h"
#include "../../../disco/keyguard/fd_keyload.h"

#include <strings.h>
#include <unistd.h>

/* The process of adding an authorized voter to the validator must be
   done carefully in order to prevent vote transactions being generated
   with an authorized voter that the sign tile is not yet aware of.
   The authorized voter must be added to the sign tile before it is
   added to the tower tile.  All transitions must be linear and in
   forward order.  The states below describe the state transitions.

   The caller should expect the command to fail if:
   1. The authorized voter keypair being passed in is already part of
      the authorized voter set.
   2. There are too many authorized voters being passed in. */

/* State 0: UNLOCKED.
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

void
add_authorized_voter_cmd_args( int *    pargc,
                               char *** pargv,
                               args_t * args ) {

  if( FD_UNLIKELY( *pargc<1 ) ) {
    FD_LOG_ERR(( "Usage: firedancer add-authorized-voter <keypair>" ));
  }

  char const * path = *pargv[0];
  (*pargc)--;
  (*pargv)++;

  if( FD_UNLIKELY( !strcmp( path, "-" ) ) ) {
    args->add_authorized_voter.keypair = fd_keyload_alloc_protected_pages( 1UL, 2UL );
    FD_LOG_STDOUT(( "Reading authorized voter keypair from stdin.  Press Ctrl-D when done.\n" ));
    fd_keyload_read( STDIN_FILENO, "stdin", args->add_authorized_voter.keypair );
  } else {
    args->add_authorized_voter.keypair = fd_keyload_load( path, 0 );
  }
}

static void FD_FN_SENSITIVE
poll_keyswitch( fd_topo_t * topo,
                ulong *     state,
                uchar *     keypair,
                int *       has_error ) {
  fd_keyswitch_t * tower = fd_topo_obj_laddr( topo, topo->tiles[ fd_topo_find_tile( topo, "tower", 0UL ) ].av_keyswitch_obj_id );

  switch( *state ) {
    case FD_ADD_AUTH_VOTER_STATE_UNLOCKED: {
      if( FD_LIKELY( FD_KEYSWITCH_STATE_UNLOCKED==FD_ATOMIC_CAS( &tower->state, FD_KEYSWITCH_STATE_UNLOCKED, FD_KEYSWITCH_STATE_LOCKED ) ) ) {
        *state = FD_ADD_AUTH_VOTER_STATE_LOCKED;
        FD_LOG_INFO(( "Locking authorized voter set for authorized voter update..." ));
      } else {
        FD_LOG_ERR(( "Cannot add-authorized-voter because Firedancer is already in the process of updating the authorized voter keys. If you "
                     "are not currently adding an authorized voter, it might be because an authorized voter update was abandoned." ));
      }
      break;
    }
    case FD_ADD_AUTH_VOTER_STATE_LOCKED: {
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        if( FD_LIKELY( strcmp( topo->tiles[ i ].name, "sign" ) ) ) continue;
        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, topo->tiles[ i ].av_keyswitch_obj_id );
        memcpy( tile_ks->bytes, keypair, 64UL );
        FD_COMPILER_MFENCE();
        tile_ks->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
        FD_COMPILER_MFENCE();
      }
      explicit_bzero( keypair, 32UL );
      *state = FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_REQUESTED;
      FD_LOG_INFO(( "Requesting all sign tiles to update authorized voter key set..." ));
      break;
    }
    case FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_REQUESTED: {
      int all_updated = 1;
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        if( FD_LIKELY( strcmp( topo->tiles[ i ].name, "sign" ) ) ) continue;
        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, topo->tiles[ i ].av_keyswitch_obj_id );
        if( FD_UNLIKELY( tile_ks->state==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
          all_updated = 0;
          break;
        } else if( FD_UNLIKELY( tile_ks->state==FD_KEYSWITCH_STATE_FAILED ) ) {
          explicit_bzero( tile_ks->bytes, 64UL );
          *has_error  = 1;
          break;
        } else {
          explicit_bzero( tile_ks->bytes, 64UL );
        }
      }

      if( FD_LIKELY( all_updated ) ) {
        if( FD_UNLIKELY( *has_error ) ) *state = FD_ADD_AUTH_VOTER_STATE_TOWER_TILE_UPDATED;
        else                            *state = FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_UPDATED;
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    case FD_ADD_AUTH_VOTER_STATE_SIGN_TILE_UPDATED: {
      memcpy( tower->bytes, keypair+32UL, 32UL );
      tower->state = FD_KEYSWITCH_STATE_SWITCH_PENDING;
      FD_COMPILER_MFENCE();
      *state = FD_ADD_AUTH_VOTER_STATE_TOWER_TILE_REQUESTED;
      FD_COMPILER_MFENCE();
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
      *state = FD_ADD_AUTH_VOTER_STATE_UNLOCK_REQUESTED;
      FD_LOG_INFO(( "Requesting tower tile to unlock authorized voter key set..." ));
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
      FD_LOG_ERR(( "Unexpected state %lu", *state ));
    }
  }
}

static void FD_FN_SENSITIVE
add_authorized_voter( args_t *   args,
                      config_t * config ) {
  uchar check_public_key[ 32 ];
  fd_sha512_t sha512[1];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha512 ) ) );

  fd_ed25519_public_from_private( check_public_key, args->add_authorized_voter.keypair, sha512 );
  if( FD_UNLIKELY( memcmp( check_public_key, args->add_authorized_voter.keypair+32UL, 32UL ) ) ) {
    FD_LOG_ERR(( "The public key in the key file does not match the public key derived from the private key."
                 "Firedancer will not use the key pair to sign as it might leak the private key." ));
  }

  for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &config->topo.tiles[ i ];
    if( FD_LIKELY( tile->av_keyswitch_obj_id==ULONG_MAX ) ) continue;
    fd_topo_obj_t * obj = &config->topo.objs[ tile->av_keyswitch_obj_id ];
    fd_topo_join_workspace( &config->topo, &config->topo.workspaces[ obj->wksp_id ], FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  }

  int has_error = 0;
  ulong state = FD_ADD_AUTH_VOTER_STATE_UNLOCKED;
  for(;;) {
    poll_keyswitch( &config->topo, &state, args->add_authorized_voter.keypair, &has_error );
    if( FD_UNLIKELY( FD_ADD_AUTH_VOTER_STATE_UNLOCKED==state ) ) break;
  }

  char key_base58[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( args->add_authorized_voter.keypair+32UL, NULL, key_base58 );
  key_base58[ FD_BASE58_ENCODED_32_SZ-1UL ] = '\0';

  if( FD_UNLIKELY( has_error ) ) FD_LOG_ERR(( "Failed to add authorized voter key to `%s`, check validator logs for details", key_base58 ));
  else                           FD_LOG_NOTICE(( "Authorized voter key added `%s`", key_base58 ));

}

void
add_authorized_voter_cmd_fn( args_t *   args,
                             config_t * config ) {
  add_authorized_voter( args, config );
}

action_t fd_action_add_authorized_voter = {
  .name           = "add-authorized-voter",
  .args           = add_authorized_voter_cmd_args,
  .fn             = add_authorized_voter_cmd_fn,
  .require_config = 1,
  .perm           = NULL,
  .description    = "Add an authorized voter to the validator",
};
