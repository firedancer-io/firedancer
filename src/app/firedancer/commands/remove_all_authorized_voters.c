#define _GNU_SOURCE
#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"

#include "../../../disco/topo/fd_topo.h"
#include "../../../disco/keyguard/fd_keyswitch.h"

#include <string.h>

/* Removing all authorized voters from the validator is the inverse of
   add-authorized-voter, and must be done in the opposite order.  When
   adding, the sign tile is updated before the tower tile so that the
   tower never asks the sign tile to sign a vote with an authority index
   the sign tile does not yet know about.  When removing, the tower tile
   must be cleared before the sign tiles, so that the tower stops
   referencing an authorized voter index before the sign tile drops the
   corresponding key.

   Vote signing is synchronous (the tower busy-waits for the sign tile
   reply) and keyswitch processing runs during housekeeping, between
   frags, so there are never in-flight vote signing requests outstanding
   while keys change.  Once the tower clears its authorized voter map it
   can no longer emit a signing request referencing a removed voter, so
   clearing the sign tiles afterwards is safe.  All transitions are
   linear and in forward order.

   Unlike add-authorized-voter, removal cannot fail on the tile side: it
   is unconditional and idempotent (clearing an empty set succeeds). */

/* State 0: UNLOCKED.
     The validator is not currently in the process of switching keys. */
#define FD_RM_AUTH_VOTER_STATE_UNLOCKED              (0UL)

/* State 1: LOCKED.
     A client acquired an exclusive lock on the validator to prevent the
     removal being interleaved with another client. */
#define FD_RM_AUTH_VOTER_STATE_LOCKED                (1UL)

/* State 2: TOWER_TILE_REQUESTED.
     The tower tile has been notified to clear its authorized voter set.
     It is cleared first so it stops preparing vote transactions with any
     authorized voter before the sign tiles drop the keys. */
#define FD_RM_AUTH_VOTER_STATE_TOWER_TILE_REQUESTED  (2UL)

/* State 3: TOWER_TILE_CLEARED.
     The tower tile confirmed it cleared its authorized voter map.  At
     this point the validator will only prepare vote transactions signed
     by the identity key. */
#define FD_RM_AUTH_VOTER_STATE_TOWER_TILE_CLEARED    (3UL)

/* State 4: SIGN_TILE_REQUESTED.
     All sign tiles have been notified to clear their authorized voter
     keys. */
#define FD_RM_AUTH_VOTER_STATE_SIGN_TILE_REQUESTED   (4UL)

/* State 5: SIGN_TILE_CLEARED.
     All sign tiles confirmed they cleared (and securely zeroed) their
     authorized voter keys. */
#define FD_RM_AUTH_VOTER_STATE_SIGN_TILE_CLEARED     (5UL)

/* State 6: UNLOCK_REQUESTED.
     The client requests that the tower tile release the lock. */
#define FD_RM_AUTH_VOTER_STATE_UNLOCK_REQUESTED      (6UL)

static void
poll_keyswitch( fd_topo_t * topo,
                ulong *     state ) {
  fd_keyswitch_t * tower = fd_topo_obj_laddr( topo, topo->tiles[ fd_topo_find_tile( topo, "tower", 0UL ) ].av_keyswitch_obj_id );

  switch( *state ) {
    case FD_RM_AUTH_VOTER_STATE_UNLOCKED: {
      if( FD_LIKELY( FD_KEYSWITCH_STATE_UNLOCKED==FD_ATOMIC_CAS( &tower->state, FD_KEYSWITCH_STATE_UNLOCKED, FD_KEYSWITCH_STATE_LOCKED ) ) ) {
        *state = FD_RM_AUTH_VOTER_STATE_LOCKED;
        FD_LOG_INFO(( "Locking authorized voter set for authorized voter update..." ));
      } else {
        FD_LOG_ERR(( "Cannot remove-all-authorized-voters because Firedancer is already in the process of updating the authorized voter keys. If you "
                     "are not currently updating an authorized voter, it might be because an authorized voter update was abandoned." ));
      }
      break;
    }
    case FD_RM_AUTH_VOTER_STATE_LOCKED: {
      tower->state = FD_KEYSWITCH_STATE_CLEAR_PENDING;
      FD_COMPILER_MFENCE();
      *state = FD_RM_AUTH_VOTER_STATE_TOWER_TILE_REQUESTED;
      FD_LOG_INFO(( "Requesting tower tile to clear authorized voter key set..." ));
      break;
    }
    case FD_RM_AUTH_VOTER_STATE_TOWER_TILE_REQUESTED: {
      if( FD_LIKELY( tower->state==FD_KEYSWITCH_STATE_COMPLETED ) ) {
        *state = FD_RM_AUTH_VOTER_STATE_TOWER_TILE_CLEARED;
        FD_LOG_INFO(( "Tower tile authorized voter key set cleared..." ));
      } else {
        FD_SPIN_PAUSE();
      }
      break;
    }
    case FD_RM_AUTH_VOTER_STATE_TOWER_TILE_CLEARED: {
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        if( FD_LIKELY( strcmp( topo->tiles[ i ].name, "sign" ) ) ) continue;
        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, topo->tiles[ i ].av_keyswitch_obj_id );
        tile_ks->state = FD_KEYSWITCH_STATE_CLEAR_PENDING;
        FD_COMPILER_MFENCE();
      }
      *state = FD_RM_AUTH_VOTER_STATE_SIGN_TILE_REQUESTED;
      FD_LOG_INFO(( "Requesting all sign tiles to clear authorized voter key set..." ));
      break;
    }
    case FD_RM_AUTH_VOTER_STATE_SIGN_TILE_REQUESTED: {
      int all_cleared = 1;
      for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
        if( FD_LIKELY( strcmp( topo->tiles[ i ].name, "sign" ) ) ) continue;
        fd_keyswitch_t * tile_ks = fd_topo_obj_laddr( topo, topo->tiles[ i ].av_keyswitch_obj_id );
        if( FD_UNLIKELY( tile_ks->state!=FD_KEYSWITCH_STATE_COMPLETED ) ) {
          all_cleared = 0;
          break;
        }
      }

      if( FD_LIKELY( all_cleared ) ) *state = FD_RM_AUTH_VOTER_STATE_SIGN_TILE_CLEARED;
      else                           FD_SPIN_PAUSE();
      break;
    }
    case FD_RM_AUTH_VOTER_STATE_SIGN_TILE_CLEARED: {
      tower->state = FD_KEYSWITCH_STATE_UNHALT_PENDING;
      *state = FD_RM_AUTH_VOTER_STATE_UNLOCK_REQUESTED;
      FD_LOG_INFO(( "Requesting tower tile to unlock authorized voter key set..." ));
      break;
    }
    case FD_RM_AUTH_VOTER_STATE_UNLOCK_REQUESTED: {
      if( FD_LIKELY( tower->state==FD_KEYSWITCH_STATE_UNLOCKED ) ) {
        *state = FD_RM_AUTH_VOTER_STATE_UNLOCKED;
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

void
remove_all_authorized_voters_cmd_fn( args_t *   args FD_PARAM_UNUSED,
                                     config_t * config ) {
  for( ulong i=0UL; i<config->topo.tile_cnt; i++ ) {
    fd_topo_tile_t * tile = &config->topo.tiles[ i ];
    if( FD_LIKELY( tile->av_keyswitch_obj_id==ULONG_MAX ) ) continue;
    fd_topo_obj_t * obj = &config->topo.objs[ tile->av_keyswitch_obj_id ];
    fd_topo_join_workspace( &config->topo, &config->topo.workspaces[ obj->wksp_id ], FD_SHMEM_JOIN_MODE_READ_WRITE, FD_TOPO_CORE_DUMP_LEVEL_DISABLED );
  }

  ulong state = FD_RM_AUTH_VOTER_STATE_UNLOCKED;
  for(;;) {
    poll_keyswitch( &config->topo, &state );
    if( FD_UNLIKELY( FD_RM_AUTH_VOTER_STATE_UNLOCKED==state ) ) break;
  }

  FD_LOG_NOTICE(( "All authorized voters removed" ));
}

action_t fd_action_remove_all_authorized_voters = {
  .name           = "remove-all-authorized-voters",
  .args           = NULL,
  .fn             = remove_all_authorized_voters_cmd_fn,
  .require_config = 1,
  .perm           = NULL,
  .description    = "Remove all authorized voters from the validator",
  .detail         = "Removes every authorized voter key from an already running validator,\n"
                    "including any seeded from [paths.authorized_voter_paths] at startup as\n"
                    "well as any added at runtime with add-authorized-voter.  After this the\n"
                    "validator can only sign votes for vote accounts whose authorized voter is\n"
                    "the identity key.  On success it prints `All authorized voters removed` and\n"
                    "exits 0.  It is idempotent: removing when there are no authorized voters\n"
                    "also succeeds.\n"
                    "\n"
                    "This command does not start a validator; it attaches to one that is already\n"
                    "running.  It finds the running validator from the shared memory described by\n"
                    "the configuration file, so you must point --config at the SAME config file the\n"
                    "validator was started with, and run it from a binary built from the SAME git\n"
                    "commit (compare this binary's `--version` against the running validator's).  If\n"
                    "the config or binary differ, the layout will not match and the command fails\n"
                    "without changing anything.\n"
                    "\n"
                    "The change is live only: it is not written back to the config file, so any\n"
                    "voters in [paths.authorized_voter_paths] return on the validator's next\n"
                    "restart.  To drop them across restarts, also remove them from the config.",
  .usage          = "remove-all-authorized-voters",
};
