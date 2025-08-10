#define _GNU_SOURCE
#include "../fd_config.h"
#include "../fd_action.h"
#include "../../../util/fd_util.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../../../flamenco/types/fd_types_custom.h"
#include "../../../disco/shred/fd_shred_tile.h"
#include "../../../disco/keyguard/fd_keyswitch.h"
#include <unistd.h>

void
get_identity_cmd_fn( args_t *   args   FD_PARAM_UNUSED,
                     config_t * config ) {
  /* Find the shred tile which is always present and has the current runtime identity */
  ulong shred_tile_idx = fd_topo_find_tile( &config->topo, "shred", 0UL );
  if( FD_UNLIKELY( shred_tile_idx==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Shred tile not found in topology" ));
  }

  fd_topo_tile_t const * shred_tile = &config->topo.tiles[ shred_tile_idx ];
  /* Access shred tile object to find its workspace */
  if( FD_UNLIKELY( shred_tile->tile_obj_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Shred tile object not found" ));
  }
  /* Find the workspace containing the shred tile object */
  fd_topo_obj_t const * shred_obj = &config->topo.objs[ shred_tile->tile_obj_id ];
  ulong shred_wksp_id = shred_obj->wksp_id;

  /* Join the workspace in read-only mode */
  fd_topo_join_workspace( &config->topo, &config->topo.workspaces[ shred_wksp_id ], FD_SHMEM_JOIN_MODE_READ_ONLY );

  /* Cast to shred context structure */
  fd_shred_ctx_hdr_t const * shred_ctx = fd_topo_obj_laddr( &config->topo, shred_tile->tile_obj_id );
  if( FD_UNLIKELY( !shred_ctx ) ) {
    fd_topo_leave_workspaces( &config->topo );
    FD_LOG_ERR(( "Failed to access shred tile object" ));
  }
  /* Join the keyswitch to check for concurrent identity updates */
  fd_keyswitch_t * keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( &config->topo, shred_tile->keyswitch_obj_id ) );
  if( FD_UNLIKELY( !keyswitch ) ) {
    fd_topo_leave_workspaces( &config->topo );
    FD_LOG_ERR(( "Failed to join keyswitch" ));
  }

  /* Read identity key with retry if needed */
  fd_pubkey_t identity_key;
  /* TODO: Consider adding a counter to detect multiple rapid identity switches
     that could cause us to read a stale identity between state checks. */
  for( int retry = 0; retry < 2; retry++ ) {
    /* Peek the pre-read keyswitch state */
    ulong switch_state0 = fd_keyswitch_state_query( keyswitch );

    /* Speculatively read current key */
    identity_key = FD_VOLATILE_CONST( *shred_ctx->identity_key );

    /* Peek the post-read keyswitch state */
    ulong switch_state1 = fd_keyswitch_state_query( keyswitch );

    /* Check if we got a consistent read */
    if( FD_LIKELY( switch_state0 == switch_state1 &&
                   switch_state0 != FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
      /* Success - we have a consistent identity key */
      break;
    }

    /* Key switch in progress or states don't match, retry after delay */
    if( retry == 0 ) {
      usleep( 10000 ); /* 10ms delay */
    } else {
      fd_keyswitch_leave( keyswitch );
      fd_topo_leave_workspaces( &config->topo );
      FD_LOG_ERR(( "Failed to read identity key - keyswitch in progress" ));
    }
  }

  /* Leave keyswitch */
  fd_keyswitch_leave( keyswitch );

  /* Convert to base58 and print */
  char identity_key_str[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( identity_key.uc, NULL, identity_key_str );

  FD_LOG_STDOUT(( "%s\n", identity_key_str ));
}

action_t fd_action_get_identity = {
  .name           = "get-identity",
  .args           = NULL,
  .fn             = get_identity_cmd_fn,
  .require_config = 1,
  .perm           = NULL, /* TODO: This command may require RLIMIT_MLOCK permissions
                             to mlock(2) the workspace in memory. This should be
                             addressed in future updates. */
  .description    = "Get the current active identity of the running validator",
};
