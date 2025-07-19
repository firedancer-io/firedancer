#include "../fd_config.h"
#include "../fd_action.h"
#include "../../../util/fd_util.h"
#include "../../../ballet/base58/fd_base58.h"
#include "../../../flamenco/types/fd_types_custom.h"
#include <unistd.h>

/* Minimal shred tile context structure to access identity_key.
   Based on fd_shred_tile.c, the identity_key is the third field. */
typedef struct {
  void *      shredder;      /* fd_shredder_t * */
  void *      resolver;      /* fd_fec_resolver_t * */
  fd_pubkey_t identity_key[1];
  /* ... other fields we don't need ... */
} fd_shred_ctx_minimal_t;

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
  fd_topo_workspace_fill( &config->topo, &config->topo.workspaces[ shred_wksp_id ] );

  /* Access the shred context through the workspace */
  void * shred_mem = fd_topo_obj_laddr( &config->topo, shred_tile->tile_obj_id );
  if( FD_UNLIKELY( !shred_mem ) ) {
    fd_topo_leave_workspaces( &config->topo );
    FD_LOG_ERR(( "Failed to access shred tile object" ));
  }

  /* Cast to our minimal context structure */
  fd_shred_ctx_minimal_t const * shred_ctx = (fd_shred_ctx_minimal_t const *)shred_mem;
  
  /* The shred tile maintains the current identity in shred_ctx->identity_key */
  fd_pubkey_t const * identity_key = shred_ctx->identity_key;

  /* Convert to base58 and print */
  char identity_key_str[ FD_BASE58_ENCODED_32_SZ ];
  fd_base58_encode_32( identity_key->uc, NULL, identity_key_str );
  
  FD_LOG_STDOUT(( "%s\n", identity_key_str ));

  /* Leave the workspace */
  fd_topo_leave_workspaces( &config->topo );
}

action_t fd_action_get_identity = {
  .name           = "get-identity",
  .args           = NULL,
  .fn             = get_identity_cmd_fn,
  .require_config = 1,
  .perm           = NULL,
  .description    = "Get the current active identity of the running validator",
};