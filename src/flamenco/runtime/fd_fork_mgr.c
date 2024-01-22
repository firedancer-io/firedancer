#include "fd_fork_mgr.h"

#include "fd_runtime.h"

int
fd_fork_mgr_epoch_ctx_setup_from_parent( fd_fork_mgr_t * fork_mgr FD_PARAM_UNUSED,
                                         fd_exec_epoch_ctx_t const * parent_epoch_ctx,
                                         fd_exec_epoch_ctx_t * child_epoch_ctx ) {
  child_epoch_ctx->features = parent_epoch_ctx->features;
  child_epoch_ctx->valloc = parent_epoch_ctx->valloc;

  return 0;
}

int
fd_fork_mgr_slot_ctx_setup_from_parent( fd_fork_mgr_t * fork_mgr,
                                        fd_exec_slot_ctx_t * parent_slot_ctx,
                                        fd_exec_slot_ctx_t * child_slot_ctx ) {
  // Clone
  child_slot_ctx->epoch_ctx = parent_slot_ctx->epoch_ctx;
  child_slot_ctx->acc_mgr = parent_slot_ctx->acc_mgr;
  child_slot_ctx->valloc = parent_slot_ctx->valloc;

  fd_funk_txn_t * parent_txn = parent_slot_ctx->funk_txn;
  fd_funk_txn_xid_t xid;

  xid.ul[0] = fd_rng_ulong( fork_mgr->rng );
  xid.ul[1] = fd_rng_ulong( fork_mgr->rng );
  xid.ul[2] = fd_rng_ulong( fork_mgr->rng );
  xid.ul[3] = fd_rng_ulong( fork_mgr->rng );
  fd_funk_txn_t * child_txn = fd_funk_txn_prepare( parent_slot_ctx->acc_mgr->funk, parent_txn, &xid, 1 );
  child_slot_ctx->funk_txn = child_txn;

  return 0;
}
// int
// fd_fork_mgr_init( fd_fork_mgr_t * fork_mgr ) {
//   return -1;
// }

int
fd_fork_mgr_mark_block_completed( fd_fork_mgr_t * fork_mgr,
                                  fd_hash_t const * block_hash ) {
  fd_active_block_t_mapnode_t key;
  key.elem.key = *block_hash;
  fd_active_block_t_mapnode_t * n = fd_active_block_t_map_find( fork_mgr->active_block_pool, fork_mgr->active_block_root, &key);
  if( n == NULL ) {
    return -1;
  }
  n->elem.status = FD_FORK_STATUS_COMPLETE;
  return 0;
}

// TODO: we need the slot number for the microblock
// TODO: we need to check the slot number is not to low or two high.
int
fd_fork_mgr_add_new_microblock( fd_fork_mgr_t * fork_mgr,
                                fd_microblock_info_t const * mircoblock_info ) {
  uint found = 0;
  fd_hash_t poh_hash;
  fd_active_block_t_mapnode_t * n = NULL;
  for( n = fd_active_block_t_map_minimum( fork_mgr->active_block_pool, fork_mgr->active_block_root ); 
       n; 
       n = fd_active_block_t_map_successor( fork_mgr->active_block_pool, n ) 
  ) {
    if( fd_runtime_microblock_verify( mircoblock_info, &n->elem.key, &poh_hash ) == 0 ) {
      found = 1;
      break;
    }
  }

  if( !found ) {
    /* TODO: Check the slot number too high or too low */

    /* This node has no parent (yet) */
    n = fd_active_block_t_map_acquire( fork_mgr->active_block_pool );
    memcpy( n->elem.key.uc, mircoblock_info->microblock_hdr.hash, sizeof(fd_hash_t) );
    n->elem.microblock_infos_cnt = 1;
    n->elem.microblock_infos[0] = mircoblock_info;
    n->elem.child_keys_cnt = 0;
    memset( n->elem.parent_key.uc, 0, sizeof(fd_pubkey_t) );
    n->elem.status = FD_FORK_STATUS_INPROGRESS;
    return -1;
  }

  if( n->elem.status == FD_FORK_STATUS_INPROGRESS ) {
    /* The block is in progress, we should append to it */
    n = fd_active_block_t_map_remove( fork_mgr->active_block_pool, &fork_mgr->active_block_root, n );
    memcpy( n->elem.key.uc, mircoblock_info->microblock_hdr.hash, sizeof(fd_hash_t) );
    n->elem.microblock_infos[n->elem.microblock_infos_cnt++] = mircoblock_info;
    fd_active_block_t_map_insert( fork_mgr->active_block_pool, &fork_mgr->active_block_root, n );  
    
    return 0;
  } else if ( n->elem.status == FD_FORK_STATUS_COMPLETE ) {
    /* The found block is complete, we should make a new block */
    fd_active_block_t_mapnode_t * child_node = fd_active_block_t_map_acquire( fork_mgr->active_block_pool );
    memcpy( child_node->elem.key.uc, mircoblock_info->microblock_hdr.hash, sizeof(fd_hash_t) );
    child_node->elem.microblock_infos_cnt = 1;
    child_node->elem.microblock_infos[0] = mircoblock_info;
    child_node->elem.child_keys_cnt = 0;
    child_node->elem.parent_key = n->elem.key;
    child_node->elem.status = FD_FORK_STATUS_INPROGRESS;
    fd_active_block_t_map_insert( fork_mgr->active_block_pool, &fork_mgr->active_block_root, child_node );

    n->elem.child_keys[n->elem.child_keys_cnt++] = child_node->elem.key;
    return 0;
  }

  return -1;
}

int
fd_fork_mgr_merge_blocks( void ) {
  return -1;
}

int
fd_fork_mgr_set_root_block( void ) {
  return -1;
}

int
fd_fork_mgr_get_heads( fd_fork_mgr_t const * fork_mgr,
                       fd_pubkey_t * out_heads,
                       ulong out_heads_capacity,
                       ulong * out_heads_sz ) {
  ulong heads_sz = 0;
  for( fd_active_block_t_mapnode_t const * n = fd_active_block_t_map_minimum_const( fork_mgr->active_block_pool, fork_mgr->active_block_root ); 
       n; 
       n = fd_active_block_t_map_successor_const( fork_mgr->active_block_pool, n ) 
  ) {
    if( n->elem.child_keys_cnt == 0 ) {
      out_heads[heads_sz] = n->elem.key;
      heads_sz++;
      if( heads_sz > out_heads_capacity ) {
        return -1;
      }
    }
  }

  *out_heads_sz = heads_sz;
  
  return 0;
}

int
fd_fork_mgr_get_dead_forks( void ) {
  return -1;
}
