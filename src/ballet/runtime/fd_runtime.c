#include "fd_runtime.h"
#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar.h"

#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize ("O0")
#endif

// boot the global state at slot zero...
//
// We have an issue with a lot of the sysvars when we do not start at
// state zero or bounce around.  For example, if you bounce block_execute around,
// recent_hashes will make zero sense...

void
fd_runtime_boot_slot_zero( fd_global_ctx_t *global ) {
  fd_memcpy(global->poh.state, global->genesis_hash, sizeof(global->genesis_hash));
  global->poh_booted = 1;

  fd_sysvar_recent_hashes_init(global, 0);
  fd_sysvar_clock_init( global );
}

// fd_runtime_block_execute
//
// If you bounce around slots, the poh state
// will not match AND the sysvars will be set incorrectly.  Since the
// verify WILL also fail, the runtime will detect incorrect usage..

// TODO: add tracking account_state hashes so that we can verify our
// banks hash... this has interesting threading implications since we
// could execute the cryptography in another thread for tracking this
// but we don't actually have anything to compare it to until we hit
// another snapshot...  Probably we should just store the results into
// the global state (a slot/hash map)...

int
fd_runtime_block_execute( fd_global_ctx_t *global, fd_slot_blocks_t *slot_data ) {
  uchar *blob = slot_data->first_blob;
  uchar *blob_ptr = blob + FD_BLOB_DATA_START;
  uint   cnt = *((uint *) (blob + 8));

  if (0 == cnt) {
    // WHA?! . what is the correct behavior here?  what should the
    // sysvar_recent_hashes get set to?
    return FD_RUNTIME_EXECUTE_GENERIC_ERR;
  }

  // It sucks that we need to know the current block hash which is
  // stored at the END of the block.  Lets have a fever dream another
  // time and optimize this...
  while (cnt > 0) {
    fd_microblock_t * micro_block = fd_microblock_join( blob_ptr );

    blob_ptr = (uchar *) fd_ulong_align_up((ulong)blob_ptr + fd_microblock_footprint( micro_block->hdr.txn_cnt ), FD_MICROBLOCK_ALIGN);

    if (1 == cnt)
      fd_memcpy(global->block_hash, micro_block->hdr.hash, sizeof(micro_block->hdr.hash));
    fd_microblock_leave(micro_block);

    cnt--;
  } // while (cnt > 0)

  // TODO: move all these out to a fd_sysvar_update() call...
  fd_sysvar_clock_update( global);
  fd_sysvar_recent_hashes_update ( global, global->current_slot);

  blob = slot_data->first_blob;
  while (NULL != blob) {
    uchar *blob_ptr = blob + FD_BLOB_DATA_START;
    uint   cnt = *((uint *) (blob + 8));
    while (cnt > 0) {
      fd_microblock_t * micro_block = fd_microblock_join( blob_ptr );
      if (micro_block->txn_max_cnt > 0) {
        for ( ulong txn_idx = 0; txn_idx < micro_block->txn_max_cnt; txn_idx++ ) {
          fd_txn_t*      txn_descriptor = (fd_txn_t *)&micro_block->txn_tbl[ txn_idx ];
          fd_rawtxn_b_t* txn_raw   = (fd_rawtxn_b_t *)&micro_block->raw_tbl[ txn_idx ];
          // TODO: fork and commit a new funk_txn for each txn and properly
          // cancel if it fails
          fd_execute_txn( global->executor, txn_descriptor, txn_raw );
        }
      }
      fd_microblock_leave(micro_block);

      blob_ptr = (uchar *) fd_ulong_align_up((ulong)blob_ptr + fd_microblock_footprint( micro_block->hdr.txn_cnt ), FD_MICROBLOCK_ALIGN);

      cnt--;
    } // while (cnt > 0)
    blob = *((uchar **) blob);
  } // while (NULL != blob)

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

// TODO: add txn verify to this as well
int
fd_runtime_block_verify( fd_global_ctx_t *global, fd_slot_blocks_t *slot_data ) {
  if (NULL == slot_data) {
    FD_LOG_WARNING(("NULL slot passed to fd_runtime_block_execute at slot %ld", global->current_slot));
    return FD_RUNTIME_EXECUTE_GENERIC_ERR;
  }

  uchar *blob = slot_data->first_blob;
  while (NULL != blob) {
    uchar *blob_ptr = blob + FD_BLOB_DATA_START;
    uint   cnt = *((uint *) (blob + 8));
    while (cnt > 0) {
      fd_microblock_t * micro_block = fd_microblock_join( blob_ptr );
      if (micro_block->txn_max_cnt > 0) {
        if (micro_block->hdr.hash_cnt > 0)
          fd_poh_append(&global->poh, micro_block->hdr.hash_cnt - 1);
        uchar outhash[32];
        fd_microblock_mixin(micro_block, outhash);
        fd_poh_mixin(&global->poh, outhash);
      } else
        fd_poh_append(&global->poh, micro_block->hdr.hash_cnt);
      if (memcmp(micro_block->hdr.hash, global->poh.state, sizeof(global->poh.state))) {
        if (global->poh_booted)
          FD_LOG_ERR(( "poh missmatch at slot: %ld", global->current_slot));
        else {
          fd_memcpy(global->poh.state, micro_block->hdr.hash, sizeof(global->poh.state));
          global->poh_booted = 1;
        }
      }
      fd_microblock_leave(micro_block);

      blob_ptr = (uchar *) fd_ulong_align_up((ulong)blob_ptr + fd_microblock_footprint( micro_block->hdr.txn_cnt ), FD_MICROBLOCK_ALIGN);

      cnt--;
    } // while (cnt > 0)
    blob = *((uchar **) blob);
  } // while (NULL != blob)

  return FD_RUNTIME_EXECUTE_SUCCESS;
}

int
fd_runtime_block_eval( fd_global_ctx_t *global, fd_slot_blocks_t *slot_data ) {
  if (NULL == slot_data) {
    FD_LOG_WARNING(("NULL slot passed to fd_runtime_block_execute at slot %ld", global->current_slot));
    return FD_RUNTIME_EXECUTE_GENERIC_ERR;
  }
  uchar *blob = slot_data->last_blob;
  if (NULL == blob) {
    FD_LOG_WARNING(("empty slot passed to fd_runtime_block_execute at slot %ld", global->current_slot));
    return FD_RUNTIME_EXECUTE_GENERIC_ERR;
  }

  // The funk_txn needs to be a "tower" so that we can correctly
  // finalize...

  // TODO: funk_txn should just be a pointer to the top of the funk_txn stack
  ulong *p = (ulong *) &global->funk_txn.id[0];
  p[0] = fd_rng_ulong( global->rng);
  p[1] = fd_rng_ulong( global->rng);
  p[2] = fd_rng_ulong( global->rng);
  p[3] = fd_rng_ulong( global->rng);

  fd_funk_fork(global->funk, fd_funk_root(global->funk), &global->funk_txn);

  // This is simple now but really we need to execute block_verify in
  // its own thread/tile and IT needs to parallelize the
  // microblock verifies in that out into worker threads as well.
  //
  // Then, start executing the slot in the main thread, wait for the
  // block_verify to complete, and only return successful when the
  // verify threads complete successfully..

  int ret = fd_runtime_block_verify( global, slot_data );
  if (FD_RUNTIME_EXECUTE_SUCCESS != ret )
    return ret;

  ret = fd_runtime_block_execute( global, slot_data );
  if (FD_RUNTIME_EXECUTE_SUCCESS != ret ) {
    fd_funk_cancel(global->funk, &global->funk_txn);
    return ret;
  }

  // TODO: We should be committing finalized blocks... once we have a
  // "tower", we will remove this line..
  fd_funk_commit(global->funk, &global->funk_txn);

  return ret;
}
