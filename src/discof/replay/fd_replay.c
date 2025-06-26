#include "fd_replay.h"

void
leader_pipeline( void ) {
  return;
}

// after_credit
//
    /**********************************************************************/
    /* Consensus: decide (1) the fork for pack; (2) the fork to vote on   */
    /**********************************************************************/

    // ulong reset_slot = fd_tower_reset_slot( ctx->tower, ctx->epoch, ctx->ghost );
    // fd_fork_t const * reset_fork = fd_forks_query_const( ctx->forks, reset_slot );
    // if( FD_UNLIKELY( !reset_fork ) ) {
    //   FD_LOG_ERR( ( "failed to find reset fork %lu", reset_slot ) );
    // }
    // if( reset_fork->lock ) {
    //   FD_LOG_WARNING(("RESET FORK FROZEN: %lu", reset_fork->slot ));
    //   fd_fork_t * new_reset_fork = fd_forks_prepare( ctx->forks, reset_fork->slot_ctx->slot_bank.prev_slot, ctx->funk,
    //                                                  ctx->blockstore, ctx->epoch_ctx, ctx->runtime_spad );
    //   new_reset_fork->lock = 0;
    //   reset_fork = new_reset_fork;
    // }

    // ulong bank_idx    = ctx->bank_idx;
    // ulong                 txn_cnt  = ctx->txn_cnt;
    // fd_replay_out_ctx_t * bank_out = &ctx->bank_out[ bank_idx ];
    // fd_txn_p_t *          txns     = (fd_txn_p_t *)fd_chunk_to_laddr( bank_out->mem, bank_out->chunk );

    // if( FD_UNLIKELY( !ctx->startup_init_done && ctx->replay_plugin_out_mem ) ) {
    //   ctx->startup_init_done = 1;
    //   uchar msg[ 56 ];
    //   fd_memset( msg, 0, sizeof(msg) );
    //   msg[ 0 ] = 11; // ValidatorStartProgress::Running
    //   replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_START_PROGRESS, msg, sizeof(msg) );
    // }

    // /* Update the gui */
    // if( ctx->replay_plugin_out_mem ) {
    //   /* FIXME. We need a more efficient way to compute the ancestor chain. */
    //   uchar msg[4098*8] __attribute__( ( aligned( 8U ) ) );
    //   fd_memset( msg, 0, sizeof(msg) );
    //   ulong s = reset_fork->slot_ctx->slot;
    //   *(ulong*)(msg + 16U) = s;
    //   ulong i = 0;
    //   do {
    //     if( !fd_blockstore_block_info_test( ctx->blockstore, s ) ) {
    //       break;
    //     }
    //     s = fd_blockstore_parent_slot_query( ctx->blockstore, s );
    //     if( s < ctx->blockstore->shmem->wmk ) {
    //       break;
    //     }

    //     *(ulong*)(msg + 24U + i*8U) = s;
    //     if( ++i == 4095U ) {
    //       break;
    //     }
    //   } while( 1 );
    //   *(ulong*)(msg + 8U) = i;
    //   replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_SLOT_RESET, msg, sizeof(msg) );
    // }

    // fd_microblock_trailer_t * microblock_trailer = (fd_microblock_trailer_t *)(txns + txn_cnt);
    // memcpy( microblock_trailer->hash, reset_fork->slot_ctx->slot_bank.block_hash_queue.last_hash->uc, sizeof(fd_hash_t) );
    // if( ctx->poh_init_done == 1 ) {
    //   ulong parent_slot = reset_fork->slot_ctx->slot_bank.prev_slot;
    //   ulong curr_slot = reset_fork->slot_ctx->slot;
    //   FD_LOG_DEBUG(( "publishing mblk to poh - slot: %lu, parent_slot: %lu, flags: %lx", curr_slot, parent_slot, flags ));
    //   ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
    //   ulong sig = fd_disco_replay_old_sig( curr_slot, flags );
    //   fd_mcache_publish( bank_out->mcache, bank_out->depth, bank_out->seq, sig, bank_out->chunk, txn_cnt, 0UL, 0, tspub );
    //   bank_out->chunk = fd_dcache_compact_next( bank_out->chunk, (txn_cnt * sizeof(fd_txn_p_t)) + sizeof(fd_microblock_trailer_t), bank_out->chunk0, bank_out->wmark );
    //   bank_out->seq = fd_seq_inc( bank_out->seq, 1UL );
    // } else {
    //   FD_LOG_DEBUG(( "NOT publishing mblk to poh - slot: %lu, parent_slot: %lu, flags: %lx", curr_slot, ctx->parent_slot, flags ));
    // }

// during_frag
//
// if( in_idx == PACK_IN_IDX ) {
//     if( FD_UNLIKELY( chunk<ctx->pack_in_chunk0 || chunk>ctx->pack_in_wmark || sz>USHORT_MAX ) ) {
//       FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->pack_in_chunk0, ctx->pack_in_wmark ));
//     }
//     uchar * src = (uchar *)fd_chunk_to_laddr( ctx->pack_in_mem, chunk );
//     /* Incoming packet from pack tile. Format:
//        Microblock as a list of fd_txn_p_t (sz * sizeof(fd_txn_p_t))
//        Microblock bank trailer
//     */
//     ctx->curr_slot = fd_disco_poh_sig_slot( sig );
//     if( FD_UNLIKELY( ctx->curr_slot < fd_fseq_query( ctx->published_wmark ) ) ) {
//       FD_LOG_WARNING(( "pack sent slot %lu before our watermark %lu.", ctx->curr_slot, fd_fseq_query( ctx->published_wmark ) ));
//     }
//     if( fd_disco_poh_sig_pkt_type( sig )==POH_PKT_TYPE_MICROBLOCK ) {
//       ulong bank_idx = fd_disco_poh_sig_bank_tile( sig );
//       fd_replay_out_ctx_t * bank_out = &ctx->bank_out[ bank_idx ];
//       uchar * dst_poh = fd_chunk_to_laddr( bank_out->mem, bank_out->chunk );
//       ctx->flags = REPLAY_FLAG_PACKED_MICROBLOCK;
//       ctx->txn_cnt = (sz - sizeof(fd_microblock_bank_trailer_t)) / sizeof(fd_txn_p_t);
//       ctx->bank_idx = bank_idx;
//       fd_memcpy( dst_poh, src, (sz - sizeof(fd_microblock_bank_trailer_t)) );
//       src += (sz-sizeof(fd_microblock_bank_trailer_t));
//       dst_poh += (sz - sizeof(fd_microblock_bank_trailer_t));
//       fd_microblock_bank_trailer_t * t = (fd_microblock_bank_trailer_t *)src;
//       ctx->parent_slot = (ulong)t->bank;
//     } else {
//       FD_LOG_WARNING(("OTHER PACKET TYPE: %lu", fd_disco_poh_sig_pkt_type( sig )));
//       ctx->skip_frag = 1;
//       return;
//     }

//     FD_LOG_DEBUG(( "packed microblock - slot: %lu, parent_slot: %lu, txn_cnt: %lu", ctx->curr_slot, ctx->parent_slot, ctx->txn_cnt ));
//   }
  // if( ctx->flags & REPLAY_FLAG_PACKED_MICROBLOCK ) {
  //   /* We do not know the parent slot, pick one from fork selection */
  //   ulong max_slot = 0; /* FIXME: default to snapshot slot/smr */
  //   for( fd_fork_frontier_iter_t iter = fd_fork_frontier_iter_init( ctx->forks->frontier, ctx->forks->pool );
  //      !fd_fork_frontier_iter_done( iter, ctx->forks->frontier, ctx->forks->pool );
  //      iter = fd_fork_frontier_iter_next( iter, ctx->forks->frontier, ctx->forks->pool ) ) {
  //     fd_exec_slot_ctx_t * ele = &fd_fork_frontier_iter_ele( iter, ctx->forks->frontier, ctx->forks->pool )->slot_ctx;
  //     if ( max_slot < ele->slot_bank.slot ) {
  //       max_slot = ele->slot_bank.slot;
  //     }
  //   }
  //   ctx->parent_slot = max_slot;
  // }

  /*uchar block_flags = 0;
  int err = FD_MAP_ERR_AGAIN;
  while( err == FD_MAP_ERR_AGAIN ){
    fd_block_map_query_t quer[1] = { 0 };
    err = fd_block_map_query_try( ctx->blockstore->block_map, &ctx->curr_slot, NULL, quer, 0 );
    fd_block_info_t * block_info = fd_block_map_query_ele( quer );
    if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY )) break;
    block_flags = block_info->flags;
    err = fd_block_map_query_test( quer );
  }

  if( FD_UNLIKELY( fd_uchar_extract_bit( block_flags, FD_BLOCK_FLAG_PROCESSED ) ) ) {
    FD_LOG_WARNING(( "block already processed - slot: %lu", ctx->curr_slot ));
    ctx->skip_frag = 1;
  }
  if( FD_UNLIKELY( fd_uchar_extract_bit( block_flags, FD_BLOCK_FLAG_DEADBLOCK ) ) ) {
    FD_LOG_WARNING(( "block already dead - slot: %lu", ctx->curr_slot ));
    ctx->skip_frag = 1;
  }*/

  // after_frag
  //
  // /**********************************************************************/
  // /* The rest of after_frag replays some microblocks in block curr_slot */
  // /**********************************************************************/

  // ulong curr_slot   = ctx->curr_slot;
  // ulong flags       = ctx->flags;
  // ulong bank_idx    = ctx->bank_idx;

  // fd_fork_t * fork = fd_fork_frontier_ele_query( ctx->forks->frontier, &ctx->curr_slot, NULL, ctx->forks->pool );

  // /**********************************************************************/
  // /* Execute the transactions which were gathered                       */
  // /**********************************************************************/

  // ulong                 txn_cnt  = ctx->txn_cnt;
  // fd_replay_out_ctx_t * bank_out = &ctx->bank_out[ bank_idx ];
  // fd_txn_p_t *          txns     = (fd_txn_p_t *)fd_chunk_to_laddr( bank_out->mem, bank_out->chunk );

  // //Execute all txns which were successfully prepared
  // ctx->metrics.slot = curr_slot;
  // if( flags & REPLAY_FLAG_PACKED_MICROBLOCK ) {
  //   /* TODO: The leader pipeline execution needs to be optimized. This is
  //      very hacky and suboptimal. First, wait for the tpool workers to be idle.
  //      Then, execute the transactions, and notify the pack tile. We should be
  //      taking advantage of bank_busy flags.

  //      FIXME: It is currently not working and the below commented out
  //      code corresponds to executing packed microblocks. */

  //   // for( ulong i=1UL; i<ctx->exec_spad_cnt; i++ ) {
  //   //   fd_tpool_wait( ctx->tpool, i );
  //   // }

  //   // fd_runtime_process_txns_in_microblock_stream( ctx->slot_ctx,
  //   //                                               ctx->capture_ctx,
  //   //                                               txns,
  //   //                                               txn_cnt,
  //   //                                               ctx->tpool,
  //   //                                               ctx->exec_spads,
  //   //                                               ctx->exec_spad_cnt,
  //   //                                               ctx->runtime_spad,
  //   //                                               NULL );

  //   fd_microblock_trailer_t * microblock_trailer = (fd_microblock_trailer_t *)(txns + txn_cnt);

  //   hash_transactions( ctx->bmtree[ bank_idx ], txns, txn_cnt, microblock_trailer->hash );

  //   ulong sig = fd_disco_replay_old_sig( curr_slot, flags );
  //   fd_mcache_publish( bank_out->mcache, bank_out->depth, bank_out->seq, sig, bank_out->chunk, txn_cnt, 0UL, 0UL, 0UL );
  //   bank_out->chunk = fd_dcache_compact_next( bank_out->chunk, (txn_cnt * sizeof(fd_txn_p_t)) + sizeof(fd_microblock_trailer_t), bank_out->chunk0, bank_out->wmark );
  //   bank_out->seq = fd_seq_inc( bank_out->seq, 1UL );

  //   /* Indicate to pack tile we are done processing the transactions so it
  //     can pack new microblocks using these accounts.  DO NOT USE THE
  //     SANITIZED TRANSACTIONS AFTER THIS POINT, THEY ARE NO LONGER VALID. */
  //   fd_fseq_update( ctx->bank_busy[ bank_idx ], seq );

  //   publish_account_notifications( ctx, fork, curr_slot, txns, txn_cnt );
  // }

  // /**********************************************************************/
  // /* Init PoH if it is ready                                            */
  // /**********************************************************************/

  // if( FD_UNLIKELY( !(flags & REPLAY_FLAG_CATCHING_UP) && ctx->poh_init_done == 0 && ctx->blockstore ) ) {
  //   init_poh( ctx );
  // }

  // /**********************************************************************/
  // /* Publish mblk to POH                                                */
  // /**********************************************************************/

  // if( ctx->poh_init_done == 1 && !( flags & REPLAY_FLAG_FINISHED_BLOCK )
  //     && ( ( flags & REPLAY_FLAG_MICROBLOCK ) ) ) {
  //   // FD_LOG_INFO(( "publishing mblk to poh - slot: %lu, parent_slot: %lu", curr_slot, ctx->parent_slot ));
  //   ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  //   ulong sig = fd_disco_replay_old_sig( curr_slot, flags );
  //   fd_mcache_publish( bank_out->mcache, bank_out->depth, bank_out->seq, sig, bank_out->chunk, txn_cnt, 0UL, tsorig, tspub );
  //   bank_out->chunk = fd_dcache_compact_next( bank_out->chunk, (txn_cnt * sizeof(fd_txn_p_t)) + sizeof(fd_microblock_trailer_t), bank_out->chunk0, bank_out->wmark );
  //   bank_out->seq = fd_seq_inc( bank_out->seq, 1UL );
  // } else {
  //   FD_LOG_DEBUG(( "NOT publishing mblk to poh - slot: %lu, parent_slot: %lu, flags: %lx", curr_slot, ctx->parent_slot, flags ));
  // }
