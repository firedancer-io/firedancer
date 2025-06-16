#include "../../disco/tiles.h"
#include "generated/fd_exec_tile_seccomp.h"

#include "../../util/pod/fd_pod_format.h"

#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_runtime_public.h"
#include "../../flamenco/runtime/fd_executor.h"
#include "../../flamenco/runtime/fd_hashes.h"
#include "../../flamenco/runtime/program/fd_bpf_program_util.h"

#include "../../funk/fd_funk.h"

struct fd_exec_tile_out_ctx {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk;
  ulong       chunk0;
  ulong       wmark;
};
typedef struct fd_exec_tile_out_ctx fd_exec_tile_out_ctx_t;

struct fd_exec_tile_ctx {

  /* link-related data structures. */
  ulong                 replay_exec_in_idx;
  ulong                 tile_cnt;
  ulong                 tile_idx;

  fd_wksp_t *           replay_in_mem;
  ulong                 replay_in_chunk0;
  ulong                 replay_in_wmark;

  fd_exec_tile_out_ctx_t exec_writer_out[ 1 ];
  uchar                  boot_msg_sent;

  /* Runtime public and local joins of its members. */
  fd_wksp_t *           runtime_public_wksp;
  fd_runtime_public_t * runtime_public;
  fd_spad_t const *     runtime_spad;

  /* Management around exec spad and frame lifetimes.

     We will always have at least 1 frame pushed onto the exec spad.
     This frame will contain the txn_ctx. The replay tile will propogate
     new slot and new epoch messages to the exec tile at the start of a
     new epoch or at the start of a new slot. These messages will live
     in their own frames so that they have distinct lifetimes. We expect
     to recieve an update for a new epoch first: this will live inside
     of the second spad frame. Then all allocations made at the start of
     a new slot will live in the third spad frame. The following
     frame(s) will be used for the execution of the current transaction.
     The pending_{n}_pop variables are used to manage lifetimes for
     txn/slot/epoch updates. We need frames for the epoch and slot to
     store information that is copied into the exec tile at every
     epoch/slot.

     Examples:

     Start of a new transaction:
       * If pending_txn_pop==1:
         State before new transaction message received:
         | txn_ctx frame | epoch frame | slot frame | prev txn frame |
         State after new transaction message received:
         * The prev txn's frame is popped off because pending_txn_pop==1.
         | txn_ctx frame | epoch frame | slot frame |
         * A new frame is pushed onto the exec spad for the new transaction.
         | txn_ctx frame | epoch frame | slot frame | new txn frame |
         * pending_txn_pop is set to 1 to indicate that we need to pop
           the txn frame at the start of the next transaction.
      * If pending_txn_pop==0:
         State before new transaction message received:
         * Because there is no pending_txn_pop we know that there is no
           frame for a previous transaction; this implies that this is
           the first transaction in the slot
         | txn_ctx frame | epoch frame | slot frame |
         State after new transaction message received:
         * A new frame is pushed onto the exec spad for the new transaction.
         | txn_ctx frame | epoch frame | slot frame | new txn frame |
         * pending_txn_pop is set to 1 to indicate that we need to pop
           the txn frame at the start of the next transaction.

      Start of a new slot:
      * If pending_slot_pop==1:
        State before new slot message received (assuming the previous slot had txns):
        | txn_ctx frame | epoch frame | prev slot frame | prev txn frame |
        State after new slot message received:
        * The prev txn's frame is popped off because pending_txn_pop==1. (see above)
        * The prev slot's frame is also popped off because pending_slot_pop==1.
        | txn_ctx frame | epoch frame |
        * A new frame is pushed onto the exec spad for the new slot.
        | txn_ctx frame | epoch frame | slot frame |
        * pending_slot_pop is set to 1 to indicate that we need to pop
          the slot frame at the start of the next slot.
      * If pending_slot_pop==0:
        State before new slot message received:
        * Because there is no pending_slot_pop we know that there is no
          slot frame for a previous slot; this implies that this is the
          first slot in the current epoch. This also implies that there
          can be no pending txn frame that needs to get popped on.
        | txn_ctx frame | epoch frame |
        State after new slot message received:
        * A new frame is pushed onto the exec spad for the new slot.
        | txn_ctx frame | epoch frame | slot frame |
        * pending_slot_pop is set to 1 to indicate that we need to pop
          the slot frame at the start of the next slot.

      ... This same principle extends to dealing with new epoch scoped
      spad frames.

   */
  fd_spad_t *           exec_spad;
  fd_wksp_t *           exec_spad_wksp;
  int                   pending_txn_pop;
  int                   pending_slot_pop;
  int                   pending_epoch_pop;

  fd_funk_t             funk[1];

  /* Data structures related to managing and executing the transaction.
     The fd_txn_p_t is refreshed with every transaction and is sent
     from the dispatch/replay tile. The fd_exec_txn_ctx_t * is a valid
     local join that lives in the top-most frame of the spad that is
     setup when the exec tile is booted; its members are refreshed on
     the slot/epoch boundary. */
  fd_txn_p_t            txn;
  fd_exec_txn_ctx_t *   txn_ctx;
  int                   exec_res;

  /* The txn/bpf id are sequence numbers. */
  /* The txn id is a value that is monotonically increased after
     executing a transaction. It is used to prevent race conditions in
     interactions between the exec and replay tile. It is expected to
     overflow back to 0. */
  uint                  txn_id;
  /* The bpf id is the txn_id counterparts for updates to the bpf cache. */
  uint                  bpf_id;

  ulong *               exec_fseq;

  /* Pairs len is the number of accounts to hash. */
  ulong                 pairs_len;
};
typedef struct fd_exec_tile_ctx fd_exec_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  /* clang-format off */
  ulong l = FD_LAYOUT_INIT;
  l       = FD_LAYOUT_APPEND( l, alignof(fd_exec_tile_ctx_t),  sizeof(fd_exec_tile_ctx_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
  /* clang-format on */
}

static void
prepare_new_epoch_execution( fd_exec_tile_ctx_t *            ctx,
                             fd_runtime_public_epoch_msg_t * epoch_msg ) {

  /* If we need to refresh epoch-level information, we need to pop off
     the transaction-level, slot-level, and epoch-level frames.

     TODO: Epoch-level information should probably live in its own spad. */
  if( FD_LIKELY( ctx->pending_txn_pop ) ) {
    fd_spad_pop( ctx->exec_spad );
    ctx->pending_txn_pop = 0;
  }
  if( FD_LIKELY( ctx->pending_slot_pop ) ) {
    fd_spad_pop( ctx->exec_spad );
    ctx->pending_slot_pop = 0;
  }
  if( FD_LIKELY( ctx->pending_epoch_pop ) ) {
    fd_spad_pop( ctx->exec_spad );
    ctx->pending_epoch_pop = 0;
  }
  fd_spad_push( ctx->exec_spad );
  ctx->pending_epoch_pop = 1;

  ctx->txn_ctx->features          = epoch_msg->features;
  ctx->txn_ctx->total_epoch_stake = epoch_msg->total_epoch_stake;
  ctx->txn_ctx->schedule          = epoch_msg->epoch_schedule;
  ctx->txn_ctx->rent              = epoch_msg->rent;
  ctx->txn_ctx->slots_per_year    = epoch_msg->slots_per_year;

  uchar * stakes_enc = fd_wksp_laddr_fast( ctx->runtime_public_wksp, epoch_msg->stakes_encoded_gaddr );
  if( FD_UNLIKELY( !stakes_enc ) ) {
    FD_LOG_ERR(( "Could not get laddr for encoded stakes" ));
  }

  // FIXME account for this in exec spad footprint
  int err;
  fd_stakes_delegation_t * stakes = fd_bincode_decode_spad( stakes_delegation, ctx->exec_spad, stakes_enc, epoch_msg->stakes_encoded_sz, &err );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Could not decode stakes" ));
  }
  ctx->txn_ctx->stakes = *stakes;

  /* TODO: The bank hash cmp obj can likely be shared once at boot and
      there is no need to pass it forward every epoch. The proper
      solution here is probably to create a new message type. */
  fd_bank_hash_cmp_t * bank_hash_cmp_local = fd_bank_hash_cmp_join( fd_wksp_laddr_fast( ctx->runtime_public_wksp, epoch_msg->bank_hash_cmp_gaddr ) );
  if( FD_UNLIKELY( !bank_hash_cmp_local ) ) {
    FD_LOG_ERR(( "Could not get laddr for bank hash cmp" ));
  }
  ctx->txn_ctx->bank_hash_cmp = bank_hash_cmp_local;
}

static void
prepare_new_slot_execution( fd_exec_tile_ctx_t *           ctx,
                            fd_runtime_public_slot_msg_t * slot_msg ) {

  /* If we need to refresh slot-level information, we need to pop off
     the transaction-level and slot-level frame. */
  if( FD_LIKELY( ctx->pending_txn_pop ) ) {
    fd_spad_pop( ctx->exec_spad );
    ctx->pending_txn_pop = 0;
  }
  if( FD_LIKELY( ctx->pending_slot_pop ) ) {
    fd_spad_pop( ctx->exec_spad );
    ctx->pending_slot_pop = 0;
  }
  fd_spad_push( ctx->exec_spad );
  ctx->pending_slot_pop = 1;

  fd_funk_txn_map_t * txn_map = fd_funk_txn_map( ctx->funk );
  if( FD_UNLIKELY( !txn_map->map ) ) {
    FD_LOG_ERR(( "Could not find valid funk transaction map" ));
  }
  fd_funk_txn_xid_t xid = { .ul = { slot_msg->slot, slot_msg->slot } };
  fd_funk_txn_start_read( ctx->funk );
  fd_funk_txn_t * funk_txn = fd_funk_txn_query( &xid, txn_map );
  if( FD_UNLIKELY( !funk_txn ) ) {
    FD_LOG_ERR(( "Could not find valid funk transaction" ));
  }
  fd_funk_txn_end_read( ctx->funk );
  ctx->txn_ctx->funk_txn = funk_txn;

  ctx->txn_ctx->slot                        = slot_msg->slot;
  ctx->txn_ctx->prev_lamports_per_signature = slot_msg->prev_lamports_per_signature;
  ctx->txn_ctx->fee_rate_governor           = slot_msg->fee_rate_governor;
  ctx->txn_ctx->enable_exec_recording       = slot_msg->enable_exec_recording;

  uchar * block_hash_queue_enc = fd_wksp_laddr_fast( ctx->runtime_public_wksp, slot_msg->block_hash_queue_encoded_gaddr );
  if( FD_UNLIKELY( !block_hash_queue_enc ) ) {
    FD_LOG_ERR(( "Could not get laddr for encoded block hash queue" ));
  }

  // FIXME account for this in exec spad footprint
  int err;
  fd_block_hash_queue_t * block_hash_queue = fd_bincode_decode_spad(
      block_hash_queue, ctx->exec_spad,
      block_hash_queue_enc, slot_msg->block_hash_queue_encoded_sz,
      &err );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Could not decode block hash queue footprint" ));
  }

  ctx->txn_ctx->block_hash_queue = *block_hash_queue;
}

static void
execute_txn( fd_exec_tile_ctx_t * ctx ) {
  if( FD_LIKELY( ctx->pending_txn_pop ) ) {
    fd_spad_pop( ctx->exec_spad );
    ctx->pending_txn_pop = 0;
  }
  fd_spad_push( ctx->exec_spad );
  ctx->pending_txn_pop = 1;

  fd_execute_txn_task_info_t task_info = {
    .txn_ctx  = ctx->txn_ctx,
    .exec_res = 0,
    .txn      = &ctx->txn,
  };

  fd_txn_t const * txn_descriptor = TXN( task_info.txn );
  fd_rawtxn_b_t    raw_txn        = {
    .raw    = task_info.txn->payload,
    .txn_sz = (ushort)task_info.txn->payload_sz
  };

  task_info.txn->flags = FD_TXN_P_FLAGS_SANITIZE_SUCCESS;

  fd_exec_txn_ctx_setup( ctx->txn_ctx, txn_descriptor, &raw_txn );

  int err = fd_executor_setup_accessed_accounts_for_txn( ctx->txn_ctx );
  if( FD_UNLIKELY( err ) ) {
    task_info.txn->flags = 0U;
    task_info.exec_res   = err;
    return;
  }

  if( FD_UNLIKELY( fd_executor_txn_verify( ctx->txn_ctx )!=0 ) ) {
    FD_LOG_WARNING(( "sigverify failed: %s", FD_BASE58_ENC_64_ALLOCA( (uchar *)ctx->txn_ctx->_txn_raw->raw+ctx->txn_ctx->txn_descriptor->signature_off ) ));
    task_info.txn->flags = 0U;
    task_info.exec_res   = FD_RUNTIME_TXN_ERR_SIGNATURE_FAILURE;
    return;
  }

  fd_runtime_pre_execute_check( &task_info, 0 );
  if( FD_UNLIKELY( !( task_info.txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) ) {
    return;
  }

  /* Execute */
  task_info.txn->flags |= FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
  ctx->exec_res         = fd_execute_txn( &task_info );

  if( FD_LIKELY( ctx->exec_res==FD_EXECUTOR_INSTR_SUCCESS ) ) {
    fd_txn_reclaim_accounts( task_info.txn_ctx );
  }
}

//TODO hashing can be moved into the writer tile
static void
hash_accounts( fd_exec_tile_ctx_t *                ctx,
               fd_runtime_public_hash_bank_msg_t * msg ) {

  ulong start_idx = msg->start_idx;
  ulong end_idx   = msg->end_idx;

  fd_accounts_hash_task_info_t * task_info = fd_wksp_laddr_fast( ctx->runtime_public_wksp, msg->task_infos_gaddr );
  if( FD_UNLIKELY( !task_info ) ) {
    FD_LOG_ERR(( "Unable to join task info array" ));
  }

  if( FD_UNLIKELY( !msg->lthash_gaddr ) ) {
    FD_LOG_ERR(( "lthash gaddr is zero" ));
  }
  fd_lthash_value_t * lthash = fd_wksp_laddr_fast( ctx->runtime_public_wksp, msg->lthash_gaddr );
  if( FD_UNLIKELY( !lthash ) ) {
    FD_LOG_ERR(( "Unable to join lthash" ));
  }
  fd_lthash_zero( lthash );

  for( ulong i=start_idx; i<=end_idx; i++ ) {
    fd_account_hash( ctx->txn_ctx->funk,
                     ctx->txn_ctx->funk_txn,
                     &task_info[i],
                     lthash,
                     ctx->txn_ctx->slot,
                     &ctx->txn_ctx->features );
  }
}

static void
bpf_scan_accounts( fd_exec_tile_ctx_t *               ctx,
                   fd_runtime_public_bpf_scan_msg_t * msg ) {
  ulong                   start_idx = msg->start_idx;
  ulong                   end_idx   = msg->end_idx;

  fd_funk_rec_t const * * recs = fd_wksp_laddr_fast( ctx->runtime_public_wksp, msg->recs_gaddr );
  if( FD_UNLIKELY( !recs ) ) {
    FD_LOG_ERR(( "Unable to join recs" ));
  }
  uchar * is_bpf = fd_wksp_laddr_fast( ctx->runtime_public_wksp, msg->is_bpf_gaddr );
  if( FD_UNLIKELY( !is_bpf ) ) {
    FD_LOG_ERR(( "Unable to join is_bpf" ));
  }

  fd_wksp_t * wksp = fd_funk_wksp( ctx->txn_ctx->funk );
  for( ulong i=start_idx; i<=end_idx; i++ ) {
    fd_funk_rec_t const * rec = recs[ i ];
    fd_bpf_is_bpf_program( rec, wksp, &is_bpf[ i ] );
  }
}

static void
snap_hash_count( fd_exec_tile_ctx_t * ctx ) {
  ctx->pairs_len = fd_accounts_sorted_subrange_count( ctx->funk, (uint)ctx->tile_idx, (uint)ctx->tile_cnt );
}

static void
snap_hash_gather( fd_exec_tile_ctx_t *                ctx,
                  fd_runtime_public_snap_hash_msg_t * msg ) {

  ulong * num_pairs = fd_wksp_laddr_fast( ctx->runtime_public_wksp, msg->num_pairs_out_gaddr );
  if( FD_UNLIKELY( !num_pairs ) ) {
    FD_LOG_ERR(( "Unable to join num_pairs" ));
  }
  fd_pubkey_hash_pair_t * pairs = fd_wksp_laddr_fast( ctx->runtime_public_wksp, msg->pairs_gaddr );
  if( FD_UNLIKELY( !pairs ) ) {
    FD_LOG_ERR(( "Unable to join pairs" ));
  }
  fd_lthash_value_t * lthash_value = fd_wksp_laddr_fast( ctx->runtime_public_wksp, msg->lt_hash_value_out_gaddr );
  if( FD_UNLIKELY( !lthash_value ) ) {
    FD_LOG_ERR(( "Unable to join lthash values" ));
  }

  fd_accounts_sorted_subrange_gather( ctx->funk, (uint)ctx->tile_idx, (uint)ctx->tile_cnt,
                                      num_pairs, lthash_value,
                                      pairs, &ctx->runtime_public->features );
}

static void
during_frag( fd_exec_tile_ctx_t * ctx,
             ulong                in_idx,
             ulong                seq FD_PARAM_UNUSED,
             ulong                sig,
             ulong                chunk,
             ulong                sz,
             ulong                ctl FD_PARAM_UNUSED ) {

  if( FD_LIKELY( in_idx == ctx->replay_exec_in_idx ) ) {
    if( FD_UNLIKELY( chunk < ctx->replay_in_chunk0 || chunk > ctx->replay_in_wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]",
                    chunk,
                    sz,
                    ctx->replay_in_chunk0,
                    ctx->replay_in_wmark ));
    }

    if( FD_LIKELY( sig==EXEC_NEW_TXN_SIG ) ) {
      fd_runtime_public_txn_msg_t * txn = (fd_runtime_public_txn_msg_t *)fd_chunk_to_laddr( ctx->replay_in_mem, chunk );
      ctx->txn = txn->txn;
      execute_txn( ctx );
      return;
    } else if( sig==EXEC_NEW_SLOT_SIG ) {
      fd_runtime_public_slot_msg_t * msg = fd_chunk_to_laddr( ctx->replay_in_mem, chunk );
      FD_LOG_DEBUG(( "new slot=%lu msg recvd", msg->slot ));
      prepare_new_slot_execution( ctx, msg );
      return;
    } else if( sig==EXEC_NEW_EPOCH_SIG ) {
      fd_runtime_public_epoch_msg_t * msg = fd_chunk_to_laddr( ctx->replay_in_mem, chunk );
      FD_LOG_DEBUG(( "new epoch=%lu msg recvd", msg->epoch_schedule.slots_per_epoch ));
      prepare_new_epoch_execution( ctx, msg );
      return;
    } else if( sig==EXEC_HASH_ACCS_SIG ) {
      fd_runtime_public_hash_bank_msg_t * msg = fd_chunk_to_laddr( ctx->replay_in_mem, chunk );
      FD_LOG_DEBUG(( "hash accs=%lu msg recvd", msg->end_idx - msg->start_idx ));
      hash_accounts( ctx, msg );
      return;
    } else if( sig==EXEC_BPF_SCAN_SIG ) {
      fd_runtime_public_bpf_scan_msg_t * msg = fd_chunk_to_laddr( ctx->replay_in_mem, chunk );
      FD_LOG_DEBUG(( "bpf scan=%lu msg recvd", msg->end_idx - msg->start_idx ));
      bpf_scan_accounts( ctx, msg );
      return;
    } else if( sig==EXEC_SNAP_HASH_ACCS_CNT_SIG ) {
      FD_LOG_DEBUG(( "snap hash count msg recvd" ));
      snap_hash_count( ctx );
    } else if( sig==EXEC_SNAP_HASH_ACCS_GATHER_SIG ) {
      fd_runtime_public_snap_hash_msg_t * msg = fd_chunk_to_laddr( ctx->replay_in_mem, chunk );
      FD_LOG_DEBUG(( "snap hash gather msg recvd" ));
      snap_hash_gather( ctx, msg );
    } else {
      FD_LOG_ERR(( "Unknown signature" ));
    }
  }
}

static void
after_frag( fd_exec_tile_ctx_t * ctx,
            ulong                in_idx FD_PARAM_UNUSED,
            ulong                seq    FD_PARAM_UNUSED,
            ulong                sig,
            ulong                sz     FD_PARAM_UNUSED,
            ulong                tsorig,
            ulong                tspub,
            fd_stem_context_t *  stem ) {

  if( sig==EXEC_NEW_SLOT_SIG ) {
    FD_LOG_DEBUG(( "Sending ack for new slot msg" ));
    fd_fseq_update( ctx->exec_fseq, fd_exec_fseq_set_slot_done() );
  } else if( sig==EXEC_NEW_EPOCH_SIG ) {
    FD_LOG_DEBUG(( "Sending ack for new epoch msg" ));
    fd_fseq_update( ctx->exec_fseq, fd_exec_fseq_set_epoch_done() );

  } else if( sig==EXEC_NEW_TXN_SIG ) {
    FD_LOG_DEBUG(( "Sending ack for new txn msg" ));
    /* At this point we can assume that the transaction is done
       executing. A writer tile will be repsonsible for commiting
       the transaction back to funk. */
    ctx->txn_ctx->exec_err = ctx->exec_res;
    ctx->txn_ctx->flags    = ctx->txn.flags;

    fd_exec_tile_out_ctx_t * exec_out = ctx->exec_writer_out;

    fd_runtime_public_exec_writer_txn_msg_t * msg = fd_type_pun( fd_chunk_to_laddr( exec_out->mem, exec_out->chunk ) );
    msg->exec_tile_id = (uchar)ctx->tile_idx;
    msg->txn_id       = ctx->txn_id;

    fd_stem_publish( stem,
                     exec_out->idx,
                     FD_WRITER_TXN_SIG,
                     exec_out->chunk,
                     sizeof(*msg),
                     0UL,
                     tsorig,
                     tspub );
    exec_out->chunk = fd_dcache_compact_next( exec_out->chunk, sizeof(*msg), exec_out->chunk0, exec_out->wmark );

    /* Make sure that the txn/bpf id can never be equal to the sentinel
       value (this means that this is unintialized. )*/
    ctx->txn_id++;
    if( FD_UNLIKELY( ctx->txn_id==FD_EXEC_ID_SENTINEL ) ) {
      ctx->txn_id = 0U;
    }
  } else if( sig==EXEC_HASH_ACCS_SIG ) {
    FD_LOG_DEBUG(( "Sending ack for hash accs msg" ));
    fd_fseq_update( ctx->exec_fseq, fd_exec_fseq_set_hash_done() );
  } else if( sig==EXEC_BPF_SCAN_SIG ) {
    FD_LOG_DEBUG(( "Sending ack for bpf scan msg %u", ctx->bpf_id ));
    fd_fseq_update( ctx->exec_fseq, fd_exec_fseq_set_bpf_scan_done( ctx->bpf_id++ ) );
    if( FD_UNLIKELY( ctx->bpf_id==FD_EXEC_ID_SENTINEL ) ) {
      ctx->bpf_id = 0U;
    }
  } else if( sig==EXEC_SNAP_HASH_ACCS_CNT_SIG ) {
    FD_LOG_NOTICE(( "Sending ack for snap hash count msg pairs_len=%lu", ctx->pairs_len ));
    fd_fseq_update( ctx->exec_fseq, fd_exec_fseq_set_snap_hash_cnt_done( (uint)ctx->pairs_len ) );
  } else if( sig==EXEC_SNAP_HASH_ACCS_GATHER_SIG ) {
    FD_LOG_NOTICE(("Sending ack for snap hash gather msg" ));
    fd_fseq_update( ctx->exec_fseq, fd_exec_fseq_set_snap_hash_gather_done() );
  } else {
    FD_LOG_ERR(( "Unknown message signature" ));
  }
}

static void
privileged_init( fd_topo_t *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile FD_PARAM_UNUSED ) {
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  /********************************************************************/
  /* validate allocations                                             */
  /********************************************************************/

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_exec_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_tile_ctx_t), sizeof(fd_exec_tile_ctx_t) );
  ulong scratch_alloc_mem = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_alloc_mem - (ulong)scratch  - scratch_footprint( tile ) ) ) {
    FD_LOG_ERR( ( "Scratch_alloc_mem did not match scratch_footprint diff: %lu alloc: %lu footprint: %lu",
      scratch_alloc_mem - (ulong)scratch - scratch_footprint( tile ),
      scratch_alloc_mem,
      (ulong)scratch + scratch_footprint( tile ) ) );
  }

  /********************************************************************/
  /* validate links                                                   */
  /********************************************************************/

  ctx->tile_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->tile_idx = tile->kind_id;

  /* First find and setup the in-link from replay to exec. */
  ctx->replay_exec_in_idx = fd_topo_find_tile_in_link( topo, tile, "replay_exec", ctx->tile_idx );
  if( FD_UNLIKELY( ctx->replay_exec_in_idx==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Could not find replay_exec in-link" ));
  }
  fd_topo_link_t * replay_exec_in_link = &topo->links[tile->in_link_id[ctx->replay_exec_in_idx]];
  if( FD_UNLIKELY( !replay_exec_in_link) ) {
    FD_LOG_ERR(( "Invalid replay_exec in-link" ));
  }
  ctx->replay_in_mem    = topo->workspaces[topo->objs[replay_exec_in_link->dcache_obj_id].wksp_id].wksp;
  ctx->replay_in_chunk0 = fd_dcache_compact_chunk0( ctx->replay_in_mem, replay_exec_in_link->dcache );
  ctx->replay_in_wmark  = fd_dcache_compact_wmark( ctx->replay_in_mem,
                                                   replay_exec_in_link->dcache,
                                                   replay_exec_in_link->mtu );

  /* Setup out link. */
  ulong idx = fd_topo_find_tile_out_link( topo, tile, "exec_writer", ctx->tile_idx );
  fd_topo_link_t * exec_out_link = &topo->links[ tile->out_link_id[ idx ] ];

  if( strcmp( exec_out_link->name, "exec_writer" ) ) {
    FD_LOG_CRIT(("exec_writer link has unexpected name %s", exec_out_link->name ));
  }

  fd_exec_tile_out_ctx_t * exec_out = ctx->exec_writer_out;
  exec_out->idx                     = idx;
  exec_out->mem                     = topo->workspaces[ topo->objs[ exec_out_link->dcache_obj_id ].wksp_id ].wksp;
  exec_out->chunk0                  = fd_dcache_compact_chunk0( exec_out->mem, exec_out_link->dcache );
  exec_out->wmark                   = fd_dcache_compact_wmark( exec_out->mem, exec_out_link->dcache, exec_out_link->mtu );
  exec_out->chunk                   = exec_out->chunk0;
  ctx->boot_msg_sent                = 0U;

  /********************************************************************/
  /* runtime public                                                   */
  /********************************************************************/

  ulong runtime_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "runtime_pub" );
  if( FD_UNLIKELY( runtime_obj_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Could not find topology object for runtime public" ));
  }

  ctx->runtime_public_wksp = topo->workspaces[ topo->objs[ runtime_obj_id ].wksp_id ].wksp;
  if( FD_UNLIKELY( !ctx->runtime_public_wksp ) ) {
    FD_LOG_ERR(( "No runtime_public workspace" ));
  }

  ctx->runtime_public = fd_runtime_public_join( fd_topo_obj_laddr( topo, runtime_obj_id ) );
  if( FD_UNLIKELY( !ctx->runtime_public ) ) {
    FD_LOG_ERR(( "Failed to join runtime public" ));
  }

  ctx->runtime_spad = fd_runtime_public_spad( ctx->runtime_public );
  if( FD_UNLIKELY( !ctx->runtime_spad ) ) {
    FD_LOG_ERR(( "Failed to get and join runtime spad" ));
  }

  /********************************************************************/
  /* spad allocator                                                   */
  /********************************************************************/

  /* First join the correct exec spad and hten the correct runtime spad
     which lives inside of the runtime public wksp. */

  ulong exec_spad_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "exec_spad.%lu", ctx->tile_idx );
  if( FD_UNLIKELY( exec_spad_obj_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Could not find topology object for exec spad" ));
  }

  ctx->exec_spad = fd_spad_join( fd_topo_obj_laddr( topo, exec_spad_obj_id ) );
  if( FD_UNLIKELY( !ctx->exec_spad ) ) {
    FD_LOG_ERR(( "Failed to join exec spad" ));
  }
  ctx->exec_spad_wksp = fd_wksp_containing( ctx->exec_spad );

  ctx->pending_txn_pop   = 0;
  ctx->pending_slot_pop  = 0;
  ctx->pending_epoch_pop = 0;

  /********************************************************************/
  /* funk-specific setup                                              */
  /********************************************************************/

  if( FD_UNLIKELY( !fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->exec.funk_obj_id ) ) ) ) {
    FD_LOG_ERR(( "Failed to join database cache" ));
  }

  //FIXME
  /********************************************************************/
  /* setup txncache                                                   */
  /********************************************************************/

  /********************************************************************/
  /* setup txn ctx                                                    */
  /********************************************************************/

  fd_spad_push( ctx->exec_spad );
  // FIXME account for this in exec spad footprint
  uchar * txn_ctx_mem   = fd_spad_alloc_check( ctx->exec_spad, FD_EXEC_TXN_CTX_ALIGN, FD_EXEC_TXN_CTX_FOOTPRINT );
  ctx->txn_ctx          = fd_exec_txn_ctx_join( fd_exec_txn_ctx_new( txn_ctx_mem ), ctx->exec_spad, ctx->exec_spad_wksp );
  *ctx->txn_ctx->funk   = *ctx->funk;

  ctx->txn_ctx->runtime_pub_wksp = ctx->runtime_public_wksp;
  if( FD_UNLIKELY( !ctx->txn_ctx->runtime_pub_wksp ) ) {
    FD_LOG_ERR(( "Failed to find public wksp" ));
  }

  /********************************************************************/
  /* setup exec fseq                                                  */
  /********************************************************************/

  ulong exec_fseq_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "exec_fseq.%lu", ctx->tile_idx );
  ctx->exec_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, exec_fseq_id ) );
  if( FD_UNLIKELY( !ctx->exec_fseq ) ) {
    FD_LOG_ERR(( "exec tile %lu has no fseq", ctx->tile_idx ));
  }
  fd_fseq_update( ctx->exec_fseq, FD_EXEC_STATE_NOT_BOOTED );

  /* Initialize sequence numbers to be 0. */
  ctx->txn_id = 0U;
  ctx->bpf_id = 0U;

  FD_LOG_NOTICE(( "Done booting exec tile idx=%lu", ctx->tile_idx ));
}

static void
after_credit( fd_exec_tile_ctx_t * ctx,
              fd_stem_context_t *  stem,
              int *                opt_poll_in,
              int *                charge_busy ) {

  (void)opt_poll_in;
  (void)charge_busy;

  if( FD_UNLIKELY( !ctx->boot_msg_sent ) ) {
    ctx->boot_msg_sent = 1U;

    ulong txn_ctx_gaddr = fd_wksp_gaddr( ctx->exec_spad_wksp, ctx->txn_ctx );
    if( FD_UNLIKELY( !txn_ctx_gaddr ) ) {
      FD_LOG_CRIT(( "Could not get gaddr for txn_ctx" ));
    }

    ulong exec_spad_gaddr = fd_wksp_gaddr( ctx->exec_spad_wksp, ctx->exec_spad );
    if( FD_UNLIKELY( !exec_spad_gaddr ) ) {
      FD_LOG_CRIT(( "Could not get gaddr for exec_spad" ));
    }

    if( FD_UNLIKELY( txn_ctx_gaddr-exec_spad_gaddr>UINT_MAX ) ) {
      FD_LOG_CRIT(( "txn_ctx offset from exec spad is too large" ));
    }

    uint txn_ctx_offset = (uint)(txn_ctx_gaddr-exec_spad_gaddr);

    /* Notify writer tiles. */

    ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

    fd_exec_tile_out_ctx_t * exec_out = ctx->exec_writer_out;

    fd_runtime_public_exec_writer_boot_msg_t * msg = fd_type_pun( fd_chunk_to_laddr( exec_out->mem, exec_out->chunk ) );

    msg->txn_ctx_offset = txn_ctx_offset;

    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
    fd_stem_publish( stem,
                     exec_out->idx,
                     FD_WRITER_BOOT_SIG,
                     exec_out->chunk,
                     sizeof(*msg),
                     0UL,
                     tsorig,
                     tspub );
    exec_out->chunk = fd_dcache_compact_next( exec_out->chunk, sizeof(*msg), exec_out->chunk0, exec_out->wmark );

    /* Notify replay tile. */

    fd_fseq_update( ctx->exec_fseq, fd_exec_fseq_set_booted( txn_ctx_offset ) );
  }
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_exec_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_exec_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

/* The stem burst is bound by the max number of exec tiles that are
   posible. */
#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_exec_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_exec_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT after_credit
#define STEM_CALLBACK_DURING_FRAG  during_frag
#define STEM_CALLBACK_AFTER_FRAG   after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_execor = {
    .name                     = "exec",
    .loose_footprint          = 0UL,
    .populate_allowed_seccomp = populate_allowed_seccomp,
    .populate_allowed_fds     = populate_allowed_fds,
    .scratch_align            = scratch_align,
    .scratch_footprint        = scratch_footprint,
    .privileged_init          = privileged_init,
    .unprivileged_init        = unprivileged_init,
    .run                      = stem_run,
};
