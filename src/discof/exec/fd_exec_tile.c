#include "../../disco/tiles.h"
#include "generated/fd_exec_tile_seccomp.h"

#include "../../util/pod/fd_pod_format.h"
#include "../../flamenco/runtime/context/fd_capture_ctx.h"
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

  /* Shared bank hash cmp object. */
  fd_bank_hash_cmp_t * bank_hash_cmp;

  fd_spad_t *           exec_spad;
  fd_wksp_t *           exec_spad_wksp;

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

  /* Current slot being executed. */
  ulong                 slot;

  /* Current bank being executed. */
  fd_banks_t *          banks;
  fd_bank_t *           bank;

  fd_capture_ctx_t *    capture_ctx;
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
  l       = FD_LAYOUT_APPEND( l, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
  return FD_LAYOUT_FINI( l, scratch_align() );
  /* clang-format on */
}

static void
execute_txn( fd_exec_tile_ctx_t * ctx ) {

  FD_SPAD_FRAME_BEGIN( ctx->exec_spad ) {

  /* Query the funk transaction for the given slot. */
  fd_funk_txn_map_t * txn_map = fd_funk_txn_map( ctx->funk );
  if( FD_UNLIKELY( !txn_map->map ) ) {
    FD_LOG_ERR(( "Could not find valid funk transaction map" ));
  }
  fd_funk_txn_xid_t xid = { .ul = { ctx->slot, ctx->slot } };
  fd_funk_txn_start_read( ctx->funk );
  fd_funk_txn_t * funk_txn = fd_funk_txn_query( &xid, txn_map );
  if( FD_UNLIKELY( !funk_txn ) ) {
    FD_LOG_ERR(( "Could not find valid funk transaction" ));
  }
  fd_funk_txn_end_read( ctx->funk );
  ctx->txn_ctx->funk_txn = funk_txn;

  /* Get the bank for the given slot. */
  ctx->bank = fd_banks_get_bank( ctx->banks, ctx->slot );
  if( FD_UNLIKELY( !ctx->bank ) ) {
    FD_LOG_ERR(( "Could not get bank for slot %lu", ctx->slot ));
  }

  /* Setup and execute the transaction.*/
  ctx->txn_ctx->bank     = ctx->bank;
  ctx->txn_ctx->slot     = ctx->bank->slot;
  ctx->txn_ctx->features = fd_bank_features_get( ctx->bank );

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
  ctx->txn_ctx->capture_ctx = ctx->capture_ctx;

  /* Set up the core account keys. These are the account keys directly
     passed in via the serialized transaction, represented as an array.
     Note that this does not include additional keys referenced in
     address lookup tables. */
  fd_executor_setup_txn_account_keys( ctx->txn_ctx );

  if( FD_UNLIKELY( fd_executor_txn_verify( ctx->txn_ctx )!=0 ) ) {
    FD_LOG_WARNING(( "sigverify failed: %s", FD_BASE58_ENC_64_ALLOCA( (uchar *)ctx->txn_ctx->_txn_raw->raw+ctx->txn_ctx->txn_descriptor->signature_off ) ));
    task_info.txn->flags = 0U;
    task_info.exec_res   = FD_RUNTIME_TXN_ERR_SIGNATURE_FAILURE;
    return;
  }

  fd_runtime_pre_execute_check( &task_info );
  if( FD_UNLIKELY( !( task_info.txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS ) ) ) {
    return;
  }

  /* Execute */
  task_info.txn->flags |= FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
  ctx->exec_res         = fd_execute_txn( &task_info );

  if( FD_LIKELY( ctx->exec_res==FD_EXECUTOR_INSTR_SUCCESS ) ) {
    fd_txn_reclaim_accounts( task_info.txn_ctx );
  }

  } FD_SPAD_FRAME_END;
}

// TODO: hashing can be moved into the writer tile
static void
hash_accounts( fd_exec_tile_ctx_t *                ctx,
               fd_runtime_public_hash_bank_msg_t * msg ) {

  ctx->slot = msg->slot;
  fd_funk_txn_map_t * txn_map = fd_funk_txn_map( ctx->funk );
  if( FD_UNLIKELY( !txn_map->map ) ) {
    FD_LOG_ERR(( "Could not find valid funk transaction map" ));
  }
  fd_funk_txn_xid_t xid = { .ul = { ctx->slot, ctx->slot } };
  fd_funk_txn_start_read( ctx->funk );
  fd_funk_txn_t * funk_txn = fd_funk_txn_query( &xid, txn_map );
  if( FD_UNLIKELY( !funk_txn ) ) {
    FD_LOG_ERR(( "Could not find valid funk transaction" ));
  }
  fd_funk_txn_end_read( ctx->funk );
  ctx->txn_ctx->funk_txn = funk_txn;

  ctx->bank = fd_banks_get_bank( ctx->banks, ctx->slot );
  if( FD_UNLIKELY( !ctx->bank ) ) {
    FD_LOG_ERR(( "Could not get bank for slot %lu", ctx->slot ));
  }

  ctx->txn_ctx->bank     = ctx->bank;
  ctx->txn_ctx->slot     = ctx->bank->slot;

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
      ctx->txn  = txn->txn;
      ctx->slot = txn->slot;
      execute_txn( ctx );
      return;
    } else if( sig==EXEC_HASH_ACCS_SIG ) {
      fd_runtime_public_hash_bank_msg_t * msg = fd_chunk_to_laddr( ctx->replay_in_mem, chunk );
      FD_LOG_DEBUG(( "hash accs=%lu msg recvd", msg->end_idx - msg->start_idx ));
      hash_accounts( ctx, msg );
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

  if( sig==EXEC_NEW_TXN_SIG ) {
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
    fd_fseq_update( ctx->exec_fseq, fd_exec_fseq_set_hash_done( ctx->slot ) );
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
  fd_exec_tile_ctx_t * ctx               = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_tile_ctx_t), sizeof(fd_exec_tile_ctx_t) );
  void *               capture_ctx_mem   = FD_SCRATCH_ALLOC_APPEND( l, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
  ulong                scratch_alloc_mem = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
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
  /* banks                                                            */
  /********************************************************************/

  ulong banks_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "banks" );
  if( FD_UNLIKELY( banks_obj_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Could not find topology object for banks" ));
  }

  ctx->banks = fd_banks_join( fd_topo_obj_laddr( topo, banks_obj_id ) );
  if( FD_UNLIKELY( !ctx->banks ) ) {
    FD_LOG_ERR(( "Failed to join banks" ));
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

  /********************************************************************/
  /* bank hash cmp                                                    */
  /********************************************************************/

  ulong bank_hash_cmp_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "bh_cmp" );
  if( FD_UNLIKELY( bank_hash_cmp_obj_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Could not find topology object for bank hash cmp" ));
  }
  ctx->bank_hash_cmp = fd_bank_hash_cmp_join( fd_topo_obj_laddr( topo, bank_hash_cmp_obj_id ) );
  if( FD_UNLIKELY( !ctx->bank_hash_cmp ) ) {
    FD_LOG_ERR(( "Failed to join bank hash cmp" ));
  }

  /********************************************************************/
  /* funk-specific setup                                              */
  /********************************************************************/

  if( FD_UNLIKELY( !fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->exec.funk_obj_id ) ) ) ) {
    FD_LOG_ERR(( "Failed to join database cache" ));
  }

  /********************************************************************/
  /* setup txncache                                                   */
  /********************************************************************/

  /* TODO: Implement this. */

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

  ctx->txn_ctx->bank_hash_cmp = ctx->bank_hash_cmp;

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

  if( strlen(tile->exec.dump_proto_dir) > 0 ) {
    ctx->capture_ctx = fd_capture_ctx_new( capture_ctx_mem );
    ctx->capture_ctx->dump_proto_output_dir = tile->exec.dump_proto_dir;
    ctx->capture_ctx->dump_proto_start_slot = tile->exec.capture_start_slot;
    ctx->capture_ctx->dump_instr_to_pb = tile->exec.dump_instr_to_pb;
    ctx->capture_ctx->dump_txn_to_pb = tile->exec.dump_txn_to_pb;
    ctx->capture_ctx->dump_syscall_to_pb = tile->exec.dump_syscall_to_pb;
  } else {
    ctx->capture_ctx = NULL;
  }
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
