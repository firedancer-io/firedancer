#include "fd_restart.h"

#include "../../disco/stem/fd_stem.h"
#include "../../disco/topo/fd_topo.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../flamenco/runtime/fd_runtime.h"

#define GOSSIP_IN_IDX  (0UL)
#define STORE_IN_IDX   (1UL)

#define GOSSIP_OUT_IDX (0UL)
#define STORE_OUT_IDX  (1UL)

struct fd_restart_tile_ctx {
  fd_restart_t *        restart;
  fd_funk_t             funk[1];
  int                   is_funk_active;
  fd_spad_t *           runtime_spad;
  int                   tower_checkpt_fileno;
  fd_pubkey_t           identity, coordinator, genesis_hash;
  fd_slot_pair_t *      new_hard_forks;
  ulong                 new_hard_forks_len;

  // Gossip tile output
  fd_frag_meta_t *      gossip_out_mcache;
  ulong *               gossip_out_sync;
  ulong                 gossip_out_depth;
  ulong                 gossip_out_seq;

  fd_wksp_t *           gossip_out_mem;
  ulong                 gossip_out_chunk0;
  ulong                 gossip_out_wmark;
  ulong                 gossip_out_chunk;

  // Gossip tile input
  fd_wksp_t *           gossip_in_mem;
  ulong                 gossip_in_chunk0;
  ulong                 gossip_in_wmark;
  uchar                 restart_gossip_msg[ FD_RESTART_LINK_BYTES_MAX+sizeof(uint) ];

  // Store tile output
  fd_frag_meta_t *      store_out_mcache;
  ulong *               store_out_sync;
  ulong                 store_out_depth;
  ulong                 store_out_seq;

  fd_wksp_t *           store_out_mem;
  ulong                 store_out_chunk0;
  ulong                 store_out_wmark;
  ulong                 store_out_chunk;

  // Store tile input
  fd_wksp_t *           store_in_mem;
  ulong                 store_in_chunk0;
  ulong                 store_in_wmark;
  fd_funk_txn_xid_t     store_xid_msg;
};
typedef struct fd_restart_tile_ctx fd_restart_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {

  /* Do not modify order! This is join-order in unprivileged_init. */
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_restart_tile_ctx_t), sizeof(fd_restart_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_restart_align(), fd_restart_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_spad_align(), fd_spad_footprint( tile->restart.heap_mem_max ) );
  l = FD_LAYOUT_FINI  ( l, scratch_align() );
  return l;
}

static void
privileged_init( fd_topo_t      * topo FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile ) {
  /**********************************************************************/
  /* tower checkpoint                                                   */
  /**********************************************************************/

  tile->restart.tower_checkpt_fileno = -1;
  if( FD_LIKELY( strlen( tile->restart.tower_checkpt )>0 ) ) {
    tile->restart.tower_checkpt_fileno  = open( tile->restart.tower_checkpt,
                                                O_RDWR | O_CREAT,
                                                S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH );
  }
}

static void
unprivileged_init( fd_topo_t      * topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_restart_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_restart_tile_ctx_t), sizeof(fd_restart_tile_ctx_t) );
  void * restart_mem          = FD_SCRATCH_ALLOC_APPEND( l, fd_restart_align(), fd_restart_footprint() );
  void * spad_mem             = FD_SCRATCH_ALLOC_APPEND( l, fd_spad_align(), fd_spad_footprint( tile->restart.heap_mem_max ) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  /**********************************************************************/
  /* restart                                                            */
  /**********************************************************************/

  ctx->restart = fd_restart_join( fd_restart_new( restart_mem ) );

  /**********************************************************************/
  /* funk                                                               */
  /**********************************************************************/

  if( FD_UNLIKELY( !fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->restart.funk_obj_id ) ) ) ) {
    FD_LOG_ERR(( "Failed to join database cache" ));
  }
  ctx->is_funk_active = 0;

  /**********************************************************************/
  /* spad                                                               */
  /**********************************************************************/

  ctx->runtime_spad = fd_spad_join( fd_spad_new( spad_mem, tile->restart.heap_mem_max ) );
  fd_spad_push( ctx->runtime_spad );

  /**********************************************************************/
  /* tower checkpoint                                                   */
  /**********************************************************************/

  ctx->tower_checkpt_fileno = tile->restart.tower_checkpt_fileno;
  if( ctx->tower_checkpt_fileno<0 ) FD_LOG_ERR(( "Failed at opening the tower checkpoint file %s", tile->restart.tower_checkpt ));

  /**********************************************************************/
  /* hash and pubkeys                                                   */
  /**********************************************************************/

  fd_base58_decode_32( tile->restart.restart_coordinator, ctx->coordinator.key );
  fd_base58_decode_32( tile->restart.genesis_hash, ctx->genesis_hash.key );
  ctx->identity = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->restart.identity_key_path, 1 ) );

  /**********************************************************************/
  /* links                                                              */
  /**********************************************************************/

  if( FD_UNLIKELY( tile->out_cnt < 1 ||
                   strcmp( topo->links[ tile->out_link_id[ GOSSIP_OUT_IDX ] ].name, "rstart_gossi" ) ) ) {
    FD_LOG_ERR(( "restart tile has unexpected output links, out_cnt=%lu %s", tile->out_cnt, topo->links[ tile->out_link_id[ GOSSIP_OUT_IDX ] ].name ));
  }

  fd_topo_link_t * gossip_out = &topo->links[ tile->out_link_id[ GOSSIP_OUT_IDX ] ];
  ctx->gossip_out_mcache      = gossip_out->mcache;
  ctx->gossip_out_sync        = fd_mcache_seq_laddr( ctx->gossip_out_mcache );
  ctx->gossip_out_depth       = fd_mcache_depth( ctx->gossip_out_mcache );
  ctx->gossip_out_seq         = fd_mcache_seq_query( ctx->gossip_out_sync );
  ctx->gossip_out_chunk0      = fd_dcache_compact_chunk0( fd_wksp_containing( gossip_out->dcache ), gossip_out->dcache );
  ctx->gossip_out_mem         = topo->workspaces[ topo->objs[ gossip_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->gossip_out_wmark       = fd_dcache_compact_wmark( ctx->gossip_out_mem, gossip_out->dcache, gossip_out->mtu );
  ctx->gossip_out_chunk       = ctx->gossip_out_chunk0;

  fd_topo_link_t * gossip_in = &topo->links[ tile->in_link_id[ GOSSIP_IN_IDX ] ];
  ctx->gossip_in_mem         = topo->workspaces[ topo->objs[ gossip_in->dcache_obj_id ].wksp_id ].wksp;
  ctx->gossip_in_chunk0      = fd_dcache_compact_chunk0( ctx->gossip_in_mem, gossip_in->dcache );
  ctx->gossip_in_wmark       = fd_dcache_compact_wmark( ctx->gossip_in_mem, gossip_in->dcache, gossip_in->mtu );

  fd_topo_link_t * store_out = &topo->links[ tile->out_link_id[ STORE_OUT_IDX ] ];
  ctx->store_out_mcache      = store_out->mcache;
  ctx->store_out_sync        = fd_mcache_seq_laddr( ctx->store_out_mcache );
  ctx->store_out_depth       = fd_mcache_depth( ctx->store_out_mcache );
  ctx->store_out_seq         = fd_mcache_seq_query( ctx->store_out_sync );
  ctx->store_out_chunk0      = fd_dcache_compact_chunk0( fd_wksp_containing( store_out->dcache ), store_out->dcache );
  ctx->store_out_mem         = topo->workspaces[ topo->objs[ store_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->store_out_wmark       = fd_dcache_compact_wmark( ctx->store_out_mem, store_out->dcache, store_out->mtu );
  ctx->store_out_chunk       = ctx->store_out_chunk0;

  fd_topo_link_t * store_in = &topo->links[ tile->in_link_id[ STORE_IN_IDX ] ];
  ctx->store_in_mem         = topo->workspaces[ topo->objs[ store_in->dcache_obj_id ].wksp_id ].wksp;
  ctx->store_in_chunk0      = fd_dcache_compact_chunk0( ctx->store_in_mem, store_in->dcache );
  ctx->store_in_wmark       = fd_dcache_compact_wmark( ctx->store_in_mem, store_in->dcache, store_in->mtu );

}

static void
during_frag( fd_restart_tile_ctx_t * ctx,
             ulong                   in_idx,
             ulong                   seq FD_PARAM_UNUSED,
             ulong                   sig FD_PARAM_UNUSED,
             ulong                   chunk,
             ulong                   sz,
             ulong                   ctl FD_PARAM_UNUSED ) {
  if( FD_LIKELY( in_idx==GOSSIP_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->gossip_in_chunk0 || chunk>ctx->gossip_in_wmark || sz>FD_RESTART_LINK_BYTES_MAX+sizeof(uint) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->gossip_in_chunk0, ctx->gossip_in_wmark ));
    }

    fd_memcpy( ctx->restart_gossip_msg, fd_chunk_to_laddr( ctx->gossip_in_mem, chunk ), sz );
    return;
  }

  if( FD_UNLIKELY( in_idx==STORE_IN_IDX ) ) {
    if( FD_UNLIKELY( chunk<ctx->store_in_chunk0 || chunk>ctx->store_in_wmark || sz!=sizeof(fd_funk_txn_xid_t) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->store_in_chunk0, ctx->store_in_wmark ));
    }

    fd_memcpy( &ctx->store_xid_msg, fd_chunk_to_laddr( ctx->store_in_mem, chunk), sz );
    return;
  }
}

static void
after_frag( fd_restart_tile_ctx_t * ctx,
            ulong                  in_idx,
            ulong                  seq FD_PARAM_UNUSED,
            ulong                  sig FD_PARAM_UNUSED,
            ulong                  sz FD_PARAM_UNUSED,
            ulong                  tsorig FD_PARAM_UNUSED,
            ulong                  tspub FD_PARAM_UNUSED,
            fd_stem_context_t *    stem FD_PARAM_UNUSED ) {
  if( FD_LIKELY( in_idx==GOSSIP_IN_IDX ) ) {
    ulong heaviest_fork_found = 0, need_repair = 0;
    fd_restart_recv_gossip_msg( ctx->restart, ctx->restart_gossip_msg, &heaviest_fork_found );
    if( FD_UNLIKELY( heaviest_fork_found ) ) {
      fd_restart_find_heaviest_fork_bank_hash( ctx->restart, ctx->funk, &need_repair );
      if( FD_LIKELY( need_repair ) ) {
        /* Send the heaviest fork slot to the store tile for repair and replay */
        uchar * buf = fd_chunk_to_laddr( ctx->store_out_mem, ctx->store_out_chunk );
        FD_STORE( ulong, buf, ctx->restart->heaviest_fork_slot );
        FD_STORE( ulong, buf+sizeof(ulong), ctx->restart->funk_root );
        fd_mcache_publish( ctx->store_out_mcache, ctx->store_out_depth, ctx->store_out_seq, 1UL, ctx->store_out_chunk,
                           sizeof(ulong)*2, 0UL, 0, 0 );
        ctx->store_out_seq   = fd_seq_inc( ctx->store_out_seq, 1UL );
        ctx->store_out_chunk = fd_dcache_compact_next( ctx->store_out_chunk, sizeof(ulong)*2, ctx->store_out_chunk0, ctx->store_out_wmark );
      }
    }
  }

  if( FD_UNLIKELY( in_idx==STORE_IN_IDX ) ) {
    /* Decode the slot bank for HeaviestForkSlot from funk, referencing fd_runtime_recover_banks() in fd_runtime_init.c */
    // fd_funk_rec_key_t   id      = fd_runtime_slot_bank_key();
    // fd_funk_txn_map_t * txn_map = fd_funk_txn_map( ctx->funk );
    // fd_funk_txn_start_read( ctx->funk );
    // fd_funk_txn_t *    funk_txn = fd_funk_txn_query( &ctx->store_xid_msg, txn_map );
    // if( FD_UNLIKELY( !funk_txn ) ) {
    //   /* Try again with xid.ul[1] being the slot number instead of the block hash */
    //   ctx->store_xid_msg.ul[1] = ctx->restart->heaviest_fork_slot;
    //   funk_txn = fd_funk_txn_query( &ctx->store_xid_msg, txn_map );
    //   if( FD_UNLIKELY( !funk_txn ) ) {
    //     FD_LOG_ERR(( "Wen-restart fails due to NULL funk_txn" ));
    //   }
    // }
    // fd_funk_txn_end_read( ctx->funk );
    // fd_funk_rec_query_t query[1];
    // fd_funk_rec_t const * rec = fd_funk_rec_query_try( ctx->funk, funk_txn, &id, query );
    // void *                val = fd_funk_val( rec, fd_funk_wksp( ctx->funk ) );
    // if( fd_funk_val_sz( rec ) < sizeof(uint) ) {
    //   FD_LOG_ERR(( "failed to read banks record: empty record" ));
    // }
    // uint magic = *(uint*)val;

    // if( FD_UNLIKELY( magic!=FD_RUNTIME_ENC_BINCODE ) ) {
    //   FD_LOG_ERR(( "failed to read banks record: invalid magic number" ));
    // }

    // int err;
    // fd_slot_bank_t * slot_bank = fd_bincode_decode_spad(
    //     slot_bank, ctx->runtime_spad,
    //     (uchar *)val          + sizeof(uint),
    //     fd_funk_val_sz( rec ) - sizeof(uint),
    //     &err );
    // if( FD_UNLIKELY( err ) ) {
    //   FD_LOG_ERR(( "failed to read banks record: invalid decode" ));
    // }

    // FD_TEST( !fd_funk_rec_query_test( query ) );

    /* Add a hard fork into the slot bank */
    // ulong old_len           = slot_bank->hard_forks.hard_forks_len;
    // ctx->new_hard_forks_len = old_len + 1;
    // ctx->new_hard_forks     = fd_spad_alloc( ctx->runtime_spad, 8, ctx->new_hard_forks_len*sizeof(fd_slot_pair_t) );
    // fd_memcpy( ctx->new_hard_forks, slot_bank->hard_forks.hard_forks, old_len*sizeof(fd_slot_pair_t) );

    // ctx->new_hard_forks[ old_len ].slot  = ctx->restart->heaviest_fork_slot;
    // ctx->new_hard_forks[ old_len ].val   = 1;
    // slot_bank->hard_forks.hard_forks     = ctx->new_hard_forks;
    // slot_bank->hard_forks.hard_forks_len = ctx->new_hard_forks_len;

    /* Write the slot bank back to funk, referencing fd_runtime_save_slot_bank */
    // int funk_err = 0;
    // fd_funk_rec_prepare_t prepare[1];
    // fd_funk_rec_t * new_rec = fd_funk_rec_prepare(
    //     ctx->funk, funk_txn, &id, prepare, &funk_err );
    // if( FD_UNLIKELY( !new_rec ) ) {
    //   FD_LOG_ERR(( "fd_funk_rec_prepare() failed (%i-%s)", funk_err, fd_funk_strerror( funk_err ) ));
    // }

    // ulong   sz  = sizeof(uint) + fd_slot_bank_size( slot_bank );
    // uchar * buf = fd_funk_val_truncate(
    //     new_rec,
    //     fd_funk_alloc( ctx->funk ),
    //     fd_funk_wksp( ctx->funk ),
    //     0UL,
    //     sz,
    //     &funk_err );
    // if( FD_UNLIKELY( !buf ) ) FD_LOG_ERR(( "fd_funk_val_truncate(sz=%lu) failed (%i-%s)", sz, funk_err, fd_funk_strerror( funk_err ) ));
    // FD_STORE( uint, buf, FD_RUNTIME_ENC_BINCODE );
    // fd_bincode_encode_ctx_t slot_bank_encode_ctx = {
    //   .data    = buf + sizeof(uint),
    //   .dataend = buf + sz,
    // };
    // if( FD_UNLIKELY( fd_slot_bank_encode( slot_bank, &slot_bank_encode_ctx ) != FD_BINCODE_SUCCESS ||
    //                  slot_bank_encode_ctx.data!=slot_bank_encode_ctx.dataend) ) {
    //   FD_LOG_ERR(( "Wen-restart fails at inserting a hard fork in slot bank and save it in funk" ));
    // }

    // fd_funk_rec_publish( ctx->funk, prepare );

    // /* Publish the txn in funk */
    // fd_funk_txn_start_write( ctx->funk );
    // if( FD_UNLIKELY( !fd_funk_txn_publish( ctx->funk, funk_txn, 1 ) ) ) {
    //   FD_LOG_ERR(( "Wen-restart fails at funk txn publish" ));
    // }
    // fd_funk_txn_end_write( ctx->funk );

    // /* Copy the bank hash of HeaviestForkSlot to fd_restart_t */
    // // ctx->restart->heaviest_fork_bank_hash = slot_bank->banks_hash;
    // ctx->restart->heaviest_fork_ready = 1;
  }
}

static void
after_credit( fd_restart_tile_ctx_t * ctx,
              fd_stem_context_t *     stem FD_PARAM_UNUSED,
              int *                   opt_poll_in FD_PARAM_UNUSED,
              int *                   charge_busy FD_PARAM_UNUSED ) {
  if( FD_UNLIKELY( !ctx->is_funk_active ) ) {
    ctx->is_funk_active = 1;

    // /* Decode the slot bank from funk, referencing fd_runtime_recover_banks() in fd_runtime_init.c */
    // fd_slot_bank_t * slot_bank = NULL;
    // (void)slot_bank;
    // {
    //   fd_funk_rec_key_t     id  = fd_runtime_slot_bank_key();
    //   fd_funk_rec_query_t   query[1];
    //   fd_funk_rec_t const * rec = fd_funk_rec_query_try( ctx->funk, NULL, &id, query );
    //   void *                val = fd_funk_val( rec, fd_funk_wksp( ctx->funk ) );
    //   if( fd_funk_val_sz( rec ) < sizeof(uint) ) {
    //     FD_LOG_ERR(( "failed to read banks record: empty record" ));
    //   }
    //   uint magic = *(uint*)val;
    //   if( FD_UNLIKELY( magic!=FD_RUNTIME_ENC_BINCODE ) ) {
    //     FD_LOG_ERR(( "failed to read banks record: invalid magic number" ));
    //   }

    //   int err;
    //   slot_bank = fd_bincode_decode_spad(
    //       slot_bank, ctx->runtime_spad,
    //       (uchar *)val          + sizeof(uint),
    //       fd_funk_val_sz( rec ) - sizeof(uint),
    //       &err );
    //   if( FD_UNLIKELY( err ) ) {
    //     FD_LOG_ERR(( "failed to read banks record: invalid decode" ));
    //   }

    //   FD_TEST( !fd_funk_rec_query_test( query ) );
    // }

    /* Decode the epoch bank from funk, referencing fd_runtime_recover_banks() in fd_runtime_init.c */
    {
      // fd_funk_rec_key_t     id = fd_runtime_epoch_bank_key();
      // fd_funk_rec_query_t   query[1];
      // fd_funk_rec_t const * rec = fd_funk_rec_query_try( ctx->funk, NULL, &id, query );
      // void *                val = fd_funk_val( rec, fd_funk_wksp( ctx->funk ) );
      // if( fd_funk_val_sz( rec ) < sizeof(uint) ) {
      //   FD_LOG_ERR(("failed to read banks record: empty record"));
      // }
      // uint magic = *(uint*)val;
      // if( FD_UNLIKELY( magic!=FD_RUNTIME_ENC_BINCODE ) ) {
      //     FD_LOG_ERR(( "failed to read banks record: invalid magic number" ));
      // }

      // int err;
      // fd_epoch_bank_t * epoch_bank = fd_bincode_decode_spad(
      //     epoch_bank, ctx->runtime_spad,
      //     (uchar *)val          + sizeof(uint),
      //     fd_funk_val_sz( rec ) - sizeof(uint),
      //     &err );
      // if( FD_UNLIKELY( err ) ) {
      //   FD_LOG_ERR(( "failed to read banks record: invalid decode" ));
      // }

      // ctx->epoch_bank = *epoch_bank;

      // FD_TEST( !fd_funk_rec_query_test( query ) );
    }

    /* Decode the slot history sysvar, referencing fd_sysvar_slot_history_read in fd_sysvar_slot_history.c */
    fd_slot_history_t * slot_history = NULL;
    {
      fd_pubkey_t const * program = &fd_sysvar_slot_history_id;
      FD_TXN_ACCOUNT_DECL( rec );
      int err = fd_txn_account_init_from_funk_readonly( rec, program, ctx->funk, NULL );
      if (err)
        FD_LOG_ERR(( "fd_txn_account_init_from_funk_readonly(slot_history) failed: %d", err ));

      slot_history = fd_bincode_decode_spad(
          slot_history, ctx->runtime_spad,
          rec->vt->get_data( rec ),
          rec->vt->get_data_len( rec ),
          &err );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_ERR(( "fd_slot_history_decode_footprint failed" ));
      }
    }

    // fd_vote_accounts_t const * epoch_stakes[ FD_RESTART_EPOCHS_MAX ] = { &ctx->epoch_bank.stakes.vote_accounts,
    //                                                                      &ctx->epoch_bank.next_epoch_stakes };
    fd_vote_accounts_t const * epoch_stakes[ FD_RESTART_EPOCHS_MAX ] = { NULL, NULL };

    ulong buf_len = 0;
    uchar * buf   = fd_chunk_to_laddr( ctx->gossip_out_mem, ctx->gossip_out_chunk );

    /* FIXME: this has an invalid slot number. */
    fd_epoch_schedule_t * epoch_schedule = NULL;
    fd_restart_init( ctx->restart,
                     0UL,
                     NULL,
                     epoch_stakes,
                     epoch_schedule,
                     ctx->tower_checkpt_fileno,
                     slot_history,
                     &ctx->identity,
                     &ctx->coordinator,
                     buf+sizeof(uint),
                     &buf_len,
                     ctx->runtime_spad );
    buf_len += sizeof(uint);
    FD_STORE( uint, buf, fd_crds_data_enum_restart_last_voted_fork_slots );
    fd_mcache_publish( ctx->gossip_out_mcache, ctx->gossip_out_depth, ctx->gossip_out_seq, 1UL, ctx->gossip_out_chunk,
                       buf_len, 0UL, 0, 0 );
    ctx->gossip_out_seq   = fd_seq_inc( ctx->gossip_out_seq, 1UL );
    ctx->gossip_out_chunk = fd_dcache_compact_next( ctx->gossip_out_chunk, buf_len, ctx->gossip_out_chunk0, ctx->gossip_out_wmark );
  }

  /* See whether wen-restart can finish */
  ulong send  = 0;
  uchar * buf = fd_chunk_to_laddr( ctx->gossip_out_mem, ctx->gossip_out_chunk );
  fd_restart_verify_heaviest_fork( ctx->restart,
                                   0,
                                   ctx->new_hard_forks,
                                   ctx->new_hard_forks_len,
                                   &ctx->genesis_hash,
                                   buf+sizeof(uint),
                                   &send );

  if( FD_UNLIKELY( send ) ) {
    /* Send the restart_heaviest_fork message to gossip tile */
    ulong buf_len = sizeof(uint) + sizeof(fd_gossip_restart_heaviest_fork_t);
    FD_STORE( uint, buf, fd_crds_data_enum_restart_heaviest_fork );
    fd_mcache_publish( ctx->gossip_out_mcache, ctx->gossip_out_depth, ctx->gossip_out_seq, 1UL, ctx->gossip_out_chunk,
                       buf_len, 0UL, 0, 0 );
    ctx->gossip_out_seq   = fd_seq_inc( ctx->gossip_out_seq, 1UL );
    ctx->gossip_out_chunk = fd_dcache_compact_next( ctx->gossip_out_chunk, buf_len, ctx->gossip_out_chunk0, ctx->gossip_out_wmark );
  }

}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE          fd_restart_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_restart_tile_ctx_t)

#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag
#define STEM_CALLBACK_AFTER_CREDIT  after_credit

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_restart = {
  .name                     = "rstart",
//  .populate_allowed_seccomp = populate_allowed_seccomp,
//  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
