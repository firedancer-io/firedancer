#include "fd_restart.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/topo/fd_pod_format.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../funk/fd_funk_filemap.h"
#include "../../flamenco/runtime/fd_runtime.h"

#define GOSSIP_IN_IDX  (0UL)
#define STORE_IN_IDX   (1UL)

#define GOSSIP_OUT_IDX (0UL)
#define STORE_OUT_IDX  (1UL)

struct fd_restart_tile_ctx {
  int                   in_wen_restart;

  fd_restart_t *        restart;
  fd_funk_t *           funk;
  fd_epoch_bank_t       epoch_bank;
  int                   is_funk_active;
  char                  funk_file[ PATH_MAX ];
  fd_spad_t *           runtime_spad;
  int                   tower_checkpt_fileno;
  fd_pubkey_t           identity, coordinator, genesis_hash;
  fd_slot_pair_t *      new_hard_forks;
  ulong                 new_hard_forks_len;
  ulong *               is_constipated;

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
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {

  /* Do not modify order! This is join-order in unprivileged_init. */
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_restart_tile_ctx_t), sizeof(fd_restart_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_restart_align(), fd_restart_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_spad_align(), FD_RUNTIME_BLOCK_EXECUTION_FOOTPRINT );
  l = FD_LAYOUT_FINI  ( l, scratch_align() );
  return l;
}

static void
privileged_init( fd_topo_t      * topo FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile ) {
  /* TODO: not launching the restart tile if in_wen_restart is false */
  if( FD_LIKELY( !tile->restart.in_wen_restart ) ) return;

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
  /* TODO: not launching the restart tile if in_wen_restart is false */
  if( FD_LIKELY( !tile->restart.in_wen_restart ) ) {
    void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
    FD_SCRATCH_ALLOC_INIT( l, scratch );
    fd_restart_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_restart_tile_ctx_t), sizeof(fd_restart_tile_ctx_t) );
    FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

    ctx->in_wen_restart = tile->restart.in_wen_restart;
    return;
  }

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_restart_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_restart_tile_ctx_t), sizeof(fd_restart_tile_ctx_t) );
  void * restart_mem          = FD_SCRATCH_ALLOC_APPEND( l, fd_restart_align(), fd_restart_footprint() );
  void * spad_mem             = FD_SCRATCH_ALLOC_APPEND( l, fd_spad_align(), FD_RUNTIME_BLOCK_EXECUTION_FOOTPRINT );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  /**********************************************************************/
  /* restart                                                            */
  /**********************************************************************/

  ctx->in_wen_restart = tile->restart.in_wen_restart;
  ctx->restart        = fd_restart_join( fd_restart_new( restart_mem ) );

  /**********************************************************************/
  /* funk                                                               */
  /**********************************************************************/

  /* TODO: Same as what happens in the batch tile, eventually, funk should
     be joined via a shared topology object. */
  ctx->is_funk_active = 0;
  memcpy( ctx->funk_file, tile->restart.funk_file, sizeof(tile->restart.funk_file) );

  /**********************************************************************/
  /* spad                                                               */
  /**********************************************************************/

  ctx->runtime_spad = fd_spad_join( fd_spad_new( spad_mem, FD_RUNTIME_BLOCK_EXECUTION_FOOTPRINT ) );
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
  /* constipated fseq                                                   */
  /**********************************************************************/

  ulong constipated_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "constipate" );
  FD_TEST( constipated_obj_id!=ULONG_MAX );
  ctx->is_constipated = fd_fseq_join( fd_topo_obj_laddr( topo, constipated_obj_id ) );
  if( FD_UNLIKELY( !ctx->is_constipated ) ) FD_LOG_ERR(( "restart tile has no constipated fseq" ));
  //fd_fseq_update( ctx->is_constipated, 0UL );
  //FD_TEST( 0UL==fd_fseq_query( ctx->is_constipated ) );

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

static inline int
before_frag( fd_restart_tile_ctx_t * ctx,
             ulong                   in_idx FD_PARAM_UNUSED,
             ulong                   seq FD_PARAM_UNUSED,
             ulong                   sig FD_PARAM_UNUSED ) {
  /* TODO: not launching the restart tile if in_wen_restart is false */
  return !ctx->in_wen_restart;
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
    fd_slot_bank_t slot_bank;
    fd_funk_rec_key_t      id = fd_runtime_slot_bank_key();
    fd_funk_txn_t *   txn_map = fd_funk_txn_map( ctx->funk, fd_funk_wksp( ctx->funk ) );
    fd_funk_txn_t *  funk_txn = fd_funk_txn_query( &ctx->store_xid_msg, txn_map );
    if( FD_UNLIKELY( !funk_txn ) ) {
      /* Try again with xid.ul[1] being the slot number instead of the block hash */
      ctx->store_xid_msg.ul[1] = ctx->restart->heaviest_fork_slot;
      funk_txn = fd_funk_txn_query( &ctx->store_xid_msg, txn_map );
      if( FD_UNLIKELY( !funk_txn ) ) {
        FD_LOG_ERR(( "Wen-restart fails due to NULL funk_txn" ));
      }
    }
    fd_funk_rec_t const * rec = fd_funk_rec_query( ctx->funk, funk_txn, &id );
    void *                val = fd_funk_val( rec, fd_funk_wksp( ctx->funk ) );
    if( fd_funk_val_sz( rec ) < sizeof(uint) ) {
      FD_LOG_ERR(( "failed to read banks record: empty record" ));
    }
    uint magic = *(uint*)val;

    fd_bincode_decode_ctx_t slot_bank_decode_ctx = {
      .data    = (uchar*)val + sizeof(uint),
      .dataend = (uchar*)val + fd_funk_val_sz( rec ),
    };

    if( magic == FD_RUNTIME_ENC_BINCODE ) {
      ulong total_sz = 0UL;
      int   err      = fd_slot_bank_decode_footprint( &slot_bank_decode_ctx, &total_sz );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_ERR(( "failed to read banks record: invalid decode" ));
      }

      uchar * mem = fd_spad_alloc( ctx->runtime_spad, fd_slot_bank_align(), total_sz );
      if( FD_UNLIKELY( !mem ) ) {
        FD_LOG_ERR(( "failed to read banks record: unable to allocate memory" ));
      }

      fd_slot_bank_decode( mem, &slot_bank_decode_ctx );

      /* FIXME: see the FIXME in fd_runtime_recover_banks() of fd_runtime_init.c */
      memcpy( &slot_bank, mem, sizeof(fd_slot_bank_t) );

    } else {
      FD_LOG_ERR(("failed to read banks record: invalid magic number"));
    }

    /* Add a hard fork into the slot bank */
    ulong old_len           = slot_bank.hard_forks.hard_forks_len;
    ctx->new_hard_forks_len = old_len + 1;
    ctx->new_hard_forks     = fd_spad_alloc( ctx->runtime_spad, 8, ctx->new_hard_forks_len*sizeof(fd_slot_pair_t) );
    fd_memcpy( ctx->new_hard_forks, slot_bank.hard_forks.hard_forks, old_len*sizeof(fd_slot_pair_t) );

    ctx->new_hard_forks[ old_len ].slot = ctx->restart->heaviest_fork_slot;
    ctx->new_hard_forks[ old_len ].val  = 1;
    slot_bank.hard_forks.hard_forks     = ctx->new_hard_forks;
    slot_bank.hard_forks.hard_forks_len = ctx->new_hard_forks_len;

    fd_funk_start_write( ctx->funk );

    /* Write the slot bank back to funk, referencing fd_runtime_save_slot_bank */
    int opt_err = 0;
    ulong sz    = sizeof(uint) + fd_slot_bank_size( &slot_bank );
    fd_funk_rec_t * new_rec = fd_funk_rec_write_prepare( ctx->funk,
                                                         funk_txn,
                                                         &id,
                                                         sz,
                                                         1,
                                                         NULL,
                                                         &opt_err );
    if( FD_UNLIKELY( !new_rec ) ) {
      FD_LOG_ERR(( "Wen-restart fails at inserting a hard fork in slot bank and save it in funk" ));
    }

    uchar * buf = fd_funk_val( new_rec, fd_funk_wksp( ctx->funk ) );
    *(uint*)buf = FD_RUNTIME_ENC_BINCODE;
    fd_bincode_encode_ctx_t slot_bank_encode_ctx = {
      .data    = buf + sizeof(uint),
      .dataend = buf + sz,
    };
    if( FD_UNLIKELY( fd_slot_bank_encode( &slot_bank, &slot_bank_encode_ctx ) != FD_BINCODE_SUCCESS ||
                     slot_bank_encode_ctx.data!=slot_bank_encode_ctx.dataend) ) {
      FD_LOG_ERR(( "Wen-restart fails at inserting a hard fork in slot bank and save it in funk" ));
    }

    /* Publish the txn in funk */
    if( FD_UNLIKELY( !fd_funk_txn_publish( ctx->funk, funk_txn, 1 ) ) ) {
      FD_LOG_ERR(( "Wen-restart fails at funk txn publish" ));
    }
    fd_funk_end_write( ctx->funk );

    /* Copy the bank hash of HeaviestForkSlot to fd_restart_t */
    fd_memcpy( &ctx->restart->heaviest_fork_bank_hash, &slot_bank.banks_hash, sizeof(fd_hash_t) );
    ctx->restart->heaviest_fork_ready = 1;
  }
}

static void
after_credit( fd_restart_tile_ctx_t * ctx,
              fd_stem_context_t *     stem FD_PARAM_UNUSED,
              int *                   opt_poll_in FD_PARAM_UNUSED,
              int *                   charge_busy FD_PARAM_UNUSED ) {
  /* TODO: not launching the restart tile if in_wen_restart is false */
  if( FD_LIKELY( !ctx->in_wen_restart ) ) return;

  if( FD_UNLIKELY( !ctx->is_funk_active ) ) {
    /* Setting these parameters are not required because we are joining the
       funk that was setup in the replay tile. */
    ctx->funk = fd_funk_open_file( ctx->funk_file,
                                   1UL,
                                   0UL,
                                   0UL,
                                   0UL,
                                   0UL,
                                   FD_FUNK_READ_WRITE,
                                   NULL );
    if( FD_UNLIKELY( !ctx->funk ) ) {
      FD_LOG_ERR(( "failed to join a funky" ));
    } else {
      FD_LOG_NOTICE(("Restart tile joins funk successfully"));
    }
    ctx->is_funk_active = 1;

    /* Decode the slot bank from funk, referencing fd_runtime_recover_banks() in fd_runtime_init.c */
    fd_slot_bank_t slot_bank;
    {
      fd_funk_rec_key_t     id  = fd_runtime_slot_bank_key();
      fd_funk_rec_t const * rec = fd_funk_rec_query( ctx->funk, NULL, &id );
      void *                val = fd_funk_val( rec, fd_funk_wksp( ctx->funk ) );
      if( fd_funk_val_sz( rec ) < sizeof(uint) ) {
        FD_LOG_ERR(( "failed to read banks record: empty record" ));
      }
      uint magic = *(uint*)val;

      fd_bincode_decode_ctx_t slot_bank_decode_ctx = {
        .data    = (uchar*)val + sizeof(uint),
        .dataend = (uchar*)val + fd_funk_val_sz( rec ),
      };

      if( magic == FD_RUNTIME_ENC_BINCODE ) {

        ulong total_sz = 0UL;
        int   err      = fd_slot_bank_decode_footprint( &slot_bank_decode_ctx, &total_sz );
        if( FD_UNLIKELY( err ) ) {
          FD_LOG_ERR(( "failed to read banks record: invalid decode" ));
        }

        uchar * mem = fd_spad_alloc( ctx->runtime_spad, fd_slot_bank_align(), total_sz );
        if( FD_UNLIKELY( !mem ) ) {
          FD_LOG_ERR(( "failed to read banks record: unable to allocate memory" ));
        }

        fd_slot_bank_decode( mem, &slot_bank_decode_ctx );

        /* FIXME: see the FIXME in fd_runtime_recover_banks() of fd_runtime_init.c */
        memcpy( &slot_bank, mem, sizeof(fd_slot_bank_t) );

      } else {
        FD_LOG_ERR(("failed to read banks record: invalid magic number"));
      }
    }

    /* Decode the epoch bank from funk, referencing fd_runtime_recover_banks() in fd_runtime_init.c */
    {
      fd_funk_rec_key_t      id = fd_runtime_epoch_bank_key();
      fd_funk_rec_t const * rec = fd_funk_rec_query( ctx->funk, NULL, &id );
      void *                val = fd_funk_val( rec, fd_funk_wksp( ctx->funk ) );
      if( fd_funk_val_sz( rec ) < sizeof(uint) ) {
        FD_LOG_ERR(("failed to read banks record: empty record"));
      }
      uint magic = *(uint*)val;

      fd_bincode_decode_ctx_t epoch_bank_decode_ctx = {
        .data    = (uchar*)val + sizeof(uint),
        .dataend = (uchar*)val + fd_funk_val_sz( rec ),
      };
      if( magic==FD_RUNTIME_ENC_BINCODE ) {

        ulong total_sz = 0UL;
        int   err      = fd_epoch_bank_decode_footprint( &epoch_bank_decode_ctx, &total_sz );
        if( FD_UNLIKELY( err ) ) {
          FD_LOG_ERR(( "failed to read banks record: invalid decode" ));
        }

        uchar * mem = fd_spad_alloc( ctx->runtime_spad, fd_epoch_bank_align(), total_sz );
        if( FD_UNLIKELY( !mem ) ) {
          FD_LOG_ERR(( "failed to read banks record: unable to allocate memory" ));
        }

        fd_epoch_bank_decode( mem, &epoch_bank_decode_ctx );

        ctx->epoch_bank = *(fd_epoch_bank_t *)mem;
      } else {
        FD_LOG_ERR(( "failed to read banks record: invalid magic number" ));
      }
    }

    /* Decode the slot history sysvar, referencing fd_sysvar_slot_history_read in fd_sysvar_slot_history.c */
    fd_slot_history_t * slot_history;
    {
      void * acc_mgr_mem          = fd_valloc_malloc( fd_spad_virtual( ctx->runtime_spad ), FD_ACC_MGR_ALIGN, FD_ACC_MGR_FOOTPRINT );
      fd_acc_mgr_t * acc_mgr      = fd_acc_mgr_new( acc_mgr_mem, ctx->funk );
      fd_pubkey_t const * program = &fd_sysvar_slot_history_id;
      FD_TXN_ACCOUNT_DECL( rec );
      int err = fd_acc_mgr_view( acc_mgr, NULL, program, rec );
      if (err)
        FD_LOG_ERR(( "fd_acc_mgr_view(slot_history) failed: %d", err ));

      fd_bincode_decode_ctx_t sysvar_decode_ctx = {
        .data    = rec->const_data,
        .dataend = rec->const_data + rec->const_meta->dlen,
      };
      ulong total_sz = 0UL;
      err = fd_slot_history_decode_footprint( &sysvar_decode_ctx, &total_sz );
      if( err ) {
        FD_LOG_ERR(( "fd_slot_history_decode_footprint failed" ));
      }

      uchar * mem = fd_spad_alloc( ctx->runtime_spad, fd_slot_history_align(), total_sz );
      if( !mem ) {
        FD_LOG_ERR(( "Unable to allocate memory for slot history" ));
      }

      slot_history = fd_slot_history_decode( mem, &sysvar_decode_ctx );
    }

    fd_vote_accounts_t const * epoch_stakes[ FD_RESTART_EPOCHS_MAX ] = { &ctx->epoch_bank.stakes.vote_accounts,
                                                                         &ctx->epoch_bank.next_epoch_stakes };

    ulong buf_len = 0;
    uchar * buf   = fd_chunk_to_laddr( ctx->gossip_out_mem, ctx->gossip_out_chunk );

    fd_restart_init( ctx->restart,
                     slot_bank.slot,
                     &slot_bank.banks_hash,
                     epoch_stakes,
                     &ctx->epoch_bank.epoch_schedule,
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
                                   ctx->is_constipated,
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

#define STEM_CALLBACK_BEFORE_FRAG   before_frag
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
