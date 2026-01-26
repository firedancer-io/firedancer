#include "fd_snapct_test_topo.h"

#include "../fd_snapct_tile.c"
#include "../../../disco/topo/fd_topob.h"

FD_FN_CONST ulong
fd_snapct_test_topo_align( void ) {
  return alignof(fd_snapct_test_topo_t);
}

FD_FN_CONST ulong
fd_snapct_test_topo_footprint( void ) {
  return sizeof(fd_snapct_test_topo_t);
}

void *
fd_snapct_test_topo_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_snapct_test_topo_align() ) ) ) {
    FD_LOG_WARNING(("unaligned shmem " ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_snapct_test_topo_t * snapct = FD_SCRATCH_ALLOC_APPEND( l, fd_snapct_test_topo_align(), fd_snapct_test_topo_footprint() );
  fd_memset( snapct, 0, sizeof(fd_snapct_test_topo_t) );

  FD_COMPILER_MFENCE();
  snapct->magic = FD_SNAPCT_TEST_TOPO_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)snapct;
}

fd_snapct_test_topo_t *
fd_snapct_test_topo_join( void * shsnapct ) {
  if( FD_UNLIKELY( !shsnapct ) ) {
    FD_LOG_WARNING(( "NULL shsnapct" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsnapct, fd_snapct_test_topo_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsnapct" ));
    return NULL;
  }

  fd_snapct_test_topo_t * snapct = (fd_snapct_test_topo_t *)shsnapct;

  if( FD_UNLIKELY( snapct->magic!=FD_SNAPCT_TEST_TOPO_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return snapct;
}

void
fd_snapct_test_topo_init( fd_snapct_test_topo_t * snapct,
                          fd_topo_t *             topo,
                          fd_wksp_t *             wksp,
                          char const *            wksp_name,
                          int                     allow_gossip_any,
                          ulong                   servers_cnt,
                          fd_ip4_port_t const *   servers,
                          char const **           server_names,
                          ulong *                 server_names_len,
                          char const *            in_ack_link_name,
                          char const *            snapshots_path,
                          ulong                   snapshots_path_len ) {
  /* set up scratch */
  fd_topo_tile_t * tile = &topo->tiles[ fd_topo_find_tile( topo, "snapct", 0UL ) ];
  ulong tile_footprint  = scratch_footprint( tile );
  void * tile_ctx       = fd_wksp_alloc_laddr( wksp, scratch_align(), tile_footprint, WKSP_TAG );
  snapct->ctx      = tile_ctx;

  fd_topo_obj_t * tile_obj = fd_topob_obj( topo, "tile", wksp_name );
  tile_obj->offset         = fd_wksp_gaddr_fast( wksp, tile_ctx );
  tile->tile_obj_id        = tile_obj->id;

  /* set up links */
  ulong id;
  if( allow_gossip_any ) {
    id = fd_topo_find_link( topo, "gossip_out", 0UL );
    FD_TEST( id!=ULONG_MAX );
    fd_restore_link_in_init( &snapct->in_gossip, topo, &topo->links[ id ] );
  }

  id = fd_topo_find_link( topo, "snapld_dc", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_in_init( &snapct->in_ld, topo, &topo->links[ id ] );

  id = fd_topo_find_link( topo, in_ack_link_name, 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_in_init( &snapct->in_ack, topo, &topo->links[ id ] );

  id = fd_topo_find_link( topo, "snapct_ld", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_out_init( &snapct->out_ld, topo, &topo->links[ id ] );
  fd_restore_link_in_init( &snapct->out_ld_in_view, topo, &topo->links[ id ] );

  id = fd_topo_find_link( topo, "snapct_repr", 0UL );
  FD_TEST( id!=ULONG_MAX );
  fd_restore_link_out_init( &snapct->out_repr, topo, &topo->links[ id ] );
  fd_restore_link_in_init( &snapct->out_repr_in_view, topo, &topo->links[ id ] );

  fd_restore_init_stem( &snapct->mock_stem, topo, tile );

  /* TODO: make these configurable*/
  fd_memcpy( tile->snapct.snapshots_path, snapshots_path, snapshots_path_len);
  tile->snapct.incremental_snapshots             = 1;
  tile->snapct.max_full_snapshots_to_keep        = 1;
  tile->snapct.max_incremental_snapshots_to_keep = 1;
  tile->snapct.max_retry_abort                   = 5U;

  /* TODO: make these configurable or read from defaults */
  tile->snapct.sources.max_local_full_effective_age = 1000UL;
  tile->snapct.sources.max_local_incremental_age    = 1000UL;
  tile->snapct.full_effective_age_cancel_threshold  = 20000UL;

  tile->snapct.sources.servers_cnt           = servers_cnt;
  tile->snapct.sources.gossip.allow_any      = allow_gossip_any;
  tile->snapct.sources.gossip.allow_list_cnt = 0;
  tile->snapct.sources.gossip.block_list_cnt = 0;

  if( servers_cnt ) {
    for( ulong i=0UL; i<servers_cnt; i++ ) {
      tile->snapct.sources.servers[ i ].addr     = servers[ i ];
      fd_memcpy( tile->snapct.sources.servers[ i ].hostname, server_names[ i ], server_names_len[ i ] );
      tile->snapct.sources.servers[ i ].is_https = 0;
    }
  }

  /* TODO: remove hack if possible */
  if( !allow_gossip_any ) {
    /* remove the gossip in link, if it exists, by setting its name to
       something nonsensical so the snapct tile can't find it during
       privileged/unprivileged init */
    id = fd_topo_find_link( topo, "gossip_out", 0UL );
    if( id!=ULONG_MAX ) {
      fd_topo_link_t * link = &topo->links[ id ];
      fd_memcpy( link->name, "AAA", sizeof("AAA") );
    }
  }

  privileged_init( topo, tile );
  unprivileged_init( topo, tile );

  if( allow_gossip_any ) {
    /* mock saturation of the gossip ci table.  Gossip peers can be
    added later by calling fd_snapct_test_topo_inject_gossip_peer. */
    fd_snapct_tile_t * ctx = (fd_snapct_tile_t *)snapct->ctx;
    ctx->gossip.saturated  = 1;
  }

  if( !allow_gossip_any ) {
    /* Set gossip out link name back to what it was before, if it was
       changed. */
    id = fd_topo_find_link( topo, "AAA", 0UL );
    if( id!=ULONG_MAX ) {
      fd_topo_link_t * link = &topo->links[ id ];
      fd_memcpy( link->name, "gossip_out", sizeof("gossip_out") );
    }
  }
}

int
fd_snapct_test_topo_get_state( fd_snapct_test_topo_t * snapct ) {
  fd_snapct_tile_t * ctx = (fd_snapct_tile_t *)snapct->ctx;
  return ctx->state;
}

void
fd_snapct_test_topo_inject_gossip_peer( fd_snapct_test_topo_t * snapct,
                                        uchar                   origin_pubkey[ static FD_HASH_FOOTPRINT ],
                                        fd_ip4_port_t           addr,
                                        ulong                   idx ) {
  fd_snapct_tile_t * ctx = (fd_snapct_tile_t *)snapct->ctx;
  ulong existing_idx = gossip_ci_map_idx_query_const( ctx->gossip.ci_map, (fd_pubkey_t const *)origin_pubkey, ULONG_MAX, ctx->gossip.ci_table );
  if( existing_idx==ULONG_MAX ) {
    gossip_ci_entry_t * entry = ctx->gossip.ci_table + idx;
    fd_memcpy( entry->pubkey.uc, origin_pubkey, FD_HASH_FOOTPRINT );
    entry->rpc_addr = addr;
    entry->allowed  = 1;
    gossip_ci_map_idx_insert( ctx->gossip.ci_map, idx, ctx->gossip.ci_table );
  } else if ( existing_idx==idx ) {
    gossip_ci_entry_t * entry = ctx->gossip.ci_table + idx;
    fd_memcpy( entry->pubkey.uc, origin_pubkey, FD_HASH_FOOTPRINT );
    entry->rpc_addr = addr;
    entry->allowed  = 1;
  } else {
    FD_LOG_ERR(("attempted to inject gossip peer with existing pubkey and existing idx at %lu but given idx is %lu", existing_idx, idx ));
  }
}

void
fd_snapct_test_topo_inject_server_response( fd_snapct_test_topo_t * snapct,
                                            fd_ip4_port_t           addr,
                                            ulong                   full_slot,
                                            ulong                   incr_slot ) {
  fd_snapct_tile_t * ctx = (fd_snapct_tile_t *)snapct->ctx;
  fd_stem_context_t stem = {
    .mcaches             = snapct->mock_stem.out_mcache,
    .depths              = snapct->mock_stem.out_depth,
    .seqs                = snapct->mock_stem.seqs,
    .cr_avail            = snapct->mock_stem.cr_avail,
    .min_cr_avail        = &snapct->mock_stem.min_cr_avail,
    .cr_decrement_amount = 1UL
  };
  ctx->stem = &stem;
  on_resolve( ctx, addr, full_slot, incr_slot );
}

void
fd_snapct_test_topo_inject_snapshot_hash( fd_snapct_test_topo_t * snapct,
                                          uchar                   origin_pubkey[ static FD_HASH_FOOTPRINT ],
                                          fd_ip4_port_t           addr,
                                          ulong                   idx,
                                          ulong                   full_slot,
                                          ulong                   incr_slot ) {
  fd_gossip_update_message_t msg;
  msg.tag                               = FD_GOSSIP_UPDATE_TAG_SNAPSHOT_HASHES;
  msg.snapshot_hashes.full->slot        = full_slot;
  msg.snapshot_hashes.incremental->slot = incr_slot;
  msg.snapshot_hashes.incremental_len   = 1UL;

  fd_snapct_tile_t * ctx = (fd_snapct_tile_t *)snapct->ctx;
  fd_stem_context_t stem = {
    .mcaches             = snapct->mock_stem.out_mcache,
    .depths              = snapct->mock_stem.out_depth,
    .seqs                = snapct->mock_stem.seqs,
    .cr_avail            = snapct->mock_stem.cr_avail,
    .min_cr_avail        = &snapct->mock_stem.min_cr_avail,
    .cr_decrement_amount = 1UL
  };
  ctx->stem = &stem;

  on_snapshot_hash( ctx, addr, &msg );
  fd_snapct_test_topo_inject_gossip_peer( snapct, origin_pubkey, addr, idx );
}

void
fd_snapct_test_topo_inject_ping( fd_snapct_test_topo_t * snapct,
                                 fd_ip4_port_t           addr,
                                 ulong                   latency_nanos ) {
  fd_snapct_tile_t * ctx = (fd_snapct_tile_t *)snapct->ctx;
  on_ping( ctx, addr, latency_nanos );
}

int
fd_snapct_test_topo_returnable_frag( fd_snapct_test_topo_t * snapct,
                                     ulong                   in_idx,
                                     ulong                   seq,
                                     ulong                   sig,
                                     ulong                   chunk,
                                     ulong                   sz,
                                     ulong                   ctl,
                                     ulong                   tsorig,
                                     ulong                   tspub ) {
  fd_snapct_tile_t * ctx = (fd_snapct_tile_t *)snapct->ctx;

  fd_stem_context_t stem = {
    .mcaches             = snapct->mock_stem.out_mcache,
    .depths              = snapct->mock_stem.out_depth,
    .seqs                = snapct->mock_stem.seqs,
    .cr_avail            = snapct->mock_stem.cr_avail,
    .min_cr_avail        = &snapct->mock_stem.min_cr_avail,
    .cr_decrement_amount = 1UL
  };
  return returnable_frag( ctx, in_idx, seq, sig, chunk, sz, ctl, tsorig, tspub, &stem );
}

void
fd_snapct_test_topo_after_credit( fd_snapct_test_topo_t * snapct,
                                  int *                   opt_poll_in,
                                  int *                   charge_busy ) {
  fd_snapct_tile_t * ctx = (fd_snapct_tile_t *)snapct->ctx;
  fd_stem_context_t stem = {
    .mcaches             = snapct->mock_stem.out_mcache,
    .depths              = snapct->mock_stem.out_depth,
    .seqs                = snapct->mock_stem.seqs,
    .cr_avail            = snapct->mock_stem.cr_avail,
    .min_cr_avail        = &snapct->mock_stem.min_cr_avail,
    .cr_decrement_amount = 1UL
  };
  after_credit( ctx, &stem, opt_poll_in, charge_busy );
}

void
fd_snapct_test_topo_fini( fd_snapct_test_topo_t * snapct ) {
  fd_wksp_free_laddr( snapct->ctx );
}
