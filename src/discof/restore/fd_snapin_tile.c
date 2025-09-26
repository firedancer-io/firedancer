#include "utils/fd_ssctrl.h"
#include "utils/fd_snapshot_parser.h"
#include "utils/fd_ssmsg.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../flamenco/types/fd_types.h"
#include "../../funk/fd_funk.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_history.h"

#include "generated/snapin_seccomp.h"

#define NAME "snapin"

/* The snapin tile is a state machine that parses and loads a full
   and optionally an incremental snapshot.  It is currently responsible
   for loading accounts into an in-memory database, though this may
   change. */

#define FD_SNAPIN_STATE_LOADING   (0) /* We are inserting accounts from a snapshot */
#define FD_SNAPIN_STATE_DONE      (1) /* We are done inserting accounts from a snapshot */
#define FD_SNAPIN_STATE_MALFORMED (2) /* The snapshot is malformed, we are waiting for a reset notification */
#define FD_SNAPIN_STATE_SHUTDOWN  (3) /* The tile is done, been told to shut down, and has likely already exited */

#define FD_SNAPIN_TXNCACHE_MAX_ENTRIES (300UL*FD_PACK_MAX_TXN_PER_SLOT)

struct fd_blockhash_wrapper {
  uchar const * bh;
};

typedef struct fd_blockhash_wrapper fd_blockhash_wrapper_t;

struct fd_blockhash_entry {
  fd_blockhash_wrapper_t blockhash;

  struct {
    ulong next;
  } pool;

  struct {
    ulong prev;
    ulong next;
  } map;
};

typedef struct fd_blockhash_entry fd_blockhash_entry_t;

#define POOL_NAME  blockhash_pool
#define POOL_T     fd_blockhash_entry_t
#define POOL_IDX_T ulong
#define POOL_NEXT  pool.next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           blockhash_set
#define MAP_KEY                            blockhash
#define MAP_KEY_T                          fd_blockhash_wrapper_t
#define MAP_ELE_T                          fd_blockhash_entry_t
#define MAP_KEY_EQ(k0,k1)                  memcmp( k0, k1, 32UL )==0
#define MAP_KEY_HASH(key,seed)             (fd_hash( (seed), (key), 32UL))
#define MAP_PREV                           map.prev
#define MAP_NEXT                           map.next
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

struct fd_snapin_tile {
  int full;
  int state;

  ulong seed;
  long boot_timestamp;

  fd_funk_t       funk[1];
  fd_txncache_t * txncache;
  uchar *         acc_data;

  fd_funk_txn_xid_t xid[1]; /* txn XID */

  fd_stem_context_t *    stem;
  fd_snapshot_parser_t * ssparse;
  ulong                  bank_slot;

  ulong                   txncache_entries_len;
  fd_sstxncache_entry_t * txncache_entries;

  fd_blockhash_entry_t * blockhash_pool;
  ulong                  blockhash_pool_ele_cnt;
  blockhash_set_t *      blockhash_set;

  struct {
    ulong full_bytes_read;
    ulong incremental_bytes_read;
    ulong accounts_inserted;
  } metrics;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  } in;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       chunk;
    ulong       mtu;
  } manifest_out;
};

typedef struct fd_snapin_tile fd_snapin_tile_t;

static inline int
should_shutdown( fd_snapin_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPIN_STATE_SHUTDOWN ) ) {
    FD_LOG_NOTICE(( "loaded %.1fM accounts from snapshot in %.1f seconds", (double)ctx->metrics.accounts_inserted/1e6, (double)(fd_log_wallclock()-ctx->boot_timestamp)/1e9 ));
  }
  return ctx->state==FD_SNAPIN_STATE_SHUTDOWN;
}

static ulong
scratch_align( void ) {
  return 128UL;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapin_tile_t),      sizeof(fd_snapin_tile_t)                                     );
  l = FD_LAYOUT_APPEND( l, fd_snapshot_parser_align(),     fd_snapshot_parser_footprint( 1UL<<24UL )                    );
  l = FD_LAYOUT_APPEND( l, alignof(fd_sstxncache_entry_t), sizeof(fd_sstxncache_entry_t)*FD_SNAPIN_TXNCACHE_MAX_ENTRIES );
  l = FD_LAYOUT_APPEND( l, blockhash_pool_align(),         blockhash_pool_footprint( 301UL )                            );
  l = FD_LAYOUT_APPEND( l, blockhash_set_align(),          blockhash_set_footprint( 1024UL )                             );
  return FD_LAYOUT_FINI( l, alignof(fd_snapin_tile_t) );
}

static void
metrics_write( fd_snapin_tile_t * ctx ) {
  FD_MGAUGE_SET( SNAPIN, FULL_BYTES_READ, ctx->metrics.full_bytes_read );
  FD_MGAUGE_SET( SNAPIN, INCREMENTAL_BYTES_READ, ctx->metrics.incremental_bytes_read );

  FD_MGAUGE_SET( SNAPIN, ACCOUNTS_INSERTED, ctx->metrics.accounts_inserted );
  FD_MGAUGE_SET( SNAPIN, STATE, (ulong)ctx->state );
}

static int
verify_slot_deltas_with_slot_history( fd_snapin_tile_t *         ctx,
                                      fd_slot_history_global_t * slot_history ) {

  for( ulong i=0UL; i<ctx->txncache_entries_len; i++ ) {
    fd_sstxncache_entry_t const * entry = &ctx->txncache_entries[i];
    if( FD_UNLIKELY( fd_sysvar_slot_history_find_slot( slot_history, entry->slot, NULL )!=FD_SLOT_HISTORY_SLOT_FOUND ) ) return -1;
  }
  return 0;
}

static int
verify_slot_deltas_with_bank_slot( fd_snapin_tile_t * ctx,
                                   ulong              bank_slot ) {
  for( ulong i=0UL; i<ctx->txncache_entries_len; i++ ) {
    fd_sstxncache_entry_t const * entry = &ctx->txncache_entries[i];
    if( FD_UNLIKELY( entry->slot>bank_slot ) ) return -1;
  }
  return 0;
}

static void
populate_txncache( fd_snapin_tile_t *                     ctx,
                   fd_snapshot_manifest_blockhash_t const blockhashes[ static 301UL ],
                   ulong                                  blockhashes_len ) {
  if( FD_UNLIKELY( !ctx->txncache ) ) return;
  FD_TEST( blockhashes_len<=301UL );

  // fd_txncache_fork_id_t root = { .val = USHORT_MAX };
  for( ulong i=0UL; i<blockhashes_len; i++ ) {
    /* build blockhashes set */
    fd_blockhash_entry_t * blockhash_entry = &ctx->blockhash_pool[ ctx->blockhash_pool_ele_cnt++ ];
    blockhash_entry->blockhash.bh = blockhashes[i].hash;
    blockhash_set_ele_insert( ctx->blockhash_set, blockhash_entry, ctx->blockhash_pool );

    // fd_txncache_fork_id_t id = fd_txncache_attach_child( ctx->txncache, root, 0UL, blockhashes[i].hash );
    // fd_txncache_advance_root( ctx->txncache, id );
  }

  for( ulong i=0UL; i<ctx->txncache_entries_len; i++ ) {
    // fd_sstxncache_entry_t const * entry = &ctx->txncache_entries[i];
    // if( blockhash_set_idx_query_const( ctx->blockhash_set, (fd_blockhash_wrapper_t *)entry->blockhash, ULONG_MAX, ctx->blockhash_pool )==ULONG_MAX ) continue;
    // fd_txncache_insert( ctx->txncache, root, entry->blockhash, entry->txnhash );
  }

  /* clear the blockhash set and pool */
  for( ulong i=0UL; i<ctx->blockhash_pool_ele_cnt; i++ ) {
    fd_blockhash_entry_t * entry = &ctx->blockhash_pool[i];
    blockhash_set_ele_remove_fast( ctx->blockhash_set, entry, ctx->blockhash_pool );
    entry->blockhash.bh = NULL;
  }
  ctx->blockhash_pool_ele_cnt = 0UL;
}

static void
transition_malformed( fd_snapin_tile_t * ctx,
                     fd_stem_context_t * stem ) {
  ctx->state = FD_SNAPIN_STATE_MALFORMED;
  fd_stem_publish( stem, 1UL, FD_SNAPSHOT_MSG_CTRL_MALFORMED, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static void
manifest_cb( void * _ctx ) {
  fd_snapin_tile_t * ctx = (fd_snapin_tile_t*)_ctx;

  fd_snapshot_manifest_t const * manifest = fd_chunk_to_laddr_const( ctx->manifest_out.wksp, ctx->manifest_out.chunk );
  ulong bank_slot = ctx->bank_slot = manifest->slot;
  if( FD_UNLIKELY( verify_slot_deltas_with_bank_slot( ctx, bank_slot ) ) ) {
    FD_LOG_WARNING(( "slot deltas verification failed" ));
    transition_malformed( ctx, ctx->stem );
    return;
  }

  populate_txncache( ctx, manifest->blockhashes, manifest->blockhashes_len );


  ulong sig = ctx->full ? fd_ssmsg_sig( FD_SSMSG_MANIFEST_FULL ) :
                          fd_ssmsg_sig( FD_SSMSG_MANIFEST_INCREMENTAL );
  fd_stem_publish( ctx->stem, 0UL, sig, ctx->manifest_out.chunk, sizeof(fd_snapshot_manifest_t), 0UL, 0UL, 0UL );
  ctx->manifest_out.chunk = fd_dcache_compact_next( ctx->manifest_out.chunk, sizeof(fd_snapshot_manifest_t), ctx->manifest_out.chunk0, ctx->manifest_out.wmark );
}

static void
status_cache_cb( void *                        _ctx,
                 fd_sstxncache_entry_t const * entry ) {
  fd_snapin_tile_t * ctx = (fd_snapin_tile_t*)_ctx;

  if( FD_UNLIKELY( ctx->txncache_entries_len>=FD_SNAPIN_TXNCACHE_MAX_ENTRIES ) ) FD_LOG_ERR(( "txncache entries overflow, max is %lu", FD_SNAPIN_TXNCACHE_MAX_ENTRIES ));

  ctx->txncache_entries[ ctx->txncache_entries_len++ ] = *entry;
}

static void
account_cb( void *                          _ctx,
            fd_solana_account_hdr_t const * hdr ) {
  fd_snapin_tile_t * ctx = (fd_snapin_tile_t*)_ctx;

  fd_funk_rec_key_t id = fd_funk_acc_key( (fd_pubkey_t*)hdr->meta.pubkey );
  fd_funk_rec_query_t query[1];
  fd_funk_rec_t const * rec = fd_funk_rec_query_try( ctx->funk, ctx->xid, &id, query );

  int should_publish = 0;
  fd_funk_rec_prepare_t prepare[1];
  if( FD_LIKELY( !rec ) ) {
    should_publish = 1;
    rec = fd_funk_rec_prepare( ctx->funk, ctx->xid, &id, prepare, NULL );
    FD_TEST( rec );
  }

  fd_account_meta_t * meta = fd_funk_val( rec, ctx->funk->wksp );
  if( FD_UNLIKELY( meta ) ) {
    if( FD_LIKELY( meta->slot>ctx->ssparse->accv_slot ) ) {
      ctx->acc_data = NULL;
      return;
    }

    /* TODO: Reaching here means the existing value is a duplicate
       account.  We need to hash the existing account and subtract that
       hash from the running lthash. */
  }

  if( FD_LIKELY( rec->val_sz<sizeof(fd_account_meta_t)+hdr->meta.data_len ) ) {
    meta = fd_funk_val_truncate( (fd_funk_rec_t*)rec, ctx->funk->alloc, ctx->funk->wksp, 0UL, sizeof(fd_account_meta_t)+hdr->meta.data_len, NULL );
    FD_TEST( meta );
  }

  meta->dlen       = (uint)hdr->meta.data_len;
  meta->slot       = ctx->ssparse->accv_slot;
  memcpy( meta->owner, hdr->info.owner, sizeof(fd_pubkey_t) );
  meta->lamports   = hdr->info.lamports;
  meta->executable = hdr->info.executable;

  ctx->acc_data = (uchar*)meta + sizeof(fd_account_meta_t);
  ctx->metrics.accounts_inserted++;

  if( FD_LIKELY( should_publish ) ) fd_funk_rec_publish( ctx->funk, prepare );
}

static void
account_data_cb( void *        _ctx,
                 uchar const * buf,
                 ulong         data_sz ) {
  fd_snapin_tile_t * ctx = (fd_snapin_tile_t*)_ctx;
  if( FD_UNLIKELY( !ctx->acc_data ) ) return;

  fd_memcpy( ctx->acc_data, buf, data_sz );
  ctx->acc_data += data_sz;
}

static void
handle_data_frag( fd_snapin_tile_t *  ctx,
                  ulong               chunk,
                  ulong               sz,
                  fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPIN_STATE_MALFORMED ) ) return;

  FD_TEST( ctx->state==FD_SNAPIN_STATE_LOADING || ctx->state==FD_SNAPIN_STATE_DONE );
  FD_TEST( chunk>=ctx->in.chunk0 && chunk<=ctx->in.wmark && sz<=ctx->in.mtu );

  if( FD_UNLIKELY( ctx->state==FD_SNAPIN_STATE_DONE ) ) {
    FD_LOG_WARNING(( "received data fragment while in done state" ));
    transition_malformed( ctx, stem );
    return;
  }

  uchar const * const chunk_start = fd_chunk_to_laddr_const( ctx->in.wksp, chunk );
  uchar const * const chunk_end = chunk_start + sz;
  uchar const *       cur       = chunk_start;

  for(;;) {
    if( FD_UNLIKELY( cur>=chunk_end ) ) {
      break;
    }

    cur = fd_snapshot_parser_process_chunk( ctx->ssparse, cur, (ulong)( chunk_end-cur ) );
    if( FD_UNLIKELY( ctx->ssparse->flags ) ) {
      if( FD_UNLIKELY( ctx->ssparse->flags & SNAP_FLAG_FAILED ) ) {
        transition_malformed( ctx, stem );
        return;
      }
    }
  }

  if( FD_UNLIKELY( ctx->ssparse->flags & SNAP_FLAG_DONE ) ) ctx->state = FD_SNAPIN_STATE_DONE;

  if( FD_LIKELY( ctx->full ) ) ctx->metrics.full_bytes_read += sz;
  else                         ctx->metrics.incremental_bytes_read += sz;
}

static void
handle_control_frag( fd_snapin_tile_t *  ctx,
                     fd_stem_context_t * stem,
                     ulong               sig ) {
  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_RESET_FULL:
      ctx->full = 1;
      fd_snapshot_parser_reset( ctx->ssparse, fd_chunk_to_laddr( ctx->manifest_out.wksp, ctx->manifest_out.chunk ), ctx->manifest_out.mtu );
      fd_funk_txn_remove_published( ctx->funk );
      ctx->state = FD_SNAPIN_STATE_LOADING;
      break;
    case FD_SNAPSHOT_MSG_CTRL_RESET_INCREMENTAL:
      ctx->full = 0;
      fd_snapshot_parser_reset( ctx->ssparse, fd_chunk_to_laddr( ctx->manifest_out.wksp, ctx->manifest_out.chunk ), ctx->manifest_out.mtu );
      fd_funk_txn_cancel( ctx->funk, ctx->xid );
      fd_funk_txn_xid_copy( ctx->xid, fd_funk_last_publish( ctx->funk ) );
      ctx->state = FD_SNAPIN_STATE_LOADING;
      break;
    case FD_SNAPSHOT_MSG_CTRL_EOF_FULL:
      FD_TEST( ctx->full );
      if( FD_UNLIKELY( ctx->state!=FD_SNAPIN_STATE_DONE ) ) {
        FD_LOG_WARNING(( "unexpected end of snapshot when not done parsing" ));
        transition_malformed( ctx, stem );
        break;
      }

      fd_snapshot_parser_reset( ctx->ssparse, fd_chunk_to_laddr( ctx->manifest_out.wksp, ctx->manifest_out.chunk ), ctx->manifest_out.mtu );

      fd_funk_txn_xid_t incremental_xid = fd_funk_generate_xid();
      fd_funk_txn_prepare( ctx->funk, ctx->xid, &incremental_xid );
      fd_funk_txn_xid_copy( ctx->xid, &incremental_xid );

      ctx->full     = 0;
      ctx->state    = FD_SNAPIN_STATE_LOADING;
      break;
    case FD_SNAPSHOT_MSG_CTRL_DONE: {
      if( FD_UNLIKELY( ctx->state!=FD_SNAPIN_STATE_DONE ) ) {
        FD_LOG_WARNING(( "unexpected end of snapshot when not done parsing" ));
        transition_malformed( ctx, stem );
        break;
      }

      uchar slot_history_mem[ FD_SYSVAR_SLOT_HISTORY_FOOTPRINT ];
      fd_slot_history_global_t * slot_history = fd_sysvar_slot_history_read( ctx->funk, ctx->xid, slot_history_mem );
      if( FD_UNLIKELY( verify_slot_deltas_with_slot_history( ctx, slot_history ) ) ) {
        FD_LOG_WARNING(( "slot deltas verification failed" ));
        transition_malformed( ctx, stem );
        break;
      }

      /* Publish any remaining funk txn */
      if( FD_LIKELY( fd_funk_last_publish_is_frozen( ctx->funk ) ) ) {
        fd_funk_txn_publish_into_parent( ctx->funk, ctx->xid );
      }
      FD_TEST( !fd_funk_last_publish_is_frozen( ctx->funk ) );

      /* Make 'Last published' XID equal the restored slot number */
      fd_funk_txn_xid_t target_xid = { .ul = { ctx->bank_slot, ctx->bank_slot } };
      fd_funk_txn_prepare( ctx->funk, ctx->xid, &target_xid );
      fd_funk_txn_publish_into_parent( ctx->funk, &target_xid );
      fd_funk_txn_xid_copy( ctx->xid, &target_xid );

      fd_stem_publish( stem, 0UL, fd_ssmsg_sig( FD_SSMSG_DONE ), 0UL, 0UL, 0UL, 0UL, 0UL );
      break;
    }
    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN:
      ctx->state = FD_SNAPIN_STATE_SHUTDOWN;
      metrics_write( ctx ); /* ensures that shutdown state is written to metrics workspace before the tile actually shuts down */
      break;
    default:
      FD_LOG_ERR(( "unexpected control sig %lu", sig ));
      return;
  }

  /* We must acknowledge after handling the control frag, because if it
     causes us to generate a malformed transition, that must be sent
     back to the snaprd controller before the acknowledgement. */
  fd_stem_publish( stem, 1UL, FD_SNAPSHOT_MSG_CTRL_ACK, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static inline int
returnable_frag( fd_snapin_tile_t *  ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)in_idx;
  (void)seq;
  (void)ctl;
  (void)tsorig;
  (void)tspub;

  ctx->stem = stem;

  FD_TEST( ctx->state!=FD_SNAPIN_STATE_SHUTDOWN );

  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_DATA ) ) handle_data_frag( ctx, chunk, sz, stem );
  else                                           handle_control_frag( ctx, stem, sig  );

  return 0;
}

static ulong
populate_allowed_fds( fd_topo_t      const * topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2UL; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) {
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  }

  return out_cnt;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {

  populate_sock_filter_policy_snapin( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_snapin_instr_cnt;
}


static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapin_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapin_tile_t), sizeof(fd_snapin_tile_t) );

  FD_TEST( fd_rng_secure( &ctx->seed, 8UL ) );
}

FD_FN_UNUSED static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapin_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapin_tile_t),      sizeof(fd_snapin_tile_t)                                     );
  void * _ssparse        = FD_SCRATCH_ALLOC_APPEND( l, fd_snapshot_parser_align(),     fd_snapshot_parser_footprint( 1UL<<24UL )                    );
  void * _txnc_entries   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sstxncache_entry_t), sizeof(fd_sstxncache_entry_t)*FD_SNAPIN_TXNCACHE_MAX_ENTRIES );
  void * _blockhash_pool = FD_SCRATCH_ALLOC_APPEND( l, blockhash_pool_align(),         blockhash_pool_footprint( 301UL )                            );
  void * _blockhash_set  = FD_SCRATCH_ALLOC_APPEND( l, blockhash_set_align(),          blockhash_set_footprint( 1024UL )                             );

  ctx->full = 1;
  ctx->state = FD_SNAPIN_STATE_LOADING;

  ctx->boot_timestamp = fd_log_wallclock();

  FD_TEST( fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->snapin.funk_obj_id ) ) );
  fd_funk_txn_xid_set_root( ctx->xid );

  if( FD_LIKELY( tile->snapin.txncache_obj_id!=ULONG_MAX ) ) {
    ctx->txncache = fd_txncache_join( fd_topo_obj_laddr( topo, tile->snapin.txncache_obj_id ) );
    FD_TEST( ctx->txncache );
  } else {
    ctx->txncache = NULL;
  }

  ctx->txncache_entries     = (fd_sstxncache_entry_t*)_txnc_entries;
  ctx->txncache_entries_len = 0UL;

  ctx->blockhash_pool = blockhash_pool_join( blockhash_pool_new( _blockhash_pool, 301UL ) );
  FD_TEST( ctx->blockhash_pool );

  ctx->blockhash_set = blockhash_set_join( blockhash_set_new( _blockhash_set, 1024UL, ctx->seed ) );
  FD_TEST( ctx->blockhash_set );

  ctx->blockhash_pool_ele_cnt = 0UL;

  ctx->ssparse = fd_snapshot_parser_new( _ssparse, ctx, ctx->seed, 1UL<<24UL, manifest_cb, status_cache_cb, account_cb, account_data_cb );
  FD_TEST( ctx->ssparse );

  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  if( FD_UNLIKELY( tile->kind_id ) ) FD_LOG_ERR(( "There can only be one `" NAME "` tile" ));
  if( FD_UNLIKELY( tile->in_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=2UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 2",  tile->out_cnt  ));

  fd_topo_link_t * writer_link = &topo->links[ tile->out_link_id[ 0UL ] ];
  ctx->manifest_out.wksp    = topo->workspaces[ topo->objs[ writer_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->manifest_out.chunk0  = fd_dcache_compact_chunk0( fd_wksp_containing( writer_link->dcache ), writer_link->dcache );
  ctx->manifest_out.wmark   = fd_dcache_compact_wmark ( ctx->manifest_out.wksp, writer_link->dcache, writer_link->mtu );
  ctx->manifest_out.chunk   = ctx->manifest_out.chunk0;
  ctx->manifest_out.mtu     = writer_link->mtu;

  fd_snapshot_parser_reset( ctx->ssparse, fd_chunk_to_laddr( ctx->manifest_out.wksp, ctx->manifest_out.chunk ), ctx->manifest_out.mtu );

  fd_topo_link_t const * in_link = &topo->links[ tile->in_link_id[ 0UL ] ];
  fd_topo_wksp_t const * in_wksp = &topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ];
  ctx->in.wksp                   = in_wksp->wksp;;
  ctx->in.chunk0                 = fd_dcache_compact_chunk0( ctx->in.wksp, in_link->dcache );
  ctx->in.wmark                  = fd_dcache_compact_wmark( ctx->in.wksp, in_link->dcache, in_link->mtu );
  ctx->in.mtu                    = in_link->mtu;
}

#define STEM_BURST 2UL /* For control fragments, one acknowledgement, and one malformed message */
#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snapin_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snapin_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapin = {
  .name                     = NAME,
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};

#undef NAME
