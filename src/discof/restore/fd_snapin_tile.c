#include "utils/fd_ssctrl.h"
#include "utils/fd_snapshot_parser.h"
#include "utils/fd_ssmsg.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"
#include "../../flamenco/types/fd_types.h"
#include "../../funk/fd_funk.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../flamenco/runtime/fd_hashes.h"

#define NAME "snapin"

/* The snapin tile is a state machine that parses and loads a full
   and optionally an incremental snapshot.  It is currently responsible
   for loading accounts into an in-memory database, though this may
   change. */

#define FD_SNAPIN_STATE_LOADING   (0) /* We are inserting accounts from a snapshot */
#define FD_SNAPIN_STATE_DONE      (1) /* We are done inserting accounts from a snapshot */
#define FD_SNAPIN_STATE_MALFORMED (1) /* The snapshot is malformed, we are waiting for a reset notification */
#define FD_SNAPIN_STATE_SHUTDOWN  (2) /* The tile is done, been told to shut down, and has likely already exited */

#define FD_SNAPIN_HSH_IDX (2UL)

struct fd_snapin_tile {
  int  full;
  int  state;
  int  pending_ack;

  ulong seed;
  long boot_timestamp;

  fd_funk_t       funk[1];
  fd_funk_txn_t * root_funk_txn;
  fd_funk_txn_t * funk_txn;
  uchar *         acc_data;

  fd_stem_context_t *    stem;
  fd_snapshot_parser_t * ssparse;

  struct {
    int               enabled;
    ulong             received_lthashes;
    ulong             num_hash_tiles;
    fd_lthash_value_t expected_lthash;
    fd_lthash_value_t calculated_lthash;
  } hash_info;

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
    ulong       chunk_offset;
  } in;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       chunk;
    ulong       mtu;
  } manifest_out;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       chunk;
    ulong       mtu;
  } hash_out;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
  } hash_in[ FD_MAX_SNAPLT_TILES ];
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
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapin_tile_t),  sizeof(fd_snapin_tile_t)                  );
  l = FD_LAYOUT_APPEND( l, fd_snapshot_parser_align(), fd_snapshot_parser_footprint( 1UL<<24UL ) );
  return FD_LAYOUT_FINI( l, alignof(fd_snapin_tile_t) );
}

static void
metrics_write( fd_snapin_tile_t * ctx ) {
  FD_MGAUGE_SET( SNAPIN, FULL_BYTES_READ, ctx->metrics.full_bytes_read );
  FD_MGAUGE_SET( SNAPIN, INCREMENTAL_BYTES_READ, ctx->metrics.incremental_bytes_read );

  FD_MGAUGE_SET( SNAPIN, ACCOUNTS_INSERTED, ctx->metrics.accounts_inserted );
  FD_MGAUGE_SET( SNAPIN, STATE, (ulong)ctx->state );
}

static void
transition_malformed( fd_snapin_tile_t *  ctx,
                      fd_stem_context_t * stem ) {
  ctx->state = FD_SNAPIN_STATE_MALFORMED;
  fd_stem_publish( stem, 1UL, FD_SNAPSHOT_MSG_CTRL_MALFORMED, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static void
manifest_cb( void * _ctx ) {
  fd_snapin_tile_t * ctx = (fd_snapin_tile_t*)_ctx;

  ulong sz = sizeof(fd_snapshot_manifest_t);

  if( FD_LIKELY( ctx->hash_info.enabled ) ) {
    fd_snapshot_manifest_t const * manifest = fd_chunk_to_laddr_const( ctx->manifest_out.wksp, ctx->manifest_out.chunk );
    if( FD_LIKELY( manifest->has_accounts_lthash ) ) {
      fd_memcpy( &ctx->hash_info.expected_lthash, manifest->accounts_lthash, sizeof(fd_lthash_value_t) );
    } else {
      FD_LOG_WARNING(( "snapshot manifest doesn't have an accounts lthash" ));
      transition_malformed( ctx, ctx->stem );
    }
  }

  FD_TEST( sz<=ctx->manifest_out.mtu );
  ulong sig = ctx->full ? fd_ssmsg_sig( FD_SSMSG_MANIFEST_FULL ) :
                          fd_ssmsg_sig( FD_SSMSG_MANIFEST_INCREMENTAL );
  fd_stem_publish( ctx->stem, 0UL, sig, ctx->manifest_out.chunk, sz, 0UL, 0UL, 0UL );
  ctx->manifest_out.chunk = fd_dcache_compact_next( ctx->manifest_out.chunk, sz, ctx->manifest_out.chunk0, ctx->manifest_out.wmark );
}

static void
account_cb( void *                          _ctx,
            fd_solana_account_hdr_t const * hdr ) {
  fd_snapin_tile_t * ctx = (fd_snapin_tile_t*)_ctx;

  fd_funk_rec_key_t id = fd_funk_acc_key( (fd_pubkey_t*)hdr->meta.pubkey );
  fd_funk_rec_query_t query[1];
  fd_funk_rec_t const * rec          = fd_funk_rec_query_try( ctx->funk, ctx->funk_txn, &id, query );
  fd_funk_rec_t const * existing_rec = rec;

  int should_publish = 0;
  fd_funk_rec_prepare_t prepare[1];
  if( FD_LIKELY( !existing_rec && !ctx->full ) ) {
    /* An existing record may exist in an ancestor transaction when
       loading the incremental snapshot. */
    existing_rec = fd_funk_rec_clone( ctx->funk, ctx->funk_txn, &id, prepare, NULL );
  }
  if( FD_LIKELY( existing_rec ) ) {
    /* If a record exists either in the current txn, its hash needs to
       be subtracted from the running hash in the hashing tiles. */
    fd_account_meta_t * meta = fd_funk_val( existing_rec, ctx->funk->wksp );
    if( FD_UNLIKELY( meta ) ) {
      if( FD_LIKELY( meta->slot>ctx->ssparse->accv_slot ) ) {
        /* Existing record has a higher slot than the current account
           being inserted.  Ignore the current account and keep the
           existing record as is. */
        ctx->acc_data = NULL;
        return;
      }

      if( FD_LIKELY( ctx->hash_info.enabled ) ) {
        /* Account is a duplicate, need to subtract its hash before
           updating the record in funk. */
        fd_snapshot_existing_account_t * existing_account = fd_chunk_to_laddr( ctx->hash_out.wksp, ctx->hash_out.chunk );
        fd_snapshot_account_init( &existing_account->hdr, hdr->meta.pubkey, meta->owner, meta->lamports, meta->executable, meta->dlen );
        fd_memcpy( existing_account->data, (uchar const *)meta + sizeof(fd_account_meta_t), meta->dlen );
        fd_stem_publish( ctx->stem, FD_SNAPIN_HSH_IDX, FD_SNAPSHOT_HASH_MSG_SUB, ctx->hash_out.chunk, sizeof(fd_snapshot_existing_account_t), 0UL, 0UL, 0UL );
        ctx->hash_out.chunk = fd_dcache_compact_next( ctx->hash_out.chunk, sizeof(fd_snapshot_existing_account_t), ctx->hash_out.chunk0, ctx->hash_out.wmark );
      }
    }
  }

  if( FD_LIKELY( !rec ) ) {
    should_publish = 1;
    rec = fd_funk_rec_prepare( ctx->funk, ctx->funk_txn, &id, prepare, NULL );
    FD_TEST( rec );
  }

  fd_account_meta_t * meta = fd_funk_val( rec, ctx->funk->wksp );
  if( FD_LIKELY( rec->val_sz<sizeof(fd_account_meta_t)+hdr->meta.data_len ) ) {
    meta = fd_funk_val_truncate( (fd_funk_rec_t*)rec, ctx->funk->alloc, ctx->funk->wksp, 0UL, sizeof(fd_account_meta_t)+hdr->meta.data_len, NULL );
    FD_TEST( meta );
  }

  meta->dlen = (uint)hdr->meta.data_len;
  meta->slot = ctx->ssparse->accv_slot;
  memcpy( meta->owner, hdr->info.owner, sizeof(fd_pubkey_t) );
  meta->lamports   = hdr->info.lamports;
  meta->executable = hdr->info.executable;

  ctx->acc_data = (uchar*)meta + sizeof(fd_account_meta_t);
  ctx->metrics.accounts_inserted++;

  if( FD_LIKELY( should_publish ) ) fd_funk_rec_publish( ctx->funk, prepare );

  if( FD_LIKELY( ctx->hash_info.enabled ) ) {
    /* send account hdr to snaplt tile */
    fd_snapshot_account_t * account = fd_chunk_to_laddr( ctx->hash_out.wksp, ctx->hash_out.chunk );
    fd_snapshot_account_init( account, hdr->meta.pubkey, hdr->info.owner, hdr->info.lamports, hdr->info.executable, hdr->meta.data_len );
    fd_stem_publish( ctx->stem, FD_SNAPIN_HSH_IDX, FD_SNAPSHOT_HASH_MSG_ACCOUNT_HDR, ctx->hash_out.chunk, sizeof(fd_snapshot_account_t), 0UL, 0UL, 0UL );
    ctx->hash_out.chunk = fd_dcache_compact_next( ctx->hash_out.chunk, sizeof(fd_snapshot_account_t), ctx->hash_out.chunk0, ctx->hash_out.wmark );
  }
}

static void
account_data_cb( void *        _ctx,
                 uchar const * buf,
                 ulong         data_sz ) {
  fd_snapin_tile_t * ctx = (fd_snapin_tile_t*)_ctx;
  if( FD_UNLIKELY( !ctx->acc_data ) ) return;

  fd_memcpy( ctx->acc_data, buf, data_sz );
  ctx->acc_data += data_sz;

  if( FD_LIKELY( ctx->hash_info.enabled ) ) {
    FD_TEST( data_sz<=ctx->hash_out.mtu );
    /* send acc data to snaplt tile */
    uchar * snaplt_acc_data = fd_chunk_to_laddr( ctx->hash_out.wksp, ctx->hash_out.chunk );
    fd_memcpy( snaplt_acc_data, buf, data_sz );
    fd_stem_publish( ctx->stem, FD_SNAPIN_HSH_IDX, FD_SNAPSHOT_HASH_MSG_ACCOUNT_DATA, ctx->hash_out.chunk, data_sz, 0UL, 0UL, 0UL );
    ctx->hash_out.chunk = fd_dcache_compact_next( ctx->hash_out.chunk, data_sz, ctx->hash_out.chunk0, ctx->hash_out.wmark );
  }
}

static int
handle_data_frag( fd_snapin_tile_t *  ctx,
                  ulong               chunk,
                  ulong               sz,
                  fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPIN_STATE_MALFORMED ) ) return 0;

  FD_TEST( ctx->state==FD_SNAPIN_STATE_LOADING || ctx->state==FD_SNAPIN_STATE_DONE );
  FD_TEST( chunk>=ctx->in.chunk0 && chunk<=ctx->in.wmark && sz<=ctx->in.mtu );

  if( FD_UNLIKELY( ctx->state==FD_SNAPIN_STATE_DONE ) ) {
    FD_LOG_WARNING(( "received data fragment while in done state" ));
    transition_malformed( ctx, stem );
    return 0;
  }

  uchar const * const chunk_start = fd_chunk_to_laddr_const( ctx->in.wksp, chunk );
  uchar const * const chunk_end   = chunk_start + sz;
  uchar const *       cur         = chunk_start + ctx->in.chunk_offset;

  cur = fd_snapshot_parser_process_chunk( ctx->ssparse, cur, (ulong)( chunk_end-cur ) );
  if( FD_UNLIKELY( ctx->ssparse->flags ) ) {
    if( FD_UNLIKELY( ctx->ssparse->flags & SNAP_FLAG_FAILED ) ) {
      transition_malformed( ctx, stem );
      return 0;
    }
  }

  ctx->in.chunk_offset = (ulong)(cur - chunk_start);

  if( FD_UNLIKELY( ctx->ssparse->flags & SNAP_FLAG_DONE ) ) ctx->state = FD_SNAPIN_STATE_DONE;

  if( FD_LIKELY( ctx->full ) ) ctx->metrics.full_bytes_read += sz;
  else                         ctx->metrics.incremental_bytes_read += sz;

  if( FD_UNLIKELY( ctx->in.chunk_offset==sz ) ) {
    ctx->in.chunk_offset = 0UL;
    return 0;
  }

  return 1;
}

static void
handle_control_frag( fd_snapin_tile_t *  ctx,
                     fd_stem_context_t * stem,
                     ulong               sig,
                     ulong               in_idx,
                     ulong               chunk ) {
  /* 1. Pass the control message downstream to the next consumer. */
  if( FD_LIKELY( ctx->hash_info.enabled && sig!=FD_SNAPSHOT_HASH_MSG_RESULT ) )
    fd_stem_publish( stem, FD_SNAPIN_HSH_IDX, sig, ctx->hash_out.chunk, 0UL, 0UL, 0UL, 0UL );

  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_RESET_FULL:
      ctx->full = 1;
      fd_snapshot_parser_reset( ctx->ssparse, fd_chunk_to_laddr( ctx->manifest_out.wksp, ctx->manifest_out.chunk ), ctx->manifest_out.mtu );
      fd_funk_txn_cancel( ctx->funk, ctx->funk_txn, 0 );
      fd_lthash_zero( &ctx->hash_info.expected_lthash );
      fd_lthash_zero( &ctx->hash_info.calculated_lthash );
      ctx->state = FD_SNAPIN_STATE_LOADING;
      break;
    case FD_SNAPSHOT_MSG_CTRL_RESET_INCREMENTAL:
      ctx->full = 0;
      fd_snapshot_parser_reset( ctx->ssparse, fd_chunk_to_laddr( ctx->manifest_out.wksp, ctx->manifest_out.chunk ), ctx->manifest_out.mtu );
      fd_funk_txn_cancel( ctx->funk, ctx->funk_txn, 0 );
      fd_lthash_zero( &ctx->hash_info.expected_lthash );
      fd_lthash_zero( &ctx->hash_info.calculated_lthash );
      ctx->state = FD_SNAPIN_STATE_LOADING;
      break;
    case FD_SNAPSHOT_MSG_CTRL_EOF_FULL:
      FD_TEST( ctx->full );
      if( FD_UNLIKELY( ctx->state!=FD_SNAPIN_STATE_DONE ) ) {
        FD_LOG_WARNING(( "unexpected end of snapshot when not done parsing" ));
        transition_malformed( ctx, stem );
        break;
      }

      if( FD_LIKELY( ctx->hash_info.enabled ) ) ctx->pending_ack = 1;
      fd_snapshot_parser_reset( ctx->ssparse, fd_chunk_to_laddr( ctx->manifest_out.wksp, ctx->manifest_out.chunk ), ctx->manifest_out.mtu );
      fd_funk_txn_xid_t incremental_xid = fd_funk_generate_xid();
      ctx->funk_txn = fd_funk_txn_prepare( ctx->funk, ctx->root_funk_txn, &incremental_xid, 0 );
      FD_TEST( ctx->funk_txn );

      ctx->full     = 0;
      ctx->state    = FD_SNAPIN_STATE_LOADING;
      break;
    case FD_SNAPSHOT_MSG_CTRL_DONE:
      if( FD_UNLIKELY( ctx->state!=FD_SNAPIN_STATE_DONE ) ) {
        FD_LOG_WARNING(( "unexpected end of snapshot when not done parsing" ));
        transition_malformed( ctx, stem );
        break;
      }

      if( FD_LIKELY( ctx->hash_info.enabled ) ) ctx->pending_ack = 1;
      break;
    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN:
      FD_TEST( ctx->pending_ack==0 );
      ctx->state = FD_SNAPIN_STATE_SHUTDOWN;
      metrics_write( ctx ); /* ensures that shutdown state is written to metrics workspace before the tile actually shuts down */

      fd_funk_txn_publish_into_parent( ctx->funk, ctx->funk_txn, 0 );
      fd_stem_publish( stem, 0UL, fd_ssmsg_sig( FD_SSMSG_DONE ), 0UL, 0UL, 0UL, 0UL, 0UL );
      break;
    case FD_SNAPSHOT_HASH_MSG_RESULT: {
      FD_TEST( ctx->hash_info.enabled && ctx->pending_ack );
      /* TODO: more robust in indexing */
      fd_lthash_value_t const * calculated_lthash = fd_chunk_to_laddr_const( ctx->hash_in[ in_idx - 1UL ].wksp, chunk );
      fd_lthash_add( &ctx->hash_info.calculated_lthash, calculated_lthash );
      ctx->hash_info.received_lthashes++;

      if( FD_LIKELY( ctx->hash_info.received_lthashes!=ctx->hash_info.num_hash_tiles ) ) break;

      ctx->pending_ack = 0;
      if( FD_UNLIKELY( memcmp( &ctx->hash_info.expected_lthash, &ctx->hash_info.calculated_lthash, sizeof(fd_lthash_value_t) ) ) ) {
        FD_LOG_WARNING(( "calculated accounts lthash %s does not match accounts lthash %s in snapshot manifest",
                         FD_LTHASH_ENC_32_ALLOCA( &ctx->hash_info.calculated_lthash ),
                         FD_LTHASH_ENC_32_ALLOCA( &ctx->hash_info.expected_lthash ) ));
        transition_malformed( ctx, stem );
      } else {
        FD_LOG_NOTICE(( "calculated accounts lthash %s matches accounts lthash %s in snapshot manifest",
                        FD_LTHASH_ENC_32_ALLOCA( &ctx->hash_info.calculated_lthash ),
                        FD_LTHASH_ENC_32_ALLOCA( &ctx->hash_info.expected_lthash ) ));
      }
      ctx->hash_info.received_lthashes = 0UL;
      break;
    }
    default:
      FD_LOG_ERR(( "unexpected control sig %lu", sig ));
      return;
  }

  /* snapin waits for result lthashes to come back from the snaplt tiles.
     Until these hashes come back, snapin cannot ack the control message
     sent from snaprd because snaprd would advance before snapin
     is ready to receive another snapshot byte stream or shutdown. */
  if( FD_UNLIKELY( ctx->pending_ack ) ) return;

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

  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_DATA ) ) return handle_data_frag( ctx, chunk, sz, stem );
  else                                           handle_control_frag( ctx, stem, sig, in_idx, chunk );

  return 0;
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
  fd_snapin_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapin_tile_t),  sizeof(fd_snapin_tile_t)                  );
  void * _ssparse        = FD_SCRATCH_ALLOC_APPEND( l, fd_snapshot_parser_align(), fd_snapshot_parser_footprint( 1UL<<24UL ) );

  ctx->full         = 1;
  ctx->state        = FD_SNAPIN_STATE_LOADING;
  ctx->pending_ack  = 0;

  ctx->boot_timestamp = fd_log_wallclock();

  FD_TEST( fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->snapin.funk_obj_id ) ) );
  ctx->root_funk_txn = fd_funk_txn_query( fd_funk_root( ctx->funk ), ctx->funk->txn_map );
  ctx->funk_txn      = ctx->root_funk_txn;

  ctx->ssparse  = fd_snapshot_parser_new( _ssparse, ctx, ctx->seed, 1UL<<24UL, manifest_cb, account_cb, account_data_cb );

  FD_TEST( ctx->ssparse );

  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  ulong num_hash_tiles = fd_topo_tile_name_cnt( topo, "snaplt" );
  ctx->hash_info.num_hash_tiles    = num_hash_tiles;
  ctx->hash_info.received_lthashes = 0UL;
  ctx->hash_info.enabled           = num_hash_tiles>0UL;
  ulong snapin_out_cnt             = ctx->hash_info.enabled ? 3UL : 2UL;

  if( FD_UNLIKELY( tile->kind_id ) ) FD_LOG_ERR(( "There can only be one `" NAME "` tile" ));
  if( FD_UNLIKELY( tile->in_cnt!=1UL + num_hash_tiles ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 2",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=snapin_out_cnt ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 3",  tile->out_cnt  ));

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
  ctx->in.chunk_offset           = 0UL;

  if( FD_LIKELY( ctx->hash_info.enabled ) ) {
    for( ulong i=0UL; i<num_hash_tiles; i++ ) {
      fd_topo_link_t const * hash_in_link = &topo->links[ tile->in_link_id[ i+1UL ] ];
      FD_TEST( strcmp( hash_in_link->name, "snaplt_out" )==0 );
      fd_topo_wksp_t const * hash_in_wksp = &topo->workspaces[ topo->objs[ hash_in_link->dcache_obj_id ].wksp_id ];
      ctx->hash_in[ i ].wksp              = hash_in_wksp->wksp;
      ctx->hash_in[ i ].chunk0            = fd_dcache_compact_chunk0( ctx->hash_in[ i ].wksp, hash_in_link->dcache );
      ctx->hash_in[ i ].wmark             = fd_dcache_compact_wmark( ctx->hash_in[ i ].wksp, hash_in_link->dcache, hash_in_link->mtu );
      ctx->hash_in[ i ].mtu               = hash_in_link->mtu;
    }

    fd_topo_link_t const * hash_out_link = &topo->links[ tile->out_link_id[ FD_SNAPIN_HSH_IDX ] ];
    FD_TEST( strcmp( hash_out_link->name, "snapin_lt" )==0 );
    ctx->hash_out.wksp   = topo->workspaces[ topo->objs[ hash_out_link->dcache_obj_id ].wksp_id ].wksp;
    ctx->hash_out.chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( hash_out_link->dcache ), hash_out_link->dcache );
    ctx->hash_out.wmark  = fd_dcache_compact_wmark ( ctx->hash_out.wksp, hash_out_link->dcache, hash_out_link->mtu );
    ctx->hash_out.chunk  = ctx->hash_out.chunk0;
    ctx->hash_out.mtu    = hash_out_link->mtu;
  }

  fd_lthash_zero( &ctx->hash_info.expected_lthash );
  fd_lthash_zero( &ctx->hash_info.calculated_lthash );
}

/* For control fragments, one acknowledgement, and one malformed
   message. Or one FD_SNAPSHOT_HASH_MSG_SUB, one
   FD_SNAPSHOT_HASH_MSG_ACCOUNT_HDR, and one malformed message */
#define STEM_BURST 3UL
#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snapin_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snapin_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapin = {
  .name              = NAME,
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .privileged_init   = privileged_init,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run,
};

#undef NAME
