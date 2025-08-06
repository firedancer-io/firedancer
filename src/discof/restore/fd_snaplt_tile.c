#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../flamenco/runtime/fd_hashes.h"
#include "../../flamenco/runtime/fd_acc_mgr.h"

#include "utils/fd_ssctrl.h"

#define NAME "snaplt"

/* The snaplt tile is a state machine that hashes accounts from an
   account input stream that it receives from the snapin tile.

   An account input stream starts with a SNAPSHOT_HASH_MSG_RESET
   message, which indicates the start of an account input stream.
   An account input stream ends with a SNAPSHOT_HASH_MSG_FINI message,
   indicating snaplt should send its calculated accounts hash to snapin
   with a SNAPSHOT_HASH_MSG_RESULT message. */

#define FD_SNAPLT_STATE_WAITING  (0)
#define FD_SNAPLT_STATE_HASHING  (1)
#define FD_SNAPLT_STATE_DONE     (2)
#define FD_SNAPLT_STATE_SHUTDOWN (3)

struct fd_snaplt_tile {
  int state;

  fd_lthash_value_t running_lthash;

  fd_snapshot_account_t account;
  ulong                 acc_data_sz;

  int                   hash_account;
  ulong                 num_hash_tiles;
  ulong                 hash_tile_idx;
  fd_blake3_t           b3[1];


  struct {
    ulong accounts_hashed;
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
  } out;

};

typedef struct fd_snaplt_tile fd_snaplt_tile_t;

static int
should_hash_account( fd_snaplt_tile_t * ctx,
                     uchar const        account_pubkey[ static FD_HASH_FOOTPRINT ] ) {
  return fd_hash( account_pubkey[ 4UL ], account_pubkey, sizeof(fd_pubkey_t) )%ctx->num_hash_tiles==ctx->hash_tile_idx;
}

static inline int
should_shutdown( fd_snaplt_tile_t * ctx ) {
  return ctx->state==FD_SNAPLT_STATE_SHUTDOWN;
}

static ulong
scratch_align( void ) {
  return 128UL;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snaplt_tile_t), sizeof(fd_snaplt_tile_t) );
  return FD_LAYOUT_FINI( l, alignof(fd_snaplt_tile_t) );
}

static void
metrics_write( fd_snaplt_tile_t * ctx ) {
  FD_MGAUGE_SET( SNAPLT, ACCOUNTS_HASHED, ctx->metrics.accounts_hashed );
  FD_MGAUGE_SET( SNAPLT, STATE, (ulong)(ctx->state) );
}

static void
during_frag( fd_snaplt_tile_t * ctx,
             ulong               in_idx,
             ulong               seq,
             ulong               sig,
             ulong               chunk,
             ulong               sz,
             ulong               ctl ) {
  (void)in_idx;
  (void)seq;
  (void)ctl;

  FD_TEST( ctx->state!=FD_SNAPLT_STATE_SHUTDOWN );
  if( FD_LIKELY( sz ) ) FD_TEST( chunk>=ctx->in.chunk0 && chunk<=ctx->in.wmark && sz<=ctx->in.mtu );

  switch( sig ) {
    case FD_SNAPSHOT_HASH_MSG_SUB: {
      FD_TEST( ctx->state==FD_SNAPLT_STATE_HASHING );

      fd_snapshot_existing_account_t * prev_acc = (fd_snapshot_existing_account_t *)fd_chunk_to_laddr_const( ctx->in.wksp, chunk );

      if( !should_hash_account( ctx, prev_acc->hdr.pubkey) ) break;

      fd_lthash_value_t prev_lthash[1];
      fd_hashes_account_lthash_simple( prev_acc->hdr.pubkey,
                                       prev_acc->hdr.owner,
                                       prev_acc->hdr.lamports,
                                       prev_acc->hdr.executable,
                                       prev_acc->data,
                                       prev_acc->hdr.data_len,
                                       prev_lthash );
      fd_lthash_sub( &ctx->running_lthash, prev_lthash );
      break;
    }
    case FD_SNAPSHOT_HASH_MSG_ACCOUNT_HDR: {
      FD_TEST( ctx->state==FD_SNAPLT_STATE_HASHING && ctx->acc_data_sz==0UL );
      fd_snapshot_account_t * account = (fd_snapshot_account_t *)fd_chunk_to_laddr_const( ctx->in.wksp, chunk );
      if( !should_hash_account( ctx, account->pubkey) ) break;

      if( FD_LIKELY( account->lamports!=0UL ) ) {
        ctx->hash_account = 1;
        fd_blake3_init( ctx->b3 );
        fd_blake3_append( ctx->b3, &account->lamports, sizeof( ulong ) );
        fd_memcpy( &ctx->account, account, sizeof(fd_snapshot_account_t) );
      }
      break;
    }
    case FD_SNAPSHOT_HASH_MSG_ACCOUNT_DATA: {
      FD_TEST( ctx->state==FD_SNAPLT_STATE_HASHING );
      if( FD_LIKELY( ctx->hash_account ) ) {
        fd_blake3_append( ctx->b3, fd_chunk_to_laddr_const( ctx->in.wksp, chunk ), sz );
        ctx->acc_data_sz += sz;
      }
      break;
    }
    case FD_SNAPSHOT_HASH_MSG_RESET:
    case FD_SNAPSHOT_HASH_MSG_FINI:
    case FD_SNAPSHOT_HASH_MSG_SHUTDOWN: {
      break;
    }
    default:
      FD_LOG_ERR(( "unexpected sig %lu in during_frag", sig ));
      return;
  }
}

static void
after_frag( fd_snaplt_tile_t *    ctx,
            ulong                  in_idx,
            ulong                  seq,
            ulong                  sig,
            ulong                  sz,
            ulong                  tsorig,
            ulong                  _tspub,
            fd_stem_context_t *    stem ) {
  (void)in_idx;
  (void)seq;
  (void)tsorig;
  (void)_tspub;
  (void)sz;

  switch( sig ) {
    case FD_SNAPSHOT_HASH_MSG_ACCOUNT_HDR:
    case FD_SNAPSHOT_HASH_MSG_ACCOUNT_DATA: {
      FD_TEST( ctx->state==FD_SNAPLT_STATE_HASHING );
      if( FD_LIKELY( ctx->acc_data_sz==ctx->account.data_len && ctx->hash_account ) ) {
        /* hash account here */
        fd_lthash_value_t account_lthash[1];
        fd_lthash_zero( account_lthash );

        uchar executable_flag = ctx->account.executable & 0x1;
        fd_blake3_append( ctx->b3, &executable_flag, sizeof( uchar ) );
        fd_blake3_append( ctx->b3, ctx->account.owner, FD_HASH_FOOTPRINT );
        fd_blake3_append( ctx->b3, ctx->account.pubkey,  FD_HASH_FOOTPRINT );
        fd_blake3_fini_2048( ctx->b3, account_lthash->bytes );

        fd_lthash_add( &ctx->running_lthash, account_lthash );
        ctx->acc_data_sz  = 0UL;
        ctx->hash_account = 0;
        ctx->metrics.accounts_hashed++;
      }
      break;
    }
    case FD_SNAPSHOT_HASH_MSG_FINI: {
      FD_TEST( ctx->state==FD_SNAPLT_STATE_HASHING );
      uchar * lthash_out = fd_chunk_to_laddr( ctx->out.wksp, ctx->out.chunk );
      fd_memcpy( lthash_out, &ctx->running_lthash, sizeof(fd_lthash_value_t) );
      fd_stem_publish( stem, 0UL, FD_SNAPSHOT_HASH_MSG_RESULT, ctx->out.chunk, FD_LTHASH_LEN_BYTES, 0UL, 0UL, 0UL );
      ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk, FD_SNAPSHOT_HASH_MSG_RESULT, ctx->out.chunk0, ctx->out.wmark );
      ctx->state     = FD_SNAPLT_STATE_DONE;
      break;
    }
    case FD_SNAPSHOT_HASH_MSG_SHUTDOWN: {
      FD_LOG_INFO(( "num hashed accounts is %lu", ctx->metrics.accounts_hashed ));
      FD_TEST( ctx->state==FD_SNAPLT_STATE_DONE );
      ctx->state = FD_SNAPLT_STATE_SHUTDOWN;
      break;
    }
    case FD_SNAPSHOT_HASH_MSG_RESET: {
      ctx->state = FD_SNAPLT_STATE_HASHING;
      fd_lthash_zero( &ctx->running_lthash );
      ctx->metrics.accounts_hashed = 0UL;
      break;
    }
    case FD_SNAPSHOT_HASH_MSG_SUB:
      /* These messages are handled in during_frag, do nothing here. */
      break;
    default:
      FD_LOG_ERR(( "unexpected sig %lu in during_frag", sig ));
      return;
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaplt_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaplt_tile_t), sizeof(fd_snaplt_tile_t) );

  if( FD_UNLIKELY( tile->in_cnt!=1UL ) )  FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1", tile->out_cnt  ));

  fd_topo_link_t const * in_link = &topo->links[ tile->in_link_id[ 0UL ] ];
  fd_topo_wksp_t const * in_wksp = &topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ];
  ctx->in.wksp                   = in_wksp->wksp;;
  ctx->in.chunk0                 = fd_dcache_compact_chunk0( ctx->in.wksp, in_link->dcache );
  ctx->in.wmark                  = fd_dcache_compact_wmark( ctx->in.wksp, in_link->dcache, in_link->mtu );
  ctx->in.mtu                    = in_link->mtu;

  fd_topo_link_t * writer_link = &topo->links[ tile->out_link_id[ 0UL ] ];
  ctx->out.wksp    = topo->workspaces[ topo->objs[ writer_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->out.chunk0  = fd_dcache_compact_chunk0( fd_wksp_containing( writer_link->dcache ), writer_link->dcache );
  ctx->out.wmark   = fd_dcache_compact_wmark ( ctx->out.wksp, writer_link->dcache, writer_link->mtu );
  ctx->out.chunk   = ctx->out.chunk0;
  ctx->out.mtu     = writer_link->mtu;

  ctx->metrics.accounts_hashed = 0UL;
  ctx->state                   = FD_SNAPLT_STATE_WAITING;
  ctx->acc_data_sz             = 0UL;
  ctx->hash_account            = 0;
  ctx->num_hash_tiles          = fd_topo_tile_name_cnt( topo, "snaplt" );
  ctx->hash_tile_idx           = tile->kind_id;

  fd_lthash_zero( &ctx->running_lthash );
}

#define STEM_BURST 1UL
#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snaplt_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snaplt_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_DURING_FRAG     during_frag
#define STEM_CALLBACK_AFTER_FRAG      after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snaplt = {
  .name              = NAME,
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run,
};

#undef NAME
