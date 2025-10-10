#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../flamenco/runtime/fd_hashes.h"

#include "utils/fd_ssctrl.h"

#include "generated/fd_snaplts_tile_seccomp.h"

#define NAME "snaplts"

#define FD_SNAPLTS_STATE_HASHING   (0)
#define FD_SNAPLTS_STATE_DONE      (1)
#define FD_SNAPLTS_STATE_MALFORMED (2)
#define FD_SNAPLTS_STATE_SHUTDOWN  (3)

#define IN_KIND_SNAPDC  (0)
#define IN_KIND_SNAPIN  (1)
#define MAX_IN_LINKS    (2)

struct fd_snaplts_tile {
  int state;
  int full;

  fd_lthash_value_t running_lthash;

  fd_blake3_t b3[1];
  ulong       acc_data_sz;
  int         hash_account;
  ulong num_hash_tiles;
  ulong hash_tile_idx;

  uchar in_kind[ MAX_IN_LINKS ];

  struct {
    uchar pubkey[ FD_HASH_FOOTPRINT ];
    uchar owner[ FD_HASH_FOOTPRINT ];
    ulong data_len;
    int   executable;
  } account_hdr;

  struct {
    struct {
      ulong accounts_hashed;
    } full;

    struct {
      ulong accounts_hashed;
    } incremental;
  } metrics;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
    ulong       pos;
  } in;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       chunk;
    ulong       mtu;
  } out;
};

typedef struct fd_snaplts_tile fd_snaplts_tile_t;

static inline int
should_shutdown( fd_snaplts_tile_t * ctx ) {
  return ctx->state==FD_SNAPLTS_STATE_SHUTDOWN;
}

static ulong
scratch_align( void ) {
  return 128UL;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snaplts_tile_t), sizeof(fd_snaplts_tile_t) );
  return FD_LAYOUT_FINI( l, alignof(fd_snaplts_tile_t) );
}

static void
metrics_write( fd_snaplts_tile_t * ctx ) {
  FD_MGAUGE_SET( SNAPLTS, FULL_ACCOUNTS_HASHED,        ctx->metrics.full.accounts_hashed );
  FD_MGAUGE_SET( SNAPLTS, INCREMENTAL_ACCOUNTS_HASHED, ctx->metrics.incremental.accounts_hashed );
  FD_MGAUGE_SET( SNAPLTS, STATE,                       (ulong)(ctx->state) );
}

static int
should_hash_account( fd_snaplts_tile_t * ctx,
                     uchar const         pubkey[ static FD_HASH_FOOTPRINT ] ) {
  return fd_hash( pubkey[ 4UL ], pubkey, sizeof(fd_pubkey_t) )%ctx->num_hash_tiles==ctx->hash_tile_idx;
}

static void
handle_data_frag( fd_snaplts_tile_t *  ctx,
                  ulong                sig,
                  ulong                chunk,
                  ulong                sz ) {
  FD_TEST( ctx->state==FD_SNAPLTS_STATE_HASHING );

  switch( sig ) {
    case FD_SNAPSHOT_HASH_MSG_SUB: {
      fd_snapshot_existing_account_t const * prev_acc = fd_chunk_to_laddr_const( ctx->in.wksp, chunk );

      if( should_hash_account( ctx, prev_acc->hdr.pubkey ) ) {
        fd_lthash_value_t prev_lthash[1];
        fd_hashes_account_lthash_simple( prev_acc->hdr.pubkey,
                                         prev_acc->hdr.owner,
                                         prev_acc->hdr.lamports,
                                         prev_acc->hdr.executable,
                                         prev_acc->data,
                                         prev_acc->hdr.data_len,
                                         prev_lthash );
        fd_lthash_add( &ctx->running_lthash, prev_lthash );

        if( FD_LIKELY( ctx->full ) ) ctx->metrics.full.accounts_hashed++;
        else                         ctx->metrics.incremental.accounts_hashed++;
      }
      break;
    }
    case FD_SNAPSHOT_HASH_MSG_SUB_HDR: {
      fd_snapshot_account_t const * acc = fd_chunk_to_laddr_const( ctx->in.wksp, chunk );

      if( should_hash_account( ctx, acc->pubkey ) && acc->lamports!=0UL ) {
        ctx->hash_account = 1;
        fd_blake3_init( ctx->b3 );
        fd_blake3_append( ctx->b3, &acc->lamports, sizeof(ulong) );
        ctx->account_hdr.data_len = acc->data_len;
        ctx->account_hdr.executable = acc->executable;
        memcpy( ctx->account_hdr.owner, acc->owner, FD_HASH_FOOTPRINT );
        memcpy( ctx->account_hdr.pubkey, acc->pubkey, FD_HASH_FOOTPRINT );
      }
      break;
    }
    case FD_SNAPSHOT_HASH_MSG_SUB_DATA: {
      if( FD_LIKELY( !ctx->hash_account ) ) break;

      uchar const * acc_data = fd_chunk_to_laddr_const( ctx->in.wksp, chunk );
      fd_blake3_append( ctx->b3, acc_data, sz );
      ctx->acc_data_sz += sz;
      break;
    }
    default:
      FD_LOG_ERR(( "unexpected sig %lu in handle_data_frag", sig ));
      return;
  }

  if( FD_LIKELY( ctx->hash_account && ctx->acc_data_sz==ctx->account_hdr.data_len ) ) {
    fd_lthash_value_t account_lthash[1];
    fd_lthash_zero( account_lthash );

    uchar executable_flag = ctx->account_hdr.executable & 0x1;
    fd_blake3_append( ctx->b3, &executable_flag, sizeof(uchar) );
    fd_blake3_append( ctx->b3, ctx->account_hdr.owner, FD_HASH_FOOTPRINT );
    fd_blake3_append( ctx->b3, ctx->account_hdr.pubkey,  FD_HASH_FOOTPRINT );
    fd_blake3_fini_2048( ctx->b3, account_lthash->bytes );

    fd_lthash_add( &ctx->running_lthash, account_lthash );
    ctx->acc_data_sz  = 0UL;
    ctx->hash_account = 0;

    if( FD_LIKELY( ctx->full ) ) ctx->metrics.full.accounts_hashed++;
    else                         ctx->metrics.incremental.accounts_hashed++;
  }

}

static void
handle_control_frag( fd_snaplts_tile_t *  ctx,
                     fd_stem_context_t *  stem,
                     ulong                sig ) {
  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_RESET_FULL:
      ctx->full  = 1;
      ctx->state = FD_SNAPLTS_STATE_HASHING;
      fd_lthash_zero( &ctx->running_lthash );

      ctx->metrics.full.accounts_hashed        = 0UL;
      ctx->metrics.incremental.accounts_hashed = 0UL;
      break;
    case FD_SNAPSHOT_MSG_CTRL_RESET_INCREMENTAL:
      ctx->full  = 0;
      ctx->state = FD_SNAPLTS_STATE_HASHING;
      fd_lthash_zero( &ctx->running_lthash );
      ctx->metrics.incremental.accounts_hashed = 0UL;
      break;
    case FD_SNAPSHOT_MSG_CTRL_EOF_FULL: {
      FD_LOG_WARNING(("hashed %lu accounts in full snapshot", ctx->metrics.full.accounts_hashed));
      uchar * lthash_out = fd_chunk_to_laddr( ctx->out.wksp, ctx->out.chunk );
      fd_memcpy( lthash_out, &ctx->running_lthash, sizeof(fd_lthash_value_t) );
      fd_stem_publish( stem, 0UL, FD_SNAPSHOT_HASH_MSG_RESULT_SUB, ctx->out.chunk, FD_LTHASH_LEN_BYTES, 0UL, 0UL, 0UL );
      ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk, FD_LTHASH_LEN_BYTES, ctx->out.chunk0, ctx->out.wmark );
      ctx->full      = 0;
      fd_lthash_zero( &ctx->running_lthash );

      break;
    }
    case FD_SNAPSHOT_MSG_CTRL_DONE: {
      FD_LOG_WARNING(("hashed %lu accounts in incremental snapshot", ctx->metrics.incremental.accounts_hashed));
      uchar * lthash_out = fd_chunk_to_laddr( ctx->out.wksp, ctx->out.chunk );
      fd_memcpy( lthash_out, &ctx->running_lthash, sizeof(fd_lthash_value_t) );
      fd_stem_publish( stem, 0UL, FD_SNAPSHOT_HASH_MSG_RESULT_SUB, ctx->out.chunk, FD_LTHASH_LEN_BYTES, 0UL, 0UL, 0UL );
      ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk, FD_LTHASH_LEN_BYTES, ctx->out.chunk0, ctx->out.wmark );
      ctx->state     = FD_SNAPLTS_STATE_DONE;
      break;
    }
    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN:
      FD_LOG_INFO(( "num hashed accounts in full snapshot is %lu and in incremental snapshot is %lu", ctx->metrics.full.accounts_hashed, ctx->metrics.incremental.accounts_hashed ));
      FD_TEST( ctx->state==FD_SNAPLTS_STATE_DONE );
      ctx->state = FD_SNAPLTS_STATE_SHUTDOWN;
      break;
    default:
      FD_LOG_ERR(( "unexpected sig %lu in handle_control_frag", sig ));
      return;
  }
  /* We must acknowledge after handling the control frag, because if it
     causes us to generate a malformed transition, that must be sent
     back to the snaprd controller before the acknowledgement. */
  fd_stem_publish( stem, 1UL, FD_SNAPSHOT_MSG_CTRL_ACK, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static inline int
returnable_frag( fd_snaplts_tile_t * ctx,
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
  (void)sz;

  FD_TEST( ctx->state!=FD_SNAPLTS_STATE_SHUTDOWN );

  if( FD_LIKELY( sig==FD_SNAPSHOT_HASH_MSG_SUB || sig==FD_SNAPSHOT_HASH_MSG_SUB_HDR || sig==FD_SNAPSHOT_HASH_MSG_SUB_DATA ) ) handle_data_frag( ctx, sig, chunk, sz );
  else                                             handle_control_frag( ctx, stem, sig ); 

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
  populate_sock_filter_policy_fd_snaplts_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_snaplts_tile_instr_cnt;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaplts_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaplts_tile_t), sizeof(fd_snaplts_tile_t)         );

  if( FD_UNLIKELY( tile->in_cnt!=1UL ) )  FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=2UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 2", tile->out_cnt  ));

  for( ulong i=0UL; i<(tile->in_cnt); i++ ) {
    fd_topo_link_t * in_link = &topo->links[ tile->in_link_id[ i ] ];
    if( FD_LIKELY( 0==strcmp( in_link->name, "snapin_lts" ) ) ) {
      fd_topo_wksp_t const * in_wksp = &topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ];
      ctx->in.wksp                   = in_wksp->wksp;;
      ctx->in.chunk0                 = fd_dcache_compact_chunk0( ctx->in.wksp, in_link->dcache );
      ctx->in.wmark                  = fd_dcache_compact_wmark( ctx->in.wksp, in_link->dcache, in_link->mtu );
      ctx->in.mtu                    = in_link->mtu;
      ctx->in.pos                    = 0UL;
    } else {
      FD_LOG_ERR(( "tile `" NAME "` has unexpected in link name `%s`", in_link->name ));
    }
  }

  fd_topo_link_t * out_link = &topo->links[ tile->out_link_id[ 0UL ] ];
  ctx->out.wksp    = topo->workspaces[ topo->objs[ out_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->out.chunk0  = fd_dcache_compact_chunk0( fd_wksp_containing( out_link->dcache ), out_link->dcache );
  ctx->out.wmark   = fd_dcache_compact_wmark ( ctx->out.wksp, out_link->dcache, out_link->mtu );
  ctx->out.chunk   = ctx->out.chunk0;
  ctx->out.mtu     = out_link->mtu;

  FD_TEST( strncmp( topo->links[ tile->out_link_id[ 1UL ] ].name, "snaplts_rd", 9UL )==0 );

  ctx->metrics.full.accounts_hashed        = 0UL;
  ctx->metrics.incremental.accounts_hashed = 0UL;

  ctx->state                      = FD_SNAPLTS_STATE_HASHING;
  ctx->full                       = 1;
  ctx->hash_account               = 0;
  ctx->num_hash_tiles             = fd_topo_tile_name_cnt( topo, "snaplts" );
  ctx->hash_tile_idx              = tile->kind_id;

  fd_lthash_zero( &ctx->running_lthash );
}

#define STEM_BURST 1UL
#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snaplts_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snaplts_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snaplts = {
  .name                     = NAME,
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};

#undef NAME
