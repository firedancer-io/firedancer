#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../ballet/lthash/fd_lthash_adder.h"

#include "utils/fd_ssctrl.h"
#include "utils/fd_ssparse.h"
#include "utils/fd_ssmanifest_parser.h"

#include "generated/fd_snaplta_tile_seccomp.h"

#define NAME "snaplta"

#define FD_SNAPLTA_STATE_HASHING   (0)
#define FD_SNAPLTA_STATE_DONE      (1)
#define FD_SNAPLTA_STATE_MALFORMED (2)
#define FD_SNAPLTA_STATE_SHUTDOWN  (3)

struct fd_snaplta_tile {
  int state;
  int full;

  int   hash_account;
  ulong num_hash_tiles;
  ulong hash_tile_idx;

  fd_blake3_t b3[1];
  // fd_lthash_adder_t adder[1];
  // uchar       data[ FD_RUNTIME_ACC_SZ_MAX ];
  ulong       acc_data_sz;

  fd_ssparse_t *    ssparse;
  fd_ssmanifest_parser_t * manifest_parser;
  fd_lthash_value_t running_lthash;
  ulong num_accounts_seen;

  struct {
    uchar pubkey[ FD_HASH_FOOTPRINT ];
    uchar owner[ FD_HASH_FOOTPRINT ];
    ulong data_len;
    // ulong lamports;
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

  fd_snapshot_manifest_t manifest[1];
};

typedef struct fd_snaplta_tile fd_snaplta_tile_t;

static inline int
should_shutdown( fd_snaplta_tile_t * ctx ) {
  return ctx->state==FD_SNAPLTA_STATE_SHUTDOWN;
}

static ulong
scratch_align( void ) {
  return 128UL;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snaplta_tile_t),   sizeof(fd_snaplta_tile_t)         );
  l = FD_LAYOUT_APPEND( l, fd_ssparse_align(),           fd_ssparse_footprint( 1UL<<24UL ) );
  l = FD_LAYOUT_APPEND( l, fd_ssmanifest_parser_align(), fd_ssmanifest_parser_footprint()  );
  return FD_LAYOUT_FINI( l, alignof(fd_snaplta_tile_t) );
}

static void
metrics_write( fd_snaplta_tile_t * ctx ) {
  FD_MGAUGE_SET( SNAPLTA, FULL_ACCOUNTS_HASHED,        ctx->metrics.full.accounts_hashed );
  FD_MGAUGE_SET( SNAPLTA, INCREMENTAL_ACCOUNTS_HASHED, ctx->metrics.incremental.accounts_hashed );
  FD_MGAUGE_SET( SNAPLTA, STATE,                       (ulong)(ctx->state) );
}

static void
transition_malformed( fd_snaplta_tile_t * ctx,
                      fd_stem_context_t * stem ) {
  ctx->state = FD_SNAPLTA_STATE_MALFORMED;
  fd_stem_publish( stem, 1UL, FD_SNAPSHOT_MSG_CTRL_MALFORMED, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static int
should_hash_account( fd_snaplta_tile_t * ctx,
                     uchar const         pubkey[ static FD_HASH_FOOTPRINT ] ) {
  (void)pubkey;
  return ctx->num_accounts_seen%ctx->num_hash_tiles==ctx->hash_tile_idx;
}

static int
handle_data_frag( fd_snaplta_tile_t * ctx,
                  ulong               chunk,
                  ulong               sz,
                  fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPLTA_STATE_SHUTDOWN ) ) return 0;

  FD_TEST( ctx->state==FD_SNAPLTA_STATE_HASHING || ctx->state==FD_SNAPLTA_STATE_DONE );
  FD_TEST( chunk>=ctx->in.chunk0 && chunk<=ctx->in.wmark && sz<=ctx->in.mtu );

  if( FD_UNLIKELY( ctx->state==FD_SNAPLTA_STATE_DONE ) ) {
    FD_LOG_WARNING(( "received data fragment while in done state" ));
    transition_malformed( ctx, stem );
    return 0;
  }

    for(;;) {

      if( FD_UNLIKELY( sz-ctx->in.pos==0UL ) ) break;
    uchar const * data = (uchar const *)fd_chunk_to_laddr_const( ctx->in.wksp, chunk ) + ctx->in.pos;

    fd_ssparse_advance_result_t result[1];
    int res = fd_ssparse_advance( ctx->ssparse, data, sz-ctx->in.pos, result );
    switch( res ) {
      case FD_SSPARSE_ADVANCE_ERROR:
        transition_malformed( ctx, stem );
        return 0;
      case FD_SSPARSE_ADVANCE_AGAIN:
        break;
      case FD_SSPARSE_ADVANCE_STATUS_CACHE:
      case FD_SSPARSE_ADVANCE_MANIFEST_AND_STATUS_CACHE_DONE:
        /* ignore */
        break;
      case FD_SSPARSE_ADVANCE_MANIFEST: {
        int res = fd_ssmanifest_parser_consume( ctx->manifest_parser,
          result->manifest.data,
          result->manifest.data_sz,
          result->manifest.acc_vec_map,
          result->manifest.acc_vec_pool );
        if( FD_UNLIKELY( res==FD_SSMANIFEST_PARSER_ADVANCE_ERROR ) ) {
          transition_malformed( ctx, stem );
          return 0;
        }
        break;
      }
      case FD_SSPARSE_ADVANCE_ACCOUNT_HEADER:
        ctx->num_accounts_seen++;
        if( FD_LIKELY( should_hash_account( ctx, result->account_header.pubkey) && result->account_header.lamports!=0UL ) ) {
          FD_TEST( ctx->acc_data_sz==0UL );
          ctx->hash_account = 1;
          // fd_blake3_init( ctx->b3 );
          // fd_blake3_append( ctx->b3, &result->account_header.lamports, sizeof( ulong ) );
          // fd_memcpy( ctx->account_hdr.pubkey, result->account_header.pubkey, FD_HASH_FOOTPRINT );
          // fd_memcpy( ctx->account_hdr.owner,  result->account_header.owner,  FD_HASH_FOOTPRINT );
          ctx->account_hdr.data_len   = result->account_header.data_len;
          // ctx->account_hdr.executable = result->account_header.executable;
          // ctx->account_hdr.lamports   = result->account_header.lamports;
        }
        break;
      case FD_SSPARSE_ADVANCE_ACCOUNT_DATA:
        if( FD_LIKELY( ctx->hash_account ) ) {
          fd_blake3_append( ctx->b3, result->account_data.data, result->account_data.len );
          // fd_memcpy( ctx->data + ctx->acc_data_sz, result->account_data.data, result->account_data.len );
          ctx->acc_data_sz += result->account_data.len;
        }
        break;
      case FD_SSPARSE_ADVANCE_DONE:
        ctx->state = FD_SNAPLTA_STATE_DONE;
        break;
      default:
        FD_LOG_ERR(( "unexpected fd_ssparse_advance result %d", res ));
        break;
    }

    ctx->in.pos += result->bytes_consumed;
    if( FD_LIKELY( ctx->hash_account && ctx->acc_data_sz==ctx->account_hdr.data_len ) ) {
      //fd_lthash_value_t account_lthash[1];
      // fd_lthash_zero( account_lthash );

      // uchar executable_flag = ctx->account_hdr.executable & 0x1;
      // fd_blake3_append( ctx->b3, &executable_flag, sizeof(uchar) );
      // fd_blake3_append( ctx->b3, ctx->account_hdr.owner, FD_HASH_FOOTPRINT );
      // fd_blake3_append( ctx->b3, ctx->account_hdr.pubkey,  FD_HASH_FOOTPRINT );
      // fd_blake3_fini_2048( ctx->b3, account_lthash->bytes );

      // fd_lthash_add( &ctx->running_lthash, account_lthash );
      // fd_lthash_adder_push_solana_account( ctx->adder,
      //                                      &ctx->running_lthash,
      //                                      ctx->account_hdr.pubkey,
      //                                      ctx->data,
      //                                      ctx->account_hdr.data_len,
      //                                      ctx->account_hdr.lamports,
      //                                      (uchar)ctx->account_hdr.executable,
      //                                      ctx->account_hdr.owner );
      ctx->acc_data_sz  = 0UL;
      ctx->hash_account = 0;

      if( FD_LIKELY( ctx->full ) ) ctx->metrics.full.accounts_hashed++;
      else                         ctx->metrics.incremental.accounts_hashed++;
    }

    }

  int reprocess_frag = ctx->in.pos<sz;
  if( FD_LIKELY( !reprocess_frag ) ) ctx->in.pos = 0UL;
  return reprocess_frag;
}

static void
handle_control_frag( fd_snaplta_tile_t *  ctx,
                     fd_stem_context_t *  stem,
                     ulong                sig ) {
  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_RESET_FULL:
      ctx->full  = 1;
      ctx->state = FD_SNAPLTA_STATE_HASHING;
      fd_lthash_zero( &ctx->running_lthash );
      fd_ssparse_reset( ctx->ssparse );
      fd_ssmanifest_parser_init( ctx->manifest_parser, ctx->manifest );
      // fd_lthash_adder_new( ctx->adder );
      ctx->metrics.full.accounts_hashed        = 0UL;
      ctx->metrics.incremental.accounts_hashed = 0UL;
      break;
    case FD_SNAPSHOT_MSG_CTRL_RESET_INCREMENTAL:
      ctx->full  = 0;
      ctx->state = FD_SNAPLTA_STATE_HASHING;
      fd_lthash_zero( &ctx->running_lthash );
      fd_ssparse_reset( ctx->ssparse );
      fd_ssmanifest_parser_init( ctx->manifest_parser, ctx->manifest );
      // fd_lthash_adder_new( ctx->adder );
      ctx->metrics.incremental.accounts_hashed = 0UL;
      break;
    case FD_SNAPSHOT_MSG_CTRL_EOF_FULL: {
      // fd_lthash_adder_flush( ctx->adder, &ctx->running_lthash );
      uchar * lthash_out = fd_chunk_to_laddr( ctx->out.wksp, ctx->out.chunk );
      fd_memcpy( lthash_out, &ctx->running_lthash, sizeof(fd_lthash_value_t) );
      fd_stem_publish( stem, 0UL, FD_SNAPSHOT_HASH_MSG_RESULT_ADD, ctx->out.chunk, FD_LTHASH_LEN_BYTES, 0UL, 0UL, 0UL );
      ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk, FD_LTHASH_LEN_BYTES, ctx->out.chunk0, ctx->out.wmark );
      ctx->full      = 0;
      fd_lthash_zero( &ctx->running_lthash );
      fd_ssparse_reset( ctx->ssparse );
      fd_ssmanifest_parser_init( ctx->manifest_parser, ctx->manifest );
      // fd_lthash_adder_new( ctx->adder );
      ctx->state = FD_SNAPLTA_STATE_HASHING;
      break;
    }
    case FD_SNAPSHOT_MSG_CTRL_DONE: {
      // fd_lthash_adder_flush( ctx->adder, &ctx->running_lthash );
      uchar * lthash_out = fd_chunk_to_laddr( ctx->out.wksp, ctx->out.chunk );
      fd_memcpy( lthash_out, &ctx->running_lthash, sizeof(fd_lthash_value_t) );
      fd_stem_publish( stem, 0UL, FD_SNAPSHOT_HASH_MSG_RESULT_ADD, ctx->out.chunk, FD_LTHASH_LEN_BYTES, 0UL, 0UL, 0UL );
      ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk, FD_LTHASH_LEN_BYTES, ctx->out.chunk0, ctx->out.wmark );
      ctx->state     = FD_SNAPLTA_STATE_DONE;
      break;
    }
    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN:
      FD_LOG_INFO(( "num hashed accounts in full snapshot is %lu and in incremental snapshot is %lu", ctx->metrics.full.accounts_hashed, ctx->metrics.incremental.accounts_hashed ));
      FD_TEST( ctx->state==FD_SNAPLTA_STATE_DONE );
      ctx->state = FD_SNAPLTA_STATE_SHUTDOWN;
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
returnable_frag( fd_snaplta_tile_t * ctx,
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

  FD_TEST( ctx->state!=FD_SNAPLTA_STATE_SHUTDOWN );

  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_DATA ) ) return handle_data_frag( ctx, chunk, sz, stem );
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
  populate_sock_filter_policy_fd_snaplta_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_snaplta_tile_instr_cnt;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_LOG_WARNING(("starting up"));

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snaplta_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snaplta_tile_t),   sizeof(fd_snaplta_tile_t)        );
  void * _ssparse         = FD_SCRATCH_ALLOC_APPEND( l, fd_ssparse_align(),           fd_ssparse_footprint( 1UL<<24UL ));
  void * _manifest_parser = FD_SCRATCH_ALLOC_APPEND( l, fd_ssmanifest_parser_align(), fd_ssmanifest_parser_footprint() );

  if( FD_UNLIKELY( tile->in_cnt!=1UL ) )  FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=2UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 2", tile->out_cnt  ));

  fd_topo_link_t const * in_link = &topo->links[ tile->in_link_id[ 0UL ] ];
  fd_topo_wksp_t const * in_wksp = &topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ];
  ctx->in.wksp                   = in_wksp->wksp;;
  ctx->in.chunk0                 = fd_dcache_compact_chunk0( ctx->in.wksp, in_link->dcache );
  ctx->in.wmark                  = fd_dcache_compact_wmark( ctx->in.wksp, in_link->dcache, in_link->mtu );
  ctx->in.mtu                    = in_link->mtu;
  ctx->in.pos                    = 0UL;

  fd_topo_link_t * out_link = &topo->links[ tile->out_link_id[ 0UL ] ];
  ctx->out.wksp    = topo->workspaces[ topo->objs[ out_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->out.chunk0  = fd_dcache_compact_chunk0( fd_wksp_containing( out_link->dcache ), out_link->dcache );
  ctx->out.wmark   = fd_dcache_compact_wmark ( ctx->out.wksp, out_link->dcache, out_link->mtu );
  ctx->out.chunk   = ctx->out.chunk0;
  ctx->out.mtu     = out_link->mtu;

  FD_TEST( strncmp( topo->links[ tile->out_link_id[ 1UL ] ].name, "snaplta_rd", 9UL )==0 );

  /* TODO: get seed in privileged init  */
  ctx->ssparse = fd_ssparse_new( _ssparse, 1UL<<24UL, 0UL );
  FD_TEST( ctx->ssparse );

  ctx->manifest_parser = fd_ssmanifest_parser_join( fd_ssmanifest_parser_new( _manifest_parser ) );
  FD_TEST( ctx->manifest_parser );

  // fd_lthash_adder_new( ctx->adder );

  fd_ssmanifest_parser_init( ctx->manifest_parser, ctx->manifest );

  ctx->metrics.full.accounts_hashed        = 0UL;
  ctx->metrics.incremental.accounts_hashed = 0UL;

  ctx->state                   = FD_SNAPLTA_STATE_HASHING;
  ctx->full                    = 1;
  ctx->acc_data_sz             = 0UL;
  ctx->hash_account            = 0;
  ctx->num_hash_tiles          = fd_topo_tile_name_cnt( topo, "snaplta" );
  ctx->hash_tile_idx           = tile->kind_id;
  ctx->num_accounts_seen       = 0UL;
  FD_LOG_WARNING(("hashing accounts for tile %lu out of %lu", ctx->hash_tile_idx, ctx->num_hash_tiles ));

  fd_lthash_zero( &ctx->running_lthash );
  FD_LOG_WARNING(("started up"));
}

#define STEM_BURST 1UL
#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snaplta_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snaplta_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snaplta = {
  .name                     = NAME,
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};

#undef NAME
