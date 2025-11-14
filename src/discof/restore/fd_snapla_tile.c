#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../ballet/lthash/fd_lthash_adder.h"

#include "generated/fd_snapla_tile_seccomp.h"

#include "utils/fd_ssctrl.h"
#include "utils/fd_ssparse.h"
#include "utils/fd_ssmanifest_parser.h"

#define NAME "snapla"

#define FD_SNAPLA_OUT_CTRL 0UL

struct fd_snapla_tile {
  int state;
  int full;

  ulong seed;
  int   hash_account;
  ulong num_hash_tiles;
  ulong hash_tile_idx;
  ulong accounts_seen;

  fd_lthash_adder_t adder[1];
  uchar             data[ FD_RUNTIME_ACC_SZ_MAX ];
  ulong             acc_data_sz;

  fd_ssparse_t *           ssparse;
  fd_ssmanifest_parser_t * manifest_parser;
  fd_lthash_value_t        running_lthash;

  struct {
    uchar pubkey[ FD_HASH_FOOTPRINT ];
    uchar owner[ FD_HASH_FOOTPRINT ];
    ulong data_len;
    ulong lamports;
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

typedef struct fd_snapla_tile fd_snapla_tile_t;

static inline int
should_shutdown( fd_snapla_tile_t * ctx ) {
  return ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN;
}

static ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_snapla_tile_t),
                       fd_ulong_max( fd_ssparse_align(), fd_ssmanifest_parser_align() ) );
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapla_tile_t),    sizeof(fd_snapla_tile_t)         );
  l = FD_LAYOUT_APPEND( l, fd_ssparse_align(),           fd_ssparse_footprint( 1UL<<24UL ) );
  l = FD_LAYOUT_APPEND( l, fd_ssmanifest_parser_align(), fd_ssmanifest_parser_footprint()  );
  return FD_LAYOUT_FINI( l, alignof(fd_snapla_tile_t) );
}

static void
metrics_write( fd_snapla_tile_t * ctx ) {
  FD_MGAUGE_SET( SNAPLA, FULL_ACCOUNTS_HASHED,        ctx->metrics.full.accounts_hashed );
  FD_MGAUGE_SET( SNAPLA, INCREMENTAL_ACCOUNTS_HASHED, ctx->metrics.incremental.accounts_hashed );
  FD_MGAUGE_SET( SNAPLA, STATE,                       (ulong)(ctx->state) );
}

static void
transition_malformed( fd_snapla_tile_t *  ctx,
                      fd_stem_context_t *  stem ) {
  ctx->state = FD_SNAPSHOT_STATE_ERROR;
  fd_stem_publish( stem, FD_SNAPLA_OUT_CTRL, FD_SNAPSHOT_MSG_CTRL_ERROR, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static int
should_hash_account( fd_snapla_tile_t * ctx ) {
  return ctx->accounts_seen%ctx->num_hash_tiles==ctx->hash_tile_idx;
}

static void
streamlined_hash( fd_snapla_tile_t * ctx,
                    uchar const *      frame ) {
  ulong data_len   = fd_ulong_load_8_fast( frame+0x08UL );
  uchar pubkey[32];  memcpy( pubkey, frame+0x10UL, 32UL );
  ulong lamports   = fd_ulong_load_8_fast( frame+0x30UL );
  ulong rent_epoch = fd_ulong_load_8_fast( frame+0x38UL ); (void)rent_epoch;
  uchar owner[32];   memcpy( owner, frame+0x40UL, 32UL );
  _Bool executable = !!frame[ 0x60UL ];

  if( FD_UNLIKELY( data_len > FD_RUNTIME_ACC_SZ_MAX ) ) FD_LOG_ERR(( "Found unusually large account (data_sz=%lu), aborting", data_len ));
  if( FD_UNLIKELY( lamports==0UL ) ) return;

  uchar executable_flag = executable & 0x1;

  fd_lthash_adder_push_solana_account( ctx->adder,
                                       &ctx->running_lthash,
                                       pubkey,
                                       frame+0x88UL,
                                       data_len,
                                       lamports,
                                       executable_flag,
                                       owner );

  if( FD_LIKELY( ctx->full ) ) ctx->metrics.full.accounts_hashed++;
  else                         ctx->metrics.incremental.accounts_hashed++;
}

static int
handle_data_frag( fd_snapla_tile_t * ctx,
                  ulong               chunk,
                  ulong               sz,
                  fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_FINISHING ) ) {
    FD_LOG_WARNING(( "received data fragment while in finishing state" ));
    transition_malformed( ctx, stem );
    return 0;
  } else if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_ERROR ) ) {
    /* Ignore all data frags after observing an error in the stream until
       we receive fail & init control messages to restart processing. */
    return 0;
  } else if( FD_UNLIKELY( ctx->state!=FD_SNAPSHOT_STATE_PROCESSING ) ) {
    FD_LOG_ERR(( "invalid state for data frag %d", ctx->state ));
  }

  FD_TEST( chunk>=ctx->in.chunk0 && chunk<=ctx->in.wmark && sz<=ctx->in.mtu );

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
        if( FD_LIKELY( should_hash_account( ctx ) && result->account_header.lamports!=0UL ) ) {
          FD_TEST( ctx->acc_data_sz==0UL );
          ctx->hash_account = 1;
          fd_memcpy( ctx->account_hdr.pubkey, result->account_header.pubkey, FD_HASH_FOOTPRINT );
          fd_memcpy( ctx->account_hdr.owner,  result->account_header.owner,  FD_HASH_FOOTPRINT );
          ctx->account_hdr.data_len   = result->account_header.data_len;
          ctx->account_hdr.executable = result->account_header.executable;
          ctx->account_hdr.lamports   = result->account_header.lamports;
        }
        ctx->accounts_seen++;
        break;
      case FD_SSPARSE_ADVANCE_ACCOUNT_DATA:
        if( FD_LIKELY( ctx->hash_account ) ) {
          fd_memcpy( ctx->data + ctx->acc_data_sz, result->account_data.data, result->account_data.data_sz );
          ctx->acc_data_sz += result->account_data.data_sz;
        }
        break;
      case FD_SSPARSE_ADVANCE_ACCOUNT_BATCH: {
        for( ulong i=0UL; i<result->account_batch.batch_cnt; i++ ) {
          if( FD_LIKELY( should_hash_account( ctx ) ) ) streamlined_hash( ctx, result->account_batch.batch[ i ] );
          ctx->accounts_seen++;
        }
        break;
      }
      case FD_SSPARSE_ADVANCE_DONE:
        ctx->state = FD_SNAPSHOT_STATE_FINISHING;
        break;
      default:
        FD_LOG_ERR(( "unexpected fd_ssparse_advance result %d", res ));
        break;
    }

    ctx->in.pos += result->bytes_consumed;
    if( FD_LIKELY( ctx->hash_account && ctx->acc_data_sz==ctx->account_hdr.data_len ) ) {
      fd_lthash_adder_push_solana_account( ctx->adder,
                                           &ctx->running_lthash,
                                           ctx->account_hdr.pubkey,
                                           ctx->data,
                                           ctx->account_hdr.data_len,
                                           ctx->account_hdr.lamports,
                                           (uchar)ctx->account_hdr.executable,
                                           ctx->account_hdr.owner );
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
handle_control_frag( fd_snapla_tile_t *  ctx,
                     fd_stem_context_t *  stem,
                     ulong                sig ) {
  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_INIT_FULL:
    case FD_SNAPSHOT_MSG_CTRL_INIT_INCR:
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->full = sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL;
      ctx->state = FD_SNAPSHOT_STATE_PROCESSING;
      fd_lthash_zero( &ctx->running_lthash );
      fd_ssparse_reset( ctx->ssparse );
      fd_ssmanifest_parser_init( ctx->manifest_parser, ctx->manifest );
      fd_lthash_adder_new( ctx->adder );
      break;

    case FD_SNAPSHOT_MSG_CTRL_FAIL:
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING ||
               ctx->state==FD_SNAPSHOT_STATE_FINISHING ||
               ctx->state==FD_SNAPSHOT_STATE_ERROR );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      fd_lthash_zero( &ctx->running_lthash );
      fd_ssparse_reset( ctx->ssparse );
      fd_ssmanifest_parser_init( ctx->manifest_parser, ctx->manifest );
      fd_lthash_adder_new( ctx->adder );
      break;

    case FD_SNAPSHOT_MSG_CTRL_NEXT:
    case FD_SNAPSHOT_MSG_CTRL_DONE:{
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_PROCESSING ||
               ctx->state==FD_SNAPSHOT_STATE_FINISHING  ||
               ctx->state==FD_SNAPSHOT_STATE_ERROR );
      if( FD_UNLIKELY( ctx->state!=FD_SNAPSHOT_STATE_FINISHING ) ) {
        transition_malformed( ctx, stem );
        return;
      }
      fd_lthash_adder_flush( ctx->adder, &ctx->running_lthash );
      uchar * lthash_out = fd_chunk_to_laddr( ctx->out.wksp, ctx->out.chunk );
      fd_memcpy( lthash_out, &ctx->running_lthash, sizeof(fd_lthash_value_t) );
      fd_stem_publish( stem, 0UL, FD_SNAPSHOT_HASH_MSG_RESULT_ADD, ctx->out.chunk, FD_LTHASH_LEN_BYTES, 0UL, 0UL, 0UL );
      ctx->out.chunk = fd_dcache_compact_next( ctx->out.chunk, FD_LTHASH_LEN_BYTES, ctx->out.chunk0, ctx->out.wmark );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN:
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->state = FD_SNAPSHOT_STATE_SHUTDOWN;
      break;

    case FD_SNAPSHOT_MSG_CTRL_ERROR:
      ctx->state = FD_SNAPSHOT_STATE_ERROR;
      break;

    default:
      FD_LOG_ERR(( "unexpected control sig %lu", sig ));
      return;
  }

  /* Forward the control message down the pipeline */
  fd_stem_publish( stem, FD_SNAPLA_OUT_CTRL, sig, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static inline int
returnable_frag( fd_snapla_tile_t *  ctx,
                 ulong                in_idx FD_PARAM_UNUSED,
                 ulong                seq    FD_PARAM_UNUSED,
                 ulong                sig,
                 ulong                chunk,
                 ulong                sz,
                 ulong                ctl    FD_PARAM_UNUSED,
                 ulong                tsorig FD_PARAM_UNUSED,
                 ulong                tspub  FD_PARAM_UNUSED,
                 fd_stem_context_t *  stem ) {
  FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );

  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_DATA ) ) return handle_data_frag( ctx, chunk, sz, stem );
  else                                           handle_control_frag( ctx, stem, sig );

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
  populate_sock_filter_policy_fd_snapla_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_snapla_tile_instr_cnt;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapla_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapla_tile_t), sizeof(fd_snapla_tile_t) );

  FD_TEST( fd_rng_secure( &ctx->seed, 8UL ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapla_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapla_tile_t),   sizeof(fd_snapla_tile_t)        );
  void * _ssparse         = FD_SCRATCH_ALLOC_APPEND( l, fd_ssparse_align(),           fd_ssparse_footprint( 1UL<<24UL ));
  void * _manifest_parser = FD_SCRATCH_ALLOC_APPEND( l, fd_ssmanifest_parser_align(), fd_ssmanifest_parser_footprint() );

  if( FD_UNLIKELY( tile->in_cnt!=1UL ) )  FD_LOG_ERR(( "tile `" NAME "` has %lu ins, expected 1",  tile->in_cnt  ));
  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "tile `" NAME "` has %lu outs, expected 1", tile->out_cnt  ));

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
  FD_TEST( 0==strcmp( out_link->name, "snapla_ls" ) );

  ctx->ssparse = fd_ssparse_new( _ssparse, 1UL<<24UL, 0UL );
  FD_TEST( ctx->ssparse );

  ctx->manifest_parser = fd_ssmanifest_parser_join( fd_ssmanifest_parser_new( _manifest_parser ) );
  FD_TEST( ctx->manifest_parser );

  fd_ssparse_batch_enable( ctx->ssparse, 1 );
  fd_lthash_adder_new( ctx->adder );
  fd_ssmanifest_parser_init( ctx->manifest_parser, ctx->manifest );

  ctx->metrics.full.accounts_hashed        = 0UL;
  ctx->metrics.incremental.accounts_hashed = 0UL;

  ctx->state                   = FD_SNAPSHOT_STATE_IDLE;
  ctx->full                    = 1;
  ctx->acc_data_sz             = 0UL;
  ctx->hash_account            = 0;
  ctx->num_hash_tiles          = fd_topo_tile_name_cnt( topo, "snapla" );
  ctx->hash_tile_idx           = tile->kind_id;
  ctx->accounts_seen           = 0UL;
  fd_lthash_zero( &ctx->running_lthash );
}

#define STEM_BURST 2UL /* one control message and one malformed message or one hash result message */
#define STEM_LAZY  1000L

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snapla_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snapla_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapla = {
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

