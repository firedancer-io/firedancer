#include "fd_gossix_tile.h"

#include "../../../../ballet/base58/fd_base58.h"
#include "../../../../disco/metrics/fd_metrics.h"
#include "../../../../disco/metrics/generated/fd_metrics_enums.h"
#include "../../../../util/pod/fd_pod_format.h"
#include "../../../../util/net/fd_ip4.h"

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( fd_gossix_tile_ctx_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_gossix_tile_ctx_t), sizeof(fd_gossix_tile_ctx_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_gossix_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_gossix_tile_ctx_t), sizeof(fd_gossix_tile_ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  memset( ctx, 0, sizeof(*ctx) );

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    if( !strcmp( link->name, "gossip_out" ) ) {
      fd_topo_wksp_t * wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];
      ctx->gossip_out_wksp = wksp->wksp;
    }
  }
  FD_TEST( ctx->gossip_out_wksp );

  /* Join gossip tile metrics (read-only) for CRDS counts */
  ulong gossip_tile_idx = fd_topo_find_tile( topo, "gossip", 0UL );
  FD_TEST( gossip_tile_idx!=ULONG_MAX );
  ctx->gossip_metrics = fd_metrics_tile( topo->tiles[ gossip_tile_idx ].metrics );
  FD_TEST( ctx->gossip_metrics );

  /* Read config from pod properties */
  char const * pod_path = fd_pod_queryf_cstr( topo->props, NULL, "gossix.out_path" );
  FD_TEST( pod_path );
  fd_cstr_fini( fd_cstr_append_cstr_safe( fd_cstr_init( ctx->out_path ), pod_path, PATH_MAX-1UL ) );

  ctx->max_entries   = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "gossix.max_entries" );
  ctx->max_contact   = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "gossix.max_contact" );
  ctx->timeout_nanos = fd_pod_queryf_long( topo->props, LONG_MAX, "gossix.timeout_nanos" );
  ctx->start_nanos   = fd_log_wallclock();
  ctx->done          = 0;

  ctx->exit_after_steady        = fd_pod_queryf_int( topo->props, 0, "gossix.exit_after_steady" );
  ctx->steady_last_ci_cnt       = 0UL;
  ctx->steady_last_change_nanos = ctx->start_nanos;

  /* Join the done fseq */
  ulong done_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "gossix_done" );
  FD_TEST( done_obj_id!=ULONG_MAX );
  ctx->done_fseq = fd_fseq_join( fd_topo_obj_laddr( topo, done_obj_id ) );
  FD_TEST( ctx->done_fseq );
}

/* gossix_append_sock appends a JSON key with a socket value.  Uses
   a quoted "ip:port" string if the socket is set, or null if unset. */

static char *
gossix_append_sock( char *                     p,
                    char const *               key,
                    fd_gossip_socket_t const * s,
                    int                        trailing_comma ) {
  if( FD_LIKELY( s->ip4 || s->port ) ) {
    p = fd_cstr_append_printf( p, "    \"%s\": \"" FD_IP4_ADDR_FMT ":%u\"%s\n", key, FD_IP4_ADDR_FMT_ARGS( s->ip4 ), (uint)s->port, trailing_comma ? "," : "" );
  } else {
    p = fd_cstr_append_printf( p, "    \"%s\": null%s\n", key, trailing_comma ? "," : "" );
  }
  return p;
}

static void
gossix_write_json( fd_gossix_tile_ctx_t * ctx ) {
  char const * path = ctx->out_path;
  int fd = open( path, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0644 );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_WARNING(( "Failed to open output file `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return;
  }

  uchar wbuf[ 4096UL ];
  fd_io_buffered_ostream_t out[ 1UL ];
  fd_io_buffered_ostream_init( out, fd, wbuf, sizeof(wbuf) );

  int werr = fd_io_buffered_ostream_write( out, "[\n", 2UL );

  char   buf[ 2048 ];
  ulong ci_cnt = 0UL;
  int   first  = 1;

  for( ulong i=0UL; i<FD_CONTACT_INFO_TABLE_SIZE && !werr; i++ ) {
    fd_gossix_ci_entry_t * entry = &ctx->ci_table[ i ];
    if( !entry->valid ) continue;

    fd_gossip_contact_info_t * ci = entry->ci;

    char identity_b58[ FD_BASE58_ENCODED_32_SZ ];
    fd_base58_encode_32( entry->pubkey, NULL, identity_b58 );

    char version_buf[ 64 ];
    fd_gossip_version_cstr( ci->version.major, ci->version.minor, ci->version.patch, version_buf, sizeof(version_buf) );

    char * p = fd_cstr_init( buf );
    if( FD_LIKELY( !first ) ) p = fd_cstr_append_cstr( p, ",\n" );
    first = 0;

    /* Fields aligned with fd.validators ClickHouse schema */
    p = fd_cstr_append_cstr( p, "  {\n" );
    p = fd_cstr_append_printf( p, "    \"identity\": \"%s\",\n",         identity_b58 );
    p = fd_cstr_append_printf( p, "    \"software_version\": \"%s\",\n", version_buf );
    p = fd_cstr_append_printf( p, "    \"shred_version\": %u,\n",        ci->shred_version );
    p = fd_cstr_append_printf( p, "    \"wallclock\": %lu,\n",           entry->wallclock );
    p = fd_cstr_append_printf( p, "    \"client_id\": %u,\n",            (uint)ci->version.client );
    p = fd_cstr_append_printf( p, "    \"feature_set\": %u,\n",          ci->version.feature_set );
    p = gossix_append_sock( p, "gossip",       &ci->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_GOSSIP       ], 1 );
    p = gossix_append_sock( p, "rpc",          &ci->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_RPC          ], 1 );
    p = gossix_append_sock( p, "tpu",          &ci->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_TPU          ], 1 );
    p = gossix_append_sock( p, "tpu_quic",     &ci->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_QUIC     ], 1 );
    p = gossix_append_sock( p, "tvu",          &ci->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_TVU          ], 1 );
    p = gossix_append_sock( p, "serve_repair", &ci->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_SERVE_REPAIR ], 1 );
    p = gossix_append_sock( p, "tpu_vote",     &ci->sockets[ FD_GOSSIP_CONTACT_INFO_SOCKET_TPU_VOTE     ], 0 );
    p = fd_cstr_append_cstr( p, "  }" );
    fd_cstr_fini( p );

    ulong len = (ulong)(p - buf);
    werr = fd_io_buffered_ostream_write( out, buf, len );
    ci_cnt++;
  }

  if( !werr ) fd_io_buffered_ostream_write( out, "\n]\n", 3UL );
  int err = fd_io_buffered_ostream_flush( out );
  if( FD_UNLIKELY( err ) ) FD_LOG_WARNING(( "flush failed for %s (%i-%s)", path, err, fd_io_strerror( err ) ));
  fd_io_buffered_ostream_fini( out );
  close( fd );

  FD_LOG_NOTICE(( "Wrote %lu contact infos to %s", ci_cnt, path ));
}

static inline void
during_housekeeping( fd_gossix_tile_ctx_t * ctx ) {
  if( FD_UNLIKELY( ctx->done ) ) return;

  volatile ulong const * gm = ctx->gossip_metrics;
  ulong total_crds = 0UL;
  for( ulong i=0UL; i<FD_METRICS_ENUM_CRDS_VALUE_CNT; i++ ) {
    total_crds += gm[ MIDX( GAUGE, GOSSIP, CRDS_COUNT )+i ];
  }
  ulong total_contact_infos = gm[ MIDX( GAUGE, GOSSIP, CRDS_COUNT_CONTACT_INFO_V2 ) ];

  int threshold = ( total_crds>=ctx->max_entries || total_contact_infos>=ctx->max_contact );
  int timeout   = ( (fd_log_wallclock()-ctx->start_nanos)>=ctx->timeout_nanos );

  int steady = 0;
  if( ctx->exit_after_steady ) {
    long now = fd_log_wallclock();
    if( FD_LIKELY( total_contact_infos!=ctx->steady_last_ci_cnt ) ) {
      ctx->steady_last_ci_cnt       = total_contact_infos;
      ctx->steady_last_change_nanos = now;
    } else if( FD_UNLIKELY( total_contact_infos>0UL && (now-ctx->steady_last_change_nanos)>=(long)5e9 /* 5s */ ) ) {
      steady = 1;
    }
  }

  if( FD_UNLIKELY( threshold || timeout || steady ) ) {
    gossix_write_json( ctx );
    ctx->done = 1;
    fd_fseq_update( ctx->done_fseq, FD_GOSSIX_FSEQ_DONE );
  }
}

static inline int
returnable_frag( fd_gossix_tile_ctx_t * ctx,
                 ulong                  in_idx   FD_PARAM_UNUSED,
                 ulong                  seq      FD_PARAM_UNUSED,
                 ulong                  sig,
                 ulong                  chunk,
                 ulong                  sz       FD_PARAM_UNUSED,
                 ulong                  ctl      FD_PARAM_UNUSED,
                 ulong                  tsorig   FD_PARAM_UNUSED,
                 ulong                  tspub    FD_PARAM_UNUSED,
                 fd_stem_context_t *    stem     FD_PARAM_UNUSED ) {

  fd_gossip_update_message_t const * msg = (fd_gossip_update_message_t const *)fd_chunk_to_laddr_const( ctx->gossip_out_wksp, chunk );

  if( sig==(ulong)FD_GOSSIP_UPDATE_TAG_CONTACT_INFO ) {
    ulong idx = msg->contact_info->idx;
    if( FD_LIKELY( idx<FD_CONTACT_INFO_TABLE_SIZE ) ) {
      fd_gossix_ci_entry_t * entry = &ctx->ci_table[ idx ];
      entry->valid     = 1;
      entry->wallclock = msg->wallclock;
      fd_memcpy( entry->pubkey, msg->origin, 32UL );
      fd_memcpy( entry->ci,     msg->contact_info->value, sizeof(fd_gossip_contact_info_t) );
    }
  } else if( sig==(ulong)FD_GOSSIP_UPDATE_TAG_CONTACT_INFO_REMOVE ) {
    ulong idx = msg->contact_info_remove->idx;
    if( FD_LIKELY( idx<FD_CONTACT_INFO_TABLE_SIZE ) ) ctx->ci_table[ idx ].valid = 0;
  }

  return 0;
}

/* TODO: seccomp */

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo    FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile    FD_PARAM_UNUSED,
                          ulong                  out_cnt FD_PARAM_UNUSED,
                          struct sock_filter *   out     FD_PARAM_UNUSED ) {
  return 0UL;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo    FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile    FD_PARAM_UNUSED,
                      ulong                  out_cnt FD_PARAM_UNUSED,
                      int *                  out     FD_PARAM_UNUSED ) {
  return 0UL;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  (128L*3000L) /* 384us */

#define STEM_CALLBACK_CONTEXT_TYPE        fd_gossix_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(fd_gossix_tile_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_gossix = {
  .name                     = "gossix",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
