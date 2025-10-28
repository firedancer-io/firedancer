#include "../../disco/topo/fd_topo.h"
#include <stddef.h>
#include <sys/socket.h>
#include "generated/fd_rpc_tile_seccomp.h"
#include "../replay/fd_replay_tile.h"
#include "../../waltz/http/fd_http_server.h"
#include "../../ballet/json/cJSON.h"

#define FD_HTTP_SERVER_RPC_MAX_REQUEST_LEN 8192UL

#define IN_KIND_REPLAY (0)

#define FD_RPC_COMMITMENT_PROCESSED (0)
#define FD_RPC_COMMITMENT_CONFIRMED (1)
#define FD_RPC_COMMITMENT_FINALIZED (2)

#define FD_RPC_METHOD_GET_LATEST_BLOCKHASH  (0)
#define FD_RPC_METHOD_GET_TRANSACTION_COUNT (1)

// Keep in sync with https://github.com/solana-labs/solana-web3.js/blob/master/src/errors.ts
// and https://github.com/anza-xyz/agave/blob/master/rpc-client-api/src/custom_error.rs
#define FD_RPC_ERROR_BLOCK_CLEANED_UP                            (-32001)
#define FD_RPC_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE          (-32002)
#define FD_RPC_ERROR_TRANSACTION_SIGNATURE_VERIFICATION_FAILURE  (-32003)
#define FD_RPC_ERROR_BLOCK_NOT_AVAILABLE                         (-32004)
#define FD_RPC_ERROR_NODE_UNHEALTHY                              (-32005)
#define FD_RPC_ERROR_TRANSACTION_PRECOMPILE_VERIFICATION_FAILURE (-32006)
#define FD_RPC_ERROR_SLOT_SKIPPED                                (-32007)
#define FD_RPC_ERROR_NO_SNAPSHOT                                 (-32008)
#define FD_RPC_ERROR_LONG_TERM_STORAGE_SLOT_SKIPPED              (-32009)
#define FD_RPC_ERROR_KEY_EXCLUDED_FROM_SECONDARY_INDEX           (-32010)
#define FD_RPC_ERROR_TRANSACTION_HISTORY_NOT_AVAILABLE           (-32011)
#define FD_RPC_ROR                                               (-32012)
#define FD_RPC_ERROR_TRANSACTION_SIGNATURE_LEN_MISMATCH          (-32013)
#define FD_RPC_ERROR_BLOCK_STATUS_NOT_AVAILABLE_YET              (-32014)
#define FD_RPC_ERROR_UNSUPPORTED_TRANSACTION_VERSION             (-32015)
#define FD_RPC_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED                (-32016)
#define FD_RPC_ERROR_EPOCH_REWARDS_PERIOD_ACTIVE                 (-32017)
#define FD_RPC_ERROR_SLOT_NOT_EPOCH_BOUNDARY                     (-32018)
#define FD_RPC_ERROR_LONG_TERM_STORAGE_UNREACHABLE               (-32019)

static fd_http_server_params_t
derive_http_params( fd_topo_tile_t const * tile ) {
  return (fd_http_server_params_t) {
    .max_connection_cnt    = tile->rpc.max_http_connections,
    .max_ws_connection_cnt = 0UL,
    .max_request_len       = FD_HTTP_SERVER_RPC_MAX_REQUEST_LEN,
    .max_ws_recv_frame_len = 0UL,
    .max_ws_send_frame_cnt = 0UL,
    .outgoing_buffer_sz    = tile->rpc.send_buffer_size_mb * (1UL<<20UL),
    .compress_websocket    = 0,
  };
}

struct fd_rpc_tile_in {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
};

typedef struct fd_rpc_tile_in fd_rpc_tile_in_t;

struct fd_rpc_tile {
  fd_http_server_t * http;

  ulong slot;
  ulong transaction_count;
  uchar block_hash[ 32 ];

  long next_poll_deadline;

  int in_kind[ 64UL ];
  fd_rpc_tile_in_t in[ 64UL ];
};

typedef struct fd_rpc_tile fd_rpc_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( fd_rpc_tile_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong http_fp = fd_http_server_footprint( derive_http_params( tile ) );
  if( FD_UNLIKELY( !http_fp ) ) FD_LOG_ERR(( "Invalid [tiles.rpc] config parameters" ));

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_rpc_tile_t ), sizeof( fd_rpc_tile_t ) );
  l = FD_LAYOUT_APPEND( l, fd_http_server_align(),   http_fp                 );
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(),         fd_alloc_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 256UL * (1UL<<20UL); /* 256MiB of heap space for the cJSON allocator */
}

static void
before_credit( fd_rpc_tile_t *     ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

  if( FD_UNLIKELY( ctx->slot==ULONG_MAX ) ) return;

  long now = fd_tickcount();
  if( FD_UNLIKELY( now>=ctx->next_poll_deadline ) ) {
    *charge_busy = fd_http_server_poll( ctx->http, 0 );
    ctx->next_poll_deadline = fd_tickcount() + (long)(fd_tempo_tick_per_ns( NULL )*128L*1000L);
  }
}

static inline int
returnable_frag( fd_rpc_tile_t *     ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)ctx;
  (void)in_idx;
  (void)seq;
  (void)sig;
  (void)chunk;
  (void)sz;
  (void)ctl;
  (void)tsorig;
  (void)tspub;
  (void)stem;

  if( FD_UNLIKELY( sig!=REPLAY_SIG_SLOT_COMPLETED ) ) return 0;

  fd_replay_slot_completed_t const * slot_completed = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
  ctx->slot = slot_completed->slot;
  ctx->transaction_count = slot_completed->transaction_count;
  fd_memcpy( ctx->block_hash, slot_completed->block_hash.uc, 32 );

  return 0;
}

static fd_http_server_response_t
getLatestBlockhash( fd_rpc_tile_t * ctx,
                    ulong           request_id,
                    cJSON const *   params ) {
  int commitment = FD_RPC_COMMITMENT_FINALIZED;
  ulong minContextSlot = ULONG_MAX;

  if( FD_UNLIKELY( params && cJSON_GetArraySize( params ) ) ) {
    if( FD_UNLIKELY( cJSON_GetArraySize( params )>1 ) ) return (fd_http_server_response_t){ .status = 400 };

    const cJSON * param = cJSON_GetArrayItem( params, 0 );
    if( FD_UNLIKELY( !cJSON_IsObject( param ) ) ) return (fd_http_server_response_t){ .status = 400 };

    const cJSON * _commitment = cJSON_GetObjectItemCaseSensitive( param, "commitment" );
    if( FD_UNLIKELY( _commitment && ( !cJSON_IsString( _commitment ) || _commitment->valuestring==NULL ) ) ) return (fd_http_server_response_t){ .status = 400 };

    if( FD_LIKELY( !strcmp( _commitment->valuestring, "processed" ) ) ) commitment = FD_RPC_COMMITMENT_PROCESSED;
    else if( FD_LIKELY( !strcmp( _commitment->valuestring, "confirmed" ) ) ) commitment = FD_RPC_COMMITMENT_CONFIRMED;
    else if( FD_LIKELY( !strcmp( _commitment->valuestring, "finalized" ) ) ) commitment = FD_RPC_COMMITMENT_FINALIZED;
    else return (fd_http_server_response_t){ .status = 400 };

    const cJSON * _minContextSlot = cJSON_GetObjectItemCaseSensitive( param, "minContextSlot" );
    if( FD_UNLIKELY( _minContextSlot ) ) {
      if( FD_UNLIKELY( !cJSON_IsNumber( _minContextSlot ) || _minContextSlot->valueulong==ULONG_MAX ) ) return (fd_http_server_response_t){ .status = 400 };
      minContextSlot = _minContextSlot->valueulong;
    }
  }

  if( FD_UNLIKELY( commitment!=FD_RPC_COMMITMENT_PROCESSED ) ) return (fd_http_server_response_t){ .status = 400 };

  if( FD_UNLIKELY( minContextSlot!=ULONG_MAX && minContextSlot>ctx->slot ) ) {
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Minimum context slot has not been reached\",\"data\":{\"contextSlot\":%lu}},\"id\":%lu}\n", FD_RPC_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED, ctx->slot, request_id );
    fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
    FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
    return response;
  }

  ulong slot = ctx->slot;
  uchar const * block_hash = ctx->block_hash;
  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"slot\":%lu},\"value\":{\"blockhash\":\"%s\",\"lastValidBlockHeight\":0}},\"id\":%lu}\n", slot, FD_BASE58_ENC_32_ALLOCA( block_hash ), request_id );
  fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
  FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
  return response;
}

static fd_http_server_response_t
getTransactionCount( fd_rpc_tile_t * ctx,
                     ulong           request_id,
                     cJSON const *   params ) {
  int commitment = FD_RPC_COMMITMENT_FINALIZED;
  ulong minContextSlot = ULONG_MAX;

  if( FD_UNLIKELY( params && cJSON_GetArraySize( params ) ) ) {
    if( FD_UNLIKELY( cJSON_GetArraySize( params )>1 ) ) return (fd_http_server_response_t){ .status = 400 };

    const cJSON * param = cJSON_GetArrayItem( params, 0 );
    if( FD_UNLIKELY( !cJSON_IsObject( param ) ) ) return (fd_http_server_response_t){ .status = 400 };

    const cJSON * _commitment = cJSON_GetObjectItemCaseSensitive( param, "commitment" );
    if( FD_UNLIKELY( _commitment && ( !cJSON_IsString( _commitment ) || _commitment->valuestring==NULL ) ) ) return (fd_http_server_response_t){ .status = 400 };

    if( FD_LIKELY( !strcmp( _commitment->valuestring, "processed" ) ) ) commitment = FD_RPC_COMMITMENT_PROCESSED;
    else if( FD_LIKELY( !strcmp( _commitment->valuestring, "confirmed" ) ) ) commitment = FD_RPC_COMMITMENT_CONFIRMED;
    else if( FD_LIKELY( !strcmp( _commitment->valuestring, "finalized" ) ) ) commitment = FD_RPC_COMMITMENT_FINALIZED;
    else return (fd_http_server_response_t){ .status = 400 };

    const cJSON * _minContextSlot = cJSON_GetObjectItemCaseSensitive( param, "minContextSlot" );
    if( FD_UNLIKELY( _minContextSlot ) ) {
      if( FD_UNLIKELY( !cJSON_IsNumber( _minContextSlot ) || _minContextSlot->valueulong==ULONG_MAX ) ) return (fd_http_server_response_t){ .status = 400 };
      minContextSlot = _minContextSlot->valueulong;
    }
  }

  if( FD_UNLIKELY( commitment!=FD_RPC_COMMITMENT_PROCESSED ) ) return (fd_http_server_response_t){ .status = 400 };

  if( FD_UNLIKELY( minContextSlot!=ULONG_MAX && minContextSlot>ctx->slot ) ) {
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Minimum context slot has not been reached\",\"data\":{\"contextSlot\":%lu}},\"id\":%lu}\n", FD_RPC_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED, ctx->slot, request_id );
    fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
    FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
    return response;
  }

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%lu}\n", ctx->transaction_count, request_id );
  fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
  FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
  return response;
}

static fd_http_server_response_t
rpc_http_request( fd_http_server_request_t const * request ) {
  fd_rpc_tile_t * ctx = (fd_rpc_tile_t *)request->ctx;

  if( FD_UNLIKELY( request->method!=FD_HTTP_SERVER_METHOD_POST ) ) {
    return (fd_http_server_response_t){
      .status = 400,
    };
  }

  const char * parse_end;
  cJSON * json = cJSON_ParseWithLengthOpts( (char *)request->post.body, request->post.body_len, &parse_end, 0 );
  if( FD_UNLIKELY( !json ) ) {
    return (fd_http_server_response_t){ .status = 400 };
  }

  const cJSON * jsonrpc = cJSON_GetObjectItemCaseSensitive( json, "jsonrpc" );
  if( FD_UNLIKELY( !cJSON_IsString( jsonrpc ) || strcmp( jsonrpc->valuestring, "2.0" ) ) ) goto bad_request;

  const cJSON * id = cJSON_GetObjectItemCaseSensitive( json, "id" );
  ulong request_id = 0UL;
  if( FD_UNLIKELY( !cJSON_IsNumber( id ) ) ) goto bad_request;
  request_id = id->valueulong;

  const cJSON * params = cJSON_GetObjectItemCaseSensitive( json, "params" );
  if( FD_UNLIKELY( params && !cJSON_IsArray( params ) ) ) goto bad_request;

  int method = INT_MAX;
  const cJSON * _method = cJSON_GetObjectItemCaseSensitive( json, "method" );
  if( FD_LIKELY( !cJSON_IsString( _method ) || _method->valuestring==NULL ) ) goto bad_request;
  if( FD_LIKELY( !strcmp( _method->valuestring, "getLatestBlockhash" ) ) ) method = FD_RPC_METHOD_GET_LATEST_BLOCKHASH;
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getTransactionCount" ) ) ) method = FD_RPC_METHOD_GET_TRANSACTION_COUNT;
  else goto bad_request;

  fd_http_server_response_t response;
  switch( method ) {
    case FD_RPC_METHOD_GET_LATEST_BLOCKHASH: response = getLatestBlockhash( ctx, request_id, params ); break;
    case FD_RPC_METHOD_GET_TRANSACTION_COUNT: response = getTransactionCount( ctx, request_id, params ); break;
    default: goto bad_request;
  }

  cJSON_Delete( json );
  return response;

bad_request:
  cJSON_Delete( json );
  return (fd_http_server_response_t){ .status = 400 };
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  fd_http_server_params_t http_params = derive_http_params( tile );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpc_tile_t * ctx      = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_rpc_tile_t ), sizeof( fd_rpc_tile_t ) );
  fd_http_server_t * _http = FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(),   fd_http_server_footprint( http_params ) );

  fd_http_server_callbacks_t callbacks = {
    .request = rpc_http_request,
  };
  ctx->http = fd_http_server_join( fd_http_server_new( _http, http_params, callbacks, ctx ) );
  fd_http_server_listen( ctx->http, tile->rpc.listen_addr, tile->rpc.listen_port );

  FD_LOG_NOTICE(( "rpc server listening at http://" FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS( tile->rpc.listen_addr ), tile->rpc.listen_port ));
}

static FD_TL fd_alloc_t * cjson_alloc_ctx;

static void *
cjson_alloc( ulong sz ) {
  return fd_alloc_malloc( cjson_alloc_ctx, alignof(max_align_t), sz );
}

static void
cjson_free( void * ptr ) {
  fd_alloc_free( cjson_alloc_ctx, ptr );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpc_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_rpc_tile_t ), sizeof( fd_rpc_tile_t )       );
                        FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(),   fd_http_server_footprint( derive_http_params( tile ) ) );
  void * _alloc       = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(),         fd_alloc_footprint() );

  cjson_alloc_ctx = fd_alloc_join( fd_alloc_new( _alloc, 1UL ), 1UL );
  FD_TEST( cjson_alloc_ctx );
  cJSON_Hooks hooks = {
    .malloc_fn = cjson_alloc,
    .free_fn   = cjson_free,
  };
  cJSON_InitHooks( &hooks );

  ctx->slot = ULONG_MAX;
  ctx->next_poll_deadline = fd_tickcount();

  FD_TEST( tile->in_cnt<=sizeof( ctx->in )/sizeof( ctx->in[ 0 ] ) );
  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    ctx->in[ i ].mtu    = link->mtu;

    if( FD_LIKELY( !strcmp( link->name, "replay_out" ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else FD_LOG_ERR(( "unexpected link name %s", link->name ));
  }

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpc_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_rpc_tile_t ), sizeof( fd_rpc_tile_t ) );

  populate_sock_filter_policy_fd_rpc_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)fd_http_server_fd( ctx->http ) );
  return sock_filter_policy_fd_rpc_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpc_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_rpc_tile_t ), sizeof( fd_rpc_tile_t ) );

  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = fd_http_server_fd( ctx->http ); /* rpc listen socket */
  return out_cnt;
}

static ulong
rlimit_file_cnt( fd_topo_t const *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t const * tile ) {
  /* pipefd, socket, stderr, logfile, and one spare for new accept() connections */
  ulong base = 5UL;
  return base+tile->rpc.max_http_connections;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  (50UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_rpc_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_rpc_tile_t)

#define STEM_CALLBACK_BEFORE_CREDIT   before_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_rpc = {
  .name                     = "rpc",
  .rlimit_file_cnt_fn       = rlimit_file_cnt,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .loose_footprint          = loose_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
