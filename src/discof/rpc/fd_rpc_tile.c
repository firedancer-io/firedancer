#include "../replay/fd_replay_tile.h"
#include "../genesis/fd_genesi_tile.h"
#include "../../disco/topo/fd_topo.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../discof/fd_accdb_topo.h"
#include "../../flamenco/accdb/fd_accdb_sync.h"
#include "../../flamenco/features/fd_features.h"
#include "../../flamenco/runtime/fd_runtime_const.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_rent.h"
#include "../../waltz/http/fd_http_server.h"
#include "../../waltz/http/fd_http_server_private.h"
#include "../../ballet/base64/fd_base64.h"
#include "../../ballet/json/cJSON.h"
#include "../../ballet/json/cJSON_alloc.h"
#include "../../ballet/lthash/fd_lthash.h"

#include <stddef.h>
#include <sys/socket.h>

#if FD_HAS_ZSTD
#include <zstd.h>
#endif

#include "generated/fd_rpc_tile_seccomp.h"

#define FD_HTTP_SERVER_RPC_MAX_REQUEST_LEN 8192UL

#define IN_KIND_REPLAY (0)
#define IN_KIND_GENESI (0)

#define FD_RPC_COMMITMENT_PROCESSED (0)
#define FD_RPC_COMMITMENT_CONFIRMED (1)
#define FD_RPC_COMMITMENT_FINALIZED (2)

#define FD_RPC_ENCODING_BASE58      (0)
#define FD_RPC_ENCODING_BASE64      (1)
#define FD_RPC_ENCODING_BASE64_ZSTD (2)
#define FD_RPC_ENCODING_BINARY      (3)
#define FD_RPC_ENCODING_JSON_PARSED (4)

#define FD_RPC_METHOD_GET_ACCOUNT_INFO                       ( 0)
#define FD_RPC_METHOD_GET_BALANCE                            ( 1)
#define FD_RPC_METHOD_GET_BLOCK                              ( 2)
#define FD_RPC_METHOD_GET_BLOCK_COMMITMENT                   ( 3)
#define FD_RPC_METHOD_GET_BLOCK_HEIGHT                       ( 4)
#define FD_RPC_METHOD_GET_BLOCK_PRODUCTION                   ( 5)
#define FD_RPC_METHOD_GET_BLOCKS                             ( 6)
#define FD_RPC_METHOD_GET_BLOCKS_WITH_LIMIT                  ( 7)
#define FD_RPC_METHOD_GET_BLOCK_TIME                         ( 8)
#define FD_RPC_METHOD_GET_CLUSTER_NODES                      ( 9)
#define FD_RPC_METHOD_GET_EPOCH_INFO                         (10)
#define FD_RPC_METHOD_GET_EPOCH_SCHEDULE                     (11)
#define FD_RPC_METHOD_GET_FEE_FOR_MESSAGE                    (12)
#define FD_RPC_METHOD_GET_FIRST_AVAILABLE_BLOCK              (13)
#define FD_RPC_METHOD_GET_GENESIS_HASH                       (14)
#define FD_RPC_METHOD_GET_HEALTH                             (15)
#define FD_RPC_METHOD_GET_HIGHEST_SNAPSHOT_SLOT              (16)
#define FD_RPC_METHOD_GET_IDENTITY                           (17)
#define FD_RPC_METHOD_GET_INFLATION_GOVERNOR                 (18)
#define FD_RPC_METHOD_GET_INFLATION_RATE                     (19)
#define FD_RPC_METHOD_GET_INFLATION_REWARD                   (20)
#define FD_RPC_METHOD_GET_LARGEST_ACCOUNTS                   (21)
#define FD_RPC_METHOD_GET_LATEST_BLOCKHASH                   (22)
#define FD_RPC_METHOD_GET_LEADER_SCHEDULE                    (23)
#define FD_RPC_METHOD_GET_MAX_RETRANSMIT_SLOT                (24)
#define FD_RPC_METHOD_GET_MAX_SHRED_INSERT_SLOT              (25)
#define FD_RPC_METHOD_GET_MINIMUM_BALANCE_FOR_RENT_EXEMPTION (26)
#define FD_RPC_METHOD_GET_MULTIPLE_ACCOUNTS                  (27)
#define FD_RPC_METHOD_GET_PROGRAM_ACCOUNTS                   (28)
#define FD_RPC_METHOD_GET_RECENT_PERFORMANCE_SAMPLES         (29)
#define FD_RPC_METHOD_GET_RECENT_PRIORITIZATION_FEES         (30)
#define FD_RPC_METHOD_GET_SIGNATURES_FOR_ADDRESS             (31)
#define FD_RPC_METHOD_GET_SIGNATURE_STATUSES                 (32)
#define FD_RPC_METHOD_GET_SLOT                               (33)
#define FD_RPC_METHOD_GET_SLOT_LEADER                        (34)
#define FD_RPC_METHOD_GET_SLOT_LEADERS                       (35)
#define FD_RPC_METHOD_GET_STAKE_MINIMUM_DELEGATION           (36)
#define FD_RPC_METHOD_GET_SUPPLY                             (37)
#define FD_RPC_METHOD_GET_TOKEN_ACCOUNT_BALANCE              (38)
#define FD_RPC_METHOD_GET_TOKEN_ACCOUNTS_BY_DELEGATE         (39)
#define FD_RPC_METHOD_GET_TOKEN_ACCOUNTS_BY_OWNER            (40)
#define FD_RPC_METHOD_GET_TOKEN_LARGEST_ACCOUNTS             (41)
#define FD_RPC_METHOD_GET_TOKEN_SUPPLY                       (42)
#define FD_RPC_METHOD_GET_TRANSACTION                        (43)
#define FD_RPC_METHOD_GET_TRANSACTION_COUNT                  (44)
#define FD_RPC_METHOD_GET_VERSION                            (45)
#define FD_RPC_METHOD_GET_VOTE_ACCOUNTS                      (46)
#define FD_RPC_METHOD_IS_BLOCKHASH_VALID                     (47)
#define FD_RPC_METHOD_MINIMUM_LEDGER_SLOT                    (48)
#define FD_RPC_METHOD_REQUEST_AIRDROP                        (49)
#define FD_RPC_METHOD_SEND_TRANSACTION                       (50)
#define FD_RPC_METHOD_SIMULATE_TRANSACTION                   (51)

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

struct fd_rpc_in {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
};

typedef struct fd_rpc_in fd_rpc_in_t;

struct fd_rpc_out {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
};

typedef struct fd_rpc_out fd_rpc_out_t;

struct bank_info {
  ulong slot;
  ulong transaction_count;
  uchar block_hash[ 32 ];
  ulong block_height;

  struct {
    double initial;
    double terminal;
    double taper;
    double foundation;
    double foundation_term;
  } inflation;

  struct {
    ulong lamports_per_uint8_year;
    double exemption_threshold;
    uchar burn_percent;
  } rent;
};

typedef struct bank_info bank_info_t;

struct fd_rpc_tile {
  fd_http_server_t * http;

  bank_info_t * banks;

  ulong cluster_confirmed_slot;

  ulong processed_idx;
  ulong confirmed_idx;
  ulong finalized_idx;

  int has_genesis_hash;
  uchar genesis_hash[ 32 ];

  long next_poll_deadline;

  char version_string[ 16UL ];

  fd_keyswitch_t * keyswitch;
  uchar identity_pubkey[ 32UL ];

  int in_kind[ 64UL ];
  fd_rpc_in_t in[ 64UL ];

  fd_rpc_out_t replay_out[1];

  fd_accdb_user_t accdb[1];

# if FD_HAS_ZSTD
  uchar compress_buf[ ZSTD_COMPRESSBOUND( FD_RUNTIME_ACC_SZ_MAX ) ];
# endif
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
  l = FD_LAYOUT_APPEND( l, alignof( fd_rpc_tile_t ), sizeof( fd_rpc_tile_t )                      );
  l = FD_LAYOUT_APPEND( l, fd_http_server_align(),   http_fp                                      );
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(),         fd_alloc_footprint()                         );
  l = FD_LAYOUT_APPEND( l, alignof(bank_info_t),     tile->rpc.max_live_slots*sizeof(bank_info_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 256UL * (1UL<<20UL); /* 256MiB of heap space for the cJSON allocator */
}

static inline void
during_housekeeping( fd_rpc_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING ) ) {
    fd_memcpy( ctx->identity_pubkey, ctx->keyswitch->bytes, 32UL );
    fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_COMPLETED );
  }
}

static void
before_credit( fd_rpc_tile_t *     ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)stem;

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

  if( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY ) {
    switch( sig ) {
      case REPLAY_SIG_SLOT_COMPLETED: {
        fd_replay_slot_completed_t const * slot_completed = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );

        bank_info_t * bank = &ctx->banks[ slot_completed->bank_idx ];
        bank->slot = slot_completed->slot;
        bank->transaction_count = slot_completed->transaction_count;
        bank->block_height = slot_completed->block_height;
        fd_memcpy( bank->block_hash, slot_completed->block_hash.uc, 32 );

        bank->inflation.initial         = slot_completed->inflation.initial;
        bank->inflation.terminal        = slot_completed->inflation.terminal;
        bank->inflation.taper           = slot_completed->inflation.taper;
        bank->inflation.foundation      = slot_completed->inflation.foundation;
        bank->inflation.foundation_term = slot_completed->inflation.foundation_term;

        bank->rent.lamports_per_uint8_year = slot_completed->rent.lamports_per_uint8_year;
        bank->rent.exemption_threshold     = slot_completed->rent.exemption_threshold;
        bank->rent.burn_percent            = slot_completed->rent.burn_percent;

        break;
      }
      case REPLAY_SIG_RESET: {
        fd_poh_reset_t const * reset = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );

        ulong prior_processed_idx = ctx->processed_idx;
        ctx->processed_idx = reset->bank_idx;

        if( FD_LIKELY( prior_processed_idx!=ULONG_MAX ) ) fd_stem_publish( stem, ctx->replay_out->idx, prior_processed_idx, 0UL, 0UL, 0UL, 0UL, 0UL );
        break;
      }
      default: break;
    }
  } else if( ctx->in_kind[ in_idx ]==IN_KIND_GENESI ) {
    ctx->has_genesis_hash = 1;
    uchar const * src = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    if( FD_LIKELY( sig==GENESI_SIG_BOOTSTRAP_COMPLETED ) ) {
      fd_memcpy( ctx->genesis_hash, src+sizeof(fd_lthash_value_t), 32UL );
    } else {
      fd_memcpy( ctx->genesis_hash, src, 32UL );
    }
  }

  return 0;
}

static void
jsonp_strip_trailing_comma( fd_http_server_t * http ) {
  if( FD_LIKELY( !http->stage_err &&
                  http->stage_len>=1UL &&
                  http->oring[ (http->stage_off%http->oring_sz)+http->stage_len-1UL ]==(uchar)',' ) ) {
    http->stage_len--;
  }
}

static void
jsonp_open_object( fd_http_server_t * http,
                   char const *       key ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":{", key );
  else                   fd_http_server_printf( http, "{" );
}

static void
jsonp_close_object( fd_http_server_t * http ) {
  jsonp_strip_trailing_comma( http );
  fd_http_server_printf( http, "}," );
}


static void FD_FN_UNUSED
jsonp_open_array( fd_http_server_t * http,
                  char const *       key ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":[", key );
  else                   fd_http_server_printf( http, "[" );
}

static void FD_FN_UNUSED
jsonp_close_array( fd_http_server_t * http ) {
  jsonp_strip_trailing_comma( http );
  fd_http_server_printf( http, "]," );
}

static void
jsonp_ulong( fd_http_server_t * http,
             char const *       key,
             ulong              value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":%lu,", key, value );
  else                   fd_http_server_printf( http, "%lu,", value );
}

static void FD_FN_UNUSED
jsonp_long( fd_http_server_t * http,
            char const *       key,
            long               value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":%ld,", key, value );
  else                   fd_http_server_printf( http, "%ld,", value );
}

static void FD_FN_UNUSED
jsonp_double( fd_http_server_t * http,
              char const *       key,
              double             value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":%.2f,", key, value );
  else                   fd_http_server_printf( http, "%.2f,", value );
}

static void
jsonp_string( fd_http_server_t * http,
              char const *       key,
              char const *       value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":", key );
  if( FD_LIKELY( value ) ) {
    ulong value_len = strlen( value );
    FD_TEST( fd_utf8_verify( value, value_len ) );
    for( ulong i=0UL; i<value_len; i++ ) FD_TEST( value[ i ]>=0x20 && value[ i ]!='"' && value[ i ]!='\\' );

    fd_http_server_printf( http, "\"%s\",", value );
  } else {
    fd_http_server_printf( http, "null," );
  }
}

static void FD_FN_UNUSED
jsonp_bool( fd_http_server_t * http,
            char const *       key,
            int                value ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\":%s,", key, value ? "true" : "false" );
  else                   fd_http_server_printf( http, "%s,", value ? "true" : "false" );
}

static void FD_FN_UNUSED
jsonp_null( fd_http_server_t * http,
            char const *       key ) {
  if( FD_LIKELY( key ) ) fd_http_server_printf( http, "\"%s\": null,", key );
  else                   fd_http_server_printf( http, "null," );
}

static void
jsonp_open_envelope( fd_http_server_t * http ) {
  jsonp_open_object( http, NULL );
  jsonp_string( http, "jsonrpc", "2.0" );
  jsonp_open_object( http, "result" );
}

static void
jsonp_close_envelope( fd_http_server_t * http,
                      ulong              id ) {
  jsonp_close_object( http );
  jsonp_ulong( http, "id", id );
  jsonp_close_object( http );
  jsonp_strip_trailing_comma( http );
}

#define UNIMPLEMENTED(X)                               \
static fd_http_server_response_t                       \
X( fd_rpc_tile_t * ctx,                                \
   ulong           request_id,                         \
   cJSON const *   params ) {                          \
  (void)ctx; (void)request_id; (void)params;           \
  return (fd_http_server_response_t){ .status = 501 }; \
}

UNIMPLEMENTED(getBlock) // TODO: Used by solana-exporter
UNIMPLEMENTED(getBlockCommitment)

static fd_http_server_response_t
getAccountInfo( fd_rpc_tile_t * ctx,
                ulong           request_id,
                cJSON const *   params ) {
  int param_cnt = cJSON_GetArraySize( params );
  if( param_cnt!=2 ) {
    /* In theory, the second argument (options) is not required.  But if
       it is omitted, it implies Base58-encoded account data, which we
       deliberately don't support. */
    return (fd_http_server_response_t){ .status = 400 };
  }

  cJSON const * address_node = cJSON_GetArrayItem( params, 0 );
  cJSON const * config       = cJSON_GetArrayItem( params, 1 );
  if( FD_UNLIKELY( !cJSON_IsString( address_node ) ) ) {
    return (fd_http_server_response_t){ .status = 400 };
  }
  if( FD_UNLIKELY( !cJSON_IsObject( config ) ) ) {
    return (fd_http_server_response_t){ .status = 400 };
  }

  char const * encoding = cJSON_GetStringValue( cJSON_GetObjectItemCaseSensitive( config, "encoding" ) );
  if( !encoding ) encoding = "binary"; /* "binary" is base58 */
  _Bool use_zstd = 0; (void)use_zstd;
  if( 0==strcmp( encoding, "base64+zstd" ) && FD_HAS_ZSTD ) {
    use_zstd = 1;
  } else if( 0==strcmp( encoding, "base64" ) ||
             0==strcmp( encoding, "jsonParsed" ) ) {
    encoding = "base64";
  } else {
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid param: this server only supports 'base64' account data encoding\"},\"id\":%lu}\n", request_id );
    fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200 };
    FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
    return response;
  }

  ulong bank_idx = ULONG_MAX;
  char const * commitment = cJSON_GetStringValue( cJSON_GetObjectItemCaseSensitive( config, "commitment" ) );
  if( !commitment ) commitment = "confirmed";
  if( 0==strcmp( commitment, "confirmed" ) ) {
    bank_idx = ctx->confirmed_idx;
  } else if( 0==strcmp( commitment, "processed" ) ) {
    bank_idx = ctx->processed_idx;
  } else if( 0==strcmp( commitment, "finalized" ) ) {
    bank_idx = ctx->finalized_idx;
  } else {
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid param: unsupported commitment level\"},\"id\":%lu}\n", request_id );
    fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200 };
    FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
    return response;
  }
  if( FD_UNLIKELY( bank_idx==ULONG_MAX ) ) {
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid param: cannot resolve slot for '%s' commitment level\"},\"id\":%lu}\n", commitment, request_id );
    fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200 };
    FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
    return response;
  }

  ulong minContextSlot = 0UL;
  cJSON const * _minContextSlot = cJSON_GetObjectItemCaseSensitive( config, "minContextSlot" );
  if( FD_UNLIKELY( _minContextSlot && !cJSON_IsNull( _minContextSlot ) ) ) {
    if( FD_UNLIKELY( !cJSON_IsNumber( _minContextSlot ) || _minContextSlot->valueulong==ULONG_MAX ) ) return (fd_http_server_response_t){ .status = 400 };
    minContextSlot = _minContextSlot->valueulong;
  }

  bank_info_t const * info = &ctx->banks[ bank_idx ];
  if( info->slot < minContextSlot ) {
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Minimum context slot has not been reached\",\"data\":{\"contextSlot\":%lu}},\"id\":%lu}\n", FD_RPC_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED, info->slot, request_id );
    fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
    FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
    return response;
  }

  ulong data_off = 0U;
  ulong data_max = UINT_MAX;
  const cJSON * dataSlice = cJSON_GetObjectItemCaseSensitive( config, "dataSlice" );
  if( dataSlice && !cJSON_IsNull( dataSlice ) ) {
    cJSON const * _length = cJSON_GetObjectItemCaseSensitive( dataSlice, "length" );
    cJSON const * _offset = cJSON_GetObjectItemCaseSensitive( dataSlice, "offset" );
    if( FD_UNLIKELY( !_length || !cJSON_IsNumber( _length ) ||
                     !_offset || !cJSON_IsNumber( _offset ) ) ) {
      return (fd_http_server_response_t){ .status = 400 };
    }
    data_off = _offset->valueulong;
    data_max = _length->valueulong;
  }

  uchar address[ 32 ];
  if( FD_UNLIKELY( !fd_base58_decode_32( cJSON_GetStringValue( address_node ), address ) ) ) {
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid param: address is not a valid Base58 encoding\"},\"id\":%lu}\n", request_id );
    fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200 };
    FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
    return response;
  }

  fd_funk_txn_xid_t xid = { .ul={ info->slot, bank_idx } };
  fd_accdb_ro_t ro[1];
  if( FD_UNLIKELY( !fd_accdb_open_ro( ctx->accdb, ro, &xid, address ) ) ) {
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"slot\":%lu},\"value\":null},\"id\":%lu}\n", info->slot, request_id );
    fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200 };
    FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
    return response;
  }

  ulong data_sz = fd_accdb_ref_data_sz( ro );
  if( data_off>data_sz ) data_off = data_sz;
  ulong snip_sz = data_sz - data_off;
  if( snip_sz>data_max ) snip_sz = data_max;

  uchar const * compressed    = (uchar const *)fd_accdb_ref_data_const( ro )+data_off;
  ulong         compressed_sz = snip_sz;
# if FD_HAS_ZSTD
  if( use_zstd ) {
    size_t zstd_res = ZSTD_compress( ctx->compress_buf, sizeof(ctx->compress_buf), compressed, snip_sz, 3 );
    if( ZSTD_isError( zstd_res ) ) {
      fd_accdb_close_ro( ctx->accdb, ro );
      return (fd_http_server_response_t){ .status = 500 };
    }
    compressed    = ctx->compress_buf;
    compressed_sz = (ulong)zstd_res;
  }
# endif

  FD_BASE58_ENCODE_32_BYTES( fd_accdb_ref_owner( ro ), owner_b58 );
  fd_http_server_printf( ctx->http,
      "{\"jsonrpc\":\"2.0\",\"id\":%lu,\"result\":{\"context\":{\"slot\":%lu},\"value\":{"
      "\"executable\":%s,"
      "\"lamports\":%lu,"
      "\"owner\":\"%s\","
      "\"rentEpoch\":18446744073709551615,"
      "\"space\":%lu,"
      "\"dataSlice\":{\"offset\":%lu,\"length\":%lu},"
      "\"data\":[\"",
      request_id,
      info->slot,
      fd_accdb_ref_exec_bit( ro ) ? "true" : "false",
      fd_accdb_ref_lamports( ro ),
      owner_b58,
      data_sz,
      data_off, snip_sz );

  ulong   encoded_sz = FD_BASE64_ENC_SZ( snip_sz );
  uchar * encoded    = fd_http_server_append_start( ctx->http, encoded_sz );
  if( FD_UNLIKELY( !encoded ) ) {
    fd_accdb_close_ro( ctx->accdb, ro );
    return (fd_http_server_response_t){ .status = 500 };
  }
  encoded_sz = fd_base64_encode( (char *)encoded, compressed, compressed_sz );
  fd_http_server_append_end( ctx->http, encoded_sz );

  fd_http_server_printf( ctx->http, "\",\"%s\"]}}}\n", encoding );
  fd_accdb_close_ro( ctx->accdb, ro );

  fd_http_server_response_t response = { .content_type = "application/json", .status = 200 };
  if( fd_http_server_stage_body( ctx->http, &response ) ) response.status = 500;
  return response;
}

static fd_http_server_response_t
getBalance( fd_rpc_tile_t * ctx,
            ulong           request_id,
            cJSON const *   params ) {
  int param_cnt = cJSON_GetArraySize( params );
  if( param_cnt<1 || param_cnt>2 ) {
    return (fd_http_server_response_t){ .status = 400 };
  }

  cJSON const * address_node = cJSON_GetArrayItem( params, 0 );
  cJSON const * config       = cJSON_GetArrayItem( params, 1 );
  if( FD_UNLIKELY( !cJSON_IsString( address_node ) ) ) {
    return (fd_http_server_response_t){ .status = 400 };
  }
  if( FD_UNLIKELY( config && !cJSON_IsNull( config ) && !cJSON_IsString( config ) ) ) {
    return (fd_http_server_response_t){ .status = 400 };
  }

  ulong bank_idx = ULONG_MAX;
  char const * commitment = cJSON_GetStringValue( cJSON_GetObjectItemCaseSensitive( config, "commitment" ) );
  if( !commitment ) commitment = "confirmed";
  if( 0==strcmp( commitment, "confirmed" ) ) {
    bank_idx = ctx->confirmed_idx;
  } else if( 0==strcmp( commitment, "processed" ) ) {
    bank_idx = ctx->processed_idx;
  } else if( 0==strcmp( commitment, "finalized" ) ) {
    bank_idx = ctx->finalized_idx;
  } else {
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid param: unsupported commitment level\"},\"id\":%lu}\n", request_id );
    fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200 };
    FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
    return response;
  }
  if( FD_UNLIKELY( bank_idx==ULONG_MAX ) ) {
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid param: cannot resolve slot for '%s' commitment level\"},\"id\":%lu}\n", commitment, request_id );
    fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200 };
    FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
    return response;
  }

  ulong minContextSlot = 0UL;
  cJSON const * _minContextSlot = cJSON_GetObjectItemCaseSensitive( config, "minContextSlot" );
  if( FD_UNLIKELY( _minContextSlot && !cJSON_IsNull( _minContextSlot ) ) ) {
    if( FD_UNLIKELY( !cJSON_IsNumber( _minContextSlot ) || _minContextSlot->valueulong==ULONG_MAX ) ) return (fd_http_server_response_t){ .status = 400 };
    minContextSlot = _minContextSlot->valueulong;
  }

  bank_info_t const * info = &ctx->banks[ bank_idx ];
  if( info->slot < minContextSlot ) {
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Minimum context slot has not been reached\",\"data\":{\"contextSlot\":%lu}},\"id\":%lu}\n", FD_RPC_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED, info->slot, request_id );
    fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
    FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
    return response;
  }

  uchar address[ 32 ];
  if( FD_UNLIKELY( !fd_base58_decode_32( cJSON_GetStringValue( address_node ), address ) ) ) {
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid param: address is not a valid Base58 encoding\"},\"id\":%lu}\n", request_id );
    fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200 };
    FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
    return response;
  }

  ulong balance = 0UL;
  fd_funk_txn_xid_t xid = { .ul={ info->slot, bank_idx } };
  fd_accdb_ro_t ro[1];
  if( FD_UNLIKELY( fd_accdb_open_ro( ctx->accdb, ro, &xid, address ) ) ) {
    balance = fd_accdb_ref_lamports( ro );
    fd_accdb_close_ro( ctx->accdb, ro );
  }

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":{\"context\":{\"slot\":%lu},\"value\":%lu},\"id\":%lu}\n", info->slot, balance, request_id );
  fd_http_server_response_t response = { .content_type = "application/json", .status = 200 };
  FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
  return response;
}

static fd_http_server_response_t
getBlockHeight( fd_rpc_tile_t * ctx,
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
    if( FD_UNLIKELY( _minContextSlot && !cJSON_IsNull( _minContextSlot ) ) ) {
      if( FD_UNLIKELY( !cJSON_IsNumber( _minContextSlot ) || _minContextSlot->valueulong==ULONG_MAX ) ) return (fd_http_server_response_t){ .status = 400 };
      minContextSlot = _minContextSlot->valueulong;
    }
  }

  if( FD_UNLIKELY( commitment!=FD_RPC_COMMITMENT_PROCESSED ) ) return (fd_http_server_response_t){ .status = 400 };
  bank_info_t const * bank = &ctx->banks[ ctx->processed_idx ];

  if( FD_UNLIKELY( minContextSlot!=ULONG_MAX && minContextSlot>bank->slot ) ) {
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Minimum context slot has not been reached\",\"data\":{\"contextSlot\":%lu}},\"id\":%lu}\n", FD_RPC_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED, bank->slot, request_id );
    fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
    FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
    return response;
  }

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%lu}\n", bank->block_height, request_id );
  fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
  FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
  return response;
}

UNIMPLEMENTED(getBlockProduction) // TODO: Used by solana-exporter
UNIMPLEMENTED(getBlocks)
UNIMPLEMENTED(getBlocksWithLimit)
UNIMPLEMENTED(getBlockTime)
UNIMPLEMENTED(getClusterNodes)
UNIMPLEMENTED(getEpochInfo) // TODO: Used by solana-exporter
UNIMPLEMENTED(getEpochSchedule)
UNIMPLEMENTED(getFeeForMessage)
UNIMPLEMENTED(getFirstAvailableBlock) // TODO: Used by solana-exporter

/* Get the genesis hash of the cluster.  Firedancer deviates slightly
   from Agave here, as the genesis hash is not always known when RPC
   is first booted, it may need to be determined asynchronously in the
   background, fetched from a peer node.  If the genesis hash is not yet
   known, we return an error indicating no snapshot is available. */

static fd_http_server_response_t
getGenesisHash( fd_rpc_tile_t * ctx,
                ulong           request_id,
                cJSON const *   params ) {
  (void)params;

  if( FD_UNLIKELY( !ctx->has_genesis_hash ) ) {
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"No genesis hash\"},\"id\":%lu}\n", FD_RPC_ERROR_NO_SNAPSHOT, request_id );
    fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
    FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
    return response;
  }

  FD_BASE58_ENCODE_32_BYTES( ctx->genesis_hash, genesis_hash_b58 );
  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":\"%s\",\"id\":%lu}\n", genesis_hash_b58, request_id );
  fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
  FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
  return response;
}

/* Determines if the node is healthy.  Agave defines this as follows,

    - On boot, nodes must go through the entire snapshot slot database
      and hash everything, and once it's done verify the hash matches.
      While this is ongoing, the node is unhealthy with a "slotsBehind"
      value of null.

    - On boot, if the cluster is restarting and we are currently waiting
      for a supermajority of stake to join gossip to proceed with
      booting, the node is forcibly marked as healthy, to, per Agave,

       > prevent load balancers from removing the node from their list
       > of candidates during a manual restart

    - In addition, once booted, there is a period where we do not yet
      know the cluster confirmed slot, because we have not yet observed
      any (or enough) votes arrive from peers in the cluster.  During
      this period the node is unhealthy with a "slotsBehind" value of
      null.

    - Finally, once the cluster confirmed slot is known, which is the
      highest optimistically confirmed slot observed from both gossip,
      and votes procesed in blocks, it is compared to our own
      optimistically confirmed slot, which is just the highest slot down
      the cluster confirmed fork that we have finished replaying
      locally.  The difference between these two slots is compared, and
      if it is less than or equal to 128, the node is healthy, otherwise
      it is unhealthy with a "slotsBehind" value equal to the
      difference.

   Firedancer currently only implements the final two checks, and does
   not forcibly mark the node as healthy while waiting for a
   supermajority, nor does it mark a node as unhealthy while hashing the
   snapshot database on boot.  Firedancer hashes snapshots so quickly
   that the node will die on boot if the hash is not valid. */

static fd_http_server_response_t
getHealth( fd_rpc_tile_t * ctx,
           ulong           request_id,
           cJSON const *   params ) {
  (void)params;

  // TODO: We should probably implement the same waiting_for_supermajority
  // logic to conform with Agave here.

  int unknown = ctx->cluster_confirmed_slot==ULONG_MAX || ctx->confirmed_idx==ULONG_MAX;
  if( FD_UNLIKELY( unknown ) ) fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Node is unhealthy\",\"data\":{\"slotsBehind\":null}},\"id\":%lu}\n", FD_RPC_ERROR_NODE_UNHEALTHY, request_id );
  else {
    ulong slots_behind = fd_ulong_sat_sub( ctx->cluster_confirmed_slot, ctx->banks[ ctx->confirmed_idx ].slot );
    if( FD_LIKELY( slots_behind<=128UL ) ) fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":\"ok\",\"id\":%lu}\n", request_id );
    else                                   fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Node is unhealthy\",\"data\":{\"slotsBehind\":%lu}},\"id\":%lu}\n", FD_RPC_ERROR_NODE_UNHEALTHY, slots_behind, request_id );
  }

  fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
  FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
  return response;
}

static fd_http_server_response_t
getHighestSnapshotSlot( fd_rpc_tile_t * ctx,
                        ulong           request_id,
                        cJSON const *   params ) {
  (void)params;
  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"No snapshot\"},\"id\":%lu}\n", FD_RPC_ERROR_NO_SNAPSHOT, request_id );
  fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
  FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
  return response;
}

static fd_http_server_response_t
getIdentity( fd_rpc_tile_t * ctx,
             ulong           request_id,
             cJSON const *   params ) {
  (void)params;

  FD_BASE58_ENCODE_32_BYTES( ctx->identity_pubkey, identity_pubkey_b58 );
  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":\"%s\",\"id\":%lu}\n", identity_pubkey_b58, request_id );
  fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
  FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
  return response;
}

static fd_http_server_response_t
getInflationGovernor( fd_rpc_tile_t * ctx,
                     ulong           request_id,
                     cJSON const *   params ) {
  (void)params;

  int commitment = FD_RPC_COMMITMENT_FINALIZED;

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
  }

  if( FD_UNLIKELY( commitment!=FD_RPC_COMMITMENT_PROCESSED ) ) return (fd_http_server_response_t){ .status = 400 };
  bank_info_t const * bank = &ctx->banks[ ctx->processed_idx ];

  jsonp_open_envelope( ctx->http );
    jsonp_double( ctx->http, "foundation",      bank->inflation.foundation );
    jsonp_double( ctx->http, "foundationTerm",  bank->inflation.foundation_term );
    jsonp_double( ctx->http, "initial",         bank->inflation.initial );
    jsonp_double( ctx->http, "taper",           bank->inflation.taper );
    jsonp_double( ctx->http, "terminal",        bank->inflation.terminal );
  jsonp_close_envelope( ctx->http, request_id );

  fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
  FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
  return response;
}

UNIMPLEMENTED(getInflationRate)
UNIMPLEMENTED(getInflationReward) // TODO: Used by solana-exporter
UNIMPLEMENTED(getLargestAccounts)

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
  bank_info_t const * bank = &ctx->banks[ ctx->processed_idx ];

  if( FD_UNLIKELY( minContextSlot!=ULONG_MAX && minContextSlot>bank->slot ) ) {
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Minimum context slot has not been reached\",\"data\":{\"contextSlot\":%lu}},\"id\":%lu}\n", FD_RPC_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED, bank->slot, request_id );
    fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
    FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
    return response;
  }

  FD_BASE58_ENCODE_32_BYTES( bank->block_hash, block_hash_b58 );
  jsonp_open_envelope( ctx->http );
    jsonp_open_object( ctx->http, "context" );
      jsonp_ulong( ctx->http, "slot", bank->slot );
    jsonp_close_object( ctx->http );

    jsonp_open_object( ctx->http, "value" );
      jsonp_string( ctx->http, "blockhash", block_hash_b58 );
      jsonp_ulong( ctx->http, "lastValidBlockHeight", 0UL /* TODO: Implement */ );
    jsonp_close_object( ctx->http );
  jsonp_close_envelope( ctx->http, request_id );

  fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
  FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
  return response;
}

UNIMPLEMENTED(getLeaderSchedule) // TODO: Used by solana-exporter
UNIMPLEMENTED(getMaxRetransmitSlot)
UNIMPLEMENTED(getMaxShredInsertSlot)

static fd_http_server_response_t
getMinimumBalanceForRentExemption( fd_rpc_tile_t * ctx,
                                   ulong           request_id,
                                   cJSON const *   params ) {
  int commitment = FD_RPC_COMMITMENT_FINALIZED;

  if( FD_UNLIKELY( cJSON_GetArraySize( params )>2 || !cJSON_GetArraySize( params ) ) ) return (fd_http_server_response_t){ .status = 400 };

  const cJSON * data_len = cJSON_GetArrayItem( params, 0 );
  if( FD_UNLIKELY( !cJSON_IsNumber( data_len ) ) ) return (fd_http_server_response_t){ .status = 400 };

  if( FD_UNLIKELY( cJSON_GetArraySize( params )==2 ) ) {
    const cJSON * config = cJSON_GetArrayItem( params, 1 );
    if( FD_UNLIKELY( !cJSON_IsObject( config ) ) ) return (fd_http_server_response_t){ .status = 400 };

    const cJSON * _commitment = cJSON_GetObjectItemCaseSensitive( config, "commitment" );
    if( FD_UNLIKELY( _commitment && ( !cJSON_IsString( _commitment ) || _commitment->valuestring==NULL ) ) ) return (fd_http_server_response_t){ .status = 400 };

    if( FD_UNLIKELY( _commitment ) ) {
      if( FD_LIKELY( !strcmp( _commitment->valuestring, "processed" ) ) ) commitment = FD_RPC_COMMITMENT_PROCESSED;
      else if( FD_LIKELY( !strcmp( _commitment->valuestring, "confirmed" ) ) ) commitment = FD_RPC_COMMITMENT_CONFIRMED;
      else if( FD_LIKELY( !strcmp( _commitment->valuestring, "finalized" ) ) ) commitment = FD_RPC_COMMITMENT_FINALIZED;
      else return (fd_http_server_response_t){ .status = 400 };
    }
  }

  if( FD_UNLIKELY( commitment!=FD_RPC_COMMITMENT_PROCESSED ) ) return (fd_http_server_response_t){ .status = 400 };
  bank_info_t const * bank = &ctx->banks[ ctx->processed_idx ];

  fd_rent_t rent = {
    .lamports_per_uint8_year = bank->rent.lamports_per_uint8_year,
    .exemption_threshold = bank->rent.exemption_threshold,
    .burn_percent = bank->rent.burn_percent,
  };
  ulong minimum = fd_rent_exempt_minimum_balance( &rent, data_len->valueulong );

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%lu}\n", minimum, request_id );
  fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
  FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
  return response;
}

UNIMPLEMENTED(getMultipleAccounts)
UNIMPLEMENTED(getProgramAccounts)
UNIMPLEMENTED(getRecentPerformanceSamples)
UNIMPLEMENTED(getRecentPrioritizationFees)
UNIMPLEMENTED(getSignaturesForAddress)
UNIMPLEMENTED(getSignatureStatuses)

static fd_http_server_response_t
getSlot( fd_rpc_tile_t * ctx,
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
  bank_info_t const * bank = &ctx->banks[ ctx->processed_idx ];

  if( FD_UNLIKELY( minContextSlot!=ULONG_MAX && minContextSlot>bank->slot ) ) {
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Minimum context slot has not been reached\",\"data\":{\"contextSlot\":%lu}},\"id\":%lu}\n", FD_RPC_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED, bank->slot, request_id );
    fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
    FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
    return response;
  }

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%lu}\n", bank->slot, request_id );
  fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
  FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
  return response;
}

UNIMPLEMENTED(getSlotLeader)
UNIMPLEMENTED(getSlotLeaders)
UNIMPLEMENTED(getStakeMinimumDelegation)
UNIMPLEMENTED(getSupply)
UNIMPLEMENTED(getTokenAccountBalance)
UNIMPLEMENTED(getTokenAccountsByDelegate)
UNIMPLEMENTED(getTokenAccountsByOwner)
UNIMPLEMENTED(getTokenLargestAccounts)
UNIMPLEMENTED(getTokenSupply)
UNIMPLEMENTED(getTransaction)

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
  bank_info_t const * bank = &ctx->banks[ ctx->processed_idx ];

  if( FD_UNLIKELY( minContextSlot!=ULONG_MAX && minContextSlot>bank->slot ) ) {
    fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":%d,\"message\":\"Minimum context slot has not been reached\",\"data\":{\"contextSlot\":%lu}},\"id\":%lu}\n", FD_RPC_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED, bank->slot, request_id );
    fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
    FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
    return response;
  }

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":%lu,\"id\":%lu}\n", bank->transaction_count, request_id );
  fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
  FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
  return response;
}

static fd_http_server_response_t
getVersion( fd_rpc_tile_t * ctx,
            ulong           request_id,
            cJSON const *   params ) {
  (void)params;

  fd_http_server_printf( ctx->http, "{\"jsonrpc\":\"2.0\",\"result\":{\"solana-core\":\"%s\",\"feature-set\":%u},\"id\":%lu}\n", ctx->version_string, FD_FEATURE_SET_ID, request_id );
  fd_http_server_response_t response = (fd_http_server_response_t){ .content_type = "application/json", .status = 200, .upgrade_websocket = 0 };
  FD_TEST( !fd_http_server_stage_body( ctx->http, &response ) );
  return response;
}

UNIMPLEMENTED(getVoteAccounts) // TODO: Used by solana-exporter
UNIMPLEMENTED(isBlockhashValid)
UNIMPLEMENTED(minimumLedgerSlot) // TODO: Used by solana-exporter
UNIMPLEMENTED(requestAirdrop)
UNIMPLEMENTED(sendTransaction)
UNIMPLEMENTED(simulateTransaction)

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

  fd_http_server_response_t response;

  const cJSON * _method = cJSON_GetObjectItemCaseSensitive( json, "method" );
  if( FD_LIKELY( !cJSON_IsString( _method ) || _method->valuestring==NULL ) ) goto bad_request;
  if( FD_LIKELY(      !strcmp( _method->valuestring, "getAccountInfo"                    ) ) ) response = getAccountInfo( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getBalance"                        ) ) ) response = getBalance( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getBlock"                          ) ) ) response = getBlock( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getBlockCommitment"                ) ) ) response = getBlockCommitment( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getBlockHeight"                    ) ) ) response = getBlockHeight( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getBlockProduction"                ) ) ) response = getBlockProduction( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getBlocks"                         ) ) ) response = getBlocks( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getBlocksWithLimit"                ) ) ) response = getBlocksWithLimit( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getBlockTime"                      ) ) ) response = getBlockTime( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getClusterNodes"                   ) ) ) response = getClusterNodes( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getEpochInfo"                      ) ) ) response = getEpochInfo( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getEpochSchedule"                  ) ) ) response = getEpochSchedule( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getFeeForMessage"                  ) ) ) response = getFeeForMessage( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getFirstAvailableBlock"            ) ) ) response = getFirstAvailableBlock( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getGenesisHash"                    ) ) ) response = getGenesisHash( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getHealth"                         ) ) ) response = getHealth( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getHighestSnapshotSlot"            ) ) ) response = getHighestSnapshotSlot( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getIdentity"                       ) ) ) response = getIdentity( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getInflationGovernor"              ) ) ) response = getInflationGovernor( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getInflationRate"                  ) ) ) response = getInflationRate( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getInflationReward"                ) ) ) response = getInflationReward( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getLargestAccounts"                ) ) ) response = getLargestAccounts( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getLatestBlockhash"                ) ) ) response = getLatestBlockhash( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getLeaderSchedule"                 ) ) ) response = getLeaderSchedule( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getMaxRetransmitSlot"              ) ) ) response = getMaxRetransmitSlot( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getMaxShredInsertSlot"             ) ) ) response = getMaxShredInsertSlot( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getMinimumBalanceForRentExemption" ) ) ) response = getMinimumBalanceForRentExemption( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getMultipleAccounts"               ) ) ) response = getMultipleAccounts( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getProgramAccounts"                ) ) ) response = getProgramAccounts( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getRecentPerformanceSamples"       ) ) ) response = getRecentPerformanceSamples( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getRecentPrioritizationFees"       ) ) ) response = getRecentPrioritizationFees( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getSignaturesForAddress"           ) ) ) response = getSignaturesForAddress( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getSignatureStatuses"              ) ) ) response = getSignatureStatuses( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getSlot"                           ) ) ) response = getSlot( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getSlotLeader"                     ) ) ) response = getSlotLeader( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getSlotLeaders"                    ) ) ) response = getSlotLeaders( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getStakeMinimumDelegation"         ) ) ) response = getStakeMinimumDelegation( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getSupply"                         ) ) ) response = getSupply( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getTokenAccountBalance"            ) ) ) response = getTokenAccountBalance( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getTokenAccountsByDelegate"        ) ) ) response = getTokenAccountsByDelegate( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getTokenAccountsByOwner"           ) ) ) response = getTokenAccountsByOwner( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getTokenLargestAccounts"           ) ) ) response = getTokenLargestAccounts( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getTokenSupply"                    ) ) ) response = getTokenSupply( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getTransaction"                    ) ) ) response = getTransaction( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getTransactionCount"               ) ) ) response = getTransactionCount( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getVersion"                        ) ) ) response = getVersion( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "getVoteAccounts"                   ) ) ) response = getVoteAccounts( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "isBlockhashValid"                  ) ) ) response = isBlockhashValid( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "minimumLedgerSlot"                 ) ) ) response = minimumLedgerSlot( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "requestAirdrop"                    ) ) ) response = requestAirdrop( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "sendTransaction"                   ) ) ) response = sendTransaction( ctx, request_id, params );
  else if( FD_LIKELY( !strcmp( _method->valuestring, "simulateTransaction"               ) ) ) response = simulateTransaction( ctx, request_id, params );
  else goto bad_request;

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

  if( FD_UNLIKELY( !strcmp( tile->rpc.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  const uchar * identity_key = fd_keyload_load( tile->rpc.identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->identity_pubkey, identity_key, 32UL );

  fd_http_server_callbacks_t callbacks = {
    .request = rpc_http_request,
  };
  ctx->http = fd_http_server_join( fd_http_server_new( _http, http_params, callbacks, ctx ) );
  fd_http_server_listen( ctx->http, tile->rpc.listen_addr, tile->rpc.listen_port );

  FD_LOG_NOTICE(( "rpc server listening at http://" FD_IP4_ADDR_FMT ":%u", FD_IP4_ADDR_FMT_ARGS( tile->rpc.listen_addr ), tile->rpc.listen_port ));
}

extern char const fdctl_version_string[];

static inline fd_rpc_out_t
out1( fd_topo_t const *      topo,
      fd_topo_tile_t const * tile,
      char const *           name ) {
  ulong idx = ULONG_MAX;

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    if( !strcmp( link->name, name ) ) {
      if( FD_UNLIKELY( idx!=ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu had multiple output links named %s but expected one", tile->name, tile->kind_id, name ));
      idx = i;
    }
  }

  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return (fd_rpc_out_t){ .idx = ULONG_MAX, .mem = NULL, .chunk0 = 0, .wmark = 0, .chunk = 0 };


  ulong mtu = topo->links[ tile->out_link_id[ idx ] ].mtu;
  if( FD_UNLIKELY( mtu==0UL ) ) return (fd_rpc_out_t){ .idx = idx, .mem = NULL, .chunk0 = ULONG_MAX, .wmark = ULONG_MAX, .chunk = ULONG_MAX };

  void * mem = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, topo->links[ tile->out_link_id[ idx ] ].mtu );

  return (fd_rpc_out_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0 };
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpc_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_rpc_tile_t ), sizeof( fd_rpc_tile_t )                                );
                        FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(),   fd_http_server_footprint( derive_http_params( tile ) ) );
  void * _alloc       = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(),         fd_alloc_footprint()                                   );
  void * _banks       = FD_SCRATCH_ALLOC_APPEND( l, alignof(bank_info_t),     tile->rpc.max_live_slots*sizeof(bank_info_t)           );

  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( _alloc, 1UL ), 1UL );
  FD_TEST( alloc );
  cJSON_alloc_install( alloc );

  ctx->keyswitch = fd_keyswitch_join( fd_topo_obj_laddr( topo, tile->keyswitch_obj_id ) );
  FD_TEST( ctx->keyswitch );

  ctx->next_poll_deadline = fd_tickcount();

  ctx->cluster_confirmed_slot = ULONG_MAX;

  ctx->processed_idx = ULONG_MAX;
  ctx->confirmed_idx = ULONG_MAX;
  ctx->finalized_idx = ULONG_MAX;

  ctx->banks = _banks;

  FD_TEST( fd_cstr_printf_check( ctx->version_string, sizeof( ctx->version_string ), NULL, "%s", fdctl_version_string ) );

  FD_TEST( tile->in_cnt<=sizeof( ctx->in )/sizeof( ctx->in[ 0 ] ) );
  for( ulong i=0; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    ctx->in[ i ].mtu    = link->mtu;

    if( FD_LIKELY( !strcmp( link->name, "replay_out" ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( FD_LIKELY( !strcmp( link->name, "genesi_out" ) ) ) ctx->in_kind[ i ] = IN_KIND_GENESI;
    else FD_LOG_ERR(( "unexpected link name %s", link->name ));
  }

  *ctx->replay_out = out1( topo, tile, "rpc_replay" ); FD_TEST( ctx->replay_out->idx!=ULONG_MAX );

  fd_accdb_init_from_topo( ctx->accdb, topo, tile );

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

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag

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
