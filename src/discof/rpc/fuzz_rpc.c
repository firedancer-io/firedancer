#define _GNU_SOURCE

#include <limits.h>
#if !FD_HAS_HOSTED
#error "This target requires FD_HAS_HOSTED"
#endif

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <poll.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/mman.h>

#include "../../util/fd_util.h"
#include "../../funk/fd_funk.h"
#include "../../flamenco/accdb/fd_accdb_impl_v1.h"
#include "../../disco/topo/fd_topob.h"
#include "../../util/pod/fd_pod.h"
#include "../../util/pod/fd_pod_format.h"
#include "../../ballet/json/cJSON_alloc.h"
#include "../../util/sanitize/fd_fuzz.h"

#define FD_TILE_TEST
#include "fd_rpc_tile.c"

#define FUZZ_RPC_OUTGOING_BUFFER_SZ (1024UL) /* matches default.toml */

const fd_http_server_params_t http_params = {
  .max_connection_cnt    = 1024UL,
  .max_ws_connection_cnt = 0UL,
  .max_request_len       = FD_HTTP_SERVER_RPC_MAX_REQUEST_LEN,
  .max_ws_recv_frame_len = 0UL,
  .max_ws_send_frame_cnt = 0UL,
  .outgoing_buffer_sz    = FUZZ_RPC_OUTGOING_BUFFER_SZ,
  .compress_websocket    = 0,
};

static uchar * nodes_dlist_mem;
static uchar * http_mem;
static uchar * rpc_mem;

static fd_topo_t * topo;
static ulong funk_obj_id;
static ulong locks_obj_id;

static fd_wksp_t *
fd_wksp_new_lazy( ulong footprint ) {
  footprint = fd_ulong_align_up( footprint, FD_SHMEM_NORMAL_PAGE_SZ );
  void * mem = mmap( NULL, footprint, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( mem==MAP_FAILED ) ) {
    FD_LOG_ERR(( "mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS) failed (%i-%s)",
                 footprint>>10, errno, fd_io_strerror( errno ) ));
  }

  ulong part_max = fd_wksp_part_max_est( footprint, 64UL<<10 );
  FD_TEST( part_max );
  ulong data_max = fd_wksp_data_max_est( footprint, part_max );
  FD_TEST( data_max );
  fd_wksp_t * wksp = fd_wksp_join( fd_wksp_new( mem, "wksp", 1U, part_max, data_max ) );
  FD_TEST( wksp );

  FD_TEST( 0==fd_shmem_join_anonymous( "wksp", FD_SHMEM_JOIN_MODE_READ_WRITE, wksp, mem, FD_SHMEM_NORMAL_PAGE_SZ, footprint>>FD_SHMEM_NORMAL_LG_PAGE_SZ ) );
  return wksp;
}

void
setup_topo_funk( fd_topo_t *  topo,
                 ulong        max_account_records,
                 ulong        max_database_transactions,
                 ulong        heap_size_mib ) {
  fd_topo_obj_t * funk_obj = fd_topob_obj( topo, "funk", "funk" );
  FD_TEST( fd_pod_insert_ulong(  topo->props, "funk", funk_obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_account_records,       "obj.%lu.rec_max",  funk_obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_database_transactions, "obj.%lu.txn_max",  funk_obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, heap_size_mib*(1UL<<20),   "obj.%lu.heap_max", funk_obj->id ) );
  ulong funk_footprint = fd_funk_shmem_footprint( max_database_transactions, max_account_records );
  if( FD_UNLIKELY( !funk_footprint ) ) FD_LOG_ERR(( "Invalid [accounts] parameters" ));

  /* Increase workspace partition count */
  ulong wksp_idx = fd_topo_find_wksp( topo, "funk" );
  FD_TEST( wksp_idx!=ULONG_MAX );
  fd_topo_wksp_t * wksp = &topo->workspaces[ wksp_idx ];
  ulong size     = funk_footprint+(heap_size_mib*(1UL<<20));
  ulong part_max = fd_wksp_part_max_est( size, 1U<<14U );
  if( FD_UNLIKELY( !part_max ) ) FD_LOG_ERR(( "fd_wksp_part_max_est(%lu,16KiB) failed", size ));
  wksp->part_max += part_max;

  fd_topo_obj_t * locks_obj = fd_topob_obj( topo, "funk_locks", "funk_locks" );
  FD_TEST( fd_pod_insert_ulong( topo->props, "funk_locks", locks_obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_database_transactions, "obj.%lu.txn_max", locks_obj->id ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, max_account_records,       "obj.%lu.rec_max", locks_obj->id ) );
}

int
LLVMFuzzerInitialize( int  *   argc,
                      char *** argv ) {
  (void)privileged_init;
  (void)unprivileged_init;
  (void)populate_allowed_seccomp;
  (void)populate_allowed_fds;
  (void)rlimit_file_cnt;

  /* Set up shell without signal handlers */
  putenv( "FD_LOG_BACKTRACE=0" );
  putenv( "FD_LOG_PATH=" );
  fd_boot( argc, argv );
  fd_log_level_core_set(5);  /* abort on FD_LOG_ERR */

  topo = aligned_alloc( alignof(fd_topo_t), sizeof(fd_topo_t) );
  FD_TEST( topo );

  nodes_dlist_mem = aligned_alloc( fd_rpc_cluster_node_dlist_align(), fd_rpc_cluster_node_dlist_footprint() );
  FD_TEST( nodes_dlist_mem );

  http_mem = aligned_alloc( fd_http_server_align(), fd_http_server_footprint( http_params ) );
  FD_TEST( http_mem );

  rpc_mem = aligned_alloc( alignof(fd_rpc_tile_t), sizeof(fd_rpc_tile_t) );
  FD_TEST( rpc_mem );

  fd_wksp_t * wksp = fd_wksp_new_lazy( 4UL << 30UL );
  fd_topob_new( topo, "topo" );
  fd_topo_wksp_t * topo_wksp = fd_topob_wksp( topo, "wksp" );
  topo_wksp->wksp = wksp;

  ulong const funk_txn_max = 16UL;
  ulong const funk_rec_max = 16UL;
  setup_topo_funk( topo, funk_rec_max, funk_txn_max, 1UL );

  FD_TEST( (funk_obj_id  = fd_pod_query_ulong( topo->props, "funk",       ULONG_MAX ))!=ULONG_MAX );
  FD_TEST( (locks_obj_id = fd_pod_query_ulong( topo->props, "funk_locks", ULONG_MAX ))!=ULONG_MAX );

  void * shalloc = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 2UL );
  fd_alloc_t * alloc = fd_alloc_join( fd_alloc_new( shalloc, 1UL ), 1UL );
  FD_TEST( alloc );
  cJSON_alloc_install( alloc );

  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  ulong __i = 0UL;
#define FETCH_REF(__sz) (__extension__({ \
  __i += (__sz); \
  if( FD_UNLIKELY( __i>=size ) ) return 0; \
  (void const *)(data+__i-(__sz)); }))

#define FETCH_TYPE(__type) (FD_LOAD( __type, FETCH_REF( sizeof(__type) ) ))

  fd_rpc_tile_t * ctx = fd_type_pun( rpc_mem );
  memset( ctx, 0, sizeof(*ctx) );

  fd_http_server_t * http = fd_http_server_join( fd_http_server_new( http_mem, http_params, (fd_http_server_callbacks_t){ 0 }, NULL ) );
  ctx->http = http;

  FD_TEST( fd_accdb_user_v1_init( ctx->accdb, fd_topo_obj_laddr( topo, funk_obj_id ), fd_topo_obj_laddr( topo, locks_obj_id ), 16UL ) );

  ctx->cluster_nodes_dlist = fd_rpc_cluster_node_dlist_join( fd_rpc_cluster_node_dlist_new( nodes_dlist_mem ) );
  ctx->cluster_nodes[ 0 ].valid = 1;
  fd_rpc_cluster_node_dlist_idx_push_tail( ctx->cluster_nodes_dlist, 0, ctx->cluster_nodes );

  bank_info_t banks[ 3UL ] = { 0 };
  ctx->banks = banks;

  ctx->processed_idx = FETCH_TYPE( uchar ) % 64 ? 0UL : ULONG_MAX;
  ctx->confirmed_idx = FETCH_TYPE( uchar ) % 64 ? 1UL : ULONG_MAX;
  ctx->finalized_idx = FETCH_TYPE( uchar ) % 64 ? 2UL : ULONG_MAX;

  for( ulong j=0UL; j<3UL; j++ ) {
    ctx->banks[ j ].slot = FETCH_TYPE( ulong );
    ctx->banks[ j ].bank_idx = j;
  }
  ctx->has_genesis_hash = FETCH_TYPE( uchar ) % 2;

  fd_cstr_ncpy( ctx->version_string, "0.1.1", sizeof(ctx->version_string) );

  fd_http_server_request_t req[ 1 ];
  req->ctx = ctx;
  req->connection_id = 0UL;

  req->headers.content_type       = NULL;
  req->headers.accept_encoding    = NULL;
  req->headers.compress_websocket = 0;
  req->headers.upgrade_websocket  = 0;

  req->method = FD_HTTP_SERVER_METHOD_POST;
  req->path   = "";

  uchar req_body[ FD_HTTP_SERVER_RPC_MAX_REQUEST_LEN ];
  ulong req_body_sz;

  if( FETCH_TYPE( uchar ) % 2 ) {
    /* unstructured */
    req_body_sz = FETCH_TYPE( ushort ) % FD_HTTP_SERVER_RPC_MAX_REQUEST_LEN;
    fd_memcpy( req_body, FETCH_REF( req_body_sz ), req_body_sz );
  } else {
    /* structured - use full buffer for CHECKED_APPEND bounds */
    req_body_sz = FD_HTTP_SERVER_RPC_MAX_REQUEST_LEN;

#define CHECKED_APPEND( __d, __s) \
    ulong remaining = req_body_sz-((ulong)__d-(ulong)req_body); \
    if( strlen(__s)+1UL>remaining ) return 0; \
    (__d) = fd_cstr_append_cstr( (__d), (__s) )

    char * cstr = fd_cstr_init( (char *)req_body );

    { CHECKED_APPEND( cstr, "{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"" ); }

    switch( FETCH_TYPE(uchar) % 53 ) {
      case  0: { CHECKED_APPEND( cstr, "getAccountInfo"                    ); } break;
      case  1: { CHECKED_APPEND( cstr, "getBalance"                        ); } break;
      case  2: { CHECKED_APPEND( cstr, "getBlock"                          ); } break;
      case  3: { CHECKED_APPEND( cstr, "getBlockCommitment"                ); } break;
      case  4: { CHECKED_APPEND( cstr, "getBlockHeight"                    ); } break;
      case  5: { CHECKED_APPEND( cstr, "getBlockProduction"                ); } break;
      case  6: { CHECKED_APPEND( cstr, "getBlocks"                         ); } break;
      case  7: { CHECKED_APPEND( cstr, "getBlocksWithLimit"                ); } break;
      case  8: { CHECKED_APPEND( cstr, "getBlockTime"                      ); } break;
      case  9: { CHECKED_APPEND( cstr, "getClusterNodes"                   ); } break;
      case 10: { CHECKED_APPEND( cstr, "getEpochInfo"                      ); } break;
      case 11: { CHECKED_APPEND( cstr, "getEpochSchedule"                  ); } break;
      case 12: { CHECKED_APPEND( cstr, "getFeeForMessage"                  ); } break;
      case 13: { CHECKED_APPEND( cstr, "getFirstAvailableBlock"            ); } break;
      case 14: { CHECKED_APPEND( cstr, "getGenesisHash"                    ); } break;
      case 15: { CHECKED_APPEND( cstr, "getHealth"                         ); } break;
      case 16: { CHECKED_APPEND( cstr, "getHighestSnapshotSlot"            ); } break;
      case 17: { CHECKED_APPEND( cstr, "getIdentity"                       ); } break;
      case 18: { CHECKED_APPEND( cstr, "getInflationGovernor"              ); } break;
      case 19: { CHECKED_APPEND( cstr, "getInflationRate"                  ); } break;
      case 20: { CHECKED_APPEND( cstr, "getInflationReward"                ); } break;
      case 21: { CHECKED_APPEND( cstr, "getLargestAccounts"                ); } break;
      case 22: { CHECKED_APPEND( cstr, "getLatestBlockhash"                ); } break;
      case 23: { CHECKED_APPEND( cstr, "getLeaderSchedule"                 ); } break;
      case 24: { CHECKED_APPEND( cstr, "getMaxRetransmitSlot"              ); } break;
      case 25: { CHECKED_APPEND( cstr, "getMaxShredInsertSlot"             ); } break;
      case 26: { CHECKED_APPEND( cstr, "getMinimumBalanceForRentExemption" ); } break;
      case 27: { CHECKED_APPEND( cstr, "getMultipleAccounts"               ); } break;
      case 28: { CHECKED_APPEND( cstr, "getProgramAccounts"                ); } break;
      case 29: { CHECKED_APPEND( cstr, "getRecentPerformanceSamples"       ); } break;
      case 30: { CHECKED_APPEND( cstr, "getRecentPrioritizationFees"       ); } break;
      case 31: { CHECKED_APPEND( cstr, "getSignaturesForAddress"           ); } break;
      case 32: { CHECKED_APPEND( cstr, "getSignatureStatuses"              ); } break;
      case 33: { CHECKED_APPEND( cstr, "getSlot"                           ); } break;
      case 34: { CHECKED_APPEND( cstr, "getSlotLeader"                     ); } break;
      case 35: { CHECKED_APPEND( cstr, "getSlotLeaders"                    ); } break;
      case 36: { CHECKED_APPEND( cstr, "getStakeMinimumDelegation"         ); } break;
      case 37: { CHECKED_APPEND( cstr, "getSupply"                         ); } break;
      case 38: { CHECKED_APPEND( cstr, "getTokenAccountBalance"            ); } break;
      case 39: { CHECKED_APPEND( cstr, "getTokenAccountsByDelegate"        ); } break;
      case 40: { CHECKED_APPEND( cstr, "getTokenAccountsByOwner"           ); } break;
      case 41: { CHECKED_APPEND( cstr, "getTokenLargestAccounts"           ); } break;
      case 42: { CHECKED_APPEND( cstr, "getTokenSupply"                    ); } break;
      case 43: { CHECKED_APPEND( cstr, "getTransaction"                    ); } break;
      case 44: { CHECKED_APPEND( cstr, "getTransactionCount"               ); } break;
      case 45: { CHECKED_APPEND( cstr, "getVersion"                        ); } break;
      case 46: { CHECKED_APPEND( cstr, "getVoteAccounts"                   ); } break;
      case 47: { CHECKED_APPEND( cstr, "isBlockhashValid"                  ); } break;
      case 48: { CHECKED_APPEND( cstr, "minimumLedgerSlot"                 ); } break;
      case 49: { CHECKED_APPEND( cstr, "requestAirdrop"                    ); } break;
      case 50: { CHECKED_APPEND( cstr, "sendTransaction"                   ); } break;
      case 51: { CHECKED_APPEND( cstr, "simulateTransaction"               ); } break;
      default: { CHECKED_APPEND( cstr, "unknownMethod"                     ); } break;
    }
    { CHECKED_APPEND( cstr, "\",\"params\":[" ); }

    /* optional positional params */
    ulong num_params = FETCH_TYPE( uchar ) % 3UL;
    for( ulong p = 0UL; p < num_params; p++ ) {
      if( p > 0UL ) { CHECKED_APPEND( cstr, "," ); }
      if( FETCH_TYPE( uchar ) % 2 ) {
        ulong plen = FETCH_TYPE( uchar ) % 64UL;
        char  pbuf[ 65 ];
        for( ulong k = 0UL; k < plen; k++ )
          pbuf[k] = (char)(0x20 + FETCH_TYPE( uchar ) % 95);
        pbuf[ plen ] = '\0';
        { CHECKED_APPEND( cstr, pbuf  ); }
      } else {
        { CHECKED_APPEND( cstr, "null" ); }
      }
    }

    /* optional config */
    if( FETCH_TYPE( uchar ) % 2 ) {
      if( num_params > 0UL ) { CHECKED_APPEND( cstr, "," ); }
      { CHECKED_APPEND( cstr, "{" ); }
      int need_comma = 0;

      /* "commitment" */
      if( FETCH_TYPE( uchar ) % 2 ) {
        if( need_comma ) { CHECKED_APPEND( cstr, "," ); }
        need_comma = 1;
        { CHECKED_APPEND( cstr, "\"commitment\":\"" ); }
        switch( FETCH_TYPE( uchar ) % 4 ) {
          case 0: { CHECKED_APPEND( cstr, "finalized" ); } break;
          case 1: { CHECKED_APPEND( cstr, "confirmed"  ); } break;
          case 2: { CHECKED_APPEND( cstr, "processed"  ); } break;
          default: {
            /* random commitment string */
            ulong clen = FETCH_TYPE( uchar ) % 16UL;
            char  cbuf[ 17 ];
            for( ulong k = 0UL; k < clen; k++ )
              cbuf[k] = (char)(0x20 + FETCH_TYPE( uchar ) % 95);
            cbuf[ clen ] = '\0';
            { CHECKED_APPEND( cstr, cbuf ); }
            break;
          }
        }
        { CHECKED_APPEND( cstr, "\"" ); }
      }

      /* "encoding" */
      if( FETCH_TYPE( uchar ) % 2 ) {
        if( need_comma ) { CHECKED_APPEND( cstr, "," ); }
        need_comma = 1;
        { CHECKED_APPEND( cstr, "\"encoding\":\"" ); }
        switch( FETCH_TYPE( uchar ) % 5 ) {
          case 0: { CHECKED_APPEND( cstr, "base58"      ); } break;
          case 1: { CHECKED_APPEND( cstr, "base64"      ); } break;
          case 2: { CHECKED_APPEND( cstr, "base64+zstd" ); } break;
          case 3: { CHECKED_APPEND( cstr, "jsonParsed"  ); } break;
          default: {
            /* random encoding string */
            ulong elen = FETCH_TYPE( uchar ) % 16UL;
            char  ebuf[ 17 ];
            for( ulong k = 0UL; k < elen; k++ )
              ebuf[k] = (char)(0x20 + FETCH_TYPE( uchar ) % 95);
            ebuf[ elen ] = '\0';
            { CHECKED_APPEND( cstr, ebuf ); }
            break;
          }
        }
        { CHECKED_APPEND( cstr, "\"" ); }
      }

      /* "dataSlice" */
      if( FETCH_TYPE( uchar ) % 2 ) {
        if( need_comma ) { CHECKED_APPEND( cstr, "," ); }
        need_comma = 1;
        { CHECKED_APPEND( cstr, "\"dataSlice\":" ); }
        if( FETCH_TYPE( uchar ) % 2 ) {
          ulong dlen = FETCH_TYPE( uchar ) % 32UL;
          char  dbuf[ 33 ];
          for( ulong k = 0UL; k < dlen; k++ )
            dbuf[k] = (char)(0x20 + FETCH_TYPE( uchar ) % 95);
          dbuf[ dlen ] = '\0';
          { CHECKED_APPEND( cstr, dbuf  ); }
        } else {
          /* structured {"offset":<num>,"length":<num>} */
          char nbuf[ 32 ];
          { CHECKED_APPEND( cstr, "{\"offset\":" ); }
          fd_cstr_printf( nbuf, sizeof(nbuf), NULL, "%lu", (ulong)FETCH_TYPE( ulong ) );
          { CHECKED_APPEND( cstr, nbuf ); }
          { CHECKED_APPEND( cstr, ",\"length\":" ); }
          fd_cstr_printf( nbuf, sizeof(nbuf), NULL, "%lu", (ulong)FETCH_TYPE( ulong ) );
          { CHECKED_APPEND( cstr, nbuf ); }
          { CHECKED_APPEND( cstr, "}" ); }
        }
      }

      /* "minContextSlot" */
      if( FETCH_TYPE( uchar ) % 2 ) {
        if( need_comma ) { CHECKED_APPEND( cstr, "," ); }
        need_comma = 1;
        char nbuf[ 32 ];
        { CHECKED_APPEND( cstr, "\"minContextSlot\":" ); }
        fd_cstr_printf( nbuf, sizeof(nbuf), NULL, "%lu", (ulong)FETCH_TYPE( ulong ) );
        { CHECKED_APPEND( cstr, nbuf ); }
      }

      { CHECKED_APPEND( cstr, "}" ); }
    }

    { CHECKED_APPEND( cstr, "]}" ); }

    req_body_sz = (ulong)cstr - (ulong)req_body;
  }

  req->post.body     = req_body;
  req->post.body_len = req_body_sz;
  // FD_LOG_WARNING(("request:\n%.*s", (int)req_body_sz, req_body ));
  rpc_http_request( req );
  FD_FUZZ_MUST_BE_COVERED;
  return 0;

#undef CHECKED_APPEND
#undef FETCH_TYPE
#undef FETCH_REF
}
