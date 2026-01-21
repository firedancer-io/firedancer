#define _GNU_SOURCE
#include "fd_rpc_tile.c"
#include "../../funk/fd_funk.h"
#include "../../disco/topo/fd_topob.h"
#include "../../waltz/http/fd_http_server_private.h"
#include "../../util/pod/fd_pod.h"
#include <errno.h>
#include <sys/mman.h>

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

static fd_topo_link_t *
create_link( fd_topo_t *  topo,
             fd_wksp_t *  wksp,
             char const * name,
             ulong        depth,
             ulong        mtu,
             ulong        burst ) {
  fd_topo_link_t * link = fd_topob_link( topo, name, wksp->name, depth, mtu, burst );

  fd_topo_obj_t *  mcache_obj = &topo->objs[ link->mcache_obj_id ];
  void *           mcache_mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( depth, mtu ), 1UL );
  fd_frag_meta_t * mcache     = fd_mcache_join( fd_mcache_new( mcache_mem, depth, mtu, 0UL ) );
  FD_TEST( mcache );
  link->mcache       = mcache;
  mcache_obj->offset = fd_wksp_gaddr_fast( wksp, mcache_mem );

  if( mtu ) {
    fd_topo_obj_t * dcache_obj     = &topo->objs[ link->dcache_obj_id ];
    ulong           dcache_data_sz = fd_dcache_req_data_sz( mtu, depth, burst, 1 );
    void *          dcache_mem     = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( dcache_data_sz, 0UL ), 1UL );
    uchar *         dcache         = fd_dcache_join( fd_dcache_new( dcache_mem, dcache_data_sz, 0UL ) );
    FD_TEST( dcache );
    link->dcache       = dcache;
    dcache_obj->offset = fd_wksp_gaddr_fast( wksp, dcache_mem );
  }

  return link;
}

static void
expect_rpc_response( fd_rpc_tile_t * ctx,
                     char const *    rpc_req,
                     char const *    rpc_res ) {

  struct fd_http_server_connection * conn = &ctx->http->conns[0];
  conn->state                  = FD_HTTP_SERVER_CONNECTION_STATE_READING;
  conn->request_bytes          = (char *)rpc_req;
  conn->request_bytes_read     = (ulong)strlen(rpc_req);
  conn->response._body_off     = 0UL;
  conn->response._body_len     = 0UL;
  conn->response_bytes_written = 0UL;

  fd_http_server_request_t http_req = {
    .method = FD_HTTP_SERVER_METHOD_POST,
    .path   = "/",
    .ctx    = ctx,
    .headers = {
      .content_type = "application/json"
    },
    .post = {
      .body     = (uchar const *)rpc_req,
      .body_len = strlen( rpc_req )
    }
  };
  fd_http_server_response_t http_res = rpc_http_request( &http_req );
  FD_TEST( http_res.status==200 );
  FD_TEST( !ctx->http->stage_err );

  uchar const * got_json    = ctx->http->oring + (http_res._body_off % ctx->http->oring_sz);
  ulong         got_json_sz = http_res._body_len;

  cJSON * got = cJSON_ParseWithLength( (char const *)got_json, got_json_sz );
  FD_TEST( got );

  cJSON * expected = cJSON_Parse( rpc_res );
  FD_TEST( expected );

  char * got_reserialized = cJSON_Print( got      ); FD_TEST( got_reserialized );
  char * exp_reserialized = cJSON_Print( expected ); FD_TEST( exp_reserialized );
  if( 0!=strcmp( got_reserialized, exp_reserialized ) ) {
    FD_LOG_WARNING(( "Expected RPC response:\n---\n%s\n---", exp_reserialized ));
    FD_LOG_WARNING(( "Got RPC response:\n---\n%s\n---", got_reserialized ));
    FD_LOG_ERR(( "RPC response did not match expected" ));
  }

  cJSON_free( got_reserialized );
  cJSON_free( exp_reserialized );
  cJSON_Delete( expected );
  cJSON_Delete( got );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_wksp_t * wksp = fd_wksp_new_lazy( 4UL<<30 );
  static fd_topo_t topo[1];
  fd_topob_new( topo, "topo" );
  fd_topo_wksp_t * topo_wksp = fd_topob_wksp( topo, "wksp" );
  topo_wksp->wksp = wksp;
  void * keyswitch_mem = fd_wksp_alloc_laddr( wksp, fd_keyswitch_align(), fd_keyswitch_footprint(), 1UL );
  FD_TEST( keyswitch_mem );

  fd_keyswitch_t * keyswitch = fd_keyswitch_join( fd_keyswitch_new( keyswitch_mem, FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( keyswitch );
  fd_topo_obj_t * keyswitch_obj = fd_topob_obj( topo, "keyswitch", "wksp" );
  keyswitch_obj->wksp_id = topo_wksp->id;
  keyswitch_obj->offset  = fd_wksp_gaddr_fast( wksp, keyswitch_mem );

  ulong const funk_txn_max = 16UL;
  ulong const funk_rec_max = 16UL;
  void * shfunk = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( funk_txn_max, funk_rec_max ), 1UL );
  FD_TEST( fd_funk_new( shfunk, 1UL, 1UL, funk_txn_max, funk_rec_max ) );
  fd_topo_obj_t * funk_obj = fd_topob_obj( topo, "funk", "wksp" );
  funk_obj->wksp_id = topo_wksp->id;
  funk_obj->offset  = fd_wksp_gaddr_fast( wksp, shfunk );
  fd_pod_insert_ulong( topo->props, "funk", funk_obj->id );

  fd_topo_link_t * link_rpc_replay = create_link( topo, wksp, "rpc_replay", 4UL, 0UL, 1UL );
  (void)link_rpc_replay;

  fd_topo_tile_t * tile     = fd_topob_tile( topo, "rpc", "wksp", "wksp", 0UL, 0, 0 );
  fd_topo_obj_t *  tile_obj = &topo->objs[ tile->tile_obj_id ];
  strcpy( tile->name, "rpc" );
  tile->rpc.max_live_slots = 16UL;
  tile->rpc.send_buffer_size_mb = 64UL;
  tile->keyswitch_obj_id = keyswitch_obj->id;

  fd_topob_tile_out( topo, "rpc", 0UL, "rpc_replay", 0UL );

  void * scratch = fd_wksp_alloc_laddr( wksp, scratch_align(), scratch_footprint( tile ), 1UL );
  fd_http_server_params_t http_params = derive_http_params( tile );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_rpc_tile_t * ctx      = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_rpc_tile_t ), sizeof( fd_rpc_tile_t ) );
  void *          http_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_http_server_align(),   fd_http_server_footprint( http_params ) );
  tile_obj->offset = fd_wksp_gaddr_fast( wksp, ctx );
  memset( ctx, 0, sizeof(fd_rpc_tile_t) );
  static fd_http_server_callbacks_t const callbacks = {
    .request = rpc_http_request,
  };
  ctx->http = fd_http_server_join( fd_http_server_new( http_mem, http_params, callbacks, ctx ) );
  FD_TEST( ctx->http );
  FD_TEST( ctx->http->oring_sz );
  unprivileged_init( topo, tile );

  expect_rpc_response( ctx,
      "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getHealth\"}",
      "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32005,\"message\":\"Node is unhealthy\",\"data\":{\"slotsBehind\":null}},\"id\":1}"
  );

  /* Don't bother with cleanup since all resources are reclaimed by the
     kernel on return. */
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
