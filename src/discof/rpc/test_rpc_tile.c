#define _GNU_SOURCE
#include "fd_rpc_tile.c"
#include "../../disco/topo/fd_topob.h"
#include "../../waltz/http/fd_http_server_private.h"
#include "../../util/pod/fd_pod.h"
#include "../../tango/fseq/fd_fseq.h"
#include <errno.h>
#include <fcntl.h>
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

  ulong const max_accounts                = 1024UL;
  ulong const max_live_slots              = 16UL;
  ulong const max_writes_per_slot         = 64UL;
  ulong const partition_cnt               = 8192UL;
  ulong const partition_sz                = 1UL<<24UL;
  ulong const cache_fp                    = 64UL<<20UL;
  ulong const cache_min_reserved          = 1UL;
  ulong const joiner_cnt                  = 2UL; /* writer + readonly rpc */

  fd_topo_obj_t * accdb_shmem_obj = fd_topob_obj( topo, "accdb_shmem", "wksp" );
  ulong accdb_shmem_fp = fd_accdb_shmem_footprint( max_accounts, max_live_slots, max_writes_per_slot, partition_cnt, cache_fp, cache_min_reserved, joiner_cnt );
  void * accdb_shmem_mem = fd_wksp_alloc_laddr( wksp, fd_accdb_shmem_align(), accdb_shmem_fp, 1UL );
  FD_TEST( accdb_shmem_mem );
  FD_TEST( fd_accdb_shmem_new( accdb_shmem_mem, max_accounts, max_live_slots, max_writes_per_slot, partition_cnt, partition_sz, cache_fp, cache_min_reserved, 42UL, joiner_cnt ) );
  accdb_shmem_obj->wksp_id = topo_wksp->id;
  accdb_shmem_obj->offset  = fd_wksp_gaddr_fast( wksp, accdb_shmem_mem );
  fd_pod_insert_ulong( topo->props, "accdb", accdb_shmem_obj->id );

  /* Set up an fseq for the rpc tile's epoch slot. */
  void * fseq_mem = fd_wksp_alloc_laddr( wksp, fd_fseq_align(), fd_fseq_footprint(), 1UL );
  FD_TEST( fseq_mem );
  FD_TEST( fd_fseq_new( fseq_mem, ULONG_MAX ) );
  fd_topo_obj_t * fseq_obj = fd_topob_obj( topo, "fseq", "wksp" );
  fseq_obj->wksp_id = topo_wksp->id;
  fseq_obj->offset  = fd_wksp_gaddr_fast( wksp, fseq_mem );

  /* Open the on-disk accdb file and dup it to the well-known fd 123460
     that the rpc tile expects for its O_RDONLY join. */
  int accdb_data_fd = memfd_create( "accdb_test_data", 0 );
  FD_TEST( accdb_data_fd>=0 );
  FD_TEST( dup2( accdb_data_fd, 123460 )==123460 );

  /* Set up a writer accdb join used solely by the test to populate
     accounts.  The rpc tile will join read-only against the same shmem. */
  fd_accdb_shmem_t * writer_shmem = fd_accdb_shmem_join( accdb_shmem_mem );
  FD_TEST( writer_shmem );
  void * writer_ljoin = fd_wksp_alloc_laddr( wksp, fd_accdb_align(), fd_accdb_footprint( max_live_slots ), 1UL );
  FD_TEST( writer_ljoin );
  fd_accdb_t * writer_accdb = fd_accdb_join( fd_accdb_new( writer_ljoin, writer_shmem, accdb_data_fd, 0UL, NULL ) );
  FD_TEST( writer_accdb );

  fd_accdb_fork_id_t test_fork_id;
  {
    fd_accdb_fork_id_t sentinel = { .val = USHORT_MAX };
    fd_accdb_fork_id_t root_fork = fd_accdb_attach_child( writer_accdb, sentinel );
    test_fork_id = fd_accdb_attach_child( writer_accdb, root_fork );
  }

  fd_topo_link_t * link_rpc_replay = create_link( topo, wksp, "rpc_replay", 4UL, 0UL, 1UL );
  (void)link_rpc_replay;

  fd_topo_tile_t * tile     = fd_topob_tile( topo, "rpc", "wksp", "wksp", 0UL, 0, 0, 0 );
  fd_topo_obj_t *  tile_obj = &topo->objs[ tile->tile_obj_id ];
  strcpy( tile->name, "rpc" );
  tile->rpc.max_live_slots          = max_live_slots;
  tile->rpc.send_buffer_size_mb     = 64UL;
  tile->rpc.accdb_obj_id            = accdb_shmem_obj->id;
  tile->rpc.accdb_epoch_fseq_obj_id = fseq_obj->id;
  tile->id_keyswitch_obj_id         = keyswitch_obj->id;

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

  /* -- getMultipleAccounts -- */

  ctx->banks[0].slot          = 42UL;
  ctx->banks[0].accdb_fork_id = test_fork_id;
  ctx->processed_idx = 0UL;
  ctx->confirmed_idx = 0UL;
  ctx->finalized_idx = 0UL;

  /* Account A: 4 bytes of data, 1000000 lamports */
  fd_pubkey_t addr_a;
  memset( addr_a.uc, 0xAA, 32 );
  uchar owner_a[32];
  memset( owner_a, 0xBB, 32 );
  uchar data_a[4] = { 0x01, 0x02, 0x03, 0x04 };
  {
    uchar const * pks[1] = { addr_a.uc };
    int wr[1] = { 1 };
    fd_accdb_entry_t ent[1]; memset( ent, 0, sizeof(ent) );
    fd_accdb_acquire( writer_accdb, test_fork_id, 1UL, pks, wr, ent );
    ent[0].lamports = 1000000UL;
    ent[0].data_len = sizeof(data_a);
    memcpy( ent[0].owner, owner_a, 32UL );
    memcpy( ent[0].data, data_a, sizeof(data_a) );
    ent[0].commit = 1;
    fd_accdb_release( writer_accdb, 1UL, ent );
  }

  /* Account B: 2 bytes of data, 500000 lamports */
  fd_pubkey_t addr_b;
  memset( addr_b.uc, 0xCC, 32 );
  uchar owner_b[32];
  memset( owner_b, 0xDD, 32 );
  uchar data_b[2] = { 0xFE, 0xED };
  {
    uchar const * pks[1] = { addr_b.uc };
    int wr[1] = { 1 };
    fd_accdb_entry_t ent[1]; memset( ent, 0, sizeof(ent) );
    fd_accdb_acquire( writer_accdb, test_fork_id, 1UL, pks, wr, ent );
    ent[0].lamports = 500000UL;
    ent[0].data_len = sizeof(data_b);
    memcpy( ent[0].owner, owner_b, 32UL );
    memcpy( ent[0].data, data_b, sizeof(data_b) );
    ent[0].commit = 1;
    fd_accdb_release( writer_accdb, 1UL, ent );
  }

  FD_BASE58_ENCODE_32_BYTES( addr_a.uc, addr_a_b58 );
  FD_BASE58_ENCODE_32_BYTES( addr_b.uc, addr_b_b58 );
  FD_BASE58_ENCODE_32_BYTES( owner_a, owner_a_b58 );
  FD_BASE58_ENCODE_32_BYTES( owner_b, owner_b_b58 );

  fd_pubkey_t addr_missing;
  memset( addr_missing.uc, 0x11, 32 );
  FD_BASE58_ENCODE_32_BYTES( addr_missing.uc, addr_missing_b58 );

  char req_buf[8192];
  char res_buf[4096];

  expect_rpc_response( ctx,
      "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getMultipleAccounts\",\"params\":[\"not-an-array\"]}",
      "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid params: invalid type: string \\\"not-an-array\\\", expected a sequence.\"},\"id\":1}" );

  /* too many accounts (101) */
  {
    char * p = fd_cstr_init( req_buf );
    p = fd_cstr_append_cstr( p, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getMultipleAccounts\",\"params\":[[" );
    for( int i=0; i<101; i++ ) {
      if( i>0 ) p = fd_cstr_append_char( p, ',' );
      p = fd_cstr_append_printf( p, "\"%s\"", addr_a_b58 );
    }
    p = fd_cstr_append_cstr( p, "]]}" );
    fd_cstr_fini( p );

    expect_rpc_response( ctx, req_buf,
        "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Too many accounts provided; max 100\"},\"id\":1}" );
  }

  /* empty array */
  expect_rpc_response( ctx,
      "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getMultipleAccounts\",\"params\":[[]]}",
      "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"apiVersion\":\"" FD_RPC_AGAVE_API_VERSION "\",\"slot\":42},\"value\":[]}}" );

  /* mix of existing and missing accounts */
  {
    FD_TEST( fd_cstr_printf_check( req_buf, sizeof(req_buf), NULL,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getMultipleAccounts\",\"params\":[[\"%s\",\"%s\",\"%s\"],{\"encoding\":\"base64\"}]}",
        addr_a_b58, addr_missing_b58, addr_b_b58 ) );

    FD_TEST( fd_cstr_printf_check( res_buf, sizeof(res_buf), NULL,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"apiVersion\":\"" FD_RPC_AGAVE_API_VERSION "\",\"slot\":42},\"value\":["
        "{\"executable\":false,\"lamports\":1000000,\"owner\":\"%s\",\"rentEpoch\":18446744073709551615,\"space\":4,\"data\":[\"AQIDBA==\",\"base64\"]},"
        "null,"
        "{\"executable\":false,\"lamports\":500000,\"owner\":\"%s\",\"rentEpoch\":18446744073709551615,\"space\":2,\"data\":[\"/u0=\",\"base64\"]}"
        "]}}",
        owner_a_b58, owner_b_b58 ) );

    expect_rpc_response( ctx, req_buf, res_buf );
  }

  /* all missing accounts */
  {
    FD_TEST( fd_cstr_printf_check( req_buf, sizeof(req_buf), NULL,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getMultipleAccounts\",\"params\":[[\"%s\",\"%s\"],{\"encoding\":\"base64\"}]}",
        addr_missing_b58, addr_missing_b58 ) );

    expect_rpc_response( ctx, req_buf,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"apiVersion\":\"" FD_RPC_AGAVE_API_VERSION "\",\"slot\":42},\"value\":[null,null]}}" );
  }

  /* invalid pubkey in the middle of array */
  {
    FD_TEST( fd_cstr_printf_check( req_buf, sizeof(req_buf), NULL,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getMultipleAccounts\",\"params\":[[\"%s\",\"not-a-valid-pubkey\",\"%s\"]]}",
        addr_a_b58, addr_b_b58 ) );

    expect_rpc_response( ctx, req_buf,
        "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32602,\"message\":\"Invalid param: Invalid\"},\"id\":1}" );
  }

  /* Don't bother with cleanup since all resources are reclaimed by the
     kernel on return. */
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
