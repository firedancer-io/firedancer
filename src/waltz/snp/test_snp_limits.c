#include "fd_snp.h"
#include "fd_snp_app.h"
#include "../../ballet/sha512/fd_sha512.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../util/fd_util.h"

#define ITERATIONS_N (16)

#define TEST_SNP_LIMITS_LOG_ENABLED (0)

#if TEST_SNP_LIMITS_LOG_ENABLED
#define TEST_SNP_LIMITS_LOG(...) __VA_ARGS__
#else
#define TEST_SNP_LIMITS_LOG(...)
#endif

struct test_cb_ctx {
  uchar * out_packet;
  uchar * assert_packet;
  ulong   assert_packet_sz;
  uchar * assert_data;
  ulong   assert_data_sz;
  ulong   assert_peer;
  ulong   assert_meta;

  /* buffering */
  uchar   assert_buffered;
  fd_snp_pkt_t buf_packet[2];
  ulong   buf_cnt;

  /* signature */
  ulong   sign_cnt;
  uchar   signature   [64];
  uchar   public_key  [32];
  uchar   private_key [32];
  fd_snp_t * snp; /* to invoke fd_snp_process_signature */

  /* test_v1_detailed */
  fd_snp_app_t * snp_app;
  uchar success;
  uint ip;
};
typedef struct test_cb_ctx test_cb_ctx_t;

static void
external_generate_keypair( uchar private_key[32], uchar public_key[32] ) {
  fd_sha512_t sha512[1];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha512 ) ) );
  FD_TEST( fd_rng_secure( private_key, 32 )!=NULL );
  fd_ed25519_public_from_private( public_key, private_key, sha512 );
}

static int
test_cb_snp_tx( void const *  _ctx,
                uchar const * packet,
                ulong         packet_sz,
                fd_snp_meta_t meta ) {
  test_cb_ctx_t * ctx = (test_cb_ctx_t *)_ctx;

  /* set src ip - snp doesn't set it because in fd the net tile takes care of it */
  fd_ip4_udp_hdrs_t * hdr = (fd_ip4_udp_hdrs_t *)packet;
  hdr->ip4->saddr = ctx->ip;

  if( meta & FD_SNP_META_OPT_BUFFERED ) {
    memcpy( ctx->buf_packet[ ctx->buf_cnt ].data, packet, packet_sz );
    ctx->buf_packet[ ctx->buf_cnt ].data_sz = (ushort)packet_sz;
    ctx->buf_cnt++;
  }
  return (int)packet_sz;
}

static int
test_cb_snp_rx( void const *  _ctx,
                uchar const * packet,
                ulong         packet_sz,
                fd_snp_meta_t meta ) {
  test_cb_ctx_t * ctx = (test_cb_ctx_t *)_ctx;
  uchar buffered = (meta & FD_SNP_META_OPT_BUFFERED)==FD_SNP_META_OPT_BUFFERED;
  FD_TEST( buffered  == ctx->assert_buffered );
  FD_TEST( packet_sz == ctx->assert_packet_sz );
  FD_TEST( meta      == ctx->assert_meta );
  if( buffered ) {
    ctx->buf_cnt++;
    FD_TEST( fd_memeq( packet, ctx->assert_packet, packet_sz ) );
  } else {
    FD_TEST( packet  == ctx->assert_packet );
  }
  return 1;
}

static int
test_cb_snp_sign( void const *  _ctx,
                  ulong         session_id,
                  uchar const   to_sign[ FD_SNP_TO_SIGN_SZ ] ) {
  test_cb_ctx_t * ctx = (test_cb_ctx_t *)_ctx;
  fd_sha512_t sha512[1];
  fd_ed25519_sign( ctx->signature, to_sign, 32, ctx->public_key, ctx->private_key, sha512 );
  ctx->sign_cnt++;
  return fd_snp_process_signature( ctx->snp, session_id, ctx->signature );
}

int
test_cb_app_rx( void const *  _ctx,
                fd_snp_peer_t peer,
                uchar const * data,
                ulong         data_sz,
                fd_snp_meta_t meta ) {
  test_cb_ctx_t * ctx = (test_cb_ctx_t *)_ctx;
  FD_TEST( peer    == ctx->assert_peer );
  FD_TEST( data_sz == ctx->assert_data_sz );
  FD_TEST( meta    == ctx->assert_meta );
  if( ctx->assert_data ) FD_TEST( fd_memeq( data, ctx->assert_data, data_sz ) );
  return 1;
}

static void
test_snp_limits_private( fd_snp_t * server,
                         uint       server_ip4,
                         ushort     server_port,
                         fd_snp_t * client,
                         uint       client_ip4,
                         ushort     client_port,
                         int        should_pass_many_to_one,
                         int        should_pass_one_to_many ) {
  ulong proto = FD_SNP_META_PROTO_V1;

  /* Client */
  int client_sz = 0;
  fd_snp_meta_t client_meta = 0UL;
  int client_cb_res = 0;
  ulong client_msg_sz = 5UL;
  uchar * client_msg = (uchar *)"hello";

  test_cb_ctx_t * client_cb_test = client->cb.ctx;
  uchar * client_pkt = client_cb_test->out_packet;

  fd_snp_app_t client_app[1] = { 0 };
  client_app->cb.rx = test_cb_app_rx;
  client_app->cb.ctx = client_cb_test;

  client_cb_test->buf_cnt  = 0;
  client_cb_test->sign_cnt = 0;

  /* Server */
  int server_sz = 0UL;
  fd_snp_meta_t server_meta = 0UL;
  int server_cb_res = 0;
  ulong server_msg_sz = 6UL;
  uchar * server_msg = (uchar *)"world!";

  test_cb_ctx_t * server_cb_test = server->cb.ctx;
  uchar * server_pkt = server_cb_test->out_packet;

  fd_snp_app_t server_app[1] = { 0 };
  server_app->cb.rx = test_cb_app_rx;
  server_app->cb.ctx = server_cb_test;

  server_cb_test->buf_cnt  = 0;
  server_cb_test->sign_cnt = 0;

  /* Test protocol */

  /* Client sends */
  client_meta = fd_snp_meta_from_parts( proto, /* app_id */ 0, server_ip4, server_port );
  client_sz   = fd_snp_app_send( client_app, client_pkt, FD_SNP_MTU, client_msg, client_msg_sz, client_meta );
  FD_TEST( client_sz>0 );
  client_sz   = fd_snp_send( client, client_pkt, (ulong)client_sz, client_meta ); /* client_init */
  if( !should_pass_one_to_many ) {
    FD_TEST( client_sz==-1 );
    TEST_SNP_LIMITS_LOG( FD_LOG_WARNING(( "test stops earlier" )) );
    return;
  } else {
    FD_TEST( client_sz>0 );
  }

  /* Handshake - snp_app is not involved - don't really need to memcpy pkt all the times */
  server_sz = fd_snp_process_packet( server, client_pkt, (ulong)client_sz );    /* server_init */
  FD_TEST( server_sz>0 );
  client_sz = fd_snp_process_packet( client, client_pkt, (ulong)server_sz );    /* client_cont */
  FD_TEST( client_sz>0 );

  FD_TEST( server_cb_test->buf_cnt ==0 );
  FD_TEST( server_cb_test->sign_cnt==0 );
  server_sz = fd_snp_process_packet( server, client_pkt, (ulong)client_sz );    /* server_fini */
  if( !should_pass_many_to_one ) {
    FD_TEST( server_sz==-1 );
    FD_TEST( server_cb_test->buf_cnt ==0 );
    FD_TEST( server_cb_test->sign_cnt==0 );
    TEST_SNP_LIMITS_LOG( FD_LOG_WARNING(( "test stops earlier" )) );
    return;
  } else {
    FD_TEST( server_sz>0 );
    FD_TEST( server_cb_test->buf_cnt ==1 );
    FD_TEST( server_cb_test->sign_cnt==1 );
    FD_TEST( (ushort)server_sz==server_cb_test->buf_packet[0].data_sz );
  }

  /* send buffered packet (server_fini): server_cb_test->buf_packet[0].data */
  FD_TEST( client_cb_test->buf_cnt==0 );
  FD_TEST( client_cb_test->sign_cnt==0 );
  client_sz = fd_snp_process_packet( client, server_cb_test->buf_packet[0].data, (ulong)server_sz );    /* client_fini */
  if( !should_pass_many_to_one ) {
    FD_TEST( client_cb_test->buf_cnt ==0 );
    FD_TEST( client_cb_test->sign_cnt==0 );
    FD_TEST( client_sz>0 );
  } else {
    FD_TEST( client_cb_test->buf_cnt ==2 );
    FD_TEST( client_cb_test->sign_cnt==1 );
    FD_TEST( client_sz>0 );
    FD_TEST( (ushort)client_sz==client_cb_test->buf_packet[0].data_sz );
  }

  /* send buffered packet (client_fini): client_cb_test->buf_packet[0].data */
  server_sz = fd_snp_process_packet( server, client_cb_test->buf_packet[0].data, (ulong)client_sz );    /* server_acpt */
  if( !should_pass_many_to_one ) {
    FD_TEST( server_sz==-1 );
  } else {
    FD_TEST( server_sz==0 );
  }

  /* send buffered packet (client_app_payload): client_cb_test->buf_packet[1].data */
  server_sz = (int)client_cb_test->buf_packet[1].data_sz;
  memcpy( server_pkt, client_cb_test->buf_packet[1].data, (ulong)server_sz );

  /* Server receives */
  server_meta = fd_snp_meta_from_parts( proto, /* app_id */ 0, client_ip4, client_port );

  server_cb_test->assert_packet = server_pkt;
  server_cb_test->assert_packet_sz = (ulong)server_sz;
  server_cb_test->assert_meta = server_meta;
  TEST_SNP_LIMITS_LOG( FD_LOG_HEXDUMP_NOTICE(( "packet", server_cb_test->assert_packet, (ulong)server_cb_test->assert_packet_sz )) );
  server_cb_res = fd_snp_process_packet( server, server_pkt, (ulong)server_sz );
  TEST_SNP_LIMITS_LOG( FD_LOG_NOTICE(( "fd_snp_process_packet server_cb_res %d", server_cb_res )) );
  if( !should_pass_many_to_one ) {
    FD_TEST( server_cb_res==-1 );
  } else {
    FD_TEST( server_cb_res==1 );
  }

  server_cb_test->assert_peer = 0UL;
  server_cb_test->assert_data = client_msg;
  server_cb_test->assert_data_sz = client_msg_sz;
  server_cb_test->assert_meta = server_meta;
  server_cb_res = fd_snp_app_recv( server_app, server_cb_test->assert_packet, (ulong)server_cb_test->assert_packet_sz, server_meta );
  TEST_SNP_LIMITS_LOG( FD_LOG_NOTICE(( "fd_snp_app_recv server_cb_res %d", server_cb_res )) );
  FD_TEST( server_cb_res==1 );

  /* Server sends */
  server_sz = fd_snp_app_send( server_app, server_pkt, FD_SNP_MTU, server_msg, server_msg_sz, server_meta );
  if( !should_pass_many_to_one ) {
    FD_TEST( server_sz>0 );
  } else {
    FD_TEST( server_sz>=0 );
  }
  server_sz = fd_snp_send( server, server_pkt, (ulong)server_sz, server_meta );
    if( !should_pass_many_to_one ) {
    FD_TEST( server_sz==-1 );
  } else {
    FD_TEST( server_sz>0 );
  }

  /* Handshake NOT needed a second time */

  /* simulate network */ client_sz = server_sz; memcpy( client_pkt, server_pkt, (ulong)server_sz );
  TEST_SNP_LIMITS_LOG( FD_LOG_HEXDUMP_NOTICE(( "packet", client_pkt, (ulong)client_sz )) );

  /* Client receives */
  client_cb_test->assert_packet = client_pkt;
  client_cb_test->assert_packet_sz = (ulong)client_sz;
  client_cb_test->assert_meta = client_meta;
  client_cb_res = fd_snp_process_packet( client, client_pkt, (ulong)client_sz );
  TEST_SNP_LIMITS_LOG( FD_LOG_NOTICE(( "fd_snp_process_packet client_cb_res %d", client_cb_res )) );
  FD_TEST( client_cb_res==1 );

  client_cb_test->assert_peer = 0UL;
  client_cb_test->assert_data = server_msg;
  client_cb_test->assert_data_sz = server_msg_sz;
  client_cb_test->assert_meta = client_meta;
  client_cb_res = fd_snp_app_recv( client_app, client_pkt, (ulong)client_sz, client_meta );
  TEST_SNP_LIMITS_LOG( FD_LOG_NOTICE(( "fd_snp_app_recv client_cb_res %d", client_cb_res )) );
  FD_TEST( client_cb_res==1 );
}

static void
test_snp_limits_many_to_one( fd_wksp_t  * wksp,
                             fd_snp_limits_t * limits ) {

  FD_LOG_NOTICE(( "test_snp_limits_many_to_one" ));

  void * server_mem = fd_wksp_alloc_laddr( wksp, fd_snp_align(), fd_snp_footprint( limits ), 1 );
  fd_snp_t * server = fd_snp_join( fd_snp_new( server_mem, limits ) );

  void * client_mem[ ITERATIONS_N ];
  fd_snp_t * client[ ITERATIONS_N ];
  for( ulong i=0; i< ITERATIONS_N; i++ ) {
    client_mem[i] = fd_wksp_alloc_laddr( wksp, fd_snp_align(), fd_snp_footprint( limits ), 1+i );
    client[i]     = fd_snp_join( fd_snp_new( client_mem[ i ], limits ) );
  }

  /* Server */
  uint server_ip4 = 0x010000a4;
  ushort server_port = 8001;
  test_cb_ctx_t server_cb_test[1] = { 0 };
  uchar server_pkt[FD_SNP_MTU] = { 0 };

  server->cb.tx = test_cb_snp_tx;
  server->cb.rx = test_cb_snp_rx;
  server->cb.sign = test_cb_snp_sign;
  server->cb.ctx = server_cb_test;
  server_cb_test->out_packet = server_pkt;
  external_generate_keypair( server_cb_test->private_key, server_cb_test->public_key );
  memcpy( server->config.identity, server_cb_test->public_key, 32 );
  server_cb_test->snp = server;
  server_cb_test->ip  = server_ip4;
  server->apps_cnt = 1;
  server->apps[0].port = server_port;
  server->flow_cred_total = LONG_MAX;
  server->flow_cred_alloc = 32;
  FD_TEST( fd_snp_init( server ) );

  for( ulong i=0; i<ITERATIONS_N; i++ ) {

    /* Client */
    uint   client_ip4  = (uint)(0x010000a5 + (i << 24));
    ushort client_port = (ushort)(9001 + i);
    test_cb_ctx_t client_cb_test[1] = { 0 };
    uchar client_pkt[FD_SNP_MTU] = { 0 };

    client[i]->cb.rx = test_cb_snp_rx;
    client[i]->cb.tx = test_cb_snp_tx;
    client[i]->cb.sign = test_cb_snp_sign;
    client[i]->cb.ctx = client_cb_test;
    client_cb_test->out_packet = client_pkt;
    external_generate_keypair( client_cb_test->private_key, client_cb_test->public_key );
    memcpy( client[i]->config.identity, client_cb_test->public_key, 32 );
    client_cb_test->snp = client[i];
    client_cb_test->ip  = client_ip4;
    client[i]->apps_cnt = 1;
    client[i]->apps[0].port = client_port;
    client[i]->flow_cred_total = LONG_MAX;
    client[i]->flow_cred_alloc = 32;
    FD_TEST( fd_snp_init( client[i] ) );

    int should_pass = (i < limits->peer_cnt) ? 1 : 0;

    TEST_SNP_LIMITS_LOG( FD_LOG_NOTICE(( "................" )) );
    TEST_SNP_LIMITS_LOG( FD_LOG_NOTICE(( "[ A ] many_to_one %02lu should_pass %d", i, should_pass )) );
    test_snp_limits_private( server,    server_ip4, server_port,
                             client[i], client_ip4, client_port,
                             should_pass /*should_pass_many_to_one*/,
                             1           /*should_pass_one_to_many*/ );
    TEST_SNP_LIMITS_LOG( FD_LOG_NOTICE(( "fd_snp_connmap_key_cnt( server->conn_map ) %lu", fd_snp_conn_map_key_cnt( server->conn_map ) )) );
  }
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_snp_limits_one_to_many( fd_wksp_t  * wksp,
                             fd_snp_limits_t * limits ) {

  FD_LOG_NOTICE(( "test_snp_limits_one_to_many" ));

  void * client_mem = fd_wksp_alloc_laddr( wksp, fd_snp_align(), fd_snp_footprint( limits ), 1 );
  fd_snp_t * client = fd_snp_join( fd_snp_new( client_mem, limits ) );

  void * server_mem[ ITERATIONS_N ];
  fd_snp_t * server[ ITERATIONS_N ];
  for( ulong i=0; i< ITERATIONS_N; i++ ) {
    server_mem[i] = fd_wksp_alloc_laddr( wksp, fd_snp_align(), fd_snp_footprint( limits ), 1+i );
    server[i]     = fd_snp_join( fd_snp_new( server_mem[ i ], limits ) );
  }

  /* Client */
  uint   client_ip4  = 0x010000a4;
  ushort client_port = 8001;
  test_cb_ctx_t client_cb_test[1] = { 0 };
  uchar client_pkt[FD_SNP_MTU] = { 0 };

  client->cb.rx = test_cb_snp_rx;
  client->cb.tx = test_cb_snp_tx;
  client->cb.sign = test_cb_snp_sign;
  client->cb.ctx = client_cb_test;
  client_cb_test->out_packet = client_pkt;
  external_generate_keypair( client_cb_test->private_key, client_cb_test->public_key );
  memcpy( client->config.identity, client_cb_test->public_key, 32 );
  client_cb_test->snp = client;
  client_cb_test->ip  = client_ip4;
  client->apps_cnt = 1;
  client->apps[0].port = client_port;
  client->flow_cred_total = LONG_MAX;
  client->flow_cred_alloc = 32;
  FD_TEST( fd_snp_init( client ) );

  for( ulong i=0; i<ITERATIONS_N; i++ ) {

    /* Server */
    uint   server_ip4  = (uint)(0x010000a5 + (i << 24));
    ushort server_port = (ushort)(9001 + i);
    test_cb_ctx_t server_cb_test[1] = { 0 };
    uchar server_pkt[FD_SNP_MTU] = { 0 };

    server[i]->cb.tx = test_cb_snp_tx;
    server[i]->cb.rx = test_cb_snp_rx;
    server[i]->cb.sign = test_cb_snp_sign;
    server[i]->cb.ctx = server_cb_test;
    server_cb_test->out_packet = server_pkt;
    external_generate_keypair( server_cb_test->private_key, server_cb_test->public_key );
    memcpy( server[i]->config.identity, server_cb_test->public_key, 32 );
    server_cb_test->snp = server[i];
    server_cb_test->ip  = server_ip4;
    server[i]->apps_cnt = 1;
    server[i]->apps[0].port = server_port;
    server[i]->flow_cred_total = LONG_MAX;
    server[i]->flow_cred_alloc = 32;
    FD_TEST( fd_snp_init( server[i] ) );

    int should_pass = (i < limits->peer_cnt) ? 1 : 0;

    TEST_SNP_LIMITS_LOG( FD_LOG_NOTICE(( "................" )) );
    TEST_SNP_LIMITS_LOG( FD_LOG_NOTICE(( "[ B ] one_to_many %02lu should_pass %d", i, should_pass )) );
    test_snp_limits_private( server[i], server_ip4, server_port,
                             client,    client_ip4, client_port,
                             1           /*should_pass_many_to_one*/,
                             should_pass /*should_pass_one_to_many*/ );
    TEST_SNP_LIMITS_LOG( FD_LOG_NOTICE(( "fd_snp_connmap_key_cnt( client->conn_map ) %lu", fd_snp_conn_map_key_cnt( client->conn_map ) )) );
  }
  FD_LOG_NOTICE(( "... pass" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_wksp_t  * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( "huge" ), ITERATIONS_N/*page_cnt*/, fd_log_cpu_id() /*near_cpu*/, "wksp", 0UL );
  FD_TEST( wksp );

  fd_snp_limits_t limits = { .peer_cnt = ITERATIONS_N / 2 };

  test_snp_limits_many_to_one( wksp, &limits );

  test_snp_limits_one_to_many( wksp, &limits );

  FD_LOG_NOTICE(( "pass" ));
 fd_halt();
  return 0;
}
