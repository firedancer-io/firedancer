#include "fd_snp.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

// Global buffer for tx callback
static uchar g_tx_buffer[SNP_MTU];
static size_t g_tx_size = 0;
static char app_buf[] = "HelloWorld from SNPx";
static const ulong app_buf_sz = sizeof(app_buf)-1;
static uint CLIENT_IP = 12345;
static ushort CLIENT_PORT = 8000;
static uint SERVER_IP = 67890;
static ushort SERVER_PORT = 8001;

static uchar buf[4096*16];

// SNP now callback implementation
static ulong
snp_now(void *ctx) {
  (void)ctx;
  static ulong start = 0;
  return start++;
}

// RX callback for both client and server
static void
snp_rx_callback(fd_snp_t *snp, snp_net_ctx_t *sockAddr, uchar const *data, ulong data_sz) {
  (void)snp;
  (void)sockAddr;
  // FD_LOG_NOTICE(("Received %lu bytes from %u:%u\n", data_sz, sockAddr->parts.ip4, sockAddr->parts.port));
  FD_LOG_HEXDUMP_NOTICE(( "SNP rx", data, data_sz ));
  /* TODO - compare received data to app_buf */
}

// TX callback for both client and server
static void
snp_tx_callback(fd_snp_t *snp, snp_net_ctx_t *sockAddr, uchar const *data, ulong data_sz) {
  (void)snp;
  (void)sockAddr;
  memcpy(g_tx_buffer, data, data_sz);
  g_tx_size = data_sz;
  FD_LOG_NOTICE(("Sent %lu bytes to %u:%u\n", data_sz, sockAddr->parts.ip4, sockAddr->parts.port));
}

// Setup client SNP
static fd_snp_t*
setup_client_snp(void *mem, fd_snp_limits_t *limits) {
  fd_snp_t *client = fd_snp_new(mem, limits);
  if (!client) {
    FD_LOG_NOTICE(("Failed to create client SNP\n"));
    return NULL;
  }

  // Configure callbacks
  client->cb.rx = snp_rx_callback;
  client->cb.tx = snp_tx_callback;
  client->cb.now = snp_now;
  client->cb.now_ctx = NULL;
  client->cb.snp_ctx = NULL;

  /* TODO - handle IP/ports */

  return fd_snp_init( fd_snp_join( client ) );
}

// Setup server SNP
static fd_snp_t*
setup_server_snp(void *mem, fd_snp_limits_t *limits) {
  fd_snp_t *server = fd_snp_new(mem, limits);
  if (!server) {
    FD_LOG_NOTICE(("Failed to create server SNP\n"));
    return NULL;
  }

  // Configure callbacks
  server->cb.rx = snp_rx_callback;
  server->cb.tx = snp_tx_callback;
  server->cb.now = snp_now;
  server->cb.now_ctx = NULL;
  server->cb.snp_ctx = NULL;

  // // Initialize server parameters
  // for (uint i = 0; i < SNP_ED25519_KEY_SZ; ++i) {
  //   server->server_params.identity[i] = (uchar)(i & 0xff);
  // }
  // server->server_params.cookie_secret[15] = 0x02;
  // server->server_params.token[15] = 0x03;

  /* TODO - handle IP/ports */

  return fd_snp_init( fd_snp_join( server ) );
}

// Function to create and initialize both client and server
static void
setup_snp_client_server(fd_snp_t **client_out, fd_snp_t **server_out) {
  fd_snp_limits_t limits = {
    .conn_cnt = 16  // Allow up to 16 concurrent connections
  };

  // Calculate memory requirements
  ulong footprint = fd_snp_footprint(&limits);
  ulong align = fd_snp_align();


  void* client_mem = (void*)fd_ulong_align_up((ulong)buf, align);
  void* server_mem = (void*)fd_ulong_align_up((ulong)buf + footprint, align);

  assert(client_mem && server_mem);

  // Setup client and server
  *client_out = setup_client_snp(client_mem, &limits);
  *server_out = setup_server_snp(server_mem, &limits);

  if (!*client_out || !*server_out) {
    FD_LOG_NOTICE(("Failed to initialize SNP instances\n"));
    *client_out = NULL;
    *server_out = NULL;
  }
}

int
main( int     argc,
      char ** argv ) {
  (void)argc;
  (void)argv;

  fd_snp_t *client, *server;
  setup_snp_client_server(&client, &server);
  FD_LOG_NOTICE(("Client: Server:"));

  /* send from client to server */
  snp_net_ctx_t mock_dst[1];
  mock_dst->parts.ip4 = SERVER_IP;
  mock_dst->parts.port = SERVER_PORT;
  FD_LOG_NOTICE(( "client hello" ));
  fd_snp_send(client, mock_dst, app_buf, app_buf_sz);

  /* process packet on each of them */
  // server receive
  FD_LOG_NOTICE(( "server hello" ));
  fd_snp_process_packet(server, g_tx_buffer, g_tx_size, CLIENT_IP, CLIENT_PORT);

  // client receive
  FD_LOG_NOTICE(( "client continue" ));
  fd_snp_process_packet(client, g_tx_buffer, g_tx_size, SERVER_IP, SERVER_PORT);

  // server receive
  FD_LOG_NOTICE(( "server continue" ));
  fd_snp_process_packet(server, g_tx_buffer, g_tx_size, CLIENT_IP, CLIENT_PORT);

  // client receive
  FD_LOG_NOTICE(( "client accept" ));
  fd_snp_process_packet(client, g_tx_buffer, g_tx_size, SERVER_IP, SERVER_PORT);

  // server receive application data
  FD_LOG_NOTICE(( "server accept" ));
  fd_snp_process_packet(server, g_tx_buffer, g_tx_size, CLIENT_IP, CLIENT_PORT);

  FD_LOG_NOTICE(( "client-server" ));
  for(int i=0; i<10; ++i) {
    app_buf[app_buf_sz-1] = (char)('0' + i);
    fd_snp_send(client, mock_dst, app_buf, app_buf_sz);
    fd_snp_process_packet(server, g_tx_buffer, g_tx_size, CLIENT_IP, CLIENT_PORT);
  }

  return 0;
}
