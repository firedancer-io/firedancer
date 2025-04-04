#include "../fd_stl.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

// Global buffer for tx callback
static uchar g_tx_buffer[STL_MTU];
static size_t g_tx_size = 0;
static char app_buf[] = "HelloWorld from STL0";
static const ulong app_buf_sz = sizeof(app_buf)-1;
static uint CLIENT_IP = 12345;
static ushort CLIENT_PORT = 8000;
static uint SERVER_IP = 67890;
static ushort SERVER_PORT = 8001;

static uchar buf[4096*16];

// STL now callback implementation
static ulong
stl_now(void *ctx) {
  (void)ctx;
  static ulong start = 0;
  return start++;
}

// RX callback for both client and server
static void
stl_rx_callback(fd_stl_t *stl, stl_net_ctx_t *sockAddr, uchar const *data, ulong data_sz) {
  (void)stl;
  (void)sockAddr;
  // FD_LOG_NOTICE(("Received %lu bytes from %u:%u\n", data_sz, sockAddr->parts.ip4, sockAddr->parts.port));
  FD_LOG_HEXDUMP_NOTICE(( "STL rx", data, data_sz ));
  /* TODO - compare received data to app_buf */
}

// TX callback for both client and server
static void
stl_tx_callback(fd_stl_t *stl, stl_net_ctx_t *sockAddr, uchar const *data, ulong data_sz) {
  (void)stl;
  (void)sockAddr;
  memcpy(g_tx_buffer, data, data_sz);
  g_tx_size = data_sz;
  // FD_LOG_NOTICE(("Sent %lu bytes to %u:%u\n", data_sz, sockAddr->parts.ip4, sockAddr->parts.port));
}

// Setup client STL
static fd_stl_t*
setup_client_stl(void *mem, fd_stl_limits_t *limits) {
  fd_stl_t *client = fd_stl_new(mem, limits);
  if (!client) {
    FD_LOG_NOTICE(("Failed to create client STL\n"));
    return NULL;
  }

  // Configure callbacks
  client->cb.rx = stl_rx_callback;
  client->cb.tx = stl_tx_callback;
  client->cb.now = stl_now;
  client->cb.now_ctx = NULL;
  client->cb.stl_ctx = NULL;

  /* TODO - handle IP/ports */

  return fd_stl_init( fd_stl_join( client ) );
}

// Setup server STL
static fd_stl_t*
setup_server_stl(void *mem, fd_stl_limits_t *limits) {
  fd_stl_t *server = fd_stl_new(mem, limits);
  if (!server) {
    FD_LOG_NOTICE(("Failed to create server STL\n"));
    return NULL;
  }

  // Configure callbacks
  server->cb.rx = stl_rx_callback;
  server->cb.tx = stl_tx_callback;
  server->cb.now = stl_now;
  server->cb.now_ctx = NULL;
  server->cb.stl_ctx = NULL;

  // // Initialize server parameters
  // for (uint i = 0; i < STL_ED25519_KEY_SZ; ++i) {
  //   server->server_params.identity[i] = (uchar)(i & 0xff);
  // }
  // server->server_params.cookie_secret[15] = 0x02;
  // server->server_params.token[15] = 0x03;

  /* TODO - handle IP/ports */

  return fd_stl_init( fd_stl_join( server ) );
}

// Function to create and initialize both client and server
static void
setup_stl_client_server(fd_stl_t **client_out, fd_stl_t **server_out) {
  fd_stl_limits_t limits = {
    .conn_cnt = 16  // Allow up to 16 concurrent connections
  };

  // Calculate memory requirements
  ulong footprint = fd_stl_footprint(&limits);
  ulong align = fd_stl_align();


  void* client_mem = (void*)fd_ulong_align_up((ulong)buf, align);
  void* server_mem = (void*)fd_ulong_align_up((ulong)buf + footprint, align);

  assert(client_mem && server_mem);

  // Setup client and server
  *client_out = setup_client_stl(client_mem, &limits);
  *server_out = setup_server_stl(server_mem, &limits);

  if (!*client_out || !*server_out) {
    FD_LOG_NOTICE(("Failed to initialize STL instances\n"));
    *client_out = NULL;
    *server_out = NULL;
  }
}

int
main( int     argc,
      char ** argv ) {
  (void)argc;
  (void)argv;

  fd_stl_t *client, *server;
  setup_stl_client_server(&client, &server);
  FD_LOG_NOTICE(("Client: Server:"));


  FD_LOG_HEXDUMP_NOTICE(("Initial application msg", app_buf, app_buf_sz));

  /* send from client to server */
  stl_net_ctx_t mock_dst[1];
  mock_dst->parts.ip4 = SERVER_IP;
  mock_dst->parts.port = SERVER_PORT;
  fd_stl_send(client, mock_dst, app_buf, app_buf_sz);

  /* process packet on each of them */
  // server receive
  fd_stl_process_packet(server, g_tx_buffer, g_tx_size, CLIENT_IP, CLIENT_PORT);

  // client receive
  fd_stl_process_packet(client, g_tx_buffer, g_tx_size, SERVER_IP, SERVER_PORT);

  // server receive
  fd_stl_process_packet(server, g_tx_buffer, g_tx_size, CLIENT_IP, CLIENT_PORT);

  // client receive
  fd_stl_process_packet(client, g_tx_buffer, g_tx_size, SERVER_IP, SERVER_PORT);

  // server receive application data
  fd_stl_process_packet(server, g_tx_buffer, g_tx_size, CLIENT_IP, CLIENT_PORT);

  for(int i=1; i<10; ++i) {
    app_buf[app_buf_sz-1] = (char)('0' + i);
    fd_stl_send(client, mock_dst, app_buf, app_buf_sz);
    fd_stl_process_packet(server, g_tx_buffer, g_tx_size, CLIENT_IP, CLIENT_PORT);
  }

  return 0;
}
