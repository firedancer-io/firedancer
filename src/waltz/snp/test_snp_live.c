#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include "fd_snp_app.h"
#include "fd_snp.h"
#include "../../ballet/ed25519/fd_ed25519.h"

#define BUFFER_SIZE 2048

static void
external_generate_keypair( uchar private_key[32], uchar public_key[32] ) {
  fd_sha512_t sha512[1];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha512 ) ) );
  FD_TEST( fd_rng_secure( private_key, 32 )!=NULL );
  fd_ed25519_public_from_private( public_key, private_key, sha512 );
}

// Create UDP socket and bind if server
int create_udp_socket( uint ip, ushort port ) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    perror("error: socket create failed");
    return -1;
  }

  // Set socket to non-blocking
  int flags = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);

  struct sockaddr_in addr = { 0 };
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = ip;

  if( bind( fd, (void*)&addr, sizeof(addr) )<0 ) {
    perror("error: socket bind failed");
    close(fd);
    return -1;
  }

  return fd;
}

// Clean up resources
static void cleanup( int sock_fd ) {
  printf("Cleanup done\n");
  if (sock_fd >= 0) {
    close(sock_fd);
    sock_fd = -1;
  }
}

/* Callbacks */
struct test_cb_ctx {
  fd_snp_app_t * snp_app;
  fd_snp_t *     snp;
  ulong          ack;
  int            sock_fd;
  uint           ip;
  ushort         sport;
  uchar          done;
  uchar          private_key[ 32 ];
  uchar          packet[ BUFFER_SIZE ];
};
typedef struct test_cb_ctx test_cb_ctx_t;

static int
test_cb_snp_tx( void const *  _ctx,
                uchar const * packet,
                ulong         packet_sz,
                fd_snp_meta_t meta ) {
  test_cb_ctx_t * ctx = (test_cb_ctx_t *)_ctx;

  uint ip;
  ushort port;
  fd_snp_meta_into_parts( NULL, NULL, &ip, &port, meta );

  if( meta & FD_SNP_META_OPT_HANDSHAKE ) {
    FD_LOG_NOTICE(( "sending handshake %x dport=%hx session_id=%016lx...", packet[45], port, *((ulong *)(packet+46)) ));
  }

  struct sockaddr_in dest_addr;
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(port);
  dest_addr.sin_addr.s_addr = ip;

  *((uint *)(packet + 14 + 12)) = ip;
  // FD_LOG_NOTICE(( " >> test_cb_snp_tx: sendto %016lx", meta ));
  ssize_t sent = sendto( ctx->sock_fd, packet, packet_sz, 0, (void*)&dest_addr, sizeof(dest_addr) );
  if (sent < 0) {
    FD_LOG_WARNING(( "sendto failed: %x dport=%hx session_id=%016lx", packet[45], port, *((ulong *)(packet+46)) ));
  }

  return (int)packet_sz;
}

static int
test_cb_snp_rx( void const *  _ctx,
                uchar const * packet,
                ulong         packet_sz,
                fd_snp_meta_t meta ) {
  test_cb_ctx_t * ctx = (test_cb_ctx_t *)_ctx;
  // FD_LOG_NOTICE(( " >> test_cb_snp_rx: fd_snp_app_recv" ));
  return fd_snp_app_recv( ctx->snp_app, packet, packet_sz, meta );
}

static int
test_cb_snp_sign( void const *  _ctx,
                  ulong         session_id,
                  uchar const   to_sign[ FD_SNP_TO_SIGN_SZ ] ) {
  test_cb_ctx_t * ctx = (test_cb_ctx_t *)_ctx;
  fd_sha512_t sha512[1];
  uchar signature[ 64 ];
  fd_ed25519_sign( signature, to_sign, 32, ctx->snp->config.identity, ctx->private_key, sha512 );
  FD_LOG_NOTICE(( "test_cb_snp_sign" ));
  return fd_snp_process_signature( ctx->snp, session_id, signature );
}

int
test_cb_app_tx( void const *  _ctx,
                uchar *       packet,
                ulong         packet_sz,
                fd_snp_meta_t meta ) {
  test_cb_ctx_t * ctx = (test_cb_ctx_t *)_ctx;
  // FD_LOG_NOTICE(( " >> test_cb_app_tx: fd_snp_send" ));
  printf("Sending to %016lx...\n", meta);
  return fd_snp_send( ctx->snp, packet, packet_sz, meta );
}

int
test_cb_app_rx( void const *  _ctx,
                fd_snp_peer_t peer,
                uchar const * data,
                ulong         data_sz,
                fd_snp_meta_t meta ) {
  (void)peer;
  test_cb_ctx_t * ctx = (test_cb_ctx_t *)_ctx;
  printf("Received from %016lx: %s\n", meta, data);
  if( strncmp( (char *)data, "ACK", fd_min( data_sz, 4 ) )==0 ) {
    // ctx->done = 1;
  } else {
    (void)ctx;
    // ctx->ack = meta | ctx->ip;
    // fd_snp_app_send( ctx->snp_app, ctx->packet, sizeof(ctx->packet), "ACK", 4, meta | ctx->ip );
  }
  return (int)data_sz;
}


int main(int argc, char *argv[]) {
  fd_boot( &argc, &argv );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 1UL << 15, fd_shmem_cpu_idx( 0 ), "wksp", 0UL );
  FD_TEST( wksp );

  /* Parse command line arguments */
  if( argc < 2 ) {
    fprintf(stderr, "Usage: %s <listen-port> [<connect-port>...]\n", argv[0]);
    return 1;
  }
  const char * ip_str = "127.0.0.1";
  uint ip = inet_addr(ip_str);
  ushort port = (ushort)atoi(argv[1]);

  /* Setup SNP */
  fd_snp_limits_t limits = {
    .conn_cnt = 256,
  };
  void * _snp = fd_wksp_alloc_laddr( wksp, fd_snp_align(), fd_snp_footprint( &limits ), 1UL );
  fd_snp_t * snp = fd_snp_join( fd_snp_new( _snp, &limits ) );
  fd_snp_app_t snp_app[1] = { 0 };
  test_cb_ctx_t ctx[1] = { 0 };

  snp->apps_cnt = 1;
  snp->apps[0].port = port;
  FD_TEST( fd_snp_init( snp ) );
  external_generate_keypair( ctx->private_key, snp->config.identity );

  snp_app->cb.ctx = ctx;
  snp_app->cb.rx = test_cb_app_rx;
  snp_app->cb.tx = test_cb_app_tx;

  snp->cb.ctx = ctx;
  snp->cb.rx = test_cb_snp_rx;
  snp->cb.tx = test_cb_snp_tx;
  snp->cb.sign = test_cb_snp_sign;

  snp->flow_cred_total = 16384L; /* Arbitrary for this test - typically dcache's depth. */
  // snp->flow_cred_taken = 0L;  /* Initialized inside fd_snp_init( snp ). */
  snp->flow_cred_alloc = 4 * FD_SNP_MTU; /* Arbitrary for this test */

  /* Create UDP socket */
  int sock_fd = create_udp_socket(ip, port);
  if (sock_fd < 0) {
    return 1;
  }
  ctx->snp = snp;
  ctx->snp_app = snp_app;
  ctx->sock_fd = sock_fd;
  ctx->ip = ip;
  printf("Listening on %s:%d...\n", ip_str, port);

  /* Setup poll fds */
  struct pollfd fds[2];
  fds[0].fd = STDIN_FILENO;
  fds[0].events = POLLIN;
  fds[1].fd = sock_fd;
  fds[1].events = POLLIN;

  /* Main loop */
  uchar packet[BUFFER_SIZE];
  uchar recv_buffer[BUFFER_SIZE];
  int running = 1;
  int housekeep = 0;
  int j = 0;
  while (running) {
    int ret = poll(fds, 2, 300);
    if (ret == -1) {
      perror("poll");
      break;
    }

    // Check for network data
    if (fds[1].revents & POLLIN) {
      struct sockaddr_in src_addr;
      socklen_t src_len = sizeof(src_addr);
      long recv_len = recvfrom(sock_fd, recv_buffer, BUFFER_SIZE, 0, (void*)&src_addr, &src_len);
      if (recv_len > 46) {
        /* drop 30% packets */
        if( (double)rand() / (double)RAND_MAX > -0.1 || recv_buffer[45]==0x1F ) {
          FD_LOG_NOTICE(( "received packet %x dport=%hx session_id=%016lx...", recv_buffer[45], src_addr.sin_port, *((ulong *)(recv_buffer+46)) ));
          fd_snp_process_packet( snp, recv_buffer, (ulong)recv_len );
        } else {
          FD_LOG_NOTICE(( "dropped packet %x dport=%hx session_id=%016lx...", recv_buffer[45], src_addr.sin_port, *((ulong *)(recv_buffer+46)) ));
        }
      }
    }

    // Check for user input (client mode only sends on input)
    if (fds[0].revents & POLLIN) {
      char c;
      if (scanf("%c", &c) != 1) {
        printf("Error reading input\n");
        break;
      }
      while (getchar() != '\n');  // Clear input buffer

      if (c == 'q') {
        FD_LOG_NOTICE(( "cmd 'q'" ));
        running=0;
      }

      if (c == 's') {
        FD_LOG_NOTICE(( "cmd 's'" ));
        ctx->done = 1;
      }

      if (c == 'h') {
        FD_LOG_NOTICE(( "cmd 'h'" ));
        housekeep=1;
      }
    }

    if( ctx->done==1 ) {
      ctx->done = 0;
      for( int j=2; j<argc; j++ ) {
        ushort dport = (ushort)atoi(argv[j]);
        fd_snp_meta_t meta = fd_snp_meta_from_parts( FD_SNP_META_PROTO_V1, 0, ip, dport );
        fd_snp_app_send( snp_app, packet, sizeof(packet), "hack the planet", 16, meta );
      }
    }

    if( ctx->ack ) {
      fd_snp_app_send( ctx->snp_app, packet, sizeof(packet), "ACK", 4, ctx->ack );
      ctx->ack = 0;
    }

    if( ( (++j % 1) == 0 ) || ( housekeep != 0 ) ) {
      housekeep=0;
      fd_snp_housekeeping( snp );
    }
  }

  cleanup( sock_fd );
  fd_wksp_delete_anonymous( wksp );
  return 0;
}
