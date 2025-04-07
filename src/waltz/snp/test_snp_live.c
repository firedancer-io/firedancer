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

#include "fd_snp.h"

#define BUFFER_SIZE 2048

struct pollfd fds[2];

static int sock_fd = -1;
static struct sockaddr_in server_addr;
static int running = 1;
static int is_server = 0;

// Forward declarations
static void cleanup(void);
static void tx_callback(fd_snp_t* snp, snp_net_ctx_t* dst, const uchar* data, ulong data_sz);
static void rx_callback(fd_snp_t* snp, snp_net_ctx_t* src, const uchar* data, ulong data_sz);

// Create UDP socket and bind if server
static int create_udp_socket(const char* ip, ushort port) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    perror("socket creation failed");
    return -1;
  }

  // Set socket to non-blocking
  int flags = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;

  if (is_server) {
    // Server binds to specified port and address
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
  } else {
    // Client binds to any address and lets kernel assign port
    addr.sin_port = 0;  // Let kernel assign ephemeral port
    addr.sin_addr.s_addr = INADDR_ANY;
  }

  if (bind(fd, (void*)&addr, sizeof(addr)) < 0) {
    perror("bind failed");
    close(fd);
    return -1;
  }

  if (is_server) {
    printf("Server listening on %s:%d\n", ip, port);
  } else {
    // Get the assigned port number
    socklen_t len = sizeof(addr);
    if (getsockname(fd, (void*)&addr, &len) < 0) {
      perror("getsockname failed");
      close(fd);
      return -1;
    }
    printf("Client bound to port %d\n", ntohs(addr.sin_port));
  }

  return fd;
}

// Clean up resources
static void cleanup(void) {
  if (sock_fd >= 0) {
    close(sock_fd);
    sock_fd = -1;
  }
}

// TX callback for SNP - sends UDP packet
static void tx_callback(fd_snp_t* snp, snp_net_ctx_t* dst, const uchar* data, ulong data_sz) {
  (void)snp;

  struct sockaddr_in dest_addr;
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(dst->parts.port);
  dest_addr.sin_addr.s_addr = dst->parts.ip4;

  ssize_t sent = sendto(sock_fd, data, data_sz, 0,
                  (void*)&dest_addr, sizeof(dest_addr));

  if (sent < 0) {
    perror("sendto failed");
  }
}

// RX callback for SNP - processes received data
static void rx_callback(fd_snp_t* snp, snp_net_ctx_t* src, const uchar* data, ulong data_sz) {
  (void)snp; // Unused parameter

  char ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(src->parts.ip4), ip_str, INET_ADDRSTRLEN);

  printf("Received %lu bytes from %s:%d\n", data_sz, ip_str, src->parts.port);
  printf("Data: ");

  // Print the data as a string if it's printable, otherwise as hex
  int printable = 1;
  for (ulong i = 0; i < data_sz; i++) {
    if (data[i] < 32 || data[i] > 126) {
      printable = 0;
      break;
    }
  }

  if (printable) {
    printf("%.*s\n", (int)data_sz, (char*)data);
  } else {
    for (ulong i = 0; i < data_sz; i++) {
      printf("%02x ", data[i]);
    }
    printf("\n");
  }
}

int main(int argc, char *argv[]) {
  if (argc != 4) {
    fprintf(stderr, "Usage: %s <server|client> <ip> <port>\n", argv[0]);
    return 1;
  }

  // Parse command line arguments
  is_server = (strcmp(argv[1], "server") == 0);
  const char* ip = argv[2];
  ushort port = (ushort)atoi(argv[3]);

  // Create UDP socket
  sock_fd = create_udp_socket(ip, port);
  if (sock_fd < 0) {
    return 1;
  }

  if (!is_server) {
    // Set up server address for client mode
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
      perror("Invalid address");
      cleanup();
      return 1;
    }
  }

  // Initialize SNP
  fd_snp_limits_t limits = {
    .conn_cnt = 16
  };

  // Allocate memory for SNP
  uchar buf[1<<15];
  void* snp_mem = (void*)fd_ulong_align_up((ulong)buf, fd_snp_align());
  if (!snp_mem) {
      perror("Failed to allocate memory for SNP");
      cleanup();
      return 1;
  }

  // Create and initialize SNP
  fd_snp_t* snp = fd_snp_new(snp_mem, &limits);
  if (!snp) {
      fprintf(stderr, "Failed to initialize SNP\n");
      cleanup();
      return 1;
  }

  // Set up callbacks
  snp->cb.tx = tx_callback;
  snp->cb.rx = rx_callback;

  if (is_server) {
    // Initialize server parameters
    fd_snp_s0_server_params_t server_params;
    memset(&server_params, 0, sizeof(server_params));
    snp->server_params = server_params;
  } else {
    // Initialize client parameters
    fd_snp_s0_client_params_t client_params;
    memset(&client_params, 0, sizeof(client_params));
    snp->client_params = client_params;

    printf("SNP client initialized. Connecting to %s:%d\n", ip, port);
  }

  // Create network context for the server (used in client mode)
  snp_net_ctx_t server_ctx;
  if (!is_server) {
    server_ctx.parts.ip4 = server_addr.sin_addr.s_addr;
    server_ctx.parts.port = port;
  }

  /* setup poll fds */
  fds[0].fd = STDIN_FILENO;
  fds[0].events = POLLIN;
  fds[1].fd = sock_fd;
  fds[1].events = POLLIN;

  // Main loop
  uchar recv_buffer[BUFFER_SIZE];

  while (running) {
    int ret = poll(fds, 2, 1000);
    if (ret == -1) {
      perror("poll");
      break;
    }

    // Check for network data
    if (fds[1].revents & POLLIN) {
      struct sockaddr_in src_addr;
      socklen_t src_len = sizeof(src_addr);
      long recv_len = recvfrom(sock_fd, recv_buffer, BUFFER_SIZE, 0,
                              (void*)&src_addr, &src_len);
      if (recv_len > 0) {
        // Process the packet with SNP
        fd_snp_process_packet(snp, recv_buffer, (ulong)recv_len,
                            src_addr.sin_addr.s_addr, ntohs(src_addr.sin_port));
      }
    }

    // Check for user input (client mode only sends on input)
    if (fds[0].revents & POLLIN) {
      char c;
      if (scanf(" %c", &c) != 1) {
        printf("Error reading input\n");
        break;
      }
      while (getchar() != '\n');  // Clear input buffer

      if (c == 'q') break;

      if (!is_server) {
        char msg[16];
        snprintf(msg, sizeof(msg), "FD_SNP_%c", c);
        FD_LOG_NOTICE(("Sending message: %s\n", msg));
        fd_snp_send(snp, &server_ctx, msg, strlen(msg));
      }
    }
  }

  // Clean up
  cleanup();

  return 0;
}
