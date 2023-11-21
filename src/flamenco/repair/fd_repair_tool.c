/**

   export RUST_LOG=solana_gossip=TRACE
   cargo run --bin solana-test-validator

 **/

#define _GNU_SOURCE         /* See feature_test_macros(7) */

#include "../gossip/fd_gossip.h"
#include "../fd_flamenco.h"
#include "../../util/fd_util.h"
#include "../../ballet/base58/fd_base58.h"
#include "../types/fd_types_yaml.h"
#include "../../util/net/fd_eth.h"
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/random.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>

// SIGINT signal handler
volatile int stopflag = 0;
static void stop(int sig) { (void)sig; stopflag = 1; }

static int sockfd = -1;
static fd_pubkey_t public_key;
static uchar private_key[32];

/* Convert my style of address to UNIX style */
static int
gossip_to_sockaddr( uchar * dst, fd_gossip_peer_addr_t const * src ) {
  fd_memset(dst, 0, sizeof(struct sockaddr_in));
  struct sockaddr_in * t = (struct sockaddr_in *)dst;
  t->sin_family = AF_INET;
  t->sin_addr.s_addr = src->addr;
  t->sin_port = src->port;
  return sizeof(struct sockaddr_in);
}

/* Convert my style of address from UNIX style */
static int
gossip_from_sockaddr( fd_gossip_peer_addr_t * dst, uchar const * src ) {
  FD_STATIC_ASSERT(sizeof(fd_gossip_peer_addr_t) == sizeof(ulong),"messed up size");
  dst->l = 0;
  const struct sockaddr_in * sa = (const struct sockaddr_in *)src;
  dst->addr = sa->sin_addr.s_addr;
  dst->port = sa->sin_port;
  return 0;
}

static void
send_packet( uchar const * data, size_t sz, fd_gossip_peer_addr_t const * addr ) {
  uchar saddr[sizeof(struct sockaddr_in)];
  int saddrlen = gossip_to_sockaddr(saddr, addr);
  if ( sendto(sockfd, data, sz, MSG_DONTWAIT,
              (const struct sockaddr *)saddr, (socklen_t)saddrlen) < 0 ) {
    FD_LOG_WARNING(("sendto failed: %s", strerror(errno)));
  }
}

/* Convert a host:port string to a gossip network address. If host is
 * missing, it assumes the local hostname. */
static fd_gossip_peer_addr_t *
resolve_hostport(const char* str /* host:port */, fd_gossip_peer_addr_t * res) {
  fd_memset(res, 0, sizeof(fd_gossip_peer_addr_t));

  /* Find the : and copy out the host */
  char buf[128];
  uint i;
  for (i = 0; ; ++i) {
    if (str[i] == '\0' || i > sizeof(buf)-1U) {
      FD_LOG_ERR(("missing colon"));
      return NULL;
    }
    if (str[i] == ':') {
      buf[i] = '\0';
      break;
    }
    buf[i] = str[i];
  }
  if (i == 0)
    /* :port means $HOST:port */
    gethostname(buf, sizeof(buf));

  struct hostent * host = gethostbyname( buf );
  if (host == NULL) {
    FD_LOG_WARNING(("unable to resolve host %s", buf));
    return NULL;
  }
  /* Convert result to gossip address */
  res->l = 0;
  res->addr = ((struct in_addr *)host->h_addr)->s_addr;
  int port = atoi(str + i + 1);
  if (port < 1024 || port > (int)USHORT_MAX) {
    FD_LOG_ERR(("invalid port number"));
    return NULL;
  }
  res->port = htons((ushort)port);

  return res;
}

static void
fd_repair_sign_and_send(fd_repair_protocol_t * protocol) {
  fd_bincode_encode_ctx_t ctx;
  uchar buf[1024];
  ctx.data = buf;
  ctx.dataend = buf + sizeof(buf);
  FD_TEST(0 == fd_repair_protocol_encode(protocol, &ctx));

  // https://github.com/solana-labs/solana/blob/master/core/src/repair/serve_repair.rs#L874
  ulong buflen = (ulong)((uchar*)ctx.data - buf);
  fd_memcpy(buf + 64U, buf, 4U);
  fd_sha512_t sha[1];
  fd_signature_t sig;
  fd_ed25519_sign( /* sig */ &sig,
                   /* msg */ buf + 64U,
                   /* sz  */ buflen - 64U,
                   /* public_key  */ public_key.uc,
                   /* private_key */ private_key,
                   sha );
  fd_memcpy(buf + 4U, &sig, 64U);
  
  fd_gossip_peer_addr_t peer_addr;
  resolve_hostport("127.0.0.1:1032", &peer_addr);
  send_packet(buf, buflen, &peer_addr);
}

static void
test_send() {
  fd_repair_protocol_t protocol;
  fd_repair_protocol_new_disc(&protocol, fd_repair_protocol_enum_window_index);
  fd_repair_window_index_t * wi = &protocol.inner.window_index;
  fd_memcpy(wi->header.sender.uc, public_key.uc, 32U);
  fd_base58_decode_32("95hduWHW6BDrnVWzB2ekF9vmiFxpz62F1HNtRAQ19S71", wi->header.recipient.uc);
  wi->header.timestamp = (ulong)fd_log_wallclock()/1000000LU;
  wi->slot = 1;
  wi->shred_index = 0;
  fd_repair_sign_and_send(&protocol);
}

static int
main_loop(fd_gossip_peer_addr_t const * my_addr, volatile int * stopflag ) {
  int fd;
  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    FD_LOG_ERR(("socket failed: %s", strerror(errno)));
    return -1;
  }
  sockfd = fd;
  int optval = 1<<20;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&optval, sizeof(int)) < 0) {
    FD_LOG_ERR(("setsocketopt failed: %s", strerror(errno)));
    return -1;
  }
  if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *)&optval, sizeof(int)) < 0) {
    FD_LOG_ERR(("setsocketopt failed: %s", strerror(errno)));
    return -1;
  }
  uchar saddr[sizeof(struct sockaddr_in6)];
  int saddrlen = gossip_to_sockaddr(saddr, my_addr);
  if (saddrlen < 0 || bind(fd, (struct sockaddr*)saddr, (uint)saddrlen) < 0) {
    FD_LOG_ERR(("bind failed: %s", strerror(errno)));
    return -1;
  }
  
#define VLEN 32U
  struct mmsghdr msgs[VLEN];
  struct iovec iovecs[VLEN];
  uchar bufs[VLEN][FD_ETH_PAYLOAD_MAX];
  uchar sockaddrs[VLEN][sizeof(struct sockaddr_in6)]; /* sockaddr is smaller than sockaddr_in6 */

  int need_test = 1;
  
  while ( !*stopflag ) {
    if (need_test) {
      test_send();
      need_test = 0;
    }
    
    fd_memset(msgs, 0, sizeof(msgs));
    for (uint i = 0; i < VLEN; i++) {
      iovecs[i].iov_base          = bufs[i];
      iovecs[i].iov_len           = FD_ETH_PAYLOAD_MAX;
      msgs[i].msg_hdr.msg_iov     = &iovecs[i];
      msgs[i].msg_hdr.msg_iovlen  = 1;
      msgs[i].msg_hdr.msg_name    = sockaddrs[i];
      msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in6);
    }

    /* Read more packets */
    int retval = recvmmsg(fd, msgs, VLEN, MSG_DONTWAIT, NULL);
    if (retval < 0) {
      if (errno == EINTR || errno == EWOULDBLOCK)
        continue;
      FD_LOG_ERR(("recvmmsg failed: %s", strerror(errno)));
      return -1;
    }
    if (retval == 0)
      continue;

    for (uint i = 0; i < (uint)retval; ++i) {
      fd_gossip_peer_addr_t from;
      gossip_from_sockaddr( &from, msgs[i].msg_hdr.msg_name );
      (void)from;
    }
  }

  close(fd);
  return 0;
}

int main(int argc, char **argv) {
  fd_boot         ( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  FD_TEST( 32UL==getrandom( private_key, 32UL, 0 ) );
  fd_sha512_t sha[1];
  FD_TEST( fd_ed25519_public_from_private( public_key.uc, private_key, sha ) );

  signal(SIGINT, stop);
  signal(SIGPIPE, SIG_IGN);

  fd_gossip_peer_addr_t my_addr;
  resolve_hostport(":1185", &my_addr);
  
  if ( main_loop(&my_addr, &stopflag) )
    return 1;

  fd_halt();

  return 0;
}
