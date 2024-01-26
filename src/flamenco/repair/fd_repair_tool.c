/**

   export RUST_LOG=solana_repair=TRACE
   cargo run --bin solana-test-validator

   build/native/gcc/bin/fd_repair_tool --peer_id 75dLVGm338wpo2SsfM7pWestidAjJL1Y9nw9Rb1x7yQQ --slot 1533:0,1534:0

 **/

#define _GNU_SOURCE         /* See feature_test_macros(7) */

#include "fd_repair.h"
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

/* Convert my style of address to UNIX style */
static int
repair_to_sockaddr( uchar * dst, fd_repair_peer_addr_t const * src ) {
  fd_memset(dst, 0, sizeof(struct sockaddr_in));
  struct sockaddr_in * t = (struct sockaddr_in *)dst;
  t->sin_family = AF_INET;
  t->sin_addr.s_addr = src->addr;
  t->sin_port = src->port;
  return sizeof(struct sockaddr_in);
}

/* Convert my style of address from UNIX style */
static int
repair_from_sockaddr( fd_repair_peer_addr_t * dst, uchar const * src ) {
  FD_STATIC_ASSERT(sizeof(fd_repair_peer_addr_t) == sizeof(ulong),"messed up size");
  dst->l = 0;
  const struct sockaddr_in * sa = (const struct sockaddr_in *)src;
  dst->addr = sa->sin_addr.s_addr;
  dst->port = sa->sin_port;
  return 0;
}

static void
send_packet( uchar const * data, size_t sz, fd_repair_peer_addr_t const * addr, void * arg ) {
  // FD_LOG_HEXDUMP_NOTICE(("send: ", data, sz));
  (void)arg;
  uchar saddr[sizeof(struct sockaddr_in)];
  int saddrlen = repair_to_sockaddr(saddr, addr);
  if ( sendto(sockfd, data, sz, MSG_DONTWAIT,
              (const struct sockaddr *)saddr, (socklen_t)saddrlen) < 0 ) {
    FD_LOG_WARNING(("sendto failed: %s", strerror(errno)));
  }
}

/* Convert a host:port string to a repair network address. If host is
 * missing, it assumes the local hostname. */
static fd_repair_peer_addr_t *
resolve_hostport(const char* str /* host:port */, fd_repair_peer_addr_t * res) {
  fd_memset(res, 0, sizeof(fd_repair_peer_addr_t));

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
  /* Convert result to repair address */
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

static int
main_loop( int * argc, char *** argv, fd_repair_t * glob, fd_repair_config_t * config, volatile int * stopflag ) {
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
  int saddrlen = repair_to_sockaddr(saddr, &config->intake_addr);
  if (saddrlen < 0 || bind(fd, (struct sockaddr*)saddr, (uint)saddrlen) < 0) {
    FD_LOG_ERR(("bind failed: %s", strerror(errno)));
    return -1;
  }

  fd_repair_settime(glob, fd_log_wallclock());
  fd_repair_start(glob);

  char const * id_cstr = fd_env_strip_cmdline_cstr ( argc, argv, "--peer_id", NULL, NULL );
  if ( id_cstr == NULL )
    FD_LOG_ERR(("--peer_id command line argument required"));
  fd_pubkey_t id;
  fd_base58_decode_32(id_cstr, id.uc);
  char const * addr_cstr = fd_env_strip_cmdline_cstr ( argc, argv, "--peer_addr", NULL, "127.0.0.1:1032" );
  fd_repair_peer_addr_t peeraddr;
  if ( fd_repair_add_active_peer(glob, resolve_hostport(addr_cstr, &peeraddr), &id) )
    return -1;

  char const * slot_cstr = fd_env_strip_cmdline_cstr ( argc, argv, "--slot", NULL, NULL );
  if ( slot_cstr == NULL )
    FD_LOG_ERR(("--slot command line argument required"));
  do {
    ulong slot = strtoul(slot_cstr, (char **)&slot_cstr, 10);
    if ( *slot_cstr != ':' )
      FD_LOG_ERR(("--slot takes <slot>:<idx>,<slot>:<idx>,<slot>:<idx>..."));
    ++slot_cstr;
    ulong idx = strtoul(slot_cstr, (char **)&slot_cstr, 10);
    if ( fd_repair_need_highest_window_index(glob, &id, slot, (uint)idx) )
      return -1;
    if ( *slot_cstr == '\0' )
      break;
    if ( *slot_cstr != ',' )
      FD_LOG_ERR(("--slot takes <slot>:<idx>,<slot>:<idx>,<slot>:<idx>..."));
    ++slot_cstr;
  } while (1);

#define VLEN 32U
  struct mmsghdr msgs[VLEN];
  struct iovec iovecs[VLEN];
  uchar bufs[VLEN][FD_ETH_PAYLOAD_MAX];
  uchar sockaddrs[VLEN][sizeof(struct sockaddr_in6)]; /* sockaddr is smaller than sockaddr_in6 */

  while ( !*stopflag ) {
    fd_repair_settime(glob, fd_log_wallclock());
    fd_repair_continue(glob);

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
      fd_repair_peer_addr_t from;
      repair_from_sockaddr( &from, msgs[i].msg_hdr.msg_name );
      FD_LOG_HEXDUMP_NOTICE(("recv: ", bufs[i], msgs[i].msg_len));
      fd_repair_recv_packet(glob, bufs[i], msgs[i].msg_len, &from);
    }
  }

  close(fd);
  return 0;
}

static void
recv_shred(fd_shred_t const * shred, ulong shred_sz, fd_gossip_peer_addr_t const * from, fd_pubkey_t const * id, void * arg) {
  (void)from;
  (void)id;
  (void)arg;
  FD_LOG_NOTICE(( "shred variant=0x%02x sz=%lu slot=%lu idx=%u header_sz=0x%lx merkle_sz=0x%lx payload_sz=0x%lx",
                  (uint)shred->variant, shred_sz, shred->slot, shred->idx, fd_shred_header_sz(shred->variant),
                  fd_shred_merkle_sz(shred->variant), fd_shred_payload_sz(shred) ));
}

static void
deliver_fail_fun( fd_pubkey_t const * id,
                         ulong               slot,
                         uint                shred_index,
                         void *              arg,
                         int                 reason ) {
  (void)arg;
  FD_LOG_WARNING( ( "repair_deliver_fail_fun - shred: %32J, slot: %lu, idx: %u, reason: %d",
                    id,
                    slot,
                    shred_index,
                    reason ) );
}

int main(int argc, char **argv) {
  fd_boot         ( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  fd_valloc_t valloc = fd_libc_alloc_virtual();

  fd_repair_config_t config;
  fd_memset(&config, 0, sizeof(config));

  uchar private_key[32];
  FD_TEST( 32UL==getrandom( private_key, 32UL, 0 ) );
  fd_sha512_t sha[1];
  fd_pubkey_t public_key;
  FD_TEST( fd_ed25519_public_from_private( public_key.uc, private_key, sha ) );

  config.private_key = private_key;
  config.public_key = &public_key;

  char hostname[64];
  gethostname(hostname, sizeof(hostname));

  char const * my_addr = fd_env_strip_cmdline_cstr ( &argc, &argv, "--my_addr", NULL, ":1125");
  FD_TEST( resolve_hostport(my_addr, &config.intake_addr) );

  config.deliver_fun = recv_shred;
  config.deliver_fail_fun = deliver_fail_fun;
  config.send_fun = send_packet;
  config.deliver_fail_fun = deliver_fail_fun;

  ulong seed = fd_hash(0, hostname, strnlen(hostname, sizeof(hostname)));

  void * shm = fd_valloc_malloc(valloc, fd_repair_align(), fd_repair_footprint());
  fd_repair_t * glob = fd_repair_join(fd_repair_new(shm, seed, valloc));

  if ( fd_repair_set_config(glob, &config) )
    return 1;

  signal(SIGINT, stop);
  signal(SIGPIPE, SIG_IGN);

  if ( main_loop(&argc, &argv, glob, &config, &stopflag) )
    return 1;

  fd_valloc_free(valloc, fd_repair_delete(fd_repair_leave(glob), valloc));

  fd_halt();

  return 0;
}
