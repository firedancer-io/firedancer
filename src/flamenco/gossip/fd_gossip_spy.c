/**

   export RUST_LOG=solana_gossip=TRACE
   cargo run --bin solana-test-validator

 **/

#define _GNU_SOURCE         /* See feature_test_macros(7) */

#include "fd_gossip.h"
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

static void print_data(fd_crds_data_t* data, void* arg) {
  fd_flamenco_yaml_t * yamldump = (fd_flamenco_yaml_t *)arg;
  FILE * dumpfile = (FILE *)fd_flamenco_yaml_file(yamldump);
  fd_crds_data_walk(yamldump, data, fd_flamenco_yaml_walk, NULL, 1U);

  if (data->discriminant == fd_crds_data_enum_vote) {
    fd_gossip_vote_t * v = &data->inner.vote;
    fd_txn_t * txn = v->txn.txn;
    for ( ushort i = 0; i < txn->instr_cnt; ++i ) {
      fd_txn_instr_t const * txn_instr = &txn->instr[i];
      uchar * data = v->txn.raw + txn_instr->data_off;
      ushort data_sz = txn_instr->data_sz;
      fd_bincode_decode_ctx_t decode_ctx;
      decode_ctx.data    = data;
      decode_ctx.dataend = data + data_sz;
      decode_ctx.valloc  = fd_libc_alloc_virtual();
      fd_vote_instruction_t vinstruction;
      int rc = fd_vote_instruction_decode( &vinstruction, &decode_ctx );
      if ( rc || decode_ctx.data != decode_ctx.dataend ) {
        FD_LOG_WARNING(("failed to decode vote instruction"));
      } else {
        fd_vote_instruction_walk(yamldump, &vinstruction, fd_flamenco_yaml_walk, NULL, 1U);
      }
    }
  }

  fflush(dumpfile);
}

// SIGINT signal handler
volatile int stopflag = 0;
static void stop(int sig) { (void)sig; stopflag = 1; }

static int sockfd = -1;

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
send_packet( uchar const * data, size_t sz, fd_gossip_peer_addr_t const * addr, void * arg ) {
  (void)arg;
  uchar saddr[sizeof(struct sockaddr_in)];
  int saddrlen = gossip_to_sockaddr(saddr, addr);
  if ( sendto(sockfd, data, sz, MSG_DONTWAIT,
              (const struct sockaddr *)saddr, (socklen_t)saddrlen) < 0 ) {
    FD_LOG_WARNING(("sendto failed: %s", strerror(errno)));
  }
}

static int
main_loop( fd_gossip_t * glob, fd_gossip_config_t * config, volatile int * stopflag ) {
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
  int saddrlen = gossip_to_sockaddr(saddr, &config->my_addr);
  if (saddrlen < 0 || bind(fd, (struct sockaddr*)saddr, (uint)saddrlen) < 0) {
    FD_LOG_ERR(("bind failed: %s", strerror(errno)));
    return -1;
  }
  if( getsockname( fd, (struct sockaddr *)saddr, (uint*)&saddrlen ) < 0 ) {
    FD_LOG_ERR( ( "getsockname failed: %s", strerror( errno ) ) );
    return -1;
  }
  gossip_from_sockaddr( &config->my_addr, saddr );
  fd_gossip_update_addr( glob, &config->my_addr );

  fd_gossip_settime(glob, fd_log_wallclock());
  fd_gossip_start(glob);

#define VLEN 32U
  struct mmsghdr msgs[VLEN];
  struct iovec iovecs[VLEN];
  uchar bufs[VLEN][FD_ETH_PAYLOAD_MAX];
  uchar sockaddrs[VLEN][sizeof(struct sockaddr_in6)]; /* sockaddr is smaller than sockaddr_in6 */

  while ( !*stopflag ) {
    fd_gossip_settime(glob, fd_log_wallclock());
    fd_gossip_continue(glob);

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
      fd_gossip_recv_packet(glob, bufs[i], msgs[i].msg_len, &from);
    }
  }

  close(fd);
  return 0;
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
  if ((port > 0 && port < 1024) || port > (int)USHORT_MAX) {
    FD_LOG_ERR(("invalid port number"));
    return NULL;
  }
  res->port = htons((ushort)port);

  return res;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_valloc_t valloc = fd_libc_alloc_virtual();

  fd_gossip_config_t config;
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

  FD_TEST( resolve_hostport(":0", &config.my_addr) );

  config.shred_version = 4274;

  fd_flamenco_yaml_t * yamldump =
    fd_flamenco_yaml_init( fd_flamenco_yaml_new(
      fd_valloc_malloc( valloc, fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() ) ),
      stdout );
  config.deliver_fun = print_data;
  config.fun_arg = yamldump;
  config.send_fun = send_packet;

  ulong seed = fd_hash(0, hostname, strnlen(hostname, sizeof(hostname)));

  void * shm = fd_valloc_malloc(valloc, fd_gossip_align(), fd_gossip_footprint());
  fd_gossip_t * glob = fd_gossip_join(fd_gossip_new(shm, seed, valloc));

  if ( fd_gossip_set_config(glob, &config) )
    return 1;

  fd_gossip_peer_addr_t peeraddr;
  // if ( fd_gossip_add_active_peer(glob, resolve_hostport("entrypoint.mainnet-beta.solana.com:8001", &peeraddr)) )
  // return 1;
  // if ( fd_gossip_add_active_peer(glob, resolve_hostport("entrypoint2.mainnet-beta.solana.com:8001", &peeraddr)) )
  // return 1;
  // if ( fd_gossip_add_active_peer(glob, resolve_hostport("entrypoint3.mainnet-beta.solana.com:8001", &peeraddr)) )
  // return 1;
  // if ( fd_gossip_add_active_peer(glob, resolve_hostport("entrypoint4.mainnet-beta.solana.com:8001", &peeraddr)) )
  // return 1;
  // if ( fd_gossip_add_active_peer(glob, resolve_hostport("entrypoint5.mainnet-beta.solana.com:8001", &peeraddr)) )
  // return 1;
  // if ( fd_gossip_add_active_peer(glob, resolve_hostport("entrypoint.testnet.solana.com:8001", &peeraddr)) )
  //   return 1;
  // if ( fd_gossip_add_active_peer(glob, resolve_hostport("entrypoint2.testnet.solana.com:8001", &peeraddr)) )
  //   return 1;
  // if ( fd_gossip_add_active_peer(glob, resolve_hostport("entrypoint3.testnet.solana.com:8001", &peeraddr)) )
  //   return 1;
  if ( fd_gossip_add_active_peer(glob, resolve_hostport(":1024", &peeraddr)) )
  return 1;

  signal(SIGINT, stop);
  signal(SIGPIPE, SIG_IGN);

  if ( main_loop(glob, &config, &stopflag) )
    return 1;

  fd_valloc_free(valloc, fd_flamenco_yaml_delete(yamldump));

  fd_valloc_free(valloc, fd_gossip_delete(fd_gossip_leave(glob), valloc));

  fd_halt();
  return 0;
}
