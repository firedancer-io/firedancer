/*
 build/native/gcc/bin/fdctl spy --config src/app/fdctl/config/testnet.toml
*/

#define _GNU_SOURCE         /* See feature_test_macros(7) */

#include "fdctl.h"
#include "../../flamenco/gossip/fd_gossip.h"
#include "../../flamenco/types/fd_types_yaml.h"
#include "../../disco/keyguard/fd_keyguard.h"
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

static void print_data(FD_FN_UNUSED fd_crds_data_t* data, FD_FN_UNUSED void* arg) {
  // fd_flamenco_yaml_t * yamldump = (fd_flamenco_yaml_t *)arg;
  // FILE * dumpfile = (FILE *)fd_flamenco_yaml_file(yamldump);
  // fd_crds_data_walk(yamldump, data, fd_flamenco_yaml_walk, NULL, 1U);
  // fflush(dumpfile);
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

static uchar       private_key[32] = {0};
static fd_pubkey_t public_key = {0};
static fd_sha512_t sha512 = {0};

static void
gossip_signer( void *        signer_ctx,
               uchar         signature[ static 64 ],
               uchar const * buffer,
               ulong         len,
               int           sign_type ){
  (void)signer_ctx;

  switch (sign_type) {
    case FD_KEYGUARD_SIGN_TYPE_ED25519:
      fd_ed25519_sign(signature, buffer, len, public_key.uc, private_key, &sha512);
      break;
    case FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519:
      {
        uchar hash[32];
        fd_sha256_hash(buffer, len, hash);
        fd_ed25519_sign(signature, hash, 32UL, public_key.uc, private_key, &sha512);
      }
      break;
    default:
      FD_LOG_ERR(("unexpected sign type"));
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

#define MY_SMAX (1UL << 16) // 65536
#define MY_DEPTH 64UL
uchar smem[ MY_SMAX ] __attribute__((aligned(FD_SCRATCH_SMEM_ALIGN)));
ulong fmem[ MY_DEPTH ] __attribute((aligned(FD_SCRATCH_FMEM_ALIGN)));

void
spy_cmd_fn( args_t *         args,
            config_t * const config ) {
  (void)args;
  fd_scratch_attach( smem, fmem, MY_SMAX, MY_DEPTH );
  fd_valloc_t valloc = fd_libc_alloc_virtual();

  /* Retrieve gossip tile object, which has metadata we need */
  ulong gtile_idx = fd_topo_find_tile( &config->topo, "gossip", 0UL );
  if( gtile_idx == ULONG_MAX ) {
    FD_LOG_ERR(("gossip tile not found, was topology initialized?"));
  }
  fd_topo_tile_t const * gtile = &config->topo.tiles[ gtile_idx ];

  fd_gossip_config_t gconfig;
  fd_memset(&gconfig, 0, sizeof(gconfig));

  FD_TEST( 32UL==getrandom( private_key, 32UL, 0 ) );
  FD_TEST( fd_ed25519_public_from_private( public_key.uc, private_key, &sha512 ) );

  gconfig.private_key = private_key;
  gconfig.public_key = &public_key;
  fd_sha512_join( fd_sha512_new( &sha512 ) );

  
  /* Compute my address */
  gconfig.my_addr.l = 0;
  gconfig.my_addr.addr = gtile->gossip.ip_addr;
  gconfig.my_addr.port = fd_ushort_bswap( gtile->gossip.gossip_listen_port );

  gconfig.my_version = (fd_gossip_version_v2_t){
    .from = public_key,
    .major = 42U,
    .minor = 42U,
    .patch = 42U,
    .commit = 0U,
    .has_commit = 0U,
    .feature_set = 0U,
  };

  gconfig.shred_version = config->consensus.expected_shred_version;
  if( 0 == gconfig.shred_version ){
    /* TODO: This is a placeholder until we can do something smarter */
    gconfig.shred_version = 64475U;
  }

  fd_flamenco_yaml_t * yamldump =
    fd_flamenco_yaml_init( fd_flamenco_yaml_new(
      fd_valloc_malloc( valloc, fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() ) ),
      stdout );
  gconfig.deliver_fun = print_data;
  gconfig.deliver_arg = yamldump;
  gconfig.send_fun    = send_packet;
  gconfig.send_arg    = NULL;
  gconfig.sign_fun    = gossip_signer;
  gconfig.sign_arg    = NULL;

  ulong seed = fd_hash(0, &gtile->gossip.ip_addr, sizeof(gtile->gossip.ip_addr));

  void * shm = fd_valloc_malloc(valloc, fd_gossip_align(), fd_gossip_footprint());
  fd_gossip_t * glob = fd_gossip_join(fd_gossip_new(shm, seed));

  if ( fd_gossip_set_config(glob, &gconfig) )
    return;


  fd_gossip_set_entrypoints( glob, gtile->gossip.entrypoints, gtile->gossip.entrypoints_cnt, gtile->gossip.peer_ports);

  signal(SIGINT, stop);
  signal(SIGPIPE, SIG_IGN);

  if ( main_loop(glob, &gconfig, &stopflag) )
    return;

  fd_valloc_free(valloc, fd_flamenco_yaml_delete(yamldump));

  fd_valloc_free(valloc, fd_gossip_delete(fd_gossip_leave(glob)));
  fd_scratch_detach( NULL );
}
