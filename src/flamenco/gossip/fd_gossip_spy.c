#include "fd_gossip.h"
#include "../fd_flamenco.h"
#include "../../util/fd_util.h"
#include "../../ballet/base58/fd_base58.h"
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
static void usage(const char* progname) {
  fprintf( stderr, "USAGE: %s\n", progname );
  fprintf( stderr,
           " --config      <file>       startup configuration file\n" );
}
*/

// SIGINT signal handler
volatile int stopflag = 0;
void stop(int sig) { (void)sig; stopflag = 1; }

int main(int argc, char **argv) {
  fd_boot         ( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  /*
  const char* config_file = fd_env_strip_cmdline_cstr ( &argc, &argv, "--config", NULL, NULL );
  if ( config_file == NULL ) {
    fprintf( stderr, "--config flag required\n" );
    usage( argv[0] );
    return 1;
  }
  */
  fd_gossip_config_t config;
  fd_memset(&config, 0, sizeof(config));
  static const uchar keypair[64] = {151,50,112,166,226,63,194,20,148,252,40,64,15,177,107,182,33,55,205,229,41,89,253,105,59,34,222,63,137,61,149,108,57,78,32,56,180,204,58,197,119,82,62,204,48,103,63,242,241,207,147,187,12,159,8,106,193,251,118,170,166,141,103,111};
  fd_memcpy(config.my_creds.private_key, keypair, 32UL);
  fd_memcpy(config.my_creds.public_key.uc, keypair + 32U, 32UL);
  config.my_addr.family = AF_INET;
  config.my_addr.port = htons(1125);
  config.my_addr.addr[0] = inet_addr("127.0.0.1");

  char hostname[64];
  gethostname(hostname, sizeof(hostname));
  ulong seed = fd_hash(0, hostname, strnlen(hostname, sizeof(hostname)));

  fd_valloc_t valloc = fd_libc_alloc_virtual();
  void * shm = fd_valloc_malloc(valloc, fd_gossip_global_align(), fd_gossip_global_footprint());
  fd_gossip_global_t * glob = fd_gossip_global_join(fd_gossip_global_new(shm, seed, valloc));

  if ( fd_gossip_global_set_config(glob, &config) )
    return 1;

  fd_pubkey_t peerid;
  fd_base58_decode_32("5wU7dNgcfn58mXcuKVEDqcVT4xTQaBYeKiNud14otjh8", peerid.uc);
  fd_gossip_network_addr_t peeraddr;
  fd_memset(&peeraddr, 0, sizeof(peeraddr));
  peeraddr.family = AF_INET;
  peeraddr.port = htons(1024);
  peeraddr.addr[0] = inet_addr("127.0.0.1");
  if ( fd_gossip_add_active_peer(glob, &peerid, &peeraddr) )
    return 1;
  
  signal(SIGINT, stop);
  signal(SIGPIPE, SIG_IGN);

  if ( fd_gossip_main_loop(glob, valloc, &stopflag) )
    return 1;

  fd_valloc_free(valloc, fd_gossip_global_delete(fd_gossip_global_leave(glob), valloc));

  fd_halt();

  return 0;
}
