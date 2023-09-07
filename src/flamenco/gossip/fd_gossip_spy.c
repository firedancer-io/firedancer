/**

   export RUST_LOG=solana_gossip=TRACE
   cargo run --bin solana-test-validator

 **/

#include "fd_gossip.h"
#include "../fd_flamenco.h"
#include "../../util/fd_util.h"
#include "../../ballet/base58/fd_base58.h"
#include "../types/fd_types_yaml.h"
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/random.h>

/*
static void usage(const char* progname) {
  fprintf( stderr, "USAGE: %s\n", progname );
  fprintf( stderr,
           " --config      <file>       startup configuration file\n" );
}
*/

static void print_data(fd_crds_data_t* data, void* arg, long now) {
  (void)now;
  fd_flamenco_yaml_t * yamldump = (fd_flamenco_yaml_t *)arg;
  FILE * dumpfile = (FILE *)fd_flamenco_yaml_file(yamldump);
  fd_crds_data_walk(yamldump, data, fd_flamenco_yaml_walk, NULL, 1U);
  fflush(dumpfile);
}

// SIGINT signal handler
volatile int stopflag = 0;
void stop(int sig) { (void)sig; stopflag = 1; }

int main(int argc, char **argv) {
  fd_boot         ( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  fd_valloc_t valloc = fd_libc_alloc_virtual();

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
  FD_TEST( 32UL==getrandom( config.my_creds.private_key, 32UL, 0 ) );
  fd_sha512_t sha[1];
  FD_TEST( fd_ed25519_public_from_private( config.my_creds.public_key.uc, config.my_creds.private_key, sha ) );

  char hostname[64];
  gethostname(hostname, sizeof(hostname));

  FD_TEST( fd_gossip_resolve_hostport(":1125", &config.my_addr) );

  config.shred_version = 56177U;
  // config.shred_version = 61807U;

  fd_flamenco_yaml_t * yamldump =
    fd_flamenco_yaml_init( fd_flamenco_yaml_new(
      fd_valloc_malloc( valloc, fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() ) ),
      stdout );
  config.deliver_fun = print_data;
  config.deliver_fun_arg = yamldump;

  ulong seed = fd_hash(0, hostname, strnlen(hostname, sizeof(hostname)));

  void * shm = fd_valloc_malloc(valloc, fd_gossip_global_align(), fd_gossip_global_footprint());
  fd_gossip_global_t * glob = fd_gossip_global_join(fd_gossip_global_new(shm, seed, valloc));

  if ( fd_gossip_global_set_config(glob, &config) )
    return 1;

  fd_gossip_network_addr_t peeraddr;
  if ( fd_gossip_add_active_peer(glob, fd_gossip_resolve_hostport("entrypoint.mainnet-beta.solana.com:8001", &peeraddr)) )
    return 1;
  if ( fd_gossip_add_active_peer(glob, fd_gossip_resolve_hostport("entrypoint2.mainnet-beta.solana.com:8001", &peeraddr)) )
    return 1;
  if ( fd_gossip_add_active_peer(glob, fd_gossip_resolve_hostport("entrypoint3.mainnet-beta.solana.com:8001", &peeraddr)) )
    return 1;
  if ( fd_gossip_add_active_peer(glob, fd_gossip_resolve_hostport("entrypoint4.mainnet-beta.solana.com:8001", &peeraddr)) )
    return 1;
  if ( fd_gossip_add_active_peer(glob, fd_gossip_resolve_hostport("entrypoint5.mainnet-beta.solana.com:8001", &peeraddr)) )
    return 1;
  // if ( fd_gossip_add_active_peer(glob, fd_gossip_resolve_hostport("entrypoint.testnet.solana.com:8001", &peeraddr)) )
  // return 1;
  // if ( fd_gossip_add_active_peer(glob, fd_gossip_resolve_hostport("entrypoint2.testnet.solana.com:8001", &peeraddr)) )
  // return 1;
  // if ( fd_gossip_add_active_peer(glob, fd_gossip_resolve_hostport("entrypoint3.testnet.solana.com:8001", &peeraddr)) )
  // return 1;
  // if ( fd_gossip_add_active_peer(glob, fd_gossip_resolve_hostport("localhost:1024", &peeraddr)) )
  // return 1;

  signal(SIGINT, stop);
  signal(SIGPIPE, SIG_IGN);

  if ( fd_gossip_main_loop(glob, valloc, &stopflag) )
    return 1;

  fd_valloc_free(valloc, fd_flamenco_yaml_delete(yamldump));

  fd_valloc_free(valloc, fd_gossip_global_delete(fd_gossip_global_leave(glob), valloc));

  fd_halt();

  return 0;
}
