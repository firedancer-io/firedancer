#include "fd_gossip.h"
#include "../fd_flamenco.h"
#include "../../util/fd_util.h"
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

static void usage(const char* progname) {
  fprintf( stderr, "USAGE: %s\n", progname );
  fprintf( stderr,
           " --config      <file>       startup configuration file\n" );
}

// SIGINT signal handler
volatile int stopflag = 0;
void stop(int sig) { (void)sig; stopflag = 1; }

int main(int argc, char **argv) {
  fd_boot         ( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  const char* config_file = fd_env_strip_cmdline_cstr ( &argc, &argv, "--config", NULL, NULL );
  if ( config_file == NULL ) {
    fprintf( stderr, "--config flag required\n" );
    usage( argv[0] );
    return 1;
  }
  fd_gossip_config_t config;

  char hostname[64];
  gethostname(hostname, sizeof(hostname));
  ulong seed = fd_hash(0, hostname, strnlen(hostname, sizeof(hostname)));

  fd_valloc_t valloc = fd_libc_alloc_virtual();
  void * shm = fd_valloc_malloc(valloc, fd_gossip_global_align(), fd_gossip_global_footprint());
  fd_gossip_global_t * glob = fd_gossip_global_join(fd_gossip_global_new(shm, seed, valloc));

  if ( fd_gossip_global_set_config(glob, &config) )
    return 1;

  signal(SIGINT, stop);
  signal(SIGPIPE, SIG_IGN);

  if ( fd_gossip_main_loop(glob, valloc, &stopflag) )
    return 1;

  fd_valloc_free(valloc, fd_gossip_global_delete(fd_gossip_global_leave(glob), valloc));

  fd_halt();

  return 0;
}
