#include "fd_gossip.h"
#include "../fd_flamenco.h"
#include "../../util/fd_util.h"
#include <stdio.h>
#include <unistd.h>

static void usage(const char* progname) {
  fprintf( stderr, "USAGE: %s\n", progname );
  fprintf( stderr,
           " --config      <file>       startup configuration file\n" );
}

int main(int argc, char **argv) {
  fd_boot         ( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  const char* config = fd_env_strip_cmdline_cstr ( &argc, &argv, "--config", NULL, NULL );
  if ( config == NULL ) {
    fprintf( stderr, "--config flag required\n" );
    usage( argv[0] );
    return 1;
  }

  char hostname[64];
  gethostname(hostname, sizeof(hostname));
  ulong seed = fd_hash(0, hostname, strnlen(hostname, sizeof(hostname)));

  fd_valloc_t valloc = fd_libc_alloc_virtual();
  void * shm = fd_valloc_malloc(valloc, fd_gossip_global_align(), fd_gossip_global_footprint());
  fd_gossip_global_t * glob = fd_gossip_global_join(fd_gossip_global_new(shm, seed, valloc));

  fd_valloc_free(valloc, fd_gossip_global_delete(fd_gossip_global_leave(glob), valloc));

  fd_halt();

  return 0;
}
