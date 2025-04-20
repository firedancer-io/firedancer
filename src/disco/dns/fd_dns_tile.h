#ifndef HEADER_fd_src_disco_dns_fd_dns_tile_h
#define HEADER_fd_src_disco_dns_fd_dns_tile_h

/* The dns tile resolves DNS records.  This is only a separate tile
   because doing DNS lookups in application tiles would compromise their
   security.  getaddrinfo() does arbitrary system calls and is therefore
   practically only possible when disabling seccomp and landlock.

   The dns tile collects a list of domains to query on startup.  Then,
   it periodically refreshes these domains in the background.  The
   topology code ensures that the dns tile does not read data generated
   by untrusted tiles after startup. */

#include "../topo/fd_topo.h"
#include "../../waltz/dns/fd_dns_cache.h"

struct fd_dns_tile_task {
  ulong val_hash;
  char  name[ 256 ]; /* cstr */
  int   gai_err_cache;
  uchar name_len;
};

typedef struct fd_dns_tile_task fd_dns_tile_task_t;

struct fd_dns_tile {
  fd_dns_cache_join_t cache[1];

  /* tempo async_reload timer */
  fd_rng_t rng[1];
  ulong    resolve_async_min;
  long     resolve_next_nanos;

  /* Hardcoded list of domains to resolve */
  fd_dns_tile_task_t tasks[1];
  ulong              task_cnt;

  /* Scratch buffer for collecting getaddrinfo results */
  uchar ip6_scratch[ 128*16 ];

  struct {
    ulong gai_cnt;
    ulong gai_err_cnt;
    ulong addr_set_change_cnt;
    ulong last_refresh; /* unix timestamp, seconds */
  } metrics;
};

typedef struct fd_dns_tile fd_dns_tile_t;

FD_PROTOTYPES_BEGIN

extern fd_topo_run_tile_t fd_tile_dns;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_dns_fd_dns_tile_h */
