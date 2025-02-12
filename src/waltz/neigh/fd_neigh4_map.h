#ifndef HEADER_fd_src_waltz_neigh_fd_neigh4_map_h
#define HEADER_fd_src_waltz_neigh_fd_neigh4_map_h

/* fd_neigh4.h provides APIs for IPv4 neighbor discovery using ARP. */

#include "../../util/log/fd_log.h" /* fd_log_wallclock */

struct __attribute__((aligned(16))) fd_neigh4_entry {
  uint  ip4_addr;
  uchar mac_addr[6]; /* MAC address */
  uchar state;
  uchar _pad[1];
  long  probe_suppress_until;
};

typedef struct fd_neigh4_entry fd_neigh4_entry_t;

#define FD_NEIGH4_STATE_INCOMPLETE (0)
#define FD_NEIGH4_STATE_ACTIVE     (1)

#include "fd_neigh4_map_defines.h"
#define MAP_IMPL_STYLE 1
#include "../../util/tmpl/fd_map_slot_para.c"

FD_PROTOTYPES_BEGIN

#if FD_HAS_HOSTED

/* fd_neigh4_hmap_fprintf prints the routing table to the given FILE *
   pointer (or target equivalent).  Order of routes is undefined but
   guaranteed to be stable between calls.  Outputs ASCII encoding with LF
   newlines.  Returns errno on failure and 0 on success.  Only works on
   ACTIVE tables. */

int
fd_neigh4_hmap_fprintf( fd_neigh4_hmap_t const * map,
                        void *                   file );

#endif /* FD_HAS_HOSTED */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_neigh_fd_neigh4_map_h */
