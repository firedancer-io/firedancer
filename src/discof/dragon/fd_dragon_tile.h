#ifndef HEADER_fd_src_discof_dragon_fd_dragon_tile_h
#define HEADER_fd_src_discof_dragon_fd_dragon_tile_h

/* The dragon tile's message to replay, and the sizes of the link that
   carries it, needed by the topologies that wire it and by replay. */

#include "../../util/fd_util_base.h"

/* fd_dragon_release_t gives bank references back to replay.  It
   applies to every reference replay granted for bank_idx while
   publishing a replay_out frag with a sequence number below
   seq_bound, and to nothing else.

   The bound is what makes a release safe across a recycled bank
   index.  The tile learns of a grant from the frag that carries it,
   so a release it sends while acting on frag S can name S+1 and give
   back exactly the grants it has seen.  A grant replay published on a
   later frag, which is still on its way to the tile, is untouched
   even though it names the same bank index. */

struct fd_dragon_release {
  ulong bank_idx;
  ulong seq_bound;
};

typedef struct fd_dragon_release fd_dragon_release_t;

/* FD_DRAGON_RELEASE_DETACH as bank_idx is the tile's last message: it
   is leaving, so replay gives back every reference it granted, on
   every bank index, and grants no more for the rest of the run.
   Nothing releases those references once the tile is gone, and a bank
   that keeps a reference is a bank replay cannot prune. */

#define FD_DRAGON_RELEASE_DETACH (ULONG_MAX)

/* FD_DRAGON_RELEASE_BURST is how many releases the tile publishes per
   stem iteration, and therefore its stem burst.

   FD_DRAGON_RELEASE_LINK_DEPTH is the depth of the dragon_replay link.
   The tile never has more releases pending than one per bank replay
   can have live, plus one per bank in its fork graph; the default
   [runtime.max_live_slots] is 2048, so a depth of 4096 keeps the tile
   from ever waiting on replay to consume. */

#define FD_DRAGON_RELEASE_BURST      (  64UL)
#define FD_DRAGON_RELEASE_LINK_DEPTH (4096UL)

/* Where the deferred levels' subscription filters run
   ([tiles.dragon.filter_at]). */

#define FD_DRAGON_FILTER_AT_INGEST (0)
#define FD_DRAGON_FILTER_AT_SEND   (1)

/* The buffer the deferred levels are served from is an mcache of
   FD_DRAGON_BUF_DEPTH entries and a dcache of [tiles.dragon.buffer_size_mib]
   less FD_DRAGON_BUF_RESERVE, which is what the dcache and workspace
   headers need for the workspace to be exactly that many MiB. */

#define FD_DRAGON_BUF_DEPTH   (1UL<<20)
#define FD_DRAGON_BUF_RESERVE (2UL<<20)

#endif /* HEADER_fd_src_discof_dragon_fd_dragon_tile_h */
