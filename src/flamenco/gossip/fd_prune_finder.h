#ifndef HEADER_fd_src_flamenco_gossip_fd_prune_finder_h
#define HEADER_fd_src_flamenco_gossip_fd_prune_finder_h

#include "fd_gossip_private.h"

/* fd_prune_finder provides an API for tracking receiving gossip
   messages and determining which peers to prune.

   Recall that in the gossip protocol, each node selects a random set of
   up to 300 peers to send messages to, and then rotates one of the
   nodes out for a new, randomly selected one every so often.

   Imagine a theoretical gossip network, which looks like

      A ----> B ----> C
      |               ^
      ----------------|

   As in node A sends to B and C, and node B sends to C.  Note
   importantly that node B will rebroadcast messages from node A to node
   C, so C receives all messages from A twice.

   This might not be desirable for C, and she may wish to tell B not
   forward her messages from A any more.  This request is called a prune
   message.  Nodes are regularly pruning their peers so that they don't
   receive too many duplicate messages.

   This file tracks information about received messages, and where the
   duplicates are coming from so that we can prune them.  At a high
   level, the two fastest senders for any particular originating node
   are kept, and all others will eventually be pruned, with some
   exceptions depending on stake of the senders.

   The actual structure is very simple, and borowed from the Agave
   design (see ReceivedCache).  We have a fixed size
   Map<Pubkey, Map<Pubkey, u64>>.  The outer map is from the
   originating node to a map of nodes which send us messages originating
   from that node.  If the outer map fills, we evict the oldest entry,
   and if the inner map fills, we stop inserting.  It is an exercise for
   the reader to figure out why this cannot be DoS'd.

   The u64 is the count of messages received from the sender, where they
   were either the first or second fastest sender.

   Periodically, we will prune the map, which means we retrieve all the
   entries from the inner map with a low score, and then send prune
   messages for them.  */

/* FD_PRUNE_MIN_INGRESS_NODES determines the minimum number of ingress
   links to retain for a particular origin. It is recommended to set
   this number to at least 2 for partition tolerance.

   FD_PRUNE_MIN_UPSERTS determines the minimum CRDS upserts a particular
   origin must observe before it is considered for pruning. When an
   origin's upsert count exceeds this value during a
   fd_prune_finder_get_prunes call, prune messages for ingress links
   containing this origin may be generated, and the upsert count for
   that origin is reset. A higher threshold provides more data points to
   score ingress links, but also means longer intervals between
   generating prune messages for a particular origin.

   When considering an origin for pruning, the top ingress links
   (sorted by score) are retained until the cumulative stake of the
   retained links exceeds
   FD_PRUNE_STAKE_THRESHOLD_PCT*min(origin_stake,my_stake). See
   https://github.com/solana-labs/solana/issues/3214 for more details */
#define FD_PRUNE_MIN_INGRESS_NODES   2UL
#define FD_PRUNE_MIN_UPSERTS         20UL
#define FD_PRUNE_STAKE_THRESHOLD_PCT 0.15

struct fd_prune_finder_private;
typedef struct fd_prune_finder_private fd_prune_finder_t;

/* fd_relayer_prune_data represents a set of paths to prune for
   a specific relayer, needed to construct prune messages. */
struct fd_relayer_prune_data {
   fd_pubkey_t relayer_pubkey;
   ulong       prune_len;
   fd_pubkey_t prunes[ FD_GOSSIP_MSG_MAX_CRDS ];
};

typedef struct fd_relayer_prune_data fd_relayer_prune_data_t;

typedef ulong fd_prune_data_iter_t;

fd_prune_data_iter_t
fd_prune_finder_relayer_prune_data_iter_next( fd_prune_finder_t * pf, fd_prune_data_iter_t iter );

fd_relayer_prune_data_t const *
fd_prune_finder_relayer_prune_data_iter_ele( fd_prune_finder_t * pf, fd_prune_data_iter_t iter );

int
fd_prune_finder_relayer_prune_data_iter_done( fd_prune_finder_t * pf, fd_prune_data_iter_t iter );

struct fd_prune_finder_metrics {
   ulong origin_evicted_cnt;
   ulong origin_relayer_evicted_cnt;
};
typedef struct fd_prune_finder_metrics fd_prune_finder_metrics_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_prune_finder_align( void );

FD_FN_CONST ulong
fd_prune_finder_footprint( ulong origin_max,
                           ulong relayer_max_per_origin );

void *
fd_prune_finder_new( void *     shmem,
                     ulong      origin_max,
                     ulong      relayer_max_per_origin,
                     fd_rng_t * rng );

fd_prune_finder_t *
fd_prune_finder_join( void * shpf );

fd_prune_finder_metrics_t const *
fd_prune_finder_metrics( fd_prune_finder_t const * pf );

/* fd_prune_finder_record records a received gossip message from a peer
   in the finder.  This should be called for every message received that
   is attempted to be inserted into the CRDS.

   origin_pubkey and relayer_pubkey identify the message originator, and
   the node which forwarded the message to us, respectively.  num_dups
   is the number of times the message has already been received from
   other nodes.  The first peer to send the message to us should have a
   value of zero, and the next peer a value of one, and so on. */

void
fd_prune_finder_record( fd_prune_finder_t * pf,
                        uchar const *       origin_pubkey,
                        ulong               origin_stake,
                        uchar const *       relayer_pubkey,
                        ulong               relayer_stake,
                        ulong               num_dups );

/* fd_prune_finder_gen_prunes returns an iterator to relayer prune data
   entries generated from the supplied list of origins. Individual
   fd_relayer_prune_data_t entries can be retrieved from with
   fd_prune_finder_prune_data.

   origins holds a list of pubkeys for which we are interested in
   pruning their relayers. Duplicates are OK, and will be skipped.
   Since the maximum number of unique origins that can be encountered
   during a single rx_push loop is bounded by FD_GOSSIP_MSG_MAX_CRDS,
   origins_len cannot exceed that.

   Origins that appear in any out_prunes entry will have their prune
   finder state reset. Therefore all prune messages must be
   transmitted prior to the next fd_prune_finder_record call.
   The returned number is valid until the next
   fd_prune_finder_gen_prunes call. */

fd_prune_data_iter_t
fd_prune_finder_gen_prunes( fd_prune_finder_t *   pf,
                            ulong                 my_stake,
                            uchar const * const * origins,
                            ulong                 origins_len );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_gossip_fd_prune_finder_h */
