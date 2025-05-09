#ifndef HEADER_fd_src_flamenco_gossip_fd_prune_finder_h
#define HEADER_fd_src_flamenco_gossip_fd_prune_finder_h

#include "../../util/fd_util.h"

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

struct fd_prune_finder_private;
typedef struct fd_prune_finder_private fd_prune_finder_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_prune_finder_align( void );

FD_FN_CONST ulong
fd_prune_finder_footprint( void );

void *
fd_prune_finder_new( void * shmem );

fd_prune_finder_t *
fd_prune_finder_join( void * shpf );

/* fd_prune_finder_record records a received gossip message from a peer
   in the finder.  This should be called for every message received that
   is attempted to be inserted into the CRDS.

   origin_pubkey and relayer_pubkey identify the message originator, and
   the node which forwarded the message to us, respectively.  num_dups
   is the number of times the message has already been received from
   other nodes.  The first peer to send the message to us should have a
   value of zero, and the next peer a value of one, and so on.

   If the message is the 20th recorded for a given originator, the
   finder will prune any peers relaying that origin which have not been
   performing well, and reset the record counter to zero. */

void
fd_prune_finder_record( fd_prune_finder_t * pf,
                        uchar const *       origin_pubkey,
                        ulong               origin_stake,
                        uchar const *       relayer_pubkey,
                        ulong               relayer_stake,
                        ulong               num_dups );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_gossip_fd_prune_finder_h */
