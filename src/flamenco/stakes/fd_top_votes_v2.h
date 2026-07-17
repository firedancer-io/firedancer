#ifndef HEADER_fd_src_flamenco_stakes_fd_top_votes_v2_h
#define HEADER_fd_src_flamenco_stakes_fd_top_votes_v2_h

#include "../../util/fd_util_base.h"
#include "../fd_flamenco_base.h"

struct fd_top_votes_v2;
typedef struct fd_top_votes_v2 fd_top_votes_v2_t;

FD_PROTOTYPES_BEGIN

/* fd_top_votes_v2_{align,footprint} describe a position-independent
   top-votes store with max_fork_width t-1 account groups and
   max_live_banks t-2 state snapshots. */

ulong
fd_top_votes_v2_align( void );

ulong
fd_top_votes_v2_footprint( ulong max_fork_width,
                           ulong max_live_banks );

/* fd_top_votes_v2_new formats the store, including independent lazy
   pools and maps for the two t-2 and max_fork_width t-1 account sets. */

void *
fd_top_votes_v2_new( void * mem,
                     ulong  max_fork_width,
                     ulong  max_live_banks,
                     ulong  seed );

fd_top_votes_v2_t *
fd_top_votes_v2_join( void * mem );

/* fd_top_votes_v2_new_child copies the parent's t-2 state snapshot and
   inherits its t-1/t-2 group indices.  The caller manages bank slot
   allocation and lifetime. */

void
fd_top_votes_v2_new_child( fd_top_votes_v2_t * top_votes,
                           ulong               parent_idx,
                           ulong               child_idx );

/* fd_top_votes_v2_new_epoch_child rotates the parent's t-1 accounts
   into the alternate t-2 group, clears the child's t-2 state for
   refresh, and acquires an empty t-1 group for the child. */

void
fd_top_votes_v2_new_epoch_child( fd_top_votes_v2_t * top_votes,
                                 ulong               parent_idx,
                                 ulong               child_idx );

/* An insertion session exclusively binds the shared scratch heap to a
   fresh t-1 group owned by child_idx. */

void
fd_top_votes_v2_insert_init( fd_top_votes_v2_t * top_votes,
                             ulong               child_idx );

void
fd_top_votes_v2_insert( fd_top_votes_v2_t * top_votes,
                        fd_pubkey_t const *  pubkey,
                        fd_pubkey_t const *  node_account,
                        ulong                stake,
                        ushort               commission );

void
fd_top_votes_v2_insert_fini( fd_top_votes_v2_t * top_votes );

int
fd_top_votes_v2_query_t_1( fd_top_votes_v2_t const * top_votes,
                           ulong                     child_idx,
                           fd_pubkey_t const *        pubkey,
                           fd_pubkey_t *              node_account_out_opt,
                           ulong *                    stake_out_opt,
                           ushort *                   commission_out_opt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_top_votes_v2_h */
