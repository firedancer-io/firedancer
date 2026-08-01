#ifndef HEADER_fd_src_flamenco_stakes_fd_top_votes_v2_h
#define HEADER_fd_src_flamenco_stakes_fd_top_votes_v2_h

#include "../../util/fd_util_base.h"
#include "../fd_flamenco_base.h"

/* With the introduction of the validator_admission_ticket (VAT)
   feature, the set of vote accounts that receive epoch rewards,
   participate in clock calculation, and are elgibile for becoming
   leader becomes the top 2000 validators by stake (that also have
   a BLS pubkey).  fd_top_votes_v2_t allows for efficiently populating
   and querying the set of top staked validators and is fork-aware ish.
   This data structure is intended to be coupled with fd_banks_t.  This
   data structure is directly paralleled to Agave's epoch_stakes.

   fd_top_votes_v2_t maintains the t-1 and t-2 state of the top staked
   validators across forks.  The set of vote accounts for a specific
   bank only updates at the epoch boundary.  We also know that for a
   running validator, there will only be 1 epoch transition from the
   current root to the tip of the network (exlcuding forks).  Also, even
   across forks, the t-2 state will be the same; this means that there
   can be 2 t-2 set of vote accounts for any running validator.
   Similarly, there can be max_fork_width + 1 t-1 set of vote accounts
   for any running validator: 1 that is shared by all forks before the
   boundary and max_fork_width that are specific to each fork that
   crosses the epoch boundary.  The only data that must be unique across
   each is the metadata associated with each vote account (has it been
   deleted, and what is the last vote slot and timestamp).  The reason
   that the full set of t-1/t-2 top votes isn't stored for each bank
   is to save memory used by the data structure.

   Under the hood, fd_top_votes_v2_t uses a map/pool pair for each t-1
   and t-2 group.  This allows for quick queries for each account.
   Insertion is done via a shared heap which is reused for t-1 account
   creation.  The t-2 set is created by copying the t-1 set from the
   parent bank. */

struct fd_top_votes_v2;
typedef struct fd_top_votes_v2 fd_top_votes_v2_t;

FD_PROTOTYPES_BEGIN

/* fd_top_votes_v2_align returns the alignment of the fd_top_votes_v2_t
   structure. */

ulong
fd_top_votes_v2_align( void );

/* fd_top_votes_v2_footprint returns the footprint of the
   fd_top_votes_v2_t structure given a max number of fork width and max
   number of live banks. */

ulong
fd_top_votes_v2_footprint( ulong max_fork_width,
                           ulong max_live_banks );

/* fd_top_votes_v2_new formats a region of memory and creates a
   new fd_top_votes_v2_t structure given a memory buffer, max fork
   width, max live banks, and a seed. */

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
                           uint                parent_idx,
                           uint                child_idx );

/* fd_top_votes_v2_advance_root transfers ownership of the new root's
   shared t-1 group to root_idx.  Call this before pruning the old root.
   It does not prune any bank. */

void
fd_top_votes_v2_advance_root( fd_top_votes_v2_t * top_votes,
                              uint                root_idx );

/* fd_top_votes_v2_prune removes a bank.  It releases the t-1 group
   when child_idx owns that group; inherited groups remain owned by an
   ancestor.  A discarded subtree may be pruned parent-first provided
   no t-1 group is acquired until the complete subtree is pruned. */

void
fd_top_votes_v2_prune( fd_top_votes_v2_t * top_votes,
                       uint                child_idx );

/* fd_top_votes_v2_insert_init starts an insertion session for child_idx.
   UINT_MAX parent_idx lazily initializes a root bank.  Otherwise, it
   rotates the parent's t-1 accounts into t-2 and initializes an epoch
   child with a fresh t-1 group. */

void
fd_top_votes_v2_insert_init( fd_top_votes_v2_t * top_votes,
                             uint                parent_idx,
                             uint                child_idx );

/* fd_top_votes_v2_insert_init_t_2 starts direct population of
   child_idx's t-2 set.  It clears the existing t-2 accounts and
   bank-local vote state.  Subsequent fd_top_votes_v2_insert calls add
   accounts to t-2.  This is only safe while bootstrapping an isolated
   bank whose t-2 group is not shared. */

void
fd_top_votes_v2_insert_init_t_2( fd_top_votes_v2_t * top_votes,
                                 uint                child_idx );

void
fd_top_votes_v2_insert( fd_top_votes_v2_t * top_votes,
                        fd_pubkey_t const * pubkey,
                        fd_pubkey_t const * node_account,
                        ulong               stake,
                        ushort              commission );

/* fd_top_votes_v2_update updates one t-2 vote account's bank-local
   state, replacing the latest vote slot and timestamp and setting
   is_valid.  The child and vote account must already exist. */

void
fd_top_votes_v2_update( fd_top_votes_v2_t * top_votes,
                        uint                child_idx,
                        fd_pubkey_t const * pubkey,
                        ulong               last_vote_slot,
                        long                last_vote_timestamp,
                        int                 is_valid );

int
fd_top_votes_v2_query_t_1( fd_top_votes_v2_t const * top_votes,
                           uint                      child_idx,
                           fd_pubkey_t const *       pubkey,
                           fd_pubkey_t *             node_account_out_opt,
                           ulong *                   stake_out_opt,
                           ushort *                  commission_out_opt );

/* fd_top_votes_v2_query_t_2 queries a vote account from child_idx's
   t-2 set.  Static account fields come from the shared t-2 group and
   vote state comes from child_idx's bank-local snapshot. */

int
fd_top_votes_v2_query_t_2( fd_top_votes_v2_t const * top_votes,
                           uint                      child_idx,
                           fd_pubkey_t const *       pubkey,
                           fd_pubkey_t *             node_account_out_opt,
                           ulong *                   stake_out_opt,
                           ushort *                  commission_out_opt,
                           ulong *                   last_vote_slot_out_opt,
                           long *                    last_vote_timestamp_out_opt,
                           uchar *                   is_valid_out_opt );

#define FD_TOP_VOTES_V2_ITER_FOOTPRINT (16UL)
#define FD_TOP_VOTES_V2_ITER_ALIGN     (8UL)
struct map_iter;
typedef struct map_iter fd_top_votes_v2_iter_t;

/* The t-1 and t-2 iterator APIs iterate child_idx's respective vote
   account set.  The caller owns the iterator memory. */

fd_top_votes_v2_iter_t *
fd_top_votes_v2_iter_init_t_1( fd_top_votes_v2_t const * top_votes,
                               uint                      child_idx,
                               uchar                     iter_mem[ static FD_TOP_VOTES_V2_ITER_FOOTPRINT ] );

int
fd_top_votes_v2_iter_done_t_1( fd_top_votes_v2_t const * top_votes,
                               uint                      child_idx,
                               fd_top_votes_v2_iter_t *  iter );

void
fd_top_votes_v2_iter_next_t_1( fd_top_votes_v2_t const * top_votes,
                               uint                      child_idx,
                               fd_top_votes_v2_iter_t *  iter );

void
fd_top_votes_v2_iter_ele_t_1( fd_top_votes_v2_t const * top_votes,
                              uint                      child_idx,
                              fd_top_votes_v2_iter_t *  iter,
                              fd_pubkey_t *             pubkey_out,
                              fd_pubkey_t *             node_account_out_opt,
                              ulong *                   stake_out_opt,
                              ushort *                  commission_out_opt );

fd_top_votes_v2_iter_t *
fd_top_votes_v2_iter_init_t_2( fd_top_votes_v2_t const * top_votes,
                               uint                      child_idx,
                               uchar                     iter_mem[ static FD_TOP_VOTES_V2_ITER_FOOTPRINT ] );

int
fd_top_votes_v2_iter_done_t_2( fd_top_votes_v2_t const * top_votes,
                               uint                      child_idx,
                               fd_top_votes_v2_iter_t *  iter );

void
fd_top_votes_v2_iter_next_t_2( fd_top_votes_v2_t const * top_votes,
                               uint                      child_idx,
                               fd_top_votes_v2_iter_t *  iter );

void
fd_top_votes_v2_iter_ele_t_2( fd_top_votes_v2_t const * top_votes,
                              uint                      child_idx,
                              fd_top_votes_v2_iter_t *  iter,
                              fd_pubkey_t *             pubkey_out,
                              fd_pubkey_t *             node_account_out_opt,
                              ulong *                   stake_out_opt,
                              ushort *                  commission_out_opt,
                              ulong *                   last_vote_slot_out_opt,
                              long *                    last_vote_timestamp_out_opt,
                              uchar *                   is_valid_out_opt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_top_votes_v2_h */
