#ifndef HEADER_fd_src_flamenco_stakes_fd_vote_stakes_h
#define HEADER_fd_src_flamenco_stakes_fd_vote_stakes_h

#include "../../util/fd_util_base.h"
#include "../types/fd_types_custom.h"

/* fd_vote_stakes_t is a data structure that stores vote account stake
   updates across epoch boundaries.  It offers a mapping from vote
   account pubkeys to their t_1 and t_2 stakes.  The structure is
   designed to work with a large amount of vote accounts (in the order
   of 10s of millions) along with a relatively small number of forks
   across epoch boundaries.

   The structure is designed around these operations:
   1. Inserting updated vote account stakes into a given fork.
   2. Querying the stake for a given vote account with a given fork.

   Concurrent queries are allowed but concurrent inserts are not.  This
   is fine because the structure is only modified during boot and during
   the epoch boundary.

   Given a large number of vote accounts (e.g. 2^25 = 33,554,432), we
   need to store the pubkey, t_1 stake, and t_2 stake for each vote
   account.  We also need to store potentially ~32 forks across each
   epoch boundary.  If done naively, this would require
   2^25 * (32 + 8 + 8) * 32 = 51GB of memory not including any overhead
   for maintaining lookups for accounts.

   To avoid this, we can use some important runtime protocol properties.
   The most notable is that across forks, we will only have a small
   number of differences in vote account stakes: this is because
   realistically very few vote accounts will have differences in stakes
   that are caused by forks right before the epoch boundary.  So we can
   set our bound on elements as the total number of vote accounts +
   stakes across forks.  Let's say this is 2^26 if the max number of
   vote accounts we want to support is 2^25.  Now to store our index we
   only need:
   2^26 * (32 + 8 + 8) = 3GB of memory (not including overhead).
   Our index structure will look like this:
   pool<pubkey, stake_t_1, stake_t_2>

   What is described above the index of all vote accounts.  We need to
   account for the stakes across forks.  We have to maintain a list of
   all of the index entries used by each fork.  It is sufficient to use
   a uint list of indices into the index.  So each fork is just:
   pool<uint>.

   4 (uint pool idx) * 2^25 (# vote accounts) * 32 (# forks) = 4GiB

   For a given fork, when we insert a vote account we check if:
   1. The vote account + stake pair is already in the index.  If it is,
      we just increment a reference to the pair.  Add it to the list of
      pool indices that the fork maintains.
   2. The vote account + stake pair is not in the index.  If it is not,
      we need to insert it into the index and assume a reference of 1.
      Add it to the local list of pool indices that the fork maintains.
   In order to make both of these cases performant we need a mapping
   from pubkey + stake to the index pool element.  This is simply
   represented as:
   map<(pubkey+stake), index_pool_idx>.

   Now for queries, we need a way to query the t_1 and t_2 stake for a
   pubkey on a given fork.  The problem is the above map requires the
   t_1 stake as part of the key and there are potentially multiple
   entries for a given pubkey.  This is solved with a
   multi_map<pubkey, index_pool_idx>.  We query for a given pubkey and
   iterate through all of the entries: this is an acceptable trade-off
   since there will almost always be one element for a given pubkey
   (except around the epoch boundary).  However, for each index entry
   we need a way to make sure that it's the one that is in our fork's
   list of indices.  This is solved with a map for each fork that is
   keyed by the index pool idx.
   map<index_pool_idx, fork list entry>.

   Now, we can quickly insert entries for a given fork and also do fast
   queries for a given pubkey.

   The only remaining operation is updating the root fork.  If we are
   updating which fork is the root, we can safely assume that all other
   forks are no longer valid:
   1. either the fork was a competing fork that executed the epoch
      boundary and is no longer needed
   2. the fork corresponds to a fork for the previous epoch boundary.

   For any fork that's being removed, we need to reset its fork's pool
   and remove any references to the index pool entries.  If an index
   entry has a reference count of 0, we can remove it from the index
   entirely.  Under the hood, the forks in use are stored in a deque;
   when a root is being advanced, all entries from the deque are removed
   and each removed fork's entries are released.

   The memory footprint of what is actually described above is larger
   because each key of the index needs to be a compound of
   the pubkey, stake_t_1, node_account_t_1, and epoch.

   As an important note, the vote stakes object can be used globally
   across different threads, but it is not safe to access concurrently.
   The caller is responsible for ensuring that reads and writes are
   properly synchronized. */

FD_PROTOTYPES_BEGIN

#define FD_VOTE_STAKES_ALIGN (128UL)

struct fd_vote_stakes;
typedef struct fd_vote_stakes fd_vote_stakes_t;

/* fd_vote_stakes_align returns the minimum alignment required for the
   fd_vote_stakes_t struct. */

ulong
fd_vote_stakes_align( void );

/* fd_vote_stakes_footprint returns the minimum footprint required for
   the fd_vote_stakes_t object given the max number of vote accounts,
   the max fork width (number of forks that can cross the epoch
   boundary), and the max number of map chains.  The map chains should
   be a power of 2 that is roughly equal to the expected number of vote
   accounts and not the maximum. */

ulong
fd_vote_stakes_footprint( ulong max_vote_accounts,
                          ulong expected_vote_accounts,
                          ulong max_fork_width );


/* fd_vote_stakes_new creates a new fd_vote_stakes_t object given a
   region of memory sized out according to fd_vote_stakes_footprint. */

void *
fd_vote_stakes_new( void * shmem,
                    ulong  max_vote_accounts,
                    ulong  expected_vote_accounts,
                    ulong  max_fork_width,
                    ulong  seed );


/* fd_vote_stakes_join joins a valid fd_vote_stakes_t object from a
   region of memory. */

fd_vote_stakes_t *
fd_vote_stakes_join( void * shmem );

/* fd_vote_stakes_root_{insert, update, purge}_key are APIs for
   inserting, updating, and purging keys for the root fork.  These
   operations are split out in order to support the snapshot loading
   process.  The set of stakes from the T-1 epoch are inserted into
   the root fork with a call to fd_vote_stakes_root_insert_key.  The
   set of stakes from the T-2 epoch are updated with a call to
   fd_vote_stakes_root_update_meta.  The caller is responsible for
   ensuring that for a given pubkey, insert_key is called before
   update_meta.  It is important that these APIs should only be called
   while the root fork is the only and current fork in use.

   If update_meta is called on a key that has not had a corresponding
   insert_key call, a key is created into the root fork with a t-1 stake
   of 0.  This usually means the vote account has been deleted, but it
   can be possible in the case where the only staker of a vote account
   has been marked delinquent in epoch T-1 and needs to be counted
   towards clock calculation for the rest of the epoch. */

void
fd_vote_stakes_root_insert_key( fd_vote_stakes_t *  vote_stakes,
                                fd_pubkey_t const * pubkey,
                                fd_pubkey_t const * node_account_t_1,
                                ulong               stake_t_1,
                                ulong               epoch );

void
fd_vote_stakes_root_update_meta( fd_vote_stakes_t *  vote_stakes,
                                 fd_pubkey_t const * pubkey,
                                 fd_pubkey_t const * node_account_t_2,
                                 ulong               stake_t_2,
                                 ulong               epoch );

/* fd_vote_stakes_root_purge_key allows the caller to purge a key from
   the root fork.  This unfortunately has to be decoupled from the other
   root APIs due to quirks in the Solana protocol.  The elements of the
   vote stakes are loaded in along with the snapshot manifest: before
   the actual account data has been loaded.  Some vote stakes keys may
   be stale however, and can only be removed after the account data has
   been loaded. */

void
fd_vote_stakes_root_purge_key( fd_vote_stakes_t *  vote_stakes,
                               fd_pubkey_t const * pubkey );

/* fd_vote_stakes_insert_{key, update, fini} is API for inserting
   entries into a given fork.  It reflects the access pattern during
   epoch rewards, where the current stake for a vote account is
   accumulated by iterating over the set of vote accounts.  The caller
   is responsible for ensuring that fd_vote_stakes_insert_key is only
   called once for each vote account.  It is unsafe to call any
   other vote_stakes API between calls to insert_key and insert_fini
   except other insert_* APIs.

   The calling pattern is as follows:

   for each vote account: call fd_vote_stakes_insert_key() once
   for each stake delegation: call fd_vote_stakes_insert_update()

   after all entries are inserted, call fd_vote_stakes_insert_fini()

   Under the hood, insert_key inserts an entry into the fork's map and
   into the index.  Each call to insert_update increments the stake for
   the given vote account.  insert_fini will either dedup the entry if
   one already exists, or insert a new map entry.  */

void
fd_vote_stakes_insert_key( fd_vote_stakes_t *  vote_stakes,
                           ushort              fork_idx,
                           fd_pubkey_t const * pubkey,
                           fd_pubkey_t const * node_account_t_1,
                           fd_pubkey_t const * node_account_t_2,
                           ulong               stake_t_2,
                           ulong               epoch );

void
fd_vote_stakes_insert_update( fd_vote_stakes_t *  vote_stakes,
                              ushort              fork_idx,
                              fd_pubkey_t const * pubkey,
                              ulong               stake );

void
fd_vote_stakes_insert_fini( fd_vote_stakes_t * vote_stakes,
                            ushort             fork_idx );

/* fd_vote_stakes_genesis_fini finalizes the vote stakes on the genesis
   block.  Any vote stakes that have been inserted will be updated to
   have identical T-1/T-2 stakes and node accounts.  This function
   assumes that all vote accounts have already been inserted into the
   genesis fork. */

void
fd_vote_stakes_genesis_fini( fd_vote_stakes_t * vote_stakes );

/* fd_vote_stakes_new_child creates a new child fork and returns the
   index identifier for the new fork. */

ushort
fd_vote_stakes_new_child( fd_vote_stakes_t * vote_stakes );

/* fd_vote_stakes_advance_root will move the root fork to the new
   candidate root fork.  If the root_idx is equal to the root, this
   function is a no-op.  However, if the root is different, all other
   child nodes will be removed from the structure. */

void
fd_vote_stakes_advance_root( fd_vote_stakes_t * vote_stakes,
                             ushort             root_idx );

/* fd_vote_stakes_query_stake queries the stake for a given vote account
   in the given fork.  If the element is found returns 1, otherwise
   returns 0.  If any of the optional fields are set to NULL, then their
   corresponding value will not be set. */

int
fd_vote_stakes_query( fd_vote_stakes_t *  vote_stakes,
                      ushort              fork_idx,
                      fd_pubkey_t const * pubkey,
                      ulong *             stake_t_1_out_opt,
                      ulong *             stake_t_2_out_opt,
                      fd_pubkey_t *       node_account_t_1_out_opt,
                      fd_pubkey_t *       node_account_t_2_out_opt );

/* fd_vote_stakes_ele_cnt returns the number of entries for a given
   fork. */

uint
fd_vote_stakes_ele_cnt( fd_vote_stakes_t * vote_stakes,
                        ushort             fork_idx );

/* fd_vote_stakes_get_root_idx returns the index of the root fork. */

ushort
fd_vote_stakes_get_root_idx( fd_vote_stakes_t * vote_stakes );

/* fd_vote_stakes_reset resets the vote stakes object to the initial
   state.  This is useful for resetting vote stakes if a new snapshot
   manifest is being loaded. */

void
fd_vote_stakes_reset( fd_vote_stakes_t * vote_stakes );

#define FD_VOTE_STAKES_ITER_FOOTPRINT (16UL)
#define FD_VOTE_STAKES_ITER_ALIGN     (8UL)
struct stakes_map_iter_t;
typedef struct stakes_map_iter_t fd_vote_stakes_iter_t;

/* A caller can iterate through the entries for a given fork.  The
   iterator is initialized by a call to fd_vote_stakes_fork_iter_init.
   The caller is responsible for managing the memory for the iterator.
   It is safe to call fd_vote_stakes_fork_iter_next if the result of
   fd_vote_stakes_fork_iter_done() == 0.  It is safe to call
   fd_vote_stakes_fork_iter_ele() to get the current entry if there is
   a valid initialized iterator.  fd_vote_stakes_fork_iter_next is
   called to advance the iterator.

   It is not safe to call any other vote stakes apis while an iteration
   is in progress.

   Example use:
   uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
   for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_fork_iter_init( vote_stakes, fork_idx, iter_mem );
        !fd_vote_stakes_fork_iter_done( vote_stakes, fork_idx, iter );
        fd_vote_stakes_fork_iter_next( vote_stakes, fork_idx, iter ) ) {
     fd_vote_stakes_fork_iter_ele( vote_stakes, fork_idx, iter, &pubkey, &stake_t_1, &stake_t_2, &node_account_t_1, &node_account_t_2 );
   }

   Under the hood, the vote stakes iterator is a wrapper of the map
   chain iterator.

   TODO: fork_idx can probably get absorbed into the iterator. */

fd_vote_stakes_iter_t *
fd_vote_stakes_fork_iter_init( fd_vote_stakes_t * vote_stakes,
                               ushort             fork_idx,
                               uchar              iter_mem[ static FD_VOTE_STAKES_ITER_FOOTPRINT ] );

int
fd_vote_stakes_fork_iter_done( fd_vote_stakes_t *      vote_stakes,
                               ushort                  fork_idx,
                               fd_vote_stakes_iter_t * iter );

void
fd_vote_stakes_fork_iter_next( fd_vote_stakes_t *      vote_stakes,
                               ushort                  fork_idx,
                               fd_vote_stakes_iter_t * iter );

void
fd_vote_stakes_fork_iter_ele( fd_vote_stakes_t *      vote_stakes,
                              ushort                  fork_idx,
                              fd_vote_stakes_iter_t * iter,
                              fd_pubkey_t *           pubkey_out,
                              ulong *                 stake_t_1_out_opt,
                              ulong *                 stake_t_2_out_opt,
                              fd_pubkey_t *           node_account_t_1_out_opt,
                              fd_pubkey_t *           node_account_t_2_out_opt );

FD_PROTOTYPES_END

#endif
