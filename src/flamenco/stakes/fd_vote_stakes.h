#ifndef HEADER_fd_src_flamenco_stakes_fd_vote_stakes_h
#define HEADER_fd_src_flamenco_stakes_fd_vote_stakes_h

#include "../../util/fd_util_base.h"
#include "../fd_flamenco_base.h"
#include "../accdb/fd_accdb_base.h"
#include "../runtime/program/vote/fd_vote_codec.h"

#define FD_VOTE_STAKES_ALIGN                (128UL)
#define FD_VOTE_STAKES_ALPENGLOW_RANK_NULL  USHORT_MAX

/* fd_vote_stakes is the Firedancer equivalent of the Agave epoch stakes
   data structure.  It is a fork aware data structure that maintains the
   vote account state that is used for clock and VM syscall calculations
   during execution.

   The underlying data structure is a tiered set of caches:
   - t-2/t-3: these are caches used for the vote account states at the
     end of the t-2 epoch and the t-3 epoch assuming you are currently
     in the t epoch.  These caches are shared across all forks.
   - t-1: these are sized to max_fork_width and are computed at the
     most recent epoch boundary.  These caches are ref-cnt'd and fork
     specific.  After the epoch boundary slot is rooted, then there will
     only be 1 active t-1 cache.
   - state: each bank has its own view of the t-2 state of vote
     accounts.  This is what is actually used for clock calculations
     which is a stake weighted median of the last vote slot and
     timestamp.

   fd_vote_stakes also handles the creation of new vote stakes caches.
   The creation of new vote stakes caches happens at the epoch boundary
   and follows the rules defined in the validator_admission_ticket
   feature where every vote account must be in the top 2000 by stake.
   Under the hood, this is managed by a stake-sorted heap that is shared
   across all forks.

   NOTE:
   This system assumes that multiple forks can cross an epoch boundary
   but only one epoch boundary can be crossed at a time.  This means
   that there can be multiple t-1 forks after an epoch boundary, but
   only one will be active when the first fork crosses into an epoch
   boundary.  Similarly, this means that there will be 2 t-2 sets active
   during an epoch boundary crossing and 1 most of the time. */

struct fd_vote_stakes;
typedef struct fd_vote_stakes fd_vote_stakes_t;

FD_PROTOTYPES_BEGIN

ulong
fd_vote_stakes_align( void );

ulong
fd_vote_stakes_footprint( ulong max_live_slots,
                          ulong max_fork_width );

void *
fd_vote_stakes_new( void * mem,
                    ulong  max_live_slots,
                    ulong  max_fork_width,
                    ulong  seed );

fd_vote_stakes_t *
fd_vote_stakes_join( void * mem );

/* fd_vote_stakes_fork_epoch returns the epoch of the fork. */

ulong
fd_vote_stakes_fork_epoch( ulong fork_id );

/* fd_vote_stakes_init initializes the vote stakes data structure for a
   given epoch. */

ulong
fd_vote_stakes_init( fd_vote_stakes_t * vote_stakes,
                     ulong              epoch );

/* fd_vote_stakes_reset resets the vote stakes data structure. */

void
fd_vote_stakes_reset( fd_vote_stakes_t * vote_stakes );

/* fd_vote_stakes_snap_insert_t_1 inserts a new vote account into the
   t-1 set.  This skips over any vote account validation and should
   only be used when loading in vote accounts from a snapshot. */

void
fd_vote_stakes_snap_insert_t_1( fd_vote_stakes_t *  vote_stakes,
                                ulong               fork_id,
                                fd_pubkey_t const * pubkey,
                                fd_pubkey_t const * node_account,
                                ulong               stake,
                                ushort              commission,
                                uchar const         bls_key[ static FD_BLS_PUBKEY_COMPRESSED_SZ ] );

/* fd_vote_stakes_snap_insert_t_2 inserts a new vote account into the
   t-2 set.  This skips over any vote account validation and should
   only be used when loading in vote accounts from a snapshot. */

void
fd_vote_stakes_snap_insert_t_2( fd_vote_stakes_t *  vote_stakes,
                                ulong               fork_id,
                                fd_pubkey_t const * pubkey,
                                fd_pubkey_t const * node_account,
                                ulong               stake,
                                ushort              commission,
                                uchar const         bls_key[ static FD_BLS_PUBKEY_COMPRESSED_SZ ] );

/* fd_vote_stakes_snap_insert_t_3 inserts a new vote account into the
   t-3 set.  This skips over any vote account validation and should
   only be used when loading in vote accounts from a snapshot. */

void
fd_vote_stakes_snap_insert_t_3( fd_vote_stakes_t *  vote_stakes,
                                ulong               fork_id,
                                fd_pubkey_t const * pubkey,
                                fd_pubkey_t const * node_account,
                                ulong               stake,
                                ushort              commission,
                                uchar const         bls_key[ static FD_BLS_PUBKEY_COMPRESSED_SZ ] );

/* fd_vote_stakes_insert inserts a new vote account into the t-1 set.
   This can be called repeatedly after a boundary-crossing
   fd_vote_stakes_new_fork.  An account will only be inserted if it
   matches the semantics of the validator_admission_ticket feature.
   The top 2000 vote accounts by stake are inserted into the t-1 set. */

void
fd_vote_stakes_insert( fd_vote_stakes_t *  vote_stakes,
                       ulong               fork_id,
                       fd_pubkey_t const * pubkey,
                       fd_pubkey_t const * node_account,
                       ulong               stake,
                       ushort              commission,
                       uchar const         bls_key[ static FD_BLS_PUBKEY_COMPRESSED_SZ ] );

/* fd_vote_stakes_finalize assigns Alpenglow ranks to the resident
   epoch-stakes set for epoch.  Accounts with invalid BLS keys or
   duplicate BLS/identity keys retain
   FD_VOTE_STAKES_ALPENGLOW_RANK_NULL but remain in the set.  This is a
   no-op if the set is not resident. */

void
fd_vote_stakes_finalize( fd_vote_stakes_t * vote_stakes,
                         ulong              epoch );

/* fd_vote_stakes_purge_fork removes a t-1 set.  This should be called
   when the banks are evicting a bank or during root advancement. */

void
fd_vote_stakes_purge_fork( fd_vote_stakes_t * vote_stakes,
                           ulong              fork_id );

/* fd_vote_stakes_new_fork creates a child of the given parent fork.
   Within an epoch, the child shares the parent's t-1 set and receives a
   copy of its t-2 state.  At an epoch boundary, it rotates t-1 into
   t-2 and acquires fresh t-1 and t-2 state. */

ulong
fd_vote_stakes_new_fork( fd_vote_stakes_t * vote_stakes,
                         ulong              parent_fork_id,
                         ulong              epoch );

/* fd_vote_stakes_update updates the vote account state for a given
   fork id.  It is a no-op if the pubkey corresponds to an account not
   in the t-2 set.  If is_valid==0, the last vote arguments will be
   ignored. */

void
fd_vote_stakes_update_state( fd_vote_stakes_t *  vote_stakes,
                             ulong               fork_id,
                             fd_pubkey_t const * pubkey,
                             ulong               last_vote_slot,
                             long                last_vote_ts,
                             uchar               is_valid );

void
fd_vote_stakes_refresh( fd_vote_stakes_t * vote_stakes,
                        ulong              fork_id,
                        fd_accdb_t *        accdb,
                        fd_accdb_fork_id_t  accdb_fork_id );

/* fd_vote_stakes_query_t_1 queries the fork's t-1 vote account.
   Returns 1 if the account exists in t-1 and 0 otherwise. */

int
fd_vote_stakes_query_t_1( fd_vote_stakes_t const * vote_stakes,
                          ulong                    fork_id,
                          fd_pubkey_t const *      pubkey,
                          fd_pubkey_t *            node_account_out_opt,
                          ulong *                  stake_out_opt,
                          ushort *                 commission_out_opt );

/* fd_vote_stakes_query_t_2 queries the t-2 vote account and fork-local
   vote state.  Returns 1 if the account exists in t-2 and 0 otherwise. */

int
fd_vote_stakes_query_t_2( fd_vote_stakes_t const * vote_stakes,
                          ulong                    fork_id,
                          fd_pubkey_t const *      pubkey,
                          fd_pubkey_t *            node_account_out_opt,
                          ulong *                  stake_out_opt,
                          ulong *                  last_vote_slot_out_opt,
                          long *                   last_vote_ts_out_opt,
                          ushort *                 commission_out_opt,
                          uchar *                  is_valid_out_opt );

/* fd_vote_stakes_query_t_3 queries the fork's t-3 vote account.
   Returns 1 if the account exists in t-3 and 0 otherwise. */

int
fd_vote_stakes_query_t_3( fd_vote_stakes_t const * vote_stakes,
                          ulong                    fork_id,
                          fd_pubkey_t const *      pubkey,
                          fd_pubkey_t *            node_account_out_opt,
                          ulong *                  stake_out_opt,
                          ushort *                 commission_out_opt );

/* fd_vote_stakes_cnt_t_{1,2} returns the number of vote accounts in the
   t-1 and t-2 sets respectively. */

ulong
fd_vote_stakes_cnt_t_1( fd_vote_stakes_t const * vote_stakes,
                        ulong                    fork_id );

ulong
fd_vote_stakes_cnt_t_2( fd_vote_stakes_t const * vote_stakes,
                        ulong                    fork_id );

/* fd_vote_stakes_total_stake returns the total stake of the epoch
   stakes set for epoch.
   epoch must be the current (the t-2 set) or the one before it
   (the t-3 set); returns 0 if that epoch's set is not resident. */

ulong
fd_vote_stakes_total_stake( fd_vote_stakes_t const * vote_stakes,
                            ulong                    epoch );

/* The iterator will NOT skip over invalid vote accounts
   intentionally.  The reason being is that invalid vote accounts are
   still considered for stake and leader calculations: the caller is
   expected to handle the state of each account correctly. */

#define FD_VOTE_STAKES_ITER_FOOTPRINT     (16UL)
#define FD_VOTE_STAKES_ITER_ALIGN         (8UL)
#define FD_VOTE_STAKES_ITER_T_1           (1)
#define FD_VOTE_STAKES_ITER_T_2           (2)
#define FD_VOTE_STAKES_ITER_T_3           (3)

struct vacc_map_iter;
typedef struct vacc_map_iter fd_vote_stakes_iter_t;

/* The iterator accesses the fork's t-1, t-2, or t-3 set according to
   iter_kind.  Fork-local vote state outputs may only be requested for
   FD_VOTE_STAKES_ITER_T_2. */

fd_vote_stakes_iter_t *
fd_vote_stakes_iter_init( fd_vote_stakes_t const * vote_stakes,
                          ulong                    fork_id,
                          int                      iter_kind,
                          uchar                    iter_mem[ static FD_VOTE_STAKES_ITER_FOOTPRINT ] );

int
fd_vote_stakes_iter_done( fd_vote_stakes_t const * vote_stakes,
                          ulong                    fork_id,
                          int                      iter_kind,
                          fd_vote_stakes_iter_t *  iter );

void
fd_vote_stakes_iter_next( fd_vote_stakes_t const * vote_stakes,
                          ulong                    fork_id,
                          int                      iter_kind,
                          fd_vote_stakes_iter_t *  iter );

void
fd_vote_stakes_iter_ele( fd_vote_stakes_t const * vote_stakes,
                         ulong                    fork_id,
                         int                      iter_kind,
                         fd_vote_stakes_iter_t *  iter,
                         fd_pubkey_t *            pubkey_out,
                         fd_pubkey_t *            node_account_out_opt,
                         ulong *                  stake_out_opt,
                         ulong *                  last_vote_slot_out_opt,
                         long *                   last_vote_ts_out_opt,
                         ushort *                 commission_out_opt,
                         uchar *                  is_valid_out_opt,
                         ushort *                 alpenglow_rank_out_opt,
                         uchar                    bls_key_out_opt[ FD_BLS_PUBKEY_COMPRESSED_SZ ] );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_vote_stakes_h */
