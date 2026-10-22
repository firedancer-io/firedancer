#ifndef HEADER_fd_src_discof_replay_fd_sched_lthash_h
#define HEADER_fd_src_discof_replay_fd_sched_lthash_h

#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/lthash/fd_lthash.h"

/* This module helps the scheduler manage per-account state for
   computing a block's LtHash delta out of band.  Each staging lane has
   two maps from pubkey to an entry that tracks the account's
   subtraction and addition, one for the head block of the lane and one
   in which the block behind it builds ahead.  A pool
   of LtHash values shared by all lanes keeps the values of speculative
   additions that a later write to the account may need to undo.

   An entry is inserted the first time the lane head sees a write to the
   account, according to either fd_rdisp_add_txn() or
   fd_rdisp_add_writable(), or when a pseudo transaction is force
   created for the account.  It starts SUB_QUEUED and ADD_NONE and lives
   until the lane is reset, which also releases its speculation entry.
   The state machine implemented for each account is as follows:

                  dispatched to execrp              execrp done, delta -= value
     sub: QUEUED ---------------------> DISPATCHED ----------------------------> DONE

                                                                                                               execrp done, ptxn_idx==PIDX
                rdisp_add_pseudo_txn()==PIDX                   rdisp_get_next_ready()==PIDX                    delta += value, ptxn_idx=0
                speculative: spec_idx acquired                 and ptxn_idx==PIDX                              spec[spec_idx] = value, if any
     add: NONE -------------------------------> PENDING(PIDX) -----------------------------> DISPATCHED(PIDX) -------------------------------> DONE
           ^                                          |                                             |                                           |
           |                                       rewrite                                       rewrite                                     rewrite
           |                                     ptxn_idx=0                                    ptxn_idx=0                             delta-=spec[spec_idx]
           |                              spec_idx released, if any                     spec_idx released, if any                       spec_idx released
           |                                          |                                             |                                           |
           |                                          v                                             v                                           v
           +------------------------------------------+---------------------------------------------+-------------------------------------------+
                  PIDX surfaces or returns later and !=ptxn_idx: pseudo transaction completed or hash result dropped without effect

   A rewrite is a new first write to the account, a speculation we gave
   up, or a new pseudo transaction force inserted for it.  In the latter
   case, the block is the lane head, and the force created pseudo
   transaction will move straight onto the PENDING state.  A pseudo
   transaction created while the block is not a lane head takes effect
   when the block becomes the head.

   A speculative pseudo transaction is one the scheduler creates before
   the block has all its FEC sets, betting that the account's last write
   has happened.  A speculative addition may need to be undone after it
   is applied, so it requires a speculation entry.  A pseudo transaction
   created once the block is complete or by add_extra_pseudo_txn(), is
   no longer speculative and acquires no speculation entry, so its
   addition must not be rewritten once DONE.  This is guaranteed by
   construction.  Such a pseudo transaction is created only after every
   transaction of the block has been inserted, because the fec_eos drain
   happens after the last FEC set, and add_extra_pseudo_txn() requires a
   child staged behind the block.  So the only writes that can still
   arrive are registrations.  Registrations land before the addition can
   apply.  Start-of-block registrations run before anything else
   (including a PENDING addition) in the block gets dispatched.  Late
   ALT registrations come from serializing transactions.  A serializing
   transaction blocks every pseudo transaction inserted after it until
   it completes, and these pseudo transactions are inserted after every
   transaction of the block, so all of them wait on the last serializing
   transaction.  Each serializing transaction registers at its own
   completion, no later than the last serializing transaction's
   completion.  A rewrite therefore finds such an addition PENDING,
   which only makes it stale and needs no undo. */

#define FD_SCHED_LTHASH_LANE_CNT (4UL) /* One per staging lane. */

#define FD_SCHED_LTHASH_SUB_QUEUED     (0)
#define FD_SCHED_LTHASH_SUB_DISPATCHED (1)
#define FD_SCHED_LTHASH_SUB_DONE       (2)

#define FD_SCHED_LTHASH_ADD_NONE       (0)
#define FD_SCHED_LTHASH_ADD_PENDING    (1) /* Pseudo transaction added to rdisp, but not yet surfaced by fd_rdisp_get_next_ready(). */
#define FD_SCHED_LTHASH_ADD_DISPATCHED (2) /* Surfaced and still the addition of record.  Might be batched or immediately hashed. */
#define FD_SCHED_LTHASH_ADD_DONE       (3) /* Applied to the block's LtHash, value cached for potential undo if spec_idx is valid. */

/* This is one account in a lane's map. */
struct fd_sched_lthash_entry {
  fd_acct_addr_t acct;
  uint  map_next;
  uint  q_next;    /* Subtraction queue link while SUB_QUEUED. */
  uint  spec_idx;  /* Speculation pool entry or UINT_MAX. */
  uint  ptxn_idx;  /* Non-zero only if the entry is ADD_PENDING or ADD_DISPATCHED, otherwise 0.  High-bit set if non-zero, like the index returned from fd_rdisp_get_next_ready(). */
  uint  bank_idx;
  uchar sub_state;
  uchar add_state;
  uchar pad[ 2 ];
};
typedef struct fd_sched_lthash_entry fd_sched_lthash_entry_t;
FD_STATIC_ASSERT( sizeof(fd_sched_lthash_entry_t)==56UL, lthash_entry );

struct fd_sched_lthash;
typedef struct fd_sched_lthash fd_sched_lthash_t;

typedef uint fd_sched_lthash_iter_t;

FD_PROTOTYPES_BEGIN

/* fd_sched_lthash_{align,footprint} return the alignment and footprint
   of a memory region for an fd_sched_lthash with entry_max entries per
   lane and spec_max speculation pool entries.  footprint returns 0 unless
   entry_max is in [1,UINT_MAX/2] and spec_max is in [0,UINT_MAX]. */

ulong fd_sched_lthash_align    ( void );
ulong fd_sched_lthash_footprint( ulong entry_max, ulong spec_max );

/* fd_sched_lthash_new formats mem, which has the required alignment and
   footprint, with every lane idle and empty and every speculation entry
   free.  Seeds the lane maps with the given seed.  Returns mem, or NULL
   on bad arguments.

   fd_sched_lthash_join joins the caller to a formatted fd_sched_lthash
   and returns the local handle. */

void *
fd_sched_lthash_new( void * mem,
                     ulong  entry_max,
                     ulong  spec_max,
                     ulong  seed );

fd_sched_lthash_t *
fd_sched_lthash_join( void * mem );

/* The lane must be in [0,FD_SCHED_LTHASH_LANE_CNT).  Each lane has two
   maps, each with its own entry region, so that the block behind the
   lane head can build its entries while the head still uses its map,
   and the switch of heads only swaps the two.  A map is FREE, LIVE
   while a block owns it, or CLEANING after it is released with entries
   still to clear.  Entry indices are lane wide, map k owns
   [k*entry_max,(k+1)*entry_max), so the subtraction queue and the
   batches need not know which map an entry is in.

   fd_sched_lthash_lane_primary returns the index of the map the lane
   head owns and fd_sched_lthash_lane_spare the other one.
   fd_sched_lthash_lane_map_of returns the LIVE map owned by bank_idx,
   or ULONG_MAX.  fd_sched_lthash_map_state returns a map's
   FD_SCHED_LTHASH_MAP_* state and fd_sched_lthash_map_bank the bank
   that owns a LIVE map, else ULONG_MAX.

   fd_sched_lthash_map_claim gives a FREE map to bank_idx, which must be
   less than UINT_MAX, after clearing it in full if it was CLEANING.
   fd_sched_lthash_map_release takes a LIVE map from its owner, leaving
   it CLEANING if it has entries and FREE otherwise.  Pointers to and
   indices of its entries are invalid afterwards.
   fd_sched_lthash_map_clean clears up to max entries of a CLEANING
   map, releasing their speculation entries, and returns how many are
   left.  Clearing the last one makes the map FREE.
   fd_sched_lthash_lane_swap makes the spare map, which must be LIVE,
   the primary one.  The primary must not be LIVE.

   fd_sched_lthash_lane_bank returns the bank that owns the primary
   map, or ULONG_MAX.  fd_sched_lthash_lane_claim gives the primary map
   to bank_idx unless it owns it already.  fd_sched_lthash_lane_reset
   releases the primary map and clears it in full.
   fd_sched_lthash_lane_entry_cnt returns its entry count. */

#define FD_SCHED_LTHASH_MAP_FREE     (0)
#define FD_SCHED_LTHASH_MAP_LIVE     (1)
#define FD_SCHED_LTHASH_MAP_CLEANING (2)

ulong fd_sched_lthash_lane_primary( fd_sched_lthash_t const * l, ulong lane_idx );
ulong fd_sched_lthash_lane_spare  ( fd_sched_lthash_t const * l, ulong lane_idx );
ulong fd_sched_lthash_lane_map_of ( fd_sched_lthash_t const * l, ulong lane_idx, ulong bank_idx );
int   fd_sched_lthash_map_state   ( fd_sched_lthash_t const * l, ulong lane_idx, ulong map_idx );
ulong fd_sched_lthash_map_bank    ( fd_sched_lthash_t const * l, ulong lane_idx, ulong map_idx );
void  fd_sched_lthash_map_claim   ( fd_sched_lthash_t * l, ulong lane_idx, ulong map_idx, ulong bank_idx );
void  fd_sched_lthash_map_release ( fd_sched_lthash_t * l, ulong lane_idx, ulong map_idx );
ulong fd_sched_lthash_map_clean   ( fd_sched_lthash_t * l, ulong lane_idx, ulong map_idx, ulong max );
void  fd_sched_lthash_lane_swap   ( fd_sched_lthash_t * l, ulong lane_idx );

ulong
fd_sched_lthash_lane_bank( fd_sched_lthash_t * l,
                           ulong               lane_idx );

void
fd_sched_lthash_lane_claim( fd_sched_lthash_t * l,
                            ulong               lane_idx,
                            ulong               bank_idx );

void
fd_sched_lthash_lane_reset( fd_sched_lthash_t * l,
                            ulong               lane_idx );

ulong
fd_sched_lthash_lane_entry_cnt( fd_sched_lthash_t const * l,
                                ulong                     lane_idx );

/* fd_sched_lthash_query returns the primary map's entry for acct, or
   NULL if there is none.

   fd_sched_lthash_insert adds an entry for acct to the primary map and
   returns it as SUB_QUEUED, ADD_NONE, no speculation entry, pseudo
   transaction index 0, q_next UINT_MAX, and the map's bank as
   bank_idx.  The map must be LIVE, must not already have an entry for
   acct, and must have free entry space.  The entry lives until the map
   is released.

   fd_sched_lthash_query_map and fd_sched_lthash_insert_map do the same
   on the map map_idx names.

   fd_sched_lthash_entry_idx returns the index in [0,entry_max) of
   entry, an entry of the lane.  fd_sched_lthash_entry is the reverse of
   that. */

fd_sched_lthash_entry_t *
fd_sched_lthash_query( fd_sched_lthash_t *    l,
                       ulong                  lane_idx,
                       fd_acct_addr_t const * acct );

fd_sched_lthash_entry_t *
fd_sched_lthash_insert( fd_sched_lthash_t *    l,
                        ulong                  lane_idx,
                        fd_acct_addr_t const * acct );

fd_sched_lthash_entry_t *
fd_sched_lthash_query_map( fd_sched_lthash_t *    l,
                           ulong                  lane_idx,
                           ulong                  map_idx,
                           fd_acct_addr_t const * acct );

fd_sched_lthash_entry_t *
fd_sched_lthash_insert_map( fd_sched_lthash_t *    l,
                            ulong                  lane_idx,
                            ulong                  map_idx,
                            fd_acct_addr_t const * acct );

ulong
fd_sched_lthash_entry_idx( fd_sched_lthash_t *             l,
                           ulong                           lane_idx,
                           fd_sched_lthash_entry_t const * entry );

fd_sched_lthash_entry_t *
fd_sched_lthash_entry( fd_sched_lthash_t * l,
                       ulong               lane_idx,
                       ulong               entry_idx );

/* Applies the rewrite rule to entry when a new write to its account
   makes its addition stale.  If entry is ADD_DONE, the value in its
   speculation entry is subtracted from the block's LtHash delta.  Then
   the speculation entry is freed, entry's pseudo transaction of record
   is cleared and entry becomes ADD_NONE.  The entry must not be
   ADD_DONE without a speculation entry, since then the stale addition
   cannot be undone.  sub_state is untouched. */

void
fd_sched_lthash_entry_rewrite( fd_sched_lthash_t *       l,
                               fd_sched_lthash_entry_t * entry,
                               fd_lthash_value_t *       block_lthash );

/* fd_sched_lthash_spec_acquire takes a free speculation entry and
   returns its index, or UINT_MAX if none is free.

   fd_sched_lthash_spec_release frees the idx, which must be allocated.

   fd_sched_lthash_spec_entry returns a pointer to the value at idx,
   aligned to FD_LTHASH_ALIGN.

   fd_sched_lthash_spec_free_cnt returns the number of free entries. */

uint
fd_sched_lthash_spec_acquire( fd_sched_lthash_t * l );

void
fd_sched_lthash_spec_release( fd_sched_lthash_t * l,
                              uint                idx );

fd_lthash_value_t *
fd_sched_lthash_spec_entry( fd_sched_lthash_t * l,
                            uint                idx );

ulong
fd_sched_lthash_spec_free_cnt( fd_sched_lthash_t const * l );

/* fd_sched_lthash_iter_{init,done,next,ele} visit each entry of the
   lane's map map_idx once, in insertion order:

     for( fd_sched_lthash_iter_t it = fd_sched_lthash_iter_init( l, lane, map_idx );
          !fd_sched_lthash_iter_done( l, lane, it );
          it = fd_sched_lthash_iter_next( l, lane, it ) ) {
       fd_sched_lthash_entry_t * e = fd_sched_lthash_iter_ele( l, lane, it );
       ...
     }

   The map may be queried during the walk, but no entry may be inserted
   and the map may not be released until the walk ends.  Fields of the
   visited entries other than acct and map_next may be modified. */

fd_sched_lthash_iter_t
fd_sched_lthash_iter_init( fd_sched_lthash_t * l,
                           ulong               lane_idx,
                           ulong               map_idx );

int
fd_sched_lthash_iter_done( fd_sched_lthash_t *    l,
                           ulong                  lane_idx,
                           fd_sched_lthash_iter_t iter );

FD_WARN_UNUSED fd_sched_lthash_iter_t
fd_sched_lthash_iter_next( fd_sched_lthash_t *    l,
                           ulong                  lane_idx,
                           fd_sched_lthash_iter_t iter );

fd_sched_lthash_entry_t *
fd_sched_lthash_iter_ele( fd_sched_lthash_t *    l,
                          ulong                  lane_idx,
                          fd_sched_lthash_iter_t iter );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_replay_fd_sched_lthash_h */
