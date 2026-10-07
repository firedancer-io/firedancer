#ifndef HEADER_fd_src_discof_replay_fd_sched_lthash_h
#define HEADER_fd_src_discof_replay_fd_sched_lthash_h

#include "../../ballet/txn/fd_txn.h"
#include "../../ballet/lthash/fd_lthash.h"
#include "../../util/tmpl/fd_map.h"

/* fd_sched_lthash is fd_sched's per-account state for computing a
   block's LtHash delta out of band.  Each staging lane has a map from
   account address to an entry that tracks the account's subtraction and
   addition for the one bank the lane is claimed by.  A pool of hash
   slots shared by all lanes keeps the values of additions that a later
   write to the account may need to undo.  fd_sched drives the states;
   this module stores them and implements the rewrite rule. */

#define FD_SCHED_LTHASH_LANE_CNT (4UL) /* one per staging lane */

#define FD_SCHED_LTHASH_SUB_QUEUED     (0) /* owed, on the block's sub queue */
#define FD_SCHED_LTHASH_SUB_DISPATCHED (1) /* hashing the parent's value on a tile */
#define FD_SCHED_LTHASH_SUB_DONE       (2) /* applied to the block's delta */
#define FD_SCHED_LTHASH_ADD_NONE       (0) /* no live addition */
#define FD_SCHED_LTHASH_ADD_PENDING    (1) /* created, not yet surfaced by fd_rdisp_get_next_ready */
#define FD_SCHED_LTHASH_ADD_DISPATCHED (2) /* hashing on a tile */
#define FD_SCHED_LTHASH_ADD_DONE       (3) /* applied to the block's delta, value in the slot if hash_idx is valid */

/* fd_sched_lthash_entry_t is one account in a lane's map.  ptxn_idx,
   the ticket, is the addition pseudo-transaction the entry believes in.
   It is non-zero only while the entry is ADD_PENDING or ADD_DISPATCHED.
   A pseudo-transaction that surfaces or returns a result is honoured
   only if its index equals the ticket.  That makes staleness a single
   comparison with no generation count, since a rewrite clears the
   ticket, the next pop installs a new one, and every older
   pseudo-transaction mismatches it. */

struct fd_sched_lthash_entry {
  fd_acct_addr_t acct;      /* map key */
  uint  map_next;           /* fd_map_chain link */
  uint  q_next;             /* sub queue link while SUB_QUEUED, free list link while free */
  uint  hash_idx;           /* hash pool slot or UINT_MAX */
  uint  ptxn_idx;           /* ticket: live addition pseudo-txn incl. FD_RDISP_LTHASH_PSEUDO_TXN, or 0 */
  uint  bank_idx;           /* bank the states describe */
  uchar sub_state;
  uchar add_state;
  uchar pad[ 2 ];
};
typedef struct fd_sched_lthash_entry fd_sched_lthash_entry_t;
FD_STATIC_ASSERT( sizeof(fd_sched_lthash_entry_t)==56UL, lthash_entry );

struct fd_sched_lthash;
typedef struct fd_sched_lthash fd_sched_lthash_t;

/* fd_sched_lthash_iter_t is a position in a walk over a lane's entries
   (the lane map's fd_map_chain iterator).  Treat it as opaque. */

typedef struct fd_map_chain_iter fd_sched_lthash_iter_t;

FD_PROTOTYPES_BEGIN

/* fd_sched_lthash_{align,footprint} return the alignment and footprint
   of a memory region for an fd_sched_lthash with entry_max entries per
   lane and hash_max hash slots.  footprint returns 0 unless entry_max
   is in [1,UINT_MAX] and hash_max is in [0,UINT_MAX]. */

ulong fd_sched_lthash_align    ( void );
ulong fd_sched_lthash_footprint( ulong entry_max, ulong hash_max );

/* fd_sched_lthash_new formats mem, which has the required alignment and
   footprint, with every lane idle and empty and every hash slot free.
   seed seeds the lane maps.  Returns mem, or NULL on bad arguments
   (logs details).  The caller is not joined on return.

   fd_sched_lthash_join joins the caller to a formatted fd_sched_lthash
   and returns the local handle. */

void *
fd_sched_lthash_new( void * mem,
                     ulong  entry_max,
                     ulong  hash_max,
                     ulong  seed );

fd_sched_lthash_t *
fd_sched_lthash_join( void * mem );

/* Below, lane is in [0,FD_SCHED_LTHASH_LANE_CNT).

   fd_sched_lthash_lane_bank returns the bank the lane is claimed by, or
   ULONG_MAX if the lane is idle.

   fd_sched_lthash_lane_claim claims the lane for bank_idx, which must
   be less than UINT_MAX.  The lane must be idle or already claimed by
   bank_idx.  CRITs otherwise. */

ulong
fd_sched_lthash_lane_bank( fd_sched_lthash_t * l,
                           ulong               lane );

void
fd_sched_lthash_lane_claim( fd_sched_lthash_t * l,
                            ulong               lane,
                            ulong               bank_idx );

/* fd_sched_lthash_query returns the lane's entry for acct, or NULL if
   there is none.

   fd_sched_lthash_insert adds an entry for acct to the lane and returns
   it: SUB_QUEUED, ADD_NONE, no slot, ticket 0, q_next UINT_MAX, and the
   lane's bank as bank_idx.  CRITs if the lane is idle, already has an
   entry for acct, or has no free entry.  The entry lives until the lane
   is reset.

   fd_sched_lthash_entry_idx returns the index in [0,entry_max) of e, an
   entry of the lane, and fd_sched_lthash_entry returns the entry at
   index idx in [0,entry_max).

   fd_sched_lthash_lane_cnt returns the number of entries in the lane.

   fd_sched_lthash_lane_reset frees every entry of the lane along with
   its slot, if any, empties the map and makes the lane idle.  For an
   empty lane it only makes the lane idle.  Pointers to and indices of
   the lane's entries are invalid afterwards. */

fd_sched_lthash_entry_t *
fd_sched_lthash_query( fd_sched_lthash_t *    l,
                       ulong                  lane,
                       fd_acct_addr_t const * acct );

fd_sched_lthash_entry_t *
fd_sched_lthash_insert( fd_sched_lthash_t *    l,
                        ulong                  lane,
                        fd_acct_addr_t const * acct );

ulong
fd_sched_lthash_entry_idx( fd_sched_lthash_t *             l,
                           ulong                           lane,
                           fd_sched_lthash_entry_t const * e );

fd_sched_lthash_entry_t *
fd_sched_lthash_entry( fd_sched_lthash_t * l,
                       ulong               lane,
                       ulong               idx );

ulong
fd_sched_lthash_lane_cnt( fd_sched_lthash_t const * l,
                          ulong                     lane );

void
fd_sched_lthash_lane_reset( fd_sched_lthash_t * l,
                            ulong               lane );

/* fd_sched_lthash_iter_{init,done,next,ele} visit each entry of the
   lane once, in no particular order:

     for( fd_sched_lthash_iter_t it = fd_sched_lthash_iter_init( l, lane );
          !fd_sched_lthash_iter_done( l, lane, it );
          it = fd_sched_lthash_iter_next( l, lane, it ) ) {
       fd_sched_lthash_entry_t * e = fd_sched_lthash_iter_ele( l, lane, it );
       ...
     }

   As with any fd_map_chain walk, entries of the lane must not be
   inserted, removed (fd_sched_lthash_lane_reset) or queried until the
   walk ends.  Fields of the visited entries other than acct and
   map_next may be modified.  next and ele assume the walk is not
   done. */

fd_sched_lthash_iter_t
fd_sched_lthash_iter_init( fd_sched_lthash_t * l,
                           ulong               lane );

int
fd_sched_lthash_iter_done( fd_sched_lthash_t *    l,
                           ulong                  lane,
                           fd_sched_lthash_iter_t it );

FD_WARN_UNUSED fd_sched_lthash_iter_t
fd_sched_lthash_iter_next( fd_sched_lthash_t *    l,
                           ulong                  lane,
                           fd_sched_lthash_iter_t it );

fd_sched_lthash_entry_t *
fd_sched_lthash_iter_ele( fd_sched_lthash_t *    l,
                          ulong                  lane,
                          fd_sched_lthash_iter_t it );

/* fd_sched_lthash_slot_acquire takes a free hash slot and returns its
   index, or UINT_MAX if none is free.  fd_sched_lthash_slot_release
   frees slot idx, which must be held; CRITs if idx is out of range or
   every slot is already free.  fd_sched_lthash_slot returns a pointer
   to the value in slot idx, aligned to FD_LTHASH_ALIGN.
   fd_sched_lthash_slot_free_cnt returns the number of free slots. */

uint
fd_sched_lthash_slot_acquire( fd_sched_lthash_t * l );

void
fd_sched_lthash_slot_release( fd_sched_lthash_t * l,
                              uint                idx );

fd_lthash_value_t *
fd_sched_lthash_slot( fd_sched_lthash_t * l,
                      uint                idx );

ulong
fd_sched_lthash_slot_free_cnt( fd_sched_lthash_t const * l );

/* fd_sched_lthash_entry_rewrite applies the rewrite rule to e when a
   new write to its account makes its addition stale.  If e is ADD_DONE,
   the value in its slot is subtracted from delta, the block's LtHash
   delta, which must not be a slot.  Then any slot is freed, the ticket
   is cleared and e becomes ADD_NONE.  sub_state is untouched.  e must
   not be ADD_DONE without a slot, since that addition cannot be undone;
   CRITs if it is. */

void
fd_sched_lthash_entry_rewrite( fd_sched_lthash_t *       l,
                               fd_sched_lthash_entry_t * e,
                               fd_lthash_value_t *       delta );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_replay_fd_sched_lthash_h */
