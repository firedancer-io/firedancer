#ifndef HEADER_fd_src_ballet_pack_fd_pack_h
#define HEADER_fd_src_ballet_pack_fd_pack_h
#include "../fd_ballet_base.h"
#include "../../tango/fd_tango.h"
#include "../txn/fd_txn.h"
#include "fd_est_tbl.h"

/* fd_pack declares an object that does block packing.  It simulates the
   specified number of banking threads and schedules transactions to them with
   the goal of maximizing the total fees transactions in the block will pay.
   The scheduling process is aware of conflicts between transactions based on
   which accounts each transaction reads and writes.  It estimates how long a
   transaction will take to execute using the provided compute unit estimation
   table.  fd_pack is designed to operate on-line, i.e. without a priori
   knowledge of all transaction that may be scheduled in a block.

   fd_pack exposes two primary operations: inserting a transaction, and
   scheduling a transaction.  Inserting a transaction makes it available for
   scheduling later.
   The problem of optimal scheduling is NP-hard, so this implements a
   greedy approximation that's roughly O(log(n)) for both insertion and
   scheduling.  The greedy approximation is forward-only.  Within a given
   banking thread, a transaction will never be scheduled to execute prior to a
   an already-scheduled transaction.  Additionally, after a transaction has
   been scheduled, it cannot be unscheduled, even if a better choice arrives
   later.

   fd_pack is also block-aware; after scheduling enough transactions to fill a
   block, it will refuse to schedule additional transactions until told to do
   so with fd_pack_next_block. */


#define FD_PACK_ALIGN     (32UL)
/* The types in tmpl don't declare compile-time footprint macros, making it
   hard to compute the pack tile's footprint at compile time.
#define FD_PACK_TILE_SCRATCH_FOOTPRINT( bank_cnt, cu_est_tbl_sz, txn_q_sz )
   */


/* FIXME: Move this */
#define FD_MTU (1232UL)
struct fd_txn_p {
  uchar payload[FD_MTU];
  ulong payload_sz;
  ulong mline_sig;
  /* union {
    This would be ideal but doesn't work because of the flexible array member
    uchar _[FD_TXN_MAX_SZ];
    fd_txn_t txn;
  }; */
  /* Acces with TXN macro below */
  uchar _[FD_TXN_MAX_SZ] __attribute__((aligned(alignof(fd_txn_t))));
};
typedef struct fd_txn_p fd_txn_p_t;

#define TXN(txn_p) ((fd_txn_t *)( (txn_p)->_ ))



#define FD_PACK_SCHEDULE_RETVAL_ALLDONE   ((uchar)0)
#define FD_PACK_SCHEDULE_RETVAL_BANKDONE  ((uchar)1)
#define FD_PACK_SCHEDULE_RETVAL_STALLING  ((uchar)2)
#define FD_PACK_SCHEDULE_RETVAL_SCHEDULED ((uchar)3)

/* 8B, so returned in a register */
struct fd_pack_schedule_return {
  union {
    struct {
      uchar status; /* FD_PACK_SCHEDULE_RETVAL_* "enum" */
      uchar banking_thread;
      uchar mcache_emitted_cnt;
      uchar __padding;
      union {
        uint start_time; /* if SCHEDULED */
        uint stall_duration; /* if STALLING */
      };
    };
    ulong _as_ulong;
  };
};
typedef struct fd_pack_schedule_return fd_pack_schedule_return_t;

struct fd_pack_private;
typedef struct fd_pack_private fd_pack_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_pack_align( void );

FD_FN_CONST ulong
fd_pack_footprint( ulong bank_cnt,
                   ulong txnq_sz   );

void *
fd_pack_new( void *           shmem,
             ulong            bank_cnt,
             ulong            txnq_sz,
             uint             cu_limit,
             ulong            lamports_per_signature,
             fd_rng_t *       rng,
             fd_est_tbl_t *   cu_est_tbl,
             uchar *          dcache,
             void *           wksp_base,
             fd_frag_meta_t * out_mcache );

fd_pack_t *
fd_pack_join( void * shmpack );

void *
fd_pack_leave( fd_pack_t const * pack );

void *
fd_pack_delete( void * shmpack );

/* fd_pack_prepare_insert: returns the address of a slot where the next
   transaction to be scheduled should be written.  The pack object retains
   ownership of the memory, and the pointer must be passed to exactly one of
   fd_pack_insert_transaction (to actually insert it) or fd_pack_cancel_insert
   (to abort the insert, e.g. if overrun after speculative reading). */
fd_txn_p_t *
fd_pack_prepare_insert( fd_pack_t * pack );

/* fd_pack_insert_transaction: Inserts the transaction stored in transaction
   into the list of transactions that are ready to be scheduled.  pack retains
   ownership of slot, which must come from a call to prepare_insert and should
   come from the most recent call to prepare_insert. */
void
fd_pack_insert_transaction(
    fd_pack_t *  pack,
    fd_txn_p_t * transaction
);

/* fd_pack_cancel_insert: aborts a previously prepared insertion (e.g. in the
   case of overrun).  transaction must be a value returned from a
   prepare_insert call, should not already have been inerted with
   insert_transaction.  Unless the size of the freelist is adjusted,
   transaction should be from the most recent prepare call. */
void
fd_pack_cancel_insert(
    fd_pack_t *  pack,
    fd_txn_p_t * transaction
);

/* fd_pack_fully_scheduled_until: returns the scheduled start time (in CUs) of
   a hypothetical 0-CU transaction that reads and writes no accounts.  In other
   words, it's impossible for this fd_pack to schedule a transaction in this
   block to start any earlier than the returned value.  An equivalent
   characterization is that it returns the first time at which one of the
   simulated banking threads is not busy. */
uint
fd_pack_fully_scheduled_until( fd_pack_t *  pack );

/* fd_pack_available_cnt: returns the number of transactions in pack's priority
   queue that are available to be scheduled. */
FD_FN_CONST ulong
fd_pack_available_cnt( fd_pack_t const * pack );

/* Try to schedule the best transaction from those that are available to be
   scheduled. */
fd_pack_schedule_return_t
fd_pack_schedule_transaction(
    fd_pack_t * pack
    );

/* Update the state to prepare for next block.  Assumes a barrier between any
   transactions scheduled prior to the return of this call and after the return
   of this call.  Publishes any pending transactions in outq on the mcache. */
void fd_pack_next_block(
    fd_pack_t * pack
  );

/* Resets pack to a pristine state. Forgets about all pending transactions and
   all previously scheduled transactions.  Does not clear the CU estimation
   table. */
void fd_pack_reset(
    fd_pack_t * pack
  );
FD_PROTOTYPES_END
#endif /*HEADER_fd_src_ballet_pack_fd_pack_h*/
