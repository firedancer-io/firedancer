#ifndef HEADER_fd_src_ballet_pack_fd_pack_h
#define HEADER_fd_src_ballet_pack_fd_pack_h
#include "../fd_ballet_base.h"
#include "../../tango/fd_tango_base.h"
#include "../txn/fd_txn.h"
#include "fd_est_tbl.h"


#define FD_PACK_TILE_SCRATCH_ALIGN     (32UL)
/* The types in tmpl don't declare compile-time footprint macros, making it
   hard to compute the pack tile's footprint at compile time.
#define FD_PACK_TILE_SCRATCH_FOOTPRINT( bank_cnt, cu_est_tbl_sz, txn_q_sz )
   */

#define FD_MTU (1232UL) /* FIXME: Move this */

/* FIXME: Move this */
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


/* Define the big max-heap that we pull transactions off to schedule. The
   priority is given by reward/compute.  We may want to add in some additional
   terms at a later point. */

struct fd_pack_private_orderable_txn {
  /* We want rewards*compute_est to fit in a ulong so that r1/c1 < r2/c2 can be
     computed as r1*c2 < r2*c1, with the product fitting in a ulong.
     compute_est has a small natural limit of mid-20 bits. rewards doesn't have
     a natural limit, so there is some argument to be made for raising the
     limit for rewards to 40ish bits. The struct has better packing with
     uint/uint though. */
  uint         rewards; /* in Lamports */
  uint         compute_est; /* in compute units */
  uint         compute_max;
  float        compute_var; /* An estimate of the variance associated with compute_est */
  fd_txn_p_t * txnp;
  ulong        __padding_reserved;
};
typedef struct fd_pack_private_orderable_txn fd_pack_orderable_txn_t;



struct fd_pack_private_addr_use_record {
  uchar * key; /* Pointer to account address */
  uint    hash; /* First 32 bits of account address */
  uint    in_use_until;
  ulong   in_use_until_var; /* FIXME: Test if 64bit hash, float var is better */
  uchar   in_use_for_bank;
  uchar   _padding[7];
};
typedef struct fd_pack_private_addr_use_record fd_pack_addr_use_t;



struct fd_pack_private_bank_status {
  int        done;
  uint       in_use_until;
  ulong      in_use_until_var;
};
typedef struct fd_pack_private_bank_status fd_pack_bank_status_t;


FD_PROTOTYPES_BEGIN
/* Declare all the data structures */

#define DEQUE_NAME freelist
#define DEQUE_T    ulong
#include "../../util/tmpl/fd_deque_dynamic.c"


/* Returns 1 if x.rewards/x.compute < y.rewards/y.compute. Not robust. */
#define COMPARE_WORSE(x,y) ( ((ulong)((x).rewards)*(ulong)((y).compute_est)) < ((ulong)((y).rewards)*(ulong)((x).compute_est)) )

#define PRQ_NAME txnq
#define PRQ_T    fd_pack_orderable_txn_t
#define PRQ_EXPLICIT_TIMEOUT 0
#define PRQ_AFTER(x,y)     COMPARE_WORSE(x,y)
#include "../../util/tmpl/fd_prq.c"

/* Define a small min-heap for transactions we've scheduled but not emitted in
   the output mcache yet. We'll overload the tspub field for this, since we
   don't need the value and it fits our needs perfectly. */
#define PRQ_NAME        outq
#define PRQ_T           fd_frag_meta_t
#define PRQ_TIMEOUT_T   uint
#define PRQ_TIMEOUT     tspub
#include "../../util/tmpl/fd_prq.c"


#define MAP_NAME              acct_uses
#define MAP_T                 fd_pack_addr_use_t
#define MAP_KEY_T             uchar *
#define MAP_KEY_NULL          NULL
#define MAP_KEY_INVAL(k)      !(k)
#define MAP_KEY_EQUAL(k0,k1)  (((!!(k0))&(!!(k1)))&&(!memcmp((k0),(k1), FD_TXN_ACCT_ADDR_SZ)))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     (*(uint*)(key))
#include "../../util/tmpl/fd_map_dynamic.c"

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

FD_FN_CONST ulong
fd_pack_tile_scratch_align( void );

FD_FN_CONST ulong
fd_pack_tile_scratch_footprint( ulong bank_cnt,
                                ulong txnq_sz,
                                ulong lg_cu_est_tbl_sz );

/* Inserts the transaction stored in slot into the list of transactions that
   are ready to be scheduled.  Takes ownership of slot, which must come from
   freelist.  Due to the speculative read pattern, memory management around
   slot is a little strange.  Use the following pattern:
     slot = freelist_pop_head( freelist );
     ... speculatively populate chunk indicated by slot ...
     if( overrun ) freelist_push_head( freelist, slot );
     else          insert_transaction( slot, ... );
 */
void
fd_pack_insert_transaction(
    ulong                     slot_chunk,
    void *                    dcache_base,
    ulong                     lamports_per_signature,
    uint                      cu_limit,
    fd_rng_t *                rng,
    fd_est_tbl_t *            cu_est_tbl,
    fd_pack_orderable_txn_t * txnq,
    ulong *                   freelist
  );

/* Try to schedule the best transaction from those that are available to be
   scheduled. */
fd_pack_schedule_return_t
fd_pack_schedule_transaction(
    ulong                     bank_cnt,
    uint                      cu_limit,
    fd_pack_bank_status_t *   bank_status,
    fd_pack_orderable_txn_t * last_scheduled,
    fd_pack_orderable_txn_t * txnq,
    fd_frag_meta_t *          outq,
    fd_pack_addr_use_t *      r_accts_in_use,
    fd_pack_addr_use_t *      w_accts_in_use,
    ulong *                   freelist,
    void *                    dcache_base,
    fd_frag_meta_t *          out_mcache,
    ulong *                   out_seq,
    ulong                     out_depth
  );

/* Update the state to prepare for next block.  Assumes a barrier between any
   transactions scheduled prior to the return of this call and after the return
   of this call.  Publishes any pending transactions in outq on the mcache. */
void fd_pack_next_block(
    ulong                     bank_cnt,
    fd_pack_bank_status_t *   bank_status,
    fd_pack_orderable_txn_t * last_scheduled,
    fd_pack_addr_use_t *      r_accts_in_use,
    fd_pack_addr_use_t *      w_accts_in_use,
    fd_frag_meta_t *          outq,
    fd_frag_meta_t *          out_mcache, /* Ignored if outq is empty */
    ulong *                   out_seq,    /* Ignored if outq is empty */
    ulong                     out_depth,  /* Ignored if outq is empty */
    ulong *                   freelist
  );

/* Resets pack to a pristine state. Forgets about all pending transactions and
   all previously scheduled transactions.  Does not clear the CU estimation
   table. */
void fd_pack_reset(
    ulong                     bank_cnt,
    fd_pack_bank_status_t *   bank_status,
    fd_pack_orderable_txn_t * last_scheduled,
    fd_pack_addr_use_t *      r_accts_in_use,
    fd_pack_addr_use_t *      w_accts_in_use,
    fd_frag_meta_t *          outq,
    ulong *                   freelist,
    fd_pack_orderable_txn_t * txnq,
    void *                    dcache_base
  );
FD_PROTOTYPES_END
#endif /*HEADER_fd_src_ballet_pack_fd_pack_h*/
