#ifndef HEADER_fd_src_ballet_pack_fd_pack_rebate_sum_h
#define HEADER_fd_src_ballet_pack_fd_pack_rebate_sum_h

#include "../fd_disco_base.h"
#include "fd_microblock.h"


/* Pack schedules transactions assuming they consume all the CUs they
   request in order to accommodate the worst case.  However,
   transactions frequently consume fewer CUs than they request.  If the
   bank tiles notify pack of how many CUs can be rebated, pack can use
   that information to schedule additional transactions.

   fd_pack_rebate_sum_t digests microblocks and produces 0-3
   fd_pack_rebate_t messages which summarizes what rebates are needed.
   From the bank tiles's perspective, fd_pack_rebate_t is an opaque
   type, but pack reads its internals. */

FD_STATIC_ASSERT( MAX_TXN_PER_MICROBLOCK*FD_TXN_ACCT_ADDR_MAX<4096UL, map_size );

#define FD_PACK_REBATE_SUM_CAPACITY (5UL*1024UL)

typedef struct {
  fd_acct_addr_t key; /* account address */
  ulong rebate_cus;
} fd_pack_rebate_entry_t;


struct fd_pack_rebate_sum_private {
  ulong total_cost_rebate;
  ulong vote_cost_rebate;
  ulong data_bytes_rebate;
  ulong microblock_cnt_rebate;
  int   ib_result; /* -1: IB failed, 0: not an IB, 1: IB success */
  uint  writer_cnt;

  fd_pack_rebate_entry_t map[ 8192UL ];
  fd_pack_rebate_entry_t * inserted[ FD_PACK_REBATE_SUM_CAPACITY ];
};
typedef struct fd_pack_rebate_sum_private fd_pack_rebate_sum_t;


struct fd_pack_rebate {
  ulong total_cost_rebate;
  ulong vote_cost_rebate;
  ulong data_bytes_rebate;
  ulong microblock_cnt_rebate;
  int   ib_result; /* -1: IB failed, 0: not an IB, 1: IB success */
  uint  writer_cnt;

  fd_pack_rebate_entry_t writer_rebates[ 1UL ]; /* Actually writer_cnt, up to 1637 */
};
typedef struct fd_pack_rebate fd_pack_rebate_t;

#define FD_PACK_REBATE_MIN_SZ (sizeof(fd_pack_rebate_t)       -sizeof(fd_pack_rebate_entry_t))
#define FD_PACK_REBATE_MAX_SZ (sizeof(fd_pack_rebate_t)+1636UL*sizeof(fd_pack_rebate_entry_t))

FD_STATIC_ASSERT( sizeof(fd_pack_rebate_t)+1636UL*sizeof(fd_pack_rebate_entry_t)<USHORT_MAX, rebate_depth );


FD_FN_PURE static inline ulong fd_pack_rebate_sum_align    ( void ) { return alignof(fd_pack_rebate_sum_t); }
FD_FN_PURE static inline ulong fd_pack_rebate_sum_footprint( void ) { return sizeof (fd_pack_rebate_sum_t); }

FD_FN_PURE static inline fd_pack_rebate_sum_t * fd_pack_rebate_sum_join( void * mem ) { return (fd_pack_rebate_sum_t *)mem; }

void * fd_pack_rebate_sum_new( void * mem );

/* fd_pack_rebate_sum_add_txn adds rebate information from a bundle or
   microblock to the pending summary.  This reads the EXECUTE_SUCCESS
   flag and the bank_cu field, so those must be populated in the
   transactions before this is called.

   s must be a valid local join. txn will be indexed txn[i] for i in [0,
   txn_cnt), and each transaction must have the previously mentioned
   fields set.  Additionally, if the transaction txn[i] loads writable
   accounts from one or more address lookup tables, addtl_writable[i]
   must point to the first writable account address that it loaded.
   adtl_writable is indexed addtl_writable[i][j] for j in
   [0, TXN(txn[i])->addr_table_adtl_writable_cnt ).  If txn[i] does not
   load any accounts writably from address lookup tables or if the
   SANITIZE_SUCCESS flag is not set, adtl_writable[i] is ignored and can
   be NULL.  txn_cnt must be in [0, MAX_TXN_PER_MICROBLOCK], where
   txn_cnt==0 is a no-op.  txn and adtl_writable can be NULL if
   txn_cnt==0.

   This function does not retain any read interest in txn or
   adtl_writable after returning.

   Returns the number of times fd_pack_rebate_sum_report must be called
   before the next call to add_txn with a non-zero txn_cnt. */
ulong
fd_pack_rebate_sum_add_txn( fd_pack_rebate_sum_t         * s,
                            fd_txn_p_t     const         * txn,
                            fd_acct_addr_t const * const * adtl_writable,
                            ulong                          txn_cnt );

/* fd_pack_rebate_sum_report generates a rebate report from the state of
   the current rebate information.  s must point to a valid local join.
   out must point to a region of memory with at least USHORT_MAX bytes
   of capacity.  Returns the number of bytes that were written, which
   will be in [0, USHORT_MAX].  Updates the state of s so that
   subsequent calls to this function will write new information. */
ulong
fd_pack_rebate_sum_report( fd_pack_rebate_sum_t * s,
                           fd_pack_rebate_t     * out );

/* fd_pack_rebate_sum_clear clears the state of any pending rebates.
   Requires that s is a valid local join.  Given that, it's faster but
   equivalent to calling leave, delete, new, then join. */
void
fd_pack_rebate_sum_clear( fd_pack_rebate_sum_t * s );

#endif /* HEADER_fd_src_ballet_pack_fd_pack_rebate_sum_h */
