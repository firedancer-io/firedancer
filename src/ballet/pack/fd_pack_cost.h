#ifndef HEADER_fd_src_ballet_pack_fd_pack_cost_h
#define HEADER_fd_src_ballet_pack_fd_pack_cost_h
#include "../fd_ballet_base.h"
#include "fd_compute_budget_program.h"
#include "../../flamenco/runtime/fd_system_ids_pp.h"

/* The functions in this header implement the transaction cost model
   that is soon to be part of consensus.
   The cost model consists of several components:
     * per-signature cost
     * per-write-lock cost
     * instruction data length cost
     * built-in execution cost
     * BPF execution cost
   These are all summed to determine the total cost.  Additionally, this
   header provides a method for determining if a transaction is a simple
   vote transaction, in which case its costs are used slightly
   differently. */

/* To compute the built-in cost, we need to check a table. The table
   is known ahead of time though, so we can build a perfect hash
   table for performance.
   The values of the table are based on https://github.com/
   solana-labs/solana/blob/9fb105c801e2999a24f0773443d6164e30c9ff0c/
   runtime/src/block_cost_limits.rs#L34-L47 . */



struct __attribute__((aligned(32))) fd_pack_builtin_prog_cost {
  uchar program_id[32];
  ulong cost_per_instr;
};
typedef struct fd_pack_builtin_prog_cost fd_pack_builtin_prog_cost_t;

#define MAP_PERFECT_NAME      fd_pack_builtin
#define MAP_PERFECT_LG_TBL_SZ 4
#define MAP_PERFECT_T         fd_pack_builtin_prog_cost_t
#define MAP_PERFECT_HASH_C    3770250927U
#define MAP_PERFECT_KEY       program_id
#define MAP_PERFECT_KEY_T     fd_acct_addr_t const *
#define MAP_PERFECT_ZERO_KEY  (0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define MAP_PERFECT_COMPLEX_KEY 1
#define MAP_PERFECT_KEYS_EQUAL(k1,k2) (!memcmp( (k1), (k2), 32UL ))

#define PERFECT_HASH( u ) (((3770250927U*(u))>>28)&0xFU)

#define MAP_PERFECT_HASH_PP( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15, \
                             a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31) \
                                          PERFECT_HASH( (a08 | (a09<<8) | (a10<<16) | (a11<<24)) )
#define MAP_PERFECT_HASH_R( ptr ) PERFECT_HASH( fd_uint_load_4( (uchar const *)ptr->b + 8UL ) )


#define VOTE_PROG_COST 2100UL

#define MAP_PERFECT_0  ( STAKE_PROG_ID           ), .cost_per_instr=         750UL
#define MAP_PERFECT_1  ( CONFIG_PROG_ID          ), .cost_per_instr=         450UL
#define MAP_PERFECT_2  ( VOTE_PROG_ID            ), .cost_per_instr=VOTE_PROG_COST
#define MAP_PERFECT_3  ( SYS_PROG_ID             ), .cost_per_instr=         150UL
#define MAP_PERFECT_4  ( COMPUTE_BUDGET_PROG_ID  ), .cost_per_instr=         150UL
#define MAP_PERFECT_5  ( ADDR_LUT_PROG_ID        ), .cost_per_instr=         750UL
#define MAP_PERFECT_6  ( BPF_UPGRADEABLE_PROG_ID ), .cost_per_instr=        2370UL
#define MAP_PERFECT_7  ( BPF_LOADER_1_PROG_ID    ), .cost_per_instr=        1140UL
#define MAP_PERFECT_8  ( BPF_LOADER_2_PROG_ID    ), .cost_per_instr=         570UL
#define MAP_PERFECT_9  ( LOADER_V4_PROG_ID       ), .cost_per_instr=        2000UL
#define MAP_PERFECT_10 ( KECCAK_SECP_PROG_ID     ), .cost_per_instr=         720UL
#define MAP_PERFECT_11 ( ED25519_SV_PROG_ID      ), .cost_per_instr=         720UL

#include "../../util/tmpl/fd_map_perfect.c"

/* Redefine it so we can use it below */
#define MAP_PERFECT_HASH_PP( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15, \
                             a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31) \
                                          PERFECT_HASH( ((uint)a08 | ((uint)a09<<8) | ((uint)a10<<16) | ((uint)a11<<24)) )

#define COST_PER_SIGNATURE           (720UL)
#define COST_PER_WRITABLE_ACCT       (300UL)
#define INV_COST_PER_INSTR_DATA_BYTE (  4UL)

/* This is an extremely conservative upper bound on the max cost.  The
   majority of it comes from TXN_INSTR_MAX*2370, which is excessively
   high in this branch.  The only useful insight from this limit is that
   costs will fit conveniently in a uint and definitely in a ulong.  A
   transaction with cost this high can't fit in a block, so will never
   make it on chain, but that's not the job of this part of the code to
   know about. */
#define FD_PACK_MAX_TXN_COST (156981760UL)
FD_STATIC_ASSERT( FD_PACK_MAX_TXN_COST>= (
      ((ulong)FD_TXN_ACCT_ADDR_MAX*(720UL+300UL)) + /* writable signer are the most expensive */
      ((ulong)FD_TXN_INSTR_MAX*2370UL) + /* the most expensive built-in */
      (FD_TPU_MTU/INV_COST_PER_INSTR_DATA_BYTE) +
      (ulong)FD_COMPUTE_BUDGET_MAX_CU_LIMIT), fd_pack_max_cost );
FD_STATIC_ASSERT( FD_PACK_MAX_TXN_COST < (ulong)UINT_MAX, fd_pack_max_cost );

/* Every transaction has at least a fee payer, a writable signer. */
#define FD_PACK_MIN_TXN_COST (COST_PER_SIGNATURE+COST_PER_WRITABLE_ACCT)

/* A typical vote transaction has the authorized voter (writable
   signer), the vote account (writable non-signer), clock sysvar, slot
   hashes sysvar (both readonly), and the vote program (readonly).  Then
   it has one instruction a built-in to the vote program, which is
   typically 61 bytes (1 slot) or 69 bytes (2 slot) long.  The mean over
   1000 slots of vote transactions is 69.3 bytes. */
static const ulong FD_PACK_TYPICAL_VOTE_COST = ( COST_PER_SIGNATURE                +
                                                 2UL*COST_PER_WRITABLE_ACCT        +
                                                 69UL/INV_COST_PER_INSTR_DATA_BYTE +
                                                 VOTE_PROG_COST );

#undef VOTE_PROG_COST

/* Computes the total cost for the specified transaction and whether the
   transaction is a Simple Vote transaction.  On success, returns the
   cost, which is in [1020, FD_PACK_MAX_COST] and sets the value pointed to by
   is_simple_vote to nonzero/zero depending on if it is a simple vote
   transaction.  On failure, returns 0 and does not modify the value
   pointed to by is_simple_vote. */
static inline ulong
fd_pack_compute_cost( fd_txn_p_t * txnp,
                      int        * is_simple_vote ) {
  fd_txn_t * txn = TXN(txnp);

#define ROW(x) fd_pack_builtin_tbl + MAP_PERFECT_HASH_PP( x )

  fd_pack_builtin_prog_cost_t const * compute_budget_row = ROW( COMPUTE_BUDGET_PROG_ID );
  fd_pack_builtin_prog_cost_t const * vote_row           = ROW( VOTE_PROG_ID           );
#undef ROW

  /* We need to be mindful of overflow here, but it's not terrible.
         signature_cost <= FD_TXN_ACCT_ADDR_MAX*720,
         writable_cost  <= FD_TXN_ACCT_ADDR_MAX*300 */

  ulong signature_cost = COST_PER_SIGNATURE      * fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_SIGNER   );
  ulong writable_cost  = COST_PER_WRITABLE_ACCT  * fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE );

  ulong instr_data_sz    = 0UL; /* < FD_TPU_MTU */
  ulong builtin_cost     = 0UL; /* <= 2370*FD_TXN_INSTR_MAX */
  ulong non_builtin_cnt  = 0UL; /* <= FD_TXN_INSTR_MAX */
  ulong vote_instr_cnt   = 0UL; /* <= FD_TXN_INSTR_MAX */
  fd_acct_addr_t const * addr_base = fd_txn_get_acct_addrs( txn, txnp->payload );

  fd_compute_budget_program_state_t cbp[1];
  fd_compute_budget_program_init( cbp );


  for( ulong i=0UL; i<txn->instr_cnt; i++ ) {
    instr_data_sz += txn->instr[i].data_sz;

    ulong prog_id_idx = (ulong)txn->instr[i].program_id;
    fd_acct_addr_t const * prog_id = addr_base + prog_id_idx;

    /* Lookup prog_id in hash table */

    fd_pack_builtin_prog_cost_t null_row[1] = {{{ 0 }, 0UL }};
    fd_pack_builtin_prog_cost_t const * in_tbl = fd_pack_builtin_query( prog_id, null_row );
    builtin_cost    +=  in_tbl->cost_per_instr;
    non_builtin_cnt += !in_tbl->cost_per_instr; /* The only one with no cost is the null one */

    if( FD_UNLIKELY( in_tbl==compute_budget_row ) )
      if( FD_UNLIKELY( 0==fd_compute_budget_program_parse( txnp->payload+txn->instr[i].data_off, txn->instr[i].data_sz, cbp ) ) )
        return 0UL;

    vote_instr_cnt += (ulong)(in_tbl==vote_row);

  }

  ulong instr_data_cost = instr_data_sz / INV_COST_PER_INSTR_DATA_BYTE; /* <= 320 */

  ulong fee[1];
  uint compute[1];
  fd_compute_budget_program_finalize( cbp, txn->instr_cnt, fee, compute );
  /* TODO: Consider also returning the fee so we don't have to recompute
     it later. */
  non_builtin_cnt = fd_ulong_min( non_builtin_cnt, FD_COMPUTE_BUDGET_MAX_CU_LIMIT/FD_COMPUTE_BUDGET_DEFAULT_INSTR_CU_LIMIT );

  ulong non_builtin_cost = fd_ulong_if( (cbp->flags & FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_CU),
                                        (ulong)*compute,
                                        non_builtin_cnt*FD_COMPUTE_BUDGET_DEFAULT_INSTR_CU_LIMIT
                                       ); /* <= FD_COMPUTE_BUDGET_MAX_CU_LIMIT */


  *is_simple_vote = (vote_instr_cnt==1UL) & (txn->instr_cnt==1UL);

  /* <= FD_PACK_MAX_COST, so no overflow concerns */
  return signature_cost + writable_cost + builtin_cost + instr_data_cost + non_builtin_cost;
}
#undef MAP_PERFECT_HASH_PP
#undef PERFECT_HASH
#endif /* HEADER_fd_src_ballet_pack_fd_pack_cost_h */
