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
#define MAP_PERFECT_HASH_C    478U
#define MAP_PERFECT_KEY       program_id
#define MAP_PERFECT_KEY_T     fd_acct_addr_t const *
#define MAP_PERFECT_ZERO_KEY  (0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0)
#define MAP_PERFECT_COMPLEX_KEY 1
#define MAP_PERFECT_KEYS_EQUAL(k1,k2) (!memcmp( (k1), (k2), 32UL ))

#define PERFECT_HASH( u ) (((478U*(u))>>28)&0xFU)

#define MAP_PERFECT_HASH_PP( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15, \
                             a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31) \
                                          PERFECT_HASH( (a08 | (a09<<8) | (a10<<16) | (a11<<24)) )
#define MAP_PERFECT_HASH_R( ptr ) PERFECT_HASH( fd_uint_load_4( (uchar const *)ptr->b + 8UL ) )


#define VOTE_PROG_COST 2100UL

#define MAP_PERFECT_0  ( STAKE_PROG_ID           ), .cost_per_instr=         750UL
#define MAP_PERFECT_1  ( VOTE_PROG_ID            ), .cost_per_instr=VOTE_PROG_COST
#define MAP_PERFECT_2  ( SYS_PROG_ID             ), .cost_per_instr=         150UL
#define MAP_PERFECT_3  ( COMPUTE_BUDGET_PROG_ID  ), .cost_per_instr=         150UL
#define MAP_PERFECT_4  ( ADDR_LUT_PROG_ID        ), .cost_per_instr=         750UL
#define MAP_PERFECT_5  ( BPF_UPGRADEABLE_PROG_ID ), .cost_per_instr=        2370UL
#define MAP_PERFECT_6  ( BPF_LOADER_1_PROG_ID    ), .cost_per_instr=        1140UL
#define MAP_PERFECT_7  ( BPF_LOADER_2_PROG_ID    ), .cost_per_instr=         570UL
#define MAP_PERFECT_8  ( LOADER_V4_PROG_ID       ), .cost_per_instr=        2000UL
#define MAP_PERFECT_9  ( KECCAK_SECP_PROG_ID     ), .cost_per_instr=         720UL
#define MAP_PERFECT_10 ( ED25519_SV_PROG_ID      ), .cost_per_instr=         720UL
#define MAP_PERFECT_11 ( SECP256R1_PROG_ID       ), .cost_per_instr=         720UL

#include "../../util/tmpl/fd_map_perfect.c"

/* Redefine it so we can use it below */
#define MAP_PERFECT_HASH_PP( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15, \
                             a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31) \
                                          PERFECT_HASH( ((uint)a08 | ((uint)a09<<8) | ((uint)a10<<16) | ((uint)a11<<24)) )

#define FD_PACK_COST_PER_SIGNATURE           (720UL)
#define FD_PACK_COST_PER_WRITABLE_ACCT       (300UL)
#define FD_PACK_INV_COST_PER_INSTR_DATA_BYTE (  4UL)

/* The computation here is similar to the computation for the max
   fd_txn_t size.  There are various things a transaction can include
   that consume CUs, and they also consume some bytes of payload.  It
   then becomes an integer linear programming problem.  First, the best
   use of bytes is to include a compute budget program instruction that
   requests 1.4M CUs.  That also requires the invocation of another
   non-builtin program, consuming 3 bytes of payload.  In total to do
   this, we need 2 pubkey and 11 bytes of instruction payload.  This is
   >18,000 CUs per byte, which is obviously the best move.

   From there, we can also invoke built-in programs with no accounts and
   no instruction data, which also consumes 3 bytes of payload.  The
   most expensive built-in is the BPF upgradeable loader.  We're limited
   to 64 instructions, so we can only consume it at most 62 times.  This
   is about 675 CUs per byte.

   We've maxed out the instruction limit, so we can only continue to
   increase the cost by adding writable accounts or writable signer
   accounts.  Writable signers consume 96 bytes use 1020 CUs.  Writable
   non-signers consume 32 bytes and use 300 CUs.  That's 10.6 CUs/byte
   and 9.4 CUs/byte, respectively, so in general, writable signers are
   more efficient and we want to add as many as we can.  We also need at
   least one writable signer to be the fee payer, and, although it's
   unusual, there's actually no reason the non-builtin program can't be
   a writable signer too.

   Finally, with any bytes that remain, we can add them to one of the
   instruction datas for 0.25 CUs/byte.

   This gives a transaction that looks like
     Field                   bytes consumed               CUs used
     sig cnt                      1                             0
     fee payer sig               64                           720
     8 other signatures         512                         5,670
     fixed header (no ALTs)       3                             0
     acct addr cnt                1                             0
     fee payer pubkey            32                           300
     8 writable pubkeys         256                         2,400
     2 writable non-signers      64                           600
     CBP, BPF upg loader         64                             0
     Recent blockhash            32                             0
     Instruction count            1                             0
     Compute budget program ix    8                           151.25
     62 dummy BPF upg ixs       186                       146,940
     1 dummy non-builtin ix       8                     1,400,001.25
   + ---------------------------------------------------------------
                              1,232                     1,556,782

   One of the main take-aways from this is that the cost of a
   transaction easily fits in a uint. */
#define FD_PACK_MAX_TXN_COST (1556782UL)
FD_STATIC_ASSERT( FD_PACK_MAX_TXN_COST < (ulong)UINT_MAX, fd_pack_max_cost );

/* Every transaction has at least a fee payer, a writable signer. */
#define FD_PACK_MIN_TXN_COST (FD_PACK_COST_PER_SIGNATURE+FD_PACK_COST_PER_WRITABLE_ACCT)

/* A typical vote transaction has the authorized voter (writable
   signer), the vote account (writable non-signer), and the vote program
   (readonly).  Then it has one instruction, a built-in to the vote
   program, which is typically 116 bytes long, but occasionally a little
   less than that.  The mean over several million slots of vote
   transactions (10B votes) is 115.990 bytes. */
static const ulong FD_PACK_TYPICAL_VOTE_COST = ( FD_PACK_COST_PER_SIGNATURE                 +
                                                 2UL*FD_PACK_COST_PER_WRITABLE_ACCT         +
                                                 116UL/FD_PACK_INV_COST_PER_INSTR_DATA_BYTE +
                                                 VOTE_PROG_COST );

#undef VOTE_PROG_COST


/* Computes the total cost and a few related properties for the
   specified transaction.  On success, returns the cost, which is in
   [1020, FD_PACK_MAX_TXN_COST] and sets or clears the
   FD_TXN_P_FLAG_IS_SIMPLE_VOTE bit of the value pointed to by flags to
   indicate whether the transaction is a simple vote or not.

   Additionally:
   If opt_execution_cost is non-null, on success it will contain the
   execution cost (BPF execution cost + built-in execution cost).  This
   value is in [0, the returned value).
   If opt_fee is non-null, on success it will contain the priority fee,
   measured in lamports (i.e. the part of the fee that excludes the
   per-signature fee). This value is in [0, ULONG_MAX].
   If opt_precompile_sig_cnt is non-null, on success it will contain the
   total number of signatures in precompile instructions, namely Keccak
   and Ed25519 signature verification programs. This value is in [0,
   256*64].  Note that this does not do full parsing of the precompile
   instruction, and it may be malformed.

   On failure, returns 0 and does not modify the value pointed to by
   flags, opt_execution_cost, opt_fee, or opt_precompile_sig_cnt. */
static inline ulong
fd_pack_compute_cost( fd_txn_t const * txn,
                      uchar    const * payload,
                      uint           * flags,
                      ulong          * opt_execution_cost,
                      ulong          * opt_fee,
                      ulong          * opt_precompile_sig_cnt ) {

#define ROW(x) fd_pack_builtin_tbl + MAP_PERFECT_HASH_PP( x )

  fd_pack_builtin_prog_cost_t const * compute_budget_row     = ROW( COMPUTE_BUDGET_PROG_ID );
  fd_pack_builtin_prog_cost_t const * vote_row               = ROW( VOTE_PROG_ID           );
  fd_pack_builtin_prog_cost_t const * ed25519_precompile_row = ROW( ED25519_SV_PROG_ID     );
  fd_pack_builtin_prog_cost_t const * keccak_precompile_row  = ROW( KECCAK_SECP_PROG_ID    );
  fd_pack_builtin_prog_cost_t const * secp256r1_precomp_row  = ROW( SECP256R1_PROG_ID      );
#undef ROW

  /* We need to be mindful of overflow here, but it's not terrible.
         signature_cost <= FD_TXN_ACCT_ADDR_MAX*720,
         writable_cost  <= FD_TXN_ACCT_ADDR_MAX*300 */

  ulong signature_cost = FD_PACK_COST_PER_SIGNATURE      * fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_SIGNER   );
  ulong writable_cost  = FD_PACK_COST_PER_WRITABLE_ACCT  * fd_txn_account_cnt( txn, FD_TXN_ACCT_CAT_WRITABLE );

  ulong instr_data_sz      = 0UL; /* < FD_TPU_MTU */
  ulong builtin_cost       = 0UL; /* <= 2370*FD_TXN_INSTR_MAX */
  ulong non_builtin_cnt    = 0UL; /* <= FD_TXN_INSTR_MAX */
  ulong vote_instr_cnt     = 0UL; /* <= FD_TXN_INSTR_MAX */
  ulong precompile_sig_cnt = 0UL; /* <= FD_TXN_INSTR_MAX * UCHAR_MAX */
  fd_acct_addr_t const * addr_base = fd_txn_get_acct_addrs( txn, payload );

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

    if( FD_UNLIKELY( in_tbl==compute_budget_row ) ) {
      if( FD_UNLIKELY( 0==fd_compute_budget_program_parse( payload+txn->instr[i].data_off, txn->instr[i].data_sz, cbp ) ) )
        return 0UL;
    } else if( FD_UNLIKELY( (in_tbl==ed25519_precompile_row) | (in_tbl==keccak_precompile_row) | (in_tbl==secp256r1_precomp_row) ) ) {
      /* First byte is # of signatures.  Branchless tail reading here is
         probably okay, but this seems safer. */
      precompile_sig_cnt += (txn->instr[i].data_sz>0) ? (ulong)payload[ txn->instr[i].data_off ] : 0UL;
    }

    vote_instr_cnt += (ulong)(in_tbl==vote_row);

  }

  ulong instr_data_cost = instr_data_sz / FD_PACK_INV_COST_PER_INSTR_DATA_BYTE; /* <= 320 */

  ulong fee[1];
  uint compute[1];
  fd_compute_budget_program_finalize( cbp, txn->instr_cnt, fee, compute );

  non_builtin_cnt = fd_ulong_min( non_builtin_cnt, FD_COMPUTE_BUDGET_MAX_CU_LIMIT/FD_COMPUTE_BUDGET_DEFAULT_INSTR_CU_LIMIT );

  ulong non_builtin_cost = fd_ulong_if( (cbp->flags & FD_COMPUTE_BUDGET_PROGRAM_FLAG_SET_CU) && (non_builtin_cnt>0UL),
                                        (ulong)*compute,
                                        non_builtin_cnt*FD_COMPUTE_BUDGET_DEFAULT_INSTR_CU_LIMIT
                                       ); /* <= FD_COMPUTE_BUDGET_MAX_CU_LIMIT */


  if( FD_LIKELY( (vote_instr_cnt==1UL) & (txn->instr_cnt==1UL) ) ) *flags |= FD_TXN_P_FLAGS_IS_SIMPLE_VOTE;
  else                                                             *flags &= ~FD_TXN_P_FLAGS_IS_SIMPLE_VOTE;

  fd_ulong_store_if( !!opt_execution_cost,     opt_execution_cost,     builtin_cost + non_builtin_cost );
  fd_ulong_store_if( !!opt_fee,                opt_fee,                *fee                            );
  fd_ulong_store_if( !!opt_precompile_sig_cnt, opt_precompile_sig_cnt, precompile_sig_cnt              );

  /* <= FD_PACK_MAX_COST, so no overflow concerns */
  return signature_cost + writable_cost + builtin_cost + instr_data_cost + non_builtin_cost;
}
#undef MAP_PERFECT_HASH_PP
#undef PERFECT_HASH
#endif /* HEADER_fd_src_ballet_pack_fd_pack_cost_h */
