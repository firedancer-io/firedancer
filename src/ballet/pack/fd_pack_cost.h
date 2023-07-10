#ifndef HEADER_fd_src_ballet_pack_fd_pack_cost_h
#define HEADER_fd_src_ballet_pack_fd_pack_cost_h
#include "../fd_ballet_base.h"
#include "fd_compute_budget_program.h"

/* The functions in this header implement the transaction cost model
   that is soon to be part of consensus.
   The cost model consists of several components:
     * per-signature cost
     * per-write-lock cost
     * instruction data length cost
     * built-in execution cost
     * BPF execution cost
   These are all summed to determine the total cost.  Aditionally, this
   header provides a method for determining if a transaction is a simple
   vote transaction, in which case its costs are used slightly
   differently. */

/* To compute the built-in cost, we need to check a table. The table
   is known ahead of time though, so we can build a perfect hash
   table for performance.
   H(prog_id) = (3770250927U*(prog_id[8..12] as uint))>>28 is a
   perfect hash function for the specific program ids, i.e. the 12
   programs are mapped to [0, 16) with no collisions.  This means we can
   do the lookup with one hash and one account address comparison.  If
   the set of programs changes, the hash function will need to be
   updated.
   The values of the table are based on https://github.com/
   solana-labs/solana/blob/9fb105c801e2999a24f0773443d6164e30c9ff0c/
   runtime/src/block_cost_limits.rs#L34-L47 . */

#define PERFECT_HASH( u ) ((3770250927U*(uint)(u))>>28)

#define ADD_PROG( PROG_ID, cost ) ADD_PROG_( PROG_ID, cost )
#define ADD_PROG_( a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15,                         \
                   a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31, cost )                  \
           [PERFECT_HASH( ((uint)a08 | ((uint)a09<<8) | ((uint)a10<<16) | ((uint)a11<<24)) )] = {           \
             .program_id = {a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15,                \
                            a16,a17,a18,a19,a20,a21,a22,a23,a24,a25,a26,a27,a28,a29,a30,a31 },              \
             .cost_per_instr = (cost) }

struct __attribute__((aligned(32))) fd_pack_builtin_prog_cost {
  uchar program_id[32];
  ulong cost_per_instr;
};
typedef struct fd_pack_builtin_prog_cost fd_pack_builtin_prog_cost_t;

#define STAKE_PROG_ID           0x06,0xa1,0xd8,0x17,0x91,0x37,0x54,0x2a,0x98,0x34,0x37,0xbd,0xfe,0x2a,0x7a,0xb2, \
                                0x55,0x7f,0x53,0x5c,0x8a,0x78,0x72,0x2b,0x68,0xa4,0x9d,0xc0,0x00,0x00,0x00,0x00
#define CONFIG_PROG_ID          0x03,0x06,0x4a,0xa3,0x00,0x2f,0x74,0xdc,0xc8,0x6e,0x43,0x31,0x0f,0x0c,0x05,0x2a, \
                                0xf8,0xc5,0xda,0x27,0xf6,0x10,0x40,0x19,0xa3,0x23,0xef,0xa0,0x00,0x00,0x00,0x00
#define VOTE_PROG_ID            0x07,0x61,0x48,0x1d,0x35,0x74,0x74,0xbb,0x7c,0x4d,0x76,0x24,0xeb,0xd3,0xbd,0xb3, \
                                0xd8,0x35,0x5e,0x73,0xd1,0x10,0x43,0xfc,0x0d,0xa3,0x53,0x80,0x00,0x00,0x00,0x00
#define SYS_PROG_ID             0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, \
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
#define COMPUTE_BUDGET_PROG_ID  0x03,0x06,0x46,0x6f,0xe5,0x21,0x17,0x32,0xff,0xec,0xad,0xba,0x72,0xc3,0x9b,0xe7, \
                                0xbc,0x8c,0xe5,0xbb,0xc5,0xf7,0x12,0x6b,0x2c,0x43,0x9b,0x3a,0x40,0x00,0x00,0x00
#define ADDR_LUT_PROG_ID        0x02,0x77,0xa6,0xaf,0x97,0x33,0x9b,0x7a,0xc8,0x8d,0x18,0x92,0xc9,0x04,0x46,0xf5, \
                                0x00,0x02,0x30,0x92,0x66,0xf6,0x2e,0x53,0xc1,0x18,0x24,0x49,0x82,0x00,0x00,0x00
#define BPF_UPGRADEABLE_PROG_ID 0x02,0xa8,0xf6,0x91,0x4e,0x88,0xa1,0xb0,0xe2,0x10,0x15,0x3e,0xf7,0x63,0xae,0x2b, \
                                0x00,0xc2,0xb9,0x3d,0x16,0xc1,0x24,0xd2,0xc0,0x53,0x7a,0x10,0x04,0x80,0x00,0x00
#define BPF_LOADER_1_PROG_ID    0x02,0xa8,0xf6,0x91,0x4e,0x88,0xa1,0x6b,0xbd,0x23,0x95,0x85,0x5f,0x64,0x04,0xd9, \
                                0xb4,0xf4,0x56,0xb7,0x82,0x1b,0xb0,0x14,0x57,0x49,0x42,0x8c,0x00,0x00,0x00,0x00
#define BPF_LOADER_2_PROG_ID    0x02,0xa8,0xf6,0x91,0x4e,0x88,0xa1,0x6e,0x39,0x5a,0xe1,0x28,0x94,0x8f,0xfa,0x69, \
                                0x56,0x93,0x37,0x68,0x18,0xdd,0x47,0x43,0x52,0x21,0xf3,0xc6,0x00,0x00,0x00,0x00
#define LOADER_V4_PROG_ID       0x05,0x12,0xb4,0x11,0x51,0x51,0xe3,0x7a,0xad,0x0a,0x8b,0xc5,0xd3,0x88,0x2e,0x7b, \
                                0x7f,0xda,0x4c,0xf3,0xd2,0xc0,0x28,0xc8,0xcf,0x83,0x36,0x18,0x00,0x00,0x00,0x00
#define KECCAK_SECP_PROG_ID     0x04,0xc6,0xfc,0x20,0xf0,0x50,0xcc,0xf0,0x55,0x84,0xd7,0x21,0x1c,0x9f,0x8c,0xf5, \
                                0x9e,0xc1,0x47,0x85,0xbb,0x16,0x6a,0x1e,0x28,0x30,0xe8,0x12,0x20,0x00,0x00,0x00
#define ED25519_SV_PROG_ID      0x03,0x7d,0x46,0xd6,0x7c,0x93,0xfb,0xbe,0x12,0xf9,0x42,0x8f,0x83,0x8d,0x40,0xff, \
                                0x05,0x70,0x74,0x49,0x27,0xf4,0x8a,0x64,0xfc,0xca,0x70,0x44,0x80,0x00,0x00,0x00

static const fd_pack_builtin_prog_cost_t fd_pack_builtin_table[16] = {
  ADD_PROG( STAKE_PROG_ID,            750UL ),
  ADD_PROG( CONFIG_PROG_ID,           450UL ),
  ADD_PROG( VOTE_PROG_ID,            2100UL ),
  ADD_PROG( SYS_PROG_ID,              150UL ),
  ADD_PROG( COMPUTE_BUDGET_PROG_ID,   150UL ),
  ADD_PROG( ADDR_LUT_PROG_ID,         750UL ),
  ADD_PROG( BPF_UPGRADEABLE_PROG_ID, 2370UL ),
  ADD_PROG( BPF_LOADER_1_PROG_ID,    1140UL ),
  ADD_PROG( BPF_LOADER_2_PROG_ID,     570UL ),
  ADD_PROG( LOADER_V4_PROG_ID,       2000UL ),
  ADD_PROG( KECCAK_SECP_PROG_ID,      720UL ),
  ADD_PROG( ED25519_SV_PROG_ID,       720UL )
};


#undef STAKE_PROG_ID
#undef CONFIG_PROG_ID
/* #undef VOTE_PROG_ID <- undefine this later so we can use it in
   determining simple vote */
#undef SYS_PROG_ID
/* #undef COMPUTE_BUDGET_PROG_ID */
#undef ADDR_LUT_PROG_ID
#undef BPF_UPGRADEABLE_PROG_ID
#undef BPF_LOADER_1_PROG_ID
#undef BPF_LOADER_2_PROG_ID
#undef LOADER_V4_PROG_ID
#undef KECCAK_SECP_PROG_ID
#undef ED25519_SV_PROG_ID

#undef ADD_PROG_
#undef ADD_PROG

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
#define FD_PACK_MAX_COST (156981760UL)
FD_STATIC_ASSERT( FD_PACK_MAX_COST>= (
      ((ulong)FD_TXN_ACCT_ADDR_MAX*(720UL+300UL)) + /* writable signer are the most expensive */
      ((ulong)FD_TXN_INSTR_MAX*2370UL) + /* the most expensive built-in */
      (FD_TPU_MTU/INV_COST_PER_INSTR_DATA_BYTE) +
      (ulong)FD_COMPUTE_BUDGET_MAX_CU_LIMIT), fd_pack_max_cost );
FD_STATIC_ASSERT( FD_PACK_MAX_COST < (ulong)UINT_MAX, fd_pack_max_cost );


/* Computes the total cost for the specified transaction and whether the
   transaction is a Simple Vote transaction.  On success, returns the
   cost, which is in [1020, TODO) and sets the value pointed to by
   is_simple_vote to nonzero/zero depending on if it is a simple vote
   transaction.  On failure, returns 0 and does not modify the value
   pointed to by is_simple_vote. */
static inline ulong
fd_pack_compute_cost( fd_txn_p_t * txnp,
                      int        * is_simple_vote ) {
  fd_txn_t * txn = TXN(txnp);

  const uchar compute_budget_prog_id[FD_TXN_ACCT_ADDR_SZ] = { COMPUTE_BUDGET_PROG_ID };
  const uchar vote_prog_id          [FD_TXN_ACCT_ADDR_SZ] = { VOTE_PROG_ID           };
  const ulong compute_budget_prog_id_hash = PERFECT_HASH( fd_uint_load_4( compute_budget_prog_id+8UL ) );
  const ulong vote_prog_id_hash           = PERFECT_HASH( fd_uint_load_4( vote_prog_id          +8UL ) );

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
    ulong hash_idx = PERFECT_HASH( fd_uint_load_4( 8UL + (uchar*)prog_id ) );
    ulong cost = fd_pack_builtin_table[hash_idx].cost_per_instr;
    int is_builtin = memcmp( fd_pack_builtin_table[hash_idx].program_id, prog_id, FD_TXN_ACCT_ADDR_SZ )==0;
    builtin_cost    += fd_ulong_if( is_builtin, cost, 0UL );
    non_builtin_cnt += fd_ulong_if( is_builtin,  0UL, 1UL );

    if( FD_UNLIKELY( is_builtin & (hash_idx==compute_budget_prog_id_hash) ) )
      if( FD_UNLIKELY( 0==fd_compute_budget_program_parse( txnp->payload+txn->instr[i].data_off, txn->instr[i].data_sz, cbp ) ) )
        return 0UL;

    vote_instr_cnt += fd_ulong_if( is_builtin & (hash_idx==vote_prog_id_hash), 1UL, 0UL );

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
#undef PERFECT_HASH
#undef VOTE_PROG_ID
#undef COMPUTE_BUDGET_PROG_ID
#endif /* HEADER_fd_src_ballet_pack_fd_pack_cost_h */
