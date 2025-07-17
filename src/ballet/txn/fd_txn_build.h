#ifndef HEADER_fd_src_ballet_txn_fd_txn_build_h
#define HEADER_fd_src_ballet_txn_fd_txn_build_h

/* fd_txn_build.h is an API to procedurally build Solana transactions.
   For now, mostly used to generate test / fuzz inputs.

   This API is loosely modelled after solana-go:
   https://github.com/gagliardetto/solana-go/blob/v1.12.0/transaction.go

   FIXME This API overlaps with fd_txn_generate.h. */

#include "../../disco/pack/fd_microblock.h"
#include "../../funk/fd_funk_base.h"

/* The fd_txn_builder_t class provides methods for assembling a txn.
   fd_txn_builder_t is a static size struct, so a local declaration is a
   valid way to reserve memory for a txn_builder object:

     fd_txn_builder_t builder[1];
     fd_txn_builder_new( builder );
     ... */

struct fd_txn_b_acct {
  fd_acct_addr_t key;

  uchar cat;
  uchar map_next;
  uchar prio;

  uchar alut_i; /* idx of ALUT account */
  uint  alut_j; /* idx within ALUT account */
};
typedef struct fd_txn_b_acct fd_txn_b_acct_t;

struct fd_txn_b_instr {
  uchar  program_id;
  uchar  instr_acct0;
  uchar  instr_acct_cnt;
  ushort data_off;
  ushort data_sz;
};
typedef struct fd_txn_b_instr fd_txn_b_instr_t;

/* Declare a separately-chained hashmap of instruction accounts */

#define MAP_NAME          fd_txn_b_addr_map
#define MAP_ELE_T         fd_txn_b_acct_t
#define MAP_IDX_T         uchar
#define MAP_KEY_T         fd_acct_addr_t
#define MAP_KEY_EQ(a,b)   0==memcmp( a, b, sizeof(fd_acct_addr_t) )
#define MAP_KEY_HASH(k,s) fd_funk_rec_key_hash1( k, 0, s )
#define MAP_NEXT  map_next
#include "../../util/tmpl/fd_map_chain.c"
#define FD_TXN_B_ADDR_CHAIN_CNT (2*FD_TXN_ACCT_ADDR_MAX)
#define FD_TXN_B_ADDR_MAP_SZ    (sizeof(fd_txn_b_addr_map_t) + FD_TXN_B_ADDR_CHAIN_CNT)

struct fd_txn_builder {

  /* Misc fields */
  fd_acct_addr_t recent_blockhash;
  uchar fee_payer_acct;

  /* Flags */
  uchar fee_payer_set  : 1;
  uchar program_id_set : 1;
  uchar blockhash_set  : 1;
  uchar alut_set       : 1;
  uchar alut_empty     : 1;
  uchar built          : 1;

  /* ALUT */
  uchar alut_i; /* current ALUT account */

  /* Instructions */
  fd_txn_b_instr_t instr[ FD_TXN_INSTR_MAX ];
  uchar            instr_cnt;

  /* Transaction Accounts */
  fd_txn_b_acct_t acct    [ FD_TXN_ACCT_ADDR_MAX ];
  uchar           acct_map[ FD_TXN_ACCT_ADDR_MAX ];
  uchar           acct_cnt;

  /* Instruction Account Pool */
  uchar instr_acct[ FD_TXN_ACCT_ADDR_MAX ];
  uchar instr_acct_cnt;

  /* Address Hash Map */
  union {
    fd_txn_b_addr_map_t map;
    uchar               map_mem[ FD_TXN_B_ADDR_MAP_SZ ];
  };

  /* Bump allocator for instruction datas */
#define FD_TXN_B_DATA_BUMP_MAX FD_TXN_MTU
  uchar  data_bump[ FD_TXN_B_DATA_BUMP_MAX ];
  ushort data_bump_sz;

};
typedef struct fd_txn_builder fd_txn_builder_t;

FD_PROTOTYPES_BEGIN

/* Constructors *******************************************************/

FD_FN_CONST ulong
fd_txn_builder_align( void );

FD_FN_CONST ulong
fd_txn_builder_footprint( void );

fd_txn_builder_t *
fd_txn_builder_new( void * mem,
                    ulong  seed );

void *
fd_txn_builder_delete( fd_txn_builder_t * builder );

static fd_txn_builder_t *
fd_txn_builder_reset( fd_txn_builder_t * builder ) {
  ulong const seed = builder->map.seed;
  fd_txn_builder_delete( builder );
  return fd_txn_builder_new( builder, seed );
}

/* Miscellaneous fields ***********************************************/

/* fd_txn_builder_fee_payer_set sets the transaction's fee payer. */

fd_txn_builder_t *
fd_txn_builder_fee_payer_set( fd_txn_builder_t * builder,
                              void const *       fee_payer );

/* fd_txn_builder_blockhash_set sets the transaction's "recent block
   hash" field. */

static inline void
fd_txn_builder_blockhash_set( fd_txn_builder_t * builder,
                              void const *       blockhash ) {
  builder->blockhash_set = 1;
  memcpy( &builder->recent_blockhash, blockhash, sizeof(fd_acct_addr_t) );
}

/* fd_txn_builder_nonce_set sets the transaction's nonce account (by
   making the first instruction a "system program advance nonce"
   instruction).  This is only useful in combination with
   fd_txn_builder_blockhash_set( builder, nonce_hash ).  Must be called
   before fd_txn_builder_instr_open.  May not be called multiple times. */

fd_txn_builder_t *
fd_txn_builder_nonce_set( fd_txn_builder_t * builder,
                          void const *       nonce_account,
                          void const *       nonce_authority );

/* Transaction Instructions *******************************************/

/* fd_txn_builder_instr_open starts building an instruction.  Returns
   builder on success, NULL on failure. */

fd_txn_builder_t *
fd_txn_builder_instr_open( fd_txn_builder_t * builder,
                           void const *       program_id,
                           void const *       data,
                           ulong              data_sz );

/* fd_txn_builder_instr_account_push appends an instruction account to
   the instruction being built.  acct_cat is a bitwise-OR of any of
   FD_TXN_ACCT_CAT_{WRITABLE,SIGNER}.  acct_cat==0 is fine and implies
   a readonly account access. */

fd_txn_builder_t *
fd_txn_builder_instr_account_push(
    fd_txn_builder_t * builder,
    void const *       acct_addr,
    uint               acct_cat
);

/* fd_txn_builder_instr_close finishes building an instruction. */

void
fd_txn_builder_instr_close( fd_txn_builder_t * builder );

/* FIXME add compute budget / priority fee instructions */

/* Address Lookup Tables **********************************************/

/* fd_txn_builder_alut_open adds an address lookup table (ALUT) to the
   txn builder, which acts like a dictionary for account addresses.
   This helps reduce serialized transaction size.  alut_addr is the
   account address of the ALUT.

   ALUTs should only be registered with the builder once the caller is
   done adding instructions. */

fd_txn_builder_t *
fd_txn_builder_alut_open( fd_txn_builder_t * builder,
                          void const *       alut_addr );

/* fd_txn_builder_alut_address_push registers an ALUT address entry with
   the transaction builder.  acct_addr is the address referenced by the
   ALUT, acct_idx is the index of that address within the ALUT.  If the
   acct_addr is used by any instruction, it is replaced with an ALUT
   reference, if possible.  acct_addr that are not used or cannot be
   referenced using ALUT (e.g. because it is also in use as a program
   ID) are silently ignored.  Safe to call multiple times for the same
   acct_addr/acct_idx (ignores subsequent calls), and accepts acct_idx
   in arbitrary order. */

void
fd_txn_builder_alut_address_push(
    fd_txn_builder_t * builder,
    void const *       acct_addr,
    uint               acct_idx
);

/* fd_txn_builder_alut_close finishes adding an ALUT. */

void
fd_txn_builder_alut_close( fd_txn_builder_t * builder );

/* Build Finish *******************************************************/

/* fd_txn_build_raw produces a serialized transaction object.
   Serializes the transaction to out and returns the byte size on
   success.  On failure returns 0 silently. */

uint
fd_txn_build_raw( fd_txn_builder_t * builder,
                  uchar              out[ FD_TXN_MTU ] );

/* fd_txn_build builds a transaction separately into a raw buffer and a
   fd_txn_t.  Serializes the transaction to out, populates out_txn,
   and returns the serialized byte size on success.  If opt_out_txn_t_sz
   !=NULL, sets *opt_out_txn_t_sz to the size of the out_txn object.
   The footprint of out_txn must be at least FD_TXN_MAX_SZ.  On failure
   returns 0 silently. */

uint
fd_txn_build( fd_txn_builder_t *  builder,
              uchar               out[ FD_TXN_MTU ],
              fd_txn_t * restrict out_txn,
              ushort *            opt_out_txn_t_sz );

/* fd_txn_build_p builds a transaction into a txn_p_t. */

FD_FN_UNUSED static uint
fd_txn_build_p( fd_txn_builder_t * builder,
                fd_txn_p_t *       out ) {
  return (out->payload_sz = (ushort)fd_txn_build( builder, out->payload, TXN( out ), NULL ));
}

FD_PROTOTYPES_END

/* FD_TXN_ACCT_CAT_PIN prevents an ALUT demote.  For internal use only.
   Must not overlap with the flags in fd_txn.h */
#define FD_TXN_ACCT_CAT_PIN       0x40
#define FD_TXN_ACCT_CAT_FEE_PAYER 0x80
#define FD_TXN_ACCT_CAT_IS_PIN    (FD_TXN_ACCT_CAT_PIN|FD_TXN_ACCT_CAT_SIGNER|FD_TXN_ACCT_CAT_FEE_PAYER)

#endif /* HEADER_fd_src_ballet_txn_fd_txn_build_h */
