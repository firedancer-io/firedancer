#ifndef HEADER_fd_src_disco_bundle_fd_bundle_crank_h
#define HEADER_fd_src_disco_bundle_fd_bundle_crank_h

#include "../fd_disco_base.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../flamenco/runtime/fd_system_ids_pp.h"
#include "fd_bundle_crank_constants.h"


/* This header defines the crank transactions and some helper functions
   for working with them.  There are two types of crank transactions:
   one that creates the tip distribution account in addition to updating
   it and one that only updates it.  The tip distribution account only
   needs to be created once per epoch, but it needs to be updated pretty
   much each time the leader changes. */


/* Forward declare this struct.  It's defined at the bottom of this
   header, and it's fixed size, so you can declare one easily, but
   putting it up here clutters the file. */
struct fd_bundle_crank_gen_private;
typedef struct fd_bundle_crank_gen_private fd_bundle_crank_gen_t;


/* fd_bundle_crank_gen_init initializes a bundle crank generator so that
   it can produce bundle crank transactions.  This does some
   precomputation that is somewhat expensive (a few SHA256s), so it's
   better not to have to do it each slot.  mem points to a region of
   memory with suitable alignment and footprint for a
   fd_bundle_crank_gen_t.  fd_bundle_crank_gen_t x[1] is the easiest way
   to get that.

   tip_distribution_program_addr and tip_payment_program_addr are
   non-NULL pointers to the respective account address of the
   appropriately configured tip distribution program and tip payment
   program.  This code does not support the one-time initialization that
   must be done on those programs.

   validator_vote_acct_addr is a non-NULL pointer to the pubkey for this
   validator's vote account.

   merkle_root_authority_addr is a non-NULL pointer to a pubkey that
   will be delegated authority to distribute tips according to the
   Merkle root.  commission_bps is the validator's tip commission,
   stored in basis points.  Must be in [0, 10,000].  The value of
   merkle_root_authority and commission_bps are only used in
   fd_bundle_crank_generate, which means that if that function will not
   be called, it's okay to pass bogus data here; even in this case,
   however, merkle_root_authority_addr must point to a valid 32-byte
   region.

   schedule_mode is an ASCII cstr that describe what schedule mode is
   currently in use.  It is useful for metrics aggregation but otherwise
   has no effect.  Only the first 3 characters are used on-chain.

   Returns mem, which is properly initialized for use in
   fd_bundle_crank_generate. */
fd_bundle_crank_gen_t *
fd_bundle_crank_gen_init( void                 * mem,
                          fd_acct_addr_t const * tip_distribution_program_addr,
                          fd_acct_addr_t const * tip_payment_program_addr,
                          fd_acct_addr_t const * validator_vote_acct_addr,
                          fd_acct_addr_t const * merkle_root_authority_addr,
                          char const           * schedule_mode,
                          ulong                  commission_bps );


/* fd_bundle_crank_get_addresses returns the account addresses that need
   to be queried at the start of each slot.  gen must be a valid
   initialized bundle crank generator.  epoch is the epoch number of the
   slot in which the initialization transactions will be submitted.
   out_tip_payment_config and out_tip_receiver point to regions of
   memory that will be populated with the tip payment config account
   address and this validator's tip receiver account address for the
   provided epoch. */
void
fd_bundle_crank_get_addresses( fd_bundle_crank_gen_t * gen,
                               ulong                   epoch,
                               fd_acct_addr_t        * out_tip_payment_config,
                               fd_acct_addr_t        * out_tip_receiver );


/* fd_bundle_crank_tip_payment_config is the layout of the tip payment
   configuration account on chain. */
struct __attribute__((packed)) fd_bundle_crank_tip_payment_config {
  ulong          discriminator;   /* == 0x82ccfa1ee0aa0c9b */
  fd_acct_addr_t tip_receiver[1];
  fd_acct_addr_t block_builder[1];
  ulong          commission_pct;
  uchar          bumps[9];
};
typedef struct fd_bundle_crank_tip_payment_config fd_bundle_crank_tip_payment_config_t;


/* fd_bundle_crank_generate produces the necessary bundle crank
   transactions. gen must be a valid initialized bundle crank generator.
   old_tip_payment_config must point to a copy of the contents of the
   tip payment configuration account (use fd_bundle_crank_get_addresses
   to get the account address of the tip payment configuration account).
   Since the previous leader can modify the contents of this account
   almost arbitrarily, this is treated as mostly untrusted input.
   new_block_builder points to the desired block builder, which
   typically comes from the bundle metadata.  identity points to the
   current validator's identity pubkey, which must also be an authorized
   voter for the vote account used in _init(); this account will be used
   as the signer for this transaction.  tip_receiver_owner points to the
   pubkey of the on-chain account owner of the tip_receiver account
   (also normally retrieved with get_addresses).  By convention, the
   owner for accounts that don't exist is the system program (111..1).
   The only other acceptable answer is the tip distribution program
   (since it's a PDA of the tip distribution acct, no other program can
   create it).  epoch is the epoch number of the slot in which the
   transaction will be submitted.  block_builder_commission is the block
   builder's commission (in percentage points, not basis points like the
   validator's tip commission!).  This commission also typically comes
   from the bundle's metadata.  out_payload must point to the first byte
   of a memory region of at least sizeof(fd_bundle_crank_3_t) bytes, but
   probably should be FD_TXN_MTU bytes.  out_txn must point to the first
   byte of a memory region of at least FD_TXN_MAX_SZ bytes.

   This function determines what cranks are necessary.  If any, it
   writes the transaction payload to the region pointed to by
   out_payload and the corresponding fd_txn_t to the region pointed to
   by out_txn.  If no cranks are neccessary, the contents of these
   regions are unmodified.

   If cranks are necessary, returns the size of the transaction payload
   written to out_payload.  Otherwise, returns 0.  The size of the
   fd_txn_t written to out_txn can be determined using other means.  If
   some expected invariant is violated, returns ULONG_MAX and logs a
   warning.  This should be impossible in a production network, and it
   will prevent the validator from using bundles.

   The transactions written to out_payload are fully populated except
   for the blockhash and signature fields.  Space is reserved for them
   in the proper place, but the fields are filled with 0s.  These two
   fields must be populated before the transaction can be submitted. */
ulong
fd_bundle_crank_generate( fd_bundle_crank_gen_t                       * gen,
                          fd_bundle_crank_tip_payment_config_t const  * old_tip_payment_config,
                          fd_acct_addr_t                       const  * new_block_builder,
                          fd_acct_addr_t                       const  * identity,
                          fd_acct_addr_t                       const  * tip_receiver_owner,
                          ulong                                         epoch,
                          ulong                                         block_builder_commission,
                          uchar                                       * out_payload,
                          fd_txn_t                                    * out_txn );


/* fd_bundle_crank_apply updates tip_payment_config and
   tip_receiver_owner as if the transaction produced by
   fd_bundle_crank_generate with the same parameters executed
   successfully.  Arguments have the same meaning as in _generate with
   tip_payment_config playing the role of old_tip_payment_config (since
   it's not old anymore). */
void
fd_bundle_crank_apply( fd_bundle_crank_gen_t                       * gen,
                       fd_bundle_crank_tip_payment_config_t        * tip_payment_config,
                       fd_acct_addr_t                       const  * new_block_builder,
                       fd_acct_addr_t                              * tip_receiver_owner,
                       ulong                                         epoch,
                       ulong                                         block_builder_commission );


/* These are fixed sized transactions, so sizeof() gives you the proper
   size of the payload. */
typedef struct fd_bundle_crank_3 fd_bundle_crank_3_t; /* init and update */
typedef struct fd_bundle_crank_2 fd_bundle_crank_2_t; /* update only     */



struct __attribute__((packed)) fd_bundle_crank_3 {
  uchar sig_cnt; /* = 1 */
  uchar signature[64];
  uchar _sig_cnt; /* = 1 */
  uchar ro_signed_cnt; /* = 0 */
  uchar ro_unsigned_cnt; /* = 6 */
  uchar acct_addr_cnt; /* = 21 */

  /* Writable signers */
  /* 0 */   uchar authorized_voter[32];
  /* Readonly signers (none) */
  /* Writable non-signers */
  /* 1-8 */ uchar tip_payment_accounts[8][32];
  /*  9  */ uchar tip_distribution_program_config[32];
  /* 10  */ uchar tip_payment_program_config[32];
  /* 11  */ uchar old_tip_receiver[32];
  /* 12  */ uchar old_block_builder[32];
  /* 13  */ uchar new_tip_receiver[32];
  /* 14  */ uchar new_block_builder[32];

  /* Readonly non-signers */
  /* 15  */ uchar compute_budget_program[32];
  /* 16  */ uchar tip_payment_program[32];
  /* 17  */ uchar validator_vote_account[32];
  /* 18  */ uchar system_program[32];
  /* 19  */ uchar tip_distribution_program[32];
  /* 20  */ uchar memo_program[32];

  uchar recent_blockhash[32];
  uchar instr_cnt; /* = 5 */

  /* Compute budget instruction */
  struct __attribute__((packed)) {
  uchar prog_id; /* = 15 */
  uchar acct_cnt; /* = 0 */
  uchar data_sz; /* = 5 */
  uchar set_cu_limit; /* = 2 */
  uint cus; /* = 150+39195 + 38260 + 13696 + 2500 + 1500*(255-bump) approx 100k */
  } compute_budget_instruction;

  /* Initialize Tip Distribution Account */
  struct __attribute__((packed)) {
  uchar prog_id; /* = 19 */
  uchar acct_cnt; /* = 5 */
  uchar acct_idx[5]; /* = { 9, 13, 17, 0, 18} */
  uchar data_sz; /* = 43 */
  uchar ix_discriminator[8]; /* = {78 bf 19 b6 6f 31 b3 37} */
  uchar merkle_root_upload_authority[32];
  ushort commission_bps;
  uchar bump;
  } init_tip_distribution_acct;

  /* Change Tip Receiver */
  struct __attribute__((packed)) {
  uchar prog_id; /* = 16 */
  uchar acct_cnt; /* = 13 */
  uchar acct_idx[13]; /* = { 10, 11, 13, 12, 1, 2, 3, 4, 5, 6, 7, 8, 0} */
  uchar data_sz; /* = 8 */
  uchar ix_discriminator[8]; /* = {456316470be7568f} */
  } change_tip_receiver;

  /* Change Block Builder */
  struct __attribute__((packed)) {
  uchar prog_id; /* = 16 */
  uchar acct_cnt; /* = 13 */
  uchar acct_idx[13]; /* = { 10, 13, 12, 14, 1, 2, 3, 4, 5, 6, 7, 8, 0} */
  uchar data_sz; /* = 16 */
  uchar ix_discriminator[8]; /* = {86 50 26 89 a5 15 72 7b} */
  ulong block_builder_commission_pct;
  } change_block_builder;

  /* Memo */
  struct __attribute__((packed)) {
  uchar prog_id; /* = 20 */
  uchar acct_cnt; /* = 0 */
  uchar data_sz; /* = 3 */
  char  memo[3];
  } memo;
};

struct __attribute__((packed)) fd_bundle_crank_2 {
  uchar sig_cnt; /* = 1 */
  uchar signature[64];
  uchar _sig_cnt; /* = 1 */
  uchar ro_signed_cnt; /* = 0 */
  uchar ro_unsigned_cnt; /* = 3 */
  uchar acct_addr_cnt; /* = 18 */

  /* Writable signers */
  /* 0 */   uchar authorized_voter[32];
  /* Readonly signers (none) */
  /* Writable non-signers */
  /* 1-8 */ uchar tip_payment_accounts[8][32];
  /*  9  */ uchar tip_distribution_program_config[32];
  /* 10  */ uchar tip_payment_program_config[32];
  /* 11  */ uchar old_tip_receiver[32];
  /* 12  */ uchar old_block_builder[32];
  /* 13  */ uchar new_tip_receiver[32];
  /* 14  */ uchar new_block_builder[32];

  /* Readonly non-signers */
  /* 15  */ uchar compute_budget_program[32];
  /* 16  */ uchar tip_payment_program[32];
  /* 17  */ uchar memo_program[32];

  uchar recent_blockhash[32];
  uchar instr_cnt; /* = 4 */

  /* Compute budget instruction */
  struct __attribute__((packed)) {
  uchar prog_id; /* = 15 */
  uchar acct_cnt; /* = 0 */
  uchar data_sz; /* = 5 */
  uchar set_cu_limit; /* = 2 */
  uint cus; /* = 150+39195 + 38260 + 2500= 77,605 */
  } compute_budget_instruction;

  /* Change Tip Receiver */
  struct __attribute__((packed)) {
  uchar prog_id; /* = 16 */
  uchar acct_cnt; /* = 13 */
  uchar acct_idx[13]; /* = { 10, 11, 13, 12, 1, 2, 3, 4, 5, 6, 7, 8, 0} */
  uchar data_sz; /* = 8 */
  uchar ix_discriminator[8]; /* = {456316470be7568f} */
  } change_tip_receiver;

  /* Change Block Builder */
  struct __attribute__((packed)) {
  uchar prog_id; /* = 16 */
  uchar acct_cnt; /* = 13 */
  uchar acct_idx[13]; /* = { 10, 13, 12, 14, 1, 2, 3, 4, 5, 6, 7, 8, 0} */
  uchar data_sz; /* = 16 */
  uchar ix_discriminator[8]; /* = {86 50 26 89 a5 15 72 7b} */
  ulong block_builder_commission_pct;
  } change_block_builder;

  /* Memo */
  struct __attribute__((packed)) {
  uchar prog_id; /* = 17 */
  uchar acct_cnt; /* = 0 */
  uchar data_sz; /* = 3 */
  char  memo[3];
  } memo;
};


/* This is only here so that the bundle_crank_gen struct can be declared
   here statically sized. */
typedef struct {
  fd_acct_addr_t key;
  ulong          idx;
} fd_bundle_crank_gen_pidx_t;




struct fd_bundle_crank_gen_private {
  fd_bundle_crank_3_t crank3[1];
  fd_bundle_crank_2_t crank2[1];

  uchar txn3[ sizeof(fd_txn_t)+5UL*sizeof(fd_txn_instr_t) ] __attribute__(( aligned( alignof(fd_txn_t) ) ));
  uchar txn2[ sizeof(fd_txn_t)+4UL*sizeof(fd_txn_instr_t) ] __attribute__(( aligned( alignof(fd_txn_t) ) ));
  ulong configured_epoch;

  fd_bundle_crank_gen_pidx_t map[32];
};
typedef struct fd_bundle_crank_gen_private fd_bundle_crank_gen_t;

#endif /* HEADER_fd_src_disco_bundle_fd_bundle_crank_h */
