#include <math.h>
#include <stdio.h>
#include <string.h>

#include "../../../ballet/base58/fd_base58.h"
#include "../../../ballet/txn/fd_compact_u16.h"
#include "../fd_account.h"
#include "../fd_executor.h"
#include "../fd_runtime.h"
#include "../sysvar/fd_sysvar.h"

#include "../../types/fd_types_yaml.h"
#include "fd_vote_program.h"

/* N.B. This is an as-close-as-possible transliteration of the Solana Labs vote native program
written in Rust. The idea is this code contains the same logic, the same control flow, the same
bugs... such that even an uninformed reader could declare these two versions of Vote behave the
same. This is especially important given Vote's implications for consensus.

Henceforth, thou shalt abide by the transliteration commandments:
  - All variable names shall be kept the same.
  - All function signatures shall be kept the same.
    - Order of parameters
    - Naming of parameters
    - Return types (including error codes!)
  - All control flow shall be kept the same.
  - All modules shall be structured similarly, and prefixed in C accordingly.
    - e.g. `VoteState::new` in Rust becomes `vote_state_new` in C.
    - It is possible such a prefix is overloaded. For example, there is both `mod vote_state` and
`impl VoteState`. In those situations, there is a comment block dividing the functions that live at
the module-level vs. the impl level.

These rules are of course best-effort, given there are differences in the FD vs. Labs APIs that Vote
depends on and fundamental differences between how various constructs are expressed in C vs. Rust.

Therefore, here is an incomplete, in-flux list of exceptions to the above:
  - Memory allocation semantics may be different. The caller may be responsible for supplying a
pointer indicating an allocated memory region, and can therefore choose where to put a given object
(whereas the Rust impl has a tendency to blindly allocate and move memory).
    - A simple example is the different signature of the VoteState constructor: `vote_state_new` vs.
`VoteState::new`.
    - A more complicated example is `vote_state_set_vote_account_state` vs.
`VoteState::set_vote_account_state`.
  - A function may take additional parameters, if they are necessary to implement the function
    - For example, functions often take a pointer to the global context, for reasons specific to the
FD API.
  - A function returning Result<T, E> will return `int` to represent the error code, and the actual
return value `T` will be filled in additional caller-supplied arguments.
  - There will be a branch-free translation of a Rust snippet when it is too painfully obvious and
egregious not do so (e.g. `fd_ulong_if`, bitwise ops)... otherwise it preserves the original `if /
else` construct. */

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L29
#define MAX_LOCKOUT_HISTORY 31UL

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L30
#define INITIAL_LOCKOUT 2UL

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L34
#define MAX_EPOCH_CREDITS_HISTORY 64UL

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L36
#define DEFAULT_PRIOR_VOTERS_OFFSET 114

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/clock.rs#L114
#define SLOT_DEFAULT 0UL

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/clock.rs#L114
#define SLOT_MAX ULONG_MAX

#define ACCOUNTS_MAX 4 /* Vote instructions take in at most 4 accounts */
#define SIGNERS_MAX  3 /* Vote instructions have most 3 signers */

/**********************************************************************/
/* mod vote_processor                                                 */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L21
static int
vote_processor_process_authorize_with_seed_instruction(
    /* invoke_context */
    instruction_ctx_t instruction_context,
    /* transaction_context */
    fd_borrowed_account_t * vote_account,
    fd_pubkey_t const *     new_authority,
    fd_vote_authorize_t     authorization_type,
    fd_pubkey_t const *     curnt_authority_derived_key_owner,
    char *                  current_authority_derived_key_seed );

/**********************************************************************/
/* mod vote_state                                                     */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L146
static int
vote_state_set_vote_account_state( fd_borrowed_account_t * vote_account,
                                   fd_vote_state_t *       vote_state,
                                   /* feature_set */
                                   instruction_ctx_t * ctx );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L178
static int
vote_state_check_update_vote_state_slots_are_valid( fd_vote_state_t *        vote_state,
                                                    fd_vote_state_update_t * vote_state_update,
                                                    fd_slot_hashes_t *       slot_hashes,
                                                    instruction_ctx_t        ctx );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L421
static int
vote_state_check_slots_are_valid( fd_vote_state_t *  vote_state,
                                  ulong *            vote_slots,
                                  fd_hash_t *        vote_hash,
                                  fd_slot_hashes_t * slot_hashes,
                                  instruction_ctx_t  ctx );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L546
static int
vote_state_process_new_vote_state( fd_vote_state_t *   vote_state,
                                   fd_vote_lockout_t * new_state,
                                   ulong *             new_root,
                                   ulong *             timestamp,
                                   ulong               epoch,
                                   /* feature_set */
                                   instruction_ctx_t ctx );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L711
static int
vote_state_process_vote_unfiltered( fd_vote_state_t *  vote_state,
                                    ulong *            vote_slots,
                                    fd_vote_t *        vote,
                                    fd_slot_hashes_t * slot_hashes,
                                    ulong              epoch,
                                    instruction_ctx_t  ctx );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L776
static int
vote_state_authorize( fd_borrowed_account_t * vote_account,
                      fd_pubkey_t const *     authorized,
                      fd_vote_authorize_t     vote_authorize,
                      fd_pubkey_t const *     signers[static SIGNERS_MAX],
                      fd_sol_sysvar_clock_t * clock,
                      /* feature set */
                      instruction_ctx_t ctx );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L821
static int
vote_state_update_validator_identity( fd_borrowed_account_t * vote_account,
                                      fd_pubkey_t const *     node_pubkey,
                                      fd_pubkey_t const *     signers[static SIGNERS_MAX],
                                      /* feature_set */
                                      instruction_ctx_t ctx );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L843
static int
vote_state_update_commission( fd_borrowed_account_t * vote_account,
                              uchar                   commission,
                              fd_pubkey_t const *     signers[static SIGNERS_MAX],
                              /* feature set */
                              instruction_ctx_t ctx );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L877
static int
vote_state_verify_authorized_signer( fd_pubkey_t const * authorized,
                                     fd_pubkey_t const * signers[static SIGNERS_MAX] );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L889
static int
vote_state_withdraw(
    /* transaction_context */
    instruction_ctx_t       instruction_context,
    fd_borrowed_account_t * vote_account,
    ulong                   lamports,
    ulong                   to_account_index,
    fd_pubkey_t const *     signers[static SIGNERS_MAX],
    fd_rent_t *             rent_sysvar,
    fd_sol_sysvar_clock_t * clock
    /* feature_set */
);

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L952
static int
vote_state_initialize_account( fd_borrowed_account_t *       vote_account,
                               fd_vote_init_t *              vote_init,
                               fd_pubkey_t const *           signers[static SIGNERS_MAX],
                               fd_sol_sysvar_clock_t const * clock,
                               /* feature set contained in ctx */
                               instruction_ctx_t ctx );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L978-L994
static int
vote_state_verify_and_get_vote_state( fd_borrowed_account_t *       vote_account,
                                      fd_sol_sysvar_clock_t const * clock,
                                      fd_pubkey_t const * signers[static SIGNERS_MAX],
                                      instruction_ctx_t   ctx,
                                      /* return */ fd_vote_state_t * vote_state );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L996
static int
vote_state_process_vote_with_account( fd_borrowed_account_t *       vote_account,
                                      fd_slot_hashes_t *            slot_hashes,
                                      fd_sol_sysvar_clock_t const * clock,
                                      fd_vote_t *                   vote,
                                      fd_pubkey_t const * signers[static SIGNERS_MAX],
                                      /* feature_set */
                                      instruction_ctx_t ctx );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L1017
static int
vote_state_process_vote_state_update( fd_borrowed_account_t *       vote_account,
                                      fd_slot_hashes_t *            slot_hashes,
                                      fd_sol_sysvar_clock_t const * clock,
                                      fd_vote_state_update_t *      vote_state_update,
                                      fd_pubkey_t const * signers[static SIGNERS_MAX],
                                      /* feature_set */
                                      instruction_ctx_t ctx );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L1036
static int
vote_state_do_process_vote_state_update( fd_vote_state_t *        vote_state,
                                         fd_slot_hashes_t *       slot_hashes,
                                         ulong                    epoch,
                                         fd_vote_state_update_t * vote_state_update,
                                         /* feature_set */
                                         instruction_ctx_t ctx );

/**********************************************************************/
/* impl VoteState                                                     */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L312
static void
vote_state_new( fd_vote_init_t *              vote_init,
                fd_sol_sysvar_clock_t const * clock,
                instruction_ctx_t             ctx,
                fd_vote_state_t *             vote_state );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L338-L342
static ulong
vote_state_size_of( void );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L423
static void
vote_state_process_next_vote_slot( fd_vote_state_t * self, ulong next_vote_slot, ulong epoch );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L447
static void
vote_state_increment_credits( fd_vote_state_t * self, ulong epoch, ulong credits );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L529
static int
vote_state_set_new_authorized_voter(
    fd_vote_state_t *                          self,
    fd_pubkey_t const *                        authorized_pubkey,
    ulong                                      current_epoch,
    ulong                                      target_epoch,
    /* "verify" closure */ int                 authorized_withdrawer_signer,
    /* "verify" closure */ fd_pubkey_t const * signers[static SIGNERS_MAX],
    instruction_ctx_t                          ctx );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L800-L807
static int
verify( fd_pubkey_t *       epoch_authorized_voter,
        int                 authorized_withdrawer_signer,
        fd_pubkey_t const * signers[static SIGNERS_MAX] );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L587
static int
vote_state_get_and_update_authorized_voter( fd_vote_state_t *            self,
                                            ulong                        current_epoch,
                                            instruction_ctx_t            ctx,
                                            /* returns */ fd_pubkey_t ** pubkey );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L605
static void
vote_state_pop_expired_votes( fd_vote_state_t * self, ulong next_vote_slot );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L614
static void
vote_state_double_lockouts( fd_vote_state_t * self );

// https://github.com/firedancer-io/solana/blob/debug-master/sdk/program/src/vote/state/mod.rs#L628
static int
vote_state_process_timestamp( fd_vote_state_t * self,
                              ulong             slot,
                              ulong             timestamp,
                              instruction_ctx_t ctx );

/**********************************************************************/
/* impl Lockout                                                       */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L83
static ulong
lockout_lockout( fd_vote_lockout_t * self );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L90
static ulong
lockout_last_locked_out_slot( fd_vote_lockout_t * self );

/**********************************************************************/
/* impl VoteState1_14_11                                              */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_1_14_11.rs#L45-L49
static ulong
vote_state1_14_11_size_of( void );

/**********************************************************************/
/* impl From<VoteState> for VoteState1_14_11                          */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_1_14_11.rs#L60
static void
vote_state1_14_11_from_vote_state( fd_vote_state_t *                      vote_state,
                                   instruction_ctx_t *                    ctx,
                                   /* return */ fd_vote_state_1_14_11_t * vote_state1_14_11 );

/**********************************************************************/
/* impl VoteStateVersions                                             */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_versions.rs#L15
static void
vote_state_versions_convert_to_current( fd_vote_state_versioned_t * self, instruction_ctx_t ctx );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_versions.rs#L74-L76
static fd_landed_vote_t *
vote_state_versions_landed_votes_from_lockouts( fd_vote_lockout_t * lockouts,
                                                instruction_ctx_t   ctx );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_versions.rs#L78
static int
vote_state_versions_is_uninitialized( fd_vote_state_versioned_t * self );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_versions.rs#L78
static ulong
vote_state_versions_vote_state_size_of( int is_current );

/**********************************************************************/
/* impl VoteAccount                                                   */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L841
static int
vote_account_checked_add_lamports( fd_account_meta_t * self, ulong lamports );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L851
static int
vote_account_checked_sub_lamports( fd_account_meta_t * self, ulong lamports );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L959
static ulong
vote_account_get_data_len( fd_borrowed_account_t const * self );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L929
static int
vote_account_set_data_length( fd_borrowed_account_t * self,
                              ulong                   new_length,
                              instruction_ctx_t       ctx );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L966
static int
vote_account_get_state( fd_borrowed_account_t *                  self,
                        instruction_ctx_t                        ctx,
                        /* return */ fd_vote_state_versioned_t * versioned );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L1017
static int
vote_account_set_state( fd_borrowed_account_t *     self,
                        fd_vote_state_versioned_t * state,
                        instruction_ctx_t           ctx );

static bool
vote_account_is_rent_exempt_at_data_length( fd_borrowed_account_t * self,
                                            ulong                   data_length,
                                            instruction_ctx_t       ctx );

/**********************************************************************/
/* impl AuthorizedVoters                                              */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L13-L17
static void
authorized_voters_new( ulong                                      epoch,
                       fd_pubkey_t *                              pubkey,
                       instruction_ctx_t                          ctx,
                       /* return */ fd_vote_authorized_voters_t * authorized_voters );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L24
static fd_vote_authorized_voter_t *
authorized_voters_get_and_cache_authorized_voter_for_epoch( fd_vote_authorized_voters_t * self,
                                                            ulong                         epoch );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L39
static void
authorized_voters_purge_authorized_voters( fd_vote_authorized_voters_t * self,
                                           ulong                         current_epoch,
                                           instruction_ctx_t             ctx );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L60-L62
static bool
authorized_voters_is_empty( fd_vote_authorized_voters_t * self );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L68-L70
static fd_vote_authorized_voter_t *
authorized_voters_last( fd_vote_authorized_voters_t * self );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L76-L78
static bool
authorized_voters_contains( fd_vote_authorized_voters_t * self, ulong epoch );

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L87-L108
static fd_vote_authorized_voter_t *
authorized_voters_get_or_calculate_authorized_voter_for_epoch( fd_vote_authorized_voters_t * self,
                                                               ulong                         epoch,
                                                               int * existed );

/**********************************************************************/
/* FD-only encoders / decoders (doesn't map directly to Labs impl)    */
/**********************************************************************/

static int
decode_compact_update( instruction_ctx_t                ctx,
                       fd_compact_vote_state_update_t * compact_update,
                       fd_vote_state_update_t *         vote_update );

ulong
fd_vote_transcoding_state_versioned_size( fd_vote_state_versioned_t const * self );

int
fd_vote_transcoding_state_versioned_encode( fd_vote_state_versioned_t const * self,
                                            fd_bincode_encode_ctx_t *         ctx );

/**********************************************************************/
/* Entry point for the Vote Program                                   */
/**********************************************************************/

int
fd_executor_vote_program_execute_instruction( instruction_ctx_t ctx ) {
  /* FD-specific init */
  int                      rc      = FD_EXECUTOR_INSTR_SUCCESS;
  fd_bincode_destroy_ctx_t destroy = { .valloc = ctx.global->valloc };

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L61-L63
  fd_pubkey_t const * txn_accs       = ctx.txn_ctx->accounts;
  uchar const *       instr_acc_idxs = ctx.instr->acct_txn_idxs;
  uchar *             data           = ctx.instr->data;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L67
  if ( FD_UNLIKELY( ctx.instr->acct_cnt < 1 ) ) {
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L593
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }

  /* This next block implements instruction_context.try_borrow_instruction_account
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L67
   */
  FD_BORROWED_ACCOUNT_DECL(me);

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L685-L690
  rc = fd_acc_mgr_view( ctx.global->acc_mgr,
                          ctx.global->funk_txn,
                          &txn_accs[instr_acc_idxs[0]],
                          me);
  switch ( rc ) {
  case FD_ACC_MGR_SUCCESS:
    break;
  case FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT:
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L637
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  default:
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L639
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L67-L70
  if ( FD_UNLIKELY( 0 !=
                    memcmp( &me->const_meta->info.owner, ctx.global->solana_vote_program, 32UL ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L72
  fd_pubkey_t const * signers[SIGNERS_MAX] = { 0 };
  /* ignores if too many signer accounts */
  uchar signers_idx = 0;
  for ( uchar i = 0; i < ctx.instr->acct_cnt; i++ ) {
    if ( FD_UNLIKELY( fd_instr_acc_is_signer_idx( ctx.instr, i ) ) ) {
      signers[signers_idx++] = &txn_accs[instr_acc_idxs[i]];
      if ( FD_UNLIKELY( signers_idx == SIGNERS_MAX ) ) break;
    }
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L73
  fd_vote_instruction_t instruction;
  fd_vote_instruction_new( &instruction );
  fd_bincode_decode_ctx_t decode_ctx = {
      .data    = data,
      .dataend = (void const *)( (ulong)data + ctx.instr->data_sz ),
      .valloc  = ctx.global->valloc /* use instruction alloc */
  };
  if ( FD_UNLIKELY( FD_EXECUTOR_INSTR_SUCCESS !=
                    fd_vote_instruction_decode( &instruction, &decode_ctx ) ) ) {
    FD_LOG_INFO( ( "fd_vote_instruction_decode failed" ) );
    /* TODO free */
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* PLEASE PRESERVE SWITCH-CASE ORDERING TO MIRROR LABS IMPL:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L73
   */
  switch ( instruction.discriminant ) {

  /* InitializeAccount
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L24-L31
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L74
   */
  case fd_vote_instruction_enum_initialize_account: {
    FD_LOG_INFO( ( "executing VoteInstruction::InitializeAccount instruction" ) );

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L75-L76
    if ( 0 !=
         memcmp( &txn_accs[instr_acc_idxs[1]], ctx.global->sysvar_rent, sizeof( fd_pubkey_t ) ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      break;
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L77-L79
    /* TODO: verify account at index 0 is rent exempt */

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L80-L81
    if ( 0 !=
         memcmp( &txn_accs[instr_acc_idxs[2]], ctx.global->sysvar_clock, sizeof( fd_pubkey_t ) ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      break;
    }
    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L82-L88
    rc = vote_state_initialize_account(
        me, &instruction.inner.initialize_account, signers, &clock, ctx );

    break;
  }

  /* Authorize
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L33-L39
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L90-L101
   *
   * Notes:
   * - Up to two signers: the vote authority and the authorized withdrawer.
   */
  case fd_vote_instruction_enum_authorize: {
    FD_LOG_INFO( ( "executing VoteInstruction::Authorize instruction" ) );

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L90
    fd_pubkey_t const * voter_pubkey   = &instruction.inner.authorize.pubkey;
    fd_vote_authorize_t vote_authorize = instruction.inner.authorize.vote_authorize;

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L91-L92
    fd_pubkey_t const * clock_acc_addr = &txn_accs[instr_acc_idxs[1]];
    if ( FD_UNLIKELY( 0 !=
                      memcmp( clock_acc_addr, ctx.global->sysvar_clock, sizeof( fd_pubkey_t ) ) ) )
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    fd_sol_sysvar_clock_t clock;
    fd_sysvar_clock_read( ctx.global, &clock );

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L93-L100
    rc = vote_state_authorize( me, voter_pubkey, vote_authorize, signers, &clock, ctx );

    break;
  }

  /* AuthorizeWithSeed
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L108-L116
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L102-L114
   */
  case fd_vote_instruction_enum_authorize_with_seed: {
    FD_LOG_INFO( ( "executing VoteInstruction::AuthorizeWithSeed instruction" ) );

    /* FIXME should there be a feature check for authorized with seed?*/

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L103
    if ( FD_UNLIKELY( ctx.instr->acct_cnt < 3 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      break;
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L104-L113
    fd_vote_authorize_with_seed_args_t * args = &instruction.inner.authorize_with_seed;
    rc = vote_processor_process_authorize_with_seed_instruction(
        ctx,
        me,
        &args->new_authority,
        args->authorization_type,
        &args->current_authority_derived_key_owner,
        args->current_authority_derived_key_seed );

    break;
  }

  /* AuthorizeCheckedWithSeed
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L118-L130
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L115-L133
   */
  case fd_vote_instruction_enum_authorize_checked_with_seed: {
    FD_LOG_INFO( ( "executing VoteInstruction::AuthorizeCheckedWithSeed instruction" ) );
    fd_vote_authorize_checked_with_seed_args_t const * args =
        &instruction.inner.authorize_checked_with_seed;

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L116
    if ( FD_UNLIKELY( ctx.instr->acct_cnt < 4 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      break;
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L117-L119
    fd_pubkey_t const * new_authority = &txn_accs[instr_acc_idxs[3]];

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L120-L122
    if ( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx.instr, 3 ) ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      break;
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L123-L132
    rc = vote_processor_process_authorize_with_seed_instruction(
        ctx,
        me,
        new_authority,
        args->authorization_type,
        &args->current_authority_derived_key_owner,
        args->current_authority_derived_key_seed );

    break;
  }

  /* UpdateValidatorIdentity
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L58-L64
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L134-L145
   */
  case fd_vote_instruction_enum_update_validator_identity: {
    FD_LOG_INFO( ( "executing VoteInstruction::UpdateValidatorIdentity instruction" ) );

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L135
    if ( FD_UNLIKELY( ctx.instr->acct_cnt < 2 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      break;
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L136-L138
    fd_pubkey_t const * node_pubkey = &txn_accs[instr_acc_idxs[1]];

    rc = vote_state_update_validator_identity( me, node_pubkey, signers, ctx );

    break;
  }

  case fd_vote_instruction_enum_update_commission: {
    FD_LOG_INFO( ( "executing VoteInstruction::UpdateCommission instruction" ) );

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L150-L155
    if ( FD_LIKELY( FD_FEATURE_ACTIVE(
             ctx.global, commission_updates_only_allowed_in_first_half_of_epoch ) ) ) {
      fd_sol_sysvar_clock_t clock;
      fd_sysvar_clock_read( ctx.global, &clock );
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L157-L162
    rc = vote_state_update_commission( me, instruction.inner.update_commission, signers, ctx );

    break;
  }

  /* Vote
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L41-L48
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L164-L180
   */
  case fd_vote_instruction_enum_vote:;
    /* clang-format off */
    __attribute__((fallthrough));
    /* clang-format on */

  /* VoteSwitch
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L73-L80
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L164-L180
   */
  case fd_vote_instruction_enum_vote_switch: {
    fd_vote_t * vote;
    if ( instruction.discriminant == fd_vote_instruction_enum_vote ) {
      FD_LOG_INFO( ( "executing VoteInstruction::VoteSwitch instruction" ) );
      vote = &instruction.inner.vote;
    } else if ( instruction.discriminant == fd_vote_instruction_enum_vote_switch ) {
      FD_LOG_INFO( ( "executing VoteInstruction::VoteSwitch instruction" ) );
      vote = &instruction.inner.vote_switch.vote;
    } else {
      FD_LOG_ERR( ( "invalid fallthrough detected: %d", instruction.discriminant ) );
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L165-L169
    if ( 0 != memcmp( &txn_accs[instr_acc_idxs[1]],
                      ctx.global->sysvar_slot_hashes,
                      sizeof( fd_pubkey_t ) ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      break;
    }
    fd_slot_hashes_t slot_hashes;
    fd_slot_hashes_new( &slot_hashes );
    rc = fd_sysvar_slot_hashes_read( ctx.global, &slot_hashes );
    if ( FD_UNLIKELY( rc != OK ) ) return rc;

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L170-L171
    if ( 0 !=
         memcmp( &txn_accs[instr_acc_idxs[2]], ctx.global->sysvar_clock, sizeof( fd_pubkey_t ) ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      break;
    }
    fd_sol_sysvar_clock_t clock;
    rc = fd_sysvar_clock_read( ctx.global, &clock );
    if ( FD_UNLIKELY( rc != OK ) ) return rc;

    rc = vote_state_process_vote_with_account( me, &slot_hashes, &clock, vote, signers, ctx );

    break;
  }

  /* UpdateVoteState
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L94-L99
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L181-L201
   */
  case fd_vote_instruction_enum_update_vote_state:;
    /* clang-format off */
    __attribute__((fallthrough));
    /* clang-format on */

  /* UpdateVoteStateSwitch
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L101-L106
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L181-L201
   */
  case fd_vote_instruction_enum_update_vote_state_switch: {
    fd_vote_state_update_t * vote_state_update;
    if ( instruction.discriminant == fd_vote_instruction_enum_update_vote_state ) {
      FD_LOG_INFO( ( "executing VoteInstruction::UpdateVoteState instruction" ) );
      vote_state_update = &instruction.inner.update_vote_state;
    } else if ( instruction.discriminant == fd_vote_instruction_enum_update_vote_state_switch ) {
      FD_LOG_INFO( ( "executing VoteInstruction::UpdateVoteStateSwitch instruction" ) );
      vote_state_update = &instruction.inner.update_vote_state_switch.vote_state_update;
    }

    if ( FD_LIKELY( FD_FEATURE_ACTIVE( ctx.global, vote_stake_checked_instructions ) ) ) {
      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L183-L197
      fd_slot_hashes_t slot_hashes;
      fd_slot_hashes_new( &slot_hashes );
      rc = fd_sysvar_slot_hashes_read( ctx.global, &slot_hashes );
      if ( FD_UNLIKELY( rc != OK ) ) return rc;

      fd_sol_sysvar_clock_t clock;
      rc = fd_sysvar_clock_read( ctx.global, &clock );
      if ( FD_UNLIKELY( rc != OK ) ) return rc;

      rc = vote_state_process_vote_state_update(
          me, &slot_hashes, &clock, vote_state_update, signers, ctx );
    } else {
      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L198-L200
      rc = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    break;
  }

  /* Withdraw
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L50-L56
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L227
   */
  case fd_vote_instruction_enum_withdraw: {
    FD_LOG_INFO( ( "executing VoteInstruction::Withdraw instruction" ) );
    if ( FD_UNLIKELY( ctx.instr->acct_cnt < 2 ) ) {
      rc = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
      break;
    }
    fd_rent_t rent_sysvar;
    fd_sysvar_rent_read( ctx.global, &rent_sysvar );
    fd_sol_sysvar_clock_t clock_sysvar;
    fd_sysvar_clock_read( ctx.global, &clock_sysvar );

    rc = vote_state_withdraw(
        ctx, me, instruction.inner.withdraw, 1, signers, &rent_sysvar, &clock_sysvar );

    break;
  }

  /* AuthorizeChecked
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L82-L92
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L90-L101
   *
   * Notes:
   * - Up to three signers: the vote authority, the authorized withdrawer, and the new authority.
   * - Feature gated, but live on mainnet.
   */
  case fd_vote_instruction_enum_authorize_checked: {
    FD_LOG_INFO( ( "executing VoteInstruction::AuthorizeChecked instruction" ) );
    if ( FD_LIKELY( FD_FEATURE_ACTIVE( ctx.global, vote_stake_checked_instructions ) ) ) {
      if ( FD_UNLIKELY( ctx.instr->acct_cnt < 4 ) ) {
        rc = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
        break;
      }

      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L251-L253
      fd_pubkey_t const * voter_pubkey = &txn_accs[instr_acc_idxs[3]];

      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L254-L256
      if ( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx.instr, 3 ) ) ) {
        rc = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
        break;
      }

      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L257-L261
      fd_pubkey_t const * clock_acc_addr = &txn_accs[instr_acc_idxs[1]];
      if ( FD_UNLIKELY(
               0 != memcmp( clock_acc_addr, ctx.global->sysvar_clock, sizeof( fd_pubkey_t ) ) ) )
        return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      fd_sol_sysvar_clock_t clock;
      fd_sysvar_clock_read( ctx.global, &clock );

      rc = vote_state_authorize(
          me, voter_pubkey, instruction.inner.authorize_checked, signers, &clock, ctx );
    } else {
      rc = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    break;
  }

  /* CompactUpdateVoteState
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L132-L138
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L202-L225
   *
   * Notes:
   * - Up to three signers: the vote authority, the authorized withdrawer, and the new authority.
   * - Feature gated, but live on mainnet.
   */
  case fd_vote_instruction_enum_compact_update_vote_state:;
    /* clang-format off */
    __attribute__((fallthrough));
    /* clang-format on */

  /* CompactUpdateVoteStateSwitch
   *
   * Instruction:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/instruction.rs#L140-L148
   *
   * Processor:
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L202-L225
   *
   * Notes:
   * - Up to three signers: the vote authority, the authorized withdrawer, and the new authority.
   * - Feature gated, but live on mainnet.
   */
  case fd_vote_instruction_enum_compact_update_vote_state_switch: {
    fd_compact_vote_state_update_t * vote_state_update = NULL;
    if ( instruction.discriminant == fd_vote_instruction_enum_compact_update_vote_state ) {
      FD_LOG_INFO( ( "executing VoteInstruction::CompactUpdateVoteState instruction" ) );
      vote_state_update = &instruction.inner.compact_update_vote_state;
    } else if ( instruction.discriminant ==
                fd_vote_instruction_enum_compact_update_vote_state_switch ) {
      FD_LOG_INFO( ( "executing VoteInstruction::CompactUpdateVoteStateSwitch instruction" ) );
      vote_state_update =
          &instruction.inner.compact_update_vote_state_switch.compact_vote_state_update;
    }

    if ( FD_LIKELY( FD_FEATURE_ACTIVE( ctx.global, vote_stake_checked_instructions ) ) ) {
      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L212
      fd_slot_hashes_t slot_hashes;
      fd_slot_hashes_new( &slot_hashes );
      rc = fd_sysvar_slot_hashes_read( ctx.global, &slot_hashes );
      if ( FD_UNLIKELY( rc != OK ) ) return rc;

      fd_sol_sysvar_clock_t clock;
      rc = fd_sysvar_clock_read( ctx.global, &clock );
      if ( FD_UNLIKELY( rc != OK ) ) return rc;

      fd_vote_state_update_t decode;
      fd_vote_state_update_new( &decode );

      decode_compact_update( ctx, vote_state_update, &decode );

#if 0
      fd_flamenco_yaml_t * yaml =
        fd_flamenco_yaml_init( fd_flamenco_yaml_new(
            fd_valloc_malloc(ctx.global->valloc, fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() ) ),
          stdout );

      fd_vote_state_update_walk(yaml, &decode, fd_flamenco_yaml_walk, NULL, 0U );
#endif

      rc = vote_state_process_vote_state_update( me, &slot_hashes, &clock, &decode, signers, ctx );

      decode.root      = NULL;
      decode.timestamp = NULL;

      fd_vote_state_update_destroy( &decode, &destroy );
    } else {
      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L223
      rc = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }

    break;
  }

  default:
    FD_LOG_ERR( ( "unsupported vote instruction: %u", instruction.discriminant ) );
  }

  fd_vote_instruction_destroy( &instruction, &destroy );
  return rc;
}

/**********************************************************************/
/* mod vote_processor                                                */
/**********************************************************************/

static int
vote_processor_process_authorize_with_seed_instruction(
    /* invoke_context */
    instruction_ctx_t instruction_context,
    /* transaction_context */
    fd_borrowed_account_t * vote_account,
    fd_pubkey_t const *     new_authority,
    fd_vote_authorize_t     authorization_type,
    fd_pubkey_t const *     current_authority_derived_key_owner,
    char *                  current_authority_derived_key_seed ) {
  int               rc;
  instruction_ctx_t ctx = instruction_context;

  /* This is intentionally duplicative with the entrypoint to vote process instruction to match Labs
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L34-L36
   */

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L31
  if ( 0 != memcmp( &ctx.txn_ctx->accounts[ctx.instr->acct_txn_idxs[1]],
                    ctx.global->sysvar_clock,
                    sizeof( fd_pubkey_t ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }
  fd_sol_sysvar_clock_t clock;
  fd_sysvar_clock_read( ctx.global, &clock );

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L32
  fd_pubkey_t * expected_authority_keys[SIGNERS_MAX] = { 0 };
  for ( int i = 0; i < SIGNERS_MAX; i++ ) {
    expected_authority_keys[i] =
        (fd_pubkey_t *)fd_valloc_malloc( ctx.global->valloc, 1, sizeof( fd_pubkey_t ) );
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L33
  if ( FD_UNLIKELY( fd_instr_acc_is_signer_idx( ctx.instr, 2 ) ) ) {
    rc = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L34-L36
    fd_pubkey_t const * base_pubkey = &ctx.txn_ctx->accounts[ctx.instr->acct_txn_idxs[2]];

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L37-L41
    if ( FD_UNLIKELY(
             rc = fd_pubkey_create_with_seed( base_pubkey->uc,
                                              current_authority_derived_key_seed,
                                              /* TODO DoS vector? */
                                              strlen( current_authority_derived_key_seed ),
                                              current_authority_derived_key_owner->uc,
                                              /* insert */ expected_authority_keys[0]->uc ) !=
                  FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      return rc;
    }
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_processor.rs#L43-L50
  rc = vote_state_authorize( vote_account,
                             new_authority,
                             authorization_type,
                             (fd_pubkey_t const **)expected_authority_keys,
                             &clock,
                             ctx );
  for ( int i = 0; i < SIGNERS_MAX; i++ ) {
    fd_valloc_free( ctx.global->valloc, expected_authority_keys[i] );
  }

  return rc;
}

/**********************************************************************/
/* mod vote_state                                                    */
/**********************************************************************/

static inline fd_vote_lockout_t *
vote_state_last_lockout( fd_vote_state_t * self ) {
  fd_landed_vote_t * last_vote = deq_fd_landed_vote_t_peek_tail( self->votes );
  if ( FD_UNLIKELY( !last_vote ) ) return NULL;
  return &last_vote->lockout;
}

static inline ulong *
vote_state_last_voted_slot( fd_vote_state_t * self ) {
  fd_vote_lockout_t * last_lockout = vote_state_last_lockout( self );
  if ( FD_UNLIKELY( !last_lockout ) ) return NULL;
  return &last_lockout->slot;
}

static bool
vote_state_contains_slot( fd_vote_state_t * vote_state, ulong slot ) {
  ulong start = deq_fd_landed_vote_t_iter_init( vote_state->votes );
  ulong end   = deq_fd_landed_vote_t_iter_init_reverse( vote_state->votes );

  while ( start <= end ) {
    ulong mid      = start + ( end - start ) / 2;
    ulong mid_slot = deq_fd_landed_vote_t_peek_index( vote_state->votes, mid )->lockout.slot;
    if ( mid_slot == slot ) {
      return true;
    } else if ( mid_slot < slot ) {
      start = mid + 1;
    } else {
      end = mid - 1;
    }
  }
  return false;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L178
static int
vote_state_check_update_vote_state_slots_are_valid( fd_vote_state_t *        vote_state,
                                                    fd_vote_state_update_t * vote_state_update,
                                                    fd_slot_hashes_t *       slot_hashes,
                                                    instruction_ctx_t        ctx

) {
  if ( FD_UNLIKELY( deq_fd_vote_lockout_t_empty( vote_state_update->lockouts ) ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_EMPTY_SLOTS;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  fd_landed_vote_t * last_vote = deq_fd_landed_vote_t_peek_tail( vote_state->votes );
  if ( FD_LIKELY( last_vote ) ) {
    if ( FD_UNLIKELY( deq_fd_vote_lockout_t_peek_tail( vote_state_update->lockouts )->slot <=
                      last_vote->lockout.slot ) ) {
      ctx.txn_ctx->custom_err = FD_VOTE_VOTE_TOO_OLD;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  }

  /* must be nonempty, checked above */
  ulong last_vote_state_update_slot =
      deq_fd_vote_lockout_t_peek_tail( vote_state_update->lockouts )->slot;

  if ( FD_UNLIKELY( deq_fd_slot_hash_t_empty( slot_hashes->hashes ) ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_SLOTS_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  ulong earliest_slot_hash_in_history =
      deq_fd_slot_hash_t_peek_tail_const( slot_hashes->hashes )->slot;

  if ( FD_UNLIKELY( last_vote_state_update_slot < earliest_slot_hash_in_history ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_VOTE_TOO_OLD;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  ulong * original_proposed_root = vote_state_update->root;
  if ( original_proposed_root ) {
    ulong new_proposed_root = *original_proposed_root;
    if ( earliest_slot_hash_in_history > new_proposed_root ) {
      vote_state_update->root = vote_state->root_slot;
      ulong   prev_slot       = ULONG_MAX;
      ulong * current_root    = vote_state_update->root;
      for ( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( vote_state->votes );
            !deq_fd_landed_vote_t_iter_done( vote_state->votes, iter );
            iter = deq_fd_landed_vote_t_iter_next( vote_state->votes, iter ) ) {
        fd_landed_vote_t * vote = deq_fd_landed_vote_t_iter_ele( vote_state->votes, iter );
        bool               is_slot_bigger_than_root = true;
        if ( current_root ) { is_slot_bigger_than_root = vote->lockout.slot > *current_root; }

        FD_TEST( vote->lockout.slot < prev_slot && is_slot_bigger_than_root );
        if ( vote->lockout.slot <= new_proposed_root ) {
          vote_state_update->root = &vote->lockout.slot;
          break;
        }
        prev_slot = vote->lockout.slot;
      }
    }
  }

  ulong * root_to_check           = vote_state_update->root;
  ulong   vote_state_update_index = 0;
  ulong   lockouts_len            = deq_fd_vote_lockout_t_cnt( vote_state_update->lockouts );

  ulong   slot_hashes_index                   = deq_fd_slot_hash_t_cnt( slot_hashes->hashes );
  ulong * vote_state_update_indexes_to_filter = (ulong *)fd_valloc_malloc(
      ctx.global->valloc, sizeof( ulong ), lockouts_len * sizeof( ulong ) );
  ulong filter_index = 0;

  while ( vote_state_update_index < lockouts_len && slot_hashes_index > 0 ) {
    ulong proposed_vote_slot = deq_fd_vote_lockout_t_peek_index_const( vote_state_update->lockouts,
                                                                       vote_state_update_index )
                                   ->slot;
    if ( root_to_check ) { proposed_vote_slot = *root_to_check; }

    if ( !root_to_check && vote_state_update_index > 0 &&
         proposed_vote_slot <= deq_fd_vote_lockout_t_peek_index_const( vote_state_update->lockouts,
                                                                       vote_state_update_index - 1 )
                                   ->slot ) {
      ctx.txn_ctx->custom_err = FD_VOTE_SLOTS_NOT_ORDERED;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    ulong ancestor_slot =
        deq_fd_slot_hash_t_peek_index_const( slot_hashes->hashes, slot_hashes_index - 1 )->slot;
    if ( proposed_vote_slot < ancestor_slot ) {
      ulong cnt = deq_fd_slot_hash_t_cnt( slot_hashes->hashes );
      if ( slot_hashes_index == cnt ) {
        FD_TEST( proposed_vote_slot < earliest_slot_hash_in_history );
        if ( !vote_state_contains_slot( vote_state, proposed_vote_slot ) && !root_to_check ) {
          vote_state_update_indexes_to_filter[filter_index++] = vote_state_update_index;
        }

        if ( root_to_check ) {
          FD_TEST( *root_to_check == proposed_vote_slot );
          FD_TEST( *root_to_check < earliest_slot_hash_in_history );

          root_to_check = NULL;
        } else {
          vote_state_update_index = fd_ulong_sat_add( vote_state_update_index, 1 );
        }
        continue;
      } else {
        if ( root_to_check ) {
          ctx.txn_ctx->custom_err = FD_VOTE_ROOT_ON_DIFFERENT_FORK;
        } else {
          ctx.txn_ctx->custom_err = FD_VOTE_SLOTS_MISMATCH;
        }
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
    } else if ( proposed_vote_slot > ancestor_slot ) {
      slot_hashes_index = fd_ulong_sat_sub( slot_hashes_index, 1 );
      continue;
    } else {
      if ( root_to_check ) {
        root_to_check = NULL;
      } else {
        vote_state_update_index = fd_ulong_sat_add( vote_state_update_index, 1 );
        slot_hashes_index       = fd_ulong_sat_sub( slot_hashes_index, 1 );
      }
    }
  }

  if ( vote_state_update_index != deq_fd_vote_lockout_t_cnt( vote_state_update->lockouts ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_SLOTS_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  // FD_TEST( last_vote_state_update_slot == slot_hashes[slot_hashes_index].0);

  if ( memcmp( &deq_fd_slot_hash_t_peek_index_const( slot_hashes->hashes, slot_hashes_index )->hash,
               &vote_state_update->hash,
               sizeof( fd_hash_t ) ) != 0 ) {
    ctx.txn_ctx->custom_err = FD_VOTE_SLOT_HASH_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  vote_state_update_index = 0;
  for ( ulong i = 0; i < filter_index; i++ ) {
    deq_fd_vote_lockout_t_pop_index( vote_state_update->lockouts,
                                     vote_state_update_indexes_to_filter[i] );
  }
  fd_valloc_free( ctx.global->valloc, vote_state_update_indexes_to_filter );

  return OK;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L421
static int
vote_state_check_slots_are_valid( fd_vote_state_t *  vote_state,
                                  ulong *            vote_slots,
                                  fd_hash_t *        vote_hash,
                                  fd_slot_hashes_t * slot_hashes,
                                  instruction_ctx_t  ctx ) {
  ulong i              = 0;
  ulong j              = deq_fd_slot_hash_t_cnt( slot_hashes->hashes );
  ulong vote_slots_len = deq_ulong_cnt( vote_slots );

  while ( i < vote_slots_len && j > 0 ) {
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L446-L448
    ulong * last_voted_slot = vote_state_last_voted_slot( vote_state );
    if ( FD_UNLIKELY( last_voted_slot &&
                      *deq_ulong_peek_index( vote_slots, i ) <= *last_voted_slot ) ) {
      if ( FD_UNLIKELY( i + 1 < i ) ) {
        FD_LOG_ERR( ( "`i` is bounded by `MAX_LOCKOUT_HISTORY` when finding larger slots" ) );
      }
      i++;
      continue;
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L457-L463
    if ( FD_UNLIKELY( j - 1 > j ) ) FD_LOG_ERR( ( "`j` is positive when finding newer slots" ) );
    if ( FD_UNLIKELY( *deq_ulong_peek_index( vote_slots, i ) !=
                      deq_fd_slot_hash_t_peek_index( slot_hashes->hashes, j - 1 )->slot ) ) {
      j--;
      continue;
    }

    if ( FD_UNLIKELY( i + 1 < i ) ) {
      FD_LOG_ERR( ( "`i` is bounded by `MAX_LOCKOUT_HISTORY` when hash is found" ) );
    }
    i++;
    if ( FD_UNLIKELY( j - 1 > j ) ) { FD_LOG_ERR( ( "`j` is positive when hash is found" ) ); }
    j--;
  }

  if ( FD_UNLIKELY( j == deq_fd_slot_hash_t_cnt( slot_hashes->hashes ) ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_VOTE_TOO_OLD;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  if ( FD_UNLIKELY( i != vote_slots_len ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_SLOTS_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  if ( FD_UNLIKELY( 0 != memcmp( &deq_fd_slot_hash_t_peek_index( slot_hashes->hashes, j )->hash,
                                 vote_hash,
                                 32UL ) ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_SLOT_HASH_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  return OK;
}

static int
vote_state_process_new_vote_state( fd_vote_state_t *   vote_state,
                                   fd_vote_lockout_t * new_state,
                                   ulong *             new_root,
                                   ulong *             timestamp,
                                   ulong               epoch,
                                   /* feature_set */
                                   instruction_ctx_t ctx ) {
  FD_TEST( !deq_fd_vote_lockout_t_empty( new_state ) );
  if ( FD_UNLIKELY( deq_fd_vote_lockout_t_cnt( new_state ) > MAX_LOCKOUT_HISTORY ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_TOO_MANY_VOTES;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  };

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L559-L569
  if ( FD_UNLIKELY( new_root && vote_state->root_slot ) ) {
    if ( FD_UNLIKELY( *new_root < *vote_state->root_slot ) ) {
      ctx.txn_ctx->custom_err = FD_VOTE_ROOT_ROLL_BACK;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  } else if ( FD_UNLIKELY( !new_root && vote_state->root_slot ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_ROOT_ROLL_BACK;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  fd_vote_lockout_t * previous_vote = NULL;
  for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( new_state );
        !deq_fd_vote_lockout_t_iter_done( new_state, iter );
        iter = deq_fd_vote_lockout_t_iter_next( new_state, iter ) ) {
    fd_vote_lockout_t * vote = deq_fd_vote_lockout_t_iter_ele( new_state, iter );
    if ( FD_LIKELY( vote->confirmation_count == 0 ) ) {
      ctx.txn_ctx->custom_err = FD_VOTE_ZERO_CONFIRMATIONS;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    } else if ( FD_UNLIKELY( vote->confirmation_count > MAX_LOCKOUT_HISTORY ) ) {
      ctx.txn_ctx->custom_err = FD_VOTE_CONFIRMATION_TOO_LARGE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    } else if ( FD_LIKELY( new_root ) ) {
      if ( FD_UNLIKELY( vote->slot <= *new_root && *new_root != SLOT_DEFAULT ) ) {
        ctx.txn_ctx->custom_err = FD_VOTE_SLOT_SMALLER_THAN_ROOT;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
    }

    if ( FD_LIKELY( previous_vote ) ) {
      if ( FD_UNLIKELY( previous_vote->slot >= vote->slot ) ) {
        ctx.txn_ctx->custom_err = FD_VOTE_SLOTS_NOT_ORDERED;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      } else if ( FD_UNLIKELY( previous_vote->confirmation_count <= vote->confirmation_count ) ) {
        ctx.txn_ctx->custom_err = FD_VOTE_CONFIRMATIONS_NOT_ORDERED;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      } else if ( FD_UNLIKELY( vote->slot > lockout_last_locked_out_slot( previous_vote ) ) ) {
        ctx.txn_ctx->custom_err = FD_VOTE_NEW_VOTE_STATE_LOCKOUT_MISMATCH;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
    }
    previous_vote = vote;
  }

  ulong current_vote_state_index = 0;
  ulong new_vote_state_index     = 0;

  ulong finalized_slot_count = 1;

  if ( FD_LIKELY( new_root ) ) {
    for ( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( vote_state->votes );
          !deq_fd_landed_vote_t_iter_done( vote_state->votes, iter );
          iter = deq_fd_landed_vote_t_iter_next( vote_state->votes, iter ) ) {
      fd_landed_vote_t * current_vote = deq_fd_landed_vote_t_iter_ele( vote_state->votes, iter );
      if ( FD_UNLIKELY( current_vote->lockout.slot <= *new_root ) ) {
        current_vote_state_index++;
        if ( FD_UNLIKELY( current_vote->lockout.slot != *new_root ) ) finalized_slot_count++;
        continue;
      }
      break;
    }
  }

  while ( current_vote_state_index < deq_fd_landed_vote_t_cnt( vote_state->votes ) &&
          new_vote_state_index < deq_fd_vote_lockout_t_cnt( new_state ) ) {
    fd_landed_vote_t * current_vote =
        deq_fd_landed_vote_t_peek_index( vote_state->votes, current_vote_state_index );
    fd_vote_lockout_t * new_vote =
        deq_fd_vote_lockout_t_peek_index( new_state, new_vote_state_index );

    if ( FD_LIKELY( current_vote->lockout.slot < new_vote->slot ) ) {
      ulong last_locked_out_slot =
          current_vote->lockout.slot +
          (ulong)pow( INITIAL_LOCKOUT, current_vote->lockout.confirmation_count );
      if ( last_locked_out_slot >= new_state->slot ) {
        ctx.txn_ctx->custom_err = FD_VOTE_LOCKOUT_CONFLICT;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
      current_vote_state_index++;
    } else if ( FD_UNLIKELY( current_vote->lockout.slot == new_vote->slot ) ) {
      if ( new_vote->confirmation_count < current_vote->lockout.confirmation_count ) {
        ctx.txn_ctx->custom_err = FD_VOTE_CONFIRMATION_ROLL_BACK;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }
      current_vote_state_index++;
      new_vote_state_index++;
    } else {
      new_vote_state_index++;
    }
  }

  if ( ( ( vote_state->root_slot != NULL ) ^ ( new_root != NULL ) ) ||
       ( ( ( vote_state->root_slot != NULL ) && ( vote_state->root_slot != NULL ) ) &&
         ( *new_root != *vote_state->root_slot ) ) ) {
    if ( FD_FEATURE_ACTIVE( ctx.global, vote_state_update_credit_per_dequeue ) )
      vote_state_increment_credits( vote_state, epoch, finalized_slot_count );
    else vote_state_increment_credits( vote_state, epoch, 1 );
  }

  /* Update the new root slot, timestamp and votes */
  if ( timestamp != NULL ) {
    vote_state->last_timestamp.slot      = deq_fd_vote_lockout_t_peek_tail( new_state )->slot;
    vote_state->last_timestamp.timestamp = *timestamp;
  }

  /* TODO: add constructors to fd_types */
  if ( NULL != new_root ) {
    if ( vote_state->root_slot == NULL )
      vote_state->root_slot = fd_valloc_malloc( ctx.global->valloc, 8UL, sizeof( ulong ) );
    *vote_state->root_slot = *new_root;
  }
  deq_fd_landed_vote_t_remove_all( vote_state->votes );

  for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( new_state );
        !deq_fd_vote_lockout_t_iter_done( new_state, iter );
        iter = deq_fd_vote_lockout_t_iter_next( new_state, iter ) ) {
    FD_TEST( !deq_fd_vote_lockout_t_full( new_state ) );

    fd_vote_lockout_t * lockout = deq_fd_vote_lockout_t_iter_ele( new_state, iter );

    fd_landed_vote_t landed_vote = {
        .latency = 0, // TODO
        .lockout =
            {
                      .slot               = lockout->slot,
                      .confirmation_count = lockout->confirmation_count,
                      },
    };

    deq_fd_landed_vote_t_push_tail( vote_state->votes, landed_vote );
  }
  return OK;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L776
static int
vote_state_authorize( fd_borrowed_account_t * vote_account,
                      fd_pubkey_t const *     authorized,
                      fd_vote_authorize_t     vote_authorize,
                      fd_pubkey_t const *     signers[static SIGNERS_MAX],
                      fd_sol_sysvar_clock_t * clock,
                      /* feature_set */
                      instruction_ctx_t ctx ) {
  int rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L784-L786
  fd_vote_state_versioned_t vote_state_versioned;
  rc = vote_account_get_state( vote_account, ctx, &vote_state_versioned );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;
  vote_state_versions_convert_to_current( &vote_state_versioned, ctx );
  fd_vote_state_t * vote_state = &vote_state_versioned.inner.current;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L788
  switch ( vote_authorize.discriminant ) {

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L789-L809
  case fd_vote_authorize_enum_voter:;
    int authorized_withdrawer_signer =
        FD_EXECUTOR_INSTR_SUCCESS ==
        vote_state_verify_authorized_signer( &vote_state->authorized_withdrawer, signers );
    rc = vote_state_set_new_authorized_voter( vote_state,
                                              authorized,
                                              clock->epoch,
                                              clock->leader_schedule_epoch + 1UL,
                                              authorized_withdrawer_signer,
                                              signers,
                                              ctx );
    if ( FD_UNLIKELY( rc != OK ) ) return rc;
    break;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L810-L814
  case fd_vote_authorize_enum_withdrawer:
    rc = vote_state_verify_authorized_signer( &vote_state->authorized_withdrawer, signers );
    if ( FD_UNLIKELY( rc != OK ) ) return rc;
    memcpy( &vote_state->authorized_withdrawer, authorized, sizeof( fd_pubkey_t ) );
    break;

  // failing exhaustive check is fatal
  default:
    FD_LOG_ERR(
        ( "missing handler or invalid vote authorize mode: %lu", vote_authorize.discriminant ) );
  }

  return vote_state_set_vote_account_state( vote_account, vote_state, &ctx );
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L821
static int
vote_state_update_validator_identity( fd_borrowed_account_t * vote_account,
                                      fd_pubkey_t const *     node_pubkey,
                                      fd_pubkey_t const *     signers[static SIGNERS_MAX],
                                      /* feature_set */
                                      instruction_ctx_t ctx ) {
  int rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L959-L965
  fd_vote_state_versioned_t vote_state_versioned;
  rc = vote_account_get_state( vote_account, ctx, &vote_state_versioned );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;
  vote_state_versions_convert_to_current( &vote_state_versioned, ctx );
  fd_vote_state_t * vote_state = &vote_state_versioned.inner.current;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L832
  rc = vote_state_verify_authorized_signer( &vote_state->authorized_withdrawer, signers );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L835
  rc = vote_state_verify_authorized_signer( node_pubkey, signers );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L837
  vote_state->node_pubkey = *node_pubkey;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L839
  vote_state_set_vote_account_state( vote_account, vote_state, &ctx );

  return OK;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L843
static int
vote_state_update_commission( fd_borrowed_account_t * vote_account,
                              uchar                   commission,
                              fd_pubkey_t const *     signers[static SIGNERS_MAX],
                              /* feature_set */
                              instruction_ctx_t ctx ) {
  int rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L959-L965
  fd_vote_state_versioned_t vote_state_versioned;
  rc = vote_account_get_state( vote_account, ctx, &vote_state_versioned );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;
  vote_state_versions_convert_to_current( &vote_state_versioned, ctx );
  fd_vote_state_t * vote_state = &vote_state_versioned.inner.current;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L832
  rc = vote_state_verify_authorized_signer( &vote_state->authorized_withdrawer, signers );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L837
  vote_state->commission = commission;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L839
  vote_state_set_vote_account_state( vote_account, vote_state, &ctx );

  fd_bincode_destroy_ctx_t destroy = { .valloc = ctx.global->valloc };
  fd_vote_state_versioned_destroy( &vote_state_versioned, &destroy );
  return OK;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L877
static inline int
vote_state_verify_authorized_signer( fd_pubkey_t const * authorized,
                                     fd_pubkey_t const * signers[static SIGNERS_MAX] ) {
  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L881
  for ( ulong i = 0; i < SIGNERS_MAX; i++ ) {
    if ( FD_UNLIKELY( signers[i] &&
                      0 == memcmp( signers[i], authorized, sizeof( fd_pubkey_t ) ) ) ) {
      return FD_EXECUTOR_INSTR_SUCCESS;
    }
  }
  return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L889
static int
vote_state_withdraw(
    /* transaction_context */
    instruction_ctx_t       instruction_context,
    fd_borrowed_account_t * vote_account,
    ulong                   lamports,
    ulong                   to_account_index,
    fd_pubkey_t const *     signers[static SIGNERS_MAX],
    fd_rent_t *             rent_sysvar,
    fd_sol_sysvar_clock_t * clock
    /* feature_set */
) {
  int                 rc;
  instruction_ctx_t   ctx            = instruction_context;
  fd_pubkey_t const * txn_accs       = ctx.txn_ctx->accounts;
  uchar const *       instr_acc_idxs = ctx.instr->acct_txn_idxs;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L900-L901
  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L902-L904

  fd_vote_state_versioned_t vote_state_versioned;
  rc = vote_account_get_state( vote_account, ctx, &vote_state_versioned );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;
  vote_state_versions_convert_to_current( &vote_state_versioned, ctx );
  fd_vote_state_t * vote_state = &vote_state_versioned.inner.current;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L906
  rc = vote_state_verify_authorized_signer( &vote_state->authorized_withdrawer, signers );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L908-L911
  ulong remaining_balance = vote_account->const_meta->info.lamports - lamports;
  if ( FD_UNLIKELY( lamports > vote_account->const_meta->info.lamports ) ) {
    rc                               = FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    fd_bincode_destroy_ctx_t destroy = { .valloc = ctx.global->valloc };
    fd_vote_state_versioned_destroy( &vote_state_versioned, &destroy );
    return rc;
  }

  if ( FD_UNLIKELY( remaining_balance == 0 ) ) {
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L924
    int reject_active_vote_account_close = 0;

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L914-L923
    ulong last_epoch_with_credits;
    if ( FD_LIKELY( !deq_fd_vote_epoch_credits_t_empty( vote_state->epoch_credits ) ) ) {
      last_epoch_with_credits =
          deq_fd_vote_epoch_credits_t_peek_tail_const( vote_state->epoch_credits )->epoch;
      ulong current_epoch = clock->epoch;
      reject_active_vote_account_close =
          fd_ulong_sat_sub( current_epoch, last_epoch_with_credits ) < 2;
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L926-L933
    if ( FD_UNLIKELY( reject_active_vote_account_close ) ) {
      // TODO metrics
      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L927
      ctx.txn_ctx->custom_err = FD_VOTE_ACTIVE_VOTE_ACCOUNT_CLOSE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    } else {
      // TODO metrics
      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L931
      fd_vote_state_versioned_t vote_state_versions;
      fd_vote_state_versioned_new_disc( &vote_state_versions,
                                        fd_vote_state_versioned_enum_current );
      vote_state_versions.inner.current.prior_voters.idx      = 31;
      vote_state_versions.inner.current.prior_voters.is_empty = 1;
      fd_vote_state_t * default_vote_state                    = &vote_state_versions.inner.current;
      rc                                                      = 0;
      rc = vote_state_set_vote_account_state( vote_account, default_vote_state, &ctx );
      if ( FD_UNLIKELY( rc != 0 ) ) return rc;
    }
  } else {
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L935-L938
    ulong min_rent_exempt_balance =
        fd_rent_exempt_minimum_balance2( rent_sysvar, vote_account->const_meta->dlen );
    if ( remaining_balance < min_rent_exempt_balance ) {
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L941
  rc = fd_acc_mgr_modify( ctx.global->acc_mgr,
                          ctx.global->funk_txn,
                          vote_account->pubkey,
                          0,
                          0 /* TODO min_data_sz */,
                          vote_account);
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  rc = vote_account_checked_sub_lamports( vote_account->meta, lamports );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L943-L944
  FD_BORROWED_ACCOUNT_DECL(to_account);

  rc = fd_acc_mgr_modify( ctx.global->acc_mgr,
                          ctx.global->funk_txn,
                          &txn_accs[instr_acc_idxs[to_account_index]],
                          0,
                          0 /* TODO min_data_sz */,
                          to_account);
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L945
  rc = vote_account_checked_add_lamports( to_account->meta, lamports );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;
  return OK;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L146
static int
vote_state_set_vote_account_state( fd_borrowed_account_t * vote_account,
                                   fd_vote_state_t *       vote_state,
                                   /* feature_set */
                                   instruction_ctx_t * ctx ) {
  if ( FD_FEATURE_ACTIVE( ctx->global, vote_state_add_vote_latency ) ) {
    // This is a horrible conditional, but replicating as-is
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L155-L160
    ulong vsz = vote_state_versions_vote_state_size_of( true );
    if ( FD_UNLIKELY( ( vote_account_get_data_len( vote_account ) < vsz ) &&
                      ( !vote_account_is_rent_exempt_at_data_length( vote_account, vsz, *ctx ) ||
                        ( vote_account_set_data_length( vote_account, vsz, *ctx ) != OK ) ) ) ) {

      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L164-L166
      fd_vote_state_versioned_t v1_14_11;
      fd_vote_state_versioned_new_disc( &v1_14_11, fd_vote_state_versioned_enum_v1_14_11 );
      vote_state1_14_11_from_vote_state( vote_state, ctx, &v1_14_11.inner.v1_14_11 );
      // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L164-L166
      return vote_account_set_state( vote_account, &v1_14_11, *ctx );
    }
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L169

    // TODO: This is stupid...  optimize this... later
    fd_vote_state_versioned_t new_current = { .discriminant = fd_vote_state_versioned_enum_current,
                                              .inner        = { .current = *vote_state } };
    return vote_account_set_state( vote_account, &new_current, *ctx );
  } else {
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L172-L174
    fd_vote_state_versioned_t v1_14_11;
    fd_vote_state_versioned_new_disc( &v1_14_11, fd_vote_state_versioned_enum_v1_14_11 );

    vote_state1_14_11_from_vote_state( vote_state, ctx, &v1_14_11.inner.v1_14_11 );
    return vote_account_set_state( vote_account, &v1_14_11, *ctx );
  }
}

static int
vote_state_process_vote_unfiltered( fd_vote_state_t *  vote_state,
                                    ulong *            vote_slots,
                                    fd_vote_t *        vote,
                                    fd_slot_hashes_t * slot_hashes,
                                    ulong              epoch,
                                    instruction_ctx_t  ctx ) {
  int rc;
  rc = vote_state_check_slots_are_valid( vote_state, vote_slots, &vote->hash, slot_hashes, ctx );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;
  for ( deq_ulong_iter_t iter = deq_ulong_iter_init( vote->slots );
        !deq_ulong_iter_done( vote->slots, iter );
        iter = deq_ulong_iter_next( vote->slots, iter ) ) {
    ulong * ele = deq_ulong_iter_ele( vote->slots, iter );
    vote_state_process_next_vote_slot( vote_state, *ele, epoch );
  }
  return OK;
}

static int
vote_state_process_vote( fd_vote_state_t *  vote_state,
                         fd_vote_t *        vote,
                         fd_slot_hashes_t * slot_hashes,
                         ulong              epoch,
                         instruction_ctx_t  ctx ) {
  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L734
  ulong earliest_slot_in_history = 0;
  if ( FD_UNLIKELY( !deq_fd_slot_hash_t_empty( slot_hashes->hashes ) ) ) {
    earliest_slot_in_history = deq_fd_slot_hash_t_peek_tail_const( slot_hashes->hashes )->slot;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L735-L740
  ulong   scratch[128];
  ulong * vote_slots = deq_ulong_join( deq_ulong_new( scratch ) );
  for ( deq_ulong_iter_t iter = deq_ulong_iter_init( vote->slots );
        !deq_ulong_iter_done( vote->slots, iter );
        iter = deq_ulong_iter_next( vote->slots, iter ) ) {
    ulong * ele = deq_ulong_iter_ele( vote->slots, iter );
    if ( FD_UNLIKELY( *ele >= earliest_slot_in_history ) ) {
      vote_slots = deq_ulong_push_tail( vote_slots, *ele );
    }
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L741-L743
  if ( FD_UNLIKELY( deq_ulong_cnt( vote_slots ) == 0 ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_VOTES_TOO_OLD_ALL_FILTERED;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L744
  return vote_state_process_vote_unfiltered(
      vote_state, vote_slots, vote, slot_hashes, epoch, ctx );
}

static int
vote_state_initialize_account( fd_borrowed_account_t *       vote_account,
                               fd_vote_init_t *              vote_init,
                               fd_pubkey_t const *           signers[static SIGNERS_MAX],
                               fd_sol_sysvar_clock_t const * clock,
                               /* feature_set */
                               instruction_ctx_t ctx ) {
  int                      rc;
  fd_bincode_destroy_ctx_t destroy = { .valloc = ctx.global->valloc };

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L959-L965
  ulong vote_account_data_len = vote_account_get_data_len( vote_account );
  if ( FD_UNLIKELY( vote_account_data_len !=
                    vote_state_versions_vote_state_size_of(
                        FD_FEATURE_ACTIVE( ctx.global, vote_state_add_vote_latency ) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L966
  fd_vote_state_versioned_t versioned;
  rc = vote_account_get_state( vote_account, ctx, &versioned );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L968-L970
  if ( FD_UNLIKELY( !vote_state_versions_is_uninitialized( &versioned ) ) ) {
    fd_vote_state_versioned_destroy( &versioned, &destroy );
    return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L973
  rc = vote_state_verify_authorized_signer( &vote_init->node_pubkey, signers );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L975
  vote_state_new( vote_init, clock, ctx, &versioned.inner.current );
  rc = vote_state_set_vote_account_state( vote_account, &versioned.inner.current, &ctx );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  fd_vote_state_versioned_destroy( &versioned, &destroy );
  return OK;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L978-L994
static int
vote_state_verify_and_get_vote_state( fd_borrowed_account_t *        vote_account,
                                      fd_sol_sysvar_clock_t const *  clock,
                                      fd_pubkey_t const *            signers[SIGNERS_MAX],
                                      instruction_ctx_t              ctx,
                                      /* return */ fd_vote_state_t * vote_state ) {
  int                       rc;
  fd_vote_state_versioned_t versioned;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L983
  rc = vote_account_get_state( vote_account, ctx, &versioned );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  if ( FD_UNLIKELY( vote_state_versions_is_uninitialized( &versioned ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L989
  vote_state_versions_convert_to_current( &versioned, ctx );
  memcpy( vote_state, &versioned.inner.current, sizeof( fd_vote_state_t ) );

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L990
  fd_pubkey_t * authorized_voter = NULL;
  rc                             = vote_state_get_and_update_authorized_voter(
      vote_state, clock->epoch, ctx, &authorized_voter );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L991
  rc = vote_state_verify_authorized_signer( authorized_voter, signers );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

static int
vote_state_process_vote_with_account( fd_borrowed_account_t *       vote_account,
                                      fd_slot_hashes_t *            slot_hashes,
                                      fd_sol_sysvar_clock_t const * clock,
                                      fd_vote_t *                   vote,
                                      fd_pubkey_t const * signers[static SIGNERS_MAX],
                                      instruction_ctx_t   ctx ) {
  int             rc;
  fd_vote_state_t vote_state;
  rc = vote_state_verify_and_get_vote_state( vote_account, clock, signers, ctx, &vote_state );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  rc = vote_state_process_vote( &vote_state, vote, slot_hashes, clock->epoch, ctx );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L1007-L1013
  if ( FD_LIKELY( vote->timestamp ) ) {
    if ( FD_UNLIKELY( deq_ulong_cnt( vote->slots ) == 0 ) ) {
      ctx.txn_ctx->custom_err = FD_VOTE_EMPTY_SLOTS;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    ulong * max = deq_ulong_peek_head( vote->slots ) ? deq_ulong_peek_head( vote->slots ) : NULL;
    for ( deq_ulong_iter_t iter = deq_ulong_iter_init( vote->slots );
          !deq_ulong_iter_done( vote->slots, iter );
          iter = deq_ulong_iter_next( vote->slots, iter ) ) {
      ulong * ele = deq_ulong_iter_ele( vote->slots, iter );
      *max        = fd_ulong_max( *max, *ele );
    }
    if ( FD_UNLIKELY( !max ) ) {
      ctx.txn_ctx->custom_err = FD_VOTE_EMPTY_SLOTS;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
    // https://github.com/firedancer-io/solana/blob/debug-master/programs/vote/src/vote_state/mod.rs#L1012
    rc = vote_state_process_timestamp( &vote_state, *max, *vote->timestamp, ctx );
    if ( FD_UNLIKELY( rc != OK ) ) return rc;

    // FD-specific: update the global.bank.timestamp_votes pool
    fd_vote_record_timestamp_vote( ctx.global, vote_account->pubkey, *vote->timestamp );
  }

  return vote_state_set_vote_account_state( vote_account, &vote_state, &ctx );
}

static int
vote_state_process_vote_state_update( fd_borrowed_account_t *       vote_account,
                                      fd_slot_hashes_t *            slot_hashes,
                                      fd_sol_sysvar_clock_t const * clock,
                                      fd_vote_state_update_t *      vote_state_update,
                                      fd_pubkey_t const * signers[static SIGNERS_MAX],
                                      /* feature_set */
                                      instruction_ctx_t ctx ) {
  int rc;

  fd_vote_state_t vote_state;
  rc = vote_state_verify_and_get_vote_state( vote_account, clock, signers, ctx, &vote_state );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  rc = vote_state_do_process_vote_state_update(
      &vote_state, slot_hashes, clock->epoch, vote_state_update, ctx );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  return vote_state_set_vote_account_state( vote_account, &vote_state, &ctx );
}

static int
vote_state_do_process_vote_state_update( fd_vote_state_t *        vote_state,
                                         fd_slot_hashes_t *       slot_hashes,
                                         ulong                    epoch,
                                         fd_vote_state_update_t * vote_state_update,
                                         /* feature_set */
                                         instruction_ctx_t ctx ) {
  int rc;

  rc = vote_state_check_update_vote_state_slots_are_valid(
      vote_state, vote_state_update, slot_hashes, ctx );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  return vote_state_process_new_vote_state( vote_state,
                                            vote_state_update->lockouts,
                                            vote_state_update->root,
                                            vote_state_update->timestamp,
                                            epoch,
                                            ctx );
}

/**********************************************************************/
/* impl VoteState                                                     */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L312
static void
vote_state_new( fd_vote_init_t *               vote_init,
                fd_sol_sysvar_clock_t const *  clock,
                instruction_ctx_t              ctx,
                /* return */ fd_vote_state_t * vote_state ) {
  vote_state->node_pubkey = vote_init->node_pubkey;
  authorized_voters_new(
      clock->epoch, &vote_init->authorized_voter, ctx, &vote_state->authorized_voters );
  vote_state->authorized_withdrawer = vote_init->authorized_withdrawer;
  vote_state->commission            = vote_init->commission;
  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L318
  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L239-L249
  vote_state->prior_voters.idx      = 31;
  vote_state->prior_voters.is_empty = 1;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L338-L342
static inline ulong
vote_state_size_of( void ) {
  return 3762UL;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L800-L807
static inline int
verify( fd_pubkey_t *       epoch_authorized_voter,
        int                 authorized_withdrawer_signer,
        fd_pubkey_t const * signers[static SIGNERS_MAX] ) {
  if ( FD_UNLIKELY( authorized_withdrawer_signer ) ) return OK;
  else return vote_state_verify_authorized_signer( epoch_authorized_voter, signers );
}

static void
vote_state_process_next_vote_slot( fd_vote_state_t * self, ulong next_vote_slot, ulong epoch ) {
  ulong * last_voted_slot = vote_state_last_voted_slot( self );
  if ( FD_UNLIKELY( last_voted_slot && next_vote_slot <= *last_voted_slot ) ) return;

  fd_vote_lockout_t lockout = { .slot = next_vote_slot };

  vote_state_pop_expired_votes( self, next_vote_slot );

  if ( FD_UNLIKELY( deq_fd_landed_vote_t_cnt( self->votes ) == MAX_LOCKOUT_HISTORY ) ) {
    fd_landed_vote_t vote = deq_fd_landed_vote_t_pop_head( self->votes );
    *self->root_slot       = vote.lockout.slot; // FIXME is a null check required here?

    vote_state_increment_credits( self, epoch, 1 );
  }

  deq_fd_landed_vote_t_push_tail( self->votes,
                                  ( fd_landed_vote_t ){ .latency = 0, .lockout = lockout } );
  vote_state_double_lockouts( self );
}

static void
vote_state_increment_credits( fd_vote_state_t * self, ulong epoch, ulong credits ) {
  if ( FD_UNLIKELY( deq_fd_vote_epoch_credits_t_empty( self->epoch_credits ) ) ) {
    deq_fd_vote_epoch_credits_t_push_tail(
        self->epoch_credits,
        ( fd_vote_epoch_credits_t ){ .epoch = epoch, .credits = 0, .prev_credits = 0 } );
  } else if ( FD_LIKELY( epoch !=
                         deq_fd_vote_epoch_credits_t_peek_tail( self->epoch_credits )->epoch ) ) {
    fd_vote_epoch_credits_t * last = deq_fd_vote_epoch_credits_t_peek_tail( self->epoch_credits );

    ulong credits      = last->credits;
    ulong prev_credits = last->prev_credits;

    if ( FD_LIKELY( credits != prev_credits ) ) {
      deq_fd_vote_epoch_credits_t_push_tail(
          self->epoch_credits,
          ( fd_vote_epoch_credits_t ){
              .epoch = epoch, .credits = credits, .prev_credits = credits } );
    } else {
      deq_fd_vote_epoch_credits_t_peek_tail( self->epoch_credits )->epoch = epoch;
    }

    if ( FD_UNLIKELY( deq_fd_vote_epoch_credits_t_cnt( self->epoch_credits ) >
                      MAX_EPOCH_CREDITS_HISTORY ) ) {
      deq_fd_vote_epoch_credits_t_pop_head( self->epoch_credits );
    }
  }

  deq_fd_vote_epoch_credits_t_peek_tail( self->epoch_credits )->credits = fd_ulong_sat_add(
      deq_fd_vote_epoch_credits_t_peek_tail( self->epoch_credits )->credits, credits );
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L529
static int
vote_state_set_new_authorized_voter(
    fd_vote_state_t *                          self,
    fd_pubkey_t const *                        authorized_pubkey,
    ulong                                      current_epoch,
    ulong                                      target_epoch,
    /* "verify" closure */ int                 authorized_withdrawer_signer,
    /* "verify" closure */ fd_pubkey_t const * signers[static SIGNERS_MAX],
    instruction_ctx_t                          ctx ) {
  int           rc;
  fd_pubkey_t * epoch_authorized_voter = NULL;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L539
  rc = vote_state_get_and_update_authorized_voter(
      self, current_epoch, ctx, &epoch_authorized_voter );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L540
  rc = verify( epoch_authorized_voter, authorized_withdrawer_signer, signers );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L547-549
  if ( FD_UNLIKELY( authorized_voters_contains( &self->authorized_voters, target_epoch ) ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_TOO_SOON_TO_REAUTHORIZE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L552-L555
  fd_vote_authorized_voter_t * latest_authorized =
      authorized_voters_last( &self->authorized_voters );
  if ( FD_UNLIKELY( ( !latest_authorized ) ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  ulong         latest_epoch             = latest_authorized->epoch;
  fd_pubkey_t * latest_authorized_pubkey = &latest_authorized->pubkey;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L560-L579
  if ( 0 != memcmp( latest_authorized_pubkey, authorized_pubkey, sizeof( fd_pubkey_t ) ) ) {
    fd_vote_prior_voters_t * prior_voters = &self->prior_voters;

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L562-L563
    ulong epoch_of_last_authorized_switch = 0UL;
    if ( !prior_voters->is_empty ) {
      epoch_of_last_authorized_switch = prior_voters->buf[prior_voters->idx].epoch_end;
    }

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L571
    FD_TEST( target_epoch > latest_epoch );

    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L574-L578
    prior_voters->idx += 1UL; /* FIXME bounds check */
    prior_voters->idx %= 32UL;
    prior_voters->buf[prior_voters->idx] =
        ( fd_vote_prior_voter_t ){ .pubkey      = *latest_authorized_pubkey,
                                   .epoch_start = epoch_of_last_authorized_switch,
                                   .epoch_end   = target_epoch };
    prior_voters->is_empty = 0;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L581-L582
  fd_vote_authorized_voter_t * ele =
      fd_vote_authorized_voters_pool_ele_acquire( self->authorized_voters.pool );
  ele->epoch = target_epoch;
  memcpy( &ele->pubkey, authorized_pubkey, sizeof( fd_pubkey_t ) );
  ele->prio = (ulong)&ele->pubkey;
  fd_vote_authorized_voters_treap_ele_insert(
      self->authorized_voters.treap, ele, self->authorized_voters.pool );

  return OK;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L587
static int
vote_state_get_and_update_authorized_voter( fd_vote_state_t *            self,
                                            ulong                        current_epoch,
                                            instruction_ctx_t            ctx,
                                            /* returns */ fd_pubkey_t ** pubkey ) {
  fd_vote_authorized_voter_t * authorized_voter =
      authorized_voters_get_and_cache_authorized_voter_for_epoch( &self->authorized_voters,
                                                                  current_epoch );
  if ( FD_UNLIKELY( !authorized_voter ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  *pubkey = &authorized_voter->pubkey;
  authorized_voters_purge_authorized_voters( &self->authorized_voters, current_epoch, ctx );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L605
static void
vote_state_pop_expired_votes( fd_vote_state_t * self, ulong next_vote_slot ) {
  while ( !deq_fd_landed_vote_t_empty( self->votes ) ) {
    fd_landed_vote_t * vote = deq_fd_landed_vote_t_peek_tail( self->votes );
    ulong last_locked_out_slot = lockout_last_locked_out_slot(&vote->lockout);
    if ( last_locked_out_slot >= next_vote_slot ) break;
    deq_fd_landed_vote_t_pop_tail( self->votes );
  }
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L614
static void
vote_state_double_lockouts( fd_vote_state_t * self ) {
  ulong stack_depth = deq_fd_landed_vote_t_cnt( self->votes );
  ulong i           = 0;
  for ( deq_fd_landed_vote_t_iter_t iter = deq_fd_landed_vote_t_iter_init( self->votes );
        !deq_fd_landed_vote_t_iter_done( self->votes, iter );
        iter = deq_fd_landed_vote_t_iter_next( self->votes, iter ) ) {
    fd_landed_vote_t * v = deq_fd_landed_vote_t_iter_ele( self->votes, iter );
    if ( FD_UNLIKELY( i + v->lockout.confirmation_count < i ) ) {
      FD_LOG_ERR(
          ( "`confirmation_count` and tower_size should be bounded by `MAX_LOCKOUT_HISTORY`" ) );
    }
    ulong confirmations = i + v->lockout.confirmation_count;
    if ( stack_depth > confirmations ) v->lockout.confirmation_count++;
    i++;
  }
}

// https://github.com/firedancer-io/solana/blob/debug-master/sdk/program/src/vote/state/mod.rs#L628
static int
vote_state_process_timestamp( fd_vote_state_t * self,
                              ulong             slot,
                              ulong             timestamp,
                              instruction_ctx_t ctx ) {
  if ( FD_UNLIKELY( ( slot < self->last_timestamp.slot || timestamp < self->last_timestamp.timestamp ) ||
                    ( slot == self->last_timestamp.slot && slot != self->last_timestamp.slot &&
                      timestamp != self->last_timestamp.timestamp &&
                      self->last_timestamp.slot != 0 ) ) ) {
    ctx.txn_ctx->custom_err = FD_VOTE_TIMESTAMP_TOO_OLD;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  self->last_timestamp.slot = slot;
  self->last_timestamp.timestamp = timestamp;

  return OK;
}

/**********************************************************************/
/* impl Lockout                                                       */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L83
static inline ulong
lockout_lockout( fd_vote_lockout_t * self ) {
  return (ulong)pow( INITIAL_LOCKOUT, self->confirmation_count ); // FIXME
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L90
static inline ulong
lockout_last_locked_out_slot( fd_vote_lockout_t * self ) {
  return fd_ulong_sat_add( self->slot, lockout_lockout( self ) );
}

/**********************************************************************/
/* impl VoteState1_14_11                                              */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_1_14_11.rs#L45-L49
static inline ulong
vote_state1_14_11_size_of( void ) {
  return 3731UL;
}

/**********************************************************************/
/* impl From<VoteState> for VoteState1_14_11                          */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_1_14_11.rs#L60
static void
vote_state1_14_11_from_vote_state( fd_vote_state_t *                      vote_state,
                                   instruction_ctx_t *                    ctx,
                                   /* return */ fd_vote_state_1_14_11_t * vote_state1_14_11 ) {
  vote_state1_14_11->node_pubkey           = vote_state->node_pubkey;
  vote_state1_14_11->authorized_withdrawer = vote_state->authorized_withdrawer;
  vote_state1_14_11->commission            = vote_state->commission;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_1_14_11.rs#L65-L69
  if ( NULL != vote_state->votes ) {
    vote_state1_14_11->votes = deq_fd_vote_lockout_t_alloc( ctx->global->valloc );
    for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_landed_vote_t_iter_init( vote_state->votes );
          !deq_fd_landed_vote_t_iter_done( vote_state->votes, iter );
          iter = deq_fd_landed_vote_t_iter_next( vote_state->votes, iter ) ) {
      fd_landed_vote_t * landed_vote = deq_fd_landed_vote_t_iter_ele( vote_state->votes, iter );
      deq_fd_vote_lockout_t_push_tail( vote_state1_14_11->votes, landed_vote->lockout );
    }
  }

  vote_state1_14_11->root_slot         = vote_state->root_slot;
  vote_state1_14_11->authorized_voters = vote_state->authorized_voters;
  vote_state1_14_11->prior_voters      = vote_state->prior_voters;
  vote_state1_14_11->epoch_credits     = vote_state->epoch_credits;
  vote_state1_14_11->last_timestamp    = vote_state->last_timestamp;
}

/**********************************************************************/
/* impl VoteStateVersions                                             */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_versions.rs#L15
static void
vote_state_versions_convert_to_current( fd_vote_state_versioned_t * self, instruction_ctx_t ctx ) {
  switch ( self->discriminant ) {
  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_versions.rs#L17-L50
  case fd_vote_state_versioned_enum_v0_23_5: {
    fd_vote_state_0_23_5_t      state = self->inner.v0_23_5;
    fd_vote_authorized_voters_t authorized_voters;
    authorized_voters_new(
        state.authorized_voter_epoch, &state.authorized_voter, ctx, &authorized_voters );

    /* Temporary to hold current */
    fd_vote_state_t current;
    current.node_pubkey           = state.node_pubkey;
    current.authorized_withdrawer = state.authorized_withdrawer;
    current.commission            = state.commission;
    current.votes             = vote_state_versions_landed_votes_from_lockouts( state.votes, ctx );
    current.root_slot         = state.root_slot;
    current.authorized_voters = authorized_voters;
    current.prior_voters      = ( fd_vote_prior_voters_t ){
             .idx      = 31UL,
             .is_empty = 1,
    };
    memset( current.prior_voters.buf, 0, sizeof( current.prior_voters.buf ) );
    current.epoch_credits  = state.epoch_credits;
    current.last_timestamp = state.last_timestamp;

    /* Deallocate objects owned by old vote state */
    fd_bincode_destroy_ctx_t destroy = { .valloc = ctx.global->valloc };
    fd_vote_state_0_23_5_destroy( &state, &destroy );

    /* Emplace new vote state into target */
    self->discriminant = fd_vote_state_versioned_enum_current;
    memcpy( &self->inner.current, &current, sizeof( fd_vote_state_t ) );

    break;
  }
  case fd_vote_state_versioned_enum_v1_14_11: {
    fd_vote_state_1_14_11_t state = self->inner.v1_14_11;

    /* Temporary to hold current */
    fd_vote_state_t current;
    current.node_pubkey           = state.node_pubkey;
    current.authorized_withdrawer = state.authorized_withdrawer;
    current.commission            = state.commission;
    current.votes             = vote_state_versions_landed_votes_from_lockouts( state.votes, ctx );
    current.root_slot         = state.root_slot;
    current.authorized_voters = state.authorized_voters;
    // TODO is it safe to hang onto the old pointers?
    current.prior_voters  = state.prior_voters;
    current.epoch_credits = state.epoch_credits;
    // memcpy( &current.prior_voters, &state.prior_voters, sizeof( state.prior_voters ) );
    // memcpy( &current.epoch_credits, &state.epoch_credits, deq_fd_vote_epoch_credits_t_footprint()
    // );
    current.last_timestamp = state.last_timestamp;

    /* TODO Deallocate objects owned by old vote state? would require memcpys above */
    // fd_bincode_destroy_ctx_t destroy = { .valloc = ctx.global->valloc };
    // fd_vote_state_1_14_11_destroy( &state, &destroy );

    /* Emplace new vote state into target */
    self->discriminant = fd_vote_state_versioned_enum_current;
    memcpy( &self->inner.current, &current, sizeof( fd_vote_state_t ) );

    break;
  }
  case fd_vote_state_versioned_enum_current:
    break;
  default:
    FD_LOG_ERR( ( "unsupported vote state version: %u", self->discriminant ) );
  }
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_versions.rs#L74-L76
static fd_landed_vote_t *
vote_state_versions_landed_votes_from_lockouts( fd_vote_lockout_t * lockouts,
                                                instruction_ctx_t   ctx ) {
  fd_landed_vote_t * landed_votes = deq_fd_landed_vote_t_alloc( ctx.global->valloc );

  for ( deq_fd_vote_lockout_t_iter_t iter = deq_fd_vote_lockout_t_iter_init( lockouts );
        !deq_fd_vote_lockout_t_iter_done( lockouts, iter );
        iter = deq_fd_vote_lockout_t_iter_next( lockouts, iter ) ) {
    fd_vote_lockout_t * ele = deq_fd_vote_lockout_t_iter_ele( lockouts, iter );

    fd_landed_vote_t * elem = deq_fd_landed_vote_t_push_tail_nocopy( landed_votes );
    fd_landed_vote_new( elem );

    elem->latency                    = 0;
    elem->lockout.slot               = ele->slot;
    elem->lockout.confirmation_count = ele->confirmation_count;
  }

  return landed_votes;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_versions.rs#L78
static inline int
vote_state_versions_is_uninitialized( fd_vote_state_versioned_t * self ) {
  switch ( self->discriminant ) {
  case fd_vote_state_versioned_enum_v0_23_5:;
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_versions.rs#L81
    fd_pubkey_t pubkey_default = { 0 };
    return 0 ==
           memcmp( &self->inner.v0_23_5.authorized_voter, &pubkey_default, sizeof( fd_pubkey_t ) );
  case fd_vote_state_versioned_enum_v1_14_11:;
    return authorized_voters_is_empty( &self->inner.v1_14_11.authorized_voters );
  case fd_vote_state_versioned_enum_current:
    return authorized_voters_is_empty( &self->inner.current.authorized_voters );
  default:
    FD_LOG_ERR( ( "missing handler or invalid vote state version: %lu", self->discriminant ) );
  }
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/vote_state_versions.rs#L78
static inline ulong
vote_state_versions_vote_state_size_of( int is_current ) {
  return fd_ulong_if( is_current, vote_state_size_of(), vote_state1_14_11_size_of() );
}

/**********************************************************************/
/* impl VoteAccount                                                   */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L841
static inline int
vote_account_checked_add_lamports( fd_account_meta_t * self, ulong lamports ) {
  if ( FD_UNLIKELY( self->info.lamports > ( ULONG_MAX - lamports ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  };
  self->info.lamports += lamports;
  return OK;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L851
static inline int
vote_account_checked_sub_lamports( fd_account_meta_t * self, ulong lamports ) {
  if ( FD_UNLIKELY( lamports > self->info.lamports ) ) {
    return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  };
  self->info.lamports -= lamports;
  return OK;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L959
static ulong
vote_account_get_data_len( fd_borrowed_account_t const * self ) {
  return self->const_meta->dlen;
}

static int
vote_account_set_data_length( fd_borrowed_account_t * self,
                              ulong                   new_length,
                              instruction_ctx_t       ctx ) {
  // TODO which APIs should i be using?
  int rc = fd_account_can_data_be_resized( &ctx, self->const_meta, new_length, &rc );
  if ( FD_UNLIKELY( !rc ) ) return rc;

  rc = fd_account_can_data_be_changed( &ctx, self->const_meta, self->pubkey, &rc );
  if ( FD_UNLIKELY( !rc ) ) return rc;

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L933-L935
  if ( FD_UNLIKELY( vote_account_get_data_len( self ) == new_length ) ) return OK;

  rc = fd_account_touch( &ctx, self->const_meta, self->pubkey, &rc );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  // Tell funk we have a new length...
  rc = fd_acc_mgr_modify( ctx.global->acc_mgr,
                          ctx.global->funk_txn,
                          self->pubkey,
                          0,
                          new_length,
                          self);
  switch ( rc ) {
  case FD_ACC_MGR_SUCCESS:
    return OK;
  case FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT:
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L637
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  default:
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L639
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/programs/vote/src/vote_state/mod.rs#L966
static int
vote_account_get_state( fd_borrowed_account_t *                  self,
                        instruction_ctx_t                        ctx,
                        /* return */ fd_vote_state_versioned_t * versioned ) {
  int rc;
  fd_vote_state_versioned_new( versioned );

  fd_bincode_decode_ctx_t decode_ctx;
  decode_ctx.data    = self->const_data;
  decode_ctx.dataend = &self->const_data[self->const_meta->dlen];
  decode_ctx.valloc  = ctx.global->valloc;

  rc = fd_vote_state_versioned_decode( versioned, &decode_ctx );
  if ( FD_UNLIKELY( rc != FD_BINCODE_SUCCESS ) ) {
    FD_LOG_INFO( ( "fd_vote_state_versioned_decode failed: %d", rc ) );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

#if 0
  fd_flamenco_yaml_t * yaml =
    fd_flamenco_yaml_init( fd_flamenco_yaml_new(
        fd_valloc_malloc(ctx.global->valloc, fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() ) ),
      stdout );

  fd_vote_state_versioned_walk(yaml, versioned, fd_flamenco_yaml_walk, NULL, 0U );
#endif

  return OK;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L1017
static int
vote_account_set_state( fd_borrowed_account_t *     self,
                        fd_vote_state_versioned_t * state,
                        instruction_ctx_t           ctx ) {
  // TODO this deviates from Labs impl
  ulong current_sz       = vote_state_versions_vote_state_size_of( 1 );
  ulong v14_sz           = vote_state_versions_vote_state_size_of( 0 );
  bool  add_vote_latency = FD_FEATURE_ACTIVE( ctx.global, vote_state_add_vote_latency );

  ulong serialized_sz          = add_vote_latency ? fd_vote_state_versioned_size( state )
                                                  : fd_vote_transcoding_state_versioned_size( state );
  ulong original_serialized_sz = serialized_sz;

  if ( add_vote_latency ) {
    if ( serialized_sz < current_sz ) serialized_sz = current_sz;
  } else {
    if ( serialized_sz < v14_sz ) serialized_sz = v14_sz;
  }

  int                 err          = 0;

  ulong re  = fd_rent_exempt( ctx.global, serialized_sz );
  bool  cbr = fd_account_can_data_be_resized( &ctx, self->const_meta, serialized_sz, &err );
  if ( ( ( self->const_meta->dlen < serialized_sz && self->const_meta->info.lamports < re ) ) || !cbr ) {
    serialized_sz = original_serialized_sz;
    if ( serialized_sz < v14_sz ) { serialized_sz = v14_sz; }
    add_vote_latency = 0;
  }

  int rc = fd_acc_mgr_modify( ctx.global->acc_mgr,
                          ctx.global->funk_txn,
                          self->pubkey,
                          0,
                          serialized_sz,
                          self);
  if ( FD_UNLIKELY( rc != OK ) ) return rc;

  fd_account_meta_t * m            = self->meta;
  char *              raw_acc_data = (char *)self->data;

  if ( m->dlen < serialized_sz ) {
    fd_memset( raw_acc_data + m->dlen, 0, serialized_sz - m->dlen );
    m->dlen = serialized_sz;
  }

  /* Encode account data */
  fd_bincode_encode_ctx_t encode = { .data    = raw_acc_data,
                                     .dataend = (char *)( raw_acc_data ) + serialized_sz };
  if ( add_vote_latency ) {
    if ( FD_UNLIKELY( 0 != fd_vote_state_versioned_encode( state, &encode ) ) )
      FD_LOG_ERR( ( "fd_vote_state_versioned_encode failed" ) );
  } else {
    if ( FD_UNLIKELY( 0 != fd_vote_transcoding_state_versioned_encode( state, &encode ) ) )
      FD_LOG_ERR( ( "fd_vote_state_versioned_encode failed" ) );
  }

#if 0
  {
    fd_vote_state_versioned_t p;
    fd_vote_state_versioned_new( &p );

    fd_bincode_decode_ctx_t decode = {
      .data    = raw_acc_data,
      .dataend = encode.dataend,
      .valloc  = ctx.global->valloc
    };

    fd_flamenco_yaml_t * yaml =
      fd_flamenco_yaml_init( fd_flamenco_yaml_new(
          fd_valloc_malloc(ctx.global->valloc, fd_flamenco_yaml_align(), fd_flamenco_yaml_footprint() ) ),
        stdout );

    fd_vote_state_versioned_decode(&p, &decode);
    fd_vote_state_versioned_walk(yaml, &p, fd_flamenco_yaml_walk, NULL, 0U );
  }
#endif

  return 0;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L1031
static bool
vote_account_is_rent_exempt_at_data_length( fd_borrowed_account_t * self,
                                            ulong                   data_length,
                                            instruction_ctx_t       ctx ) {
  return fd_rent_exempt_minimum_balance( ctx.global, data_length ) <= self->const_meta->info.lamports;
}

/**********************************************************************/
/* impl AuthorizedVoters                                              */
/**********************************************************************/

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L13-L17
static void
authorized_voters_new( ulong                                      epoch,
                       fd_pubkey_t *                              pubkey,
                       instruction_ctx_t                          ctx,
                       /* return */ fd_vote_authorized_voters_t * authorized_voters ) {
  authorized_voters->pool  = fd_vote_authorized_voters_pool_alloc( ctx.global->valloc );
  authorized_voters->treap = fd_vote_authorized_voters_treap_alloc( ctx.global->valloc );
  fd_vote_authorized_voter_t * ele =
      fd_vote_authorized_voters_pool_ele_acquire( authorized_voters->pool );
  ele->epoch = epoch;
  memcpy( &ele->pubkey, pubkey, sizeof( fd_pubkey_t ) );
  ele->prio = (ulong)&ele->pubkey;
  fd_vote_authorized_voters_treap_ele_insert(
      authorized_voters->treap, ele, authorized_voters->pool );
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L24
static fd_vote_authorized_voter_t *
authorized_voters_get_and_cache_authorized_voter_for_epoch( fd_vote_authorized_voters_t * self,
                                                            ulong                         epoch ) {
  int                          existed = 0;
  fd_vote_authorized_voter_t * res =
      authorized_voters_get_or_calculate_authorized_voter_for_epoch( self, epoch, &existed );
  if ( !res ) return NULL;
  if ( !existed ) {
    /* insert cannot fail because !existed */
    fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_pool_ele_acquire( self->pool );
    ele->epoch                       = epoch;
    memcpy( &ele->pubkey, &res->pubkey, sizeof( fd_pubkey_t ) );
    ele->prio = (ulong)&res->pubkey;
    fd_vote_authorized_voters_treap_ele_insert( self->treap, ele, self->pool );
  }
  return res;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L39
static void
authorized_voters_purge_authorized_voters( fd_vote_authorized_voters_t * self,
                                           ulong                         current_epoch,
                                           instruction_ctx_t             ctx ) {
  fd_bincode_destroy_ctx_t ctx3 = { .valloc = ctx.global->valloc };

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L42-L46
  ulong expired_keys[FD_VOTE_AUTHORIZED_VOTERS_MAX] = { 0 }; /* TODO use fd_set */
  ulong key_cnt                                     = 0;
  for ( fd_vote_authorized_voters_treap_fwd_iter_t iter =
            fd_vote_authorized_voters_treap_fwd_iter_init( self->treap, self->pool );
        !fd_vote_authorized_voters_treap_fwd_iter_done( iter );
        iter = fd_vote_authorized_voters_treap_fwd_iter_next( iter, self->pool ) ) {
    fd_vote_authorized_voter_t * ele =
        fd_vote_authorized_voters_treap_fwd_iter_ele( iter, self->pool );
    if ( ele->epoch < current_epoch ) expired_keys[key_cnt++] = ele->epoch;
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L48-L50
  for ( ulong i = 0; i < key_cnt; i++ ) {
    fd_vote_authorized_voter_t * ele =
        fd_vote_authorized_voters_treap_ele_query( self->treap, expired_keys[i], self->pool );
    fd_vote_authorized_voters_treap_ele_remove( self->treap, ele, self->pool );
    fd_vote_authorized_voters_pool_ele_release( self->pool, ele );
    fd_vote_authorized_voter_destroy( &self->pool[i], &ctx3 );
  }

  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L56
  FD_TEST( !authorized_voters_is_empty( self ) );
}

static inline bool
authorized_voters_is_empty( fd_vote_authorized_voters_t * self ) {
  return fd_vote_authorized_voters_treap_ele_cnt( self->treap ) == 0;
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L68-L70
static inline fd_vote_authorized_voter_t *
authorized_voters_last( fd_vote_authorized_voters_t * self ) {
  fd_vote_authorized_voters_treap_rev_iter_t iter =
      fd_vote_authorized_voters_treap_rev_iter_init( self->treap, self->pool );
  return fd_vote_authorized_voters_treap_rev_iter_ele( iter, self->pool );
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L76-L78
static inline bool
authorized_voters_contains( fd_vote_authorized_voters_t * self, ulong epoch ) {
  return !!fd_vote_authorized_voters_treap_ele_query( self->treap, epoch, self->pool );
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/authorized_voters.rs#L87-L108
static fd_vote_authorized_voter_t *
authorized_voters_get_or_calculate_authorized_voter_for_epoch( fd_vote_authorized_voters_t * self,
                                                               ulong                         epoch,
                                                               int * existed ) {
  *existed                                  = 0;
  ulong                        latest_epoch = 0;
  fd_vote_authorized_voter_t * res =
      fd_vote_authorized_voters_treap_ele_query( self->treap, epoch, self->pool );
  /* "predecessor" would be more big-O optimal here, but mirroring labs logic
   * https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/self.rs#L89-L104
   */
  if ( FD_UNLIKELY( !res ) ) {
    for ( fd_vote_authorized_voters_treap_fwd_iter_t iter =
              fd_vote_authorized_voters_treap_fwd_iter_init( self->treap, self->pool );
          !fd_vote_authorized_voters_treap_fwd_iter_done( iter );
          iter = fd_vote_authorized_voters_treap_fwd_iter_next( iter, self->pool ) ) {
      fd_vote_authorized_voter_t * ele =
          fd_vote_authorized_voters_treap_fwd_iter_ele( iter, self->pool );
      if ( ele->epoch < epoch && ( latest_epoch == 0 || ele->epoch > latest_epoch ) ) {
        latest_epoch = ele->epoch;
        res          = ele;
      }
    }
    *existed = 0;
    return res;
  } else {
    *existed = 1;
    return res;
  }
  return res;
}

static int
decode_compact_update( instruction_ctx_t                ctx,
                       fd_compact_vote_state_update_t * compact_update,
                       fd_vote_state_update_t *         vote_update ) {
  // Taken from:
  // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L712
  vote_update->root = compact_update->root != ULONG_MAX ? &compact_update->root : NULL;
  if ( vote_update->lockouts ) FD_LOG_WARNING( ( "MEM LEAK: %p", (void *)vote_update->lockouts ) );

  vote_update->lockouts = deq_fd_vote_lockout_t_alloc( ctx.global->valloc );
  ulong lockouts_len    = compact_update->lockouts_len;
  ulong slot            = vote_update->root ? *vote_update->root : 0;

  vote_update->lockouts = deq_fd_vote_lockout_t_alloc( ctx.global->valloc );
  if ( lockouts_len > deq_fd_vote_lockout_t_max( vote_update->lockouts ) )
    return FD_BINCODE_ERR_SMALL_DEQUE;
  for ( ulong i = 0; i < lockouts_len; ++i ) {
    fd_vote_lockout_t * elem = deq_fd_vote_lockout_t_push_tail_nocopy( vote_update->lockouts );
    fd_vote_lockout_new( elem );

    fd_lockout_offset_t * lock_offset = &compact_update->lockouts[i];
    slot += lock_offset->offset;
    elem->slot               = slot;
    elem->confirmation_count = (uint)lock_offset->confirmation_count;
  }

  vote_update->hash      = compact_update->hash;
  vote_update->timestamp = compact_update->timestamp;

  return 0;
}

void
fd_vote_record_timestamp_vote( fd_global_ctx_t *   global,
                               fd_pubkey_t const * vote_acc,
                               ulong               timestamp ) {
  fd_vote_record_timestamp_vote_with_slot( global, vote_acc, timestamp, global->bank.slot );
}

void
fd_vote_record_timestamp_vote_with_slot( fd_global_ctx_t *   global,
                                         fd_pubkey_t const * vote_acc,
                                         ulong               timestamp,
                                         ulong               slot ) {
  fd_clock_timestamp_vote_t_mapnode_t * root = global->bank.timestamp_votes.votes_root;
  fd_clock_timestamp_vote_t_mapnode_t * pool = global->bank.timestamp_votes.votes_pool;
  if ( NULL == pool )
    pool = global->bank.timestamp_votes.votes_pool =
        fd_clock_timestamp_vote_t_map_alloc( global->valloc, 10000 );

  fd_clock_timestamp_vote_t timestamp_vote = {
      .pubkey    = *vote_acc,
      .timestamp = (long)timestamp,
      .slot      = slot,
  };
  fd_clock_timestamp_vote_t_mapnode_t   key = { .elem = timestamp_vote };
  fd_clock_timestamp_vote_t_mapnode_t * node =
      fd_clock_timestamp_vote_t_map_find( pool, root, &key );
  if ( NULL != node ) {
    node->elem = timestamp_vote;
  } else {
    node = fd_clock_timestamp_vote_t_map_acquire( pool );
    FD_TEST( node != NULL );
    node->elem = timestamp_vote;
    fd_clock_timestamp_vote_t_map_insert( pool, &root, node );
    global->bank.timestamp_votes.votes_root = root;
  }
}

// https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/program/src/vote/state/mod.rs#L512
int
fd_vote_acc_credits( instruction_ctx_t         ctx,
                     fd_account_meta_t const * vote_acc_meta,
                     uchar const *             vote_acc_data,
                     ulong *                   result ) {
  int rc;

  fd_sol_sysvar_clock_t clock;
  fd_sysvar_clock_read( ctx.global, &clock );

  /* Read vote account */
  fd_borrowed_account_t vote_account = {
      // FIXME call sites
      .const_meta = vote_acc_meta,
      .const_data = vote_acc_data,
  };

  rc = OK;
  fd_vote_state_versioned_t vote_state_versioned;
  rc = vote_account_get_state( &vote_account, ctx, &vote_state_versioned );
  if ( FD_UNLIKELY( rc != OK ) ) return rc;
  vote_state_versions_convert_to_current( &vote_state_versioned, ctx );
  fd_vote_state_t * state = &vote_state_versioned.inner.current;
  if ( deq_fd_vote_epoch_credits_t_empty( state->epoch_credits ) ) {
    *result = 0;
  } else {
    *result = deq_fd_vote_epoch_credits_t_peek_tail_const( state->epoch_credits )->credits;
  }

  fd_bincode_destroy_ctx_t ctx5 = { .valloc = ctx.global->valloc };
  fd_vote_state_versioned_destroy( &vote_state_versioned, &ctx5 );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/// returns commission split as (voter_portion, staker_portion, was_split) tuple
///
///  if commission calculation is 100% one way or other, indicate with false for was_split
void
fd_vote_commission_split( fd_vote_state_versioned_t * vote_state_versioned,
                          ulong                       on,
                          fd_commission_split_t *     result ) {
  uchar * commission = NULL;
  switch ( vote_state_versioned->discriminant ) {
  case fd_vote_state_versioned_enum_current:
    commission = &vote_state_versioned->inner.current.commission;
    break;
  case fd_vote_state_versioned_enum_v0_23_5:
    commission = &vote_state_versioned->inner.v0_23_5.commission;
    break;
  case fd_vote_state_versioned_enum_v1_14_11:
    commission = &vote_state_versioned->inner.v1_14_11.commission;
    break;
  default:
    __builtin_unreachable();
  }
  uint commission_split = fd_uint_min( *( (uint *)commission ), 100 );
  result->is_split      = ( commission_split != 0 && commission_split != 100 );
  if ( commission_split == 0 ) {
    result->voter_portion  = 0;
    result->staker_portion = on;
    return;
  }
  if ( commission_split == 100 ) {
    result->voter_portion  = on;
    result->staker_portion = 0;
    return;
  }
  /* Note: order of operations may matter for int division. That's why I didn't make the
   * optimization of getting out the common calculations */
  result->voter_portion =
      (ulong)( (__uint128_t)on * (__uint128_t)commission_split / (__uint128_t)100 );
  result->staker_portion =
      (ulong)( (__uint128_t)on * (__uint128_t)( 100 - commission_split ) / (__uint128_t)100 );
  return;
}
