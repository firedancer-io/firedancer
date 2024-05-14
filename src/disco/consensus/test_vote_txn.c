#include <sys/random.h>
#include "../../util/fd_util.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../flamenco/fd_flamenco.h"
#include "../../flamenco/txn/fd_txn_generate.h"
#include "../../flamenco/runtime/fd_system_ids.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

#define TEST_VOTE_TXN_MAGIC (0x7e58UL)

fd_vote_lockout_t *
dummy_tower(ulong height) {
  /* Workspace */
  ulong page_cnt = 1;
  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous(
      fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /* Create deque of fd_vote_lockout_t */
  void * mem = fd_wksp_alloc_laddr(
      wksp, deq_fd_vote_lockout_t_align(), deq_fd_vote_lockout_t_footprint( height ), TEST_VOTE_TXN_MAGIC );
  fd_vote_lockout_t * tower =
      deq_fd_vote_lockout_t_join( deq_fd_vote_lockout_t_new( mem, height ) );
  FD_TEST( tower );

  /* Insert lockouts into the tower */
  for (ulong i = 0; i < height; i++) {
      fd_vote_lockout_t lockout = { .slot = i, .confirmation_count = (uint)(height - i) };
      deq_fd_vote_lockout_t_push_head( tower, lockout );
  }

  return tower;
}

ushort
vote_instr_fun( uchar * out_buf, uchar * FD_PARAM_UNUSED opt_args, ulong FD_PARAM_UNUSED opt_args_len ) {
  (void) opt_args;
  (void) opt_args_len;

  /* Create vote_update with some dummy values */
  fd_vote_state_update_t vote_update;
  memset( &vote_update, 0, sizeof(fd_vote_state_update_t) );
  vote_update.lockouts = dummy_tower(32);
  vote_update.root = 100;
  FD_TEST( 32UL == getrandom( vote_update.hash.key, 32UL, 0 ) );
  static ulong now = 1715701506716580798UL;
  vote_update.timestamp = &now;

  /* Create the vote instruction */
  fd_vote_instruction_t vote_instr;
  vote_instr.discriminant = fd_vote_instruction_enum_update_vote_state;
  vote_instr.inner.update_vote_state = vote_update;
  fd_bincode_encode_ctx_t encode = { .data = out_buf, .dataend = (out_buf + FD_TXN_MTU) };
  fd_vote_instruction_encode ( &vote_instr, &encode );
  return (ushort)fd_vote_instruction_size( &vote_instr );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  fd_flamenco_boot( &argc, &argv );

  /* Create keys if needed */
  uchar vote_identity_privkey[32], vote_authority_privkey[32];
  fd_sha512_t vote_identity_sha[1], vote_authority_sha[1];
  fd_pubkey_t vote_pubkeys[2], vote_program_pubkey; /* identity and authority  */

  FD_TEST( 32UL == getrandom( vote_identity_privkey, 32UL, 0 ) );
  FD_TEST( fd_ed25519_public_from_private( vote_pubkeys[0].uc, vote_identity_privkey, vote_identity_sha ) );
  FD_TEST( 32UL == getrandom( vote_authority_privkey, 32UL, 0 ) );
  FD_TEST( fd_ed25519_public_from_private( vote_pubkeys[1].uc, vote_authority_privkey, vote_authority_sha ) );
  memcpy( &vote_program_pubkey, &fd_solana_vote_program_id, sizeof(fd_pubkey_t) );

  /* Create transaction base */
  uchar txn_meta_buf[ FD_TXN_MAX_SZ ];
  uchar txn_buf [ FD_TXN_MTU ];
  fd_txn_accounts_t vote_txn_accounts;
  vote_txn_accounts.signature_cnt         = 2;
  vote_txn_accounts.readonly_signed_cnt   = 0;
  vote_txn_accounts.readonly_unsigned_cnt = 1;
  vote_txn_accounts.acct_cnt              = 3;
  vote_txn_accounts.signers_w             = vote_pubkeys;         /* 2 pubkeys: vote identity, vote authority */
  vote_txn_accounts.signers_r             = NULL;                 /* 0 pubkey */
  vote_txn_accounts.non_signers_w         = NULL;                 /* 0 pubkey  */
  vote_txn_accounts.non_signers_r         = &vote_program_pubkey; /* 1 pubkey: vote program */
  fd_txn_base_generate( txn_meta_buf, txn_buf, 2, &vote_txn_accounts, NULL );

  /* Add fd_vote_instruction to the vote transaction */
  uchar instr_accounts[2];
  instr_accounts[0] = 1;
  instr_accounts[1] = 0;  /* this is 1 on local, but 0 on testnet; not sure why */
  ulong size = fd_txn_add_instr(txn_meta_buf, txn_buf, 2, instr_accounts, 2, vote_instr_fun, NULL, 0);
  FD_LOG_NOTICE(("Create a vote transaction: txn raw_size=%u.", size));

  /* Parse the transaction back to fd_txn_t */
  uchar out_buf[ FD_TXN_MAX_SZ ];
  fd_txn_t * parsed_txn = (fd_txn_t *)out_buf;
  ulong out_sz = fd_txn_parse( txn_buf, size, out_buf, NULL );
  FD_TEST( out_sz );
  FD_TEST( parsed_txn );
  FD_TEST( parsed_txn->instr_cnt == 1);

  uchar program_id = parsed_txn->instr[0].program_id;
  uchar* account_addr = (txn_buf + parsed_txn->acct_addr_off
                        + FD_TXN_ACCT_ADDR_SZ * program_id );

  FD_LOG_NOTICE( ("Parse the vote txn: voter_addr=%32J, txn_acct_cnt=%u(readonly_sign=%u, readonly_unsign=%u), sign_cnt=%u | instruction#0: program=%32J",
                  txn_buf + parsed_txn->acct_addr_off,
                  parsed_txn->acct_addr_cnt,
                  parsed_txn->readonly_signed_cnt,
                  parsed_txn->readonly_unsigned_cnt,
                  parsed_txn->signature_cnt,
                  account_addr) );
}
