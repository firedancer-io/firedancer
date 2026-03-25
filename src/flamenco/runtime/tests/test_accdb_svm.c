#include "fd_svm_mini.h"
#include "../../accdb/fd_accdb_sync.h"
#include "../fd_accdb_svm.h"
#include "../fd_bank.h"
#include "../../../ballet/lthash/fd_lthash.h"

static const fd_pubkey_t acct_a = {{ 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                                     17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 }};
static const fd_pubkey_t acct_b = {{ 99,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                                     17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 }};
static const fd_pubkey_t acct_c = {{ 42,42,42,4,5,6,7,8,9,10,11,12,13,14,15,16,
                                     17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 }};
static const fd_pubkey_t owner1 = {{ 0xAA,0xBB,0xCC,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
static const fd_pubkey_t owner2 = {{ 0xDD,0xEE,0xFF,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};

/* Helper: read lamports for a given account */
static ulong
read_lamports( fd_svm_mini_t *     mini,
               fd_xid_t const *    xid,
               fd_pubkey_t const * pubkey ) {
  fd_accdb_ro_t ro[1];
  if( !fd_accdb_open_ro( mini->accdb, ro, xid, pubkey ) ) return 0UL;
  ulong lamports = fd_accdb_ref_lamports( ro );
  fd_accdb_close_ro( mini->accdb, ro );
  return lamports;
}

/* Helper: check account does not exist */
static int
account_missing( fd_svm_mini_t *     mini,
                 fd_xid_t const *    xid,
                 fd_pubkey_t const * pubkey ) {
  fd_accdb_ro_t ro[1];
  if( !fd_accdb_open_ro( mini->accdb, ro, xid, pubkey ) ) return 1;
  fd_accdb_close_ro( mini->accdb, ro );
  return 0;
}

static void
test_credit( fd_svm_mini_t * mini,
             ulong           bank_idx ) {
  fd_bank_t * bank = fd_svm_mini_bank( mini, bank_idx );
  fd_xid_t    xid  = fd_svm_mini_xid ( mini, bank_idx );

  ulong cap_before = bank->f.capitalization;
  fd_lthash_value_t lthash = bank->f.lthash;

  /* Credit a new account (should create it) */
  fd_accdb_svm_credit( mini->accdb, bank, &xid, NULL, &acct_a, 1000UL );
  FD_TEST( read_lamports( mini, &xid, &acct_a )==1000UL );
  FD_TEST( bank->f.capitalization==cap_before+1000UL );
  FD_TEST( !fd_lthash_eq( &lthash, &bank->f.lthash ) );
  lthash = bank->f.lthash;

  /* Credit the same account again */
  fd_accdb_svm_credit( mini->accdb, bank, &xid, NULL, &acct_a, 500UL );
  FD_TEST( read_lamports( mini, &xid, &acct_a )==1500UL );
  FD_TEST( bank->f.capitalization==cap_before+1500UL );
  FD_TEST( !fd_lthash_eq( &lthash, &bank->f.lthash ) );
  lthash = bank->f.lthash;

  /* Credit with zero lamports is a no-op */
  fd_accdb_svm_credit( mini->accdb, bank, &xid, NULL, &acct_a, 0UL );
  FD_TEST( read_lamports( mini, &xid, &acct_a )==1500UL );
  FD_TEST( bank->f.capitalization==cap_before+1500UL );
  FD_TEST( fd_lthash_eq( &lthash, &bank->f.lthash ) );

  FD_LOG_NOTICE(( "test_credit passed" ));
}

static void
test_write_create( fd_svm_mini_t * mini,
                   ulong           bank_idx ) {
  fd_bank_t * bank = fd_svm_mini_bank( mini, bank_idx );
  fd_xid_t    xid  = fd_svm_mini_xid ( mini, bank_idx );

  ulong cap_before = bank->f.capitalization;
  fd_lthash_value_t lthash = bank->f.lthash;

  /* Write to a non-existent account without CREATE flag => no-op */
  uchar data1[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
  fd_accdb_svm_write( mini->accdb, bank, &xid, NULL,
                      &acct_b, &owner1, data1, sizeof(data1),
                      100UL, 0, 0 /* no flags */ );
  FD_TEST( account_missing( mini, &xid, &acct_b ) );
  FD_TEST( bank->f.capitalization==cap_before );
  FD_TEST( fd_lthash_eq( &lthash, &bank->f.lthash ) );

  /* Write with CREATE flag => creates the account */
  fd_accdb_svm_write( mini->accdb, bank, &xid, NULL,
                      &acct_b, &owner1, data1, sizeof(data1),
                      100UL, 1, FD_ACCDB_FLAG_CREATE );
  FD_TEST( read_lamports( mini, &xid, &acct_b )==100UL );
  FD_TEST( bank->f.capitalization==cap_before+100UL );
  FD_TEST( !fd_lthash_eq( &lthash, &bank->f.lthash ) );
  lthash = bank->f.lthash;

  /* Verify owner, data, and exec_bit */
  fd_accdb_ro_t ro[1];
  FD_TEST( fd_accdb_open_ro( mini->accdb, ro, &xid, &acct_b ) );
  FD_TEST( fd_accdb_ref_exec_bit( ro )==1 );
  FD_TEST( !memcmp( fd_accdb_ref_owner( ro ), &owner1, 32UL ) );
  FD_TEST( fd_accdb_ref_data_sz( ro )>=sizeof(data1) );
  FD_TEST( !memcmp( fd_accdb_ref_data_const( ro ), data1, sizeof(data1) ) );
  fd_accdb_close_ro( mini->accdb, ro );

  FD_LOG_NOTICE(( "test_write_create passed" ));
}

static void
test_write_overwrite( fd_svm_mini_t * mini,
                      ulong           bank_idx ) {
  fd_bank_t * bank = fd_svm_mini_bank( mini, bank_idx );
  fd_xid_t    xid  = fd_svm_mini_xid ( mini, bank_idx );

  /* Seed acct_c with credit */
  fd_accdb_svm_credit( mini->accdb, bank, &xid, NULL, &acct_c, 500UL );

  ulong cap_before = bank->f.capitalization;
  fd_lthash_value_t lthash = bank->f.lthash;

  /* Overwrite with new owner, data, and exec_bit=0.  lamports_min=0
     means no minting since account already has 500 lamports. */
  uchar data2[8] = { 1,2,3,4,5,6,7,8 };
  fd_accdb_svm_write( mini->accdb, bank, &xid, NULL,
                      &acct_c, &owner2, data2, sizeof(data2),
                      0UL, 0, FD_ACCDB_FLAG_TRUNCATE );
  FD_TEST( read_lamports( mini, &xid, &acct_c )==500UL );
  FD_TEST( bank->f.capitalization==cap_before );
  FD_TEST( !fd_lthash_eq( &lthash, &bank->f.lthash ) );
  lthash = bank->f.lthash;

  /* Verify owner changed */
  fd_accdb_ro_t ro[1];
  FD_TEST( fd_accdb_open_ro( mini->accdb, ro, &xid, &acct_c ) );
  FD_TEST( !memcmp( fd_accdb_ref_owner( ro ), &owner2, 32UL ) );
  FD_TEST( fd_accdb_ref_exec_bit( ro )==0 );
  FD_TEST( fd_accdb_ref_data_sz( ro )==sizeof(data2) );
  FD_TEST( !memcmp( fd_accdb_ref_data_const( ro ), data2, sizeof(data2) ) );
  fd_accdb_close_ro( mini->accdb, ro );

  /* Overwrite again with lamports_min > current => should mint */
  uchar data3[2] = { 0xFF, 0x00 };
  fd_accdb_svm_write( mini->accdb, bank, &xid, NULL,
                      &acct_c, &owner1, data3, sizeof(data3),
                      1000UL, 0, FD_ACCDB_FLAG_TRUNCATE );
  FD_TEST( read_lamports( mini, &xid, &acct_c )==1000UL );
  FD_TEST( bank->f.capitalization==cap_before+500UL );
  FD_TEST( !fd_lthash_eq( &lthash, &bank->f.lthash ) );

  FD_LOG_NOTICE(( "test_write_overwrite passed" ));
}

static void
test_remove( fd_svm_mini_t * mini,
             ulong           bank_idx ) {
  fd_bank_t * bank = fd_svm_mini_bank( mini, bank_idx );
  fd_xid_t    xid  = fd_svm_mini_xid ( mini, bank_idx );

  /* Seed an account */
  fd_accdb_svm_credit( mini->accdb, bank, &xid, NULL, &acct_a, 2000UL );
  ulong cap_before = bank->f.capitalization;

  /* Remove the account => returns burned lamports */
  ulong burned = fd_accdb_svm_remove( mini->accdb, bank, &xid, NULL, &acct_a );
  FD_TEST( burned==2000UL );
  FD_TEST( bank->f.capitalization==cap_before-2000UL );

  /* Account should either be gone or have zero lamports */
  FD_TEST( read_lamports( mini, &xid, &acct_a )==0UL );

  /* Remove non-existent account => returns 0 */
  fd_pubkey_t ghost = {{ 0xFF,0xFF,0xFF,0xFF,0,0,0,0,0,0,0,0,0,0,0,0,
                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  ulong burned2 = fd_accdb_svm_remove( mini->accdb, bank, &xid, NULL, &ghost );
  FD_TEST( burned2==0UL );

  FD_LOG_NOTICE(( "test_remove passed" ));
}

static void
test_open_close_rw( fd_svm_mini_t * mini,
                    ulong           bank_idx ) {
  fd_bank_t * bank = fd_svm_mini_bank( mini, bank_idx );
  fd_xid_t    xid  = fd_svm_mini_xid ( mini, bank_idx );

  /* Seed an account */
  fd_accdb_svm_credit( mini->accdb, bank, &xid, NULL, &acct_a, 3000UL );
  ulong cap_before = bank->f.capitalization;

  /* Open for rw, modify lamports, close */
  fd_accdb_rw_t         rw[1];
  fd_accdb_svm_update_t update[1];
  FD_TEST( fd_accdb_svm_open_rw( mini->accdb, bank, &xid, rw, update, &acct_a, 0UL, 0 ) );
  FD_TEST( fd_accdb_ref_lamports( rw->ro )==3000UL );
  FD_TEST( update->lamports_before==3000UL );

  /* Increase lamports */
  fd_accdb_ref_lamports_set( rw, 5000UL );
  fd_accdb_svm_close_rw( mini->accdb, bank, NULL, rw, update );

  /* Capitalization should increase by 2000 */
  FD_TEST( bank->f.capitalization==cap_before+2000UL );
  FD_TEST( read_lamports( mini, &xid, &acct_a )==5000UL );

  /* Open for rw, decrease lamports, close */
  cap_before = bank->f.capitalization;
  FD_TEST( fd_accdb_svm_open_rw( mini->accdb, bank, &xid, rw, update, &acct_a, 0UL, 0 ) );
  fd_accdb_ref_lamports_set( rw, 1000UL );
  fd_accdb_svm_close_rw( mini->accdb, bank, NULL, rw, update );
  FD_TEST( bank->f.capitalization==cap_before-4000UL );
  FD_TEST( read_lamports( mini, &xid, &acct_a )==1000UL );

  /* Open rw on non-existent account without CREATE => NULL */
  fd_pubkey_t ghost = {{ 0xFE,0xFE,0xFE,0,0,0,0,0,0,0,0,0,0,0,0,0,
                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  FD_TEST( !fd_accdb_svm_open_rw( mini->accdb, bank, &xid, rw, update, &ghost, 0UL, 0 ) );

  /* Open rw on non-existent account with CREATE => succeeds */
  FD_TEST( fd_accdb_svm_open_rw( mini->accdb, bank, &xid, rw, update, &ghost, 16UL, FD_ACCDB_FLAG_CREATE ) );
  FD_TEST( update->lamports_before==0UL );
  fd_accdb_ref_lamports_set( rw, 100UL );
  cap_before = bank->f.capitalization;
  fd_accdb_svm_close_rw( mini->accdb, bank, NULL, rw, update );
  FD_TEST( bank->f.capitalization==cap_before+100UL );
  FD_TEST( read_lamports( mini, &xid, &ghost )==100UL );

  FD_LOG_NOTICE(( "test_open_close_rw passed" ));
}

static void
test_fork_isolation( fd_svm_mini_t * mini,
                     ulong           root_idx ) {
  /* Seed account via a child fork, then root it */
  ulong seed_idx = fd_svm_mini_attach_child( mini, root_idx, 11UL );
  fd_bank_t * seed_bank = fd_svm_mini_bank( mini, seed_idx );
  fd_xid_t    seed_xid  = fd_svm_mini_xid ( mini, seed_idx );
  fd_accdb_svm_credit( mini->accdb, seed_bank, &seed_xid, NULL, &acct_a, 1000UL );

  /* Freeze and advance root so account is rooted */
  fd_banks_mark_bank_frozen( seed_bank );
  fd_svm_mini_advance_root( mini, seed_idx );

  /* Create two child forks from the new root */
  ulong fork_a = fd_svm_mini_attach_child( mini, seed_idx, 12UL );
  ulong fork_b = fd_svm_mini_attach_child( mini, seed_idx, 13UL );
  fd_bank_t * bank_a = fd_svm_mini_bank( mini, fork_a );
  fd_bank_t * bank_b = fd_svm_mini_bank( mini, fork_b );
  fd_xid_t    xid_a  = fd_svm_mini_xid ( mini, fork_a );
  fd_xid_t    xid_b  = fd_svm_mini_xid ( mini, fork_b );

  /* Credit on fork A */
  fd_accdb_svm_credit( mini->accdb, bank_a, &xid_a, NULL, &acct_a, 500UL );
  FD_TEST( read_lamports( mini, &xid_a, &acct_a )==1500UL );

  /* Fork B should still see original balance */
  FD_TEST( read_lamports( mini, &xid_b, &acct_a )==1000UL );

  /* Write on fork B with different owner */
  uchar data[4] = { 1,2,3,4 };
  fd_accdb_svm_write( mini->accdb, bank_b, &xid_b, NULL,
                      &acct_a, &owner2, data, sizeof(data),
                      0UL, 0, FD_ACCDB_FLAG_TRUNCATE );

  /* Fork A should still have original owner (system program / zero) */
  fd_accdb_ro_t ro[1];
  FD_TEST( fd_accdb_open_ro( mini->accdb, ro, &xid_a, &acct_a ) );
  FD_TEST( memcmp( fd_accdb_ref_owner( ro ), &owner2, 32UL )!=0 );
  fd_accdb_close_ro( mini->accdb, ro );

  /* Fork B should have new owner */
  FD_TEST( fd_accdb_open_ro( mini->accdb, ro, &xid_b, &acct_a ) );
  FD_TEST( !memcmp( fd_accdb_ref_owner( ro ), &owner2, 32UL ) );
  fd_accdb_close_ro( mini->accdb, ro );

  FD_LOG_NOTICE(( "test_fork_isolation passed" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );
  FD_TEST( mini );

  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->mock_validator_cnt = 0UL;
  params->root_slot          = 10UL;
  params->slots_per_epoch    = 100UL;

  ulong root_idx;
  ulong child_idx;

  /* Each test operates on a non-rooted child fork, since accdb does
     not allow writes to the rooted XID. */

  root_idx  = fd_svm_mini_reset( mini, params );
  child_idx = fd_svm_mini_attach_child( mini, root_idx, 11UL );
  test_credit( mini, child_idx );

  root_idx  = fd_svm_mini_reset( mini, params );
  child_idx = fd_svm_mini_attach_child( mini, root_idx, 11UL );
  test_write_create( mini, child_idx );

  root_idx  = fd_svm_mini_reset( mini, params );
  child_idx = fd_svm_mini_attach_child( mini, root_idx, 11UL );
  test_write_overwrite( mini, child_idx );

  root_idx  = fd_svm_mini_reset( mini, params );
  child_idx = fd_svm_mini_attach_child( mini, root_idx, 11UL );
  test_remove( mini, child_idx );

  root_idx  = fd_svm_mini_reset( mini, params );
  child_idx = fd_svm_mini_attach_child( mini, root_idx, 11UL );
  test_open_close_rw( mini, child_idx );

  root_idx = fd_svm_mini_reset( mini, params );
  test_fork_isolation( mini, root_idx );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
