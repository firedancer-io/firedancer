#include "fd_svm_mini.h"
#include "../fd_accdb_svm.h"
#include "../fd_bank.h"
#include "../fd_hashes.h"
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
static const fd_pubkey_t acct_d = {{ 77,77,77,77,5,6,7,8,9,10,11,12,13,14,15,16,
                                     17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 }};
static const fd_pubkey_t acct_missing = {{ 0xFD,0xFD,0xFD,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                           0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};

static void
test_credit( fd_svm_mini_t * mini,
             ulong           bank_idx ) {
  fd_bank_t *        bank    = fd_svm_mini_bank( mini, bank_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, bank_idx );
  fd_accdb_t *       accdb   = mini->runtime->accdb;

  ulong cap_before = bank->f.capitalization;
  fd_lthash_value_t lthash = bank->f.lthash;

  /* Credit a new account (should create it) */
  fd_accdb_svm_credit( bank, accdb, NULL, &acct_a, 1000UL, 0 );
  FD_TEST( fd_accdb_lamports( accdb, fork_id, acct_a.uc )==1000UL );
  FD_TEST( bank->f.capitalization==cap_before+1000UL );
  FD_TEST( !fd_lthash_eq( &lthash, &bank->f.lthash ) );
  lthash = bank->f.lthash;

  /* Credit the same account again */
  fd_accdb_svm_credit( bank, accdb, NULL, &acct_a, 500UL, 0 );
  FD_TEST( fd_accdb_lamports( accdb, fork_id, acct_a.uc )==1500UL );
  FD_TEST( bank->f.capitalization==cap_before+1500UL );
  FD_TEST( !fd_lthash_eq( &lthash, &bank->f.lthash ) );
  lthash = bank->f.lthash;

  /* Credit with zero lamports is a no-op */
  fd_accdb_svm_credit( bank, accdb, NULL, &acct_a, 0UL, 0 );
  FD_TEST( fd_accdb_lamports( accdb, fork_id, acct_a.uc )==1500UL );
  FD_TEST( bank->f.capitalization==cap_before+1500UL );
  FD_TEST( fd_lthash_eq( &lthash, &bank->f.lthash ) );

  FD_LOG_NOTICE(( "test_credit passed" ));
}

static void
test_write_create( fd_svm_mini_t * mini,
                   ulong           bank_idx ) {
  fd_bank_t *        bank    = fd_svm_mini_bank( mini, bank_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, bank_idx );
  fd_accdb_t *       accdb   = mini->runtime->accdb;

  ulong cap_before = bank->f.capitalization;
  fd_lthash_value_t lthash = bank->f.lthash;

  /* Write to a non-existent account — should create since svm_write always creates */
  uchar data1[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
  fd_accdb_svm_write( bank, accdb, NULL,
                      &acct_b, &owner1, data1, sizeof(data1),
                      100UL, 1, 0 );
  FD_TEST( fd_accdb_lamports( accdb, fork_id, acct_b.uc )==100UL );
  FD_TEST( bank->f.capitalization==cap_before+100UL );
  FD_TEST( !fd_lthash_eq( &lthash, &bank->f.lthash ) );
  lthash = bank->f.lthash;

  /* Verify owner, data, and exec_bit */
  fd_acc_t acc = fd_accdb_read_one( accdb, fork_id, acct_b.uc );
  FD_TEST( acc.executable==1 );
  FD_TEST( !memcmp( acc.owner, owner1.key, 32UL ) );
  FD_TEST( acc.data_len>=sizeof(data1) );
  FD_TEST( !memcmp( acc.data, data1, sizeof(data1) ) );
  fd_accdb_unread_one( accdb, &acc );

  FD_LOG_NOTICE(( "test_write_create passed" ));
}

static void
test_write_overwrite( fd_svm_mini_t * mini,
                      ulong           bank_idx ) {
  fd_bank_t *        bank    = fd_svm_mini_bank( mini, bank_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, bank_idx );
  fd_accdb_t *       accdb   = mini->runtime->accdb;

  /* Seed acct_c with credit */
  fd_accdb_svm_credit( bank, accdb, NULL, &acct_c, 500UL, 0 );

  ulong cap_before = bank->f.capitalization;
  fd_lthash_value_t lthash = bank->f.lthash;

  /* Overwrite with new owner, data, and exec_bit=0.  lamports_min=0
     means no minting since account already has 500 lamports. */
  uchar data2[8] = { 1,2,3,4,5,6,7,8 };
  fd_accdb_svm_write( bank, accdb, NULL,
                      &acct_c, &owner2, data2, sizeof(data2),
                      0UL, 0, 0 );
  FD_TEST( fd_accdb_lamports( accdb, fork_id, acct_c.uc )==500UL );
  FD_TEST( bank->f.capitalization==cap_before );
  FD_TEST( !fd_lthash_eq( &lthash, &bank->f.lthash ) );
  lthash = bank->f.lthash;

  /* Verify owner changed */
  fd_acc_t acc = fd_accdb_read_one( accdb, fork_id, acct_c.uc );
  FD_TEST( !memcmp( acc.owner, owner2.key, 32UL ) );
  FD_TEST( acc.executable==0 );
  FD_TEST( acc.data_len==sizeof(data2) );
  FD_TEST( !memcmp( acc.data, data2, sizeof(data2) ) );
  fd_accdb_unread_one( accdb, &acc );

  /* Overwrite again with lamports_min > current => should mint */
  uchar data3[2] = { 0xFF, 0x00 };
  fd_accdb_svm_write( bank, accdb, NULL,
                      &acct_c, &owner1, data3, sizeof(data3),
                      1000UL, 0, 0 );
  FD_TEST( fd_accdb_lamports( accdb, fork_id, acct_c.uc )==1000UL );
  FD_TEST( bank->f.capitalization==cap_before+500UL );
  FD_TEST( !fd_lthash_eq( &lthash, &bank->f.lthash ) );

  acc = fd_accdb_read_one( accdb, fork_id, acct_c.uc );
  FD_TEST( acc.data_len==sizeof(data3) );
  FD_TEST( !memcmp( acc.data, data3, sizeof(data3) ) );
  fd_accdb_unread_one( accdb, &acc );

  FD_LOG_NOTICE(( "test_write_overwrite passed" ));
}

static void
test_remove( fd_svm_mini_t * mini,
             ulong           bank_idx ) {
  fd_bank_t *        bank    = fd_svm_mini_bank( mini, bank_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, bank_idx );
  fd_accdb_t *       accdb   = mini->runtime->accdb;

  /* Seed an account */
  fd_accdb_svm_credit( bank, accdb, NULL, &acct_a, 2000UL, 0 );
  ulong cap_before = bank->f.capitalization;

  /* Remove the account => returns burned lamports */
  ulong burned = fd_accdb_svm_remove( bank, accdb, NULL, &acct_a );
  FD_TEST( burned==2000UL );
  FD_TEST( bank->f.capitalization==cap_before-2000UL );

  /* Account should either be gone or have zero lamports */
  FD_TEST( fd_accdb_lamports( accdb, fork_id, acct_a.uc )==0UL );

  /* Remove non-existent account => returns 0 */
  fd_pubkey_t ghost = {{ 0xFF,0xFF,0xFF,0xFF,0,0,0,0,0,0,0,0,0,0,0,0,
                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  ulong burned2 = fd_accdb_svm_remove( bank, accdb, NULL, &ghost );
  FD_TEST( burned2==0UL );

  FD_LOG_NOTICE(( "test_remove passed" ));
}

static void
test_open_close_rw( fd_svm_mini_t * mini,
                    ulong           bank_idx ) {
  fd_bank_t *        bank    = fd_svm_mini_bank( mini, bank_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, bank_idx );
  fd_accdb_t *       accdb   = mini->runtime->accdb;

  /* Seed an account */
  fd_accdb_svm_credit( bank, accdb, NULL, &acct_a, 3000UL, 0 );
  ulong cap_before = bank->f.capitalization;

  /* Open for rw, modify lamports, close */
  fd_accdb_svm_update_t update[1];
  fd_acc_t rw = fd_accdb_svm_open_rw( bank, accdb, update, &acct_a, 0 );
  FD_TEST( rw.lamports==3000UL );
  FD_TEST( update->lamports_before==3000UL );

  /* Increase lamports */
  rw.lamports = 5000UL;
  fd_accdb_svm_close_rw( bank, accdb, NULL, &rw, update );

  /* Capitalization should increase by 2000 */
  FD_TEST( bank->f.capitalization==cap_before+2000UL );
  FD_TEST( fd_accdb_lamports( accdb, fork_id, acct_a.uc )==5000UL );

  /* Open for rw, decrease lamports, close */
  cap_before = bank->f.capitalization;
  rw = fd_accdb_svm_open_rw( bank, accdb, update, &acct_a, 0 );
  rw.lamports = 1000UL;
  fd_accdb_svm_close_rw( bank, accdb, NULL, &rw, update );
  FD_TEST( bank->f.capitalization==cap_before-4000UL );
  FD_TEST( fd_accdb_lamports( accdb, fork_id, acct_a.uc )==1000UL );

  /* Open rw on non-existent account with CREATE => succeeds */
  fd_pubkey_t ghost = {{ 0xFE,0xFE,0xFE,0,0,0,0,0,0,0,0,0,0,0,0,0,
                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  rw = fd_accdb_svm_open_rw( bank, accdb, update, &ghost, 1 );
  FD_TEST( update->lamports_before==0UL );
  rw.lamports = 100UL;
  cap_before = bank->f.capitalization;
  fd_accdb_svm_close_rw( bank, accdb, NULL, &rw, update );
  FD_TEST( bank->f.capitalization==cap_before+100UL );
  FD_TEST( fd_accdb_lamports( accdb, fork_id, ghost.uc )==100UL );

  FD_LOG_NOTICE(( "test_open_close_rw passed" ));
}

static void
test_fork_isolation( fd_svm_mini_t * mini,
                     ulong           root_idx ) {
  fd_accdb_t * accdb = mini->runtime->accdb;

  /* Seed account via a child fork, then root it */
  ulong seed_idx = fd_svm_mini_attach_child( mini, root_idx, 11UL );
  fd_bank_t *        seed_bank    = fd_svm_mini_bank( mini, seed_idx );
  fd_accdb_fork_id_t seed_fork_id = fd_svm_mini_fork_id( mini, seed_idx );
  fd_accdb_svm_credit( seed_bank, accdb, NULL, &acct_a, 1000UL, 0 );

  /* Freeze and advance root so account is rooted */
  fd_banks_mark_bank_frozen( seed_bank );
  fd_svm_mini_advance_root( mini, seed_idx );

  /* Create two child forks from the new root */
  ulong fork_a_idx = fd_svm_mini_attach_child( mini, seed_idx, 12UL );
  ulong fork_b_idx = fd_svm_mini_attach_child( mini, seed_idx, 13UL );
  fd_bank_t *        bank_a    = fd_svm_mini_bank( mini, fork_a_idx );
  fd_bank_t *        bank_b    = fd_svm_mini_bank( mini, fork_b_idx );
  fd_accdb_fork_id_t fork_id_a = fd_svm_mini_fork_id( mini, fork_a_idx );
  fd_accdb_fork_id_t fork_id_b = fd_svm_mini_fork_id( mini, fork_b_idx );

  /* Credit on fork A */
  fd_accdb_svm_credit( bank_a, accdb, NULL, &acct_a, 500UL, 0 );
  FD_TEST( fd_accdb_lamports( accdb, fork_id_a, acct_a.uc )==1500UL );

  /* Fork B should still see original balance */
  FD_TEST( fd_accdb_lamports( accdb, fork_id_b, acct_a.uc )==1000UL );

  /* Write on fork B with different owner */
  uchar data[4] = { 1,2,3,4 };
  fd_accdb_svm_write( bank_b, accdb, NULL,
                      &acct_a, &owner2, data, sizeof(data),
                      0UL, 0, 0 );

  /* Fork A should still have original owner (system program / zero) */
  fd_acc_t acc_a = fd_accdb_read_one( accdb, fork_id_a, acct_a.uc );
  FD_TEST( memcmp( acc_a.owner, owner2.key, 32UL )!=0 );
  fd_accdb_unread_one( accdb, &acc_a );

  /* Fork B should have new owner */
  fd_acc_t acc_b = fd_accdb_read_one( accdb, fork_id_b, acct_a.uc );
  FD_TEST( !memcmp( acc_b.owner, owner2.key, 32UL ) );
  fd_accdb_unread_one( accdb, &acc_b );

  (void)seed_fork_id;

  FD_LOG_NOTICE(( "test_fork_isolation passed" ));
}

/* LtHash mode tests.  In INBAND mode a write moves the bank LtHash by
   the account's new hash minus its old hash.  In OOB_RECORD mode it
   leaves the bank LtHash alone and appends the pubkey to the record
   list, once per write call.  In OOB_SKIP mode it does neither.  All
   other effects of a write are the same in every mode. */

/* TEST_REC_CNT is the number of write calls test_lthash_mode makes
   after switching modes.  The record list holds exactly that many keys,
   so OOB_RECORD mode fills it without overflowing. */

#define TEST_REC_CNT (8UL)

static fd_pubkey_t          test_rec_keys[ TEST_REC_CNT ];
static fd_bank_lthash_rec_t test_rec[1];

/* hash_acct computes the LtHash of pubkey as it is on fork_id, which is
   zero for an account that does not exist. */

static void
hash_acct( fd_accdb_t *        accdb,
           fd_accdb_fork_id_t  fork_id,
           fd_pubkey_t const * pubkey,
           fd_lthash_value_t * out ) {
  fd_acc_t acc = fd_accdb_read_one( accdb, fork_id, pubkey->uc );
  fd_hashes_account_lthash_simple( pubkey->uc, acc.owner, acc.lamports, acc.executable, acc.data, acc.data_len, out );
  fd_accdb_unread_one( accdb, &acc );
}

struct lthash_snap {
  fd_lthash_value_t bank_lthash;
  fd_lthash_value_t acct_lthash;
  ulong             rec_cnt;
};
typedef struct lthash_snap lthash_snap_t;

static void
snap_take( lthash_snap_t *     snap,
           fd_bank_t *         bank,
           fd_accdb_t *        accdb,
           fd_accdb_fork_id_t  fork_id,
           fd_pubkey_t const * pubkey ) {
  snap->bank_lthash = bank->f.lthash;
  hash_acct( accdb, fork_id, pubkey, &snap->acct_lthash );
  snap->rec_cnt = test_rec->cnt;
}

/* snap_check verifies the effect of write_cnt write calls to pubkey made
   since snap_take, which must have changed the account. */

static void
snap_check( lthash_snap_t const * snap,
            fd_bank_t *           bank,
            fd_accdb_t *          accdb,
            fd_accdb_fork_id_t    fork_id,
            fd_pubkey_t const *   pubkey,
            ulong                 write_cnt ) {
  fd_lthash_value_t acct_lthash[1];
  hash_acct( accdb, fork_id, pubkey, acct_lthash );
  FD_TEST( !fd_lthash_eq( acct_lthash, &snap->acct_lthash ) );

  switch( bank->lthash_mode ) {
  case FD_BANK_LTHASH_MODE_INBAND: {
    fd_lthash_value_t expected[1] = { snap->bank_lthash };
    fd_lthash_sub( expected, &snap->acct_lthash );
    fd_lthash_add( expected, acct_lthash );
    FD_TEST( fd_lthash_eq( expected, &bank->f.lthash ) );
    FD_TEST( test_rec->cnt==snap->rec_cnt );
    break;
  }
  case FD_BANK_LTHASH_MODE_OOB_RECORD:
    FD_TEST( fd_lthash_eq( &snap->bank_lthash, &bank->f.lthash ) );
    FD_TEST( test_rec->cnt==snap->rec_cnt+write_cnt );
    for( ulong i=snap->rec_cnt; i<test_rec->cnt; i++ ) FD_TEST( fd_pubkey_eq( &test_rec_keys[ i ], pubkey ) );
    break;
  case FD_BANK_LTHASH_MODE_OOB_SKIP:
    FD_TEST( fd_lthash_eq( &snap->bank_lthash, &bank->f.lthash ) );
    FD_TEST( test_rec->cnt==snap->rec_cnt );
    break;
  default:
    FD_LOG_ERR(( "unexpected lthash_mode %u", (uint)bank->lthash_mode ));
  }
}

/* snap_check_none verifies that nothing was written since snap_take. */

static void
snap_check_none( lthash_snap_t const * snap,
                 fd_bank_t *           bank ) {
  FD_TEST( fd_lthash_eq( &snap->bank_lthash, &bank->f.lthash ) );
  FD_TEST( test_rec->cnt==snap->rec_cnt );
}

/* test_lthash_mode runs one sequence of writes in the given mode and
   returns the resulting capitalization and the hashes of the accounts
   it wrote, for comparison across modes. */

static void
test_lthash_mode( fd_svm_mini_t *        mini,
                  fd_svm_mini_params_t * params,
                  uchar                  mode,
                  ulong *                cap_out,
                  fd_lthash_value_t      acct_out[ static 4 ] ) {
  ulong              root_idx = fd_svm_mini_reset( mini, params );
  ulong              bank_idx = fd_svm_mini_attach_child( mini, root_idx, 11UL );
  fd_bank_t *        bank     = fd_svm_mini_bank( mini, bank_idx );
  fd_accdb_fork_id_t fork_id  = fd_svm_mini_fork_id( mini, bank_idx );
  fd_accdb_t *       accdb    = mini->runtime->accdb;

  /* A new bank hashes in band and has no record list. */
  FD_TEST( bank->lthash_mode==FD_BANK_LTHASH_MODE_INBAND );
  FD_TEST( !bank->lthash_rec );

  /* Seed in band, then switch.  The record list is attached in every
     mode so that a stray append shows up. */
  fd_accdb_svm_credit( bank, accdb, NULL, &acct_a, 3000UL, 0 );
  fd_accdb_svm_credit( bank, accdb, NULL, &acct_c, 500UL,  0 );
  test_rec->cnt  = 0UL;
  test_rec->max  = TEST_REC_CNT;
  test_rec->keys = test_rec_keys;
  bank->lthash_mode = mode;
  bank->lthash_rec  = test_rec;

  ulong         cap = bank->f.capitalization;
  lthash_snap_t snap[1];

  /* In band, open_rw subtracts the old hash and close_rw adds the new
     one.  In OOB_RECORD mode close_rw records the pubkey.  Write 1. */
  snap_take( snap, bank, accdb, fork_id, &acct_a );
  fd_accdb_svm_update_t update[1];
  fd_acc_t rw = fd_accdb_svm_open_rw( bank, accdb, update, &acct_a, 0 );
  FD_TEST( rw.lamports==3000UL );
  if( mode==FD_BANK_LTHASH_MODE_INBAND ) {
    fd_lthash_value_t expected[1] = { snap->bank_lthash };
    fd_lthash_sub( expected, &snap->acct_lthash );
    FD_TEST( fd_lthash_eq( expected, &bank->f.lthash ) );
  } else {
    FD_TEST( fd_lthash_eq( &snap->bank_lthash, &bank->f.lthash ) );
  }
  FD_TEST( test_rec->cnt==0UL );
  rw.lamports = 5000UL;
  fd_accdb_svm_close_rw( bank, accdb, NULL, &rw, update );
  snap_check( snap, bank, accdb, fork_id, &acct_a, 1UL );
  FD_TEST( bank->f.capitalization==cap+2000UL );
  FD_TEST( fd_accdb_lamports( accdb, fork_id, acct_a.uc )==5000UL );

  /* open_rw on a missing account without create writes nothing. */
  snap_take( snap, bank, accdb, fork_id, &acct_missing );
  rw = fd_accdb_svm_open_rw( bank, accdb, update, &acct_missing, 0 );
  FD_TEST( !rw.lamports );
  snap_check_none( snap, bank );

  /* credit creates an account, then adds to it.  Writes 2 and 3. */
  snap_take( snap, bank, accdb, fork_id, &acct_b );
  fd_accdb_svm_credit( bank, accdb, NULL, &acct_b, 1000UL, 0 );
  snap_check( snap, bank, accdb, fork_id, &acct_b, 1UL );
  snap_take( snap, bank, accdb, fork_id, &acct_b );
  fd_accdb_svm_credit( bank, accdb, NULL, &acct_b, 250UL, 0 );
  snap_check( snap, bank, accdb, fork_id, &acct_b, 1UL );
  FD_TEST( bank->f.capitalization==cap+3250UL );

  /* A zero credit writes nothing. */
  snap_take( snap, bank, accdb, fork_id, &acct_b );
  fd_accdb_svm_credit( bank, accdb, NULL, &acct_b, 0UL, 0 );
  snap_check_none( snap, bank );

  /* write overwrites an account and mints up to lamports_min, then
     creates one.  Writes 4 and 5. */
  uchar data1[ 4 ] = { 0xDE, 0xAD, 0xBE, 0xEF };
  uchar data2[ 8 ] = { 1,2,3,4,5,6,7,8 };
  snap_take( snap, bank, accdb, fork_id, &acct_c );
  fd_accdb_svm_write( bank, accdb, NULL, &acct_c, &owner2, data2, sizeof(data2), 1000UL, 1, 0 );
  snap_check( snap, bank, accdb, fork_id, &acct_c, 1UL );
  FD_TEST( bank->f.capitalization==cap+3750UL );
  snap_take( snap, bank, accdb, fork_id, &acct_d );
  fd_accdb_svm_write( bank, accdb, NULL, &acct_d, &owner1, data1, sizeof(data1), 100UL, 0, 0 );
  snap_check( snap, bank, accdb, fork_id, &acct_d, 1UL );
  FD_TEST( bank->f.capitalization==cap+3850UL );

  /* remove burns an account.  Write 6.  Removing a missing account
     writes nothing. */
  snap_take( snap, bank, accdb, fork_id, &acct_a );
  FD_TEST( fd_accdb_svm_remove( bank, accdb, NULL, &acct_a )==5000UL );
  snap_check( snap, bank, accdb, fork_id, &acct_a, 1UL );
  FD_TEST( bank->f.capitalization==cap-1150UL );
  FD_TEST( !fd_accdb_lamports( accdb, fork_id, acct_a.uc ) );
  snap_take( snap, bank, accdb, fork_id, &acct_missing );
  FD_TEST( !fd_accdb_svm_remove( bank, accdb, NULL, &acct_missing ) );
  snap_check_none( snap, bank );

  /* Two writes to one account are recorded twice.  Writes 7 and 8. */
  snap_take( snap, bank, accdb, fork_id, &acct_b );
  rw = fd_accdb_svm_open_rw( bank, accdb, update, &acct_b, 0 );
  rw.lamports -= 50UL;
  fd_accdb_svm_close_rw( bank, accdb, NULL, &rw, update );
  fd_accdb_svm_credit( bank, accdb, NULL, &acct_b, 20UL, 0 );
  snap_check( snap, bank, accdb, fork_id, &acct_b, 2UL );
  FD_TEST( bank->f.capitalization==cap-1180UL );

  FD_TEST( test_rec->cnt==( mode==FD_BANK_LTHASH_MODE_OOB_RECORD ? TEST_REC_CNT : 0UL ) );

  *cap_out = bank->f.capitalization;
  hash_acct( accdb, fork_id, &acct_a, &acct_out[ 0 ] );
  hash_acct( accdb, fork_id, &acct_b, &acct_out[ 1 ] );
  hash_acct( accdb, fork_id, &acct_c, &acct_out[ 2 ] );
  hash_acct( accdb, fork_id, &acct_d, &acct_out[ 3 ] );

  bank->lthash_mode = FD_BANK_LTHASH_MODE_INBAND;
  bank->lthash_rec  = NULL;

  FD_LOG_NOTICE(( "test_lthash_mode(%u) passed", (uint)mode ));
}

static void
test_lthash_modes( fd_svm_mini_t *        mini,
                   fd_svm_mini_params_t * params ) {
  static uchar const modes[ 3 ] = { FD_BANK_LTHASH_MODE_INBAND, FD_BANK_LTHASH_MODE_OOB_RECORD, FD_BANK_LTHASH_MODE_OOB_SKIP };
  static fd_lthash_value_t accts[ 3 ][ 4 ];
  ulong cap[ 3 ];
  for( ulong i=0UL; i<3UL; i++ ) test_lthash_mode( mini, params, modes[ i ], &cap[ i ], accts[ i ] );

  /* The accounts and capitalization do not depend on the mode. */
  for( ulong i=1UL; i<3UL; i++ ) {
    FD_TEST( cap[ i ]==cap[ 0 ] );
    for( ulong j=0UL; j<4UL; j++ ) FD_TEST( fd_lthash_eq( &accts[ i ][ j ], &accts[ 0 ][ j ] ) );
  }

  FD_LOG_NOTICE(( "test_lthash_modes passed" ));
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
     not allow writes to the rooted fork. */

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

  test_lthash_modes( mini, params );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
