#include "fd_cost_tracker.h"
#include "fd_slot_params.h"
#include "../features/fd_features.h"
#include "fd_runtime.h"
#include <string.h>

/* SIMD-525: verify fd_cost_tracker_init applies the per-regime
   slot-params limits and the raise_block_limits_to_100m scaling, and
   sets the per-regime data-size limit. */
static void
test_cost_tracker_init_reconciliation( fd_cost_tracker_t * ct ) {
  ulong const   SLOT = 10UL; /* features with activation_slot 0 are active here */
  fd_features_t f;

  /* 400ms baseline, no features: table 60M / 24M / 100M. */
  memset( &f, 0xFF, sizeof(f) );
  fd_cost_tracker_init( ct, &f, &FD_SLOT_PARAMS_400MS, SLOT );
  FD_TEST( ct->block_cost_limit  ==60000000UL  );
  FD_TEST( ct->account_cost_limit==24000000UL  );
  FD_TEST( ct->data_size_limit   ==100000000UL );

  /* 400ms + raise_block_limits_to_100m: table scaled by 100/60 ->
     100M / 40M. */
  memset( &f, 0xFF, sizeof(f) );
  f.raise_block_limits_to_100m = 0UL;
  fd_cost_tracker_init( ct, &f, &FD_SLOT_PARAMS_400MS, SLOT );
  FD_TEST( ct->block_cost_limit  ==100000000UL );
  FD_TEST( ct->account_cost_limit==40000000UL  );
  FD_TEST( ct->data_size_limit   ==100000000UL );

  /* 200ms + 100m: regime table scaled by 100/60 -> 50M / 20M / 50M. */
  memset( &f, 0xFF, sizeof(f) );
  f.raise_block_limits_to_100m = 0UL;
  fd_cost_tracker_init( ct, &f, &FD_SLOT_PARAMS_200MS, SLOT );
  FD_TEST( ct->block_cost_limit  ==50000000UL );
  FD_TEST( ct->account_cost_limit==20000000UL );
  FD_TEST( ct->data_size_limit   ==50000000UL );

  /* 200ms, no 100m: regime table 30M / 12M / 50M (account = table
     40%). */
  memset( &f, 0xFF, sizeof(f) );
  fd_cost_tracker_init( ct, &f, &FD_SLOT_PARAMS_200MS, SLOT );
  FD_TEST( ct->block_cost_limit  ==30000000UL );
  FD_TEST( ct->account_cost_limit==12000000UL );
  FD_TEST( ct->data_size_limit   ==50000000UL );

  /* 350ms + 100m: 52.5M*100/60=87.5M, 21M*100/60=35M, 87.5M. */
  memset( &f, 0xFF, sizeof(f) );
  f.raise_block_limits_to_100m = 0UL;
  fd_cost_tracker_init( ct, &f, &FD_SLOT_PARAMS_350MS, SLOT );
  FD_TEST( ct->block_cost_limit  ==87500000UL );
  FD_TEST( ct->account_cost_limit==35000000UL );
  FD_TEST( ct->data_size_limit   ==87500000UL );
}

static void
test_cost_tracker_block_limit( fd_cost_tracker_t * ct ) {
  ulong const slot = 10UL;
  fd_features_t f;
  static fd_txn_out_t txn_out = {0};

  fd_features_disable_all( &f );
  fd_cost_tracker_init( ct, &f, &FD_SLOT_PARAMS_400MS, slot );

  FD_TEST( ct->block_cost == 0UL );
  FD_TEST( ct->block_cost_limit == 60000000UL );

  /* Multiple txns required because max add is 24M. Transaction 1: 24M */
  txn_out.details.txn_cost.transaction.programs_execution_cost = 24000000U;
  int err = fd_cost_tracker_try_add_cost( ct, &txn_out );
  FD_TEST( err == FD_COST_TRACKER_SUCCESS );
  FD_TEST( ct->block_cost == 24000000UL );

  /* Transaction 2: another 24M */
  err = fd_cost_tracker_try_add_cost( ct, &txn_out );
  FD_TEST( err == FD_COST_TRACKER_SUCCESS );
  FD_TEST( ct->block_cost == 48000000UL );

  /* Transaction 3: 12M, bringing the block exactly to 60M */
  txn_out.details.txn_cost.transaction.programs_execution_cost = 12000000U;
  err = fd_cost_tracker_try_add_cost( ct, &txn_out );
  FD_TEST( err == FD_COST_TRACKER_SUCCESS );
  FD_TEST( ct->block_cost == 60000000UL );

  /* Transaction 4: 1 more CU should exceed the block limit */
  txn_out.details.txn_cost.transaction.programs_execution_cost = 1U;
  err = fd_cost_tracker_try_add_cost( ct, &txn_out );
  FD_TEST( err == FD_COST_TRACKER_ERROR_WOULD_EXCEED_BLOCK_MAX_LIMIT );
  FD_TEST( ct->block_cost == 60000000UL );
}

static void
test_cost_tracker_account_limit( fd_cost_tracker_t * ct ) {
  ulong const slot = 10UL;
  fd_features_t f;
  static fd_txn_out_t txn_out = {0};

  fd_features_enable_all( &f );
  fd_cost_tracker_init( ct, &f, &FD_SLOT_PARAMS_400MS, slot );

  ct->block_cost_limit  = 10000UL;
  ct->account_cost_limit = 1000UL;
  ct->data_size_limit  = 10000UL;

  /* Cost below account limit succeeds. */
  txn_out.details.txn_cost.transaction.loaded_accounts_data_size_cost = 600U;
  int err = fd_cost_tracker_try_add_cost( ct, &txn_out );
  FD_TEST( err == FD_COST_TRACKER_SUCCESS );
  FD_TEST( ct->block_cost == 600UL );

  /* Cost above account limit fails */
  txn_out.details.txn_cost.transaction.loaded_accounts_data_size_cost = 1001U;
  err = fd_cost_tracker_try_add_cost( ct, &txn_out );
  FD_TEST( err == FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_MAX_LIMIT );
  FD_TEST( ct->block_cost == 600UL );
}

static void
test_cost_tracker_txn_cost_sum( fd_cost_tracker_t * ct ) {
  ulong const slot = 10UL;
  fd_features_t f;
  static fd_txn_out_t txn_out = {0};

  fd_features_enable_all( &f );
  fd_cost_tracker_init( ct, &f, &FD_SLOT_PARAMS_400MS, slot );

  ct->account_cost_limit = 1000UL;
  txn_out.details.txn_cost.transaction.signature_cost = 600U;
  txn_out.details.txn_cost.transaction.data_bytes_cost = 500U;

  int err = fd_cost_tracker_try_add_cost( ct, &txn_out );
  FD_TEST( err == FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_MAX_LIMIT );
  FD_TEST( ct->block_cost == 0UL );
}

static void
test_cost_tracker_data_size_limit( fd_cost_tracker_t * ct ) {
  ulong const slot = 10UL;
  fd_features_t f;
  static fd_txn_out_t txn_out = {0};

  fd_features_enable_all( &f );
  fd_cost_tracker_init( ct, &f, &FD_SLOT_PARAMS_400MS, slot );
  txn_out.details.txn_cost.transaction.allocated_accounts_data_size = ct->data_size_limit;

  int err = fd_cost_tracker_try_add_cost( ct, &txn_out );
  FD_TEST( err == FD_COST_TRACKER_SUCCESS );
  FD_TEST( ct->allocated_accounts_data_size == ct->data_size_limit );

  txn_out.details.txn_cost.transaction.allocated_accounts_data_size = ct->data_size_limit + 1UL;
  err = fd_cost_tracker_try_add_cost( ct, &txn_out );
  FD_TEST( err == FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT );
  FD_TEST( ct->allocated_accounts_data_size == ct->data_size_limit );
}

static void
test_cost_tracker_rejection_non_mutating( fd_cost_tracker_t * ct ) {
  ulong const slot = 10UL;
  fd_features_t f;
  static fd_txn_out_t txn_out = {0};

  fd_features_enable_all( &f );
  fd_cost_tracker_init( ct, &f, &FD_SLOT_PARAMS_400MS, slot );
  FD_TEST( ct->block_cost == 0UL );

  ct->block_cost_limit = 1000UL;
  ulong block_cost = ct->block_cost;
  ulong allocated_accounts_data_size = ct->allocated_accounts_data_size;

  txn_out.details.txn_cost.transaction.programs_execution_cost = 1001U;
  int err = fd_cost_tracker_try_add_cost( ct, &txn_out );
  FD_TEST( err == FD_COST_TRACKER_ERROR_WOULD_EXCEED_BLOCK_MAX_LIMIT );
  FD_TEST( ct->block_cost == block_cost );
  FD_TEST( ct->allocated_accounts_data_size == allocated_accounts_data_size );
}

static void
test_cost_tracker_multiple_accounts( fd_cost_tracker_t * ct ) {
  ulong const slot = 10UL;
  fd_features_t f;
  static fd_txn_out_t txn_out = {0};

  fd_features_enable_all( &f );
  fd_cost_tracker_init( ct, &f, &FD_SLOT_PARAMS_400MS, slot );

  /* Set up two writable accounts */
  ct->account_cost_limit = 1000UL;
  txn_out.accounts.cnt = 2UL;
  txn_out.accounts.is_writable[0] = 1U;
  txn_out.accounts.is_writable[1] = 1U;

  memset( txn_out.accounts.keys, 0, sizeof( txn_out.accounts.keys ));
  txn_out.accounts.keys[1].uc[1] = 1U;

  /* Setting up the txn costs */
  txn_out.details.txn_cost.transaction.programs_execution_cost = 600U;
  int err = fd_cost_tracker_try_add_cost( ct, &txn_out );
  FD_TEST( ct->block_cost == 600UL );
  FD_TEST( err == FD_COST_TRACKER_SUCCESS );
  txn_out.details.txn_cost.transaction.programs_execution_cost = 500U;
  txn_out.accounts.is_writable[0] = 1U;
  txn_out.accounts.is_writable[1] = 0U;
  err = fd_cost_tracker_try_add_cost( ct, &txn_out );
  FD_TEST( err == FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_MAX_LIMIT );
  FD_TEST( ct->block_cost == 600UL );
}

/* set_accounts sets up txn_out with accounts keyed by the given ids
   (key byte 0), writable iff wr[ i ], and the given txn cost. */
static void
set_accounts( fd_txn_out_t * txn_out,
              uchar const *  ids,
              uchar const *  wr,
              ulong          cnt,
              uint           cost ) {
  memset( txn_out->accounts.keys, 0, sizeof(txn_out->accounts.keys) );
  for( ulong i=0UL; i<cnt; i++ ) {
    txn_out->accounts.keys[ i ].uc[ 0 ] = ids[ i ];
    txn_out->accounts.is_writable[ i ]  = wr[ i ];
  }
  txn_out->accounts.cnt = cnt;
  memset( &txn_out->details.txn_cost, 0, sizeof(txn_out->details.txn_cost) );
  txn_out->details.txn_cost.transaction.programs_execution_cost = cost;
}

/* Mixes accounts that already have chained cost with first-touch
   accounts in one transaction, and checks that a transaction rejected
   by the per-account limit (after the cost was applied to earlier
   writable accounts in it, both new and existing) leaves every account
   cost, the block cost and the allocated data size unchanged. */
static void
test_cost_tracker_mixed_accounts( fd_cost_tracker_t * ct ) {
  ulong const slot = 10UL;
  fd_features_t f;
  static fd_txn_out_t txn_out = {0};

  fd_features_enable_all( &f );
  fd_cost_tracker_init( ct, &f, &FD_SLOT_PARAMS_400MS, slot );
  ct->account_cost_limit = 1000UL;

  /* A=600 B=600 */
  set_accounts( &txn_out, (uchar[]){ 1, 2 }, (uchar[]){ 1, 1 }, 2UL, 600U );
  FD_TEST( fd_cost_tracker_try_add_cost( ct, &txn_out )==FD_COST_TRACKER_SUCCESS );
  FD_TEST( ct->block_cost==600UL );

  /* Existing A, new C, readonly B: A=900 B=600 C=300 */
  set_accounts( &txn_out, (uchar[]){ 1, 3, 2 }, (uchar[]){ 1, 1, 0 }, 3UL, 300U );
  FD_TEST( fd_cost_tracker_try_add_cost( ct, &txn_out )==FD_COST_TRACKER_SUCCESS );
  FD_TEST( ct->block_cost==900UL );

  /* Existing C, new D, then A which would exceed the account limit
     (900+200>1000): rejected, nothing changes. */
  set_accounts( &txn_out, (uchar[]){ 3, 4, 1 }, (uchar[]){ 1, 1, 1 }, 3UL, 200U );
  txn_out.details.txn_cost.transaction.allocated_accounts_data_size = 7UL;
  FD_TEST( fd_cost_tracker_try_add_cost( ct, &txn_out )==FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_MAX_LIMIT );
  FD_TEST( ct->block_cost==900UL );
  FD_TEST( ct->allocated_accounts_data_size==0UL );

  /* D was rolled back: it takes the full account limit. */
  set_accounts( &txn_out, (uchar[]){ 4 }, (uchar[]){ 1 }, 1UL, 1000U );
  FD_TEST( fd_cost_tracker_try_add_cost( ct, &txn_out )==FD_COST_TRACKER_SUCCESS );
  set_accounts( &txn_out, (uchar[]){ 4 }, (uchar[]){ 1 }, 1UL, 1U );
  FD_TEST( fd_cost_tracker_try_add_cost( ct, &txn_out )==FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_MAX_LIMIT );

  /* C is still 300 and A still 900: each fits exactly to the limit. */
  set_accounts( &txn_out, (uchar[]){ 3 }, (uchar[]){ 1 }, 1UL, 700U );
  FD_TEST( fd_cost_tracker_try_add_cost( ct, &txn_out )==FD_COST_TRACKER_SUCCESS );
  set_accounts( &txn_out, (uchar[]){ 1 }, (uchar[]){ 1 }, 1UL, 100U );
  FD_TEST( fd_cost_tracker_try_add_cost( ct, &txn_out )==FD_COST_TRACKER_SUCCESS );
  set_accounts( &txn_out, (uchar[]){ 3, 1 }, (uchar[]){ 0, 1 }, 2UL, 1U );
  FD_TEST( fd_cost_tracker_try_add_cost( ct, &txn_out )==FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_MAX_LIMIT );

  /* B is still 600. */
  set_accounts( &txn_out, (uchar[]){ 2 }, (uchar[]){ 1 }, 1UL, 400U );
  FD_TEST( fd_cost_tracker_try_add_cost( ct, &txn_out )==FD_COST_TRACKER_SUCCESS );
  set_accounts( &txn_out, (uchar[]){ 2 }, (uchar[]){ 1 }, 1UL, 1U );
  FD_TEST( fd_cost_tracker_try_add_cost( ct, &txn_out )==FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_MAX_LIMIT );

  FD_TEST( ct->block_cost==900UL+1000UL+700UL+100UL+400UL );
}

/* Rejects a transaction whose last writable account is over the limit,
   after its cost was applied to every earlier (new) account, enough
   times that the account pool would run out if a rejection did not
   release the pool elements it took. */
static void
test_cost_tracker_rollback_releases_pool( fd_cost_tracker_t * ct ) {
  ulong const slot = 10UL;
  fd_features_t f;
  static fd_txn_out_t txn_out = {0};

  fd_features_enable_all( &f );
  fd_cost_tracker_init( ct, &f, &FD_SLOT_PARAMS_400MS, slot );
  ct->account_cost_limit = 1000UL;

  ulong const cnt = MAX_TX_ACCOUNT_LOCKS;
  uchar ids[ MAX_TX_ACCOUNT_LOCKS ];
  uchar wr [ MAX_TX_ACCOUNT_LOCKS ];
  for( ulong i=0UL; i<cnt; i++ ) { ids[ i ] = (uchar)(i+1UL); wr[ i ] = 1; }

  /* Last account at the limit */
  set_accounts( &txn_out, ids+cnt-1UL, wr, 1UL, 1000U );
  FD_TEST( fd_cost_tracker_try_add_cost( ct, &txn_out )==FD_COST_TRACKER_SUCCESS );

  set_accounts( &txn_out, ids, wr, cnt, 1U );
  ulong iter = FD_RUNTIME_MAX_TXN_ACC_WRITES_PER_SLOT/(cnt-1UL) + 1UL;
  for( ulong i=0UL; i<iter; i++ ) {
    FD_TEST( fd_cost_tracker_try_add_cost( ct, &txn_out )==FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_MAX_LIMIT );
  }
  FD_TEST( ct->block_cost==1000UL );

  /* New accounts take the released pool elements.  Then the earlier
     accounts, which must be gone from the map, take the full limit.
     Every account is then at the limit. */
  uchar ids2[ MAX_TX_ACCOUNT_LOCKS ];
  for( ulong i=0UL; i<cnt; i++ ) ids2[ i ] = (uchar)(i+101UL);
  set_accounts( &txn_out, ids2, wr, cnt-1UL, 1000U );
  FD_TEST( fd_cost_tracker_try_add_cost( ct, &txn_out )==FD_COST_TRACKER_SUCCESS );
  set_accounts( &txn_out, ids, wr, cnt-1UL, 1000U );
  FD_TEST( fd_cost_tracker_try_add_cost( ct, &txn_out )==FD_COST_TRACKER_SUCCESS );
  FD_TEST( ct->block_cost==3000UL );
  for( ulong i=0UL; i<cnt-1UL; i++ ) {
    set_accounts( &txn_out, ids+i, wr, 1UL, 1U );
    FD_TEST( fd_cost_tracker_try_add_cost( ct, &txn_out )==FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_MAX_LIMIT );
    set_accounts( &txn_out, ids2+i, wr, 1UL, 1U );
    FD_TEST( fd_cost_tracker_try_add_cost( ct, &txn_out )==FD_COST_TRACKER_ERROR_WOULD_EXCEED_ACCOUNT_MAX_LIMIT );
  }
}

int main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL, NULL            );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"      );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 1UL             );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );
  ulong        wksp_tag = fd_env_strip_cmdline_ulong( &argc, &argv, "--wksp-tag",  NULL, 1234UL          );

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  void * cost_tracker_mem = fd_wksp_alloc_laddr( wksp, fd_cost_tracker_align(), fd_cost_tracker_footprint(), wksp_tag );
  FD_TEST( cost_tracker_mem );

  FD_TEST( fd_cost_tracker_align()>=alignof(fd_cost_tracker_t) );
  FD_TEST( fd_cost_tracker_align()<=FD_COST_TRACKER_ALIGN );

  FD_TEST( fd_cost_tracker_footprint()<=FD_COST_TRACKER_FOOTPRINT );

  FD_TEST( !fd_cost_tracker_new( NULL, 0, 999UL ) );
  void * new_cost_tracker_mem = fd_cost_tracker_new( cost_tracker_mem, 0, 999UL );

  FD_TEST( !fd_cost_tracker_join( NULL ) );
  void * junk_mem = fd_wksp_alloc_laddr( wksp, 1UL, 1UL, 999UL );
  FD_TEST( junk_mem );
  FD_TEST( !fd_cost_tracker_join( junk_mem ) );

  fd_cost_tracker_t * cost_tracker = fd_cost_tracker_join( new_cost_tracker_mem );
  FD_TEST( cost_tracker );
  FD_LOG_NOTICE(( "fd_cost_tracker_footprint: %lu", fd_cost_tracker_footprint() ));

  test_cost_tracker_init_reconciliation( cost_tracker );
  test_cost_tracker_block_limit( cost_tracker );
  test_cost_tracker_account_limit( cost_tracker );
  test_cost_tracker_txn_cost_sum( cost_tracker );
  test_cost_tracker_data_size_limit( cost_tracker );
  test_cost_tracker_rejection_non_mutating( cost_tracker );
  test_cost_tracker_multiple_accounts( cost_tracker );
  test_cost_tracker_mixed_accounts( cost_tracker );
  test_cost_tracker_rollback_releases_pool( cost_tracker );

  /* TODO: Add more sophisticated tests for the cost tracker. */
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
