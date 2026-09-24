#include "fd_event_runtime.h"
#include "../../disco/events/fd_event_report.h"

static fd_event_runtime_txn_t captured;
#undef fd_event_report_runtime_txn
#define fd_event_report_runtime_txn( ev ) (captured = *(ev))
#include "fd_event_runtime.c"

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  static fd_event_reporter_t reporter;
  fd_event_tl = &reporter;
  static fd_txn_p_t txn;
  static fd_txn_in_t in;
  static fd_txn_out_t out;
  static fd_bank_t bank;
  static fd_acc_t accounts[ 2 ];
  uchar const zero[ 32 ] = {0};
  in.txn = &txn;
  in.index_in_slot = 17UL;
  out.err.is_committable = 1;
  out.accounts.cnt = 2UL;
  for( ulong i=0UL; i<2UL; i++ ) {
    accounts[i].prior_lamports = 10UL;
    accounts[i].lamports = 9UL;
    out.accounts.account[i] = &accounts[i];
    out.accounts.is_writable[i] = 1;
    out.accounts.keys[i].uc[0] = (uchar)(i+1UL);
  }
  /* Skipping an unchanged account must not shift the checksum mapping. */
  accounts[0].lamports = 10UL;
  memset( out.accounts.lthash_checksum[1], 0xAB, 32UL );
  fd_event_runtime_txn_emit( &in, &out, &bank );
  FD_TEST( captured.index_in_slot==17UL );
  FD_TEST( captured.account_diffs_cnt==1UL );
  FD_TEST( !memcmp( captured.account_diffs[0].pubkey, out.accounts.keys[1].uc, 32UL ) );
  FD_TEST( !memcmp( captured.account_diffs[0].lthash, out.accounts.lthash_checksum[1], 32UL ) );

  /* A deletion's checksum is not the uncaptured zero sentinel. */
  fd_lthash_value_t identity;
  fd_lthash_zero( &identity );
  uchar deleted[ 32 ];
  fd_blake3_hash( identity.bytes, FD_LTHASH_LEN_BYTES, deleted );
  FD_TEST( memcmp( deleted, zero, 32UL ) );
  accounts[1].lamports = 0UL;
  memcpy( out.accounts.lthash_checksum[1], deleted, 32UL );
  fd_event_runtime_txn_emit( &in, &out, &bank );
  FD_TEST( !memcmp( captured.account_diffs[0].lthash, deleted, 32UL ) );

  /* Rejection after checksum computation must suppress the checksum. */
  out.err.is_committable = 0;
  fd_event_runtime_txn_emit( &in, &out, &bank );
  FD_TEST( !memcmp( captured.account_diffs[0].lthash, zero, 32UL ) );
  out.err.is_committable = 1;
  memset( out.accounts.lthash_checksum[1], 0, 32UL );
  fd_event_runtime_txn_emit( &in, &out, &bank );
  FD_TEST( !memcmp( captured.account_diffs[0].lthash, zero, 32UL ) );

  /* Block diffs must also checksum deletions and keep the latest hash. */
  static uchar diff_mem[ FD_EVENT_RUNTIME_SLOT_DIFFS_FOOTPRINT ] __attribute__((aligned(8)));
  fd_event_runtime_slot_diffs_init( diff_mem, 1UL );
  fd_lthash_value_t live;
  memset( live.bytes, 0xAB, FD_LTHASH_LEN_BYTES );
  fd_event_runtime_block_account( &bank, out.accounts.keys[1].uc, zero, zero, 10UL, 9UL, 0UL, 0UL, 0, &live );
  fd_event_runtime_block_account( &bank, out.accounts.keys[1].uc, zero, zero, 9UL, 0UL, 0UL, 0UL, 0, &identity );
  fd_event_runtime_slot_diffs_t * diffs = fd_event_runtime_slot_diffs_at( bank.idx );
  FD_TEST( diffs->other_cnt==1UL );
  FD_TEST( diffs->other[0].prev_lamports==10UL && !diffs->other[0].lamports );
  FD_TEST( !memcmp( diffs->other[0].lthash, deleted, 32UL ) );
  fd_event_tl = NULL;
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
