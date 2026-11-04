#include "fd_disco.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* Execle adds the bundle member index to pack's uint pack_idx using
     ulong arithmetic.  A bundle spanning the wrap must keep its slot. */
  for( ulong slot=0UL; slot<4UL; slot++ ) {
    for( ulong i=0UL; i<5UL; i++ ) {
      ulong pack_idx = (ulong)UINT_MAX+i;
      ulong sig = fd_disco_execle_sig( slot, pack_idx );
      FD_TEST( fd_disco_execle_sig_slot( sig )==slot );
      FD_TEST( fd_disco_execle_sig_pack_idx( sig )==(ulong)(uint)pack_idx );
    }
  }

  uchar txn_mem[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
  fd_txn_t * txn = (fd_txn_t *)txn_mem;
  *txn = (fd_txn_t){ .transaction_version=FD_TXN_VLEGACY, .acct_addr_cnt=3, .signature_cnt=1, .readonly_unsigned_cnt=1, .instr_cnt=1 };
  uchar payload[ 3UL*32UL + 3UL + 4UL ] = {0};
  fd_memset( payload, 'a', 2UL*32UL );
  txn->instr[0] = (fd_txn_instr_t){ .program_id=2, .acct_off=3U*32U, .acct_cnt=3, .data_off=3U*32U+3U, .data_sz=4 };
  payload[ txn->instr[0].acct_off   ] = 1;
  payload[ txn->instr[0].acct_off+1 ] = 2;
  payload[ txn->instr[0].acct_off+2 ] = 0;
  FD_STORE( uint, payload+txn->instr[0].data_off, 4U );
  FD_TEST( fd_disco_tpu_is_durable_nonce( txn, payload ) );
  txn->readonly_unsigned_cnt = 2;
  FD_TEST( !fd_disco_tpu_is_durable_nonce( txn, payload ) );

  /* The nonce may be loaded from an address lookup table. */
  txn->transaction_version = FD_TXN_V0;
  txn->addr_table_adtl_cnt = 2;
  txn->addr_table_adtl_writable_cnt = 1;
  payload[ txn->instr[0].acct_off ] = 3;
  FD_TEST( fd_disco_tpu_is_durable_nonce( txn, payload ) );
  payload[ txn->instr[0].acct_off ] = 4;
  FD_TEST( !fd_disco_tpu_is_durable_nonce( txn, payload ) );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

