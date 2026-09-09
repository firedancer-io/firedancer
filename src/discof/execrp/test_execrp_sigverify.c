#include "fd_execrp_sigverify.h"
#include "../../flamenco/txn/fd_txn_generate.h"

static void
build_txn( fd_txn_p_t * txn_p, ulong sig_cnt, int v1, ulong tag, fd_sha512_t * sha ) {
  uchar private_keys[ FD_TXN_SIG_MAX ][32];
  fd_pubkey_t keys[ FD_TXN_SIG_MAX+1UL ];
  fd_memset( txn_p, 0, sizeof(*txn_p) );
  for( ulong j=0UL; j<sig_cnt; j++ ) {
    fd_memset( private_keys[j], (int)(tag+j+1UL), 32UL );
    fd_ed25519_public_from_private( keys[j].uc, private_keys[j], sha );
  }
  fd_memset( keys[sig_cnt].uc, 0x42, 32UL );
  if( v1 ) {
    uchar * p = txn_p->payload;
    p[0] = 0x81U; p[1] = (uchar)sig_cnt; p[3] = 1U;
    p[40] = 1U; p[41] = (uchar)(sig_cnt+1UL);
    fd_memcpy( p+42UL, keys, 32UL*(sig_cnt+1UL) );
    ulong instr_off = 42UL+32UL*(sig_cnt+1UL);
    p[instr_off] = (uchar)sig_cnt;
    FD_STORE( ushort, p+instr_off+2UL, 19U );
    fd_memset( p+instr_off+4UL, (int)tag, 19UL );
    txn_p->payload_sz = instr_off+4UL+19UL+64UL*sig_cnt;
  } else {
    fd_txn_accounts_t accounts = {
      .signature_cnt = (uchar)sig_cnt, .readonly_unsigned_cnt = 1U,
      .acct_cnt = (ushort)(sig_cnt+1UL), .signers_w = keys, .non_signers_r = keys+sig_cnt
    };
    fd_txn_base_generate( txn_p->_, txn_p->payload, sig_cnt, &accounts, NULL );
    uchar acct = 0U;
    uchar data = (uchar)tag;
    txn_p->payload_sz = fd_txn_add_instr( txn_p->_, txn_p->payload, (uchar)sig_cnt, &acct, 1UL, &data, 1UL );
  }
  FD_TEST( fd_txn_parse( txn_p->payload, txn_p->payload_sz, txn_p->_, NULL ) );
  fd_txn_t * txn = TXN( txn_p );
  for( ulong j=0UL; j<sig_cnt; j++ )
    fd_ed25519_sign( txn_p->payload+txn->signature_off+64UL*j,
                     txn_p->payload+txn->message_off, fd_txn_msg_sz( txn, txn_p->payload_sz ),
                     keys[j].uc, private_keys[j], sha );
}

static void
check_group( fd_execrp_txn_sigverify_msg_t * msg, fd_sha512_t * shas[ FD_TXN_SIG_MAX ], ulong bad_mask ) {
  int expected[ FD_EXECRP_SIGVERIFY_MAX ] = {0};
  ulong signature_cnt = 0UL;
  for( ulong i=0UL; i<msg->cnt; i++ ) {
    fd_execrp_sigverify_txn_t const * txn = msg->txn+i;
    uchar const * payload = msg->payload+txn->payload_off;
    signature_cnt += txn->signature_cnt;
    for( ulong j=0UL; j<txn->signature_cnt; j++ ) {
      int res = fd_ed25519_verify( payload+txn->message_off, txn->message_sz,
                                  payload+txn->signature_off+64UL*j, payload+txn->acct_addr_off+32UL*j, shas[0] );
      if( !expected[i] ) expected[i] = res;
    }
    FD_TEST( (!!expected[i])==(int)((bad_mask>>i)&1UL) );
  }
  fd_execrp_txn_sigverify_done_msg_t out[1];
  fd_memset( out, 0xa5, sizeof(*out) );
  FD_TEST( fd_execrp_sigverify( msg, out, shas )==signature_cnt );
  FD_TEST( out->cnt==msg->cnt );
  for( ulong i=0UL; i<msg->cnt; i++ ) {
    FD_TEST( out->txn_idx[i]==msg->txn_idx[i] );
    FD_TEST( out->err[i]==expected[i] );
  }
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  fd_sha512_t sha_mem[ FD_TXN_SIG_MAX ];
  fd_sha512_t * shas[ FD_TXN_SIG_MAX ];
  for( ulong i=0UL; i<FD_TXN_SIG_MAX; i++ ) shas[i] = fd_sha512_join( fd_sha512_new( sha_mem+i ) );
  ulong counts[] = { 1UL, 3UL, 8UL };
  for( ulong c=0UL; c<3UL; c++ ) {
    fd_execrp_txn_sigverify_msg_t msg[1] = {{0}};
    for( ulong i=0UL; i<counts[c]; i++ ) {
      fd_txn_p_t txn[1];
      /* Twelve signatures in the first transaction cross a lane-group
         boundary.  Later transactions cover varying messages and tails. */
      build_txn( txn, i ? 1UL+i%3UL : 12UL, !(i&1UL), 13UL*i, shas[0] );
      fd_execrp_sigverify_add( msg, 100UL+i, txn );
    }
    check_group( msg, shas, 0UL );
    for( ulong i=0UL; i<msg->cnt; i++ ) {
      fd_execrp_sigverify_txn_t const * txn = msg->txn+i;
      uchar * sig = msg->payload+txn->payload_off+txn->signature_off+64UL*(txn->signature_cnt-1UL);
      uchar saved = sig[63];
      sig[63] |= 0x80U; /* Noncanonical scalar in the last signature. */
      check_group( msg, shas, 1UL<<i );
      sig[63] = saved;
    }
    /* Two different failure causes within a multisignature transaction:
       the first failure must retain scalar API precedence and not affect
       the valid transactions in later lanes. */
    uchar * first = msg->payload+msg->txn[0].signature_off;
    fd_memset( first, 0, 32UL );
    first[64UL*11UL+63UL] |= 0x80U;
    check_group( msg, shas, 1UL );
  }
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
