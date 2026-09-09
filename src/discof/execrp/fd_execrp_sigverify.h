#ifndef HEADER_fd_src_discof_execrp_fd_execrp_sigverify_h
#define HEADER_fd_src_discof_execrp_fd_execrp_sigverify_h

#include "../replay/fd_execrp.h"
#include "../../ballet/ed25519/fd_ed25519.h"

/* fd_execrp_sigverify flattens a group of parsed transactions into
   independent signature lanes, including signatures of multi-signer
   transactions.  Every signature is checked.  The first failing
   signature's exact Ed25519 result is retained for its transaction;
   neighbors are unaffected.  Returns the number of signatures checked.
   shas contains FD_TXN_SIG_MAX distinct joined calculators. */
static inline ulong
fd_execrp_sigverify( fd_execrp_txn_sigverify_msg_t const * msg,
                    fd_execrp_txn_sigverify_done_msg_t * out,
                    fd_sha512_t *                      shas[ FD_TXN_SIG_MAX ] ) {
  enum { lane_cnt = 8 };
  FD_STATIC_ASSERT( FD_TXN_SIG_MAX>=lane_cnt, sigverify_sha_count );
  uchar const * msgs[ lane_cnt ];
  ulong         msg_szs[ lane_cnt ];
  uchar const * sigs[ lane_cnt ];
  uchar const * public_keys[ lane_cnt ];
  ulong         owners[ lane_cnt ];
  int           results[ lane_cnt ];
  ulong         cnt = 0UL;
  ulong         total = 0UL;

  FD_TEST( msg->cnt && msg->cnt<=FD_EXECRP_SIGVERIFY_MAX );
  FD_TEST( msg->payload_used<=FD_EXECRP_SIGVERIFY_BYTES );
  out->cnt = msg->cnt;
  for( ulong i=0UL; i<msg->cnt; i++ ) {
    fd_execrp_sigverify_txn_t const * txn = msg->txn+i;
    FD_TEST( txn->payload_sz<=FD_TXN_MTU );
    FD_TEST( (ulong)txn->payload_off+txn->payload_sz<=msg->payload_used );
    FD_TEST( txn->signature_cnt && txn->signature_cnt<=FD_TXN_SIG_MAX );
    FD_TEST( (ulong)txn->signature_off+64UL*txn->signature_cnt<=txn->payload_sz );
    FD_TEST( (ulong)txn->acct_addr_off+32UL*txn->signature_cnt<=txn->payload_sz );
    FD_TEST( (ulong)txn->message_off+txn->message_sz<=txn->payload_sz );
    out->txn_idx[ i ] = msg->txn_idx[ i ];
    out->err[ i ] = FD_ED25519_SUCCESS;
  }
  ulong txn_idx = 0UL;
  ulong sig_idx = 0UL;
  while( txn_idx<msg->cnt ) {
    fd_execrp_sigverify_txn_t const * txn = msg->txn+txn_idx;
    uchar const * payload = msg->payload+txn->payload_off;
    msgs[ cnt ]        = payload+txn->message_off;
    msg_szs[ cnt ]     = txn->message_sz;
    sigs[ cnt ]        = payload+txn->signature_off+64UL*sig_idx;
    public_keys[ cnt ] = payload+txn->acct_addr_off+32UL*sig_idx;
    owners[ cnt++ ]    = txn_idx;
    if( ++sig_idx==txn->signature_cnt ) {
      sig_idx = 0UL;
      txn_idx++;
    }
    if( cnt==lane_cnt || txn_idx==msg->cnt ) {
      fd_ed25519_verify_batch_multi_msg( msgs, msg_szs, sigs, public_keys, shas, results, cnt );
      for( ulong j=0UL; j<cnt; j++ ) {
        if( !out->err[ owners[ j ] ] ) out->err[ owners[ j ] ] = results[ j ];
      }
      total += cnt;
      cnt = 0UL;
    }
  }
  return total;
}

#endif /* HEADER_fd_src_discof_execrp_fd_execrp_sigverify_h */
