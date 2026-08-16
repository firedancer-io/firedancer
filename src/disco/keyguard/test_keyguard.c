#include "fd_keyguard.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../alpenglow/consensus/ag_vote.h"

static uchar v1_buf [ FD_TXN_MTU    ];
static uchar v1_txn [ FD_TXN_MAX_SZ ];

static ulong
build_txn_v1( uchar * buf,
              ulong   sig_cnt,
              ulong   num_addr,
              ulong   instr_cnt,
              ulong * msg_sz ) {
  ulong o = 0UL;
  buf[ o++ ] = (uchar)0x81;            /* version byte: MESSAGE_VERSION_PREFIX | 1 */
  buf[ o++ ] = (uchar)sig_cnt;
  buf[ o++ ] = (uchar)( fd_ulong_max( sig_cnt, 1UL )-1UL );      /* ro signed cnt */
  buf[ o++ ] = (uchar)0;               /* ro unsigned cnt */
  for( ulong j=0UL; j< 4UL; j++ ) buf[ o++ ] = (uchar)0;         /* config mask */
  for( ulong j=0UL; j<32UL; j++ ) buf[ o++ ] = (uchar)(0xB0+j);  /* blockhash */
  buf[ o++ ] = (uchar)instr_cnt;
  buf[ o++ ] = (uchar)num_addr;
  for( ulong a=0UL; a<num_addr; a++ )
    for( ulong j=0UL; j<32UL; j++ ) buf[ o++ ] = (uchar)(a*32UL+j);
  /* instruction headers: program id 1, no accounts, no data */
  for( ulong x=0UL; x<instr_cnt; x++ ) {
    buf[ o++ ] = (uchar)1;  /* program id */
    buf[ o++ ] = (uchar)0;  /* acct cnt */
    buf[ o++ ] = (uchar)0;  /* data sz lo */
    buf[ o++ ] = (uchar)0;  /* data sz hi */
  }

  *msg_sz = o;  /* v1 signs payload[0,signature_off) */

  for( ulong s=0UL; s<sig_cnt; s++ )
    for( ulong j=0UL; j<64UL; j++ ) buf[ o++ ] = (uchar)(0x40+s);
  return o;
}

/* Every v1 txn that fd_txn_parse accepts must fingerprint as a txn.  A
   false negative would let the keyguard sign a transaction under
   another payload type's authorization rules.  Sweep every header
   field the keyguard inspects across its limit. */

void
test_txn_v1_match( void ) {
  fd_txn_t *  parsed          = (fd_txn_t *)v1_txn;
  ulong const instr_cnts[ 4 ] = { 0UL, 1UL, FD_TXN_INSTR_MAX, FD_TXN_INSTR_MAX+1UL };
  ulong       matched         = 0UL;

  for( ulong sig_cnt=0UL; sig_cnt<=FD_TXN_SIG_MAX+8UL; sig_cnt++ ) {
    for( ulong num_addr=0UL; num_addr<=FD_TXN_ACCT_ADDR_MAX+6UL; num_addr++ ) {
      for( ulong k=0UL; k<4UL; k++ ) {
        ulong msg_sz;
        ulong sz = build_txn_v1( v1_buf, sig_cnt, num_addr, instr_cnts[ k ], &msg_sz );
        if( !fd_txn_parse( v1_buf, sz, v1_txn, NULL ) ) continue;

        FD_TEST( parsed->transaction_version    ==FD_TXN_V1 );
        FD_TEST( parsed->message_off            ==0         );
        FD_TEST( fd_txn_msg_sz( parsed, sz )    ==msg_sz    );

        FD_TEST( fd_keyguard_payload_match( v1_buf, msg_sz, FD_KEYGUARD_SIGN_TYPE_ED25519 )
                 ==FD_KEYGUARD_PAYLOAD_TXN );
        matched++;
      }
    }
  }

  /* Guard against the sweep passing vacuously */
  FD_TEST( matched>1000UL );

  /* Payloads that are not v1 txn msgs */

  ulong msg_sz;
  build_txn_v1( v1_buf, 1UL, 1UL, 0UL, &msg_sz );

  /* Undersized */
  FD_TEST( !fd_keyguard_payload_match( v1_buf, 68UL, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );

  /* Not a raw Ed25519 signing request */
  FD_TEST( !fd_keyguard_payload_match( v1_buf, msg_sz, FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519        ) );
  FD_TEST( !fd_keyguard_payload_match( v1_buf, msg_sz, FD_KEYGUARD_SIGN_TYPE_PUBKEY_CONCAT_ED25519 ) );

  /* Unrecognized version */
  v1_buf[  0 ] = (uchar)0x82;
  FD_TEST( !fd_keyguard_payload_match( v1_buf, msg_sz, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  v1_buf[  0 ] = (uchar)0x81;

  /* No signatures */
  v1_buf[  1 ] = (uchar)0;
  FD_TEST( !fd_keyguard_payload_match( v1_buf, msg_sz, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  v1_buf[  1 ] = (uchar)1;

  /* Too many instructions */
  v1_buf[ 40 ] = (uchar)( FD_TXN_INSTR_MAX+1UL );
  FD_TEST( !fd_keyguard_payload_match( v1_buf, msg_sz, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  v1_buf[ 40 ] = (uchar)0;

  /* Too many addresses */
  v1_buf[ 41 ] = (uchar)( FD_TXN_ACCT_ADDR_MAX+1UL );
  FD_TEST( !fd_keyguard_payload_match( v1_buf, msg_sz, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );

  /* More signers than addresses */
  v1_buf[ 41 ] = (uchar)0;
  FD_TEST( !fd_keyguard_payload_match( v1_buf, msg_sz, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  v1_buf[ 41 ] = (uchar)1;

  FD_TEST( fd_keyguard_payload_match( v1_buf, msg_sz, FD_KEYGUARD_SIGN_TYPE_ED25519 )
           ==FD_KEYGUARD_PAYLOAD_TXN );
}

/* Every Alpenglow VotePayloadToSign the votor can actually produce must
   be matched and authorized, and nothing else must be.  Built with the
   real ag_vote_payload_bytes_to_sign rather than a hand-written table:
   the AG_VOTE_TYPE_* values are NOT in wire-tag order (FINAL is 1,
   NOTAR_FALLBACK is 3), so a table gets it wrong. */

static void
test_ag_vote_payload( void ) {
  static uint const kinds[] = {
    AG_VOTE_TYPE_NOTAR, AG_VOTE_TYPE_FINAL, AG_VOTE_TYPE_SKIP,
    AG_VOTE_TYPE_NOTAR_FALLBACK, AG_VOTE_TYPE_SKIP_FALLBACK
  };

  fd_keyguard_authority_t authority;
  memset( &authority, 0xAA, sizeof(authority) );

  fd_hash_t h;
  memset( h.uc, 0x5A, sizeof(h) );

  for( ulong i=0UL; i<sizeof(kinds)/sizeof(kinds[0]); i++ ) {
    uchar buf[ AG_VOTE_PAYLOAD_MAX ];
    ulong sz = ag_vote_payload_bytes_to_sign( buf, kinds[i], 1234UL, &h, (ushort)0x5a5a );

    FD_TEST( fd_keyguard_payload_match( buf, sz, FD_KEYGUARD_SIGN_TYPE_BLS12_381 )==FD_KEYGUARD_PAYLOAD_AG_VOTE );
    FD_TEST( fd_keyguard_payload_authorize( &authority, buf, sz, FD_KEYGUARD_ROLE_VOTOR, FD_KEYGUARD_SIGN_TYPE_BLS12_381 ) );

    /* wrong sign type, wrong length, and unknown tag are all rejected */
    FD_TEST( !fd_keyguard_payload_match( buf, sz,     FD_KEYGUARD_SIGN_TYPE_ED25519    ) );
    FD_TEST( !fd_keyguard_payload_match( buf, sz-1UL, FD_KEYGUARD_SIGN_TYPE_BLS12_381  ) );
    FD_TEST( !fd_keyguard_payload_match( buf, sz+1UL, FD_KEYGUARD_SIGN_TYPE_BLS12_381  ) );

    uchar bad[ AG_VOTE_PAYLOAD_MAX ];
    memcpy( bad, buf, sz );
    bad[ 0 ] = 0;  FD_TEST( !fd_keyguard_payload_match( bad, sz, FD_KEYGUARD_SIGN_TYPE_BLS12_381 ) );
    bad[ 0 ] = 6;  FD_TEST( !fd_keyguard_payload_match( bad, sz, FD_KEYGUARD_SIGN_TYPE_BLS12_381 ) );
  }

  /* the BLS sign type must not open a door for any identity-key payload */
  uchar zero[ 128 ];
  memset( zero, 0, sizeof(zero) );
  FD_TEST( !fd_keyguard_payload_match( zero, sizeof(zero), FD_KEYGUARD_SIGN_TYPE_BLS12_381 ) );
}

void
test_vote_txn_oob( void ) {
  uchar data[172];
  memset( data, 0, sizeof(data) );

  data[0] = 2;    /* signer_cnt */
  data[1] = 1;    /* ro_signed_cnt = signer_cnt - 1 */
  data[2] = 1;    /* ro_unsigned_cnt */
  data[3] = 4;    /* acc_cnt (compact_u16, 1 byte) */

  fd_keyguard_authority_t authority;
  memset( &authority, 0xAA, sizeof(authority) );
  memcpy( data + 4, authority.identity_pubkey, 32 );

  /* account 3, vote program id */
  uchar vote_prog_id[32] = {
    0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb,
    0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd, 0xb3,
    0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc,
    0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00
  };
  memcpy( data + 100, vote_prog_id, 32 );

  /* recent blockhash */

  data[164] = 1;  /* instr_cnt = 1 (compact_u16, 1 byte) */
  data[165] = 3;  /* index of vote program = acc_cnt - 1 */
  data[166] = 2;  /* compact_u16 = 2, 1 byte */

  /* account indices for instruction (offsets 167, 168) */
  data[167] = 0;
  data[168] = 1;

  data[169] = 0x80;  /* bit 7 set -> need at least 2 bytes */
  data[170] = 0x80;  /* bit 7 set -> need 3 bytes */
  data[171] = 0x01;  /* non-zero, upper bits clear -> valid 3-byte cu16 */

  int res = fd_keyguard_payload_authorize(
      &authority, data, sizeof(data),
      FD_KEYGUARD_ROLE_TXSEND,
      FD_KEYGUARD_SIGN_TYPE_ED25519 );

  (void)res;
}

int
main( int     argc,
      char ** argv ) {
  fd_log_private_boot( &argc, &argv );
  test_vote_txn_oob();
  test_txn_v1_match();
  test_ag_vote_payload();
  FD_LOG_NOTICE(( "pass" ));
  return 0;
}
