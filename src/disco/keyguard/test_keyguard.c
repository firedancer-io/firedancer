#include "fd_keyguard.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../flamenco/gossip/fd_gossip_value.h"
#include "../../discof/repair/fd_repair.h"
#include "../../waltz/tls/fd_tls.h"

static uchar v1_buf [ FD_TXN_MTU    ];
static uchar v1_txn [ FD_TXN_MAX_SZ ];

static ulong
build_txn_v1( uchar * buf,
              ulong   sig_cnt,
              ulong   num_addr,
              ulong   instr_cnt,
              ulong * msg_sz );

/* test_failov_message: only the failov role gets the exact member
   certificate message signed, and it also gets a TLS
   CertificateVerify signed. */

static void
test_failov_message( void ) {
  fd_keyguard_authority_t authority = {0};
  uchar                   msg[ FD_KEYGUARD_MEMBER_CERT_MSG_SZ ];
  fd_memcpy( msg, FD_KEYGUARD_MEMBER_CERT_PREFIX, FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ );
  fd_memset( msg+FD_KEYGUARD_MEMBER_CERT_PREFIX_SZ, 0x5a, 32UL );

  FD_TEST( fd_keyguard_payload_match( msg, sizeof(msg), FD_KEYGUARD_SIGN_TYPE_ED25519 )==FD_KEYGUARD_PAYLOAD_FAILOV );
  FD_TEST( fd_keyguard_payload_authorize( &authority, msg, sizeof(msg), FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );

  /* Only the exact prefix, size and sign type are a member certificate. */
  FD_TEST( !fd_keyguard_payload_match( msg, sizeof(msg), FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 ) );
  FD_TEST( !(fd_keyguard_payload_match( msg, sizeof(msg)-1UL, FD_KEYGUARD_SIGN_TYPE_ED25519 ) & FD_KEYGUARD_PAYLOAD_FAILOV) );
  FD_TEST( !(fd_keyguard_payload_match( msg+1, sizeof(msg)-1UL, FD_KEYGUARD_SIGN_TYPE_ED25519 ) & FD_KEYGUARD_PAYLOAD_FAILOV) );

  /* Longer payloads with the prefix are not a member certificate either. */
  uchar longer[ FD_KEYGUARD_MEMBER_CERT_MSG_SZ+32UL ];
  fd_memcpy( longer, msg, sizeof(msg) );
  fd_memset( longer+sizeof(msg), 0x5a, 32UL );
  for( ulong sz=sizeof(msg)+1UL; sz<=sizeof(longer); sz++ ) {
    FD_TEST( !(fd_keyguard_payload_match( longer, sz, FD_KEYGUARD_SIGN_TYPE_ED25519 ) & FD_KEYGUARD_PAYLOAD_FAILOV) );
    FD_TEST( !fd_keyguard_payload_authorize( &authority, longer, sz, FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  }
  msg[ 0 ] ^= 1;
  FD_TEST( !(fd_keyguard_payload_match( msg, sizeof(msg), FD_KEYGUARD_SIGN_TYPE_ED25519 ) & FD_KEYGUARD_PAYLOAD_FAILOV) );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, msg, sizeof(msg), FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  msg[ 0 ] ^= 1;

  /* Client and server CertificateVerify, with the exact prefix and size. */
  uchar cv[ FD_TLS_CV_SIGN_SZ ];
  fd_memcpy( cv, fd_tls13_cli_sign_prefix, sizeof(fd_tls13_cli_sign_prefix) );
  fd_memset( cv+sizeof(fd_tls13_cli_sign_prefix), 0x5a, 32UL );
  FD_TEST(  fd_keyguard_payload_authorize( &authority, cv, sizeof(cv), FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, cv, sizeof(cv), FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 ) );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, cv, sizeof(cv)-1UL, FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  fd_memcpy( cv, fd_tls13_srv_sign_prefix, sizeof(fd_tls13_srv_sign_prefix) );
  FD_TEST(  fd_keyguard_payload_authorize( &authority, cv, sizeof(cv), FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  cv[ 0 ] ^= 1;
  FD_TEST( !fd_keyguard_payload_authorize( &authority, cv, sizeof(cv), FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );

  /* No other role signs a member certificate, and the failov role signs
     it only as Ed25519. */
  for( int role=0; role<FD_KEYGUARD_ROLE_CNT; role++ ) {
    if( role==FD_KEYGUARD_ROLE_FAILOV ) continue;
    FD_TEST( !fd_keyguard_payload_authorize( &authority, msg, sizeof(msg), role, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  }
  FD_TEST( !fd_keyguard_payload_authorize( &authority, msg, sizeof(msg), FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 ) );

  /* The failov role signs nothing else: a ping, a pong, a shred root, a
     transaction or a CertificateVerify of another size. */
  uchar other[ 162 ];
  fd_memset( other, 0x5a, sizeof(other) );
  fd_memcpy( other, "SOLANA_PING_PONG", 16UL );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, other, 32UL, FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, other, 48UL, FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 ) );
  fd_memset( other, 0x5a, 32UL );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, other, 32UL, FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
  ulong msg_sz;
  build_txn_v1( v1_buf, 1UL, 1UL, 0UL, &msg_sz );
  FD_TEST( fd_keyguard_payload_match( v1_buf, msg_sz, FD_KEYGUARD_SIGN_TYPE_ED25519 )==FD_KEYGUARD_PAYLOAD_TXN );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, v1_buf, msg_sz, FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  fd_memcpy( other, fd_tls13_cli_sign_prefix, sizeof(fd_tls13_cli_sign_prefix) );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, other, 146UL, FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, other, 162UL, FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
}

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

static void
test_ag_vote_authorize( void ) {
  fd_keyguard_authority_t authority = {0};
  uchar skip[ 11 ]  = { 3 /* skip */ };
  uchar notar[ 43 ] = { 1 /* notar */ };

  FD_TEST(  fd_keyguard_payload_authorize( &authority, skip,  sizeof(skip),  FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_BLS     ) );
  FD_TEST(  fd_keyguard_payload_authorize( &authority, notar, sizeof(notar), FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_BLS     ) );
  /* wrong sign type */
  FD_TEST( !fd_keyguard_payload_authorize( &authority, skip,  sizeof(skip),  FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  /* wrong role */
  FD_TEST( !fd_keyguard_payload_authorize( &authority, skip,  sizeof(skip),  FD_KEYGUARD_ROLE_TXSEND, FD_KEYGUARD_SIGN_TYPE_BLS     ) );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, skip,  sizeof(skip),  FD_KEYGUARD_ROLE_GOSSIP, FD_KEYGUARD_SIGN_TYPE_BLS     ) );
  /* hash-carrying tag with the short size and vice versa */
  FD_TEST( !fd_keyguard_payload_authorize( &authority, notar, sizeof(skip),  FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_BLS     ) );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, skip,  sizeof(notar), FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_BLS     ) );
  /* bad tag */
  skip[ 0 ] = 6;
  FD_TEST( !fd_keyguard_payload_authorize( &authority, skip,  sizeof(skip),  FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_BLS     ) );
  skip[ 0 ] = 0;
  FD_TEST( !fd_keyguard_payload_authorize( &authority, skip,  sizeof(skip),  FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_BLS     ) );
}

static void
test_bls_pubkey_authorize( void ) {
  fd_keyguard_authority_t authority = {0};
  uchar query[ sizeof(ulong)+1UL ] = {0}; /* authority index */

  FD_TEST( fd_keyguard_payload_match( query, sizeof(ulong), FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY )==FD_KEYGUARD_PAYLOAD_BLS_PUBKEY );
  FD_TEST(  fd_keyguard_payload_authorize( &authority, query, sizeof(ulong),     FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY ) );
  /* wrong sign type */
  FD_TEST( !fd_keyguard_payload_authorize( &authority, query, sizeof(ulong),     FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_BLS        ) );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, query, sizeof(ulong),     FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_ED25519    ) );
  /* wrong role */
  FD_TEST( !fd_keyguard_payload_authorize( &authority, query, sizeof(ulong),     FD_KEYGUARD_ROLE_TXSEND, FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY ) );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, query, sizeof(ulong),     FD_KEYGUARD_ROLE_GOSSIP, FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY ) );
  /* wrong size */
  FD_TEST( !fd_keyguard_payload_authorize( &authority, query, sizeof(ulong)-1UL, FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY ) );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, query, sizeof(ulong)+1UL, FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY ) );
  /* authority index is the identity (ULONG_MAX) or in [0,16) */
  FD_STORE( ulong, query, 15UL );
  FD_TEST(  fd_keyguard_payload_authorize( &authority, query, sizeof(ulong),     FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY ) );
  FD_STORE( ulong, query, ULONG_MAX );
  FD_TEST(  fd_keyguard_payload_authorize( &authority, query, sizeof(ulong),     FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY ) );
  FD_STORE( ulong, query, 16UL );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, query, sizeof(ulong),     FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY ) );
  FD_STORE( ulong, query, ULONG_MAX-1UL );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, query, sizeof(ulong),     FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_BLS_PUBKEY ) );
}

static void
test_tower_authorize( void ) {
  /* The smallest body the tower tile writes: prefix, vote state with
     one vote and no root, TowerSync with one lockout, last_timestamp.
     The largest adds 30 votes, a root, a timestamp, and has 31
     lockouts with 10 byte offsets instead of one with a 1 byte offset. */
  ulong const min_sz = 48UL + (65UL+8UL+12UL+1UL+8UL+32UL*48UL+8UL+1UL+8UL+16UL) + (4UL+74UL+2UL) + 16UL;
  ulong const max_sz = min_sz + 30UL*12UL + 8UL + 8UL + (31UL*11UL-2UL);

  static uchar body[ FD_KEYGUARD_SIGN_REQ_MTU ];
  fd_keyguard_authority_t authority;
  memset( &authority, 0xAA, sizeof(authority) );
  memcpy( body, authority.identity_pubkey, 32UL );
  FD_STORE( ulong,  body+32UL,  8UL     ); /* threshold_depth */
  FD_STORE( double, body+40UL,  2.0/3.0 ); /* threshold_size */
  FD_STORE( ulong,  body+113UL, 1UL     ); /* votes_cnt */

  FD_TEST(  fd_keyguard_payload_authorize( &authority, body, min_sz,       FD_KEYGUARD_ROLE_TOWER,  FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
  FD_TEST(  fd_keyguard_payload_authorize( &authority, body, max_sz,       FD_KEYGUARD_ROLE_TOWER,  FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
  /* too small for a Tower1_14_11 body, larger than the tower tile writes */
  FD_TEST( !fd_keyguard_payload_authorize( &authority, body, min_sz-1UL,   FD_KEYGUARD_ROLE_TOWER,  FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, body, max_sz+1UL,   FD_KEYGUARD_ROLE_TOWER,  FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
  /* wrong sign type */
  FD_TEST( !fd_keyguard_payload_authorize( &authority, body, min_sz,       FD_KEYGUARD_ROLE_TOWER,  FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 ) );
  /* wrong role */
  FD_TEST( !fd_keyguard_payload_authorize( &authority, body, min_sz,       FD_KEYGUARD_ROLE_TXSEND, FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, body, min_sz,       FD_KEYGUARD_ROLE_GOSSIP, FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
  /* not our identity, threshold_depth, threshold_size, the zeroed vote
     state node_pubkey, authorized_withdrawer and commission, votes_cnt */
  ulong const flip[ 6 ] = { 31UL, 32UL, 40UL, 48UL, 112UL, 113UL };
  for( ulong i=0UL; i<6UL; i++ ) {
    body[ flip[ i ] ] ^= (uchar)1;
    FD_TEST( !fd_keyguard_payload_authorize( &authority, body, min_sz,     FD_KEYGUARD_ROLE_TOWER,  FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
    body[ flip[ i ] ] ^= (uchar)1;
  }
  /* 1 to 31 votes */
  FD_STORE( ulong, body+113UL, 31UL );
  FD_TEST(  fd_keyguard_payload_authorize( &authority, body, min_sz,       FD_KEYGUARD_ROLE_TOWER,  FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
  FD_STORE( ulong, body+113UL, 32UL );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, body, min_sz,       FD_KEYGUARD_ROLE_TOWER,  FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
  FD_STORE( ulong, body+113UL, 1UL );
  /* an identity that also reads as a legacy txn header */
  uchar const txn_hdr[ 4 ] = { 1, 0, 0, 1 };
  memcpy( authority.identity_pubkey, txn_hdr, 4UL );
  memcpy( body,                      txn_hdr, 4UL );
  FD_TEST(  fd_keyguard_payload_authorize( &authority, body, min_sz,       FD_KEYGUARD_ROLE_TOWER,  FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
}

static void
test_tower_match( void ) {
  /* The identity at the start of a tower body can read as the header of
     another payload type.  Those types fit in a packet and a tower body
     does not, so a tower body only matches the tower type. */

  ulong const min_sz = 48UL + (65UL+8UL+12UL+1UL+8UL+32UL*48UL+8UL+1UL+8UL+16UL) + (4UL+74UL+2UL) + 16UL;
  static uchar body[ FD_KEYGUARD_SIGN_REQ_MTU ];
  FD_STORE( ulong,  body+32UL,  8UL     ); /* threshold_depth */
  FD_STORE( double, body+40UL,  2.0/3.0 ); /* threshold_size */
  FD_STORE( ulong,  body+113UL, 1UL     ); /* votes_cnt */

  uint  const hdr [ 3 ] = { 0x01000001U /* legacy txn, 1 signer, 1 account */, FD_GOSSIP_VALUE_VOTE,       FD_REPAIR_KIND_SHRED       };
  ulong const type[ 3 ] = { FD_KEYGUARD_PAYLOAD_TXN,                           FD_KEYGUARD_PAYLOAD_GOSSIP, FD_KEYGUARD_PAYLOAD_REPAIR };
  ulong const max [ 3 ] = { FD_TXN_MTU_V0,                                     FD_GOSSIP_MTU,              FD_REPAIR_MAX_PREIMAGE_SZ  };
  for( ulong i=0UL; i<3UL; i++ ) {
    FD_STORE( uint, body, hdr[ i ] );
    FD_TEST(    fd_keyguard_payload_match( body, min_sz,       FD_KEYGUARD_SIGN_TYPE_ED25519 )==FD_KEYGUARD_PAYLOAD_TOWER );
    FD_TEST(    fd_keyguard_payload_match( body, max[ i ],     FD_KEYGUARD_SIGN_TYPE_ED25519 ) & type[ i ]                );
    FD_TEST( !( fd_keyguard_payload_match( body, max[ i ]+1UL, FD_KEYGUARD_SIGN_TYPE_ED25519 ) & type[ i ] )              );
  }

  /* prune data is 106 bytes plus 32 per prune, the prune count is at
     offset 58, in the zeroed vote state of a tower body */
  FD_STORE( ulong, body, 18UL );
  memcpy( body+8UL, "\xffSOLANA_PRUNE_DATA", 18UL );
  FD_TEST(    fd_keyguard_payload_match( body, 106UL+54UL*32UL, FD_KEYGUARD_SIGN_TYPE_ED25519 )==FD_KEYGUARD_PAYLOAD_TOWER );
  FD_STORE( ulong, body+58UL, 35UL );
  FD_TEST(    fd_keyguard_payload_match( body, 106UL+35UL*32UL, FD_KEYGUARD_SIGN_TYPE_ED25519 ) & FD_KEYGUARD_PAYLOAD_PRUNE  );
  FD_STORE( ulong, body+58UL, 36UL );
  FD_TEST( !( fd_keyguard_payload_match( body, 106UL+36UL*32UL, FD_KEYGUARD_SIGN_TYPE_ED25519 ) & FD_KEYGUARD_PAYLOAD_PRUNE ) );
}

static void
test_vote_history_authorize( void ) {
  /* The smallest VoteHistory body: identity, nine empty collections and
     root.  The largest the votor writes fills a 32688 byte file. */
  ulong const min_sz = 32UL + 9UL*8UL + 8UL;
  ulong const max_sz = 32688UL - (4UL+64UL+8UL);

  static uchar body[ FD_KEYGUARD_SIGN_REQ_MTU ];
  fd_keyguard_authority_t authority;
  memset( &authority, 0xAA, sizeof(authority) );
  memcpy( body, authority.identity_pubkey, 32UL );

  FD_TEST(  fd_keyguard_payload_match( body, min_sz,     FD_KEYGUARD_SIGN_TYPE_ED25519 )==FD_KEYGUARD_PAYLOAD_VOTE_HISTORY );
  FD_TEST( !fd_keyguard_payload_match( body, min_sz-1UL, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  /* a voted slot only fits with 8 more bytes */
  FD_STORE( ulong, body+32UL, 1UL );
  FD_TEST( !fd_keyguard_payload_match( body, min_sz,     FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  FD_TEST(  fd_keyguard_payload_match( body, min_sz+8UL, FD_KEYGUARD_SIGN_TYPE_ED25519 )==FD_KEYGUARD_PAYLOAD_VOTE_HISTORY );
  FD_STORE( ulong, body+32UL, 0UL );
  FD_TEST(  fd_keyguard_payload_authorize( &authority, body, min_sz, FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
  FD_TEST(  fd_keyguard_payload_authorize( &authority, body, max_sz, FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
  /* wrong sign type, wrong role, not our identity */
  FD_TEST( !fd_keyguard_payload_authorize( &authority, body, min_sz, FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 ) );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, body, min_sz, FD_KEYGUARD_ROLE_TOWER,  FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, body, min_sz, FD_KEYGUARD_ROLE_GOSSIP, FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
  body[ 31 ] ^= (uchar)1;
  FD_TEST( !fd_keyguard_payload_authorize( &authority, body, min_sz, FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
  body[ 31 ] ^= (uchar)1;

  /* A payload of another type is never a vote history, even with our
     identity in front, here a tower body */
  FD_STORE( ulong,  body+32UL,  8UL     ); /* threshold_depth */
  FD_STORE( double, body+40UL,  2.0/3.0 ); /* threshold_size */
  FD_STORE( ulong,  body+113UL, 1UL     ); /* votes_cnt */
  FD_TEST(  fd_keyguard_payload_match( body, 1807UL, FD_KEYGUARD_SIGN_TYPE_ED25519 )==FD_KEYGUARD_PAYLOAD_TOWER );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, body, 1807UL, FD_KEYGUARD_ROLE_VOTOR, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );

  /* An identity whose first bytes read as a legacy txn message header
     (one signer, three accounts) makes a vote history body also match a
     txn, or even be a whole txn message, like these 133 bytes: three
     accounts, a blockhash and no instructions.  The votor role still
     signs it, because the fee payer key of that txn starts with bytes 4
     to 31 of our identity. */
  uchar const txn_hdr[ 4 ] = { 1, 0, 0, 3 };
  memcpy( authority.identity_pubkey, txn_hdr, 4UL );
  memcpy( body, authority.identity_pubkey, 32UL );
  memset( body+32UL, 0, 133UL-32UL );
  FD_TEST(  fd_keyguard_payload_match( body, min_sz, FD_KEYGUARD_SIGN_TYPE_ED25519 )==(FD_KEYGUARD_PAYLOAD_TXN|FD_KEYGUARD_PAYLOAD_VOTE_HISTORY) );
  FD_TEST(  fd_keyguard_payload_authorize( &authority, body, min_sz, FD_KEYGUARD_ROLE_VOTOR, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  FD_TEST(  fd_keyguard_payload_match( body, 133UL,  FD_KEYGUARD_SIGN_TYPE_ED25519 )==(FD_KEYGUARD_PAYLOAD_TXN|FD_KEYGUARD_PAYLOAD_VOTE_HISTORY) );
  FD_TEST(  fd_keyguard_payload_authorize( &authority, body, 133UL,  FD_KEYGUARD_ROLE_VOTOR, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_log_private_boot( &argc, &argv );
  test_vote_txn_oob();
  test_txn_v1_match();
  test_ag_vote_authorize();
  test_bls_pubkey_authorize();
  test_tower_authorize();
  test_tower_match();
  test_vote_history_authorize();
  test_failov_message();
  FD_LOG_NOTICE(( "pass" ));
  return 0;
}
