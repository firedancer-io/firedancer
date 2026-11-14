#include "fd_keyguard.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../flamenco/gossip/fd_gossip_value.h"
#include "../../disco/repair/fd_repair_serde.h"
#include "../../waltz/tls/fd_tls.h"

static uchar v1_buf [ FD_TXN_MTU    ];
static uchar v1_txn [ FD_TXN_MAX_SZ ];

static ulong
build_txn_v1( uchar * buf,
              ulong   sig_cnt,
              ulong   num_addr,
              ulong   instr_cnt,
              ulong * msg_sz );

/* test_failov_message: the failov role gets the exact admission
   proof message and a TLS CertificateVerify signed. */

static void
test_failov_message( void ) {
  fd_keyguard_authority_t authority = {0};
  uchar                   msg[ FD_KEYGUARD_FAILOVER_PROOF_SZ ];
  fd_memcpy( msg, FD_KEYGUARD_FAILOVER_CLIENT_DOMAIN, FD_KEYGUARD_FAILOVER_DOMAIN_SZ );
  fd_memset( msg+FD_KEYGUARD_FAILOVER_DOMAIN_SZ, 0x5a, sizeof(msg)-FD_KEYGUARD_FAILOVER_DOMAIN_SZ );
  FD_TEST( fd_keyguard_payload_match( msg, sizeof(msg), FD_KEYGUARD_SIGN_TYPE_ED25519 )==FD_KEYGUARD_PAYLOAD_FAILOV );
  FD_TEST( fd_keyguard_payload_authorize( &authority, msg, sizeof(msg), FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  msg[0] ^= 1;
  FD_TEST( !fd_keyguard_payload_authorize( &authority, msg, sizeof(msg), FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );

  uchar cv[ FD_TLS_CV_SIGN_SZ ];
  fd_memcpy( cv, fd_tls13_cli_sign_prefix, sizeof(fd_tls13_cli_sign_prefix) );
  fd_memset( cv+sizeof(fd_tls13_cli_sign_prefix), 0x5a, 32UL );
  FD_TEST( fd_keyguard_payload_authorize( &authority, cv, sizeof(cv), FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  fd_memcpy( cv, fd_tls13_srv_sign_prefix, sizeof(fd_tls13_srv_sign_prefix) );
  FD_TEST( fd_keyguard_payload_authorize( &authority, cv, sizeof(cv), FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, cv, sizeof(cv), FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 ) );
  cv[0] ^= 1;
  FD_TEST( !fd_keyguard_payload_authorize( &authority, cv, sizeof(cv), FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );

  /* No other role signs an admission proof, and the failov role signs
     it only as Ed25519. */
  msg[0] ^= 1;
  for( int role=0; role<FD_KEYGUARD_ROLE_CNT; role++ ) {
    if( role==FD_KEYGUARD_ROLE_FAILOV ) continue;
    FD_TEST( !fd_keyguard_payload_authorize( &authority, msg, sizeof(msg), role, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  }
  FD_TEST( !fd_keyguard_payload_authorize( &authority, msg, sizeof(msg), FD_KEYGUARD_ROLE_FAILOV, FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 ) );

  /* The failov role signs nothing else, not a ping, a pong, a shred
     root, a transaction or a CertificateVerify of another size. */
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
test_vote_history_authorize( void ) {
  /* The only VoteHistory body the votor writes: identity, nine empty
     collections and root. */
  ulong const sz = 32UL + 9UL*8UL + 8UL;

  static uchar body[ FD_KEYGUARD_SIGN_REQ_MTU ];
  fd_keyguard_authority_t authority;
  memset( &authority, 0xAA, sizeof(authority) );
  memcpy( body, authority.identity_pubkey, 32UL );
  FD_STORE( ulong, body+sz-8UL, 1007UL ); /* root, any value */

  FD_TEST(  fd_keyguard_payload_match( body, sz,     FD_KEYGUARD_SIGN_TYPE_ED25519 )==FD_KEYGUARD_PAYLOAD_VOTE_HISTORY );
  FD_TEST( !fd_keyguard_payload_match( body, sz-1UL, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  FD_TEST( !fd_keyguard_payload_match( body, sz+1UL, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  /* a non-empty collection, even one that would fit */
  for( ulong i=0UL; i<9UL; i++ ) {
    FD_STORE( ulong, body+32UL+i*8UL, 1UL );
    FD_TEST( !( fd_keyguard_payload_match( body, sz,     FD_KEYGUARD_SIGN_TYPE_ED25519 ) & FD_KEYGUARD_PAYLOAD_VOTE_HISTORY ) );
    FD_TEST( !( fd_keyguard_payload_match( body, sz+8UL, FD_KEYGUARD_SIGN_TYPE_ED25519 ) & FD_KEYGUARD_PAYLOAD_VOTE_HISTORY ) );
    FD_STORE( ulong, body+32UL+i*8UL, 0UL );
  }
  FD_TEST(  fd_keyguard_payload_authorize( &authority, body, sz, FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
  /* wrong sign type, wrong role, not our identity */
  FD_TEST( !fd_keyguard_payload_authorize( &authority, body, sz, FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_SHA256_ED25519 ) );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, body, sz, FD_KEYGUARD_ROLE_GOSSIP, FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
  body[ 31 ] ^= (uchar)1;
  FD_TEST( !fd_keyguard_payload_authorize( &authority, body, sz, FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_ED25519        ) );
  body[ 31 ] ^= (uchar)1;

  /* An identity whose first bytes read as a legacy txn message header
     (one signer, three accounts) still makes the vote history body also
     match a txn, so the votor signs it.  The whole txn message of 133
     bytes it used to also sign is no longer a vote history. */
  uchar const txn_hdr[ 4 ] = { 1, 0, 0, 3 };
  memcpy( authority.identity_pubkey, txn_hdr, 4UL );
  memcpy( body, authority.identity_pubkey, 32UL );
  memset( body+32UL, 0, 133UL-32UL );
  FD_TEST(  fd_keyguard_payload_match( body, sz,    FD_KEYGUARD_SIGN_TYPE_ED25519 )==(FD_KEYGUARD_PAYLOAD_TXN|FD_KEYGUARD_PAYLOAD_VOTE_HISTORY) );
  FD_TEST(  fd_keyguard_payload_authorize( &authority, body, sz,    FD_KEYGUARD_ROLE_VOTOR, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
  FD_TEST(  fd_keyguard_payload_match( body, 133UL, FD_KEYGUARD_SIGN_TYPE_ED25519 )==FD_KEYGUARD_PAYLOAD_TXN );
  FD_TEST( !fd_keyguard_payload_authorize( &authority, body, 133UL, FD_KEYGUARD_ROLE_VOTOR, FD_KEYGUARD_SIGN_TYPE_ED25519 ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_log_private_boot( &argc, &argv );
  test_txn_v1_match();
  test_ag_vote_authorize();
  test_bls_pubkey_authorize();
  test_vote_history_authorize();
  test_failov_message();
  FD_LOG_NOTICE(( "pass" ));
  return 0;
}
