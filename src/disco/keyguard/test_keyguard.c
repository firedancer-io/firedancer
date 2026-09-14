#include "fd_keyguard.h"
#include "fd_keyguard_bls.h"
#include "../../ballet/txn/fd_txn.h"

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
  uchar skip [ FD_KEYGUARD_BLS_PUBKEY_SZ+11UL ] = {0};
  uchar notar[ FD_KEYGUARD_BLS_PUBKEY_SZ+43UL ] = {0};
  skip [ FD_KEYGUARD_BLS_PUBKEY_SZ ] = 3; /* skip */
  notar[ FD_KEYGUARD_BLS_PUBKEY_SZ ] = 1; /* notar */

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
  /* selector is mandatory */
  FD_TEST( !fd_keyguard_payload_authorize( &authority, skip+FD_KEYGUARD_BLS_PUBKEY_SZ, 11UL, FD_KEYGUARD_ROLE_VOTOR, FD_KEYGUARD_SIGN_TYPE_BLS ) );
  /* bad tag */
  skip[ FD_KEYGUARD_BLS_PUBKEY_SZ ] = 6;
  FD_TEST( !fd_keyguard_payload_authorize( &authority, skip,  sizeof(skip),  FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_BLS     ) );
  skip[ FD_KEYGUARD_BLS_PUBKEY_SZ ] = 0;
  FD_TEST( !fd_keyguard_payload_authorize( &authority, skip,  sizeof(skip),  FD_KEYGUARD_ROLE_VOTOR,  FD_KEYGUARD_SIGN_TYPE_BLS     ) );
}

static void
test_bls_key_lookup( void ) {
  fd_sha512_t sha[1];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha ) ) );

  /* Generated independently by Agave 4.1.0 `solana-keygen
     bls_pubkey`.  The keypair is private seed followed by Ed25519
     public key. */
  static uchar const agave_keypair[ 64 ] = {
    149, 138, 120, 246, 229, 211,  77, 206, 163,  78,  57, 172, 248,  93, 205, 236,
     20,  90,   0,   7, 157, 121,  25,  54, 212, 189,  91,  26, 164, 253, 110, 203,
     51, 129, 127, 165, 142,   4, 248, 195,  91,  93,  33,  19,  91, 130, 175,   9,
    229, 142, 180, 156,  23, 173, 190, 249, 207,   5, 181,  31, 251,  76,   2, 208
  };
  static uchar const expected_selector[ FD_KEYGUARD_BLS_PUBKEY_SZ ] = {
    149, 157, 254, 148, 170,  68,   3,  78,  50,  10,   2, 167,  49,  36, 104, 157,
    220, 152, 181, 228,  47, 146, 210, 186, 254, 247,  17,  30, 130, 234, 224, 119,
    213, 125,  40, 244,  22,  34,  81,   8, 254, 105, 239,  43, 186, 178, 113,   1
  };

  fd_keyguard_bls_key_t keys[ 2 ];
  uchar other_private_key[ 32 ]; memset( other_private_key, 0x11, sizeof(other_private_key) );
  uchar other_public_key [ 32 ]; fd_ed25519_public_from_private( other_public_key, other_private_key, sha );
  fd_keyguard_bls_key_derive( &keys[ 0 ], other_public_key,     other_private_key, sha );
  fd_keyguard_bls_key_derive( &keys[ 1 ], agave_keypair+32UL,  agave_keypair,     sha );
  FD_TEST( !memcmp( keys[ 1 ].public_key, expected_selector, sizeof(expected_selector) ) );

  fd_bls_pub_t expected_public[1];
  FD_TEST( !fd_bls_pub_de( expected_public, expected_selector, sizeof(expected_selector) ) );

  fd_keyguard_bls_key_t const * selected =
      fd_keyguard_bls_key_query( keys, 2UL, expected_selector );
  FD_TEST( selected==&keys[ 1 ] );

  uchar payload[ 11 ] = { 3 /* skip */ };
  fd_bls_sig_t sig[1];
  fd_bls_sec_sign( &selected->secret_key, payload, sizeof(payload), sig );
  FD_TEST(  fd_bls_agg_verify( payload, sizeof(payload), expected_public, sig ) );

  fd_bls_pub_t wrong_public[1];
  FD_TEST( !fd_bls_pub_de( wrong_public, keys[ 0 ].public_key, FD_KEYGUARD_BLS_PUBKEY_SZ ) );
  FD_TEST( !fd_bls_agg_verify( payload, sizeof(payload), wrong_public, sig ) );

  uchar unknown_selector[ FD_KEYGUARD_BLS_PUBKEY_SZ ];
  memcpy( unknown_selector, expected_selector, sizeof(unknown_selector) );
  unknown_selector[ 0 ] ^= 1U;
  FD_TEST( !fd_keyguard_bls_key_query( keys, 2UL, unknown_selector ) );
}

static void
test_bls_request_signing( void ) {
  fd_sha512_t sha[1];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha ) ) );
  uchar private_key[ 32 ]; memset( private_key, 0x33, sizeof(private_key) );
  uchar public_key [ 32 ]; fd_ed25519_public_from_private( public_key, private_key, sha );
  fd_keyguard_bls_key_t key[1];
  fd_keyguard_bls_key_derive( key, public_key, private_key, sha );

  uchar payload[ 43 ];
  for( ulong i=0UL; i<sizeof(payload); i++ ) payload[ i ] = (uchar)(0x20UL+i);
  payload[ 0 ] = 1; /* notar */

  uchar request[ FD_KEYGUARD_BLS_PUBKEY_SZ+sizeof(payload) ];
  ulong request_sz = fd_keyguard_bls_request_encode( request, key->public_key, payload, sizeof(payload) );
  FD_TEST( request_sz==sizeof(request) );
  FD_TEST( !memcmp( request, key->public_key, FD_KEYGUARD_BLS_PUBKEY_SZ ) );
  FD_TEST( !memcmp( request+FD_KEYGUARD_BLS_PUBKEY_SZ, payload, sizeof(payload) ) );
  fd_keyguard_authority_t authority = {0};
  FD_TEST( fd_keyguard_payload_authorize( &authority, request, request_sz, FD_KEYGUARD_ROLE_VOTOR, FD_KEYGUARD_SIGN_TYPE_BLS ) );

  fd_bls_sig_t sig[1];
  FD_TEST( fd_keyguard_bls_sign_request( key, 1UL, request, request_sz, sig ) );

  fd_bls_pub_t bls_public_key[1];
  FD_TEST( !fd_bls_pub_de( bls_public_key, key->public_key, FD_KEYGUARD_BLS_PUBKEY_SZ ) );
  FD_TEST(  fd_bls_agg_verify( payload, sizeof(payload), bls_public_key, sig ) );
  FD_TEST( !fd_bls_agg_verify( request, request_sz, bls_public_key, sig ) );

  request[ 0 ] ^= 1U;
  FD_TEST( !fd_keyguard_bls_sign_request( key, 1UL, request, request_sz, sig ) );
  FD_TEST( !fd_keyguard_bls_sign_request( key, 1UL, request, FD_KEYGUARD_BLS_PUBKEY_SZ-1UL, sig ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_log_private_boot( &argc, &argv );
  test_vote_txn_oob();
  test_txn_v1_match();
  test_ag_vote_authorize();
  test_bls_key_lookup();
  test_bls_request_signing();
  FD_LOG_NOTICE(( "pass" ));
  return 0;
}
