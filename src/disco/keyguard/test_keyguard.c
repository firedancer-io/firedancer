#include "fd_keyguard.h"
#include "../../alpenglow/consensus/ag_vote.h"

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
  test_ag_vote_payload();
  FD_LOG_NOTICE(( "pass" ));
  return 0;
}
