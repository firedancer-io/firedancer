#include "fd_keyguard.h"

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
  FD_LOG_NOTICE(( "pass" ));
  return 0;
}
