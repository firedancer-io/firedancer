#include "fd_alpen.h"
#include "../../ballet/hex/fd_hex.h"
#include "../../ballet/base58/fd_base58.h"

void
load_test_txn( uchar * tx, char * hex[], ulong hex_sz, ulong * tx_len ) {
  ulong hex_len = 0;
  for ( ulong i=0; i<hex_sz/sizeof(char *); i++ ) {
    hex_len += strlen(hex[i]);
  }
  *tx_len = hex_len / 2;

  hex_len = 0;
  for ( ulong i=0; i<hex_sz/sizeof(char *); i++ ) {
    ulong cur_len = strlen(hex[i]);
    fd_hex_decode( &tx[hex_len/2], hex[i], cur_len/2 );
    hex_len += cur_len;
  }
}

// REF ALPENGLOW VOTE: [2, 70, 142, 173, 21, 59, 101, 221, 75, 12, 173, 22, 227, 154, 64, 8, 93, 250, 13, 8, 32, 94, 175, 241, 104, 42, 125, 33, 83, 173, 231, 9, 30, 84, 95, 63, 192, 40, 155, 8, 222, 51, 67, 13, 221, 70, 91, 230, 128, 215, 204, 70, 217, 222, 103, 156, 45, 217, 206, 248, 121, 56, 104, 210, 7, 169, 90, 230, 249, 25, 26, 170, 172, 140, 197, 193, 74, 241, 153, 2, 82, 112, 102, 119, 86, 75, 205, 232, 194, 102, 255, 185, 201, 177, 229, 213, 74, 197, 34, 121, 209, 71, 201, 15, 158, 53, 7, 205, 93, 109, 136, 54, 135, 211, 61, 245, 147, 160, 18, 130, 180, 179, 166, 84, 10, 48, 205, 215, 6, 2, 0, 1, 3, 59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50, 21, 119, 29, 226, 67, 166, 58, 192, 72, 161, 139, 89, 218, 41, 180, 201, 87, 121, 248, 239, 198, 76, 100, 169, 61, 200, 136, 198, 55, 94, 238, 130, 78, 10, 53, 128, 15, 16, 8, 137, 25, 112, 248, 12, 126, 109, 7, 97, 72, 29, 152, 99, 27, 211, 124, 233, 196, 186, 79, 54, 172, 222, 197, 254, 12, 219, 166, 45, 77, 5, 37, 237, 177, 112, 71, 220, 17, 247, 199, 146, 238, 124, 248, 87, 34, 185, 33, 50, 42, 250, 41, 219, 249, 125, 31, 163, 232, 64, 176, 192, 130, 56, 125, 139, 110, 147, 63, 226, 31, 45, 1, 2, 2, 1, 1, 82, 8, 1, 32, 0, 0, 0, 0, 0, 0, 0, 67, 3, 203, 221, 92, 149, 170, 136, 186, 216, 176, 123, 123, 123, 160, 38, 167, 28, 147, 104, 36, 60, 91, 181, 119, 151, 203, 60, 134, 195, 194, 59, 0, 0, 0, 0, 0, 0, 0, 0, 97, 36, 119, 116, 252, 208, 227, 115, 100, 249, 21, 137, 217, 233, 174, 44, 123, 188, 83, 229, 231, 106, 92, 115, 43, 108, 149, 11, 159, 104, 32, 56]

static char *
ref_vote_0[] = {
  "02",
  "468ead153b65dd4b0cad16e39a40085dfa0d08205eaff1682a7d2153ade7091e",
  "545f3fc0289b08de33430ddd465be680d7cc46d9de679c2dd9cef8793868d207",
  "a95ae6f9191aaaac8cc5c14af1990252706677564bcde8c266ffb9c9b1e5d54a",
  "c52279d147c90f9e3507cd5d6d883687d33df593a01282b4b3a6540a30cdd706",
  "020001",
  "03",
  "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
  "b4c95779f8efc64c64a93dc888c6375eee824e0a35800f1008891970f80c7e6d",
  "0761481d98631bd37ce9c4ba4f36acdec5fe0cdba62d4d0525edb17047dc11f7",
  "c792ee7cf85722b921322afa29dbf97d1fa3e840b0c082387d8b6e933fe21f2d",
  "010202010152080120000000000000004303cbdd5c95aa88bad8b07b7b7ba026a71c9368243c5bb57797cb3c86c3c23b000000000000000061247774fcd0e37364f91589d9e9ae2c7bbc53e5e76a5c732b6c950b9f682038"
};

// REF ALPENGLOW VOTE: [2, 191, 102, 136, 95, 81, 175, 155, 197, 86, 234, 76, 53, 242, 227, 223, 224, 65, 61, 45, 124, 123, 24, 48, 166, 214, 255, 73, 230, 67, 235, 4, 77, 190, 245, 32, 254, 135, 58, 62, 172, 31, 81, 148, 53, 5, 141, 202, 117, 249, 215, 67, 236, 219, 52, 13, 248, 52, 113, 162, 145, 254, 209, 141, 11, 235, 180, 201, 130, 54, 191, 220, 228, 61, 184, 115, 24, 30, 166, 32, 88, 32, 245, 33, 97, 67, 173, 40, 46, 133, 67, 77, 122, 208, 80, 79, 212, 75, 32, 250, 208, 64, 119, 178, 220, 133, 43, 159, 25, 55, 34, 46, 136, 216, 128, 69, 137, 48, 72, 50, 208, 61, 155, 209, 150, 240, 154, 18, 10, 2, 0, 1, 3, 59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50, 21, 119, 29, 226, 67, 166, 58, 192, 72, 161, 139, 89, 218, 41, 180, 201, 87, 121, 248, 239, 198, 76, 100, 169, 61, 200, 136, 198, 55, 94, 238, 130, 78, 10, 53, 128, 15, 16, 8, 137, 25, 112, 248, 12, 126, 109, 7, 97, 72, 29, 152, 99, 27, 211, 124, 233, 196, 186, 79, 54, 172, 222, 197, 254, 12, 219, 166, 45, 77, 5, 37, 237, 177, 112, 71, 220, 17, 247, 199, 146, 238, 124, 248, 87, 34, 185, 33, 50, 42, 250, 41, 219, 249, 125, 31, 163, 232, 64, 176, 192, 130, 56, 125, 139, 110, 147, 63, 226, 31, 45, 1, 2, 2, 1, 1, 9, 9, 32, 0, 0, 0, 0, 0, 0, 0]

static char *
ref_vote_1[] = {
  "02",
  "bf66885f51af9bc556ea4c35f2e3dfe0413d2d7c7b1830a6d6ff49e643eb044d",
  "bef520fe873a3eac1f519435058dca75f9d743ecdb340df83471a291fed18d0b",
  "ebb4c98236bfdce43db873181ea6205820f5216143ad282e85434d7ad0504fd4",
  "4b20fad04077b2dc852b9f1937222e88d8804589304832d03d9bd196f09a120a",
  "020001",
  "03",
  "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
  "b4c95779f8efc64c64a93dc888c6375eee824e0a35800f1008891970f80c7e6d",
  "0761481d98631bd37ce9c4ba4f36acdec5fe0cdba62d4d0525edb17047dc11f7",
  "c792ee7cf85722b921322afa29dbf97d1fa3e840b0c082387d8b6e933fe21f2d",
  "010202010109092000000000000000"
};

static void
log_ag_vote( fd_ag_vote_t const * vote ) {
  switch( vote->type ) {
    case FD_AG_VOTE_NOTARIZE: 
    case FD_AG_VOTE_NOTARIZE_FALLBACK: {
      FD_LOG_NOTICE(( "... version %u", vote->version ));
      FD_LOG_NOTICE(( "... slot %lu", vote->slot ));
      char enc[FD_BASE58_ENCODED_32_LEN];
      char buf[65UL] = {0};
      fd_hex_encode( buf, vote->block_id, 32UL );
      fd_base58_encode_32( vote->block_id, NULL, enc );
      FD_LOG_NOTICE(( "... block_id 0x%s", buf ));
      FD_LOG_NOTICE(( "... block_id (base58) %s", enc ));
      FD_LOG_NOTICE(( "... replayed_slot %lu", vote->replayed_slot ));
      fd_hex_encode( buf, vote->replayed_bank_hash, 32UL );
      fd_base58_encode_32( vote->replayed_bank_hash, NULL, enc );
      FD_LOG_NOTICE(( "... replayed_bank_hash 0x%s", buf ));
      FD_LOG_NOTICE(( "... replayed_bank_hash (base58) %s", enc ));
    } break;
    case FD_AG_VOTE_FINALIZE:
    case FD_AG_VOTE_SKIP:
    case FD_AG_VOTE_SKIP_FALLBACK: {
      FD_LOG_NOTICE(( "... slot %lu", vote->slot ));
    } break;
    default: FD_LOG_WARNING(( "... unrecognized type 0x%02x", vote->type ));
  }
}
int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( FD_AG_VOTE_SERDES_SUCCESS==0 );
  FD_TEST( FD_AG_VOTE_SERDES_FAILURE==-1 );

  uchar           out_buf[ FD_TXN_MAX_SZ ];
  fd_txn_t *      txn = (fd_txn_t *)out_buf;
  uchar           payload[ FD_TXN_MAX_SZ ];
  ulong           payload_sz = 0;
  fd_ag_vote_t    vote[1];
  uchar           ser_buf[ FD_TXN_MTU ];
  int             res = 0;

  for( ulong i=0UL; i<2UL; i++) {
  FD_LOG_NOTICE(( "ref_vote_%lu", i ));
    load_test_txn( payload, i==0 ? ref_vote_0 : ref_vote_1, 
                   i==0 ? sizeof(ref_vote_0) : sizeof(ref_vote_1), &payload_sz );
    fd_txn_parse( payload, payload_sz, out_buf, NULL );
    FD_LOG_NOTICE(( "... payload_sz %lu", payload_sz ));
    FD_LOG_NOTICE(( "... transaction_version %u", txn->transaction_version ));
    FD_LOG_NOTICE(( "... signature_cnt %u", txn->signature_cnt ));
    FD_LOG_NOTICE(( "... signature_off %u", txn->signature_off ));
    FD_LOG_NOTICE(( "... signature_off %u", txn->message_off ));
    FD_LOG_NOTICE(( "... readonly_signed_cnt %u", txn->readonly_signed_cnt ));
    FD_LOG_NOTICE(( "... readonly_unsigned_cnt %u", txn->readonly_unsigned_cnt ));
    FD_LOG_NOTICE(( "... acct_addr_cnt %u", txn->acct_addr_cnt ));
    FD_LOG_NOTICE(( "... acct_addr_off %u", txn->acct_addr_off ));
    FD_LOG_NOTICE(( "... recent_blockhash_off %u", txn->recent_blockhash_off ));
    FD_LOG_NOTICE(( "... instr_cnt %u", txn->instr_cnt ));
    for( ulong i=0; i<txn->instr_cnt; i++ ) {
      FD_LOG_NOTICE(( "... instr[%lu].data_sz %u", i, txn->instr[0].data_sz ));
      FD_LOG_NOTICE(( "... instr[%lu].data_off %u", i, txn->instr[0].data_off ));
    }

    /* normal conditions */
    res = fd_txn_is_simple_ag_vote_transaction( txn, payload );
    FD_LOG_NOTICE(( "... fd_txn_is_simple_ag_vote_transaction %d", res ));
    FD_TEST( res==1 );
    res = fd_ag_vote_deserialize_from_data( vote, payload + txn->instr[0].data_off );
    FD_LOG_NOTICE(( "... fd_ag_vote_deserialize_from_data %d", res ));
    FD_TEST( !res );
    log_ag_vote( vote );
    res = fd_ag_vote_serialize_into_data( ser_buf, vote );
    FD_LOG_NOTICE(( "... fd_ag_vote_serialize_into_data %d", res ));
    FD_TEST( !res );
    res = memcmp( payload + txn->instr[0].data_off, ser_buf, txn->instr[0].data_sz );
    FD_LOG_NOTICE(( "... memcmp %d", res ));
    FD_TEST( !res );

    /* error conditions */
    FD_TEST( !fd_txn_is_simple_ag_vote_transaction( txn, payload + 1UL ) );
    for( ulong j=0; j<256; j++) {
      uchar type = (uchar)j;
      int exp0 = 1;
      int exp1 = FD_AG_VOTE_SERDES_SUCCESS;
      *(payload + txn->instr[0].data_off) = type;
      if( FD_UNLIKELY( !(type==FD_AG_VOTE_NOTARIZE ||
                         type==FD_AG_VOTE_FINALIZE ||
                         type==FD_AG_VOTE_SKIP ||
                         type==FD_AG_VOTE_NOTARIZE_FALLBACK ||
                         type==FD_AG_VOTE_SKIP_FALLBACK ) ) ) {
        exp0 = 0;
        exp1 = FD_AG_VOTE_SERDES_FAILURE;
      }
      res = fd_txn_is_simple_ag_vote_transaction( txn, payload );
      FD_TEST( res==exp0 );
      res = fd_ag_vote_deserialize_from_data( vote, payload + txn->instr[0].data_off );
      FD_TEST( res==exp1 );
      FD_TEST( type==vote->type );
      if( res==FD_AG_VOTE_SERDES_FAILURE ) { FD_TEST( vote->slot==ULONG_MAX ); }
      res = fd_ag_vote_serialize_into_data( ser_buf, vote );
      FD_TEST( res==exp1 );
    }
  }

  /* TODO expand testing */

  FD_LOG_WARNING(( "pass" ));
  fd_halt();
  return 0;
}
