#include "../../util/fd_util.h"
#include "fd_gossip_private.h"
#include "fd_gossip_txbuild.h"
#include "fd_gossip_types.h"

FD_IMPORT_BINARY( fd_gossip_test_vote_txn, "src/flamenco/gossip/fixtures/test_vote_txn.bin" );

void
gen_pubkey( fd_rng_t * rng, uchar * pubkey ) {
  for( ulong i=0UL; i<32UL; i++ ) pubkey[i] = fd_rng_uchar( rng );
}

void
test_gossip_vote_enc( void ) {
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  uchar pubkey[32UL];
  gen_pubkey( rng, pubkey );

  fd_gossip_txbuild_t txbuild[1];
  fd_gossip_txbuild_init( txbuild, pubkey, FD_GOSSIP_MESSAGE_PUSH );

  uchar crds_val[ FD_GOSSIP_CRDS_MAX_SZ ];
  fd_gossip_view_crds_value_t ser_view[1];

  long now = 1234L*1000L*1000L;

  fd_gossip_crds_vote_encode( crds_val,
                              FD_GOSSIP_CRDS_MAX_SZ,
                              fd_gossip_test_vote_txn,
                              fd_gossip_test_vote_txn_sz,
                              pubkey,
                              now,
                              0UL, /* vote_index */
                              ser_view );
  FD_TEST( ser_view->tag==FD_GOSSIP_VALUE_VOTE );
  FD_TEST( fd_memeq( crds_val+ser_view->pubkey_off, pubkey, 32UL ) );
  FD_TEST( ser_view->vote->index==0UL );
  FD_TEST( ser_view->vote->txn_sz==fd_gossip_test_vote_txn_sz );
  FD_TEST( fd_memeq( crds_val+ser_view->vote->txn_off, fd_gossip_test_vote_txn, fd_gossip_test_vote_txn_sz ) );
  FD_TEST( ser_view->wallclock_nanos==now );

  ulong crds_val_sz = ser_view->length;

  FD_TEST( !!fd_gossip_txbuild_can_fit( txbuild, crds_val_sz ) );
  fd_gossip_txbuild_append( txbuild, crds_val_sz, crds_val );


  /* Simple parse test */
  fd_gossip_view_t parse_view[1];
  ulong sz = fd_gossip_msg_parse( parse_view, txbuild->bytes, txbuild->bytes_len );
  FD_TEST( sz==txbuild->bytes_len );

  fd_gossip_view_crds_value_t * parsed_vote = &parse_view->push->crds_values[0];
  FD_TEST( parsed_vote->tag==FD_GOSSIP_VALUE_VOTE );
  FD_TEST( fd_memeq( txbuild->bytes+parsed_vote->pubkey_off, pubkey, 32UL ) );
  FD_TEST( parsed_vote->vote->index==0UL );
  FD_TEST( parsed_vote->length==crds_val_sz );
  FD_TEST( parsed_vote->vote->txn_sz==fd_gossip_test_vote_txn_sz );
  FD_TEST( fd_memeq( txbuild->bytes+parsed_vote->vote->txn_off, fd_gossip_test_vote_txn, parsed_vote->vote->txn_sz ) );
  FD_TEST( parsed_vote->wallclock_nanos==now );
}

FD_IMPORT_BINARY( push_vote,                        "src/flamenco/gossip/fixtures/push_vote.bin" );
FD_IMPORT_BINARY( pull_req,                         "src/flamenco/gossip/fixtures/pull_req.bin" );
FD_IMPORT_BINARY( pull_resp_legacy_snapshot_hashes, "src/flamenco/gossip/fixtures/pull_resp_legacy_snapshot_hashes.bin" );
FD_IMPORT_BINARY( pull_resp_snapshot_hashes,        "src/flamenco/gossip/fixtures/pull_resp_snapshot_hashes.bin" );
FD_IMPORT_BINARY( pull_resp_node_instance,          "src/flamenco/gossip/fixtures/pull_resp_node_instance.bin" );
FD_IMPORT_BINARY( pull_resp_version,                "src/flamenco/gossip/fixtures/pull_resp_version.bin" );

static inline int
base58_eq_32( void const * q,
              char const * b ) {
  uchar b2[32]; FD_TEST( fd_base58_decode_32( b, b2 ) );
  return 0==memcmp( q, b2, 32UL );
}

static inline int
base58_eq_64( void const * q,
              char const * b ) {
  uchar b2[64]; FD_TEST( fd_base58_decode_64( b, b2 ) );
  return 0==memcmp( q, b2, 64UL );
}

static void
test_parse_push_vote( void ) {
  fd_gossip_view_t view[1];
  FD_TEST( fd_gossip_msg_parse( view, push_vote, push_vote_sz )==push_vote_sz );
  FD_TEST( view->tag==FD_GOSSIP_MESSAGE_PUSH );
  FD_TEST( view->push->crds_values_len==2UL );
  FD_TEST( base58_eq_64( push_vote+view->push->crds_values[0].signature_off, "3WtiW29DRc4jGx9bqPkBm8evtL1bEnwiGnPRZbp2GXXkuZ7SfJpFEdEfoMJn5iZzHUjXyFCG4f4sySQS13oqF22w" ) );
  FD_TEST( base58_eq_32( push_vote+view->push->crds_values[0].pubkey_off, "9Diwct7c6braQnne86jutswAW4iZmPfcg6VHVp4FBrLn" ) );
  FD_TEST( view->push->crds_values[0].tag==FD_GOSSIP_VALUE_VOTE );
  FD_TEST( view->push->crds_values[0].wallclock_nanos==1660658421296L*(long)1e6 );
  FD_TEST( view->push->crds_values[0].vote->index==7 );
  FD_TEST( base58_eq_64( push_vote+view->push->crds_values[1].signature_off, "5Xrqaz4ESCnZyGKY9xT4bXDTrM54mDBdGD8T4ooSHkGYH7LHMrDu9oP6r6ofi4ydKDtvGgTdJZsUcdsmqkipD1Sg" ) );
  FD_TEST( base58_eq_32( push_vote+view->push->crds_values[1].pubkey_off, "9Diwct7c6braQnne86jutswAW4iZmPfcg6VHVp4FBrLn" ) );
  FD_TEST( view->push->crds_values[1].tag==FD_GOSSIP_VALUE_VOTE );
  FD_TEST( view->push->crds_values[1].wallclock_nanos==1660658421764L*(long)1e6 );
  FD_TEST( view->push->crds_values[1].vote->index==8 );
  /* FIXME verify txn_t content */
}

static void
test_parse_pull_req( void ) {
  fd_gossip_view_t view[1];
  FD_TEST( fd_gossip_msg_parse( view, pull_req, pull_req_sz )==pull_req_sz );
  FD_TEST( view->tag==FD_GOSSIP_MESSAGE_PULL_REQUEST );
  FD_TEST( view->pull_request->bloom_keys_len==3UL );
  FD_TEST( view->pull_request->bloom_bits_cnt==6168UL );
  FD_TEST( view->pull_request->bloom_num_bits_set==0UL );
  FD_TEST( view->pull_request->mask==288230376151711743UL );
  FD_TEST( view->pull_request->mask_bits==6U );
  FD_TEST( view->pull_request->pr_ci->tag==FD_GOSSIP_VALUE_LEGACY_CONTACT_INFO );
}

static void
test_parse_pull_resp_legacy_snapshot_hashes( void ) {
  fd_gossip_view_t view[1];
  FD_TEST( fd_gossip_msg_parse( view, pull_resp_legacy_snapshot_hashes, pull_resp_legacy_snapshot_hashes_sz )==pull_resp_legacy_snapshot_hashes_sz );
  FD_TEST( view->tag==FD_GOSSIP_MESSAGE_PULL_RESPONSE );
  FD_TEST( base58_eq_32( pull_resp_legacy_snapshot_hashes+view->pull_response->from_off, "9Diwct7c6braQnne86jutswAW4iZmPfcg6VHVp4FBrLn" ) );
  FD_TEST( view->pull_response->crds_values_len==1UL );
  FD_TEST( base58_eq_64( pull_resp_legacy_snapshot_hashes+view->pull_response->crds_values[0].signature_off, "4ovwbuxF1k5hAej248Eay3ZLDssxXi9P4UWtsU6vu3jZmAHedtsZ55fkdSjLp4GicXCZCoCmHLbk5nHMnhYZ2QWq" ) );
  FD_TEST( base58_eq_32( pull_resp_legacy_snapshot_hashes+view->pull_response->crds_values[0].pubkey_off, "9Diwct7c6braQnne86jutswAW4iZmPfcg6VHVp4FBrLn" ) );
  FD_TEST( view->pull_response->crds_values[0].tag==FD_GOSSIP_VALUE_LEGACY_SNAPSHOT_HASHES );
  FD_TEST( view->pull_response->crds_values[0].wallclock_nanos==1660658416429*(long)1e6 );
}

static void
test_parse_pull_resp_snapshot_hashes( void ) {
  fd_gossip_view_t view[1];
  FD_TEST( fd_gossip_msg_parse( view, pull_resp_snapshot_hashes, pull_resp_snapshot_hashes_sz )==pull_resp_snapshot_hashes_sz );
  FD_TEST( view->tag==FD_GOSSIP_MESSAGE_PULL_RESPONSE );
  FD_TEST( base58_eq_32( pull_resp_snapshot_hashes+view->pull_response->from_off, "9Diwct7c6braQnne86jutswAW4iZmPfcg6VHVp4FBrLn" ) );
  FD_TEST( view->pull_response->crds_values_len==1UL );
  FD_TEST( base58_eq_64( pull_resp_snapshot_hashes+view->pull_response->crds_values[0].signature_off, "4ovwbuxF1k5hAej248Eay3ZLDssxXi9P4UWtsU6vu3jZmAHedtsZ55fkdSjLp4GicXCZCoCmHLbk5nHMnhYZ2QWq" ) );
  FD_TEST( base58_eq_32( pull_resp_snapshot_hashes+view->pull_response->crds_values[0].pubkey_off, "9Diwct7c6braQnne86jutswAW4iZmPfcg6VHVp4FBrLn" ) );
  FD_TEST( view->pull_response->crds_values[0].tag==FD_GOSSIP_VALUE_INC_SNAPSHOT_HASHES );
  fd_gossip_snapshot_hash_pair_t full = FD_LOAD( fd_gossip_snapshot_hash_pair_t, pull_resp_snapshot_hashes+view->pull_response->crds_values[0].snapshot_hashes->full_off );
  FD_TEST( full.slot==47411 );
  FD_TEST( base58_eq_32( full.hash, "CDhgJ4hV9WK3KNTQK5mMcS2RtfphCeDsZeqesAgnbrkh" ) );
  FD_TEST( view->pull_response->crds_values[0].snapshot_hashes->inc_len==0UL );
  FD_TEST( view->pull_response->crds_values[0].wallclock_nanos==1660658416429*(long)1e6 );
}

static void
test_parse_pull_resp_node_instance( void ) {
  fd_gossip_view_t view[1];
  FD_TEST( fd_gossip_msg_parse( view, pull_resp_node_instance, pull_resp_node_instance_sz )==pull_resp_node_instance_sz );
  FD_TEST( view->tag==FD_GOSSIP_MESSAGE_PULL_RESPONSE );
  FD_TEST( base58_eq_32( pull_resp_node_instance+view->pull_response->from_off, "9Diwct7c6braQnne86jutswAW4iZmPfcg6VHVp4FBrLn" ) );
  FD_TEST( view->pull_response->crds_values_len==1UL );
  FD_TEST( base58_eq_64( pull_resp_node_instance+view->pull_response->crds_values[0].signature_off, "2x1fZN5oR8BXGKW8CuHQBw5rKL68sn4WRBrDnepjn4TXmd4XWLwUUo5kdq8npmPbtCUwcBy8nq4667wRSUph7jv9" ) );
  FD_TEST( base58_eq_32( pull_resp_node_instance+view->pull_response->crds_values[0].pubkey_off, "9Diwct7c6braQnne86jutswAW4iZmPfcg6VHVp4FBrLn" ) );
  FD_TEST( view->pull_response->crds_values[0].tag==FD_GOSSIP_VALUE_NODE_INSTANCE );
  FD_TEST( view->pull_response->crds_values[0].node_instance->token==6711090452999269525UL );
  FD_TEST( view->pull_response->crds_values[0].wallclock_nanos==1660658416907*(long)1e6 );
}

static void
test_parse_pull_resp_version( void ) {
  fd_gossip_view_t view[1];
  FD_TEST( fd_gossip_msg_parse( view, pull_resp_version, pull_resp_version_sz )==pull_resp_version_sz );
  FD_TEST( view->tag==FD_GOSSIP_MESSAGE_PULL_RESPONSE );
  FD_TEST( base58_eq_32( pull_resp_version+view->pull_response->from_off, "9Diwct7c6braQnne86jutswAW4iZmPfcg6VHVp4FBrLn" ) );
  FD_TEST( view->pull_response->crds_values_len==1UL );
  FD_TEST( base58_eq_64( pull_resp_version+view->pull_response->crds_values[0].signature_off, "41fQjMjZF8Uw3ydc4tfSiJZGkBwFSu8SqqaqsDysiDepVrhV1QvYsqETystLsay7swYxPxDnfFVX4mxqMzoFWy4S" ) );
  FD_TEST( base58_eq_32( pull_resp_version+view->pull_response->crds_values[0].pubkey_off, "9Diwct7c6braQnne86jutswAW4iZmPfcg6VHVp4FBrLn" ) );
  FD_TEST( view->pull_response->crds_values[0].tag==FD_GOSSIP_VALUE_VERSION );
  FD_TEST( view->pull_response->crds_values[0].wallclock_nanos==1660658416907*(long)1e6 );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_gossip_vote_enc();
  test_parse_push_vote();
  test_parse_pull_req();
  test_parse_pull_resp_legacy_snapshot_hashes();
  test_parse_pull_resp_snapshot_hashes();
  test_parse_pull_resp_node_instance();
  test_parse_pull_resp_version();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
