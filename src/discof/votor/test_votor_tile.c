#define FD_TILE_TEST 1
#include "fd_votor_tile.c"

#define TEST_VOTER_MAX (4UL)

/* An ag_epoch_info_t is nearly 300 KiB, too big for the stack. */

static ag_epoch_info_t epoch_info_mem;

/* Builds cnt voters with distinct identities and valid BLS keys, staked
   base, base+1, ... rank_voters drops any voter whose BLS key fails to
   deserialize, so the keys have to be real points. */

static void
build_stakes( fd_vote_stake_weight_t * out,
              ulong                    cnt,
              ulong                    base ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    memset( &out[i], 0, sizeof(fd_vote_stake_weight_t) );
    out[i].stake           = base + i;
    out[i].id_key.uc  [ 0 ] = (uchar)( i + 1UL );
    out[i].vote_key.uc[ 0 ] = (uchar)( i + 0x80UL );

    fd_bls_sec_t sec; memset( &sec, (int)( i*7UL + 1UL ), FD_BLS_SEC_SZ );
    fd_bls_pub_t pub; fd_bls_sec_to_pub( &sec, &pub );
    blst_p1_compress( out[i].bls_key, &pub );
  }
}

static void
test_rank_voters_resets_total_stake( void ) {
  fd_vote_stake_weight_t stakes[ TEST_VOTER_MAX ];
  ag_epoch_info_t *      epoch_info = &epoch_info_mem;

  build_stakes( stakes, 3UL, 10UL );
  FD_TEST( rank_voters( epoch_info, stakes, 3UL )==epoch_info );
  FD_TEST( epoch_info->validator_cnt==3UL  );
  FD_TEST( epoch_info->total_stake  ==33UL ); /* 10+11+12 */

  /* Same buffer, next epoch. */

  build_stakes( stakes, 2UL, 5UL );
  FD_TEST( rank_voters( epoch_info, stakes, 2UL )==epoch_info );
  FD_TEST( epoch_info->validator_cnt==2UL  );
  FD_TEST( epoch_info->total_stake  ==11UL ); /* 5+6, not 33+11 */
}

static void
test_sign_bls_request( void ) {
  static fd_votor_tile_t ctx;
  static uchar request_mcache_mem [ FD_MCACHE_FOOTPRINT( 128UL, 0UL ) ] __attribute__((aligned(FD_MCACHE_ALIGN)));
  static uchar response_mcache_mem[ FD_MCACHE_FOOTPRINT( 128UL, 0UL ) ] __attribute__((aligned(FD_MCACHE_ALIGN)));
  static uchar request_data [ FD_KEYGUARD_BLS_PUBKEY_SZ+AG_VOTE_SIGNING_SER_MAX ] __attribute__((aligned(FD_CHUNK_ALIGN)));
  static uchar response_data[ FD_BLS_SIG_SZ ] __attribute__((aligned(FD_CHUNK_ALIGN)));

  fd_keyguard_client_t * client = ctx.keyguard_client;
  client->request        = fd_mcache_join( fd_mcache_new( request_mcache_mem, 128UL, 0UL, 0UL ) );
  client->response       = fd_mcache_join( fd_mcache_new( response_mcache_mem, 128UL, 0UL, 0UL ) );
  FD_TEST( client->request && client->response );
  client->request_depth  = 128UL;
  client->response_depth = 128UL;
  client->request_mem    = (fd_wksp_t *)request_data;
  client->response_mem   = (fd_wksp_t *)response_data;
  client->request_mtu    = sizeof(request_data);
  client->response_mtu   = sizeof(response_data);

  fd_bls_sec_t sec; memset( &sec, 7, sizeof(sec) );
  fd_bls_pub_t pub; fd_bls_sec_to_pub( &sec, &pub );
  uchar public_key[ FD_BLS_PUB_COMPRESSED_SZ ];
  blst_p1_compress( public_key, &pub );

  for( uchar tag=1U; tag<=5U; tag++ ) {
    uchar payload[43];
    memset( payload, 0x42, sizeof(payload) );
    payload[0] = tag;
    ulong payload_sz = ( tag==1U || tag==4U ) ? 43UL : 11UL;
    ulong seq        = client->request_seq;

    /* Prepublish the signer's response so the blocking callback can
       run here.  Inspect the request it publishes below. */
    fd_bls_sig_t expected_sig;
    fd_bls_sec_sign( &sec, payload, payload_sz, &expected_sig );
    fd_bls_sig_ser( &expected_sig, response_data );
    fd_mcache_publish( client->response, 128UL, seq, FD_KEYGUARD_SIGN_TYPE_BLS, 0UL, FD_BLS_SIG_SZ, 0UL, 0UL, 0UL );

    fd_bls_sig_t sig;
    sign_bls( &ctx, &sig, public_key, payload, payload_sz );
    fd_frag_meta_t const * request = client->request+fd_mcache_line_idx( seq, 128UL );
    FD_TEST( fd_frag_meta_seq_query( request )==seq );
    FD_TEST( request->sig==FD_KEYGUARD_SIGN_TYPE_BLS );
    FD_TEST( request->sz==FD_KEYGUARD_BLS_PUBKEY_SZ+payload_sz );
    FD_TEST( !memcmp( request_data, public_key, FD_KEYGUARD_BLS_PUBKEY_SZ ) );
    FD_TEST( !memcmp( request_data+FD_KEYGUARD_BLS_PUBKEY_SZ, payload, payload_sz ) );
    FD_TEST( fd_bls_agg_verify( payload, payload_sz, &pub, &sig ) );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_rank_voters_resets_total_stake();
  test_sign_bls_request();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
