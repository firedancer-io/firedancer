#include "fd_verify.h"
#include "../../../../ballet/hex/fd_hex.h"

static char *
valid_txn_1sig[] = {
  "01",
  "fd5dd258de925a158adf344fede5089121bf6eceb8339cebc707d5f47ab16986803c667a12693265dcdf2d89cd5ddf5da636f6c01d2cf1e64eb662304da78f00",
  "01000104",
  "be5b54cdb01762497c7fd98bfcaaec1d2a2cad1c2bb5134857b68f0214935ebb",
  "39b50f550575dc96d25125430d6a1aa7483b458f5786ef9e7e605ead7d7b9a13",
  "62e658c293c604459865e83503e2d1987f4dc07210e3a777477ee13843fcd265",
  "0863ba8dd9c4c2fb174a05cba27e2a2cd623573d79e90b35b579fc0d00000000",
  "f270416e4022a36d79c23416f8c483693b5da245ec40d4b3049ff5ab11e7d009",
  "01",
  "030302010001",
  "00", // CloseContextState
};

static char *
invalid_txn_same_1sig[] = {
  "01",
  "fd5dd258de925a158adf344fede5089121bf6eceb8339cebc707d5f47ab16986803c667a12693265dcdf2d89cd5ddf5da636f6c01d2cf1e64eb662304da78f00",
  "01000104",
  // zeroed all accounts, signature will be invalid
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "f270416e4022a36d79c23416f8c483693b5da245ec40d4b3049ff5ab11e7d009",
  "01",
  "030302010001",
  "00",
};

static char *
valid_txn_2sigs[] = {
  "02",
  "50e91db2a2c889fec7f7a92cfdfc4735c20722e58cedeec048e1de80dec5937e31c46b37efea6f6cf91241b48c84d11a12aaf6864990f3ae0de975487ef7fd0c",
  "f23b8becca7c2771e45a87677c2cdaff4bfc331d2456faab48ebe893c7a879609c157380319935d8df8816a6f5c9852342bec49fc997546c1040443755e26d00",
  "02000204",
  "be5b54cdb01762497c7fd98bfcaaec1d2a2cad1c2bb5134857b68f0214935ebb",
  "0d55cec08108e1c2d7df2abe179cbd3ea581e4933d8d620f0f0730ab5c4ae244",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0863ba8dd9c4c2fb174a05cba27e2a2cd623573d79e90b35b579fc0d00000000",
  "417b7e47ddaf7b8b35ebc59dd92b26c0224bbd3b3018fff36470eaefd5e645a3",
  "02",
  "0202000134",
  "0000000030b11e0000000000a1000000000000000863ba8dd9c4c2fb174a05cba27e2a2cd623573d79e90b35b579fc0d00000000",
  "03020100c102",
  "0b", // VerifyCiphertextCommitmentEquality
  "a0d0383c8e276e1748ac744b7106b4ea8ae1de3fc3879e59a01124209f4a6c05",
  "62afc0e4f37af5a857e4223b5a4ad9244e03af05f2945224ffbac7772bcbd053",
  "2647444d6b3edeb2d4cfeedef404f203f8ad1f2d5a64530ad890bffab4861a66",
  "52461434fb059f202ef7bd99c98b52c1cd891e2e5327635cd9559a7776cb451c",
  "fa12dc19b4339808c62d57ef8ae419e51dfac6a9b0b28f8e11ee29a1dc3fcf6d",
  "9cd922081d9832ab12fbdd69fb0a01e21a0748a347e56881872d71372edf544d",
  "aa1e3e4ff64d6a95ed20c68ce3d0f08a5420ad223c9f0a3c2ab2269f13ff9a0c",
  "7f81fa6227fc794e16a42c6f45d9ca7fac9087400babaeef2e5dae1b935fc507",
  "16df6090d8845eadb2827f764b1fd880e84e7706577c8200668506280104a60e",
  "2a30d4e6de4995c74462c83e1d3e86dca53bb8b3c6b56fd769172fa4fc2a450e",
};

static char *
invalid_txn_2sigs[] = {
  "02",
  "50e91db2a2c889fec7f7a92cfdfc4735c20722e58cedeec048e1de80dec5937e31c46b37efea6f6cf91241b48c84d11a12aaf6864990f3ae0de975487ef7fd0c",
  // invalid signature
  "0000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "02000204",
  "be5b54cdb01762497c7fd98bfcaaec1d2a2cad1c2bb5134857b68f0214935ebb",
  "0d55cec08108e1c2d7df2abe179cbd3ea581e4933d8d620f0f0730ab5c4ae244",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0863ba8dd9c4c2fb174a05cba27e2a2cd623573d79e90b35b579fc0d00000000",
  "417b7e47ddaf7b8b35ebc59dd92b26c0224bbd3b3018fff36470eaefd5e645a3",
  "02",
  "0202000134",
  "0000000030b11e0000000000a1000000000000000863ba8dd9c4c2fb174a05cba27e2a2cd623573d79e90b35b579fc0d00000000",
  "03020100c102",
  "0b",
  "a0d0383c8e276e1748ac744b7106b4ea8ae1de3fc3879e59a01124209f4a6c05",
  "62afc0e4f37af5a857e4223b5a4ad9244e03af05f2945224ffbac7772bcbd053",
  "2647444d6b3edeb2d4cfeedef404f203f8ad1f2d5a64530ad890bffab4861a66",
  "52461434fb059f202ef7bd99c98b52c1cd891e2e5327635cd9559a7776cb451c",
  "fa12dc19b4339808c62d57ef8ae419e51dfac6a9b0b28f8e11ee29a1dc3fcf6d",
  "9cd922081d9832ab12fbdd69fb0a01e21a0748a347e56881872d71372edf544d",
  "aa1e3e4ff64d6a95ed20c68ce3d0f08a5420ad223c9f0a3c2ab2269f13ff9a0c",
  "7f81fa6227fc794e16a42c6f45d9ca7fac9087400babaeef2e5dae1b935fc507",
  "16df6090d8845eadb2827f764b1fd880e84e7706577c8200668506280104a60e",
  "2a30d4e6de4995c74462c83e1d3e86dca53bb8b3c6b56fd769172fa4fc2a450e",
};

uchar *
load_test_txn( char * hex[], ulong hex_sz, ulong * tx_len ) {
  ulong hex_len = 0;
  for ( ulong i=0; i<hex_sz/sizeof(char *); i++ ) {
    hex_len += strlen(hex[i]);
    // printf("adding %d, total %d\n", strlen(hex[i]), hex_len);
  }
  *tx_len = hex_len / 2;
  uchar * tx = malloc(hex_len / 2);

  hex_len = 0;
  for ( ulong i=0; i<hex_sz/sizeof(char *); i++ ) {
    ulong cur_len = strlen(hex[i]);
    fd_hex_decode( &tx[hex_len/2], hex[i], cur_len/2 );
    hex_len += cur_len;
  }
  return tx;
}

static void
setup_verify_ctx( fd_verify_ctx_t * ctx, void ** mem ) {
  /* tcache - note: using aligned_alloc for tests */
  ulong depth     = VERIFY_TCACHE_DEPTH;
  ulong map_cnt   = VERIFY_TCACHE_MAP_CNT;
  ulong align     = fd_tcache_align();
  ulong footprint = fd_tcache_footprint( depth, map_cnt );
  if( FD_UNLIKELY( !footprint ) ) FD_LOG_ERR(( "bad depth / map_cnt" ));
  *mem = aligned_alloc( align, footprint ); FD_TEST( *mem );
  fd_tcache_t * tcache = fd_tcache_join( fd_tcache_new( *mem, VERIFY_TCACHE_DEPTH, VERIFY_TCACHE_MAP_CNT ) );
  if( FD_UNLIKELY( !tcache ) ) FD_LOG_ERR(( "fd_tcache_join failed" ));
  ctx->tcache_depth   = fd_tcache_depth       ( tcache );
  ctx->tcache_map_cnt = fd_tcache_map_cnt     ( tcache );
  ctx->tcache_sync    = fd_tcache_oldest_laddr( tcache );
  ctx->tcache_ring    = fd_tcache_ring_laddr  ( tcache );
  ctx->tcache_map     = fd_tcache_map_laddr   ( tcache );
  fd_tcache_reset( ctx->tcache_ring, ctx->tcache_depth, ctx->tcache_map, ctx->tcache_map_cnt );

  /* ctx->sha */
  uchar * _sha = aligned_alloc( FD_SHA512_ALIGN, sizeof(fd_sha512_t)*FD_TXN_ACTUAL_SIG_MAX );
  for ( ulong i=0; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha + i*sizeof(fd_sha512_t) ) );
    if( FD_UNLIKELY( !sha ) ) FD_LOG_ERR(( "fd_sha512_join failed" ));
    ctx->sha[i] = sha;
  }
}

static void
free_verify_ctx( fd_verify_ctx_t * ctx, void * mem ) {
  free(mem);
  free(ctx->sha[0]); // all sha allocated in a single malloc, the first one has the address
}

static void
test_verify_success( void ) {
  fd_verify_ctx_t ctx[1];
  void *          mem = NULL;
  uchar           out_buf[FD_TXN_MAX_SZ];
  fd_txn_t *      txn = (fd_txn_t *)out_buf;
  ulong           opt_sig = 0;
  uchar *         payload = NULL;
  ulong           payload_sz = 0;
  int             res = 0;

  FD_LOG_NOTICE(( "test_verify_success" ));
  setup_verify_ctx( ctx, &mem );

  payload = load_test_txn( valid_txn_2sigs, sizeof(valid_txn_2sigs), &payload_sz );
  fd_txn_parse( payload, payload_sz, out_buf, NULL );

  /* valid txn with 2 signatures */
  res = fd_txn_verify( ctx, payload, (ushort)payload_sz, txn, &opt_sig );
  FD_TEST( res==FD_TXN_VERIFY_SUCCESS );

  /* same txn as before: should dedup */
  res = fd_txn_verify( ctx, payload, (ushort)payload_sz, txn, &opt_sig );
  FD_TEST( res==FD_TXN_VERIFY_DEDUP );

  res = fd_txn_verify( ctx, payload, (ushort)payload_sz, txn, &opt_sig );
  FD_TEST( res==FD_TXN_VERIFY_DEDUP );

  free(payload);
  payload = load_test_txn( valid_txn_1sig, sizeof(valid_txn_1sig), &payload_sz );
  fd_txn_parse( payload, payload_sz, out_buf, NULL );

  /* valid txn with 1 signature */
  int res1 = fd_txn_verify( ctx, payload, (ushort)payload_sz, txn, &opt_sig );
  FD_TEST( res1==FD_TXN_VERIFY_SUCCESS );

  res = fd_txn_verify( ctx, payload, (ushort)payload_sz, txn, &opt_sig );
  FD_TEST( res==FD_TXN_VERIFY_DEDUP );

  res = fd_txn_verify( ctx, payload, (ushort)payload_sz, txn, &opt_sig );
  FD_TEST( res==FD_TXN_VERIFY_DEDUP );

  free(payload);
  free_verify_ctx( ctx, mem );
}

static void
test_verify_invalid_sigs_success( void ) {
  fd_verify_ctx_t ctx[1];
  void *          mem = NULL;
  uchar           out_buf[FD_TXN_MAX_SZ];
  fd_txn_t *      txn = (fd_txn_t *)out_buf;
  ulong           opt_sig = 0;
  uchar *         payload = NULL;
  ulong           payload_sz = 0;
  int             res = 0;

  FD_LOG_NOTICE(( "test_verify_invalid_sigs_success" ));
  setup_verify_ctx( ctx, &mem );

  payload = load_test_txn( invalid_txn_2sigs, sizeof(invalid_txn_2sigs), &payload_sz );
  fd_txn_parse( payload, payload_sz, out_buf, NULL );

  /* invalid txn with 2 signatures */
  res = fd_txn_verify( ctx, payload, (ushort)payload_sz, txn, &opt_sig );
  FD_TEST( res==FD_TXN_VERIFY_FAILED );

  /* there's no dedup for failed txs */
  res = fd_txn_verify( ctx, payload, (ushort)payload_sz, txn, &opt_sig );
  FD_TEST( res==FD_TXN_VERIFY_FAILED );

  free(payload);
  free_verify_ctx( ctx, mem );
}

static void
test_verify_invalid_dedup_success( void ) {
  fd_verify_ctx_t ctx[1];
  void *          mem = NULL;
  uchar           out_buf[FD_TXN_MAX_SZ];
  fd_txn_t *      txn = (fd_txn_t *)out_buf;
  ulong           opt_sig = 0;
  uchar *         payload = NULL;
  ulong           payload_sz = 0;
  int             res = 0;

  FD_LOG_NOTICE(( "test_verify_invalid_dedup_success" ));
  setup_verify_ctx( ctx, &mem );

  payload = load_test_txn( invalid_txn_same_1sig, sizeof(invalid_txn_same_1sig), &payload_sz );
  fd_txn_parse( payload, payload_sz, out_buf, NULL );

  /* invalid txn, with same signature as a valid one. attacker tries to frontrun/DoS a user.
     see: https://github.com/firedancer-io/firedancer/pull/1068 */
  res = fd_txn_verify( ctx, payload, (ushort)payload_sz, txn, &opt_sig );
  FD_TEST( res==FD_TXN_VERIFY_FAILED );

  free(payload);
  payload = load_test_txn( valid_txn_1sig, sizeof(valid_txn_1sig), &payload_sz );
  fd_txn_parse( payload, payload_sz, out_buf, NULL );

  /* valid txn with 1 signature. this should NOT be deduped */
  res = fd_txn_verify( ctx, payload, (ushort)payload_sz, txn, &opt_sig );
  FD_TEST( res==FD_TXN_VERIFY_SUCCESS );

  /* clear to test the other way */
  fd_tcache_reset( ctx->tcache_ring, ctx->tcache_depth, ctx->tcache_map, ctx->tcache_map_cnt );

  /* valid txn with 1 signature */
  res = fd_txn_verify( ctx, payload, (ushort)payload_sz, txn, &opt_sig );
  FD_TEST( res==FD_TXN_VERIFY_SUCCESS );

  free(payload);
  payload = load_test_txn( invalid_txn_same_1sig, sizeof(invalid_txn_same_1sig), &payload_sz );
  fd_txn_parse( payload, payload_sz, out_buf, NULL );

  /* invalid txn, with same signature as a valid one. this is deduped */
  res = fd_txn_verify( ctx, payload, (ushort)payload_sz, txn, &opt_sig );
  FD_TEST( res==FD_TXN_VERIFY_DEDUP );

  free(payload);
  free_verify_ctx( ctx, mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_verify_success();
  test_verify_invalid_sigs_success();
  test_verify_invalid_dedup_success();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
