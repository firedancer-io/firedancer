/* test_rserve_tile drives rserve's request path with signed requests,
   with fd_stem_publish mocked to capture sent packets.  Covers the
   Alpenglow metadata requests end to end, the shared validation, and
   the asynchronous ping signing. */

#include "../../disco/topo/fd_topo.h" /* pulls in fd_stem.h so the static inline parses */

#define TEST_NET_OUT  (0UL)
#define TEST_SIGN_OUT (1UL)

static uchar * test_out_mem;
static uchar * test_sign_mem;
static uchar   pub_data[ 2048 ];
static ulong   pub_sz;
static ulong   pub_cnt;
static uchar   sign_req[ 32 ];
static ulong   sign_req_sz;
static ulong   sign_req_sig;
static ulong   sign_req_cnt;

static void
test_stem_publish( ulong out_idx,
                   ulong sig,
                   ulong chunk,
                   ulong sz ) {
  if( out_idx==TEST_SIGN_OUT ) {
    FD_TEST( sz<=sizeof(sign_req) );
    fd_memcpy( sign_req, fd_chunk_to_laddr( test_sign_mem, chunk ), sz );
    sign_req_sz  = sz;
    sign_req_sig = sig;
    sign_req_cnt++;
    return;
  }
  FD_TEST( out_idx==TEST_NET_OUT );
  FD_TEST( sz<=sizeof(pub_data) );
  fd_memcpy( pub_data, fd_chunk_to_laddr( test_out_mem, chunk ), sz );
  pub_sz = sz;
  pub_cnt++;
}

#define fd_stem_publish( stem, out_idx, sig, chunk, sz, ctl, tsorig, tspub )             \
  do { (void)(stem); (void)(ctl); (void)(tsorig); (void)(tspub);                         \
       test_stem_publish( (out_idx), (sig), (chunk), (sz) ); } while(0)

#include "fd_rserve_tile.c"

#include <unistd.h>
#include "../../ballet/sha256/fd_sha256.h"

#define PING_MAX (16UL)
#define BLK_MAX  (4UL)

static uchar rserve_mem [ 1UL<<16 ] __attribute__((aligned(128)));
static uchar blockdb_mem[ 1UL<<20 ] __attribute__((aligned(FD_BLOCKDB_ALIGN)));
static uchar out_mem    [ 1UL<<16 ] __attribute__((aligned(FD_CHUNK_ALIGN)));
static uchar sign_mem   [ 1UL<<16 ] __attribute__((aligned(FD_CHUNK_ALIGN)));

#define SIGN_DEPTH (4UL)
static uchar sign_pool_mem[ 1UL<<12 ] __attribute__((aligned(128)));
static uchar keyswitch_mem[ FD_KEYSWITCH_FOOTPRINT ] __attribute__((aligned(FD_KEYSWITCH_ALIGN)));

static uchar       client_priv[ 32 ];
static fd_pubkey_t client_pub;
static uchar       server_priv[ 32 ];
static fd_pubkey_t server_pub;

static uint   const CLIENT_IP   = 0x0A000002U;
static ushort const CLIENT_PORT = 9001;

static fd_sha512_t sha[1];

static void
setup( ctx_t * ctx,
       int     with_blockdb ) {
  memset( ctx, 0, sizeof(ctx_t) );
  uchar secret[ 32 ] = {0};
  FD_TEST( fd_rserve_footprint( PING_MAX )<=sizeof(rserve_mem) );
  ctx->rserve = fd_rserve_join( fd_rserve_new( rserve_mem, PING_MAX, 1UL, secret ) );
  FD_TEST( ctx->rserve );
  if( with_blockdb ) {
    FD_TEST( fd_blockdb_footprint( BLK_MAX, BLK_MAX )<=sizeof(blockdb_mem) );
    ctx->blockdb = fd_blockdb_join( fd_blockdb_new( blockdb_mem, BLK_MAX, BLK_MAX, 2UL, -1, 0UL ) );
    FD_TEST( ctx->blockdb );
  }
  ctx->store   = NULL; /* legacy lookups miss */
  ctx->disk_fd = -1;
  ctx->max_shreds_per_block = FD_SHRED_BLK_MAX;
  ctx->identity_public_key  = server_pub;
  fd_sha512_new( ctx->sha512 );

  test_out_mem        = out_mem;
  ctx->net_out_idx    = 0U;
  ctx->net_out_mem    = (fd_wksp_t *)out_mem;
  ctx->net_out_chunk0 = 0UL;
  ctx->net_out_wmark  = (sizeof(out_mem)>>FD_CHUNK_LG_SZ)-(2048UL>>FD_CHUNK_LG_SZ)-1UL;
  ctx->net_out_chunk  = 0UL;
  fd_ip4_udp_hdr_init( ctx->serve_hdr, FD_RSERVE_MAX_PACKET_SIZE, 0, 8700 );
  pub_cnt = 0UL;

  FD_TEST( sign_pool_footprint( SIGN_DEPTH )<=sizeof(sign_pool_mem) );
  ctx->sign_pool       = sign_pool_join( sign_pool_new( sign_pool_mem, SIGN_DEPTH ) );
  FD_TEST( ctx->sign_pool );
  test_sign_mem        = sign_mem;
  ctx->sign_out_idx    = TEST_SIGN_OUT;
  ctx->sign_out_mem    = (fd_wksp_t *)sign_mem;
  ctx->sign_out_chunk0 = 0UL;
  ctx->sign_out_wmark  = (sizeof(sign_mem)>>FD_CHUNK_LG_SZ)-1UL;
  ctx->sign_out_chunk  = 0UL;
  sign_req_cnt = 0UL;

  ctx->keyswitch = fd_keyswitch_join( fd_keyswitch_new( keyswitch_mem, FD_KEYSWITCH_STATE_UNLOCKED ) );
  FD_TEST( ctx->keyswitch );
}

/* ping_cache_add marks the client as having completed a ping, as
   handle_pong does. */

static void
ping_cache_add( ctx_t * ctx ) {
  fd_rserve_t * rserve = ctx->rserve;
  ping_cache_entry_t * entry = ping_pool_ele_acquire( rserve->ping_pool );
  memset( &entry->key, 0, sizeof(ping_cache_key_t) );
  entry->key.pubkey = client_pub;
  entry->key.ip4    = CLIENT_IP;
  entry->key.port   = CLIENT_PORT;
  entry->timestamp  = (ulong)fd_log_wallclock();
  ping_map_ele_insert( rserve->ping_map, entry, rserve->ping_pool );
  ping_dlist_ele_push_tail( rserve->ping_dlist, entry, rserve->ping_pool );
}

/* The client's requests are serialized into req, signed, and return
   their wire size. */

static uchar                  req[ FD_REPAIR_SER_MAX ];
static fd_ed25519_sig_t const sig_null;

static ulong
sign( ulong sz ) {
  uchar preimage[ FD_REPAIR_SIG_SER_MAX ];
  ulong preimage_sz = fd_repair_req_sig_ser( req, sz, preimage );
  fd_ed25519_sign( req+sizeof(uint), preimage, preimage_sz, client_pub.uc, client_priv, sha );
  return sz;
}

static ulong
window_index( ulong ts, uint nonce, ulong slot, ulong shred_idx ) {
  return sign( fd_repair_req_window_index_ser( &(fd_repair_shred_t){ .slot = slot, .shred_idx = shred_idx }, sig_null, &client_pub, &server_pub, ts, nonce, req ) );
}

static ulong
highest_window_index( ulong ts, uint nonce, ulong slot, ulong shred_idx ) {
  return sign( fd_repair_req_highest_window_index_ser( &(fd_repair_highest_shred_t){ .slot = slot, .shred_idx = shred_idx }, sig_null, &client_pub, &server_pub, ts, nonce, req ) );
}

static ulong
orphan( ulong ts, uint nonce, ulong slot ) {
  return sign( fd_repair_req_orphan_ser( &(fd_repair_orphan_t){ .slot = slot }, sig_null, &client_pub, &server_pub, ts, nonce, req ) );
}

static ulong
parent_and_fec_set_count( fd_pubkey_t const * to, ulong ts, uint nonce, ulong slot, fd_hash_t const * block_id ) {
  return sign( fd_repair_req_parent_and_fec_set_count_ser( &(fd_repair_parent_fec_set_count_t){ .slot = slot, .block_id = *block_id }, sig_null, &client_pub, to, ts, nonce, req ) );
}

static ulong
fec_set_root( ulong ts, uint nonce, ulong slot, fd_hash_t const * block_id, uint fec_set_idx ) {
  return sign( fd_repair_req_fec_set_root_ser( &(fd_repair_fec_set_root_t){ .slot = slot, .block_id = *block_id, .fec_set_idx = fec_set_idx }, sig_null, &client_pub, &server_pub, ts, nonce, req ) );
}

static ulong
window_index_for_block_id( ulong ts, uint nonce, ulong slot, fd_hash_t const * block_id, uint shred_idx ) {
  return sign( fd_repair_req_window_index_for_block_id_ser( &(fd_repair_shred_for_block_id_t){ .slot = slot, .shred_idx = shred_idx, .block_id = *block_id }, sig_null, &client_pub, &server_pub, ts, nonce, req ) );
}

/* request sends payload to rserve from the client address and returns
   the response payload size, or 0 if nothing was sent. */

static ulong
request( ctx_t *       ctx,
         uchar const * payload,
         ulong         payload_sz ) {
  fd_ip4_hdr_t ip4[1] = {{ .saddr = CLIENT_IP, .daddr = 0x0A000001U }};
  fd_udp_hdr_t udp[1] = {{ .net_sport = CLIENT_PORT }};
  ulong before = pub_cnt;
  handle_net_request( ctx, NULL, payload, payload_sz, udp, ip4 );
  if( pub_cnt==before ) return 0UL;
  FD_TEST( pub_cnt==before+1UL );
  FD_TEST( pub_sz>sizeof(fd_ip4_udp_hdrs_t) );
  return pub_sz-sizeof(fd_ip4_udp_hdrs_t);
}

static uchar const *
response( void ) {
  return pub_data+sizeof(fd_ip4_udp_hdrs_t);
}

/* A 3 FEC set block whose block id is computed independently. */

#define FEC_CNT (3U)
static ulong     blk_slot   = 500UL;
static ulong     blk_parent = 499UL;
static fd_hash_t blk_parent_id;
static fd_hash_t blk_id;
static uchar     blk_roots[ FEC_CNT ][ FD_SHRED_MERKLE_NODE_SZ ];

static void
make_block( void ) {
  memset( blk_parent_id.uc, 0x55, sizeof(fd_hash_t) );
  static uchar tree_mem[ FD_BMTREE_COMMIT_FOOTPRINT( 0UL ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( tree_mem, FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ, 0UL );
  fd_bmtree_node_t leaf[1];
  for( uint k=0U; k<FEC_CNT; k++ ) {
    memset( leaf->hash, (int)(0xA0+k), sizeof(leaf->hash) );
    memcpy( blk_roots[ k ], leaf->hash, FD_SHRED_MERKLE_NODE_SZ );
    fd_bmtree_commit_append( tree, leaf, 1UL );
  }
  uint cnt = FEC_CNT;
  fd_sha256_t s[1];
  fd_sha256_init  ( s );
  fd_sha256_append( s, &blk_parent,        sizeof(ulong)     );
  fd_sha256_append( s, blk_parent_id.uc,   sizeof(fd_hash_t) );
  fd_sha256_append( s, &cnt,               sizeof(uint)      );
  fd_sha256_fini  ( s, leaf->hash );
  fd_bmtree_commit_append( tree, leaf, 1UL );
  memcpy( blk_id.uc, fd_bmtree_commit_fini( tree ), sizeof(fd_hash_t) );
}

static ulong
now_ms( void ) {
  return (ulong)FD_NANOSEC_TO_MILLI( fd_log_wallclock() );
}

static void
test_meta_requests( void ) {
  static ctx_t ctx[1];
  setup( ctx, 1 );
  ping_cache_add( ctx );
  FD_TEST( fd_blockdb_insert( ctx->blockdb, blk_slot, &blk_id, blk_parent, &blk_parent_id, FEC_CNT, (uchar const *)blk_roots ) );

  uint      fec_set_cnt;
  ulong     parent_slot;
  fd_hash_t parent_block_id;
  uchar     root[ FD_SHRED_MERKLE_NODE_SZ ];
  uchar     proof[ FD_REPAIR_PROOF_MAX ];
  ulong     proof_sz;
  uint      nonce;

  /* ParentAndFecSetCount */
  ulong sz = request( ctx, req, parent_and_fec_set_count( &server_pub, now_ms(), 7U, blk_slot, &blk_id ) );
  FD_TEST( sz );
  FD_TEST( fd_repair_res_parent_fec_set_count_de( response(), sz, &fec_set_cnt, &parent_slot, &parent_block_id, proof, &proof_sz, &nonce )==sz );
  FD_TEST( nonce==7U );
  FD_TEST( fec_set_cnt==FEC_CNT );
  FD_TEST( parent_slot==blk_parent );
  FD_TEST( fd_hash_eq( &parent_block_id, &blk_parent_id ) );
  FD_TEST( !fd_repair_res_parent_fec_set_count_verify( fec_set_cnt, parent_slot, &parent_block_id, proof, proof_sz, &blk_id ) );
  FD_TEST( ctx->metrics->sent_pkt_types[ FD_METRICS_ENUM_REPAIR_RESPONSE_TYPE_V_PARENT_FEC_SET_COUNT_IDX ]==1UL );
  FD_TEST( ctx->metrics->received_request_count[ FD_METRICS_ENUM_REPAIR_REQUEST_TYPE_V_PARENT_FEC_SET_COUNT_IDX ]==1UL );

  /* FecSetRoot for every FEC set */
  for( uint k=0U; k<FEC_CNT; k++ ) {
    sz = request( ctx, req, fec_set_root( now_ms(), 100U+k, blk_slot, &blk_id, k*FD_FEC_SHRED_CNT ) );
    FD_TEST( sz );
    FD_TEST( fd_repair_res_fec_set_root_de( response(), sz, root, proof, &proof_sz, &nonce )==sz );
    FD_TEST( nonce==100U+k );
    FD_TEST( !memcmp( root, blk_roots[ k ], FD_SHRED_MERKLE_NODE_SZ ) );
    FD_TEST( !fd_repair_res_fec_set_root_verify( root, proof, proof_sz, &blk_id, k*FD_FEC_SHRED_CNT, FEC_CNT ) );
  }
  FD_TEST( ctx->metrics->sent_pkt_types[ FD_METRICS_ENUM_REPAIR_RESPONSE_TYPE_V_FEC_SET_ROOT_IDX ]==FEC_CNT );

  /* Unaligned and out of range FEC set indices are rejected */
  FD_TEST( !request( ctx, req, fec_set_root( now_ms(), 1U, blk_slot, &blk_id, FD_FEC_SHRED_CNT+1U ) ) );
  FD_TEST( !request( ctx, req, fec_set_root( now_ms(), 1U, blk_slot, &blk_id, FEC_CNT*FD_FEC_SHRED_CNT ) ) );
  FD_TEST( ctx->metrics->dropped[ FD_METRICS_ENUM_REQUEST_DROP_REASON_V_FEC_SET_INDEX_INVALID_IDX ]==2UL );

  /* Unknown blocks miss: other block id, or right block id in another slot */
  fd_hash_t other = blk_id; other.uc[ 5 ] ^= 1;
  FD_TEST( !request( ctx, req, parent_and_fec_set_count( &server_pub, now_ms(), 1U, blk_slot, &other ) ) );
  FD_TEST( !request( ctx, req, fec_set_root( now_ms(), 1U, blk_slot+1UL, &blk_id, 0U ) ) );
  FD_TEST( ctx->metrics->unanswered[ FD_METRICS_ENUM_REPAIR_REQUEST_TYPE_V_PARENT_FEC_SET_COUNT_IDX ]==1UL );
  FD_TEST( ctx->metrics->unanswered[ FD_METRICS_ENUM_REPAIR_REQUEST_TYPE_V_FEC_SET_ROOT_IDX        ]==1UL );

  /* Tampered after signing */
  sz = fec_set_root( now_ms(), 1U, blk_slot, &blk_id, 0U );
  FD_STORE( uint, req+sz-sizeof(uint), FD_FEC_SHRED_CNT );
  FD_TEST( !request( ctx, req, sz ) );
  FD_TEST( ctx->metrics->dropped[ FD_METRICS_ENUM_REQUEST_DROP_REASON_V_SIGNATURE_FAILED_IDX ]==1UL );

  /* Addressed to someone else */
  fd_pubkey_t someone = server_pub; someone.uc[ 0 ] ^= 1;
  FD_TEST( !request( ctx, req, parent_and_fec_set_count( &someone, now_ms(), 1U, blk_slot, &blk_id ) ) );
  FD_TEST( ctx->metrics->dropped[ FD_METRICS_ENUM_REQUEST_DROP_REASON_V_WRONG_RECIPIENT_IDX ]==1UL );

  /* Wrong size */
  sz = parent_and_fec_set_count( &server_pub, now_ms(), 1U, blk_slot, &blk_id );
  FD_TEST( !request( ctx, req, sz-1UL ) );
  FD_TEST( ctx->metrics->received_malformed_count[ FD_METRICS_ENUM_REQUEST_MALFORMED_REASON_V_WRONG_SIZE_IDX ]==1UL );

  /* Stale timestamp */
  FD_TEST( !request( ctx, req, parent_and_fec_set_count( &server_pub, now_ms()-FD_RSERVE_SIGNED_REPAIR_WINDOW-1000UL, 1U, blk_slot, &blk_id ) ) );
  FD_TEST( ctx->metrics->dropped[ FD_METRICS_ENUM_REQUEST_DROP_REASON_V_TIMESTAMP_SKEW_IDX ]==1UL );

  FD_LOG_NOTICE(( "pass: test_meta_requests" ));
}

/* Legacy requests still pass signature verification with the
   generalized signable size, then miss in the (absent) store. */

static void
test_legacy_sigverify( void ) {
  static ctx_t ctx[1];
  setup( ctx, 1 );
  ping_cache_add( ctx );

  FD_TEST( !request( ctx, req, window_index        ( now_ms(), 1U, 10UL, 3UL ) ) );
  FD_TEST( !request( ctx, req, highest_window_index( now_ms(), 1U, 10UL, 3UL ) ) );
  FD_TEST( !request( ctx, req, orphan              ( now_ms(), 1U, 10UL      ) ) );

  FD_TEST( ctx->metrics->dropped[ FD_METRICS_ENUM_REQUEST_DROP_REASON_V_SIGNATURE_FAILED_IDX ]==0UL );
  FD_TEST( ctx->metrics->disk_read[ FD_METRICS_ENUM_DISK_READ_RESULT_V_MISS_IDX ]==3UL );
  FD_LOG_NOTICE(( "pass: test_legacy_sigverify" ));
}

/* Without a blockdb, block id requests are dropped as unknown before
   any signature work. */

static void
test_no_blockdb( void ) {
  static ctx_t ctx[1];
  setup( ctx, 0 );
  ping_cache_add( ctx );

  FD_TEST( !request( ctx, req, parent_and_fec_set_count ( &server_pub, now_ms(), 1U, blk_slot, &blk_id ) ) );
  FD_TEST( !request( ctx, req, fec_set_root             ( now_ms(), 1U, blk_slot, &blk_id, 0U ) ) );
  FD_TEST( !request( ctx, req, window_index_for_block_id( now_ms(), 1U, blk_slot, &blk_id, 0U ) ) );
  FD_TEST( ctx->metrics->received_malformed_count[ FD_METRICS_ENUM_REQUEST_MALFORMED_REASON_V_UNKNOWN_TAG_IDX ]==3UL );
  FD_LOG_NOTICE(( "pass: test_no_blockdb" ));
}

/* ShredForBlockId against a real store.  An alternate version of shred
   33 is stored first, so it owns (slot,idx) and legacy requests serve
   it, while ShredForBlockId serves the block's own version. */

#define TEST_STORE_PATH "/tmp/test_rserve_tile_store.db"

static fd_shred_t *
make_shred( uchar buf[ FD_SHRED_MAX_SZ ],
            ulong slot,
            uint  idx,
            uchar marker ) {
  fd_memset( buf, 0, FD_SHRED_MAX_SZ );
  fd_shred_t * shred = fd_type_pun( buf );
  shred->variant   = fd_shred_variant( FD_SHRED_TYPE_LEGACY_DATA, 0 );
  shred->slot      = slot;
  shred->idx       = idx;
  shred->data.size = (ushort)(FD_SHRED_DATA_HEADER_SZ+1UL);
  buf[ FD_SHRED_DATA_HEADER_SZ ] = marker;
  return shred;
}

/* insert stores shred under a root whose first FD_SHRED_MERKLE_NODE_SZ
   bytes are root20. */

static void
insert( ctx_t *       ctx,
        fd_shred_t *  shred,
        uchar const * root20 ) {
  fd_hash_t root;
  memset( root.uc, 0x77, sizeof(fd_hash_t) );
  memcpy( root.uc, root20, FD_SHRED_MERKLE_NODE_SZ );
  FD_TEST( fd_store_disk_insert( ctx->store, ctx->disk_fd, shred, &root )==FD_STORE_DISK_INSERT_SUCCESS );
}

/* check_shred checks a response of sz bytes is shred (slot, idx) with
   marker, followed by nonce. */

static void
check_shred( ulong sz,
             ulong slot,
             uint  idx,
             uchar marker,
             uint  nonce ) {
  uchar const * res = response();
  fd_shred_t const * shred = fd_type_pun_const( res );
  FD_TEST( sz==fd_shred_sz( shred )+sizeof(uint) );
  FD_TEST( shred->slot==slot && shred->idx==idx && res[ FD_SHRED_DATA_HEADER_SZ ]==marker );
  FD_TEST( FD_LOAD( uint, res+sz-sizeof(uint) )==nonce );
}

static void
test_shred_for_block_id( fd_wksp_t * wksp ) {
  static ctx_t ctx[1];
  setup( ctx, 0 );
  ping_cache_add( ctx );

  ulong  footprint = fd_store_footprint( 8UL, 31840UL, 1UL, 0UL, 0UL, 1UL );
  void * store_mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  FD_TEST( store_mem );
  ctx->store = fd_store_join( fd_store_new( store_mem, 8UL, 31840UL, 1UL, 0UL, 0UL, FD_SHRED_BLK_MAX, 42UL, 1UL ) );
  FD_TEST( ctx->store );
  ctx->store->disk_max_shreds = 16UL;
  ctx->disk_fd = fd_store_file_create( TEST_STORE_PATH, ctx->store->wire_off, ctx->store->disk_max_shreds, BLK_MAX*FD_BLOCKDB_ROOTS_SZ );
  FD_TEST( ctx->disk_fd>=0 );

  /* One-block roots window: the next insert leaves the block's roots
     only in the store file tail. */
  ctx->blockdb = fd_blockdb_join( fd_blockdb_new( blockdb_mem, BLK_MAX, 1UL, 2UL, ctx->disk_fd, fd_store_tail_off( ctx->store ) ) );
  FD_TEST( ctx->blockdb );
  FD_TEST( fd_blockdb_insert( ctx->blockdb, blk_slot, &blk_id, blk_parent, &blk_parent_id, FEC_CNT, (uchar const *)blk_roots ) );
  fd_hash_t other_id = blk_id; other_id.uc[ 0 ] ^= 1;
  FD_TEST( fd_blockdb_insert( ctx->blockdb, blk_slot+1UL, &other_id, blk_slot, &blk_id, 1U, (uchar const *)blk_roots ) );
  FD_TEST( ctx->blockdb->wseq-fd_blockdb_query( ctx->blockdb, blk_slot, &blk_id )->wseq>ctx->blockdb->win_max );

  uchar buf[ FD_SHRED_MAX_SZ ];
  uchar alt_root[ FD_SHRED_MERKLE_NODE_SZ ];
  memset( alt_root, 0xEE, sizeof(alt_root) );
  insert( ctx, make_shred( buf, blk_slot, 33U, 0xEEU ), alt_root );
  insert( ctx, make_shred( buf, blk_slot,  0U, 0x00U ), blk_roots[ 0 ] );
  insert( ctx, make_shred( buf, blk_slot, 33U, 0x21U ), blk_roots[ 1 ] );
  insert( ctx, make_shred( buf, blk_slot, 95U, 0x5FU ), blk_roots[ 2 ] );

  /* Each FEC set's shred is served by root */
  uint const idxs   [ 3 ] = { 0U, 33U, 95U };
  uchar const marks [ 3 ] = { 0x00U, 0x21U, 0x5FU };
  for( ulong i=0UL; i<3UL; i++ ) {
    ulong sz = request( ctx, req, window_index_for_block_id( now_ms(), 200U+(uint)i, blk_slot, &blk_id, idxs[ i ] ) );
    FD_TEST( sz );
    check_shred( sz, blk_slot, idxs[ i ], marks[ i ], 200U+(uint)i );
  }
  FD_TEST( ctx->metrics->sent_pkt_types        [ FD_METRICS_ENUM_REPAIR_RESPONSE_TYPE_V_WINDOW_INDEX_FOR_BLOCK_ID_IDX ]==3UL );

  /* Proofs from roots read off disk verify */
  for( uint k=0U; k<FEC_CNT; k++ ) {
    uchar root[ FD_SHRED_MERKLE_NODE_SZ ];
    uchar proof[ FD_REPAIR_PROOF_MAX ];
    ulong proof_sz;
    uint  nonce;
    ulong rsz = request( ctx, req, fec_set_root( now_ms(), 300U+k, blk_slot, &blk_id, k*FD_FEC_SHRED_CNT ) );
    FD_TEST( fd_repair_res_fec_set_root_de( response(), rsz, root, proof, &proof_sz, &nonce )==rsz );
    FD_TEST( !memcmp( root, blk_roots[ k ], FD_SHRED_MERKLE_NODE_SZ ) );
    FD_TEST( !fd_repair_res_fec_set_root_verify( root, proof, proof_sz, &blk_id, k*FD_FEC_SHRED_CNT, FEC_CNT ) );
  }
  FD_TEST( ctx->metrics->received_request_count[ FD_METRICS_ENUM_REPAIR_REQUEST_TYPE_V_WINDOW_INDEX_FOR_BLOCK_ID_IDX  ]==3UL );

  /* The legacy request gets the alternate version */
  ulong sz = request( ctx, req, window_index( now_ms(), 9U, blk_slot, 33UL ) );
  FD_TEST( sz );
  check_shred( sz, blk_slot, 33U, 0xEEU, 9U );

  /* A shred of the block that isn't stored misses */
  ulong read_miss = ctx->metrics->disk_read[ FD_METRICS_ENUM_DISK_READ_RESULT_V_MISS_IDX ];
  FD_TEST( !request( ctx, req, window_index_for_block_id( now_ms(), 1U, blk_slot, &blk_id, 1U ) ) );
  FD_TEST( ctx->metrics->disk_read[ FD_METRICS_ENUM_DISK_READ_RESULT_V_MISS_IDX ]==read_miss+1UL );

  /* An unknown block misses */
  fd_hash_t other = blk_id; other.uc[ 3 ] ^= 1;
  FD_TEST( !request( ctx, req, window_index_for_block_id( now_ms(), 1U, blk_slot, &other, 0U ) ) );
  FD_TEST( ctx->metrics->unanswered[ FD_METRICS_ENUM_REPAIR_REQUEST_TYPE_V_WINDOW_INDEX_FOR_BLOCK_ID_IDX ]==2UL );

  /* Past the end of the block */
  FD_TEST( !request( ctx, req, window_index_for_block_id( now_ms(), 1U, blk_slot, &blk_id, FEC_CNT*FD_FEC_SHRED_CNT ) ) );
  FD_TEST( ctx->metrics->dropped[ FD_METRICS_ENUM_REQUEST_DROP_REASON_V_SHRED_INDEX_INVALID_IDX ]==1UL );

  /* Tampered after signing */
  sz = window_index_for_block_id( now_ms(), 1U, blk_slot, &blk_id, 0U );
  FD_STORE( uint, req+FD_REPAIR_HEADER_SER_SZ+sizeof(ulong), 95U );
  FD_TEST( !request( ctx, req, sz ) );
  FD_TEST( ctx->metrics->dropped[ FD_METRICS_ENUM_REQUEST_DROP_REASON_V_SIGNATURE_FAILED_IDX ]==1UL );

  /* Wrong size */
  sz = window_index_for_block_id( now_ms(), 1U, blk_slot, &blk_id, 0U );
  FD_TEST( !request( ctx, req, sz-1UL ) );
  FD_TEST( ctx->metrics->received_malformed_count[ FD_METRICS_ENUM_REQUEST_MALFORMED_REASON_V_WRONG_SIZE_IDX ]==1UL );

  close( ctx->disk_fd );
  FD_TEST( !unlink( TEST_STORE_PATH ) );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( ctx->store ) ) );
  FD_LOG_NOTICE(( "pass: test_shred_for_block_id" ));
}

/* The sign tile's half of the request: sign the token with the server
   key and hand back the signature with sig echoed, as after_frag would
   deliver it. */

static void
sign_reply( ctx_t * ctx,
            ulong   sig ) {
  FD_TEST( sign_req_sz==32UL );
  FD_TEST( (uint)sig==FD_KEYGUARD_SIGN_TYPE_ED25519 );
  fd_ed25519_sign( ctx->sign_buf, sign_req, 32UL, server_pub.uc, server_priv, sha );
  handle_sign( ctx, NULL, sig );
}

/* check_ping checks the last packet is a ping of variant block_id to
   the client, carrying token signed by the server key. */

static void
check_ping( int           block_id,
            uchar const * token ) {
  fd_ip4_udp_hdrs_t const * hdr = (fd_ip4_udp_hdrs_t const *)pub_data;
  FD_TEST( hdr->ip4->daddr==CLIENT_IP && hdr->ip4->saddr==0x0A000001U && hdr->udp->net_dport==CLIENT_PORT );

  fd_pubkey_t      from;
  fd_hash_t        tok;
  fd_ed25519_sig_t sig;
  ulong            sz = pub_sz-sizeof(fd_ip4_udp_hdrs_t);
  if( block_id ) {
    FD_TEST( fd_repair_block_id_ping_de( response(), sz, &from, &tok, sig )==sz );
    FD_TEST( !fd_repair_ping_de        ( response(), sz, &from, &tok, sig ) );
  } else {
    FD_TEST( fd_repair_ping_de         ( response(), sz, &from, &tok, sig )==sz );
    FD_TEST( !fd_repair_block_id_ping_de( response(), sz, &from, &tok, sig ) );
  }
  FD_TEST( fd_pubkey_eq( &from, &server_pub ) );
  FD_TEST( !memcmp( tok.uc, token, 32UL ) );
  FD_TEST( fd_ed25519_verify( tok.uc, 32UL, sig, server_pub.uc, sha )==FD_ED25519_SUCCESS );
}

/* A request from a client that never ponged is answered with a ping
   once the sign tile signs its token.  Nothing is sent before then. */

static void
test_ping_async( void ) {
  static ctx_t ctx[1];
  setup( ctx, 1 );
  FD_TEST( fd_blockdb_insert( ctx->blockdb, blk_slot, &blk_id, blk_parent, &blk_parent_id, FEC_CNT, (uchar const *)blk_roots ) );

  uchar expect[ 32 ];
  fd_rserve_ping_token( ctx->rserve, expect, &client_pub, CLIENT_IP, CLIENT_PORT );

  /* Two requests in flight, answered out of order */
  FD_TEST( !request( ctx, req, parent_and_fec_set_count( &server_pub, now_ms(), 1U, blk_slot, &blk_id ) ) );
  FD_TEST( sign_req_cnt==1UL && !memcmp( sign_req, expect, 32UL ) );
  ulong sig0 = sign_req_sig;
  uchar req0[ 32 ]; memcpy( req0, sign_req, 32UL );

  FD_TEST( !request( ctx, req, window_index_for_block_id( now_ms(), 2U, blk_slot, &blk_id, 0U ) ) );
  FD_TEST( sign_req_cnt==2UL && !memcmp( sign_req, expect, 32UL ) );
  ulong sig1 = sign_req_sig;
  FD_TEST( (sig0>>32)!=(sig1>>32) );
  FD_TEST( sign_pool_used( ctx->sign_pool )==2UL );
  FD_TEST( pub_cnt==0UL );

  sign_reply( ctx, sig1 );
  FD_TEST( pub_cnt==1UL );
  check_ping( 0, expect );

  memcpy( sign_req, req0, 32UL );
  sign_reply( ctx, sig0 );
  FD_TEST( pub_cnt==2UL );
  check_ping( 1, expect );

  FD_TEST( sign_pool_used( ctx->sign_pool )==0UL );
  FD_TEST( ctx->metrics->sent_pkt_types[ FD_METRICS_ENUM_REPAIR_RESPONSE_TYPE_V_PING_IDX ]==2UL );
  FD_TEST( ctx->metrics->send_pkt_cnt==2UL );
  FD_LOG_NOTICE(( "pass: test_ping_async" ));
}

/* With every sign slot taken, a ping is dropped instead of waiting. */

static void
test_ping_pool_full( void ) {
  static ctx_t ctx[1];
  setup( ctx, 0 );

  /* Orphan skips the store probe, which misses with no store */
  for( ulong i=0UL; i<SIGN_DEPTH; i++ ) FD_TEST( !request( ctx, req, orphan( now_ms(), 1U, 10UL ) ) );
  FD_TEST( sign_req_cnt==SIGN_DEPTH );
  FD_TEST( !sign_pool_free( ctx->sign_pool ) );
  ulong unanswered = ctx->metrics->unanswered[ FD_METRICS_ENUM_REPAIR_REQUEST_TYPE_V_ORPHAN_IDX ];
  FD_TEST( !request( ctx, req, orphan( now_ms(), 1U, 10UL ) ) );
  FD_TEST( sign_req_cnt==SIGN_DEPTH );
  FD_TEST( ctx->metrics->unanswered[ FD_METRICS_ENUM_REPAIR_REQUEST_TYPE_V_ORPHAN_IDX ]==unanswered+1UL );

  /* A returned signature frees its slot */
  sign_reply( ctx, sign_req_sig );
  FD_TEST( pub_cnt==1UL );
  FD_TEST( !request( ctx, req, orphan( now_ms(), 1U, 10UL ) ) );
  FD_TEST( sign_req_cnt==SIGN_DEPTH+1UL );
  FD_LOG_NOTICE(( "pass: test_ping_pool_full" ));
}

/* A keyswitch halts new sign requests at once, but only completes once
   every outstanding request has returned under the old key. */

static void
test_ping_keyswitch( void ) {
  static ctx_t ctx[1];
  setup( ctx, 0 );

  FD_TEST( !request( ctx, req, orphan( now_ms(), 1U, 10UL ) ) );
  FD_TEST( sign_req_cnt==1UL );
  ulong sig0 = sign_req_sig;
  uchar expect[ 32 ];
  memcpy( expect, sign_req, 32UL ); /* housekeeping may rotate the token secret */

  fd_pubkey_t new_key; memset( new_key.uc, 0x42, sizeof(fd_pubkey_t) );
  memcpy( ctx->keyswitch->bytes, new_key.uc, 32UL );
  fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_SWITCH_PENDING );
  during_housekeeping( ctx );
  FD_TEST( ctx->halt_signing );
  FD_TEST( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING );

  /* No new requests while halted */
  FD_TEST( !request( ctx, req, orphan( now_ms(), 1U, 10UL ) ) );
  FD_TEST( sign_req_cnt==1UL );
  during_housekeeping( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_SWITCH_PENDING );

  /* The outstanding ping goes out under the old identity */
  sign_reply( ctx, sig0 );
  FD_TEST( pub_cnt==1UL );
  check_ping( 0, expect );

  during_housekeeping( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( ctx->halt_signing );

  fd_keyswitch_state( ctx->keyswitch, FD_KEYSWITCH_STATE_UNHALT_PENDING );
  during_housekeeping( ctx );
  FD_TEST( fd_keyswitch_state_query( ctx->keyswitch )==FD_KEYSWITCH_STATE_COMPLETED );
  FD_TEST( !ctx->halt_signing );
  FD_TEST( fd_pubkey_eq( &ctx->identity_public_key, &new_key ) );
  FD_LOG_NOTICE(( "pass: test_ping_keyswitch" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_sha512_new( sha );
  for( ulong i=0UL; i<32UL; i++ ) client_priv[ i ] = (uchar)(i+1UL);
  fd_ed25519_public_from_private( client_pub.uc, client_priv, sha );
  for( ulong i=0UL; i<32UL; i++ ) server_priv[ i ] = (uchar)(0x80+i);
  fd_ed25519_public_from_private( server_pub.uc, server_priv, sha );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"               );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL                      );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0UL ) );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  make_block();
  test_meta_requests     ();
  test_legacy_sigverify  ();
  test_no_blockdb        ();
  test_shred_for_block_id( wksp );
  test_ping_async        ();
  test_ping_pool_full    ();
  test_ping_keyswitch    ();

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
