/* test_rserve_tile drives rserve's request path with signed requests,
   with fd_stem_publish mocked to capture sent packets.  Covers the
   Alpenglow metadata requests end to end and the shared validation. */

#include "../../disco/topo/fd_topo.h" /* pulls in fd_stem.h so the static inline parses */

static uchar * test_out_mem;
static uchar   pub_data[ 2048 ];
static ulong   pub_sz;
static ulong   pub_cnt;

static void
test_stem_publish( ulong chunk,
                   ulong sz ) {
  FD_TEST( sz<=sizeof(pub_data) );
  fd_memcpy( pub_data, fd_chunk_to_laddr( test_out_mem, chunk ), sz );
  pub_sz = sz;
  pub_cnt++;
}

#define fd_stem_publish( stem, out_idx, sig, chunk, sz, ctl, tsorig, tspub )             \
  do { (void)(stem); (void)(out_idx); (void)(sig); (void)(ctl); (void)(tsorig);          \
       (void)(tspub); test_stem_publish( (chunk), (sz) ); } while(0)

#include "fd_rserve_tile.c"

#include <unistd.h>
#include "../../ballet/sha256/fd_sha256.h"

#define PING_MAX (16UL)
#define BLK_MAX  (4UL)

static uchar rserve_mem [ 1UL<<16 ] __attribute__((aligned(128)));
static uchar blockdb_mem[ 1UL<<20 ] __attribute__((aligned(FD_BLOCKDB_ALIGN)));
static uchar repair_mem [ 4096    ] __attribute__((aligned(128)));
static uchar out_mem    [ 1UL<<16 ] __attribute__((aligned(FD_CHUNK_ALIGN)));

static uchar       client_priv[ 32 ];
static fd_pubkey_t client_pub;
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
    FD_TEST( fd_blockdb_footprint( BLK_MAX )<=sizeof(blockdb_mem) );
    ctx->blockdb = fd_blockdb_join( fd_blockdb_new( blockdb_mem, BLK_MAX, 2UL ) );
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

/* sign signs msg in place as the client and returns its wire size. */

static ulong
sign( fd_repair_msg_t * msg ) {
  ulong preimage_sz;
  uchar * preimage = preimage_req( msg, &preimage_sz );
  uchar sig[ 64 ];
  fd_ed25519_sign( sig, preimage, preimage_sz, client_pub.uc, client_priv, sha );
  memcpy( msg->header.sig, sig, 64UL );
  return fd_repair_sz( msg );
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
test_meta_requests( fd_repair_t * client ) {
  static ctx_t ctx[1];
  setup( ctx, 1 );
  ping_cache_add( ctx );
  FD_TEST( fd_blockdb_insert( ctx->blockdb, blk_slot, &blk_id, blk_parent, &blk_parent_id, FEC_CNT, (uchar const *)blk_roots ) );

  ag_repair_response_t res[1];

  /* ParentAndFecSetCount */
  fd_repair_msg_t * msg = ag_repair_parent_and_fec_set_count( client, &server_pub, now_ms(), 7U, blk_slot, &blk_id );
  ulong sz = request( ctx, (uchar const *)msg, sign( msg ) );
  FD_TEST( sz );
  FD_TEST( !ag_repair_response_de( res, response(), sz, FD_FEC_BLK_MAX ) );
  FD_TEST( res->kind==AG_REPAIR_RESPONSE_PARENT_FEC_SET_COUNT && res->nonce==7U );
  FD_TEST( res->parent_fec_set_res.fec_set_count==FEC_CNT );
  FD_TEST( res->parent_fec_set_res.parent_slot==blk_parent );
  FD_TEST( fd_hash_eq( &res->parent_fec_set_res.parent_block_id, &blk_parent_id ) );
  FD_TEST( !ag_repair_parent_fec_count_verify( &res->parent_fec_set_res, &blk_id ) );
  FD_TEST( ctx->metrics->sent_pkt_types[ FD_METRICS_ENUM_RSERVE_SENT_RESPONSE_TYPES_V_PARENT_FEC_SET_COUNT_IDX ]==1UL );
  FD_TEST( ctx->metrics->received_request_count[ FD_METRICS_ENUM_RSERVE_REQUEST_TYPES_V_PARENT_FEC_SET_COUNT_IDX ]==1UL );

  /* FecSetRoot for every FEC set */
  for( uint k=0U; k<FEC_CNT; k++ ) {
    msg = ag_repair_fec_set_root( client, &server_pub, now_ms(), 100U+k, blk_slot, &blk_id, k*FD_FEC_SHRED_CNT );
    sz  = request( ctx, (uchar const *)msg, sign( msg ) );
    FD_TEST( sz );
    FD_TEST( !ag_repair_response_de( res, response(), sz, FD_FEC_BLK_MAX ) );
    FD_TEST( res->kind==AG_REPAIR_RESPONSE_FEC_SET_ROOT && res->nonce==100U+k );
    FD_TEST( !memcmp( res->fec_set_root.root, blk_roots[ k ], FD_SHRED_MERKLE_NODE_SZ ) );
    FD_TEST( !ag_repair_fec_set_root_verify( &res->fec_set_root, &blk_id, k*FD_FEC_SHRED_CNT, FEC_CNT ) );
  }
  FD_TEST( ctx->metrics->sent_pkt_types[ FD_METRICS_ENUM_RSERVE_SENT_RESPONSE_TYPES_V_FEC_SET_ROOT_IDX ]==FEC_CNT );

  /* Unaligned and out of range FEC set indices are rejected */
  msg = ag_repair_fec_set_root( client, &server_pub, now_ms(), 1U, blk_slot, &blk_id, FD_FEC_SHRED_CNT+1U );
  FD_TEST( !request( ctx, (uchar const *)msg, sign( msg ) ) );
  msg = ag_repair_fec_set_root( client, &server_pub, now_ms(), 1U, blk_slot, &blk_id, FEC_CNT*FD_FEC_SHRED_CNT );
  FD_TEST( !request( ctx, (uchar const *)msg, sign( msg ) ) );
  FD_TEST( ctx->metrics->fail_invalid_fec_set_idx==2UL );

  /* Unknown blocks miss: other block id, or right block id in another slot */
  fd_hash_t other = blk_id; other.uc[ 5 ] ^= 1;
  msg = ag_repair_parent_and_fec_set_count( client, &server_pub, now_ms(), 1U, blk_slot, &other );
  FD_TEST( !request( ctx, (uchar const *)msg, sign( msg ) ) );
  msg = ag_repair_fec_set_root( client, &server_pub, now_ms(), 1U, blk_slot+1UL, &blk_id, 0U );
  FD_TEST( !request( ctx, (uchar const *)msg, sign( msg ) ) );
  FD_TEST( ctx->metrics->missed_pkt_types[ FD_METRICS_ENUM_RSERVE_SENT_RESPONSE_TYPES_V_PARENT_FEC_SET_COUNT_IDX ]==1UL );
  FD_TEST( ctx->metrics->missed_pkt_types[ FD_METRICS_ENUM_RSERVE_SENT_RESPONSE_TYPES_V_FEC_SET_ROOT_IDX        ]==1UL );

  /* Tampered after signing */
  msg = ag_repair_fec_set_root( client, &server_pub, now_ms(), 1U, blk_slot, &blk_id, 0U );
  sz  = sign( msg );
  msg->fec_set_root.fec_set_idx = FD_FEC_SHRED_CNT;
  FD_TEST( !request( ctx, (uchar const *)msg, sz ) );
  FD_TEST( ctx->metrics->fail_sigverify_request==1UL );

  /* Addressed to someone else */
  fd_pubkey_t someone = server_pub; someone.uc[ 0 ] ^= 1;
  msg = ag_repair_parent_and_fec_set_count( client, &someone, now_ms(), 1U, blk_slot, &blk_id );
  FD_TEST( !request( ctx, (uchar const *)msg, sign( msg ) ) );
  FD_TEST( ctx->metrics->fail_not_for_us==1UL );

  /* Wrong size */
  msg = ag_repair_parent_and_fec_set_count( client, &server_pub, now_ms(), 1U, blk_slot, &blk_id );
  sz  = sign( msg );
  FD_TEST( !request( ctx, (uchar const *)msg, sz-1UL ) );
  FD_TEST( ctx->metrics->received_malformed_count[ FD_METRICS_ENUM_RSERVE_MALFORMED_TYPES_V_WRONG_SIZE_IDX ]==1UL );

  /* Stale timestamp */
  msg = ag_repair_parent_and_fec_set_count( client, &server_pub, now_ms()-FD_RSERVE_SIGNED_REPAIR_WINDOW-1000UL, 1U, blk_slot, &blk_id );
  FD_TEST( !request( ctx, (uchar const *)msg, sign( msg ) ) );
  FD_TEST( ctx->metrics->fail_outdated==1UL );

  FD_LOG_NOTICE(( "pass: test_meta_requests" ));
}

/* Legacy requests still pass signature verification with the
   generalized signable size, then miss in the (absent) store. */

static void
test_legacy_sigverify( fd_repair_t * client ) {
  static ctx_t ctx[1];
  setup( ctx, 1 );
  ping_cache_add( ctx );

  fd_repair_msg_t * msg = fd_repair_shred( client, &server_pub, now_ms(), 1U, 10UL, 3UL );
  FD_TEST( !request( ctx, (uchar const *)msg, sign( msg ) ) );
  msg = fd_repair_highest_shred( client, &server_pub, now_ms(), 1U, 10UL, 3UL );
  FD_TEST( !request( ctx, (uchar const *)msg, sign( msg ) ) );
  msg = fd_repair_orphan( client, &server_pub, now_ms(), 1U, 10UL );
  FD_TEST( !request( ctx, (uchar const *)msg, sign( msg ) ) );

  FD_TEST( ctx->metrics->fail_sigverify_request==0UL );
  FD_TEST( ctx->metrics->disk_read_miss==3UL );
  FD_LOG_NOTICE(( "pass: test_legacy_sigverify" ));
}

/* Without a blockdb, block id requests are dropped as unknown before
   any signature work. */

static void
test_no_blockdb( fd_repair_t * client ) {
  static ctx_t ctx[1];
  setup( ctx, 0 );
  ping_cache_add( ctx );

  fd_repair_msg_t * msg = ag_repair_parent_and_fec_set_count( client, &server_pub, now_ms(), 1U, blk_slot, &blk_id );
  FD_TEST( !request( ctx, (uchar const *)msg, sign( msg ) ) );
  msg = ag_repair_fec_set_root( client, &server_pub, now_ms(), 1U, blk_slot, &blk_id, 0U );
  FD_TEST( !request( ctx, (uchar const *)msg, sign( msg ) ) );
  msg = ag_repair_shred_block_id( client, &server_pub, now_ms(), 1U, blk_slot, &blk_id, 0U );
  FD_TEST( !request( ctx, (uchar const *)msg, sign( msg ) ) );
  FD_TEST( ctx->metrics->received_malformed_count[ FD_METRICS_ENUM_RSERVE_MALFORMED_TYPES_V_UNKNOWN_TAG_IDX ]==3UL );
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
test_shred_for_block_id( fd_repair_t * client,
                         fd_wksp_t *   wksp ) {
  static ctx_t ctx[1];
  setup( ctx, 1 );
  ping_cache_add( ctx );
  FD_TEST( fd_blockdb_insert( ctx->blockdb, blk_slot, &blk_id, blk_parent, &blk_parent_id, FEC_CNT, (uchar const *)blk_roots ) );

  ulong  footprint = fd_store_footprint( 8UL, 31840UL, 1UL, 0UL, 0UL );
  void * store_mem = fd_wksp_alloc_laddr( wksp, fd_store_align(), footprint, 1UL );
  FD_TEST( store_mem );
  ctx->store = fd_store_join( fd_store_new( store_mem, 8UL, 31840UL, 1UL, 0UL, 0UL, FD_SHRED_BLK_MAX, 42UL ) );
  FD_TEST( ctx->store );
  ctx->store->disk_max_shreds = 16UL;
  ctx->disk_fd = fd_store_file_create( TEST_STORE_PATH, ctx->store->wire_off, ctx->store->disk_max_shreds );
  FD_TEST( ctx->disk_fd>=0 );

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
    fd_repair_msg_t * msg = ag_repair_shred_block_id( client, &server_pub, now_ms(), 200U+(uint)i, blk_slot, &blk_id, idxs[ i ] );
    ulong sz = request( ctx, (uchar const *)msg, sign( msg ) );
    FD_TEST( sz );
    check_shred( sz, blk_slot, idxs[ i ], marks[ i ], 200U+(uint)i );
  }
  FD_TEST( ctx->metrics->sent_pkt_types        [ FD_METRICS_ENUM_RSERVE_SENT_RESPONSE_TYPES_V_SHRED_FOR_BLOCK_ID_IDX ]==3UL );
  FD_TEST( ctx->metrics->received_request_count[ FD_METRICS_ENUM_RSERVE_REQUEST_TYPES_V_SHRED_FOR_BLOCK_ID_IDX       ]==3UL );

  /* The legacy request gets the alternate version */
  fd_repair_msg_t * msg = fd_repair_shred( client, &server_pub, now_ms(), 9U, blk_slot, 33UL );
  ulong sz = request( ctx, (uchar const *)msg, sign( msg ) );
  FD_TEST( sz );
  check_shred( sz, blk_slot, 33U, 0xEEU, 9U );

  /* A shred of the block that isn't stored misses */
  ulong read_miss = ctx->metrics->disk_read_miss;
  msg = ag_repair_shred_block_id( client, &server_pub, now_ms(), 1U, blk_slot, &blk_id, 1U );
  FD_TEST( !request( ctx, (uchar const *)msg, sign( msg ) ) );
  FD_TEST( ctx->metrics->disk_read_miss==read_miss+1UL );

  /* An unknown block misses */
  fd_hash_t other = blk_id; other.uc[ 3 ] ^= 1;
  msg = ag_repair_shred_block_id( client, &server_pub, now_ms(), 1U, blk_slot, &other, 0U );
  FD_TEST( !request( ctx, (uchar const *)msg, sign( msg ) ) );
  FD_TEST( ctx->metrics->missed_pkt_types[ FD_METRICS_ENUM_RSERVE_SENT_RESPONSE_TYPES_V_SHRED_FOR_BLOCK_ID_IDX ]==2UL );

  /* Past the end of the block */
  msg = ag_repair_shred_block_id( client, &server_pub, now_ms(), 1U, blk_slot, &blk_id, FEC_CNT*FD_FEC_SHRED_CNT );
  FD_TEST( !request( ctx, (uchar const *)msg, sign( msg ) ) );
  FD_TEST( ctx->metrics->fail_invalid_shred_idx==1UL );

  /* Tampered after signing */
  msg = ag_repair_shred_block_id( client, &server_pub, now_ms(), 1U, blk_slot, &blk_id, 0U );
  sz  = sign( msg );
  msg->shred_block_id.shred_idx = 95U;
  FD_TEST( !request( ctx, (uchar const *)msg, sz ) );
  FD_TEST( ctx->metrics->fail_sigverify_request==1UL );

  /* Wrong size */
  msg = ag_repair_shred_block_id( client, &server_pub, now_ms(), 1U, blk_slot, &blk_id, 0U );
  sz  = sign( msg );
  FD_TEST( !request( ctx, (uchar const *)msg, sz-1UL ) );
  FD_TEST( ctx->metrics->received_malformed_count[ FD_METRICS_ENUM_RSERVE_MALFORMED_TYPES_V_WRONG_SIZE_IDX ]==1UL );

  close( ctx->disk_fd );
  FD_TEST( !unlink( TEST_STORE_PATH ) );
  fd_wksp_free_laddr( fd_store_delete( fd_store_leave( ctx->store ) ) );
  FD_LOG_NOTICE(( "pass: test_shred_for_block_id" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_sha512_new( sha );
  for( ulong i=0UL; i<32UL; i++ ) client_priv[ i ] = (uchar)(i+1UL);
  fd_ed25519_public_from_private( client_pub.uc, client_priv, sha );
  memset( server_pub.uc, 0x99, sizeof(fd_pubkey_t) );

  /* fd_repair_join only adds a workspace check, so skip it to avoid
     needing huge pages. */
  FD_TEST( fd_repair_footprint()<=sizeof(repair_mem) );
  fd_repair_t * client = (fd_repair_t *)fd_repair_new( repair_mem, &client_pub );
  FD_TEST( client );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"               );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL                      );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0UL ) );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  make_block();
  test_meta_requests     ( client );
  test_legacy_sigverify  ( client );
  test_no_blockdb        ( client );
  test_shred_for_block_id( client, wksp );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
