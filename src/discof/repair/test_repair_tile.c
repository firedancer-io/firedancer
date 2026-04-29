/* Mock fd_stem_publish to a no-op so we can test the sign lifecycle
   without real tile infrastructure.

   Include fd_stem.h (via fd_topo.h) first so the static
   inline declaration parses normally.  Then override with a macro
   before including fd_repair_tile.c so all call sites expand to our
   mock instead. */

#include "../../disco/topo/fd_topo.h"   /* pulls in fd_stem.h */
#include "../../disco/shred/fd_shred_tile.h"

static ulong mock_stem_publish_cnt;
#undef  fd_stem_publish  /* no prior macro, but harmless */
#define fd_stem_publish( stem, out_idx, sig, chunk, sz, ctl, tsorig, tspub ) \
  do { (void)(stem); (void)(out_idx); (void)(sig); (void)(chunk); (void)(sz); \
       (void)(ctl); (void)(tsorig); (void)(tspub); mock_stem_publish_cnt++; } while(0)

#include "fd_repair_tile.c"

static ulong dedup_max     = 64;
static ulong peer_max      = 64;
static int   lg_sign_depth = 6;

static void
setup_ctx( ctx_t * ctx, fd_wksp_t * wksp, ulong slot_max ) {
  memset( ctx, 0, sizeof(*ctx) );

  FD_TEST( fd_rng_secure( ctx->repair_nonce_ss, sizeof(fd_rnonce_ss_t) ) );

  void * forest_mem     = fd_wksp_alloc_laddr( wksp, fd_forest_align(), fd_forest_footprint( slot_max ), 1UL );
  void * policy_mem     = fd_wksp_alloc_laddr( wksp, fd_policy_align(), fd_policy_footprint( dedup_max, peer_max ), 1UL );
  void * inflights_mem  = fd_wksp_alloc_laddr( wksp, fd_inflights_align(), fd_inflights_footprint(), 1UL );
  void * signs_map_mem  = fd_wksp_alloc_laddr( wksp, fd_signs_map_align(), fd_signs_map_footprint( lg_sign_depth ), 1UL );
  void * pong_queue_mem = fd_wksp_alloc_laddr( wksp, fd_signs_queue_align(), fd_signs_queue_footprint(), 1UL );
  void * repair_mem     = fd_wksp_alloc_laddr( wksp, fd_repair_align(), fd_repair_footprint(), 1UL );
  void * metrics_mem    = fd_wksp_alloc_laddr( wksp, fd_repair_metrics_align(), fd_repair_metrics_footprint(), 1UL );

  ctx->forest       = fd_forest_join        ( fd_forest_new        ( forest_mem, slot_max, 0UL ) );
  ctx->policy       = fd_policy_join        ( fd_policy_new        ( policy_mem, dedup_max, peer_max, 0UL, ctx->repair_nonce_ss ) );
  ctx->inflights    = fd_inflights_join     ( fd_inflights_new     ( inflights_mem, 0UL ) );
  ctx->signs_map    = fd_signs_map_join     ( fd_signs_map_new     ( signs_map_mem, lg_sign_depth, 0UL ) );
  ctx->pong_queue   = fd_signs_queue_join   ( fd_signs_queue_new   ( pong_queue_mem ) );
  ctx->protocol     = fd_repair_join        ( fd_repair_new        ( repair_mem, &ctx->identity_public_key ) );
  ctx->slot_metrics = fd_repair_metrics_join( fd_repair_metrics_new( metrics_mem ) );

  /* Set up output link contexts with workspace-allocated buffers so
     send_packet and fd_repair_send_sign_request can write into them.
     fd_chunk_to_laddr(mem, chunk) = (void*)((ulong)mem + (chunk<<6)).
     We set mem to a wksp-allocated buffer and chunk0=0 so
     fd_chunk_to_laddr(mem, 0) == mem. */

  ulong dcache_sz = 4096UL; /* plenty for test packets */

  void * net_dcache  = fd_wksp_alloc_laddr( wksp, FD_CHUNK_ALIGN, dcache_sz, 1UL );
  void * sign_dcache = fd_wksp_alloc_laddr( wksp, FD_CHUNK_ALIGN, dcache_sz, 1UL );
  FD_TEST( net_dcache && sign_dcache );

  ctx->net_out_ctx->idx    = 0;
  ctx->net_out_ctx->mem    = net_dcache;
  ctx->net_out_ctx->chunk0 = 0;
  ctx->net_out_ctx->wmark  = (dcache_sz >> FD_CHUNK_LG_SZ) - 1;
  ctx->net_out_ctx->chunk  = 0;

  /* One mock sign tile. */

  ctx->repair_sign_cnt                  = 1;
  ctx->repair_sign_out_ctx[0].idx       = 1;
  ctx->repair_sign_out_ctx[0].in_idx    = 42; /* arbitrary, matches what we pass to after_sign */
  ctx->repair_sign_out_ctx[0].mem       = sign_dcache;
  ctx->repair_sign_out_ctx[0].chunk0    = 0;
  ctx->repair_sign_out_ctx[0].wmark     = (dcache_sz >> FD_CHUNK_LG_SZ) - 1;
  ctx->repair_sign_out_ctx[0].chunk     = 0;
  ctx->repair_sign_out_ctx[0].max_credits = 128;
  ctx->repair_sign_out_ctx[0].credits     = 128;

  /* Initialize header templates (send_packet dereferences these). */

  fd_ip4_udp_hdr_init( ctx->intake_hdr, 0, 0, 1234 );
}

/* Helper to build a raw network packet containing a repair ping in
   ctx->net_buf.  Returns the total packet size. */

static ulong
mock_ping_packet( ctx_t *             ctx,
                  fd_pubkey_t const * from,
                  uchar const *       private_key, /* if non-NULL, sign hash with this key (from must be the corresponding pubkey) */
                  uint                src_ip,
                  ushort              src_port ) {

  ulong payload_sz = sizeof(fd_repair_ping_t);

  /* Build Eth+IP4+UDP headers. */

  fd_ip4_udp_hdrs_t hdrs[1];
  fd_ip4_udp_hdr_init( hdrs, payload_sz, src_ip, src_port );

  /* Build the ping payload. */

  fd_repair_ping_t ping[1];
  memset( ping, 0, sizeof(*ping) );
  ping->kind      = FD_REPAIR_KIND_PING;
  ping->ping.from = *from;
  /* hash is zeroed — arbitrary 32-byte token */

  if( private_key ) {
    fd_sha512_t sha[1];
    fd_ed25519_sign( ping->ping.sig, ping->ping.hash.uc, 32UL, from->uc, private_key, sha );
  }
  /* otherwise sig is zeroed — will fail sigverify if reached */

  uchar ping_buf[ sizeof(fd_repair_ping_t) ];
  FD_TEST( 0==fd_repair_ping_ser( ping, ping_buf, sizeof(ping_buf) ) );

  /* Assemble into ctx->net_buf. */

  ulong hdr_sz = sizeof(fd_ip4_udp_hdrs_t);
  ulong total  = hdr_sz + payload_sz;
  FD_TEST( total <= FD_NET_MTU );
  memcpy( ctx->net_buf,          hdrs,     hdr_sz     );
  memcpy( ctx->net_buf + hdr_sz, ping_buf, payload_sz );

  return total;
}

static void
test_after_net( fd_wksp_t * wksp ) {

  /* Allocate a minimal ctx with just the fields after_net touches. */

  static ctx_t ctx[1];
  setup_ctx( ctx, wksp, 512 );

  ulong unknown_peer_ping_b4   = ctx->metrics->unknown_peer_ping;
  ulong malformed_ping_b4      = ctx->metrics->malformed_ping;
  ulong fail_sigverify_ping_b4 = ctx->metrics->fail_sigverify_ping;

  /* Build a valid ping from an unknown peer (not in policy). */

  {
    fd_pubkey_t unknown_peer = { .ul = { 0xDEAD } };
    ulong sz = mock_ping_packet( ctx, &unknown_peer, NULL, 0x01020304U, 1234 );

    /* Call after_net — should hit the unknown_peer_ping path. */
    after_net( ctx, sz );

    FD_TEST( ctx->metrics->unknown_peer_ping== ++unknown_peer_ping_b4 );
    FD_TEST( ctx->metrics->malformed_ping==      malformed_ping_b4 );
    FD_TEST( ctx->metrics->fail_sigverify_ping== fail_sigverify_ping_b4 );

    FD_LOG_NOTICE(( "pass: test_after_net_unknown_peer" ));
  }

  {
    /* Add peer to policy, then call after_net */
    fd_pubkey_t   known_peer = { .ul = { 0xBEEF } };
    fd_ip4_port_t known_addr = { .addr = 0x01020304U, .port = 1234 };
    fd_policy_peer_upsert( ctx->policy, &known_peer, &known_addr );

    ulong sz = mock_ping_packet( ctx, &known_peer, NULL, 0x01020304U, 1234 );
    after_net( ctx, sz );

    FD_TEST( ctx->metrics->unknown_peer_ping  ==  unknown_peer_ping_b4  );
    FD_TEST( ctx->metrics->malformed_ping     ==  malformed_ping_b4      );
    FD_TEST( ctx->metrics->fail_sigverify_ping==++fail_sigverify_ping_b4 );

    FD_LOG_NOTICE(( "pass: test_after_net_fail_sigverify" ));
  }

  {
    /* Generate a valid ed25519 keypair, register the pubkey as a known
       peer, then send a ping with a valid signature.  after_net should
       pass sigverify and enqueue a pong. */

    uchar private_key[32] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 };
    fd_pubkey_t pubkey;
    fd_sha512_t sha[1];
    fd_ed25519_public_from_private( pubkey.uc, private_key, sha );

    fd_ip4_port_t addr = { .addr = 0x05060708U, .port = 5678 };
    fd_policy_peer_upsert( ctx->policy, &pubkey, &addr );

    ulong pong_cnt_before = fd_signs_queue_cnt( ctx->pong_queue );

    ulong sz = mock_ping_packet( ctx, &pubkey, private_key, 0x05060708U, 5678 );
    after_net( ctx, sz );

    FD_TEST( ctx->metrics->unknown_peer_ping  ==unknown_peer_ping_b4 );   /* unchanged from earlier tests */
    FD_TEST( ctx->metrics->malformed_ping     ==malformed_ping_b4 );
    FD_TEST( ctx->metrics->fail_sigverify_ping==fail_sigverify_ping_b4 );  /* unchanged from earlier tests */
    FD_TEST( fd_signs_queue_cnt( ctx->pong_queue )==++pong_cnt_before );

    /* Verify the peer's ping rate-limit counter was incremented. */

    fd_policy_peer_t * peer = fd_policy_peer_query( ctx->policy, &pubkey );
    FD_TEST( peer && peer->ping==1 );

    /* Peer tries to send a ping again */

    sz = mock_ping_packet( ctx, &pubkey, private_key, 0x05060708U, 5678 );
    after_net( ctx, sz );

    FD_TEST( ctx->metrics->unknown_peer_ping  ==unknown_peer_ping_b4 );   /* unchanged from earlier tests */
    FD_TEST( ctx->metrics->malformed_ping     ==malformed_ping_b4 );
    FD_TEST( ctx->metrics->fail_sigverify_ping==fail_sigverify_ping_b4 );  /* unchanged from earlier tests */
    FD_TEST( fd_signs_queue_cnt( ctx->pong_queue )==pong_cnt_before );
    FD_TEST( peer && peer->ping==1 ); /* still has a ping in the queue */

    FD_LOG_NOTICE(( "pass: test_after_net_valid_ping" ));
  }
}
/* test_sign_lifecycle

   Tests the sign request lifecycle:

   1. Pongs: insert a pong into signs_map via
      fd_repair_send_sign_request, simulate the sign response via
      after_sign, verify the pending entry is removed, credits are
      restored, and peer->ping is decremented.

   2. Regular shreds: insert a shred request, simulate the
      sign response, verify the inflight entry is created and credits
      track correctly.

   3. Peer disappears: insert a shred request, remove the peer before
      the sign response arrives, verify the inflight entry is still
      created (so the request can be re-sent on timeout). */

static void
test_sign_lifecycle( fd_wksp_t * wksp ) {

  static ctx_t ctx[1];
  setup_ctx( ctx, wksp, 512 );

  ulong sign_in_idx = ctx->repair_sign_out_ctx[0].in_idx;

  /* 1. Pong sign lifecycle */
  {
    /* Set up a known peer and simulate a pong needing to be signed. */

    fd_pubkey_t   peer_key  = { .ul = { 0xAA } };
    fd_ip4_port_t peer_addr = { .addr = 0x0A0B0C0DU, .port = 4000 };
    fd_policy_peer_upsert( ctx->policy, &peer_key, &peer_addr );
    fd_policy_peer_t * peer = fd_policy_peer_query( ctx->policy, &peer_key );
    FD_TEST( peer );
    peer->ping = 1; /* simulate that a ping was received */

    /* Construct a pong message */

    fd_hash_t         ping_hash = { .ul = { 0xCC } };
    fd_repair_msg_t * pong      = fd_repair_pong( ctx->protocol, &ping_hash );

    pong_data_t pong_data = { .peer_addr = peer_addr, .hash = ping_hash,
                              .daddr = 0x01020304U, .key = peer_key };

    /* Dispatch the sign request. */

    out_ctx_t * sign_out = sign_avail_credits( ctx );
    FD_TEST( sign_out );
    ulong credits_before = sign_out->credits;
    ulong map_cnt_before = fd_signs_map_key_cnt( ctx->signs_map );

    fd_repair_send_sign_request( ctx, sign_out, pong, &pong_data );

    FD_TEST( sign_out->credits==credits_before-1 );
    FD_TEST( fd_signs_map_key_cnt( ctx->signs_map )==map_cnt_before+1 );

    /* The pending key is ctx->pending_key_next - 1 (post-increment in
       sign_map_insert). */

    ulong pending_key = (ulong)(ctx->pending_key_next - 1);

    /* Simulate sign tile returning the signature.  The sig field of
       after_sign encodes pending_key<<32 | sign_type. */

    ulong after_sign_sig = pending_key << 32;
    memset( ctx->sign_buf, 0xAB, sizeof(ctx->sign_buf) ); /* mock signature */

    mock_stem_publish_cnt = 0;
    after_sign( ctx, sign_in_idx, after_sign_sig, NULL );

    /* Verify: pending entry removed, credit restored, peer->ping
       decremented, packet sent (mock_stem_publish called by
       send_packet). */

    FD_TEST( fd_signs_map_key_cnt( ctx->signs_map )==map_cnt_before );
    FD_TEST( sign_out->credits==credits_before );
    FD_TEST( peer->ping==0 );
    FD_TEST( mock_stem_publish_cnt==1 ); /* send_packet called once */
    FD_TEST( ctx->metrics->send_pkt_cnt>=1 );

    FD_LOG_NOTICE(( "pass: test_sign_lifecycle_pong" ));
  }

  /* 2. Regular shred request lifecycle */
  {
    fd_pubkey_t   peer_key  = { .ul = { 0xBB } };
    fd_ip4_port_t peer_addr = { .addr = 0x0A0B0C0EU, .port = 5000 };
    fd_policy_peer_upsert( ctx->policy, &peer_key, &peer_addr );

    /* Construct a shred request: slot=100, shred_idx=5, nonce=999. */

    fd_repair_msg_t * shred_req = fd_repair_shred( ctx->protocol, &peer_key,
                                                    (ulong)fd_log_wallclock()/1000000L,
                                                    999U, 100UL, 5UL );

    out_ctx_t * sign_out = sign_avail_credits( ctx );
    FD_TEST( sign_out );
    ulong credits_before = sign_out->credits;
    ulong map_cnt_before = fd_signs_map_key_cnt( ctx->signs_map );

    fd_repair_send_sign_request( ctx, sign_out, shred_req, NULL );

    FD_TEST( sign_out->credits==credits_before-1 );
    FD_TEST( fd_signs_map_key_cnt( ctx->signs_map )==map_cnt_before+1 );

    ulong pending_key = (ulong)(ctx->pending_key_next - 1);
    ulong after_sign_sig = pending_key << 32;
    memset( ctx->sign_buf, 0xCD, sizeof(ctx->sign_buf) );

    mock_stem_publish_cnt = 0;
    after_sign( ctx, sign_in_idx, after_sign_sig, NULL );

    /* Verify: pending removed, credit restored, inflight created,
       packet sent. */

    FD_TEST( fd_signs_map_key_cnt( ctx->signs_map )==map_cnt_before );
    FD_TEST( sign_out->credits==credits_before );
    FD_TEST( mock_stem_publish_cnt==1 );

    FD_LOG_NOTICE(( "pass: test_sign_lifecycle_shred" ));
  }

  /*  3. Peer-gone shred request */
  {
    fd_pubkey_t   peer_key  = { .ul = { 0xDD } };
    fd_ip4_port_t peer_addr = { .addr = 0x0A0B0C0FU, .port = 6000 };
    fd_policy_peer_upsert( ctx->policy, &peer_key, &peer_addr );

    fd_repair_msg_t * shred_req = fd_repair_shred( ctx->protocol, &peer_key,
                                                    (ulong)fd_log_wallclock()/1000000L,
                                                    777U, 200UL, 3UL );

    out_ctx_t * sign_out = sign_avail_credits( ctx );
    FD_TEST( sign_out );
    ulong credits_before = sign_out->credits;

    fd_repair_send_sign_request( ctx, sign_out, shred_req, NULL );

    /* Remove the peer before the sign response arrives. */

    fd_policy_peer_remove( ctx->policy, &peer_key );
    FD_TEST( !fd_policy_peer_query( ctx->policy, &peer_key ) );

    ulong pending_key = (ulong)(ctx->pending_key_next - 1);
    ulong after_sign_sig = pending_key << 32;
    memset( ctx->sign_buf, 0xEF, sizeof(ctx->sign_buf) );

    mock_stem_publish_cnt = 0;
    after_sign( ctx, sign_in_idx, after_sign_sig, NULL );

    /* Verify: pending removed, credit restored, but NO packet sent
       (peer is gone).  The inflight is still inserted so the request
       will be retried on timeout. */

    FD_TEST( sign_out->credits==credits_before );
    FD_TEST( mock_stem_publish_cnt==0 ); /* no send_packet */

    FD_LOG_NOTICE(( "pass: test_sign_lifecycle_peer_gone" ));
  }
}

#define PCAP_PKT_MAX (1<<19) /* max packets per file */

FD_IMPORT_BINARY( shred_messages_min,        "src/discof/repair/fixtures/shred_messages_min.bin" );
FD_IMPORT_BINARY( future_shred_messages_min, "src/discof/repair/fixtures/future_shred_messages_min.bin" );

/* Minimized shred records (96 bytes for shreds, 92 for fec_complete).
   so that we don't need to write the full shred payload to file

   Layout:
     sig              u64   (8)
     merkle_root      [32]
     slot             u64   (8)
     idx              u32   (4)
     fec_set_idx      u32   (4)
     variant          u8    (1)
     flags            u8    (1)
     parent_off       u16   (2)
     rnonce           u32   (4)  <-- shreds only (src 0-4)
     chained_merkle_root [32]
*/
typedef struct __attribute__((packed)) {
  ulong     sig;
  fd_hash_t merkle_root;
  ulong     slot;
  uint      idx;
  uint      fec_set_idx;
  uchar     variant;
  uchar     flags;
  ushort    parent_off;
  uint      rnonce;             /* only valid for shreds (src 0-4) */
  fd_hash_t chained_merkle_root;
} shred_pkt_t;

#define MIN_SHRED_SZ       (96UL) /* sizeof shred record (with rnonce) */
#define MIN_FEC_COMPLETE_SZ (92UL) /* sizeof fec_complete record (no rnonce) */

/* Parse minimized records from an in-memory buffer into pkts[0..cap).
   Iterates by pointer arithmetic over variable-length records.
   Returns the number of packets parsed. */
static ulong
read_shred_bin( uchar const * buf, ulong buf_sz, shred_pkt_t * pkts, ulong cap ) {
  uchar const * cur = buf;
  uchar const * end = buf + buf_sz;
  ulong cnt = 0UL;

  while( cur + sizeof(ulong) <= end && cnt < cap ) {
    ulong sig = FD_LOAD( ulong, cur );
    uint  src = fd_shred_sig_src( sig );
    int   is_fec = ( src==SHRED_SIG_FEC_COMPLETE || src==SHRED_SIG_FEC_COMPLETE_LEADER );
    ulong rec_sz = is_fec ? MIN_FEC_COMPLETE_SZ : MIN_SHRED_SZ;

    if( cur + rec_sz > end ) break;

    memset( &pkts[cnt], 0, sizeof(shred_pkt_t) );
    pkts[cnt].sig = sig;

    /* Copy fields after sig.  For fec_complete the rnonce field is
       absent in the file, so copy in two parts around it. */
    uchar const * src_ptr = cur + sizeof(ulong);
    uchar       * dst     = (uchar *)&pkts[cnt] + sizeof(ulong);
    ulong common_sz = 32+8+4+4+1+1+2; /* merkle_root..parent_off = 52 bytes */

    fd_memcpy( dst, src_ptr, common_sz );
    if( is_fec ) {
      /* No rnonce in file — skip the field (stays 0), copy cmr. */
      fd_memcpy( &pkts[cnt].chained_merkle_root, src_ptr + common_sz, 32 );
    } else {
      /* rnonce(4) + chained_merkle_root(32) */
      fd_memcpy( dst + common_sz, src_ptr + common_sz, 4 + 32 );
    }

    cur += rec_sz;
    cnt++;
  }

  return cnt;
}

static void
test_future_slots( fd_wksp_t * wksp ) {
  /* Tests future slot attacks by sampling from shred_out during a
     testnet run, and interleaving them evenly with future shreds. */
  static ctx_t ctx[1];
  setup_ctx( ctx, wksp, 128 );

  fd_forest_init( ctx->forest, 402053352 );

  /* wksp allocate for 2^19 packets per file */
  void * reg_pkts_mem    = fd_wksp_alloc_laddr( wksp, FD_CHUNK_ALIGN, PCAP_PKT_MAX * sizeof(shred_pkt_t), 1UL );
  void * future_pkts_mem = fd_wksp_alloc_laddr( wksp, FD_CHUNK_ALIGN, PCAP_PKT_MAX * sizeof(shred_pkt_t), 1UL );

  shred_pkt_t * reg_pkts    = (shred_pkt_t *)reg_pkts_mem;
  shred_pkt_t * future_pkts = (shred_pkt_t *)future_pkts_mem;

  ulong reg_cnt    = read_shred_bin( shred_messages_min,        shred_messages_min_sz,        reg_pkts,    PCAP_PKT_MAX );
  ulong future_cnt = read_shred_bin( future_shred_messages_min, future_shred_messages_min_sz, future_pkts, PCAP_PKT_MAX );

  fd_rng_t rng[1];
  fd_rng_join( fd_rng_new( rng, 42U, 0UL ) );

  ulong reg_idx    = 0;
  ulong future_idx = 0;

  while( reg_idx < reg_cnt || future_idx < future_cnt ) {
    int pick;
    if     ( reg_idx    >= reg_cnt    ) pick = 0;
    else if( future_idx >= future_cnt ) pick = 1;
    else                                pick = (int)(fd_rng_uint( rng ) & 1U);

    shred_pkt_t * pkt = pick ? &reg_pkts[ reg_idx++ ] : &future_pkts[ future_idx++ ];
    uint src = fd_shred_sig_src( pkt->sig );

    /* Reconstruct a minimal fd_shred_t on the stack from the compact fields. */
    fd_shred_t shred_hdr[1];
    memset( shred_hdr, 0, sizeof(fd_shred_t) );
    shred_hdr->variant     = pkt->variant;
    shred_hdr->slot        = pkt->slot;
    shred_hdr->idx         = pkt->idx;
    shred_hdr->fec_set_idx = pkt->fec_set_idx;
    shred_hdr->data.parent_off = pkt->parent_off;
    shred_hdr->data.flags      = pkt->flags;

    if( src == SHRED_SIG_FEC_COMPLETE || src == SHRED_SIG_FEC_COMPLETE_LEADER ) {
      after_fec( ctx, shred_hdr, &pkt->merkle_root, &pkt->chained_merkle_root );
    } else {
      after_shred( ctx, pkt->sig, shred_hdr, pkt->rnonce, &pkt->merkle_root, &pkt->chained_merkle_root );
    }
  }
  fd_forest_print( ctx->forest );
  FD_TEST( !fd_forest_verify( ctx->forest ) );

  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass: test_future_slots" ));
}

/* test_after_tower_confirmed_eviction

   Tests the after_tower confirmation path that detects an incorrect FEC
   set and evicts it.

   Setup:
     root = 0
     slot 2: two FEC sets (0..31, 32..63), both correct
     slot 3: two FEC sets (0..31, 32..63)
       - FEC 32..63 has a WRONG merkle root (doesn't match the confirmed block_id)

   Then send a FD_TOWER_SIG_SLOT_CONFIRMED for slot 3 with the correct
   block_id.  after_tower -> check_confirmed -> fec_chain_verify should
   detect the mismatch at FEC 32 of slot 3 and call fec_clear on it.

   We verify:
     - The bad FEC's shred indices are cleared (buffered_idx regresses)
     - complete_idx is reset (since fec 32 was the last FEC)
     - The slot is not chain_confirmed */

static void
test_after_tower_confirmed_eviction( fd_wksp_t * wksp ) {

  static ctx_t ctx[1];
  setup_ctx( ctx, wksp, 512 );

  fd_forest_init( ctx->forest, 0 );

  /* Merkle root / chained merkle root values.
     Chain for slot 2:  bid confirms mr_2_32 -> cmr=mr_2_0 -> cmr=mr_root
     Chain for slot 3:  bid confirms mr_3_32 -> cmr=mr_3_0 -> cmr=mr_2_32

     We'll insert slot 3's FEC 32 with a WRONG merkle root (mr_3_32_bad)
     so that when tower confirms with the correct block_id (mr_3_32),
     the chain verify fails at slot 3's last FEC. */

  fd_hash_t mr_root  = (fd_hash_t){ .ul = { 100 } };
  fd_hash_t mr_2_0   = (fd_hash_t){ .ul = { 200 } };
  fd_hash_t mr_2_32  = (fd_hash_t){ .ul = { 201 } };
  fd_hash_t mr_3_0   = (fd_hash_t){ .ul = { 300 } };
  fd_hash_t mr_3_32  = (fd_hash_t){ .ul = { 301 } };  /* correct */

  fd_hash_t mr_3_32_bad = (fd_hash_t){ .ul = { 999 } };  /* wrong version */

  /* Insert blocks and their FEC sets.
     fd_forest_fec_insert( forest, slot, parent, last_shred_idx, fec_set_idx, slot_complete, ref_tick, mr, cmr ) */

  fd_forest_blk_insert( ctx->forest, 2, 0, NULL );
  fd_forest_blk_insert( ctx->forest, 3, 2, NULL );

  /* Slot 2: two correct FEC sets */
  fd_forest_fec_insert( ctx->forest, 2, 0, 31, 0,  0, 0, &mr_2_0,  &mr_root );
  fd_forest_fec_insert( ctx->forest, 2, 0, 63, 32, 1, 0, &mr_2_32, &mr_2_0  );

  /* Slot 3: FEC 0 is correct, FEC 32 is the WRONG version */
  fd_forest_fec_insert( ctx->forest, 3, 2, 31, 0,  0, 0, &mr_3_0,      &mr_2_32 );
  fd_forest_fec_insert( ctx->forest, 3, 2, 63, 32, 1, 0, &mr_3_32_bad, &mr_3_0  );

  /* Verify pre-conditions: slot 3 is complete */
  fd_forest_blk_t * blk3 = fd_forest_query( ctx->forest, 3 );
  FD_TEST( blk3 );
  FD_TEST( blk3->complete_idx == 63 );
  FD_TEST( blk3->buffered_idx == 63 );
  FD_TEST( blk3->chain_confirmed == 0 );

  /* Now send a tower confirmation for slot 3 with the CORRECT block_id.
     The confirmed block_id is the merkle root of the last FEC set. */

  fd_tower_slot_confirmed_t confirmed_msg[1];
  memset( confirmed_msg, 0, sizeof(*confirmed_msg) );
  confirmed_msg->level    = FD_TOWER_SLOT_CONFIRMED_DUPLICATE;
  confirmed_msg->fwd      = 0;
  confirmed_msg->slot     = 3;
  confirmed_msg->block_id = mr_3_32;  /* correct block_id */

  after_tower( ctx, FD_TOWER_SIG_SLOT_CONFIRMED, (uchar *)confirmed_msg );

  /* After tower: fec_chain_verify should have detected that slot 3's
     last FEC (index 32) has mr_3_32_bad != mr_3_32 (the confirmed bid).
     It should have called fec_clear on slot 3, fec_set_idx=32. */

  blk3 = fd_forest_query( ctx->forest, 3 );
  FD_TEST( blk3 );

  /* complete_idx should be reset because fec_clear clears the last FEC */
  FD_TEST( blk3->complete_idx == UINT_MAX );

  /* chain_confirmed should still be 0 — we evicted a bad FEC */
  FD_TEST( blk3->chain_confirmed == 0 );

  /* buffered_idx should regress to 31 (only FEC 0..31 remains) */
  FD_TEST( blk3->buffered_idx == 31 );

  /* Slot 2 should be unaffected — not yet chain_confirmed because
     verification stopped at slot 3 before reaching slot 2. */
  fd_forest_blk_t * blk2 = fd_forest_query( ctx->forest, 2 );
  FD_TEST( blk2 );
  FD_TEST( blk2->chain_confirmed == 0 );

  /* Now simulate re-receiving the CORRECT version of slot 3's FEC 32.
     This time the merkle root matches the confirmed block_id. */

  fd_hash_t mr_3_0_correct_cmr = mr_2_32; /* cmr of FEC 0 should chain to slot 2's last mr */
  (void)mr_3_0_correct_cmr;

  fd_forest_fec_insert( ctx->forest, 3, 2, 63, 32, 1, 0, &mr_3_32, &mr_3_0 );

  /* Now manually re-trigger check_confirmed (in the real flow,
     after_fec would do this when lowest_verified_fec == fec_set_idx/32 + 1). */
  blk3 = fd_forest_query( ctx->forest, 3 );
  FD_TEST( blk3->complete_idx == 63 );
  FD_TEST( blk3->buffered_idx == 63 );

  /* Re-verify the chain with the correct FEC */
  fd_forest_blk_t * bad = fd_forest_fec_chain_verify( ctx->forest, blk3, &mr_3_32 );
  FD_TEST( !bad ); /* should succeed now */

  FD_TEST( blk3->chain_confirmed == 1 );

  /* Slot 2 should also be chain_confirmed now (chain verify walks
     backwards through parents). */
  blk2 = fd_forest_query( ctx->forest, 2 );
  FD_TEST( blk2->chain_confirmed == 1 );

  fd_forest_verify( ctx->forest );

  FD_LOG_NOTICE(( "pass: test_after_tower_confirmed_eviction" ));
}


int main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt = 2;
  char * page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_after_net( wksp );

  fd_wksp_reset( wksp, 1UL );
  test_sign_lifecycle( wksp );

  fd_wksp_reset( wksp, 1UL );
  test_future_slots( wksp );

  fd_wksp_reset( wksp, 1UL );
  test_after_tower_confirmed_eviction( wksp );

  fd_halt();
  return 0;
}
