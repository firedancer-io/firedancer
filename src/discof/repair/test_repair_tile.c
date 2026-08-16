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
setup_ctx( ctx_t * ctx, fd_wksp_t * wksp, ulong slot_max, int is_alpenglow ) {
  memset( ctx, 0, sizeof(*ctx) );

  FD_TEST( fd_rng_secure( ctx->repair_nonce_ss, sizeof(fd_rnonce_ss_t) ) );

  void * chainer_mem = NULL;
  if( FD_UNLIKELY( is_alpenglow ) ) {
    chainer_mem = fd_wksp_alloc_laddr( wksp, fd_chainer_align(), fd_chainer_footprint( slot_max ), 1UL );
  }
  void * forest_mem     = fd_wksp_alloc_laddr( wksp, fd_forest_align(), fd_forest_footprint( slot_max ), 1UL );
  void * policy_mem     = fd_wksp_alloc_laddr( wksp, fd_policy_align(), fd_policy_footprint( peer_max ), 1UL );
  void * dedup_mem      = fd_wksp_alloc_laddr( wksp, fd_reqlim_align(), fd_reqlim_footprint( dedup_max ), 1UL );
  void * inflights_mem  = fd_wksp_alloc_laddr( wksp, fd_inflights_align(), fd_inflights_footprint(), 1UL );
  void * signs_map_mem  = fd_wksp_alloc_laddr( wksp, fd_signs_map_align(), fd_signs_map_footprint( lg_sign_depth ), 1UL );
  void * pong_queue_mem = fd_wksp_alloc_laddr( wksp, fd_signs_queue_align(), fd_signs_queue_footprint(), 1UL );
  void * repair_mem     = fd_wksp_alloc_laddr( wksp, fd_repair_align(), fd_repair_footprint(), 1UL );
  void * metrics_mem    = fd_wksp_alloc_laddr( wksp, fd_repair_metrics_align(), fd_repair_metrics_footprint(), 1UL );

  if( FD_UNLIKELY( is_alpenglow ) ) {
    ctx->chainer    = fd_chainer_join       ( fd_chainer_new       ( chainer_mem, slot_max, 0UL ) );
  }
  ctx->forest       = fd_forest_join        ( fd_forest_new        ( forest_mem, slot_max, 0UL ) );
  ctx->policy       = fd_policy_join        ( fd_policy_new        ( policy_mem, peer_max, 0UL, ctx->repair_nonce_ss ) );
  ctx->dedup        = fd_reqlim_join        ( fd_reqlim_new        ( dedup_mem, dedup_max, 0UL ) );
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

/* call_after_ping mirrors the after_frag IN_KIND_NET path: strip the
   headers off the frame in ctx->net_buf, then dispatch to after_ping. */

static void
call_after_ping( ctx_t * ctx, ulong sz ) {
  fd_ip4_hdr_t * ip4; fd_udp_hdr_t * udp;
  uchar * data; ulong data_sz;
  if( FD_UNLIKELY( !fd_ip4_udp_hdr_strip( ctx->net_buf, sz, &data, &data_sz, NULL, &ip4, &udp ) ) ) {
    ctx->metrics->malformed_ping++;
    return;
  }
  after_ping( ctx, data, data_sz, ip4, udp );
}

static void
test_after_net( fd_wksp_t * wksp ) {

  /* Allocate a minimal ctx with just the fields after_net touches. */

  static ctx_t ctx[1];
  setup_ctx( ctx, wksp, 512, 0 );

  ulong unknown_peer_ping_b4   = ctx->metrics->unknown_peer_ping;
  ulong malformed_ping_b4      = ctx->metrics->malformed_ping;
  ulong fail_sigverify_ping_b4 = ctx->metrics->fail_sigverify_ping;

  /* Build a valid ping from an unknown peer (not in policy). */

  {
    fd_pubkey_t unknown_peer = { .ul = { 0xDEAD } };
    ulong sz = mock_ping_packet( ctx, &unknown_peer, NULL, 0x01020304U, 1234 );

    /* Call after_net — should hit the unknown_peer_ping path. */
    call_after_ping( ctx, sz );

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
    call_after_ping( ctx, sz );

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
    call_after_ping( ctx, sz );

    FD_TEST( ctx->metrics->unknown_peer_ping  ==unknown_peer_ping_b4 );   /* unchanged from earlier tests */
    FD_TEST( ctx->metrics->malformed_ping     ==malformed_ping_b4 );
    FD_TEST( ctx->metrics->fail_sigverify_ping==fail_sigverify_ping_b4 );  /* unchanged from earlier tests */
    FD_TEST( fd_signs_queue_cnt( ctx->pong_queue )==++pong_cnt_before );

    /* Verify the peer's ping rate-limit counter was incremented. */

    fd_policy_peer_t * peer = fd_policy_peer_query( ctx->policy, &pubkey );
    FD_TEST( peer && peer->ping==1 );

    /* Peer tries to send a ping again */

    sz = mock_ping_packet( ctx, &pubkey, private_key, 0x05060708U, 5678 );
    call_after_ping( ctx, sz );

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
  setup_ctx( ctx, wksp, 512, 0 );

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
  setup_ctx( ctx, wksp, 128, 0 );

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
  setup_ctx( ctx, wksp, 512, 0 );

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


/* test_after_fec_dup_confirm_larger_slot

   An attacker sends us a non-canonical version of slot 3 that can never
   complete contiguously:

     1. We receive 64 contiguous shreds (FEC 0 and FEC 1, shreds 0-63),
        no slot_complete.
     2. The attacker sends the maximum FEC set (fec_set_idx=1023*32)
        with slot_complete.  complete_idx is now at a very high shred
        index, but buffered_idx stays at 63 because there's a huge gap.

   Then tower sends a duplicate confirmation with the correct block_id.
   fec_chain_verify detects the wrong last FEC and fec_clears it,
   resetting complete_idx to UINT_MAX.

   Finally, the canonical FEC 1 (shreds 32-63, slot_complete) arrives
   via after_fec.  This sets complete_idx=63 and buffered_idx==63,
   triggering check_confirmed which chain-verifies the whole slot. */

static void
test_after_fec_dup_confirm_larger_slot( fd_wksp_t * wksp ) {

  static ctx_t ctx[1];
  setup_ctx( ctx, wksp, 512, 0 );

  fd_forest_init( ctx->forest, 0 );

  fd_hash_t mr_root   = (fd_hash_t){ .ul = { 100 } };
  fd_hash_t mr_2_0    = (fd_hash_t){ .ul = { 200 } };
  fd_hash_t mr_2_32   = (fd_hash_t){ .ul = { 201 } };
  fd_hash_t mr_3_0    = (fd_hash_t){ .ul = { 300 } };
  fd_hash_t mr_3_1    = (fd_hash_t){ .ul = { 301 } };  /* correct block_id for slot 3 */
  fd_hash_t mr_3_1_bad = (fd_hash_t){ .ul = { 997 } };  /* attacker's  FEC 1 mr */

  fd_hash_t mr_3_bad  = (fd_hash_t){ .ul = { 999 } };  /* attacker's max FEC mr */
  fd_hash_t cmr_3_bad = (fd_hash_t){ .ul = { 998 } };

  /* Set up ancestry: root=0 -> slot 2 (2 correct FEC sets) */
  fd_forest_blk_insert( ctx->forest, 2, 0, NULL );
  fd_forest_fec_insert( ctx->forest, 2, 0, 31, 0,  0, 0, &mr_2_0,  &mr_root );
  fd_forest_fec_insert( ctx->forest, 2, 0, 63, 32, 1, 0, &mr_2_32, &mr_2_0  );

  /* Slot 3: receive FEC 0 and FEC 1 (shreds 0-63), no slot_complete */
  fd_forest_blk_insert( ctx->forest, 3, 2, NULL );
  fd_forest_fec_insert( ctx->forest, 3, 2, 31, 0,  0, 0, &mr_3_0, &mr_2_32 );
  fd_forest_fec_insert( ctx->forest, 3, 2, 63, 32, 0, 0, &mr_3_1_bad, &mr_3_0  );

  fd_forest_blk_t * blk3 = fd_forest_query( ctx->forest, 3 );
  FD_TEST( blk3->complete_idx == UINT_MAX );
  FD_TEST( blk3->buffered_idx == 63 );

  /* Attacker sends the max FEC set with slot_complete.
     complete_idx jumps to a very high value, but buffered_idx stays 63
     because there's a gap between shred 63 and the max FEC. */
  uint max_fec_set_idx = (FD_FEC_BLK_MAX - 1) * 32;
  uint max_last_shred  = max_fec_set_idx + 31;
  fd_forest_fec_insert( ctx->forest, 3, 2, max_last_shred, max_fec_set_idx, 1, 0, &mr_3_bad, &cmr_3_bad );

  blk3 = fd_forest_query( ctx->forest, 3 );
  FD_TEST( blk3->complete_idx == max_last_shred );
  FD_TEST( blk3->buffered_idx == 63 );  /* gap prevents contiguous buffering */
  FD_TEST( blk3->chain_confirmed == 0 );

  /* Tower sends duplicate confirmation with the correct block_id.
     check_confirmed -> fec_chain_verify should fail because the last
     FEC (at max index) has mr_3_bad != mr_3_1 (the correct block_id).
     fec_clear should remove the bad max FEC. */

  fd_tower_slot_confirmed_t confirmed_msg[1];
  memset( confirmed_msg, 0, sizeof(*confirmed_msg) );
  confirmed_msg->level    = FD_TOWER_SLOT_CONFIRMED_DUPLICATE;
  confirmed_msg->fwd      = 0;
  confirmed_msg->slot     = 3;
  confirmed_msg->block_id = mr_3_1;

  after_tower( ctx, FD_TOWER_SIG_SLOT_CONFIRMED, (uchar *)confirmed_msg );

  blk3 = fd_forest_query( ctx->forest, 3 );
  FD_TEST( blk3 );

  /* fec_clear should have reset complete_idx since it cleared the last FEC */
  FD_TEST( blk3->complete_idx == UINT_MAX );
  FD_TEST( blk3->chain_confirmed == 0 );

  /* Now the canonical FEC 1 arrives via after_fec with slot_complete.
     This is the correct version with complete_idx=63.
     after_fec should set complete_idx=63, and since buffered_idx==63
     and lowest_verified_fec was set by fec_chain_verify, it should
     trigger check_confirmed and chain-verify the whole slot. */

  fd_shred_t shred_hdr[1];
  memset( shred_hdr, 0, sizeof(fd_shred_t) );
  shred_hdr->variant     = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 5 );
  shred_hdr->slot        = 3;
  shred_hdr->idx         = 63;
  shred_hdr->fec_set_idx = 32;
  shred_hdr->data.parent_off = 1;  /* parent = slot 2 */
  shred_hdr->data.flags      = FD_SHRED_DATA_FLAG_SLOT_COMPLETE;

  after_fec( ctx, shred_hdr, &mr_3_1, &mr_3_0 );

  blk3 = fd_forest_query( ctx->forest, 3 );
  FD_TEST( blk3->complete_idx == 63 );
  FD_TEST( blk3->buffered_idx == 63 );
  FD_TEST( blk3->chain_confirmed == 1 );

  /* Slot 2 should also be chain_confirmed (chain verify walks parents) */
  fd_forest_blk_t * blk2 = fd_forest_query( ctx->forest, 2 );
  FD_TEST( blk2->chain_confirmed == 1 );

  FD_TEST( !fd_forest_verify( ctx->forest ) );

  FD_LOG_NOTICE(( "pass: test_after_fec_dup_confirm_larger_slot" ));
}


/*  - slot 8 has a duplicate-confirmed block id, then only its
       slot-complete shred arrives.  This verifies FEC 0 immediately
       (lowest_verified_fec=0) but leaves the slot unbuffered and not
       chain_confirmed.
     - slot 10 is first linked under slot 8.
     - a completed duplicate-confirmed FEC for slot 10 later arrives with a
       chained merkle root that names a different parent block id.

   At that point chain verification returns slot 8, but there is no
   clearable incorrect FEC in slot 8: fd_forest_merkle_last_incorrect_idx
   returns UINT_MAX. */

static void
test_parent_edge_mismatch_with_verified_fec0( fd_wksp_t * wksp ) {

   static ctx_t ctx[1];
   setup_ctx( ctx, wksp, 512, 0 );

   fd_forest_init( ctx->forest, 0 );

   fd_hash_t mr_root     = (fd_hash_t){ .ul = { 100 } };
   fd_hash_t mr_8        = (fd_hash_t){ .ul = { 108 } };
   fd_hash_t mr_8_stale  = (fd_hash_t){ .ul = { 808 } };
   fd_hash_t mr_9        = (fd_hash_t){ .ul = { 109 } };
   fd_hash_t mr_10       = (fd_hash_t){ .ul = { 110 } };
   fd_hash_t mr_10_stale = (fd_hash_t){ .ul = { 1010 } };

   fd_tower_slot_confirmed_t confirmed_msg[1];
   memset( confirmed_msg, 0, sizeof(*confirmed_msg) );
   confirmed_msg->level    = FD_TOWER_SLOT_CONFIRMED_DUPLICATE;
   confirmed_msg->fwd      = 0;
   confirmed_msg->slot     = 8;
   confirmed_msg->block_id = mr_8;

   after_tower( ctx, FD_TOWER_SIG_SLOT_CONFIRMED, (uchar *)confirmed_msg );

   fd_forest_blk_t * slot8 = fd_forest_query( ctx->forest, 8 );
   FD_TEST( slot8 );
   FD_TEST( fd_hash_eq( &slot8->confirmed_bid, &mr_8 ) );
   FD_TEST( slot8->complete_idx == UINT_MAX );

   fd_shred_t shred_hdr[1];
   memset( shred_hdr, 0, sizeof(fd_shred_t) );
   shred_hdr->variant         = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 5 );
   shred_hdr->slot            = 8;
   shred_hdr->idx             = FD_FEC_SHRED_CNT - 1U;
   shred_hdr->fec_set_idx     = 0;
   shred_hdr->data.parent_off = 8; /* parent = root slot 0 */
   shred_hdr->data.flags      = FD_SHRED_DATA_FLAG_SLOT_COMPLETE;

   after_shred( ctx, SHRED_SIG_SRC_TURBINE, shred_hdr, 0, &mr_8, &mr_root );

   slot8 = fd_forest_query( ctx->forest, 8 );
   FD_TEST( slot8 );
   FD_TEST( slot8->complete_idx == FD_FEC_SHRED_CNT - 1U );
   FD_TEST( slot8->buffered_idx == UINT_MAX );
   FD_TEST( slot8->lowest_verified_fec == 0 );
   FD_TEST( !slot8->chain_confirmed );

   memset( shred_hdr, 0, sizeof(fd_shred_t) );
   shred_hdr->variant         = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 5 );
   shred_hdr->slot            = 10;
   shred_hdr->idx             = 0;
   shred_hdr->fec_set_idx     = 0;
   shred_hdr->data.parent_off = 2; /* stale parent = slot 8 */

   after_shred( ctx, SHRED_SIG_SRC_TURBINE, shred_hdr, 0, &mr_10_stale, &mr_8_stale );

   fd_forest_blk_t * slot10 = fd_forest_query( ctx->forest, 10 );
   FD_TEST( slot10 );
   FD_TEST( slot10->parent_slot == 8 );
   FD_TEST( slot10->buffered_idx == 0 );
   FD_TEST( slot10->complete_idx == UINT_MAX );

   memset( shred_hdr, 0, sizeof(fd_shred_t) );
   shred_hdr->variant         = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 5 );
   shred_hdr->slot            = 10;
   shred_hdr->idx             = FD_FEC_SHRED_CNT - 1U;
   shred_hdr->fec_set_idx     = 0;
   shred_hdr->data.parent_off = 1; /* canonical duplicate-confirmed parent = slot 9 */
   shred_hdr->data.flags      = FD_SHRED_DATA_FLAG_SLOT_COMPLETE;

   after_fec( ctx, shred_hdr, &mr_10, &mr_9 );

   slot10 = fd_forest_query( ctx->forest, 10 );
   FD_TEST( slot10 );
   FD_TEST( slot10->parent_slot == 9 );
   FD_TEST( slot10->buffered_idx == slot10->complete_idx );
   FD_TEST( slot10->complete_idx == FD_FEC_SHRED_CNT - 1U );
   FD_TEST( fd_hash_eq( &slot10->merkle_roots[0].mr,  &mr_10 ) );
   FD_TEST( fd_hash_eq( &slot10->merkle_roots[0].cmr, &mr_9  ) );

   /* Slot 10 gets duplicate confirmed which triggers check_confirmed.
      The parent edge mismatch is detected and slot 8 is returned as the bad block.
      Because repair logic assumes the returned bad block must contain a
      clearable bad FEC, this trips the UINT_MAX FD_TEST on bad_fec_idx. */
   fd_tower_slot_confirmed_t confirmed_msg_10[1];
   memset( confirmed_msg_10, 0, sizeof(*confirmed_msg_10) );
   confirmed_msg_10->level    = FD_TOWER_SLOT_CONFIRMED_DUPLICATE;
   confirmed_msg_10->fwd      = 0;
   confirmed_msg_10->slot     = 10;
   confirmed_msg_10->block_id = mr_10;

   after_tower( ctx, FD_TOWER_SIG_SLOT_CONFIRMED, (uchar *)confirmed_msg_10 );

   FD_LOG_NOTICE(( "pass: test_parent_edge_mismatch_with_verified_fec0" ));
}

static void
test_after_fec0_parent_update_unconfirmed_stale_parent( fd_wksp_t * wksp ) {

  static ctx_t ctx[1];
  setup_ctx( ctx, wksp, 512, 0 );

  ulong const root_slot         = 40UL;
  ulong const real_parent_slot  = 41UL;
  ulong const stale_parent_slot = 42UL;
  ulong const child_slot        = 43UL;

  fd_forest_init( ctx->forest, root_slot );

  fd_hash_t empty_mr  = {0};
  fd_hash_t mr_root   = (fd_hash_t){ .ul = { 400 } };
  fd_hash_t mr_41     = (fd_hash_t){ .ul = { 410 } };
  fd_hash_t mr_42     = (fd_hash_t){ .ul = { 420 } };
  fd_hash_t mr_43     = (fd_hash_t){ .ul = { 430 } };
  fd_hash_t mr_43_fec = (fd_hash_t){ .ul = { 431 } };

  fd_shred_t shred_hdr[1];
  /* Complete slot 41 on top of the root without confirming it. */
  memset( shred_hdr, 0, sizeof(fd_shred_t) );
  shred_hdr->variant         = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 5 );
  shred_hdr->slot            = real_parent_slot;
  shred_hdr->idx             = FD_FEC_SHRED_CNT - 1U;
  shred_hdr->fec_set_idx     = 0;
  shred_hdr->data.parent_off = (ushort)( real_parent_slot - root_slot );
  shred_hdr->data.flags      = FD_SHRED_DATA_FLAG_SLOT_COMPLETE;
  FD_TEST( !after_fec( ctx, shred_hdr, &mr_41, &mr_root ) );

  /* Complete slot 42 as an unconfirmed local branch. */
  memset( shred_hdr, 0, sizeof(fd_shred_t) );
  shred_hdr->variant         = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 5 );
  shred_hdr->slot            = stale_parent_slot;
  shred_hdr->idx             = FD_FEC_SHRED_CNT - 1U;
  shred_hdr->fec_set_idx     = 0;
  shred_hdr->data.parent_off = (ushort)( stale_parent_slot - real_parent_slot );
  shred_hdr->data.flags      = FD_SHRED_DATA_FLAG_SLOT_COMPLETE;
  FD_TEST( !after_fec( ctx, shred_hdr, &mr_42, &mr_41 ) );

  /* Verify the stale branch is complete but not duplicate-confirmed. */
  fd_forest_blk_t * slot42 = fd_forest_query( ctx->forest, stale_parent_slot );
  FD_TEST( slot42 );
  FD_TEST( slot42->complete_idx == FD_FEC_SHRED_CNT - 1U );
  FD_TEST( !slot42->chain_confirmed );
  FD_TEST( fd_hash_eq( &slot42->confirmed_bid, &empty_mr ) );

  /* Link slot 43 under slot 42 using a later-FEC shred. */
  memset( shred_hdr, 0, sizeof(fd_shred_t) );
  shred_hdr->variant         = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 5 );
  shred_hdr->slot            = child_slot;
  shred_hdr->idx             = FD_FEC_SHRED_CNT;
  shred_hdr->fec_set_idx     = FD_FEC_SHRED_CNT;
  shred_hdr->data.parent_off = (ushort)( child_slot - stale_parent_slot );
  after_shred( ctx, SHRED_SIG_SRC_TURBINE, shred_hdr, 0, &mr_43_fec, &mr_42 );

  /* Verify the stale parent link exists before FEC 0 arrives.*/
  fd_forest_blk_t * slot43 = fd_forest_query( ctx->forest, child_slot );
  FD_TEST( slot43 );
  FD_TEST( slot43->parent_slot == stale_parent_slot );
  FD_TEST( slot43->complete_idx == UINT_MAX );

  /* Complete slot 43 FEC 0 with slot 41 as its actual parent. */
  memset( shred_hdr, 0, sizeof(fd_shred_t) );
  shred_hdr->variant         = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 5 );
  shred_hdr->slot            = child_slot;
  shred_hdr->idx             = FD_FEC_SHRED_CNT - 1U;
  shred_hdr->fec_set_idx     = 0;
  shred_hdr->data.parent_off = (ushort)( child_slot - real_parent_slot );
  shred_hdr->data.flags      = FD_SHRED_DATA_FLAG_SLOT_COMPLETE;
  FD_TEST( !after_fec( ctx, shred_hdr, &mr_43, &mr_41 ) );

  /* Verify FEC 0 reparented slot 43 to slot 41. */
  slot43 = fd_forest_query( ctx->forest, child_slot );
  FD_TEST( slot43 );
  FD_TEST( slot43->parent_slot == real_parent_slot );
  FD_TEST( slot43->complete_idx == FD_FEC_SHRED_CNT - 1U );
  FD_TEST( slot43->buffered_idx == slot43->complete_idx );

  fd_tower_slot_confirmed_t confirmed_msg[1];
  /* Duplicate-confirm only slot 43. */
  memset( confirmed_msg, 0, sizeof(*confirmed_msg) );
  confirmed_msg->level    = FD_TOWER_SLOT_CONFIRMED_DUPLICATE;
  confirmed_msg->fwd      = 0;
  confirmed_msg->slot     = child_slot;
  confirmed_msg->block_id = mr_43;
  after_tower( ctx, FD_TOWER_SIG_SLOT_CONFIRMED, (uchar *)confirmed_msg );

  /* Verify the stale unconfirmed slot 42 was not touched. */
  fd_forest_blk_t * slot41 = fd_forest_query( ctx->forest, real_parent_slot );
  slot42 = fd_forest_query( ctx->forest, stale_parent_slot );
  slot43 = fd_forest_query( ctx->forest, child_slot );
  FD_TEST( slot41 );
  FD_TEST( slot42 );
  FD_TEST( slot43 );
  FD_TEST( slot41->chain_confirmed );
  FD_TEST( !slot42->chain_confirmed );
  FD_TEST( slot43->chain_confirmed );
  FD_TEST( fd_hash_eq( &slot41->confirmed_bid, &mr_41 ) );
  FD_TEST( fd_hash_eq( &slot42->confirmed_bid, &empty_mr ) );
  FD_TEST( slot42->complete_idx == FD_FEC_SHRED_CNT - 1U );
  FD_TEST( !fd_forest_verify( ctx->forest ) );

  FD_LOG_NOTICE(( "pass: test_after_fec0_parent_update_unconfirmed_stale_parent" ));
}

/* ---------------------------------------------------------------------------
   test_alpenglow_repair_full_path

   End-to-end new-Alpenglow repair flow:
     1. Ingest every shred of a slot (turbine "version 0") + extra / duplicate
        shreds -> duplicates are idempotent (no state change).
     2. Slot completes -> chainer computes the version-0 (turbine) block_id.
     3. A notar-fallback cert arrives for a DIFFERENT block_id; verifying it
        against our computed block_id shows a mismatch (equivocation).
     4. Algorithm-4 block-id repair fires:
          ParentAndFecSetCount -> FecSetRoot (xN) -> ShredForBlockId (xM),
        and the shared FEC prefix is NOT re-requested.
     5. Proof-verified metadata creates sentinels; verified shreds fill them.
     6. The certified (alternate) version of the slot completes.

   SCAFFOLD: guarded by #if 0 until the fd_chainer + block-id repair helpers
   below exist.  Remove the guard and implement the assumed helpers:
     mk_data_shred, feed_shred, feed_fec_complete, chainer_block_id,
     chainer_slot_complete, feed_notar_fallback, drain_repair_reqs,
     mk_parent_count_resp, mk_fecroot_resp, mk_shred_for_blockid_resp,
     feed_repair_resp.  Then enable the call in main().
   --------------------------------------------------------------------------- */
typedef struct {
  int       kind;          /* FD_REPAIR_KIND_{PARENT_FEC_COUNT,FEC_ROOT,SHRED_FOR_BLOCK_ID} */
  ulong     slot;
  fd_hash_t block_id;      /* block-id repair kinds */
  uint      fec_set_idx;   /* FecSetRoot / ShredForBlockId */
  uint      shred_idx;     /* ShredForBlockId */
} test_repair_req_t;

static uchar shred_buf[FD_SHRED_MAX_SZ];

/* parent block id declared by make_shred's BlockHeader marker for slot
   (arbitrary but deterministic and nonzero) */
static inline fd_hash_t
marker_parent_bid( ulong slot ) {
  return (fd_hash_t){ .ul = { 0xb10cUL, slot } };
}

static inline fd_shred_t *
make_shred( ulong slot, uint shred_idx, int slot_complete, int make_parent_marker ) {
  fd_shred_t * shred = (fd_shred_t *)fd_type_pun(shred_buf);
  memset( shred_buf, 0, sizeof(shred_buf) );
  shred->variant = fd_shred_variant( FD_SHRED_TYPE_MERKLE_DATA, 5 );
  shred->slot = slot;
  shred->idx = shred_idx;
  shred->fec_set_idx = (shred_idx / 32) * 32;
  shred->data.parent_off = 1; /* Alpenglow never reads this -- the declared marker is authoritative */
  shred->data.flags = slot_complete ? FD_SHRED_DATA_FLAG_SLOT_COMPLETE : 0;
  shred->data.size = FD_SHRED_DATA_HEADER_SZ + AG_BLOCK_HEADER_V1_SZ;

  /* poison the (static, reused) payload so a marker written by a
     previous call can't leak into this shred: a nonzero entry count
     parses as an entry batch, not a marker */
  uchar * payload = shred_buf + FD_SHRED_DATA_HEADER_SZ;
  memset( payload, 0xFF, AG_BLOCK_HEADER_V1_SZ );

  if( make_parent_marker ) {
    /* BlockHeader marker declaring parent (slot-1, marker_parent_bid(slot)) */
    memset( payload, 0, AG_BLOCK_HEADER_V1_SZ );
    fd_block_marker_t * marker = (fd_block_marker_t *)fd_type_pun( payload );
    marker->marker_flag                    = 0UL; /* entry count 0 -> marker */
    marker->version                        = 1;
    marker->variant                        = HEADER;
    marker->length                         = 41;
    marker->data.header.header_version     = 1;
    marker->data.header.v1.parent_slot     = slot - 1UL;
    marker->data.header.v1.parent_block_id = marker_parent_bid( slot );
  }
  return shred;
}

/* dmr_t is the double-merkle tree over a block: the per-FEC-set merkle
   roots followed by the parent-info leaf, exactly as a leader builds it.
   The repair tile verifies every block-id repair response against this
   tree, so the fixtures below have to produce real proofs. */

#define DMR_LAYER_CNT (12UL) /* >= depth of FD_FEC_BLK_MAX+1 leaves */

typedef struct {
  uchar     mem[ FD_BMTREE_COMMIT_FOOTPRINT( DMR_LAYER_CNT ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_commit_t * tree;
  fd_hash_t root;
  ulong     proof_len;
} dmr_t;

static void
dmr_build( dmr_t *           dmr,
           fd_hash_t const * fec_roots,
           ulong             fec_set_count,
           ulong             parent_slot,
           fd_hash_t const * parent_block_id ) {
  dmr->tree = fd_bmtree_commit_init( dmr->mem, FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ, DMR_LAYER_CNT );
  for( ulong i=0UL; i<fec_set_count; i++ ) {
    fd_bmtree_node_t leaf[1];
    memcpy( leaf->hash, fec_roots[i].uc, sizeof(fd_hash_t) );
    fd_bmtree_commit_append( dmr->tree, leaf, 1UL );
  }
  uchar buf[ sizeof(ulong)+sizeof(fd_hash_t)+sizeof(uint) ];
  FD_STORE( ulong, buf,                                 parent_slot           );
  memcpy( buf+sizeof(ulong), parent_block_id->uc,        sizeof(fd_hash_t)     );
  FD_STORE( uint,  buf+sizeof(ulong)+sizeof(fd_hash_t),  (uint)fec_set_count  );
  fd_bmtree_node_t pleaf[1];
  fd_sha256_hash( buf, sizeof(buf), pleaf->hash );
  fd_bmtree_commit_append( dmr->tree, pleaf, 1UL );

  memcpy( dmr->root.uc, fd_bmtree_commit_fini( dmr->tree ), sizeof(fd_hash_t) );
  dmr->proof_len = fd_bmtree_depth( fec_set_count+1UL ) - 1UL;
}

static void
dmr_proof( dmr_t * dmr,
           ulong   leaf_idx,
           uchar * dest ) {
  int n = fd_bmtree_get_proof( dmr->tree, dest, leaf_idx );
  FD_TEST( n>=0 && (ulong)n==dmr->proof_len );
}

/* build_double_merkle constructs the Alpenglow double-merkle tree over
   fec_roots[0..fec_set_cnt) with the parent-info leaf appended (see
   ag_repair_response_verify) and returns the block id (tree root) in
   bid_out.  proofs_out[i] receives the inclusion proof for leaf i, i in
   [0, fec_set_cnt] (index fec_set_cnt is the parent-info leaf), and
   proof_len_out the per-leaf proof node count. */

static void
build_double_merkle( fd_hash_t const * fec_roots,
                     uint              fec_set_cnt,
                     ulong             parent_slot,
                     fd_hash_t const * parent_block_id,
                     fd_hash_t *       bid_out,
                     ag_proof_node_t (*proofs_out)[ AG_MAX_FEC_PROOF_NODE_CNT ],
                     ulong *           proof_len_out ) {
  static uchar __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN))) bmtree_mem[ FD_BMTREE_COMMIT_FOOTPRINT( AG_MAX_FEC_PROOF_NODE_CNT+1UL ) ];
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( bmtree_mem, FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ, AG_MAX_FEC_PROOF_NODE_CNT+1UL );

  fd_bmtree_node_t leaf[1] = {{{ 0 }}};
  for( uint i=0; i<fec_set_cnt; i++ ) {
    memcpy( leaf->hash, fec_roots[i].uc, sizeof(fd_hash_t) );
    fd_bmtree_commit_append( tree, leaf, 1UL );
  }

  fd_sha256_t sha[1];
  fd_sha256_init  ( sha );
  fd_sha256_append( sha, &parent_slot,        sizeof(ulong)     );
  fd_sha256_append( sha, parent_block_id->uc, sizeof(fd_hash_t) );
  fd_sha256_append( sha, &fec_set_cnt,        sizeof(uint)      );
  fd_sha256_fini  ( sha, leaf->hash );
  fd_bmtree_commit_append( tree, leaf, 1UL );

  memcpy( bid_out->uc, fd_bmtree_commit_fini( tree ), sizeof(fd_hash_t) );

  for( uint i=0; i<=fec_set_cnt; i++ ) {
    int proof_cnt = fd_bmtree_get_proof( tree, proofs_out[i][0], i );
    FD_TEST( proof_cnt>=0 );
    *proof_len_out = (ulong)proof_cnt;
  }
}

/* test_ag_response_verify -- exercise ag_repair_response_verify against
   a reference double-merkle tree, including rejection of tampered
   responses. */

static void
test_ag_response_verify( void ) {
  ulong const PARENT_SLOT = 41;
  uint  const FEC_CNT     = 5; /* odd leaf pairing exercises the unpaired-node self-join */

  fd_hash_t fec_roots[ 5 ];
  for( uint i=0; i<FEC_CNT; i++ ) fec_roots[i] = (fd_hash_t){ .ul = { i+1UL, 0xabc } };
  fd_hash_t parent_bid = { .ul = { 77 } };

  fd_hash_t       bid;
  ag_proof_node_t proofs[ 6 ][ AG_MAX_FEC_PROOF_NODE_CNT ];
  ulong           proof_len = ULONG_MAX;
  build_double_merkle( fec_roots, FEC_CNT, PARENT_SLOT, &parent_bid, &bid, proofs, &proof_len );
  FD_TEST( proof_len==fd_bmtree_depth( FEC_CNT+1UL )-1UL );

  /* parent fec count response */
  ag_repair_response_t resp = {
    .kind = AG_REPAIR_RESPONSE_PARENT_FEC_SET_COUNT,
    .parent_fec_set_res = {
      .fec_set_count   = FEC_CNT,
      .parent_slot     = PARENT_SLOT,
      .parent_block_id = parent_bid,
      .proof_len       = proof_len,
    },
  };
  memcpy( resp.parent_fec_set_res.parent_proof, proofs[ FEC_CNT ], proof_len*FD_SHRED_MERKLE_NODE_SZ );
  FD_TEST( 0==ag_repair_parent_fec_count_verify( &resp.parent_fec_set_res, &bid ) );

  ag_repair_response_t bad;

  bad = resp; bad.parent_fec_set_res.fec_set_count--;            /* lie about the fec count (same proof sz) */
  FD_TEST( -1==ag_repair_parent_fec_count_verify( &bad.parent_fec_set_res, &bid ) );
  bad = resp; bad.parent_fec_set_res.parent_slot++;              /* lie about the parent slot */
  FD_TEST( -1==ag_repair_parent_fec_count_verify( &bad.parent_fec_set_res, &bid ) );
  bad = resp; bad.parent_fec_set_res.parent_block_id.uc[0] ^= 1; /* lie about the parent block id */
  FD_TEST( -1==ag_repair_parent_fec_count_verify( &bad.parent_fec_set_res, &bid ) );
  bad = resp; bad.parent_fec_set_res.parent_proof[0][0] ^= 1;    /* corrupt the proof */
  FD_TEST( -1==ag_repair_parent_fec_count_verify( &bad.parent_fec_set_res, &bid ) );
  bad = resp; bad.parent_fec_set_res.proof_len--;                /* truncate the proof */
  FD_TEST( -1==ag_repair_parent_fec_count_verify( &bad.parent_fec_set_res, &bid ) );
  fd_hash_t not_bid = bid; not_bid.uc[0] ^= 1;                   /* wrong block id */
  FD_TEST( -1==ag_repair_parent_fec_count_verify( &resp.parent_fec_set_res, &not_bid ) );

  /* fec set root responses, one per leaf */
  for( uint f=0; f<FEC_CNT; f++ ) {
    ag_repair_response_t rresp = {
      .kind = AG_REPAIR_RESPONSE_FEC_SET_ROOT,
      .fec_set_root = { .root = fec_roots[f], .proof_len = proof_len },
    };
    memcpy( rresp.fec_set_root.fec_proof, proofs[ f ], proof_len*FD_SHRED_MERKLE_NODE_SZ );
    FD_TEST( 0==ag_repair_fec_set_root_verify( &rresp.fec_set_root, &bid, f*FD_FEC_SHRED_CNT ) );

    bad = rresp; bad.fec_set_root.root.uc[0] ^= 1;               /* lie about the fec set root */
    FD_TEST( -1==ag_repair_fec_set_root_verify( &bad.fec_set_root, &bid, f*FD_FEC_SHRED_CNT ) );
    /* right root and proof, but for a different fec_set_idx than requested */
    FD_TEST( -1==ag_repair_fec_set_root_verify( &rresp.fec_set_root, &bid, (f+1U)*FD_FEC_SHRED_CNT ) );
  }

  FD_LOG_NOTICE(( "pass: test_ag_response_verify" ));
}

static void
test_alpenglow_repair_full_path( fd_wksp_t * wksp ) {
  ctx_t ctx[1];
  setup_ctx( ctx, wksp, /* slot_max */ 512, 1 );   /* assume setup wires ctx->chainer too */
  fd_hash_t root = { .ul = { 67 } };
  fd_chainer_init( ctx->chainer, 0UL, &root );            /* root=0 so slot 2 > root (below-root guard in after_alpen_repair) */

  /* add a couple policy peers for repair */
  fd_pubkey_t peer = (fd_pubkey_t){ .ul = { 1 } };
  fd_pubkey_t peer2 = (fd_pubkey_t){ .ul = { 2 } };
  fd_ip4_port_t ip  = { .addr = 1, .port = 0 };
  fd_ip4_port_t ip2 = { .addr = 1, .port = 0 };
  fd_policy_peer_upsert( ctx->policy, &peer, &ip );
  fd_policy_peer_upsert( ctx->policy, &peer2, &ip2 );

  ulong const SLOT         = 2;
  uint  const TOTAL_SHREDS = 96; /* 3 fec sets */
  /* versions share fec 0, diverge at fec 1 & fec 2 */

  /* v0 = turbine version, v1 = notar-fallback-certified version; shared prefix */
  fd_hash_t mr0 = (fd_hash_t){ .ul = { 1 } };
  fd_hash_t mr1_bad = (fd_hash_t){ .ul = { 2 } }; fd_hash_t mr1_good = (fd_hash_t){ .ul = { 2, 1 } };
  fd_hash_t mr2_bad = (fd_hash_t){ .ul = { 3 } }; fd_hash_t mr2_good = (fd_hash_t){ .ul = { 3, 1 } };

  fd_hash_t mr_bad[3] = { mr0, mr1_bad, mr2_bad };
  fd_hash_t mr_good[3] = { mr0, mr1_good, mr2_good };

  /* Both versions declare the same parent; they differ only in their FEC
     roots, so their double-merkle block ids differ. */
  ulong     const PARENT_SLOT = SLOT - 1UL;
  fd_hash_t const PARENT_BID  = (fd_hash_t){ .ul = { 5 } };

  /* Real double-merkle roots, so the repair responses below can carry
     proofs that verify (and so the ids cannot collide with the all-zero
     unknown/not-yet-finalized block_id sentinel). */
  static dmr_t dmr_v0, dmr_v1;
  dmr_build( &dmr_v0, mr_bad,  3UL, PARENT_SLOT, &PARENT_BID );
  dmr_build( &dmr_v1, mr_good, 3UL, PARENT_SLOT, &PARENT_BID );
  fd_hash_t bid_v0 = dmr_v0.root;
  fd_hash_t bid_v1 = dmr_v1.root;
  FD_TEST( !fd_hash_eq( &bid_v0, &bid_v1 ) );
  fd_shred_t * shred = NULL;

  /* -------- Phase 1: ingest turbine version 0 (+ dups) -------- */
   for( uint s=0; s<TOTAL_SHREDS; s++ ) {
     shred = make_shred( SLOT, s, (s==TOTAL_SHREDS-1), s==0 /* shred 0 carries the block header */ );
     after_alpen_shred( ctx, 0, shred, 0, &mr_bad[s / 32] );          /* first receipt: changed */
     if( s % 32 == 31 ) {
       FD_TEST( !after_alpen_fec( ctx, shred, &mr_bad[s / 32] ) );
     }
   }

  {
    shred = make_shred( SLOT, 33, 1, 0 );
    after_alpen_shred( ctx, 0, shred, 0, &mr_good[1] ); /* no-op */
    FD_TEST( after_alpen_fec( ctx, shred, &mr_good[1] ) == 1 );   /* dup fec: no-op */
  }

  //FD_TEST( chainer_slot_complete( ctx->chainer, SLOT, /*ver*/0 ) );
  //bid_v0 = chainer_block_id( ctx->chainer, SLOT, /*ver*/0 );
  FD_LOG_NOTICE(( "pass: turbine version received, dedup idempotent" ));

  /* -------- Phase 2: notar-fallback for a DIFFERENT block_id -------- */
  ag_votor_notar_fallback_t nf = {
    .slot = SLOT,
    .block_id = bid_v1,
  };
  after_votor_notar_fallback( ctx, &nf );

  {
    /* the notar-fallback created the alternate slotv version keyed by its block_id */
    fd_slotv_t * slotv = fd_chainer_slot_version_query( ctx->chainer, SLOT, &bid_v1 );
    FD_TEST( slotv && fd_hash_eq( &slotv->block_id, &bid_v1 ) );
  }
  FD_LOG_NOTICE(( "pass: notar-fallback mismatch detected -> alt warranted" ));

  /* -------- block-id repair requests emitted -------- */

  FD_TEST( !fd_signs_queue_empty( ctx->pong_queue ) );
  sign_pending_t sign = fd_signs_queue_pop( ctx->pong_queue );
  FD_TEST( sign.msg.kind==AG_REPAIR_KIND_PARENT_FEC_COUNT );
  ag_repair_parent_fec_count_req_t * req = &sign.msg.parent_fec_set_count;
  FD_TEST( req->slot==SLOT && fd_hash_eq( &req->block_id, &bid_v1 ) );

  /* simulate return response for parent fec count.  The parent info is
     the tree's FINAL leaf, at index fec_set_count. */
  ag_parent_fec_count_res_t res = {
    .fec_set_count = TOTAL_SHREDS / 32,
    .parent_slot = PARENT_SLOT,
    .parent_block_id = PARENT_BID,
    .proof_len = dmr_v1.proof_len,
  };
  dmr_proof( &dmr_v1, TOTAL_SHREDS / 32, res.parent_proof[0] );
  ag_repair_response_t resp = (ag_repair_response_t){
    .kind = AG_REPAIR_RESPONSE_PARENT_FEC_SET_COUNT,
    .parent_fec_set_res = res,
    .nonce = req->nonce
  };

  after_alpen_repair( ctx, &resp );

  /* step 2: FecSetRoot xN */
  uint f = 0;
  while( !fd_signs_queue_empty( ctx->pong_queue ) ) {
    sign_pending_t sign = fd_signs_queue_pop( ctx->pong_queue );
    FD_TEST( sign.msg.kind==AG_REPAIR_KIND_FEC_ROOT );
    ag_repair_fec_root_req_t * req = &sign.msg.fec_set_root;
    FD_TEST( req->slot==SLOT && req->fec_set_idx==f*FD_FEC_SHRED_CNT );

    /* simulate return response for fec root, carrying the real
       inclusion proof for leaf f */
    ag_fec_root_res_t res = {
      .root      = mr_good[f],
      .proof_len = dmr_v1.proof_len,
    };
    dmr_proof( &dmr_v1, f, res.fec_proof[0] );
    ag_repair_response_t resp = (ag_repair_response_t){
      .kind = AG_REPAIR_RESPONSE_FEC_SET_ROOT,
      .fec_set_root = res,
      .nonce = req->nonce
    };
    after_alpen_repair( ctx, &resp );
    f++;
  }

#if 0
  n = drain_repair_reqs( ctx, reqs, 64 );               /* step 3: ShredForBlockId, diverged FECs only */
  FD_TEST( n==(N_FEC-FEC_DIV)*SHREDS );
  for( ulong i=0; i<n; i++ ) {
    FD_TEST( reqs[i].kind==FD_REPAIR_KIND_SHRED_FOR_BLOCK_ID );
    FD_TEST( reqs[i].slot==SLOT && reqs[i].fec_set_idx>=FEC_DIV*FEC_STEP );
  }
  FD_LOG_NOTICE(( "pass: alg-4 requests (count->roots->shreds), shared prefix not re-requested" ));
#endif
  /* -------- Phase 4: verified shreds fill -> alt completes -------- */
  for( uint idx=0; idx<TOTAL_SHREDS; idx++ ) {
    shred = make_shred( SLOT, idx, idx==TOTAL_SHREDS-1, idx==0 /* shred 0 carries the block header */ );
    after_alpen_shred( ctx, 0, shred, 0, &mr_good[idx / 32] );
    FD_TEST(!after_alpen_fec( ctx, shred, &mr_good[idx / 32] ) );
  }
  FD_LOG_NOTICE(( "pass: certified alternate version completed via block-id repair" ));
}

/* test_repair_request_order -- with the root at slot 0, verify
   ag_policy_next runs the orphan (ancestry) pass before the shred-fill
   pass, each min-slot-first.

   Setup (root slotv = slot 0, so slot 1's parent is present):
     slot 1 v0 : tip unknown, parent (slot 0 root) present -> not orphan
     slot 2 v0 : tip known, gap at idx 1, parent (slot 1) present -> not orphan
     slot 2 v1 : notar-fallback, tip + parent known via
                 verified_parent_fec_count -> not orphan.  That call
                 creates the (unknown) parent version slot 1 v1, whose
                 own parent is unknown -> slot 1 v1 is the orphan.

   Expected order (one request per call, same `now` so reqlim dedups
   across calls):
     1. Shred(slot 1, idx 0)           orphan-pass shred-0 for the created
                                       parent version slot 1 v1
                                       (parent unknown -> no Orphan req)
     2. HighestShred(slot 1)           shred-fill, v0 unknown tip
                                       (slot 1 v1's HighestShred dedups)
     3. Shred(slot 2, idx 1)           shred-fill, v0 gap
     4. ShredForBlockId(slot 2, idx 0) shred-fill, v1 block-id repair
                                       (gated on the authorized fec 0 root
                                       from the simulated getFecRoot) */
static void
test_repair_request_order( fd_wksp_t * wksp ) {
  ctx_t ctx[1];
  setup_ctx( ctx, wksp, 512, 1 );

  fd_hash_t root = { .ul = { 67 } };
  /* root at slot 0 */
  fd_chainer_init( ctx->chainer, 0UL, &root );

  fd_pubkey_t   peer = { .ul = { 1 } };
  fd_ip4_port_t ip   = { .addr = 1, .port = 0 };
  fd_policy_peer_upsert( ctx->policy, &peer, &ip );

  fd_hash_t mr         = { .ul = { 42 } };
  fd_hash_t bid        = { .ul = { 7 } }; /* slot-2 notar-fallback block_id (non-zero, != v0's zero) */
  fd_hash_t parent_bid = { .ul = { 5 } };

  fd_shred_t * shred;

  /* slot 1 v0: one shred, no slot-complete -> complete_idx unknown.  Its
     shred 0 carries the block header declaring parent slot 0 (the root),
     which is what takes it out of the orphan treap. */
  shred = make_shred( 1, 0, /*slot_complete*/0, /*parent marker*/1 );
  after_alpen_shred( ctx, 0, shred, 0, &mr );

  /* slot 2 v0: shreds 0,2..31 then fec-complete (32..63) -> complete_idx=63, gap at idx 1 */
  for( uint i = 0; i < 32; i++ ) {
    if( i == 1 ) continue;
    shred = make_shred( 2, i, 0, /*parent marker*/i==0 );
    after_alpen_shred( ctx, 0, shred, 0, &mr );
  }
  shred = make_shred( 2, 63, /*slot_complete*/1, 0 );
  after_alpen_fec( ctx, shred, &mr );

  /* slot 2 v1: notar-fallback for a different block_id + proof-verified
     fec-count so its tip and parent (slot 1, parent_bid) are known; this
     creates the parent version slot 1 v1, which becomes the orphan */
  fd_chainer_notar_fallback( ctx->chainer, 2, bid );
  fd_chainer_verified_parent_fec_count( ctx->chainer, 2, &bid, /*fec_set_cnt*/2, 1, &parent_bid );

  /* authorize v1's fec 0 root (simulates a proof-verified getFecRoot
     response) -- the shred-fill pass gates ShredForBlockId on it */
  fd_hash_t v1_fec0_mr = { .ul = { 43 } };
  fd_chainer_verified_hash_insert( ctx->chainer, 2, &bid, 0, &v1_fec0_mr );

  /* drive the walk, same `now` so reqlim dedups across calls; each call
     emits one request until all four are out */
  out_ctx_t * sign_out = sign_avail_credits( ctx );
  FD_TEST( sign_out );
  long  now = fd_log_wallclock();
  ulong k0  = (ulong)ctx->pending_key_next;

  int charge_busy = 0;
  for( int i=0; i<16 && (ulong)ctx->pending_key_next < k0+4UL; i++ )
    ag_policy_next( ctx, sign_out, now, &charge_busy );

  FD_TEST( (ulong)ctx->pending_key_next == k0 + 4UL );

  sign_req_t * r0 = fd_signs_map_query( ctx->signs_map, k0+0UL, NULL );
  sign_req_t * r1 = fd_signs_map_query( ctx->signs_map, k0+1UL, NULL );
  sign_req_t * r2 = fd_signs_map_query( ctx->signs_map, k0+2UL, NULL );
  sign_req_t * r3 = fd_signs_map_query( ctx->signs_map, k0+3UL, NULL );
  FD_TEST( r0 && r1 && r2 && r3 );

  /* 1st: orphan-pass shred-0 for slot 1 v1 (parent unknown -> no Orphan) */
  FD_TEST( r0->msg.kind == FD_REPAIR_KIND_SHRED );
  FD_TEST( r0->msg.shred.slot == 1UL && r0->msg.shred.shred_idx == 0UL );

  /* 2nd: shred-fill HighestShred for slot 1 (unknown tip) */
  FD_TEST( r1->msg.kind == FD_REPAIR_KIND_HIGHEST_SHRED );
  FD_TEST( r1->msg.highest_shred.slot == 1UL );

  /* 3rd: shred-fill window Shred for slot 2 v0 (first gap = idx 1) */
  FD_TEST( r2->msg.kind == FD_REPAIR_KIND_SHRED );
  FD_TEST( r2->msg.shred.slot == 2UL && r2->msg.shred.shred_idx == 1UL );

  /* 4th: shred-fill block-id repair for slot 2 v1 (idx 0, matching block_id) */
  FD_TEST( r3->msg.kind == AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID );
  FD_TEST( r3->msg.shred_block_id.slot == 2UL );
  FD_TEST( r3->msg.shred_block_id.shred_idx == 0UL );
  FD_TEST( fd_hash_eq( &r3->msg.shred_block_id.block_id, &bid ) );

  FD_LOG_NOTICE(( "pass: repair request order (orphan shred-0 s1/v1, HighestShred s1, Shred s2, ShredForBlockId s2/v1)" ));
}

int main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"               );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 2UL                      );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0UL ) );
  fd_wksp_t * wksp      = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_after_net( wksp );

  fd_wksp_reset( wksp, 1UL );
  test_sign_lifecycle( wksp );

  fd_wksp_reset( wksp, 1UL );
  test_future_slots( wksp );

  fd_wksp_reset( wksp, 1UL );
  test_after_tower_confirmed_eviction( wksp );

  fd_wksp_reset( wksp, 1UL );
  test_after_fec_dup_confirm_larger_slot( wksp );

  fd_wksp_reset( wksp, 1UL );
  test_parent_edge_mismatch_with_verified_fec0( wksp );

  fd_wksp_reset( wksp, 1UL );
  test_after_fec0_parent_update_unconfirmed_stale_parent( wksp );


  test_ag_response_verify();

  fd_wksp_reset( wksp, 1UL );
  test_alpenglow_repair_full_path( wksp );

  fd_wksp_reset( wksp, 1UL );
  test_repair_request_order( wksp );

  fd_halt();
  return 0;
}
