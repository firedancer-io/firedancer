/* test_fec_resolver_bp627.c

   Boundary point BP627: divergence between Firedancer and Agave when a
   FEC set contains two shreds carrying two distinct valid ed25519
   signatures over the same reconstructed merkle root.

   Original divergence: Firedancer's fd_fec_resolver_add_shred keyed
   its in-progress FEC-set map (`ctx_map`) by the ed25519 signature
   bytes; the pair (slot, fec_set_idx) is a secondary index in a treap.
   When two shreds carried different valid signatures over the same
   merkle root, the treap hit set `equivoc_or_invalid=1` and the
   resolver returned FD_FEC_RESOLVER_SHRED_EQUIVOC -- a false positive
   that propagated through the shred/tower tiles into fd_ghost_eqvoc
   and caused FD to abstain from voting on blocks Agave votes on.

   Fix (this branch): before returning EQUIVOC, compare the newly
   reconstructed merkle root against the root recorded for the existing
   (slot, fec_set_idx).  If they match, return SHRED_IGNORED (no
   equivocation -- Agave semantics); if they differ, return EQUIVOC
   (genuine equivocation).

     src/disco/shred/fd_fec_resolver.c  (MAP_KEY = sig)
     src/disco/shred/fd_fec_resolver.c  (equivoc-branch merkle-root compare)

   Agave reference: keys FEC-set metadata by (slot, fec_set_index) in
   `MerkleRootMeta` (agave/ledger/src/blockstore_meta.rs:376) and its
   cross-shred consistency check `check_merkle_root_consistency`
   (agave/ledger/src/blockstore.rs:3010) compares only the merkle root.
   Two shreds with the same merkle root but different valid ed25519
   signatures both land in the ShredData column with no
   PossibleDuplicateShred pushed.

   Ed25519 verify is stateless.  RFC 8032's deterministic-r rule for
   nonce derivation is a signer-side convention -- verify only checks
   that s is canonical, that R and A' decompress and are non-small
   order, and that [8][S]B == [8]R + [8][k]A'.  A malfunctioning or
   malicious leader can therefore produce two accepting signatures
   Sig_A and Sig_B over the same message M by using two different
   values of r.  fd_ed25519_verify (see the block comment at
   src/ballet/ed25519/fd_ed25519_user.c:168 -- "verify_strict"
   semantics) accepts both.

   Tests:

   test_bp627_two_valid_sigs (same-root, fix asserted):
     1. Sig_A != Sig_B (byte-inequal signatures).
     2. Both verify against pk_L over M under fd_ed25519_verify.
     3. Feeding shred_A returns FD_FEC_RESOLVER_SHRED_OKAY.
     4. Feeding shred_B returns FD_FEC_RESOLVER_SHRED_IGNORED (fix).
     5. Resent shred_B still returns FD_FEC_RESOLVER_SHRED_IGNORED.

   test_bp627_real_equivocation (different-root, regression guard):
     Two shreds at the same (slot, fec_set_idx) but with different
     merkle roots must still return FD_FEC_RESOLVER_SHRED_EQUIVOC. */

#include <stdio.h>
#include <string.h>
#include "fd_shredder.h"
#include "fd_fec_resolver.h"
#include "fd_fec_set.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/ed25519/fd_curve25519.h"
#include "../../ballet/ed25519/fd_curve25519_scalar.h"
#include "../../disco/metrics/fd_metrics.h"

/* Reuse the same demo-shreds keypair the neighbor test_fec_resolver.c
   uses -- 32 bytes private || 32 bytes public. */
FD_IMPORT_BINARY( test_private_key, "src/disco/shred/fixtures/demo-shreds.key" );

#define SHRED_VER (ushort)6051
#define MAX       (32UL*1024UL)
#define SEED      10388431120836828144UL

static uchar entry_batch[ 32768UL ];

static uchar res_mem[ 1024UL*1024UL ] __attribute__((aligned(FD_FEC_RESOLVER_ALIGN)));
static fd_fec_set_t out_sets[ 4UL ];
static fd_fec_set_t _set[ 1UL ];
static fd_shredder_t _shredder[ 1 ];
static uchar metrics_scratch[ FD_METRICS_FOOTPRINT( 0 ) ] __attribute__((aligned(FD_METRICS_ALIGN)));

/* Signer context / callback identical in shape to test_fec_resolver.c.
   The shredder calls this once per FEC set to produce Sig_A. */
struct signer_ctx {
  fd_sha512_t   sha512[ 1 ];
  uchar const * public_key;
  uchar const * private_key;
};
typedef struct signer_ctx signer_ctx_t;

static void
signer_ctx_init( signer_ctx_t * ctx,
                 uchar const *  private_key ) {
  FD_TEST( fd_sha512_init( fd_sha512_new( ctx->sha512 ) ) );
  ctx->public_key  = private_key + 32UL;
  ctx->private_key = private_key;
}

static void
det_signer( void *        _ctx,
            uchar *       signature,
            uchar const * merkle_root ) {
  signer_ctx_t * ctx = (signer_ctx_t *)_ctx;
  fd_ed25519_sign( signature, merkle_root, 32UL, ctx->public_key, ctx->private_key, ctx->sha512 );
}

/* alt_ed25519_sign produces a valid ed25519 signature over msg using
   the caller-supplied 32-byte nonce_seed to drive the choice of r.

   This mirrors fd_ed25519_sign (fd_ed25519_user.c:60) exactly except
   for the r-derivation step: RFC 8032 specifies
   r = SHA-512(prefix || M) where prefix is the second half of
   SHA-512(private_key); we substitute r = SHA-512(nonce_seed || M)
   reduced mod L.  Everything after r is identical:

     R  = [r] B                    (curve base point)
     k  = SHA-512(R || A || M) mod L
     S  = (r + k*s) mod L
     sig = R || S

   The resulting signature verifies under RFC 8032 verify (and thus
   under fd_ed25519_verify) because the equations
     [8][S]B == [8]R + [8][k]A'
   depend only on the algebraic relation, not on how r was chosen.
   The signer-side deterministic-r rule is a hygiene requirement to
   avoid leaking s across signatures; it is NOT part of the verify
   contract.  Using two different nonce_seed values with the same
   (private_key, msg) yields two byte-distinct signatures, both of
   which fd_ed25519_verify accepts. */
static void
alt_ed25519_sign( uchar         sig[ 64 ],
                  uchar const   msg[ 32 ],
                  uchar const   public_key[ 32 ],
                  uchar const   private_key[ 32 ],
                  uchar const   nonce_seed[ 32 ],
                  fd_sha512_t * sha ) {

  /* s (secret scalar) derived from private_key exactly as in RFC 8032. */
  uchar s_h[ FD_SHA512_HASH_SZ ];
  fd_sha512_fini( fd_sha512_append( fd_sha512_init( sha ), private_key, 32UL ), s_h );
  s_h[ 0] &= (uchar)0xF8;
  s_h[31] &= (uchar)0x7F;
  s_h[31] |= (uchar)0x40;
  uchar * s = s_h; /* first 32 bytes */

  /* r derived from (nonce_seed || msg) instead of (prefix || msg).
     Note: fd_curve25519_scalar_reduce reduces a 64-byte little-endian
     value mod L into the first 32 bytes of its output. */
  uchar r[ FD_SHA512_HASH_SZ ];
  fd_sha512_fini( fd_sha512_append( fd_sha512_append( fd_sha512_init( sha ), nonce_seed, 32UL ), msg, 32UL ), r );
  fd_curve25519_scalar_reduce( r, r );

  /* R = [r] B, write encoded R into sig[0..32). */
  fd_ed25519_point_t R[1];
  fd_ed25519_scalar_mul_base_const_time( R, r );
  fd_ed25519_point_tobytes( sig, R );

  /* k = SHA-512(R || A || M) mod L. */
  uchar k[ FD_SHA512_HASH_SZ ];
  fd_sha512_fini( fd_sha512_append( fd_sha512_append( fd_sha512_append( fd_sha512_init( sha ),
                  sig, 32UL ), public_key, 32UL ), msg, 32UL ), k );
  fd_curve25519_scalar_reduce( k, k );

  /* S = (k*s + r) mod L, into sig[32..64). */
  fd_curve25519_scalar_muladd( sig + 32UL, k, s, r );
}

static void
test_bp627_two_valid_sigs( void ) {
  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );

  uchar const * private_key = test_private_key;
  uchar const * pubkey      = test_private_key + 32UL;

  /* Fill the entry batch with arbitrary bytes -- content does not
     matter, only that the shredder produces a well-formed 32/32 FEC
     set.  Using 28000 bytes matches test_chained_merkle_shreds and
     produces exactly one FEC set with 32 data + 32 parity shreds. */
  for( ulong i=0UL; i<sizeof(entry_batch); i++ ) entry_batch[ i ] = (uchar)(i*0x9EU + 0x37U);
  ulong const data_sz = 28000UL;
  FD_TEST( fd_shredder_count_fec_sets( data_sz, 1 ) == 1UL );
  FD_TEST( fd_shredder_count_data_shreds( data_sz, 1 ) == FD_FEC_SHRED_CNT );

  FD_TEST( _shredder==fd_shredder_new( _shredder, det_signer, signer_ctx ) );
  fd_shredder_t * shredder = fd_shredder_join( _shredder ); FD_TEST( shredder );
  fd_shredder_set_shred_version( shredder, SHRED_VER );

  fd_entry_batch_meta_t meta[1];
  fd_memset( meta, 0, sizeof(fd_entry_batch_meta_t) );
  meta->block_complete = 1;
  /* parent_offset must be non-zero for slots >0 (fd_shred_parse
     rejects slot!=0 & parent_off==0, per fd_shred.c:96). */
  meta->parent_offset  = 1UL;

  /* Build the FEC set at slot 100.  All 32 data + 32 parity shreds
     share the same signature Sig_A over the merkle root M of this set. */
  ulong const slot     = 100UL;
  FD_TEST( fd_shredder_init_batch( shredder, entry_batch, data_sz, slot, meta ) );
  uchar chained_merkle_root[ 32 ] = { 0 };
  fd_fec_set_t * set = fd_shredder_next_fec_set( shredder, _set, chained_merkle_root );
  FD_TEST( set );
  FD_TEST( fd_shredder_fini_batch( shredder ) );

  /* Reconstruct M (the merkle root over the 32 data + 32 parity shreds)
     from data_shreds[0]. */
  uchar bmtree_mem[ fd_bmtree_commit_footprint( FD_SHRED_MERKLE_LAYER_CNT ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_node_t M[1] = { 0 };
  FD_TEST( fd_shred_merkle_root( set->data_shreds[ 0 ].s, bmtree_mem, M ) );

  /* Sanity: idx=0 and idx=1 shreds carry the SAME signature Sig_A
     (the shredder signs once over M and copies the signature into every
     shred in the FEC set). */
  uchar Sig_A[ 64 ];
  fd_memcpy( Sig_A, set->data_shreds[ 0 ].s->signature, 64UL );
  FD_TEST( 0==memcmp( set->data_shreds[ 1 ].s->signature, Sig_A, 64UL ) );

  /* Sig_A must verify against pk_L over M. */
  fd_sha512_t _sha[ 1 ];
  fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
  FD_TEST( FD_ED25519_SUCCESS == fd_ed25519_verify( M->hash, 32UL, Sig_A, pubkey, sha ) );

  /* Compute an alternate valid signature Sig_B over the SAME message
     M using a different nonce seed.  Any nonce_seed distinct from the
     RFC 8032 prefix-derived r produces a distinct valid signature. */
  uchar Sig_B[ 64 ];
  static const uchar nonce_seed[ 32 ] = {
    0xB6,0x27,0xBE,0xEF,0xF0,0x0D,0xDE,0xAD,
    0xCA,0xFE,0xBA,0xBE,0xFA,0xCE,0xB0,0x0C,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
  };
  alt_ed25519_sign( Sig_B, M->hash, pubkey, private_key, nonce_seed, sha );

  /* Assertion 1: Sig_A and Sig_B are byte-distinct. */
  FD_TEST( 0 != memcmp( Sig_A, Sig_B, 64UL ) );

  /* Assertion 2: both signatures verify against pk_L over M. */
  FD_TEST( FD_ED25519_SUCCESS == fd_ed25519_verify( M->hash, 32UL, Sig_A, pubkey, sha ) );
  FD_TEST( FD_ED25519_SUCCESS == fd_ed25519_verify( M->hash, 32UL, Sig_B, pubkey, sha ) );

  fd_sha512_delete( fd_sha512_leave( sha ) );

  /* Assemble shred_A (a copy of data_shreds[0] with Sig_A -- unchanged)
     and shred_B (a copy of data_shreds[1] with Sig_A overwritten by
     Sig_B).  We work on stack copies so we don't perturb the FEC set. */
  uchar shred_A_buf[ FD_SHRED_MIN_SZ ];
  uchar shred_B_buf[ FD_SHRED_MIN_SZ ];
  fd_memcpy( shred_A_buf, set->data_shreds[ 0 ].b, FD_SHRED_MIN_SZ );
  fd_memcpy( shred_B_buf, set->data_shreds[ 1 ].b, FD_SHRED_MIN_SZ );
  /* Overwrite signature on shred_B. */
  fd_memcpy( shred_B_buf, Sig_B, 64UL );

  /* Now drive the resolver. */
  fd_fec_resolver_t * r =
      fd_fec_resolver_join( fd_fec_resolver_new( res_mem, NULL, NULL, 2UL, 1UL, 1UL, 1UL, out_sets, SEED ) );
  FD_TEST( r );
  fd_fec_resolver_set_shred_version( r, SHRED_VER );

  fd_fec_set_t const * out_fec[ 1 ];
  fd_shred_t   const * out_shred[ 1 ];
  fd_bmtree_node_t     out_merkle_root[ 1 ];

  /* Assertion 3: shred_A is accepted. */
  fd_shred_t const * parsed_A = fd_shred_parse( shred_A_buf, FD_SHRED_MIN_SZ, FD_SHRED_BLK_MAX );
  FD_TEST( parsed_A );
  int rv_A = fd_fec_resolver_add_shred( r, parsed_A, FD_SHRED_MIN_SZ, MAX, 0, pubkey,
                                        out_fec, out_shred, out_merkle_root, NULL );
  FD_LOG_NOTICE(( "BP627: add_shred(shred_A, Sig_A) returned %d (expected %d = OKAY)",
                  rv_A, FD_FEC_RESOLVER_SHRED_OKAY ));
  FD_TEST( rv_A == FD_FEC_RESOLVER_SHRED_OKAY );
  /* Reconstructed root must equal M. */
  FD_TEST( 0 == memcmp( out_merkle_root->hash, M->hash, 32UL ) );

  /* Assertion 4 (post-fix): shred_B is IGNORED, not EQUIVOC.  The
     ctx_map lookup by Sig_B misses (Sig_B != Sig_A), the ctx_treap
     lookup on (slot=100, fec_set_idx=0) hits, equivoc_or_invalid is
     set to 1, the merkle proof recomputes root M, sig-verify of Sig_B
     over M succeeds -- and then the merkle-root compare against the
     existing ctx finds M == M, so the resolver returns
     SHRED_IGNORED without stamping SIG_HASH_EQUIVOC.  This matches
     Agave's check_merkle_root_consistency semantics. */
  fd_shred_t const * parsed_B = fd_shred_parse( shred_B_buf, FD_SHRED_MIN_SZ, FD_SHRED_BLK_MAX );
  FD_TEST( parsed_B );
  int rv_B = fd_fec_resolver_add_shred( r, parsed_B, FD_SHRED_MIN_SZ, MAX, 0, pubkey,
                                        out_fec, out_shred, out_merkle_root, NULL );
  FD_LOG_NOTICE(( "BP627: add_shred(shred_B, Sig_B) returned %d (expected %d = IGNORED)",
                  rv_B, FD_FEC_RESOLVER_SHRED_IGNORED ));
  FD_TEST( rv_B == FD_FEC_RESOLVER_SHRED_IGNORED );

  /* Follow-up: resending shred_B must still be IGNORED.  Without a
     SIG_HASH_EQUIVOC stamp in done_map, the done_map lookup at
     fd_fec_resolver.c misses; ctx_map by Sig_B still misses;
     ctx_treap on (100,0) still hits; equivoc_or_invalid=1; merkle-root
     compare finds M == M; return SHRED_IGNORED. */
  int rv_B2 = fd_fec_resolver_add_shred( r, parsed_B, FD_SHRED_MIN_SZ, MAX, 0, pubkey,
                                         out_fec, out_shred, out_merkle_root, NULL );
  FD_LOG_NOTICE(( "BP627: add_shred(shred_B, Sig_B) resent returned %d (expected %d = IGNORED)",
                  rv_B2, FD_FEC_RESOLVER_SHRED_IGNORED ));
  FD_TEST( rv_B2 == FD_FEC_RESOLVER_SHRED_IGNORED );

  fd_fec_resolver_delete( fd_fec_resolver_leave( r ) );
}

/* Regression guard: genuine equivocation (same slot/fec_set_idx but
   different merkle roots) MUST still return EQUIVOC.  Build two
   distinct FEC sets (payloads chosen so their merkle roots differ) at
   the same (slot, fec_set_idx=0), then feed one shred from each. */
static void
test_bp627_real_equivocation( void ) {
  signer_ctx_t signer_ctx[ 1 ];
  signer_ctx_init( signer_ctx, test_private_key );

  uchar const * pubkey = test_private_key + 32UL;

  ulong const slot = 200UL;

  /* Build FEC set A (payload pattern 1). */
  static uchar entry_batch_A[ 32768UL ];
  for( ulong i=0UL; i<sizeof(entry_batch_A); i++ ) entry_batch_A[ i ] = (uchar)(i*0x9EU + 0x37U);

  fd_shredder_t _shredder_A[ 1 ];
  FD_TEST( _shredder_A==fd_shredder_new( _shredder_A, det_signer, signer_ctx ) );
  fd_shredder_t * shredder_A = fd_shredder_join( _shredder_A ); FD_TEST( shredder_A );
  fd_shredder_set_shred_version( shredder_A, SHRED_VER );

  fd_entry_batch_meta_t meta[1];
  fd_memset( meta, 0, sizeof(fd_entry_batch_meta_t) );
  meta->block_complete = 1;
  meta->parent_offset  = 1UL;

  fd_fec_set_t _set_A[ 1 ];
  FD_TEST( fd_shredder_init_batch( shredder_A, entry_batch_A, 28000UL, slot, meta ) );
  uchar chained_A[ 32 ] = { 0 };
  fd_fec_set_t * set_A = fd_shredder_next_fec_set( shredder_A, _set_A, chained_A );
  FD_TEST( set_A );
  FD_TEST( fd_shredder_fini_batch( shredder_A ) );

  /* Build FEC set B (payload pattern 2) at the SAME slot/fec_set_idx. */
  static uchar entry_batch_B[ 32768UL ];
  for( ulong i=0UL; i<sizeof(entry_batch_B); i++ ) entry_batch_B[ i ] = (uchar)(i*0x5DU + 0x91U);

  fd_shredder_t _shredder_B[ 1 ];
  FD_TEST( _shredder_B==fd_shredder_new( _shredder_B, det_signer, signer_ctx ) );
  fd_shredder_t * shredder_B = fd_shredder_join( _shredder_B ); FD_TEST( shredder_B );
  fd_shredder_set_shred_version( shredder_B, SHRED_VER );

  fd_fec_set_t _set_B[ 1 ];
  FD_TEST( fd_shredder_init_batch( shredder_B, entry_batch_B, 28000UL, slot, meta ) );
  uchar chained_B[ 32 ] = { 0 };
  fd_fec_set_t * set_B = fd_shredder_next_fec_set( shredder_B, _set_B, chained_B );
  FD_TEST( set_B );
  FD_TEST( fd_shredder_fini_batch( shredder_B ) );

  /* Sanity: the two FEC sets have different merkle roots (different
     payloads under the same slot/fec_set_idx). */
  uchar bmtree_mem_A[ fd_bmtree_commit_footprint( FD_SHRED_MERKLE_LAYER_CNT ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  uchar bmtree_mem_B[ fd_bmtree_commit_footprint( FD_SHRED_MERKLE_LAYER_CNT ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_node_t M_A[1] = { 0 };
  fd_bmtree_node_t M_B[1] = { 0 };
  FD_TEST( fd_shred_merkle_root( set_A->data_shreds[ 0 ].s, bmtree_mem_A, M_A ) );
  FD_TEST( fd_shred_merkle_root( set_B->data_shreds[ 0 ].s, bmtree_mem_B, M_B ) );
  FD_TEST( 0 != memcmp( M_A->hash, M_B->hash, 32UL ) );

  /* And the signatures differ (each set signed over its own root). */
  FD_TEST( 0 != memcmp( set_A->data_shreds[ 0 ].s->signature,
                        set_B->data_shreds[ 0 ].s->signature, 64UL ) );

  static uchar res_mem2[ 1024UL*1024UL ] __attribute__((aligned(FD_FEC_RESOLVER_ALIGN)));
  static fd_fec_set_t out_sets2[ 4UL ];
  fd_fec_resolver_t * r =
      fd_fec_resolver_join( fd_fec_resolver_new( res_mem2, NULL, NULL, 2UL, 1UL, 1UL, 1UL, out_sets2, SEED ) );
  FD_TEST( r );
  fd_fec_resolver_set_shred_version( r, SHRED_VER );

  fd_fec_set_t const * out_fec[ 1 ];
  fd_shred_t   const * out_shred[ 1 ];
  fd_bmtree_node_t     out_merkle_root[ 1 ];

  int rv_A = fd_fec_resolver_add_shred( r, set_A->data_shreds[ 0 ].s, FD_SHRED_MIN_SZ, MAX, 0, pubkey,
                                        out_fec, out_shred, out_merkle_root, NULL );
  FD_LOG_NOTICE(( "BP627 regression: add_shred(set_A idx0) returned %d (expected %d = OKAY)",
                  rv_A, FD_FEC_RESOLVER_SHRED_OKAY ));
  FD_TEST( rv_A == FD_FEC_RESOLVER_SHRED_OKAY );

  int rv_B = fd_fec_resolver_add_shred( r, set_B->data_shreds[ 0 ].s, FD_SHRED_MIN_SZ, MAX, 0, pubkey,
                                        out_fec, out_shred, out_merkle_root, NULL );
  FD_LOG_NOTICE(( "BP627 regression: add_shred(set_B idx0) returned %d (expected %d = EQUIVOC)",
                  rv_B, FD_FEC_RESOLVER_SHRED_EQUIVOC ));
  FD_TEST( rv_B == FD_FEC_RESOLVER_SHRED_EQUIVOC );

  fd_fec_resolver_delete( fd_fec_resolver_leave( r ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_metrics_register( (ulong *)fd_metrics_new( metrics_scratch, 0UL ) );

  test_bp627_two_valid_sigs();
  test_bp627_real_equivocation();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
