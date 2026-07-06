/* test_bhp_627_integration.c

   Integration test for BHP-627 (= BP-627): consensus-layer projection
   of the FEC-resolver divergence.  Given two shreds in the same FEC
   set that reconstruct the same 32-byte merkle root but carry
   byte-different, individually-valid ed25519 signatures under the
   leader keypair, the correct behavior (matching Agave's
   check_merkle_root_consistency at agave/ledger/src/blockstore.rs
   :3010) is to ingest both shreds and continue toward completion.
   The buggy behavior returned FD_FEC_RESOLVER_SHRED_EQUIVOC, which
   propagated through fd_shred_tile -> fd_tower_tile -> fd_eqvoc ->
   fd_ghost_eqvoc, marked the block invalid, and made FD abstain from
   voting on a block Agave would vote on.

   This test drives the resolver end-to-end AND simulates the
   tower-tile propagation:

     1. Build a valid 32-data/32-parity chained-merkle FEC set with a
        controlled leader keypair (slot=100, fec_set_idx=0).
     2. Craft a second valid ed25519 signature Sig_B over the same
        merkle root M via an RFC-8032-compatible signer with a
        distinct nonce seed.  Sig_A != Sig_B, but both verify.
     3. Build a ghost tree: root -> eqvoc_blk -> child_blk.
     4. Feed shred_A (Sig_A) into fd_fec_resolver_add_shred -- assert
        SHRED_OKAY.
     5. Feed shred_B (Sig_B) into fd_fec_resolver_add_shred.
        - Simulate the tower-tile propagation: if the resolver returns
          EQUIVOC, call fd_ghost_eqvoc on eqvoc_blk (this mirrors
          fd_shred_tile.c publishing SHRED_SIG_RESULT_EQVOC -> the
          tower tile calling fd_eqvoc_shred_insert -> the SLOT_COMPLETED
          handler firing fd_ghost_eqvoc).
     6. Assert eqvoc_blk->valid == 1.  This is the load-bearing
        assertion: FD did not mark the block invalid, so fork-choice
        can still select it and FD's vote is preserved.

   Behavior across the fix:
     - Before BP-627 fix: resolver returns EQUIVOC on step (5); the
       simulated propagation calls fd_ghost_eqvoc; eqvoc_blk->valid
       drops to 0; assertion FAILS.
     - After BP-627 fix: resolver returns IGNORED on step (5); no
       propagation; eqvoc_blk->valid stays 1; assertion PASSES.

   This makes the test a real failure signal for the BP-627 bug and a
   real passing signal for the fix -- not a documentation-only
   scaffold.

   Layout: this test lives under discof/tower/ because the
   consensus-visible effect (vote-abstain) surfaces at the tower tile
   through fd_ghost.  The sibling unit test at
   src/disco/shred/test_fec_resolver_bp627.c asserts the resolver-only
   behavior; this test asserts that behavior does not break the
   downstream vote path. */

#include "../../../disco/shred/fd_fec_resolver.h"
#include "../../../disco/shred/fd_shredder.h"
#include "../../../disco/shred/fd_fec_set.h"
#include "../../../ballet/shred/fd_shred.h"
#include "../../../ballet/ed25519/fd_ed25519.h"
#include "../../../ballet/ed25519/fd_curve25519.h"
#include "../../../ballet/ed25519/fd_curve25519_scalar.h"
#include "../../../choreo/ghost/fd_ghost.h"
#include "../../../disco/metrics/fd_metrics.h"

#include <string.h>

FD_IMPORT_BINARY( bhp627_private_key, "src/disco/shred/fixtures/demo-shreds.key" );

#define SHRED_VER (ushort)6051
#define MAX       (32UL*1024UL)
#define SEED      10388431120836828144UL

static uchar bhp627_entry_batch[ 32768UL ];
static uchar bhp627_res_mem[ 1024UL*1024UL ] __attribute__((aligned(FD_FEC_RESOLVER_ALIGN)));
static fd_fec_set_t bhp627_out_sets[ 4UL ];
static fd_fec_set_t bhp627_set[ 1UL ];
static fd_shredder_t bhp627_shredder[ 1 ];
static uchar bhp627_metrics_scratch[ FD_METRICS_FOOTPRINT( 0 ) ] __attribute__((aligned(FD_METRICS_ALIGN)));

struct bhp627_signer_ctx {
  fd_sha512_t   sha512[ 1 ];
  uchar const * public_key;
  uchar const * private_key;
};
typedef struct bhp627_signer_ctx bhp627_signer_ctx_t;

static void
bhp627_signer_init( bhp627_signer_ctx_t * ctx,
                    uchar const *         private_key ) {
  FD_TEST( fd_sha512_init( fd_sha512_new( ctx->sha512 ) ) );
  ctx->public_key  = private_key + 32UL;
  ctx->private_key = private_key;
}

static void
bhp627_det_signer( void *        _ctx,
                   uchar *       signature,
                   uchar const * merkle_root ) {
  bhp627_signer_ctx_t * ctx = (bhp627_signer_ctx_t *)_ctx;
  fd_ed25519_sign( signature, merkle_root, 32UL, ctx->public_key, ctx->private_key, ctx->sha512 );
}

/* Produces a valid ed25519 signature over msg using a caller-supplied
   nonce_seed instead of the RFC-8032 prefix.  See the sibling test at
   src/disco/shred/test_fec_resolver_bp627.c for the full derivation
   commentary. */
static void
bhp627_alt_ed25519_sign( uchar         sig[ 64 ],
                         uchar const   msg[ 32 ],
                         uchar const   public_key[ 32 ],
                         uchar const   private_key[ 32 ],
                         uchar const   nonce_seed[ 32 ],
                         fd_sha512_t * sha ) {
  uchar s_h[ FD_SHA512_HASH_SZ ];
  fd_sha512_fini( fd_sha512_append( fd_sha512_init( sha ), private_key, 32UL ), s_h );
  s_h[ 0] &= (uchar)0xF8;
  s_h[31] &= (uchar)0x7F;
  s_h[31] |= (uchar)0x40;
  uchar * s = s_h;

  uchar r[ FD_SHA512_HASH_SZ ];
  fd_sha512_fini( fd_sha512_append( fd_sha512_append( fd_sha512_init( sha ), nonce_seed, 32UL ), msg, 32UL ), r );
  fd_curve25519_scalar_reduce( r, r );

  fd_ed25519_point_t R[1];
  fd_ed25519_scalar_mul_base_const_time( R, r );
  fd_ed25519_point_tobytes( sig, R );

  uchar k[ FD_SHA512_HASH_SZ ];
  fd_sha512_fini( fd_sha512_append( fd_sha512_append( fd_sha512_append( fd_sha512_init( sha ),
                  sig, 32UL ), public_key, 32UL ), msg, 32UL ), k );
  fd_curve25519_scalar_reduce( k, k );

  fd_curve25519_scalar_muladd( sig + 32UL, k, s, r );
}

static void
test_bhp_627_end_to_end( fd_wksp_t * wksp ) {
  bhp627_signer_ctx_t signer_ctx[ 1 ];
  bhp627_signer_init( signer_ctx, bhp627_private_key );

  uchar const * private_key = bhp627_private_key;
  uchar const * pubkey      = bhp627_private_key + 32UL;

  for( ulong i=0UL; i<sizeof(bhp627_entry_batch); i++ ) bhp627_entry_batch[ i ] = (uchar)(i*0x9EU + 0x37U);
  ulong const data_sz = 28000UL;
  FD_TEST( fd_shredder_count_fec_sets( data_sz, 1 ) == 1UL );
  FD_TEST( fd_shredder_count_data_shreds( data_sz, 1 ) == FD_FEC_SHRED_CNT );

  FD_TEST( bhp627_shredder==fd_shredder_new( bhp627_shredder, bhp627_det_signer, signer_ctx ) );
  fd_shredder_t * shredder = fd_shredder_join( bhp627_shredder ); FD_TEST( shredder );
  fd_shredder_set_shred_version( shredder, SHRED_VER );

  fd_entry_batch_meta_t meta[1];
  fd_memset( meta, 0, sizeof(fd_entry_batch_meta_t) );
  meta->block_complete = 1;
  meta->parent_offset  = 1UL;

  ulong const slot = 100UL;
  FD_TEST( fd_shredder_init_batch( shredder, bhp627_entry_batch, data_sz, slot, meta ) );
  uchar chained_merkle_root[ 32 ] = { 0 };
  fd_fec_set_t * set = fd_shredder_next_fec_set( shredder, bhp627_set, chained_merkle_root );
  FD_TEST( set );
  FD_TEST( fd_shredder_fini_batch( shredder ) );

  uchar bmtree_mem[ fd_bmtree_commit_footprint( FD_SHRED_MERKLE_LAYER_CNT ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_node_t M[1] = { 0 };
  FD_TEST( fd_shred_merkle_root( set->data_shreds[ 0 ].s, bmtree_mem, M ) );

  uchar Sig_A[ 64 ];
  fd_memcpy( Sig_A, set->data_shreds[ 0 ].s->signature, 64UL );

  fd_sha512_t _sha[ 1 ];
  fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( _sha ) );
  FD_TEST( FD_ED25519_SUCCESS == fd_ed25519_verify( M->hash, 32UL, Sig_A, pubkey, sha ) );

  uchar Sig_B[ 64 ];
  static const uchar nonce_seed[ 32 ] = {
    0xB6,0x27,0xBE,0xEF,0xF0,0x0D,0xDE,0xAD,
    0xCA,0xFE,0xBA,0xBE,0xFA,0xCE,0xB0,0x0C,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
  };
  bhp627_alt_ed25519_sign( Sig_B, M->hash, pubkey, private_key, nonce_seed, sha );

  FD_TEST( 0 != memcmp( Sig_A, Sig_B, 64UL ) );
  FD_TEST( FD_ED25519_SUCCESS == fd_ed25519_verify( M->hash, 32UL, Sig_B, pubkey, sha ) );

  fd_sha512_delete( fd_sha512_leave( sha ) );

  uchar shred_A_buf[ FD_SHRED_MIN_SZ ];
  uchar shred_B_buf[ FD_SHRED_MIN_SZ ];
  fd_memcpy( shred_A_buf, set->data_shreds[ 0 ].b, FD_SHRED_MIN_SZ );
  fd_memcpy( shred_B_buf, set->data_shreds[ 1 ].b, FD_SHRED_MIN_SZ );
  fd_memcpy( shred_B_buf, Sig_B, 64UL );

  /* Build a small ghost tree: root -> eqvoc_blk (slot 100) -> child.
     block_ids are placeholders (ghost topology is what we care about;
     any distinct 32-byte value works). */
  ulong const blk_max = 8UL;
  ulong const vtr_max = 8UL;
  void       * ghost_mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( blk_max, vtr_max ), 42UL );
  FD_TEST( ghost_mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( ghost_mem, blk_max, vtr_max, 42UL ) );
  FD_TEST( ghost );

  fd_hash_t const root_id  = { .ul = { 0xB6270000UL, 0UL, 0UL, 0UL } };
  fd_hash_t const eqvoc_id = { .ul = { 0xB6270001UL, 0UL, 0UL, 0UL } };
  fd_hash_t const child_id = { .ul = { 0xB6270002UL, 0UL, 0UL, 0UL } };

  fd_ghost_blk_t * root_blk  = fd_ghost_init( ghost, 0UL, 99UL, &root_id );
  FD_TEST( root_blk && root_blk->valid == 1 );

  fd_ghost_blk_t * eqvoc_blk = fd_ghost_insert( ghost, 100UL, 100UL, &eqvoc_id, &root_id );
  FD_TEST( eqvoc_blk && eqvoc_blk->valid == 1 );

  fd_ghost_blk_t * child_blk = fd_ghost_insert( ghost, 101UL, 101UL, &child_id, &eqvoc_id );
  FD_TEST( child_blk && child_blk->valid == 1 );

  /* Drive the resolver. */
  fd_fec_resolver_t * r =
      fd_fec_resolver_join( fd_fec_resolver_new( bhp627_res_mem, NULL, NULL, 2UL, 1UL, 1UL, 1UL, bhp627_out_sets, SEED ) );
  FD_TEST( r );
  fd_fec_resolver_set_shred_version( r, SHRED_VER );

  fd_fec_set_t const * out_fec[ 1 ];
  fd_shred_t   const * out_shred[ 1 ];
  fd_bmtree_node_t     out_merkle_root[ 1 ];

  fd_shred_t const * parsed_A = fd_shred_parse( shred_A_buf, FD_SHRED_MIN_SZ, FD_SHRED_BLK_MAX );
  FD_TEST( parsed_A );
  int rv_A = fd_fec_resolver_add_shred( r, parsed_A, FD_SHRED_MIN_SZ, MAX, 0, pubkey,
                                        out_fec, out_shred, out_merkle_root, NULL );
  FD_LOG_NOTICE(( "BHP-627 integration: add_shred(shred_A, Sig_A) returned %d", rv_A ));
  FD_TEST( rv_A == FD_FEC_RESOLVER_SHRED_OKAY );

  fd_shred_t const * parsed_B = fd_shred_parse( shred_B_buf, FD_SHRED_MIN_SZ, FD_SHRED_BLK_MAX );
  FD_TEST( parsed_B );
  int rv_B = fd_fec_resolver_add_shred( r, parsed_B, FD_SHRED_MIN_SZ, MAX, 0, pubkey,
                                        out_fec, out_shred, out_merkle_root, NULL );
  FD_LOG_NOTICE(( "BHP-627 integration: add_shred(shred_B, Sig_B) returned %d", rv_B ));

  /* Simulate the tower-tile propagation.  In the real tile:
       fd_shred_tile.c publishes SHRED_SIG_RESULT_EQVOC when the
         resolver returns EQUIVOC (fd_shred_tile.c:997).
       fd_tower_tile.c:1732 calls fd_eqvoc_shred_insert with
         shred_hint=1.
       fd_eqvoc.c:717-728 inserts a proof.
       fd_tower_tile.c:1268-1275 fires fd_ghost_eqvoc on SLOT_COMPLETED.
     For this test we compress the whole chain into a single
     conditional: if the resolver reports EQUIVOC, invoke
     fd_ghost_eqvoc on the equivocated slot. */
  if( rv_B == FD_FEC_RESOLVER_SHRED_EQUIVOC ) {
    FD_LOG_NOTICE(( "BHP-627 integration: resolver returned EQUIVOC; "
                    "simulating tower-tile propagation to fd_ghost_eqvoc" ));
    fd_ghost_eqvoc( ghost, &eqvoc_id );
  }

  /* Load-bearing assertion: eqvoc_blk stays valid.  For the block to
     retain a chance of receiving FD's vote, the ghost's valid flag
     must not be zeroed.
     - Before fix: rv_B == EQUIVOC, fd_ghost_eqvoc runs, valid drops
       to 0 (fd_ghost.c:638), this assertion fails.
     - After fix: rv_B == IGNORED, fd_ghost_eqvoc is skipped, valid
       stays 1, this assertion passes. */
  FD_TEST( eqvoc_blk->valid == 1 );
  FD_TEST( child_blk->valid == 1 );
  FD_TEST( root_blk->valid  == 1 );
  FD_LOG_NOTICE(( "BHP-627 integration: eqvoc_blk.valid=%d child_blk.valid=%d "
                  "-- vote path preserved", eqvoc_blk->valid, child_blk->valid ));

  /* Fork-choice remains selectable on the eqvoc slot's subtree.
     fd_ghost_best traverses through valid children only; child_blk
     is a leaf and eqvoc_blk is its parent, both valid, so best from
     root reaches child_blk. */
  fd_ghost_blk_t * best = fd_ghost_best( ghost, root_blk );
  FD_TEST( best == child_blk );
  FD_LOG_NOTICE(( "BHP-627 integration: fd_ghost_best(root) == child (slot %lu) "
                  "-- fork-choice can still select the eqvoc subtree", best->slot ));

  /* fd_ghost_invalid_ancestor on child returns NULL (no invalid
     ancestor on the fork). */
  FD_TEST( fd_ghost_invalid_ancestor( ghost, child_blk ) == NULL );

  fd_fec_resolver_delete( fd_fec_resolver_leave( r ) );
  fd_wksp_free_laddr( fd_ghost_delete( fd_ghost_leave( ghost ) ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_metrics_register( (ulong *)fd_metrics_new( bhp627_metrics_scratch, 0UL ) );

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"               );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL                      );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( 0UL ) );
  fd_wksp_t *  wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  FD_LOG_NOTICE(( "BHP-627 integration test: resolver -> ghost vote-path preservation" ));

  test_bhp_627_end_to_end( wksp );

  FD_LOG_NOTICE(( "BHP-627 integration test pass" ));

  fd_wksp_delete_anonymous( wksp );
  fd_halt();
  return 0;
}
