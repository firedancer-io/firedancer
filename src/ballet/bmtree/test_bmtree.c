#include "../fd_ballet.h"

#include "../sha256/fd_sha256.h"

#define REFERENCE_PROOF_SZ  (80UL)
#define REFERENCE_PROOF_CNT (11UL)

FD_IMPORT_BINARY( reference_proofs,         "src/ballet/bmtree/reference_proofs.bin"         );

#define MEMORY_SZ (70UL*1024UL*1024UL)
uchar memory[ MEMORY_SZ ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
uchar inc_proof[ 63*32 ];

/* Test tree-20 construction */
static void
test_bmtree20_commit( ulong        leaf_cnt,
                      void const * expected_root ) {
  fd_bmtree_commit_t _tree[1];
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( _tree, 20UL, 1UL, 0UL ); FD_TEST( tree==_tree );

  fd_bmtree_node_t leaf[1];
  fd_memset( leaf->hash, 0, 20UL );
  for( ulong i=0UL; i<leaf_cnt; i++ ) {
    FD_TEST( fd_bmtree_commit_leaf_cnt( tree )==i );
    FD_STORE( ulong, leaf->hash, i );
    FD_TEST( fd_bmtree_commit_append( tree, leaf, 1UL )==tree );
  }

  FD_TEST( fd_bmtree_commit_leaf_cnt( tree )==leaf_cnt );

  uchar * root = fd_bmtree_commit_fini( tree ); FD_TEST( !!root );

  FD_TEST( fd_bmtree_commit_leaf_cnt( tree )==leaf_cnt );

  if( FD_UNLIKELY( memcmp( root, expected_root, 20UL ) ) )
    FD_LOG_ERR(( "FAIL (leaf_cnt %lu)"
                 "\n\tGot"
                 "\n\t\t" FD_LOG_HEX20_FMT
                 "\n\tExpected"
                 "\n\t\t" FD_LOG_HEX20_FMT,
                 leaf_cnt, FD_LOG_HEX20_FMT_ARGS( root ), FD_LOG_HEX20_FMT_ARGS( expected_root ) ));
}
static void
test_bmtree20_commitp( ulong        leaf_cnt,
                       void const * expected_root ) {
  FD_TEST( fd_bmtree_commit_footprint( fd_bmtree_depth( leaf_cnt ) ) < MEMORY_SZ ); /* Otherwise increase MEMORY_SZ */
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( memory, 20UL, 1UL, fd_bmtree_depth( leaf_cnt ) );
  FD_TEST( tree );

  FD_LOG_NOTICE(( "leaf_cnt %lu", leaf_cnt ));

  /* Iterate over evens */
  fd_bmtree_node_t leaf[1];
  fd_memset( leaf->hash, 0, 20UL );
  for( ulong i=0UL; i<leaf_cnt; i += 2UL ) {
    FD_STORE( ulong, leaf->hash, i );
    FD_TEST( fd_bmtree_commitp_insert_with_proof( tree, i, leaf, NULL, 0, NULL ) );
  }
  /* Then insert the odds */
  for( ulong i=1UL; i<leaf_cnt; i += 2UL ) {
    FD_STORE( ulong, leaf->hash, i );
    FD_TEST( fd_bmtree_commitp_insert_with_proof( tree, i, leaf, NULL, 0, NULL ) );
  }

  uchar * root = fd_bmtree_commitp_fini( tree, leaf_cnt );
  FD_TEST( root );
  FD_TEST( fd_memeq( root, expected_root, 20UL ) );
}


static void
hash_leaf( fd_bmtree_node_t * leaf,
           char const *       leaf_cstr ) {
  FD_TEST( fd_bmtree_hash_leaf( leaf, leaf_cstr, strlen( leaf_cstr ), 1UL )==leaf );
}


static void
test_inclusion( ulong leaf_cnt ) {
  ulong const prefix_sz = FD_BMTREE_LONG_PREFIX_SZ;
  FD_TEST( 9 >= fd_bmtree_depth( leaf_cnt ) );
  ulong footprint = fd_bmtree_commit_footprint( 9UL );
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( memory, 20UL, prefix_sz, 9UL );
  uchar * _memory = (uchar*)fd_ulong_align_up( (ulong)(memory+footprint), FD_BMTREE_COMMIT_ALIGN );
  fd_bmtree_commit_t * ptree = fd_bmtree_commit_init( _memory, 20UL, prefix_sz, 9UL );

  fd_bmtree_node_t leaf[1];
  fd_memset( leaf->hash, 0, 20UL );
  for( ulong i=0UL; i<leaf_cnt; i++ ) {
    FD_TEST( fd_bmtree_commit_leaf_cnt( tree )==i );
    FD_STORE( ulong, leaf->hash, i );
    FD_TEST( fd_bmtree_commit_append( tree, leaf, 1UL )==tree );
  }
  uchar * root = fd_bmtree_commit_fini( tree );

  fd_bmtree_node_t proof_root[1];
  fd_bmtree_node_t root2[1];

  ulong depth = fd_bmtree_depth( leaf_cnt );
  for( ulong i=0UL; i<leaf_cnt; i++ ) {
    FD_STORE( ulong, leaf->hash, i );
    FD_TEST( (int)depth-1==fd_bmtree_get_proof( tree, inc_proof, i ) );
    FD_TEST( proof_root==fd_bmtree_from_proof( leaf, i, proof_root, inc_proof, depth-1UL, 20UL, prefix_sz ) );
    FD_TEST( fd_memeq( root, proof_root, 32UL ) );
    FD_TEST( fd_bmtree_commitp_insert_with_proof( ptree, i, leaf, inc_proof, depth-1, root2 ) );
    FD_TEST( fd_memeq( root, root2, 32UL ) );

    if( FD_LIKELY( leaf_cnt>1UL ) ) {
      inc_proof[ 1 ]++; /* Corrupt the proof */
      FD_TEST( proof_root==fd_bmtree_from_proof( leaf, i, proof_root, inc_proof, depth-1UL, 20UL, prefix_sz ) );
      FD_TEST( !fd_memeq( root, proof_root, 32UL ) );
      FD_TEST( !fd_bmtree_commitp_insert_with_proof( ptree, i, leaf, inc_proof, depth-1, NULL ) );
      inc_proof[ 1 ]--;
    } /* Otherwise the proof is empty, so there's nothing to corrupt */

    root[ 1 ]++; /* Corrupt the root */
    FD_TEST( proof_root==fd_bmtree_from_proof( leaf, i, proof_root, inc_proof, depth-1UL, 20UL, prefix_sz ) );
    FD_TEST( !fd_memeq( root, proof_root, 32UL ) );
    root[ 1 ]--;

    leaf->hash[ 1 ]++; /* Corrupt the leaf */
    FD_TEST( proof_root==fd_bmtree_from_proof( leaf, i, proof_root, inc_proof, depth-1UL, 20UL, prefix_sz ) );
    FD_TEST( !fd_memeq( root, proof_root, 32UL ) );
    FD_TEST( !fd_bmtree_commitp_insert_with_proof( ptree, i, leaf, inc_proof, depth-1, NULL ) );
    leaf->hash[ 1 ]--;
  }
  uchar * root3 = fd_bmtree_commitp_fini( ptree, leaf_cnt );
  FD_TEST( root3 );
  FD_TEST( fd_memeq( root, root3, 32UL ) );
  FD_TEST( !fd_bmtree_from_proof( leaf, 1234567UL, proof_root, inc_proof, depth-1UL, 20UL, prefix_sz ) );

}



/* Appending all leaves at once must leave the same commit state as
   appending them one at a time. */
static void
test_append_batch( ulong leaf_cnt,
                   ulong hash_sz,
                   ulong prefix_sz ) {
  static uchar _a[ FD_BMTREE_COMMIT_FOOTPRINT( 7UL ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  static uchar _b[ FD_BMTREE_COMMIT_FOOTPRINT( 7UL ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_node_t leaf[ 64 ];
  for( ulong i=0UL; i<leaf_cnt; i++ ) { fd_memset( leaf[i].hash, (int)i+1, 32UL ); FD_STORE( ulong, leaf[i].hash, i*0x9e3779b97f4a7c15UL ); }

  fd_bmtree_commit_t * a = fd_bmtree_commit_init( _a, hash_sz, prefix_sz, 7UL );
  fd_bmtree_commit_t * b = fd_bmtree_commit_init( _b, hash_sz, prefix_sz, 7UL );
  for( ulong i=0UL; i<leaf_cnt; i++ ) FD_TEST( fd_bmtree_commit_append( a, leaf+i, 1UL )==a );
  FD_TEST( fd_bmtree_commit_append( b, leaf, leaf_cnt )==b );

  ulong depth = fd_bmtree_depth( leaf_cnt );
  FD_TEST( fd_bmtree_commit_leaf_cnt( b )==leaf_cnt );
  FD_TEST( !memcmp( a->node_buf, b->node_buf, depth*sizeof(fd_bmtree_node_t) ) );
  FD_TEST( !memcmp( a->inclusion_proofs, b->inclusion_proofs, a->inclusion_proof_sz*sizeof(fd_bmtree_node_t) ) );

  uchar * ra = fd_bmtree_commit_fini( a );
  uchar * rb = fd_bmtree_commit_fini( b );
  FD_TEST( !memcmp( ra, rb, 32UL ) );
  for( ulong i=0UL; i<leaf_cnt; i++ ) {
    uchar pa[ 7*32 ]; uchar pb[ 7*32 ];
    fd_memset( pa, 0xa5, sizeof(pa) ); fd_memset( pb, 0xa5, sizeof(pb) );
    int da = fd_bmtree_get_proof( a, pa, i );
    int db = fd_bmtree_get_proof( b, pb, i );
    FD_TEST( (da==db) & (da==(int)depth-1) );
    FD_TEST( !memcmp( pa, pb, sizeof(pa) ) );
  }
}

/* commitp20 must match commitp (hash_sz 20) on every insert, including
   truncated and corrupted proofs, and return the full 32 B top node. */
static void
test_commitp20( ulong      leaf_cnt,
                fd_rng_t * rng ) {
  ulong const prefix_sz = FD_BMTREE_LONG_PREFIX_SZ;
  ulong depth = fd_bmtree_depth( leaf_cnt );
  static uchar _ref[ FD_BMTREE_COMMIT_FOOTPRINT( 7UL ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  static uchar _full[ FD_BMTREE_COMMIT_FOOTPRINT( 7UL ) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  static uchar _c20[ FD_BMTREE_COMMITP20_FOOTPRINT( 7UL ) ] __attribute__((aligned(FD_BMTREE_COMMITP20_ALIGN)));
  FD_TEST( depth<=7UL );

  fd_bmtree_node_t leaf[ 64 ];
  fd_bmtree_commit_t * ref = fd_bmtree_commit_init( _ref, 20UL, prefix_sz, 7UL );
  for( ulong i=0UL; i<leaf_cnt; i++ ) {
    for( ulong j=0UL; j<32UL; j++ ) leaf[ i ].hash[ j ] = fd_rng_uchar( rng );
    fd_bmtree_commit_append( ref, leaf+i, 1UL );
  }
  uchar const * ref_root = fd_bmtree_commit_fini( ref );
  ulong accepted_bad = 0UL;

  for( ulong trial=0UL; trial<4UL; trial++ ) {
    accepted_bad = 0UL;
    fd_bmtree_commit_t    * full = fd_bmtree_commit_init( _full, 20UL, prefix_sz, depth );
    fd_bmtree_commitp20_t * c20  = fd_bmtree_commitp20_init( _c20, prefix_sz, depth );
    FD_TEST( c20 );

    for( ulong k=0UL; k<3UL*leaf_cnt; k++ ) {
      ulong i = fd_rng_ulong_roll( rng, leaf_cnt );
      uchar proof[ 7*20 ];
      FD_TEST( (int)depth-1==fd_bmtree_get_proof( ref, proof, i ) );
      ulong proof_depth = fd_ulong_if( (int)fd_rng_uint_roll( rng, 2U ), depth-1UL, fd_rng_ulong_roll( rng, depth ) );
      fd_bmtree_node_t l = leaf[ i ];
      uint corrupt = fd_rng_uint_roll( rng, 8U );
      if( corrupt==0U )                  l.hash[ fd_rng_uint_roll( rng, 20U ) ]++;
      if( corrupt==1U && proof_depth )   proof[ fd_rng_ulong_roll( rng, 20UL*proof_depth ) ]++;

      fd_bmtree_node_t r_full[1]; fd_bmtree_node_t r_c20[1];
      int rv_full = fd_bmtree_commitp_insert_with_proof  ( full, i, &l, proof, proof_depth, r_full );
      int rv_c20  = fd_bmtree_commitp20_insert_with_proof( c20,  i, &l, proof, proof_depth, r_c20  );
      FD_TEST( rv_full==rv_c20 );
      accepted_bad += (ulong)( rv_full & (corrupt<2U) & ( (corrupt==0U) | (proof_depth>0UL) ) );
      if( rv_full ) {
        /* A full proof reaches the top node, which must be all 32 B */
        FD_TEST( fd_memeq( r_full, r_c20, fd_ulong_if( proof_depth==depth-1UL, 32UL, 20UL ) ) );
      }
    }

    /* Fill in remaining leaves without proofs, odds first */
    for( ulong k=0UL; k<leaf_cnt; k++ ) {
      ulong j = fd_ulong_if( k<leaf_cnt/2UL, 2UL*k+1UL, 2UL*(k-leaf_cnt/2UL) );
      FD_TEST( fd_bmtree_commitp_insert_with_proof( full, j, leaf+j, NULL, 0UL, NULL )==fd_bmtree_commitp20_insert_with_proof( c20, j, leaf+j, NULL, 0UL, NULL ) );
    }

    uchar * f_full = fd_bmtree_commitp_fini  ( full, leaf_cnt );
    uchar * f_c20  = fd_bmtree_commitp20_fini( c20,  leaf_cnt );
    FD_TEST( !f_full==!f_c20 );
    if( f_full ) {
      FD_TEST( fd_memeq( f_full, f_c20, 32UL ) );
      if( !accepted_bad ) FD_TEST( fd_memeq( f_c20, ref_root, 32UL ) );
      for( ulong i=0UL; i<leaf_cnt; i++ ) {
        uchar pa[ 7*20 ]; uchar pb[ 7*20 ];
        fd_memset( pa, 0xa5, sizeof(pa) ); fd_memset( pb, 0xa5, sizeof(pb) );
        FD_TEST( fd_bmtree_get_proof( full, pa, i )==fd_bmtree_commitp20_get_proof( c20, pb, i ) );
        FD_TEST( fd_memeq( pa, pb, sizeof(pa) ) );
      }
    }
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 1234U, 0UL ) );
  for( ulong leaf_cnt=1UL; leaf_cnt<=64UL; leaf_cnt++ ) test_commitp20( leaf_cnt, rng );
  FD_TEST( !fd_bmtree_commitp20_init( memory, FD_BMTREE_LONG_PREFIX_SZ, 0UL ) );
  FD_TEST( !fd_bmtree_commitp20_init( memory, FD_BMTREE_LONG_PREFIX_SZ, FD_BMTREE_COMMITP20_LAYER_MAX+1UL ) );
  fd_rng_delete( fd_rng_leave( rng ) );

  for( ulong leaf_cnt=1UL; leaf_cnt<=64UL; leaf_cnt++ ) {
    test_append_batch( leaf_cnt, 20UL, 26UL );
    test_append_batch( leaf_cnt, 20UL,  1UL );
    test_append_batch( leaf_cnt, 32UL,  1UL );
  }

  /* Internal checks */
  FD_TEST( fd_bmtree_commit_align()         ==FD_BMTREE_COMMIT_ALIGN            );
  FD_TEST( fd_bmtree_commit_footprint( 0UL )==FD_BMTREE_COMMIT_FOOTPRINT( 0UL ) );

  /* Iterate test fd_bmtree_depth, fd_bmtree_node_cnt against naive
     division algorithm */

  FD_TEST( fd_bmtree_depth(    0UL )==0UL );
  FD_TEST( fd_bmtree_depth(    1UL )==1UL );
  FD_TEST( fd_bmtree_node_cnt( 0UL )==0UL );
  FD_TEST( fd_bmtree_node_cnt( 1UL )==1UL );

  for( ulong leaf_cnt=1UL; leaf_cnt<=256UL; leaf_cnt++ ) test_inclusion( leaf_cnt );

  for( ulong leaf_cnt=2UL; leaf_cnt<10000000UL; leaf_cnt++ ) {
    ulong depth = 1UL;
    ulong nodes = 1UL;
    for( ulong i=leaf_cnt; i>1UL; i=(i+1UL) >> 1 ) { depth++; nodes += i; }
    FD_TEST( fd_bmtree_depth(    leaf_cnt )==depth );
    FD_TEST( fd_bmtree_node_cnt( leaf_cnt )==nodes );
  }


  /* Test 20-byte tree */

  /* Construct trees of different sizes. */
  test_bmtree20_commit (       1UL, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" );
  test_bmtree20_commit (       2UL, "\x08\x11\x80\xe2\x59\x04\xa6\x23\xe5\x5c\x4a\x60\xc7\xfe\xd6\x7e\xe3\xd6\x7c\x4c" );
  test_bmtree20_commit (       3UL, "\x22\x50\xc2\x9d\x86\x90\xfa\x5c\x03\x94\x75\x17\x6d\x99\x06\xde\x2c\xc6\x0e\x79" );
  test_bmtree20_commit (      10UL, "\x42\x69\x92\xf5\x19\xee\x7e\x7b\xc2\xb6\x77\x6d\xc7\x82\x2d\x42\x68\x6a\xde\x25" );
  test_bmtree20_commit ( 1000000UL, "\x20\x61\x9a\x7a\xe4\x65\x27\x5a\x70\x9c\xa5\xc2\x8a\x21\x91\x6c\xdf\xf9\x0e\x26" ); /* TODO verify */
  test_bmtree20_commitp(       1UL, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" );
  test_bmtree20_commitp(       2UL, "\x08\x11\x80\xe2\x59\x04\xa6\x23\xe5\x5c\x4a\x60\xc7\xfe\xd6\x7e\xe3\xd6\x7c\x4c" );
  test_bmtree20_commitp(       3UL, "\x22\x50\xc2\x9d\x86\x90\xfa\x5c\x03\x94\x75\x17\x6d\x99\x06\xde\x2c\xc6\x0e\x79" );
  test_bmtree20_commitp(      10UL, "\x42\x69\x92\xf5\x19\xee\x7e\x7b\xc2\xb6\x77\x6d\xc7\x82\x2d\x42\x68\x6a\xde\x25" );
  test_bmtree20_commitp( 1000000UL, "\x20\x61\x9a\x7a\xe4\x65\x27\x5a\x70\x9c\xa5\xc2\x8a\x21\x91\x6c\xdf\xf9\x0e\x26" ); /* TODO verify */

  /* FIXME: WRITE BETTER BENCHMARK */
  ulong bench_cnt = 1000000UL;
  long dt = -fd_log_wallclock();
  test_bmtree20_commit( bench_cnt, "\x20\x61\x9a\x7a\xe4\x65\x27\x5a\x70\x9c\xa5\xc2\x8a\x21\x91\x6c\xdf\xf9\x0e\x26" );
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "%.3f ns/leaf @ %lu leaves", (double)((float)dt / (float)bench_cnt), bench_cnt ));

  /* Test 32-byte tree */

  // Source: https://github.com/solana-foundation/specs/blob/main/core/merkle-tree.md

  ulong leaf_cnt = 11UL;
  fd_bmtree_node_t leaf[ 11UL ];

  hash_leaf( leaf +  0, "my"     );
  hash_leaf( leaf +  1, "very"   );
  hash_leaf( leaf +  2, "eager"  );
  hash_leaf( leaf +  3, "mother" );
  hash_leaf( leaf +  4, "just"   );
  hash_leaf( leaf +  5, "served" );
  hash_leaf( leaf +  6, "us"     );
  hash_leaf( leaf +  7, "nine"   );
  hash_leaf( leaf +  8, "pizzas" );
  hash_leaf( leaf +  9, "make"   );
  hash_leaf( leaf + 10, "prime"  );

  fd_bmtree_commit_t _tree[1];
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( _tree, 32UL, 1UL, 0UL ); FD_TEST( tree==_tree );

  FD_TEST( fd_bmtree_commit_leaf_cnt( tree )==0UL );

  FD_TEST( fd_bmtree_commit_append( tree, leaf, leaf_cnt )==tree );

  FD_TEST( fd_bmtree_commit_leaf_cnt( tree )==leaf_cnt );

  uchar * root = fd_bmtree_commit_fini( tree );

  FD_TEST( fd_bmtree_commit_leaf_cnt( tree )==leaf_cnt );

# define _(v) ((uchar)0x##v)
  uchar const expected[FD_SHA256_HASH_SZ] = {
    _(b4),_(0c),_(84),_(75),_(46),_(fd),_(ce),_(ea),_(16),_(6f),_(92),_(7f),_(c4),_(6c),_(5c),_(a3),
    _(3c),_(36),_(38),_(23),_(6a),_(36),_(27),_(5c),_(13),_(46),_(d3),_(df),_(fb),_(84),_(e1),_(bc)
  };
# undef _

  if( FD_UNLIKELY( memcmp( root, expected, 32UL ) ) )
    FD_LOG_ERR(( "FAIL"
                 "\n\tGot"
                 "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT
                 "\n\tExpected"
                 "\n\t\t" FD_LOG_HEX16_FMT "  " FD_LOG_HEX16_FMT,
                 FD_LOG_HEX16_FMT_ARGS(     root ), FD_LOG_HEX16_FMT_ARGS(     root+16 ),
                 FD_LOG_HEX16_FMT_ARGS( expected ), FD_LOG_HEX16_FMT_ARGS( expected+16 ) ));


  tree = fd_bmtree_commit_init( memory, 20UL, 1UL, 5UL );
  FD_TEST( fd_bmtree_commit_append( tree, leaf, leaf_cnt )==tree );
  fd_bmtree_commit_fini( tree );

  for( ulong i=0UL; i<leaf_cnt; i++ ) {
    uchar proof[REFERENCE_PROOF_SZ];
    FD_TEST( 4UL==fd_bmtree_get_proof( tree, proof, i ) );

    FD_TEST( 0==memcmp( proof, reference_proofs + REFERENCE_PROOF_SZ*i, REFERENCE_PROOF_SZ ) );
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

