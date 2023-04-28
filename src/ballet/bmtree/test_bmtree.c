#include "../fd_ballet.h"
#include "fd_wbmtree.h"
#include "../../util/simd/fd_avx.h"
#include "../base58/fd_base58.h"
#include <stdio.h>

FD_STATIC_ASSERT( FD_BMTREE20_HASH_SZ         ==  20UL, unit_test );
FD_STATIC_ASSERT( FD_BMTREE20_COMMIT_ALIGN    ==  32UL, unit_test );
FD_STATIC_ASSERT( FD_BMTREE20_COMMIT_FOOTPRINT==2048UL, unit_test );

FD_STATIC_ASSERT( FD_BMTREE32_HASH_SZ         ==  32UL, unit_test );
FD_STATIC_ASSERT( FD_BMTREE32_COMMIT_ALIGN    ==  32UL, unit_test );
FD_STATIC_ASSERT( FD_BMTREE32_COMMIT_FOOTPRINT==2048UL, unit_test );

FD_STATIC_ASSERT( FD_BMTREE20_COMMIT_ALIGN    ==alignof(fd_bmtree20_commit_t), unit_test );
FD_STATIC_ASSERT( FD_BMTREE20_COMMIT_FOOTPRINT==sizeof (fd_bmtree20_commit_t), unit_test );

FD_STATIC_ASSERT( FD_BMTREE32_COMMIT_ALIGN    ==alignof(fd_bmtree32_commit_t), unit_test );
FD_STATIC_ASSERT( FD_BMTREE32_COMMIT_FOOTPRINT==sizeof (fd_bmtree32_commit_t), unit_test );

/* Test tree-20 construction */

#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize ("O0")
#endif

static void
test_bmtree20_commit( ulong        leaf_cnt,
                      void const * expected_root ) {
  fd_bmtree20_commit_t   _tree[1];
  fd_bmtree20_commit_t * tree = fd_bmtree20_commit_init( _tree ); FD_TEST( tree==_tree );

  fd_bmtree20_node_t leaf[1];
  fd_memset( leaf->hash, 0, 20UL );
  for( ulong i=0UL; i<leaf_cnt; i++ ) {
    FD_TEST( fd_bmtree20_commit_leaf_cnt( tree )==i );
    FD_STORE( ulong, leaf->hash, i );
    FD_TEST( fd_bmtree20_commit_append( tree, leaf, 1UL )==tree );
  }

  FD_TEST( fd_bmtree20_commit_leaf_cnt( tree )==leaf_cnt );

  uchar * root = fd_bmtree20_commit_fini( tree ); FD_TEST( !!root );

  FD_TEST( fd_bmtree20_commit_leaf_cnt( tree )==leaf_cnt );

  if( FD_UNLIKELY( memcmp( root, expected_root, 20UL ) ) )
    FD_LOG_ERR(( "FAIL (leaf_cnt %lu)"
                 "\n\tGot"
                 "\n\t\t" FD_LOG_HEX20_FMT
                 "\n\tExpected"
                 "\n\t\t" FD_LOG_HEX20_FMT,
                 leaf_cnt, FD_LOG_HEX20_FMT_ARGS( root ), FD_LOG_HEX20_FMT_ARGS( expected_root ) ));
}

//static void
//test_bmtree32_commit( ulong        leaf_cnt,
//                      void const * expected_root ) {
//}

static void
hash_leaf( fd_bmtree32_node_t * leaf,
           char const *         leaf_cstr ) {
  FD_TEST( fd_bmtree32_hash_leaf( leaf, leaf_cstr, strlen( leaf_cstr ) )==leaf );
}

uchar* local_allocf(ulong align, ulong len) {
  ulong   sz = fd_ulong_align_up(sizeof(char *) + len + align, align);
  uchar * ptr = malloc(sz);
  uchar * ret = (uchar *) fd_ulong_align_up( (ulong) (ptr + sizeof(char *)), align );
  *((uchar **)(ret - sizeof(char *))) = ptr;
  return ret;
}

void local_freef(void *ptr) {
  free(*((char **)((char *) ptr - sizeof(char *))));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Internal checks */

  /* Iterate test fd_bmtree_depth against naive division algorithm */

  FD_TEST( fd_bmtree20_private_depth( 0UL )==0UL ); FD_TEST( fd_bmtree32_private_depth( 0UL )==0UL );
  FD_TEST( fd_bmtree20_private_depth( 1UL )==1UL ); FD_TEST( fd_bmtree32_private_depth( 1UL )==1UL );

  for( ulong node_cnt=2UL; node_cnt<10000000UL; node_cnt++ ) {
    ulong depth = 1UL;
    for( ulong i=node_cnt; i>1UL; i=(i+1UL) >> 1 ) depth++;
    FD_TEST( fd_bmtree20_private_depth( node_cnt )==depth ); FD_TEST( fd_bmtree32_private_depth( node_cnt )==depth );
  }

  /* Test 20-byte tree */

  FD_TEST( fd_bmtree20_commit_align()    ==FD_BMTREE20_COMMIT_ALIGN     );
  FD_TEST( fd_bmtree20_commit_footprint()==FD_BMTREE20_COMMIT_FOOTPRINT );

  /* Construct trees of different sizes. */
  test_bmtree20_commit(       1UL, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" );
  test_bmtree20_commit(       2UL, "\x08\x11\x80\xe2\x59\x04\xa6\x23\xe5\x5c\x4a\x60\xc7\xfe\xd6\x7e\xe3\xd6\x7c\x4c" );
  test_bmtree20_commit(       3UL, "\x22\x50\xc2\x9d\x86\x90\xfa\x5c\x03\x94\x75\x17\x6d\x99\x06\xde\x2c\xc6\x0e\x79" );
  test_bmtree20_commit(      10UL, "\x42\x69\x92\xf5\x19\xee\x7e\x7b\xc2\xb6\x77\x6d\xc7\x82\x2d\x42\x68\x6a\xde\x25" );
  test_bmtree20_commit( 1000000UL, "\x20\x61\x9a\x7a\xe4\x65\x27\x5a\x70\x9c\xa5\xc2\x8a\x21\x91\x6c\xdf\xf9\x0e\x26" ); /* TODO verify */

  /* FIXME: WRITE BETTER BENCHMARK */
  ulong bench_cnt = 1000000UL;
  long  dt = -fd_log_wallclock();
  test_bmtree20_commit( bench_cnt, "\x20\x61\x9a\x7a\xe4\x65\x27\x5a\x70\x9c\xa5\xc2\x8a\x21\x91\x6c\xdf\xf9\x0e\x26" );
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "%.3f ns/leaf @ %lu leaves", (double)((float)dt / (float)bench_cnt), bench_cnt ));

  /* Test 32-byte tree */

  // Source: https://github.com/solana-foundation/specs/blob/main/core/merkle-tree.md

  ulong              leaf_cnt = 11UL;
  fd_bmtree32_node_t leaf[ 11UL ];
  char *             vals[] = {"my" , "very" , "eager" , "mother" , "just" , "served" , "us" , "nine" , "pizzas" , "make" , "prime" };

  for (ulong i = 0; i < leaf_cnt; i++)
    hash_leaf( leaf +  i, vals[i] );

  FD_TEST( fd_bmtree32_commit_align()    ==FD_BMTREE32_COMMIT_ALIGN     );
  FD_TEST( fd_bmtree32_commit_footprint()==FD_BMTREE32_COMMIT_FOOTPRINT );

  fd_bmtree32_commit_t   _tree[1];
  fd_bmtree32_commit_t * tree = fd_bmtree32_commit_init( _tree ); FD_TEST( tree==_tree );

  FD_TEST( fd_bmtree32_commit_leaf_cnt( tree )==0UL );

  FD_TEST( fd_bmtree32_commit_append( tree, leaf, leaf_cnt )==tree );

  FD_TEST( fd_bmtree32_commit_leaf_cnt( tree )==leaf_cnt );

  uchar * root = fd_bmtree32_commit_fini( tree );

  FD_TEST( fd_bmtree32_commit_leaf_cnt( tree )==leaf_cnt );

  unsigned char *  mem = local_allocf(128UL, fd_wbmtree32_footprint(leaf_cnt));
  fd_wbmtree32_t * wide_bmtree = fd_wbmtree32_init(mem, leaf_cnt);

  // This is annoying.. that we are booting off a different format... lets revisit this..
  fd_wbmtree32_leaf_t leafs[leaf_cnt];
  ulong               tsize = 0;
  for (ulong i = 0; i < leaf_cnt; i++) {
    leafs[i].data = (unsigned char *) vals[i];
    leafs[i].data_len = strlen(vals[i]);
    tsize += leafs[i].data_len + 1;
  }

  unsigned char *cbuf = local_allocf(1UL, tsize);

  fd_wbmtree32_append(wide_bmtree, leafs, leaf_cnt, cbuf);
  uchar *root2 = fd_wbmtree32_fini(wide_bmtree);

  local_freef(mem);
  local_freef(cbuf);

  FD_TEST( memcmp(root, root2, 32) == 0 );

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

  leaf_cnt = 1000000;

  ulong  sz = leaf_cnt * 65;
  uchar *d = malloc(sz);
  for (ulong i = 0; i < sz; i++)
    d[i] = i&0xff;

  fd_bmtree32_node_t *l = (fd_bmtree32_node_t *) malloc(leaf_cnt * sizeof(fd_bmtree32_node_t));

  // This is what we are timing,
  dt = -fd_log_wallclock();
  for (ulong i = 0; i < leaf_cnt; i++)
    fd_bmtree32_hash_leaf( l+i, &d[i*65], 65);
  fd_bmtree32_commit_append( tree, l, leaf_cnt );
  root = fd_bmtree32_commit_fini( tree );
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "%.3f ns/leaf @ %lu leaves  -- fd_bmtree32_ code path", (double)((float)dt / (float)leaf_cnt), leaf_cnt ));

  mem = local_allocf(128UL, fd_wbmtree32_footprint(leaf_cnt));
  wide_bmtree = fd_wbmtree32_init(mem, leaf_cnt);

  // This is annoying.. that we are booting off a different format... lets revisit this..
  fd_wbmtree32_leaf_t *leaf2 = (fd_wbmtree32_leaf_t *)local_allocf(128UL, sizeof(fd_wbmtree32_leaf_t) * leaf_cnt);
  tsize = 0;
  for (ulong i = 0; i < leaf_cnt; i++) {
    leaf2[i].data = (unsigned char *) &d[i*65];
    leaf2[i].data_len = 65;
    tsize += leaf2[i].data_len + 1;
  }

  cbuf = local_allocf(1UL, tsize);
  dt = -fd_log_wallclock();
  fd_wbmtree32_append(wide_bmtree, leaf2, leaf_cnt, cbuf);
  root2 = fd_wbmtree32_fini(wide_bmtree);
  dt += fd_log_wallclock();
  FD_LOG_NOTICE(( "%.3f ns/leaf @ %lu leaves  -- fd_wbmtree32_ code path", (double)((float)dt / (float)leaf_cnt), leaf_cnt ));

  local_freef(mem);
  local_freef(cbuf);

  char * sigs[] = { "3gHmkVTtVpPinzNGZE9C3Fjsao5T74yrENzkeJCwGUu2GZEhydvPQjWbtiwhPGnevkpfsyMHvTDNMpGf2YjPQNxa", 
                    "KwpKjWrwxnV9H5ejWZ7WzX7h86xmAZEfQRFQHnsdKCdYAGXaeaVotkso9gM1tWSTk92asQF2Sy4ai8H3W3VeRxm",
                    "naDHRgKqqVDFvZb2RG7aVoHNZxGd1aY2HsDjEEYvfxQgjuEz5KeuKE6b2My2HNsxH2orpQB626sgAeMjgUN474a"
  };
  ulong              sigs_cnt = sizeof(sigs) / sizeof(sigs[0]);;
  fd_bmtree32_node_t sigs_leaf[ sigs_cnt ];

  tree = fd_bmtree32_commit_init( _tree );
  FD_TEST( fd_bmtree32_commit_leaf_cnt( tree )==0UL );

  for (ulong i = 0; i < sigs_cnt; i++) {
    char buf[64];
    fd_base58_decode_64( sigs[i],  (unsigned char *) buf);
    fd_bmtree32_hash_leaf( sigs_leaf + i, buf, sizeof(buf) );
    FD_TEST( fd_bmtree32_commit_append( tree, sigs_leaf + i, 1 )==tree );
  }

  //FD_TEST( fd_bmtree32_commit_append( tree, sigs_leaf, sigs_cnt )==tree );

  root = fd_bmtree32_commit_fini( tree );

  char encoded_root[50];
  fd_base58_encode_32((uchar *) root, NULL, encoded_root);

  FD_LOG_NOTICE(( "%s", encoded_root ));

// mixin: 679cSmvKtaU7N5GFKNAheibmUq6vyNEAaz4gvKKez4WQ
// markle_tree: MerkleTree { leaf_count: 3, nodes: [679cSmvKtaU7N5GFKNAheibmUq6vyNEAaz4gvKKez4WQ, HMUgEFKS2o74gvJJ9k5xDnci3cfV2woNdMTARYdc4SLW, 7v8SHXjZaR5kmbFFeFyp71EHNTYf1UZT18ZkJnce2oZw, 9eovxaBahfaRnXo16mAGNxWBF9G1VyeZT3GYxebDdmQy, 4agJvx37ochKYNeEX3NZF7dKWKhpA1X2dhVMfUoyzHR1, AgVm6NDMgVdjGhTbKE8LdukfpTdUVXS8sFQ25jGP8tr9] }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

