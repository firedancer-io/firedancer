#include "fd_rotor_serde.h"
#include "../../ballet/bmtree/fd_bmtree.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../disco/shred/fd_fec_set.h"

/* agave core/src/repair/serve_repair.rs RepairProtocol, encoded with
   wincode's default config: u32 tag, fixint little endian, no padding */

FD_STATIC_ASSERT( FD_ROTOR_PONG_SER_SZ                      ==132UL, fd_rotor_serde );
FD_STATIC_ASSERT( FD_ROTOR_WINDOW_INDEX_SER_SZ              ==160UL, fd_rotor_serde );
FD_STATIC_ASSERT( FD_ROTOR_HIGHEST_WINDOW_INDEX_SER_SZ      ==160UL, fd_rotor_serde );
FD_STATIC_ASSERT( FD_ROTOR_ORPHAN_SER_SZ                    ==152UL, fd_rotor_serde );
FD_STATIC_ASSERT( FD_ROTOR_PARENT_AND_FEC_SET_COUNT_SER_SZ  ==184UL, fd_rotor_serde );
FD_STATIC_ASSERT( FD_ROTOR_FEC_SET_ROOT_SER_SZ              ==188UL, fd_rotor_serde );
FD_STATIC_ASSERT( FD_ROTOR_WINDOW_INDEX_FOR_BLOCK_ID_SER_SZ ==188UL, fd_rotor_serde );
FD_STATIC_ASSERT( FD_ROTOR_SER_MAX                          ==188UL, fd_rotor_serde );
FD_STATIC_ASSERT( FD_ROTOR_SIG_SER_MAX                      ==124UL, fd_rotor_serde );

#define SIGNATURE_OFF (  4UL )
#define SENDER_OFF    ( 68UL )
#define RECIPIENT_OFF (100UL )
#define TIMESTAMP_OFF (132UL )
#define NONCE_OFF     (140UL )
#define SLOT_OFF      (144UL )
#define BODY_OFF      (152UL )

#define TIMESTAMP (0x0102030405060708UL)
#define NONCE     (0x0a0b0c0dU)
#define SLOT      (0x1112131415161718UL)

static fd_ed25519_sig_t signature;
static fd_pubkey_t      sender;
static fd_pubkey_t      recipient;

static void
fill( void * p, ulong sz, uchar seed ) {
  for( ulong i=0UL; i<sz; i++ ) ((uchar *)p)[ i ] = (uchar)( seed+i );
}

/* check_header checks the tag, the RepairRequestHeader, the slot and
   the signing preimage of a request ser wrote sz bytes of into buf. */

static void
check_header( uchar const * buf,
              ulong         sz,
              uint          tag ) {
  FD_TEST( FD_LOAD( uint, buf )==tag );
  FD_TEST( !memcmp( buf+SIGNATURE_OFF, signature,    FD_ED25519_SIG_SZ   ) );
  FD_TEST( !memcmp( buf+SENDER_OFF,    sender.uc,    sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( buf+RECIPIENT_OFF, recipient.uc, sizeof(fd_pubkey_t) ) );
  FD_TEST( FD_LOAD( ulong, buf+TIMESTAMP_OFF )==TIMESTAMP );
  FD_TEST( FD_LOAD( uint,  buf+NONCE_OFF     )==NONCE     );
  FD_TEST( FD_LOAD( ulong, buf+SLOT_OFF      )==SLOT      );

  uchar pre[ FD_ROTOR_SIG_SER_MAX ];
  FD_TEST( fd_rotor_req_sig_ser( buf, sz, pre )==sz-FD_ED25519_SIG_SZ );
  FD_TEST( !memcmp( pre,     buf,            sizeof(uint)  ) );
  FD_TEST( !memcmp( pre+4UL, buf+SENDER_OFF, sz-SENDER_OFF ) );
}

static void
test_pong( void ) {
  uchar           buf[ FD_ROTOR_SER_MAX ];
  fd_rotor_pong_t pong; fill( &pong.hash, sizeof(fd_hash_t), 41 );
  FD_TEST( fd_rotor_pong_ser( &pong, signature, &sender, buf )==132UL );
  FD_TEST( FD_LOAD( uint, buf )==7U );
  FD_TEST( !memcmp( buf+4UL,  sender.uc,    32UL ) );
  FD_TEST( !memcmp( buf+36UL, pong.hash.uc, 32UL ) );
  FD_TEST( !memcmp( buf+68UL, signature,    64UL ) );
}

static void
test_requests( void ) {
  uchar buf[ FD_ROTOR_SER_MAX ];

  fd_rotor_shred_t shred = { .slot = SLOT, .shred_idx = 0x2122232425262728UL };
  FD_TEST( fd_rotor_req_window_index_ser( &shred, signature, &sender, &recipient, TIMESTAMP, NONCE, buf )==160UL );
  check_header( buf, 160UL, 8U );
  FD_TEST( FD_LOAD( ulong, buf+BODY_OFF )==shred.shred_idx );

  fd_rotor_highest_shred_t highest_shred = { .slot = SLOT, .shred_idx = 0x3132333435363738UL };
  FD_TEST( fd_rotor_req_highest_window_index_ser( &highest_shred, signature, &sender, &recipient, TIMESTAMP, NONCE, buf )==160UL );
  check_header( buf, 160UL, 9U );
  FD_TEST( FD_LOAD( ulong, buf+BODY_OFF )==highest_shred.shred_idx );

  fd_rotor_orphan_t orphan = { .slot = SLOT };
  FD_TEST( fd_rotor_req_orphan_ser( &orphan, signature, &sender, &recipient, TIMESTAMP, NONCE, buf )==152UL );
  check_header( buf, 152UL, 10U );

  fd_rotor_parent_fec_set_count_t parent_fec_set_count = { .slot = SLOT }; fill( &parent_fec_set_count.block_id, sizeof(fd_hash_t), 151 );
  FD_TEST( fd_rotor_req_parent_and_fec_set_count_ser( &parent_fec_set_count, signature, &sender, &recipient, TIMESTAMP, NONCE, buf )==184UL );
  check_header( buf, 184UL, 12U );
  FD_TEST( !memcmp( buf+BODY_OFF, parent_fec_set_count.block_id.uc, 32UL ) );

  fd_rotor_fec_set_root_t fec_set_root = { .slot = SLOT, .fec_set_idx = 0x41424344U }; fill( &fec_set_root.block_id, sizeof(fd_hash_t), 161 );
  FD_TEST( fd_rotor_req_fec_set_root_ser( &fec_set_root, signature, &sender, &recipient, TIMESTAMP, NONCE, buf )==188UL );
  check_header( buf, 188UL, 13U );
  FD_TEST( !memcmp( buf+BODY_OFF, fec_set_root.block_id.uc, 32UL ) );
  FD_TEST( FD_LOAD( uint, buf+BODY_OFF+32UL )==fec_set_root.fec_set_idx );

  fd_rotor_shred_for_block_id_t shred_for_block_id = { .slot = SLOT, .shred_idx = 0x51525354U }; fill( &shred_for_block_id.block_id, sizeof(fd_hash_t), 171 );
  FD_TEST( fd_rotor_req_window_index_for_block_id_ser( &shred_for_block_id, signature, &sender, &recipient, TIMESTAMP, NONCE, buf )==188UL );
  check_header( buf, 188UL, 14U );
  FD_TEST( FD_LOAD( uint, buf+BODY_OFF )==shred_for_block_id.shred_idx );
  FD_TEST( !memcmp( buf+BODY_OFF+4UL, shred_for_block_id.block_id.uc, 32UL ) );
}

/* agave core/src/repair/serve_repair.rs RepairResponse and
   BlockIdRepairResponse, encoded with wincode's default config (Vec<u8>
   is a u64 length then the bytes), followed by the u32 nonce
   repair_handler.rs appends to every response but a ping */

static void
test_ping( void ) {
  uchar buf[ FD_ROTOR_PING_DE_SZ+8UL ];
  fill( buf, sizeof(buf), 3 );

  for( uint tag=0U; tag<3U; tag++ ) {
    FD_STORE( uint, buf, tag );
    fd_pubkey_t      from;
    fd_hash_t        token;
    fd_ed25519_sig_t sig;
    ulong sz = tag==FD_ROTOR_SERDE_TAG_PING ? fd_rotor_ping_de( buf, sizeof(buf), &from, &token, sig ) : fd_rotor_block_id_ping_de( buf, sizeof(buf), &from, &token, sig );
    if( tag==1U ) { FD_TEST( !sz ); continue; }
    FD_TEST( sz==132UL );
    FD_TEST( !memcmp( from.uc,  buf+4UL,  32UL ) );
    FD_TEST( !memcmp( token.uc, buf+36UL, 32UL ) );
    FD_TEST( !memcmp( sig,      buf+68UL, 64UL ) );
  }

  FD_STORE( uint, buf, FD_ROTOR_SERDE_TAG_BLOCK_ID_PING );
  fd_pubkey_t from; fd_hash_t token; fd_ed25519_sig_t sig;
  FD_TEST( !fd_rotor_ping_de         ( buf, sizeof(buf),             &from, &token, sig ) );
  FD_TEST( !fd_rotor_block_id_ping_de( buf, FD_ROTOR_PING_DE_SZ-1UL, &from, &token, sig ) );
}

static void
test_parent_fec_set_count_res( void ) {
  uchar buf[ 2048 ];
  ulong proof_sz = 11UL*FD_SHRED_MERKLE_NODE_SZ;
  ulong off = 0UL;
  FD_STORE( uint,  buf+off, 0U          ); off += 4UL;
  FD_STORE( uint,  buf+off, 1024U       ); off += 4UL;
  FD_STORE( ulong, buf+off, SLOT        ); off += 8UL;
  fill( buf+off, 32UL, 51 );               off += 32UL;
  FD_STORE( ulong, buf+off, proof_sz    ); off += 8UL;
  fill( buf+off, proof_sz, 91 );           off += proof_sz;
  FD_STORE( uint,  buf+off, NONCE       ); off += 4UL;

  uint fec_set_cnt; ulong parent_slot; fd_hash_t parent_block_id; uchar proof[ FD_ROTOR_PROOF_MAX ]; ulong res_proof_sz; uint nonce;
  FD_TEST( fd_rotor_res_parent_fec_set_count_de( buf, off+16UL, &fec_set_cnt, &parent_slot, &parent_block_id, proof, &res_proof_sz, &nonce )==off );
  FD_TEST( fec_set_cnt==1024U && parent_slot==SLOT && res_proof_sz==proof_sz && nonce==NONCE );
  FD_TEST( !memcmp( parent_block_id.uc, buf+16UL, 32UL     ) );
  FD_TEST( !memcmp( proof,              buf+56UL, proof_sz ) );

  FD_TEST( !fd_rotor_res_parent_fec_set_count_de( buf, off-1UL, &fec_set_cnt, &parent_slot, &parent_block_id, proof, &res_proof_sz, &nonce ) ); /* no room for the nonce */
  FD_STORE( uint, buf, 1U );
  FD_TEST( !fd_rotor_res_parent_fec_set_count_de( buf, off, &fec_set_cnt, &parent_slot, &parent_block_id, proof, &res_proof_sz, &nonce ) );
  FD_STORE( uint, buf, 0U );
  FD_STORE( ulong, buf+48UL, FD_ROTOR_PROOF_MAX+1UL );
  FD_TEST( !fd_rotor_res_parent_fec_set_count_de( buf, sizeof(buf), &fec_set_cnt, &parent_slot, &parent_block_id, proof, &res_proof_sz, &nonce ) );
  FD_STORE( ulong, buf+48UL, ULONG_MAX );
  FD_TEST( !fd_rotor_res_parent_fec_set_count_de( buf, sizeof(buf), &fec_set_cnt, &parent_slot, &parent_block_id, proof, &res_proof_sz, &nonce ) );
}

static void
test_fec_set_root_res( void ) {
  uchar buf[ 2048 ];
  ulong proof_sz = 10UL*FD_SHRED_MERKLE_NODE_SZ;
  ulong off = 0UL;
  FD_STORE( uint,  buf+off, 1U       ); off += 4UL;
  fill( buf+off, 20UL, 61 );            off += 20UL;
  FD_STORE( ulong, buf+off, proof_sz ); off += 8UL;
  fill( buf+off, proof_sz, 81 );        off += proof_sz;
  FD_STORE( uint,  buf+off, NONCE    ); off += 4UL;

  uchar fec_set_root[ FD_SHRED_MERKLE_NODE_SZ ]; uchar proof[ FD_ROTOR_PROOF_MAX ]; ulong res_proof_sz; uint nonce;
  FD_TEST( fd_rotor_res_fec_set_root_de( buf, off, fec_set_root, proof, &res_proof_sz, &nonce )==off );
  FD_TEST( res_proof_sz==proof_sz && nonce==NONCE );
  FD_TEST( !memcmp( fec_set_root, buf+4UL,  20UL     ) );
  FD_TEST( !memcmp( proof,        buf+32UL, proof_sz ) );

  FD_TEST( !fd_rotor_res_fec_set_root_de( buf, off-1UL, fec_set_root, proof, &res_proof_sz, &nonce ) );
  FD_STORE( uint, buf, 0U );
  FD_TEST( !fd_rotor_res_fec_set_root_de( buf, off, fec_set_root, proof, &res_proof_sz, &nonce ) );
  FD_STORE( uint, buf, 1U );
  FD_STORE( ulong, buf+24UL, FD_ROTOR_PROOF_MAX+1UL );
  FD_TEST( !fd_rotor_res_fec_set_root_de( buf, sizeof(buf), fec_set_root, proof, &res_proof_sz, &nonce ) );
}

#define TREE_LAYERS (16UL)

static uchar __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN))) tree_mem[ FD_BMTREE_COMMIT_FOOTPRINT( TREE_LAYERS ) ];

/* commit builds a block id the way a leader does: the merkle tree over
   cnt FEC set roots (FEC set k's is fill seed k, with k in its first 4
   bytes so every root differs) and the parent info leaf.  Returns the
   tree, to take proofs from. */

static fd_bmtree_commit_t *
commit( uint              cnt,
        ulong             parent_slot,
        fd_hash_t const * parent_block_id,
        fd_hash_t *       block_id ) {
  fd_bmtree_commit_t * tree = fd_bmtree_commit_init( tree_mem, FD_SHRED_MERKLE_NODE_SZ, FD_BMTREE_LONG_PREFIX_SZ, TREE_LAYERS );
  fd_bmtree_node_t     leaf[1];
  for( uint k=0U; k<cnt; k++ ) {
    fill( leaf->hash, sizeof(fd_hash_t), (uchar)k );
    FD_STORE( uint, leaf->hash, k );
    fd_bmtree_commit_append( tree, leaf, 1UL );
  }
  fd_sha256_t sha[1];
  fd_sha256_init  ( sha );
  fd_sha256_append( sha, &parent_slot,        sizeof(ulong)     );
  fd_sha256_append( sha, parent_block_id->uc, sizeof(fd_hash_t) );
  fd_sha256_append( sha, &cnt,                sizeof(uint)      );
  fd_sha256_fini  ( sha, leaf->hash );
  fd_bmtree_commit_append( tree, leaf, 1UL );
  memcpy( block_id->uc, fd_bmtree_commit_fini( tree ), sizeof(fd_hash_t) );
  return tree;
}

static void
test_parent_fec_set_count_verify( void ) {
  uint const cnts[] = { 1U, 2U, 3U, 33U, (uint)FD_FEC_BLK_MAX };
  for( ulong i=0UL; i<sizeof(cnts)/sizeof(cnts[0]); i++ ) {
    uint      cnt = cnts[ i ];
    fd_hash_t parent_block_id; fill( &parent_block_id, sizeof(fd_hash_t), 51 );
    fd_hash_t block_id;
    uchar     proof[ FD_ROTOR_PROOF_MAX ];
    int       depth = fd_bmtree_get_proof( commit( cnt, SLOT, &parent_block_id, &block_id ), proof, cnt );
    FD_TEST( depth>=0 );
    ulong     proof_sz = (ulong)depth*FD_SHRED_MERKLE_NODE_SZ;

    FD_TEST( !fd_rotor_res_parent_fec_set_count_verify( cnt,     SLOT,     &parent_block_id, proof, proof_sz,                         &block_id ) );
    FD_TEST(  fd_rotor_res_parent_fec_set_count_verify( cnt+1U,  SLOT,     &parent_block_id, proof, proof_sz,                         &block_id ) );
    FD_TEST(  fd_rotor_res_parent_fec_set_count_verify( cnt,     SLOT+1UL, &parent_block_id, proof, proof_sz,                         &block_id ) );
    FD_TEST(  fd_rotor_res_parent_fec_set_count_verify( cnt,     SLOT,     &parent_block_id, proof, proof_sz-FD_SHRED_MERKLE_NODE_SZ, &block_id ) ); /* too shallow */
    FD_TEST(  fd_rotor_res_parent_fec_set_count_verify( cnt,     SLOT,     &parent_block_id, proof, proof_sz+FD_SHRED_MERKLE_NODE_SZ, &block_id ) ); /* too deep */
    FD_TEST(  fd_rotor_res_parent_fec_set_count_verify( cnt,     SLOT,     &parent_block_id, proof, proof_sz-1UL,                     &block_id ) );
    proof[ proof_sz-1UL ] ^= 1;
    FD_TEST(  fd_rotor_res_parent_fec_set_count_verify( cnt,     SLOT,     &parent_block_id, proof, proof_sz,                         &block_id ) );
    proof[ proof_sz-1UL ] ^= 1;
    parent_block_id.uc[ 0 ] ^= 1;
    FD_TEST(  fd_rotor_res_parent_fec_set_count_verify( cnt,     SLOT,     &parent_block_id, proof, proof_sz,                         &block_id ) );
  }

  /* a block has 1 to FD_FEC_BLK_MAX FEC sets, even with a valid proof */

  uint const bad[] = { 0U, (uint)FD_FEC_BLK_MAX+1U };
  for( ulong i=0UL; i<sizeof(bad)/sizeof(bad[0]); i++ ) {
    fd_hash_t parent_block_id; fill( &parent_block_id, sizeof(fd_hash_t), 51 );
    fd_hash_t block_id;
    uchar     proof[ FD_ROTOR_PROOF_MAX ];
    int       depth = fd_bmtree_get_proof( commit( bad[ i ], SLOT, &parent_block_id, &block_id ), proof, bad[ i ] );
    FD_TEST( depth>=0 );
    FD_TEST( fd_rotor_res_parent_fec_set_count_verify( bad[ i ], SLOT, &parent_block_id, proof, (ulong)depth*FD_SHRED_MERKLE_NODE_SZ, &block_id ) );
  }
}

static void
test_fec_set_root_verify( void ) {
  uint const cnts[] = { 1U, 2U, 3U, 33U, (uint)FD_FEC_BLK_MAX };
  for( ulong i=0UL; i<sizeof(cnts)/sizeof(cnts[0]); i++ ) {
    uint      cnt = cnts[ i ];
    fd_hash_t parent_block_id; fill( &parent_block_id, sizeof(fd_hash_t), 51 );
    fd_hash_t block_id;
    fd_bmtree_commit_t * tree = commit( cnt, SLOT, &parent_block_id, &block_id );

    uint const ks[] = { 0U, cnt/2U, cnt-1U };
    for( ulong j=0UL; j<sizeof(ks)/sizeof(ks[0]); j++ ) {
      uint  k = ks[ j ];
      uchar root[ FD_SHRED_MERKLE_NODE_SZ ]; fill( root, FD_SHRED_MERKLE_NODE_SZ, (uchar)k ); FD_STORE( uint, root, k );
      uchar proof[ FD_ROTOR_PROOF_MAX ];
      int   depth = fd_bmtree_get_proof( tree, proof, k );
      FD_TEST( depth>=0 );
      ulong proof_sz = (ulong)depth*FD_SHRED_MERKLE_NODE_SZ;
      uint  idx      = k*FD_FEC_SHRED_CNT;

      FD_TEST( !fd_rotor_res_fec_set_root_verify( root, proof, proof_sz,                         &block_id, idx,                  cnt                     ) );
      FD_TEST(  fd_rotor_res_fec_set_root_verify( root, proof, proof_sz,                         &block_id, idx+1U,               cnt                     ) ); /* not a FEC set's first shred */
      FD_TEST(  fd_rotor_res_fec_set_root_verify( root, proof, proof_sz,                         &block_id, cnt*FD_FEC_SHRED_CNT, cnt                     ) ); /* past the last FEC set */
      FD_TEST(  fd_rotor_res_fec_set_root_verify( root, proof, proof_sz,                         &block_id, idx,                  0U                      ) );
      FD_TEST(  fd_rotor_res_fec_set_root_verify( root, proof, proof_sz,                         &block_id, idx,                  (uint)FD_FEC_BLK_MAX+1U ) );
      FD_TEST(  fd_rotor_res_fec_set_root_verify( root, proof, proof_sz-FD_SHRED_MERKLE_NODE_SZ, &block_id, idx,                  cnt                     ) );
      FD_TEST(  fd_rotor_res_fec_set_root_verify( root, proof, proof_sz+FD_SHRED_MERKLE_NODE_SZ, &block_id, idx,                  cnt                     ) );
      if( FD_LIKELY( cnt>1U ) ) FD_TEST( fd_rotor_res_fec_set_root_verify( root, proof, proof_sz, &block_id, fd_uint_if( !k, FD_FEC_SHRED_CNT, 0U ), cnt ) ); /* another FEC set's index */
      root[ 0 ] ^= 1;
      FD_TEST(  fd_rotor_res_fec_set_root_verify( root, proof, proof_sz,                         &block_id, idx,                  cnt                     ) );
    }
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fill( signature,  FD_ED25519_SIG_SZ,   1   );
  fill( &sender,    sizeof(fd_pubkey_t), 71  );
  fill( &recipient, sizeof(fd_pubkey_t), 111 );
  test_pong();
  test_requests();
  test_ping();
  test_parent_fec_set_count_res();
  test_fec_set_root_res();
  test_parent_fec_set_count_verify();
  test_fec_set_root_verify();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
