#include "ag_cert_serde.h"
#include "test_ag_cert_builder.h"

#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/bls/fd_bls12_381.h" /* fd_bls12_381_g2_add_syscall */
#include "../../third_party/blst/bindings/blst.h"

#include <stdlib.h>

#define TEST_SHRED_VERSION ((ushort)514)

/* sha256 over the whole serialized message of each golden vector below.
   Captured from the wire the Alpenglow cert serde produced before it was
   rewritten to drop its packed overlays; any change to these is a change
   to an Agave interop format. */

#define GOLDEN_FINAL                 "2acf222cc3a944724b3645adb3b1f1dd022244984d0493ddc2aae31f8049e9c5"
#define GOLDEN_FAST_FINAL            "6a0b759fa2ac2dcf38d0ba9faef01b1d00b2d0888aca891c9734e016ed73926a"
#define GOLDEN_NOTAR                 "79003321e9bf47b64b9c351404044614907c43b0e42ec1521a6311432b3be2b7"
#define GOLDEN_NOTAR_FALLBACK_BASE3  "01e524f741722135e3b5fd4450c63b81c442f52ac68cbc41a5825184adc3d7d0"
#define GOLDEN_NOTAR_FALLBACK_BASE2  "6dbfd83b14067e4ec0c6cb257ee8aae9f3b7ffee57160cb44ccf64a3e6c3a627"
#define GOLDEN_SKIP_BASE3            "92679933efb335bb98f2291204ae095f393dccb5a0be3298c9b476caffe35f17"
#define GOLDEN_SKIP_BASE2            "45a2ba2c905e70ead67bca511e10277188b1cb8855877beb79488ff637103d3b"

#define MAXV 128UL

static fd_bls_sec_t     g_sk  [ MAXV ];
static ag_validator_info_t g_info[ MAXV ];

static void
create_signers( ulong n ) {
  FD_TEST( n<=MAXV );
  for( ulong i=0UL; i<n; i++ ) {
    fd_memset( &g_sk[i], 0, FD_BLS_SEC_SZ );
    g_sk[i].b[0] = (uchar)( i+1UL );
    memset( &g_info[i], 0, sizeof(ag_validator_info_t) );
    g_info[i].id    = i;
    g_info[i].stake = 1UL;
    fd_bls_sec_to_pub( &g_sk[i], &g_info[i].bls_key );
  }
}

static ag_epoch_info_t *
make_epoch( ulong   n,
            void ** out_mem ) {
  ag_epoch_info_t * epoch_info = aligned_alloc( alignof(ag_epoch_info_t), sizeof(ag_epoch_info_t) );
  FD_TEST( epoch_info );
  *out_mem = epoch_info;
  ag_epoch_info( epoch_info, g_info, n );
  return epoch_info;
}

static void
mk_notar( ag_vote_notar_t *     o,
          ulong                 slot,
          ag_block_hash_t const h,
          ulong                 lo,
          ulong                 n ) {
  for( ulong i=0UL; i<n; i++ ) o[i] = ag_vote_construct_notar( sec_sign_fn, &g_sk[lo+i], slot, h, (ushort)(lo+i), TEST_SHRED_VERSION ).notar;
}
static void
mk_final( ag_vote_final_t * o,
          ulong             slot,
          ulong             lo,
          ulong             n ) {
  for( ulong i=0UL; i<n; i++ ) o[i] = ag_vote_construct_final( sec_sign_fn, &g_sk[lo+i], slot, (ushort)(lo+i), TEST_SHRED_VERSION ).final;
}
static void
mk_skip( ag_vote_skip_t * o,
         ulong            slot,
         ulong            lo,
         ulong            n ) {
  for( ulong i=0UL; i<n; i++ ) o[i] = ag_vote_construct_skip( sec_sign_fn, &g_sk[lo+i], slot, (ushort)(lo+i), TEST_SHRED_VERSION ).skip;
}
static void
mk_nf( ag_vote_notar_fallback_t * o,
       ulong                      slot,
       ag_block_hash_t const      h,
       ulong                      lo,
       ulong                      n ) {
  for( ulong i=0UL; i<n; i++ ) o[i] = ag_vote_construct_notar_fallback( sec_sign_fn, &g_sk[lo+i], slot, h, (ushort)(lo+i), TEST_SHRED_VERSION ).notar_fallback;
}
static void
mk_sf( ag_vote_skip_fallback_t * o,
       ulong                     slot,
       ulong                     lo,
       ulong                     n ) {
  for( ulong i=0UL; i<n; i++ ) o[i] = ag_vote_construct_skip_fallback( sec_sign_fn, &g_sk[lo+i], slot, (ushort)(lo+i), TEST_SHRED_VERSION ).skip_fallback;
}

static ulong
cert_stake( ag_cert_t const * c ) {
  switch( c->kind ) {
  case AG_CERT_KIND_FINAL:          return c->final.stake;
  case AG_CERT_KIND_FAST_FINAL:     return c->fast_final.stake;
  case AG_CERT_KIND_NOTAR:          return c->notar.stake;
  case AG_CERT_KIND_NOTAR_FALLBACK: return c->notar_fallback.stake;
  default:                          return c->skip.stake;
  }
}

static int
cert_is_signer( ag_cert_t const * c,
                ulong             v ) {
  switch( c->kind ) {
  case AG_CERT_KIND_FINAL:      return fd_bls_set_test( c->final.agg.set,      v );
  case AG_CERT_KIND_FAST_FINAL: return fd_bls_set_test( c->fast_final.agg.set, v );
  case AG_CERT_KIND_NOTAR:      return fd_bls_set_test( c->notar.agg.set,      v );
  case AG_CERT_KIND_NOTAR_FALLBACK: {
    ag_cert_notar_fallback_t const * n = &c->notar_fallback;
    return fd_bls_set_test( n->agg_notar.set, v ) || fd_bls_set_test( n->agg_notar_fallback.set, v );
  }
  default: {
    ag_cert_skip_t const * s = &c->skip;
    return fd_bls_set_test( s->agg_skip.set, v ) || fd_bls_set_test( s->agg_skip_fallback.set, v );
  }
  }
}

static void
check_full_cert( ag_cert_t const * c,
                 ulong             n ) {
  FD_TEST( cert_stake( c )==n );
  for( ulong i=0UL; i<n; i++ ) FD_TEST( cert_is_signer( c, g_info[i].id ) );
}

/* src/consensus/cert.rs::create */

static void
test_create( void ) {
  ulong n = 100UL;
  create_signers( n );
  void * em; ag_epoch_info_t * e = make_epoch( n, &em );
  ag_block_hash_t h; memset( h, 0x42, sizeof(ag_block_hash_t) );

  ag_vote_notar_t nv[ 100 ];
  ag_vote_notar_fallback_t fv[ 100 ];
  ag_vote_skip_t sv[ 100 ];
  ag_vote_final_t ev[ 100 ];
  ag_cert_t c;

  mk_notar( nv, 0UL, h, 0UL, n );
    c = cert_build_notar( nv, n, e );
  check_full_cert( &c, n );
  FD_TEST( ag_cert_block_hash( &c ) && !memcmp( ag_cert_block_hash(&c), h, sizeof(ag_block_hash_t) ) );

  mk_nf( fv, 0UL, h, 0UL, n );
    c = cert_build_notar_fallback( NULL, 0UL, fv, n, e );
  check_full_cert( &c, n );

  mk_skip( sv, 0UL, 0UL, n );
    c = cert_build_skip( sv, n, NULL, 0UL, e );
  check_full_cert( &c, n );
  FD_TEST( ag_cert_block_hash( &c )==NULL );

  mk_notar( nv, 0UL, h, 0UL, n );
    c = cert_build_fast_final( nv, n, e );
  check_full_cert( &c, n );

  mk_final( ev, 0UL, 0UL, n );
    c = cert_build_final( ev, n, e );
  check_full_cert( &c, n );
  FD_TEST( ag_cert_block_hash( &c )==NULL );

  free( em );
}

/* src/consensus/cert.rs::mixed_notar_fallback, ::mixed_skip */

static void
test_mixed( void ) {
  create_signers( 2UL );
  void * em; ag_epoch_info_t * e = make_epoch( 2UL, &em );
  ag_block_hash_t h; memset( h, 0x42, sizeof(ag_block_hash_t) );

  ag_vote_notar_t nv[1]; mk_notar( nv, 0UL, h, 0UL, 1UL );
  ag_vote_notar_fallback_t fv[1]; mk_nf   ( fv, 0UL, h, 1UL, 1UL );
  ag_cert_t c = cert_build_notar_fallback( nv, 1UL, fv, 1UL, e );
  check_full_cert( &c, 2UL );

  ag_vote_skip_t sv[1]; mk_skip( sv, 0UL, 0UL, 1UL );
  ag_vote_skip_fallback_t fv2[1]; mk_sf ( fv2, 0UL, 1UL, 1UL );
    c = cert_build_skip( sv, 1UL, fv2, 1UL, e );
  check_full_cert( &c, 2UL );

  free( em );
}

/* CERT_HDR_SZ is everything a serialized cert carries ahead of its
   bitmap: the version and kind tags, the slot, the block id for the kinds
   that carry one, the aggregate signature and the bitmap byte count.
   CERT_BITMAP_HDR_SZ is the bitmap's own version byte and bit count. */

#define CERT_HDR_SZ( has_block_id ) ( 1UL + 1UL + 8UL + ( (has_block_id) ? sizeof(ag_block_hash_t) : 0UL ) + FD_BLS_SIG_SZ + 8UL )
#define CERT_BITMAP_HDR_SZ           ( 1UL + 2UL )

/* Golden wire vectors.

   ag_cert_ser and ag_cert_de speak an Agave interop format, so the bytes
   themselves are the contract: a ser -> de round trip through our own
   decoder agrees with itself even when both halves have drifted off the
   format together, and would not notice.  check_cert_wire therefore
   spells out what the wire must contain field by field at explicit
   offsets, and pins the whole message with a sha256 digest captured from
   the implementation in place when these vectors were written.  Every
   cert kind appears below, and both bitmap encodings -- base2 for a
   single partition, base3 for two -- for the two kinds that have a
   fallback partition. */

static void
wire_sha( char          out[ 65 ],
          uchar const * buf,
          ulong         sz ) {
  static char const digit[] = "0123456789abcdef";
  uchar             h[ 32 ];
  fd_sha256_hash( buf, sz, h );
  for( ulong i=0UL; i<32UL; i++ ) {
    out[ 2UL*i      ] = digit[   h[i]>>4    ];
    out[ 2UL*i+1UL  ] = digit[ ( h[i]&0xfU ) ];
  }
  out[ 64 ] = '\0';
}

static void
check_cert_wire( char const *         name,
                 ag_cert_t const *    c,
                 uchar                kind,       /* WireConsensusMessageKind tag                     */
                 ulong                slot,
                 uchar const *        block_id,   /* NULL for the kinds whose wire form carries none  */
                 fd_bls_agg_t const * agg,        /* base aggregate                                   */
                 fd_bls_agg_t const * agg2,       /* second partition, NULL for the single-partition kinds;
                                                     the wire carries the two signatures summed          */
                 uchar                bitmap_ver, /* 0 base2, 1 base3                                 */
                 ushort               bit_cnt,
                 uchar const *        bitmap,
                 ulong                bitmap_sz,
                 ulong                exp_sz,
                 char const *         exp_sha ) {
  uchar buf[ AG_CERT_SER_MAX ];
  ulong sz   = ag_cert_ser( c, TEST_SHRED_VERSION, buf );
  ulong hdr = CERT_HDR_SZ( !!block_id );

  FD_TEST( sz==hdr+CERT_BITMAP_HDR_SZ+bitmap_sz+2UL );
  FD_TEST( sz==exp_sz );

  ulong off = 0UL;
  FD_TEST( buf[ off ]==(uchar)1 ); off += 1UL;
  FD_TEST( buf[ off ]==kind     ); off += 1UL;
  FD_TEST( FD_LOAD( ulong, buf+off )==slot ); off += 8UL;
  if( block_id ) { FD_TEST( !memcmp( buf+off, block_id, sizeof(ag_block_hash_t) ) ); off += sizeof(ag_block_hash_t); }
  fd_bls_sig_t exp_sig[1]; *exp_sig = agg->sig;
  if( agg2 ) blst_p2_add_or_double( exp_sig, exp_sig, &agg2->sig );
  uchar exp_bytes[ FD_BLS_SIG_SZ ];
  { blst_p2_affine a[1]; blst_p2_to_affine( a, exp_sig ); blst_p2_affine_serialize( exp_bytes, a ); }
  FD_TEST( !memcmp( buf+off, exp_bytes, FD_BLS_SIG_SZ ) ); off += FD_BLS_SIG_SZ;
  FD_TEST( FD_LOAD( ulong, buf+off )==CERT_BITMAP_HDR_SZ+bitmap_sz ); off += 8UL;
  FD_TEST( off==hdr );
  FD_TEST( buf[ off ]==bitmap_ver ); off += 1UL;
  FD_TEST( FD_LOAD( ushort, buf+off )==bit_cnt ); off += 2UL;
  FD_TEST( !memcmp( buf+off, bitmap, bitmap_sz ) ); off += bitmap_sz;
  FD_TEST( FD_LOAD( ushort, buf+off )==TEST_SHRED_VERSION ); off += 2UL;
  FD_TEST( off==sz );

  char sha[ 65 ]; wire_sha( sha, buf, sz );
  if( FD_UNLIKELY( memcmp( sha, exp_sha, 64UL ) ) ) FD_LOG_ERR(( "%s wire digest %s, expected %s", name, sha, exp_sha ));

  /* the same bytes decode back, and the decoded cert reserializes to them */

  ag_cert_t rt;
  FD_TEST( ag_cert_de( &rt, TEST_SHRED_VERSION, buf, sz )==AG_CERT_DE_SUCCESS );
  FD_TEST( rt.kind==c->kind );
  FD_TEST( ag_cert_slot( &rt )==slot );
  if( block_id ) FD_TEST( ag_cert_block_hash( &rt ) && !memcmp( ag_cert_block_hash( &rt ), block_id, sizeof(ag_block_hash_t) ) );
  else           FD_TEST( ag_cert_block_hash( &rt )==NULL );

  uchar again[ AG_CERT_SER_MAX ];
  FD_TEST( ag_cert_ser( &rt, TEST_SHRED_VERSION, again )==sz );
  FD_TEST( !memcmp( again, buf, sz ) );

  FD_TEST( ag_cert_de( &rt, (ushort)(TEST_SHRED_VERSION+1), buf, sz     )==AG_CERT_DE_ERR_SHRED_VERSION );
  FD_TEST( ag_cert_de( &rt, TEST_SHRED_VERSION,             buf, sz-1UL )==AG_CERT_DE_ERR_SZ ); /* too few  */
  FD_TEST( ag_cert_de( &rt, TEST_SHRED_VERSION,             buf, sz+1UL )==AG_CERT_DE_ERR_SZ ); /* trailing */
}

static void
test_wire_golden( void ) {
  ulong n = 11UL;
  create_signers( n );
  void * em; ag_epoch_info_t * e = make_epoch( n, &em );
  ag_block_hash_t h; memset( h, 0x42, sizeof(ag_block_hash_t) );

  ulong const slot = 7UL;

  ag_vote_notar_t          nv [ 11 ];
  ag_vote_final_t          ev [ 11 ];
  ag_vote_skip_t           sv [ 11 ];
  ag_vote_notar_fallback_t fv [ 11 ];
  ag_vote_skip_fallback_t  sfv[ 11 ];
  ag_cert_t                c;

  /* base2 packs one rank per bit, least significant bit first.  base3
     packs five ranks per byte, digit 1 for a base partition signer and
     digit 2 for a fallback signer, least significant digit first: ranks
     0..4 in the base partition are 1+3+9+27+81 == 121, ranks 5..8 in the
     fallback partition are 2+6+18+54 == 80. */

  uchar const bm5   [1] = { 0x1f };       /* base2, ranks 0..4                       */
  uchar const bm7   [1] = { 0x7f };       /* base2, ranks 0..6                       */
  uchar const bm9   [2] = { 0xff, 0x01 }; /* base2, ranks 0..8                       */
  uchar const bm_b3 [2] = { 121, 80 };    /* base3, base 0..4 and fallback 5..8      */

  mk_final( ev, slot, 0UL, 5UL );
  c = cert_build_final( ev, 5UL, e );
  check_cert_wire( "final", &c, 7, slot, NULL, &c.final.agg, NULL,
                   0, 5, bm5, sizeof(bm5), 216UL, GOLDEN_FINAL );

  mk_notar( nv, slot, h, 0UL, 9UL );
  c = cert_build_fast_final( nv, 9UL, e );
  check_cert_wire( "fast final", &c, 8, slot, h, &c.fast_final.agg, NULL,
                   0, 9, bm9, sizeof(bm9), 249UL, GOLDEN_FAST_FINAL );

  mk_notar( nv, slot, h, 0UL, 7UL );
  c = cert_build_notar( nv, 7UL, e );
  check_cert_wire( "notar", &c, 9, slot, h, &c.notar.agg, NULL,
                   0, 7, bm7, sizeof(bm7), 248UL, GOLDEN_NOTAR );

  mk_notar( nv, slot, h, 0UL, 5UL );
  mk_nf   ( fv, slot, h, 5UL, 4UL );
  c = cert_build_notar_fallback( nv, 5UL, fv, 4UL, e );
  check_cert_wire( "notar fallback base3", &c, 10, slot, h, &c.notar_fallback.agg_notar, &c.notar_fallback.agg_notar_fallback,
                   1, 9, bm_b3, sizeof(bm_b3), 249UL, GOLDEN_NOTAR_FALLBACK_BASE3 );

  mk_notar( nv, slot, h, 0UL, 7UL );
  c = cert_build_notar_fallback( nv, 7UL, NULL, 0UL, e );
  check_cert_wire( "notar fallback base2", &c, 10, slot, h, &c.notar_fallback.agg_notar, &c.notar_fallback.agg_notar_fallback,
                   0, 7, bm7, sizeof(bm7), 248UL, GOLDEN_NOTAR_FALLBACK_BASE2 );

  mk_skip( sv,  slot, 0UL, 5UL );
  mk_sf  ( sfv, slot, 5UL, 4UL );
  c = cert_build_skip( sv, 5UL, sfv, 4UL, e );
  check_cert_wire( "skip base3", &c, 11, slot, NULL, &c.skip.agg_skip, &c.skip.agg_skip_fallback,
                   1, 9, bm_b3, sizeof(bm_b3), 217UL, GOLDEN_SKIP_BASE3 );

  mk_skip( sv, slot, 0UL, 7UL );
  c = cert_build_skip( sv, 7UL, NULL, 0UL, e );
  check_cert_wire( "skip base2", &c, 11, slot, NULL, &c.skip.agg_skip, &c.skip.agg_skip_fallback,
                   0, 7, bm7, sizeof(bm7), 216UL, GOLDEN_SKIP_BASE2 );

  free( em );
  FD_LOG_NOTICE(( "cert golden wire vectors pass" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_create();
  test_mixed();
  test_wire_golden();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
