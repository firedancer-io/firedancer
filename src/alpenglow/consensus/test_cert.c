#include "ag_cert.h"

#define TEST_SHRED_VERSION ((ushort)514)
#include <stdlib.h>

#define MAXV 128UL

static ag_aggsig_sk_t     g_sk  [ MAXV ];
static ag_validator_info_t g_info[ MAXV ];

static void
create_signers( ulong n ) {
  FD_TEST( n<=MAXV );
  for( ulong i=0UL; i<n; i++ ) {
    /* i*7+1 wraps to an all-zero (invalid) scalar at i=73 */
    fd_memset( g_sk[i].v, 0, AG_AGGSIG_SECKEY_SZ );
    g_sk[i].v[0] = (uchar)( i+1UL );
    memset( &g_info[i], 0, sizeof(ag_validator_info_t) );
    g_info[i].id    = i;
    g_info[i].stake = 1UL;
    ag_aggsig_sk_to_pk( &g_info[i].voting_pubkey, &g_sk[i] );
  }
}

static ag_epoch_info_t *
make_epoch( ulong   n,
            void ** out_mem ) {
  void * mem = aligned_alloc( ag_epoch_info_align(), ag_epoch_info_footprint( n ) );
  FD_TEST( mem );
  *out_mem = mem;
  return ag_epoch_info_join( ag_epoch_info_new( mem, g_info, n ) );
}

static void
mk_notar( ag_notar_vote_t * o,
          ulong             slot,
          fd_hash_t const * h,
          ulong             lo,
          ulong             n ) {
  for( ulong i=0UL; i<n; i++ ) ag_notar_vote_new( &o[i], slot, h, &g_sk[lo+i], (ushort)(lo+i) , TEST_SHRED_VERSION );
}
static void
mk_nf( ag_notar_fallback_vote_t * o,
       ulong                      slot,
       fd_hash_t const *          h,
       ulong                      lo,
       ulong                      n ) {
  for( ulong i=0UL; i<n; i++ ) ag_notar_fallback_vote_new( &o[i], slot, h, &g_sk[lo+i], (ushort)(lo+i) , TEST_SHRED_VERSION );
}
static void
mk_skip( ag_skip_vote_t * o,
         ulong            slot,
         ulong            lo,
         ulong            n ) {
  for( ulong i=0UL; i<n; i++ ) ag_skip_vote_new( &o[i], slot, &g_sk[lo+i], (ushort)(lo+i) , TEST_SHRED_VERSION );
}
static void
mk_sf( ag_skip_fallback_vote_t * o,
       ulong                     slot,
       ulong                     lo,
       ulong                     n ) {
  for( ulong i=0UL; i<n; i++ ) ag_skip_fallback_vote_new( &o[i], slot, &g_sk[lo+i], (ushort)(lo+i) , TEST_SHRED_VERSION );
}
static void
mk_final( ag_final_vote_t * o,
          ulong             slot,
          ulong             lo,
          ulong             n ) {
  for( ulong i=0UL; i<n; i++ ) ag_final_vote_new( &o[i], slot, &g_sk[lo+i], (ushort)(lo+i) , TEST_SHRED_VERSION );
}

static void
check_full_cert( ag_cert_t const * c,
                 ulong             n ) {
  void *            mem = NULL;
  ag_epoch_info_t * ei  = make_epoch( n, &mem );
  FD_TEST( ag_cert_check_sig( c, TEST_SHRED_VERSION, ei ) );
  free( mem );
  FD_TEST( ag_cert_stake( c )==n );
  for( ulong i=0UL; i<n; i++ ) FD_TEST( ag_cert_is_signer( c, g_info[i].id ) );
}

static void
test_create( void ) {
  ulong n = 100UL;
  create_signers( n );
  fd_hash_t h; memset( h.uc, 0x42, sizeof(fd_hash_t) );

  ag_notar_vote_t          nv[ 100 ];
  ag_notar_fallback_vote_t fv[ 100 ];
  ag_skip_vote_t           sv[ 100 ];
  ag_final_vote_t          ev[ 100 ];
  ag_cert_t c;

  mk_notar( nv, 0UL, &h, 0UL, n );
  c.kind = AG_CERT_TYPE_NOTAR;
  FD_TEST( ag_notar_cert_try_new( &c.inner.notar, nv, n, g_info, n )==AG_CERT_SUCCESS );
  check_full_cert( &c, n );
  FD_TEST( ag_cert_block_hash( &c ) && !memcmp( ag_cert_block_hash(&c)->uc, h.uc, 32 ) );

  mk_nf( fv, 0UL, &h, 0UL, n );
  c.kind = AG_CERT_TYPE_NOTAR_FALLBACK;
  FD_TEST( ag_notar_fallback_cert_try_new( &c.inner.notar_fallback, NULL, 0UL, fv, n, g_info, n )==AG_CERT_SUCCESS );
  check_full_cert( &c, n );

  mk_skip( sv, 0UL, 0UL, n );
  c.kind = AG_CERT_TYPE_SKIP;
  FD_TEST( ag_skip_cert_try_new( &c.inner.skip, sv, n, NULL, 0UL, g_info, n )==AG_CERT_SUCCESS );
  check_full_cert( &c, n );
  FD_TEST( ag_cert_block_hash( &c )==NULL );

  mk_notar( nv, 0UL, &h, 0UL, n );
  c.kind = AG_CERT_TYPE_FAST_FINAL;
  FD_TEST( ag_fast_final_cert_try_new( &c.inner.fast_final, nv, n, g_info, n )==AG_CERT_SUCCESS );
  check_full_cert( &c, n );

  mk_final( ev, 0UL, 0UL, n );
  c.kind = AG_CERT_TYPE_FINAL;
  FD_TEST( ag_final_cert_try_new( &c.inner.final, ev, n, g_info, n )==AG_CERT_SUCCESS );
  check_full_cert( &c, n );
  FD_TEST( ag_cert_block_hash( &c )==NULL );
}

static void
test_mixed( void ) {
  create_signers( 2UL );
  fd_hash_t h; memset( h.uc, 0x42, sizeof(fd_hash_t) );

  ag_notar_vote_t          nv[1]; mk_notar( nv, 0UL, &h, 0UL, 1UL );
  ag_notar_fallback_vote_t fv[1]; mk_nf   ( fv, 0UL, &h, 1UL, 1UL );
  ag_cert_t c; c.kind = AG_CERT_TYPE_NOTAR_FALLBACK;
  FD_TEST( ag_notar_fallback_cert_try_new( &c.inner.notar_fallback, nv, 1UL, fv, 1UL, g_info, 2UL )==AG_CERT_SUCCESS );
  check_full_cert( &c, 2UL );

  ag_skip_vote_t          sv[1]; mk_skip( sv, 0UL, 0UL, 1UL );
  ag_skip_fallback_vote_t fv2[1]; mk_sf ( fv2, 0UL, 1UL, 1UL );
  c.kind = AG_CERT_TYPE_SKIP;
  FD_TEST( ag_skip_cert_try_new( &c.inner.skip, sv, 1UL, fv2, 1UL, g_info, 2UL )==AG_CERT_SUCCESS );
  check_full_cert( &c, 2UL );
}

static void
test_failures( void ) {
  create_signers( 2UL );
  fd_hash_t h1; memset( h1.uc, 0x11, sizeof(fd_hash_t) );
  fd_hash_t h2; memset( h2.uc, 0x22, sizeof(fd_hash_t) );

  ag_notar_vote_t nv[2];
  ag_notar_vote_new( &nv[0], 1UL, &h1, &g_sk[0], 0UL , TEST_SHRED_VERSION );
  ag_notar_vote_new( &nv[1], 2UL, &h1, &g_sk[1], 1UL , TEST_SHRED_VERSION );
  ag_notar_cert_t nc;
  FD_TEST( ag_notar_cert_try_new( &nc, nv, 2UL, g_info, 2UL )==AG_CERT_ERR_SLOT_MISMATCH );

  ag_notar_vote_new( &nv[0], 1UL, &h1, &g_sk[0], 0UL , TEST_SHRED_VERSION );
  ag_notar_vote_new( &nv[1], 1UL, &h2, &g_sk[1], 1UL , TEST_SHRED_VERSION );
  FD_TEST( ag_notar_cert_try_new( &nc, nv, 2UL, g_info, 2UL )==AG_CERT_ERR_BLOCK_HASH_MISMATCH );

  ag_notar_vote_t          nv1[1]; ag_notar_vote_new( &nv1[0], 2UL, &h1, &g_sk[0], 0UL , TEST_SHRED_VERSION );
  ag_notar_fallback_vote_t fv1[1]; ag_notar_fallback_vote_new( &fv1[0], 1UL, &h1, &g_sk[1], 1UL , TEST_SHRED_VERSION );
  ag_notar_fallback_cert_t nfc;
  FD_TEST( ag_notar_fallback_cert_try_new( &nfc, nv1, 1UL, fv1, 1UL, g_info, 2UL )==AG_CERT_ERR_SLOT_MISMATCH );

  ag_skip_vote_t sv[2];
  ag_skip_vote_new( &sv[0], 1UL, &g_sk[0], 0UL , TEST_SHRED_VERSION );
  ag_skip_vote_new( &sv[1], 2UL, &g_sk[1], 1UL , TEST_SHRED_VERSION );
  ag_skip_cert_t sc;
  FD_TEST( ag_skip_cert_try_new( &sc, sv, 2UL, NULL, 0UL, g_info, 2UL )==AG_CERT_ERR_SLOT_MISMATCH );

  ag_final_vote_t ev[2];
  ag_final_vote_new( &ev[0], 1UL, &g_sk[0], 0UL , TEST_SHRED_VERSION );
  ag_final_vote_new( &ev[1], 2UL, &g_sk[1], 1UL , TEST_SHRED_VERSION );
  ag_final_cert_t fc;
  FD_TEST( ag_final_cert_try_new( &fc, ev, 2UL, g_info, 2UL )==AG_CERT_ERR_SLOT_MISMATCH );
}

static void
test_thresholds( void ) {
  ulong n = 11UL;
  create_signers( n );
  void * em; ag_epoch_info_t * e = make_epoch( n, &em );
  fd_hash_t h; memset( h.uc, 0x42, sizeof(fd_hash_t) );

  ag_notar_vote_t          nv[ 11 ];
  ag_notar_fallback_vote_t fv[ 11 ];
  ag_skip_vote_t           sv[ 11 ];
  ag_final_vote_t          ev[ 11 ];
  ag_cert_t c;

  mk_notar( nv, 1UL, &h, 0UL, 7UL );
  c.kind = AG_CERT_TYPE_NOTAR; FD_TEST( ag_notar_cert_try_new( &c.inner.notar, nv, 7UL, g_info, n )==AG_CERT_SUCCESS );
  FD_TEST( ag_cert_check_threshold( &c, e ) );
  mk_notar( nv, 1UL, &h, 0UL, 6UL );
  FD_TEST( ag_notar_cert_try_new( &c.inner.notar, nv, 6UL, g_info, n )==AG_CERT_SUCCESS );
  FD_TEST( !ag_cert_check_threshold( &c, e ) );

  mk_notar( nv, 1UL, &h, 0UL, 4UL );
  mk_nf   ( fv, 1UL, &h, 4UL, 3UL );
  c.kind = AG_CERT_TYPE_NOTAR_FALLBACK;
  FD_TEST( ag_notar_fallback_cert_try_new( &c.inner.notar_fallback, nv, 4UL, fv, 3UL, g_info, n )==AG_CERT_SUCCESS );
  FD_TEST( ag_cert_check_threshold( &c, e ) );
  mk_notar( nv, 1UL, &h, 0UL, 3UL );
  mk_nf   ( fv, 1UL, &h, 3UL, 3UL );
  FD_TEST( ag_notar_fallback_cert_try_new( &c.inner.notar_fallback, nv, 3UL, fv, 3UL, g_info, n )==AG_CERT_SUCCESS );
  FD_TEST( !ag_cert_check_threshold( &c, e ) );

  mk_skip( sv, 1UL, 0UL, 7UL );
  c.kind = AG_CERT_TYPE_SKIP; FD_TEST( ag_skip_cert_try_new( &c.inner.skip, sv, 7UL, NULL, 0UL, g_info, n )==AG_CERT_SUCCESS );
  FD_TEST( ag_cert_check_threshold( &c, e ) );
  mk_skip( sv, 1UL, 0UL, 6UL );
  FD_TEST( ag_skip_cert_try_new( &c.inner.skip, sv, 6UL, NULL, 0UL, g_info, n )==AG_CERT_SUCCESS );
  FD_TEST( !ag_cert_check_threshold( &c, e ) );

  mk_final( ev, 1UL, 0UL, 7UL );
  c.kind = AG_CERT_TYPE_FINAL; FD_TEST( ag_final_cert_try_new( &c.inner.final, ev, 7UL, g_info, n )==AG_CERT_SUCCESS );
  FD_TEST( ag_cert_check_threshold( &c, e ) );
  mk_final( ev, 1UL, 0UL, 6UL );
  FD_TEST( ag_final_cert_try_new( &c.inner.final, ev, 6UL, g_info, n )==AG_CERT_SUCCESS );
  FD_TEST( !ag_cert_check_threshold( &c, e ) );

  mk_notar( nv, 1UL, &h, 0UL, 9UL );
  c.kind = AG_CERT_TYPE_FAST_FINAL; FD_TEST( ag_fast_final_cert_try_new( &c.inner.fast_final, nv, 9UL, g_info, n )==AG_CERT_SUCCESS );
  FD_TEST( ag_cert_check_threshold( &c, e ) );
  mk_notar( nv, 1UL, &h, 0UL, 8UL );
  FD_TEST( ag_fast_final_cert_try_new( &c.inner.fast_final, nv, 8UL, g_info, n )==AG_CERT_SUCCESS );
  FD_TEST( !ag_cert_check_threshold( &c, e ) );

  free( em );
}

/* put_aggregate writes one footer votes aggregate: a compressed point at
   infinity as the signature (decompresses under real BLS without needing a
   compression helper here) + a base2 bitmap with the first signer_cnt of
   nbits ranks set.  Returns the encoded size. */

static ulong
put_aggregate( uchar * p, ulong nbits, ulong signer_cnt ) {
  memset( p, 0, AG_AGGSIG_SIG_COMPRESSED_SZ );
  p[0] = 0xc0; /* compressed (0x80) + infinity (0x40) flags */
  ulong payload = (nbits+7UL)/8UL;
  ulong bm_len  = 3UL+payload;
  p[ AG_AGGSIG_SIG_COMPRESSED_SZ     ] = (uchar)( bm_len     & 0xffUL );
  p[ AG_AGGSIG_SIG_COMPRESSED_SZ+1UL ] = (uchar)( (bm_len>>8) & 0xffUL );
  uchar * b = p+AG_AGGSIG_SIG_COMPRESSED_SZ+2UL;
  b[0] = 0; /* base2 */
  b[1] = (uchar)( nbits & 0xffUL ); b[2] = (uchar)( nbits>>8 );
  memset( b+3UL, 0, payload );
  for( ulong i=0UL; i<signer_cnt; i++ ) b[ 3UL+(i>>3) ] = (uchar)( b[ 3UL+(i>>3) ] | (1U<<(i&7UL)) );
  return AG_AGGSIG_SIG_COMPRESSED_SZ+2UL+bm_len;
}

static void
test_footer_de( void ) {
  ulong n = 11UL;
  create_signers( n );
  void * em; ag_epoch_info_t * e = make_epoch( n, &em );
  fd_hash_t h; memset( h.uc, 0x42, sizeof(fd_hash_t) );

  /* slow finalization: final aggregate + notar aggregate, 7/11 signers */
  uchar buf[ 1024 ];
  ulong off = 0UL;
  FD_STORE( ulong, buf, 7UL ); off += 8UL;
  memcpy( buf+off, h.uc, sizeof(fd_hash_t) ); off += sizeof(fd_hash_t);
  off += put_aggregate( buf+off, n, 7UL );
  buf[ off++ ] = 1; /* has notar aggregate */
  off += put_aggregate( buf+off, n, 7UL );

  ag_cert_t certs[ 2 ]; ulong cert_cnt;
  FD_TEST( ag_block_final_cert_de( certs, &cert_cnt, buf, off )==AG_CERT_DE_SUCCESS );
  FD_TEST( ag_block_final_cert_decompress( certs, cert_cnt )==AG_CERT_DE_SUCCESS );
  FD_TEST( cert_cnt==2UL );
  FD_TEST( certs[0].kind==AG_CERT_TYPE_FINAL && certs[0].inner.final.slot==7UL );
  FD_TEST( certs[1].kind==AG_CERT_TYPE_NOTAR && certs[1].inner.notar.slot==7UL );
  FD_TEST( !memcmp( certs[1].inner.notar.block_hash.uc, h.uc, sizeof(fd_hash_t) ) );
  for( ulong i=0UL; i<7UL; i++ ) { FD_TEST( ag_cert_is_signer( &certs[0], i ) ); FD_TEST( ag_cert_is_signer( &certs[1], i ) ); }
  FD_TEST( !ag_cert_is_signer( &certs[0], 7UL ) );
  FD_TEST( ag_cert_check_threshold( &certs[0], e ) ); /* 7/11 meets 60% */
  FD_TEST( ag_cert_check_threshold( &certs[1], e ) );

  /* trailing bytes (the reward certs follow in a real footer) are ignored */
  buf[ off ] = 0xaa;
  FD_TEST( ag_block_final_cert_de( certs, &cert_cnt, buf, off+1UL )==AG_CERT_DE_SUCCESS );

  /* truncated */
  FD_TEST( ag_block_final_cert_de( certs, &cert_cnt, buf, off-1UL )==AG_CERT_DE_ERR_TRUNCATED );

  /* fast finalization: single aggregate, 9/11 signers */
  ulong off2 = 8UL+sizeof(fd_hash_t);
  off2 += put_aggregate( buf+off2, n, 9UL );
  buf[ off2++ ] = 0; /* no notar aggregate */
  FD_TEST( ag_block_final_cert_de( certs, &cert_cnt, buf, off2 )==AG_CERT_DE_SUCCESS );
  FD_TEST( ag_block_final_cert_decompress( certs, cert_cnt )==AG_CERT_DE_SUCCESS );
  FD_TEST( cert_cnt==1UL );
  FD_TEST( certs[0].kind==AG_CERT_TYPE_FAST_FINAL && certs[0].inner.fast_final.slot==7UL );
  FD_TEST( !memcmp( certs[0].inner.fast_final.block_hash.uc, h.uc, sizeof(fd_hash_t) ) );
  FD_TEST( ag_cert_check_threshold( &certs[0], e ) ); /* 9/11 meets 80% */

  free( em );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_create();
  test_mixed();
  test_failures();
  test_thresholds();
  test_footer_de();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
