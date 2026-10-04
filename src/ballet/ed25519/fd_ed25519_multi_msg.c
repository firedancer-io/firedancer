#include "fd_ed25519.h"
#include "fd_curve25519.h"

#if FD_HAS_AVX512
#include "avx512/fd_ed25519_lane.h"

/* LANE_HASH_COPY_MAX is the largest message verify_x8 copies into a
   contiguous buffer for the multi-buffer SHA-512.  It is the legacy/v0
   transaction MTU (FD_TXN_MTU_V0, not included here so ballet/ed25519
   does not depend on ballet/txn). */

#define LANE_HASH_COPY_MAX (1232UL)

/* verify_x8 verifies cnt<=8 items as one lane group. */

static void
verify_x8( uchar const * const msgs[],
           ulong const         msg_szs[],
           uchar const * const sigs[],
           uchar const * const public_keys[],
           fd_sha512_t *       shas[],
           int                 results[],
           ulong               cnt ) {
  static uchar const identity[32] = {1};
  uchar const * a_buf[8], * r_buf[8];
  uchar k[8][32] = {{0}}, s[8][32] = {{0}};
  int candidates = 0;
  for( ulong j=0; j<8UL; j++ ) {
    a_buf[j] = r_buf[j] = identity;
    if( j>=cnt ) continue;
    results[j] = FD_ED25519_ERR_SIG;
    if( FD_UNLIKELY( !fd_curve25519_scalar_validate( sigs[j]+32 ) ) ) continue;
    a_buf[j] = public_keys[j]; r_buf[j] = sigs[j];
    candidates |= 1<<j;
  }
  if( FD_UNLIKELY( !candidates ) ) return;

  fd_ed25519_lane_point_t a, r;
  int a_valid = 0, r_valid = 0;
  fd_ed25519_lane_decode2( &a, a_buf, &a_valid, &r, r_buf, &r_valid );
  int a_small = fd_ed25519_lane_small_order( &a );
  int r_small = fd_ed25519_lane_small_order( &r );
  int live = 0;
  for( ulong j=0; j<cnt; j++ ) {
    if( !(candidates & (1<<j)) ) continue;
    /* Preserve verify's precedence: scalar, decode A, decode R,
       small-order A, small-order R, then the group equation. */
    if( FD_UNLIKELY( !(a_valid & (1<<j)) ) ) results[j] = FD_ED25519_ERR_PUBKEY;
    else if( FD_UNLIKELY( !(r_valid & (1<<j)) ) ) results[j] = FD_ED25519_ERR_SIG;
    else if( FD_UNLIKELY( a_small & (1<<j) ) ) results[j] = FD_ED25519_ERR_PUBKEY;
    else if( FD_LIKELY( !(r_small & (1<<j)) ) ) live |= 1<<j;
  }
  if( FD_UNLIKELY( !live ) ) return;

  /* The multi-buffer SHA-512 API takes contiguous inputs, so messages
     of up to LANE_HASH_COPY_MAX bytes are copied after R and A into
     hash_input.  Larger messages use streaming SHA-512 through shas[j],
     so the API has no message-size limit.  hash_input is about 10 KiB.
     The deepest stack use is about 44 KiB (gcc -fstack-usage: verify_x8
     ~18 KiB plus fd_ed25519_lane_verify ~26 KiB; clang inlines the
     latter into a ~38 KiB verify_x8). */
  uchar hash_input[8][64UL+LANE_HASH_COPY_MAX];
  uchar hashes[8][64];
  fd_sha512_batch_t batch[1];
  fd_sha512_batch_init( batch );
  for( ulong j=0; j<cnt; j++ ) {
    if( !(live & (1<<j)) ) continue;
    if( FD_LIKELY( msg_szs[j]<=LANE_HASH_COPY_MAX ) ) {
      fd_memcpy( hash_input[j], sigs[j], 32UL );
      fd_memcpy( hash_input[j]+32, public_keys[j], 32UL );
      if( msg_szs[j] ) fd_memcpy( hash_input[j]+64, msgs[j], msg_szs[j] );
      fd_sha512_batch_add( batch, hash_input[j], 64UL+msg_szs[j], hashes[j] );
    } else {
      fd_sha512_fini( fd_sha512_append( fd_sha512_append( fd_sha512_append( fd_sha512_init( shas[j] ),
                      sigs[j], 32UL ), public_keys[j], 32UL ), msgs[j], msg_szs[j] ), hashes[j] );
    }
  }
  fd_sha512_batch_fini( batch );
  for( ulong j=0; j<cnt; j++ ) {
    if( !(live & (1<<j)) ) continue;
    fd_curve25519_scalar_reduce( k[j], hashes[j] );
    fd_memcpy( s[j], sigs[j]+32, 32UL );
  }
  fd_ed25519_lane_fe_t zero;
  for( int i=0; i<5; i++ ) zero.limb[i] = wwv_zero();
  fd_ed25519_lane_sub( &a.x, &zero, &a.x );
  fd_ed25519_lane_sub( &a.t, &zero, &a.t );
  int valid = fd_ed25519_lane_verify( &a, &r, (uchar const (*)[32])k, (uchar const (*)[32])s );
  for( ulong j=0; j<cnt; j++ ) {
    if( live & (1<<j) ) results[j] = (valid & (1<<j)) ? FD_ED25519_SUCCESS : FD_ED25519_ERR_MSG;
  }
}
#endif

void
fd_ed25519_verify_batch_multi_msg( uchar const * const msgs[],
                                   ulong const         msg_szs[],
                                   uchar const * const sigs[],
                                   uchar const * const public_keys[],
                                   fd_sha512_t *       shas[],
                                   int                 results[],
                                   ulong               batch_sz ) {
#if FD_HAS_AVX512
  while( batch_sz ) {
    /* One or two remaining signatures do not amortize an x8 group.
       Keep the small-tail rule independent of message contents. */
    if( batch_sz<=2UL ) {
      for( ulong j=0; j<batch_sz; j++ ) {
        results[j] = fd_ed25519_verify( msgs[j], msg_szs[j], sigs[j], public_keys[j], shas[j] );
      }
      return;
    }
    ulong cnt = fd_ulong_min( batch_sz, 8UL );
    verify_x8( msgs, msg_szs, sigs, public_keys, shas, results, cnt );
    msgs += cnt; msg_szs += cnt; sigs += cnt; public_keys += cnt; shas += cnt; results += cnt;
    batch_sz -= cnt;
  }
#else
  for( ulong j=0; j<batch_sz; j++ ) {
    results[j] = fd_ed25519_verify( msgs[j], msg_szs[j], sigs[j], public_keys[j], shas[j] );
  }
#endif
}

/* An x8 group costs about as much as three verifies against a warm
   signer cache, so a tail of three or fewer goes through the cache. */

#define LANE_MIN_CACHED (4UL)

void
fd_ed25519_verify_batch_multi_msg_cached( uchar const * const  msgs[],
                                          ulong const          msg_szs[],
                                          uchar const * const  sigs[],
                                          uchar const * const  public_keys[],
                                          fd_sha512_t *        shas[],
                                          int                  results[],
                                          ulong                batch_sz,
                                          fd_ed25519_cache_t * cache ) {
#if FD_HAS_AVX512
  while( batch_sz ) {
    if( batch_sz<LANE_MIN_CACHED ) {
      for( ulong j=0; j<batch_sz; j++ ) {
        results[j] = fd_ed25519_verify_cached( msgs[j], msg_szs[j], sigs[j], public_keys[j], shas[j], cache );
      }
      return;
    }
    ulong cnt = fd_ulong_min( batch_sz, 8UL );
    verify_x8( msgs, msg_szs, sigs, public_keys, shas, results, cnt );
    msgs += cnt; msg_szs += cnt; sigs += cnt; public_keys += cnt; shas += cnt; results += cnt;
    batch_sz -= cnt;
  }
#else
  for( ulong j=0; j<batch_sz; j++ ) {
    results[j] = fd_ed25519_verify_cached( msgs[j], msg_szs[j], sigs[j], public_keys[j], shas[j], cache );
  }
#endif
}
