#include "fd_ed25519.h"
#include "fd_curve25519.h"

#if FD_HAS_AVX512
#include "avx512/fd_ed25519_lane.h"
#endif

void
fd_ed25519_verify_batch_multi_msg( uchar const * const msgs[],
                                   ulong const           msg_szs[],
                                   uchar const * const sigs[],
                                   uchar const * const public_keys[],
                                   fd_sha512_t *         shas[],
                                   int                   results[],
                                   ulong                 batch_sz ) {
#if FD_HAS_AVX512
  while( batch_sz ) {
    /* One or two remaining signatures do not amortize an x8 group.
       Keep the small-tail rule independent of message contents. */
    if( batch_sz<=2UL ) {
      for( ulong j=0; j<batch_sz; j++ )
        results[j] = fd_ed25519_verify( msgs[j], msg_szs[j], sigs[j], public_keys[j], shas[j] );
      return;
    }
    ulong cnt = fd_ulong_min( batch_sz, 8UL );
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
    if( FD_LIKELY( candidates ) ) {
      fd_ed25519_lane_point_t a, r;
      int a_valid = fd_ed25519_lane_decode( &a, a_buf );
      int r_valid = fd_ed25519_lane_decode( &r, r_buf );
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
      if( FD_LIKELY( live ) ) {
        /* The existing multibuffer SHA API takes contiguous inputs.
           Bound the copy to a common wire-message size; larger messages
           retain streaming SHA and the API has no message-size limit. */
        uchar hash_input[8][64+1232];
        uchar hashes[8][64];
        fd_sha512_batch_t batch[1];
        fd_sha512_batch_init( batch );
        for( ulong j=0; j<cnt; j++ ) {
          if( !(live & (1<<j)) ) continue;
          if( FD_LIKELY( msg_szs[j]<=1232UL ) ) {
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
        for( ulong j=0; j<cnt; j++ )
          if( live & (1<<j) ) results[j] = (valid & (1<<j)) ? FD_ED25519_SUCCESS : FD_ED25519_ERR_MSG;
      }
    }
    msgs += cnt; msg_szs += cnt; sigs += cnt; public_keys += cnt; shas += cnt; results += cnt;
    batch_sz -= cnt;
  }
#else
  for( ulong j=0; j<batch_sz; j++ )
    results[j] = fd_ed25519_verify( msgs[j], msg_szs[j], sigs[j], public_keys[j], shas[j] );
#endif
}
