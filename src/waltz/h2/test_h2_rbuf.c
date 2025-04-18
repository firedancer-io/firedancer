#include "fd_h2_rbuf_sock.h"
#include "../../util/rng/fd_rng.h"

void
test_h2_rbuf( fd_rng_t * rng ) {
  uchar scratch[64];
  for( int j=0UL; j<64; j++ ) scratch[j] = (uchar)( 'A'+j );

  uchar buf[64];
  fd_h2_rbuf_t rbuf[1];
  fd_h2_rbuf_init( rbuf, buf, sizeof(buf) );
  FD_TEST( fd_h2_rbuf_free_sz( rbuf )==64 );
  FD_TEST( fd_h2_rbuf_used_sz( rbuf )== 0 );

  uchar shadow[64];
  ulong shadow_cons = 0UL;
  ulong shadow_prod = 0UL;

  for( ulong iter=0UL; iter<10000000UL; iter++ ) {
    FD_TEST( rbuf->lo >= buf && rbuf->lo < buf+sizeof(buf) );
    FD_TEST( rbuf->hi >= buf && rbuf->hi < buf+sizeof(buf) );
    FD_TEST( rbuf->lo_off <= rbuf->hi_off );

    ulong action  = fd_rng_ulong( rng );
    ulong free_sz = fd_h2_rbuf_free_sz( rbuf );
    ulong used_sz = fd_h2_rbuf_used_sz( rbuf );
    FD_TEST( used_sz==shadow_prod-shadow_cons );
    if( action & 1 ) {
      /* push */
      ulong push_sz = fd_rng_ulong_roll( rng, free_sz+1UL );
      for( ulong j=0UL; j<push_sz; j++ ) {
        shadow[ (shadow_prod++)%64 ] = scratch[j];
      }
      if( action & 2 ) {
        /* copy directly */
        fd_h2_rbuf_push( rbuf, scratch, push_sz );
      } else {
        /* copy via scatter list */
        struct iovec iov[2];
        ulong iov_cnt = fd_h2_rbuf_prepare_recvmsg( rbuf, iov );
        FD_TEST( free_sz ? iov_cnt>0 : iov_cnt==0 );
        FD_TEST( iov_cnt<=2 );
        if( iov_cnt ) {
          FD_TEST( iov[0].iov_len+iov[1].iov_len==free_sz );
          ulong copy0_sz = fd_ulong_min( iov[0].iov_len, push_sz );
          fd_memcpy( iov[0].iov_base, scratch, copy0_sz );
          ulong copy1_sz = fd_ulong_min( iov[1].iov_len, push_sz-copy0_sz );
          if( copy1_sz ) fd_memcpy( iov[1].iov_base, scratch+copy0_sz, copy1_sz );
          fd_h2_rbuf_commit_recvmsg( rbuf, iov, push_sz );
        }
      }
      FD_TEST( fd_h2_rbuf_free_sz( rbuf )==free_sz-push_sz );
      FD_TEST( fd_h2_rbuf_used_sz( rbuf )==used_sz+push_sz );
    } else {
      /* pop */
      ulong pop_sz = fd_rng_ulong_roll( rng, used_sz+1UL );
      if( action & (2+4+8) ) {
        /* gather */
        ulong sz0, sz1;
        uchar * b = fd_h2_rbuf_peek_used( rbuf, &sz0, &sz1 );
        for( ulong j=0UL; j<pop_sz; j++ ) {
          FD_TEST( shadow[ (shadow_cons++)%64 ]==b[0] );
          b++; sz0--;
          if( !sz0 ) {
            sz0 = sz1;
            b   = rbuf->buf0;
          }
        }
        fd_h2_rbuf_skip( rbuf, pop_sz );
      } else {
        /* pop */
        uchar scratch2[64];
        uchar * b = fd_h2_rbuf_pop( rbuf, scratch2, pop_sz );
        for( ulong j=0UL; j<pop_sz; j++ ) {
          FD_TEST( shadow[ (shadow_cons++)%64 ]==b[j] );
        }
      }
      FD_TEST( fd_h2_rbuf_free_sz( rbuf )==free_sz+pop_sz );
      FD_TEST( fd_h2_rbuf_used_sz( rbuf )==used_sz-pop_sz );
    }

    FD_TEST( fd_h2_rbuf_free_sz( rbuf )<=rbuf->bufsz );
    FD_TEST( fd_h2_rbuf_used_sz( rbuf )<=rbuf->bufsz );
    FD_TEST( fd_h2_rbuf_used_sz( rbuf )+fd_h2_rbuf_free_sz( rbuf )<=64 );
    FD_TEST( shadow_cons==rbuf->lo_off );
  }
}
