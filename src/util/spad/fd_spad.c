#include "fd_spad.h"
#include "../log/fd_log.h"

int
fd_spad_verify( fd_spad_t const * spad ) {

# define TEST(c) do { if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return -1; } } while(0)

  /* Test spad is a current local join */

  TEST( spad!=NULL );
  TEST( spad->magic==FD_SPAD_MAGIC );

  /* Extract the metadata */

  ulong frame_free = spad->frame_free; TEST( frame_free<=FD_SPAD_FRAME_MAX );
  ulong mem_used   = spad->mem_used;   TEST( mem_used  <=spad->mem_max     );

  /* If there are no frames, there should be no memory used.  Otherwise,
     make sure the mem_used and frames are properly ordered starting
     from 0. */

  if( frame_free==FD_SPAD_FRAME_MAX ) FD_TEST( !mem_used );
  else {
    FD_TEST( mem_used >= spad->off[ frame_free ] );
    for( ulong idx=frame_free; idx<FD_SPAD_FRAME_MAX-1UL; idx++ ) FD_TEST( spad->off[ idx ]>=spad->off[ idx+1UL ] );
    FD_TEST( !spad->off[ FD_SPAD_FRAME_MAX-1UL] );
  }

# undef TEST

  return 0;
}

ulong
fd_spad_alloc_max_debug( fd_spad_t const * spad,
                         ulong             align ) {
  if( FD_UNLIKELY( !fd_spad_frame_used( spad )               ) ) FD_LOG_CRIT(( "not in a frame" ));
  if( FD_UNLIKELY( (!!align) & (!fd_ulong_is_pow2( align ) ) ) ) FD_LOG_CRIT(( "bad align"      ));
  return fd_spad_alloc_max( spad, align );
}

void *
fd_spad_frame_lo_debug( fd_spad_t * spad ) {
  if( FD_UNLIKELY( !fd_spad_frame_used( spad ) ) ) FD_LOG_CRIT(( "not in a frame" ));
  return fd_spad_frame_lo( spad );
}

void *
fd_spad_frame_hi_debug( fd_spad_t * spad ) {
  if( FD_UNLIKELY( !fd_spad_frame_used( spad ) ) ) FD_LOG_CRIT(( "not in a frame" ));
  return fd_spad_frame_hi( spad );
}

void
fd_spad_push_debug( fd_spad_t * spad ) {
  if( FD_UNLIKELY( !fd_spad_frame_free( spad ) ) ) FD_LOG_CRIT(( "too many frames" ));
  fd_spad_push( spad );
}

void
fd_spad_pop_debug( fd_spad_t * spad ) {
  if( FD_UNLIKELY( !fd_spad_frame_used( spad ) ) ) FD_LOG_CRIT(( "not in a frame" ));
  fd_spad_pop( spad );
}

void *
fd_spad_alloc_debug( fd_spad_t * spad,
                     ulong       align,
                     ulong       sz ) {
  if( FD_UNLIKELY( !fd_spad_frame_used( spad )               ) ) FD_LOG_CRIT(( "not in a frame"  ));
  if( FD_UNLIKELY( (!!align) & (!fd_ulong_is_pow2( align ) ) ) ) FD_LOG_CRIT(( "bad align"       ));
  if( FD_UNLIKELY( fd_spad_alloc_max( spad, align )<sz       ) ) FD_LOG_CRIT(( "bad sz"          ));
  return fd_spad_alloc( spad, align, sz );
}

void
fd_spad_trim_debug( fd_spad_t * spad,
                    void *      hi ) {
  if( FD_UNLIKELY( !fd_spad_frame_used( spad )                 ) ) FD_LOG_CRIT(( "not in a frame"    ));
  if( FD_UNLIKELY( ((ulong)fd_spad_frame_lo( spad ))>(ulong)hi ) ) FD_LOG_CRIT(( "hi below frame_lo" ));
  if( FD_UNLIKELY( ((ulong)fd_spad_frame_hi( spad ))<(ulong)hi ) ) FD_LOG_CRIT(( "hi above frame_hi" ));
  fd_spad_trim( spad, hi );
}

void *
fd_spad_prepare_debug( fd_spad_t * spad,
                       ulong       align,
                       ulong       max ) {
  if( FD_UNLIKELY( !fd_spad_frame_used( spad )               ) ) FD_LOG_CRIT(( "not in a frame" ));
  if( FD_UNLIKELY( (!!align) & (!fd_ulong_is_pow2( align ) ) ) ) FD_LOG_CRIT(( "bad align"      ));
  if( FD_UNLIKELY( fd_spad_alloc_max( spad, align )<max      ) ) FD_LOG_CRIT(( "bad max"        ));
  return fd_spad_prepare( spad, align, max );
}

void
fd_spad_cancel_debug( fd_spad_t * spad ) {
  if( FD_UNLIKELY( !fd_spad_frame_used( spad ) ) ) FD_LOG_CRIT(( "not in a frame" ));
  /* FIXME: check if in prepare?  needs extra state and a lot of extra
     tracking that state */
  fd_spad_cancel( spad );
}

void
fd_spad_publish_debug( fd_spad_t * spad,
                       ulong       sz ) {
  if( FD_UNLIKELY( !fd_spad_frame_used( spad )       ) ) FD_LOG_CRIT(( "not in a frame" ));
  if( FD_UNLIKELY( fd_spad_alloc_max( spad, 1UL )<sz ) ) FD_LOG_CRIT(( "bad sz"         ));
  /* FIXME: check if in prepare?  needs extra state and a lot of extra
     tracking that state */
  fd_spad_publish( spad, sz );
}
