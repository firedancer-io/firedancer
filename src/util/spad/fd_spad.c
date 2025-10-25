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

/* Debug fn definitions */
#if (FD_HAS_DEEPASAN || FD_HAS_MSAN)
#define SELECT_DEBUG_IMPL(fn) fn##_sanitizer_impl
#else
#define SELECT_DEBUG_IMPL(fn) fn##_impl
#endif

void
fd_spad_reset_debug( fd_spad_t * spad ) {
  SELECT_DEBUG_IMPL(fd_spad_reset)(spad);
}

void *
fd_spad_delete_debug( void * shspad ) {
  return SELECT_DEBUG_IMPL(fd_spad_delete)(shspad);
}

ulong
fd_spad_alloc_max_debug( fd_spad_t const * spad,
                         ulong             align ) {
  if( FD_UNLIKELY( !fd_spad_frame_used( spad )               ) ) FD_LOG_CRIT(( "not in a frame" ));
  if( FD_UNLIKELY( (!!align) & (!fd_ulong_is_pow2( align ) ) ) ) FD_LOG_CRIT(( "bad align"      ));
  return SELECT_DEBUG_IMPL(fd_spad_alloc_max)( spad, align );
}

void *
fd_spad_frame_lo_debug( fd_spad_t * spad ) {
  if( FD_UNLIKELY( !fd_spad_frame_used( spad ) ) ) FD_LOG_CRIT(( "not in a frame" ));
  return SELECT_DEBUG_IMPL(fd_spad_frame_lo)( spad );
}

void *
fd_spad_frame_hi_debug( fd_spad_t * spad ) {
  if( FD_UNLIKELY( !fd_spad_frame_used( spad ) ) ) FD_LOG_CRIT(( "not in a frame" ));
  return SELECT_DEBUG_IMPL(fd_spad_frame_hi)( spad );
}

void
fd_spad_push_debug( fd_spad_t * spad ) {
  if( FD_UNLIKELY( !fd_spad_frame_free( spad ) ) ) FD_LOG_CRIT(( "too many frames" ));
  SELECT_DEBUG_IMPL(fd_spad_push)( spad );
}

void
fd_spad_pop_debug( fd_spad_t * spad ) {
  if( FD_UNLIKELY( !fd_spad_frame_used( spad ) ) ) FD_LOG_CRIT(( "not in a frame" ));
  SELECT_DEBUG_IMPL(fd_spad_pop)( spad );
}

void *
fd_spad_alloc_check( fd_spad_t * spad,
                     ulong       align,
                     ulong       sz ) {
  if( FD_UNLIKELY( !fd_spad_frame_used( spad )               ) ) FD_LOG_CRIT(( "not in a frame"  ));
  if( FD_UNLIKELY( (!!align) & (!fd_ulong_is_pow2( align ) ) ) ) FD_LOG_CRIT(( "bad align"       ));
  ulong alloc_max = fd_spad_alloc_max( spad, align );
  if( FD_UNLIKELY( alloc_max<sz ) ) FD_LOG_CRIT(( "out of memory: attempted to allocate %lu bytes, but only %lu available", sz, alloc_max ));
  return SELECT_DEBUG_IMPL(fd_spad_alloc)( spad, align, sz );
}

void
fd_spad_trim_debug( fd_spad_t * spad,
                    void *      hi ) {
  if( FD_UNLIKELY( !fd_spad_frame_used( spad )                 ) ) FD_LOG_CRIT(( "not in a frame"    ));
  if( FD_UNLIKELY( ((ulong)fd_spad_frame_lo( spad ))>(ulong)hi ) ) FD_LOG_CRIT(( "hi below frame_lo" ));
  if( FD_UNLIKELY( ((ulong)fd_spad_frame_hi( spad ))<(ulong)hi ) ) FD_LOG_CRIT(( "hi above frame_hi" ));
  SELECT_DEBUG_IMPL(fd_spad_trim)( spad, hi );
}

void *
fd_spad_prepare_debug( fd_spad_t * spad,
                       ulong       align,
                       ulong       max ) {
  if( FD_UNLIKELY( !fd_spad_frame_used( spad )               ) ) FD_LOG_CRIT(( "not in a frame" ));
  if( FD_UNLIKELY( (!!align) & (!fd_ulong_is_pow2( align ) ) ) ) FD_LOG_CRIT(( "bad align"      ));
  if( FD_UNLIKELY( fd_spad_alloc_max( spad, align )<max      ) ) FD_LOG_CRIT(( "bad max of %lu", max        ));
  return SELECT_DEBUG_IMPL(fd_spad_prepare)( spad, align, max );
}

void
fd_spad_cancel_debug( fd_spad_t * spad ) {
  if( FD_UNLIKELY( !fd_spad_frame_used( spad ) ) ) FD_LOG_CRIT(( "not in a frame" ));
  /* FIXME: check if in prepare?  needs extra state and a lot of extra
     tracking that state */
  SELECT_DEBUG_IMPL(fd_spad_cancel)( spad );
}

void
fd_spad_publish_debug( fd_spad_t * spad,
                       ulong       sz ) {
  if( FD_UNLIKELY( !fd_spad_frame_used( spad )       ) ) FD_LOG_CRIT(( "not in a frame" ));
  if( FD_UNLIKELY( fd_spad_alloc_max( spad, 1UL )<sz ) ) FD_LOG_CRIT(( "bad sz"         ));
  /* FIXME: check if in prepare?  needs extra state and a lot of extra
     tracking that state */
  SELECT_DEBUG_IMPL(fd_spad_publish)( spad, sz );
}

#undef SELECT_DEBUG_IMPL

/* Sanitizer impl fn definitions
   Note that these definitions assume either FD_HAS_DEEPASAN and/or FD_HAS_MSAN is active. */
void
fd_spad_reset_sanitizer_impl( fd_spad_t * spad ) {
  fd_spad_reset_impl( spad );

  /* poison the entire spad memory region */
  fd_asan_poison( (void*)(fd_ulong_align_up((ulong)fd_spad_private_mem( spad ), FD_ASAN_ALIGN )), spad->mem_max );
  fd_msan_poison( (void*)(fd_ulong_align_up((ulong)fd_spad_private_mem( spad ), FD_MSAN_ALIGN )), spad->mem_max );
}

void *
fd_spad_delete_sanitizer_impl( void * shspad ) {
  void * deleted_shspad = fd_spad_delete_impl( shspad );

  if( deleted_shspad ) {
    fd_spad_t * spad = (fd_spad_t *)shspad;

    /* unpoison the entire spad memory region upon deletion */
    fd_asan_unpoison( (void*)(fd_ulong_align_up( (ulong)fd_spad_private_mem( spad ), FD_ASAN_ALIGN )), spad->mem_max );
    fd_msan_unpoison( (void*)(fd_ulong_align_up( (ulong)fd_spad_private_mem( spad ), FD_MSAN_ALIGN )), spad->mem_max );
  }

  return deleted_shspad;
}

ulong
fd_spad_alloc_max_sanitizer_impl( fd_spad_t const * spad,
                                  ulong             align ) {
  /* enforce a minimum alignment of FD_ASAN_ALIGN or FD_MSAN_ALIGN when running ASAN or MSAN respectively */
#if FD_HAS_DEEPASAN
  align = fd_ulong_if( align>0UL, fd_ulong_max( align, FD_ASAN_ALIGN ), FD_SPAD_ALLOC_ALIGN_DEFAULT ); /* typically compile time */
#elif FD_HAS_MSAN
  align = fd_ulong_if( align>0UL, fd_ulong_max( align, FD_MSAN_ALIGN ), FD_SPAD_ALLOC_ALIGN_DEFAULT ); /* typically compile time */
#endif

  return fd_spad_alloc_max_impl( spad, align );
}

void *
fd_spad_frame_lo_sanitizer_impl( fd_spad_t * spad ) {
  return fd_spad_frame_lo_impl( spad );
}

void *
fd_spad_frame_hi_sanitizer_impl( fd_spad_t * spad ) {
  return fd_spad_frame_hi_impl( spad );
}

void
fd_spad_push_sanitizer_impl( fd_spad_t * spad ) {
  fd_spad_push_impl( spad );

  /* poison the remaining free memory to cancel any in-progress prepare */
  fd_asan_poison( (void*)(fd_ulong_align_up( (ulong)(fd_spad_private_mem( spad ) + spad->mem_used), FD_ASAN_ALIGN )), spad->mem_max - spad->mem_used );
}

void
fd_spad_pop_sanitizer_impl( fd_spad_t * spad ) {
  fd_spad_pop_impl( spad );

  /* poison the entire memory region from mem_used to mem_max */
  fd_asan_poison( (void*)(fd_ulong_align_up( (ulong)(fd_spad_private_mem( spad ) + spad->mem_used), FD_ASAN_ALIGN )), spad->mem_max - spad->mem_used );
  fd_msan_poison( (void*)(fd_ulong_align_up( (ulong)(fd_spad_private_mem( spad ) + spad->mem_used), FD_MSAN_ALIGN )), spad->mem_max - spad->mem_used );
}

void *
fd_spad_alloc_sanitizer_impl( fd_spad_t * spad,
                              ulong       align,
                              ulong       sz ) {
  /* enforce a minimum alignment of FD_ASAN_ALIGN or FD_MSAN_ALIGN when running ASAN or MSAN respectively */
#if FD_HAS_DEEPASAN
  align = fd_ulong_if( align>0UL, fd_ulong_max( align, FD_ASAN_ALIGN ), FD_SPAD_ALLOC_ALIGN_DEFAULT ); /* typically compile time */
#elif FD_HAS_MSAN
  align = fd_ulong_if( align>0UL, fd_ulong_max( align, FD_MSAN_ALIGN ), FD_SPAD_ALLOC_ALIGN_DEFAULT ); /* typically compile time */
#endif

  void * buf = fd_spad_alloc_impl( spad, align, sz );

  /* first poison from buf to mem_max to cancel any in-progress prepare.
     buf is guaranteed to be an 8-byte aligned adddress */
  ulong remaining_memory = (ulong)(fd_spad_private_mem( spad ) + spad->mem_max) - (ulong)buf;
  fd_asan_poison( buf, remaining_memory );

  /* unpoison the allocated region */
  fd_asan_unpoison( buf, sz );
  fd_msan_unpoison( buf, sz );

  return buf;
}

void
fd_spad_trim_sanitizer_impl( fd_spad_t * spad,
                             void *      hi ) {
  fd_spad_trim_impl( spad, hi );

  /* at this point, mem_used is set to hi - fd_spad_private_mem(spad) */
#if FD_HAS_DEEPASAN
  /* Trim can be called at any time to set frame_hi.
     After trim is called, the memory from hi to mem_max should be poisoned
     and any valid allocations from frame_lo to the new frame_hi should
     remain unpoisoned. */
  ulong hi_aligned_dn = fd_ulong_align_dn( (ulong)hi, FD_ASAN_ALIGN );
  /* check whether hi_aligned_dn falls in a valid allocation */
  int in_allocation = !fd_asan_test( (void*)hi_aligned_dn );
  /* poison from hi_aligned_dn to mem_max */
  ulong region_sz = (ulong)( fd_spad_private_mem( spad ) + spad->mem_max ) - hi_aligned_dn;
  fd_asan_poison( (void*)hi_aligned_dn, region_sz );

  /* unpoison a correction region if hi_aligned_dn was in a valid allocation */
  if ( in_allocation ) {
    ulong correction_sz = (ulong)hi - hi_aligned_dn;
    fd_asan_unpoison( (void*)hi_aligned_dn, correction_sz );
  }
#endif

  /* poison from the next 4-byte aligned address to mem_max */
  fd_msan_poison( (void*)(fd_ulong_align_up( (ulong)hi, FD_MSAN_ALIGN )), spad->mem_max - spad->mem_used );
}

void *
fd_spad_prepare_sanitizer_impl( fd_spad_t * spad,
                                ulong       align,
                                ulong       max ) {
  /* enforce a minimum alignment of FD_ASAN_ALIGN or FD_MSAN_ALIGN when running ASAN or MSAN respectively */
#if FD_HAS_DEEPASAN
  align = fd_ulong_if( align>0UL, fd_ulong_max( align, FD_ASAN_ALIGN ), FD_SPAD_ALLOC_ALIGN_DEFAULT ); /* typically compile time */
#elif FD_HAS_MSAN
  align = fd_ulong_if( align>0UL, fd_ulong_max( align, FD_MSAN_ALIGN ), FD_SPAD_ALLOC_ALIGN_DEFAULT ); /* typically compile time */
#endif

  void * buf = fd_spad_prepare_impl( spad, align, max );

  /* unpoison memory starting at buf, which is guaranteed to be 8 byte aligned */
  fd_asan_unpoison( buf,  spad->mem_max - spad->mem_used );
  return buf;
}

void
fd_spad_cancel_sanitizer_impl( fd_spad_t * spad ) {
  fd_spad_cancel_impl( spad );

  /* poison the entire memory region from mem_used to mem_max to cancel any in-progress prepares */
  fd_asan_poison( (void*)(fd_spad_private_mem( spad ) + spad->mem_used), spad->mem_max - spad->mem_used );
}

void
fd_spad_publish_sanitizer_impl( fd_spad_t * spad,
                                ulong       sz ) {
  /* save the pointer to the start of the allocated buffer */
  ulong   off = spad->mem_used;
  uchar * buf = fd_spad_private_mem( spad ) + off;

  fd_spad_publish_impl( spad, sz );

  /* first poison from buf to mem_max to cancel the in-progress prepare */
  fd_asan_poison( (void*)buf, spad->mem_max - off );

  /* unpoison the allocated region, which is guaranteed to start at an 8-byte aligned address */
  fd_asan_unpoison( (void*)buf, sz );
  fd_msan_unpoison( (void*)buf, sz );
}
