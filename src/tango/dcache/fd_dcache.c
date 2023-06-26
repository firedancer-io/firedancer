#include "fd_dcache_private.h"

ulong
fd_dcache_req_data_sz( ulong mtu,
                       ulong depth,
                       ulong burst,
                       int   compact ) {

  if( FD_UNLIKELY( !mtu   ) ) return 0UL; /* zero mtu (technically unnecessary) */
  if( FD_UNLIKELY( !depth ) ) return 0UL; /* zero depth */
  if( FD_UNLIKELY( !burst ) ) return 0UL; /* zero burst */

  ulong slot_footprint = FD_DCACHE_SLOT_FOOTPRINT( mtu );
  if( FD_UNLIKELY( !slot_footprint ) ) return 0UL; /* overflow */

  ulong slot_cnt = depth + burst;  
  if( FD_UNLIKELY( slot_cnt<depth ) ) return 0UL; /* overflow */
  slot_cnt += (ulong)!!compact;
  if( FD_UNLIKELY( !slot_cnt ) ) return 0UL; /* overflow (technically unnecessary) */
  if( FD_UNLIKELY( slot_cnt>(ULONG_MAX/slot_footprint) ) ) return 0UL; /* overflow */

  return slot_footprint*slot_cnt;
}

ulong
fd_dcache_align( void ) {
  return FD_DCACHE_ALIGN;
}

ulong
fd_dcache_footprint( ulong data_sz,
                     ulong app_sz ) {

  ulong data_footprint = fd_ulong_align_up( data_sz, FD_DCACHE_ALIGN );
  if( FD_UNLIKELY( data_footprint<data_sz ) ) return 0UL; /* overflow */

  ulong app_footprint  = fd_ulong_align_up( app_sz,  FD_DCACHE_ALIGN );
  if( FD_UNLIKELY( app_footprint<app_sz ) ) return 0UL; /* overflow */

  ulong footprint = data_footprint + app_footprint; /* data and app */
  if( FD_UNLIKELY( footprint<data_footprint ) ) return 0UL; /* overflow */

  footprint += sizeof(fd_dcache_private_hdr_t); /* header and guard */
  if( FD_UNLIKELY( footprint<sizeof(fd_dcache_private_hdr_t) ) ) return 0UL; /* overflow */

  return footprint;
}

void *
fd_dcache_new( void * shmem,
               ulong  data_sz,
               ulong  app_sz ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_dcache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = fd_dcache_footprint( data_sz, app_sz );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad data_sz (%lu) or app_sz (%lu)", data_sz, app_sz ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  fd_dcache_private_hdr_t * hdr = (fd_dcache_private_hdr_t *)shmem;

  hdr->data_sz = data_sz;
  hdr->app_sz  = app_sz;
  hdr->app_off = sizeof(fd_dcache_private_hdr_t) + fd_ulong_align_up( data_sz, FD_DCACHE_ALIGN );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = FD_DCACHE_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

uchar *
fd_dcache_join( void * shdcache ) {

  if( FD_UNLIKELY( !shdcache ) ) {
    FD_LOG_WARNING(( "NULL shdcache" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shdcache, fd_dcache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shdcache" ));
    return NULL;
  }

  fd_dcache_private_hdr_t * hdr = (fd_dcache_private_hdr_t *)shdcache;
  if( FD_UNLIKELY( hdr->magic!=FD_DCACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return fd_dcache_private_dcache( hdr );
}

void *
fd_dcache_leave( uchar const * dcache ) {

  if( FD_UNLIKELY( !dcache ) ) {
    FD_LOG_WARNING(( "NULL dcache" ));
    return NULL;
  }

  return (void *)fd_dcache_private_hdr_const( dcache ); /* Kinda ugly const cast */
}

void *
fd_dcache_delete( void * shdcache ) {

  if( FD_UNLIKELY( !shdcache ) ) {
    FD_LOG_WARNING(( "NULL shdcache" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shdcache, fd_dcache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shdcache" ));
    return NULL;
  }

  fd_dcache_private_hdr_t * hdr = (fd_dcache_private_hdr_t *)shdcache;
  if( FD_UNLIKELY( hdr->magic != FD_DCACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return shdcache;
}

ulong
fd_dcache_data_sz( uchar const * dcache ) {
  return fd_dcache_private_hdr_const( dcache )->data_sz;
}

ulong
fd_dcache_app_sz( uchar const * dcache ) {
  return fd_dcache_private_hdr_const( dcache )->app_sz;
}

uchar const *
fd_dcache_app_laddr_const( uchar const * dcache ) {
  fd_dcache_private_hdr_t const * hdr = fd_dcache_private_hdr_const( dcache );
  return (uchar const *)(((ulong)hdr) + hdr->app_off);
}

uchar *
fd_dcache_app_laddr( uchar * dcache ) {
  fd_dcache_private_hdr_t * hdr = fd_dcache_private_hdr( dcache );
  return (uchar *)(((ulong)hdr) + hdr->app_off);
}

int
fd_dcache_compact_is_safe( void const * base,
                           void const * dcache,
                           ulong        mtu,
                           ulong        depth ) {

  /* Validate base */

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)base, 2UL*FD_CHUNK_SZ ) ) ) {
    FD_LOG_WARNING(( "base is not double chunk aligned" ));
    return 0;
  }

  if( FD_UNLIKELY( (ulong)dcache < (ulong)base ) ) {
    FD_LOG_WARNING(( "dcache before base" ));
    return 0;
  }

  /* Validate dcache */

  if( FD_UNLIKELY( !dcache ) ) {
    FD_LOG_WARNING(( "NULL dcache" ));
    return 0;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)dcache, 2UL*FD_CHUNK_SZ ) ) ) { /* Should be impossible if valid join */
    FD_LOG_WARNING(( "bad dcache (alignment)" ));
    return 0;
  }

  ulong data_sz = fd_dcache_data_sz( (uchar const *)dcache );
  if( FD_UNLIKELY( ((ulong)dcache + (ulong)data_sz) < (ulong)dcache ) ) { /* Should be impossible if valid join */
    FD_LOG_WARNING(( "bad dcache (data_sz)" ));
    return 0;
  }

  ulong chunk0 = ((ulong)dcache - (ulong)base) >> FD_CHUNK_LG_SZ; /* No overflow */
  ulong chunk1 = ((ulong)dcache + data_sz - (ulong)base) >> FD_CHUNK_LG_SZ; /* No overflow */

  if( FD_UNLIKELY( chunk1>(ulong)UINT_MAX ) ) {
    FD_LOG_WARNING(( "base to dcache address space span too large" ));
    return 0;
  }

  /* At this point, complete chunks in dcache cover [chunk0,chunk1)
     relative to the base address and any range of chunks in the dcache
     can be be losslessly compressed into two 32-bit values. */

  /* Validate mtu */

  if( FD_UNLIKELY( !mtu ) ) {
    FD_LOG_WARNING(( "zero mtu" ));
    return 0;
  }

  ulong mtu_up = mtu + (2UL*FD_CHUNK_SZ-1UL);

  if( FD_UNLIKELY( mtu_up < mtu ) ) {
    FD_LOG_WARNING(( "too large mtu" ));
    return 0;
  }

  ulong chunk_mtu = (mtu_up >> (1+FD_CHUNK_LG_SZ)) << 1; /* >0 */

  /* At this point, mtu is non-zero, chunk_mtu is non-zero and a
     sufficient number of chunks to cover an mtu frag.  Further, the
     fd_dcache_chunk_next calculation is guaranteed overflow safe for
     any size in [0,mtu]. */

  /* Validate depth */

  if( FD_UNLIKELY( !depth ) ) {
    FD_LOG_WARNING(( "zero depth" ));
    return 0;
  }

  ulong overhead  = 2UL*chunk_mtu-1UL; /* no overflow chunk_sz >> 1, chunk_mtu << ULONG_MAX/2 */
  ulong depth_max = (ULONG_MAX-overhead) / chunk_mtu; /* no overflow as overhead < ULONG_MAX */

  if( FD_UNLIKELY( depth > depth_max ) ) {
    FD_LOG_WARNING(( "too large depth" ));
    return 0;
  }

  ulong chunk_req = depth*chunk_mtu + overhead; /* (depth+2)*chunk_mtu-1, no overflow */

  if( FD_UNLIKELY( (chunk1-chunk0) < chunk_req ) ) {
    FD_LOG_WARNING(( "too small dcache" ));
    return 0;
  }

  return 1;
}

