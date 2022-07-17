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

  memset( shmem, 0, footprint );

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

