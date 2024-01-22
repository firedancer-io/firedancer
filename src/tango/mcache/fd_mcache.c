#include "fd_mcache_private.h"

ulong
fd_mcache_align( void ) {
  return FD_MCACHE_ALIGN;
}

ulong
fd_mcache_footprint( ulong depth,
                     ulong app_sz ) {

  if( FD_UNLIKELY( depth<FD_MCACHE_BLOCK                  ) ) return 0UL; /* too small depth */
  if( FD_UNLIKELY( depth>ULONG_MAX/sizeof(fd_frag_meta_t) ) ) return 0UL; /* too large depth */
  if( FD_UNLIKELY( !fd_ulong_is_pow2( depth )             ) ) return 0UL; /* non-power-of-two depth */
  ulong meta_footprint = depth*sizeof( fd_frag_meta_t ); /* no overflow */

  ulong app_footprint = fd_ulong_align_up( app_sz, FD_MCACHE_ALIGN );
  if( FD_UNLIKELY( app_footprint<app_sz ) ) return 0UL; /* overflow */

  ulong footprint = meta_footprint + app_footprint; /* meta and app */
  if( footprint<meta_footprint ) return 0UL; /* overflow */

  footprint += sizeof(fd_mcache_private_hdr_t); /* header and seq */
  if( FD_UNLIKELY( footprint<sizeof(fd_mcache_private_hdr_t) ) ) return 0UL; /* overflow */

  return footprint;
}

void *
fd_mcache_new( void * shmem,
               ulong  depth,
               ulong  app_sz,
               ulong  seq0 ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_mcache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = fd_mcache_footprint( depth, app_sz );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad depth (%lu) or app_sz (%lu)", depth, app_sz ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  fd_mcache_private_hdr_t * hdr = (fd_mcache_private_hdr_t *)shmem;

  hdr->depth    = depth;
  hdr->app_sz   = app_sz;
  hdr->seq0     = seq0;
  hdr->app_off  = sizeof(fd_mcache_private_hdr_t) + fd_ulong_align_up( depth*sizeof(fd_frag_meta_t), FD_MCACHE_ALIGN );

  hdr->seq[0] = seq0;

  fd_frag_meta_t * mcache = fd_mcache_private_mcache( hdr );

  ulong seq1 = fd_seq_inc( seq0, depth );
  for( ulong seq=seq0; seq!=seq1; seq=fd_seq_inc(seq,1UL) ) {
    ulong line = fd_mcache_line_idx( seq, depth );
    mcache[line].seq = fd_seq_dec( seq, 1UL );
    mcache[line].ctl = (ushort)fd_frag_meta_ctl( 0UL /*orig*/, 1 /*som*/, 1 /*eom*/, 1 /*err*/ );
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = FD_MCACHE_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_frag_meta_t *
fd_mcache_join( void * shmcache ) {

  if( FD_UNLIKELY( !shmcache ) ) {
    FD_LOG_WARNING(( "NULL shmcache" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmcache, fd_mcache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmcache" ));
    return NULL;
  }

  fd_mcache_private_hdr_t * hdr = (fd_mcache_private_hdr_t *)shmcache;
  if( FD_UNLIKELY( hdr->magic!=FD_MCACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return fd_mcache_private_mcache( hdr );
}

void *
fd_mcache_leave( fd_frag_meta_t const * mcache ) {

  if( FD_UNLIKELY( !mcache ) ) {
    FD_LOG_WARNING(( "NULL mcache" ));
    return NULL;
  }

  return (void *)fd_mcache_private_hdr_const( mcache ); /* Kinda ugly const cast */
}

void *
fd_mcache_delete( void * shmcache ) {

  if( FD_UNLIKELY( !shmcache ) ) {
    FD_LOG_WARNING(( "NULL shmcache" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmcache, fd_mcache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmcache" ));
    return NULL;
  }

  fd_mcache_private_hdr_t * hdr = (fd_mcache_private_hdr_t *)shmcache;
  if( FD_UNLIKELY( hdr->magic != FD_MCACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return shmcache;
}

ulong
fd_mcache_depth( fd_frag_meta_t const * mcache ) {
  return fd_mcache_private_hdr_const( mcache )->depth;
}

ulong
fd_mcache_app_sz( fd_frag_meta_t const * mcache ) {
  return fd_mcache_private_hdr_const( mcache )->app_sz;
}

ulong
fd_mcache_seq0( fd_frag_meta_t const * mcache ) {
  return fd_mcache_private_hdr_const( mcache )->seq0;
}

ulong const *
fd_mcache_seq_laddr_const( fd_frag_meta_t const * mcache ) {
  return fd_mcache_private_hdr_const( mcache )->seq;
}

ulong *
fd_mcache_seq_laddr( fd_frag_meta_t * mcache ) {
  return fd_mcache_private_hdr( mcache )->seq;
}

uchar const *
fd_mcache_app_laddr_const( fd_frag_meta_t const * mcache ) {
  fd_mcache_private_hdr_t const * hdr = fd_mcache_private_hdr_const( mcache );
  return (uchar const *)(((ulong)hdr) + hdr->app_off);
}

uchar *
fd_mcache_app_laddr( fd_frag_meta_t * mcache ) {
  fd_mcache_private_hdr_t * hdr = fd_mcache_private_hdr( mcache );
  return (uchar *)(((ulong)hdr) + hdr->app_off);
}

