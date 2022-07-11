#include "fd_mcache_private.h"

ulong
fd_mcache_align( void ) {
  return FD_MCACHE_ALIGN;
}

ulong
fd_mcache_footprint( ulong depth ) {
  if( FD_UNLIKELY( depth<FD_MCACHE_BLOCK      ) ) return 0UL;
  if( FD_UNLIKELY( !fd_ulong_is_pow2( depth ) ) ) return 0UL;
  return FD_MCACHE_FOOTPRINT( depth );
}

void *
fd_mcache_new( void * shmem,
               ulong  depth,
               ulong  seq0 ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_mcache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( depth<FD_MCACHE_BLOCK ) ) {
    FD_LOG_WARNING(( "too small depth" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_pow2( depth ) ) ) {
    FD_LOG_WARNING(( "non-power-of-2 depth" ));
    return NULL;
  }

  memset( shmem, 0, fd_mcache_footprint( depth ) );

  fd_mcache_private_hdr_t * hdr = (fd_mcache_private_hdr_t *)shmem;

  hdr->depth    = depth;
  hdr->seq0     = seq0;
  hdr->seq[0]   = seq0;

  fd_frag_meta_t * mcache = fd_mcache_private_mcache( hdr );

  ulong seq1 = fd_seq_inc( seq0, depth );
  for( ulong seq=seq0; seq<seq1; seq++ ) {
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

  return fd_mcache_private_hdr( (fd_frag_meta_t *)mcache ); /* Kinda ugly const cast */
}
 
void *
fd_mcache_delete( void * shmcache ) {
  if( FD_UNLIKELY( !shmcache ) ) {
    FD_LOG_WARNING(( "NULL shmcache" ));
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
  return fd_mcache_private_hdr_const( mcache )->app;
}

uchar *
fd_mcache_app_laddr( fd_frag_meta_t * mcache ) {
  return fd_mcache_private_hdr( mcache )->app;
}

