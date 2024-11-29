#include "fd_quic_log_tx.h"
#include "../../../tango/dcache/fd_dcache.h"

/* fd_quic_log_buf API ************************************************/

FD_FN_CONST ulong
fd_quic_log_buf_align( void ) {
  return FD_QUIC_LOG_BUF_ALIGN;
}

FD_FN_CONST ulong
fd_quic_log_buf_footprint( ulong depth ) {
  if( FD_UNLIKELY( depth>INT_MAX ) ) return 0UL;
  depth = fd_ulong_max( depth, FD_MCACHE_BLOCK );

  ulong mcache_footprint = fd_mcache_footprint( depth, 0 );
  ulong req_data_sz      = fd_dcache_req_data_sz( FD_QUIC_LOG_MTU, depth, 1, 1 );
  ulong dcache_footprint = fd_dcache_footprint( req_data_sz, 0UL );

  if( FD_UNLIKELY( !mcache_footprint ) ) return 0UL;
  if( FD_UNLIKELY( !req_data_sz      ) ) return 0UL;
  if( FD_UNLIKELY( !dcache_footprint ) ) return 0UL;

  if( FD_UNLIKELY( mcache_footprint > INT_MAX ) ) return 0UL;
  if( FD_UNLIKELY( dcache_footprint > INT_MAX ) ) return 0UL;

  /* Keep this in sync with FD_QUIC_LOG_BUF_FOOTPRINT */
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_QUIC_LOG_BUF_ALIGN, sizeof(fd_quic_log_buf_t) );
  l = FD_LAYOUT_APPEND( l, FD_MCACHE_ALIGN,      mcache_footprint           );
  l = FD_LAYOUT_APPEND( l, FD_DCACHE_ALIGN,      dcache_footprint           );
  l = FD_LAYOUT_FINI( l, FD_QUIC_LOG_BUF_ALIGN );
  return l;
}

void *
fd_quic_log_buf_new( void * shmlog,
                     ulong  depth ) {

  depth = fd_ulong_max( depth, FD_MCACHE_BLOCK );
  if( FD_UNLIKELY( !shmlog ) ) {
    FD_LOG_WARNING(( "NULL shmlog" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmlog, FD_QUIC_LOG_BUF_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned shmlog" ));
    return NULL;
  }
  ulong sz = fd_quic_log_buf_footprint( depth );
  if( FD_UNLIKELY( !sz ) ) {
    FD_LOG_WARNING(( "invalid footprint for depth %lu", depth ));
    return NULL;
  }
  fd_memset( shmlog, 0, sz );

  /* Keep this in sync with FD_QUIC_LOG_BUF_FOOTPRINT */
  ulong mcache_footprint = fd_mcache_footprint( depth, 0 );
  ulong req_data_sz      = fd_dcache_req_data_sz( FD_QUIC_LOG_MTU, depth, 1, 1 );
  ulong dcache_footprint = fd_dcache_footprint( req_data_sz, 0UL );
  FD_SCRATCH_ALLOC_INIT( l, shmlog );
  fd_quic_log_buf_t * log       = FD_SCRATCH_ALLOC_APPEND( l, FD_QUIC_LOG_BUF_ALIGN, sizeof(fd_quic_log_buf_t) );
  void *             mcache_mem = FD_SCRATCH_ALLOC_APPEND( l, FD_MCACHE_ALIGN,       mcache_footprint          );
  void *             dcache_mem = FD_SCRATCH_ALLOC_APPEND( l, FD_DCACHE_ALIGN,       dcache_footprint          );
  FD_SCRATCH_ALLOC_FINI( l, FD_QUIC_LOG_BUF_ALIGN );

  ulong            seq0   = 0UL;
  fd_frag_meta_t * mcache = fd_mcache_join( fd_mcache_new( mcache_mem, depth, 0UL, seq0 ) );
  void *           dcache = fd_dcache_join( fd_dcache_new( dcache_mem, req_data_sz, 0UL ) );
  if( FD_UNLIKELY( !mcache ) ) return NULL;
  if( FD_UNLIKELY( !dcache ) ) return NULL;
  fd_mcache_seq_laddr( mcache )[0] = seq0;

  uint chunk0 = (uint)fd_dcache_compact_chunk0( log, dcache );
  uint wmark  = (uint)fd_dcache_compact_wmark ( log, dcache, FD_QUIC_LOG_MTU );
  uint chunk1 = (uint)fd_dcache_compact_chunk1( log, dcache );

  *log = (fd_quic_log_buf_t) {
    .abi = {
      .magic      = 0UL,
      .mcache_off = (uint)( (ulong)mcache_mem - (ulong)log ),
      .chunk0     = chunk0,
      .chunk1     = chunk1
    },
    .dcache_off = (uint)( (ulong)dcache_mem - (ulong)log ),
    .chunk0     = chunk0,
    .wmark      = wmark,
  };

  FD_COMPILER_MFENCE();
  log->magic = FD_QUIC_LOG_BUF_MAGIC;
  FD_COMPILER_MFENCE();
  log->abi.magic = FD_QUIC_LOG_MAGIC;
  FD_COMPILER_MFENCE();

  return shmlog;
}

void *
fd_quic_log_buf_delete( void * shmlog ) {
  if( FD_UNLIKELY( !shmlog ) ) {
    FD_LOG_WARNING(( "NULL shmlog" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmlog, FD_QUIC_LOG_BUF_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned shmlog" ));
    return NULL;
  }

  fd_quic_log_buf_t * log = shmlog;
  if( FD_UNLIKELY( log->magic!=FD_QUIC_LOG_BUF_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
  }

  void * mcache_mem = (void *)( (ulong)log + log->abi.mcache_off );
  fd_mcache_delete( mcache_mem );

  void * dcache_mem = (void *)( (ulong)log + log->dcache_off );
  fd_dcache_delete( dcache_mem );

  log->abi.magic = 0UL;
  FD_COMPILER_MFENCE();
  log->magic = 0UL;
  FD_COMPILER_MFENCE();
  return log;
}

/* fd_quic_log_tx API *************************************************/

fd_quic_log_tx_t *
fd_quic_log_tx_join( fd_quic_log_tx_t * tx,
                     void *             shmlog ) {

  if( FD_UNLIKELY( !shmlog ) ) {
    FD_LOG_WARNING(( "NULL shmlog" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmlog, FD_QUIC_LOG_BUF_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned shmlog" ));
    return NULL;
  }

  fd_quic_log_buf_t * log = shmlog;
  if( FD_UNLIKELY( log->magic != FD_QUIC_LOG_BUF_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  fd_frag_meta_t * mcache = fd_mcache_join( (void *)( (ulong)log + log->abi.mcache_off ) );
  if( FD_UNLIKELY( !mcache ) ) return NULL;
  void *           dcache = fd_dcache_join( (void *)( (ulong)log + log->dcache_off     ) );
  if( FD_UNLIKELY( !dcache ) ) return NULL;

  ulong * mcache_seq = fd_mcache_seq_laddr( mcache );

  *tx = (fd_quic_log_tx_t) {
    .mcache     = mcache,
    .mcache_seq = mcache_seq,
    .base       = shmlog,
    .depth      = fd_mcache_depth( mcache ),
    .seq        = mcache_seq[0],
    .chunk      = log->chunk0,
    .chunk0     = log->chunk0,
    .wmark      = log->wmark,
  };
  return tx;
}

void *
fd_quic_log_tx_leave( fd_quic_log_tx_t * log ) {
  if( FD_UNLIKELY( !log ) ) {
    FD_LOG_WARNING(( "NULL log" ));
    return NULL;
  }
  fd_quic_log_tx_seq_update( log );
  memset( log, 0, sizeof(fd_quic_log_tx_t) );
  return log;
}

/* fd_quic_log_rx API *************************************************/

fd_quic_log_rx_t *
fd_quic_log_rx_join( fd_quic_log_rx_t * rx,
                     void *             shmlog ) {

  if( FD_UNLIKELY( !shmlog ) ) {
    FD_LOG_WARNING(( "NULL shmlog" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmlog, FD_QUIC_LOG_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned shmlog" ));
    return NULL;
  }

  fd_quic_log_abi_t * abi = shmlog;
  if( FD_UNLIKELY( abi->magic != FD_QUIC_LOG_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  fd_frag_meta_t * mcache = fd_mcache_join( (void *)( (ulong)shmlog + abi->mcache_off ) );
  if( FD_UNLIKELY( !mcache ) ) return NULL;
  ulong const * mcache_seq = fd_mcache_seq_laddr_const( mcache );

  void * base = shmlog;
  ulong  seq  = fd_mcache_seq_query( mcache_seq );

  *rx = (fd_quic_log_rx_t) {
    .mcache        = mcache,
    .mcache_seq    = mcache_seq,
    .base          = base,
    .data_lo_laddr = (ulong)fd_chunk_to_laddr_const( base, abi->chunk0 ),
    .data_hi_laddr = (ulong)fd_chunk_to_laddr_const( base, abi->chunk1 ),
    .depth         = fd_mcache_depth( mcache ),
    .seq           = seq
  };
  return rx;
}

void *
fd_quic_log_rx_leave( fd_quic_log_rx_t * log ) {
  if( FD_UNLIKELY( !log ) ) {
    FD_LOG_WARNING(( "NULL log" ));
    return NULL;
  }
  memset( log, 0, sizeof(fd_quic_log_rx_t) );
  return log;
}
