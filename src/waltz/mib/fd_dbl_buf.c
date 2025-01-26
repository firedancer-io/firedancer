#include "fd_dbl_buf.h"
#include "../../util/log/fd_log.h"
#include "../../tango/fd_tango_base.h"

#if FD_HAS_SSE
#include "../../util/simd/fd_sse.h"
#endif

ulong
fd_dbl_buf_align( void ) {
  return FD_DBL_BUF_ALIGN;
}

ulong
fd_dbl_buf_footprint( ulong mtu ) {
  return FD_DBL_BUF_FOOTPRINT( mtu );
}

void *
fd_dbl_buf_new( void * shmem,
                ulong  mtu,
                ulong  seq0 ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, FD_DBL_BUF_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong mtu_align = fd_ulong_align_up( mtu, FD_DBL_BUF_ALIGN );
  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_dbl_buf_t * dbl_buf = FD_SCRATCH_ALLOC_APPEND( l, FD_DBL_BUF_ALIGN, sizeof(fd_dbl_buf_t) );
  void *         buf0    = FD_SCRATCH_ALLOC_APPEND( l, FD_DBL_BUF_ALIGN, mtu_align            );
  void *         buf1    = FD_SCRATCH_ALLOC_APPEND( l, FD_DBL_BUF_ALIGN, mtu_align            );
  FD_SCRATCH_ALLOC_FINI( l, FD_DBL_BUF_ALIGN );

  *dbl_buf = (fd_dbl_buf_t) {
    .magic = 0UL,
    .seq   = seq0,
    .sz    = 0UL,
    .mtu   = mtu,
    .buf0  = (ulong)buf0 - (ulong)dbl_buf,
    .buf1  = (ulong)buf1 - (ulong)dbl_buf
  };

  FD_COMPILER_MFENCE();
  FD_VOLATILE( dbl_buf->magic ) = FD_DBL_BUF_MAGIC;
  FD_COMPILER_MFENCE();

  return dbl_buf;
}

fd_dbl_buf_t *
fd_dbl_buf_join( void * shbuf ) {

  if( FD_UNLIKELY( !shbuf ) ) {
    FD_LOG_WARNING(( "NULL shbuf" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shbuf, FD_DBL_BUF_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned shbuf" ));
    return NULL;
  }

  fd_dbl_buf_t * dbl_buf = shbuf;
  if( FD_UNLIKELY( dbl_buf->magic!=FD_DBL_BUF_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return dbl_buf;
}

void *
fd_dbl_buf_leave( fd_dbl_buf_t * buf ) {
  return buf;
}

void *
fd_dbl_buf_delete( void * shbuf ) {

  if( FD_UNLIKELY( !shbuf ) ) {
    FD_LOG_WARNING(( "NULL shbuf" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shbuf, FD_DBL_BUF_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned shbuf" ));
    return NULL;
  }

  fd_dbl_buf_t * dbl_buf = shbuf;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( dbl_buf->magic ) = 0UL;
  FD_COMPILER_MFENCE();
  return dbl_buf;
}

void
fd_dbl_buf_insert( fd_dbl_buf_t * buf,
                   void const *   msg,
                   ulong          sz ) {
  /* */  sz  = fd_ulong_min( sz, buf->mtu );
  ulong  seq = fd_seq_inc( buf->seq, 1UL );
  void * dst = fd_dbl_buf_slot( buf, seq );

  fd_memcpy( dst, msg, sz );

# if FD_HAS_SSE
  FD_COMPILER_MFENCE();
  vv_t seq_sz = vv( seq, sz );
  _mm_store_si128( &buf->seq_sz, seq_sz );
  FD_COMPILER_MFENCE();
# else
  buf->sz = sz;
  FD_COMPILER_MFENCE();
  buf->seq = seq;
  FD_COMPILER_MFENCE();
# endif
}

ulong
fd_dbl_buf_read( fd_dbl_buf_t * buf,
                 void *         obj,
                 ulong *        opt_seqp ) {
  ulong _seq[1];
  ulong * seqp = opt_seqp ? opt_seqp : _seq;
  ulong sz;
  do {
    sz = fd_dbl_buf_try_read( buf, obj, seqp );
  } while( FD_UNLIKELY( sz==ULONG_MAX ) );
  return sz;
}
