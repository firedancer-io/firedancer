#include "fd_capture_ctx.h"

#include <time.h>

void *
fd_capture_ctx_new( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_capture_ctx_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_capture_ctx_t *   capture_ctx = FD_SCRATCH_ALLOC_APPEND( l, fd_capture_ctx_align(),   sizeof(fd_capture_ctx_t) );
  fd_solcap_writer_t * capture     = FD_SCRATCH_ALLOC_APPEND( l, fd_solcap_writer_align(), fd_solcap_writer_footprint() );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_capture_ctx_align() ) == (ulong)mem + fd_capture_ctx_footprint() );

  fd_memset( capture_ctx, 0, sizeof(fd_capture_ctx_t) );

  capture_ctx->capture = fd_solcap_writer_new( capture );
  if( FD_UNLIKELY( !capture_ctx->capture ) ) {
    FD_LOG_WARNING(( "failed to create solcap writer" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( capture_ctx->magic ) = FD_CAPTURE_CTX_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_capture_ctx_t *
fd_capture_ctx_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  fd_capture_ctx_t * ctx = (fd_capture_ctx_t *) mem;

  if( FD_UNLIKELY( ctx->magic!=FD_CAPTURE_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ctx;
}

void *
fd_capture_ctx_leave( fd_capture_ctx_t * ctx) {
  if( FD_UNLIKELY( !ctx ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  if( FD_UNLIKELY( ctx->magic!=FD_CAPTURE_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (void *) ctx;
}

void *
fd_capture_ctx_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_capture_ctx_align() ) ) )  {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_capture_ctx_t * hdr = (fd_capture_ctx_t *)mem;
  if( FD_UNLIKELY( hdr->magic!=FD_CAPTURE_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  /* Clean up capctx_buf */
  if( FD_LIKELY( hdr->capctx_buf ) ) {
    fd_capctx_buf_leave( hdr->capctx_buf );
  }

  if( FD_UNLIKELY( fd_solcap_writer_delete( hdr->capture ) == NULL ) ) {
    FD_LOG_WARNING(( "failed deleting capture" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return mem;
}

#include "../../fd_rwlock.h"
static fd_rwlock_t txn_status_lock[ 1 ] = {0};

void
fd_capture_ctx_txn_status_start_read( void ) {
  fd_rwlock_read( txn_status_lock );
}

void
fd_capture_ctx_txn_status_end_read( void ) {
  fd_rwlock_unread( txn_status_lock );
}

void
fd_capture_ctx_txn_status_start_write( void ) {
  fd_rwlock_write( txn_status_lock );
}

void
fd_capture_ctx_txn_status_end_write( void ) {
  fd_rwlock_unwrite( txn_status_lock );
}
