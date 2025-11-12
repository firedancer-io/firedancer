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

  fd_memset( mem, 0, fd_capture_ctx_footprint() );

  /* TODO: use layout macros */
  fd_capture_ctx_t * self = (fd_capture_ctx_t *) mem;
  self->capture = (fd_solcap_writer_t *)((uchar *)mem + sizeof(fd_capture_ctx_t));
  fd_solcap_writer_new( self->capture );

  self->account_updates_buffer     = (uchar *)mem + sizeof(fd_capture_ctx_t) + fd_solcap_writer_footprint();
  self->account_updates_buffer_ptr = self->account_updates_buffer;
  self->account_updates_len        = 0UL;

  FD_COMPILER_MFENCE();
  self->magic = FD_CAPTURE_CTX_MAGIC;
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
/* Use a concrete fd_rwlock_t, not a single-element array, to keep
   thread-safety annotations consistent with other wrappers. */
static fd_rwlock_t txn_status_lock = {0};

void
fd_capture_ctx_txn_status_start_read( void ) FD_ACQUIRE_SHARED( &txn_status_lock ) {
  fd_rwlock_read( &txn_status_lock );
}

void
fd_capture_ctx_txn_status_end_read( void ) FD_RELEASE_SHARED( &txn_status_lock ) {
  fd_rwlock_unread( &txn_status_lock );
}

void
fd_capture_ctx_txn_status_start_write( void ) FD_ACQUIRE( &txn_status_lock ) {
  fd_rwlock_write( &txn_status_lock );
}

void
fd_capture_ctx_txn_status_end_write( void ) FD_RELEASE( &txn_status_lock ) {
  fd_rwlock_unwrite( &txn_status_lock );
}
