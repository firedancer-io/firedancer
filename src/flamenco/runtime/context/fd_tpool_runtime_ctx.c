#include "fd_tpool_runtime_ctx.h"
#include "fd_exec_slot_ctx.h"
#include <assert.h>

ulong
fd_tpool_runtime_ctx_align( void ) {
  return FD_TPOOL_RUNTIME_CTX_ALIGN;
}

ulong
fd_tpool_runtime_ctx_footprint( ulong threads ) {
  ulong ret = fd_ulong_align_up(sizeof(struct fd_tpool_runtime_ctx),  FD_TPOOL_ALIGN);
  ret = ret + FD_TPOOL_FOOTPRINT( threads );

  return ret;
}

void
fd_tpool_runtime_ctx_init( fd_exec_slot_ctx_t * slot_ctx, fd_tpool_runtime_ctx_t * tpool_ctx ) {
  ulong tcnt = fd_tile_cnt();
  uchar * tpool_scr_mem = NULL;
  fd_tpool_t * tpool = NULL;
  uchar *tpool_mem = (uchar *) ((ulong) tpool_ctx + fd_ulong_align_up(sizeof(fd_tpool_runtime_ctx_t),  FD_TPOOL_ALIGN));
  if( tcnt > 1UL ) {
    tpool = fd_tpool_init( tpool_mem, tcnt );
    if( tpool == NULL ) {
      FD_LOG_ERR(( "failed to create thread pool" ));
    }
    ulong scratch_sz = fd_scratch_smem_footprint( 256UL<<20UL );
    tpool_scr_mem = fd_valloc_malloc( slot_ctx->valloc, FD_SCRATCH_SMEM_ALIGN, scratch_sz*(tcnt-1UL) );
    if( tpool_scr_mem == NULL ) {
      FD_LOG_ERR( ( "failed to allocate thread pool scratch space" ) );
    }
    for( ulong i=1UL; i<tcnt; ++i ) {
      if( fd_tpool_worker_push( tpool, i, tpool_scr_mem + scratch_sz*(i-1UL), scratch_sz ) == NULL ) {
        FD_LOG_ERR(( "failed to launch worker" ));
      }
      else {
        FD_LOG_NOTICE(( "launched worker" ));
      }
    }
  }
  tpool_ctx->tpool       = tpool;
}

void *
fd_tpool_runtime_ctx_new( void * mem, ulong threads, ulong bg_threads ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_TPOOL_RUNTIME_CTX_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_tpool_runtime_ctx_t * self = mem;
  fd_memset( self, 0, fd_tpool_runtime_ctx_footprint( threads ) );

  self->threads = threads;
  self->bg_threads = bg_threads;

  // setup tpools

  FD_COMPILER_MFENCE();
  self->magic = FD_TPOOL_RUNTIME_CTX_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_tpool_runtime_ctx_t *
fd_tpool_runtime_ctx_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  fd_tpool_runtime_ctx_t * ctx = (fd_tpool_runtime_ctx_t *) mem;

  if( FD_UNLIKELY( ctx->magic!=FD_TPOOL_RUNTIME_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ctx;
}

void *
fd_tpool_runtime_ctx_leave( fd_tpool_runtime_ctx_t * ctx ) {
  if( FD_UNLIKELY( !ctx ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  if( FD_UNLIKELY( ctx->magic!=FD_TPOOL_RUNTIME_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (void *) ctx;
}

void *
fd_tpool_runtime_ctx_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_TPOOL_RUNTIME_CTX_ALIGN) ) )  {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_tpool_runtime_ctx_t * hdr = (fd_tpool_runtime_ctx_t *)mem;
  if( FD_UNLIKELY( hdr->magic!=FD_TPOOL_RUNTIME_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  if( hdr->tpool ) {
    fd_tpool_fini( hdr->tpool );
  }

  // delete the tpool

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return mem;
}

ulong
fd_tpool_ctx_worker_cnt( fd_tpool_runtime_ctx_t * tpool_ctx ) {
  return tpool_ctx->threads - tpool_ctx->bg_threads;
}
