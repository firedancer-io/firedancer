#include "fd_exec_txn_ctx.h"

void *
fd_exec_txn_ctx_new( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_EXEC_TXN_CTX_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  // fd_memset(mem, 0, FD_EXEC_TXN_CTX_FOOTPRINT);

  fd_exec_txn_ctx_t * self = (fd_exec_txn_ctx_t *) mem;

  FD_COMPILER_MFENCE();
  self->magic = FD_EXEC_TXN_CTX_MAGIC;
  FD_COMPILER_MFENCE();

  return mem;
}

fd_exec_txn_ctx_t *
fd_exec_txn_ctx_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  fd_exec_txn_ctx_t * ctx = (fd_exec_txn_ctx_t *) mem;

  if( FD_UNLIKELY( ctx->magic!=FD_EXEC_TXN_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ctx;
}

void *
fd_exec_txn_ctx_leave( fd_exec_txn_ctx_t * ctx) {
  if( FD_UNLIKELY( !ctx ) ) {
    FD_LOG_WARNING(( "NULL block" ));
    return NULL;
  }

  if( FD_UNLIKELY( ctx->magic!=FD_EXEC_TXN_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return (void *) ctx;
}

void *
fd_exec_txn_ctx_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_EXEC_TXN_CTX_ALIGN) ) )  {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  fd_exec_txn_ctx_t * hdr = (fd_exec_txn_ctx_t *)mem;
  if( FD_UNLIKELY( hdr->magic!=FD_EXEC_TXN_CTX_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return mem;
}
