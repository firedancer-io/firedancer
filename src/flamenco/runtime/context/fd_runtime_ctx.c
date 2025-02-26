#include "fd_runtime_ctx.h"

void *
fd_runtime_ctx_new( void * mem ) {
  fd_memset(mem, 0, sizeof(fd_runtime_ctx_t));
  return mem;
}

fd_runtime_ctx_t *
fd_runtime_ctx_join( void * mem ) {
  return (fd_runtime_ctx_t *) mem;
}

void *
fd_runtime_ctx_leave( fd_runtime_ctx_t * ctx ) {
  return ctx;
}

void *
fd_runtime_ctx_delete( void * mem ) {
  return mem;
}

ulong
fd_runtime_ctx_align( void ) {
  return alignof(fd_runtime_ctx_t);
}

ulong
fd_runtime_ctx_footprint( void ) {
  return sizeof(fd_runtime_ctx_t);
}
