#ifndef HEADER_fd_src_flamenco_runtime_context_fd_runtime_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_runtime_ctx_h

#include "../../features/fd_features.h"
#include "../../../util/wksp/fd_wksp.h"
#include "../fd_runtime.h"

/* definition of process specific runtime context

   Everything in this is address space specific and not intended to be visible between
   tiles.
 */
struct fd_runtime_ctx {
  fd_valloc_t                 private_valloc;
  fd_runtime_public_t        *public;
};
typedef struct fd_runtime_ctx fd_runtime_ctx_t;

FD_PROTOTYPES_BEGIN

void *
fd_runtime_ctx_new( void * mem );

fd_runtime_ctx_t *
fd_runtime_ctx_join( void * mem );

void *
fd_runtime_ctx_leave( fd_runtime_ctx_t * ctx );

void *
fd_runtime_ctx_delete( void * mem );

ulong
fd_runtime_ctx_align( void );

ulong
fd_runtime_ctx_footprint( void );

FD_PROTOTYPES_END


#endif /* HEADER_fd_src_flamenco_runtime_context_fd_runtime_ctx_h */
