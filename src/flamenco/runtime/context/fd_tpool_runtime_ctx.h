#ifndef HEADER_fd_src_flamenco_runtime_context_fd_tpool_runtime_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_tpool_runtime_ctx_h

#include "../../features/fd_features.h"
#include "../../leaders/fd_leaders.h"
#include "../fd_bank_hash_cmp.h"
#include "../fd_rent_lists.h"

/* fd_tpool_runtime_ctx_t is the context that stays constant throughout
   an entire run. */

#define FD_TPOOL_RUNTIME_CTX_ALIGN (FD_TPOOL_ALIGN)
#define FD_TPOOL_RUNTIME_CTX_MAGIC (0x2F64A54C9F44358AUL) /* random */

struct __attribute__((aligned(FD_TPOOL_RUNTIME_CTX_ALIGN))) fd_tpool_runtime_ctx {
  ulong magic; /* ==FD_TPOOL_RUNTIME_CTX_MAGIC */

  fd_tpool_t *          tpool;                   /* thread pool for execution */
  ulong                 threads;
  ulong                 bg_threads;
};

typedef struct fd_tpool_runtime_ctx fd_tpool_runtime_ctx_t;

FD_PROTOTYPES_BEGIN

void *
fd_tpool_runtime_ctx_new( void * mem, ulong threads, ulong bg_threads );

fd_tpool_runtime_ctx_t *
fd_tpool_runtime_ctx_join( void * mem );

void *
fd_tpool_runtime_ctx_leave( fd_tpool_runtime_ctx_t * ctx );

void *
fd_tpool_runtime_ctx_delete( void * mem );

ulong
fd_tpool_runtime_ctx_align( void );

ulong
fd_tpool_runtime_ctx_footprint( ulong threads );

void
fd_tpool_runtime_ctx_init( fd_exec_slot_ctx_t * slot_ctx, fd_tpool_runtime_ctx_t * tpool_ctx );

ulong
fd_tpool_ctx_worker_cnt( fd_tpool_runtime_ctx_t * tpool_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_tpool_runtime_ctx_h */
