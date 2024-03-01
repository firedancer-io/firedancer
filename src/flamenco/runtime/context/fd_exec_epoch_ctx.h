#ifndef HEADER_fd_src_flamenco_runtime_context_fd_exec_epoch_ctx_h
#define HEADER_fd_src_flamenco_runtime_context_fd_exec_epoch_ctx_h

#include "../../features/fd_features.h"
#include "../fd_rent_lists.h"
#include "../../leaders/fd_leaders.h"

struct fd_bank_match {
  ulong slot;
  uint hash;
  fd_hash_t ours;
  fd_hash_t theirs;
};
typedef struct fd_bank_match fd_bank_match_t;
#define MAP_NAME fd_bank_match_map
#define MAP_T    fd_bank_match_t
#define MAP_KEY  slot
#include "../../../util/tmpl/fd_map_dynamic.c"

/* fd_exec_epoch_ctx_t is the context that stays constant throughout
   an entire epoch. */

struct __attribute__((aligned(8UL))) fd_exec_epoch_ctx {
  ulong magic; /* ==FD_EXEC_EPOCH_CTX_MAGIC */

  /* TODO: Epoch context should preallocate instead of using dynamic allocs */
  fd_valloc_t valloc;

  fd_epoch_leaders_t * leaders;  /* Current epoch only */
  fd_features_t        features;
  fd_epoch_bank_t      epoch_bank;
  fd_bank_match_t *    bank_matches;
};

#define FD_EXEC_EPOCH_CTX_ALIGN     (alignof(fd_exec_epoch_ctx_t))
#define FD_EXEC_EPOCH_CTX_FOOTPRINT ( sizeof(fd_exec_epoch_ctx_t))
#define FD_EXEC_EPOCH_CTX_MAGIC (0x3E64F44C9F44366AUL) /* random */

FD_PROTOTYPES_BEGIN

void *
fd_exec_epoch_ctx_new( void * mem );

fd_exec_epoch_ctx_t *
fd_exec_epoch_ctx_join( void * mem );

void *
fd_exec_epoch_ctx_leave( fd_exec_epoch_ctx_t * ctx );

void *
fd_exec_epoch_ctx_delete( void * mem );

/* Free all allocated memory within a epoch ctx */
void
fd_exec_epoch_ctx_free( fd_exec_epoch_ctx_t * ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_context_fd_exec_epoch_ctx_h */
