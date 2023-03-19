#ifndef HEADER_fd_src_disco_tpu_fd_tpu_defrag_private_h
#define HEADER_fd_src_disco_tpu_fd_tpu_defrag_private_h

#include "fd_tpu_defrag.h"

#define STACK_NAME fd_tpu_defrag_freelist
#define STACK_T    uint
#include "../../util/tmpl/fd_stack.c"

struct __attribute__((aligned(FD_TPU_DEFRAG_ALIGN))) fd_tpu_defrag_private {

  ulong entry_cnt;

  ulong freelist_off;  /* Byte offset of freelist within struct */
  ulong chunks_off;    /* Byte offset of chunk array within struct */

  /* Variable-length data *********************************************/

  /* ... freelist follows    ... */
  /* ... chunk array follows ... */
};

/* fd_tpu_defrag_get_freelist returns the fd_stack of free chunks. */
FD_FN_PURE static inline uint *
fd_tpu_defrag_get_freelist( fd_tpu_defrag_t * defragger ) {
  return (uint *)( (ulong)defragger + defragger->freelist_off );
}

/* fd_tpu_defrag_get_chunks returns a pointer to the check array. */
FD_FN_PURE static inline fd_tpu_defrag_entry_t *
fd_tpu_defrag_get_chunks( fd_tpu_defrag_t * defragger ) {
  return (fd_tpu_defrag_entry_t *)( (ulong)defragger + defragger->chunks_off );
}

#endif /* HEADER_fd_src_disco_tpu_fd_tpu_defrag_private_h */
