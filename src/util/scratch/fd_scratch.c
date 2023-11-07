#include "fd_scratch.h"

FD_TL int     fd_scratch_in_prepare;         /* 0    on thread start */

FD_TL ulong   fd_scratch_private_start;      /* 0UL  on thread start */
FD_TL ulong   fd_scratch_private_free;       /* 0UL  on thread start */
FD_TL ulong   fd_scratch_private_stop;       /* 0UL  on thread start */

FD_TL ulong * fd_scratch_private_frame;      /* NULL on thread start */
FD_TL ulong   fd_scratch_private_frame_cnt;  /* 0UL  on thread start */
FD_TL ulong   fd_scratch_private_frame_max;  /* 0UL  on thread start */

#if FD_HAS_ALLOCA
FD_TL ulong fd_alloca_check_private_sz;
#endif

/* Virtual function table
   TODO type pun functions instead of using virtual wrappers? */

static void *
fd_scratch_malloc_virtual( void * _self __attribute__((unused)),
                           ulong  align,
                           ulong  sz ) {
  return fd_scratch_alloc( align, sz );
}

static void
fd_scratch_free_virtual( void * _self __attribute__((unused)),
                         void * _addr __attribute__((unused))) {
}

const fd_valloc_vtable_t
fd_scratch_vtable = {
  .malloc = fd_scratch_malloc_virtual,
  .free   = fd_scratch_free_virtual
};
